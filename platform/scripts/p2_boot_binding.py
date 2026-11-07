"""P2's canonical served/importer QEMU adapter over existing bound launch.

The original durable-boot.sh and GNU timeout remain in charge of their exact
execution/status semantics. The adapter inherits their process group. Only
IDE, the existing e1000 path and the existing operator argv grammar are
supported; it is not an adapter for arbitrary qualification suites.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shlex
import sys
import tomllib
import uuid

import boot_artifacts as ba
import operator_boot_binding as ob


def release_inputs(path, pin):
    path=Path(path)
    raw=(path/'release-manifest.toml').read_bytes()
    ba.need(hashlib.sha256(raw).hexdigest()==pin,'P2 release manifest differs from admission')
    manifest=tomllib.loads(raw.decode())
    result={}
    for name in ('sshd.elf','absd-fsd.elf','fixture-import.elf'):
        data=(path/name).read_bytes()
        ba.need(hashlib.sha256(data).hexdigest()==manifest['artifacts']['files'][name]['sha256'],
                'P2 consumed release ELF differs: '+name)
        result[name]=data
    return result


def inspect_iso(data, releases):
    kernel,grub=ob.iso_payload(data)
    lines=[line.strip() for line in grub.decode('ascii').splitlines()
           if line.strip() and not line.lstrip().startswith('#')]
    prefix=['insmod all_video','set timeout=0','menuentry "ABSD durable step" {']
    ba.need(lines[:3]==prefix and lines[-2:]==['boot','}'] and len(lines)==6,
            'P2 ISO has noncanonical GRUB commands')
    importer=re.fullmatch(r'multiboot2 /boot/absd-kernel durable=([1-5])  nvme-write=absd',lines[3])
    if not importer:
        ob.validate_operator_grub(grub)
    matches=[]
    for entry in releases:
        payload=release_inputs(entry['path'],entry['manifest_sha256'])
        expected=({'external-workload':payload['fixture-import.elf']} if importer else
                  {'external-workload':payload['sshd.elf'],'file-server':payload['absd-fsd.elf']})
        try:catalog=ob.verify_kernel_catalog(kernel,expected)
        except ob.BindingError:continue
        matches.append({'release_manifest_sha256':entry['manifest_sha256'],'catalog':catalog})
    ba.need(matches,'P2 ISO does not contain an admitted active release ELF')
    return {'profile':'importer' if importer else 'served','grub':ob.digest(grub),'matches':matches,
            'limit':'Active importer or served SSH/FSD slots only; all catalog entries structurally checked.'}



def proxy_command(original):
    words=shlex.split(original) if isinstance(original,str) else list(original)
    ba.need(words[1:] in (['-cpu','max,vendor=GenuineIntel,+rdrand'],
                          ['-accel','tcg','-cpu','max,vendor=GenuineIntel,+rdrand']),
            'bound release requires the canonical TCG CPU recipe')
    return [sys.executable,str(Path(__file__).with_name('p2-bound-qemu.py')),
            '-accel','tcg','-cpu','max,vendor=GenuineIntel,+rdrand']


def prepare(path, qemu, qemu_pin, releases, receipts):
    qemu=Path(qemu)
    ba.need(qemu.is_absolute() and ba.sha(qemu)==qemu_pin,'P2 QEMU identity differs')
    for entry in releases:release_inputs(entry['path'],entry['manifest_sha256'])
    receipts=Path(receipts);receipts.mkdir()
    record={'schema':'absd-p2-bound-boot-inputs/1','qemu':str(qemu),'qemu_sha256':qemu_pin,
            'releases':releases,'receipts':str(receipts)}
    with Path(path).open('x') as out:json.dump(record,out,indent=2);out.write('\n')
    return record


def proxy(argv):
    config=json.loads(Path(os.environ['ABSD_P2_BOUND_INPUTS']).read_text())
    ba.need(config['schema']=='absd-p2-bound-boot-inputs/1','P2 bound input schema differs')
    command=[config['qemu'],*argv]
    iso,disk=ba.operator_inputs(command)
    data=iso.read_bytes()
    inspection=inspect_iso(data,config['releases'])
    inspection['iso_sha256']=hashlib.sha256(data).hexdigest()
    prefix=Path(config['receipts'])/str(uuid.uuid4())
    with prefix.with_suffix('.catalog.json').open('x') as out:json.dump(inspection,out,indent=2);out.write('\n')
    process=None
    def forward(number,frame):
        if process is None:raise SystemExit(128+number)
        process.send_signal(number)
    old={number:signal.signal(number,forward) for number in (signal.SIGTERM,signal.SIGINT)}
    try:
        # No new session: durable-boot's existing timeout/process group applies.
        process=ba.launch(command,iso_sha256=hashlib.sha256(data).hexdigest(),
            disk_sha256=ba.sha(disk),qemu_sha256=config['qemu_sha256'],record_path=prefix.with_suffix('.launch.json'))
        status=process.wait()
        if status < 0:
            # Preserve Popen's signal result and the original timeout semantics.
            number = -status
            signal.signal(number, signal.SIG_DFL) if number not in (signal.SIGKILL, signal.SIGSTOP) else None
            os.kill(os.getpid(), number)
        return status
    finally:
        for number,handler in old.items():signal.signal(number,handler)


def terminal_bindings(directory, qemu_pin=None, release_pins=None):
    """Read all exact launch/catalog pairs; an orphan is an incomplete chain."""
    directory=Path(directory)
    launches={p.name.removesuffix('.launch.json'):p for p in directory.glob('*.launch.json')}
    catalogs={p.name.removesuffix('.catalog.json'):p for p in directory.glob('*.catalog.json')}
    ba.need(launches and launches.keys()==catalogs.keys(),'P2 bound launch/catalog inventory incomplete')
    for name,path in launches.items():
        launch=json.loads(path.read_text());catalog=json.loads(catalogs[name].read_text())
        ba.need(launch.get('admitted') is True and launch['iso_sha256']==catalog['iso_sha256'],
                'P2 bound launch/catalog identity differs')
        ba.need(qemu_pin is None or launch.get('qemu_sha256')==qemu_pin,'P2 actual QEMU pin differs')
        ba.need(release_pins is None or (catalog.get('matches') and all(
            match['release_manifest_sha256'] in release_pins for match in catalog['matches'])),
            'P2 consumed ELF release pin differs')
    return len(launches)


def kill_served(proxy_pid, serial, directory):
    """Stop the exact admitted QEMU child; its adapter reflects SIGKILL."""
    found=[]
    for path in Path(directory).glob('*.launch.json'):
        record=json.loads(path.read_text())
        words=record.get('requested_command',[])
        if record.get('admitted') is True and '-serial' in words and words[words.index('-serial')+1]=='file:'+str(serial):
            found.append(record)
    ba.need(len(found)==1,'P2 actual served QEMU identity missing or ambiguous')
    record=found[0];pid=record['pid']
    state=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
    ba.need(state[19]==record['start_ticks'] and int(state[1])==proxy_pid,
            'P2 actual served QEMU process identity differs')
    os.kill(pid,signal.SIGKILL)
