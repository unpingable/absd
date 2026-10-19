#!/usr/bin/env python3
"""Native std/command mtime qualification on an isolated ABSD guest.

The direct boot sets the filesystem library clock explicitly in its own
fixture. The served boot compares actual metadata with committed disk records
and checks unknown imported and actual backing-directory metadata. No timestamp-setting interface
is added to a session or the kernel. Only use a disposable kernel/VM.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import absd_fs
import ssh_absd
import mtime_reference
from served_kernel import kernel_make
from served_ram import served_qemu

spec = importlib.util.spec_from_file_location('ssh_matrix', HERE / 'ssh-matrix.py')
sm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sm)


class Target(ssh_absd.AbsdTarget):
    def files(self, authorized):
        return super().files(authorized) + [
            ('/bin/stat', (self.root / 'commands/stat').read_bytes()),
            ('/bin/sync', (self.root / 'commands/sync').read_bytes()),
            ('/bin/mtime-probe', (self.root / 'target/x86_64-unknown-absd/release/mtime_probe').read_bytes()),
        ]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--platform', required=True)
    p.add_argument('--kernel', required=True)
    p.add_argument('--work', required=True)
    p.add_argument('--qemu', required=True)
    args = p.parse_args()
    args.shell = str(Path(args.platform) / 'commands/absd-sh')
    args.boot_seconds = 900
    work = Path(args.work).resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    result = {'schema_version': 1, 'started': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'disposition': 'FAIL', 'checks': [], 'qemu': args.qemu,
              'scope': 'One guest CPU, exact local direct clock fixtures and actual FSD metadata/commands. No kernel ABI, timestamp setter, authority change or broad memory/latency claim.'}
    target = Target(args)
    key = work / 'id_mtime_operator'
    identities = []

    def check(name, ok, detail=''):
        result['checks'].append({'name': name, 'ok': bool(ok), 'detail': detail})
        print(('ok ' if ok else 'FAIL ') + name, flush=True)
        if not ok:
            raise RuntimeError(name + ': ' + str(detail))

    def command(command, expected=0):
        rc, out, err = client.run(key, command, extra=('-o', 'IdentityAgent=none', '-o', 'ForwardAgent=no'), timeout=120)
        record = {'command': command, 'rc': rc, 'stdout': out.decode(errors='replace'), 'stderr': err.decode(errors='replace')}
        (work / ('command-%02d.json' % sum(x.name.startswith('command-') for x in work.iterdir()))).write_text(json.dumps(record, indent=2)+'\n')
        check('exit: ' + command, rc == expected, record)
        return out.decode(errors='replace')

    try:
        # Record runtime identity lifecycle before generation. The entire VM
        # and these exact disposable key paths are retired after the receipt.
        (work / 'SSH-LIFECYCLE.json').write_text(json.dumps({'owner': os.environ.get('ABSD_RUN_OWNER', 'std-mtime lane'),
            'purpose': 'Loopback OpenSSH client to this occurrence\'s own QEMU forwarded port', 'paths': [str(key), str(key)+'.pub'],
            'created': result['started'], 'destination': '127.0.0.1, generated QEMU port, disposable root VM only',
            'agent': 'Disabled explicitly; never loaded/forwarded', 'retirement': 'After exact guest stopped in finally, unlink own client key. VM disk host identity retired by deleting VM; disk is not exported.'}, indent=2)+'\n')
        sm.keygen(key)
        identities.append(subprocess.check_output(['ssh-keygen', '-lf', str(key)+'.pub'], text=True).strip())
        image = work / 'direct.img'
        with image.open('xb') as f:
            f.truncate(ssh_absd.IMAGE_BYTES)
        target.work = work
        iso = target.iso(1, Path(args.platform) / 'target/x86_64-unknown-absd/release/mtime_probe')
        log = work / 'direct.serial.log'
        boot = subprocess.run([str(Path(args.kernel)/'scripts/durable-boot.sh'), str(iso), str(image), str(log),
                               '600', *served_qemu(args.qemu)], capture_output=True, text=True, timeout=650)
        text = ssh_absd.captured(log.read_bytes())
        (work/'direct.capture.txt').write_text(text)
        check('direct boot terminates normally', boot.returncode == 0 and boot.stdout.strip() == '3', boot.stdout+boot.stderr)
        check('direct path/handle/listing and V1 canaries', 'MTIME DIRECT OK' in text and text.count('MTIME PATH OK') == 5, text)
        target.setup(work, key.with_suffix('.pub').read_text())
        info = target.start(fresh=True)
        client = sm.Client(work, target.port)
        client.trust(info['public'])
        # New mtime cases have no subsecond exchange claim. The cold e1000
        # setup is allowed to settle before the first ordinary SSH exchange.
        time.sleep(1.1)
        unknown = command('mtime-probe /etc/motd unknown')
        check('imported mtime is Unsupported on all metadata routes', 'seconds=unknown routes=path,handle,entry' in unknown, unknown)
        check('stat shows unknown, never epoch/current time', 'modified: unknown\n' in command('stat /etc/motd'))
        check('ls -l shows explicit unknown time', ' - /etc/motd\n' in command('ls -l /etc/motd'))
        # stat() serves actual root attributes; readonly namespace access
        # does not manufacture a synthetic object's unknown timestamp.
        root_time = mtime_reference.records(target.image)['/']['mtime']
        check('root reference has a real positive timestamp', isinstance(root_time, int) and root_time > 0, root_time)
        check('root metadata equals actual disk time',
              'modified: '+mtime_reference.timestamp(root_time, True)+'\n' in command('stat /'))
        command('echo stamped > /home/operator/mtime-known && sync')
        record = mtime_reference.records(target.image)['/home/operator/mtime-known']
        record = {**record, 'name_hex': record['name'].hex()}
        del record['name']
        stamp = record['mtime']
        check('served file has actual positive disk backing', isinstance(stamp, int) and stamp > 0, record)
        shown = command('mtime-probe /home/operator/mtime-known '+str(stamp))
        check('FSD path/handle/listing equal exact disk time', 'seconds='+str(stamp)+' routes=path,handle,entry' in shown, shown)
        iso_time = datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        minute = datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M')
        check('stat prints exact committed UTC time', 'modified: '+iso_time+'\n' in command('stat /home/operator/mtime-known'))
        check('ls -l prints exact committed UTC minute', ' '+minute+' /home/operator/mtime-known\n' in command('ls -l /home/operator/mtime-known'))
        wrong = command('mtime-probe /home/operator/mtime-known '+str(stamp+1), expected=1)
        # Errors use stderr; require the exact explicit probe failure there.
        last = json.loads(sorted(work.glob('command-*.json'))[-1].read_text())
        check('wrong expected timestamp is refused explicitly', 'MTIME FAILED path /home/operator/mtime-known:' in last['stderr'], last)
        result['disk_record'] = record
        result['disposition'] = 'PASS'
        print('MTIME NATIVE OK', flush=True)
    except BaseException as e:
        result['error'] = repr(e)
        raise
    finally:
        target.stop()
        retired = []
        for path in [key, key.with_suffix('.pub')]:
            if path.exists():
                path.unlink(); retired.append(str(path))
        result.update(ended=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      ssh_identity_closeout={'public_fingerprints': identities, 'private_paths_retired': retired,
                                             'agent': 'Never used; no unrelated identity enumerated or modified',
                                             'guest_host_identity': 'Disposable image retained only on own VM until VM deletion, never exported'})
        (work/'MTIME-RESULT.json').write_text(json.dumps(result, indent=2)+'\n')


if __name__ == '__main__':
    main()
