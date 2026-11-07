#!/usr/bin/env python3
"""Prepare/run one serial #143 OVMF sequence, regular-file disks only.

Default is offline preparation, with exact QEMU argv saved to COMMANDS.json.
--execute requires the steward's independent apparatus review and host admission.
Execution requires explicit ABSD_PROTECTED_HOST and refuses that host. A fresh --work is required for each attempt.
"""
import argparse
import ctypes
import hashlib
import json
import mmap
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import native_installer as builder
import install_disk as layout
import media
import absd_image
import absd_fs
from served_ram import served_qemu


def exit_status(code):
    # kernel exit_qemu sends (code << 1) | 1; isa-debug-exit encodes again.
    return (((code << 1) | 1) << 1) | 1


def external_output(raw):
    """Decode one complete, ordered stdout stream, verifying its byte count/FNV-1a."""
    output = bytearray()
    begun = ended = False
    digest = 0x811c9dc5
    for line in raw.replace(b'\r\n', b'\n').splitlines(keepends=True):
        if b'EXTERNAL OUTPUT' not in line:
            continue
        if line == b'EXTERNAL OUTPUT BEGIN encoding=hex\n' and not begun:
            begun = True
            continue
        chunk = re.fullmatch(rb'EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]*)\n', line)
        if chunk and begun and not ended:
            if int(chunk[1], 16) != len(output) or len(chunk[2]) % 2:
                raise layout.Refused('external output chunk offset or hex length mismatch')
            data = bytes.fromhex(chunk[2].decode('ascii'))
            output.extend(data)
            for byte in data:
                digest = ((digest ^ byte) * 0x1000193) & 0xffffffff
            continue
        end = re.fullmatch(rb'EXTERNAL OUTPUT END bytes=([0-9]+) digest=([0-9a-f]{8})\n', line)
        if end and begun and not ended:
            if int(end[1]) != len(output) or int(end[2], 16) != digest:
                raise layout.Refused('external output byte count or digest mismatch')
            ended = True
            continue
        raise layout.Refused('malformed or out-of-order external output frame')
    if not begun or not ended:
        raise layout.Refused('incomplete external output stream')
    return bytes(output)


def check_case_output(case, returncode, raw):
    output = external_output(raw) if case['case'].startswith('cold-') or b'EXTERNAL OUTPUT' in raw else raw
    failed = any(word in text for text in (raw, output)
                 for word in (b'PANIC', b'KERNEL FAULT', b'WORKLOAD FAILED'))
    if returncode != case['exit'] or case['expected'].encode() not in output or failed:
        raise layout.Refused(f"{case['case']} failed: exit={returncode}; retain all evidence; do not retry")


def install_cases(artifact, work, serial):
    blank, wrong, other, nonempty = (work/name for name in ('target.img', 'wrong.img', 'other.img', 'nonempty.img'))
    return [
        ('inspect', blank, serial, artifact/'installer.iso', None, 'INSTALL REFUSED consent', exit_status(2)),
        ('wrong', wrong, 'wrong-target', work/'commit.iso', None, 'INSTALL REFUSED unsupported-target', exit_status(2)),
        ('ambiguous', blank, serial, work/'commit.iso', other, 'INSTALL REFUSED disk-identity', exit_status(2)),
        ('nonempty', nonempty, serial, work/'commit.iso', None, 'INSTALL REFUSED not-blank', exit_status(2)),
        ('install', blank, serial, work/'commit.iso', None, 'INSTALL INSTALLED ', exit_status(0)),
        ('repeat', blank, serial, work/'commit.iso', None, 'INSTALL REFUSED not-blank', exit_status(2)),
        ('cold-first', blank, serial, None, None, 'INSTALL PERSIST CREATED SYNCED', 3),
        ('cold-second', blank, serial, None, None, 'INSTALL PERSIST VERIFIED', 3),
    ]


def verify_artifact(root, expected_plan_sha256):
    if not re.fullmatch(r'[0-9a-f]{64}', expected_plan_sha256):
        raise layout.Refused('expected plan sha256 must be 64 lowercase hexadecimal digits')
    if media.sha(root/'PLAN.json') != expected_plan_sha256:
        raise layout.Refused('expected plan sha256 mismatch')
    plan = json.loads((root/'PLAN.json').read_text())
    if plan['schema'] != 'absd-native-install-plan/1' or plan['model'] != builder.MODEL:
        raise layout.Refused('unsupported artifact plan')
    for name, digest in plan['artifacts'].items():
        if name not in ('payload.bin','installed.elf','installer.elf','installer.iso'):
            raise layout.Refused('unexpected artifact name')
        if (root/name).is_symlink() or media.sha(root/name) != digest:
            raise layout.Refused('artifact digest mismatch: '+name)
    if set(plan['artifacts']) != {'payload.bin','installed.elf','installer.elf','installer.iso'}:
        raise layout.Refused('missing artifact')
    payload = (root/'payload.bin').read_bytes()
    import zlib
    if hashlib.sha256(payload).hexdigest() != plan['payload_sha256'] or f'{zlib.crc32(payload):08x}' != plan['payload_crc32']:
        raise layout.Refused('payload/plan mismatch')
    return plan


def command(qemu, code, vars_file, image, serial, iso=None, other=None, log=None, trace=None):
    argv = served_qemu([qemu, '-machine', 'pc,accel=kvm', '-cpu', 'max,vendor=GenuineIntel,+rdrand',
            '-smp', '1', '-m', '512', '-nic', 'none', '-display', 'none', '-monitor', 'none',
            '-serial', 'file:'+str(log), '-no-reboot', '-no-shutdown',
            '-trace', 'ide_bus_exec_cmd', '-trace', 'serial_write', '-D', str(trace),
            '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
            '-drive', f'if=pflash,format=raw,readonly=on,file={code}',
            '-drive', f'if=pflash,format=raw,file={vars_file}',
            '-device', 'ich9-ahci,id=sata',
            '-drive', f'if=none,id=target,format=raw,file={image}',
            '-device', f'ide-hd,drive=target,bus=sata.0,serial={serial},bootindex=1'])
    if iso is not None:
        argv += ['-drive', f'if=none,id=install-media,media=cdrom,format=raw,readonly=on,file={iso}',
                 '-device', 'ide-cd,drive=install-media,bus=ide.0,bootindex=0']
    if other is not None:
        argv += ['-drive', f'if=none,id=other,format=raw,file={other}',
                 '-device', f'ide-hd,drive=other,bus=sata.1,serial={serial}']
    return argv


def qemu_version(qemu):
    version = subprocess.run([qemu, '--version'], check=True, capture_output=True, text=True).stdout.strip()
    if not re.match(r'^QEMU emulator version 8\.2\.2(?:\s|$)', version):
        raise layout.Refused('requires QEMU 8.2.2: '+version)
    return version


def run_qemu(argv, log, timeout=300):
    parent = os.getpid()
    def child_setup():
        # Linux sends SIGKILL even if the runner itself is killed with SIGKILL.
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
            raise OSError(ctypes.get_errno(), 'PR_SET_PDEATHSIG')
        if os.getppid() != parent:  # parent may have died before prctl
            os.kill(os.getpid(), signal.SIGKILL)
    return subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT,
                          timeout=timeout, preexec_fn=child_setup)


def check_install_flushes(trace):
    # Follow the kernel AHCI census gate's QEMU 8.2 trace/serial boundary.
    # The install case has exactly one writable disk; firmware traffic before
    # INSTALL PLAN is excluded. No guest counter or PASS.json supplies this count.
    positions, serial = [], bytearray()
    commands = []
    with trace.open() as handle:
        for index, line in enumerate(handle):
            match = re.fullmatch(r'serial_write write addr 0x00 val 0x([0-9a-f]+)\n?', line)
            if match:
                positions.append(index); serial.append(int(match[1], 16))
            match = re.fullmatch(r'ide_bus_exec_cmd .* cmd 0x([0-9a-f]+)\n?', line)
            if match and int(match[1], 16) in (0xe7, 0xea):
                commands.append((index, int(match[1], 16)))
    at = serial.find(b'INSTALL PLAN ')
    if at < 0: raise layout.Refused('install trace lacks native serial boundary')
    flushes = [op for index, op in commands if index >= positions[at] and op in (0xe7, 0xea)]
    if flushes != [0xea, 0xea]:
        raise layout.Refused(f'install expected two native FLUSH CACHE EXT commands, observed {flushes}')
    return len(flushes)


def host_check(checks, name, check, *args):
    entry = checks[name] = {'status':'RUNNING'}
    try:
        entry['result'] = check(*args)
        entry['status'] = 'PASS'
    except Exception as error:
        entry.update(status='FAIL', error=str(error))
        raise


def inspect(image, plan, artifact, checks=None):
    checks = {} if checks is None else checks
    target = layout.Target(image, writable=False)
    try:
        def gpt():
            layout.read_back(target.fd, target.size, plan['guids'])
            return {'guids':plan['guids']}
        host_check(checks, 'gpt', gpt)
        def payload():
            for lba, data in builder.records((artifact/'payload.bin').read_bytes()):
                if layout.pread_exact(target.fd, lba*512, len(data)) != data:
                    raise layout.Refused('installed boot payload differs')
            return {'sha256':media.sha(artifact/'payload.bin')}
        host_check(checks, 'boot_payload', payload)
    finally: target.close()
    # Independent FAT reader; verify loader, kernel and configuration bytes.
    def esp():
        files = {}
        for name, expected in plan['esp_files'].items():
            data = subprocess.run(['mtype','-i',f'{image}@@{layout.ESP_FIRST*512}','::/'+name],
                                  capture_output=True, check=True).stdout
            files[name] = hashlib.sha256(data).hexdigest()
            if files[name] != expected['sha256']:
                raise layout.Refused('installed ESP file differs: '+name)
        return {'files':files}
    host_check(checks, 'esp', esp)


def inspect_state(image):
    # Reuse the independent host reader without loading a multi-GiB disk
    # into RAM. The layout is relative to the selected ABSD partition.
    with image.open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        start = layout.ABSD_FIRST*512
        regions = absd_image.parse_layout_sector(data[start:start+512], layout.ABSD_SECTORS)
        if regions is None: raise layout.Refused('installed state has no layout')
        fs_span = absd_image.region_of_kind(regions, absd_image.KIND_FS)
        region = absd_fs.Region.of_bytes(data, layout.ABSD_FIRST+fs_span.first, fs_span.sectors)
        state = absd_fs.select(region)
        if state is None: raise layout.Refused('installed filesystem is unformatted')
        record = absd_fs.tree(region, state).get('/native-installer-143')
        if record is None or absd_fs.content(region, state, record) != b'ABSD native installer 143 persistent file v1\n':
            raise layout.Refused('independent installed file check failed')
        data = absd_fs.content(region, state, record)
        return {'path':'/native-installer-143', 'bytes':len(data),
                'sha256':hashlib.sha256(data).hexdigest()}


def prepare(args):
    artifact = pathlib.Path(args.artifact).resolve()
    plan = verify_artifact(artifact, args.expected_plan_sha256)
    work = pathlib.Path(args.work).resolve()
    work.mkdir()
    if ',' in str(work) or ',' in str(artifact): raise layout.Refused('QEMU path contains comma')
    code, vars_source = pathlib.Path(args.ovmf_code).resolve(), pathlib.Path(args.ovmf_vars).resolve()
    if not code.is_file() or not vars_source.is_file(): raise layout.Refused('OVMF files missing')
    protected_host = os.environ.get('ABSD_PROTECTED_HOST')
    if args.execute:
        if protected_host is None:
            raise layout.Refused('set ABSD_PROTECTED_HOST explicitly before execution')
        if protected_host and socket.gethostname().split('.')[0].lower() == protected_host.split('.')[0].lower():
            raise layout.Refused('QEMU is prohibited on the configured protected host')
    version = qemu_version(args.qemu) if args.execute else None
    if args.execute:
        for path in ('/', str(work)):
            free = shutil.disk_usage(path).free
            if free < 60*(1<<30)+8*(1<<30): raise layout.Refused('60 GiB floor plus 8 GiB forecast fails')
    serial, sectors = plan['serial'], plan['sectors']
    if not layout.SERIAL.fullmatch(serial) or not layout.MIN_SECTORS <= sectors <= (512<<30)//512:
        raise layout.Refused('invalid disk identity')
    blank = work/'target.img'; wrong = work/'wrong.img'; other = work/'other.img'; nonempty = work/'nonempty.img'
    for image in (blank, wrong, other, nonempty):
        with image.open('xb') as f: f.truncate(sectors*512)
    with nonempty.open('r+b') as f: f.seek(layout.ABSD_FIRST*512+7); f.write(b'PREEXISTING')
    builder.iso(artifact/'installer.elf', work/'commit.iso', builder.config(serial, int(plan['payload_crc32'],16), True, plan), work/'commit-media', plan)
    cases = install_cases(artifact, work, serial)
    commands = []
    for name, image, selected, iso, extra, expected, status in cases:
        vars_file = work/(name+'.vars.fd'); shutil.copyfile(vars_source, vars_file)
        argv = command(args.qemu, code, vars_file, image, selected, iso, extra,
                       work/(name+'.serial.log'), work/(name+'.trace'))
        commands.append({'case':name, 'argv':argv, 'expected':expected, 'exit':status})
    (work/'COMMANDS.json').write_text(json.dumps(commands, indent=2)+'\n')
    (work/'APPARATUS.json').write_text(json.dumps({'script_sha256':media.sha(__file__),
        'ovmf_code_sha256':media.sha(code), 'ovmf_vars_sha256':media.sha(vars_source),
        'plan_sha256':media.sha(artifact/'PLAN.json'), 'execute':args.execute,
        'qemu':args.qemu, 'qemu_version':version,
        'qemu_version_observation':'actual --version' if args.execute else 'unobserved; offline preparation invokes no QEMU',
        'limits':'single serial occurrence, no retries, 1 CPU per guest; RAM as recorded in COMMANDS.json; timeout 300s each; fresh NVRAM every boot'},indent=2)+'\n')
    if not args.execute:
        print('PREPARED ONLY; no QEMU executed: '+str(work/'COMMANDS.json'))
        return
    receipt = {'schema':'absd-native-installer-e2e-receipt/1', 'status':'RUNNING',
               'plan_sha256':args.expected_plan_sha256,
               'cases':[{'case':c['case'], 'expected_exit':c['exit'], 'actual_exit':None,
                         'status':'NOT_RUN', 'host_checks':{}} for c in commands]}
    def save_receipt():
        pending = work/'RECEIPT.json.pending'
        pending.write_text(json.dumps(receipt, indent=2)+'\n')
        pending.replace(work/'RECEIPT.json')
    save_receipt()
    for case, entry in zip(commands, receipt['cases']):
        name = case['case']
        entry['status'] = 'RUNNING'
        save_receipt()
        try:
            watched = (blank, wrong, other, nonempty) if name in ('inspect','wrong','ambiguous','nonempty','repeat') else ()
            before = {str(p):layout_digest(p) for p in watched}
            with (work/(name+'.qemu.log')).open('xb') as log:
                result = run_qemu(case['argv'], log)
            entry['actual_exit'] = result.returncode
            save_receipt()  # preserve the observed exit even if a later check fails
            check_case_output(case, result.returncode, (work/(name+'.serial.log')).read_bytes())
            def unchanged():
                after = {path:layout_digest(pathlib.Path(path)) for path in before}
                if before != after: raise layout.Refused(name+' changed refused target')
                return {'before':before, 'after':after}
            if watched: host_check(entry['host_checks'], 'refused_targets_unchanged', unchanged)
            if name == 'install':
                flushes = check_install_flushes(work/(name+'.trace'))
                (work/'INSTALL-FLUSHES.json').write_text(json.dumps({'source':'QEMU ide_bus_exec_cmd after INSTALL PLAN',
                    'trace_sha256':media.sha(work/(name+'.trace')), 'flush_cache_ext_count':flushes},indent=2)+'\n')
                inspect(blank, plan, artifact, entry['host_checks'])
                def blank_state():
                    target = layout.Target(blank, False)
                    try:
                        if layout.first_nonzero(target.fd, layout.ABSD_FIRST*512, layout.ABSD_END*512) is not None:
                            raise layout.Refused('state partition is not blank before first installed boot')
                    finally: target.close()
                host_check(entry['host_checks'], 'state_blank_before_boot', blank_state)
            if name.startswith('cold-'):
                inspect(blank, plan, artifact, entry['host_checks'])
                host_check(entry['host_checks'], 'persisted_file', inspect_state, blank)
            entry['status'] = 'PASS'
        except Exception as error:
            entry.update(status='TIMEOUT' if isinstance(error, subprocess.TimeoutExpired) else 'FAIL', error=str(error))
            receipt['status'] = 'FAIL'
            raise
        finally:
            save_receipt()
    receipt['status'] = 'PASS'
    save_receipt()
    (work/'PASS.json').write_text(json.dumps({'status':'PASS','cases':[c['case'] for c in commands],
        'plan_sha256':media.sha(artifact/'PLAN.json'),'limits':'QEMU only; physical hardware_fixture/SSH enrollment unproven'},indent=2)+'\n')
    print('INSTALLER E2E PASS '+str(work))


def layout_digest(path):
    target = layout.Target(path, writable=False)
    try: return layout.content_digest(target.fd, [(0,target.size)])
    finally: target.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--artifact', required=True); p.add_argument('--work', required=True)
    p.add_argument('--expected-plan-sha256', required=True,
                   help='independently supplied SHA256 of the accepted PLAN.json')
    p.add_argument('--execute', action='store_true')
    p.add_argument('--qemu', default='qemu-system-x86_64')
    p.add_argument('--ovmf-code', default='/usr/share/OVMF/OVMF_CODE_4M.fd')
    p.add_argument('--ovmf-vars', default='/usr/share/OVMF/OVMF_VARS_4M.fd')
    args = p.parse_args()
    try: prepare(args)
    except (layout.Refused, subprocess.TimeoutExpired, ValueError) as error: p.exit(2, f'E2E STOP: {error}\n')

if __name__ == '__main__': main()
