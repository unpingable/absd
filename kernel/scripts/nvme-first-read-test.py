#!/usr/bin/env python3
"""QEMU blkdebug read error after Identify: contain before the boot refuses.

Only disposable images under build/ are attached. No product fault hook is used.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import shlex
import subprocess
import tempfile


CLEANUP = 'NVME PROBE CLEANUP csts=00000001 reset=requested stop=confirmed dma=off'
WITHDRAWN = 'NVME CONTROLLER WITHDRAWN reason=first-read'
FAILED = 'BLOCK DEVICE FAILED: Device'


def judge(log, status):
    if status != 7:
        raise ValueError(f'expected refusal exit 7, got {status}')
    lines = log.splitlines()
    reads = [line for line in lines if re.fullmatch(
        r'NVME READ FAILED lba=0 Command \{ opcode: 2, status: [1-9][0-9]* \}', line)]
    if len(reads) != 1:
        raise ValueError('expected one failed read completion after successful probe')
    required = ['NVME NAMESPACE nsid=1 lba_bytes=512 sectors=4096 access=read-only',
                reads[0], CLEANUP, WITHDRAWN, FAILED]
    positions = []
    for line in required:
        if lines.count(line) != 1:
            raise ValueError('expected one record: ' + line)
        positions.append(lines.index(line))
    if positions != sorted(positions):
        raise ValueError('identify/read/stop/withdraw/refusal order')
    if any(token in log for token in ('NVME READ OK', 'NVME UNAVAILABLE', 'BLOCK BACKEND',
                                     'BLOCK DEVICE OK', 'ABSD BOOT OK', 'PANIC', 'KERNEL FAULT')):
        raise ValueError('failed first read published a backend, fell back or continued boot')


def controls(log):
    negatives = {
        'missing cleanup': log.replace(CLEANUP + '\n', ''),
        'DMA still enabled': log.replace('stop=confirmed dma=off', 'stop=confirmed dma=on'),
        'stop unconfirmed': log.replace('stop=confirmed dma=off', 'stop=unconfirmed dma=off'),
        'not withdrawn': log.replace(WITHDRAWN + '\n', ''),
        'cleanup after refusal': log.replace(CLEANUP + '\n', '').replace(FAILED, FAILED + '\n' + CLEANUP),
        'ATA fallback': log + '\nBLOCK BACKEND ata access=read-only\n',
        'error lost': log.replace(FAILED, 'BLOCK DEVICE FAILED: Absent'),
    }
    for name, negative in negatives.items():
        if negative == log:
            raise ValueError('negative not applied: ' + name)
        try:
            judge(negative, 7)
        except ValueError:
            continue
        raise ValueError('negative survived: ' + name)
    try:
        judge(log, 3)
    except ValueError:
        pass
    else:
        raise ValueError('successful exit accepted')
    return len(negatives) + 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        sample = '\n'.join(['NVME NAMESPACE nsid=1 lba_bytes=512 sectors=4096 access=read-only',
                            'NVME READ FAILED lba=0 Command { opcode: 2, status: 642 }',
                            CLEANUP, WITHDRAWN, FAILED, ''])
        judge(sample, 7)
        print(f'NVME FIRST READ ORACLE OK controls={controls(sample)}')
        return
    root = Path(__file__).resolve().parents[1]
    build = root / 'build'
    iso = build / 'absd-nvme-verify.iso'
    if not iso.is_file():
        raise SystemExit('build read-only ISO first: make nvme-iso')
    records = []
    with tempfile.TemporaryDirectory(prefix='nvme-first-read-', dir=build) as temporary:
        scratch = Path(temporary)
        config = scratch / 'blkdebug.conf'
        config.write_text('[inject-error]\nevent = "read_aio"\nerrno = "5"\n')
        for dual in [False, True]:
            name = 'dual' if dual else 'alone'
            image = scratch / (name + '.img')
            image.write_bytes(bytes(2 * 1024 * 1024))
            ata = scratch / 'ata.img'
            if dual:
                ata.write_bytes(bytes(2 * 1024 * 1024))
            digest = hashlib.sha256(image.read_bytes()).hexdigest()
            serial = build / f'nvme-first-read-{name}.serial.log'
            output = build / f'nvme-first-read-{name}.qemu.log'
            command = shlex.split(args.qemu) + [
                '-cdrom', str(iso), '-boot', 'd',
                '-drive', f'if=none,id=nvm,file=blkdebug:{config}:{image},format=raw',
                '-device', 'nvme,serial=absd,drive=nvm',
                '-display', 'none', '-serial', 'file:' + str(serial),
                '-no-reboot', '-no-shutdown',
                '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
            if dual:
                command += ['-drive', f'file={ata},format=raw,if=ide,index=0']
            with output.open('w') as out:
                done = subprocess.run(command, stdout=out, stderr=subprocess.STDOUT, timeout=90)
            log = serial.read_text()
            judge(log, done.returncode)
            count = controls(log)
            if hashlib.sha256(image.read_bytes()).hexdigest() != digest:
                raise ValueError('NVMe scratch image changed')
            if dual and hashlib.sha256(ata.read_bytes()).hexdigest() != digest:
                raise ValueError('ATA scratch image changed')
            records.append({'case': name, 'exit': done.returncode, 'controls': count,
                            'serial_sha256': hashlib.sha256(serial.read_bytes()).hexdigest(),
                            'scratch_bytes_per_image': image.stat().st_size,
                            'image_sha256_before_after': digest, 'unchanged': True,
                            'command': command, 'blkdebug_configuration': config.read_text()})
    (build / 'nvme-first-read-result.json').write_text(json.dumps(records, indent=2) + '\n')
    print('NVME FIRST READ OK cases=2 controls=8 stop=confirmed dma=off withdrawn=true images=unchanged')


if __name__ == '__main__':
    main()
