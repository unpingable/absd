#!/usr/bin/env python3
"""QEMU qualification of the AHCI block backend (coordination record #45, #123 step 3).

Every boot attaches QEMU's `ich9-ahci` with two `ide-hd` disks on
disposable images under build/: port 0 serial `other` (never selected; its
image must stay zero in every case) and port 1 serial `absd`. The cases,
in order:

  none          no ahci- option: the AHCI backend is never probed
  write         ahci-write=absd: patterns, eight-sector run, flush, bounds
  verify        ahci-disk=absd on the same image: fresh-boot re-read, writes
                and flushes refused without a command
  other         ahci-write=not-absd: no disk selected, nothing written (the
                taken-over controller's engines stay stopped)
  device-error  blkdebug fails one read (LBA 100): recover, keep serving
  timeout       fixture: a completed command judged timed out: retire,
                bus mastering off, buffers reusable
  stuck-stop    fixture: that, and the stop judged failed: buffers retired
  first-read    blkdebug fails every read: the proving read fails, the port
                is withdrawn, no backend, no fallback
  not-emulated  ahci-write=absd naming a disk whose model is not QEMU's: the
                writable selection is refused
  pending       fixture: port 1 judged not idle (a command issued): the
                controller is refused before any controller-wide write (PCI
                command as found, zero counted configuration and AHCI register
                writes, no engine stopped, no IDENTIFY)
  decode-off    fixture: memory decoding judged off: refused before any register
                access, with zero counted writes (enabling decode would be one)
  bare-write    ahci-write=absd with the CPUID hypervisor bit cleared: refused
                before any controller is touched
  bare-read     ahci-disk=absd likewise: no takeover outside a VM in either
                access mode

After each boot the host checks both images (scripts/ahci-image-check.py).
`--self-test` runs the log judge against synthetic logs and their negative
controls without QEMU.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import re
import shlex
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ahci_image_check", HERE / "ahci-image-check.py")
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)

SECTORS = 4096
PCI = r"[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]"
OTHER = (rf'AHCI DISK pci={PCI} port=0 serial="other" model="QEMU HARDDISK" selected=no',
         'AHCI DISK pci=00:04.0 port=0 serial="other" model="QEMU HARDDISK" selected=no')
SELECTED = (rf'AHCI DISK pci={PCI} port=1 serial="absd" model="QEMU HARDDISK" selected=yes',
            'AHCI DISK pci=00:04.0 port=1 serial="absd" model="QEMU HARDDISK" selected=yes')
UNSELECTED = (rf'AHCI DISK pci={PCI} port=1 serial="absd" model="QEMU HARDDISK" selected=no',
              'AHCI DISK pci=00:04.0 port=1 serial="absd" model="QEMU HARDDISK" selected=no')
CONTROLLER = (rf'AHCI CONTROLLER pci={PCI} vendor=8086 device=2922 port=1 serial=absd model=QEMU HARDDISK',
              'AHCI CONTROLLER pci=00:04.0 vendor=8086 device=2922 port=1 serial=absd model=QEMU HARDDISK')
READ_OK = (r'AHCI READ OK lba=0 fnv1a=0x[0-9a-f]{16}', 'AHCI READ OK lba=0 fnv1a=0x7da144b97d054b25')


def disk(access):
    line = f'AHCI DISK lba_bytes=512 sectors={SECTORS} access={access}'
    return (re.escape(line), line)


def literal(line):
    return (re.escape(line), line)


RW = disk('read-write (selected by ahci-write)')
RO = disk('read-only')
FENCE_RW = literal('STORAGE FENCE fence=none reason=not_declared')
FENCE_RO = literal('STORAGE FENCE fence=none reason=read_only')
NO_DEVICE = literal('block: no device')
NO_BACKEND = literal('AHCI QUALIFY FAILED no ahci backend lba=0')
# Admission before bus mastering: SeaBIOS leaves both ports' engines running
# idle, and they are stopped before any IDENTIFY.
# SeaBIOS also leaves bus mastering on; the takeover turns it off, then stops
# both ports' idle engines, before any IDENTIFY.
BME_OFF = (rf'AHCI CONTROLLER pci={PCI} bus mastering found on: turned off at takeover',
           'AHCI CONTROLLER pci=00:04.0 bus mastering found on: turned off at takeover')
ADMITTED = [BME_OFF] + [literal(f'AHCI PORT {n} STOPPED idle engines firmware left running cmd=0000c017') for n in (0, 1)]
NOT_EMULATED_DISK = (rf'AHCI DISK pci={PCI} port=1 serial="absd" model="Samsung SSD 870 EVO 1TB" selected=yes',
                     'AHCI DISK pci=00:04.0 port=1 serial="absd" model="Samsung SSD 870 EVO 1TB" selected=yes')
SERVING = ADMITTED + [OTHER, SELECTED, CONTROLLER]

# name: (ISO, blkdebug rule or None, image, exit, required lines in order,
#        forbidden substrings, patterned LBAs of the absd image afterwards)
CASES = {
    'none': ('verify-none', None, 'fresh', 7, [NO_DEVICE, NO_BACKEND],
             ['AHCI DISK', 'AHCI CONTROLLER', 'AHCI UNAVAILABLE', 'BLOCK BACKEND'], ''),
    'write': ('write', None, 'fresh', 3,
              SERVING + [RW, READ_OK, literal('BLOCK BACKEND ahci access=read-write'), FENCE_RW,
                         literal(f'AHCI BLOCK OK lbas=13 sectors={SECTORS}'),
                         literal('AHCI FLUSH OK flush_commands=1'),
                         (r'AHCI BOUNDS OK kernel=OutOfRange device_tfd=0x[0-9a-f]{8} recovered=1',
                          'AHCI BOUNDS OK kernel=OutOfRange device_tfd=0x00000441 recovered=1')],
              ['RETIRED', 'WITHDRAWN', 'AHCI QUALIFY FAILED'], oracle.WRITE_BOOT),
    'verify': ('verify', None, 'same', 3,
               SERVING + [RO, READ_OK, literal('BLOCK BACKEND ahci access=read-only'), FENCE_RO,
                          literal('AHCI REINIT OK lbas=13'), literal('AHCI READ ONLY OK')],
               ['RETIRED', 'WITHDRAWN', 'AHCI QUALIFY FAILED'], oracle.WRITE_BOOT),
    'other': ('other', None, 'same', 7,
              ADMITTED + [OTHER, UNSELECTED, literal('AHCI UNAVAILABLE Refused(NotFound)'), NO_DEVICE, NO_BACKEND],
              ['AHCI CONTROLLER pci=00:04.0 vendor', 'BLOCK BACKEND', 'AHCI READ'], oracle.WRITE_BOOT),
    'not-emulated': ('write', None, 'fresh', 7,
                     ADMITTED + [OTHER, NOT_EMULATED_DISK,
                                 literal('AHCI UNAVAILABLE Refused(WriteNotEmulated)'), NO_DEVICE, NO_BACKEND],
                     ['AHCI CONTROLLER pci=00:04.0 vendor', 'BLOCK BACKEND', 'AHCI READ'], ''),
    'device-error': ('device-error', '[inject-error]\nevent = "read_aio"\nerrno = "5"\nsector = "100"\nonce = "on"\n',
                     'fresh', 3,
                     SERVING + [RW, READ_OK, literal('BLOCK BACKEND ahci access=read-write'),
                                (r'AHCI DEVICE ERROR OK tfd=0x[0-9a-f]{8} recovered=1 then=read,write,flush',
                                 'AHCI DEVICE ERROR OK tfd=0x00000441 recovered=1 then=read,write,flush')],
                     ['RETIRED', 'WITHDRAWN', 'AHCI QUALIFY FAILED'], '5'),
    'timeout': ('timeout', None, 'fresh', 3,
                SERVING + [RW, READ_OK, literal('BLOCK BACKEND ahci access=read-write'),
                           (r'AHCI PORT 1 RETIRED after=timeout tfd=[0-9a-f]{8} stop=confirmed buffers=reusable dma=off',
                            'AHCI PORT 1 RETIRED after=timeout tfd=00000050 stop=confirmed buffers=reusable dma=off'),
                           literal('AHCI TIMEOUT OK retired=yes buffers=reusable dma=off later=refused reprobe=refused')],
                ['dma=on', 'stop=failed', 'AHCI QUALIFY FAILED'], ''),
    'stuck-stop': ('stuck-stop', None, 'fresh', 3,
                   SERVING + [RW, READ_OK, literal('BLOCK BACKEND ahci access=read-write'),
                              (r'AHCI PORT 1 RETIRED after=timeout tfd=[0-9a-f]{8} stop=failed buffers=retired dma=off',
                               'AHCI PORT 1 RETIRED after=timeout tfd=00000050 stop=failed buffers=retired dma=off'),
                              literal('AHCI STUCK STOP OK retired=yes buffers=retired dma=off later=refused reprobe=refused')],
                   ['dma=on', 'stop=confirmed', 'buffers=reusable', 'AHCI QUALIFY FAILED'], ''),
    'first-read': ('verify', '[inject-error]\nevent = "read_aio"\nerrno = "5"\n', 'fresh', 7,
                   SERVING + [RO,
                              (r'AHCI READ FAILED lba=0 Command\(TaskFile \{ tfd: [1-9][0-9]* \}\)',
                               'AHCI READ FAILED lba=0 Command(TaskFile { tfd: 1105 })'),
                              literal('AHCI PORT WITHDRAWN reason=first-read stop=confirmed dma=off'),
                              literal('BLOCK DEVICE FAILED: Device')],
                   ['AHCI READ OK', 'BLOCK BACKEND', 'BLOCK DEVICE OK', 'ABSD BOOT OK', 'RETIRED', 'NVME'], ''),
    'pending': ('pending', None, 'fresh', 7,
                [literal('AHCI PORT 1 PENDING ci=00000000 sact=00000000 fixture=pretend-pending'),
                 # Nothing written before the refusal: the PCI command as found
                 # (DMA INHERITED reported 0x0107), and the counted configuration
                 # and AHCI register writes since the checks began are zero.
                 (rf'AHCI CONTROLLER pci={PCI} REFUSED a port is not idle: no exclusive takeover command=0107 pci_config_writes=0 ahci_register_writes=0 \(left as found\)',
                  'AHCI CONTROLLER pci=00:04.0 REFUSED a port is not idle: no exclusive takeover command=0107 pci_config_writes=0 ahci_register_writes=0 (left as found)'),
                 literal('AHCI UNAVAILABLE Refused(NoController)'), NO_DEVICE, NO_BACKEND],
                ['STOPPED', 'bus mastering found on', 'AHCI DISK', 'BLOCK BACKEND', 'AHCI PORT 0 PENDING'], ''),
    'decode-off': ('decode-off', None, 'fresh', 7,
                   [(rf'AHCI CONTROLLER pci={PCI} REFUSED memory decoding off: enabling it would write before eligibility command=0107 pci_config_writes=0 ahci_register_writes=0 \(left as found\)',
                     'AHCI CONTROLLER pci=00:04.0 REFUSED memory decoding off: enabling it would write before eligibility command=0107 pci_config_writes=0 ahci_register_writes=0 (left as found)'),
                    literal('AHCI UNAVAILABLE Refused(NoController)'), NO_DEVICE, NO_BACKEND],
                   ['STOPPED', 'bus mastering found on', 'AHCI DISK', 'BLOCK BACKEND', 'PENDING'], ''),
    'bare-write': ('write', None, 'fresh', 7,
                   [literal('AHCI UNAVAILABLE Refused(OutsideVm)'), NO_DEVICE, NO_BACKEND],
                   ['AHCI DISK', 'AHCI PORT', 'AHCI CONTROLLER', 'BLOCK BACKEND'], ''),
    'bare-read': ('verify', None, 'fresh', 7,
                  [literal('AHCI UNAVAILABLE Refused(OutsideVm)'), NO_DEVICE, NO_BACKEND],
                  ['AHCI DISK', 'AHCI PORT', 'AHCI CONTROLLER', 'BLOCK BACKEND'], ''),
}
# The selected disk's model per case (QEMU's default otherwise).
MODEL = {'not-emulated': 'Samsung SSD 870 EVO 1TB'}
# Extra QEMU words per case: the bare cases hide the hypervisor bit.
EXTRA = {'bare-write': ['-cpu', 'qemu64,-hypervisor'], 'bare-read': ['-cpu', 'qemu64,-hypervisor']}
ALWAYS_FORBIDDEN = ['PANIC', 'KERNEL FAULT']


def judge(name, log, status):
    _, _, _, want, required, forbidden, _ = CASES[name]
    if status != want:
        raise ValueError(f'{name}: exit {status}, expected {want}')
    lines = log.splitlines()
    positions = []
    for pattern, _ in required:
        found = [index for index, line in enumerate(lines) if re.fullmatch(pattern, line)]
        if len(found) != 1:
            raise ValueError(f'{name}: expected exactly one line matching {pattern!r}, found {len(found)}')
        positions.append(found[0])
    if positions != sorted(positions):
        raise ValueError(f'{name}: required lines out of order')
    for token in forbidden + ALWAYS_FORBIDDEN:
        if token in log:
            raise ValueError(f'{name}: unexpected {token!r}')


def sample(name):
    return '\n'.join(['ABSD KERNEL BOOT'] + [example for _, example in CASES[name][4]] + [''])


def controls(name, log, status):
    """Negative controls on a passing log: each must be rejected."""
    _, _, _, _, required, forbidden, _ = CASES[name]
    negatives = {'wrong exit': (log, status ^ 4)}
    for pattern, _ in required:
        line = next(line for line in log.splitlines() if re.fullmatch(pattern, line))
        negatives['missing ' + line] = (log.replace(line + '\n', '', 1), status)
        negatives['repeated ' + line] = (log + line + '\n', status)
    lines = log.splitlines()
    first = next(line for line in lines if re.fullmatch(required[0][0], line))
    last = next(line for line in lines if re.fullmatch(required[-1][0], line))
    if first != last:
        swapped = log.replace(first, '\0').replace(last, first).replace('\0', last)
        negatives['order'] = (swapped, status)
    for token in forbidden + ALWAYS_FORBIDDEN:
        negatives['forbidden ' + token] = (log + token + '\n', status)
    for label, (negative, code) in negatives.items():
        try:
            judge(name, negative, code)
        except ValueError:
            continue
        raise ValueError(f'{name}: negative survived: {label}')
    return len(negatives)


def self_test():
    total = 0
    for name in CASES:
        log = sample(name)
        judge(name, log, CASES[name][3])
        total += controls(name, log, CASES[name][3])
    print(f'AHCI BLOCK ORACLE OK cases={len(CASES)} controls={total}')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    parser.add_argument('--cases', default=','.join(CASES))
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    names = args.cases.split(',')
    unknown = [name for name in names if name not in CASES]
    if unknown:
        parser.error(f'unknown cases {unknown}')
    root = HERE.parent
    build = root / 'build'
    records = []
    with tempfile.TemporaryDirectory(prefix='ahci-block-', dir=build) as temporary:
        scratch = Path(temporary)
        image = scratch / 'absd.img'
        other = scratch / 'other.img'
        other.write_bytes(bytes(SECTORS * 512))
        zero = sha(other)
        for name in names:
            iso_name, blkdebug, start, _, _, _, written = CASES[name]
            iso = build / f'absd-ahci-{iso_name}.iso'
            if not iso.is_file():
                raise SystemExit(f'missing {iso}: make ahci-iso')
            if start == 'fresh' or not image.exists():
                image.write_bytes(bytes(SECTORS * 512))
            before = sha(image)
            backing = str(image)
            if blkdebug:
                config = scratch / f'{name}.blkdebug'
                config.write_text(blkdebug)
                backing = f'blkdebug:{config}:{image}'
            serial = build / f'ahci-{name}.serial.log'
            serial.unlink(missing_ok=True)
            command = shlex.split(args.qemu) + [
                '-cdrom', str(iso), '-boot', 'd',
                '-device', 'ich9-ahci,id=ahci',
                '-drive', f'if=none,id=other,file={other},format=raw',
                '-device', 'ide-hd,drive=other,bus=ahci.0,serial=other',
                '-drive', f'if=none,id=disk,file={backing},format=raw',
                '-device', 'ide-hd,drive=disk,bus=ahci.1,serial=absd'
                + (f',model={MODEL[name]}' if name in MODEL else ''),
                '-display', 'none', '-serial', 'file:' + str(serial), '-no-reboot',
                '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04'] + EXTRA.get(name, [])
            with (build / f'ahci-{name}.qemu.log').open('w') as out:
                done = subprocess.run(command, stdout=out, stderr=subprocess.STDOUT, timeout=180)
            log = serial.read_text(errors='replace')
            judge(name, log, done.returncode)
            count = controls(name, log, done.returncode)
            patterned = oracle.check(image.read_bytes(), written)
            if sha(other) != zero:
                raise ValueError(f'{name}: the unselected disk changed')
            if start == 'same' and sha(image) != before:
                raise ValueError(f'{name}: the selected image changed on a boot that must not write')
            records.append({'case': name, 'iso': str(iso), 'iso_sha256': sha(iso),
                            'exit': done.returncode, 'controls': count,
                            'serial_sha256': sha(serial), 'image_sha256_before': before,
                            'image_sha256_after': sha(image), 'patterned': patterned,
                            'other_image_zero': True, 'command': command,
                            'blkdebug_configuration': blkdebug})
            print(f'AHCI CASE OK case={name} exit={done.returncode} controls={count} patterned={len(patterned)}')
    (build / 'ahci-block-result.json').write_text(json.dumps(records, indent=2) + '\n')
    print(f'AHCI BLOCK TEST OK cases={len(records)} unselected=unchanged')


if __name__ == '__main__':
    main()
