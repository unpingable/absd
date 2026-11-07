#!/usr/bin/env python3
"""Build the native readable fixture or verify an admitted external-workload boot.

No guest is launched here. Use the existing external-iso composition and admitted
runner; keep its kernel, fixture, image, exit status and serial identities together.
"""
import argparse
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    'absent': b'READABLE NATIVE ABSENT\n',
    'supported': b'READABLE DATA PASS\nREADABLE EOF PASS\nREADABLE KILL PASS\nREADABLE NATIVE PASS\n',
}


def build(output):
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    fixture = ROOT / 'tests/fixtures/wait-readable/Cargo.toml'
    flags = subprocess.check_output([sys.executable, str(ROOT / 'scripts/rust-build-flags.py'),
                                     'user', str(ROOT)], text=True).rstrip('\n')
    env = dict(os.environ, CARGO_ENCODED_RUSTFLAGS=flags)
    command = ['cargo', 'build', '--offline', '--locked', '--release', '--manifest-path', str(fixture),
               '--target', 'x86_64-unknown-linux-gnu', '--target-dir', str(output)]
    subprocess.run(command + ['--bin', 'child', '--bin', 'boot_liveness'], env=env, check=True)
    env['READABLE_CHILD_ELF'] = str(output / 'x86_64-unknown-linux-gnu/release/child')
    subprocess.run(command + ['--bin', 'parent'], env=env, check=True)
    print(output / 'x86_64-unknown-linux-gnu/release/parent')


def verify(serial, status, mode):
    text = serial.read_bytes()
    lines = text.splitlines()
    required = [b'EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0',
                b'EXTERNAL WORKLOAD OK', b'ABSD BOOT OK']
    if status != 3 or any(lines.count(line) != 1 for line in required):
        raise ValueError('missing or ambiguous normal zero-resource terminal')
    if any(marker in text for marker in [b'PANIC', b'KERNEL FAULT', b'EXTERNAL WORKLOAD FAILED']):
        raise ValueError('kernel or workload failure')
    with tempfile.TemporaryDirectory(prefix='absd-readable-check-') as directory:
        expected = Path(directory) / 'expected'
        expected.write_bytes(EXPECTED[mode])
        subprocess.run([sys.executable, str(ROOT / 'scripts/check-external-output.py'),
                        str(serial), str(expected)], check=True)
    print('WAIT READABLE NATIVE VERIFIED ' + mode)


def verify_boot_liveness(serial, status):
    # A direct init replacement owns a live read/write Pipe and waits only
    # for its unreadable read end. No timed supervisor or Console waiter is
    # present. Correct boot-liveness classification ends the deadlocked boot;
    # this deliberately negative boot retains its one process and Pipe.
    text = serial.read_bytes()
    lines = text.splitlines()
    terminal = re.compile(rb'EXTERNAL status=none frames=[1-9][0-9]* processes=1 cells=0 pipes=1')
    if (status != 7 or lines.count(b'READABLE PIPE ONLY WAIT') != 1
            or sum(terminal.fullmatch(line) is not None for line in lines) != 1
            or lines.count(b'EXTERNAL WORKLOAD FAILED') != 1):
        raise ValueError('pipe-only wait did not reach the expected deadlock terminal')
    if any(marker in text for marker in [b'PANIC', b'KERNEL FAULT',
                                        b'READABLE WAIT RETURNED', b'ABSD BOOT OK']):
        raise ValueError('unexpected return, fault, or successful boot')
    print('WAIT READABLE PIPE ONLY BOOT LIVENESS VERIFIED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    building = commands.add_parser('build')
    building.add_argument('--output', type=Path, required=True)
    checking = commands.add_parser('verify')
    checking.add_argument('--serial', type=Path, required=True)
    checking.add_argument('--qemu-status', type=int, required=True)
    checking.add_argument('--mode', choices=[*EXPECTED, 'boot-liveness'], required=True)
    args = parser.parse_args()
    if args.command == 'build':
        build(args.output)
    elif args.mode == 'boot-liveness':
        verify_boot_liveness(args.serial.resolve(), args.qemu_status)
    else:
        verify(args.serial.resolve(), args.qemu_status, args.mode)


if __name__ == '__main__':
    main()
