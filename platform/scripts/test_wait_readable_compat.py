#!/usr/bin/env python3
"""Verify actual FSD old-kernel refusal output from an admitted external boot.

This checker never launches a guest. Its caller owns admission, the exact old
kernel/new FSD composition, and the QEMU exit status recorded by that producer.
"""
import argparse
from pathlib import Path
import importlib.util

EXPECTED = b'FSD FAILED kernel lacks wait_readable\n'


def verify_failure(kernel, serial, status, child_status, expected):
    """Check a failed ordinary workload, not a successful completed stream.

    Match the existing authority-effect-mutants.sh negative-boot contract.
    The real init records the child outcome, exits 99 and leaves output open.
    Exact bounded diagnostic bytes and lifecycle records supply the oracle;
    this does not certify a successful frame or any unobserved output.
    """
    if status != 7 or child_status <= 0:
        raise ValueError('expected negative QEMU status 7 and nonzero child')
    text = serial.read_bytes()
    lines = text.splitlines()
    records = [
        f'USER EXIT pid=2 status={child_status}'.encode(),
        f'EXTERNAL WORKLOAD OUTCOME pid=2 status={child_status}'.encode(),
        b'init: FAILED at external workload outcome',
        b'USER EXIT pid=1 status=99',
        b'EXTERNAL status=99 frames=0 processes=0 cells=0 pipes=0',
        b'EXTERNAL WORKLOAD FAILED',
    ]
    prefixes = [b'USER EXIT pid=2 ', b'EXTERNAL WORKLOAD OUTCOME ',
                b'init: FAILED ', b'USER EXIT pid=1 ', b'EXTERNAL status=',
                b'EXTERNAL WORKLOAD FAILED']
    for prefix, record in zip(prefixes, records):
        if [line for line in lines if line.startswith(prefix)] != [record]:
            raise ValueError('missing or ambiguous negative workload provenance')
    positions = [lines.index(record) for record in records]
    if positions != sorted(positions):
        raise ValueError('misordered negative workload provenance')
    if any(marker in text for marker in [b'FSD READY', b'PANIC', b'KERNEL FAULT',
                                        b'RECOVERY WRITABLE RESUMED', b'ABSD BOOT OK',
                                        b'EXTERNAL WORKLOAD OK', b'EXTERNAL OUTPUT END']):
        raise ValueError('unexpected startup, fault or completed output')
    # Reuse the kernel format definitions; do not relax its success decoder.
    spec = importlib.util.spec_from_file_location('external_frame', kernel / 'scripts/check-external-output.py')
    frame = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(frame)
    if [line for line in lines if line.startswith(b'EXTERNAL OUTPUT BEGIN')] != [frame.BEGIN]:
        raise ValueError('missing or ambiguous output begin')
    beginning = lines.index(frame.BEGIN)
    outcome = positions[1]
    if beginning >= outcome:
        raise ValueError('misordered output begin')
    data = bytearray()
    for index, line in enumerate(lines):
        if not line.startswith(b'EXTERNAL OUTPUT CHUNK'):
            continue
        match = frame.CHUNK.fullmatch(line)
        if match is None or not beginning < index < outcome:
            raise ValueError('malformed or misplaced diagnostic chunk')
        if int(match[1], 16) != len(data):
            raise ValueError('noncontiguous diagnostic chunk')
        try:
            data.extend(bytes.fromhex(match[2].decode('ascii')))
        except ValueError as error:
            raise ValueError('invalid diagnostic hex') from error
        if len(data) > len(expected):
            raise ValueError('oversized diagnostic')
    if data != expected:
        raise ValueError('unexpected diagnostic bytes')


def verify(kernel, serial, status):
    verify_failure(kernel, serial, status, 3, EXPECTED)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--serial', type=Path, required=True)
    parser.add_argument('--qemu-status', type=int, required=True)
    args = parser.parse_args()
    verify(args.kernel.resolve(), args.serial.resolve(), args.qemu_status)
    print('WAIT READABLE FSD OLD KERNEL REFUSAL VERIFIED')


if __name__ == '__main__':
    main()
