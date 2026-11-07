#!/usr/bin/env python3
"""Regression controls from the real old-kernel FSD negative boot."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('compat', Path(__file__).with_name('test_wait_readable_compat.py'))
compat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compat)
KERNEL = Path(os.environ['ABSD_KERNEL_SOURCE'])
CAPTURE = Path(__file__).with_name('fixtures').joinpath('wait-readable-old-fsd.log').read_bytes()


class RefusalTests(unittest.TestCase):
    def check(self, text, status=7):
        with tempfile.TemporaryDirectory() as directory:
            serial = Path(directory) / 'serial'
            serial.write_bytes(text)
            compat.verify(KERNEL, serial, status)

    def test_real_old_kernel_refusal(self):
        self.check(CAPTURE)

    def test_wrong_refusal_and_corrupt_chunks(self):
        chunk = next(line for line in CAPTURE.splitlines() if line.startswith(b'EXTERNAL OUTPUT CHUNK'))
        for replacement in [chunk.replace(b'465344', b'465345'),
                            chunk.replace(b'offset=0000000000000000', b'offset=0000000000000001'),
                            chunk + b'0', chunk.replace(b'data=', b'data=z'),
                            chunk + b'\n' + chunk, b'', b'EXTERNAL OUTPUT CHUNK broken']:
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                self.check(CAPTURE.replace(chunk, replacement))

    def test_terminal_and_provenance_controls(self):
        required = [b'USER EXIT pid=2 status=3', b'EXTERNAL OUTPUT BEGIN encoding=hex',
                    b'EXTERNAL WORKLOAD OUTCOME pid=2 status=3',
                    b'init: FAILED at external workload outcome', b'USER EXIT pid=1 status=99',
                    b'EXTERNAL status=99 frames=0 processes=0 cells=0 pipes=0',
                    b'EXTERNAL WORKLOAD FAILED']
        cases = [(CAPTURE, 3), (CAPTURE.replace(b'processes=0', b'processes=1'), 7),
                 (CAPTURE.replace(b'status=99', b'status=3'), 7),
                 (CAPTURE.replace(b'pid=2 status=3', b'pid=2 status=4'), 7)]
        for line in required:
            cases.extend([(CAPTURE.replace(line+b'\n', b''), 7),
                          (CAPTURE + line+b'\n', 7)])
        cases += [(CAPTURE + marker, 7) for marker in [b'FSD READY', b'PANIC', b'KERNEL FAULT',
                  b'RECOVERY WRITABLE RESUMED', b'ABSD BOOT OK', b'EXTERNAL WORKLOAD OK',
                  b'EXTERNAL OUTPUT END bytes=35 digest=deadbeef\n']]
        for text, status in cases:
            with self.subTest(text=text[-160:], status=status), self.assertRaises(ValueError):
                self.check(text, status)

    def test_other_negative_cases_share_init_mapping(self):
        # Derived variants, not runtime evidence: parent emits nothing before
        # failure59; both old/no-probe FSD fail on their required handles.
        chunk = next(line for line in CAPTURE.splitlines(keepends=True)
                     if line.startswith(b'EXTERNAL OUTPUT CHUNK'))
        timer = CAPTURE.replace(chunk, b'').replace(b'pid=2 status=3', b'pid=2 status=59')
        missing_handles = b'FSD FAILED needs the block handle and at least the control channel and one slot\n'
        fsd = CAPTURE.replace(chunk, b'EXTERNAL OUTPUT CHUNK offset=0000000000000000 data='
                              + missing_handles.hex().encode() + b'\n')
        for text, code, expected in [(timer, 59, b''), (fsd, 3, missing_handles)]:
            with tempfile.TemporaryDirectory() as directory:
                serial = Path(directory) / 'serial'
                serial.write_bytes(text)
                compat.verify_failure(KERNEL, serial, 7, code, expected)
                with self.assertRaises(ValueError):
                    compat.verify_failure(KERNEL, serial, 7, code + 1, expected)
                with self.assertRaises(ValueError):
                    compat.verify(KERNEL, serial, 7)

    def test_misordered_output_and_outcomes(self):
        lines = CAPTURE.splitlines(keepends=True)
        chunk = next(line for line in lines if line.startswith(b'EXTERNAL OUTPUT CHUNK'))
        moved = CAPTURE.replace(chunk, b'') + chunk
        with self.assertRaises(ValueError):
            self.check(moved)
        exit_line = b'USER EXIT pid=1 status=99\n'
        with self.assertRaises(ValueError):
            self.check(exit_line + CAPTURE.replace(exit_line, b''))


if __name__ == '__main__':
    unittest.main()
