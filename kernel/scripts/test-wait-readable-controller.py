import unittest
from pathlib import Path
import subprocess
import sys
import tempfile
import importlib.util
spec = importlib.util.spec_from_file_location('readable_controller', Path(__file__).with_name('check-wait-readable.py'))
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)
EXPECTED = controller.EXPECTED


def validate_terminal(status, text, output_verified):
    # The controller always invokes the real output decoder; a failed output
    # control is represented by a missing frame, not a trusted boolean verdict.
    with tempfile.TemporaryDirectory() as directory:
        serial = Path(directory) / 'serial'
        serial.write_bytes((frame(EXPECTED['supported']) if output_verified else b'') + text)
        try:
            controller.verify(serial, status, 'supported')
        except subprocess.CalledProcessError as error:
            raise ValueError('output decoder rejected frame') from error


def frame(payload):
    digest = 0x811c9dc5
    for byte in payload:
        digest = ((digest ^ byte) * 0x01000193) & 0xffffffff
    return (b'EXTERNAL OUTPUT BEGIN encoding=hex\n'
        + b'EXTERNAL OUTPUT CHUNK offset=0000000000000000 data=' + payload.hex().encode() + b'\n'
        + f'EXTERNAL OUTPUT END bytes={len(payload)} digest={digest:08x}\n'.encode())

GOOD = b'EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0\nEXTERNAL WORKLOAD OK\nABSD BOOT OK\n'


class NativeTerminalTests(unittest.TestCase):
    def test_exact_normal_terminal_accepts_after_canonical_output_check(self):
        validate_terminal(3, GOOD, True)

    def test_missing_records_wrong_exit_failed_output_and_panics_are_rejected(self):
        cases = [(0, GOOD, True), (3, GOOD, False)]
        cases += [(3, GOOD.replace(line + b'\n', b''), True) for line in GOOD.splitlines()]
        cases += [(3, GOOD + text, True) for text in [b'PANIC', b'KERNEL FAULT', b'EXTERNAL WORKLOAD FAILED']]
        cases += [(3, GOOD.replace(b'processes=0', b'processes=1'), True),
                  (3, GOOD.replace(b'pipes=0', b'pipes=1'), True), (3, GOOD + GOOD, True)]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                validate_terminal(*case)

    def test_actual_external_consumer_rejects_wrong_side_and_missing_native_case(self):
        checker = Path(__file__).with_name('check-external-output.py')
        def frame(payload):
            digest = 0x811c9dc5
            for byte in payload:
                digest = ((digest ^ byte) * 0x01000193) & 0xffffffff
            return (b'EXTERNAL OUTPUT BEGIN encoding=hex\n'
                + b'EXTERNAL OUTPUT CHUNK offset=0000000000000000 data=' + payload.hex().encode() + b'\n'
                + f'EXTERNAL OUTPUT END bytes={len(payload)} digest={digest:08x}\n'.encode() + GOOD)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = root / 'expected.bin'
            console = root / 'console.log'
            for mode, payload in EXPECTED.items():
                expected.write_bytes(payload)
                wrong = EXPECTED['supported' if mode == 'absent' else 'absent']
                for observed in [payload, wrong, payload[:-1], payload.replace(b'READABLE EOF PASS\n', b'')]:
                    console.write_bytes(frame(observed))
                    result = subprocess.run([sys.executable, str(checker), str(console), str(expected)],
                                            capture_output=True)
                    self.assertEqual(result.returncode == 0, observed == payload)
                    if observed == payload:
                        validate_terminal(3, GOOD, result.returncode == 0)
                    else:
                        with self.assertRaises(ValueError):
                            validate_terminal(3, GOOD, result.returncode == 0)


class BootLivenessTests(unittest.TestCase):
    GOOD = (b'READABLE PIPE ONLY WAIT\n'
            b'EXTERNAL status=none frames=12 processes=1 cells=0 pipes=1\n'
            b'EXTERNAL WORKLOAD FAILED\n')

    def check(self, text, status=7):
        with tempfile.TemporaryDirectory() as directory:
            serial = Path(directory) / 'serial'
            serial.write_bytes(text)
            controller.verify_boot_liveness(serial, status)

    def test_pipe_only_deadlock_reaches_kernel_terminal(self):
        self.check(self.GOOD)

    def test_broad_liveness_timeout_and_wrong_terminal_are_rejected(self):
        cases = [(b'READABLE PIPE ONLY WAIT\n', 124), (self.GOOD, 3),
                 (self.GOOD.replace(b'status=none', b'status=0'), 7),
                 (self.GOOD.replace(b'processes=1', b'processes=0'), 7),
                 (self.GOOD.replace(b'pipes=1', b'pipes=0'), 7),
                 (self.GOOD.replace(b'frames=12', b'frames=0'), 7),
                 (self.GOOD.replace(b'READABLE PIPE ONLY WAIT\n', b''), 7),
                 (self.GOOD + self.GOOD, 7)]
        cases += [(self.GOOD + marker, 7) for marker in
                  [b'PANIC', b'KERNEL FAULT', b'READABLE WAIT RETURNED', b'ABSD BOOT OK']]
        for text, status in cases:
            with self.subTest(text=text, status=status), self.assertRaises(ValueError):
                self.check(text, status)


if __name__ == '__main__':
    unittest.main()
