#!/usr/bin/env python3
"""Real PTY/matcher regression; guest output and kernel records are fixtures.

This checks the driver, not kernel enforcement. Native enforcement still needs
the separately admitted matrix occurrence.
"""
import importlib.util
import os
from pathlib import Path
import re
import select
import sys
import tempfile
import tty
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('ssh_matrix', ROOT / 'scripts/ssh-matrix.py')
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)
from ssh_absd import AbsdTarget

SCRIPT = b'absd-sh -c "sshtest sleep 15000"'
NATIVE = b'fsd-probe spawn /bin/fsd-probe block'


def producer(mode, directory):
    tty.setraw(0)
    serial = Path(directory) / 'kernel.serial'
    os.write(1, b'\x1b[?2004habsd$ ')
    def line(want):
        got = bytearray()
        while not got.endswith(b'\r'):
            if not select.select([0], [], [], 1)[0]:
                return False
            got.extend(os.read(0, 1))
        return got == want + b'\r'
    def child(pid, status=0):
        with serial.open('a') as out:
            out.write(f'SPAWN OK pid={pid} parent=38 program=image\nUSER EXIT pid={pid} status={status}\n')
    if not line(SCRIPT):
        return 8
    child(41)
    # Completed-script output plus the current native mode boundaries.
    os.write(1, SCRIPT + b'\r\n\x1b[?2004lslept\r\n\x1b[?2004habsd$ ')
    if not line(b'status'):
        return 9
    status = b'7' if mode == 'script-failed' else b'0'
    os.write(1, b'status\r\n\x1b[?2004l' + status + b'\r\n\x1b[?2004habsd$ ')
    if not line(NATIVE):
        return 10
    child(42, 1)
    if mode == 'grandchild':
        with serial.open('a') as out:
            out.write('SPAWN OK pid=43 parent=42 program=image\nUSER EXIT pid=43 status=0\n')
    reason = b'not found' if mode == 'wrong-refusal' else b'permission denied'
    os.write(1, NATIVE + b'\r\n\x1b[?2004lspawn: /bin/fsd-probe: ' + reason
             + b'\r\nabsd-sh: fsd-probe: exit status 1\r\n\x1b[?2004habsd$ ')
    if not line(b'status'):
        return 11
    os.write(1, b'status\r\n\x1b[?2004l1\r\n\x1b[?2004habsd$ ')
    return 0


class ProcessAuthority(unittest.TestCase):
    def exercise(self, mode):
        with tempfile.TemporaryDirectory(prefix='ssh-authority-driver-') as directory:
            target = AbsdTarget.__new__(AbsdTarget)
            target.log = Path(directory) / 'kernel.serial'
            target.log.write_text('SPAWN OK pid=38 parent=3 program=image\n')
            subject = matrix.Matrix.__new__(matrix.Matrix)
            subject.t = target
            subject.check = lambda name, good, detail='': self.assertTrue(good, f'{name}: {detail}')
            term = matrix.Terminal([sys.executable, str(Path(__file__).resolve()), '--producer', mode, directory])
            expect = term.expect
            term.expect = lambda want, timeout=60: expect(want, timeout=min(timeout, .3))
            try:
                self.assertTrue(term.wait_raw(timeout=3))
                self.assertTrue(term.expect(target.pty_prompt, timeout=3))
                if mode == 'exact':
                    target.check_process_authority(subject, term)
                    self.assertEqual(term.wait(timeout=3), 0)
                    self.assertEqual(term.rest(), b'')
                else:
                    check = {
                        'grandchild': 'only the native probe starts; no grandchild is created',
                        'wrong-refusal': "a native command's spawn request is refused by permission",
                        'script-failed': 'the interpreted script exits with status zero',
                    }[mode]
                    with self.assertRaisesRegex(AssertionError, re.escape(check)):
                        target.check_process_authority(subject, term)
            finally:
                term.close()

    def test_interpreted_success_and_native_spawn_refusal(self):
        self.exercise('exact')

    def test_native_grandchild_is_not_accepted(self):
        self.exercise('grandchild')

    def test_an_unrelated_refusal_is_not_permission_evidence(self):
        self.exercise('wrong-refusal')

    def test_nonzero_interpreted_command_is_not_accepted(self):
        self.exercise('script-failed')


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--producer':
        sys.exit(producer(sys.argv[2], sys.argv[3]))
    unittest.main()
