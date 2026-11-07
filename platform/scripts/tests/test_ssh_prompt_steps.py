#!/usr/bin/env python3
"""Drive both native shell drivers over a fresh real PTY, without a VM."""
import importlib.util
import os
from pathlib import Path
import sys
import time
import tty
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('ssh_matrix', ROOT / 'scripts/ssh-matrix.py')
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)
from ssh_absd import AbsdTarget


def producer(mode):
    tty.setraw(0)
    prompt = b'' if mode == 'reference' else b'\x1b[?2004habsd$ '
    os.write(1, prompt)
    for keys, echo in ((b'ech\x03', b'ech^C\r\n'), (b'\x03', b'^C\r\n')):
        if os.read(0, 1024) != keys:
            return 9
        os.write(1, echo)
        time.sleep(.05)
        if mode == 'extra':
            os.write(1, b'unexpected')
        if mode != 'missing':
            os.write(1, prompt)
    if os.read(0, 1024) != b'sshtest sleep 1500\r':
        return 10
    os.write(1, b'sshtest sleep 1500\r\n' + (b'' if mode == 'reference' else b'\x1b[?2004l') + b'slept\r\n' + prompt)
    if os.read(0, 1024) != b'status\r':
        return 11
    os.write(1, b'status\r\n' + (b'' if mode == 'reference' else b'\x1b[?2004l') + b'0\r\n' + prompt)
    return 0


class PromptSteps(unittest.TestCase):
    def exercise(self, driver, mode):
        subject = matrix.Matrix.__new__(matrix.Matrix)
        target = AbsdTarget.__new__(AbsdTarget)
        target.pty_prompt = b'' if mode == 'reference' else b'\x1b[?2004habsd$ '
        subject.t = target
        subject.check = lambda name, good, detail='': self.assertTrue(good, f'{name}: {detail}')
        term = matrix.Terminal([sys.executable, str(Path(__file__).resolve()), '--producer', mode])
        def step(keys, want):
            if driver == 'session-control':
                target.step(subject, term, keys, want, 'offline shell step', timeout=.3)
            else:
                self.assertTrue(subject.pty_shell_step(term, keys, want, timeout=.3))
        try:
            self.assertTrue(term.wait_raw(timeout=3))
            self.assertTrue(term.expect(target.pty_prompt, timeout=3))
            if mode not in ('exact', 'reference'):
                with self.assertRaises(AssertionError):
                    step(b'ech\x03', b'ech^C\r\n')
                return
            step(b'ech\x03', b'ech^C\r\n')
            step(b'\x03', b'^C\r\n')
            step(b'sshtest sleep 1500\r', b'sshtest sleep 1500\r\n' + (b'' if mode == 'reference' else b'\x1b[?2004l') + b'slept\r\n' + target.pty_prompt)
            step(b'status\r', b'status\r\n' + (b'' if mode == 'reference' else b'\x1b[?2004l') + b'0\r\n' + target.pty_prompt)
            self.assertEqual(term.wait(timeout=3), 0)
            self.assertEqual(term.rest(), b'')
        finally:
            term.close()

    def test_both_drivers_wait_for_each_prompt(self):
        for driver in ('interactive', 'session-control'):
            with self.subTest(driver=driver):
                self.exercise(driver, 'exact')

    def test_both_drivers_refuse_missing_prompt(self):
        for driver in ('interactive', 'session-control'):
            with self.subTest(driver=driver):
                self.exercise(driver, 'missing')

    def test_both_drivers_refuse_unexpected_output(self):
        for driver in ('interactive', 'session-control'):
            with self.subTest(driver=driver):
                self.exercise(driver, 'extra')

    def test_reference_shell_does_not_require_native_prompt(self):
        self.exercise('interactive', 'reference')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--producer':
        sys.exit(producer(sys.argv[2]))
    unittest.main()
