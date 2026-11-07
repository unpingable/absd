"""Finite real-process controls for the localhost SSH capture's owned cleanup."""
from pathlib import Path
import importlib.util
import os
import select
import signal
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('priority', Path(__file__).with_name('test-ssh-priority.py'))
priority = importlib.util.module_from_spec(spec)
spec.loader.exec_module(priority)


class Cleanup(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='absd-priority-cleanup-')
        self.private = Path(self.temp.name)/'private'
        self.private.mkdir()
        (self.private/'sentinel').write_text('ordinary fixture, not a credential')
        self.children = []

    def tearDown(self):
        # Independent emergency cleanup also makes a failing regression finite.
        for child in self.children:
            if child.returncode is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            child.wait(timeout=3)
            if child.stdout:
                child.stdout.close()
        self.temp.cleanup()

    def child(self, ignores_term):
        code = ('import pathlib,signal,time\n'
                f'private=pathlib.Path({str(self.private)!r})\n')
        if ignores_term:
            code += ('signal.signal(signal.SIGTERM, lambda *_: '
                     'print("TERM key_exists="+str(private.exists()),flush=True))\n')
        code += 'print("ready",flush=True)\n'
        if ignores_term:
            code += 'time.sleep(60)\n'
        child = subprocess.Popen([sys.executable, '-u', '-c', code],
                                 stdout=subprocess.PIPE, start_new_session=True)
        self.children.append(child)
        self.assertTrue(select.select([child.stdout], [], [], 3)[0])
        self.assertEqual(child.stdout.readline(), b'ready\n')
        return child

    def test_term_ignoring_server_is_killed_reaped_before_key_retirement(self):
        child = self.child(True)
        result = priority.finish_server_keys(child, self.private, .05, 1)
        self.assertEqual(child.returncode, -signal.SIGKILL)
        self.assertTrue(result['kill_sent'])
        self.assertFalse(priority.group_exists(child.pid))
        self.assertIn(b'TERM key_exists=True', child.stdout.read())
        self.assertFalse(self.private.exists())

    def test_already_exited_group_race_still_waits_and_retires_keys(self):
        child = self.child(False)
        self.assertEqual(child.wait(timeout=3), 0)
        result = priority.finish_server_keys(child, self.private, .05, 1)
        self.assertEqual(result['returncode'], 0)
        self.assertFalse(result['term_sent'])
        self.assertFalse(result['kill_sent'])
        self.assertFalse(self.private.exists())

    def test_assertion_failure_still_ends_owned_server_before_retiring_keys(self):
        child = self.child(True)
        with self.assertRaisesRegex(AssertionError, 'fixture assertion'):
            try:
                raise AssertionError('fixture assertion')
            finally:
                priority.finish_server_keys(child, self.private, .05, 1)
        self.assertIsNotNone(child.returncode)
        self.assertFalse(priority.group_exists(child.pid))
        self.assertFalse(self.private.exists())

    def test_real_wait_timeout_still_ends_server_and_preserves_the_exception(self):
        child = self.child(True)
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            try:
                child.wait(timeout=.01)
            finally:
                priority.finish_server_keys(child, self.private, .05, 1)
        self.assertEqual(caught.exception.timeout, .01)
        self.assertIsNotNone(child.returncode)
        self.assertFalse(priority.group_exists(child.pid))
        self.assertFalse(self.private.exists())


if __name__ == '__main__':
    unittest.main()
