"""Clean host-key test reboots must not turn a refused halt into a restart."""
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import ssh_absd
import storage_fence_state as guard

spec = importlib.util.spec_from_file_location('ssh_matrix_clean_halt', SCRIPTS/'ssh-matrix.py')
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)


class CleanHalt(unittest.TestCase):
    def target(self, output=b'3\n', status=0, serial='FSD SHUTDOWN FINALIZED status=0\n', state='clean'):
        target = object.__new__(ssh_absd.AbsdTarget)
        target.proc = Mock(returncode=status)
        target.proc.communicate.return_value = (output, None)
        target.serial = Mock(return_value=serial)
        target.tree = Mock(return_value={} if state is None else {guard.PATH: guard.encode(state)})
        return target

    def test_clean_halt(self):
        target = self.target()
        target.wait_clean_halt()
        target.proc.communicate.assert_called_once_with(timeout=300)
        target.tree.assert_called_once_with()

    def test_all_bad_terminal_outputs_refused(self):
        for output in [b'', b'7\n', b'0\n', b'3\n7\n']:
            with self.subTest(output=output), self.assertRaises(ssh_absd.Failed):
                self.target(output=output).wait_clean_halt()

    def test_wrapper_failure_refused(self):
        with self.assertRaises(ssh_absd.Failed):
            self.target(status=1).wait_clean_halt()

    def test_missing_finalization_refused(self):
        for serial in ['', 'FSD SHUTDOWN FINALIZED status=1\n']:
            with self.subTest(serial=serial), self.assertRaises(ssh_absd.Failed):
                self.target(serial=serial).wait_clean_halt()

    def test_guard_must_be_clean(self):
        for state in ['fresh', 'dirty', None]:
            with self.subTest(state=state), self.assertRaises(ssh_absd.Failed):
                self.target(state=state).wait_clean_halt()

    def test_finalization_requires_one_exact_record(self):
        for serial in [
            'FSD SHUTDOWN FINALIZED status=01\n',
            'diagnostic: FSD SHUTDOWN FINALIZED status=0\n',
            'FSD SHUTDOWN FINALIZED status=0\nFSD SHUTDOWN FINALIZED status=1\n',
            'FSD SHUTDOWN FINALIZED status=0\nFSD SHUTDOWN FINALIZED status=0\n',
            'FSD SHUTDOWN FINALIZED status=0 extra\n',
            'FSD SHUTDOWN FINALIZED status=0\nFSD SHUTDOWN FINALIZE FAILED step=finalize timeout\n',
            'FSD SHUTDOWN FINALIZE FAILED step=finalize timeout\nFSD SHUTDOWN FINALIZED status=0\n',
        ]:
            with self.subTest(serial=serial), self.assertRaises(ssh_absd.Failed):
                self.target(serial=serial).wait_clean_halt()

    def test_malformed_guard_refused(self):
        target = self.target()
        target.tree.return_value = {guard.PATH: b'absd-writable v1 clean\n'}
        with self.assertRaises(ssh_absd.Failed):
            target.wait_clean_halt()

    def test_timeout_never_stops_or_restarts(self):
        target = self.target()
        target.proc.communicate.side_effect = subprocess.TimeoutExpired('boot', 300)
        target.stop = Mock()
        target.start = Mock()
        with self.assertRaises(subprocess.TimeoutExpired):
            target.wait_clean_halt()
        target.stop.assert_not_called()
        target.start.assert_not_called()

    def test_missing_boot_refused(self):
        target = self.target()
        target.proc = None
        with self.assertRaises(ssh_absd.Failed):
            target.wait_clean_halt()


class RestartOrdering(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.work = Path(self.scratch.name)
        self.events = []
        self.target = Mock(port=12345)
        self.target.wait_clean_halt.side_effect = lambda: self.events.append('halt')
        self.target.restart.side_effect = lambda **kw: self.events.append(('restart', kw)) or {'public': 'current'}
        self.m = object.__new__(matrix.Matrix)
        self.m.t = self.target
        self.m.work = self.work
        self.m.op = self.work/'existing-operator-key'
        self.m.checks = 10
        self.m.client = matrix.Client(self.work, self.target.port)
        self.m.client.trust('previous-key')

    def request(self, client, key, command):
        self.assertEqual(key, self.m.op)
        self.assertEqual(command, 'shutdown')
        self.assertEqual(client.known_hosts.read_text(), '[127.0.0.1]:12345 current-key\n')
        self.events.append('request')
        return 0, b'', b''

    def restart(self, result=None):
        with contextlib.redirect_stdout(io.StringIO()), patch.object(matrix.Client, 'run', autospec=True, side_effect=self.request if result is None else lambda *a: result):
            return self.m.restart('current-key', regenerate=True)

    def test_request_halt_then_restart_and_trust_isolation(self):
        self.assertEqual(self.restart(), {'public': 'current'})
        self.assertEqual(self.events, ['request', 'halt', ('restart', {'regenerate': True})])
        self.assertEqual(self.m.client.known_hosts.read_text(), '[127.0.0.1]:12345 previous-key\n')

    def test_failed_shutdown_request_does_not_restart(self):
        with self.assertRaises(matrix.Failed):
            self.restart(result=(255, b'', b'refused'))
        self.target.wait_clean_halt.assert_not_called()
        self.target.restart.assert_not_called()

    def test_failed_halt_does_not_restart(self):
        self.target.wait_clean_halt.side_effect = ssh_absd.Failed('dirty guard')
        with self.assertRaises(ssh_absd.Failed):
            self.restart()
        self.target.restart.assert_not_called()

    def test_final_clean_halt_does_not_reboot(self):
        with contextlib.redirect_stdout(io.StringIO()), patch.object(matrix.Client, 'run', autospec=True, side_effect=self.request):
            self.m.clean_halt('current-key')
        self.assertEqual(self.events, ['request', 'halt'])
        self.target.restart.assert_not_called()
        self.assertEqual(self.m.client.known_hosts.read_text(), '[127.0.0.1]:12345 previous-key\n')

    def test_linux_restart_has_no_guest_shutdown(self):
        self.m.t = Mock(spec=matrix.LinuxTarget)
        with patch.object(matrix.Client, 'run') as request:
            self.m.restart('current-key')
        request.assert_not_called()
        self.m.t.restart.assert_called_once_with(regenerate=False)


if __name__ == '__main__':
    unittest.main()
