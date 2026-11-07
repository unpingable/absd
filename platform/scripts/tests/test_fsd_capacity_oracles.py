"""Current durable/FSD profile at real builder and matrix callsites; no guest."""
from pathlib import Path
from unittest.mock import Mock, patch
import importlib.util
import os
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import served_kernel
import ssh_absd


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


served = load('served-matrix')
fsd = load('fsd-matrix')
STORAGE = ('SSH STORAGE VIA FILE SERVER OK block=none control=/ssh:ro,/bin:ro,/etc:ro,/var/log:rw,'
           '/var/log/journal:ro,/var/log/journal-health:ro,/var/state:ro,/var/state/facts:rw slots=18\n')


class ReachedStart(Exception):
    pass


class CapacityOracles(unittest.TestCase):
    def matrix_start(self, module, serial, storage=STORAGE):
        target = Mock()
        target.start.return_value = {'generated': True, 'public': 'fixture'}
        target.serial.return_value = serial
        target.output.return_value = storage + 'SSH LISTENING port=22\n'
        cls = module.ServedMatrix if module is served else module.FsdMatrix
        matrix = cls.__new__(cls)
        matrix.t = target
        matrix.start = Mock(return_value={'public': 'fixture'})
        matrix.ram_below_minimum_boot = Mock()
        wanted = ('the served boot starts the file server and sshd as in an fsd boot'
                  if module is served else 'the file server is the one process with the block handle')

        def check(name, good, detail=''):
            self.assertTrue(good, name + ': ' + str(detail))
            if name == wanted:
                raise ReachedStart()

        matrix.check = check
        with tempfile.TemporaryDirectory(prefix='absd-fsd-start-oracle-') as directory:
            matrix.work = Path(directory)
            matrix.op = matrix.work / 'operator'
            matrix.op.with_suffix('.pub').write_text('fixture')
            with patch.object(module.sm, 'Client', return_value=Mock()):
                with self.assertRaises(ReachedStart):
                    matrix.run()

    def test_actual_matrix_start_checks_accept_exact_current_profile(self):
        for module in (served, fsd):
            with self.subTest(matrix=module.__name__):
                self.matrix_start(module, 'FILE SERVER START pid=2 channels=20\nSPAWN OK pid=2 parent=1 program=file-server\n')

    def test_actual_matrix_start_checks_refuse_stale_wrong_logger_and_malformed_records(self):
        for module in (served, fsd):
            for bad in [
                'FILE SERVER START pid=2 channels=11\n',
                'FILE SERVER START pid=2 channels=19\n',
                'FILE SERVER START pid=2 channels=200\n',
                'FILE SERVER START pid=3 channels=20\n',
                'FILE SERVER START pid=2 channels=20 extra\n',
                'FILE SERVER START pid=2 channels=20\n' * 2,
                'FILE SERVER START pid=2 channels=11\nFILE SERVER START pid=2 channels=20\n',
            ]:
                with self.subTest(matrix=module.__name__, record=bad), self.assertRaises(AssertionError):
                    self.matrix_start(module, bad + 'SPAWN OK pid=2 parent=1 program=file-server\n')

    def test_live_fsd_mount_check_requires_current_slots_and_exact_rights(self):
        serial = 'FILE SERVER START pid=2 channels=20\nSPAWN OK pid=2 parent=1 program=file-server\n'
        for bad in [STORAGE.replace('slots=18', 'slots=10'), STORAGE.replace('/journal:ro', '/journal:rw'),
                    STORAGE.replace('/var/log/journal:ro,/var/log/journal-health:ro,', ''),
                    STORAGE.replace('block=none', 'block=present')]:
            with self.subTest(record=bad), self.assertRaises(AssertionError):
                self.matrix_start(fsd, serial, bad)

    def test_exact_profile_distinguishes_optional_logger(self):
        self.assertEqual(served_kernel.FILE_SERVER_SLOTS, 18)
        for logger, good, bad in [(True, 20, 19), (False, 19, 20)]:
            self.assertTrue(served_kernel.file_server_started(f'FILE SERVER START pid=2 channels={good}\n', logger_present=logger))
            self.assertFalse(served_kernel.file_server_started(f'FILE SERVER START pid=2 channels={bad}\n', logger_present=logger))
            self.assertFalse(served_kernel.file_server_started('FILE SERVER START pid=2 channels=11\n', logger_present=logger))

    @unittest.skipUnless(os.environ.get('ABSD_KERNEL_RUN'), 'kernel source conformance input not supplied')
    def test_profile_session_slots_match_owning_kernel_constant(self):
        program = (Path(os.environ['ABSD_KERNEL_RUN']) / 'abi/src/program.rs').read_text()
        values = re.findall(r'^pub const FILE_SERVER_SLOTS: usize = (\d+);$', program, re.M)
        self.assertEqual(len(values), 1, 'owning ABI must declare the profile once')
        self.assertEqual(int(values[0]), served_kernel.FILE_SERVER_SLOTS)

    def test_actual_iso_builders_always_enable_logger_with_file_server(self):
        for cls in (ssh_absd.AbsdTarget, served.ServedTarget):
            with self.subTest(builder=cls.__name__), tempfile.TemporaryDirectory(prefix='absd-fsd-args-') as directory:
                target = cls.__new__(cls)
                target.root = ROOT
                target.kernel = Path(directory) / 'kernel'
                target.work = Path(directory)
                target.storage_fence = None
                server = ROOT / 'absd-fsd.elf'
                with patch.object(ssh_absd.subprocess, 'run') as run:
                    target.iso(0, ROOT / 'sshd.elf', options='net fsd served', server=server)
                    args = run.call_args.args[0]
                    self.assertIn(f'FILE_SERVER_ELF={server}', args)
                    self.assertIn(f'LOGD_ELF={ROOT / "absd-logd.elf"}', args)
                    self.assertIn('LOGD_FAULT=0', args)
                    target.iso(1, ROOT / 'fixture-import.elf')
                    self.assertIn('LOGD_ELF=', run.call_args.args[0])


if __name__ == '__main__':
    unittest.main()
