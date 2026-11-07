"""Actual image/snapshot/start consumers with bounded host filesystem records."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
import copy
import importlib.util
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import agent_warm
import cports_warm
import ssh_absd

spec = importlib.util.spec_from_file_location('cports_journal_oracle', ROOT / 'scripts/cports-matrix.py')
cports = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cports)

LEGACY = ('/var/log/fsd', '/var/log/fsd.0', '/var/log/sshd', '/var/log/sshd.0')
JOURNAL = ('/var/log/journal/current', '/var/log/journal/current.0',
           '/var/log/journal/previous', '/var/log/journal/previous.0', '/var/log/journal-health')
LOGS = LEGACY + JOURNAL
PUBLIC = 'ssh-ed25519 AAAAFIXTURE'
OUTPUT = (f'SSH HOST KEY LOADED {PUBLIC} SHA256:fixture\n'
          'SSH STORAGE VIA FILE SERVER OK block=none control=/ssh:ro,/bin:ro,/etc:ro,/var/log:rw,'
          '/var/log/journal:ro,/var/log/journal-health:ro,/var/state:ro,/var/state/facts:rw slots=18\n'
          'SSH ENTROPY OK source=rdrand\nSSH LISTENING port=22\n')


def record(data=b'', *, serial=7, directory=False, readonly=False):
    return {'dir': directory, 'readonly': readonly, 'serial': serial, 'size': len(data), 'data': data}


def initial():
    return {'/etc/motd': record(b'protected', readonly=True),
            '/var/log': record(directory=True), '/var/log/journal': record(directory=True),
            **{path: record(b'old log') for path in LOGS}}


def rotated(before):
    after = copy.deepcopy(before)
    for path in LOGS:
        after[path] = record(b'new boot / rotated bytes', serial=27)
    del after['/var/log/journal/current.0']
    return after


class JournalObjects(unittest.TestCase):
    def filesystem(self, rows):
        return patch.multiple(ssh_absd.absd_fs, fs_region=Mock(return_value=object()),
                              select=Mock(return_value=object()), tree=Mock(return_value=rows),
                              content=Mock(side_effect=lambda region, selected, entry: entry['data']))

    def target(self):
        target = ssh_absd.AbsdTarget.__new__(ssh_absd.AbsdTarget)
        target.image = Path('/unused/image')
        return target

    def views(self, rows):
        target = self.target()
        rehearsal = agent_warm.Rehearsal.__new__(agent_warm.Rehearsal)
        rehearsal.t = SimpleNamespace(target=target)
        with self.filesystem(rows):
            return (target.system_objects(), target.system_digest(),
                    cports_warm.target_state(SimpleNamespace(t=target), None), rehearsal.state())

    def loaded_key_boot(self, before, after):
        target = self.target()
        target.root = ROOT
        target.kernel = ROOT
        target.work = Path('/unused/journal-oracle')
        target.boots = 0
        target.port = 12345
        target.boot_seconds = 1
        target.qemu = ['qemu-system-x86_64']
        target.sshd_iso = Mock(return_value=Path('/unused/journal.iso'))
        target.output = lambda: OUTPUT
        target.serial = lambda: 'FSD HOST KEY PRESENT \nFSD READY\n'
        target.host_public_from_image = lambda: PUBLIC
        with self.filesystem(before), \
             patch.object(ssh_absd.absd_fs, 'tree', side_effect=[before, after]), \
             patch.object(ssh_absd.subprocess, 'Popen', return_value=Mock()), \
             patch.object(ssh_absd, 'end_boots_on_signal'), \
             patch.object(ssh_absd, 'wait_rx_setup'), \
             patch.object(ssh_absd, 'LIVE_BOOTS', set()):
            return target.start()

    def test_exact_log_set_matches_actual_producer_and_retention(self):
        source = (ROOT / 'fsd/src/journal.rs').read_text()
        directory = re.search(r'^pub const DIR: &\[u8\] = b"([^"]+)";', source, re.M).group(1)
        files = re.search(r'^pub const FILES: \[&str; 4\] = \[([^\n]+)\];', source, re.M).group(1)
        names = re.findall(r'"([^"]+)"', files)
        self.assertEqual(set(JOURNAL[:-1]), {directory + '/' + name for name in names})
        self.assertIn('b"/var/log/journal-health"', source)
        self.assertIn('two files for the current boot and two for one previous', (ROOT / 'man/logs.1').read_text())
        self.assertEqual(set(ssh_absd.AbsdTarget.LOGS), set(LOGS))
        self.assertEqual(len(ssh_absd.AbsdTarget.LOGS), 9)

    def test_actual_object_digest_and_warm_snapshots_ignore_only_known_mutable_logs(self):
        before = initial()
        self.assertEqual(self.views(before), self.views(rotated(before)))
        self.assertIn('/var/log/journal', [row[0] for row in self.views(before)[0]])

    def test_actual_loaded_key_boot_allows_documented_log_rotation(self):
        before = initial()
        result = self.loaded_key_boot(before, rotated(before))
        self.assertFalse(result['generated'])
        self.assertFalse(result['image_changed'])

    def test_unexpected_log_paths_and_changed_nonlog_still_fail_all_consumers(self):
        before = initial()
        for path in ('/var/log/unexpected', '/var/log/journal/unexpected', '/var/log/journal/current.new', '/etc/motd'):
            after = rotated(before)
            after[path] = record(b'unexpected change', readonly=path.startswith('/etc/'))
            with self.subTest(path=path):
                for first, second in zip(self.views(before), self.views(after)):
                    self.assertNotEqual(first, second)
                with self.assertRaisesRegex(ssh_absd.Failed, 'files.*changed on a boot'):
                    self.loaded_key_boot(before, after)

    def test_known_log_path_replaced_by_directory_or_readonly_file_is_not_ignored(self):
        before = initial()
        for path in LOGS:
            for directory, readonly in ((True, False), (False, True)):
                after = rotated(before)
                after[path] = record(b'changed shape', directory=directory, readonly=readonly)
                with self.subTest(path=path, directory=directory, readonly=readonly):
                    for first, second in zip(self.views(before), self.views(after)):
                        self.assertNotEqual(first, second)
                    with self.assertRaisesRegex(ssh_absd.Failed, 'files.*changed on a boot'):
                        self.loaded_key_boot(before, after)


class CportsJournalConsumers(unittest.TestCase):
    def fixture(self):
        matrix = cports.CportsMatrix.__new__(cports.CportsMatrix)
        matrix.settle = lambda name, after, accepts: after
        matrix.rest_handles = lambda census: True
        matrix.rest_opens = lambda *args: None
        matrix.check = lambda name, good, detail='': self.assertTrue(good, name + ': ' + str(detail))
        case = SimpleNamespace(name='journal-oracle', cwd='case', outputs=('out',), retained=(), removed=())
        return matrix, case

    def census(self, rows):
        # Feed both actual Cports predicates the actual owning inventory.
        return {'objects': JournalObjects().views(rows)[0], 'images': 0,
                'memory': 'stable frames', 'kernel': 'stable kernel objects', 'fsd': 7}

    def test_actual_case_allowed_output_and_declared_log_rotation_remain_accepted(self):
        matrix, case = self.fixture()
        before = initial()
        for after in (rotated(before), {**before, f'{cports.CPORTS}/case/out': record(b'allowed output')}):
            first, second = self.census(before), self.census(after)
            self.assertTrue(matrix.census_accepts(case, first, second))
            matrix.compare_census(case, first, second, allow_rest_lowering=False)

    def test_actual_cports_predicates_refuse_unknown_log_and_nonlog_changes(self):
        matrix, case = self.fixture()
        before = initial()
        for path in ('/var/log/unexpected', '/var/log/journal/unexpected', '/var/log/journal/current.new', '/etc/motd'):
            after = copy.deepcopy(before)
            after[path] = record(b'unexpected change', readonly=path.startswith('/etc/'))
            first, second = self.census(before), self.census(after)
            with self.subTest(path=path):
                self.assertFalse(matrix.census_accepts(case, first, second))
                with self.assertRaises(AssertionError):
                    matrix.compare_census(case, first, second, allow_rest_lowering=False)

    def test_existing_resource_comparison_is_still_active(self):
        matrix, case = self.fixture()
        before = self.census(initial())
        after = {**before, 'images': 1}
        self.assertFalse(matrix.census_accepts(case, before, after))
        with self.assertRaises(AssertionError):
            matrix.compare_census(case, before, after, allow_rest_lowering=False)


if __name__ == '__main__':
    unittest.main()
