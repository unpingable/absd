#!/usr/bin/env python3
"""Exercise actual existing qualification consumers of the new ls time column."""
import importlib.util
from pathlib import Path
import sys
import os
import time
import unittest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


operator = load('operator-matrix.py')
tcc_checks = load('tcc-matrix-selftest.py')
import mtime_reference


class Listing(unittest.TestCase):
    def rotation(self, rows):
        matrix = operator.OperatorMatrix.__new__(operator.OperatorMatrix)
        matrix.ssh = lambda command: (0, b'sshd\nsshd.0\n' if command == 'ls /var/log' else rows, b'')
        def check(name, ok, detail=''):
            if not ok:
                raise AssertionError(name + ': ' + str(detail))
        matrix.check = check
        return matrix.rotation()

    def test_rotation_keeps_the_size_bound_with_known_time(self):
        self.assertEqual(self.rotation(b'- -- 1 65000 2026-10-17 06:00 sshd.0\n- -- 1 100 2026-10-17 06:01 sshd\n'), 0)

    def test_rotation_unknown_time_is_explicit(self):
        self.assertEqual(self.rotation(b'- -- 1 65000 - sshd.0\n- -- 1 100 - sshd\n'), 0)

    def test_rotation_refuses_oversize(self):
        with self.assertRaisesRegex(AssertionError, '64 KiB'):
            self.rotation(b'- -- 1 70000 2026-10-17 06:00 sshd.0\n- -- 1 100 - sshd\n')

    def test_rotation_refuses_missing_or_invalid_time(self):
        for time in ['', 'now ', '2026-10-17 bad-time ']:
            with self.subTest(time=time), self.assertRaisesRegex(AssertionError, 'explicit mtime'):
                self.rotation(('- -- 1 65000 '+time+'sshd.0\n- -- 1 100 - sshd\n').encode())

    def test_root_listing_uses_backing_times_and_preserves_exact_columns(self):
        names = ('bin', 'etc', 'home', 'share', 'tmp', 'var')
        snapshot = {'/'+n: {'mtime': 0} for n in names}
        snapshot['/var']['mtime'] = 1_800_000_000
        expected = (b'd -- 1 0 - bin/\nd -- 1 0 - etc/\nd -- 1 0 - home/\n'
                    b'd -- 1 0 - share/\nd -- 1 0 - tmp/\nd -- 1 0 2027-01-15 08:00 var/\n')
        self.assertEqual(mtime_reference.root_listing(snapshot, lambda p: p), expected)
        old_unknown = b''.join(b'd -- 1 0 - '+n.encode()+b'/\n' for n in names)
        self.assertNotEqual(expected, old_unknown)

    def test_root_listing_resolves_release_backing_objects(self):
        snapshot = {'/'+n: {'mtime': 0} for n in ('etc', 'home', 'tmp', 'var')}
        snapshot['/releases/dev/bin'] = {'mtime': 1}
        snapshot['/releases/dev/share'] = {'mtime': 0}
        physical = lambda p: '/releases/dev'+p if p in ('/bin', '/share') else p
        self.assertTrue(mtime_reference.root_listing(snapshot, physical).startswith(b'd -- 1 0 1970-01-01 00:00 bin/\n'))
        self.assertEqual(mtime_reference.timestamp(0, True), 'unknown')

    def test_reference_time_is_utc_under_a_different_process_timezone(self):
        previous = os.environ.get('TZ')
        try:
            os.environ['TZ'] = 'UTC+7'
            time.tzset()
            self.assertEqual(mtime_reference.timestamp(1_800_000_000), '2027-01-15 08:00')
            self.assertEqual(mtime_reference.timestamp(1_800_000_000, True), '2027-01-15T08:00:00Z')
        finally:
            if previous is None:
                os.environ.pop('TZ', None)
            else:
                os.environ['TZ'] = previous
            time.tzset()

    def test_tcc_keeps_all_refusal_evidence_requirements(self):
        tcc_checks.refusal()


if __name__ == '__main__':
    unittest.main()
