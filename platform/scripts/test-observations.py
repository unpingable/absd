#!/usr/bin/env python3
"""Real process/interface CLIs and runtime reader consume the kernel-shared vectors."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class Observations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='absd-observation-cli-')
        cls.out = Path(cls.temp.name)
        env = dict(os.environ, RUSTC_BOOTSTRAP='1')
        library = cls.out / 'libabsd_runtime.rlib'
        subprocess.run(['rustc', '--edition=2024', '--crate-name', 'absd_runtime',
                        '--crate-type=rlib', str(ROOT / 'tests/fixtures/observation_mock_runtime.rs'),
                        '-o', str(library)], env=env, check=True)
        for name in ['ps', 'interfaces']:
            subprocess.run(['rustc', '--edition=2024', str(ROOT / 'src/bin' / (name + '.rs')),
                            '--extern', 'absd_runtime=' + str(library), '-o', str(cls.out / name)],
                           env=env, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_cli(self, name, *args, scenario=''):
        return subprocess.run([str(self.out / name), *args], capture_output=True,
                              env=dict(os.environ, OBSERVATION_MOCK=scenario), timeout=5)

    def test_process_shared_frame_reaches_actual_cli(self):
        for args in [(), ('-A',)]:
            result = self.run_cli('ps', *args)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertRegex(result.stdout, rb'47\s+2\s+waiting\s+pipe\s+1\s+-\s+boot-worker')
            self.assertIn(b'PID identity is scoped to this boot', result.stdout)

    def test_readable_wait_kind_reaches_actual_cli(self):
        result = self.run_cli('ps', scenario='readable-wait')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, rb'47\s+2\s+waiting\s+readable\s+1\s+-\s+boot-worker')

    def test_interface_and_candidate_shared_frames_reach_actual_cli(self):
        result = self.run_cli('interfaces')
        self.assertEqual(result.returncode, 0, result.stderr)
        for line in [b'driver=rtl8125 pci=02:03.1 initialized=yes', b'ticks 900..901',
                     b'disabled=no carrier=up', b'mac: 02:00:00:12:34:56',
                     b'delivered=11 refused=12 missed=13', b'completed=14 refused=15 errors=16',
                     b'02:03.1 10ec:8125 rev=07 selected']:
            self.assertIn(line, result.stdout)

    def test_missing_device_sample_does_not_claim_zero_counters(self):
        result = self.run_cli('interfaces', scenario='unavailable')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'initialized=no', result.stdout)
        self.assertIn(b'disabled=unknown carrier=unknown', result.stdout)
        self.assertIn(b'rx: unknown', result.stdout)
        self.assertIn(b'tx: unknown', result.stdout)
        self.assertNotIn(b'delivered=0', result.stdout)

    def test_denied_and_unknown_versions_refuse_without_a_successful_view(self):
        for name in ['ps', 'interfaces']:
            for scenario, code in [('denied', b'-1'), ('unsupported-version', b'-22')]:
                result = self.run_cli(name, scenario=scenario)
                self.assertEqual(result.returncode, 1)
                expected = ((b'ps: process capacity unavailable code=' + code +
                             b'; no partial census reported\n') if name == 'ps' else
                            b'interfaces: unavailable code=' + code + b'\n')
                self.assertEqual(result.stderr, expected)
                self.assertEqual(result.stdout, b'')
            self.assertEqual(self.run_cli(name, '--unsupported').returncode, 2)

    def test_ap_device_query_reports_named_unsupported_and_process_view_still_works(self):
        result = self.run_cli('interfaces', scenario='ap-unsupported')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertIn(b'interfaces: unsupported', result.stderr)
        self.assertIn(b'BSP', result.stderr)
        self.assertEqual(self.run_cli('ps', '-A', scenario='ap-unsupported').returncode, 0)


if __name__ == '__main__':
    unittest.main()
