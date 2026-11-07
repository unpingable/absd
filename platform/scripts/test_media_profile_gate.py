"""Exercise the real composition wrapper without building media or starting VMs."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
WRAPPER = ROOT / "scripts/qualification/composition/media-profile.sh"
PRODUCER = """#!/usr/bin/python3 -I
from pathlib import Path
import os
import sys

args = sys.argv[1:]
if args[:2] != ['-I', '-B']:
    sys.exit(91)
script = Path(args[2]).name
if script == 'media.py':
    out = Path(args[args.index('--out') + 1])
    if args[3] == 'operator-image':
        if int(os.environ['PRODUCER_STATUS']):
            sys.exit(int(os.environ['PRODUCER_STATUS']))
        out.mkdir()
    elif args[3] == 'operator-validate':
        if not out.is_dir():
            sys.exit(92)
        (out / 'validated').touch()
    else:
        sys.exit(93)
elif script == 'test_media.py':
    if not (Path(os.environ['ABSD_OPERATOR_FIXTURE']) / 'validated').is_file():
        sys.exit(94)
    if os.environ.get('ABSD_MEDIA_E2E') != '1' or os.environ.get('ABSD_REQUIRE_S4') != '1':
        sys.exit(95)
    print(os.environ['TEST_OUTPUT'])
    sys.exit(int(os.environ['TEST_STATUS']))
else:
    sys.exit(96)
"""


class MediaProfileGate(unittest.TestCase):
    def run_gate(self, output, *, producer_status=0, test_status=0, foreign=False):
        with tempfile.TemporaryDirectory(prefix="absd-media-gate-") as tmp:
            root = Path(tmp)
            run = root / "run"
            for directory in [root / "bin", run / "tools", run / "logs", run / "work"]:
                directory.mkdir(parents=True, exist_ok=True)
            python = root / "bin/python3"
            python.write_text(PRODUCER)
            python.chmod(0o755)
            gate = run / "tools/gate.sh"
            gate.write_text('#!/bin/sh\nif [ "$1" = --list ] && [ "$FOREIGN" = 1 ]; then\n'
                            '  echo "other foreign-fixture"\nfi\nexit 0\n')
            gate.chmod(0o755)
            env = dict(os.environ, PATH=f"{root}/bin:/usr/bin:/bin",
                       ABSD_COMPOSITION_PLATFORM=str(ROOT),
                       ABSD_COMPOSITION_RUN_ROOT=str(run),
                       ABSD_COMPOSITION_PROFILE_KERNEL=str(root / "kernel"),
                       ABSD_COMPOSITION_SOURCE_REVISION="fixture-platform",
                       ABSD_COMPOSITION_KERNEL_COMMIT="fixture-kernel",
                       ABSD_COMPOSITION_KEY=str(root / "fixture-key"),
                       ABSD_COMPOSITION_PROFILE_BOOT_INPUTS=str(root / "inputs"),
                       ABSD_COMPOSITION_PROFILE_BOOT_INPUTS_SHA256="0" * 64,
                       TEST_OUTPUT=output, PRODUCER_STATUS=str(producer_status),
                       TEST_STATUS=str(test_status), FOREIGN="1" if foreign else "0")
            return subprocess.run(["/bin/sh", str(WRAPPER)], env=env,
                                  capture_output=True, text=True, timeout=10)

    def test_complete_74_test_zero_skip_suite_is_accepted(self):
        result = self.run_gate("MEDIA HOST TEST OK cases=74 skipped=0")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_or_extra_test_is_refused(self):
        for count in (73, 75):
            with self.subTest(count=count):
                self.assertNotEqual(self.run_gate(
                    f"MEDIA HOST TEST OK cases={count} skipped=0").returncode, 0)

    def test_skipped_coverage_is_refused(self):
        self.assertNotEqual(self.run_gate("MEDIA HOST TEST OK cases=74 skipped=1").returncode, 0)

    def test_missing_or_malformed_success_marker_is_refused(self):
        for output in ("", "Ran 74 tests\nOK", "MEDIA HOST TEST OK cases=74 skipped=0 trailing",
                       "prefix MEDIA HOST TEST OK cases=74 skipped=0"):
            with self.subTest(output=output):
                self.assertNotEqual(self.run_gate(output).returncode, 0)

    def test_failed_suite_cannot_be_rescued_by_a_success_marker(self):
        self.assertNotEqual(self.run_gate("MEDIA HOST TEST OK cases=74 skipped=0",
                                         test_status=1).returncode, 0)

    def test_failed_image_producer_is_refused(self):
        self.assertNotEqual(self.run_gate("MEDIA HOST TEST OK cases=74 skipped=0",
                                         producer_status=1).returncode, 0)

    def test_foreign_vm_census_is_refused(self):
        self.assertNotEqual(self.run_gate("MEDIA HOST TEST OK cases=74 skipped=0",
                                         foreign=True).returncode, 0)


if __name__ == "__main__":
    unittest.main()
