"""Entry refusals run against a declared-tool fixture, before any build."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ITEMS = [line for line in (HERE / "gate-host-items.txt").read_text().splitlines()
         if line and not line.startswith("#")]
COMMANDS = [item for item in ITEMS if item != "xfonts-base"]
FIXTURE = """#!/bin/sh
case ${0##*/} in
  id) printf '%s\\n' "${FIXTURE_UID:-1001}" ;;
  dpkg-query)
    [ "${FIXTURE_FONTS:-installed}" = installed ] || exit 1
    printf 'install ok installed' ;;
  bwrap)
    [ "${FIXTURE_NAMESPACE:-ok}" = ok ] || exit 1
    printf '%s\\n' "${FIXTURE_NAMESPACE_UID:-${FIXTURE_UID:-1001}}" ;;
  timeout) shift; exec "$@" ;;
  *) exit 0 ;;
esac
"""


class Entry(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="absd-entry-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        fixture = self.root / "tool-fixture"
        fixture.write_text(FIXTURE)
        fixture.chmod(0o755)
        for name in COMMANDS:
            (self.bin / name).symlink_to(fixture)
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        for name in ("check-gate-entry.sh", "gate-host-items.txt", "check-all.sh"):
            shutil.copy2(HERE / name, self.scripts / name)

    def run_entry(self, name="check-gate-entry.sh", **overrides):
        env = dict(os.environ, PATH=str(self.bin), **overrides)
        return subprocess.run(["/bin/sh", str(self.scripts / name)], env=env,
                              capture_output=True, text=True, timeout=5)

    def refused(self, result, item):
        self.assertEqual(result.returncode, 2, result)
        self.assertEqual(result.stdout, "")
        self.assertEqual(len(result.stderr.splitlines()), 1, result.stderr)
        self.assertIn("ABSD ENTRY REFUSED", result.stderr)
        self.assertIn(item, result.stderr)

    def test_declared_tool_fixture_reaches_readiness(self):
        result = self.run_entry()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertIn(f"commands={len(COMMANDS)}", result.stdout)
        self.assertIn("bwrap=unprivileged xfonts-base=installed", result.stdout)

    def test_uid_zero_refuses_before_inventory(self):
        (self.scripts / "gate-host-items.txt").unlink()
        self.refused(self.run_entry(FIXTURE_UID="0"), "uid 0")

    def test_missing_bwrap_refuses(self):
        (self.bin / "bwrap").unlink()
        self.refused(self.run_entry(), "bwrap")

    def test_missing_font_package_refuses(self):
        self.refused(self.run_entry(FIXTURE_FONTS="absent"), "xfonts-base")

    def test_namespace_failure_refuses(self):
        self.refused(self.run_entry(FIXTURE_NAMESPACE="failed"), "bwrap")

    def test_namespace_identity_change_refuses(self):
        self.refused(self.run_entry(FIXTURE_NAMESPACE_UID="0"), "bwrap")

    def test_missing_declared_command_is_named(self):
        (self.bin / "llvm-strip-18").unlink()
        self.refused(self.run_entry(), "llvm-strip-18")

    def test_canonical_entry_refuses_before_inputs_build_or_cleanup(self):
        (self.bin / "bwrap").unlink()
        marker = self.root / "unexpected-cleanup"
        (self.scripts / "clean-owned.sh").write_text(f"#!/bin/sh\nprintf invoked >'{marker}'\n")
        (self.scripts / "clean-owned.sh").chmod(0o755)
        self.refused(self.run_entry("check-all.sh"), "bwrap")
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
