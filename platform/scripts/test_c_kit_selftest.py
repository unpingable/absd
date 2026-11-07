"""Run the real host selftest from fresh directories without build products."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SELFTEST = Path(__file__).resolve().with_name("c-kit-matrix-selftest.py")


class Selftest(unittest.TestCase):
    def run_selftest(self, cwd, *args):
        result = subprocess.run([sys.executable, "-B", "-I", "-X", f"pycache_prefix={sys.pycache_prefix or ''}", str(SELFTEST), *map(str, args)],
                                cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("C KIT SELFTEST OK checks=", result.stdout)
        self.assertIn("real +1 after: compare_census fails", result.stdout)
        self.assertIn("cports: shell_ssh (session_probes' path) runs and counts", result.stdout)

    def test_default_needs_no_external_campaign_from_fresh_cwd(self):
        # Catches a default that reads build artifacts outside the fixture.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cwd = root / "cwd"
            cwd.mkdir()
            work = root / "output"
            self.run_selftest(cwd, "--work", work)
            self.assertFalse(list(work.rglob("id_operator")))
            self.assertFalse(list(work.rglob("id_other")))
            self.assertEqual(list(cwd.iterdir()), [])

    def test_explicit_campaign_keeps_read_only_constructor_compatibility(self):
        # Catches writing fixture paths into the caller's campaign.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign = root / "campaign"
            for name in ("cports-build/absd", "cports-build/linux",
                         "upstream/lua-tests/absd/lua-5.4.9-tests"):
                (campaign / name).mkdir(parents=True)
            marker = campaign / "caller-owned.txt"
            marker.write_text("preserve caller input\n")
            before = sorted(p.relative_to(campaign) for p in campaign.rglob("*"))
            self.run_selftest(root, "--campaign", campaign)
            self.assertEqual(sorted(p.relative_to(campaign) for p in campaign.rglob("*")), before)
            self.assertEqual(marker.read_text(), "preserve caller input\n")


if __name__ == "__main__":
    unittest.main()
