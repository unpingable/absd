#!/usr/bin/env python3
"""Run the real staging script in sibling worktrees; preserve foreign inputs."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class StageIsolation(unittest.TestCase):
    def test_stage_never_replaces_sibling_workspace_material(self):
        with tempfile.TemporaryDirectory(prefix="absd-stage-isolation-") as temporary:
            parent = Path(temporary)
            root = parent / "platform"
            for directory in ("scripts", "patches", "ssh"):
                (root / directory).mkdir(parents=True)
            for name in ("scripts/stage-ssh.sh", "patches/sunset-server-channel.patch", "ssh/Cargo.lock"):
                shutil.copy2(ROOT / name, root / name)
            foreign = parent / "absd-std-staged-ssh"
            foreign.mkdir()
            sentinel = foreign / "foreign-owner-evidence"
            sentinel.write_bytes(b"retained by another lane\n")
            result = subprocess.run(["sh", str(root / "scripts/stage-ssh.sh")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(sentinel.exists(), "another worktree's staged inputs were deleted")
            self.assertEqual(sentinel.read_bytes(), b"retained by another lane\n")
            self.assertTrue((root / "ssh/tree/sunset/src/runner.rs").is_file())
            self.assertTrue((root / ".staged-ssh/sunset/src/runner.rs").is_file())

if __name__ == "__main__":
    unittest.main()
