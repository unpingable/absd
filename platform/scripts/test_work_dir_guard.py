#!/usr/bin/env python3
"""Host test for absd_work_dir in scripts/inputs.sh: work directories taken from
the environment (ABSD_SERVED_WORK, ABSD_LINK_WORK, ABSD_FENCE_WORK,
ABSD_CORE_FSD_WORK) are emptied with rm -rf, so the guard must refuse paths
that are not this tooling's own. Runs the real shell function with HOME set to
a temporary directory; nothing outside that directory is touched."""
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def guard(work, default, home):
    script = '. "$root/scripts/inputs.sh"; absd_work_dir "$1" "$2"'
    env = dict(os.environ, HOME=str(home), root=str(ROOT))
    return subprocess.run(["sh", "-c", script, "guard", str(work), str(default)], env=env,
                          capture_output=True, text=True, cwd=ROOT)


class WorkDirGuard(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name)
        self.home = self.base / "home" / "user"
        self.home.mkdir(parents=True)
        self.default = ROOT / ".served-work"

    def tearDown(self):
        self.tmp.cleanup()

    def refused(self, work, reason):
        result = guard(work, self.default, self.home)
        self.assertEqual(result.returncode, 2, (work, result.stdout, result.stderr))
        self.assertIn("refusing work directory", result.stderr)
        self.assertIn(reason, result.stderr)

    def accepted(self, work, default=None):
        result = guard(work, default or self.default, self.home)
        self.assertEqual(result.returncode, 0, (work, result.stderr))

    def test_refuses_root_relative_home_and_ancestors(self):
        self.refused("/", "is /")
        self.refused("relative/work", "not an absolute path")
        self.refused(self.home, "$HOME or one of its ancestors")
        self.refused(self.home.parent, "$HOME or one of its ancestors")
        self.refused(f"{self.home}/../../home", "$HOME or one of its ancestors")

    def test_refuses_this_tree_and_its_ancestors(self):
        self.refused(ROOT, "this platform tree or one of its ancestors")
        self.refused(ROOT.parent, "this platform tree or one of its ancestors")

    def test_refuses_foreign_non_empty_directory(self):
        foreign = self.base / "foreign"
        foreign.mkdir()
        (foreign / "precious").write_text("keep me\n")
        self.refused(foreign, "non-empty directory without the .absd-work marker")
        self.assertTrue((foreign / "precious").exists())

    def test_refuses_symlink_and_file(self):
        target = self.base / "target"
        target.mkdir()
        link = self.base / "link"
        link.symlink_to(target)
        self.refused(link, "is a symbolic link")
        plain = self.base / "plain"
        plain.write_text("x")
        self.refused(plain, "exists and is not a directory")

    def test_accepts_fresh_empty_and_marked(self):
        self.accepted(self.base / "fresh" / "work")
        empty = self.base / "empty"
        empty.mkdir()
        self.accepted(empty)
        marked = self.base / "marked"
        marked.mkdir()
        (marked / ".absd-work").write_text("")
        (marked / "ssh.img").write_text("old run")
        self.accepted(marked)

    def test_default_stays_trusted_without_marker(self):
        default = self.base / "platform" / ".served-work"
        default.mkdir(parents=True)
        (default / "ssh.img").write_text("from before the marker")
        self.accepted(default, default=default)

    def test_mark_work_writes_marker(self):
        work = self.base / "made"
        work.mkdir()
        (work / "file").write_text("x")
        env = dict(os.environ, HOME=str(self.home), root=str(ROOT))
        subprocess.run(["sh", "-c", '. "$root/scripts/inputs.sh"; absd_mark_work "$1"', "m", str(work)],
                       env=env, check=True, cwd=ROOT)
        self.assertTrue((work / ".absd-work").is_file())
        self.accepted(work)


if __name__ == "__main__":
    unittest.main()
