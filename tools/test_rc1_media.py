import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("rc1_media", Path(__file__).with_name("rc1_media.py"))
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "public"
        self.source = self.root / "kernel"
        self.source.mkdir(parents=True)
        (self.source / ".gitignore").write_text("/build\n")
        (self.source / "Makefile").write_text("all:\n\ttrue\n")
        adapter.git(self.root, "init", "-q")
        adapter.git(self.root, "add", ".")
        adapter.git(self.root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                    "commit", "-qm", "local source fixture")
        self.entry = dict(path="kernel", commit="1" * 40,
                          tree=adapter.git(self.root, "rev-parse", "HEAD:kernel").decode().strip())

    def verify(self, path=None, copy=False):
        return adapter.verify_snapshot(self.root, self.entry, path or self.source, kernel_copy=copy)

    def test_clean_component_and_ignored_build_output(self):
        (self.source / "build").mkdir()
        (self.source / "build/kernel").write_bytes(b"reproducible build output")
        self.assertEqual(self.verify(), self.entry["tree"])

    def test_mutation_and_untracked_source_refuse(self):
        (self.source / "Makefile").write_text("all:\n\tfalse\n")
        with self.assertRaisesRegex(ValueError, "source bytes or mode changed"):
            self.verify()
        adapter.git(self.root, "checkout", "--", "kernel/Makefile")
        (self.source / "extra.rs").write_text("new source")
        with self.assertRaisesRegex(ValueError, "untracked source"):
            self.verify()

    def test_manifest_tree_mismatch_refuses(self):
        self.entry["tree"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "committed component"):
            self.verify()

    def test_kernel_copy_and_identity_change(self):
        copy = Path(self.temp.name) / "run"
        shutil.copytree(self.source, copy)
        (copy / ".absd-identity").write_text(self.entry["commit"] + "\n")
        self.assertEqual(self.verify(copy, True), self.entry["tree"])
        (copy / ".absd-identity").write_text("2" * 40)
        with self.assertRaisesRegex(ValueError, "copy identity"):
            self.verify(copy, True)

    def test_different_location_symlink_and_copy_checkout_refuse(self):
        copy = Path(self.temp.name) / "run"
        shutil.copytree(self.source, copy)
        with self.assertRaisesRegex(ValueError, "location"):
            self.verify(copy)
        link = Path(self.temp.name) / "link"
        link.symlink_to(self.source, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "real directory"):
            self.verify(link)
        (copy / ".git").mkdir()
        with self.assertRaisesRegex(ValueError, "different checkout"):
            self.verify(copy, True)

    def test_local_clean_filter_cannot_hide_source_mutation(self):
        (self.root / ".git/info/attributes").write_text("Makefile filter=fixture\n")
        adapter.git(self.root, "config", "filter.fixture.clean", "sed s/false/true/g")
        (self.source / "Makefile").write_text("all:\n\tfalse\n")
        with self.assertRaisesRegex(ValueError, "source bytes or mode changed"):
            self.verify()

    def test_local_exclude_cannot_hide_cargo_configuration(self):
        (self.root / ".git/info/exclude").write_text("kernel/.cargo/\n")
        (self.source / ".cargo").mkdir()
        (self.source / ".cargo/config.toml").write_text('[build]\nrustflags=["--cfg=fixture"]\n')
        with self.assertRaisesRegex(ValueError, "untracked source"):
            self.verify()

    def test_file_mode_and_output_symlink_refuse(self):
        (self.source / "Makefile").chmod(0o755)
        with self.assertRaisesRegex(ValueError, "mode changed"):
            self.verify()
        (self.source / "Makefile").chmod(0o644)
        (self.source / "build").symlink_to(self.temp.name, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "output directory is a symlink"):
            self.verify()

    def test_bytecode_cache_is_not_an_allowed_source_output(self):
        cache = self.source / "scripts/__pycache__"
        cache.mkdir(parents=True)
        (cache / "example.cpython-312.pyc").write_bytes(b"cached code is not source")
        with self.assertRaisesRegex(ValueError, "untracked source"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
