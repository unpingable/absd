import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("harness_cohort", HERE / "check-harness-cohort.py")
cohort = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cohort)


class MemorySource:
    """Opaque content identities for dependency-graph controls, not Git receipts."""
    def __init__(self, files):
        self.files = {name: content.encode() for name, content in files.items()}

    def blob(self, path):
        return hashlib.sha256(self.files[path]).hexdigest() if path in self.files else None

    def read(self, path):
        return self.files[path]


BASE = {"scripts/ssh_absd.py": "import helper\n",
        "scripts/helper.py": 'import importlib.util\nspec = importlib.util.spec_from_file_location("leaf", here / "leaf.py")\n',
        "scripts/leaf.py": "VALUE = 1\n"}


class Cohort(unittest.TestCase):
    def test_identical_transitive_helpers_pass(self):
        self.assertEqual(cohort.compare(MemorySource(BASE), MemorySource(BASE)), sorted(BASE))

    def test_changed_transitive_leaf_refuses_even_with_same_root(self):
        candidate = BASE | {"scripts/leaf.py": "VALUE = 2\n"}
        with self.assertRaisesRegex(cohort.Refused, "scripts/leaf.py"):
            cohort.compare(MemorySource(BASE), MemorySource(candidate))

    def test_missing_transitive_helper_refuses(self):
        harness = {path: text for path, text in BASE.items() if not path.endswith("leaf.py")}
        with self.assertRaisesRegex(cohort.Refused, "scripts/leaf.py harness=missing"):
            cohort.compare(MemorySource(harness), MemorySource(BASE))

    def test_new_local_module_resolution_is_included(self):
        harness = {"scripts/ssh_absd.py": "import json\n"}
        candidate = harness | {"scripts/json.py": "VALUE = 1\n"}
        with self.assertRaisesRegex(cohort.Refused, "scripts/json.py"):
            cohort.compare(MemorySource(harness), MemorySource(candidate))

    def test_local_package_and_from_import_are_followed(self):
        files = {"scripts/ssh_absd.py": "from package import helper\n",
                 "scripts/package/__init__.py": "",
                 "scripts/package/helper.py": "VALUE = 1\n"}
        self.assertEqual(cohort.compare(MemorySource(files), MemorySource(files)), sorted(files))

    def test_unresolved_importlib_path_refuses(self):
        files = {"scripts/ssh_absd.py": 'spec = importlib.util.spec_from_file_location("helper", selected_path)\n'}
        with self.assertRaisesRegex(cohort.Refused, "unresolved importlib"):
            cohort.compare(MemorySource(files), MemorySource(files))

    def test_absent_root_on_both_sides_is_not_an_empty_pass(self):
        with self.assertRaisesRegex(cohort.Refused, "scripts/ssh_absd.py"):
            cohort.compare(MemorySource({}), MemorySource({}))

    def test_git_context_override_is_refused_without_exposing_its_value(self):
        with mock.patch.dict(os.environ, {"GIT_DIR": "fixture-value-not-a-source"}), \
                self.assertRaises(cohort.Refused) as raised:
            cohort.Source(HERE.parent, "0" * 40)
        self.assertIn("GIT_DIR", str(raised.exception))
        self.assertNotIn("fixture-value", str(raised.exception))

    def test_parent_repository_discovery_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="absd-cohort-root-") as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "--quiet", "--template=", str(root)], check=True)
            nested = root / "not-the-source-root"
            nested.mkdir()
            with self.assertRaisesRegex(cohort.Refused, "exact checkout root"):
                cohort.Source(nested, "0" * 40)

    def test_replacement_refs_cannot_hide_a_changed_imported_helper(self):
        with tempfile.TemporaryDirectory(prefix="absd-cohort-replacement-") as temporary:
            sources = []
            for index in (1, 2):
                root = Path(temporary) / str(index)
                subprocess.run(["git", "init", "--quiet", "--template=", str(root)], check=True)

                def git(*args, data=None):
                    return subprocess.check_output(
                        ["git", "-C", str(root), "-c", "core.hooksPath=/dev/null",
                         "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                         "-c", "commit.gpgsign=false", *args], input=data)

                (root / "scripts").mkdir()
                (root / "scripts/ssh_absd.py").write_text("import leaf\n")
                (root / "scripts/leaf.py").write_text(f"VALUE = {index}\n")
                git("add", "scripts")
                git("commit", "--quiet", "-m", "local fixture")
                revision = git("rev-parse", "HEAD").decode().strip()
                original = git("rev-parse", "HEAD:scripts/ssh_absd.py").decode().strip()
                replacement = git("hash-object", "-w", "--stdin", data=b"# no imports\n").decode().strip()
                git("replace", original, replacement)
                self.assertEqual(git("cat-file", "blob", original), b"# no imports\n")
                self.assertEqual(git("status", "--porcelain=v1"), b"")
                self.assertEqual(git("rev-parse", "HEAD").decode().strip(), revision)
                sources.append(cohort.Source(root, revision))
            with self.assertRaisesRegex(cohort.Refused, "scripts/leaf.py"):
                cohort.compare(*sources)


if __name__ == "__main__":
    unittest.main()
