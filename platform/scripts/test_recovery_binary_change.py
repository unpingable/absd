"""Host controls for candidate P2's explicit guest ELF content difference."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("recovery_candidate", HERE / "recovery-point-matrix.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class Release:
    def __init__(self, path, data=None):
        self.path = path
        self.id = path.name.lower()
        self.path.mkdir()
        self.digests = {}
        if data is not None:
            binary = path / "tree/bin/https-document"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(data)
            self.digests["tree/bin/https-document"] = hashlib.sha256(data).hexdigest()

    def artifact_digests(self):
        return self.digests


class BinaryChange(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.A = Release(self.root / "A", b"\x7fELFA-old")
        self.B = Release(self.root / "B", b"\x7fELFB-new")
        self.name = "tree/bin/https-document"

    def test_different_binary_hashes_are_recorded(self):
        found = native.binary_change(self.A, self.B, self.name)
        self.assertEqual(found["A"]["sha256"], self.A.digests[self.name])
        self.assertEqual(found["B"]["sha256"], self.B.digests[self.name])
        self.assertNotEqual(found["A"], found["B"])

    def test_new_binary_is_a_real_content_addition(self):
        A = Release(self.root / "absent")
        found = native.binary_change(A, self.B, self.name)
        self.assertIsNone(found["A"])
        self.assertEqual(found["B"]["bytes"], len(b"\x7fELFB-new"))

    def test_unchanged_binary_refuses(self):
        B = Release(self.root / "same", b"\x7fELFA-old")
        with self.assertRaisesRegex(RuntimeError, "did not change"):
            native.binary_change(self.A, B, self.name)

    def test_manifest_mismatch_refuses(self):
        (self.B.path / self.name).write_bytes(b"\x7fELFsubstituted")
        with self.assertRaisesRegex(RuntimeError, "differs from its manifest"):
            native.binary_change(self.A, self.B, self.name)

    def test_missing_B_refuses(self):
        B = Release(self.root / "absent")
        with self.assertRaisesRegex(RuntimeError, "B binary is absent"):
            native.binary_change(self.A, B, self.name)

    def test_unrecorded_binary_refuses(self):
        self.B.digests.clear()
        with self.assertRaisesRegex(RuntimeError, "unrecorded"):
            native.binary_change(self.A, self.B, self.name)

    def test_non_ELF_refuses(self):
        B = Release(self.root / "text", b"version label only")
        with self.assertRaisesRegex(RuntimeError, "not ELF"):
            native.binary_change(self.A, B, self.name)

    def test_selected_installed_bytes_are_bound_to_B(self):
        binary = (self.B.path / self.name).read_bytes()
        class Target:
            def tree(inner):
                return {"/releases/b/bin/https-document": binary}
            def selected(inner, tree):
                return "b"
        found = native.installed_binary(Target(), self.B, self.name)
        self.assertEqual(found["sha256"], self.B.digests[self.name])
        self.assertEqual(found["logical_path"], "/bin/https-document")
        self.B.digests[self.name] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "differs from B manifest"):
            native.installed_binary(Target(), self.B, self.name)

    def test_wrong_selected_release_refuses(self):
        class Target:
            def tree(inner): return {}
            def selected(inner, tree): return "a"
        with self.assertRaisesRegex(RuntimeError, "not selected"):
            native.installed_binary(Target(), self.B, self.name)

    def test_missing_selected_binary_refuses(self):
        class Target:
            def tree(inner): return {}
            def selected(inner, tree): return "b"
        with self.assertRaisesRegex(RuntimeError, "absent or not ELF"):
            native.installed_binary(Target(), self.B, self.name)

    def test_non_tree_binary_paths_refuse(self):
        for name in ("../outside", "tree/bin/../sshd", "/bin/sshd", "tree/share/version"):
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "tree/bin"):
                native.binary_change(self.A, self.B, name)


if __name__ == "__main__":
    unittest.main()
