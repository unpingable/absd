"""Host-only byte, length, allocation and independence controls for fixture copies."""
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import media_test_copy


class MediaCopyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="test-media-copy-")
        self.root = Path(self.tmp.name)
        self.source, self.destination = self.root / "source", self.root / "copy"

    def tearDown(self):
        self.tmp.cleanup()

    def check_bytes(self, data):
        self.source.write_bytes(data)
        self.destination.write_bytes(b"old destination" * 100000)
        media_test_copy.copyfile(self.source, self.destination)
        self.assertEqual(self.destination.stat().st_size, len(data))
        self.assertEqual(self.destination.read_bytes(), data)
        self.assertEqual(self.source.read_bytes(), data)

    def test_empty_and_zero_tails_keep_exact_length(self):
        for size in (0, 1, 511, 65535, 65536, 65537, 131073):
            with self.subTest(size=size):
                self.check_bytes(bytes(size))

    def test_mixed_bytes_and_partial_final_blocks_are_exact(self):
        self.check_bytes(b"head" + bytes(130005) + bytes(range(256)) + bytes(37))

    def test_nonzero_file_is_not_discarded(self):
        self.check_bytes(bytes(range(256)) * 1025 + b"tail")

    def test_sparse_image_is_bounded_without_reflinks(self):
        # A regular file, with no clone/reflink/extent-query implementation path.
        with self.source.open("wb") as image:
            image.write(b"header")
            image.seek(17 * 1024 * 1024 + 13)
            image.write(b"middle")
            image.seek(64 * 1024 * 1024 - 1)
            image.write(b"!")
        media_test_copy.copyfile(self.source, self.destination)
        self.assertEqual(self.destination.stat().st_size, self.source.stat().st_size)
        self.assertEqual(hashlib.sha256(self.destination.read_bytes()).digest(),
                         hashlib.sha256(self.source.read_bytes()).digest())
        self.assertLessEqual(self.destination.stat().st_blocks * 512, 1024 * 1024)

    def test_copy_mutation_does_not_change_original(self):
        original = b"header" + bytes(100000) + b"end"
        self.source.write_bytes(original)
        media_test_copy.copyfile(self.source, self.destination)
        with self.destination.open("r+b") as copied:
            copied.seek(70000)
            copied.write(b"changed")
        self.assertEqual(self.source.read_bytes(), original)
        self.assertNotEqual(self.destination.read_bytes(), original)
        self.assertNotEqual(self.source.stat().st_ino, self.destination.stat().st_ino)

    def test_copytree_preserves_names_contents_and_metadata(self):
        tree = self.root / "tree"
        (tree / "nested").mkdir(parents=True)
        item = tree / "nested/image"
        item.write_bytes(b"header" + bytes(100003))
        item.chmod(0o640)
        os.utime(item, ns=(1600000000123456789, 1600000000123456789))
        out = self.root / "out"
        shutil.copytree(tree, out, copy_function=media_test_copy.copy2)
        copied = out / "nested/image"
        self.assertEqual(copied.read_bytes(), item.read_bytes())
        self.assertEqual(copied.stat().st_mode, item.stat().st_mode)
        self.assertEqual(copied.stat().st_mtime_ns, item.stat().st_mtime_ns)

    def test_same_file_and_hardlink_refuse_before_truncating(self):
        self.source.write_bytes(b"keep")
        self.destination.hardlink_to(self.source)
        for destination in (self.source, self.destination):
            with self.subTest(destination=destination), self.assertRaises(shutil.SameFileError):
                media_test_copy.copyfile(self.source, destination)
            self.assertEqual(self.source.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
