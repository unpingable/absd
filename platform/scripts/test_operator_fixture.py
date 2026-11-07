"""Mode and exclusive-creation controls for private operator fixture copies."""

import importlib.util
import os
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("operator_matrix", HERE / "operator-matrix.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class PrivateFixtureCopy(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        for name in (fixture.oi.ISO, fixture.oi.IMAGE, "MANIFEST"):
            (self.source / name).write_bytes(bytes(range(256)))
        (self.source / fixture.oi.IMAGE).chmod(0o600)
        self.output = self.root / "copy"

    def test_private_modes_apply_before_any_image_byte_is_copied(self):
        copy = fixture.shutil.copyfileobj
        observed = []

        def inspect(source, output):
            observed.append((stat.S_IMODE(os.fstat(output.fileno()).st_mode),
                             stat.S_IMODE(self.output.stat().st_mode)))
            copy(source, output)

        previous = os.umask(0o022)
        try:
            with mock.patch.object(fixture.shutil, "copyfileobj", side_effect=inspect):
                fixture.copy_fixture(self.source, self.output)
        finally:
            os.umask(previous)
        self.assertEqual(observed, [(0o600, 0o700)])
        self.assertEqual(stat.S_IMODE((self.output / fixture.oi.IMAGE).stat().st_mode), 0o600)
        for name in (fixture.oi.ISO, fixture.oi.IMAGE, "MANIFEST"):
            self.assertEqual((self.source / name).read_bytes(), (self.output / name).read_bytes())

    def test_existing_destination_refuses_without_overwriting(self):
        self.output.mkdir(mode=0o700)
        sentinel = self.output / fixture.oi.IMAGE
        sentinel.write_bytes(b"existing")
        with self.assertRaises(FileExistsError):
            fixture.copy_fixture(self.source, self.output)
        self.assertEqual(sentinel.read_bytes(), b"existing")

    def test_each_copy_has_its_own_private_directory_and_image(self):
        fixture.copy_fixture(self.source, self.output)
        other = self.root / "repair"
        fixture.copy_fixture(self.output, other)
        self.assertEqual(stat.S_IMODE(other.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((other / fixture.oi.IMAGE).stat().st_mode), 0o600)
        self.assertNotEqual((self.output / fixture.oi.IMAGE).stat().st_ino,
                            (other / fixture.oi.IMAGE).stat().st_ino)


if __name__ == "__main__":
    unittest.main()
