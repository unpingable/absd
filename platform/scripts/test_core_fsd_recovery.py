"""Small host checks for the recovery fixture's outcome boundary."""

import importlib.util
import os
import pathlib
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("core_fsd_recovery", HERE / "core-fsd-recovery.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class RecoveryBoundary(unittest.TestCase):
    def test_pending_accepts_only_whole_previous_or_candidate(self):
        path = "/home/operator/recovery-pending"
        self.assertEqual(fixture.classify_pending({path: fixture.OLD}), "previous")
        self.assertEqual(fixture.classify_pending({path: fixture.PENDING}), "candidate")
        for content in (None, b"", fixture.OLD[:-1],
                        fixture.OLD[:4096] + fixture.PENDING[4096:]):
            with self.subTest(content=content and len(content)):
                with self.assertRaisesRegex(RuntimeError, "mixed or missing"):
                    fixture.classify_pending({} if content is None else {path: content})

    def test_image_identity_refuses_pathname_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "disk.img"
            path.write_bytes(b"first")
            before = fixture.image_identity(path)
            other = pathlib.Path(directory) / "other.img"
            other.write_bytes(b"first")
            other.replace(path)
            self.assertNotEqual(before, fixture.image_identity(path))

    def test_process_identity_checks_start_time_as_well_as_pid(self):
        pid = os.getpid()
        start = pathlib.Path(f"/proc/{pid}/stat").read_text().split()[21]
        self.assertTrue(fixture.same_process((pid, start)))
        self.assertFalse(fixture.same_process((pid, "0")))


if __name__ == "__main__":
    unittest.main()
