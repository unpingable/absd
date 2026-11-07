"""Small host checks for the recovery fixture's outcome boundary."""

import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest import mock

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


class ColdRefusalBoundary(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.image = pathlib.Path(self.directory.name) / "disk.img"
        self.image.write_bytes(b"unchanged disk")
        self.contents = {fixture.BASELINE_PATH: fixture.BASELINE,
                         "/home/operator/recovery-pending": fixture.PENDING}
        self.target = mock.Mock(image=self.image)
        self.target.tree.side_effect = lambda: dict(self.contents)
        self.identity = fixture.image_identity(self.image)

    def run_refusal(self):
        fixture.refuse_recovery(self.target, self.identity, "open_write", fixture.classify_pending)

    def test_uses_strict_plain_fsd_refusal_on_the_interrupted_image(self):
        with mock.patch.object(fixture.fence_guest, "refused_cold_boot", return_value={"log": "refused.serial.log"}) as cold:
            self.run_refusal()
        cold.assert_called_once_with(self.target, "ata", "open_write-refused", served=False)
        self.assertEqual(self.image.read_bytes(), b"unchanged disk")

    def test_wrong_baseline_or_mixed_write_never_reaches_guest_check(self):
        for path, content in [(fixture.BASELINE_PATH, b"changed"),
                              ("/home/operator/recovery-pending", fixture.OLD[:4096] + fixture.PENDING[4096:])]:
            with self.subTest(path=path):
                original = self.contents[path]
                self.contents[path] = content
                try:
                    with mock.patch.object(fixture.fence_guest, "refused_cold_boot") as cold:
                        with self.assertRaises(RuntimeError):
                            self.run_refusal()
                        cold.assert_not_called()
                finally:
                    self.contents[path] = original

    def test_image_pathname_replacement_refuses_even_if_guest_reports_refusal(self):
        def replace(*args, **kwargs):
            replacement = self.image.with_suffix(".new")
            replacement.write_bytes(self.image.read_bytes())
            replacement.replace(self.image)
            return {"log": "refused.serial.log"}
        with mock.patch.object(fixture.fence_guest, "refused_cold_boot", side_effect=replace):
            with self.assertRaisesRegex(RuntimeError, "replaced the disk"):
                self.run_refusal()

    def test_filesystem_change_after_refusal_is_rejected(self):
        def change(*args, **kwargs):
            self.contents["/unrelated"] = b"unexpected"
            return {"log": "refused.serial.log"}
        with mock.patch.object(fixture.fence_guest, "refused_cold_boot", side_effect=change):
            with self.assertRaisesRegex(RuntimeError, "changed filesystem"):
                self.run_refusal()

    def test_guest_oracle_failure_is_preserved(self):
        with mock.patch.object(fixture.fence_guest, "refused_cold_boot", side_effect=RuntimeError("write issued")):
            with self.assertRaisesRegex(RuntimeError, "write issued"):
                self.run_refusal()


if __name__ == "__main__":
    unittest.main()
