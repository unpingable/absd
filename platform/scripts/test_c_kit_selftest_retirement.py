"""Lifecycle controls use dummy text files, never usable SSH identities."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("selftest_retirement", HERE / "c-kit-matrix-selftest.py")
selftest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(selftest)


def fixture_key(work):
    directory = work / "cports"
    directory.mkdir(exist_ok=True)
    key = directory / "id_operator"
    key.write_text("dummy local retirement fixture; not an SSH key\n")
    key.chmod(0o600)
    key.with_suffix(".pub").write_text("dummy public fixture\n")
    (work / "result.txt").write_text("inspectable fixture result\n")
    return key


class Retirement(unittest.TestCase):
    def test_default_success_retires_entire_temporary_directory(self):
        with selftest.selftest_work(None) as work:
            key = fixture_key(work)
            self.assertTrue(key.exists())
        self.assertFalse(work.exists())

    def test_default_failure_retires_entire_temporary_directory(self):
        with self.assertRaisesRegex(RuntimeError, "constructor failed"):
            with selftest.selftest_work(None) as work:
                fixture_key(work)
                raise RuntimeError("constructor failed")
        self.assertFalse(work.exists())

    def test_explicit_success_retires_private_file_and_preserves_results(self):
        with tempfile.TemporaryDirectory() as parent:
            with selftest.selftest_work(Path(parent) / "work") as work:
                key = fixture_key(work)
            self.assertTrue(work.is_dir())
            self.assertFalse(key.exists())
            self.assertEqual(key.with_suffix(".pub").read_text(), "dummy public fixture\n")
            self.assertEqual((work / "result.txt").read_text(), "inspectable fixture result\n")

    def test_explicit_partial_constructor_failure_retires_private_file(self):
        with tempfile.TemporaryDirectory() as parent:
            with self.assertRaises(SystemExit):
                with selftest.selftest_work(Path(parent) / "work") as work:
                    key = fixture_key(work)
                    raise SystemExit(1)
            self.assertFalse(key.exists())
            self.assertTrue((work / "result.txt").exists())

    def test_nonempty_explicit_directory_is_preserved_and_refused(self):
        with tempfile.TemporaryDirectory() as parent:
            work = Path(parent)
            key = fixture_key(work)
            before = key.read_bytes(), key.stat().st_ino
            with self.assertRaisesRegex(ValueError, "empty directory"):
                with selftest.selftest_work(work):
                    self.fail("nonempty caller directory was admitted")
            self.assertEqual((key.read_bytes(), key.stat().st_ino), before)

    def test_new_linked_file_is_refused_without_altering_its_other_name(self):
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as parent:
                root = Path(parent)
                original = root / "other-owner-fixture"
                original.write_text("preserve this dummy text\n")
                with self.assertRaisesRegex(RuntimeError, "unexpected key file"):
                    with selftest.selftest_work(root / "work") as work:
                        key = work / "id_operator"
                        if kind == "symlink":
                            key.symlink_to(original)
                        else:
                            os.link(original, key)
                self.assertEqual(original.read_text(), "preserve this dummy text\n")

    def test_termination_signals_retire_private_file_and_restore_handlers(self):
        for sig in (signal.SIGHUP, signal.SIGTERM):
            with self.subTest(signal=sig), tempfile.TemporaryDirectory() as parent:
                previous = signal.getsignal(sig)
                with self.assertRaises(SystemExit) as raised:
                    with selftest.selftest_work(Path(parent) / "work") as work:
                        key = fixture_key(work)
                        signal.raise_signal(sig)
                self.assertEqual(raised.exception.code, 128 + sig)
                self.assertFalse(key.exists())
                self.assertIs(signal.getsignal(sig), previous)

    def test_retirement_failure_still_attempts_the_remaining_private_files(self):
        with tempfile.TemporaryDirectory() as parent:
            run = subprocess.run

            def retire(argv, **kwargs):
                if argv[-1].endswith("id_first"):
                    raise subprocess.CalledProcessError(1, argv)
                return run(argv, **kwargs)

            with mock.patch.object(selftest.subprocess, "run", side_effect=retire), \
                    self.assertRaisesRegex(RuntimeError, "key retirement failed"):
                with selftest.selftest_work(Path(parent) / "work") as work:
                    first, second = work / "id_first", work / "id_second"
                    first.write_text("dummy first file\n")
                    second.write_text("dummy second file\n")
            self.assertTrue(first.exists())
            self.assertFalse(second.exists())

    def test_main_cleans_up_after_partial_constructor_failure(self):
        with tempfile.TemporaryDirectory() as parent:
            work = Path(parent) / "work"

            def failed(want, campaign, owned):
                fixture_key(owned)
                raise RuntimeError("partial constructor failed")

            output = io.StringIO()
            with mock.patch.object(selftest, "subclasses", side_effect=failed), \
                    mock.patch("sys.argv", [str(HERE / "c-kit-matrix-selftest.py"), "--work", str(work)]), \
                    contextlib.redirect_stdout(output), self.assertRaisesRegex(RuntimeError, "partial constructor"):
                selftest.main()
            self.assertFalse((work / "cports/id_operator").exists())
            self.assertNotIn("C KIT SELFTEST OK", output.getvalue())
            self.assertIn("control: sysinfo opened before quiescence", output.getvalue())

    def test_actual_missing_campaign_failure_cleans_up_default_directory(self):
        with tempfile.TemporaryDirectory() as parent:
            created = []
            factory = tempfile.TemporaryDirectory

            def temporary(*args, **kwargs):
                instance = factory(*args, **kwargs)
                created.append(Path(instance.name))
                return instance

            with mock.patch.object(selftest.tempfile, "TemporaryDirectory", side_effect=temporary), \
                    mock.patch("sys.argv", [str(HERE / "c-kit-matrix-selftest.py"), "--campaign", parent]), \
                    contextlib.redirect_stdout(io.StringIO()), self.assertRaises(FileNotFoundError):
                selftest.main()
            self.assertEqual(len(created), 1)
            self.assertFalse(created[0].exists())


if __name__ == "__main__":
    unittest.main()
