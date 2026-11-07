#!/usr/bin/env python3
"""Host checks of producer wiring; no image tools, builds or guests."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import media
import media_operator


class ProducerValidation(unittest.TestCase):
    def arguments(self, producer=True):
        args = ["operator-validate", "--profile", "vm-operator", "--platform-tree", "/run/platform",
                "--kernel-run", "/run/kernel", "--out", "/run/media"]
        return args + (["--producer-tests"] if producer else [])

    def invoke(self, child=None, validation_error=None, producer=True):
        child = child or subprocess.CompletedProcess([], 0, "MEDIA HOST TEST OK cases=5 skipped=0\n", "")
        with patch.object(media_operator, "operator_validate", side_effect=validation_error) as validate, \
                patch.object(media.subprocess, "run", return_value=child) as run, \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = media.main(self.arguments(producer))
        return result, validate, run

    def test_preview_option_reaches_the_actual_image_builder_command(self):
        class Captured(Exception):
            pass
        for disabled in (False, True):
            with self.subTest(disabled=disabled), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                args = ["operator-image", "--profile", "vm-operator", "--platform-tree", str(root),
                        "--kernel-run", str(root), "--kernel-commit", "a" * 40,
                        "--platform-commit", "b" * 40, "--authorized-keys", str(root / "keys"),
                        "--out", str(root / "out")]
                if disabled:
                    args.append("--no-local-login")
                with patch.object(media_operator, "load_operator_profile", return_value={}), \
                     patch.object(media_operator, "checkout_at"), \
                     patch.object(media, "check_pins", return_value=[]), \
                     patch.object(media_operator, "epoch_of", return_value=0), \
                     patch.object(media_operator, "operator_env", return_value={}), \
                     patch.object(media, "confined"), \
                     patch.object(media, "tool", side_effect=lambda name: name), \
                     patch.object(media_operator.subprocess, "run", side_effect=Captured) as run:
                    with self.assertRaises(Captured):
                        media.main(args)
                command = run.call_args.args[0]
                self.assertEqual(command[2:4], [str(root / "scripts/operator_image.py"), "build"])
                self.assertEqual(command.count("--no-local-login"), int(disabled))
                self.assertIn("--authorized-keys", command)

    def test_producer_binds_its_own_fixture_and_requires_all_five_cases(self):
        with patch.dict(os.environ, dict(ABSD_REQUIRE_S4="0", ABSD_OPERATOR_FIXTURE="/stale/media",
                                        ABSD_OPERATOR_PLATFORM="/stale/platform", ABSD_OPERATOR_KERNEL="/stale/kernel")):
            result, validate, run = self.invoke()
        self.assertEqual(result, 0)
        validate.assert_called_once()
        command = run.call_args.args[0]
        self.assertEqual(command[0], sys.executable)
        self.assertEqual(command[-2:], [str(Path(media.__file__).with_name("test_media.py")), "OperatorValidateGrub"])
        self.assertIn("-I", command)
        self.assertIn("-B", command)
        self.assertTrue(any(a.startswith("pycache_prefix=") for a in command))
        env = run.call_args.kwargs["env"]
        self.assertEqual({k: env[k] for k in ("ABSD_REQUIRE_S4", "ABSD_OPERATOR_FIXTURE", "ABSD_OPERATOR_PLATFORM", "ABSD_OPERATOR_KERNEL")},
                         dict(ABSD_REQUIRE_S4="1", ABSD_OPERATOR_FIXTURE="/run/media",
                              ABSD_OPERATOR_PLATFORM="/run/platform", ABSD_OPERATOR_KERNEL="/run/kernel"))

    def test_unvalidated_media_never_reaches_producer_tests(self):
        result, _, run = self.invoke(validation_error=media.Refused("build_unbound"))
        self.assertEqual(result, 2)
        run.assert_not_called()

    def test_child_failure_refuses_even_with_a_success_shaped_line(self):
        result, _, _ = self.invoke(subprocess.CompletedProcess([], 1, "MEDIA HOST TEST OK cases=5 skipped=0\n", "failed"))
        self.assertEqual(result, 2)

    def test_missing_skipped_or_wrong_case_count_refuses(self):
        for text in ("", "MEDIA HOST TEST OK cases=5 skipped=1\n", "MEDIA HOST TEST OK cases=0 skipped=0\n",
                     "MEDIA HOST TEST OK cases=4 skipped=0\n", "MEDIA HOST TEST OK cases=5 skipped=0 trailing\n"):
            with self.subTest(text=text):
                result, _, _ = self.invoke(subprocess.CompletedProcess([], 0, text, ""))
                self.assertEqual(result, 2)

    def test_ordinary_validation_does_not_start_producer_tests(self):
        result, validate, run = self.invoke(producer=False)
        self.assertEqual(result, 0)
        validate.assert_called_once()
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
