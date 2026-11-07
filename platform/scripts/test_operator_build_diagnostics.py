#!/usr/bin/env python3
"""Real make failures retain bounded diagnostics before any importer boot."""
import contextlib
import io
import pathlib
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import operator_image as operator


class BuildDiagnostics(unittest.TestCase):
    def make_tree(self, root, recipe):
        (root / "Makefile").write_text("durable-iso:\n" + recipe)

    def test_pipe_read_failure_kills_and_reaps_the_child(self):
        original_popen = subprocess.Popen
        children = []
        failure = OSError("fixture pipe read failed")

        class BrokenRead:
            def __init__(self, pipe):
                self.pipe = pipe

            def read(self, size):
                raise failure

            def close(self):
                self.pipe.close()

        def start_child(command, **kwargs):
            child = original_popen(
                [sys.executable, "-c", "import sys; sys.stdin.buffer.read()"],
                stdin=subprocess.PIPE, **kwargs)
            children.append(child)
            child.stdout = BrokenRead(child.stdout)
            return child

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            try:
                with patch.object(operator.subprocess, "Popen", side_effect=start_child), \
                     self.assertRaises(OSError) as caught:
                    operator.kernel_iso(root, 2, "fixture", work=root)
                self.assertIs(caught.exception, failure)
                self.assertEqual(len(children), 1)
                self.assertEqual(children[0].returncode, -signal.SIGKILL)
            finally:
                for child in children:
                    if child.poll() is None:
                        child.kill()
                    child.wait()

    def test_failed_make_keeps_stdout_and_stderr_in_log_and_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.make_tree(root, "\t@printf 'prepare-stdout\\n'\n"
                                 "\t@printf 'missing-prerequisite-stderr\\n' >&2\n\t@false\n")
            log = io.StringIO()
            with contextlib.redirect_stdout(log), self.assertRaises(subprocess.CalledProcessError) as caught:
                operator.kernel_iso(root, 2, "fixture", work=root)
            for marker in ("prepare-stdout", "missing-prerequisite-stderr"):
                self.assertIn(marker, log.getvalue())
                self.assertIn(marker, str(caught.exception))
            self.assertEqual(caught.exception.returncode, 2)

    def test_importer_context_does_not_replace_make_failure_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.make_tree(root, "\t@printf 'compiler-is-missing\\n' >&2\n\t@false\n")
            log = []
            with patch.object(operator.em, "inspect_import_plan", return_value=([], {})), \
                 self.assertRaises(operator.Failed) as caught:
                operator._prepare_boots(root, root / "unused.img", [(2, [])], root, root, log.append)
            self.assertIn("importer boot 1 (step 2)", str(caught.exception))
            self.assertIn("compiler-is-missing", str(caught.exception))
            self.assertTrue(any("compiler-is-missing" in line for line in log))
            self.assertFalse((root / "unused.img").exists())

    def test_large_failure_retains_only_the_bounded_tail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "noisy.py").write_text(
                "import os\nos.write(1, b'old-prefix\\n' + b'x' * (1024 * 1024))\n"
                "os.write(2, b'final-stderr-marker\\n')\nraise SystemExit(9)\n")
            self.make_tree(root, "\t@python3 noisy.py\n")
            log = io.StringIO()
            with contextlib.redirect_stdout(log), self.assertRaises(subprocess.CalledProcessError) as caught:
                operator.kernel_iso(root, 2, "fixture", work=root)
            self.assertIn("final-stderr-marker", str(caught.exception))
            self.assertNotIn("old-prefix", log.getvalue())
            self.assertNotIn("old-prefix", str(caught.exception))
            self.assertEqual(len(caught.exception.output), 64 * 1024)
            self.assertIn(b"final-stderr-marker", caught.exception.output)

    def test_success_is_quiet_and_keeps_the_iso_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.make_tree(root, "\t@printf 'quiet-stdout\\n'\n"
                                 "\t@printf 'quiet-stderr\\n' >&2\n"
                                 "\t@mkdir -p build/durable\n\t@touch build/durable/absd-durable-2.iso\n")
            log = io.StringIO()
            with contextlib.redirect_stdout(log):
                result = operator.kernel_iso(root, 2, "fixture", work=root)
            self.assertEqual(log.getvalue(), "")
            self.assertEqual(result, root / "build/durable/absd-durable-2.iso")
            self.assertTrue(result.is_file())


if __name__ == "__main__":
    unittest.main()
