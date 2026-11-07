#!/usr/bin/env python3
"""Fresh operator-image profile selection, without importer guests."""
import contextlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import operator_image as oi


class OperatorGeometryWrapper(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        scripts = self.root / "platform" / "scripts"
        scripts.mkdir(parents=True)
        for name in ("build-operator-image.sh", "inputs.sh"):
            shutil.copy2(pathlib.Path(oi.__file__).with_name(name), scripts / name)
        self.wrapper = scripts / "build-operator-image.sh"
        kernel = self.root / "kernel-run"
        kernel.mkdir()
        (kernel / "Makefile").write_text("# fixture; builds are forbidden\n")
        self.calls = self.root / "calls"
        blocked = '#!/bin/sh\nprintf "%s\\n" "$0" >> "$WRAPPER_CALLS"\nexit 97\n'
        for name in ("prepare-and-build.sh", "build-ports.sh"):
            path = scripts / name
            path.write_text(blocked)
            path.chmod(0o755)
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        python = bin_dir / "python3"
        python.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >> "$WRAPPER_CALLS"\n')
        python.chmod(0o755)
        for name in ("make", "cargo", "rustc", "qemu-system-x86_64"):
            path = bin_dir / name
            path.write_text(blocked)
            path.chmod(0o755)
        self.env = dict(os.environ, ABSD_KERNEL_RUN=str(kernel), ABSD_KERNEL_SOURCE="",
                        ABSD_KERNEL_PROTECTED="", ABSD_PROFILE="core", ABSD_SKIP_BUILD="0",
                        ABSD_QEMU=str(bin_dir / "qemu-system-x86_64"), WRAPPER_CALLS=str(self.calls),
                        PATH=str(bin_dir) + os.pathsep + os.environ["PATH"])
        self.out = self.root / "output with spaces"

    def run_wrapper(self, *arguments):
        return subprocess.run([str(self.wrapper), *arguments, str(self.out)],
                              env=self.env, capture_output=True, text=True, timeout=10)

    def assert_refused_before_consumers(self, run, message):
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertIn(message, run.stderr)
        self.assertFalse(self.calls.exists(), "refusal reached a build or Python consumer")
        self.assertFalse(self.out.exists())

    def test_invalid_profile_refuses_before_build_or_python(self):
        run = self.run_wrapper("--authorized-keys", "key path", "--disk-profile", "256m")
        self.assert_refused_before_consumers(run, "--disk-profile must be 128m or 2g")

    def test_reconfigure_profile_refuses_before_consumers(self):
        run = self.run_wrapper("--reconfigure", "--etc", "etc path", "--disk-profile", "2g")
        self.assert_refused_before_consumers(run, "--disk-profile is for fresh construction, not reconfigure")

    def test_default_forwards_no_profile_flag(self):
        self.env["ABSD_SKIP_BUILD"] = "1"
        run = self.run_wrapper("--authorized-keys", "key path")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.calls.read_text().splitlines(), [
            str(self.wrapper.with_name("operator_image.py")), "build", "--kernel",
            self.env["ABSD_KERNEL_RUN"], "--authorized-keys", "key path", "--qemu",
            self.env["ABSD_QEMU"] + " -cpu max,vendor=GenuineIntel,+rdrand", str(self.out)])
        self.assertFalse(self.out.exists())

    def test_profile_and_enrollment_reach_actual_cli_with_literal_paths(self):
        self.env["ABSD_SKIP_BUILD"] = "1"
        capture = self.root / "parsed arguments.json"
        python = pathlib.Path(self.env["PATH"].split(os.pathsep)[0]) / "python3"
        python.write_text(
            f"#!{sys.executable}\n"
            "import importlib.util, json, pathlib, sys\n"
            f"spec = importlib.util.spec_from_file_location('actual_operator_cli', {oi.__file__!r})\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(module)\n"
            "def capture_build(*args, **kwargs):\n"
            f"    pathlib.Path({str(capture)!r}).write_text(json.dumps(dict(args=args, kwargs=kwargs)))\n"
            "module.build = capture_build\n"
            "sys.argv = sys.argv[1:]\n"
            "module.main()\n"
        )
        for flag, keyword in (("--local-token-file", "local_token_file"),
                              ("--local-login-verifier", "local_login_verifier")):
            with self.subTest(flag=flag):
                run = self.run_wrapper("--authorized-keys", "key path", "--etc", "etc path",
                                       "--disk-profile", "2g", flag, "enrollment path")
                self.assertEqual(run.returncode, 0, run.stderr)
                parsed = json.loads(capture.read_text())
                self.assertEqual(parsed["args"][:4],
                                 [self.env["ABSD_KERNEL_RUN"], str(self.out), "key path", "etc path"])
                self.assertEqual(parsed["kwargs"], {
                    "release_id": None, "disk_profile": "2g",
                    "no_local_login": False,
                    "local_token_file": "enrollment path" if keyword == "local_token_file" else None,
                    "local_login_verifier": "enrollment path" if keyword == "local_login_verifier" else None,
                })
                self.assertFalse(self.out.exists())
                self.assertFalse(self.calls.exists(), "CLI parsing reached a build consumer")


class OperatorGeometry(unittest.TestCase):
    def test_profiles_are_explicit_and_default_does_not_change(self):
        import operator_geometry as geometry
        self.assertEqual(geometry.DEFAULT_PROFILE, "128m")
        self.assertEqual(geometry.image_bytes("128m"), 128 << 20)
        self.assertEqual(geometry.image_bytes("2g"), 2 << 30)
        self.assertEqual(oi.IMAGE_BYTES, 128 << 20)
        for size in (128 << 20, 2 << 30):
            self.assertTrue(geometry.is_writable_size(size))
        for size in (0, 64 << 20, 256 << 20, (2 << 30) - 512, (2 << 30) + 512):
            self.assertFalse(geometry.is_writable_size(size))
        for profile in ("", "64m", "256m", "2048", "2G", " 2g", "2g\n"):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                geometry.image_bytes(profile)

    def test_unknown_profile_refuses_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            out = pathlib.Path(directory) / "out"
            with self.assertRaisesRegex(ValueError, "profile"):
                oi.build(directory, out, "missing-keys", disk_profile="256m")
            self.assertFalse(out.exists())

    def test_explicit_profile_controls_new_image_and_default_call_stays_compatible(self):
        import operator_geometry as geometry
        for profile, expected in ((None, 8192), ("2g", 4096)):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                out = root / "out"
                keys = root / "keys"
                keys.write_text("ssh-ed25519 AAAA fixture\n")

                def imported(kernel, image, *args, **kwargs):
                    self.assertEqual(image.stat().st_size, expected)
                    self.assertEqual(image.stat().st_mode & 0o777, 0o600)
                    self.assertTrue(kwargs["fresh"])
                    raise oi.Failed("profile fixture reached importer")

                with contextlib.ExitStack() as stack:
                    stack.enter_context(mock.patch.dict(os.environ, {"ABSD_OPERATOR_CPUS": "1"}))
                    stack.enter_context(mock.patch.dict(geometry.PROFILES, {"2g": 4096}))
                    for name, value in (("IMAGE_BYTES", 8192), ("system_files", lambda root: []),
                                        ("etc_files", lambda *args: []), ("import_boots", imported)):
                        stack.enter_context(mock.patch.object(oi, name, value))
                    with self.assertRaisesRegex(oi.Failed, "fixture reached importer"):
                        kwargs = {} if profile is None else {"disk_profile": profile}
                        oi.build(root, out, keys, root=root, release_id="dev", **kwargs)
                self.assertFalse((out / oi.ISO).exists())
                self.assertFalse((out / "MANIFEST").exists())

    def test_cli_exposes_only_supported_profile_choices(self):
        help_run = subprocess.run([sys.executable, oi.__file__, "build", "--help"],
                                  capture_output=True, text=True)
        self.assertEqual(help_run.returncode, 0, help_run.stderr)
        self.assertIn("--disk-profile {128m,2g}", help_run.stdout)
        with tempfile.TemporaryDirectory() as directory:
            out = pathlib.Path(directory) / "out"
            bad = subprocess.run([sys.executable, oi.__file__, "build", "--kernel", directory,
                                  "--authorized-keys", "missing", "--disk-profile", "256m", str(out)],
                                 capture_output=True, text=True)
            self.assertEqual(bad.returncode, 2, bad.stderr)
            self.assertFalse(out.exists())

    def test_headroom_refusal_does_not_mislabel_a_large_image_as_128_mib(self):
        with mock.patch.object(oi, "tree", return_value={}), \
                mock.patch.object(oi.em, "check_import_capacity",
                                  return_value={"peak_extra_blocks": 100, "free_blocks": 124}):
            with self.assertRaises(oi.Failed) as caught:
                oi.check_successor_headroom(pathlib.Path("unused-image"), [], "dev")
        self.assertIn("needs 125", str(caught.exception))
        self.assertNotIn("128 MiB", str(caught.exception))

    def test_shell_wrapper_forwards_profile_with_literal_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            kernel = root / "kernel"
            kernel.mkdir()
            (kernel / "Makefile").write_text("# fixture\n")
            tool = root / "python3"
            tool.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n")
            tool.chmod(0o755)
            env = dict(os.environ, ABSD_KERNEL_RUN=str(kernel), ABSD_SKIP_BUILD="1",
                       PATH=str(root) + os.pathsep + os.environ["PATH"])
            out = root / "output with spaces"
            run = subprocess.run([str(pathlib.Path(oi.__file__).with_name("build-operator-image.sh")),
                                  "--authorized-keys", "key path", "--disk-profile", "2g", str(out)],
                                 env=env, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            args = run.stdout.splitlines()
            self.assertIn("--disk-profile", args)
            self.assertEqual(args[args.index("--disk-profile") + 1], "2g")
            self.assertEqual(args[-1], str(out))
            self.assertIn("key path", args)


if __name__ == "__main__":
    unittest.main()
