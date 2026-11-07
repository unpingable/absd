#!/usr/bin/env python3
"""Small-file release boundary controls; reported large sizes are injected.

No filesystem-geometry/product claim: real sparse 2 GiB validation belongs to
parent's separately admitted fixture turn. Actual destination writes are
observed here, and creation stops at truncate before allocating a large file.
"""
import builtins
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("release_geometry_test_subject", HERE / "release.py")
rel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rel)
SMALL = 134217728
LARGE = 2147483648


class BoundaryReached(Exception):
    pass


@contextlib.contextmanager
def observed_size(path, size):
    """Keep the fixture tiny while injecting only its observed st_size."""
    original = Path.stat
    def stat(subject, *args, **kwargs):
        result = original(subject, *args, **kwargs)
        if subject == path:
            fields = list(result)
            fields[6] = size
            return os.stat_result(fields)
        return result
    with mock.patch.object(Path, "stat", stat):
        yield


class GeometryRelease(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="release-geometry-small-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.backup = self.root / "backup"
        self.backup.mkdir()
        self.image = self.backup / rel.IMAGE
        self.image.write_bytes(b"small observed-size fixture\n")
        self.out = self.root / "destination"

    def args(self, **values):
        return SimpleNamespace(**dict(backup=str(self.backup), target=str(self.out),
            release="release", kernel="kernel", key="key", clone=True,
            replace=False, target_identity="target", **values))

    def parse_install(self, *extra):
        with mock.patch.object(sys, "argv", ["release.py", "install", "--release", "release",
                "--kernel", "kernel", "--target", str(self.out), "--target-identity", "target", *extra]), \
                mock.patch.object(rel, "cmd_install", side_effect=BoundaryReached) as command:
            with self.assertRaises(BoundaryReached):
                rel.main()
        return command.call_args.args[0]

    def test_install_parser_default_and_both_explicit_profiles(self):
        self.assertIsNone(getattr(self.parse_install(), "disk_profile", None))
        for profile in ("128m", "2g"):
            with self.subTest(profile=profile):
                self.assertEqual(self.parse_install("--disk-profile", profile).disk_profile, profile)
        self.assertFalse(self.out.exists())

    def test_profile_flag_is_install_only_and_unknown_profile_has_no_effects(self):
        commands = ["install", "stage", "migrate", "restore"]
        for name in commands:
            argv = ["release.py", name, "--target", str(self.out), "--disk-profile",
                    "unknown" if name == "install" else "2g"]
            if name == "install":
                argv += ["--release", "release", "--kernel", "kernel", "--target-identity", "target"]
            if name == "restore":
                argv += [str(self.backup)]
            with self.subTest(command=name), mock.patch.object(sys, "argv", argv), \
                    contextlib.redirect_stderr(io.StringIO()), \
                    mock.patch.object(rel, "cmd_" + name, side_effect=AssertionError("dispatched")) as dispatch:
                with self.assertRaises(SystemExit) as error:
                    rel.main()
                self.assertEqual(error.exception.code, 2)
                dispatch.assert_not_called()
        self.assertFalse(self.out.exists())

    def test_invalid_python_profile_precedes_release_reads_and_destination_creation(self):
        args = self.args(disk_profile="unknown")
        with mock.patch.object(rel, "Release", side_effect=AssertionError("release read")) as release:
            with self.assertRaises(rel.Failed):
                rel.cmd_install(args)
        release.assert_not_called()
        self.assertFalse(self.out.exists())
        target = rel.Target(self.out)
        source = mock.Mock()
        source.verified_tree_files.side_effect = AssertionError("release read")
        with self.assertRaises(rel.Failed):
            rel.install(args, source, "kernel", target, lambda _: None)
        source.verified_tree_files.assert_not_called()
        self.assertFalse(self.out.exists())

    def test_install_selects_size_at_real_creation_boundary_without_large_allocation(self):
        # Existing Python callers without disk_profile retain oi.IMAGE_BYTES.
        for profile, expected in ((None, 4096), ("128m", SMALL), ("2g", LARGE)):
            with self.subTest(profile=profile):
                self.out.mkdir(exist_ok=True)
                target = rel.Target(self.out)
                target.image.write_bytes(b"existing destination remains unchanged")
                source = mock.Mock(id="release")
                source.verified_tree_files.return_value = [("/ssh/authorized_keys", b"public\n")]
                source.verified_site_defaults.return_value = []
                args = self.args(**({} if profile is None else {"disk_profile": profile}))
                sizes = []
                real_open = builtins.open
                class Probe:
                    def __init__(self, handle): self.handle = handle
                    def __enter__(self): return self
                    def __exit__(self, *exc): self.handle.close()
                    def truncate(self, size):
                        sizes.append(size)
                        raise BoundaryReached
                def opening(path, mode="r", *rest, **kwargs):
                    handle = real_open(path, mode, *rest, **kwargs)
                    return Probe(handle) if Path(path).name == "install.img" and mode == "xb" else handle
                with mock.patch.object(rel.oi, "IMAGE_BYTES", 4096), \
                        mock.patch.object(rel, "build_select_cache", return_value="cache"), \
                        mock.patch.object(rel, "import_files", side_effect=AssertionError("import reached")) as importer, \
                        mock.patch.object(builtins, "open", opening):
                    with self.assertRaises(BoundaryReached):
                        rel.install(args, source, "kernel", target, lambda _: None)
                self.assertEqual(sizes, [expected])
                importer.assert_not_called()
                self.assertEqual(target.image.read_bytes(), b"existing destination remains unchanged")
                self.assertEqual(sorted(p.name for p in self.out.iterdir()), [rel.IMAGE])

    def test_stage_allows_exact_profiles_before_capacity_or_tree_reads(self):
        target = SimpleNamespace(image=self.image, tree=lambda: {})
        for size in (SMALL, LARGE):
            with self.subTest(size=size), observed_size(self.image, size), \
                    mock.patch.object(rel.em, "import_plan", return_value=[]), \
                    mock.patch.object(rel.em, "check_import_capacity", return_value={"peak_extra_blocks": 0, "free_blocks": 1}):
                source = mock.Mock(id="release")
                source.verified_tree_files.return_value = []
                rel.refuse_other_geometry(target, source)
                source.verified_tree_files.assert_not_called()
        self.assertEqual(self.image.read_bytes(), b"small observed-size fixture\n")

    def test_stage_refuses_legacy_and_intermediate_sizes_without_writes(self):
        target = SimpleNamespace(image=self.image, tree=lambda: {})
        source = mock.Mock(id="release")
        source.verified_tree_files.return_value = []
        for size in (64 << 20, SMALL + 512, LARGE - 512, LARGE + 512):
            with self.subTest(size=size), observed_size(self.image, size), \
                    mock.patch.object(rel.em, "import_plan", return_value=[]), \
                    mock.patch.object(rel.em, "check_import_capacity", return_value={"peak_extra_blocks": 2, "free_blocks": 1}):
                with self.assertRaisesRegex(rel.Failed, "image_size:.*Nothing was written"):
                    rel.refuse_other_geometry(target, source)
        self.assertEqual(self.image.read_bytes(), b"small observed-size fixture\n")

    def test_recovery_snapshot_preserves_legacy_bound_and_admits_only_exact_large(self):
        args = self.args()
        for size in (4096, SMALL, LARGE):
            with self.subTest(size=size), mock.patch.object(rel, "disk_sectors", return_value=size // 512), \
                    mock.patch.object(rel.recovery_point, "validate", return_value="validated") as validate, \
                    mock.patch.object(rel, "refuse_in_use") as refuse:
                self.assertEqual(rel.recovery_snapshot(args), "validated")
                self.assertEqual(validate.call_args.kwargs["image_bytes"], size)
                self.assertEqual(validate.call_args.kwargs["device_sectors"], size // 512)
                refuse.assert_called_once()
        with mock.patch.object(rel.oi, "IMAGE_BYTES", 4096), \
                mock.patch.object(rel, "disk_sectors", return_value=8), \
                mock.patch.object(rel.recovery_point, "validate", return_value="legacy"), \
                mock.patch.object(rel, "refuse_in_use"):
            self.assertEqual(rel.recovery_snapshot(args), "legacy")

    def test_recovery_refuses_other_large_sizes_before_validator(self):
        for size in (SMALL + 512, LARGE - 512, LARGE + 512):
            with self.subTest(size=size), mock.patch.object(rel, "disk_sectors", return_value=size // 512), \
                    mock.patch.object(rel.recovery_point, "validate", side_effect=AssertionError("validation reached")) as validate:
                with self.assertRaisesRegex(rel.Failed, "recovery_point_member_size"):
                    rel.recovery_snapshot(self.args())
                validate.assert_not_called()
        self.assertFalse(self.out.exists())

    def test_large_recovery_does_not_bypass_validation_failure(self):
        with mock.patch.object(rel, "disk_sectors", return_value=LARGE // 512), \
                mock.patch.object(rel.recovery_point, "validate", side_effect=rel.recovery_point.Refused("identity mismatch")), \
                mock.patch.object(rel, "refuse_in_use") as refuse:
            with self.assertRaisesRegex(rel.Failed, "identity mismatch"):
                rel.recovery_snapshot(self.args())
            refuse.assert_not_called()

    def test_clone_allows_exact_profiles_only_before_release_and_destination_effects(self):
        for size in (SMALL, LARGE, 64 << 20, SMALL + 512, LARGE - 512, LARGE + 512):
            with self.subTest(size=size), observed_size(self.image, size), \
                    mock.patch.object(rel, "validate_backup", return_value=({}, {}, "release")), \
                    mock.patch.object(rel, "Release", side_effect=BoundaryReached) as release:
                if size in (SMALL, LARGE):
                    with self.assertRaises(BoundaryReached): rel.cmd_restore(self.args())
                    release.assert_called_once()
                else:
                    with self.assertRaisesRegex(rel.Failed, "image_size"):
                        rel.cmd_restore(self.args())
                    release.assert_not_called()
            self.assertFalse(self.out.exists())
            self.assertEqual(self.image.read_bytes(), b"small observed-size fixture\n")


if __name__ == "__main__":
    unittest.main()
