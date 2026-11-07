"""Host recovery controls on real filesystem bytes, with no guest boot.

The small device contains a Rust-written format-2 region with test-only
records rebuilt using the existing reader vectors. Its complete v3 layout,
superblocks, file records and content pass the real independent host reader.
Only the operator and recovery-slot image-size constants are reduced for these local fixtures.
Native served recovery remains a separate qualification requirement.
"""

import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import absd_fs
import absd_image
import recovery_point as rp
import release_record as rr
import storage_fence_state as guard
import storage_fence_resume as resume
import test_absd_fs as vectors

spec = importlib.util.spec_from_file_location("release_recovery_controls", HERE / "release.py")
rel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rel)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def disk(path, guard_bytes=None, extra=None):
    data = vectors.load("format2.sectors")
    files = {guard.PATH: guard.encode("clean") if guard_bytes is None else guard_bytes,
             "/ssh/host_ed25519_seed": bytes(range(32)),
             "/ssh/authorized_keys": b"synthetic qualification public key\n",
             "/etc/network.conf": b"address 192.0.2.100\n",
             "/home/operator/data/state.bin": bytes(range(256)) + b"\0\xff\n",
             rr.SELECTED: rr.selected_bytes("rel-a"),
             "/releases/rel-a/release": rr.record_text("rel-a").encode()}
    goldens = HERE.parent / "fixtures/storage-fence"
    files["/var/state/recovery.init"] = b""
    files["/var/state/recovery"] = (goldens / "recovery-v1-ledger.bin").read_bytes()
    for name in ("ready", "end", "stopped", "completed"):
        files["/var/state/facts/served-" + name] = (goldens / ("recovery-v1-" + name + ".bin")).read_bytes()
    files.update(extra or {})
    files = {path: data for path, data in files.items() if data is not None}
    directories = {"/", "/home/operator/data/empty"}
    for name in files:
        directories.update(str(p) for p in Path(name).parents)
    entries = sorted(directories | set(files), key=lambda p: (len(Path(p).parts), p))
    serials = {name: index + 1 for index, name in enumerate(entries)}
    raw = vectors.selected_raw(data)[:64]
    struct.pack_into("<Q", raw, 32, len(entries) + 1)
    struct.pack_into("<I", raw, 44, len(entries))
    geo = absd_fs.geometry(len(data) // 512)
    next_block = 0
    for name in entries:
        directory = name in directories
        value = files.get(name, b"")
        blocks = [] if directory else list(range(next_block, next_block + (len(value) + 4095) // 4096))
        next_block += len(blocks)
        label = b"" if name == "/" else Path(name).name.encode()
        parent = 0 if name == "/" else serials[str(Path(name).parent)]
        raw += struct.pack("<QQQBBHIQ", serials[name], parent, len(value),
                           2 if directory else 1, 0, len(label), len(blocks), 0)
        raw += label + b"".join(struct.pack("<I", n) for n in blocks)
        for index, block in enumerate(blocks):
            offset = (geo["data_first"] + block * 8) * 512
            data[offset:offset + 4096] = value[index * 4096:(index + 1) * 4096].ljust(4096, b"\0")
    vectors.resign(data, raw)
    device_sectors = len(data) // 512 * 2
    half, slot = device_sectors // 2, device_sectors // 8
    segment = slot // 4
    regions = [(1, 1, 1, 2), (2, 2, 16, slot - 16),
               (3, 3, half - 2 * slot, slot), (4, 3, half - slot, slot),
               *[(5 + i, 4, slot + i * segment, segment) for i in range(4)],
               (9, 5, half, half)]
    layout = bytearray(512)
    layout[:8] = b"ABSDLAY1"
    struct.pack_into("<IIQ", layout, 8, 3, len(regions), device_sectors)
    for index, entry in enumerate(regions):
        struct.pack_into("<IIQQ", layout, 24 + index * 32, *entry)
    struct.pack_into("<Q", layout, 504, absd_image.fnv1a(layout[:504]))
    image = bytes(layout).ljust(len(data), b"\0") + bytes(data)
    Path(path).write_bytes(image)
    return files, len(image), device_sectors


def snapshot(path):
    path = Path(path)
    if not path.exists():
        return None
    result = {}
    for p in [path, *sorted(path.rglob("*"))]:
        s = p.lstat()
        result[str(p.relative_to(path))] = (stat.S_IMODE(s.st_mode), s.st_ino,
            s.st_mtime_ns, s.st_ctime_ns, sha(p) if p.is_file() else None)
    return result


class Args:
    def __init__(self, **values):
        self.__dict__.update(values)

    def __getattr__(self, name):
        return None


class RecoveryControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="test-recovery-point-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.source = self.work / "source"
        self.source.mkdir()
        self.files, size, sectors = disk(self.source / rel.IMAGE)
        bounds = mock.patch.multiple(rel.oi, IMAGE_BYTES=size, DEVICE_SECTORS=sectors)
        bounds.start(); self.addCleanup(bounds.stop)
        slot_bounds = mock.patch.multiple(resume, DEVICE_SECTORS=sectors, IMAGE_BYTES=size)
        slot_bounds.start(); self.addCleanup(slot_bounds.stop)
        # This suite's 512 KiB synthetic disk stands in for the default
        # profile; patch the shared write policy as well as the old aliases.
        policy_bounds = mock.patch.object(resume.operator_geometry, "DEFAULT_IMAGE_BYTES", size)
        policy_bounds.start(); self.addCleanup(policy_bounds.stop)
        (self.source / rel.TARGET).write_text("qualification-machine-a\n")
        boot = self.source / "releases/rel-a" / rel.ISO
        boot.parent.mkdir(parents=True)
        boot.write_bytes(b"synthetic boot artifact for source release A\n")
        self.backup = self.work / "point"
        self.output = self.work / "replacement"
        self.logs = []
        rel.cmd_backup(Args(target=str(self.source), backup=str(self.backup), recovery_point=True),
                       log=self.logs.append)
        self.pin = sha(self.backup / "backup.toml")

    def args(self, **changes):
        values = dict(target=str(self.output), backup=str(self.backup),
                      recovery_point_sha256=self.pin, expected_release="rel-a")
        values.update(changes)
        return Args(**values)

    def metadata(self):
        return tomllib.loads((self.backup / "backup.toml").read_text())

    def rewrite(self, meta):
        (self.backup / "backup.toml").write_text(rel.toml_dump(meta))
        self.pin = sha(self.backup / "backup.toml")

    def refuse(self, reason, **changes):
        before = snapshot(self.output)
        with self.assertRaisesRegex(rel.Failed, reason):
            rel.cmd_restore(self.args(**changes), log=lambda _: None)
        self.assertEqual(snapshot(self.output), before)

    def sentinel(self):
        self.output.mkdir()
        (self.output / "sentinel").write_bytes(b"existing destination must stay unchanged\n")

    def refuse_input(self, reason, **changes):
        """Refuse both an absent destination and an existing sentinel tree."""
        self.refuse(reason, **changes)
        self.sentinel()
        self.refuse(reason, **changes)

    def test_point_creation_pins_clean_state_and_iso(self):
        meta = self.metadata()
        self.assertIn("recovery", meta)
        self.assertEqual(meta["recovery"]["schema"], "absd-recovery-point/1")
        self.assertEqual(meta["recovery"]["state_roots"], ["/etc", "/home", "/ssh"])
        self.assertEqual(meta["recovery"]["iso_sha256"], sha(self.backup / "releases/rel-a" / rel.ISO))
        self.assertIn(f"RECOVERY POINT SHA256 {self.pin} selected=rel-a", self.logs)
        self.assertEqual(sha(self.source / rel.IMAGE), sha(self.backup / rel.IMAGE))
        self.assertEqual(stat.S_IMODE(self.backup.stat().st_mode), 0o700)

    def test_fresh_restore_preserves_exact_image_state_and_identity(self):
        rel.cmd_restore(self.args(), log=lambda _: None)
        self.assertEqual(sha(self.output / rel.IMAGE), sha(self.backup / rel.IMAGE))
        self.assertEqual((self.output / rel.ISO).read_bytes(),
                         (self.backup / "releases/rel-a" / rel.ISO).read_bytes())
        self.assertEqual((self.output / rel.TARGET).read_text(), "qualification-machine-a\n")
        self.assertEqual(rel.Target(self.output).tree(), self.files)
        region = absd_fs.fs_region(self.output / rel.IMAGE, rel.oi.DEVICE_SECTORS)
        records = absd_fs.tree(region, absd_fs.select(region))
        self.assertTrue(records["/home/operator/data/empty"]["dir"])
        receipt = next((self.output / "receipts").glob("restore-*.toml"))
        self.assertEqual(tomllib.loads(receipt.read_text())["restore"]["recovery_point_sha256"], self.pin)

    def test_external_pin_mismatch_changes_no_destination(self):
        self.refuse_input("recovery_point_pin_mismatch", recovery_point_sha256="0" * 64)

    def test_rehashed_local_metadata_cannot_replace_external_pin(self):
        old_pin = self.pin
        image = bytearray((self.backup / rel.IMAGE).read_bytes()); image[512] ^= 1
        (self.backup / rel.IMAGE).write_bytes(image)
        meta = self.metadata(); meta["disk"]["image_sha256"] = sha(self.backup / rel.IMAGE)
        self.rewrite(meta)
        self.refuse_input("recovery_point_pin_mismatch", recovery_point_sha256=old_pin)

    def test_image_digest_covers_bytes_outside_filesystem(self):
        image = bytearray((self.backup / rel.IMAGE).read_bytes()); image[512] ^= 1
        (self.backup / rel.IMAGE).write_bytes(image)
        self.refuse_input("recovery_point_image_digest")

    def test_truncated_image_is_refused_before_destination_changes(self):
        # The point is read at its image's own size (coordination record #28): a
        # truncated image fails the pinned digest, an oversized one the cap.
        with (self.backup / rel.IMAGE).open("r+b") as f:f.truncate(512)
        self.refuse_input("recovery_point_image_digest")

    def test_oversized_image_is_refused_before_it_is_read(self):
        with (self.backup / rel.IMAGE).open("r+b") as f:f.truncate(rel.oi.IMAGE_BYTES + 512)
        self.refuse_input("recovery_point_member_size")

    def test_iso_mutation_is_refused_before_destination_changes(self):
        path = self.backup / "releases/rel-a" / rel.ISO
        value = bytearray(path.read_bytes()); value[0] ^= 1; path.write_bytes(value)
        self.refuse_input("recovery_point_iso_digest")

    def test_expected_release_is_not_inferred_from_backup(self):
        self.refuse_input("recovery_point_release_mismatch", expected_release="rel-b")

    def test_unknown_schema_is_refused(self):
        meta = self.metadata(); meta["recovery"]["schema"] = "absd-recovery-point/99"
        self.rewrite(meta); self.refuse_input("recovery_point_schema")

    def test_malformed_metadata_is_named(self):
        (self.backup / "backup.toml").write_bytes(b'[backup\n')
        self.pin = sha(self.backup / "backup.toml")
        self.refuse_input("recovery_point_metadata")

    def test_dirty_and_malformed_guards_cannot_be_restored(self):
        for data in (guard.encode("dirty"), b"absd-writable v1 not_ready\n".ljust(512, b"\0")):
            with self.subTest(guard=data[:28]):
                tree, _, _ = disk(self.backup / rel.IMAGE, data)
                meta = self.metadata(); meta["disk"]["image_sha256"] = sha(self.backup / rel.IMAGE)
                meta["disk"]["files_digest"] = rp.files_digest(tree)
                self.rewrite(meta); self.refuse("recovery_point_unclean")

    def test_dirty_and_malformed_guards_cannot_produce_points(self):
        for i, data in enumerate((guard.encode("dirty"), b"absd-writable v1 not_ready\n".ljust(512, b"\0"))):
            disk(self.source / rel.IMAGE, data); destination = self.work / f"bad-point-{i}"
            before = sha(self.source / rel.IMAGE)
            with self.assertRaisesRegex(rel.Failed, "recovery_point_unclean"):
                rel.cmd_backup(Args(target=str(self.source), backup=str(destination), recovery_point=True))
            self.assertFalse(destination.exists()); self.assertEqual(sha(self.source / rel.IMAGE), before)

    def test_held_source_cannot_produce_point(self):
        destination = self.work / "held-point"
        with (self.source / rel.IMAGE).open("rb"):
            with self.assertRaisesRegex(rel.Failed, "image_in_use"):
                rel.cmd_backup(Args(target=str(self.source), backup=str(destination), recovery_point=True))
        self.assertFalse(destination.exists())

    def test_held_point_cannot_be_restored(self):
        with (self.backup / rel.IMAGE).open("rb"):
            self.refuse("image_in_use")

    def test_existing_directory_and_image_are_unchanged(self):
        self.sentinel(); self.refuse("recovery_point_target_exists")
        (self.output / rel.IMAGE).write_bytes(b"original fenced image fixture")
        self.refuse("recovery_point_target_exists")

    def test_symlinked_existing_destination_is_unchanged(self):
        self.output.symlink_to(self.source, target_is_directory=True)
        before = snapshot(self.source)
        self.refuse("recovery_point_target_exists")
        self.assertEqual(snapshot(self.source), before)

    def test_replace_and_clone_combinations_are_refused(self):
        for flag in ("replace", "clone"):
            with self.subTest(flag=flag):self.refuse("recovery_point_mode_conflict", **{flag: True})

    def test_metadata_does_not_rename_the_logical_machine(self):
        self.refuse("recovery_point_identity", target_identity="different-machine")

    def test_symlinked_recovery_members_are_refused(self):
        path = self.backup / "releases/rel-a"
        moved = self.backup / "boot-original"; path.rename(moved); path.symlink_to(moved)
        self.refuse("recovery_point_member_io")

    def test_structural_reader_is_required_even_for_pinned_bytes(self):
        image = bytearray((self.backup / rel.IMAGE).read_bytes())
        first = rel.oi.DEVICE_SECTORS // 2 * 512
        image[first + 480] ^= 1
        (self.backup / rel.IMAGE).write_bytes(image)
        meta = self.metadata(); meta["disk"]["image_sha256"] = sha(self.backup / rel.IMAGE)
        self.rewrite(meta); self.refuse("recovery_point_image_invalid")

    def test_input_replacement_after_validation_publishes_validated_bytes(self):
        original = (self.backup / rel.IMAGE).read_bytes()
        validate = rel.recovery_snapshot
        def substitute(args):
            point = validate(args)
            replacement = self.work / "substitution.img"
            replacement.write_bytes(b"changed after capture".ljust(len(original), b"\0"))
            replacement.replace(self.backup / rel.IMAGE)
            return point
        with mock.patch.object(rel, "recovery_snapshot", side_effect=substitute):
            rel.cmd_restore(self.args(), log=lambda _: None)
        self.assertEqual((self.output / rel.IMAGE).read_bytes(), original)
        self.assertNotEqual(sha(self.output / rel.IMAGE), sha(self.backup / rel.IMAGE))

    def test_cli_enforces_the_external_pin_before_output(self):
        args = ["release.py", "restore", str(self.backup), "--target", str(self.output),
                "--recovery-point-sha256", "0" * 64, "--expected-release", "rel-a"]
        errors = io.StringIO()
        with mock.patch.object(sys, "argv", args), contextlib.redirect_stderr(errors):
            with self.assertRaises(SystemExit) as stop:rel.main()
        self.assertEqual(stop.exception.code, 1)
        self.assertIn("recovery_point_pin_mismatch", errors.getvalue())
        self.assertFalse(self.output.exists())

    def bad_release_record(self):
        body = rr.record_text("rel-a").split("check=")[0].replace("kernel_abi=1", "kernel_abi=9")
        return (body + "check=" + hashlib.sha256(body.encode()).hexdigest() + "\n").encode()

    def test_incompatible_source_record_cannot_produce_point(self):
        disk(self.source / rel.IMAGE, extra={"/releases/rel-a/release": self.bad_release_record()})
        destination = self.work / "incompatible-point"
        with self.assertRaisesRegex(rel.Failed, "recovery_point_release_record"):
            rel.cmd_backup(Args(target=str(self.source), backup=str(destination), recovery_point=True))
        self.assertFalse(destination.exists())

    def test_incompatible_pinned_record_changes_no_destination(self):
        tree, _, _ = disk(self.backup / rel.IMAGE,
                          extra={"/releases/rel-a/release": self.bad_release_record()})
        meta = self.metadata(); meta["disk"]["image_sha256"] = sha(self.backup / rel.IMAGE)
        meta["disk"]["files_digest"] = rp.files_digest(tree)
        self.rewrite(meta); self.refuse_input("recovery_point_release_record")

    def test_copy_io_failure_is_incomplete_and_cannot_retry_as_fresh(self):
        original = sha(self.backup / rel.IMAGE); logs = []
        def interrupted(path, data):
            with Path(path).open("xb") as f:f.write(data[:512])
            raise OSError("local fixture interruption")
        with mock.patch.object(rel, "write_recovery_file", side_effect=interrupted):
            with self.assertRaisesRegex(rel.Failed, "recovery_point_construction_incomplete"):
                rel.cmd_restore(self.args(), log=logs.append)
        self.assertTrue(self.output.exists())
        self.assertEqual((self.output / rel.IMAGE).stat().st_size, 512)
        self.assertFalse(any(line.startswith("RESTORE COPIED") for line in logs))
        self.assertEqual(sha(self.backup / rel.IMAGE), original)
        self.refuse("recovery_point_target_exists")

    def test_clean_guard_not_ready_history_refuses_point_and_restore(self):
        self.history_refusal({"/var/state/facts/served-" + name: bytes(64)
                              for name in ("ready", "end", "stopped", "completed")},
                             "history_not_ended.*not_ready")

    def test_clean_guard_failed_history_refuses_point_and_restore(self):
        self.history_refusal({"/var/state/facts/served-completed": bytes(64)}, "history_not_ended.*failed")

    def test_clean_guard_invalid_history_refuses_point_and_restore(self):
        for changes in ({"/var/state/recovery": b"corrupt ledger"},
                        {"/var/state/recovery.init": None},
                        {"/var/state/recovery": None}):
            with self.subTest(changes=changes):
                self.history_refusal(changes, "history_invalid")

    def history_refusal(self, changes, reason):
        disk(self.source / rel.IMAGE, extra=changes)
        destination = self.work / "history-refused-point"
        before = sha(self.source / rel.IMAGE)
        with self.assertRaisesRegex(rel.Failed, reason):
            rel.cmd_backup(Args(target=str(self.source), backup=str(destination), recovery_point=True))
        self.assertFalse(destination.exists()); self.assertEqual(sha(self.source / rel.IMAGE), before)
        tree, _, _ = disk(self.backup / rel.IMAGE, extra=changes)
        meta = self.metadata(); meta["disk"]["image_sha256"] = sha(self.backup / rel.IMAGE)
        meta["disk"]["files_digest"] = rp.files_digest(tree); meta["disk"]["files"] = len(tree)
        self.rewrite(meta); self.refuse(reason)

    def test_history_ended_accepts_bounded_completion(self):
        changes = {"/var/state/facts/served-" + name: bytes(64) for name in ("ready", "end")}
        changes["/var/state/facts/served-completed"] = (
            b"boot=0123456789abcdef0123456789abcdef action=bounded\n").ljust(64, b"\0")
        tree, _, _ = disk(self.backup / rel.IMAGE, extra=changes)
        meta = self.metadata(); meta["disk"]["image_sha256"] = sha(self.backup / rel.IMAGE)
        meta["disk"]["files_digest"] = rp.files_digest(tree); self.rewrite(meta)
        rel.cmd_restore(self.args(), log=lambda _: None)
        self.assertEqual(sha(self.output / rel.IMAGE), sha(self.backup / rel.IMAGE))

    def test_history_checksum_padding_and_wrong_boot_are_refused(self):
        golden = (HERE.parent / "fixtures/storage-fence/recovery-v1-ledger.bin").read_bytes()
        changed = bytearray(golden); changed[25] ^= 1
        wrong_boot = b"boot=ffffffffffffffffffffffffffffffff\n".ljust(64, b"\0")
        for changes, reason in (({"/var/state/recovery": bytes(changed)}, "history_invalid"),
                                ({"/var/state/recovery": golden[:-1] + b"x"}, "history_invalid"),
                                ({"/var/state/facts/served-completed": wrong_boot}, "history_not_ended")):
            with self.subTest(reason=reason):self.history_refusal(changes, reason)

    def test_wrong_format_metadata_changes_no_destination(self):
        meta = self.metadata(); meta["disk"]["fs_format"] = 3; self.rewrite(meta)
        self.refuse_input("recovery_point_format")

    def test_truncated_metadata_changes_no_destination(self):
        with (self.backup / "backup.toml").open("r+b") as f:f.truncate(5)
        self.pin = sha(self.backup / "backup.toml")
        self.refuse_input("recovery_point_metadata")

    def test_truncated_iso_changes_no_destination(self):
        path = self.backup / "releases/rel-a" / rel.ISO
        with path.open("r+b") as f:f.truncate(path.stat().st_size - 1)
        self.refuse_input("recovery_point_member_size")

    def legacy_point(self):
        meta = self.metadata(); del meta["recovery"]; self.rewrite(meta)

    def legacy_args(self):
        return self.args(recovery_point_sha256=None, expected_release=None, replace=True)

    def test_legacy_restore_cannot_consume_pinned_point(self):
        self.refuse_input("recovery_point_strict_required", recovery_point_sha256=None,
                          expected_release=None, replace=True)

    def test_resume_labeled_legacy_backup_remains_restorable(self):
        # #63 adds only a pending-id label; it is not a P2 recovery point.
        meta = self.metadata()
        meta["recovery"] = {"pending_id": "none"}
        self.rewrite(meta)
        rel.cmd_restore(self.legacy_args(), log=lambda _: None)
        self.assertEqual(sha(self.output / rel.IMAGE), sha(self.backup / rel.IMAGE))

    def test_recovery_point_with_pending_label_still_requires_strict_route(self):
        meta = self.metadata()
        meta["recovery"]["pending_id"] = "none"
        self.rewrite(meta)
        self.refuse_input("recovery_point_strict_required", recovery_point_sha256=None,
                          expected_release=None, replace=True)

    def test_legacy_replace_refuses_unclean_target(self):
        self.legacy_point(); self.output.mkdir(); disk(self.output / rel.IMAGE, guard.encode("dirty"))
        self.refuse("restore_target_not_clean", recovery_point_sha256=None, expected_release=None, replace=True)

    def test_legacy_replace_refuses_held_target(self):
        self.legacy_point(); self.output.mkdir(); disk(self.output / rel.IMAGE)
        with (self.output / rel.IMAGE).open("rb"):
            self.refuse("image_in_use", recovery_point_sha256=None, expected_release=None, replace=True)

    def test_legacy_replace_names_zeroed_and_layoutless_target_refusal(self):
        self.legacy_point(); self.output.mkdir()
        valid = (self.backup / rel.IMAGE).read_bytes()
        for value in (bytes(len(valid)), bytes(512) + valid[512:]):
            with self.subTest(zeroed=value == bytes(len(valid))):
                (self.output / rel.IMAGE).write_bytes(value)
                self.refuse("restore_target_not_clean:.*no filesystem region", recovery_point_sha256=None,
                            expected_release=None, replace=True)

    def test_legacy_replace_over_clean_ended_target_still_copies_exactly(self):
        self.legacy_point(); self.output.mkdir()
        disk(self.output / rel.IMAGE, extra={"/home/operator/data/state.bin": b"earlier clean state"})
        rel.cmd_restore(self.legacy_args(), log=lambda _: None)
        self.assertEqual(sha(self.output / rel.IMAGE), sha(self.backup / rel.IMAGE))


if __name__ == "__main__":
    unittest.main()
