"""Host-only controls for scripts/install_disk.py on sparse image files in a
temporary directory: the layout and both GPT copies, every refusal with the
target's bytes unchanged, the exact-disk confirmation, and the read-back's
negative controls. No device is opened; the block-device case is a stat
the test fakes. Needs the pinned gdisk, dosfstools, mtools and GRUB; a host
without them skips the install cases and says so."""
import contextlib
import errno
import hashlib
import io
import json
import os
import pathlib
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
import uuid
import zlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import install_disk as inst  # noqa: E402
import media  # noqa: E402

GIB = 1 << 30
SIZE = 3 * GIB


def tools_ready():
    try:
        media.check_pins(inst.load_profile(), env=media.clean_env(0))
        for name in ("sgdisk", "mkfs.vfat", "mcopy", "mmd", "mtype", "grub-mkstandalone", "grub-file"):
            media.tool(name)
    except media.Refused as error:
        return str(error)
    return None


SKIP = tools_ready()


def multiboot2_stub(path):
    magic, arch, length = 0xE85250D6, 0, 24
    header = struct.pack("<IIII", magic, arch, length, (-(magic + arch + length)) & 0xFFFFFFFF)
    path.write_bytes(header + struct.pack("<HHI", 0, 0, 8) + bytes(4096))


class BrokenStream(io.TextIOBase):
    """A stream whose reader has gone: every write and flush raises EPIPE."""

    def write(self, text):
        raise BrokenPipeError(errno.EPIPE, "Broken pipe")

    def flush(self):
        raise BrokenPipeError(errno.EPIPE, "Broken pipe")

    def fileno(self):
        raise io.UnsupportedOperation("no descriptor")


def file_sha(path):
    return sparse_sha(path)


def sparse_sha(path):
    """The file's size and every data extent's offset and bytes: equal for
    two files exactly when their bytes are equal, provided neither turned a
    hole into written zeros (a stricter comparison, never a looser one)."""
    fd = os.open(path, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        digest = hashlib.sha256(str(size).encode())
        for lo, hi in inst.data_extents(fd, 0, size):
            digest.update(f"@{lo}:{hi}".encode())
            digest.update(os.pread(fd, hi - lo, lo))
        return digest.hexdigest()
    finally:
        os.close(fd)


@unittest.skipIf(SKIP is not None, f"install tools unavailable: {SKIP}")
class InstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="test-install-disk-")
        cls.root = pathlib.Path(cls.tmp.name)
        cls.kernel = cls.root / "kernel.elf"
        multiboot2_stub(cls.kernel)
        cls.golden = cls.root / "golden.img"
        cls.golden_receipt = cls.root / "golden.json"
        cls.make(cls.golden)
        code, out, err = cls.run_install(cls.golden, cls.golden_receipt)
        assert code == 0, err

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @staticmethod
    def make(path, size=SIZE):
        with open(path, "xb") as handle:
            handle.truncate(size)

    @classmethod
    def run_install(cls, target, receipt, *extra, serial="absd-test"):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = inst.main(["install", "--target", str(target), "--kernel", str(cls.kernel), "--serial", serial,
                              "--receipt", str(receipt), *extra])
        return code, out.getvalue(), err.getvalue()

    def fresh(self, name, size=SIZE):
        path = self.root / name
        if path.exists():
            path.unlink()
        self.make(path, size)
        return path

    def copy_golden(self, name):
        path = self.root / name
        subprocess.run(["cp", "--sparse=always", str(self.golden), str(path)], check=True)
        return path

    def read_back(self, path, expect=None):
        fd = os.open(path, os.O_RDONLY)
        try:
            return inst.read_back(fd, os.fstat(fd).st_size, expect)
        finally:
            os.close(fd)

    def assert_refused(self, target, *extra, contains, serial="absd-test", kernel=None):
        before = file_sha(target)
        receipt = self.root / f"refused-{uuid.uuid4().hex}.json"
        code, out, err = self.run_install(target, receipt, *extra, serial=serial)
        self.assertEqual(code, 2, out + err)
        self.assertIn("INSTALL REFUSED", err)
        self.assertIn(contains, err)
        self.assertFalse(receipt.exists())
        self.assertEqual(file_sha(target), before, "a refused install changed the target")
        return err

    # -- the layout ----------------------------------------------------------

    def test_layout_both_copies_and_receipt(self):
        receipt = json.loads(self.golden_receipt.read_text())
        table = self.read_back(self.golden, receipt["guids"])
        esp, absd = table["partitions"]
        self.assertEqual((esp["type"], esp["first_lba"], esp["last_lba"]), (inst.ESP_TYPE, 2048, 2048 + 524288 - 1))
        self.assertEqual((absd["type"], absd["first_lba"]), ("7AF614A7-2C5B-4EBA-B8F6-217AEC90357A", 526336))
        self.assertEqual((absd["last_lba"] - absd["first_lba"] + 1) * 512, 2 * GIB)
        self.assertEqual(absd["first_lba"] % 2048, 0)
        last = SIZE // 512 - 1
        self.assertEqual(table["backup"]["my_lba"], last)
        self.assertEqual(table["backup"]["entries_lba"], last - 32)
        self.assertEqual(table["unallocated_lba"], [inst.ABSD_END, last - 33])
        self.assertTrue(receipt["layout"]["absd"]["zero"])
        self.assertTrue(receipt["target"]["was_empty"])
        self.assertIn(f"block-partition={receipt['guids']['absd'].lower()} ahci-write=absd-test",
                      receipt["grub"]["kernel_line"])
        self.assertTrue(receipt["grub"]["kernel_line"].startswith("multiboot2 /BOOT/KERNEL.ELF durable=0 net fsd served "))
        self.assertEqual(receipt["types"]["absd"], inst.ABSD_TYPE)
        self.assertEqual(receipt["inputs"]["kernel"]["sha256"], hashlib.sha256(self.kernel.read_bytes()).hexdigest())
        self.assertIn("No problems found", receipt["readback"]["sgdisk_verify"])
        for name in ("sgdisk", "mkfs.vfat", "grub-mkstandalone"):
            self.assertIn(name, receipt["tools"])
        out = subprocess.run(["sgdisk", "--verify", str(self.golden)], capture_output=True, text=True).stdout
        self.assertIn("No problems found", out)

    def test_bytes_outside_the_regions_are_never_written(self):
        target = self.fresh("outside.img")
        fd = os.open(target, os.O_RDWR)
        marks = [inst.ABSD_END * 512, inst.ABSD_END * 512 + 12345, SIZE - 33 * 512 - 1]
        for at in marks:
            os.pwrite(fd, b"\xa5", at)
        os.close(fd)
        code, _, err = self.run_install(target, self.root / "outside.json")
        self.assertEqual(code, 0, err)
        fd = os.open(target, os.O_RDONLY)
        try:
            for at in marks:
                self.assertEqual(os.pread(fd, 1, at), b"\xa5")
            self.assertEqual(inst.first_nonzero(fd, inst.ABSD_FIRST * 512, inst.ABSD_END * 512), None)
            hole = [b for b in (inst.first_nonzero(fd, inst.ABSD_END * 512, SIZE - 33 * 512),)]
            self.assertEqual(hole, [marks[0]])
        finally:
            os.close(fd)
        # The unallocated span held data, so the receipt records its SHA-256.
        outside = json.loads((self.root / "outside.json").read_text())["outside"]["unallocated"]
        self.assertFalse(outside["all_zero"])
        self.assertEqual(self.verify(target, self.root / "outside.json")[0], 0)
        fd = os.open(target, os.O_RDWR)
        os.pwrite(fd, b"\x5a", marks[1])
        os.close(fd)
        code, err = self.verify(target, self.root / "outside.json")
        self.assertEqual(code, 2)
        self.assertIn("region_changed unallocated: its content digest", err)

    def test_each_install_has_fresh_guids_and_odd_sizes_work(self):
        size = SIZE + 7 * 512 + 3 * (1 << 20)
        target = self.fresh("odd.img", size)
        receipt = self.root / "odd.json"
        code, _, err = self.run_install(target, receipt)
        self.assertEqual(code, 0, err)
        mine = json.loads(receipt.read_text())["guids"]
        golden = json.loads(self.golden_receipt.read_text())["guids"]
        self.assertEqual(len(set(mine.values()) | set(golden.values())), 6)
        table = self.read_back(target, mine)
        self.assertEqual(table["backup"]["my_lba"], size // 512 - 1)

    def verify(self, target, receipt):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = inst.main(["verify", "--target", str(target), "--receipt", str(receipt), "--outside-unchanged"])
        return code, out.getvalue() + err.getvalue()

    def test_verify_outside_unchanged(self):
        code, text = self.verify(self.golden, self.golden_receipt)
        self.assertEqual(code, 0, text)
        self.assertIn("VERIFY OK", text)
        self.assertIn("outside_absd=unchanged", text)
        self.assertTrue(json.loads(self.golden_receipt.read_text())["outside"]["unallocated"]["all_zero"])
        last = SIZE // 512 - 1
        for name, offset, contains in (
                ("esp", (inst.ESP_FIRST + 100000) * 512, "region_changed esp"),
                ("head", 100, "region_changed head_lba0_2047"),   # MBR boot code
                ("unallocated-first", inst.ABSD_END * 512, "region_changed unallocated: non-zero byte"),
                ("unallocated-mid", (inst.ABSD_END + 777777) * 512 + 3, "region_changed unallocated: non-zero byte"),
                ("unallocated-last", (last - 32) * 512 - 1, "region_changed unallocated: non-zero byte")):
            with self.subTest(region=name):
                target = self.copy_golden(f"outside-{name}.img")
                fd = os.open(target, os.O_RDWR)
                os.pwrite(fd, b"\x01", offset)
                os.close(fd)
                code, text = self.verify(target, self.golden_receipt)
                self.assertEqual(code, 2)
                self.assertIn(contains, text)
        # A write inside the ABSD partition is the guest's business: allowed.
        target = self.copy_golden("absd-written.img")
        fd = os.open(target, os.O_RDWR)
        os.pwrite(fd, b"ABSDLAY1", inst.ABSD_FIRST * 512)
        os.close(fd)
        self.assertEqual(self.verify(target, self.golden_receipt)[0], 0)

    # -- refusals, target unchanged --------------------------------------------

    def test_refuses_an_existing_gpt(self):
        target = self.fresh("gpt.img")
        subprocess.run(["sgdisk", "-o", "-n", "1:2048:+100M", str(target)], check=True, capture_output=True)
        self.assert_refused(target, contains="target_not_empty")

    def test_refuses_mbr_only(self):
        target = self.fresh("mbr.img")
        mbr = bytearray(512)
        mbr[446:462] = struct.pack("<B3sB3sII", 0x80, b"\0\0\0", 0x83, b"\0\0\0", 2048, 204800)
        mbr[510:] = b"\x55\xaa"
        fd = os.open(target, os.O_RDWR)
        os.pwrite(fd, bytes(mbr), 0)
        os.close(fd)
        err = self.assert_refused(target, contains="mbr-55aa@510")
        self.assertIn("first MiB sha256", err)

    def test_refuses_nonzero_bytes_in_each_region(self):
        for name, at in (("head", 4096 * 3), ("esp", inst.ESP_FIRST * 512 + 777), ("absd", inst.ABSD_FIRST * 512 + 5),
                         ("absd-last", inst.ABSD_END * 512 - 1), ("tail", SIZE - 33 * 512), ("last", SIZE - 1)):
            with self.subTest(region=name):
                target = self.fresh(f"nz-{name}.img")
                fd = os.open(target, os.O_RDWR)
                os.pwrite(fd, b"\x01", at)
                os.close(fd)
                self.assert_refused(target, contains=f"nonzero@{at}")

    def test_refuses_an_installed_disk(self):
        self.assert_refused(self.copy_golden("again.img"), contains="gpt-header@512")

    def test_refuses_bad_targets_and_options(self):
        small = self.fresh("small.img", inst.MIN_SECTORS * 512 - 512)
        self.assert_refused(small, contains="target_too_small")
        ragged = self.fresh("ragged.img", SIZE + 100)
        self.assert_refused(ragged, contains="whole number of 512-byte sectors")
        link = self.root / "link.img"
        link.symlink_to(self.fresh("linked.img"))
        self.assert_refused(link, contains="is a link")
        empty = self.fresh("opts.img")
        self.assert_refused(empty, "--boot-options", "durable=0 nvme-write=x", contains="boot_options_refused")
        self.assert_refused(empty, "--boot-options", "durable=0 block-partition=x", contains="boot_options_refused")
        self.assert_refused(empty, serial="has space", contains="serial_refused")
        self.assert_refused(empty, serial="x" * 21, contains="serial_refused")
        self.assert_refused(empty, "--allow-block-device", contains="not implemented")
        self.assert_refused(empty, "--kernel-sha256", "0" * 64, contains="kernel_mismatch")
        code, _, err = self.run_install(self.root / "missing.img", self.root / "m.json")
        self.assertEqual(code, 2)
        self.assertIn("target_missing", err)
        self.assertFalse((self.root / "missing.img").exists())

    def test_refuses_a_non_multiboot_kernel(self):
        bad = self.root / "notakernel.elf"
        bad.write_bytes(bytes(8192))
        target = self.fresh("badkernel.img")
        before = file_sha(target)
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = inst.main(["install", "--target", str(target), "--kernel", str(bad), "--serial", "s",
                              "--receipt", str(self.root / "bk.json")])
        self.assertEqual(code, 2)
        self.assertIn("not a multiboot2 kernel", err.getvalue())
        self.assertEqual(file_sha(target), before)

    def test_refuses_a_block_device_before_opening_it(self):
        target = self.fresh("pretend-device.img")
        real_stat = os.lstat

        def fake_stat(path, *args, **kwargs):
            st = real_stat(path, *args, **kwargs)
            if str(path) == str(target):
                values = list(st)
                values[0] = stat.S_IFBLK | 0o660
                return os.stat_result(values)
            return st

        opened = []
        real_open = os.open
        before = file_sha(target)
        with unittest.mock.patch.object(inst.os, "lstat", fake_stat), \
                unittest.mock.patch.object(inst.os, "open", lambda p, *a, **k: opened.append(p) or real_open(p, *a, **k)):
            code, _, err = self.run_install(target, self.root / "device.json")
        self.assertEqual(code, 2)
        self.assertIn("block_device_refused", err)
        self.assertNotIn(str(target), [str(p) for p in opened])
        self.assertEqual(file_sha(target), before)

    def test_refuses_an_existing_receipt(self):
        target = self.fresh("receipt-exists.img")
        receipt = self.root / "exists.json"
        receipt.write_text("{}")
        before = file_sha(target)
        code, _, err = self.run_install(target, receipt)
        self.assertEqual(code, 2)
        self.assertIn("receipt_exists", err)
        self.assertEqual(file_sha(target), before)

    # -- exact-disk confirmation -----------------------------------------------

    def confirmation(self, target):
        handle = inst.Target(target, writable=False)
        try:
            return inst.identity(handle)
        finally:
            handle.close()

    def test_confirmation_must_name_this_exact_disk(self):
        target = self.fresh("confirm.img")
        subprocess.run(["sgdisk", "-o", "-n", "1:2048:+100M", str(target)], check=True, capture_output=True)
        fd = os.open(target, os.O_RDWR)
        os.pwrite(fd, b"old data", inst.ABSD_FIRST * 512 + 4096)
        os.pwrite(fd, b"keep", inst.ABSD_END * 512 + 4096)
        os.close(fd)
        ident = self.confirmation(target)
        good = inst.token(ident)
        wrong = {
            "size+1": good.replace(f"bytes={SIZE}", f"bytes={SIZE + 1}"),
            "size-1": good.replace(f"bytes={SIZE}", f"bytes={SIZE - 1}"),
            "sha": good.replace(ident["first_mib_sha256"], "0" * 64),
            "path": good.replace(ident["path"], ident["path"] + ".other"),
            "dev": good.replace(f"dev={ident['dev']}", f"dev={ident['dev'] + 1}"),
            "ino": good.replace(f"ino={ident['ino']}", f"ino={ident['ino'] + 1}"),
            "regions": good.replace(ident["regions_sha256"], "0" * 64),
        }
        for name, text in wrong.items():
            with self.subTest(wrong=name):
                self.assert_refused(target, "--confirm-disk", text, contains="confirm_mismatch")
        dropped = ",".join(f for f in good[6:].split(",") if not f.startswith("regions-sha256="))
        for text in ("image:bytes=1", "disk:" + good[6:], good + ",extra=1", "image:" + dropped,
                     good.replace(ident["regions_sha256"], ident["regions_sha256"].upper()),
                     "device:serial=X,bytes=1,first-mib-sha256=" + "0" * 64):
            with self.subTest(malformed=text):
                self.assert_refused(target, "--confirm-disk", text, contains="confirm_")
        # The token of another, identical-looking disk is not this disk's.
        twin = self.root / "twin.img"
        subprocess.run(["cp", "--sparse=always", str(target), str(twin)], check=True)
        self.assert_refused(twin, "--confirm-disk", good, contains="confirm_mismatch path")
        receipt = self.root / "confirm.json"
        code, out, err = self.run_install(target, receipt, "--confirm-disk", good)
        self.assertEqual(code, 0, err)
        record = json.loads(receipt.read_text())
        self.assertFalse(record["target"]["was_empty"])
        self.assertEqual(record["target"]["confirmed_overwrite"], good)
        self.read_back(target, record["guids"])
        fd = os.open(target, os.O_RDONLY)
        try:
            self.assertIsNone(inst.first_nonzero(fd, inst.ABSD_FIRST * 512, inst.ABSD_END * 512))
            self.assertEqual(os.pread(fd, 4, inst.ABSD_END * 512 + 4096), b"keep")
        finally:
            os.close(fd)
        # The same token is spent: the first MiB changed with the install.
        self.assert_refused(target, "--confirm-disk", good, contains="confirm_mismatch first_mib_sha256")

    def test_token_refused_on_a_replaced_image_with_the_same_path_and_first_mib(self):
        target = self.fresh("replaced.img")
        subprocess.run(["sgdisk", "-o", "-n", "1:2048:+100M", str(target)], check=True, capture_output=True)
        good = inst.token(self.confirmation(target))
        # Same path, same size, byte-identical copy (so the same first MiB
        # and regions): another file all the same.
        twin = self.root / "replaced.new"
        subprocess.run(["cp", "--sparse=always", str(target), str(twin)], check=True)
        os.replace(twin, target)
        self.assert_refused(target, "--confirm-disk", good, contains="confirm_mismatch ino")
        # The same file with a change only beyond the first MiB, inside what
        # install would erase.
        target = self.fresh("changed-in-place.img")
        subprocess.run(["sgdisk", "-o", "-n", "1:2048:+100M", str(target)], check=True, capture_output=True)
        good = inst.token(self.confirmation(target))
        fd = os.open(target, os.O_RDWR)
        os.pwrite(fd, b"later data", inst.ABSD_FIRST * 512 + 8192)
        os.close(fd)
        self.assert_refused(target, "--confirm-disk", good, contains="confirm_mismatch regions_sha256")

    def hooked(self, hook):
        return unittest.mock.patch.object(inst, "_HOOK", hook)

    def test_target_replaced_between_inspection_and_writing(self):
        target = self.fresh("swap.img")
        original = self.root / "swap.original"
        os.link(target, original)                  # keep the inspected object reachable
        replacement = self.fresh("swap.replacement")
        fd = os.open(replacement, os.O_RDWR)
        os.pwrite(fd, b"someone else's disk", 4096)
        os.close(fd)
        before_original, before_replacement = file_sha(original), file_sha(replacement)

        def swap(phase, path):
            if phase == "inspected":
                os.replace(replacement, path)

        receipt = self.root / "swap.json"
        with self.hooked(swap):
            code, _, err = self.run_install(target, receipt)
        self.assertEqual(code, 2, err)
        self.assertIn("target_changed", err)
        self.assertIn("now names another file", err)
        self.assertFalse(receipt.exists())
        self.assertEqual(file_sha(original), before_original)
        self.assertEqual(file_sha(target), before_replacement)   # the replacement, now at the path

    def test_symlink_to_a_block_device_swapped_in_is_never_written(self):
        target = self.fresh("swaplink.img")
        original = self.root / "swaplink.original"
        os.link(target, original)
        before = file_sha(original)
        seen = []

        def swap(phase, path):
            if phase == "inspected":
                os.unlink(path)
                os.symlink("/dev/null", path)        # stands in for a block device; never opened
                seen.append(os.path.islink(path))

        real_run = subprocess.run

        def no_path(argv, *a, **k):
            self.assertNotIn(str(target), [str(x) for x in argv])
            return real_run(argv, *a, **k)

        with self.hooked(swap), unittest.mock.patch.object(inst.subprocess, "run", no_path):
            code, _, err = self.run_install(target, self.root / "swaplink.json")
        self.assertEqual(seen, [True])
        self.assertEqual(code, 2, err)
        self.assertIn("is now a link", err)
        self.assertEqual(file_sha(original), before)
        self.assertFalse((self.root / "swaplink.json").exists())

    def test_tools_get_the_descriptor_never_the_path(self):
        target = self.fresh("fdonly.img")
        argvs = []
        real_run = subprocess.run

        def record(argv, *a, **k):
            argvs.append([str(x) for x in argv])
            return real_run(argv, *a, **k)

        with unittest.mock.patch.object(inst.subprocess, "run", record):
            code, _, err = self.run_install(target, self.root / "fdonly.json")
        self.assertEqual(code, 0, err)
        flat = [x for argv in argvs for x in argv]
        self.assertNotIn(str(target), flat)
        self.assertTrue(any(x.startswith("/dev/fd/") for x in flat))

    def test_failure_after_the_first_write_exits_3_with_a_failure_receipt(self):
        for when in ("after-gpt", "after-esp"):
            with self.subTest(after=when):
                target = self.fresh(f"fail-{when}.img")

                def fail(phase, path, when=when):
                    if phase == when:
                        raise OSError(5, "simulated I/O error")

                receipt = self.root / f"fail-{when}.json"
                with self.hooked(fail):
                    code, _, err = self.run_install(target, receipt)
                self.assertEqual(code, 3, err)
                self.assertIn("INSTALL FAILED", err)
                record = json.loads(receipt.read_text())
                self.assertEqual(record["schema"], "absd-disk-install-failure/1")
                self.assertEqual(record["failed_step"], when)
                self.assertEqual(record["steps_completed"], ["gpt"] if when == "after-gpt" else ["gpt", "esp"])
                self.assertEqual(record["write_regions"], [list(r) for r in inst.regions(SIZE)])
                self.assertIn("simulated I/O error", record["error"])
                self.assertIn("--confirm-disk", record["recovery"])
                self.assertEqual(record["target"]["bytes"], SIZE)
                # Recovery as documented: a fresh token, then a confirmed install.
                good = inst.token(self.confirmation(target))
                code, _, err = self.run_install(target, self.root / f"fail-{when}-retry.json", "--confirm-disk", good)
                self.assertEqual(code, 0, err)
        # The target swapped while the writes are under way: the writes went
        # to the validated file, the replacement is untouched, exit 3.
        target = self.fresh("swap-mid.img")
        replacement = self.fresh("swap-mid.replacement")
        before = file_sha(replacement)

        def swap(phase, path):
            if phase == "after-gpt":
                os.replace(replacement, path)

        receipt = self.root / "swap-mid.json"
        with self.hooked(swap):
            code, _, err = self.run_install(target, receipt)
        self.assertEqual(code, 3, err)
        self.assertEqual(json.loads(receipt.read_text())["failed_step"], "esp")
        self.assertIn("now names another file", json.loads(receipt.read_text())["error"])
        self.assertEqual(file_sha(target), before)

    def test_preflight_refuses_missing_git_before_any_write(self):
        target = self.fresh("nogit.img")
        real_tool = media.tool

        def no_git(name):
            if name == "git":
                raise media.Refused("tool_missing git (package git) is not on /usr/sbin:/usr/bin:/sbin:/bin")
            return real_tool(name)

        phases = []
        with unittest.mock.patch.object(media, "tool", no_git), self.hooked(lambda p, path: phases.append(p)):
            err = self.assert_refused(target, contains="tool_missing git")
        self.assertEqual(phases, [], "the target was opened before the git preflight")
        self.assertNotIn("INSTALL FAILED", err)

    def test_receipt_destination_is_checked_before_any_write(self):
        target = self.fresh("receipt-dest.img")
        before = file_sha(target)
        cases = {"missing": (self.root / "no-such-dir" / "r.json", "does not exist")}
        readonly = self.root / "readonly-dir"
        readonly.mkdir()
        os.chmod(readonly, 0o500)
        if not os.access(readonly, os.W_OK):     # (root can write anyway)
            cases["read-only"] = (readonly / "r.json", "is not writable")
        try:
            for name, (receipt, contains) in cases.items():
                with self.subTest(case=name):
                    code, _, err = self.run_install(target, receipt)
                    self.assertEqual(code, 2, err)
                    self.assertIn("receipt_refused", err)
                    self.assertIn(contains, err)
                    self.assertFalse(receipt.exists())
                    self.assertEqual(file_sha(target), before)
            with unittest.mock.patch.object(inst, "RECEIPT_RESERVE", 1 << 62):
                code, _, err = self.run_install(target, self.root / "full.json")
            self.assertEqual(code, 2)
            self.assertIn("bytes free", err)
            self.assertEqual(file_sha(target), before)
        finally:
            os.chmod(readonly, 0o700)

    def test_a_late_metadata_failure_after_the_writes_is_exit_3(self):
        target = self.fresh("late-meta.img")
        receipt = self.root / "late-meta.json"

        def broken():
            raise media.Refused("tool_missing git (removed after the preflight)")

        with unittest.mock.patch.object(media, "tools_used", broken):
            code, _, err = self.run_install(target, receipt)
        self.assertEqual(code, 3, err)
        self.assertIn("INSTALL FAILED step=receipt", err)
        self.assertIn(str(target.resolve()), err)
        self.assertIn(str(inst.regions(SIZE)[0][1]), err)
        record = json.loads(receipt.read_text())
        self.assertEqual(record["schema"], "absd-disk-install-failure/1")
        self.assertEqual(record["failed_step"], "receipt")
        self.assertEqual(record["steps_completed"], ["gpt", "esp", "readback"])

    def test_a_receipt_write_error_after_the_writes_is_exit_3_and_names_the_target(self):
        real = inst._write_all
        for name, failures in (("enospc-once", 1), ("eio-always", 99)):
            with self.subTest(case=name):
                target = self.fresh(f"{name}.img")
                receipt = self.root / f"{name}.json"
                left = [failures]

                def flaky(fd, data, left=left):
                    if left[0] > 0:
                        left[0] -= 1
                        os.write(fd, data[:100])          # a partial write, then the error
                        raise OSError(errno.ENOSPC if name.startswith("enospc") else errno.EIO, "simulated")
                    return real(fd, data)

                with unittest.mock.patch.object(inst, "_write_all", flaky):
                    code, out, err = self.run_install(target, receipt)
                self.assertEqual(code, 3, err)
                self.assertIn("INSTALL FAILED step=receipt", err)
                self.assertIn(str(target.resolve()), err)
                self.assertIn("only in byte ranges", err)
                if failures == 1:
                    record = json.loads(receipt.read_text())        # the failure receipt, not a truncated one
                    self.assertEqual(record["schema"], "absd-disk-install-failure/1")
                    self.assertIn("simulated", record["error"])
                else:
                    self.assertFalse(receipt.exists(), "a truncated receipt was left behind")
                    self.assertIn("printing it to stdout", err)
                    printed = json.loads(out.split("INSTALL FAILURE RECEIPT\n", 1)[1])
                    self.assertEqual(printed["schema"], "absd-disk-install-failure/1")
                    self.assertEqual(printed["target"]["path"], str(target.resolve()))
                # The disk itself was installed; only the record failed.
                self.read_back(target)

    def test_cleanup_errors_never_replace_the_outcome(self):
        real = inst._write_all
        # Writes done, success receipt ENOSPC, failure receipt written, then
        # the staging cleanup fails with EIO: still exit 3, target named.
        target = self.fresh("combined.img")
        receipt = self.root / "combined.json"
        left = [1]

        def enospc_once(fd, data):
            if left[0]:
                left[0] -= 1
                raise OSError(errno.ENOSPC, "simulated ENOSPC")
            return real(fd, data)

        def eio(path, *a, **k):
            raise OSError(errno.EIO, "simulated cleanup EIO")

        with unittest.mock.patch.object(inst, "_write_all", enospc_once), \
                unittest.mock.patch.object(inst, "_rmtree", eio):
            code, _, err = self.run_install(target, receipt)
        self.assertEqual(code, 3, err)
        self.assertIn("INSTALL FAILED step=receipt", err)
        self.assertIn(str(target.resolve()), err)
        self.assertIn("only in byte ranges", err)
        self.assertIn("INSTALL CLEANUP FAILED staging=", err)
        self.assertIn("simulated cleanup EIO", err)
        self.assertEqual(json.loads(receipt.read_text())["schema"], "absd-disk-install-failure/1")
        # The same cleanup failure leaves exit 0 and exit 2 as they were.
        for name, extra, want in (("ok", (), 0), ("refused", ("--kernel-sha256", "0" * 64), 2)):
            with self.subTest(outcome=name):
                target = self.fresh(f"cleanup-{name}.img")
                with unittest.mock.patch.object(inst, "_rmtree", eio):
                    code, _, err = self.run_install(target, self.root / f"cleanup-{name}.json", *extra)
                self.assertEqual(code, want, err)
        # A failing close of the target descriptor is reported the same way.
        target = self.fresh("close-eio.img")
        real_close = inst.Target.close

        def close_eio(handle):
            real_close(handle)
            raise OSError(errno.EIO, "simulated close EIO")

        with unittest.mock.patch.object(inst.Target, "close", close_eio):
            code, _, err = self.run_install(target, self.root / "close-eio.json")
        self.assertEqual(code, 0, err)
        self.assertIn("INSTALL CLEANUP FAILED target-fd=", err)

    def test_a_residual_truncated_receipt_is_named(self):
        target = self.fresh("residual.img")
        receipt = self.root / "residual.json"

        def eio_after_100(fd, data):
            os.write(fd, data[:100])
            raise OSError(errno.EIO, "simulated write EIO")

        def unlink_eio(path):
            raise OSError(errno.EIO, "simulated unlink EIO")

        with unittest.mock.patch.object(inst, "_write_all", eio_after_100), \
                unittest.mock.patch.object(inst, "_unlink", unlink_eio):
            code, out, err = self.run_install(target, receipt)
        self.assertEqual(code, 3, err)
        first = err.splitlines()
        failed = [l for l in first if l.startswith("INSTALL FAILED step=receipt [")]
        self.assertEqual(len(failed), 1, err)
        self.assertIn("simulated write EIO", failed[0])          # the original error, first
        self.assertNotIn("simulated unlink EIO", failed[0])
        self.assertEqual(first.index(failed[0]), 0, "the target line must come first")
        residual = [l for l in first if "residual_receipt:" in l]
        self.assertTrue(residual, err)
        self.assertIn(f"{receipt} (truncated, remove it", residual[0])
        self.assertIn("simulated unlink EIO", residual[0])        # the removal's error, secondary
        self.assertTrue(receipt.exists())
        self.assertEqual(receipt.stat().st_size, 100)
        printed = json.loads(out.split("INSTALL FAILURE RECEIPT\n", 1)[1])
        self.assertTrue(any(str(receipt) in r for r in printed["residual_receipt"]))

    # -- reporting never changes the outcome -----------------------------------

    def run_with_streams(self, argv, stdout_broken, stderr_broken):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(BrokenStream() if stdout_broken else out), \
                contextlib.redirect_stderr(BrokenStream() if stderr_broken else err):
            code = inst.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_reporting_matrix_with_broken_streams(self):
        """Every path after the first write (and the refusal, verify and
        identity paths), with stdout broken, stderr broken and both: the exit
        status is the decided one, the target and its regions are named
        whenever stderr works, and a receipt that exists is complete."""
        real_write = inst._write_all

        def enospc_once():
            left = [1]

            def write(fd, data):
                if left[0]:
                    left[0] -= 1
                    raise OSError(errno.ENOSPC, "simulated ENOSPC")
                return real_write(fd, data)
            return write

        def always_eio(fd, data):
            os.write(fd, data[:100])
            raise OSError(errno.EIO, "simulated EIO")

        def raise_after_gpt(phase, path):
            if phase == "after-gpt":
                raise OSError(errno.EIO, "simulated I/O error")

        def eio(*a, **k):
            raise OSError(errno.EIO, "simulated cleanup EIO")

        paths = {
            "success": (0, lambda: [], ()),
            "after-gpt": (3, lambda: [unittest.mock.patch.object(inst, "_HOOK", raise_after_gpt)], ()),
            "receipt-enospc": (3, lambda: [unittest.mock.patch.object(inst, "_write_all", enospc_once())], ()),
            "receipt-to-stdout": (3, lambda: [unittest.mock.patch.object(inst, "_write_all", always_eio)], ()),
            "residual": (3, lambda: [unittest.mock.patch.object(inst, "_write_all", always_eio),
                                     unittest.mock.patch.object(inst, "_unlink", eio)], ()),
            "enospc-and-cleanup": (3, lambda: [unittest.mock.patch.object(inst, "_write_all", enospc_once()),
                                               unittest.mock.patch.object(inst, "_rmtree", eio)], ()),
            "refused": (2, lambda: [], ("--kernel-sha256", "0" * 64)),
        }
        for name, (want, patches, extra) in paths.items():
            for mode in ("stdout", "stderr", "both"):
                with self.subTest(path=name, broken=mode):
                    target = self.fresh(f"rep-{name}-{mode}.img")
                    receipt = self.root / f"rep-{name}-{mode}.json"
                    argv = ["install", "--target", str(target), "--kernel", str(self.kernel), "--serial", "absd-test",
                            "--receipt", str(receipt), *extra]
                    with contextlib.ExitStack() as stack:
                        for patch in patches():
                            stack.enter_context(patch)
                        code, out, err = self.run_with_streams(argv, mode in ("stdout", "both"), mode in ("stderr", "both"))
                    self.assertEqual(code, want, err)
                    if want == 3 and mode == "stdout":
                        lines = err.splitlines()
                        self.assertTrue(lines[0].startswith("INSTALL FAILED step="), err)
                        self.assertIn(str(target.resolve()), lines[0])
                        self.assertIn(str(inst.regions(SIZE)), lines[0])
                    if receipt.exists() and name != "residual":
                        record = json.loads(receipt.read_text())       # complete, parseable
                        self.assertIn(record["schema"], (inst.SCHEMA, inst.FAILURE_SCHEMA))
                    if want == 0:
                        self.assertEqual(json.loads(receipt.read_text())["schema"], inst.SCHEMA)
        for command in (["verify", "--target", str(self.golden), "--receipt", str(self.golden_receipt),
                         "--outside-unchanged"], ["identity", "--target", str(self.golden)]):
            for mode in ("stdout", "stderr", "both"):
                with self.subTest(command=command[0], broken=mode):
                    code, _, _ = self.run_with_streams(command, mode in ("stdout", "both"), mode in ("stderr", "both"))
                    self.assertEqual(code, 0)

    def cli(self, argv, stdout_closed, stderr_closed, wrapper=None):
        """The real CLI in a subprocess, with stdout and/or stderr on a pipe
        whose read end is already closed (EPIPE on the first write and at the
        interpreter's exit flush). `wrapper` is Python run before cli()."""
        script = pathlib.Path(inst.__file__)
        if wrapper is None:
            command = [sys.executable, "-I", "-B", "-X", f"pycache_prefix={sys.pycache_prefix or ''}", str(script), *argv]
        else:
            code = (f"import sys; sys.path.insert(0, {str(script.parent)!r}); import install_disk as inst; "
                    f"{wrapper}; inst.run({argv!r})")
            command = [sys.executable, "-I", "-B", "-X", f"pycache_prefix={sys.pycache_prefix or ''}", "-c", code]
        fds = {}
        for name, closed in (("stdout", stdout_closed), ("stderr", stderr_closed)):
            if closed:
                r, w = os.pipe()
                os.close(r)
                fds[name] = w
            else:
                fds[name] = subprocess.PIPE
        done = subprocess.run(command, stdout=fds["stdout"], stderr=fds["stderr"], timeout=300)
        for value in fds.values():
            if isinstance(value, int) and value >= 0:
                os.close(value)
        return done.returncode, (done.stdout or b"").decode(), (done.stderr or b"").decode()

    def test_real_cli_with_closed_pipes(self):
        for mode in ("stdout", "both"):
            with self.subTest(path="success", closed=mode):
                target = self.fresh(f"cli-ok-{mode}.img")
                receipt = self.root / f"cli-ok-{mode}.json"
                code, _, err = self.cli(["install", "--target", str(target), "--kernel", str(self.kernel), "--serial",
                                         "absd-test", "--receipt", str(receipt)], True, mode == "both")
                self.assertEqual(code, 0, err)
                self.assertNotIn("Exception ignored", err)
                self.assertEqual(json.loads(receipt.read_text())["schema"], inst.SCHEMA)
                self.read_back(target)
        wrapper = ("import errno, os\n"
                   "def eio(fd, data):\n"
                   "    raise OSError(errno.EIO, 'simulated EIO')\n"
                   "inst._write_all = eio")
        wrapper = f"exec({wrapper!r})"
        for mode in ("stdout", "stderr", "both"):
            with self.subTest(path="receipt-to-stdout", closed=mode):
                target = self.fresh(f"cli-fail-{mode}.img")
                receipt = self.root / f"cli-fail-{mode}.json"
                argv = ["install", "--target", str(target), "--kernel", str(self.kernel), "--serial", "absd-test",
                        "--receipt", str(receipt)]
                code, out, err = self.cli(argv, mode in ("stdout", "both"), mode in ("stderr", "both"), wrapper)
                self.assertEqual(code, 3, err)
                self.assertFalse(receipt.exists())
                if mode == "stdout":
                    first = err.splitlines()[0]
                    self.assertTrue(first.startswith("INSTALL FAILED step=receipt"), err)
                    self.assertIn(str(target.resolve()), first)
                    self.assertIn(str(inst.regions(SIZE)), first)
                    self.assertIn("could not be printed to stdout either", err)
                if mode == "stderr":
                    self.assertIn("INSTALL FAILURE RECEIPT", out)
        for argv in (["verify", "--target", str(self.golden), "--receipt", str(self.golden_receipt), "--outside-unchanged"],
                     ["identity", "--target", str(self.golden)]):
            with self.subTest(command=argv[0]):
                code, _, err = self.cli(argv, True, False)
                self.assertEqual(code, 0, err)
                self.assertNotIn("Exception ignored", err)
        target = self.fresh("cli-refused.img")
        code, _, _ = self.cli(["install", "--target", str(target), "--kernel", str(self.kernel), "--serial", "s",
                               "--receipt", str(self.root / "cli-refused.json"), "--kernel-sha256", "0" * 64], True, True)
        self.assertEqual(code, 2)

    def test_a_closed_output_descriptor_keeps_the_status(self):
        """A stream whose descriptor itself is closed (not a pipe with its read
        end closed): /dev/null then takes the same number, and silencing must
        keep it rather than close it again, or the exit flush fails with EBADF
        and the status becomes 120."""
        script = pathlib.Path(inst.__file__)
        for status in (0, 3):
            with self.subTest(status=status):
                code = (f"import os, sys; sys.path.insert(0, {str(script.parent)!r}); import install_disk as inst; "
                        f"os.close(1); inst.emit('stdout', 'INSTALL OK'); inst.emit('stdout', 'again'); "
                        f"inst.finish({status})")
                done = subprocess.run([sys.executable, "-I", "-B", "-X", f"pycache_prefix={sys.pycache_prefix or ''}", "-c", code], stderr=subprocess.PIPE, timeout=60)
                self.assertEqual(done.returncode, status, done.stderr)
                self.assertNotIn(b"Bad file descriptor", done.stderr)
        for status in (0, 3):
            with self.subTest(stream="stderr", status=status):
                code = (f"import os, sys; sys.path.insert(0, {str(script.parent)!r}); import install_disk as inst; "
                        f"os.close(2); inst.emit('stderr', 'INSTALL FAILED x'); inst.finish({status})")
                done = subprocess.run([sys.executable, "-I", "-B", "-X", f"pycache_prefix={sys.pycache_prefix or ''}", "-c", code], stdout=subprocess.PIPE, timeout=60)
                self.assertEqual(done.returncode, status)

    def test_no_devnull_still_keeps_the_status(self):
        """When /dev/null cannot be opened (descriptor exhaustion), the broken
        stream cannot be silenced; finish() must still end with the decided
        status rather than letting the interpreter's exit flush make it 120."""
        script = pathlib.Path(inst.__file__)
        prelude = (f"import errno, os, sys; sys.path.insert(0, {str(script.parent)!r}); import install_disk as inst; "
                   "real = os.open\n"
                   "def no_null(path, flags, *a, **k):\n"
                   "    if path == os.devnull: raise OSError(errno.ENFILE, 'injected ENFILE')\n"
                   "    return real(path, flags, *a, **k)\n"
                   "os.open = no_null\n")
        for closing in ("descriptor", "pipe"):
            for status in (0, 3):
                with self.subTest(closing=closing, status=status):
                    body = "os.close(1)\n" if closing == "descriptor" else ""
                    code = f"exec({(prelude + body + 'inst.emit(\"stdout\", \"INSTALL OK\")\n' + f'inst.finish({status})').__repr__()})"
                    if closing == "pipe":
                        r, w = os.pipe()
                        os.close(r)
                        done = subprocess.run([sys.executable, "-I", "-B", "-X", f"pycache_prefix={sys.pycache_prefix or ''}", "-c", code], stdout=w,
                                              stderr=subprocess.PIPE, timeout=60)
                        os.close(w)
                    else:
                        done = subprocess.run([sys.executable, "-I", "-B", "-X", f"pycache_prefix={sys.pycache_prefix or ''}", "-c", code], stderr=subprocess.PIPE,
                                              timeout=60)
                    self.assertEqual(done.returncode, status, done.stderr)

    def test_a_held_lock_refuses(self):
        import fcntl
        target = self.fresh("locked.img")
        fd = os.open(target, os.O_RDONLY)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            self.assert_refused(target, contains="target_busy")
        finally:
            os.close(fd)

    # -- read-back negative controls -------------------------------------------

    def corrupt(self, name, offset, data, fix_crc=None):
        target = self.copy_golden(name)
        fd = os.open(target, os.O_RDWR)
        os.pwrite(fd, data, offset)
        if fix_crc:
            fix_crc(fd)
        os.close(fd)
        return target

    def refuse_read_back(self, target, contains):
        with self.assertRaises(inst.Refused) as caught:
            self.read_back(target)
        self.assertIn(contains, str(caught.exception))

    def test_read_back_rejects_damaged_or_inconsistent_copies(self):
        last = SIZE // 512 - 1

        def rewrite_backup_header(fd, mutate):
            sector = bytearray(os.pread(fd, 512, last * 512))
            mutate(sector)
            sector[16:20] = b"\0\0\0\0"
            struct.pack_into("<I", sector, 16, zlib.crc32(bytes(sector[:92])))
            os.pwrite(fd, bytes(sector), last * 512)

        cases = {
            "backup header CRC": (self.corrupt("c1.img", last * 512 + 40, b"\xff"), "gpt_backup header CRC"),
            "backup missing": (self.corrupt("c2.img", last * 512, bytes(512)), "gpt_backup no EFI PART"),
            "backup entries": (self.corrupt("c3.img", (last - 32) * 512 + 200, b"\x99"), "gpt_backup entry array CRC"),
            "primary entries": (self.corrupt("c4.img", 2 * 512 + 70, b"\x99"), "gpt_primary entry array CRC"),
            "mbr": (self.corrupt("c5.img", 450, b"\x83"), "mbr not protective"),
        }

        def backup_disk_guid(fd):
            rewrite_backup_header(fd, lambda s: s.__setitem__(slice(56, 72), uuid.uuid4().bytes_le))
        cases["disk guid differs"] = (self.corrupt("c6.img", 0, b"\0",
                                                   backup_disk_guid), "gpt_copies_differ disk_guid")

        def backup_entries_changed_consistently(fd):
            raw = bytearray(os.pread(fd, 16384, (last - 32) * 512))
            raw[128 + 56:128 + 58] = "Z".encode("utf-16-le")
            os.pwrite(fd, bytes(raw), (last - 32) * 512)
            rewrite_backup_header(fd, lambda s: struct.pack_into("<I", s, 88, zlib.crc32(bytes(raw))))
        cases["backup entries differ"] = (self.corrupt("c7.img", 0, b"\0",
                                                       backup_entries_changed_consistently), "gpt_copies_differ")
        for name, (target, contains) in cases.items():
            with self.subTest(case=name):
                self.refuse_read_back(target, contains)

    def test_read_back_rejects_other_layouts(self):
        third = self.copy_golden("third.img")
        subprocess.run(["sgdisk", "-n", f"3:{inst.ABSD_END}:+1M", str(third)], check=True, capture_output=True)
        self.refuse_read_back(third, "3 partitions")
        retyped = self.copy_golden("retyped.img")
        subprocess.run(["sgdisk", "-t", "2:8300", str(retyped)], check=True, capture_output=True)
        self.refuse_read_back(retyped, "want number 2 type 7AF614A7")
        receipt = json.loads(self.golden_receipt.read_text())
        with self.assertRaises(inst.Refused) as caught:
            self.read_back(self.golden, dict(receipt["guids"], absd=str(uuid.uuid4())))
        self.assertIn("guid_mismatch absd", str(caught.exception))
        moved = self.root / "moved.img"
        self.make(moved)
        subprocess.run(["sgdisk", "-o", "-n", "1:2048:+512M", "-t", "1:ef00", "-n", "2:0:+2G", "-t", f"2:{inst.ABSD_TYPE}",
                        "-c", "1:EFI System", "-c", "2:ABSD", str(moved)], check=True, capture_output=True)
        self.refuse_read_back(moved, "partition 1 is")


class PureTests(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(inst.ABSD_FIRST * 512 % (1 << 20), 0)
        self.assertEqual(inst.ABSD_SECTORS * 512, 2 * GIB)
        self.assertEqual(inst.ESP_SECTORS * 512, 256 << 20)
        self.assertEqual(str(uuid.UUID(inst.ABSD_TYPE)).upper(), "7AF614A7-2C5B-4EBA-B8F6-217AEC90357A")
        for reused in ("0FC63DAF-8483-4772-8E79-3D69D8477DE4", "516E7CB6-6ECF-11D6-8FF8-00022D09712B",
                       "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", inst.ESP_TYPE):
            self.assertNotEqual(inst.ABSD_TYPE, reused)

    def test_regions(self):
        self.assertEqual(inst.regions(SIZE), [(0, inst.ABSD_END * 512), (SIZE - 33 * 512, SIZE)])

    def test_token_parse(self):
        ident = {"path": "/x/y.img", "dev": 7, "ino": 99, "bytes": 10, "first_mib_sha256": "a" * 64,
                 "regions_sha256": "b" * 64}
        self.assertEqual(inst.parse_token(inst.token(ident)), ident)
        inst.check_confirmation(inst.token(ident), ident)
        tail = ",dev=7,ino=99,regions-sha256=" + "b" * 64
        for text in ("image:path=/x,bytes=1O,first-mib-sha256=" + "a" * 64 + tail,
                     "image:path=/x,bytes=1,first-mib-sha256=" + "A" * 64 + tail,
                     "image:path=/x,path=/y,bytes=1,first-mib-sha256=" + "a" * 64 + tail,
                     "image:path=/x,bytes=1,first-mib-sha256=" + "a" * 64):
            with self.assertRaises(inst.Refused):
                inst.parse_token(text)

    def test_kernel_line(self):
        line = inst.kernel_line(["durable=0", "net", "fsd", "served"], "65F1BA2F-CF09-4589-B7BD-D72BE33A2E87", "ser-1")
        self.assertEqual(line, "multiboot2 /BOOT/KERNEL.ELF durable=0 net fsd served "
                               "block-partition=65f1ba2f-cf09-4589-b7bd-d72be33a2e87 ahci-write=ser-1")


if __name__ == "__main__":
    if SKIP:
        print(f"test_install_disk: install cases skipped: {SKIP}", file=sys.stderr)
    unittest.main()
