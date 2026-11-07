#!/usr/bin/env python3
"""Host tests of operator-authorized writable recovery (coordination record #63;
scripts/storage_fence_resume.py, release.py recover, boot-operator.sh).

Every case runs on a real format-2 operator image built here: the v3
device layout, both superblocks, the metadata image, the guard, the resume
slot, the recovery ledger and facts, and a few files. The independent host
reader (scripts/absd_fs.py) reads it exactly as it reads a guest-written
one; nothing is mocked but statfs (R1c) and QEMU (a shell fake for the
launcher). ACCEPTANCE-v5 host cases: R1c, R1d, R2d, R4c, B3, B7, B8 (the
150 generated combinations plus the Hm-only supplement), M3, the
reconciliation sequence (superseded intent → consumption → repeated
status), W over synthetic consoles, the launcher, descriptor behavior
across exec and lock retention when the launcher dies. L1/L2 against a
real QEMU run only with ABSD_RESUME_REAL_QEMU=1 (a host-only lock
correspondence runs always).
"""

import contextlib
import hashlib
import importlib.util
import itertools
import os
import pathlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
from unittest.mock import patch

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import absd_fs  # noqa: E402
import storage_fence_resume as sfr  # noqa: E402
import storage_fence_state as guard  # noqa: E402

SECTOR = 512
DEVICE_SECTORS = sfr.DEVICE_SECTORS
FS_FIRST = DEVICE_SECTORS // 2
FS_SECTORS = DEVICE_SECTORS - FS_FIRST
BOOT0 = "0123456789abcdef0123456789abcdef"
BOOT1 = "fedcba9876543210fedcba9876543210"


# -- a real format-2 operator image -------------------------------------------

def layout_sector():
    half = DEVICE_SECTORS // 2
    slot = half // 4
    segment = slot // 4
    regions = [(1, 1, 1, 2), (2, 2, 16, slot - 16), (3, 3, half - 2 * slot, slot), (4, 3, half - slot, slot),
               (5, 4, slot, segment), (6, 4, slot + segment, segment), (7, 4, slot + 2 * segment, segment),
               (8, 4, slot + 3 * segment, segment), (9, 5, half, DEVICE_SECTORS - half)]
    sector = bytearray(SECTOR)
    sector[:8] = b"ABSDLAY1"
    struct.pack_into("<II", sector, 8, 3, len(regions))
    struct.pack_into("<Q", sector, 16, DEVICE_SECTORS)
    for index, region in enumerate(regions):
        struct.pack_into("<IIQQ", sector, 24 + index * 32, *region)
    struct.pack_into("<Q", sector, SECTOR - 8, guard.fnv1a(bytes(sector[:SECTOR - 8])))
    return bytes(sector)


def encode_image(fs_id, seq, records, next_serial, geo):
    raw = bytearray(b"ABSDFSI2")
    raw += struct.pack("<IIQQQIIQQ", 2, 0, fs_id, seq, next_serial, geo["data_blocks"], len(records),
                       geo["region_sectors"], geo["half_sectors"])
    for record in records:
        serial, parent, size, kind, name, blocks, mtime = record
        raw += struct.pack("<QQQBBHIQ", serial, parent, size, kind, 0, len(name), len(blocks), mtime)
        raw += name + b"".join(struct.pack("<I", b) for b in blocks)
    return bytes(raw)


def encode_superblock(slot, fs_id, seq, image, geo):
    sector = bytearray(SECTOR)
    sector[:8] = b"ABSDFSS2"
    struct.pack_into("<IIQQII", sector, 8, 2, slot, fs_id, seq, len(image), 0)
    struct.pack_into("<QQQQ", sector, 40, geo["region_sectors"], geo["half_sectors"], geo["data_first"],
                     geo["data_blocks"])
    sector[72:104] = hashlib.sha256(image).digest()
    sector[480:] = hashlib.sha256(bytes(sector[:480])).digest()
    return bytes(sector)


def build_image(path, files, *, fs_id=7, seq=11, mtimes=None):
    """Writes `files` ({path: bytes}, directories implied) as a committed
    format-2 filesystem in the v3 layout's region, both superblocks
    consecutive (seq-1 in the other slot), to a sparse 64 MiB file."""
    mtimes = mtimes or {}
    geo = absd_fs.geometry(FS_SECTORS)
    names = set()
    for name in files:
        parent = pathlib.PurePosixPath(name).parent
        while str(parent) != "/":
            names.add(str(parent))
            parent = parent.parent
    objects = ["/"] + sorted(names | set(files))
    serial = {name: index + 1 for index, name in enumerate(objects)}
    records = []
    block = 0
    data = []
    for name in objects:
        if name == "/":
            records.append((1, 0, 0, 2, b"", [], mtimes.get("/", 0)))
            continue
        parent = serial[str(pathlib.PurePosixPath(name).parent)]
        leaf = pathlib.PurePosixPath(name).name.encode()
        if name in files:
            content = files[name]
            blocks = list(range(block, block + -(-len(content) // 4096)))
            block += len(blocks)
            data.append((blocks, content))
            records.append((serial[name], parent, len(content), 1, leaf, blocks, mtimes.get(name, 0)))
        else:
            records.append((serial[name], parent, 0, 2, leaf, [], mtimes.get(name, 0)))
    path = pathlib.Path(path)
    with open(path, "wb") as handle:
        handle.truncate(sfr.IMAGE_BYTES)
        handle.seek(0)
        handle.write(layout_sector())
        base = FS_FIRST * SECTOR
        for n in (seq - 1, seq):
            image = encode_image(fs_id, n, records, len(objects) + 1, geo)
            half = (absd_fs.META_FIRST + (n % 2) * geo["half_sectors"]) * SECTOR
            handle.seek(base + half)
            handle.write(image)
            handle.seek(base + (n % 2) * SECTOR)
            handle.write(encode_superblock(n % 2, fs_id, n, image, geo))
        for blocks, content in data:
            for index, b in enumerate(blocks):
                handle.seek(base + (geo["data_first"] + b * 8) * SECTOR)
                handle.write(content[index * 4096:(index + 1) * 4096])
    path.chmod(0o600)
    return path


def ledger_bytes(seq, boot, streak):
    line = f"absd-recovery v1 seq={seq} boot={boot} streak={streak}".encode()
    line += b" fnv=%016x\n" % guard.fnv1a(line)
    return line.ljust(128, b"\0")


def fact(boot, action=None):
    return sfr.format_fact(boot, action)


def machine_files(previous="failed", *, guard_state="dirty", slot=guard.RESUME_NONE, with_slot=True,
                  ledger_seq=3, boot=BOOT0, state=True, with_guard=True, with_ledger=True):
    """The files of an operator image after an unclean stop with history
    `previous` (failed: the old boot's served-ready fact; not_ready: the
    old ledger with no matching fact; ended: every fact)."""
    files = {"/absd/selected": b"rel-a\n", "/releases/rel-a/release": b"release rel-a\n",
             "/releases/rel-a/bin/ls": b"ELF ls", "/etc/network.conf": b"address 10.0.2.15\n",
             "/etc/sshd.conf": b"port 22\n", "/ssh/authorized_keys": b"ssh-ed25519 AAAA key\n",
             "/ssh/host_ed25519_seed": bytes(range(32)), "/home/operator/notes": b"hello\n",
             "/home/operator/big": bytes(5000), guard.PATH: guard.encode(guard_state)}
    if not with_guard:
        del files[guard.PATH]
    if with_slot:
        files[guard.RESUME_PATH] = slot
    if state:
        files["/var/state/recovery.init"] = b""
        if with_ledger:
            files["/var/state/recovery"] = ledger_bytes(ledger_seq, boot, 1)
        zero = bytes(64)
        facts = {"ready": zero, "end": zero, "stopped": zero, "completed": zero}
        if previous == "failed":
            facts["ready"] = fact(boot)
        elif previous == "ended":
            facts = {"ready": fact(boot), "end": fact(boot, "halt"), "stopped": fact(boot), "completed": fact(boot)}
        for name, data in facts.items():
            files[f"/var/state/facts/served-{name}"] = data
    return files


def record_for(path, previous="failed", ident="a" * 32, when=1761100000):
    disk = sfr.read_disk(path)
    state = sfr.recovery_state(disk["files"], disk["guard"])
    return {"id": ident, "fs": disk["fs_id"], "seq": disk["seq"], "image": disk["image"],
            "ledger_seq": state["ledger"]["seq"], "ledger_boot": state["ledger"]["boot"], "previous": previous,
            "time": when}


def write_slot(path, data):
    disk = sfr.read_disk(path)
    with open(path, "r+b") as handle:
        handle.seek(disk["slot"]["offset"])
        handle.write(data)


def flip_byte(path, offset):
    with open(path, "r+b") as handle:
        handle.seek(offset)
        byte = handle.read(1)
        handle.seek(offset)
        handle.write(bytes([byte[0] ^ 1]))


def toml(path):
    return tomllib.loads(pathlib.Path(path).read_text())


def set_record_flag(path, leaf, flags):
    """Rewrites one record's flags byte (1 = read-only) in the selected
    metadata image and re-signs the superblock: the guest's view of a
    read-only object, made on the host."""
    region = absd_fs.fs_region(path, DEVICE_SECTORS)
    selected = absd_fs.select(region)
    geo = selected["geometry"]
    slot = selected["seq"] % 2
    length = absd_fs.superblock(region.read(slot), slot, geo)["image_len"]
    half = (region.first + absd_fs.META_FIRST + slot * geo["half_sectors"]) * SECTOR
    with open(path, "r+b") as handle:
        handle.seek(half)
        raw = bytearray(handle.read(length))
        offset = absd_fs.HEADER_BYTES
        for _ in range(len(selected["records"])):
            serial, parent, size, kind, old_flags, name_len, block_count = struct.unpack_from("<QQQBBHI", raw, offset)
            if bytes(raw[offset + 40:offset + 40 + name_len]) == leaf:
                raw[offset + 25] = flags
                break
            offset += 40 + name_len + 4 * block_count
        else:
            raise AssertionError(f"no record named {leaf!r}")
        handle.seek(half)
        handle.write(raw)
        superblock = (region.first + slot) * SECTOR
        handle.seek(superblock)
        sector = bytearray(handle.read(SECTOR))
        sector[72:104] = hashlib.sha256(bytes(raw)).digest()
        sector[480:] = hashlib.sha256(bytes(sector[:480])).digest()
        handle.seek(superblock)
        handle.write(sector)


class Lines:
    def __init__(self):
        self.lines = []

    def __call__(self, text):
        self.lines.append(text)

    @property
    def text(self):
        return "\n".join(self.lines)


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="resume-")
        self.addCleanup(self.temp.cleanup)
        self.work = pathlib.Path(self.temp.name)
        self.holders = []
        self.addCleanup(self.stop_holders)

    def stop_holders(self):
        for proc in self.holders:
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def target(self, name="out", previous="failed", **kw):
        out = self.work / name
        out.mkdir(parents=True, exist_ok=True)
        build_image(out / sfr.IMAGE, machine_files(previous, **kw), mtimes={"/home/operator/notes": 1761000000})
        (out / "TARGET").write_text("lab-1\n")
        (out / sfr.LEDGER).write_text("2026-10-20T00:00:00Z installed rel-a\n")
        sfr.ensure_lock(out)
        return out

    def act(self, out, **kw):
        lines = Lines()
        options = dict(attest_sole_instance=True, accept_committed_state=True, reason="test", log=lines)
        options.update(kw)
        intent = sfr.act(out, **options)
        return intent, lines

    def refused(self, func, want, *args, **kw):
        with self.assertRaises(sfr.Refused) as caught:
            func(*args, **kw)
        self.assertEqual(caught.exception.reason, want, str(caught.exception))
        return caught.exception

    def status(self, out, **kw):
        lines = Lines()
        decision = sfr.status(out, log=lines, **kw)
        return decision, lines.text

    def hold_lock(self, out):
        """A second process holding OUT/recovery/lock (R2d)."""
        proc = subprocess.Popen([sys.executable, "-I", "-c",
                                 "import fcntl, os, sys, time\nfd = os.open(sys.argv[1], os.O_RDWR)\n"
                                 "fcntl.flock(fd, fcntl.LOCK_EX)\nprint('held', flush=True)\ntime.sleep(300)\n",
                                 str(out / "recovery" / "lock")], stdout=subprocess.PIPE)
        self.assertEqual(proc.stdout.readline(), b"held\n")
        self.holders.append(proc)
        return proc

    def hold_ofd(self, image, kind="write", start=100, length=1):
        """A second process holding an OFD lock on the image as QEMU's
        file-posix does (a shared lock on a permission byte)."""
        proc = subprocess.Popen([sys.executable, "-I", "-c",
                                 "import fcntl, os, struct, sys, time\nfd = os.open(sys.argv[1], os.O_RDWR)\n"
                                 "kind = fcntl.F_WRLCK if sys.argv[2] == 'write' else fcntl.F_RDLCK\n"
                                 "fcntl.fcntl(fd, fcntl.F_OFD_SETLK, struct.pack('hhqqi', kind, 0, int(sys.argv[3]), int(sys.argv[4]), 0))\n"
                                 "print('held', flush=True)\ntime.sleep(300)\n",
                                 str(image), kind, str(start), str(length)], stdout=subprocess.PIPE)
        self.assertEqual(proc.stdout.readline(), b"held\n")
        self.holders.append(proc)
        return proc


# -- the record, the reader, the act -----------------------------------------

class ActAndReader(Base):
    def test_the_host_reader_reads_the_built_image_like_a_guest_one(self):
        out = self.target()
        disk = sfr.read_disk(out / sfr.IMAGE)
        self.assertEqual(disk["guard"], "dirty")
        self.assertEqual(disk["slot"]["parsed"], "none")
        self.assertEqual(disk["selected"], "rel-a")
        self.assertEqual(disk["files"]["/home/operator/big"], bytes(5000))
        state = sfr.recovery_state(disk["files"], disk["guard"])
        self.assertEqual((state["previous"], state["ledger"]["seq"], state["streak"]), ("failed", 3, 2))
        out = self.target("nr", "not_ready")
        disk = sfr.read_disk(out / sfr.IMAGE)
        self.assertEqual(sfr.recovery_state(disk["files"], disk["guard"])["previous"], "not_ready")
        out = self.target("ended", "ended", guard_state="clean")
        disk = sfr.read_disk(out / sfr.IMAGE)
        self.assertEqual(sfr.recovery_state(disk["files"], disk["guard"])["previous"], "ended")

    def test_recovery_state_refusals_match_the_guest_reasons(self):
        # R3c: (i) fnv altered -> corrupt; (ii) ledger absent -> lost;
        # (iii) init absent -> uninitialized_ledger; (iv) no state, dirty -> first_boot_interrupted.
        files = machine_files()
        bad = bytearray(files["/var/state/recovery"])
        bad[bad.index(b"fnv=") + 5] ^= 1
        corrupt = dict(files, **{"/var/state/recovery": bytes(bad)})
        self.assertEqual(self.refused(sfr.recovery_state, "recovery_state_refused", corrupt, "dirty").args[0],
                         "recovery_state_refused: corrupt")
        lost = {k: v for k, v in files.items() if k != "/var/state/recovery"}
        self.assertIn("lost", str(self.refused(sfr.recovery_state, "recovery_state_refused", lost, "dirty")))
        uninit = {k: v for k, v in files.items() if k != "/var/state/recovery.init"}
        self.assertIn("uninitialized_ledger", str(self.refused(sfr.recovery_state, "recovery_state_refused", uninit, "dirty")))
        none = {k: v for k, v in files.items() if not k.startswith("/var/state")}
        self.refused(sfr.recovery_state, "first_boot_interrupted", none, "dirty")
        self.assertEqual(sfr.recovery_state(none, "fresh")["previous"], "none")

    def test_host_reader_refuses_a_changed_image_digest_and_a_structural_fault(self):
        # R3a: a flipped byte in the selected metadata half.
        out = self.target()
        geo = absd_fs.geometry(FS_SECTORS)
        half = (FS_FIRST + absd_fs.META_FIRST + (11 % 2) * geo["half_sectors"]) * SECTOR
        flip_byte(out / sfr.IMAGE, half + 100)
        error = self.refused(sfr.read_disk, "host_reader_refused", out / sfr.IMAGE)
        self.assertIn("image digest", str(error))
        decision, text = self.status(out)
        self.assertEqual(decision.final.name, "slot-unreadable")
        self.assertIn("state=slot-unreadable", text)
        self.refused(self.act, "host_reader_refused", out)

    def test_the_act_writes_the_record_and_publishes_the_authorization(self):
        for previous in ("failed", "not_ready"):
            out = self.target(previous, previous)
            image = out / sfr.IMAGE
            before = sfr.read_disk(image)
            intent, lines = self.act(out)
            self.assertRegex(lines.text, rf"(?m)^RECOVERY AUTHORIZED id={intent['id']} target=lab-1 previous={previous} fs_seq=11 hm=[0-9a-f]{{64}}$")
            self.assertRegex(lines.text, rf"(?m)^previous={previous} boot={BOOT0} ledger_seq=3 streak=\d release=rel-a files=\d+ newest=/home/operator/notes@1761000000")
            self.assertIn("caveat: synced files exact", lines.text)
            disk = sfr.read_disk(image)
            record = disk["slot"]["parsed"]
            self.assertEqual(record["id"], intent["id"])
            self.assertEqual((record["fs"], record["seq"], record["image"], record["previous"]),
                             (before["fs_id"], before["seq"], before["image"], previous))
            self.assertEqual((record["ledger_seq"], record["ledger_boot"]), (3, BOOT0))
            self.assertEqual(disk["guard"], "dirty", "the act leaves the guard dirty")
            self.assertEqual(disk["seq"], before["seq"], "no metadata commit")
            active = toml(out / "recovery" / sfr.ACTIVE)["active"]
            self.assertEqual((active["state"], active["id"], active["previous"]), ("authorized", intent["id"], previous))
            self.assertEqual(active["f"], list(sfr.identity_of(image)))
            self.assertEqual(active["planned"], guard.encode_resume(record).hex())
            self.assertTrue((out / "recovery" / f"intent-{intent['id']}.toml").is_file())
            self.assertEqual(len(list((out / "receipts").glob(f"recover-{intent['id']}-*.toml"))), 1)
            self.assertRegex((out / sfr.LEDGER).read_text(), rf"(?m)^\S+ recovered rel-a id={intent['id']} previous={previous}$")
            decision, text = self.status(out)
            self.assertEqual((decision.final.row, decision.final.state), (8, "authorized"))
            self.assertIn("state=authorized last=none history=0", text)
            self.assertIn("action: boot (Terminal A)", text)
            # A second act while one is pending: recovery_pending.
            self.refused(self.act, "recovery_pending", out)
            self.assertEqual(sfr.precheck(out, log=Lines()), 0)

    def test_attestation_is_required_and_no_intent_is_written_without_it(self):
        # R4c
        out = self.target()
        for flags in ({}, {"attest_sole_instance": False}, {"accept_committed_state": False},
                      {"attest_sole_instance": False, "accept_committed_state": False}, {"reason": ""}):
            if flags:
                self.refused(self.act, "attestation_required", out, **flags)
                self.assertEqual(list((out / "recovery").iterdir()), [out / "recovery" / "lock"])
        self.assertEqual(sfr.read_disk(out / sfr.IMAGE)["slot"]["parsed"], "none")

    def test_the_act_refuses_a_clean_fresh_or_slot_less_image(self):
        self.refused(self.act, "not_unclean", self.target("clean", "ended", guard_state="clean"))
        self.refused(self.act, "not_unclean", self.target("fresh", state=False, guard_state="fresh"))
        self.refused(self.act, "first_boot_interrupted", self.target("fbi", state=False, guard_state="dirty"))
        out = self.target("slotless", with_slot=False)
        error = self.refused(self.act, "host_reader_refused", out)
        self.assertIn("resume_slot_missing", str(error))
        self.refused(self.act, "previous_not_recoverable", self.target("de", "ended", guard_state="dirty"))

    def test_status_action_follows_the_guard_for_state_none(self):
        # F4: state none prints `recover` only when `recover` would act.
        cases = {"clean": dict(previous="ended", guard_state="clean"),
                 "fresh": dict(state=False, guard_state="fresh"),
                 "dirty": dict(previous="failed", guard_state="dirty"),
                 "dirty-nr": dict(previous="not_ready", guard_state="dirty")}
        for name, kw in cases.items():
            out = self.target(name, **kw)
            decision, text = self.status(out)
            self.assertEqual(decision.final.name, "none", name)
            actions = [line for line in text.splitlines() if line.startswith("action: ")]
            self.assertEqual(len(actions), 1, text)
            if kw["guard_state"] == "dirty":
                self.assertEqual(actions[0], "action: recover", name)
                self.act(out)  # the advice holds: the act proceeds
            else:
                self.assertEqual(actions[0], f"action: guard {kw['guard_state']}: no recovery needed; boot", name)
                self.assertNotRegex(actions[0], r"\brecover\b", name)
                self.refused(self.act, "not_unclean", out)
        self.assertIn("previous=ended", self.status(self.work / "clean")[1])

    def test_identity_refusals(self):
        # R1c: symlink, hard link, non-local filesystem.
        out = self.target()
        image = out / sfr.IMAGE
        real = out / "real.img"
        image.rename(real)
        image.symlink_to(real)
        self.refused(self.act, "image_not_regular", out)
        decision, text = self.status(out)
        self.assertIn("state=identity-unreadable", text)
        self.assertEqual(sfr.precheck(out, log=Lines()), 7)
        image.unlink()
        real.rename(image)
        os.link(image, out / "link.img")
        self.refused(self.act, "image_linked", out)
        self.assertIn("state=identity-unreadable", self.status(out)[1])
        (out / "link.img").unlink()
        with patch.object(sfr, "fs_type", lambda fd: 0x6969):
            self.refused(self.act, "image_not_local", out)
        self.act(out)

    def test_self_holder_proceeds_and_an_extra_descriptor_is_named(self):
        # R1d
        out = self.target()
        with patch.dict(os.environ, {"ABSD_RECOVER_FAULT": "extra-descriptor"}):
            error = self.refused(self.act, "image_in_use", out)
        self.assertIn(f"pid {os.getpid()} (python", str(error))
        self.assertEqual(list((out / "recovery").iterdir()), [out / "recovery" / "lock"])
        self.act(out)

    def test_a_second_tool_is_refused_tool_busy_and_a_qemu_lock_image_locked(self):
        # R2d and the host-only L1/L2 correspondence.
        out = self.target()
        self.hold_lock(out)
        self.refused(self.act, "tool_busy", out)
        self.refused(lambda: sfr.revoke(out, reason="x", log=Lines()), "tool_busy")
        with self.assertRaises(sfr.Refused):
            with sfr.mutation(out, out / sfr.IMAGE):
                pass
        self.stop_holders()
        self.holders.clear()
        for kind, byte in (("read", 100), ("read", 201), ("write", 150)):
            holder = self.hold_ofd(out / sfr.IMAGE, kind, byte)
            error = self.refused(self.act, "image_locked", out)
            # R2: the OFD refusal comes first and names the holder the
            # /proc scan sees (the holding process, by pid).
            self.assertIn(f"holders: pid {holder.pid} (", str(error))
            error = self.refused(sfr.probe_exclusion, "image_locked", out / sfr.IMAGE)
            self.assertIn(f"pid {holder.pid} (", str(error))
            holder.kill()
            holder.wait()
        self.holders.clear()
        # The other direction: while the tool holds its lock, a QEMU-style
        # shared lock on a permission byte fails.
        with sfr.exclusion(out / sfr.IMAGE) as (fd, f):
            probe = subprocess.run([sys.executable, "-I", "-c",
                                    "import fcntl, os, struct, sys\nfd = os.open(sys.argv[1], os.O_RDWR)\n"
                                    "try:\n    fcntl.fcntl(fd, fcntl.F_OFD_SETLK, struct.pack('hhqqi', fcntl.F_RDLCK, 0, 100, 1, 0))\n"
                                    "except OSError as e:\n    print(e.errno)\nelse:\n    print('taken')\n",
                                    str(out / sfr.IMAGE)], capture_output=True, text=True)
            self.assertIn(probe.stdout.strip(), ("11", "13"), probe.stdout)
        self.act(out)

    @unittest.skipUnless(os.environ.get("ABSD_RESUME_REAL_QEMU") == "1", "L1/L2 need a real QEMU (ABSD_RESUME_REAL_QEMU=1)")
    def test_real_qemu_lock_correspondence(self):
        qemu = shutil.which(os.environ.get("ABSD_QEMU", "qemu-system-x86_64"))
        if qemu is None:
            self.skipTest("no qemu-system-x86_64 on this host")
        dummy = self.work / "dummy.img"
        with open(dummy, "wb") as handle:
            handle.truncate(sfr.IMAGE_BYTES)
        # L1: a paused QEMU holds the file; the tool's exclusive lock fails.
        errors = self.work / "qemu-l1.err"
        with open(errors, "wb") as sink:
            proc = subprocess.Popen([qemu, "-S", "-display", "none", "-monitor", "none", "-drive",
                                     f"file={dummy},format=raw,if=ide"], stdout=subprocess.DEVNULL, stderr=sink)
        self.holders.append(proc)
        time.sleep(1.5)
        self.assertIsNone(proc.poll(), errors.read_text(errors="replace"))
        error = self.refused(sfr.probe_exclusion, "image_locked", dummy)
        self.assertRegex(str(error), r"E(AGAIN|ACCES|WOULDBLOCK)")
        self.assertIn(f"holders: pid {proc.pid} (qemu-system-", str(error))
        print(f"L1 tool refusal: {error}", flush=True)
        proc.kill()
        proc.wait(timeout=20)
        print(f"L1 qemu stderr after exit: {errors.read_text(errors='replace')[-300:]!r}", flush=True)
        sfr.probe_exclusion(dummy)
        # L2: the tool holds its lock; the same QEMU exits nonzero; with
        # locking=off it starts (the disclosed limit, recorded, never a pass).
        fd, _ = sfr.open_image(dummy)
        try:
            sfr.ofd_lock(fd)
            ran = subprocess.run([qemu, "-S", "-display", "none", "-monitor", "none", "-drive",
                                  f"file={dummy},format=raw,if=ide", "-no-reboot"], capture_output=True, text=True,
                                 timeout=20)
            self.assertNotEqual(ran.returncode, 0)
            self.assertIn("lock", ran.stderr)
            print(f"L2 qemu stderr: {ran.stderr.strip()[-300:]!r}", flush=True)
            with open(self.work / "qemu-l2-off.err", "wb") as sink:
                off = subprocess.Popen([qemu, "-S", "-display", "none", "-monitor", "none", "-drive",
                                        f"file={dummy},format=raw,if=ide,file.locking=off"], stdout=subprocess.DEVNULL,
                                       stderr=sink)
            self.holders.append(off)
            time.sleep(1.5)
            started = off.poll() is None
            off.kill()
            off.wait(timeout=20)
            print(f"RESUME LIMIT RECORDED case=l2-locking-off started={started}", flush=True)
            self.assertTrue(started, "locking=off is the disclosed limit: QEMU opens the locked image")
        finally:
            os.close(fd)


# -- the mutators' boundary, backup, build -----------------------------------

class Mutators(Base):
    def test_mutation_refuses_recovery_pending_and_an_intent_alone_does_not_block(self):
        out = self.target()
        image = out / sfr.IMAGE
        with sfr.mutation(out, image):
            pass
        with patch.dict(os.environ, {"ABSD_RECOVER_FAULT": "after-intent"}):
            with self.assertRaises(sfr.Fault):
                self.act(out)
        self.assertEqual(self.status(out)[0].final.name, "intent-only")
        with sfr.mutation(out, image):
            pass  # M1: an unsuperseded intent does not block a mutator
        intent, _ = self.act(out)
        error = self.refused(sfr.mutation(out, image).__enter__, "recovery_pending")
        self.assertIn(intent["id"], str(error))
        # The record alone (records gone) still refuses; a replacing mutator too.
        shutil.rmtree(out / "recovery")
        self.refused(sfr.mutation(out, image).__enter__, "recovery_pending")
        self.refused(sfr.mutation(out, image, replacing=True).__enter__, "recovery_pending")
        # A corrupt slot refuses by name; a missing image is not a slot.
        write_slot(image, (here.parent / "fixtures/storage-fence/resume-v1-torn-40.bin").read_bytes())
        self.refused(sfr.mutation(out, image).__enter__, "resume_slot_corrupt")
        with sfr.mutation(out, out / "absent.img"):
            pass

    def test_pending_id_labels_a_backup_taken_after_the_act(self):
        out = self.target()
        self.assertEqual(sfr.pending_id(out, out / sfr.IMAGE), "none")
        intent, _ = self.act(out)
        self.assertEqual(sfr.pending_id(out, out / sfr.IMAGE), intent["id"])

    def test_build_refuses_an_operator_directory_by_its_layout_markers(self):
        # M3 (host): (a)-(e) refuse, (f) fresh and (g) a release directory do not;
        # a file named `ledger` is not a marker.
        spec = importlib.util.spec_from_file_location("release_for_resume", here / "release.py")
        rel = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(rel)
        for marker in (rel.IMAGE, rel.LEDGER, rel.TARGET, "receipts", "recovery"):
            directory = self.work / f"m-{marker}"
            directory.mkdir()
            if marker in ("receipts", "recovery"):
                (directory / marker).mkdir()
            else:
                (directory / marker).write_bytes(b"x")
            with self.assertRaises(rel.Failed) as caught:
                rel.refuse_target_directory(directory)
            self.assertIn("target_directory", str(caught.exception))
            self.assertTrue((directory / marker).exists())
        authorized = self.target()
        self.act(authorized)
        with self.assertRaises(rel.Failed):
            rel.refuse_target_directory(authorized)
        fresh = self.work / "fresh"
        rel.refuse_target_directory(fresh)
        release_dir = self.work / "release-dir"
        (release_dir / "tree").mkdir(parents=True)
        (release_dir / "release").write_text("release rel-a\n")
        (release_dir / rel.ISO).write_bytes(b"iso")
        rel.refuse_target_directory(release_dir)
        lookalike = self.work / "ledger-only"
        lookalike.mkdir()
        (lookalike / "ledger").write_text("not RELEASES\n")
        rel.refuse_target_directory(lookalike)


# -- revoke, status, reconciliation, B3, B7 -----------------------------------

class Records(Base):
    def test_revoke_rewrites_none_and_archives_the_authorization(self):
        out = self.target()
        intent, _ = self.act(out)
        self.refused(lambda: sfr.revoke(out, reason="", log=Lines()), "attestation_required")
        lines = Lines()
        sfr.revoke(out, reason="changed my mind", log=lines)
        self.assertIn(f"RECOVERY REVOKED id={intent['id']} disposition=revoked slot=none", lines.text)
        self.assertEqual(sfr.read_disk(out / sfr.IMAGE)["slot"]["parsed"], "none")
        self.assertFalse((out / "recovery" / sfr.ACTIVE).exists())
        archive = toml(out / "recovery" / f"revoked-{intent['id']}.toml")["archive"]
        self.assertEqual((archive["kind"], archive["disposition"], archive["reason_revoked"]),
                         ("revoked", "revoked", "changed my mind"))
        decision, text = self.status(out)
        self.assertEqual(decision.final.name, "none")
        self.assertIn(f"state=none last=revoked {intent['id']} ", text)
        self.assertIn("history=1", text)
        self.refused(lambda: sfr.revoke(out, reason="again", log=Lines()), "nothing_to_revoke")
        # A new act after the revoke: a new id.
        second, _ = self.act(out)
        self.assertNotEqual(second["id"], intent["id"])

    def test_every_act_interruption_lands_in_its_row(self):
        # B3: the ten fault hooks.
        expected = {"after-intent": ("intent-only", None), "short-write:8": ("intent-only", None),
                    "short-write:40": ("corrupt-slot", None), "short-write:120": ("corrupt-slot", None),
                    "short-write:200": ("corrupt-slot", None), "short-write:400": ("authorized-unpublished", "authorized"),
                    "after-pwrite": ("authorized-unpublished", "authorized"),
                    "fsync-fail": ("authorized-unpublished", "authorized"),
                    "after-slot": ("authorized-unpublished", "authorized"), "after-active": ("authorized", "authorized")}
        for hook, (row, finalized) in expected.items():
            with self.subTest(hook=hook):
                out = self.target(hook.replace(":", "-"))
                image = out / sfr.IMAGE
                with patch.dict(os.environ, {"ABSD_RECOVER_FAULT": hook}):
                    if hook == "fsync-fail":
                        self.refused(self.act, "authorization_unverified", out)
                    else:
                        with self.assertRaises(sfr.Fault):
                            self.act(out)
                decision, text = self.status(out, reconcile=False)
                self.assertEqual(decision.chain[0].name, row, text)
                if hook == "short-write:8":
                    self.assertEqual(sfr.read_disk(image)["slot"]["parsed"], "none")
                decision, text = self.status(out)
                if finalized:
                    self.assertEqual(decision.final.state, finalized, text)
                    active = toml(out / "recovery" / sfr.ACTIVE)["active"]
                    self.assertEqual(active["state"], "authorized")
                    self.assertTrue(list((out / "receipts").glob(f"recover-{active['id']}-*.toml")))
                    self.assertIn("recovered rel-a id=" + active["id"], (out / sfr.LEDGER).read_text())
                    if row == "authorized-unpublished":
                        self.assertIn("finalized id=", text)
                    self.assertEqual(sfr.precheck(out, log=Lines()), 0)
                elif row == "corrupt-slot":
                    self.assertEqual(decision.final.name, "corrupt-slot")
                    self.assertEqual(sfr.precheck(out, log=Lines()), 7)
                    self.refused(self.act, "resume_slot_corrupt", out)
                    lines = Lines()
                    sfr.revoke(out, reason="torn", log=lines)
                    self.assertIn("disposition=revoked_corrupt", lines.text)
                    self.assertEqual(sfr.read_disk(image)["slot"]["parsed"], "none")
                    self.act(out)
                else:
                    self.assertEqual(decision.final.name, "intent-only")
                    self.assertEqual(sfr.precheck(out, log=Lines()), 0)
                    intent, _ = self.act(out)
                    archives = list((out / "recovery").glob("superseded-*.toml"))
                    self.assertEqual(len(archives), 1)
                    self.assertEqual(toml(archives[0])["archive"]["superseded_by"], intent["id"])

    def test_finalization_refuses_a_changed_image_as_record_unverified(self):
        out = self.target()
        image = out / sfr.IMAGE
        with patch.dict(os.environ, {"ABSD_RECOVER_FAULT": "after-slot"}):
            with self.assertRaises(sfr.Fault):
                self.act(out)
        disk = sfr.read_disk(image)
        flip_byte(image, (FS_FIRST + absd_fs.geometry(FS_SECTORS)["data_first"] + 2 * 8) * SECTOR + 5)
        decision, text = self.status(out)
        self.assertEqual(decision.chain[0].name, "mismatch")
        self.assertIn("recovery_image_changed (hm)", text)
        self.assertFalse((out / "recovery" / sfr.ACTIVE).exists())
        self.assertEqual(sfr.precheck(out, log=Lines()), 7)
        self.assertEqual(sfr.read_disk(image)["slot"]["parsed"]["id"], disk["slot"]["parsed"]["id"])

    def test_corrupt_missing_and_half_retired_host_records(self):
        # B7
        torn = (here.parent / "fixtures/storage-fence/resume-v1-torn-40.bin").read_bytes()
        # slot R with intent and active deleted -> record-unreceipted.
        out = self.target("a")
        intent, _ = self.act(out)
        for name in (sfr.ACTIVE, f"intent-{intent['id']}.toml"):
            (out / "recovery" / name).unlink()
        decision, text = self.status(out)
        self.assertEqual(decision.final.name, "record-unreceipted")
        self.assertEqual(sfr.precheck(out, log=Lines()), 7)
        self.refused(self.act, "record_unreceipted", out)
        sfr.revoke(out, reason="unreceipted", log=Lines())
        self.act(out)
        # active unparsable with slot none -> quarantined, continues to row 14.
        out = self.target("b")
        (out / "recovery" / sfr.ACTIVE).write_text("not toml [")
        decision, text = self.status(out)
        self.assertEqual([step.name for step in decision.chain], ["corrupt-receipt", "none"])
        self.assertTrue(list((out / "recovery").glob("corrupt-*active.toml")))
        self.assertFalse((out / "recovery" / sfr.ACTIVE).exists())
        self.assertIn("state=none", self.status(out)[1])
        # active unparsable with slot R -> corrupt_receipt refusal.
        out = self.target("c")
        intent, _ = self.act(out)
        (out / "recovery" / sfr.ACTIVE).write_text("[active]\nid = 7\n")
        decision, text = self.status(out)
        self.assertEqual(decision.final.name, "corrupt-receipt")
        self.assertEqual(sfr.precheck(out, log=Lines()), 7)
        self.refused(self.act, "corrupt_receipt", out)
        sfr.revoke(out, reason="corrupt receipt", log=Lines())
        self.assertEqual(sfr.read_disk(out / sfr.IMAGE)["slot"]["parsed"], "none")
        self.act(out)
        # retirement interrupted after the archive (active still present) -> row 4, then none last=consumed.
        out = self.target("d")
        intent, _ = self.act(out)
        write_slot(out / sfr.IMAGE, guard.RESUME_NONE)
        with patch.dict(os.environ, {"ABSD_RECOVER_FAULT": "retire-after-archive"}):
            with self.assertRaises(sfr.Fault):
                self.status(out)
        self.assertTrue((out / "recovery" / f"consumed-{intent['id']}.toml").is_file())
        self.assertTrue((out / "recovery" / sfr.ACTIVE).is_file())
        # Deferred (the lock held by a launcher): the observed row is reported, not the prediction.
        self.hold_lock(out)
        decision, text = self.status(out)
        self.assertIn("reconciliation deferred: tool_busy", text)
        self.assertIn("state=retirement-incomplete ", text)
        self.assertIn("pending=none reconciliation=deferred", text)
        self.assertTrue((out / "recovery" / sfr.ACTIVE).is_file(), "deferred: nothing happened")
        self.stop_holders()
        self.holders.clear()
        decision, text = self.status(out)
        self.assertEqual([step.name for step in decision.chain], ["retirement-incomplete", "none"])
        self.assertIn(f"state=none last=consumed {intent['id']}", text)
        self.assertIn("observed=retirement-incomplete reconciliation=done", text)
        self.assertFalse((out / "recovery" / sfr.ACTIVE).exists())
        self.assertTrue(sfr.has_receipt(out, "consumed", intent["id"]))
        self.assertTrue(sfr.has_ledger_line(out, "consumed", intent["id"]))
        # retirement interrupted with only the archive's temp file -> row 10 again.
        out = self.target("e")
        intent, _ = self.act(out)
        write_slot(out / sfr.IMAGE, guard.RESUME_NONE)
        with patch.dict(os.environ, {"ABSD_RECOVER_FAULT": "retire-temp-only"}):
            with self.assertRaises(sfr.Fault):
                sfr.precheck(out, log=Lines())
        self.assertTrue((out / "recovery" / f"consumed-{intent['id']}.toml.tmp").is_file())
        decision, text = self.status(out)
        self.assertEqual(decision.chain[0].name, "consumed-pending")
        self.assertEqual(decision.final.name, "none")
        self.assertIn(f"state=none last=consumed {intent['id']}", text)
        # archive present and intent present, no active -> none last=consumed, never intent-only.
        out = self.target("f")
        intent, _ = self.act(out)
        write_slot(out / sfr.IMAGE, guard.RESUME_NONE)
        self.status(out)
        self.assertTrue((out / "recovery" / f"intent-{intent['id']}.toml").is_file())
        for _ in range(3):
            decision, text = self.status(out)
            self.assertEqual(decision.final.name, "none")
            self.assertIn(f"state=none last=consumed {intent['id']}", text)
            self.assertEqual(sfr.precheck(out, log=Lines()), 0)
        # corrupt slot plus unparsable active -> corrupt-slot (row 2 terminates before row 3).
        out = self.target("g")
        write_slot(out / sfr.IMAGE, torn)
        (out / "recovery" / sfr.ACTIVE).write_text("garbage")
        decision, text = self.status(out)
        self.assertEqual(decision.chain[0].name, "corrupt-slot")
        self.assertEqual(len(decision.chain), 1)
        self.assertTrue((out / "recovery" / sfr.ACTIVE).is_file(), "row 2 consulted no record")
        self.assertEqual(sfr.precheck(out, log=Lines()), 7)

    def test_superseded_intent_then_consumption_then_repeated_status(self):
        # Codex v5 required change 3: an interrupted intent, another recovery
        # superseding it, consumption, repeated status: the abandoned intent
        # never resurfaces.
        out = self.target()
        with patch.dict(os.environ, {"ABSD_RECOVER_FAULT": "after-intent"}):
            with self.assertRaises(sfr.Fault):
                self.act(out)
        first = toml(next((out / "recovery").glob("intent-*.toml")))["intent"]["id"]
        intent, _ = self.act(out)
        self.assertTrue((out / "recovery" / f"superseded-{first}.toml").is_file())
        write_slot(out / sfr.IMAGE, guard.RESUME_NONE)  # the guest consumed it
        for index in range(4):
            decision, text = self.status(out)
            self.assertEqual(decision.final.name, "none", text)
            self.assertIn(f"state=none last=consumed {intent['id']}", text)
            self.assertIn("history=2", text)
            self.assertEqual(sfr.precheck(out, log=Lines()), 0)
        self.assertTrue((out / "recovery" / f"intent-{first}.toml").is_file(), "intents are never deleted")

    def test_status_reclassifies_under_the_lock_before_any_side_effect(self):
        # The reviewer's sequence: status observes consumed A; another
        # command retires A and publishes B before status takes the lock;
        # status must not retire its stale A payload over B.
        out = self.target()
        first, _ = self.act(out)
        write_slot(out / sfr.IMAGE, guard.RESUME_NONE)  # A consumed by a guest
        second = {}

        def concurrent():
            # Another recovery command: retires A (row 10) and publishes B.
            sfr.precheck(out, log=Lines())
            second["intent"], _ = self.act(out)
        decision, text = self.status(out, before_lock=concurrent)
        self.assertEqual(decision.chain[0].name, "consumed-pending", "status observed A consumed")
        active = toml(out / "recovery" / sfr.ACTIVE)["active"]
        self.assertEqual(active["id"], second["intent"]["id"], "B's active record survived")
        self.assertTrue((out / "recovery" / f"consumed-{first['id']}.toml").is_file())
        self.assertIn("state=authorized", text)
        self.assertIn("observed=consumed-pending", text)
        # The same race against a quarantine: the unparsable file became valid meanwhile.
        out = self.target("q")
        (out / "recovery" / sfr.ACTIVE).write_text("[active\n")
        valid = {}

        def repair():
            (out / "recovery" / sfr.ACTIVE).unlink()
            valid["intent"], _ = self.act(out)
        decision, text = self.status(out, before_lock=repair)
        self.assertEqual(decision.chain[0].name, "corrupt-receipt")
        self.assertTrue((out / "recovery" / sfr.ACTIVE).is_file(), "the valid active was not quarantined")
        self.assertFalse(list((out / "recovery").glob("corrupt-*")))
        self.assertIn("state=authorized", text)

    def test_failed_finalization_never_launches_on_a_predicted_row(self):
        # The round-2 reviewer's control: F, Hm and slot all match the
        # intent, and finalization's durability check raises EIO. Precheck
        # must refuse with record_unverified, publish nothing; status must
        # report the unresolved row, never reconciliation=done.
        out = self.target()
        with patch.dict(os.environ, {"ABSD_RECOVER_FAULT": "after-slot"}):
            with self.assertRaises(sfr.Fault):
                self.act(out)
        published = []
        real_publish = sfr.publish

        def counting(path, text):
            published.append(pathlib.Path(path).name)
            return real_publish(path, text)

        def eio(fd):
            raise OSError(5, "Input/output error")
        with patch.object(sfr, "fsync_image", eio), patch.object(sfr, "publish", counting):
            lines = Lines()
            code = sfr.precheck(out, log=lines)
            self.assertEqual(code, 7, lines.text)
            self.assertIn("refusal=record_unverified", lines.text)
            self.assertNotIn("authorization id=", lines.text)
            self.assertIn("state=authorized-unpublished", lines.text)
            self.assertIn("reconciliation=failed reason=record_unverified", lines.text)
            decision, text = self.status(out)
            self.assertIn("state=authorized-unpublished", text)
            self.assertIn("reconciliation=failed reason=record_unverified", text)
            self.assertNotIn("reconciliation=done", text)
            self.assertNotIn("state=authorized ", text)
            self.refused(self.act, "record_unverified", out)
        self.assertEqual(published, [], "nothing was published")
        self.assertFalse((out / "recovery" / sfr.ACTIVE).exists())
        # Once the device behaves, the same state finalizes normally.
        self.assertEqual(sfr.precheck(out, log=Lines()), 0)
        self.assertTrue((out / "recovery" / sfr.ACTIVE).exists())

    def test_every_derived_event_is_reconciled_from_durable_evidence(self):
        # Interruption between every publication step of the act and of
        # retirement; each owed receipt and ledger line is written later from
        # intent/active/archive evidence, after active removal too.
        for hook in ("after-active", "after-receipt"):
            out = self.target(hook)
            with patch.dict(os.environ, {"ABSD_RECOVER_FAULT": hook}):
                with self.assertRaises(sfr.Fault):
                    self.act(out)
            ident = toml(out / "recovery" / sfr.ACTIVE)["active"]["id"]
            if hook == "after-receipt":
                self.assertTrue(sfr.has_receipt(out, "recover", ident))
                self.assertFalse(sfr.has_ledger_line(out, "recovered", ident))
            decision, text = self.status(out)
            self.assertEqual(decision.final.state, "authorized")
            self.assertTrue(sfr.has_receipt(out, "recover", ident), hook)
            self.assertTrue(sfr.has_ledger_line(out, "recovered", ident), hook)
            self.assertEqual(len(list((out / "receipts").glob(f"recover-{ident}-*.toml"))), 1, "written once")
            self.status(out)
            self.assertEqual((out / sfr.LEDGER).read_text().count(f"recovered rel-a id={ident}"), 1)
        for hook in ("retire-temp-only", "retire-after-archive", "retire-after-remove", "retire-after-receipt"):
            out = self.target(hook)
            intent, _ = self.act(out)
            ident = intent["id"]
            write_slot(out / sfr.IMAGE, guard.RESUME_NONE)
            with patch.dict(os.environ, {"ABSD_RECOVER_FAULT": hook}):
                with self.assertRaises(sfr.Fault):
                    sfr.precheck(out, log=Lines())
            if hook == "retire-after-remove":
                self.assertFalse((out / "recovery" / sfr.ACTIVE).exists())
                self.assertFalse(sfr.has_receipt(out, "consumed", ident), "row 14 with the receipt still owed")
            decision, text = self.status(out)
            self.assertEqual(decision.final.name, "none", hook)
            self.assertIn(f"last=consumed {ident}", text)
            self.assertFalse((out / "recovery" / sfr.ACTIVE).exists())
            for kind, action in (("recover", "recovered"), ("consumed", "consumed")):
                self.assertTrue(sfr.has_receipt(out, kind, ident), f"{hook}: {kind} receipt")
                self.assertTrue(sfr.has_ledger_line(out, action, ident), f"{hook}: {action} line")
            self.assertEqual(len(list((out / "receipts").glob(f"consumed-{ident}-*.toml"))), 1)
            self.assertEqual(sfr.precheck(out, log=Lines()), 0)
        # A published authorization interrupted before its receipt, then
        # revoked: the revoked archive records it was published and owes
        # the authorization receipt and `recovered` line as well.
        out = self.target("rvp")
        with patch.dict(os.environ, {"ABSD_RECOVER_FAULT": "after-active"}):
            with self.assertRaises(sfr.Fault):
                self.act(out)
        ident = toml(out / "recovery" / sfr.ACTIVE)["active"]["id"]
        with patch.object(sfr, "reconcile_derived", lambda *a, **k: []):
            sfr.revoke(out, reason="before receipt", log=Lines())
        archive = toml(out / "recovery" / f"revoked-{ident}.toml")["archive"]
        self.assertIs(archive["published"], True)
        self.assertFalse(sfr.has_receipt(out, "recover", ident))
        self.assertTrue(sfr.derived_missing(out, sfr.read_records(out)))
        self.status(out)
        self.assertTrue(sfr.has_receipt(out, "recover", ident))
        self.assertTrue(sfr.has_ledger_line(out, "recovered", ident))
        self.assertTrue(sfr.has_receipt(out, "revoke", ident))
        self.assertFalse(sfr.derived_missing(out, sfr.read_records(out)))
        # An intent revoked before publication stays distinguishable: no
        # authorization events are owed or written.
        out = self.target("rvi")
        with patch.dict(os.environ, {"ABSD_RECOVER_FAULT": "after-slot"}):
            with self.assertRaises(sfr.Fault):
                self.act(out)
        ident = toml(next((out / "recovery").glob("intent-*.toml")))["intent"]["id"]
        sfr.revoke(out, reason="unpublished", log=Lines())
        archive = toml(out / "recovery" / f"revoked-{ident}.toml")["archive"]
        self.assertIs(archive["published"], False)
        self.status(out)
        self.assertFalse(sfr.has_receipt(out, "recover", ident))
        self.assertFalse(sfr.has_ledger_line(out, "recovered", ident))
        self.assertTrue(sfr.has_receipt(out, "revoke", ident))
        # A revoked archive owes its receipt and line too.
        out = self.target("rv")
        intent, _ = self.act(out)
        sfr.revoke(out, reason="x", log=Lines())
        for path in (out / "receipts").glob(f"revoke-{intent['id']}-*.toml"):
            path.unlink()
        (out / sfr.LEDGER).write_text("")
        self.status(out)
        self.assertTrue(sfr.has_receipt(out, "revoke", intent["id"]))
        self.assertTrue(sfr.has_ledger_line(out, "revoked", intent["id"]))

    def test_malformed_host_records_take_the_corrupt_receipt_row(self):
        # Finding 5: the full schema; the reviewer's two controls and more.
        out = self.target()
        intent, _ = self.act(out)
        ident = intent["id"]
        active_path = out / "recovery" / sfr.ACTIVE
        good = toml(active_path)["active"]
        self.assertTrue(sfr.valid_authorization(good))
        bad_records = {
            "no-attestations": {k: v for k, v in good.items() if not k.startswith(("attest_", "accept_"))},
            "attestation-false": dict(good, attest_sole_instance=False),
            "f-int": dict(good, f=123),
            "f-strings": dict(good, f=[str(v) for v in good["f"]]),
            "empty-reason": dict(good, reason=" "),
            "bad-hm": dict(good, hm="zz" * 32),
            "planned-other-id": dict(good, planned=guard.encode_resume(dict(record_for(out / sfr.IMAGE), id="b" * 32)).hex()),
            "planned-garbage": dict(good, planned="00" * 512),
            "previous-ended": dict(good, previous="ended"),
            "state-unknown": dict(good, state="pending"),
            "launched-without-facts": dict(good, state="launched"),
            "fs_seq-negative": dict(good, fs_seq=-1),
        }
        for name, record in bad_records.items():
            with self.subTest(record=name):
                if name not in ("state-unknown", "launched-without-facts"):
                    self.assertFalse(sfr.valid_authorization(record), name)
                sfr.publish(active_path, sfr.toml_dump({"active": record}))
                self.assertIsNone(sfr.parse_record_file(active_path, "active"), name)
                decision, text = self.status(out, reconcile=False)
                self.assertEqual(decision.chain[0].name, "corrupt-receipt", name)
                self.assertEqual(sfr.precheck(out, log=Lines()), 7, name)  # slot R: corrupt_receipt refusal
        sfr.publish(active_path, sfr.toml_dump({"active": good}))
        self.assertEqual(self.status(out)[0].final.state, "authorized")
        # An intent missing its attestations never finalizes (row 6 needs a valid intent).
        out = self.target("i")
        with patch.dict(os.environ, {"ABSD_RECOVER_FAULT": "after-slot"}):
            with self.assertRaises(sfr.Fault):
                self.act(out)
        path = next((out / "recovery").glob("intent-*.toml"))
        fields = toml(path)["intent"]
        sfr.publish(path, sfr.toml_dump({"intent": {k: v for k, v in fields.items() if k != "attest_sole_instance"}}))
        decision, text = self.status(out)
        self.assertEqual(decision.chain[0].name, "corrupt-receipt")
        self.assertFalse((out / "recovery" / sfr.ACTIVE).exists())
        self.assertEqual(sfr.precheck(out, log=Lines()), 7)

    def test_a_readonly_guard_is_corrupt_on_the_host_as_in_the_guest(self):
        out = self.target()
        image = out / sfr.IMAGE
        # The guard record's read-only flag: the guest's write_guard::read refuses it.
        set_record_flag(image, b"recovery.guard", 1)
        disk = sfr.read_disk(image)
        self.assertTrue(disk["records"][guard.PATH]["readonly"])
        self.assertIsNone(disk["guard"])
        self.refused(self.act, "guard_corrupt", out)

    def test_real_syscall_failures_are_named_refusals(self):
        out = self.target()
        image = out / sfr.IMAGE
        with patch.object(os, "pwrite", side_effect=OSError(5, "Input/output error")):
            error = self.refused(self.act, "slot_write_failed", out)
        self.assertIn("Input/output error", str(error))
        self.assertEqual(self.status(out)[0].final.name, "intent-only")
        self.assertEqual(sfr.read_disk(image)["slot"]["parsed"], "none")
        # fsync fails after the write landed in the page cache: the hook
        # raises the OSError the real path handles.
        with patch.dict(os.environ, {"ABSD_RECOVER_FAULT": "fsync-fail"}):
            error = self.refused(self.act, "authorization_unverified", out)
        self.assertIn("Input/output error", str(error))
        decision, text = self.status(out)
        self.assertEqual(decision.final.state, "authorized")  # finalized from the readback
        # A real fsync OSError on revoke.
        with patch.object(os, "fsync", side_effect=OSError(5, "Input/output error")):
            self.refused(lambda: sfr.revoke(out, reason="x", log=Lines()), "revoke_unverified")
        sfr.revoke(out, reason="x", log=Lines())
        # finalize's durability check failing.
        with patch.dict(os.environ, {"ABSD_RECOVER_FAULT": "after-slot"}):
            with self.assertRaises(sfr.Fault):
                self.act(out)
        with patch.object(os, "fsync", side_effect=OSError(5, "Input/output error")):
            decision, text = self.status(out)
        self.assertIn("record_unverified", text)
        self.assertFalse((out / "recovery" / sfr.ACTIVE).exists())

    def test_replaced_pathname_after_authorization_is_row_11_and_revoke_names_it(self):
        # B5 (b1) host analog: the pathname replaced by a pre-authorization copy.
        out = self.target()
        image = out / sfr.IMAGE
        copy = self.work / "copy.img"
        shutil.copyfile(image, copy)
        intent, _ = self.act(out)
        copy.replace(image)
        decision, text = self.status(out)
        self.assertEqual(decision.final.name, "replaced")
        self.assertIn("recovery_image_replaced F=", text)
        self.assertEqual(sfr.precheck(out, log=Lines()), 7)
        self.refused(self.act, "recovery_image_replaced", out)
        lines = Lines()
        sfr.revoke(out, reason="replaced", log=lines)
        self.assertEqual(toml(out / "recovery" / f"revoked-{intent['id']}.toml")["archive"]["disposition"], "image_replaced")
        self.assertEqual(sfr.precheck(out, log=Lines()), 0)
        self.assertEqual(self.status(out)[0].final.name, "none")
        # B5 (c): a copy with identical bytes under a new inode: row 9 (F).
        out = self.target("c")
        image = out / sfr.IMAGE
        intent, _ = self.act(out)
        shutil.copyfile(image, self.work / "same.img")
        (self.work / "same.img").replace(image)
        decision, text = self.status(out)
        self.assertEqual((decision.final.row, decision.final.name), (9, "mismatch"))
        self.assertIn("recovery_image_changed (F)", text)

    def test_stale_intent_archives_and_launches_on_a_replaced_file(self):
        # Row 13: an intent precedes a reinstall; the new file's slot is none.
        out = self.target()
        with patch.dict(os.environ, {"ABSD_RECOVER_FAULT": "after-intent"}):
            with self.assertRaises(sfr.Fault):
                self.act(out)
        ident = toml(next((out / "recovery").glob("intent-*.toml")))["intent"]["id"]
        build_image(out / "new.img", machine_files("failed"), seq=12)
        (out / "new.img").replace(out / sfr.IMAGE)
        decision, text = self.status(out, reconcile=False)
        self.assertEqual([step.name for step in decision.chain], ["stale-intent", "none"])
        self.assertEqual(sfr.precheck(out, log=Lines()), 0)
        archive = toml(out / "recovery" / f"stale-{ident}.toml")["archive"]
        self.assertEqual(archive["kind"], "stale")
        self.assertNotEqual(archive["new_f"], archive["f"])
        self.assertIn(f"state=none last=stale {ident}", self.status(out)[1])


# -- B8: decision-table totality --------------------------------------------

F_KINDS = ("equal", "differs", "unreadable")
SLOT_KINDS = ("none", "R-matching", "R-other", "corrupt", "unreadable")
RECORD_KINDS = ("none", "intent-only", "active-authorized", "active-launched", "intent+active", "active-with-archive",
                "intent-with-archive", "unparsable-intent", "unparsable-active", "two-archives-no-current")


def oracle(f, slot, records):
    """ACCEPTANCE-v5 B8 expected-row table: (initial row number, final row number)."""
    if f == "unreadable":
        return 0, 0
    if slot == "unreadable":
        return 1, 1
    if slot == "corrupt":
        return 2, 2
    if records in ("unparsable-intent", "unparsable-active"):
        return (3, 14) if slot == "none" else (3, 3)
    if records == "active-with-archive":
        # row 4, then without the active: T = none
        return (4, 14) if slot == "none" else (4, 5)
    t = {"none": "none", "intent-only": "intent", "active-authorized": "active", "active-launched": "active",
         "intent+active": "active", "intent-with-archive": "none", "two-archives-no-current": "none"}[records]
    if slot in ("R-matching", "R-other"):
        if t == "none":
            return 5, 5
        if t == "intent":
            return (6, 8) if (slot == "R-matching" and f == "equal") else (7, 7)
        return (8, 8) if (slot == "R-matching" and f == "equal") else (9, 9)
    if t == "active":
        return (10, 14) if f == "equal" else (11, 11)
    if t == "intent":
        return (12, 12) if f == "equal" else (13, 14)
    return 14, 14


class Totality(Base):
    def combination(self, index, f, slot, records, guard_readonly=False, **disk):
        out = self.target(f"c{index}", **disk)
        image = out / sfr.IMAGE
        directory = out / "recovery"
        if guard_readonly:
            set_record_flag(image, b"recovery.guard", 1)
        try:
            record = record_for(image)
        except (sfr.Refused, TypeError):  # a history the act refuses: the record's ledger fields are placeholders
            facts = sfr.read_disk(image)
            record = {"id": "a" * 32, "fs": facts["fs_id"], "seq": facts["seq"], "image": facts["image"],
                      "ledger_seq": 3, "ledger_boot": BOOT0, "previous": "failed", "time": 1761100000}
        planned = guard.encode_resume(record)
        other = guard.encode_resume(dict(record, seq=record["seq"] + 1))
        this_f = sfr.identity_of(image)
        recorded_f = list(this_f) if f == "equal" else [this_f[0], this_f[1] + 1, this_f[2]]
        fd = os.open(image, os.O_RDONLY)
        try:
            hm = sfr.masked_hash(fd, sfr.read_disk(image)["slot"]["offset"])
        finally:
            os.close(fd)
        base = {"id": record["id"], "time": "2026-10-22T10:00:00Z", "f": recorded_f, "hm": hm, "planned": planned.hex(),
                "fs_id": record["fs"], "fs_seq": record["seq"], "image": record["image"], "ledger_seq": 3,
                "ledger_boot": BOOT0, "previous": "failed", "release": "rel-a", "target": "lab-1", "reason": "b8",
                "user": "test", "tool": "test", "platform": "test", "attest_sole_instance": True,
                "accept_committed_state": True}
        self.assertTrue(sfr.valid_authorization(base))
        if slot == "R-matching":
            write_slot(image, planned)
        elif slot == "R-other":
            write_slot(image, other)
        elif slot == "corrupt":
            write_slot(image, (here.parent / "fixtures/storage-fence/resume-v1-torn-200.bin").read_bytes())
        elif slot == "unreadable":
            geo = absd_fs.geometry(FS_SECTORS)
            flip_byte(image, (FS_FIRST + absd_fs.META_FIRST + geo["half_sectors"]) * SECTOR + 300)
        if f == "unreadable":
            image.rename(out / "moved.img")
            image.symlink_to(out / "moved.img")

        def intent(ident=base["id"]):
            sfr.publish(directory / f"intent-{ident}.toml", sfr.toml_dump({"intent": dict(base, id=ident)}))

        def active(state="authorized"):
            facts = {} if state == "authorized" else {"launch_pid": 1, "launch_console": str(out / "console.log"),
                                                      "launch_time": "2026-10-22T10:00:01Z", "launches": 1}
            sfr.publish(directory / sfr.ACTIVE, sfr.toml_dump({"active": dict(base, state=state, **facts)}))

        def archive(kind, ident=base["id"], when="2026-10-22T09:00:00Z"):
            sfr.publish(directory / f"{kind}-{ident}.toml",
                        sfr.toml_dump({"archive": dict(base, id=ident, kind=kind, time=when)}))
        if records == "intent-only":
            intent()
        elif records == "active-authorized":
            active()
        elif records == "active-launched":
            active("launched")
        elif records == "intent+active":
            intent()
            active()
        elif records == "active-with-archive":
            active()
            archive("consumed")
        elif records == "intent-with-archive":
            intent()
            archive("revoked")
        elif records == "unparsable-intent":
            (directory / f"intent-{'b' * 32}.toml").write_text("[intent]\nid = 'b' * 32\n")
        elif records == "unparsable-active":
            (directory / sfr.ACTIVE).write_text("[active\n")
        elif records == "two-archives-no-current":
            archive("consumed", "c" * 32, "2026-10-22T08:00:00Z")
            archive("revoked", "d" * 32, "2026-10-22T09:00:00Z")
        return out

    def test_every_combination_maps_to_exactly_the_oracle_row(self):
        count = 0
        for index, (f, slot, records) in enumerate(itertools.product(F_KINDS, SLOT_KINDS, RECORD_KINDS)):
            with self.subTest(f=f, slot=slot, records=records):
                out = self.combination(index, f, slot, records)
                want_initial, want_final = oracle(f, slot, records)
                decision, text = self.status(out, reconcile=False)
                self.assertEqual(decision.chain[0].row, want_initial, f"initial: {text}")
                self.assertEqual(decision.final.row, want_final, f"final: {text}")
                self.assertRegex(text, r"(?m)^state=\S+ last=.* history=\d+")
                if records == "two-archives-no-current":
                    self.assertIn("history=2", text)
                # The launcher takes the row's disposition and leaves the row's file set.
                names_before = sorted(p.name for p in (out / "recovery").iterdir())
                lines = Lines()
                code = sfr.precheck(out, log=lines)
                self.assertEqual(code, 0 if decision.final.launch else 7, lines.text)
                names = sorted(p.name for p in (out / "recovery").iterdir())
                if want_final == 14 and want_initial == 10:
                    self.assertIn(f"consumed-{'a' * 32}.toml", names)
                    self.assertNotIn(sfr.ACTIVE, names)
                if want_final == 14 and want_initial == 13:
                    self.assertIn(f"stale-{'a' * 32}.toml", names)
                if want_final == 8 and want_initial == 6:
                    self.assertIn(sfr.ACTIVE, names)
                if want_initial == 4:
                    self.assertNotIn(sfr.ACTIVE, names)
                if want_initial == 3 and want_final == 14:
                    self.assertTrue(any(name.startswith("corrupt-") for name in names))
                if want_initial in (0, 1, 2, 5, 7, 9, 11, 12, 14) or want_final == 3:
                    self.assertEqual(names, names_before, "a refusing or launching row writes no record")
                # Idempotent: the same final row again.
                self.assertEqual(self.status(out)[0].final.row, want_final)
                count += 1
        self.assertEqual(count, 150)
        print(f"RESUME TABLE OK case=b8 combinations={count}", flush=True)

    def test_status_never_advises_recover_when_the_act_refuses(self):
        # F4 ruling: for every final row the table produces, under every guard
        # and history, `--status` advises `recover` exactly when `act` acts.
        recover_now = {sfr.ACTIONS["none"], sfr.ACTIONS["intent-only"]}
        rows = {}
        for f, slot, records in itertools.product(F_KINDS, SLOT_KINDS, RECORD_KINDS):
            rows.setdefault(oracle(f, slot, records)[1], (f, slot, records))
        self.assertEqual(sorted(rows), [0, 1, 2, 3, 5, 7, 8, 9, 11, 12, 14])
        guards = {"fresh": dict(guard_state="fresh"), "clean": dict(guard_state="clean"),
                  "dirty": dict(guard_state="dirty"), "corrupt": dict(guard_state="dirty", guard_readonly=True),
                  "missing": dict(with_guard=False)}
        histories = {"none": dict(state=False), "ended": dict(previous="ended"), "failed": dict(previous="failed"),
                     "not_ready": dict(previous="not_ready"), "lost": dict(with_ledger=False)}
        count, acted = 0, []
        for (row, combo), (g, gkw), (h, hkw) in itertools.product(sorted(rows.items()), guards.items(), histories.items()):
            with self.subTest(row=row, guard=g, history=h):
                out = self.combination(f"g{count}", *combo, **gkw, **hkw)
                decision, text = self.status(out)
                self.assertEqual(decision.final.row, row, text)
                actions = [line[len("action: "):] for line in text.splitlines() if line.startswith("action: ")]
                self.assertEqual(len(actions), 1, text)
                try:
                    self.act(out)
                    refusal = None
                except sfr.Refused as error:
                    refusal = error
                if refusal is None:
                    acted.append((row, g, h))
                    self.assertIn(actions[0], recover_now, text)
                else:
                    self.assertNotIn(actions[0], recover_now, f"{refusal}: {text}")
                    if row in (12, 14):
                        self.assertNotRegex(actions[0], r"\brecover\b", f"{refusal}: {text}")
                        if refusal.reason == "previous_not_recoverable":
                            self.assertEqual(actions[0], "previous_not_recoverable: restore a backup or extract read-only")
                count += 1
        self.assertEqual(count, 11 * 5 * 5)
        # The act proceeds only on a dirty guard with a failed or not_ready history, on rows 12 and 14.
        self.assertEqual(sorted(acted), sorted(itertools.product((12, 14), ("dirty",), ("failed", "not_ready"))))

    def test_hm_only_mismatch_is_the_third_cause_supplemental_to_the_150(self):
        # F equal and bytes matching, one byte flipped outside the slot.
        supplemental = 0
        for records, row in (("intent-only", 7), ("active-authorized", 9)):
            out = self.combination(200 + row, "equal", "R-matching", records)
            geo = absd_fs.geometry(FS_SECTORS)
            flip_byte(out / sfr.IMAGE, (FS_FIRST + geo["data_first"] + 3 * 8) * SECTOR + 1)
            decision, text = self.status(out, reconcile=False)
            self.assertEqual((decision.final.row, decision.final.name), (row, "mismatch"))
            self.assertIn("recovery_image_changed (hm)", text)
            self.assertEqual(sfr.precheck(out, log=Lines()), 7)
            supplemental += 1
        print(f"RESUME TABLE OK case=b8-hm supplemental={supplemental}", flush=True)


# -- W, the launcher, the exit path ----------------------------------------------

NIC = "NETWORK LINK OK rx_descriptors=32 tx_descriptors=32 buffer_bytes=2048\n"


def chunk(text):
    data = text.encode()
    return f"EXTERNAL OUTPUT CHUNK offset={0:x} data={data.hex()}\n"


def console_text(ident, *, resumed=True, release=True, listening=True, refusal=None, nic=True):
    text = "ABSD KERNEL BOOT\n" + (NIC if nic else "")
    if refusal:
        return text + refusal + "\nDURABLE status=7 frames=0 block_writes=0 block_flushes=0 block_errors=0 ticks=1\n"
    if resumed:
        text += f"RECOVERY WRITABLE RESUMED id={ident} previous=failed fs_seq=11 ledger_seq=3\n"
    text += "FSD RECOVERY seq=4 streak=2 previous=failed\n"
    if release:
        text += "RELEASE OK release=rel-a\n"
    if listening:
        text += chunk("SSH LISTENING port=22 authorized_keys=1 preauth_per_source=4\n")
    return text


class Readiness(Base):
    def launched(self, out, ident, console, pid=None):
        if pid is None:
            holder = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(300)"])
            self.holders.append(holder)
            pid = holder.pid
        sfr.launched(out, ident=ident, pid=pid, console=console, log=Lines())
        return pid

    def wait(self, out, ident, timeout=5, steps=None):
        clock = [0.0]

        def now():
            return clock[0]

        def sleep(seconds):
            clock[0] += seconds
            if steps:
                steps(clock[0])
        lines = Lines()
        code = sfr.wait_ready(out, ident=ident, timeout=timeout, log=lines, clock=now, sleep=sleep)
        return code, lines.text

    def test_wait_ready_exits_0_7_and_124_bound_to_the_latest_boot(self):
        out = self.target()
        intent, _ = self.act(out)
        ident = intent["id"]
        console = out / "console.log"
        # Before any launch: nothing to wait for.
        code, text = self.wait(out, ident)
        self.assertEqual(code, 7)
        self.assertIn("no launch recorded", text)
        pid = self.launched(out, ident, console)
        # (a) timeout with a boot that never reaches readiness: 124.
        console.write_text("ABSD KERNEL BOOT\n" + NIC)
        code, text = self.wait(out, ident, timeout=1)
        self.assertEqual(code, 124)
        self.assertIn("do not SSH", text)
        # (b) a refusal in this launch's console: 7 with the line.
        console.write_text(console_text(ident, refusal="RECOVERY STATE REFUSED reason=resume_mismatch"))
        code, text = self.wait(out, ident)
        self.assertEqual(code, 7)
        self.assertIn("RECOVERY STATE REFUSED reason=resume_mismatch", text)
        # Readiness in an earlier boot of the same console does not count.
        console.write_text(console_text(ident) + "ABSD KERNEL BOOT\n" + NIC)
        code, text = self.wait(out, ident, timeout=1)
        self.assertEqual(code, 124)
        # The three records out of order or with another id: not ready.
        console.write_text(console_text("f" * 32))
        self.assertEqual(self.wait(out, ident, timeout=1)[0], 124)
        console.write_text(console_text(ident, listening=False))
        self.assertEqual(self.wait(out, ident, timeout=1)[0], 124)
        # Ready: the three lines in order and the receive setup settled.
        console.write_text(console_text(ident))
        code, text = self.wait(out, ident)
        self.assertEqual(code, 0, text)
        self.assertRegex(text, rf"(?m)^READY id={ident} console=.* after=\d+\.\ds$")
        # The process gone before readiness: 7.
        console.write_text("ABSD KERNEL BOOT\n")
        os.kill(pid, 9)
        time.sleep(0.2)
        code, text = self.wait(out, ident)
        self.assertEqual(code, 7)
        self.assertIn("ended before readiness", text)
        # A consumed id: nothing to wait for.
        write_slot(out / sfr.IMAGE, guard.RESUME_NONE)
        self.status(out)
        code, text = self.wait(out, ident)
        self.assertEqual(code, 7)
        self.assertIn("is consumed", text)

    def test_wait_ready_refuses_a_reset_during_the_receive_setup_and_enforces_the_order(self):
        # The reviewer's reproduction: complete readiness in the first read,
        # then a reset whose boot shows only its NIC record.
        out = self.target()
        intent, _ = self.act(out)
        ident = intent["id"]
        console = out / "console.log"
        self.launched(out, ident, console)
        console.write_text(console_text(ident))
        # Exactly the reviewer's window: wait_ready observed readiness, and
        # the reset lands before the receive helper's first read (its first
        # clock call), so the helper settles against the new boot's NIC record.
        clock = [0.0]
        calls = [0]

        def now():
            calls[0] += 1
            if calls[0] == 2 and "RESET-DONE" not in console.read_text():
                console.write_text(console_text(ident) + "ABSD KERNEL BOOT\n" + NIC + "# RESET-DONE\n")
            return clock[0]

        def sleep(seconds):
            clock[0] += seconds
        lines = Lines()
        code = sfr.wait_ready(out, ident=ident, timeout=5, log=lines, clock=now, sleep=sleep)
        self.assertEqual(code, 7, lines.text)
        self.assertIn("reset during the receive setup (boot 1 -> 2)", lines.text)
        self.assertNotIn("READY", lines.text)
        # The same with a reset the receive helper itself sees (NIC record
        # appears only in the new boot): refused too.
        console.write_text(console_text(ident, nic=False))

        def late_nic(at):
            if at >= 0.3 and "LATE" not in console.read_text():
                console.write_text(console_text(ident, nic=False) + "ABSD KERNEL BOOT\n" + NIC + "# LATE\n")
        code, text = self.wait(out, ident, steps=late_nic)
        self.assertEqual(code, 7, text)
        # Ordering: the listener before RELEASE OK, or RELEASE OK before RESUMED, is not readiness.
        chunk_first = ("ABSD KERNEL BOOT\n" + NIC + chunk("SSH LISTENING port=22 authorized_keys=1 preauth_per_source=4\n")
                       + f"RECOVERY WRITABLE RESUMED id={ident} previous=failed fs_seq=11 ledger_seq=3\n"
                       + "RELEASE OK release=rel-a\n")
        console.write_text(chunk_first)
        self.assertEqual(self.wait(out, ident, timeout=1)[0], 124)
        release_first = ("ABSD KERNEL BOOT\n" + NIC + "RELEASE OK release=rel-a\n"
                         + f"RECOVERY WRITABLE RESUMED id={ident} previous=failed fs_seq=11 ledger_seq=3\n"
                         + chunk("SSH LISTENING port=22 authorized_keys=1 preauth_per_source=4\n"))
        console.write_text(release_first)
        self.assertEqual(self.wait(out, ident, timeout=1)[0], 124)
        self.assertEqual(sfr.readiness(console_text(ident).encode(), ident)[0], "ready")
        self.assertEqual(sfr.readiness(chunk_first.encode(), ident)[0], None)

    def test_wait_ready_ignores_a_console_older_than_the_launch(self):
        # L7 (c): a complete earlier readiness left in place before the launch.
        out = self.target()
        intent, _ = self.act(out)
        ident = intent["id"]
        console = out / "console.log"
        console.write_text(console_text(ident))
        old = time.time() - 3600
        os.utime(console, (old, old))
        self.launched(out, ident, console)
        active = toml(out / "recovery" / sfr.ACTIVE)["active"]
        future = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 120))
        sfr.publish(out / "recovery" / sfr.ACTIVE, sfr.toml_dump({"active": dict(active, launch_time=future)}))
        code, text = self.wait(out, ident, timeout=1)
        self.assertEqual(code, 124, text)

    def test_exit_path_launch_failed_consumed_and_intact(self):
        out = self.target()
        intent, _ = self.act(out)
        ident = intent["id"]
        console = out / "console.log"
        pid = self.launched(out, ident, console)
        self.assertEqual(toml(out / "recovery" / sfr.ACTIVE)["active"]["state"], "launched")
        # No ABSD KERNEL BOOT: launch_failed, active back to authorized.
        console.write_text("qemu: could not open the ISO\n")
        lines = Lines()
        sfr.exit_path(out, status_word="1", console=console, log=lines)
        self.assertIn("launch_failed", lines.text)
        self.assertEqual(toml(out / "recovery" / sfr.ACTIVE)["active"]["state"], "authorized")
        # A boot that ran but did not consume (L5 shape): launched, relaunch noted.
        self.launched(out, ident, console, pid)
        self.launched(out, ident, console, pid)
        self.assertEqual(toml(out / "recovery" / sfr.ACTIVE)["active"]["launches"], 3)
        console.write_text("ABSD KERNEL BOOT\n" + NIC + "RECOVERY STATE REFUSED reason=lost\n")
        lines = Lines()
        sfr.exit_path(out, status_word="7", console=console, log=lines)
        self.assertIn("state=launched", lines.text)
        self.assertEqual(sfr.read_disk(out / sfr.IMAGE)["slot"]["parsed"]["id"], ident)
        self.assertEqual(sfr.precheck(out, log=Lines()), 0)
        # Consumed with the witness line: retired, consumed-<id> with witness=yes.
        console.write_text(console_text(ident) + "SERVED SHUTDOWN FINALIZED status=0\nABSD BOOT OK\n")
        write_slot(out / sfr.IMAGE, guard.RESUME_NONE)
        lines = Lines()
        sfr.exit_path(out, status_word="3", console=console, log=lines)
        self.assertIn(f"RECOVERY CONSUMED id={ident} witness=yes", lines.text)
        archive = toml(out / "recovery" / f"consumed-{ident}.toml")["archive"]
        self.assertEqual(archive["disposition"], "consumed")
        self.assertIn(f"RECOVERY WRITABLE RESUMED id={ident}", archive["witness"])
        self.assertIn(f"state=none last=consumed {ident}", self.status(out)[1])
        self.assertIn("witness=yes", self.status(out)[1])
        # B6: a consumption without the launcher (durable-boot.sh) is consumed_unwitnessed.
        out = self.target("b6")
        intent, _ = self.act(out)
        write_slot(out / sfr.IMAGE, guard.RESUME_NONE)
        decision, text = self.status(out)
        self.assertEqual(toml(out / "recovery" / f"consumed-{intent['id']}.toml")["archive"]["disposition"],
                         "consumed_unwitnessed")
        self.assertIn("witness=no", text)
        for _ in range(2):
            self.assertEqual(sfr.precheck(out, log=Lines()), 0)
            self.assertIn(f"state=none last=consumed {intent['id']}", self.status(out)[1])


FAKE_QEMU = r'''#!/bin/sh
# A QEMU stand-in for the launcher test: writes the console the arguments
# name, consumes the slot as the guest would (ABSD_FAKE_CONSUME), exits
# with ABSD_FAKE_STATUS. It holds the image open while it "runs".
console=; image=
for arg in "$@"; do
    case $arg in
    file:*) console=${arg#file:} ;;
    file=*,format=raw*) image=${arg#file=}; image=${image%%,*} ;;
    esac
done
exec 3<"$image"
if [ -n "${ABSD_FAKE_STDERR:-}" ]; then echo "$ABSD_FAKE_STDERR" >&2; exit "${ABSD_FAKE_STATUS:-1}"; fi
printf 'ABSD KERNEL BOOT\n' > "$console"
if [ -n "${ABSD_FAKE_APPEND:-}" ]; then printf '%s\n' "$ABSD_FAKE_APPEND" >> "$console"; fi
if [ -n "${ABSD_FAKE_HOLD:-}" ]; then sleep "$ABSD_FAKE_HOLD"; fi
if [ -n "${ABSD_FAKE_CONSUME:-}" ]; then
    python3 -I "$ABSD_FAKE_CONSUME" "$image" "$console"
fi
exit "${ABSD_FAKE_STATUS:-3}"
'''

CONSUME = r'''
import sys, pathlib
sys.path.insert(0, sys.argv[3] if len(sys.argv) > 3 else "scripts")
import storage_fence_resume as sfr
import storage_fence_state as guard
image, console = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
disk = sfr.read_disk(image)
record = disk["slot"]["parsed"]
with open(image, "r+b") as handle:
    handle.seek(disk["slot"]["offset"]); handle.write(guard.RESUME_NONE)
with open(console, "a") as out:
    out.write("NETWORK LINK OK rx_descriptors=32 tx_descriptors=32 buffer_bytes=2048\n")
    out.write(f"RECOVERY WRITABLE RESUMED id={record['id']} previous={record['previous']} fs_seq={record['seq']} ledger_seq={record['ledger_seq']}\n")
    out.write("FSD RECOVERY seq=4 streak=2 previous=failed\nRELEASE OK release=rel-a\n")
    data = b"SSH LISTENING port=22 authorized_keys=1 preauth_per_source=4\n"
    out.write(f"EXTERNAL OUTPUT CHUNK offset=0 data={data.hex()}\n")
    out.write("SERVED SHUTDOWN FINALIZED status=0\nABSD BOOT OK\n")
'''


class Launcher(Base):
    """boot-operator.sh with a QEMU stand-in: the lock, the rotation, the
    precheck, `launched` after the process exists, the exit path, and the
    descriptor behavior of the lock across the launch."""

    def setUp(self):
        super().setUp()
        self.fake = self.work / "fake-qemu"
        self.fake.write_text(FAKE_QEMU)
        self.fake.chmod(0o755)
        self.consume = self.work / "consume.py"
        self.consume.write_text(CONSUME.replace('"scripts"', repr(str(here))))

    def boot(self, out, env=None, **kw):
        environment = dict(os.environ, ABSD_QEMU=str(self.fake))
        environment.update(env or {})
        (out / "absd-operator.iso").write_bytes(b"iso")
        return subprocess.run([str(here / "boot-operator.sh"), str(out), "2299"], capture_output=True, text=True,
                              env=environment, timeout=120, **kw)

    def test_launcher_rotates_prechecks_records_the_launch_and_retires_on_exit(self):
        out = self.target()
        (out / "console.log").write_text("an older console\n")
        intent, _ = self.act(out)
        ran = self.boot(out, {"ABSD_FAKE_CONSUME": str(self.consume)})
        self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
        self.assertIn("previous console rotated to", ran.stdout)
        self.assertTrue(list(out.glob("console-*.log")))
        self.assertRegex(ran.stdout, rf"(?m)^boot-operator: launched id={intent['id']} pid=\d+ console=.*console\.log$")
        self.assertIn(f"RECOVERY CONSUMED id={intent['id']} witness=yes", ran.stdout)
        self.assertIn("boot-operator: the machine halted", ran.stdout)
        self.assertEqual(self.status(out)[0].final.name, "none")
        self.assertTrue((out / "recovery" / f"consumed-{intent['id']}.toml").is_file())
        self.assertEqual(sfr.read_disk(out / sfr.IMAGE)["slot"]["parsed"], "none")

    def test_launcher_refuses_when_the_precheck_refuses_and_when_the_lock_is_held(self):
        out = self.target()
        write_slot(out / sfr.IMAGE, (here.parent / "fixtures/storage-fence/resume-v1-torn-40.bin").read_bytes())
        ran = self.boot(out)
        self.assertEqual(ran.returncode, 7)
        self.assertIn("state=corrupt-slot", ran.stdout)
        self.assertNotIn("launched", ran.stdout)
        out = self.target("busy")
        self.hold_lock(out)
        ran = self.boot(out)
        self.assertEqual(ran.returncode, 7)
        self.assertIn("tool_busy", ran.stderr)

    def test_launch_failed_keeps_the_authorization_and_the_lock_goes_with_the_launcher(self):
        # L4 (host shape): the process never printed ABSD KERNEL BOOT. A
        # classified launch_failed is its own exit (6) and message, never
        # the bookkeeping failure (1).
        out = self.target()
        intent, _ = self.act(out)
        ran = self.boot(out, {"ABSD_FAKE_STDERR": "qemu: cannot exec", "ABSD_FAKE_STATUS": "1"})
        self.assertEqual(ran.returncode, 6, ran.stdout + ran.stderr)
        self.assertIn("launch_failed status=1", ran.stdout)
        self.assertIn("boot-operator: launch failed: QEMU exited with status 1 before ABSD KERNEL BOOT", ran.stderr)
        self.assertNotIn("exit classification failed", ran.stderr)
        active = toml(out / "recovery" / sfr.ACTIVE)["active"]
        self.assertEqual((active["state"], active["last_launch"], active["last_launch_status"]),
                         ("authorized", "launch_failed", "1"))
        # W names the boot end instead of "no launch recorded".
        lines = Lines()
        self.assertEqual(sfr.wait_ready(out, ident=intent["id"], timeout=5, log=lines), 7)
        self.assertRegex(lines.text, rf"wait-ready: id={intent['id']} launch_failed status=1: the last launch "
                                     r"\(pid \d+, [0-9TZ:-]+\) ended without ABSD KERNEL BOOT in .*console\.log; "
                                     r"the authorization is intact")
        self.assertEqual(sfr.read_disk(out / sfr.IMAGE)["slot"]["parsed"]["id"], intent["id"])
        # A QEMU path that does not exist at all: no `launched` record.
        ran = self.boot(out, {"ABSD_QEMU": str(self.work / "missing-qemu")})
        self.assertNotEqual(ran.returncode, 0)
        self.assertEqual(toml(out / "recovery" / sfr.ACTIVE)["active"]["state"], "authorized")
        # The lock is held while the launcher runs (M2), and QEMU does not
        # inherit it: once the wrapper is gone the lock is free even while
        # the fake QEMU still runs.
        proc = subprocess.Popen([str(here / "boot-operator.sh"), str(out), "2299"], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True,
                                env=dict(os.environ, ABSD_QEMU=str(self.fake), ABSD_FAKE_HOLD="20"))
        self.holders.append(proc)
        deadline = time.time() + 15
        while time.time() < deadline and not (out / "console.log").exists():
            time.sleep(0.1)
        time.sleep(0.5)
        self.assertEqual(toml(out / "recovery" / sfr.ACTIVE)["active"]["state"], "launched")
        self.refused(sfr.recovery_lock(out).__enter__, "tool_busy")
        children = subprocess.run(["pgrep", "-P", str(proc.pid)], capture_output=True, text=True).stdout.split()
        self.assertTrue(children)
        proc.kill()
        proc.wait()
        time.sleep(0.3)
        with sfr.recovery_lock(out):
            pass
        for child in children:
            with contextlib.suppress(ProcessLookupError):
                os.kill(int(child), 9)


class LauncherExits(Launcher):
    """F1: the launcher's three exits through a classified record, each
    with its own status and message: a normal halt (0), a guest refusal
    after ABSD KERNEL BOOT (QEMU's 7, the record intact and launched), a
    launch that never booted (6)."""

    launched = Readiness.launched

    def test_normal_halt_guest_refusal_and_failed_launch_exits(self):
        out = self.target()
        intent, _ = self.act(out)
        ran = self.boot(out, {"ABSD_FAKE_STATUS": "7", "ABSD_FAKE_APPEND": "RECOVERY STATE REFUSED reason=resume_mismatch"})
        self.assertEqual(ran.returncode, 7, ran.stdout + ran.stderr)
        self.assertIn("boot-operator: exit state=launched", ran.stdout)
        self.assertIn("QEMU exited with status 7", ran.stderr)
        self.assertNotIn("exit classification failed", ran.stderr)
        self.assertNotIn("launch failed", ran.stderr)
        active = toml(out / "recovery" / sfr.ACTIVE)["active"]
        self.assertEqual(active["state"], "launched")
        self.assertNotIn("last_launch", active)
        ran = self.boot(out, {"ABSD_FAKE_STDERR": "qemu: could not open the ISO", "ABSD_FAKE_STATUS": "1"})
        self.assertEqual(ran.returncode, 6, ran.stdout + ran.stderr)
        self.assertNotIn("exit classification failed", ran.stderr)
        ran = self.boot(out, {"ABSD_FAKE_CONSUME": str(self.consume)})
        self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
        self.assertIn("boot-operator: the machine halted", ran.stdout)
        self.assertNotIn("launch failed", ran.stderr)
        self.assertTrue((out / "recovery" / f"consumed-{intent['id']}.toml").is_file())

    def test_exit_path_status_codes(self):
        out = self.target()
        intent, _ = self.act(out)
        console = out / "console.log"
        self.launched(out, intent["id"], console)
        console.write_text("qemu: no such file\n")
        self.assertEqual(sfr.exit_path(out, status_word="1", console=console, log=Lines()), sfr.LAUNCH_FAILED)
        self.launched(out, intent["id"], console)
        self.assertNotIn("last_launch", toml(out / "recovery" / sfr.ACTIVE)["active"])
        console.write_text("ABSD KERNEL BOOT\n" + NIC + "RECOVERY STATE REFUSED reason=lost\n")
        self.assertEqual(sfr.exit_path(out, status_word="7", console=console, log=Lines()), 0)
        # No authorization at all: a failed boot is QEMU's business (0).
        plain = self.target("plain")
        (plain / "console.log").write_text("")
        self.assertEqual(sfr.exit_path(plain, status_word="1", console=plain / "console.log", log=Lines()), 0)


class LauncherFailures(Launcher):
    def test_a_failed_launched_publication_stops_qemu_and_fails_the_launcher(self):
        out = self.target()
        intent, _ = self.act(out)
        ran = self.boot(out, {"ABSD_FAKE_HOLD": "30", "ABSD_RECOVER_FAULT": "launched-fail"})
        self.assertEqual(ran.returncode, 1, ran.stdout + ran.stderr)
        self.assertIn("launched record could not be published", ran.stderr)
        self.assertEqual(toml(out / "recovery" / sfr.ACTIVE)["active"]["state"], "authorized")
        self.assertEqual(sfr.read_disk(out / sfr.IMAGE)["slot"]["parsed"]["id"], intent["id"])
        self.assertFalse(subprocess.run(["pgrep", "-f", str(self.fake)], capture_output=True).stdout.strip(),
                         "the fake QEMU was stopped")

    def test_a_failed_exit_classification_fails_the_launcher(self):
        out = self.target()
        intent, _ = self.act(out)
        ran = self.boot(out, {"ABSD_FAKE_CONSUME": str(self.consume), "ABSD_RECOVER_FAULT": "retire-after-archive"})
        self.assertEqual(ran.returncode, 1, ran.stdout + ran.stderr)
        self.assertIn("exit classification failed", ran.stderr)
        # The next status completes the retirement from the archive.
        decision, text = self.status(out)
        self.assertIn(f"state=none last=consumed {intent['id']}", text)


class LauncherFinalizationFailure(Launcher):
    def test_the_launcher_starts_no_qemu_when_finalization_fails(self):
        out = self.target()
        with patch.dict(os.environ, {"ABSD_RECOVER_FAULT": "after-slot"}):
            with self.assertRaises(sfr.Fault):
                self.act(out)
        ran = self.boot(out, {"ABSD_RECOVER_FAULT": "fsync-fail"})
        self.assertEqual(ran.returncode, 7, ran.stdout + ran.stderr)
        self.assertIn("refusal=record_unverified", ran.stdout)
        self.assertNotIn("launched", ran.stdout)
        self.assertFalse((out / "console.log").exists(), "no QEMU wrote a console")
        self.assertFalse((out / "recovery" / sfr.ACTIVE).exists())

    def test_the_launcher_refuses_an_authorization_it_cannot_name(self):
        # precheck named an authorization, but no active id resolves:
        # the launcher must not start QEMU.
        out = self.target()
        self.act(out)
        ran = self.boot(out, {"ABSD_RESUME_TEST_HIDE_ACTIVE": "1"})
        self.assertEqual(ran.returncode, 7, ran.stdout + ran.stderr)
        self.assertIn("no active authorization id resolves", ran.stderr)
        self.assertFalse((out / "console.log").exists())


class DescriptorBehavior(Base):
    def test_the_recovery_lock_follows_the_descriptor_across_exec(self):
        out = self.target()
        script = ("import fcntl, os, subprocess, sys\nfd = os.open(sys.argv[1], os.O_RDWR)\n"
                  "fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
                  "os.set_inheritable(fd, sys.argv[2] == 'inherit')\nprint('held', flush=True)\n"
                  "os.execvp('sleep', ['sleep', '300'])\n")
        for mode, busy in (("inherit", True), ("close", False)):
            proc = subprocess.Popen([sys.executable, "-I", "-c", script, str(out / "recovery" / "lock"), mode],
                                    stdout=subprocess.PIPE, close_fds=False)
            self.holders.append(proc)
            self.assertEqual(proc.stdout.readline(), b"held\n")
            time.sleep(0.3)
            if busy:
                self.refused(sfr.recovery_lock(out).__enter__, "tool_busy")
            else:
                with sfr.recovery_lock(out):
                    pass
            proc.kill()
            proc.wait()
            with sfr.recovery_lock(out):
                pass


if __name__ == "__main__":
    unittest.main()
