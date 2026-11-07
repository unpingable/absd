#!/usr/bin/env python3
"""Bounded operator-attested writable recovery on the host (coordination record #63;
docs/WRITABLE-ENTRY.md "Operator-authorized resume", OPERATOR-RUNBOOK.md 9a).

The act (`release.py recover`) binds one explicit, recorded operator
authorization to one logical committed state of one image file, writes it
as the resume record at the private slot `/var/recovery.resume`, and
publishes host records under `OUT/recovery/`. The next serving boot admits
only that exact state and consumes the record as its first device write.
Everything here is host-side: the OFD range lock QEMU's own file locking
uses, the recovery lock every supported launcher and mutator takes, the
identity F = (st_dev, st_ino, size), the masked content hash Hm, the
independent host reader (no repair), the current-transaction selection and
the fifteen-row decision table (`classify`, one ordered function), durable
publication, finalization, idempotent retirement, `--status`, `--revoke`,
`precheck`, `launched`, the exit path and `--wait-ready`.

Commands (release.py `recover` wraps the first four):

  storage_fence_resume.py act OUT --attest-sole-instance --accept-committed-state --reason TEXT
  storage_fence_resume.py status OUT
  storage_fence_resume.py revoke OUT --reason TEXT
  storage_fence_resume.py wait-ready OUT --id ID [--timeout S]
  storage_fence_resume.py precheck OUT          (boot-operator.sh, under its recovery lock)
  storage_fence_resume.py launched OUT --id ID --pid PID --console PATH
  storage_fence_resume.py exit OUT --status N --console PATH

Fault hooks (ABSD_RECOVER_FAULT, qualification only): after-intent,
short-write:N, after-pwrite, fsync-fail, after-slot, after-active,
retire-temp-only, retire-after-archive, extra-descriptor.
"""

import argparse
import contextlib
import ctypes
import datetime
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import re
import stat
import struct
import subprocess
import sys
import time
import tomllib
import uuid

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import absd_fs  # noqa: E402
import operator_geometry  # noqa: E402
import storage_fence_state as guard  # noqa: E402
from e1000_rx import wait_rx_setup, RxSetupFailed  # noqa: E402

IMAGE = "absd-operator.img"
# Compatibility aliases retain the default fresh image geometry. Writes
# admit only explicit supported profiles; reads use each disk's actual size
# and validate its descriptor and filesystem geometry (image_sectors).
IMAGE_BYTES = operator_geometry.DEFAULT_IMAGE_BYTES
DEVICE_SECTORS = IMAGE_BYTES // 512


def image_sectors(path):
    """The device sectors of the disk at `path`, from its own size. Reads
    use the disk's geometry, never the creation size (coordination record #28: a
    64 MiB disk stays readable); the layout descriptor check then binds it
    (absd_image.parse_layout refuses a descriptor written for another
    size, so a truncated or padded image still fails closed)."""
    size = os.stat(path).st_size
    if size == 0 or size % absd_fs.SECTOR:
        raise Refused("image_size", f"{path} is {size} bytes, not a whole number of sectors")
    return size // absd_fs.SECTOR
LEDGER = "RELEASES"
RECOVERY = "recovery"
LOCK = "lock"
ACTIVE = "active.toml"
ARCHIVE_KINDS = ("consumed", "revoked", "stale", "superseded")
# QEMU file-posix: RAW_LOCK_PERM_BASE 100, RAW_LOCK_SHARED_BASE 200, each
# with a byte per permission; one exclusive lock over both ranges.
OFD_START, OFD_LENGTH = 100, 200
SECTOR = guard.SECTOR
READY_LINE = "RECOVERY WRITABLE RESUMED"
BOOT_LINE = b"ABSD KERNEL BOOT\n"
# A refusal or an end of the boot, as the console shows it (predicate W).
END_LINES = ("RECOVERY WRITABLE REFUSED", "RECOVERY STATE REFUSED", "RELEASE REFUSED", "FSD FAILED",
             "FSD FINALIZE FAILED", "SERVED RECOVERY REFUSED", "SERVED SHUTDOWN", "DURABLE status=", "ABSD BOOT OK",
             "MACHINE ", "init: FAILED", "ABI REFUSED", "FSD PROTOCOL REFUSED")
# statfs f_type magics of filesystems that are not one local disk.
NON_LOCAL = {0x6969: "nfs", 0xFF534D42: "cifs", 0xFE534D42: "smb2", 0x517B: "smb", 0x01021997: "9p",
             0x65735546: "fuse", 0x794C7630: "overlay", 0x73757245: "coda", 0x5346414F: "afs",
             0x00C36400: "ceph", 0x01161970: "gfs2", 0x7461636F: "ocfs2", 0x564C: "ncp", 0x6165676C: "pstore"}
WAIT_TIMEOUT = 180


class Refused(Exception):
    """One named refusal: `reason` is the word, `detail` the evidence."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


class Fault(Exception):
    """A qualification fault hook fired: the tool stops as a crash would."""


def fault(name):
    want = os.environ.get("ABSD_RECOVER_FAULT", "")
    if want == name:
        raise Fault(name)


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def toml_string(value):
    scalar = "".join("�" if 0xD800 <= ord(char) <= 0xDFFF else char for char in str(value))
    return json.dumps(scalar, ensure_ascii=False).replace("\x7f", "\\u007f")


def toml_dump(data):
    out = []
    for section, fields in data.items():
        out.append(f"[{section}]")
        for key, value in fields.items():
            if isinstance(value, bool):
                text = "true" if value else "false"
            elif isinstance(value, int):
                text = str(value)
            elif isinstance(value, (list, tuple)):
                text = "[" + ", ".join(str(v) if type(v) is int else toml_string(v) for v in value) + "]"
            else:
                text = toml_string(value)
            out.append(f"{key} = {text}")
        out.append("")
    return "\n".join(out)


def publish(path, text):
    """Durable publication: temp file in the same directory, fsync, rename
    over `path`, directory fsync."""
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    with open(temp, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)
    fsync_dir(path.parent)
    return path


def fsync_dir(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def remove_published(path):
    path = pathlib.Path(path)
    path.unlink(missing_ok=True)
    fsync_dir(path.parent)


# -- the image file: F, locality, exclusion ---------------------------------

def file_identity(st):
    return (st.st_dev, st.st_ino, st.st_size)


def identity_text(f):
    return "none" if f is None else f"{f[0]}:{f[1]}:{f[2]}"


def fs_type(fd):
    """statfs f_type of the filesystem holding `fd` (Linux, LP64)."""
    libc = ctypes.CDLL(None, use_errno=True)
    buffer = ctypes.create_string_buffer(256)
    if libc.fstatfs(fd, buffer) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return struct.unpack_from("q", buffer.raw, 0)[0] & 0xFFFFFFFF


def open_image(path):
    """Opens the image for the act: a regular, singly linked, local file of
    a supported profile size. Returns (fd, F). Named refusals, no write."""
    path = pathlib.Path(path)
    try:
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise Refused("image_not_regular", f"{path} is a symbolic link") from None
        raise Refused("image_unreadable", f"{path}: {error.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refused("image_not_regular", f"{path} is not a regular file")
        if st.st_nlink != 1:
            raise Refused("image_linked", f"{path} has {st.st_nlink} links; the image must be one exclusively named file")
        if not operator_geometry.is_writable_size(st.st_size):
            raise Refused("image_size", f"{path} is {st.st_size} bytes, not a supported writable profile (128m or 2g)")
        kind = fs_type(fd)
        if kind in NON_LOCAL:
            raise Refused("image_not_local", f"{path} is on {NON_LOCAL[kind]} (statfs type {kind:#x}); S-R1 needs a local filesystem")
    except BaseException:
        os.close(fd)
        raise
    return fd, file_identity(st)


def identity_of(path):
    """F of the pathname for classification, or None (row 0) when it is
    unreadable, not a regular file, linked or of the wrong size."""
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or not operator_geometry.is_writable_size(st.st_size):
        return None
    return file_identity(st)


@contextlib.contextmanager
def recovery_lock(out):
    """`flock(LOCK_EX | LOCK_NB)` on OUT/recovery/lock, held on an open
    descriptor for the block; never unlinked or recreated. `tool_busy`
    when another supported tool or a running boot-operator.sh holds it."""
    directory = pathlib.Path(out) / RECOVERY
    directory.mkdir(parents=True, exist_ok=True)
    fd = os.open(directory / LOCK, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                raise Refused("tool_busy", f"{directory / LOCK} is held by another tool or a running boot-operator.sh") from None
            raise
        yield fd
    finally:
        os.close(fd)


def ensure_lock(out):
    """The lock file of the layout, created once (install); never unlinked
    or recreated by any tool."""
    directory = pathlib.Path(out) / RECOVERY
    directory.mkdir(parents=True, exist_ok=True)
    os.close(os.open(directory / LOCK, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600))
    return directory / LOCK


def try_recovery_lock(out):
    """The lock, or None when it is busy (for --status reconciliation)."""
    directory = pathlib.Path(out) / RECOVERY
    directory.mkdir(parents=True, exist_ok=True)
    fd = os.open(directory / LOCK, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        os.close(fd)
        if error.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
            return None
        raise
    return fd


def ofd_lock(fd, exclusive=True, image=None):
    """QEMU's own protocol: an OFD write lock over bytes 100-299 of the
    image. Fails `image_locked` while any default-locking QEMU holds it
    (running, paused, -no-shutdown-stopped, any user); while held, a
    default-locking QEMU open fails at its own permission probe. The
    refusal names the holders the /proc scan can see (`image` given), or
    `unknown` when none is visible (another user's QEMU)."""
    kind = fcntl.F_WRLCK if exclusive else fcntl.F_RDLCK
    want = struct.pack("hhqqi", kind, os.SEEK_SET, OFD_START, OFD_LENGTH, 0)
    try:
        fcntl.fcntl(fd, fcntl.F_OFD_SETLK, want)
    except OSError as error:
        if error.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
            raise Refused("image_locked", f"a QEMU holds the image (OFD lock bytes {OFD_START}-{OFD_START + OFD_LENGTH - 1}: "
                          f"{errno.errorcode.get(error.errno, error.errno)}); holders: {holder_text(image, fd)}; "
                          "find and stop it, nothing to delete") from None
        raise


def holder_text(image, fd):
    """The holder list for an `image_locked` refusal: the same /proc scan
    as `image_in_use` (this process's own descriptor excluded), or
    `unknown` when it sees none or cannot scan."""
    if image is None:
        return "unknown"
    try:
        holders = image_holders(image, exclude_fd=fd)
    except (Refused, OSError):
        holders = []
    return ", ".join(f"pid {pid} ({name})" for pid, name in holders) if holders else "unknown (none visible to this user)"


def ofd_unlock(fd):
    fcntl.fcntl(fd, fcntl.F_OFD_SETLK, struct.pack("hhqqi", fcntl.F_UNLCK, os.SEEK_SET, OFD_START, OFD_LENGTH, 0))


def error_name(code):
    return errno.errorcode.get(code, str(code))


def image_holders(image, exclude_fd=None):
    """(pid, comm) of every process holding `image` open (/proc/*/fd by
    device and inode), this process included except for the one
    descriptor `exclude_fd` it opened itself."""
    proc = pathlib.Path("/proc")
    if not (proc / "self" / "fd").is_dir():
        raise Refused("image_in_use", f"cannot tell whether {image} is in use (no /proc)")
    want = os.stat(image)
    me = os.getpid()
    holders = []
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fds = list((entry / "fd").iterdir())
        except OSError:
            continue
        for fd in fds:
            if int(entry.name) == me and exclude_fd is not None and fd.name == str(exclude_fd):
                continue
            try:
                found = fd.stat()
            except OSError:
                continue
            if (found.st_dev, found.st_ino) == (want.st_dev, want.st_ino):
                try:
                    name = (entry / "comm").read_text().strip()
                except OSError:
                    name = "?"
                holders.append((int(entry.name), name))
                break
    return sorted(holders)


def refuse_holders(image, exclude_fd=None):
    holders = image_holders(image, exclude_fd)
    if holders:
        raise Refused("image_in_use", ", ".join(f"pid {pid} ({name})" for pid, name in holders)
                      + "; a QEMU of this machine: kill it; a tool: let it finish")


@contextlib.contextmanager
def exclusion(image, *, hold=True):
    """The act's held exclusion: the image opened and checked (F), the OFD
    range lock taken (`image_locked`), no other holder (`image_in_use`).
    With hold=False the OFD lock is released at once (a mutator's probe)."""
    fd, f = open_image(image)
    try:
        ofd_lock(fd, image=image)
        if os.environ.get("ABSD_RECOVER_FAULT") == "extra-descriptor":
            extra = os.open(image, os.O_RDONLY | os.O_CLOEXEC)
        else:
            extra = None
        try:
            refuse_holders(image, exclude_fd=fd)
        finally:
            if extra is not None:
                os.close(extra)
        if not hold:
            ofd_unlock(fd)
        yield fd, f
    finally:
        os.close(fd)


def probe_exclusion(image):
    """A mutator's OFD probe: taken and released once; `image_locked` while
    a QEMU holds the image (also one whose launcher died). Holders are the
    mutator's own business (release.py refuse_in_use where it applies)."""
    fd, _ = open_image(image)
    try:
        ofd_lock(fd, image=image)
        ofd_unlock(fd)
    finally:
        os.close(fd)


# -- the disk through the host reader (no repair) ----------------------------

def fnv1a(data):
    return guard.fnv1a(data)


def parse_ledger(data):
    if len(data) > 128:
        return None
    line, separator, padding = data.partition(b"\n")
    match = re.fullmatch(rb"absd-recovery v1 seq=(0|[1-9][0-9]*) boot=([0-9a-f]{32}) "
                         rb"streak=(0|[1-9][0-9]*) fnv=([0-9a-f]{16})", line)
    if not separator or padding.strip(b"\0") or not match:
        return None
    seq, boot, streak, check = match.groups()
    if max(int(seq), int(streak)) >= 1 << 64 or int(check, 16) != fnv1a(line.rsplit(b" fnv=", 1)[0]):
        return None
    return {"seq": int(seq), "boot": boot.decode(), "streak": int(streak)}


def fact_boot(data):
    if len(data) > 64:
        return None
    line, separator, padding = data.partition(b"\n")
    if not separator or padding.strip(b"\0"):
        return None
    match = re.fullmatch(rb"boot=([0-9a-f]{32})(?: action=([A-Za-z_]+))?", line)
    return None if match is None else (match.group(1).decode(), (match.group(2) or b"").decode())


def format_fact(boot, action=None):
    suffix = "" if action is None else " action=" + action
    return ("boot=" + boot + suffix + "\n").encode().ljust(64, b"\0")


def recovery_state(files, guard_state):
    """The guest's `recovery::read_previous` on the extracted files, with
    its refusals by name: {'previous', 'ledger', 'streak'} or Refused
    `recovery_state_refused: corrupt|lost|uninitialized_ledger` or
    `first_boot_interrupted`."""
    if "/var/state" not in files and not any(path.startswith("/var/state/") for path in files):
        if guard_state == "dirty":
            raise Refused("first_boot_interrupted", "the first start never completed (dirty guard, no ledger): "
                          "release.py install --replace")
        return {"previous": "none", "ledger": None, "streak": 0}
    initialized = "/var/state/recovery.init" in files
    raw = files.get("/var/state/recovery")
    if raw is None:
        raise Refused("recovery_state_refused", "lost")
    if len(raw) > 128:
        raise Refused("recovery_state_refused", "corrupt" if initialized else "uninitialized_ledger")
    if not initialized:
        raise Refused("recovery_state_refused", "uninitialized_ledger")
    ledger = parse_ledger(raw)
    if ledger is None:
        raise Refused("recovery_state_refused", "corrupt")
    boot = ledger["boot"]

    def matches(name):
        found = fact_boot(files.get(f"/var/state/facts/served-{name}", b""))
        return found is not None and found[0] == boot

    ready = matches("ready")
    stopped = matches("stopped")
    bounded_end = files.get("/var/state/facts/served-completed") == format_fact(boot, "bounded")
    ended = stopped and (bounded_end or (matches("end") and matches("completed")))
    if ended:
        return {"previous": "ended", "ledger": ledger, "streak": 0}
    if ready:
        return {"previous": "failed", "ledger": ledger, "streak": ledger["streak"] + 1}
    return {"previous": "not_ready", "ledger": ledger, "streak": ledger["streak"]}


def read_disk(image):
    """Everything the independent host reader establishes about `image`
    without repairing anything: the selected committed state (digest and
    every structural check), every file's bytes (every referenced block
    read), the guard, the slot's fixed allocation and bytes, the recovery
    state, the selected release and a summary. Refused
    `host_reader_refused: <check>` when the reader refuses."""
    image = pathlib.Path(image)
    try:
        region = absd_fs.fs_region(image, image_sectors(image))
        if region is None:
            raise Refused("host_reader_refused", "no device layout (not an ABSD disk)")
        selected = absd_fs.select(region)
        if selected is None:
            raise Refused("host_reader_refused", "unformatted filesystem region")
        if selected.get("format") != 2:
            raise Refused("host_reader_refused", f"filesystem format {selected.get('format')}; this release reads format 2")
        records = absd_fs.tree(region, selected)
        files = {path: absd_fs.content(region, selected, record) for path, record in records.items()
                 if not record["dir"]}
        # The selected superblock's image digest: what Fs::image_digest names.
        slot_index = selected["seq"] % 2
        digest = absd_fs.superblock(region.read(slot_index), slot_index, selected["geometry"])["digest"].hex()
    except absd_fs.Refused as error:
        raise Refused("host_reader_refused", str(error)) from None
    guard_record = records.get(guard.PATH)
    guard_state = None
    # As the guest reads it (write_guard::read): a file of exactly one
    # sector that is not read-only; anything else is a corrupt guard.
    if (guard_record is not None and not guard_record["dir"] and not guard_record["readonly"]
            and guard_record["size"] == SECTOR):
        guard_state = guard.parse(files[guard.PATH])
    slot = None
    slot_record = records.get(guard.RESUME_PATH)
    if slot_record is not None:
        if (slot_record["dir"] or slot_record["readonly"] or slot_record["size"] != SECTOR
                or len(slot_record["blocks"]) != 1):
            slot = {"shape": "invalid"}
        else:
            offset = (region.first + selected["geometry"]["data_first"]
                      + slot_record["blocks"][0] * absd_fs.SECTORS_PER_BLOCK) * SECTOR
            slot = {"shape": "ok", "identity": (slot_record["serial"], tuple(slot_record["blocks"]), offset),
                    "offset": offset, "bytes": files[guard.RESUME_PATH],
                    "parsed": guard.parse_resume(files[guard.RESUME_PATH])}
    selected_release = None
    data = files.get("/absd/selected")
    if data is not None and data.endswith(b"\n"):
        selected_release = data[:-1].decode(errors="replace")
    newest = sorted(((record.get("mtime") or 0, path) for path, record in records.items()
                     if path.startswith("/home/operator/") and not record["dir"]), reverse=True)[:5]
    return {"fs_id": selected["fs_id"], "seq": selected["seq"], "image": digest,
            "files": files, "records": records, "guard": guard_state, "guard_missing": guard_record is None,
            "slot": slot, "selected": selected_release, "file_count": len(files),
            "newest": [(path, mtime) for mtime, path in newest]}


def fsync_image(fd):
    """The image's fsync, with the qualification hook that makes the real
    syscall-error path run (`fsync-fail`: an EIO as the kernel reports it)."""
    if os.environ.get("ABSD_RECOVER_FAULT") == "fsync-fail":
        raise OSError(errno.EIO, "Input/output error (ABSD_RECOVER_FAULT=fsync-fail)")
    os.fsync(fd)


def masked_hash(fd, slot_offset):
    """Hm: SHA-256 of the image with the slot's 512-byte sector zeroed."""
    digest = hashlib.sha256()
    chunk = 1 << 20
    at = 0
    while True:
        data = os.pread(fd, chunk, at)
        if not data:
            break
        if at <= slot_offset < at + len(data):
            inside = slot_offset - at
            data = data[:inside] + bytes(SECTOR) + data[inside + SECTOR:]
        digest.update(data)
        at += len(data)
    return digest.hexdigest()


def slot_state(image):
    """What the slot holds, for the mutators' recovery_pending check:
    ('missing' | 'none' | 'record' | 'corrupt', record or None)."""
    disk = read_disk(image)
    slot = disk["slot"]
    if slot is None:
        return "missing", None
    if slot["shape"] != "ok" or slot["parsed"] is None:
        return "corrupt", None
    if slot["parsed"] == "none":
        return "none", None
    return "record", slot["parsed"]


# -- host records under OUT/recovery/ ----------------------------------------

def recovery_dir(out):
    return pathlib.Path(out) / RECOVERY


HEX32 = r"[0-9a-f]{32}"
HEX64 = r"[0-9a-f]{64}"


def is_u64(value):
    return type(value) is int and 0 <= value < 1 << 64


def is_text(value, nonempty=False):
    return isinstance(value, str) and (value.strip() != "" or not nonempty)


def valid_authorization(fields):
    """The complete schema of an intent or active record: every field the
    act writes, with its type, value and cross-field consistency (the
    planned sector is a record naming exactly the recorded state fields).
    Anything else is a malformed record: the corrupt-receipt row."""
    if not isinstance(fields, dict):
        return False
    if not (is_text(fields.get("id")) and re.fullmatch(HEX32, fields["id"])):
        return False
    if not is_text(fields.get("time"), nonempty=True):
        return False
    f = fields.get("f")
    if not (isinstance(f, list) and len(f) == 3 and all(type(part) is int and part >= 0 for part in f)):
        return False
    if not (is_text(fields.get("hm")) and re.fullmatch(HEX64, fields["hm"])):
        return False
    if not (is_text(fields.get("image")) and re.fullmatch(HEX64, fields["image"])):
        return False
    if not (is_text(fields.get("ledger_boot")) and re.fullmatch(HEX32, fields["ledger_boot"])):
        return False
    if not all(is_u64(fields.get(name)) for name in ("fs_id", "fs_seq", "ledger_seq")):
        return False
    if fields.get("previous") not in guard.RESUME_PREVIOUS:
        return False
    if not is_text(fields.get("reason"), nonempty=True):
        return False
    if not all(is_text(fields.get(name)) for name in ("user", "tool", "platform")):
        return False
    for name in ("release", "target"):
        if name in fields and not is_text(fields[name]):
            return False
    if fields.get("attest_sole_instance") is not True or fields.get("accept_committed_state") is not True:
        return False
    planned = fields.get("planned")
    if not (is_text(planned) and re.fullmatch(r"[0-9a-f]{%d}" % (2 * SECTOR), planned)):
        return False
    record = guard.parse_resume(bytes.fromhex(planned))
    if not isinstance(record, dict):
        return False
    if (record["id"], record["fs"], record["seq"], record["image"], record["ledger_seq"], record["ledger_boot"],
            record["previous"]) != (fields["id"], fields["fs_id"], fields["fs_seq"], fields["image"],
                                    fields["ledger_seq"], fields["ledger_boot"], fields["previous"]):
        return False
    return True


def parse_record_file(path, table):
    """The flat table `table` of a record file, validated against the
    full schema, or None when it does not parse, lacks a field or holds a
    value outside the schema (the corrupt-receipt row)."""
    try:
        doc = tomllib.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    fields = doc.get(table)
    if not isinstance(fields, dict):
        return None
    if table in ("intent", "active"):
        if not valid_authorization(fields):
            return None
        if table == "active":
            if fields.get("state") not in ("authorized", "launched"):
                return None
            if "launches" in fields and not (type(fields["launches"]) is int and fields["launches"] >= 0):
                return None
            if fields["state"] == "launched" and not (type(fields.get("launch_pid")) is int
                                                      and is_text(fields.get("launch_console"), nonempty=True)
                                                      and is_text(fields.get("launch_time"), nonempty=True)):
                return None
        return fields
    if table == "archive":
        if not (is_text(fields.get("id")) and re.fullmatch(HEX32, fields["id"])):
            return None
        if fields.get("kind") not in ARCHIVE_KINDS or not is_text(fields.get("time"), nonempty=True):
            return None
        return fields
    return None


def read_records(out):
    """The record files: parsed intents by id, the active record (a dict,
    None, or 'unparsable'), archives, unparsable intent files, temp
    files, and quarantined files."""
    directory = recovery_dir(out)
    found = {"intents": {}, "active": None, "archives": [], "unparsable": [], "temps": [], "quarantined": []}
    if not directory.is_dir():
        return found
    for path in sorted(directory.iterdir()):
        name = path.name
        if name == LOCK:
            continue
        if name.endswith(".tmp"):
            found["temps"].append(path)
            continue
        if name == ACTIVE:
            fields = parse_record_file(path, "active")
            found["active"] = fields if fields is not None else "unparsable"
            if fields is None:
                found["unparsable"].append(path)
            continue
        match = re.fullmatch(r"intent-([0-9a-f]{32})\.toml", name)
        if match:
            fields = parse_record_file(path, "intent")
            if fields is None or fields["id"] != match.group(1):
                found["unparsable"].append(path)
            else:
                found["intents"][fields["id"]] = fields
            continue
        match = re.fullmatch(r"(consumed|revoked|stale|superseded)-([0-9a-f]{32})\.toml", name)
        if match:
            fields = parse_record_file(path, "archive")
            found["archives"].append({"kind": match.group(1), "id": match.group(2), "path": path,
                                      "time": (fields or {}).get("time", ""), "fields": fields})
            continue
        if re.fullmatch(r"corrupt-.*\.toml", name):
            found["quarantined"].append(path)
    return found


def current_transaction(records):
    """T: the newest unsuperseded record. An archive supersedes the intent
    and any active record with its own id, and nothing else."""
    archived = {archive["id"] for archive in records["archives"]}
    active = records["active"]
    if isinstance(active, dict) and active["id"] not in archived:
        return "active", active
    candidates = [intent for intent in records["intents"].values() if intent["id"] not in archived]
    if candidates:
        newest = max(candidates, key=lambda intent: (str(intent["time"]), intent["id"]))
        return "intent", newest
    return "none", None


# -- the decision table ------------------------------------------------------

ROWS = {0: "identity-unreadable", 1: "slot-unreadable", 2: "corrupt-slot", 3: "corrupt-receipt",
        4: "retirement-incomplete", 5: "record-unreceipted", 6: "authorized-unpublished", 7: "mismatch",
        8: "authorized", 9: "mismatch", 10: "consumed-pending", 11: "replaced", 12: "intent-only",
        13: "stale-intent", 14: "none"}
ACTIONS = {"identity-unreadable": "make OUT/absd-operator.img one regular local file, then --status",
           "slot-unreadable": "restore a backup (restore --replace, after --revoke if a record exists) or extract read-only",
           "corrupt-slot": "--revoke --reason \"...\", then recover",
           "corrupt-receipt": "slot none: nothing authorized (the file was quarantined), boot; slot holds a record: --revoke, then recover",
           "retirement-incomplete": "none",
           "record-unreceipted": "--revoke --reason \"...\", then recover",
           "authorized-unpublished": "--status finalizes; on record_unverified: --revoke, recover",
           "mismatch": "--revoke, then decide whether to recover",
           "authorized": "boot (Terminal A); or --revoke if you changed your mind; every other tool refuses until then",
           "launched": "a launch happened and the record is still unconsumed: boot again",
           "consumed-pending": "none",
           "replaced": "--revoke (archive revoked-<id> reason=image_replaced), then decide whether to recover on the file now in place",
           "intent-only": "nothing was written: run recover again",
           "stale-intent": "none; recover if recovery of the new file is wanted",
           "none": "recover"}


# The operator path for each refusal `recoverable_state` raises
# (docs/OPERATOR-RUNBOOK.md, refusals table); rows 12 and 14 hold no record.
REFUSAL_ACTIONS = {"guard_corrupt": "restore a backup or extract read-only",
                   "first_boot_interrupted": "release.py install --replace",
                   "previous_not_recoverable": "restore a backup or extract read-only",
                   "recovery_state_refused": "nothing repairs: release.py restore --target OUT BACKUP --replace "
                                             "with a backup, or extract read-only"}


def recoverable_state(disk):
    """`recover`'s refusals on the disk itself, in the act's order, for the
    rows it acts on (12 and 14): the history it would recover, or Refused."""
    if disk["guard_missing"]:
        raise Refused("guard_missing", "the image has no writable guard; it predates the fence")
    if disk["guard"] is None:
        raise Refused("guard_corrupt", "the writable guard is malformed")
    if disk["guard"] in ("fresh", "clean"):
        raise Refused("not_unclean", f"guard {disk['guard']}: no recovery needed; boot")
    state = recovery_state(disk["files"], disk["guard"])
    if state["previous"] not in ("failed", "not_ready"):
        raise Refused("previous_not_recoverable", f"previous={state['previous']} with a dirty guard is not a "
                      "history this act covers; restore a backup or extract read-only")
    return state


def action_of(final, disk):
    """The printed action for the reduced row. On rows 12 and 14 the table
    says `recover`, but `act` acts only when `recoverable_state` passes;
    otherwise the action is the path for the refusal it would raise, never
    `recover`."""
    if final.row in (12, 14) and disk is not None:
        try:
            recoverable_state(disk)
        except Refused as refusal:
            if refusal.reason == "not_unclean":
                return f"guard {disk['guard']}: no recovery needed; boot"
            if refusal.reason in REFUSAL_ACTIONS:
                return f"{refusal.reason}: {REFUSAL_ACTIONS[refusal.reason]}"
            return str(refusal)
    return ACTIONS.get(final.state, ACTIONS.get(final.name, "none"))


class Decision:
    """One evaluation of the table: the first matching row, its launcher
    disposition, the reconciliation it performs, and the row the state
    reduces to once that reconciliation is done (`final`)."""

    def __init__(self, row, name, launch, reason, actions, state=None, transaction=None):
        self.row, self.name, self.launch, self.reason = row, name, launch, reason
        self.actions = actions          # [(kind, payload)] in order
        self.state = state or name      # authorized | launched for row 8
        self.transaction = transaction  # (kind, record)
        self.final = self               # the decision after reconciliation
        self.chain = [self]

    def __repr__(self):
        return f"Decision(row={self.row}, name={self.name}, launch={self.launch}, reason={self.reason!r})"


def probe_of(out, image, *, hm=True, image_fd=None):
    """What the table is evaluated over: F, the slot, Hm (only when a record
    is present and hm is wanted) and the records."""
    out = pathlib.Path(out)
    probe = {"f": identity_of(image), "slot": ("unreadable", "identity"), "hm": None, "records": read_records(out),
             "disk": None}
    if probe["f"] is None:
        return probe
    try:
        disk = read_disk(image)
    except Refused as error:
        probe["slot"] = ("unreadable", str(error))
        return probe
    probe["disk"] = disk
    slot = disk["slot"]
    if slot is None:
        probe["slot"] = ("unreadable", "resume_slot_missing: image built before this release")
    elif slot["shape"] != "ok" or slot["parsed"] is None:
        probe["slot"] = ("corrupt", slot.get("bytes"))
    elif slot["parsed"] == "none":
        probe["slot"] = ("none", slot["bytes"])
    else:
        probe["slot"] = ("record", slot["bytes"], slot["parsed"])
        if hm:
            fd = image_fd if image_fd is not None else os.open(image, os.O_RDONLY | os.O_CLOEXEC)
            try:
                probe["hm"] = masked_hash(fd, slot["offset"])
            finally:
                if image_fd is None:
                    os.close(fd)
    return probe


def classify(probe):
    """DESIGN-v5 2.6, top to bottom, first match wins; one function. Rows
    0-3 are preconditions evaluated before T. Reconciliation rows (3 with
    slot none, 4, 6, 10, 13) name their actions and continue on a reduced
    copy of the records, so the returned decision's `final` is the row the
    state ends in and `chain` lists every row matched on the way."""
    f, slot, hm, records = probe["f"], probe["slot"], probe["hm"], probe["records"]
    if f is None:
        return Decision(0, ROWS[0], False, "identity_unreadable", [])
    if slot[0] == "unreadable":
        return Decision(1, ROWS[1], False, f"host_reader_refused: {slot[1]}", [])
    if slot[0] == "corrupt":
        return Decision(2, ROWS[2], False, "resume_slot_corrupt", [])
    if records["unparsable"]:
        if slot[0] == "none":
            reduced = dict(records, unparsable=[], active=None if records["active"] == "unparsable" else records["active"])
            decision = Decision(3, ROWS[3], False, "corrupt_receipt", [("quarantine", list(records["unparsable"]))])
            return continue_with(decision, dict(probe, records=reduced))
        return Decision(3, ROWS[3], False, "corrupt_receipt", [])
    archived = {archive["id"] for archive in records["archives"]}
    active = records["active"]
    if isinstance(active, dict) and active["id"] in archived:
        decision = Decision(4, ROWS[4], False, "retirement_completed", [("remove-active", active)])
        return continue_with(decision, dict(probe, records=dict(records, active=None)))
    kind, record = current_transaction(records)
    archives = records["archives"]
    if slot[0] == "record":
        bytes_hex = slot[1].hex()
        if kind == "none":
            return Decision(5, ROWS[5], False, "record_unreceipted", [], transaction=(kind, record))
        causes = []
        if f != tuple(record["f"]):
            causes.append("F")
        if hm is not None and hm != record["hm"]:
            causes.append("hm")
        if bytes_hex != record["planned"]:
            causes.append("bytes")
        if kind == "intent":
            if not causes:
                decision = Decision(6, ROWS[6], False, "finalize", [("finalize", record)], transaction=(kind, record))
                published = dict(record, state="authorized")
                return continue_with(decision, dict(probe, records=dict(records, active=published)))
            return Decision(7, ROWS[7], False, f"recovery_image_changed ({','.join(causes)})", [],
                            transaction=(kind, record))
        if not causes:
            return Decision(8, record["state"], True, record["state"], [], state=record["state"],
                            transaction=(kind, record))
        return Decision(9, ROWS[9], False, f"recovery_image_changed ({','.join(causes)})", [],
                        transaction=(kind, record))
    # slot none
    if kind == "active":
        if f == tuple(record["f"]):
            decision = Decision(10, ROWS[10], False, "retire", [("retire", record)], transaction=(kind, record))
            archive = {"kind": "consumed", "id": record["id"], "time": now(), "path": None, "fields": None}
            return continue_with(decision, dict(probe, records=dict(records, active=None, archives=archives + [archive])))
        return Decision(11, ROWS[11], False,
                        f"recovery_image_replaced F={identity_text(tuple(record['f']))}->{identity_text(f)}", [],
                        transaction=(kind, record))
    if kind == "intent":
        if f == tuple(record["f"]):
            return Decision(12, ROWS[12], True, "intent_only", [], transaction=(kind, record))
        decision = Decision(13, ROWS[13], False, "stale_intent", [("stale", record)], transaction=(kind, record))
        archive = {"kind": "stale", "id": record["id"], "time": now(), "path": None, "fields": None}
        return continue_with(decision, dict(probe, records=dict(records, archives=archives + [archive])))
    return Decision(14, ROWS[14], True, "none", [], transaction=(kind, record))


def continue_with(decision, probe):
    rest = classify(probe)
    decision.final = rest.final
    decision.chain = [decision] + rest.chain
    return decision


# Archives of one second sort by what they say about the current act: a
# superseded or stale intent precedes the revocation or consumption of the
# act that replaced it.
ARCHIVE_RANK = {"superseded": 0, "stale": 1, "revoked": 2, "consumed": 3}


def archive_order(archive):
    return (str(archive["time"]), ARCHIVE_RANK.get(archive["kind"], 0), archive["id"])


def status_line(decision, records, observed=None):
    """`state=<row> last=<newest archive> history=<n>`; `state` is the
    reconciled state once reconciliation ran, else the observed row (a
    deferred reconciliation names the predicted state as `pending=`)."""
    archives = sorted(records["archives"], key=archive_order)
    last = archives[-1] if archives else None
    last_text = "none" if last is None else f"{last['kind']} {last['id']} {last['time'] or '?'}"
    if last is not None and last["kind"] == "consumed" and last["fields"] is not None:
        last_text += " witness=" + ("yes" if last["fields"].get("witness") else "no")
    deferred = getattr(decision, "deferred", False)
    reconciled = getattr(decision, "reconciled", False)
    failed = getattr(decision, "failed", False)
    state = decision.chain[0].state if (deferred or failed) else decision.final.state
    text = f"state={state} last={last_text} history={len(archives)}"
    if observed is not None and (reconciled or deferred) and observed.name != state:
        text += f" observed={observed.name}"
    if failed:
        text += f" reconciliation=failed reason={decision.failure.reason}"
    elif deferred:
        text += f" pending={decision.final.state} reconciliation=deferred"
    elif reconciled:
        text += " reconciliation=done"
    if len(decision.chain) > 1 and not (deferred or failed):
        text += " matched=" + "/".join(step.name for step in decision.chain[:-1])
    return text


# -- reconciliation side effects (under the recovery lock) -------------------

def refusal_of(decision):
    """The Refused a terminal row names."""
    final = decision.final
    word = final.reason.split(" ")[0].rstrip(":")
    return Refused(word, f"state={final.state}; {final.reason}")


def current_active_id(out):
    """The id active.toml holds now (parsed), or None."""
    path = recovery_dir(out) / ACTIVE
    if not path.is_file():
        return None
    fields = parse_record_file(path, "active")
    return fields["id"] if fields is not None else None


def remove_active_if(out, ident):
    """Removes active.toml only while it still holds `ident`: an action
    computed under the lock never removes a record another command
    published meanwhile."""
    if current_active_id(out) == ident:
        remove_published(recovery_dir(out) / ACTIVE)
        return True
    return False


def apply(decision, out, image, console=None, log=print, fd=None):
    """Performs the reconciliation of every row in the chain, in order:
    quarantine (3), remove active (4), finalize (6), retire (10), stale
    archive (13). The decision must have been computed under the recovery
    lock; every action still revalidates the file it touches. Returns the
    words it printed."""
    said = []
    for step in decision.chain:
        for kind, payload in step.actions:
            if kind == "quarantine":
                stamp = now().replace(":", "")
                for index, path in enumerate(payload):
                    table = "active" if path.name == ACTIVE else "intent"
                    if not path.is_file() or parse_record_file(path, table) is not None:
                        continue  # gone, or valid again: not ours to move
                    moved = path.with_name(f"corrupt-{stamp}-{index}-{path.name}")
                    os.replace(path, moved)
                    fsync_dir(path.parent)
                    said.append(f"quarantined {path.name} -> {moved.name}")
            elif kind == "remove-active":
                if remove_active_if(out, payload["id"]):
                    said.append(f"retirement_completed id={payload['id']}")
            elif kind == "finalize":
                finalize(payload, out, image, log, fd=fd)
                said.append(f"finalized id={payload['id']}")
            elif kind == "retire":
                retire(payload, out, console, log)
                said.append(f"retired id={payload['id']}")
            elif kind == "stale":
                archive = dict(payload, kind="stale", disposition="stale_intent", time=now(),
                               new_f=list(identity_of(image) or ()), f=list(payload["f"]))
                publish(recovery_dir(out) / f"stale-{payload['id']}.toml", toml_dump({"archive": archive}))
                said.append(f"stale id={payload['id']}")
    for word in said:
        log(f"reconciliation: {word}")
    return said


def finalize(intent, out, image, log, fd=None):
    """Row 6: under the locks, F equals the intent's, the slot bytes equal
    the planned bytes exactly, Hm equals the intent's, then fsync and a
    second readback; then active.toml and the receipt. Any failed check is
    record_unverified: no publication. `fd` is the caller's held exclusion
    (the act, precheck, the exit path); --status takes its own."""
    held = contextlib.nullcontext((fd, file_identity(os.fstat(fd)))) if fd is not None else exclusion(image)
    with held as (fd, f):
        if f != tuple(intent["f"]):
            raise Refused("record_unverified", f"F {identity_text(f)} is not the intent's {identity_text(tuple(intent['f']))}")
        disk = read_disk(image)
        slot = disk["slot"]
        if slot is None or slot["shape"] != "ok":
            raise Refused("record_unverified", "the slot is not readable")
        if os.pread(fd, SECTOR, slot["offset"]).hex() != intent["planned"]:
            raise Refused("record_unverified", "the slot bytes are not the planned record")
        if masked_hash(fd, slot["offset"]) != intent["hm"]:
            raise Refused("record_unverified", "the masked image hash differs from the intent's")
        try:
            fsync_image(fd)
            readback = os.pread(fd, SECTOR, slot["offset"])
        except OSError as error:
            raise Refused("record_unverified", f"{error.strerror} during the durability check") from None
        if readback.hex() != intent["planned"]:
            raise Refused("record_unverified", "the slot bytes changed after the flush")
        active = dict(intent, state="authorized", finalized=now())
        publish(recovery_dir(out) / ACTIVE, toml_dump({"active": active}))
        write_receipt(out, "recover", intent["id"], {"recover": dict(active, event="finalized")})
        ledger_append(out, "recovered", intent.get("release", "none"),
                      f"id={intent['id']} previous={intent['previous']} finalized")
        log(f"RECOVERY AUTHORIZED id={intent['id']} target={intent.get('target', 'none')} previous={intent['previous']} "
            f"fs_seq={intent['fs_seq']} hm={intent['hm']} (finalized)")


def witness_of(console, ident):
    """The RECOVERY WRITABLE RESUMED line for `ident` in the latest boot
    of `console`, or None."""
    if console is None:
        return None
    try:
        raw = pathlib.Path(console).read_bytes()
    except OSError:
        return None
    latest = raw.rsplit(BOOT_LINE, 1)[-1].decode(errors="replace")
    match = re.search(rf"(?m)^{re.escape(READY_LINE)} id={re.escape(ident)} .*$", latest)
    return match.group(0) if match else None


def retire(active, out, console, log):
    """Row 10, idempotent and ordered: (a) the consumed archive (atomic
    publication), (b) active.toml removed, (c) the receipt and ledger line.
    Interrupted after (a), row 4 completes it; during (a), row 10 runs
    again; after (b), the receipt is reconciled."""
    directory = recovery_dir(out)
    witness = witness_of(console, active["id"])
    archive = dict(active, kind="consumed", disposition="consumed" if witness else "consumed_unwitnessed",
                   witness=witness or "", time=now(), f=list(active["f"]))
    path = directory / f"consumed-{active['id']}.toml"
    if not path.is_file():
        if os.environ.get("ABSD_RECOVER_FAULT") == "retire-temp-only":
            temp = path.with_name(path.name + ".tmp")
            temp.write_text(toml_dump({"archive": archive}))
            raise Fault("retire-temp-only")
        publish(path, toml_dump({"archive": archive}))
    fault("retire-after-archive")
    remove_active_if(out, active["id"])
    fault("retire-after-remove")
    write_receipt(out, "consumed", active["id"], {"consumed": dict(archive, event="consumed")})
    fault("retire-after-receipt")
    ledger_append(out, "consumed", active.get("release", "none"),
                  f"id={active['id']} witness={'yes' if witness else 'no'}")
    log(f"RECOVERY CONSUMED id={active['id']} witness={'yes' if witness else 'no'}")


def has_receipt(out, kind, ident):
    directory = pathlib.Path(out) / "receipts"
    return directory.is_dir() and any(directory.glob(f"{kind}-{ident}-*.toml"))


def has_ledger_line(out, action, ident):
    path = pathlib.Path(out) / LEDGER
    if not path.is_file():
        return False
    return re.search(rf"(?m)^\S+ {re.escape(action)} \S+ id={re.escape(ident)}(?: |$)", path.read_text()) is not None


def reconcile_derived(out, records, log):
    """The derived events (receipts and ledger lines) owed by the durable
    intent/active/archive evidence, each written when missing, independently
    of the others and of whether active.toml still exists: an active or a
    consumed archive owes the authorization receipt and `recovered` line; a
    consumed archive owes the consumption receipt and `consumed` line; a
    revoked archive owes the revoke receipt and `revoked` line. Under the
    recovery lock."""
    done = []
    owed = []
    active = records["active"]
    if isinstance(active, dict):
        owed.append(("authorized", active))
    for archive in records["archives"]:
        fields = archive["fields"]
        if fields is None:
            continue
        if archive["kind"] == "consumed":
            owed.append(("authorized", fields))
            owed.append(("consumed", fields))
        elif archive["kind"] == "revoked":
            if fields.get("published") is True:
                owed.append(("authorized", fields))
            owed.append(("revoked", fields))
    for event, record in owed:
        ident = record["id"]
        release_id = record.get("release", "none")
        if event == "authorized":
            if not has_receipt(out, "recover", ident):
                write_receipt(out, "recover", ident, {"recover": dict(record, event="authorized", reconciled=True)})
                done.append(f"receipt recover {ident}")
            if not has_ledger_line(out, "recovered", ident):
                ledger_append(out, "recovered", release_id,
                              f"id={ident} previous={record.get('previous', '?')} reconciled")
                done.append(f"ledger recovered {ident}")
        elif event == "consumed":
            witness = "yes" if record.get("witness") else "no"
            if not has_receipt(out, "consumed", ident):
                write_receipt(out, "consumed", ident, {"consumed": dict(record, event="consumed", reconciled=True)})
                done.append(f"receipt consumed {ident}")
            if not has_ledger_line(out, "consumed", ident):
                ledger_append(out, "consumed", release_id, f"id={ident} witness={witness} reconciled")
                done.append(f"ledger consumed {ident}")
        else:
            disposition = record.get("disposition", "revoked")
            if not has_receipt(out, "revoke", ident):
                write_receipt(out, "revoke", ident, {"revoke": dict(record, event="revoked", reconciled=True)})
                done.append(f"receipt revoke {ident}")
            if not has_ledger_line(out, "revoked", ident):
                ledger_append(out, "revoked", release_id, f"id={ident} disposition={disposition} reconciled")
                done.append(f"ledger revoked {ident}")
    for word in done:
        log(f"reconciliation: {word}")
    return done


def derived_missing(out, records):
    """Whether reconcile_derived would write anything (read-only check)."""
    active = records["active"]
    if isinstance(active, dict) and not (has_receipt(out, "recover", active["id"])
                                         and has_ledger_line(out, "recovered", active["id"])):
        return True
    for archive in records["archives"]:
        if archive["fields"] is None:
            continue
        ident = archive["id"]
        if archive["kind"] == "consumed" and not (has_receipt(out, "recover", ident) and has_ledger_line(out, "recovered", ident)
                                                  and has_receipt(out, "consumed", ident) and has_ledger_line(out, "consumed", ident)):
            return True
        if archive["kind"] == "revoked" and not (has_receipt(out, "revoke", ident) and has_ledger_line(out, "revoked", ident)):
            return True
        if (archive["kind"] == "revoked" and archive["fields"].get("published") is True
                and not (has_receipt(out, "recover", ident) and has_ledger_line(out, "recovered", ident))):
            return True
    return False


def write_receipt(out, name, ident, data):
    directory = pathlib.Path(out) / "receipts"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}-{ident}-{now().replace(':', '')}.toml"
    publish(path, toml_dump(data))
    return path


def ledger_append(out, action, release_id, detail=""):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / LEDGER, "a", encoding="utf-8") as handle:
        handle.write(f"{now()} {action} {release_id} {detail}".rstrip() + "\n")
        handle.flush()
        os.fsync(handle.fileno())


# -- the commands -------------------------------------------------------------

def summary(disk, state):
    newest = ",".join(f"{path}@{mtime}" for path, mtime in disk["newest"]) or "none"
    ledger = state["ledger"] or {}
    return (f"previous={state['previous']} boot={ledger.get('boot', 'none')} ledger_seq={ledger.get('seq', 0)} "
            f"streak={state['streak']} release={disk['selected'] or 'none'} files={disk['file_count']} newest={newest}")


CAVEAT = ("caveat: synced files exact; a file being overwritten may hold a mix of old and new sectors; "
          "growth lost (FILESYSTEM.md)")


def platform_commit():
    try:
        return subprocess.run(["git", "-C", str(here.parent), "rev-parse", "HEAD"], check=True, capture_output=True,
                              text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def act(out, *, attest_sole_instance, accept_committed_state, reason, target_identity=None, log=print):
    """The act, DESIGN-v5 2.6: (1) every check, no write; (2) intent; (3)
    one 512-byte pwrite of R at the slot (identity verified, current bytes
    none), fsync, readback; (4) Hm recomputed; (5) active.toml
    state=authorized; (6) receipt and ledger line."""
    out = pathlib.Path(out).resolve()
    image = out / IMAGE
    if not (attest_sole_instance and accept_committed_state):
        raise Refused("attestation_required", "give --attest-sole-instance and --accept-committed-state only if both "
                      "statements are true")
    if not reason or not reason.strip():
        raise Refused("attestation_required", "--reason TEXT is required")
    with recovery_lock(out), exclusion(image) as (fd, f):
        decision, probe = reconcile_under_lock(out, image, out / "console.log", log, fd=fd)
        if decision.failure is not None:
            raise decision.failure
        if decision.final.row == 8:
            raise Refused("recovery_pending", f"authorization {decision.final.transaction[1]['id']} is on the disk; "
                          "boot it or run recover --revoke")
        if decision.final.row not in (12, 14):
            raise refusal_of(decision)
        disk = probe["disk"]
        state = recoverable_state(disk)
        slot = disk["slot"]
        log(summary(disk, state))
        log(CAVEAT)
        ident = uuid.uuid4().hex
        when = int(time.time())
        record = {"id": ident, "fs": disk["fs_id"], "seq": disk["seq"], "image": disk["image"],
                  "ledger_seq": state["ledger"]["seq"], "ledger_boot": state["ledger"]["boot"],
                  "previous": state["previous"], "time": when}
        planned = guard.encode_resume(record)
        hm = masked_hash(fd, slot["offset"])
        intent = {"id": ident, "time": now(), "f": list(f), "hm": hm, "planned": planned.hex(),
                  "fs_id": disk["fs_id"], "fs_seq": disk["seq"], "image": disk["image"],
                  "ledger_seq": state["ledger"]["seq"], "ledger_boot": state["ledger"]["boot"],
                  "previous": state["previous"], "streak": state["streak"], "release": disk["selected"] or "none",
                  "target": target_identity or read_target(out), "attest_sole_instance": True,
                  "accept_committed_state": True, "reason": reason, "user": os.environ.get("USER", str(os.getuid())),
                  "tool": "scripts/release.py recover", "platform": platform_commit(),
                  "slot_identity": [str(part) for part in slot["identity"]]}
        # A previous unsuperseded intent (row 12) is superseded by this act.
        kind, previous_record = decision.final.transaction
        if kind == "intent":
            archive = dict(previous_record, kind="superseded", disposition="superseded", time=now(), superseded_by=ident,
                           f=list(previous_record["f"]))
            publish(recovery_dir(out) / f"superseded-{previous_record['id']}.toml", toml_dump({"archive": archive}))
        publish(recovery_dir(out) / f"intent-{ident}.toml", toml_dump({"intent": intent}))
        fault("after-intent")
        # (3) the one sector write, identity rechecked immediately before it.
        named = os.lstat(image)
        if (named.st_dev, named.st_ino) != (f[0], f[1]):
            raise Refused("image_replaced", "the pathname changed under the tool; nothing was written")
        current = os.pread(fd, SECTOR, slot["offset"])
        if current != guard.RESUME_NONE:
            raise Refused("slot_changed", "the slot no longer holds none; nothing was written")
        short = os.environ.get("ABSD_RECOVER_FAULT", "")
        if short.startswith("short-write:"):
            count = int(short.split(":", 1)[1])
            os.pwrite(fd, planned[:count], slot["offset"])
            raise Fault(short)
        try:
            written = os.pwrite(fd, planned, slot["offset"])
        except OSError as error:
            raise Refused("slot_write_failed", f"pwrite: {error.strerror}; nothing published; --status reports "
                          "intent-only or the row the landed bytes make") from None
        if written != SECTOR:
            raise Refused("slot_write_short", "incomplete sector write")
        fault("after-pwrite")
        try:
            fsync_image(fd)
            readback = os.pread(fd, SECTOR, slot["offset"])
        except OSError as error:
            raise Refused("authorization_unverified", f"{error.strerror} after the slot write; --status will "
                          "finalize or report intent-only per the readback") from None
        if readback != planned:
            raise Refused("authorization_unverified", "the slot readback differs from the planned record")
        fault("after-slot")
        # (4) the content commitment holds.
        if masked_hash(fd, slot["offset"]) != hm:
            raise Refused("authorization_unverified", "the masked image hash changed during the act")
        # (5) publication of the authorization.
        active = dict(intent, state="authorized")
        publish(recovery_dir(out) / ACTIVE, toml_dump({"active": active}))
        fault("after-active")
        # (6) receipt and ledger line.
        write_receipt(out, "recover", ident, {"recover": dict(active, event="authorized")})
        fault("after-receipt")
        ledger_append(out, "recovered", intent["release"], f"id={ident} previous={state['previous']}")
        log(f"RECOVERY AUTHORIZED id={ident} target={intent['target']} previous={state['previous']} "
            f"fs_seq={disk['seq']} hm={hm}")
        return intent


def read_target(out):
    path = pathlib.Path(out) / "TARGET"
    return path.read_text().strip() if path.is_file() else "none"


def reconcile_under_lock(out, image, console, log, fd=None):
    """Re-probes and reclassifies under the recovery lock (which the
    caller holds), applies the rows' reconciliation to that fresh view,
    writes the owed derived events, and returns the final classification.
    A reconciliation that fails (for example finalization's
    `record_unverified`) is recorded on the returned decision as
    `failure`: the classification of the unchanged state then still
    *predicts* a later row, which no caller may treat as reached."""
    probe = probe_of(out, image, image_fd=fd)
    decision = classify(probe)
    failure = None
    if any(step.actions for step in decision.chain):
        try:
            apply(decision, out, image, console=console, log=log, fd=fd)
        except Refused as error:
            failure = error
            log(f"reconciliation refused: {error}")
    if failure is None:
        reconcile_derived(out, read_records(out), log)
    probe = probe_of(out, image, image_fd=fd)
    after = classify(probe)
    after.failure = failure
    return after, probe


def status(out, *, reconcile=True, log=print, console=None, before_lock=None):
    """`--status`: observes without any lock; takes the recovery lock only
    to write a reconciliation, re-probes and reclassifies under it before
    any side effect, and defers when a running boot-operator.sh holds the
    lock. Prints `state=` (the observed row, or the reconciled state once
    reconciliation ran), the summary and the action. `before_lock` is a
    qualification hook run between the observation and the lock."""
    out = pathlib.Path(out).resolve()
    image = out / IMAGE
    probe = probe_of(out, image)
    decision = classify(probe)
    observed = decision.chain[0]
    decision.reconciled = False
    decision.deferred = False
    needs = any(step.actions for step in decision.chain) or derived_missing(out, probe["records"])
    if reconcile and needs:
        if before_lock is not None:
            before_lock()
        fd = try_recovery_lock(out)
        if fd is None:
            decision.deferred = True
            log("reconciliation deferred: tool_busy")
        else:
            try:
                after, probe = reconcile_under_lock(out, image, console or (out / "console.log"), log)
                if after.failure is not None:
                    # Unresolved: the state is the one now on disk, never
                    # the predicted row, and never reconciliation=done.
                    decision = after
                    decision.failed = True
                    decision.reconciled = False
                    decision.deferred = False
                else:
                    decision.final = after.final
                    decision.reconciled = True
            finally:
                os.close(fd)
    records = probe["records"]
    log(status_line(decision, records, observed=observed))
    if probe["disk"] is not None:
        try:
            state = recovery_state(probe["disk"]["files"], probe["disk"]["guard"])
            log(summary(probe["disk"], state) + f" guard={probe['disk']['guard']}")
            log(CAVEAT)
        except Refused as error:
            log(str(error))
    final = decision.chain[0] if getattr(decision, "failed", False) else decision.final
    if getattr(decision, "failed", False):
        log(f"refusal: {decision.failure}")
    elif final.row in (7, 9, 11, 1, 2):
        log(f"refusal: {final.reason}")
    log(f"action: {action_of(final, probe['disk'])}")
    for archive in sorted(records["archives"], key=archive_order):
        log(f"history: {archive['kind']} {archive['id']} {archive['time'] or '?'}")
    for ident, intent in sorted(records["intents"].items()):
        log(f"intent: {ident} {intent['time']} previous={intent['previous']}")
    return decision


def revoke(out, *, reason, log=print):
    """`--revoke`: rewrites `none` at the slot (a record or a corrupt
    sector) and archives `revoked-<id>` for the current transaction, under
    the locks and with no other holder."""
    out = pathlib.Path(out).resolve()
    image = out / IMAGE
    if not reason or not reason.strip():
        raise Refused("attestation_required", "--reason TEXT is required")
    with recovery_lock(out), exclusion(image) as (fd, f):
        probe = probe_of(out, image, image_fd=fd)
        decision = classify(probe)
        if decision.row in (0, 1):
            raise refusal_of(decision)
        kind, record = current_transaction(probe["records"])
        slot_kind = probe["slot"][0]
        if slot_kind == "none" and kind == "none" and not probe["records"]["unparsable"]:
            raise Refused("nothing_to_revoke", "the slot holds none and no authorization is current")
        disk = probe["disk"]
        slot = disk["slot"] if disk is not None else None
        rewritten = False
        if slot_kind in ("record", "corrupt"):
            if slot is None or slot["shape"] != "ok":
                raise Refused("resume_slot_corrupt", "the slot's shape is wrong; restore a backup")
            named = os.lstat(image)
            if (named.st_dev, named.st_ino) != (f[0], f[1]):
                raise Refused("image_replaced", "the pathname changed under the tool; nothing was written")
            try:
                if os.pwrite(fd, guard.RESUME_NONE, slot["offset"]) != SECTOR:
                    raise Refused("slot_write_short", "incomplete sector write")
                fsync_image(fd)
                readback = os.pread(fd, SECTOR, slot["offset"])
            except OSError as error:
                raise Refused("revoke_unverified", f"{error.strerror} while rewriting none; run --revoke again") from None
            if readback != guard.RESUME_NONE:
                raise Refused("revoke_unverified", "the slot readback is not none")
            rewritten = True
        directory = recovery_dir(out)
        for path in probe["records"]["unparsable"]:
            stamp = now().replace(":", "")
            moved = path.with_name(f"corrupt-{stamp}-{path.name}")
            os.replace(path, moved)
            fsync_dir(path.parent)
        ident = record["id"] if record is not None else "none"
        disposition = "revoked"
        if decision.final.row == 11:
            disposition = "image_replaced"
        elif decision.row == 2:
            disposition = "revoked_corrupt"
        if record is not None:
            # `published`: whether the revoked transaction was a published
            # authorization (active.toml), which owes its own receipt and
            # `recovered` line, or an intent revoked before publication.
            archive = dict(record, kind="revoked", disposition=disposition, reason_revoked=reason, time=now(),
                           f=list(record["f"]), new_f=list(f), slot_rewritten=rewritten,
                           published=(kind == "active"))
            publish(directory / f"revoked-{ident}.toml", toml_dump({"archive": archive}))
        if isinstance(probe["records"]["active"], dict):
            remove_published(directory / ACTIVE)
        write_receipt(out, "revoke", ident, {"revoke": {"id": ident, "time": now(), "reason": reason,
                                                        "disposition": disposition, "slot_rewritten": rewritten,
                                                        "f": list(f)}})
        ledger_append(out, "revoked", (record or {}).get("release", "none"), f"id={ident} disposition={disposition}")
        log(f"RECOVERY REVOKED id={ident} disposition={disposition} slot={'none' if rewritten else 'unchanged'}")
        return ident


def precheck(out, *, console=None, log=print):
    """boot-operator.sh's precheck, under the launcher's recovery lock:
    opens the image, takes the exclusive OFD range lock, evaluates the
    table (performing its reconciliations), releases the lock. Exit 0 to
    launch, 7 to refuse (the reason printed)."""
    out = pathlib.Path(out).resolve()
    image = out / IMAGE
    try:
        with exclusion(image) as (fd, f):
            decision, probe = reconcile_under_lock(out, image, console, log, fd=fd)
            if decision.failure is not None:
                # The original reason; the predicted row is not reached.
                decision.reconciled, decision.failed = False, True
                log(f"precheck: {status_line(decision, probe['records'])}")
                raise decision.failure
    except Refused as error:
        if error.reason in ("image_not_regular", "image_linked", "image_size", "image_unreadable", "image_not_local"):
            log(f"precheck: state=identity-unreadable refusal=identity_unreadable ({error})")
        else:
            log(f"precheck: refusal={error}")
        return 7
    final = decision.final
    log(f"precheck: {status_line(decision, probe['records'])}")
    if not final.launch:
        log(f"precheck: refusal={final.reason}")
        log(f"precheck: action: {action_of(final, probe['disk'])}")
        return 7
    if final.row == 8:
        log(f"precheck: authorization id={final.transaction[1]['id']} state={final.state}")
    return 0


def launched(out, *, ident, pid, console, log=print):
    """`launched`, written by boot-operator.sh only after the process
    exists: active.toml state=launched with the launch facts."""
    out = pathlib.Path(out).resolve()
    records = read_records(out)
    active = records["active"]
    if not isinstance(active, dict) or active["id"] != ident:
        log(f"launched: no active record for id={ident}; nothing recorded")
        return 1
    launches = int(active.get("launches", 0)) + 1
    # launch_epoch: the same instant with sub-second precision, the common
    # clock readiness timings are measured against.
    active = {key: value for key, value in active.items() if key not in ("last_launch", "last_launch_status")}
    active = dict(active, state="launched", launch_pid=int(pid), launch_time=now(),
                  launch_epoch=f"{time.time():.3f}", launch_console=str(console), launches=launches)
    fault("launched-fail")
    publish(recovery_dir(out) / ACTIVE, toml_dump({"active": active}))
    log(f"boot-operator: launched id={ident} pid={pid} console={console}")
    return 0


def active_id(out):
    """The current authorization's id (active.toml, unsuperseded), or None."""
    kind, record = current_transaction(read_records(out))
    return record["id"] if kind == "active" else None


# exit_path's status for a correctly classified launch that never booted
# (record back to `authorized`), distinct from 1 (classification failed).
LAUNCH_FAILED = 6


def exit_path(out, *, status_word, console, log=print):
    """boot-operator.sh's exit path: no ABSD KERNEL BOOT in this launch's
    console is launch_failed (active back to authorized); otherwise the
    table is re-evaluated (retiring a consumed record with this console
    as witness, keeping an intact R as launched, or reporting replaced)."""
    out = pathlib.Path(out).resolve()
    image = out / IMAGE
    try:
        raw = pathlib.Path(console).read_bytes()
    except OSError:
        raw = b""
    records = read_records(out)
    active = records["active"]
    if BOOT_LINE not in raw:
        if isinstance(active, dict) and active.get("state") == "launched":
            # Back to authorized; the failed launch stays named in the
            # record, so --wait-ready can report it instead of "no launch".
            publish(recovery_dir(out) / ACTIVE, toml_dump({"active": dict(
                active, state="authorized", last_launch="launch_failed", last_launch_status=str(status_word))}))
        log(f"boot-operator: launch_failed status={status_word} (no ABSD KERNEL BOOT in {console}); the authorization is intact")
        # LAUNCH_FAILED: classified, not a bookkeeping failure (boot-operator.sh).
        return LAUNCH_FAILED if isinstance(active, dict) else 0
    try:
        with exclusion(image) as (fd, f):
            decision, probe = reconcile_under_lock(out, image, console, log, fd=fd)
            if decision.failure is not None:
                raise decision.failure
    except Refused as error:
        log(f"boot-operator: exit classification refused: {error}")
        return 1
    log(f"boot-operator: exit {status_line(decision, probe['records'])}")
    return 0


def captured(raw):
    """The worker's output stream from a serial capture (ssh_absd.captured)."""
    data = bytearray()
    for match in re.finditer(rb"EXTERNAL OUTPUT CHUNK offset=([0-9a-f]+) data=([0-9a-f]*)\n", raw):
        if int(match.group(1), 16) != len(data):
            break
        data.extend(bytes.fromhex(match.group(2).decode()))
    return data.decode(errors="replace")


def latest_boot(raw):
    """The latest ABSD KERNEL BOOT segment of a console, or None."""
    if BOOT_LINE not in raw:
        return None
    return BOOT_LINE + raw.rsplit(BOOT_LINE, 1)[-1]


def listener_position(segment):
    """The byte offset in `segment` of the worker chunk that completes the
    listener record (`SSH LISTENING` in the reconstructed worker stream),
    or None: the third readiness record's position among the serial lines."""
    data = bytearray()
    for match in re.finditer(rb"EXTERNAL OUTPUT CHUNK offset=([0-9a-f]+) data=([0-9a-f]*)\n", segment):
        if int(match.group(1), 16) != len(data):
            return None
        data.extend(bytes.fromhex(match.group(2).decode()))
        if re.search(rb"(?m)^SSH LISTENING .*$", data):
            return match.start()
    return None


def readiness(segment, ident):
    """Predicate W over one boot segment: the three readiness records,
    RESUMED (with the id) then RELEASE OK then the listener, in that order
    → ('ready', positions); a refusal or boot end → ('ended', line);
    otherwise (None, None) (still booting)."""
    resumed = re.search(rb"(?m)^" + re.escape(READY_LINE.encode()) + rb" id=" + re.escape(ident.encode())
                        + rb" previous=\S+ fs_seq=\d+ ledger_seq=\d+$", segment)
    release = re.search(rb"(?m)^RELEASE OK release=\S+$", segment)
    listener = listener_position(segment)
    if resumed and release and listener is not None and resumed.start() < release.start() < listener:
        return "ready", (resumed.start(), release.start(), listener)
    text = segment.decode(errors="replace")
    for line in text.splitlines():
        if any(line.startswith(word) for word in END_LINES):
            if line.startswith("MACHINE ") and not any(w in line for w in ("RESET", "STOP", "HALT", "RESTART")):
                continue
            return "ended", line
    return None, None


def wait_ready(out, *, ident, timeout=WAIT_TIMEOUT, log=print, clock=None, sleep=None):
    """`--wait-ready --id ID --timeout S`: reads the launched record,
    observes only the console it names (created after the launch time),
    binds all three readiness records to the latest ABSD KERNEL BOOT
    segment, then the receive-setup/liveness check; exit 0 READY, 7 with
    the refusal or boot-end line, 124 on timeout."""
    clock = time.monotonic if clock is None else clock
    sleep = time.sleep if sleep is None else sleep
    out = pathlib.Path(out).resolve()
    records = read_records(out)
    active = records["active"]
    if not isinstance(active, dict) or active["id"] != ident:
        archives = [a for a in records["archives"] if a["id"] == ident]
        if archives:
            log(f"wait-ready: id={ident} is {archives[-1]['kind']}; nothing to wait for")
        else:
            log(f"wait-ready: no active record for id={ident}")
        return 7
    if active.get("state") == "authorized" and active.get("last_launch") == "launch_failed":
        log(f"wait-ready: id={ident} launch_failed status={active.get('last_launch_status', '?')}: the last launch "
            f"(pid {active.get('launch_pid', '?')}, {active.get('launch_time', '?')}) ended without ABSD KERNEL BOOT in "
            f"{active.get('launch_console', '?')}; the authorization is intact; fix the cause and boot again")
        return 7
    if active.get("state") != "launched" or not active.get("launch_console"):
        log(f"wait-ready: id={ident} state={active.get('state')}: no launch recorded; start boot-operator.sh first")
        return 7
    console = pathlib.Path(active["launch_console"])
    pid = int(active.get("launch_pid", 0))
    launch_time = active.get("launch_time", "")
    started = clock()
    deadline = started + timeout

    def running():
        if pid <= 0:
            return True
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        try:
            with open(f"/proc/{pid}/stat") as handle:
                return handle.read().split(")")[-1].split()[0] != "Z"
        except OSError:
            return True

    try:
        launch_epoch = float(active["launch_epoch"]) if "launch_epoch" in active else (
            datetime.datetime.strptime(launch_time, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=datetime.timezone.utc).timestamp())
    except ValueError:
        launch_epoch = 0

    def read_console():
        try:
            st = console.stat()
            if st.st_ctime + 1 < launch_epoch:
                return b""  # a console older than the launch is not this launch's
            return console.read_bytes()
        except FileNotFoundError:
            return b""

    while True:
        raw = read_console()
        segment = latest_boot(raw) if raw else None
        if segment is not None:
            word, line = readiness(segment, ident)
            if word == "ready":
                # The observation, the receive setup and the success are
                # bound to this one boot generation: the segment count and
                # the segment's readiness are re-read after the setup.
                generation = raw.count(BOOT_LINE)
                try:
                    wait_rx_setup(read_console, running, deadline, clock=clock, sleep=sleep)
                except RxSetupFailed as error:
                    log(f"wait-ready: {error}")
                    # A reset the helper saw, or a process that is gone, is
                    # a refusal of the earlier readiness; only the deadline is 124.
                    return 124 if running() and "deadline" in str(error) else 7
                again = read_console()
                if again.count(BOOT_LINE) != generation:
                    log(f"wait-ready: the machine reset during the receive setup (boot {generation} -> "
                        f"{again.count(BOOT_LINE)}); the earlier readiness is refused; run --status")
                    return 7
                latest = latest_boot(again)
                if latest is None or readiness(latest, ident)[0] != "ready" or not latest.startswith(segment):
                    log("wait-ready: the readiness records changed during the receive setup; refused")
                    return 7
                elapsed = clock() - started
                log(f"READY id={ident} console={console} launched={launch_time} after={elapsed:.1f}s")
                return 0
            if word == "ended":
                log(f"wait-ready: the boot ended before readiness: {line}")
                return 7
        if not running():
            if segment is None:
                log(f"wait-ready: launch_failed (no ABSD KERNEL BOOT in {console}); the process is gone")
            else:
                log(f"wait-ready: the process ended before readiness (console {console})")
            return 7
        if clock() >= deadline:
            log(f"wait-ready: no readiness within {timeout}s; do not SSH; run --status")
            return 124
        sleep(0.5)


# -- the mutators' entry -------------------------------------------------------

def refuse_pending(out, image, *, replacing=False):
    """Every mutator: refuses recovery_pending whenever the slot holds a
    record or an unsuperseded active.toml exists; an unsuperseded intent
    alone does not block. A corrupt slot refuses too (only --revoke
    rewrites it). A replacing mutator (install --replace, restore
    --replace, migrate) tolerates an image the reader cannot read."""
    records = read_records(out)
    kind, record = current_transaction(records)
    if kind == "active":
        raise Refused("recovery_pending", f"authorization {record['id']} is on the disk; boot it or run recover --revoke")
    if not pathlib.Path(image).exists():
        return
    try:
        state, record = slot_state(image)
    except Refused:
        if replacing:
            return
        raise
    if state == "record":
        raise Refused("recovery_pending", f"authorization {record['id']} is on the disk; boot it or run recover --revoke")
    if state == "corrupt":
        raise Refused("resume_slot_corrupt", "the resume slot is corrupt: recover --revoke, then decide")


@contextlib.contextmanager
def mutation(out, image, *, replacing=False, probe=True):
    """The hand-off boundary: the recovery lock for the command's
    duration (tool_busy), the OFD probe taken and released once
    (image_locked), recovery_pending refused."""
    with recovery_lock(out):
        if probe and pathlib.Path(image).exists():
            probe_exclusion(image)
        refuse_pending(out, image, replacing=replacing)
        yield


def pending_id(out, image):
    """The id a backup labels: the current authorization's, or 'none'."""
    records = read_records(out)
    kind, record = current_transaction(records)
    if kind == "active":
        return record["id"]
    try:
        state, found = slot_state(image)
    except Refused:
        return "unknown"
    return found["id"] if state == "record" else "none"


# -- command line ----------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("act"); p.add_argument("out")
    p.add_argument("--attest-sole-instance", action="store_true")
    p.add_argument("--accept-committed-state", action="store_true")
    p.add_argument("--reason", default="")
    p = sub.add_parser("status"); p.add_argument("out"); p.add_argument("--no-reconcile", action="store_true")
    p = sub.add_parser("revoke"); p.add_argument("out"); p.add_argument("--reason", default="")
    p = sub.add_parser("wait-ready"); p.add_argument("out"); p.add_argument("--id", required=True)
    p.add_argument("--timeout", type=float, default=WAIT_TIMEOUT)
    p = sub.add_parser("precheck"); p.add_argument("out"); p.add_argument("--console")
    p = sub.add_parser("launched"); p.add_argument("out"); p.add_argument("--id", required=True)
    p.add_argument("--pid", required=True, type=int); p.add_argument("--console", required=True)
    p = sub.add_parser("exit"); p.add_argument("out"); p.add_argument("--status", required=True)
    p.add_argument("--console", required=True)
    p = sub.add_parser("active-id"); p.add_argument("out")
    args = parser.parse_args(argv)
    try:
        if args.command == "act":
            act(args.out, attest_sole_instance=args.attest_sole_instance,
                accept_committed_state=args.accept_committed_state, reason=args.reason)
            return 0
        if args.command == "status":
            status(args.out, reconcile=not args.no_reconcile)
            return 0
        if args.command == "revoke":
            revoke(args.out, reason=args.reason)
            return 0
        if args.command == "wait-ready":
            return wait_ready(args.out, ident=args.id, timeout=args.timeout)
        if args.command == "precheck":
            return precheck(args.out, console=args.console)
        if args.command == "launched":
            return launched(args.out, ident=args.id, pid=args.pid, console=args.console)
        if args.command == "exit":
            return exit_path(args.out, status_word=args.status, console=args.console)
        if args.command == "active-id":
            ident = active_id(args.out)
            if ident is None:
                return 1
            print(ident)
            return 0
    except Refused as error:
        print(f"recover: refused: {error}", file=sys.stderr)
        return 1
    except Fault as error:
        print(f"recover: fault hook {error} fired; stopped as a crash would", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
