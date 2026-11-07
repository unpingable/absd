#!/usr/bin/env python3
"""The first ABSD disk installer (coordination record #123 step 5): one GPT disk with
an EFI System Partition that boots the kernel and one blank 2 GiB ABSD
partition that the guest formats on its first writable mount.

    install_disk.py install --target IMAGE --kernel KERNEL.ELF --serial SERIAL
                            --receipt NEW.json [--boot-options "..."]
                            [--kernel-sha256 HEX] [--manifest FILE]
                            [--confirm-disk TOKEN]
    install_disk.py identity --target IMAGE
    install_disk.py verify  --target IMAGE [--receipt RECEIPT.json] [--outside-unchanged]

Exit 0: done. Exit 2: refused before anything was written; the target is
unchanged. Exit 3: failed after the first write; a failure receipt
(absd-disk-install-failure/1) at --receipt says what was written and how to
recover.

The target is opened once (O_NOFOLLOW), checked to be the regular file the
path names, and held under an exclusive flock. Every write goes through
that descriptor: hole punching and the ESP copy directly, sgdisk as
/dev/fd/N. Before and after every step the descriptor and the path's lstat
must still be the same object. The ESP is built by mkfs.vfat and mtools in
a private image file and copied in.

`install` writes only the head (LBA 0 to the end of the ABSD partition) and
the tail (the backup GPT's 33 sectors). It refuses a target with any
non-zero byte there or any MBR/GPT signature, unless `--confirm-disk` names
this exact disk: path, device and inode numbers, size, the SHA-256 of the
first MiB and of both install regions (`identity` prints it).

The GPT is written by sgdisk. This file only reads the table back: both
GPT copies, the protective MBR, types, GUIDs and ranges, refusing anything
but exactly this layout; it never repairs a table. Block devices are
refused in this slice (docs/INSTALL-DISK.md).
"""

import argparse
import ctypes
import datetime
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import tomllib
import uuid
import zlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import media  # noqa: E402

Refused = media.Refused
PROFILE = media.PROFILES / "disk-install.toml"
SCHEMA = "absd-disk-install-receipt/1"
FAILURE_SCHEMA = "absd-disk-install-failure/1"

SECTOR = 512
MIB = 1 << 20
ALIGN_SECTORS = MIB // SECTOR
ENTRY_COUNT = 128
ENTRY_BYTES = 128
ENTRY_SECTORS = ENTRY_COUNT * ENTRY_BYTES // SECTOR      # 32
GPT_SECTORS = 1 + ENTRY_SECTORS                           # header + entries: 33

ESP_FIRST = 2048
ESP_SECTORS = 256 * MIB // SECTOR                         # 256 MiB
ABSD_FIRST = ESP_FIRST + ESP_SECTORS                      # 526336, 1 MiB aligned
ABSD_SECTORS = 2 * 1024 * MIB // SECTOR                   # 2 GiB
ABSD_END = ABSD_FIRST + ABSD_SECTORS                      # first sector after it
# The smallest disk: the ABSD partition, then the backup GPT.
MIN_SECTORS = ABSD_END + GPT_SECTORS

ESP_TYPE = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
ABSD_TYPE = "7AF614A7-2C5B-4EBA-B8F6-217AEC90357A"
ESP_NAME = "EFI System"
ABSD_NAME = "ABSD"
FAT_LABEL = "ABSDBOOT"

SERIAL = re.compile(r"[A-Za-z0-9._-]{1,20}")
# Options the installer owns on the kernel line; the caller may not set them.
OWNED_OPTIONS = ("block-partition=", "ahci-write=", "ahci-disk=", "nvme-write=", "nvme-disk=")
DEFAULT_BOOT_OPTIONS = "durable=0 net fsd served"

for _name, _package in (("mtype", "mtools"), ("mdir", "mtools")):
    media.TOOL_PACKAGES.setdefault(_name, _package)


def load_profile():
    return tomllib.loads(PROFILE.read_text())


# -- the target --------------------------------------------------------------------

class Failed(Exception):
    """A failure after the first write to the target (exit 3)."""

    def __init__(self, step, error, target=None, write_regions=None, receipt=None, residual=None):
        super().__init__(f"step={step} {error}")
        self.step, self.error = step, str(error)
        self.target, self.write_regions, self.receipt = target, write_regions, receipt
        self.residual = residual or []


# The staging cleanup and the receipt writer's unlink, through names a test
# can replace to simulate EIO.
_rmtree = shutil.rmtree
_unlink = os.unlink


# -- reporting ------------------------------------------------------------------
#
# The outcome (exit 0, 2 or 3) is decided first; reporting never changes it.
# Every line goes through emit(), which never raises: a write or flush that
# fails (EPIPE/BrokenPipeError, any OSError, ValueError on a closed stream)
# silences that stream for the rest of the run. A real stream's descriptor
# is pointed at /dev/null (Python's documented SIGPIPE idiom), so the
# interpreter's own flush at exit cannot fail either and turn the exit
# status into 120.

def _silence(name):
    stream = getattr(sys, name)
    try:
        fd = stream.fileno()
    except (OSError, ValueError, AttributeError):
        fd = None
    try:
        null = os.open(os.devnull, os.O_WRONLY)
    except OSError:
        return
    if fd is not None:
        if null == fd:
            # The stream's descriptor was already closed, so /dev/null took its
            # number: it is now in place, and closing it would undo that.
            return
        try:
            os.dup2(null, fd)
            os.close(null)
            return
        except OSError:
            pass
    try:
        setattr(sys, name, os.fdopen(null, "w"))
    except OSError:
        os.close(null)


def emit(name, text):
    """`text` and a newline on sys.stdout or sys.stderr (`name`), flushed.
    Returns whether it was written; never raises."""
    try:
        stream = getattr(sys, name)
        stream.write(text + "\n")
        stream.flush()
        return True
    except (OSError, ValueError, AttributeError):
        _silence(name)
        return False


def final_flush():
    """Flushes both streams once more before exit, silencing one that fails."""
    for name in ("stdout", "stderr"):
        try:
            getattr(sys, name).flush()
        except (OSError, ValueError, AttributeError):
            _silence(name)


def cleanup(label, action):
    """Runs a cleanup action (closing the target, removing staging) without
    letting its error replace the install's outcome: a failure is reported
    as its own `INSTALL CLEANUP FAILED` line and the exit status stays what
    the install decided."""
    try:
        action()
    except OSError as error:
        emit("stderr", f"INSTALL CLEANUP FAILED {label} error={error}")


# Tests set this to a function(phase, path) to act between phases.
_HOOK = None


def phase(name, path):
    if _HOOK is not None:
        _HOOK(name, path)


def regions(size):
    """The byte ranges install may write, for a target of `size` bytes."""
    return [(0, ABSD_END * SECTOR), (size - GPT_SECTORS * SECTOR, size)]


def unallocated(size):
    """The byte range between the ABSD partition and the backup GPT."""
    return (ABSD_END * SECTOR, size - GPT_SECTORS * SECTOR)


def lstat_target(path):
    """The pathname's own lstat, refused unless it names a regular file of a
    usable size (never followed through a link)."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise Refused(f"target_missing {path} (create the image first, e.g. truncate -s BYTES)") from None
    if stat.S_ISLNK(st.st_mode):
        raise Refused(f"target_refused {path} is a link; name the file itself")
    if stat.S_ISBLK(st.st_mode):
        raise Refused(f"block_device_refused {path}: installing to a block device is not implemented in this slice")
    if not stat.S_ISREG(st.st_mode):
        raise Refused(f"target_refused {path} is not a regular file")
    if st.st_size % SECTOR:
        raise Refused(f"target_refused {path} is {st.st_size} bytes, not a whole number of 512-byte sectors")
    if st.st_size // SECTOR < MIN_SECTORS:
        raise Refused(f"target_too_small {path} is {st.st_size} bytes; the layout needs at least {MIN_SECTORS * SECTOR}")
    return st


class Target:
    """The validated object: opened once (O_NOFOLLOW, O_NONBLOCK so a FIFO
    swapped in cannot block), checked to be the regular file the pathname
    named, and, for writing, held under an exclusive flock for the whole
    install. Every write goes to this descriptor or to /dev/fd/N passed to
    a child, never to the pathname again."""

    def __init__(self, path, writable):
        self.path = str(path)
        st = lstat_target(self.path)
        flags = (os.O_RDWR if writable else os.O_RDONLY) | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            self.fd = os.open(self.path, flags)
        except OSError as error:
            raise Refused(f"target_refused {self.path}: {error.strerror}") from None
        fst = os.fstat(self.fd)
        if not stat.S_ISREG(fst.st_mode) or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
            os.close(self.fd)
            raise Refused(f"target_changed {self.path} was replaced while it was opened")
        try:
            fcntl.flock(self.fd, (fcntl.LOCK_EX if writable else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            raise Refused(f"target_busy {self.path} is locked by another installer") from None
        self.st = fst
        self.size = fst.st_size

    def close(self):
        os.close(self.fd)

    @property
    def fd_path(self):
        return f"/dev/fd/{self.fd}"

    def changed(self):
        """Why the descriptor or the pathname no longer is the validated
        object, or None."""
        fst = os.fstat(self.fd)
        if not stat.S_ISREG(fst.st_mode) or (fst.st_dev, fst.st_ino, fst.st_size) != \
                (self.st.st_dev, self.st.st_ino, self.st.st_size):
            return f"the open target changed (dev/ino/size {fst.st_dev}/{fst.st_ino}/{fst.st_size})"
        try:
            lst = os.lstat(self.path)
        except FileNotFoundError:
            return f"{self.path} no longer exists"
        if stat.S_ISLNK(lst.st_mode):
            return f"{self.path} is now a link"
        if (lst.st_dev, lst.st_ino) != (self.st.st_dev, self.st.st_ino):
            return f"{self.path} now names another file (dev/ino {lst.st_dev}/{lst.st_ino})"
        return None

    def run(self, *argv, env):
        """A child tool on this object as /dev/fd/N (argv's TARGET is replaced)."""
        argv = [self.fd_path if a is TARGET else str(a) for a in argv]
        done = subprocess.run(argv, pass_fds=(self.fd,), capture_output=True, text=True, env=env)
        if done.returncode != 0:
            raise Refused(f"{os.path.basename(argv[0])} exit {done.returncode}: {done.stdout.strip()} {done.stderr.strip()}")
        return done.stdout


TARGET = object()   # placeholder for the target in Target.run argv


def pread_exact(fd, offset, count):
    data = os.pread(fd, count, offset)
    if len(data) != count:
        raise Refused(f"short_read at {offset}: {len(data)} of {count} bytes")
    return data


def data_extents(fd, start, end):
    """The ranges of [start, end) that may hold data: SEEK_DATA/SEEK_HOLE on
    a sparse file, the whole range where the filesystem cannot say."""
    try:
        position = start
        while position < end:
            try:
                data = os.lseek(fd, position, os.SEEK_DATA)
            except OSError as error:
                if error.errno == errno.ENXIO:   # no data after position
                    return
                raise
            if data >= end:
                return
            hole = min(os.lseek(fd, data, os.SEEK_HOLE), end)
            yield data, hole
            position = hole
    except OSError:
        yield start, end


def first_nonzero(fd, start, end):
    """The offset of the first non-zero byte in [start, end), or None."""
    for lo, hi in data_extents(fd, start, end):
        position = lo
        while position < hi:
            block = pread_exact(fd, position, min(MIB, hi - position))
            if block.count(0) != len(block):
                return position + next(i for i, b in enumerate(block) if b)
            position += len(block)
    return None


def ranges_sha256(fd, ranges):
    """SHA-256 of the bytes of `ranges`, in order, reading only the data
    extents (holes are hashed as the zeros they read as)."""
    digest = hashlib.sha256()
    zeros = bytes(MIB)
    for start, end in ranges:
        position = start
        for lo, hi in data_extents(fd, start, end):
            while position < lo:
                take = min(MIB, lo - position)
                digest.update(zeros[:take])
                position += take
            while position < hi:
                block = pread_exact(fd, position, min(MIB, hi - position))
                digest.update(block)
                position += len(block)
        while position < end:
            take = min(MIB, end - position)
            digest.update(zeros[:take])
            position += take
    return digest.hexdigest()


def region_sha256(fd, start, end):
    return ranges_sha256(fd, [(start, end)])


def content_digest(fd, ranges):
    """A digest of the bytes of `ranges` that costs nothing for holes:
    SHA-256 over (offset, length, bytes) of every 1 MiB-aligned window
    (clipped to its range) that holds a non-zero byte. Equal bytes give an
    equal digest whether zeros are holes or written; a window of zeros is
    skipped either way."""
    digest = hashlib.sha256(b"absd-content-digest/1")
    for start, end in ranges:
        done = start
        for lo, hi in data_extents(fd, start, end):
            window = max(done, lo - lo % MIB, start)
            while window < hi:
                stop = min(window - window % MIB + MIB, end)
                block = pread_exact(fd, window, stop - window)
                if block.count(0) != len(block):
                    digest.update(struct.pack("<QQ", window, len(block)) + block)
                window = done = stop
    return digest.hexdigest()


def signatures(fd, size):
    """Partition-table signatures anywhere a 512- or 4096-byte-sector disk
    would carry one."""
    found = []
    if pread_exact(fd, 510, 2) == b"\x55\xaa":
        found.append("mbr-55aa@510")
    for offset in (512, 4096, size - 512, size - 4096):
        if pread_exact(fd, offset, 8) == b"EFI PART":
            found.append(f"gpt-header@{offset}")
    return found


IDENTITY_FIELDS = ("path", "dev", "ino", "bytes", "first_mib_sha256", "regions_sha256")


def identity(target):
    """What names this exact disk: for an image, its resolved path, the
    open file's device and inode numbers, its size in bytes, the SHA-256
    of its first MiB and the content digest of both install regions
    (everything install would erase). A device would carry its serial in place of path,
    dev and ino (not implemented)."""
    return {"kind": "image", "path": os.path.realpath(target.path), "dev": target.st.st_dev,
            "ino": target.st.st_ino, "bytes": target.size,
            "first_mib_sha256": hashlib.sha256(pread_exact(target.fd, 0, MIB)).hexdigest(),
            "regions_sha256": content_digest(target.fd, regions(target.size))}


def token(ident):
    return (f"image:path={ident['path']},dev={ident['dev']},ino={ident['ino']},bytes={ident['bytes']},"
            f"first-mib-sha256={ident['first_mib_sha256']},regions-sha256={ident['regions_sha256']}")


TOKEN_FIELDS = ("path", "dev", "ino", "bytes", "first-mib-sha256", "regions-sha256")


def parse_token(text):
    kind, sep, rest = text.partition(":")
    if not sep or kind not in ("image", "device"):
        raise Refused("confirm_malformed the token is image:" + ",".join(f"{f}=..." for f in TOKEN_FIELDS))
    fields = {}
    for part in rest.split(","):
        key, sep, value = part.partition("=")
        if not sep or key in fields:
            raise Refused(f"confirm_malformed field {part!r}")
        fields[key] = value
    if kind == "device":
        raise Refused("confirm_refused device confirmation (serial=S,bytes=N,...) is not implemented")
    if set(fields) != set(TOKEN_FIELDS):
        raise Refused(f"confirm_malformed fields {sorted(fields)}; want {', '.join(TOKEN_FIELDS)}")
    for key in ("dev", "ino", "bytes"):
        if not re.fullmatch(r"[0-9]+", fields[key]):
            raise Refused(f"confirm_malformed {key} must be decimal")
    for key in ("first-mib-sha256", "regions-sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", fields[key]):
            raise Refused(f"confirm_malformed {key} must be 64 lower-case hex digits")
    return {"path": fields["path"], "dev": int(fields["dev"]), "ino": int(fields["ino"]), "bytes": int(fields["bytes"]),
            "first_mib_sha256": fields["first-mib-sha256"], "regions_sha256": fields["regions-sha256"]}


def inspect(fd, size):
    """Why the target is not empty, as a list (empty when it is)."""
    reasons = signatures(fd, size)
    for start, end in regions(size):
        at = first_nonzero(fd, start, end)
        if at is not None:
            reasons.append(f"nonzero@{at} in [{start},{end})")
    return reasons


def check_confirmation(text, ident):
    want = parse_token(text)
    for key in IDENTITY_FIELDS:
        if want[key] != ident[key]:
            raise Refused(f"confirm_mismatch {key}: confirmation says {want[key]!r}, the target is {ident[key]!r}")


def punch_hole(fd, start, length):
    """fallocate(PUNCH_HOLE | KEEP_SIZE) on the descriptor itself."""
    libc = ctypes.CDLL(None, use_errno=True)
    fallocate = libc.fallocate
    fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int64, ctypes.c_int64]
    if fallocate(fd, 0x01 | 0x02, start, length) != 0:
        error = ctypes.get_errno()
        raise OSError(error, f"fallocate punch-hole: {os.strerror(error)}")


def zero_regions(target):
    """Zeroes the install regions of a confirmed target by punching holes
    in the open file, then checks they read as zero. Nothing outside them
    is touched."""
    for start, end in regions(target.size):
        punch_hole(target.fd, start, end - start)
    os.fsync(target.fd)
    for start, end in regions(target.size):
        if first_nonzero(target.fd, start, end) is not None:
            raise Refused(f"zeroing_failed [{start},{end}) still holds data")


# -- reading the GPT back ------------------------------------------------------------

def guid_text(raw):
    return str(uuid.UUID(bytes_le=bytes(raw))).upper()


def guid_raw(text):
    return uuid.UUID(text).bytes_le


def parse_header(sector, where):
    if sector[:8] != b"EFI PART":
        raise Refused(f"gpt_{where} no EFI PART signature")
    (rev, hsize, crc, reserved, my_lba, alt_lba, first_usable, last_usable) = struct.unpack_from("<IIIIQQQQ", sector, 8)
    disk_guid = sector[56:72]
    entries_lba, count, entry_size, entries_crc = struct.unpack_from("<QIII", sector, 72)
    if rev != 0x00010000 or hsize != 92:
        raise Refused(f"gpt_{where} revision {rev:#x} / header size {hsize}")
    check = bytearray(sector[:hsize])
    check[16:20] = b"\0\0\0\0"
    if zlib.crc32(check) != crc:
        raise Refused(f"gpt_{where} header CRC mismatch")
    if reserved or any(sector[hsize:]):
        raise Refused(f"gpt_{where} reserved bytes are not zero")
    return {"my_lba": my_lba, "alt_lba": alt_lba, "first_usable": first_usable, "last_usable": last_usable,
            "disk_guid": guid_text(disk_guid), "entries_lba": entries_lba, "count": count,
            "entry_size": entry_size, "entries_crc": entries_crc, "header_crc": crc}


def parse_entries(raw):
    used = []
    for index in range(ENTRY_COUNT):
        entry = raw[index * ENTRY_BYTES:(index + 1) * ENTRY_BYTES]
        if not any(entry[:16]):
            if any(entry):
                raise Refused(f"gpt_entries unused entry {index + 1} is not all zero")
            continue
        first, last, attributes = struct.unpack_from("<QQQ", entry, 32)
        name = entry[56:128].decode("utf-16-le").rstrip("\0")
        used.append({"number": index + 1, "type": guid_text(entry[:16]), "guid": guid_text(entry[16:32]),
                     "first_lba": first, "last_lba": last, "attributes": attributes, "name": name})
    return used


def read_back(fd, size, expect=None):
    """Both GPT copies and the protective MBR of an installed disk, checked
    against the one layout this installer makes (and, with `expect`, the
    receipt's GUIDs). Returns what it read; refuses anything else."""
    last = size // SECTOR - 1
    mbr = pread_exact(fd, 0, SECTOR)
    if mbr[510:] != b"\x55\xaa":
        raise Refused("mbr no 55AA signature")
    status, ptype = mbr[446], mbr[450]
    start, count = struct.unpack_from("<II", mbr, 454)
    if status != 0 or ptype != 0xEE or start != 1 or count != min(last, 0xFFFFFFFF):
        raise Refused(f"mbr not protective: status {status:#x} type {ptype:#x} start {start} sectors {count}")
    if any(mbr[462:510]):
        raise Refused("mbr records 2-4 are not empty")
    primary = parse_header(pread_exact(fd, SECTOR, SECTOR), "primary")
    backup = parse_header(pread_exact(fd, last * SECTOR, SECTOR), "backup")
    for name, header, my, alt, entries in (("primary", primary, 1, last, 2),
                                           ("backup", backup, last, 1, last - ENTRY_SECTORS)):
        if (header["my_lba"], header["alt_lba"], header["entries_lba"]) != (my, alt, entries):
            raise Refused(f"gpt_{name} my/alternate/entries LBA {header['my_lba']}/{header['alt_lba']}/"
                          f"{header['entries_lba']}, want {my}/{alt}/{entries}")
        if (header["count"], header["entry_size"]) != (ENTRY_COUNT, ENTRY_BYTES):
            raise Refused(f"gpt_{name} {header['count']} entries of {header['entry_size']} bytes")
        if (header["first_usable"], header["last_usable"]) != (2 + ENTRY_SECTORS, last - GPT_SECTORS):
            raise Refused(f"gpt_{name} usable range {header['first_usable']}..{header['last_usable']}")
    for field in ("disk_guid", "first_usable", "last_usable", "entries_crc", "count", "entry_size"):
        if primary[field] != backup[field]:
            raise Refused(f"gpt_copies_differ {field}: primary {primary[field]} backup {backup[field]}")
    arrays = {}
    for name, header in (("primary", primary), ("backup", backup)):
        raw = pread_exact(fd, header["entries_lba"] * SECTOR, ENTRY_COUNT * ENTRY_BYTES)
        if zlib.crc32(raw) != header["entries_crc"]:
            raise Refused(f"gpt_{name} entry array CRC mismatch")
        arrays[name] = raw
    if arrays["primary"] != arrays["backup"]:
        raise Refused("gpt_copies_differ entry arrays")
    if any(pread_exact(fd, SECTOR * 34, (ESP_FIRST - 34) * SECTOR)):
        raise Refused("gap between the primary entries and the ESP is not zero")
    used = parse_entries(arrays["primary"])
    if len(used) != 2:
        raise Refused(f"layout has {len(used)} partitions, want exactly 2")
    esp, absd = used
    wanted = [(esp, 1, ESP_TYPE, ESP_FIRST, ESP_SECTORS, ESP_NAME), (absd, 2, ABSD_TYPE, ABSD_FIRST, ABSD_SECTORS, ABSD_NAME)]
    for entry, number, type_, first, sectors, name in wanted:
        if (entry["number"], entry["type"], entry["first_lba"], entry["last_lba"], entry["attributes"], entry["name"]) != \
                (number, type_, first, first + sectors - 1, 0, name):
            raise Refused(f"partition {entry['number']} is {entry}, want number {number} type {type_} "
                          f"LBA {first}..{first + sectors - 1} name {name!r} no attributes")
    guids = [primary["disk_guid"], esp["guid"], absd["guid"]]
    if len(set(guids)) != 3 or any(uuid.UUID(g).int == 0 for g in guids):
        raise Refused(f"GUIDs not distinct and non-zero: {guids}")
    if expect is not None:
        got = {"disk": primary["disk_guid"], "esp": esp["guid"], "absd": absd["guid"]}
        for key, value in expect.items():
            if got[key] != value.upper():
                raise Refused(f"guid_mismatch {key}: disk has {got[key]}, receipt says {value}")
    return {"last_lba": last, "disk_guid": primary["disk_guid"], "primary": primary, "backup": backup,
            "partitions": used, "unallocated_lba": [ABSD_END, last - GPT_SECTORS]}


def sgdisk_verify(target, env):
    """sgdisk --verify on the open target, as /dev/fd/N."""
    done = subprocess.run([media.tool("sgdisk"), "--verify", target.fd_path], pass_fds=(target.fd,),
                          capture_output=True, text=True, env=env)
    if done.returncode != 0 or "No problems found" not in done.stdout:
        raise Refused(f"sgdisk_verify failed (exit {done.returncode}): {done.stdout.strip()} {done.stderr.strip()}")
    return done.stdout.strip()


# -- building the ESP ----------------------------------------------------------------

def check_kernel(path, pinned, env):
    path = pathlib.Path(path)
    if path.is_symlink() or not path.is_file():
        raise Refused(f"kernel_refused {path} is not a regular file")
    digest = media.sha(path)
    if pinned is not None and digest != pinned.lower():
        raise Refused(f"kernel_mismatch {path} sha256 {digest}, pinned {pinned}")
    if subprocess.run([media.tool("grub-file"), "--is-x86-multiboot2", str(path)], env=env).returncode != 0:
        raise Refused(f"kernel_refused {path} is not a multiboot2 kernel")
    return {"sha256": digest, "bytes": path.stat().st_size}


def check_options(serial, options):
    if not SERIAL.fullmatch(serial):
        raise Refused(f"serial_refused {serial!r}: 1-20 of A-Z a-z 0-9 . _ -")
    words = options.split()
    for word in words:
        if any(word.startswith(owned) for owned in OWNED_OPTIONS):
            raise Refused(f"boot_options_refused {word!r}: the installer sets the disk selection itself")
        if not re.fullmatch(r"[A-Za-z0-9._=-]+", word):
            raise Refused(f"boot_options_refused {word!r}")
    return words


def kernel_line(words, partition_guid, serial):
    return " ".join(["multiboot2", "/BOOT/KERNEL.ELF", *words, f"block-partition={partition_guid.lower()}",
                     f"ahci-write={serial}"])


def grub_config(profile, line):
    return profile["grub"]["config"].format(kernel_line=line)


def build_esp(work, profile, kernel, config, fat_uuid, volume_id, install_json, epoch, env):
    """The whole ESP as a private 256 MiB image file in `work`: GRUB loader,
    kernel, config, made by mkfs.vfat and mtools on that file (never on the
    target), dates normalised, GRUB.CFG read back. Returns the image, the
    staged files' inventory and the copy order."""
    stage_dir = work / "fat"
    for d in ("EFI/BOOT", "BOOT"):
        (stage_dir / d).mkdir(parents=True)
    shutil.copyfile(kernel, stage_dir / "BOOT/KERNEL.ELF")
    (stage_dir / "BOOT/GRUB.CFG").write_text(config)
    (stage_dir / "INSTALL.JSON").write_text(install_json)
    early = work / "early.cfg"
    early.write_text(profile["grub"]["early_cfg"].format(fat_uuid=fat_uuid))
    modules = profile["grub"]["modules"]
    subprocess.run([media.tool("grub-mkstandalone"), "-O", "x86_64-efi", "--fonts=", "--locales=", "--themes=",
                    f"--install-modules={modules}", f"--modules={modules}",
                    "-o", str(stage_dir / "EFI/BOOT/BOOTX64.EFI"), f"boot/grub/grub.cfg={early}"],
                   check=True, capture_output=True, env=env)
    for p in [stage_dir, *stage_dir.rglob("*")]:
        os.chmod(p, 0o755 if p.is_dir() else 0o644)
        os.utime(p, (epoch, epoch))
    esp = work / "esp.img"
    with open(esp, "xb") as handle:
        handle.truncate(ESP_SECTORS * SECTOR)
    # -h: the hidden-sector count is the partition's first LBA, as on the disk.
    subprocess.run([media.tool("mkfs.vfat"), "--invariant", "-F", "32", "-s", "1", "-i", volume_id, "-n", FAT_LABEL,
                    "-h", str(ESP_FIRST), str(esp), str(ESP_SECTORS // 2)], check=True, capture_output=True, env=env)
    order = media.copy_order(stage_dir, {})
    media.fat_copy(esp, 0, stage_dir, order, env)
    media.normalize_fat_dates(esp, 0, epoch)
    read_cfg = subprocess.run([media.tool("mtype"), "-i", str(esp), "::/BOOT/GRUB.CFG"],
                              capture_output=True, text=True, env=env, check=True).stdout
    if read_cfg.replace("\r\n", "\n") != config:
        raise Refused("esp_readback GRUB.CFG in the ESP image differs from the one written")
    files = {str(p.relative_to(stage_dir)): {"sha256": media.sha(p), "bytes": p.stat().st_size}
             for p in sorted(stage_dir.rglob("*")) if p.is_file()}
    return esp, files, order


def write_gpt(target, disk_guid, esp_guid, absd_guid, env):
    """Shared fixed layout for host provisioning and native-payload staging."""
    target.run(media.tool("sgdisk"), "--clear", "--set-alignment=2048", f"--disk-guid={disk_guid}",
               f"--new=1:{ESP_FIRST}:{ESP_FIRST + ESP_SECTORS - 1}", f"--typecode=1:{ESP_TYPE}",
               f"--partition-guid=1:{esp_guid}", f"--change-name=1:{ESP_NAME}",
               f"--new=2:{ABSD_FIRST}:{ABSD_END - 1}", f"--typecode=2:{ABSD_TYPE}",
               f"--partition-guid=2:{absd_guid}", f"--change-name=2:{ABSD_NAME}", TARGET, env=env)


def copy_esp(esp, target):
    """The ESP image's data extents written into the target at the ESP's
    offset through the open descriptor (the target's ESP range is zero, so
    the image's holes need no write)."""
    src = os.open(esp, os.O_RDONLY | os.O_CLOEXEC)
    try:
        for lo, hi in data_extents(src, 0, ESP_SECTORS * SECTOR):
            position = lo
            while position < hi:
                block = pread_exact(src, position, min(MIB, hi - position))
                if os.pwrite(target.fd, block, ESP_FIRST * SECTOR + position) != len(block):
                    raise OSError(errno.EIO, "short write")
                position += len(block)
        return ranges_sha256(src, [(0, ESP_SECTORS * SECTOR)])
    finally:
        os.close(src)


def outside_baseline(fd, size):
    """What `verify --outside-unchanged` compares: SHA-256 of LBA 0-2047, the
    ESP and the backup GPT, and the unallocated span, which is recorded as
    all zero (checked later by SEEK_DATA/read) or, if it held data, by its
    content digest."""
    start, end = unallocated(size)
    zero = first_nonzero(fd, start, end) is None
    return {"head_lba0_2047": region_sha256(fd, 0, ESP_FIRST * SECTOR),
            "esp": region_sha256(fd, ESP_FIRST * SECTOR, ABSD_FIRST * SECTOR),
            "backup_gpt": region_sha256(fd, size - GPT_SECTORS * SECTOR, size),
            "unallocated": {"range": [start, end], "all_zero": zero,
                            "digest": None if zero else content_digest(fd, [(start, end)])}}


RECOVERY = ("The install stopped after writing to the target. Only the install regions listed under "
            "`write_regions` can have been written; bytes outside them were not written by the installer. "
            "The target is not a valid ABSD disk and must not be booted. To retry on this exact target: "
            "`install_disk.py identity --target T` (it now reports the partial writes and a new token), then "
            "`install --confirm-disk <that token>`, which zeroes both regions and installs. An image can "
            "instead be deleted and recreated. See docs/INSTALL-DISK.md, 'Failures after the first write'.")


# Free space the receipt destination must have before the first write.
RECEIPT_RESERVE = 4 * MIB


def check_receipt_destination(path):
    """Refuses, before anything is written, a receipt path that already
    exists or whose directory is missing, not writable or nearly full."""
    path = pathlib.Path(path)
    if path.exists() or path.is_symlink():
        raise Refused(f"receipt_exists {path}")
    parent = path.parent
    if not parent.is_dir():
        raise Refused(f"receipt_refused the receipt directory {parent} does not exist")
    if not os.access(parent, os.W_OK | os.X_OK):
        raise Refused(f"receipt_refused the receipt directory {parent} is not writable")
    fs = os.statvfs(parent)
    if fs.f_bavail * fs.f_frsize < RECEIPT_RESERVE:
        raise Refused(f"receipt_refused {parent} has less than {RECEIPT_RESERVE} bytes free")


def _write_all(fd, data):
    """Writes all of `data` (the receipt writer's only write call; a test
    replaces it to simulate ENOSPC or EIO)."""
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        view = view[count:]


def write_json(path, record):
    """`record` written to a new file at `path` and synced. A file left
    half-written by a failure is removed. If that removal fails too, the
    original error is raised with `residual_receipt` set to a note naming
    the truncated file (the removal's error is secondary)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o644)
    try:
        _write_all(fd, (json.dumps(record, indent=2, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    except BaseException as error:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            _unlink(path)
        except OSError as unlink_error:
            error.residual_receipt = f"{path} (truncated, remove it; its removal failed: {unlink_error})"
        raise
    os.close(fd)


def write_failure(receipt_path, base, steps, step, error):
    """The failure receipt at the receipt path or, if that cannot be
    written, printed to stdout after an `INSTALL FAILURE RECEIPT` line.
    Returns where it went."""
    residual = [r for r in (getattr(error, "residual_receipt", None),) if r]
    record = dict(base, schema=FAILURE_SCHEMA, failed_step=step, error=str(error), steps_completed=steps,
                  recovery=RECOVERY, residual_receipt=residual)
    try:
        write_json(receipt_path, record)
        return str(receipt_path), residual
    except OSError as failure:
        extra = getattr(failure, "residual_receipt", None)
        if extra:
            residual.append(extra)
        emit("stderr", f"INSTALL FAILED could not write the failure receipt {receipt_path}: {failure}; "
                       "printing it to stdout instead")
        if emit("stdout", "INSTALL FAILURE RECEIPT\n" + json.dumps(record, indent=2, sort_keys=True)):
            return "stdout", residual
        emit("stderr", "INSTALL FAILED the failure receipt could not be printed to stdout either; "
                       "the target and its written ranges are named above")
        return "lost (stdout failed)", residual


# -- commands -----------------------------------------------------------------------

def install(args):
    profile = load_profile()
    epoch = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    env = media.clean_env(epoch)
    receipt_path = pathlib.Path(args.receipt)
    check_receipt_destination(receipt_path)
    if args.allow_block_device:
        raise Refused("block_device_refused --allow-block-device is not implemented in this slice")
    words = check_options(args.serial, args.boot_options)
    pins = media.check_pins(profile, env=env)
    kernel = check_kernel(args.kernel, args.kernel_sha256, env)
    manifest = None
    if args.manifest:
        m = pathlib.Path(args.manifest)
        if m.is_symlink() or not m.is_file():
            raise Refused(f"manifest_refused {m} is not a regular file")
        manifest = {"sha256": media.sha(m), "bytes": m.stat().st_size}
    for name in ("sgdisk", "mkfs.vfat", "mcopy", "mmd", "mtype", "grub-mkstandalone", "git", "dpkg-query"):
        media.tool(name)
    # Everything the receipt needs that could fail is collected now, before
    # the first write: the installer's revision (git), package versions,
    # sgdisk's version, the profile digest.
    installer = media.builder_identity()
    packages = [f"{n}={v}" for n, v in sorted(media.package_versions(sorted(profile["pins"]["packages"]), env).items())]
    sgdisk_version = subprocess.run([media.tool("sgdisk"), "--version"], capture_output=True, text=True,
                                    env=env, check=True).stdout.strip()
    profile_sha = media.sha(PROFILE)
    lstat_target(args.target)   # refuse a missing, linked or wrong target before building anything

    disk_guid, esp_guid, absd_guid = (str(uuid.uuid4()).upper() for _ in range(3))
    volume_id = f"{uuid.uuid4().int & 0xFFFFFFFF:08X}"
    fat_uuid = f"{volume_id[:4]}-{volume_id[4:]}"
    line = kernel_line(words, absd_guid, args.serial)
    config = grub_config(profile, line)
    install_json = json.dumps({"schema": "absd-disk-install/1", "disk_guid": disk_guid, "esp_guid": esp_guid,
                               "absd_guid": absd_guid, "absd_type": ABSD_TYPE, "serial": args.serial,
                               "kernel_sha256": kernel["sha256"], "kernel_line": line}, indent=2,
                              sort_keys=True) + "\n"
    work = pathlib.Path(tempfile.mkdtemp(prefix="absd-install-"))
    try:
        esp, files, order = build_esp(work, profile, args.kernel, config, fat_uuid, volume_id, install_json, epoch, env)
        target = Target(args.target, writable=True)
        try:
            phase("opened", args.target)
            size = target.size
            before = identity(target)
            reasons = inspect(target.fd, size)
            phase("inspected", args.target)
            # Immediately before the first write, on the locked descriptor:
            # still the same object, and (when confirming) still exactly
            # the confirmed contents.
            why = target.changed()
            if why:
                raise Refused(f"target_changed {why}; nothing was written")
            now = identity(target)
            reasons_now = inspect(target.fd, size)
            confirmed = None
            if args.confirm_disk is not None:
                check_confirmation(args.confirm_disk, now)
                confirmed = args.confirm_disk
            elif now != before or reasons_now != reasons:
                raise Refused("target_changed its contents changed during inspection; nothing was written")
            if reasons_now and confirmed is None:
                raise Refused("target_not_empty " + "; ".join(reasons_now[:6]) +
                              f" (target is {size} bytes, first MiB sha256 {now['first_mib_sha256']}; nothing was "
                              "written; overwriting needs --confirm-disk for this exact disk, docs/INSTALL-DISK.md)")
            base = {"target": {k: now[k] for k in ("kind", *IDENTITY_FIELDS)}, "write_regions": regions(size),
                    "was_empty": not reasons_now, "nonempty_reasons": reasons_now, "confirmed_overwrite": confirmed,
                    "guids": {"disk": disk_guid, "esp": esp_guid, "absd": absd_guid}, "installed_at_epoch": epoch}
            steps = []
            step = "start"
            try:
                def checked(name):
                    why = target.changed()
                    if why:
                        raise Refused(f"target_changed after {name}: {why}")
                    steps.append(name)

                if reasons_now:
                    step = "zero-regions"
                    zero_regions(target)
                    if inspect(target.fd, size):
                        raise Refused("zeroing_failed " + "; ".join(inspect(target.fd, size)))
                    checked(step)
                    step = "after-zero-regions"
                    phase(step, args.target)
                step = "gpt"
                write_gpt(target, disk_guid, esp_guid, absd_guid, env)
                checked(step)
                step = "after-gpt"
                phase(step, args.target)
                step = "esp"
                esp_sha = copy_esp(esp, target)
                os.fsync(target.fd)
                checked(step)
                step = "after-esp"
                phase(step, args.target)
                step = "readback"
                verify_text = sgdisk_verify(target, env)
                table = read_back(target.fd, size, {"disk": disk_guid, "esp": esp_guid, "absd": absd_guid})
                if first_nonzero(target.fd, ABSD_FIRST * SECTOR, ABSD_END * SECTOR) is not None:
                    raise Refused("absd_partition_not_zero after the install")
                if region_sha256(target.fd, ESP_FIRST * SECTOR, ABSD_FIRST * SECTOR) != esp_sha:
                    raise Refused("esp_readback the target's ESP differs from the ESP image written")
                boot = pread_exact(target.fd, ESP_FIRST * SECTOR, SECTOR)
                if boot[510:] != b"\x55\xaa" or boot[82:90] != b"FAT32   " or \
                        struct.unpack_from("<I", boot, 67)[0] != int(volume_id, 16):
                    raise Refused("esp_readback the ESP boot sector is not the FAT32 volume written")
                outside = outside_baseline(target.fd, size)
                checked(step)
                step = "receipt"
                receipt = {
                    "schema": SCHEMA, "installed_at_epoch": epoch, "installer": installer,
                    "profile_sha256": profile_sha,
                    "target": {"kind": now["kind"], "path": now["path"], "dev": now["dev"], "ino": now["ino"],
                               "bytes": size, "sectors": size // SECTOR, "was_empty": not reasons_now,
                               "nonempty_reasons": reasons_now, "confirmed_overwrite": confirmed,
                               "first_mib_sha256_before": now["first_mib_sha256"],
                               "regions_sha256_before": now["regions_sha256"]},
                    "inputs": {"kernel": kernel, "serial": args.serial, "boot_options": args.boot_options,
                               "manifest": manifest},
                    "guids": {"disk": disk_guid, "esp": esp_guid, "absd": absd_guid},
                    "types": {"esp": ESP_TYPE, "absd": ABSD_TYPE},
                    "layout": {"sector_bytes": SECTOR,
                               "esp": {"number": 1, "first_lba": ESP_FIRST, "sectors": ESP_SECTORS,
                                       "offset": ESP_FIRST * SECTOR, "bytes": ESP_SECTORS * SECTOR},
                               "absd": {"number": 2, "first_lba": ABSD_FIRST, "sectors": ABSD_SECTORS,
                                        "offset": ABSD_FIRST * SECTOR, "bytes": ABSD_SECTORS * SECTOR, "zero": True},
                               "unallocated_lba": table["unallocated_lba"],
                               "backup_gpt_lba": [size // SECTOR - GPT_SECTORS, size // SECTOR - 1],
                               "write_regions": regions(size)},
                    "esp": {"fat_volume_id": volume_id, "fat_uuid": fat_uuid, "label": FAT_LABEL, "files": files,
                            "copy_order": order, "image_sha256": esp_sha},
                    "grub": {"kernel_line": line, "config": config, "modules": profile["grub"]["modules"]},
                    "outside": outside, "steps": steps + ["receipt"],
                    "readback": {"sgdisk_verify": verify_text, "primary": table["primary"], "backup": table["backup"],
                                 "partitions": table["partitions"]},
                    "pins_checked": pins, "packages": packages, "sgdisk_version": sgdisk_version,
                    "tools": media.tools_used(), "environment": env,
                }
                write_json(receipt_path, receipt)
            except Exception as error:   # noqa: BLE001 - every failure after a write must be exit 3
                if not steps and step in ("start", "zero-regions", "gpt") and \
                        isinstance(error, (Refused, OSError, subprocess.SubprocessError)) and \
                        not _wrote_anything(target, before, reasons_now):
                    raise Refused(f"{error}; nothing was written") from None
                # Name the target and what was written first, before any
                # attempt at a receipt file or stdout.
                emit("stderr", f"INSTALL FAILED step={step} {error}; target {now['path']} was written, only in "
                               f"byte ranges {regions(size)}; it is not a valid ABSD disk")
                where, residual = write_failure(receipt_path, base, steps, step, error)
                raise Failed(step, error, target=now["path"], write_regions=regions(size), receipt=where,
                             residual=residual) from None
        finally:
            cleanup(f"target-fd={args.target}", target.close)
    finally:
        cleanup(f"staging={work}", lambda: _rmtree(work))
    # Exit 0 was decided when the receipt was synced; this line is best effort.
    emit("stdout", f"INSTALL OK disk_guid={disk_guid} absd_guid={absd_guid} serial={args.serial} "
                   f"bytes={size} esp_sha256={outside['esp']} receipt={receipt_path}")


def _wrote_anything(target, before, reasons):
    """After a failure in the first write step: whether the target's install
    regions differ from what was inspected (if not, the failure is still a
    pre-write refusal)."""
    try:
        return content_digest(target.fd, regions(target.size)) != before["regions_sha256"]
    except (Refused, OSError):
        return True


def verify(args):
    env = media.clean_env(0)
    receipt = json.loads(pathlib.Path(args.receipt).read_text()) if args.receipt else None
    if receipt is not None and receipt.get("schema") != SCHEMA:
        raise Refused(f"receipt_schema {receipt.get('schema')!r}")
    target = Target(args.target, writable=False)
    try:
        fd, size = target.fd, target.size
        if receipt is not None and receipt["target"]["bytes"] != size:
            raise Refused(f"size_mismatch target {size}, receipt {receipt['target']['bytes']}")
        table = read_back(fd, size, receipt["guids"] if receipt else None)
        text = sgdisk_verify(target, env)
        result = {"disk_guid": table["disk_guid"], "absd_guid": table["partitions"][1]["guid"]}
        if args.outside_unchanged:
            if receipt is None:
                raise Refused("--outside-unchanged needs --receipt")
            want = receipt["outside"]
            for name, (start, end) in (("head_lba0_2047", (0, ESP_FIRST * SECTOR)),
                                       ("esp", (ESP_FIRST * SECTOR, ABSD_FIRST * SECTOR)),
                                       ("backup_gpt", (size - GPT_SECTORS * SECTOR, size))):
                got = region_sha256(fd, start, end)
                if got != want[name]:
                    raise Refused(f"region_changed {name}: {got}, receipt {want[name]}")
            start, end = unallocated(size)
            if [start, end] != want["unallocated"]["range"]:
                raise Refused(f"region_changed unallocated range {[start, end]}, receipt {want['unallocated']['range']}")
            if want["unallocated"]["all_zero"]:
                at = first_nonzero(fd, start, end)
                if at is not None:
                    raise Refused(f"region_changed unallocated: non-zero byte at {at}, receipt says all zero")
            elif content_digest(fd, [(start, end)]) != want["unallocated"]["digest"]:
                raise Refused("region_changed unallocated: its content digest differs from the receipt's")
            result["outside_absd"] = "unchanged"
    finally:
        cleanup(f"target-fd={args.target}", target.close)
    emit("stdout", "VERIFY OK " + " ".join(f"{k}={v}" for k, v in result.items()) + f" sgdisk={text.splitlines()[-1]!r}")


def show_identity(args):
    target = Target(args.target, writable=False)
    try:
        ident = identity(target)
        reasons = inspect(target.fd, target.size)
    finally:
        cleanup(f"target-fd={args.target}", target.close)
    emit("stdout", json.dumps({"identity": {k: ident[k] for k in ("kind", *IDENTITY_FIELDS)},
                               "empty": not reasons, "nonempty_reasons": reasons, "confirm_token": token(ident)},
                              indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("install")
    p.add_argument("--target", required=True)
    p.add_argument("--kernel", required=True)
    p.add_argument("--serial", required=True)
    p.add_argument("--receipt", required=True)
    p.add_argument("--boot-options", default=DEFAULT_BOOT_OPTIONS)
    p.add_argument("--kernel-sha256")
    p.add_argument("--manifest")
    p.add_argument("--confirm-disk")
    p.add_argument("--allow-block-device", action="store_true", help="not implemented; refused")
    p.set_defaults(func=install)
    p = sub.add_parser("identity")
    p.add_argument("--target", required=True)
    p.set_defaults(func=show_identity)
    p = sub.add_parser("verify")
    p.add_argument("--target", required=True)
    p.add_argument("--receipt")
    p.add_argument("--outside-unchanged", action="store_true")
    p.set_defaults(func=verify)
    args = parser.parse_args(argv)
    # Disposition first, reporting second: the exit status is fixed before
    # any line is emitted, and emitting cannot change it.
    try:
        args.func(args)
        code, report = 0, []
    except Refused as error:
        code, report = 2, [f"INSTALL REFUSED {error}"]
    except Failed as error:
        code = 3
        report = [f"INSTALL FAILED step={error.step}: failure receipt: {error.receipt}; target {error.target}, "
                  f"written byte ranges {error.write_regions}; recovery: docs/INSTALL-DISK.md "
                  "'Failures after the first write'"]
        report += [f"INSTALL FAILED residual_receipt: {note}" for note in error.residual]
    for line in report:
        emit("stderr", line)
    final_flush()
    return code


def cli(argv=None):
    """main() with the streams flushed through the emitter's rules."""
    code = main(argv)
    final_flush()
    return code


def finish(code):
    """Ends the process with exactly `code`. The streams were already flushed
    (best effort, never raising); os._exit then skips the interpreter's own
    exit-time flush, which could otherwise fail (EPIPE, or EBADF when no
    /dev/null could be opened to silence a broken stream) and turn the
    status into 120. Nothing is left to run at exit: the target is closed,
    staging is removed and any receipt is fsynced before this point."""
    try:
        final_flush()
    except BaseException:
        pass
    os._exit(code)


def run(argv=None):
    finish(cli(argv))


if __name__ == "__main__":
    run()
