"""Pinned clean recovery points for the existing host release tool.

The caller retains the metadata digest independently. This supplies integrity
against that pin, not release signatures or authority to resume an old image.
Only the captured immutable bytes are eligible for replacement construction.
"""

import hashlib
import os
import pathlib
import re
import stat
import struct
import tomllib
from typing import NamedTuple

import absd_fs
import absd_image
import release_record as rr
import storage_fence_state as guard

SCHEMA = "absd-recovery-point/1"
STATE_ROOTS = ("/etc", "/home", "/ssh")
MAX_METADATA = 64 * 1024
MAX_ISO = 128 * 1024 * 1024


class Refused(ValueError):
    pass


def refuse(code, detail):
    raise Refused(f"recovery_point_{code}: {detail}")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def files_digest(tree):
    return digest(b"".join(path.encode() + b"\0" + hashlib.sha256(data).digest()
                           for path, data in sorted(tree.items())))


def require_clean(tree):
    require_clean_history(tree)
    if len(tree.get("/ssh/host_ed25519_seed", b"")) != 32:
        refuse("identity", "a recovery point needs the existing machine host identity")


def require_clean_history(tree):
    if guard.parse(tree.get(guard.PATH)) != "clean":
        refuse("unclean", "only an orderly-halted clean guard is a recovery point")
    require_ended_history(tree)


def _line(data, maximum):
    """recovery.rs first_line/small_file: bounded file and zero padding."""
    if not isinstance(data, bytes) or len(data) > maximum or b"\n" not in data:
        return None
    line, padding = data.split(b"\n", 1)
    return line if not any(padding) else None


def _fact_boot(data):
    line = _line(data, 64)
    match = re.fullmatch(rb"boot=([0-9a-f]{32})(?: action=.*)?", line) if line is not None else None
    return match[1] if match else None


def require_ended_history(tree):
    """Read-only subset of fsd recovery::assess, requiring Previous::Ended.

    The canonical producer's initialization marker is a regular file. Its
    bytes are not authority. No ledger, fact or guard is created or repaired.
    Shared Rust/Python golden vectors specify the existing v1 bytes.
    """
    if "/var/state/recovery.init" not in tree:
        refuse("history_invalid", "canonical recovery initialization is absent")
    line = _line(tree.get("/var/state/recovery"), 128)
    match = re.fullmatch(rb"absd-recovery v1 seq=([0-9]{1,19}) boot=([0-9a-f]{32}) "
                         rb"streak=([0-9]{1,19}) fnv=([0-9a-f]{16})", line) if line is not None else None
    if not match or int(match[4], 16) != absd_image.fnv1a(line.rsplit(b" fnv=", 1)[0]):
        refuse("history_invalid", "canonical recovery ledger is missing, malformed or has a bad check")
    boot = match[2]
    prefix = "/var/state/facts/served-"
    ready = _fact_boot(tree.get(prefix + "ready")) == boot
    stopped = _fact_boot(tree.get(prefix + "stopped")) == boot
    completed = tree.get(prefix + "completed")
    bounded = completed == (b"boot=" + boot + b" action=bounded\n").ljust(64, b"\0")
    ended = stopped and (bounded or (_fact_boot(tree.get(prefix + "end")) == boot
                                    and _fact_boot(completed) == boot))
    if not ended:
        refuse("history_not_ended", "previous=" + ("failed" if ready else "not_ready"))


def source_identity(value):
    if (not isinstance(value, str) or not value or value == "unknown" or value != value.strip()
            or len(value.encode("utf-8")) > 256
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        refuse("identity", "a bounded explicit logical machine identity is required")
    return value


def require_release(tree, selected):
    if not rr.valid_id(selected or "") or selected in (".", ".."):
        refuse("release", "a recovery point needs a selected release")
    try:
        record = rr.parse_record(tree.get(f"{rr.tree_root(selected)}/release", b""))
    except rr.Malformed as error:
        refuse("release_record", str(error))
    if record["release"] != selected or any(record[k] != v for k, v in rr.IDENTITY.items()):
        refuse("release_record", "release identity is unsupported")


def table(tree, selected, iso):
    require_clean(tree)
    require_release(tree, selected)
    if not 0 < len(iso) <= MAX_ISO:
        refuse("iso_size", "selected boot image is empty or exceeds the recovery bound")
    return {"schema": SCHEMA, "state_roots": list(STATE_ROOTS),
            "iso_bytes": len(iso), "iso_sha256": digest(iso)}


def capture_iso(directory, selected, iso_name):
    if not rr.valid_id(selected or ""):
        refuse("release", "a recovery point needs a selected release")
    root_fd = None
    try:
        root_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        return _member(root_fd, ("releases", selected, iso_name), MAX_ISO)
    except OSError as error:
        refuse("directory", f"cannot open source operator directory: {error.strerror}")
    finally:
        if root_fd is not None:
            os.close(root_fd)


class Snapshot(NamedTuple):
    metadata: dict
    tree: dict
    selected: str
    image: bytes
    iso: bytes
    metadata_sha256: str


def _member(root_fd, parts, limit, exact=None):
    """Open beneath the captured directory, refusing symbolic-link components."""
    if any(part in ("", ".", "..") or "/" in part or "\0" in part for part in parts):
        refuse("member_path", "invalid recovery member component")
    directory = os.dup(root_fd)
    fd = None
    label = "/".join(parts)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=directory)
            os.close(directory)
            directory = next_fd
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            refuse("member_type", f"{label} is not a regular file")
        if before.st_size > limit or (exact is not None and before.st_size != exact):
            refuse("member_size", f"{label} has an unsupported size")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        if (len(data) != before.st_size or len(data) > limit
                or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            refuse("member_changed", f"{label} changed during capture")
        return data
    except OSError as error:
        refuse("member_io", f"cannot read {label}: {error.strerror}")
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def image_tree(data, device_sectors):
    """Use the existing independent layout/filesystem checks on one snapshot."""
    try:
        regions = absd_image.parse_layout_sector(data[:absd_fs.SECTOR], device_sectors)
        if regions is None:
            refuse("image_invalid", "no disk layout")
        where = absd_image.region_of_kind(regions, absd_image.KIND_FS)
        region = absd_fs.Region.of_bytes(data, where.first, where.sectors)
        selected = absd_fs.select(region)
        if selected is None:
            refuse("image_invalid", "no committed filesystem")
        records = absd_fs.tree(region, selected)
        tree = {path: absd_fs.content(region, selected, record)
                for path, record in records.items() if not record["dir"]}
        return selected, tree
    except Refused:
        raise
    except (ValueError, IndexError, KeyError, TypeError, UnicodeError, struct.error) as error:
        refuse("image_invalid", str(error))
    except absd_fs.Refused as error:
        refuse("image_invalid", str(error))


def validate(backup, expected_pin, expected_release, *, image_name, image_bytes,
             iso_name, device_sectors):
    if not isinstance(expected_pin, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_pin):
        refuse("pin", "an independently retained metadata SHA-256 is required")
    if not isinstance(expected_release, str) or not rr.valid_id(expected_release):
        refuse("release", "an explicit expected source release is required")
    root_fd = None
    try:
        root_fd = os.open(pathlib.Path(backup), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        metadata_bytes = _member(root_fd, ("backup.toml",), MAX_METADATA)
        if digest(metadata_bytes) != expected_pin:
            refuse("pin_mismatch", "backup metadata differs from the independent pin")
        try:
            meta = tomllib.loads(metadata_bytes.decode("utf-8"))
        except (ValueError, UnicodeError) as error:
            refuse("metadata", str(error))
        for name in ("backup", "disk", "release", "identity", "recovery"):
            if not isinstance(meta.get(name), dict):
                refuse("metadata", f"missing or malformed {name} table")
        recovery = meta["recovery"]
        if (set(recovery) != {"schema", "state_roots", "iso_bytes", "iso_sha256"}
                or recovery["schema"] != SCHEMA
                or recovery["state_roots"] != list(STATE_ROOTS)):
            refuse("schema", "unsupported recovery schema or declared-state inventory")
        selected = meta["release"].get("selected")
        if selected != expected_release:
            refuse("release_mismatch", "backup does not select the expected source release")
        if meta["backup"].get("kind") != "halted":
            refuse("identity", "a halted point is required")
        source_identity(meta["backup"].get("target"))
        disk = meta["disk"]
        if any(type(disk.get(key)) is not int for key in
               ("fs_format", "fs_id", "commit_sequence", "files")):
            refuse("metadata", "malformed filesystem identity or sequence")
        if disk["fs_format"] != rr.IDENTITY["fs_format"]:
            refuse("format", "backup filesystem format is unsupported")
        if type(recovery["iso_bytes"]) is not int or not 0 < recovery["iso_bytes"] <= MAX_ISO:
            refuse("iso_size", "unsupported selected boot image size")
        image = _member(root_fd, (image_name,), image_bytes, exact=image_bytes)
        if digest(image) != disk.get("image_sha256"):
            refuse("image_digest", "disk differs from the pinned recovery point")
        fs, tree = image_tree(image, device_sectors)
        if (fs["format"] != disk["fs_format"] or fs["fs_id"] != disk["fs_id"]
                or fs["seq"] != disk["commit_sequence"] or len(tree) != disk["files"]
                or files_digest(tree) != disk.get("files_digest")):
            refuse("state_mismatch", "filesystem state differs from the pinned inventory")
        if tree.get(rr.SELECTED) != rr.selected_bytes(selected):
            refuse("release_mismatch", "filesystem selection differs from the recovery point")
        require_release(tree, selected)
        require_clean(tree)
        iso = _member(root_fd, ("releases", selected, iso_name), MAX_ISO,
                      exact=recovery["iso_bytes"])
        if digest(iso) != recovery["iso_sha256"]:
            refuse("iso_digest", "boot image differs from the pinned recovery point")
        return Snapshot(meta, tree, selected, image, iso, expected_pin)
    except OSError as error:
        refuse("directory", f"cannot open recovery point: {error.strerror}")
    finally:
        if root_fd is not None:
            os.close(root_fd)
