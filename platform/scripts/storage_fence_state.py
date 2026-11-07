"""Private writable-entry guard v1, shared with fsd/src/write_guard.rs, and
the operator-authorized resume slot v1, shared with fsd/src/resume.rs
(docs/WRITABLE-ENTRY.md, "Operator-authorized resume").

Only a fresh, exclusively owned image constructor seeds FRESH and the slot's
`none`. Normal boot and reconfiguration never create or reset either record.
A missing record on an older image means refuse writable entry, including
during upgrades; a missing slot means no operator act can authorize resume.
"""

import re

PATH = "/var/recovery.guard"
SECTOR = 512
RESUME_PATH = "/var/recovery.resume"
RESUME_PREFIX = b"absd-resume v1 "
RESUME_PREVIOUS = ("failed", "not_ready")
RESUME_FIELDS = ("id", "fs", "seq", "image", "ledger_seq", "ledger_boot", "previous", "time")
# A record line is at most this long including its newline (DESIGN-v5 2.1).
RESUME_LINE_MAX = 300


def encode(state):
    if state not in ("fresh", "dirty", "clean"):
        raise ValueError("unknown writable guard state")
    return f"absd-writable v1 {state}\n".encode().ljust(SECTOR, b"\0")


FRESH = encode("fresh")


def parse(data):
    return next((state for state in ("fresh", "dirty", "clean") if data == encode(state)), None)


def fnv1a(data):
    value = 0xcbf29ce484222325
    for byte in data:
        value = ((value ^ byte) * 0x100000001b3) & ((1 << 64) - 1)
    return value


def resume_line(record):
    """The record line (without its check) for the fields of `record`:
    id (32 hex), fs (int), seq (int), image (64 hex), ledger_seq (int),
    ledger_boot (32 hex), previous (failed|not_ready), time (int)."""
    if not re.fullmatch(r"[0-9a-f]{32}", record["id"]):
        raise ValueError("resume record: id is not 32 lowercase hex digits")
    if not re.fullmatch(r"[0-9a-f]{64}", record["image"]):
        raise ValueError("resume record: image is not 64 lowercase hex digits")
    if not re.fullmatch(r"[0-9a-f]{32}", record["ledger_boot"]):
        raise ValueError("resume record: ledger_boot is not 32 lowercase hex digits")
    if record["previous"] not in RESUME_PREVIOUS:
        raise ValueError("resume record: previous must be failed or not_ready")
    for name in ("fs", "seq", "ledger_seq", "time"):
        if type(record[name]) is not int or not 0 <= record[name] < 1 << 64:
            raise ValueError(f"resume record: {name} is not a 64-bit unsigned integer")
    return (f"absd-resume v1 id={record['id']} fs={record['fs']:016x} seq={record['seq']} "
            f"image={record['image']} ledger_seq={record['ledger_seq']} ledger_boot={record['ledger_boot']} "
            f"previous={record['previous']} time={record['time']}").encode()


def encode_resume(value):
    """The 512-byte slot sector: `none`, or the record dict's line with its
    FNV-1a 64 check and newline, zero-padded."""
    if value == "none":
        return RESUME_PREFIX + b"none\n" + bytes(SECTOR - len(RESUME_PREFIX) - 5)
    if not isinstance(value, dict):
        raise ValueError("unknown resume slot state")
    line = resume_line(value)
    line += b" fnv=%016x\n" % fnv1a(line)
    if len(line) > RESUME_LINE_MAX:
        raise ValueError("resume record line too long")
    return line.ljust(SECTOR, b"\0")


RESUME_NONE = encode_resume("none")
RESUME_RE = re.compile(rb"absd-resume v1 id=([0-9a-f]{32}) fs=([0-9a-f]{16}) seq=(0|[1-9][0-9]*) "
                       rb"image=([0-9a-f]{64}) ledger_seq=(0|[1-9][0-9]*) ledger_boot=([0-9a-f]{32}) "
                       rb"previous=(failed|not_ready) time=(0|[1-9][0-9]*) fnv=([0-9a-f]{16})")


def parse_resume(data):
    """`"none"`, a record dict, or None when the sector is corrupt (anything
    but the two exact encodings: a wrong length, a changed byte, a bad
    check, nonzero padding, a short or torn line)."""
    if len(data) != SECTOR or data == RESUME_NONE:
        return "none" if data == RESUME_NONE else None
    line, separator, padding = data.partition(b"\n")
    if not separator or padding.strip(b"\0") or len(line) + 1 > RESUME_LINE_MAX:
        return None
    match = RESUME_RE.fullmatch(line)
    if match is None:
        return None
    ident, fs, seq, image, ledger_seq, boot, previous, time, check = match.groups()
    if int(check, 16) != fnv1a(line.rsplit(b" fnv=", 1)[0]):
        return None
    record = {"id": ident.decode(), "fs": int(fs, 16), "seq": int(seq), "image": image.decode(),
              "ledger_seq": int(ledger_seq), "ledger_boot": boot.decode(), "previous": previous.decode(),
              "time": int(time)}
    if max(record["seq"], record["ledger_seq"], record["time"]) >= 1 << 64:
        return None
    return record if encode_resume(record) == data else None


def fresh_files():
    return [(PATH, FRESH), (RESUME_PATH, RESUME_NONE)]
