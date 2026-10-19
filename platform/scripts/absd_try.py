#!/usr/bin/env python3
"""absd-try: run an ABSD developer preview under QEMU without building it
(design docs/preview-pipeline-20261015/DESIGN.md, slice C).

Python 3.11+ standard library only, plus the platform's own host reader
(scripts/absd_fs.py and scripts/absd_image.py, also standard library only),
which the preview producer ships beside this file or bundles with it.

    absd-try verify ASSETS
    absd-try create DIR --assets ASSETS --key KEY.pub [--replace]
    absd-try enroll DIR --key KEY.pub
    absd-try boot DIR [--port 2222] [--accel auto|kvm|tcg]

ASSETS is a directory holding one release's downloaded files. DIR is one
machine: disk.img (the writable disk), operator.iso, enroll.iso,
MANIFEST.toml, known_hosts and console.log. Every refusal is one line
beginning `absd-try: REFUSED` with a reason word and exit status 2; the
helper never retries silently and never repairs anything.

The release's MANIFEST.toml (written by `release.py preview`, slice B) is
this tool's input contract:

    schema = "absd-preview-manifest/1"
    signature = "unsigned"            # or the exact ssh-keygen -Y verify line
    [release]  id, tag, kernel_commit, platform_commit
    [assets.operator_iso]  name, sha256, bytes
    [assets.enroll_iso]    name, sha256, bytes
    [assets.disk]          name, sha256, bytes, raw_sha256, raw_bytes
    [qemu]     cpu_tcg = "max,vendor=GenuineIntel,+rdrand"

SHA256SUMS lists every asset (`<sha256>  <name>`); the manifest's digests
must equal its lines.

Trust model (DESIGN.md sections 2, 5, 6): the user's key reaches the disk
only through the release's enroll image, which accepts exactly one file,
/ssh/authorized_keys; the helper then reads the whole disk with the host
reader and requires everything else unchanged. The host key is learned from
the VM's own console (`SSH HOST KEY GENERATED <key> <fingerprint>`), not from
the network, and a changed host key stops the machine.
"""

import argparse
import base64
import contextlib
import fcntl
import hashlib
import lzma
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import tomllib

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
from served_ram import served_qemu

SCHEMA = "absd-preview-manifest/1"
SUMS = "SHA256SUMS"
MANIFEST = "MANIFEST.toml"
DISK = "disk.img"
OPERATOR_ISO = "operator.iso"
ENROLL_ISO = "enroll.iso"
KNOWN_HOSTS = "known_hosts"
CONSOLE = "console.log"
LOCK = ".absd-try.lock"
MARKER = ".absd-try-machine"

KEYS_PATH = "/ssh/authorized_keys"
SEED_PATH = "/ssh/host_ed25519_seed"
SELECTED_PATH = "/absd/selected"
KEYS_MAX_BYTES = 16 * 1024
ED25519_PREFIX = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"

# absd-stream-v1, the host side (kernel user/src/bin/init.rs:333-397,
# scripts/external-live-session.py in the kernel repository).
STREAM_READY = re.compile(rb"EXTERNAL INPUT READY protocol=absd-stream-v1 max=([0-9]+) credit=([0-9]+)")
STREAM_ACCEPTED = b"EXTERNAL INPUT ACCEPTED protocol=absd-stream-v1"
STREAM_CREDIT = re.compile(rb"EXTERNAL INPUT CREDIT offset=([0-9]+) max=([0-9]+)")
STREAM_REFUSED = re.compile(rb"EXTERNAL INPUT REFUSED reason=(\S+)")
STREAM_MAGIC = b"ABSDST01"
# A chunk line counts only once its newline has arrived: a console log read
# while QEMU runs may end mid-line (ssh_absd.py `captured` does the same).
CHUNK = re.compile(rb"^EXTERNAL OUTPUT CHUNK offset=([0-9a-f]+) data=([0-9a-f]*)\n", re.M)
ENROLL_OK = re.compile(r"^ENROLL OK keys=([0-9]+) sha256=([0-9a-f]{64})$", re.M)
HOST_KEY = re.compile(r"^SSH HOST KEY (GENERATED|LOADED) (ssh-ed25519 [A-Za-z0-9+/=]+) (SHA256:[A-Za-z0-9+/]+)$", re.M)
LISTENING = re.compile(r"^SSH LISTENING port=", re.M)

ENROLL_TIMEOUT = 600
QEMU_HALTED = 3


class Refused(Exception):
    """One named refusal: `reason` is a word, `detail` the evidence."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason} {detail}".strip())
        self.reason = reason


def say(line):
    print(f"absd-try: {line}", flush=True)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


# -- the release assets ---------------------------------------------------------

def load_manifest(path):
    try:
        doc = tomllib.loads(pathlib.Path(path).read_text())
    except (OSError, ValueError) as error:
        raise Refused("manifest_unreadable", str(error)) from None
    if doc.get("schema") != SCHEMA:
        raise Refused("manifest_schema", repr(doc.get("schema")))
    release = doc.get("release")
    assets = doc.get("assets")
    if not isinstance(release, dict) or not isinstance(assets, dict):
        raise Refused("manifest_malformed", "release and assets tables are required")
    if not isinstance(release.get("id"), str) or not re.fullmatch(r"[a-z0-9.-]{1,64}", release["id"]):
        raise Refused("manifest_malformed", "release.id")
    for role in ("operator_iso", "enroll_iso", "disk"):
        entry = assets.get(role)
        if not isinstance(entry, dict):
            raise Refused("manifest_malformed", f"assets.{role} missing")
        name, digest, size = entry.get("name"), entry.get("sha256"), entry.get("bytes")
        if not isinstance(name, str) or "/" in name or name in ("", ".", ".."):
            raise Refused("manifest_malformed", f"assets.{role}.name")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise Refused("manifest_malformed", f"assets.{role}.sha256")
        if type(size) is not int or size <= 0:
            raise Refused("manifest_malformed", f"assets.{role}.bytes")
    disk = assets["disk"]
    if not isinstance(disk.get("raw_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", disk["raw_sha256"]):
        raise Refused("manifest_malformed", "assets.disk.raw_sha256")
    if type(disk.get("raw_bytes")) is not int or disk["raw_bytes"] <= 0 or disk["raw_bytes"] % 512:
        raise Refused("manifest_malformed", "assets.disk.raw_bytes")
    signature = doc.get("signature")
    if not isinstance(signature, str) or not (signature == "unsigned" or signature.startswith("ssh-keygen -Y verify ")):
        raise Refused("manifest_malformed", "signature must be unsigned or an ssh-keygen -Y verify line")
    return doc


def parse_sums(text):
    sums = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([^/\s]+)", line)
        if match is None:
            raise Refused("sums_malformed", f"line {number}")
        if match.group(2) in sums:
            raise Refused("sums_malformed", f"{match.group(2)} listed twice")
        sums[match.group(2)] = match.group(1)
    if not sums:
        raise Refused("sums_malformed", "no lines")
    return sums


def verify_assets(assets):
    """Every SHA256SUMS line against its file, every manifest asset against
    SHA256SUMS. Returns the manifest."""
    assets = pathlib.Path(assets)
    try:
        sums = parse_sums((assets / SUMS).read_text())
    except OSError as error:
        raise Refused("sums_missing", str(error)) from None
    if MANIFEST not in sums:
        raise Refused("sums_incomplete", f"{MANIFEST} is not listed")
    for name, digest in sorted(sums.items()):
        path = assets / name
        if not path.is_file():
            raise Refused("asset_missing", name)
        if sha256_file(path) != digest:
            raise Refused("asset_digest", name)
    doc = load_manifest(assets / MANIFEST)
    for role, entry in sorted(doc["assets"].items()):
        if not isinstance(entry, dict):
            raise Refused("manifest_malformed", f"assets.{role}")
        if sums.get(entry.get("name")) != entry.get("sha256"):
            raise Refused("manifest_sums_disagree", role)
        if (assets / entry["name"]).stat().st_size != entry.get("bytes"):
            raise Refused("asset_size", entry["name"])
    if doc["signature"] == "unsigned":
        say("signature: none (an unsigned preview; SHA256SUMS guards against corruption, not a compromised account)")
    else:
        say(f"signature: check it yourself before trusting this helper: {doc['signature']}")
    return doc


# -- the disk, by the host reader --------------------------------------------------

def read_tree(image):
    """path -> bytes for every file on the disk, by the platform's host
    reader (never the guest's code). Refuses a disk it cannot read."""
    import absd_fs
    image = pathlib.Path(image)
    sectors = image.stat().st_size // 512
    try:
        region = absd_fs.fs_region(image, sectors)
        if region is None:
            raise Refused("disk_unreadable", "no ABSD layout")
        selected = absd_fs.select(region)
        if selected is None:
            raise Refused("disk_unreadable", "no committed filesystem")
        out = {}
        for path, record in absd_fs.tree(region, selected).items():
            if path.endswith("/") or record.get("dir"):
                continue
            out[path] = absd_fs.content(region, selected, record)
        return out
    except absd_fs.Refused as error:
        raise Refused("disk_unreadable", str(error)) from None


def read_state(image):
    """The disk as the host reader sees it, for identity comparison: the
    filesystem id, format and commit sequence, and every object (files and
    directories) with its kind, read-only flag, mtime, size and content
    digest."""
    import absd_fs
    image = pathlib.Path(image)
    sectors = image.stat().st_size // 512
    try:
        region = absd_fs.fs_region(image, sectors)
        selected = absd_fs.select(region) if region is not None else None
        if selected is None:
            raise Refused("disk_unreadable", "no committed filesystem")
        objects = {}
        for path, record in absd_fs.tree(region, selected).items():
            entry = {"dir": record["dir"], "readonly": record["readonly"], "mtime": record["mtime"],
                     "size": record["size"]}
            if not record["dir"]:
                entry["sha256"] = sha256_bytes(absd_fs.content(region, selected, record))
            objects[path] = entry
        return {"fs_id": selected["fs_id"], "format": selected["format"], "seq": selected["seq"], "objects": objects}
    except absd_fs.Refused as error:
        raise Refused("disk_unreadable", str(error)) from None


def enrol_changes(before, after, key_bytes):
    """What an enroll boot may change: exactly one commit, and /ssh/authorized_keys
    replaced by the sent bytes as a writable file. Everything else - every
    file and directory, kind, read-only flag, mtime, size, content, the
    filesystem id and format - must be identical. Returns the violations."""
    problems = []
    for field in ("fs_id", "format"):
        if before[field] != after[field]:
            problems.append(f"{field} {before[field]}->{after[field]}")
    if after["seq"] != before["seq"] + 1:
        problems.append(f"commits {before['seq']}->{after['seq']} (exactly one expected)")
    old, new = before["objects"], after["objects"]
    for path in sorted(set(old) | set(new)):
        if path == KEYS_PATH:
            continue
        if old.get(path) != new.get(path):
            problems.append(path)
    keys = new.get(KEYS_PATH)
    if keys is None or keys["dir"] or keys["readonly"] or keys.get("sha256") != sha256_bytes(key_bytes):
        problems.append(f"{KEYS_PATH} is not the sent key as a writable file")
    return problems


def key_lines(data):
    """The ed25519 public keys of an authorized_keys file, under sshd's own
    rules (ssh/src/keys.rs parse_authorized): blank lines and `#` comments
    skipped, every other line `ssh-ed25519 <base64> [comment]`, at least one.
    The enroll worker's further rules apply too (ssh/src/enroll_main.rs
    validate_keys): printable ASCII, tab and line ends only (CR only before
    LF), and no key twice. Both are held to ssh/enroll-cases/."""
    if len(data) > KEYS_MAX_BYTES:
        raise Refused("key_too_large", f"{len(data)} bytes, at most {KEYS_MAX_BYTES}")
    for index, byte in enumerate(data):
        if not (0x20 <= byte <= 0x7e or byte in b"\t\n" or (byte == 0x0d and data[index + 1:index + 2] == b"\n")):
            raise Refused("key_malformed", f"byte {byte:#04x} at offset {index}")
    text = data.decode("ascii")
    keys = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        words = line.split()
        if words[0] != "ssh-ed25519":
            raise Refused("key_malformed", f"line {number}: only plain ssh-ed25519 keys are accepted")
        # An ed25519 blob (51 bytes) is exactly 68 base64 characters with no
        # padding. Python would accept redundant `=` that sshd's decoder refuses.
        word = words[1] if len(words) > 1 else ""
        blob = base64.b64decode(word) if re.fullmatch(r"[A-Za-z0-9+/]{68}", word) else b""
        if len(blob) != 51 or not blob.startswith(ED25519_PREFIX):
            raise Refused("key_malformed", f"line {number}: not an ssh-ed25519 key blob")
        if blob[19:] in keys:
            raise Refused("key_duplicate", f"line {number}: repeats an earlier key")
        keys.append(blob[19:])
    if not keys:
        raise Refused("key_missing", "no keys")
    return keys


def enrolled(tree):
    try:
        return key_lines(tree.get(KEYS_PATH, b""))
    except Refused:
        return []


def check_blank(tree, release_id):
    """A downloaded disk: nobody's key, no host identity, no user state."""
    if tree.get(SELECTED_PATH, b"").strip() != release_id.encode():
        raise Refused("disk_not_blank", f"{SELECTED_PATH} does not name {release_id}")
    if SEED_PATH in tree:
        raise Refused("disk_not_blank", f"{SEED_PATH} present (a downloaded disk never carries a host key)")
    if KEYS_PATH not in tree or tree[KEYS_PATH].strip():
        raise Refused("disk_not_blank", f"{KEYS_PATH} must be present and empty")
    used = sorted(p for p in tree if p.startswith(("/home/", "/var/log/")))
    if used:
        raise Refused("disk_not_blank", f"user state present: {', '.join(used[:4])}")


# -- the console -------------------------------------------------------------------

def decode_console(raw):
    """The captured worker streams of a console log, one per boot. Worker
    output is hex-framed (`EXTERNAL OUTPUT CHUNK offset=… data=…`); a stream
    starts at offset 0 (each boot starts one) and must be contiguous: any
    other offset is a gap, refused rather than read past."""
    streams = []
    for match in CHUNK.finditer(raw):
        offset = int(match.group(1), 16)
        try:
            data = bytes.fromhex(match.group(2).decode())
        except ValueError:
            raise Refused("console_malformed", f"chunk at offset {offset} is not whole bytes of hex") from None
        if offset == 0:
            streams.append(bytearray())
        elif not streams or offset != len(streams[-1]):
            have = len(streams[-1]) if streams else 0
            raise Refused("console_gap", f"chunk at offset {offset}, expected {have}")
        streams[-1].extend(data)
    return [bytes(s).decode(errors="replace") for s in streams]


# -- QEMU --------------------------------------------------------------------------

def qemu_binary():
    return os.environ.get("ABSD_TRY_QEMU", "qemu-system-x86_64")


def host_has(flag):
    try:
        return any(re.search(rf"\b{flag}\b", line) for line in open("/proc/cpuinfo") if line.startswith("flags"))
    except OSError:
        return False


def accel_args(choice, doc):
    """`-accel`/`-cpu` for the request. sshd refuses to start without RDRAND
    ("SSH ENTROPY"), so KVM needs a host CPU that has it."""
    tcg_cpu = doc.get("qemu", {}).get("cpu_tcg", "max,vendor=GenuineIntel,+rdrand")
    if choice == "auto":
        choice = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) and host_has("rdrand") else "tcg"
    if choice == "kvm":
        if not host_has("rdrand"):
            raise Refused("kvm_without_rdrand", "this host CPU does not report rdrand; use --accel tcg")
        return ["-accel", "kvm", "-cpu", "host"], "kvm"
    return ["-accel", "tcg", "-cpu", tcg_cpu], "tcg"


def disk_holders(image):
    """Processes with the disk open (Linux /proc); empty where unknown."""
    target = os.path.realpath(image)
    found = []
    proc = pathlib.Path("/proc")
    if not proc.is_dir():
        return found
    for entry in proc.iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        with contextlib.suppress(OSError):
            for fd in (entry / "fd").iterdir():
                with contextlib.suppress(OSError):
                    if os.readlink(fd) == target:
                        found.append(int(entry.name))
                        break
    return found


@contextlib.contextmanager
def machine_lock(machine):
    """One helper at a time per machine, and none while QEMU holds the disk."""
    handle = open(machine / LOCK, "a+")
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused("machine_busy", f"another absd-try holds {machine / LOCK}") from None
        holders = disk_holders(machine / DISK)
        if holders:
            raise Refused("machine_busy", f"{machine / DISK} is open in pid {', '.join(map(str, holders))}")
        yield
    finally:
        handle.close()


def stream_record(path, data):
    """The importer's input format (scripts/exec-matrix.py `stream`): one
    record, then the end marker."""
    import struct
    name = path.encode()
    return (b"ABSDFIX1" + struct.pack("<H", len(name)) + name + struct.pack("<Q", len(data))
            + hashlib.sha256(data).digest() + data + struct.pack("<H", 0))


def send_stream(sock, payload, log, deadline):
    """absd-stream-v1 from the host side: wait for READY, send the magic,
    send each chunk within its credit, then the zero-length end. Every byte
    QEMU's serial port writes is appended to `log`."""
    pending = bytearray()
    offset = 0
    header_sent = accepted = done = False
    sock.settimeout(0.5)
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            if not done:
                raise Refused("enroll_stream", "the guest closed the console before taking the key")
            return
        log.write(chunk)
        log.flush()
        pending.extend(chunk)
        while b"\n" in pending:
            line, _, rest = pending.partition(b"\n")
            pending = bytearray(rest)
            line = line.rstrip(b"\r")
            refused = STREAM_REFUSED.fullmatch(line)
            if refused:
                raise Refused("enroll_stream", f"the guest refused the input: {refused.group(1).decode()}")
            ready = STREAM_READY.fullmatch(line)
            if ready and not header_sent:
                if len(payload) > int(ready.group(1)):
                    raise Refused("enroll_stream", f"{len(payload)} bytes exceed the guest's {ready.group(1)}")
                sock.sendall(STREAM_MAGIC)
                header_sent = True
            elif line == STREAM_ACCEPTED and header_sent:
                accepted = True
            elif accepted and not done:
                credit = STREAM_CREDIT.fullmatch(line)
                if credit is None:
                    continue
                if int(credit.group(1)) != offset:
                    raise Refused("enroll_stream", f"guest credit at offset {credit.group(1)}, sent {offset}")
                piece = payload[offset:offset + int(credit.group(2))]
                sock.sendall(len(piece).to_bytes(2, "big") + piece)
                offset += len(piece)
                done = not piece
    raise Refused("enroll_timeout", f"no end of the enroll boot within {ENROLL_TIMEOUT} s")


def run_enroll(machine, doc, key_bytes, accel):
    """One enroll boot of the release's enroll image against the disk;
    the decoded worker output."""
    with tempfile.TemporaryDirectory(prefix="absd-try-") as work:
        sock_path = pathlib.Path(work) / "console.sock"
        log_path = machine / "enroll-console.log"
        accel_argv, _ = accel_args(accel, doc)
        argv = [*served_qemu([qemu_binary(), *accel_argv]), "-rtc", "base=utc", "-cdrom", str(machine / ENROLL_ISO),
                "-drive", f"file={machine / DISK},format=raw,if=ide,index=0", "-nic", "none", "-display", "none",
                "-chardev", f"socket,id=con,path={sock_path},server=on,wait=on", "-serial", "chardev:con",
                "-no-reboot", "-no-shutdown", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
        qemu_log = machine / "qemu.log"
        with open(qemu_log, "wb") as errors:
            qemu = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=errors)
        deadline = time.monotonic() + ENROLL_TIMEOUT
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            while True:
                try:
                    sock.connect(str(sock_path))
                    break
                except OSError:
                    if qemu.poll() is not None or time.monotonic() >= deadline:
                        raise Refused("enroll_qemu", f"QEMU did not open its console (status {qemu.poll()}): "
                                      + qemu_log.read_text(errors="replace")[-400:]) from None
                    time.sleep(0.05)
            with sock, open(log_path, "wb") as log:
                send_stream(sock, stream_record(KEYS_PATH, key_bytes), log, deadline)
            status = qemu.wait(timeout=max(1, deadline - time.monotonic()))
        except BaseException:
            stop(qemu)
            raise
        if status != QEMU_HALTED:
            raise Refused("enroll_failed", f"QEMU exited {status}; see {log_path}")
        return decode_console(log_path.read_bytes())


def enroll(machine, key_path, accel="auto"):
    machine = pathlib.Path(machine)
    doc = load_manifest(machine / MANIFEST)
    key_bytes = pathlib.Path(key_path).read_bytes()
    count = len(key_lines(key_bytes))
    with machine_lock(machine):
        before = read_state(machine / DISK)
        streams = run_enroll(machine, doc, key_bytes, accel)
        found = ENROLL_OK.search(streams[-1] if streams else "")
        if found is None:
            raise Refused("enroll_failed", "no ENROLL OK line from the enroll worker")
        if int(found.group(1)) != count or found.group(2) != sha256_bytes(key_bytes):
            raise Refused("enroll_mismatch", f"guest reports keys={found.group(1)} sha256={found.group(2)[:16]}")
        after = read_state(machine / DISK)
        if read_tree(machine / DISK).get(KEYS_PATH) != key_bytes:
            raise Refused("enroll_mismatch", f"the disk's {KEYS_PATH} is not the key that was sent")
        changed = enrol_changes(before, after, key_bytes)
        if changed:
            raise Refused("enroll_wrote_elsewhere", ", ".join(changed))
    say(f"ENROLLED keys={count} sha256={sha256_bytes(key_bytes)} machine={machine}")


def create(machine, assets, key_path, replace=False, accel="auto"):
    machine, assets = pathlib.Path(machine), pathlib.Path(assets)
    key_lines(pathlib.Path(key_path).read_bytes())  # refuse a bad key before any work
    doc = verify_assets(assets)
    if machine.is_symlink() or (machine.exists() and not machine.is_dir()):
        raise Refused("machine_not_directory", str(machine))
    if machine.exists() and any(machine.iterdir()):
        if not replace:
            raise Refused("machine_exists", f"{machine} is not empty; --replace destroys it")
        if not (machine / MARKER).is_file():
            raise Refused("machine_foreign", f"{machine} was not made by absd-try ({MARKER} missing); not deleting it")
        with machine_lock(machine):
            pass
        shutil.rmtree(machine)
    machine.mkdir(parents=True, exist_ok=True)
    (machine / MARKER).write_text(f"absd-try machine for release {doc['release']['id']}\n")
    a = doc["assets"]
    raw = machine / DISK
    with lzma.open(assets / a["disk"]["name"]) as source, open(raw, "wb") as dest:
        shutil.copyfileobj(source, dest, 1 << 20)
    raw.chmod(0o600)
    if raw.stat().st_size != a["disk"]["raw_bytes"] or sha256_file(raw) != a["disk"]["raw_sha256"]:
        raise Refused("disk_digest", "the decompressed disk differs from the manifest")
    for role, name in (("operator_iso", OPERATOR_ISO), ("enroll_iso", ENROLL_ISO)):
        shutil.copyfile(assets / a[role]["name"], machine / name)
        if sha256_file(machine / name) != a[role]["sha256"]:
            raise Refused("asset_digest", f"{name} as copied")
    shutil.copyfile(assets / MANIFEST, machine / MANIFEST)
    check_blank(read_tree(raw), doc["release"]["id"])
    say(f"CREATED release={doc['release']['id']} machine={machine}")
    enroll(machine, key_path, accel)


# -- the served boot ---------------------------------------------------------------

def endpoint(tree):
    """(guest address, guest port) from the disk's /etc, as boot-operator.sh."""
    def setting(path, keyword, default):
        for line in tree.get(path, b"").decode(errors="replace").splitlines():
            words = line.split()
            if len(words) == 2 and words[0] == keyword:
                return words[1]
        return default
    import ipaddress
    address, port = setting("/etc/network.conf", "address", "10.0.2.15"), setting("/etc/sshd.conf", "port", "22")
    try:
        parsed = ipaddress.IPv4Address(address)
    except ValueError:
        raise Refused("disk_config_invalid", f"/etc/network.conf address {address!r}") from None
    if parsed.is_unspecified or parsed.is_multicast or parsed.is_loopback or str(parsed) != address:
        raise Refused("disk_config_invalid", f"/etc/network.conf address {address!r}")
    if not re.fullmatch(r"[1-9][0-9]{0,4}", port) or int(port) > 65535:
        raise Refused("disk_config_invalid", f"/etc/sshd.conf port {port!r}")
    return address, port


def free_port(port):
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            raise Refused("port_in_use", f"127.0.0.1:{port}") from None


def stop(qemu):
    """No QEMU outlives the helper's supervision."""
    if qemu.poll() is None:
        qemu.kill()
    qemu.wait()


def host_key_line(machine, port, key):
    return f"[127.0.0.1]:{port} {key}\n"


def known_key(path):
    """The `ssh-ed25519 <base64>` a machine's known_hosts records, if any."""
    if not path.is_file():
        return None
    words = path.read_text().split()
    return " ".join(words[1:3]) if len(words) >= 3 else None


def boot(machine, port=2222, accel="auto", poll=0.2):
    machine = pathlib.Path(machine)
    doc = load_manifest(machine / MANIFEST)
    with machine_lock(machine):
        tree = read_tree(machine / DISK)
        if not enrolled(tree):
            raise Refused("not_enrolled", f"{KEYS_PATH} holds no key; run: absd-try enroll {machine} --key KEY.pub")
        free_port(port)
        guest, guest_port = endpoint(tree)
        net = ".".join(guest.split(".")[:3]) + ".0/24"
        accel_argv, chosen = accel_args(accel, doc)
        console = machine / CONSOLE
        console.write_bytes(b"")
        argv = [*served_qemu([qemu_binary(), *accel_argv]), "-rtc", "base=utc", "-cdrom", str(machine / OPERATOR_ISO),
                "-drive", f"file={machine / DISK},format=raw,if=ide,index=0",
                "-netdev", f"user,id=n0,net={net},hostfwd=tcp:127.0.0.1:{port}-{guest}:{guest_port}",
                "-device", "e1000,netdev=n0", "-display", "none", "-serial", f"file:{console}",
                "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
        known = machine / KNOWN_HOSTS
        say(f"BOOTING accel={chosen} console={console}")
        with open(machine / "qemu.log", "wb") as errors:
            qemu = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=errors)
        keyed, listening = set(), set()  # boot streams already handled
        try:
            while True:
                status = qemu.poll()
                streams = decode_console(console.read_bytes())
                for index, text in enumerate(streams):
                    if index not in keyed:
                        seen = HOST_KEY.search(text)
                        if seen is None:
                            continue
                        state, key, fingerprint = seen.groups()
                        recorded = known_key(known)
                        if recorded is not None and recorded != key:
                            raise Refused("host_key_changed",
                                          f"the console shows {fingerprint}; {known} holds another key")
                        known.write_text(host_key_line(machine, port, key))
                        say(f"HOST KEY {state} {fingerprint} (read from the VM console, recorded in {known})")
                        keyed.add(index)
                    if index not in listening and LISTENING.search(text):
                        say(f"READY ssh -p {port} -i KEY -o UserKnownHostsFile={known} operator@127.0.0.1")
                        listening.add(index)
                if status is not None:
                    break
                time.sleep(poll)
        except KeyboardInterrupt:
            stop(qemu)
            raise Refused("interrupted", "QEMU was stopped hard; run `shutdown` in a session next time") from None
        except BaseException:
            stop(qemu)
            raise
    if status == QEMU_HALTED:
        say("HALTED cleanly")
        return 0
    raise Refused("boot_failed", f"QEMU exited {status}; see {console}")


# -- command line ------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(prog="absd-try", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify")
    v.add_argument("assets")
    c = sub.add_parser("create")
    c.add_argument("machine")
    c.add_argument("--assets", required=True)
    c.add_argument("--key", required=True)
    c.add_argument("--replace", action="store_true")
    c.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    e = sub.add_parser("enroll")
    e.add_argument("machine")
    e.add_argument("--key", required=True)
    e.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    b = sub.add_parser("boot")
    b.add_argument("machine")
    b.add_argument("--port", type=int, default=2222)
    b.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    args = ap.parse_args(argv)
    try:
        if args.command == "verify":
            doc = verify_assets(args.assets)
            say(f"VERIFIED release={doc['release']['id']} assets={len(doc['assets'])}")
        elif args.command == "create":
            create(args.machine, args.assets, args.key, args.replace, args.accel)
        elif args.command == "enroll":
            enroll(args.machine, args.key, args.accel)
        else:
            return boot(args.machine, args.port, args.accel)
        return 0
    except Refused as error:
        say(f"REFUSED {error}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
