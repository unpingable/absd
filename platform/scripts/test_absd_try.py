#!/usr/bin/env python3
"""Host tests of scripts/absd_try.py (the developer-preview helper, #31
slice C). No QEMU and no kernel: a fake QEMU (this file, run with
`--fake-qemu`) plays init's side of absd-stream-v1, the enroll worker and
the served console, against a fake disk (a JSON header in a sparse file)
that the tests' replacement of `read_tree` reads.

    python3 -I scripts/test_absd_try.py

Prints `ABSD TRY HOST TEST OK cases=N` when every case passes.
"""

import base64
import contextlib
import fcntl
import hashlib
import io
import json
import lzma
import os
import pathlib
import re
import shutil
import shlex
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
MAGIC = b"FAKEDISK"
DISK_BYTES = 64 * 1024
RELEASE = "absd-preview-test"


# -- the fake disk ---------------------------------------------------------------

def write_disk(path, files, meta=None):
    """files: path -> bytes; meta: fs_id, seq, dirs, mtimes (the fake
    filesystem's metadata, which `fake_state` reports as the host reader would)."""
    meta = dict({"fs_id": 7, "seq": 1, "dirs": ["/absd", "/etc", "/ssh"], "mtimes": {}}, **(meta or {}))
    doc = {"files": {p: d.decode("latin-1") for p, d in files.items()}, "meta": meta}
    body = MAGIC + json.dumps(doc).encode() + b"\n"
    assert len(body) <= DISK_BYTES
    pathlib.Path(path).write_bytes(body + bytes(DISK_BYTES - len(body)))


def read_doc(path):
    raw = pathlib.Path(path).read_bytes()
    if not raw.startswith(MAGIC):
        raise ValueError("not a fake disk")
    return json.loads(raw[len(MAGIC):raw.index(b"\n")])


def read_disk(path):
    return {p: d.encode("latin-1") for p, d in read_doc(path)["files"].items()}


def fake_state(path):
    doc = read_doc(path)
    meta = doc["meta"]
    objects = {d: {"dir": True, "readonly": False, "mtime": 0, "size": 0} for d in meta["dirs"]}
    for p, d in doc["files"].items():
        data = d.encode("latin-1")
        objects[p] = {"dir": False, "readonly": False, "mtime": meta["mtimes"].get(p, 0), "size": len(data),
                      "sha256": hashlib.sha256(data).hexdigest()}
    return {"fs_id": meta["fs_id"], "format": 2, "seq": meta["seq"], "objects": objects}


def update_disk(path, change):
    doc = read_doc(path)
    files = {p: d.encode("latin-1") for p, d in doc["files"].items()}
    change(files, doc["meta"])
    write_disk(path, files, doc["meta"])


def ed25519_line(seed, comment="user@host"):
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + hashlib.sha256(seed).digest()
    return f"ssh-ed25519 {base64.b64encode(blob).decode()} {comment}\n".encode()


# -- the fake QEMU -----------------------------------------------------------------

def framed(text, offset=0):
    data = text.encode()
    return f"EXTERNAL OUTPUT CHUNK offset={offset:016x} data={data.hex()}\n".encode()


def fake_qemu(argv):
    mode = os.environ.get("FAKE_QEMU_MODE", "ok")
    disk = next(a.split("file=", 1)[1].split(",", 1)[0] for a in argv if a.startswith("file="))
    if "-chardev" in argv:
        path = argv[argv.index("-chardev") + 1].split("path=", 1)[1].split(",", 1)[0]
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        server.listen(1)
        conn, _ = server.accept()
        stream = conn.makefile("rb")
        conn.sendall(b"ABSD KERNEL BOOT\nEXTERNAL INPUT READY protocol=absd-stream-v1 max=131072 credit=64\n")
        if stream.read(8) != b"ABSDST01":
            conn.sendall(b"EXTERNAL INPUT REFUSED reason=bad-header\n")
            return 7
        if mode == "refuse":
            conn.sendall(b"EXTERNAL INPUT REFUSED reason=chunk-exceeds-credit\n")
            return 7
        conn.sendall(b"EXTERNAL INPUT ACCEPTED protocol=absd-stream-v1\n")
        data = bytearray()
        while True:
            conn.sendall(f"EXTERNAL INPUT CREDIT offset={len(data)} max=64\n".encode())
            (length,) = struct.unpack(">H", stream.read(2))
            if length == 0:
                break
            data += stream.read(length)
        conn.sendall(f"EXTERNAL INPUT EOF bytes={len(data)}\n".encode())
        assert data[:8] == b"ABSDFIX1"
        (n,) = struct.unpack_from("<H", data, 8)
        name = data[10:10 + n].decode()
        (size,) = struct.unpack_from("<Q", data, 10 + n)
        body = bytes(data[10 + n + 8 + 32:10 + n + 8 + 32 + size])
        def change(files, meta):
            files[name] = body
            meta["seq"] += 2 if mode == "two-commits" else 1
            if mode == "elsewhere":
                files["/etc/network.conf"] = b"address 10.0.2.99\n"
            if mode == "newdir":
                meta["dirs"].append("/home")
            if mode == "mtime":
                meta["mtimes"]["/etc/network.conf"] = 1792052576
            if mode == "fs-id":
                meta["fs_id"] += 1
        update_disk(disk, change)
        keys = sum(1 for line in body.decode().splitlines() if line.startswith("ssh-ed25519"))
        digest = hashlib.sha256(body).hexdigest() if mode != "wrong-sha" else "0" * 64
        if mode == "gap":
            conn.sendall(framed("ENROLL OK", 0) + framed(f" keys={keys}\n", 40))
        else:
            conn.sendall(framed(f"ENROLL OK keys={keys} sha256={digest}\n"))
        conn.close()
        return 7 if mode == "exit7" else 3
    console = next(a.split("file:", 1)[1] for a in argv if a.startswith("file:"))
    if os.environ.get("FAKE_QEMU_PIDFILE"):
        pathlib.Path(os.environ["FAKE_QEMU_PIDFILE"]).write_text(str(os.getpid()))
    if mode in ("odd-hex", "partial"):
        with open(console, "ab") as log:
            if mode == "odd-hex":
                log.write(b"ABSD KERNEL BOOT\nEXTERNAL OUTPUT CHUNK offset=0000000000000000 data=abc\n")
            else:
                log.write(b"ABSD KERNEL BOOT\n" + framed("SSH HOST KEY GENERATED ssh-ed25519 AAAA")[:-1])
        import time
        time.sleep(60)  # a QEMU that never ends by itself
        return 0
    key = os.environ.get("FAKE_HOST_KEY", ed25519_line(b"host").decode().split()[1])
    state = "LOADED" if read_disk(disk).get("/ssh/host_ed25519_seed") else "GENERATED"

    def seed(files, meta):
        files["/ssh/host_ed25519_seed"] = b"seed"
        meta["seq"] += 1
    update_disk(disk, seed)
    text = f"SSH HOST KEY {state} ssh-ed25519 {key} SHA256:abcdef\nSSH LISTENING port=22 authorized_keys=1\n"
    with open(console, "ab") as log:
        log.write(b"ABSD KERNEL BOOT\n" + framed(text))
    if mode == "wait-shutdown":
        import time
        while not pathlib.Path(os.environ["FAKE_SHUTDOWN"]).exists():
            time.sleep(0.01)
    return int(os.environ.get("FAKE_QEMU_HALT_STATUS", "3"))


# -- fixtures ----------------------------------------------------------------------

import absd_try  # noqa: E402


def make_assets(root, disk_files=None, signature="unsigned", tamper=None):
    root = pathlib.Path(root)
    root.mkdir(parents=True)
    raw = root / "raw.img"
    files = {"/absd/selected": f"{RELEASE}\n".encode(), "/ssh/authorized_keys": b"",
             "/etc/network.conf": b"address 10.0.2.15\n", f"/releases/{RELEASE}/bin/ls": b"ls\n"}
    if disk_files is not None:
        files = disk_files
    write_disk(raw, files)
    names = {"operator_iso": f"absd-{RELEASE}-operator.iso", "enroll_iso": f"absd-{RELEASE}-enroll.iso",
             "disk": f"absd-{RELEASE}-disk.img.xz"}
    (root / names["operator_iso"]).write_bytes(b"operator iso\n")
    (root / names["enroll_iso"]).write_bytes(b"enroll iso\n")
    (root / names["disk"]).write_bytes(lzma.compress(raw.read_bytes()))
    raw_sha, raw_bytes = absd_try.sha256_file(raw), raw.stat().st_size
    raw.unlink()
    lines = [f'schema = "{absd_try.SCHEMA}"', f'signature = "{signature}"', "", "[release]", f'id = "{RELEASE}"',
             f'tag = "{RELEASE}"', 'kernel_commit = "' + "a" * 40 + '"', 'platform_commit = "' + "b" * 40 + '"']
    for role, name in names.items():
        path = root / name
        lines += ["", f"[assets.{role}]", f'name = "{name}"', f'sha256 = "{absd_try.sha256_file(path)}"',
                  f"bytes = {path.stat().st_size}"]
        if role == "disk":
            lines += [f'raw_sha256 = "{raw_sha}"', f"raw_bytes = {raw_bytes}"]
    (root / absd_try.MANIFEST).write_text("\n".join(lines) + "\n")
    sums = "".join(f"{absd_try.sha256_file(p)}  {p.name}\n" for p in sorted(root.iterdir()))
    (root / absd_try.SUMS).write_text(sums)
    if tamper:
        tamper(root)
    return root


class AbsdTry(unittest.TestCase):
    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp(prefix="test-absd-try-"))
        self.saved_reader = absd_try.read_tree
        self.saved_state = absd_try.read_state
        absd_try.read_tree = lambda image: read_disk(image)
        absd_try.read_state = fake_state
        self.saved_env = dict(os.environ)
        wrapper = self.work / "qemu"
        wrapper.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} -I -B -X {shlex.quote('pycache_prefix=' + (sys.pycache_prefix or ''))} {shlex.quote(str(pathlib.Path(__file__).resolve()))} --fake-qemu \"$@\"\n")
        wrapper.chmod(0o755)
        os.environ["ABSD_TRY_QEMU"] = str(wrapper)
        os.environ.pop("FAKE_QEMU_MODE", None)
        self.key = self.work / "id.pub"
        self.key.write_bytes(ed25519_line(b"user"))
        self.out = io.StringIO()

    def tearDown(self):
        absd_try.read_tree = self.saved_reader
        absd_try.read_state = self.saved_state
        os.environ.clear()
        os.environ.update(self.saved_env)
        shutil.rmtree(self.work, ignore_errors=True)

    def run_main(self, *argv):
        with contextlib.redirect_stdout(self.out):
            return absd_try.main(list(argv))

    def refused(self, reason, *argv):
        status = self.run_main(*argv)
        self.assertEqual(status, 2, self.out.getvalue())
        self.assertIn(f"absd-try: REFUSED {reason}", self.out.getvalue())

    def machine(self, mode=None):
        assets = make_assets(self.work / "assets")
        if mode:
            os.environ["FAKE_QEMU_MODE"] = mode
        return assets, self.work / "machine"

    def created(self):
        assets, machine = self.machine()
        self.assertEqual(self.run_main("create", str(machine), "--assets", str(assets), "--key", str(self.key),
                                       "--accel", "tcg"), 0, self.out.getvalue())
        return machine

    # verify

    def test_verify_accepts_an_intact_release_and_says_it_is_unsigned(self):
        assets = make_assets(self.work / "assets")
        self.assertEqual(self.run_main("verify", str(assets)), 0)
        self.assertIn("signature: none", self.out.getvalue())
        self.assertIn(f"VERIFIED release={RELEASE} assets=3", self.out.getvalue())

    def test_verify_refuses_a_changed_asset(self):
        assets = make_assets(self.work / "assets", tamper=lambda r: (r / f"absd-{RELEASE}-enroll.iso").write_bytes(b"x"))
        self.refused("asset_digest", "verify", str(assets))

    def test_verify_refuses_a_missing_asset(self):
        assets = make_assets(self.work / "assets", tamper=lambda r: (r / f"absd-{RELEASE}-operator.iso").unlink())
        self.refused("asset_missing", "verify", str(assets))

    def test_verify_refuses_sums_without_the_manifest(self):
        def drop(root):
            text = (root / absd_try.SUMS).read_text()
            (root / absd_try.SUMS).write_text("".join(l + "\n" for l in text.splitlines() if not l.endswith(absd_try.MANIFEST)))
        self.refused("sums_incomplete", "verify", str(make_assets(self.work / "assets", tamper=drop)))

    def test_verify_refuses_a_malformed_sums_line(self):
        def append(root):
            with open(root / absd_try.SUMS, "a") as sums:
                sums.write("nonsense\n")
        assets = make_assets(self.work / "assets", tamper=append)
        self.refused("sums_malformed", "verify", str(assets))

    def test_verify_refuses_a_manifest_that_disagrees_with_the_sums(self):
        def edit(root):
            text = (root / absd_try.MANIFEST).read_text()
            digest = re.search(r'sha256 = "([0-9a-f]{64})"', text).group(1)
            (root / absd_try.MANIFEST).write_text(text.replace(digest, "f" * 64, 1))
            sums = "".join(f"{absd_try.sha256_file(p)}  {p.name}\n" for p in sorted(root.iterdir()) if p.name != absd_try.SUMS)
            (root / absd_try.SUMS).write_text(sums)
        self.refused("manifest_sums_disagree", "verify", str(make_assets(self.work / "assets", tamper=edit)))

    def test_verify_refuses_a_malformed_signature_field(self):
        self.refused("manifest_malformed", "verify", str(make_assets(self.work / "assets", signature="gpg --verify")))

    def test_verify_prints_the_signature_check_it_cannot_do_for_you(self):
        line = "ssh-keygen -Y verify -f allowed_signers -I release@absd.dev -n file -s SHA256SUMS.sig"
        self.assertEqual(self.run_main("verify", str(make_assets(self.work / "assets", signature=line))), 0)
        self.assertIn(line, self.out.getvalue())

    # keys

    def test_key_refuses_a_non_ed25519_line(self):
        self.key.write_bytes(b"ssh-rsa AAAAB3Nza user\n")
        assets, machine = self.machine()
        self.refused("key_malformed", "create", str(machine), "--assets", str(assets), "--key", str(self.key))
        self.assertFalse(machine.exists())

    def test_key_refuses_an_empty_file(self):
        self.key.write_bytes(b"# nothing\n\n")
        assets, machine = self.machine()
        self.refused("key_missing", "create", str(machine), "--assets", str(assets), "--key", str(self.key))

    def test_key_refuses_a_bad_blob(self):
        self.key.write_bytes(b"ssh-ed25519 " + base64.b64encode(b"short") + b" x\n")
        assets, machine = self.machine()
        self.refused("key_malformed", "create", str(machine), "--assets", str(assets), "--key", str(self.key))

    def test_key_refuses_an_oversize_file(self):
        self.key.write_bytes(ed25519_line(b"u") * 200)
        assets, machine = self.machine()
        self.refused("key_too_large", "create", str(machine), "--assets", str(assets), "--key", str(self.key))

    def test_key_rules_match_the_enroll_worker(self):
        """ssh/enroll-cases/<verdict>.<name>.keys: the enroll worker's unit
        test (ssh/src/enroll_main.rs) holds the guest to the same verdicts."""
        import absd_try
        reasons = {"empty": "key_missing", "malformed": "key_malformed", "duplicate": "key_duplicate",
                   "too-large": "key_too_large"}
        cases = sorted((here.parent / "ssh" / "enroll-cases").glob("*.keys"))
        self.assertGreaterEqual(len(cases), 20)
        for case in cases:
            verdict = case.name.split(".")[0]
            with self.subTest(case.name):
                if verdict.startswith("ok-"):
                    self.assertEqual(len(absd_try.key_lines(case.read_bytes())), int(verdict[3:]))
                else:
                    with self.assertRaises(absd_try.Refused) as caught:
                        absd_try.key_lines(case.read_bytes())
                    self.assertEqual(caught.exception.reason, reasons[verdict.removeprefix("refuse-")])

    # create and enroll

    def test_create_enrolls_the_key_and_changes_nothing_else(self):
        machine = self.created()
        disk = read_disk(machine / absd_try.DISK)
        self.assertEqual(disk["/ssh/authorized_keys"], self.key.read_bytes())
        self.assertEqual(disk["/etc/network.conf"], b"address 10.0.2.15\n")
        self.assertIn("ENROLLED keys=1", self.out.getvalue())
        self.assertIn("EXTERNAL INPUT EOF", (machine / "enroll-console.log").read_text())

    def test_create_refuses_an_existing_machine_without_replace(self):
        machine = self.created()
        assets = self.work / "assets"
        self.refused("machine_exists", "create", str(machine), "--assets", str(assets), "--key", str(self.key))

    def test_create_replace_refuses_a_directory_absd_try_did_not_make(self):
        assets, _ = self.machine()
        foreign = self.work / "foreign"
        foreign.mkdir()
        (foreign / "precious.txt").write_text("keep me\n")
        self.refused("machine_foreign", "create", str(foreign), "--assets", str(assets), "--key", str(self.key),
                     "--replace")
        self.assertEqual((foreign / "precious.txt").read_text(), "keep me\n")

    def test_create_replace_rebuilds_its_own_machine(self):
        machine = self.created()
        (machine / "scratch").write_text("old\n")
        self.assertEqual(self.run_main("create", str(machine), "--assets", str(self.work / "assets"), "--key",
                                       str(self.key), "--replace", "--accel", "tcg"), 0, self.out.getvalue())
        self.assertFalse((machine / "scratch").exists())

    def test_create_refuses_a_disk_with_a_host_key(self):
        files = {"/absd/selected": f"{RELEASE}\n".encode(), "/ssh/authorized_keys": b"",
                 "/ssh/host_ed25519_seed": b"seed"}
        assets = make_assets(self.work / "assets", disk_files=files)
        self.refused("disk_not_blank", "create", str(self.work / "m"), "--assets", str(assets), "--key", str(self.key))

    def test_create_refuses_a_distributed_local_login_verifier(self):
        for descriptor in (b'', b'ABSD-LOCAL-1 operator ' + b'0' * 64 + b'\n'):
            with self.subTest(descriptor=descriptor):
                root = self.work / ('empty-verifier' if not descriptor else 'verifier')
                files = {'/absd/selected': f'{RELEASE}\n'.encode(),
                         '/ssh/authorized_keys': b'', '/ssh/local-login': descriptor}
                assets = make_assets(root / 'assets', disk_files=files)
                self.refused('disk_not_blank', 'create', str(root / 'machine'),
                             '--assets', str(assets), '--key', str(self.key))
                self.assertIn('/ssh/local-login', self.out.getvalue())

    def test_create_refuses_a_disk_with_someone_elses_key(self):
        files = {"/absd/selected": f"{RELEASE}\n".encode(), "/ssh/authorized_keys": ed25519_line(b"other")}
        assets = make_assets(self.work / "assets", disk_files=files)
        self.refused("disk_not_blank", "create", str(self.work / "m"), "--assets", str(assets), "--key", str(self.key))

    def test_create_refuses_a_disk_for_another_release(self):
        files = {"/absd/selected": b"another\n", "/ssh/authorized_keys": b""}
        assets = make_assets(self.work / "assets", disk_files=files)
        self.refused("disk_not_blank", "create", str(self.work / "m"), "--assets", str(assets), "--key", str(self.key))

    def test_enroll_refuses_a_guest_that_wrote_anything_else(self):
        assets, machine = self.machine("elsewhere")
        self.refused("enroll_wrote_elsewhere /etc/network.conf", "create", str(machine), "--assets", str(assets),
                     "--key", str(self.key), "--accel", "tcg")

    def test_enroll_refuses_a_new_directory(self):
        assets, machine = self.machine("newdir")
        self.refused("enroll_wrote_elsewhere /home", "create", str(machine), "--assets", str(assets),
                     "--key", str(self.key), "--accel", "tcg")

    def test_enroll_refuses_a_changed_mtime_elsewhere(self):
        assets, machine = self.machine("mtime")
        self.refused("enroll_wrote_elsewhere /etc/network.conf", "create", str(machine), "--assets", str(assets),
                     "--key", str(self.key), "--accel", "tcg")

    def test_enroll_refuses_more_than_one_commit(self):
        assets, machine = self.machine("two-commits")
        self.refused("enroll_wrote_elsewhere commits 1->3 (exactly one expected)", "create", str(machine), "--assets", str(assets),
                     "--key", str(self.key), "--accel", "tcg")

    def test_enroll_refuses_a_changed_filesystem_id(self):
        assets, machine = self.machine("fs-id")
        self.refused("enroll_wrote_elsewhere fs_id 7->8", "create", str(machine), "--assets", str(assets),
                     "--key", str(self.key), "--accel", "tcg")

    def test_enroll_refuses_a_guest_report_that_names_other_bytes(self):
        assets, machine = self.machine("wrong-sha")
        self.refused("enroll_mismatch", "create", str(machine), "--assets", str(assets), "--key", str(self.key),
                     "--accel", "tcg")

    def test_enroll_refuses_when_the_guest_refuses_the_stream(self):
        assets, machine = self.machine("refuse")
        self.refused("enroll_stream", "create", str(machine), "--assets", str(assets), "--key", str(self.key),
                     "--accel", "tcg")

    def test_enroll_refuses_a_failed_qemu_exit(self):
        assets, machine = self.machine("exit7")
        self.refused("enroll_failed", "create", str(machine), "--assets", str(assets), "--key", str(self.key),
                     "--accel", "tcg")

    def test_enroll_refuses_a_pending_resume_authorization_on_the_disk(self):
        # coordination record #63 M1: the enrollment tool enters the mutators' boundary.
        machine = self.created()
        record = (b"absd-resume v1 id=" + b"a" * 32 + b" fs=0000000000000007 seq=11 image=" + b"e3" * 32
                  + b" ledger_seq=3 ledger_boot=" + b"0" * 32 + b" previous=failed time=1 fnv=0000000000000000\n")
        update_disk(machine / absd_try.DISK, lambda f, m: f.__setitem__(absd_try.RESUME_PATH, record.ljust(512, b"\0")))
        new = self.work / "new.pub"
        new.write_bytes(b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGpT2Ro6RqS5rT4kVf2ZgEoqbXaYgA3+Q8gJUnQPz0Oi other\n")
        self.refused("recovery_pending", "enroll", str(machine), "--key", str(new), "--accel", "tcg")
        update_disk(machine / absd_try.DISK, lambda f, m: f.__setitem__(absd_try.RESUME_PATH, b"torn".ljust(512, b"\0")))
        self.refused("resume_slot_corrupt", "enroll", str(machine), "--key", str(new), "--accel", "tcg")
        update_disk(machine / absd_try.DISK, lambda f, m: f.__setitem__(absd_try.RESUME_PATH, absd_try.RESUME_NONE))
        self.assertTrue((machine / "recovery" / "lock").is_file())
        # The other half of the boundary: an unsuperseded published
        # authorization (active.toml) with slot none refuses; an archive of
        # its id supersedes it; an unparsable active is a corrupt receipt.
        active = machine / "recovery" / "active.toml"
        active.write_text('[active]\nid = "' + "b" * 32 + '"\nstate = "authorized"\n')
        self.refused("recovery_pending", "enroll", str(machine), "--key", str(new), "--accel", "tcg")
        for kind in absd_try.ARCHIVE_KINDS:
            archive = machine / "recovery" / f"{kind}-{'b' * 32}.toml"
            archive.write_text('[archive]\nid = "' + "b" * 32 + f'"\nkind = "{kind}"\n')
            self.assertEqual(self.run_main("enroll", str(machine), "--key", str(new), "--accel", "tcg"), 0, kind)
            archive.unlink()
        (machine / "recovery" / f"consumed-{'c' * 32}.toml").write_text("[archive]\nid = \"" + "c" * 32 + "\"\n")
        self.refused("recovery_pending", "enroll", str(machine), "--key", str(new), "--accel", "tcg")
        active.write_text("[active\n")
        self.refused("corrupt_receipt", "enroll", str(machine), "--key", str(new), "--accel", "tcg")
        active.unlink()

    def test_enroll_refuses_a_console_gap(self):
        assets, machine = self.machine("gap")
        self.refused("console_gap", "create", str(machine), "--assets", str(assets), "--key", str(self.key),
                     "--accel", "tcg")

    def test_enroll_rotates_the_key(self):
        machine = self.created()
        new = self.work / "new.pub"
        new.write_bytes(ed25519_line(b"rotated"))
        self.assertEqual(self.run_main("enroll", str(machine), "--key", str(new), "--accel", "tcg"), 0)
        self.assertEqual(read_disk(machine / absd_try.DISK)["/ssh/authorized_keys"], new.read_bytes())

    def test_enroll_refuses_a_busy_machine(self):
        machine = self.created()
        with open(machine / absd_try.LOCK, "a+") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            self.refused("machine_busy", "enroll", str(machine), "--key", str(self.key))

    # the console decoder

    def test_decode_console_ignores_a_partial_last_line(self):
        whole = framed("SSH HOST KEY GENERATED ssh-ed25519 AAAA SHA256:abcdef\n")
        self.assertEqual(absd_try.decode_console(whole[:-1]), [])
        self.assertEqual(absd_try.decode_console(whole[:-9]), [])
        self.assertEqual(absd_try.decode_console(whole), ["SSH HOST KEY GENERATED ssh-ed25519 AAAA SHA256:abcdef\n"])

    def test_decode_console_refuses_odd_hex(self):
        with self.assertRaises(absd_try.Refused) as caught:
            absd_try.decode_console(b"EXTERNAL OUTPUT CHUNK offset=0000000000000000 data=abc\n")
        self.assertEqual(caught.exception.reason, "console_malformed")

    def test_boot_stops_qemu_when_the_console_is_malformed(self):
        machine = self.created()
        pidfile = self.work / "qemu.pid"
        os.environ.update(FAKE_QEMU_MODE="odd-hex", FAKE_QEMU_PIDFILE=str(pidfile))
        self.refused("console_malformed", "boot", str(machine), "--accel", "tcg", "--port", str(free_port()))
        self.assertFalse(alive(int(pidfile.read_text())))

    def interrupted_boot(self, mode="clean", early=False, login_key=False, startup=False):
        """Real child processes and SIGINT; only QEMU and SSH executables are fixtures."""
        import signal
        import threading
        machine = self.created()
        renamed = machine.with_name("machine with spaces")
        machine.rename(renamed)
        machine = renamed
        pidfile, request = self.work / "qemu.pid", self.work / "ssh-request.json"
        halt = self.work / "halt"
        os.environ.update(FAKE_QEMU_MODE="partial" if early else "wait-shutdown",
                          FAKE_QEMU_PIDFILE=str(pidfile), FAKE_SHUTDOWN=str(halt),
                          FAKE_SSH_REQUEST=str(request), FAKE_SSH_MODE=mode,
                          FAKE_QEMU_HALT_STATUS="0" if mode == "bad-exit" else "3")
        ssh = self.work / "ssh"
        ssh.write_text("#!/usr/bin/env python3\n"
                       "import json, os, pathlib, sys, time\n"
                       "pathlib.Path(os.environ['FAKE_SSH_REQUEST']).write_text(json.dumps(sys.argv[1:]))\n"
                       "mode = os.environ['FAKE_SSH_MODE']\n"
                       "if mode == 'no-identity': sys.exit(255)\n"
                       "if mode in ('clean', 'bad-exit'): pathlib.Path(os.environ['FAKE_SHUTDOWN']).touch()\n"
                       "if mode in ('timeout', 'force'): time.sleep(30)\n")
        ssh.chmod(0o755)
        os.environ['PATH'] = str(self.work) + os.pathsep + os.environ['PATH']
        finished = threading.Event()
        sent = []
        def interrupt():
            if startup:
                return
            while not finished.wait(0.01):
                if (early and pidfile.exists()) or 'READY ssh' in self.out.getvalue():
                    os.kill(os.getpid(), signal.SIGINT)
                    sent.append('first')
                    break
            if mode == 'force':
                while not finished.wait(0.01):
                    if request.exists():
                        os.kill(os.getpid(), signal.SIGINT)
                        sent.append('second')
                        break
        thread = threading.Thread(target=interrupt)
        children = []
        popen = subprocess.Popen
        def spawn(*args, **kwargs):
            child = popen(*args, **kwargs)
            children.append(child)
            if startup and not sent:
                sent.append('first')
                os.kill(os.getpid(), signal.SIGINT)  # child exists; caller has not received ownership
            return child
        previous_handler = signal.getsignal(signal.SIGINT)
        thread.start()
        try:
            argv = ['boot', str(machine), '--accel', 'tcg', '--port', str(free_port())]
            if login_key:
                argv += ['--login-key', str(self.work / 'my private key')]
            with mock.patch.object(absd_try, 'SHUTDOWN_TIMEOUT', 0.5, create=True), \
                 mock.patch.object(absd_try.subprocess, 'Popen', side_effect=spawn):
                try:
                    status = self.run_main(*argv)
                except KeyboardInterrupt:
                    self.fail('first SIGINT escaped during QEMU ownership acquisition')
            self.assertEqual(signal.getsignal(signal.SIGINT), previous_handler)
            self.assertEqual(sent[0], 'first')
            qemu = children[0]
            text = self.out.getvalue()
            self.assertTrue((machine / absd_try.DISK).is_file())
            if mode == 'clean' and not early:
                self.assertEqual(status, 0, text)
                self.assertEqual(qemu.poll(), 3)
                self.assertIn('HALTED cleanly', text)
            elif mode == 'bad-exit':
                self.assertEqual(status, 2, text)
                self.assertEqual(qemu.poll(), 0)
                self.assertNotIn('HALTED cleanly', text)
                self.assertIn('without a confirmed clean halt', text)
            elif mode == 'force':
                self.assertEqual(status, 2, text)
                self.assertIsNotNone(qemu.poll())
                self.assertIn('recovery', text.lower())
                self.assertIn('forced', text.lower())
                self.assertEqual(sent, ['first', 'second'])
            else:
                self.assertEqual(status, 2, text)
                self.assertIsNone(qemu.poll(), text)
                self.assertEqual(os.getsid(qemu.pid), qemu.pid,
                                 'terminal SIGINT must not reach QEMU directly')
                self.assertIn('still running', text)
                self.assertIn(f'PID {qemu.pid}', text)
                self.assertIn('shutdown', text)
                self.assertIn(str(machine), text)
            if early:
                self.assertFalse(request.exists(), 'no unverified SSH shutdown request')
                self.assertNotIn('HOST KEY', text)
                self.assertIn('not ready', text)
            else:
                command = json.loads(request.read_text())
                self.assertEqual(command[-2:], ['operator@127.0.0.1', 'shutdown'])
                self.assertIn('StrictHostKeyChecking=yes', command)
                self.assertIn('BatchMode=yes', command)
                self.assertIn('UserKnownHostsFile="' + str(machine / absd_try.KNOWN_HOSTS) + '"', command)
                if login_key:
                    self.assertEqual(command[command.index('-i') + 1], str(self.work / 'my private key'))
                else:
                    self.assertNotIn('-i', command)
        finally:
            finished.set()
            thread.join(timeout=2)
            signal.signal(signal.SIGINT, previous_handler)  # fixture cleanup after the restoration assertion
            for child in children:
                if child.poll() is None:
                    child.kill()  # fixture custody only, after asserting product preservation
                child.wait()

    def test_failed_qemu_creation_restores_interrupt_handler(self):
        import signal
        machine = self.created()
        previous = signal.getsignal(signal.SIGINT)
        try:
            with mock.patch.object(absd_try.subprocess, 'Popen', side_effect=OSError('fixture launch failure')):
                with self.assertRaisesRegex(OSError, 'fixture launch failure'):
                    self.run_main('boot', str(machine), '--accel', 'tcg', '--port', str(free_port()))
            self.assertEqual(signal.getsignal(signal.SIGINT), previous)
        finally:
            signal.signal(signal.SIGINT, previous)

    def test_ctrl_c_during_qemu_creation_preserves_owned_child_and_guidance(self):
        self.interrupted_boot(early=True, startup=True)

    def test_ctrl_c_clean_shutdown_with_explicit_identity(self):
        self.interrupted_boot(login_key=True)

    def test_ctrl_c_successful_ssh_is_not_a_confirmed_halt(self):
        self.interrupted_boot('bad-exit')

    def test_ctrl_c_no_identity_preserves_machine(self):
        self.interrupted_boot('no-identity')

    def test_ctrl_c_ssh_timeout_preserves_machine(self):
        self.interrupted_boot('timeout')

    def test_ctrl_c_guest_timeout_preserves_machine(self):
        self.interrupted_boot('no-halt')

    def test_second_ctrl_c_explicitly_forces_stop_with_warning(self):
        self.interrupted_boot('force')

    def test_ctrl_c_before_listening_preserves_machine(self):
        self.interrupted_boot(early=True)

    def test_boot_refuses_a_guest_address_that_is_not_an_address(self):
        machine = self.created()
        update_disk(machine / absd_try.DISK, lambda f, m: f.__setitem__(
            "/etc/network.conf", b"address 10.0.2.15,hostfwd=tcp::1-:2\n"))
        self.refused("disk_config_invalid", "boot", str(machine), "--accel", "tcg", "--port", str(free_port()))

    def test_boot_refuses_a_guest_port_that_is_not_a_port(self):
        machine = self.created()
        update_disk(machine / absd_try.DISK, lambda f, m: f.__setitem__("/etc/sshd.conf", b"port 70000\n"))
        self.refused("disk_config_invalid", "boot", str(machine), "--accel", "tcg", "--port", str(free_port()))

    def test_decode_console_splits_boots_and_refuses_a_gap(self):
        raw = b"noise\n" + framed("one\n") + framed("two\n", 4) + b"ABSD KERNEL BOOT\n" + framed("again\n")
        self.assertEqual(absd_try.decode_console(raw), ["one\ntwo\n", "again\n"])
        with self.assertRaises(absd_try.Refused) as caught:
            absd_try.decode_console(framed("one\n") + framed("lost\n", 9))
        self.assertEqual(caught.exception.reason, "console_gap")

    # boot

    def test_boot_refuses_an_unenrolled_disk(self):
        machine = self.work / "m"
        machine.mkdir()
        assets = make_assets(self.work / "assets")
        shutil.copyfile(assets / absd_try.MANIFEST, machine / absd_try.MANIFEST)
        write_disk(machine / absd_try.DISK, {"/ssh/authorized_keys": b""})
        self.refused("not_enrolled", "boot", str(machine))

    def test_boot_records_the_host_key_from_the_console(self):
        machine = self.created()
        self.assertEqual(self.run_main("boot", str(machine), "--accel", "tcg", "--port", str(free_port())), 0,
                         self.out.getvalue())
        text = self.out.getvalue()
        self.assertIn("HOST KEY GENERATED SHA256:abcdef", text)
        self.assertIn("READY ssh -p", text)
        self.assertIn("HALTED cleanly", text)
        self.assertTrue((machine / absd_try.KNOWN_HOSTS).read_text().startswith("[127.0.0.1]:"))

    def test_boot_stops_on_a_changed_host_key(self):
        machine = self.created()
        self.assertEqual(self.run_main("boot", str(machine), "--accel", "tcg", "--port", str(free_port())), 0)
        os.environ["FAKE_HOST_KEY"] = ed25519_line(b"impostor").decode().split()[1]
        self.refused("host_key_changed", "boot", str(machine), "--accel", "tcg", "--port", str(free_port()))

    def test_boot_refuses_a_port_in_use(self):
        machine = self.created()
        with socket.socket() as held:
            held.bind(("127.0.0.1", 0))
            self.refused("port_in_use", "boot", str(machine), "--port", str(held.getsockname()[1]))

    def test_kvm_is_refused_without_rdrand(self):
        saved = absd_try.host_has
        absd_try.host_has = lambda flag: False
        try:
            with self.assertRaises(absd_try.Refused) as caught:
                absd_try.accel_args("kvm", {})
            self.assertEqual(caught.exception.reason, "kvm_without_rdrand")
            self.assertEqual(absd_try.accel_args("auto", {})[1], "tcg")
        finally:
            absd_try.host_has = saved


def alive(pid):
    import time
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        try:  # a zombie child of a reaped wrapper still answers kill(0) until reaped by init
            if pathlib.Path(f"/proc/{pid}/stat").read_text().split()[2] == "Z":
                return False
        except OSError:
            return False
        time.sleep(0.1)
    return True


class ShutdownAllowance(unittest.TestCase):
    def test_downloaded_helper_matches_media_boot_shutdown_allowance(self):
        import ast
        import inspect
        import media_operator
        tree = ast.parse(inspect.getsource(media_operator.operator_boot))
        bounds = []
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
                continue
            is_request = (call.func.attr == 'run' and call.args and
                          any(isinstance(node, ast.Constant) and node.value == 'shutdown'
                              for node in ast.walk(call.args[0])))
            is_halt_wait = call.func.attr == 'wait'
            if is_request or is_halt_wait:
                bounds.extend(ast.literal_eval(option.value) for option in call.keywords
                              if option.arg == 'timeout')
        self.assertEqual(len(bounds), 2, 'find the actual SSH request and QEMU halt wait')
        self.assertEqual(bounds, [absd_try.SHUTDOWN_TIMEOUT] * 2,
                         'the standalone preview helper must follow the media shutdown allowance')


class NoBytecode(unittest.TestCase):
    """#62 item 7: running the helper from a download directory, as QUICKSTART
    does, leaves no __pycache__ there, including for its lazily imported host
    reader (absd_fs, absd_image)."""

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="test-absd-try-bytecode-"))
        self.addCleanup(shutil.rmtree, self.dir)
        here = pathlib.Path(__file__).resolve().parent
        shutil.copy(here / "absd_try.py", self.dir / "absd-try.py")
        for name in ("served_ram.py", "absd_fs.py", "absd_image.py"):
            shutil.copy(here / name, self.dir / name)
        self.env = {k: v for k, v in os.environ.items() if k not in ("PYTHONDONTWRITEBYTECODE", "PYTHONPYCACHEPREFIX")}

    def run_here(self, *argv):
        return subprocess.run([sys.executable, *argv], cwd=self.dir, env=self.env, capture_output=True, text=True)

    def test_control_plain_import_writes_bytecode(self):
        # Without the helper's setting, this interpreter would write a cache here.
        self.assertEqual(self.run_here("-c", "import served_ram").returncode, 0)
        self.assertTrue((self.dir / "__pycache__").is_dir())

    def test_helper_and_host_reader_write_no_bytecode(self):
        ran = self.run_here("absd-try.py", "--help")
        self.assertEqual(ran.returncode, 0, ran.stderr)
        # The host reader is imported lazily; reach it through the script's own namespace.
        code = ("import runpy\n"
                "g = runpy.run_path('absd-try.py')\n"
                "try:\n    g['read_tree']('missing.img')\nexcept Exception:\n    pass\n"
                "import sys\nassert 'absd_fs' in sys.modules and 'absd_image' in sys.modules\n")
        ran = self.run_here("-c", code)
        self.assertEqual(ran.returncode, 0, ran.stderr)
        self.assertFalse((self.dir / "__pycache__").exists())


# Opt-in only: never a default path, and never a protected endurance guest's image.
# Point ABSD_TRY_REAL_DISK at a built operator disk you own; the test reads a copy.
REAL_DISK = pathlib.Path(os.environ["ABSD_TRY_REAL_DISK"]) if os.environ.get("ABSD_TRY_REAL_DISK") else None


@unittest.skipUnless(REAL_DISK is not None and REAL_DISK.is_file(), "ABSD_TRY_REAL_DISK not set to an operator disk")
class RealReader(unittest.TestCase):
    """The real host reader on a copy of a built operator disk."""

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="test-absd-try-real-"))
        self.disk = self.tmp / "disk.img"
        shutil.copyfile(REAL_DISK, self.disk)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_state_and_tree_agree_and_an_identical_disk_has_no_changes(self):
        state = absd_try.read_state(self.disk)
        tree = absd_try.read_tree(self.disk)
        files = {p for p, o in state["objects"].items() if not o["dir"]}
        self.assertEqual(files, set(tree))
        self.assertTrue(any(o["dir"] for o in state["objects"].values()))
        for path, data in tree.items():
            self.assertEqual(state["objects"][path]["sha256"], absd_try.sha256_bytes(data))
        keys = tree[absd_try.KEYS_PATH]
        after = dict(state, seq=state["seq"] + 1)
        self.assertEqual(absd_try.enrol_changes(state, after, keys), [])
        self.assertTrue(absd_try.enrol_changes(state, state, keys))  # no commit happened
        absd_try.endpoint(tree)

    def test_a_used_disk_is_not_blank(self):
        tree = absd_try.read_tree(self.disk)
        with self.assertRaises(absd_try.Refused):
            absd_try.check_blank(tree, tree["/absd/selected"].decode().strip())


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--fake-qemu":
        sys.exit(fake_qemu(sys.argv[2:]))
    result = unittest.main(exit=False, verbosity=1).result
    if result.wasSuccessful():
        print(f"ABSD TRY HOST TEST OK cases={result.testsRun}")
    sys.exit(0 if result.wasSuccessful() else 1)
