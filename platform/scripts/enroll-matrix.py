#!/usr/bin/env python3
"""The enrollment image's case matrix (slice A).

Builds two durable ISOs from one kernel checkout: an importer image whose
embedded fixture lays out a small operator disk (the release's blank-disk
shape: /absd/selected, /etc, /home/operator, an empty writable
/ssh/authorized_keys placeholder, no host key seed), and the dedicated
enrollment image (`make ENROLL_STREAM=1`, worker absd-enroll.elf, step 1).
Then it boots the enrollment image once per case against a copy of the
blank disk and sends the case's stream over absd-stream-v1, with the
helper's own code (scripts/absd_try.py) as the host side and the host
reader (scripts/absd_fs.py) as the oracle:

    happy        ENROLL OK keys=1 sha256=<sent>, exactly one commit,
                 /ssh/authorized_keys = the sent bytes, every other object
                 identical (absd_try.enrol_changes); then a second
                 enrollment of two keys on the same disk, again one commit
    malformed    ENROLL REFUSED reason=malformed, disk image byte-identical
    duplicate    ENROLL REFUSED reason=duplicate, disk byte-identical
    empty        ENROLL REFUSED reason=empty, disk byte-identical
    extra-file   a second record: reason=extra-file, disk byte-identical
    non-key-path /etc/rc as the record's path: reason=path, byte-identical
    interrupted  (a) the host stops mid-stream, or sends the whole record but
                 never the end of the stream: init refuses the stream
                 (EXTERNAL INPUT REFUSED), no ENROLL OK, disk byte-identical;
                 (b) QEMU is killed (SIGKILL) at delays after the worker's
                 ENROLL MOUNT line: the disk holds the old state (placeholder
                 empty, same commit) or the new one (the sent key, one
                 commit), nothing else, and a fresh enrollment then succeeds
    unformatted  a blank device: reason=storage (never formats), disk
                 still all zero
    no-placeholder  a disk without /ssh/authorized_keys: reason=placeholder,
                 byte-identical

Every refused case also requires no `ENROLL OK` line and a failed boot.
Prints `ABSD ENROLL MATRIX OK cases=N` or exits 1 at the first failure.
Writes result.json and each case's console log under --work.
"""

import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import absd_try  # noqa: E402
from served_kernel import kernel_make  # noqa: E402
from served_ram import served_qemu

DISK_BYTES = 16 * 1024 * 1024
KEYS = absd_try.KEYS_PATH
ED25519_PREFIX = absd_try.ED25519_PREFIX
ENROLL_REFUSED = re.compile(r"^ENROLL REFUSED reason=(\S+)", re.M)
BOOT_SECONDS = 600


class Failed(Exception):
    pass


def require(ok, what):
    if not ok:
        raise Failed(what)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def key_line(byte, comment="user@host"):
    blob = ED25519_PREFIX + bytes([byte]) * 32
    return b"ssh-ed25519 " + base64.b64encode(blob) + b" " + comment.encode() + b"\n"


def record(path, data):
    name = path.encode()
    return struct.pack("<H", len(name)) + name + struct.pack("<Q", len(data)) + hashlib.sha256(data).digest() + data


def stream(*records):
    return b"ABSDFIX1" + b"".join(records) + struct.pack("<H", 0)


def blank_tree(release_id):
    """The release's blank operator disk, in miniature."""
    return [
        ("/absd/selected", release_id.encode() + b"\n"),
        ("/etc/rc", b"# enroll-matrix fixture\n"),
        ("/etc/hostname", b"absd\n"),
        ("/home/operator/", b""),
        (KEYS, b""),
    ]


def make(kernel, out, log, **variables):
    argv = [*kernel_make(), "--no-print-directory", "-C", str(kernel), "durable-iso"] + [f"{k}={v}" for k, v in variables.items()]
    with open(log, "ab") as f:
        f.write(("$ " + " ".join(argv) + "\n").encode())
        f.flush()
        subprocess.run(argv, check=True, stdout=f, stderr=subprocess.STDOUT)
    built = pathlib.Path(kernel) / f"build/durable/absd-durable-{variables['DURABLE_STEP']}.iso"
    shutil.copyfile(built, out)
    return sha(out.read_bytes())


def qemu_argv(iso, disk, serial):
    return [*served_qemu(["qemu-system-x86_64"]), "-cpu", "max,vendor=GenuineIntel,+rdrand", "-cdrom", str(iso),
            "-drive", f"file={disk},format=raw,if=ide,index=0", "-nic", "none", "-display", "none",
            *serial, "-no-reboot", "-no-shutdown", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]


def boot_embedded(iso, disk, log):
    """An importer boot: its input is embedded; the console goes to a file."""
    status = subprocess.run(qemu_argv(iso, disk, ["-serial", f"file:{log}"]), timeout=BOOT_SECONDS,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
    return status, absd_try.decode_console(log.read_bytes())


def boot_enroll(iso, disk, log, payload, cut_at=None, kill_after_mount=None, withhold_end=False):
    """One enrollment boot. Sends `payload` over absd-stream-v1: whole, or
    stopping inside a chunk after `cut_at` payload bytes, or (`withhold_end`)
    whole but never sending the zero-length chunk that ends the stream. Or
    kills QEMU `kill_after_mount` seconds after the worker's ENROLL MOUNT line.
    Returns (QEMU status, raw console, killed)."""
    with tempfile.TemporaryDirectory(prefix="enroll-matrix-") as work:
        sock_path = pathlib.Path(work) / "console.sock"
        qemu = subprocess.Popen(qemu_argv(iso, disk, ["-chardev", f"socket,id=con,path={sock_path},server=on,wait=on",
                                                      "-serial", "chardev:con"]),
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + BOOT_SECONDS
        raw = bytearray()
        killed = False
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            while True:
                try:
                    sock.connect(str(sock_path))
                    break
                except OSError:
                    require(qemu.poll() is None and time.monotonic() < deadline, "QEMU did not open its console")
                    time.sleep(0.05)
            sock.settimeout(0.05)
            pending = bytearray()
            offset, header_sent, accepted, done, closed = 0, False, False, False, False
            limit = len(payload) if cut_at is None else cut_at
            mounted_at = None
            while time.monotonic() < deadline:
                if mounted_at is not None and time.monotonic() >= mounted_at + kill_after_mount:
                    qemu.send_signal(signal.SIGKILL)
                    killed = True
                    break
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    if qemu.poll() is not None:
                        break
                    continue
                if not chunk:
                    break
                raw.extend(chunk)
                if kill_after_mount is not None and mounted_at is None:
                    if "ENROLL MOUNT" in "".join(absd_try.decode_console(bytes(raw[:raw.rfind(b"\n") + 1]))):
                        mounted_at = time.monotonic()
                pending.extend(chunk)
                while b"\n" in pending and not closed:
                    line, _, rest = pending.partition(b"\n")
                    pending = bytearray(rest)
                    line = line.rstrip(b"\r")
                    if absd_try.STREAM_READY.fullmatch(line) and not header_sent:
                        sock.sendall(absd_try.STREAM_MAGIC)
                        header_sent = True
                    elif line == absd_try.STREAM_ACCEPTED and header_sent:
                        accepted = True
                    elif accepted and not done:
                        credit = absd_try.STREAM_CREDIT.fullmatch(line)
                        if credit is None:
                            continue
                        require(int(credit.group(1)) == offset, f"credit at {credit.group(1)}, sent {offset}")
                        piece = payload[offset:min(limit, offset + int(credit.group(2)))]
                        if withhold_end and not piece:
                            # Every byte of the inner record is across; the
                            # stream's end never comes.
                            closed = True
                            break
                        if cut_at is not None and not piece:
                            # Interrupted: a chunk header promising bytes that never
                            # come. The console stays open (QEMU drops the guest's
                            # output to a half-closed socket), so init's refusal is seen.
                            sock.sendall((1).to_bytes(2, "big"))
                            closed = True
                            break
                        sock.sendall(len(piece).to_bytes(2, "big") + piece)
                        offset += len(piece)
                        done = not piece
            sock.close()
            status = qemu.wait(timeout=max(1, deadline - time.monotonic()))
        except BaseException:
            if qemu.poll() is None:
                qemu.kill()
                qemu.wait()
            raise
        log.write_bytes(bytes(raw))
        return status, bytes(raw), killed


def worker_text(raw):
    whole = bytes(raw[:raw.rfind(b"\n") + 1])
    return "".join(absd_try.decode_console(whole))


class Matrix:
    def __init__(self, args):
        self.args = args
        self.work = pathlib.Path(args.work).resolve()
        if self.work.exists():
            shutil.rmtree(self.work)
        self.work.mkdir(parents=True)
        self.result = {"cases": {}, "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        self.count = 0

    def ok(self, what, cond, detail=""):
        print(("  ok   " if cond else "  FAIL ") + what + ("" if cond else f": {detail}"), flush=True)
        require(cond, f"{what}: {detail}")
        self.count += 1

    def build(self):
        a, w = self.args, self.work
        release_id = "absd-enroll-matrix"
        fixture = w / "blank-fixture.bin"
        fixture.write_bytes(stream(*[record(p, d) for p, d in blank_tree(release_id)]))
        bare = w / "bare-fixture.bin"  # no placeholder
        bare.write_bytes(stream(*[record(p, d) for p, d in blank_tree(release_id) if p != KEYS]))
        empty_input = w / "empty-input.bin"
        empty_input.write_bytes(b"")
        log = w / "build.log"
        common = {"DURABLE_STEP": 1}
        self.import_iso = w / "import.iso"
        self.bare_iso = w / "import-bare.iso"
        self.enroll_iso = w / "enroll.iso"
        self.result["isos"] = {
            "import": make(a.kernel, self.import_iso, log, EXTERNAL_USER_ELF=a.importer, EXTERNAL_INPUT=fixture, **common),
            "import_bare": make(a.kernel, self.bare_iso, log, EXTERNAL_USER_ELF=a.importer, EXTERNAL_INPUT=bare, **common),
            "enroll": make(a.kernel, self.enroll_iso, log, EXTERNAL_USER_ELF=a.enroll, EXTERNAL_INPUT=empty_input,
                           ENROLL_STREAM=1, **common),
        }
        self.result["elfs"] = {"importer": sha(pathlib.Path(a.importer).read_bytes()),
                               "enroll": sha(pathlib.Path(a.enroll).read_bytes())}
        self.blank = w / "blank.img"
        self.bare = w / "bare.img"
        for iso, image, name in ((self.import_iso, self.blank, "blank"), (self.bare_iso, self.bare, "bare")):
            image.write_bytes(bytes(DISK_BYTES))
            status, streams = boot_embedded(iso, image, w / f"{name}.serial.log")
            text = streams[-1] if streams else ""
            self.ok(f"{name} disk: the importer formatted it and laid out the operator tree (status {status})",
                    status == 3 and "FIXTURE IMPORT OK files=" in text, text[-300:])
        tree = absd_try.read_tree(self.blank)
        self.ok("blank disk: the placeholder is present and empty, no host key seed, /absd/selected names the release",
                tree.get(KEYS) == b"" and absd_try.SEED_PATH not in tree
                and tree.get(absd_try.SELECTED_PATH, b"").strip() == release_id.encode(), str(sorted(tree)))

    def disk(self, name, source=None):
        image = self.work / f"{name}.img"
        shutil.copyfile(source or self.blank, image)
        return image

    def happy(self, name, image, payload, keys_bytes, count):
        before = absd_try.read_state(image)
        status, raw, _ = boot_enroll(self.enroll_iso, image, self.work / f"{name}.serial.log", payload)
        text = worker_text(raw)
        found = absd_try.ENROLL_OK.search(text)
        self.ok(f"{name}: ENROLL OK keys={count} sha256 of the sent bytes, orderly end (status {status})",
                status == 3 and found is not None and int(found.group(1)) == count and found.group(2) == sha(keys_bytes),
                text[-400:])
        after = absd_try.read_state(image)
        changes = absd_try.enrol_changes(before, after, keys_bytes)
        self.ok(f"{name}: exactly one commit ({before['seq']} -> {after['seq']}), {KEYS} is the sent bytes, every other "
                f"object, the filesystem id and format unchanged", not changes, str(changes))
        self.ok(f"{name}: the host reader reads {count} key(s) under sshd's rules",
                len(absd_try.key_lines(absd_try.read_tree(image)[KEYS])) == count)
        return {"status": status, "seq": [before["seq"], after["seq"]], "keys": count, "sha256": sha(keys_bytes)}

    def refused(self, name, image, payload, reason, cut_at=None, withhold_end=False):
        before = image.read_bytes()
        status, raw, _ = boot_enroll(self.enroll_iso, image, self.work / f"{name}.serial.log", payload, cut_at=cut_at,
                                     withhold_end=withhold_end)
        text = worker_text(raw)
        console = raw.decode(errors="replace")
        if reason == "stream":
            got = absd_try.STREAM_REFUSED.search(raw)
            self.ok(f"{name}: init refuses the interrupted stream (EXTERNAL INPUT REFUSED"
                    f" reason={got.group(1).decode() if got else '?'}) and the boot fails (status {status})",
                    got is not None and status != 3, console[-400:])
        else:
            got = ENROLL_REFUSED.search(text)
            self.ok(f"{name}: the worker refuses it by name (ENROLL REFUSED reason={got.group(1) if got else '?'}) and "
                    f"the boot fails (status {status})", got is not None and got.group(1) == reason and status != 3,
                    text[-400:] or console[-400:])
        self.ok(f"{name}: no ENROLL OK, and the disk image is byte-identical",
                absd_try.ENROLL_OK.search(text) is None and image.read_bytes() == before)
        return {"status": status, "refused": reason, "disk_unchanged": True}

    def run(self):
        self.build()
        one = key_line(1)
        two = key_line(1, "a") + key_line(2, "b")
        cases = self.result["cases"]
        # happy path, then a second enrollment (two keys) on the same disk
        image = self.disk("happy")
        cases["happy"] = self.happy("happy", image, stream(record(KEYS, one)), one, 1)
        cases["happy-again"] = self.happy("happy-again", image, stream(record(KEYS, two)), two, 2)
        # refusals before the filesystem is touched
        for name, payload, reason in (
            ("malformed", stream(record(KEYS, b"ssh-rsa AAAAB3NzaC1yc2E user\n")), "malformed"),
            ("malformed-options", stream(record(KEYS, b'command="/bin/sh" ' + one)), "malformed"),
            ("duplicate", stream(record(KEYS, one + key_line(1, "again"))), "duplicate"),
            ("empty", stream(record(KEYS, b"")), "empty"),
            ("empty-comments", stream(record(KEYS, b"# no keys\n")), "empty"),
            ("extra-file", stream(record(KEYS, one), record("/etc/rc", b"evil\n")), "extra-file"),
            ("non-key-path", stream(record("/etc/rc", one)), "path"),
            ("no-record", stream(), "no-record"),
            ("digest", stream(record(KEYS, one))[:-3] + b"X" + stream(record(KEYS, one))[-2:], "digest"),
        ):
            cases[name] = self.refused(name, self.disk(name), payload, reason)
        # interrupted (a): the host stops mid-stream
        full = stream(record(KEYS, one))
        cases["interrupted-stream"] = self.refused("interrupted-stream", self.disk("interrupted-stream"), full,
                                                   "stream", cut_at=len(full) // 2)
        # interrupted (a'): the whole inner record arrives, the stream's end does
        # not; init must stop the worker before it can see end of file
        cases["interrupted-before-end"] = self.refused("interrupted-before-end", self.disk("interrupted-before-end"),
                                                       full, "stream", withhold_end=True)
        # interrupted (b): a power cut after the worker mounted
        cuts = {}
        blank_state = absd_try.read_state(self.blank)
        for delay in self.args.kill_delays:
            name = f"interrupted-kill-{int(delay * 1000)}ms"
            image = self.disk(name)
            status, raw, killed = boot_enroll(self.enroll_iso, image, self.work / f"{name}.serial.log", full,
                                              kill_after_mount=delay)
            after = absd_try.read_state(image)
            keys = absd_try.read_tree(image).get(KEYS)
            old = after == blank_state
            new = not absd_try.enrol_changes(blank_state, after, one)
            finished = not killed and status == 3 and absd_try.ENROLL_OK.search(worker_text(raw)) is not None
            self.ok(f"{name}: {'QEMU killed after ENROLL MOUNT' if killed else 'the enrollment finished before the cut'}; "
                    f"the disk holds the old state or the new one, nothing else "
                    f"({'new' if new else 'old' if old else 'NEITHER'}, seq {after['seq']})",
                    (killed and (old or new)) or (finished and new), f"{status} {after['seq']} {keys!r:.80}")
            if old:
                self.ok(f"{name}: the unenrolled disk is refused by the helper's boot check (no key)",
                        absd_try.enrolled(absd_try.read_tree(image)) == [])
            again = self.happy(f"{name}-again", image, stream(record(KEYS, two)), two, 2)
            cuts[name] = {"killed": killed, "state": "new" if new else "old", "seq": after["seq"], "again": again}
        cases["interrupted-kill"] = cuts
        # a blank device is never formatted; a disk without the placeholder is refused
        zero = self.work / "unformatted.img"
        zero.write_bytes(bytes(DISK_BYTES))
        cases["unformatted"] = self.refused("unformatted", zero, full, "storage")
        self.ok("unformatted: the device is still all zero", zero.read_bytes() == bytes(DISK_BYTES))
        cases["no-placeholder"] = self.refused("no-placeholder", self.disk("no-placeholder", self.bare), full, "placeholder")
        self.result["checks"] = self.count
        self.result["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        (self.work / "result.json").write_text(json.dumps(self.result, indent=1) + "\n")
        for image in self.work.glob("*.img"):
            image.unlink()
        print(f"ABSD ENROLL MATRIX OK cases={len(cases)} checks={self.count}")


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--kernel", required=True, help="kernel checkout (make durable-iso)")
    p.add_argument("--importer", required=True, help="fixture-import.elf")
    p.add_argument("--enroll", required=True, help="absd-enroll.elf")
    p.add_argument("--work", required=True)
    p.add_argument("--kill-delays", type=float, nargs="+", default=[0.0, 0.001, 0.002, 0.005, 0.01, 0.02])
    args = p.parse_args()
    for name in ("importer", "enroll"):
        setattr(args, name, str(pathlib.Path(getattr(args, name)).resolve()))
    try:
        Matrix(args).run()
    except (Failed, absd_try.Refused, subprocess.SubprocessError) as error:
        print(f"ABSD ENROLL MATRIX FAILED: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
