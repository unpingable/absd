#!/usr/bin/env python3
"""Bounded cold-boot recovery cases for the guest file server.

Every interruption ends the exact QEMU process after a named guest
operation boundary. The next boot uses the exact same raw image. The host
reads that image through absd_fs, independently of the guest file server.
This covers three representative histories, not every sector write or a
physical power-loss model. The AG SQLite matrix remains a separate gate.
"""

import argparse
import datetime
import importlib.util
import os
import pathlib
import select
import signal
import subprocess
import sys
import time
import uuid

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ssh_absd  # noqa: E402

spec = importlib.util.spec_from_file_location("ssh_matrix", HERE / "ssh-matrix.py")
ssh_matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ssh_matrix)


class Client(ssh_matrix.Client):
    def base(self, key, extra=()):
        return super().base(key, ("-o", "IdentityAgent=none", *extra))


SIZE = 8193
OLD = bytes(i % 251 for i in range(SIZE))
PENDING = bytes((i + 17) % 251 for i in range(SIZE))
BASELINE_PATH = "/home/operator/recovery-baseline"
BASELINE = OLD[:4097]
MARKER = f"RECOVERY PENDING write_accepted bytes={SIZE}\n".encode()


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def classify_pending(tree):
    """Only whole previous or candidate content is a valid recovery view."""
    value = tree.get("/home/operator/recovery-pending")
    if value == OLD:
        return "previous"
    if value == PENDING:
        return "candidate"
    raise RuntimeError(f"pending write recovered mixed or missing content (length={len(value) if value is not None else None})")


def await_marker(pipe, marker, process, timeout=90):
    data = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"guest exited before marker: rc={process.returncode} output={bytes(data)!r}")
        readable, _, _ = select.select([pipe], [], [], min(0.2, max(0, deadline - time.monotonic())))
        if readable:
            chunk = os.read(pipe.fileno(), 4096)
            if not chunk:
                raise RuntimeError(f"guest output ended before marker: {bytes(data)!r}")
            data.extend(chunk)
            if marker in data:
                return bytes(data)
            need(len(data) <= 4096, "excess guest output before interruption marker")
    raise RuntimeError(f"guest did not report interruption marker: {bytes(data)!r}")


def image_identity(path):
    stat = path.stat()
    return (stat.st_dev, stat.st_ino, stat.st_size)


def qemu_identity(runner):
    found = []
    for pid in ssh_absd.descendants(runner.pid):
        try:
            if pathlib.Path(f"/proc/{pid}/comm").read_text().strip().startswith("qemu-system"):
                found.append((pid, pathlib.Path(f"/proc/{pid}/stat").read_text().split()[21]))
        except FileNotFoundError:
            continue
    return found


def same_process(identity):
    pid, start = identity
    try:
        fields = pathlib.Path(f"/proc/{pid}/stat").read_text().split()
        return fields[21] == start and fields[2] != "Z"
    except FileNotFoundError:
        return False


def interrupt(target, label):
    """End only this target's QEMU session, without an orderly guest end."""
    runner = target.proc
    need(runner is not None and runner.poll() is None, f"{label}: QEMU runner is not live")
    serial = target.serial()
    need("FSD READY " in serial and "ABSD BOOT OK" not in serial,
         f"{label}: no live file server or boot already ended")
    identity = image_identity(target.image)
    qemu = qemu_identity(runner)
    need(len(qemu) == 1, f"{label}: expected one owned QEMU descendant, found {qemu}")
    os.kill(qemu[0][0], signal.SIGKILL)
    runner.wait(timeout=30)
    status = runner.stdout.read().decode(errors="replace").strip()
    need(status == "137", f"{label}: expected SIGKILL QEMU status 137, got {status!r}")
    need(not same_process(qemu[0]), f"{label}: original QEMU process still exists")
    need(image_identity(target.image) == identity, f"{label}: disk pathname or size changed")
    need("ABSD BOOT OK" not in target.serial(), f"{label}: orderly boot end in interrupted transcript")
    print(f"CORE FSD INTERRUPT case={label} runner_pid={runner.pid} qemu_pid={qemu[0][0]} qemu_start={qemu[0][1]} qemu_status={status} image={target.image} serial={target.log}", flush=True)
    return identity


def recover(target, client, key, identity, label, expected, read_path, read_bytes):
    need(image_identity(target.image) == identity, f"{label}: reboot would use a different disk")
    boot = target.start(expect_sweep=True)
    need(image_identity(target.image) == identity, f"{label}: reboot replaced the disk")
    need(not boot["generated"] and "FSD READY " in target.serial(),
         f"{label}: a new file server did not mount the same disk")
    tree = target.tree()
    need(tree.get(BASELINE_PATH) == BASELINE, f"{label}: independent baseline changed across the interruption")
    outcome = expected(tree)
    # A fresh guest request must pass through the recovered file server.
    rc, out, err = client.run(key, f"/bin/cat {read_path}")
    need(rc == 0 and out == read_bytes and err == b"",
         f"{label}: recovered server read failed rc={rc} bytes={len(out)} err={err!r}")
    print(f"CORE FSD RECOVERED case={label} outcome={outcome} image={target.image} serial={target.log}", flush=True)
    return tree


def command(client, key, argv, answer):
    rc, out, err = client.run(key, argv)
    need(rc == 0 and out.startswith(answer) and err == b"",
         f"{argv}: rc={rc} out={out!r} err={err!r}")


def run(args):
    root = pathlib.Path(args.work).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    need(root.stat().st_mode & 0o077 == 0, "work root must be owner-only for the local test key")
    work = root / str(uuid.uuid4())
    work.mkdir(mode=0o700)
    need(work.stat().st_mode & 0o077 == 0, "work directory must be owner-only for the local test key")
    print(f"CORE FSD WORK run={work.name} path={work}", flush=True)
    target = ssh_absd.target(["--kernel", args.kernel, "--platform", args.platform,
                              "--shell", args.shell, "--qemu", args.qemu,
                              "--boot-seconds", "1200"])
    key = work / "operator"
    success = False
    fingerprint = "unavailable"
    review = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)).date().isoformat()
    try:
        subprocess.run([ssh_matrix.KEYGEN, "-q", "-t", "ed25519", "-N", "",
                        "-C", f"core-fsd-recovery-{work.name}", "-f", str(key)], check=True)
        public = key.with_suffix(".pub")
        fingerprint = subprocess.run([ssh_matrix.KEYGEN, "-lf", str(public)], check=True,
                                     capture_output=True, text=True).stdout.split()[1]
        print(f"CORE FSD KEY run={work.name} fingerprint={fingerprint} "
              f"destination=local-vm-operator path={key} owner_only=true", flush=True)
        target.setup(work, public.read_text())
        target.start(fresh=True)
        client = Client(work, target.port)
        client.trust(target.host_public_from_image())
        path = "/home/operator/recovery-pending"
        command(client, key, f"/bin/fsd-probe write {BASELINE_PATH} 4097", b"write: 4097 bytes ")
        need(target.tree().get(BASELINE_PATH) == BASELINE, "initial independent baseline differs from host oracle")
        command(client, key, f"/bin/fsd-probe write {path} {SIZE}", f"write: {SIZE} bytes ".encode())
        need(target.tree().get(path) == OLD, "initial committed content differs from host oracle")

        # WRITE_AT answered while its handle is open and unsynced. The SSH
        # command remains live when the host ends QEMU.
        process = subprocess.Popen(client.base(key) + [f"/bin/fsd-probe recovery-pending {path} {SIZE}"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            shown = await_marker(process.stdout, MARKER, process)
            need(MARKER in shown and process.poll() is None, "pending write did not reach its live boundary")
            identity = interrupt(target, "open_write")
        finally:
            try:
                process.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
        cold = target.tree()  # independent structural and content check before any recovery boot
        outcome = classify_pending(cold)
        print(f"CORE FSD HOST ORACLE case=open_write outcome={outcome}", flush=True)
        recover(target, client, key, identity, "open_write",
                lambda tree: outcome if classify_pending(tree) == outcome else need(False, "pending outcome changed on recovery boot"),
                path, OLD if outcome == "previous" else PENDING)

        # A completed sync must survive an abrupt stop and cold boot.
        committed = "/home/operator/recovery-committed"
        command(client, key, f"/bin/fsd-probe write {committed} {SIZE}", f"write: {SIZE} bytes ".encode())
        need(target.tree().get(committed) == OLD, "sync was not visible to the independent reader")
        identity = interrupt(target, "synced_write")
        need(target.tree().get(committed) == OLD, "synced bytes absent after interruption")
        recover(target, client, key, identity, "synced_write",
                lambda tree: "committed" if tree.get(committed) == OLD else need(False, "synced bytes lost"),
                committed, OLD)

        # Rename replacement commits a complete namespace transition.
        old_path = "/home/operator/recovery-old"
        new_path = "/home/operator/recovery-new"
        command(client, key, f"/bin/fsd-probe write {old_path} {SIZE}", f"write: {SIZE} bytes ".encode())
        command(client, key, f"/bin/fsd-probe write {new_path} 4097", b"write: 4097 bytes ")
        command(client, key, f"/bin/fsd-probe rename {old_path} {new_path}", b"rename: OK ")
        identity = interrupt(target, "rename_replace")
        def renamed(tree):
            need(old_path not in tree and tree.get(new_path) == OLD, "rename replacement recovered an incomplete namespace")
            return "replaced"
        renamed(target.tree())
        recover(target, client, key, identity, "rename_replace", renamed, new_path, OLD)
        success = True
    finally:
        runner = target.proc
        had_live_runner = runner is not None and runner.poll() is None
        qemu = qemu_identity(runner) if had_live_runner else []
        try:
            target.stop()
        finally:
            # Waiting for the wrapper is not evidence that its QEMU child
            # ended. Keep disk and key if that exact consumer is still live
            # or cannot be identified for the successful final boot.
            uncertain = runner is not None and (not had_live_runner or len(qemu) != 1 or same_process(qemu[0]))
            if uncertain:
                print(f"CORE FSD CUSTODY run={work.name} qemu={qemu} image=retained "
                      f"private_key=retained reason=live_or_unresolved_consumer review={review}", flush=True)
                raise RuntimeError("cannot retire image or key: final QEMU exit is unverified")
            # The run's exact private identity has no consumer after the
            # VM stops. Logs remain for result review; a failed image
            # remains for bounded diagnosis. A successful image and
            # importer inputs are reproducible substrate and retire here.
            key.unlink(missing_ok=True)
            if success:
                target.image.unlink(missing_ok=True)
                for source in work.glob("input-*.bin"):
                    source.unlink()
            print(f"CORE FSD CUSTODY run={work.name} fingerprint={fingerprint} private_key=retired "
                  f"image={'retired' if success else 'retained_for_diagnosis'} "
                  f"logs=retained review={review}", flush=True)
    if success:
        print("ABSD RUST CORE FSD RECOVERY OK cases=3 guest_fsd=ready host_oracle=agree", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True, help="admitted work root; each attempt gets a unique child")
    ap.add_argument("--kernel", required=True)
    ap.add_argument("--platform", default=str(HERE.parent))
    ap.add_argument("--shell", required=True)
    ap.add_argument("--qemu", default="qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand")
    run(ap.parse_args())


if __name__ == "__main__":
    main()
