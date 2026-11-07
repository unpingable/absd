#!/usr/bin/env python3
"""Bounded interruption and cold-refusal cases for the guest file server.

Every case has a fresh image and ends its exact QEMU process after a named
operation boundary. The host checks complete file contents independently.
The next boot uses that same interrupted image and must refuse writable
entry without a checked storage fence, issuing no writes or flushes. This
covers three histories, not every sector write or physical power loss.
The AG SQLite matrix remains a separate gate.
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
import storage_fence_guest as fence_guest  # noqa: E402

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


def refuse_recovery(target, identity, label, expected):
    need(image_identity(target.image) == identity, f"{label}: reboot would use a different disk")
    before = target.tree()
    need(before.get(BASELINE_PATH) == BASELINE, f"{label}: independent baseline changed")
    outcome = expected(before)
    refusal = fence_guest.refused_cold_boot(target, "ata", label + "-refused", served=False)
    need(image_identity(target.image) == identity, f"{label}: reboot replaced the disk")
    after = target.tree()
    need(after == before, f"{label}: cold refusal changed filesystem contents")
    need(expected(after) == outcome, f"{label}: cold refusal changed the host outcome")
    print(f"CORE FSD COLD REFUSAL case={label} outcome={outcome} "
          f"image={target.image} serial={refusal['log']} image_unchanged=true", flush=True)


def command(client, key, argv, answer):
    rc, out, err = client.run(key, argv)
    need(rc == 0 and out.startswith(answer) and err == b"",
         f"{argv}: rc={rc} out={out!r} err={err!r}")


def run_case(args, work, key, label):
    # An interrupted generation cannot authorize the next case's writes.
    work.mkdir(mode=0o700)
    target = ssh_absd.target(["--kernel", args.kernel, "--platform", args.platform,
                              "--shell", args.shell, "--qemu", args.qemu,
                              "--boot-seconds", "1200"])
    try:
        target.setup(work, key.with_suffix(".pub").read_text())
        target.start(fresh=True)
        client = Client(work, target.port)
        client.trust(target.host_public_from_image())
        path = "/home/operator/recovery-pending"
        command(client, key, f"/bin/fsd-probe write {BASELINE_PATH} 4097", b"write: 4097 bytes ")
        need(target.tree().get(BASELINE_PATH) == BASELINE, "initial independent baseline differs from host oracle")
        command(client, key, f"/bin/fsd-probe write {path} {SIZE}", f"write: {SIZE} bytes ".encode())
        need(target.tree().get(path) == OLD, "initial committed content differs from host oracle")

        if label == "open_write":
            # WRITE_AT answered while its handle is open and unsynced.
            process = subprocess.Popen(client.base(key) + [f"/bin/fsd-probe recovery-pending {path} {SIZE}"],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                shown = await_marker(process.stdout, MARKER, process)
                need(MARKER in shown and process.poll() is None, "pending write did not reach its live boundary")
                identity = interrupt(target, label)
            finally:
                try:
                    process.communicate(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
            outcome = classify_pending(target.tree())
            expected = classify_pending
        elif label == "synced_write":
            committed = "/home/operator/recovery-committed"
            command(client, key, f"/bin/fsd-probe write {committed} {SIZE}", f"write: {SIZE} bytes ".encode())
            need(target.tree().get(committed) == OLD, "sync was not visible to the independent reader")
            identity = interrupt(target, label)

            def expected(tree):
                need(tree.get(committed) == OLD, "synced bytes lost")
                return "committed"

            outcome = expected(target.tree())
        elif label == "rename_replace":
            old_path = "/home/operator/recovery-old"
            new_path = "/home/operator/recovery-new"
            command(client, key, f"/bin/fsd-probe write {old_path} {SIZE}", f"write: {SIZE} bytes ".encode())
            command(client, key, f"/bin/fsd-probe write {new_path} 4097", b"write: 4097 bytes ")
            command(client, key, f"/bin/fsd-probe rename {old_path} {new_path}", b"rename: OK ")
            identity = interrupt(target, label)

            def expected(tree):
                need(old_path not in tree and tree.get(new_path) == OLD, "rename replacement recovered an incomplete namespace")
                return "replaced"

            outcome = expected(target.tree())
        else:
            raise RuntimeError(f"unknown interruption case: {label}")
        print(f"CORE FSD HOST ORACLE case={label} outcome={outcome}", flush=True)
        refuse_recovery(target, identity, label, expected)
        return target
    finally:
        target.stop()


def run(args):
    root = pathlib.Path(args.work).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    need(root.stat().st_mode & 0o077 == 0, "work root must be owner-only for the local test key")
    work = root / str(uuid.uuid4())
    work.mkdir(mode=0o700)
    print(f"CORE FSD WORK run={work.name} path={work}", flush=True)
    key = work / "operator"
    success = False
    targets = []
    fingerprint = "unavailable"
    review = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)).date().isoformat()
    try:
        subprocess.run([ssh_matrix.KEYGEN, "-q", "-t", "ed25519", "-N", "",
                        "-C", f"core-fsd-refusal-{work.name}", "-f", str(key)], check=True)
        fingerprint = subprocess.run([ssh_matrix.KEYGEN, "-lf", str(key.with_suffix(".pub"))], check=True,
                                     capture_output=True, text=True).stdout.split()[1]
        print(f"CORE FSD KEY run={work.name} fingerprint={fingerprint} "
              f"destination=local-vm-operator path={key} owner_only=true", flush=True)
        for label in ("open_write", "synced_write", "rename_replace"):
            targets.append(run_case(args, work / label, key, label))
        success = True
    finally:
        # A successful case verified the writer's exact QEMU exit and the
        # cold boot's terminal refusal. On any incomplete path retain the
        # private fixture for explicit campaign process/custody reconciliation;
        # do not replace the original exception with a cleanup exception.
        if success:
            key.unlink(missing_ok=True)
            for target in targets:
                target.image.unlink(missing_ok=True)
                for source in target.work.glob("input-*.bin"):
                    source.unlink()
        print(f"CORE FSD CUSTODY run={work.name} fingerprint={fingerprint} "
              f"private_key={'retired' if success else 'retained'} "
              f"image={'retired' if success else 'retained_for_reconciliation'} "
              f"logs=retained review={review}", flush=True)
    print("ABSD RUST CORE FSD REFUSAL OK cases=3 guest_fsd=refused host_oracle=agree", flush=True)


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
