#!/usr/bin/env python3
"""One served startup refusal: a bad local config must not reset-loop."""

import argparse
import importlib.util
import os
import pathlib
import re
import signal
import subprocess

here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("survival_recovery", here / "survival-recovery.py")
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class BadConfigTarget(recovery.RecoveryTarget):
    def files(self, authorized):
        return super().files(authorized) + [("/etc/sshd.conf", b"max-connections 5\n")]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--qemu", default="qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand")
    args = parser.parse_args()
    key = pathlib.Path(args.key).resolve()
    if not key.is_file() or not key.with_suffix(".pub").is_file():
        parser.error("exact campaign key and public key must already exist")
    work = pathlib.Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=False)

    target = BadConfigTarget.__new__(BadConfigTarget)
    target.kernel = pathlib.Path(args.kernel).resolve()
    target.root = pathlib.Path(args.platform).resolve()
    target.qemu = args.qemu
    target.shell = target.root / "commands/absd-sh"
    target.boot_seconds = 180
    target.proc, target.boots, target.port = None, 0, None
    target.component = "sshd"
    target.sshd_elf = target.root / "sshd.elf"
    target.fsd_elf = target.root / "absd-fsd.elf"
    target.setup(work, key.with_suffix(".pub").read_text())

    iso = target.sshd_iso()
    log = work / "pre-ready.serial.log"
    env = os.environ.copy()
    env["ABSD_QEMU_REBOOT"] = "allow"
    command = [str(target.kernel / "scripts/durable-boot.sh"), str(iso),
               str(target.image), str(log), "120", *args.qemu.split(),
               "-netdev", "user,id=n0,net=10.0.2.0/24", "-device", "e1000,netdev=n0"]
    runner = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, env=env, start_new_session=True)
    try:
        stdout, stderr = runner.communicate(timeout=180)
    except subprocess.TimeoutExpired as error:
        # This exact campaign-owned process group contains the wrapper,
        # its timeout command and the local QEMU instance.
        os.killpg(runner.pid, signal.SIGTERM)
        try:
            runner.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(runner.pid, signal.SIGKILL)
            runner.communicate()
        raise RuntimeError("pre-ready VM outcome indeterminate after outer timeout") from error
    raw = log.read_bytes()
    serial = raw.decode(errors="replace")
    boots = raw.count(b"ABSD KERNEL BOOT\n")
    captured = recovery.served.captured_all(raw)
    worker = captured[0] if len(captured) == 1 else ""
    if runner.returncode != 0 or stdout.strip() != "7":
        raise RuntimeError(f"pre-ready boot did not fail once: wrapper={runner.returncode} status={stdout!r} stderr={stderr!r}")
    if boots != 1 or "SSH LISTENING" in worker or "MACHINE RECOVER RESET" in serial:
        raise RuntimeError("pre-ready failure reached a listener or machine reset")
    if "SERVED RECOVERY REFUSED generation_not_ready" not in serial:
        raise RuntimeError("init did not refuse automatic recovery before readiness")
    if not re.search(r"max-connections.*(?:outside|range|1 to 4|between)", worker, re.IGNORECASE):
        raise RuntimeError("the intended malformed configuration was not diagnosed")
    print("SERVED PRE-READY REFUSAL OK boots=1 reset=0 listener=0", flush=True)


if __name__ == "__main__":
    main()
