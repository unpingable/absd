#!/usr/bin/env python3
"""Writable-entry fence matrix, including unverified declarations and plain fsd.

Each former declaration-admission case now requires refusal after an unclean
end. The same image is also cold-booted with an external declaration and as
plain `net fsd`, with exact zero-write/flush and unchanged-image assertions.
Orderly served reboot and two successful bounded boots remain positive cases.
The original backend/fault inputs are retained; no declaration overrides the
private guard. See docs/WRITABLE-ENTRY.md.
"""

import argparse
import importlib.util
import os
import pathlib
import re

import storage_fence_guest as guest
import storage_fence_state as guard

here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("survival_recovery", here / "survival-recovery.py")
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)

# backend, declaration (None: no option), kernel fence word, kernel reason, outcome
CASES = {
    "ata-undeclared": ("ata", None, "none", "not_declared", "refused"),
    "ata-controller": ("ata", "controller", "none", "no_controller_reset", "refused"),
    "nvme-undeclared": ("nvme", None, "none", "not_declared", "refused"),
    "nvme-invalid": ("nvme", "reset", "none", "invalid_declaration", "refused"),
    "nvme-controller": ("nvme", "controller", "none", "backend_unverified", "refused"),
    "ata-external": ("ata", "external", "none", "external_unverified", "refused"),
    "nvme-external": ("nvme", "external", "none", "external_unverified", "refused"),
    "ata-bounded": ("ata", None, "none", "not_declared", "bounded"),
    "nvme-bounded": ("nvme", None, "none", "not_declared", "bounded"),
    "ata-reboot": ("ata", None, "none", "not_declared", "clean"),
}
# init's status for a failed served boot (scripts/survival-pre-ready.py).
REFUSED_STATUS = "7"


class FenceTarget(recovery.RecoveryTarget):
    storage_fence = None


class Args:
    """What survival-recovery's helpers read from its command line."""
    recovery_lines = True


def kernel_fence(serial, word, reason):
    line = re.search(r"(?m)^STORAGE FENCE fence=(\w+)(?: reason=(\w+)| basis=([\w+-]+))$", serial)
    if not line:
        raise RuntimeError(f"no kernel STORAGE FENCE line: {serial[:3000]}")
    if line.group(1) != word or line.group(2) != reason:
        raise RuntimeError(f"kernel fence {line.group(0)!r}, expected fence={word} reason={reason}")
    return line.group(0)


def fsd_fence(serial, word, previous):
    line = re.search(r"(?m)^FSD STORAGE FENCE fence=(\w+) previous=(\w+) assessed=(\w+)$", serial)
    if not line or line.groups() != (word, previous, previous):
        raise RuntimeError(f"file server fence line {line.group(0) if line else None!r}, "
                           f"expected fence={word} previous={previous} assessed={previous}")
    if serial.index(line.group(0)) > serial.index("FSD READY "):
        raise RuntimeError("the fence line came after READY")
    return line.group(0)


def accounting(serial):
    line = re.search(r"(?m)^DURABLE status=.* block_writes=(\d+) block_flushes=(\d+) block_errors=(\d+) ", serial)
    if not line:
        raise RuntimeError(f"no DURABLE accounting line in the refused boot: {serial[-2000:]}")
    return int(line.group(1)), int(line.group(2)), int(line.group(3))


def new_target(args, work, key, fence):
    target = FenceTarget.__new__(FenceTarget)
    target.kernel = pathlib.Path(args.kernel).resolve()
    target.root = pathlib.Path(args.platform).resolve()
    target.qemu = args.qemu
    target.shell = target.root / "commands/absd-sh"
    target.boot_seconds = 3600
    target.proc, target.boots, target.port = None, 0, None
    target.component = "sshd"
    target.fault = "exit"
    target.sshd_elf = pathlib.Path(args.sshd_controls).resolve()
    target.fsd_elf = target.root / "absd-fsd.elf"
    target.storage_fence = fence
    target.setup(work, key.with_suffix(".pub").read_text())
    return target


def start(target, backend, expect_sweep=False):
    os.environ["ABSD_QEMU_REBOOT"] = "allow"
    os.environ["ABSD_BLOCK_ATTACH"] = backend
    try:
        info = target.start(expect_sweep=expect_sweep)
    finally:
        os.environ.pop("ABSD_QEMU_REBOOT", None)
        os.environ.pop("ABSD_BLOCK_ATTACH", None)
    return info


def one_case(args, name, key):
    backend, declaration, word, reason, outcome = CASES[name]
    work = pathlib.Path(args.work) / name
    work.mkdir(parents=True, exist_ok=False)
    target = new_target(args, work, key, declaration)
    marker = bytes(i % 251 for i in range(32))
    try:
        if outcome == "bounded":
            for index, previous in enumerate(("none", "ended")):
                raw, status, log = guest.cold_boot(target, backend, f"bounded-{index}",
                    served=False, worker=target.root / "commands/echo")
                serial = raw.decode(errors="replace")
                if status != "3" or serial.count("ABSD KERNEL BOOT\n") != 1:
                    raise RuntimeError(f"bounded boot did not end cleanly: status={status} log={log}")
                fsd_fence(serial, word, previous)
                if "FSD SHUTDOWN FINALIZED status=0" not in serial:
                    raise RuntimeError("bounded boot lacks checked same-boot finalization")
                if target.tree().get(guard.PATH) != guard.encode("clean"):
                    raise RuntimeError("bounded finalizer did not leave a clean guard")
            print(f"STORAGE FENCE CASE OK case={name} outcome=bounded_clean boots=2", flush=True)
            return
        info = start(target, backend)
        client = recovery.served.sm.Client(work, target.port)
        client.trust(info["public"])
        runner_pid = target.proc.pid
        recovery.serve_and_check(target, client, key, 0, runner_pid, marker, Args, 0, "none")
        first = recovery.boot_parts(target)[0][0]
        fence_line = kernel_fence(first, word, reason)
        fsd_fence(first, word, "none")
        if outcome == "clean":
            rebooted = recovery.ssh(client, key, "reboot")
            if rebooted.returncode != 0:
                raise RuntimeError(f"reboot request failed: {rebooted.stderr!r}")
            recovery.serve_and_check(target, client, key, 1, runner_pid, marker, Args, 0, "ended")
            second = recovery.boot_parts(target)[1][0]
            fsd_fence(second, word, "ended")
            halted = recovery.ssh(client, key, "shutdown")
            if halted.returncode != 0 or target.status(300) != "3":
                raise RuntimeError("the boot after the orderly reboot did not halt cleanly")
            print(f"STORAGE FENCE CASE OK case={name} outcome=clean previous=ended {fence_line!r}", flush=True)
            return
        active, session_pid = recovery.active_session(client, key, target, 0, runner_pid)
        try:
            triggered = recovery.ssh(client, key, recovery.fault_plan("sshd", "exit")["command"])
            if triggered.returncode == 0:
                raise RuntimeError("fault control returned a successful SSH command")
            status = target.status(300)
        finally:
            recovery.end_session(active)
        parts = recovery.boot_parts(target)
        if status != REFUSED_STATUS or len(parts) != 2:
            raise RuntimeError(f"refused successor: status={status} boots={len(parts)}, "
                               f"expected status {REFUSED_STATUS} after exactly 2 boots")
        recovery.recover_record(target, 0, session_pid, False)
        serial, worker = parts[1]
        kernel_fence(serial, word, reason)
        refusal = f"RECOVERY WRITABLE REFUSED reason=storage_fence previous=failed fence=none"
        if not re.search(rf"(?m)^{refusal}$", serial):
            raise RuntimeError(f"no named refusal in the successor: {serial[-2500:]}")
        for absent in ("FSD READY ", "FSD RECOVERY seq=", "MACHINE RECOVER RESET"):
            if absent in serial:
                raise RuntimeError(f"the refused successor printed {absent!r}")
        if "SSH LISTENING" in worker:
            raise RuntimeError("the refused successor listened")
        if "SERVED RECOVERY REFUSED generation_not_ready" not in serial:
            raise RuntimeError("init did not refuse the not-ready generation by name")
        writes, flushes, errors = accounting(serial)
        if (writes, flushes, errors) != (0, 0, 0):
            raise RuntimeError(f"the refused successor reached the device: writes={writes} "
                               f"flushes={flushes} errors={errors}")
        print(f"STORAGE FENCE REFUSAL OK case={name} status={status} block_writes=0 block_flushes=0 "
              f"{fence_line!r}", flush=True)
        # Neither an unverified declaration nor omitting served can turn
        # the same unclean image into a writable deployment.
        guest.refused_cold_boot(target, backend, "retry-external", declaration="external",
                                reason="external_unverified")
        guest.refused_cold_boot(target, backend, "retry-plain-fsd", served=False)
        if name == "ata-undeclared":
            # release.py clone_identity uses this same guarded file-server
            # entry point with host-key regeneration enabled.
            ordinary = target.fsd_elf
            try:
                target.fsd_elf = target.root / "absd-fsd-regenerate.elf"
                guest.refused_cold_boot(target, backend, "retry-clone-regenerate")
            finally:
                target.fsd_elf = ordinary
        print(f"STORAGE FENCE CASE OK case={name} outcome=refused declaration_and_plain_retry=refused", flush=True)
    finally:
        target.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--sshd-controls", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--qemu", default="qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand")
    parser.add_argument("--cases", default=",".join(CASES))
    args = parser.parse_args()
    names = args.cases.split(",")
    unknown = [name for name in names if name not in CASES]
    if unknown:
        parser.error(f"unknown cases {unknown}; known: {','.join(CASES)}")
    key = pathlib.Path(args.key).resolve()
    if not key.is_file() or not key.with_suffix(".pub").is_file():
        parser.error("exact campaign key and public key must already exist")
    work = pathlib.Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=False)
    for name in names:
        one_case(args, name, key)
    print(f"STORAGE FENCE MATRIX OK cases={len(names)}", flush=True)


if __name__ == "__main__":
    main()
