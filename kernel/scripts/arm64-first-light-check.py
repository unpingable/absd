#!/usr/bin/env python3
"""Boots the first-light build (arm64-first-light feature, PL011 early
console) on QEMU virt under TCG and checks the diagnostic lines: GICv3 and
GICv2, EL1 and EL2 entry, one vCPU with 512 MiB, and four vCPUs with 3 GiB
(the multi-CPU tree the board has, Aff0-numbered on virt). Every expected
line must be present, in order, with the values QEMU virt-8.2 under TCG
produces; from `ARM FIRST LIGHT` to `ARM FIRST LIGHT OK` no other line may
intervene; a panic anywhere fails. The kernel must stop by PSCI. This
exercises the board-derived parser, map and diagnostic path on the qualified
platform; the RK3568 console itself has no QEMU model.

    arm64-first-light-check.py --image build/arm64-first-light-virt/kernel.img --work DIR [--qemu Q] [--cpu C]
"""
import argparse
import json
import pathlib
import re
import subprocess
import time

HEX16 = r"0x[0-9a-f]{16}"


def expected(cpus, ram_bytes, gic, el2):
    el, psci = ("2", "smc") if el2 else ("1", "hvc")
    if gic == 3:
        gic_lines = [
            rf"^ARM GIC distributor pidr2_archrev=3 typer={HEX16} gicd=0x0000000008000000 gicr=0x00000000080a0000 redistributors={cpus}$",
            r"^ARM GIC redistributors count=%d ended=last affinities=%s$"
            % (cpus, ",".join(f"0x{i:08x}" for i in range(cpus))),
        ]
    else:
        gic_lines = [rf"^ARM GIC distributor v2 typer={HEX16} gicd=0x0000000008000000 gicc=0x0000000008010000$"]
    # (pattern, strict): strict lines must follow the previous one directly.
    return [
        (r"^ABSD ARM64 KERNEL BOOT$", False),
        (rf"^ARM BOOT entry_el={el} psci={psci}$", False),
        (rf"^ARM RAM REGION base=0x0000000040000000 bytes=0x{ram_bytes:016x}$", False),
        (r"^ARM RAM OK frames=[1-9]\d*$", False),
        (r"^ARM MMU OK$", False),
        (r"^ARM EXCEPTION OK$", False),
        (rf"^ARM FIRST LIGHT kernel=0x0000000040080000 end={HEX16} dtb={HEX16} dtb_bytes={HEX16}$", False),
        (rf"^ARM FIRMWARE psci_version=0x0000000000010001 cpus={cpus} cpu_shift=0 console=0x0000000009000000 pl011$", True),
        *[(line, True) for line in gic_lines],
        (r"^ARM TIMER MARK \.{1484}$", True),
        (r"^ARM TIMER cntfrq=62500000 ticks_per_1500_bytes=[1-9]\d*$", True),
        (r"^ARM FIRST LIGHT OK$", True),
    ]


def boot(args, work, name, gic, el2, cpus, ram_mib):
    serial = work / f"{name}.serial.log"
    machine = f"virt-8.2,gic-version={gic}" + (",virtualization=on" if el2 else "")
    accel = "tcg,thread=multi" if cpus > 1 else "tcg"
    command = [args.qemu, "-machine", machine, "-accel", accel, "-cpu", args.cpu, "-smp", str(cpus), "-m", f"{ram_mib}M",
               "-kernel", str(args.image), "-display", "none", "-serial", f"file:{serial}", "-nic", "none", "-no-reboot"]
    started = time.time()
    proc = subprocess.run(command, capture_output=True, text=True, timeout=args.boot_seconds)
    text = serial.read_text(errors="replace") if serial.exists() else ""
    lines = [line.rstrip("\r") for line in text.split("\n")]
    record = {"name": name, "gic": gic, "el2": el2, "cpus": cpus, "ram_mib": ram_mib, "command": command,
              "qemu_exit": proc.returncode, "seconds": round(time.time() - started, 1), "serial": serial.name,
              "stderr": proc.stderr[-2000:], "checks": 0}
    if proc.returncode != 0:
        raise SystemExit(f"{name}: QEMU exited {proc.returncode}: {proc.stderr}\n{text}")
    if any("PANIC" in line for line in lines):
        raise SystemExit(f"{name}: the kernel panicked:\n{text}")
    # PSCI SYSTEM_OFF prints nothing: the last line must be the OK line and
    # QEMU must have exited by itself (returncode 0 above, not the timeout).
    if [line for line in lines if line][-1] != "ARM FIRST LIGHT OK":
        raise SystemExit(f"{name}: output continued after the OK line:\n{text}")
    at = 0
    for pattern, strict in expected(cpus, ram_mib << 20, gic, el2):
        rx = re.compile(pattern)
        if strict:
            if at >= len(lines) or not rx.match(lines[at]):
                got = lines[at] if at < len(lines) else "<end>"
                raise SystemExit(f"{name}: expected /{pattern}/ directly after line {at}, got {got!r}; serial:\n{text}")
        else:
            while at < len(lines) and not rx.match(lines[at]):
                at += 1
            if at == len(lines):
                raise SystemExit(f"{name}: expected /{pattern}/ not found; serial:\n{text}")
        at += 1
        record["checks"] += 1
    print(f"  ok   {name}: {record['checks']} lines, the diagnostics contiguous, stopped by PSCI")
    return record


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True, type=pathlib.Path)
    ap.add_argument("--work", required=True, type=pathlib.Path)
    ap.add_argument("--qemu", default="qemu-system-aarch64")
    ap.add_argument("--cpu", default="cortex-a72")
    ap.add_argument("--boot-seconds", type=int, default=300)
    args = ap.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    version = subprocess.run([args.qemu, "--version"], capture_output=True, text=True).stdout.split("\n")[0]
    boots = []
    for gic in (3, 2):
        for el2 in (False, True):
            boots.append(boot(args, args.work, f"first-light-gic{gic}" + ("-el2" if el2 else ""), gic, el2, 1, 512))
    boots.append(boot(args, args.work, "first-light-gic3-4cpu-3g-el2", 3, True, 4, 3072))
    boots.append(boot(args, args.work, "first-light-gic2-4cpu-3g", 2, False, 4, 3072))
    result = {"accelerator": "tcg", "cpu": args.cpu, "qemu_version": version, "image": str(args.image),
              "boots": boots, "checks": sum(b["checks"] for b in boots), "result": "OK"}
    (args.work / "result.json").write_text(json.dumps(result, indent=1))
    print(f"ARM FIRST LIGHT CHECK OK boots={len(boots)} checks={result['checks']} accel=tcg")


if __name__ == "__main__":
    main()
