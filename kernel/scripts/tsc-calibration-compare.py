#!/usr/bin/env python3
"""Clock 6a control (iv), docs/clock-contract-20261015 §2.1 and §6a: does
KVM's PIT re-injection change `tsc_per_tick` relative to TCG, idle and under
host load? An observation, not a pass/fail gate: it boots the ordinary ISO
under each accelerator, idle and with one busy process per host CPU running
alongside, reads the `TIMER CALIBRATION` line each time, and records medians
and spreads per cell. It fails only if a boot does not produce the line.

    tsc-calibration-compare.py --iso ISO --work DIR [--qemu Q] [--repeat N]
"""
import argparse
import json
import os
import pathlib
import re
import subprocess
import time

LINE = re.compile(r"^TIMER CALIBRATION tsc_per_tick=(\d+) min=(\d+) max=(\d+) samples=(\d+) ticks=(\d+) tsc_hz=(\d+) "
                  r"virtualized=(yes|no) cpuid15=(\S+) cpuid16=(\S+) invariant=(yes|no|unknown)$")


def boot(args, name, accel, cpu):
    log = args.work / f"{name}.serial.log"
    command = args.qemu.split() + ["-accel", accel, "-cpu", cpu, "-cdrom", str(args.iso), "-display", "none",
                                   "-serial", f"file:{log}", "-no-reboot", "-no-shutdown", "-rtc", "base=utc",
                                   "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
    started = time.time()
    proc = subprocess.run(command, capture_output=True, text=True, timeout=args.boot_seconds)
    text = log.read_text(errors="replace") if log.exists() else ""
    lines = [line.rstrip("\r") for line in text.split("\n")]
    found = [LINE.match(line) for line in lines if line.startswith("TIMER CALIBRATION")]
    if len(found) != 1 or not found[0] or "ABSD BOOT OK" not in lines:
        raise SystemExit(f"{name}: no single decodable TIMER CALIBRATION line with ABSD BOOT OK (exit {proc.returncode}):\n{text}")
    m = found[0]
    median, low, high = int(m[1]), int(m[2]), int(m[3])
    return {"name": name, "accel": accel, "cpu": cpu, "line": m[0], "median": median, "min": low, "max": high,
            "spread_percent": (high - low) * 100 // median, "invariant": m[10], "seconds": round(time.time() - started, 1),
            "qemu_exit": proc.returncode}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iso", required=True, type=pathlib.Path)
    ap.add_argument("--work", required=True, type=pathlib.Path)
    ap.add_argument("--qemu", default="qemu-system-x86_64")
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--boot-seconds", type=int, default=240)
    args = ap.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    cpus = os.cpu_count() or 1
    cells = {}
    for accel, cpu in (("kvm", "host"), ("tcg", "qemu64")):
        for load in (False, True):
            name = f"{accel}-{'load' if load else 'idle'}"
            busy = []
            if load:
                busy = [subprocess.Popen(["python3", "-c", "while True: pass"]) for _ in range(cpus)]
                time.sleep(1)
            try:
                boots = [boot(args, f"{name}-{i}", accel, cpu) for i in range(args.repeat)]
            finally:
                for p in busy:
                    p.kill()
                for p in busy:
                    p.wait()
            medians = sorted(b["median"] for b in boots)
            cells[name] = {"boots": boots, "median_of_medians": medians[len(medians) // 2],
                           "max_spread_percent": max(b["spread_percent"] for b in boots)}
            print(f"  {name}: medians {medians} spreads {[b['spread_percent'] for b in boots]}%")
    k, t = cells["kvm-idle"]["median_of_medians"], cells["tcg-idle"]["median_of_medians"]
    result = {"host_cpus": cpus, "repeat": args.repeat, "cells": cells,
              "kvm_vs_tcg_idle_percent": round((k - t) * 100 / t, 2),
              "kvm_load_vs_idle_percent": round((cells["kvm-load"]["median_of_medians"] - k) * 100 / k, 2),
              "tcg_load_vs_idle_percent": round((cells["tcg-load"]["median_of_medians"] - t) * 100 / t, 2),
              "qemu_version": subprocess.run(args.qemu.split() + ["--version"], capture_output=True, text=True).stdout.split("\n")[0],
              "result": "OBSERVED"}
    (args.work / "result.json").write_text(json.dumps(result, indent=1))
    print(f"TSC CALIBRATION COMPARE OBSERVED kvm_vs_tcg_idle={result['kvm_vs_tcg_idle_percent']}% "
          f"kvm_load={result['kvm_load_vs_idle_percent']}% tcg_load={result['tcg_load_vs_idle_percent']}% "
          f"max_spreads kvm-load={cells['kvm-load']['max_spread_percent']}% tcg-load={cells['tcg-load']['max_spread_percent']}%")


if __name__ == "__main__":
    main()
