#!/usr/bin/env python3
"""Clock 6a gate (docs/clock-contract-20261015 §6a) under QEMU.

Boots the ordinary ISO and reads its one `TIMER CALIBRATION` line: it must
decode, report samples=5 ticks=100, a hypervisor (`virtualized=yes`),
`cpuid15=absent` on the qemu64 model (its highest basic leaf is 0xd), a
spread (max−min over the median) within SPREAD_BOUND percent, and `TIMER OK
ticks=5` unchanged beside it. One host scheduling stall during a pair can
push a TCG boot past the bound, so a plain boot over the bound is booted
once more and both results are recorded; two failures fail the gate. Then
the falsifiable controls: `+invtsc` must flip `invariant=` to yes while the
plain model says no — but only under KVM (`--kvm`, model `host`): TCG
implements no CPUID.80000007H:EDX feature and strips `invtsc` with a
warning, so without `--kvm` that control is recorded as not run and both
boots must say `invariant=no`. The stall ISO (`tsc-calibration-stall`),
which holds the boot CPU with interrupts off for 20 ticks inside one sample
pair, must widen the spread past the bound and past twice the plain boot's,
with `fixture=stall` named — under TCG; under KVM the in-kernel PIT
re-injects the missed ticks after `sti`, so the stall boot is recorded as
the contract's 2.1 observation and not asserted. `-cpu max` is booted to
record what CPUID leaves 0x15/0x16 look like (no assertion).

    tsc-calibration-check.py --iso ISO --stall-iso ISO --work DIR [--qemu Q] [--kvm]
"""
import argparse
import json
import pathlib
import re
import subprocess
import time

SPREAD_BOUND = 10  # percent of the median: the stated bound for an unstalled boot

FIELDS = re.compile(
    r"^TIMER CALIBRATION tsc_per_tick=(?P<median>\d+) min=(?P<min>\d+) max=(?P<max>\d+) samples=(?P<samples>\d+) "
    r"ticks=(?P<ticks>\d+) tsc_hz=(?P<hz>\d+) virtualized=(?P<virt>yes|no) cpuid15=(?P<c15>\S+) cpuid16=(?P<c16>\S+) "
    r"invariant=(?P<inv>yes|no|unknown)(?P<fixture> fixture=stall)?$"
)


EXIT_AFTER_BOOT_OK = 3  # exit_qemu(1) through isa-debug-exit, as the other gates require


def boot(args, name, iso, cpu):
    log = args.work / f"{name}.serial.log"
    accel = ["-accel", "kvm"] if args.kvm else ["-accel", "tcg"]
    command = args.qemu.split() + accel + ["-cpu", cpu, "-cdrom", str(iso), "-display", "none", "-serial", f"file:{log}",
                                   "-no-reboot", "-no-shutdown", "-rtc", "base=utc",
                                   "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
    started = time.time()
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=args.boot_seconds)
    except subprocess.TimeoutExpired:
        raise SystemExit(f"{name}: QEMU did not exit within {args.boot_seconds}s") from None
    text = log.read_text(errors="replace") if log.exists() else ""
    lines = [line.rstrip("\r") for line in text.split("\n")]
    if "ABSD BOOT OK" not in lines or proc.returncode != EXIT_AFTER_BOOT_OK:
        raise SystemExit(f"{name}: no 'ABSD BOOT OK' with exit {EXIT_AFTER_BOOT_OK} (qemu exit {proc.returncode}):\n{text}")
    if "TIMER OK ticks=5" not in lines:
        raise SystemExit(f"{name}: 'TIMER OK ticks=5' missing or changed:\n{text}")
    calibration = [line for line in lines if line.startswith("TIMER CALIBRATION")]
    if len(calibration) != 1:
        raise SystemExit(f"{name}: expected exactly one TIMER CALIBRATION line, got {calibration}:\n{text}")
    match = FIELDS.match(calibration[0])
    if not match:
        raise SystemExit(f"{name}: the line does not decode: {calibration[0]!r}")
    m = {k: (int(v) if v and v.isdigit() else v) for k, v in match.groupdict().items()}
    if m["samples"] != 5 or m["ticks"] != 100:
        raise SystemExit(f"{name}: samples/ticks not 5/100: {calibration[0]}")
    if not (0 < m["min"] <= m["median"] <= m["max"]):
        raise SystemExit(f"{name}: min/median/max out of order: {calibration[0]}")
    if m["hz"] != m["median"] * 3_579_545 // 3579:
        raise SystemExit(f"{name}: tsc_hz does not follow the PIT divisor: {calibration[0]}")
    if m["virt"] != "yes":
        raise SystemExit(f"{name}: QEMU must report a hypervisor: {calibration[0]}")
    spread = (m["max"] - m["min"]) * 100 // m["median"]
    record = {"name": name, "cpu": cpu, "accel": accel[1], "iso": str(iso), "line": calibration[0], "spread_percent": spread,
              "invariant": m["inv"], "cpuid15": m["c15"], "cpuid16": m["c16"], "fixture": bool(m["fixture"]),
              "qemu_exit": proc.returncode, "qemu_stderr": proc.stderr.strip()[-500:],
              "seconds": round(time.time() - started, 1), "serial": log.name}
    print(f"  ok   {name}: {calibration[0]} (spread {spread}%)")
    return record


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iso", required=True, type=pathlib.Path)
    ap.add_argument("--stall-iso", required=True, type=pathlib.Path)
    ap.add_argument("--work", required=True, type=pathlib.Path)
    ap.add_argument("--qemu", default="qemu-system-x86_64")
    ap.add_argument("--boot-seconds", type=int, default=240)
    ap.add_argument("--kvm", action="store_true", help="use KVM: enables the invtsc flip control (TCG cannot express it)")
    args = ap.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    version = subprocess.run(args.qemu.split() + ["--version"], capture_output=True, text=True).stdout.split("\n")[0]
    boots = []
    model = "host" if args.kvm else "qemu64"
    plain = boot(args, f"plain-{model}", args.iso, model)
    boots.append(plain)
    if plain["spread_percent"] > SPREAD_BOUND:
        # One host scheduling stall inside a pair does this under TCG; a second boot decides.
        print(f"  note plain spread {plain['spread_percent']}% over the bound; booting once more")
        plain = boot(args, f"plain-{model}-retry", args.iso, model)
        boots.append(plain)
        if plain["spread_percent"] > SPREAD_BOUND:
            raise SystemExit(f"plain boot spread {plain['spread_percent']}% exceeds the {SPREAD_BOUND}% bound twice")
    if plain["fixture"]:
        raise SystemExit("plain boot names the stall fixture")
    if not args.kvm:
        if plain["invariant"] != "no":
            raise SystemExit(f"qemu64 without +invtsc must say invariant=no: {plain['line']}")
        if plain["cpuid15"] != "absent":
            raise SystemExit(f"qemu64 has no leaf 0x15; the line must say absent: {plain['line']}")
    invtsc = boot(args, f"invtsc-{model}", args.iso, f"{model},+invtsc")
    boots.append(invtsc)
    if args.kvm:
        if invtsc["invariant"] != "yes":
            raise SystemExit(f"+invtsc under KVM must flip invariant= to yes: {invtsc['line']}")
        invtsc_control = "flipped under KVM (host vs host,+invtsc)"
    else:
        # TCG strips the feature (its stderr says so); the line must not pretend otherwise.
        if invtsc["invariant"] != "no":
            raise SystemExit(f"TCG cannot provide invtsc, yet the line says: {invtsc['line']}")
        invtsc_control = "NOT RUN: requires KVM (TCG strips CPUID.80000007H:EDX.invtsc; both boots said invariant=no)"
        print(f"  skip invtsc flip: {invtsc_control}")
    stall = boot(args, f"stall-{model}", args.stall_iso, model)
    boots.append(stall)
    if not stall["fixture"]:
        raise SystemExit(f"the stall boot must name its fixture: {stall['line']}")
    if args.kvm:
        # KVM's in-kernel PIT re-injects the missed ticks after sti (contract 2.1): recorded, not asserted.
        stall_control = f"KVM observation: stall spread {stall['spread_percent']}% (re-injection expected to hide the stall)"
        print(f"  note {stall_control}")
    elif stall["spread_percent"] <= SPREAD_BOUND or stall["spread_percent"] <= 2 * max(plain["spread_percent"], 1):
        raise SystemExit(f"the stall must widen the spread past {SPREAD_BOUND}% and past twice the plain boot's: "
                         f"plain {plain['spread_percent']}%, stall {stall['spread_percent']}%")
    else:
        stall_control = f"widened under TCG: plain {plain['spread_percent']}%, stall {stall['spread_percent']}%"
    boots.append(boot(args, "leaves-max", args.iso, "max"))
    result = {"accelerator": "kvm" if args.kvm else "tcg", "qemu_version": version, "spread_bound_percent": SPREAD_BOUND,
              "invtsc_control": invtsc_control, "stall_control": stall_control, "boots": boots, "result": "OK"}
    (args.work / "result.json").write_text(json.dumps(result, indent=1))
    print(f"TSC CALIBRATION CHECK OK boots={len(boots)} plain_spread={plain['spread_percent']}% "
          f"stall_spread={stall['spread_percent']}% accel={result['accelerator']} invtsc={'flipped' if args.kvm else 'not-run'}")


if __name__ == "__main__":
    main()
