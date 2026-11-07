#!/usr/bin/env python3
"""Producer smoke for operator-mode AMD-Vi containment (Q10 fixtures only).

`--build DIR` makes one ISO per case on the build host. `--run DIR` boots them
under QEMU 10.2.1 and judges serial output. ABSD's lines are claims, and this
smoke only checks the path behaves as designed: it is not an oracle, and no
result here says anything about real hardware.
"""
import argparse
import hashlib
import os
import pathlib
import re
import subprocess
import sys

BASE = ["-M", "q35", "-accel", "tcg", "-m", "512M", "-smp", "1", "-display", "none",
        "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
IOMMU = ["-device", "amd-iommu,dma-remap=on"]
SHORT = "dma-contain-census-seconds=2"
ARM = re.compile(r"^DMA ARM .*decision=arm", re.M)
UNREGISTERED_ARM = re.compile(r"^DMA ARM (?!.*state=contained).*decision=arm", re.M)
UNIT_ON = "AMDVI OPERATOR unit=enabled"
UNIT_OFF = "AMDVI OPERATOR unit=refused"


def ahci(addr="0x7", serial="absd", bus=None, image="FIXTURE", model=None):
    where = f"bus={bus}," if bus else ""
    snapshot = ",snapshot=on" if image == "FIXTURE" else ""
    return ["-device", f"ich9-ahci,id=a7,{where}addr={addr}",
            "-drive", f"if=none,id=s7,file={image},format=raw{snapshot}",
            "-device", f"ide-hd,bus=a7.0,drive=s7,serial={serial}" + (f",model={model}" if model else "")]


# name, boot line, QEMU arguments, must-match, must-not-match
CASES = [
    ("census", f"dma-contain=none {SHORT}", IOMMU,
     [UNIT_ON, "AMDVI DENY-BY-DEFAULT devtab-invalidated=65536 of=65536",
      "DMA CENSUS SUMMARY inherited-masters=", "qualification=none", "DMA CENSUS unit=enabled",
      "DMA CENSUS table=ok deviations=1 quirked=1 display=blocked",
      "DMA CONTAIN EVIDENCE digest="],
     [ARM]),
    ("census-sees-ahci", f"dma-contain=none {SHORT}", IOMMU + ahci(),
     ["DMA CENSUS pci=00:07.0 driver=ahci ids=8086:2922", "DMA CENSUS pci=00:07.0 scope=ok"], [ARM]),
    ("no-iommu", f"dma-contain=none {SHORT}", [],
     [UNIT_OFF, "DMA CONTAIN INHERITED-BME closed=", "DMA CENSUS unit=refused"], [ARM, UNIT_ON]),
    ("bad-word", "dma-contain=nvme@01:00.0", IOMMU,
     ["DMA CONTAIN WORD REFUSED reason=unknown-driver firmware-masters=as-found"],
     [ARM, "AMDVI ENABLED", "DMA CONTAIN START"]),
    ("word-with-smp", "dma-contain=none smp-cpus=2", IOMMU,
     ["DMA CONTAIN WORD REFUSED reason=conflict"], [ARM, "AMDVI ENABLED"]),
    ("needs-disk", "dma-contain=ahci@00:07.0", IOMMU,
     ["DMA CONTAIN WORD REFUSED reason=needs-ahci-disk"], [ARM]),
    ("ahci-positive", "block-probe dma-report dma-contain=ahci@00:07.0 ahci-write=absd", IOMMU + ahci(image="BLANK"),
     [UNIT_ON, "DMA CONTAIN TAKEN pci=00:07.0 driver=ahci inherited=", "DMA CONTAIN pci=00:07.0 driver=ahci domain=2 scope=ok pages=4 interrupts=deny-all",
      "owner=ahci state=contained profile=enforced decision=arm containment=contained", "BLOCK BACKEND ahci access=read-write",
      "DURABLE WORKLOAD OK", "ABSD BOOT OK"],
     [UNREGISTERED_ARM, "DURABLE WORKLOAD FAILED", "DMA CONTAIN TERMINAL"]),
    ("write-real-model", "block-probe dma-contain=ahci@00:07.0 ahci-write=absd", IOMMU + ahci(image="BLANK", model="REAL SSD"),
     [UNIT_ON, "model=REAL SSD", "BLOCK BACKEND ahci access=read-write", "DURABLE WORKLOAD OK", "ABSD BOOT OK"],
     [UNREGISTERED_ARM, "WriteNotEmulated", "DURABLE WORKLOAD FAILED", "DMA CONTAIN TERMINAL"]),
    ("write-real-model-uncontained", "block-probe ahci-write=absd", ahci(image="BLANK", model="REAL SSD"),
     ["AHCI UNAVAILABLE Refused(WriteNotEmulated)", "block: no device"], ["BLOCK BACKEND ahci access=read-write", "DURABLE WORKLOAD OK"]),
    ("read-serial", "block-probe dma-contain=ahci@00:07.0 ahci-disk=none-selected dma-contain-check", IOMMU + ahci(),
     [UNIT_ON, "DMA CONTAIN DISK port=0 serial=absd model=QEMU HARDDISK selected=no",
      "DMA CONTAIN CHECK permitted=FAILED forbidden=FAILED"], []),
    ("ahci-check", "block-probe dma-report dma-contain=ahci@00:07.0 ahci-disk=absd dma-contain-check", IOMMU + ahci(),
     ["DMA CONTAIN DISK port=0 serial=absd model=QEMU HARDDISK selected=yes", UNIT_ON, "DMA CONTAIN CHECK permitted=ok forbidden=denied-completed attribution=devid-only",
      "observer=kernel-only qualification=none", "DMA CONTAIN EVIDENCE digest="],
     [UNREGISTERED_ARM, "DMA CONTAIN TERMINAL"]),
    ("inject-unit-error", "block-probe dma-contain=ahci@00:07.0 ahci-disk=absd dma-contain-inject=unit-error", IOMMU + ahci(),
     ["DMA CONTAIN STOPPED pci=00:07.0 driver=ahci bme=clear step=R2 claims=none", "DMA CONTAIN TERMINAL reason=unit-failed",
      "DMA CONTAIN INJECT kind=unit-error later-read=refused rearm=refused bme=clear"], []),
    ("inject-overflow", "block-probe dma-contain=ahci@00:07.0 ahci-disk=absd dma-contain-inject=overflow", IOMMU + ahci(),
     ["DMA CONTAIN TERMINAL reason=event-log-overflow", "DMA CONTAIN INJECT kind=overflow later-read=refused rearm=refused bme=clear"], []),
    ("inject-target-fault", "block-probe dma-contain=ahci@00:07.0 ahci-disk=absd dma-contain-inject=target-fault", IOMMU + ahci(),
     ["DMA CONTAIN REVOKED pci=00:07.0 driver=ahci reason=io-page-fault",
      "DMA CONTAIN RETIRED pci=00:07.0 driver=ahci r3=completed retained=yes",
      "DMA CONTAIN INJECT kind=target-fault later-read=refused rearm=refused bme=clear"], ["DMA CONTAIN TERMINAL"]),
    ("ahci-custody-trace", "block-probe dma-contain=ahci@00:07.0 ahci-disk=absd", IOMMU + ahci()
     + ["-trace", "amdvi_devtab_inval", "-trace", "pci_cfg_write", "-D", "TRACE"],
     [UNIT_ON, "DMA CONTAIN pci=00:07.0 driver=ahci domain=2"], ["DMA CONTAIN TERMINAL"]),
    ("inject-port-retire", "block-probe dma-contain=ahci@00:07.0 ahci-disk=absd dma-contain-inject=port-retire", IOMMU + ahci(),
     ["DMA CONTAIN RETIRED pci=00:07.0 driver=ahci r3=completed retained=yes",
      "DMA CONTAIN INJECT kind=port-retire later-read=refused rearm=refused bme=clear"], ["DMA CONTAIN TERMINAL"]),
    ("check-denied-retired", "block-probe dma-contain=ahci@00:07.0 ahci-disk=absd dma-contain-inject=check-retire", IOMMU + ahci(),
     ["DMA CONTAIN CHECK permitted=ok forbidden=denied-port-retired attribution=devid-only",
      "DMA CONTAIN RETIRED pci=00:07.0 driver=ahci r3=completed retained=yes"], []),
    ("selector-first-word", "ahci-disk=absd dma-contain=ahci@00:07.0", IOMMU + ahci(),
     ["DMA CONTAIN WORD REFUSED reason=needs-ahci-disk"], [ARM, "AMDVI ENABLED", "ATA"]),
    ("ahci-identify-retires", "block-probe dma-contain=ahci@00:07.0 ahci-disk=other", IOMMU + ahci(),
     [UNIT_ON, "block: no device", "DMA CONTAIN RETIRED pci=00:07.0 driver=ahci r3=completed retained=yes"], []),
    ("check-needs-ahci", f"dma-contain=none dma-contain-check {SHORT}", IOMMU,
     ["DMA CONTAIN WORD REFUSED reason=check-needs-ahci"], [ARM, "AMDVI ENABLED"]),
    ("ahci-wrong-serial", "block-probe dma-report dma-contain=ahci@00:07.0 ahci-disk=other", IOMMU + ahci(),
     [UNIT_ON, "block: no device"], [UNREGISTERED_ARM]),
    ("ahci-absent", "block-probe dma-report dma-contain=ahci@00:09.0 ahci-disk=absd", IOMMU + ahci(),
     [UNIT_ON, "block: no device"], [ARM]),
    ("ahci-no-iommu", "block-probe dma-report dma-contain=ahci@00:07.0 ahci-disk=absd", ahci(),
     [UNIT_OFF, "DMA CONTAIN REFUSED pci=00:07.0 driver=ahci reason=unit-unavailable", "block: no device"], [ARM]),
    ("ahci-behind-bridge", "block-probe dma-report dma-contain=ahci@01:00.0 ahci-disk=absd",
     IOMMU + ["-device", "pcie-root-port,id=rp,addr=0x6"] + ahci(addr="0x0", bus="rp"),
     [UNIT_ON, "DMA CONTAIN REFUSED pci=01:00.0 driver=ahci reason=path", "block: no device"], [ARM]),
    ("ahci-sibling", "block-probe dma-report dma-contain=ahci@00:07.0 ahci-disk=absd",
     IOMMU + ["-device", "ich9-ahci,id=a7,addr=0x7.0,multifunction=on", "-device", "edu,addr=0x7.1",
              "-drive", "if=none,id=s7,file=FIXTURE,format=raw,snapshot=on",
              "-device", "ide-hd,bus=a7.0,drive=s7,serial=absd"],
     [UNIT_ON, "DMA CONTAIN REFUSED pci=00:07.0 driver=ahci reason=sibling", "block: no device"], [ARM]),
    ("unnamed-devices", "net-probe dma-report dma-contain=ahci@00:07.0 ahci-disk=absd",
     IOMMU + ahci() + ["-device", "e1000", "-device", "nvme,serial=x,drive=n", "-drive", "if=none,id=n,file=FIXTURE,format=raw,snapshot=on"],
     [UNIT_ON, "owner=e1000", "decision=refuse-not-registered", "BLOCK BACKEND ahci"],
     [re.compile(r"^DMA ARM .*owner=(e1000|nvme).*decision=arm", re.M)]),
]


def run_case(case, directory, qemu, fixture):
    name, _line, extra, want, avoid = case
    iso = directory / f"{name}.iso"
    log = directory / f"{name}.serial"
    log.unlink(missing_ok=True)
    args = [qemu, *BASE, "-cdrom", str(iso), "-serial", f"file:{log}"]
    blank = directory / "blank.img"
    blank.write_bytes(bytes(2 << 20))
    trace = directory / f"{name}.trace"
    args += [a.replace("FIXTURE", str(fixture)).replace("BLANK", str(blank)).replace("TRACE", str(trace))
             for a in extra]
    try:
        subprocess.run(args, timeout=240, capture_output=True, check=False)
    except subprocess.TimeoutExpired:
        return [f"{name}: timed out"]
    text = log.read_text(errors="replace")
    failures = []
    if "PANIC" in text or "KERNEL FAULT" in text:
        failures.append(f"{name}: kernel fault")
    for pattern in want:
        if pattern not in text:
            failures.append(f"{name}: missing {pattern!r}")
    for pattern in avoid:
        if (pattern.search(text) if hasattr(pattern, "search") else pattern in text):
            failures.append(f"{name}: forbidden {getattr(pattern, 'pattern', pattern)!r}")
    if name == "inject-target-fault":
        if text.find("DMA CONTAIN RETIRED") > text.find("AHCI PORT CLEANUP"):
            failures.append(f"{name}: device stopped before its domain was blocked")
    if name == "ahci-custody-trace":
        failures += custody_order(trace.read_text(errors="replace"))
    return failures


def custody_order(text):
    """When the target's own grant is invalidated, its last command write must
    have Bus Master Enable clear. The kernel's serial order is a claim; this is
    QEMU's account."""
    lines = text.splitlines()
    inval = [i for i, l in enumerate(lines) if "amdvi_devtab_inval" in l and "00:07.0 " in l + " "]
    if not inval:
        return ["ahci-custody-trace: no invalidation in the trace"]
    writes = [l for l in lines[:inval[-1]] if "ich9-ahci 00:07.0 @0x4 <- " in l]
    if not writes:
        return ["ahci-custody-trace: no command write before the grant"]
    if int(writes[-1].rsplit("<- ", 1)[1], 16) & 4:
        return [f"ahci-custody-trace: bus mastering on at the grant: {writes[-1]}"]
    return []


# Kernel builds that must make a named case fail. Each proves the smoke can see
# that defect.
CONTROLS = [
    ("absd_mutant_contain_skip_bme_clear", "ahci-custody-trace"),
    ("absd_mutant_contain_gate_open", "unnamed-devices"),
    ("absd_mutant_scope_sibling_any", "ahci-sibling"),
    ("absd_mutant_ahci_write_uncontained", "write-real-model-uncontained"),
    # Overflow is noted at the observation and judged again at the poll: disable both.
    ("absd_mutant_contain_overflow_unnoted absd_mutant_operator_overflow_ignored", "inject-overflow"),
    ("absd_mutant_contain_extra_page", "ahci-check"),
]


def write_fixture(path):
    with path.open("wb") as image:
        for lba in range(2048):
            image.write((hashlib.sha256(b"absd116-lba-%d" % lba).digest() * 16)[:512])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", type=pathlib.Path)
    parser.add_argument("--run", type=pathlib.Path)
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--only")
    parser.add_argument("--build-controls", type=pathlib.Path)
    parser.add_argument("--run-controls", type=pathlib.Path)
    args = parser.parse_args()
    cases = [c for c in CASES if not args.only or c[0] == args.only]
    by_name = {c[0]: c for c in CASES}
    if args.build_controls:
        for mutant, name in CONTROLS:
            out = args.build_controls / mutant.split()[0]
            out.mkdir(parents=True, exist_ok=True)
            env = {**os.environ, "RUSTFLAGS": " ".join(f"--cfg {m}" for m in mutant.split())}
            subprocess.run(["make", "--no-print-directory", "amdvi-operator-build"], check=True,
                           stdout=subprocess.DEVNULL, env=env)
            subprocess.run(["make", "--no-print-directory", "amdvi-operator-iso",
                            f"OPERATOR_LINE={by_name[name][1]}", f"OPERATOR_ISO={out}/{name}.iso"],
                           check=True, env=env)
    if args.run_controls:
        survived = 0
        for mutant, name in CONTROLS:
            out = args.run_controls / mutant.split()[0]
            fixture = out / "fixture.img"
            write_fixture(fixture)
            failures = run_case(by_name[name], out, args.qemu, fixture)
            print(f"{'KILLED' if failures else 'SURVIVED'} {mutant} by {name}: {failures[:1]}")
            survived += not failures
        sys.exit(1 if survived else 0)
    if args.build:
        args.build.mkdir(parents=True, exist_ok=True)
        subprocess.run(["make", "--no-print-directory", "amdvi-operator-build"], check=True,
                       stdout=subprocess.DEVNULL)
        for case in cases:
            subprocess.run(["make", "--no-print-directory", "amdvi-operator-iso",
                            f"OPERATOR_LINE={case[1]}", f"OPERATOR_ISO={args.build}/{case[0]}.iso"],
                           check=True)
    if args.run:
        version = subprocess.run([args.qemu, "--version"], capture_output=True, text=True).stdout
        if "version 10.2" not in version:
            sys.exit(f"needs QEMU 10.2: {version.splitlines()[:1]}")
        fixture = args.run / "fixture.img"
        write_fixture(fixture)
        failed = 0
        for case in cases:
            failures = run_case(case, args.run, args.qemu, fixture)
            print(f"{'FAIL' if failures else 'PASS'} {case[0]}")
            for failure in failures:
                print(f"  {failure}")
            failed += bool(failures)
        print(f"{len(cases) - failed}/{len(cases)} passed")
        sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
