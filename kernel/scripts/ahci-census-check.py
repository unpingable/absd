#!/usr/bin/env python3
"""Gate for the AHCI census entry (docs/hardware/SATA-AHCI-CENSUS.md).

Boots the census ISO under QEMU q35 (ich9-ahci 8086:2922 at 00:1f.2):
 1. two raw disks on ports 0 and 2, a CD-ROM on port 1 and the boot ISO on
    port 5: the controller line, every implemented port, the two ATA devices
    identified with QEMU's model string and the images' sector counts, both
    ATAPI devices reported without a command, `AHCI CENSUS OK` with
    identified=2 commands=2, the COMPLETE line; QEMU's `ide_bus_exec_cmd`
    trace, sliced at the kernel's first serial line (the firmware's own
    IDENTIFY/PACKET traffic for the boot CD precedes it), shows IDENTIFY
    DEVICE (0xec) twice and nothing else; both images are byte-identical
    afterwards;
 2. the same machine booted from the pretend-RAID fixture ISO: the refusal
    line names fixture=pretend-raid, no ATA command and no AHCI register
    write is traced, exit code 7 (exit_qemu(1));
 3. a `pc` machine (PIIX IDE, no AHCI): `AHCI CENSUS none …`;
 4. q35 with only the boot CD: five empty ports, identified=0, no register
    written;
 5. the physical ISO's default GRUB entry halts on screen;
 6. the stuck-stop fixture ISO (`ahci-census-pretend-stuck-stop`: the first
    IDENTIFY's post-command engine stop is treated as failed) on q35 with a
    second ich9-ahci controller: the controller that ran that IDENTIFY is
    refused at that port with bus mastering turned off (a PCI command write
    clearing bus master, after the IDENTIFY, before the failure is printed,
    and with no AHCI register write to it afterwards), its bases are not written back, its remaining ports are
    not read, the other controller's ATA ports are skipped because the
    static buffers are retired, exactly one IDENTIFY is traced, exit 7.
QEMU's `ahci_port_write`/`ahci_mem_write` traces after the kernel's first
line must show port writes only on the two ATA ports, none at HBA level,
and each port's last PxCLB/PxFB write equal to the firmware's.

    ahci-census-check.py --iso QEMU_ISO --raid-iso ISO --stuck-iso ISO --physical-iso ISO --work DIR [--qemu Q]
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import time

# exit_qemu(code) writes (code << 1) | 1 to isa-debug-exit, and QEMU exits with (value << 1) | 1.
OK_EXIT = 3  # exit_qemu(0)
REFUSED_EXIT = 7  # exit_qemu(1)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def boot(args, name, iso, machine, boot_bus, devices, expect_exit):
    """Boots `iso` as an ATAPI device on `boot_bus` (so the census sees it as one more
    ATAPI port) with `devices` attached; returns the record and the serial lines."""
    log = args.work / f"{name}.serial.log"
    trace = args.work / f"{name}.trace"
    command = args.qemu.split() + ["-machine", machine, "-accel", "tcg", "-m", "512M",
                                   "-drive", f"if=none,id=boot,file={iso},format=raw,media=cdrom",
                                   "-device", f"ide-cd,drive=boot,bus={boot_bus}", "-boot", "d",
                                   "-display", "none", "-serial", f"file:{log}", "-no-reboot", "-no-shutdown",
                                   "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
                                   "-trace", "ide_bus_exec_cmd", "-trace", "serial_write",
                                   "-trace", "ahci_port_write", "-trace", "ahci_mem_write", "-trace", "pci_cfg_write",
                                   "-D", str(trace)] + devices
    started = time.time()
    proc = subprocess.run(command, capture_output=True, text=True, timeout=args.boot_seconds)
    text = log.read_text(errors="replace") if log.exists() else ""
    lines = [line.rstrip("\r") for line in text.split("\n")]
    firmware_cmds, cmds, firmware_writes, writes = split_trace(trace)
    if proc.returncode != expect_exit:
        raise SystemExit(f"{name}: QEMU exit {proc.returncode}, expected {expect_exit}; serial:\n{text}\nstderr: {proc.stderr[-500:]}")
    record = {"name": name, "machine": machine, "devices": devices, "qemu_exit": proc.returncode,
              "firmware_ata_commands": len(firmware_cmds), "ata_commands": cmds,
              "firmware_register_writes": len(firmware_writes), "register_writes": len(writes),
              "seconds": round(time.time() - started, 1), "serial": log.name}
    return record, lines, firmware_writes, writes


MARKER = b"ABSD KERNEL BOOT\n"


def split_trace(trace):
    """ATA commands before and after the kernel's first serial line (the firmware
    identifies and reads the boot CD itself; only the rest is the kernel's), as the
    survey gate does it (scripts/survey-check.py)."""
    if not trace.exists():
        return [], []
    text = trace.read_text(errors="replace").splitlines()
    positions, values = [], []
    for index, line in enumerate(text):
        found = re.match(r"serial_write write addr 0x00 val 0x([0-9a-f]+)$", line)
        if found:
            positions.append(index)
            values.append(int(found.group(1), 16))
    at = bytes(values).find(MARKER)
    if at < 0:
        raise SystemExit(f"{trace}: the kernel's first line is not in the serial trace")
    cut = positions[at]
    rx = re.compile(r"^ide_bus_exec_cmd .* cmd 0x([0-9a-f]+)$")
    before = [m.group(1) for m in map(rx.match, text[:cut]) if m]
    after = [m.group(1) for m in map(rx.match, text[cut:]) if m]
    # Controller register writes: port writes as (port, register, value), HBA-level as ("hba", offset, value).
    port_rx = re.compile(r"^ahci_port_write ahci\(0x[0-9a-f]+\)\[(\d+)\]: port write \[reg:(\w+)\] @ 0x[0-9a-f]+: 0x([0-9a-f]+)$")
    mem_rx = re.compile(r"^ahci_mem_write ahci\(0x[0-9a-f]+\): write to \[reg:(\w+)\] @ 0x([0-9a-f]+): 0x([0-9a-f]+)$")
    def writes(chunk):
        found = []
        for line in chunk:
            m = port_rx.match(line)
            if m:
                found.append((int(m.group(1)), m.group(2), int(m.group(3), 16)))
                continue
            m = mem_rx.match(line)
            if m:
                found.append(("hba", m.group(1), int(m.group(3), 16)))
        return found
    return before, after, writes(text[:cut]), writes(text[cut:])


def bases_restored(name, firmware_writes, writes):
    """For every port the kernel wrote, its last PxCLB/PxCLBU/PxFB/PxFBU write must equal the
    firmware's last value for that register (or 0 if the firmware never wrote it)."""
    last_firmware = {}
    for port, reg, value in firmware_writes:
        last_firmware[(port, reg)] = value
    last_kernel = {}
    for port, reg, value in writes:
        last_kernel[(port, reg)] = value
    for (port, reg), value in last_kernel.items():
        if reg in ("PxCLB", "PxCLBU", "PxFB", "PxFBU"):
            expected = last_firmware.get((port, reg), 0)
            if value != expected:
                raise SystemExit(f"{name}: port {port} {reg} left at 0x{value:x}, firmware had 0x{expected:x}")
    return sorted({f"{port}:{reg}" for (port, reg) in last_kernel if reg in ("PxCLB", "PxFB")})


def need(name, lines, pattern):
    rx = re.compile(pattern)
    hits = [line for line in lines if rx.search(line)]
    if not hits:
        raise SystemExit(f"{name}: expected /{pattern}/ in:\n" + "\n".join(lines))
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iso", required=True, type=pathlib.Path)
    ap.add_argument("--raid-iso", required=True, type=pathlib.Path, help="the same kernel with the pretend-RAID fixture entry as default")
    ap.add_argument("--stuck-iso", required=True, type=pathlib.Path, help="the same kernel with the stuck-stop fixture entry as default")
    ap.add_argument("--physical-iso", required=True, type=pathlib.Path, help="the ISO for a physical machine: its default entry must halt")
    ap.add_argument("--work", required=True, type=pathlib.Path)
    ap.add_argument("--qemu", default="qemu-system-x86_64")
    ap.add_argument("--boot-seconds", type=int, default=240)
    args = ap.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    version = subprocess.run(args.qemu.split() + ["--version"], capture_output=True, text=True).stdout.split("\n")[0]
    boots = []

    disk0 = args.work / "disk0.img"
    disk2 = args.work / "disk2.img"
    cd = args.work / "cd.iso"
    disk0.write_bytes(b"ABSD AHCI CENSUS WITNESS 0".ljust(4096, b"\0") * 1024)   # 4 MiB
    disk2.write_bytes(b"ABSD AHCI CENSUS WITNESS 2".ljust(4096, b"\0") * 512)    # 2 MiB
    cd.write_bytes(b"\0" * 65536)
    before = (sha(disk0), sha(disk2))
    devices = ["-drive", f"if=none,id=d0,file={disk0},format=raw", "-device", "ide-hd,drive=d0,bus=ide.0,model=QEMU HARDDISK,serial=CENSUS0",
               "-drive", f"if=none,id=cd1,file={cd},format=raw,media=cdrom", "-device", "ide-cd,drive=cd1,bus=ide.1",
               "-drive", f"if=none,id=d2,file={disk2},format=raw", "-device", "ide-hd,drive=d2,bus=ide.2,serial=CENSUS2"]
    record, lines, fw_writes, kwrites = boot(args, "q35-two-disks-cd", args.iso, "q35", "ide.5", devices, OK_EXIT)
    need("q35", lines, r"^AHCI CENSUS controller=00:1f\.2 8086:2922 class=01\.06\.01 abar=0x[0-9a-f]{16} abar_bytes=0x[0-9a-f]{8} version=\d+\.\d+\.\d+ cap=0x[0-9a-f]{8} ports_implemented=0x0000003f np=6 ncs=\d+ s64a=(yes|no) sss=(yes|no) bohc=\S+ ahci_enable=yes$")
    p0 = need("q35", lines, r'^AHCI PORT 0 det=3 spd=gen\d ipm=active sig=0x00000101 ata model="QEMU HARDDISK" serial="CENSUS0" firmware="\S+" sectors=8192 lba48=(yes|no) logical_sector=512 rotation=\S+ identify=ok$')
    need("q35", lines, r"^AHCI PORT 1 det=3 spd=gen\d ipm=active sig=0xeb140101 atapi identify=skipped \(no PACKET command issued\)$")
    need("q35", lines, r'^AHCI PORT 2 det=3 spd=gen\d ipm=active sig=0x00000101 ata model="QEMU HARDDISK" serial="CENSUS2" firmware="\S+" sectors=4096 lba48=(yes|no) logical_sector=512 rotation=\S+ identify=ok$')
    for port in (3, 4):
        need("q35", lines, rf"^AHCI PORT {port} det=0 spd=none ipm=none sig=0x[0-9a-f]{{8}} no-device$")
    need("q35", lines, r"^AHCI PORT 5 det=3 spd=gen\d ipm=active sig=0xeb140101 atapi identify=skipped \(no PACKET command issued\)$")
    need("q35", lines, r"^AHCI CENSUS OK controllers=1 refused=0 ports=6 ports_refused=0 ata=2 atapi=2 present_unprobed=0 identified=2 commands=2 \(IDENTIFY DEVICE only\) writes=0$")
    need("q35", lines, r"^AHCI CENSUS COMPLETE no device written; probed ports returned to the firmware's command list and FIS base with ST/FRE off; PCI command left with memory decode on, INTx masked, bus mastering off$")
    if sorted(record["ata_commands"]) != ["ec", "ec"]:
        raise SystemExit(f"q35: ATA commands after the kernel's first line {record['ata_commands']}, expected exactly two IDENTIFY DEVICE (0xec)")
    if any(w[0] == "hba" for w in kwrites):
        raise SystemExit(f"q35: the kernel wrote HBA-level registers: {[w for w in kwrites if w[0] == 'hba']}")
    touched = {w[0] for w in kwrites}
    if touched != {0, 2}:
        raise SystemExit(f"q35: the kernel wrote port registers of ports {sorted(touched)}, expected only the two ATA ports 0 and 2")
    record["ports_with_bases_restored"] = bases_restored("q35", fw_writes, kwrites)
    if (sha(disk0), sha(disk2)) != before:
        raise SystemExit("q35: a disk image changed")
    record["images_unchanged"] = True
    boots.append(record)
    print(f"  ok   q35-two-disks-cd: {p0[0]}")

    # 2. The pretend-RAID fixture ISO: refusal by name, nothing traced, exit 3.
    record, lines, _, kwrites = boot(args, "pretend-raid", args.raid_iso, "q35", "ide.5", devices, REFUSED_EXIT)
    need("pretend-raid", lines, r"^AHCI CENSUS controller=00:1f\.2 8086:2922 class=01\.06\.01 mode=raid REFUSED firmware RAID owns these disks: ports not probed, no register touched, no command issued fixture=pretend-raid$")
    need("pretend-raid", lines, r"^AHCI CENSUS OK controllers=0 refused=1 ports=0 ports_refused=0 ata=0 atapi=0 present_unprobed=0 identified=0 commands=0 \(IDENTIFY DEVICE only\) writes=0$")
    if record["ata_commands"]:
        raise SystemExit(f"pretend-raid: ATA commands traced although the controller was refused: {record['ata_commands']}")
    if kwrites:
        raise SystemExit(f"pretend-raid: AHCI register writes traced although the controller was refused: {kwrites}")
    if (sha(disk0), sha(disk2)) != before:
        raise SystemExit("pretend-raid: a disk image changed")
    record["images_unchanged"] = True
    boots.append(record)
    print("  ok   pretend-raid: refused by name, no ATA command traced")

    # 3. No AHCI at all (PIIX IDE): the boot CD and a disk on the legacy controller.
    record, lines, _, _ = boot(args, "pc-no-ahci", args.iso, "pc", "ide.1",
                         ["-drive", f"if=none,id=d0,file={disk0},format=raw", "-device", "ide-hd,drive=d0,bus=ide.0"], OK_EXIT)
    need("pc", lines, r"^AHCI CENSUS none \(no PCI class 01\.06 SATA or 01\.04 RAID function\)$")
    need("pc", lines, r"^AHCI CENSUS OK controllers=0 refused=0 ports=0 ports_refused=0 ata=0 atapi=0 present_unprobed=0 identified=0 commands=0 \(IDENTIFY DEVICE only\) writes=0$")
    if record["ata_commands"]:
        raise SystemExit(f"pc: ATA commands traced on a machine without AHCI: {record['ata_commands']}")
    boots.append(record)
    print("  ok   pc-no-ahci: none, no command")

    # 4. An AHCI controller with only the boot CD.
    record, lines, _, kwrites = boot(args, "q35-empty", args.iso, "q35", "ide.5", [], OK_EXIT)
    for port in range(5):
        need("q35-empty", lines, rf"^AHCI PORT {port} det=0 spd=none ipm=none sig=0x[0-9a-f]{{8}} no-device$")
    need("q35-empty", lines, r"^AHCI CENSUS OK controllers=1 refused=0 ports=6 ports_refused=0 ata=0 atapi=1 present_unprobed=0 identified=0 commands=0 \(IDENTIFY DEVICE only\) writes=0$")
    if record["ata_commands"]:
        raise SystemExit(f"q35-empty: ATA commands traced with no ATA device: {record['ata_commands']}")
    if kwrites:
        raise SystemExit(f"q35-empty: AHCI register writes traced with no ATA device: {kwrites}")
    boots.append(record)
    print("  ok   q35-empty: five empty ports and the boot CD, no register written")

    # 5. The physical ISO: its default entry halts on screen instead of exiting QEMU, so an
    # unattended machine never writes the debug-exit port; check the menu, not a boot.
    grub = subprocess.run(["xorriso", "-osirrox", "on", "-indev", str(args.physical_iso), "-extract", "/boot/grub/grub.cfg", str(args.work / "physical-grub.cfg")],
                          capture_output=True, text=True)
    cfg = (args.work / "physical-grub.cfg").read_text() if grub.returncode == 0 else ""
    entries = re.findall(r"multiboot2 /boot/absd-kernel (.*)$", cfg, re.M)
    if not entries or entries[0] != "ahci-census halt-on-exit" or "set default=0" not in cfg:
        raise SystemExit(f"physical ISO: default entry must be the halting census, got {entries}")
    print(f"  ok   physical ISO: default entry halts on screen; entries {entries}")

    # 6. The stuck-stop fixture: fail closed at controller level.
    disk3 = args.work / "disk3.img"
    disk3.write_bytes(b"ABSD AHCI CENSUS WITNESS 3".ljust(4096, b"\0") * 256)     # 1 MiB
    before3 = before + (sha(disk3),)
    stuck_devices = devices + ["-device", "ich9-ahci,id=ahci2", "-drive", f"if=none,id=d3,file={disk3},format=raw",
                               "-device", "ide-hd,drive=d3,bus=ahci2.0,serial=CENSUS3"]
    record, lines, _, _ = boot(args, "stuck-stop", args.stuck_iso, "q35", "ide.5", stuck_devices, REFUSED_EXIT)
    failed = need("stuck-stop", lines, r"^AHCI PORT (\d+) det=3 spd=gen\d ipm=active sig=0x00000101 ata identify=FAILED "
                  r"engine did not stop after IDENTIFY; bases not restored, data discarded$")
    refusal = need("stuck-stop", lines, r"^AHCI CENSUS controller=(\S+) REFUSED port (\d+) engine not shown quiescent \(engine did not stop "
                   r"after IDENTIFY; bases not restored, data discarded\): walk stopped, bus mastering off, bases left on the census "
                   r"buffers, census DMA buffers retired, remaining ports not probed$")
    stuck_bdf, stuck_port = re.match(r"^AHCI CENSUS controller=(\S+) REFUSED port (\d+)", refusal[0]).groups()
    # The refused controller's walk ends at that port: no later port line before the refusal.
    header = next(i for i, line in enumerate(lines) if line.startswith(f"AHCI CENSUS controller={stuck_bdf} ") and "abar=" in line)
    at = lines.index(refusal[0])
    walked = [re.match(r"^AHCI PORT (\d+) ", line).group(1) for line in lines[header:at] if line.startswith("AHCI PORT ")]
    if walked[-1] != stuck_port or len(walked) != len(set(walked)):
        raise SystemExit(f"stuck-stop: ports walked on {stuck_bdf} {walked}, expected the walk to end at port {stuck_port}")
    skipped = need("stuck-stop", lines, r"^AHCI PORT \d+ det=3 spd=gen\d ipm=active sig=0x00000101 ata identify=skipped "
                   r"\(census DMA buffers retired after a failed engine stop\)$")
    need("stuck-stop", lines, r"^AHCI CENSUS OK controllers=2 refused=1 ports=\d+ ports_refused=0 ata=\d+ atapi=\d+ present_unprobed=\d+ "
         r"identified=0 commands=1 \(IDENTIFY DEVICE only\) writes=0$")
    need("stuck-stop", lines, r"^AHCI CENSUS COMPLETE no device written; probed ports returned to the firmware's command list and FIS base "
         r"with ST/FRE off except 1 whose engine was not shown quiescent: its controller's walk stopped there with bus mastering off "
         r"at once, its bases untouched if the stop failed before IDENTIFY or left on the census buffers if after \(census DMA "
         r"buffers retired\); PCI command left with memory decode on, INTx masked, bus mastering off$")
    if record["ata_commands"] != ["ec"]:
        raise SystemExit(f"stuck-stop: ATA commands after the kernel's first line {record['ata_commands']}, expected one IDENTIFY")
    # Ordered trace after the kernel's first line: the IDENTIFY, then the refused controller's
    # bus-master-off command write, then no register write to that controller.
    trace = (args.work / "stuck-stop.trace").read_text(errors="replace").splitlines()
    serial_at, values = [], []
    for index, line in enumerate(trace):
        m = re.match(r"serial_write write addr 0x00 val 0x([0-9a-f]+)$", line)
        if m:
            serial_at.append(index)
            values.append(int(m.group(1), 16))
    cut = serial_at[bytes(values).find(MARKER)]
    kernel = trace[cut:]
    ident = next(i for i, line in enumerate(kernel) if re.match(r"^ide_bus_exec_cmd .* cmd 0xec$", line))
    port_rx = re.compile(r"^ahci_port_write ahci\((0x[0-9a-f]+)\)\[(\d+)\]: port write \[reg:(\w+)\] @ 0x[0-9a-f]+: 0x([0-9a-f]+)$")
    stuck_ahci = {m.group(1) for m in map(port_rx.match, kernel[:ident]) if m}
    if len(stuck_ahci) != 1:
        raise SystemExit(f"stuck-stop: port writes before the IDENTIFY came from {stuck_ahci}, expected one controller")
    stuck_ahci = stuck_ahci.pop()
    # QEMU 8.2: "pci_cfg_write ich9-ahci 00:03.0 @0x4 <- 0x407" (the kernel prints the same bb:dd.f).
    cfg_rx = re.compile(rf"^pci_cfg_write \S+ {re.escape(stuck_bdf)} @0x4 <- 0x([0-9a-f]+)$")
    bm_off = next((i for i, line in enumerate(kernel) if i > ident and (m := cfg_rx.match(line)) and not int(m.group(1), 16) & 4), None)
    if bm_off is None:
        raise SystemExit(f"stuck-stop: no PCI command write clearing bus mastering on {stuck_bdf} after the IDENTIFY")
    # Containment first: bus mastering is off before the kernel prints the failure.
    failed_at = bytes(values).find(b" identify=FAILED")
    if failed_at < 0 or serial_at[failed_at] - cut <= bm_off:
        raise SystemExit("stuck-stop: the failure was printed before bus mastering went off")
    after = [line for line in kernel[bm_off:] if (m := port_rx.match(line)) and m.group(1) == stuck_ahci]
    if after:
        raise SystemExit(f"stuck-stop: register writes to {stuck_bdf} after bus mastering went off: {after[:4]}")
    between = [port_rx.match(line) for line in kernel[ident:bm_off]]
    regs = [(m.group(2), m.group(3)) for m in between if m and m.group(1) == stuck_ahci]
    if any(reg in ("PxCLB", "PxCLBU", "PxFB", "PxFBU") for _, reg in regs) or {p for p, _ in regs} - {stuck_port}:
        raise SystemExit(f"stuck-stop: after the IDENTIFY {stuck_bdf} saw {regs}, expected only port {stuck_port} engine-stop writes")
    other = [m for m in map(port_rx.match, kernel) if m and m.group(1) != stuck_ahci]
    if other:
        raise SystemExit(f"stuck-stop: the other controller's ports were written although the buffers were retired: {other[:4]}")
    if (sha(disk0), sha(disk2), sha(disk3)) != before3:
        raise SystemExit("stuck-stop: a disk image changed")
    record.update(images_unchanged=True, stuck_controller=stuck_bdf, stuck_port=int(stuck_port),
                  writes_after_identify=regs, retired_skips=len(skipped))
    boots.append(record)
    print(f"  ok   stuck-stop: {stuck_bdf} port {stuck_port} refused, bus mastering off after the IDENTIFY, bases not written back, "
          f"{len(skipped)} ATA port(s) elsewhere skipped on retired buffers")

    (args.work / "result.json").write_text(json.dumps({"qemu_version": version, "accelerator": "tcg", "images_sha256_before": before,
                                                       "boots": boots, "result": "OK"}, indent=1))
    print(f"AHCI CENSUS CHECK OK boots={len(boots)} accel=tcg")


if __name__ == "__main__":
    main()
