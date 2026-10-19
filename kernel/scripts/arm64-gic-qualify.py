"""ARM64 interrupt-controller qualification on QEMU virt: GICv3 and the
GICv2 regression, with refusal controls (docs/ARM64.md).

    arm64-gic-qualify.py --image build/arm64/kernel.img --work DIR [--smp-image IMG]
                         [--accel tcg|hvf] [--qemu QEMU] [--cpu CPU] [--full-smp]

Boots: one vCPU under gic-version=3 and gic-version=2 (the whole A2 suite
must pass, and the kernel's `ARM GIC version=N` line must name the version
booted); controls derived from QEMU's own GICv3 tree (the tree re-packed and
passed back boots in full; the same tree with an unknown `compatible` or two
redistributor regions is refused by name before any GIC access; an unknown
PSCI method has no control, since QEMU regenerates the `psci` node of any
tree passed with -dtb); entry at EL2 with the PSCI conduit `smc`
(`virtualization=on`, which is how EL3 firmware and U-Boot hand a kernel
over) under both versions, where the kernel must report `entry_el=2
psci=smc` and pass the same suite, skipped with a recorded reason where the
accelerator cannot provide EL2; and, with --smp-image (the
arm64-smp-qualification build), two and four vCPUs under both versions and
both entry levels, where every CPU must receive timer and IPI interrupts
(`ARM SMP TIMER IPI OK`), and with --full-smp the whole B1 suite (`ARM B1
OK`), which the weak-memory litmus cases make HVF-only today: under TCG
they report a forbidden outcome for GICv2 as well, so without --full-smp an
SMP boot may end in exactly that litmus panic and nothing else, and the
result records that it did. Serial logs and result.json land in the work
directory.
"""
import argparse
import hashlib
import json
import pathlib
import re
import struct
import subprocess
import sys
import time


class Failed(Exception):
    pass


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def packed(dtb):
    """QEMU's dumped tree, re-packed to its used size (the dump is padded,
    and QEMU grows a passed-in tree past the kernel's size bound)."""
    (magic, _, off_struct, off_strings, _, _, _, _, size_strings, size_struct) = struct.unpack(">10I", dtb[:40])
    if magic != 0xD00DFEED:
        raise Failed("not a device tree")
    end = max(off_struct + size_struct, off_strings + size_strings)
    out = bytearray(dtb[:end])
    out[4:8] = struct.pack(">I", end)
    return bytes(out), off_struct, off_strings, size_strings


def with_redistributor_regions(dtb, value):
    """The tree with its `#redistributor-regions` cell set to `value`."""
    blob, off_struct, off_strings, size_strings = packed(dtb)
    strings = blob[off_strings:off_strings + size_strings]
    name_offset = (b"\0" + strings).index(b"\0#redistributor-regions\0")
    pos, hit = off_struct, None
    while True:
        token = struct.unpack(">I", blob[pos:pos + 4])[0]
        pos += 4
        if token == 1:
            pos = (blob.index(b"\0", pos) + 1 + 3) & ~3
        elif token == 3:
            length, name = struct.unpack(">II", blob[pos:pos + 8])
            pos += 8
            if name == name_offset and length == 4:
                hit = pos
            pos = (pos + length + 3) & ~3
        elif token == 9:
            break
    if hit is None:
        raise Failed("no #redistributor-regions property")
    out = bytearray(blob)
    out[hit:hit + 4] = struct.pack(">I", value)
    return bytes(out)


class Run:
    def __init__(self, args):
        self.args = args
        self.work = pathlib.Path(args.work).resolve()
        self.work.mkdir(parents=True, exist_ok=True)
        self.qemu = args.qemu.split()
        self.cpu = "host" if args.accel == "hvf" else args.cpu
        self.checks = 0
        self.record = {"started": time.time(), "accelerator": args.accel, "cpu": self.cpu,
                       "image_sha256": sha(args.image), "smp_image_sha256": sha(args.smp_image) if args.smp_image else None,
                       "qemu_version": subprocess.run(self.qemu[:1] + ["--version"], check=True, capture_output=True,
                                                      text=True).stdout.splitlines()[0], "boots": []}

    def check(self, name, ok, detail=""):
        self.checks += 1
        print(f"  {'ok  ' if ok else 'FAIL'} {name}", flush=True)
        if not ok:
            raise Failed(f"{name}: {detail}")

    def boot(self, name, gic, cpus, image, extra=(), dtb=None, machine="", timeout=None):
        serial = self.work / f"{name}.serial.log"
        serial.unlink(missing_ok=True)
        command = self.qemu + ["-machine", f"virt-8.2,gic-version={gic}{machine}",
                               "-accel", self.args.accel + (",thread=multi" if self.args.accel == "tcg" and cpus > 1 else ""),
                               "-cpu", self.cpu, "-smp", str(cpus), "-m", "512M", "-kernel", str(image), "-display", "none",
                               "-serial", f"file:{serial}", "-nic", "none", "-no-reboot"] + list(extra)
        if cpus > 1:
            command += ["-append", f"absd-arm-smp={cpus}"]
        if dtb is not None:
            command += ["-dtb", str(dtb)]
        started = time.monotonic()
        try:
            proc = subprocess.run(command, timeout=timeout or self.args.boot_seconds, capture_output=True, text=True)
            rc, err = proc.returncode, proc.stderr
        except subprocess.TimeoutExpired as expired:
            rc, err = "timeout", (expired.stderr or b"").decode(errors="replace") if isinstance(expired.stderr, bytes) else str(expired.stderr)
        text = serial.read_text(errors="replace") if serial.exists() else ""
        self.record["boots"].append({"name": name, "gic": gic, "cpus": cpus, "image": pathlib.Path(image).name,
                                     "command": [c.replace(str(self.work), "WORK") for c in command], "qemu_exit": rc,
                                     "seconds": round(time.monotonic() - started, 1), "serial": serial.name,
                                     "serial_sha256": sha(serial) if serial.exists() else None, "stderr": err[-300:]})
        return rc, text, err

    def el2_available(self, image):
        """Whether this accelerator gives the guest EL2 (`virtualization=on`).
        TCG always does, so there the EL2 boots are never skipped. Another
        accelerator may fail before the guest runs a single instruction (HVF
        aborts); that, and only that, is recorded as the reason the EL2 boots
        are skipped: an empty serial log and a failed QEMU. A guest that ran
        and then failed is a failure."""
        if self.args.accel == "tcg":
            return True
        rc, text, err = self.boot("el2-probe", 2, 1, image, machine=",virtualization=on", timeout=120)
        if rc != 0 and text == "":
            self.record["el2_skipped"] = f"rc={rc} stderr={err[-300:]!r}"
            print(f"  skip EL2 boots: the accelerator failed before the guest ran ({err.strip()[-160:]!r})", flush=True)
            return False
        self.check("el2-probe: the accelerator ran the guest at EL2", rc == 0 and "ARM BOOT entry_el=2 psci=smc\n" in text,
                   f"rc={rc} {text[:300]!r} {err[-200:]!r}")
        return True

    def full_boot(self, name, gic, cpus, image, dtb=None, el2=False):
        rc, text, err = self.boot(name, gic, cpus, image, dtb=dtb, machine=",virtualization=on" if el2 else "")
        self.check(f"{name}: QEMU exited 0 and the kernel booted", rc == 0 and "ABSD ARM64 KERNEL BOOT" in text, f"rc={rc} {err[-200:]!r}")
        entry = re.search(r"^ARM BOOT entry_el=(\d) psci=(hvc|smc)$", text, re.M)
        self.check(f"{name}: the kernel entered at EL{2 if el2 else 1} and reaches PSCI by {'smc' if el2 else 'hvc'}",
                   entry is not None and entry.groups() == (("2", "smc") if el2 else ("1", "hvc")), text[:300])
        line = re.search(r"^ARM GIC version=(\d) (.*)$", text, re.M)
        self.check(f"{name}: the kernel named GIC version {gic}", line is not None and int(line.group(1)) == gic, text[:400])
        if gic == 3:
            self.check(f"{name}: a redistributor frame inside the FDT region was used",
                       re.search(r"gicr=0x0+80a0000 frame=0x0+80[a-f0-9]{5}", line.group(2)) is not None, line.group(2))
        if cpus > 1 and not self.args.full_smp and "forbidden SC store-load outcome" in text:
            # The weak-memory litmus suite's own refusal under TCG (it runs
            # during bring-up, before EL0), after the interrupt-controller
            # evidence this run needs; recorded, not required to be absent.
            want = ["ARM TIMER OK", f"ARM SMP ONLINE cpus={cpus}", "ARM SMP TIMER IPI OK"]
            missing = [m for m in want if text.count(m + "\n") != 1]
            panics = re.findall(r"^ABSD ARM PANIC: (.*)$", text, re.M)
            self.check(f"{name}: timer and IPI interrupts reached every CPU before the litmus suite's TCG refusal: {', '.join(want)}",
                       not missing and len(panics) == 1 and "litmus.rs" in panics[0] and "ARM GIC version" in text,
                       f"missing={missing} panics={panics} tail={text[-300:]!r}")
            self.record["boots"][-1]["ended_by"] = "litmus forbidden-outcome panic under TCG (known; same under GICv2)"
            return text
        want = ["ARM TIMER OK", "ARM EL0 ENTER", "USER EXIT pid=1 status=0", "ARM A2 OK", "ARM PSCI POWEROFF"]
        if cpus > 1:
            want += [f"ARM SMP ONLINE cpus={cpus}", "ARM SMP TIMER IPI OK"]
            if self.args.full_smp:
                want += ["ARM WEAK MEMORY WITNESSES OK", "PORTABLE CROSS CPU STOP OK", "ARM SMP PARK RECLAIM OK", "ARM B1 OK"]
        missing = [m for m in want if text.count(m + "\n") != 1]
        self.check(f"{name}: every required marker once: {', '.join(want)}", not missing and "PANIC" not in text
                   and "ASSERTION FAILED" not in text and text.endswith("ARM PSCI POWEROFF\n"), f"missing={missing} tail={text[-300:]!r}")
        preempts = re.search(r"^ARM A2 RECLAIM OK preempts=(\d+)$", text, re.M)
        self.check(f"{name}: the kernel's own reclamation accounting passed with preemption", preempts is not None and int(preempts.group(1)) > 0)
        if cpus > 1:
            rows = re.findall(r"^ARM SMP CPU cpu=(\d+) dispatches=(\d+) timers=(\d+) ipis=(\d+)$", text, re.M)
            if self.args.full_smp:
                self.check(f"{name}: every CPU received timer and IPI interrupts",
                           len(rows) == cpus and all(int(t) > 0 and int(i) > 0 for _, _, t, i in rows), str(rows))
                cases = len(re.findall(r"^ARM LITMUS case=\S+ peer=\d+ witnesses=\d+ PASS$", text, re.M))
                self.check(f"{name}: the litmus cases passed for every peer", cases == 10 * (cpus - 1), str(cases))
        return text

    def refused_boot(self, name, gic, image, reason, dtb=None, machine=""):
        # A refused boot panics and never powers off; a minute is plenty.
        rc, text, err = self.boot(name, gic, 1, image, dtb=dtb, machine=machine, timeout=60)
        self.check(f"{name}: refused by name before any interrupt controller use: {reason}",
                   "ABSD ARM64 KERNEL BOOT" in text and f'"{reason}"' in text and "ARM GIC version" not in text
                   and "ARM A2 OK" not in text, f"rc={rc} {text[:400]!r} {err[-200:]!r}")

    def run(self):
        image = pathlib.Path(self.args.image).resolve()
        self.full_boot("gic3-1cpu", 3, 1, image)
        self.full_boot("gic2-1cpu", 2, 1, image)
        # Controls from QEMU's own GICv3 tree.
        dumped = self.work / "virt-gic3.dtb"
        dumped.unlink(missing_ok=True)
        subprocess.run(self.qemu + ["-machine", f"virt-8.2,gic-version=3,dumpdtb={dumped}", "-accel", self.args.accel, "-cpu", self.cpu,
                                    "-smp", "1", "-m", "512M", "-display", "none", "-nic", "none"], check=True, capture_output=True)
        raw = dumped.read_bytes()
        good, _, _, _ = packed(raw)
        self.check("control: QEMU's GICv3 tree names arm,gic-v3 once", good.count(b"arm,gic-v3\0") == 1)
        (self.work / "control-packed.dtb").write_bytes(good)
        (self.work / "control-bogus.dtb").write_bytes(good.replace(b"arm,gic-v3\0", b"arm,gic-v9\0"))
        (self.work / "control-two-regions.dtb").write_bytes(with_redistributor_regions(raw, 2))
        self.full_boot("gic3-packed-tree", 3, 1, image, dtb=self.work / "control-packed.dtb")
        self.refused_boot("gic3-bogus-compatible", 3, image, "FDT unsupported GIC version", dtb=self.work / "control-bogus.dtb")
        self.refused_boot("gic3-two-regions", 3, image, "FDT unsupported GIC redistributor regions", dtb=self.work / "control-two-regions.dtb")
        el2 = self.el2_available(image)
        if el2:
            self.full_boot("gic3-1cpu-el2", 3, 1, image, el2=True)
            self.full_boot("gic2-1cpu-el2", 2, 1, image, el2=True)
        if self.args.smp_image:
            smp = pathlib.Path(self.args.smp_image).resolve()
            for gic in (3, 2):
                for cpus in (2, 4):
                    self.full_boot(f"gic{gic}-{cpus}cpu", gic, cpus, smp)
                    if el2:
                        self.full_boot(f"gic{gic}-{cpus}cpu-el2", gic, cpus, smp, el2=True)
        self.record.update(checks=self.checks, result="OK", finished=time.time())
        (self.work / "result.json").write_text(json.dumps(self.record, indent=1))
        print(f"ARM GIC QUALIFY OK boots={len(self.record['boots'])} checks={self.checks} accel={self.args.accel} "
              f"full_smp={self.args.full_smp}", flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image", required=True, help="kernel.img from make arm64-build")
    ap.add_argument("--smp-image", help="kernel.img from make arm64-smp-build (two and four vCPUs)")
    ap.add_argument("--work", required=True)
    ap.add_argument("--accel", choices=("tcg", "hvf"), default="tcg")
    ap.add_argument("--qemu", default="qemu-system-aarch64")
    ap.add_argument("--cpu", default="cortex-a72", help="for tcg; hvf uses host")
    ap.add_argument("--full-smp", action="store_true", help="require the whole B1 suite on the SMP boots (HVF)")
    ap.add_argument("--boot-seconds", type=int, default=600)
    args = ap.parse_args()
    run = Run(args)
    try:
        run.run()
    except Exception as error:  # noqa: BLE001 - every failure is recorded the same way
        run.record.update(result="FAILED", error=f"{type(error).__name__}: {error}", checks=run.checks)
        (run.work / "result.json").write_text(json.dumps(run.record, indent=1))
        print(f"ARM GIC QUALIFY FAILED: {type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
