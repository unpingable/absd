#!/usr/bin/env python3
"""Bounded QEMU controller/IRQ cases. No USB class or physical device access.

Run after make xhci-controller-iso in an admitted guest slot. Each child is
waited for in the foreground and has a 120 s outer deadline. Fresh logs are
retained under build/xhci-controller until candidate acceptance; the lane
owner retires that exact directory afterwards. No existing log is replaced.
"""
import json
import os
from pathlib import Path
import re
import runpy
import shlex
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
CASES = [
    ("absent", "base", [], None),
    ("empty", "observe", ["-device", "qemu-xhci,id=xhci"], None),
    ("keyboard", "base", ["-device", "qemu-xhci,id=xhci", "-device", "usb-kbd,bus=xhci.0,port=1"], None),
    ("nec", "base", ["-device", "nec-usb-xhci,id=xhci", "-device", "usb-kbd,bus=xhci.0,port=1"], None),
    ("no-msix", "base", ["-device", "nec-usb-xhci,id=xhci,msix=off"], "unavailable"),
    ("masked", "masked", ["-device", "qemu-xhci,id=xhci"], "Interrupt(CompletedWithoutInterrupt)"),
    ("storm", "storm", ["-device", "qemu-xhci,id=xhci"], "Interrupt(InterruptStorm)"),
    ("late", "late", ["-device", "qemu-xhci,id=xhci"], None),
    ("rounds", "rounds", ["-device", "qemu-xhci,id=xhci"], None),
    ("run-timeout", "run-timeout", ["-device", "qemu-xhci,id=xhci"], 'Timeout("run")'),
    ("legacy-smi", "legacy-smi", ["-device", "qemu-xhci,id=xhci"], None),
    ("legacy-reacquire", "legacy-reacquire", ["-device", "qemu-xhci,id=xhci"], "unavailable"),
    ("legacy-probe-loss", "legacy-probe-loss", ["-device", "qemu-xhci,id=xhci"], "abandoned"),
]
# QEMU 8.2 declares usb_xhci_irq_msix but its PCI callback never emits it.
# Observe the message at the BSP LAPIC instead, alongside the independently
# sampled MSI-X table and the guest's ISR count. Other vectors cannot credit USB.
USB_DELIVERY = re.compile(r"^apic_deliver_irq dest 0 dest_mode 0 delivery_mode 0 vector 208 trigger_mode 0$", re.M)
USB_VECTOR_DELIVERY = re.compile(r"^apic_deliver_irq .* vector 208 trigger_mode [0-9]+$", re.M)
TRACES = ["apic_deliver_irq", "usb_xhci_irq_msix_use", "usb_xhci_irq_msix_unuse",
          "usb_xhci_oper_write", "usb_xhci_port_write", "usb_xhci_runtime_write",
          "usb_xhci_doorbell_write", "pci_cfg_write", "msix_write_config"]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def observe_table(args, output, log_path, work):
    """Read the running route from QEMU, independently of the guest's
    decoded MSI-X metadata. This case pins QEMU 8.2's table/PBA offsets.
    Reuse the existing observer's QMP and PCI-selection helpers unchanged.
    """
    helpers = runpy.run_path(str(ROOT / "scripts/xhci-observe.py"))
    qmp_path = work / "qmp.sock"
    require(len(str(qmp_path).encode()) < 108, "QMP socket path too long")
    deadline = time.monotonic() + 120
    process = subprocess.Popen(args + ["-qmp", f"unix:{qmp_path},server=on,wait=off"], stdout=output, stderr=subprocess.STDOUT, cwd=ROOT)
    qmp = None
    observed = None
    try:
        qmp = helpers["Qmp"](str(qmp_path), process, deadline)
        qmp.sock.settimeout(5)
        while process.poll() is None and time.monotonic() < deadline:
            match = helpers["READY"].search(log_path.read_bytes())
            if match and observed is None:
                qmp.execute("stop")
                _, guest_bar, operational, _ = [int(value, 16 if n in (1, 2) else 10) for n, value in enumerate(match.groups())]
                bar = helpers["device_bar"](qmp, guest_bar)
                hcs = qmp.words(bar + 4, 1)[0]
                intrs = (hcs >> 8) & 0x7ff
                require(0 < intrs <= 1024, "invalid device MaxIntrs")
                table = qmp.words(bar + 0x3000, intrs * 4)
                require(table[:4] == [0xfee00000, 0, 0xd0, 0], "QEMU table entry 0 is not the unmasked BSP route")
                require(all(table[index * 4 + 3] & 1 for index in range(1, intrs)), "another vector is unmasked")
                runtime = qmp.words(bar + 0x18, 1)[0] & ~0x1f
                usbcmd = qmp.words(bar + operational, 1)[0]
                iman, imod = qmp.words(bar + runtime + 0x20, 2)
                require(usbcmd & 5 == 5 and iman & 2, "controller interrupt enable is absent")
                require(imod == 0, "interrupt moderation was not initialized to zero")
                pending = qmp.quadwords(bar + 0x3800, (intrs + 63) // 64)
                observed = {"bar": bar, "max_intrs": intrs, "table_entry0": table[:4], "unused_entries_masked": True, "iman": iman, "imod": imod, "pba": pending}
                (work / "table-observation.json").write_text(json.dumps(observed, indent=2) + "\n")
                qmp.execute("cont")
            time.sleep(0.02)
        require(time.monotonic() < deadline, "observer QEMU deadline expired")
        require(observed is not None, "running controller was never independently observed")
        return process.wait(timeout=max(1, deadline - time.monotonic()))
    finally:
        if process.poll() is None:
            process.kill()  # Exact child created by this call; never a pattern.
            process.wait()
        if qmp is not None:
            qmp.lines.close()
            qmp.sock.close()
        if qmp_path.exists():
            qmp_path.unlink()


def check(name, error, log):
    require("ABSD BOOT OK\n" in log, "ordinary boot did not complete")
    require(not re.search(r"PANIC|KERNEL FAULT|XHCI IRQ NOT QUIET|XHCI FIRMWARE MODEL VIOLATION", log), "fault or IRQ quiescence failure")
    if name == "absent":
        require("XHCI UNAVAILABLE Absent\n" in log, "absence not reported")
        return
    if error == "abandoned":
        require("XHCI UNAVAILABLE OwnershipLost(" in log, "probe ownership loss not reported")
        require("XHCI ABANDONED owner=ownership-lost " in log, "lost ownership was treated as preservation or release")
        require(re.search(r"^XHCI FIRMWARE MODEL .* violations=0 ",log,re.M), "cleanup wrote without ownership")
        require("XHCI RUNNING" not in log, "controller started after probe ownership loss")
        return
    if error == "unavailable":
        expected = "Interrupt(MissingMsix)" if name == "no-msix" else "Refused(Handoff("
        require("XHCI UNAVAILABLE " + expected in log, "wrong unavailability reason")
        require("XHCI RUNNING" not in log, "refused controller ran")
        return
    require("XHCI IRQ QUIET generation=" in log, "no terminal IRQ quiet observation")
    require("XHCI DMA OFF bus_master=0 " in log, "DMA disable not read back")
    require("halted=no" not in log, "controller did not halt")
    require(re.search(r"^XHCI HALTED round=1 halted=yes ",log,re.M), "halt was not observed")
    if error:
        require("XHCI FAILED round=1 error=" + error + "\n" in log, "wrong failure reason")
        require("XHCI STOPPED\n" in log and "XHCI DONE" not in log, "failed controller continued")
    else:
        require("XHCI FAILED" not in log, "controller failed")
        rounds = 3 if name == "rounds" else 1
        require(f"XHCI DONE rounds={rounds}\n" in log, "rounds incomplete")
        for generation in range(1, rounds + 1):
            require(re.search(rf"^XHCI HALTED round={generation} halted=yes ",log,re.M), "generation did not halt")
            require(re.search(rf"^XHCI IRQ DRAINED generation={generation} count=[1-9][0-9]* late=[0-9]+$", log, re.M), "no genuine IRQ progress in generation")
            require(f"XHCI COMMAND RING OK round={generation} noops=40 command_ring_wraps=2 event_ring_wraps=2\n" in log, "command/event wrap missing")
        require(USB_DELIVERY.search(log), "no external delivery of USB vector 208 to the BSP")
    if name in ("keyboard", "nec"):
        require("XHCI EP0 OK round=1 reads=8 transfer_ring_wraps=3\n" in log, "EP0/transfer wrap missing")
    if name == "late":
        require("XHCI LATE MSI PENDING source=device\n" in log, "no actual pending device MSI")
        require(re.search(r"^XHCI IRQ DRAINED generation=1 count=[0-9]+ late=[1-9][0-9]*$", log, re.M), "pending MSI not delivered as retired")
    if name == "masked":
        require(re.search(r"^XHCI IRQ DRAINED generation=1 count=0 late=[0-9]+$",log,re.M), "masked vector received IRQ credit")
        require(not USB_VECTOR_DELIVERY.search(log), "masked vector reached an APIC")
    if name == "storm":
        require("XHCI FAULT INJECTED interrupt-storm source=software-entry\n" in log, "no ISR-entry storm fixture")
        require(re.search(r"^XHCI IRQ DRAINED generation=1 count=65 late=[0-9]+$",log,re.M), "wrong storm budget crossing")
    if name == "legacy-smi":
        require(re.search(r"^XHCI FIRMWARE MODEL .* violations=0 ", log, re.M), "firmware model saw a write without ownership")
    # The marker follows all driver stop/disable writes. Only reads and
    # ordinary boot work may follow it; check the external device trace.
    after = log.split("XHCI IRQ QUIET generation=", 1)[1]
    require(not USB_VECTOR_DELIVERY.search(after), "USB message delivered after quiet marker")
    require(not re.search(r"^usb_xhci_(irq_msix|oper_write|port_write|runtime_write|doorbell_write)\b|^pci_cfg_write (qemu-xhci|nec-usb-xhci) |^msix_write_config ", after, re.M), "device/configuration activity after quiet marker")


def self_test():
    good = "\n".join([
        "apic_deliver_irq dest 0 dest_mode 0 delivery_mode 0 vector 208 trigger_mode 0", "XHCI IRQ DRAINED generation=1 count=40 late=0",
        "XHCI COMMAND RING OK round=1 noops=40 command_ring_wraps=2 event_ring_wraps=2",
        "XHCI HALTED round=1 halted=yes commands=40 transfers=0 events=40 port_events=0",
        "XHCI DONE rounds=1", "XHCI DMA OFF bus_master=0 command=0402",
        "XHCI IRQ QUIET generation=1 late=0", "ABSD BOOT OK", ""])
    check("empty",None,good)
    bad = [good.replace("count=40", "count=0"),
           good.replace("XHCI HALTED", "missing halt record"),
           good.replace("apic_deliver_irq dest 0 dest_mode 0 delivery_mode 0 vector 208 trigger_mode 0\n", ""),
           good + "usb_xhci_oper_write 0\n",
           good + "msix_write_config changed\n", good + "KERNEL FAULT\n",
           good.replace("vector 208", "vector 32"),
           good.replace("dest 0 dest_mode", "dest 1 dest_mode"),
           good.replace("apic_deliver_irq dest 0 dest_mode 0 delivery_mode 0 vector 208 trigger_mode 0", "usb_xhci_irq_msix_use nr 0"),
           good + "apic_deliver_irq dest 0 dest_mode 0 delivery_mode 0 vector 208 trigger_mode 0\n"]
    for fixture in bad:
        try:
            check("empty",None,fixture)
        except RuntimeError:
            continue
        raise RuntimeError("controller oracle accepted a negative fixture")
    abandoned = "\n".join(["XHCI UNAVAILABLE OwnershipLost(Lost { legsup: 65537 })",
        "XHCI ABANDONED owner=ownership-lost usbcmd=00000000 pci_command=0406 bus_master=1 statics=reserved",
        "XHCI FIRMWARE MODEL behaviour=Reacquire(2) violations=0 legsup=00010001", "ABSD BOOT OK", ""])
    check("legacy-probe-loss","abandoned",abandoned)
    try:
        check("legacy-probe-loss","abandoned",abandoned.replace("violations=0","violations=1"))
    except RuntimeError:
        pass
    else:
        raise RuntimeError("ownership-loss oracle accepted cleanup mutation")
    def rejects(name, error, fixtures):
        for fixture in fixtures:
            try:
                check(name, error, fixture)
            except RuntimeError:
                continue
            raise RuntimeError(f"{name} oracle accepted a negative fixture")

    def failed(reason, count):
        return good.replace("apic_deliver_irq dest 0 dest_mode 0 delivery_mode 0 vector 208 trigger_mode 0\n", "").replace("count=40", f"count={count}").replace(
            "XHCI DONE rounds=1", f"XHCI FAILED round=1 error={reason}\nXHCI STOPPED")

    masked_error = "Interrupt(CompletedWithoutInterrupt)"
    masked = failed(masked_error, 0)
    check("masked", masked_error, masked)
    rejects("masked", masked_error, [masked.replace("count=0", "count=1"),
            masked.replace(masked_error, 'Timeout("no-op")'),
            "apic_deliver_irq dest 0 dest_mode 0 delivery_mode 0 vector 208 trigger_mode 0\n" + masked])
    storm_error = "Interrupt(InterruptStorm)"
    storm = failed(storm_error, 65) + "XHCI FAULT INJECTED interrupt-storm source=software-entry\n"
    check("storm", storm_error, storm)
    rejects("storm", storm_error, [storm.replace("count=65", "count=64"),
            storm.replace("XHCI FAULT INJECTED", "missing fixture")])
    late = good.replace("count=40 late=0", "count=40 late=1") + "XHCI LATE MSI PENDING source=device\n"
    check("late", None, late)
    rejects("late", None, [late.replace("count=40 late=1", "count=40 late=0"),
            late.replace("XHCI LATE MSI PENDING", "missing pending")])
    unavailable = "XHCI UNAVAILABLE Interrupt(MissingMsix)\nABSD BOOT OK\n"
    check("no-msix", "unavailable", unavailable)
    rejects("no-msix", "unavailable", [unavailable.replace("MissingMsix", "Apic"),
            unavailable + "XHCI RUNNING round=1\n"])
    print("xhci-controller-test: oracle self-test: 6 positive and 20 negative fixtures passed")


def main():
    if sys.argv[1:]==["--self-test"]:
        self_test()
        return
    qemu = shlex.split(sys.argv[1] if len(sys.argv) > 1 else "qemu-system-x86_64")
    parent = ROOT / "build/xhci-controller"
    parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="run-", dir=parent))
    selected = os.environ.get("XHCI_CONTROLLER_CASES", "").split()
    require(not (set(selected) - {c[0] for c in CASES}), "unknown case selection")
    results = []
    try:
        for name, iso, devices, error in CASES:
            if selected and name not in selected:
                continue
            args = qemu + ["-accel", "tcg", "-m", "128M", "-display", "none", "-no-reboot", "-no-shutdown",
                "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-serial", "stdio",
                "-cdrom", str(ROOT / f"build/absd-xhci-controller-{iso}.iso")]
            for event in TRACES:
                args += ["-trace", event]
            args += devices
            start = time.monotonic()
            with (work / f"{name}.log").open("w") as output:
                if name == "empty":
                    status = observe_table(args, output, work / f"{name}.log", work)
                else:
                    status = subprocess.run(args, stdout=output, stderr=subprocess.STDOUT, timeout=120, cwd=ROOT, check=False).returncode
            require(status == 3, f"QEMU exited {status}, expected 3")
            check(name, error, (work / f"{name}.log").read_text())
            results.append({"case": name, "result": "PASS", "seconds": round(time.monotonic() - start, 3)})
            print(f"xhci-controller-test: {name}: PASS", flush=True)
    except (Exception, SystemExit, KeyboardInterrupt) as error:
        results.append({"case": name, "result": "FAIL", "reason": str(error)})
        raise
    finally:
        (work / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        print(f"xhci-controller-test: logs {work}", flush=True)
    print(f"xhci-controller-test: {len(results)} cases passed")


if __name__ == "__main__":
    main()
