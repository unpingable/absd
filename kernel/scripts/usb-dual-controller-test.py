#!/usr/bin/env python3
"""Two explicit xHCI functions; use the existing keyboard/QMP consumer.

--build-isos KERNEL builds only this fixture's ISOs; ordinary invocation runs
serialized QEMU 8.2.2 guests. No provisioning or external access is performed.
"""
import json
import os
from pathlib import Path
import re
import runpy
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
BASE = runpy.run_path(str(ROOT / "scripts/usb-keyboard-test.py"))
require = BASE["require"]
CASES = {
    "dual-default": "",
    "dual-first": "xhci-pci=00:04.0",
    "dual-second": "xhci-pci=00:05.0",
    "dual-missing": "xhci-pci=00:06.0",
    "dual-wrong-class": "xhci-pci=00:02.0",
    "dual-malformed": "xhci-pci=00:05.8",
    "dual-repeated": "xhci-pci=00:05.0 xhci-pci=00:04.0",
    "dual-first-refused": "xhci-pci=00:04.0",
}
REFUSALS = {
    "dual-missing": b"Selection(Missing(",
    "dual-wrong-class": b"Selection(WrongClass(",
    "dual-malformed": b"Selection(Malformed)",
    "dual-repeated": b"Selection(Repeated)",
    "dual-first-refused": b"Interrupt(MissingMsix)",
}
CONFIG_WRITE = re.compile(rb"pci_cfg_write \S+ (\w\w:\w\w\.\w) @0x([0-9a-f]+) <- 0x([0-9a-f]+)")


def check_selection(data, name):
    serial = BASE["console_bytes"](data)
    census = re.findall(rb"^XHCI CANDIDATE bdf=(\S+)$", serial, re.M)
    require(census == [b"00:04.0", b"00:05.0"], "wrong or incomplete xHCI census")
    # Exclude firmware traffic. raw_position preserves the boundary even when
    # trace records interrupt the census's UART bytes.
    boundary = serial.index(b"XHCI CANDIDATE bdf=")
    native = data[BASE["raw_position"](data, boundary):]
    writes = CONFIG_WRITE.findall(native)
    selected = re.findall(rb"^XHCI SELECTED bdf=(\S+) source=(\S+)$", serial, re.M)
    invalid = name in REFUSALS and name != "dual-first-refused"
    if invalid:
        require(not selected and b"XHCI CLAIMED" not in serial, "invalid selection reached claim")
        require(not any(bdf in {b"00:04.0", b"00:05.0"} for bdf, _, _ in writes),
                "invalid selection wrote controller config")
        require(not re.search(rb"usb_xhci_(?:oper|runtime|port|doorbell)_write ", native),
                "invalid selection wrote controller MMIO")
    else:
        target = b"00:05.0" if name == "dual-second" else b"00:04.0"
        source = b"default" if name == "dual-default" else b"explicit"
        require(selected == [(target, source)], "wrong selected controller or fallback")
        require(serial.count(b"XHCI CLAIMED") == 1, "wrong claim count")
        controller_writes = [bdf for bdf, _, _ in writes if bdf in {b"00:04.0", b"00:05.0"}]
        require(controller_writes and set(controller_writes) == {target}, "writes escaped selected BDF or evidence absent")
    if name in REFUSALS:
        require(b"USB KEYBOARD REFUSED " + REFUSALS[name] in serial, "wrong named refusal")
    if name != "dual-second":
        require(b"USB KEYBOARD READY" not in serial and b"USB KEYBOARD ENQUEUED" not in serial,
                "unselected second controller credited input")


def self_test():
    census = b"XHCI CANDIDATE bdf=00:04.0\nXHCI CANDIDATE bdf=00:05.0\n"
    selected = b"XHCI SELECTED bdf=00:05.0 source=explicit\n"
    write = b"pci_cfg_write qemu-xhci 00:05.0 @0x10 <- 0xffffffff\n"
    good = census + selected + b"XHCI CLAIMED pci_command=0000\n" + write + b"USB KEYBOARD READY\n"
    check_selection(good, "dual-second")
    # Firmware writes before the native census are outside the native claim.
    check_selection(write.replace(b"00:05.0", b"00:04.0") + good, "dual-second")
    missing = census + b"USB KEYBOARD REFUSED Selection(Missing(Function { bus: 0, device: 6, function: 0 }))\n"
    check_selection(missing, "dual-missing")
    bad = [good.replace(b"00:05.0 @", b"00:04.0 @"),
           good.replace(selected, b"XHCI SELECTED bdf=00:04.0 source=explicit\n"),
           good.replace(b"XHCI CANDIDATE bdf=00:04.0\n", b""),
           good.replace(write, b""),
           missing + write,
           missing + b"USB KEYBOARD READY\n",
           missing + selected,
           missing.replace(b"Missing", b"WrongClass")]
    for n, data in enumerate(bad):
        try:
            check_selection(data, "dual-second" if n < 4 else "dual-missing")
        except RuntimeError:
            continue
        raise RuntimeError(f"dual oracle accepted negative control {n}")
    print(f"usb-dual-controller-test: 3 positive, {len(bad)} negative controls")


def build_isos(kernel):
    require(kernel.is_file(), f"missing kernel {kernel}")
    for name, option in CASES.items():
        stage = ROOT / f"build/usb-keyboard-{name}-iso/boot"
        (stage / "grub").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(kernel, stage / "absd-kernel")
        (stage / "grub/grub.cfg").write_text(
            'set timeout=0\nmenuentry "ABSD dual xHCI" {\n'
            f'  multiboot2 /boot/absd-kernel shell usb-keyboard usb-keyboard-observe {option}\n'
            '  boot\n}\n')
        subprocess.run(["grub-mkrescue", "-o", str(ROOT / f"build/absd-usb-keyboard-{name}.iso"),
                        str(stage.parent)], check=True, stdout=subprocess.DEVNULL)


def snapshot(g, work, phase):
    g.qmp.execute("stop")
    try:
        pci = g.qmp.execute("query-pci")
        functions = runpy.run_path(str(ROOT / "scripts/xhci-observe.py"))["pci_functions"](pci)
        controllers = [f for f in functions if f.get("qdev_id") in {"first", "second"}]
        require(sorted((f["bus"], f["slot"], f["function"]) for f in controllers) == [(0, 4, 0), (0, 5, 0)],
                "independent PCI identities differ from explicit fixture")
        registers = {}
        if phase == "active":
            for f in controllers:
                bars = [r for r in f["regions"] if r["bar"] == 0 and r["type"] == "memory"]
                require(len(bars) == 1, "missing independent BAR0")
                bar = bars[0]["address"]
                record = {"bar": bar, "bar-size": bars[0]["size"]}
                registers[f["qdev_id"]] = record
                if bar <= 0:
                    record["observation"] = "BAR decode unavailable"
                    continue
                caps = g.qmp.words(bar, 8)
                record["capabilities"] = caps
                operational, runtime = caps[0] & 255, caps[6] & ~31
                if (operational < 32 or operational + 64 > bars[0]["size"]
                        or runtime + 64 > bars[0]["size"]):
                    record["observation"] = "capability reads unavailable or out of BAR bounds"
                    continue
                record["operational"] = g.qmp.words(bar + operational, 16)
                record["interrupter0"] = g.qmp.words(bar + runtime + 32, 8)
        monitor = g.qmp.execute("human-monitor-command", **{"command-line": "info pci"})
        (work / f"{g.name}-{phase}-pci.json").write_text(json.dumps(
            {"query-pci": pci, "info-pci": monitor, "registers": registers}, indent=2) + "\n")
    finally:
        g.qmp.execute("cont")


def run_case(name, qemu, work):
    first = "nec-usb-xhci,id=first,addr=04.0,msix=off" if name == "dual-first-refused" else "qemu-xhci,id=first,addr=04.0"
    devices = ["-vga", "none", "-device", "VGA,id=wrong,addr=02.0", "-device", first, "-device", "qemu-xhci,id=second,addr=05.0",
               "-device", "usb-kbd,id=kbd,bus=second.0,port=1"]
    g = BASE["Guest"](name, qemu, work, serial=True, variant=name, devices=devices,
                      paused=True, extra_traces=["pci_cfg_read", "pci_cfg_write"])
    try:
        snapshot(g, work, "before-boot")  # Resumes from -S after capturing identities.
        g.wait(rb"^> ")
        snapshot(g, work, "active")
        if name == "dual-second":
            g.endpoint(work)
            g.type("hello-b\n")
            g.wait(rb"shell: hello-b exited 0", shell=True)
            g.type("quit\n", final=True)
        else:
            # Inject actual events into the keyboard attached only to second.
            # Then complete a serial command before testing absence of credit.
            for key in ["h", "ret"]:
                g.key(key, wait=False)
                g.key(key, False, wait=False)
            g.write_serial("hello-b\n")
            g.wait(rb"shell: hello-b exited 0", shell=True)
            require(b"USB KEYBOARD ENQUEUED" not in g.console(), "second HID leaked into selected first")
            g.write_serial("quit\n")
        data = g.finish()
        BASE["check"](data, keyboard=name == "dual-second")
        check_selection(data, name)
    finally:
        g.close()


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    if len(sys.argv) == 3 and sys.argv[1] == "--build-isos":
        build_isos(Path(sys.argv[2]).resolve())
        return
    qemu = shlex.split(sys.argv[1] if len(sys.argv) > 1 else "qemu-system-x86_64")
    version = subprocess.check_output(qemu + ["--version"], text=True)
    require(re.search(r"version 8\.2\.2(?:\s|$)", version), "requires QEMU 8.2.2")
    parent = ROOT / "build/usb-dual-controller"
    parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="run-", dir=parent))
    (work / "qemu-version.txt").write_text(version)
    selected = os.environ.get("USB_DUAL_CASES", "").split() or list(CASES)
    require(not set(selected) - set(CASES), "unknown case selection")
    results = []
    try:
        for name in selected:
            try:
                run_case(name, qemu, work)
            except BaseException as error:
                results.append({"case": name, "result": "FAIL", "reason": str(error)})
                raise
            results.append({"case": name, "result": "PASS"})
            print(f"usb-dual-controller-test: {name}: PASS", flush=True)
    finally:
        (work / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        print(f"usb-dual-controller-test: evidence {work}", flush=True)


if __name__ == "__main__":
    main()
