#!/usr/bin/env python3
"""Observe an `xhci-observe` boot's controller from outside the guest
(docs/xhci-hw-readiness-20261010/RECORD.md).

Usage: xhci-observe.py WORKDIR SERIAL_LOG OBSERVATIONS QEMU_COMMAND...
       xhci-observe.py --self-test

Starts QEMU with the given command plus a QMP socket (WORKDIR/qmp.sock) and
the serial log. Each time the guest prints

    XHCI OBSERVE READY round=R bar=0x... operational=0x... scratchpads=N

(it then keeps the controller running for a few seconds), the guest is
paused and the controller's BAR 0 is taken from QEMU's own PCI state
(QMP `query-pci`: the one qemu-xhci function, 1b36:000d class 0c03, with
an assigned memory BAR 0); the guest's `bar=` must equal it, or the run
fails. Through the monitor's physical-memory reads (`xp`) this script then
reads what the controller itself would use: USBCMD and DCBAAP from the
device's registers (BAR + operational offset), DCBAA entry 0 from guest
memory at the address the device holds, and, if that entry is nonzero, the
first 65 Scratchpad Buffer Array entries. The only value it takes from the
guest's log is the operational offset. Then the guest is resumed. One line
per observation goes to OBSERVATIONS:

    OBSERVED round=R usbcmd=XXXXXXXX dcbaap=0x... dcbaa0=0x... entries=E
        aligned=0|1 distinct=0|1 terminator=0x... lowest=0x... highest=0x...

`entries` counts the leading nonzero array entries; `aligned` is 1 when each
is 4 KiB-aligned; `distinct` when no two are equal; `terminator` is the entry
after them. The caller compares `entries` with the count the case asked
for. Exits with QEMU's exit status, or 1 on a harness failure.

`--self-test` checks the `query-pci` selection against canned replies,
without QEMU.
"""
import json
import os
import re
import socket
import subprocess
import sys
import time

TIMEOUT = 150.0
ARRAY_READ = 65
# qemu-xhci's PCI identity and the USB controller class (0c03).
XHCI_ID = (0x1B36, 0x000D)
USB_CLASS = 0x0C03
READY = re.compile(
    rb"^XHCI OBSERVE READY round=(\d+) bar=0x([0-9a-f]+) operational=0x([0-9a-f]+) "
    rb"scratchpads=(\d+)$",
    re.MULTILINE,
)


def fail(message: str) -> None:
    print(f"xhci-observe: {message}", file=sys.stderr)
    sys.exit(1)


class Qmp:
    def __init__(self, path: str, qemu, deadline: float):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        while True:
            try:
                self.sock.connect(path)
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if qemu.poll() is not None or time.monotonic() > deadline:
                    fail("QEMU offered no QMP socket")
                time.sleep(0.05)
        self.lines = self.sock.makefile("rwb", buffering=0)
        self.lines.readline()  # the greeting
        self.execute("qmp_capabilities")

    def execute(self, command: str, **arguments):
        request = {"execute": command}
        if arguments:
            request["arguments"] = arguments
        self.lines.write((json.dumps(request) + "\n").encode())
        while True:
            line = self.lines.readline()
            if not line:
                fail(f"QMP connection closed during {command}")
            answer = json.loads(line)
            if "error" in answer:
                fail(f"QMP {command}: {answer['error']}")
            if "return" in answer:
                return answer["return"]

    def words(self, address: int, count: int) -> list:
        """`count` 32-bit words of guest-physical memory (or device
        registers) at `address`, through the monitor."""
        text = self.execute("human-monitor-command",
                            **{"command-line": f"xp /{count}wx {address:#x}"})
        values = []
        for line in text.splitlines():
            _, _, rest = line.partition(":")
            values += [int(token, 16) for token in re.findall(r"0x[0-9a-f]+", rest)]
        if len(values) != count:
            fail(f"xp {address:#x} returned {len(values)} words, not {count}: {text!r}")
        return values

    def quadwords(self, address: int, count: int) -> list:
        words = self.words(address, 2 * count)
        return [words[i] | (words[i + 1] << 32) for i in range(0, len(words), 2)]


class SelectError(Exception):
    pass


def pci_functions(buses: list):
    """Every function in a `query-pci` reply, behind bridges included."""
    for bus in buses:
        pending = list(bus.get("devices", []))
        while pending:
            device = pending.pop(0)
            yield device
            pending += device.get("pci_bridge", {}).get("devices", [])


def xhci_bar(buses: list) -> int:
    """BAR 0 of the single qemu-xhci function in a `query-pci` reply."""
    found = [
        device for device in pci_functions(buses)
        if (device["id"]["vendor"], device["id"]["device"]) == XHCI_ID
        and device["class_info"]["class"] == USB_CLASS
    ]
    if len(found) != 1:
        raise SelectError(f"query-pci shows {len(found)} qemu-xhci functions, not 1")
    bars = [region for region in found[0].get("regions", []) if region["bar"] == 0]
    if len(bars) != 1 or bars[0]["type"] != "memory":
        raise SelectError("the qemu-xhci function has no memory BAR 0")
    address = bars[0]["address"]
    if address <= 0:
        raise SelectError(f"the qemu-xhci BAR 0 is unassigned or decode is off: {address:#x}")
    return address


def device_bar(qmp: Qmp, guest_bar: int) -> int:
    """The BAR from `query-pci`, refused unless the guest reported the same."""
    try:
        bar = xhci_bar(qmp.execute("query-pci"))
    except (KeyError, TypeError, AttributeError) as error:
        raise SelectError(f"malformed query-pci reply: {error!r}") from error
    if bar != guest_bar:
        raise SelectError(f"the guest reported bar={guest_bar:#x}; query-pci shows {bar:#x}")
    return bar


def self_test() -> int:
    def function(slot, vendor, device, class_, regions, bridge=None):
        entry = {
            "bus": 0, "slot": slot, "function": 0, "irq_pin": 1, "qdev_id": "",
            "class_info": {"class": class_},
            "id": {"vendor": vendor, "device": device},
            "regions": regions,
        }
        if bridge is not None:
            entry["pci_bridge"] = {"bus": {"number": 0, "secondary": 1, "subordinate": 1},
                                   "devices": bridge}
        return entry

    def memory(bar, address):
        return {"bar": bar, "type": "memory", "address": address, "size": 0x4000,
                "prefetch": False, "mem_type_64": True}

    host = function(0, 0x8086, 0x1237, 0x0600, [])
    nvme = function(5, 0x1B36, 0x0010, 0x0108, [memory(0, 0xFEBF0000)])
    xhci = function(4, 0x1B36, 0x000D, USB_CLASS, [memory(0, 0xFEBF4000)])
    high = function(4, 0x1B36, 0x000D, USB_CLASS, [memory(0, 0x8000_0000_0000)])
    accepted = {
        "plain": ([{"bus": 0, "devices": [host, xhci, nvme]}], 0xFEBF4000),
        "behind-bridge": ([{"bus": 0, "devices": [
            host, function(3, 0x1B36, 0x000C, 0x0604, [], bridge=[xhci])]}], 0xFEBF4000),
        "above-4g": ([{"bus": 0, "devices": [high]}], 0x8000_0000_0000),
    }
    refused = {
        "absent": [{"bus": 0, "devices": [host, nvme]}],
        "two": [{"bus": 0, "devices": [xhci, dict(xhci, slot=6)]}],
        "other-usb": [{"bus": 0, "devices": [
            function(4, 0x8086, 0xA12F, USB_CLASS, [memory(0, 0xFEBF4000)])]}],
        "unassigned": [{"bus": 0, "devices": [
            function(4, 0x1B36, 0x000D, USB_CLASS, [memory(0, -1)])]}],
        "zero": [{"bus": 0, "devices": [
            function(4, 0x1B36, 0x000D, USB_CLASS, [memory(0, 0)])]}],
        "io-bar": [{"bus": 0, "devices": [function(4, 0x1B36, 0x000D, USB_CLASS, [
            {"bar": 0, "type": "io", "address": 0xC000, "size": 32}])]}],
        "other-class": [{"bus": 0, "devices": [
            function(4, 0x1B36, 0x000D, 0x0C80, [memory(0, 0xFEBF4000)])]}],
        "no-bar0": [{"bus": 0, "devices": [
            function(4, 0x1B36, 0x000D, USB_CLASS, [memory(2, 0xFEBF4000)])]}],
    }
    for name, (reply, want) in accepted.items():
        got = xhci_bar(json.loads(json.dumps(reply)))
        if got != want:
            fail(f"self-test {name}: {got:#x}, not {want:#x}")
    for name, reply in refused.items():
        try:
            got = xhci_bar(json.loads(json.dumps(reply)))
        except SelectError:
            continue
        fail(f"self-test {name}: accepted {got:#x}")

    class Canned:
        def __init__(self, reply):
            self.reply = reply

        def execute(self, command):
            assert command == "query-pci"
            return json.loads(json.dumps(self.reply))

    malformed = {
        "no-regions": [{"bus": 0, "devices": [
            {k: v for k, v in xhci.items() if k != "regions"}]}],
        "no-id": [{"bus": 0, "devices": [{k: v for k, v in xhci.items() if k != "id"}]}],
        "null-address": [{"bus": 0, "devices": [
            function(4, 0x1B36, 0x000D, USB_CLASS, [memory(0, None)])]}],
        "null-bridge": [{"bus": 0, "devices": [dict(host, pci_bridge=None), xhci]}],
    }
    for name, reply in malformed.items():
        try:
            got = device_bar(Canned(reply), 0xFEBF4000)
        except SelectError:
            continue
        fail(f"self-test malformed {name}: accepted {got:#x}")

    if device_bar(Canned(accepted["plain"][0]), 0xFEBF4000) != 0xFEBF4000:
        fail("self-test agreeing guest bar not returned")
    try:
        device_bar(Canned(accepted["plain"][0]), 0xFEBF8000)
    except SelectError:
        pass
    else:
        fail("self-test guest bar that disagrees with query-pci was accepted")
    print(f"xhci-observe self-test OK accepted={len(accepted)} refused={len(refused)} "
          f"malformed={len(malformed)} guest-mismatch=refused")
    return 0


def observe(qmp: Qmp, round_: int, bar: int, operational: int) -> str:
    registers = bar + operational
    usbcmd = qmp.words(registers, 1)[0]
    dcbaap = qmp.quadwords(registers + 0x30, 1)[0] & ~0x3F
    dcbaa0 = qmp.quadwords(dcbaap, 1)[0] if dcbaap else 0
    entries, terminator, aligned, distinct = 0, 0, 1, 1
    lowest = highest = 0
    if dcbaa0:
        array = qmp.quadwords(dcbaa0, ARRAY_READ)
        while entries < len(array) and array[entries]:
            entries += 1
        terminator = array[entries] if entries < len(array) else array[-1]
        used = array[:entries]
        aligned = int(all(value % 4096 == 0 for value in used))
        distinct = int(len(set(used)) == len(used))
        if used:
            lowest, highest = min(used), max(used)
    return (f"OBSERVED round={round_} usbcmd={usbcmd:08x} dcbaap={dcbaap:#x} "
            f"dcbaa0={dcbaa0:#x} entries={entries} aligned={aligned} "
            f"distinct={distinct} terminator={terminator:#x} lowest={lowest:#x} "
            f"highest={highest:#x}")


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if len(sys.argv) < 5:
        fail("usage: xhci-observe.py WORKDIR SERIAL_LOG OBSERVATIONS QEMU_COMMAND...")
    workdir, log_path, out_path, *qemu_command = sys.argv[1:]
    os.makedirs(workdir, exist_ok=True)
    qmp_path = os.path.join(workdir, "qmp.sock")
    for stale in (qmp_path, log_path, out_path):
        if os.path.exists(stale):
            os.unlink(stale)
    command = qemu_command + [
        "-qmp", f"unix:{qmp_path},server=on,wait=off",
        "-serial", f"file:{log_path}",
    ]
    deadline = time.monotonic() + TIMEOUT
    qemu = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    seen = 0
    try:
        qmp = Qmp(qmp_path, qemu, deadline)
        with open(out_path, "w") as out:
            while qemu.poll() is None:
                if time.monotonic() > deadline:
                    fail("QEMU did not exit")
                try:
                    with open(log_path, "rb") as log:
                        ready = READY.findall(log.read())
                except FileNotFoundError:
                    ready = []
                for round_, bar, operational, _ in ready[seen:]:
                    qmp.execute("stop")
                    try:
                        bar = device_bar(qmp, int(bar, 16))
                    except SelectError as error:
                        fail(f"query-pci: {error}")
                    out.write(observe(qmp, int(round_), bar, int(operational, 16)) + "\n")
                    out.flush()
                    qmp.execute("cont")
                    seen += 1
                time.sleep(0.02)
        status = qemu.wait()
    finally:
        if qemu.poll() is None:
            qemu.kill()
            qemu.wait()
    print(f"xhci-observe: {seen} observations, QEMU exited {status}")
    return status


if __name__ == "__main__":
    sys.exit(main())
