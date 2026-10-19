#!/usr/bin/env python3
"""Bounded QMP USB input -> native Console cases, one guest at a time."""
import io
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
# A serial prompt can precede a complete QEMU trace record on the same line.
DELIVERY = re.compile(rb"apic_deliver_irq dest 0 dest_mode 0 delivery_mode 0 vector 208 trigger_mode 0$", re.M)
VECTOR = re.compile(rb"apic_deliver_irq [^\n]* vector 208 trigger_mode [0-9]+$", re.M)
PROGRESS = re.compile(rb"USB KEYBOARD PROGRESS tick=(\d+) events=(\d+) acknowledged=(\d+)$", re.M)
ENDPOINT = re.compile(rb"^USB KEYBOARD ENDPOINT slot=(\d+) port=(\d+) dci=(\d+) packet=(\d+) interval=(\d+) ring=0x([0-9a-f]+) context=0x([0-9a-f]+) report=0x([0-9a-f]+)$", re.M)
# The shell prompt has no terminating newline while it waits for input.
IDLE = rb"^(?:> )?USB KEYBOARD IDLE ticks=(\d+) outstanding=1 acknowledged=(\d+)$"
CONSOLE_BLOCKED = rb"^SHELL CONSOLE BLOCKED$"
# Only these complete observation records may interrupt the fixed fixture's
# shell writes. The ordinary diagnostic view and its checks retain them.
SHELL_DIAGNOSTIC = re.compile(
    rb"USB KEYBOARD (?:PROGRESS tick=\d+ events=\d+ acknowledged=\d+|"
    rb"ENQUEUED bytes=\d+ total=\d+ dropped=\d+|"
    rb"IDLE ticks=\d+ outstanding=1 acknowledged=\d+)\n")
TRACES = ["apic_deliver_irq", "usb_xhci_xfer_start", "usb_xhci_xfer_success",
          "usb_xhci_xfer_nak", "usb_xhci_oper_write", "usb_xhci_runtime_write",
          "usb_xhci_port_write", "usb_xhci_doorbell_write", "msix_write_config"]
TRACE_RECORD = re.compile(rb"(?:" + b"|".join(name.encode() for name in TRACES) + rb") [^\n]*\n")
CASES = ["keyboard", "nec", "held", "modifiers", "idle", "mixed", "absent",
         "unsupported", "no-msix", "masked", "unplug", "replug", "flood",
         "bootstick", "large-descriptor", "console-test", "combo-probe", "combo-ap",
         "combo-controller", "combo-user", "combo-test", "combo-recovery"]


def require(value, message):
    if not value:
        raise RuntimeError(message)


def console_bytes(data):
    # In this controlled QEMU fixture, complete configured trace records can
    # interrupt UART text between any two bytes. Their LF is not a UART LF.
    # The fixed guest programs/inputs do not print these trace record names.
    return TRACE_RECORD.sub(b"", data)


def shell_bytes(data):
    # Fixture programs never print these diagnostic names. Removing their
    # complete records reconstructs the user writes without changing case,
    # control bytes or malformed/unrecognized records.
    return SHELL_DIAGNOSTIC.sub(b"", console_bytes(data))


def raw_position(data, serial_position):
    skipped = 0
    for record in TRACE_RECORD.finditer(data):
        if record.start() - skipped > serial_position:
            break
        skipped += record.end() - record.start()
    return serial_position + skipped


def kernel_descriptor_reads(records):
    # The final device reset precedes the native xHCI enumeration. Firmware
    # may have fetched the complete configuration before that reset. Require
    # the native repeated device-descriptor reads to identify this segment.
    reset = max(n for n, record in enumerate(records) if record.get("reset"))
    native = records[reset + 1:]
    require(sum(r.get("descriptor") == 1 and r.get("requested") == 18 for r in native) >= 2,
            "native descriptor rereads missing after reset")
    return native


def normal_reports(data):
    active = {}
    reports = 0
    for line in data.splitlines():
        start = re.search(rb"usb_xhci_xfer_start (\S+): slotid (\d+), epid (\d+), streamid (\d+)$", line)
        success = re.search(rb"usb_xhci_xfer_success (\S+): len (\d+)$", line)
        if start:
            active[start[1]] = tuple(map(int, start.groups()[1:]))
        if success:
            identity = active.pop(success[1], None)
            reports += int(identity == (1, 3, 0) and success[2] == b"8")
    return reports


def check(data, keyboard=True, masked=False):
    serial = console_bytes(data)
    for marker in [b"SHELL SESSION OK\n", b"ABSD BOOT OK\n"]:
        require(marker in serial, f"missing {marker!r}")
    require(not re.search(rb"PANIC|KERNEL FAULT|USB KEYBOARD FAILED|QUARANTINED|SHELL SESSION FAILED", serial), "guest fault or failed driver")
    require(len(VECTOR.findall(data)) == len(DELIVERY.findall(data)), "unexpected USB-vector destination or delivery mode")
    progress = [tuple(map(int, m.groups())) for m in PROGRESS.finditer(serial)]
    require(all(0 < events <= 8 for _, events, _ in progress), "event budget exceeded")
    require(len({tick for tick, _, _ in progress}) == len(progress), "multiple device progress passes in one PIT tick")
    require(all(a[2] < b[2] for a, b in zip(progress, progress[1:])), "event acknowledgement did not advance")
    if keyboard:
        require(b"USB KEYBOARD READY\n" in serial, "keyboard not initialized")
        require(DELIVERY.search(data), "no USB message to the BSP")
        require(normal_reports(data) > 0, "no actual eight-byte normal-IN completion")
        enqueues = len(re.findall(rb"USB KEYBOARD ENQUEUED ", serial))
        require(normal_reports(data) >= enqueues, "enqueue receipts exceed actual report completions")
    if masked:
        require(not VECTOR.search(data), "masked vector delivered")
        require(b"Interrupt(CompletedWithoutInterrupt)" in serial, "wrong masked-route refusal")
    stop = [b"USB KEYBOARD STATE Halting\n", b"USB KEYBOARD HALTED DMA_OFF bus_master=0\n",
            b"USB KEYBOARD STATE Draining\n", b"USB KEYBOARD STATE Clean\n", b"USB KEYBOARD QUIET "]
    fenced = b"USB KEYBOARD STATE Fenced\n"
    if fenced in serial or any(marker in serial for marker in stop):
        for marker in stop:
            require(marker in serial, f"stop incomplete: {marker!r}")
        # Initialization can start already fenced after refusing a device.
        order = [serial.index(marker) for marker in ([fenced] if fenced in serial else []) + stop]
        require(order == sorted(order), "wrong stop order")
        quiet = serial.index(b"USB KEYBOARD QUIET ")
        after = data[raw_position(data, quiet):]
        require(not VECTOR.search(after), "USB message after quiet")
        require(not re.search(rb"usb_xhci_(oper_write|runtime_write|port_write|doorbell_write)\b|msix_write_config ", after), "device writes after quiet")
        require(b"USB KEYBOARD ENQUEUED " not in serial[quiet:], "input published after stop")
    elif keyboard:
        require(False, "keyboard never stopped")


class Guest:
    def __init__(self, name, qemu, work, serial=False, variant=None, keyboard=True):
        self.name = name
        self.path = work / (name + ".log")
        self.path.write_bytes(b"")
        self.output = self.path.open("ab")
        self.scratch = tempfile.TemporaryDirectory(prefix="absd-usb2-")
        self.qmp_path = Path(self.scratch.name) / "qmp"
        self.serial = None
        self.qmp = None
        self.fixture = None
        self.deadline = time.monotonic() + 90
        variant = variant or (name if name in {"masked", "console-test"} or name.startswith("combo-") else "base")
        args = qemu + ["-accel", "tcg", "-m", "128M", "-display", "none", "-nic", "none", "-no-reboot", "-no-shutdown",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-cdrom", str(ROOT / f"build/absd-usb-keyboard-{variant}.iso"),
            "-qmp", f"unix:{self.qmp_path},server=on,wait=off"]
        # One inherited append descriptor preserves emitted UART/trace byte order.
        # A file sink keeps draining output while the host waits for guest exit.
        args += ["-serial", "stdio"]
        for trace in TRACES:
            args += ["-trace", trace]
        if name not in {"absent", "combo-probe", "combo-ap"}:
            device = "nec-usb-xhci" if name in {"nec", "no-msix"} else "qemu-xhci"
            extra = ",msix=off" if name == "no-msix" else ",p2=12,p3=4" if name == "flood" else ",p2=8,p3=4" if name == "bootstick" else ""
            args += ["-device", device + ",id=xhci" + extra]
            if name == "unsupported":
                args += ["-device", "usb-mouse,id=mouse,bus=xhci.0,port=1"]
            elif keyboard:
                port = 6 if name == "bootstick" else 2 if name == "large-descriptor" else 1
                args += ["-device", f"usb-kbd,id=kbd,bus=xhci.0,port={port}"]
            if name == "large-descriptor":
                fixture = runpy.run_path(str(ROOT / "scripts/usb-large-descriptor.py"))
                path = Path(self.scratch.name) / "usb"
                self.fixture = fixture["LargeDescriptor"](path, work / "large-descriptor-device.json")
                args += ["-S", "-chardev", f"socket,id=usbfixture,path={path}",
                         "-device", "usb-redir,id=large,bus=xhci.0,port=1,chardev=usbfixture"]
            if name == "bootstick":
                self.disk = work / "read-only-stick.img"
                self.disk.write_bytes(b"USB unsupported-class fixture\n".ljust(65536, b"\0"))
                args += ["-drive", f"if=none,id=stick,file={self.disk},format=raw,readonly=on",
                         "-device", "usb-storage,id=stick-device,bus=xhci.0,port=5,drive=stick"]
        self.process = subprocess.Popen(args, cwd=ROOT, stdin=subprocess.PIPE if serial else subprocess.DEVNULL, stdout=self.output, stderr=subprocess.STDOUT)
        self.serial = self.process.stdin
        try:
            helpers = runpy.run_path(str(ROOT / "scripts/xhci-observe.py"))
            self.qmp = helpers["Qmp"](str(self.qmp_path), self.process, self.deadline)
            self.qmp.sock.settimeout(5)
            if self.fixture:
                self.qmp.execute("cont")
                require(self.fixture.connected.wait(timeout=5), "descriptor fixture did not connect")
        except BaseException:
            self.close()
            raise

    def data(self):
        return self.path.read_bytes()

    def console(self):
        return console_bytes(self.data())

    def wait(self, pattern, start=0, *, shell=False):
        normalize = shell_bytes if shell else console_bytes
        while time.monotonic() < self.deadline:
            data = self.data()
            match = re.search(pattern, normalize(data[start:]), re.M)
            if match:
                return match
            require(self.process.poll() is None, f"guest exited before {pattern!r}")
            time.sleep(.005)
        raise RuntimeError(f"deadline waiting for {pattern!r}")

    def key(self, code, down=True, wait=True):
        before = len(self.data())
        self.qmp.execute("input-send-event", events=[{"type": "key", "data": {"down": down, "key": {"type": "qcode", "data": code}}}])
        if wait:
            self.wait(rb"USB KEYBOARD PROGRESS ", before)

    def tap(self, code):
        self.key(code)
        self.key(code, False)

    def type(self, text, final=False):
        names = {"\n": "ret", " ": "spc", "-": "minus"}
        for n, char in enumerate(text):
            code = names.get(char, char)
            self.key(code)
            if not (final and n == len(text) - 1):
                self.key(code, False)

    def write_serial(self, text):
        require(self.serial is not None, "case has read-only serial capture")
        self.wait(CONSOLE_BLOCKED)
        self.serial.write(text.encode())
        self.serial.flush()

    def endpoint(self, work):
        self.wait(rb"^USB KEYBOARD READY$")
        match = ENDPOINT.search(self.console())
        require(match, "missing endpoint identity")
        self.qmp.execute("stop")
        context = self.qmp.words(int(match[7], 16), 5)
        self.qmp.execute("cont")
        require(tuple(map(int, match.groups()[2:5])) == (3, 8, 6), "unexpected boot-keyboard endpoint")
        require(context[0] & 7 == 1 and (context[0] >> 16) & 255 == 6, "endpoint not Running with required interval")
        require((context[1] >> 3) & 7 == 7 and context[1] >> 16 == 8, "not an eight-byte interrupt-IN endpoint")
        dequeue = ((context[3] << 32) | context[2]) & ~15
        ring = int(match[6], 16)
        require(ring <= dequeue < ring + 7 * 16, "dequeue outside owned normal-IN ring")
        require(context[4] == (8 << 16) | 8, "endpoint service/TRB lengths wrong")
        (work / (self.name + "-endpoint.json")).write_text(json.dumps({"guest_fields": [x.decode() for x in match.groups()], "context": context}, indent=2) + "\n")

    def finish(self):
        status = self.process.wait(timeout=max(1, self.deadline - time.monotonic()))
        require(status == 3, f"QEMU exit {status}, expected 3")
        return self.data()

    def close(self):
        if self.process.poll() is None:
            self.process.kill()  # Exact owned child, never a process pattern.
            self.process.wait()
        if self.fixture is not None:
            self.fixture.close()
        if self.qmp is not None:
            self.qmp.lines.close()
            self.qmp.sock.close()
        if self.serial is not None:
            self.serial.close()
        self.output.close()
        self.scratch.cleanup()


def run_case(name, qemu, work):
    writable = name in {"mixed", "absent", "unsupported", "no-msix", "masked", "unplug", "replug"}
    g = Guest(name, qemu, work, serial=writable)
    try:
        if name.startswith("combo-"):
            status = g.process.wait(timeout=60)
            data = g.data()
            reason = b"test-requires-shell-keyboard" if name == "combo-test" else b"recovery-requires-keyboard" if name == "combo-recovery" else b"combination=ap-or-probe"
            require(status == 7 and b"USB KEYBOARD REFUSED " + reason + b"\n" in console_bytes(data), "combination not refused")
            require(b"XHCI CLAIMED" not in console_bytes(data) and not VECTOR.search(data), "refused boot touched controller")
            return
        keyboard = name not in {"absent", "unsupported", "no-msix", "masked"}
        if keyboard:
            g.endpoint(work)
        if name == "console-test":
            g.wait(rb"^USB CONSOLE READY$")
            g.type("a")
            g.wait(rb"^USB CONSOLE QUEUE READY$")
            g.type("b")
            g.wait(rb"USB KEYBOARD ENQUEUED bytes=1 total=2 dropped=0$")
            g.wait(rb"^USB CONSOLE RIGHTS OK$")
            g.wait(rb"^USB CONSOLE RACE ARMED$")
            g.key("c", wait=False)
            held = g.wait(rb"^USB KEYBOARD TEST RACE HELD deadline=(\d+)$")
            g.key("c", False, wait=False)
            released = g.wait(rb"^USB KEYBOARD TEST RACE RELEASED tick=(\d+)$")
            require(int(released[1]) >= int(held[1]), "fixture released before timed wait expired")
            g.wait(rb"^USB CONSOLE RACE OK$")
        else:
            g.wait(rb"^> ")
            if name in {"keyboard", "nec", "bootstick", "large-descriptor"}:
                g.type("hello-b\n")
                g.wait(rb"shell: hello-b exited 0", shell=True)
                if name == "bootstick":
                    require(b"USB KEYBOARD UNSUPPORTED port=9\n" in g.console(), "lower-port USB2 storage not examined/refused")
                if name == "large-descriptor":
                    serial = g.console()
                    require(serial.index(b"USB KEYBOARD UNSUPPORTED port=5\n") < serial.index(b"USB KEYBOARD ENDPOINT slot=1 port=6 "), "large lower-port device hid the keyboard")
                    native = kernel_descriptor_reads(g.fixture.records)
                    require(any(r.get("descriptor") == 2 and r["requested"] == 9 and r["config_total"] > 1024
                                for r in native), "no real large configuration header read")
                    require(not any(r.get("descriptor") == 2 and r["requested"] > 9
                                    for r in native), "oversized configuration fetched by native driver")
                    require(g.fixture.error is None, f"descriptor fixture failed: {g.fixture.error}")
                g.type("quit\n", final=True)
            elif name == "held":
                g.key("q")
                g.tap("shift")  # Modifier-only reports must not repeat held q.
                g.key("q", False)
                g.type("uit\n", final=True)
            elif name == "modifiers":
                g.key("shift"); g.tap("a"); g.key("shift", False); g.tap("ret")
                g.wait(rb"shell: unknown program A\n", shell=True)
                before = len(g.data()); g.tap("caps_lock"); g.type("a\n")
                g.wait(rb"shell: unknown program A\n", before, shell=True)
                g.tap("caps_lock")
                g.key("ctrl"); g.tap("c"); g.key("ctrl", False); g.tap("ret")
                g.wait(rb"shell: unknown program \x03\n", shell=True)
                g.type("quit\n", final=True)
            elif name == "idle":
                idle = g.wait(IDLE)
                require(int(idle[1]) > 200, "insufficient no-key interval")
                g.type("quit\n", final=True)
            elif name == "mixed":
                g.type("h")
                g.wait(rb"USB KEYBOARD ENQUEUED bytes=1 total=1 dropped=0$")
                g.write_serial("ello-b\n")
                g.wait(rb"shell: hello-b exited 0", shell=True)
                g.type("q")
                g.wait(rb"USB KEYBOARD ENQUEUED bytes=1 total=2 dropped=0$")
                g.write_serial("uit\n")
            elif name in {"unplug", "replug"}:
                g.wait(IDLE)
                g.qmp.execute("device_del", id="kbd")
                g.wait(rb"^USB KEYBOARD QUIET ")
                require(b"USB KEYBOARD FENCED reason=disconnected\n" in g.console(), "disconnect did not fence")
                if name == "replug":
                    before = len(g.data())
                    g.qmp.execute("device_add", driver="usb-kbd", id="kbd2", bus="xhci.0", port="1")
                    g.key("q", wait=False)
                    time.sleep(.1)
                    require(b"USB KEYBOARD ENQUEUED" not in console_bytes(g.data()[before:]), "terminal driver rebound implicitly")
                g.write_serial("quit\n")
            elif name == "flood":
                idle = g.wait(IDLE)
                for action in ["add", "del"]:
                    prior = PROGRESS.findall(g.console())
                    baseline = int(prior[-1][2]) if prior else int(idle[2])
                    before = len(g.data())
                    g.qmp.execute("stop")
                    for port in range(2, 13):
                        if action == "add":
                            g.qmp.execute("device_add", driver="usb-mouse", id=f"mouse{port}", bus="xhci.0", port=str(port))
                        else:
                            g.qmp.execute("device_del", id=f"mouse{port}")
                    g.qmp.execute("cont")
                    g.wait(rb"USB KEYBOARD PROGRESS tick=\d+ events=8 acknowledged=\d+$", before)
                    while True:
                        progress = PROGRESS.findall(console_bytes(g.data()[before:]))
                        if sum(int(x[1]) for x in progress) >= 11:
                            break
                        require(time.monotonic() < g.deadline and g.process.poll() is None, "port flood not acknowledged")
                        time.sleep(.005)
                    require(int(progress[-1][2]) >= baseline + 11, "flood acknowledgement counter did not advance")
                g.type("quit\n", final=True)
            else:
                if name in {"unsupported", "masked"}:
                    g.wait(rb"^USB KEYBOARD QUIET ")
                g.write_serial("quit\n")
        data = g.finish()
        check(data, keyboard=keyboard, masked=name == "masked")
        serial = console_bytes(data)
        if not keyboard:
            require(b"USB KEYBOARD READY" not in serial, "refused device became keyboard")
        if name == "absent":
            require(b"USB KEYBOARD REFUSED Absent\n" in serial, "wrong absent-controller refusal")
        if name == "no-msix":
            require(b"USB KEYBOARD REFUSED Interrupt(MissingMsix)\n" in serial, "wrong missing-route refusal")
        if name == "unsupported":
            require(b"USB KEYBOARD UNSUPPORTED port=" in serial and b"INITIALIZATION FAILED" not in serial,
                    "unsupported class was not cleanly examined/refused")
        if name in {"absent", "no-msix"}:
            require(not VECTOR.search(data), "pre-arm refusal received USB delivery")
        if name == "bootstick":
            require(g.disk.read_bytes() == b"USB unsupported-class fixture\n".ljust(65536, b"\0"), "read-only storage fixture changed")
    finally:
        g.close()


def self_test():
    class CapturedGuest:
        def __init__(self, data):
            self.observation = data
            self.deadline = time.monotonic() + 1
            self.process = self

        def data(self):
            return self.observation

        def poll(self):
            return 0

    # Reproduce the actual CapsLock capture: the correct A is followed by a
    # native progress record before the shell's own newline. Native checks
    # must still see that record, and wrong user bytes must remain wrong.
    diagnostic = b"USB KEYBOARD PROGRESS tick=89 events=1 acknowledged=30\n"
    interleaved = b"shell: unknown program A" + diagnostic + b"\n"
    Guest.wait(CapturedGuest(interleaved), rb"shell: unknown program A\n", shell=True)
    Guest.wait(CapturedGuest(interleaved), PROGRESS.pattern)
    for bad in [interleaved.replace(b"program A", b"program a"),
                interleaved.replace(b"events=1", b"events=bad")]:
        try:
            Guest.wait(CapturedGuest(bad), rb"shell: unknown program A\n", shell=True)
        except RuntimeError:
            continue
        raise RuntimeError("shell reconstruction accepted wrong bytes or a malformed diagnostic")
    class SerialFixture:
        def __init__(self, observation):
            self.serial = io.BytesIO()
            self.observation = observation

        def wait(self, pattern):
            require(re.search(pattern, self.observation, re.M), "fixture read has not blocked")

    # The old prompt-only handshake writes before the blocked-read condition.
    # Exercise the real injection method, with an observation that cannot yet
    # satisfy that condition. No input may escape while wait is unsatisfied.
    early = SerialFixture(b"> ")
    try:
        Guest.write_serial(early, "quit\n")
    except RuntimeError as error:
        require(str(error) == "fixture read has not blocked", "wrong readiness refusal")
    else:
        raise RuntimeError("serial input admitted at prompt before the read blocked")
    require(early.serial.getvalue() == b"", "input escaped before blocked-read observation")
    ready = SerialFixture(b"> \nSHELL CONSOLE BLOCKED\n")
    Guest.write_serial(ready, "quit\n")
    require(ready.serial.getvalue() == b"quit\n", "blocked reader did not admit exact input")
    for prefix in [b"", b"> "]:
        require(re.search(IDLE, prefix + b"USB KEYBOARD IDLE ticks=250 outstanding=1 acknowledged=18\n", re.M), "idle receipt after prompt not recognized")
    good = (b"USB KEYBOARD READY\n"
            b"usb_xhci_xfer_start 0x123: slotid 1, epid 3, streamid 0\n"
            b"usb_xhci_xfer_success 0x123: len 8\n"
            b"apic_deliver_irq dest 0 dest_mode 0 delivery_mode 0 vector 208 trigger_mode 0\n"
            b"USB KEYBOARD PROGRESS tick=1 events=1 acknowledged=20\n"
            b"USB KEYBOARD STATE Fenced\nUSB KEYBOARD STATE Halting\n"
            b"USB KEYBOARD HALTED DMA_OFF bus_master=0\nUSB KEYBOARD STATE Draining\n"
            b"USB KEYBOARD STATE Clean\nUSB KEYBOARD QUIET late=0 max_events=1 reports=1\n"
            b"SHELL SESSION OK\nABSD BOOT OK\n")
    check(good)
    prefixed = good
    for marker in [b"apic_deliver_irq", b"usb_xhci_xfer_start", b"usb_xhci_xfer_success"]:
        prefixed = prefixed.replace(marker, b"> " + marker)
    check(prefixed)
    irq = b"apic_deliver_irq dest 0 dest_mode 0 delivery_mode 0 vector 208 trigger_mode 0\n"
    interleaved = good.replace(b"USB KEYBOARD READY", b"USB KEY" + irq + b"BOARD READY")
    check(interleaved)
    queue = b"USB CONSOLusb_xhci_xfer_success 0x123: len 8\nE QUEUE READY\n"
    require(console_bytes(queue) == b"USB CONSOLE QUEUE READY\n", "trace interrupted native receipt")
    initial_stop = b"USB KEYBOARD UNAVAILABLE serial_fallback=1\n" + good[good.index(b"USB KEYBOARD STATE Halting"):]
    check(initial_stop, keyboard=False)
    bad = [good.replace(b"dest 0 dest_mode", b"dest 1 dest_mode"),
           good.replace(b"epid 3", b"epid 1"), good.replace(b"len 8", b"len 7"),
           good.replace(b"events=1 acknowledged", b"events=9 acknowledged"),
           good.replace(b"USB KEYBOARD HALTED DMA_OFF bus_master=0\n", b""),
           good + b"apic_deliver_irq dest 0 dest_mode 0 delivery_mode 0 vector 208 trigger_mode 0\n",
           good + b"usb_xhci_doorbell_write off 0x0004, val 0x00000003\n",
           b"apic_deliver_irq dest 1 dest_mode 0 delivery_mode 0 vector 208 trigger_mode 0\n" + good,
           good.replace(b"SHELL SESSION OK\n", b"SHELL SESSION FAILED\n"),
           b"> apic_deliver_irq dest 1 dest_mode 0 delivery_mode 0 vector 208 trigger_mode 0\n" + good,
           good + b"> apic_deliver_irq dest 0 dest_mode 0 delivery_mode 0 vector 208 trigger_mode 0\n",
           good + b"> usb_xhci_doorbell_write off 0x0004, val 0x00000003\n",
           good.replace(b"USB KEYBOARD QUIET ", b"USB KEYBOARD QUIusb_xhci_doorbell_write off 0x0004, val 0x00000003\nET ")]
    for data in bad:
        try:
            check(data)
        except RuntimeError:
            continue
        raise RuntimeError("keyboard oracle accepted a deterministic negative control")
    for marker in [b"USB KEYBOARD HALTED DMA_OFF bus_master=0\n", b"USB KEYBOARD STATE Draining\n"]:
        try:
            check(initial_stop.replace(marker, b""), keyboard=False)
        except RuntimeError:
            continue
        raise RuntimeError("keyboard oracle accepted an incomplete initial stop")
    print(f"usb-keyboard-test: oracle passed 4 positive and {len(bad) + 2} negative controls")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test(); return
    qemu = shlex.split(sys.argv[1] if len(sys.argv) > 1 else "qemu-system-x86_64")
    parent = ROOT / "build/usb-keyboard"; parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="run-", dir=parent))
    selected = os.environ.get("USB_KEYBOARD_CASES", "").split() or CASES
    require(not set(selected) - set(CASES), "unknown case selection")
    results = []
    name = "setup"
    try:
        for name in selected:
            start = time.monotonic()
            run_case(name, qemu, work)
            results.append({"case": name, "result": "PASS", "seconds": round(time.monotonic() - start, 3)})
            print(f"usb-keyboard-test: {name}: PASS", flush=True)
    except BaseException as error:
        results.append({"case": name, "result": "FAIL", "reason": str(error)})
        raise
    finally:
        (work / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        print(f"usb-keyboard-test: logs {work}", flush=True)
    print(f"usb-keyboard-test: {len(results)} cases passed")


if __name__ == "__main__":
    main()
