#!/usr/bin/env python3
"""Drive the `xhci-probe xhci-hotplug` boot (docs/xhci-20261010/RECORD.md).

Usage: xhci-hotplug.py WORKDIR SERIAL_LOG QEMU_COMMAND...

Starts QEMU with the given command plus a QMP socket (WORKDIR/qmp.sock),
a `qemu-xhci` controller and a high-speed `usb-kbd` (id `kbd0`) on root
port 1 of its USB 2 bus. When the guest prints `XHCI AWAIT DETACH`, the
keyboard is removed with `device_del`; when it prints `XHCI AWAIT ATTACH`,
a full-speed keyboard (`usb_version=1`, id `kbd1`) is added on the same
port, so the second enumeration must report a different speed and packet
size than the first. Device removal and attachment are QEMU monitor
operations on emulated devices only.

Exits 0 only if both enumerations were reported and QEMU exited with the
kernel's success status (3). The caller checks the log's exact lines.
"""
import json
import os
import re
import socket
import subprocess
import sys
import time

TIMEOUT = 120.0


def fail(message: str) -> None:
    print(f"xhci-hotplug: {message}", file=sys.stderr)
    sys.exit(1)


def wait_for(log_path: str, pattern: bytes, deadline: float, qemu) -> None:
    while time.monotonic() < deadline:
        try:
            with open(log_path, "rb") as log:
                if re.search(pattern, log.read(), re.MULTILINE):
                    return
        except FileNotFoundError:
            pass
        if qemu.poll() is not None:
            fail(f"QEMU exited ({qemu.returncode}) before {pattern!r}")
        time.sleep(0.05)
    fail(f"timed out waiting for {pattern!r}")


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

    def execute(self, command: str, **arguments) -> None:
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
                return

    def close(self) -> None:
        self.sock.close()


def main() -> int:
    if len(sys.argv) < 4:
        fail("usage: xhci-hotplug.py WORKDIR SERIAL_LOG QEMU_COMMAND...")
    workdir, log_path, *qemu_command = sys.argv[1:]
    os.makedirs(workdir, exist_ok=True)
    qmp_path = os.path.join(workdir, "qmp.sock")
    for stale in (qmp_path, log_path):
        if os.path.exists(stale):
            os.unlink(stale)
    command = qemu_command + [
        "-qmp", f"unix:{qmp_path},server=on,wait=off",
        "-serial", f"file:{log_path}",
        "-device", "qemu-xhci,id=xhci",
        "-device", "usb-kbd,bus=xhci.0,port=1,id=kbd0",
    ]
    deadline = time.monotonic() + TIMEOUT
    qemu = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        qmp = Qmp(qmp_path, qemu, deadline)
        wait_for(log_path, rb"^XHCI AWAIT DETACH port=", deadline, qemu)
        qmp.execute("device_del", id="kbd0")
        wait_for(log_path, rb"^XHCI AWAIT ATTACH round=", deadline, qemu)
        qmp.execute("device_add", driver="usb-kbd", bus="xhci.0", port="1",
                    id="kbd1", usb_version=1)
        qmp.close()
        remaining = max(1.0, deadline - time.monotonic())
        try:
            status = qemu.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            fail("QEMU did not exit")
    finally:
        if qemu.poll() is None:
            qemu.kill()
            qemu.wait()
    if status != 3:
        fail(f"QEMU exited with {status}, not 3")
    print("xhci-hotplug: detach and attach delivered, QEMU exited 3")
    return 0


if __name__ == "__main__":
    sys.exit(main())
