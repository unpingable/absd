#!/usr/bin/env python3
"""Drive the `net-probe` boot's layer-2 reflector (docs/NETWORK.md).

Usage: nic-reflect.py [--link-down] WORKDIR SERIAL_LOG QEMU_COMMAND...

Binds the host end of a QEMU `-netdev dgram` pair of unix datagram
sockets (WORKDIR/host.sock; QEMU binds WORKDIR/guest.sock), starts QEMU
with the given command plus the e1000 and netdev options, and waits for
the guest's `NIC PROBE READY` line. Then, with frames of the local
experimental EtherType 0x88b5:

- the guest's broadcast hello must come from the MAC it printed;
- `E` frames of 15..1514 bytes must come back byte for byte with the
  addresses swapped (QEMU pads a received frame shorter than 60 bytes with
  zeros, and the reflection carries that padding);
- a burst of 24 frames sent back to back must all come back, in order;
- frames of 1515, 1516, and 1518 bytes, which QEMU's e1000 accepts but the
  ABI does not carry, must get no reflection;
- `Q` ends the probe.

With `--link-down`, QEMU starts stopped and the link is set down over QMP
before `cont`, so the kernel probes a NIC with no carrier: the guest must
print `NIC LINK DOWN AT PROBE` and `NIC PROBE LINK DOWN`, nothing may reach
the wire (the probe sends one hello with the link down), and once the
harness raises the link the guest must print `NIC PROBE LINK UP` and run
the whole reflection as above.

Prints `NIC REFLECT OK ...` and exits 0 only if every check held and QEMU
exited with the kernel's success status (3).
"""
import json
import os
import random
import re
import socket
import subprocess
import sys
import time

ETHERTYPE = b"\x88\xb5"
HOST_MAC = bytes.fromhex("020000000001")
TIMEOUT = 120.0


def fail(message: str) -> None:
    print(f"nic-reflect: {message}", file=sys.stderr)
    sys.exit(1)


def wait_for(log_path: str, pattern: bytes, deadline: float, qemu) -> re.Match:
    while time.monotonic() < deadline:
        try:
            with open(log_path, "rb") as log:
                found = re.search(pattern, log.read())
            if found:
                return found
        except FileNotFoundError:
            pass
        if qemu.poll() is not None:
            fail(f"QEMU exited ({qemu.returncode}) before {pattern!r}")
        time.sleep(0.05)
    fail(f"timed out waiting for {pattern!r}")


class Qmp:
    """One QMP connection, enough for `set_link` and `cont`."""

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

    def set_link(self, up: bool) -> None:
        self.execute("set_link", name="n0", up=up)

    def close(self) -> None:
        self.sock.close()


def main() -> int:
    arguments = sys.argv[1:]
    link_down = False
    if arguments and arguments[0] == "--link-down":
        link_down = True
        arguments = arguments[1:]
    workdir, log_path, *qemu_command = arguments
    os.makedirs(workdir, exist_ok=True)
    host_path = os.path.join(workdir, "host.sock")
    guest_path = os.path.join(workdir, "guest.sock")
    qmp_path = os.path.join(workdir, "qmp.sock")
    for path in (host_path, guest_path, qmp_path, log_path):
        if os.path.exists(path):
            os.unlink(path)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(host_path)
    sock.settimeout(0.2)
    command = qemu_command + [
        "-serial", f"file:{log_path}",
        "-device", "e1000,netdev=n0",
        "-netdev", f"dgram,id=n0,local.type=unix,local.path={guest_path},"
        f"remote.type=unix,remote.path={host_path}",
    ]
    if link_down:
        command += ["-S", "-qmp", f"unix:{qmp_path},server,nowait"]
    qemu = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + TIMEOUT
    qmp = None
    try:
        def receive(wait: float):
            end = time.monotonic() + wait
            while time.monotonic() < end:
                try:
                    return sock.recv(4096)
                except socket.timeout:
                    if qemu.poll() is not None:
                        fail(f"QEMU exited ({qemu.returncode}) during the exchange")
            return None

        if link_down:
            qmp = Qmp(qmp_path, qemu, deadline)
            qmp.set_link(False)
            qmp.execute("cont")
            wait_for(log_path, rb"NIC LINK DOWN AT PROBE ", deadline, qemu)
            down = wait_for(log_path, rb"NIC PROBE LINK DOWN mac=([0-9a-f:]{17})\n", deadline, qemu)
            # The guest sent one hello with the link down; QEMU completed
            # the descriptor and dropped the frame.
            early = receive(1.5)
            if early is not None:
                fail(f"a frame reached the wire with the link down ({len(early)} bytes)")
            qmp.set_link(True)
            wait_for(log_path, rb"NIC PROBE LINK UP\n", deadline, qemu)
        ready = wait_for(log_path, rb"NIC PROBE READY mac=([0-9a-f:]{17})\n", deadline, qemu)
        guest_mac = bytes.fromhex(ready.group(1).decode().replace(":", ""))
        if link_down and down.group(1) != ready.group(1):
            fail("the MAC changed between link down and link up")

        hello = receive(10.0)
        if hello is None:
            fail("no hello frame")
        if hello[:6] != b"\xff" * 6 or hello[6:12] != guest_mac or hello[12:14] != ETHERTYPE:
            fail(f"hello frame header {hello[:14].hex()}")
        if hello[14:24] != b"ABSD-HELLO" or len(hello) != 60 or any(hello[24:]):
            fail(f"hello frame body {hello.hex()}")

        def send(frame: bytes) -> None:
            sock.sendto(frame, guest_path)

        def echo_frame(length: int, rng: random.Random) -> bytes:
            header = guest_mac + HOST_MAC + ETHERTYPE + b"E"
            return header + bytes(rng.getrandbits(8) for _ in range(length - len(header)))

        def expect_reflection(sent: bytes) -> None:
            got = receive(5.0)
            if got is None:
                fail(f"no reflection of a {len(sent)}-byte frame")
            wire = sent + b"\0" * max(0, 60 - len(sent))
            expected = HOST_MAC + guest_mac + wire[12:]
            if got != expected:
                fail(f"reflection of {len(sent)} bytes differs: {got[:32].hex()}...")

        rng = random.Random(0xAB5D)
        sizes = [15, 42, 59, 60, 61, 64, 100, 511, 512, 1000, 1499, 1513, 1514]
        for size in sizes:
            frame = echo_frame(size, rng)
            send(frame)
            expect_reflection(frame)
        burst = [echo_frame(rng.randrange(15, 1515), rng) for _ in range(24)]
        for frame in burst:
            send(frame)
        for frame in burst:
            expect_reflection(frame)
        for size in (1515, 1516, 1518):
            send(echo_frame(size, rng))
        stray = receive(1.5)
        if stray is not None:
            fail(f"an oversize frame was answered ({len(stray)} bytes)")
        # The link still works after the refusals.
        frame = echo_frame(77, rng)
        send(frame)
        expect_reflection(frame)
        send(guest_mac + HOST_MAC + ETHERTYPE + b"Q" + b"\0" * 45)
        try:
            status = qemu.wait(timeout=max(1.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            fail("QEMU did not exit after the quit frame")
        if status != 3:
            fail(f"unexpected QEMU exit {status}")
        echoed = len(sizes) + len(burst) + 1
        link = " link=down-then-up" if link_down else ""
        print(f"NIC REFLECT OK frames={echoed} oversize_unanswered=3 mac={ready.group(1).decode()}{link}")
        return 0
    finally:
        if qemu.poll() is None:
            qemu.kill()
            qemu.wait()
        if qmp is not None:
            qmp.close()
        sock.close()
        for path in (host_path, guest_path, qmp_path):
            if os.path.exists(path):
                os.unlink(path)


if __name__ == "__main__":
    sys.exit(main())
