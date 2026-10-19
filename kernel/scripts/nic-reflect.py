#!/usr/bin/env python3
"""Drive the `net-probe` boot's layer-2 reflector (docs/NETWORK.md).

Usage: nic-reflect.py [--link-down|--tx-hold|--tx-hold-stuck] WORKDIR SERIAL_LOG QEMU_COMMAND...

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

With `--tx-hold` (kernel `net-probe nic-tx-hold`) or `--tx-hold-stuck`,
QEMU starts stopped and the link is set down before `cont`; the kernel's
fixture holds the descriptor the guest posts without carrier. Nothing may
reach the wire while held. Released: once the link is up the held hello
and then the next frame must arrive, in that order, and nothing else
(`kind=software`: only the next frame, QEMU having dropped the held one).
Stuck: the NIC must disable itself (`NIC DISABLED reason=tx-timeout`) and
nothing may reach the wire. After the release (or the disable) the harness
watches for stray frames for 1.5 s, ending early only when QEMU exits 3;
after that exit it also checks for a queued frame. No frame establishes
absence only over that observation window. QEMU must exit 3.

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


def probe_failure(log_path: str) -> str:
    """The guest's last `NIC PROBE FAILED at <step>` line, if any."""
    try:
        with open(log_path, "rb") as log:
            found = re.findall(rb"NIC PROBE FAILED at [^\n]*", log.read())
    except FileNotFoundError:
        return ""
    return f" ({found[-1].decode(errors='replace')})" if found else ""


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
            fail(f"QEMU exited ({qemu.returncode}) before {pattern!r}{probe_failure(log_path)}")
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
    link_down, hold = False, None
    if arguments and arguments[0] == "--link-down":
        link_down, arguments = True, arguments[1:]
    elif arguments and arguments[0] in ("--tx-hold", "--tx-hold-stuck"):
        hold, arguments = ("stuck" if arguments[0] == "--tx-hold-stuck" else "release"), arguments[1:]
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
    if link_down or hold:
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
                        fail(f"QEMU exited ({qemu.returncode}) during the exchange{probe_failure(log_path)}")
            return None

        def drain(wait: float):
            """The first frame within `wait`, or None once it elapses or the
            guest has exited with the kernel's success status (3); after a
            hold ends the guest may finish while the window is still open."""
            end = time.monotonic() + wait
            while time.monotonic() < end:
                try:
                    return sock.recv(4096)
                except socket.timeout:
                    if qemu.poll() is None:
                        continue
                    if qemu.returncode != 3:
                        fail(f"QEMU exited ({qemu.returncode}) during the post-hold stray-frame window{probe_failure(log_path)}")
                    # A frame queued just before the exit is still readable.
                    sock.setblocking(False)
                    try:
                        return sock.recv(4096)
                    except BlockingIOError:
                        return None
                    finally:
                        sock.settimeout(0.2)
            return None

        if hold:
            qmp = Qmp(qmp_path, qemu, deadline)
            qmp.set_link(False)
            qmp.execute("cont")
            armed = wait_for(log_path, rb"NIC TX HOLD FIXTURE ARMED mode=" + hold.encode() + rb" kind=(tctl|software)\n",
                             deadline, qemu)
            kind = armed.group(1).decode()
            wait_for(log_path, rb"NIC LINK DOWN AT PROBE ", deadline, qemu)
            held = wait_for(log_path, rb"NIC PROBE TX HELD held_ticks=(\d+) refused_ticks=(\d+)\n", deadline, qemu)
            early = receive(1.5)
            if early is not None:
                fail(f"a frame reached the wire while held ({early[14:24]!r})")
            qmp.set_link(True)
            if hold == "stuck":
                wait_for(log_path, rb"NIC DISABLED reason=tx-timeout\n", deadline, qemu)
                wait_for(log_path, rb"NIC PROBE TX STUCK DISABLED tx_errors=2\n", deadline, qemu)
                stray = drain(1.5)
                if stray is not None:
                    fail(f"a frame reached the wire from a stuck device ({stray[14:24]!r})")
                result = "NIC TX HOLD STUCK DISABLED OK tx_errors=2"
            else:
                expected = [b"ABSD-HELD1", b"ABSD-AFTER"] if kind == "tctl" else [b"ABSD-AFTER"]
                bodies = []
                for _ in expected:
                    frame = receive(10.0)
                    bodies.append(frame[14:24] if frame is not None else None)
                if bodies != expected:
                    fail(f"after release the wire carried {bodies}, expected {expected}")
                stray = drain(1.5)
                if stray is not None:
                    fail(f"a refused frame reached the wire ({stray[14:24]!r})")
                wait_for(log_path, rb"NIC PROBE TX RELEASED tx_frames=2 tx_errors=1\n", deadline, qemu)
                fast = "yes" if int(held.group(2)) < 50 else "no"
                result = (f"NIC TX HOLD OK held_ticks={held.group(1).decode()} refused_fast={fast} "
                          f"late_frames={len(expected) - 1} tx_errors=1")
            try:
                status = qemu.wait(timeout=max(1.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                fail("QEMU did not exit after the hold")
            if status != 3:
                fail(f"unexpected QEMU exit {status}")
            print(f"{result} kind={kind}")
            return 0
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
