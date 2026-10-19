#!/usr/bin/env python3
"""Network matrix for `netd-probe` (absd-net over the kernel NIC).

Usage: net-matrix.py KERNEL_CHECKOUT NETD_ELF WORKDIR [--only frames,linkdown,deadnic,tcp]

Builds a `durable=N net` ISO per step from KERNEL_CHECKOUT with NETD_ELF as
the durable worker, boots it under QEMU with an e1000, and plays the peer:

frames (step 1, `-netdev dgram` on unix sockets; this script is the only
other host on the wire, speaking raw Ethernet):
  ARP OK         the guest answers who-has 10.0.2.15 with its MAC, and
                 nothing for another address;
  IPV4 OK        well-formed IPv4 to 10.0.2.15 is answered with a correct
                 IPv4 header; ten malformed or misaddressed packets get no
                 answer while the guest's frame counter rises by exactly
                 their number;
  ICMP ECHO OK   echo requests of 0..1472 payload bytes come back as byte-
                 exact echo replies with valid IPv4 and ICMP checksums.

linkdown (step 1 again, QEMU started stopped and the link set down over
QMP before `cont`, so the kernel grants a NIC with no carrier):
  LINK DOWN OK   the stack opens and the worker reports ready with
                 `link=down`; the wire is silent (QEMU drops frames both
                 ways with the link down, so this checks the wire, not the
                 guest); once the harness raises the link the worker
                 reports `NETD LINK UP` without re-opening anything, the
                 whole frames phase above then passes on the same boot,
                 and its final frame counters equal the healthy boot's
                 (nothing leaked in or out while the link was down).

deadnic (step 3, `-netdev user`, the kernel's `nic-ring-fault` injection):
  DEAD NIC OK    the stack opens, the first poll finds the device disabled
                 (`NIC DISABLED reason=rx-head-outside-ring head=35`), and
                 two seconds of poll/wait make one pass per 5..=20 ms (the
                 idle cadence: neither a spin nor a stall), every pass
                 counted in link_errors with last_error -5 and the stack
                 reporting `disabled()`.

tcp (step 2, `-netdev user` with host forwards to guest ports 7000/7001;
the clients are ordinary Python sockets on 127.0.0.1):
  TCP LISTEN OK     a forwarded, listened port echoes; an unlistened one
                    is closed without data;
  TCP STREAM OK     2 MiB both ways with random write and read sizes (one
                    send is not one receive), the peer's FIN, a 1 MiB
                    server-sent stream closed by the server, a client that
                    stops reading (backpressure: the in-flight amount stops
                    growing, then everything arrives intact), and a reset;
  TCP RECONNECT OK  200 sequential connections; afterwards no connection
                    socket is left and the heap stopped growing after the
                    first 20.

Each boot must end with init's zero accounting line (`DURABLE status=0
frames=0 processes=0 cells=0 pipes=0`) and `DURABLE WORKLOAD OK`.
"""
import hashlib
import json
import os
import pathlib
import random
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from served_kernel import kernel_make
from served_ram import served_qemu
from e1000_rx import wait_rx_setup

QEMU = os.environ.get("ABSD_QEMU", "qemu-system-x86_64")
QEMU_CPU = ["-cpu", "max,vendor=GenuineIntel,+rdrand"]
BOOT_TIMEOUT = 300.0
CONTROL = 0x88B5
HOST_MAC = bytes.fromhex("525500000202")
HOST_IP = bytes([10, 0, 2, 2])
GUEST_IP = bytes([10, 0, 2, 15])
CHUNK = re.compile(rb"EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]*)\n")


def fail(message):
    print(f"net-matrix: {message}", file=sys.stderr)
    sys.exit(1)


def stdout_of(log_path):
    """The worker's stdout, decoded from init's hex frames so far."""
    try:
        raw = open(log_path, "rb").read()
    except FileNotFoundError:
        return b""
    data = bytearray()
    for match in CHUNK.finditer(raw):
        if int(match.group(1), 16) == len(data):
            data.extend(bytes.fromhex(match.group(2).decode()))
    return bytes(data)


def wait_output(log_path, pattern, qemu, timeout=BOOT_TIMEOUT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = re.search(pattern, stdout_of(log_path))
        if found:
            return found
        if qemu.poll() is not None:
            fail(f"QEMU exited ({qemu.returncode}) before {pattern!r}; log {log_path}")
        time.sleep(0.1)
    fail(f"timed out waiting for {pattern!r}")


def wait_network_ready(log_path, pattern, qemu, timeout=BOOT_TIMEOUT):
    """Existing readiness and receive preparation share one absolute bound."""
    deadline = time.monotonic() + timeout
    found = wait_output(log_path, pattern, qemu, timeout=timeout)
    wait_rx_setup(lambda: pathlib.Path(log_path).read_bytes(), lambda: qemu.poll() is None, deadline)
    return found


def build_iso(kernel, elf, work, step, broker=(), options="net"):
    empty = os.path.join(work, "empty")
    open(empty, "wb").close()
    built = subprocess.run(
        [*kernel_make(), "-C", kernel, "--no-print-directory", "durable-iso", f"DURABLE_STEP={step}",
         f"DURABLE_OPTIONS={options}", f"EXTERNAL_USER_ELF={elf}", f"EXTERNAL_INPUT={empty}", *broker],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if built.returncode != 0:
        sys.stderr.write(built.stdout.decode(errors="replace"))
        fail(f"durable ISO build for step {step} failed")
    iso = os.path.join(work, f"net-{step}.iso")
    os.replace(os.path.join(kernel, "build", "durable", f"absd-durable-{step}.iso"), iso)
    image = os.path.join(work, f"net-{step}.img")
    with open(image, "wb") as handle:
        handle.truncate(2 * 1024 * 1024)
    return iso, image


def start_qemu(iso, image, log_path, netdev, stopped_with_qmp=None):
    """Boots the ISO; with `stopped_with_qmp` (a socket path) QEMU starts
    stopped (`-S`) and serves QMP there, for `Qmp.set_link` before `cont`."""
    if os.path.exists(log_path):
        os.unlink(log_path)
    command = served_qemu(QEMU) + QEMU_CPU + [
        "-cdrom", iso, "-drive", f"file={image},format=raw,if=ide,index=0",
        "-display", "none", "-serial", f"file:{log_path}", "-no-reboot", "-no-shutdown",
        "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        "-device", "e1000,netdev=n0"] + netdev
    if stopped_with_qmp is not None:
        if os.path.exists(stopped_with_qmp):
            os.unlink(stopped_with_qmp)
        command += ["-S", "-qmp", f"unix:{stopped_with_qmp},server,nowait"]
    return subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class Qmp:
    """One QMP connection, enough for `set_link` and `cont`."""

    def __init__(self, path, qemu, timeout=10.0):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        deadline = time.monotonic() + timeout
        while True:
            try:
                self.sock.connect(path)
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if qemu.poll() is not None or time.monotonic() > deadline:
                    fail("QEMU offered no QMP socket")
                time.sleep(0.05)
        self.sock.settimeout(30.0)
        self.lines = self.sock.makefile("rwb", buffering=0)
        if not self.lines.readline():  # the greeting
            fail("QMP closed before its greeting")
        self.execute("qmp_capabilities")

    def execute(self, command, **arguments):
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

    def set_link(self, up):
        self.execute("set_link", name="n0", up=up)

    def close(self):
        self.sock.close()


def finish_boot(qemu, log_path, done_pattern, link_line=rb"\nNETWORK LINK OK ", disabled_line=None):
    """Waits for QEMU to end and checks the boot's accounting. `disabled_line`
    is the one `NIC DISABLED` line a dead-NIC boot must print; otherwise any
    such line fails the boot."""
    try:
        status = qemu.wait(timeout=60)
    except subprocess.TimeoutExpired:
        fail("QEMU did not exit after the quit command")
    log = open(log_path, "rb").read()
    output = stdout_of(log_path)
    done = re.search(done_pattern, output)
    if not done:
        fail(f"no {done_pattern!r} in the worker's output")
    for line in (rb"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ", rb"\nDURABLE WORKLOAD OK\n",
                 rb"\nABSD BOOT OK\n", link_line):
        if not re.search(line, log):
            fail(f"serial log lacks {line!r}")
    for bad in (rb"PANIC", rb"KERNEL FAULT", rb"init: FAILED", rb"NIC DISABLED"):
        if bad in log and not (disabled_line is not None and bad == rb"NIC DISABLED"):
            fail(f"serial log has {bad!r}")
    if disabled_line is not None:
        if log.count(rb"NIC DISABLED") != 1 or not re.search(disabled_line, log):
            fail(f"serial log lacks exactly one {disabled_line!r}")
    if status != 3:
        fail(f"QEMU exit {status}")
    nic = re.search(rb"NIC STATS (.*)\n", log)
    return done, nic.group(1).decode() if nic else "none"


# ---------------------------------------------------------------- frames

def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(payload, protocol=1, src=HOST_IP, dst=GUEST_IP, ident=0x1234, flags_offset=0x4000,
         ihl=5, version=4, total=None, bad_checksum=False, ttl=64):
    total = 20 + len(payload) if total is None else total
    header = struct.pack("!BBHHHBBH4s4s", (version << 4) | ihl, 0, total, ident, flags_offset,
                         ttl, protocol, 0, src, dst)
    value = checksum(header)
    if bad_checksum:
        value ^= 0x5A5A
    header = header[:10] + struct.pack("!H", value) + header[12:]
    return header + payload


def icmp_echo(ident, sequence, data, bad_checksum=False, kind=8):
    body = struct.pack("!BBHHH", kind, 0, 0, ident, sequence) + data
    value = checksum(body)
    if bad_checksum:
        value ^= 0x00FF
    return body[:2] + struct.pack("!H", value) + body[4:]


def ethernet(dst, payload, kind=0x0800):
    return dst + HOST_MAC + struct.pack("!H", kind) + payload


def arp_request(target_ip, sender_ip=HOST_IP):
    body = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, HOST_MAC, sender_ip, b"\0" * 6, target_ip)
    return ethernet(b"\xff" * 6, body, 0x0806)


class Wire:
    def __init__(self, sock, guest_path):
        self.sock = sock
        self.guest_path = guest_path

    def send(self, frame):
        self.sock.sendto(frame, self.guest_path)

    def receive(self, wait, qemu, accept=lambda frame: True):
        """The next frame `accept` takes within `wait` seconds; answers any
        ARP request for the host address on the way."""
        end = time.monotonic() + wait
        while time.monotonic() < end:
            try:
                frame = self.sock.recv(4096)
            except socket.timeout:
                if qemu.poll() is not None:
                    fail(f"QEMU exited ({qemu.returncode}) during the exchange")
                continue
            if frame[12:14] == b"\x08\x06" and frame[20:22] == b"\x00\x01" and frame[38:42] == HOST_IP:
                reply = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2, HOST_MAC, HOST_IP,
                                    frame[22:28], frame[28:32])
                self.send(ethernet(frame[6:12], reply, 0x0806))
                continue
            if accept(frame):
                return frame
        return None


def stats_query(wire, guest_mac, qemu):
    wire.send(ethernet(guest_mac, b"S" + b"\0" * 45, CONTROL))
    frame = wire.receive(5.0, qemu, lambda frame: frame[12:14] == b"\x88\xb5" and frame[14:15] == b"s")
    if frame is None:
        fail("no answer to a counter query")
    return struct.unpack("<QQQQ", frame[15:47])


def run_frames(kernel, elf, work, link_down=False):
    # AF_UNIX paths are limited to 107 bytes on this host. Keep only the
    # transient sockets here; images, captures and logs stay in work.
    with tempfile.TemporaryDirectory(prefix="absd-net-", dir="/tmp") as sockets:
        return run_frames_with_sockets(kernel, elf, work, sockets, link_down)


def run_frames_with_sockets(kernel, elf, work, sockets, link_down=False):
    phase = "linkdown" if link_down else "frames"
    iso, image = build_iso(kernel, elf, work, 1)
    log = os.path.join(work, f"{phase}.serial.log")
    host_path, guest_path = os.path.join(sockets, "host.sock"), os.path.join(sockets, "guest.sock")
    qmp_path = os.path.join(sockets, "qmp.sock")
    for path in (host_path, guest_path):
        if os.path.exists(path):
            os.unlink(path)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    qemu = None
    qmp = None
    try:
        sock.bind(host_path)
        sock.settimeout(0.1)
        qemu = start_qemu(iso, image, log, [
            "-netdev", f"dgram,id=n0,local.type=unix,local.path={guest_path},"
                       f"remote.type=unix,remote.path={host_path}",
            "-object", f"filter-dump,id=f0,netdev=n0,file={os.path.join(work, f'{phase}.pcap')}"],
            stopped_with_qmp=qmp_path if link_down else None)
        if link_down:
            qmp = Qmp(qmp_path, qemu)
            qmp.set_link(False)
            qmp.execute("cont")
        ready = wait_network_ready(log, rb"NETD FRAMES READY mac=([0-9a-f:]{17}) ip=10.0.2.15/24 link=(up|down)", qemu)
        guest_mac = bytes.fromhex(ready.group(1).decode().replace(":", ""))
        if ready.group(2) != (b"down" if link_down else b"up"):
            fail(f"ready with link={ready.group(2).decode()}")
        # QMP cont and receive preparation have completed before any wire
        # exchange/silence window. First TX alone would not open the gate.
        wire = Wire(sock, guest_path)
        not_control = lambda frame: frame[12:14] != b"\x88\xb5"

        if link_down:
            # Nothing flows with the link down: the stack is up and
            # listening, the wire is not.
            # A wire check: QEMU drops frames both ways with the link down.
            wire.send(arp_request(GUEST_IP))
            stray = wire.receive(1.0, qemu, not_control)
            if stray is not None:
                fail(f"a frame crossed the wire with the link down: {stray[:42].hex()}")
            qmp.set_link(True)
            wait_output(log, rb"NETD LINK UP\n", qemu, timeout=30.0)
            print("LINK DOWN OK ready=link-down wire=silent then=link-up", flush=True)

        # ARP: an answer for our address, silence for another.
        wire.send(arp_request(GUEST_IP))
        reply = wire.receive(5.0, qemu, lambda frame: frame[12:14] == b"\x08\x06")
        if reply is None:
            fail("no ARP reply")
        expected = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2, guest_mac, GUEST_IP, HOST_MAC, HOST_IP)
        if reply[:6] != HOST_MAC or reply[6:12] != guest_mac or reply[14:42] != expected:
            fail(f"ARP reply {reply[:42].hex()}")
        wire.send(arp_request(bytes([10, 0, 2, 99])))
        stray = wire.receive(1.0, qemu, not_control)
        if stray is not None:
            fail(f"answer to ARP for another address: {stray[:42].hex()}")
        print("ARP OK reply=is-at other-address=silent", flush=True)

        def echo(data, ident, sequence):
            wire.send(ethernet(guest_mac, ipv4(icmp_echo(ident, sequence, data), ident=sequence)))
            frame = wire.receive(5.0, qemu, lambda frame: frame[12:14] == b"\x08\x00")
            if frame is None:
                fail(f"no echo reply for {len(data)} payload bytes")
            if frame[:6] != HOST_MAC or frame[6:12] != guest_mac:
                fail("echo reply addressing")
            header = frame[14:34]
            version_ihl, _, total, _, _, _, protocol, _, src, dst = struct.unpack("!BBHHHBBH4s4s", header)
            if version_ihl != 0x45 or protocol != 1 or src != GUEST_IP or dst != HOST_IP:
                fail(f"echo reply IPv4 header {header.hex()}")
            if checksum(header) != 0:
                fail("echo reply IPv4 checksum")
            if total != 20 + 8 + len(data):
                fail(f"echo reply total length {total}")
            body = frame[34:14 + total]
            if checksum(body) != 0:
                fail("echo reply ICMP checksum")
            if body[:2] != b"\0\0" or body[4:8] != struct.pack("!HH", ident, sequence) or body[8:] != data:
                fail(f"echo reply body differs for {len(data)} bytes")
            return header

        rng = random.Random(0x1CE)
        header = echo(b"ipv4", 0x4242, 1)
        before = stats_query(wire, guest_mac, qemu)
        good = ipv4(icmp_echo(7, 7, b"x" * 32))
        malformed = {
            "bad-header-checksum": ipv4(icmp_echo(7, 1, b"x" * 32), bad_checksum=True),
            "ihl-4": ipv4(icmp_echo(7, 2, b"x" * 32), ihl=4),
            "total-beyond-frame": ipv4(icmp_echo(7, 3, b"x" * 32), total=200),
            "version-6": ipv4(icmp_echo(7, 4, b"x" * 32), version=6),
            "other-destination": ipv4(icmp_echo(7, 5, b"x" * 32), dst=bytes([10, 0, 2, 16])),
            "more-fragments": ipv4(icmp_echo(7, 6, b"x" * 32), flags_offset=0x2000),
            "fragment-offset": ipv4(icmp_echo(7, 7, b"x" * 32), flags_offset=0x0010),
            "bad-icmp-checksum": ipv4(icmp_echo(7, 8, b"x" * 32, bad_checksum=True)),
            "truncated-icmp": ipv4(icmp_echo(7, 9, b"x" * 32)[:4]),
            "short-ip-header": good[:12],
        }
        for name, packet in malformed.items():
            wire.send(ethernet(guest_mac, packet))
            stray = wire.receive(0.7, qemu, not_control)
            if stray is not None:
                fail(f"malformed packet {name} was answered: {stray[:48].hex()}")
        after = stats_query(wire, guest_mac, qemu)
        rx_delta, tx_delta = after[0] - before[0], after[1] - before[1]
        # The counter query itself is the one frame beyond the malformed
        # ones, and the previous query's answer the one frame sent.
        if rx_delta != len(malformed) + 1 or tx_delta != 1:
            fail(f"counters after malformed packets rx_delta={rx_delta} tx_delta={tx_delta}")
        echo(b"after", 0x4242, 2)
        print(f"IPV4 OK reply_header={header.hex()} malformed={len(malformed)} unanswered={len(malformed)} "
              f"rx_delta={rx_delta} tx_delta={tx_delta}", flush=True)

        sizes = [0, 1, 56, 100, 512, 1000, 1471, 1472]
        for index, size in enumerate(sizes):
            echo(bytes(rng.getrandbits(8) for _ in range(size)), 0x5151, 100 + index)
        print(f"ICMP ECHO OK requests={len(sizes)} payloads={sizes[0]}..{sizes[-1]} byte-exact", flush=True)

        wire.send(ethernet(guest_mac, b"Q" + b"\0" * 45, CONTROL))
        done, nic = finish_boot(qemu, log, rb"NETD FRAMES DONE rx_frames=(\d+) tx_frames=(\d+) link_errors=0 ",
                                link_line=rb"\nNIC LINK DOWN AT PROBE " if link_down else rb"\nNETWORK LINK OK ")
        print(f"{phase.upper()} BOOT OK {done.group(0).decode()} nic: {nic}", flush=True)
        return int(done.group(1)), int(done.group(2))
    finally:
        if qemu is not None and qemu.poll() is None:
            qemu.kill()
            qemu.wait()
        if qmp is not None:
            qmp.close()
        sock.close()
        for path in (host_path, guest_path, qmp_path):
            if os.path.exists(path):
                os.unlink(path)


# ---------------------------------------------------------------- dead NIC

def run_dead_nic(kernel, elf, work):
    """A `net` boot with the kernel's `nic-ring-fault` injection: the device
    disables itself at the stack's first ring access and the worker's
    poll/wait loop must then run at the idle cadence, not spin."""
    iso, image = build_iso(kernel, elf, work, 3, options="net nic-ring-fault")
    log = os.path.join(work, "deadnic.serial.log")
    qemu = start_qemu(iso, image, log, ["-netdev", "user,id=n0,restrict=on"])
    try:
        ready = wait_output(log, rb"NETD DEAD NIC READY link=(up|down) disabled=(yes|no)\n", qemu)
        if ready.groups() != (b"up", b"no"):
            fail(f"dead-NIC boot ready with link={ready.group(1).decode()} disabled={ready.group(2).decode()}")
        done, nic = finish_boot(
            qemu, log,
            rb"NETD DEAD NIC DONE passes=(\d+) ms=(\d+) link_errors=(\d+) last_error=(-?\d+) disabled=yes\n",
            disabled_line=rb"\nNIC DISABLED reason=rx-head-outside-ring head=35\n")
        passes, ms, errors, last = (int(group) for group in done.groups())
        # Pacing: with no sockets every wait pauses its 10 ms bound, so a
        # pass takes 5..=20 ms. A spin makes tens of thousands of passes in
        # the window (the no-pacing mutant made 24651); a stalled loop
        # makes almost none.
        if not ms // 20 <= passes <= ms // 5 or errors < passes or last != -5:
            fail(f"dead-NIC loop passes={passes} ms={ms} link_errors={errors} last_error={last}")
        if not re.search(rb"\nNIC RING FAULT INJECTED rdh=35\n", open(log, "rb").read()):
            fail("serial log lacks the ring fault injection line")
        if not re.search(rb" flags=2$", nic.encode(), re.M):
            fail(f"NIC STATS without the disabled flag: {nic}")
        print(f"DEAD NIC OK passes={passes} ms={ms} link_errors={errors} last_error={last} "
              f"paced=yes disabled=yes nic: {nic}", flush=True)
    finally:
        if qemu.poll() is None:
            qemu.kill()
            qemu.wait()


# ---------------------------------------------------------------- tcp

def free_ports(count):
    ports, holders = [], []
    for _ in range(count):
        holder = socket.socket()
        holder.bind(("127.0.0.1", 0))
        ports.append(holder.getsockname()[1])
        holders.append(holder)
    for holder in holders:
        holder.close()
    return ports


def connect(port, timeout=30.0):
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def receive_all(sock):
    data = bytearray()
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            return bytes(data)
        data += chunk


def control(port, command):
    with connect(port) as sock:
        sock.sendall(command.encode() + b"\n")
        return receive_all(sock).decode()


def stats(port):
    line = control(port, "STATS")
    if not line.startswith("STATS "):
        fail(f"control reply {line!r}")
    return {key: int(value) for key, value in (item.split("=") for item in line.split()[1:])}


def echo_stream(port, total, rng):
    """Random-size writes and reads concurrently; returns the size lists."""
    data = rng.randbytes(total)
    sock = connect(port)
    writes, reads = [], []
    failure = []

    def writer():
        try:
            offset = 0
            while offset < total:
                size = min(rng.choice([1, 7, 100, 1000, 1460, 4096, 9000, 65536]), total - offset)
                sock.sendall(data[offset:offset + size])
                writes.append(size)
                offset += size
            sock.shutdown(socket.SHUT_WR)
        except OSError as error:
            failure.append(error)

    thread = threading.Thread(target=writer)
    thread.start()
    received = bytearray()
    read_rng = random.Random(rng.random())
    while True:
        chunk = sock.recv(read_rng.choice([1, 13, 500, 1460, 8192, 65536]))
        if not chunk:
            break
        reads.append(len(chunk))
        received += chunk
    thread.join()
    sock.close()
    if failure:
        fail(f"writer: {failure[0]}")
    if hashlib.sha256(received).digest() != hashlib.sha256(data).digest():
        fail(f"echo stream differs ({len(received)} of {total} bytes)")
    return writes, reads


def run_tcp(kernel, elf, work):
    # A broker-mode boot: the worker's startup record names the NIC and a
    # broker channel with four slots, the SSH server's shape.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    iso, image = build_iso(kernel, elf, work, 2, (
        f"BROKER_POLICY={os.path.join(root, 'broker-policy.txt')}",
        f"OWNER_1_ELF={os.path.join(root, 'broker-echo.elf')}"))
    log = os.path.join(work, "tcp.serial.log")
    echo_port, control_port, closed_port = free_ports(3)
    forwards = (f"hostfwd=tcp:127.0.0.1:{echo_port}-:7000,hostfwd=tcp:127.0.0.1:{control_port}-:7001,"
                f"hostfwd=tcp:127.0.0.1:{closed_port}-:7005")
    qemu = start_qemu(iso, image, log, [
        "-netdev", f"user,id=n0,net=10.0.2.0/24,host=10.0.2.2,restrict=on,{forwards}",
        "-object", f"filter-dump,id=f0,netdev=n0,file={os.path.join(work, 'tcp.pcap')}"])
    try:
        ready = wait_network_ready(log, rb"NETD TCP READY .* sockets=(\d+)", qemu)
        listening = int(ready.group(1))
        rng = random.Random(0x7C9)
        started = time.monotonic()

        # LISTEN: the listened port answers; the unlistened one is closed
        # (QEMU accepts the host side, the guest refuses, the host sees EOF
        # or a reset and never a byte).
        with connect(echo_port) as sock:
            sock.sendall(b"L")
            if sock.recv(1) != b"L":
                fail("no echo from the listened port")
        try:
            with connect(closed_port, timeout=10) as sock:
                sock.sendall(b"nobody")
                if sock.recv(16) != b"":
                    fail("data from an unlistened port")
        except (ConnectionResetError, BrokenPipeError, ConnectionRefusedError):
            pass
        counters = stats(control_port)
        if counters["echo_accepted"] != 1:
            fail(f"accepted after listen check: {counters}")
        print(f"TCP LISTEN OK port=7000 accepted={counters['echo_accepted']} unlistened=closed", flush=True)

        # STREAM: large, both directions, uneven sizes, peer FIN.
        writes, reads = echo_stream(echo_port, 2 * 1024 * 1024, rng)
        if writes == reads:
            fail("write and read sizes coincide")
        # Server-sent stream with the server closing first.
        with connect(control_port) as sock:
            sock.sendall(b"SOURCE 1048576\n")
            data = receive_all(sock)
        expected = bytes(((index * 2654435761) >> 13) & 0xFF for index in range(1048576))
        if data != expected:
            fail(f"SOURCE stream differs ({len(data)} bytes)")
        # Backpressure: stop reading. The guest echoes until its send buffer
        # is full (the host's own receive buffers, up to several MiB, fill
        # first), then stops reading, and the host's writes stall.
        total = 32 * 1024 * 1024
        payload = rng.randbytes(total)
        sock = connect(echo_port)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        sock.setblocking(False)
        # Established when, together, the host has made no write progress
        # for 3 s and the guest's echoed count has not moved for 2 s.
        offset, last_progress = 0, time.monotonic()
        samples = []
        deadline = time.monotonic() + 120
        first = second = None
        while offset < total and time.monotonic() < deadline:
            try:
                offset += sock.send(payload[offset:offset + 65536])
                last_progress = time.monotonic()
                continue
            except BlockingIOError:
                pass
            time.sleep(0.2)
            if time.monotonic() - last_progress < 1.0:
                continue
            samples.append((time.monotonic(), stats(control_port)))
            old = [sample for sample in samples if sample[0] <= samples[-1][0] - 2.0]
            if (time.monotonic() - last_progress >= 3.0 and old
                    and old[-1][1]["live_bytes"] == samples[-1][1]["live_bytes"]):
                first, second = old[-1][1], samples[-1][1]
                break
        stalled_at = offset
        if first is None or stalled_at >= total:
            fail(f"no backpressure: host wrote {offset} of {total}, samples {[s[1]['live_bytes'] for s in samples]}")
        if first["active"] != 1 or first["live_bytes"] >= stalled_at:
            fail(f"backpressure accounting: {first} then {second} (host stalled at {stalled_at})")
        sock.setblocking(True)
        received = bytearray()
        sender_error = []

        def finish_sending():
            try:
                sock.sendall(payload[stalled_at:])
                sock.shutdown(socket.SHUT_WR)
            except OSError as error:
                sender_error.append(error)

        thread = threading.Thread(target=finish_sending)
        thread.start()
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            received += chunk
        thread.join()
        sock.close()
        if sender_error or bytes(received) != payload:
            fail(f"backpressured stream differs ({len(received)} of {total}) {sender_error}")
        # Reset: data then RST; the guest drops the connection and goes on.
        sock = connect(echo_port)
        sock.sendall(b"about to reset")
        time.sleep(0.5)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        sock.close()
        time.sleep(1.0)
        counters = stats(control_port)
        if counters["echo_reset"] != 1 or counters["active"] != 0:
            fail(f"after reset: {counters}")
        print(f"TCP STREAM OK echo_bytes=2097152 writes={len(writes)} reads={len(reads)} source=1048576 "
              f"backpressure_stalled_at={stalled_at} guest_echoed={first['live_bytes']} of={total} reset=1 peer_fin=yes", flush=True)

        # RECONNECT: sequential connections; nothing left behind.
        heap_after_warmup = None
        connections = 200
        for index in range(connections):
            message = rng.randbytes(rng.randrange(1, 3000))
            with connect(echo_port) as sock:
                sock.sendall(message)
                sock.shutdown(socket.SHUT_WR)
                if receive_all(sock) != message:
                    fail(f"reconnect {index} echo differs")
            if index == 19:
                heap_after_warmup = stats(control_port)["heap_pages"]
        time.sleep(1.0)
        final = stats(control_port)
        expected_accepted = 1 + 1 + 1 + 1 + connections
        if (final["active"] != 0 or final["echo_accepted"] != expected_accepted
                or final["echo_finished"] != expected_accepted - 1 or final["echo_reset"] != 1
                or final["heap_pages"] != heap_after_warmup or final["link_errors"] != 0):
            fail(f"after reconnects: {final} (heap after 20: {heap_after_warmup})")
        # Every connection socket was released: only the listeners remain
        # (the control connection answering this query is the one extra).
        if final["sockets"] != listening + 1:
            fail(f"sockets after reconnects {final['sockets']} (listening {listening})")
        print(f"TCP RECONNECT OK connections={connections} active=0 sockets={final['sockets']} "
              f"listening={listening} heap_pages={final['heap_pages']} (unchanged since connection 20) "
              f"released={final['released']}", flush=True)

        # A brokered child while the worker holds the NIC; the child's
        # startup vector has no NIC (init never hands it on).
        reply = control(control_port, "SPAWN")
        if reply != "SPAWNED status=0 stderr=broker-echo args=0,net\nbroker-echo env=BROKER_ECHO=hello=world\n":
            fail(f"spawn reply {reply!r}")
        print(f"TCP BROKER OK {' | '.join(reply.split(chr(10))).strip(' |')}", flush=True)
        reply = control(control_port, "QUIT")
        if reply != "BYE\n":
            fail(f"quit reply {reply!r}")
        done, nic = finish_boot(qemu, log, rb"NETD TCP DONE .* sockets=(\d+) listening=(\d+) .*link_errors=0")
        if done.group(1) != done.group(2):
            fail(f"sockets left at quit: {done.group(0)!r}")
        summary = b"BROKER SUMMARY generation=1 requests=1 dropped=0 started=1 refused=0 exited=1 reclaimed=0 idle=true"
        if summary not in open(log, "rb").read():
            fail("broker summary")
        print(f"TCP BOOT OK seconds={time.monotonic() - started:.0f} {done.group(0).decode()} nic: {nic}",
              flush=True)
    finally:
        if qemu.poll() is None:
            qemu.kill()
            qemu.wait()


def main():
    arguments = sys.argv[1:]
    only = {"frames", "linkdown", "deadnic", "tcp"}
    if "--only" in arguments:
        at = arguments.index("--only")
        only = set(arguments[at + 1].split(","))
        del arguments[at:at + 2]
    kernel, elf, work = arguments
    elf, work = os.path.abspath(elf), os.path.abspath(work)
    os.makedirs(work, exist_ok=True)
    healthy = run_frames(kernel, elf, work) if "frames" in only else None
    if "linkdown" in only:
        counts = run_frames(kernel, elf, work, link_down=True)
        # The guest saw and sent exactly what the healthy boot did: nothing
        # leaked in or out while the link was down.
        if healthy is not None and counts != healthy:
            fail(f"link-down boot frame counters {counts} differ from the healthy boot's {healthy}")
    if "deadnic" in only:
        run_dead_nic(kernel, elf, work)
    if "tcp" in only:
        run_tcp(kernel, elf, work)
    print(f"NET MATRIX OK phases={','.join(sorted(only))}")


if __name__ == "__main__":
    main()
