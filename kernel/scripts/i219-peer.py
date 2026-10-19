#!/usr/bin/env python3
"""Operator-only Linux L2 peer for an explicitly selected ABSD net-probe boot.

Start before boot: sudo python3 scripts/i219-peer.py --interface eno1 \
    --target-mac 02:11:22:33:44:55
Use the target's independently recorded MAC and a dedicated Ethernet link.
Does not change interface configuration. --self-test never opens a socket.
Peer success does not establish kernel completion: separately capture the
target's NIC PROBE OK and terminal boot record. Oversize/error receive controls
remain unqualified here; physical hardware may discard them before the driver.
"""
import argparse
from collections import deque
import random
import re
import socket
import sys
import time

ETHERTYPE = b"\x88\xb5"
SIZES = (15, 42, 59, 60, 61, 64, 100, 511, 512, 1000, 1499, 1513, 1514)


def mac_argument(text):
    if not re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", text):
        raise argparse.ArgumentTypeError("MAC must contain six colon-separated octets")
    mac = bytes.fromhex(text.replace(":", ""))
    if mac == bytes(6) or mac[0] & 1:
        raise argparse.ArgumentTypeError("MAC must be nonzero and unicast")
    return mac


def padded(frame):
    return frame + bytes(max(0, 60 - len(frame)))


def reflected(frame):
    return frame[6:12] + frame[:6] + padded(frame)[12:]


def exchange(send, receive, local, target, hello_timeout=120.0):
    """receive(seconds) returns one frame or None; deadlines include filtering."""
    def target_frame(wait):
        deadline = time.monotonic() + wait
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("target frame deadline expired")
            frame = receive(remaining)
            if frame is None:
                raise TimeoutError("no target frame before deadline")
            # Ignore other stations/protocols, including our outgoing packets.
            if frame[6:12] == target and frame[12:14] == ETHERTYPE:
                return frame

    hello = b"\xff" * 6 + target + ETHERTYPE + b"ABSD-HELLO" + bytes(36)
    if target_frame(hello_timeout) != hello:
        raise ValueError("pinned target's hello differs from the reflector protocol")
    rng = random.Random(0xAB5D)

    def echo(size):
        return target + local + ETHERTYPE + b"E" + rng.randbytes(size - 15)

    def expect(frame):
        if target_frame(5.0) != reflected(frame):
            raise ValueError(f"byte mismatch reflecting {len(frame)}-byte frame")

    for size in SIZES:
        frame = echo(size)
        send(frame)
        expect(frame)
    # Together with the individual frames, crosses RX32 and TX16 ring wraps.
    burst = [echo(rng.randrange(15, 1515)) for _ in range(24)]
    for frame in burst:
        send(frame)
    for frame in burst:
        expect(frame)
    send(target + local + ETHERTYPE + b"Q" + bytes(45))
    return len(SIZES) + len(burst)


def self_test():
    local = mac_argument("02:00:00:00:00:01")
    target = mac_argument("02:11:22:33:44:55")

    class MemoryPeer:
        def __init__(self, mode="ok"):
            hello = b"\xff" * 6 + target + ETHERTYPE + b"ABSD-HELLO" + bytes(36)
            self.queue = deque([hello])
            self.mode, self.echoes, self.quit = mode, [], False
            if mode == "hello":
                self.queue[0] = hello[:-1] + b"x"
            if mode == "silent":
                self.queue.clear()
            if mode == "wrong-mac":
                self.queue[0] = hello[:6] + local + hello[12:]

        def send(self, frame):
            assert frame[:14] == target + local + ETHERTYPE
            if frame[14:15] == b"Q":
                assert len(frame) == 60
                self.quit = True
                return
            assert frame[14:15] == b"E" and 15 <= len(frame) <= 1514
            self.echoes.append(frame)
            # Independent in-memory reflector, including Ethernet padding.
            reply = local + target + frame[12:]
            reply += b"\0" * max(0, 60 - len(reply))
            if self.mode == "corrupt":
                reply = reply[:-1] + bytes([reply[-1] ^ 1])
            if self.mode == "timeout":
                return
            self.queue.append(reply)

        def receive(self, wait):
            assert 0 < wait <= 120
            return self.queue.popleft() if self.queue else None

    peer = MemoryPeer()
    peer.queue.appendleft(b"unrelated frame")
    assert exchange(peer.send, peer.receive, local, target) == 37
    assert peer.quit and len(peer.echoes) == 37
    assert [len(f) for f in peer.echoes[:len(SIZES)]] == list(SIZES)
    for mode, error in (("hello", ValueError), ("corrupt", ValueError),
                        ("silent", TimeoutError), ("timeout", TimeoutError),
                        ("wrong-mac", TimeoutError)):
        peer = MemoryPeer(mode)
        try:
            exchange(peer.send, peer.receive, local, target)
        except error:
            assert not peer.quit
        else:
            raise AssertionError(f"negative control {mode} was accepted")
    for text in ("", "02:11:22:33:44", "zz:11:22:33:44:55", "021122334455",
                 "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:00:00:00:01"):
        try:
            mac_argument(text)
        except argparse.ArgumentTypeError:
            pass
        else:
            raise AssertionError(f"invalid target MAC accepted: {text}")
    print("I219 PEER SELF-TEST OK (memory only; no hardware)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", help="exact Linux Ethernet interface")
    parser.add_argument("--target-mac", type=mac_argument)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        if args.interface or args.target_mac:
            parser.error("--self-test cannot be combined with hardware arguments")
        self_test()
        return 0
    if not args.interface or not args.target_mac:
        parser.error("physical peer requires both --interface and --target-mac")
    if not sys.platform.startswith("linux"):
        parser.error("physical peer requires Linux AF_PACKET")
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x88B5)) as sock:
        sock.bind((args.interface, 0))
        address = sock.getsockname()
        local = address[4]
        if address[3] != 1 or len(local) != 6 or local == bytes(6) or local[0] & 1:
            raise ValueError("selected interface is not an Ethernet unicast endpoint")
        if local == args.target_mac:
            raise ValueError("target MAC equals selected peer interface MAC")

        def send(frame):
            if sock.send(frame) != len(frame):
                raise OSError("short raw Ethernet send")

        def receive(wait):
            sock.settimeout(wait)
            try:
                return sock.recv(4096)
            except socket.timeout:
                return None

        print(f"Waiting for pinned target on {args.interface}; boot net-probe now", flush=True)
        count = exchange(send, receive, local, args.target_mac)
    print(f"I219 PEER EXCHANGE OK frames={count} quit_sent=yes")
    print("Kernel completion not observed here; oversize/error controls unqualified.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f"i219-peer: {error}", file=sys.stderr)
        sys.exit(1)
