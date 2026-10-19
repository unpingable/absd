#!/usr/bin/env python3
"""Bounded DNS application fixture on an independent Linux AF_INET6 UDP socket.

Linux implements IPv6, UDP and Neighbor Discovery. This application supplies
controlled DNS A/AAAA answers; it is not an independent DNS server product.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import threading
import time

if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
    raise SystemExit("native-ipv6-peer: optimized Python is refused")

MAX_QUERIES = 16
MAX_DATAGRAM = 1232


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def question(packet):
    if len(packet) < 17 or packet[2:12] != b"\x01\x00\x00\x01" + b"\0" * 6:
        raise ValueError("query header")
    at = 12
    labels = []
    while True:
        if at >= len(packet):
            raise ValueError("missing label terminator")
        size = packet[at]
        at += 1
        if size == 0:
            break
        if size > 63 or at + size > len(packet):
            raise ValueError("query label")
        labels.append(packet[at:at + size].decode("ascii"))
        at += size
    if at + 4 != len(packet):
        raise ValueError("query length")
    kind, klass = struct.unpack("!HH", packet[at:])
    name = ".".join(labels)
    if klass != 1 or (name, kind) not in (("a.example", 1), ("aaaa.example", 28)):
        raise ValueError("unexpected question")
    return name, kind


def answer(query):
    name, kind = question(query)
    data = bytes([192, 0, 2, 9]) if kind == 1 else ipaddress.IPv6Address("2001:db8::9").packed
    header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    record = b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 60, len(data)) + data
    return header + query[12:] + record


class Peer:
    def __init__(self, bind="::1", port=0, forbidden_port=None, expected_source=None, timeout=120,
                 reverse_nd_interface=None):
        self.records = []
        self.errors = []
        self.stop = threading.Event()
        self.deadline = time.monotonic() + timeout
        self.expected_source = expected_source
        self.reverse_nd_interface = reverse_nd_interface
        self.reverse_nd_done = False
        self.sockets = []
        self.closed = False
        try:
            for value in (port, forbidden_port):
                if value is None:
                    continue
                sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((bind, value))
                self.sockets.append(sock)
            self.port = self.sockets[0].getsockname()[1]
            self.thread = threading.Thread(target=self.serve, name="ipv6-linux-peer")
            self.thread.start()
        except BaseException:
            for sock in self.sockets:
                sock.close()
            raise

    def serve(self):
        try:
            while not self.stop.is_set():
                if time.monotonic() >= self.deadline:
                    raise TimeoutError("peer absolute deadline")
                ready, _, _ = select.select(self.sockets, [], [], 0.05)
                for sock in ready:
                    query, _, flags, source = sock.recvmsg(MAX_DATAGRAM + 1)
                    if len(self.records) >= MAX_QUERIES:
                        raise AssertionError("query census bound")
                    record = {"transport": "Linux AF_INET6 SOCK_DGRAM", "source": source,
                              "port": sock.getsockname()[1], "query_hex": query.hex()}
                    self.records.append(record)
                    if sock is not self.sockets[0]:
                        raise AssertionError("ungranted destination received a datagram")
                    if flags & socket.MSG_TRUNC or len(query) > MAX_DATAGRAM:
                        raise AssertionError("oversize query")
                    if self.expected_source is not None:
                        expected_ip, expected_port = self.expected_source
                        if ipaddress.IPv6Address(source[0]) != ipaddress.IPv6Address(expected_ip) or source[1] != expected_port:
                            raise AssertionError("unexpected native source")
                    name, kind = question(query)
                    record.update(name=name, kind=kind)
                    response = answer(query)
                    record["answer_hex"] = response.hex()
                    if self.reverse_nd_interface and not self.reverse_nd_done:
                        # This exact entry belongs to the disposable namespace.
                        # Make Linux resolve the guest before its first reply,
                        # so capture proves NS/NA in both directions.
                        show = ["ip", "-j", "-6", "neigh", "show", "to", source[0],
                                "dev", self.reverse_nd_interface]
                        before = json.loads(subprocess.check_output(show, text=True, timeout=2))
                        subprocess.run(["ip", "-6", "neigh", "flush", "to", source[0],
                                        "dev", self.reverse_nd_interface], check=True,
                                       capture_output=True, timeout=2)
                        after = json.loads(subprocess.check_output(show, text=True, timeout=2))
                        if after:
                            raise AssertionError("exact neighbor entry remained after flush")
                        record["reverse_nd"] = {"before": before, "after": after}
                        self.reverse_nd_done = True
                    if sock.sendto(response, source) != len(response):
                        raise AssertionError("short datagram send")
        except BaseException as error:
            self.errors.append(repr(error))
            self.stop.set()

    def close(self):
        if self.closed:
            return
        self.stop.set()
        self.thread.join(timeout=2)
        for sock in self.sockets:
            sock.close()
        self.closed = True
        if self.thread.is_alive():
            self.errors.append("fixture thread did not stop")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path)
    parser.add_argument("--bind", default="fd00:ab5d::2")
    parser.add_argument("--port", type=int, default=42010)
    parser.add_argument("--forbidden-port", type=int, default=42011)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--reverse-nd-interface")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 180:
        parser.error("timeout must be 1..180 seconds")
    if not args.work.is_dir():
        parser.error("work must be an existing campaign directory")
    if args.reverse_nd_interface and (len(args.reverse_nd_interface) > 15
            or not all(c.isascii() and (c.isalnum() or c in "_.-") for c in args.reverse_nd_interface)):
        parser.error("invalid interface name")
    peer = Peer(args.bind, args.port, args.forbidden_port,
                ("fd00:ab5d::15", 7002), args.timeout, args.reverse_nd_interface)
    def stop(_signum, _frame):
        peer.stop.set()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        write_json(args.work / "PEER-READY.json", {"pid": os.getpid(), "port": peer.port,
                   "transport": "Linux AF_INET6 SOCK_DGRAM", "bind": args.bind})
        while not peer.stop.is_set() and not (args.work / "PEER-STOP").exists():
            peer.stop.wait(0.05)
    finally:
        peer.close()
        write_json(args.work / "PEER-RESULT.json", {"records": peer.records, "errors": peer.errors,
                   "disposition": "FAIL" if peer.errors else "PASS"})
    if peer.errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
