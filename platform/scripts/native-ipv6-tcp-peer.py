#!/usr/bin/env python3
"""Independent Linux IPv6 UDP/TCP/ND with a bounded DNS application fixture."""
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
    raise SystemExit("native-ipv6-tcp-peer: optimized Python refused")


def write_json(path, value):
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2) + "\n")
    temp.replace(path)


def question(query):
    if not 17 <= len(query) <= 271 or query[2:12] != b"\x01\0\0\x01" + b"\0" * 6:
        raise ValueError("query header")
    at, labels = 12, []
    while at < len(query):
        size = query[at]
        at += 1
        if size == 0:
            break
        if size > 63 or at + size > len(query):
            raise ValueError("query label")
        labels.append(query[at:at + size].decode("ascii"))
        at += size
    if at + 4 != len(query):
        raise ValueError("query suffix")
    kind, klass = struct.unpack("!HH", query[at:])
    name = ".".join(labels)
    if klass != 1 or (name, kind) not in (("a.example", 1), ("tc.example", 1), ("tcaaaa.example", 28)):
        raise ValueError("unexpected question")
    return name, kind


def answer(query, truncated=False, other_family=False, large=False):
    _, kind = question(query)
    q = bytearray(query)
    if other_family:
        kind = 1 if kind == 28 else 28
        q[-4:-2] = kind.to_bytes(2, "big")
    q[2:4] = (0x8380 if truncated else 0x8180).to_bytes(2, "big")
    if truncated:
        return bytes(q)
    data = bytes([192, 0, 2, 9]) if kind == 1 else ipaddress.IPv6Address("2001:db8::9").packed
    q[6:8] = (2 if large else 1).to_bytes(2, "big")
    q.extend(b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 60, len(data)) + data)
    if large:
        text = (bytes([200]) + b"x" * 200) * 8
        q.extend(b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(text)) + text)
        assert 1232 < len(q) <= 4096
    return bytes(q)


def exact(stream, length, deadline):
    data = bytearray()
    while len(data) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("TCP fixture absolute deadline")
        stream.settimeout(remaining)
        part = stream.recv(length - len(data))
        if not part:
            if not data:
                return None
            raise EOFError("partial TCP frame")
        data.extend(part)
    return bytes(data)


class Peer:
    def __init__(self, bind="::1", port=0, forbidden_port=None, expected_source=None,
                 timeout=120, reverse_nd_interface=None):
        self.records, self.errors, self.listeners, self.datagrams, self.connections, self.workers = [], [], [], [], [], []
        self.stop = threading.Event()
        self.deadline = time.monotonic() + timeout
        self.expected_source = expected_source
        self.reverse_nd_interface = reverse_nd_interface
        self.reversed = False
        self.tcp_accepts = 0
        try:
            for value in (port, forbidden_port):
                if value is None:
                    continue
                udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                udp.bind((bind, value))
                self.datagrams.append(udp)
                tcp = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                tcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                tcp.bind((bind, udp.getsockname()[1]))
                tcp.listen(2)
                self.listeners.append(tcp)
            self.port = self.datagrams[0].getsockname()[1]
            self.thread = threading.Thread(target=self.serve)
            self.thread.start()
        except BaseException:
            for sock in self.datagrams + self.listeners:
                sock.close()
            raise

    def serve(self):
        try:
            while not self.stop.is_set():
                if time.monotonic() >= self.deadline:
                    raise TimeoutError("peer absolute deadline")
                ready, _, _ = select.select(self.datagrams + self.listeners, [], [], 0.05)
                for sock in ready:
                    if len(self.records) >= 32:
                        raise AssertionError("record census bound")
                    if sock in self.listeners:
                        stream, source = sock.accept()
                        self.connections.append(stream)
                        if sock is not self.listeners[0]:
                            raise AssertionError("ungranted TCP destination")
                        if self.expected_source and (source[0], source[1]) != (self.expected_source[0], 7203):
                            raise AssertionError("unexpected native TCP source")
                        self.tcp_accepts += 1
                        if self.expected_source and self.tcp_accepts != 1:
                            raise AssertionError("native TCP connection repeated")
                        self.records.append({"transport": "TCP-accept", "source": source})
                        worker = threading.Thread(target=self.tcp, args=(stream, source))
                        self.workers.append(worker)
                        worker.start()
                        continue
                    query, source = sock.recvfrom(1233)
                    if sock is not self.datagrams[0]:
                        raise AssertionError("ungranted UDP destination")
                    if self.expected_source and (source[0], source[1]) != self.expected_source:
                        raise AssertionError("unexpected native UDP source")
                    name, kind = question(query)
                    data = answer(query, truncated=name != "a.example")
                    record = {"transport": "UDP", "source": source, "name": name, "kind": kind,
                              "query_hex": query.hex(), "answer_hex": data.hex()}
                    self.records.append(record)
                    if self.reverse_nd_interface and not self.reversed:
                        subprocess.run(["ip", "-6", "neigh", "flush", "to", source[0], "dev", self.reverse_nd_interface],
                                       check=True, capture_output=True, timeout=2)
                        record["reverse_nd"] = True
                        self.reversed = True
                    if sock.sendto(data, source) != len(data):
                        raise AssertionError("short UDP response")
        except BaseException as error:
            self.errors.append(repr(error))
            self.stop.set()

    def tcp(self, stream, source):
        try:
            with stream:
                stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                deadline = min(self.deadline, time.monotonic() + 15)
                queries = 0
                while not self.stop.is_set():
                    prefix = exact(stream, 2, deadline)
                    if prefix is None:
                        self.records.append({"transport": "TCP-FIN-EOF", "source": source, "queries": queries})
                        stream.shutdown(socket.SHUT_WR)
                        return
                    length = int.from_bytes(prefix, "big")
                    if not 17 <= length <= 271:
                        raise AssertionError("TCP query length")
                    query = exact(stream, length, deadline)
                    if query is None:
                        raise EOFError("missing TCP question")
                    name, kind = question(query)
                    if name == "a.example" or queries >= 2:
                        raise AssertionError("unexpected native fallback")
                    if self.expected_source and not any(
                            r.get("transport") == "UDP" and r.get("query_hex") == query.hex()
                            and bytes.fromhex(r["answer_hex"])[2] & 2 for r in self.records):
                        raise AssertionError("TCP question did not match the complete prior UDP TC query")
                    self.records.append({"transport": "TCP-DNS", "source": source, "name": name,
                                         "kind": kind, "query_hex": query.hex()})
                    queries += 1
                    responses = [answer(query, large=True)]
                    if self.expected_source:
                        responses.insert(0, answer(query, other_family=True))
                    for data in responses:
                        frame = len(data).to_bytes(2, "big") + data
                        for at in range(0, len(frame), 71):
                            stream.sendall(frame[at:at + 71])
        except BaseException as error:
            if not self.stop.is_set():
                self.errors.append(repr(error))
                self.stop.set()

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        for stream in self.connections:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for worker in self.workers:
            worker.join(timeout=2)
        for sock in self.datagrams + self.listeners + self.connections:
            sock.close()
        if self.thread.is_alive() or any(worker.is_alive() for worker in self.workers):
            self.errors.append("fixture thread did not stop")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("work", type=Path)
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("--reverse-nd-interface")
    a = p.parse_args()
    if not 1 <= a.timeout <= 180 or not a.work.is_dir():
        p.error("existing output directory and timeout 1..180 required")
    peer = Peer("fd00:ab5d::2", 42020, 42021, ("fd00:ab5d::15", 7202), a.timeout, a.reverse_nd_interface)
    signal.signal(signal.SIGTERM, lambda *_: peer.stop.set())
    signal.signal(signal.SIGINT, lambda *_: peer.stop.set())
    try:
        write_json(a.work / "PEER-READY.json", {"pid": os.getpid(), "transport": "Linux AF_INET6 UDP and TCP", "port": peer.port})
        while not peer.stop.is_set() and not (a.work / "PEER-STOP").exists():
            peer.stop.wait(0.05)
    finally:
        peer.close()
        write_json(a.work / "PEER-RESULT.json", {"disposition": "FAIL" if peer.errors else "PASS",
                   "records": peer.records, "errors": peer.errors, "tcp_accepts": peer.tcp_accepts})
    if peer.errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
