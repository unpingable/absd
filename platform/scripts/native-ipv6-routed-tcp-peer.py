#!/usr/bin/env python3
"""Bounded Linux IPv6 DNS peer: UDP truncation, then A/AAAA on one TCP stream.

Linux supplies IPv6, routing, ND and both transports. The hash-bound existing
codec supplies controlled DNS messages. This is a fixture, not a DNS product.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import time
import types

SOURCE = Path(__file__).with_name("native-ipv6-peer.py")
SOURCE_HASH = "c72d3146d9eb26850208ce5cd85744209ee41af140fa878b523da73b4d90da37"
BIND = "fd00:ab5d:2::9"
GUEST = "fd00:ab5d:1::15"
PORT, FORBIDDEN_PORT = 42010, 42011
QUESTIONS = (("a.example", 1), ("aaaa.example", 28))
MAX_DNS, MAX_STREAM, MAX_EVENTS = 1232, 4096, 128


def stamp():
    # These are Linux host clocks, not the native guest's operation clock.
    return {"monotonic_ns": time.monotonic_ns(), "realtime_ns": time.time_ns()}


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("x") as stream:
        stream.write(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Peer:
    def __init__(self, codec, timeout):
        self.codec = codec
        self.deadline = time.monotonic() + timeout
        self.records, self.io, self.errors = [], [], []
        self.sockets = []
        self.connection = None
        self.stop_reason = None
        self.udp_queries, self.tcp_queries, self.tcp_answers = [], [], []
        self.received, self.sent = bytearray(), bytearray()
        self.pending, self.output = bytearray(), bytearray()
        self.tcp = {"source": None, "connections": 0, "read_eof": False,
                    "write_shutdown": False, "closed": False}

    def event_slot(self):
        require(len(self.io) < MAX_EVENTS, "I/O event census exceeded")

    def event(self, kind, **values):
        self.event_slot()
        row = {"event": kind, **stamp(), **values}
        self.io.append(row)
        return row

    def open(self):
        for transport in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
            for port in (PORT, FORBIDDEN_PORT):
                sock = socket.socket(socket.AF_INET6, transport)
                self.sockets.append(sock)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((BIND, port))
                if transport == socket.SOCK_STREAM:
                    sock.listen(1)
                sock.setblocking(False)
        self.udp, self.forbidden_udp, self.listener, self.forbidden_tcp = self.sockets

    @staticmethod
    def source(source, port):
        require(len(source) == 4 and ipaddress.IPv6Address(source[0]) == ipaddress.IPv6Address(GUEST)
                and source[1:] == (port, 0, 0), "unexpected source tuple")

    def datagram(self, sock):
        self.event_slot()
        query, _, flags, source = sock.recvmsg(MAX_DNS + 1)
        self.event("udp-recv", source=list(source), port=sock.getsockname()[1],
                   flags=flags, hex=query.hex())
        require(sock is self.udp, "ungranted UDP destination received a datagram")
        self.source(source, 7002)
        require(not flags & socket.MSG_TRUNC and len(query) <= MAX_DNS, "oversize UDP query")
        at = len(self.udp_queries)
        require(at < 2 and len(self.tcp_queries) == at, "unexpected UDP query count/order")
        name, kind = self.codec.question(query)
        require((name, kind) == QUESTIONS[at], "unexpected UDP question order")
        # Preserve transaction and question exactly; TC=1 and zero answers.
        response = query[:2] + struct.pack("!HHHHH", 0x8380, 1, 0, 0, 0) + query[12:]
        row = {"transport": "UDP", "source": list(source), "port": PORT,
               "name": name, "kind": kind, "query_hex": query.hex(),
               "answer_hex": response.hex(), **stamp()}
        self.records.append(row)
        self.udp_queries.append(query)
        self.event_slot()
        count = sock.sendto(response, source)
        self.event("udp-send", destination=list(source), port=PORT,
                   requested=len(response), count=count, hex=response[:count].hex())
        require(count == len(response), "short UDP answer send")

    def accept(self, listener):
        self.event_slot()
        connection, source = listener.accept()
        try:
            self.event("tcp-accept", source=list(source), port=listener.getsockname()[1])
            require(listener is self.listener, "ungranted TCP destination received a connection")
            self.source(source, 7003)
            require(self.tcp["connections"] == 0 and len(self.udp_queries) == 1,
                    "unexpected TCP connection count/order")
            connection.setblocking(False)
            self.connection = connection
            self.tcp.update(source=list(source), connections=1, accepted=stamp())
        except BaseException:
            connection.close()
            raise

    def receive(self):
        self.event_slot()
        chunk = self.connection.recv(MAX_STREAM + 1 - len(self.received))
        self.received.extend(chunk)
        self.pending.extend(chunk)
        self.event("tcp-recv", hex=chunk.hex(), count=len(chunk))
        if not chunk:
            self.tcp.update(read_eof=True, eof_observed=stamp())
            require(len(self.tcp_queries) == 2 and not self.pending and not self.output,
                    "TCP EOF before both complete answers were sent")
            self.event_slot()
            self.connection.shutdown(socket.SHUT_WR)
            self.tcp.update(write_shutdown=True, shutdown_observed=stamp())
            self.event("tcp-write-shutdown")
            self.event_slot()
            self.connection.close()
            self.connection = None
            self.tcp.update(closed=True, closed_observed=stamp())
            self.event("tcp-close")
            return
        require(len(self.received) <= MAX_STREAM, "TCP received stream bound")
        while len(self.pending) >= 2:
            length = int.from_bytes(self.pending[:2], "big")
            require(17 <= length <= MAX_DNS, "DNS TCP length bound")
            if len(self.pending) < length + 2:
                break
            query = bytes(self.pending[2:length + 2])
            del self.pending[:length + 2]
            at = len(self.tcp_queries)
            require(at < 2 and len(self.udp_queries) == at + 1, "unexpected TCP question count/order")
            name, kind = self.codec.question(query)
            require((name, kind) == QUESTIONS[at] and query == self.udp_queries[at],
                    "TCP question differs from its truncated UDP transaction")
            response = self.codec.answer(query)
            self.records.append({"transport": "TCP", "source": self.tcp["source"], "port": PORT,
                                 "name": name, "kind": kind, "query_hex": query.hex(),
                                 "answer_hex": response.hex(), **stamp()})
            self.tcp_queries.append(query)
            self.tcp_answers.append(response)
            self.output.extend(struct.pack("!H", len(response)) + response)
            require(len(self.sent) + len(self.output) <= MAX_STREAM, "TCP sent stream bound")

    def send(self):
        self.event_slot()
        requested = bytes(self.output)
        count = self.connection.send(requested)
        self.sent.extend(requested[:count])
        del self.output[:count]
        self.event("tcp-send", requested=len(requested), count=count, hex=requested[:count].hex())
        require(count > 0, "zero TCP send")

    def run(self, work):
        while self.stop_reason is None:
            require(time.monotonic() < self.deadline, "peer absolute deadline")
            if (work / "PEER-STOP").exists():
                self.stop_reason = "PEER-STOP"
                break
            readable = list(self.sockets)
            if self.connection is not None:
                readable.append(self.connection)
            read, write, _ = select.select(readable, [self.connection] if self.output else [], [],
                                            min(0.02, max(0, self.deadline - time.monotonic())))
            # Flush before accepting a concurrently observed EOF.
            if write:
                self.send()
            for sock in read:
                if sock in (self.udp, self.forbidden_udp):
                    self.datagram(sock)
                elif sock in (self.listener, self.forbidden_tcp):
                    self.accept(sock)
                elif sock is self.connection:
                    self.receive()
        require(len(self.udp_queries) == len(self.tcp_queries) == 2
                and self.tcp["connections"] == 1 and self.tcp["read_eof"]
                and self.tcp["write_shutdown"] and self.tcp["closed"], "peer stopped before complete exchange")

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
            self.tcp.update(closed=True, closed_observed=stamp())
        for sock in self.sockets:
            sock.close()

    def result(self):
        tcp = {**self.tcp, "received_hex": self.received.hex(), "sent_hex": self.sent.hex(),
               "received_sha256": hashlib.sha256(self.received).hexdigest(),
               "sent_sha256": hashlib.sha256(self.sent).hexdigest(),
               "received_frames": [q.hex() for q in self.tcp_queries],
               "sent_frames": [a.hex() for a in self.tcp_answers],
               "pending_hex": self.pending.hex(), "unsent_hex": self.output.hex()}
        return {"schema_version": 1, "pid": os.getpid(), "bind": BIND, "port": PORT,
                "forbidden_port": FORBIDDEN_PORT, "records": self.records, "io": self.io,
                "tcp": tcp, "errors": self.errors, "stop_reason": self.stop_reason,
                "disposition": "FAIL" if self.errors else "PASS", "codec_sha256": SOURCE_HASH,
                "limits": {"dns_bytes": MAX_DNS, "stream_bytes": MAX_STREAM, "io_events": MAX_EVENTS},
                "clock_scope": "Linux host monotonic and realtime only; neither is native guest time",
                "eof_scope": "Socket read EOF and successful local SHUT_WR; captured FINs are evaluated separately"}


def main():
    if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
        raise SystemExit("optimized Python refused")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path)
    parser.add_argument("--timeout", type=int, required=True)
    args = parser.parse_args()
    require(args.work.is_dir() and 1 <= args.timeout <= 180, "invalid work directory or timeout")
    require(not any((args.work / name).exists() for name in
                    ("PEER-READY.json", "PEER-RESULT.json", "PEER-STOP")), "stale peer output")
    with SOURCE.open("rb") as stream:
        data = stream.read((1 << 20) + 1)
    require(len(data) <= 1 << 20 and hashlib.sha256(data).hexdigest() == SOURCE_HASH, "DNS codec identity")
    codec = types.ModuleType("routed_tcp_linux_dns")
    codec.__file__ = str(SOURCE)
    exec(compile(data, str(SOURCE), "exec"), codec.__dict__)
    peer = Peer(codec, args.timeout)
    def stop(signum, _frame):
        peer.stop_reason = signal.Signals(signum).name
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        peer.open()
        write_json(args.work / "PEER-READY.json", {"schema_version": 1, "pid": os.getpid(),
                   "bind": BIND, "port": PORT, "forbidden_port": FORBIDDEN_PORT,
                   "udp_source": [GUEST, 7002], "tcp_source": [GUEST, 7003],
                   "transport": "Linux AF_INET6 SOCK_DGRAM + SOCK_STREAM", "codec_sha256": SOURCE_HASH})
        peer.run(args.work)
    except BaseException as error:
        peer.errors.append(repr(error))
    finally:
        peer.close()
        write_json(args.work / "PEER-RESULT.json", peer.result())
    if peer.errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
