#!/usr/bin/env python3
"""Private AF_INET6 Linux/OpenSSL fixture, with bounded full wire transcripts.

This extends only the first-party canonical fixture's listener and source
checks. Its TLS/HTTP implementation is the unchanged OpenSSL MemoryBIO path.
No Linux control connection is substituted for a native guest connection.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import ssl
import sys
import threading
import time

ROOT = Path(__file__).resolve().parent
CANONICAL_SHA = "9f82fc85874f61eb300ff635548cc80ad000803c8854e52b25acc2fb1635fbbd"
MAX_WIRE = 65536
if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
    raise SystemExit("optimized Python is refused")
assert hashlib.sha256((ROOT / "native-tls-matrix.py").read_bytes()).hexdigest() == CANONICAL_SHA
spec = importlib.util.spec_from_file_location("ipv6_tls_canonical", ROOT / "native-tls-matrix.py")
canonical = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canonical)


class Peer(canonical.Peer):
    def event(self, kind, **values):
        assert len(self.events) < 1024, "peer event bound"
        return super().event(kind, **values)

    def __init__(self, case, pki, timeout):
        self.case, self.pki, self.timeout = case, pki, timeout
        self.bind, self.native = "fd00:ab5d::2", True
        self.events, self.errors, self.sockets, self.threads, self.listeners = [], [], [], [], []
        self.stop, self.lock = threading.Event(), threading.Lock()
        self.accepts = self.guard_accepts = 0
        self.request = b""
        self.client_close_notify = self.server_close_notify = False
        self.authenticated = self.mutated = False
        self.received, self.sent = bytearray(), bytearray()
        self.deadline = time.monotonic() + timeout
        try:
            for role, port in (("tls", 4443), ("guard", 4444)):
                listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                listener.bind((self.bind, port, 0, 0))
                listener.listen(2)
                self.listeners.append((listener, role))
            self.port = 4443
            self.thread = threading.Thread(target=self.serve, name="ipv6-tls-listeners")
            self.thread.start()
        except BaseException:
            for listener, _ in self.listeners:
                listener.close()
            raise

    def serve(self):
        try:
            while not self.stop.is_set():
                if time.monotonic() >= self.deadline:
                    raise TimeoutError("original peer deadline")
                ready, _, _ = select.select([s for s, _ in self.listeners], [], [], 0.05)
                for listener in ready:
                    conn, source = listener.accept()
                    self.sockets.append(conn)
                    role = next(role for s, role in self.listeners if s == listener)
                    self.event("accept", role=role, source=list(source), local=list(conn.getsockname()))
                    if role == "guard":
                        self.guard_accepts += 1
                        conn.close()
                        continue
                    self.accepts += 1
                    assert source == ("fd00:ab5d::15", 7401, 0, 0), "unexpected native source"
                    assert self.accepts == 1, "repeated native connection"
                    worker = threading.Thread(target=self.connection, args=(conn,), name="ipv6-tls-connection")
                    self.threads.append(worker)
                    worker.start()
        except BaseException as error:
            self.errors.append(repr(error))

    def receive(self, conn, deadline):
        data = super().receive(conn, min(deadline, self.deadline))
        assert len(self.received) + len(data) <= MAX_WIRE, "received ciphertext bound"
        self.received.extend(data)
        return data

    def send(self, conn, data):
        # Preserve every successfully submitted fragment, including a prefix
        # before an uncertain later send; no retry of that failed call.
        at, index = 0, 0
        sizes = [1, 2, 5, 17, 1024]
        while at < len(data):
            assert not self.stop.is_set() and time.monotonic() < self.deadline
            part = data[at:at + sizes[index % len(sizes)]]
            assert len(self.sent) + len(part) <= MAX_WIRE, "sent ciphertext bound"
            conn.sendall(part)
            self.sent.extend(part)
            self.event("tcp-write", bytes=len(part), cumulative_bytes=len(self.sent),
                       sha256=hashlib.sha256(part).hexdigest())
            at += len(part)
            index += 1

    def report(self):
        result = super().report()
        result.update(transport="Linux AF_INET6 TCP / OpenSSL TLS1.3 / kernel ND",
                      received_hex=self.received.hex(), sent_hex=self.sent.hex(),
                      received_sha256=hashlib.sha256(self.received).hexdigest(),
                      sent_sha256=hashlib.sha256(self.sent).hexdigest())
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--case", choices=("P01", "P02", "L07"), required=True)
    parser.add_argument("--pki", type=Path, required=True)
    parser.add_argument("--timeout", type=int, required=True)
    args = parser.parse_args()
    assert 30 <= args.timeout <= 120
    pki = json.loads(args.pki.read_bytes())
    cases = json.loads((ROOT / "native-tls-cases.json").read_bytes())["native_occurrences"]
    case = next(c for c in cases if c["id"] == args.case)
    peer = Peer(case, pki, args.timeout)
    try:
        canonical.seal(args.work / "PEER-READY.json", {
            "case": args.case, "family": "AF_INET6", "pid": os.getpid(),
            "listeners": [list(s.getsockname()) for s, _ in peer.listeners],
            "v6only": [s.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) for s, _ in peer.listeners],
            "openssl": ssl.OPENSSL_VERSION, "canonical_sha256": CANONICAL_SHA})
        while not (args.work / "PEER-STOP").exists():
            assert time.monotonic() < peer.deadline, "peer original deadline"
            assert peer.thread.is_alive(), "listener worker ended"
            time.sleep(0.02)
    finally:
        peer.close()
        result = peer.report()
        result["disposition"] = "FAIL" if peer.errors else "PASS"
        canonical.seal(args.work / "PEER-RESULT.json", result)
    raise SystemExit(0 if result["disposition"] == "PASS" else 1)


if __name__ == "__main__":
    main()
