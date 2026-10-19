#!/usr/bin/env python3
"""Exercise the actual peer over Linux loopback sockets in the disposable VM."""
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
import types
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("routed_tcp_peer", HERE / "native-ipv6-routed-tcp-peer.py")
peer_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer_module)
codec_bytes = (HERE / "native-ipv6-peer.py").read_bytes()
if hashlib.sha256(codec_bytes).hexdigest() != peer_module.SOURCE_HASH:
    raise SystemExit("codec identity")
codec = types.ModuleType("routed_tcp_test_codec")
exec(compile(codec_bytes, str(HERE / "native-ipv6-peer.py"), "exec"), codec.__dict__)


def query(kind, ident):
    label = b"a" if kind == 1 else b"aaaa"
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + bytes([len(label)]) + label + b"\x07example\0" + struct.pack("!HH", kind, 1)


def free_port():
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
        sock.bind(("::1", 0))
        return sock.getsockname()[1]


class PeerTests(unittest.TestCase):
    def setUp(self):
        # Only this isolated loopback fixture changes these module constants.
        # The product entry point always binds the routed fixed tuple.
        peer_module.BIND = peer_module.GUEST = "::1"
        peer_module.PORT = free_port()
        peer_module.FORBIDDEN_PORT = free_port()
        self.assertNotEqual(peer_module.PORT, peer_module.FORBIDDEN_PORT)
        self.directory = tempfile.TemporaryDirectory(prefix="routed-tcp-peer-control-")
        self.work = Path(self.directory.name)
        self.peer = peer_module.Peer(codec, 4)
        self.peer.open()
        self.clients = []
        def serve():
            try:
                self.peer.run(self.work)
            except BaseException as error:
                self.peer.errors.append(repr(error))
            finally:
                self.peer.close()
                peer_module.write_json(self.work / "PEER-RESULT.json", self.peer.result())
        self.thread = threading.Thread(target=serve, name="actual-routed-dns-peer-control")
        self.thread.start()

    def tearDown(self):
        for sock in self.clients:
            sock.close()
        self.peer.stop_reason = self.peer.stop_reason or "test-cleanup"
        self.thread.join(1)
        self.assertFalse(self.thread.is_alive(), "control thread survived cleanup")
        self.directory.cleanup()

    def client(self, transport, source_port):
        sock = socket.socket(socket.AF_INET6, transport)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1)
        self.clients.append(sock)
        sock.bind(("::1", source_port))
        return sock

    def udp(self, question=None):
        sock = self.client(socket.SOCK_DGRAM, 7002)
        if question is not None:
            self.truncate(sock, question)
        return sock

    def truncate(self, sock, question):
        sock.sendto(question, ("::1", peer_module.PORT))
        answer, source = sock.recvfrom(1233)
        self.assertEqual(source[:2], ("::1", peer_module.PORT))
        self.assertEqual(answer, question[:2] + struct.pack("!HHHHH", 0x8380, 1, 0, 0, 0) + question[12:])

    def tcp(self, source_port=7003, port=None):
        sock = self.client(socket.SOCK_STREAM, source_port)
        sock.connect(("::1", peer_module.PORT if port is None else port))
        return sock

    def failed(self, message):
        self.thread.join(1)
        self.assertFalse(self.thread.is_alive())
        result = json.loads((self.work / "PEER-RESULT.json").read_bytes())
        self.assertEqual(result["disposition"], "FAIL")
        self.assertTrue(any(message in error for error in result["errors"]), result["errors"])
        return result

    def wait_received(self, count):
        until = time.monotonic() + 1
        while len(self.peer.received) < count and self.thread.is_alive() and time.monotonic() < until:
            time.sleep(0.001)
        self.assertEqual(len(self.peer.received), count)

    def exact(self, sock, length):
        output = bytearray()
        while len(output) < length:
            chunk = sock.recv(length - len(output))
            self.assertTrue(chunk)
            output.extend(chunk)
        return bytes(output)

    def test_two_questions_one_stream_partial_framing_and_raw_byte_custody(self):
        questions = [query(1, 0x1234), query(28, 0x5678)]
        udp = self.udp(questions[0])
        tcp = self.tcp()
        offset = 0
        for at, question in enumerate(questions):
            if at:
                self.truncate(udp, question)
            frame = struct.pack("!H", len(question)) + question
            # Wait for actual reads at both partial-frame boundaries.
            tcp.sendall(frame[:1])
            self.wait_received(offset + 1)
            tcp.sendall(frame[1:6])
            self.wait_received(offset + 6)
            tcp.sendall(frame[6:])
            offset += len(frame)
            length = int.from_bytes(self.exact(tcp, 2), "big")
            self.assertEqual(self.exact(tcp, length), codec.answer(question))
        tcp.shutdown(socket.SHUT_WR)
        self.assertEqual(tcp.recv(1), b"")
        (self.work / "PEER-STOP").write_bytes(b"")
        self.thread.join(1)
        self.assertFalse(self.thread.is_alive())
        result = json.loads((self.work / "PEER-RESULT.json").read_bytes())
        self.assertEqual(result["disposition"], "PASS", result["errors"])
        self.assertEqual([r["transport"] for r in result["records"]], ["UDP", "TCP", "UDP", "TCP"])
        for direction, stream_key in (("tcp-recv", "received"), ("tcp-send", "sent")):
            actual = b"".join(bytes.fromhex(r["hex"]) for r in result["io"] if r["event"] == direction)
            self.assertEqual(actual.hex(), result["tcp"][stream_key + "_hex"])
            self.assertEqual(hashlib.sha256(actual).hexdigest(), result["tcp"][stream_key + "_sha256"])
        self.assertEqual(result["tcp"]["received_frames"], [q.hex() for q in questions])
        self.assertEqual(result["tcp"]["sent_frames"], [codec.answer(q).hex() for q in questions])
        self.assertTrue(all(result["tcp"][key] for key in ("read_eof", "write_shutdown", "closed")))
        self.assertEqual(result["tcp"]["connections"], 1)
        self.assertEqual(result["tcp"]["pending_hex"], result["tcp"]["unsent_hex"])
        self.assertEqual(result["tcp"]["pending_hex"], "")

    def test_udp_wrong_source_refused_and_bytes_retained(self):
        sock = self.client(socket.SOCK_DGRAM, 7004)
        q = query(1, 7)
        sock.sendto(q, ("::1", peer_module.PORT))
        self.assertEqual(self.failed("unexpected source tuple")["io"][0]["hex"], q.hex())

    def test_udp_forbidden_destination_refused(self):
        sock = self.udp()
        sock.sendto(query(1, 7), ("::1", peer_module.FORBIDDEN_PORT))
        self.failed("ungranted UDP destination")

    def test_udp_malformed_question_refused(self):
        sock = self.udp()
        sock.sendto(b"invalid", ("::1", peer_module.PORT))
        self.failed("query header")

    def test_udp_oversize_refused(self):
        sock = self.udp()
        sock.sendto(b"x" * 1233, ("::1", peer_module.PORT))
        self.failed("oversize UDP query")

    def test_duplicate_udp_before_tcp_refused(self):
        q = query(1, 7)
        sock = self.udp(q)
        sock.sendto(q, ("::1", peer_module.PORT))
        self.failed("UDP query count/order")

    def test_tcp_wrong_source_refused(self):
        self.udp(query(1, 7))
        self.tcp(source_port=7004)
        self.failed("unexpected source tuple")

    def test_tcp_forbidden_destination_refused(self):
        self.udp(query(1, 7))
        self.tcp(port=peer_module.FORBIDDEN_PORT)
        self.failed("ungranted TCP destination")

    def test_tcp_invalid_frame_length_refused(self):
        self.udp(query(1, 7))
        self.tcp().sendall(b"\0\0")
        self.failed("DNS TCP length bound")

    def test_tcp_substituted_transaction_refused(self):
        self.udp(query(1, 7))
        replacement = query(1, 8)
        self.tcp().sendall(struct.pack("!H", len(replacement)) + replacement)
        self.failed("differs from its truncated UDP transaction")

    def test_tcp_premature_eof_refused(self):
        self.udp(query(1, 7))
        self.tcp().shutdown(socket.SHUT_WR)
        self.failed("EOF before both complete answers")

    def test_interrupted_incomplete_exchange_fails_closed(self):
        self.peer.stop_reason = "SIGTERM"
        self.failed("stopped before complete exchange")


class EventBudgetTests(unittest.TestCase):
    def setUp(self):
        peer_module.BIND = peer_module.GUEST = "::1"
        self.peer = peer_module.Peer(codec, 4)
        # Deterministic exhausted diagnostic census. Real sockets below test
        # whether the next operation consumes or emits bytes before refusal.
        for _ in range(peer_module.MAX_EVENTS):
            self.peer.event("control-budget-entry")
        self.sockets = []

    def tearDown(self):
        self.peer.close()
        for sock in self.sockets:
            sock.close()

    def connected(self):
        listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.sockets.append(listener)
        listener.bind(("::1", 0))
        listener.listen(1)
        client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.sockets.append(client)
        client.settimeout(0.1)
        client.connect(listener.getsockname())
        server, _ = listener.accept()
        server.settimeout(0.1)
        self.peer.connection = server
        return client, server

    def test_exhausted_receive_leaves_actual_tcp_bytes_queued(self):
        client, server = self.connected()
        client.sendall(b"queued-byte")
        with self.assertRaisesRegex(ValueError, "I/O event census exceeded"):
            self.peer.receive()
        self.assertEqual(server.recv(64), b"queued-byte")
        self.assertEqual(self.peer.received, b"")
        self.assertEqual(self.peer.pending, b"")
        self.assertEqual(len(self.peer.io), peer_module.MAX_EVENTS)

    def test_exhausted_send_emits_no_actual_tcp_bytes(self):
        client, _ = self.connected()
        self.peer.output.extend(b"unsent-answer")
        with self.assertRaisesRegex(ValueError, "I/O event census exceeded"):
            self.peer.send()
        with self.assertRaises(socket.timeout):
            client.recv(64)
        self.assertEqual(self.peer.output, b"unsent-answer")
        self.assertEqual(self.peer.sent, b"")
        self.assertEqual(len(self.peer.io), peer_module.MAX_EVENTS)

    def test_exhausted_receive_leaves_actual_udp_datagram_queued(self):
        server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        client = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.sockets.extend((server, client))
        server.bind(("::1", 0))
        server.settimeout(0.1)
        self.peer.udp = server
        client.sendto(b"queued-datagram", server.getsockname())
        with self.assertRaisesRegex(ValueError, "I/O event census exceeded"):
            self.peer.datagram(server)
        self.assertEqual(server.recvfrom(64)[0], b"queued-datagram")
        self.assertEqual(self.peer.records, [])
        self.assertEqual(len(self.peer.io), peer_module.MAX_EVENTS)


if __name__ == "__main__":
    unittest.main()
