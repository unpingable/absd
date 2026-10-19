#!/usr/bin/env python3
"""Finite routed HTTPS artifact controls. Synthetic bytes are not TLS runs.

Run only on the admitted Linux test VM. No cryptographic/native positive is
claimed by these data fixtures; the three actual cases remain separate.
"""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("routed_tls_controls", Path(__file__).with_name("native-tls-ipv6-routed-matrix.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def serial(case="P01", **changes):
    common = {"outcome": "SUCCESS", "phase": "FENCED", "start_ms": "1200", "end_ms": "1800",
              "deadline_ms": "11200", "grant_expiry_ms": "16100", "http_emitted": str(len(m.REQUEST)), "preauth_http_emitted": "0",
              "http_body": "2048", "authenticated": "true", "peer_closed": "true", "local_close_drained": "true",
              "native_close_accepted": "true", "protocol_version": 'Some("TLSv1_3")', "cleanup_error": "None",
              "native_error": "None", "pipe_fenced": "true", "connect_calls": "1"}
    if case == "P02":
        common.update(outcome="CERTIFICATE", tls_error_code='Some("UNKNOWN_ISSUER")', http_emitted="0", http_body="0", authenticated="false", write_accepted="269")
    if case == "L07":
        common = {"outcome": "NATIVE", "phase": "INIT", "native_error": "Denied", "actor": "authority-control",
                  "denied_connect_requests": "1", "http_emitted": "0", "preauth_http_emitted": "0", "http_body": "0", "end_ms": "1300"}
    common.update(changes)
    denial = ""
    if case == "L07":
        header = bytes([2, 16, 2, 6]) + m.HOST + struct.pack("!IH", 1, 4443) + bytes(2)
        denial = "TLS DENIAL reply_bytes=28 header=" + str(list(header)) + "\n"
    text = ("TLS IPV6 RX SETUP nic_ready_ms=0 ready_ms=1100 continuous_vm_required=1\n"
            "TLS IPV6 ROUTE READY local=fd00:ab5d:1::15/64 router=fd00:ab5d:1::2 peer=fd00:ab5d:2::9 scope=1 port=4443 path_mtu=1500 no_route_denied=1\n"
            "TLS IPV6 RESOURCES label=before processes=2 handles=13 pipes=2 cells=1 frames=200\n"
            f"TLS IPV6 SERVICE READY case={case} issued_ms=1100 expiry_ms=16100 invocation_deadline_ms=20000 local_port=7401 scope=1 peer_port=4443\n"
            "TLS IPV6 CLIENT AUTHORITY nic=0 block=false input=2 output=3\n"
            "TLS CPU vendor=GenuineIntel family=6 model=60 leaf1_eax=198336 leaf1_ecx=1073741824 rdrand=1\n"
            f"TLS IPV6 BEGIN case={case} start_ms=1200 grant_expiry_ms=16100 deadline_ms=11200 unix_time=Some(1792209064) expected_body=2048\n"
            + denial + f"TLS RESULT case={case} " + " ".join(k + "=" + v for k, v in common.items()) + "\n"
            f"TLS IPV6 CHILD DONE case={case} kind=1 status=0\n"
            "TLS IPV6 RESOURCES label=after processes=2 handles=13 pipes=2 cells=1 frames=202\n"
            f"TLS IPV6 SERVICE DONE case={case} sockets=0 rx_missed_before=0 rx_missed_after=0 at_ms=1900\n")
    raw = (b"\nABSD BOOT OK\nNETWORK LINK OK rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048\n"
           b"EXTERNAL OUTPUT CHUNK offset=0000000000000000 data=" + text.encode().hex().encode() + b"\n"
           b"NIC STATS rx_frames=5 tx_frames=5 rx_refused=0 rx_missed=0 tx_refused=0 tx_errors=0 flags=1\n"
           b"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ticks=2001\nDURABLE WORKLOAD OK\n")
    return raw

def hello():
    name = b"absd-fixture.test"
    exts = {0: struct.pack("!H", len(name) + 3) + b"\0" + struct.pack("!H", len(name)) + name,
            16: b"\0\x09\x08http/1.1", 43: b"\x02\x03\x04"}
    extensions = b"".join(struct.pack("!HH", kind, len(value)) + value for kind, value in exts.items())
    body = b"\x03\x03" + bytes(32) + b"\0\0\x02\x13\x01\x01\0" + struct.pack("!H", len(extensions)) + extensions
    message = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(message).to_bytes(2, "big") + message

def ip_frame(source, dest, sm, dm, protocol, payload, hop=64):
    pseudo = source + dest + struct.pack("!I3xB", len(payload), protocol)
    payload = bytearray(payload)
    offset = 2 if protocol == 58 else 16 if protocol == 6 else 6
    payload[offset:offset + 2] = struct.pack("!H", m.original.checksum(pseudo + payload))
    ip = b"\x60\0\0\0" + struct.pack("!HBB", len(payload), protocol, hop) + source + dest + payload
    return dm + sm + b"\x86\xdd" + ip

def packet(direction, seq, ack, flags, body=b"", options=b""):
    source, dest, sm, dm, sport, dport = (m.GUEST, m.HOST, m.GM, m.HM, 7401, 4443) if direction == "outgoing" else (m.HOST, m.GUEST, m.HM, m.GM, 4443, 7401)
    segment = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, (5 + len(options) // 4) << 4, flags, 1024, 0, 0) + options + body
    return ip_frame(source, dest, sm, dm, 6, segment, 64 if direction == "outgoing" else 63)

def pcap(frames):
    data = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    for i, frame in enumerate(frames):
        data += struct.pack("<IIII", 1, i, len(frame), len(frame)) + frame
    return data

def nd(link):
    if link == "guest":
        a, b, am, bm = m.GUEST, m.ROUTER, m.GUEST_MAC, m.ROUTER_MAC
        flags = bytes.fromhex("e0000000")
    else:
        a, b, am, bm = m.UPLINK_LL, m.PEER, m.UPLINK_MAC, m.PEER_MAC
        flags = bytes.fromhex("60000000")
    ns = bytes([135, 0, 0, 0]) + bytes(4) + b + b"\x01\x01" + am
    na = bytes([136, 0, 0, 0]) + flags + b + b"\x02\x01" + bm
    return [ip_frame(a, m.original.solicited(b), am, b"\x33\x33\xff" + b[-3:], 58, ns, 255),
            ip_frame(b, a, bm, am, 58, na, 255)]


def peer_leg(data):
    records, complete = m.original.capture_records(data)
    assert complete == len(data)
    frames = []
    for row in records:
        frame = bytearray(row["frame"])
        if len(frame) >= 54 and frame[12:14] == b"\x86\xdd" and frame[20] == 6:
            outgoing = frame[22:38] == m.GUEST
            frame[:6] = m.PEER_MAC if outgoing else m.UPLINK_MAC
            frame[6:12] = m.UPLINK_MAC if outgoing else m.PEER_MAC
            frame[21] = frame[21] - 1 if outgoing else frame[21] + 1
            frames.append(bytes(frame))
    return pcap((nd("peer") if frames else []) + frames)


def inspect(data, case, peer):
    return m.inspect_captures(data, peer_leg(data), case, peer)["guest"]


def fixture():
    guest = hello()
    # Opaque TLS-record bytes exercise TCP/peer correspondence only. They
    # are explicitly not an OpenSSL or certificate-verification positive.
    host = b"\x16\x03\x03\0\x01\x02"
    frames = nd("guest") + [
              packet("outgoing", 100, 0, 2, options=b"\x02\x04\x05\xa0"),
              packet("incoming", 300, 101, 18), packet("outgoing", 101, 301, 16),
              packet("outgoing", 101, 301, 24, guest), packet("incoming", 301, 101 + len(guest), 24, host),
              packet("outgoing", 101 + len(guest), 301 + len(host), 17),
              packet("incoming", 301 + len(host), 102 + len(guest), 17),
              packet("outgoing", 102 + len(guest), 302 + len(host), 16)]
    case = next(c for c in json.loads((m.ROOT / "scripts/native-tls-cases.json").read_bytes())["native_occurrences"] if c["id"] == "P01")
    request = b"GET /native-network HTTP/1.1\r\nHost: absd-fixture.test:4443\r\nConnection: close\r\n\r\n"
    response = m.tls.response(case)
    peer = {"case": case, "disposition": "PASS", "errors": [], "accepts": 1, "guard_accepts": 0,
            "transport": "Linux routed AF_INET6 TCP / OpenSSL TLS1.3 / kernel ND", "received_hex": guest.hex(), "sent_hex": host.hex(),
            "received_sha256": m.digest(guest)["sha256"], "sent_sha256": m.digest(host)["sha256"],
            "request_bytes": len(request), "request_sha256": m.digest(request)["sha256"], "server_handshake_complete": True,
            "client_close_notify_received": True, "server_close_notify_drained": True,
            "events": [{"event": "tls-handshake-complete", "version": "TLSv1.3", "alpn": "http/1.1", "session_reused": False},
                       {"event": "http-response", **m.digest(response)}]}
    return frames, peer

def failure_fixture(guest_bytes):
    frames, peer = fixture()
    padding = guest_bytes - len(hello()) - 5
    assert padding >= 0
    # A well-formed opaque record preserves all existing capture/stream
    # predicates while crossing only the pre-auth output budget.
    guest = hello() + b"\x17\x03\x03" + struct.pack("!H", padding) + bytes(padding)
    host = bytes.fromhex(peer["sent_hex"])
    frames[5] = packet("outgoing", 101, 301, 24, guest)
    frames[6] = packet("incoming", 301, 101 + len(guest), 24, host)
    del frames[7:]
    peer.update(case={"id": "P02"}, request_bytes=0, server_handshake_complete=False,
                received_hex=guest.hex(), received_sha256=m.digest(guest)["sha256"],
                events=[{"event": "connection-ended"}])
    return frames, peer

class Controls(unittest.TestCase):
    def test_three_typed_profiles(self):
        for case in ("P01", "P02", "L07"):
            self.assertEqual(m.native_output(serial(case), 3, case, 1792209064)["case"], case)

    def test_service_done_alone_refused(self):
        raw = serial().replace(b"EXTERNAL OUTPUT CHUNK", b"IGNORED OUTPUT CHUNK")
        with self.assertRaises(AssertionError): m.native_output(raw, 3, "P01", 1792209064)

    def test_wrong_tls_outcome_refused(self):
        with self.assertRaises(AssertionError): m.native_output(serial(outcome="TLS"), 3, "P01", 1792209064)

    def test_pre_auth_http_refused(self):
        with self.assertRaises(AssertionError): m.native_output(serial("P02", http_emitted="1"), 3, "P02", 1792209064)

    def test_p02_native_accepted_write_budget(self):
        self.assertEqual(m.native_output(serial("P02", write_accepted="1024"), 3, "P02", 1792209064)["case"], "P02")
        with self.assertRaisesRegex(AssertionError, "pre-auth accepted writes exceed 1024 bytes"):
            m.native_output(serial("P02", write_accepted="1025"), 3, "P02", 1792209064)

    def test_p02_full_wire_output_budget(self):
        frames, peer = failure_fixture(1024)
        self.assertEqual(inspect(pcap(frames), "P02", peer)["guest_stream"]["bytes"], 1024)
        frames, peer = failure_fixture(1025)
        with self.assertRaisesRegex(AssertionError, "pre-auth guest stream exceeds 1024 bytes"):
            inspect(pcap(frames), "P02", peer)

    def test_missing_positive_close_refused(self):
        with self.assertRaises(AssertionError): m.native_output(serial(peer_closed="false"), 3, "P01", 1792209064)

    def test_repeated_connect_refused(self):
        with self.assertRaises(AssertionError): m.native_output(serial(connect_calls="2"), 3, "P01", 1792209064)

    def test_wrong_public_time_refused(self):
        with self.assertRaises(AssertionError): m.native_output(serial(), 3, "P01", 1792209065)

    def test_native_status_and_durable_residue_refused(self):
        for raw, code in ((serial(), 7), (serial().replace(b"cells=0 pipes=0 ticks", b"cells=1 pipes=0 ticks"), 3),
                          (serial().replace(b"flags=1\n", b"flags=0\n"), 3), (serial().replace(b"flags=1\n", b"flags=3\n"), 3)):
            with self.assertRaises(AssertionError): m.native_output(raw, code, "P01", 1792209064)

    def test_late_report_and_clock_unit_refused(self):
        with self.assertRaises(AssertionError): m.native_output(serial(end_ms="11200"), 3, "P01", 1792209064)
        # Raw ticks1900 would exceed done_ms1899, but converted boot_ms1899
        # must not be treated as1900. Actual constructor done_ms1900 is late.
        with self.assertRaises(AssertionError): m.native_output(serial().replace(b"ticks=2001", b"ticks=1900"), 3, "P01", 1792209064)

    def test_duplicate_terminal_or_chunk_refused(self):
        for extra in (b"DURABLE status=0\n", b"EXTERNAL OUTPUT CHUNK invalid\n"):
            with self.assertRaises(AssertionError): m.native_output(serial() + extra, 3, "P01", 1792209064)

    def test_positive_complete_packet_and_stream_fixture(self):
        frames, peer = fixture()
        self.assertEqual(inspect(pcap(frames), "P01", peer)["tcp_frames"], 8)

    def test_checksum_or_frame_length_refused(self):
        for change in (lambda f: f[:-1] + bytes([f[-1] ^ 1]), lambda f: f + b"\0"):
            frames, peer = fixture(); frames[5] = change(frames[5])
            with self.assertRaises(AssertionError): inspect(pcap(frames), "P01", peer)

    def test_wrong_tuple_or_unknown_frame_refused(self):
        frames, peer = fixture(); segment = bytearray(frames[5][54:]); segment[:2] = struct.pack("!H", 7402); segment[16:18] = bytes(2)
        frames[5] = ip_frame(m.GUEST, m.HOST, m.GM, m.HM, 6, segment)
        with self.assertRaises(AssertionError): inspect(pcap(frames), "P01", peer)
        frames, peer = fixture(); frames.append(b"\xff" * 60)
        with self.assertRaises(AssertionError): inspect(pcap(frames), "P01", peer)

    def test_wrong_mss_with_valid_checksum_refused(self):
        frames, peer = fixture(); frames[2] = packet("outgoing", 100, 0, 2, options=b"\x02\x04\x05\xb4")
        with self.assertRaises(AssertionError): inspect(pcap(frames), "P01", peer)

    def test_nd_hop_and_order_refused(self):
        frames, peer = fixture(); frame = bytearray(frames[1]); frame[21] = 64; frames[1] = bytes(frame)
        with self.assertRaises(AssertionError): inspect(pcap(frames), "P01", peer)
        frames, peer = fixture(); frames[1], frames[2] = frames[2], frames[1]
        with self.assertRaises(AssertionError): inspect(pcap(frames), "P01", peer)

    def test_gap_or_conflicting_overlap_refused(self):
        frames, peer = fixture(); frames[5] = packet("outgoing", 102, 301, 24, hello())
        with self.assertRaises(AssertionError): inspect(pcap(frames), "P01", peer)
        frames, peer = fixture(); frames.insert(6, packet("outgoing", 101, 301, 24, b"X"))
        with self.assertRaises(AssertionError): inspect(pcap(frames), "P01", peer)

    def test_peer_stream_content_mutation_refused(self):
        frames, peer = fixture(); peer["received_hex"] += "00"
        with self.assertRaises(AssertionError): inspect(pcap(frames), "P01", peer)

    def test_wrong_sni_or_tls_version_refused(self):
        for data in (hello().replace(b"absd-fixture.test", b"xxxx-fixture.test"), hello().replace(b"\x16\x03\x01", b"\x16\x03\x04", 1)):
            with self.assertRaises(AssertionError): m.client_hello(data)

    def test_missing_fin_ack_or_close_event_refused(self):
        frames, peer = fixture(); frames.pop()
        with self.assertRaises(AssertionError): inspect(pcap(frames), "P01", peer)
        frames, peer = fixture(); peer["client_close_notify_received"] = False
        with self.assertRaises(AssertionError): inspect(pcap(frames), "P01", peer)

    def test_guard_or_repeated_peer_accept_refused(self):
        for key in ("guard_accepts", "accepts"):
            frames, peer = fixture(); peer[key] += 1
            with self.assertRaises(AssertionError): inspect(pcap(frames), "P01", peer)

    def test_l07_silent_peer_positive_and_tcp_refusal(self):
        peer = {"case": {"id": "L07"}, "disposition": "PASS", "errors": [], "guard_accepts": 0, "accepts": 0,
                "request_bytes": 0, "received_hex": "", "sent_hex": "", "transport": "Linux routed AF_INET6 TCP / OpenSSL TLS1.3 / kernel ND"}
        self.assertTrue(inspect(pcap([]), "L07", peer)["authority_denial"])
        with self.assertRaises(AssertionError): inspect(pcap([packet("outgoing", 1, 0, 2)]), "L07", peer)

    def test_cleanup_fact_mutation_refused(self):
        with tempfile.TemporaryDirectory() as root:
            work = Path(root); data = m.write(work / "LOCAL-CLEANUP.json", {"disposition": "PASS", "errors": []})
            evaluated = {"LOCAL-CLEANUP.json": m.digest(data)}
            self.assertIn("LOCAL-CLEANUP.json", m.seal_artifacts(work, evaluated))
            (work / "LOCAL-CLEANUP.json").write_text('{"disposition":"FAIL","errors":["changed"]}')
            with self.assertRaises(AssertionError): m.seal_artifacts(work, evaluated)

    def test_namespace_identity_checked_after_pid_query(self):
        calls = []
        def command(argv):
            calls.append(argv)
            return "owned\n" if argv[-1] == "list" else ""
        with mock.patch.object(m, "namespace_identity", side_effect=[{"inode": 1}, {"inode": 2}]):
            with self.assertRaises(AssertionError): m.retire_namespace("owned", {"inode": 1}, command)
        self.assertFalse(any("del" in c for c in calls))

    def test_unknown_namespace_is_retained(self):
        with self.assertRaises(AssertionError): m.retire_namespace("owned", None, lambda _: "owned\n")

    def test_namespace_absence_needs_no_delete(self):
        calls = []
        self.assertTrue(m.retire_namespace("owned", None, lambda argv: calls.append(argv) or ""))
        self.assertEqual(calls, [["ip", "netns", "list"]])

    def test_artifact_symlink_refused(self):
        with tempfile.TemporaryDirectory() as root:
            work = Path(root); (work / "alias").symlink_to("missing")
            with self.assertRaises(AssertionError): m.seal_artifacts(work, {})

    def test_leader_exit_does_not_hide_owned_process_group(self):
        process = mock.Mock(pid=123)
        process.poll.return_value = 0
        with mock.patch.object(m, "group_live", side_effect=[True, False, False, False]), mock.patch.object(m.os, "killpg") as kill:
            observed = m.stop_owned(process)
        kill.assert_called_once_with(123, m.signal.SIGTERM)
        self.assertTrue(observed["forced"])
        self.assertTrue(observed["group_absent"])

    def test_elf_load_extent_and_machine(self):
        data = bytearray(128)
        data[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<H", data, 18, 62)
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<HH", data, 54, 56, 1)
        struct.pack_into("<IIQQQQQQ", data, 64, 1, 0, 0, 0, 0, len(data), len(data), 0)
        m.elf(data)
        wrong_machine = bytearray(data); struct.pack_into("<H", wrong_machine, 18, 3)
        with self.assertRaises(AssertionError): m.elf(wrong_machine)
        struct.pack_into("<Q", data, 64 + 32, len(data) + 1)
        with self.assertRaises(AssertionError): m.elf(data)

    def test_actual_iso_file_extent_correspondence(self):
        # Minimal critical-directory fixture, not a claim of GRUB bootability.
        def record(name, sector, size, directory=False):
            n = len(name); result = bytearray(33 + n + (n % 2 == 0))
            result[0] = len(result)
            struct.pack_into("<I", result, 2, sector); struct.pack_into(">I", result, 6, sector)
            struct.pack_into("<I", result, 10, size); struct.pack_into(">I", result, 14, size)
            result[25] = 2 if directory else 0
            result[32] = n; result[33:33 + n] = name
            return result
        image = bytearray(24 * 2048); kernel = b"unique-kernel-ELF-fixture"
        pvd = bytearray(2048); pvd[:7] = b"\x01CD001\x01"
        struct.pack_into("<H", pvd, 128, 2048); struct.pack_into(">H", pvd, 130, 2048)
        root = record(b"\0", 19, 2048, True); pvd[156:156 + len(root)] = root
        image[16 * 2048:17 * 2048] = pvd
        root_body = record(b"BOOT", 20, 2048, True); image[19 * 2048:19 * 2048 + len(root_body)] = root_body
        boot = record(b"ABSD-KERNEL", 22, len(kernel)) + record(b"GRUB", 21, 2048, True)
        image[20 * 2048:20 * 2048 + len(boot)] = boot
        grub = record(b"GRUB.CFG", 23, len(m.BOOT)); image[21 * 2048:21 * 2048 + len(grub)] = grub
        image[22 * 2048:22 * 2048 + len(kernel)] = kernel
        image[23 * 2048:23 * 2048 + len(m.BOOT)] = m.BOOT
        self.assertEqual(m.iso_binding(image, kernel)["kernel"], m.digest(kernel))
        image[23 * 2048] ^= 1
        with self.assertRaises(AssertionError): m.iso_binding(image, kernel)

class RoutedControls(unittest.TestCase):
    def test_checksum_valid_guest_mld_is_unexplained_while_linux_mld_is_allowed(self):
        source, destination = bytes(16), bytes.fromhex("ff020000000000000000000000000016")
        hbh = bytes.fromhex("3a00050200000100")
        payload = bytearray(bytes.fromhex("8f00000000000001") + bytes.fromhex("04000000")
                            + bytes.fromhex("ff020000000000000000000000000002"))
        pseudo = source + destination + struct.pack("!I3xB", len(payload), 58)
        payload[2:4] = struct.pack("!H", m.original.checksum(pseudo + payload))
        self.assertTrue(m.original.valid_mld(payload, hbh, source, destination,
                                          bytes.fromhex("333300000016"), 1))
        ip = b"\x60\0\0\0" + struct.pack("!HBB", len(hbh) + len(payload), 0, 1) + source + destination + hbh + payload
        for link, sm, allowed in [("guest", m.GUEST_MAC, False), ("guest", m.ROUTER_MAC, True),
                                  ("peer", m.UPLINK_MAC, True), ("peer", m.PEER_MAC, True)]:
            frame = bytes.fromhex("333300000016") + sm + b"\x86\xdd" + ip
            records, _ = m.original.capture_records(pcap([frame]))
            self.assertEqual(m.classify(records[0], link)["kind"], "linux-mldv2" if allowed else "unexplained")
        frames, peer = fixture()
        guest_mld = bytes.fromhex("333300000016") + m.GUEST_MAC + b"\x86\xdd" + ip
        with self.assertRaises(AssertionError):
            inspect(pcap(frames + [guest_mld]), "P01", peer)

    def test_two_complete_links_and_exact_hop_counterparts(self):
        frames, peer = fixture()
        data = pcap(frames)
        value = m.inspect_captures(data, peer_leg(data), "P01", peer)
        self.assertEqual(value["guest"]["guest_stream"], value["peer"]["guest_stream"])

    def test_missing_peer_packet_is_refused(self):
        frames, peer = fixture()
        data = pcap(frames)
        rows, _ = m.original.capture_records(peer_leg(data))
        changed = [r["frame"] for r in rows]
        del changed[5]
        with self.assertRaises(AssertionError):
            m.inspect_captures(data, pcap(changed), "P01", peer)

    def test_valid_checksum_wrong_routed_hop_is_refused(self):
        frames, peer = fixture()
        data = pcap(frames)
        rows, _ = m.original.capture_records(peer_leg(data))
        changed = [r["frame"] for r in rows]
        value = bytearray(changed[5]); value[21] += 1; changed[5] = bytes(value)
        with self.assertRaises(AssertionError):
            m.inspect_captures(data, pcap(changed), "P01", peer)

    def test_partial_capture_suffix_is_refused_on_either_leg(self):
        frames, peer = fixture(); data = pcap(frames); other = peer_leg(data)
        for guest, linux in [(data + b"x", other), (data, other + b"x")]:
            with self.assertRaises(AssertionError):
                m.inspect_captures(guest, linux, "P01", peer)

    def test_udp_cannot_be_reclassified_as_https(self):
        segment = struct.pack("!HHHH", 7401, 4443, 9, 0) + b"x"
        frame = ip_frame(m.GUEST, m.HOST, m.GM, m.HM, 17, segment)
        records, _ = m.original.capture_records(pcap([frame]))
        self.assertEqual(m.classify(records[0], "guest")["kind"], "unexplained")

    def test_direct_peer_nd_cannot_replace_router_nd(self):
        frames, peer = fixture()
        ns = bytes([135, 0, 0, 0]) + bytes(4) + m.PEER + b"\x01\x01" + m.GUEST_MAC
        frames[0] = ip_frame(m.GUEST, m.original.solicited(m.PEER), m.GUEST_MAC,
                             b"\x33\x33\xff" + m.PEER[-3:], 58, ns, 255)
        with self.assertRaises(AssertionError):
            inspect(pcap(frames), "P01", peer)

    def test_missing_explicit_route_or_wrong_router_report_is_refused(self):
        for a, b in [("TLS IPV6 ROUTE READY", "IGNORED ROUTE READY"),
                     ("router=fd00:ab5d:1::2", "router=fd00:ab5d:2::9"),
                     ("no_route_denied=1", "no_route_denied=0")]:
            raw = serial()
            # Change the decoded chunk itself, preserving the data container.
            match = m.CHUNK.search(raw)
            text = bytes.fromhex(match[2].decode()).decode().replace(a, b)
            raw = raw[:match.start(2)] + text.encode().hex().encode() + raw[match.end(2):]
            with self.assertRaises(AssertionError):
                m.native_output(raw, 3, "P01", 1792209064)

    def test_both_complete_link_streams_match_actual_peer_bytes(self):
        frames, peer = fixture(); peer["sent_hex"] += "00"
        with self.assertRaises(AssertionError):
            m.inspect_captures(pcap(frames), peer_leg(pcap(frames)), "P01", peer)

    def test_on_link_default_addresses_are_not_a_routed_capture(self):
        frames, peer = fixture()
        frame = bytearray(frames[5]); frame[38:54] = bytes.fromhex("fd00ab5d000000000000000000000002")
        frames[5] = bytes(frame)
        with self.assertRaises(AssertionError):
            inspect(pcap(frames), "P01", peer)



class BuildControls(unittest.TestCase):
    def actor(self):
        # Structural receipt fixture only; this is no compiled actor claim.
        child, root = b"child identity fixture", b"public root identity fixture"
        item = {"source_revision": m.PRODUCT, "source_tree": m.PRODUCT_TREE,
                "tracked_dirty": False, "untracked_source": False,
                "root_der": m.digest(root), "transport_profile": copy.deepcopy(m.PROFILE),
                "staged_std_source_sha256": m.STD, "cargo_lock_sha256": m.TLS_LOCK,
                "explicit_environment": {"ABSD_TLS_IPV6_PROFILE": "routed", "ABSD_TLS_IPV6_CLIENT_ELF": "/actor/child.elf"},
                "outputs": {"https_get_ipv6": {"path": "/actor/child.elf", **m.digest(child)}}}
        return item, child, root

    def test_exact_actor_source_route_root_and_child_receipt(self):
        item, child, root = self.actor()
        m.actor_binding(item, child, root)

    def test_actor_profile_source_dirty_or_environment_mismatch_refused(self):
        changes = [("source_revision", "0" * 40), ("source_tree", "0" * 40),
                   ("tracked_dirty", True), ("untracked_source", True),
                   ("staged_std_source_sha256", "0" * 64), ("cargo_lock_sha256", "0" * 64)]
        for key, value in changes:
            item, child, root = self.actor(); item[key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                m.actor_binding(item, child, root)
        for key, value in [("peer", "fd00:ab5d::2"), ("router", "fd00:ab5d:2::9"), ("port", 4444)]:
            item, child, root = self.actor(); item["transport_profile"][key] = value
            with self.subTest(profile=key), self.assertRaises(AssertionError):
                m.actor_binding(item, child, root)
        item, child, root = self.actor(); item["explicit_environment"]["ABSD_TLS_IPV6_PROFILE"] = "on-link"
        with self.assertRaises(AssertionError): m.actor_binding(item, child, root)

    def test_actor_changed_public_root_or_reused_child_refused(self):
        item, child, root = self.actor()
        for wrong_child, wrong_root in [(child + b"x", root), (child, root + b"x")]:
            with self.assertRaises(AssertionError): m.actor_binding(item, wrong_child, wrong_root)
        item["explicit_environment"]["ABSD_TLS_IPV6_CLIENT_ELF"] = "/other/child.elf"
        with self.assertRaises(AssertionError): m.actor_binding(item, child, root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
