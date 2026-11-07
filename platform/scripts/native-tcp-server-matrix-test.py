#!/usr/bin/env python3
"""Pure artifact controls for the separate server proof. No sockets or guest.

Authored source only until the resource owner executes this exact file.
"""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location("server_matrix", Path(__file__).with_name("native-tcp-server-matrix.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def tcp(outgoing, seq, ack, flags, body=b"", port=42030, mss=1460):
    source, target = (m.GUEST, m.HOST) if outgoing else (m.HOST, m.GUEST)
    srcmac, dstmac = (m.GUEST_MAC, m.HOST_MAC) if outgoing else (m.HOST_MAC, m.GUEST_MAC)
    options = struct.pack("!BBH", 2, 4, mss) if flags & 2 else b""
    ports = (7005, port) if outgoing else (port, 7005)
    segment = bytearray(struct.pack("!HHIIBBHHH", *ports, seq, ack, (5 + len(options) // 4) << 4, flags, 8192, 0, 0) + options + body)
    segment[16:18] = struct.pack("!H", m.boot.checksum(source + target + struct.pack("!BBH", 0, 6, len(segment)) + segment))
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0, 0x4000, 64, 6, 0, source, target))
    ip[10:12] = struct.pack("!H", m.boot.checksum(ip))
    return dstmac + srcmac + b"\x08\0" + ip + segment


def baseline():
    header = b"\0\x01\x08\0\x06\x04"
    request = m.arp_request()
    reply = m.HOST_MAC + m.GUEST_MAC + b"\x08\x06" + header + b"\0\x02" + m.GUEST_MAC + m.GUEST + m.HOST_MAC + m.HOST
    rows = [request, reply, tcp(False, 8000, 0, 2, port=42031), tcp(False, 1000, 0, 2),
            tcp(True, 4000, 1001, 18), tcp(False, 1001, 4001, 16)]
    for at in range(0, 3072, 1024):
        rows.append(tcp(False, 1001 + at, 4001, 24, m.DATA[at:at + 1024]))
    rows += [tcp(False, 4073, 4001, 17), tcp(True, 4001, 4074, 16)]
    for at in range(0, 3072, 511):
        rows.append(tcp(True, 4001 + at, 4074, 24, m.DATA[at:at + 511]))
    rows += [tcp(True, 7073, 4074, 17), tcp(False, 4074, 7074, 16)]
    return rows


def pcap(rows, times=None):
    data = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    times = times if times is not None else [1_000_000, 1_000_100, 1_000_200] + [2_250_300 + i * 100 for i in range(len(rows) - 3)]
    assert len(times) == len(rows)
    for i, frame in enumerate(rows):
        sec, usec = divmod(times[i], 1_000_000)
        data += struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame
    return data


def peer_fixture():
    rows = baseline()
    wrong = {"disposition": "PASS", "local": ["192.0.2.1", 42031], "peer": ["192.0.2.100", 7005],
             "result": "connect-timeout", "sent_bytes": 0, "timeout_ns": m.WRONG_TIMEOUT_NS,
             "connect_attempts": 1, "started_monotonic_ns": 3_000_000_000, "ended_monotonic_ns": 4_250_000_000}
    peer = {"disposition": "PASS", "local": ["192.0.2.1", 42030], "peer": ["192.0.2.100", 7005], "bytes": 3072,
            "sha256": m.digest(m.DATA)["sha256"], "write_half_closed": True, "read_EOF": True,
            "connect_started_monotonic_ns": 4_300_000_000, "connected_monotonic_ns": 4_400_000_000,
            "completed_monotonic_ns": 5_000_000_000}
    replace, show = m.neighbor_commands("tcps-tap0")
    readiness = {"schema": "absd-native-tcp-server-neighbor/1", "disposition": "PASS", "interface": "tcps-tap0",
                 "request_hex": rows[0].hex(), "request": m.digest(rows[0]), "reply_hex": rows[1].hex(), "reply": m.digest(rows[1]),
                 "reply_monotonic_ns": 1_000_000_000, "pin_verified_monotonic_ns": 2_000_000_000,
                 "replace_argv": replace, "readback_argv": show,
                 "neighbor_readback": [{"dst": "192.0.2.100", "dev": "tcps-tap0", "lladdr": m.GUEST_MAC.hex(":"), "state": ["PERMANENT"]}]}
    return wrong, peer, readiness, m.inspect_capture(pcap(rows))


def serial():
    output = (b"TCP SERVER GRANT READY local=192.0.2.100:7005 peer=192.0.2.1:42030 lifetime_ms=10000\n" +
              m.READY + b"TCP SERVER ECHO PASS bytes=3072 denied=1 nic=0\nTCP SERVER DONE child=exited sockets=0\n")
    return (b"\nABSD BOOT OK\nNETWORK LINK OK x\n" +
            b"EXTERNAL OUTPUT CHUNK offset=0000000000000000 data=" + output.hex().encode() + b"\n" +
            b"NIC STATS rx_frames=20 tx_frames=20 rx_refused=0 rx_missed=0 tx_refused=0 tx_errors=0\n" +
            b"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 x\nDURABLE WORKLOAD OK\n")


def telemetry_native(count=1, frame_bytes=58):
    raw = serial()
    original = m.native_output(raw, 3)["stdout"]
    baseline = "TCP SERVER PEER REFUSAL BASELINE v=1 count=0 last=none\n"
    final = (f"TCP SERVER PEER REFUSAL FINAL v=1 count={count} source=192.0.2.1:42031 "
             f"destination=192.0.2.100:7005 expected_peer=192.0.2.1:42030 flags=2 seq=8000 frame_bytes={frame_bytes}\n")
    output = baseline + original.replace("TCP SERVER DONE ", final + "TCP SERVER DONE ")
    # Exercise actual chunk reconstruction before the new correspondence check.
    return m.native_output(raw.replace(original.encode().hex().encode(), output.encode().hex().encode()), 3)


def boundary_native():
    # Independent literal record fixture; no kernel or pipe operations here.
    rows = ["TCP SERVER NEG BEGIN v=1 whole_start_ms=0 whole_until_ms=20000"]
    for case in ("local-port", "peer-port", "offlink", "self", "broadcast", "accept-low", "accept-high", "lifetime-short", "lifetime-high"):
        rows.append(f"TCP SERVER NEG GRANT v=1 case={case} code=1 sockets=0 tx=0")
    rows += ["TCP SERVER NEG SLOTS v=1 reserved=8 duplicate=3 ninth=4 sockets=0 tx=0",
             "TCP SERVER NEG SLOTS RETIRED v=1 stale=8 fresh=8 sockets=0 tx=0",
             "TCP SERVER NEG CENSUS v=1 label=before processes=3 handles=7 pipes=2 cells=0 frames=100"]
    literal = (
        ("version", "000c01200004c0000201a42e0000", "000c03200104c0000201a42e0000"),
        ("family", "000c03200006c0000201a42e0000", "000c03200104c0000201a42e0000"),
        ("reserved", "000c03200104c0000201a42e0000", "000c03200104c0000201a42e0000"),
        ("listen-length", "000c03200004c0000201a42e0001", "000c03200104c0000201a42e0000"),
        ("connect", "000c03100004c0000201a42e0000", "000c03100104c0000201a42e0000"),
        ("write-declared-without-body", "000c03120004c0000201a42e0401", "000c03120104c0000201a42e0000"),
        ("peer", "000c03200004c0000201a42f0000", "000c03200204c0000201a42e0000"))
    for case, request, reply in literal:
        rows.append(f"TCP SERVER NEG API v=1 case={case} request={request} reply={reply} sockets=0 tx=0")
    rows += ["TCP SERVER NEG LISTEN v=1 request=000c03200004c0000201a42e0000 reply=000d03200004c0000201a42e000100 sockets=1 tx=0",
             "TCP SERVER NEG INTERRUPT v=1 child_handle=17 constructed_ms=100 grant_until_ms=10100 partial_poll_ms=500 observed_ms=501 prefix=00 prefix_bytes=1 kill_ms=502 kill_return=0 reaped_ms=503 wait_kind=3 wait_status=0 eof_ms=504 retired_ms=504 channel_live=0 sockets=0 tx=0 fallback_fence=0",
             "TCP SERVER NEG CHILD v=1 cases=7 listen=1 nic=0",
             "TCP SERVER NEG CLOSED v=1 process_reaped=1 protocol_handles=2 result_handles=1 result_eof=1",
             "TCP SERVER NEG CENSUS v=1 label=after processes=3 handles=7 pipes=2 cells=0 frames=107",
             "TCP SERVER NEG COMPLETE v=1 grants=9 api=7 slots=8 interrupted=1 objects_restored=1 sockets=0 tx=0"]
    positive = telemetry_native()["stdout"].replace("TCP SERVER GRANT READY ",
        "TCP SERVER POSITIVE CLOCK v=1 owner_start_ms=600 owner_until_ms=10600 accept_ms=5000 grant_ms=10000 child_ms=8000 whole_until_ms=20000\nTCP SERVER GRANT READY ")
    raw = serial(); original = m.native_output(raw, 3)["stdout"]
    output = "\n".join(rows) + "\n" + positive
    return m.native_output(raw.replace(original.encode().hex().encode(), output.encode().hex().encode()), 3)


class ArtifactControls(unittest.TestCase):
    def refusal(self, rows):
        with self.assertRaises(AssertionError):
            m.inspect_capture(pcap(rows))

    def test_complete_partial_echo_has_exact_census(self):
        rows = baseline(); result = m.inspect_capture(pcap(rows))
        self.assertEqual(result["frames"], len(rows))
        self.assertEqual(result["wrong_port_syns"], [2])
        self.assertGreater(result["segments"]["guest"], 2)

    def test_literal_native_smoltcp_arp_and_directional_substitutions(self):
        # Sealed DHCP467 frame 12, same pinned Stack producer and IPs.
        # The request contains no peer MAC, so the literal is unchanged.
        literal = bytes.fromhex(
            "ffffffffffff52540012345608060001080006040001525400123456c0000264"
            "ffffffffffffc0000201000000000000000000000000000000000000")
        self.assertEqual(m.digest(literal)["sha256"],
                         "161373db3a1188391be4fa2f50c61e581f527a762a8941469636cc3515df9e2f")
        rows = baseline() + [literal]
        self.assertEqual(m.inspect_capture(pcap(rows))["census"][-1]["kind"], "peer-arp")
        for at, value in ((32, b"\0" * 6), (0, m.HOST_MAC)):
            substituted = literal[:at] + value + literal[at + 6:]
            self.refusal(baseline() + [substituted])
        rows = baseline()
        rows[0] = m.GUEST_MAC + rows[0][6:]  # Linux may probe known neighbor directly.
        self.assertEqual(m.inspect_capture(pcap(rows))["frames"], len(rows))
        for at, value in ((32, b"\xff" * 6), (0, m.HOST_MAC)):
            rows = baseline()
            rows[0] = rows[0][:at] + value + rows[0][at + 6:]
            self.refusal(rows)

    def test_missing_or_late_wrong_port_probe(self):
        rows = baseline(); self.refusal(rows[:2] + rows[3:])
        rows[2], rows[3] = rows[3], rows[2]; self.refusal(rows)
        rows = baseline(); rows.insert(5, tcp(False, 8000, 0, 2, port=42031)); self.refusal(rows)

    def test_wrong_port_response_cannot_be_explained(self):
        for flags, body in ((18, b""), (16, b""), (17, b""), (20, b""), (24, b"unexpected")):
            with self.subTest(flags=flags):
                rows = baseline(); rows.insert(3, tcp(True, 9000, 8001, flags, body, port=42031)); self.refusal(rows)

    def test_third_tuple_and_address_cannot_be_explained(self):
        rows = baseline(); rows[6] = tcp(False, 1001, 4001, 24, m.DATA[:1024], port=42032); self.refusal(rows)
        rows = baseline(); bad = bytearray(rows[6]); bad[26] ^= 1; rows[6] = bytes(bad); self.refusal(rows)

    def test_checksum_and_truncated_capture_are_refused(self):
        rows = baseline(); bad = bytearray(rows[6]); bad[-1] ^= 1; rows[6] = bytes(bad); self.refusal(rows)
        with self.assertRaises(AssertionError):
            m.inspect_capture(pcap(baseline())[:-1])

    def test_valid_checksum_changed_application_bytes_are_refused(self):
        rows = baseline(); rows[6] = tcp(False, 1001, 4001, 24, b"x" * 1024); self.refusal(rows)

    def test_unseen_data_ack_and_sequence_gap_are_refused(self):
        rows = baseline(); rows[5] = tcp(False, 1001, 7074, 16); self.refusal(rows)
        rows = baseline(); del rows[6]; self.refusal(rows)

    def test_half_close_fin_and_ack_are_required(self):
        rows = baseline(); del rows[-2]; self.refusal(rows)
        self.refusal(baseline()[:-1])
        rows = baseline(); rows[9] = tcp(False, 4072, 4001, 17); self.refusal(rows)

    def test_mss_reset_and_unrelated_ethernet_are_refused(self):
        rows = baseline(); rows[4] = tcp(True, 4000, 1001, 18, mss=1200); self.refusal(rows)
        rows = baseline(); rows[5] = tcp(False, 1001, 4001, 20); self.refusal(rows)
        rows = baseline(); rows.append(b"\xff" * 60); self.refusal(rows)

    def test_real_newline_native_output_positive(self):
        self.assertEqual(m.native_output(serial(), 3)["NIC_counters"]["rx_refused"], "0")

    def test_native_counters_exit_and_missing_child_marker_are_refused(self):
        for key in (b"rx_refused", b"rx_missed", b"tx_refused", b"tx_errors"):
            with self.subTest(key=key), self.assertRaises(AssertionError):
                m.native_output(serial().replace(key + b"=0", key + b"=1"), 3)
        with self.assertRaises(AssertionError):
            m.native_output(serial(), 1)
        with self.assertRaises(AssertionError):
            m.native_output(serial().replace(b"EXTERNAL OUTPUT CHUNK", b"REMOVED OUTPUT CHUNK"), 3)

    def test_exact_embed_and_build_source_substitutions(self):
        child = b"\x7fELFchild"; parent = b"\x7fELFparent" + child; kernel = b"\x7fELFkernel" + parent
        receipt = {"schema": "absd-native-tcp-server-build/4", "profile": m.PROFILE, "platform": {"revision": m.PRODUCT, "tree": m.PRODUCT_TREE, "clean": True,
                       "archive": {"bytes": m.PRODUCT_BYTES, "sha256": m.PRODUCT_ARCHIVE}},
                   "kernel": {"revision": m.KERNEL, "tree": m.KERNEL_TREE, "clean": True,
                       "archive": {"bytes": m.KERNEL_BYTES, "sha256": m.KERNEL_ARCHIVE}},
                   "served_kernel_policy": "frame-admission-v0", "served_wrapper_sha256": m.SERVED_WRAPPER,
                   "commands": [["sh", "scripts/build-native-tcp-server.sh"], ["python3", "scripts/served_kernel.py", "external-build", "EXTERNAL_USER_ELF=parent.elf"]],
                   "logs": [m.digest(b"build log")], "toolchain_receipt": m.digest(b"pinned toolchain"),
                   "outputs": {name: m.digest(data) for name, data in (("child", child), ("parent", parent), ("kernel", kernel))}}
        m.build_binding(receipt, child, parent, kernel)
        for key, value in (("schema", "absd-native-tcp-server-build/2"), ("schema", "absd-native-tcp-server-build/3"),
                           ("profile", "tcp-server-peer-refusal-telemetry-v1"), ("profile", "historical-no-telemetry")):
            bad = copy.deepcopy(receipt); bad[key] = value
            with self.assertRaises(AssertionError):
                m.build_binding(bad, child, parent, kernel)
        for key in ("platform", "kernel"):
            bad = copy.deepcopy(receipt); bad[key]["revision"] = "0" * 40
            with self.assertRaises(AssertionError):
                m.build_binding(bad, child, parent, kernel)
            bad = copy.deepcopy(receipt); bad[key]["archive"]["sha256"] = "0" * 64
            with self.assertRaises(AssertionError):
                m.build_binding(bad, child, parent, kernel)
            bad = copy.deepcopy(receipt); bad[key]["archive"]["bytes"] -= 1
            with self.assertRaises(AssertionError):
                m.build_binding(bad, child, parent, kernel)
        for key, value in (("served_kernel_policy", "frame-reservation"), ("served_wrapper_sha256", "0" * 64),
                           ("commands", [["sh", "scripts/build-native-tcp-server.sh"], ["make", "external-build", "EXTERNAL_USER_ELF=parent.elf"]])):
            bad = copy.deepcopy(receipt); bad[key] = value
            with self.assertRaises(AssertionError):
                m.build_binding(bad, child, parent, kernel)
        with self.assertRaises(AssertionError):
            m.build_binding(receipt, child + b"changed", parent, kernel)
        bad = copy.deepcopy(receipt); bad["outputs"]["parent"] = m.digest(parent + child)
        bad["outputs"]["kernel"] = m.digest(b"\x7fELF" + parent + child)
        with self.assertRaises(AssertionError):
            m.build_binding(bad, child, parent + child, b"\x7fELF" + parent + child)

    def test_peer_result_eof_tuple_and_digest_are_required(self):
        wrong, peer, readiness, capture = peer_fixture()
        m.peer_results(wrong, peer, readiness, capture)
        for key, value in (("read_EOF", False), ("sha256", "0" * 64), ("local", ["192.0.2.1", 42031])):
            bad = copy.deepcopy(peer); bad[key] = value
            with self.assertRaises(AssertionError):
                m.peer_results(wrong, bad, readiness, capture)

    def test_readiness_reply_must_precede_first_wrong_syn(self):
        rows = baseline(); reply = rows.pop(1); rows.insert(3, reply)
        # Keep >1s wrong→authorized separation so only late readiness fails.
        times = [1_000_000, 1_000_100] + [2_250_200 + i * 100 for i in range(len(rows) - 2)]
        with self.assertRaises(AssertionError):
            m.inspect_capture(pcap(rows, times))
        for missing in (0, 1):
            rows = baseline(); rows.pop(missing)
            times = [1_000_000, 1_000_100] + [2_250_200 + i * 100 for i in range(len(rows) - 2)]
            with self.subTest(missing=missing), self.assertRaises(AssertionError):
                m.inspect_capture(pcap(rows, times))

    def test_short_equal_and_arp_delayed_wire_intervals_are_refused(self):
        rows = baseline()
        for gap in (22, 300_000, 1_000_000):
            with self.subTest(gap=gap), self.assertRaises(AssertionError):
                m.inspect_capture(pcap(rows, [1_000_000, 1_000_100, 1_000_200] +
                                       [1_000_200 + gap + i * 100 for i in range(len(rows) - 3)]))

    def test_wrong_syn_retransmission_preserves_identity_and_full_census(self):
        rows = baseline(); rows.insert(3, tcp(False, 8000, 0, 2, port=42031))
        times = [1_000_000, 1_000_100, 1_000_200, 2_000_200] + [2_250_300 + i * 100 for i in range(len(rows) - 4)]
        observed = m.inspect_capture(pcap(rows, times))
        self.assertEqual(observed["wrong_port_syns"], [2, 3])
        self.assertEqual(observed["negative_interval_us"], 1_250_100)
        rows[3] = tcp(False, 9000, 0, 2, port=42031)
        with self.assertRaises(AssertionError):
            m.inspect_capture(pcap(rows, times))

    def test_false_timeout_and_overlapping_client_receipts_are_refused(self):
        wrong, peer, ready, capture = peer_fixture()
        for key, value in (("ended_monotonic_ns", wrong["started_monotonic_ns"] + 300_000_000),
                           ("ended_monotonic_ns", wrong["started_monotonic_ns"] + m.MIN_NEGATIVE_NS),
                           ("result", "connection-refused"), ("timeout_ns", 300_000_000), ("sent_bytes", 1), ("connect_attempts", 2)):
            bad = copy.deepcopy(wrong); bad[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(AssertionError):
                m.peer_results(bad, peer, ready, capture)
        bad = copy.deepcopy(peer); bad["connect_started_monotonic_ns"] = wrong["ended_monotonic_ns"] - 1
        with self.assertRaises(AssertionError):
            m.peer_results(wrong, bad, ready, capture)

    def test_neighbor_pin_and_exact_arp_receipt_cannot_be_assumed(self):
        wrong, peer, ready, capture = peer_fixture()
        for key, value in (("lladdr", m.HOST_MAC.hex(":")), ("state", ["STALE"]), ("dst", "192.0.2.101"), ("dev", "other-tap")):
            bad = copy.deepcopy(ready); bad["neighbor_readback"][0][key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                m.peer_results(wrong, peer, bad, capture)
        bad = copy.deepcopy(ready); del bad["neighbor_readback"][0]["dev"]
        with self.assertRaises(KeyError):
            m.peer_results(wrong, peer, bad, capture)
        bad = copy.deepcopy(ready); bad["neighbor_readback"].append(copy.deepcopy(bad["neighbor_readback"][0]))
        with self.assertRaises(AssertionError):
            m.peer_results(wrong, peer, bad, capture)
        for key, value in (("reply_hex", ready["request_hex"]), ("pin_verified_monotonic_ns", wrong["started_monotonic_ns"] + 1),
                           ("replace_argv", []), ("readback_argv", [])):
            bad = copy.deepcopy(ready); bad[key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                m.peer_results(wrong, peer, bad, capture)

    def test_actual_wrong_client_timeout_duration_and_one_connect(self):
        sock = MagicMock(); sock.__enter__.return_value = sock
        sock.connect.side_effect = TimeoutError()
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "wrong.json"
            with patch.object(m.socket, "socket", return_value=sock), patch.object(m.time, "monotonic_ns", side_effect=[3_000_000_000, 4_250_000_000]):
                m.wrong_port_client(result)
            sock.connect.assert_called_once_with(("192.0.2.100", 7005))
            sock.bind.assert_called_once_with(("192.0.2.1", 42031))
            sock.settimeout.assert_called_once_with(1.25)
            _, peer, ready, capture = peer_fixture()
            m.peer_results(json.loads(result.read_text()), peer, ready, capture)

    def test_actual_wrong_client_refuses_false_timeout_or_connect_success(self):
        for error in (TimeoutError(), ConnectionRefusedError(), None):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as directory:
                sock = MagicMock(); sock.__enter__.return_value = sock; sock.connect.side_effect = error
                result = Path(directory) / "wrong.json"
                with patch.object(m.socket, "socket", return_value=sock), patch.object(m.time, "monotonic_ns", side_effect=[3_000_000_000, 3_300_000_000]):
                    with self.assertRaises((AssertionError, ConnectionRefusedError)):
                        m.wrong_port_client(result)
                self.assertFalse(result.exists())

    def test_actual_neighbor_probe_pins_only_after_exact_reply_then_readback(self):
        _, _, ready, _ = peer_fixture()
        effects = []
        sock = MagicMock(); sock.__enter__.return_value = sock; sock.send.return_value = len(m.arp_request())
        def receive(_limit):
            effects.append("reply")
            return bytes.fromhex(ready["reply_hex"])
        sock.recv.side_effect = receive
        def checked(argv):
            effects.append(argv)
            self.assertEqual(effects[0], "reply")
            return SimpleNamespace(stdout=json.dumps(ready["neighbor_readback"]))
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "ready.json"
            with patch.object(m.socket, "socket", return_value=sock), patch.object(m, "checked", side_effect=checked):
                m.neighbor_ready_client("tcps-tap0", result)
            sock.send.assert_called_once_with(m.arp_request())
            sock.bind.assert_called_once_with(("tcps-tap0", 0x0806))
            self.assertEqual(effects[1:], list(m.neighbor_commands("tcps-tap0")))
            saved = json.loads(result.read_text())
            self.assertEqual(saved["reply"], ready["reply"])
            self.assertEqual(saved["neighbor_readback"], ready["neighbor_readback"])

    def test_actual_neighbor_wrong_reply_budget_and_false_pin_refuse(self):
        _, _, ready, _ = peer_fixture()
        with tempfile.TemporaryDirectory() as directory:
            sock = MagicMock(); sock.__enter__.return_value = sock; sock.send.return_value = len(m.arp_request())
            sock.recv.return_value = m.arp_request()  # This is never a matching reply.
            result = Path(directory) / "ready.json"
            with patch.object(m.socket, "socket", return_value=sock), patch.object(m.time, "monotonic_ns", return_value=1_000_000), patch.object(m, "checked") as checked:
                with self.assertRaises(AssertionError):
                    m.neighbor_ready_client("tcps-tap0", result)
                self.assertEqual(sock.recv.call_count, 32)
                checked.assert_not_called()
            self.assertFalse(result.exists())
            sock.recv.return_value = bytes.fromhex(ready["reply_hex"])
            with patch.object(m.socket, "socket", return_value=sock), patch.object(m.time, "monotonic_ns", side_effect=[1, 2, 3_000_000_002]), patch.object(m, "checked") as checked:
                with self.assertRaises(AssertionError):
                    m.neighbor_ready_client("tcps-tap0", result)
                checked.assert_not_called()
            bad = copy.deepcopy(ready["neighbor_readback"]); bad[0]["state"] = ["STALE"]
            with patch.object(m.socket, "socket", return_value=sock), patch.object(m, "checked", return_value=SimpleNamespace(stdout=json.dumps(bad))):
                with self.assertRaises(AssertionError):
                    m.neighbor_ready_client("tcps-tap0", result)
            self.assertFalse(result.exists())


class RefusalObservationControls(unittest.TestCase):
    def test_one_and_two_actual_wrong_syn_census_bind_to_guest_count(self):
        for count in (1, 2):
            rows = baseline()
            if count == 2:
                rows.insert(3, tcp(False, 8000, 0, 2, port=42031))
            captured = m.inspect_capture(pcap(rows))
            result = m.refusal_observation(telemetry_native(count), captured)
            self.assertEqual(result["count"], count)
            self.assertEqual(result["captured_indices"], list(range(2, 2 + count)))

    def test_missing_zero_mismatched_or_saturated_count_is_refused(self):
        captured = m.inspect_capture(pcap(baseline()))
        for count in (0, 2, 2**64 - 1, 2**64):
            with self.subTest(count=count), self.assertRaises(AssertionError):
                m.refusal_observation(telemetry_native(count), captured)

    def test_exact_last_tuple_expected_peer_flags_sequence_and_length_required(self):
        captured = m.inspect_capture(pcap(baseline()))
        for old, new in (("source=192.0.2.1:42031", "source=192.0.2.2:42031"),
                         ("source=192.0.2.1:42031", "source=192.0.2.1:42030"),
                         ("destination=192.0.2.100:7005", "destination=192.0.2.101:7005"),
                         ("destination=192.0.2.100:7005", "destination=192.0.2.100:7006"),
                         ("expected_peer=192.0.2.1:42030", "expected_peer=192.0.2.1:42031"),
                         ("flags=2", "flags=18"), ("seq=8000", "seq=8001"),
                         ("seq=8000", "seq=4294967296"), ("frame_bytes=58", "frame_bytes=60")):
            native = telemetry_native(); native["stdout"] = native["stdout"].replace(old, new)
            with self.subTest(field=old), self.assertRaises(AssertionError):
                m.refusal_observation(native, captured)

    def test_zero_unique_baseline_version_and_record_set_required(self):
        captured = m.inspect_capture(pcap(baseline()))
        line = "TCP SERVER PEER REFUSAL BASELINE v=1 count=0 last=none\n"
        for replacement in ("", line * 2, line.replace("count=0", "count=1"), line.replace("v=1", "v=2")):
            native = telemetry_native(); native["stdout"] = native["stdout"].replace(line, replacement)
            with self.subTest(replacement=replacement), self.assertRaises(AssertionError):
                m.refusal_observation(native, captured)

    def test_api_denied_marker_is_never_a_filter_observation_substitute(self):
        captured = m.inspect_capture(pcap(baseline()))
        with self.assertRaises(AssertionError):
            m.refusal_observation(m.native_output(serial(), 3), captured)
        for replacement in ("", "TCP SERVER PEER REFUSAL FINAL v=1 count=0 last=none\n",
                            "TCP SERVER PEER REFUSAL FINAL v=2 count=1 last=none\n"):
            native = telemetry_native()
            line = next(line for line in native["stdout"].splitlines(keepends=True) if "REFUSAL FINAL" in line)
            native["stdout"] = native["stdout"].replace(line, replacement)
            with self.subTest(replacement=replacement), self.assertRaises(AssertionError):
                m.refusal_observation(native, captured)
        native = telemetry_native()
        line = next(line for line in native["stdout"].splitlines(keepends=True) if "REFUSAL FINAL" in line)
        native["stdout"] += line
        with self.assertRaises(AssertionError):
            m.refusal_observation(native, captured)

    def test_observation_marker_order_is_part_of_the_contract(self):
        captured = m.inspect_capture(pcap(baseline()))
        for target in ("TCP SERVER GRANT READY ", "TCP SERVER ECHO PASS ", "after-done"):
            native = telemetry_native()
            line = next(line for line in native["stdout"].splitlines(keepends=True) if "REFUSAL FINAL" in line)
            native["stdout"] = native["stdout"].replace(line, "")
            if target == "after-done":
                native["stdout"] += line
            else:
                native["stdout"] = native["stdout"].replace(target, line + target)
            with self.subTest(target=target), self.assertRaises(AssertionError):
                m.refusal_observation(native, captured)
        native = telemetry_native()
        line = native["stdout"].splitlines(keepends=True)[0]
        native["stdout"] = native["stdout"].replace(line, "").replace(m.READY.decode(), m.READY.decode() + line)
        with self.assertRaises(AssertionError):
            m.refusal_observation(native, captured)

    def test_actual_last_padded_frame_and_extra_wire_input_are_not_hidden(self):
        rows = baseline(); rows.insert(3, tcp(False, 8000, 0, 2, port=42031) + b"\0\0")
        captured = m.inspect_capture(pcap(rows))
        self.assertEqual(m.refusal_observation(telemetry_native(2, 60), captured)["last"]["frame_bytes"], 60)
        with self.assertRaises(AssertionError):
            m.refusal_observation(telemetry_native(2, 58), captured)
        rows.insert(4, tcp(False, 8000, 0, 2, port=42031))
        captured = m.inspect_capture(pcap(rows))
        with self.assertRaises(AssertionError):
            m.refusal_observation(telemetry_native(2), captured)


class NativeBoundaryControls(unittest.TestCase):
    def refused(self, old, new):
        native = boundary_native(); native["stdout"] = native["stdout"].replace(old, new)
        self.assertNotEqual(native["stdout"], boundary_native()["stdout"])
        with self.assertRaises(AssertionError):
            m.boundary_observation(native)

    def test_complete_native_ledger_preserves_positive_and_reports_frame_delta_only(self):
        native = boundary_native()
        result = m.boundary_observation(native)
        self.assertEqual((result["input_bytes"], result["output_bytes"]), (113, 113))
        self.assertEqual(result["frame_delta_observed"], 7)
        captured = m.inspect_capture(pcap(baseline()))
        self.assertEqual(m.refusal_observation(native, captured)["count"], 1)

    def test_grant_codes_eight_slots_distinct_ninth_stale_and_zero_effect_required(self):
        for old, new in (("case=offlink code=1", "case=offlink code=0"), ("reserved=8", "reserved=7"),
                         ("duplicate=3", "duplicate=4"), ("ninth=4", "ninth=3"),
                         ("stale=8", "stale=7"), ("fresh=8", "fresh=7")):
            with self.subTest(field=old): self.refused(old, new)
        lines = boundary_native()["stdout"].splitlines()
        for line in lines:
            if line.startswith("TCP SERVER NEG ") and "sockets=0 tx=0" in line:
                for field in ("sockets", "tx"):
                    with self.subTest(line=line, field=field):
                        self.refused(line, line.replace(field + "=0", field + "=1"))

    def test_actual_api_literal_frame_and_canonical_status_cannot_be_substituted(self):
        for old, new in (("request=000c01200004", "request=000c03200004"),
                         ("request=000c03200006", "request=000b03200006"),
                         ("reply=000c03200104", "reply=000c03200004"),
                         ("reply=000c03200204", "reply=000c03200104"),
                         ("a42e0401", "a42e0400"), ("case=peer request=000c03200004c0000201a42f", "case=peer request=000c03200004c0000201a42e")):
            with self.subTest(field=old): self.refused(old, new)

    def test_full_listen_reply_then_actual_one_zero_prefix_byte_required(self):
        for old, new in (("reply=000d03200004c0000201a42e000100", "reply=000c03200004c0000201a42e0000"),
                         ("sockets=1 tx=0", "sockets=0 tx=0"), ("prefix=00", "prefix=01"),
                         ("prefix_bytes=1", "prefix_bytes=0"), ("prefix_bytes=1", "prefix_bytes=2"),
                         ("observed_ms=501", "observed_ms=499")):
            with self.subTest(field=old): self.refused(old, new)

    def test_killed_outcome_true_eof_and_retirement_before_fallback_required(self):
        for old, new in (("child_handle=17", "child_handle=0"), ("kill_return=0", "kill_return=5"),
                         ("wait_kind=3", "wait_kind=1"), ("wait_status=0", "wait_status=1"),
                         ("eof_ms=504", "no_eof_ms=504"), ("channel_live=0", "channel_live=1"),
                         ("fallback_fence=0", "fallback_fence=1"), ("result_eof=1", "result_eof=0"),
                         ("process_reaped=1", "process_reaped=0"), ("protocol_handles=2", "protocol_handles=1"),
                         ("nic=0", "nic=1")):
            with self.subTest(field=old): self.refused(old, new)

    def test_native_deadline_equality_expiry_and_reordered_transitions_refuse(self):
        for old, new in (("retired_ms=504", "retired_ms=750"), ("retired_ms=504", "retired_ms=751"),
                         ("reaped_ms=503", "reaped_ms=501"), ("eof_ms=504", "eof_ms=502"),
                         ("grant_until_ms=10100", "grant_until_ms=504"),
                         ("grant_until_ms=10100", "grant_until_ms=10101"),
                         ("whole_start_ms=0 whole_until_ms=20000", "whole_start_ms=0 whole_until_ms=20001")):
            with self.subTest(field=old): self.refused(old, new)

    def test_nonframe_object_restoration_is_not_full_memory_restoration(self):
        before = "label=after processes=3 handles=7 pipes=2 cells=0 frames=107"
        for old, new in (("processes=3", "processes=4"), ("handles=7", "handles=8"),
                         ("pipes=2", "pipes=3"), ("cells=0", "cells=1")):
            with self.subTest(field=old): self.refused(before, before.replace(old, new))
        for frames in (0, 100, 1000):
            native = boundary_native(); native["stdout"] = native["stdout"].replace(before, before.replace("frames=107", f"frames={frames}"))
            self.assertEqual(m.boundary_observation(native)["census_after"]["frames"], frames)

    def test_missing_duplicate_reordered_and_old_positive_only_records_refuse(self):
        native = boundary_native(); lines = native["stdout"].splitlines(keepends=True)
        for index, line in enumerate(lines):
            if line.startswith("TCP SERVER NEG "):
                with self.subTest(index=index): self.refused(line, "")
        for index in (0, 10, 12, 20):
            with self.subTest(duplicate=index): self.refused(lines[index], lines[index] * 2)
        self.refused(lines[10] + lines[11], lines[11] + lines[10])
        with self.assertRaises(AssertionError): m.boundary_observation(telemetry_native())

    def test_positive_phase_is_fresh_and_original_clocks_are_unchanged(self):
        for old, new in (("owner_start_ms=600", "owner_start_ms=500"), ("owner_until_ms=10600", "owner_until_ms=10601"),
                         ("accept_ms=5000", "accept_ms=6000"), ("grant_ms=10000", "grant_ms=10001"),
                         ("child_ms=8000", "child_ms=9000")):
            with self.subTest(field=old): self.refused(old, new)
        native = boundary_native()
        line = next(line for line in native["stdout"].splitlines(keepends=True) if "NEG COMPLETE" in line)
        native["stdout"] = native["stdout"].replace(line, "") + line
        with self.assertRaises(AssertionError): m.boundary_observation(native)


if __name__ == "__main__":
    unittest.main()
