#!/usr/bin/env python3
"""Synthetic artifact controls for the actual TCP MTU proof checker.

These call the real checker functions. Literal packets are local byte arrays,
never sent, and a passing method is not a native/router execution claim.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("tcp_mtu_controls", HERE / "native-tcp-mtu-matrix.py")
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)
VECTORS = json.loads((HERE.parent / "fixtures/native-tcp-mtu/v1.json").read_text())


def vector(name):
    return bytes.fromhex(VECTORS["frames"][name]["hex"])


def recalculate(frame):
    """Independent control constructor: retain sizes, recalculate checksums."""
    value = bytearray(frame)
    value[24:26] = bytes(2)
    value[24:26] = proof.base.checksum(bytes(value[14:34])).to_bytes(2, "big")
    if value[23] == 1:
        value[36:38] = bytes(2)
        value[36:38] = proof.base.checksum(bytes(value[34:])).to_bytes(2, "big")
    else:
        value[50:52] = bytes(2)
        data = bytes(value[34:])
        value[50:52] = proof.base.checksum(bytes(value[26:34]) + b"\0\6" + len(data).to_bytes(2, "big") + data).to_bytes(2, "big")
    return bytes(value)


def routed(frame):
    ip = bytearray(frame[14:])
    out = ip[12:16] == proof.GUEST_IP
    if out:
        ip[8] -= 1
    else:
        ip[8] += 1
    ip[10:12] = bytes(2)
    ip[10:12] = proof.base.checksum(bytes(ip[:20])).to_bytes(2, "big")
    return ((proof.PEER_MAC + proof.ROUTER_EGRESS_MAC) if out else (proof.ROUTER_EGRESS_MAC + proof.PEER_MAC)) + b"\x08\0" + bytes(ip)


def baseline():
    lines, capture, egress = [], [], []
    counters, transaction = {"tx": 0, "rx": 0}, 0

    def line(tag, **values):
        lines.append("TCP MTU " + tag + " v=1 " + " ".join(str(k) + "=" + str(v) for k, v in values.items()))

    def frame(name, direction, phase, at):
        value = vector(name)
        counters[direction] += 1
        line("FRAME", direction=direction, ordinal=counters[direction], phase=phase, at_ms=at, bytes=len(value), hex=value.hex())
        captured = value + bytes(18) if name == "arp_request" else value
        capture.append((len(capture), [1000, len(capture) * 1000], captured))
        if value[12:14] == b"\x08\0" and value[23] == 6 and len(value[14:]) <= 576:
            egress.append((len(egress), [1000, len(egress) * 1000], routed(value)))

    def rpc(at, phase, op, status=0, body=b"", count=0, payload=b""):
        nonlocal transaction
        transaction += 1
        port = 42100 if phase == "refusal" else 42101
        tuple_bytes = proof.PEER_IP + port.to_bytes(2, "big")
        request = bytes((4, op, 0, 0)) + tuple_bytes + count.to_bytes(2, "big") + body
        reply_count = 576 if status == 17 else (len(payload) if op in (16, 17, 19) and not status else count if op == 18 and not status else 0)
        reply = bytes((4, op, status, 0)) + tuple_bytes + reply_count.to_bytes(2, "big") + payload
        line("RPC", index=transaction, phase=phase, at_ms=at, request_bytes=len(request), request_hex=request.hex(), reply_bytes=len(reply), reply_hex=reply.hex())

    line("BEGIN", start_ms=100, until_ms=30100, refusal_until_ms=12100, guest="192.0.2.100", router="192.0.2.1", peer="198.51.100.2")
    frame("arp_request", "tx", "refusal", 110)
    frame("arp_reply", "rx", "refusal", 120)
    frame("negative_syn", "tx", "refusal", 125)
    rpc(130, "refusal", 16, payload=b"\0")
    frame("negative_synack", "rx", "refusal", 140)
    frame("negative_ack", "tx", "refusal", 145)
    rpc(150, "refusal", 17, payload=b"\1")
    line("CONNECTED", at_ms=150, phase="refusal", sockets=1)
    rpc(160, "refusal", 18, body=proof.peer.NEGATIVE, count=1024)
    line("QUEUED", at_ms=160, phase="refusal", bytes=1024)
    frame("negative_data", "tx", "refusal", 170)
    frame("icmp576", "rx", "refusal", 180)
    rpc(190, "refusal", 19, status=17, count=64)
    line("REFUSED", at_ms=190, code=17, mtu=576, sockets=0, until_ms=12100, effects="unknown")
    line("FENCED", at_ms=191, code=8, rpc_before=transaction, rpc_after=transaction, tx_before=counters["tx"], tx_after=counters["tx"])
    line("REVOKED", at_ms=192, sockets=0)
    line("POSITIVE", start_ms=193, until_ms=10193, bytes=64)
    frame("positive_syn", "tx", "positive", 200)
    rpc(210, "positive", 16, payload=b"\0")
    frame("positive_synack", "rx", "positive", 220)
    frame("positive_ack", "tx", "positive", 225)
    rpc(230, "positive", 17, payload=b"\1")
    line("CONNECTED", at_ms=230, phase="positive", sockets=1)
    rpc(240, "positive", 18, body=proof.peer.POSITIVE, count=64)
    line("QUEUED", at_ms=240, phase="positive", bytes=64)
    rpc(250, "positive", 20)
    frame("positive_data", "tx", "positive", 260)
    frame("positive_fin", "tx", "positive", 270)
    frame("positive_echo", "rx", "positive", 280)
    rpc(290, "positive", 19, count=64, payload=proof.peer.POSITIVE)
    line("OBSERVED", at_ms=290, bytes=64, hex=proof.peer.POSITIVE.hex(), sockets=1)
    frame("positive_reply_fin", "rx", "positive", 300)
    rpc(310, "positive", 19, status=6, count=64)
    line("EOF", at_ms=310, phase="positive", code=6)
    frame("positive_final_ack", "tx", "positive", 320)
    line("DONE", at_ms=330, sockets=0, negative_bytes=1024, positive_bytes=64)
    return lines, capture, egress


def serial(lines):
    output = ("\n".join(lines) + "\n").encode()
    digest = 0x811c9dc5
    for value in output:
        digest = ((digest ^ value) * 0x1000193) & 0xffffffff
    raw = (b"ABSD KERNEL BOOT\nNETWORK LINK OK descriptors=32\nSPAWN OK pid=2 parent=1 program=external-workload\n"
           b"EXTERNAL OUTPUT BEGIN encoding=hex\nDURABLE WORKER GENERATION generation=1 pid=2\n")
    for offset in range(0, len(output), 96):
        raw += f"EXTERNAL OUTPUT CHUNK offset={offset:016x} data={output[offset:offset + 96].hex()}\n".encode()
    counts = {direction: sum("FRAME " in row and "direction=" + direction in row for row in lines) for direction in ("tx", "rx")}
    return (raw + b"USER EXIT pid=2 status=0\nDURABLE WORKER OUTCOME generation=1 pid=2 status=0\n"
        + f"EXTERNAL OUTPUT END bytes={len(output)} digest={digest:08x}\n".encode()
        + b"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ticks=400\n"
        + f"NIC STATS rx_frames={counts['rx']} rx_refused=0 rx_missed=0 tx_frames={counts['tx']} tx_refused=0 tx_errors=0 flags=1\n".encode()
        + b"DURABLE WORKLOAD OK\nABSD BOOT OK\n")


def evaluate(lines=None, capture=None, egress=None):
    canonical, frames, routed_frames = baseline()
    native = proof.native_output(serial(canonical if lines is None else lines), 3)
    wire = proof.inspect_frames(frames if capture is None else capture, native, routed_frames if egress is None else egress)
    return native, wire


def peer_report():
    empty, body = b"", proof.peer.POSITIVE
    rows = []
    for port, start, end, received, sent, completion in ((42100, 10, 100, empty, 0, "eof"), (42101, 20, 90, body, 64, "echo-and-half-close")):
        rows.append({"port": port, "source": ["192.0.2.100", 7100 if port == 42100 else 7101], "destination": ["198.51.100.2", port],
            "accepted_monotonic_ns": start, "finished_monotonic_ns": end, "received_bytes": len(received), "received_hex": received.hex(),
            "received_sha256": hashlib.sha256(received).hexdigest(), "sent": sent, "completion": completion,
            "finished": True, "eof": True, "reset": False})
    return {"schema": "absd-native-tcp-mtu-peer/1", "disposition": "PASS", "pid": 123, "network_namespace_inode": 456,
        "bind": "198.51.100.2", "sockets_closed": True, "started_monotonic_ns": 1, "ended_monotonic_ns": 110,
        "runner_stop_received": True, "runner_stop_monotonic_ns": 109,
        "zero_read_window_ns": 1500000000, "connections": rows,
        "events": [{"event": "accept", "port": port, "monotonic_ns": at, "source": rows[index]["source"], "destination": rows[index]["destination"]}
                   for index, (port, at) in enumerate(((42100, 10), (42101, 20)))] + [
            {"event": "read", "port": 42101, "monotonic_ns": 30, "bytes": 64, "hex": body.hex(), "reset": False},
            {"event": "write", "port": 42101, "monotonic_ns": 40, "offset": 0, "bytes": 64, "hex": body.hex()},
            {"event": "read", "port": 42101, "monotonic_ns": 50, "bytes": 0, "hex": "", "reset": False},
            {"event": "shutdown-write", "port": 42101, "monotonic_ns": 60, "bytes": 64},
            {"event": "read", "port": 42100, "monotonic_ns": 100, "bytes": 0, "hex": "", "reset": False}]}


class TCPMTUControls(unittest.TestCase):
    def mutate_line(self, marker, old, new):
        lines, _, _ = baseline()
        indices = [index for index, row in enumerate(lines) if marker in row]
        self.assertEqual(len(indices), 1)
        index = indices[0]
        self.assertIn(old, lines[index])
        lines[index] = lines[index].replace(old, new)
        return lines

    def test_01_synthetic_full_witness(self):
        native, wire = evaluate()
        self.assertEqual(native["lifecycle"]["REFUSED"]["mtu"], "576")
        self.assertEqual(wire["oversized_submissions"], 1)
        self.assertEqual(proof.inspect_peer(peer_report(), 123, 456)["positive_echo_bytes"], 64)

    def test_02_literal_vectors_checksum_and_identity(self):
        for name, row in VECTORS["frames"].items():
            value = vector(name)
            self.assertEqual(row["bytes"], len(value))
            self.assertEqual(row["sha256"], hashlib.sha256(value).hexdigest())
            if value[12:14] == b"\x08\0":
                ip = proof.ipv4(value)
                if ip[9] == 6:
                    proof.tcp(ip)

    def test_03_quote_requires_actual_literal_prefix(self):
        changed = bytearray(vector("icmp576"))
        changed[-1] ^= 1
        with self.assertRaises(AssertionError):
            proof.icmp_quote(recalculate(changed), vector("negative_data"))

    def test_04_quote_requires_full_tcp_prefix(self):
        value = bytearray(vector("icmp576")[:14 + 20 + 8 + 27])
        value[16:18] = (len(value) - 14).to_bytes(2, "big")
        with self.assertRaises(AssertionError):
            proof.icmp_quote(recalculate(value), vector("negative_data"))

    def test_05_quote_wrong_mtu_type_code_checksum(self):
        for offset, value in ((34, 11), (35, 3), (36, 99), (40, 3), (41, 65)):
            changed = bytearray(vector("icmp576"))
            changed[offset] = changed[offset] ^ 1 if offset == 36 else value
            candidate = bytes(changed) if offset == 36 else recalculate(changed)
            with self.subTest(offset=offset), self.assertRaises(AssertionError):
                proof.icmp_quote(candidate, vector("negative_data"))

    def test_06_quote_router_tuple_unused_and_quoted_sequence(self):
        for offset in (26, 30, 38, 66):
            changed = bytearray(vector("icmp576"))
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(AssertionError):
                proof.icmp_quote(recalculate(changed), vector("negative_data"))

    def test_07_actual_submission_requires_df_and_full1024(self):
        for name in ("positive_data", "negative_ack"):
            with self.subTest(name=name), self.assertRaises(AssertionError):
                proof.icmp_quote(vector("icmp576"), vector(name))
        changed = bytearray(vector("negative_data"))
        changed[20:22] = b"\0\0"
        with self.assertRaises(AssertionError):
            proof.icmp_quote(vector("icmp576"), recalculate(changed))

    def test_08_native_frame_missing_and_substituted(self):
        lines, _, _ = baseline()
        for selection in ([row for row in lines if "direction=rx ordinal=3 " not in row],
                          self.mutate_line("direction=rx ordinal=3 ", "ordinal=3", "ordinal=4")):
            with self.assertRaises(AssertionError):
                evaluate(selection)

    def test_09_full_capture_count_order_and_bytes(self):
        _, frames, _ = baseline()
        variants = (frames[:-1], frames + [frames[0]], [frames[2], frames[1], frames[0]] + frames[3:])
        for variant in variants:
            with self.subTest(count=len(variant)), self.assertRaises(AssertionError):
                evaluate(capture=variant)

    def test_10_router_egress_missing_extra_and_reorder(self):
        _, _, egress = baseline()
        for variant in (egress[:-1], egress + [egress[0]], [egress[2], egress[1], egress[0]] + egress[3:]):
            with self.assertRaises(AssertionError):
                evaluate(egress=variant)

    def test_11_router_must_not_forward_oversized_data(self):
        _, _, egress = baseline()
        egress.insert(3, (3, [1000, 3000], routed(vector("negative_data"))))
        with self.assertRaises(AssertionError):
            evaluate(egress=egress)

    def test_12_router_ttl_transform_is_exact(self):
        _, _, egress = baseline()
        index, stamp, value = egress[0]
        changed = bytearray(value)
        changed[22] -= 1
        egress[0] = index, stamp, recalculate(changed)
        with self.assertRaises(AssertionError):
            evaluate(egress=egress)

    def test_13_typed_refusal_not_stale_deadline_or_unknown(self):
        for code in ("8", "9", "16", "0"):
            with self.subTest(code=code), self.assertRaises(AssertionError):
                evaluate(self.mutate_line("REFUSED ", "code=17", "code=" + code))

    def test_14_refusal_mtu_effects_socket_and_original_deadline(self):
        for old, new in (("mtu=576", "mtu=577"), ("effects=unknown", "effects=none"), ("sockets=0", "sockets=1"), ("until_ms=12100", "until_ms=12200")):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                evaluate(self.mutate_line("REFUSED ", old, new))

    def test_15_fenced_client_cannot_issue_rpc_or_tx(self):
        for old, new in (("rpc_after=4", "rpc_after=5"), ("tx_after=4", "tx_after=5"), ("code=8", "code=5")):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                evaluate(self.mutate_line("FENCED ", old, new))

    def test_16_explicit_revoke_before_fresh_positive(self):
        lines, _, _ = baseline()
        with self.assertRaises(AssertionError):
            evaluate([row for row in lines if " REVOKED " not in row])
        with self.assertRaises(AssertionError):
            evaluate(self.mutate_line("REVOKED ", "sockets=0", "sockets=1"))

    def test_17_original_guest_budgets_and_canonical_integers(self):
        for marker, old, new in (("BEGIN ", "until_ms=30100", "until_ms=30101"),
                                  ("BEGIN ", "refusal_until_ms=12100", "refusal_until_ms=12101"),
                                  ("POSITIVE ", "until_ms=10193", "until_ms=10194"),
                                  ("REFUSED ", "at_ms=190", "at_ms=0189"),
                                  ("REFUSED ", "at_ms=190", "at_ms=18446744073709551616")):
            with self.subTest(new=new), self.assertRaises(AssertionError):
                evaluate(self.mutate_line(marker, old, new))

    def test_18_guest_clock_rewind_and_terminal_after_deadline(self):
        for marker, old, new in (("FENCED ", "at_ms=191", "at_ms=189"), ("DONE ", "at_ms=330", "at_ms=30100")):
            with self.assertRaises(AssertionError):
                evaluate(self.mutate_line(marker, old, new))

    def test_19_actual_v4_rpc_version_family_tuple_and_frame_size(self):
        lines, _, _ = baseline()
        at = next(i for i, row in enumerate(lines) if "RPC v=1 index=1 " in row)
        for old, new in (("request_hex=04100000", "request_hex=01100000"),
                         ("request_hex=04100000", "request_hex=04100004"),
                         ("c6336402a474", "c6336403a474"), ("request_bytes=12", "request_bytes=11")):
            changed = list(lines)
            self.assertIn(old, changed[at])
            changed[at] = changed[at].replace(old, new)
            with self.subTest(new=new), self.assertRaises(AssertionError):
                evaluate(changed)

    def test_20_rpc_refusal_detail_and_successful_write_count(self):
        for index, old, new in ((4, "04131100c6336402a4740240", "04131100c6336402a4740241"),
                                 (3, "reply_hex=04120000c6336402a4740400", "reply_hex=04120000c6336402a47403ff")):
            with self.assertRaises(AssertionError):
                evaluate(self.mutate_line("RPC v=1 index=" + str(index) + " ", old, new))

    def test_21_rpc_index_and_missing_physical_transaction(self):
        with self.assertRaises(AssertionError):
            evaluate(self.mutate_line("RPC v=1 index=4 ", "index=4", "index=3"))
        lines, _, _ = baseline()
        with self.assertRaises(AssertionError):
            evaluate([row for row in lines if "RPC v=1 index=4 " not in row])

    def test_22_positive_echo_and_eof_required(self):
        lines, _, _ = baseline()
        for removed in (" EOF ", " OBSERVED "):
            with self.assertRaises(AssertionError):
                evaluate([row for row in lines if removed not in row])
        with self.assertRaises(AssertionError):
            evaluate(self.mutate_line("OBSERVED ", "hex=000102", "hex=010102"))

    def test_23_missing_fin_or_corrupted_tcp_checksum(self):
        _, frames, _ = baseline()
        at = next(i for i, row in enumerate(frames) if row[2] == vector("positive_reply_fin"))
        for candidate in (vector("positive_echo"), vector("positive_reply_fin")[:-1] + b"\xff"):
            changed = list(frames)
            changed[at] = changed[at][0], changed[at][1], candidate
            with self.assertRaises(AssertionError):
                evaluate(capture=changed)

    def test_24_native_complete_serial_seal_and_terminal(self):
        lines, _, _ = baseline()
        raw = serial(lines)
        for changed in (raw.replace(b"USER EXIT pid=2 status=0", b"USER EXIT pid=2 status=1"),
                        raw.replace(b"NIC STATS rx_frames=6", b"NIC STATS rx_frames=7"),
                        raw.replace(b"EXTERNAL OUTPUT END bytes=", b"EXTERNAL OUTPUT END bytes=1")):
            self.assertNotEqual(changed, raw)
            with self.assertRaises(AssertionError):
                proof.native_output(changed, 3)
        with self.assertRaises(AssertionError):
            proof.native_output(raw, 0)

    def test_25_peer_error_application_and_ledger_substitution(self):
        for section in ("connections", "events"):
            report = peer_report()
            if section == "connections":
                report[section][0]["received_bytes"] = 1
            else:
                report[section][-1].update(bytes=1, hex="00")
            with self.assertRaises(AssertionError):
                proof.inspect_peer(report, 123, 456)

    def test_26_peer_pid_namespace_and_tuple_binding(self):
        for key in ("pid", "network_namespace_inode"):
            report = peer_report()
            report[key] += 1
            with self.assertRaises(AssertionError):
                proof.inspect_peer(report, 123, 456)
        report = peer_report()
        report["connections"][1]["source"][1] = 7100
        with self.assertRaises(AssertionError):
            proof.inspect_peer(report, 123, 456)

    def test_27_peer_echo_halfclose_and_monotonic_events(self):
        for action in (lambda r: r["connections"][1].update(sent=63),
                       lambda r: r["connections"][1].update(eof=False),
                       lambda r: r["events"][-1].update(monotonic_ns=2),
                       lambda r: r.update(sockets_closed=False),
                       lambda r: r.update(runner_stop_received=False),
                       lambda r: r.update(runner_stop_monotonic_ns=0),
                       lambda r: r.update(runner_stop_monotonic_ns=111),
                       lambda r: r.update(runner_stop_monotonic_ns=True),
                       lambda r: r.update(runner_stop_monotonic_ns=2)):
            report = peer_report()
            action(report)
            with self.assertRaises(AssertionError):
                proof.inspect_peer(report, 123, 456)

    def test_28_exact_tx_arp_padding_only(self):
        value = vector("arp_request")
        self.assertTrue(proof.frame_equal("tx", value, value + bytes(18)))
        self.assertFalse(proof.frame_equal("rx", value, value + bytes(18)))
        self.assertFalse(proof.frame_equal("tx", value, value + bytes(17) + b"\1"))
        self.assertFalse(proof.frame_equal("tx", value, value + bytes(19)))

    def test_29_exact_tcp54_control_padding_flags(self):
        for flag in (0x10, 0x11, 0x14, 0x04):
            value = bytearray(vector("pure_ack54"))
            value[47] = flag
            value = recalculate(value)
            with self.subTest(flag=flag):
                self.assertTrue(proof.frame_equal("tx", value, value + bytes(6)))
                self.assertFalse(proof.frame_equal("rx", value, value + bytes(6)))

    def test_30_tcp_padding_rejects_data_syn_options_lengths_and_nonzero(self):
        pure = vector("pure_ack54")
        for tail in (bytes(5), bytes(7), bytes(5) + b"\1"):
            self.assertFalse(proof.frame_equal("tx", pure, pure + tail))
        for name in ("positive_syn", "positive_data", "positive_ack"):
            value = vector(name)
            self.assertFalse(proof.frame_equal("tx", value, value + bytes(max(0, 60 - len(value))) + b"\0"))
        for flag in (0x02, 0x12, 0x18, 0x00, 0xff):
            value = bytearray(pure)
            value[47] = flag
            value = recalculate(value)
            self.assertFalse(proof.frame_equal("tx", value, value + bytes(6)))

    def test_31_tcp_padding_rejects_checksum_fragment_and_other_protocol(self):
        pure = vector("pure_ack54")
        for offset in (24, 50):
            value = bytearray(pure)
            value[offset] ^= 1
            self.assertFalse(proof.frame_equal("tx", bytes(value), bytes(value) + bytes(6)))
        for offset, byte in ((20, 0x60), (14, 0x46), (23, 1), (46, 0x60)):
            value = bytearray(pure)
            value[offset] = byte
            value = recalculate(value)
            self.assertFalse(proof.frame_equal("tx", value, value + bytes(6)))

    def late_old_tx(self, after, positive=False):
        """Keep source, both censuses and fence counters consistent."""
        lines, captured, egress = baseline()
        insertion = next(i + 1 for i, row in enumerate(lines) if after in row)
        for index in range(insertion, len(lines)):
            if "FRAME " in lines[index] and "direction=tx " in lines[index]:
                fields = dict(part.split("=") for part in lines[index].split()[3:])
                lines[index] = lines[index].replace("ordinal=" + fields["ordinal"] + " ", "ordinal=" + str(int(fields["ordinal"]) + 1) + " ")
            if "FENCED " in lines[index]:
                lines[index] = lines[index].replace("tx_before=4 tx_after=4", "tx_before=5 tx_after=5")
        value = vector("negative_data")
        at = 195 if positive else (190 if "REFUSED" in after else 185)
        lines.insert(insertion, f"TCP MTU FRAME v=1 direction=tx ordinal=5 phase={'positive' if positive else 'refusal'} at_ms={at} bytes={len(value)} hex={value.hex()}")
        captured.insert(7, (7, [1000, 6500], value))
        captured = [(i, stamp, frame) for i, (_, stamp, frame) in enumerate(captured)]
        return lines, captured, egress

    def test_32_consumed_error_stops_same_poll_egress(self):
        for after in ("FRAME v=1 direction=rx ordinal=3 ", "REFUSED "):
            lines, captured, egress = self.late_old_tx(after)
            with self.subTest(after=after), self.assertRaisesRegex(AssertionError, "old tuple TX after consumed MTU error"):
                evaluate(lines, captured, egress)

    def test_33_no_old_application_data_after_explicit_revoke(self):
        lines, captured, egress = self.late_old_tx("POSITIVE ", positive=True)
        with self.assertRaisesRegex(AssertionError, "post-revoke old tuple only generic stack RST"):
            evaluate(lines, captured, egress)

    def test_34_error_peer_needs_actual_terminal_read(self):
        report = peer_report()
        report["events"] = [event for event in report["events"] if event["port"] != 42100 or event["event"] != "read"]
        with self.assertRaises(AssertionError):
            proof.inspect_peer(report, 123, 456)

    def test_35_positive_peer_needs_shutdown_witness(self):
        report = peer_report()
        report["events"] = [event for event in report["events"] if event["event"] != "shutdown-write"]
        with self.assertRaises(AssertionError):
            proof.inspect_peer(report, 123, 456)

    def test_36_every_phase_terminal_obeys_original_budget(self):
        for marker, old, new in (("FENCED ", "at_ms=191", "at_ms=12100"),
                                 ("REVOKED ", "at_ms=192", "at_ms=12100"),
                                 ("DONE ", "at_ms=330", "at_ms=10193")):
            with self.subTest(marker=marker), self.assertRaisesRegex(AssertionError, "original (refusal|positive) guest budget"):
                evaluate(self.mutate_line(marker, old, new))


if __name__ == "__main__":
    unittest.main()
