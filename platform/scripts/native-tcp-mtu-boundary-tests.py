#!/usr/bin/env python3
"""Finite synthetic artifact controls; no native/router execution claim."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


proof = module("boundary_controls", "native-tcp-mtu-boundary-matrix.py")
old_controls = module("mtu_vector_constructors", "native-tcp-mtu-tests.py")
VECTORS = json.loads((HERE.parent / "fixtures/native-tcp-mtu-boundary/v1.json").read_text())


def vector(name):
    return bytes.fromhex(VECTORS["frames"][name]["hex"])


def baseline():
    lines, captured, downstream = [], [], []
    counters, transaction = {"tx": 0, "rx": 0}, 0

    def line(kind, **values):
        lines.append("TCP MTU BOUNDARY " + kind + " v=1 " + " ".join(key + "=" + str(value) for key, value in values.items()))

    def frame(name, direction, phase, at, control=False):
        value = bytes.fromhex(VECTORS["cases"][name]["hex"]) if control else vector(name)
        counters[direction] += 1
        line("FRAME", direction=direction, ordinal=counters[direction], phase=phase, at_ms=at, bytes=len(value), hex=value.hex())
        captured.append((len(captured), [1000, len(captured) * 1000], value + bytes(18) if name == "arp_request" else value))
        if value[12:14] == b"\x08\0" and value[23] == 6:
            downstream.append((len(downstream), [1000, len(downstream) * 1000], old_controls.routed(value)))
        return counters[direction]

    def rpc(at, slot, phase, op, status=0, amount=0, body=b"", payload=b""):
        nonlocal transaction
        transaction += 1
        port = 42101 if slot == "unaffected" else 42100
        destination = proof.peer.PEER + port.to_bytes(2, "big")
        request = bytes((4, op, 0, 0)) + destination + amount.to_bytes(2, "big") + body
        count = 576 if status == 17 else (len(payload) if op in (16, 17, 19) and not status else amount if op == 18 and not status else 0)
        reply = bytes((4, op, status, 0)) + destination + count.to_bytes(2, "big") + payload
        line("RPC", index=transaction, slot=slot, logical=proof.SLOTS[slot], phase=phase, at_ms=at,
             request_bytes=len(request), request_hex=request.hex(), reply_bytes=len(reply), reply_hex=reply.hex())

    def grant(slot, at):
        line("GRANT", slot=slot, logical=proof.SLOTS[slot], local_port=7101 if slot == "unaffected" else 7100,
             peer_port=42101 if slot == "unaffected" else 42100, at_ms=at, until_ms=30100)

    line("BEGIN", start_ms=100, until_ms=30100, guest="192.0.2.100", router="192.0.2.1", peer="198.51.100.2")
    grant("target", 101)
    grant("unaffected", 102)
    frame("arp_request", "tx", "setup", 104)
    frame("arp_reply", "rx", "setup", 105)
    frame("negative_syn", "tx", "setup", 110)
    rpc(115, "target", "setup", 16, payload=b"\0")
    frame("negative_synack", "rx", "setup", 120)
    frame("negative_ack", "tx", "setup", 125)
    rpc(130, "target", "setup", 17, payload=b"\1")
    line("CONNECTED", slot="target", logical=1, at_ms=130, sockets=1)
    frame("positive_syn", "tx", "setup", 140)
    rpc(145, "unaffected", "setup", 16, payload=b"\0")
    frame("positive_synack", "rx", "setup", 150)
    frame("positive_ack", "tx", "setup", 155)
    rpc(160, "unaffected", "setup", 17, payload=b"\1")
    line("CONNECTED", slot="unaffected", logical=2, at_ms=160, sockets=2)
    rpc(170, "target", "cases", 18, amount=1024, body=proof.peer.BODY)
    line("QUEUED", slot="target", logical=1, at_ms=170, bytes=1024)
    frame("negative_data", "tx", "cases", 180)
    frame("target_data_ack", "rx", "cases", 190)
    line("CONTROLS_READY", at_ms=200, target_logical=1, unaffected_logical=2, sockets=2)
    for index, at in enumerate((210, 230, 250)):
        ordinal = frame(index, "rx", "cases", at, control=True)
        rpc(at + 10, "target", "cases", 17, payload=b"\1")
        line("CASE", index=index, case=proof.peer.CASES[index], receive_ordinal=ordinal, at_ms=at + 10,
             code=0, connected=1, sockets=2, logical=1, until_ms=30100)
    ordinal = frame(3, "rx", "matching", 270, control=True)
    rpc(280, "target", "matching", 17, status=17)
    line("REFUSED", at_ms=280, receive_ordinal=ordinal, code=17, mtu=576, sockets=1, logical=1, until_ms=30100, effects="unknown")
    line("FENCED", at_ms=281, code=8, logical=1, rpc_before=transaction, rpc_after=transaction, tx_before=counters["tx"], tx_after=counters["tx"])
    line("REVOKED", slot="target", logical=1, at_ms=282, sockets=1)
    rpc(290, "unaffected", "survivor", 17, payload=b"\1")
    rpc(300, "unaffected", "survivor", 18, amount=64, body=proof.peer.ECHO)
    line("QUEUED", slot="unaffected", logical=2, at_ms=300, bytes=64)
    rpc(310, "unaffected", "survivor", 20)
    frame("positive_data", "tx", "survivor", 320)
    frame("positive_fin", "tx", "survivor", 330)
    frame("positive_echo", "rx", "survivor", 340)
    rpc(350, "unaffected", "survivor", 19, amount=64, payload=proof.peer.ECHO)
    line("OBSERVED", slot="unaffected", logical=2, at_ms=350, bytes=64, hex=proof.peer.ECHO.hex(), sockets=1)
    frame("positive_reply_fin", "rx", "survivor", 360)
    rpc(370, "unaffected", "survivor", 19, status=6, amount=64)
    line("EOF", slot="unaffected", logical=2, at_ms=370, code=6)
    frame("positive_final_ack", "tx", "survivor", 380)
    line("REVOKED", slot="unaffected", logical=2, at_ms=390, sockets=0)
    grant("reserved", 400)
    rpc(410, "reserved", "reserved", 17, payload=b"\0")
    line("EMPTY_READY", at_ms=410, logical=3, sockets=0, until_ms=30100)
    ordinal = frame(4, "rx", "reserved", 420, control=True)
    rpc(430, "reserved", "reserved", 17, payload=b"\0")
    line("CASE", index=4, case="empty-history", receive_ordinal=ordinal, at_ms=430, code=0, connected=0, sockets=0, logical=3, until_ms=30100)
    line("REVOKED", slot="reserved", logical=3, at_ms=440, sockets=0)
    line("DONE", at_ms=450, sockets=0, target_bytes=1024, unaffected_bytes=64, cases=4)
    return lines, captured, downstream


def evaluated(lines=None, captured=None, downstream=None):
    canonical, frames, route = baseline()
    native = proof.native_output(old_controls.serial(canonical if lines is None else lines), 3)
    checked = proof.inspect_frames(frames if captured is None else captured, native)
    proof.inspect_route(frames if captured is None else captured, route if downstream is None else downstream)
    return native, checked


def reports(native, wire):
    acknowledgements = native["cases"][:3] + [native["events"]["REFUSED"], native["cases"][3]]
    actor = {"schema": "absd-tcp-mtu-boundary-actor/1", "disposition": "PASS", "mode": "actor", "pid": 123,
             "network_namespace_inode": 456, "raw_socket_closed": True, "submitted": wire["submitted"],
             "start_monotonic_ns": 1, "end_monotonic_ns": 110,
             "reads": [{"at_monotonic_ns": 2, "packet_type": 0, "frame": wire["submitted"]}],
             "cases": [{"index": index, "case": proof.peer.CASES[index], "frame": wire["raw_controls"][index],
                        "send_monotonic_ns": 10 + index * 20, "ack_read_monotonic_ns": 20 + index * 20,
                        "native_acknowledgement": acknowledgements[index]} for index in range(5)]}
    server = {"schema": "absd-tcp-mtu-boundary-server/1", "mode": "server", "disposition": "PASS", "pid": 234,
              "network_namespace_inode": 567, "sockets_closed": True, "runner_stop_received": True,
              "start_monotonic_ns": 1, "end_monotonic_ns": 100,
              "connections": [{"port": port, "source": ["192.0.2.100", local], "received": proof.peer.identity(body),
                               "sent": 0 if port == 42100 else 64, "eof": port == 42101, "write_closed": port == 42101}
                              for port, local, body in ((42100, 7100, proof.peer.BODY), (42101, 7101, proof.peer.ECHO))],
              "events": [{"event": "accept", "port": 42100, "monotonic_ns": 10, "source": ["192.0.2.100", 7100]},
                         {"event": "accept", "port": 42101, "monotonic_ns": 20, "source": ["192.0.2.100", 7101]},
                         {"event": "read", "port": 42100, "monotonic_ns": 30, "bytes": 1024, "hex": proof.peer.BODY.hex()},
                         {"event": "read", "port": 42101, "monotonic_ns": 40, "bytes": 64, "hex": proof.peer.ECHO.hex()},
                         {"event": "write", "port": 42101, "monotonic_ns": 50, "offset": 0, "bytes": 64, "hex": proof.peer.ECHO.hex()},
                         {"event": "read", "port": 42101, "monotonic_ns": 60, "bytes": 0, "hex": ""},
                         {"event": "shutdown-write", "port": 42101, "monotonic_ns": 70, "bytes": 64}]}
    return actor, server


class BoundaryControls(unittest.TestCase):
    def changed(self, marker, old, new):
        lines, _, _ = baseline()
        indices = [i for i, row in enumerate(lines) if marker in row]
        self.assertEqual(len(indices), 1)
        i = indices[0]
        self.assertIn(old, lines[i])
        lines[i] = lines[i].replace(old, new)
        return lines

    def test_01_full_synthetic_witness(self):
        native, wire = evaluated()
        actor, server = reports(native, wire)
        proof.inspect_actor(actor, native, wire, 123, 456)
        proof.inspect_server(server, 234, 567)

    def test_02_literal_constructor_relations(self):
        submitted = vector("negative_data")
        for row in VECTORS["cases"]:
            frame = bytes.fromhex(row["hex"])
            self.assertEqual(proof.peer.identity(frame), {key: row[key] for key in ("bytes", "sha256", "hex")})
            self.assertEqual(frame, proof.peer.control(submitted, row["case"]))
            self.assertEqual(proof.peer.checksum(frame[14:34]), 0)
            self.assertEqual(proof.peer.checksum(frame[34:]) == 0, row["case"] != "bad-checksum")
        self.assertEqual(VECTORS["cases"][3]["hex"], VECTORS["cases"][4]["hex"])

    def test_03_repaired_bad_checksum_cannot_substitute_case(self):
        lines, frames, route = baseline()
        old = bytes.fromhex(VECTORS["cases"][0]["hex"])
        good = bytes.fromhex(VECTORS["cases"][3]["hex"])
        lines = [row.replace(old.hex(), good.hex()) for row in lines]
        frames = [(i, stamp, good if frame == old else frame) for i, stamp, frame in frames]
        with self.assertRaisesRegex(AssertionError, "exact independently selected raw control"):
            evaluated(lines, frames, route)

    def test_04_wrong_sequence_and_equal_mtu_are_exact(self):
        for index in (1, 2):
            lines, frames, route = baseline()
            old = bytes.fromhex(VECTORS["cases"][index]["hex"])
            changed = bytearray(old)
            changed[-1] ^= 2
            changed = old_controls.recalculate(changed)
            lines = [row.replace(old.hex(), changed.hex()) for row in lines]
            frames = [(i, stamp, changed if frame == old else frame) for i, stamp, frame in frames]
            with self.assertRaises(AssertionError):
                evaluated(lines, frames, route)

    def test_05_missing_duplicate_or_wrong_case(self):
        lines, _, _ = baseline()
        case = next(row for row in lines if "CASE v=1 index=1 " in row)
        for changed in ([row for row in lines if row != case], lines + [case],
                        self.changed("CASE v=1 index=1 ", "case=wrong-sequence", "case=bad-checksum")):
            with self.assertRaises(AssertionError):
                evaluated(changed)

    def test_06_missing_or_substituted_native_rx(self):
        for marker, old, new in (("CASE v=1 index=0 ", "receive_ordinal=5", "receive_ordinal=4"),
                                  ("CASE v=1 index=4 ", "receive_ordinal=11", "receive_ordinal=10")):
            with self.assertRaises(AssertionError):
                evaluated(self.changed(marker, old, new))

    def test_07_after_each_input_actual_status_required(self):
        lines, _, _ = baseline()
        at = next(i for i, row in enumerate(lines) if "RPC v=1 index=6 " in row)
        moved = lines.pop(at)
        before = next(i for i, row in enumerate(lines) if "FRAME v=1 direction=rx ordinal=5 " in row)
        lines.insert(before, moved.replace("at_ms=220", "at_ms=205"))
        with self.assertRaisesRegex(AssertionError, "actual STATUS transaction after selected RX"):
            evaluated(lines)

    def test_08_unaffected_was_already_connected(self):
        lines, _, _ = baseline()
        with self.assertRaises(AssertionError):
            evaluated([row for row in lines if "CONNECTED v=1 slot=unaffected " not in row])
        with self.assertRaises(AssertionError):
            evaluated(self.changed("CONNECTED v=1 slot=unaffected ", "logical=2", "logical=3"))
        for marker, old, new in (("CONNECTED v=1 slot=target ", "sockets=1", "sockets=2"),
                                  ("CONNECTED v=1 slot=unaffected ", "sockets=2", "sockets=1")):
            with self.assertRaises(AssertionError):
                evaluated(self.changed(marker, old, new))

    def test_09_bad_input_must_preserve_both_grants(self):
        for old, new in (("code=0", "code=17"), ("connected=1", "connected=0"), ("sockets=2", "sockets=1")):
            with self.assertRaises(AssertionError):
                evaluated(self.changed("CASE v=1 index=1 ", old, new))

    def test_10_matched_raw_control_must_fence_only_target(self):
        for old, new in (("code=17", "code=8"), ("mtu=576", "mtu=575"), ("sockets=1", "sockets=0"),
                         ("logical=1", "logical=2"), ("effects=unknown", "effects=none")):
            with self.assertRaises(AssertionError):
                evaluated(self.changed("REFUSED ", old, new))

    def test_11_client_fence_has_no_new_rpc_or_tx(self):
        for old, new in (("rpc_after=9", "rpc_after=10"), ("tx_after=6", "tx_after=7"), ("code=8", "code=0")):
            with self.assertRaises(AssertionError):
                evaluated(self.changed("FENCED ", old, new))

    def test_12_same_survivor_connection_not_reconnect(self):
        with self.assertRaises(AssertionError):
            evaluated(self.changed("RPC v=1 index=10 ", "04110000", "04100000"))
        with self.assertRaises(AssertionError):
            evaluated(self.changed("QUEUED v=1 slot=unaffected ", "logical=2", "logical=4"))

    def test_13_survivor_echo_eof_and_socket_retirement(self):
        lines, _, _ = baseline()
        for selected in (" EOF ", "REVOKED v=1 slot=unaffected "):
            with self.assertRaises(AssertionError):
                evaluated([row for row in lines if selected not in row])
        with self.assertRaises(AssertionError):
            evaluated(self.changed("OBSERVED ", "hex=000102", "hex=010102"))

    def test_14_empty_history_no_connect_or_transmission(self):
        with self.assertRaises(AssertionError):
            evaluated(self.changed("RPC v=1 index=15 ", "04110000", "04100000"))
        lines, frames, route = baseline()
        at = next(i for i, row in enumerate(lines) if "EMPTY_READY " in row)
        value = vector("pure_ack54")
        lines.insert(at, f"TCP MTU BOUNDARY FRAME v=1 direction=tx ordinal=10 phase=reserved at_ms=410 bytes=54 hex={value.hex()}")
        frames.insert(-1, (999, [1000, 19500], value))
        # Control is intentionally complete at the native parser layer; the
        # no-TX interval is asserted independently of the packet census.
        native = proof.native_records(("\n".join(lines) + "\n").encode())
        start, stop = native["positions"]["GRANT:reserved"], native["positions"]["REVOKED:reserved"]
        self.assertTrue(any(start < native["positions"]["FRAME:tx:" + row["ordinal"]] < stop for row in native["frames"] if row["direction"] == "tx"))
        with self.assertRaises(AssertionError):
            proof.inspect_frames(frames, native)

    def test_15_old_matching_quote_exact_on_new_empty_reservation(self):
        with self.assertRaises(AssertionError):
            evaluated(self.changed("CASE v=1 index=4 ", "connected=0", "connected=1"))
        with self.assertRaises(AssertionError):
            evaluated(self.changed("EMPTY_READY ", "logical=3", "logical=1"))
        for marker in ("EMPTY_READY ", "CASE v=1 index=4 "):
            with self.assertRaises(AssertionError):
                evaluated(self.changed(marker, "sockets=0", "sockets=1"))

    def test_16_original_budget_for_every_record_and_grant(self):
        for marker, old, new in (("DONE ", "at_ms=450", "at_ms=30100"),
                                  ("GRANT v=1 slot=reserved ", "until_ms=30100", "until_ms=30200"),
                                  ("CASE v=1 index=0 ", "until_ms=30100", "until_ms=30200"),
                                  ("FENCED ", "at_ms=281", "at_ms=0271")):
            with self.assertRaises(AssertionError):
                evaluated(self.changed(marker, old, new))

    def test_17_full_capture_and_route_census(self):
        _, frames, route = baseline()
        for changed in (frames[:-1], frames + [frames[0]], [frames[2], frames[1], frames[0]] + frames[3:]):
            with self.assertRaises(AssertionError):
                evaluated(captured=changed)
        for changed in (route[:-1], route + [route[0]]):
            with self.assertRaises(AssertionError):
                evaluated(downstream=changed)

    def test_18_tampered_tcp_data_and_checksum(self):
        _, frames, _ = baseline()
        at = next(i for i, (_, _, frame) in enumerate(frames) if frame == vector("positive_echo"))
        changed = bytearray(frames[at][2])
        changed[-1] ^= 1
        frames[at] = frames[at][0], frames[at][1], bytes(changed)
        with self.assertRaises(AssertionError):
            evaluated(captured=frames)

    def test_19_actor_pid_namespace_and_actual_ack_binding(self):
        native, wire = evaluated()
        actor, _ = reports(native, wire)
        for change in (lambda r: r.update(pid=124), lambda r: r.update(network_namespace_inode=457),
                       lambda r: r["cases"][0]["native_acknowledgement"].update(sockets="1")):
            value = copy.deepcopy(actor)
            change(value)
            with self.assertRaises(AssertionError):
                proof.inspect_actor(value, native, wire, 123, 456)

    def test_20_actor_send_order_complete_bytes_and_closed_socket(self):
        native, wire = evaluated()
        actor, _ = reports(native, wire)
        for change in (lambda r: r["cases"][1].update(send_monotonic_ns=1),
                       lambda r: r["cases"][3]["frame"].update(bytes=69),
                       lambda r: r.update(raw_socket_closed=False)):
            value = copy.deepcopy(actor)
            change(value)
            with self.assertRaises(AssertionError):
                proof.inspect_actor(value, native, wire, 123, 456)

    def test_21_ordinary_tcp_peer_body_and_halfclose_receipts(self):
        native, wire = evaluated()
        _, server = reports(native, wire)
        for change in (lambda r: r["connections"][0]["received"].update(bytes=0),
                       lambda r: r["connections"][1].update(eof=False),
                       lambda r: r.update(runner_stop_received=False),
                       lambda r: r["events"].pop()):
            value = copy.deepcopy(server)
            change(value)
            with self.assertRaises(AssertionError):
                proof.inspect_server(value, 234, 567)

    def test_22_original_serial_end_fnv_exit_and_nic(self):
        lines, _, _ = baseline()
        raw = old_controls.serial(lines)
        for changed in (raw.replace(b"USER EXIT pid=2 status=0", b"USER EXIT pid=2 status=1"),
                        raw.replace(b"EXTERNAL OUTPUT END bytes=", b"EXTERNAL OUTPUT END bytes=1"),
                        raw.replace(b"rx_refused=0", b"rx_refused=1")):
            with self.assertRaises(AssertionError):
                proof.native_output(changed, 3)
        with self.assertRaises(AssertionError):
            proof.native_output(raw, 0)

    def test_23_only_existing_narrow_tx_padding_relations(self):
        arp, tcp = vector("arp_request"), vector("pure_ack54")
        self.assertTrue(proof.prior.frame_equal("tx", arp, arp + bytes(18)))
        self.assertTrue(proof.prior.frame_equal("tx", tcp, tcp + bytes(6)))
        self.assertFalse(proof.prior.frame_equal("rx", arp, arp + bytes(18)))
        self.assertFalse(proof.prior.frame_equal("tx", tcp, tcp + bytes(5) + b"\1"))

    def test_24_matching_receive_stops_target_before_explicit_revoke(self):
        lines, frames, route = baseline()
        for i, row in enumerate(lines):
            if "FRAME v=1 direction=tx " in row:
                fields = dict(word.split("=") for word in row.split()[4:])
                ordinal = int(fields["ordinal"])
                if ordinal >= 7:
                    lines[i] = row.replace(f"ordinal={ordinal} ", f"ordinal={ordinal + 1} ")
            elif " FENCED " in row:
                lines[i] = row.replace("tx_before=6 tx_after=6", "tx_before=7 tx_after=7")
        value = vector("negative_data")
        at = next(i for i, row in enumerate(lines) if "RPC v=1 index=9 " in row)
        lines.insert(at, f"TCP MTU BOUNDARY FRAME v=1 direction=tx ordinal=7 phase=matching at_ms=275 bytes={len(value)} hex={value.hex()}")
        selected = bytes.fromhex(VECTORS["cases"][3]["hex"])
        at = next(i for i, (_, _, frame) in enumerate(frames) if frame == selected) + 1
        frames.insert(at, (999, [1000, 12500], value))
        at = next(i for i, (_, _, frame) in enumerate(route) if frame == old_controls.routed(value)) + 1
        route.insert(at, (999, [1000, 12500], old_controls.routed(value)))
        native = proof.native_output(old_controls.serial(lines), 3)
        # These checks succeed for the mutation: the rejection below must
        # come from the consumed-input boundary, not a stale count or capture.
        proof.inspect_route(frames, route)
        self.assertEqual(native["events"]["FENCED"]["tx_after"], "7")
        with self.assertRaisesRegex(AssertionError, "target stopped after consumed matching advice"):
            proof.inspect_frames(frames, native)

    def test_25_echo_writes_require_accepted_already_read_prefix(self):
        native, wire = evaluated()
        _, server = reports(native, wire)
        variants = []
        for before, stamp, reason in (("accept", 15, "echo write requires accepted connection"),
                                       ("read", 35, "echo write requires already-read prefix")):
            value = copy.deepcopy(server)
            at = next(i for i, row in enumerate(value["events"]) if row["event"] == "write")
            write = value["events"].pop(at)
            write["monotonic_ns"] = stamp
            at = next(i for i, row in enumerate(value["events"]) if row["event"] == before and row["port"] == 42101)
            value["events"].insert(at, write)
            variants.append((value, reason))
        # A nonempty earlier read alone is insufficient: preserve the exact
        # final 64-byte body but deliver only its first 32 bytes before write.
        value = copy.deepcopy(server)
        at = next(i for i, row in enumerate(value["events"]) if row["event"] == "read" and row["port"] == 42101)
        value["events"][at].update(bytes=32, hex=proof.peer.ECHO[:32].hex())
        at = next(i for i, row in enumerate(value["events"]) if row["event"] == "write") + 1
        value["events"].insert(at, {"event": "read", "port": 42101, "monotonic_ns": 55,
                                     "bytes": 32, "hex": proof.peer.ECHO[32:].hex()})
        variants.append((value, "echo write requires already-read prefix"))
        for value, reason in variants:
            with self.subTest(reason=reason, events=len(value["events"])):
                self.assertEqual(value["connections"], server["connections"])
                times = [row["monotonic_ns"] for row in value["events"]]
                self.assertEqual(times, sorted(times))
                self.assertEqual(sum(row["bytes"] for row in value["events"] if row["event"] == "write"), 64)
                with self.assertRaisesRegex(AssertionError, reason):
                    proof.inspect_server(value, 234, 567)


if __name__ == "__main__":
    unittest.main()
