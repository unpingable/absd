#!/usr/bin/env python3
"""Finite synthetic controls calling the actual delegated checker; native UNRUN."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


proof = module("delegated_controls", "native-tcp-mtu-delegated-matrix.py")
old = module("delegated_literal_constructors", "native-tcp-mtu-tests.py")


def baseline():
    original, captured, egress = old.baseline()
    rows = []

    def add(record_kind, **values):
        row = {"v": "1", **{key: str(value) for key, value in values.items()}}
        rows.append([record_kind, row])
        return row

    def census(label, after=False):
        add("CENSUS", label=label, processes=1, handles=2, pipes=0, cells=0, frames=103 if after else 100)

    prior = []
    for line in original:
        words = line.split()
        prior.append((words[2], dict(word.split("=") for word in words[3:])))
    add("BEGIN", start_ms=100, until_ms=30100, refusal_until_ms=12100, guest="192.0.2.100", router="192.0.2.1", peer="198.51.100.2")
    for child in (1, 2):
        phase = "refusal" if child == 1 else "positive"
        at, until, boot_at = (101, 12100, 103) if child == 1 else (198, 10197, 200)
        census(phase + "-before")
        add("GRANT", child=child, phase=phase, local_port=7099 + child, peer_port=42099 + child, at_ms=at, until_ms=until, lifetime_ms=until - at)
        # Handle slots may be reused; kernel process IDs below must be distinct.
        add("SPAWN", child=child, phase=phase, process_handle=11, at_ms=at + 1, no_spawn=1, nic_copies=0, protocol_handles=2, diagnostic_handles=2)
        boot = b"MTUD\x01" + bytes([child]) + proof.PEER_IP + (42099 + child).to_bytes(2, "big") + until.to_bytes(8, "big")
        add("BOOTSTRAP", child=child, phase=phase, at_ms=boot_at, bytes=20, hex=boot.hex())
        phase_rpc = [row for kind, row in prior if kind == "RPC" and row["phase"] == phase]
        ledgers = {}
        for observer in ("child", "owner"):
            records, offsets, ordinals = [], {"request": 0, "reply": 0}, {"request": 0, "reply": 0}

            def emit(direction, value, stamp):
                width = 128 if observer == "owner" else 256
                parts = [b""] if not value else [value[i:i + width] for i in range(0, len(value), width)]
                for part in parts:
                    ordinals[direction] += 1
                    records.append({"v": "1", "observer": observer, "child": str(child), "phase": phase, "direction": direction,
                        "ordinal": str(ordinals[direction]), "offset": str(offsets[direction]), "at_ms": str(stamp),
                        "bytes": str(len(part)), "hex": part.hex() if part else "none"})
                    offsets[direction] += len(part)
            emit("reply", boot, boot_at)
            for row in phase_rpc:
                stamp = int(row["at_ms"])
                request, reply = bytes.fromhex(row["request_hex"]), bytes.fromhex(row["reply_hex"])
                # Client writes and Channel reads the request prefix apart
                # from its body. Channel may publish a complete short reply;
                # Client reads its reply prefix separately from the body.
                emit("request", len(request).to_bytes(2, "big"), stamp - 1)
                emit("request", request, stamp - 1)
                if observer == "owner":
                    emit("reply", len(reply).to_bytes(2, "big") + reply, stamp)
                else:
                    emit("reply", len(reply).to_bytes(2, "big"), stamp)
                    emit("reply", reply, stamp)
            if observer == "owner":
                emit("request", b"", 193 if child == 1 else 322)
            reads = ordinals["request" if observer == "owner" else "reply"] + 3
            writes = ordinals["reply" if observer == "owner" else "request"] + 2
            seal = {"v": "1", "observer": observer, "child": str(child), "phase": phase, "records": str(len(records)),
                "request_bytes": str(offsets["request"]), "reply_bytes": str(offsets["reply"]), "read_calls": str(reads), "write_calls": str(writes),
                "request_eof": str(193 if child == 1 else 322) if observer == "owner" else "none", "reply_eof": "none", "failed": "0"}
            ledgers[observer] = records, seal
        add("REAP", child=child, phase=phase, reaped_ms=194 if child == 1 else 323, at_ms=195 if child == 1 else 325,
            kind=1, status=0, request_eof_ms=193 if child == 1 else 322, result_eof_ms=194 if child == 1 else 324, channel_live=0, eof_revoked=1)
        add("CHILD_BEGIN", child=child, phase=phase, at_ms=104 if child == 1 else 200, until_ms=until, nic=0, bootstrap_bytes=20, bootstrap_hex=boot.hex())
        add("CHILD_CONNECTED", child=child, phase=phase, at_ms=150 if child == 1 else 230)
        add("CHILD_QUEUED", child=child, phase=phase, at_ms=160 if child == 1 else 240, bytes=1024 if child == 1 else 64)
        if child == 1:
            add("CHILD_REFUSED", child=1, phase=phase, at_ms=190, code=17, mtu=576, effects="unknown")
            seal = ledgers["child"][1]
            values = {}
            for label, field in (("request", "request_bytes"), ("reply", "reply_bytes"), ("reads", "read_calls"), ("writes", "write_calls")):
                values[label + "_before"] = values[label + "_after"] = seal[field]
            add("CHILD_FENCED", child=1, phase=phase, at_ms=191, read_code=8, write_code=8, **values)
        else:
            add("CHILD_OBSERVED", child=2, phase=phase, at_ms=290, bytes=64, hex=proof.peer.POSITIVE.hex())
            add("CHILD_EOF", child=2, phase=phase, at_ms=310, code=6)
        add("CHILD_DONE", child=child, phase=phase, at_ms=192 if child == 1 else 321, nic=0)
        for observer in ("child", "owner"):
            records, seal = ledgers[observer]
            rows.extend(["PIPE", row] for row in records)
            rows.append(["PIPE_SEAL", seal])
        for kind, row in prior:
            if kind == "FRAME" and row["phase"] == phase:
                rows.append(["FRAME", row])
        frame_rows = [row for kind, row in rows if kind == "FRAME"]
        add("FRAME_SEAL", phase=phase, records=len(frame_rows), tx=sum(row["direction"] == "tx" for row in frame_rows), rx=sum(row["direction"] == "rx" for row in frame_rows))
        census(phase + "-after", after=True)
        add("RETIRED", child=child, phase=phase, explicit_revoke_ms=196 if child == 1 else 326,
            channel_live_before_explicit=0, channel_live=0, process_handle_live=0, protocol_handles=0, result_handles=0, sockets=0, objects_restored=1)
        if child == 1:
            add("POSITIVE", at_ms=197, until_ms=10197, child=2, fresh_grant=1, old_child_retired=1)
    add("DONE", at_ms=330, children=2, sockets=0, negative_bytes=1024, positive_bytes=64)
    return rows, captured, egress


def encoded(rows):
    return ("\n".join("TCP MTU DELEGATED " + kind + " " + " ".join(key + "=" + value for key, value in row.items()) for kind, row in rows) + "\n").encode()


def serial(rows):
    raw = old.serial(encoded(rows).decode().splitlines())
    children = b"SPAWN OK pid=3 parent=2 program=tcp-mtu-delegated-client\nUSER EXIT pid=3 status=0\nSPAWN OK pid=4 parent=2 program=tcp-mtu-delegated-client\nUSER EXIT pid=4 status=0\n"
    return raw.replace(b"USER EXIT pid=2 status=0\n", children + b"USER EXIT pid=2 status=0\n")


def evaluated(rows=None, capture=None, egress=None):
    original, frames, route = baseline()
    native = proof.native_output(serial(original if rows is None else rows), 3)
    wire = proof.inspect_frames(frames if capture is None else capture, native, route if egress is None else egress)
    return native, wire


def selected(rows, kind, child=None, **fields):
    values = [row for k, row in rows if k == kind and (child is None or row.get("child") == str(child)) and all(row.get(key) == value for key, value in fields.items())]
    assert len(values) == 1
    return values[0]


class DelegatedControls(unittest.TestCase):
    def refused(self, kind, child, key, value):
        rows, _, _ = baseline()
        selected(rows, kind, child)[key] = value
        with self.assertRaises((AssertionError, ValueError)):
            evaluated(rows)

    def test_01_complete_synthetic_two_child_witness(self):
        native, wire = evaluated()
        self.assertEqual(native["transactions"][1][-1]["code"], 17)
        self.assertEqual(native["child_pids"], [3, 4])
        self.assertTrue(wire["ICMP_matches"])

    def test_02_different_real_chunk_boundaries_same_streams(self):
        native, _ = evaluated()
        self.assertNotEqual(len(native["pipes"]["owner", 1]), len(native["pipes"]["child", 1]))

    def test_03_missing_duplicate_or_unknown_record(self):
        rows, _, _ = baseline()
        for changed in (rows[:-1], rows + [rows[-1]], rows + [["OTHER", {"v": "1"}]]):
            with self.assertRaises(AssertionError): proof.native_records(encoded(changed))

    def test_04_no_nic_or_spawn_authority_expansion(self):
        for kind, key, value in (("SPAWN", "no_spawn", "0"), ("SPAWN", "nic_copies", "1"), ("CHILD_BEGIN", "nic", "1"), ("CHILD_DONE", "nic", "1")):
            self.refused(kind, 1, key, value)

    def test_05_bootstrap_literal_tuple_deadline_and_logical(self):
        for key, value in (("bytes", "19"), ("hex", "00" * 20)):
            self.refused("BOOTSTRAP", 1, key, value)
        self.refused("CHILD_BEGIN", 1, "bootstrap_hex", "00" * 20)
        self.refused("GRANT", 1, "peer_port", "42101")

    def test_06_actual_owner_child_bytes_must_match(self):
        rows, _, _ = baseline()
        row = next(row for kind, row in rows if kind == "PIPE" and row["observer"] == "owner" and row["direction"] == "reply")
        row["hex"] = "00" + row["hex"][2:]
        with self.assertRaisesRegex(AssertionError, "independent owner/child actual byte streams"): evaluated(rows)

    def test_07_offsets_ordinals_and_counts_are_exact(self):
        for key, value in (("offset", "1"), ("ordinal", "2"), ("bytes", "257")):
            rows, _, _ = baseline()
            row = next(row for kind, row in rows if kind == "PIPE")
            row[key] = value
            with self.assertRaises((AssertionError, ValueError)): evaluated(rows)

    def test_08_missing_real_request_eof_cannot_be_timeout(self):
        rows, _, _ = baseline()
        selected(rows, "PIPE_SEAL", 1, observer="owner")["request_eof"] = "none"
        with self.assertRaises(AssertionError): evaluated(rows)
        self.refused("REAP", 1, "request_eof_ms", "0")

    def test_09_result_eof_and_normal_reap_required(self):
        for key, value in (("status", "1"), ("kind", "3"), ("result_eof_ms", "196"), ("result_eof_ms", "0"), ("reaped_ms", "0"), ("eof_revoked", "0"), ("channel_live", "1")):
            self.refused("REAP", 1, key, value)

    def test_10_no_later_child_pipe_calls_after_fencing(self):
        for key in ("request_after", "reply_after", "reads_after", "writes_after"):
            rows, _, _ = baseline(); row = selected(rows, "CHILD_FENCED", 1); row[key] = str(int(row[key]) + 1)
            with self.assertRaisesRegex(AssertionError, "two stale calls"): evaluated(rows)

    def test_11_typed_terminal_reason_and_both_stale_operations(self):
        for kind, key, value in (("CHILD_REFUSED", "code", "14"), ("CHILD_REFUSED", "mtu", "575"), ("CHILD_REFUSED", "effects", "none"), ("CHILD_FENCED", "read_code", "0"), ("CHILD_FENCED", "write_code", "17")):
            self.refused(kind, 1, key, value)

    def test_12_typed_reply_substitution_in_both_observers(self):
        rows, _, _ = baseline()
        for kind, row in rows:
            if kind == "PIPE" and row["direction"] == "reply" and row["child"] == "1":
                value = bytes.fromhex(row["hex"])
                if value[:5] == b"\0\x0c\4\x13\x11":
                    value = value[:4] + b"\x08" + value[5:]
                    row["hex"] = value.hex()
                elif value[:3] == b"\4\x13\x11":
                    row["hex"] = (value[:2] + b"\x08" + value[3:]).hex()
        with self.assertRaises(AssertionError): evaluated(rows)

    def test_13_full_accepted_payload_not_marker_only(self):
        self.refused("CHILD_QUEUED", 1, "bytes", "1023")
        self.refused("CHILD_QUEUED", 2, "bytes", "63")

    def test_14_current_child_grant_and_original_budget(self):
        self.refused("GRANT", 1, "until_ms", "12101")
        self.refused("GRANT", 2, "lifetime_ms", "10000")
        self.refused("CHILD_DONE", 1, "at_ms", "12100")
        self.refused("CHILD_DONE", 2, "at_ms", "10197")

    def test_15_retirement_all_handles_sockets_and_objects(self):
        for key in ("process_handle_live", "protocol_handles", "result_handles", "sockets", "channel_live"):
            self.refused("RETIRED", 1, key, "1")
        self.refused("RETIRED", 1, "objects_restored", "0")

    def test_16_actual_census_not_only_restored_label(self):
        rows, _, _ = baseline(); selected(rows, "CENSUS", label="refusal-after")["pipes"] = "1"
        with self.assertRaisesRegex(AssertionError, "actual object restoration"): evaluated(rows)

    def test_17_fresh_child_after_retirement_not_handle_revival(self):
        rows, _, _ = baseline(); row = selected(rows, "POSITIVE"); row["old_child_retired"] = "0"
        with self.assertRaises(AssertionError): evaluated(rows)
        self.refused("GRANT", 2, "local_port", "7100")

    def test_18_positive_exact_echo_halfclose_eof(self):
        self.refused("CHILD_OBSERVED", 2, "hex", "00" * 64)
        self.refused("CHILD_EOF", 2, "code", "5")

    def test_19_complete_capture_and_router_census(self):
        _, frames, route = baseline()
        for changed in (frames[:-1], frames + [frames[0]]):
            with self.assertRaises(AssertionError): evaluated(capture=changed)
        with self.assertRaises(AssertionError): evaluated(egress=route[:-1])

    def test_20_matching_quote_checksum_and_actual_submission(self):
        _, frames, _ = baseline(); at = next(i for i, (_, _, f) in enumerate(frames) if f[23:24] == b"\1")
        i, stamp, frame = frames[at]; frames[at] = i, stamp, frame[:-1] + bytes([frame[-1] ^ 1])
        with self.assertRaises(AssertionError): evaluated(capture=frames)

    def test_21_native_frame_counter_and_phase_census(self):
        rows, _, _ = baseline(); row = next(r for k, r in rows if k == "FRAME"); row["ordinal"] = "2"
        with self.assertRaises(AssertionError): evaluated(rows)
        rows, _, _ = baseline(); selected(rows, "FRAME_SEAL", phase="positive")["records"] = "0"
        with self.assertRaises(AssertionError): evaluated(rows)

    def test_22_real_two_child_kernel_exit_and_external_seal(self):
        rows, _, _ = baseline(); raw = serial(rows)
        for changed in (raw.replace(b"USER EXIT pid=3 status=0", b"USER EXIT pid=3 status=1"), raw.replace(b"pid=4 parent=2", b"pid=3 parent=2"), raw.replace(b"EXTERNAL OUTPUT END bytes=", b"EXTERNAL OUTPUT END bytes=1")):
            with self.assertRaises(AssertionError): proof.native_output(changed, 3)
        with self.assertRaisesRegex(AssertionError, "pipe-only child cannot spawn descendants"):
            proof.native_output(raw + b"SPAWN OK pid=5 parent=3 program=extra\nUSER EXIT pid=5 status=0\n", 3)
        with self.assertRaises(AssertionError): proof.native_output(raw, 0)

    def test_23_only_exact_two_elf_embedding_chain(self):
        child = b"\x7fELF" + b"c" * 60; owner = b"\x7fELF" + b"o" * 60 + child; kernel = b"\x7fELF" + b"k" * 60 + owner
        proof.embedding({"child": child, "owner": owner, "kernel": kernel})
        for changed in ({"child": child + b"x", "owner": owner, "kernel": kernel}, {"child": child, "owner": owner, "kernel": kernel + owner}):
            with self.assertRaises(AssertionError): proof.embedding(changed)

    def test_24_separate_observation_clock_and_canonical_integers(self):
        self.refused("REAP", 1, "at_ms", "0195")
        rows, _, _ = baseline(); next(r for k, r in rows if k == "PIPE")["at_ms"] = "0"
        with self.assertRaises(AssertionError): evaluated(rows)

    def test_25_consistent_late_target_tx_after_consumed_error(self):
        rows, captured, route = baseline()
        for kind, row in rows:
            if kind == "FRAME" and row["direction"] == "tx" and int(row["ordinal"]) >= 5:
                row["ordinal"] = str(int(row["ordinal"]) + 1)
            elif kind == "FRAME_SEAL":
                row["records"] = str(int(row["records"]) + 1)
                row["tx"] = str(int(row["tx"]) + 1)
        submitted, error = old.vector("negative_data"), old.vector("icmp576")
        at = next(i for i, (kind, row) in enumerate(rows) if kind == "FRAME" and row["hex"] == error.hex()) + 1
        rows.insert(at, ["FRAME", {"v": "1", "direction": "tx", "ordinal": "5", "phase": "refusal", "at_ms": "185", "bytes": str(len(submitted)), "hex": submitted.hex()}])
        at = next(i for i, (_, _, frame) in enumerate(captured) if frame == error) + 1
        captured.insert(at, (999, [1000, 6500], submitted))
        with self.assertRaisesRegex(AssertionError, "old tuple TX after consumed error before owner retirement"):
            evaluated(rows, captured, route)

    def test_26_real_peer_identity_bodies_and_read_before_echo(self):
        report = old.peer_report()
        self.assertEqual(proof.inspect_peer(report, 123, 456)["positive_echo_bytes"], 64)
        for change in (lambda r: r.update(pid=124), lambda r: r.update(network_namespace_inode=457),
                       lambda r: r.update(sockets_closed=False), lambda r: r["connections"][0].update(received_bytes=1)):
            value = copy.deepcopy(report); change(value)
            with self.assertRaises(AssertionError): proof.inspect_peer(value, 123, 456)
        value = copy.deepcopy(report)
        at = next(i for i, row in enumerate(value["events"]) if row["event"] == "write")
        write = value["events"].pop(at); write["monotonic_ns"] = 25
        at = next(i for i, row in enumerate(value["events"]) if row["event"] == "read" and row["port"] == 42101)
        value["events"].insert(at, write)
        with self.assertRaisesRegex(AssertionError, "peer echo accepted/read prefix"):
            proof.inspect_peer(value, 123, 456)

    def test_27_both_observers_agree_but_frame_prefix_invalid(self):
        rows, _, _ = baseline()
        for observer in ("owner", "child"):
            row = next(row for kind, row in rows if kind == "PIPE" and row["child"] == "1" and row["observer"] == observer and row["direction"] == "request")
            row["hex"] = "000b" + row["hex"][4:]
        with self.assertRaisesRegex(AssertionError, "complete bounded framed message"):
            evaluated(rows)

    def test_28_fresh_positive_cannot_precede_old_retirement(self):
        rows, _, _ = baseline()
        at = next(i for i, (kind, _) in enumerate(rows) if kind == "POSITIVE")
        positive = rows.pop(at)
        at = next(i for i, (kind, row) in enumerate(rows) if kind == "RETIRED" and row["child"] == "1")
        rows.insert(at, positive)
        with self.assertRaises(AssertionError): evaluated(rows)

    def test_29_zero_write_cannot_establish_eof(self):
        native, _ = evaluated()
        for observer, direction in (("owner", "reply"), ("child", "request")):
            rows = copy.deepcopy(native["pipes"][observer, 1])
            seal = copy.deepcopy(native["seals"][observer, 1])
            last = [row for row in rows if row["direction"] == direction][-1]
            zero = dict(last, ordinal=str(int(last["ordinal"]) + 1), offset=str(int(last["offset"]) + int(last["bytes"])), at_ms="192", bytes="0", hex="none")
            if observer == "owner":
                rows.insert(-1, zero)
            else:
                rows.append(zero)
            seal["records"] = str(len(rows))
            seal[direction + "_eof"] = "192"
            seal["write_calls"] = str(int(seal["write_calls"]) + 1)
            with self.assertRaisesRegex(AssertionError, "only actual owner request EOF"):
                proof.pipe_stream(rows, seal, observer, 1, 101, 12100)

    def test_30_census_values_cannot_substitute_early_observation(self):
        rows, _, _ = baseline()
        census = [entry for entry in rows if entry[0] == "CENSUS"]
        early = rows[:1] + census + [entry for entry in rows[1:] if entry[0] != "CENSUS"]
        with self.assertRaisesRegex(AssertionError, "phase census after reap and frame seal"):
            evaluated(early)
        for phase, child in (("refusal", 1), ("positive", 2)):
            for label, anchor in ((phase + "-before", "GRANT"), (phase + "-after", "REAP"), (phase + "-after", "FRAME_SEAL"), (phase + "-after", "RETIRED")):
                changed = copy.deepcopy(rows)
                entry = next(entry for entry in changed if entry[0] == "CENSUS" and entry[1]["label"] == label)
                changed.remove(entry)
                at = next(i for i, (kind, row) in enumerate(changed) if kind == anchor and row.get("phase") == phase)
                changed.insert(at + (1 if anchor in ("GRANT", "RETIRED") else 0), entry)
                with self.subTest(phase=phase, label=label, anchor=anchor):
                    with self.assertRaisesRegex(AssertionError, "phase census"):
                        evaluated(changed)

    def test_31_equal_clock_reply_before_request_or_next_request_too_early(self):
        native, _ = evaluated()
        for child in (1, 2):
            for observer in ("owner", "child"):
                original = native["pipes"][observer, child]
                for direction in ("reply", "request"):
                    rows = copy.deepcopy(original)
                    # Keep each direction's bytes, ordinals and offsets exact.
                    # Equal timestamps preserve the existing clock predicates.
                    for row in rows:
                        if int(row["bytes"]): row["at_ms"] = "150" if child == 1 else "230"
                    request_at = next(i for i, row in enumerate(rows) if row["direction"] == "request")
                    first_reply = next(i for i, row in enumerate(rows) if row["direction"] == "reply" and int(row["offset"]) >= 20)
                    if direction == "reply":
                        rows.insert(request_at, rows.pop(first_reply))
                    else:
                        request_end = native["transactions"][child][0]["end_request"]
                        next_request = next(i for i, row in enumerate(rows) if row["direction"] == "request" and int(row["offset"]) == request_end)
                        rows.insert(first_reply, rows.pop(next_request))
                    until = 12100 if child == 1 else 10197
                    with self.subTest(child=child, observer=observer, direction=direction):
                        with self.assertRaisesRegex(AssertionError, "one request in flight observer order"):
                            proof.pipe_stream(rows, native["seals"][observer, child], observer, child, 101 if child == 1 else 198, until)

    def test_32_child_done_cannot_follow_normal_reap_or_result_eof(self):
        for child in (1, 2):
            for boundary in ("reaped_ms", "result_eof_ms"):
                rows, _, _ = baseline()
                reap = selected(rows, "REAP", child)
                # Keep child clocks monotone and inside the original budget;
                # isolate each boundary by moving the other witness later.
                late = int(reap[boundary]) + 1
                other = "result_eof_ms" if boundary == "reaped_ms" else "reaped_ms"
                reap[other] = str(late)
                selected(rows, "CHILD_DONE", child)["at_ms"] = str(late)
                with self.subTest(child=child, boundary=boundary):
                    with self.assertRaisesRegex(AssertionError, "child DONE before normal reap and true result EOF"):
                        evaluated(rows)

    def test_33_tcpdump_counts_match_each_other_and_complete_pcap(self):
        literal = b"tcpdump: listening on mtu-r0\n12 packets captured\n12 packets received by filter\n0 packets dropped by kernel\n"
        self.assertEqual(proof.capture_census(literal, 12), {"captured": 12, "received": 12, "dropped": 0})
        for changed, count in ((literal.replace(b"12 packets received", b"13 packets received"), 12),
                               (literal, 11), (literal.replace(b"0 packets dropped", b"1 packets dropped"), 12),
                               (literal + b"12 packets captured\n", 12),
                               (literal.replace(b"12 packets captured", b"012 packets captured"), 12),
                               (literal.replace(b"12 packets received by filter\n", b""), 12)):
            with self.assertRaisesRegex(AssertionError, "tcpdump"):
                proof.capture_census(changed, count)

    def test_34_retained_router_unicast_arp_and_exact_boundaries(self):
        actual = bytes.fromhex("52540012345652550000060108060001080006040001525500000601c0000201000000000000c0000264000000000000000000000000000000000000")
        self.assertEqual(len(actual), 60)

        def witness(value, direction="rx"):
            rows, captured, route = baseline()
            row = next(row for kind, row in rows if kind == "FRAME" and row["direction"] == "rx" and bytes.fromhex(row["hex"])[12:14] == b"\x08\x06")
            original = bytes.fromhex(row["hex"])
            row.update(direction=direction, bytes=str(len(value)), hex=value.hex())
            at = next(i for i, (_, _, frame) in enumerate(captured) if frame == original)
            index, stamp, _ = captured[at]; captured[at] = index, stamp, value
            counts, records = {"tx": 0, "rx": 0}, 0
            for kind, row in rows:
                if kind == "FRAME":
                    records += 1; counts[row["direction"]] += 1
                    row["ordinal"] = str(counts[row["direction"]])
                elif kind == "FRAME_SEAL":
                    row.update(records=str(records), tx=str(counts["tx"]), rx=str(counts["rx"]))
            return rows, captured, route

        evaluated(*witness(actual))
        # Native RX and capture bytes/counts agree for every mutation, so a
        # final census cannot hide an endpoint, protocol or padding mismatch.
        changes = ((0, bytes(6)), (0, bytes.fromhex("525400123499")), (6, bytes(6)), (14, b"\0\2"), (16, b"\x86\xdd"),
                   (18, b"\5"), (19, b"\5"), (20, b"\0\2"), (20, b"\0\3"), (22, bytes(6)),
                   (28, proof.GUEST_IP), (32, proof.GUEST_MAC), (32, b"\xff" * 6),
                   (38, proof.ROUTER_IP), (42, b"\1"))
        for offset, replacement in changes:
            changed = actual[:offset] + replacement + actual[offset + len(replacement):]
            with self.subTest(offset=offset, replacement=replacement.hex()):
                with self.assertRaises(AssertionError): evaluated(*witness(changed))
        for changed in (actual[:41], actual[:-1], actual + b"\0"):
            with self.subTest(length=len(changed)):
                with self.assertRaises(AssertionError): evaluated(*witness(changed))
        # A fully tuple-consistent unicast TX request is outside this RX-only
        # addition, even with updated native direction ordinals and seals.
        tx = proof.ROUTER_MAC + proof.GUEST_MAC + actual[12:22] + proof.GUEST_MAC + proof.GUEST_IP + bytes(6) + proof.ROUTER_IP + bytes(18)
        with self.assertRaisesRegex(AssertionError, "exact broadcast or router unicast ARP request"):
            evaluated(*witness(tx, "tx"))


if __name__ == "__main__":
    unittest.main()
