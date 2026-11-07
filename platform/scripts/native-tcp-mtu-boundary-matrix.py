#!/usr/bin/env python3
"""Native malformed-advice/current-grant isolation with disclosed raw ICMP.

Fixed1500 Linux routing is ordinary TCP calibration. The five selected ICMP
inputs, including the matching control, are explicitly constructed fixtures.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import sys
import time
import uuid

if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
    raise SystemExit("native-tcp-mtu-boundary-matrix: optimized Python refused")
SCRIPTS = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


prior = module("mtu_boundary_prior", SCRIPTS / "native-tcp-mtu-matrix.py")
peer = module("mtu_boundary_peer", SCRIPTS / "native-tcp-mtu-boundary-peer.py")
base, number, hx = prior.base, prior.number, prior.hexbytes
from served_ram import served_qemu
MAX_LOG, MAX_CAPTURE, MAX_ELF = prior.MAX_LOG, prior.MAX_CAPTURE, prior.MAX_ELF
SLOTS = {"target": "1", "unaffected": "2", "reserved": "3"}
LIMITS = ("Five disclosed raw ICMP fixtures, not Linux-generated errors or authenticated provenance. "
          "One owner/local synchronous Pipe, no child/kernel IPC. Finite grant/history isolation, "
          "no PMTU recovery/replay/full-memory/DMA/live replacement or physical clock claim.")
KEYS = {
    "BEGIN": {"v", "start_ms", "until_ms", "guest", "router", "peer"},
    "FRAME": {"v", "direction", "ordinal", "phase", "at_ms", "bytes", "hex"},
    "RPC": {"v", "index", "slot", "logical", "phase", "at_ms", "request_bytes", "request_hex", "reply_bytes", "reply_hex"},
    "GRANT": {"v", "slot", "logical", "local_port", "peer_port", "at_ms", "until_ms"},
    "CONNECTED": {"v", "slot", "logical", "at_ms", "sockets"},
    "QUEUED": {"v", "slot", "logical", "at_ms", "bytes"},
    "CONTROLS_READY": {"v", "at_ms", "target_logical", "unaffected_logical", "sockets"},
    "CASE": {"v", "index", "case", "receive_ordinal", "at_ms", "code", "connected", "sockets", "logical", "until_ms"},
    "REFUSED": {"v", "at_ms", "receive_ordinal", "code", "mtu", "sockets", "logical", "until_ms", "effects"},
    "FENCED": {"v", "at_ms", "code", "logical", "rpc_before", "rpc_after", "tx_before", "tx_after"},
    "REVOKED": {"v", "slot", "logical", "at_ms", "sockets"},
    "OBSERVED": {"v", "slot", "logical", "at_ms", "bytes", "hex", "sockets"},
    "EOF": {"v", "slot", "logical", "at_ms", "code"},
    "EMPTY_READY": {"v", "at_ms", "logical", "sockets", "until_ms"},
    "DONE": {"v", "at_ms", "sockets", "target_bytes", "unaffected_bytes", "cases"},
}


def rpc(row):
    # Reuse the existing strict actual v4 message validator. Its old two
    # phase names only select the exact granted port and terminal policy.
    adapted = dict(row, phase="positive" if row["slot"] == "unaffected" else "refusal")
    value = prior.rpc(adapted)
    if row["slot"] == "reserved":
        assert value["op"] == 17 and value["code"] == 0 and value["reply"][12] == 0, "empty-history STATUS only"
    return value


def native_records(output):
    assert output.endswith(b"\n") and len(output) <= 3 * 1024 * 1024
    rows, frames, transactions, events, positions = [], [], [], {}, {}
    grants, connected, queued, revoked = {}, {}, {}, {}
    cases, case_rpc_positions, counts, phase, previous = [], {}, {"tx": 0, "rx": 0}, "setup", 0
    for line in output.decode("ascii").splitlines():
        match = re.fullmatch(r"TCP MTU BOUNDARY ([A-Z_]+) (.*)", line)
        assert match, "native boundary record"
        row = {}
        for part in match[2].split(" "):
            assert part.count("=") == 1
            key, value = part.split("=")
            assert key and value and key not in row
            row[key] = value
        kind = match[1]
        assert kind in KEYS and set(row) == KEYS[kind] and row["v"] == "1", "exact boundary record schema"
        at = number(row, "start_ms" if kind == "BEGIN" else "at_ms")
        assert at >= previous and "DONE" not in events, "original monotone guest clock/terminal"
        previous = at
        if rows:
            assert rows[0][0] == "BEGIN" and at < number(events["BEGIN"], "until_ms"), "original whole deadline"
        if "slot" in row:
            slot = row["slot"]
            assert slot in SLOTS and row["logical"] == SLOTS[slot], "slot/logical identity"
        if kind == "FRAME":
            direction = row["direction"]
            assert direction in counts and row["phase"] == phase, "native frame phase"
            counts[direction] += 1
            assert number(row, "ordinal") == counts[direction] <= 256
            value = hx(row, "hex", number(row, "bytes"))
            assert 14 <= len(value) <= 1514
            frames.append(row)
            positions["FRAME:" + direction + ":" + row["ordinal"]] = len(rows)
        elif kind == "RPC":
            assert row["phase"] == phase and slot in grants and slot not in revoked
            assert number(row, "index") == len(transactions) + 1 <= 256
            assert slot != "target" or "REFUSED" not in events, "no RPC through fenced target"
            transactions.append({"row": row, "position": len(rows), **rpc(row)})
        elif kind == "GRANT":
            assert slot not in grants and row["until_ms"] == events["BEGIN"]["until_ms"]
            assert (row["local_port"], row["peer_port"]) == (("7101", "42101") if slot == "unaffected" else ("7100", "42100"))
            if slot == "reserved":
                assert set(revoked) == {"target", "unaffected"}
            else:
                assert not cases and "CONTROLS_READY" not in events
            grants[slot] = row
            positions["GRANT:" + slot] = len(rows)
        elif kind == "CONNECTED":
            assert slot in ("target", "unaffected") and slot in grants and slot not in connected
            assert slot == ("target" if not connected else "unaffected"), "actual serial connection order"
            assert row["sockets"] == ("1" if slot == "target" else "2") and "CONTROLS_READY" not in events
            connected[slot] = row
            if set(connected) == {"target", "unaffected"}:
                phase = "cases"
        elif kind == "QUEUED":
            assert slot in connected and slot not in queued
            assert row["bytes"] == ("1024" if slot == "target" else "64")
            assert phase == ("cases" if slot == "target" else "survivor")
            queued[slot] = row
        elif kind == "CASE":
            index = number(row, "index")
            assert index == ([0, 1, 2, 4][len(cases)] if len(cases) < 4 else -1), "ordered four invalid/empty cases"
            assert row["case"] == peer.CASES[index] and row["code"] == "0" and row["until_ms"] == events["BEGIN"]["until_ms"]
            empty = index == 4
            assert phase == ("reserved" if empty else "cases")
            assert (row["logical"], row["connected"], row["sockets"]) == (("3", "0", "0") if empty else ("1", "1", "2"))
            assert "EMPTY_READY" in events if empty else "CONTROLS_READY" in events
            selected = transactions[-1]
            assert selected["row"]["slot"] == ("reserved" if empty else "target") and selected["op"] == 17 and selected["code"] == 0
            assert selected["reply"][12] == (0 if empty else 1), "actual STATUS proves case outcome"
            cases.append(row)
            case_rpc_positions[str(index)] = selected["position"]
            positions["CASE:" + str(index)] = len(rows)
            if index == 2:
                phase = "matching"
        elif kind == "REVOKED":
            assert slot in grants and slot not in revoked
            assert row["sockets"] == ("1" if slot == "target" else "0")
            assert "FENCED" in events if slot == "target" else "EOF" in events if slot == "unaffected" else len(cases) == 4
            revoked[slot] = row
            positions["REVOKED:" + slot] = len(rows)
            phase = {"target": "survivor", "unaffected": "reserved", "reserved": "done"}[slot]
        else:
            assert kind not in events
            events[kind] = row
            positions[kind] = len(rows)
            if kind == "BEGIN":
                assert not rows and number(row, "until_ms") == at + 30000
                assert (row["guest"], row["router"], row["peer"]) == ("192.0.2.100", "192.0.2.1", "198.51.100.2")
            elif kind == "CONTROLS_READY":
                assert set(connected) == {"target", "unaffected"} and "target" in queued and row["target_logical"] == "1" and row["unaffected_logical"] == "2" and row["sockets"] == "2"
                assert phase == "cases"
            elif kind == "REFUSED":
                assert len(cases) == 3 and phase == "matching"
                assert (row["code"], row["mtu"], row["sockets"], row["logical"], row["effects"]) == ("17", "576", "1", "1", "unknown")
                assert row["until_ms"] == events["BEGIN"]["until_ms"]
                assert transactions[-1]["row"]["slot"] == "target" and transactions[-1]["op"] == 17 and transactions[-1]["code"] == 17
                case_rpc_positions["3"] = transactions[-1]["position"]
            elif kind == "FENCED":
                assert "REFUSED" in events and row["code"] == "8" and row["logical"] == "1"
                assert number(row, "rpc_before") == number(row, "rpc_after") == len(transactions)
                assert number(row, "tx_before") == number(row, "tx_after") == counts["tx"]
            elif kind == "OBSERVED":
                assert slot == "unaffected" and "unaffected" in queued and row["bytes"] == "64" and hx(row, "hex", 64) == peer.ECHO and row["sockets"] == "1"
                assert b"".join(value["reply"][12:] for value in transactions if value["row"]["slot"] == "unaffected" and value["op"] == 19 and value["code"] == 0) == peer.ECHO, "actual echo RPCs precede observation"
            elif kind == "EOF":
                assert slot == "unaffected" and "OBSERVED" in events and row["code"] == "6"
                assert transactions[-1]["row"]["slot"] == "unaffected" and transactions[-1]["op"] == 19 and transactions[-1]["code"] == 6
            elif kind == "EMPTY_READY":
                assert "reserved" in grants and row["logical"] == "3" and row["sockets"] == "0" and row["until_ms"] == events["BEGIN"]["until_ms"]
                assert transactions[-1]["row"]["slot"] == "reserved" and transactions[-1]["reply"][12] == 0
            elif kind == "DONE":
                assert set(revoked) == set(SLOTS) and len(cases) == 4
                assert (row["sockets"], row["target_bytes"], row["unaffected_bytes"], row["cases"]) == ("0", "1024", "64", "4")
        rows.append((kind, row))
    assert set(events) == {"BEGIN", "CONTROLS_READY", "REFUSED", "FENCED", "OBSERVED", "EOF", "EMPTY_READY", "DONE"}
    assert set(grants) == set(revoked) == set(SLOTS) and set(connected) == set(queued) == {"target", "unaffected"}
    for slot, expected in (("target", peer.BODY), ("unaffected", peer.ECHO)):
        selected = [value for value in transactions if value["row"]["slot"] == slot]
        writes = [value for value in selected if value["op"] == 18 and value["code"] == 0]
        assert len(writes) == 1 and writes[0]["request"][12:] == expected and writes[0]["count"] == len(expected)
        assert number(writes[0]["row"], "at_ms") <= number(queued[slot], "at_ms")
        assert any(value["op"] in (16, 17) and value["code"] == 0 and value["reply"][12] & 1 and number(value["row"], "at_ms") <= number(connected[slot], "at_ms") for value in selected), "actual connected status before controls"
    survivor = [value for value in transactions if value["row"]["slot"] == "unaffected"]
    assert sum(value["op"] == 16 for value in survivor) == 1, "same existing unaffected connection; no reconnect"
    assert b"".join(value["reply"][12:] for value in survivor if value["op"] == 19 and value["code"] == 0) == peer.ECHO
    assert any(value["op"] == 20 and value["code"] == 0 for value in survivor)
    assert sum(value["code"] == 17 for value in transactions) == 1
    reserved = [value for value in transactions if value["row"]["slot"] == "reserved"]
    assert len(reserved) == 2 and all(value["op"] == 17 and value["code"] == 0 and value["reply"][12] == 0 for value in reserved)
    return {"records": len(rows), "frames": frames, "transactions": transactions, "events": events,
            "positions": positions, "grants": grants, "connected": connected, "queued": queued, "revoked": revoked,
            "cases": cases, "case_rpc_positions": case_rpc_positions, "census": counts}


def native_output(raw, status):
    assert status == 3, "natural QEMU exit"
    for marker in (b"\nNETWORK LINK OK ", b"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ", b"\nDURABLE WORKLOAD OK\n", b"\nABSD BOOT OK\n"):
        assert marker in raw
    assert not any(value in raw for value in (b"PANIC", b"KERNEL FAULT", b"init: FAILED", b"NIC DISABLED"))
    assert re.findall(rb"(?m)^USER EXIT pid=2 status=(.*)\n", raw) == [b"0"]
    assert re.findall(rb"(?m)^DURABLE WORKER OUTCOME generation=1 pid=2 status=(.*)\n", raw) == [b"0"]
    assert re.findall(rb"(?m)^DURABLE WORKER GENERATION (.*)\n", raw) == [b"generation=1 pid=2"]
    assert raw.count(b"EXTERNAL OUTPUT BEGIN encoding=hex\n") == 1 and not re.search(rb"(?m)^SPAWN OK pid=\d+ parent=2 ", raw)
    output = bytearray()
    chunks = list(base.CHUNK.finditer(raw))
    assert len(chunks) == raw.count(b"EXTERNAL OUTPUT CHUNK")
    for chunk in chunks:
        assert int(chunk[1], 16) == len(output)
        output.extend(bytes.fromhex(chunk[2].decode()))
        assert len(output) <= 3 * 1024 * 1024
    digest = 0x811c9dc5
    for value in output:
        digest = ((digest ^ value) * 0x1000193) & 0xffffffff
    assert re.findall(rb"(?m)^EXTERNAL OUTPUT END bytes=(\d+) digest=([0-9a-f]{8})\n", raw) == [(str(len(output)).encode(), f"{digest:08x}".encode())]
    assert raw.count(b"EXTERNAL OUTPUT END ") == 1
    native = native_records(bytes(output))
    stats = re.findall(rb"(?m)^NIC STATS (.*)\n", raw)
    assert len(stats) == 1
    counters = dict(word.split("=") for word in stats[0].decode().split(" "))
    assert set(counters) == {"rx_frames", "rx_refused", "rx_missed", "tx_frames", "tx_refused", "tx_errors", "flags"}
    assert all(counters[key] == "0" for key in ("rx_refused", "rx_missed", "tx_refused", "tx_errors")) and counters["flags"] == "1"
    assert number(counters, "rx_frames") == native["census"]["rx"] and number(counters, "tx_frames") == native["census"]["tx"]
    native.update(output=output.decode(), output_bytes=len(output), FNV32=f"{digest:08x}", NIC_counters=counters)
    return native


def sequence_bytes(packets, expected):
    selected = [packet for packet in packets if packet["body"]]
    assert selected
    start, assembled = selected[0]["sequence"], {}
    for packet in selected:
        for index, value in enumerate(packet["body"]):
            offset = (packet["sequence"] - start + index) & 0xffffffff
            assert offset < len(expected) and (offset not in assembled or assembled[offset] == value)
            assembled[offset] = value
    assert len(assembled) == len(expected) and bytes(assembled[index] for index in range(len(expected))) == expected


def inspect_frames(rows, native):
    captures, census, controls, target, survivor = {"tx": [], "rx": []}, [], [], [], {"tx": [], "rx": []}
    for index, stamp, frame in rows:
        direction = "tx" if frame[6:12] == peer.GUEST_MAC else "rx"
        assert frame[6:12] == (peer.GUEST_MAC if direction == "tx" else peer.ROUTER_MAC)
        assert frame[:6] in ((peer.ROUTER_MAC, bytes([255]) * 6) if direction == "tx" else (peer.GUEST_MAC, bytes([255]) * 6))
        captures[direction].append(frame)
        census.append({"index": index, "timestamp": stamp, "direction": direction, "frame": peer.identity(frame)})
        if frame[12:14] == b"\x08\6":
            assert len(frame) in (42, 60) and not any(frame[42:]) and frame[14:20] == b"\0\1\x08\0\6\4"
            assert frame[22:28] == frame[6:12] and frame[28:32] + frame[38:42] == (peer.GUEST + peer.ROUTER if direction == "tx" else peer.ROUTER + peer.GUEST)
            assert int.from_bytes(frame[20:22], "big") in (1, 2)
            continue
        ip = prior.ipv4(frame)
        if ip[9] == 1:
            assert direction == "rx"
            controls.append((index, frame))
            continue
        packet = prior.tcp(ip)
        assert ip[12:20] == (peer.GUEST + peer.PEER if direction == "tx" else peer.PEER + peer.GUEST)
        local, remote = (packet["source"], packet["destination"]) if direction == "tx" else (packet["destination"], packet["source"])
        assert (local, remote) in ((7100, 42100), (7101, 42101))
        if local == 7100:
            assert not packet["body"] or direction == "tx", "target receives no application echo"
            if packet["body"]:
                peer.checked_submission(frame)
                target.append((index, frame, packet))
        else:
            survivor[direction].append(packet)
    assert target and len(controls) == 5
    submitted = target[0][1]
    submitted_native = [row for row in native["frames"] if row["direction"] == "tx" and bytes.fromhex(row["hex"]) == submitted]
    assert submitted_native and native["positions"]["FRAME:tx:" + submitted_native[0]["ordinal"]] < native["positions"]["CONTROLS_READY"], "actual1024 submission precedes controls readiness"
    for index, (capture_index, value) in enumerate(controls):
        expected = peer.control(submitted, "matching" if index == 4 else peer.CASES[index])
        assert value == expected, "exact independently selected raw control"
        assert target[0][0] < capture_index
    for direction in ("tx", "rx"):
        actual = [bytes.fromhex(row["hex"]) for row in native["frames"] if row["direction"] == direction]
        assert len(actual) == len(captures[direction]) and all(prior.frame_equal(direction, a, b) for a, b in zip(actual, captures[direction])), "complete native/capture ordered census"
    acknowledgements = native["cases"][:3] + [native["events"]["REFUSED"], native["cases"][3]]
    positions = native["positions"]
    previous = positions["CONTROLS_READY"]
    for index, ((_, value), row) in enumerate(zip(controls, acknowledgements)):
        receives = [f for f in native["frames"] if f["direction"] == "rx" and f["ordinal"] == row["receive_ordinal"]]
        assert len(receives) == 1 and receives[0]["hex"] == value.hex()
        position = positions["FRAME:rx:" + row["receive_ordinal"]]
        acknowledged = positions["REFUSED"] if index == 3 else positions["CASE:" + str(index)]
        assert previous < position < acknowledged and number(receives[0], "at_ms") <= number(row, "at_ms"), "consumed input before actual STATUS outcome"
        assert position < native["case_rpc_positions"][str(index)] < acknowledged, "actual STATUS transaction after selected RX"
        if index == 4:
            assert positions["EMPTY_READY"] < position
        previous = acknowledged
    matched = positions["FRAME:rx:" + native["events"]["REFUSED"]["receive_ordinal"]]
    for row in native["frames"]:
        position = positions["FRAME:" + row["direction"] + ":" + row["ordinal"]]
        if row["direction"] != "tx":
            continue
        assert not positions["GRANT:reserved"] < position < positions["REVOKED:reserved"], "empty history reservation emitted no TX"
        frame = bytes.fromhex(row["hex"])
        if position <= matched or frame[12:14] != b"\x08\0" or frame[23] != 6:
            continue
        packet = prior.tcp(prior.ipv4(frame))
        if (packet["source"], packet["destination"]) == (7100, 42100):
            assert position > positions["REVOKED:target"] and not packet["body"] and packet["flags"] in (4, 20), "target stopped after consumed matching advice"
    sequence_bytes([item[2] for item in target], peer.BODY)
    for direction in ("tx", "rx"):
        sequence_bytes(survivor[direction], peer.ECHO)
        assert any(packet["flags"] & 1 for packet in survivor[direction]), "survivor FIN both ways"
    return {"census": census, "submitted": peer.identity(submitted), "raw_controls": [peer.identity(frame) for _, frame in controls],
            "claim": "disclosed raw advice classification and existing grant isolation, not genuine Linux error generation"}


def inspect_actor(report, native, wire, pid, namespace):
    assert report["schema"] == "absd-tcp-mtu-boundary-actor/1" and report["disposition"] == "PASS" and report["mode"] == "actor"
    assert report["pid"] == pid and report["network_namespace_inode"] == namespace and report["raw_socket_closed"] is True
    assert report["submitted"] == wire["submitted"] and len(report["cases"]) == 5
    assert 1 <= len(report["reads"]) <= 256 and any(row["frame"] == report["submitted"] and row["packet_type"] != 4 for row in report["reads"])
    ack = native["cases"][:3] + [native["events"]["REFUSED"], native["cases"][3]]
    previous = report["start_monotonic_ns"]
    for index, row in enumerate(report["cases"]):
        assert row["index"] == index and row["case"] == peer.CASES[index] and row["frame"] == wire["raw_controls"][index]
        assert row["native_acknowledgement"] == ack[index]
        assert previous <= row["send_monotonic_ns"] <= row["ack_read_monotonic_ns"] <= report["end_monotonic_ns"]
        previous = row["ack_read_monotonic_ns"]


def inspect_server(report, pid, namespace):
    assert report["schema"] == "absd-tcp-mtu-boundary-server/1" and report["disposition"] == "PASS" and report["mode"] == "server"
    assert report["pid"] == pid and report["network_namespace_inode"] == namespace
    assert report["sockets_closed"] is True and report["runner_stop_received"] is True
    connections = {row["port"]: row for row in report["connections"]}
    assert len(report["connections"]) == 2 and set(connections) == {42100, 42101}
    for port, data in ((42100, peer.BODY), (42101, peer.ECHO)):
        row = connections[port]
        assert row["source"] == ["192.0.2.100", 7100 if port == 42100 else 7101] and row["received"] == peer.identity(data)
    assert connections[42100]["sent"] == 0 and connections[42100]["eof"] is False and connections[42100]["write_closed"] is False
    assert connections[42101]["sent"] == 64 and connections[42101]["eof"] is True and connections[42101]["write_closed"] is True
    reads, echoed, accepted, eof, shutdown = {42100: bytearray(), 42101: bytearray()}, bytearray(), [], set(), 0
    previous = report["start_monotonic_ns"]
    assert len(report["events"]) <= 128
    for row in report["events"]:
        assert previous <= row["monotonic_ns"] <= report["end_monotonic_ns"]
        previous = row["monotonic_ns"]
        port = row["port"]
        assert port in connections
        if row["event"] == "accept":
            assert port not in accepted and row["source"] == connections[port]["source"]
            accepted.append(port)
        elif row["event"] == "read":
            assert port in accepted and port not in eof
            data = bytes.fromhex(row["hex"])
            assert data.hex() == row["hex"] and len(data) == row["bytes"] <= 1025
            reads[port].extend(data)
            if not data:
                assert port == 42101
                eof.add(port)
        elif row["event"] == "write":
            assert port == 42101 and row["offset"] == len(echoed)
            assert port in accepted, "echo write requires accepted connection"
            data = bytes.fromhex(row["hex"])
            assert data.hex() == row["hex"] and 0 < len(data) == row["bytes"]
            end = len(echoed) + len(data)
            assert end <= len(reads[port]) and data == reads[port][len(echoed):end], "echo write requires already-read prefix"
            echoed.extend(data)
        else:
            assert row["event"] == "shutdown-write" and port == 42101 and row["bytes"] == 64 and port in eof
            shutdown += 1
    assert accepted == [42100, 42101] and reads[42100] == peer.BODY and reads[42101] == echoed == peer.ECHO and shutdown == 1


def inspect_route(rows, downstream):
    expected, actual = {"out": [], "in": []}, {"out": [], "in": []}

    def decreased(ip):
        value = bytearray(ip)
        assert value[8] > 1
        value[8] -= 1
        value[10:12] = bytes(2)
        value[10:12] = base.checksum(bytes(value[:20])).to_bytes(2, "big")
        return bytes(value)

    for _, _, frame in rows:
        if frame[12:14] == b"\x08\0" and frame[23] == 6:
            ip = prior.ipv4(frame)
            expected["out" if ip[12:16] == peer.GUEST else "in"].append(decreased(ip) if ip[12:16] == peer.GUEST else ip)
    for _, _, frame in downstream:
        if frame[12:14] == b"\x08\6":
            assert len(frame) in (42, 60) and not any(frame[42:])
            assert frame[14:20] == b"\0\1\x08\0\6\4" and frame[22:28] == frame[6:12]
            assert frame[28:32] + frame[38:42] in (bytes((198, 51, 100, 1)) + peer.PEER, peer.PEER + bytes((198, 51, 100, 1)))
            continue
        ip = prior.ipv4(frame)
        prior.tcp(ip)
        out = ip[12:20] == peer.GUEST + peer.PEER
        assert out or ip[12:20] == peer.PEER + peer.GUEST
        assert frame[:12] == (prior.PEER_MAC + prior.ROUTER_EGRESS_MAC if out else prior.ROUTER_EGRESS_MAC + prior.PEER_MAC)
        actual["out" if out else "in"].append(ip if out else decreased(ip))
    assert actual == expected and actual["out"] and actual["in"], "full fixed1500 two-leg TCP census, TTL/checksum only"
    return {"out_packets": len(actual["out"]), "in_packets": len(actual["in"]), "mtu": 1500}


def packet_records(path):
    data = base.read_bound(path, MAX_CAPTURE)
    assert len(data) >= 24
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(data[:4])
    assert endian is not None
    major, minor, _, _, snaplen, link = struct.unpack(endian + "HHIIII", data[4:24])
    assert (major, minor, link) == (2, 4, 1) and snaplen >= 1514
    offset, rows = 24, []
    while offset < len(data):
        assert offset + 16 <= len(data)
        seconds, fraction, size, original = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        assert fraction < 1_000_000 and 14 <= size <= 1514 and size == original and offset + size <= len(data)
        rows.append((len(rows), [seconds, fraction], data[offset:offset + size]))
        assert len(rows) <= 1024
        offset += size
    return data, rows


json_value = prior.json_value


def run(args, work):
    assert os.geteuid() == 0, "owned disposable VM root only"
    deadline = time.monotonic() + args.timeout
    suffix = uuid.uuid4().hex
    router_ns, peer_ns = "mtur-" + suffix, "mtup-" + suffix
    tap, egress, peer_device = "mtu-tap0", "mtu-r0", "mtu-p0"
    processes, logs, bounds, created, errors = {}, [], {}, [], []
    process_env = {key: value for key, value in os.environ.items()
                   if key not in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "NOTIFY_SOCKET")}

    def left(maximum):
        for path, bound in bounds.items():
            assert not path.exists() or path.stat().st_size <= bound, "artifact byte bound: " + path.name
        remaining = deadline - time.monotonic()
        assert remaining > 0, "outer absolute deadline"
        return min(maximum, remaining)

    def checked(argv):
        result = subprocess.run(argv, check=True, capture_output=True, text=True,
                                timeout=left(5), env=process_env)
        assert len(result.stdout) + len(result.stderr) <= 65536, "control output bound"
        return result.stdout

    def control(namespace, *words):
        return checked(["ip", "netns", "exec", namespace, *words])

    def start(name, argv, env=None):
        path = work / (name + ".log")
        bounds[path] = MAX_LOG
        output = path.open("xb")
        logs.append(output)
        process = subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT,
            start_new_session=True, env=process_env if env is None else env)
        processes[name] = process
        return process

    try:
        buffers = {name: base.read_bound(path, MAX_ELF) for name, path in (("owner", args.elf), ("kernel", args.kernel_elf))}
        assert all(len(data) >= 64 and data.startswith(b"\x7fELF") for data in buffers.values())
        assert buffers["kernel"].count(buffers["owner"]) == 1, "exact unique owner ELF embedded in kernel"
        inputs = {name: base.identity(args.elf if name == "owner" else args.kernel_elf, data) for name, data in buffers.items()}
        tree = work / "iso-tree/boot/grub"
        tree.mkdir(parents=True)
        (tree.parent / "absd-kernel").write_bytes(buffers["kernel"])
        grub = b'insmod all_video\nset timeout=0\nmenuentry "ABSD TCP MTU" {\n multiboot2 /boot/absd-kernel durable=1 net nvme-write=absd\n boot\n}\n'
        (tree / "grub.cfg").write_bytes(grub)
        iso, disk = work / "native-tcp-mtu-boundary.iso", work / "native-tcp-mtu-boundary.img"
        temporary = work / "iso-tmp"
        temporary.mkdir()
        bounds[iso], bounds[disk] = 128 * 1024 * 1024, 2 * 1024 * 1024
        builder = start("iso-build", ["grub-mkrescue", "-o", str(iso), str(tree.parent.parent)], dict(process_env, TMPDIR=str(temporary)))
        builder.wait(timeout=left(60))
        assert builder.returncode == 0, "ISO build"
        with disk.open("xb") as stream:
            stream.truncate(2 * 1024 * 1024)
        for namespace in (router_ns, peer_ns):
            assert namespace not in [line.split()[0] for line in checked(["ip", "netns", "list"]).splitlines()]
            # Retain the exact attempted identity even if ip fails partway.
            created.append(namespace)
            checked(["ip", "netns", "add", namespace])
            for key in ("net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1",
                        "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0"):
                control(namespace, "sysctl", "-qw", key)
            checked(["ip", "-n", namespace, "link", "set", "lo", "up"])
        control(router_ns, "sysctl", "-qw", "net.ipv4.ip_forward=1")
        control(peer_ns, "sysctl", "-qw", "net.ipv4.ip_forward=0")
        checked(["ip", "-n", router_ns, "tuntap", "add", "dev", tap, "mode", "tap"])
        checked(["ip", "-n", router_ns, "link", "add", egress, "type", "veth", "peer", "name", peer_device])
        checked(["ip", "-n", router_ns, "link", "set", peer_device, "netns", peer_ns])
        for namespace, device, address, mac, mtu in (
                (router_ns, tap, "192.0.2.1/24", prior.ROUTER_MAC, 1500),
                (router_ns, egress, "198.51.100.1/24", prior.ROUTER_EGRESS_MAC, 1500),
                (peer_ns, peer_device, "198.51.100.2/24", prior.PEER_MAC, 1500)):
            checked(["ip", "-n", namespace, "link", "set", device, "address", mac.hex(":"), "mtu", str(mtu)])
            checked(["ip", "-n", namespace, "addr", "add", address, "dev", device])
            checked(["ip", "-n", namespace, "link", "set", device, "up"])
        checked(["ip", "-n", peer_ns, "route", "add", "192.0.2.0/24", "via", "198.51.100.1", "dev", peer_device])
        offloads = {}
        for namespace, device in ((router_ns, egress), (peer_ns, peer_device)):
            control(namespace, "ethtool", "-K", device, "tx", "off", "tso", "off", "gso", "off", "gro", "off")
            text = control(namespace, "ethtool", "-k", device)
            for feature in ("tx-checksumming", "tcp-segmentation-offload", "generic-segmentation-offload", "generic-receive-offload"):
                assert re.search(r"(?m)^" + feature + r": off(?: \[fixed\])?$", text), "offload readback: " + feature
            offloads[device] = text
        topology = {"schema": "absd-native-tcp-mtu-boundary-topology/1", "host_kernel": list(os.uname()), "offloads": offloads}
        for role, namespace in (("router", router_ns), ("peer", peer_ns)):
            addresses = json.loads(checked(["ip", "-n", namespace, "-j", "address", "show"]))
            routes = json.loads(checked(["ip", "-n", namespace, "-j", "-4", "route", "show"]))
            keys = ["net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6", "net.ipv4.ip_forward"]
            settings = {key: control(namespace, "sysctl", "-n", key).strip() for key in keys}
            assert settings[keys[0]] == settings[keys[1]] == "1" and settings[keys[2]] == ("1" if role == "router" else "0")
            devices = {row["ifname"]: row for row in addresses if row["ifname"] != "lo"}
            expected = {tap: (1500, "192.0.2.1", prior.ROUTER_MAC), egress: (1500, "198.51.100.1", prior.ROUTER_EGRESS_MAC)} if role == "router" else {peer_device: (1500, "198.51.100.2", prior.PEER_MAC)}
            assert set(devices) == set(expected)
            for device, (mtu, address, mac) in expected.items():
                value = devices[device]
                assert value["mtu"] == mtu and "UP" in value["flags"] and value["address"] == mac.hex(":")
                assert len(value["addr_info"]) == 1 and value["addr_info"][0]["family"] == "inet" and value["addr_info"][0]["local"] == address and value["addr_info"][0]["prefixlen"] == 24
            assert len(routes) == (2 if role == "router" else 2) and not any(row["dst"] == "default" for row in routes)
            if role == "peer":
                assert any(row["dst"] == "192.0.2.0/24" and row["gateway"] == "198.51.100.1" and row["dev"] == peer_device for row in routes)
            topology[role] = {"namespace": namespace, "inode": os.stat("/run/netns/" + namespace).st_ino,
                              "addresses": addresses, "routes": routes, "sysctls": settings}
        peer.write(work / "TOPOLOGY.json", topology)
        serial = work / "native-tcp-mtu-boundary.serial.log"
        ingress_capture, egress_capture = work / "native-tcp-mtu-boundary.pcap", work / "router-egress.pcap"
        bounds[serial], bounds[ingress_capture], bounds[egress_capture] = MAX_LOG, MAX_CAPTURE, MAX_CAPTURE
        dump = start("router-capture", ["ip", "netns", "exec", router_ns, "tcpdump", "--immediate-mode", "-U", "-n", "-i", egress, "-s", "0", "-w", str(egress_capture)])
        ready_at = time.monotonic() + left(5)
        while b"listening on" not in base.read_bound(work / "router-capture.log", MAX_LOG):
            assert dump.poll() is None and time.monotonic() < ready_at, "router capture ready deadline"
            time.sleep(0.01)
        peer_result = work / "PEER.json"
        ready_path = peer_result.with_suffix(".ready.json")
        bounds[peer_result], bounds[ready_path] = 65536, 4096
        actor = start("tcp-peer", ["ip", "netns", "exec", peer_ns, sys.executable, "-I", "-B", str(SCRIPTS / "native-tcp-mtu-boundary-peer.py"), "--output", str(peer_result), "--mode", "server", "--stop-file", str(work / "PEER-STOP"), "--timeout", str(min(90, int(left(90))))])
        ready_at = time.monotonic() + left(5)
        while not ready_path.exists():
            assert actor.poll() is None and time.monotonic() < ready_at, "TCP peer ready deadline"
            time.sleep(0.01)
        ready = json.loads(base.read_bound(ready_path, 4096))
        assert ready["schema"] == "absd-tcp-mtu-boundary-server-ready/1" and ready["pid"] == actor.pid
        assert ready["network_namespace_inode"] == topology["peer"]["inode"] and ready["bind"] == "198.51.100.2" and ready["ports"] == [42100, 42101]
        raw_result = work / "RAW-PEER.json"
        raw_ready = raw_result.with_suffix(".ready.json")
        bounds[raw_result], bounds[raw_ready] = MAX_LOG, 4096
        raw_actor = start("raw-peer", ["ip", "netns", "exec", router_ns, sys.executable, "-I", "-B", str(SCRIPTS / "native-tcp-mtu-boundary-peer.py"), "--mode", "actor", "--tap", tap, "--serial", str(serial), "--output", str(raw_result), "--timeout", str(min(150, int(left(150))))])
        raw_ready_until = time.monotonic() + left(5)
        while not raw_ready.exists():
            assert raw_actor.poll() is None and time.monotonic() < raw_ready_until, "raw actor ready deadline"
            time.sleep(0.005)
        raw_registration = json.loads(base.read_bound(raw_ready, 4096))
        assert raw_registration["schema"] == "absd-tcp-mtu-boundary-actor-ready/1" and raw_registration["pid"] == raw_actor.pid
        assert raw_registration["network_namespace_inode"] == topology["router"]["inode"] and raw_registration["tap"] == tap
        qemu = shutil.which(os.environ.get("ABSD_QEMU", "qemu-system-x86_64"))
        assert qemu, "QEMU executable"
        command = served_qemu(["ip", "netns", "exec", router_ns, str(Path(qemu).resolve()),
            "-accel", "tcg,thread=single", "-cpu", "max,vendor=GenuineIntel,+rdrand", "-smp", "1", "-m", "256M",
            "-cdrom", str(iso), "-drive", f"file={disk},format=raw,if=ide,index=0", "-display", "none", "-serial", f"file:{serial}",
            "-no-reboot", "-no-shutdown", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
            "-device", f"e1000,netdev=n0,mac={prior.GUEST_MAC.hex(':')}", "-netdev", f"tap,id=n0,ifname={tap},script=no,downscript=no,vnet_hdr=off",
            "-object", f"filter-dump,id=cap0,netdev=n0,file={ingress_capture}"])
        emulator = start("qemu", command)
        peer.write(work / "LAUNCH.json", {"schema": "absd-native-tcp-mtu-boundary-launch/1", "inputs": inputs,
            "ISO": base.identity(iso, base.read_bound(iso, bounds[iso])), "command": command,
            "runner_pid": os.getpid(), "process_pid_and_pgid": {name: p.pid for name, p in processes.items()},
            "runner": base.identity(__file__, base.read_bound(__file__, MAX_LOG)),
            "peer_source": base.identity(SCRIPTS / "native-tcp-mtu-boundary-peer.py", base.read_bound(SCRIPTS / "native-tcp-mtu-boundary-peer.py", MAX_LOG)),
            "topology": topology, "outer_timeout_seconds": args.timeout})
        while emulator.poll() is None:
            left(args.timeout)
            assert actor.poll() is None and raw_actor.poll() in (None, 0) and dump.poll() is None, "peer/capture failed before QEMU exit"
            time.sleep(0.02)
        raw_actor.wait(timeout=left(3))
        assert raw_actor.returncode == 0, "raw actor terminal status"
        os.killpg(dump.pid, signal.SIGINT)
        dump.wait(timeout=left(3))
        assert dump.returncode == 0, "router capture terminal status"
        dump_log = base.read_bound(work / "router-capture.log", MAX_LOG)
        assert re.findall(rb"(?m)^(\d+) packets dropped by kernel\r?$", dump_log) == [b"0"], "router capture loss census"
        peer.write(work / "PEER-STOP", {"reason": "natural QEMU end and captures closed"})
        actor.wait(timeout=left(3))
        assert actor.returncode == 0, "ordinary TCP peer terminal status"
        raw = base.read_bound(serial, MAX_LOG)
        observed = native_output(raw, emulator.returncode)
        capture_bytes, captured = packet_records(ingress_capture)
        egress_bytes, egress_rows = packet_records(egress_capture)
        frames = inspect_frames(captured, observed)
        frames["route"] = inspect_route(captured, egress_rows)
        report = json.loads(base.read_bound(peer_result, 65536))
        inspect_server(report, actor.pid, topology["peer"]["inode"])
        actor_report = json.loads(base.read_bound(raw_result, MAX_LOG))
        inspect_actor(actor_report, observed, frames, raw_actor.pid, topology["router"]["inode"])
        checked_peer = {"target_received_bytes": 1024, "unaffected_received_and_echoed_bytes": 64, "raw_controls": 5}
        return json_value({"schema": "absd-native-tcp-mtu-boundary-proof/1", "disposition": "PASS", "limits": LIMITS,
            "native": observed, "wire": frames, "peer": checked_peer, "inputs": inputs,
            "capture": base.identity(ingress_capture, capture_bytes), "egress_capture": base.identity(egress_capture, egress_bytes)})
    finally:
        terminal, group_terminal = {}, {}
        for name in ("qemu", "raw-peer", "tcp-peer", "router-capture", "iso-build"):
            process = processes.get(name)
            try:
                if process is not None and base.group_live(process):
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    stop = time.monotonic() + 3
                    while (process.poll() is None or base.group_live(process)) and time.monotonic() < stop:
                        time.sleep(0.02)
                    if process.poll() is None or base.group_live(process):
                        errors.append(name + " required SIGKILL")
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait(timeout=3)
                terminal[name] = None if process is None else process.poll()
                group_terminal[name] = process is None or not base.group_live(process)
                assert process is None or terminal[name] is not None
                assert group_terminal[name]
            except BaseException as error:
                errors.append(name + ": " + repr(error))
        for log in logs:
            log.close()
        absent = {}
        for namespace in reversed(created):
            try:
                listing = subprocess.run(["ip", "netns", "list"], check=True, capture_output=True, text=True, timeout=5, env=process_env).stdout
                if namespace in [line.split()[0] for line in listing.splitlines()]:
                    pids = subprocess.run(["ip", "netns", "pids", namespace], check=True, capture_output=True, text=True, timeout=5, env=process_env).stdout
                    assert not pids.strip(), "namespace has an unretired process; no unknown process is killed"
                    subprocess.run(["ip", "netns", "del", namespace], check=True, capture_output=True, timeout=5, env=process_env)
                listing = subprocess.run(["ip", "netns", "list"], check=True, capture_output=True, text=True, timeout=5, env=process_env).stdout
                absent[namespace] = namespace not in [line.split()[0] for line in listing.splitlines()]
                assert absent[namespace]
            except BaseException as error:
                errors.append(namespace + ": " + repr(error))
        peer.write(work / "LOCAL-CLEANUP.json", {"schema": "absd-native-tcp-mtu-boundary-cleanup/1",
            "created_namespace_identities": created, "namespaces_absent": absent,
            "process_exit_status": terminal, "owned_session_process_groups_terminal": group_terminal,
            "errors": errors, "disposition": "FAIL" if errors else "PASS",
            "custody": "Root source/result/replay dependency until integration or review2026-10-19T00:00:00Z; exact temporary namespaces/processes retired here; no provider/key creation."})
        if errors:
            raise RuntimeError(errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--kernel-elf", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if not 45 <= args.timeout <= 180:
        parser.error("timeout must be45..180seconds")
    work = args.work.resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=False)

    def stopped(_signum, _frame):
        raise KeyboardInterrupt("TCP MTU boundary fixture terminated")

    signal.signal(signal.SIGTERM, stopped)
    signal.signal(signal.SIGINT, stopped)
    try:
        result = run(args, work)
        result["artifacts"] = {path.name: base.identity(path, base.read_bound(path,
            128 * 1024 * 1024 if path.suffix == ".iso" else MAX_LOG)) for path in sorted(work.iterdir()) if path.is_file()}
    except BaseException as error:
        peer.write(work / "RESULT.json", {"schema": "absd-native-tcp-mtu-boundary-proof/1", "disposition": "FAIL", "error": repr(error), "limits": LIMITS})
        raise
    peer.write(work / "RESULT.json", result)


if __name__ == "__main__":
    main()
