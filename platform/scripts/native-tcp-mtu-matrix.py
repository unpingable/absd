#!/usr/bin/env python3
"""Actual Linux-router TCP MTU refusal and a separate fresh-grant TCP echo.

Only the owned disposable VM may execute this runner. Linux emits the ICMP
error from a real DF forwarding failure. No synthetic positive/error packet
is sent. This is opt-in refusal, not PMTU recovery, authentication, child IPC,
physical-time evidence or live implementation replacement.
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
    raise SystemExit("native-tcp-mtu-matrix: optimized Python is refused")
SCRIPTS = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


base = module("tcp_mtu_base", SCRIPTS / "native-echo-matrix.py")
peer = module("tcp_mtu_peer", SCRIPTS / "native-tcp-mtu-peer.py")
from served_ram import served_qemu
GUEST_MAC = bytes.fromhex("525400123456")
ROUTER_MAC = bytes.fromhex("525500000601")
ROUTER_EGRESS_MAC = bytes.fromhex("525500000602")
PEER_MAC = bytes.fromhex("525500000603")
GUEST_IP = bytes((192, 0, 2, 100))
ROUTER_IP = bytes((192, 0, 2, 1))
PEER_IP = bytes((198, 51, 100, 2))
MAX_CAPTURE, MAX_LOG, MAX_ELF = 4 * 1024 * 1024, 8 * 1024 * 1024, base.MAX_ELF
LIMITS = ("One native owner and synchronous local Pipe/Session fixture; no kernel pipe or child IPC. "
          "An actual routed IPv4 DF submission receives unauthenticated ICMP advice and fences its "
          "opt-in stream; no recovery, replay, authenticated origin, physical RTT, all-memory or DMA claim. "
          "Guest boot clocks and Linux/capture clocks are never subtracted.")


def number(row, key):
    assert re.fullmatch(r"0|[1-9][0-9]*", row[key]), "canonical integer: " + key
    value = int(row[key])
    assert value < 2**64, "u64 bound"
    return value


def hexbytes(row, key, length):
    value = bytes.fromhex(row[key])
    assert value.hex() == row[key] and len(value) == length, "exact hexadecimal bytes: " + key
    return value


def ipv4(frame):
    assert frame[12:14] == b"\x08\x00" and len(frame) >= 34, "IPv4 Ethernet layout"
    ip = frame[14:]
    assert ip[0] == 0x45 and 20 <= int.from_bytes(ip[2:4], "big") <= 1500, "bounded no-options IPv4"
    length = int.from_bytes(ip[2:4], "big")
    assert len(ip) == length or (len(frame) == 60 and length < 46 and not any(ip[length:])), "exact IPv4 size or Ethernet zero padding"
    ip = ip[:length]
    assert base.checksum(ip[:20]) == 0 and ip[8] > 0, "IPv4 header checksum/TTL"
    assert int.from_bytes(ip[6:8], "big") & 0xbfff == 0, "IPv4 no fragment/reserved flag"
    return ip


def tcp(ip):
    assert ip[9] == 6 and len(ip) >= 40, "TCP packet"
    data = ip[20:]
    header = (data[12] >> 4) * 4
    assert 20 <= header <= 60 and header <= len(data) and data[12] & 15 == 0, "TCP header size/reserved"
    pseudo = ip[12:20] + b"\x00\x06" + len(data).to_bytes(2, "big")
    assert base.checksum(pseudo + data) == 0, "complete TCP checksum"
    return {"source": int.from_bytes(data[:2], "big"), "destination": int.from_bytes(data[2:4], "big"),
            "sequence": int.from_bytes(data[4:8], "big"), "acknowledgement": int.from_bytes(data[8:12], "big"),
            "flags": data[13], "header_bytes": header, "body": data[header:], "options": data[20:header]}


def mss(options):
    values, offset = [], 0
    while offset < len(options):
        kind = options[offset]
        if kind == 0:
            assert not any(options[offset:]), "TCP options after END"
            break
        if kind == 1:
            offset += 1
            continue
        assert offset + 2 <= len(options) and options[offset + 1] >= 2, "TCP option layout"
        length = options[offset + 1]
        assert offset + length <= len(options), "TCP option bounds"
        if kind == 2:
            assert length == 4
            values.append(int.from_bytes(options[offset + 2:offset + 4], "big"))
        offset += length
    assert len(values) == 1, "one actual peer MSS option"
    return values[0]


def icmp_quote(frame, submitted):
    ip, original = ipv4(frame), ipv4(submitted)
    assert ip[12:20] == ROUTER_IP + GUEST_IP and ip[9] == 1, "router ICMP tuple"
    body = ip[20:]
    assert len(body) >= 8 + 28 and body[:2] == b"\x03\x04", "fragmentation-needed literal quote minimum"
    assert base.checksum(body) == 0 and body[4:6] == b"\0\0", "ICMP checksum/unused field"
    assert int.from_bytes(body[6:8], "big") == 576, "actual router MTU"
    quote = body[8:]
    assert 28 <= len(quote) <= len(original) and original.startswith(quote), "exact original IPv4/TCP quoted prefix"
    assert len(original) > 576 and original[6:8] == b"\x40\0", "actual oversized DF IPv4 submission"
    segment = tcp(original)
    assert original[12:20] == GUEST_IP + PEER_IP and (segment["source"], segment["destination"]) == (7100, 42100)
    assert segment["body"] == peer.NEGATIVE, "actual1024-byte native TCP submission"
    return {"mtu": 576, "quote_bytes": len(quote), "quote_hex": quote.hex(),
            "original_ip_bytes": len(original), "sequence": segment["sequence"],
            "submitted_sha256": hashlib.sha256(submitted).hexdigest(),
            "ICMP_sha256": hashlib.sha256(frame).hexdigest()}


def rpc(row):
    request = hexbytes(row, "request_hex", number(row, "request_bytes"))
    reply = hexbytes(row, "reply_hex", number(row, "reply_bytes"))
    assert 12 <= len(request) <= 1036 and 12 <= len(reply) <= 1036, "RPC message bound"
    phase = row["phase"]
    port = 42100 if phase == "refusal" else 42101
    target = PEER_IP + port.to_bytes(2, "big")
    assert request[0] == reply[0] == 4 and request[3] == reply[3] == 0, "actual explicit v4 RPC"
    assert request[2] == 0 and request[4:10] == reply[4:10] == target, "exact RPC grant tuple"
    op, amount = request[1], int.from_bytes(request[10:12], "big")
    assert op in (16, 17, 18, 19, 20, 21, 22) and reply[1] == op, "RPC opcode correspondence"
    assert len(request) == (12 + amount if op == 18 else 12), "RPC complete request"
    assert 0 < amount <= 1024 if op in (18, 19) else amount == 0, "RPC capacity/count"
    code, count = reply[2], int.from_bytes(reply[10:12], "big")
    if code:
        assert len(reply) == 12 and code in (5, 6, 17), "expected complete RPC refusal"
        assert count == (576 if code == 17 else 0), "RPC error detail"
        assert code != 17 or phase == "refusal", "no positive MTU refusal"
        assert code != 6 or phase == "positive", "no negative app/EOF observation"
    elif op in (16, 17):
        assert len(reply) == 13 and count == 1 and reply[12] & ~7 == 0, "RPC status reply"
    elif op == 18:
        assert len(reply) == 12 and 0 < count <= amount, "RPC accepted write count"
    elif op == 19:
        assert len(reply) == 12 + count and 0 < count <= amount, "RPC actual read body"
        assert phase == "positive", "no negative successful application read"
    else:
        assert len(reply) == 12 and count == 0, "RPC empty success reply"
    return {"op": op, "code": code, "count": count, "request": request, "reply": reply}


KEYS = {
    "BEGIN": {"v", "start_ms", "until_ms", "refusal_until_ms", "guest", "router", "peer"},
    "FRAME": {"v", "direction", "ordinal", "phase", "at_ms", "bytes", "hex"},
    "RPC": {"v", "index", "phase", "at_ms", "request_bytes", "request_hex", "reply_bytes", "reply_hex"},
    "CONNECTED": {"v", "at_ms", "phase", "sockets"},
    "QUEUED": {"v", "at_ms", "phase", "bytes"},
    "REFUSED": {"v", "at_ms", "code", "mtu", "sockets", "until_ms", "effects"},
    "FENCED": {"v", "at_ms", "code", "rpc_before", "rpc_after", "tx_before", "tx_after"},
    "REVOKED": {"v", "at_ms", "sockets"},
    "POSITIVE": {"v", "start_ms", "until_ms", "bytes"},
    "OBSERVED": {"v", "at_ms", "bytes", "hex", "sockets"},
    "EOF": {"v", "at_ms", "phase", "code"},
    "DONE": {"v", "at_ms", "sockets", "negative_bytes", "positive_bytes"},
}


def native_records(output):
    assert output.endswith(b"\n") and len(output) <= 512 * 1024, "complete bounded native output"
    rows, frames, transactions, unique, positions = [], [], [], {}, {}
    counts, phase, previous = {"tx": 0, "rx": 0}, "refusal", 0
    connected, queued = {}, {}
    for line in output.decode("ascii").splitlines():
        match = re.fullmatch(r"TCP MTU ([A-Z]+) (.*)", line)
        assert match, "native TCP MTU record"
        row = {}
        for field in match[2].split(" "):
            assert field.count("=") == 1
            key, value = field.split("=")
            assert key and value and key not in row, "unique nonempty native field"
            row[key] = value
        kind = match[1]
        assert kind in KEYS and set(row) == KEYS[kind] and row["v"] == "1", "native record schema"
        at = number(row, "start_ms" if kind in ("BEGIN", "POSITIVE") else "at_ms")
        assert at >= previous, "monotone guest clock observations"
        previous = at
        assert not rows or rows[0][0] == "BEGIN"
        assert "DONE" not in unique, "no output after terminal"
        if rows:
            assert at < number(unique["BEGIN"], "until_ms"), "original whole guest budget"
            if phase == "positive":
                assert at < number(unique["POSITIVE"], "until_ms"), "original positive guest budget"
            elif kind != "POSITIVE":
                assert at < number(unique["BEGIN"], "refusal_until_ms"), "original refusal guest budget"
        if kind == "FRAME":
            direction = row["direction"]
            assert direction in counts and row["phase"] == phase
            counts[direction] += 1
            assert number(row, "ordinal") == counts[direction] <= 128, "full native per-direction ordinal"
            body = hexbytes(row, "hex", number(row, "bytes"))
            assert 14 <= len(body) <= 1514, "native frame size"
            assert "REVOKED" not in unique or phase == "positive", "no old-authority frame after explicit revoke"
            frames.append(row)
            positions["FRAME:" + direction + ":" + row["ordinal"]] = len(rows)
        elif kind == "RPC":
            assert row["phase"] == phase and ("REFUSED" not in unique or phase == "positive")
            assert number(row, "index") == len(transactions) + 1 <= 128, "actual RPC ordinal"
            transactions.append({"row": row, **rpc(row)})
        elif kind in ("CONNECTED", "QUEUED"):
            collection = connected if kind == "CONNECTED" else queued
            assert row["phase"] == phase and phase not in collection
            if kind == "CONNECTED":
                assert row["sockets"] == "1"
            else:
                assert phase in connected and row["bytes"] == ("1024" if phase == "refusal" else "64")
            collection[phase] = row
        else:
            assert kind not in unique, "one native lifecycle marker: " + kind
            unique[kind] = row
            positions[kind] = len(rows)
            if kind == "BEGIN":
                assert not rows and (row["guest"], row["router"], row["peer"]) == (peer.GUEST, peer.ROUTER, peer.PEER)
                assert number(row, "until_ms") == at + 30000 and number(row, "refusal_until_ms") == at + 12000
            elif kind == "REFUSED":
                assert "refusal" in queued and row["code"] == "17" and row["mtu"] == "576" and row["sockets"] == "0"
                assert row["effects"] == "unknown" and row["until_ms"] == unique["BEGIN"]["refusal_until_ms"]
                assert transactions and transactions[-1]["code"] == 17 and transactions[-1]["row"]["phase"] == "refusal"
                assert at < number(row, "until_ms"), "no renewed refusal deadline"
            elif kind == "FENCED":
                assert "REFUSED" in unique and row["code"] == "8", "actual terminal client fence"
                assert number(row, "rpc_before") == number(row, "rpc_after") == len(transactions)
                assert number(row, "tx_before") == number(row, "tx_after") == counts["tx"], "fenced call has no RPC/TX"
            elif kind == "REVOKED":
                assert "FENCED" in unique and row["sockets"] == "0"
            elif kind == "POSITIVE":
                assert "REVOKED" in unique and row["bytes"] == "64"
                assert at < number(row, "until_ms") <= min(at + 10000, number(unique["BEGIN"], "until_ms"))
                phase = "positive"
            elif kind == "OBSERVED":
                assert "positive" in queued and row["bytes"] == "64" and row["sockets"] == "1"
                assert hexbytes(row, "hex", 64) == peer.POSITIVE
                assert at < number(unique["POSITIVE"], "until_ms")
            elif kind == "DONE":
                assert "EOF" in unique and row["sockets"] == "0" and (row["negative_bytes"], row["positive_bytes"]) == ("1024", "64")
                assert at < number(unique["BEGIN"], "until_ms")
            elif kind == "EOF":
                assert "OBSERVED" in unique and row["phase"] == "positive" and row["code"] == "6"
                assert transactions and transactions[-1]["op"] == 19 and transactions[-1]["code"] == 6
                assert at < number(unique["POSITIVE"], "until_ms")
        rows.append((kind, row))
    assert set(unique) == set(KEYS) - {"FRAME", "RPC", "CONNECTED", "QUEUED"} and set(queued) == set(connected) == {"refusal", "positive"}
    assert sum(t["code"] == 17 for t in transactions) == 1
    for stage, pattern in (("refusal", peer.NEGATIVE), ("positive", peer.POSITIVE)):
        selected = [t for t in transactions if t["row"]["phase"] == stage]
        writes = [t for t in selected if t["op"] == 18 and t["code"] == 0]
        assert len(writes) == 1 and writes[0]["request"][12:] == pattern and writes[0]["count"] == len(pattern), "actual complete accepted Client.write"
        assert number(writes[0]["row"], "at_ms") <= number(queued[stage], "at_ms")
        status = [t for t in selected if t["op"] in (16, 17) and t["code"] == 0 and t["reply"][12] & 1]
        assert status and number(status[0]["row"], "at_ms") <= number(connected[stage], "at_ms"), "actual connected status"
    reads = b"".join(t["reply"][12:] for t in transactions if t["op"] == 19 and t["code"] == 0)
    assert reads == peer.POSITIVE, "actual RPC echo bytes"
    assert any(t["op"] == 20 and t["code"] == 0 and t["row"]["phase"] == "positive" for t in transactions), "positive half-close RPC"
    return {"records": len(rows), "frames": frames, "transactions": transactions,
            "lifecycle": unique, "positions": positions, "connected": connected, "queued": queued, "census": counts}


def native_output(raw, exit_status):
    assert exit_status == 3, "natural QEMU debug-exit"
    for marker in (b"\nNETWORK LINK OK ", b"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ",
                   b"\nDURABLE WORKLOAD OK\n", b"\nABSD BOOT OK\n"):
        assert marker in raw, "native terminal marker"
    assert not any(value in raw for value in (b"PANIC", b"KERNEL FAULT", b"init: FAILED", b"NIC DISABLED"))
    assert re.findall(rb"(?m)^USER EXIT pid=2 status=(.*)\n", raw) == [b"0"]
    assert re.findall(rb"(?m)^DURABLE WORKER OUTCOME generation=1 pid=2 status=(.*)\n", raw) == [b"0"]
    assert re.findall(rb"(?m)^DURABLE WORKER GENERATION (.*)\n", raw) == [b"generation=1 pid=2"]
    assert raw.count(b"EXTERNAL OUTPUT BEGIN encoding=hex\n") == 1
    assert not re.search(rb"(?m)^SPAWN OK pid=\d+ parent=2 ", raw), "owner-only fixture"
    output = bytearray()
    chunks = list(base.CHUNK.finditer(raw))
    assert len(chunks) == raw.count(b"EXTERNAL OUTPUT CHUNK")
    for chunk in chunks:
        assert int(chunk[1], 16) == len(output)
        output.extend(bytes.fromhex(chunk[2].decode()))
        assert len(output) <= 512 * 1024
    digest = 0x811c9dc5
    for byte in output:
        digest = ((digest ^ byte) * 0x1000193) & 0xffffffff
    ends = re.findall(rb"(?m)^EXTERNAL OUTPUT END bytes=(\d+) digest=([0-9a-f]{8})\n", raw)
    assert ends == [(str(len(output)).encode(), f"{digest:08x}".encode())] and raw.count(b"EXTERNAL OUTPUT END ") == 1
    native = native_records(bytes(output))
    stats = re.findall(rb"(?m)^NIC STATS (.*)\n", raw)
    assert len(stats) == 1
    fields = dict(part.split("=") for part in stats[0].decode().split(" "))
    assert set(fields) == {"rx_frames", "rx_refused", "rx_missed", "tx_frames", "tx_refused", "tx_errors", "flags"}
    assert all(fields[key] == "0" for key in ("rx_refused", "rx_missed", "tx_refused", "tx_errors")) and fields["flags"] == "1"
    assert number(fields, "rx_frames") == native["census"]["rx"] and number(fields, "tx_frames") == native["census"]["tx"]
    native.update(output=output.decode(), output_bytes=len(output), FNV32=f"{digest:08x}", NIC_counters=fields)
    return native


def frame_equal(direction, native, captured):
    if native == captured:
        return True
    if direction != "tx":
        return False
    if len(native) == 42 and native[12:14] == b"\x08\x06" and captured == native + bytes(18):
        return True
    if len(native) != 54 or captured != native + bytes(6):
        return False
    try:
        ip = ipv4(native)
        packet = tcp(ip)
        return (len(ip) == 40 and packet["header_bytes"] == 20 and not packet["body"]
                and packet["flags"] in (0x10, 0x11, 0x14, 0x04))
    except AssertionError:
        return False


def inspect_frames(rows, native, downstream):
    by_direction, census, oversized, errors, positive = {"tx": [], "rx": []}, [], [], [], []
    syns, echo_tx, echo_rx = [], [], []
    for index, stamp, frame in rows:
        direction = "tx" if frame[6:12] == GUEST_MAC else "rx"
        assert frame[6:12] == (GUEST_MAC if direction == "tx" else ROUTER_MAC), "guest-facing exact Ethernet source"
        assert frame[:6] in ((ROUTER_MAC, b"\xff" * 6) if direction == "tx" else (GUEST_MAC, b"\xff" * 6))
        by_direction[direction].append(frame)
        census.append({"index": index, "timestamp": stamp, "direction": direction,
                       "bytes": len(frame), "sha256": hashlib.sha256(frame).hexdigest()})
        if frame[12:14] == b"\x08\x06":
            assert len(frame) in (42, 60) and not any(frame[42:])
            assert frame[14:20] == b"\x00\x01\x08\x00\x06\x04" and frame[22:28] == frame[6:12]
            assert frame[28:32] + frame[38:42] == (GUEST_IP + ROUTER_IP if direction == "tx" else ROUTER_IP + GUEST_IP)
            op = int.from_bytes(frame[20:22], "big")
            assert op in (1, 2)
            if op == 1:
                assert frame[:6] == b"\xff" * 6 and frame[32:38] in (bytes(6), b"\xff" * 6)
            else:
                assert frame[:6] == frame[32:38] == (ROUTER_MAC if direction == "tx" else GUEST_MAC)
            continue
        ip = ipv4(frame)
        if ip[9] == 1:
            assert direction == "rx" and ip[20:22] == b"\x03\x04", "only expected routed error ICMP"
            errors.append((index, frame))
            continue
        packet = tcp(ip)
        assert ip[12:20] == (GUEST_IP + PEER_IP if direction == "tx" else PEER_IP + GUEST_IP)
        local = packet["source"] if direction == "tx" else packet["destination"]
        remote = packet["destination"] if direction == "tx" else packet["source"]
        assert (local, remote) in ((7100, 42100), (7101, 42101)), "only exact two native grants"
        if direction == "rx" and local == 7100 and packet["flags"] & 2:
            assert packet["flags"] & 16 and mss(packet["options"]) >= 1024, "peer actual sufficient SYNACK MSS"
            syns.append(index)
        if local == 7100:
            assert not packet["body"] or direction == "tx" and packet["body"] == peer.NEGATIVE, "no error-stream peer application data"
            if packet["body"]:
                assert len(ip) > 576 and ip[6:8] == b"\x40\0"
                oversized.append((index, frame))
        else:
            positive.append(index)
            (echo_tx if direction == "tx" else echo_rx).append(packet)
    assert oversized and errors and syns, "actual route/MSS/submission/error witnesses"
    assert syns[0] < oversized[0][0] < errors[0][0] and positive and errors[-1][0] < positive[0], "wire phase order"
    matches = []
    for index, frame in errors:
        candidates = [(at, submitted) for at, submitted in oversized if at < index and ipv4(submitted).startswith(ipv4(frame)[28:])]
        assert candidates, "error quotes an earlier actual submitted frame"
        at, submitted = candidates[0]
        matches.append({"capture_index": index, "submission_index": at, **icmp_quote(frame, submitted)})
    for direction, captured in by_direction.items():
        observed = [bytes.fromhex(row["hex"]) for row in native["frames"] if row["direction"] == direction]
        assert len(observed) == len(captured) and all(frame_equal(direction, a, b) for a, b in zip(observed, captured)), "complete native/capture ordered byte census"
    matched_rx = []
    for row in native["frames"]:
        value = bytes.fromhex(row["hex"])
        if row["direction"] == "rx" and any(value == frame for _, frame in errors):
            matched_rx.append(native["positions"]["FRAME:rx:" + row["ordinal"]])
    assert matched_rx, "matched error actually consumed by native Link"
    boundary, revoked = min(matched_rx), native["positions"]["REVOKED"]
    assert boundary < native["positions"]["REFUSED"] < native["positions"]["FENCED"] < revoked
    for row in native["frames"]:
        value = bytes.fromhex(row["hex"])
        position = native["positions"]["FRAME:" + row["direction"] + ":" + row["ordinal"]]
        if row["direction"] != "tx" or position <= boundary or value[12:14] != b"\x08\x00":
            continue
        ip = ipv4(value)
        if ip[9] != 6:
            continue
        segment = tcp(ip)
        if (segment["source"], segment["destination"]) == (7100, 42100):
            assert position > revoked, "old tuple TX after consumed MTU error and before explicit revoke"
            assert not segment["body"] and segment["flags"] in (0x04, 0x14), "post-revoke old tuple only generic stack RST, no application bytes"
    for packets in (echo_tx, echo_rx):
        bodies = [packet for packet in packets if packet["body"]]
        assert bodies and any(packet["flags"] & 1 for packet in packets), "positive actual data and FIN both ways"
        initial = bodies[0]["sequence"]
        assembled = {}
        for packet in bodies:
            for at, value in enumerate(packet["body"]):
                offset = (packet["sequence"] - initial + at) & 0xffffffff
                assert offset < 64 and (offset not in assembled or assembled[offset] == value), "positive bounded consistent sequence reassembly"
                assembled[offset] = value
        assert bytes(assembled[i] for i in range(64)) == peer.POSITIVE and len(assembled) == 64
    # Every routed TCP packet has exactly the same IP bytes except for the
    # router's specified TTL decrement and corresponding IPv4 checksum.
    forwarded, downstream_error_data = [], []
    expected_routes, actual_routes = {"out": [], "in": []}, {"out": [], "in": []}
    for _, _, frame in rows:
        if frame[12:14] != b"\x08\x00" or frame[23] != 6:
            continue
        original = ipv4(frame)
        if original[12:20] == GUEST_IP + PEER_IP:
            if len(original) > 576:
                continue
            candidate = bytearray(original)
            assert candidate[8] > 1
            candidate[8] -= 1
            candidate[10:12] = b"\0\0"
            candidate[10:12] = base.checksum(bytes(candidate[:20])).to_bytes(2, "big")
            expected_routes["out"].append(bytes(candidate))
        else:
            expected_routes["in"].append(original)
    for index, stamp, frame in downstream:
        if frame[12:14] == b"\x08\x06":
            assert len(frame) in (42, 60) and not any(frame[42:])
            assert frame[14:20] == b"\x00\x01\x08\x00\x06\x04"
            assert frame[28:32] + frame[38:42] in (bytes((198, 51, 100, 1)) + PEER_IP, PEER_IP + bytes((198, 51, 100, 1)))
            continue
        ip = ipv4(frame)
        segment = tcp(ip)
        assert frame[6:12] in (ROUTER_EGRESS_MAC, PEER_MAC) and frame[:6] == (PEER_MAC if frame[6:12] == ROUTER_EGRESS_MAC else ROUTER_EGRESS_MAC)
        out = ip[12:20] == GUEST_IP + PEER_IP
        assert out or ip[12:20] == PEER_IP + GUEST_IP
        if out and segment["destination"] == 42100 and segment["body"]:
            downstream_error_data.append(index)
        if out:
            actual_routes["out"].append(ip)
        else:
            candidate = bytearray(ip)
            assert candidate[8] > 1, "peer TTL permits forwarding"
            candidate[8] -= 1
            candidate[10:12] = b"\0\0"
            candidate[10:12] = base.checksum(bytes(candidate[:20])).to_bytes(2, "big")
            actual_routes["in"].append(bytes(candidate))
        forwarded.append({"index": index, "timestamp": stamp, "sha256": hashlib.sha256(frame).hexdigest()})
    assert forwarded and not downstream_error_data, "oversized1024-byte TCP data never forwarded to peer"
    assert expected_routes == actual_routes, "full two-leg ordered TCP routing census (TTL/checksum only)"
    return {"census": census, "ICMP_matches": matches, "downstream_forwarded": forwarded,
            "oversized_submissions": len(oversized), "peer_MSS_witnesses": syns}


def inspect_peer(report, expected_pid, namespace_inode):
    assert report["schema"] == "absd-native-tcp-mtu-peer/1" and report["disposition"] == "PASS"
    assert report["pid"] == expected_pid and report["network_namespace_inode"] == namespace_inode and report["bind"] == peer.PEER
    assert report["sockets_closed"] is True and report["started_monotonic_ns"] <= report["ended_monotonic_ns"]
    assert report.get("runner_stop_received") is True, "peer held its sockets until the runner stop"
    stopped = report.get("runner_stop_monotonic_ns")
    assert type(stopped) is int and report["started_monotonic_ns"] <= stopped <= report["ended_monotonic_ns"]
    assert all(row["monotonic_ns"] <= stopped for row in report["events"]), "no peer event after the runner stop"
    connections = {row["port"]: row for row in report["connections"]}
    assert len(report["connections"]) == 2 and set(connections) == {42100, 42101}
    for port, expected in ((42100, b""), (42101, peer.POSITIVE)):
        row = connections[port]
        assert row["source"] == [peer.GUEST, 7100 if port == 42100 else 7101] and row["destination"] == [peer.PEER, port]
        assert row["received_bytes"] == len(expected) and row["received_hex"] == expected.hex() and row["received_sha256"] == hashlib.sha256(expected).hexdigest()
        assert row["finished"] is True and report["started_monotonic_ns"] <= row["accepted_monotonic_ns"] <= row["finished_monotonic_ns"] <= report["ended_monotonic_ns"]
    error, positive = connections[42100], connections[42101]
    assert error["sent"] == 0 and error["completion"] in ("reset", "eof", "bounded-no-data")
    assert positive["sent"] == 64 and positive["eof"] is True and positive["reset"] is False and positive["completion"] == "echo-and-half-close"
    events = report["events"]
    assert 1 <= len(events) <= 64
    previous, reads, writes, accepted = report["started_monotonic_ns"], {42100: bytearray(), 42101: bytearray()}, bytearray(), []
    terminal_reads, windows, shutdowns = {}, [], []
    for event in events:
        assert previous <= event["monotonic_ns"] <= report["ended_monotonic_ns"]
        previous = event["monotonic_ns"]
        port = event["port"]
        assert port in connections
        if event["event"] == "accept":
            assert port not in accepted and event["source"] == connections[port]["source"] and event["destination"] == connections[port]["destination"]
            accepted.append(port)
        else:
            assert port in accepted
            if event["event"] == "read":
                value = bytes.fromhex(event["hex"])
                assert value.hex() == event["hex"] and len(value) == event["bytes"] <= 65
                reads[port].extend(value)
                assert port not in terminal_reads, "no peer read after EOF/reset"
                if not value:
                    assert type(event["reset"]) is bool
                    terminal_reads[port] = "reset" if event["reset"] else "eof"
            elif event["event"] == "write":
                assert port == 42101 and event["offset"] == len(writes)
                value = bytes.fromhex(event["hex"])
                assert 0 < len(value) == event["bytes"] and value.hex() == event["hex"]
                writes.extend(value)
            elif event["event"] == "zero-window-ended":
                assert port == 42100 and event["bytes"] == 0 and event["elapsed_ns"] >= report["zero_read_window_ns"]
                assert event["monotonic_ns"] - error["accepted_monotonic_ns"] >= report["zero_read_window_ns"]
                assert type(event["pending_read_would_block"]) is bool
                windows.append(event)
            else:
                assert event["event"] == "shutdown-write" and port == 42101 and event["bytes"] == 64
                assert terminal_reads.get(42101) == "eof" and writes == peer.POSITIVE
                shutdowns.append(event)
    assert reads[42100] == b"" and reads[42101] == writes == peer.POSITIVE
    assert accepted == [42100, 42101]
    assert len(shutdowns) == 1 and terminal_reads.get(42101) == "eof"
    if error["completion"] == "bounded-no-data":
        assert len(windows) == 1
    else:
        assert not windows and terminal_reads.get(42100) == error["completion"]
    return {"error_received_bytes": 0, "positive_received_bytes": 64, "positive_echo_bytes": 64,
            "error_completion": error["completion"], "clock_scope": "host monotonic only; no guest-clock subtraction"}


def json_value(value):
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {key: json_value(part) for key, part in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_value(part) for part in value]
    return value


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
        iso, disk = work / "native-tcp-mtu.iso", work / "native-tcp-mtu.img"
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
                (router_ns, tap, "192.0.2.1/24", ROUTER_MAC, 1500),
                (router_ns, egress, "198.51.100.1/24", ROUTER_EGRESS_MAC, 576),
                (peer_ns, peer_device, "198.51.100.2/24", PEER_MAC, 1500)):
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
        topology = {"schema": "absd-native-tcp-mtu-topology/1", "host_kernel": list(os.uname()), "offloads": offloads}
        for role, namespace in (("router", router_ns), ("peer", peer_ns)):
            addresses = json.loads(checked(["ip", "-n", namespace, "-j", "address", "show"]))
            routes = json.loads(checked(["ip", "-n", namespace, "-j", "-4", "route", "show"]))
            keys = ["net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6", "net.ipv4.ip_forward"]
            settings = {key: control(namespace, "sysctl", "-n", key).strip() for key in keys}
            assert settings[keys[0]] == settings[keys[1]] == "1" and settings[keys[2]] == ("1" if role == "router" else "0")
            devices = {row["ifname"]: row for row in addresses if row["ifname"] != "lo"}
            expected = {tap: (1500, "192.0.2.1", ROUTER_MAC), egress: (576, "198.51.100.1", ROUTER_EGRESS_MAC)} if role == "router" else {peer_device: (1500, "198.51.100.2", PEER_MAC)}
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
        peer.atomic(work / "TOPOLOGY.json", topology)
        serial = work / "native-tcp-mtu.serial.log"
        ingress_capture, egress_capture = work / "native-tcp-mtu.pcap", work / "router-egress.pcap"
        bounds[serial], bounds[ingress_capture], bounds[egress_capture] = MAX_LOG, MAX_CAPTURE, MAX_CAPTURE
        dump = start("router-capture", ["ip", "netns", "exec", router_ns, "tcpdump", "--immediate-mode", "-U", "-n", "-i", egress, "-s", "0", "-w", str(egress_capture)])
        ready_at = time.monotonic() + left(5)
        while b"listening on" not in base.read_bound(work / "router-capture.log", MAX_LOG):
            assert dump.poll() is None and time.monotonic() < ready_at, "router capture ready deadline"
            time.sleep(0.01)
        peer_result = work / "PEER.json"
        ready_path = peer_result.with_suffix(".ready.json")
        bounds[peer_result], bounds[ready_path] = 65536, 4096
        actor = start("tcp-peer", ["ip", "netns", "exec", peer_ns, sys.executable, "-I", "-B", str(SCRIPTS / "native-tcp-mtu-peer.py"), "--output", str(peer_result), "--stop-file", str(work / "PEER-STOP"), "--timeout", str(min(90, int(left(90))))])
        ready_at = time.monotonic() + left(5)
        while not ready_path.exists():
            assert actor.poll() is None and time.monotonic() < ready_at, "TCP peer ready deadline"
            time.sleep(0.01)
        ready = json.loads(base.read_bound(ready_path, 4096))
        assert ready["schema"] == "absd-native-tcp-mtu-peer-ready/1" and ready["pid"] == actor.pid
        assert ready["network_namespace_inode"] == topology["peer"]["inode"] and ready["bind"] == peer.PEER and ready["ports"] == [42100, 42101]
        qemu = shutil.which(os.environ.get("ABSD_QEMU", "qemu-system-x86_64"))
        assert qemu, "QEMU executable"
        command = served_qemu(["ip", "netns", "exec", router_ns, str(Path(qemu).resolve()),
            "-accel", "tcg,thread=single", "-cpu", "max,vendor=GenuineIntel,+rdrand", "-smp", "1", "-m", "256M",
            "-cdrom", str(iso), "-drive", f"file={disk},format=raw,if=ide,index=0", "-display", "none", "-serial", f"file:{serial}",
            "-no-reboot", "-no-shutdown", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
            "-device", f"e1000,netdev=n0,mac={GUEST_MAC.hex(':')}", "-netdev", f"tap,id=n0,ifname={tap},script=no,downscript=no,vnet_hdr=off",
            "-object", f"filter-dump,id=cap0,netdev=n0,file={ingress_capture}"])
        emulator = start("qemu", command)
        peer.atomic(work / "LAUNCH.json", {"schema": "absd-native-tcp-mtu-launch/1", "inputs": inputs,
            "ISO": base.identity(iso, base.read_bound(iso, bounds[iso])), "command": command,
            "runner_pid": os.getpid(), "process_pid_and_pgid": {name: p.pid for name, p in processes.items()},
            "runner": base.identity(__file__, base.read_bound(__file__, MAX_LOG)),
            "peer_source": base.identity(SCRIPTS / "native-tcp-mtu-peer.py", base.read_bound(SCRIPTS / "native-tcp-mtu-peer.py", MAX_LOG)),
            "topology": topology, "outer_timeout_seconds": args.timeout})
        while emulator.poll() is None:
            left(args.timeout)
            assert actor.poll() is None and dump.poll() is None, "peer/capture failed before QEMU exit"
            time.sleep(0.02)
        os.killpg(dump.pid, signal.SIGINT)
        dump.wait(timeout=left(3))
        assert dump.returncode == 0, "router capture terminal status"
        dump_log = base.read_bound(work / "router-capture.log", MAX_LOG)
        assert re.findall(rb"(?m)^(\d+) packets dropped by kernel\r?$", dump_log) == [b"0"], "router capture loss census"
        peer.atomic(work / "PEER-STOP", {"reason": "natural QEMU end and captures closed"})
        actor.wait(timeout=left(3))
        assert actor.returncode == 0, "TCP peer terminal status"
        raw = base.read_bound(serial, MAX_LOG)
        observed = native_output(raw, emulator.returncode)
        capture_bytes, captured = base.packet_records(ingress_capture)
        egress_bytes, egress_rows = base.packet_records(egress_capture)
        frames = inspect_frames(captured, observed, egress_rows)
        report = json.loads(base.read_bound(peer_result, 65536))
        checked_peer = inspect_peer(report, actor.pid, topology["peer"]["inode"])
        return json_value({"schema": "absd-native-tcp-mtu-proof/1", "disposition": "PASS", "limits": LIMITS,
            "native": observed, "wire": frames, "peer": checked_peer, "inputs": inputs,
            "capture": base.identity(ingress_capture, capture_bytes), "egress_capture": base.identity(egress_capture, egress_bytes)})
    finally:
        terminal, group_terminal = {}, {}
        for name in ("qemu", "tcp-peer", "router-capture", "iso-build"):
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
        peer.atomic(work / "LOCAL-CLEANUP.json", {"schema": "absd-native-tcp-mtu-cleanup/1",
            "created_namespace_identities": created, "namespaces_absent": absent,
            "process_exit_status": terminal, "owned_session_process_groups_terminal": group_terminal,
            "errors": errors, "disposition": "FAIL" if errors else "PASS",
            "custody": "Root source/result/replay dependency until integration or review2026-10-19T00:00:00Z; exact temporary namespaces/processes retired here; no provider/key creation."})
        if errors:
            raise RuntimeError(errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path, help="fresh output directory")
    parser.add_argument("--elf", type=Path, required=True, help="native TCP MTU owner ELF")
    parser.add_argument("--kernel-elf", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if not 45 <= args.timeout <= 180:
        parser.error("timeout must be45..180seconds")
    work = args.work.resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=False)

    def stopped(_signum, _frame):
        raise KeyboardInterrupt("TCP MTU fixture terminated")

    signal.signal(signal.SIGTERM, stopped)
    signal.signal(signal.SIGINT, stopped)
    try:
        result = run(args, work)
        artifacts = {}
        for path in sorted(work.iterdir()):
            if path.is_file():
                limit = 128 * 1024 * 1024 if path.suffix == ".iso" else MAX_LOG
                artifacts[path.name] = base.identity(path, base.read_bound(path, limit))
        result["artifacts"] = artifacts
    except BaseException as error:
        peer.atomic(work / "RESULT.json", {"schema": "absd-native-tcp-mtu-proof/1", "disposition": "FAIL", "error": repr(error), "limits": LIMITS})
        raise
    peer.atomic(work / "RESULT.json", result)


if __name__ == "__main__":
    main()
