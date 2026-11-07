#!/usr/bin/env python3
"""Actual delegated kernel-pipe v4 refusal with a genuine Linux MTU576 router."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid

if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
    raise SystemExit("optimized Python refused")
SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("delegated_prior", SCRIPTS / "native-tcp-mtu-matrix.py")
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
base, peer, number = prior.base, prior.peer, prior.number
from served_ram import served_qemu
MAX_LOG, MAX_CAPTURE, MAX_ELF = prior.MAX_LOG, prior.MAX_CAPTURE, prior.MAX_ELF
GUEST_MAC, ROUTER_MAC, ROUTER_EGRESS_MAC, PEER_MAC = prior.GUEST_MAC, prior.ROUTER_MAC, prior.ROUTER_EGRESS_MAC, prior.PEER_MAC
LIMITS = ("Actual kernel-pipe delegation and unauthenticated Linux-generated MTU advice; finite owner/child "
          "observations, no recovery, authenticated origin, private grant-expiry, all-memory/DMA or replacement claim. "
          "Buffered ledger publication and post-call clocks alone do not establish cross-process causal order.")
FIELDS = {
    "BEGIN": "start_ms until_ms refusal_until_ms guest router peer",
    "GRANT": "child phase local_port peer_port at_ms until_ms lifetime_ms",
    "SPAWN": "child phase process_handle at_ms no_spawn nic_copies protocol_handles diagnostic_handles",
    "BOOTSTRAP": "child phase at_ms bytes hex",
    "PIPE": "observer child phase direction ordinal offset at_ms bytes hex",
    "PIPE_SEAL": "observer child phase records request_bytes reply_bytes read_calls write_calls request_eof reply_eof failed",
    "FRAME": "direction ordinal phase at_ms bytes hex",
    "FRAME_SEAL": "phase records tx rx",
    "REAP": "child phase reaped_ms at_ms kind status request_eof_ms result_eof_ms channel_live eof_revoked",
    "RETIRED": "child phase explicit_revoke_ms channel_live_before_explicit channel_live process_handle_live protocol_handles result_handles sockets objects_restored",
    "POSITIVE": "at_ms until_ms child fresh_grant old_child_retired",
    "CENSUS": "label processes handles pipes cells frames",
    "DONE": "at_ms children sockets negative_bytes positive_bytes",
    "CHILD_BEGIN": "child phase at_ms until_ms nic bootstrap_bytes bootstrap_hex",
    "CHILD_CONNECTED": "child phase at_ms",
    "CHILD_QUEUED": "child phase at_ms bytes",
    "CHILD_REFUSED": "child phase at_ms code mtu effects",
    "CHILD_FENCED": "child phase at_ms read_code write_code request_before request_after reply_before reply_after reads_before reads_after writes_before writes_after",
    "CHILD_OBSERVED": "child phase at_ms bytes hex",
    "CHILD_EOF": "child phase at_ms code",
    "CHILD_DONE": "child phase at_ms nic",
}
FIELDS = {kind: set(value.split()) | {"v"} for kind, value in FIELDS.items()}


def binary(row, key, count):
    value = b"" if row[key] == "none" else bytes.fromhex(row[key])
    assert len(value) == count and row[key] == (value.hex() if value else "none"), "exact literal bytes"
    return value


def framed(value):
    result, offset = [], 0
    while offset < len(value):
        assert offset + 2 <= len(value), "complete framing prefix"
        size = int.from_bytes(value[offset:offset + 2], "big")
        assert 12 <= size <= 1036 and offset + 2 + size <= len(value), "complete bounded framed message"
        result.append((value[offset + 2:offset + 2 + size], offset + 2 + size))
        offset += 2 + size
    return result


def pipe_stream(rows, seal, observer, child, start, until):
    values, ordinals, eof = {"request": bytearray(), "reply": bytearray()}, {"request": 0, "reply": 0}, {}
    spans, eof_positions = {"request": [], "reply": []}, {}
    previous = start
    assert len(rows) <= 512 and number(seal, "records") == len(rows) and seal["failed"] == "0"
    for position, row in enumerate(rows):
        direction = row["direction"]
        assert direction in values and direction not in eof
        assert (row["observer"], row["child"]) == (observer, str(child))
        at = number(row, "at_ms")
        assert previous <= at < until, "pipe observation clock bound"
        previous = at
        ordinals[direction] += 1
        assert number(row, "ordinal") == ordinals[direction] and number(row, "offset") == len(values[direction])
        size = number(row, "bytes")
        assert size <= 256
        value = binary(row, "hex", size)
        if not value:
            assert observer == "owner" and direction == "request", "only actual owner request EOF in successful fixture"
            eof[direction] = at
            eof_positions[direction] = position
        else:
            spans[direction].append((len(values[direction]), len(values[direction]) + size, position))
        values[direction].extend(value)
        assert len(values[direction]) <= 65536
    for direction in values:
        assert number(seal, direction + "_bytes") == len(values[direction])
        assert seal[direction + "_eof"] == (str(eof[direction]) if direction in eof else "none")
    read_direction = "request" if observer == "owner" else "reply"
    assert number(seal, "read_calls") >= ordinals[read_direction]
    assert number(seal, "write_calls") >= ordinals["reply" if observer == "owner" else "request"]
    assert ("request" in eof) == (observer == "owner"), "true request EOF required"
    # Each observer records its actual calls in order. Bootstrap is the sole
    # unsolicited reply; Client/Channel then keep exactly one RPC in flight.
    requests, replies = framed(values["request"]), framed(values["reply"][20:])
    assert len(values["reply"]) >= 20 and requests and len(requests) == len(replies), "one reply per actual request"

    def observed_position(direction, offset):
        return next(position for begin, end, position in spans[direction] if begin <= offset < end)

    previous_reply = observed_position("reply", 19)
    request_start, reply_start = 0, 20
    for (_, request_end), (_, reply_end) in zip(requests, replies):
        reply_end += 20
        request_first, request_last = (observed_position("request", offset) for offset in (request_start, request_end - 1))
        reply_first, reply_last = (observed_position("reply", offset) for offset in (reply_start, reply_end - 1))
        assert previous_reply < request_first <= request_last < reply_first <= reply_last, "one request in flight observer order"
        previous_reply, request_start, reply_start = reply_last, request_end, reply_end
    if observer == "owner":
        assert previous_reply < eof_positions["request"], "request EOF after complete final reply"
    return {key: bytes(value) for key, value in values.items()}


def native_records(output):
    assert output.endswith(b"\n") and len(output) <= 4 * 1024 * 1024
    single, scoped, pipes, seals, censuses, frames, frame_seals, publication = {}, {}, {}, {}, {}, [], {}, {}
    count = 0
    for line in output.decode("ascii").splitlines():
        match = re.fullmatch(r"TCP MTU DELEGATED ([A-Z_]+) (.*)", line)
        assert match and match[1] in FIELDS, "exact successful record kind"
        kind, row = match[1], {}
        for word in match[2].split(" "):
            assert word.count("=") == 1
            key, value = word.split("=")
            assert key not in row and value
            row[key] = value
        assert set(row) == FIELDS[kind] and row["v"] == "1", "exact record fields"
        if "child" in row:
            child = number(row, "child")
            assert child in (1, 2)
            if "phase" in row:
                assert row["phase"] == ("refusal" if child == 1 else "positive")
        if kind == "PIPE":
            assert row["observer"] in ("owner", "child")
            pipes.setdefault((row["observer"], child), []).append(row)
        elif kind == "PIPE_SEAL":
            key = row["observer"], child
            assert key not in seals and key in pipes
            seals[key] = row
        elif kind == "FRAME":
            frames.append(row)
        elif kind == "FRAME_SEAL":
            assert row["phase"] in ("refusal", "positive") and row["phase"] not in frame_seals
            frame_seals[row["phase"]] = (row, len(frames))
            publication[kind, row["phase"]] = count
        elif kind == "CENSUS":
            assert row["label"] not in censuses
            censuses[row["label"]] = row
            publication[kind, row["label"]] = count
        elif "child" in row and kind != "POSITIVE":
            assert (kind, child) not in scoped
            scoped[kind, child] = row
            publication[kind, child] = count
        else:
            assert kind not in single
            single[kind] = row
            publication[kind] = count
        count += 1
    assert set(single) == {"BEGIN", "POSITIVE", "DONE"} and publication["BEGIN"] == 0
    begin, positive, done = (single[key] for key in ("BEGIN", "POSITIVE", "DONE"))
    start, whole = number(begin, "start_ms"), number(begin, "until_ms")
    assert whole == start + 30000 and number(begin, "refusal_until_ms") == start + 12000
    assert (begin["guest"], begin["router"], begin["peer"]) == ("192.0.2.100", "192.0.2.1", "198.51.100.2")
    assert positive["child"] == "2" and positive["fresh_grant"] == positive["old_child_retired"] == "1"
    assert number(positive, "until_ms") == number(positive, "at_ms") + 10000 <= whole
    assert done["children"] == "2" and (done["sockets"], done["negative_bytes"], done["positive_bytes"]) == ("0", "1024", "64")
    assert number(done, "at_ms") < whole and publication["DONE"] == count - 1
    common = {"GRANT", "SPAWN", "BOOTSTRAP", "REAP", "RETIRED", "CHILD_BEGIN", "CHILD_CONNECTED", "CHILD_QUEUED", "CHILD_DONE"}
    expected = {(kind, child) for kind in common for child in (1, 2)} | {("CHILD_REFUSED", 1), ("CHILD_FENCED", 1), ("CHILD_OBSERVED", 2), ("CHILD_EOF", 2)}
    assert set(scoped) == expected and set(pipes) == set(seals) == {(o, c) for o in ("owner", "child") for c in (1, 2)}
    assert set(censuses) == {phase + suffix for phase in ("refusal", "positive") for suffix in ("-before", "-after")}
    transactions, streams = {}, {}
    for child in (1, 2):
        phase = "refusal" if child == 1 else "positive"
        get = lambda kind: scoped[kind, child]
        grant, spawn, boot, reap, retired = (get(key) for key in ("GRANT", "SPAWN", "BOOTSTRAP", "REAP", "RETIRED"))
        until = number(begin, "refusal_until_ms") if child == 1 else number(positive, "until_ms")
        assert number(grant, "until_ms") == until and start <= number(grant, "at_ms") < until
        assert number(grant, "lifetime_ms") == until - number(grant, "at_ms")
        assert (grant["local_port"], grant["peer_port"]) == (("7100", "42100") if child == 1 else ("7101", "42101"))
        assert number(spawn, "process_handle") > 0 and (spawn["no_spawn"], spawn["nic_copies"], spawn["protocol_handles"], spawn["diagnostic_handles"]) == ("1", "0", "2", "2")
        assert publication["GRANT", child] < publication["SPAWN", child] < publication["BOOTSTRAP", child] < publication["REAP", child] < publication["RETIRED", child]
        assert (reap["kind"], reap["status"], reap["channel_live"], reap["eof_revoked"]) == ("1", "0", "0", "1")
        assert all(retired[key] == "0" for key in ("channel_live_before_explicit", "channel_live", "process_handle_live", "protocol_handles", "result_handles", "sockets")) and retired["objects_restored"] == "1"
        assert number(grant, "at_ms") <= number(spawn, "at_ms") <= number(boot, "at_ms") <= number(reap, "at_ms") <= number(retired, "explicit_revoke_ms") < until
        assert number(grant, "at_ms") <= number(reap, "reaped_ms") <= number(reap, "at_ms") and number(grant, "at_ms") <= number(reap, "result_eof_ms") <= number(reap, "at_ms")
        first, last = censuses[phase + "-before"], censuses[phase + "-after"]
        phase_begin = publication["BEGIN"] if child == 1 else publication["POSITIVE"]
        assert phase_begin < publication["CENSUS", phase + "-before"] < publication["GRANT", child], "phase census before actual grant"
        assert publication["REAP", child] < publication["FRAME_SEAL", phase] < publication["CENSUS", phase + "-after"] < publication["RETIRED", child], "phase census after reap and frame seal before retirement marker"
        assert all(number(first, key) == number(last, key) for key in ("processes", "handles", "pipes", "cells")), "actual object restoration"
        for key in ("processes", "handles", "pipes", "cells", "frames"):
            number(first, key); number(last, key)
        owner = pipe_stream(pipes["owner", child], seals["owner", child], "owner", child, number(grant, "at_ms"), until)
        consumer = pipe_stream(pipes["child", child], seals["child", child], "child", child, number(grant, "at_ms"), until)
        assert owner == consumer, "independent owner/child actual byte streams"
        assert number(reap, "request_eof_ms") == number(seals["owner", child], "request_eof") <= number(reap, "at_ms")
        expected_boot = b"MTUD\x01" + bytes([child]) + prior.PEER_IP + int(grant["peer_port"]).to_bytes(2, "big") + until.to_bytes(8, "big")
        assert binary(boot, "hex", number(boot, "bytes")) == expected_boot and owner["reply"][:20] == expected_boot
        child_begin = get("CHILD_BEGIN")
        assert child_begin["nic"] == get("CHILD_DONE")["nic"] == "0" and number(child_begin, "until_ms") == until
        assert binary(child_begin, "bootstrap_hex", number(child_begin, "bootstrap_bytes")) == expected_boot
        requests, replies = framed(owner["request"]), framed(owner["reply"][20:])
        assert requests and len(requests) == len(replies), "one reply per actual request"
        parsed = []
        for (request, end_request), (reply, end_reply) in zip(requests, replies):
            item = prior.rpc({"phase": phase, "request_bytes": str(len(request)), "request_hex": request.hex(), "reply_bytes": str(len(reply)), "reply_hex": reply.hex()})
            item.update(end_request=end_request, end_reply=end_reply + 20)
            parsed.append(item)
        assert sum(t["op"] == 16 for t in parsed) == 1 and any(t["op"] in (16, 17) and not t["code"] and t["reply"][12] & 1 for t in parsed)
        body = peer.NEGATIVE if child == 1 else peer.POSITIVE
        writes = [t for t in parsed if t["op"] == 18]
        assert len(writes) == 1 and writes[0]["code"] == 0 and writes[0]["request"][12:] == body and writes[0]["count"] == len(body)
        assert number(get("CHILD_QUEUED"), "bytes") == len(body)
        kinds = ["CHILD_BEGIN", "CHILD_CONNECTED", "CHILD_QUEUED"] + (["CHILD_REFUSED", "CHILD_FENCED"] if child == 1 else ["CHILD_OBSERVED", "CHILD_EOF"]) + ["CHILD_DONE"]
        times = [number(get(kind), "at_ms") for kind in kinds]
        assert start <= times[0] and times == sorted(times) and times[-1] < until, "child original clock bounds"
        assert times[-1] <= min(number(reap, "reaped_ms"), number(reap, "result_eof_ms")), "child DONE before normal reap and true result EOF"
        if child == 1:
            refused, fenced = get("CHILD_REFUSED"), get("CHILD_FENCED")
            assert (refused["code"], refused["mtu"], refused["effects"], fenced["read_code"], fenced["write_code"]) == ("17", "576", "unknown", "8", "8")
            assert parsed[-1]["op"] == 19 and parsed[-1]["code"] == 17 and sum(t["code"] == 17 for t in parsed) == 1
            assert all(t["op"] in (16, 17, 18, 19) for t in parsed)
            seal = seals["child", child]
            for label, field in (("request", "request_bytes"), ("reply", "reply_bytes"), ("reads", "read_calls"), ("writes", "write_calls")):
                assert number(fenced, label + "_before") == number(fenced, label + "_after") == number(seal, field), "two stale calls with no later pipe I/O"
        else:
            assert all(t["op"] in (16, 17, 18, 19, 20) and t["code"] != 17 for t in parsed)
            assert sum(t["op"] == 20 and t["code"] == 0 for t in parsed) == 1
            assert b"".join(t["reply"][12:] for t in parsed if t["op"] == 19 and t["code"] == 0) == peer.POSITIVE
            assert parsed[-1]["op"] == 19 and parsed[-1]["code"] == 6
            assert get("CHILD_EOF")["code"] == "6" and binary(get("CHILD_OBSERVED"), "hex", number(get("CHILD_OBSERVED"), "bytes")) == peer.POSITIVE
        transactions[child], streams[child] = parsed, owner
    assert publication["RETIRED", 1] < publication["POSITIVE"] < publication["GRANT", 2] and publication["RETIRED", 2] < publication["DONE"]
    assert number(scoped["RETIRED", 1], "explicit_revoke_ms") <= number(positive, "at_ms") <= number(scoped["GRANT", 2], "at_ms")
    assert number(scoped["RETIRED", 2], "explicit_revoke_ms") <= number(done, "at_ms")
    counts, previous = {"tx": 0, "rx": 0}, start
    for row in frames:
        direction = row["direction"]
        assert direction in counts and row["phase"] in ("refusal", "positive")
        counts[direction] += 1
        assert number(row, "ordinal") == counts[direction] <= 256
        at = number(row, "at_ms")
        assert at >= number(scoped["GRANT", 1 if row["phase"] == "refusal" else 2], "at_ms"), "native frame after explicit grant construction"
        assert previous <= at < (number(begin, "refusal_until_ms") if row["phase"] == "refusal" else number(positive, "until_ms"))
        previous = at
        assert 14 <= number(row, "bytes") <= 1514
        binary(row, "hex", number(row, "bytes"))
    assert set(frame_seals) == {"refusal", "positive"}
    assert frame_seals["positive"][1] == len(frames) and all(row["phase"] == "positive" for row in frames[frame_seals["refusal"][1]:])
    for phase, (seal, end) in frame_seals.items():
        assert number(seal, "records") == end and all(number(seal, key) == sum(r["direction"] == key for r in frames[:end]) for key in counts)
        assert all(r["phase"] == "refusal" for r in frames[:frame_seals["refusal"][1]])
    return {"single": single, "scoped": scoped, "pipes": pipes, "seals": seals, "frames": frames, "census": counts, "transactions": transactions, "streams": streams, "records": count, "censuses": censuses}


def native_output(raw, exit_status):
    assert exit_status == 3, "natural QEMU exit"
    for marker in (b"\nNETWORK LINK OK ", b"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ", b"\nDURABLE WORKLOAD OK\n", b"\nABSD BOOT OK\n"):
        assert marker in raw
    assert not any(v in raw for v in (b"PANIC", b"KERNEL FAULT", b"init: FAILED", b"NIC DISABLED"))
    children = re.findall(rb"(?m)^SPAWN OK pid=(\d+) parent=2 program=", raw)
    assert len(children) == len(set(children)) == 2, "two actual distinct child processes"
    for pid in [b"2"] + children:
        assert re.findall(rb"(?m)^USER EXIT pid=" + pid + rb" status=(.*)\n", raw) == [b"0"]
    for pid in children:
        assert not re.search(rb"(?m)^SPAWN OK pid=\d+ parent=" + pid + rb" ", raw), "pipe-only child cannot spawn descendants"
    assert re.findall(rb"(?m)^DURABLE WORKER OUTCOME generation=1 pid=2 status=(.*)\n", raw) == [b"0"]
    assert re.findall(rb"(?m)^DURABLE WORKER GENERATION (.*)\n", raw) == [b"generation=1 pid=2"]
    assert raw.count(b"EXTERNAL OUTPUT BEGIN encoding=hex\n") == 1
    output = bytearray()
    chunks = list(base.CHUNK.finditer(raw))
    assert len(chunks) == raw.count(b"EXTERNAL OUTPUT CHUNK")
    for chunk in chunks:
        assert int(chunk[1], 16) == len(output)
        output.extend(bytes.fromhex(chunk[2].decode()))
        assert len(output) <= 4 * 1024 * 1024
    digest = 0x811c9dc5
    for value in output:
        digest = ((digest ^ value) * 0x1000193) & 0xffffffff
    assert re.findall(rb"(?m)^EXTERNAL OUTPUT END bytes=(\d+) digest=([0-9a-f]{8})\n", raw) == [(str(len(output)).encode(), f"{digest:08x}".encode())] and raw.count(b"EXTERNAL OUTPUT END ") == 1
    native = native_records(bytes(output))
    stats = re.findall(rb"(?m)^NIC STATS (.*)\n", raw)
    assert len(stats) == 1
    counters = dict(word.split("=") for word in stats[0].decode().split())
    assert set(counters) == {"rx_frames", "rx_refused", "rx_missed", "tx_frames", "tx_refused", "tx_errors", "flags"}
    assert all(counters[k] == "0" for k in ("rx_refused", "rx_missed", "tx_refused", "tx_errors")) and counters["flags"] == "1"
    assert number(counters, "tx_frames") == native["census"]["tx"] and number(counters, "rx_frames") == native["census"]["rx"]
    native.update(output=output.decode(), FNV32=f"{digest:08x}", child_pids=[int(v) for v in children], NIC_counters=counters)
    return native


ipv4, tcp, mss, icmp_quote = prior.ipv4, prior.tcp, prior.mss, prior.icmp_quote
frame_equal = prior.frame_equal
GUEST_IP, ROUTER_IP, PEER_IP = prior.GUEST_IP, prior.ROUTER_IP, prior.PEER_IP


def json_value(value):
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {":".join(map(str, key)) if isinstance(key, tuple) else key: json_value(part) for key, part in value.items()}
    if isinstance(value, (tuple, list)):
        return [json_value(part) for part in value]
    return value


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
                broadcast = frame[:6] == b"\xff" * 6 and frame[32:38] in (bytes(6), b"\xff" * 6)
                router_probe = direction == "rx" and frame[:6] == GUEST_MAC and frame[32:38] == bytes(6)
                assert broadcast or router_probe, "exact broadcast or router unicast ARP request"
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
    consumed = [(i, row) for i, row in enumerate(native["frames"]) if row["direction"] == "rx" and any(bytes.fromhex(row["hex"]) == value for _, value in errors)]
    assert consumed, "matched error actually consumed by native Link"
    boundary, received = consumed[0]
    assert received["phase"] == "refusal"
    transaction = native["transactions"][1][-1]
    child_reads = [row for row in native["pipes"]["child", 1] if row["direction"] == "reply" and number(row, "offset") + number(row, "bytes") == transaction["end_reply"]]
    assert len(child_reads) == 1
    assert number(received, "at_ms") <= number(child_reads[0], "at_ms") <= number(native["scoped"]["CHILD_REFUSED", 1], "at_ms"), "consumed error and actual received typed reply observations"
    revoked = number(native["scoped"]["RETIRED", 1], "explicit_revoke_ms")
    for index, row in enumerate(native["frames"]):
        value = bytes.fromhex(row["hex"])
        if row["direction"] != "tx" or index <= boundary or value[12:14] != b"\x08\x00":
            continue
        ip = ipv4(value)
        if ip[9] != 6:
            continue
        segment = tcp(ip)
        if (segment["source"], segment["destination"]) == (7100, 42100):
            assert number(row, "at_ms") > revoked, "old tuple TX after consumed error before owner retirement"
            assert not segment["body"] and segment["flags"] in (4, 20), "post-revoke old tuple only generic RST"
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
    checked = prior.inspect_peer(report, expected_pid, namespace_inode)
    reads, sent, accepted = bytearray(), 0, set()
    for row in report["events"]:
        if row["event"] == "accept":
            accepted.add(row["port"])
        elif row["port"] == 42101 and row["event"] == "read":
            reads.extend(bytes.fromhex(row["hex"]))
        elif row["event"] == "write":
            data = bytes.fromhex(row["hex"])
            assert row["port"] in accepted and sent + len(data) <= len(reads) and data == reads[sent:sent + len(data)], "peer echo accepted/read prefix"
            sent += len(data)
    return checked


def embedding(buffers):
    assert set(buffers) == {"owner", "child", "kernel"}
    assert all(len(data) >= 64 and data.startswith(b"\x7fELF") for data in buffers.values())
    assert buffers["kernel"].count(buffers["owner"]) == 1, "exact unique owner ELF embedded in kernel"
    assert buffers["owner"].count(buffers["child"]) == 1, "exact child ELF embedded once in owner"


def capture_census(log, packet_count):
    counts = {}
    for key, label in (("captured", b"packets captured"), ("received", b"packets received by filter"), ("dropped", b"packets dropped by kernel")):
        values = re.findall(rb"(?m)^(\d+) " + label + rb"\r?$", log)
        assert len(values) == 1 and values[0] == str(int(values[0])).encode(), "one canonical numeric tcpdump terminal record"
        counts[key] = int(values[0])
    assert counts["captured"] == counts["received"] == packet_count and counts["dropped"] == 0, "tcpdump captured received and full PCAP census"
    return counts


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
        buffers = {name: base.read_bound(path, MAX_ELF) for name, path in (("owner", args.elf), ("child", args.client_elf), ("kernel", args.kernel_elf))}
        embedding(buffers)
        paths = {"owner": args.elf, "child": args.client_elf, "kernel": args.kernel_elf}
        inputs = {name: base.identity(paths[name], data) for name, data in buffers.items()}
        tree = work / "iso-tree/boot/grub"
        tree.mkdir(parents=True)
        (tree.parent / "absd-kernel").write_bytes(buffers["kernel"])
        grub = b'insmod all_video\nset timeout=0\nmenuentry "ABSD TCP MTU" {\n multiboot2 /boot/absd-kernel durable=1 net nvme-write=absd\n boot\n}\n'
        (tree / "grub.cfg").write_bytes(grub)
        iso, disk = work / "native-tcp-mtu-delegated.iso", work / "native-tcp-mtu-delegated.img"
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
        topology = {"schema": "absd-native-tcp-mtu-delegated-topology/1", "host_kernel": list(os.uname()), "offloads": offloads}
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
        serial = work / "native-tcp-mtu-delegated.serial.log"
        ingress_capture, egress_capture = work / "native-tcp-mtu-delegated.pcap", work / "router-egress.pcap"
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
        peer.atomic(work / "LAUNCH.json", {"schema": "absd-native-tcp-mtu-delegated-launch/1", "inputs": inputs,
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
        peer.atomic(work / "PEER-STOP", {"reason": "natural QEMU end and captures closed"})
        actor.wait(timeout=left(3))
        assert actor.returncode == 0, "TCP peer terminal status"
        raw = base.read_bound(serial, MAX_LOG)
        observed = native_output(raw, emulator.returncode)
        capture_bytes, captured = base.packet_records(ingress_capture)
        egress_bytes, egress_rows = base.packet_records(egress_capture)
        dump_counts = capture_census(dump_log, len(egress_rows))
        frames = inspect_frames(captured, observed, egress_rows)
        report = json.loads(base.read_bound(peer_result, 65536))
        checked_peer = inspect_peer(report, actor.pid, topology["peer"]["inode"])
        return json_value({"schema": "absd-native-tcp-mtu-delegated-proof/1", "disposition": "PASS", "limits": LIMITS,
            "native": observed, "wire": frames, "peer": checked_peer, "inputs": inputs,
            "egress_capture_census": dump_counts,
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
        peer.atomic(work / "LOCAL-CLEANUP.json", {"schema": "absd-native-tcp-mtu-delegated-cleanup/1",
            "created_namespace_identities": created, "namespaces_absent": absent,
            "process_exit_status": terminal, "owned_session_process_groups_terminal": group_terminal,
            "errors": errors, "disposition": "FAIL" if errors else "PASS",
            "custody": "Root source/result/replay dependency until integration or review2026-10-19T00:00:00Z; exact temporary namespaces/processes retired here; no provider/key creation."})
        if errors:
            raise RuntimeError(errors)



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path, help="fresh output directory")
    parser.add_argument("--elf", type=Path, required=True, help="native delegated TCP MTU owner ELF")
    parser.add_argument("--client-elf", type=Path, required=True)
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
        peer.atomic(work / "RESULT.json", {"schema": "absd-native-tcp-mtu-delegated-proof/1", "disposition": "FAIL", "error": repr(error), "limits": LIMITS})
        raise
    peer.atomic(work / "RESULT.json", result)


if __name__ == "__main__":
    main()
