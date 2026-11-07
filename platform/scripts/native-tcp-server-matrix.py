#!/usr/bin/env python3
"""One foreground IPv4 TCP server proof in an admitted disposable Linux VM.

Prebuilt exact inputs only. No compilation, provider or host network changes.
The fresh namespace owns both Linux clients and its TAP/QEMU process groups.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import signal
import socket
import struct
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from served_ram import served_qemu

if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
    raise SystemExit("native-tcp-server-matrix: optimized Python is refused")

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("server_boot", ROOT / "scripts/net-matrix.py")
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)
PROFILE = "tcp-server-native-boundary-v1"
LAST_REFUSAL_PROFILE = "tcp-server-last-refusal-v1"
LAST_REFUSAL_PRODUCT = ("5775b70f6167e407bcc6253ef4de9d56b9cdb7cc",
                        "c1d860be75d7db32c0835c1d07107b8376bffb62",
                        "fc55e9b71f2c77d6c6a46d30d6d7d1e3570148aa4689256ffb51fa1412c8cd1f", 27392000)
PRODUCT = "137f6ac6b55fe92cee94816ce609658e96d1ec05"
PRODUCT_TREE = "18aa6d16d7d8293f360cd67ab5b5a2607bd6358d"
PRODUCT_ARCHIVE = "b4ab4a3ee760ee98411c034bb5f6fa06ed13692382228123b389e75268a0ab68"
PRODUCT_BYTES = 26388480
KERNEL = "2775bbaf6c1b8ebbaec66579b39d1fd78d71e57b"
KERNEL_TREE = "8763f164ddfed11aa2f55626bd8e85123c595a08"
KERNEL_ARCHIVE = "fbfff7902d7bf6334b0c2d141558ef8cbdb23d56ce3db0c81dd32ebfb81be224"
KERNEL_BYTES = 12574720
SERVED_WRAPPER = "e3822e288d37e49a4efff2e30e35178d4c895c944ce43b4b690179565c6d51d2"
HOST, GUEST = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 100])
HOST_MAC, GUEST_MAC = bytes.fromhex("525500000501"), bytes.fromhex("525400123456")
READY = b"TCP SERVER LISTEN READY sockets=1\n"
DATA = bytes((i * 131 ^ (i >> 7)) & 255 for i in range(3072))
MAX_CAPTURE, MAX_LOG, MAX_ELF, MAX_ISO = 2 << 20, 8 << 20, 64 << 20, 128 << 20
WRONG_TIMEOUT_NS, MIN_NEGATIVE_NS = 1_250_000_000, 1_000_000_000
UNRUN = ["native malformed outer-prefix lengths/wire", "native connected-data/pending-reply interruption",
         "native clock/link faults or exhausted queues/rings/load",
         "native stale READ/WRITE or cross-stack handles", "isolated complete oversized WRITE body",
         "retransmission under deliberate loss", "live SSH coexistence", "general listener/backlog",
         "routed paths/PMTU", "hardware and physical elapsed-time accuracy"]


def digest(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def read_bound(path, limit):
    with Path(path).open("rb") as source:
        data = source.read(limit + 1)
    assert len(data) <= limit, f"input bound: {path}"
    return data


def write(path, value):
    with Path(path).open("x") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def checked(argv, timeout=5):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=timeout)


def producer_file_limit():
    # This strict profile needs far less; cap each producer-owned regular file
    # at the capture bound as well as checking final/polled logical bounds.
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_CAPTURE, MAX_CAPTURE))


def iso_file_limit():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_ISO, MAX_ISO))


def build_binding(receipt, child, parent, kernel, profile=PROFILE):
    assert profile in (PROFILE, LAST_REFUSAL_PROFILE)
    assert receipt["schema"] == "absd-native-tcp-server-build/4" and receipt["profile"] == profile
    platform = LAST_REFUSAL_PRODUCT if profile == LAST_REFUSAL_PROFILE else (PRODUCT, PRODUCT_TREE, PRODUCT_ARCHIVE, PRODUCT_BYTES)
    for name, revision, tree, archive, size in (("platform", *platform),
                                                ("kernel", KERNEL, KERNEL_TREE, KERNEL_ARCHIVE, KERNEL_BYTES)):
        source = receipt[name]
        assert source["revision"] == revision and source["tree"] == tree and source["clean"] is True
        assert source["archive"]["sha256"] == archive and source["archive"]["bytes"] == size
    assert receipt["commands"] and all(isinstance(c, list) and c and all(isinstance(s, str) for s in c)
                                       for c in receipt["commands"])
    assert 1 <= len(receipt["logs"]) <= 8 and all(re.fullmatch(r"[0-9a-f]{64}", log["sha256"])
                                   and log["bytes"] > 0 for log in receipt["logs"])
    toolchain = receipt["toolchain_receipt"]
    assert re.fullmatch(r"[0-9a-f]{64}", toolchain["sha256"]) and toolchain["bytes"] > 0
    assert any(any(s.endswith("scripts/build-native-tcp-server.sh") for s in c) for c in receipt["commands"])
    assert receipt["served_kernel_policy"] == "frame-admission-v0" and receipt["served_wrapper_sha256"] == SERVED_WRAPPER
    assert any(any(s.endswith("scripts/served_kernel.py") for s in c)
               and "external-build" in c and any(s.startswith("EXTERNAL_USER_ELF=") for s in c)
               for c in receipt["commands"]), "current served-wrapper build command required"
    for name, data in (("child", child), ("parent", parent), ("kernel", kernel)):
        assert receipt["outputs"][name] == digest(data), f"build output binding: {name}"
        assert data.startswith(b"\x7fELF"), f"ELF magic: {name}"
    assert parent.count(child) == 1, "exact child not uniquely embedded in parent"
    assert kernel.count(parent) == 1, "exact parent not uniquely embedded in kernel"


def records(data):
    assert 24 <= len(data) <= MAX_CAPTURE, "PCAP bound/header"
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(data[:4])
    assert endian is not None, "PCAP magic"
    major, minor, _, _, snap, link = struct.unpack(endian + "HHIIII", data[4:24])
    assert (major, minor, link) == (2, 4, 1) and snap >= 1514
    rows, at, previous = [], 24, (0, 0)
    while at < len(data):
        assert at + 16 <= len(data), "short PCAP record"
        sec, usec, size, original = struct.unpack(endian + "IIII", data[at:at + 16])
        at += 16
        assert usec < 1_000_000 and (sec, usec) >= previous, "capture timestamp order"
        assert 14 <= size <= 1514 and size == original and at + size <= len(data), "truncated frame"
        rows.append((sec * 1_000_000 + usec, data[at:at + size])); at += size; previous = (sec, usec)
        assert len(rows) <= 256, "frame census bound"
    return rows


def tcp_options(data):
    result, at = {}, 0
    while at < len(data):
        kind = data[at]
        if kind == 0:
            assert not any(data[at:]), "TCP EOL padding"
            break
        if kind == 1:
            at += 1
            continue
        assert at + 2 <= len(data) and data[at + 1] >= 2, "TCP option header"
        size = data[at + 1]
        assert at + size <= len(data) and kind not in result, "TCP option length/duplicate"
        assert kind in (2, 3, 4, 5, 8), "unsupported TCP option"
        assert {2: size == 4, 3: size == 3, 4: size == 2,
                5: size >= 10 and (size - 2) % 8 == 0, 8: size == 10}[kind]
        result[kind] = data[at + 2:at + size]; at += size
    return result


def inspect_capture(data, distinct_attempts=1):
    assert type(distinct_attempts) is int and distinct_attempts in (1, 2)
    flows, census, arps = {"host": [], "guest": []}, [], []
    wrong, first_valid = [], None
    timestamps = []
    wrong_sequences = []
    for index, (timestamp, frame) in enumerate(records(data)):
        timestamps.append(timestamp)
        assert frame[6:12] in (HOST_MAC, GUEST_MAC), "third Ethernet source"
        outgoing = frame[6:12] == GUEST_MAC
        source, target = (GUEST, HOST) if outgoing else (HOST, GUEST)
        srcmac, dstmac = (GUEST_MAC, HOST_MAC) if outgoing else (HOST_MAC, GUEST_MAC)
        row = {"index": index, "timestamp_us": timestamp, **digest(frame)}
        if frame[12:14] == b"\x08\x06":
            assert len(frame) in (42, 60) and not any(frame[42:]), "ARP size/padding"
            assert frame[14:20] == b"\0\x01\x08\0\x06\x04" and frame[22:28] == srcmac
            op = int.from_bytes(frame[20:22], "big")
            assert frame[28:32] == source and frame[38:42] == target, "unrelated ARP IP"
            if op == 1:
                if outgoing:
                    assert frame[:6] == b"\xff" * 6 and frame[32:38] == b"\xff" * 6, "smoltcp ARP request destination"
                else:
                    assert frame[:6] in (b"\xff" * 6, GUEST_MAC) and frame[32:38] == b"\0" * 6, "Linux ARP request destination"
            else:
                assert op == 2 and frame[:6] == dstmac and frame[32:38] == dstmac, "ARP reply tuple"
            row["kind"] = "peer-arp"; arps.append((index, outgoing, op))
        else:
            assert len(frame) >= 54 and frame[:6] == dstmac and frame[12:14] == b"\x08\0", "unexplained frame"
            assert frame[14] == 0x45 and frame[23] == 6 and frame[22] > 0, "unexplained IPv4 header"
            length = int.from_bytes(frame[16:18], "big")
            assert 40 <= length <= 1500 and len(frame) in (14 + length, max(60, 14 + length))
            assert not any(frame[14 + length:]) and boot.checksum(frame[14:34]) == 0
            assert int.from_bytes(frame[20:22], "big") & ~0x4000 == 0, "fragmented/reserved IPv4"
            assert frame[26:30] == source and frame[30:34] == target, "ungranted IP"
            tcp = frame[34:14 + length]
            sport, dport, seq, ack = struct.unpack("!HHII", tcp[:12])
            header, flags = (tcp[12] >> 4) * 4, tcp[13]
            assert 20 <= header <= len(tcp) and tcp[12] & 15 == 0 and not flags & (4 | 32 | 64 | 128), "TCP header/reset/urgent/ECN"
            assert tcp[18:20] == b"\0\0" and boot.checksum(source + target + struct.pack("!BBH", 0, 6, len(tcp)) + tcp) == 0, "TCP checksum"
            options = tcp_options(tcp[20:header]); body = tcp[header:]
            if not outgoing and (sport, dport) == (42031, 7005):
                assert flags == 2 and ack == 0 and not body, "wrong-port flow progressed"
                assert first_valid is None, "wrong-port SYN after authorized flow"
                if seq not in wrong_sequences:
                    wrong_sequences.append(seq)
                assert len(wrong_sequences) <= distinct_attempts, "wrong-port client made extra connection attempts"
                assert seq == wrong_sequences[-1], "earlier wrong-port attempt resumed after later attempt"
                wrong.append(index); row["kind"] = "refused-source-port-syn"
                row["refusal_header"] = {"source": "192.0.2.1:42031", "destination": "192.0.2.100:7005",
                    "expected_peer": "192.0.2.1:42030", "flags": flags, "seq": seq, "frame_bytes": len(frame)}
            else:
                assert (sport, dport) == ((7005, 42030) if outgoing else (42030, 7005)), "ungranted TCP port"
                if first_valid is None:
                    assert not outgoing and flags == 2 and wrong, "authorized SYN must follow refused SYN"
                    first_valid = index
                if flags & 2:
                    assert flags == (18 if outgoing else 2) and not body, "SYN flags/data"
                    assert 2 in options and int.from_bytes(options[2], "big") == 1460, "Ethernet1500 MSS"
                else:
                    assert flags & 16 and flags & ~(1 | 8 | 16) == 0, "non-SYN needs ACK"
                flows["guest" if outgoing else "host"].append({"index": index, "seq": seq, "ack": ack,
                    "flags": flags, "body": body, "options": options})
                row["kind"] = "authorized-tcp"
        census.append(row)
    assert wrong and first_valid is not None and arps, "refusal/flow/ARP absent"
    assert len(wrong_sequences) == distinct_attempts, "missing distinct wrong-port sequence"
    assert any(not direction and op == 1 for _, direction, op in arps)
    assert any(direction and op == 2 for _, direction, op in arps), "guest ARP reply absent"
    # Require a real ARP exchange before the *first* refused SYN. A late reply
    # followed by two nearly simultaneous queued SYNs cannot establish this.
    replies = [i for i, direction, op in arps if direction and op == 2 and i < wrong[0]]
    assert replies, "guest neighbor readiness must precede wrong-port SYN"
    reply = replies[0]
    requests = [i for i, direction, op in arps if not direction and op == 1 and i < reply]
    assert requests, "readiness ARP reply lacks a preceding exact request"
    gap_us = timestamps[first_valid] - timestamps[wrong[0]]
    assert gap_us > MIN_NEGATIVE_NS // 1000, "captured wrong-source interval is not greater than one second"
    base, assembled, seen_end, fin, fin_ack, chunks = {}, {}, {}, {}, {}, {}
    for side in flows:
        syns = [r for r in flows[side] if r["flags"] & 2]
        assert syns and len({r["seq"] for r in syns}) == 1, "multiple connections"
        base[side] = syns[0]["seq"]; assembled[side] = {}; seen_end[side] = 0
        fin[side] = None; fin_ack[side] = None; chunks[side] = 0
    assert flows["host"][0]["index"] < flows["guest"][0]["index"]
    for side, row in sorted(((s, r) for s in flows for r in flows[s]), key=lambda v: v[1]["index"]):
        other = "guest" if side == "host" else "host"
        offset = (row["seq"] - base[side]) & 0xffffffff
        assert offset <= 3074, "TCP sequence outside finite exchange"
        if row["flags"] & 16:
            ack = (row["ack"] - base[other]) & 0xffffffff
            assert 1 <= ack <= seen_end[other], "ACK beyond captured peer data"
            if fin[other] is not None and ack == 3074:
                fin_ack[other] = row["index"]
        else:
            assert side == "host" and row["flags"] == 2 and row["ack"] == 0
        if row["flags"] & 2:
            assert offset == 0
            seen_end[side] = max(seen_end[side], 1)
            continue
        body = row["body"]
        assert 1 <= offset <= 3074
        if offset == 3074:
            assert not body and row["flags"] == 16 and fin[side] is not None, "data beyond FIN"
        else:
            assert offset - 1 + len(body) <= 3072
        assert offset <= seen_end[side], "uncaptured TCP sequence gap"
        if body:
            assert fin[side] is None or offset - 1 + len(body) <= 3072
            chunks[side] += 1
            for at, byte in enumerate(body, offset - 1):
                assert byte == DATA[at] and assembled[side].get(at, byte) == byte, "application bytes differ"
                assembled[side][at] = byte
        end = offset + len(body)
        if row["flags"] & 1:
            assert end == 3073 and len(assembled[side]) == 3072, "FIN before complete data"
            if fin[side] is None:
                fin[side] = row["index"]
            end += 1
        seen_end[side] = max(seen_end[side], end)
    assert all(len(assembled[s]) == 3072 and chunks[s] >= 2 for s in flows), "partial stream echo absent"
    assert all(fin[s] is not None and fin_ack[s] is not None and fin_ack[s] > fin[s] for s in flows), "FIN not acknowledged"
    assert fin["host"] < fin["guest"], "peer half-close must precede server FIN"
    result = {"frames": len(census), "wrong_port_syns": wrong, "first_authorized_syn": first_valid,
            "readiness_arp": {"request": census[requests[0]], "reply": census[reply]},
            "negative_interval_us": gap_us, "last_wrong_syn_to_authorized_us": timestamps[first_valid] - timestamps[wrong[-1]],
            "application_bytes_each": 3072, "segments": chunks, "fin": fin, "fin_ack": fin_ack, "census": census}
    if distinct_attempts == 2:
        result["wrong_port_attempts"] = [{"sequence": seq, "indices": [i for i in wrong if census[i]["refusal_header"]["seq"] == seq]}
                                         for seq in wrong_sequences]
    return result


def native_output(raw, status):
    assert status == 3, f"QEMU exit {status}"
    for needed in (b"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ",
                   b"\nDURABLE WORKLOAD OK\n", b"\nABSD BOOT OK\n", b"\nNETWORK LINK OK "):
        assert needed in raw, f"serial lacks {needed!r}"
    for bad in (b"PANIC", b"KERNEL FAULT", b"init: FAILED", b"NIC DISABLED", b"TCP SERVER ERROR", b"TCP SERVER ECHO ERROR"):
        assert bad not in raw, f"serial contains {bad!r}"
    output, offset = bytearray(), 0
    for match in boot.CHUNK.finditer(raw):
        assert int(match[1], 16) == offset, "worker output offset discontinuity"
        block = bytes.fromhex(match[2].decode()); output.extend(block); offset += len(block)
    markers = (b"TCP SERVER GRANT READY local=192.0.2.100:7005 peer=192.0.2.1:42030 lifetime_ms=10000\n",
               READY, b"TCP SERVER ECHO PASS bytes=3072 denied=1 nic=0\n", b"TCP SERVER DONE child=exited sockets=0\n")
    for marker in markers:
        assert output.count(marker) == 1, f"worker lacks exact single marker {marker!r}"
    assert [output.index(m) for m in markers] == sorted(output.index(m) for m in markers), "native marker order"
    assert b"TCP SERVER ERROR" not in output and b"TCP SERVER ECHO ERROR" not in output
    lines = re.findall(rb"NIC STATS ([^\n]*)\n", raw)
    assert len(lines) == 1, "exactly one terminal NIC counter line required"
    fields = dict(field.split("=", 1) for field in lines[0].decode().split())
    assert len(re.findall(rb"DURABLE status=[^\n]*\n", raw)) == 1, "unique terminal accounting required"
    assert int(fields["rx_frames"]) > 0 and int(fields["tx_frames"]) > 0
    assert all(int(fields[k]) == 0 for k in ("rx_refused", "rx_missed", "tx_refused", "tx_errors")), fields
    return {"stdout": output.decode(), "NIC_counters": fields}


def refusal_observation(native, capture):
    """Bind one Stack's bounded observation to this profile's full census.

    This is count/tuple/header correspondence, not a full-frame identity or
    a comparison of guest and host clocks. Existing wire/native checks remain.
    """
    output = native["stdout"]
    baseline = "TCP SERVER PEER REFUSAL BASELINE v=1 count=0 last=none"
    lines = [line for line in output.splitlines() if line.startswith("TCP SERVER PEER REFUSAL")]
    assert len(lines) == 2 and lines[0] == baseline, "exact zero baseline and final refusal observations required"
    match = re.fullmatch(r"TCP SERVER PEER REFUSAL FINAL v=1 count=([1-9][0-9]*) "
        r"source=(192\.0\.2\.1:42031) destination=(192\.0\.2\.100:7005) expected_peer=(192\.0\.2\.1:42030) "
        r"flags=([0-9]+) seq=([0-9]+) frame_bytes=([0-9]+)", lines[1])
    assert match is not None, "exact versioned final peer-refusal tuple/header required"
    count = int(match[1])
    observed = dict(zip(("source", "destination", "expected_peer"), match.group(2, 3, 4)))
    observed.update({key: int(value) for key, value in zip(("flags", "seq", "frame_bytes"), match.group(5, 6, 7))})
    assert 0 < count < 2**64 - 1 and 0 <= observed["seq"] < 2**32, "finite nonsaturated observation required"
    wrong = [capture["census"][i] for i in capture["wrong_port_syns"]]
    assert count == len(wrong), "guest refusal count differs from full captured wrong-SYN census"
    assert observed == wrong[-1]["refusal_header"], "last guest refusal header differs from last captured wrong SYN"
    assert output.index(baseline) < output.index("TCP SERVER GRANT READY "), "baseline after grant"
    assert output.index("TCP SERVER ECHO PASS ") < output.index(lines[1]) < output.index("TCP SERVER DONE "), "final observation outside reap/fence marker order"
    return {"schema": "absd-native-tcp-server-peer-refusal/1", "baseline": 0, "count": count,
            "last": observed, "captured_indices": capture["wrong_port_syns"],
            "scope": "Checksum-validated guest filter subset; bounded count/last header under complete capture. No full-frame identity, cryptographic identity or continuous polling proof."}


def boundary_observation(native):
    """Closed native fixture records, not a configurable protocol/test engine."""
    output = native["stdout"]
    lines = [line for line in output.splitlines() if line.startswith("TCP SERVER NEG ")]
    cursor = 0

    def take(tag, keys):
        nonlocal cursor
        prefix = "TCP SERVER NEG " + tag + " v=1 "
        assert cursor < len(lines) and lines[cursor].startswith(prefix), "missing/reordered native boundary record: " + tag
        pairs = lines[cursor][len(prefix):].split(); cursor += 1
        assert all(item.count("=") == 1 for item in pairs), "boundary field shape"
        fields = dict(item.split("=", 1) for item in pairs)
        assert len(fields) == len(pairs) and set(fields) == set(keys.split()), "boundary field set: " + tag
        return fields

    def numbers(fields):
        assert all(re.fullmatch(r"[0-9]+", value) for value in fields.values()), "boundary unsigned integer"
        parsed = {key: int(value) for key, value in fields.items()}
        assert all(value < 2**64 for value in parsed.values()), "boundary integer range"
        return parsed

    begin = numbers(take("BEGIN", "whole_start_ms whole_until_ms"))
    assert begin["whole_until_ms"] == begin["whole_start_ms"] + 20000, "whole fixture bound changed"
    for case in ("local-port", "peer-port", "offlink", "self", "broadcast", "accept-low", "accept-high", "lifetime-short", "lifetime-high"):
        row = take("GRANT", "case code sockets tx")
        assert row == {"case": case, "code": "1", "sockets": "0", "tx": "0"}, "invalid grant had effect/wrong refusal"
    assert take("SLOTS", "reserved duplicate ninth sockets tx") == {"reserved": "8", "duplicate": "3", "ninth": "4", "sockets": "0", "tx": "0"}
    assert take("SLOTS RETIRED", "stale fresh sockets tx") == {"stale": "8", "fresh": "8", "sockets": "0", "tx": "0"}
    before = take("CENSUS", "label processes handles pipes cells frames")
    assert before.pop("label") == "before"
    before = numbers(before)
    assert before["processes"] > 0 and before["handles"] > 0, "impossible active parent census"
    literal = (
        ("version", "01200004c0000201a42e0000", 1),
        ("family", "03200006c0000201a42e0000", 1),
        ("reserved", "03200104c0000201a42e0000", 1),
        ("listen-length", "03200004c0000201a42e0001", 1),
        ("connect", "03100004c0000201a42e0000", 1),
        ("write-declared-without-body", "03120004c0000201a42e0401", 1),
        ("peer", "03200004c0000201a42f0000", 2))
    requests, replies = bytearray(), bytearray()
    for case, request_hex, status in literal:
        request = bytes.fromhex(request_hex)
        reply = bytes([3, request[1], status, 4]) + HOST + (42030).to_bytes(2, "big") + b"\0\0"
        row = take("API", "case request reply sockets tx")
        framed_request, framed_reply = b"\0\x0c" + request, b"\0\x0c" + reply
        assert row == {"case": case, "request": framed_request.hex(), "reply": framed_reply.hex(), "sockets": "0", "tx": "0"}, "native literal API refusal differs"
        requests.extend(framed_request); replies.extend(framed_reply)
    listen = bytes.fromhex("03200004c0000201a42e0000")
    listen_request = b"\0\x0c" + listen
    listen_reply = b"\0\x0d" + listen[:11] + b"\x01\x00"
    assert take("LISTEN", "request reply sockets tx") == {"request": listen_request.hex(), "reply": listen_reply.hex(), "sockets": "1", "tx": "0"}, "actual full LISTEN required before partial prefix"
    requests.extend(listen_request); requests.append(0); replies.extend(listen_reply)
    event = take("INTERRUPT", "child_handle constructed_ms grant_until_ms partial_poll_ms observed_ms prefix prefix_bytes kill_ms kill_return reaped_ms wait_kind wait_status eof_ms retired_ms channel_live sockets tx fallback_fence")
    assert event.pop("prefix") == "00", "partial input byte differs"
    event = numbers(event)
    assert event["child_handle"] > 0 and event["prefix_bytes"] == 1
    assert all(event[key] == 0 for key in ("kill_return", "wait_status", "channel_live", "sockets", "tx", "fallback_fence")), "kill/EOF/zero-effect/fallback record differs"
    assert event["wait_kind"] == 3, "native child not actually killed"
    assert event["grant_until_ms"] == event["constructed_ms"] + 10000
    times = [begin["whole_start_ms"], event["constructed_ms"], event["partial_poll_ms"], event["observed_ms"], event["kill_ms"], event["reaped_ms"], event["eof_ms"], event["retired_ms"]]
    assert times == sorted(times), "native partial/kill/reap/true-EOF order"
    assert event["retired_ms"] < event["partial_poll_ms"] + 250, "frame expiry could substitute for EOF"
    assert event["retired_ms"] < event["grant_until_ms"] <= begin["whole_until_ms"], "original negative authority exceeded"
    assert take("CHILD", "cases listen nic") == {"cases": "7", "listen": "1", "nic": "0"}
    assert take("CLOSED", "process_reaped protocol_handles result_handles result_eof") == {"process_reaped": "1", "protocol_handles": "2", "result_handles": "1", "result_eof": "1"}
    after = take("CENSUS", "label processes handles pipes cells frames")
    assert after.pop("label") == "after"
    after = numbers(after)
    assert all(before[key] == after[key] for key in ("processes", "handles", "pipes", "cells")), "native object census not restored"
    assert take("COMPLETE", "grants api slots interrupted objects_restored sockets tx") == {"grants": "9", "api": "7", "slots": "8", "interrupted": "1", "objects_restored": "1", "sockets": "0", "tx": "0"}
    assert cursor == len(lines), "extra native boundary records"
    positive = re.findall(r"^TCP SERVER POSITIVE CLOCK v=1 (.*)$", output, re.M)
    assert len(positive) == 1
    fields = positive[0].split(); clock = dict(item.split("=", 1) for item in fields)
    assert len(fields) == len(clock) and set(clock) == {"owner_start_ms", "owner_until_ms", "accept_ms", "grant_ms", "child_ms", "whole_until_ms"}
    clock = numbers(clock)
    assert clock["owner_start_ms"] >= event["retired_ms"] and clock["owner_until_ms"] == clock["owner_start_ms"] + 10000
    assert (clock["accept_ms"], clock["grant_ms"], clock["child_ms"]) == (5000, 10000, 8000)
    assert clock["owner_until_ms"] <= clock["whole_until_ms"] == begin["whole_until_ms"]
    assert output.index(lines[-1]) < output.index("TCP SERVER PEER REFUSAL BASELINE ") < output.index("TCP SERVER POSITIVE CLOCK ") < output.index("TCP SERVER GRANT READY "), "positive grant/clock not fresh after negative retirement"
    return {"schema": "absd-native-tcp-server-boundary/1", "input_bytes": len(requests), "output_bytes": len(replies),
            "input": digest(requests), "output": digest(replies), "interruption": event,
            "census_before": before, "census_after": after, "frame_delta_observed": after["frames"] - before["frames"],
            "positive_clock": clock, "scope": "Native typed API/slot refusal and LISTEN partial-prefix kill/EOF retirement only; frame equality and connected-data interruption unclaimed."}


def peer_results(wrong, peer, readiness, capture, distinct_attempts=1):
    assert type(distinct_attempts) is int and distinct_attempts in (1, 2)
    if distinct_attempts == 2:
        assert set(wrong) == {"schema", "disposition", "connect_attempts", "attempts"}
        assert wrong["schema"] == "absd-native-tcp-last-refusal-client/1" and wrong["disposition"] == "PASS"
        assert type(wrong["connect_attempts"]) is int and wrong["connect_attempts"] == 2
        assert type(wrong["attempts"]) is list and len(wrong["attempts"]) == 2
        first, second = wrong["attempts"]
        for attempt in wrong["attempts"]:
            peer_results(attempt, peer, readiness, capture)
        assert first["ended_monotonic_ns"] <= second["started_monotonic_ns"], "wrong-port attempt intervals overlap"
        groups = capture["wrong_port_attempts"]
        assert len(groups) == 2 and groups[0]["sequence"] != groups[1]["sequence"]
        assert groups[0]["indices"] and groups[1]["indices"] and max(groups[0]["indices"]) < min(groups[1]["indices"])
        return
    assert set(wrong) == {"disposition", "local", "peer", "result", "sent_bytes", "connect_attempts", "timeout_ns",
                          "started_monotonic_ns", "ended_monotonic_ns"}
    assert wrong["disposition"] == "PASS" and wrong["local"] == ["192.0.2.1", 42031]
    assert wrong["peer"] == ["192.0.2.100", 7005] and wrong["result"] == "connect-timeout" and wrong["sent_bytes"] == 0
    assert wrong["connect_attempts"] == 1 and wrong["timeout_ns"] == WRONG_TIMEOUT_NS
    assert type(wrong["started_monotonic_ns"]) is type(wrong["ended_monotonic_ns"]) is int
    assert wrong["ended_monotonic_ns"] - wrong["started_monotonic_ns"] > MIN_NEGATIVE_NS, "false short timeout evidence"
    assert readiness["schema"] == "absd-native-tcp-server-neighbor/1" and readiness["disposition"] == "PASS"
    assert all(type(readiness[k]) is int for k in ("reply_monotonic_ns", "pin_verified_monotonic_ns"))
    assert 0 < readiness["reply_monotonic_ns"] <= readiness["pin_verified_monotonic_ns"] <= wrong["started_monotonic_ns"]
    neighbor_binding(readiness["neighbor_readback"], readiness["interface"])
    replace, show = neighbor_commands(readiness["interface"])
    assert readiness["replace_argv"] == replace and readiness["readback_argv"] == show
    for direction in ("request", "reply"):
        data = bytes.fromhex(readiness[direction + "_hex"])
        assert digest(data) == readiness[direction]
        observed = capture["readiness_arp"][direction]
        assert {k: observed[k] for k in ("bytes", "sha256")} == readiness[direction], "readiness/capture identity differs"
    assert bytes.fromhex(readiness["request_hex"]) == arp_request()
    arp_reply(bytes.fromhex(readiness["reply_hex"]))
    assert peer["disposition"] == "PASS" and peer["local"] == ["192.0.2.1", 42030]
    assert peer["peer"] == ["192.0.2.100", 7005] and peer["bytes"] == 3072
    assert peer["sha256"] == digest(DATA)["sha256"] and peer["write_half_closed"] is True and peer["read_EOF"] is True
    assert all(type(peer[k]) is int for k in ("connect_started_monotonic_ns", "connected_monotonic_ns", "completed_monotonic_ns"))
    assert wrong["ended_monotonic_ns"] <= peer["connect_started_monotonic_ns"] <= peer["connected_monotonic_ns"] <= peer["completed_monotonic_ns"], "client intervals overlap"


def arp_request():
    return (b"\xff" * 6 + HOST_MAC + b"\x08\x06\0\x01\x08\0\x06\x04\0\x01"
            + HOST_MAC + HOST + b"\0" * 6 + GUEST + b"\0" * 18)


def arp_reply(frame):
    expected = (HOST_MAC + GUEST_MAC + b"\x08\x06\0\x01\x08\0\x06\x04\0\x02"
                + GUEST_MAC + GUEST + HOST_MAC + HOST)
    assert len(frame) in (42, 60) and frame[:42] == expected and not any(frame[42:]), "exact matching guest ARP reply required"


def neighbor_binding(rows, interface):
    assert interface == "tcps-tap0", "owned fixture interface required"
    assert len(rows) == 1
    row = rows[0]
    assert row["dst"] == "192.0.2.100" and row["dev"] == interface and row["lladdr"] == GUEST_MAC.hex(":")
    assert row["state"] == ["PERMANENT"], "fixture-known permanent neighbor pin not verified"


def neighbor_commands(interface):
    # iproute2 omits JSON "dev" when a dev selector is supplied. Read the
    # fresh owned namespace's whole table, then require its one exact entry.
    return (["ip", "neigh", "replace", "192.0.2.100", "lladdr", GUEST_MAC.hex(":"), "nud", "permanent", "dev", interface],
            ["ip", "-j", "neigh", "show"])


def neighbor_ready_client(interface, result):
    assert interface == "tcps-tap0" and not result.exists()
    # Raw ARP receipt is observed readiness, not proof of Linux cache mutation.
    # Explicitly pin the known fixture mapping only AFTER the matching reply.
    request, observations = arp_request(), []
    until = time.monotonic_ns() + 3_000_000_000
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806)) as sock:
        sock.bind((interface, 0x0806))
        assert sock.send(request) == len(request), "short ARP request send"
        while True:
            remaining = until - time.monotonic_ns()
            assert remaining > 0 and len(observations) < 32, "neighbor readiness deadline/census"
            sock.settimeout(remaining / 1_000_000_000)
            frame = sock.recv(1515)
            assert time.monotonic_ns() <= until, "late neighbor readiness"
            observations.append({"frame_hex": frame.hex(), **digest(frame)})
            try:
                arp_reply(frame)
            except AssertionError:
                continue
            reply_at = time.monotonic_ns()
            break
    replace, show = neighbor_commands(interface)
    checked(replace)
    rows = json.loads(checked(show).stdout)
    neighbor_binding(rows, interface)
    write(result, {"schema": "absd-native-tcp-server-neighbor/1", "disposition": "PASS", "interface": interface,
          "request_hex": request.hex(), "request": digest(request), "reply_hex": frame.hex(), "reply": digest(frame),
          "reply_monotonic_ns": reply_at, "pin_verified_monotonic_ns": time.monotonic_ns(),
          "replace_argv": replace, "readback_argv": show, "neighbor_readback": rows, "observed_frames": observations,
          "limit": "Explicit fixture-known neighbor pin; raw ARP alone is not assumed to populate the Linux cache."})


def wrong_port_client(result, distinct_attempts=1):
    assert type(distinct_attempts) is int and distinct_attempts in (1, 2)
    attempts = []
    for index in range(distinct_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("192.0.2.1", 42031)); sock.settimeout(WRONG_TIMEOUT_NS / 1_000_000_000)
            started = time.monotonic_ns()
            try:
                sock.connect(("192.0.2.100", 7005))
            except TimeoutError:
                ended = time.monotonic_ns()
                assert ended - started > MIN_NEGATIVE_NS, "short connect timeout cannot establish negative interval"
                attempt = {"disposition": "PASS", "local": ["192.0.2.1", 42031],
                           "peer": ["192.0.2.100", 7005], "result": "connect-timeout", "sent_bytes": 0,
                           "connect_attempts": 1, "timeout_ns": WRONG_TIMEOUT_NS,
                           "started_monotonic_ns": started, "ended_monotonic_ns": ended}
            else:
                raise AssertionError("unauthorized source port connected")
        attempts.append(attempt)
        if distinct_attempts == 2:
            write(result.with_name(result.stem + f"-attempt-{index + 1}.json"), attempt)
    write(result, attempts[0] if distinct_attempts == 1 else {
        "schema": "absd-native-tcp-last-refusal-client/1", "disposition": "PASS", "connect_attempts": 2, "attempts": attempts})


def group_present(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    # Permission or other control errors are unknown state, never absence.
    return True


def stop_group(process):
    if process is None:
        return None
    # Every owned subprocess starts a fresh session; PID is its original PGID.
    # Leader exit does not establish that its descendants have exited.
    term_sent, kill_sent = False, False
    for requested in (signal.SIGTERM, signal.SIGKILL):
        if not group_present(process.pid):
            break
        try:
            os.killpg(process.pid, requested)
            term_sent |= requested == signal.SIGTERM
            kill_sent |= requested == signal.SIGKILL
        except ProcessLookupError:
            pass
        until = time.monotonic() + 3
        while True:
            process.poll()  # Reap the owned leader, including an earlier exit.
            if not group_present(process.pid):
                break
            if time.monotonic() >= until:
                break
            time.sleep(0.02)
    process.wait(timeout=3)
    assert not group_present(process.pid), f"owned process group remains: {process.pid}"
    return {"pid_pgid": process.pid, "leader_status": process.returncode,
            "term_sent": term_sent, "kill_sent": kill_sent, "group_absent_verified": True}


def namespace_present(namespace):
    return any(line.split()[0] == namespace for line in checked(["ip", "netns", "list"]).stdout.splitlines())


def cleanup_namespace(namespace, creation_attempted):
    present = namespace_present(namespace)
    deleted = False
    if present:
        # A name present before our creation attempt is never ours to delete.
        assert creation_attempted, "namespace present without owned creation attempt"
        assert not checked(["ip", "netns", "pids", namespace]).stdout.strip(), "namespace has live processes"
        checked(["ip", "netns", "del", namespace]); deleted = True
    assert not namespace_present(namespace), "namespace remains after cleanup"
    return {"name": namespace, "creation_attempted": creation_attempted,
            "deleted": deleted, "absence_verified": True}


def run(args, work):
    assert os.geteuid() == 0, "run only as root inside the admitted disposable VM"
    profile = args.profile
    distinct_attempts = 2 if profile == LAST_REFUSAL_PROFILE else 1
    inputs = {name: read_bound(path, MAX_ELF) for name, path in
              (("child", args.child_elf), ("parent", args.elf), ("kernel", args.kernel_elf))}
    receipt_bytes = read_bound(args.build_receipt, MAX_LOG)
    receipt = json.loads(receipt_bytes); build_binding(receipt, **inputs, profile=profile)
    for name in ("platform", "kernel"):
        item = receipt[name]["archive"]; data = read_bound(item["path"], MAX_ELF)
        assert digest(data) == {k: item[k] for k in ("bytes", "sha256")}, "exact reviewed source archive"
        (work / (name + "-source.tar")).write_bytes(data)
    for i, item in enumerate([receipt["toolchain_receipt"], *receipt["logs"]]):
        data = read_bound(item["path"], MAX_LOG)
        assert digest(data) == {k: item[k] for k in ("bytes", "sha256")}, "retained build log/toolchain identity"
        (work / f"build-input-{i}.log").write_bytes(data)
    # Retained immutable copies, not pathname re-reads, define every embed edge.
    for name, data in inputs.items():
        (work / (name + ".elf")).write_bytes(data)
    (work / "BUILD-RECEIPT.json").write_bytes(receipt_bytes)
    tree = work / "iso-tree/boot/grub"; tree.mkdir(parents=True)
    (tree.parent / "absd-kernel").write_bytes(inputs["kernel"])
    (tree / "grub.cfg").write_text('insmod all_video\nset timeout=0\nmenuentry "ABSD TCP server" {\n multiboot2 /boot/absd-kernel durable=1 net nvme-write=absd\n boot\n}\n')
    iso, disk = work / "native-tcp-server.iso", work / "native-tcp-server.img"
    iso_command = ["grub-mkrescue", "-o", str(iso), str(tree.parent.parent)]
    iso_log = work / "iso-build.log"
    with iso_log.open("wb") as log:
        maker = subprocess.Popen(iso_command, stdout=log, stderr=subprocess.STDOUT,
                                 start_new_session=True, preexec_fn=iso_file_limit)
        try:
            end = time.monotonic() + 60
            while maker.poll() is None:
                assert time.monotonic() < end and iso_log.stat().st_size <= MAX_LOG, "ISO producer time/log bound"
                time.sleep(0.02)
            assert maker.returncode == 0 and iso_log.stat().st_size <= MAX_LOG, "ISO producer failed/log bound"
        finally:
            iso_group = stop_group(maker)
    iso_bytes = read_bound(iso, MAX_ISO)
    assert iso_bytes.count(inputs["kernel"]) == 1, "exact kernel bytes not uniquely present in ISO"
    with disk.open("wb") as output:
        output.truncate(2 << 20)
    namespace, tap = "absdtcps-" + uuid.uuid4().hex[:12], "tcps-tap0"
    created, creation_attempted, qemu, clients, logs, errors = False, False, None, [], [], []
    try:
        assert not namespace_present(namespace), "namespace name already exists"
        # ip may mutate the namespace and then time out or lose its response.
        creation_attempted = True
        checked(["ip", "netns", "add", namespace]); created = True
        for key in ("all.disable_ipv6=1", "default.disable_ipv6=1"):
            checked(["ip", "netns", "exec", namespace, "sysctl", "-qw", "net.ipv6.conf." + key])
        for command in (["link", "set", "lo", "up"], ["tuntap", "add", "dev", tap, "mode", "tap"],
                        ["link", "set", tap, "address", HOST_MAC.hex(":")], ["link", "set", tap, "mtu", "1500"],
                        ["addr", "add", "192.0.2.1/24", "dev", tap], ["link", "set", tap, "up"]):
            checked(["ip", "-n", namespace, *command])
        link = json.loads(checked(["ip", "-j", "-n", namespace, "link", "show", "dev", tap]).stdout)
        assert len(link) == 1 and link[0]["mtu"] == 1500 and link[0]["address"] == HOST_MAC.hex(":")
        serial, capture = work / "serial.log", work / "capture.pcap"
        qlog = (work / "qemu.log").open("wb"); logs.append(qlog)
        command = served_qemu(["ip", "netns", "exec", namespace, os.environ.get("ABSD_QEMU", "qemu-system-x86_64"),
                   "-accel", "tcg,thread=single", "-cpu", "max,vendor=GenuineIntel,+rdrand", "-smp", "1", "-m", "256M",
                   "-cdrom", str(iso), "-drive", f"file={disk},format=raw,if=ide,index=0", "-display", "none",
                   "-serial", f"file:{serial}", "-no-reboot", "-no-shutdown", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
                   "-device", f"e1000,netdev=n0,mac={GUEST_MAC.hex(':')}", "-netdev", f"tap,id=n0,ifname={tap},script=no,downscript=no,vnet_hdr=off",
                   "-object", f"filter-dump,id=cap0,netdev=n0,file={capture}"])
        qemu = subprocess.Popen(command, stdout=qlog, stderr=subprocess.STDOUT,
                                start_new_session=True, preexec_fn=producer_file_limit)
        deadline = time.monotonic() + args.timeout
        write(work / "LAUNCH.json", {"profile": profile, "namespace": namespace, "tap": tap, "qemu_pid_pgid": qemu.pid,
              "command": command, "inputs": {k: digest(v) for k, v in inputs.items()}, "iso": digest(iso_bytes),
              "iso_command": iso_command, "iso_builder_pid_pgid": maker.pid, "iso_builder_terminal": maker.returncode,
              "iso_builder_group_cleanup": iso_group,
              "build_receipt": digest(receipt_bytes), "runner": digest(read_bound(__file__, MAX_LOG)),
              "boot_helper": digest(read_bound(boot.__file__, MAX_LOG)),
              "peer_source": digest(read_bound(ROOT / "scripts/native-tcp-server-peer.py", MAX_LOG)),
              "namespace_link": link, "timeout_seconds": args.timeout})

        def bounded_wait(process=None, marker=None):
            while True:
                for path, limit in ((serial, MAX_LOG), (capture, MAX_CAPTURE), (work / "qemu.log", MAX_LOG),
                                    (work / "neighbor-ready.log", MAX_LOG), (work / "wrong-port.log", MAX_LOG),
                                    (work / "peer.log", MAX_LOG)):
                    assert not path.exists() or path.stat().st_size <= limit, f"output bound: {path}"
                assert time.monotonic() < deadline, "proof wall deadline"
                if marker is not None:
                    if marker in boot.stdout_of(serial):
                        return
                    assert qemu.poll() is None, "guest exited before LISTEN readiness"
                elif process.poll() is not None:
                    return
                time.sleep(0.02)

        bounded_wait(marker=READY)
        write(work / "LISTEN-OBSERVED.json", {"marker": READY.decode(), "serial_prefix": digest(read_bound(serial, MAX_LOG)),
              "observation_monotonic": time.monotonic(), "meaning": "Trusted sole-socket marker observed before wrong-port client launch. No counter reset, capture boundary selection or physical-time equivalence."})
        for name, script in (("neighbor-ready", [sys.executable, str(Path(__file__).resolve()), "--neighbor-ready-client", tap]),
                             ("wrong-port", [sys.executable, str(Path(__file__).resolve()), "--last-refusal-client" if distinct_attempts == 2 else "--wrong-port-client"]),
                             ("peer", [sys.executable, str(ROOT / "scripts/native-tcp-server-peer.py")])):
            log = (work / (name + ".log")).open("wb"); logs.append(log)
            process = subprocess.Popen(["ip", "netns", "exec", namespace, *script, str(work / (name + ".json"))],
                                       stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                                       preexec_fn=producer_file_limit)
            clients.append(process); bounded_wait(process=process)
            assert process.returncode == 0, name + " client failed"
        bounded_wait(process=qemu)
        result = native_output(read_bound(serial, MAX_LOG), qemu.returncode)
        boundary_result = boundary_observation(result)
        capture_bytes = read_bound(capture, MAX_CAPTURE)
        capture_result = inspect_capture(capture_bytes, distinct_attempts=distinct_attempts)
        refusal_result = refusal_observation(result, capture_result)
        readiness = json.loads(read_bound(work / "neighbor-ready.json", MAX_LOG))
        wrong = json.loads(read_bound(work / "wrong-port.json", MAX_LOG))
        peer = json.loads(read_bound(work / "peer.json", MAX_LOG))
        peer_results(wrong, peer, readiness, capture_result, distinct_attempts=distinct_attempts)
        result.update({"disposition": "PASS", "profile": profile, "scope": "one exact-peer delegated IPv4 TCP echo and observed pre-connect wrong-source-port filter refusal",
                       "capture": digest(capture_bytes), "capture_result": capture_result,
                       "guest_peer_refusal": refusal_result,
                       "native_boundary": boundary_result,
                       "neighbor_readiness": digest(read_bound(work / "neighbor-ready.json", MAX_LOG)),
                       "wrong_port_result": digest(read_bound(work / "wrong-port.json", MAX_LOG)),
                       "peer_result": digest(read_bound(work / "peer.json", MAX_LOG)), "unrun": UNRUN,
                       "source_binding_limit": "Build receipt attests exact clean source and commands; bytes prove child/parent/kernel/ISO containment, not compiler correctness."})
        return result
    finally:
        groups, namespace_result = [], {"name": namespace, "absence_verified": False}
        for process in [*reversed(clients), qemu]:
            try:
                if process is not None:
                    groups.append(stop_group(process))
            except BaseException as error:
                errors.append(repr(error))
        for log in logs:
            log.close()
        try:
            namespace_result = cleanup_namespace(namespace, creation_attempted)
        except BaseException as error:
            errors.append("namespace: " + repr(error))
        write(work / "LOCAL-CLEANUP.json", {"disposition": "FAIL" if errors else "PASS", "errors": errors,
              "namespace": namespace, "created": created, "creation_attempted": creation_attempted,
              "namespace_result": namespace_result, "process_groups": groups,
              "owned_processes_terminal": all(p.poll() is not None for p in clients + ([qemu] if qemu else [])),
              "custody": "Root retains exact ELF/ISO/capture/log/receipt inputs for review/replay. Reproducible scratch retires after dependencies end; review source handoff or 2026-10-18T23:59:59Z."})
        if errors:
            raise RuntimeError(errors)


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--neighbor-ready-client":
        neighbor_ready_client(sys.argv[2], Path(sys.argv[3])); return
    if len(sys.argv) == 3 and sys.argv[1] == "--wrong-port-client":
        wrong_port_client(Path(sys.argv[2])); return
    if len(sys.argv) == 3 and sys.argv[1] == "--last-refusal-client":
        wrong_port_client(Path(sys.argv[2]), distinct_attempts=2); return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path)
    parser.add_argument("--profile", choices=(PROFILE, LAST_REFUSAL_PROFILE), default=PROFILE)
    for name in ("kernel-elf", "elf", "child-elf", "build-receipt"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    assert 10 <= args.timeout <= 180, "timeout must be 10..180 seconds"
    work = args.work.resolve(); work.mkdir(parents=True, mode=0o700, exist_ok=False)
    def stopped(_signum, _frame):
        raise KeyboardInterrupt("runner terminated")
    signal.signal(signal.SIGTERM, stopped); signal.signal(signal.SIGINT, stopped)
    try:
        result = run(args, work)
    except BaseException as error:
        write(work / "RESULT.json", {"schema": "absd-native-tcp-server-proof/4", "profile": args.profile, "disposition": "FAIL", "error": repr(error), "unrun": UNRUN})
        raise
    write(work / "RESULT.json", {"schema": "absd-native-tcp-server-proof/4", **result})
    print("NATIVE TCP SERVER PROOF PASS")


if __name__ == "__main__":
    main()
