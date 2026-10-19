#!/usr/bin/env python3
"""Opt-in, three-case Linux IPv6 HTTPS proof with exact source pins.

No compilation, PKI creation, clock setting or source transfer is performed.
Run one case in one fresh namespace, with prebuilt exact input buffers. A
SERVICE DONE line is never substituted for the selected case's actual oracle.
"""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import shutil
import ssl
import stat
import struct
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
PRODUCT = "8b93d2d57dc43e321308d62e3e66d18f73214520"
PRODUCT_TREE = "ef8a1776a3618df3a780e83cac08534c5e653723"
KERNEL = "929a8efd7dee6a0f227c677cb453516b9a380c10"
KERNEL_TREE = "bd1f5c036bd11875121858d20f8809548e2a87c0"
ARCHIVES = {"platform": (24279040, "b0c298c7ea53edccad2ba6b3ce035bfc2b5f8a3e9dfb9620a6b87294440f42ee"),
            "kernel": (12451840, "81600785cdedb0ad0e5552563da10f11c591b842b2fbc7d7e30e2c1807293f6c")}
PINS = {"native-tls-matrix.py": "9f82fc85874f61eb300ff635548cc80ad000803c8854e52b25acc2fb1635fbbd",
        "native-ipv6-accounting.py": "22d5f091c23c0d436be538d3695b43b3ed52b48ec5b4b30668be215a08001ad3",
        "native-ipv6-reason-accounting.py": "8155af1e25c73b1eb67636955a8e350c881cdd869c6cc73e70038bca06e0a827",
        "net-matrix.py": "7d51d1861e9a7942a3cde05137ac0ba040b219c0ef18c5a68d26aea78d060b36",
        "served_ram.py": "232c63d71884be4216860614108c4527b30a1f48debb6a6226abd94b49cf7bba",
        "native-tls-cases.json": "9e33abf2e5152efd91a47da564c49ffc919c8809f0fd6db283d1390e65b799fa"}
GUEST = ipaddress.IPv6Address("fd00:ab5d::15").packed
HOST = ipaddress.IPv6Address("fd00:ab5d::2").packed
GM = bytes.fromhex("525400ab5d15")
HM = bytes.fromhex("525500000202")
PROFILE = {"guest": "fd00:ab5d::15", "host": "fd00:ab5d::2", "udp": None, "tcp": [7401, 4443]}
MAX_LOG, MAX_CAPTURE, MAX_ELF, MAX_ISO = 8 << 20, 2 << 20, 32 << 20, 64 << 20
MAX_WIRE = 65536
TLS_LOCK = "cb9ae1c849fe3f86196e2d0a162453b7f437d1e32be633a4ac02888c26dd42d9"
REQUEST = b"GET /native-network HTTP/1.1\r\nHost: absd-fixture.test:4443\r\nConnection: close\r\n\r\n"
BOOT = (b'insmod all_video\nset timeout=0\nmenuentry "ABSD IPv6 HTTPS" {\n'
        b' multiboot2 /boot/absd-kernel durable=1 net nvme-write=absd\n boot\n}\n')
CHUNK = re.compile(rb"(?m)^EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]*)\n")
if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
    raise SystemExit("optimized Python is refused")


def digest(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def bounded(path, maximum):
    with Path(path).open("rb") as stream:
        data = stream.read(maximum + 1)
    assert len(data) <= maximum, "byte bound: " + str(path)
    return data


def write(path, value):
    data = (json.dumps(value, indent=2) + "\n").encode()
    with Path(path).open("xb") as stream:
        stream.write(data)
    return data


def sibling(name, filename):
    path = ROOT / "scripts" / filename
    if filename in PINS:
        assert digest(bounded(path, MAX_LOG))["sha256"] == PINS[filename], "helper changed: " + filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sys.path.insert(0, str(ROOT / "scripts"))
accounting = sibling("tls6_reasons", "native-ipv6-reason-accounting.py")
original = accounting.original
assert "tls" not in original.PROFILES
# Only this private module instance's tuple table changes. Accepted helper
# source, classifier, first-four policy and sidecar-equality guard are intact.
original.PROFILES["tls"] = PROFILE
tls = sibling("tls6_canonical", "native-tls-matrix.py")
assert digest(bounded(ROOT / "scripts/served_ram.py", MAX_LOG))["sha256"] == PINS["served_ram.py"]
from served_ram import served_qemu


def fields(line):
    tokens = line.split()[3:] if line.startswith("TLS IPV6 ") else line.split()[2:]
    pairs = [token.split("=", 1) for token in tokens if "=" in token]
    assert len({p[0] for p in pairs}) == len(pairs), "duplicate diagnostic field"
    return dict(pairs)


def one(lines, prefix):
    matching = [line for line in lines if line.startswith(prefix)]
    assert len(matching) == 1, "missing/repeated marker: " + prefix
    return fields(matching[0])


def natural(value):
    assert re.fullmatch(r"0|[1-9][0-9]*", value), "noncanonical natural"
    result = int(value)
    assert result <= (1 << 64) - 1
    return result


def native_output(raw, status, case, anchor):
    assert case in ("P01", "P02", "L07") and status == 3, "case/QEMU exit"
    assert b"\nABSD BOOT OK\n" in raw and b"\nDURABLE WORKLOAD OK\n" in raw
    terminal = re.findall(rb"(?m)^DURABLE status=([^\n]+)\n", raw)
    assert len(terminal) == 1 and raw.count(b"DURABLE status=") == 1
    pairs = [p.split("=", 1) for p in ("status=" + terminal[0].decode()).split()]
    assert len({p[0] for p in pairs}) == len(pairs)
    durable = dict(pairs)
    assert all(durable[k] == "0" for k in ("status", "frames", "processes", "cells", "pipes"))
    for bad in (b"PANIC", b"KERNEL FAULT", b"init: FAILED", b"NIC DISABLED"):
        assert bad not in raw
    chunks = list(CHUNK.finditer(raw))
    assert chunks and len(chunks) == raw.count(b"EXTERNAL OUTPUT CHUNK"), "malformed chunk"
    output = bytearray()
    for chunk in chunks:
        assert int(chunk[1], 16) == len(output), "chunk offset/order"
        output.extend(bytes.fromhex(chunk[2].decode()))
        assert len(output) <= 65536
    text = output.decode("utf-8")
    assert "ERROR" not in text and "FAILED" not in text
    lines = text.splitlines()
    setup = one(lines, "TLS IPV6 RX SETUP ")
    assert setup["continuous_vm_required"] == "1"
    assert natural(setup["ready_ms"]) - natural(setup["nic_ready_ms"]) >= 1100
    ready = one(lines, "TLS IPV6 SERVICE READY ")
    assert ready["case"] == case and ready["local_port"] == "7401" and ready["scope"] == "1" and ready["peer_port"] == "4443"
    issued, expiry, end = [natural(ready[k]) for k in ("issued_ms", "expiry_ms", "invocation_deadline_ms")]
    assert expiry == issued + 15000 and natural(setup["ready_ms"]) <= issued < expiry < end
    before = one(lines, "TLS IPV6 RESOURCES label=before ")
    after = one(lines, "TLS IPV6 RESOURCES label=after ")
    assert all(natural(before[k]) == natural(after[k]) for k in ("processes", "handles", "pipes", "cells"))
    authority = one(lines, "TLS IPV6 CLIENT AUTHORITY ")
    assert authority["nic"] == "0" and authority["block"] == "false"
    assert natural(authority["input"]) > 0 and natural(authority["output"]) > 0 and authority["input"] != authority["output"]
    begin = one(lines, "TLS IPV6 BEGIN ")
    assert begin["case"] == case and begin["unix_time"] == "Some(" + str(anchor) + ")" and begin["expected_body"] == "2048"
    start = natural(begin["start_ms"])
    deadline = natural(begin["deadline_ms"])
    assert issued <= start < expiry and natural(begin["grant_expiry_ms"]) == expiry and deadline == min(start + 10000, expiry)
    child = one(lines, "TLS IPV6 CHILD DONE ")
    assert child == {"case": case, "kind": "1", "status": "0"}
    done = one(lines, "TLS IPV6 SERVICE DONE ")
    assert done["case"] == case and done["sockets"] == "0"
    assert natural(done["rx_missed_before"]) == natural(done["rx_missed_after"])
    done_at = natural(done["at_ms"])
    assert start <= done_at < end
    terminal_ms = natural(durable["ticks"]) * 1193 * 3000 // 3579545
    assert done_at <= terminal_ms, "PIT ticks are not boot milliseconds"
    cpu = one(lines, "TLS CPU ")
    eax, ecx = natural(cpu["leaf1_eax"]), natural(cpu["leaf1_ecx"])
    assert cpu["vendor"] == "GenuineIntel" and cpu["rdrand"] == "1" and ecx & (1 << 30)
    assert natural(cpu["family"]) == ((eax >> 8) & 15) == 6
    assert natural(cpu["model"]) == ((eax >> 4) & 15) | (((eax >> 16) & 15) << 4) == 60
    result = one(lines, "TLS RESULT case=")
    assert sum(line.startswith("TLS RESULT") for line in lines) == 1
    assert result["case"] == case and result["preauth_http_emitted"] == "0"
    if case == "L07":
        assert result["outcome"] == "NATIVE" and result["native_error"] == "Denied" and result["actor"] == "authority-control"
        assert result["denied_connect_requests"] == "1" and result["http_emitted"] == result["http_body"] == "0"
        denial = [line for line in lines if line.startswith("TLS DENIAL ")]
        expected = bytes([2, 16, 2, 6]) + HOST + struct.pack("!IH", 1, 4443) + bytes(2)
        assert len(denial) == 1
        match = re.fullmatch(r"TLS DENIAL reply_bytes=28 header=\[([0-9, ]+)\]", denial[0])
        assert match and bytes(int(x.strip()) for x in match[1].split(",")) == expected
        assert natural(result["end_ms"]) < deadline
    else:
        assert result["pipe_fenced"] == "true" and result["connect_calls"] == "1"
        assert natural(result["start_ms"]) == start and natural(result["deadline_ms"]) == deadline
        assert natural(result["grant_expiry_ms"]) == expiry and start <= natural(result["end_ms"]) < deadline
        if case == "P01":
            assert result["outcome"] == "SUCCESS" and result["protocol_version"] == 'Some("TLSv1_3")'
            assert result["http_body"] == "2048" and natural(result["http_emitted"]) == len(REQUEST)
            assert all(result[k] == "true" for k in ("authenticated", "peer_closed", "local_close_drained", "native_close_accepted"))
            assert result["cleanup_error"] == "None" and result["native_error"] == "None"
        else:
            assert result["outcome"] == "CERTIFICATE" and result["tls_error_code"] == 'Some("UNKNOWN_ISSUER")'
            assert result["http_emitted"] == result["http_body"] == "0" and result["authenticated"] == "false"
            assert natural(result["write_accepted"]) <= 1024, "pre-auth accepted writes exceed 1024 bytes"
    positions = [text.index(prefix) for prefix in ("TLS IPV6 RX SETUP ", "TLS IPV6 RESOURCES label=before ",
                 "TLS IPV6 SERVICE READY ", "TLS IPV6 CLIENT AUTHORITY ", "TLS IPV6 BEGIN ",
                 "TLS RESULT case=", "TLS IPV6 CHILD DONE ", "TLS IPV6 RESOURCES label=after ", "TLS IPV6 SERVICE DONE ")]
    assert positions == sorted(positions) and lines[-1].startswith("TLS IPV6 SERVICE DONE ")
    nic = re.findall(rb"(?m)^NIC STATS ([^\n]+)\n", raw)
    assert len(nic) == 1 and raw.count(b"NIC STATS ") == 1
    pairs = [p.split("=", 1) for p in nic[0].decode().split()]
    assert len({p[0] for p in pairs}) == len(pairs)
    counters = dict(pairs)
    assert counters["flags"] == "1", "NIC must report LINK_UP without DISABLED"
    for key in ("rx_frames", "tx_frames", "rx_refused", "rx_missed", "tx_refused", "tx_errors"):
        natural(counters[key])
    if case != "L07":
        assert natural(counters["rx_frames"]) > 0 and natural(counters["tx_frames"]) > 0
    return {"output": text, "case": case, "result": result, "counters": counters,
            "done_boot_ms": done_at, "terminal_boot_ms": terminal_ms, "authority": authority,
            "resources_before": before, "resources_after": after}


def client_hello(data):
    records = tls.record_frames(data)
    assert len(records) <= 128
    assert all(record[0] in (20, 22, 23) and record[1:3] in (b"\x03\x01", b"\x03\x03")
               and len(record) <= 18437 for _, record in records), "TLS record envelope"
    assert records and records[0][1][0] == 22, "ClientHello first TLS record"
    handshake = b"".join(record[5:] for _, record in records if record[0] == 22)
    assert len(handshake) >= 4 and handshake[0] == 1
    size = int.from_bytes(handshake[1:4], "big")
    assert len(handshake) >= size + 4
    body = handshake[4:4 + size]
    assert body[:2] == b"\x03\x03" and len(body) >= 38
    at = 35 + body[34]
    assert at + 2 <= len(body)
    width = int.from_bytes(body[at:at + 2], "big")
    assert width > 0 and width % 2 == 0 and at + 2 + width < len(body)
    at += 2 + width
    width = body[at]
    assert body[at + 1:at + 1 + width] == b"\0"
    at += 1 + width
    assert at + 2 <= len(body) and int.from_bytes(body[at:at + 2], "big") == len(body) - at - 2
    at += 2
    extensions = {}
    while at < len(body):
        assert at + 4 <= len(body)
        kind, width = struct.unpack("!HH", body[at:at + 4]); at += 4
        assert kind not in extensions and at + width <= len(body)
        extensions[kind] = body[at:at + width]; at += width
    name = b"absd-fixture.test"
    assert extensions[0] == struct.pack("!H", len(name) + 3) + b"\0" + struct.pack("!H", len(name)) + name
    assert extensions[16] == b"\0\x09\x08http/1.1" and b"\x03\x04" in extensions[43]
    return {"bytes": size + 4, "sha256": digest(handshake[:size + 4])["sha256"], "sni": name.decode(), "alpn": "http/1.1"}


def inspect_capture(data, case, peer):
    records, _ = original.capture_records(data)
    rows = [original.classify(r, GM, HM, PROFILE) for r in records]
    assert all(r["kind"] in ("linux-mldv2", "peer-nd", "peer-tcp") for r in rows), "unexplained complete capture frame"
    nd = [{"index": r["index"], "type": r["icmpv6_type"], "direction": r["direction"]} for r in rows if r["kind"] == "peer-nd"]
    tcp = []
    for r, row in zip(records, rows):
        if row["kind"] != "peer-tcp":
            continue
        frame = r["frame"]; segment = frame[54:54 + int.from_bytes(frame[18:20], "big")]
        assert frame[21] == 64, "direct-link TCP hop limit"
        end = (segment[12] >> 4) * 4
        flags = segment[13]
        assert flags in (2, 18, 16, 24, 17, 25, 4, 20), "unexpected TCP flag combination"
        assert flags & 0xc0 == 0 and segment[12] & 1 == 0 and flags & 0x20 == 0 and segment[18:20] == bytes(2)
        tcp.append({"index": r["index"], "direction": row["direction"], "seq": int.from_bytes(segment[4:8], "big"),
                    "ack": int.from_bytes(segment[8:12], "big"), "flags": flags, "options": segment[20:end], "data": segment[end:]})
    assert peer["case"]["id"] == case and peer["disposition"] == "PASS" and not peer["errors"]
    assert peer["guard_accepts"] == 0 and peer["transport"] == "Linux AF_INET6 TCP / OpenSSL TLS1.3 / kernel ND"
    if case == "L07":
        assert not tcp and not nd and peer["accepts"] == peer["request_bytes"] == 0
        assert peer["received_hex"] == peer["sent_hex"] == ""
        return {"census": rows, "tcp_frames": 0, "authority_denial": True}
    assert peer["accepts"] == 1 and tcp
    syns = {d: [r for r in tcp if r["direction"] == d and r["flags"] & 2] for d in ("outgoing", "incoming")}
    assert all(1 <= len(v) <= 3 and len({r["seq"] for r in v}) == 1 and not any(r["data"] for r in v) for v in syns.values())
    gs, hs = syns["outgoing"][0], syns["incoming"][0]
    assert gs["flags"] == 2 and hs["flags"] == 18 and hs["ack"] == (gs["seq"] + 1) % (1 << 32)
    assert all(r["flags"] == 2 for r in syns["outgoing"]) and all(r["flags"] == 18 for r in syns["incoming"])
    assert gs["index"] < hs["index"]
    guest_data = [r for r in tcp if r["direction"] == "outgoing" and r["data"]]
    linux_data = [r for r in tcp if r["direction"] == "incoming" and r["data"]]
    assert guest_data and linux_data and hs["index"] < guest_data[0]["index"] < linux_data[0]["index"], "SYN/SYNACK/ClientHello/server order"
    assert any(r["direction"] == "outgoing" and r["flags"] & 16 and r["ack"] == (hs["seq"] + 1) % (1 << 32)
               and hs["index"] < r["index"] <= guest_data[0]["index"] for r in tcp), "completed three-way handshake"
    assert any(a["direction"] == "outgoing" and a["type"] == 135 and any(b["direction"] == "incoming" and b["type"] == 136 and a["index"] < b["index"] < gs["index"] for b in nd) for a in nd), "actual guest NS/Linux NA before first SYN"
    for syn in syns["outgoing"]:
        options, at, mss = syn["options"], 0, []
        while at < len(options):
            kind = options[at]
            if kind == 0: break
            if kind == 1: at += 1; continue
            width = options[at + 1]
            if kind == 2:
                assert width == 4; mss.append(int.from_bytes(options[at + 2:at + 4], "big"))
            at += width
        assert mss == [1440], "native IPv6 MSS1440"
    streams, fins = {}, {}
    for direction, first in (("outgoing", gs), ("incoming", hs)):
        cells, finishes = {}, set()
        for row in tcp:
            if row["direction"] != direction: continue
            assert row["index"] >= first["index"] and (case != "P01" or not row["flags"] & 4)
            offset = (row["seq"] - first["seq"] - 1) % (1 << 32)
            if row["flags"] & 2: continue
            assert offset <= MAX_WIRE and offset + len(row["data"]) <= MAX_WIRE
            for i, byte in enumerate(row["data"], offset):
                assert i not in cells or cells[i] == byte, "conflicting retransmission"
                cells[i] = byte
            if row["flags"] & 1: finishes.add(offset + len(row["data"]))
        assert cells and set(cells) == set(range(max(cells) + 1)), "TCP stream gap"
        streams[direction] = bytes(cells[i] for i in range(len(cells)))
        assert len(finishes) <= 1
        fins[direction] = next(iter(finishes)) if finishes else None
        assert not finishes or fins[direction] == len(streams[direction]), "FIN before stream end"
    for row in tcp:
        if not row["flags"] & 16: continue
        other = "incoming" if row["direction"] == "outgoing" else "outgoing"
        first = hs if other == "incoming" else gs
        relative = (row["ack"] - first["seq"] - 1) % (1 << 32)
        assert relative <= len(streams[other]) + (fins[other] is not None), "ACK outside captured stream"
    assert streams["outgoing"].hex() == peer["received_hex"] and streams["incoming"].hex() == peer["sent_hex"], "Linux recv/send versus full captured TCP bytes"
    assert digest(streams["outgoing"])["sha256"] == peer["received_sha256"]
    assert digest(streams["incoming"])["sha256"] == peer["sent_sha256"]
    hello = client_hello(streams["outgoing"])
    tls.record_frames(streams["incoming"])
    if case == "P01":
        assert peer["request_bytes"] == len(REQUEST)
        assert peer["request_sha256"] == digest(REQUEST)["sha256"]
        assert peer["server_handshake_complete"] and peer["client_close_notify_received"] and peer["server_close_notify_drained"]
        handshake = [e for e in peer["events"] if e["event"] == "tls-handshake-complete"]
        assert len(handshake) == 1 and handshake[0]["version"] == "TLSv1.3" and handshake[0]["alpn"] == "http/1.1" and not handshake[0]["session_reused"]
        response = [e for e in peer["events"] if e["event"] == "http-response"]
        expected = tls.response(peer["case"])
        assert len(response) == 1 and response[0]["bytes"] == len(expected) and response[0]["sha256"] == digest(expected)["sha256"]
        for direction, first in (("outgoing", gs), ("incoming", hs)):
            assert fins[direction] == len(streams[direction]), "positive FIN absent"
            wanted = (first["seq"] + 2 + len(streams[direction])) % (1 << 32)
            assert any(r["direction"] != direction and r["flags"] & 16 and r["ack"] == wanted and r["index"] > min(x["index"] for x in tcp if x["direction"] == direction and x["flags"] & 1) for r in tcp), "FIN acknowledgement absent"
    else:
        assert len(streams["outgoing"]) <= 1024, "pre-auth guest stream exceeds 1024 bytes"
        assert peer["request_bytes"] == 0 and not peer["server_handshake_complete"]
        assert not any(e["event"] in ("http-request", "http-response") for e in peer["events"])
        assert any(e["event"] == "connection-ended" for e in peer["events"])
    return {"census": rows, "ND": nd, "tcp_frames": len(tcp), "client_hello": hello,
            "guest_stream": digest(streams["outgoing"]), "linux_stream": digest(streams["incoming"]),
            "guest_FIN": fins["outgoing"], "linux_FIN": fins["incoming"]}


def elf(data):
    assert len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01"
    assert struct.unpack_from("<H", data, 18)[0] == 62
    offset = struct.unpack_from("<Q", data, 32)[0]
    width, count = struct.unpack_from("<HH", data, 54)
    assert width == 56 and 0 < count <= 128 and offset + width * count <= len(data)
    loads = 0
    for at in range(count):
        kind, _, start, _, _, length, memory, _ = struct.unpack_from("<IIQQQQQQ", data, offset + at * width)
        if kind == 1:
            assert start + length <= len(data) and length <= memory
            loads += 1
    assert loads


def build_binding(receipt, buffers, case):
    assert receipt["schema"] == "absd-native-ipv6-tls-build/1" and receipt["case"] == case
    assert receipt["tls_lock_sha256"] == TLS_LOCK
    for role, revision, tree in (("platform", PRODUCT, PRODUCT_TREE), ("kernel", KERNEL, KERNEL_TREE)):
        item = receipt[role]
        assert item["revision"] == revision and item["tree"] == tree and item["clean"] is True
        assert item["archive"] == digest(buffers[role + "_tar"]) == dict(zip(("bytes", "sha256"), ARCHIVES[role]))
    for role in ("child", "parent", "kernel"):
        elf(buffers[role])
        assert receipt["outputs"][role] == digest(buffers[role])
    assert buffers["parent"].count(buffers["child"]) == 1
    assert buffers["kernel"].count(buffers["parent"]) == buffers["kernel"].count(buffers["child"]) == 1
    pki = json.loads(buffers["public_pki"])
    assert pki["private_keys_in_evidence"] is False and pki["reference_name"] == "absd-fixture.test"
    anchor = pki["validation_unix_time"]
    assert type(anchor) is int and 0 < anchor <= (1 << 64) - 16
    assert {k: pki["root_der"][k] for k in ("bytes", "sha256")} == digest(buffers["root_der"])
    for leaf in ("valid", "untrusted"):
        item = pki["leaf_certificates"][leaf]
        assert {k: item[k] for k in ("bytes", "sha256")} == digest(buffers[leaf + "_pem"])
        assert ssl.PEM_cert_to_DER_cert(buffers[leaf + "_pem"].decode()), "public leaf PEM"
    assert buffers["valid_pem"] != buffers["untrusted_pem"]
    for role in ("client_build", "service_build"):
        item = json.loads(buffers[role])
        assert item["source_revision"] == PRODUCT and item["source_tree"] == PRODUCT_TREE
        assert item["tracked_dirty"] is False and item["untracked_source"] is False
        assert {k: item["root_der"][k] for k in ("bytes", "sha256")} == digest(buffers["root_der"])
        assert item["transport_profile"] == {"family": 6, "scope": 1, "peer": "fd00:ab5d::2", "port": 4443,
            "local_port": 7401, "mtu": 1500, "route": "static on-link only", "parent_invocation_ms": 20000,
            "client_deadline_ms": 10000, "grant_lifetime_ms": 15000}
        output = item["outputs"]["https_get_ipv6"]
        assert {k: output[k] for k in ("bytes", "sha256")} == digest(buffers["child"])
        assert item["explicit_environment"]["ABSD_TLS_IPV6_CLIENT_ELF"] == output["path"]
        assert item["cargo_lock_sha256"] == receipt["tls_lock_sha256"]
        if role == "service_build":
            assert item["service_selectors"] == {"ABSD_TLS_CASE": case, "ABSD_TLS_UNIX_SECONDS": str(anchor)}
            assert item["explicit_environment"]["ABSD_TLS_IPV6_CASE"] == case
            output = item["outputs"]["tls_ipv6_service_probe"]
            assert {k: output[k] for k in ("bytes", "sha256")} == digest(buffers["parent"])
    commands = receipt["commands"]
    assert commands and all(isinstance(c, list) and c and all(isinstance(x, str) for x in c) for c in commands)
    assert any(any(x.endswith("scripts/build-native-tls-fixture.py") for x in c) and {"--ipv6", "--client-only"} <= set(c) for c in commands)
    assert any(any(x.endswith("scripts/build-native-tls-fixture.py") for x in c) and {"--ipv6", "--service-only"} <= set(c) for c in commands)
    external = receipt["external"]
    assert set(external) == {"input", "expected", "parent"}
    assert all({k: external[n][k] for k in ("bytes", "sha256")} == digest(b"") for n in ("input", "expected"))
    assert {k: external["parent"][k] for k in ("bytes", "sha256")} == digest(buffers["parent"])
    required = {"external-build", "EXTERNAL_USER_ELF=" + external["parent"]["path"],
                "EXTERNAL_INPUT=" + external["input"]["path"], "EXTERNAL_EXPECTED=" + external["expected"]["path"]}
    assert any(required <= set(c) for c in commands)
    assert receipt["toolchain_receipt"] == digest(buffers["toolchain"])
    tools = json.loads(buffers["toolchain"])["tools"]
    for name in ("rustc_platform", "cargo_platform", "rustc_kernel", "cargo_kernel", "clang", "llvm_ar", "openssl", "qemu", "ip", "ethtool", "grub_mkrescue", "python"):
        item = tools[name]
        assert item["bytes"] > 0 and re.fullmatch("[0-9a-f]{64}", item["sha256"]) and item["version"] and Path(item["path"]).is_absolute()
    for name, key in (("clang", "compiler"), ("llvm_ar", "archiver")):
        for role in ("client_build", "service_build"):
            item = json.loads(buffers[role])["native_c_toolchain"][key]
            assert item["sha256"] == tools[name]["sha256"] and item["version"] == tools[name]["version"]
    assert 1 <= len(receipt["logs"]) <= 8
    assert all(item == digest(buffers["log_" + str(i)]) and item["bytes"] > 0 for i, item in enumerate(receipt["logs"]))
    return anchor


def iso_binding(data, kernel):
    # First-party ISO extent reader, adapted from the routed-DNS proof. Read
    # actual critical file extents, not a loose substring in an unrelated file.
    pvd = data[32768:34816]
    assert len(pvd) == 2048 and pvd[:7] == b"\x01CD001\x01"
    assert struct.unpack_from("<H", pvd, 128)[0] == struct.unpack_from(">H", pvd, 130)[0] == 2048
    def contents(record):
        assert len(record) >= 34
        at, size = struct.unpack_from("<I", record, 2)[0], struct.unpack_from("<I", record, 10)[0]
        assert at == struct.unpack_from(">I", record, 6)[0] and size == struct.unpack_from(">I", record, 14)[0]
        assert at * 2048 + size <= len(data)
        return data[at * 2048:at * 2048 + size]
    def child(directory, wanted):
        assert directory[25] & 2
        raw, at, found = contents(directory), 0, []
        while at < len(raw):
            size = raw[at]
            if not size:
                at = (at // 2048 + 1) * 2048; continue
            record = raw[at:at + size]
            assert len(record) == size and size >= 34
            at += size
            width = record[32]
            name = record[33:33 + width].split(b";", 1)[0].lower()
            extra = 33 + width + (width % 2 == 0)
            while extra + 4 <= len(record):
                kind, length = record[extra:extra + 2], record[extra + 2]
                assert length >= 4 and extra + length <= len(record)
                if kind == b"NM" and record[extra + 4] == 0:
                    name = record[extra + 5:extra + length]
                extra += length
            if name == wanted: found.append(record)
        assert len(found) == 1, "missing/duplicate ISO critical file"
        return found[0]
    boot = child(pvd[156:156 + pvd[156]], b"boot")
    image, config = child(boot, b"absd-kernel"), child(child(boot, b"grub"), b"grub.cfg")
    assert not image[25] & 2 and not config[25] & 2
    assert contents(image) == kernel and contents(config) == BOOT and data.count(kernel) == 1
    return {"kernel": digest(contents(image)), "boot_config": digest(contents(config))}


def namespace_identity(name):
    info = os.lstat("/run/netns/" + name)
    assert stat.S_ISREG(info.st_mode)
    return {"device": info.st_dev, "inode": info.st_ino}


def retire_namespace(name, expected, command):
    def present(): return name in [r.split()[0] for r in command(["ip", "netns", "list"]).splitlines() if r]
    if not present(): return True
    assert expected is not None and namespace_identity(name) == expected, "unknown/replaced namespace retained"
    assert not command(["ip", "netns", "pids", name]).strip(), "namespace has live PIDs"
    assert namespace_identity(name) == expected, "namespace replaced during PID query"
    command(["ip", "netns", "del", name])
    return not present()


def group_live(pgid):
    try: os.killpg(pgid, 0); return True
    except ProcessLookupError: return False


def stop_owned(process):
    if process is None: return {"status": None, "group_absent": True, "forced": False}
    forced = False
    for sig in (signal.SIGTERM, signal.SIGKILL):
        process.poll()
        if not group_live(process.pid): break
        forced = True
        try: os.killpg(process.pid, sig)
        except ProcessLookupError: pass
        end = time.monotonic() + 3
        while (process.poll() is None or group_live(process.pid)) and time.monotonic() < end: time.sleep(0.02)
    process.poll()
    return {"status": process.poll(), "group_absent": not group_live(process.pid), "forced": forced}


def validate_setup(state, tap):
    addresses, links = state["addresses"], state["links"]
    assert len(addresses) == len(links) == 1
    a, link = addresses[0], links[0]
    assert a["ifname"] == link["ifname"] == tap and type(a["ifindex"]) is int and a["ifindex"] > 0 and a["ifindex"] == link["ifindex"]
    assert link["address"] == HM.hex(":") and link["mtu"] == 1500 and "UP" in link["flags"]
    assert len(a["addr_info"]) == 1
    info = a["addr_info"][0]
    assert info["family"] == "inet6" and info["local"] == "fd00:ab5d::2" and info["prefixlen"] == 64
    assert not {"tentative", "dadfailed"}.intersection(info.get("flags", []))
    assert not any(r.get("dst") == "default" for r in state["routes"])
    assert all(state["sysctls"][key] == value for key, value in
               {"all.disable_ipv6": "0", "default.disable_ipv6": "0", "all.forwarding": "0", "default.forwarding": "0", "all.accept_ra": "0",
                "default.accept_ra": "0", "default.autoconf": "0", "default.dad_transmits": "0", "default.addr_gen_mode": "1", "default.hop_limit": "64"}.items())
    assert all(text in state["offloads"] for text in ("tx-checksumming: off", "generic-segmentation-offload: off", "generic-receive-offload: off"))
    return state


def seal_artifacts(work, evaluated):
    rows = {}
    for path in work.rglob("*"):
        assert not path.is_symlink(), "artifact symlink"
        if path.is_file():
            bound = MAX_ISO if path.suffix == ".iso" else MAX_ELF if path.suffix in (".elf", ".tar") or path.name == "absd-kernel" else MAX_LOG
            rows[str(path.relative_to(work))] = digest(bounded(path, bound))
    for name, expected in evaluated.items():
        assert rows[name] == expected and digest(bounded(work / name, MAX_ISO)) == expected, "evaluated artifact changed: " + name
    return rows


def run(args):
    assert os.geteuid() == 0, "owned disposable Linux VM root required"
    assert args.work.is_absolute() and not args.work.resolve().is_relative_to(ROOT), "fresh output must be outside proof checkout"
    assert 30 <= args.timeout <= 120 and args.timeout + 45 < args.lease - time.time() <= 14400
    assert re.fullmatch(r"[0-9a-f]{40}", args.proof_revision)
    def command(argv, timeout=5):
        return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=timeout).stdout
    assert command(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).strip() == args.proof_revision
    assert not command(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all"])
    source = json.loads(bounded(args.inputs, MAX_LOG))
    expected = {"platform_tar", "kernel_tar", "child", "parent", "kernel", "root_der", "valid_pem", "untrusted_pem", "public_pki", "client_build", "service_build", "toolchain", "receipt"}
    assert expected <= set(source) and set(source) - expected <= {"log_" + str(i) for i in range(8)}
    buffers, evaluated = {}, {}
    args.work.mkdir(mode=0o700)  # Must be fresh. No nested producer is replaced.
    work = args.work.resolve()
    args._owned_work = work
    info = work.stat()
    args._owned_work_identity = (info.st_dev, info.st_ino)
    inputs = work / "inputs"; inputs.mkdir()
    for role, path in source.items():
        assert Path(path).is_absolute() and not Path(path).is_symlink()
        buffers[role] = bounded(path, MAX_ELF if role.endswith("_tar") or role in ("child", "parent", "kernel") else MAX_LOG)
        destination = inputs / (role + (".elf" if role in ("child", "parent", "kernel") else ".tar" if role.endswith("_tar") else ".json" if role in ("receipt", "client_build", "service_build", "public_pki", "toolchain") else ".pem" if role.endswith("_pem") else ".der" if role == "root_der" else ".log"))
        destination.write_bytes(buffers[role]); evaluated[str(destination.relative_to(work))] = digest(buffers[role])
    receipt = json.loads(buffers["receipt"])
    anchor = build_binding(receipt, buffers, args.case)
    tools = json.loads(buffers["toolchain"])["tools"]
    actual_tools = {}
    for name, executable in (("qemu", tools["qemu"]["path"]), ("ip", shutil.which("ip")),
                             ("ethtool", shutil.which("ethtool")), ("grub_mkrescue", shutil.which("grub-mkrescue")),
                             ("python", sys.executable)):
        assert executable is not None
        identity = digest(bounded(executable, 128 << 20))
        assert identity == {k: tools[name][k] for k in ("bytes", "sha256")}, "actual executable differs: " + name
        actual_tools[name] = {"path": str(Path(executable).resolve()), **identity}
    assert args.peer_key.is_absolute() and args.peer_key.is_file() and not args.peer_key.is_symlink()
    assert args.peer_key.stat().st_mode & 0o077 == 0 and not args.peer_key.resolve().is_relative_to(work)
    pki = json.loads(buffers["public_pki"])
    pki["leaf_private_key_path"] = str(args.peer_key)
    pki["root_der"]["path"] = str(inputs / "root_der.der")
    for leaf in ("valid", "untrusted"): pki["leaf_certificates"][leaf]["path"] = str(inputs / (leaf + "_pem.pem"))
    peer_config = work / "PEER-CONFIG.json"
    evaluated[peer_config.name] = digest(write(peer_config, pki))  # Public bytes and a path, never key material.
    proof = {}
    names = [*PINS, "native-tls-ipv6-matrix.py", "native-tls-ipv6-peer.py"]
    for name in names:
        data = bounded(ROOT / "scripts" / name, MAX_LOG)
        if name in PINS: assert digest(data)["sha256"] == PINS[name]
        actual = command(["git", "-C", str(ROOT), "show", args.proof_revision + ":scripts/" + name]).encode()
        assert actual == data, "proof file differs from exact Git source"
        proof[name] = digest(data)
    deadline = time.monotonic() + args.timeout
    assert args.timeout + 45 < args.lease - time.time(), "lease margin after input validation"
    namespace = "absdtls6-" + uuid.UUID(args.run_id).hex
    tap = "tls6-tap"
    attempted, expected_namespace = False, None
    processes, logs, cleanup_errors = {}, [], []
    marker = None
    result = {"schema": "absd-native-ipv6-tls-proof/1", "case": args.case, "disposition": "FAIL", "proof_revision": args.proof_revision,
              "product": PRODUCT, "kernel": KERNEL, "proof_inputs": proof, "evaluated_artifacts": evaluated}
    def fact(name, value):
        data = write(work / name, value); evaluated[name] = digest(data); return value
    try:
        fact("ACTUAL-TOOLS.json", actual_tools)
        assert namespace not in [r.split()[0] for r in command(["ip", "netns", "list"]).splitlines() if r]
        attempted = True
        command(["ip", "netns", "add", namespace])
        expected_namespace = namespace_identity(namespace)
        sysctls = {"all.disable_ipv6": "0", "default.disable_ipv6": "0", "all.forwarding": "0", "default.forwarding": "0", "all.accept_ra": "0", "default.accept_ra": "0",
                   "default.autoconf": "0", "default.dad_transmits": "0", "default.addr_gen_mode": "1", "default.hop_limit": "64"}
        for key, value in sysctls.items(): command(["ip", "netns", "exec", namespace, "sysctl", "-qw", "net.ipv6.conf." + key + "=" + value])
        command(["ip", "-n", namespace, "link", "set", "lo", "up"])
        command(["ip", "-n", namespace, "tuntap", "add", "dev", tap, "mode", "tap"])
        command(["ip", "-n", namespace, "link", "set", tap, "address", HM.hex(":"), "mtu", "1500"])
        command(["ip", "netns", "exec", namespace, "ethtool", "-K", tap, "tx", "off", "tso", "off", "gso", "off", "gro", "off"])
        command(["ip", "-n", namespace, "link", "set", tap, "up"])
        command(["ip", "-n", namespace, "-6", "addr", "add", "fd00:ab5d::2/64", "dev", tap, "nodad"])
        state = {"namespace": namespace, "identity": expected_namespace,
                 "addresses": json.loads(command(["ip", "-n", namespace, "-j", "-6", "addr", "show", "dev", tap])),
                 "links": json.loads(command(["ip", "-n", namespace, "-j", "link", "show", "dev", tap])),
                 "routes": json.loads(command(["ip", "-n", namespace, "-j", "-6", "route", "show"])),
                 "offloads": command(["ip", "netns", "exec", namespace, "ethtool", "-k", tap]),
                 "sysctls": {key: command(["ip", "netns", "exec", namespace, "sysctl", "-n", "net.ipv6.conf." + key]).strip() for key in sysctls}}
        assert namespace_identity(namespace) == expected_namespace
        fact("LINUX-SETUP.json", validate_setup(state, tap))
        tree = work / "iso-tree" / "boot"; (tree / "grub").mkdir(parents=True)
        (tree / "absd-kernel").write_bytes(buffers["kernel"])
        (tree / "grub" / "grub.cfg").write_bytes(BOOT)
        iso = work / "native-tls-ipv6.iso"
        with (work / "iso-build.log").open("xb") as output:
            subprocess.run(["grub-mkrescue", "-o", str(iso), str(work / "iso-tree")], stdout=output, stderr=subprocess.STDOUT, check=True, timeout=45)
        iso_data = bounded(iso, MAX_ISO); evaluated[iso.name] = digest(iso_data)
        fact("ISO-BINDING.json", iso_binding(iso_data, buffers["kernel"]))
        disk = work / "scratch.img"
        with disk.open("xb") as output: output.truncate(2 << 20)
        peer_log = (work / "peer.log").open("xb"); logs.append(peer_log)
        peer_argv = ["ip", "netns", "exec", namespace, sys.executable, str(ROOT / "scripts/native-tls-ipv6-peer.py"),
                     "--work", str(work), "--case", args.case, "--pki", str(peer_config), "--timeout", str(args.timeout)]
        processes["peer"] = subprocess.Popen(peer_argv, stdout=peer_log, stderr=subprocess.STDOUT, start_new_session=True)
        ready_end = min(deadline, time.monotonic() + 5)
        while not (work / "PEER-READY.json").exists():
            assert processes["peer"].poll() is None and time.monotonic() < ready_end, "peer readiness"
            time.sleep(0.02)
        ready_bytes = bounded(work / "PEER-READY.json", MAX_LOG)
        ready = json.loads(ready_bytes); evaluated["PEER-READY.json"] = digest(ready_bytes)
        assert ready["case"] == args.case and ready["family"] == "AF_INET6" and ready["pid"] == processes["peer"].pid
        assert ready["v6only"] == [1, 1] and ready["listeners"] == [["fd00:ab5d::2", 4443, 0, 0], ["fd00:ab5d::2", 4444, 0, 0]]
        assert ready["canonical_sha256"] == PINS["native-tls-matrix.py"]
        serial, capture = work / "native.serial.log", work / "native.pcap"
        qemu_argv = served_qemu(["ip", "netns", "exec", namespace, actual_tools["qemu"]["path"],
            "-accel", "tcg,thread=single", "-cpu", "Haswell,vendor=GenuineIntel,+rdrand", "-smp", "1", "-m", "256M",
            "-cdrom", str(iso), "-drive", "file=" + str(disk) + ",format=raw,if=ide,index=0", "-display", "none", "-serial", "file:" + str(serial),
            "-no-reboot", "-no-shutdown", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-device", "e1000,netdev=n0,mac=" + GM.hex(":"),
            "-netdev", "tap,id=n0,ifname=" + tap + ",script=no,downscript=no,vnet_hdr=off", "-object", "filter-dump,id=cap0,netdev=n0,file=" + str(capture)])
        marker = original.ReadyMarker(serial, capture); marker.poll(False)
        qemu_log = (work / "qemu.log").open("xb"); logs.append(qemu_log)
        launch_now = time.monotonic()
        assert launch_now < deadline and time.time() + (deadline - launch_now) + 45 < args.lease, "original deadline/lease before guest"
        processes["qemu"] = subprocess.Popen(qemu_argv, stdout=qemu_log, stderr=subprocess.STDOUT, start_new_session=True)
        fact("LAUNCH.json", {"run": args.run_id, "namespace": namespace, "namespace_identity": expected_namespace, "tap": tap,
             "qemu": {"pid": processes["qemu"].pid, "pgid": processes["qemu"].pid, "argv": qemu_argv},
             "peer": {"pid": processes["peer"].pid, "pgid": processes["peer"].pid, "argv": peer_argv},
             "lease_epoch": args.lease, "absolute_host_monotonic_deadline": deadline, "timeout_seconds": args.timeout,
             "recovery": "Observe exact original PGIDs and terminal RESULT/LOCAL-CLEANUP. Do not restart unknown producers. Enclosing approved durable supervisor and provider owner retain lease/fallback authority."})
        while processes["qemu"].poll() is None:
            marker.poll(True)
            assert time.monotonic() < deadline and time.time() < args.lease, "original host deadline/lease"
            assert processes["peer"].poll() is None, "peer died during guest"
            for path, maximum in ((serial, MAX_LOG), (capture, MAX_CAPTURE), (work / "peer.log", MAX_LOG), (work / "qemu.log", MAX_LOG)):
                assert not path.exists() or path.stat().st_size <= maximum
            time.sleep(0.02)
        assert time.monotonic() < deadline and time.time() < args.lease, "late guest completion"
        marker.poll(False); marker.seal(work)
        annotation = bounded(work / "NIC-READY-CAPTURE.json", MAX_LOG)
        evaluated["NIC-READY-CAPTURE.json"] = digest(annotation)
        raw, captured = bounded(serial, MAX_LOG), bounded(capture, MAX_CAPTURE)
        evaluated[serial.name], evaluated[capture.name] = digest(raw), digest(captured)
        native = native_output(raw, processes["qemu"].returncode, args.case, anchor)
        (work / "PEER-STOP").touch(exist_ok=False)
        assert processes["peer"].wait(timeout=4) == 0
        assert time.monotonic() < deadline and time.time() < args.lease, "late peer completion"
        peer_bytes = bounded(work / "PEER-RESULT.json", MAX_LOG)
        peer = json.loads(peer_bytes); evaluated["PEER-RESULT.json"] = digest(peer_bytes)
        assert peer["python_openssl_version"] == ready["openssl"], "OpenSSL observation changed"
        wire = inspect_capture(captured, args.case, peer)
        reasons = accounting.evaluate(work, marker, native["counters"], GM.hex(":"), HM.hex(":"), "tls")
        reason_bytes = bounded(work / "NIC-REASON-ACCOUNTING.json", MAX_LOG)
        assert json.loads(reason_bytes) == reasons
        evaluated["NIC-REASON-ACCOUNTING.json"] = digest(reason_bytes)
        result.update(native=fact("NATIVE-EVIDENCE.json", native), wire=fact("WIRE-EVIDENCE.json", wire),
                      peer=peer, reason_accounting=reasons, validation_unix_time=anchor)
        result["disposition"] = "PASS"
    except BaseException as error:
        result["error"] = repr(error)
    finally:
        outcomes = {}
        for name, process in processes.items():
            try:
                outcomes[name] = stop_owned(process)
                if not outcomes[name]["group_absent"] or outcomes[name]["forced"]:
                    cleanup_errors.append(name + " required forced/unfinished retirement")
            except BaseException as error: cleanup_errors.append(name + " retirement: " + repr(error))
        for stream in logs: stream.close()
        if attempted:
            try:
                assert retire_namespace(namespace, expected_namespace, command), "namespace still present"
            except BaseException as error: cleanup_errors.append("namespace retirement: " + repr(error))
        # Shared mapping survives the return/finally boundary. Cleanup is an
        # evaluated semantic fact, so later content mutation cannot gain PASS.
        fact("LOCAL-CLEANUP.json", {"namespace": namespace, "attempted": attempted, "expected_identity": expected_namespace,
             "processes": outcomes, "errors": cleanup_errors, "disposition": "FAIL" if cleanup_errors else "PASS",
             "limits": "Private single-producer fixture; dev/inode sampled before/after PID query, not atomic stat-to-delete exclusion. External namespace mutators are outside this profile."})
        if cleanup_errors: result["disposition"] = "FAIL"
    result["artifacts"] = seal_artifacts(work, evaluated)
    for name, expected in proof.items(): assert digest(bounded(ROOT / "scripts" / name, MAX_LOG)) == expected
    for row in actual_tools.values(): assert digest(bounded(row["path"], 128 << 20)) == {k: row[k] for k in ("bytes", "sha256")}
    assert command(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).strip() == args.proof_revision
    assert not command(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all"])
    write(work / "RESULT.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=("P01", "P02", "L07"), required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--proof-revision", required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--peer-key", type=Path, required=True)
    parser.add_argument("--lease", type=float, required=True)
    parser.add_argument("--timeout", type=int, default=90)
    args = parser.parse_args()
    try: result = run(args)
    except BaseException as error:
        owned = getattr(args, "_owned_work", None)
        info = owned.stat() if owned is not None and owned.is_dir() else None
        if info is not None and (info.st_dev, info.st_ino) == args._owned_work_identity and not (owned / "RESULT.json").exists():
            write(args.work / "RESULT.json", {"disposition": "FAIL", "error": repr(error), "case": args.case,
                  "limits": "Preflight or final correspondence failure. No positive verdict; consult any exact LAUNCH/LOCAL-CLEANUP and original producer state before recovery."})
        raise
    print(json.dumps({"case": args.case, "disposition": result["disposition"], "result": str(args.work / "RESULT.json")}))
    raise SystemExit(0 if result["disposition"] == "PASS" else 1)


if __name__ == "__main__":
    main()
