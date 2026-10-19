#!/usr/bin/env python3
"""Three private routed IPv6 HTTPS cases with two full Linux link captures.

Source-only until exact product/proof pins and separately built input receipts
exist. No build, key creation or source transfer occurs inside this runner.
Existing on-link oracles and the native TLS engine are unchanged.
"""
import argparse
from collections import Counter
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
PRODUCT = "d1a6ee0b3ec14559804a0b03d4c9d59bdfd857c5"
PRODUCT_TREE = "343838dbc6f80374581d139578b2b58f62d398b1"
KERNEL = "38b4242f4b3e0b05ad13cc21aa0890c1fbe99074"
KERNEL_TREE = "92ef86310444ff218bd00e9d6ea28f04294d0a13"
ARCHIVES = {"platform": (24576000, "dcbd379647f5072f214dc86050abaa64e149cc6794625bb27d7daf90e2d29ff7"),
            "kernel": (12503040, "ba6af4a752eda3939c6c879d9326f4597824a85d886f35469207a3311179b0e3")}
PINS = {
        "served_kernel.py": "e3822e288d37e49a4efff2e30e35178d4c895c944ce43b4b690179565c6d51d2",
        "native-tls-ipv6-matrix.py": "6a277c5815230610fe312b7ad736403a23a47fd57fed44329c52ae87ae574cae",
        "native-tls-ipv6-routed-peer.py": "e75629e357860145053aa297b82d8fa13b79159346daac86c5f7524231580cf6"
}
TLS_LOCK = "cb9ae1c849fe3f86196e2d0a162453b7f437d1e32be633a4ac02888c26dd42d9"
STD = "c35493ccdf6cb87a81767902413ad4487caa1bff401d5ccecb1cce9e7a18760c"
PROFILE = {"family": 6, "scope": 1, "peer": "fd00:ab5d:2::9", "port": 4443,
           "local_port": 7401, "mtu": 1500, "route": "explicit exact-peer /128",
           "parent_invocation_ms": 20000, "client_deadline_ms": 10000,
           "grant_lifetime_ms": 15000, "local": "fd00:ab5d:1::15",
           "router": "fd00:ab5d:1::2", "prefix_len": 64, "profile": "routed"}
GUEST_IP, ROUTER_IP, UPLINK_IP, PEER_IP = "fd00:ab5d:1::15", "fd00:ab5d:1::2", "fd00:ab5d:2::1", "fd00:ab5d:2::9"
GUEST, ROUTER, UPLINK, PEER = (ipaddress.IPv6Address(v).packed for v in (GUEST_IP, ROUTER_IP, UPLINK_IP, PEER_IP))
UPLINK_LL_IP = "fe80::203"
UPLINK_LL = ipaddress.IPv6Address(UPLINK_LL_IP).packed
GUEST_MAC, ROUTER_MAC, UPLINK_MAC, PEER_MAC = (bytes.fromhex(v) for v in ("525400ab5d15", "525500000202", "525500000203", "525500000209"))
GM, HM, HOST = GUEST_MAC, ROUTER_MAC, PEER
MAX_LOG, MAX_CAPTURE, MAX_ELF, MAX_ISO, MAX_WIRE = 8 << 20, 2 << 20, 32 << 20, 64 << 20, 65536
if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
    raise SystemExit("optimized Python refused")


def load(name, filename):
    path = ROOT / "scripts" / filename
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == PINS[filename], "pinned first-party helper changed: " + filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Private module instances; no accepted helper globals/classifier are modified.
tls6 = load("routed_https_onlink_helpers", "native-tls-ipv6-matrix.py")
original, tls = tls6.original, tls6.tls
digest, bounded, write = tls6.digest, tls6.bounded, tls6.write
fields, one, natural = tls6.fields, tls6.one, tls6.natural
elf, iso_binding = tls6.elf, tls6.iso_binding
seal_artifacts, client_hello = tls6.seal_artifacts, tls6.client_hello
BOOT, CHUNK, REQUEST = tls6.BOOT, tls6.CHUNK, tls6.REQUEST
from served_ram import served_qemu


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
    route = one(lines, "TLS IPV6 ROUTE READY ")
    assert route == {"local": "fd00:ab5d:1::15/64", "router": ROUTER_IP, "peer": PEER_IP,
                     "scope": "1", "port": "4443", "path_mtu": "1500", "no_route_denied": "1"}
    assert text.index("TLS IPV6 ROUTE READY ") < text.index("TLS IPV6 RESOURCES label=before ")
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

def actor_binding(item, child, root_der):
    """Bind each native actor to the same source, route, public root and child."""
    assert item["source_revision"] == PRODUCT and item["source_tree"] == PRODUCT_TREE
    assert item["tracked_dirty"] is False and item["untracked_source"] is False
    assert {k: item["root_der"][k] for k in ("bytes", "sha256")} == digest(root_der)
    assert item["transport_profile"] == PROFILE
    assert item["staged_std_source_sha256"] == STD
    assert item["explicit_environment"]["ABSD_TLS_IPV6_PROFILE"] == "routed"
    output = item["outputs"]["https_get_ipv6"]
    assert {k: output[k] for k in ("bytes", "sha256")} == digest(child)
    assert item["explicit_environment"]["ABSD_TLS_IPV6_CLIENT_ELF"] == output["path"]
    assert item["cargo_lock_sha256"] == TLS_LOCK


def build_binding(receipt, buffers, case):
    assert receipt["schema"] == "absd-native-ipv6-routed-tls-build/1" and receipt["case"] == case
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
    assert buffers["child"].count(buffers["root_der"]) == 1, "exact embedded validation root"
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
        actor_binding(item, buffers["child"], buffers["root_der"])
        if role == "service_build":
            assert item["reused_client_receipt"]["sha256"] == digest(buffers["client_build"])["sha256"]
            assert item["service_selectors"] == {"ABSD_TLS_CASE": case, "ABSD_TLS_UNIX_SECONDS": str(anchor)}
            assert item["explicit_environment"]["ABSD_TLS_IPV6_CASE"] == case
            output = item["outputs"]["tls_ipv6_service_probe"]
            assert {k: output[k] for k in ("bytes", "sha256")} == digest(buffers["parent"])
    commands = receipt["commands"]
    assert commands and all(isinstance(c, list) and c and all(isinstance(x, str) for x in c) for c in commands)
    assert any(any(x.endswith("scripts/build-native-tls-fixture.py") for x in c) and {"--ipv6-routed", "--client-only"} <= set(c) for c in commands)
    service = json.loads(buffers["service_build"])
    child_receipt_path = service["reused_client_receipt"]["path"]
    assert Path(child_receipt_path).is_absolute()
    assert any(any(x.endswith("scripts/build-native-tls-fixture.py") for x in c)
               and {"--ipv6-routed", "--service-only", "--client-receipt"} <= set(c)
               and c.index("--client-receipt") + 1 < len(c)
               and c[c.index("--client-receipt") + 1] == child_receipt_path for c in commands)
    external = receipt["external"]
    assert set(external) == {"input", "expected", "parent"}
    assert all({k: external[n][k] for k in ("bytes", "sha256")} == digest(b"") for n in ("input", "expected"))
    assert {k: external["parent"][k] for k in ("bytes", "sha256")} == digest(buffers["parent"])
    required = {"external-build", "EXTERNAL_USER_ELF=" + external["parent"]["path"],
                "EXTERNAL_INPUT=" + external["input"]["path"], "EXTERNAL_EXPECTED=" + external["expected"]["path"]}
    assert receipt["served_kernel_policy"] == {"features": "frame-admission-v0", "helper_sha256": PINS["served_kernel.py"]}
    assert any(required <= set(c) and any(x.endswith("scripts/served_kernel.py") for x in c) for c in commands)
    assert receipt["toolchain_receipt"] == digest(buffers["toolchain"])
    tools = json.loads(buffers["toolchain"])["tools"]
    for name in ("rustc_platform", "cargo_platform", "rustc_kernel", "cargo_kernel", "clang", "llvm_ar", "openssl", "qemu", "ip", "ethtool", "tcpdump", "grub_mkrescue", "python"):
        item = tools[name]
        assert item["bytes"] > 0 and re.fullmatch("[0-9a-f]{64}", item["sha256"]) and item["version"] and Path(item["path"]).is_absolute()
    for name, key in (("clang", "compiler"), ("llvm_ar", "archiver")):
        for role in ("client_build", "service_build"):
            item = json.loads(buffers[role])["native_c_toolchain"][key]
            assert item["sha256"] == tools[name]["sha256"] and item["version"] == tools[name]["version"]
    assert 1 <= len(receipt["logs"]) <= 8
    assert all(item == digest(buffers["log_" + str(i)]) and item["bytes"] > 0 for i, item in enumerate(receipt["logs"]))
    return anchor

def classify(record, link):
    """Exact two-link tuple, ND and MLD envelope; no generic explained traffic."""
    frame = record["frame"]
    row = {k: v for k, v in record.items() if k != "frame"}
    row.update(bytes=len(frame), sha256=digest(frame)["sha256"], source_mac=frame[6:12].hex(":"),
               destination_mac=frame[:6].hex(":"), kind="unexplained", protocol_peer=False,
               filter_refused=False, link=link)
    assert link in ("guest", "peer")
    left, right, lm, rm = (GUEST, ROUTER, GUEST_MAC, ROUTER_MAC) if link == "guest" else (UPLINK, PEER, UPLINK_MAC, PEER_MAC)
    direction = "left-to-right" if frame[6:12] == lm else "right-to-left" if frame[6:12] == rm else "unknown"
    row["direction"] = direction
    if link == "guest":
        row["filter_refused"] = direction == "right-to-left" and not original.accepted(frame[:6], GUEST_MAC)
    if direction == "unknown" or len(frame) < 54 or frame[12:14] != b"\x86\xdd" or frame[14] >> 4 != 6:
        return row
    length = int.from_bytes(frame[18:20], "big")
    if len(frame) != max(60, 54 + length) or any(frame[54 + length:]):
        return row
    source, destination, next_header, hop = frame[22:38], frame[38:54], frame[20], frame[21]
    payload, hbh = frame[54:54 + length], b""
    row.update(source_ip=str(ipaddress.IPv6Address(source)), destination_ip=str(ipaddress.IPv6Address(destination)), hop=hop)
    if next_header == 0:
        if len(payload) < 8 or payload[1] != 0:
            return row
        next_header, hbh, payload = payload[0], payload[:8], payload[8:]
    pseudo = source + destination + struct.pack("!I3xB", len(payload), next_header)
    if next_header == 58 and payload and original.checksum(pseudo + payload) == 0:
        if ((link == "peer" or direction == "right-to-left")
                and original.valid_mld(payload, hbh, source, destination, frame[:6], hop)):
            row.update(kind="linux-mldv2", icmpv6_type=143)
        elif not hbh and hop == 255 and len(payload) == 32 and payload[1] == 0:
            local, remote, local_mac, remote_mac = (left, right, lm, rm) if direction == "left-to-right" else (right, left, rm, lm)
            if link == "peer":
                # Forwarded guest source is not local to the Linux egress.
                # Linux solicits that neighbor from its explicit link-local.
                if payload[0] == 135 and direction == "left-to-right":
                    local = UPLINK_LL
                elif payload[0] == 136 and direction == "right-to-left":
                    remote = UPLINK_LL
            if payload[0] == 135:
                multicast = original.solicited(remote)
                nd = (source == local and payload[4:24] == bytes(4) + remote
                      and destination in (remote, multicast)
                      and frame[:6] == (remote_mac if destination == remote else b"\x33\x33\xff" + remote[-3:])
                      and payload[24:] == b"\x01\x01" + local_mac)
            elif payload[0] == 136:
                flags = int.from_bytes(payload[4:8], "big")
                router = local in (ROUTER, UPLINK)
                nd = (source == local and destination == remote and frame[:6] == remote_mac
                      and payload[8:24] == local and payload[24:] == b"\x02\x01" + local_mac
                      and flags & 0x40000000 != 0 and flags & 0x1fffffff == 0
                      and bool(flags & 0x80000000) == router)
            else:
                nd = False
            if nd:
                row.update(kind="neighbor-discovery", protocol_peer=True, icmpv6_type=payload[0])
    elif next_header == 6 and not hbh and 20 <= len(payload) <= 1460:
        query = source == GUEST and destination == PEER
        answer = source == PEER and destination == GUEST
        expected_direction = "left-to-right" if query else "right-to-left"
        ports = (7401, 4443) if query else (4443, 7401)
        expected_hop = (64 if query else 63) if link == "guest" else (63 if query else 64)
        header = (payload[12] >> 4) * 4
        flags = payload[13]
        if ((query or answer) and direction == expected_direction and frame[:6] == (rm if query else lm)
                and hop == expected_hop and struct.unpack("!HH", payload[:4]) == ports
                and 20 <= header <= len(payload) and payload[12] & 15 == 0
                and flags in (2, 0x12, 0x10, 0x18, 0x11, 0x19, 4, 0x14)
                and payload[18:20] == bytes(2) and original.checksum(pseudo + payload) == 0):
            options, at, mss = payload[20:header], 0, []
            while at < len(options):
                kind = options[at]
                if kind == 0:
                    assert not any(options[at + 1:]), "nonzero TCP option padding"
                    break
                if kind == 1:
                    at += 1
                    continue
                assert at + 2 <= len(options) and options[at + 1] >= 2 and at + options[at + 1] <= len(options), "TCP option length"
                if kind == 2:
                    assert options[at + 1] == 4
                    mss.append(int.from_bytes(options[at + 2:at + 4], "big"))
                at += options[at + 1]
            if flags & 2 and query:
                assert mss == [1440], "explicit1500-byte path requires original guest MSS1440"
            row.update(kind="tcp-query" if query else "tcp-answer", protocol_peer=True,
                       sequence=int.from_bytes(payload[4:8], "big"), acknowledgement=int.from_bytes(payload[8:12], "big"),
                       flags=flags, tcp_hex=payload[header:].hex(), mss=mss,
                       ipv6_hex=frame[14:54 + length].hex())
    return row

def inspect_link_capture(data, case, peer, link):
    records, complete = original.capture_records(data)
    assert complete == len(data), "partial capture suffix"
    assert all(a["timestamp"] <= b["timestamp"] for a, b in zip(records, records[1:])), "nonmonotone capture"
    rows = [classify(r, link) for r in records]
    assert all(r["kind"] in ("linux-mldv2", "neighbor-discovery", "tcp-query", "tcp-answer") for r in rows), "unexplained complete capture frame"
    nd = [{"index": r["index"], "type": r["icmpv6_type"], "direction": "outgoing" if r["direction"] == "left-to-right" else "incoming"} for r in rows if r["kind"] == "neighbor-discovery"]
    tcp = []
    for r, row in zip(records, rows):
        if row["kind"] not in ("tcp-query", "tcp-answer"):
            continue
        frame = r["frame"]; segment = frame[54:54 + int.from_bytes(frame[18:20], "big")]
        end = (segment[12] >> 4) * 4
        flags = segment[13]
        assert flags in (2, 18, 16, 24, 17, 25, 4, 20), "unexpected TCP flag combination"
        assert flags & 0xc0 == 0 and segment[12] & 1 == 0 and flags & 0x20 == 0 and segment[18:20] == bytes(2)
        tcp.append({"index": r["index"], "direction": "outgoing" if row["direction"] == "left-to-right" else "incoming", "seq": int.from_bytes(segment[4:8], "big"),
                    "ack": int.from_bytes(segment[8:12], "big"), "flags": flags, "options": segment[20:end], "data": segment[end:]})
    assert peer["case"]["id"] == case and peer["disposition"] == "PASS" and not peer["errors"]
    assert peer["guard_accepts"] == 0 and peer["transport"] == "Linux routed AF_INET6 TCP / OpenSSL TLS1.3 / kernel ND"
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
    assert any(a["direction"] == "outgoing" and a["type"] == 135 and any(b["direction"] == "incoming" and b["type"] == 136 and a["index"] < b["index"] < gs["index"] for b in nd) for a in nd), "actual selected-link NS/NA before first SYN"
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

def inspect_captures(guest, peer_link, case, peer):
    results = {"guest": inspect_link_capture(guest, case, peer, "guest"),
               "peer": inspect_link_capture(peer_link, case, peer, "peer")}
    for direction, first, second in (("left-to-right", "guest", "peer"), ("right-to-left", "peer", "guest")):
        forwarded = Counter()
        for row in results[first]["census"]:
            if row["direction"] == direction and row["kind"] in ("tcp-query", "tcp-answer"):
                packet = bytearray.fromhex(row["ipv6_hex"])
                assert packet[7] > 1
                packet[7] -= 1
                forwarded[bytes(packet)] += 1
        actual = Counter(bytes.fromhex(row["ipv6_hex"]) for row in results[second]["census"]
                         if row["direction"] == direction and row["kind"] in ("tcp-query", "tcp-answer"))
        assert forwarded == actual, "every complete TCP packet needs exact one-hop counterpart"
    results["scope"] = "Exact explicit1500MTU/MSS1440 topology and two full link captures versus actual Linux socket ciphertext. FIN/ACK only when actually observed; native CLOSE alone is not wire completion. No physical timing or guest/host clock mapping."
    return results


def reason_accounting(capture, serial, annotation_bytes, annotation, fields, census):
    """Accepted first-four destination correspondence applied to explicit routed guest-link census.

    Adapted from the first-party native-ipv6-reason-accounting.py evaluator;
    no original helper globals/source/classifier are modified.
    """
    assert json.loads(annotation_bytes) == annotation, "serialized sidecar differs"
    assert annotation["schema"] == "absd-ipv6-ready-capture-sidecar/1" and annotation["policy"] == original.POLICY
    failures, ambiguities = [], []
    actual = {key: int(fields[key]) for key in ("rx_refused", "rx_missed", "tx_refused", "tx_errors")}
    if any(n < 0 for n in actual.values()):
        failures.append("negative NIC counter")
    if actual["rx_refused"] > 4:
        ambiguities.append("rx_refused exceeds exhaustive first-four diagnostic budget")
    for raw, key in ((capture, "capture"), (serial, "serial")):
        if digest(raw) != {k: annotation[key][k] for k in ("bytes", "sha256")}:
            failures.append(key + " changed after sidecar seal")
    for sample in (annotation["previous_absent"], annotation["observation"]):
        if sample is None:
            continue
        if not 0 <= sample["serial_bytes"] <= len(serial) or digest(serial[:sample["serial_bytes"]])["sha256"] != sample["serial_sha256"]:
            failures.append("serial observation not terminal prefix")
        for key in ("capture_before_serial_read", "capture_after_serial_read"):
            snap = sample[key]
            if not 0 <= snap["bytes"] <= len(capture) or digest(capture[:snap["bytes"]])["sha256"] != snap["sha256"]:
                failures.append("capture observation not terminal prefix")
    if len(list(original.READY.finditer(serial))) != 1:
        failures.append("exactly one NIC-ready line required")
    lines = list(re.finditer(rb"(?m)^NIC RX (?:FILTERED|REFUSED)[^\n]*", serial))
    reasons = []
    for line in lines:
        match = re.fullmatch(rb"NIC RX FILTERED dst=([0-9a-f]{2}(?::[0-9a-f]{2}){5})", line.group())
        if match is None or line.end() == len(serial):
            failures.append("descriptor or malformed refusal reason")
            continue
        destination = match[1].decode()
        if original.accepted(bytes.fromhex(destination.replace(":", "")), GUEST_MAC):
            failures.append("driver refusal names accepted destination")
        candidates = [r["index"] for r in census if r["filter_refused"] and r["destination_mac"] == destination]
        reasons.append({"serial_offset": line.start(), "destination": destination, "compatible_capture_indices": candidates})
    if len(lines) != actual["rx_refused"] or len(reasons) != actual["rx_refused"]:
        failures.append("reason cardinality differs from rx_refused")
    available = Counter(r["destination_mac"] for r in census if r["filter_refused"])
    for destination, count in Counter(r["destination"] for r in reasons).items():
        if available[destination] < count:
            failures.append("insufficient captured destination copies")
    peer_refused = [r["index"] for r in census if r["filter_refused"] and r["protocol_peer"]]
    unexplained = [r["index"] for r in census if r["kind"] == "unexplained"]
    if peer_refused or unexplained:
        failures.append("refused protocol peer or unexplained capture frame")
    if any(actual[k] for k in ("rx_missed", "tx_refused", "tx_errors")):
        failures.append("missed RX or TX refusal/error")
    return {"schema": "absd-ipv6-route-driver-reasons/1", "disposition": "FAIL" if failures or ambiguities else "PASS",
            "inconclusive": bool(ambiguities), "actual": actual, "failures": failures, "ambiguities": ambiguities,
            "driver_reasons": reasons, "protocol_peer_refused": peer_refused, "unexplained": unexplained,
            "policy": original.POLICY, "classification": census, "capture": digest(capture), "serial": digest(serial),
            "annotation": digest(annotation_bytes), "limit": "Exhaustive logged reasons only at rx_refused<=4; captured destinations are compatible, not unique frame/DMA assignments. Readiness and counters are not synchronized. No deduction/tolerance or old strict post-ready PASS."}

def validate_topology(state):
    assert state["transport"] == "Linux kernel IPv6 forwarding and AF_INET6 TCP; HTTPS answers are controlled fixtures"
    assert set(state["namespaces"]) == {"router", "peer"}
    for role, interfaces in (("router", {"r6-tap": (ROUTER_IP, ROUTER_MAC), "r6-out": (UPLINK_IP, UPLINK_MAC)}),
                             ("peer", {"r6-peer": (PEER_IP, PEER_MAC)})):
        row = state["namespaces"][role]
        assert type(row["inode"]) is int and row["inode"] > 0
        assert all(value == ("1" if role == "router" and key.endswith(".forwarding") else "0") for key, value in row["sysctls"].items())
        assert {r["ifname"] for r in row["links"]} == {"lo", *interfaces}
        assert not any(r.get("dst") == "default" for r in row["routes"])
        for device, (address, mac) in interfaces.items():
            found = [r for r in row["addresses"] if r["ifname"] == device]
            links = [r for r in row["links"] if r["ifname"] == device]
            assert len(found) == len(links) == 1
            index = found[0]["ifindex"]
            assert type(index) is int and index > 0 and links[0]["ifindex"] == index
            assert links[0]["address"] == mac.hex(":") and links[0]["mtu"] == 1500 and "UP" in links[0]["flags"]
            actual = found[0]["addr_info"]
            wanted = {address, UPLINK_LL_IP} if role == "router" and device == "r6-out" else {address}
            assert len(actual) == len(wanted) and {item["local"] for item in actual} == wanted
            for item in actual:
                assert item["family"] == "inet6" and item["prefixlen"] == 64
                assert not any(flag in item.get("flags", []) for flag in ("tentative", "dadfailed"))
                if item["local"] == UPLINK_LL_IP:
                    assert item["scope"] == "link"
            assert all(text in row["offloads"][device] for text in ("tx-checksumming: off", "generic-segmentation-offload: off", "generic-receive-offload: off"))
        if role == "peer":
            assert any(r.get("dst") == "fd00:ab5d:1::/64" and r.get("gateway") == UPLINK_IP and r.get("dev") == "r6-peer" for r in row["routes"])
    return state


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

def run(args):
    assert os.geteuid() == 0, "owned disposable Linux VM root required"
    assert re.fullmatch(r"[0-9a-f]{40}", PRODUCT), "product is not sealed"
    assert args.work.is_absolute() and not args.work.resolve().is_relative_to(ROOT)
    assert 30 <= args.timeout <= 120 and args.timeout + 45 < args.lease - time.time() <= 14400
    assert re.fullmatch(r"[0-9a-f]{40}", args.proof_revision)
    uuid.UUID(args.run_id)

    def command(argv, timeout=5):
        value = subprocess.run(argv, check=True, capture_output=True, timeout=timeout)
        assert len(value.stdout) + len(value.stderr) <= MAX_LOG
        return value.stdout.decode()

    assert command(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).strip() == args.proof_revision
    assert not command(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all"])
    source = json.loads(bounded(args.inputs, MAX_LOG))
    expected = {"platform_tar", "kernel_tar", "child", "parent", "kernel", "root_der", "valid_pem", "untrusted_pem", "public_pki", "client_build", "service_build", "toolchain", "receipt"}
    assert expected <= set(source) and set(source) - expected <= {"log_" + str(i) for i in range(8)}
    args.work.mkdir(mode=0o700)
    work = args.work.resolve()
    args._owned_work = work
    st = work.stat()
    args._owned_work_identity = (st.st_dev, st.st_ino)
    inputs = work / "inputs"
    inputs.mkdir()
    buffers, evaluated = {}, {}
    for role, path in source.items():
        assert Path(path).is_absolute() and not Path(path).is_symlink()
        buffers[role] = bounded(path, MAX_ELF if role.endswith("_tar") or role in ("child", "parent", "kernel") else MAX_LOG)
        suffix = ".elf" if role in ("child", "parent", "kernel") else ".tar" if role.endswith("_tar") else ".json" if role in ("receipt", "client_build", "service_build", "public_pki", "toolchain") else ".pem" if role.endswith("_pem") else ".der" if role == "root_der" else ".log"
        destination = inputs / (role + suffix)
        destination.write_bytes(buffers[role])
        evaluated[str(destination.relative_to(work))] = digest(buffers[role])
    anchor = build_binding(json.loads(buffers["receipt"]), buffers, args.case)
    tools, actual_tools = json.loads(buffers["toolchain"])["tools"], {}
    for name, executable in (("qemu", tools["qemu"]["path"]), ("ip", shutil.which("ip")),
                             ("ethtool", shutil.which("ethtool")), ("tcpdump", shutil.which("tcpdump")),
                             ("grub_mkrescue", shutil.which("grub-mkrescue")), ("python", sys.executable)):
        assert executable is not None
        row = digest(bounded(executable, 128 << 20))
        assert row == {k: tools[name][k] for k in ("bytes", "sha256")}, "actual executable differs: " + name
        actual_tools[name] = {"path": str(Path(executable).resolve()), **row}
    assert args.peer_key.is_absolute() and args.peer_key.is_file() and not args.peer_key.is_symlink()
    assert args.peer_key.stat().st_mode & 0o077 == 0 and not args.peer_key.resolve().is_relative_to(work)
    pki = json.loads(buffers["public_pki"])
    pki["leaf_private_key_path"] = str(args.peer_key)
    pki["root_der"]["path"] = str(inputs / "root_der.der")
    for leaf in ("valid", "untrusted"):
        pki["leaf_certificates"][leaf]["path"] = str(inputs / (leaf + "_pem.pem"))
    peer_config = work / "PEER-CONFIG.json"
    evaluated[peer_config.name] = digest(write(peer_config, pki))
    proof = {}
    for name in [*PINS, "native-tls-ipv6-routed-matrix.py"]:
        data = bounded(ROOT / "scripts" / name, MAX_LOG)
        if name in PINS:
            assert digest(data)["sha256"] == PINS[name]
        assert command(["git", "-C", str(ROOT), "show", args.proof_revision + ":scripts/" + name]).encode() == data
        proof[name] = digest(data)
    suffix = uuid.UUID(args.run_id).hex
    namespaces = {"router": "absdtlsr-r-" + suffix, "peer": "absdtlsr-p-" + suffix}
    processes, logs, identities = {}, [], {}
    attempted, cleanup_errors = set(), []
    deadline = time.monotonic() + args.timeout
    result = {"schema": "absd-native-ipv6-routed-tls-proof/1", "run": args.run_id, "case": args.case,
              "disposition": "FAIL", "proof_revision": args.proof_revision, "product": PRODUCT,
              "kernel": KERNEL, "proof_inputs": proof, "evaluated_artifacts": evaluated,
              "unrun": ["DAD, automatic routes, PMTU/PTB, malformed native wire and device/clock faults",
                        "public Internet policy, physical timing, live generation/hardware transfer"],
              "limits": "One explicit /128 route and exact-peer capability on a1500-byte path. No native CLOSE-to-wire-completion inference; FIN/ACK must be actually captured. Public fixture roots/time are test inputs, not deployment trust/time policy."}

    def fact(name, value):
        data = write(work / name, value)
        evaluated[name] = digest(data)
        return value

    def left(maximum):
        for path, bound in ((work / "native.serial.log", MAX_LOG), (work / "guest-link.pcap", MAX_CAPTURE),
                            (work / "peer-link.pcap", MAX_CAPTURE), (work / "peer.log", MAX_LOG),
                            (work / "qemu.log", MAX_LOG), (work / "capture.log", MAX_LOG)):
            assert not path.exists() or path.stat().st_size <= bound, "output bound: " + path.name
        remaining = min(deadline - time.monotonic(), args.lease - time.time() - 45)
        assert remaining > 0, "original case/lease deadline"
        return min(maximum, remaining)

    def checked(argv):
        return command(argv, left(5))

    def ip(role, argv):
        return checked(["ip", "-n", namespaces[role], *argv])

    def net(role, argv):
        return checked(["ip", "netns", "exec", namespaces[role], *argv])

    def start(name, argv):
        log = (work / (name + ".log")).open("xb")
        logs.append(log)
        env = {k: v for k, v in os.environ.items() if k not in ("PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONINSPECT", "SSLKEYLOGFILE", "LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "NOTIFY_SOCKET")}
        process = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True, env=env)
        processes[name] = process
        return process

    settings = {"net.ipv6.conf.all.disable_ipv6": "0", "net.ipv6.conf.default.disable_ipv6": "0",
                "net.ipv6.conf.all.forwarding": "0", "net.ipv6.conf.default.forwarding": "0",
                "net.ipv6.conf.all.accept_ra": "0", "net.ipv6.conf.default.accept_ra": "0",
                "net.ipv6.conf.all.autoconf": "0", "net.ipv6.conf.default.autoconf": "0",
                "net.ipv6.conf.default.accept_dad": "0"}

    def topology():
        state = {"transport": "Linux kernel IPv6 forwarding and AF_INET6 TCP; HTTPS answers are controlled fixtures",
                 "kernel": list(os.uname()), "namespaces": {}}
        for role, devices in (("router", ("r6-tap", "r6-out")), ("peer", ("r6-peer",))):
            identity = namespace_identity(namespaces[role])
            assert identity == identities[role], "namespace identity changed"
            state["namespaces"][role] = {"name": namespaces[role], **identity,
                "sysctls": {key: net(role, ["sysctl", "-n", key]).strip() for key in settings},
                "addresses": json.loads(ip(role, ["-j", "-6", "addr", "show"])),
                "links": json.loads(ip(role, ["-j", "link", "show"])),
                "routes": json.loads(ip(role, ["-j", "-6", "route", "show"])),
                "neighbors": json.loads(ip(role, ["-j", "-6", "neigh", "show"])),
                "offloads": {dev: net(role, ["ethtool", "-k", dev]) for dev in devices},
                "TCP_sockets": net(role, ["ss", "-H", "-a", "-n", "-t"])}
        return validate_topology(state)

    try:
        fact("CASE.json", {"run": args.run_id, "case": args.case, "product": PRODUCT, "profile": PROFILE,
                           "DAD": "UNRUN", "canonical_TLS_oracles": "Unchanged engine/trust/name/time,10s child/15s grant/20s invocation"})
        fact("ACTUAL-TOOLS.json", actual_tools)
        existing = [row.split()[0] for row in checked(["ip", "netns", "list"]).splitlines()]
        assert not any(ns in existing for ns in namespaces.values())
        for role, ns in namespaces.items():
            attempted.add(role)
            checked(["ip", "netns", "add", ns])
            identities[role] = namespace_identity(ns)
            fact("NAMESPACE-" + role.upper() + "-CREATED.json", {"name": ns, **identities[role]})
            for key, value in settings.items():
                net(role, ["sysctl", "-qw", key + "=" + ("1" if role == "router" and key.endswith(".forwarding") else value)])
            net(role, ["sysctl", "-qw", "net.ipv6.conf.default.hop_limit=64"])
            ip(role, ["link", "set", "lo", "up"])
        ip("router", ["tuntap", "add", "dev", "r6-tap", "mode", "tap"])
        ip("router", ["link", "add", "r6-out", "type", "veth", "peer", "name", "r6-peer", "netns", namespaces["peer"]])
        for role, dev, mac, address in (("router", "r6-tap", ROUTER_MAC, ROUTER_IP),
                                       ("router", "r6-out", UPLINK_MAC, UPLINK_IP), ("peer", "r6-peer", PEER_MAC, PEER_IP)):
            for argv in (["link", "set", dev, "address", mac.hex(":")], ["link", "set", dev, "mtu", "1500"],
                         ["link", "set", dev, "addrgenmode", "none"], ["link", "set", dev, "up"],
                         ["-6", "addr", "add", address + "/64", "dev", dev, "nodad"]):
                ip(role, argv)
            net(role, ["ethtool", "-K", dev, "tx", "off", "tso", "off", "gso", "off", "gro", "off"])
        ip("router", ["-6", "addr", "add", UPLINK_LL_IP + "/64", "dev", "r6-out", "nodad"])
        ip("peer", ["-6", "route", "add", "fd00:ab5d:1::/64", "via", UPLINK_IP, "dev", "r6-peer"])
        fact("LINUX-TOPOLOGY-BEFORE.json", topology())
        tree = work / "iso-tree" / "boot"
        (tree / "grub").mkdir(parents=True)
        (tree / "absd-kernel").write_bytes(buffers["kernel"])
        (tree / "grub" / "grub.cfg").write_bytes(BOOT)
        iso, disk = work / "native-tls-ipv6-routed.iso", work / "scratch.img"
        with (work / "iso-build.log").open("xb") as log:
            subprocess.run(["grub-mkrescue", "-o", str(iso), str(work / "iso-tree")], stdout=log,
                           stderr=subprocess.STDOUT, timeout=left(45), check=True)
        iso_bytes = bounded(iso, MAX_ISO)
        evaluated[iso.name] = digest(iso_bytes)
        fact("ISO-BINDING.json", iso_binding(iso_bytes, buffers["kernel"]))
        with disk.open("xb") as stream:
            stream.truncate(2 << 20)
        peer_argv = ["ip", "netns", "exec", namespaces["peer"], actual_tools["python"]["path"], "-I", "-B",
                     str(ROOT / "scripts/native-tls-ipv6-routed-peer.py"), "--work", str(work), "--case", args.case,
                     "--pki", str(peer_config), "--timeout", str(args.timeout)]
        peer_process = start("peer", peer_argv)
        ready_end = time.monotonic() + left(5)
        while not (work / "PEER-READY.json").exists():
            assert peer_process.poll() is None and time.monotonic() < ready_end
            left(1)
            time.sleep(0.01)
        ready_bytes = bounded(work / "PEER-READY.json", MAX_LOG)
        ready = json.loads(ready_bytes)
        evaluated["PEER-READY.json"] = digest(ready_bytes)
        assert ready["case"] == args.case and ready["pid"] == peer_process.pid and ready["family"] == "AF_INET6"
        assert ready["listeners"] == [[PEER_IP, 4443, 0, 0], [PEER_IP, 4444, 0, 0]] and ready["v6only"] == [1, 1]
        assert ready["canonical_sha256"] == tls6.PINS["native-tls-matrix.py"]
        peer_capture = work / "peer-link.pcap"
        capture_argv = ["ip", "netns", "exec", namespaces["peer"], actual_tools["tcpdump"]["path"],
                                            "--immediate-mode", "-n", "-U", "-p", "-s", "1514", "-i", "r6-peer", "-w", str(peer_capture)]
        capture_process = start("capture", capture_argv)
        ready_end = time.monotonic() + left(5)
        while not peer_capture.exists() or peer_capture.stat().st_size < 24:
            assert capture_process.poll() is None and time.monotonic() < ready_end
            left(1)
            time.sleep(0.01)
        serial, guest_capture = work / "native.serial.log", work / "guest-link.pcap"
        marker = original.ReadyMarker(serial, guest_capture)
        marker.poll(False)
        qemu_argv = served_qemu(["ip", "netns", "exec", namespaces["router"], actual_tools["qemu"]["path"],
            "-accel", "tcg,thread=single", "-cpu", "Haswell,vendor=GenuineIntel,+rdrand", "-smp", "1", "-m", "256M",
            "-cdrom", str(iso), "-drive", "file=" + str(disk) + ",format=raw,if=ide,index=0", "-display", "none",
            "-serial", "file:" + str(serial), "-no-reboot", "-no-shutdown", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
            "-device", "e1000,netdev=n0,mac=" + GM.hex(":"), "-netdev", "tap,id=n0,ifname=r6-tap,script=no,downscript=no,vnet_hdr=off",
            "-object", "filter-dump,id=cap0,netdev=n0,file=" + str(guest_capture)])
        left(1)
        qemu = start("qemu", qemu_argv)
        fact("LAUNCH.json", {"run": args.run_id, "namespaces": namespaces, "namespace_identities": identities,
             "qemu": {"pid": qemu.pid, "pgid": qemu.pid, "argv": qemu_argv},
             "peer": {"pid": peer_process.pid, "pgid": peer_process.pid, "argv": peer_argv},
             "capture": {"pid": capture_process.pid, "pgid": capture_process.pid, "argv": capture_argv},
             "lease_epoch": args.lease, "absolute_host_monotonic_deadline": deadline, "timeout_seconds": args.timeout,
             "recovery": "Inspect exact original processes, terminal and cleanup under enclosing durable producer. Never restart unknown runs."})
        while qemu.poll() is None:
            marker.poll(True)
            left(1)
            assert peer_process.poll() is None and capture_process.poll() is None
            time.sleep(0.01)
        left(1)
        marker.poll(False)
        annotation = marker.seal(work)
        annotation_bytes = bounded(work / "NIC-READY-CAPTURE.json", MAX_LOG)
        evaluated["NIC-READY-CAPTURE.json"] = digest(annotation_bytes)
        raw = bounded(serial, MAX_LOG)
        native = native_output(raw, qemu.returncode, args.case, anchor)
        (work / "PEER-STOP").touch(exist_ok=False)
        assert peer_process.wait(timeout=left(4)) == 0
        # tcpdump handles SIGINT by flushing its capture; this planned stop is
        # distinct from the cleanup path's forced termination of a failed run.
        os.killpg(capture_process.pid, signal.SIGINT)
        assert capture_process.wait(timeout=left(3)) == 0 and not group_live(capture_process.pid)
        fact("CAPTURE-TERMINAL.json", {"status": 0, "group_absent": True, "planned_signal": "SIGINT"})
        capture_log = bounded(work / "capture.log", MAX_LOG).decode()
        dropped = re.findall(r"(?m)^([0-9]+) packets dropped by kernel$", capture_log)
        assert dropped == ["0"], "capture drop count absent/nonzero"
        peer_bytes = bounded(work / "PEER-RESULT.json", MAX_LOG)
        peer = json.loads(peer_bytes)
        assert peer["python_openssl_version"] == ready["openssl"]
        guest_bytes, peer_link_bytes = bounded(guest_capture, MAX_CAPTURE), bounded(peer_capture, MAX_CAPTURE)
        for name, data in ((serial.name, raw), (guest_capture.name, guest_bytes), (peer_capture.name, peer_link_bytes), ("PEER-RESULT.json", peer_bytes)):
            evaluated[name] = digest(data)
        wire = inspect_captures(guest_bytes, peer_link_bytes, args.case, peer)
        reasons = reason_accounting(guest_bytes, raw, annotation_bytes, json.loads(annotation_bytes), native["counters"], wire["guest"]["census"])
        assert reasons["disposition"] == "PASS"
        result.update(native=fact("NATIVE-EVIDENCE.json", native), wire=fact("WIRE-EVIDENCE.json", wire),
                      peer=peer, reason_accounting=fact("NIC-REASON-ACCOUNTING.json", reasons), validation_unix_time=anchor)
        fact("LINUX-TOPOLOGY-AFTER.json", topology())
        left(1)
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
            except BaseException as error:
                cleanup_errors.append(name + " retirement: " + repr(error))
        for log in logs:
            log.close()
        absent = {}
        for role in ("peer", "router"):
            if role not in attempted:
                continue
            try:
                absent[role] = retire_namespace(namespaces[role], identities.get(role), command)
                assert absent[role]
            except BaseException as error:
                cleanup_errors.append(role + " namespace retirement: " + repr(error))
        fact("LOCAL-CLEANUP.json", {"namespaces": namespaces, "attempted": sorted(attempted), "expected_identities": identities,
             "namespace_absent": absent, "processes": outcomes, "errors": cleanup_errors,
             "disposition": "FAIL" if cleanup_errors else "PASS",
             "limits": "Private single producer; identity observations are not atomic exclusion of other namespace mutators."})
        if cleanup_errors:
            result["disposition"] = "FAIL"
    result["artifacts"] = seal_artifacts(work, evaluated)
    for name, expected in proof.items():
        assert digest(bounded(ROOT / "scripts" / name, MAX_LOG)) == expected
    for row in actual_tools.values():
        assert digest(bounded(row["path"], 128 << 20)) == {k: row[k] for k in ("bytes", "sha256")}
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
    try:
        result = run(args)
    except BaseException as error:
        owned = getattr(args, "_owned_work", None)
        info = owned.stat() if owned is not None and owned.is_dir() else None
        if info is not None and (info.st_dev, info.st_ino) == args._owned_work_identity and not (owned / "RESULT.json").exists():
            write(owned / "RESULT.json", {"disposition": "FAIL", "error": repr(error), "case": args.case,
                  "limits": "Preflight/final correspondence failed. Reconcile original processes and LOCAL-CLEANUP; never restart an unknown producer."})
        raise
    print(json.dumps({"case": args.case, "disposition": result["disposition"], "result": str(args.work / "RESULT.json")}))
    raise SystemExit(0 if result["disposition"] == "PASS" else 1)


if __name__ == "__main__":
    main()

