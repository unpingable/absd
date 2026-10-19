#!/usr/bin/env python3
"""Distinct immutable 1280-MTU routed IPv6 paired UDP/TCP DNS proof.

Derived from the existing fixed 1500-MTU proof; that runner remains unchanged.

No source compilation, packet injection or public peer. Run only on the separately admitted disposable Linux resource.
"""
import argparse
from collections import Counter
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import struct
import subprocess
import time
import types
import uuid

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from served_ram import served_qemu

if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
    raise SystemExit("native-ipv6-route: optimized Python refused")
ROOT = Path(__file__).resolve().parent.parent
PRODUCT = "86be29e40c46f7f76f95a92730e9d16cfa955c6b"
PRODUCT_TREE = "be34924522431f080896f90c750f4977e4136281"
PRODUCT_ARCHIVE = "83f53f97d9deb0bbecaa7f40f49f84eaa41365c7bb51c3402af834f2af0d4d99"
PRODUCT_BYTES = 24934400
KERNEL = "38b4242f4b3e0b05ad13cc21aa0890c1fbe99074"
KERNEL_TREE = "92ef86310444ff218bd00e9d6ea28f04294d0a13"
KERNEL_ARCHIVE = "ba6af4a752eda3939c6c879d9326f4597824a85d886f35469207a3311179b0e3"
KERNEL_BYTES = 12503040
SERVED_KERNEL_HASH = "e3822e288d37e49a4efff2e30e35178d4c895c944ce43b4b690179565c6d51d2"
HELPER = "native-ipv6-accounting.py"
HELPER_HASH = "22d5f091c23c0d436be538d3695b43b3ed52b48ec5b4b30668be215a08001ad3"
DNS_HELPER = "native-ipv6-peer.py"
DNS_HASH = "c72d3146d9eb26850208ce5cd85744209ee41af140fa878b523da73b4d90da37"
GUEST_IP, ROUTER_IP, UPLINK_IP, PEER_IP = "fd00:ab5d:1::15", "fd00:ab5d:1::2", "fd00:ab5d:2::1", "fd00:ab5d:2::9"
GUEST, ROUTER, UPLINK, PEER = (ipaddress.IPv6Address(s).packed for s in (GUEST_IP, ROUTER_IP, UPLINK_IP, PEER_IP))
UPLINK_LL_IP = "fe80::203"
UPLINK_LL = ipaddress.IPv6Address(UPLINK_LL_IP).packed
GUEST_MAC, ROUTER_MAC, UPLINK_MAC, PEER_MAC = (bytes.fromhex(s) for s in ("525400ab5d15", "525500000202", "525500000203", "525500000209"))
MAX_ELF, MAX_ISO, MAX_LOG, MAX_CAPTURE = 64 << 20, 128 << 20, 8 << 20, 2 << 20
IP_MTU = 1280
CASE = "routed-tcp-dns-mtu1280"
UNRUN = [
    "native malformed IPv6/ND frames, wrong-peer wire injection, child kill, device/clock faults",
    "PMTU/ICMPv6 PTB, automatic routes, RA/SLAAC/DHCPv6 and DAD in this static profile",
    "hardware/live generation transfer, physical RTT or cross-domain clock mapping",
]


def bounded(path, maximum):
    with Path(path).open("rb") as stream:
        data = stream.read(maximum + 1)
    assert len(data) <= maximum, "byte bound: " + str(path)
    return data


def digest(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def identity(path, data):
    return {"path": str(Path(path).resolve()), **digest(data)}


def write(path, value):
    data = (json.dumps(value, indent=2) + "\n").encode()
    with Path(path).open("xb") as stream:
        stream.write(data)
    return data


# Load the exact accepted helper buffer once, without rewriting its source,
# globals, profiles or classifier. Guest execution requires a dedicated VM.
_helper_path = ROOT / "scripts" / HELPER
_helper_bytes = bounded(_helper_path, MAX_LOG)
assert digest(_helper_bytes)["sha256"] == HELPER_HASH, "accepted helper changed"
original = types.ModuleType("route_accepted_accounting")
original.__file__ = str(_helper_path)
exec(compile(_helper_bytes, str(_helper_path), "exec"), original.__dict__)
_dns_path = ROOT / "scripts" / DNS_HELPER
_dns_bytes = bounded(_dns_path, MAX_LOG)
assert digest(_dns_bytes)["sha256"] == DNS_HASH, "accepted DNS codec changed"
dns = types.ModuleType("route_dns_codec")
dns.__file__ = str(_dns_path)
exec(compile(_dns_bytes, str(_dns_path), "exec"), dns.__dict__)
_served_path = ROOT / "scripts" / "served_kernel.py"
_served_bytes = bounded(_served_path, MAX_LOG)
assert digest(_served_bytes)["sha256"] == SERVED_KERNEL_HASH, "served kernel policy helper changed"


def elf(data):
    assert len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01"
    assert struct.unpack_from("<H", data, 18)[0] == 62, "x86_64 ELF required"
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    assert size == 56 and 0 < count <= 128 and offset + size * count <= len(data)
    loads = 0
    for at in range(count):
        kind, _, start, _, _, length, memory, _ = struct.unpack_from("<IIQQQQQQ", data, offset + at * size)
        if kind == 1:
            assert start + length <= len(data) and length <= memory
            loads += 1
    assert loads, "no bounded ELF LOAD segment"


def build_binding(receipt, buffers):
    assert receipt["schema"] == "absd-native-ipv6-mtu1280-build/1"
    for key, rev, tree, archive, size in (
        ("platform", PRODUCT, PRODUCT_TREE, PRODUCT_ARCHIVE, PRODUCT_BYTES),
        ("kernel", KERNEL, KERNEL_TREE, KERNEL_ARCHIVE, KERNEL_BYTES),
    ):
        item = receipt[key]
        assert item["revision"] == rev and item["tree"] == tree and item["clean"] is True
        assert {k: item["archive"][k] for k in ("bytes", "sha256")} == {"bytes": size, "sha256": archive}
    assert receipt["ip_mtu"] == IP_MTU, "immutable build MTU binding"
    commands = receipt["commands"]
    assert commands and all(isinstance(c, list) and c and all(isinstance(x, str) for x in c) for c in commands)
    assert any(any(x.endswith("scripts/build-native-ipv6-routed-tcp.sh") for x in c) for c in commands)
    assert any("ABSD_ROUTE6_TCP_IP_MTU=1280" in c
               and any(x.endswith("scripts/build-native-ipv6-routed-tcp.sh") for x in c)
               for c in commands), "explicit owner build selector missing"
    external = receipt["external"]
    assert set(external) == {"input", "expected", "parent"}
    empty = digest(b"")
    assert all({k: external[n][k] for k in empty} == empty for n in ("input", "expected"))
    assert {k: external["parent"][k] for k in empty} == digest(buffers["parent"])
    required = {"external-build", "EXTERNAL_USER_ELF=" + external["parent"]["path"],
                "EXTERNAL_INPUT=" + external["input"]["path"], "EXTERNAL_EXPECTED=" + external["expected"]["path"]}
    assert receipt["served_kernel_policy"] == {"features": "frame-admission-v0", "helper_sha256": SERVED_KERNEL_HASH}
    assert any(required <= set(command) and any(x.endswith("scripts/served_kernel.py") for x in command)
               for command in commands), "served external build/empty-input binding"
    assert 1 <= len(receipt["logs"]) <= 8
    for item in [receipt["toolchain_receipt"], *receipt["logs"]]:
        assert 0 < item["bytes"] <= MAX_LOG and re.fullmatch("[0-9a-f]{64}", item["sha256"])
    for key, data in buffers.items():
        elf(data)
        assert receipt["outputs"][key] == digest(data), "exact build output: " + key
    assert buffers["parent"].count(buffers["child"]) == 1
    assert buffers["kernel"].count(buffers["parent"]) == buffers["kernel"].count(buffers["child"]) == 1


def iso_binding(data, kernel, boot):
    """Read the actual ISO9660/Rock Ridge critical file extents, without mounting."""
    pvd = data[16 * 2048:17 * 2048]
    assert len(pvd) == 2048 and pvd[:7] == b"\x01CD001\x01"
    assert struct.unpack_from("<H", pvd, 128)[0] == struct.unpack_from(">H", pvd, 130)[0] == 2048

    def contents(record):
        assert len(record) >= 34
        at, length = struct.unpack_from("<I", record, 2)[0], struct.unpack_from("<I", record, 10)[0]
        assert at == struct.unpack_from(">I", record, 6)[0] and length == struct.unpack_from(">I", record, 14)[0]
        assert at * 2048 + length <= len(data)
        return data[at * 2048:at * 2048 + length]

    def child(directory, wanted):
        assert directory[25] & 2
        raw, at, found = contents(directory), 0, []
        while at < len(raw):
            size = raw[at]
            if not size:
                at = (at // 2048 + 1) * 2048
                continue
            record = raw[at:at + size]
            assert len(record) == size and size >= 34
            at += size
            n = record[32]
            name = record[33:33 + n].split(b";", 1)[0].lower()
            extra = 33 + n + (n % 2 == 0)
            while extra + 4 <= len(record):
                kind, length = record[extra:extra + 2], record[extra + 2]
                assert length >= 4 and extra + length <= len(record)
                if kind == b"NM" and record[extra + 4] == 0:
                    name = record[extra + 5:extra + length]
                extra += length
            if name == wanted:
                found.append(record)
        assert len(found) == 1, "ISO critical directory/file missing or duplicated"
        return found[0]

    root = pvd[156:156 + pvd[156]]
    directory = child(root, b"boot")
    image = child(directory, b"absd-kernel")
    config = child(child(directory, b"grub"), b"grub.cfg")
    assert not image[25] & 2 and not config[25] & 2
    assert contents(image) == kernel and contents(config) == boot and data.count(kernel) == 1
    return {"kernel": digest(contents(image)), "grub_config": digest(contents(config))}


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
    if 40 + length > IP_MTU or len(frame) != max(60, 54 + length) or any(frame[54 + length:]):
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
        if original.valid_mld(payload, hbh, source, destination, frame[:6], hop):
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
    elif next_header == 17 and not hbh and 8 <= len(payload) <= 1240:
        query = source == GUEST and destination == PEER
        answer = source == PEER and destination == GUEST
        expected_direction = "left-to-right" if query else "right-to-left"
        ports = (7002, 42010) if query else (42010, 7002)
        remote_mac = rm if query else lm
        expected_hop = (64 if query else 63) if link == "guest" else (63 if query else 64)
        if ((query or answer) and direction == expected_direction and frame[:6] == remote_mac
                and hop == expected_hop and payload[6:8] != bytes(2)
                and struct.unpack("!HHH", payload[:6]) == (*ports, len(payload))
                and original.checksum(pseudo + payload) == 0):
            row.update(kind="dns-query" if query else "dns-answer", protocol_peer=True,
                       dns_hex=payload[8:].hex(), ipv6_hex=frame[14:54 + length].hex())
    elif next_header == 6 and not hbh and 20 <= len(payload) <= 1240:
        query = source == GUEST and destination == PEER
        answer = source == PEER and destination == GUEST
        expected_direction = "left-to-right" if query else "right-to-left"
        ports = (7003, 42010) if query else (42010, 7003)
        expected_hop = (64 if query else 63) if link == "guest" else (63 if query else 64)
        header = (payload[12] >> 4) * 4
        flags = payload[13]
        if ((query or answer) and direction == expected_direction and frame[:6] == (rm if query else lm)
                and hop == expected_hop and struct.unpack("!HH", payload[:4]) == ports
                and 20 <= header <= len(payload) and payload[12] & 15 == 0
                and flags in (2, 0x12, 0x10, 0x18, 0x11, 0x19)
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
                assert mss == [1220], "explicit 1280-byte path requires guest MSS1220"
            row.update(kind="tcp-query" if query else "tcp-answer", protocol_peer=True,
                       sequence=int.from_bytes(payload[4:8], "big"), acknowledgement=int.from_bytes(payload[8:12], "big"),
                       flags=flags, tcp_hex=payload[header:].hex(), mss=mss,
                       ipv6_hex=frame[14:54 + length].hex())
    return row


def truncated(query):
    dns.question(query)
    answer = bytearray(query)
    answer[2:4] = b'\x83\x80'
    answer[6:12] = bytes(6)
    return bytes(answer)


def stream_messages(raw):
    messages, at = [], 0
    while at < len(raw):
        assert at + 2 <= len(raw), 'incomplete DNS stream prefix'
        n = int.from_bytes(raw[at:at+2], 'big')
        assert 12 <= n <= 1232 and at + 2 + n <= len(raw), 'incomplete/oversize DNS stream message'
        messages.append(raw[at+2:at+2+n])
        at += 2 + n
    assert len(messages) == 2, 'exactly two DNS stream messages required'
    return messages


def peer_result(data):
    value = json.loads(data)
    assert value['schema_version'] == 1 and value['disposition'] == 'PASS' and value['errors'] == []
    assert type(value['pid']) is int and value['pid'] > 0
    assert value['bind'] == PEER_IP and value['port'] == 42010 and value['forbidden_port'] == 42011
    assert value['codec_sha256'] == DNS_HASH and value['stop_reason'] == 'PEER-STOP'
    assert value['limits'] == {'dns_bytes': 1232, 'stream_bytes': 4096, 'io_events': 128}
    records = value['records']
    assert len(records) == 4
    selected = [('UDP', 'a.example', 1), ('TCP', 'a.example', 1), ('UDP', 'aaaa.example', 28), ('TCP', 'aaaa.example', 28)]
    questions = {}
    for row, wanted in zip(records, selected):
        assert (row['transport'], row['name'], row['kind']) == wanted
        assert row['port'] == 42010 and row['source'] == [GUEST_IP, 7002 if row['transport'] == 'UDP' else 7003, 0, 0]
        query, answer = bytes.fromhex(row['query_hex']), bytes.fromhex(row['answer_hex'])
        assert dns.question(query) == wanted[1:]
        if row['transport'] == 'UDP':
            assert answer == truncated(query)
            questions[wanted[1:]] = query
        else:
            assert query == questions[wanted[1:]] and answer == dns.answer(query)
    tcp = value['tcp']
    assert tcp['source'] == [GUEST_IP, 7003, 0, 0] and tcp['connections'] == 1
    assert tcp['read_eof'] is True and tcp['write_shutdown'] is True and tcp['closed'] is True
    assert tcp['pending_hex'] == tcp['unsent_hex'] == ''
    for stem, field in (('received', 'query_hex'), ('sent', 'answer_hex')):
        raw = bytes.fromhex(tcp[stem + '_hex'])
        assert len(raw) <= 4096 and digest(raw)['sha256'] == tcp[stem + '_sha256']
        messages = stream_messages(raw)
        expected = [bytes.fromhex(r[field]) for r in records if r['transport'] == 'TCP']
        assert messages == expected and tcp[stem + '_frames'] == [b.hex() for b in expected]
    io = value['io']
    assert 9 <= len(io) <= 128
    assert all(type(r['monotonic_ns']) is int and r['monotonic_ns'] > 0 and type(r['realtime_ns']) is int and r['realtime_ns'] > 0 for r in io)
    assert all(a['monotonic_ns'] <= b['monotonic_ns'] for a,b in zip(io,io[1:]))
    kinds = Counter(r['event'] for r in io)
    assert set(kinds) == {'udp-recv','udp-send','tcp-accept','tcp-recv','tcp-send','tcp-write-shutdown','tcp-close'}
    assert all(kinds[n] == count for n,count in [('udp-recv',2),('udp-send',2),('tcp-accept',1),('tcp-write-shutdown',1),('tcp-close',1)])
    for event, field in [('udp-recv','query_hex'),('udp-send','answer_hex')]:
        observed = [r for r in io if r['event'] == event]
        assert [r['hex'] for r in observed] == [r[field] for r in records if r['transport']=='UDP']
        for r in observed:
            assert r['port'] == 42010
            if event == 'udp-recv':
                assert r['source'] == [GUEST_IP,7002,0,0] and r['flags'] == 0
            else:
                assert r['destination'] == [GUEST_IP,7002,0,0] and r['requested'] == r['count'] == len(bytes.fromhex(r['hex']))
    accepted = next(r for r in io if r['event']=='tcp-accept')
    assert accepted['port'] == 42010 and accepted['source'] == [GUEST_IP,7003,0,0]
    for event, stem in [('tcp-recv','received'),('tcp-send','sent')]:
        events = [r for r in io if r['event']==event]
        assert ''.join(r['hex'] for r in events) == tcp[stem+'_hex']
        assert all(r['count'] == len(bytes.fromhex(r['hex'])) for r in events)
        if event == 'tcp-recv':
            assert sum(r['count']==0 for r in events) == 1 and events[-1]['count'] == 0
        else:
            assert all(0 < r['count'] <= r['requested'] for r in events)
    accepted_at = next(at for at,r in enumerate(io) if r['event']=='tcp-accept')
    eof_at = next(at for at,r in enumerate(io) if r['event']=='tcp-recv' and r['count']==0)
    shutdown_at = next(at for at,r in enumerate(io) if r['event']=='tcp-write-shutdown')
    close_at = next(at for at,r in enumerate(io) if r['event']=='tcp-close')
    assert accepted_at < eof_at < shutdown_at < close_at
    assert all(accepted_at < at < eof_at for at,r in enumerate(io) if r['event']=='tcp-send' or r['event']=='tcp-recv' and r['count']>0)
    pending = []
    for r in io:
        if r['event']=='udp-recv':pending.append(truncated(bytes.fromhex(r['hex'])).hex())
        elif r['event']=='udp-send':assert pending and pending.pop(0)==r['hex']
    assert not pending
    return value


def reassemble_tcp(rows, kind):
    packets = [r for r in rows if r['kind'] == kind]
    syn = [r for r in packets if r['flags'] & 2]
    assert syn and len({r['sequence'] for r in syn}) == 1, 'one initial TCP sequence per direction'
    assert all(not bytes.fromhex(r['tcp_hex']) for r in syn)
    if kind == 'tcp-query':
        assert all(r['flags'] == 2 and r['acknowledgement'] == 0 for r in syn)
    else:
        assert all(r['flags'] == 0x12 for r in syn)
    initial = syn[0]['sequence']
    data, fin = {}, set()
    for row in packets:
        if row['flags'] & 2:
            continue
        offset = (row['sequence'] - initial - 1) & 0xffffffff
        body = bytes.fromhex(row['tcp_hex'])
        assert offset <= 4096 and offset + len(body) <= 4096, 'TCP sequence outside bounded connection'
        for at, byte in enumerate(body, offset):
            assert at not in data or data[at] == byte, 'conflicting retransmission bytes'
            data[at] = byte
        if row['flags'] & 1:
            fin.add(offset + len(body))
    assert data and set(data) == set(range(max(data) + 1)), 'gapped DNS stream'
    raw = bytes(data[n] for n in range(len(data)))
    assert fin == {len(raw)}, 'exact EOF after complete stream required'
    return raw, initial, packets


def inspect(guest_capture, peer_capture, peer):
    captures = {}
    records = peer['records']
    udp = [r for r in records if r['transport'] == 'UDP']
    expected_query = Counter(r['query_hex'] for r in udp)
    expected_answer = Counter(r['answer_hex'] for r in udp)
    for link, data in (('guest', guest_capture), ('peer', peer_capture)):
        packets, complete = original.capture_records(data)
        assert complete == len(data) and packets, 'empty/incomplete link capture'
        assert all(a['timestamp'] <= b['timestamp'] for a,b in zip(packets, packets[1:])), 'non-monotone capture time'
        rows = [classify(p, link) for p in packets]
        assert all(r['kind'] != 'unexplained' for r in rows), (link, rows)
        assert not any(r['filter_refused'] and r['protocol_peer'] for r in rows)
        queries = [r for r in rows if r['kind'] == 'dns-query']
        answers = [r for r in rows if r['kind'] == 'dns-answer']
        assert Counter(r['dns_hex'] for r in queries) == expected_query, 'UDP socket/query correspondence'
        assert Counter(r['dns_hex'] for r in answers) == expected_answer, 'UDP socket/TC correspondence'
        available = Counter()
        for row in rows:
            if row['kind'] == 'dns-query':
                available[truncated(bytes.fromhex(row['dns_hex'])).hex()] += 1
            elif row['kind'] == 'dns-answer':
                assert available[row['dns_hex']] > 0, 'TC without prior identical query'
                available[row['dns_hex']] -= 1
        assert not +available
        sent, client_isn, client = reassemble_tcp(rows, 'tcp-query')
        received, server_isn, server = reassemble_tcp(rows, 'tcp-answer')
        assert sent.hex() == peer['tcp']['received_hex'] and received.hex() == peer['tcp']['sent_hex'], 'complete TCP socket/wire stream correspondence'
        assert stream_messages(sent) == [bytes.fromhex(r['query_hex']) for r in records if r['transport'] == 'TCP']
        assert stream_messages(received) == [bytes.fromhex(r['answer_hex']) for r in records if r['transport'] == 'TCP']
        assert all(r['acknowledgement'] == (client_isn + 1) & 0xffffffff for r in server if r['flags'] & 2)
        client_fin = min(r['index'] for r in client if r['flags'] & 1)
        server_fin = min(r['index'] for r in server if r['flags'] & 1)
        assert any(r['flags'] & 16 and r['index'] > server_fin and r['acknowledgement'] == ((server_isn + len(received) + 2) & 0xffffffff) for r in client), 'client never ACKed observed peer FIN'
        assert any(r['flags'] & 16 and r['index'] > client_fin and r['acknowledgement'] == ((client_isn + len(sent) + 2) & 0xffffffff) for r in server), 'peer never ACKed observed client FIN'
        first_syn = min(r['index'] for r in client if r['flags'] & 2)
        first_synack = min(r['index'] for r in server if r['flags'] & 2)
        handshake_acks = [r['index'] for r in client if r['flags'] & 16 and not r['flags'] & 2
                          and r['sequence'] == ((client_isn + 1) & 0xffffffff)
                          and r['acknowledgement'] == ((server_isn + 1) & 0xffffffff)
                          and r['index'] > first_synack]
        assert first_syn < first_synack and handshake_acks, 'observed SYN/SYNACK/client ACK handshake required'
        assert answers[0]['index'] < first_syn, 'TCP contact before UDP TC fallback'
        first_data = min(r['index'] for r in client if r['tcp_hex'])
        assert first_data >= min(handshake_acks) and first_data > first_synack, 'TCP data preceded observed SYNACK/handshake ACK'
        assert answers[0]['index'] < first_data
        def byte_observed(flow, initial, offset):
            candidates = []
            for packet in flow:
                start = (packet['sequence'] - initial - 1) & 0xffffffff
                if start <= offset < start + len(bytes.fromhex(packet['tcp_hex'])):
                    candidates.append(packet['index'])
            assert candidates, 'unobserved framed stream byte'
            return min(candidates)
        query_at = answer_at = 0
        for udp_record, tcp_record in zip(udp, [r for r in records if r['transport'] == 'TCP']):
            tc = [r for r in answers if r['dns_hex'] == udp_record['answer_hex']]
            assert len(tc) == 1
            question = bytes.fromhex(tcp_record['query_hex'])
            answer = bytes.fromhex(tcp_record['answer_hex'])
            assert tc[0]['index'] < byte_observed(client, client_isn, query_at), 'TCP question prefix preceded its own UDP TC'
            assert byte_observed(client, client_isn, query_at + 1 + len(question)) < byte_observed(server, server_isn, answer_at), 'TCP answer preceded complete matching question'
            query_at += 2 + len(question)
            answer_at += 2 + len(answer)
        ns = [r['index'] for r in rows if r['kind']=='neighbor-discovery' and r['icmpv6_type']==135 and r['direction']=='left-to-right']
        na = [r['index'] for r in rows if r['kind']=='neighbor-discovery' and r['icmpv6_type']==136 and r['direction']=='right-to-left']
        assert ns and na and ns[0] < na[0] < queries[0]['index'], 'actual router/peer ND before valid query'
        captures[link] = rows
    for direction, first, second in (('left-to-right','guest','peer'), ('right-to-left','peer','guest')):
        forwarded = Counter()
        for row in captures[first]:
            if row['direction']==direction and row['kind'] in ('dns-query','dns-answer','tcp-query','tcp-answer'):
                packet = bytearray.fromhex(row['ipv6_hex']);assert packet[7] > 1;packet[7] -= 1;forwarded[bytes(packet).hex()] += 1
        actual = Counter(r['ipv6_hex'] for r in captures[second] if r['direction']==direction and r['kind'] in ('dns-query','dns-answer','tcp-query','tcp-answer'))
        assert forwarded == actual, 'every complete UDP/TCP packet requires exact one-hop counterpart'
    return {'guest_census':captures['guest'],'peer_census':captures['peer'],'queries':2,'answers':2,'tcp_queries':2,'tcp_answers':2,'connections':1,
            'scope':'Two complete checksum-checked Linux forwarded link captures, exact UDP TC and complete two-message TCP streams/FIN/ACK correspondence; explicit1280MTU/MSS1220, no host/guest time mapping or PMTU claim'}


def native_output(raw, status):
    assert status == 3, "normal native debug exit required"
    assert not any(word in raw for word in (b"PANIC", b"KERNEL FAULT", b"NIC DISABLED", b"init: FAILED"))
    assert raw.count(b"NETWORK LINK OK rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048\n") == 1
    chunks = list(re.finditer(rb"(?m)^EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]*)\n", raw))
    assert len(chunks) == raw.count(b"EXTERNAL OUTPUT CHUNK")
    output = bytearray()
    for match in chunks:
        assert int(match[1], 16) == len(output)
        output.extend(bytes.fromhex(match[2].decode()))
        assert len(output) <= 16384
    lines = output.decode().splitlines()
    expected = [
        "ROUTE6TCP SELECTOR local=fd00:ab5d:1::15/64 router=fd00:ab5d:1::2 peer=fd00:ab5d:2::9 udp=42010 scope=1 dad=unrun",
        None,
        "ROUTE6TCP NO-ROUTE REFUSAL PASS udp=denied tcp=denied sockets=0",
        "ROUTE6 API BOUNDARIES PASS malformed=9 denied=3 oversize=1 queue=4 endpoints=8 stale=2 sockets=0 queued-test-wire=0",
        "ROUTE6 PIPE BOUNDARIES PASS eof=1 partial-expiry=1 port-reuse=2 sockets=0",
        None,
        "ROUTE6TCP SERVICE READY scope=1 udp-local-port=7002 tcp-local-port=7003 path-mtu=1280 peer=fd00:ab5d:2::9 peer-port=42010",
        "ROUTE6TCP CLIENT AUTHORITY PASS nic=0 udp-denied=3 tcp-denied=3",
        "ROUTE6TCP DNS A PASS address=192.0.2.9", "ROUTE6TCP DNS AAAA PASS address=2001:db8::9",
        "ROUTE6TCP DNS CLOSE PASS", None, "ROUTE6TCP RETIRE sockets=0", None,
        "ROUTE6TCP SERVICE PASS child=exited sockets=0 resources=restored",
    ]
    assert len(lines) == len(expected) and all(wanted is None or actual == wanted for actual, wanted in zip(lines, expected))
    setup = re.fullmatch(r"ROUTE6TCP RX SETUP elapsed_ms=(\d+) continuous-vm=assumed", lines[5])
    drain = re.fullmatch(r"ROUTE6TCP CLOSE DRAIN observed-ms=(\d+)", lines[11])
    assert setup and 1100 <= int(setup[1]) < 12000, "bounded pre-poll RX setup interval"
    assert drain and 1000 <= int(drain[1]) < 12000, "observed bounded close/drain interval"
    counts = []
    for at, label in ((1, "before"), (13, "after")):
        match = re.fullmatch(r"ROUTE6TCP CENSUS label=" + label + r" processes=(\d+) handles=(\d+) pipes=(\d+) cells=(\d+) frames=(\d+)", lines[at])
        assert match
        counts.append([int(n) for n in match.groups()])
    assert counts[0][:4] == counts[1][:4], "exact four-counter resource equality"
    value = 0x811c9dc5
    for byte in output:
        value = ((value ^ byte) * 0x01000193) & 0xffffffff
    end = re.findall(rb"(?m)^EXTERNAL OUTPUT END bytes=(\d+) digest=([0-9a-f]{8})\n", raw)
    assert len(end) == 1 and int(end[0][0]) == len(output) and int(end[0][1], 16) == value
    stats = re.findall(rb"(?m)^NIC STATS ([^\n]+)\n", raw)
    assert len(stats) == raw.count(b"NIC STATS ") == 1
    fields = dict(part.split("=", 1) for part in stats[0].decode().split())
    assert set(fields) == {"rx_frames", "rx_refused", "rx_missed", "tx_frames", "tx_refused", "tx_errors", "flags"}
    assert all(re.fullmatch("[0-9]+", n) for n in fields.values())
    assert fields["flags"] == "1" and int(fields["rx_frames"]) > 0 and int(fields["tx_frames"]) > 0
    for pid in (2, 3):
        assert raw.count(f"USER EXIT pid={pid} status=0\n".encode()) == 1
        assert len(re.findall(rb"(?m)^USER (?:EXIT pid=" + str(pid).encode() + rb" status=|KILLED pid=" + str(pid).encode() + rb" by=)", raw)) == 1
    assert re.findall(rb"(?m)^SPAWN OK pid=(\d+) parent=2 program=image\n", raw) == [b"3"]
    assert len(re.findall(rb"(?m)^SPAWN OK pid=\d+ parent=2 program=", raw)) == 1
    assert raw.count(b"DURABLE WORKER OUTCOME generation=1 pid=2 status=0\n") == 1
    terminal = re.findall(rb"(?m)^DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ([^\n]+)\n", raw)
    assert len(terminal) == raw.count(b"DURABLE status=") == 1
    tail = dict(part.split("=", 1) for part in terminal[0].decode().split())
    assert set(tail) == {"block_reads", "block_writes", "block_flushes", "block_errors", "block_waits", "block_irqs", "ticks"}
    assert all(re.fullmatch("[0-9]+", n) for n in tail.values()) and all(n == "0" for k, n in tail.items() if k != "ticks")
    assert b"\nDURABLE WORKLOAD OK\nABSD BOOT OK\n" in raw
    return {"output": output.decode(), "NIC_counters": fields, "census_before": counts[0], "census_after": counts[1],
            "authority_limit": "nic=0/framed-denied markers require exact child/parent construction and checks; no separately sampled spawn authority telemetry",
            "controls": "unchanged UDP boundary fixtures plus three real framed TCP wrong-tuple CONNECT denials, paired DNS consumer and explicit close/drain. No malformed wire/child-kill claim"}


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


def group_live(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


def stop_owned(process):
    if process is None:
        return {"status": None, "group_absent": True, "forced": False}
    process.poll()
    forced = False
    if group_live(process.pid):
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        stop = time.monotonic() + 3
        while (process.poll() is None or group_live(process.pid)) and time.monotonic() < stop:
            time.sleep(0.02)
        if process.poll() is None or group_live(process.pid):
            forced = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stop = time.monotonic() + 3
            while (process.poll() is None or group_live(process.pid)) and time.monotonic() < stop:
                time.sleep(0.02)
    return {"status": process.poll(), "group_absent": not group_live(process.pid), "forced": forced}


def seal_artifacts(work, result):
    artifacts = {}
    for path in work.rglob("*"):
        assert not path.is_symlink(), "case artifact symlink refused"
        if path.is_file():
            maximum = MAX_ISO if path.suffix == ".iso" else MAX_ELF if path.suffix in (".elf", ".tar") or path.name in ("absd-kernel", "external-parent") else MAX_LOG
            artifacts[str(path.relative_to(work))] = identity(path, bounded(path, maximum))
    for collection in ("evaluated_build_inputs", "evaluated_artifacts"):
        for name, expected in result[collection].items():
            wanted = {k: expected[k] for k in ("bytes", "sha256")}
            assert {k: artifacts[name][k] for k in wanted} == wanted, "evaluated buffer changed before seal: " + name
            assert digest(bounded(work / name, MAX_ISO)) == wanted, "evaluated buffer changed during seal: " + name
    for row in result["proof_inputs"].values():
        assert digest(bounded(row["path"], MAX_LOG)) == {k: row[k] for k in ("bytes", "sha256")}, "proof input changed before seal"
    return artifacts


def validate_topology(state):
    assert state["transport"] == "Linux kernel IPv6 forwarding and AF_INET6 UDP/TCP; application DNS answers are controlled fixtures"
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
            assert links[0]["address"] == mac.hex(":") and links[0]["mtu"] == IP_MTU and "UP" in links[0]["flags"]
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
    assert stat.S_ISREG(info.st_mode), "namespace handle is not an ordinary mounted file"
    return {"device": info.st_dev, "inode": info.st_ino}


def retire_namespace(name, expected, command):
    listing = command(["ip", "netns", "list"])
    if name not in [row.split()[0] for row in listing.splitlines()]:
        return True  # Actual absence clears an uncertain creation, without deletion.
    assert expected is not None and namespace_identity(name) == expected, "unknown/replaced namespace retained"
    assert not command(["ip", "netns", "pids", name]).strip(), "owned namespace retains processes"
    assert namespace_identity(name) == expected, "namespace replaced before deletion; retained"
    command(["ip", "netns", "del", name])
    return name not in [row.split()[0] for row in command(["ip", "netns", "list"]).splitlines()]


def run(args):
    assert os.geteuid() == 0, "owned disposable Linux VM root required"
    assert args.timeout + 45 < args.lease - time.time() <= 4 * 3600, "finite lease margin"
    work, deadline = args.work, time.monotonic() + args.timeout
    suffix = uuid.UUID(args.run_id).hex
    namespaces = {"router": "absdr6-r-" + suffix, "peer": "absdr6-p-" + suffix}
    processes, logs, bounds, evaluated, retained = {}, [], {}, {}, {}
    attempted, created, errors, owned_namespaces = set(), set(), [], {}
    env = {k: v for k, v in os.environ.items() if k not in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "NOTIFY_SOCKET")}

    def fact(name, value):
        data = write(work / name, value)
        assert json.loads(data) == value
        evaluated[name] = identity(work / name, data)
        return data

    def left(maximum):
        for path, bound in bounds.items():
            assert not path.exists() or path.stat().st_size <= bound, "output bound: " + path.name
        remaining = min(deadline - time.monotonic(), args.lease - time.time() - 45)
        assert remaining > 0, "absolute case/lease deadline"
        return min(maximum, remaining)

    def command(argv, timeout=5):
        result = subprocess.run(argv, capture_output=True, check=True, timeout=timeout, env=env)
        assert len(result.stdout) + len(result.stderr) <= 65536
        return result.stdout.decode()

    def checked(argv):
        return command(argv, left(5))

    def net(role, argv):
        return checked(["ip", "netns", "exec", namespaces[role], *argv])

    def ip(role, argv):
        return checked(["ip", "-n", namespaces[role], *argv])

    def start(name, argv, process_env=None):
        path = work / (name + ".log")
        bounds[path] = MAX_LOG
        log = path.open("xb")
        logs.append(log)
        processes[name] = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                                           env=env if process_env is None else process_env)
        return processes[name]

    def ended(name, timeout):
        end = time.monotonic() + left(timeout)
        process = processes[name]
        while process.poll() is None:
            left(timeout)
            assert time.monotonic() < end, "bounded terminal wait: " + name
            time.sleep(0.01)
        return process.returncode

    def topology():
        state = {"transport": "Linux kernel IPv6 forwarding and AF_INET6 UDP/TCP; application DNS answers are controlled fixtures",
                 "kernel": list(os.uname()), "namespaces": {}}
        for role, devices in (("router", ("r6-tap", "r6-out")), ("peer", ("r6-peer",))):
            observed_identity = namespace_identity(namespaces[role])
            assert observed_identity == owned_namespaces[role], "namespace replaced before topology observation"
            state["namespaces"][role] = {
                "name": namespaces[role], **observed_identity,
                "sysctls": {key: net(role, ["sysctl", "-n", key]).strip() for key in settings},
                "addresses": json.loads(ip(role, ["-j", "-6", "addr", "show"])),
                "links": json.loads(ip(role, ["-j", "link", "show"])),
                "routes": json.loads(ip(role, ["-j", "-6", "route", "show"])),
                "neighbors": json.loads(ip(role, ["-j", "-6", "neigh", "show"])),
                "offloads": {dev: net(role, ["ethtool", "-k", dev]) for dev in devices},
                "UDP_sockets": net(role, ["ss", "-H", "-a", "-n", "-u"]),
                "TCP_sockets": net(role, ["ss", "-H", "-a", "-n", "-t"])}
        return validate_topology(state)

    try:
        proof_inputs = {"runner": identity(__file__, bounded(__file__, MAX_LOG)),
                        "accepted_helper": identity(_helper_path, _helper_bytes), "DNS_codec": identity(_dns_path, _dns_bytes),
                        "served_kernel_policy": identity(_served_path, _served_bytes)}
        peer_script = Path(__file__).with_name("native-ipv6-routed-tcp-peer.py")
        proof_inputs["peer"] = identity(peer_script, bounded(peer_script, MAX_LOG))
        fact("CASE.json", {"run": args.run_id, "case": CASE, "runtime": PRODUCT, "kernel": KERNEL,
                           "guest": GUEST_IP, "router": ROUTER_IP, "uplink": UPLINK_IP, "peer": PEER_IP,
                           "udp_local_port": 7002, "tcp_local_port": 7003, "path_mtu": IP_MTU, "peer_port": 42010, "scope": 1, "route": PEER_IP + "/128", "DAD": "UNRUN"})
        buffers = {n: bounded(p, MAX_ELF) for n, p in (("child", args.client_elf), ("parent", args.elf), ("kernel", args.kernel_elf))}
        receipt_bytes = bounded(args.build_receipt, MAX_LOG)
        receipt = json.loads(receipt_bytes)
        build_binding(receipt, buffers)
        for name, data in buffers.items():
            path = work / (name + ".elf")
            path.write_bytes(data)
            retained[path.name] = identity(path, data)
        for name, item in [("platform-source.tar", receipt["platform"]["archive"]), ("kernel-source.tar", receipt["kernel"]["archive"]),
                           ("build-input-0.log", receipt["toolchain_receipt"]),
                           *[(f"build-input-{i+1}.log", v) for i, v in enumerate(receipt["logs"])],
                           *[("external-" + n, v) for n, v in receipt["external"].items()]]:
            data = bounded(item["path"], MAX_ELF if name.endswith(".tar") or name == "external-parent" else MAX_LOG)
            assert digest(data) == {k: item[k] for k in ("bytes", "sha256")}
            path = work / name
            path.write_bytes(data)
            retained[name] = identity(path, data)
        (work / "BUILD-RECEIPT.json").write_bytes(receipt_bytes)
        retained["BUILD-RECEIPT.json"] = identity(work / "BUILD-RECEIPT.json", receipt_bytes)
        tree = work / "iso-tree/boot/grub"
        tree.mkdir(parents=True)
        (tree.parent / "absd-kernel").write_bytes(buffers["kernel"])
        boot = b'insmod all_video\nset timeout=0\nmenuentry "ABSD routed IPv6 DNS" {\n multiboot2 /boot/absd-kernel durable=1 net nvme-write=absd\n boot\n}\n'
        (tree / "grub.cfg").write_bytes(boot)
        iso, disk = work / "native-ipv6-mtu1280.iso", work / "native-ipv6-mtu1280.img"
        bounds[iso], bounds[disk] = MAX_ISO, 2 << 20
        temporary = work / "iso-tmp"
        temporary.mkdir()
        builder = start("iso-build", ["grub-mkrescue", "-o", str(iso), str(tree.parent.parent)], dict(env, TMPDIR=str(temporary)))
        assert ended("iso-build", 60) == 0
        iso_bytes = bounded(iso, MAX_ISO)
        extracted = iso_binding(iso_bytes, buffers["kernel"], boot)
        with disk.open("xb") as stream:
            stream.truncate(2 << 20)
        settings = {"net.ipv6.conf.all.forwarding": "0", "net.ipv6.conf.default.forwarding": "0", "net.ipv6.conf.all.accept_ra": "0", "net.ipv6.conf.default.accept_ra": "0",
                    "net.ipv6.conf.all.autoconf": "0", "net.ipv6.conf.default.autoconf": "0", "net.ipv6.conf.default.accept_dad": "0"}
        existing = [row.split()[0] for row in checked(["ip", "netns", "list"]).splitlines()]
        assert not any(ns in existing for ns in namespaces.values())
        for role, ns in namespaces.items():
            attempted.add(role)  # A timed-out mutating command still requires reconciliation.
            checked(["ip", "netns", "add", ns])
            created.add(role)
            owned_namespaces[role] = namespace_identity(ns)
            fact("NAMESPACE-" + role.upper() + "-CREATED.json", {"name": ns, **owned_namespaces[role]})
            for key, value in settings.items():
                net(role, ["sysctl", "-qw", key + "=" + ("1" if role == "router" and key.endswith(".forwarding") else value)])
            ip(role, ["link", "set", "lo", "up"])
        ip("router", ["tuntap", "add", "dev", "r6-tap", "mode", "tap"])
        ip("router", ["link", "add", "r6-out", "type", "veth", "peer", "name", "r6-peer", "netns", namespaces["peer"]])
        for role, device, mac, address in (("router", "r6-tap", ROUTER_MAC, ROUTER_IP), ("router", "r6-out", UPLINK_MAC, UPLINK_IP),
                                            ("peer", "r6-peer", PEER_MAC, PEER_IP)):
            for argv in (["link", "set", device, "address", mac.hex(":")], ["link", "set", device, "mtu", str(IP_MTU)],
                         ["link", "set", device, "addrgenmode", "none"], ["link", "set", device, "up"],
                         ["-6", "addr", "add", address + "/64", "dev", device, "nodad"]):
                ip(role, argv)
            net(role, ["ethtool", "-K", device, "tx", "off", "gso", "off", "gro", "off", "tso", "off"])
        # ndisc_send_ns(NULL source) requires an egress link-local on Linux.
        # addrgenmode none deliberately creates none; install this one exactly.
        ip("router", ["-6", "addr", "add", UPLINK_LL_IP + "/64", "dev", "r6-out", "nodad"])
        ip("peer", ["-6", "route", "add", "fd00:ab5d:1::/64", "via", UPLINK_IP, "dev", "r6-peer"])
        before = topology()
        fact("LINUX-TOPOLOGY-BEFORE.json", before)
        peer = start("peer", ["ip", "netns", "exec", namespaces["peer"], "python3", "-B", str(peer_script), str(work), "--timeout", str(args.timeout)])
        bounds[work / "PEER-RESULT.json"] = MAX_LOG
        until = time.monotonic() + left(5)
        while not (work / "PEER-READY.json").exists():
            assert peer.poll() is None and time.monotonic() < until
            left(1)
            time.sleep(0.01)
        ready_bytes = bounded(work / "PEER-READY.json", 65536)
        ready = json.loads(ready_bytes)
        assert ready == {"schema_version": 1, "pid": peer.pid, "bind": PEER_IP, "port": 42010, "forbidden_port": 42011, "udp_source": [GUEST_IP, 7002], "tcp_source": [GUEST_IP, 7003], "transport": "Linux AF_INET6 SOCK_DGRAM + SOCK_STREAM", "codec_sha256": DNS_HASH}
        evaluated["PEER-READY.json"] = identity(work / "PEER-READY.json", ready_bytes)
        peer_capture = work / "peer-link.pcap"
        bounds[peer_capture] = MAX_CAPTURE
        start("capture", ["ip", "netns", "exec", namespaces["peer"], "tcpdump", "--immediate-mode", "-n", "-U", "-p", "-s", "1514", "-i", "r6-peer", "-w", str(peer_capture)])
        until = time.monotonic() + left(5)
        while not peer_capture.exists() or peer_capture.stat().st_size < 24:
            assert processes["capture"].poll() is None and time.monotonic() < until
            left(1)
            time.sleep(0.01)
        serial, capture = work / "native-ipv6-routed-tcp.serial.log", work / "guest-link.pcap"
        bounds[serial], bounds[capture] = MAX_LOG, MAX_CAPTURE
        selected = shutil.which(args.qemu or os.environ.get("ABSD_QEMU", "qemu-system-x86_64"))
        assert selected, "QEMU unavailable"
        selected = str(Path(selected).resolve())
        qemu_identity = identity(selected, bounded(selected, MAX_ELF))
        argv = served_qemu(["ip", "netns", "exec", namespaces["router"], selected, "-accel", "tcg,thread=single", "-cpu", "max,vendor=GenuineIntel,+rdrand",
                "-smp", "1", "-m", "256M", "-cdrom", str(iso), "-drive", f"file={disk},format=raw,if=ide,index=0",
                "-display", "none", "-serial", f"file:{serial}", "-no-reboot", "-no-shutdown",
                "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-device", f"e1000,netdev=n0,mac={GUEST_MAC.hex(':')}",
                "-netdev", "tap,id=n0,ifname=r6-tap,script=no,downscript=no,vnet_hdr=off",
                "-object", f"filter-dump,id=cap0,netdev=n0,file={capture}"])
        marker = original.ReadyMarker(serial, capture)
        marker.poll(running=False)
        q = start("qemu", argv)
        fact("LAUNCH.json", {"run": args.run_id, "case": CASE, "argv": argv, "qemu_pid_pgid": q.pid,
                             "processes": {name: p.pid for name, p in processes.items()}, "selected_QEMU_or_launcher": qemu_identity,
                             "qemu_identity_limit": "Selected file may be a launcher; its argv[0]/hash does not establish a distro executable identity.",
                             "lease_end": args.lease_end, "timeout": args.timeout, "ISO": identity(iso, iso_bytes),
                             "extracted_ISO": extracted, "inputs": {n: digest(b) for n, b in buffers.items()}, "proof_inputs": proof_inputs})
        while q.poll() is None:
            marker.poll(running=q.poll() is None)
            left(args.timeout)
            time.sleep(0.005)
        left(1)
        marker.poll(running=False)
        annotation = marker.seal(work)
        sidecar_bytes = bounded(work / "NIC-READY-CAPTURE.json", 65536)
        evaluated["NIC-READY-CAPTURE.json"] = identity(work / "NIC-READY-CAPTURE.json", sidecar_bytes)
        (work / "PEER-STOP").write_bytes(b"")
        evaluated["PEER-STOP"] = identity(work / "PEER-STOP", b"")
        assert ended("peer", 3) == 0
        capture_terminal = stop_owned(processes["capture"])
        fact("CAPTURE-TERMINAL.json", capture_terminal)
        assert capture_terminal == {"status": 0, "group_absent": True, "forced": False}
        peer_bytes = bounded(work / "PEER-RESULT.json", MAX_LOG)
        observed = peer_result(peer_bytes)
        assert observed["pid"] == peer.pid
        evaluated["PEER-RESULT.json"] = identity(work / "PEER-RESULT.json", peer_bytes)
        after = topology()
        assert all(after["namespaces"][role]["inode"] == before["namespaces"][role]["inode"] for role in namespaces)
        fact("LINUX-TOPOLOGY-AFTER.json", after)
        raw_serial, guest_bytes, remote_bytes = bounded(serial, MAX_LOG), bounded(capture, MAX_CAPTURE), bounded(peer_capture, MAX_CAPTURE)
        native = native_output(raw_serial, q.returncode)
        captured = inspect(guest_bytes, remote_bytes, observed)
        reasons = reason_accounting(guest_bytes, raw_serial, sidecar_bytes, annotation, native["NIC_counters"], captured["guest_census"])
        fact("NIC-REASON-ACCOUNTING.json", reasons)
        assert reasons["disposition"] == "PASS", (reasons["failures"], reasons["ambiguities"])
        for name, data in (("iso-tree/boot/absd-kernel", buffers["kernel"]), ("iso-tree/boot/grub/grub.cfg", boot),
                           (iso.name, iso_bytes), (serial.name, raw_serial), (capture.name, guest_bytes), (peer_capture.name, remote_bytes)):
            evaluated[name] = identity(work / name, data)
        left(1)
        return {"schema": "absd-native-ipv6-mtu1280-proof/1", "disposition": "PASS", "run": args.run_id, "case": CASE,
                "case_deadline_monotonic": deadline, "native": native, "capture_result": captured, "peer": observed,
                "reason_accounting": reasons, "evaluated_build_inputs": retained, "evaluated_artifacts": evaluated,
                "proof_inputs": proof_inputs, "unrun": UNRUN,
                "source_binding_limit": f"Exact clean {PRODUCT}/{KERNEL} build receipts, source/ELF/ISO buffers and tool logs; no compiler-correctness proof.",
                "limits": "One explicit1280-MTU paired routed UDP/TCP DNS capability; small answers establish MSS and DNS success, not bulk segment sizing. No DAD/PMTU/automatic routes. Reason logs are first-four compatible attribution, not synchronized frame/DMA assignments."}
    finally:
        terminals = {}
        for name in ("qemu", "peer", "capture", "iso-build"):
            try:
                row = stop_owned(processes.get(name))
                terminals[name] = row
                if row["forced"] or not row["group_absent"] or (processes.get(name) is not None and row["status"] is None):
                    errors.append(name + " not terminal/clean")
            except BaseException as error:
                terminals[name] = {"unknown": repr(error)}
                errors.append(name + " " + repr(error))
        for log in logs:
            log.close()
        absent = {}
        for role in ("peer", "router"):
            if role not in attempted:
                absent[role] = None
                continue
            ns = namespaces[role]
            try:
                absent[role] = retire_namespace(ns, owned_namespaces.get(role), command)
                assert absent[role]
            except BaseException as error:
                errors.append(role + " namespace " + repr(error))
        for path, maximum in bounds.items():
            if path.exists() and path.stat().st_size > maximum:
                errors.append("output bound " + path.name)
        fact("LOCAL-CLEANUP.json", {"run": args.run_id, "namespaces": namespaces, "creation_attempted": sorted(attempted),
                                   "created": sorted(created), "owned_namespace_identities": owned_namespaces, "namespace_absent": absent, "processes": terminals, "errors": errors,
                                   "disposition": "FAIL" if errors else "PASS",
                                   "custody": "Root retains source/ELFs/ISO/raw/receipts through actual handoff or review2026-10-17; creator retires ended substrate after dependency checks. No keys created by this runner."})
        if errors:
            raise RuntimeError(errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path, help="new owned case directory; must not exist")
    parser.add_argument("--run-id", required=True, help="fresh UUID naming exact owned router/peer namespaces")
    parser.add_argument("--kernel-elf", type=Path, required=True)
    parser.add_argument("--elf", type=Path, required=True, help="ipv6-route-service-probe.elf embedded in kernel")
    parser.add_argument("--client-elf", type=Path, required=True, help="ipv6-route-dns-client.elf embedded in parent")
    parser.add_argument("--build-receipt", type=Path, required=True, help="exact platform/kernel/tool/source/build/empty-input receipt")
    parser.add_argument("--lease-end", required=True, help="absolute UTC resource lease, timezone required")
    parser.add_argument("--timeout", type=int, default=150, help="10..180 seconds, ISO setup through final seal")
    parser.add_argument("--qemu", help="exact admitted QEMU/launcher; otherwise ABSD_QEMU or qemu-system-x86_64")
    args = parser.parse_args()
    try:
        uuid.UUID(args.run_id)
        stamp = datetime.datetime.fromisoformat(args.lease_end.replace("Z", "+00:00"))
        assert stamp.tzinfo is not None and 10 <= args.timeout <= 180
    except (ValueError, AssertionError):
        parser.error("fresh UUID, timezone-bearing lease and10..180 second timeout required")
    args.lease, args.work = stamp.timestamp(), args.work.resolve()
    args.work.mkdir(mode=0o700, parents=True, exist_ok=False)
    def stopped(_signal, _frame):
        raise KeyboardInterrupt("qualification runner interrupted")
    signal.signal(signal.SIGTERM, stopped)
    signal.signal(signal.SIGINT, stopped)
    try:
        result = run(args)
        result["artifacts"] = seal_artifacts(args.work, result)
        assert time.monotonic() < result["case_deadline_monotonic"] and time.time() < args.lease, "case/lease expired before final seal"
    except BaseException as error:
        write(args.work / "RESULT.json", {"schema": "absd-native-ipv6-mtu1280-proof/1", "disposition": "FAIL",
                                         "run": args.run_id, "case": CASE, "error": repr(error), "unrun": UNRUN})
        raise
    write(args.work / "RESULT.json", result)
    print("NATIVE IPV6 MTU1280 ROUTED DNS PROOF PASS")


if __name__ == "__main__":
    main()
