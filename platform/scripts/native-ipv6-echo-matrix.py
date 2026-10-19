#!/usr/bin/env python3
"""One owned Linux-kernel IPv6 Echo case using exact prebuilt ABSD inputs.

No source compilation, userspace Echo responder, packet injection or public
peer. Run only on the separately admitted disposable Linux resource.
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
import struct
import subprocess
import time
import types
import uuid

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from served_ram import served_qemu

if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
    raise SystemExit("native-ipv6-echo: optimized Python refused")
ROOT = Path(__file__).resolve().parent.parent
PRODUCT = "62a27858e601cbf51c32fcbe909f1dcd5240693b"
PRODUCT_TREE = "61786b3224b9986af9c79135a2da537c1fc56fca"
PRODUCT_ARCHIVE = "64a088744abc4cb4c6b4792c3a5454124caa761d8205944ac1035ca4cf01a32c"
PRODUCT_BYTES = 22630400
KERNEL = "ed6a15ea7c7c999422e1e294e139b6119619b06c"
KERNEL_TREE = "5c3834dcdb8cf393c86bc0e436ae62c7cda67af5"
KERNEL_ARCHIVE = "568ac7c029d9d8e6e101519b1341c2e860300cb7dded1e65ea526efaa731212e"
KERNEL_BYTES = 11417600
HELPER = "native-ipv6-accounting.py"
HELPER_HASH = "22d5f091c23c0d436be538d3695b43b3ed52b48ec5b4b30668be215a08001ad3"
GUEST_IP, HOST_IP = "fd00:ab5d::15", "fd00:ab5d::2"
GUEST, HOST = (ipaddress.IPv6Address(s).packed for s in (GUEST_IP, HOST_IP))
GUEST_MAC, HOST_MAC = bytes.fromhex("525400ab5d15"), bytes.fromhex("525500000202")
ALL, SOL = (ipaddress.IPv6Address(s).packed for s in ("ff02::1", "ff02::1:ff00:15"))
MAX_ELF, MAX_ISO, MAX_LOG, MAX_CAPTURE = 64 << 20, 128 << 20, 8 << 20, 2 << 20
CASES = {
    "positive": {"preassigned_candidate": False, "echo_ignore_all": 0, "qemu_exit": 3},
    "preassigned-conflict": {"preassigned_candidate": True, "echo_ignore_all": 0, "qemu_exit": 7},
    "no-reply": {"preassigned_candidate": False, "echo_ignore_all": 1, "qemu_exit": 7},
}
UNRUN = [
    "native malformed/unauthorized wire substitutions or partial/EOF/interrupted pipe cases",
    "native slot/generation/frame/call/defense exhaustion, uncertain writes and clock/link fault injection",
    "global before/after handle census, physical RTT, uniqueness/authentication, hardware/live transfer",
    "general IPv6/DAD/ICMPv6 conformance, MLD-snooping links and an inbound Echo responder",
]
OBSERVED = re.compile(
    r"PING6 OBSERVED peer=fd00:ab5d::2 scope=1 identifier=([0-9]+) sequence=([0-9]+) "
    r"instance=([0-9]+) epoch=([0-9]+) nonce=([0-9a-f]{16}) boot_elapsed_ms=([0-9]+) auth=none requests=1"
)
NO_REPLY_ERRORS = {
    "DAD wait Expired", "DAD after result read Expired", "DAD after wait Expired",
    "DAD during terminal drain Expired",
}


ACTIVE_MS, ACQUIRE_MS, TOTAL_MS, FRAME_MS = 8000, 3000, 12000, 250


def guest_clock_trace(lines, case, ticks):
    """All samples are one boot's floored PIT-derived milliseconds, not host PCAP time."""
    owner = re.fullmatch(r"PING6 OWNER invocation_start_ms=([0-9]+) invocation_until_ms=([0-9]+) stop_ms=([0-9]+) current_ms=([0-9]+)", lines[0])
    submission = re.fullmatch(r"PING6 SUBMISSION before_ms=([0-9]+) after_ms=([0-9]+) result=(-?[0-9]+) frame=([0-9a-f]+)", lines[-3])
    terminal = re.fullmatch(r"PING6 TERMINAL boot_ms=([0-9]+) attempts=([0-9]+)", lines[-2])
    assert owner and submission and terminal, "exact owner/submission/terminal boot trace required"
    start, until, stop, current = map(int, owner.groups())
    before, after, result = map(int, submission.groups()[:3])
    terminal_ms, attempts = map(int, terminal.groups())
    assert all(0 <= n <= (1 << 63) - 1 for n in (start, until, stop, current, before, after, terminal_ms))
    assert 0 <= ticks < 1 << 64
    # Exact runtime/src/lib.rs boot_millis conversion, with Python's wide integers.
    terminal_from_ticks = ticks * 1193 * 3000 // 3579545
    assert terminal_from_ticks <= (1 << 63) - 1
    activation = stop - ACTIVE_MS
    assert until == start + TOTAL_MS
    # Successful acquisition is before start+3000, so the following 8000 ms
    # window cannot be truncated by the original 12000 ms invocation bound.
    assert start < activation < start + ACQUIRE_MS
    assert activation <= current <= before <= after < stop < until
    assert after <= terminal_ms <= terminal_from_ticks, "boot trace/tick order differs"
    assert terminal_ms < until, "original invocation bound crossed"
    packet = bytes.fromhex(submission[4])
    assert attempts == 1 and result == 0 and len(packet) == 94, "one successful bounded local submission required"
    assert packet[12:14] == b"\x86\xdd" and packet[20] == 58 and packet[54:56] == b"\x80\0"
    if case == "no-reply":
        assert after + FRAME_MS < stop, "request did not precede owner expiry by more than one frame"
        assert stop <= terminal_ms, "no-reply ended before the active owner window expired"
    return {"invocation_start_ms": start, "invocation_until_ms": until,
            "activation_ms": activation, "stop_ms": stop, "owner_sample_ms": current,
            "submission": {"before_ms": before, "after_ms": after, "result": result, "frame": packet.hex()},
            "terminal_boot_ms": terminal_ms, "terminal_boot_from_ticks_ms": terminal_from_ticks,
            "attempts": attempts,
            "limit": "Local successful Link submission bracket; no wire receipt, atomic cancellation, physical time or host/guest clock mapping."}


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
original = types.ModuleType("echo_accepted_accounting")
original.__file__ = str(_helper_path)
exec(compile(_helper_bytes, str(_helper_path), "exec"), original.__dict__)
PROFILE = {"guest": GUEST_IP, "host": HOST_IP, "udp": None, "tcp": None}


def manifest(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            assert key not in result, "duplicate manifest member"
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=unique)
    expected = {"schema": "absd-native-ipv6-echo-cases/1", "runtime": PRODUCT, "kernel": KERNEL, "cases": CASES}
    assert json.dumps(value, sort_keys=True) == json.dumps(expected, sort_keys=True), "fixed three-case manifest differs"
    return value


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
    assert receipt["schema"] == "absd-native-ipv6-echo-build/1"
    for key, rev, tree, archive, size in (
        ("platform", PRODUCT, PRODUCT_TREE, PRODUCT_ARCHIVE, PRODUCT_BYTES),
        ("kernel", KERNEL, KERNEL_TREE, KERNEL_ARCHIVE, KERNEL_BYTES),
    ):
        item = receipt[key]
        assert item["revision"] == rev and item["tree"] == tree and item["clean"] is True
        assert {k: item["archive"][k] for k in ("bytes", "sha256")} == {"bytes": size, "sha256": archive}
    commands = receipt["commands"]
    assert commands and all(isinstance(c, list) and c and all(isinstance(x, str) for x in c) for c in commands)
    assert any(any(x.endswith("scripts/build-native-ipv6-echo.sh") for x in c) for c in commands)
    external = receipt["external"]
    assert set(external) == {"input", "expected", "parent"}
    empty = digest(b"")
    assert all({k: external[n][k] for k in empty} == empty for n in ("input", "expected"))
    assert {k: external["parent"][k] for k in empty} == digest(buffers["parent"])
    required = {"external-build", "EXTERNAL_USER_ELF=" + external["parent"]["path"],
                "EXTERNAL_INPUT=" + external["input"]["path"], "EXTERNAL_EXPECTED=" + external["expected"]["path"]}
    assert any(required <= set(command) for command in commands), "external build/empty-input binding"
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


def classify(record):
    row = original.classify(record, GUEST_MAC, HOST_MAC, PROFILE)
    if row["kind"] != "unexplained":
        return row
    frame = record["frame"]
    if (len(frame) < 62 or frame[12:14] != b"\x86\xdd" or frame[14] >> 4 != 6
            or frame[20] != 58 or len(frame) != 54 + int.from_bytes(frame[18:20], "big")):
        return row
    source, destination, body = frame[22:38], frame[38:54], frame[54:]
    outgoing = frame[6:12] == GUEST_MAC
    if not outgoing and frame[6:12] != HOST_MAC:
        return row
    if original.checksum(source + destination + struct.pack("!I3xB", len(body), 58) + body):
        return row
    if (outgoing and frame[21] == 255 and source == bytes(16) and destination == SOL
            and frame[:6] == b"\x33\x33\xff\0\0\x15" and len(body) == 24
            and body[:2] == b"\x87\0" and body[4:] == bytes(4) + GUEST):
        row.update(kind="guest-dad-ns", protocol_peer=True)
    elif (not outgoing and frame[21] == 255 and source == GUEST and destination == ALL
          and frame[:6] == b"\x33\x33\0\0\0\x01" and len(body) == 32
          and body[:2] == b"\x88\0" and body[4:] == b"\x20\0\0\0" + GUEST + b"\x02\x01" + HOST_MAC):
        row.update(kind="linux-conflict-na", protocol_peer=True)
    elif (len(body) == 40 and body[0] == (128 if outgoing else 129) and body[1] == 0
          and frame[21] == 64 and source == (GUEST if outgoing else HOST)
          and destination == (HOST if outgoing else GUEST)
          and frame[:6] == (HOST_MAC if outgoing else GUEST_MAC)
          and body[8:16] == b"ABSDPNG6"):
        identifier, sequence, instance, epoch, nonce = struct.unpack("!HHQQQ", body[4:8] + body[16:])
        if identifier and sequence and instance and epoch and nonce:
            row.update(kind="echo-request" if outgoing else "echo-reply", protocol_peer=True,
                       identifier=identifier, sequence=sequence, instance=instance, epoch=epoch, nonce=nonce)
    return row


def native_output(raw, status, case):
    assert status == CASES[case]["qemu_exit"], "QEMU exit differs from fixed case"
    assert not any(word in raw for word in (b"PANIC", b"KERNEL FAULT", b"NIC DISABLED"))
    assert raw.count(b"NETWORK LINK OK rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048\n") == 1
    chunks = list(re.finditer(rb"(?m)^EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]*)\n", raw))
    assert len(chunks) == raw.count(b"EXTERNAL OUTPUT CHUNK")
    output = bytearray()
    for item in chunks:
        assert int(item[1], 16) == len(output)
        output.extend(bytes.fromhex(item[2].decode()))
        assert len(output) <= 16384
    text = output.decode("utf-8")
    assert text.endswith("\n")
    stats = re.findall(rb"(?m)^NIC STATS ([^\n]+)\n", raw)
    durable = re.findall(rb"(?m)^DURABLE status=(\d+) frames=0 processes=0 cells=0 pipes=0 ([^\n]+)\n", raw)
    assert len(stats) == raw.count(b"NIC STATS ") == len(durable) == raw.count(b"DURABLE status=") == 1
    fields = dict(part.split("=", 1) for part in stats[0].decode().split())
    assert set(fields) == {"rx_frames", "rx_refused", "rx_missed", "tx_frames", "tx_refused", "tx_errors", "flags"}
    assert all(re.fullmatch("[0-9]+", value) for value in fields.values())
    assert int(fields["flags"]) == 1 and int(fields["rx_frames"]) > 0 and int(fields["tx_frames"]) > 0
    ticks = re.search(rb"(?:^| )ticks=([0-9]+)(?: |$)", durable[0][1])
    assert ticks
    tail = dict(part.split("=", 1) for part in durable[0][1].decode().split())
    assert set(tail) == {"block_reads", "block_writes", "block_flushes", "block_errors", "block_waits", "block_irqs", "ticks"}
    assert all(tail[k] == "0" for k in tail if k != "ticks"), "unexpected block activity/error"
    children = re.findall(rb"(?m)^SPAWN OK pid=(\d+) parent=2 program=image\n", raw)
    assert len(children) == len(re.findall(rb"(?m)^SPAWN OK pid=\d+ parent=2 program=", raw))
    positive = case == "positive"
    assert int(durable[0][0]) == (0 if positive else 99)
    observation = None
    trace = None
    if positive:
        lines = text.splitlines()
        assert len(lines) == 8
        trace = guest_clock_trace(lines, case, int(ticks[1]))
        assert lines[1:3] == [
            "PING6 DAD CLEAR local=fd00:ab5d::15 scope=1 auth=none uniqueness=unproven",
            "PING6 SERVICE READY scope=1 peer=fd00:ab5d::2 requests=1"]
        assert lines[3] == "PING6 CLIENT AUTHORITY PASS nic=0 denied=1"
        found = OBSERVED.fullmatch(lines[4])
        assert found
        values = [int(found[i], 16 if i == 5 else 10) for i in range(1, 7)]
        assert all(0 < n < 65536 for n in values[:2]) and all(0 < n < 1 << 64 for n in values[2:5])
        assert values[5] < 8000
        observation = dict(zip(("identifier", "sequence", "instance", "epoch", "nonce", "boot_elapsed_ms"), values))
        terminal = re.fullmatch(r"PING6 SERVICE PASS child=exited sockets=0 probes=1 defenses=0 received=([0-9]+) malformed=0", lines[7])
        assert terminal and 2 <= int(terminal[1]) <= 128
        assert children == [b"3"] and raw.count(b"USER EXIT pid=3 status=0\n") == 1
        assert len(re.findall(rb"(?m)^USER (?:EXIT pid=3 status=|KILLED pid=3 by=)", raw)) == 1
        assert b"\nDURABLE WORKLOAD OK\nABSD BOOT OK\n" in raw and b"init: FAILED" not in raw
        ends = re.findall(rb"(?m)^EXTERNAL OUTPUT END bytes=(\d+) digest=([0-9a-f]{8})\n", raw)
        value = 0x811c9dc5
        for byte in output:
            value = ((value ^ byte) * 0x01000193) & 0xffffffff
        assert len(ends) == 1 and int(ends[0][0]) == len(output) and int(ends[0][1], 16) == value
    else:
        assert b"EXTERNAL OUTPUT END" not in raw and b"ABSD BOOT OK" not in raw
        assert b"init: FAILED at durable worker outcome\n" in raw and b"DURABLE WORKLOAD FAILED\n" in raw
        if case == "preassigned-conflict":
            assert text == "PING6 SERVICE ERROR DAD acquisition refused Dad(Conflict)\n" and not children
        else:
            lines = text.splitlines()
            assert len(lines) == 6
            trace = guest_clock_trace(lines, case, int(ticks[1]))
            assert lines[1:3] == [
                "PING6 DAD CLEAR local=fd00:ab5d::15 scope=1 auth=none uniqueness=unproven",
                "PING6 SERVICE READY scope=1 peer=fd00:ab5d::2 requests=1"]
            assert lines[5].removeprefix("PING6 SERVICE ERROR ") in NO_REPLY_ERRORS
            assert lines[5].startswith("PING6 SERVICE ERROR ") and children == [b"3"]
            terminal = re.findall(rb"(?m)^USER (?:EXIT pid=3 status=1|KILLED pid=3 by=2)\n", raw)
            assert len(terminal) == 1, "child normal refusal or owned kill/reap required"
            assert len(re.findall(rb"(?m)^USER (?:EXIT pid=3 status=|KILLED pid=3 by=)", raw)) == 1
    assert raw.count(b"USER EXIT pid=2 status=" + (b"0" if positive else b"1") + b"\n") == 1
    assert len(re.findall(rb"(?m)^USER EXIT pid=2 status=", raw)) == 1
    assert raw.count(b"DURABLE WORKER OUTCOME generation=1 pid=2 status=" + (b"0" if positive else b"1") + b"\n") == 1
    return {"output": text, "case": case, "observation": observation, "guest_clock_trace": trace, "NIC_counters": fields,
            "terminal_ticks": int(ticks[1]), "available_resources": "terminal frames/processes/cells/pipes=0; positive owner sockets=0",
            "authority_limit": "Positive nic=0/denied=1 and empty successful CLOSE ACK follow exact child/transact code checks, not separate pipe/NIC telemetry.",
            "time_limit": "Exact pinned PIT-tick to boot-ms conversion; no-reply requires DAD Expired after its untruncated active window. Successful local submission is not wire delivery; no physical RTT or host/boot mapping."}


def validate_peer(peer, case):
    assert peer["case"] == case and peer["transport"] == "Linux kernel ICMPv6; no userspace responder or packet injection"
    assert peer["namespace_inode"] > 0 and peer["sysctls"] == peer_settings(peer["tap"], case)
    links, addresses = peer["links"], peer["addresses"]
    assert len(links) == len(addresses) == 1
    link = links[0]
    assert link["mtu"] == 1500 and link["address"] == HOST_MAC.hex(":") and "UP" in link["flags"]
    assert link["ifname"] == addresses[0]["ifname"] == peer["tap"]
    assigned = addresses[0]["addr_info"]
    expected = {HOST_IP, *([GUEST_IP] if CASES[case]["preassigned_candidate"] else [])}
    assert {a["local"] for a in assigned} == expected and len(assigned) == len(expected)
    for address in assigned:
        assert address["family"] == "inet6" and address["prefixlen"] == 64
        assert not any(address.get(flag) is True or flag in address.get("flags", []) for flag in ("tentative", "dadfailed", "optimistic"))
    routes = peer["routes"]
    assert routes and all(r["dst"] == "fd00:ab5d::/64" and r["dev"] == peer["tap"] and "gateway" not in r for r in routes)
    assert not peer["sockets"].strip(), "no TCP/UDP sockets in owned namespace"


def peer_settings(tap, case):
    return {"net.ipv6.conf.all.disable_ipv6": "0", "net.ipv6.conf.default.disable_ipv6": "0",
            "net.ipv6.conf.all.forwarding": "0", "net.ipv6.conf.default.accept_ra": "0",
            "net.ipv6.conf.default.autoconf": "0", "net.ipv6.conf.default.dad_transmits": "0",
            "net.ipv6.icmp.echo_ignore_all": str(CASES[case]["echo_ignore_all"]),
            f"net.ipv6.conf.{tap}.accept_ra": "0", f"net.ipv6.conf.{tap}.autoconf": "0",
            f"net.ipv6.conf.{tap}.forwarding": "0", f"net.ipv6.conf.{tap}.hop_limit": "64",
            f"net.ipv6.conf.{tap}.ndisc_notify": "0"}


def inspect(capture, native, peer, case):
    validate_peer(peer, case)
    records, _ = original.capture_records(capture)
    assert all(a["timestamp"] <= b["timestamp"] for a, b in zip(records, records[1:]))
    census = [classify(record) for record in records]
    assert all(row["kind"] in ("linux-mldv2", "peer-nd", "guest-dad-ns", "linux-conflict-na", "echo-request", "echo-reply") for row in census), "unexplained frame anywhere in whole capture"
    by = {kind: [row["index"] for row in census if row["kind"] == kind] for kind in ("guest-dad-ns", "linux-conflict-na", "echo-request", "echo-reply")}
    assert len(by["guest-dad-ns"]) == 1, "one actual tentative guest probe"
    probe = by["guest-dad-ns"][0]
    ordinary = [row["index"] for row in census if row["direction"] == "outgoing" and row.get("source_ip") == GUEST_IP]
    # The fallback classifier records IP endpoints too, to cover Echo and DAD.
    ordinary += [r["index"] for r in records if r["frame"][6:12] == GUEST_MAC and len(r["frame"]) >= 54 and r["frame"][22:38] == GUEST]
    assert all(probe < at for at in ordinary), "ordinary candidate traffic before tentative probe"
    if case == "preassigned-conflict":
        assert len(by["linux-conflict-na"]) == 1 and probe < by["linux-conflict-na"][0]
        assert not ordinary and not by["echo-request"] and not by["echo-reply"]
        assert native["observation"] is None
    else:
        assert not by["linux-conflict-na"] and len(by["echo-request"]) == 1
        request = by["echo-request"][0]
        assert native["guest_clock_trace"]["submission"]["frame"] == records[request - 1]["frame"].hex(), "guest submission differs from complete captured Request"
        nd = [row for row in census if row["kind"] == "peer-nd"]
        assert any(a["direction"] == "outgoing" and a["icmpv6_type"] == 135 and any(
            b["direction"] == "incoming" and b["icmpv6_type"] == 136 and a["index"] < b["index"] < request for b in nd) for a in nd), "resolved ND before actual request"
        if case == "positive":
            assert len(by["echo-reply"]) == 1 and request < by["echo-reply"][0]
            req, rep = (records[i - 1]["frame"] for i in (request, by["echo-reply"][0]))
            assert req[58:] == rep[58:], "reply correlation differs from actual submitted Request"
            row = census[request - 1]
            assert native["observation"] is not None
            for key in ("identifier", "sequence", "instance", "epoch", "nonce"):
                assert native["observation"][key] == row[key], "native observation differs from wire: " + key
        else:
            assert not by["echo-reply"] and native["observation"] is None
    return {"capture": digest(capture), "census": census, "by_kind": by,
            "limit": "Complete raw frame/checksum/order/correlation evidence. One observation is code-mediated consumption; no unique peer identity, physical RTT or synchronized delivery claim."}


def reason_accounting(capture, serial, annotation_bytes, annotation, fields, census):
    """Accepted first-four destination correspondence applied to explicit Echo census.

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
    return {"schema": "absd-ipv6-echo-driver-reasons/1", "disposition": "FAIL" if failures or ambiguities else "PASS",
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


def run(args):
    assert os.geteuid() == 0, "owned disposable Linux VM root required"
    assert args.timeout + 45 < args.lease - time.time() <= 4 * 3600, "finite lease margin"
    work, deadline = args.work, time.monotonic() + args.timeout
    namespace, tap = "absdecho6-" + uuid.UUID(args.run_id).hex, "echo6-tap0"
    processes, logs, bounds, evaluated, retained = {}, [], {}, {}, {}
    attempted, created, errors = False, False, []
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

    def net(argv):
        return checked(["ip", "netns", "exec", namespace, *argv])

    def start(name, argv, process_env=None):
        path = work / (name + ".log")
        bounds[path] = MAX_LOG
        log = path.open("xb")
        logs.append(log)
        processes[name] = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                                           env=env if process_env is None else process_env)
        return processes[name]

    try:
        case_bytes = bounded(args.cases, 65536)
        manifest(case_bytes)
        proof_inputs = {"runner": identity(__file__, bounded(__file__, MAX_LOG)),
                        "cases": identity(args.cases, case_bytes), "accepted_helper": identity(_helper_path, _helper_bytes)}
        fact("CASE.json", {"run": args.run_id, "case": args.case, "contract": CASES[args.case], "manifest": proof_inputs["cases"]})
        (work / "echo-cases.json").write_bytes(case_bytes)
        evaluated["echo-cases.json"] = identity(work / "echo-cases.json", case_bytes)
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
        boot = b'insmod all_video\nset timeout=0\nmenuentry "ABSD IPv6 Echo" {\n multiboot2 /boot/absd-kernel durable=1 net nvme-write=absd\n boot\n}\n'
        (tree / "grub.cfg").write_bytes(boot)
        iso, disk = work / "native-ipv6-echo.iso", work / "native-ipv6-echo.img"
        bounds[iso], bounds[disk] = MAX_ISO, 2 << 20
        temporary = work / "iso-tmp"
        temporary.mkdir()
        builder = start("iso-build", ["grub-mkrescue", "-o", str(iso), str(tree.parent.parent)], dict(env, TMPDIR=str(temporary)))
        build_until = time.monotonic() + left(60)
        while builder.poll() is None:
            left(60)
            assert time.monotonic() < build_until, "ISO construction deadline"
            time.sleep(0.02)
        assert builder.returncode == 0
        iso_bytes = bounded(iso, MAX_ISO)
        extracted = iso_binding(iso_bytes, buffers["kernel"], boot)
        with disk.open("xb") as stream:
            stream.truncate(2 << 20)
        assert namespace not in [row.split()[0] for row in checked(["ip", "netns", "list"]).splitlines()]
        attempted = True
        checked(["ip", "netns", "add", namespace])
        created = True
        observed = {}
        settings = peer_settings(tap, args.case)
        for key, value in settings.items():
            if key.startswith("net.ipv6.conf." + tap + "."):
                continue
            net(["sysctl", "-qw", key + "=" + value])
        for argv in (["link", "set", "lo", "up"], ["tuntap", "add", "dev", tap, "mode", "tap"],
                     ["link", "set", tap, "address", HOST_MAC.hex(":")], ["link", "set", tap, "mtu", "1500"],
                     ["link", "set", tap, "addrgenmode", "none"], ["link", "set", tap, "up"]):
            checked(["ip", "-n", namespace, *argv])
        for key, value in settings.items():
            if key.startswith("net.ipv6.conf." + tap + "."):
                net(["sysctl", "-qw", key + "=" + value])
        for address in [HOST_IP, *([GUEST_IP] if CASES[args.case]["preassigned_candidate"] else [])]:
            checked(["ip", "-n", namespace, "-6", "addr", "add", address + "/64", "dev", tap, "nodad"])
        for key, value in settings.items():
            observed[key] = net(["sysctl", "-n", key]).strip()
            assert observed[key] == value
        def peer_state():
            return {"case": args.case, "transport": "Linux kernel ICMPv6; no userspace responder or packet injection",
                    "kernel": list(os.uname()), "namespace": namespace, "namespace_inode": os.stat("/run/netns/" + namespace).st_ino,
                    "tap": tap, "sysctls": {k: net(["sysctl", "-n", k]).strip() for k in settings},
                    "addresses": json.loads(net(["ip", "-j", "-6", "address", "show", "dev", tap])),
                    "links": json.loads(net(["ip", "-j", "link", "show", "dev", tap])),
                    "routes": json.loads(net(["ip", "-j", "-6", "route", "show"])),
                    "sockets": net(["ss", "-H", "-a", "-n", "-t", "-u"]),
                    "socket_inventory_scope": "TCP/UDP only. No raw userspace Echo responder is launched by this source; absence is not inferred from this inventory."}
        peer = peer_state()
        validate_peer(peer, args.case)
        assert peer["sysctls"] == settings
        fact("LINUX-PEER-BEFORE.json", peer)
        serial, capture = work / "native-ipv6-echo.serial.log", work / "native-ipv6-echo.pcap"
        bounds[serial], bounds[capture] = MAX_LOG, MAX_CAPTURE
        selected = shutil.which(args.qemu or os.environ.get("ABSD_QEMU", "qemu-system-x86_64"))
        assert selected, "QEMU unavailable"
        selected = str(Path(selected).resolve())
        qemu_identity = identity(selected, bounded(selected, MAX_ELF))
        argv = served_qemu(["ip", "netns", "exec", namespace, selected, "-accel", "tcg,thread=single", "-cpu", "max,vendor=GenuineIntel,+rdrand",
                "-smp", "1", "-m", "256M", "-cdrom", str(iso), "-drive", f"file={disk},format=raw,if=ide,index=0",
                "-display", "none", "-serial", f"file:{serial}", "-no-reboot", "-no-shutdown",
                "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-device", f"e1000,netdev=n0,mac={GUEST_MAC.hex(':')}",
                "-netdev", f"tap,id=n0,ifname={tap},script=no,downscript=no,vnet_hdr=off",
                "-object", f"filter-dump,id=cap0,netdev=n0,file={capture}"])
        marker = original.ReadyMarker(serial, capture)
        marker.poll(running=False)
        q = start("qemu", argv)
        fact("LAUNCH.json", {"run": args.run_id, "case": args.case, "argv": argv, "qemu_pid_pgid": q.pid,
                             "builder_pid_pgid": builder.pid, "selected_QEMU_or_launcher": qemu_identity,
                             "qemu_identity_limit": "This selected file may be an ABSD_QEMU launcher; its argv[0]/hash is not an inferred distro executable identity.",
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
        after = peer_state()
        validate_peer(after, args.case)
        assert after["sysctls"] == peer["sysctls"] and after["namespace_inode"] == peer["namespace_inode"]
        fact("LINUX-PEER-AFTER.json", after)
        raw_serial, raw_capture = bounded(serial, MAX_LOG), bounded(capture, MAX_CAPTURE)
        native = native_output(raw_serial, q.returncode, args.case)
        captured = inspect(raw_capture, native, peer, args.case)
        reasons = reason_accounting(raw_capture, raw_serial, sidecar_bytes, annotation, native["NIC_counters"], captured["census"])
        fact("NIC-REASON-ACCOUNTING.json", reasons)
        assert reasons["disposition"] == "PASS", (reasons["failures"], reasons["ambiguities"])
        evaluated.update({"iso-tree/boot/absd-kernel": identity(tree.parent / "absd-kernel", buffers["kernel"]),
                          "iso-tree/boot/grub/grub.cfg": identity(tree / "grub.cfg", boot), "native-ipv6-echo.iso": identity(iso, iso_bytes),
                          "native-ipv6-echo.serial.log": identity(serial, raw_serial), "native-ipv6-echo.pcap": identity(capture, raw_capture)})
        left(1)
        return {"schema": "absd-native-ipv6-echo-proof/1", "disposition": "PASS", "run": args.run_id, "case": args.case,
                "case_deadline_monotonic": deadline,
                "scope": "Fixed Linux-kernel Echo/DAD/no-response case; deliberately limited native coverage",
                "native": native, "capture_result": captured, "peer": peer, "peer_after": after, "reason_accounting": reasons,
                "evaluated_build_inputs": retained, "evaluated_artifacts": evaluated, "proof_inputs": proof_inputs, "unrun": UNRUN,
                "source_binding_limit": f"Exact clean {PRODUCT}/{KERNEL} source/build receipts, retained compiler logs and ELF/ISO buffers; no compiler-correctness proof.",
                "limits": "No exact no-reply retirement cause, global handle census, physical clock/RTT, unique authenticated peer, synchronized readiness/DMA, general IPv6 conformance or new native boundary-case claim."}
    finally:
        terminals = {}
        for name in ("qemu", "iso-build"):
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
        absent = None
        if attempted:
            try:
                listing = command(["ip", "netns", "list"])
                if namespace in [r.split()[0] for r in listing.splitlines()]:
                    assert not command(["ip", "netns", "pids", namespace]).strip(), "owned namespace retains processes"
                    command(["ip", "netns", "del", namespace])
                absent = namespace not in [r.split()[0] for r in command(["ip", "netns", "list"]).splitlines()]
                assert absent
            except BaseException as error:
                errors.append("namespace " + repr(error))
        for path, maximum in bounds.items():
            if path.exists() and path.stat().st_size > maximum:
                errors.append("output bound " + path.name)
        fact("LOCAL-CLEANUP.json", {"run": args.run_id, "namespace": namespace, "creation_attempted": attempted, "created": created,
                                    "namespace_absent": absent, "processes": terminals, "errors": errors,
                                    "disposition": "FAIL" if errors else "PASS", "not_attempted_limit": "No owned namespace mutation if creation_attempted=false; absence then not claimed.",
                                    "custody": "Root retains exact source/ELFs/ISO/raw/receipts through first native handoff or review2026-10-17, then retires ended substrate after dependency checks. No runtime keys created."})
        if errors:
            raise RuntimeError(errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path, help="new owned case directory; must not exist")
    parser.add_argument("--run-id", required=True, help="fresh UUID; also names the exact owned namespace")
    parser.add_argument("--case", choices=CASES, required=True)
    parser.add_argument("--cases", type=Path, default=Path(__file__).with_name("native-ipv6-echo-cases.json"))
    parser.add_argument("--kernel-elf", type=Path, required=True)
    parser.add_argument("--elf", type=Path, required=True, help="ipv6-echo-service-probe.elf embedded in kernel")
    parser.add_argument("--client-elf", type=Path, required=True, help="ping6-once.elf embedded in parent")
    parser.add_argument("--build-receipt", type=Path, required=True, help="strict d36/ed6 compiler/source/output/empty-input receipt")
    parser.add_argument("--lease-end", required=True, help="existing absolute UTC resource lease, timezone required")
    parser.add_argument("--timeout", type=int, default=120, help="10..180 seconds, ISO setup through evidence evaluation")
    parser.add_argument("--qemu", help="exact admitted QEMU/launcher path; otherwise ABSD_QEMU or qemu-system-x86_64")
    args = parser.parse_args()
    try:
        uuid.UUID(args.run_id)
        stamp = datetime.datetime.fromisoformat(args.lease_end.replace("Z", "+00:00"))
        assert stamp.tzinfo is not None and 10 <= args.timeout <= 180
    except (ValueError, AssertionError):
        parser.error("fresh UUID, timezone-bearing lease and 10..180 second timeout required")
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
        write(args.work / "RESULT.json", {"schema": "absd-native-ipv6-echo-proof/1", "disposition": "FAIL",
                                         "run": args.run_id, "case": args.case, "error": repr(error), "unrun": UNRUN})
        raise
    write(args.work / "RESULT.json", result)
    print("NATIVE IPV6 ECHO PROOF PASS case=" + args.case)


if __name__ == "__main__":
    main()
