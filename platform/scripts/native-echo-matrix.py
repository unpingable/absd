#!/usr/bin/env python3
"""One foreground native fixed ICMP Echo proof against the isolated Linux kernel.

Builds only an ISO from exact prebuilt ELF buffers. No userspace packet
responder, public peer, host route/service change or source compilation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import time
import uuid

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from served_ram import served_qemu

if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
    raise SystemExit("native-echo-matrix: optimized Python is refused")
ROOT = Path(__file__).resolve().parent.parent
HOST, GUEST = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 100])
HOST_MAC, GUEST_MAC = bytes.fromhex("525500000501"), bytes.fromhex("525400123456")
MAX_ELF, MAX_CAPTURE, MAX_LOG = 64 * 1024 * 1024, 2 * 1024 * 1024, 8 * 1024 * 1024
CHUNK = re.compile(rb"EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]*)\n")
UNRUN = ["native malformed/wrong-peer/type/code/id/sequence/body/epoch/nonce/checksum replies",
         "native queue/slot exhaustion, interruption, frame timeout and uncertain pipe effects",
         "native absent peer, deadline/boot rewind/link/device loss and queued retirement",
         "live SSH coexistence, hardware DMA, physical clock/wire RTT accuracy or authentication"]
BOUNDARY_PROFILE = "ipv4-echo-boundary-v1"
BOUNDARY_UNRUN = [UNRUN[0],
                  "native packet queue exhaustion",
                  "native queued or connected-data interruption, reply stall and uncertain pipe effects",
                  "native absent peer, frame expiry, clock rewind, link/device loss and wire replay",
                  "live SSH coexistence, full memory restoration, hardware DMA or physical timing"]
BOUNDARY_CTORS = (
    ("unspecified", 2, 0), ("loopback", 2, 0), ("multicast", 2, 0),
    ("local", 2, 0), ("subnet", 2, 0), ("broadcast", 2, 0), ("off-link", 2, 0),
    ("expired", 1, 0), ("too-long", 1, 0), ("entropy-error", 13, 0),
    ("entropy-zero", 13, 0), ("second-grant", 3, 1), ("closed-stale", 4, 0),
)
BOUNDARY_REQUESTS = tuple(bytes.fromhex(value) for value in (
    "00010000c0000201", "017f0000c0000201", "01010100c0000201",
    "01010001c0000201", "01010000c0000202", "01020000c0000202",
    "01030000c0000202",
))


def identity(label, data):
    return {"path": str(Path(label).resolve()), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def read_bound(path, bound):
    with Path(path).open("rb") as source:
        data = source.read(bound + 1)
    assert len(data) <= bound, f"input byte bound: {path}"
    return data


def write(path, value):
    with Path(path).open("x") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def peer_config(template, work):
    expected = (b"# Lane-owned isolated VM/network namespace only; invoke chronyd with -x -d.\n"
                b"# No upstream server/pool, RTC synchronization or system-clock adjustment.\n"
                b"bindaddress 192.0.2.1\nbinddevice sntp-tap0\nallow 192.0.2.100/32\n"
                b"local stratum 10\nport 123\ncmdport 0\nbindcmdaddress /\n"
                b"pidfile @PROOF_PIDFILE@\n")
    assert template == expected, "exact guest-only chrony fixture template"
    pidfile = Path(work).resolve() / "chronyd.pid"
    path = str(pidfile).encode("ascii")
    assert re.fullmatch(rb"/[A-Za-z0-9_./-]+", path), "PID pathname must be one safe configuration token"
    return template.replace(b"@PROOF_PIDFILE@", path), pidfile


def group_live(process):
    # Every producer starts a fresh session, whose process-group ID is its PID.
    try:
        os.killpg(process.pid, 0)
        return True
    except ProcessLookupError:
        return False


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def packet_records(path):
    data = read_bound(path, MAX_CAPTURE)
    assert len(data) >= 24, "capture header missing"
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(data[:4])
    assert endian is not None, "PCAP magic"
    major, minor, _, _, snaplen, link = struct.unpack(endian + "HHIIII", data[4:24])
    assert (major, minor, link) == (2, 4, 1) and snaplen >= 1514
    at, rows = 24, []
    while at < len(data):
        assert at + 16 <= len(data), "short capture record"
        sec, usec, size, original = struct.unpack(endian + "IIII", data[at:at + 16])
        at += 16
        assert usec < 1_000_000 and 14 <= size <= 1514 and size == original and at + size <= len(data), "capture record length/timestamp/truncation"
        rows.append((len(rows), [sec, usec], data[at:at + size]))
        assert len(rows) <= 256, "capture frame bound"
        at += size
    return data, rows


def native_output(raw, exit_status):
    assert exit_status == 3, f"QEMU exit {exit_status}"
    for needed in (b"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ",
                   b"\nDURABLE WORKLOAD OK\n", b"\nABSD BOOT OK\n", b"\nNETWORK LINK OK "):
        assert needed in raw, f"serial lacks {needed!r}"
    for bad in (b"PANIC", b"KERNEL FAULT", b"init: FAILED", b"NIC DISABLED"):
        assert bad not in raw, f"serial contains {bad!r}"
    output = bytearray()
    chunks = list(CHUNK.finditer(raw))
    assert len(chunks) == raw.count(b"EXTERNAL OUTPUT CHUNK"), "malformed output frame"
    for chunk in chunks:
        assert int(chunk[1], 16) == len(output), "output frame offset/order"
        output.extend(bytes.fromhex(chunk[2].decode("ascii")))
        assert len(output) <= 16384, "native output bound"
    output = output.decode("utf-8")
    observations = re.findall(
        r"^PING peer=192\.0\.2\.1 identifier=(\d+) sequence=(\d+) instance=(\d+) "
        r"epoch=(\d+) nonce=([0-9a-f]{16}) boot_rtt_ms=(\d+) auth=none denied=1 nic=0 requests=1$", output, re.M)
    done = "PING DONE child=exited sockets=0 requests=1\n"
    assert len(observations) == 1 and output.count(done) == 1 and output.endswith(done), "one exact observation and normal completion required"
    assert output.count("PING ") == 2, "unexpected native PING records"
    identifier, sequence, instance, epoch, nonce, rtt = observations[0]
    identifier, sequence, instance, epoch, rtt = map(int, (identifier, sequence, instance, epoch, rtt))
    nonce = int(nonce, 16)
    assert 1 <= identifier <= 65535 and 1 <= sequence <= 65535
    assert 1 <= instance < 2 ** 64 and 1 <= epoch < 2 ** 64 and nonce != 0
    assert 0 <= rtt < 8000, "observed boot RTT outside grant profile"
    stats = re.findall(rb"NIC STATS (.*)\n", raw)
    assert len(stats) == 1, "one final NIC accounting record required"
    counters = dict(field.split("=", 1) for field in stats[0].decode("ascii").split())
    assert int(counters["rx_frames"]) > 0 and int(counters["tx_frames"]) > 0
    assert all(int(counters[k]) == 0 for k in ("rx_refused", "rx_missed", "tx_refused", "tx_errors")), counters
    return {"identifier": identifier, "sequence": sequence, "instance": instance, "epoch": epoch,
            "nonce": nonce, "boot_rtt_ms": rtt, "auth": "none", "wrong_peer_denied": True,
            "child_nic": False, "child_exit": 0, "sockets_after_retirement": 0,
            "output": output, "NIC_counters": counters}


def boundary_fields(line, kind, keys):
    prefix = "ECHO BOUNDARY " + kind + " v=1 "
    assert line.startswith(prefix) and line.endswith("\n"), "boundary record " + kind
    tokens = line[len(prefix):-1].split(" ")
    assert all(re.fullmatch(r"[a-z_]+=[A-Za-z0-9_.:-]+", token) for token in tokens), "boundary field syntax"
    pairs = [token.split("=", 1) for token in tokens]
    fields = dict(pairs)
    assert len(fields) == len(pairs) and set(fields) == set(keys), "boundary field set " + kind
    return fields


def boundary_number(fields, key):
    value = fields[key]
    assert re.fullmatch(r"0|[1-9][0-9]*", value), "boundary decimal " + key
    number = int(value)
    assert number < 2 ** 64, "boundary integer range"
    return number


def native_boundary_output(raw, exit_status):
    # Validate the unchanged positive result against the original raw bytes.
    # Boundary records and the terminal digest are additional predicates; no
    # output is trimmed, rewritten or re-framed for the positive evaluator.
    observation = native_output(raw, exit_status)
    output = observation["output"]
    lines = output.splitlines(keepends=True)
    assert len(lines) == 29 and all(line.endswith("\n") for line in lines), "complete boundary record order/count"
    assert lines[27].startswith("PING peer=") and lines[28] == "PING DONE child=exited sockets=0 requests=1\n"
    begin = boundary_fields(lines[0], "BEGIN", ("start_ms", "until_ms", "negative_until_ms"))
    start, until, negative_until = (boundary_number(begin, key) for key in ("start_ms", "until_ms", "negative_until_ms"))
    assert until - start == 20_000 and 0 < negative_until - start <= 8_000, "original whole/negative bounds"
    constructors = []
    for line, (name, code, sockets) in zip(lines[1:14], BOUNDARY_CTORS):
        fields = boundary_fields(line, "CTOR", ("case", "code", "sockets"))
        assert fields == {"case": name, "code": str(code), "sockets": str(sockets)}, "constructor result/order"
        constructors.append(fields)

    def census(line, label):
        fields = boundary_fields(line, "CENSUS", ("label", "processes", "handles", "pipes", "cells", "frames"))
        assert fields.pop("label") == label, "census role/order"
        return {key: boundary_number(fields, key) for key in fields}

    before = census(lines[14], "before-negative")
    assert before["processes"] > 0 and before["handles"] > 0 and before["frames"] > 0
    bootstrap = boundary_fields(lines[15], "BOOTSTRAP", ("bytes", "hex"))
    expected_bootstrap = b"\x01\xc0\x00\x02\x01" + negative_until.to_bytes(8, "big")
    assert bootstrap == {"bytes": "13", "hex": expected_bootstrap.hex()}, "exact original negative bootstrap"
    prefix = boundary_fields(lines[16], "PREFIX", ("before_ms", "read_before_ms", "read_ms", "bytes", "hex", "sockets"))
    pre_read, read_before, read = (boundary_number(prefix, key) for key in ("before_ms", "read_before_ms", "read_ms"))
    assert prefix["bytes"] == "1" and prefix["hex"] == "00" and prefix["sockets"] == "1", "actual single partial byte and reserved socket"
    killed = boundary_fields(lines[17], "KILL", ("before_ms", "code", "at_ms"))
    assert killed["code"] == "0", "exact child kill result"
    kill_before = boundary_number(killed, "before_ms")
    kill_at = boundary_number(killed, "at_ms")
    reaped = boundary_fields(lines[18], "REAP", ("before_ms", "kind", "status", "at_ms"))
    assert reaped["kind"] == "3" and reaped["status"] == "0", "actual killed-child reap"
    reap_before = boundary_number(reaped, "before_ms")
    reap_at = boundary_number(reaped, "at_ms")
    eof = boundary_fields(lines[19], "EOF", ("before_ms", "at_ms", "bytes"))
    assert eof["bytes"] == "0", "actual request EOF read"
    eof_before, eof_at = (boundary_number(eof, key) for key in ("before_ms", "at_ms"))
    ledger = boundary_fields(lines[20], "LEDGER", ("read_bytes", "read_hex", "written_bytes", "written_hex", "link_sends"))
    expected_read = b"".join(BOUNDARY_REQUESTS) + b"\x00"
    expected_written = b"".join(bytes([1, request[1], 1 if index < 4 else 2, 0]) + bytes(44)
                                for index, request in enumerate(BOUNDARY_REQUESTS))
    assert ledger == {"read_bytes": "57", "read_hex": expected_read.hex(),
                      "written_bytes": "336", "written_hex": expected_written.hex(), "link_sends": "0"}, "exact actual request/reply ledger and zero delegated sends"
    retired = boundary_fields(lines[21], "RETIRED", ("at_ms", "request_eof", "result_eof", "channel", "sockets", "fallback", "stale_code"))
    assert {key: value for key, value in retired.items() if key != "at_ms"} == {
        "request_eof": "1", "result_eof": "1", "channel": "0", "sockets": "0", "fallback": "0", "stale_code": "4"}, "EOF-caused authority retirement"
    retire_at = boundary_number(retired, "at_ms")
    assert start <= pre_read <= read_before <= read <= kill_before <= kill_at <= reap_before <= reap_at <= eof_before <= eof_at <= retire_at < min(pre_read + 250, negative_until), "EOF retirement before original frame/grant expiry"
    after_negative = census(lines[22], "after-negative")
    positive = boundary_fields(lines[23], "POSITIVE", ("start_ms", "until_ms", "fresh", "sockets"))
    positive_start, positive_until = (boundary_number(positive, key) for key in ("start_ms", "until_ms"))
    assert positive["fresh"] == "1" and positive["sockets"] == "1", "fresh positive authority"
    assert retire_at <= positive_start < positive_until <= until and positive_until - positive_start <= 8_000, "separate original positive bounds"
    positive_reap = boundary_fields(lines[24], "POSITIVE-REAP", ("kind", "status", "request_eof", "result_eof", "at_ms"))
    assert {key: value for key, value in positive_reap.items() if key != "at_ms"} == {
        "kind": "1", "status": "0", "request_eof": "1", "result_eof": "1"}, "natural positive child and EOF"
    positive_at = boundary_number(positive_reap, "at_ms")
    after_positive = census(lines[25], "after-positive")
    done = boundary_fields(lines[26], "DONE", ("objects_restored", "sockets", "at_ms"))
    assert done["objects_restored"] == "1" and done["sockets"] == "0"
    done_at = boundary_number(done, "at_ms")
    assert positive_start <= positive_at < positive_until and positive_at <= done_at < until, "terminal observations within original bounds"
    for key in ("processes", "handles", "pipes", "cells"):
        assert before[key] == after_negative[key] == after_positive[key], "owned resource restoration " + key

    # Check the complete terminal stream, not just the decoded semantic rows.
    encoded = output.encode("utf-8")
    ends = re.findall(rb"(?m)^EXTERNAL OUTPUT END bytes=(\d+) digest=([0-9a-f]{8})\n", raw)
    digest = 0x811c9dc5
    for byte in encoded:
        digest = ((digest ^ byte) * 0x01000193) & 0xffffffff
    assert len(ends) == raw.count(b"EXTERNAL OUTPUT END ") == 1, "one native output END"
    assert int(ends[0][0]) == len(encoded) and int(ends[0][1], 16) == digest, "complete native output digest"
    assert raw.count(b"USER EXIT pid=2 status=0\n") == 1
    assert raw.count(b"DURABLE WORKER OUTCOME generation=1 pid=2 status=0\n") == 1
    children = re.findall(rb"(?m)^SPAWN OK pid=(\d+) parent=2 program=", raw)
    assert len(children) == len(set(children)) == 2, "exact two children"
    assert raw.count(b"USER EXIT pid=" + children[1] + b" status=0\n") == 1, "positive child normal exit"
    observation["boundary"] = {"constructors": constructors, "prefix": prefix, "kill": killed,
        "reap": reaped, "eof": eof, "ledger": ledger, "retirement": retired, "positive": positive,
        "positive_reap": positive_reap, "before": before, "after_negative": after_negative,
        "after_positive": after_positive, "done": done,
        "frame_accounting": "Observed frame counts only; no equality or full memory restoration claim."}
    return observation


def inspect(path, observation, *, directional=False):
    capture, frames = packet_records(path)
    requests, replies, arp, census = [], [], [], []
    for index, timestamp, frame in frames:
        source_mac, target_mac = frame[6:12], frame[:6]
        assert source_mac in (HOST_MAC, GUEST_MAC), "unexplained Ethernet source"
        outgoing = source_mac == GUEST_MAC
        row = {"index": index, "timestamp": timestamp, "bytes": len(frame),
               "sha256": hashlib.sha256(frame).hexdigest(), "outgoing": outgoing}
        if frame[12:14] == b"\x08\x06":
            assert len(frame) in (42, 60) and not any(frame[42:]), "ARP frame length/padding"
            assert frame[14:20] == bytes([0, 1, 8, 0, 6, 4]) and frame[22:28] == source_mac
            operation = int.from_bytes(frame[20:22], "big")
            sender, target, target_hw = frame[28:32], frame[38:42], frame[32:38]
            assert (sender, target) == ((GUEST, HOST) if outgoing else (HOST, GUEST)), "unrelated ARP tuple"
            peer_mac = HOST_MAC if outgoing else GUEST_MAC
            if operation == 1:
                if directional and outgoing:
                    # The accepted pinned-smoltcp path broadcasts both fields.
                    assert target_mac == target_hw == b"\xff" * 6, "guest ARP request destination/target hardware"
                else:
                    assert target_mac in (b"\xff" * 6, peer_mac) and target_hw == b"\0" * 6, "ARP request destination"
            else:
                assert operation == 2 and target_mac == target_hw == peer_mac, "ARP reply destination"
            row["kind"] = "arp-request" if operation == 1 else "arp-reply"
            arp.append({"index": index, "operation": operation, "outgoing": outgoing,
                        "sender": sender.hex(), "target": target.hex()})
        else:
            assert frame[12:14] == b"\x08\x00" and len(frame) >= 34 and frame[14] == 0x45, "unexplained frame"
            assert target_mac == (HOST_MAC if outgoing else GUEST_MAC), "IPv4 MAC destination"
            size = int.from_bytes(frame[16:18], "big")
            assert size == 60 and len(frame) == 74 and checksum(frame[14:34]) == 0, "IPv4 length/checksum"
            assert int.from_bytes(frame[20:22], "big") & 0x3fff == 0 and frame[22] > 0, "IPv4 fragment/TTL"
            assert frame[23] == 1 and (frame[26:30], frame[30:34]) == ((GUEST, HOST) if outgoing else (HOST, GUEST)), "ungranted IPv4 protocol/peer"
            packet = frame[34:]
            assert packet[:2] == (b"\x08\0" if outgoing else b"\0\0") and checksum(packet) == 0, "Echo type/code/checksum"
            assert packet[8:16] == b"ABSDPING", "fixed body magic"
            fields = {"identifier": int.from_bytes(packet[4:6], "big"), "sequence": int.from_bytes(packet[6:8], "big"),
                      "instance": int.from_bytes(packet[16:24], "big"), "epoch": int.from_bytes(packet[24:32], "big"),
                      "nonce": int.from_bytes(packet[32:40], "big")}
            assert all(fields[key] == observation[key] for key in fields), "native/captured identifier/sequence/instance/epoch/nonce correlation"
            record = {"index": index, "hex": packet.hex(), **fields}
            (requests if outgoing else replies).append(record)
            assert len(requests) <= 1 and len(replies) <= 1, "one request/reply only; no retry or duplicates"
            row["kind"] = "echo-request" if outgoing else "echo-reply"
        census.append(row)
    assert len(requests) == len(replies) == 1, "one native request and Linux-kernel reply required"
    assert requests[0]["index"] < replies[0]["index"], "reply precedes request"
    assert bytes.fromhex(requests[0]["hex"])[4:] == bytes.fromhex(replies[0]["hex"])[4:], "exact reflected data"
    assert any(a["outgoing"] and a["operation"] == 1 and
               any(not b["outgoing"] and b["operation"] == 2 and
                   a["index"] < b["index"] < requests[0]["index"] for b in arp) for a in arp), "paired Linux ARP reply before Echo required"
    return {"capture": identity(path, capture), "ARP": arp, "request": requests[0], "reply": replies[0], "census": census}


def run(args, work):
    assert os.geteuid() == 0, "requires root inside the owned disposable VM"
    deadline = time.monotonic() + args.timeout
    namespace, tap = "absdecho-" + uuid.uuid4().hex, "echo-tap0"
    processes, logs, errors, bounds = {}, [], [], {}
    creation_attempted, created, namespace_absent = False, False, False
    process_env = {key: value for key, value in os.environ.items()
                   if key not in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "NOTIFY_SOCKET")}

    def check_bounds():
        for path, bound in bounds.items():
            assert not path.exists() or path.stat().st_size <= bound, f"output byte bound: {path.name}"

    def left(maximum):
        check_bounds()
        remaining = deadline - time.monotonic()
        assert remaining > 0, "outer wall deadline"
        return min(maximum, remaining)

    def checked(argv):
        result = subprocess.run(argv, check=True, text=True, capture_output=True,
                                timeout=left(5), env=process_env)
        assert len(result.stdout) + len(result.stderr) <= 65536, "control command output bound"
        return result

    def start(name, argv, env=None):
        path = work / (name + ".log")
        bounds[path] = MAX_LOG
        log = path.open("xb")
        logs.append(log)
        processes[name] = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                                           start_new_session=True, env=process_env if env is None else env)
        return processes[name]

    try:
        input_paths = [("kernel", args.kernel_elf), ("parent", args.elf),
                       ("child", args.client_elf)]
        if args.profile == BOUNDARY_PROFILE:
            input_paths.append(("boundary_child", args.boundary_client_elf))
        buffers = {name: read_bound(path, MAX_ELF) for name, path in input_paths}
        assert all(data.startswith(b"\x7fELF") and len(data) >= 64 for data in buffers.values()), "ELF input magic/size"
        assert buffers["parent"].count(buffers["child"]) == 1 and buffers["kernel"].count(buffers["parent"]) == 1 and buffers["kernel"].count(buffers["child"]) == 1, "exact unique child/parent/kernel embedding"
        if args.profile == BOUNDARY_PROFILE:
            assert buffers["boundary_child"] != buffers["child"], "distinct negative and positive consumers"
            assert buffers["parent"].count(buffers["boundary_child"]) == 1 and buffers["kernel"].count(buffers["boundary_child"]) == 1, "exact unique boundary child embedding"
        inputs = {name: identity(path, buffers[name]) for name, path in input_paths}
        tree = work / "iso-tree/boot/grub"
        tree.mkdir(parents=True)
        (tree.parent / "absd-kernel").write_bytes(buffers["kernel"])
        boot_config = b'insmod all_video\nset timeout=0\nmenuentry "ABSD Echo" {\n multiboot2 /boot/absd-kernel durable=1 net nvme-write=absd\n boot\n}\n'
        (tree / "grub.cfg").write_bytes(boot_config)
        iso, disk = work / "native-echo.iso", work / "native-echo.img"
        bounds[iso], bounds[disk] = 128 * 1024 * 1024, 2 * 1024 * 1024
        temporary = work / "iso-tmp"
        temporary.mkdir()
        builder = start("iso-build", ["grub-mkrescue", "-o", str(iso), str(tree.parent.parent)],
                        env=dict(process_env, TMPDIR=str(temporary)))
        build_deadline = time.monotonic() + left(60)
        while builder.poll() is None:
            left(60)
            assert time.monotonic() < build_deadline, "ISO construction deadline"
            time.sleep(0.05)
        assert builder.returncode == 0, "ISO construction failed"
        check_bounds()
        with disk.open("xb") as output:
            output.truncate(2 * 1024 * 1024)
        assert not any(line.split()[0] == namespace for line in checked(["ip", "netns", "list"]).stdout.splitlines())
        creation_attempted = True
        checked(["ip", "netns", "add", namespace])
        created = True
        for key in ("net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1",
                    "net.ipv4.icmp_echo_ignore_all=0"):
            checked(["ip", "netns", "exec", namespace, "sysctl", "-qw", key])
        for command in (["link", "set", "lo", "up"], ["tuntap", "add", "dev", tap, "mode", "tap"],
                        ["link", "set", tap, "address", HOST_MAC.hex(":")],
                        ["addr", "add", "192.0.2.1/24", "dev", tap], ["link", "set", tap, "up"]):
            checked(["ip", "-n", namespace, *command])
        address = json.loads(checked(["ip", "-n", namespace, "-j", "address", "show", "dev", tap]).stdout)
        assert len(address) == 1 and "UP" in address[0]["flags"] and address[0]["address"] == HOST_MAC.hex(":"), "exact owned TAP"
        assigned = address[0]["addr_info"]
        assert len(assigned) == 1 and assigned[0]["family"] == "inet" and assigned[0]["local"] == "192.0.2.1" and assigned[0]["prefixlen"] == 24, "exact IPv4-only peer address"
        routes = json.loads(checked(["ip", "-n", namespace, "-j", "-4", "route", "show"]).stdout)
        assert len(routes) == 1 and routes[0]["dst"] == "192.0.2.0/24" and routes[0]["dev"] == tap and routes[0]["scope"] == "link", "only namespace connected route"
        sysctls = {}
        for key, expected in (("net.ipv4.icmp_echo_ignore_all", "0"), ("net.ipv6.conf.all.disable_ipv6", "1"),
                              ("net.ipv6.conf.default.disable_ipv6", "1")):
            value = checked(["ip", "netns", "exec", namespace, "sysctl", "-n", key]).stdout.strip()
            assert value == expected, "namespace peer setting " + key
            sysctls[key] = value
        peer = {"scope": "CONFIGURED_LINUX_KERNEL_ECHO; no control query or userspace responder",
                "kernel": list(os.uname()), "namespace": namespace,
                "network_namespace_inode": os.stat("/run/netns/" + namespace).st_ino,
                "address": address, "routes": routes, "sysctls": sysctls}
        write(work / "LINUX-PEER.json", peer)
        serial, capture = work / "native-echo.serial.log", work / "native-echo.pcap"
        bounds[serial], bounds[capture] = MAX_LOG, MAX_CAPTURE
        qemu_binary = shutil.which(os.environ.get("ABSD_QEMU", "qemu-system-x86_64"))
        assert qemu_binary, "QEMU unavailable"
        command = served_qemu(["ip", "netns", "exec", namespace, str(Path(qemu_binary).resolve()),
                   "-accel", "tcg,thread=single", "-cpu", "max,vendor=GenuineIntel,+rdrand", "-smp", "1", "-m", "256M",
                   "-cdrom", str(iso), "-drive", f"file={disk},format=raw,if=ide,index=0", "-display", "none",
                   "-serial", f"file:{serial}", "-no-reboot", "-no-shutdown", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
                   "-device", f"e1000,netdev=n0,mac={GUEST_MAC.hex(':')}", "-netdev", f"tap,id=n0,ifname={tap},script=no,downscript=no,vnet_hdr=off",
                   "-object", f"filter-dump,id=cap0,netdev=n0,file={capture}"])
        iso_identity = identity(iso, read_bound(iso, bounds[iso]))
        qemu = start("qemu", command)
        launch_schema = "absd-native-echo-boundary-launch/1" if args.profile == BOUNDARY_PROFILE else "absd-native-echo-launch/1"
        write(work / "LAUNCH.json", {"schema": launch_schema, "profile": args.profile, "namespace": namespace,
              "tap": tap, "qemu_pid_and_pgid": qemu.pid, "iso_builder_pid_and_pgid": builder.pid,
              "QEMU_command": command, "inputs": inputs, "ISO": iso_identity,
              "runner": identity(__file__, read_bound(__file__, MAX_LOG)), "Linux_peer": peer,
              "execution_host": list(os.uname()), "runner_pid": os.getpid(), "runner_uid": os.geteuid(),
              "environment_omitted": ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "NOTIFY_SOCKET"],
              "outer_timeout_seconds": args.timeout, "source_to_ELF_limit": "Exact input bytes and embedding only; compiler/source receipts are separately required."})
        while qemu.poll() is None:
            left(args.timeout)
            time.sleep(0.05)
        left(args.timeout)
        raw_serial = read_bound(serial, MAX_LOG)
        observation = (native_boundary_output(raw_serial, qemu.returncode)
                       if args.profile == BOUNDARY_PROFILE else native_output(raw_serial, qemu.returncode))
        captured = inspect(capture, observation, directional=args.profile == BOUNDARY_PROFILE)
        scope = ("native constructor and fixed IPC refusals, one-slot exhaustion, actual partial-request child kill/reap and EOF retirement, then fresh Linux-kernel Echo"
                 if args.profile == BOUNDARY_PROFILE else "one fixed native ICMP Echo request and independent Linux-kernel reply")
        result = {"disposition": "PASS", "scope": scope,
                  "profile": args.profile, "observation": observation, "capture_result": captured,
                  "unrun": BOUNDARY_UNRUN if args.profile == BOUNDARY_PROFILE else UNRUN,
                  "evaluated_artifacts": {"native-echo.iso": iso_identity,
                      "iso-tree/boot/absd-kernel": inputs["kernel"],
                      "iso-tree/boot/grub/grub.cfg": identity(tree / "grub.cfg", boot_config),
                      "native-echo.serial.log": identity(serial, raw_serial),
                      "native-echo.pcap": captured["capture"]},
                  "limits": ("Finite native IPC/constructor negatives and measured EOF retirement only; malformed wire replies, replay, physical accuracy, authenticated identity, future reachability, hardware transfer and full memory restoration remain unqualified. Non-atomic I/O can retain an already-submitted first effect."
                             if args.profile == BOUNDARY_PROFILE else
                             "Scheduled boot-domain RTT/deadlines and captured order only; no physical accuracy, authenticated identity, future reachability, hardware transfer or native negative-case claim. Non-atomic I/O can retain an already-submitted first effect.")}
        left(args.timeout)
        return result
    finally:
        terminal, group_terminal = {}, {}
        for name in ("qemu", "iso-build"):
            process = processes.get(name)
            try:
                if process is not None and group_live(process):
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    stop_at = time.monotonic() + 3
                    while (process.poll() is None or group_live(process)) and time.monotonic() < stop_at:
                        time.sleep(0.05)
                    if process.poll() is None or group_live(process):
                        errors.append(name + " required SIGKILL after shutdown deadline")
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        stop_at = time.monotonic() + 3
                        while (process.poll() is None or group_live(process)) and time.monotonic() < stop_at:
                            time.sleep(0.05)
                terminal[name] = None if process is None else process.poll()
                group_terminal[name] = process is None or not group_live(process)
                if process is not None and terminal[name] is None:
                    errors.append(name + " not terminal")
                if not group_terminal[name]:
                    errors.append(name + " session process group remains live")
            except BaseException as error:
                errors.append(name + ": " + repr(error))
        for log in logs:
            log.close()
        if creation_attempted:
            try:
                listing = subprocess.run(["ip", "netns", "list"], check=True, capture_output=True, text=True, timeout=5, env=process_env).stdout
                if any(line.split()[0] == namespace for line in listing.splitlines()):
                    pids = subprocess.run(["ip", "netns", "pids", namespace], check=True, capture_output=True, text=True, timeout=5, env=process_env).stdout
                    assert not pids.strip(), "namespace retains live processes; no unknown process is killed"
                    subprocess.run(["ip", "netns", "del", namespace], check=True, capture_output=True, timeout=5, env=process_env)
                    listing = subprocess.run(["ip", "netns", "list"], check=True, capture_output=True, text=True, timeout=5, env=process_env).stdout
                namespace_absent = not any(line.split()[0] == namespace for line in listing.splitlines())
                assert namespace_absent, "namespace remains after deletion"
            except BaseException as error:
                errors.append("namespace: " + repr(error))
        try:
            check_bounds()
        except BaseException as error:
            errors.append("final output bounds: " + repr(error))
        write(work / "LOCAL-CLEANUP.json", {"schema": "absd-native-echo-cleanup/1", "namespace": namespace,
              "creation_attempted": creation_attempted, "created": created, "namespace_absent": namespace_absent,
              "process_exit_status": terminal, "owned_session_process_groups_terminal": group_terminal,
              "errors": errors, "disposition": "FAIL" if errors else "PASS",
              "custody": "Root/resource owner retains exact ELFs, ISO, serial, raw PCAP and receipts until independent review/replay ends; then retires exact staging/scratch after dependency checks. Review 2026-10-17. No keys or provider resources created."})
        if errors:
            raise RuntimeError(errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path, help="fresh output path; must not exist")
    parser.add_argument("--kernel-elf", type=Path, required=True)
    parser.add_argument("--elf", type=Path, required=True, help="echo-service-probe.elf embedded in kernel")
    parser.add_argument("--client-elf", type=Path, required=True, help="ping-once.elf embedded in parent")
    parser.add_argument("--profile", choices=("positive-v1", BOUNDARY_PROFILE), default="positive-v1")
    parser.add_argument("--boundary-client-elf", type=Path, help="negative child embedded in the boundary parent")
    parser.add_argument("--timeout", type=int, default=120, help="outer wall timeout, setup through evidence inspection")
    args = parser.parse_args()
    if (args.profile == BOUNDARY_PROFILE) != (args.boundary_client_elf is not None):
        parser.error("--boundary-client-elf is required exactly for the boundary profile")
    if not 10 <= args.timeout <= 180:
        parser.error("timeout must be 10..180 seconds")
    work = args.work.resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=False)

    def stopped(_signum, _frame):
        raise KeyboardInterrupt("runner terminated")

    signal.signal(signal.SIGTERM, stopped)
    signal.signal(signal.SIGINT, stopped)
    schema = "absd-native-echo-boundary-proof/1" if args.profile == BOUNDARY_PROFILE else "absd-native-echo-proof/1"
    unrun = BOUNDARY_UNRUN if args.profile == BOUNDARY_PROFILE else UNRUN
    try:
        result = run(args, work)
        artifacts = {}
        for name, bound in (("iso-tree/boot/absd-kernel", MAX_ELF), ("iso-tree/boot/grub/grub.cfg", 4096),
                            ("native-echo.iso", 128 * 1024 * 1024), ("native-echo.img", 2 * 1024 * 1024),
                            ("native-echo.serial.log", MAX_LOG), ("native-echo.pcap", MAX_CAPTURE),
                            ("qemu.log", MAX_LOG), ("iso-build.log", MAX_LOG), ("LINUX-PEER.json", 65536),
                            ("LAUNCH.json", 65536), ("LOCAL-CLEANUP.json", 65536)):
            path = work / name
            artifacts[name] = identity(path, read_bound(path, bound))
            if name in result["evaluated_artifacts"]:
                expected = result["evaluated_artifacts"][name]
                assert all(artifacts[name][key] == expected[key] for key in ("bytes", "sha256")), "boot/evaluated artifact changed before final seal: " + name
        result["artifacts"] = artifacts
    except BaseException as error:
        write(work / "RESULT.json", {"schema": schema, "profile": args.profile, "disposition": "FAIL", "error": repr(error), "unrun": unrun})
        raise
    write(work / "RESULT.json", {"schema": schema, **result})
    print("NATIVE ECHO PROOF PASS")


if __name__ == "__main__":
    main()


