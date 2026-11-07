#!/usr/bin/env python3
"""Native IPv4 Echo wire refusals and a fresh Linux-kernel calibration.

The opt-in owner-path fixture is separate from the child/pipe boundary proof.
All selected Ethernet bytes must match actual native receive records as well
as the full capture. The peer sends nine negatives; Linux answers the positive.
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
    raise SystemExit("native-echo-wire-matrix: optimized Python is refused")

SCRIPTS = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


base = module("echo_wire_base", SCRIPTS / "native-echo-matrix.py")
peer = module("echo_wire_peer", SCRIPTS / "native-echo-wire-peer.py")
from served_ram import served_qemu
UNRUN = ["wire replay or authenticated identity", "packet queue exhaustion or connected-data interruption",
         "absent peer, native expiry, boot-clock rewind or link/device failure",
         "full ICMP conformance, live SSH coexistence, full memory/DMA restoration or physical timing"]
LIMITS = ("Finite native owner-path wire cases only; no new child/IPC proof. Echo is unauthenticated, "
          "and matching wire bytes do not establish generation provenance. Observed boot clocks "
          "are distinct from capture clocks. No full memory, hardware transfer or physical RTT claim.")


def number(row, name):
    assert re.fullmatch(r"0|[1-9][0-9]*", row[name]), "canonical integer: " + name
    value = int(row[name])
    assert value < 2 ** 64, "u64 bound: " + name
    return value


def parsed_line(line):
    match = re.fullmatch(r"ECHO WIRE ([A-Z]+) (.*)", line)
    assert match, "unexpected native output row"
    values = {}
    for part in match[2].split(" "):
        assert part.count("=") == 1, "native key/value layout"
        key, value = part.split("=")
        assert key and value and key not in values, "duplicate or empty native field"
        values[key] = value
    assert values.get("v") == "1", "native wire schema version"
    return match[1], values


def native_output(raw, exit_status):
    assert exit_status == 3, "natural QEMU debug-exit"
    for marker in (b"\nNETWORK LINK OK ", b"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ",
                   b"\nDURABLE WORKLOAD OK\n", b"\nABSD BOOT OK\n"):
        assert marker in raw, "missing native terminal marker"
    for bad in (b"PANIC", b"KERNEL FAULT", b"init: FAILED", b"NIC DISABLED"):
        assert bad not in raw, "failed native execution"
    output = bytearray()
    chunks = list(base.CHUNK.finditer(raw))
    assert len(chunks) == raw.count(b"EXTERNAL OUTPUT CHUNK"), "malformed native chunk"
    for chunk in chunks:
        assert int(chunk[1], 16) == len(output), "native chunk offset/order"
        output.extend(bytes.fromhex(chunk[2].decode()))
        assert len(output) <= 65536, "decoded output bound"
    digest = 0x811c9dc5
    for value in output:
        digest = ((digest ^ value) * 0x1000193) & 0xffffffff
    ends = re.findall(rb"(?m)^EXTERNAL OUTPUT END bytes=(\d+) digest=([0-9a-f]{8})\n", raw)
    assert len(ends) == raw.count(b"EXTERNAL OUTPUT END ") == 1, "one native END"
    assert ends[0] == (str(len(output)).encode(), f"{digest:08x}".encode()), "complete native bytes/FNV"
    assert output.endswith(b"\n"), "complete last native row"
    records = [parsed_line(line) for line in output.decode("ascii").splitlines()]
    assert records and records[0][0] == "BEGIN" and records[-1][0] == "DONE", "native record endpoints"
    unique = {}
    frames, cases = [], []
    phase, last, ordinals = "negative", 0, {"tx": 0, "rx": 0}
    expected_keys = {
        "BEGIN": {"v", "start_ms", "until_ms", "negative_until_ms", "cases"},
        "FRAME": {"v", "direction", "ordinal", "phase", "at_ms", "bytes", "hex"},
        "CASE": {"v", "index", "case", "receive_ordinal", "at_ms", "code", "observations", "sockets", "requests"},
        "RETIRED": {"v", "at_ms", "stale_code", "sockets", "requests"},
        "POSITIVE": {"v", "start_ms", "until_ms", "fresh", "sockets"},
        "OBSERVED": {"v", "at_ms", "identifier", "sequence", "instance", "epoch", "nonce", "boot_rtt_ms", "auth", "requests", "sockets"},
        "DONE": {"v", "at_ms", "sockets", "negative_cases", "observations"},
    }
    for tag, row in records:
        assert tag in expected_keys and set(row) == expected_keys[tag], "exact native field set: " + tag
        at = number(row, "start_ms" if tag in ("BEGIN", "POSITIVE") else "at_ms")
        assert at >= last, "monotone native observations"
        last = at
        if tag == "FRAME":
            direction = row["direction"]
            assert direction in ordinals and row["phase"] == phase, "native frame phase/direction"
            assert "RETIRED" not in unique or phase == "positive", "no negative frame after retirement"
            ordinals[direction] += 1
            assert number(row, "ordinal") == ordinals[direction], "native per-direction ordinal"
            assert ordinals[direction] <= (32 if direction == "rx" else 16), "native frame bound"
            frame = bytes.fromhex(row["hex"])
            assert row["hex"] == frame.hex() and len(frame) == number(row, "bytes") and 14 <= len(frame) <= 1514
            frames.append(row)
        elif tag == "CASE":
            index = len(cases)
            assert index < 9 and number(row, "index") == index and row["case"] == peer.CASES[index], "ordered native cases"
            assert phase == "negative" and "RETIRED" not in unique, "negative before retirement"
            assert (row["code"], row["observations"], row["sockets"], row["requests"]) == ("5", "0", "1", "1"), "actual Again/no observation"
            witness = [f for f in frames if f["direction"] == "rx" and f["ordinal"] == row["receive_ordinal"]]
            assert len(witness) == 1 and witness[0]["phase"] == "negative", "case actual ingress witness"
            assert number(witness[0], "at_ms") <= at, "ingress before case result"
            if cases:
                assert number(row, "receive_ordinal") > number(cases[-1], "receive_ordinal"), "distinct ordered case receives"
            cases.append(row)
        else:
            assert tag not in unique, "duplicate native terminal/header row"
            if tag == "RETIRED":
                assert len(cases) == 9 and (row["stale_code"], row["sockets"], row["requests"]) == ("4", "0", "1"), "negative authority retired"
            elif tag == "POSITIVE":
                assert "RETIRED" in unique and row["fresh"] == "1" and row["sockets"] == "1", "fresh positive authority"
                phase = "positive"
            elif tag == "OBSERVED":
                assert phase == "positive" and row["auth"] == "none" and row["requests"] == "1" and row["sockets"] == "0", "one positive observation"
            elif tag == "DONE":
                assert "OBSERVED" in unique and (row["sockets"], row["negative_cases"], row["observations"]) == ("0", "9", "1"), "native final counts"
            unique[tag] = row
    assert set(unique) == {"BEGIN", "RETIRED", "POSITIVE", "OBSERVED", "DONE"} and len(cases) == 9
    begin, retired, positive, observed, done = (unique[k] for k in ("BEGIN", "RETIRED", "POSITIVE", "OBSERVED", "DONE"))
    start, until, negative_until = (number(begin, k) for k in ("start_ms", "until_ms", "negative_until_ms"))
    assert begin["cases"] == "9" and until - start == 20000 and negative_until - start == 8000, "original whole/negative bounds"
    pstart, puntil = number(positive, "start_ms"), number(positive, "until_ms")
    assert start <= number(retired, "at_ms") < negative_until and pstart >= number(retired, "at_ms")
    assert puntil - pstart == 8000 and puntil <= until, "original positive bounds"
    for frame in frames:
        assert number(frame, "at_ms") < (negative_until if frame["phase"] == "negative" else puntil), "actual frame within original grant"
    assert pstart <= number(observed, "at_ms") <= number(done, "at_ms") < min(puntil, until)
    assert 0 <= number(observed, "boot_rtt_ms") < 8000
    assert number(observed, "boot_rtt_ms") <= number(observed, "at_ms") - pstart, "local RTT fits positive history"
    for key in ("identifier", "sequence", "instance", "epoch"):
        assert number(observed, key) > 0
    assert number(observed, "identifier") <= 65535 and number(observed, "sequence") <= 65535
    assert re.fullmatch(r"[0-9a-f]{16}", observed["nonce"]) and int(observed["nonce"], 16) != 0
    assert raw.count(b"USER EXIT pid=2 status=0\n") == raw.count(b"DURABLE WORKER OUTCOME generation=1 pid=2 status=0\n") == 1
    assert raw.count(b"SPAWN OK pid=2 parent=1 program=external-workload\n") == 1
    assert re.findall(rb"(?m)^DURABLE WORKER GENERATION (.*)\n", raw) == [b"generation=1 pid=2"]
    assert raw.count(b"EXTERNAL OUTPUT BEGIN encoding=hex\n") == 1
    assert not re.search(rb"(?m)^SPAWN OK pid=\d+ parent=2 ", raw), "owner-only fixture has no child"
    stats = re.findall(rb"(?m)^NIC STATS (.*)\n", raw)
    assert len(stats) == 1
    counters = peer.fields(stats[0].decode())
    assert set(counters) == {"rx_frames", "rx_refused", "rx_missed", "tx_frames", "tx_refused", "tx_errors", "flags"}
    assert all(counters[k] == "0" for k in ("rx_refused", "rx_missed", "tx_refused", "tx_errors")) and counters["flags"] == "1"
    assert number(counters, "rx_frames") == ordinals["rx"] and number(counters, "tx_frames") == ordinals["tx"], "raw/native NIC census"
    return {"output": output.decode(), "records": len(records), "frames": frames, "cases": cases,
            "begin": begin, "retired": retired, "positive": positive, "observed": observed,
            "done": done, "NIC_counters": counters, "output_bytes": len(output), "FNV32": f"{digest:08x}"}


def inspect_frames(rows, native):
    outgoing, incoming, arp, census = [], [], [], []
    by_direction = {"tx": [], "rx": []}
    for index, timestamp, frame in rows:
        assert frame[6:12] in (peer.GUEST_MAC, peer.PEER_MAC), "capture Ethernet source"
        direction = "tx" if frame[6:12] == peer.GUEST_MAC else "rx"
        by_direction[direction].append(frame)
        census.append({"index": index, "timestamp": timestamp, "direction": direction,
                       "bytes": len(frame), "sha256": hashlib.sha256(frame).hexdigest()})
        if frame[12:14] == b"\x08\x06":
            assert len(frame) in (42, 60) and not any(frame[42:]), "ARP length/padding"
            assert frame[14:20] == bytes((0, 1, 8, 0, 6, 4)) and frame[22:28] == frame[6:12]
            out = direction == "tx"
            assert (frame[28:32], frame[38:42]) == ((peer.GUEST_IP, peer.PEER_IP) if out else (peer.PEER_IP, peer.GUEST_IP))
            op = int.from_bytes(frame[20:22], "big")
            destination = peer.PEER_MAC if out else peer.GUEST_MAC
            if op == 1:
                if out:
                    assert frame[:6] == frame[32:38] == b"\xff" * 6, "accepted directional guest ARP"
                else:
                    assert frame[:6] in (destination, b"\xff" * 6) and frame[32:38] == bytes(6)
            else:
                assert op == 2 and frame[:6] == frame[32:38] == destination
            arp.append({"index": index, "direction": direction, "operation": op})
        else:
            assert frame[12:14] == b"\x08\x00" and len(frame) == 74 and frame[14] == 0x45
            assert frame[:6] == (peer.PEER_MAC if direction == "tx" else peer.GUEST_MAC)
            assert frame[16:18] == b"\x00\x3c" and peer.checksum(frame[14:34]) == 0
            assert int.from_bytes(frame[20:22], "big") & 0x3fff == 0 and frame[22] > 0 and frame[23] == 1
            (outgoing if direction == "tx" else incoming).append((index, frame))
    assert len(outgoing) == 2 and len(incoming) == 10, "exact two requests, nine negatives and one positive reply"
    negative, positive = outgoing[0][1], outgoing[1][1]
    nbody, pbody = peer.checked_request(negative), peer.checked_request(positive)
    assert nbody[16:24] == pbody[16:24] and nbody[24:32] != pbody[24:32], "same owner and distinct grant epoch"
    assert outgoing[0][0] < incoming[0][0] and incoming[8][0] < outgoing[1][0] < incoming[9][0], "wire phase order"
    for i, case in enumerate(peer.CASES):
        expected = peer.negative_reply(negative, case)
        assert incoming[i][1] == expected, "exact independently reconstructed case: " + case
        ordinal = native["cases"][i]["receive_ordinal"]
        actual = next(f for f in native["frames"] if f["direction"] == "rx" and f["ordinal"] == ordinal)
        assert actual["hex"] == expected.hex(), "selected case actually reached native ingress"
    reply = incoming[9][1]
    assert reply[26:34] == peer.PEER_IP + peer.GUEST_IP and reply[34:36] == b"\0\0" and peer.checksum(reply[34:]) == 0
    assert reply[38:] == positive[38:], "genuine positive reflected fields/body"
    observed = native["observed"]
    for key, a, b in (("identifier", 4, 6), ("sequence", 6, 8), ("instance", 16, 24), ("epoch", 24, 32)):
        assert int(observed[key]) == int.from_bytes(pbody[a:b], "big"), "positive native/wire correlation: " + key
    assert observed["nonce"] == pbody[32:40].hex()
    for direction in ("tx", "rx"):
        actual = [bytes.fromhex(f["hex"]) for f in native["frames"] if f["direction"] == direction]
        captured = by_direction[direction]
        assert len(actual) == len(captured), "full capture/native per-direction frame census"
        for submitted, wire in zip(actual, captured):
            if submitted == wire:
                continue
            # The Link submits an unpadded ARP frame; the NIC/capture may
            # expose Ethernet's 60-byte minimum (excluding FCS). This exact
            # relation is limited to TX ARP. Never strip arbitrary suffixes,
            # alter RX bytes, or relax the selected 74-byte ICMP cases.
            assert (direction == "tx" and len(submitted) == 42 and len(wire) == 60
                    and submitted[12:14] == b"\x08\x06"
                    and wire == submitted + bytes(18)), "full capture/native per-direction byte correspondence"
    assert any(a["direction"] == "tx" and a["operation"] == 1 and any(b["direction"] == "rx" and b["operation"] == 2 and a["index"] < b["index"] < outgoing[0][0] for b in arp) for a in arp), "Linux ARP calibration"
    return {"census": census, "ARP": arp, "negative_request": peer.identity(negative),
            "positive_request": peer.identity(positive), "positive_reply": peer.identity(reply)}


def inspect_peer(report, native, frames, namespace_inode, actor_pid):
    assert report["schema"] == "absd-echo-wire-peer/1" and report["disposition"] == "PASS"
    assert report["network_namespace_inode"] == namespace_inode and report["pid"] == actor_pid
    assert report["initial_echo_ignore_all"] == "1" and report["final_echo_ignore_all"] == "0" and report["enable_before_case"] == 8
    assert len(report["cases"]) == 9
    negative = next(frame for _, _, frame in frames if len(frame) == 74 and frame[6:12] == peer.GUEST_MAC)
    assert report["negative_request"] == peer.identity(negative)
    previous_ack = 0
    for i, row in enumerate(report["cases"]):
        assert row["index"] == i and row["case"] == peer.CASES[i] and row["frame"] == peer.identity(peer.negative_reply(negative, peer.CASES[i]))
        assert row["native_acknowledgement"] == native["cases"][i]
        assert previous_ack <= row["send_monotonic_ns"] <= row["ack_read_monotonic_ns"], "independent peer sequential effects"
        previous_ack = row["ack_read_monotonic_ns"]


identity, read_bound, write = base.identity, base.read_bound, base.write
group_live = base.group_live
MAX_ELF, MAX_CAPTURE, MAX_LOG = base.MAX_ELF, base.MAX_CAPTURE, base.MAX_LOG
HOST_MAC, GUEST_MAC = base.HOST_MAC, base.GUEST_MAC


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
        input_paths = [("kernel", args.kernel_elf), ("parent", args.elf)]
        buffers = {name: read_bound(path, MAX_ELF) for name, path in input_paths}
        assert all(data.startswith(b"\x7fELF") and len(data) >= 64 for data in buffers.values()), "ELF magic/size"
        assert buffers["kernel"].count(buffers["parent"]) == 1, "exact unique owner ELF in kernel"
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
                    "net.ipv4.icmp_echo_ignore_all=1"):
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
        for key, expected in (("net.ipv4.icmp_echo_ignore_all", "1"), ("net.ipv6.conf.all.disable_ipv6", "1"),
                              ("net.ipv6.conf.default.disable_ipv6", "1")):
            value = checked(["ip", "netns", "exec", namespace, "sysctl", "-n", key]).stdout.strip()
            assert value == expected, "namespace peer setting " + key
            sysctls[key] = value
        peer = {"scope": "LINUX_KERNEL_ARP_AND_FRESH_POSITIVE_ECHO; nine exact negative frames from disclosed actor; initial Echo suppressed",
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
        peer_result = work / "NEGATIVE-PEER.json"
        peer_ready = peer_result.with_suffix(".ready.json")
        bounds[peer_result], bounds[peer_ready] = 65536, 4096
        actor = start("negative-peer", ["ip", "netns", "exec", namespace, sys.executable, "-I", "-B",
            str(SCRIPTS / "native-echo-wire-peer.py"), "--tap", tap, "--serial", str(serial),
            "--output", str(peer_result), "--timeout", str(min(90, int(left(90))))])
        ready_until = time.monotonic() + left(5)
        while not peer_ready.exists():
            assert actor.poll() is None and time.monotonic() < ready_until, "negative peer ready deadline"
            left(5)
            time.sleep(0.005)
        ready = json.loads(read_bound(peer_ready, 4096))
        assert ready["pid"] == actor.pid and ready["tap"] == tap and ready["echo_ignore_all"] == "1"
        assert ready["network_namespace_inode"] == peer["network_namespace_inode"], "peer exact namespace"
        qemu = start("qemu", command)
        launch_schema = "absd-native-echo-wire-launch/1"
        write(work / "LAUNCH.json", {"schema": launch_schema, "namespace": namespace, "negative_peer_pid_and_pgid": actor.pid,
              "negative_peer_source": identity(SCRIPTS / "native-echo-wire-peer.py", read_bound(SCRIPTS / "native-echo-wire-peer.py", MAX_LOG)),
              "tap": tap, "qemu_pid_and_pgid": qemu.pid, "iso_builder_pid_and_pgid": builder.pid,
              "QEMU_command": command, "inputs": inputs, "ISO": iso_identity,
              "runner": identity(__file__, read_bound(__file__, MAX_LOG)), "Linux_peer": peer,
              "execution_host": list(os.uname()), "runner_pid": os.getpid(), "runner_uid": os.geteuid(),
              "environment_omitted": ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "NOTIFY_SOCKET"],
              "outer_timeout_seconds": args.timeout, "source_to_ELF_limit": "Exact input bytes and embedding only; compiler/source receipts are separately required."})
        while qemu.poll() is None:
            assert actor.poll() in (None, 0), "negative peer failed"
            left(args.timeout)
            time.sleep(0.05)
        left(args.timeout)
        raw_serial = read_bound(serial, MAX_LOG)
        actor.wait(timeout=left(3))
        assert actor.returncode == 0, "negative peer terminal status"
        observation = native_output(raw_serial, qemu.returncode)
        capture_bytes, frames = base.packet_records(capture)
        captured = inspect_frames(frames, observation)
        actor_report = json.loads(read_bound(peer_result, 65536))
        inspect_peer(actor_report, observation, frames, peer["network_namespace_inode"], actor.pid)
        captured["capture"] = identity(capture, capture_bytes)
        result = {"schema": "absd-native-echo-wire-proof/1", "disposition": "PASS",
                  "scope": "nine actual native owner-path wire refusals then a fresh Linux-kernel Echo",
                  "observation": observation, "capture_result": captured, "negative_peer": actor_report,
                  "unrun": UNRUN, "limits": LIMITS,
                  "evaluated_artifacts": {"native-echo.iso": iso_identity,
                      "iso-tree/boot/absd-kernel": inputs["kernel"],
                      "iso-tree/boot/grub/grub.cfg": identity(tree / "grub.cfg", boot_config),
                      "native-echo.serial.log": identity(serial, raw_serial),
                      "native-echo.pcap": captured["capture"],
                      "NEGATIVE-PEER.json": identity(peer_result, read_bound(peer_result, 65536))}}
        left(args.timeout)
        return result
    finally:
        terminal, group_terminal = {}, {}
        for name in ("qemu", "negative-peer", "iso-build"):
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
        write(work / "LOCAL-CLEANUP.json", {"schema": "absd-native-echo-wire-cleanup/1", "namespace": namespace,
              "creation_attempted": creation_attempted, "created": created, "namespace_absent": namespace_absent,
              "process_exit_status": terminal, "owned_session_process_groups_terminal": group_terminal,
              "errors": errors, "disposition": "FAIL" if errors else "PASS",
              "custody": "Root retains exact source/ELF/ISO/raw evidence through independent acceptance, composition and rollback/replay. Review at dependency end or2026-10-19T00:00:00Z. Retire exact runtime substrate after custody; this runner creates no key/provider resource."})
        if errors:
            raise RuntimeError(errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path, help="fresh output path, must not exist")
    parser.add_argument("--kernel-elf", type=Path, required=True)
    parser.add_argument("--elf", type=Path, required=True, help="exact echo-wire-service-probe.elf embedded in kernel")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if not 10 <= args.timeout <= 180:
        parser.error("timeout must be10..180seconds")
    work = args.work.resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=False)

    def stopped(_signal, _frame):
        raise KeyboardInterrupt("wire runner terminated")

    signal.signal(signal.SIGTERM, stopped)
    signal.signal(signal.SIGINT, stopped)
    try:
        result = run(args, work)
        artifacts = {}
        for name, bound in (("iso-tree/boot/absd-kernel", MAX_ELF), ("iso-tree/boot/grub/grub.cfg", 4096),
                            ("native-echo.iso", 128 * 1024 * 1024), ("native-echo.img", 2 * 1024 * 1024),
                            ("native-echo.serial.log", MAX_LOG), ("native-echo.pcap", MAX_CAPTURE),
                            ("qemu.log", MAX_LOG), ("iso-build.log", MAX_LOG), ("negative-peer.log", MAX_LOG),
                            ("LINUX-PEER.json", 65536), ("NEGATIVE-PEER.json", 65536),
                            ("NEGATIVE-PEER.ready.json", 4096), ("LAUNCH.json", 65536), ("LOCAL-CLEANUP.json", 65536)):
            path = work / name
            artifacts[name] = identity(path, read_bound(path, bound))
            expected = result["evaluated_artifacts"].get(name)
            if expected:
                assert all(artifacts[name][key] == expected[key] for key in ("bytes", "sha256")), "evaluated bytes changed before seal"
        result["artifacts"] = artifacts
    except BaseException as error:
        write(work / "RESULT.json", {"schema": "absd-native-echo-wire-proof/1", "disposition": "FAIL",
              "error": repr(error), "unrun": UNRUN, "limits": LIMITS})
        raise
    write(work / "RESULT.json", result)
    print("NATIVE ECHO WIRE PROOF PASS")


if __name__ == "__main__":
    main()
