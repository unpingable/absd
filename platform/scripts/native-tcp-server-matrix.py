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
PRODUCT = "2b2f882ce486ed85ba32b21e039e4521c96e2c63"
PRODUCT_TREE = "699e237c94e00dec19266ec1fb8c8a02d165e412"
PRODUCT_ARCHIVE = "75887cfefbf637a1806d912a5a3f703d8a638fb4bb13abc0382872f2f255dd9a"
KERNEL = "ed6a15ea7c7c999422e1e294e139b6119619b06c"
KERNEL_TREE = "5c3834dcdb8cf393c86bc0e436ae62c7cda67af5"
KERNEL_ARCHIVE = "568ac7c029d9d8e6e101519b1341c2e860300cb7dded1e65ea526efaa731212e"
HOST, GUEST = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 100])
HOST_MAC, GUEST_MAC = bytes.fromhex("525500000501"), bytes.fromhex("525400123456")
READY = b"TCP SERVER LISTEN READY sockets=1\n"
DATA = bytes((i * 131 ^ (i >> 7)) & 255 for i in range(3072))
MAX_CAPTURE, MAX_LOG, MAX_ELF, MAX_ISO = 2 << 20, 8 << 20, 64 << 20, 128 << 20
UNRUN = ["native malformed API/wire", "native pipe cancellation/partial expiry",
         "native clock/link faults or exhausted queues/slots", "native stale handle",
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


def build_binding(receipt, child, parent, kernel):
    assert receipt["schema"] == "absd-native-tcp-server-build/1"
    for name, revision, tree, archive in (("platform", PRODUCT, PRODUCT_TREE, PRODUCT_ARCHIVE),
                                           ("kernel", KERNEL, KERNEL_TREE, KERNEL_ARCHIVE)):
        source = receipt[name]
        assert source["revision"] == revision and source["tree"] == tree and source["clean"] is True
        assert source["archive"]["sha256"] == archive and 0 < source["archive"]["bytes"] <= MAX_ELF
    assert receipt["commands"] and all(isinstance(c, list) and c and all(isinstance(s, str) for s in c)
                                       for c in receipt["commands"])
    assert 1 <= len(receipt["logs"]) <= 8 and all(re.fullmatch(r"[0-9a-f]{64}", log["sha256"])
                                   and log["bytes"] > 0 for log in receipt["logs"])
    toolchain = receipt["toolchain_receipt"]
    assert re.fullmatch(r"[0-9a-f]{64}", toolchain["sha256"]) and toolchain["bytes"] > 0
    assert any(any(s.endswith("scripts/build-native-tcp-server.sh") for s in c) for c in receipt["commands"])
    assert any(any(s.startswith("EXTERNAL_USER_ELF=") for s in c) for c in receipt["commands"])
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
        rows.append(data[at:at + size]); at += size; previous = (sec, usec)
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


def inspect_capture(data):
    flows, census, arps = {"host": [], "guest": []}, [], []
    wrong, first_valid = [], None
    for index, frame in enumerate(records(data)):
        assert frame[6:12] in (HOST_MAC, GUEST_MAC), "third Ethernet source"
        outgoing = frame[6:12] == GUEST_MAC
        source, target = (GUEST, HOST) if outgoing else (HOST, GUEST)
        srcmac, dstmac = (GUEST_MAC, HOST_MAC) if outgoing else (HOST_MAC, GUEST_MAC)
        row = {"index": index, **digest(frame)}
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
                wrong.append(index); row["kind"] = "refused-source-port-syn"
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
    assert any(not direction and op == 1 for _, direction, op in arps)
    assert any(direction and op == 2 for _, direction, op in arps), "guest ARP reply absent"
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
    return {"frames": len(census), "wrong_port_syns": wrong, "first_authorized_syn": first_valid,
            "application_bytes_each": 3072, "segments": chunks, "fin": fin, "fin_ack": fin_ack, "census": census}


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


def peer_results(wrong, peer):
    assert wrong == {"disposition": "PASS", "local": ["192.0.2.1", 42031],
                     "peer": ["192.0.2.100", 7005], "result": "connect-timeout", "sent_bytes": 0}
    assert peer["disposition"] == "PASS" and peer["local"] == ["192.0.2.1", 42030]
    assert peer["peer"] == ["192.0.2.100", 7005] and peer["bytes"] == 3072
    assert peer["sha256"] == digest(DATA)["sha256"] and peer["write_half_closed"] is True and peer["read_EOF"] is True


def wrong_port_client(result):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("192.0.2.1", 42031)); sock.settimeout(0.3)
        try:
            sock.connect(("192.0.2.100", 7005))
        except TimeoutError:
            write(result, {"disposition": "PASS", "local": ["192.0.2.1", 42031],
                           "peer": ["192.0.2.100", 7005], "result": "connect-timeout", "sent_bytes": 0})
        else:
            raise AssertionError("unauthorized source port connected")


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
    inputs = {name: read_bound(path, MAX_ELF) for name, path in
              (("child", args.child_elf), ("parent", args.elf), ("kernel", args.kernel_elf))}
    receipt_bytes = read_bound(args.build_receipt, MAX_LOG)
    receipt = json.loads(receipt_bytes); build_binding(receipt, **inputs)
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
        write(work / "LAUNCH.json", {"namespace": namespace, "tap": tap, "qemu_pid_pgid": qemu.pid,
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
                                    (work / "wrong-port.log", MAX_LOG), (work / "peer.log", MAX_LOG)):
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
        for name, script in (("wrong-port", [sys.executable, str(Path(__file__).resolve()), "--wrong-port-client"]),
                             ("peer", [sys.executable, str(ROOT / "scripts/native-tcp-server-peer.py")])):
            log = (work / (name + ".log")).open("wb"); logs.append(log)
            process = subprocess.Popen(["ip", "netns", "exec", namespace, *script, str(work / (name + ".json"))],
                                       stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                                       preexec_fn=producer_file_limit)
            clients.append(process); bounded_wait(process=process)
            assert process.returncode == 0, name + " client failed"
        bounded_wait(process=qemu)
        result = native_output(read_bound(serial, MAX_LOG), qemu.returncode)
        peer_results(json.loads(read_bound(work / "wrong-port.json", MAX_LOG)), json.loads(read_bound(work / "peer.json", MAX_LOG)))
        capture_bytes = read_bound(capture, MAX_CAPTURE)
        result.update({"disposition": "PASS", "scope": "one exact-peer delegated IPv4 TCP echo and pre-connect wrong-source-port refusal",
                       "capture": digest(capture_bytes), "capture_result": inspect_capture(capture_bytes), "unrun": UNRUN,
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
              "custody": "Root retains exact ELF/ISO/capture/log/receipt inputs for review/replay. Reproducible scratch retires after dependencies end; review 2026-10-17."})
        if errors:
            raise RuntimeError(errors)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--wrong-port-client":
        wrong_port_client(Path(sys.argv[2])); return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path)
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
        write(work / "RESULT.json", {"schema": "absd-native-tcp-server-proof/1", "disposition": "FAIL", "error": repr(error), "unrun": UNRUN})
        raise
    write(work / "RESULT.json", {"schema": "absd-native-tcp-server-proof/1", **result})
    print("NATIVE TCP SERVER PROOF PASS")


if __name__ == "__main__":
    main()
