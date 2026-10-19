#!/usr/bin/env python3
"""Distinct directed-ARP DHCP/DNS proof; original failed case stays unchanged.

This foreground runner builds only an ISO from exact prebuilt input ELFs.
It owns one namespace, TAP, dnsmasq process and QEMU; no host DHCP service.
The positive profile is deliberately narrow. Negative native cases stay UNRUN.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import shutil
import struct
import subprocess
import time
import uuid

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from served_ram import served_qemu

if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
    raise SystemExit("native-dhcp-matrix: optimized Python is refused")

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("dhcp_boot_checks", ROOT / "scripts/net-matrix.py")
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)
HOST = bytes([192, 0, 2, 1])
GUEST = bytes([192, 0, 2, 100])
HOST_MAC = bytes.fromhex("525500000301")
GUEST_MAC = bytes.fromhex("525400123456")
MAX_CAPTURE = 2 * 1024 * 1024
MAX_SERIAL = 8 * 1024 * 1024
UNRUN = ["native malformed/substituted DHCP", "empty pool/no Offer", "native conflict/Decline",
         "native child interruption/stall", "native NAK/link/clock loss in each phase",
         "native queued-data expiry", "renewal/rebind/RELEASE", "live SSH coexistence",
         "physical elapsed-time accuracy or NIC hardware"]


def identity(path):
    data = Path(path).read_bytes()
    return buffer_identity(path, data)


def buffer_identity(path, data):
    return {"path": str(Path(path).resolve()), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def write(path, value):
    with Path(path).open("x") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def checked(argv, timeout=5):
    return subprocess.run(argv, check=True, text=True, capture_output=True, timeout=timeout)


def packet_records(path):
    data = Path(path).read_bytes()
    assert 24 <= len(data) <= MAX_CAPTURE, "capture byte bound/header"
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(data[:4])
    assert endian is not None, "PCAP magic"
    major, minor, _, _, snaplen, link = struct.unpack(endian + "HHIIII", data[4:24])
    assert (major, minor, link) == (2, 4, 1) and snaplen >= 1514
    at, rows = 24, []
    while at < len(data):
        assert at + 16 <= len(data), "short capture record"
        sec, usec, size, original = struct.unpack(endian + "IIII", data[at:at + 16])
        at += 16
        assert usec < 1_000_000 and 14 <= size <= 1514 and size == original and at + size <= len(data)
        rows.append((len(rows), [sec, usec], data[at:at + size]))
        assert len(rows) <= 256, "capture frame bound"
        at += size
    return rows


def options(packet):
    assert len(packet) >= 240 and packet[236:240] == bytes([99, 130, 83, 99]), "DHCP cookie"
    result, at = {}, 240
    while at < len(packet):
        tag = packet[at]
        at += 1
        if tag == 0:
            continue
        if tag == 255:
            assert not any(packet[at:]), "DHCP trailing bytes"
            return result
        assert at < len(packet)
        size = packet[at]
        at += 1
        assert at + size <= len(packet) and tag not in result, "DHCP option length/duplicate"
        expected = {1: 4, 3: 4, 6: 4, 50: 4, 51: 4, 53: 1, 54: 4, 58: 4, 59: 4}.get(tag)
        assert expected is None or size == expected, "DHCP known option size"
        result[tag] = packet[at:at + size]
        at += size
    raise AssertionError("DHCP option end missing")


def dns_name(data, at):
    labels, seen, end = [], set(), None
    for _ in range(128):
        assert at < len(data) and at not in seen, "DNS name bound/cycle"
        seen.add(at)
        size = data[at]
        if size & 0xc0 == 0xc0:
            assert at + 1 < len(data)
            if end is None:
                end = at + 2
            at = ((size & 63) << 8) | data[at + 1]
        else:
            assert size <= 63
            at += 1
            if size == 0:
                return b".".join(labels), end if end is not None else at
            assert at + size <= len(data)
            labels.append(data[at:at + size])
            at += size
    raise AssertionError("DNS name traversal bound")


def linux_arp_request(frame):
    """Only the configured Linux peer's request for this guest; no peer grant."""
    return (len(frame) >= 42 and frame[12:14] == b"\x08\x06"
            and frame[14:22] == bytes([0, 1, 8, 0, 6, 4, 0, 1])
            and frame[6:12] == HOST_MAC and frame[22:28] == HOST_MAC
            and frame[28:32] in (HOST, b"\0" * 4) and frame[38:42] == GUEST
            and frame[:6] in (b"\xff" * 6, GUEST_MAC) and frame[32:38] == b"\0" * 6)


def inspect(path, active):
    dhcp, probes, announcements, queries, answers, arp_rows, pool_checks = [], [], [], [], [], [], []
    census = []
    for index, timestamp, frame in packet_records(path):
        assert frame[6:12] in (HOST_MAC, GUEST_MAC), "unexplained Ethernet source"
        outgoing = frame[6:12] == GUEST_MAC
        row = {"index": index, "timestamp": timestamp, "bytes": len(frame),
               "sha256": hashlib.sha256(frame).hexdigest(), "outgoing": outgoing}
        if frame[12:14] == b"\x08\x06":
            assert len(frame) >= 42 and frame[14:20] == bytes([0, 1, 8, 0, 6, 4])
            operation = int.from_bytes(frame[20:22], "big")
            assert operation in (1, 2) and frame[22:28] == frame[6:12]
            sender, target = frame[28:32], frame[38:42]
            assert sender in (b"\0" * 4, HOST, GUEST) and target in (HOST, GUEST), "unrelated ARP"
            if outgoing and sender == b"\0" * 4 and target == GUEST:
                assert operation == 1 and frame[:6] == b"\xff" * 6
                probes.append(index)
                row["kind"] = "guest-address-probe"
            elif outgoing and sender == GUEST and target == GUEST:
                assert operation == 1 and frame[:6] == b"\xff" * 6
                announcements.append(index)
                row["kind"] = "guest-address-announcement"
            else:
                if outgoing:
                    assert operation == 1 and sender == GUEST and target == HOST and frame[:6] == b"\xff" * 6, "unrelated guest ARP"
                elif operation == 2:
                    assert sender == HOST and target == GUEST and frame[:6] == GUEST_MAC and frame[32:38] == GUEST_MAC, "unrelated resolver ARP reply"
                else:
                    assert linux_arp_request(frame), "unrelated Linux broadcast/directed ARP request"
                row["kind"] = "peer-arp"
                arp_rows.append({"index": index, "operation": operation,
                                 "sender": sender.hex(), "target": target.hex(), "outgoing": outgoing,
                                 "destination_mac": frame[:6].hex(), "target_mac": frame[32:38].hex()})
        else:
            assert len(frame) >= 34 and frame[12:14] == b"\x08\x00" and frame[14] == 0x45, "unexplained frame"
            length = int.from_bytes(frame[16:18], "big")
            assert length >= 20 and len(frame) in (14 + length, max(60, 14 + length)) and boot.checksum(frame[14:34]) == 0
            assert not any(frame[14 + length:]), "nonzero Ethernet minimum padding"
            assert int.from_bytes(frame[20:22], "big") & 0x3fff == 0, "fragmented IPv4"
            source, target, ip = frame[26:30], frame[30:34], frame[14:14 + length]
            if frame[23] == 1:
                icmp = ip[20:]
                assert not outgoing and source == HOST and target == GUEST and len(icmp) >= 8
                assert icmp[:2] == b"\x08\0" and boot.checksum(icmp) == 0, "unexplained ICMP"
                row["kind"] = "dnsmasq-pool-check"
                pool_checks.append(index)
            else:
                assert frame[23] == 17 and len(ip) >= 28, "unexplained IPv4 protocol"
                udp = ip[20:]
                sport, dport, size, checksum = struct.unpack("!HHHH", udp[:8])
                assert size == len(udp)
                assert checksum == 0 or boot.checksum(source + target + struct.pack("!BBH", 0, 17, size) + udp) == 0
                payload = udp[8:]
                if (sport, dport) in ((68, 67), (67, 68)):
                    assert len(payload) >= 240 and payload[1:4] == bytes([1, 6, 0])
                    assert payload[28:34] == GUEST_MAC and payload[24:28] == b"\0" * 4
                    opts = options(payload)
                    kind = opts.get(53)
                    assert kind in (b"\x01", b"\x02", b"\x03", b"\x05"), "unexpected DHCP transition"
                    assert outgoing == (kind in (b"\x01", b"\x03"))
                    assert (sport, dport) == ((68, 67) if outgoing else (67, 68))
                    assert payload[0] == (1 if outgoing else 2)
                    assert frame[:6] in ((b"\xff" * 6,) if outgoing else (b"\xff" * 6, GUEST_MAC))
                    assert source == (b"\0" * 4 if outgoing else HOST)
                    assert target in ((b"\xff" * 4,) if outgoing else (b"\xff" * 4, GUEST))
                    dhcp.append({"index": index, "kind": kind[0], "xid": int.from_bytes(payload[4:8], "big"),
                                 "address": payload[16:20].hex(), "options": {str(k): v.hex() for k, v in opts.items()}})
                    row["kind"] = "dhcp-" + str(kind[0])
                else:
                    assert checksum != 0, "DNS checksum absent"
                    assert (source, target, sport, dport) == ((GUEST, HOST, 7204, 53) if outgoing else (HOST, GUEST, 53, 7204)), "ungranted DNS tuple"
                    assert len(payload) >= 12 and int.from_bytes(payload[4:6], "big") == 1
                    name, end = dns_name(payload, 12)
                    assert name == b"a.example" and payload[end:end + 4] == b"\0\x01\0\x01"
                    if outgoing:
                        assert payload[2:4] == b"\x01\0" and payload[6:12] == b"\0" * 6 and end + 4 == len(payload)
                        queries.append({"index": index, "id": payload[:2].hex(), "hex": payload.hex()})
                    else:
                        flags = int.from_bytes(payload[2:4], "big")
                        assert flags & 0xfa0f == 0x8000 and payload[6:12] == b"\0\x01\0\0\0\0"
                        answer_name, at = dns_name(payload, end + 4)
                        assert answer_name == name and at + 14 == len(payload)
                        assert payload[at:at + 4] == b"\0\x01\0\x01" and payload[at + 8:at + 10] == b"\0\x04"
                        assert payload[at + 10:] == bytes([198, 51, 100, 9])
                        answers.append({"index": index, "id": payload[:2].hex(), "hex": payload.hex()})
                    row["kind"] = "dns-query" if outgoing else "dns-answer"
        census.append(row)
    assert [d["kind"] for d in dhcp] == [1, 2, 3, 5], "exact DORA required"
    assert {d["xid"] for d in dhcp} == {active["xid"]}
    for d in dhcp[1::2]:
        assert d["address"] == GUEST.hex() and d["options"]["54"] == HOST.hex()
    assert dhcp[2]["options"]["50"] == GUEST.hex() and dhcp[2]["options"]["54"] == HOST.hex()
    ack = dhcp[-1]["options"]
    assert ack["1"] == "ffffff00" and ack["3"] == HOST.hex() and ack["6"] == HOST.hex()
    lease = int(ack["51"], 16)
    t1, t2 = int(ack.get("58", hex(lease // 2)[2:]), 16), int(ack.get("59", hex(lease * 7 // 8)[2:]), 16)
    assert 60 <= lease <= 3600 and 0 < t1 < t2 < lease
    assert active["renew_ms"] - active["request_ms"] == t1 * 1000
    assert active["rebind_ms"] - active["request_ms"] == t2 * 1000
    assert active["expires_ms"] - active["request_ms"] == lease * 1000
    assert active["request_ms"] < active["stop_ms"] <= active["renew_ms"]
    assert len(probes) == 3 and len(announcements) == 2
    assert dhcp[-1]["index"] < probes[0] < probes[1] < probes[2] < announcements[0] < announcements[1]
    assert len(queries) == len(answers) == 1 and queries[0]["id"] == answers[0]["id"]
    assert announcements[-1] < queries[0]["index"] < answers[0]["index"]
    resolver_requests = [a["index"] for a in arp_rows if a["outgoing"] and a["sender"] == GUEST.hex() and a["target"] == HOST.hex() and a["operation"] == 1]
    resolver_replies = [a["index"] for a in arp_rows if not a["outgoing"] and a["operation"] == 2 and a["sender"] == HOST.hex() and a["target"] == GUEST.hex() and a["target_mac"] == GUEST_MAC.hex() and a["destination_mac"] == GUEST_MAC.hex()]
    assert any(request < reply < queries[0]["index"] for request in resolver_requests for reply in resolver_replies), "paired Linux resolver ARP request/response absent before DNS"
    return {"disposition": "PASS", "capture": identity(path), "dora": dhcp, "probes": probes,
            "announcements": announcements, "queries": queries, "answers": answers,
            "arp": arp_rows, "pool_checks": pool_checks, "census": census,
            "time_limit": "Captured order and boot-domain timer correspondence only; no physical elapsed lease accuracy claim."}


def run(args, work):
    assert os.geteuid() == 0, "isolated namespace requires root inside owned disposable VM"
    with args.kernel_elf.open("rb") as source:
        kernel = source.read(64 * 1024 * 1024 + 1)
    with args.elf.open("rb") as source:
        parent = source.read(64 * 1024 * 1024 + 1)
    assert len(kernel) <= 64 * 1024 * 1024 and len(parent) <= 64 * 1024 * 1024
    kernel_identity, parent_identity = buffer_identity(args.kernel_elf, kernel), buffer_identity(args.elf, parent)
    assert kernel.startswith(b"\x7fELF") and parent.startswith(b"\x7fELF") and kernel.count(parent) == 1
    tree = work / "iso-tree/boot/grub"
    tree.mkdir(parents=True)
    (tree.parent / "absd-kernel").write_bytes(kernel)
    (tree / "grub.cfg").write_text('insmod all_video\nset timeout=0\nmenuentry "ABSD DHCP" {\n multiboot2 /boot/absd-kernel durable=1 net nvme-write=absd\n boot\n}\n')
    iso, disk = work / "native-dhcp.iso", work / "native-dhcp.img"
    with (work / "iso-build.log").open("wb") as log:
        subprocess.run(["grub-mkrescue", "-o", str(iso), str(tree.parent.parent)], stdout=log, stderr=subprocess.STDOUT, timeout=60, check=True)
    with disk.open("wb") as output:
        output.truncate(2 * 1024 * 1024)
    namespace, tap = "absddhcp-" + uuid.uuid4().hex[:12], "dhcp-tap0"
    created, qemu, server, logs, errors = False, None, None, [], []
    try:
        checked(["ip", "netns", "add", namespace])
        created = True
        for key in ("all.disable_ipv6=1", "default.disable_ipv6=1"):
            checked(["ip", "netns", "exec", namespace, "sysctl", "-qw", "net.ipv6.conf." + key])
        for command in (["link", "set", "lo", "up"], ["tuntap", "add", "dev", tap, "mode", "tap"],
                        ["link", "set", tap, "address", HOST_MAC.hex(":")], ["addr", "add", "192.0.2.1/24", "dev", tap], ["link", "set", tap, "up"]):
            checked(["ip", "-n", namespace, *command])
        config = ROOT / "fixtures/native-dhcp/dnsmasq.conf"
        version = checked(["dnsmasq", "--version"]).stdout
        checked(["dnsmasq", "--test", "--conf-file=" + str(config)])
        server_log = (work / "dnsmasq.stdout.log").open("wb")
        logs.append(server_log)
        command = ["ip", "netns", "exec", namespace, "dnsmasq", "--conf-file=" + str(config),
                   "--dhcp-leasefile=" + str(work / "dnsmasq.leases"), "--pid-file=" + str(work / "dnsmasq.pid"),
                   "--log-facility=" + str(work / "dnsmasq.log")]
        server = subprocess.Popen(command, stdout=server_log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 5
        while True:
            assert server.poll() is None, "dnsmasq exited before readiness"
            control = subprocess.run(["ip", "netns", "exec", namespace, "dig", "@192.0.2.1", "a.example", "A", "+short", "+noedns", "+time=1", "+tries=1"], text=True, capture_output=True, timeout=2)
            if control.returncode == 0 and control.stdout.strip() == "198.51.100.9":
                break
            assert time.monotonic() < deadline, "independent Linux DNS readiness"
            time.sleep(0.05)
        serial, capture = work / "native-dhcp.serial.log", work / "native-dhcp.pcap"
        qemu_log = (work / "qemu.log").open("wb")
        logs.append(qemu_log)
        command = served_qemu(["ip", "netns", "exec", namespace, os.environ.get("ABSD_QEMU", "qemu-system-x86_64"),
                   "-accel", "tcg,thread=single", "-cpu", "max,vendor=GenuineIntel,+rdrand", "-smp", "1", "-m", "256M",
                   "-cdrom", str(iso), "-drive", f"file={disk},format=raw,if=ide,index=0", "-display", "none",
                   "-serial", f"file:{serial}", "-no-reboot", "-no-shutdown", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
                   "-device", f"e1000,netdev=n0,mac={GUEST_MAC.hex(':')}", "-netdev", f"tap,id=n0,ifname={tap},script=no,downscript=no,vnet_hdr=off",
                   "-object", f"filter-dump,id=cap0,netdev=n0,file={capture}"])
        qemu = subprocess.Popen(command, stdout=qemu_log, stderr=subprocess.STDOUT)
        write(work / "LAUNCH.json", {"namespace": namespace, "tap": tap, "qemu_pid": qemu.pid, "dnsmasq_pid": server.pid,
            "command": command, "server_command": server.args, "kernel": kernel_identity, "parent": parent_identity,
            "iso": identity(iso), "runner": identity(__file__), "boot_helper": identity(boot.__file__), "peer_config": identity(config),
            "peer_executable": identity(Path(shutil.which("dnsmasq"))), "peer_version": version,
            "Linux_DNS_control": {"stdout": control.stdout, "returncode": control.returncode}, "timeout_seconds": args.timeout})
        deadline = time.monotonic() + args.timeout
        while qemu.poll() is None:
            assert time.monotonic() < deadline, "native guest wall deadline"
            assert server.poll() is None, "independent dnsmasq exited"
            assert not serial.exists() or serial.stat().st_size <= MAX_SERIAL
            assert not capture.exists() or capture.stat().st_size <= MAX_CAPTURE
            assert not (work / "dnsmasq.log").exists() or (work / "dnsmasq.log").stat().st_size <= MAX_SERIAL
            time.sleep(0.05)
        assert serial.stat().st_size <= MAX_SERIAL
        _, counters = boot.finish_boot(qemu, str(serial), rb"DHCP DONE .*owner=retired")
        fields = dict(s.split("=", 1) for s in counters.split())
        assert int(fields["rx_frames"]) > 0 and int(fields["tx_frames"]) > 0
        assert all(int(fields[k]) == 0 for k in ("rx_refused", "rx_missed", "tx_refused", "tx_errors")), counters
        output = boot.stdout_of(str(serial)).decode("utf-8")
        assert "DHCP ERROR" not in output and "DHCP DNS ANSWER 198.51.100.9 denied=1 nic=0\n" in output
        match = re.search(r"DHCP ACTIVE address=192.0.2.100/24 router=192.0.2.1 resolver=192.0.2.1 xid=(\d+) request_ms=(\d+) renew_ms=(\d+) rebind_ms=(\d+) expires_ms=(\d+) stop_ms=(\d+)\n", output)
        assert match, "exact active lease record missing"
        active = dict(zip(["xid", "request_ms", "renew_ms", "rebind_ms", "expires_ms", "stop_ms"], map(int, match.groups())))
        capture_result = inspect(capture, active)
        leases = (work / "dnsmasq.leases").read_text()
        assert len(leases.splitlines()) == 1 and "52:54:00:12:34:56 192.0.2.100 " in leases, "independent server lease"
        return {"disposition": "PASS", "scope": "one finite DHCP acquisition/probe and delegated DNS consumer", "active": active,
                "capture_result": capture_result, "native_output": output, "NIC_counters": counters, "peer_lease": leases,
                "unrun": UNRUN, "limits": "No renew/rebind/clock accuracy/live SSH or general DHCP claim; non-atomic sends retain possible first effects. stop_ms is a scheduled bound; no observed retirement timestamp is asserted."}
    finally:
        for process, name in ((qemu, "qemu"), (server, "dnsmasq")):
            try:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                if process is not None and process.poll() is None:
                    errors.append(name + " not terminal")
            except BaseException as error:
                errors.append(name + ": " + repr(error))
        for log in logs:
            log.close()
        if created:
            try:
                assert not checked(["ip", "netns", "pids", namespace]).stdout.strip(), "namespace has live processes"
                checked(["ip", "netns", "del", namespace])
                assert not any(line.split()[0] == namespace for line in checked(["ip", "netns", "list"]).stdout.splitlines())
            except BaseException as error:
                errors.append("namespace: " + repr(error))
        write(work / "LOCAL-CLEANUP.json", {"namespace": namespace, "created": created, "qemu_terminal": qemu is None or qemu.poll() is not None,
              "server_terminal": server is None or server.poll() is not None, "errors": errors, "disposition": "FAIL" if errors else "PASS",
              "custody": "Exact ELF/ISO/capture/log/lease inputs retained for root review, reproducible staging/scratch retired after dependency checks; review2026-10-17."})
        if errors:
            raise RuntimeError(errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path)
    parser.add_argument("--kernel-elf", type=Path, required=True)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if not 10 <= args.timeout <= 180:
        parser.error("timeout must be 10..180 seconds")
    for path in (args.kernel_elf, args.elf):
        if not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
            parser.error("input ELF missing or exceeds 64 MiB")
    work = args.work.resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    def stopped(_signum, _frame):
        raise KeyboardInterrupt("runner terminated")
    signal.signal(signal.SIGTERM, stopped)
    signal.signal(signal.SIGINT, stopped)
    try:
        result = run(args, work)
    except BaseException as error:
        write(work / "RESULT.json", {"schema": "absd-native-dhcp-directed-arp-proof/1", "disposition": "FAIL", "error": repr(error), "unrun": UNRUN})
        raise
    write(work / "RESULT.json", {"schema": "absd-native-dhcp-directed-arp-proof/1", **result})
    print("NATIVE DHCP PROOF PASS")


if __name__ == "__main__":
    main()
