#!/usr/bin/env python3
"""One bounded native IPv6 DNS proof against Linux's IPv6/UDP/ND implementation.

Run only in the admitted disposable Linux VM. A fresh namespace and TAP are
created and retired by this process. The kernel ELF must already embed the
exact probe ELF. This runner builds a boot ISO, never compiles product code.
--linux runs independent dig controls without booting ABSD.
"""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from served_ram import served_qemu

if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
    raise SystemExit("native-ipv6-matrix: optimized Python is refused")


def sibling(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


n = sibling("net_matrix", "net-matrix.py")
peer = sibling("ipv6_peer", "native-ipv6-peer.py")
GUEST = ipaddress.IPv6Address("fd00:ab5d::15").packed
HOST = ipaddress.IPv6Address("fd00:ab5d::2").packed
GUEST_MAC = "52:54:00:ab:5d:15"
HOST_MAC = "52:55:00:00:02:02"
MAX_PCAP = 2 * 1024 * 1024
MAX_SERIAL = 8 * 1024 * 1024
UNRUN = ["native malformed IPv6/ND frame injection", "native killed consumer",
         "native link/device refusal under independent peer load", "native absent neighbor timeout",
         "native link/device refusal", "live SSH coexistence", "routed IPv6 and Packet Too Big",
         "DAD, SLAAC, DHCPv6, extension headers and fragments"]


def identity(path):
    return {"path": str(path.resolve()), "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def checked(command, timeout=5):
    return subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)


def linux_controls():
    fixture = peer.Peer(timeout=20)
    results = []
    try:
        for name, kind, expected in [("a.example", "A", "192.0.2.9"),
                                     ("aaaa.example", "AAAA", "2001:db8::9")]:
            command = ["dig", "-6", "@::1", "-p", str(fixture.port), name, kind,
                       "+noedns", "+noadflag", "+time=1", "+tries=1"]
            result = checked(command, timeout=4)
            assert expected in result.stdout, result.stdout
            results.append({"name": name, "kind": kind, "stdout": result.stdout,
                            "returncode": result.returncode})
    finally:
        fixture.close()
    assert not fixture.errors, fixture.errors
    assert len(fixture.records) == 2, fixture.records
    return {"case": "independent-Linux-dig-controls", "disposition": "PASS",
            "results": results, "records": fixture.records, "ABSD_execution": False}


def build_iso(kernel, elf, work):
    kernel_bytes = kernel.read_bytes()
    elf_bytes = elf.read_bytes()
    assert kernel_bytes.startswith(b"\x7fELF") and elf_bytes.startswith(b"\x7fELF")
    assert kernel_bytes.count(elf_bytes) == 1, "exact probe ELF not uniquely embedded in kernel"
    tree = work / "iso-tree"
    grub = tree / "boot" / "grub"
    grub.mkdir(parents=True)
    (tree / "boot" / "absd-kernel").write_bytes(kernel_bytes)
    (grub / "grub.cfg").write_text('insmod all_video\nset timeout=0\n'
        'menuentry "ABSD native IPv6" {\n'
        '  multiboot2 /boot/absd-kernel durable=1 net nvme-write=absd\n  boot\n}\n')
    iso = work / "native-ipv6.iso"
    with (work / "iso-build.log").open("wb") as log:
        subprocess.run(["grub-mkrescue", "-o", str(iso), str(tree)],
                       stdout=log, stderr=subprocess.STDOUT, check=True, timeout=60)
    image = work / "native-ipv6.img"
    with image.open("wb") as output:
        output.truncate(2 * 1024 * 1024)
    return iso, image


def read_capture(path):
    assert path.stat().st_size <= MAX_PCAP, "capture byte bound"
    data = path.read_bytes()
    assert len(data) >= 24, "short PCAP header"
    orders = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}
    order = orders.get(data[:4])
    assert order is not None, "unsupported PCAP magic"
    major, minor, _, _, snaplen, linktype = struct.unpack(order + "HHIIII", data[4:24])
    assert (major, minor, linktype) == (2, 4, 1) and snaplen >= 1514
    at = 24
    frames = []
    while at < len(data):
        assert at + 16 <= len(data), "short packet record"
        seconds, micros, size, original = struct.unpack(order + "IIII", data[at:at + 16])
        at += 16
        assert size == original and size <= 1514 and at + size <= len(data), "truncated capture packet"
        frames.append((seconds, micros, data[at:at + size]))
        assert len(frames) <= 256, "frame census bound"
        at += size
    return frames


def inspect_capture(path, records):
    nd = {"guest_ns": 0, "linux_na": 0, "linux_ns": 0, "guest_na": 0}
    queries = []
    responses = []
    for seconds, micros, frame in read_capture(path):
        if len(frame) < 54 or frame[12:14] != b"\x86\xdd":
            continue
        payload_length = int.from_bytes(frame[18:20], "big")
        assert len(frame) >= 54 + payload_length, "short captured IPv6 packet"
        source, destination = frame[22:38], frame[38:54]
        payload = frame[54:54 + payload_length]
        if frame[20] == 58 and payload and payload[0] in (135, 136):
            assert frame[21] == 255 and len(payload) >= 24 and payload[1] == 0
            pseudo = source + destination + struct.pack("!I3xB", len(payload), 58)
            assert n.checksum(pseudo + payload) == 0, "ND checksum"
            key = {(GUEST, 135): "guest_ns", (HOST, 136): "linux_na",
                   (HOST, 135): "linux_ns", (GUEST, 136): "guest_na"}.get((source, payload[0]))
            if key:
                target = HOST if key in ("guest_ns", "linux_na") else GUEST
                assert payload[8:24] == target, (key, "unrelated ND target")
                source_mac = bytes.fromhex((GUEST_MAC if source == GUEST else HOST_MAC).replace(":", ""))
                assert frame[6:12] == source_mac, (key, "wrong Ethernet source")
                remote = HOST if source == GUEST else GUEST
                remote_mac = bytes.fromhex((HOST_MAC if source == GUEST else GUEST_MAC).replace(":", ""))
                if payload[0] == 135:
                    solicited = bytes.fromhex("ff0200000000000000000001ff") + target[-3:]
                    assert destination in (remote, solicited), (key, "wrong solicitation destination")
                    destination_mac = remote_mac if destination == remote else b"\x33\x33\xff" + target[-3:]
                else:
                    assert destination == remote and payload[4] & 0xc0 == 0x40, (key, "wrong advertisement")
                    destination_mac = remote_mac
                assert frame[:6] == destination_mac, (key, "wrong Ethernet destination")
                options = payload[24:]
                found_link_address = False
                while options:
                    assert len(options) >= 2 and options[1] != 0, "invalid ND option"
                    size = options[1] * 8
                    assert size <= len(options), "short ND option"
                    if options[0] in (1, 2):
                        assert size == 8 and options[0] == (1 if payload[0] == 135 else 2)
                        assert options[2:8] == source_mac, "ND/Ethernet source mismatch"
                        found_link_address = True
                    options = options[size:]
                assert found_link_address, (key, "missing ND link address")
                nd[key] += 1
        if frame[20] != 17 or source not in (GUEST, HOST):
            continue
        assert len(payload) >= 8
        source_port, target_port, length, checksum = struct.unpack("!HHHH", payload[:8])
        assert length == len(payload) and checksum != 0
        pseudo = source + destination + struct.pack("!I3xB", length, 17)
        assert n.checksum(pseudo + payload) == 0, "UDP checksum"
        if source == GUEST:
            assert destination == HOST and (source_port, target_port) == (7002, 42010), "ungranted UDP tuple"
            assert 40 + length <= 1280, "native IPv6 datagram exceeds fixed ceiling"
            queries.append(payload[8:].hex())
        else:
            assert destination == GUEST and (source_port, target_port) == (42010, 7002)
            responses.append(payload[8:].hex())
    assert all(nd.values()), ("missing bidirectional Linux/native NS/NA", nd)
    assert queries and responses
    assert sorted(queries) == sorted(record["query_hex"] for record in records)
    assert sorted(responses) == sorted(record["answer_hex"] for record in records)
    return {"case": "captured-bidirectional-ND-and-UDP", "disposition": "PASS",
            "neighbor_discovery": nd, "queries": len(queries), "answers": len(responses),
            "capture": identity(path), "ungranted_destination_seen": False}


def guest(args, work):
    if os.geteuid() != 0:
        raise PermissionError("fresh network namespace requires root in the disposable VM")
    namespace = "absdv6-" + uuid.uuid4().hex[:12]
    tap = "absdv6tap"
    iso, image = build_iso(args.kernel_elf, args.elf, work)
    qemu = None
    fixture = None
    namespace_created = False
    owned_logs = []
    cleanup_errors = []
    try:
        checked(["ip", "netns", "add", namespace])
        namespace_created = True
        for key in ("all.disable_ipv6=0", "default.disable_ipv6=0", "all.accept_ra=0",
                    "default.accept_ra=0", "default.autoconf=0", "default.dad_transmits=0"):
            checked(["ip", "netns", "exec", namespace, "sysctl", "-qw", "net.ipv6.conf." + key])
        checked(["ip", "-n", namespace, "link", "set", "lo", "up"])
        checked(["ip", "-n", namespace, "tuntap", "add", "dev", tap, "mode", "tap"])
        checked(["ip", "-n", namespace, "link", "set", tap, "address", HOST_MAC])
        checked(["ip", "-n", namespace, "link", "set", tap, "up"])
        checked(["ip", "-n", namespace, "-6", "addr", "add", "fd00:ab5d::2/64", "dev", tap, "nodad"])
        peer_log = (work / "peer.log").open("wb")
        owned_logs.append(peer_log)
        fixture_command = ["ip", "netns", "exec", namespace, sys.executable,
                           str(Path(peer.__file__).resolve()), str(work), "--timeout", str(args.timeout),
                           "--reverse-nd-interface", tap]
        fixture = subprocess.Popen(fixture_command, stdout=peer_log, stderr=subprocess.STDOUT)
        ready_deadline = time.monotonic() + 5
        while not (work / "PEER-READY.json").exists():
            assert fixture.poll() is None, "Linux fixture exited before ready"
            if time.monotonic() >= ready_deadline:
                raise TimeoutError("Linux fixture readiness")
            time.sleep(0.05)
        capture = work / "native-ipv6.pcap"
        serial = work / "native-ipv6.serial.log"
        qemu_log = (work / "qemu.log").open("wb")
        owned_logs.append(qemu_log)
        command = served_qemu(["ip", "netns", "exec", namespace, os.environ.get("ABSD_QEMU", "qemu-system-x86_64"),
                   "-accel", "tcg,thread=single", "-cpu", "max,vendor=GenuineIntel,+rdrand",
                   "-smp", "1", "-m", "256M", "-cdrom", str(iso),
                   "-drive", f"file={image},format=raw,if=ide,index=0", "-display", "none",
                   "-serial", f"file:{serial}", "-no-reboot", "-no-shutdown",
                   "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
                   "-device", f"e1000,netdev=n0,mac={GUEST_MAC}", "-netdev",
                   f"tap,id=n0,ifname={tap},script=no,downscript=no,vnet_hdr=off", "-object",
                   f"filter-dump,id=cap0,netdev=n0,file={capture}"])
        qemu = subprocess.Popen(command, stdout=qemu_log, stderr=subprocess.STDOUT)
        peer.write_json(work / "LAUNCH.json", {"qemu_pid": qemu.pid, "peer_pid": fixture.pid,
            "namespace": namespace, "tap": tap, "command": command,
            "kernel": identity(args.kernel_elf), "probe": identity(args.elf), "iso": identity(iso),
            "runner": identity(Path(__file__)), "peer": identity(Path(peer.__file__)),
            "boot_helper": identity(Path(n.__file__)), "timeout_seconds": args.timeout,
            "bootline": "durable=1 net nvme-write=absd", "execution": "QEMU TCG single CPU with RDRAND",
            "retirement": "terminate exact peer/QEMU and delete exact owned namespace at terminal outcome"})
        deadline = time.monotonic() + args.timeout
        while qemu.poll() is None:
            if time.monotonic() >= deadline:
                raise TimeoutError("native guest absolute deadline")
            assert fixture.poll() is None, "Linux fixture ended during native execution"
            assert not capture.exists() or capture.stat().st_size <= MAX_PCAP, "capture byte bound"
            assert not serial.exists() or serial.stat().st_size <= MAX_SERIAL, "serial byte bound"
            time.sleep(0.05)
        assert serial.stat().st_size <= MAX_SERIAL, "final serial byte bound"
        _, counters = n.finish_boot(qemu, str(serial), rb"IPV6 SERVICE PASS")
        assert counters != "none", "missing NIC terminal counters"
        fields = dict(field.split("=", 1) for field in counters.split() if "=" in field)
        assert int(fields["rx_frames"]) > 0 and int(fields["tx_frames"]) > 0, counters
        assert int(fields["rx_refused"]) == 0 and int(fields["rx_missed"]) == 0, counters
        output = n.stdout_of(str(serial)).decode("utf-8")
        for expected in ("IPV6 CLIENT AUTHORITY PASS scope-and-peer-refused no-nic",
                         "IPV6 DNS A PASS address=192.0.2.9",
                         "IPV6 DNS AAAA PASS address=2001:db8::9",
                         "IPV6 BOUNDARIES PASS malformed=9 denied=3 oversize=1 queue=4 endpoints=8 stale=2 sockets=0 queued-test-wire=0",
                         "IPV6 PIPE BOUNDARIES PASS eof=1 partial-expiry=1 port-reuse=2"):
            assert expected in output, (expected, output)
        assert "IPV6 SERVICE ERROR" not in output and "IPV6 CLIENT ERROR" not in output
        (work / "PEER-STOP").touch()
        assert fixture.wait(timeout=3) == 0, "Linux fixture terminal failure"
        observed = json.loads((work / "PEER-RESULT.json").read_text())
        assert observed["disposition"] == "PASS" and not observed["errors"], observed
        records = observed["records"]
        assert {record["name"] for record in records} == {"a.example", "aaaa.example"}, records
        for name in ("a.example", "aaaa.example"):
            copies = [record for record in records if record["name"] == name]
            assert 1 <= len(copies) <= 2 and len({record["query_hex"] for record in copies}) == 1
        assert sum("reverse_nd" in record for record in records) == 1
        capture_result = inspect_capture(capture, records)
        result = {"case": "native-Linux-kernel-IPv6-DNS", "disposition": "PASS",
                  "counters": counters, "output": output, "peer_records": records,
                  "capture_result": capture_result,
                  "authority": "native wrong-scope/wrong-port requests denied; Linux wrong-port socket silent",
                  "native_api_controls": {"malformed_messages": 9, "denied": 3,
                      "oversize": 1, "queue_capacity": 4, "endpoint_capacity": 8,
                      "stale_after_reuse": 2, "temporary_test_frames": 0},
                  "native_pipe_controls": {"EOF_revokes": 1, "partial_expiry": 1, "port_reuse": 2},
                  "control_limits": "API/pipe controls execute in native ABSD; they are distinct from independent Linux ND/UDP and from malformed on-wire packet injection."}
        return result
    finally:
        for process, label in ((qemu, "qemu"), (fixture, "peer")):
            try:
                if process is not None and process.poll() is None:
                    try:
                        process.terminate()
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                if process is not None and process.poll() is None:
                    cleanup_errors.append(label + " did not terminate")
            except BaseException as error:
                cleanup_errors.append(label + " retirement: " + repr(error))
        for log in owned_logs:
            log.close()
        if namespace_created:
            try:
                remaining = checked(["ip", "netns", "pids", namespace]).stdout.strip()
                if remaining:
                    raise RuntimeError("namespace still has processes: " + remaining)
                deleted = subprocess.run(["ip", "netns", "del", namespace], capture_output=True,
                                         text=True, timeout=5)
                names = checked(["ip", "netns", "list"]).stdout.splitlines()
                if deleted.returncode or any(line.split()[0] == namespace for line in names if line):
                    cleanup_errors.append("namespace retirement not verified: " + deleted.stderr)
            except BaseException as error:
                cleanup_errors.append("namespace retirement: " + repr(error))
        peer.write_json(work / "LOCAL-CLEANUP.json", {"namespace": namespace,
            "namespace_created": namespace_created, "qemu_terminal": qemu is None or qemu.poll() is not None,
            "peer_terminal": fixture is None or fixture.poll() is not None,
            "errors": cleanup_errors, "disposition": "FAIL" if cleanup_errors else "PASS",
            "retained": "exact input ELFs remain at original paths; ISO, scratch disk and logs await lane custody closeout"})
        if cleanup_errors:
            raise RuntimeError(cleanup_errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path)
    parser.add_argument("--linux", action="store_true")
    parser.add_argument("--kernel-elf", type=Path)
    parser.add_argument("--elf", type=Path)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if not 10 <= args.timeout <= 180:
        parser.error("timeout must be 10..180 seconds")
    if not args.linux and (not args.kernel_elf or not args.elf):
        parser.error("native mode requires exact --kernel-elf and --elf")
    for path in (args.kernel_elf, args.elf):
        if path and (not path.is_file() or path.stat().st_size > 64 * 1024 * 1024):
            parser.error("input ELF absent or exceeds 64 MiB")
    work = args.work.resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    def stop(_signum, _frame):
        raise KeyboardInterrupt("runner terminated")
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    results = []
    scope = "independent Linux DNS fixture controls" if args.linux else "bounded static on-link UDP/DNS native demonstration"
    try:
        results.append(linux_controls())
        if not args.linux:
            results.append(guest(args, work))
    except BaseException as error:
        peer.write_json(work / "RESULT.json", {"schema": "absd-native-ipv6-proof/1", "disposition": "FAIL",
            "scope": scope, "results": results,
            "error": repr(error), "unrun_cases": UNRUN})
        raise
    peer.write_json(work / "RESULT.json", {"schema": "absd-native-ipv6-proof/1", "disposition": "PASS",
        "scope": scope, "results": results,
        "native_execution": not args.linux, "unrun_cases": UNRUN})
    print("NATIVE IPV6 PROOF PASS native=" + str(not args.linux).lower())


if __name__ == "__main__":
    main()
