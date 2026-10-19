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
    raise SystemExit("native-ipv6-tcp-matrix: optimized Python is refused")


def sibling(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


n = sibling("net_matrix", "net-matrix.py")
peer = sibling("ipv6_peer", "native-ipv6-tcp-peer.py")
GUEST = ipaddress.IPv6Address("fd00:ab5d::15").packed
HOST = ipaddress.IPv6Address("fd00:ab5d::2").packed
GUEST_MAC = "52:54:00:ab:5d:15"
HOST_MAC = "52:55:00:00:02:02"
MAX_PCAP = 2 * 1024 * 1024
MAX_SERIAL = 8 * 1024 * 1024
UNRUN = ["native malformed IPv6/ND frame injection", "native killed consumer",
         "native malformed API messages and oversize refusal",
         "native queue/endpoint exhaustion and stale handle reuse",
         "native pipe EOF revocation and partial-frame expiry",
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
                                     ("tc.example", "A", "192.0.2.9"),
                                     ("tcaaaa.example", "AAAA", "2001:db8::9")]:
            result = checked(["dig", "-6", "@::1", "-p", str(fixture.port), name, kind,
                              "+noedns", "+noadflag", "+time=2", "+tries=1"], timeout=5)
            assert expected in result.stdout, result.stdout
            results.append({"name": name, "kind": kind, "stdout": result.stdout})
    finally:
        fixture.close()
    assert not fixture.errors, fixture.errors
    assert fixture.tcp_accepts == 2, fixture.records
    return {"case": "independent-Linux-dig-IPv6-TCP-fallback", "disposition": "PASS",
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
    tcp = {"guest_syn": 0, "linux_synack": 0, "guest_fin": 0, "linux_fin": 0, "mss": []}
    fallback = [record for record in records if record["transport"] == "TCP-DNS"]
    assert fallback, "missing TCP fallback question"
    first_query = fallback[0]["query_hex"]
    truncated_answers = {record["answer_hex"]: record["query_hex"] for record in records
                         if record["transport"] == "UDP" and bytes.fromhex(record["answer_hex"])[2] & 2}
    received_truncated = {}
    first_contact = None
    queries, responses = [], []
    for ordinal, (seconds, micros, frame) in enumerate(read_capture(path)):
        if len(frame) < 54 or frame[12:14] != b"\x86\xdd":
            continue
        size = int.from_bytes(frame[18:20], "big")
        assert len(frame) >= 54 + size
        source, destination = frame[22:38], frame[38:54]
        payload = frame[54:54 + size]
        if frame[20] == 58 and payload and payload[0] in (135, 136):
            assert frame[21] == 255 and len(payload) >= 24 and payload[1] == 0
            pseudo = source + destination + struct.pack("!I3xB", len(payload), 58)
            assert n.checksum(pseudo + payload) == 0
            key = {(GUEST, 135): "guest_ns", (HOST, 136): "linux_na",
                   (HOST, 135): "linux_ns", (GUEST, 136): "guest_na"}.get((source, payload[0]))
            if key: nd[key] += 1
        if frame[20] == 6 and source in (GUEST, HOST):
            assert 20 <= size <= 1460
            sport, dport = struct.unpack("!HH", payload[:4])
            assert (source, destination, sport, dport) in ((GUEST, HOST, 7203, 42020), (HOST, GUEST, 42020, 7203))
            pseudo = source + destination + struct.pack("!I3xB", size, 6)
            assert n.checksum(pseudo + payload) == 0, "TCP checksum"
            flags = payload[13]
            assert not flags & 4, "unexpected TCP reset"
            if flags & 2:
                if source == GUEST:
                    if tcp["guest_syn"] == 0:
                        assert first_query in received_truncated, "TCP SYN preceded its matching UDP TC response"
                        first_contact = {"syn_frame": ordinal, "udp_tc_frame": received_truncated[first_query],
                                         "query_hex": first_query}
                    tcp["guest_syn"] += 1
                    end = (payload[12] >> 4) * 4
                    assert 20 <= end <= len(payload)
                    at = 20
                    while at < end:
                        kind = payload[at]
                        if kind == 0: break
                        if kind == 1: at += 1; continue
                        assert at + 2 <= end and payload[at + 1] >= 2
                        length = payload[at + 1]
                        assert at + length <= end
                        if kind == 2:
                            assert length == 4
                            tcp["mss"].append(int.from_bytes(payload[at + 2:at + 4], "big"))
                        at += length
                else:
                    assert flags & 16
                    tcp["linux_synack"] += 1
            if flags & 1:
                tcp["guest_fin" if source == GUEST else "linux_fin"] += 1
        if frame[20] != 17 or source not in (GUEST, HOST):
            continue
        assert len(payload) >= 8
        sport, dport, length, checksum = struct.unpack("!HHHH", payload[:8])
        assert length == len(payload) and checksum != 0
        assert n.checksum(source + destination + struct.pack("!I3xB", length, 17) + payload) == 0
        if source == GUEST:
            assert destination == HOST and (sport, dport) == (7202, 42020)
            assert 40 + length <= 1280
            queries.append(payload[8:].hex())
        else:
            assert destination == GUEST and (sport, dport) == (42020, 7202)
            responses.append(payload[8:].hex())
            query = truncated_answers.get(payload[8:].hex())
            if query is not None:
                received_truncated.setdefault(query, ordinal)
    udp = [record for record in records if record["transport"] == "UDP"]
    assert all(nd.values()), nd
    assert tcp["guest_syn"] >= 1 and tcp["linux_synack"] >= 1 and tcp["guest_fin"] >= 1 and tcp["linux_fin"] >= 1, tcp
    assert tcp["mss"] and all(mss == 1440 for mss in tcp["mss"]), tcp
    assert sorted(queries) == sorted(record["query_hex"] for record in udp)
    assert sorted(responses) == sorted(record["answer_hex"] for record in udp)
    return {"case": "captured-scoped-UDP-TCP-ND", "disposition": "PASS", "nd": nd, "tcp": tcp,
            "queries": len(queries), "answers": len(responses), "capture": identity(path),
            "first_tcp_contact_after_matching_udp_tc": first_contact}


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
        checked(["ip", "-n", namespace, "link", "set", tap, "mtu", "1500"])
        checked(["ip", "-n", namespace, "link", "set", tap, "up"])
        link = json.loads(checked(["ip", "-n", namespace, "-j", "link", "show", "dev", tap]).stdout)[0]
        assert link["mtu"] == 1500, link
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
            "namespace": namespace, "tap": tap, "link_mtu": link["mtu"], "command": command,
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
        _, counters = n.finish_boot(qemu, str(serial), rb"IPV6 TCP SERVICE PASS")
        assert counters != "none", "missing NIC terminal counters"
        fields = dict(field.split("=", 1) for field in counters.split() if "=" in field)
        assert int(fields["rx_frames"]) > 0 and int(fields["tx_frames"]) > 0, counters
        assert int(fields["rx_refused"]) == 0 and int(fields["rx_missed"]) == 0, counters
        output = n.stdout_of(str(serial)).decode("utf-8")
        for expected in ("IPV6 TCP CLIENT AUTHORITY PASS scope-and-peer-refused no-nic",
                         "IPV6 TCP DNS A PASS name=a.example address=192.0.2.9",
                         "IPV6 TCP DNS A PASS name=tc.example address=192.0.2.9",
                         "IPV6 TCP DNS AAAA PASS name=tcaaaa.example address=2001:db8::9",
                         "IPV6 TCP DNS CLOSE PASS", "IPV6 TCP LOCAL RETIRE sockets=0 closing-bounded=1"):
            assert expected in output, (expected, output)
        assert "IPV6 TCP SERVICE ERROR" not in output and "IPV6 TCP CLIENT ERROR" not in output
        (work / "PEER-STOP").touch()
        assert fixture.wait(timeout=3) == 0, "Linux fixture terminal failure"
        observed = json.loads((work / "PEER-RESULT.json").read_text())
        assert observed["disposition"] == "PASS" and not observed["errors"], observed
        records = observed["records"]
        udp = [record for record in records if record["transport"] == "UDP"]
        assert {record["name"] for record in udp} == {"a.example", "tc.example", "tcaaaa.example"}, records
        for name in ("a.example", "tc.example", "tcaaaa.example"):
            copies = [record for record in udp if record["name"] == name]
            assert 1 <= len(copies) <= 2 and len({record["query_hex"] for record in copies}) == 1
        assert sum("reverse_nd" in record for record in udp) == 1
        assert observed["tcp_accepts"] == 1
        questions = [record for record in records if record["transport"] == "TCP-DNS"]
        assert [record["name"] for record in questions] == ["tc.example", "tcaaaa.example"]
        assert any(record["transport"] == "TCP-FIN-EOF" and record["queries"] == 2 for record in records)
        capture_result = inspect_capture(capture, records)
        result = {"case": "native-Linux-kernel-IPv6-TCP-DNS", "disposition": "PASS",
                  "counters": counters, "output": output, "peer_records": records,
                  "capture_result": capture_result,
                  "authority": "native wrong-scope/wrong-port requests denied; Linux wrong-port socket silent"}
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
    scope = "independent Linux DNS fixture controls" if args.linux else "bounded static on-link 1500-MTU UDP/TCP DNS fallback"
    try:
        results.append(linux_controls())
        if not args.linux:
            results.append(guest(args, work))
    except BaseException as error:
        peer.write_json(work / "RESULT.json", {"schema": "absd-native-ipv6-tcp-proof/1", "disposition": "FAIL",
            "scope": scope, "results": results,
            "error": repr(error), "unrun_cases": UNRUN})
        raise
    peer.write_json(work / "RESULT.json", {"schema": "absd-native-ipv6-tcp-proof/1", "disposition": "PASS",
        "scope": scope, "results": results,
        "native_execution": not args.linux, "unrun_cases": UNRUN})
    print("NATIVE IPV6 TCP PROOF PASS native=" + str(not args.linux).lower())


if __name__ == "__main__":
    main()
