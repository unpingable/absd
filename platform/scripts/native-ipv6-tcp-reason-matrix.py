#!/usr/bin/env python3
"""Separate TCP peer-accounting successor; the original TCP case is unchanged.

Only for the admitted disposable Linux VM. Keep the original Linux peer,
TC-before-first-SYN, exact fallback question, MSS, FIN/EOF and cleanup proof.
The reviewed shared helper requires exhaustive first-four driver reasons and
compatible captured destinations, with explicit capture-prefix uncertainty.
Normal Linux MLD remains enabled. No source rewriting at runtime.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid
import importlib.util

sys.path.insert(0, str(Path(__file__).resolve().parent))
from served_ram import served_qemu

if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
    raise SystemExit("native-ipv6-tcp-accounting-matrix: optimized Python is refused")


def sibling(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


original = sibling("ipv6_tcp_original_case", "native-ipv6-tcp-matrix.py")
accounting = sibling("ipv6_accounting", "native-ipv6-reason-accounting.py")
n, peer = original.n, original.peer
GUEST_MAC, HOST_MAC = original.GUEST_MAC, original.HOST_MAC
MAX_PCAP, MAX_SERIAL, UNRUN = original.MAX_PCAP, original.MAX_SERIAL, original.UNRUN
identity, checked = original.identity, original.checked
build_iso, inspect_capture = original.build_iso, original.inspect_capture
linux_controls = original.linux_controls


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
    marker = None
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
        marker = accounting.ReadyMarker(serial, capture)
        marker.poll(running=False)  # Establish the pre-launch, ready-absent observation.
        qemu = subprocess.Popen(command, stdout=qemu_log, stderr=subprocess.STDOUT)
        peer.write_json(work / "LAUNCH.json", {"qemu_pid": qemu.pid, "peer_pid": fixture.pid,
            "namespace": namespace, "tap": tap, "link_mtu": link["mtu"], "command": command,
            "kernel": identity(args.kernel_elf), "probe": identity(args.elf), "iso": identity(iso),
            "runner": identity(Path(__file__)), "original_runner": identity(Path(original.__file__)),
            "accounting_helper": identity(Path(accounting.__file__)), "case": accounting.CASE,
            "profile": "tcp", "peer": identity(Path(peer.__file__)),
            "boot_helper": identity(Path(n.__file__)), "timeout_seconds": args.timeout,
            "bootline": "durable=1 net nvme-write=absd", "execution": "QEMU TCG single CPU with RDRAND",
            "retirement": "terminate exact peer/QEMU and delete exact owned namespace at terminal outcome"})
        deadline = time.monotonic() + args.timeout
        while qemu.poll() is None:
            marker.poll(running=qemu.poll() is None)
            if time.monotonic() >= deadline:
                raise TimeoutError("native guest absolute deadline")
            assert fixture.poll() is None, "Linux fixture ended during native execution"
            assert not capture.exists() or capture.stat().st_size <= MAX_PCAP, "capture byte bound"
            assert not serial.exists() or serial.stat().st_size <= MAX_SERIAL, "serial byte bound"
            time.sleep(0.05)
        marker.poll(running=False)
        marker.seal(work)
        assert serial.stat().st_size <= MAX_SERIAL, "final serial byte bound"
        _, counters = n.finish_boot(qemu, str(serial), rb"IPV6 TCP SERVICE PASS")
        assert counters != "none", "missing NIC terminal counters"
        fields = dict(field.split("=", 1) for field in counters.split() if "=" in field)
        assert int(fields["rx_frames"]) > 0 and int(fields["tx_frames"]) > 0, counters
        accounting_result = accounting.evaluate(work, marker, fields, GUEST_MAC, HOST_MAC, profile="tcp")
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
        result = {"case": "native-Linux-kernel-IPv6-TCP-DNS-driver-reason-correspondence-successor", "disposition": "PASS",
                  "counters": counters, "output": output, "peer_records": records,
                  "capture_result": capture_result, "accounting_result": accounting_result,
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
        if marker is not None and marker.annotation is None:
            try:
                marker.poll(running=False)
                marker.seal(work)
            except BaseException as error:
                cleanup_errors.append("capture readiness annotation: " + repr(error))
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
    scope = "independent Linux DNS fixture controls" if args.linux else "bounded static on-link 1500-MTU UDP/TCP DNS fallback with bounded driver-reason correspondence"
    try:
        results.append(linux_controls())
        if not args.linux:
            results.append(guest(args, work))
    except BaseException as error:
        peer.write_json(work / "RESULT.json", {"schema": "absd-native-ipv6-tcp-driver-reason-proof/1", "disposition": "FAIL",
            "scope": scope, "results": results,
            "error": repr(error), "unrun_cases": UNRUN})
        raise
    peer.write_json(work / "RESULT.json", {"schema": "absd-native-ipv6-tcp-driver-reason-proof/1", "disposition": "PASS",
        "scope": scope, "results": results,
        "native_execution": not args.linux, "unrun_cases": UNRUN})
    print("NATIVE IPV6 TCP ACCOUNTING PROOF PASS native=" + str(not args.linux).lower())


if __name__ == "__main__":
    main()
