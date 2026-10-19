#!/usr/bin/env python3
"""One foreground native SNTP observation against an isolated Linux chronyd.

Run only on the resource owner's disposable compiler/qualification VM. This
builds an ISO from exact prebuilt ELF buffers; it does not compile source.
The owned namespace, TAP and two foreground processes never use host services.
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
    raise SystemExit("native-sntp-matrix: optimized Python is refused")

ROOT = Path(__file__).resolve().parent.parent
HOST, GUEST = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 100])
HOST_MAC, GUEST_MAC = bytes.fromhex("525500000401"), bytes.fromhex("525400123456")
MAX_ELF, MAX_CAPTURE, MAX_LOG = 64 * 1024 * 1024, 2 * 1024 * 1024, 8 * 1024 * 1024
MIN_UNIX, MAX_UNIX, NTP_UNIX = 1767225600, 2082758340, 2208988800
CHUNK = re.compile(rb"EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]*)\n")
UNRUN = ["native malformed/extensions/MAC/KoD/leap/stratum/stamp/era refusals",
         "native wrong-origin/duplicate/replay/late response and three-attempt exhaustion",
         "native child interruption, queue exhaustion, link loss and boot-clock rewind",
         "TLS countertrace execution, certificate trust or NTS bootstrap",
         "live SSH coexistence, physical clock/wire RTT accuracy or NIC hardware"]


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


def peer_sockets(sockets, pid):
    # Literal endpoint spelling observed with chrony 4.5's binddevice fixture.
    # A socket with another interface, address, port or process is not readiness.
    matches = []
    for line in sockets.splitlines():
        fields = line.split(maxsplit=5)
        if (len(fields) == 6 and fields[0] == "UNCONN" and
                fields[3] == "192.0.2.1%sntp-tap0:123" and fields[4] == "0.0.0.0:*" and
                re.fullmatch(r'users:\(\("chronyd",pid=' + str(pid) + r',fd=[0-9]+\)\)', fields[5])):
            matches.append(line)
    return matches


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
    for needed in (rb"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ",
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
    grant = re.findall(r"^SNTP GRANT local_port=(\d+) peer=192\.0\.2\.1:123$", output, re.M)
    observations = re.findall(
        r"^SNTP server_claimed_unix=(\d+) server_fraction_2p32=(\d+) "
        r"rtc_unix=(\d+|unavailable\(-\d+\)) boot_rtt_ms=(\d+) auth=none uncertainty=unknown "
        r"unauthenticated_difference=(unknown|-?\d+s) attempt=([123]) denied=1 nic=0$", output, re.M)
    assert len(grant) == len(observations) == 1, "one grant and one exact observation required"
    done = "SNTP DONE child=exited sockets=0 observation_only=1\n"
    assert output.count(done) == 1 and output.endswith(done), "normal child/owner completion missing"
    assert output.count("SNTP ") == 3, "unexpected native SNTP records"
    local_port = int(grant[0])
    assert 49152 <= local_port <= 65535, "grant local port outside delegated random range"
    seconds, fraction, rtc, rtt, difference, attempt = observations[0]
    seconds, fraction, rtt, attempt = map(int, (seconds, fraction, rtt, attempt))
    assert MIN_UNIX <= seconds <= MAX_UNIX and 0 <= fraction < 2 ** 32
    assert seconds != MAX_UNIX or fraction == 0
    assert 0 <= rtt < 2000, "observed boot RTT outside live attempt"
    if rtc.isdecimal():
        assert int(rtc) < 2 ** 64 and difference == f"{seconds - int(rtc)}s", "RTC difference label/value"
    else:
        assert difference == "unknown", "fallible RTC must retain unknown difference"
    stats = re.findall(rb"NIC STATS (.*)\n", raw)
    assert len(stats) == 1, "one final NIC accounting record required"
    counters = dict(field.split("=", 1) for field in stats[0].decode("ascii").split())
    assert int(counters["rx_frames"]) > 0 and int(counters["tx_frames"]) > 0
    assert all(int(counters[k]) == 0 for k in ("rx_refused", "rx_missed", "tx_refused", "tx_errors")), counters
    return {"local_port": local_port, "unix_seconds": seconds, "fraction_2p32": fraction,
            "rtc": rtc, "boot_rtt_ms": rtt, "unauthenticated_difference": difference,
            "attempt": attempt, "auth": "none", "uncertainty": "unknown",
            "wrong_port_denied": True, "child_nic": False, "child_exit": 0,
            "sockets_after_retirement": 0, "output": output, "NIC_counters": counters}


def inspect(path, observation):
    capture, frames = packet_records(path)
    requests, replies, arp, census = [], [], [], []
    port = observation["local_port"]
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
                expected_hw = b"\xff" * 6 if outgoing else b"\0" * 6
                destinations = (b"\xff" * 6,) if outgoing else (b"\xff" * 6, peer_mac)
                assert target_mac in destinations and target_hw == expected_hw, "ARP request destination"
            else:
                assert operation == 2 and target_mac == target_hw == peer_mac, "ARP reply destination"
            row["kind"] = "arp-request" if operation == 1 else "arp-reply"
            arp.append({"index": index, "operation": operation, "outgoing": outgoing,
                        "sender": sender.hex(), "target": target.hex()})
        else:
            assert frame[12:14] == b"\x08\x00" and len(frame) >= 34 and frame[14] == 0x45, "unexplained frame"
            assert target_mac == (HOST_MAC if outgoing else GUEST_MAC), "IPv4 MAC destination"
            size = int.from_bytes(frame[16:18], "big")
            assert size == 76 and len(frame) == 90 and checksum(frame[14:34]) == 0, "IPv4 length/checksum"
            assert int.from_bytes(frame[20:22], "big") & 0x3fff == 0 and frame[22] > 0, "IPv4 fragment/TTL"
            source, target = frame[26:30], frame[30:34]
            assert frame[23] == 17 and (source, target) == ((GUEST, HOST) if outgoing else (HOST, GUEST)), "ungranted IPv4 protocol/peer"
            udp = frame[34:]
            sport, dport, length, value = struct.unpack("!HHHH", udp[:8])
            assert length == 56 and value != 0 and checksum(source + target + struct.pack("!BBH", 0, 17, length) + udp) == 0, "UDP length/checksum"
            assert (sport, dport) == ((port, 123) if outgoing else (123, port)), "ungranted UDP tuple"
            packet = udp[8:]
            if outgoing:
                assert packet[:40] == bytes([0x23]) + b"\0" * 39, "exact client request profile"
                nonce = int.from_bytes(packet[40:48], "big")
                assert nonce and nonce not in {q["nonce"] for q in requests}, "zero/repeated nonce"
                requests.append({"index": index, "nonce": nonce, "hex": packet.hex()})
                assert len(requests) <= 3, "attempt bound"
                row["kind"] = "ntp-request"
            else:
                assert packet[0] == 0x24 and 1 <= packet[1] <= 15, "reply version/mode/LI/stratum"
                origin = int.from_bytes(packet[24:32], "big")
                matches = [q for q in requests if q["nonce"] == origin]
                assert len(matches) == 1 and matches[0]["index"] < index, "reply origin/order"
                assert origin not in {r["origin"] for r in replies}, "duplicate reply"
                reference, received, sent = [int.from_bytes(packet[a:a + 8], "big") for a in (16, 32, 40)]
                assert 0 < reference < received < sent, "zero/repeated/reversed server timestamps"
                unix, fraction = (sent >> 32) - NTP_UNIX, sent & 0xffffffff
                assert MIN_UNIX <= unix <= MAX_UNIX and (unix != MAX_UNIX or fraction == 0), "permitted era"
                replies.append({"index": index, "origin": origin, "reference": reference,
                                "receive": received, "transmit": sent, "unix_seconds": unix,
                                "fraction_2p32": fraction, "hex": packet.hex()})
                row["kind"] = "ntp-reply"
        census.append(row)
    assert 1 <= len(requests) <= 3 and replies, "native request/independent Linux reply absent"
    assert observation["attempt"] == len(requests), "native/capture attempt correspondence"
    observed = [r for r in replies if (r["unix_seconds"], r["fraction_2p32"]) ==
                (observation["unix_seconds"], observation["fraction_2p32"])]
    assert len(observed) == 1 and observed[0]["origin"] == requests[-1]["nonce"], "observation/captured transmit and final nonce correspondence"
    assert requests[-1]["index"] < observed[0]["index"] == replies[-1]["index"], "final response order"
    assert all(r["index"] < requests[-1]["index"] or r is observed[0] for r in replies), "unconsumed late reply"
    assert any(a["outgoing"] and a["operation"] == 1 and
               any(not b["outgoing"] and b["operation"] == 2 and
                   a["index"] < b["index"] < requests[0]["index"] for b in arp) for a in arp), "paired Linux ARP reply before NTP required"
    return {"capture": identity(path, capture), "ARP": arp, "requests": requests,
            "replies": replies, "observed_reply_index": observed[0]["index"], "census": census}


def run(args, work):
    assert os.geteuid() == 0, "requires root inside the owned disposable VM"
    deadline = time.monotonic() + args.timeout
    namespace, tap = "absdsntp-" + uuid.uuid4().hex, "sntp-tap0"
    processes, logs, errors = {}, [], []
    creation_attempted, created, namespace_absent, peer_ready = False, False, False, None
    last_readiness = None
    bounds = {}
    pidfile = work / "chronyd.pid"
    pidfile_disposition = "NOT_CREATED"
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
        buffers = {name: read_bound(path, MAX_ELF) for name, path in
                   (("kernel", args.kernel_elf), ("parent", args.elf), ("child", args.client_elf))}
        assert all(data.startswith(b"\x7fELF") and len(data) >= 64 for data in buffers.values()), "ELF input magic/size"
        assert buffers["parent"].count(buffers["child"]) == 1 and buffers["kernel"].count(buffers["parent"]) == 1 and buffers["kernel"].count(buffers["child"]) == 1, "exact unique child/parent/kernel embedding"
        inputs = {name: identity(path, buffers[name]) for name, path in
                  (("kernel", args.kernel_elf), ("parent", args.elf), ("child", args.client_elf))}
        config_path = ROOT / "fixtures/native-sntp/chrony.conf"
        template = read_bound(config_path, 4096)
        config, pidfile = peer_config(template, work)
        assert not pidfile.exists() and not pidfile.is_symlink(), "fresh owned PID pathname required"
        bounds[pidfile] = 64
        (work / "chrony.conf").write_bytes(config)
        write(work / "PEER-CONFIG.json", {"template": identity(config_path, template),
              "effective": identity(work / "chrony.conf", config), "pidfile": str(pidfile),
              "owner": "S2 execution owner", "purpose": "Exact isolated chronyd process identity",
              "retirement": "After exact peer process group is terminal, verify any remaining regular owned PID file names that peer, then remove that exact file; retain mismatches as cleanup FAIL."})
        tree = work / "iso-tree/boot/grub"
        tree.mkdir(parents=True)
        (tree.parent / "absd-kernel").write_bytes(buffers["kernel"])
        (tree / "grub.cfg").write_text('insmod all_video\nset timeout=0\nmenuentry "ABSD SNTP" {\n multiboot2 /boot/absd-kernel durable=1 net nvme-write=absd\n boot\n}\n')
        iso, disk = work / "native-sntp.iso", work / "native-sntp.img"
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
        # A fresh name is created only here. All network mutations are scoped to it.
        assert not any(line.split()[0] == namespace for line in checked(["ip", "netns", "list"]).stdout.splitlines())
        creation_attempted = True
        checked(["ip", "netns", "add", namespace])
        created = True
        for key in ("all.disable_ipv6=1", "default.disable_ipv6=1"):
            checked(["ip", "netns", "exec", namespace, "sysctl", "-qw", "net.ipv6.conf." + key])
        for command in (["link", "set", "lo", "up"], ["tuntap", "add", "dev", tap, "mode", "tap"],
                        ["link", "set", tap, "address", HOST_MAC.hex(":")],
                        ["addr", "add", "192.0.2.1/24", "dev", tap], ["link", "set", tap, "up"]):
            checked(["ip", "-n", namespace, *command])
        binary = args.chronyd.resolve()
        assert binary.is_file(), "explicit chronyd ELF unavailable"
        binary_bytes = read_bound(binary, MAX_ELF)
        assert binary_bytes.startswith(b"\x7fELF") and len(binary_bytes) >= 64, "chronyd must be an actual Linux ELF"
        peer_binary = identity(binary, binary_bytes)
        binary = work / "chronyd"
        binary.write_bytes(binary_bytes)
        binary.chmod(0o700)
        version = checked([str(binary), "-v"]).stdout
        assert version.strip(), "chronyd version missing"
        (work / "chrony.version.txt").write_text(version)
        server_command = ["ip", "netns", "exec", namespace, str(binary), "-u", "root", "-x", "-d", "-f", str(work / "chrony.conf")]
        server = start("chrony", server_command)
        write(work / "PEER-START.json", {"pid_and_pgid": server.pid, "command": server_command,
              "namespace": namespace, "expected_executable": str(binary), "pidfile": str(pidfile)})
        readiness_deadline = time.monotonic() + left(5)
        while True:
            last_readiness = {"host_monotonic_seconds": time.monotonic(), "peer_pid": server.pid,
                              "peer_returncode": server.poll(), "pidfile_exists": pidfile.exists(),
                              "pidfile_is_symlink": pidfile.is_symlink()}
            assert server.poll() is None, "chronyd exited before socket readiness"
            sockets = checked(["ip", "netns", "exec", namespace, "ss", "-H", "-lunp"]).stdout
            last_readiness["ss_H_lunp"] = sockets[:8192]
            last_readiness["ss_truncated"] = len(sockets) > 8192
            matches = peer_sockets(sockets, server.pid)
            if matches and (pidfile.exists() or pidfile.is_symlink()):
                assert len(matches) == 1 and Path(f"/proc/{server.pid}/exe").resolve() == binary, "chronyd socket process identity"
                assert os.stat(f"/proc/{server.pid}/ns/net").st_ino == os.stat("/run/netns/" + namespace).st_ino, "chronyd namespace identity"
                assert not pidfile.is_symlink() and pidfile.is_file(), "owned chronyd PID file required"
                assert read_bound(pidfile, 64).strip() == str(server.pid).encode("ascii"), "chronyd PID file/process correspondence"
                peer_ready = {"scope": "BOUND_SOCKET_ONLY; no Linux NTP control request", "socket": matches[0],
                              "pid": server.pid, "pidfile": str(pidfile),
                              "network_namespace_inode": os.stat("/run/netns/" + namespace).st_ino}
                break
            assert time.monotonic() < readiness_deadline, "chronyd socket readiness deadline"
            time.sleep(0.05)
        serial, capture = work / "native-sntp.serial.log", work / "native-sntp.pcap"
        bounds[serial], bounds[capture] = MAX_LOG, MAX_CAPTURE
        qemu_binary = shutil.which(os.environ.get("ABSD_QEMU", "qemu-system-x86_64"))
        assert qemu_binary, "QEMU unavailable"
        command = served_qemu(["ip", "netns", "exec", namespace, str(Path(qemu_binary).resolve()),
                   "-accel", "tcg,thread=single", "-cpu", "max,vendor=GenuineIntel,+rdrand", "-smp", "1", "-m", "256M",
                   "-cdrom", str(iso), "-drive", f"file={disk},format=raw,if=ide,index=0", "-display", "none",
                   "-serial", f"file:{serial}", "-no-reboot", "-no-shutdown", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
                   "-device", f"e1000,netdev=n0,mac={GUEST_MAC.hex(':')}", "-netdev", f"tap,id=n0,ifname={tap},script=no,downscript=no,vnet_hdr=off",
                   "-object", f"filter-dump,id=cap0,netdev=n0,file={capture}"])
        qemu = start("qemu", command)
        write(work / "LAUNCH.json", {"schema": "absd-native-sntp-launch/1", "namespace": namespace,
              "tap": tap, "qemu_pid_and_pgid": qemu.pid, "chronyd_pid_and_pgid": server.pid,
              "iso_builder_pid_and_pgid": builder.pid, "QEMU_command": command,
              "chronyd_command": server_command, "inputs": inputs, "ISO": identity(iso, read_bound(iso, bounds[iso])),
              "runner": identity(__file__, read_bound(__file__, MAX_LOG)), "peer_executable_origin": peer_binary,
              "peer_executed_copy": identity(binary, binary_bytes),
              "peer_config_template": identity(config_path, template),
              "peer_config": identity(work / "chrony.conf", config), "peer_version": version, "peer_readiness": peer_ready,
              "peer_user": "root inside owned disposable VM/namespace only",
              "environment_omitted": ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "NOTIFY_SOCKET"],
              "execution_host": list(os.uname()), "runner_pid": os.getpid(), "runner_uid": os.geteuid(),
              "outer_timeout_seconds": args.timeout, "source_to_ELF_limit": "Exact input bytes and embedding only; compiler/source receipts are separately required."})
        while qemu.poll() is None:
            left(args.timeout)
            assert server.poll() is None, "independent chronyd exited"
            time.sleep(0.05)
        left(args.timeout)
        assert server.poll() is None, "chronyd exited before proof inspection"
        observation = native_output(read_bound(serial, MAX_LOG), qemu.returncode)
        result = {"disposition": "PASS", "scope": "one unauthenticated native SNTP observation via delegated exact IPv4 UDP",
                  "observation": observation, "capture_result": inspect(capture, observation), "unrun": UNRUN,
                  "limits": "Boot-domain scheduled RTT/deadlines and captured order only; no physical accuracy, trusted UTC, clock adjustment, TLS input or native negative-case claim. Non-atomic I/O can retain an already-submitted first effect."}
        left(args.timeout)
        return result
    finally:
        terminal, group_terminal = {}, {}
        for name in ("qemu", "chrony", "iso-build"):
            process = processes.get(name)
            try:
                if name == "chrony" and process is not None and process.poll() is not None:
                    errors.append("chrony exited before owned shutdown")
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
                if name == "chrony" and process is not None and terminal[name] not in (0, -signal.SIGTERM):
                    errors.append("chrony abnormal shutdown " + str(terminal[name]))
            except BaseException as error:
                errors.append(name + ": " + repr(error))
        for log in logs:
            log.close()
        try:
            if pidfile.exists() or pidfile.is_symlink():
                peer = processes.get("chrony")
                assert peer is not None and peer.poll() is not None and group_terminal.get("chrony"), "PID file consumer not terminal"
                assert pidfile.is_file() and not pidfile.is_symlink(), "unexpected PID object; retained"
                info = pidfile.stat()
                assert info.st_uid == os.geteuid() and info.st_nlink == 1, "PID file ownership/link uncertainty; retained"
                assert read_bound(pidfile, 64).strip() == str(peer.pid).encode("ascii"), "PID file names another process; retained"
                pidfile.unlink()
                pidfile_disposition = "EXACT_TERMINAL_PEER_PID_FILE_RETIRED"
            else:
                pidfile_disposition = "ABSENT_AFTER_PEER_SHUTDOWN_OR_NOT_CREATED"
        except BaseException as error:
            errors.append("owned PID file: " + repr(error))
            pidfile_disposition = "RETAINED_UNCERTAIN_CLEANUP_FAIL"
        # Cleanup has its own finite 5-second command bounds even after timeout.
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
        write(work / "LOCAL-CLEANUP.json", {"schema": "absd-native-sntp-cleanup/1", "namespace": namespace,
              "creation_attempted": creation_attempted, "created": created,
              "namespace_absent": namespace_absent, "process_exit_status": terminal,
              "owned_session_process_groups_terminal": group_terminal,
              "last_peer_readiness_observation": last_readiness,
              "pidfile": {"path": str(pidfile), "disposition": pidfile_disposition,
                          "absent": not pidfile.exists() and not pidfile.is_symlink()},
              "errors": errors, "disposition": "FAIL" if errors else "PASS",
              "custody": "Root/resource owner retains exact ELFs, ISO, serial, raw PCAP, chrony binary identity/config/version/log and receipts until independent review/replay ends; then retires exact staging/scratch after dependency checks. Review 2026-10-17. No keys or provider resources created."})
        if errors:
            raise RuntimeError(errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path, help="fresh output path; must not exist")
    parser.add_argument("--kernel-elf", type=Path, required=True)
    parser.add_argument("--elf", type=Path, required=True, help="sntp-service-probe.elf embedded in kernel")
    parser.add_argument("--client-elf", type=Path, required=True, help="sntp-query.elf embedded in parent")
    parser.add_argument("--chronyd", type=Path, required=True, help="exact extracted distro chronyd ELF; no installation or service activation")
    parser.add_argument("--timeout", type=int, default=120, help="outer wall timeout, setup through evidence inspection")
    args = parser.parse_args()
    if not 10 <= args.timeout <= 180:
        parser.error("timeout must be 10..180 seconds")
    work = args.work.resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=False)

    def stopped(_signum, _frame):
        raise KeyboardInterrupt("runner terminated")

    signal.signal(signal.SIGTERM, stopped)
    signal.signal(signal.SIGINT, stopped)
    try:
        result = run(args, work)
        artifacts = {}
        for name, bound in (("chronyd", MAX_ELF), ("chrony.conf", 4096), ("chrony.version.txt", 65536),
                            ("iso-tree/boot/absd-kernel", MAX_ELF), ("iso-tree/boot/grub/grub.cfg", 4096),
                            ("native-sntp.iso", 128 * 1024 * 1024), ("native-sntp.img", 2 * 1024 * 1024),
                            ("native-sntp.serial.log", MAX_LOG), ("native-sntp.pcap", MAX_CAPTURE),
                            ("chrony.log", MAX_LOG), ("qemu.log", MAX_LOG), ("iso-build.log", MAX_LOG),
                            ("LAUNCH.json", 65536), ("LOCAL-CLEANUP.json", 65536),
                            ("PEER-CONFIG.json", 65536), ("PEER-START.json", 65536)):
            path = work / name
            artifacts[name] = identity(path, read_bound(path, bound))
        result["artifacts"] = artifacts
    except BaseException as error:
        write(work / "RESULT.json", {"schema": "absd-native-sntp-proof/1", "disposition": "FAIL", "error": repr(error), "unrun": UNRUN})
        raise
    write(work / "RESULT.json", {"schema": "absd-native-sntp-proof/1", **result})
    print("NATIVE SNTP PROOF PASS")


if __name__ == "__main__":
    main()
