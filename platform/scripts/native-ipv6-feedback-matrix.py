#!/usr/bin/env python3
"""Native IPv6 DNS closed-port feedback against the isolated Linux kernel.

Builds only an ISO from exact prebuilt ELF buffers. No userspace packet
responder, public peer, host route/service change or source compilation.
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
import time
import uuid

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from served_ram import served_qemu

if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
    raise SystemExit("native-ipv6-feedback-matrix: optimized Python is refused")
ROOT = Path(__file__).resolve().parent.parent
# Separate source/build attestation is required alongside exact ELF buffers.
PRODUCT = "f593c5da9e16268d68c18ffb8a8b75513ce6a58d"
PRODUCT_TREE = "9e521573fed9a5d45dd6ce36037d9da9d4b8dbcf"
PRODUCT_ARCHIVE = "c8fb1e3eb0786b9fc62a8577d1385008bcadaaddf3a3283886adc0ce55099e14"
KERNEL = "ed6a15ea7c7c999422e1e294e139b6119619b06c"
KERNEL_TREE = "5c3834dcdb8cf393c86bc0e436ae62c7cda67af5"
KERNEL_ARCHIVE = "568ac7c029d9d8e6e101519b1341c2e860300cb7dded1e65ea526efaa731212e"
HOST_MAC, GUEST_MAC = bytes.fromhex("525500000202"), bytes.fromhex("525400ab5d15")
spec = importlib.util.spec_from_file_location("feedback_accounting", ROOT / "scripts/native-ipv6-feedback-accounting.py")
accounting = importlib.util.module_from_spec(spec)
spec.loader.exec_module(accounting)
MAX_ELF, MAX_CAPTURE, MAX_LOG = 64 * 1024 * 1024, 2 * 1024 * 1024, 8 * 1024 * 1024
CHUNK = re.compile(rb"EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]*)\n")
UNRUN = ["native malformed/insufficient/wrong-peer/checksum/quote/substitution errors",
         "native history/slot exhaustion, interrupted pipe, deadline/rewind/link/I/O loss or uncertain effects",
         "native PTB/TimeExceeded or routed recovery, general ICMPv6/IPv6, live SSH and hardware transfer",
         "physical clock accuracy, authentication and unique wire-generation/query provenance"]


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




def buffer_digest(data):
    return {"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}


def build_binding(receipt, child, parent, kernel):
    assert receipt["schema"] == "absd-native-ipv6-feedback-build/1"
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
    assert any(any(s.endswith("scripts/build-native-ipv6-feedback.sh") for s in c) for c in receipt["commands"])
    assert any(any(s.startswith("EXTERNAL_USER_ELF=") for s in c) for c in receipt["commands"])
    for name, data in (("child", child), ("parent", parent), ("kernel", kernel)):
        assert receipt["outputs"][name] == buffer_digest(data), f"build output binding: {name}"
        assert data.startswith(b"\x7fELF"), f"ELF magic: {name}"
    assert parent.count(child) == 1, "exact child not uniquely embedded in parent"
    assert kernel.count(parent) == 1, "exact parent not uniquely embedded in kernel"



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
        assert int(chunk[1],16) == len(output), "output offset/order"
        output.extend(bytes.fromhex(chunk[2].decode("ascii")))
        assert len(output) <= 16384, "native output bound"
    text = output.decode("utf-8")
    markers = ["IPV6 FEEDBACK SERVICE READY static-on-link scope=1 udp=7002 peer-port=42019\n",
               "IPV6 FEEDBACK AUTHORITY PASS wrong-peer-and-selector-refused no-nic\n",
               "IPV6 FEEDBACK SERVICE PASS child=exited sockets=0\n"]
    assert all(text.count(m) == 1 for m in markers), "native authority/retirement markers"
    found = re.findall(r"(?m)^IPV6 DNS FEEDBACK PASS type=1 code=4 detail=0 auth=none lookup_boot_ms=(\d+)$",text)
    assert len(found) == 1 and int(found[0]) < 3000, "one finite native diagnostic"
    observation = "IPV6 DNS FEEDBACK PASS type=1 code=4 detail=0 auth=none lookup_boot_ms="
    assert text.index(markers[0]) < text.index(markers[1]) < text.index(observation) < text.index(markers[2]), "native order"
    assert text.endswith(markers[-1]) and text.count("IPV6 ") == 4 and "ERROR" not in text
    stats = re.findall(rb"NIC STATS (.*)\n",raw)
    assert len(stats) == 1 and len(re.findall(rb"DURABLE status=[^\n]*\n",raw)) == 1
    counters = dict(f.split("=",1) for f in stats[0].decode("ascii").split())
    assert int(counters["rx_frames"]) > 0 and int(counters["tx_frames"]) > 0
    # The unchanged approved reason evaluator, not a new zero/tolerance rule,
    # decides rx_refused from complete raw capture and first-four logs.
    return {"kind":1,"code":4,"detail":0,"auth":"none","lookup_boot_ms":int(found[0]),
            "wrong_peer_and_selector_denied":True,"child_nic":False,"child_exit":0,
            "sockets_after_retirement":0,"output":text,"NIC_counters":counters}



def inspect(path, observation):
    capture = read_bound(path,MAX_CAPTURE)
    records, _ = accounting.original.capture_records(capture)
    census = [accounting.classify(r,GUEST_MAC,HOST_MAC,accounting.PROFILE) for r in records]
    assert all(r["kind"] in ("linux-mldv2","peer-nd","peer-udp-dns","peer-icmpv6-port-unreachable") for r in census), "unexplained whole capture frame"
    requests, errors, nd = [], [], []
    error_counts = {}
    for record,row in zip(records,census):
        frame = record["frame"]
        if row["kind"] == "peer-nd":
            nd.append({"index":record["index"],"type":frame[54],"outgoing":row["direction"]=="outgoing"})
        elif row["kind"] == "peer-udp-dns":
            assert row["direction"] == "outgoing", "closed Linux port emitted UDP application data"
            packet = frame[14:]
            query = packet[48:]
            assert query[2:] == bytes.fromhex("0100000100000000000006636c6f736564076578616d706c650000010001"), "exact closed.example A question"
            requests.append({"index":record["index"],"IP_hex":packet.hex(),"query_hex":query.hex()})
            assert len(requests) <= 4, "existing3s/750ms resolver retry budget"
        elif row["kind"] == "peer-icmpv6-port-unreachable":
            quote = frame[62:]
            candidates = [r["index"] for r in requests if bytes.fromhex(r["IP_hex"]) == quote]
            assert candidates, "complete quoted IP packet not previously captured as submitted query"
            key = quote.hex()
            error_counts[key] = error_counts.get(key, 0) + 1
            assert error_counts[key] <= len(candidates), "more errors than prior captured copies of exact quoted IP packet"
            errors.append({"index":record["index"],"quote_hex":quote.hex(),"compatible_request_indices":candidates})
            assert len(errors) <= len(requests), "more errors than captured controlled requests"
    assert requests and errors, "actual Linux query/error exchange required"
    assert len({r["query_hex"] for r in requests}) == 1, "one DNS question/ID, bounded identical retries"
    first = requests[0]["index"]
    assert any(a["outgoing"] and a["type"]==135 and any(not b["outgoing"] and b["type"]==136 and a["index"]<b["index"]<first for b in nd) for a in nd), "guest NS/Linux NA before first query"
    assert observation["kind"]==1 and observation["code"]==4 and observation["detail"]==0
    return {"capture":identity(path,capture),"requests":requests,"errors":errors,"ND":nd,"census":census,
            "correlation_limit":"Errors per exact quoted IP-byte group do not exceed prior captured copies. Identical copies retain all compatible indices without unique assignment. Source-bound native observer emits one consumed diagnostic; no packet-specific delivery, authentication or wire-generation claim."}



def run(args, work):
    assert os.geteuid() == 0, "requires root inside the owned disposable VM"
    deadline = time.monotonic() + args.timeout
    namespace, tap = "absdv6feedback-" + uuid.uuid4().hex, "feedback-tap0"
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
        buffers = {name: read_bound(path, MAX_ELF) for name, path in
                   (("kernel", args.kernel_elf), ("parent", args.elf), ("child", args.client_elf))}
        assert all(data.startswith(b"\x7fELF") and len(data) >= 64 for data in buffers.values()), "ELF input magic/size"
        assert buffers["parent"].count(buffers["child"]) == 1 and buffers["kernel"].count(buffers["parent"]) == 1 and buffers["kernel"].count(buffers["child"]) == 1, "exact unique child/parent/kernel embedding"
        inputs = {name: identity(path, buffers[name]) for name, path in
                  (("kernel", args.kernel_elf), ("parent", args.elf), ("child", args.client_elf))}
        receipt_bytes=read_bound(args.build_receipt,MAX_LOG)
        receipt=json.loads(receipt_bytes)
        build_binding(receipt,buffers["child"],buffers["parent"],buffers["kernel"])
        retained={}
        for name,data in buffers.items():
            destination=work/(name+".elf");destination.write_bytes(data)
            retained[destination.name]=identity(destination,data)
        destination=work/"BUILD-RECEIPT.json";destination.write_bytes(receipt_bytes)
        retained[destination.name]=identity(destination,receipt_bytes)
        for name in ("platform","kernel"):
            item=receipt[name]["archive"];data=read_bound(item["path"],MAX_ELF)
            assert buffer_digest(data)=={k:item[k] for k in ("bytes","sha256")}, "reviewed source archive buffer"
            destination=work/(name+"-source.tar");destination.write_bytes(data)
            retained[destination.name]=identity(destination,data)
        for index,item in enumerate([receipt["toolchain_receipt"],*receipt["logs"]]):
            data=read_bound(item["path"],MAX_LOG)
            assert buffer_digest(data)=={k:item[k] for k in ("bytes","sha256")}, "build log/toolchain buffer"
            destination=work/("build-input-"+str(index)+".log");destination.write_bytes(data)
            retained[destination.name]=identity(destination,data)
        tree = work / "iso-tree/boot/grub"
        tree.mkdir(parents=True)
        (tree.parent / "absd-kernel").write_bytes(buffers["kernel"])
        boot_config = b'insmod all_video\nset timeout=0\nmenuentry "ABSD IPv6 feedback" {\n multiboot2 /boot/absd-kernel durable=1 net nvme-write=absd\n boot\n}\n'
        (tree / "grub.cfg").write_bytes(boot_config)
        iso, disk = work / "native-ipv6-feedback.iso", work / "native-ipv6-feedback.img"
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
        for key in ("all.disable_ipv6=0", "default.disable_ipv6=0", "all.accept_ra=0",
                    "default.accept_ra=0", "default.autoconf=0", "default.dad_transmits=0"):
            checked(["ip","netns","exec",namespace,"sysctl","-qw","net.ipv6.conf."+key])
        for command in (["link","set","lo","up"], ["tuntap","add","dev",tap,"mode","tap"],
                        ["link","set",tap,"address",HOST_MAC.hex(":")], ["link","set",tap,"mtu","1500"],
                        ["link","set",tap,"up"], ["-6","addr","add","fd00:ab5d::2/64","dev",tap,"nodad"]):
            checked(["ip","-n",namespace,*command])
        address=json.loads(checked(["ip","-n",namespace,"-j","address","show","dev",tap]).stdout)
        assert len(address)==1 and address[0]["mtu"]==1500 and address[0]["address"]==HOST_MAC.hex(":") and "UP" in address[0]["flags"]
        assigned=address[0]["addr_info"]
        assert any(a["family"]=="inet6" and a["local"]=="fd00:ab5d::2" and a["prefixlen"]==64 for a in assigned)
        assert all(a["family"]=="inet6" and (a["local"]=="fd00:ab5d::2" or a["local"].startswith("fe80:")) for a in assigned)
        routes=json.loads(checked(["ip","-n",namespace,"-j","-6","route","show"]).stdout)
        assert any(r["dst"]=="fd00:ab5d::/64" and r["dev"]==tap for r in routes)
        assert all(r["dst"] in ("fd00:ab5d::/64","fe80::/64") and r["dev"]==tap and "gateway" not in r for r in routes), "only exact owned IPv6 connected routes"
        closed=checked(["ip","netns","exec",namespace,"ss","-H","-u","-l","-n"]).stdout
        assert not closed.strip(), "fresh namespace must have no UDP listener, including42019"
        peer={"scope":"CONFIGURED_LINUX_KERNEL_UDP_PORT_CLOSED; no control query or userspace responder",
              "kernel":list(os.uname()),"namespace":namespace,"network_namespace_inode":os.stat("/run/netns/"+namespace).st_ino,
              "address":address,"routes":routes,"UDP_listeners_before":closed}
        write(work/"LINUX-PEER.json",peer)
        serial, capture = work / "native-ipv6-feedback.serial.log", work / "native-ipv6-feedback.pcap"
        bounds[serial], bounds[capture] = MAX_LOG, MAX_CAPTURE
        qemu_binary = shutil.which(os.environ.get("ABSD_QEMU", "qemu-system-x86_64"))
        assert qemu_binary, "QEMU unavailable"
        command = served_qemu(["ip", "netns", "exec", namespace, str(Path(qemu_binary).resolve()),
                   "-accel", "tcg,thread=single", "-cpu", "max,vendor=GenuineIntel,+rdrand", "-smp", "1", "-m", "256M",
                   "-cdrom", str(iso), "-drive", f"file={disk},format=raw,if=ide,index=0", "-display", "none",
                   "-serial", f"file:{serial}", "-no-reboot", "-no-shutdown", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
                   "-device", f"e1000,netdev=n0,mac={GUEST_MAC.hex(':')}", "-netdev", f"tap,id=n0,ifname={tap},script=no,downscript=no,vnet_hdr=off",
                   "-object", f"filter-dump,id=cap0,netdev=n0,file={capture}"])
        iso_bytes=read_bound(iso,bounds[iso])
        assert iso_bytes.count(buffers["kernel"])==1, "exact kernel not uniquely present in ISO"
        iso_identity = identity(iso,iso_bytes)
        marker=accounting.ReadyMarker(serial,capture)
        marker.poll(running=False)
        qemu = start("qemu", command)
        write(work / "LAUNCH.json", {"schema": "absd-native-ipv6-feedback-launch/1", "namespace": namespace,
              "tap": tap, "qemu_pid_and_pgid": qemu.pid, "iso_builder_pid_and_pgid": builder.pid,
              "QEMU_command": command, "inputs": inputs, "ISO": iso_identity,
              "build_receipt":identity(work/"BUILD-RECEIPT.json",receipt_bytes),
              "accounting_sources":{name:identity(ROOT/"scripts"/name,read_bound(ROOT/"scripts"/name,MAX_LOG)) for name in
                 ("native-ipv6-feedback-accounting.py","native-ipv6-accounting.py","native-ipv6-reason-accounting.py")},
              "runner": identity(__file__, read_bound(__file__, MAX_LOG)), "Linux_peer": peer,
              "execution_host": list(os.uname()), "runner_pid": os.getpid(), "runner_uid": os.geteuid(),
              "environment_omitted": ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "NOTIFY_SOCKET"],
              "outer_timeout_seconds": args.timeout, "source_to_ELF_limit": "Exact input bytes and embedding only; compiler/source receipts are separately required."})
        while qemu.poll() is None:
            marker.poll(running=qemu.poll() is None)
            left(args.timeout)
            time.sleep(0.05)
        left(args.timeout)
        marker.poll(running=False)
        marker.seal(work)
        assert not checked(["ip","netns","exec",namespace,"ss","-H","-u","-l","-n"]).stdout.strip(), "closed peer changed"
        raw_serial = read_bound(serial, MAX_LOG)
        observation = native_output(raw_serial, qemu.returncode)
        captured = inspect(capture, observation)
        reason_result=accounting.evaluate(work,marker,observation["NIC_counters"],GUEST_MAC.hex(":"),HOST_MAC.hex(":"))
        assert reason_result["capture_sha256"]==captured["capture"]["sha256"] and reason_result["serial_sha256"]==buffer_digest(raw_serial)["sha256"], "protocol/accounting evaluated different raw buffers"
        sidecar_bytes=read_bound(work/"NIC-READY-CAPTURE.json",65536)
        reason_bytes=read_bound(work/"NIC-REASON-ACCOUNTING.json",MAX_LOG)
        assert buffer_digest(sidecar_bytes)["sha256"]==reason_result["annotation_sha256"] and json.loads(reason_bytes)==reason_result, "accounting serialized result/sidecar correspondence"
        result = {"disposition": "PASS", "scope": "one native DNS diagnostic with bounded identical query retries and independent Linux-kernel Port Unreachable",
                  "observation": observation, "capture_result": captured, "unrun": UNRUN,
                  "reason_accounting":reason_result,"evaluated_build_inputs":retained,
                  "source_binding_limit":f"Enforced {PRODUCT}/{KERNEL} source archives and resource-owner commands/log/toolchain attestation plus exact ELF/ISO buffers; no compiler-correctness proof.",
                  "evaluated_artifacts": {"native-ipv6-feedback.iso": iso_identity,
                      "iso-tree/boot/absd-kernel": inputs["kernel"],
                      "iso-tree/boot/grub/grub.cfg": identity(tree / "grub.cfg", boot_config),
                      "native-ipv6-feedback.serial.log": identity(serial, raw_serial),
                      "native-ipv6-feedback.pcap": captured["capture"],
                      "NIC-READY-CAPTURE.json":identity(work/"NIC-READY-CAPTURE.json",sidecar_bytes),
                      "NIC-REASON-ACCOUNTING.json":identity(work/"NIC-REASON-ACCOUNTING.json",reason_bytes)},
                  "limits": "Sampled boot-domain lookup/deadline and captured order only; no physical accuracy, authenticated identity, exact packet-generation assignment, hardware transfer or native negative-case claim. Non-atomic I/O can retain an already-submitted first effect."}
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
        write(work / "LOCAL-CLEANUP.json", {"schema": "absd-native-ipv6-feedback-cleanup/1", "namespace": namespace,
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
    parser.add_argument("--elf", type=Path, required=True, help="ipv6-feedback-service-probe.elf embedded in kernel")
    parser.add_argument("--client-elf", type=Path, required=True, help="ipv6-feedback-client.elf embedded in parent")
    parser.add_argument("--build-receipt",type=Path,required=True,help="source/build/output attestation for the enforced PRODUCT/KERNEL identities")
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
        for name, bound in (("iso-tree/boot/absd-kernel", MAX_ELF), ("iso-tree/boot/grub/grub.cfg", 4096),
                            ("native-ipv6-feedback.iso", 128 * 1024 * 1024), ("native-ipv6-feedback.img", 2 * 1024 * 1024),
                            ("native-ipv6-feedback.serial.log", MAX_LOG), ("native-ipv6-feedback.pcap", MAX_CAPTURE),
                            ("qemu.log", MAX_LOG), ("iso-build.log", MAX_LOG), ("LINUX-PEER.json", 65536),
                            ("LAUNCH.json", 65536), ("LOCAL-CLEANUP.json", 65536),
                            ("NIC-READY-CAPTURE.json",65536),("NIC-REASON-ACCOUNTING.json",MAX_LOG)):
            path = work / name
            artifacts[name] = identity(path, read_bound(path, bound))
            if name in result["evaluated_artifacts"]:
                expected = result["evaluated_artifacts"][name]
                assert all(artifacts[name][key] == expected[key] for key in ("bytes", "sha256")), "boot/evaluated artifact changed before final seal: " + name
        for name,expected in result["evaluated_build_inputs"].items():
            actual=identity(work/name,read_bound(work/name,MAX_ELF))
            assert all(actual[k]==expected[k] for k in ("bytes","sha256")), "build input changed before seal: "+name
            artifacts[name]=actual
        result["artifacts"] = artifacts
    except BaseException as error:
        write(work / "RESULT.json", {"schema": "absd-native-ipv6-feedback-proof/1", "disposition": "FAIL", "error": repr(error), "unrun": UNRUN})
        raise
    write(work / "RESULT.json", {"schema": "absd-native-ipv6-feedback-proof/1", **result})
    print("NATIVE IPV6 FEEDBACK PROOF PASS")


if __name__ == "__main__":
    main()
