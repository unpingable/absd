#!/usr/bin/env python3
"""One foreground IPv6 TCP server proof in an admitted disposable Linux VM.

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
    raise SystemExit("native-ipv6-tcp-server-matrix: optimized Python is refused")

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("server_boot", ROOT / "scripts/net-matrix.py")
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)
PROFILE = "ipv6-tcp-server-boundary-close-v2"
PRODUCT = "a5d3d746e23f3304495cff583cfd3b1612b50304"
PRODUCT_TREE = "c7c76f057c9bb02d7eb937f1baec6b3062fbce3c"
PRODUCT_ARCHIVE = "126174520bf0b6ea64ed2a164af92fc6fe7edc38ba3e93ba2c9be00f53a88326"
PRODUCT_BYTES = 26634240
KERNEL = "2775bbaf6c1b8ebbaec66579b39d1fd78d71e57b"
KERNEL_TREE = "8763f164ddfed11aa2f55626bd8e85123c595a08"
KERNEL_ARCHIVE = "fbfff7902d7bf6334b0c2d141558ef8cbdb23d56ce3db0c81dd32ebfb81be224"
KERNEL_BYTES = 12574720
SERVED_WRAPPER = "e3822e288d37e49a4efff2e30e35178d4c895c944ce43b4b690179565c6d51d2"
ACCOUNTING_HASH = "22d5f091c23c0d436be538d3695b43b3ed52b48ec5b4b30668be215a08001ad3"
import ipaddress
GUEST, HOST = (ipaddress.IPv6Address(s).packed for s in ("fd00:ab5d::1","fd00:ab5d::2"))
HOST_MAC, GUEST_MAC = bytes.fromhex("525500000501"), bytes.fromhex("525400123456")
READY = b"IPV6 TCP SERVER LISTEN READY v=1 sockets=1\n"
NIC_READY = b"NETWORK LINK OK rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048\n"
DATA = bytes((i * 131 ^ (i >> 7)) & 255 for i in range(3072))
MAX_CAPTURE, MAX_LOG, MAX_ELF, MAX_ISO = 2 << 20, 8 << 20, 64 << 20, 128 << 20
WRONG_TIMEOUT_NS, MIN_NEGATIVE_NS = 1_250_000_000, 1_000_000_000
POST_NEGATIVE_NS, MAX_POST_NEGATIVE_NS = 1_100_000_000, 2_000_000_000
UNRUN = ["native malformed outer prefix or wire input", "native connected-data/pending-reply consumer interruption",
         "native active-socket/buffer exhaustion, stale READ/WRITE, foreign handles, clock/link/pending reply faults", "IPv6 telemetry counter",
         "deliberate packet loss", "routed listener", "1280 MTU listener", "SSH coexistence",
         "RA/SLAAC/DHCPv6/extensions/fragments", "hardware and physical timing accuracy"]
helper_path=ROOT/"scripts/native-ipv6-accounting.py"
assert hashlib.sha256(helper_path.read_bytes()).hexdigest()==ACCOUNTING_HASH
spec=importlib.util.spec_from_file_location("ipv6_server_capture_helpers",helper_path)
accounting=importlib.util.module_from_spec(spec);spec.loader.exec_module(accounting)
CAPTURE_PROFILE={"guest":"fd00:ab5d::1","host":"fd00:ab5d::2","udp":None,"tcp":[7005,42030]}


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
    assert receipt["schema"] == "absd-native-ipv6-tcp-server-build/1" and receipt["profile"] == PROFILE
    for name, revision, tree, archive, size in (("platform", PRODUCT, PRODUCT_TREE, PRODUCT_ARCHIVE, PRODUCT_BYTES),
                                                ("kernel", KERNEL, KERNEL_TREE, KERNEL_ARCHIVE, KERNEL_BYTES)):
        source = receipt[name]
        assert source["revision"] == revision and source["tree"] == tree and source["clean"] is True
        assert source["archive"]["sha256"] == archive and source["archive"]["bytes"] == size
    assert receipt["commands"] and all(isinstance(c, list) and c and all(isinstance(s, str) for s in c)
                                       for c in receipt["commands"])
    assert 1 <= len(receipt["logs"]) <= 8 and all(re.fullmatch(r"[0-9a-f]{64}", log["sha256"])
                                   and log["bytes"] > 0 for log in receipt["logs"])
    toolchain = receipt["toolchain_receipt"]
    assert re.fullmatch(r"[0-9a-f]{64}", toolchain["sha256"]) and toolchain["bytes"] > 0
    assert any(any(s.endswith("scripts/build-native-ipv6-tcp-server.sh") for s in c) for c in receipt["commands"])
    assert receipt["served_kernel_policy"] == "frame-admission-v0" and receipt["served_wrapper_sha256"] == SERVED_WRAPPER
    assert any(any(s.endswith("scripts/served_kernel.py") for s in c)
               and "external-build" in c and any(s.startswith("EXTERNAL_USER_ELF=") for s in c)
               for c in receipt["commands"]), "current served-wrapper build command required"
    for name, data in (("child", child), ("parent", parent), ("kernel", kernel)):
        assert receipt["outputs"][name] == digest(data), f"build output binding: {name}"
        assert data.startswith(b"\x7fELF"), f"ELF magic: {name}"
    assert parent.count(child) == 1, "exact child not uniquely embedded in parent"
    assert kernel.count(parent) == 1, "exact parent not uniquely embedded in kernel"

def metadata_binding(receipt,data):
    assert digest(data)=={k:receipt["cargo_metadata"][k] for k in ("bytes","sha256")}, "actual Cargo metadata identity"
    metadata=json.loads(data);assert metadata["version"]==1
    package=[p for p in metadata["packages"] if p["name"]=="absd-std-probe"];assert len(package)==1
    for name in ("ipv6_tcp_server_echo","ipv6_tcp_server_service_probe"):
        targets=[t for t in package[0]["targets"] if t["name"]==name];assert len(targets)==1
        target=targets[0];assert target["kind"]==["bin"] and target["required-features"]==["native-ipv6-tcp-server-probe"]
        assert target["src_path"].endswith("/src/bin/"+name+".rs")
    assert receipt["staged_std"]=={"sha256":"c35493ccdf6cb87a81767902413ad4487caa1bff401d5ccecb1cce9e7a18760c","files":2251,"bytes":45920288}
    assert receipt["target"]=="x86_64-unknown-absd"
    return {"metadata":digest(data),"target":receipt["target"],"staged_std":receipt["staged_std"]}


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
        rows.append((sec * 1_000_000 + usec, data[at:at + size])); at += size; previous = (sec, usec)
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
    flows, census, wrong, nd = {"host":[],"guest":[]},[],[],[]
    timestamps=[];first_valid=None;wrong_sequences=set()
    for index,(timestamp,frame) in enumerate(records(data)):
        timestamps.append(timestamp)
        assert frame[6:12] in (HOST_MAC,GUEST_MAC), "third Ethernet source"
        outgoing=frame[6:12]==GUEST_MAC
        source,target=(GUEST,HOST) if outgoing else (HOST,GUEST)
        profile=dict(CAPTURE_PROFILE)
        if len(frame)>=58 and frame[12:14]==b"\x86\xdd" and frame[20]==6:
            sport,dport=struct.unpack("!HH",frame[54:58])
            if not outgoing and (sport,dport)==(42031,7005):profile["tcp"]=[7005,42031]
        item={"index":index+1,"frame":frame}
        classified=accounting.classify(item,GUEST_MAC,HOST_MAC,profile)
        assert classified["kind"] in ("peer-tcp","peer-nd","linux-mldv2"), "unexplained frame"
        row={"index":index,"timestamp_us":timestamp,**digest(frame),"kind":classified["kind"],
             "incoming":not outgoing,"filter_refused":classified["filter_refused"]}
        if row["kind"]=="peer-nd":
            nd.append((index,outgoing,frame[54]));row["icmpv6_type"]=frame[54]
        elif row["kind"]=="peer-tcp":
            assert frame[21]==64,"TCP hop limit"
            payload=frame[54:];sport,dport,seq,ack=struct.unpack("!HHII",payload[:12])
            header,flags=(payload[12]>>4)*4,payload[13]
            assert not payload[12]&15 and not flags&(4|32|64|128) and payload[18:20]==b"\0\0", "TCP flags/reset/urgent"
            options=tcp_options(payload[20:header]);body=payload[header:]
            if not outgoing and (sport,dport)==(42031,7005):
                assert flags==2 and ack==0 and not body and first_valid is None,"wrong-source flow progressed/late"
                wrong_sequences.add(seq);assert len(wrong_sequences)==1,"multiple wrong-source attempts"
                wrong.append(index);row["kind"]="refused-source-port-syn"
            else:
                assert (sport,dport)==((7005,42030) if outgoing else (42030,7005)),"ungranted TCP tuple"
                if first_valid is None:
                    assert not outgoing and flags==2 and wrong,"authorized connection before negative"
                    first_valid=index
                if flags&2:
                    assert flags==(18 if outgoing else 2) and not body,"invalid handshake"
                    assert 2 in options and int.from_bytes(options[2],"big")==1440,"profile MSS1440"
                flows["guest" if outgoing else "host"].append({"index":index,"seq":seq,"ack":ack,"flags":flags,"body":body})
                row.update(seq=seq,ack=ack,flags=flags,body_bytes=len(body))
        census.append(row)
    assert wrong and first_valid is not None,"refusal/flow absent"
    replies=[i for i,direction,kind in nd if direction and kind==136 and i<wrong[0]]
    assert replies,"guest NA readiness before wrong SYN absent"
    reply=replies[0]
    requests=[i for i,direction,kind in nd if not direction and kind==135 and i<reply]
    assert requests,"guest NA lacks prior matching Linux NS"
    gap=timestamps[first_valid]-timestamps[wrong[0]]
    assert gap>MIN_NEGATIVE_NS//1000,"negative capture interval not greater than one second"
    base, assembled, seen_end, fin, fin_ack, chunks = {}, {}, {}, {}, {}, {}
    for side in flows:
        syns = [r for r in flows[side] if r["flags"] & 2]
        assert syns and len({r["seq"] for r in syns}) == 1, "multiple connections"
        base[side] = syns[0]["seq"]; assembled[side] = {}; seen_end[side] = 0
        fin[side] = None; fin_ack[side] = None; chunks[side] = 0
    assert flows["host"][0]["index"] < flows["guest"][0]["index"]
    synack = flows["guest"][0]["index"]
    handshake = [r["index"] for r in flows["host"] if r["index"] > synack and r["flags"] & 16 and r["ack"] == (base["guest"]+1)&0xffffffff]
    assert handshake, "third handshake ACK missing"
    third = handshake[0]
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
        if body:
            assert row["index"] >= third and row["index"] > synack, "data preceded handshake"
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
    return {"frames":len(census),"wrong_port_syns":wrong,"first_authorized_syn":first_valid,
            "readiness_nd":{"request":census[requests[0]],"reply":census[reply]},"negative_interval_us":gap,
            "last_wrong_syn_to_authorized_us":timestamps[first_valid]-timestamps[wrong[-1]],
            "application_bytes_each":3072,"segments":chunks,"fin":fin,"fin_ack":fin_ack,"census":census}


def native_output(raw,status):
    assert status==3, f"QEMU exit {status}"
    for needed in (b"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ",b"\nDURABLE WORKLOAD OK\n",b"\nABSD BOOT OK\n",b"\nNETWORK LINK OK "):
        assert needed in raw, f"serial lacks {needed!r}"
    for bad in (b"PANIC",b"KERNEL FAULT",b"init: FAILED",b"NIC DISABLED",b"IPV6 TCP SERVER ERROR",b"IPV6 TCP SERVER ECHO ERROR"):
        assert bad not in raw, f"serial contains {bad!r}"
    output=bytearray();offset=0
    chunks=list(boot.CHUNK.finditer(raw));assert len(chunks)==raw.count(b"EXTERNAL OUTPUT CHUNK"),"invalid chunk line"
    for match in chunks:
        assert int(match[1],16)==offset,"output discontinuity"
        block=bytes.fromhex(match[2].decode());assert block;output.extend(block);offset+=len(block)
    end=re.findall(rb"(?m)^EXTERNAL OUTPUT END bytes=(\d+) digest=([0-9a-f]{8})\n",raw)
    value=0x811c9dc5
    for byte in output:value=((value^byte)*0x01000193)&0xffffffff
    assert len(end)==1 and int(end[0][0])==len(output) and end[0][1].decode()==f"{value:08x}","output digest/end"
    text=output.decode()
    rows=[line for line in text.splitlines() if not line.startswith("IPV6 TCP SERVER NEG ")]
    assert len(rows)==7,"exact owner/consumer record count"
    before=re.fullmatch(r"IPV6 TCP SERVER CENSUS v=1 label=before processes=(\d+) handles=(\d+) pipes=(\d+) cells=(\d+) frames=(\d+)",rows[0]);assert before
    grant=re.fullmatch(r"IPV6 TCP SERVER GRANT v=1 local=\[fd00:ab5d::1\]:7005 peer=\[fd00:ab5d::2\]:42030 scope=1 mtu=1500 accept_ms=5000 lifetime_ms=10000 owner_start_ms=(\d+) owner_until_ms=(\d+) sockets=0",rows[1]);assert grant
    assert int(grant[2])-int(grant[1])==10000,"original owner budget"
    assert rows[2]==READY.decode().rstrip("\n")
    assert rows[3]=="IPV6 TCP SERVER ECHO PASS v=1 bytes=3072 denied=1 nic=0"
    reap=re.fullmatch(r"IPV6 TCP SERVER REAP v=1 kind=1 status=0 request_eof=1 result_eof=1 pipe_read_bytes=(\d+) pipe_written_bytes=(\d+)",rows[4]);assert reap and all(int(n)>0 for n in reap.groups())
    after=re.fullmatch(r"IPV6 TCP SERVER CENSUS v=1 label=after processes=(\d+) handles=(\d+) pipes=(\d+) cells=(\d+) frames=(\d+)",rows[5]);assert after
    assert before.groups()[:4]==after.groups()[:4],"owned kernel objects not restored"
    assert rows[6]=="IPV6 TCP SERVER DONE v=1 child=exited sockets=0 authority=retired objects_restored=1"
    lines=re.findall(rb"(?m)^NIC STATS ([^\n]*)\n",raw);assert len(lines)==1
    fields=dict(field.split("=",1) for field in lines[0].decode().split())
    assert len(re.findall(rb"(?m)^DURABLE status=[^\n]*\n",raw))==1
    assert all(int(fields[k])>=0 for k in ("rx_frames","tx_frames","rx_refused","rx_missed","tx_refused","tx_errors"))
    assert int(fields["rx_frames"])>0 and int(fields["tx_frames"])>0
    assert not any(int(fields[k]) for k in ("rx_missed","tx_refused","tx_errors"))
    return {"stdout":text,"NIC_counters":fields,"output":digest(bytes(output)),"fnv1a32":f"{value:08x}",
            "objects_before":list(map(int,before.groups())),"objects_after":list(map(int,after.groups())),
            "frames_observed_only":True,"pipe_read_bytes":int(reap[1]),"pipe_written_bytes":int(reap[2])}


def boundary_observation(native):
    output=native["stdout"]
    rows=[line for line in output.splitlines() if line.startswith("IPV6 TCP SERVER NEG ")]
    assert len(rows)==32,"exact native boundary record count"
    def number(value):
        assert re.fullmatch(r"[0-9]+",value),"canonical nonnegative integer"
        n=int(value);assert n<=2**64-1;return n
    begin=re.fullmatch(r"IPV6 TCP SERVER NEG BEGIN v=1 whole_start_ms=([0-9]+) whole_until_ms=([0-9]+)",rows[0]);assert begin
    whole_start,whole_end=map(number,begin.groups());assert whole_end-whole_start==20000
    census=lambda line,label: re.fullmatch(r"IPV6 TCP SERVER NEG CENSUS v=1 label="+label+r" processes=([0-9]+) handles=([0-9]+) pipes=([0-9]+) cells=([0-9]+) frames=([0-9]+)",line)
    before=census(rows[1],"before");assert before
    ids=["local-port","peer-port","offlink","self","unspecified","multicast","scope-zero","scope-other","accept-low","accept-high","lifetime-short","lifetime-high"]
    for i,name in enumerate(ids):
        code=2 if i<8 else 1
        assert rows[2+i]==f"IPV6 TCP SERVER NEG GRANT v=1 case={name} code={code} sockets=0 tx=0","constructor refusal/effect"
    assert rows[14]=="IPV6 TCP SERVER NEG SLOTS v=1 reserved=8 duplicate=3 ninth=4 sockets=0 tx=0"
    assert rows[15]=="IPV6 TCP SERVER NEG SLOTS RETIRED v=1 stale=8 fresh=8 sockets=0 tx=0"
    bootstrap="03fd00ab5d00000000000000000000000200000001a42e"
    assert rows[16]==f"IPV6 TCP SERVER NEG BOOTSTRAP v=1 bytes=23 hex={bootstrap}","separate actual peer bootstrap"
    literals=(
        ("version","001c02200006fd00ab5d00000000000000000000000200000001a42e0000","001c03200106fd00ab5d00000000000000000000000200000001a42e0000"),
        ("family","001c03200004fd00ab5d00000000000000000000000200000001a42e0000","001c03200106fd00ab5d00000000000000000000000200000001a42e0000"),
        ("reserved","001c03207f06fd00ab5d00000000000000000000000200000001a42e0000","001c03200106fd00ab5d00000000000000000000000200000001a42e0000"),
        ("listen-length","001c03200006fd00ab5d00000000000000000000000200000001a42e0001","001c03200106fd00ab5d00000000000000000000000200000001a42e0000"),
        ("connect","001c03100006fd00ab5d00000000000000000000000200000001a42e0000","001c03100106fd00ab5d00000000000000000000000200000001a42e0000"),
        ("write-declared-without-body","001c03120006fd00ab5d00000000000000000000000200000001a42e0401","001c03120106fd00ab5d00000000000000000000000200000001a42e0000"),
        ("peer-port","001c03200006fd00ab5d00000000000000000000000200000001a42f0000","001c03200206fd00ab5d00000000000000000000000200000001a42e0000"),
        ("scope","001c03200006fd00ab5d00000000000000000000000200000002a42e0000","001c03200206fd00ab5d00000000000000000000000200000001a42e0000"),
        ("peer-ip","001c03200006fd00ab5d00000000000000000000000300000001a42e0000","001c03200206fd00ab5d00000000000000000000000200000001a42e0000"))
    requests,replies=bytearray(),bytearray()
    for i,(name,request,reply) in enumerate(literals):
        match=re.fullmatch(r"IPV6 TCP SERVER NEG API v=1 case="+name+r" request=([0-9a-f]+) reply=([0-9a-f]+) sockets=0 tx=0",rows[17+i]);assert match
        assert match.groups()==(request,reply),"actual literal request/reply differs"
        requests.extend(bytes.fromhex(match[1]));replies.extend(bytes.fromhex(match[2]))
    listen="001c03200006fd00ab5d00000000000000000000000200000001a42e0000"
    listening="001d03200006fd00ab5d00000000000000000000000200000001a42e000100"
    assert rows[26]==f"IPV6 TCP SERVER NEG LISTEN v=1 request={listen} reply={listening} sockets=1 tx=0"
    requests.extend(bytes.fromhex(listen));replies.extend(bytes.fromhex(listening))
    prefix="IPV6 TCP SERVER NEG INTERRUPT v=1 "
    assert rows[27].startswith(prefix)
    fields=dict(part.split("=",1) for part in rows[27][len(prefix):].split())
    keys={"child_handle","constructed_ms","grant_until_ms","partial_poll_ms","observed_ms","prefix","prefix_bytes","input_bytes","output_bytes","kill_ms","kill_return","reaped_ms","wait_kind","wait_status","eof_ms","retired_ms","channel_live","sockets","tx","fallback_fence"}
    assert set(fields)==keys and fields["prefix"]=="00"
    event={k:number(v) for k,v in fields.items() if k!="prefix"}
    assert event["child_handle"]>0 and event["prefix_bytes"]==1 and event["input_bytes"]==301 and event["output_bytes"]==301
    assert event["kill_return"]==0 and event["wait_kind"]==3 and event["wait_status"]==0
    assert all(event[k]==0 for k in ("channel_live","sockets","tx","fallback_fence"))
    assert whole_start<=event["constructed_ms"]<=event["partial_poll_ms"]<=event["observed_ms"]<=event["kill_ms"]<=event["reaped_ms"]<=event["eof_ms"]<=event["retired_ms"]
    assert event["grant_until_ms"]==event["constructed_ms"]+10000<=whole_end
    assert event["retired_ms"]<min(event["grant_until_ms"],event["partial_poll_ms"]+250),"deadline/fallback retirement cannot substitute for EOF"
    requests.extend(bytes.fromhex(fields["prefix"]));assert len(requests)==len(replies)==301
    assert rows[28]=="IPV6 TCP SERVER NEG CHILD v=1 cases=9 listen=1 nic=0"
    assert rows[29]=="IPV6 TCP SERVER NEG CLOSED v=1 process_reaped=1 protocol_handles=2 result_handles=1 result_eof=1"
    after=census(rows[30],"after");assert after
    before_values=list(map(number,before.groups()));after_values=list(map(number,after.groups()))
    assert before_values[:4]==after_values[:4],"closed owned object census differs"
    assert rows[31]=="IPV6 TCP SERVER NEG COMPLETE v=1 grants=12 api=9 slots=8 interrupted=1 objects_restored=1 sockets=0 tx=0"
    positive=re.search(r"IPV6 TCP SERVER GRANT v=1 [^\n]*owner_start_ms=([0-9]+) owner_until_ms=([0-9]+) sockets=0\n",output);assert positive
    start,end=map(number,positive.groups());assert event["retired_ms"]<=start and end==start+10000<=whole_end
    assert output.index(rows[31])<output.index("IPV6 TCP SERVER CENSUS v=1 label=before ")<positive.start(),"fresh positive construction order"
    return {"schema":"absd-native-ipv6-tcp-server-boundary/1","bootstrap_bytes":23,"input_bytes":len(requests),"output_bytes":len(replies),"input":digest(bytes(requests)),"output":digest(bytes(replies)),"interruption":event,"census_before":before_values,"census_after":after_values,"frame_delta_observed":after_values[4]-before_values[4],"whole_start_ms":whole_start,"whole_until_ms":whole_end,"positive_start_ms":start,"positive_until_ms":end,"limits":"Typed API/constructor reservations and LISTEN partial-prefix exact child interruption only; frames observed, not full memory restoration or connected-data interruption."}


def peer_results(wrong,peer,capture):
    assert wrong["disposition"]=="PASS" and wrong["local"]==["fd00:ab5d::2",42031] and wrong["peer"]==["fd00:ab5d::1",7005]
    assert wrong["result"]=="connect-timeout" and wrong["sent_bytes"]==0 and wrong["connect_attempts"]==1 and wrong["timeout_ns"]==WRONG_TIMEOUT_NS
    assert type(wrong["started_monotonic_ns"]) is type(wrong["ended_monotonic_ns"]) is int
    assert wrong["ended_monotonic_ns"]-wrong["started_monotonic_ns"]>MIN_NEGATIVE_NS
    assert peer["disposition"]=="PASS" and peer["local"][:2]==["fd00:ab5d::2",42030] and peer["peer"][:2]==["fd00:ab5d::1",7005]
    assert peer["bytes"]==3072 and peer["sha256"]==digest(DATA)["sha256"] and peer["write_half_closed"] is True and peer["read_EOF"] is True
    assert all(type(peer[k]) is int for k in ("connect_started_monotonic_ns","connected_monotonic_ns","completed_monotonic_ns"))
    assert wrong["post_negative_required_ns"] == POST_NEGATIVE_NS
    assert type(wrong["post_negative_started_monotonic_ns"]) is type(wrong["post_negative_ended_monotonic_ns"]) is int
    quiet_start,quiet_end=wrong["post_negative_started_monotonic_ns"],wrong["post_negative_ended_monotonic_ns"]
    assert wrong["ended_monotonic_ns"]<=quiet_start and POST_NEGATIVE_NS<=quiet_end-quiet_start<=MAX_POST_NEGATIVE_NS
    assert quiet_end<=peer["connect_started_monotonic_ns"]<=peer["connected_monotonic_ns"]<=peer["completed_monotonic_ns"]
    assert capture["readiness_nd"]["request"]["index"]<capture["readiness_nd"]["reply"]["index"]<capture["wrong_port_syns"][0]


def counter_binding(raw,capture,marker,native):
    a=marker.annotation;assert a is not None and a["observation"] is not None and a["previous_absent"] is not None
    observation=a["observation"];assert observation["producer_observed_running"] is True
    assert a["capture"]["sha256"]==hashlib.sha256(capture).hexdigest() and a["serial"]["sha256"]==hashlib.sha256(raw).hexdigest()
    for sample in (a["previous_absent"],observation):
        assert hashlib.sha256(raw[:sample["serial_bytes"]]).hexdigest()==sample["serial_sha256"]
        for key in ("capture_before_serial_read","capture_after_serial_read"):
            s=sample[key];assert not s["partial_record"] and hashlib.sha256(capture[:s["bytes"]]).hexdigest()==s["sha256"]
    assert observation["capture_before_serial_read"]["bytes"]>=24 and observation["capture_after_serial_read"]["bytes"]>=24
    boundary=a["marker_after_record"]
    rows=inspect_capture(capture)["census"]
    assert not any(r["filter_refused"] for r in rows[:boundary]),"ambiguous pre-observation NIC refusal"
    expected=sum(r["filter_refused"] for r in rows[boundary:])
    assert all(not r["filter_refused"] or r["kind"]=="linux-mldv2" for r in rows),"transport/ND frame refused at NIC"
    assert int(native["NIC_counters"]["rx_refused"])==expected,"exact NIC refusal census"
    return {"marker_after_record":boundary,"expected_refused":expected,"actual_refused":expected,
            "scope":"Observed serial/capture prefixes and exact Linux MLD destination refusals; no guest/host clock comparison."}


def post_negative_wait():
    # The socket is already closed. Cold ND may consume its connect timeout,
    # so that timeout alone cannot establish the strict on-wire SYN interval.
    start=time.monotonic_ns();previous=start
    while previous-start<POST_NEGATIVE_NS:
        time.sleep((start+POST_NEGATIVE_NS-previous)/1_000_000_000)
        observed=time.monotonic_ns()
        assert previous<=observed<=start+MAX_POST_NEGATIVE_NS,"post-negative fixture clock/stall"
        previous=observed
    return {"post_negative_required_ns":POST_NEGATIVE_NS,
            "post_negative_started_monotonic_ns":start,
            "post_negative_ended_monotonic_ns":previous}


def wrong_port_client(result):
    with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as sock:
        sock.bind(("fd00:ab5d::2",42031));sock.settimeout(WRONG_TIMEOUT_NS/1_000_000_000)
        start=time.monotonic_ns()
        try:sock.connect(("fd00:ab5d::1",7005))
        except TimeoutError:
            end=time.monotonic_ns();assert end-start>MIN_NEGATIVE_NS
            receipt={"disposition":"PASS","local":["fd00:ab5d::2",42031],"peer":["fd00:ab5d::1",7005],"result":"connect-timeout","sent_bytes":0,"connect_attempts":1,"timeout_ns":WRONG_TIMEOUT_NS,"started_monotonic_ns":start,"ended_monotonic_ns":end}
        else:raise AssertionError("wrong source port connected")
    receipt.update(post_negative_wait())
    write(result,receipt)


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

def prepare_peer_link(namespace, tap):
    # An automatic link-local address would join multicast groups when QEMU
    # opens the TAP, before the guest NIC is ready to account for their reports.
    for key in ("all.disable_ipv6=0", "default.disable_ipv6=0", "all.accept_ra=0", "default.accept_ra=0",
                "default.autoconf=0", "default.dad_transmits=0", "default.addr_gen_mode=1"):
        checked(["ip", "netns", "exec", namespace, "sysctl", "-qw", "net.ipv6.conf." + key])
    for command in (["link", "set", "lo", "up"], ["tuntap", "add", "dev", tap, "mode", "tap"],
                    ["link", "set", tap, "address", HOST_MAC.hex(":")], ["link", "set", tap, "mtu", "1500"],
                    ["link", "set", tap, "up"]):
        checked(["ip", "-n", namespace, *command])
    link = json.loads(checked(["ip", "-j", "-n", namespace, "link", "show", "dev", tap]).stdout)
    assert len(link) == 1 and link[0]["mtu"] == 1500 and link[0]["address"] == HOST_MAC.hex(":")
    assert checked(["ip", "netns", "exec", namespace, "sysctl", "-n",
                    "net.ipv6.conf." + tap + ".addr_gen_mode"]).stdout.strip() == "1"
    addresses = json.loads(checked(["ip", "-j", "-6", "-n", namespace, "addr", "show", "dev", tap]).stdout)
    assert len(addresses) <= 1 and all(a["addr_info"] == [] for a in addresses), "peer address exists before NIC readiness"
    return link

def activate_peer(namespace, tap, marker):
    observation = marker.observation
    assert observation is not None and observation["producer_observed_running"] is True, "NIC readiness not observed"
    assert observation["serial_ready_line"] == NIC_READY.decode(), "wrong NIC readiness observation"
    before = json.loads(checked(["ip", "-j", "-6", "-n", namespace, "addr", "show", "dev", tap]).stdout)
    assert len(before) <= 1 and all(a["addr_info"] == [] for a in before), "peer activated before NIC readiness"
    checked(["ip", "-n", namespace, "-6", "addr", "add", "fd00:ab5d::2/64", "dev", tap, "nodad"])
    after = json.loads(checked(["ip", "-j", "-6", "-n", namespace, "addr", "show", "dev", tap]).stdout)
    assert len(after) == 1 and [(a["family"], a["local"], a["prefixlen"]) for a in after[0]["addr_info"]] == [("inet6", "fd00:ab5d::2", 64)], "unexpected peer address"
    return {"schema": "absd-ipv6-peer-activation/1", "NIC_ready_observation": observation,
            "addresses_before": before, "addresses_after": after,
            "meaning": "Exact Linux peer address activated after an actual running NIC-ready observation. No capture trimming, counter reset, or guest deadline renewal."}

def readiness_observed(marker, serial, nic_marker):
    if marker == NIC_READY:
        observation = nic_marker.observation
        if observation is None:
            return False
        assert observation["producer_observed_running"] is True, "NIC observed after producer stopped"
        assert observation["serial_ready_line"] == NIC_READY.decode(), "wrong raw NIC readiness"
        return True
    return marker in boot.stdout_of(serial)

def run(args, work):
    assert os.geteuid() == 0, "run only as root inside the admitted disposable VM"
    inputs = {name: read_bound(path, MAX_ELF) for name, path in
              (("child", args.child_elf), ("parent", args.elf), ("kernel", args.kernel_elf))}
    receipt_bytes = read_bound(args.build_receipt, MAX_LOG)
    receipt = json.loads(receipt_bytes); build_binding(receipt, **inputs)
    metadata_bytes=read_bound(receipt["cargo_metadata"]["path"], MAX_LOG)
    metadata_result=metadata_binding(receipt,metadata_bytes)
    (work/"CARGO-METADATA.json").write_bytes(metadata_bytes)
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
    (tree / "grub.cfg").write_text('insmod all_video\nset timeout=0\nmenuentry "ABSD IPv6 TCP server" {\n multiboot2 /boot/absd-kernel durable=1 net nvme-write=absd\n boot\n}\n')
    iso, disk = work / "native-ipv6-tcp-server.iso", work / "native-ipv6-tcp-server.img"
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
    namespace, tap = "absdv6s-" + uuid.uuid4().hex[:12], "v6s-tap0"
    created, creation_attempted, qemu, clients, logs, errors = False, False, None, [], [], []
    try:
        assert not namespace_present(namespace), "namespace name already exists"
        # ip may mutate the namespace and then time out or lose its response.
        creation_attempted = True
        checked(["ip", "netns", "add", namespace]); created = True
        link = prepare_peer_link(namespace, tap)
        serial, capture = work / "serial.log", work / "capture.pcap"
        qlog = (work / "qemu.log").open("wb"); logs.append(qlog)
        command = served_qemu(["ip", "netns", "exec", namespace, os.environ.get("ABSD_QEMU", "qemu-system-x86_64"),
                   "-accel", "tcg,thread=single", "-cpu", "max,vendor=GenuineIntel,+rdrand", "-smp", "1", "-m", "256M",
                   "-cdrom", str(iso), "-drive", f"file={disk},format=raw,if=ide,index=0", "-display", "none",
                   "-serial", f"file:{serial}", "-no-reboot", "-no-shutdown", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
                   "-device", f"e1000,netdev=n0,mac={GUEST_MAC.hex(':')}", "-netdev", f"tap,id=n0,ifname={tap},script=no,downscript=no,vnet_hdr=off",
                   "-object", f"filter-dump,id=cap0,netdev=n0,file={capture}"])
        nic_marker = accounting.ReadyMarker(serial,capture)
        nic_marker.poll(running=False)
        qemu = subprocess.Popen(command, stdout=qlog, stderr=subprocess.STDOUT,
                                start_new_session=True, preexec_fn=producer_file_limit)
        deadline = time.monotonic() + args.timeout
        write(work / "LAUNCH.json", {"profile": PROFILE, "namespace": namespace, "tap": tap, "qemu_pid_pgid": qemu.pid,
              "command": command, "inputs": {k: digest(v) for k, v in inputs.items()}, "iso": digest(iso_bytes),
              "iso_command": iso_command, "iso_builder_pid_pgid": maker.pid, "iso_builder_terminal": maker.returncode,
              "iso_builder_group_cleanup": iso_group,
              "build_receipt": digest(receipt_bytes), "runner": digest(read_bound(__file__, MAX_LOG)),
              "boot_helper": digest(read_bound(boot.__file__, MAX_LOG)),
              "peer_source": digest(read_bound(ROOT / "scripts/native-ipv6-tcp-server-peer.py", MAX_LOG)),
              "namespace_link": link, "timeout_seconds": args.timeout})

        def bounded_wait(process=None, marker=None):
            while True:
                nic_marker.poll(running=qemu.poll() is None)
                for path, limit in ((serial, MAX_LOG), (capture, MAX_CAPTURE), (work / "qemu.log", MAX_LOG),
                                    (work / "wrong-port.log", MAX_LOG),
                                    (work / "peer.log", MAX_LOG)):
                    assert not path.exists() or path.stat().st_size <= limit, f"output bound: {path}"
                assert time.monotonic() < deadline, "proof wall deadline"
                if marker is not None:
                    if readiness_observed(marker, serial, nic_marker):
                        return
                    assert qemu.poll() is None, "guest exited before LISTEN readiness"
                elif process.poll() is not None:
                    return
                time.sleep(0.02)

        bounded_wait(marker=NIC_READY)
        write(work / "PEER-ACTIVATION.json", activate_peer(namespace, tap, nic_marker))
        bounded_wait(marker=READY)
        write(work / "LISTEN-OBSERVED.json", {"marker": READY.decode(), "serial_prefix": digest(read_bound(serial, MAX_LOG)),
              "observation_monotonic": time.monotonic(), "meaning": "Trusted sole-socket marker observed before wrong-port client launch. No counter reset, capture boundary selection or physical-time equivalence."})
        for name, script in (("wrong-port", [sys.executable, str(Path(__file__).resolve()), "--wrong-port-client"]),
                             ("peer", [sys.executable, str(ROOT / "scripts/native-ipv6-tcp-server-peer.py")])):
            log = (work / (name + ".log")).open("wb"); logs.append(log)
            process = subprocess.Popen(["ip", "netns", "exec", namespace, *script, str(work / (name + ".json"))],
                                       stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                                       preexec_fn=producer_file_limit)
            clients.append(process); bounded_wait(process=process)
            assert process.returncode == 0, name + " client failed"
        bounded_wait(process=qemu)
        result = native_output(read_bound(serial, MAX_LOG), qemu.returncode)
        boundary_result=boundary_observation(result)
        capture_bytes = read_bound(capture, MAX_CAPTURE)
        capture_result = inspect_capture(capture_bytes)
        nic_marker.seal(work)
        counter_result = counter_binding(read_bound(serial, MAX_LOG), capture_bytes, nic_marker, result)
        wrong = json.loads(read_bound(work / "wrong-port.json", MAX_LOG))
        peer = json.loads(read_bound(work / "peer.json", MAX_LOG))
        peer_results(wrong, peer, capture_result)
        result.update({"disposition": "PASS", "profile": PROFILE, "scope": "native constructor/API/partial-prefix retirement followed by exact-peer IPv6 TCP echo and observed wrong-source-port refusal",
                       "capture": digest(capture_bytes), "capture_result": capture_result,
                       "counter_binding": counter_result,
                       "native_boundary": boundary_result,
                       "metadata_binding": metadata_result,
                       "accounting_helper": digest(read_bound(accounting.__file__, MAX_LOG)),
                       "wrong_port_result": digest(read_bound(work / "wrong-port.json", MAX_LOG)),
                       "peer_result": digest(read_bound(work / "peer.json", MAX_LOG)), "unrun": UNRUN,
                       "peer_activation": digest(read_bound(work / "PEER-ACTIVATION.json", MAX_LOG)),
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
              "custody": "Root retains exact ELF/ISO/capture/log/receipt inputs for review/replay. Reproducible scratch retires after dependencies end; review source handoff or 2026-10-18T23:59:59Z."})
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
        write(work / "RESULT.json", {"schema": "absd-native-ipv6-tcp-server-proof/4", "profile": PROFILE, "disposition": "FAIL", "error": repr(error), "unrun": UNRUN})
        raise
    write(work / "RESULT.json", {"schema": "absd-native-ipv6-tcp-server-proof/4", **result})
    print("NATIVE IPV6 TCP SERVER PROOF PASS")

if __name__ == "__main__":
    main()
