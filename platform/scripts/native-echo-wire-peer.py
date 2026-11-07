#!/usr/bin/env python3
"""Finite malformed IPv4 Echo replies on an occurrence-owned Linux TAP.

The peer supplies only the nine disclosed negative frames. Linux supplies ARP
and the subsequent positive Echo reply. This helper never creates a namespace
or changes an interface outside the namespace selected by its caller.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import struct
import tempfile
import time

CASES = ("wrong-peer", "wrong-type", "wrong-code", "wrong-identifier",
         "wrong-sequence", "wrong-body", "wrong-epoch", "wrong-nonce",
         "bad-checksum")
GUEST_MAC = bytes.fromhex("525400123456")
PEER_MAC = bytes.fromhex("525500000501")
GUEST_IP = bytes((192, 0, 2, 100))
PEER_IP = bytes((192, 0, 2, 1))
MAX_SERIAL = 2 * 1024 * 1024


def checksum(data):
    """Internet checksum, including odd-length inputs."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + str(len(data) // 2) + "H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def checked_request(frame):
    assert len(frame) == 74, "exact negative request length"
    assert frame[:14] == PEER_MAC + GUEST_MAC + b"\x08\x00", "request Ethernet tuple"
    ip, icmp = frame[14:34], frame[34:]
    assert ip[0] == 0x45 and ip[2:4] == b"\x00\x3c", "request IPv4 layout"
    assert int.from_bytes(ip[6:8], "big") & 0x3fff == 0, "request nonfragment"
    assert ip[9] == 1 and ip[12:20] == GUEST_IP + PEER_IP, "request IPv4 tuple"
    assert checksum(ip) == 0 and checksum(icmp) == 0, "request checksums"
    assert icmp[:2] == b"\x08\0" and icmp[8:16] == b"ABSDPING", "fixed Echo request"
    assert all(int.from_bytes(icmp[a:b], "big") for a, b in
               ((4, 6), (6, 8), (16, 24), (24, 32), (32, 40))), "nonzero request correlation"
    return icmp


def negative_reply(request, case):
    """Change exactly the selected field of a reflected Echo reply.

    The type3 case retains the Echo body; it is a deliberately malformed type3
    packet, not an ICMP error quotation conformance case.
    """
    assert case in CASES, "unknown negative case"
    icmp = bytearray(checked_request(request))
    icmp[0] = 0
    source = PEER_IP
    if case == "wrong-peer":
        source = bytes((192, 0, 2, 2))
    elif case == "wrong-type":
        icmp[0] = 3
    elif case == "wrong-code":
        icmp[1] = 1
    else:
        offsets = {"wrong-identifier": 4, "wrong-sequence": 6,
                   "wrong-body": 8, "wrong-epoch": 24, "wrong-nonce": 32}
        if case in offsets:
            icmp[offsets[case]] ^= 1
    icmp[2:4] = b"\0\0"
    icmp[2:4] = checksum(bytes(icmp)).to_bytes(2, "big")
    if case == "bad-checksum":
        icmp[2] ^= 1
    # Keep the captured IPv4 identification/flags/TTL. Only swap endpoints
    # and recompute the checksum; no native configuration is inferred here.
    ip = bytearray(request[14:34])
    ip[12:20] = source + GUEST_IP
    ip[10:12] = b"\0\0"
    ip[10:12] = checksum(bytes(ip)).to_bytes(2, "big")
    return GUEST_MAC + PEER_MAC + b"\x08\x00" + bytes(ip) + bytes(icmp)


def serial_output(path):
    """Decode only complete contiguous output records during a live run."""
    if not path.exists():
        return b""
    raw = path.read_bytes()
    assert len(raw) <= MAX_SERIAL, "serial byte bound"
    output = bytearray()
    for line in raw.splitlines(keepends=True):
        if not line.endswith(b"\n"):
            break
        match = re.fullmatch(rb"EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]+)\r?\n", line)
        if match:
            assert int(match[1], 16) == len(output), "live serial offset"
            assert len(match[2]) % 2 == 0, "live serial hex"
            output.extend(bytes.fromhex(match[2].decode()))
    return bytes(output)


def identity(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "hex": data.hex()}


def write(path, value):
    # The runner observes readiness while this actor is live. Publish complete
    # JSON with exclusive destination creation; existence cannot mean half JSON.
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".echo-wire-")
    try:
        with os.fdopen(fd, "w") as output:
            json.dump(value, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def fields(line):
    return dict(re.findall(r"(\w+)=([^ ]+)", line))


def complete_lines(output):
    return [line.rstrip("\r\n") for line in output.decode("ascii").splitlines(keepends=True)
            if line.endswith("\n")]


def acknowledged(output, index, frame):
    lines = complete_lines(output)
    cases = [fields(line) for line in lines if line.startswith("ECHO WIRE CASE ")
             and fields(line).get("index") == str(index)]
    if not cases:
        return None
    assert len(cases) == 1, "one native acknowledgement per case"
    row = cases[0]
    expected = dict(v="1", case=CASES[index], code="5", observations="0", sockets="1", requests="1")
    assert all(row.get(key) == value for key, value in expected.items()), "native negative result"
    receives = [fields(line) for line in lines if line.startswith("ECHO WIRE FRAME ")
                and fields(line).get("direction") == "rx"
                and fields(line).get("ordinal") == row["receive_ordinal"]]
    assert len(receives) == 1, "actual native receive record"
    received = receives[0]
    assert received.get("phase") == "negative" and received.get("v") == "1", "negative ingress phase"
    assert received.get("bytes") == str(len(frame)) and received.get("hex") == frame.hex(), "native delivered bytes equal sent case"
    assert int(received["at_ms"]) <= int(row["at_ms"]), "ingress precedes no-observation result"
    return row


def run(args, report):
    deadline = time.monotonic() + args.timeout
    setting = Path("/proc/sys/net/ipv4/icmp_echo_ignore_all")
    assert setting.read_text().strip() == "1", "Linux Echo must initially be suppressed in owned namespace"
    report["network_namespace_inode"] = os.stat("/proc/self/ns/net").st_ino
    report["initial_echo_ignore_all"] = "1"

    def remaining():
        left = deadline - time.monotonic()
        assert left > 0, "negative peer wall deadline"
        return min(0.01, left)

    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as link:
        link.bind((args.tap, 0))
        link.settimeout(remaining())
        write(args.output.with_suffix(".ready.json"), {"schema": "absd-echo-wire-peer-ready/1",
              "tap": args.tap, "pid": os.getpid(), "network_namespace_inode": report["network_namespace_inode"],
              "echo_ignore_all": "1"})
        seen = 0
        while True:
            link.settimeout(remaining())
            try:
                request, address = link.recvfrom(2048)
            except socket.timeout:
                continue
            seen += 1
            assert seen <= 256, "pre-request packet bound"
            if address[2] == 4:  # PACKET_OUTGOING is Linux/this actor, not guest ingress.
                continue
            if len(request) >= 34 and request[6:12] == GUEST_MAC and request[12:14] == b"\x08\x00" and request[23] == 1:
                checked_request(request)
                break
        report["negative_request"] = identity(request)
        while True:
            remaining()
            begin = [fields(line) for line in complete_lines(serial_output(args.serial))
                     if line.startswith("ECHO WIRE BEGIN ")]
            if begin:
                assert len(begin) == 1 and begin[0].get("cases") == "9", "native wire profile BEGIN"
                break
            time.sleep(0.005)
        # One selected frame at a time: an acknowledged actual Link receive
        # and Owner.observe(Again) must precede the next selected send.
        for index, case in enumerate(CASES):
            frame = negative_reply(request, case)
            if index == len(CASES) - 1:
                # The original request has already been followed by eight
                # processed negative replies. Enabling before the final frame
                # avoids racing the new grant's first/only request with serial
                # polling. We never replay either request or supply a good reply.
                assert setting.read_text().strip() == "1", "Echo suppression held during first eight cases"
                setting.write_text("0\n")
                assert setting.read_text().strip() == "0", "Linux Echo enabled before final negative"
                report["enable_before_case"] = index
            sent_at = time.monotonic_ns()
            assert link.send(frame) == len(frame), "complete selected Ethernet send"
            row = {"index": index, "case": case, "send_monotonic_ns": sent_at,
                   "frame": identity(frame)}
            report["cases"].append(row)
            while True:
                remaining()
                output = serial_output(args.serial)
                ack = acknowledged(output, index, frame)
                if ack is not None:
                    row["native_acknowledgement"] = ack
                    row["ack_read_monotonic_ns"] = time.monotonic_ns()
                    break
                time.sleep(0.005)
        report["final_echo_ignore_all"] = setting.read_text().strip()
        assert report["final_echo_ignore_all"] == "0", "Linux remains sole positive responder"
        report["positive_reply_source"] = "Linux kernel; this actor sent exactly the nine disclosed negative frames"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tap", required=True)
    parser.add_argument("--serial", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=90)
    args = parser.parse_args()
    assert os.geteuid() == 0 and 1 <= args.timeout <= 120, "owned VM root and bounded timeout required"
    report = {"schema": "absd-echo-wire-peer/1", "tap": args.tap, "pid": os.getpid(),
              "cases": [], "limits": "Finite malformed inputs, actual ingress acknowledgements and local sequencing only. No wire authentication or physical timing claim."}
    try:
        run(args, report)
        report["disposition"] = "PASS"
    except BaseException as error:
        report["disposition"] = "FAIL"
        report["error"] = repr(error)
        raise
    finally:
        write(args.output, report)


if __name__ == "__main__":
    main()
