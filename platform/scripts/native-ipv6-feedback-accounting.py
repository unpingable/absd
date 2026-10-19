#!/usr/bin/env python3
"""Exact closed-port ICMPv6 census adapter to the unchanged first-four policy.

The accepted helper source and sidecar-equality check remain unchanged.
Only this module's private imported classifier gains the explicit new profile.
"""
import importlib.util
from pathlib import Path
import struct

spec = importlib.util.spec_from_file_location("feedback_reasons", Path(__file__).with_name("native-ipv6-reason-accounting.py"))
reasons = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reasons)
original = reasons.original
PROFILE = {"guest": "fd00:ab5d::15", "host": "fd00:ab5d::2", "udp": [7002,42019], "tcp": None}
assert "feedback" not in original.PROFILES
original.PROFILES["feedback"] = PROFILE
base_classify = original.classify


def classify(record, guest_mac, host_mac, profile):
    row = base_classify(record, guest_mac, host_mac, profile)
    if profile != PROFILE or row["kind"] != "unexplained":
        return row
    frame = record["frame"]
    guest, host = (original.ipaddress.IPv6Address(profile[k]).packed for k in ("guest","host"))
    if (len(frame) < 110 or frame[:6] != guest_mac or frame[6:12] != host_mac
            or frame[12:14] != b"\x86\xdd" or frame[14] >> 4 != 6
            or frame[20] != 58 or frame[21] == 0
            or frame[22:38] != host or frame[38:54] != guest):
        return row
    row["protocol_peer"] = True
    length = int.from_bytes(frame[18:20], "big")
    if len(frame) != 54 + length or 40 + length > 1280:
        return row
    payload = frame[54:]
    if (payload[:2] != b"\x01\x04" or payload[4:8] != bytes(4)
            or original.checksum(host + guest + struct.pack("!I3xB",len(payload),58) + payload) != 0):
        return row
    quote = payload[8:]
    if (quote[0] >> 4 != 6 or quote[6] != 17 or quote[7] == 0
            or quote[8:24] != guest or quote[24:40] != host
            or len(quote) != 40 + int.from_bytes(quote[4:6],"big") or len(quote) > 1232):
        return row
    udp = quote[40:]
    if (udp[:4] != struct.pack("!HH",7002,42019) or int.from_bytes(udp[4:6],"big") != len(udp)
            or udp[6:8] == bytes(2) or original.checksum(guest+host+struct.pack("!I3xB",len(udp),17)+udp) != 0):
        return row
    row.update(kind="peer-icmpv6-port-unreachable",icmpv6_type=1,icmpv6_code=4)
    return row


# This affects only this freshly imported helper instance, not its source or
# the udp/tcp profiles. The unchanged reason evaluator remains the verdict.
original.classify = classify
ReadyMarker = original.ReadyMarker


def evaluate(work, marker, fields, guest_mac, host_mac):
    return reasons.evaluate(work, marker, fields, guest_mac, host_mac, "feedback")
