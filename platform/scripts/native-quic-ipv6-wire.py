#!/usr/bin/env python3
"""Full capture census for the private on-link IPv6 QUIC consumer.

Reuse the pinned IPv6/ND/MLD classifier without changing its policy or global
profiles. Its historical UDP class name does not validate a DNS message; the
additional checks here bind exact QUIC fixture tuples and datagram limits.
This classifies captured bytes, not crypto, native delivery or NIC counters.
"""
import hashlib
import importlib.util
import ipaddress
import os
from pathlib import Path
import re

ACCOUNTING_SHA256 = "22d5f091c23c0d436be538d3695b43b3ed52b48ec5b4b30668be215a08001ad3"
GUEST = "fd00:ab5d::15"
PEER = "fd00:ab5d::2"
CASES = {"Q01": ("echo", 7800), "Q08": ("wrong-root", 7807),
         "Q17": ("denied-destination", 7816)}


class Refusal(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def accounting():
    require(__debug__ and not os.environ.get("PYTHONOPTIMIZE"), "optimized Python refused")
    path = Path(__file__).with_name("native-ipv6-accounting.py")
    require(not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest() == ACCOUNTING_SHA256,
            "existing IPv6 accounting source changed")
    spec = importlib.util.spec_from_file_location("quic6_fixed_accounting", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mac(text):
    require(isinstance(text, str) and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", text),
            "canonical explicit MAC required")
    value = bytes.fromhex(text.replace(":", ""))
    require(value != bytes(6) and not value[0] & 1, "nonzero unicast MAC required")
    return value


def observe(raw, case, guest_mac, peer_mac):
    require(case.get("id") in CASES and
            (case.get("peer_mode"), case.get("local_port")) == CASES[case["id"]],
            "explicit IPv6 Q01/Q08/Q17 case, mode and port required")
    gm, pm = mac(guest_mac), mac(peer_mac)
    require(gm != pm, "distinct endpoint MACs required")
    require(24 <= len(raw) <= 2 * 1024**2, "bounded complete PCAP required")
    original = accounting()
    try:
        records, complete = original.capture_records(raw)
        require(complete == len(raw), "trailing partial capture")
        profile = {"guest": GUEST, "host": PEER,
                   "udp": [case["local_port"], 4443], "tcp": None}
        census = [original.classify(row, gm, pm, profile) for row in records]
    except (AssertionError, ValueError, IndexError) as error:
        raise Refusal("invalid full IPv6 capture: " + str(error)) from error
    require(all(row["kind"] in ("linux-mldv2", "peer-nd", "peer-udp-dns") for row in census),
            "unexplained frame in complete capture")
    datagrams, nd, mld = [], [], []
    for record, row in zip(records, census):
        frame = record["frame"]
        if row["kind"] == "linux-mldv2":
            mld.append(row)
            continue
        if row["kind"] == "peer-nd":
            nd.append(row)
            continue
        segment = frame[54:54 + int.from_bytes(frame[18:20], "big")]
        payload = segment[8:]
        outgoing = row["direction"] == "outgoing"
        # Fixed direct-link proof: both kernels use hop limit64. IPv6 ECN is
        # the low two bits of the traffic class, not the flow-label bits.
        ecn = (frame[15] >> 4) & 3
        require(frame[20] == 17 and frame[21] == 64 and 0 < len(payload) <= 1200,
                "fixed UDP MTU/hop profile differs")
        require(not outgoing or ecn == 0, "native packet claims ECN")
        source = [str(ipaddress.IPv6Address(frame[22:38])), int.from_bytes(segment[:2], "big")]
        destination = [str(ipaddress.IPv6Address(frame[38:54])), int.from_bytes(segment[2:4], "big")]
        datagrams.append({**row, "ordinal": row["index"], "source": source,
                          "destination": destination, "bytes": len(payload),
                          "frame_sha256": row["sha256"],
                          "sha256": hashlib.sha256(payload).hexdigest(), "first_byte": payload[0],
                          "long_header_version": (int.from_bytes(payload[1:5], "big")
                                                  if payload[0] & 0x80 and len(payload) >= 5 else None),
                          "ecn": ecn, "udp_checksum_valid": True})
    sent = [row for row in datagrams if row["direction"] == "outgoing"]
    received = [row for row in datagrams if row["direction"] == "incoming"]
    require(len(sent) <= 256 and len(received) <= 256 and
            sum(row["bytes"] for row in sent) <= 307200 and
            sum(row["bytes"] for row in received) <= 376832,
            "native packet/byte bounds exceeded")
    if case["id"] == "Q17":
        require(not datagrams and not nd, "denied SEND caused UDP or neighbor traffic")
    else:
        require(sent and received, "both exact-peer datagram directions required")
        require(sent[0]["bytes"] == 1200 and sent[0]["first_byte"] & 0xf0 == 0xc0 and
                sent[0]["long_header_version"] == 1,
                "first guest datagram must be a header-shaped QUICv1 Initial")
        require(any(a["direction"] == "outgoing" and a["icmpv6_type"] == 135 and
                    any(b["direction"] == "incoming" and b["icmpv6_type"] == 136 and
                        a["index"] < b["index"] < sent[0]["index"] for b in nd) for a in nd),
                "guest NS and Linux NA before first Initial required")
    return {"pcap_sha256": hashlib.sha256(raw).hexdigest(), "family": 6,
            "scope": 1, "guest": GUEST, "peer": PEER, "frames": census,
            "frame_count": len(census), "nd": nd, "linux_mldv2": mld,
            "guest_udp": sent, "peer_udp": received, "guest_udp_count": len(sent),
            "peer_udp_count": len(received), "guest_udp_bytes": sum(row["bytes"] for row in sent),
            "unexpected_frames": 0, "unauthorized_guest_udp_count": 0,
            "icmp_errors": [], "all_guest_non_ect": True,
            "accounting_source_sha256": ACCOUNTING_SHA256,
            "limit": "Every complete captured frame is pinned exact-pair ND, valid Linux MLDv2, or exact-tuple checksum-valid IPv6/UDP. Linux MLD frames remain in the census, including driver-refused destinations. No crypto, native delivery, readiness synchronization, NIC counter, physical timing or hardware transfer claim."}
