#!/usr/bin/env python3
"""Shared, bounded capture accounting for the explicit IPv6 successor case.

Read QEMU's append-only PCAP and serial output; never write either producer
file. After QEMU ends, bind the observed ready-line boundary to both exact raw
files in a sidecar. An observation is not a synchronized kernel counter reset.
Any ambiguous refused frame or counter mismatch therefore fails the case.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import struct
import time

if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
    raise SystemExit("native-ipv6-accounting: optimized Python is refused")

CASE = "ipv6-post-ready-filter-accounting-v1"
MAX_PCAP = 2 * 1024 * 1024
MAX_SERIAL = 8 * 1024 * 1024
PROFILES = {
    "udp": {"guest": "fd00:ab5d::15", "host": "fd00:ab5d::2", "udp": [7002, 42010], "tcp": None},
    "tcp": {"guest": "fd00:ab5d::15", "host": "fd00:ab5d::2", "udp": [7202, 42020], "tcp": [7203, 42020]},
}
READY = re.compile(rb"(?:^|\n)(NETWORK LINK OK rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048\n)")
RULE = ("Accept destination == station MAC, ff:ff:ff:ff:ff:ff, "
        "33:33:00:00:00:01, or 33:33:ff:*:*:*. Refuse every other destination. "
        "Only incoming frames contribute to expected_refused.")
POLICY = {"reference_kernel_revision": "ed6a15ea7c7c999422e1e294e139b6119619b06c",
          "function": "src/e1000_ring.rs::accept_rx_destination",
          "source_sha256": "205e033d5659afd61d7d3596dd85a7c0348ed859c1675af304b1390965ee2ae8",
          "documentation": "docs/NETWORK.md",
          "documentation_sha256": "90d0f407ca26e1fe5ad814441d0b0105c08852278167b55aa657ead5d3380110",
          "rule": RULE,
          "reason_log": "NIC RX FILTERED dst=<lowercase colon-separated MAC>",
          "reason_log_budget": "Only when the shared rx_refused counter is <=4; not exhaustive."}
LIMITS = ("The marker is the harness's first observation of the complete NIC-ready serial line, "
          "not the instant the device enabled reception. PCAP timestamps are retained but are "
          "not synchronized with serial polling or the boot-cumulative NIC counter snapshot. "
          "No clock conversion or tolerance is used. Pre-marker incoming refused frames can "
          "straddle device readiness; partial capture records at the marker are ambiguous. "
          "Either condition is inconclusive/FAIL even when terminal counts happen to match. "
          "Post-marker frames not processed before the terminal counter snapshot also cause "
          "an exact-count mismatch to fail. Raw files are never annotated in place.")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bounded(path, maximum):
    if not path.exists():
        return b""
    assert path.stat().st_size <= maximum, str(path) + " byte bound"
    data = path.read_bytes()
    assert len(data) <= maximum, str(path) + " byte bound"
    return data


def write_new(path, value):
    with path.open("x") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def capture_records(data, partial=False):
    """PCAP 2.4 Ethernet, exact original frames, at most 256 records."""
    if len(data) < 24 and partial:
        return [], 0
    assert len(data) >= 24, "short PCAP header"
    order = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(data[:4])
    assert order is not None, "unsupported PCAP magic"
    major, minor, _, _, snaplen, link = struct.unpack(order + "HHIIII", data[4:24])
    assert (major, minor, link) == (2, 4, 1) and snaplen >= 1514
    at, records = 24, []
    while at < len(data):
        if partial and at + 16 > len(data):
            break
        assert at + 16 <= len(data), "short PCAP record header"
        seconds, micros, size, original = struct.unpack(order + "IIII", data[at:at + 16])
        assert micros < 1_000_000 and size == original and 14 <= size <= 1514
        if partial and at + 16 + size > len(data):
            break
        assert at + 16 + size <= len(data), "short PCAP frame"
        end = at + 16 + size
        records.append({"index": len(records) + 1, "offset": at, "end_offset": end,
                        "timestamp": [seconds, micros], "frame": data[at + 16:end]})
        assert len(records) <= 256, "frame census bound"
        at = end
    return records, at


def snapshot(data):
    records, complete = capture_records(data, partial=True)
    return {"bytes": len(data), "sha256": digest(data), "complete_bytes": complete,
            "complete_records": len(records),
            "last_timestamp": records[-1]["timestamp"] if records else None,
            "partial_record": len(data) != complete}


class ReadyMarker:
    def __init__(self, serial, capture):
        self.serial, self.capture = Path(serial), Path(capture)
        self.previous_absent = None
        self.observation = None
        self.annotation = None

    def poll(self, running):
        if self.observation is not None:
            return
        start = {"monotonic_ns": time.monotonic_ns(), "realtime_ns": time.time_ns()}
        before = snapshot(bounded(self.capture, MAX_PCAP))
        serial = bounded(self.serial, MAX_SERIAL)
        matches = list(READY.finditer(serial))
        after = snapshot(bounded(self.capture, MAX_PCAP))
        end = {"monotonic_ns": time.monotonic_ns(), "realtime_ns": time.time_ns()}
        sample = {"start": start, "end": end, "capture_before_serial_read": before,
                  "capture_after_serial_read": after, "serial_bytes": len(serial),
                  "serial_sha256": digest(serial), "producer_observed_running": running}
        if not matches:
            self.previous_absent = sample
            return
        assert len(matches) == 1, "duplicate NIC-ready line"
        line = matches[0]
        sample.update(serial_ready_line=line.group(1).decode("ascii"),
                      serial_ready_line_offset=line.start(1), serial_ready_line_end=line.end(1))
        self.observation = sample

    def seal(self, work):
        """Call only after QEMU is terminal. This writes metadata, never PCAP."""
        assert self.annotation is None, "ready annotation already sealed"
        capture = bounded(self.capture, MAX_PCAP)
        serial = bounded(self.serial, MAX_SERIAL)
        annotation = {"schema": "absd-ipv6-ready-capture-sidecar/1", "case": CASE,
                      "marker": "observed complete guest NIC-ready line",
                      "capture": {"path": str(self.capture.resolve()), "bytes": len(capture), "sha256": digest(capture)},
                      "serial": {"path": str(self.serial.resolve()), "bytes": len(serial), "sha256": digest(serial)},
                      "previous_absent": self.previous_absent, "observation": self.observation,
                      "policy": POLICY, "limits": LIMITS}
        if self.observation:
            sample = self.observation
            boundary = sample["capture_after_serial_read"]
            annotation["marker_after_record"] = boundary["complete_records"]
            annotation["marker_capture_offset"] = boundary["complete_bytes"]
            annotation["marker_last_pcap_timestamp"] = boundary["last_timestamp"]
        path = Path(work) / "NIC-READY-CAPTURE.json"
        write_new(path, annotation)
        self.annotation = annotation
        return annotation


def accepted(destination, station):
    return (destination == station or destination == b"\xff" * 6
            or destination == b"\x33\x33\0\0\0\x01"
            or destination[:3] == b"\x33\x33\xff")


def checksum(data):
    # Same pure Internet checksum as the existing net-matrix capture helper.
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def solicited(target):
    return bytes.fromhex("ff0200000000000000000001ff") + target[-3:]


def valid_nd(payload, source, destination, source_mac, destination_mac, local, remote, remote_mac):
    if len(payload) < 24 or payload[1] != 0:
        return False
    if payload[0] == 135:
        if payload[4:8] != b"\0" * 4 or payload[8:24] != remote:
            return False
        if destination not in (remote, solicited(remote)):
            return False
        expected_mac = remote_mac if destination == remote else b"\x33\x33\xff" + remote[-3:]
        option = 1
    else:
        flags = int.from_bytes(payload[4:8], "big")
        if payload[8:24] != local or destination != remote or flags & 0xc0000000 != 0x40000000 or flags & 0x1fffffff:
            return False
        expected_mac, option = remote_mac, 2
    if source != local or destination_mac != expected_mac:
        return False
    # Current direct-neighbor peer proof requires exactly one Ethernet LLA.
    return payload[24:] == bytes([option, 1]) + source_mac


def valid_mld(payload, hbh, source, destination, destination_mac, hop):
    if (len(hbh) != 8 or hbh[:2] != b"\x3a\0" or hop != 1
            or not (ipaddress.IPv6Address(source).is_link_local or source == b"\0" * 16)
            or destination != ipaddress.IPv6Address("ff02::16").packed
            or destination_mac != b"\x33\x33\0\0\0\x16"
            or len(payload) < 8 or payload[:2] != b"\x8f\0" or payload[4:6] != b"\0\0"):
        return False
    at, alerts = 2, 0
    while at < len(hbh):
        kind = hbh[at]
        if kind == 0:  # Pad1
            at += 1
            continue
        if at + 2 > len(hbh) or at + 2 + hbh[at + 1] > len(hbh):
            return False
        size = hbh[at + 1]
        value = hbh[at + 2:at + 2 + size]
        if kind == 5 and value == b"\0\0":
            alerts += 1
        elif kind != 1 or any(value):  # Only zero PadN besides Router Alert.
            return False
        at += 2 + size
    if alerts != 1:
        return False
    at = 8
    for _ in range(int.from_bytes(payload[6:8], "big")):
        if at + 20 > len(payload) or payload[at] not in range(1, 7) or payload[at + 4] != 0xff:
            return False
        at += 20 + 16 * int.from_bytes(payload[at + 2:at + 4], "big") + 4 * payload[at + 1]
        if at > len(payload):
            return False
    return at == len(payload)


def classify(record, guest_mac, host_mac, profile):
    frame = record["frame"]
    result = {key: value for key, value in record.items() if key != "frame"}
    result.update(bytes=len(frame), sha256=digest(frame), source_mac=frame[6:12].hex(":"),
                  destination_mac=frame[:6].hex(":"), kind="unexplained", protocol_peer=False)
    direction = "incoming" if frame[6:12] == host_mac else "outgoing" if frame[6:12] == guest_mac else "unknown"
    result.update(direction=direction, filter_refused=direction == "incoming" and not accepted(frame[:6], guest_mac))
    if direction == "unknown" or len(frame) < 54 or frame[12:14] != b"\x86\xdd" or frame[14] >> 4 != 6:
        return result
    length = int.from_bytes(frame[18:20], "big")
    if len(frame) != max(60, 54 + length):
        return result
    source, destination = frame[22:38], frame[38:54]
    result.update(source_ip=str(ipaddress.IPv6Address(source)), destination_ip=str(ipaddress.IPv6Address(destination)))
    guest, host = (ipaddress.IPv6Address(profile[key]).packed for key in ("guest", "host"))
    local, remote = (host, guest) if direction == "incoming" else (guest, host)
    remote_mac = guest_mac if direction == "incoming" else host_mac
    next_header, payload, hbh = frame[20], frame[54:54 + length], b""
    if next_header == 0:
        if len(payload) < 8 or (payload[1] + 1) * 8 > len(payload):
            return result
        size = (payload[1] + 1) * 8
        next_header, hbh, payload = payload[0], payload[:size], payload[size:]
    pseudo = source + destination + struct.pack("!I3xB", len(payload), next_header)
    if next_header == 58 and payload:
        if payload[0] in (135, 136) and not hbh:
            result["protocol_peer"] = source == local
            if (frame[21] == 255 and checksum(pseudo + payload) == 0
                    and valid_nd(payload, source, destination, frame[6:12], frame[:6], local, remote, remote_mac)):
                result.update(kind="peer-nd", icmpv6_type=payload[0])
        elif (direction == "incoming" and checksum(pseudo + payload) == 0
              and valid_mld(payload, hbh, source, destination, frame[:6], frame[21])):
            result.update(kind="linux-mldv2", icmpv6_type=143)
    elif next_header in (17, 6) and not hbh and source == local and destination == remote:
        ports = profile["udp" if next_header == 17 else "tcp"]
        if ports is None or len(payload) < (8 if next_header == 17 else 20):
            return result
        expected_ports = list(reversed(ports)) if direction == "incoming" else ports
        observed_ports = list(struct.unpack("!HH", payload[:4]))
        if observed_ports != expected_ports:
            return result
        result.update(protocol_peer=True, ports=observed_ports)
        if frame[:6] != remote_mac or checksum(pseudo + payload) != 0:
            return result
        if next_header == 17:
            if (len(payload) < 20 or int.from_bytes(payload[4:6], "big") != len(payload)
                    or payload[6:8] == b"\0\0" or 40 + length > 1280):
                return result
            result["kind"] = "peer-udp-dns"
        elif 20 <= (payload[12] >> 4) * 4 <= len(payload) and 40 + length <= 1500 and not payload[12] & 0x0e:
            at, end = 20, (payload[12] >> 4) * 4
            while at < end:
                kind = payload[at]
                if kind == 0:
                    if any(payload[at:end]):
                        return result
                    break
                if kind == 1:
                    at += 1
                    continue
                if at + 2 > end or payload[at + 1] < 2 or at + payload[at + 1] > end:
                    return result
                at += payload[at + 1]
            result["kind"] = "peer-tcp"
    return result


def evaluate(work, marker, fields, guest_mac, host_mac, profile):
    """Return PASS only for exact accounting; write all classifications on FAIL."""
    work = Path(work)
    annotation = marker.annotation
    assert annotation is not None, "capture annotation must be sealed after producer termination"
    capture = bounded(marker.capture, MAX_PCAP)
    serial = bounded(marker.serial, MAX_SERIAL)
    records, _ = capture_records(capture)
    assert profile in PROFILES, "unknown explicit peer profile"
    classes = [classify(r, bytes.fromhex(guest_mac.replace(":", "")),
                        bytes.fromhex(host_mac.replace(":", "")), PROFILES[profile]) for r in records]
    failures, ambiguities = [], []
    observation = annotation["observation"]
    boundary = annotation.get("marker_after_record", len(records))
    if observation is None:
        ambiguities.append("NIC-ready line was not observed")
    else:
        if not observation["producer_observed_running"]:
            ambiguities.append("NIC-ready line first observed after producer termination")
        if marker.previous_absent is None:
            ambiguities.append("no preceding observation without the ready line")
        snapshots = [observation["capture_before_serial_read"], observation["capture_after_serial_read"]]
        if any(s["bytes"] < 24 for s in snapshots):
            ambiguities.append("capture header unavailable at readiness observation")
        if any(s["partial_record"] for s in snapshots):
            ambiguities.append("partial capture record straddles readiness observation")
        for sample in (marker.previous_absent, observation):
            if sample is None:
                continue
            if digest(serial[:sample["serial_bytes"]]) != sample["serial_sha256"]:
                failures.append("serial observation is not a prefix of terminal raw serial")
            for key in ("capture_before_serial_read", "capture_after_serial_read"):
                s = sample[key]
                if digest(capture[:s["bytes"]]) != s["sha256"]:
                    failures.append("capture observation is not a prefix of terminal raw capture")
    before = [r for r in classes if r["index"] <= boundary]
    after = [r for r in classes if r["index"] > boundary]
    for row in classes:
        row["post_marker"] = row["index"] > boundary
    uncertain = [r["index"] for r in before if r["filter_refused"]]
    if uncertain:
        ambiguities.append("pre-marker incoming refusal may contribute to boot-cumulative counters")
    expected = sum(r["filter_refused"] for r in after)
    peer_refused = [r["index"] for r in after if r["filter_refused"] and r["protocol_peer"]]
    unexplained = [r["index"] for r in after if r["kind"] == "unexplained"]
    actual = {key: int(fields[key]) for key in ("rx_refused", "rx_missed", "tx_refused", "tx_errors")}
    if any(value < 0 for value in actual.values()):
        failures.append("negative NIC counter")
    if digest(capture) != annotation["capture"]["sha256"] or digest(serial) != annotation["serial"]["sha256"]:
        failures.append("raw files changed after readiness sidecar was sealed")
    reason_lines = [{"serial_offset": m.start(), "line": m.group().decode("ascii", errors="replace")}
                    for m in re.finditer(rb"(?m)^NIC RX (?:FILTERED|REFUSED)[^\n]*", serial)]
    if any(line["line"].startswith("NIC RX REFUSED") for line in reason_lines):
        failures.append("device descriptor refusal is not a MAC-filter refusal")
    if actual["rx_refused"] != expected:
        failures.append("rx_refused does not equal expected_refused")
    if peer_refused:
        failures.append("protocol peer frame refused")
    if unexplained:
        failures.append("unexplained post-marker frame")
    if any(actual[key] for key in ("rx_missed", "tx_refused", "tx_errors")):
        failures.append("nonzero missed/transmit-refusal/transmit-error counter")
    result = {"schema": "absd-ipv6-filter-accounting/1", "case": CASE,
              "disposition": "FAIL" if failures or ambiguities else "PASS",
              "inconclusive": bool(ambiguities), "failures": failures, "ambiguities": ambiguities,
              "policy": POLICY, "profile": PROFILES[profile], "profile_name": profile,
              "expected_refused": expected, "actual": actual,
              "post_marker_frames": len(after), "protocol_peer_refused": peer_refused,
              "unexplained": unexplained, "pre_marker_refusal_indices": uncertain,
              "classification": classes, "marker_after_record": boundary,
              "kernel_refusal_observations": reason_lines,
              "capture_sha256": digest(capture), "serial_sha256": digest(serial),
              "annotation_sha256": digest((work / "NIC-READY-CAPTURE.json").read_bytes()), "limits": LIMITS}
    write_new(work / "NIC-ACCOUNTING.json", result)
    assert result["disposition"] == "PASS", ("IPv6 accounting FAIL", failures, ambiguities)
    return result
