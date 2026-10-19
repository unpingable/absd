#!/usr/bin/env python3
"""Bounded driver-reason correspondence, distinct from post-ready accounting.

The old readiness helper and its failed case are unchanged. A captured frame
is a possible source for a logged destination, not a synchronized DMA event.
"""
from collections import Counter
import importlib.util
import json
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location("ipv6_original_accounting", Path(__file__).with_name("native-ipv6-accounting.py"))
original = importlib.util.module_from_spec(spec)
spec.loader.exec_module(original)
ReadyMarker = original.ReadyMarker
CASE = "ipv6-bounded-driver-reason-correspondence-v1"
LIMITS = ("Capture-prefix uncertainty remains: capture starts before device reception, and neither "
          "the ready observation nor terminal counters synchronize capture with device processing. "
          "Repeated frames of one destination cannot be assigned uniquely to individual refusals. "
          "Correspondence establishes exhaustive bounded driver reasons and compatible captured "
          "destinations only, not exact frame delivery, physical timing, DMA exclusion or rollback. "
          "All captured frames, including the prefix, must be explained. Historical failures remain failures.")


def evaluate(work, marker, fields, guest_mac, host_mac, profile):
    work = Path(work)
    annotation = marker.annotation
    assert annotation is not None, "seal raw-file sidecar after producer termination"
    capture = original.bounded(marker.capture, original.MAX_PCAP)
    serial = original.bounded(marker.serial, original.MAX_SERIAL)
    assert profile in original.PROFILES, "unknown explicit peer profile"
    station = bytes.fromhex(guest_mac.replace(":", ""))
    records, _ = original.capture_records(capture)
    classes = [original.classify(r, station, bytes.fromhex(host_mac.replace(":", "")),
                                original.PROFILES[profile]) for r in records]
    failures, ambiguities = [], []
    sidecar = original.bounded(work / "NIC-READY-CAPTURE.json", 65536)
    try:
        if json.loads(sidecar) != annotation:
            failures.append("serialized sidecar differs from evaluated annotation")
    except (ValueError, UnicodeDecodeError):
        failures.append("serialized sidecar is not valid annotation JSON")
    actual = {key: int(fields[key]) for key in ("rx_refused", "rx_missed", "tx_refused", "tx_errors")}
    if any(value < 0 for value in actual.values()):
        failures.append("negative NIC counter")
    if actual["rx_refused"] > 4:
        ambiguities.append("rx_refused exceeds the exhaustive first-four diagnostic budget")
    for raw, key in ((capture, "capture"), (serial, "serial")):
        if original.digest(raw) != annotation[key]["sha256"] or len(raw) != annotation[key]["bytes"]:
            failures.append(key + " changed after sidecar seal")
    for sample in (annotation["previous_absent"], annotation["observation"]):
        if sample is None:
            continue
        if original.digest(serial[:sample["serial_bytes"]]) != sample["serial_sha256"]:
            failures.append("serial observation is not a prefix of terminal raw serial")
        for key in ("capture_before_serial_read", "capture_after_serial_read"):
            snap = sample[key]
            if original.digest(capture[:snap["bytes"]]) != snap["sha256"]:
                failures.append("capture observation is not a prefix of terminal raw capture")
    if len(list(original.READY.finditer(serial))) != 1:
        failures.append("exactly one terminal NIC-ready line required")
    lines = list(re.finditer(rb"(?m)^NIC RX (?:FILTERED|REFUSED)[^\n]*", serial))
    reasons = []
    for line in lines:
        match = re.fullmatch(rb"NIC RX FILTERED dst=([0-9a-f]{2}(?::[0-9a-f]{2}){5})", line.group())
        if match is None or line.end() == len(serial):
            failures.append("descriptor or malformed driver refusal reason")
            continue
        destination = match.group(1).decode("ascii")
        if original.accepted(bytes.fromhex(destination.replace(":", "")), station):
            failures.append("driver reason names an accepted destination")
        candidates = [r["index"] for r in classes if r["filter_refused"] and r["destination_mac"] == destination]
        reasons.append({"serial_offset": line.start(), "destination": destination,
                        "compatible_capture_indices": candidates})
    if len(lines) != actual["rx_refused"] or len(reasons) != actual["rx_refused"]:
        failures.append("driver reason cardinality differs from rx_refused")
    available = Counter(r["destination_mac"] for r in classes if r["filter_refused"])
    for destination, count in Counter(r["destination"] for r in reasons).items():
        if available[destination] < count:
            failures.append("insufficient captured refused-destination frames for driver reasons")
    peer_refused = [r["index"] for r in classes if r["filter_refused"] and r["protocol_peer"]]
    unexplained = [r["index"] for r in classes if r["kind"] == "unexplained"]
    if peer_refused:
        failures.append("protocol peer frame refused")
    if unexplained:
        failures.append("unexplained frame anywhere in capture")
    if any(actual[key] for key in ("rx_missed", "tx_refused", "tx_errors")):
        failures.append("nonzero missed/transmit-refusal/transmit-error counter")
    result = {"schema": "absd-ipv6-driver-reason-correspondence/1", "case": CASE,
              "disposition": "FAIL" if failures or ambiguities else "PASS", "inconclusive": bool(ambiguities),
              "failures": failures, "ambiguities": ambiguities, "actual": actual,
              "policy": original.POLICY, "policy_budget_scope": "Exhaustive only when terminal rx_refused <= 4",
              "profile_name": profile, "profile": original.PROFILES[profile],
              "driver_reasons": reasons, "protocol_peer_refused": peer_refused, "unexplained": unexplained,
              "captured_refused_destinations": dict(available), "classification": classes,
              "marker_after_record_observation_only": annotation.get("marker_after_record"),
              "capture_sha256": original.digest(capture), "serial_sha256": original.digest(serial),
              "annotation_sha256": original.digest(sidecar),
              "limits": LIMITS}
    original.write_new(work / "NIC-REASON-ACCOUNTING.json", result)
    assert result["disposition"] == "PASS", ("IPv6 reason accounting FAIL", failures, ambiguities)
    return result
