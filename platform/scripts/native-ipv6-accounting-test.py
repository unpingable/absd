#!/usr/bin/env python3
"""Pure capture-fixture controls; run separately from the native peer proof."""
import importlib.util
import ipaddress
import json
from pathlib import Path
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("accounting", Path(__file__).with_name("native-ipv6-accounting.py"))
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
GUEST = bytes.fromhex("525400ab5d15")
HOST = bytes.fromhex("525500000202")
HEADER = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65536, 1)
READY = b"NETWORK LINK OK rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048\n"


def packet(kind="mld", refused=False, profile="udp", source=None, source_port=None, bad_checksum=False, truncated=False):
    config = a.PROFILES[profile]
    local_port, remote_port = config["tcp" if kind == "tcp" else "udp"]
    source = source or ("fe80::5055:ff:fe00:202" if kind == "mld" else config["host"])
    destination, protocol, hop, mac, hbh = config["guest"], 17, 64, GUEST, b""
    payload = struct.pack("!HHHH", source_port or remote_port, local_port, 20, 0) + b"\0" * 12
    checksum_offset = 6
    if kind == "mld":
        payload, protocol, hop, destination = b"\x8f\0" + b"\0" * 6, 58, 1, "ff02::16"
        hbh = b"\x3a\0\x05\x02\0\0\x01\0"
        mac, checksum_offset = bytes.fromhex("333300000016"), 2
    elif kind == "nd":
        payload, protocol, hop = b"\x87\0" + b"\0" * 6 + ipaddress.IPv6Address(config["guest"]).packed + b"\x01\x01" + HOST, 58, 255
        checksum_offset = 2
    elif kind == "tcp":
        payload = struct.pack("!HHIIBBHHH", source_port or remote_port, local_port, 0, 0, 5 << 4, 16, 1024, 0, 0)
        protocol, checksum_offset = 6, 16
    elif kind == "unknown":
        protocol = 253
    if refused:
        mac = bytes.fromhex("333300000002")
    if truncated:
        payload = payload[:-1]
    src, dst = ipaddress.IPv6Address(source).packed, ipaddress.IPv6Address(destination).packed
    check = a.checksum(src + dst + struct.pack("!I3xB", len(payload), protocol) + payload)
    if bad_checksum:
        check ^= 1
    payload = payload[:checksum_offset] + (check or 0xffff).to_bytes(2, "big") + payload[checksum_offset + 2:]
    ip = bytes([0x60, 0, 0, 0]) + struct.pack("!HBB", len(hbh) + len(payload), 0 if hbh else protocol, hop)
    return mac + HOST + b"\x86\xdd" + ip + src + dst + hbh + payload


def record(frame):
    return struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame


class Accounting(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="absd-ipv6-accounting-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.serial, self.capture = self.work / "serial", self.work / "raw.pcap"
        self.marker = a.ReadyMarker(self.serial, self.capture)
        self.marker.poll(running=False)
        self.capture.write_bytes(HEADER)
        self.serial.write_bytes(b"boot\n")
        self.marker.poll(running=True)

    def ready(self):
        self.serial.write_bytes(self.serial.read_bytes() + READY)
        self.marker.poll(running=True)

    def append(self, frame):
        with self.capture.open("ab") as output:
            output.write(record(frame))

    def evaluate(self, refused=0, profile="udp", **extra):
        self.marker.seal(self.work)
        fields = dict(rx_refused=refused, rx_missed=0, tx_refused=0, tx_errors=0)
        fields.update(extra)
        return a.evaluate(self.work, self.marker, fields, GUEST.hex(), HOST.hex(), profile=profile)

    def failed(self, **fields):
        with self.assertRaises(AssertionError):
            self.evaluate(**fields)
        result = json.loads((self.work / "NIC-ACCOUNTING.json").read_text())
        self.assertEqual(result["disposition"], "FAIL")
        return result

    def test_literal_policy_and_near_misses(self):
        for mac in (GUEST, b"\xff" * 6, bytes.fromhex("333300000001"), bytes.fromhex("3333ff123456")):
            self.assertTrue(a.accepted(mac, GUEST))
        for mac in (HOST, bytes.fromhex("333300000016"), bytes.fromhex("333300000002"), bytes.fromhex("3333fe123456")):
            self.assertFalse(a.accepted(mac, GUEST))

    def test_exact_mld_count_and_protocol_classification(self):
        self.ready()
        for kind in ("mld", "nd", "udp"):
            self.append(packet(kind))
        result = self.evaluate(refused=1)
        self.assertEqual(result["expected_refused"], 1)
        self.assertEqual(result["post_marker_frames"], 3)
        self.assertEqual(result["unexplained"], [])
        self.assertEqual(result["protocol_peer_refused"], [])

    def test_mismatch_is_fail(self):
        self.ready()
        self.append(packet())
        self.assertIn("rx_refused does not equal expected_refused", self.failed()["failures"])

    def test_pre_marker_refusal_is_inconclusive_even_when_counts_match(self):
        self.append(packet())
        self.ready()
        result = self.failed()
        self.assertTrue(result["inconclusive"])
        self.assertEqual(result["actual"]["rx_refused"], result["expected_refused"])

    def test_partial_record_at_marker_is_inconclusive(self):
        encoded = record(packet())
        with self.capture.open("ab") as output:
            output.write(encoded[:10])
        self.ready()
        with self.capture.open("ab") as output:
            output.write(encoded[10:])
        self.assertTrue(self.failed(refused=1)["inconclusive"])

    def test_peer_refusal_is_fail_even_when_counts_match(self):
        self.ready()
        self.append(packet("nd", refused=True))
        self.assertIn("protocol peer frame refused", self.failed(refused=1)["failures"])

    def test_transmit_error_is_fail(self):
        self.ready()
        self.assertIn("nonzero missed/transmit-refusal/transmit-error counter", self.failed(tx_errors=1)["failures"])

    def test_unexplained_frame_is_fail(self):
        self.ready()
        self.append(packet("unknown"))
        self.assertIn("unexplained post-marker frame", self.failed()["failures"])

    def test_prefix_mutation_is_fail(self):
        self.ready()
        self.serial.write_bytes(b"changed\n" + READY)
        self.assertIn("serial observation is not a prefix of terminal raw serial", self.failed()["failures"])

    def test_explicit_tcp_profile(self):
        frame = packet("tcp", profile="tcp")
        self.assertEqual(a.classify({"frame": frame}, GUEST, HOST, a.PROFILES["tcp"])["kind"], "peer-tcp")
        self.assertEqual(a.classify({"frame": frame}, GUEST, HOST, a.PROFILES["udp"])["kind"], "unexplained")

    def test_substituted_tuple_address_and_transport_remain_unexplained(self):
        variants = [("udp", "udp", {"source_port": 42011}),
                    ("udp", "udp", {"source": "fd00:ab5d::3"}),
                    ("tcp", "tcp", {"source_port": 42021}),
                    ("tcp", "tcp", {"source": "fd00:ab5d::3"}),
                    ("udp", "udp", {"truncated": True}),
                    ("tcp", "tcp", {"truncated": True}),
                    ("nd", "udp", {"bad_checksum": True}),
                    ("nd", "udp", {"source": "fd00:ab5d::3"})]
        for kind, profile, mutation in variants:
            with self.subTest(kind=kind, profile=profile, mutation=mutation):
                value = a.classify({"frame": packet(kind, profile=profile, **mutation)}, GUEST, HOST, a.PROFILES[profile])
                self.assertEqual(value["kind"], "unexplained")

    def test_bad_mld_checksum_is_unexplained_even_with_matching_count(self):
        self.ready()
        self.append(packet(bad_checksum=True))
        self.assertIn("unexplained post-marker frame", self.failed(refused=1)["failures"])

    def test_reason_log_does_not_excuse_mismatch(self):
        self.ready()
        self.serial.write_bytes(self.serial.read_bytes() + b"NIC RX FILTERED dst=33:33:00:00:00:16\n")
        result = self.failed(refused=1)
        self.assertEqual(len(result["kernel_refusal_observations"]), 1)
        self.assertIn("rx_refused does not equal expected_refused", result["failures"])


if __name__ == "__main__":
    unittest.main()
