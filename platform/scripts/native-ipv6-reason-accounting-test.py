#!/usr/bin/env python3
"""Separate artifact fixtures for the admitted bounded driver-reason case."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


def sibling(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


a = sibling("reasons", "native-ipv6-reason-accounting.py")
f = sibling("old_capture_fixtures", "native-ipv6-accounting-test.py")
REASON = b"NIC RX FILTERED dst=33:33:00:00:00:16\n"


class Correspondence(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="absd-ipv6-reason-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.serial, self.capture = self.work / "serial", self.work / "raw.pcap"
        self.serial.write_bytes(b"boot\n")
        self.capture.write_bytes(f.HEADER)
        self.marker = a.ReadyMarker(self.serial, self.capture)
        self.marker.poll(running=True)

    def append(self, frame):
        with self.capture.open("ab") as output:
            output.write(f.record(frame))

    def ready(self):
        self.serial.write_bytes(self.serial.read_bytes() + f.READY)
        self.marker.poll(running=True)

    def reason(self, text=REASON):
        self.serial.write_bytes(self.serial.read_bytes() + text)

    def evaluate(self, refused=0, profile="udp", **fields):
        if self.marker.annotation is None:
            self.marker.seal(self.work)
        counters = dict(rx_refused=refused, rx_missed=0, tx_refused=0, tx_errors=0)
        counters.update(fields)
        return a.evaluate(self.work, self.marker, counters, f.GUEST.hex(), f.HOST.hex(), profile)

    def failed(self, **fields):
        with self.assertRaises(AssertionError):
            self.evaluate(**fields)
        result = json.loads((self.work / "NIC-REASON-ACCOUNTING.json").read_text())
        self.assertEqual(result["disposition"], "FAIL")
        return result

    def test_prefix_and_repeated_capture_destinations_remain_explicit_uncertainty(self):
        self.append(f.packet())
        self.append(f.packet())
        self.ready()
        self.append(f.packet("udp"))
        self.reason()
        result = self.evaluate(refused=1)
        self.assertEqual(result["driver_reasons"][0]["compatible_capture_indices"], [1, 2])
        self.assertIn("Capture-prefix uncertainty", result["limits"])

    def test_exact_four_reason_budget(self):
        self.ready()
        for _ in range(4):
            self.append(f.packet())
            self.reason()
        self.assertFalse(self.evaluate(refused=4)["inconclusive"])

    def test_five_is_inconclusive_even_with_complete_fixture_reasons(self):
        self.ready()
        for _ in range(5):
            self.append(f.packet())
            self.reason()
        self.assertTrue(self.failed(refused=5)["inconclusive"])

    def test_zero_refusals_and_zero_reasons(self):
        self.ready()
        self.append(f.packet("nd"))
        self.assertEqual(self.evaluate()["driver_reasons"], [])

    def test_missing_reason_fails(self):
        self.ready()
        self.append(f.packet())
        self.assertIn("driver reason cardinality differs from rx_refused", self.failed(refused=1)["failures"])

    def test_extra_reason_fails(self):
        self.ready()
        self.append(f.packet())
        self.reason()
        self.failed()

    def test_reused_capture_frame_cannot_supply_two_reasons(self):
        self.ready()
        self.append(f.packet())
        self.reason()
        self.reason()
        self.assertIn("insufficient captured refused-destination frames for driver reasons", self.failed(refused=2)["failures"])

    def test_descriptor_reason_fails(self):
        self.ready()
        self.reason(b"NIC RX REFUSED status=0 errors=1 length=60\n")
        self.assertIn("descriptor or malformed driver refusal reason", self.failed(refused=1)["failures"])

    def test_malformed_reason_fails(self):
        self.ready()
        self.append(f.packet())
        self.reason(REASON.rstrip() + b" extra\n")
        self.failed(refused=1)

    def test_accepted_destination_reason_fails(self):
        self.ready()
        self.reason(b"NIC RX FILTERED dst=52:54:00:ab:5d:15\n")
        self.assertIn("driver reason names an accepted destination", self.failed(refused=1)["failures"])

    def test_absent_destination_fails(self):
        self.ready()
        self.reason()
        self.failed(refused=1)

    def test_unexplained_prefix_fails(self):
        self.append(f.packet("unknown"))
        self.ready()
        self.assertIn("unexplained frame anywhere in capture", self.failed()["failures"])

    def test_protocol_peer_refusal_fails(self):
        self.ready()
        self.append(f.packet("nd", refused=True))
        self.reason(b"NIC RX FILTERED dst=33:33:00:00:00:02\n")
        self.assertIn("protocol peer frame refused", self.failed(refused=1)["failures"])

    def test_transmit_or_missed_counter_fails(self):
        self.ready()
        self.failed(rx_missed=1, tx_refused=1, tx_errors=1)

    def test_negative_counter_fails(self):
        self.ready()
        self.assertIn("negative NIC counter", self.failed(refused=-1)["failures"])

    def test_sealed_raw_mutation_fails(self):
        self.ready()
        self.marker.seal(self.work)
        self.reason()
        self.assertIn("serial changed after sidecar seal", self.failed()["failures"])

    def test_observed_prefix_mutation_fails(self):
        self.ready()
        self.serial.write_bytes(b"other\n" + f.READY)
        self.assertIn("serial observation is not a prefix of terminal raw serial", self.failed()["failures"])

    def test_serialized_sidecar_mutation_cannot_name_unevaluated_annotation(self):
        self.ready()
        self.marker.seal(self.work)
        path = self.work / "NIC-READY-CAPTURE.json"
        changed = json.loads(path.read_text())
        changed["marker"] = "substituted sidecar observation"
        path.write_text(json.dumps(changed))
        result = self.failed()
        self.assertIn("serialized sidecar differs from evaluated annotation", result["failures"])
        self.assertEqual(result["annotation_sha256"], a.original.digest(path.read_bytes()))

    def test_tcp_profile_is_explicit(self):
        self.ready()
        self.append(f.packet("tcp", profile="tcp"))
        self.assertEqual(self.evaluate(profile="tcp")["profile_name"], "tcp")

    def test_wrong_profile_cannot_explain_tcp(self):
        self.ready()
        self.append(f.packet("tcp", profile="tcp"))
        self.failed(profile="udp")


if __name__ == "__main__":
    unittest.main()
