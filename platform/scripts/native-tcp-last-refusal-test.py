#!/usr/bin/env python3
"""Finite controls for the explicit two-attempt fixture; native execution is separate."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location("last_refusal_literals", Path(__file__).with_name("native-tcp-server-matrix-test.py"))
old = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)
m = old.m


def capture_fixture(first_retries=0, second_retries=0):
    original = old.baseline()
    first = [old.tcp(False, 8000, 0, 2, port=42031)] * (1 + first_retries)
    second = [old.tcp(False, 9000, 0, 2, port=42031)] * (1 + second_retries)
    rows = original[:2] + first + second + original[3:]
    times = ([1_000_000, 1_000_100]
             + [1_000_200 + i * 100_000 for i in range(len(first))]
             + [2_250_400 + i * 100_000 for i in range(len(second))]
             + [3_500_800 + i * 100 for i in range(len(original) - 3)])
    return rows, times


def capture(first_retries=0, second_retries=0):
    rows, times = capture_fixture(first_retries, second_retries)
    return m.inspect_capture(old.pcap(rows, times), distinct_attempts=2)


def native(count=2, sequence=9000):
    result = old.telemetry_native(count)
    output = result["stdout"].replace(" seq=8000 ", f" seq={sequence} ")
    raw = old.serial()
    original = m.native_output(raw, 3)["stdout"]
    return m.native_output(raw.replace(original.encode().hex().encode(), output.encode().hex().encode()), 3)


def receipts():
    first, peer, readiness, _ = old.peer_fixture()
    second = copy.deepcopy(first)
    second.update(started_monotonic_ns=4_300_000_000, ended_monotonic_ns=5_550_000_000)
    wrong = {"schema": "absd-native-tcp-last-refusal-client/1", "disposition": "PASS", "connect_attempts": 2,
             "attempts": [first, second]}
    peer.update(connect_started_monotonic_ns=5_600_000_000, connected_monotonic_ns=5_700_000_000,
                completed_monotonic_ns=6_300_000_000)
    return wrong, peer, readiness, capture()


class LastRefusalControls(unittest.TestCase):
    def test_01_two_distinct_sequences_and_actual_last_header(self):
        wire = capture()
        self.assertEqual(wire["wrong_port_attempts"], [{"sequence": 8000, "indices": [2]}, {"sequence": 9000, "indices": [3]}])
        self.assertEqual(m.refusal_observation(native(), wire)["last"]["seq"], 9000)
        m.peer_results(*receipts(), distinct_attempts=2)

    def test_02_first_record_substitution_cannot_match_last(self):
        # Count, tuple, flags and frame length remain correct. Only the
        # first actual sequence is substituted for the final second one.
        with self.assertRaisesRegex(AssertionError, "last guest refusal header"):
            m.refusal_observation(native(sequence=8000), capture())

    def test_03_one_sequence_or_missing_attempt_refuses_new_profile(self):
        rows = old.baseline()
        rows.insert(3, old.tcp(False, 8000, 0, 2, port=42031))
        self.assertEqual(m.inspect_capture(old.pcap(rows))["wrong_port_syns"], [2, 3])
        with self.assertRaisesRegex(AssertionError, "missing distinct wrong-port sequence"):
            m.inspect_capture(old.pcap(rows), distinct_attempts=2)
        with self.assertRaises(AssertionError):
            m.inspect_capture(old.pcap(old.baseline()), distinct_attempts=2)

    def test_04_third_sequence_and_first_sequence_resumption_refuse(self):
        for sequence, error in ((10000, "extra connection attempts"), (8000, "earlier wrong-port attempt resumed")):
            rows, times = capture_fixture()
            rows.insert(4, old.tcp(False, sequence, 0, 2, port=42031)); times.insert(4, 2_350_400)
            with self.subTest(sequence=sequence), self.assertRaisesRegex(AssertionError, error):
                m.inspect_capture(old.pcap(rows, times), distinct_attempts=2)

    def test_05_retransmissions_are_counted_and_keep_each_sequence(self):
        for first, second in ((1, 0), (0, 1), (1, 1)):
            wire = capture(first, second); count = 2 + first + second
            self.assertEqual(m.refusal_observation(native(count), wire)["count"], count)
            with self.assertRaisesRegex(AssertionError, "guest refusal count"):
                m.refusal_observation(native(count - 1), wire)

    def test_06_any_guest_response_or_wrong_tuple_still_refuses(self):
        for flags in (18, 16, 20, 17):
            rows, times = capture_fixture()
            rows.insert(4, old.tcp(True, 3000, 9001, flags, port=42031)); times.insert(4, 2_350_400)
            with self.subTest(flags=flags), self.assertRaises(AssertionError):
                m.inspect_capture(old.pcap(rows, times), distinct_attempts=2)
        rows, times = capture_fixture(); rows[3] = old.tcp(False, 9000, 0, 2, port=42032)
        with self.assertRaises(AssertionError): m.inspect_capture(old.pcap(rows, times), distinct_attempts=2)

    def test_07_both_attempts_follow_arp_and_precede_authorized_syn(self):
        rows, times = capture_fixture(); rows[1], rows[2] = rows[2], rows[1]
        with self.assertRaisesRegex(AssertionError, "guest neighbor readiness"):
            m.inspect_capture(old.pcap(rows, times), distinct_attempts=2)
        rows, times = capture_fixture(); rows[3], rows[4] = rows[4], rows[3]
        with self.assertRaisesRegex(AssertionError, "wrong-port SYN after authorized flow"):
            m.inspect_capture(old.pcap(rows, times), distinct_attempts=2)

    def test_08_both_timeout_receipts_and_nonoverlap_are_required(self):
        wrong, peer, ready, wire = receipts()
        for attempt in (0, 1):
            for key, value in (("result", "connection-refused"), ("connect_attempts", 2), ("sent_bytes", 1),
                               ("timeout_ns", 300_000_000), ("local", ["192.0.2.1", 42032]),
                               ("ended_monotonic_ns", wrong["attempts"][attempt]["started_monotonic_ns"] + m.MIN_NEGATIVE_NS)):
                bad = copy.deepcopy(wrong); bad["attempts"][attempt][key] = value
                with self.subTest(attempt=attempt, key=key), self.assertRaises(AssertionError):
                    m.peer_results(bad, peer, ready, wire, distinct_attempts=2)
        bad = copy.deepcopy(wrong)
        bad["attempts"][1].update(started_monotonic_ns=4_000_000_000, ended_monotonic_ns=5_250_000_000)
        with self.assertRaisesRegex(AssertionError, "wrong-port attempt intervals overlap"):
            m.peer_results(bad, peer, ready, wire, distinct_attempts=2)

    def test_09_aggregate_and_positive_order_cannot_hide_missing_attempt(self):
        wrong, peer, ready, wire = receipts()
        for key, value in (("schema", "other"), ("connect_attempts", 1), ("connect_attempts", True),
                           ("attempts", wrong["attempts"][:1]), ("attempts", list(reversed(wrong["attempts"])))):
            bad = copy.deepcopy(wrong); bad[key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                m.peer_results(bad, peer, ready, wire, distinct_attempts=2)
        bad = copy.deepcopy(peer); bad["connect_started_monotonic_ns"] = wrong["attempts"][1]["ended_monotonic_ns"] - 1
        with self.assertRaisesRegex(AssertionError, "client intervals overlap"):
            m.peer_results(wrong, bad, ready, wire, distinct_attempts=2)

    def test_10_actual_helper_closes_each_socket_before_next_connect(self):
        first, second = MagicMock(), MagicMock()
        for sock in (first, second):
            sock.__enter__.return_value = sock
            sock.connect.side_effect = TimeoutError()
        events = []
        first.__exit__.side_effect = lambda *args: events.append("first-closed")
        def second_connect(_address):
            self.assertEqual(events, ["first-closed"])
            raise TimeoutError()
        second.connect.side_effect = second_connect
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "wrong-port.json"
            with patch.object(m.socket, "socket", side_effect=[first, second]), patch.object(m.time, "monotonic_ns",
                    side_effect=[3_000_000_000, 4_250_000_000, 4_300_000_000, 5_550_000_000]):
                m.wrong_port_client(result, distinct_attempts=2)
            saved = json.loads(result.read_text())
            for index, sock in enumerate((first, second)):
                sock.bind.assert_called_once_with(("192.0.2.1", 42031))
                sock.connect.assert_called_once_with(("192.0.2.100", 7005))
                sock.settimeout.assert_called_once_with(1.25)
                self.assertEqual(json.loads((Path(directory) / f"wrong-port-attempt-{index + 1}.json").read_text()), saved["attempts"][index])
            _, peer, ready, wire = receipts()
            m.peer_results(saved, peer, ready, wire, distinct_attempts=2)

    def test_11_second_helper_failure_preserves_first_and_cannot_pass(self):
        for error, end in ((None, 5_550_000_000), (ConnectionRefusedError(), 5_550_000_000),
                           (TimeoutError(), 4_600_000_000)):
            first, second = MagicMock(), MagicMock()
            for sock in (first, second): sock.__enter__.return_value = sock
            first.connect.side_effect, second.connect.side_effect = TimeoutError(), error
            with self.subTest(error=error), tempfile.TemporaryDirectory() as directory:
                result = Path(directory) / "wrong-port.json"
                with patch.object(m.socket, "socket", side_effect=[first, second]), patch.object(m.time, "monotonic_ns",
                        side_effect=[3_000_000_000, 4_250_000_000, 4_300_000_000, end]):
                    with self.assertRaises((AssertionError, ConnectionRefusedError)):
                        m.wrong_port_client(result, distinct_attempts=2)
                self.assertFalse(result.exists())
                self.assertTrue((Path(directory) / "wrong-port-attempt-1.json").exists())
                self.assertFalse((Path(directory) / "wrong-port-attempt-2.json").exists())

    def test_12_new_profile_source_and_embedding_bindings_are_separate(self):
        child = b"\x7fELFchild"; parent = b"\x7fELFparent" + child; kernel = b"\x7fELFkernel" + parent
        revision, tree, archive, size = m.LAST_REFUSAL_PRODUCT
        receipt = {"schema": "absd-native-tcp-server-build/4", "profile": m.LAST_REFUSAL_PROFILE,
                   "platform": {"revision": revision, "tree": tree, "clean": True, "archive": {"sha256": archive, "bytes": size}},
                   "kernel": {"revision": m.KERNEL, "tree": m.KERNEL_TREE, "clean": True, "archive": {"sha256": m.KERNEL_ARCHIVE, "bytes": m.KERNEL_BYTES}},
                   "commands": [["sh", "scripts/build-native-tcp-server.sh"], ["python3", "scripts/served_kernel.py", "external-build", "EXTERNAL_USER_ELF=parent.elf"]],
                   "logs": [m.digest(b"build log")], "toolchain_receipt": m.digest(b"toolchain"),
                   "served_kernel_policy": "frame-admission-v0", "served_wrapper_sha256": m.SERVED_WRAPPER,
                   "outputs": {name: m.digest(value) for name, value in (("child", child), ("parent", parent), ("kernel", kernel))}}
        m.build_binding(receipt, child, parent, kernel, profile=m.LAST_REFUSAL_PROFILE)
        with self.assertRaises(AssertionError): m.build_binding(receipt, child, parent, kernel)
        for key, value in (("revision", m.PRODUCT), ("tree", m.PRODUCT_TREE)):
            bad = copy.deepcopy(receipt); bad["platform"][key] = value
            with self.assertRaises(AssertionError):
                m.build_binding(bad, child, parent, kernel, profile=m.LAST_REFUSAL_PROFILE)
        with self.assertRaises(AssertionError):
            m.build_binding(receipt, child + b"changed", parent, kernel, profile=m.LAST_REFUSAL_PROFILE)


if __name__ == "__main__":
    unittest.main()
