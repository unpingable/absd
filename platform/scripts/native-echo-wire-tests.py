#!/usr/bin/env python3
"""Finite independent acceptance controls for the additive wire proof oracle."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("echo_wire_matrix_controls", HERE / "native-echo-wire-matrix.py")
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)
VECTORS = json.loads((HERE.parent / "fixtures/native-echo/wire-v1.json").read_text())


def baseline():
    lines = ["ECHO WIRE BEGIN v=1 start_ms=100 until_ms=20100 negative_until_ms=8100 cases=9"]
    frames = []
    ordinals = {"tx": 0, "rx": 0}

    def frame(direction, phase, at, value):
        ordinals[direction] += 1
        lines.append(f"ECHO WIRE FRAME v=1 direction={direction} ordinal={ordinals[direction]} phase={phase} at_ms={at} bytes={len(value)} hex={value.hex()}")
        frames.append((len(frames), [1000, len(frames) * 1000], value))

    frame("tx", "negative", 110, bytes.fromhex(VECTORS["arp_request_hex"]))
    frame("rx", "negative", 120, bytes.fromhex(VECTORS["arp_reply_hex"]))
    frame("tx", "negative", 130, bytes.fromhex(VECTORS["negative_request_hex"]))
    for index, row in enumerate(VECTORS["cases"]):
        frame("rx", "negative", 140 + index * 10, bytes.fromhex(row["frame_hex"]))
        lines.append(f"ECHO WIRE CASE v=1 index={index} case={row['case']} receive_ordinal={index + 2} at_ms={142 + index * 10} code=5 observations=0 sockets=1 requests=1")
    lines.append("ECHO WIRE RETIRED v=1 at_ms=240 stale_code=4 sockets=0 requests=1")
    lines.append("ECHO WIRE POSITIVE v=1 start_ms=250 until_ms=8250 fresh=1 sockets=1")
    frame("tx", "positive", 260, bytes.fromhex(VECTORS["positive_request_hex"]))
    frame("rx", "positive", 270, bytes.fromhex(VECTORS["positive_reply_hex"]))
    lines.append("ECHO WIRE OBSERVED v=1 at_ms=280 identifier=7445 sequence=3231 instance=1 epoch=4 nonce=864a18f71f24c501 boot_rtt_ms=20 auth=none requests=1 sockets=0")
    lines.append("ECHO WIRE DONE v=1 at_ms=290 sockets=0 negative_cases=9 observations=1")
    return lines, frames


def serial(lines):
    output = ("\n".join(lines) + "\n").encode()
    digest = 0x811c9dc5
    for value in output:
        digest = ((digest ^ value) * 0x1000193) & 0xffffffff
    raw = (b"ABSD KERNEL BOOT\nNETWORK LINK OK descriptors=32\n"
           b"SPAWN OK pid=2 parent=1 program=external-workload\n"
           b"EXTERNAL OUTPUT BEGIN encoding=hex\nDURABLE WORKER GENERATION generation=1 pid=2\n")
    for offset in range(0, len(output), 96):
        raw += f"EXTERNAL OUTPUT CHUNK offset={offset:016x} data={output[offset:offset + 96].hex()}\n".encode()
    raw += (b"USER EXIT pid=2 status=0\nDURABLE WORKER OUTCOME generation=1 pid=2 status=0\n"
            + f"EXTERNAL OUTPUT END bytes={len(output)} digest={digest:08x}\n".encode()
            + b"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ticks=300\n"
              b"NIC STATS rx_frames=11 rx_refused=0 rx_missed=0 tx_frames=3 tx_refused=0 tx_errors=0 flags=1\n"
              b"DURABLE WORKLOAD OK\nABSD BOOT OK\n")
    return raw


def evaluated(lines=None, frames=None):
    canonical_lines, canonical_frames = baseline()
    native = proof.native_output(serial(canonical_lines if lines is None else lines), 3)
    proof.inspect_frames(canonical_frames if frames is None else frames, native)
    return native


class WireControls(unittest.TestCase):
    def changed(self, old, new):
        lines, _ = baseline()
        assert sum(old in line for line in lines) == 1
        return [line.replace(old, new) for line in lines]

    def test_01_literal_packet_vectors_and_success(self):
        request = bytes.fromhex(VECTORS["negative_request_hex"])
        self.assertEqual([row["case"] for row in VECTORS["cases"]], list(proof.peer.CASES))
        offsets = [29, 34, 35, 38, 40, 42, 58, 66, 36]
        for index, row in enumerate(VECTORS["cases"]):
            frame = bytes.fromhex(row["frame_hex"])
            self.assertEqual(frame, proof.peer.negative_reply(request, row["case"]))
            self.assertEqual(len(frame), 74)
            self.assertEqual(proof.peer.checksum(frame[14:34]), 0)
            self.assertEqual(proof.peer.checksum(frame[34:]) == 0, index != 8)
            self.assertNotEqual(frame[offsets[index]], request[offsets[index]])
        self.assertEqual(evaluated()["records"], 28)

    def test_02_observation_in_negative_is_refused(self):
        with self.assertRaises(AssertionError):
            evaluated(self.changed("index=0 case=wrong-peer receive_ordinal=2 at_ms=142 code=5 observations=0", "index=0 case=wrong-peer receive_ordinal=2 at_ms=142 code=0 observations=1"))

    def test_03_missing_case_is_refused(self):
        lines, _ = baseline()
        with self.assertRaises(AssertionError):
            evaluated([line for line in lines if "CASE v=1 index=8 " not in line])

    def test_04_duplicate_case_is_refused(self):
        lines, _ = baseline()
        at = next(i for i, line in enumerate(lines) if "CASE v=1 index=0 " in line)
        lines.insert(at + 1, lines[at])
        with self.assertRaises(AssertionError):
            evaluated(lines)

    def test_05_substituted_actual_ingress_bytes_are_refused(self):
        lines, _ = baseline()
        at = next(i for i, line in enumerate(lines) if "direction=rx ordinal=2 " in line)
        lines[at] = lines[at][:-2] + ("01" if lines[at][-2:] != "01" else "00")
        with self.assertRaises(AssertionError):
            evaluated(lines)

    def test_06_missing_receive_witness_is_refused(self):
        with self.assertRaises(AssertionError):
            evaluated(self.changed("index=0 case=wrong-peer receive_ordinal=2", "index=0 case=wrong-peer receive_ordinal=30"))

    def test_07_one_receive_cannot_cover_two_cases(self):
        with self.assertRaises(AssertionError):
            evaluated(self.changed("index=1 case=wrong-type receive_ordinal=3", "index=1 case=wrong-type receive_ordinal=2"))

    def test_08_native_ordinal_substitution_is_refused(self):
        with self.assertRaises(AssertionError):
            evaluated(self.changed("direction=rx ordinal=2 ", "direction=rx ordinal=3 "))

    def test_09_case_receive_after_result_is_refused(self):
        with self.assertRaises(AssertionError):
            evaluated(self.changed("index=0 case=wrong-peer receive_ordinal=2 at_ms=142", "index=0 case=wrong-peer receive_ordinal=2 at_ms=139"))

    def test_10_renewed_negative_deadline_is_refused(self):
        with self.assertRaises(AssertionError):
            evaluated(self.changed("negative_until_ms=8100", "negative_until_ms=8200"))

    def test_11_renewed_positive_deadline_is_refused(self):
        with self.assertRaises(AssertionError):
            evaluated(self.changed("start_ms=250 until_ms=8250", "start_ms=250 until_ms=8350"))

    def test_12_old_authority_still_live_is_refused(self):
        with self.assertRaises(AssertionError):
            evaluated(self.changed("at_ms=240 stale_code=4 sockets=0", "at_ms=240 stale_code=4 sockets=1"))

    def test_13_relabelled_negative_as_positive_is_refused(self):
        with self.assertRaises(AssertionError):
            evaluated(self.changed("ordinal=2 phase=negative at_ms=140", "ordinal=2 phase=positive at_ms=140"))

    def test_14_wrong_positive_correlation_is_refused(self):
        with self.assertRaises(AssertionError):
            evaluated(self.changed("epoch=4 nonce=", "epoch=5 nonce="))

    def test_15_capture_missing_selected_frame_is_refused(self):
        _, frames = baseline()
        with self.assertRaises(AssertionError):
            evaluated(frames=frames[:3] + frames[4:])

    def test_16_capture_extra_application_request_is_refused(self):
        _, frames = baseline()
        with self.assertRaises(AssertionError):
            evaluated(frames=frames + [frames[2]])

    def test_17_corrected_negative_checksum_is_refused(self):
        _, frames = baseline()
        at, stamp, frame = frames[11]
        changed = bytearray(frame)
        changed[36] ^= 1
        frames[11] = at, stamp, bytes(changed)
        with self.assertRaises(AssertionError):
            evaluated(frames=frames)

    def test_18_corrupted_positive_checksum_is_refused(self):
        _, frames = baseline()
        at, stamp, frame = frames[-1]
        changed = bytearray(frame)
        changed[36] ^= 1
        frames[-1] = at, stamp, bytes(changed)
        with self.assertRaises(AssertionError):
            evaluated(frames=frames)

    def test_19_unsealed_raw_output_is_refused(self):
        lines, _ = baseline()
        raw = serial(lines)
        with self.assertRaises(AssertionError):
            proof.native_output(raw.replace(b"EXTERNAL OUTPUT END bytes=", b"EXTERNAL OUTPUT MISSING bytes="), 3)
        with self.assertRaises(AssertionError):
            proof.native_output(raw.replace(b"digest=", b"digest=0", 1), 3)

    def test_20_failed_or_nonterminal_worker_is_refused(self):
        lines, _ = baseline()
        raw = serial(lines)
        with self.assertRaises(AssertionError):
            proof.native_output(raw, 1)
        with self.assertRaises(AssertionError):
            proof.native_output(raw.replace(b"USER EXIT pid=2 status=0\n", b""), 3)

    def test_21_nic_accounting_mismatch_is_refused(self):
        lines, _ = baseline()
        with self.assertRaises(AssertionError):
            proof.native_output(serial(lines).replace(b"rx_frames=11", b"rx_frames=10"), 3)

    def test_22_native_case_ack_waits_for_complete_line(self):
        lines, _ = baseline()
        at = next(i for i, line in enumerate(lines) if "CASE v=1 index=0 " in line)
        partial = ("\n".join(lines[:at]) + "\n" + lines[at]).encode()
        expected = bytes.fromhex(VECTORS["cases"][0]["frame_hex"])
        self.assertIsNone(proof.peer.acknowledged(partial, 0, expected))
        self.assertIsNotNone(proof.peer.acknowledged(partial + b"\n", 0, expected))

    def test_23_peer_enable_and_sequential_effects_are_checked(self):
        native = evaluated()
        _, frames = baseline()
        request = bytes.fromhex(VECTORS["negative_request_hex"])
        report = {"schema": "absd-echo-wire-peer/1", "disposition": "PASS", "network_namespace_inode": 42,
                  "pid": 99, "initial_echo_ignore_all": "1", "final_echo_ignore_all": "0", "enable_before_case": 8,
                  "negative_request": proof.peer.identity(request), "cases": []}
        for i, row in enumerate(VECTORS["cases"]):
            report["cases"].append({"index": i, "case": row["case"], "frame": proof.peer.identity(bytes.fromhex(row["frame_hex"])),
                "native_acknowledgement": native["cases"][i], "send_monotonic_ns": 10 * i + 1, "ack_read_monotonic_ns": 10 * i + 2})
        proof.inspect_peer(report, native, frames, 42, 99)
        wrong = copy.deepcopy(report)
        wrong["enable_before_case"] = 7
        with self.assertRaises(AssertionError):
            proof.inspect_peer(wrong, native, frames, 42, 99)
        wrong = copy.deepcopy(report)
        wrong["cases"][1]["send_monotonic_ns"] = 1
        with self.assertRaises(AssertionError):
            proof.inspect_peer(wrong, native, frames, 42, 99)

    def arp_submission(self, direction="tx", length=42):
        lines, frames = baseline()
        ordinal = 1
        at = next(i for i, line in enumerate(lines) if f"direction={direction} ordinal={ordinal} " in line)
        prefix, value = lines[at].rsplit(" hex=", 1)
        submitted = bytes.fromhex(value)[:length]
        lines[at] = prefix.replace("bytes=60", f"bytes={length}") + " hex=" + submitted.hex()
        return lines, frames

    def test_24_exact_zero_padded_tx_arp_correspondence_is_admitted(self):
        lines, frames = self.arp_submission()
        self.assertEqual(evaluated(lines, frames)["records"], 28)

    def test_25_nonzero_arp_padding_is_refused(self):
        lines, frames = self.arp_submission()
        index, stamp, data = frames[0]
        frames[0] = index, stamp, data[:-1] + b"\x01"
        with self.assertRaises(AssertionError):
            evaluated(lines, frames)

    def test_26_padding_rule_cannot_change_rx_or_icmp(self):
        lines, frames = self.arp_submission("rx")
        with self.assertRaises(AssertionError):
            evaluated(lines, frames)
        lines, frames = baseline()
        at = next(i for i, line in enumerate(lines) if "direction=tx ordinal=2 " in line)
        prefix, value = lines[at].rsplit(" hex=", 1)
        lines[at] = prefix.replace("bytes=74", "bytes=42") + " hex=" + value[:84]
        with self.assertRaises(AssertionError):
            evaluated(lines, frames)

    def test_27_padding_rule_cannot_accept_other_lengths(self):
        for length in (41, 43, 59):
            lines, frames = self.arp_submission(length=length)
            with self.assertRaises(AssertionError):
                evaluated(lines, frames)


if __name__ == "__main__":
    unittest.main()
