#!/usr/bin/env python3
"""Finite boundary artifact controls; run on the lane's disposable build VM."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


matrix = load("echo_boundary_matrix", "native-echo-matrix.py")
positive = load("echo_positive_vectors", "native-echo-matrix-tests.py")
directional = load("echo_directional_vectors", "native-echo-matrix-arp-tests.py")

# These literal requests and complete replies are deliberately independent of
# the evaluator constants. A changed operation or response code must refuse.
REQUESTS = bytes.fromhex(
    "00010000c0000201" "017f0000c0000201" "01010100c0000201"
    "01010001c0000201" "01010000c0000202" "01020000c0000202"
    "01030000c0000202" "00")
REPLIES = b"".join(bytes.fromhex(header) + bytes(44) for header in (
    "01010100", "017f0100", "01010100", "01010100", "01010200",
    "01020200", "01030200"))
CTORS = (
    ("unspecified", 2, 0), ("loopback", 2, 0), ("multicast", 2, 0),
    ("local", 2, 0), ("subnet", 2, 0), ("broadcast", 2, 0), ("off-link", 2, 0),
    ("expired", 1, 0), ("too-long", 1, 0), ("entropy-error", 13, 0),
    ("entropy-zero", 13, 0), ("second-grant", 3, 1), ("closed-stale", 4, 0),
)


def text():
    rows = ["ECHO BOUNDARY BEGIN v=1 start_ms=100 until_ms=20100 negative_until_ms=8100"]
    rows += [f"ECHO BOUNDARY CTOR v=1 case={name} code={code} sockets={sockets}" for name, code, sockets in CTORS]
    rows += [
        "ECHO BOUNDARY CENSUS v=1 label=before-negative processes=2 handles=13 pipes=2 cells=1 frames=200",
        "ECHO BOUNDARY BOOTSTRAP v=1 bytes=13 hex=01c00002010000000000001fa4",
        "ECHO BOUNDARY PREFIX v=1 before_ms=200 read_before_ms=201 read_ms=202 bytes=1 hex=00 sockets=1",
        "ECHO BOUNDARY KILL v=1 before_ms=203 at_ms=204 code=0",
        "ECHO BOUNDARY REAP v=1 before_ms=205 at_ms=206 kind=3 status=0",
        "ECHO BOUNDARY EOF v=1 before_ms=207 at_ms=208 bytes=0",
        f"ECHO BOUNDARY LEDGER v=1 read_bytes=57 read_hex={REQUESTS.hex()} written_bytes=336 written_hex={REPLIES.hex()} link_sends=0",
        "ECHO BOUNDARY RETIRED v=1 at_ms=209 request_eof=1 result_eof=1 channel=0 sockets=0 fallback=0 stale_code=4",
        "ECHO BOUNDARY CENSUS v=1 label=after-negative processes=2 handles=13 pipes=2 cells=1 frames=203",
        "ECHO BOUNDARY POSITIVE v=1 start_ms=220 until_ms=8220 fresh=1 sockets=1",
        "ECHO BOUNDARY POSITIVE-REAP v=1 at_ms=300 kind=1 status=0 request_eof=1 result_eof=1",
        "ECHO BOUNDARY CENSUS v=1 label=after-positive processes=2 handles=13 pipes=2 cells=1 frames=204",
        "ECHO BOUNDARY DONE v=1 at_ms=301 objects_restored=1 sockets=0",
        f"PING peer=192.0.2.1 identifier={positive.IDENTIFIER} sequence={positive.SEQUENCE} instance={positive.INSTANCE} epoch={positive.EPOCH} nonce={positive.NONCE:016x} boot_rtt_ms=9 auth=none denied=1 nic=0 requests=1",
        "PING DONE child=exited sockets=0 requests=1",
    ]
    return "\n".join(rows) + "\n"


def serial(output=None):
    data = (text() if output is None else output).encode("utf-8")
    digest = 2166136261
    for byte in data:
        digest = ((digest ^ byte) * 16777619) % (1 << 32)
    raw = positive.serial(data)
    return raw + (b"SPAWN OK pid=3 parent=2 program=fixture-negative\n"
                  b"SPAWN OK pid=4 parent=2 program=fixture-positive\n"
                  b"USER EXIT pid=4 status=0\nUSER EXIT pid=2 status=0\n"
                  b"DURABLE WORKER OUTCOME generation=1 pid=2 status=0\n"
                  + f"EXTERNAL OUTPUT END bytes={len(data)} digest={digest:08x}\n".encode("ascii"))


class BoundaryArtifacts(unittest.TestCase):
    def refused_text(self, value):
        # Recompute the terminal digest so each semantic test exercises the
        # predicate itself rather than an incidental checksum mismatch.
        with self.assertRaises(AssertionError):
            matrix.native_boundary_output(serial(value), 3)

    def test_complete_boundary_and_unchanged_linux_packet_correspondence(self):
        vector_path = Path(__file__).resolve().parent.parent / "fixtures/native-echo/boundary-v1.txt"
        names = ("bad-version", "bad-op", "reserved-a", "reserved-b",
                 "wrong-peer-start", "wrong-peer-observe", "wrong-peer-close")
        expected = [f"{name} request={REQUESTS[index * 8:(index + 1) * 8].hex()} reply={REPLIES[index * 48:(index + 1) * 48].hex()}"
                    for index, name in enumerate(names)]
        expected.append("partial-after-all-replies request=00 reply=none")
        actual = [line for line in vector_path.read_text().splitlines() if line and not line.startswith("#")]
        self.assertEqual(actual, expected)
        result = matrix.native_boundary_output(serial(), 3)
        self.assertEqual(result["boundary"]["ledger"]["read_hex"], REQUESTS.hex())
        self.assertEqual(result["boundary"]["retirement"]["at_ms"], "209")
        with tempfile.TemporaryDirectory(prefix="absd-echo-boundary-control-") as temporary:
            path = Path(temporary) / "linux.pcap"
            path.write_bytes(directional.capture(directional.frames()))
            self.assertEqual(matrix.inspect(path, result, directional=True)["reply"]["index"], 3)

    def test_boundary_selects_actual_directional_arp_and_refuses_legacy_guest_fields(self):
        result = matrix.native_boundary_output(serial(), 3)
        with tempfile.TemporaryDirectory(prefix="absd-echo-directional-control-") as temporary:
            path = Path(temporary) / "linux.pcap"
            packets = directional.frames()
            packets[0] = directional.ACTUAL_GUEST_ARP
            path.write_bytes(directional.capture(packets))
            self.assertEqual(matrix.inspect(path, result, directional=True)["reply"]["index"], 3)
            # The former zero-target-hardware fixture is explicitly wrong for
            # the guest's pinned engine, while the Linux side remains zero.
            packets[0] = positive.frames()[0]
            path.write_bytes(directional.capture(packets))
            with self.assertRaisesRegex(AssertionError, "guest ARP"):
                matrix.inspect(path, result, directional=True)
            packets = directional.frames()
            packets += [directional.arp(1, False, True), directional.arp(2, True)]
            path.write_bytes(directional.capture(packets))
            self.assertEqual(len(matrix.inspect(path, result, directional=True)["ARP"]), 4)
            changed = bytearray(packets[-2])
            changed[32:38] = matrix.GUEST_MAC
            packets[-2] = bytes(changed)
            path.write_bytes(directional.capture(packets))
            with self.assertRaises(AssertionError):
                matrix.inspect(path, result, directional=True)

    def test_every_constructor_code_socket_and_order_are_checked(self):
        for name, code, sockets in CTORS:
            old = f"case={name} code={code} sockets={sockets}"
            for new in (f"case={name} code={code + 1} sockets={sockets}",
                        f"case={name} code={code} sockets={1 - sockets}"):
                with self.subTest(case=name, value=new):
                    self.refused_text(text().replace(old, new))
        rows = text().splitlines(keepends=True)
        rows[1], rows[2] = rows[2], rows[1]
        self.refused_text("".join(rows))

    def test_each_actual_request_byte_is_bound(self):
        for at in range(len(REQUESTS)):
            changed = bytearray(REQUESTS)
            changed[at] ^= 1
            with self.subTest(offset=at):
                self.refused_text(text().replace("read_hex=" + REQUESTS.hex(), "read_hex=" + changed.hex()))

    def test_every_reply_status_reserved_and_body_is_bound(self):
        for record in range(7):
            for offset in (0, 1, 2, 3, 4, 47):
                changed = bytearray(REPLIES)
                changed[record * 48 + offset] ^= 1
                with self.subTest(record=record, offset=offset):
                    self.refused_text(text().replace("written_hex=" + REPLIES.hex(), "written_hex=" + changed.hex()))

    def test_ledger_lengths_and_pre_positive_send_count_are_checked(self):
        for old, new in (("read_bytes=57", "read_bytes=56"),
                         ("written_bytes=336", "written_bytes=335"),
                         ("link_sends=0", "link_sends=1")):
            self.refused_text(text().replace(old, new))

    def test_original_bootstrap_is_not_reissued_or_extended(self):
        for old, new in (("bytes=13 hex=01c00002010000000000001fa4", "bytes=13 hex=01c00002010000000000001fa5"),
                         ("until_ms=20100", "until_ms=20101"),
                         ("negative_until_ms=8100", "negative_until_ms=8101")):
            self.refused_text(text().replace(old, new))

    def test_partial_byte_and_live_reserved_socket_are_required(self):
        old = "read_ms=202 bytes=1 hex=00 sockets=1"
        for new in ("read_ms=202 bytes=2 hex=00 sockets=1",
                    "read_ms=202 bytes=1 hex=01 sockets=1",
                    "read_ms=202 bytes=1 hex=00 sockets=0"):
            self.refused_text(text().replace(old, new))

    def test_clock_rewind_or_reordered_effect_observations_refuse(self):
        for old, new in (("read_before_ms=201", "read_before_ms=199"),
                         ("read_ms=202", "read_ms=200"),
                         ("KILL v=1 before_ms=203", "KILL v=1 before_ms=201"),
                         ("KILL v=1 before_ms=203 at_ms=204", "KILL v=1 before_ms=203 at_ms=202"),
                         ("REAP v=1 before_ms=205", "REAP v=1 before_ms=203"),
                         ("EOF v=1 before_ms=207", "EOF v=1 before_ms=205"),
                         ("RETIRED v=1 at_ms=209", "RETIRED v=1 at_ms=207")):
            self.refused_text(text().replace(old, new))

    def test_expiry_does_not_substitute_for_eof(self):
        self.refused_text(text().replace("RETIRED v=1 at_ms=209", "RETIRED v=1 at_ms=450"))
        self.refused_text(text().replace("RETIRED v=1 at_ms=209", "RETIRED v=1 at_ms=8100"))

    def test_kill_reap_and_actual_request_eof_are_required(self):
        for old, new in (("at_ms=204 code=0", "at_ms=204 code=1"),
                         ("at_ms=206 kind=3", "at_ms=206 kind=1"),
                         ("at_ms=206 kind=3 status=0", "at_ms=206 kind=3 status=1"),
                         ("EOF v=1 before_ms=207 at_ms=208 bytes=0", "EOF v=1 before_ms=207 at_ms=208 bytes=1")):
            self.refused_text(text().replace(old, new))

    def test_fallback_fence_and_live_authority_cannot_count_as_eof_retirement(self):
        for key, old, new in (("request_eof", 1, 0), ("result_eof", 1, 0),
                              ("channel", 0, 1), ("sockets", 0, 1),
                              ("fallback", 0, 1), ("stale_code", 4, 0)):
            rows = text().splitlines(keepends=True)
            rows[21] = rows[21].replace(f"{key}={old}", f"{key}={new}")
            self.refused_text("".join(rows))

    def test_object_counts_must_restore_after_both_consumers(self):
        for row in (22, 25):
            for key, value in (("processes", 2), ("handles", 13), ("pipes", 2), ("cells", 1)):
                rows = text().splitlines(keepends=True)
                rows[row] = rows[row].replace(f"{key}={value}", f"{key}={value + 1}")
                with self.subTest(row=row, key=key):
                    self.refused_text("".join(rows))

    def test_frame_counts_remain_observations(self):
        result = matrix.native_boundary_output(serial(text().replace("frames=203", "frames=211").replace("frames=204", "frames=212")), 3)
        self.assertEqual(result["boundary"]["after_negative"]["frames"], 211)
        self.assertEqual(result["boundary"]["after_positive"]["frames"], 212)

    def test_positive_uses_fresh_bounded_authority(self):
        for old, new in (("fresh=1 sockets=1", "fresh=0 sockets=1"),
                         ("fresh=1 sockets=1", "fresh=1 sockets=0"),
                         ("start_ms=220 until_ms=8220", "start_ms=208 until_ms=8220"),
                         ("start_ms=220 until_ms=8220", "start_ms=220 until_ms=8221"),
                         ("POSITIVE-REAP v=1 at_ms=300", "POSITIVE-REAP v=1 at_ms=8220"),
                         ("DONE v=1 at_ms=301", "DONE v=1 at_ms=20100")):
            self.refused_text(text().replace(old, new))

    def test_positive_natural_reap_eofs_and_done_are_required(self):
        for old, new in (("at_ms=300 kind=1", "at_ms=300 kind=3"),
                         ("at_ms=300 kind=1 status=0", "at_ms=300 kind=1 status=1"),
                         ("at_ms=300 kind=1 status=0 request_eof=1", "at_ms=300 kind=1 status=0 request_eof=0"),
                         ("at_ms=300 kind=1 status=0 request_eof=1 result_eof=1", "at_ms=300 kind=1 status=0 request_eof=1 result_eof=0"),
                         ("objects_restored=1", "objects_restored=0")):
            self.refused_text(text().replace(old, new))

    def test_missing_duplicate_reordered_and_partial_records_refuse(self):
        rows = text().splitlines(keepends=True)
        self.refused_text("".join(rows[:19] + rows[20:]))
        self.refused_text("".join(rows[:19] + [rows[19]] + rows[19:]))
        reordered = list(rows)
        reordered[17], reordered[18] = reordered[18], reordered[17]
        self.refused_text("".join(reordered))
        self.refused_text(text()[:-1])

    def test_unknown_duplicate_or_noncanonical_numeric_fields_refuse(self):
        for old, new in (("fallback=0 stale_code=4", "fallback=0 stale_code=4 extra=0"),
                         ("fallback=0 stale_code=4", "fallback=0 fallback=0 stale_code=4"),
                         ("before_ms=200", "before_ms=0200"),
                         ("before_ms=200", "before_ms=18446744073709551616")):
            self.refused_text(text().replace(old, new))

    def test_terminal_digest_and_byte_count_are_required(self):
        raw = serial()
        for changed in (raw.split(b"EXTERNAL OUTPUT END")[0], raw + raw[raw.index(b"EXTERNAL OUTPUT END"):],
                        raw.replace(b"digest=", b"digest=f", 1), raw.replace(b"END bytes=", b"END bytes=1", 1)):
            with self.assertRaises(AssertionError):
                matrix.native_boundary_output(changed, 3)

    def test_output_chunk_order_and_complete_parent_child_terminals_are_required(self):
        raw = serial()
        for changed in (raw.replace(b"offset=0000000000000000", b"offset=0000000000000001"),
                        raw.replace(b"USER EXIT pid=2 status=0\n", b""),
                        raw.replace(b"USER EXIT pid=4 status=0\n", b""),
                        raw.replace(b"DURABLE WORKER OUTCOME generation=1 pid=2 status=0\n", b""),
                        raw.replace(b"SPAWN OK pid=3 parent=2 program=fixture-negative\n", b"")):
            with self.assertRaises(AssertionError):
                matrix.native_boundary_output(changed, 3)
        with self.assertRaises(AssertionError):
            matrix.native_boundary_output(raw, 0)

    def test_original_positive_profile_still_accepts_its_original_fixture(self):
        self.assertEqual(matrix.native_output(positive.serial(), 3)["nonce"], positive.NONCE)


if __name__ == "__main__":
    unittest.main()
