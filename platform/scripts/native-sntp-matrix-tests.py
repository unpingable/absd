#!/usr/bin/env python3
"""Deterministic artifact predicates, not Linux interoperability or native tests.

Execute on a dedicated VM; source-only tests do not establish guest behavior.
"""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("sntp_matrix", Path(__file__).with_name("native-sntp-matrix.py"))
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)
PORT, NONCE = 55001, 0x0123456789abcdef
SECONDS, FRACTION = matrix.MIN_UNIX + 42, 3


def request(nonce=NONCE):
    return bytes([0x23]) + bytes(39) + nonce.to_bytes(8, "big")


def reply(nonce=NONCE, seconds=SECONDS):
    packet = bytearray(48)
    packet[:4] = bytes([0x24, 10, 0, 0])
    packet[12:16] = b"LOCL"
    for at, value in ((16, ((seconds - 2 + matrix.NTP_UNIX) << 32) + 1),
                      (24, nonce), (32, ((seconds - 1 + matrix.NTP_UNIX) << 32) + 2),
                      (40, ((seconds + matrix.NTP_UNIX) << 32) + FRACTION)):
        packet[at:at + 8] = value.to_bytes(8, "big")
    return bytes(packet)


def udp(packet, outgoing, port=PORT):
    source, target = (matrix.GUEST, matrix.HOST) if outgoing else (matrix.HOST, matrix.GUEST)
    sport, dport = (port, 123) if outgoing else (123, port)
    data = struct.pack("!HHHH", sport, dport, 8 + len(packet), 0) + packet
    value = matrix.checksum(source + target + struct.pack("!BBH", 0, 17, len(data)) + data)
    data = data[:6] + struct.pack("!H", value or 65535) + data[8:]
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(data), 1, 0x4000, 64, 17, 0, source, target)
    header = header[:10] + struct.pack("!H", matrix.checksum(header)) + header[12:]
    macs = (matrix.HOST_MAC + matrix.GUEST_MAC) if outgoing else (matrix.GUEST_MAC + matrix.HOST_MAC)
    return macs + b"\x08\x00" + header + data


def arp(operation, outgoing, directed=False):
    source_mac, peer_mac = (matrix.GUEST_MAC, matrix.HOST_MAC) if outgoing else (matrix.HOST_MAC, matrix.GUEST_MAC)
    source, target = (matrix.GUEST, matrix.HOST) if outgoing else (matrix.HOST, matrix.GUEST)
    destination = peer_mac if operation == 2 or directed else b"\xff" * 6
    target_mac = peer_mac if operation == 2 else b"\xff" * 6 if outgoing else bytes(6)
    return destination + source_mac + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x0800, 6, 4, operation) + source_mac + source + target_mac + target


def frames():
    return [arp(1, True), arp(2, False), udp(request(), True), udp(reply(), False)]


def capture(packets):
    # Exact complete Ethernet records; order is material, civil timestamps are not boot time.
    data = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65536, 1)
    for index, packet in enumerate(packets):
        data += struct.pack("<IIII", 1, index, len(packet), len(packet)) + packet
    return data


def serial(output=None):
    if output is None:
        output = (f"SNTP GRANT local_port={PORT} peer=192.0.2.1:123\n"
                  f"SNTP server_claimed_unix={SECONDS} server_fraction_2p32={FRACTION} "
                  f"rtc_unix={SECONDS - 5} boot_rtt_ms=12 auth=none uncertainty=unknown "
                  "unauthenticated_difference=5s attempt=1 denied=1 nic=0\n"
                  "SNTP DONE child=exited sockets=0 observation_only=1\n").encode()
    return (b"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 \nDURABLE WORKLOAD OK\n"
            b"ABSD BOOT OK\nNETWORK LINK OK fixture\n"
            b"EXTERNAL OUTPUT CHUNK offset=0000000000000000 data=" + output.hex().encode() + b"\n"
            b"NIC STATS rx_frames=2 tx_frames=2 rx_refused=0 rx_missed=0 tx_refused=0 tx_errors=0\n")


class ArtifactPredicates(unittest.TestCase):
    def test_literal_actual_interface_qualified_socket_and_identity_substitutions(self):
        # Independent peer-only diagnostic1182; no guest or NTP request ran.
        literal = ('UNCONN 0      0      192.0.2.1%sntp-tap0:123 0.0.0.0:* '
                   'users:(("chronyd",pid=73219,fd=3))\n')
        self.assertEqual(matrix.peer_sockets(literal, 73219), [literal.rstrip("\n")])
        for old, new in (("192.0.2.1%", "192.0.2.2%"), (":123 ", ":124 "),
                         ("sntp-tap0", "sntp-tap1"), ("pid=73219", "pid=732190"),
                         ("chronyd", "other"), ("UNCONN", "ESTAB")):
            self.assertEqual(matrix.peer_sockets(literal.replace(old, new), 73219), [])
        self.assertEqual(matrix.peer_sockets(literal, 73220), [])
        self.assertEqual(matrix.peer_sockets(literal.replace("%sntp-tap0", ""), 73219), [])

    def test_literal_actual_smoltcp_request_and_directional_target_substitutions(self):
        # Sealed native DHCP467 PCAP frame12 (zero-based), same Stack::open
        # producer, guest and peer IPs. Its request contains no peer MAC field.
        literal = bytes.fromhex(
            "ffffffffffff52540012345608060001080006040001525400123456c0000264"
            "ffffffffffffc0000201000000000000000000000000000000000000")
        packets = frames()
        packets[0] = literal
        self.assertEqual(len(self.inspect(packets)["ARP"]), 2)
        for packet, position, hardware in ((literal, 0, bytes(6)),
                                           (arp(1, False), 4, b"\xff" * 6)):
            substituted = packet[:32] + hardware + packet[38:]
            changed = frames()
            if position == 0:
                changed[0] = substituted
            else:
                changed.append(substituted)
            with self.assertRaisesRegex(AssertionError, "ARP request destination"):
                self.inspect(changed)

    def test_exact_template_has_one_owned_pid_path_and_separate_source_identity(self):
        template = (matrix.ROOT / "fixtures/native-sntp/chrony.conf").read_bytes()
        effective, pidfile = matrix.peer_config(template, Path("/tmp/absd-proof-123"))
        self.assertEqual(pidfile, Path("/tmp/absd-proof-123/chronyd.pid"))
        self.assertEqual(effective, template.replace(b"@PROOF_PIDFILE@", str(pidfile).encode()))
        self.assertNotIn(b"@PROOF_PIDFILE@", effective)
        self.assertIn(b"bindcmdaddress /\n", effective)

    def test_template_substitution_and_configuration_token_expansion_refuse(self):
        template = (matrix.ROOT / "fixtures/native-sntp/chrony.conf").read_bytes()
        for changed in (template + b"server 192.0.2.2\n", template.replace(b"allow 192.0.2.100/32", b"allow all")):
            with self.assertRaises(AssertionError):
                matrix.peer_config(changed, Path("/tmp/absd-proof-123"))
        with self.assertRaises(AssertionError):
            matrix.peer_config(template, Path("/tmp/absd proof\nextra"))

    def inspect(self, packets, observation=None, data=None):
        if observation is None:
            observation = matrix.native_output(serial(), 3)
        with tempfile.TemporaryDirectory(prefix="absd-sntp-artifact-") as temporary:
            path = Path(temporary) / "fixture.pcap"
            path.write_bytes(capture(packets) if data is None else data)
            return matrix.inspect(path, observation)

    def test_valid_complete_request_reply_and_native_stamp(self):
        result = self.inspect(frames())
        self.assertEqual(result["replies"][0]["origin"], NONCE)
        self.assertEqual(result["replies"][0]["fraction_2p32"], FRACTION)
        self.assertEqual(result["observed_reply_index"], 3)

    def test_exact_linux_directed_arp_request_is_admitted(self):
        packets = frames()
        packets.extend([arp(1, False, directed=True), arp(2, True)])
        self.assertEqual(len(self.inspect(packets)["ARP"]), 4)

    def test_wrong_origin_with_valid_transport_is_refused(self):
        packets = frames()
        packets[-1] = udp(reply(NONCE + 1), False)
        with self.assertRaisesRegex(AssertionError, "origin"):
            self.inspect(packets)

    def test_wrong_tuple_with_valid_transport_is_refused(self):
        packets = frames()
        packets[-1] = udp(reply(), False, PORT + 1)
        with self.assertRaisesRegex(AssertionError, "tuple"):
            self.inspect(packets)

    def test_out_of_era_claim_with_valid_transport_is_refused(self):
        packets = frames()
        packets[-1] = udp(reply(seconds=matrix.MAX_UNIX + 1), False)
        with self.assertRaisesRegex(AssertionError, "era"):
            self.inspect(packets)

    def test_udp_checksum_mutation_is_refused(self):
        packets = frames()
        damaged = bytearray(packets[-1])
        damaged[-1] ^= 1
        packets[-1] = bytes(damaged)
        with self.assertRaisesRegex(AssertionError, "UDP length/checksum"):
            self.inspect(packets)

    def test_ipv4_checksum_mutation_is_refused(self):
        packets = frames()
        damaged = bytearray(packets[-1])
        damaged[22] ^= 1
        packets[-1] = bytes(damaged)
        with self.assertRaisesRegex(AssertionError, "IPv4 length/checksum"):
            self.inspect(packets)

    def test_duplicate_late_extra_reply_is_refused(self):
        packets = frames()
        packets.append(packets[-1])
        with self.assertRaisesRegex(AssertionError, "duplicate reply"):
            self.inspect(packets)

    def test_prior_attempt_late_reply_is_refused_even_with_matching_final_claim(self):
        observation = matrix.native_output(serial(), 3)
        observation["attempt"] = 2
        packets = frames()[:3] + [udp(request(NONCE + 1), True), udp(reply(), False),
                                  udp(reply(NONCE + 1, SECONDS + 1), False)]
        observation["unix_seconds"] += 1
        with self.assertRaisesRegex(AssertionError, "unconsumed late reply"):
            self.inspect(packets, observation)

    def test_native_fraction_must_match_captured_transmit(self):
        observation = matrix.native_output(serial(), 3)
        observation["fraction_2p32"] += 1
        with self.assertRaisesRegex(AssertionError, "correspondence"):
            self.inspect(frames(), observation)

    def test_unrelated_frame_mutation_is_refused(self):
        packets = frames()
        damaged = bytearray(packets[-1])
        damaged[0] ^= 1
        packets[-1] = bytes(damaged)
        with self.assertRaisesRegex(AssertionError, "MAC destination"):
            self.inspect(packets)

    def test_short_capture_is_refused(self):
        with self.assertRaisesRegex(AssertionError, "capture record|PCAP|capture header"):
            self.inspect([], data=capture(frames())[:-1])

    def test_output_clock_rtt_boundary_and_authority_labels_are_not_relaxed(self):
        raw = serial()
        # Mutate decoded output, then regenerate its valid hex framing.
        decoded = matrix.native_output(raw, 3)["output"].encode()
        for old, new in ((b"boot_rtt_ms=12", b"boot_rtt_ms=2000"),
                         (b"auth=none", b"auth=trusted"), (b"denied=1", b"denied=0"),
                         (b"nic=0", b"nic=1"), (b"5s attempt", b"6s attempt")):
            with self.subTest(field=old), self.assertRaises(AssertionError):
                matrix.native_output(serial(decoded.replace(old, new)), 3)

    def test_fallible_rtc_remains_unknown_and_normal_exit_is_required(self):
        decoded = matrix.native_output(serial(), 3)["output"].encode()
        decoded = decoded.replace(f"rtc_unix={SECONDS - 5}".encode(), b"rtc_unix=unavailable(-5)")
        decoded = decoded.replace(b"unauthenticated_difference=5s", b"unauthenticated_difference=unknown")
        self.assertEqual(matrix.native_output(serial(decoded), 3)["rtc"], "unavailable(-5)")
        with self.assertRaisesRegex(AssertionError, "QEMU exit"):
            matrix.native_output(serial(decoded), 1)


if __name__ == "__main__":
    unittest.main()
