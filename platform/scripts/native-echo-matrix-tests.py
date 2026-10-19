#!/usr/bin/env python3
"""Artifact controls only; execute later on the resource owner's VM."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("echo_matrix", Path(__file__).with_name("native-echo-matrix.py"))
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)
IDENTIFIER, SEQUENCE = 0x1234, 0x5678
INSTANCE, EPOCH, NONCE = 0x0102030405060708, 0x1112131415161718, 0x2122232425262728


def wire_checksum(data):
    # Independent byte-pair writer, with a literal packet checksum oracle below.
    total = 0
    for at in range(0, len(data), 2):
        total += (data[at] << 8) + (data[at + 1] if at + 1 < len(data) else 0)
        total = (total & 65535) + (total >> 16)
    return 65535 ^ total


def icmp(outgoing):
    data = bytearray(40)
    data[0] = 8 if outgoing else 0
    data[4:8] = struct.pack("!HH", IDENTIFIER, SEQUENCE)
    data[8:16] = b"ABSDPING"
    data[16:] = struct.pack("!QQQ", INSTANCE, EPOCH, NONCE)
    return bytes(data)


def ipv4(packet, outgoing, source=None):
    source_ip, target = (matrix.GUEST, matrix.HOST) if outgoing else (matrix.HOST, matrix.GUEST)
    if source is not None:
        source_ip = source
    packet = packet[:2] + struct.pack("!H", wire_checksum(packet[:2] + b"\0\0" + packet[4:])) + packet[4:]
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(packet), 1, 0x4000, 64, 1, 0, source_ip, target)
    header = header[:10] + struct.pack("!H", wire_checksum(header)) + header[12:]
    macs = (matrix.HOST_MAC + matrix.GUEST_MAC) if outgoing else (matrix.GUEST_MAC + matrix.HOST_MAC)
    return macs + b"\x08\x00" + header + packet


def arp(operation, outgoing, directed=False):
    source_mac, peer_mac = (matrix.GUEST_MAC, matrix.HOST_MAC) if outgoing else (matrix.HOST_MAC, matrix.GUEST_MAC)
    source, target = (matrix.GUEST, matrix.HOST) if outgoing else (matrix.HOST, matrix.GUEST)
    destination = peer_mac if operation == 2 or directed else b"\xff" * 6
    target_mac = peer_mac if operation == 2 else bytes(6)
    return destination + source_mac + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x0800, 6, 4, operation) + source_mac + source + target_mac + target


def frames():
    return [arp(1, True), arp(2, False), ipv4(icmp(True), True), ipv4(icmp(False), False)]


def capture(packets):
    data = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65536, 1)
    for index, packet in enumerate(packets):
        data += struct.pack("<IIII", 1, index, len(packet), len(packet)) + packet
    return data


def serial(output=None):
    if output is None:
        output = (f"PING peer=192.0.2.1 identifier={IDENTIFIER} sequence={SEQUENCE} instance={INSTANCE} "
                  f"epoch={EPOCH} nonce={NONCE:016x} boot_rtt_ms=9 auth=none denied=1 nic=0 requests=1\n"
                  "PING DONE child=exited sockets=0 requests=1\n").encode()
    return (b"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 \nDURABLE WORKLOAD OK\n"
            b"ABSD BOOT OK\nNETWORK LINK OK fixture\n"
            b"EXTERNAL OUTPUT CHUNK offset=0000000000000000 data=" + output.hex().encode() + b"\n"
            b"NIC STATS rx_frames=2 tx_frames=2 rx_refused=0 rx_missed=0 tx_refused=0 tx_errors=0\n")


class ArtifactPredicates(unittest.TestCase):
    def inspect(self, packets, observation=None, raw=None):
        if observation is None:
            observation = matrix.native_output(serial(), 3)
        with tempfile.TemporaryDirectory(prefix="absd-echo-artifact-") as temporary:
            path = Path(temporary) / "fixture.pcap"
            path.write_bytes(capture(packets) if raw is None else raw)
            return matrix.inspect(path, observation)

    def test_complete_valid_request_reply_and_native_correlation(self):
        result = self.inspect(frames())
        self.assertEqual(result["request"]["hex"], "08006b3f123456784142534450494e47010203040506070811121314151617182122232425262728")
        self.assertEqual(result["reply"]["hex"], "0000733f123456784142534450494e47010203040506070811121314151617182122232425262728")
        self.assertEqual(result["request"]["nonce"], NONCE)
        self.assertEqual(result["reply"]["index"], 3)

    def test_exact_directed_linux_neighbor_request_is_admitted(self):
        packets = frames() + [arp(1, False, True), arp(2, True)]
        self.assertEqual(len(self.inspect(packets)["ARP"]), 4)

    def test_wrong_identifier_sequence_instance_epoch_nonce_with_valid_checksums_refuse(self):
        for at in (4, 6, 16, 24, 32):
            with self.subTest(offset=at):
                packet = bytearray(icmp(False))
                packet[at] ^= 1
                packets = frames()
                packets[-1] = ipv4(bytes(packet), False)
                with self.assertRaisesRegex(AssertionError, "correlation"):
                    self.inspect(packets)

    def test_wrong_source_with_valid_checksums_refuses(self):
        packets = frames()
        packets[-1] = ipv4(icmp(False), False, bytes([192, 0, 2, 2]))
        with self.assertRaisesRegex(AssertionError, "protocol/peer"):
            self.inspect(packets)

    def test_type_code_body_and_length_mutations_with_valid_checksums_refuse(self):
        for mutation in ("type", "code", "body", "short", "long"):
            with self.subTest(mutation=mutation):
                packet = bytearray(icmp(False))
                if mutation == "type":
                    packet[0] = 8
                elif mutation == "code":
                    packet[1] = 1
                elif mutation == "body":
                    packet[8] ^= 1
                elif mutation == "short":
                    packet.pop()
                else:
                    packet.append(0)
                packets = frames()
                packets[-1] = ipv4(bytes(packet), False)
                with self.assertRaises(AssertionError):
                    self.inspect(packets)

    def test_corrupt_wire_checksum_refuses_instead_of_normalizing(self):
        packets = frames()
        broken = bytearray(packets[-1])
        broken[-1] ^= 1
        packets[-1] = bytes(broken)
        with self.assertRaisesRegex(AssertionError, "checksum"):
            self.inspect(packets)

    def test_duplicate_request_reply_and_wrong_order_refuse(self):
        for packets in (frames() + [frames()[-1]], frames()[:3] + frames()[2:], frames()[:2] + list(reversed(frames()[2:]))):
            with self.subTest(order=len(packets)), self.assertRaises(AssertionError):
                self.inspect(packets)

    def test_native_nonce_must_name_the_actual_captured_packet(self):
        observation = matrix.native_output(serial(), 3)
        observation["nonce"] += 1
        with self.assertRaisesRegex(AssertionError, "correlation"):
            self.inspect(frames(), observation)

    def test_unrelated_ethernet_and_incomplete_capture_refuse(self):
        packets = frames()
        packets.append(b"\xff" * 60)
        with self.assertRaises(AssertionError):
            self.inspect(packets)
        with self.assertRaisesRegex(AssertionError, "capture record"):
            self.inspect([], raw=capture(frames())[:-1])

    def test_native_authority_deadline_and_exit_markers_are_strict(self):
        decoded = matrix.native_output(serial(), 3)["output"].encode()
        for old, new in ((b"boot_rtt_ms=9", b"boot_rtt_ms=8000"), (b"auth=none", b"auth=trusted"),
                         (b"denied=1", b"denied=0"), (b"nic=0", b"nic=1"),
                         (b"child=exited", b"child=unknown"), (b"sockets=0", b"sockets=1")):
            with self.subTest(field=old), self.assertRaises(AssertionError):
                matrix.native_output(serial(decoded.replace(old, new)), 3)
        with self.assertRaisesRegex(AssertionError, "QEMU exit"):
            matrix.native_output(serial(), 1)


if __name__ == "__main__":
    unittest.main()
