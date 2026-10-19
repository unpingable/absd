#!/usr/bin/env python3
"""Pure artifact controls for the separate server proof. No sockets or guest.

Authored source only until the resource owner executes this exact file.
"""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location("server_matrix", Path(__file__).with_name("native-tcp-server-matrix.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def tcp(outgoing, seq, ack, flags, body=b"", port=42030, mss=1460):
    source, target = (m.GUEST, m.HOST) if outgoing else (m.HOST, m.GUEST)
    srcmac, dstmac = (m.GUEST_MAC, m.HOST_MAC) if outgoing else (m.HOST_MAC, m.GUEST_MAC)
    options = struct.pack("!BBH", 2, 4, mss) if flags & 2 else b""
    ports = (7005, port) if outgoing else (port, 7005)
    segment = bytearray(struct.pack("!HHIIBBHHH", *ports, seq, ack, (5 + len(options) // 4) << 4, flags, 8192, 0, 0) + options + body)
    segment[16:18] = struct.pack("!H", m.boot.checksum(source + target + struct.pack("!BBH", 0, 6, len(segment)) + segment))
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0, 0x4000, 64, 6, 0, source, target))
    ip[10:12] = struct.pack("!H", m.boot.checksum(ip))
    return dstmac + srcmac + b"\x08\0" + ip + segment


def baseline():
    header = b"\0\x01\x08\0\x06\x04"
    request = b"\xff" * 6 + m.HOST_MAC + b"\x08\x06" + header + b"\0\x01" + m.HOST_MAC + m.HOST + b"\0" * 6 + m.GUEST
    reply = m.HOST_MAC + m.GUEST_MAC + b"\x08\x06" + header + b"\0\x02" + m.GUEST_MAC + m.GUEST + m.HOST_MAC + m.HOST
    rows = [request, reply, tcp(False, 8000, 0, 2, port=42031), tcp(False, 1000, 0, 2),
            tcp(True, 4000, 1001, 18), tcp(False, 1001, 4001, 16)]
    for at in range(0, 3072, 1024):
        rows.append(tcp(False, 1001 + at, 4001, 24, m.DATA[at:at + 1024]))
    rows += [tcp(False, 4073, 4001, 17), tcp(True, 4001, 4074, 16)]
    for at in range(0, 3072, 511):
        rows.append(tcp(True, 4001 + at, 4074, 24, m.DATA[at:at + 511]))
    rows += [tcp(True, 7073, 4074, 17), tcp(False, 4074, 7074, 16)]
    return rows


def pcap(rows):
    data = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    for i, frame in enumerate(rows):
        data += struct.pack("<IIII", 1, i, len(frame), len(frame)) + frame
    return data


def serial():
    output = (b"TCP SERVER GRANT READY local=192.0.2.100:7005 peer=192.0.2.1:42030 lifetime_ms=10000\n" +
              m.READY + b"TCP SERVER ECHO PASS bytes=3072 denied=1 nic=0\nTCP SERVER DONE child=exited sockets=0\n")
    return (b"\nABSD BOOT OK\nNETWORK LINK OK x\n" +
            b"EXTERNAL OUTPUT CHUNK offset=0000000000000000 data=" + output.hex().encode() + b"\n" +
            b"NIC STATS rx_frames=20 tx_frames=20 rx_refused=0 rx_missed=0 tx_refused=0 tx_errors=0\n" +
            b"DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 x\nDURABLE WORKLOAD OK\n")


class ArtifactControls(unittest.TestCase):
    def refusal(self, rows):
        with self.assertRaises(AssertionError):
            m.inspect_capture(pcap(rows))

    def test_complete_partial_echo_has_exact_census(self):
        rows = baseline(); result = m.inspect_capture(pcap(rows))
        self.assertEqual(result["frames"], len(rows))
        self.assertEqual(result["wrong_port_syns"], [2])
        self.assertGreater(result["segments"]["guest"], 2)

    def test_literal_native_smoltcp_arp_and_directional_substitutions(self):
        # Sealed DHCP467 frame 12, same pinned Stack producer and IPs.
        # The request contains no peer MAC, so the literal is unchanged.
        literal = bytes.fromhex(
            "ffffffffffff52540012345608060001080006040001525400123456c0000264"
            "ffffffffffffc0000201000000000000000000000000000000000000")
        self.assertEqual(m.digest(literal)["sha256"],
                         "161373db3a1188391be4fa2f50c61e581f527a762a8941469636cc3515df9e2f")
        rows = baseline() + [literal]
        self.assertEqual(m.inspect_capture(pcap(rows))["census"][-1]["kind"], "peer-arp")
        for at, value in ((32, b"\0" * 6), (0, m.HOST_MAC)):
            substituted = literal[:at] + value + literal[at + 6:]
            self.refusal(baseline() + [substituted])
        rows = baseline()
        rows[0] = m.GUEST_MAC + rows[0][6:]  # Linux may probe known neighbor directly.
        self.assertEqual(m.inspect_capture(pcap(rows))["frames"], len(rows))
        for at, value in ((32, b"\xff" * 6), (0, m.HOST_MAC)):
            rows = baseline()
            rows[0] = rows[0][:at] + value + rows[0][at + 6:]
            self.refusal(rows)

    def test_missing_or_late_wrong_port_probe(self):
        rows = baseline(); self.refusal(rows[:2] + rows[3:])
        rows[2], rows[3] = rows[3], rows[2]; self.refusal(rows)

    def test_wrong_port_response_cannot_be_explained(self):
        rows = baseline(); rows.insert(3, tcp(True, 9000, 8001, 18, port=42031)); self.refusal(rows)

    def test_third_tuple_and_address_cannot_be_explained(self):
        rows = baseline(); rows[6] = tcp(False, 1001, 4001, 24, m.DATA[:1024], port=42032); self.refusal(rows)
        rows = baseline(); bad = bytearray(rows[6]); bad[26] ^= 1; rows[6] = bytes(bad); self.refusal(rows)

    def test_checksum_and_truncated_capture_are_refused(self):
        rows = baseline(); bad = bytearray(rows[6]); bad[-1] ^= 1; rows[6] = bytes(bad); self.refusal(rows)
        with self.assertRaises(AssertionError):
            m.inspect_capture(pcap(baseline())[:-1])

    def test_valid_checksum_changed_application_bytes_are_refused(self):
        rows = baseline(); rows[6] = tcp(False, 1001, 4001, 24, b"x" * 1024); self.refusal(rows)

    def test_unseen_data_ack_and_sequence_gap_are_refused(self):
        rows = baseline(); rows[5] = tcp(False, 1001, 7074, 16); self.refusal(rows)
        rows = baseline(); del rows[6]; self.refusal(rows)

    def test_half_close_fin_and_ack_are_required(self):
        rows = baseline(); del rows[-2]; self.refusal(rows)
        self.refusal(baseline()[:-1])
        rows = baseline(); rows[9] = tcp(False, 4072, 4001, 17); self.refusal(rows)

    def test_mss_reset_and_unrelated_ethernet_are_refused(self):
        rows = baseline(); rows[4] = tcp(True, 4000, 1001, 18, mss=1200); self.refusal(rows)
        rows = baseline(); rows[5] = tcp(False, 1001, 4001, 20); self.refusal(rows)
        rows = baseline(); rows.append(b"\xff" * 60); self.refusal(rows)

    def test_real_newline_native_output_positive(self):
        self.assertEqual(m.native_output(serial(), 3)["NIC_counters"]["rx_refused"], "0")

    def test_native_counters_exit_and_missing_child_marker_are_refused(self):
        for key in (b"rx_refused", b"rx_missed", b"tx_refused", b"tx_errors"):
            with self.subTest(key=key), self.assertRaises(AssertionError):
                m.native_output(serial().replace(key + b"=0", key + b"=1"), 3)
        with self.assertRaises(AssertionError):
            m.native_output(serial(), 1)
        with self.assertRaises(AssertionError):
            m.native_output(serial().replace(b"EXTERNAL OUTPUT CHUNK", b"REMOVED OUTPUT CHUNK"), 3)

    def test_exact_embed_and_build_source_substitutions(self):
        child = b"\x7fELFchild"; parent = b"\x7fELFparent" + child; kernel = b"\x7fELFkernel" + parent
        receipt = {"schema": "absd-native-tcp-server-build/1", "platform": {"revision": m.PRODUCT, "tree": m.PRODUCT_TREE, "clean": True,
                       "archive": {"bytes": 1, "sha256": m.PRODUCT_ARCHIVE}},
                   "kernel": {"revision": m.KERNEL, "tree": m.KERNEL_TREE, "clean": True,
                       "archive": {"bytes": 1, "sha256": m.KERNEL_ARCHIVE}},
                   "commands": [["sh", "scripts/build-native-tcp-server.sh"], ["make", "EXTERNAL_USER_ELF=parent.elf"]],
                   "logs": [m.digest(b"build log")], "toolchain_receipt": m.digest(b"pinned toolchain"),
                   "outputs": {name: m.digest(data) for name, data in (("child", child), ("parent", parent), ("kernel", kernel))}}
        m.build_binding(receipt, child, parent, kernel)
        for key in ("platform", "kernel"):
            bad = copy.deepcopy(receipt); bad[key]["revision"] = "0" * 40
            with self.assertRaises(AssertionError):
                m.build_binding(bad, child, parent, kernel)
            bad = copy.deepcopy(receipt); bad[key]["archive"]["sha256"] = "0" * 64
            with self.assertRaises(AssertionError):
                m.build_binding(bad, child, parent, kernel)
        with self.assertRaises(AssertionError):
            m.build_binding(receipt, child + b"changed", parent, kernel)
        bad = copy.deepcopy(receipt); bad["outputs"]["parent"] = m.digest(parent + child)
        bad["outputs"]["kernel"] = m.digest(b"\x7fELF" + parent + child)
        with self.assertRaises(AssertionError):
            m.build_binding(bad, child, parent + child, b"\x7fELF" + parent + child)

    def test_peer_result_eof_tuple_and_digest_are_required(self):
        wrong = {"disposition": "PASS", "local": ["192.0.2.1", 42031], "peer": ["192.0.2.100", 7005], "result": "connect-timeout", "sent_bytes": 0}
        peer = {"disposition": "PASS", "local": ["192.0.2.1", 42030], "peer": ["192.0.2.100", 7005], "bytes": 3072,
                "sha256": m.digest(m.DATA)["sha256"], "write_half_closed": True, "read_EOF": True}
        m.peer_results(wrong, peer)
        for key, value in (("read_EOF", False), ("sha256", "0" * 64), ("local", ["192.0.2.1", 42031])):
            bad = copy.deepcopy(peer); bad[key] = value
            with self.assertRaises(AssertionError):
                m.peer_results(wrong, bad)


if __name__ == "__main__":
    unittest.main()
