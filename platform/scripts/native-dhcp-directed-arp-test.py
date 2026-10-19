#!/usr/bin/env python3
"""Exact Linux neighbor-request envelope controls; no native verdict rewrite."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("directed_arp_case", Path(__file__).with_name("native-dhcp-directed-arp-matrix.py"))
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def request(destination=None, sender=None):
    return ((destination or a.GUEST_MAC) + a.HOST_MAC + b"\x08\x06"
            + bytes([0, 1, 8, 0, 6, 4, 0, 1]) + a.HOST_MAC
            + (a.HOST if sender is None else sender) + b"\0" * 6 + a.GUEST)


class LinuxNeighborEnvelope(unittest.TestCase):
    def test_directed_and_broadcast_exact_peer(self):
        for destination in (a.GUEST_MAC, b"\xff" * 6):
            for sender in (a.HOST, b"\0" * 4):
                self.assertTrue(a.linux_arp_request(request(destination, sender)))

    def test_identity_tuple_operation_and_target_substitutions_refuse(self):
        changes = [(0, b"\x52\x54\0\0\0\x99"), (6, a.GUEST_MAC),
                   (12, b"\x86\xdd"), (14, b"\0\x02"), (20, b"\0\x02"),
                   (22, a.GUEST_MAC), (28, bytes([192, 0, 2, 2])),
                   (32, a.GUEST_MAC), (38, a.HOST)]
        original = request()
        for offset, value in changes:
            with self.subTest(offset=offset):
                changed = original[:offset] + value + original[offset + len(value):]
                self.assertFalse(a.linux_arp_request(changed))

    def test_truncated_neighbor_request_refuses(self):
        original = request()
        for size in range(len(original)):
            self.assertFalse(a.linux_arp_request(original[:size]))


if __name__ == "__main__":
    unittest.main()
