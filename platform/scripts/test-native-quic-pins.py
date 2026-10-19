#!/usr/bin/env python3
"""Finite pin/lock substitution controls; execute on the isolated VM."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("quic_pin_check", HERE / "check-native-quic-pins.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class PinControls(unittest.TestCase):
    def setUp(self):
        self.data = list(copy.deepcopy(check.inputs(HERE.parent)))

    def test_real_declared_pins_and_path_patched_ring_agree(self):
        result = check.verify(*self.data)
        self.assertEqual(len(result["checked_registry_packages"]), 49)
        self.assertEqual(len(result["path_patched_packages"]), 1)
        self.assertEqual(len(result["lock_only_registry_packages"]), 27)

    def test_changed_registry_checksum_refuses(self):
        self.data[0]["packages"][0]["archive_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "checksum differs"):
            check.verify(*self.data)

    def test_missing_locked_pin_refuses(self):
        row = self.data[0]["packages"][0]
        self.data[1]["package"] = [p for p in self.data[1]["package"] if (p["name"], p["version"]) != (row["name"], row["version"])]
        with self.assertRaisesRegex(ValueError, "absent from lock"):
            check.verify(*self.data)

    def test_duplicate_pin_refuses(self):
        self.data[0]["packages"].append(copy.deepcopy(self.data[0]["packages"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate PIN"):
            check.verify(*self.data)

    def test_ring_registry_substitution_refuses(self):
        ring = next(p for p in self.data[1]["package"] if p["name"] == "ring")
        ring.update(source=check.REGISTRY, checksum="0" * 64)
        with self.assertRaisesRegex(ValueError, "path patched"):
            check.verify(*self.data)

    def test_ring_patch_mutation_refuses(self):
        name = next(iter(self.data[4]))
        self.data[4][name] = "0" * 64
        with self.assertRaisesRegex(ValueError, "ring patches differ"):
            check.verify(*self.data)

    def test_ring_tls_archive_disagreement_refuses(self):
        next(p for p in self.data[3]["packages"] if p["name"] == "ring")["checksum"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "admitted TLS pin"):
            check.verify(*self.data)

    def test_changed_direct_dependency_refuses(self):
        self.data[2]["dependencies"]["quinn-proto"]["version"] = "=0.11.18"
        with self.assertRaisesRegex(ValueError, "exact declared pin"):
            check.verify(*self.data)


if __name__ == "__main__":
    unittest.main()
