#!/usr/bin/env python3
import pathlib
import unittest
import storage_fence_state as guard


class WritableGuardState(unittest.TestCase):
    def test_shared_golden_sectors(self):
        root = pathlib.Path(__file__).resolve().parents[1] / "fixtures/storage-fence"
        for state in ("fresh", "dirty", "clean"):
            golden = (root / f"guard-v1-{state}.bin").read_bytes()
            self.assertEqual(guard.encode(state), golden)
            self.assertEqual(guard.parse(golden), state)

    def test_incomplete_unknown_and_changed_records_refuse(self):
        for data in (b"", b"\0" * 512, guard.FRESH[:-1], guard.FRESH + b"\0",
                     guard.FRESH.replace(b"v1", b"v2")):
            self.assertIsNone(guard.parse(data))
        for index in range(512):
            changed = bytearray(guard.FRESH)
            changed[index] ^= 1
            self.assertIsNone(guard.parse(bytes(changed)))

    def test_seed_is_exact_one_sector_at_the_private_path(self):
        self.assertEqual(guard.fresh_files(), [("/var/recovery.guard", guard.FRESH),
                                               ("/var/recovery.resume", guard.RESUME_NONE)])
        self.assertEqual(len(guard.FRESH), 512)
        self.assertEqual(len(guard.RESUME_NONE), 512)
        with self.assertRaises(ValueError):
            guard.encode("external")

    def test_resume_slot_matches_shared_golden_sectors_and_refuses_torn_records(self):
        root = pathlib.Path(__file__).resolve().parents[1] / "fixtures/storage-fence"
        record = {"id": "00112233445566778899aabbccddeeff", "fs": 7, "seq": 11,
                  "image": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                  "ledger_seq": 7, "ledger_boot": "0123456789abcdef0123456789abcdef",
                  "previous": "failed", "time": 1761100000}
        golden = (root / "resume-v1-record.bin").read_bytes()
        self.assertEqual(guard.encode_resume(record), golden)
        self.assertEqual(guard.parse_resume(golden), record)
        self.assertEqual(guard.encode_resume("none"), (root / "resume-v1-none.bin").read_bytes())
        self.assertEqual(guard.parse_resume(guard.RESUME_NONE), "none")
        self.assertEqual(golden[:15], guard.RESUME_PREFIX)
        self.assertEqual((golden[15], guard.RESUME_NONE[15]), (ord("i"), ord("n")))
        for name in ("resume-v1-torn-40.bin", "resume-v1-torn-200.bin"):
            self.assertIsNone(guard.parse_resume((root / name).read_bytes()), name)
        for data in (b"", bytes(512), golden[:-1], golden + b"\0", golden.replace(b"v1", b"v2", 1),
                     golden.replace(b"previous=failed", b"previous=ended "),
                     guard.RESUME_NONE[:-1] + b"x"):
            self.assertIsNone(guard.parse_resume(data))
        for index in range(512):
            changed = bytearray(golden)
            changed[index] ^= 1
            self.assertIsNone(guard.parse_resume(bytes(changed)), index)
        for previous in guard.RESUME_PREVIOUS:
            other = dict(record, previous=previous, seq=(1 << 64) - 1, time=0)
            self.assertEqual(guard.parse_resume(guard.encode_resume(other)), other)
        with self.assertRaises(ValueError):
            guard.encode_resume(dict(record, previous="ended"))
        with self.assertRaises(ValueError):
            guard.encode_resume(dict(record, id="short"))
        with self.assertRaises(ValueError):
            guard.encode_resume("dirty")


if __name__ == "__main__":
    unittest.main()
