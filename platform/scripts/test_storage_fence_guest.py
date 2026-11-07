#!/usr/bin/env python3
"""Refusal-oracle controls only; these synthetic logs are not guest evidence."""
import unittest
import storage_fence_guest as guest


GOOD = ("ABSD KERNEL BOOT\n"
        "STORAGE FENCE fence=none reason=not_declared\n"
        "RECOVERY WRITABLE REFUSED reason=storage_fence previous=failed fence=none\n"
        "DURABLE status=99 block_writes=0 block_flushes=0 block_errors=0 halt=failed\n")


class RefusalOracle(unittest.TestCase):
    def test_complete_named_zero_io_refusal(self):
        self.assertIn("previous=failed", guest.require_refusal(GOOD.encode(), "7"))

    def test_each_missing_or_inconsistent_record_refuses_a_pass(self):
        for changed in (GOOD.replace("ABSD KERNEL BOOT\n", ""),
                        GOOD + "ABSD KERNEL BOOT\n", GOOD + GOOD.splitlines()[-1] + "\n",
                        GOOD.replace("reason=not_declared", "reason=external_unverified"),
                        GOOD.replace("RECOVERY WRITABLE REFUSED", "unrelated error"),
                        GOOD.replace("block_writes=0", "block_writes=1"),
                        GOOD.replace("block_flushes=0", "block_flushes=1"),
                        GOOD.replace("block_errors=0", "block_errors=1"),
                        GOOD + "FSD READY channels=2\n", GOOD + "SSH LISTENING port=22\n",
                        GOOD + "MACHINE RECOVER RESET pid=1\n"):
            with self.subTest(changed=changed):
                with self.assertRaises(RuntimeError):
                    guest.require_refusal(changed.encode(), "7")
        for status in ("0", "3", "124", ""):
            with self.subTest(status=status), self.assertRaises(RuntimeError):
                guest.require_refusal(GOOD.encode(), status)

    def test_changed_image_refusal_needs_named_read_only_corruption(self):
        changed = GOOD.replace("RECOVERY WRITABLE REFUSED reason=storage_fence previous=failed fence=none",
                               'FSD FAILED read-only mount: Corrupt("image digest")')
        with self.assertRaises(RuntimeError):
            guest.require_refusal(changed.encode(), "7")
        self.assertIn("read-only mount", guest.require_refusal(changed.encode(), "7", allow_corrupt=True))
        with self.assertRaises(RuntimeError):
            guest.require_refusal(changed.replace("read-only mount:", "unexpected startup:").encode(),
                                  "7", allow_corrupt=True)


if __name__ == "__main__":
    unittest.main()
