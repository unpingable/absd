#!/usr/bin/env python3
"""Host controls for link-matrix.py's fault-reset successor oracle and its
case-count verdict. The serial logs here are synthetic: they are parser
controls, not guest evidence."""

import importlib.util
import inspect
import pathlib
import tempfile
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("link_matrix", HERE / "link-matrix.py")
link = importlib.util.module_from_spec(spec)
spec.loader.exec_module(link)


def chunk(text):
    return f"EXTERNAL OUTPUT CHUNK offset=0 data={text.encode().hex()}\n"


REFUSED_WORKER = link.NO_SERVER + "\n"
REFUSED = ("ABSD KERNEL BOOT\n"
           "BLOCK BACKEND ata access=read-write\n"
           "STORAGE FENCE fence=none reason=not_declared\n"
           f"{link.WRITABLE_REFUSED}\n"
           + chunk(REFUSED_WORKER) +
           "SERVED RECOVERY REFUSED generation_not_ready\n"
           "init: FAILED at served worker\n"
           "DURABLE status=99 block_writes=0 block_flushes=0 block_errors=0 halt=failed\n")
# What the pre-fence fixture demanded: the successor serves, logs in, halts.
WRITABLE = ("ABSD KERNEL BOOT\n"
            "BLOCK BACKEND ata access=read-write\n"
            "STORAGE FENCE fence=none reason=not_declared\n"
            "FSD RECOVERY seq=2 previous=failed streak=1\n"
            "FSD READY channels=2\n"
            + chunk("SSH RECOVERY previous=failed streak=1\nSSH HOST KEY LOADED ssh-ed25519 AAAA SHA256:x\n"
                    "SSH NET link=up disabled=0 rx_missed=0 link_errors=0\nSSH LISTENING port=22\n") +
            "FSD FINALIZED boot=00\n"
            "DURABLE status=0 block_writes=40 block_flushes=6 block_errors=0 halt=ok\n")


class SuccessorOracle(unittest.TestCase):
    def test_refusal_transcript_passes(self):
        self.assertEqual(link.successor_refusal(REFUSED.encode(), "7"), link.WRITABLE_REFUSED)
        self.assertEqual(link.successor_refusal(REFUSED.encode(), "7", armed=link.FIXTURE), link.WRITABLE_REFUSED)

    def test_writable_login_successor_fails(self):
        for status in ("3", "7"):
            with self.subTest(status=status), self.assertRaises(RuntimeError):
                link.successor_refusal(WRITABLE.encode(), status)
        # Refusal lines present but the boot still reached readiness.
        for extra in ("FSD READY channels=2\n", chunk(REFUSED_WORKER + "SSH LISTENING port=22\n"),
                      chunk(REFUSED_WORKER + "SSH HOST KEY LOADED ssh-ed25519 AAAA SHA256:x\n")):
            changed = REFUSED.replace(chunk(REFUSED_WORKER), "") + extra if "CHUNK" in extra else REFUSED + extra
            with self.subTest(extra=extra), self.assertRaises(RuntimeError):
                link.successor_refusal(changed.encode(), "7")

    def test_missing_refusal_line_fails(self):
        for removed in (link.WRITABLE_REFUSED + "\n", chunk(REFUSED_WORKER),
                        "SERVED RECOVERY REFUSED generation_not_ready\n",
                        "STORAGE FENCE fence=none reason=not_declared\n", "ABSD KERNEL BOOT\n",
                        "DURABLE status=99 block_writes=0 block_flushes=0 block_errors=0 halt=failed\n"):
            with self.subTest(removed=removed), self.assertRaises(RuntimeError):
                link.successor_refusal(REFUSED.replace(removed, "").encode(), "7")
        # A different refusal or a different sshd status is not this refusal.
        for old, new in ((link.WRITABLE_REFUSED, link.WRITABLE_REFUSED.replace("previous=failed", "previous=ended")),
                         (chunk(REFUSED_WORKER), chunk(REFUSED_WORKER.replace("status=-5", "status=-38")))):
            with self.subTest(new=new), self.assertRaises(RuntimeError):
                link.successor_refusal(REFUSED.replace(old, new).encode(), "7")

    def test_io_reset_status_and_fixture_controls_fail(self):
        for changed in (REFUSED.replace("block_writes=0", "block_writes=1"),
                        REFUSED.replace("block_flushes=0", "block_flushes=1"),
                        REFUSED + "MACHINE RECOVER RESET pid=1\n",
                        REFUSED + "SERVED RECOVERY RESET streak=1\n",
                        REFUSED + "ABSD KERNEL BOOT\n",
                        REFUSED + "NIC RING FAULT INJECTED kind=rx\n"):
            with self.subTest(changed=changed[-40:]), self.assertRaises(RuntimeError):
                link.successor_refusal(changed.encode(), "7")
        for status in ("0", "3", "83", "124", ""):
            with self.subTest(status=status), self.assertRaises(RuntimeError):
                link.successor_refusal(REFUSED.encode(), status)
        with self.assertRaises(RuntimeError):
            link.successor_refusal((REFUSED + link.FIXTURE + " mode=stuck kind=tctl\n").encode(), "7",
                                   armed=link.FIXTURE)


class RefusedAfterOneReset(unittest.TestCase):
    """The matrix tail end to end on the host: the real refused_cold_boot
    (image sha256 before and after) with only the QEMU boot replaced."""

    FIRST = ("SERVED RECOVERY BEGIN reason=served worker fault file_server_status=running\n"
             "SERVED RECOVERY RESET streak=1 durability=completed_sync_only\nMACHINE RECOVER RESET\n")

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.work = pathlib.Path(directory.name)
        self.image = self.work / "disk.img"
        self.image.write_bytes(b"fenced image")
        self.matrix = link.LinkMatrix.__new__(link.LinkMatrix)
        self.matrix.checks, self.matrix.passed = 0, []
        self.matrix.t = mock.Mock(image=self.image, work=self.work, proc=None)
        patcher = mock.patch.object(link, "host_rules")
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_tail(self, transcript, status="7", touch_image=False):
        def boot(target, backend, name, **kwargs):
            self.assertEqual((backend, kwargs.get("served"), kwargs.get("declaration")), ("ata", True, None))
            if touch_image:
                self.image.write_bytes(b"written")
            log = self.work / (name + ".serial.log")
            log.write_bytes(transcript.encode())
            return transcript.encode(), status, log
        with mock.patch.object(link.fence_guest, "cold_boot", side_effect=boot):
            self.matrix.refused_after_one_reset("disabled-nic", "0", self.FIRST)

    def test_refusal_passes(self):
        self.run_tail(REFUSED)
        self.assertEqual(self.image.read_bytes(), b"fenced image")

    def test_writable_login_fails(self):
        with self.assertRaises(link.sm.Failed):
            self.run_tail(WRITABLE, status="3")

    def test_missing_no_server_line_fails(self):
        with self.assertRaises(link.sm.Failed):
            self.run_tail(REFUSED.replace(chunk(REFUSED_WORKER), ""))

    def test_changed_image_fails(self):
        with self.assertRaises(link.sm.Failed):
            self.run_tail(REFUSED, touch_image=True)

    def test_finalized_first_boot_fails(self):
        with self.assertRaises(link.sm.Failed):
            with mock.patch.object(link.fence_guest, "cold_boot") as cold:
                self.matrix.refused_after_one_reset("disabled-nic", "0", self.FIRST + "FSD FINALIZED boot=00\n")
            cold.assert_not_called()


def first_budget_boot(fault=link.FAULT):
    return ("ABSD KERNEL BOOT\nNIC RING FAULT INJECTED kind=rx\n"
            "FSD RECOVERY seq=1 streak=0 previous=none\nFSD READY channels=2\n"
            + chunk("SSH RECOVERY streak=0\nSSH LISTENING port=22\n"
                    "SSH NET link=down disabled=1 rx_missed=0 link_errors=0\n" + fault + "\n") +
            "NIC DISABLED reason=rx-head-outside-ring\n"
            "SERVED RECOVERY BEGIN reason=served worker fault file_server_status=running\n"
            "SERVED RECOVERY RESET streak=1 durability=completed_sync_only\nMACHINE RECOVER RESET\n")


FIRST_BUDGET_BOOT = first_budget_boot()


class BudgetCase(unittest.TestCase):
    """disabled-nic-budget under the owner's decision (2026-10-19, #63):
    the first fault and reset, then the strict refusal in the same QEMU,
    a cold retry, and the UNSUPPORTED capability line."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.work = pathlib.Path(directory.name)
        self.image = self.work / "disk.img"
        self.image.write_bytes(b"fenced image")
        self.matrix = link.LinkMatrix.__new__(link.LinkMatrix)
        self.matrix.checks, self.matrix.passed = 0, []
        self.matrix.qmp = mock.Mock()
        self.matrix.boot = mock.Mock()
        for name in ("host_rules",):
            patcher = mock.patch.object(link, name)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_case(self, log_text, status="7", retry=REFUSED, touch_image=False):
        log = self.work / "sshd-001.serial.log"
        log.write_bytes(log_text.encode())
        self.matrix.t = mock.Mock(image=self.image, work=self.work, proc=None, log=log)
        self.matrix.t.status.return_value = status

        def boot(target, backend, name, **kwargs):
            self.assertEqual((backend, kwargs.get("served"), kwargs.get("declaration")), ("ata", True, None))
            if touch_image:
                self.image.write_bytes(b"written")
            retry_log = self.work / (name + ".serial.log")
            retry_log.write_bytes(retry.encode())
            return retry.encode(), "7", retry_log
        with mock.patch.object(link.fence_guest, "cold_boot", side_effect=boot), \
                mock.patch("builtins.print") as out:
            try:
                self.matrix.disabled_nic_budget()
            finally:
                self.text = "\n".join(" ".join(map(str, c.args)) for c in out.call_args_list)

    def test_refusal_passes_and_prints_unsupported_not_as_a_pass(self):
        self.run_case(FIRST_BUDGET_BOOT + REFUSED)
        self.assertEqual(self.matrix.passed, ["DISABLED NIC BUDGET SUCCESSOR REFUSED OK resets=1 status=7 "
                                              "block_writes=0 block_flushes=0 image_unchanged=true"])
        unsupported = [l for l in self.text.splitlines() if l.startswith(link.UNSUPPORTED)]
        self.assertEqual(len(unsupported), 1)
        self.assertNotIn("OK", unsupported[0].split())
        self.assertIn("AUTOMATIC WRITABLE RECOVERY UNSUPPORTED (owner 2026-10-19; #63: operator act only) case=disabled-nic-budget", unsupported[0])
        self.assertFalse(any(link.UNSUPPORTED in mark for mark in self.matrix.passed))
        self.assertEqual(self.image.read_bytes(), b"fenced image")

    def test_writable_successor_fails(self):
        for status in ("3", "7"):
            with self.subTest(status=status), self.assertRaises(link.sm.Failed):
                self.run_case(FIRST_BUDGET_BOOT + WRITABLE, status)

    def test_write_or_flush_fails(self):
        for field in ("block_writes", "block_flushes"):
            with self.subTest(field=field), self.assertRaises(link.sm.Failed):
                self.run_case(FIRST_BUDGET_BOOT + REFUSED.replace(f"{field}=0", f"{field}=1"))
        with self.assertRaises(link.sm.Failed):
            self.run_case(FIRST_BUDGET_BOOT + REFUSED, retry=REFUSED.replace("block_writes=0", "block_writes=1"))

    def test_image_change_fails(self):
        with self.assertRaises(link.sm.Failed):
            self.run_case(FIRST_BUDGET_BOOT + REFUSED, touch_image=True)

    def test_missing_refusal_line_fails(self):
        for removed in (link.WRITABLE_REFUSED + "\n", chunk(REFUSED_WORKER),
                        "SERVED RECOVERY REFUSED generation_not_ready\n"):
            with self.subTest(removed=removed), self.assertRaises(link.sm.Failed):
                self.run_case(FIRST_BUDGET_BOOT + REFUSED.replace(removed, ""))

    def test_second_reset_fails(self):
        with self.assertRaises(link.sm.Failed):   # the old countdown: a third boot
            self.run_case(FIRST_BUDGET_BOOT + FIRST_BUDGET_BOOT.replace("streak=0", "streak=1") + REFUSED)
        with self.assertRaises(link.sm.Failed):   # a reset printed by the refused boot
            self.run_case(FIRST_BUDGET_BOOT + REFUSED + "MACHINE RECOVER RESET\n")

    def test_first_boot_controls_kept(self):
        for first in (FIRST_BUDGET_BOOT.replace("SERVED RECOVERY RESET ", "SERVED RECOVERY ESCALATED "),
                      first_budget_boot("other fault"),
                      FIRST_BUDGET_BOOT + "FSD FINALIZED boot=00\n"):
            with self.subTest(first=first[-60:]), self.assertRaises((link.sm.Failed, RuntimeError, ValueError)):
                self.run_case(first + REFUSED)


class CaseCount(unittest.TestCase):
    def test_no_pending_owner_case_remains(self):
        self.assertIn("disabled-nic-budget", link.CASES)
        self.assertFalse(hasattr(link, "PENDING_OWNER"))
        source = inspect.getsource(link)
        self.assertNotIn("NOT_RUN_PENDING_OWNER", source)
        self.assertNotIn("BUDGET_STOP_STATUS", inspect.getsource(link.LinkMatrix.disabled_nic_budget))

    def test_complete_run_is_ok_and_unsupported_is_never_counted(self):
        line = f"{link.UNSUPPORTED} case=disabled-nic-budget budget=3 countdown=not_exercisable"
        marks = [f"MARK {c}" for c in link.CASES]
        with mock.patch("builtins.print") as out:
            self.assertEqual(link.verdict(link.CASES, list(link.CASES), marks, 99, (line,)), 0)
        printed = [" ".join(map(str, c.args)) for c in out.call_args_list]
        self.assertEqual(printed, [line, "LINK MATRIX OK checks=99 cases=9"])
        # An UNSUPPORTED line cannot stand in for a case's mark, even when
        # the count matches, and marks must be distinct.
        with mock.patch("builtins.print"):
            self.assertEqual(link.verdict(link.CASES, list(link.CASES), marks[:-1] + [line], 99, (line,)), 1)
            self.assertEqual(link.verdict(link.CASES, list(link.CASES), marks[:-1] + [link.UNSUPPORTED], 99, ()), 1)
            self.assertEqual(link.verdict(link.CASES, list(link.CASES), marks[:-1], 99, (line,)), 1)
            self.assertEqual(link.verdict(link.CASES, list(link.CASES), marks[:-1] + [marks[0]], 99, (line,)), 1)
            self.assertEqual(link.verdict(link.CASES, list(link.CASES)[::-1], marks, 99, (line,)), 1)

    def test_miscount_fails(self):
        with mock.patch("builtins.print"):
            self.assertEqual(link.verdict(("disabled-nic",), ["disabled-nic"], ["MARK"], 5), 0)
            self.assertEqual(link.verdict(("disabled-nic",), ["disabled-nic", "disabled-nic"], ["MARK", "MARK2"], 5), 1)
            self.assertEqual(link.verdict(("disabled-nic",), ["disabled-nic"], [], 5), 1)
            self.assertEqual(link.verdict(("disabled-nic", "flaps"), ["disabled-nic"], ["MARK"], 5), 1)

if __name__ == "__main__":
    unittest.main()
