#!/usr/bin/env python3
"""Host controls for survival-recovery.py under the owner's storage fence:
the successor refusal predicates (same-QEMU and cold), the follow-on cases'
use of them, and the honest count for the pending fault loop. The serial
logs here are synthetic: parser controls, not guest evidence."""

import importlib.util
import inspect
import pathlib
import tempfile
import types
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("survival_recovery", HERE / "survival-recovery.py")
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)
guest = sr.fence_guest


def chunk(text):
    return f"EXTERNAL OUTPUT CHUNK offset=0 data={text.encode().hex()}\n"


FIRST = ("ABSD KERNEL BOOT\nSTORAGE FENCE fence=none reason=not_declared\nFSD RECOVERY seq=1 streak=0 previous=none\n"
         "FSD READY channels=2\n" + chunk("SSH RECOVERY streak=0\nSSH LISTENING port=22\n") +
         "SERVED RECOVERY BEGIN reason=served worker fault file_server_status=running\n"
         "SERVED RECOVERY RESET streak=1 durability=completed_sync_only\nMACHINE RECOVER RESET pid=1\n")
REFUSED = ("ABSD KERNEL BOOT\nSTORAGE FENCE fence=none reason=not_declared\n"
           f"{guest.WRITABLE_REFUSED}\n" + chunk(guest.NO_SERVER + "\n") +
           "SERVED RECOVERY REFUSED generation_not_ready\ninit: FAILED at served worker\n"
           "DURABLE status=99 block_writes=0 block_flushes=0 block_errors=0 halt=failed\n")
WRITABLE = ("ABSD KERNEL BOOT\nSTORAGE FENCE fence=none reason=not_declared\n"
            "FSD RECOVERY seq=2 streak=1 previous=failed\nFSD READY channels=2\n"
            + chunk("SSH RECOVERY streak=1\nSSH HOST KEY LOADED ssh-ed25519 AAAA SHA256:x\nSSH LISTENING port=22\n") +
            "DURABLE status=0 block_writes=40 block_flushes=6 block_errors=0 halt=ok\n")


class StrictPredicate(unittest.TestCase):
    """require_served_successor_refusal itself: a complete worker capture
    and init's exact whole-line refusal (Codex review 2026-10-20, F2)."""

    def refuse(self, text):
        return guest.require_served_successor_refusal(text.encode(), "7")

    def test_refusal_passes(self):
        self.assertEqual(self.refuse(REFUSED), guest.WRITABLE_REFUSED)

    def test_readiness_hidden_behind_a_gap_fails(self):
        first = len((guest.NO_SERVER + "\n").encode())
        hidden = f"EXTERNAL OUTPUT CHUNK offset={first + 5:x} data={'SSH LISTENING port=22\n'.encode().hex()}\n"
        overlap = f"EXTERNAL OUTPUT CHUNK offset=0 data={'x'.encode().hex()}\n"
        for extra in (hidden, overlap):
            with self.subTest(extra=extra[:40]), self.assertRaises(RuntimeError):
                self.refuse(REFUSED.replace("SERVED RECOVERY REFUSED", extra + "SERVED RECOVERY REFUSED"))

    def test_imitated_init_refusal_fails(self):
        line = "SERVED RECOVERY REFUSED generation_not_ready"
        for fake in ("x" + line, line + " forged", "worker says " + line):
            with self.subTest(fake=fake), self.assertRaises(RuntimeError):
                self.refuse(REFUSED.replace(line, fake))


class InPlaceSuccessor(unittest.TestCase):
    """refused_in_place: the same-QEMU successor of an unfinalized end."""

    def target(self, log_text, status="7", pid=41):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        target = sr.RecoveryTarget.__new__(sr.RecoveryTarget)
        target.log = pathlib.Path(directory.name) / "sshd-001.serial.log"
        target.log.write_bytes(log_text.encode())
        target.proc = mock.Mock(pid=pid)
        target.proc.communicate.return_value = (status.encode() + b"\n", None)
        target.storage_fence = None
        return target

    def test_refusal_passes(self):
        self.assertEqual(sr.refused_in_place(self.target(FIRST + REFUSED), 41, 1), guest.WRITABLE_REFUSED)

    def test_writable_successor_fails(self):
        for status in ("3", "7"):
            with self.subTest(status=status), self.assertRaises(RuntimeError):
                sr.refused_in_place(self.target(FIRST + WRITABLE, status), 41, 1)

    def test_missing_refusal_line_fails(self):
        for removed in (guest.WRITABLE_REFUSED + "\n", chunk(guest.NO_SERVER + "\n"),
                        "SERVED RECOVERY REFUSED generation_not_ready\n",
                        "DURABLE status=99 block_writes=0 block_flushes=0 block_errors=0 halt=failed\n"):
            with self.subTest(removed=removed), self.assertRaises(RuntimeError):
                sr.refused_in_place(self.target(FIRST + REFUSED.replace(removed, "")), 41, 1)

    def test_io_boot_count_and_process_controls_fail(self):
        for text in (FIRST + REFUSED.replace("block_writes=0", "block_writes=1"),
                     FIRST + REFUSED.replace("block_flushes=0", "block_flushes=1"),
                     FIRST + REFUSED + REFUSED,       # a further boot
                     REFUSED,                         # no unclean predecessor in this QEMU
                     FIRST + REFUSED + "MACHINE RECOVER RESET pid=1\n"):
            with self.subTest(text=text[-60:]), self.assertRaises(RuntimeError):
                sr.refused_in_place(self.target(text), 41, 1)
        with self.assertRaises(RuntimeError):
            sr.refused_in_place(self.target(FIRST + REFUSED, pid=42), 41, 1)  # relaunched QEMU
        declared = self.target(FIRST + REFUSED)
        declared.storage_fence = "external"
        with self.assertRaises(RuntimeError):
            sr.refused_in_place(declared, 41, 1)


class ColdSuccessor(unittest.TestCase):
    """refused_restart: the real refused_cold_boot with only the QEMU boot replaced."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.work = pathlib.Path(directory.name)
        self.image = self.work / "ssh.img"
        self.image.write_bytes(b"fenced image")
        self.target = types.SimpleNamespace(image=self.image, work=self.work, proc=None)

    def run_restart(self, transcript, status="7", touch=False):
        def boot(target, backend, name, **kwargs):
            self.assertEqual((backend, kwargs.get("served"), kwargs.get("declaration")), ("ata", True, None))
            if touch:
                self.image.write_bytes(b"written")
            log = self.work / (name + ".serial.log")
            log.write_bytes(transcript.encode())
            return transcript.encode(), status, log
        with mock.patch.object(guest, "cold_boot", side_effect=boot), \
                mock.patch.object(sr, "marker_on_image") as reader:
            result = sr.refused_restart(self.target, "successor", b"m")
        reader.assert_called_once_with(self.image, b"m")
        return result

    def test_refusal_passes_and_image_unchanged(self):
        self.assertEqual(self.run_restart(REFUSED)["refusal"], guest.WRITABLE_REFUSED)
        self.assertEqual(self.image.read_bytes(), b"fenced image")

    def test_writable_successor_fails(self):
        for status in ("3", "7"):
            with self.subTest(status=status), self.assertRaises(RuntimeError):
                self.run_restart(WRITABLE, status)

    def test_missing_refusal_line_fails(self):
        for removed in (guest.WRITABLE_REFUSED + "\n", chunk(guest.NO_SERVER + "\n"),
                        "SERVED RECOVERY REFUSED generation_not_ready\n"):
            with self.subTest(removed=removed), self.assertRaises(RuntimeError):
                self.run_restart(REFUSED.replace(removed, ""))

    def test_changed_image_fails(self):
        with self.assertRaises(RuntimeError):
            self.run_restart(REFUSED, touch=True)


class Cases(unittest.TestCase):
    """Which predicate each case uses; no case after an unclean end keeps a
    writable successor."""

    def test_clear_after_stop_is_refused_and_never_restarts(self):
        with mock.patch.object(sr, "refused_restart") as refused, \
                mock.patch.object(sr, "restart", side_effect=AssertionError("writable restart")):
            sr.clear_case(None, mock.Mock(), None, None, b"", 4)
        refused.assert_called_once()

    def test_clear_after_clean_halt_keeps_the_writable_restart(self):
        with mock.patch.object(sr, "restart", side_effect=RuntimeError("restart reached")), \
                mock.patch.object(sr, "refused_restart", side_effect=AssertionError("refusal on a clean halt")):
            with self.assertRaisesRegex(RuntimeError, "restart reached"):
                sr.clear_case(None, mock.Mock(), None, None, b"", 0)

    def test_unclean_follow_ons_expect_the_refusal(self):
        for case, refusal in ((sr.escalated_reboot_case, "refused_in_place(target, runner_pid, 1)"),
                              (sr.fault_at_end_case, "refused_in_place(target, runner_pid, 1)"),
                              (sr.exit0_case, "refused_restart(target, ")):
            source = inspect.getsource(case)
            with self.subTest(case=case.__name__):
                self.assertIn(refusal, source)
                self.assertIn("fresh_start(target, key, ", source)
                self.assertNotIn("restart(target)", source.replace("refused_restart(target", ""))
                self.assertNotIn('args, 1, "failed")', source)

    def test_no_pending_owner_case_remains(self):
        source = inspect.getsource(sr)
        self.assertFalse(hasattr(sr, "PENDING_OWNER"))
        self.assertNotIn("NOT_RUN_PENDING_OWNER", source)
        self.assertNotIn("ready(target, index + 1", inspect.getsource(sr.fault_loop))


SESSION = 77
FIRST_FAULT = ("ABSD KERNEL BOOT\nSTORAGE FENCE fence=none reason=not_declared\n"
               "FSD RECOVERY seq=1 streak=0 previous=none\nFSD READY channels=2\n"
               + chunk("SSH RECOVERY streak=0\nSSH LISTENING port=22\n"
                       "SERVED SERVICE FAULT component=sshd reason=qualification\n") +
               "SERVED RECOVERY BEGIN reason=served worker fault file_server_status=running\n"
               f"SERVED RECOVERY PROCESS pid={SESSION} parent=3 state=blocked handles=4 cpu=idle\n"
               "SERVED RECOVERY CENSUS processes=4\n"
               "SERVED RECOVERY RESET streak=1 durability=completed_sync_only\nMACHINE RECOVER RESET pid=1\n")


class MarkerExtraction(unittest.TestCase):
    """marker_on_image: the refused image still holds the synced marker,
    read on the host (Codex review 2026-10-20, F1). The filesystem reader is
    replaced by a stub tree; its own decoding is test_absd_fs.py's."""

    def read(self, files):
        fs = types.SimpleNamespace(
            fs_region=lambda image, sectors: "region", select=lambda region: "selected",
            tree=lambda region, selected: {p: p for p in files},
            content=lambda region, selected, record: files[record])
        with mock.patch.object(sr.served.ssh_absd, "absd_fs", fs), \
                mock.patch.object(sr.served.ssh_absd, "record_is_file", return_value=True):
            sr.marker_on_image("ssh.img", b"marker")

    def test_marker_present_passes(self):
        self.read({sr.MARKER_PATH: b"marker"})

    def test_lost_or_changed_marker_fails(self):
        for files in ({}, {sr.MARKER_PATH: b""}, {sr.MARKER_PATH: b"markeR"},
                      {"/home/operator/recovery-marker-boot2": b"marker"}):
            with self.subTest(files=files), self.assertRaises(RuntimeError):
                self.read(files)

    def test_every_refused_restart_checks_the_marker(self):
        calls = [line for line in inspect.getsource(sr).splitlines()
                 if "refused_restart(target, " in line and "def " not in line]
        self.assertEqual(len(calls), 5)
        for line in calls:
            self.assertTrue(line.rstrip().endswith(", marker)"), line)


class FaultLoop(unittest.TestCase):
    """fault_loop under the owner's decision (2026-10-19, #63): the first
    fault and its reset as before, then the strict refusal in the same QEMU,
    a cold retry, and the UNSUPPORTED capability line."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.work = pathlib.Path(directory.name)
        self.image = self.work / "ssh.img"
        self.image.write_bytes(b"fenced image")

    def run_loop(self, log_text, status="7", retry=REFUSED, touch_image=False, **overrides):
        target = sr.RecoveryTarget.__new__(sr.RecoveryTarget)
        target.log = self.work / "sshd-001.serial.log"
        target.log.write_bytes(log_text.encode())
        target.proc = mock.Mock(pid=41)
        target.proc.communicate.return_value = (status.encode() + b"\n", None)
        target.storage_fence, target.component, target.fault = None, "sshd", "exit"
        target.image, target.work = self.image, self.work

        def boot(target_, backend, name, **kwargs):
            self.assertEqual((backend, kwargs.get("served")), ("ata", True))
            if touch_image:
                self.image.write_bytes(b"written")
            log = self.work / (name + ".serial.log")
            log.write_bytes(retry.encode())
            return retry.encode(), "7", log
        outcome = sr.Outcome(["sshd:fault-loop"])
        loop_args = args(component="sshd", faults=2, **overrides)
        with mock.patch.object(sr, "first_start", return_value=(mock.Mock(), 41)), \
                mock.patch.object(sr, "serve_and_check") as serve, \
                mock.patch.object(sr, "active_session", return_value=(mock.Mock(), SESSION)), \
                mock.patch.object(sr, "end_session"), \
                mock.patch.object(sr, "ssh", return_value=mock.Mock(returncode=255)), \
                mock.patch.object(guest, "cold_boot", side_effect=boot), \
                mock.patch.object(sr, "marker_on_image") as reader, mock.patch("builtins.print") as out:
            try:
                sr.fault_loop(loop_args, "sshd", target, None, self.work, b"m", outcome)
            finally:
                self.text = "\n".join(" ".join(map(str, c.args)) for c in out.call_args_list)
        reader.assert_called_once_with(self.image, b"m")
        serve.assert_called_once()
        self.assertEqual(serve.call_args.args[3:], (0, 41, b"m", loop_args, 0, "none"))
        return outcome

    def test_refusal_passes_and_unsupported_is_printed_not_counted(self):
        outcome = self.run_loop(FIRST_FAULT + REFUSED)
        self.assertIn("SERVED RECOVERY FIRST FAULT REFUSED OK component=sshd", self.text)
        self.assertEqual(len(outcome.unsupported_lines), 1)
        line = outcome.unsupported_lines[0]
        self.assertTrue(line.startswith("AUTOMATIC WRITABLE RECOVERY UNSUPPORTED (owner 2026-10-19; #63: operator act only) case=sshd:fault-loop"))
        self.assertNotIn("OK", line.split())
        self.assertEqual(outcome.done, [])          # fault_loop never marks itself; one_case does
        self.assertEqual(self.image.read_bytes(), b"fenced image")

    def test_writable_successor_fails(self):
        for status in ("3", "7"):
            with self.subTest(status=status), self.assertRaises(RuntimeError):
                self.run_loop(FIRST_FAULT + WRITABLE, status)

    def test_write_or_flush_fails(self):
        for field in ("block_writes", "block_flushes"):
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                self.run_loop(FIRST_FAULT + REFUSED.replace(f"{field}=0", f"{field}=1"))
        with self.assertRaises(RuntimeError):
            self.run_loop(FIRST_FAULT + REFUSED, retry=REFUSED.replace("block_flushes=0", "block_flushes=1"))

    def test_image_change_fails(self):
        with self.assertRaises(RuntimeError):
            self.run_loop(FIRST_FAULT + REFUSED, touch_image=True)

    def test_missing_refusal_line_fails(self):
        for removed in (guest.WRITABLE_REFUSED + "\n", chunk(guest.NO_SERVER + "\n"),
                        "SERVED RECOVERY REFUSED generation_not_ready\n"):
            with self.subTest(removed=removed), self.assertRaises(RuntimeError):
                self.run_loop(FIRST_FAULT + REFUSED.replace(removed, ""))

    def test_second_reset_fails(self):
        with self.assertRaises(RuntimeError):   # the old countdown: another ready, faulting boot
            self.run_loop(FIRST_FAULT + FIRST_FAULT + REFUSED)
        with self.assertRaises(RuntimeError):
            self.run_loop(FIRST_FAULT + REFUSED + "MACHINE RECOVER RESET pid=1\n")

    def test_first_boot_controls_kept(self):
        for first in (FIRST_FAULT.replace("SERVED RECOVERY RESET ", "SERVED RECOVERY ESCALATED "),
                      FIRST_FAULT.replace("SERVED RECOVERY CENSUS processes=4\n", ""),
                      FIRST_FAULT.replace(f"pid={SESSION} ", "pid=78 ")):
            with self.subTest(first=first[-50:]), self.assertRaises(RuntimeError):
                self.run_loop(first + REFUSED)


class HealthInheritance(unittest.TestCase):
    def test_health_json_native_inherits_the_fenced_loop(self):
        spec = importlib.util.spec_from_file_location("health_json_native", HERE / "health-json-native.py")
        health = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(health)
        for name in ("fault_loop", "refused_in_place", "refused_restart", "main"):
            with self.subTest(name=name):
                self.assertEqual(inspect.getsource(getattr(health.recovery, name)), inspect.getsource(getattr(sr, name)))
        self.assertEqual(inspect.getsource(health.recovery.Outcome.verdict), inspect.getsource(sr.Outcome.verdict))
        own = inspect.getsource(health)
        for word in ("fault_loop", "refused_", "ready(", "Outcome"):
            self.assertNotIn(word, own)


def args(**overrides):
    base = dict(component="both", expect="reset", then_clear=False, then_exit0=False,
                then_escalated_reboot=False, then_fault_at_end=False, fault="exit")
    base.update(overrides)
    return types.SimpleNamespace(**base)


class HonestCount(unittest.TestCase):
    def verdict(self, outcome):
        with mock.patch("builtins.print") as out:
            code = outcome.verdict()
        return code, " ".join(str(a) for call in out.call_args_list for a in call.args)

    def run_cases(self, a):
        outcome = sr.Outcome(sr.planned_cases(a))
        with tempfile.TemporaryDirectory() as work, \
                mock.patch.object(sr, "fault_loop", side_effect=lambda *a: a[-1].unsupported(
                    f"{a[1]}:fault-loop", "budget=3 countdown=not_exercisable")), \
                mock.patch.object(sr, "clean_halt_predecessor"), mock.patch.object(sr, "clear_case"), \
                mock.patch.object(sr, "exit0_case"), mock.patch.object(sr, "escalated_reboot_case"), \
                mock.patch.object(sr, "fault_at_end_case"), \
                mock.patch.object(sr, "first_start", return_value=(mock.Mock(), 1)), \
                mock.patch.object(sr, "silent_case"), mock.patch("builtins.print"):
            a.work, a.kernel, a.platform, a.qemu, a.sshd_controls = work, work, work, "qemu", work + "/sshd"
            for component in sr.components(a):
                sr.one_case(a, component, pathlib.Path(work) / "key", outcome)
        return outcome

    def test_default_run_is_ok_with_unsupported_disclosed_not_counted(self):
        outcome = self.run_cases(args())
        self.assertEqual(outcome.done, ["sshd:fault-loop", "fsd:fault-loop"])
        code, text = self.verdict(outcome)
        self.assertEqual(code, 0)
        lines = text.split("AUTOMATIC WRITABLE RECOVERY UNSUPPORTED (owner 2026-10-19; #63: operator act only)")
        self.assertEqual(len(lines) - 1, 2)
        self.assertTrue(text.endswith("SERVED RECOVERY MATRIX OK cases=2"))
        self.assertNotIn("NOT_RUN_PENDING_OWNER", text)

    def test_follow_ons_and_clear_after_clean_halt_run(self):
        outcome = self.run_cases(args(component="sshd", then_clear=True, then_exit0=True,
                                      then_escalated_reboot=True, then_fault_at_end=True))
        self.assertEqual(outcome.done, ["sshd:fault-loop", "sshd:clear-after-clean-halt", "sshd:exit0",
                                        "sshd:escalated-reboot", "sshd:fault-at-end"])
        self.assertEqual(self.verdict(outcome)[0], 0)

    def test_clear_after_stop_runs_the_refusal(self):
        with mock.patch.object(sr, "clear_case") as clear:
            outcome = self.run_cases(args(component="sshd", expect="stop", then_clear=True))
        self.assertEqual(outcome.done, ["sshd:fault-loop", "sshd:clear-after-stop"])
        self.assertEqual(self.verdict(outcome)[0], 0)

    def test_unsupported_line_cannot_stand_in_for_a_case(self):
        outcome = sr.Outcome(["sshd:fault-loop"])
        outcome.unsupported("sshd:fault-loop", "budget=3")
        with mock.patch("builtins.print"):
            self.assertEqual(outcome.verdict(), 1)

    def test_silent_is_complete(self):
        outcome = self.run_cases(args(component="sshd", expect="silent", fault="hang"))
        self.assertEqual((outcome.done, outcome.unsupported_lines), (["sshd:silent"], []))
        self.assertEqual(self.verdict(outcome), (0, "SERVED RECOVERY MATRIX OK cases=1"))

    def test_miscount_fails(self):
        outcome = sr.Outcome(["sshd:exit0", "sshd:fault-loop"])
        outcome.ran("sshd:exit0")
        with mock.patch("builtins.print"):
            self.assertEqual(outcome.verdict(), 1)


if __name__ == "__main__":
    unittest.main()
