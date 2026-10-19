#!/usr/bin/env python3
"""Pure-Python checks of survival-recovery.py's fault plans and liveness
parsing (no QEMU)."""

import importlib.util
import pathlib
import re
import unittest

here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("survival_recovery", here / "survival-recovery.py")
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)

FSD_BEGIN = "SERVED RECOVERY BEGIN reason=file server unresponsive file_server_status=running"
SSHD_BEGIN = "SERVED RECOVERY BEGIN reason=served worker unresponsive file_server_status=running"


def stale(component, idle, sshd, fsd, bound=60000):
    return (f"SERVED LIVENESS STALE component={component} idle_ticks={idle} bound={bound} "
            f"sshd_idle_ticks={sshd} fsd_idle_ticks={fsd}")


def lines(*parts):
    return "\n".join(parts) + "\n"


class Plans(unittest.TestCase):
    def test_target_without_fault_builds_the_exit_iso(self):
        # survival-pre-ready.py subclasses RecoveryTarget and never sets
        # `fault`; it must get the exit option, the behaviour before --fault.
        seen = {}

        class Probe(sr.RecoveryTarget):
            def iso(self, step, worker, input_bytes=b"", options="", server=""):
                seen["options"] = options
                return "iso"
        target = Probe.__new__(Probe)
        target.root = pathlib.Path("/platform")
        target.sshd_elf = pathlib.Path("/platform/sshd-controls.elf")
        target.fsd_elf = pathlib.Path("/platform/absd-fsd.elf")
        target.component = "fsd"
        target.sshd_iso()
        self.assertEqual(seen["options"], "net fsd served served-fsd-exit-test")
        target.fault = "hang"
        target.sshd_iso()
        self.assertEqual(seen["options"], "net fsd served served-fsd-hang-test")
        target.component = "sshd"
        target.sshd_iso()
        self.assertEqual(seen["options"], "net fsd served")

    def test_controls_and_options(self):
        self.assertEqual(sr.fault_plan("sshd", "exit")["command"], "qualification-sshd-fault")
        self.assertEqual(sr.fault_plan("sshd", "hang")["command"], "qualification-sshd-hang")
        self.assertEqual(sr.fault_plan("sshd", "block")["command"], "qualification-sshd-block")
        self.assertEqual(sr.fault_plan("fsd", "exit")["iso_option"], "served-fsd-exit-test")
        self.assertEqual(sr.fault_plan("fsd", "hang")["iso_option"], "served-fsd-hang-test")
        self.assertEqual(sr.fault_plan("sshd", "hang")["iso_option"], "")
        with self.assertRaises(ValueError):
            sr.fault_plan("fsd", "block")

    def test_patterns_match_exact_lines(self):
        expected = {
            ("sshd", "exit"): ("SERVED SERVICE FAULT component=sshd reason=qualification",
                               "SERVED RECOVERY BEGIN reason=served worker fault file_server_status=0"),
            ("sshd", "hang"): ("SERVED SERVICE HANG component=sshd kind=spin reason=qualification", SSHD_BEGIN),
            ("sshd", "block"): ("SERVED SERVICE HANG component=sshd kind=block reason=qualification", SSHD_BEGIN),
            ("fsd", "exit"): ("FSD QUALIFICATION EXIT status=7",
                              "SERVED RECOVERY BEGIN reason=file server ended while the worker ran file_server_status=7"),
            ("fsd", "hang"): ("FSD QUALIFICATION HANG kind=spin", FSD_BEGIN),
        }
        for (component, fault), (service, begin) in expected.items():
            plan = sr.fault_plan(component, fault)
            self.assertTrue(re.fullmatch(plan["service"], service), (component, fault))
            self.assertTrue(re.fullmatch(plan["begin"], begin), (component, fault))


class Liveness(unittest.TestCase):
    def test_fsd_hang_accepted(self):
        serial = lines("FSD QUALIFICATION HANG kind=spin", stale("fsd", 60012, 59000, 60012),
                       FSD_BEGIN, "SERVED RECOVERY RESET x")
        record = sr.liveness_record(serial, "fsd", sr.fault_plan("fsd", "hang")["begin"])
        self.assertEqual(record["idle_ticks"], 60012)

    def test_wrong_component_refused(self):
        serial = lines(stale("sshd", 60012, 60012, 60012), SSHD_BEGIN)
        with self.assertRaisesRegex(RuntimeError, "expected fsd"):
            sr.liveness_record(serial, "fsd", sr.fault_plan("fsd", "hang")["begin"])

    def test_below_bound_refused(self):
        serial = lines(stale("sshd", 59999, 59999, 10), SSHD_BEGIN)
        with self.assertRaisesRegex(RuntimeError, "< 60000"):
            sr.liveness_record(serial, "sshd", sr.fault_plan("sshd", "hang")["begin"])

    def test_wrong_bound_refused(self):
        serial = lines(stale("sshd", 70000, 70000, 10, bound=50000), SSHD_BEGIN)
        with self.assertRaisesRegex(RuntimeError, "bound=50000"):
            sr.liveness_record(serial, "sshd", sr.fault_plan("sshd", "hang")["begin"])

    def test_inconsistent_idle_refused(self):
        serial = lines(stale("sshd", 70000, 65000, 10), SSHD_BEGIN)
        with self.assertRaisesRegex(RuntimeError, "differs"):
            sr.liveness_record(serial, "sshd", sr.fault_plan("sshd", "hang")["begin"])

    def test_begin_before_stale_refused(self):
        serial = lines(SSHD_BEGIN, stale("sshd", 60001, 60001, 10))
        with self.assertRaisesRegex(RuntimeError, "precedes"):
            sr.liveness_record(serial, "sshd", sr.fault_plan("sshd", "hang")["begin"])

    def test_wrong_reason_refused(self):
        serial = lines(stale("sshd", 60001, 60001, 10),
                       "SERVED RECOVERY BEGIN reason=served worker fault file_server_status=running")
        with self.assertRaisesRegex(RuntimeError, "no recovery line"):
            sr.liveness_record(serial, "sshd", sr.fault_plan("sshd", "hang")["begin"])

    def test_unnamed_build_checks_order_only(self):
        serial = lines(stale("sshd", 60001, 60001, 10), "SERVED RECOVERY BEGIN reason=other")
        sr.liveness_record(serial, "sshd", None)

    def test_missing_or_repeated_refused(self):
        with self.assertRaisesRegex(RuntimeError, "found 0"):
            sr.liveness_record(lines(SSHD_BEGIN), "sshd", None)
        twice = lines(stale("sshd", 60001, 60001, 10), stale("sshd", 60002, 60002, 10), SSHD_BEGIN)
        with self.assertRaisesRegex(RuntimeError, "found 2"):
            sr.liveness_record(twice, "sshd", None)

    def test_malformed_refused(self):
        serial = lines("SERVED LIVENESS STALE component=sshd idle_ticks=60001", SSHD_BEGIN)
        with self.assertRaisesRegex(RuntimeError, "malformed"):
            sr.liveness_record(serial, "sshd", None)

    def test_no_stale(self):
        self.assertEqual(sr.no_stale(lines("FSD READY x", "SERVED LIVENESS GAP ticks=1500"), "boot"), [1500])
        with self.assertRaisesRegex(RuntimeError, "liveness judgment"):
            sr.no_stale(lines(stale("fsd", 60001, 1, 60001)), "boot")


if __name__ == "__main__":
    unittest.main()
