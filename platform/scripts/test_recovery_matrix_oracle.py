"""Controls for the new native oracle, including their deliberate mutants.

These exercise predicates and a real filesystem inventory, not native service.
Each control is also run with its named acceptance check disabled. A mutant
counts as detected only through assertion failures, with no test errors.
"""

import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_recovery_point as fixture

spec = importlib.util.spec_from_file_location("recovery_native_oracle", HERE / "recovery-point-matrix.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)

FP = "SHA256:independently-retained-test-fingerprint"


def serial(worker=b"SSH LISTENING\n", release="rel-a"):
    return (f"ABSD KERNEL BOOT\nRELEASE OK release={release}\n".encode()
            + b"EXTERNAL OUTPUT CHUNK offset=00000000 data=" + worker.hex().encode() + b"\n")


class OracleControls(unittest.TestCase):
    def ready_refusal(self, raw, fingerprint=FP):
        native.require_ready(serial(), {"fingerprint": FP}, "rel-a", FP)
        with self.assertRaises(RuntimeError):
            native.require_ready(raw, {"fingerprint": fingerprint}, "rel-a", FP)

    def test_readiness_checks_independent_host_identity(self):
        self.ready_refusal(serial(), "SHA256:another-identity")

    def test_readiness_checks_exact_release(self):
        self.ready_refusal(serial(release="rel-ab"))

    def test_readiness_checks_complete_capture(self):
        self.ready_refusal(serial().replace(b"offset=00000000", b"offset=00000001"))

    def test_readiness_checks_listener(self):
        self.ready_refusal(serial(worker=b"not listening\n"))

    def test_readiness_refuses_reset(self):
        self.ready_refusal(serial() + b"MACHINE RECOVER RESET\n")

    def test_readiness_requires_one_boot(self):
        self.ready_refusal(serial() + b"ABSD KERNEL BOOT\n")

    def halt_refusal(self, raw, status=3):
        native.require_halt(serial(), 3, 0, b"going down for halt\n")
        with self.assertRaises(RuntimeError):
            native.require_halt(raw, status, 0, b"going down for halt\n")

    def test_halt_checks_exit_status(self):
        self.halt_refusal(serial(), 7)

    def test_halt_refuses_escalation(self):
        self.halt_refusal(serial() + b"SERVED SHUTDOWN ESCALATED\n")

    def test_halt_refuses_recovery(self):
        self.halt_refusal(serial() + b"SERVED RECOVERY RESET\n")

    def test_state_includes_empty_directories(self):
        expected = {"/home/empty": {"kind": "directory"}}
        native.require_state(expected, expected)
        with self.assertRaises(RuntimeError):
            native.require_state({}, expected)

    def test_state_checks_file_content(self):
        expected = {"/home/state": {"kind": "file", "bytes": 3, "sha256": native.sha(b"one")}}
        found = {"/home/state": {"kind": "file", "bytes": 3, "sha256": native.sha(b"two")}}
        native.require_state(expected, expected)
        with self.assertRaises(RuntimeError):
            native.require_state(found, expected)

    def test_inventory_reads_real_filesystem_and_empty_directory(self):
        with tempfile.TemporaryDirectory(prefix="recovery-oracle-") as tmp:
            image = Path(tmp) / "device.img"
            files, _, sectors = fixture.disk(image)
            with mock.patch.object(native.rel.oi, "DEVICE_SECTORS", sectors):
                found = native.inventory(image)
            self.assertEqual(found.get("/home/operator/data/empty"), {"kind": "directory"})
            self.assertEqual(found.get("/home/operator/data/state.bin", {}).get("sha256"),
                             native.sha(files["/home/operator/data/state.bin"]))

    def test_refusal_snapshot_detects_content_mutation(self):
        with tempfile.TemporaryDirectory(prefix="recovery-oracle-") as tmp:
            out = Path(tmp) / "out"; out.mkdir()
            path = out / "sentinel"; path.write_bytes(b"original")
            before = native.destination_snapshot(out)
            path.write_bytes(b"changed")
            self.assertNotEqual(native.destination_snapshot(out), before)

    def test_missing_reordered_or_failed_cases_cannot_pass(self):
        rows = [{"case": case, "verdict": "PASS"} for case in native.REQUIRED]
        self.assertEqual(native.terminal_result(rows)["disposition"], "PASS")
        self.assertNotEqual(native.terminal_result(rows[:-1])["disposition"], "PASS")
        self.assertNotEqual(native.terminal_result(rows[::-1])["disposition"], "PASS")
        self.assertNotEqual(native.terminal_result(rows, "producer failed")["disposition"], "PASS")
        rows[-1] = {"case": native.REQUIRED[-1], "verdict": "FAIL"}
        self.assertNotEqual(native.terminal_result(rows)["disposition"], "PASS")

    def test_guest_difference_reads_nested_release_manifest(self):
        with tempfile.TemporaryDirectory(prefix="recovery-oracle-") as tmp:
            releases = []
            for name in ("a", "b"):
                release = native.rel.Release.__new__(native.rel.Release)
                release.path = Path(tmp) / name; release.path.mkdir()
                release.manifest = release.path / "release-manifest.toml"
                release.manifest.write_text('[artifacts.files."tree/bin/release"]\nsha256 = "'
                                            + native.sha(name.encode()) + '"\n')
                releases.append(release)
            difference = native.guest_difference(*releases)
            self.assertIn("tree/bin/release", difference.get("changed_tree_files", []))


MUTANTS = {name: ("require_ready" if "readiness" in name else
                 "require_halt" if "halt_" in name else
                 "require_state" if "state_" in name else
                 "inventory" if "inventory_" in name else
                 "destination_snapshot" if "snapshot_" in name else "terminal_result")
           for name in unittest.defaultTestLoader.getTestCaseNames(OracleControls)}
MUTANTS["test_guest_difference_reads_nested_release_manifest"] = "guest_difference"


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument("--output"); args = ap.parse_args()
    log = io.StringIO()
    normal = unittest.TextTestRunner(stream=log).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(OracleControls))
    rows = []
    for test, name in MUTANTS.items():
        output = io.StringIO()
        replacement = ((lambda *args, **kw: {"disposition": "PASS"}) if name == "terminal_result" else
                       (lambda *args, **kw: {}) if name in ("inventory", "guest_difference") else lambda *args, **kw: None)
        with mock.patch.object(native, name, replacement), contextlib.redirect_stderr(output):
            result = unittest.TextTestRunner(stream=output).run(unittest.TestSuite([OracleControls(test)]))
        killed = bool(result.failures) and not result.errors
        rows.append({"test": test, "mutant": "disable_" + name, "killed": killed,
                     "failures": len(result.failures), "errors": len(result.errors),
                     "diagnostic": output.getvalue()[-2000:]})
    passed = normal.wasSuccessful() and all(row["killed"] for row in rows)
    result = {"schema_version": 1, "disposition": "PASS" if passed else "FAIL", "controls": normal.testsRun,
              "normal_log": log.getvalue(), "mutants": rows,
              "scope": "Host oracle controls only; no native execution or acceptance claim."}
    if args.output:
        with Path(args.output).open("x") as stream:
            json.dump(result, stream, indent=2); stream.write("\n")
    print(json.dumps({"disposition": result["disposition"], "controls": normal.testsRun,
                      "mutants_killed": sum(row["killed"] for row in rows)}))
    if not passed:
        print(log.getvalue())
        for row in rows:
            if not row["killed"]:
                print(json.dumps(row))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
