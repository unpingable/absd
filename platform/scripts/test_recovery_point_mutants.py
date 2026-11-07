"""Run each recovery control against a named weakened implementation.

Mutations exist only in isolated child-process module dictionaries. Checked-out
source and historical results are never changed. Three base-release-tool
projections also show the new strict contract is absent from 03479a3e; those
use the same small real filesystem fixture and current unchanged reader rules.
"""

import argparse
import contextlib
import hashlib
import inspect
import io
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_recovery_point as controls

BASE = "03479a3e090e847ccdfa647dce44e7b16d035988"
CASES = {
    "test_point_creation_pins_clean_state_and_iso": "creation_schema",
    "test_fresh_restore_preserves_exact_image_state_and_identity": "corrupt_publication",
    "test_external_pin_mismatch_changes_no_destination": "skip_pin",
    "test_rehashed_local_metadata_cannot_replace_external_pin": "skip_pin",
    "test_image_digest_covers_bytes_outside_filesystem": "skip_image_digest",
    "test_truncated_image_is_refused_before_destination_changes": "bypass_admission",
    "test_iso_mutation_is_refused_before_destination_changes": "skip_iso_digest",
    "test_expected_release_is_not_inferred_from_backup": "skip_expected_release",
    "test_unknown_schema_is_refused": "skip_schema",
    "test_malformed_metadata_is_named": "bypass_admission",
    "test_dirty_and_malformed_guards_cannot_be_restored": "skip_clean",
    "test_dirty_and_malformed_guards_cannot_produce_points": "skip_clean",
    "test_held_source_cannot_produce_point": "skip_holders",
    "test_held_point_cannot_be_restored": "skip_holders",
    "test_existing_directory_and_image_are_unchanged": "allow_existing_directory",
    "test_symlinked_existing_destination_is_unchanged": "allow_existing_directory",
    "test_replace_and_clone_combinations_are_refused": "allow_clone_replace",
    "test_metadata_does_not_rename_the_logical_machine": "ignore_requested_identity",
    "test_symlinked_recovery_members_are_refused": "follow_member_links",
    "test_structural_reader_is_required_even_for_pinned_bytes": "skip_superblock_checksum",
    "test_input_replacement_after_validation_publishes_validated_bytes": "reopen_input",
    "test_cli_enforces_the_external_pin_before_output": "skip_pin",
    "test_incompatible_source_record_cannot_produce_point": "skip_release_record",
    "test_incompatible_pinned_record_changes_no_destination": "skip_release_record",
    "test_copy_io_failure_is_incomplete_and_cannot_retry_as_fresh": "ignore_construction_error",
    "test_clean_guard_not_ready_history_refuses_point_and_restore": "skip_restore_clean_history",
    "test_clean_guard_failed_history_refuses_point_and_restore": "skip_history",
    "test_clean_guard_invalid_history_refuses_point_and_restore": "skip_restore_clean_history",
    "test_history_checksum_padding_and_wrong_boot_are_refused": "skip_history",
    "test_history_ended_accepts_bounded_completion": "corrupt_publication",
    "test_wrong_format_metadata_changes_no_destination": "bypass_admission",
    "test_truncated_metadata_changes_no_destination": "bypass_admission",
    "test_truncated_iso_changes_no_destination": "bypass_admission",
    "test_legacy_restore_cannot_consume_pinned_point": "allow_legacy_point",
    "test_resume_labeled_legacy_backup_remains_restorable": "legacy_corrupt_publication",
    "test_recovery_point_with_pending_label_still_requires_strict_route": "allow_legacy_point",
    "test_legacy_replace_refuses_unclean_target": "allow_unclean_legacy_target",
    "test_legacy_replace_refuses_held_target": "skip_holders",
    "test_legacy_replace_names_zeroed_and_layoutless_target_refusal": "allow_unknown_legacy_target",
    "test_legacy_replace_over_clean_ended_target_still_copies_exactly": "legacy_corrupt_publication",
}
BASE_CASES = ("test_external_pin_mismatch_changes_no_destination",
              "test_expected_release_is_not_inferred_from_backup",
              "test_dirty_and_malformed_guards_cannot_produce_points")


def replace_function(module, name, substitutions):
    source = inspect.getsource(getattr(module, name))
    for before, after in substitutions:
        if before not in source:
            raise RuntimeError(f"mutation no longer matches {name}: {before!r}")
        source = source.replace(before, after)
    exec(compile(source, f"<deliberate {name} mutation>", "exec"), module.__dict__)


def install_mutant(name):
    rel, rp = controls.rel, controls.rp
    guards = {
        "skip_pin": ('if digest(metadata_bytes) != expected_pin:', 'if False:'),
        "skip_expected_release": ('if selected != expected_release:', 'if False:'),
        "skip_image_digest": ('if digest(image) != disk.get("image_sha256"):', 'if False:'),
        "skip_iso_digest": ('if digest(iso) != recovery["iso_sha256"]:', 'if False:'),
        "skip_schema": ('recovery["schema"] != SCHEMA', 'False'),
    }
    if name in guards:
        replace_function(rp, "validate", [guards[name]])
    elif name == "creation_schema":
        replace_function(rp, "table", [('"schema": SCHEMA', '"schema": "absd-recovery-point/0"')])
    elif name == "skip_clean":
        rp.require_clean = lambda tree: None
    elif name == "skip_history":
        rp.require_ended_history = lambda tree: None
    elif name == "skip_restore_clean_history":
        replace_function(rp, "validate", [('require_clean(tree)', 'None')])
    elif name == "allow_legacy_point":
        replace_function(rel, "cmd_restore", [('if "recovery" in meta and set(meta["recovery"]) != {"pending_id"}:', 'if False:')])
    elif name == "allow_unclean_legacy_target":
        rp.require_clean_history = lambda tree: None
    elif name == "allow_unknown_legacy_target":
        replace_function(rel, "cmd_restore", [('recovery_point.require_clean_history(target.tree())', 'None')])
    elif name == "legacy_corrupt_publication":
        original = rel.cmd_restore
        def corrupted(args, log=print):
            original(args, log)
            path = Path(args.target) / rel.IMAGE
            data = path.read_bytes()
            path.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
        rel.cmd_restore = corrupted
    elif name == "skip_release_record":
        rp.require_release = lambda tree, selected: None
    elif name == "skip_holders":
        rel.refuse_in_use = lambda *args, **kwargs: None
    elif name == "allow_existing_directory":
        replace_function(rel, "restore_recovery_point", [
            ('if raw_target.is_symlink() or target.out.exists():', 'if False:'),
            ('parents=True, exist_ok=False)', 'parents=True, exist_ok=True)')])
    elif name == "allow_clone_replace":
        replace_function(rel, "restore_recovery_point", [
            ('if args.clone or args.replace or args.release or args.kernel:',
             'if args.release or args.kernel:')])
    elif name == "ignore_requested_identity":
        replace_function(rel, "restore_recovery_point", [
            ('if args.target_identity is not None and args.target_identity != source_identity:', 'if False:')])
    elif name == "follow_member_links":
        replace_function(rp, "_member", [(' | os.O_NOFOLLOW', '')])
    elif name == "skip_superblock_checksum":
        replace_function(controls.absd_fs, "superblock", [
            ('if raw[:7] != b"ABSDFSS" or hashlib.sha256(raw[:480]).digest() != raw[480:]:',
             'if raw[:7] != b"ABSDFSS":')])
    elif name in ("reopen_input", "corrupt_publication"):
        replacement = ('(pathlib.Path(args.backup) / IMAGE).read_bytes()' if name == "reopen_input"
                       else 'point.image[:-1] + bytes([point.image[-1] ^ 1])')
        replace_function(rel, "restore_recovery_point", [
            ('write_recovery_file(target.image, point.image)',
             f'write_recovery_file(target.image, {replacement})')])
    elif name == "ignore_construction_error":
        replace_function(rel, "restore_recovery_point", [
            ('raise Failed(f"recovery_point_construction_incomplete: {target.out}: {error}; "\n'
             '                     "reconcile this destination before reuse; the source point is unchanged") from None',
             'pass')])
    elif name == "bypass_admission":
        def unsafe(args):
            image = (Path(args.backup) / rel.IMAGE).read_bytes()
            iso = (Path(args.backup) / "releases" / args.expected_release / rel.ISO).read_bytes()
            meta = {"backup": {"target": "qualification-machine-a"},
                    "disk": {"image_sha256": rp.digest(image), "fs_format": 2}}
            return rp.Snapshot(meta, {}, args.expected_release, image, iso, args.recovery_point_sha256)
        rel.recovery_snapshot = unsafe
    elif name == "base":
        source = subprocess.check_output(['git', '-C', str(HERE.parent), 'show', BASE + ':scripts/release.py'])
        module = types.ModuleType("baseline_release_tool")
        module.__file__ = str(HERE / "release.py")
        exec(compile(source, f"<base {BASE}:release.py>", "exec"), module.__dict__)
        controls.rel = module
    else:
        raise RuntimeError(f"unknown deliberate mutation {name}")


def child(mutant, test):
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
        install_mutant(mutant)
        result = unittest.TextTestRunner(stream=captured).run(
            unittest.TestSuite([controls.RecoveryControls(test)]))
    killed = bool(result.failures) and not result.errors
    print(json.dumps({"test": test, "mutant": mutant, "disposition": "KILLED" if killed else "INVALID_OR_SURVIVED",
                      "failures": len(result.failures), "errors": len(result.errors),
                      "diagnostic": captured.getvalue()[-3000:]}))
    return 0 if killed else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mutant"); ap.add_argument("--test"); ap.add_argument("--output")
    args = ap.parse_args()
    if args.mutant:
        return child(args.mutant, args.test)
    names = set(unittest.defaultTestLoader.getTestCaseNames(controls.RecoveryControls))
    if names != set(CASES):
        raise RuntimeError("every recovery control must have an explicit mutant mapping")
    normal_log = io.StringIO()
    normal = unittest.TextTestRunner(stream=normal_log).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(controls.RecoveryControls))
    rows = []
    if normal.wasSuccessful():
        for test, mutant in [*CASES.items(), *((test, "base") for test in BASE_CASES)]:
            p = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()),
                                "--test", test, "--mutant", mutant], capture_output=True, text=True)
            try:row = json.loads(p.stdout)
            except ValueError:row = {"test": test, "mutant": mutant, "disposition": "HARNESS_ERROR",
                                    "stdout": p.stdout[-2000:], "stderr": p.stderr[-2000:]}
            row["exit"] = p.returncode; rows.append(row)
    passed = normal.wasSuccessful() and len(rows) == len(CASES) + len(BASE_CASES) and all(
        r["disposition"] == "KILLED" and r["exit"] == 0 for r in rows)
    result = {"schema_version": 1, "disposition": "PASS" if passed else "FAIL",
              "normal_controls": normal.testsRun, "normal_pass": normal.wasSuccessful(),
              "normal_log": normal_log.getvalue(), "control_mutant_cases": len(CASES),
              "base_projection_cases": len(BASE_CASES), "base_source": BASE,
              "base_projection_scope": "Exact base release.py with the same small real filesystem fixture and current unchanged reader predicates; not a whole-base native run.",
              "rows": rows}
    if args.output:
        with Path(args.output).open("x") as f:json.dump(result, f, indent=2); f.write("\n")
    print(json.dumps({k: result[k] for k in ("disposition", "normal_controls", "control_mutant_cases", "base_projection_cases")}))
    if not passed:
        print(normal_log.getvalue())
        for row in rows:
            if row["disposition"] != "KILLED":print(json.dumps(row))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
