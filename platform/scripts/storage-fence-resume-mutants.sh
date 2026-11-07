#!/bin/sh
# WORK-PLAN-v5 step 6 mutants for operator-authorized recovery (coordination record
# #63): each mutant removes one mechanism in a scratch copy of the tree and
# the named case must FAIL there. Nothing in the checkout changes.
#
#   scripts/storage-fence-resume-mutants.sh [--skip-rust]
#
# Mutants (host side):
#   ofd-lock      the OFD range lock removed            -> L1/L2 host correspondence fails
#   f-check       the F check of rows 10/11 removed      -> B5(b1) (row 11) fails
#   row-13        row 13 (stale-intent) removed          -> B8 fails on differs/none/intent-only
#   row-2         row 2's terminal rule removed          -> B7 corrupt-slot + unparsable-active fails
#   mutation      Target.mutation() removed              -> M1 host analog fails
#   reconfigure-lock  release.py reconfigure's Target.mutation() removed -> M1 host analog fails
#   oi-reconfigure-lock  operator_image.py reconfigure's recovery context removed
#                 -> its MANIFEST-target recovery_pending and real-boundary control fail
#   build-refusal build's target_directory refusal gone  -> M3 fails
#   failed-only   the B1 boundary oracle fixed to failed -> B1 with p = not_ready fails (cargo test)
# Prints `STORAGE FENCE RESUME MUTANTS OK mutants=<n>` only when every
# mutant failed its case and the unmutated copy passed the same cases.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
skip_rust=0
[ "${1:-}" = "--skip-rust" ] && skip_rust=1
scratch=$(mktemp -d "${TMPDIR:-/tmp}/resume-mutants.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
copy() {
    rm -rf "$scratch/tree"
    mkdir -p "$scratch/tree"
    cp -r "$root/scripts" "$root/fixtures" "$scratch/tree/"
}
# run EXPECT NAME PYTEST-ARGS...: EXPECT is pass or fail.
run() {
    expect=$1 name=$2
    shift 2
    if (cd "$scratch/tree" && python3 -I -m pytest -q -x "$@" > "$scratch/$name.log" 2>&1); then
        outcome=pass
    else
        outcome=fail
    fi
    if [ "$outcome" != "$expect" ]; then
        printf '%s\n' "MUTANT $name: expected $expect, got $outcome (see $scratch/$name.log)" >&2
        cat "$scratch/$name.log" | tail -30 >&2
        exit 1
    fi
    printf '%s\n' "MUTANT $name: $outcome as expected"
}
mutate() {
    # mutate FILE PYTHON-EXPR: FILE's text through the expression (s is the text).
    python3 - "$scratch/tree/$1" "$2" <<'PYEOF'
import pathlib, sys
path = pathlib.Path(sys.argv[1]); s = path.read_text()
new = eval(sys.argv[2], {"s": s})
if new == s:
    raise SystemExit(f"mutant did not change {path}")
path.write_text(new)
PYEOF
}
n=0

copy
run pass control-host scripts/test_storage_fence_resume.py -k "image_locked or replaced_pathname or every_combination or corrupt_missing or build_refuses" scripts/test_release_tool.py -k "recovery_pending or target_directory or control_the_real_boundary_refuses_first"

copy
mutate scripts/storage_fence_resume.py 's.replace("""    try:
        fcntl.fcntl(fd, fcntl.F_OFD_SETLK, want)
    except OSError as error:""", """    try:
        return
        fcntl.fcntl(fd, fcntl.F_OFD_SETLK, want)
    except OSError as error:""")'
run fail ofd-lock scripts/test_storage_fence_resume.py -k "image_locked"; n=$((n + 1))

copy
mutate scripts/storage_fence_resume.py 's.replace("""    if kind == "active":
        if f == tuple(record["f"]):
            decision = Decision(10""", """    if kind == "active":
        if True:
            decision = Decision(10""")'
run fail f-check scripts/test_storage_fence_resume.py -k "replaced_pathname"; n=$((n + 1))

copy
mutate scripts/storage_fence_resume.py 's.replace("""        decision = Decision(13, ROWS[13], False, "stale_intent", [("stale", record)], transaction=(kind, record))
        archive = {"kind": "stale", "id": record["id"], "time": now(), "path": None, "fields": None}
        return continue_with(decision, dict(probe, records=dict(records, archives=archives + [archive])))""", """        raise RuntimeError("unhandled state: intent-only with another F")""")'
run fail row-13 scripts/test_storage_fence_resume.py -k "every_combination"; n=$((n + 1))

copy
mutate scripts/storage_fence_resume.py 's.replace("""    if slot[0] == "corrupt":
        return Decision(2, ROWS[2], False, "resume_slot_corrupt", [])""", """    if slot[0] == "corrupt" and not records["unparsable"]:
        return Decision(2, ROWS[2], False, "resume_slot_corrupt", [])""")'
run fail row-2 scripts/test_storage_fence_resume.py -k "corrupt_missing"; n=$((n + 1))

copy
mutate scripts/release.py 's.replace("""        try:
            with storage_fence_resume.mutation(self.out, self.image, replacing=replacing):
                yield
        except storage_fence_resume.Refused as error:
            raise Failed(str(error)) from None""", """        yield""")'
run fail mutation scripts/test_release_tool.py -k "recovery_pending"; n=$((n + 1))

copy
mutate scripts/release.py 's.replace("""        held.enter_context(target.mutation())
""", "")'
run fail reconfigure-lock scripts/test_release_tool.py -k "every_mutator_refuses_recovery_pending"; n=$((n + 1))

copy
mutate scripts/operator_image.py 's.replace("""        with storage_fence_resume.mutation(out, image):""", """        with __import__("contextlib").nullcontext():""")'
run fail oi-reconfigure-lock scripts/test_release_tool.py -k "operator_image_reconfigure_refuses_recovery_pending_on_a_manifest_target"; n=$((n + 1))
copy
mutate scripts/operator_image.py 's.replace("""        with storage_fence_resume.mutation(out, image):""", """        with __import__("contextlib").nullcontext():""")'
run fail oi-reconfigure-lock-boundary scripts/test_release_tool.py -k "control_the_real_boundary_refuses_first"; n=$((n + 1))

copy
mutate scripts/release.py 's.replace("""    found = [name for name in TARGET_MARKERS if (out / name).exists()]""", """    found = []""")'
run fail build-refusal scripts/test_storage_fence_resume.py -k "build_refuses" scripts/test_release_tool.py -k "target_directory"; n=$((n + 1))

if [ "$skip_rust" = 0 ]; then
    # The oracle fixed to `failed`: every expectation parameterized by p
    # becomes Previous::Failed, so the not_ready history fails. Applied in
    # place (the workspace and its lock are needed) and restored after.
    guard_rs=$root/fsd/src/write_guard.rs
    cp "$guard_rs" "$scratch/write_guard.rs.orig"
    trap 'cp "$scratch/write_guard.rs.orig" "$guard_rs"; rm -rf "$scratch"' EXIT
    python3 - "$guard_rs" <<'PYEOF'
import pathlib, sys
path = pathlib.Path(sys.argv[1]); s = path.read_text()
new = s.replace("Err(Refusal::Unfenced(p))", "Err(Refusal::Unfenced(Previous::Failed))")
new = new.replace("assert!(how == p || how == Previous::NotReady,", "assert!(how == Previous::Failed || how == Previous::NotReady,")
if new == s:
    raise SystemExit("mutant did not change write_guard.rs")
path.write_text(new)
PYEOF
    if (cd "$root/fsd" && env -u RUSTFLAGS cargo +1.95.0 test --offline --release \
            --target x86_64-unknown-linux-gnu --target-dir "$root/.host-target" -p absd-fsd \
            consumption_and_charge_boundaries > "$scratch/failed-only.log" 2>&1); then
        printf '%s\n' "MUTANT failed-only: expected fail, got pass" >&2
        exit 1
    fi
    cp "$scratch/write_guard.rs.orig" "$guard_rs"
    grep -q "NotReady" "$scratch/failed-only.log" || { printf '%s\n' "MUTANT failed-only: failed for another reason" >&2; tail -30 "$scratch/failed-only.log" >&2; exit 1; }
    printf '%s\n' "MUTANT failed-only: fail as expected"
    n=$((n + 1))
fi
printf '%s\n' "STORAGE FENCE RESUME MUTANTS OK mutants=$n"
