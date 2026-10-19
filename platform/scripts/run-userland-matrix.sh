#!/bin/sh
# The base userland's guest run T5 (userland/README.md, "Guest run (T5)"):
# the host self-test of the runner's judging, then scripts/userland-matrix.py
# on one `net fsd` boot. Nothing is built here: ABSD_USERLAND_PLATFORM is a
# built platform tree whose ports/ holds the nine sbase ports at their
# userland/PORTS.tsv digests (the runner refuses any other bytes), with
# commands/absd-sh, the boot ELFs and the rendered manpages/.
# Environment: ABSD_KERNEL_RUN (required; a disposable kernel clone, never
# the protected kernel source); ABSD_USERLAND_PLATFORM (required);
# ABSD_USERLAND_WORK (default <campaign>/userland-guest) for the logs, the
# serial logs and the work directory; ABSD_USERLAND_ONLY=<prefix> runs only
# the cases whose ID starts with it; ABSD_USERLAND_PINS (default
# $ABSD_USERLAND_WORK/matrix/pins, removed with the work directory at the
# start of the next run) is where a DEFECT's result is written.
# Host rules, as scripts/run-cports.sh: the script re-executes itself under
# nice so it runs at niceness 10 or more; it refuses to start when the
# 1-minute load is above 10; and a full run (no ABSD_USERLAND_ONLY) refuses a
# working tree with any change or untracked file, so the log's source= names
# exactly what ran. The last line is the matrix's summary,
# `ABSD USERLAND GUEST OK cases= agree= diverge= defects=0 demo= notrun=`.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
camp=$(dirname "$root")
out=${ABSD_USERLAND_WORK:-$camp/userland-guest}
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel clone}
platform=${ABSD_USERLAND_PLATFORM:?set ABSD_USERLAND_PLATFORM to the built platform tree carrying the nine ports}
[ -d "$kernel" ] || { echo "run-userland-matrix: ABSD_KERNEL_RUN $kernel is not a directory" >&2; exit 1; }
[ -d "$platform/ports" ] || { echo "run-userland-matrix: $platform/ports is not a directory" >&2; exit 1; }
forbidden=/data/git/absd-kernel
[ -d "$forbidden" ] && forbidden=$(CDPATH= cd -- "$forbidden" && pwd -P)
[ "$(CDPATH= cd -- "$kernel" && pwd -P)" != "$forbidden" ] ||
    { echo "run-userland-matrix: ABSD_KERNEL_RUN must not be /data/git/absd-kernel" >&2; exit 1; }

if [ -z "${ABSD_RUN_USERLAND_CHILD:-}" ]; then
    niceness=$(nice)
    [ "$niceness" -ge 10 ] || exec nice -n $((10 - niceness)) sh "$0" "$@"
    load=$(cut -d' ' -f1 /proc/loadavg)
    awk -v l="$load" 'BEGIN { exit !(l <= 10) }' ||
        { echo "run-userland-matrix: the 1-minute load is $load (above 10): not starting" >&2; exit 1; }
    if [ -z "${ABSD_USERLAND_ONLY:-}" ] && [ -n "$(git -C "$root" status --porcelain)" ]; then
        git -C "$root" status --short >&2
        echo "run-userland-matrix: a full run needs a clean tree (the log names HEAD)" >&2; exit 1
    fi
    mkdir -p "$out"
    rm -f "$out/run-userland-matrix.status"
    { rc=0; ABSD_RUN_USERLAND_CHILD=1 sh "$0" "$@" 2>&1 || rc=$?; echo "$rc" > "$out/run-userland-matrix.status"; } |
        tee "$out/run-userland-matrix.log"
    exit "$(cat "$out/run-userland-matrix.status")"
fi

echo "RUN-USERLAND start $(date -u +%Y-%m-%dT%H:%M:%SZ) source=$(git -C "$root" rev-parse HEAD) dirty=$([ -n "$(git -C "$root" status --porcelain)" ] && echo yes || echo no) niceness=$(nice) load=$(cut -d' ' -f1 /proc/loadavg) kernel=$(git -C "$kernel" rev-parse HEAD 2>/dev/null || echo unknown) platform=$platform"
selftest=$out/selftest
rm -rf "$selftest"
python3 -I "$root/scripts/userland-matrix-selftest.py" --work "$selftest" > "$out/selftest.log" 2>&1 ||
    { tail -20 "$out/selftest.log"; echo "run-userland-matrix: the self-test failed" >&2; exit 1; }
tail -1 "$out/selftest.log"

work=$out/matrix
[ -e "$work" ] && chmod -R u+w "$work"
rm -rf "$work" "$out/matrix.log" "$out/matrix.status"
set --
[ -z "${ABSD_USERLAND_ONLY:-}" ] || set -- --only "$ABSD_USERLAND_ONLY"
[ -z "${ABSD_USERLAND_PINS:-}" ] || set -- "$@" --pins "$ABSD_USERLAND_PINS"
{ rc=0; python3 -I "$root/scripts/userland-matrix.py" --work "$work" "$@" -- \
    --kernel "$kernel" --platform "$platform" --qemu "qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand" \
    --shell "$platform/commands/absd-sh" --boot-seconds 14400 2>&1 || rc=$?; echo "$rc" > "$out/matrix.status"; } |
    tee "$out/matrix.log" | grep -E '^(USERLAND (ARGS|IMPORT|DEFECT|PIN|INTERRUPT|DEMO|NOT_RUN|RESOURCES OK|PINS|MATRIX)|ABSD USERLAND)' || true
status=$(cat "$out/matrix.status")
[ "$status" = 0 ] || { tail -20 "$out/matrix.log"; echo "run-userland-matrix: the matrix failed (log $out/matrix.log)" >&2; exit 1; }
grep -q '^ABSD USERLAND GUEST OK ' "$out/matrix.log" || { echo "run-userland-matrix: no ABSD USERLAND GUEST OK" >&2; exit 1; }
