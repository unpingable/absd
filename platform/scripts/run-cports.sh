#!/bin/sh
# Stage 2 end to end (plan Task 13): the adapter's host tests, the adapter
# archive, the staged upstream sources, every product built for ABSD and for
# Linux, then the cports matrix with every case (one boot plus the stopping
# scenarios' restarts). Each step failing fails the script. On success the
# receipts (sizes, demand lists, the two reproducibility rounds, the adapter
# archive's hash, the matrix log and its sshd serial logs, and this script's
# own log) are copied into docs/c-ecosystem-20261010/posix/receipts/ and the
# summary line is printed from the markers.
# Environment: ABSD_KERNEL_RUN (required; a disposable kernel clone, never
# the protected kernel source); ABSD_SKIP_BUILD=1 reuses the adapter archive, the
# staged sources and the products; ABSD_CPORTS_ONLY=<prefix> is passed to the
# matrix as --only (a partial run copies no receipt, nor does a run with
# ABSD_SKIP_BUILD=1, whose build receipts would predate its matrix log); ABSD_CPORTS_PLATFORM
# (default <campaign>/c-kit) is the platform tree that holds the boot ELFs
# and commands/absd-sh. The build layout defaults to the campaign's, beside
# this tree; ABSD_CKIT_BUILD (<campaign>/ckit-build), ABSD_CPORTS_BUILD
# (<campaign>/cports-build) and ABSD_CPORTS_UPSTREAM (<campaign>/upstream)
# override it here and in the scripts this one runs.
# Host rules (plan; final review M10), enforced here: the script re-executes
# itself under nice so it runs at niceness 10 or more; it refuses to start
# when the 1-minute load is above 10; and a full run (one that writes
# receipts) refuses a working tree with any change or untracked file, so the
# receipt's source= names exactly what ran. Any other run prints dirty=.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
camp=$(dirname "$root")
out=${ABSD_CPORTS_BUILD:-$camp/cports-build}
up=${ABSD_CPORTS_UPSTREAM:-$camp/upstream}
receipts=$root/docs/c-ecosystem-20261010/posix/receipts
boot_seconds=${ABSD_CPORTS_BOOT_SECONDS:-3600}
[ "$boot_seconds" -gt 0 ] 2>/dev/null ||
    { echo "run-cports: ABSD_CPORTS_BOOT_SECONDS must be a positive integer" >&2; exit 1; }
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel clone}
[ -d "$kernel" ] || { echo "run-cports: ABSD_KERNEL_RUN $kernel is not a directory" >&2; exit 1; }
forbidden=/data/git/absd-kernel
[ -d "$forbidden" ] && forbidden=$(CDPATH= cd -- "$forbidden" && pwd -P)
[ "$(CDPATH= cd -- "$kernel" && pwd -P)" != "$forbidden" ] ||
    { echo "run-cports: ABSD_KERNEL_RUN must not be /data/git/absd-kernel" >&2; exit 1; }
platform=${ABSD_CPORTS_PLATFORM:-$camp/c-kit}

# The whole pipeline's output is also written to $out/run-cports.log: the
# script runs itself as a child and keeps the child's status.
if [ -z "${ABSD_RUN_CPORTS_CHILD:-}" ]; then
    niceness=$(nice)
    [ "$niceness" -ge 10 ] || exec nice -n $((10 - niceness)) sh "$0" "$@"
    load=$(cut -d' ' -f1 /proc/loadavg)
    awk -v l="$load" 'BEGIN { exit !(l <= 10) }' ||
        { echo "run-cports: the 1-minute load is $load (above 10): not starting" >&2; exit 1; }
    if [ -z "${ABSD_CPORTS_ONLY:-}" ] && [ "${ABSD_SKIP_BUILD:-0}" != 1 ] && [ -n "$(git -C "$root" status --porcelain)" ]; then
        git -C "$root" status --short >&2
        echo "run-cports: a full run needs a clean tree (the receipt names HEAD)" >&2; exit 1
    fi
    mkdir -p "$out"
    rm -f "$out/run-cports.status"
    # set -e would end the left side before the status is written: capture it.
    { rc=0; ABSD_RUN_CPORTS_CHILD=1 sh "$0" "$@" 2>&1 || rc=$?; echo "$rc" > "$out/run-cports.status"; } | tee "$out/run-cports.log"
    rc=$(cat "$out/run-cports.status")
    if [ "$rc" = 0 ] && [ -z "${ABSD_CPORTS_ONLY:-}" ] && [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then cp "$out/run-cports.log" "$receipts/run-cports.log"; fi
    exit "$rc"
fi

echo "RUN-CPORTS start $(date -u +%Y-%m-%dT%H:%M:%SZ) source=$(git -C "$root" rev-parse HEAD) dirty=$([ -n "$(git -C "$root" status --porcelain)" ] && echo yes || echo no) niceness=$(nice) load=$(cut -d' ' -f1 /proc/loadavg) kernel=$(git -C "$kernel" rev-parse HEAD 2>/dev/null || echo unknown) skip_build=${ABSD_SKIP_BUILD:-0}"
host=$(sh "$root/scripts/check-posix-host.sh")
echo "$host"
host_tests=$(printf '%s\n' "$host" | sed -n 's/^ABSD POSIX HOST TESTS OK tests=\([0-9]*\)$/\1/p')
[ -n "$host_tests" ] || { echo "run-cports: no host-test marker" >&2; exit 1; }

if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    sh "$root/scripts/build-posix.sh"
    sh "$root/scripts/stage-cports.sh"
    sh "$root/scripts/build-cports.sh" > "$out/build-cports.log" 2>&1 ||
        { tail -40 "$out/build-cports.log"; echo "run-cports: build-cports.sh failed" >&2; exit 1; }
    grep -E '^(C ELF OK|DEMAND|CPORTS BUILD OK)' "$out/build-cports.log"
    grep -q '^CPORTS BUILD OK ' "$out/build-cports.log" || { echo "run-cports: no CPORTS BUILD OK" >&2; exit 1; }
fi
for f in "$out/lib/libabsd-posix.a" "$out/sizes.txt" "$out/repro/round1.sha256" "$out/repro/round2.sha256"; do
    test -f "$f" || { echo "run-cports: $f missing (run with ABSD_SKIP_BUILD=0)" >&2; exit 1; }
done
products=$(wc -l < "$out/sizes.txt")

work=$out/matrix
[ -e "$work" ] && chmod -R u+w "$work"
rm -rf "$work" "$out/matrix.log" "$out/matrix.status"
# The optional --only goes through the positional parameters, never an
# unquoted expansion (a prefix is not a glob).
set --
[ -z "${ABSD_CPORTS_ONLY:-}" ] || set -- --only "$ABSD_CPORTS_ONLY"
# ABSD_CPORTS_PIN=<case> re-pins one listed divergence from this run (the matrix prints "review it before committing").
[ -z "${ABSD_CPORTS_PIN:-}" ] || set -- "$@" --pin "$ABSD_CPORTS_PIN"
{ rc=0; python3 -I "$root/scripts/cports-matrix.py" --work "$work" --absd "$out/absd" --linux "$out/linux" \
    --cases "$root/cports/cases.tsv" --upstream "$up" "$@" -- \
    --kernel "$kernel" --platform "$platform" --qemu "qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand" \
    --shell "$platform/commands/absd-sh" --boot-seconds "$boot_seconds" 2>&1 || rc=$?; echo "$rc" > "$out/matrix.status"; } |
    tee "$out/matrix.log" | grep -E '^CPORTS (ARGS|ONE.BIN|IMPORT|LIMIT|SCENARIO|SQLITE|DEFECT|SHELL|RESOURCES (OK|STEP)|TIMINGS|MATRIX)' || true
[ "$(cat "$out/matrix.status")" = 0 ] || { tail -20 "$out/matrix.log"; echo "run-cports: the matrix failed (log $out/matrix.log)" >&2; exit 1; }
grep -q '^CPORTS MATRIX OK ' "$out/matrix.log" || { echo "run-cports: no CPORTS MATRIX OK" >&2; exit 1; }
shell=$(grep '^CPORTS SHELL OK ' "$out/matrix.log")
field() { printf '%s\n' "$shell" | sed -n "s/.* $1=\([0-9]*\).*/\1/p"; }

if [ -z "${ABSD_CPORTS_ONLY:-}" ] && [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    rm -rf "$receipts/demand"; mkdir -p "$receipts/demand"
    cp "$out/absd/"*.demand "$receipts/demand/"
    cp "$out/sizes.txt" "$receipts/sizes.txt"
    cp "$out/repro/round1.sha256" "$receipts/reproducible-round1.sha256"
    cp "$out/repro/round2.sha256" "$receipts/reproducible-round2.sha256"
    (cd "$out" && sha256sum lib/libabsd-posix.a) > "$receipts/libabsd-posix.sha256"
    rm -f "$receipts/matrix-full.log" "$receipts"/matrix-full-sshd-*.serial.log
    cp "$out/matrix.log" "$receipts/matrix-full.log"
    for s in "$work"/sshd-*.serial.log; do cp "$s" "$receipts/matrix-full-$(basename "$s")"; done
fi
printf '%s\n' "ABSD POSIX STAGE2 OK host_tests=$host_tests products=$products cases=$(field cases) agree=$(field agree) diverge=$(field diverge) scenarios=$(field scenarios) limits=$(field limits) defects=$(field defects) probes=$(field probes)"
