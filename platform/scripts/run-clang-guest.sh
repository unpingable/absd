#!/bin/sh
# Native Clang T4-T6 in the guest (docs/native-clang-20261012/GUEST-RUN.md):
# CL1 (lld and the split front end start on ABSD) and CL2/CL3 (the split
# pipeline compiles, links and runs hello.c in one absd-sh session), through
# scripts/clang-guest-matrix.py with the cases of
# cxx/tests/llvm/guest-cases.tsv. Nothing is built here: the LLVM images,
# the twin and the C kit are T2's (llvm-build/, read only), the platform
# tree is a built one the caller names.
#
# Steps: the host self-test (scripts/clang-guest-selftest.py, no QEMU), then
# the matrix (its host side re-derives every pin from the Linux twin, then
# one fixture, ~87 import boots, one sshd boot). Each step failing fails the
# script. A full run (every case) that passes copies its receipts into
# docs/native-clang-20261012/receipts/ and prints the matrix's summary:
#   ABSD CLANG GUEST OK cases=<n> ok=<n> failed=0 import_boots=<n>
# A run of some cases (ABSD_CLANG_ONLY) prints ABSD CLANG GUEST PARTIAL and
# copies nothing.
# Environment: ABSD_KERNEL_RUN (required; a disposable kernel clone, never
# the protected kernel source); ABSD_CLANG_PLATFORM (required; a built platform
# tree at candidate 2: sshd.elf absd-fsd.elf fixture-import.elf sshtest.elf
# fsd-probe.elf, commands/ and manpages/); ABSD_CLANG_LLVM (default
# <campaign>/llvm-build); ABSD_CLANG_KIT (default: the kit named in
# llvm-build/kit/BUILT-FROM); ABSD_CLANG_ONLY=<prefix> runs only the cases
# whose name starts with it.
# Host rules (U1's): the script re-executes itself under nice so it runs at
# niceness 10 or more; it refuses to start when the 1-minute load is above
# 10, and the matrix re-checks the load (and that no QEMU of this run is
# still up) before every QEMU launch; one run at a time (a lock directory);
# a full run refuses a working tree with any change or untracked file.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
camp=$(dirname "$root")
out=$camp/guest-run
receipts=$root/docs/native-clang-20261012/receipts
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel clone}
[ -d "$kernel" ] || { echo "run-clang-guest: ABSD_KERNEL_RUN $kernel is not a directory" >&2; exit 1; }
forbidden=/data/git/absd-kernel
[ -d "$forbidden" ] && forbidden=$(CDPATH= cd -- "$forbidden" && pwd -P)
[ "$(CDPATH= cd -- "$kernel" && pwd -P)" != "$forbidden" ] ||
    { echo "run-clang-guest: ABSD_KERNEL_RUN must not be /data/git/absd-kernel" >&2; exit 1; }
platform=${ABSD_CLANG_PLATFORM:?set ABSD_CLANG_PLATFORM to a built platform tree}
llvm=${ABSD_CLANG_LLVM:-$camp/llvm-build}
kit=${ABSD_CLANG_KIT:-$(sed -n 's/^kit \(\/[^ ]*\) .*/\1/p' "$llvm/kit/BUILT-FROM")}
[ -n "$kit" ] && [ -d "$kit" ] || { echo "run-clang-guest: no kit (ABSD_CLANG_KIT or llvm-build/kit/BUILT-FROM)" >&2; exit 1; }
cases=$root/cxx/tests/llvm/guest-cases.tsv
full() { [ -z "${ABSD_CLANG_ONLY:-}" ]; }

if [ -z "${ABSD_RUN_CLANG_CHILD:-}" ]; then
    niceness=$(nice)
    [ "$niceness" -ge 10 ] || exec nice -n $((10 - niceness)) sh "$0" "$@"
    load=$(cut -d' ' -f1 /proc/loadavg)
    awk -v l="$load" 'BEGIN { exit !(l <= 10) }' ||
        { echo "run-clang-guest: the 1-minute load is $load (above 10): not starting" >&2; exit 1; }
    if full && [ -n "$(git -C "$root" status --porcelain)" ]; then
        git -C "$root" status --short >&2
        echo "run-clang-guest: a full run needs a clean tree (the receipt names HEAD)" >&2; exit 1
    fi
    mkdir -p "$camp"
    lock=$out.lock
    mkdir "$lock" 2>/dev/null || { echo "run-clang-guest: another run holds $lock" >&2; exit 1; }
    trap 'rmdir "$lock"' EXIT
    mkdir -p "$out"
    rm -f "$out/run.status" "$out/receipts.copied"
    { rc=0; ABSD_RUN_CLANG_CHILD=1 sh "$0" "$@" 2>&1 || rc=$?; echo "$rc" > "$out/run.status"; } | tee "$out/run.log"
    rc=$(cat "$out/run.status")
    if [ "$rc" = 0 ] && [ -f "$out/receipts.copied" ]; then cp "$out/run.log" "$receipts/run.log"; fi
    exit "$rc"
fi

# The kernel stamp: what the copy says it is (.absd-identity, written by
# scripts/inputs.sh or whoever made the copy), else its own HEAD only when it
# is a checkout. A copy with neither is `unknown`: `git -C` on a directory
# without .git walks up to an enclosing repository and prints that one's HEAD
# (the first guest run stamped the protected kernel source HEAD this way; GUEST-RESULT.md).
# BEGIN kernel_stamp
kernel_stamp() {
    if [ -f "$1/.absd-identity" ]; then
        head -n 1 "$1/.absd-identity"
    elif [ -e "$1/.git" ]; then
        git -C "$1" rev-parse HEAD 2>/dev/null || echo unknown
    else
        echo unknown
    fi
}
# END kernel_stamp

echo "RUN-CLANG-GUEST start $(date -u +%Y-%m-%dT%H:%M:%SZ) source=$(git -C "$root" rev-parse HEAD) dirty=$([ -n "$(git -C "$root" status --porcelain)" ] && echo yes || echo no) niceness=$(nice) load=$(cut -d' ' -f1 /proc/loadavg) kernel=$(kernel_stamp "$kernel") platform=$platform platform_head=$(git -C "$platform" rev-parse HEAD 2>/dev/null || echo unknown) llvm=$llvm kit=$kit only=${ABSD_CLANG_ONLY:-}"
for f in sshd.elf absd-fsd.elf fixture-import.elf sshtest.elf fsd-probe.elf manpages/whatis commands/absd-sh \
         commands/cp commands/sha256sum commands/ls commands/mkdir commands/cat commands/df commands/sysinfo commands/printenv; do
    test -f "$platform/$f" || { echo "run-clang-guest: $platform/$f missing (build the platform tree first)" >&2; exit 1; }
done

rm -rf "$out/selftest"
python3 -I "$root/scripts/clang-guest-selftest.py" --work "$out/selftest" --llvm-build "$llvm" --kit "$kit" \
    --platform "$platform" > "$out/selftest.log" 2>&1 || { grep -v '^  ok ' "$out/selftest.log" | tail -20; echo "run-clang-guest: the self-test failed" >&2; exit 1; }
grep '^CLANG SELFTEST OK' "$out/selftest.log"

# ABSD_CLANG_ONLY is a prefix: each case of the table whose name starts with
# it goes to the matrix as --only (through the positional parameters; the
# prefix reaches awk through ENVIRON, uninterpreted).
set --
if [ -n "${ABSD_CLANG_ONLY:-}" ]; then
    names=$(ABSD_CLANG_PREFIX=$ABSD_CLANG_ONLY awk -F'\t' '$1 !~ /^#/ && NF >= 3 && index($1, ENVIRON["ABSD_CLANG_PREFIX"]) == 1 {print $1}' "$cases")
    while IFS= read -r c; do
        [ -n "$c" ] && set -- "$@" --only "$c"
    done <<EOF_NAMES
$names
EOF_NAMES
    [ $# -gt 0 ] || { echo "run-clang-guest: no case starts with $ABSD_CLANG_ONLY" >&2; exit 1; }
fi
work=$out/matrix
[ -e "$work" ] && chmod -R u+w "$work"
rm -rf "$work" "$out/matrix.log" "$out/matrix.status"
{ rc=0; python3 -I "$root/scripts/clang-guest-matrix.py" --work "$work" --llvm-build "$llvm" --kit "$kit" --cases "$cases" "$@" -- \
    --kernel "$kernel" --platform "$platform" --qemu "qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand" \
    --shell "$platform/commands/absd-sh" --boot-seconds 14400 2>&1 || rc=$?; echo "$rc" > "$out/matrix.status"; } |
    tee "$out/matrix.log" | grep -E '^(ABSD CLANG GUEST|CLANG (HOST|GUEST) (IMAGE|PIN|RSP|TWIN|FIXTURE|IMPORT|BOOT|SESSION|CAPACITY|STEP|OK|FAILED|GATE|KIT|RESOURCES|LOAD))' || true
[ "$(cat "$out/matrix.status")" = 0 ] || { tail -20 "$out/matrix.log"; echo "run-clang-guest: the matrix failed (log $out/matrix.log)" >&2; exit 1; }
grep -q '^CLANG GUEST MATRIX OK ' "$out/matrix.log" || { echo "run-clang-guest: no CLANG GUEST MATRIX OK" >&2; exit 1; }
summary=$(grep -E '^ABSD CLANG GUEST (OK|PARTIAL) ' "$out/matrix.log") || { echo "run-clang-guest: no summary from the matrix" >&2; exit 1; }
case $summary in
    "ABSD CLANG GUEST OK "*)
        if full; then
            mkdir -p "$receipts"
            rm -f "$receipts"/matrix.log "$receipts"/sshd-*.serial.log "$receipts"/selftest.log "$receipts"/import-serial.sha256
            cp "$out/matrix.log" "$out/selftest.log" "$receipts/"
            for s in "$work"/sshd-*.serial.log; do cp "$s" "$receipts/"; done
            ( cd "$work" && sha256sum import-*.serial.log ) > "$receipts/import-serial.sha256"
            : > "$out/receipts.copied"
        fi ;;
esac
printf '%s\n' "$summary"
