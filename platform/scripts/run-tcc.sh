#!/bin/sh
# Public snapshot: the omitted TinyCC stage is never a passing test.
printf '%s\n' 'TCC STAGE NOT_RUN: not included in the public source' >&2
exit 78
# Stage 3 end to end (plan Task 6): stage TinyCC at the pin, build it (host
# half: patches, host/hostcfg compilers, the /share/absd-c tree; cross half:
# /bin/tcc by absd-cc in two rounds), run the kernel-exact gate over every
# hostcfg output (each kit test image accepted, the unpatched hello-relro.elf
# refused for PT_GNU_RELRO), then the guest matrix with every case (no
# --only). Each step failing fails the script. On success of a full run the
# receipts (stage.txt, hostbuild.txt, share.sha256, sizes.txt,
# unpatched-init-fini.txt, tcc.demand,
# the two reproducibility rounds, the matrix log and its serial logs, and
# this script's own log) are copied into docs/c-ecosystem-20261010/tcc/receipts/
# and the summary line is printed from the markers:
#   ABSD TCC STAGE3 OK cases=<n> agree=<n> diverge=<n> defects=<n> tcc_bytes=<n> share_bytes=<n>
# A run that is not full (ABSD_TCC_ONLY, ABSD_SKIP_BUILD=1, or a matrix that
# reports PARTIAL) prints `ABSD TCC STAGE3 PARTIAL ... :: <reasons>` instead.
# The imported /bin/tcc must equal round2.sha256's absd/tcc (TCC IMPORT BOUND).
# Environment: ABSD_KERNEL_RUN (required; a disposable kernel clone, never
# the protected kernel source); ABSD_SKIP_BUILD=1 reuses the staged tree and the
# builds; ABSD_TCC_ONLY=<prefix> runs only the cases whose name starts with
# the prefix (a partial run copies no receipt, nor does a run with
# ABSD_SKIP_BUILD=1, whose build receipts would predate its matrix log);
# ABSD_TCC_PLATFORM (default <campaign>/c-kit) is the platform tree that holds
# the boot ELFs and commands/absd-sh.
# Host rules (Stage 2's, unchanged): the script re-executes itself under nice
# so it runs at niceness 10 or more; it refuses to start when the 1-minute
# load is above 10; a full run refuses a working tree with any change or
# untracked file, so the receipt's source= names exactly what ran.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
camp=$(dirname "$root")
out=$camp/tcc-build
receipts=$root/docs/c-ecosystem-20261010/tcc/receipts
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel clone}
[ -d "$kernel" ] || { echo "run-tcc: ABSD_KERNEL_RUN $kernel is not a directory" >&2; exit 1; }
forbidden=/data/git/absd-kernel
[ -d "$forbidden" ] && forbidden=$(CDPATH= cd -- "$forbidden" && pwd -P)
[ "$(CDPATH= cd -- "$kernel" && pwd -P)" != "$forbidden" ] ||
    { echo "run-tcc: ABSD_KERNEL_RUN must not be /data/git/absd-kernel" >&2; exit 1; }
platform=${ABSD_TCC_PLATFORM:-$camp/c-kit}
full() { [ -z "${ABSD_TCC_ONLY:-}" ] && [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; }

# The whole pipeline's output is also written to $out/run-tcc.log: the script
# runs itself as a child and keeps the child's status.
if [ -z "${ABSD_RUN_TCC_CHILD:-}" ]; then
    niceness=$(nice)
    [ "$niceness" -ge 10 ] || exec nice -n $((10 - niceness)) sh "$0" "$@"
    load=$(cut -d' ' -f1 /proc/loadavg)
    awk -v l="$load" 'BEGIN { exit !(l <= 10) }' ||
        { echo "run-tcc: the 1-minute load is $load (above 10): not starting" >&2; exit 1; }
    if full && [ -n "$(git -C "$root" status --porcelain)" ]; then
        git -C "$root" status --short >&2
        echo "run-tcc: a full run needs a clean tree (the receipt names HEAD)" >&2; exit 1
    fi
    mkdir -p "$out"
    rm -f "$out/run-tcc.status"
    # set -e would end the left side before the status is written: capture it.
    { rc=0; ABSD_RUN_TCC_CHILD=1 sh "$0" "$@" 2>&1 || rc=$?; echo "$rc" > "$out/run-tcc.status"; } | tee "$out/run-tcc.log"
    rc=$(cat "$out/run-tcc.status")
    if [ "$rc" = 0 ] && full; then cp "$out/run-tcc.log" "$receipts/run-tcc.log"; fi
    exit "$rc"
fi

echo "RUN-TCC start $(date -u +%Y-%m-%dT%H:%M:%SZ) source=$(git -C "$root" rev-parse HEAD) dirty=$([ -n "$(git -C "$root" status --porcelain)" ] && echo yes || echo no) niceness=$(nice) load=$(cut -d' ' -f1 /proc/loadavg) kernel=$(git -C "$kernel" rev-parse HEAD 2>/dev/null || echo unknown) skip_build=${ABSD_SKIP_BUILD:-0} only=${ABSD_TCC_ONLY:-}"

if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    sh "$root/scripts/stage-tcc.sh"
    sh "$root/scripts/build-tcc.sh" > "$out/build-tcc.log" 2>&1 ||
        { tail -40 "$out/build-tcc.log"; echo "run-tcc: build-tcc.sh failed (log $out/build-tcc.log)" >&2; exit 1; }
    grep -E '^(TCC (STAGE|PATCH|SHARE|P2|R2|KIT|HOSTBUILD|PATHFREE|BUILD)|ABI ELF|C ELF OK|DEMAND)' "$out/build-tcc.log" || true
    grep -q '^TCC HOSTBUILD OK ' "$out/build-tcc.log" || { echo "run-tcc: no TCC HOSTBUILD OK" >&2; exit 1; }
    grep -q '^TCC BUILD OK ' "$out/build-tcc.log" || { echo "run-tcc: no TCC BUILD OK" >&2; exit 1; }
fi
for f in "$out/stage.txt" "$out/hostbuild.txt" "$out/share.sha256" "$out/sizes.txt" "$out/absd/tcc" "$out/absd/tcc.demand" \
         "$out/repro/round1.sha256" "$out/repro/round2.sha256" "$out/hostcfg-unpatched/hello-relro.elf" "$out/unpatched-init-fini.txt"; do
    test -f "$f" || { echo "run-tcc: $f missing (run with ABSD_SKIP_BUILD=0)" >&2; exit 1; }
done
tcc_bytes=$(awk -F'\t' '$1=="tcc"{print $2}' "$out/sizes.txt")
share_bytes=$(awk -F'\t' '$1=="share"{print $2}' "$out/sizes.txt")
[ -n "$tcc_bytes" ] && [ -n "$share_bytes" ] || { echo "run-tcc: sizes.txt lacks the tcc or share row" >&2; exit 1; }

# The kernel-exact gate over every hostcfg output (advice; the guest spawn is
# the truth): every image the patched hostcfg tcc wrote is accepted, the
# unpatched build's image is refused for PT_GNU_RELRO.
gate() { python3 -I "$root/scripts/check-abi-elf.py" "$1"; }
accepted=0
for e in "$out"/hostcfg/verify/*.elf; do
    [ -e "$e" ] || continue
    line=$(gate "$e") || { echo "$line" >&2; echo "run-tcc: the gate refuses $e" >&2; exit 1; }
    echo "$line"; accepted=$((accepted + 1))
done
[ "$accepted" -gt 0 ] || { echo "run-tcc: no hostcfg output to gate" >&2; exit 1; }
if line=$(gate "$out/hostcfg-unpatched/hello-relro.elf"); then
    echo "$line" >&2; echo "run-tcc: the unpatched image was accepted" >&2; exit 1
fi
echo "$line"
case $line in *"type 0x6474e552)"*) ;; *) echo "run-tcc: the unpatched refusal is not PT_GNU_RELRO" >&2; exit 1 ;; esac
echo "TCC GATE OK accepted=$accepted refused=1 :: every hostcfg output accepted; hostcfg-unpatched/hello-relro.elf refused (PT_GNU_RELRO)"

work=$out/matrix/run-tcc
[ -e "$work" ] && chmod -R u+w "$work"
rm -rf "$work" "$out/matrix.log" "$out/matrix.status"
# ABSD_TCC_ONLY is a prefix: each case of cases.tsv whose name starts with it
# goes to the matrix as --only (through the positional parameters, never an
# unquoted expansion; the prefix reaches awk through ENVIRON, uninterpreted).
set --
if [ -n "${ABSD_TCC_ONLY:-}" ]; then
    names=$(ABSD_TCC_PREFIX=$ABSD_TCC_ONLY awk -F'\t' '$1 !~ /^#/ && NF >= 3 && index($1, ENVIRON["ABSD_TCC_PREFIX"]) == 1 {print $1}' "$root/tcc/cases.tsv")
    while IFS= read -r c; do
        [ -n "$c" ] && set -- "$@" --only "$c"
    done <<EOF_NAMES
$names
EOF_NAMES
    [ $# -gt 0 ] || { echo "run-tcc: no case starts with $ABSD_TCC_ONLY" >&2; exit 1; }
fi
{ rc=0; python3 -I "$root/scripts/tcc-matrix.py" --work "$work" --tcc-build "$out" --kit "${ABSD_TCC_KIT:-$camp/c-kit}" \
    --cases "$root/tcc/cases.tsv" "$@" -- \
    --kernel "$kernel" --platform "$platform" --qemu "qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand" \
    --shell "$platform/commands/absd-sh" --boot-seconds 14400 2>&1 || rc=$?; echo "$rc" > "$out/matrix.status"; } |
    tee "$out/matrix.log" | grep -E '^(ABSD TCC STAGE3 FAILED|TCC (ARGS|IMPORT|CASE|FINDING|REFERENCE LIMITATION|RESOURCES REPEAT|TIMINGS|MATRIX))|^CPORTS RESOURCES (OK|STEP)' || true
[ "$(cat "$out/matrix.status")" = 0 ] || { tail -20 "$out/matrix.log"; echo "run-tcc: the matrix failed (log $out/matrix.log)" >&2; exit 1; }
grep -q '^TCC MATRIX OK ' "$out/matrix.log" || { echo "run-tcc: no TCC MATRIX OK" >&2; exit 1; }
# Final review M3: the /bin/tcc the matrix imported is the reproducible
# build's, by digest (round2.sha256's absd/tcc line; round1 equals it).
imported=$(sed -n 's/^TCC IMPORT TCC sha256=\([0-9a-f]\{64\}\) hostcfg_sha256=\([0-9a-f]\{64\}\) .*/\1/p' "$out/matrix.log")
built=$(awk '$2 == "absd/tcc" {print $1}' "$out/repro/round2.sha256")
if [ -z "$imported" ] || [ "$imported" != "$built" ]; then
    echo "run-tcc: the imported /bin/tcc (${imported:-no TCC IMPORT TCC line}) is not round2.sha256's absd/tcc (${built:-none})" >&2; exit 1
fi
echo "TCC IMPORT BOUND sha256=$imported :: the imported /bin/tcc equals round2.sha256's absd/tcc"
summary=$(grep -E '^ABSD TCC STAGE3 (OK|PARTIAL) ' "$out/matrix.log") || { echo "run-tcc: no ABSD TCC STAGE3 OK or PARTIAL from the matrix" >&2; exit 1; }
field() { printf '%s\n' "$summary" | sed -n "s/.* $1=\([0-9]*\).*/\1/p"; }
# Final review M4: OK only for a full run (every case, the builds of this
# run, no pin written); anything else is PARTIAL with its reasons.
partial=
if [ -n "${ABSD_TCC_ONLY:-}" ]; then partial="$partial only=$ABSD_TCC_ONLY"; fi
if [ "${ABSD_SKIP_BUILD:-0}" = 1 ]; then partial="$partial skip_build=1"; fi
case $summary in "ABSD TCC STAGE3 PARTIAL "*) partial="$partial matrix=partial" ;; esac

if full && [ -z "$partial" ]; then
    rm -f "$receipts"/matrix.log "$receipts"/matrix-*.serial.log
    cp "$out/matrix.log" "$receipts/matrix.log"
    for s in "$work"/import-*.serial.log "$work"/sshd-*.serial.log; do cp "$s" "$receipts/matrix-$(basename "$s")"; done
    for f in stage.txt hostbuild.txt share.sha256 sizes.txt unpatched-init-fini.txt; do cp "$out/$f" "$receipts/$f"; done
    cp "$out/absd/tcc.demand" "$receipts/tcc.demand"
    cp "$out/repro/round1.sha256" "$receipts/round1.sha256"
    cp "$out/repro/round2.sha256" "$receipts/round2.sha256"
fi
line="cases=$(field cases) agree=$(field agree) diverge=$(field diverge) defects=$(field defects) tcc_bytes=$tcc_bytes share_bytes=$share_bytes"
if [ -n "$partial" ]; then
    printf '%s\n' "ABSD TCC STAGE3 PARTIAL $line ::$partial (not a full run; no receipt copied)"
else
    printf '%s\n' "ABSD TCC STAGE3 OK $line"
fi
