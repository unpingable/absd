#!/bin/sh
# Successor: individual statuses remain primary; terminal intake is mandatory.
set -e
[ "$#" -gt 0 ] || { echo "case selection required" >&2; exit 1; }
# Each named matrix case once, own work dir, gated; stops on a failure; existing work is refused.
W=${ABSD_COMPOSITION_PLATFORM:?clean composed worktree required}
G=${ABSD_COMPOSITION_RUN_ROOT:?fresh occurrence root required}
K=$G/work/KA
KEY=${ABSD_COMPOSITION_KEY:?occurrence key required}
cd $W
export ABSD_CKIT_BUILD=$W/.fence-work/ckit-build ABSD_USERLAND_BUILD=$W/.fence-work/userland-build ABSD_CPORTS_BUILD=$W/.fence-work/cports-build
for c in "$@"; do
  case "$c" in
    m1|s1|m2|m3|p0|p0c|p0n|r4a|r2a|r2b|r2c|r3a|r3b|r3c|r1a|r1b|r4b|r4d|r4f|l4|l5|l6|l7|b2|b3|b4|b5|b6|b7|l3|s2) ;;
    *) echo "unknown matrix case: $c" >&2; exit 1 ;;
  esac
  $G/tools/gate.sh $G/logs/load-gate.log case-$c || { echo "case $c GATE-REFUSED" >> $G/logs/cases.log; exit 1; }
  work=$W/.fence-work/resume-runs-${ABSD_COMPOSITION_RUN:?fresh run id required}/$c
  if [ -e "$work" ]; then echo "case $c work exists; not run" >> $G/logs/cases.log; exit 1; fi
  mkdir -p $(dirname $work)
  echo "case $c start $(date -u +%FT%T.%3NZ) tip=$(git rev-parse --short=8 HEAD) work=$work" >> $G/logs/cases.log
  rc=0
  ABSD_PROFILE=core taskset -c 2-5,8-11 nice -n 10 python3 -I $W/scripts/storage-fence-resume-matrix.py --work "$work" \
    --kernel $K --platform $W \
    --release $W/.fence-work/resume-releases/dev --other-release $W/.fence-work/resume-releases/other \
    --qemu "qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand" --accel tcg \
    --key $KEY --cases $c > $G/logs/case-$c.log 2>&1 || rc=$?
  echo "case $c end $(date -u +%FT%T.%3NZ) rc=$rc" >> $G/logs/cases.log
  census=$($G/tools/gate.sh --list) || { exit 1; }
  if printf '%s\n' "$census" | grep -q '^other'; then
    printf '%s\n' "$census" | grep '^other' | sed "s/^/LEFTOVER after $c: /" >> $G/logs/cases.log
    exit 1
  fi
  [ "$rc" = 0 ] || exit "$rc"
done
echo "cases batch done $(date -u +%FT%T.%3NZ)" >> $G/logs/cases.log
