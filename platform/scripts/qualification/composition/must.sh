#!/bin/sh
set -e
W=${ABSD_COMPOSITION_PLATFORM:?clean composed worktree required}
G=${ABSD_COMPOSITION_RUN_ROOT:?fresh occurrence root required}
P=$G/logs/pipeline.log
# Separate producer stages so a failed find/sort cannot be hidden by a pipe.
digests() {
  ( cd "$1" || exit 1
    find . -type f -print0 > "$2.files" || exit 1
    sort -z "$2.files" > "$2.sorted" || exit 1
    xargs -0 sha256sum < "$2.sorted"
  ) > "$2" || return 1
  rm -f "$2.files" "$2.sorted" || return 1
}
cd $W
python3 -I scripts/storage-fence-resume-matrix.py --host-only > $G/logs/selftest.log 2>&1; echo "selftest rc=$? $(tail -1 $G/logs/selftest.log)" >> $P
python3 -I scripts/check-storage-fence-frozen.py > $G/logs/frozen.log 2>&1; echo "frozen rc=$? $(tail -1 $G/logs/frozen.log)" >> $P
echo "MUST matrix start $(date -u +%FT%TZ)" >> $P
$G/tools/cases.sh m1 s1 m2 m3
echo "MUST updates start $(date -u +%FT%TZ)" >> $P
$G/tools/regress.sh updates
echo "MUST F2 start $(date -u +%FT%TZ)" >> $P
cp -a $W/.fence-work/resume-releases/dev $G/work/A
digests "$G/work/A" "$G/logs/A-sha256.txt"
digests "$W/.fence-work/resume-releases/dev" "$G/logs/source-sha256.txt"
diff "$G/logs/source-sha256.txt" "$G/logs/A-sha256.txt" > /dev/null && echo "A copy identical" >> $P || { echo "A copy DIFFERS" >> $P; exit 1; }
$G/tools/f2.sh
echo "MUST C7 start $(date -u +%FT%TZ)" >> $P
KEY=${ABSD_COMPOSITION_KEY:?occurrence key required}
for leg in tool_busy recovery_pending; do
  $G/tools/gate.sh $G/logs/load-gate.log c7-$leg || { echo "c7 $leg GATE-REFUSED" >> $P; exit 1; }
  rc=0
  ABSD_PROFILE=core ABSD_KERNEL_RUN=$G/work/KA taskset -c 2-5,8-11 nice -n 10 python3 -I $G/tools/c7.py $leg $W $G/work/OUT $G/work/C7-$leg $G/work/A $G/work/KA $KEY $G/etc-c7 2522 > $G/logs/c7-$leg.log 2>&1 || rc=$?
  echo "c7 $leg rc=$rc $(date -u +%FT%TZ)" >> $P
  census=$($G/tools/gate.sh --list) || { exit 1; }
  if printf '%s\n' "$census" | grep -q '^other'; then
    printf '%s\n' "$census" | grep '^other' | sed "s/^/LEFTOVER after c7 $leg: /" >> $P
    exit 1
  fi
  [ "$rc" = 0 ] || exit "$rc"
done
: "${ABSD_COMPOSITION_MEDIA_STATUS:?MUST7 media result required}"
test "$(cat "$ABSD_COMPOSITION_MEDIA_STATUS")" = PASS
echo "MUST subset done; full composition requires sealed intake $(date -u +%FT%TZ)" >> $P
