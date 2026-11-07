#!/bin/sh
# F2 guest qualification steps 1-5 (as archived-occurrence)
# on the composed tip. Release A = a copy of the matrix's dev release built at
# the tip; kernel KA = this lane's copy. Gate before each QEMU step. Each step
# once; a failing step is recorded and later independent steps still run.
W=${ABSD_COMPOSITION_PLATFORM:?clean composed worktree required}
G=${ABSD_COMPOSITION_RUN_ROOT:?fresh occurrence root required}
K=$G/work/KA
A=$G/work/A
O=$G/work/OUT
KEY=${ABSD_COMPOSITION_KEY:?occurrence key required}
L=$G/logs
export ABSD_PROFILE=core ABSD_KERNEL_RUN=$K
# Separate producer stages so a failed find/sort cannot be hidden by a pipe.
digests() {
  ( cd "$1" || exit 1
    find . -type f -print0 > "$2.files" || exit 1
    sort -z "$2.files" > "$2.sorted" || exit 1
    xargs -0 sha256sum < "$2.sorted"
  ) > "$2" || return 1
  rm -f "$2.files" "$2.sorted" || return 1
}
cd "$W" || exit 1
run() { # label, command...
  label=$1; shift
  echo "START $(date -u +%FT%T.%NZ) $*"
  t=$(date +%s.%N)
  taskset -c 2-5,8-11 nice -n 10 "$@"
  rc=$?
  echo "RC $rc ($(awk "BEGIN{printf \"%.2f\", $(date +%s.%N) - $t}") s) $label"
  census || return 1
  return $rc
}
snap() { python3 -I $G/tools/snapshot.py $W/scripts "$1" "$2" $G/snap; }
gate() { $G/tools/gate.sh $L/load-gate.log "$1" && tail -1 $L/load-gate.log; }
batch_rc=0
step() {
  echo "F2 STEP $1 $2" >> $L/f2-steps.log
  [ "$2" = PASS ] || batch_rc=1
}
# Preserve each command result while checking for lane processes before returning.
census() {
  found=$($G/tools/gate.sh --list) || { batch_rc=1; return 1; }
  if printf '%s\n' "$found" | grep -q '^other'; then
    printf '%s\n' "$found" >> "$L/f2-steps.log"
    batch_rc=1
    return 1
  fi
}

{ gate f2-step1-install && run install python3 -I scripts/release.py install --release $A --kernel $K --target $O --target-identity lab-1; } > $L/f2-01-install.log 2>&1
r1=$?
{ gate f2-step1-accept && run accept python3 -I scripts/release.py accept --target $O --key $KEY --port 2522; } > $L/f2-01b-accept.log 2>&1
r1b=$?
grep -E "RELEASE OK|sshd: network|FINALIZED" $O/console-accept-dev.log >> $L/f2-01b-accept.log 2>&1 || batch_rc=1
snap $O 01-after-accept > $L/f2-01-snap.log 2>&1 || batch_rc=1
[ $r1 = 0 ] && [ $r1b = 0 ] && step 1 PASS || step 1 "FAIL install=$r1 accept=$r1b"

snap $O 02-before-reconfigure > $L/f2-02-record.log 2>&1
r2=$?
grep -q "guard=clean selected='dev'" $L/f2-02-record.log && [ $r2 = 0 ] && step 2 PASS || step 2 "FAIL rc=$r2"

{ gate f2-step3 && run reconfigure python3 -I scripts/release.py reconfigure --release $A --kernel $K --target $O --etc $G/etc-new; } > $L/f2-03-reconfigure.log 2>&1
r3=$?
snap $O 03-after-reconfigure > $L/f2-03-snap.log 2>&1 || batch_rc=1
python3 -I $G/tools/verify3.py $G > $L/f2-03-verify.log 2>&1
v3=$?
ls -la $O/recovery >> $L/f2-03-verify.log 2>&1 || batch_rc=1
[ $r3 = 0 ] && [ $v3 = 0 ] && step 3 PASS || step 3 "FAIL reconfigure=$r3 verify=$v3"

sha256sum $A/absd-operator.iso $O/absd-operator.iso $O/releases/dev/absd-operator.iso > $L/f2-04-iso.sha256 || batch_rc=1
{ gate f2-step4 && taskset -c 2-5,8-11 nice -n 10 python3 -I $G/tools/boot_check.py $W $O 2522 $KEY dev "sshd: network 10.0.2.20/24 gateway 10.0.2.2 (/etc/network.conf)"; } > $L/f2-04-boot.log 2>&1
r4=$?
census || batch_rc=1
snap $O 04-after-boot > $L/f2-04-post.log 2>&1 || batch_rc=1
[ $r4 = 0 ] && step 4 PASS || step 4 "FAIL rc=$r4"

# Step 5: negative controls on copies of OUT after step 4 (no QEMU expected).
neg() { # NAME KEEP... -- COMMAND...
  n=$1; d=$G/work/$1; shift
  [ ! -e "$d" ] || return 1
  cp -a "$O" "$d" || return 1
  for f in TARGET RELEASES MANIFEST; do rm -f "$d/$f" || return 1; done
  while [ "$1" != "--" ]; do cp -a "$O/$1" "$d/$1" || return 1; shift; done; shift
  digests "$d" "$L/NC-$n-before.txt" || return 1
  python3 -I $G/tools/snapshot.py $W/scripts $d NC-$n-before $G/snap || return 1
  "$@" > $L/NC-$n-out.txt 2>&1
  command_rc=$?
  echo "RC $command_rc"
  [ "$command_rc" != 0 ] || return 1
  sed 's/^/  /' $L/NC-$n-out.txt
  digests "$d" "$L/NC-$n-after.txt" || return 1
  python3 -I $G/tools/snapshot.py $W/scripts $d NC-$n-after $G/snap || return 1
  echo "DIFF file list+digests:"; diff $L/NC-$n-before.txt $L/NC-$n-after.txt && echo "  none" || return 1
}
{
  echo "=== NC1-none build-operator-image.sh --reconfigure"
  neg NC1-none -- scripts/build-operator-image.sh --reconfigure --etc $G/etc-c7 $G/work/NC1-none || batch_rc=1
  echo "=== NC2-target build-operator-image.sh --reconfigure"
  neg NC2-target TARGET -- scripts/build-operator-image.sh --reconfigure --etc $G/etc-c7 $G/work/NC2-target || batch_rc=1
  echo "=== NC3-releases build-operator-image.sh --reconfigure"
  neg NC3-releases RELEASES -- scripts/build-operator-image.sh --reconfigure --etc $G/etc-c7 $G/work/NC3-releases || batch_rc=1
  echo "=== NC1-rel release.py reconfigure on a directory with no records"
  neg NC1-rel -- python3 -I scripts/release.py reconfigure --release $A --kernel $K --target $G/work/NC1-rel --etc $G/etc-c7 || batch_rc=1
  census || batch_rc=1
} > $L/f2-05-negative.log 2>&1
census || batch_rc=1
echo "F2 subset ended rc=$batch_rc $(date -u +%FT%TZ)" >> $L/f2-steps.log
exit "$batch_rc"
