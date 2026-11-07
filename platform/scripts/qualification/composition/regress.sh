#!/bin/sh
# #63 step-8 harnesses at the tip (as #63 r3 regress.sh). One at a time, gated.
[ "$#" -gt 0 ] || { echo "suite selection required" >&2; exit 1; }
W=${ABSD_COMPOSITION_PLATFORM:?clean composed worktree required}
G=${ABSD_COMPOSITION_RUN_ROOT:?fresh occurrence root required}
K=$G/work/KA
R=$W/.fence-work/regress-${ABSD_COMPOSITION_RUN:?fresh run id required}
KEY=${ABSD_COMPOSITION_KEY:?occurrence key required}
LEG=${ABSD_COMPOSITION_LEGACY:-}
export ABSD_PROFILE=core ABSD_KERNEL_RUN=$K ABSD_SKIP_BUILD=1 ABSD_FENCE_ACCEL=tcg
export ABSD_CKIT_BUILD=$W/.fence-work/ckit-build ABSD_USERLAND_BUILD=$W/.fence-work/userland-build ABSD_CPORTS_BUILD=$W/.fence-work/cports-build
cd "$W" || exit 1
mkdir -p "$R" || exit 1
batch_rc=0
step() {
  name=$1; shift
  $G/tools/gate.sh $G/logs/load-gate.log regress-$name || { batch_rc=1; echo "step $name GATE-REFUSED" >> $G/logs/regress.log; return; }
  echo "step $name start $(date -u +%FT%TZ) tip=$(git rev-parse --short=8 HEAD)" >> $G/logs/regress.log
  taskset -c 2-5,8-11 nice -n 10 "$@" > $G/logs/regress-$name.log 2>&1
  rc=$?
  [ "$rc" = 0 ] || batch_rc=1
  echo "step $name end $(date -u +%FT%TZ) rc=$rc" >> $G/logs/regress.log
  census=$($G/tools/gate.sh --list) || { batch_rc=1; return; }
  if printf '%s\n' "$census" | grep -q '^other'; then
    printf '%s\n' "$census" | grep '^other' | sed "s/^/LEFTOVER after $name: /" >> $G/logs/regress.log
    batch_rc=1
  fi
}
for s in "$@"; do
case $s in
matrix) step matrix env ABSD_FENCE_WORK=$R/matrix scripts/run-storage-fence-matrix.sh --key $KEY ;;
corefsd) step corefsd env ABSD_CORE_FSD_WORK=$R/core-fsd scripts/run-core-fsd-recovery.sh ;;
updates) step updates python3 -B scripts/storage-fence-updates.py --platform $W --kernel $K --key $KEY --work $R/updates --qemu "qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand" ;;
upgrade) [ -n "$LEG" ] || { echo "legacy directory required" >&2; exit 1; }; step upgrade env ABSD_QEMU=qemu-system-x86_64 python3 -B scripts/storage-fence-upgrade.py --platform $W --kernel $K --key $KEY --work $R/upgrade --legacy-fsd $LEG/absd-fsd.elf --legacy-sshd $LEG/sshd.elf ;;
ghost-ata|ghost-nvme) b=${s#ghost-}
  [ ! -e "$R/f3-$b" ] || { echo "ghost work exists; not run" >&2; exit 1; }
  mkdir "$R/f3-$b" || exit 1
  git archive "${ABSD_COMPOSITION_F3_REF:?F3 source revision required}" qual/blkstall > "$R/f3-$b/source.tar" || exit 1
  tar -xf "$R/f3-$b/source.tar" -C "$R/f3-$b" || exit 1
  step $s env ABSD_HARNESS_STORAGE_FENCE=none python3 -B scripts/storage-fence-ghost.py --platform $W --kernel $K --f3 $R/f3-$b/qual/blkstall --backend $b --receipt $R/$s --seed 2839 ;;
served) step served scripts/run-served-matrix.sh ;;
survival) step survival python3 -B scripts/survival-recovery.py --kernel $K --platform $W --sshd-controls $W/.fence-build/sshd-controls.elf --key $KEY --work $R/survival --qemu "qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand" ;;
link) step link scripts/run-link-matrix.sh --only disabled-nic-budget ;;
*) echo "unknown suite: $s" >&2; batch_rc=1 ;;
esac
done
echo "regress batch done $(date -u +%FT%TZ)" >> $G/logs/regress.log

exit "$batch_rc"
