#!/bin/sh
# The source-portability probe (docs/COMPATIBILITY-LEDGER.md): builds the
# ledger's "run" programs, unmodified upstream crates, for ABSD and for
# Linux (scripts/build-compat.sh), then runs every case of compat/cases.tsv
# on ABSD and compares it with Linux (scripts/compat-matrix.py). Needs a
# kernel with spawn_image in ABSD_KERNEL_RUN (a disposable clone). Set
# ABSD_SKIP_BUILD=1 to reuse prepare-and-build.sh output and
# ABSD_SKIP_COMPAT_BUILD=1 to reuse build-compat.sh output;
# ABSD_COMPAT_FAILURES=1 also rechecks every recorded build failure.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel clone}
work=${ABSD_COMPAT_WORK:-$root/.compat-work}
: "${ABSD_QEMU:=qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand}"

. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
if [ "${ABSD_SKIP_COMPAT_BUILD:-0}" != 1 ]; then
    "$root/scripts/build-compat.sh"
fi
test -f "$root/fixture-import.elf" && test -f "$root/compat-launch.elf"
tab=$(printf '\t')
expected=$(grep -v '^#' "$root/compat/programs.tsv" | awk -F"$tab" '$5 == "run"' | wc -l)
built=0
for bin in $(grep -v '^#' "$root/compat/programs.tsv" | awk -F"$tab" '$5 == "run" {print $4}'); do
    test -f "$root/compat-commands/$bin" && test -f "$root/compat-linux/$bin"
    built=$((built + 1))
done
test "$built" -eq "$expected"
rm -rf "${work:?}"
mkdir -p "$work"
python3 "$root/scripts/compat-matrix.py" --kernel "$kernel" \
    --importer "$root/fixture-import.elf" --launcher "$root/compat-launch.elf" \
    --commands "$root/compat-commands" --linux "$root/compat-linux" \
    --compat "$root/compat" --expected "$root/compat-expected.txt" \
    --work "$work" --qemu "$ABSD_QEMU" >"$work/matrix.txt" ||
    { cat "$work/matrix.txt"; exit 1; }
cat "$work/matrix.txt"
# ran: programs with at least one case equal to Linux byte for byte. A
# program that builds but whose every case diverges (b3sum: threads) is
# built, not ran.
ran=$(sed -n 's/^COMPAT MATRIX OK programs=\([0-9]*\) .*/\1/p' "$work/matrix.txt")
test -n "$ran" && test "$ran" -le "$built"
rm -rf "${work:?}"
printf '%s\n' "COMPAT PROBE OK built=$built ran=$ran"
