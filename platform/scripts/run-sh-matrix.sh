#!/bin/sh
# absd-sh on ABSD (scripts/sh-matrix.py): the shell, installed as
# /bin/absd-sh, runs a scripted session and a `-c` command as a filesystem
# executable. Needs a kernel with spawn_image (lane/exec or later) in
# ABSD_KERNEL_RUN.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel clone}
work=${ABSD_SH_WORK:-$root/.sh-work}
: "${ABSD_QEMU:=qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand}"

. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
test -f "$root/fixture-import.elf" && test -f "$root/sh-launch.elf" && test -d "$root/commands"
test -f "$root/commands/absd-sh"
rm -rf "${work:?}"
mkdir -p "$work"
python3 "$root/scripts/sh-matrix.py" --kernel "$kernel" \
    --importer "$root/fixture-import.elf" --launcher "$root/sh-launch.elf" \
    --shell "$root/commands/absd-sh" --commands "$root/commands" \
    --input "$root/sh-input.txt" --expected "$root/sh-expected.txt" \
    --work "$work" --qemu "$ABSD_QEMU"
rm -rf "${work:?}"
printf '%s\n' 'ABSD RUST SH OK'
