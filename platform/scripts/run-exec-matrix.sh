#!/bin/sh
# Filesystem execution (kernel docs/PROCESS-STARTUP.md): the commands under
# /bin run through std::process::Command from the ABSD filesystem, started
# by the kernel's spawn_image, with argv, environment, working directory,
# streams, exit status, kill, a read-only filesystem view, and refusals.
# Needs a kernel with spawn_image (lane/exec or later) in ABSD_KERNEL_RUN.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel clone}
work=${ABSD_EXEC_WORK:-$root/.exec-work}
: "${ABSD_QEMU:=qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand}"

. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
test -f "$root/fixture-import.elf" && test -f "$root/exec-probe.elf" && test -d "$root/commands"
rm -rf "${work:?}"
mkdir -p "$work"
python3 "$root/scripts/exec-matrix.py" --kernel "$kernel" \
    --importer "$root/fixture-import.elf" --probe "$root/exec-probe.elf" \
    --commands "$root/commands" --expected "$root/exec-expected.txt" \
    --work "$work" --qemu "$ABSD_QEMU"
rm -rf "${work:?}"
printf '%s\n' 'ABSD RUST EXEC OK'
