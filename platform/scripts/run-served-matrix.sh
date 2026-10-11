#!/bin/sh
# The served-boot matrix (scripts/served-matrix.py): a `net fsd served` boot
# that outlives the qualification deadline, the operator's orderly shutdown
# and reboot over SSH with the host's /usr/bin/ssh, the machine-ending
# right, and a served boot whose NIC link is down from power-on (QMP
# set_link) serving once the link returns. Needs a kernel with the served
# boot mode and machine handles
# (syscalls 37 and 38) in ABSD_KERNEL_RUN.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel checkout}
qemu=${ABSD_QEMU:-qemu-system-x86_64}
work=$root/.served-work

. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
for file in sshd.elf absd-fsd.elf absd-fsd-regenerate.elf sshtest.elf fsd-probe.elf fixture-import.elf \
    commands/absd-sh commands/cat; do
    test -f "$root/$file"
done
rm -rf "${work:?}"
mkdir -p "$work"
python3 "$root/scripts/served-matrix.py" --work "$work" --kernel "$kernel" --shell "$root/commands/absd-sh" \
    --qemu "$qemu -cpu max,vendor=GenuineIntel,+rdrand"
rm -rf "${work:?}"
printf '%s\n' 'ABSD RUST SERVED OK'
