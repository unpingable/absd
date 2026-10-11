#!/bin/sh
# The file server matrix (scripts/fsd-matrix.py): SSH sessions writing
# through absd-fsd on a `net fsd` boot, with the host's /usr/bin/ssh. Needs
# a kernel with pipe_info and the fsd boot mode in ABSD_KERNEL_RUN.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel checkout}
qemu=${ABSD_QEMU:-qemu-system-x86_64}
work=$root/.fsd-work

. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
for file in sshd.elf absd-fsd.elf absd-fsd-regenerate.elf sshtest.elf fsd-probe.elf fixture-import.elf \
    commands/absd-sh commands/mkdir commands/rm commands/mv; do
    test -f "$root/$file"
done
rm -rf "${work:?}"
mkdir -p "$work"
python3 "$root/scripts/fsd-matrix.py" --work "$work" --kernel "$kernel" --shell "$root/commands/absd-sh" \
    --qemu "$qemu -cpu max,vendor=GenuineIntel,+rdrand"
rm -rf "${work:?}"
printf '%s\n' 'ABSD RUST FSD OK'
