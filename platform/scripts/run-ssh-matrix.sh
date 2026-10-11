#!/bin/sh
# The SSH matrix (scripts/ssh-matrix.py): first against the Linux build of
# sshd (the reference), then against sshd on ABSD under QEMU with the host's
# /usr/bin/ssh. Needs a kernel with spawn_image, the NIC, and the fsd boot
# mode (pipe_info) in ABSD_KERNEL_RUN.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel checkout}
qemu=${ABSD_QEMU:-qemu-system-x86_64}
work=$root/.ssh-work

. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
for file in sshd.elf absd-fsd.elf absd-fsd-regenerate.elf sshtest.elf fsd-probe.elf fixture-import.elf \
    commands/absd-sh; do
    test -f "$root/$file"
done
rm -rf "${work:?}"
mkdir -p "$work"
# sshd's host tests (the PTY line discipline, authorized_keys parsing).
(cd "$root/ssh" && env -u RUSTFLAGS cargo +1.95.0 test --offline --locked --release \
    --target x86_64-unknown-linux-gnu --target-dir "$work/linux-target" --bin sshd)
(cd "$root/ssh" && env -u RUSTFLAGS cargo +1.95.0 build --offline --locked --release \
    --target x86_64-unknown-linux-gnu --target-dir "$work/linux-target" --bin sshd)
python3 "$root/scripts/ssh-matrix.py" --target linux \
    --sshd "$work/linux-target/x86_64-unknown-linux-gnu/release/sshd" --work "$work/linux"
python3 "$root/scripts/ssh-matrix.py" --target absd --work "$work/absd" \
    --kernel "$kernel" --shell "$root/commands/absd-sh" \
    --qemu "$qemu -cpu max,vendor=GenuineIntel,+rdrand"
rm -rf "${work:?}"
printf '%s\n' 'ABSD RUST SSH OK'
