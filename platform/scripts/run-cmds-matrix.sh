#!/bin/sh
# The /bin command set over SSH (scripts/cmds-matrix.py): every installed
# command run in a real session against its expected output and refusals,
# and the manual through man(1), on a `net fsd` boot. Needs a kernel with the fsd boot mode in
# ABSD_KERNEL_RUN. Builds the platform and the ports (the Rust ports and the
# sbase ports, scripts/build-ports.sh) unless ABSD_SKIP_BUILD=1.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel checkout}
qemu=${ABSD_QEMU:-qemu-system-x86_64}
work=$root/.cmds-work

. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
    "$root/scripts/build-ports.sh"
fi
for file in sshd.elf absd-fsd.elf sshtest.elf fsd-probe.elf fixture-import.elf commands/absd-sh; do
    test -f "$root/$file"
done
for command in echo pwd ls cat printenv uname mkdir rm mv cp head tail wc sha256sum stat df sync man date uptime release sysinfo; do
    test -f "$root/commands/$command"
done
test -f "$root/manpages/whatis"
for port in basename seq cut fold nl uniq base64 rg printf test grep sort sed od cmp ed find; do
    test -f "$root/ports/$port"
done
# The sbase ports against their manifest and the image's list (no boot).
python3 -I "$root/scripts/cmds-matrix.py" --host-check
rm -rf "${work:?}"
mkdir -p "$work"
python3 "$root/scripts/cmds-matrix.py" --work "$work" --kernel "$kernel" --shell "$root/commands/absd-sh" \
    --qemu "$qemu -cpu max,vendor=GenuineIntel,+rdrand" | tee "$work.log"
grep -q '^MAN PAGES OK pages=' "$work.log" || { echo "run-cmds-matrix: no MAN PAGES OK" >&2; exit 1; }
grep -q '^COMMAND SET OK names=' "$work.log" || { echo "run-cmds-matrix: no COMMAND SET OK" >&2; exit 1; }
grep -q '^SHELL LISTS OK' "$work.log" || { echo "run-cmds-matrix: no SHELL LISTS OK" >&2; exit 1; }
rm -rf "${work:?}" "${work:?}.log"
printf '%s\n' 'ABSD RUST CMDS OK'
