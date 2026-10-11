#!/bin/sh
# std::process through init's broker (kernel docs/BROKER.md): boots
# broker-requester.elf as the durable worker under broker-policy.txt, with
# broker-echo.elf as the one program init may start for it, and requires the
# exact output in broker-expected.txt and a clean, idle broker afterwards.
# Needs a kernel with broker mode (lane/broker or later) in ABSD_KERNEL_RUN.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel checkout}
qemu=${ABSD_QEMU:-qemu-system-x86_64}
work=$root/.broker-work

. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
rm -rf "${work:?}"
mkdir -p "$work"
: > "$work/empty"
make -C "$kernel" --no-print-directory durable-iso DURABLE_STEP=1 \
    EXTERNAL_USER_ELF="$root/broker-requester.elf" EXTERNAL_INPUT="$work/empty" \
    BROKER_POLICY="$root/broker-policy.txt" OWNER_1_ELF="$root/broker-echo.elf" >/dev/null
truncate -s 2M "$work/broker.img"
status=$("$kernel/scripts/durable-boot.sh" "$kernel/build/durable/absd-durable-1.iso" \
    "$work/broker.img" "$work/broker.log" 180 $qemu -cpu max,vendor=GenuineIntel,+rdrand)
test "$status" -eq 3
python3 "$kernel/scripts/check-external-output.py" "$work/broker.log" "$root/broker-expected.txt"
grep -q '^DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ' "$work/broker.log"
grep -q 'BROKER SUMMARY generation=1 requests=6 dropped=0 started=4 refused=2 exited=4 reclaimed=0 idle=true' \
    "$work/broker.log"
if grep -q 'PANIC\|KERNEL FAULT\|init: FAILED' "$work/broker.log"; then
    echo "run-broker: failure text in $work/broker.log" >&2; exit 1
fi
rm -rf "${work:?}"
printf '%s\n' 'ABSD RUST STD BROKER OK spawned=4 refused=2 checks=17'
