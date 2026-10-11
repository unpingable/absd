#!/bin/sh
# Boots one durable ISO against a persistent raw image and reports QEMU's
# exit status on stdout. The image is never created, copied, or removed
# here: the caller owns it across abrupt stops and fresh boots.
#
#   durable-boot.sh ISO IMAGE SERIAL_LOG [TIMEOUT_SECONDS] [QEMU...]
#
# ABSD_BLOCK_ATTACH selects how the image is attached: `ata` (default, the
# primary IDE master), `nvme` (one QEMU NVMe namespace whose controller
# serial is `absd`, the serial durable ISOs select as writable), or
# `laptop`: the same namespace on scripts/laptop-boot.py's `thinkpad`
# machine (q35, OVMF, USB boot, no serial port), where SERIAL_LOG receives
# the console transcript read back from the screen and the status is the
# one debug-exit would have produced. Extra QEMU words are passed through.
#
# Exit statuses (QEMU's debug-exit encoding, 4 * code + 3): 3 is an orderly
# `ABSD BOOT OK`; 7 is a failed workload; 67 upward are `machine_stop`
# codes 16 and above from the guest; 124 is the host timeout. A guest
# restart (`machine_restart`) under the default `-no-reboot -no-shutdown`
# becomes a shutdown request that QEMU answers by pausing (it neither exits
# nor reboots; the host timeout ends it). ABSD_QEMU_REBOOT=exit drops
# `-no-shutdown`, so the restart ends QEMU with status 0;
# ABSD_QEMU_REBOOT=allow drops `-no-reboot` too, so the machine resets,
# GRUB boots the same entry again, and one serial log holds every boot
# until one halts.
set -eu
iso=${1:?iso}
image=${2:?image}
output=${3:?serial log}
limit=${4:-300}
shift 4 2>/dev/null || shift $#
qemu=${1:-qemu-system-x86_64}
if [ "$#" -gt 0 ]; then shift; fi
test -f "$iso"
test -f "$image"
if [ "${ABSD_BLOCK_ATTACH:-ata}" = laptop ]; then
    result=$(python3 "$(dirname "$0")/laptop-boot.py" --qemu "$qemu" ${1:+--qemu-extra "$*"} \
        --iso "$iso" --log "$output" --nvme "$image:absd" --timeout "$limit" 2>&1) || true
    status=$(printf '%s\n' "$result" | sed -n 's/^LAPTOP BOOT boot status=\([0-9]*\) .*/\1/p')
    case $result in *" gaps=0 "*) ;; *) echo "durable-boot.sh: laptop transcript incomplete: $result" >&2; exit 1 ;; esac
    printf '%s\n' "${status:?laptop boot produced no status: $result}"
    exit 0
fi
case "${ABSD_BLOCK_ATTACH:-ata}" in
ata) set -- "$@" -drive file="$image",format=raw,if=ide,index=0 ;;
nvme) set -- "$@" -drive if=none,id=nvm,file="$image",format=raw -device nvme,serial=absd,drive=nvm ;;
*) echo "durable-boot.sh: ABSD_BLOCK_ATTACH must be ata or nvme" >&2; exit 2 ;;
esac
case "${ABSD_QEMU_REBOOT:-}" in
allow) reboot= ;;
exit) reboot=-no-reboot ;;
'') reboot="-no-reboot -no-shutdown" ;;
*) echo "durable-boot.sh: ABSD_QEMU_REBOOT must be allow, exit, or unset" >&2; exit 2 ;;
esac
rm -f "$output"
status=0
timeout "${limit}s" $qemu "$@" -cdrom "$iso" \
    -display none -serial file:"$output" $reboot \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 >/dev/null 2>&1 || status=$?
printf '%s\n' "$status"
