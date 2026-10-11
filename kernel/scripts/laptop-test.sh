#!/bin/sh
# Laptop-shaped QEMU qualification (docs/PHYSICAL-BOOT-PACKAGE.md, "QEMU
# laptop profile"). Every boot runs on scripts/laptop-boot.py's `thinkpad`
# machine: q35, OVMF, the ISO as a USB stick on xHCI, NVMe as the only
# disk, VGA, and no serial port or debug-exit device. All evidence is read
# back from the screen. Each result line is printed only after its checks
# pass; any failed check stops the script with a nonzero status.
#
#   laptop-test.sh PHYSICAL_ISO NVME_WRITE_ISO NVME_VERIFY_ISO [QEMU]
set -eu
physical=${1:?physical iso}
write_iso=${2:?nvme write iso}
verify_iso=${3:?nvme verify iso}
qemu=${4:-qemu-system-x86_64}
cd "$(dirname "$0")/.."
work=build/laptop
rm -rf "${work:?}"
mkdir -p "$work"

die() { printf 'LAPTOP TEST FAILED: %s\n' "$*" >&2; exit 1; }
has() { grep -qx "$1" "$2" || die "$2 lacks '$1'"; }
has_re() { grep -q "$1" "$2" || die "$2 lacks /$1/"; }

# 1. The physical ISO's default entry on the laptop machine, screen only.
image=$work/suite-nvme.img
truncate -s 2M "$image"
printf 'ABSD LAPTOP READ-ONLY WITNESS' | dd of="$image" conv=notrunc status=none
before=$(sha256sum < "$image")
log=$work/suite.log
python3 scripts/laptop-boot.py --qemu "$qemu" --iso "$physical" --log "$log" \
    --screen "$work/suite.ppm" --nvme "$image:laptop-witness" \
    --describe "$work/suite.machine" --timeout 600 > "$work/suite.result" \
    || { cat "$work/suite.result"; die "suite boot"; }
cat "$work/suite.result"
has_re '^LAPTOP BOOT boot status=3 halt=0 lines=[0-9]* gaps=0 profile=thinkpad$' "$work/suite.result"
has_re '^LAPTOP SCREEN OK boot ' "$work/suite.result"
test "$(head -n 1 "$log")" = 'ABSD KERNEL BOOT' || die "transcript does not start at the kernel's first line"
has_re '^FRAMEBUFFER CONSOLE OK width=[0-9]* height=[0-9]* ' "$log"
for marker in 'IDT BREAKPOINT OK' 'PAGE MAP OK' 'HEAP OK' 'BLOCK WRITES DISABLED: read-only build' \
    'NVME NAMESPACE nsid=1 lba_bytes=512 sectors=4096 access=read-only' 'BLOCK BACKEND nvme access=read-only' \
    'SPAWN EXHAUSTION OK' 'PROCESS MODEL OK' 'USER INIT STARTED' 'USERSPACE BOOTSTRAP OK' \
    'OBJECT TABLES EMPTY OK' 'SYSCALL ABI OK' 'PROCESS FAULT ISOLATION OK' 'USER PROCESSES OK' 'ABSD BOOT OK'; do
    has "$marker" "$log"
done
has_re '^NVME CONTROLLER pci=[0-9a-f:.]* vendor=1b36 device=0010 .* serial=laptop-witness ' "$log"
! grep -q 'PANIC\|KERNEL FAULT\|FAILED' "$log" || die "failure text in the transcript"
test "$before" = "$(sha256sum < "$image")" || die "suite boot changed the NVMe image"
lines=$(wc -l < "$log")
echo "FRAMEBUFFER ONLY BOOT OK lines=$lines gaps=0 final_screen=pixel-exact firmware=OVMF machine=q35 boot=usb-xhci"

# No serial, parallel, or debug-exit device exists, no character device but
# the host's own monitor, and the boot above completed anyway.
machine=$work/suite.machine
! grep -Eq 'dev: (isa-serial|pci-serial|pci-serial-2x|pci-serial-4x|usb-serial|isa-parallel|isa-debug-exit|isa-debugcon)' "$machine" \
    || die "a serial, parallel, or debug device is present"
chardevs=$(sed -n '/^# info chardev/,$p' "$machine" | grep -c ': filename=' || true)
test "$chardevs" -eq 1 || die "expected only the monitor chardev, found $chardevs"
grep -q ': filename=unix:.*monitor' "$machine" || die "the only chardev is not the monitor"
grep -q 'dev: nvme,' "$machine" || die "no NVMe device"
# The one SCSI disk is the USB stick carrying the read-only ISO.
! grep -Eq 'dev: (ide-hd|ide-cd|virtio-blk)' "$machine" || die "an ATA or virtio disk is present"
test "$(grep -c 'dev: scsi-hd' "$machine")" -eq 1 && grep -q 'drive = "stick"' "$machine" \
    || die "a SCSI disk other than the boot stick is present"
echo "NO SERIAL DEPENDENCY OK serial_devices=0 debug_exit=0 chardevs=monitor-only disks=nvme-only"

# Timer and preemption, as the screen showed them.
ticks=$(sed -n 's/^TIMER OK ticks=\([0-9]*\)$/\1/p' "$log")
test -n "$ticks" && test "$ticks" -ge 5 || die "no TIMER OK ticks>=5"
preempts=$(grep -c '^USER PREEMPT pid=[0-9]* -> pid=[0-9]*$' "$log" || true)
test "$preempts" -ge 1 || die "no USER PREEMPT line"
has 'USER PREEMPTION OK' "$log"
has 'USER SCHEDULER OK' "$log"
has 'init: timed waits verified' "$log"
has 'user-sleeper: slept for the requested ticks' "$log"
frames=$(grep '^FRAMES ' "$log") || die "no FRAMES line"
frame_ticks=$(printf '%s\n' "$frames" | sed -n 's/.* ticks=\([0-9]*\) .*/\1/p')
idle=$(printf '%s\n' "$frames" | sed -n 's/.* idle=\([0-9]*\) .*/\1/p')
timeouts=$(printf '%s\n' "$frames" | sed -n 's/.* timeouts=\([0-9]*\) .*/\1/p')
test "${frame_ticks:-0}" -gt 0 && test "${idle:-0}" -gt 0 || die "FRAMES ticks/idle not nonzero"
test "${timeouts:-0}" -eq 13 || die "FRAMES timeouts=$timeouts, expected 13"
echo "TIMER PREEMPTION OK timer_ticks=$ticks preempt_lines=$preempts frames_ticks=$frame_ticks idle=$idle timeouts=$timeouts source=PIT-8259"

# 2. NVMe writes and read-back on the same machine: one write boot, then a
# fresh boot plus a warm reset, both verifying read-only, over one image.
image=$work/nvme.img
truncate -s 2M "$image"
python3 scripts/laptop-boot.py --qemu "$qemu" --iso "$write_iso" --log "$work/nvme-write.log" \
    --screen "$work/nvme-write.ppm" --nvme "$image:absd" --timeout 300 > "$work/nvme-write.result" \
    || { cat "$work/nvme-write.result"; die "NVMe write boot"; }
cat "$work/nvme-write.result"
has_re '^LAPTOP BOOT boot status=3 halt=0 .* gaps=0 ' "$work/nvme-write.result"
log=$work/nvme-write.log
has_re '^NVME CONTROLLER pci=[0-9a-f:.]* vendor=1b36 device=0010 .* serial=absd ' "$log"
has 'NVME NAMESPACE nsid=1 lba_bytes=512 sectors=4096 access=read-write (selected by nvme-write)' "$log"
has 'NVME BLOCK OK lbas=5 sectors=4096' "$log"
has 'NVME FLUSH OK flush_commands=1' "$log"
has 'NVME BOUNDS OK kernel=OutOfRange device_status=0x0080' "$log"
python3 scripts/nvme-image-check.py "$image" >/dev/null || die "host image check after the write boot"
written=$(sha256sum < "$image")
python3 scripts/laptop-boot.py --qemu "$qemu" --iso "$verify_iso" --log "$work/nvme-verify.log" \
    --screen "$work/nvme-verify.ppm" --nvme "$image:absd" --reset-boots 1 --timeout 400 > "$work/nvme-verify.result" \
    || { cat "$work/nvme-verify.result"; die "NVMe verify boots"; }
cat "$work/nvme-verify.result"
for label in boot reset1; do
    has_re "^LAPTOP BOOT $label status=3 halt=0 .* gaps=0 " "$work/nvme-verify.result"
    log=$work/nvme-verify.log; [ $label = boot ] || log=$log.$label
    has 'NVME NAMESPACE nsid=1 lba_bytes=512 sectors=4096 access=read-only' "$log"
    has 'NVME REINIT OK lbas=5' "$log"
    has 'NVME READ ONLY OK' "$log"
done
test "$written" = "$(sha256sum < "$image")" || die "verify boots changed the image"
echo "EFI NVME BOOT OK write=5-lbas+flush fresh_boot=verified warm_reset=verified image=unchanged-after-verify firmware=OVMF"
rm -f "$work"/*.img
