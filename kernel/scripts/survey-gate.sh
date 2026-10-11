#!/bin/sh
# Gate for the physical survey ISO (docs/hardware/HP-Z2-MINI-G3-FIRST-BOOT.md).
# The survey entry must identify the machine by reads only: after the
# kernel's first line QEMU's device traces may show writes to COM1, the
# PICs, the PIT, and the PCI configuration address latch, and nothing else:
# no PCI configuration write, no NVMe or e1000 register access, no ATA
# command. Checked on the ISO's own default entry (SeaBIOS and OVMF), on an
# edited line that asks for the NIC and NVMe writes, and on the laptop
# machine from the screen alone; a positive control shows the same trace
# catching the ordinary boot's device initialization.
#
#   survey-gate.sh SURVEY_ISO READ_ONLY_KERNEL [QEMU] [OVMF]
set -eu
iso=${1:?iso}
built=${2:?read-only kernel}
qemu=${3:-qemu-system-x86_64}
ovmf=${4:-/usr/share/ovmf/OVMF.fd}
cd "$(dirname "$0")/.."
work=build/survey-gate
rm -rf "${work:?}"
mkdir -p "$work/iso/boot/grub"

say() { printf 'survey-gate: %s\n' "$*"; }
die() { printf 'SURVEY GATE FAILED: %s\n' "$*" >&2; exit 1; }
has() { grep -qx "$1" "$2" || die "$2 lacks '$1'"; }
has_re() { grep -q "$1" "$2" || die "$2 lacks /$1/"; }

# 1. The ISO file: the read-only kernel, the survey as the default entry,
# no entry that names the NIC or a writable disk, every entry halting.
xorriso -osirrox on -indev "$iso" -extract /boot/absd-kernel "$work/kernel" \
    -extract /boot/grub/grub.cfg "$work/grub.cfg" >/dev/null 2>&1 || die "cannot extract from $iso"
cmp -s "$work/kernel" "$built" || die "ISO kernel differs from $built"
grep -aq 'BLOCK WRITES DISABLED: read-only build' "$work/kernel" || die "kernel lacks the read-only banner"
grep -qx 'set default=0' "$work/grub.cfg" || die "default entry is not the first"
test "$(grep -m1 '^ *multiboot2 ' "$work/grub.cfg")" = '  multiboot2 /boot/absd-kernel survey halt-on-exit' \
    || die "first entry is not 'survey halt-on-exit'"
! grep -q 'nvme-write' "$work/grub.cfg" || die "grub.cfg names nvme-write"
! grep -Eq '^ *multiboot2 .* (net|net-probe)( |$)' "$work/grub.cfg" || die "an entry names the NIC"
entries=$(grep -c '^ *multiboot2 ' "$work/grub.cfg")
test "$entries" -eq "$(grep -c '^ *multiboot2 .* halt-on-exit$' "$work/grub.cfg")" || die "an entry lacks halt-on-exit"
say "ISO kernel is the read-only build; default entry is 'survey halt-on-exit'; $entries entries, none names the NIC or nvme-write"

traces="-trace serial_write -trace memory_region_ops_write -trace pci_cfg_write -trace pci_nvme_* -trace ide_bus_exec_cmd"
attach() { # name firmware -> QEMU device arguments over fresh witness images
    for disk in nvme ata; do
        truncate -s 2M "$work/$1-$disk.img"
        printf 'ABSD SURVEY WITNESS %s %s' "$1" "$disk" | dd of="$work/$1-$disk.img" conv=notrunc status=none
    done
    printf '%s' "-nic none -device e1000,romfile= -drive if=none,id=nvm,file=$work/$1-nvme.img,format=raw -device nvme,serial=absd,drive=nvm"
    # SeaBIOS's i440fx has the legacy IDE channel the ata driver speaks to.
    [ "$2" = efi ] || printf ' %s' "-drive file=$work/$1-ata.img,format=raw,if=ide,index=0"
}
digests() { sha256sum "$work/$1"-*.img | cut -c1-64 | tr '\n' ' '; }

survey_boot() { # name iso firmware
    name=$1 image=$2 firmware=$3
    devices=$(attach "$name" "$firmware")
    before=$(digests "$name")
    extra=""; [ "$firmware" = efi ] && extra="--firmware $ovmf"
    log="$work/$name.log"
    python3 scripts/framebuffer-check.py --iso "$image" --serial "$log" --screen "$work/$name.ppm" \
        --until 'SAFE TO POWER OFF' --halt-code 0 --timeout 240 \
        --qemu "$qemu $devices $traces -D $work/$name.trace" $extra > "$work/$name.screen" \
        || die "$name: screen does not match serial"
    # Under OVMF the firmware's own serial output precedes the first line.
    has_re 'ABSD KERNEL BOOT$' "$log"
    for marker in 'IDT BREAKPOINT OK' 'CPU ACCEPTED lm nx pae msr tsc fxsr sse2' \
        'PAGE MAP OK' 'TIMER OK ticks=5' 'HEAP OK' 'ABSD PHYSICAL SURVEY v1: identity by reads only' \
        'PERSISTENT WRITES: DISABLED (read-only build, no storage driver started)' \
        'STORAGE CONTROLLER INITIALIZATION: NOT PERFORMED' 'NETWORK INITIALIZATION: DISABLED' \
        'PHYSICAL SURVEY COMPLETE' 'ABSD BOOT OK' 'SAFE TO POWER OFF'; do
        has "$marker" "$log"
    done
    has_re '^PCI ENUMERATION OK functions=[0-9]* ' "$log"
    has_re '^STORAGE CONTROLLER [0-9a-f:.]* 1b36:0010 NVMe driver=nvme NOT INITIALIZED$' "$log"
    has_re '^NETWORK CONTROLLER [0-9a-f:.]* 8086:100e class=02.00.00 driver=e1000 NOT INITIALIZED$' "$log"
    has_re '^RECORD PCI [0-9a-f:.]* id=00101b36 ' "$log"
    ! grep -Eq '^(NVME |NIC |NETWORK LINK|BLOCK |block:|SPAWN|USER )' "$log" || die "$name: a device driver or userspace ran"
    ! grep -q 'PANIC\|KERNEL FAULT\|FAILED' "$log" || die "$name: failure text"
    python3 scripts/survey-check.py trace "$work/$name.trace" > "$work/$name.writes" || die "$name: trace"
    python3 scripts/survey-check.py visible "$log" > "$work/$name.visible" || die "$name: summary"
    test "$before" = "$(digests "$name")" || die "$name: a disk image changed"
    say "$name: $(cat "$work/$name.screen" | cut -d' ' -f1-3); $(cat "$work/$name.visible"); $(cat "$work/$name.writes"); images unchanged"
}

# 2. The ISO's own default entry, both firmware paths.
survey_boot bios "$iso" bios
if [ -f "$ovmf" ]; then survey_boot efi "$iso" efi; else say "no OVMF at $ovmf; EFI boot not run"; fi

# 3. An edited command line asking for the NIC and a writable NVMe disk:
# the survey diverges before either option is read.
cp "$work/kernel" "$work/iso/boot/absd-kernel"
line='survey net nvme-write=absd halt-on-exit'
printf '%s\n' 'insmod all_video' 'set timeout=0' "menuentry \"edited\" {" "  multiboot2 /boot/absd-kernel $line" '  boot' '}' \
    > "$work/iso/boot/grub/grub.cfg"
grub-mkrescue -o "$work/edited.iso" "$work/iso" >/dev/null 2>&1
survey_boot edited "$work/edited.iso" bios

# 4. Positive control: the ordinary boot with `net` starts the NVMe
# controller and the NIC after the same marker, and the check sees it.
line='kernel-fault-test net'
printf '%s\n' 'set timeout=0' "menuentry \"control\" {" "  multiboot2 /boot/absd-kernel $line" '  boot' '}' \
    > "$work/iso/boot/grub/grub.cfg"
grub-mkrescue -o "$work/control.iso" "$work/iso" >/dev/null 2>&1
devices=$(attach control bios)
status=0
timeout 180s $qemu -cdrom "$work/control.iso" $devices -display none -serial file:"$work/control.log" \
    -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04 $traces -D "$work/control.trace" \
    >/dev/null 2>&1 || status=$?
test "$status" -eq 11 || die "control: qemu status $status, expected 11 (kernel fault test, halt code 2)"
has_re '^NVME CONTROLLER .* serial=absd ' "$work/control.log"
has_re '^NIC CONTROLLER ' "$work/control.log"
python3 scripts/survey-check.py trace "$work/control.trace" --expect-forbidden > "$work/control.writes" \
    || die "control: the trace did not see device initialization"
say "control (kernel-fault-test net): $(cat "$work/control.writes")"

# 5. The laptop-shaped machine (q35, OVMF, USB stick, NVMe, an e1000e the
# kernel has no driver for, no serial port), read from the screen alone.
truncate -s 2M "$work/laptop.img"
printf 'ABSD SURVEY LAPTOP WITNESS' | dd of="$work/laptop.img" conv=notrunc status=none
before=$(sha256sum < "$work/laptop.img")
python3 scripts/laptop-boot.py --qemu "$qemu" --iso "$iso" --log "$work/laptop.log" --screen "$work/laptop.ppm" \
    --nvme "$work/laptop.img:laptop-witness" --qemu-extra "-device e1000e,romfile=" --timeout 300 \
    > "$work/laptop.result" || { cat "$work/laptop.result"; die "laptop boot"; }
has_re '^LAPTOP BOOT boot status=3 halt=0 lines=[0-9]* gaps=0 profile=thinkpad$' "$work/laptop.result"
has_re '^LAPTOP SCREEN OK boot ' "$work/laptop.result"
test "$(head -n 1 "$work/laptop.log")" = 'ABSD KERNEL BOOT' || die "laptop transcript does not start at the kernel's first line"
has 'BOOT EFI via Multiboot2; ACPI not consumed' "$work/laptop.log"
has_re '^STORAGE CONTROLLER [0-9a-f:.]* 1b36:0010 NVMe driver=nvme NOT INITIALIZED$' "$work/laptop.log"
has_re '^NETWORK CONTROLLER [0-9a-f:.]* 8086:10d3 class=02.00.00 driver=none NOT INITIALIZED$' "$work/laptop.log"
has 'SAFE TO POWER OFF' "$work/laptop.log"
! grep -q '^RECORD ' "$work/laptop.log" || die "a serial-only record reached the screen"
! grep -Eq '^(NVME |NIC |BLOCK |SPAWN|USER )' "$work/laptop.log" || die "laptop: a device driver or userspace ran"
python3 scripts/survey-check.py visible "$work/laptop.log" > "$work/laptop.visible" || die "laptop: summary"
test "$before" = "$(sha256sum < "$work/laptop.img")" || die "laptop: the NVMe image changed"
say "laptop: $(head -n 1 "$work/laptop.result"); $(cat "$work/laptop.visible"); image unchanged"
rm -f "$work"/*.img
echo "SURVEY GATE OK iso_sha256=$(sha256sum < "$iso" | cut -c1-64) kernel_sha256=$(sha256sum < "$built" | cut -c1-64)"
