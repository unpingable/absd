#!/bin/sh
# Safety gate for the physical ISO (docs/PHYSICAL-BOOT-PACKAGE.md). Checks
# the ISO file itself, then boots the kernel it carries, byte for byte,
# with every command line that asks for writes, against scratch images on
# both block backends, and requires:
#   - the kernel is the `block-read-only` build and says so on screen;
#   - no GRUB entry names `nvme-write=` and every entry halts on exit;
#   - QEMU's own device traces show no write, flush, or other non-read I/O
#     command, and only identify/queue-creation admin commands;
#   - every scratch image hashes the same before and after.
#
#   physical-iso-gate.sh ISO READ_ONLY_KERNEL [QEMU]
set -eu
iso=${1:?iso}
built=${2:?read-only kernel}
qemu=${3:-qemu-system-x86_64}
cd "$(dirname "$0")/.."
work=build/physical-gate
rm -rf "${work:?}"
mkdir -p "$work/iso/boot/grub"

say() { printf 'physical-iso-gate: %s\n' "$*"; }
die() { printf 'PHYSICAL ISO GATE FAILED: %s\n' "$*" >&2; exit 1; }

xorriso -osirrox on -indev "$iso" -extract /boot/absd-kernel "$work/kernel" \
    -extract /boot/grub/grub.cfg "$work/grub.cfg" >/dev/null 2>&1 || die "cannot extract from $iso"
cmp -s "$work/kernel" "$built" || die "ISO kernel differs from $built"
grep -aq 'BLOCK WRITES DISABLED: read-only build' "$work/kernel" || die "kernel lacks the read-only banner"
! grep -q 'nvme-write' "$work/grub.cfg" || die "grub.cfg names nvme-write"
entries=$(grep -c '^ *multiboot2 ' "$work/grub.cfg")
test "$entries" -eq "$(grep -c '^ *multiboot2 .* halt-on-exit$' "$work/grub.cfg")" || die "an entry lacks halt-on-exit"
say "ISO kernel is the read-only build; $entries GRUB entries, none selects a writable disk"

# The same kernel bytes, with command lines that ask for writes.
cp "$work/kernel" "$work/iso/boot/absd-kernel"
printf '%s\n' 'set timeout=0' 'set default=0' \
    'menuentry "adversarial" {' '  multiboot2 /boot/absd-kernel MODE nvme-write=absd' '  boot' '}' \
    > "$work/grub.template"

nvme_ok='^pci_nvme_io_cmd .* opname .NVME_NVM_CMD_READ.$'
admin_ok='opname .NVME_ADM_CMD_(IDENTIFY|CREATE_CQ|CREATE_SQ).$'
boot() { # mode backend
    mode=$1 backend=$2 name="$1-$2"
    sed "s/MODE/$mode/" "$work/grub.template" > "$work/iso/boot/grub/grub.cfg"
    grub-mkrescue -o "$work/$name.iso" "$work/iso" >/dev/null 2>&1
    image="$work/$name.img"
    truncate -s 2M "$image"
    printf 'ABSD PHYSICAL GATE WITNESS %s' "$name" | dd of="$image" conv=notrunc status=none
    before=$(sha256sum < "$image")
    case $backend in
    nvme) attach="-drive if=none,id=nvm,file=$image,format=raw -device nvme,serial=absd,drive=nvm" ;;
    ata) attach="-drive file=$image,format=raw,if=ide,index=0" ;;
    esac
    status=0
    timeout 180s $qemu -cdrom "$work/$name.iso" $attach -display none \
        -serial file:"$work/$name.log" -no-reboot -no-shutdown \
        -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
        -trace pci_nvme_io_cmd -trace pci_nvme_admin_cmd -trace ide_bus_exec_cmd \
        -D "$work/$name.trace" >/dev/null 2>&1 || status=$?
    log="$work/$name.log" trace="$work/$name.trace"
    grep -qx 'BLOCK WRITES DISABLED: read-only build' "$log" || die "$name: no read-only banner"
    grep -qx 'NVME WRITE OPTION IGNORED: read-only build' "$log" || die "$name: nvme-write= not reported ignored"
    grep -qx "BLOCK BACKEND $backend access=read-only" "$log" || die "$name: $backend not read-only"
    ! grep -q 'PANIC\|KERNEL FAULT' "$log" || die "$name: kernel failure"
    test "$status" -ne 124 || die "$name: timed out"
    test "$before" = "$(sha256sum < "$image")" || die "$name: image changed"
    case $backend in
    nvme)
        reads=$(grep -c '^pci_nvme_io_cmd ' "$trace" || true)
        test "$reads" -ge 1 || die "$name: no NVMe I/O traced (tracing broken?)"
        ! grep '^pci_nvme_io_cmd ' "$trace" | grep -vq "$nvme_ok" || die "$name: non-read NVMe I/O command traced"
        ! grep '^pci_nvme_admin_cmd ' "$trace" | grep -Evq "$admin_ok" || die "$name: unexpected NVMe admin command"
        detail="nvme_io_reads=$reads other_io=0" ;;
    ata)
        cmds=$(grep -c '^ide_bus_exec_cmd ' "$trace" || true)
        test "$cmds" -ge 1 || die "$name: no ATA command traced (tracing broken?)"
        # Allowed: IDENTIFY DEVICE (0xec), READ SECTORS (0x20), and the
        # IDENTIFY PACKET DEVICE probe (0xa1); PACKET (0xa0) goes only to the
        # firmware's and GRUB's reads of the CD-ROM, which is read-only media.
        ! grep '^ide_bus_exec_cmd ' "$trace" | grep -Eqv 'cmd 0x(ec|20|a1|a0)$' || die "$name: non-read ATA command traced"
        detail="ata_commands=$cmds (identify/read only)" ;;
    esac
    say "$mode nvme-write=absd on $backend: qemu status $status, image unchanged, $detail"
}
boot nvme-qualify-write nvme
boot block-probe nvme
boot block-probe ata
grep -qx 'NVME QUALIFY FAILED namespace not selected writable lba=0' "$work/nvme-qualify-write-nvme.log" \
    || die "nvme-qualify-write did not stop at the read-only namespace"
echo "PHYSICAL ISO GATE OK iso_sha256=$(sha256sum < "$iso" | cut -c1-64) kernel_sha256=$(sha256sum < "$built" | cut -c1-64)"
