#!/bin/sh
set -eu

kernel=$1
output=$2
mkdir -p "$output/iso/boot/grub"
cp "$kernel" "$output/iso/boot/absd-kernel"

boot_case() {
    name=$1
    options=$2
    cpu_count=$3
    printf '%s\n' 'set timeout=0' "menuentry ABSD-$name {" \
        "  multiboot2 /boot/absd-kernel $options" '  boot' '}' \
        > "$output/iso/boot/grub/grub.cfg"
    grub-mkrescue -o "$output/$name.iso" "$output/iso" >/dev/null 2>&1
    status=0
    timeout 60s qemu-system-x86_64 -smp "$cpu_count" \
        -cdrom "$output/$name.iso" -display none \
        -serial "file:$output/$name.serial.log" -no-reboot -no-shutdown \
        -nic none -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
        >/dev/null 2>&1 || status=$?
}

boot_case bsp-refusal bsp-refusal-test 1
if [ "$status" -ne 11 ]; then
    echo "bsp-refusal: unexpected QEMU exit $status" >&2
    exit 1
fi
if ! grep -q '^BSP REFUSAL FIXTURE$' "$output/bsp-refusal.serial.log"; then
    echo 'bsp-refusal: fixture record absent' >&2
    exit 1
fi
if grep -q '^ABSD KERNEL BOOT$' "$output/bsp-refusal.serial.log"; then
    echo 'bsp-refusal: kernel continued after refusal' >&2
    exit 1
fi

boot_case handoff-negative handoff-negative-test 1
if [ "$status" -ne 7 ]; then
    echo "handoff-negative: unexpected QEMU exit $status" >&2
    exit 1
fi
if ! grep -q '^HANDOFF NEGATIVE FIXTURE$' "$output/handoff-negative.serial.log"; then
    echo 'handoff-negative: fixture record absent' >&2
    exit 1
fi
if ! grep -q 'handoff is not on a CPU-owned stack' "$output/handoff-negative.serial.log"; then
    echo 'handoff-negative: departure assertion did not reject task stack' >&2
    exit 1
fi
if grep -q '^ABSD BOOT OK$' "$output/handoff-negative.serial.log"; then
    echo 'handoff-negative: suite unexpectedly completed' >&2
    exit 1
fi

boot_case parked-ap '' 2
if [ "$status" -ne 3 ]; then
    echo "parked-ap: unexpected QEMU exit $status" >&2
    exit 1
fi
if ! grep -q '^ABSD BOOT OK$' "$output/parked-ap.serial.log"; then
    echo 'parked-ap: BSP suite did not complete' >&2
    exit 1
fi
if grep -q '^ABSD PANIC:' "$output/parked-ap.serial.log"; then
    echo 'parked-ap: unexpected kernel panic' >&2
    exit 1
fi
echo 'SMP UP PREP TEST OK'
