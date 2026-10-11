#!/bin/sh
# Varies the laptop machine's legacy assumptions one at a time and records
# what each does to the physical ISO's default boot, read from the screen.
# Informational: it never fails on a variant's outcome, it reports it.
# Results: build/laptop-matrix/summary.txt (one line per variant); each
# variant's transcript, screens, and machine description sit beside it.
#
#   laptop-matrix.sh PHYSICAL_ISO [QEMU] [PARALLEL]
set -eu
iso=${1:?physical iso}
qemu=${2:-qemu-system-x86_64}
parallel=${3:-4}
cd "$(dirname "$0")/.."
rm -rf build/laptop-matrix
mkdir -p build/laptop-matrix
work=build/laptop-matrix

# name | laptop-boot.py options | extra QEMU words | NVMe attachment
variants() {
    cat <<'EOF'
base|||one
seabios|--profile thinkpad-bios||one
ahci-cdrom|--profile thinkpad-cdrom||one
seabios-ahci-cdrom|--profile thinkpad-bios-cdrom||one
hpet-off|--machine-extra hpet=off||one
pit-off|--machine-extra pit=off||one
pic-off|--machine-extra pic=off||one
sata-off|--machine-extra sata=off||one
i8042-off-usb-kbd|--machine-extra i8042=off|-device usb-kbd,bus=xhci.0|one
smbus-off|--machine-extra smbus=off||one
cpu-max|--cpu max||one
cpu-skylake-client|--cpu Skylake-Client-v4||one
cpu-epyc|--cpu EPYC-v4||one
smp4||-smp 4|one
mem128m|--memory 128M||one
mem4g|--memory 4G||one
bochs-display|--vga bochs-display||one
virtio-vga|--vga virtio-vga||one
ramfb|--vga ramfb||one
no-nvme|||none
two-nvme|||two
nvme-4k-lba|||4k
EOF
}

run() { # name options extra nvme
    name=$1 options=$2 extra=$3 nvme=$4
    image=$work/$name.img
    truncate -s 2M "$image"
    printf 'ABSD MATRIX WITNESS' | dd of="$image" conv=notrunc status=none
    before=$(sha256sum < "$image")
    case $nvme in
    one) attach="--nvme $image:matrix-$name" ;;
    none) attach="" ;;
    two) truncate -s 4M "$work/$name-2.img"; attach="--nvme $image:matrix-first --nvme $work/$name-2.img:matrix-second" ;;
    4k) attach=""; extra="$extra -drive if=none,id=k4,file=$image,format=raw -device nvme,serial=matrix-4k,drive=k4,logical_block_size=4096,physical_block_size=4096" ;;
    esac
    log=$work/$name.log
    start=$(date +%s)
    # shellcheck disable=SC2086
    python3 scripts/laptop-boot.py --qemu "$qemu" --iso "$iso" --log "$log" --screen "$work/$name.ppm" \
        --describe "$work/$name.machine" --timeout 300 $options $attach ${extra:+--qemu-extra "$extra"} \
        > "$work/$name.result" 2> "$work/$name.err" || true
    elapsed=$(( $(date +%s) - start ))
    result=$(grep '^LAPTOP BOOT boot' "$work/$name.result" | sed 's/^LAPTOP BOOT boot //; s/ profile=.*//' || true)
    screen=$(grep -c '^LAPTOP SCREEN OK' "$work/$name.result" || true)
    touched=same; [ "$before" = "$(sha256sum < "$image")" ] || touched=CHANGED
    notes=$( { grep -E '^(TIMER (OK|FAILED)|NVME (CONTROLLER|NAMESPACE|UNAVAILABLE)|BLOCK BACKEND|block: no device|FRAMEBUFFER CONSOLE (OK|FAILED)|ABSD PANIC|KERNEL FAULT|USER PREEMPTION OK|ABSD BOOT OK|framebuffer: )' "$log" 2>/dev/null || true; } \
        | sed -e 's/ height=\([0-9]*\) pitch=.*/x\1/' -e 's/ vendor=.* serial=/ serial=/' -e 's/ model=.*//' | tr '\n' ';')
    err=$(head -c 300 "$work/$name.err" | tr '\n' ' ')
    printf '%s | %s | screen_ok=%s | nvme_image=%s | %ss | %s%s\n' "$name" "${result:-no result}" "$screen" "$touched" "$elapsed" "$notes" "${err:+ err: $err}" \
        > "$work/$name.summary"
}

variants > "$work/variants"
i=0
while IFS='|' read -r name options extra nvme; do
    run "$name" "$options" "$extra" "$nvme" &
    i=$((i + 1))
    if [ $((i % parallel)) -eq 0 ]; then wait; fi
done < "$work/variants"
wait
while IFS='|' read -r name options extra nvme; do cat "$work/$name.summary"; done < "$work/variants" > "$work/summary.txt"
cat "$work/summary.txt"
