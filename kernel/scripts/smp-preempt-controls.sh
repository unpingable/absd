#!/bin/sh
# Retain default guards and reject incomplete preemptive admission modes.
set -eu
prototype=${1:?qualified ELF}
production=${2:?production ELF}
out=${3:?new output directory}
sh scripts/smp-user-controls.sh "$prototype" "$production" "$out"
one() {
    name=$1
    kernel=$2
    options=$3
    marker=$4
    case_dir=$out/$name
    mkdir -p "$case_dir/iso/boot/grub"
    sha256sum "$kernel" > "$case_dir/kernel.sha256"
    cp "$kernel" "$case_dir/iso/boot/absd-kernel"
    printf '%s\n' 'set timeout=0' 'menuentry "ABSD preemptive admission refusal" {' \
        "  multiboot2 /boot/absd-kernel $options" '  boot' '}' > "$case_dir/iso/boot/grub/grub.cfg"
    grub-mkrescue -o "$case_dir/boot.iso" "$case_dir/iso" > "$case_dir/iso.log" 2>&1
    status=0
    python3 scripts/smp-user-qemu.py "$case_dir" > "$case_dir/runner.log" 2>&1 || status=$?
    test "$status" -eq 7
    grep -Fq "$marker" "$case_dir/serial.log"
    if grep -q '^ABSD BOOT OK$' "$case_dir/serial.log"; then exit 1; fi
    printf '%s\n' 0 > "$case_dir/status"
}
result=1
trap 'printf "%s\n" "$result" > "$out/preempt.status"' EXIT
one native-no-pressure "$prototype" 'external smp-ap-app' \
    'native AP app requires external preemptive qualification'
one native-no-preempt "$prototype" 'external smp-user-pressure smp-ap-app' \
    'native AP app requires external preemptive qualification'
one native-no-external "$prototype" 'smp-user-pressure smp-user-preempt smp-ap-app' \
    'native AP app requires external preemptive qualification'
one native-production "$production" 'external smp-user-pressure smp-user-preempt smp-ap-app' \
    'SMP USER TEST REQUIRES smp-user-test BUILD'
one up-startup "$prototype" 'smp-user-bench smp-bench-up smp-kernel-only' \
    'UP benchmark refuses AP startup options'
result=0
