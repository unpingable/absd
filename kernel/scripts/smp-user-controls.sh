#!/bin/sh
# Normal boot, retained foundation paths, and fail-closed mode admission.
set -eu
prototype=${1:?prototype ELF}
production=${2:?production ELF}
out=${3:?new output directory}
mkdir "$out"
result=1
finish() { printf '%s\n' "$result" > "$out/status.tmp"; mv "$out/status.tmp" "$out/status"; }
trap finish EXIT
trap 'exit 1' HUP INT TERM
one() {
    name=$1
    kernel=$2
    options=$3
    expected=$4
    marker=$5
    case_dir=$out/$name
    mkdir -p "$case_dir/iso/boot/grub"
    sha256sum "$kernel" > "$case_dir/kernel.sha256"
    printf '%s\n' "$name" > "$out/phase"
    cp "$kernel" "$case_dir/iso/boot/absd-kernel"
    printf '%s\n' 'set timeout=0' 'menuentry "ABSD SMP controls" {' \
        "  multiboot2 /boot/absd-kernel $options" '  boot' '}' > "$case_dir/iso/boot/grub/grub.cfg"
    grub-mkrescue -o "$case_dir/boot.iso" "$case_dir/iso" > "$case_dir/iso.log" 2>&1
    status=0
    python3 scripts/smp-user-qemu.py "$case_dir" > "$case_dir/runner.log" 2>&1 || status=$?
    test "$status" -eq "$expected"
    grep -q "$marker" "$case_dir/serial.log"
    if [ "$expected" -eq 3 ]; then
        test "$(grep -cx 'ABSD BOOT OK' "$case_dir/serial.log")" -eq 1
        if grep -Eq 'ABSD PANIC:|KERNEL FAULT|FAILED' "$case_dir/serial.log"; then exit 1; fi
    else
        if grep -q '^ABSD BOOT OK$' "$case_dir/serial.log"; then exit 1; fi
    fi
    printf '%s\n' 0 > "$case_dir/status"
}
test -c /dev/kvm && test -r /dev/kvm && test -w /dev/kvm
one ordinary "$production" '' 3 'ABSD BOOT OK'
one kernel-only "$production" 'smp-kernel-only' 3 'ABSD BOOT OK'
one lifecycle "$production" 'smp-lifecycle' 3 'SMP-LIFECYCLE WORKLOAD OK'
test "$(grep -cx 'SMP STOP REPEAT phase=departed-before-drain' "$out/lifecycle/serial.log")" -eq 1
one created "$production" 'smp-created-stop' 3 'SMP-CREATED-STOP WORKLOAD OK'
one build-gate "$production" 'smp-user-test' 7 'SMP USER TEST REQUIRES smp-user-test BUILD'
one mode-gate "$prototype" 'smp-user-double-claim' 7 'SMP mutant requires qualification boot'
one conflicting "$prototype" 'smp-user-test smp-created-stop' 7 'conflicting SMP fixture'
sh scripts/smp-user-regression.sh "$production" "$out/guards" guards
printf '%s\n' terminal > "$out/phase"
result=0
