#!/bin/sh
# Closed FPU mode refuses incomplete admission and unrelated mutants.
set -eu
prototype=${1:?qualified ELF}; production=${2:?production ELF}; out=${3:?new output}
mkdir "$out"
result=1
trap 'printf "%s\n" "$result" > "$out/status"' EXIT
one() {
    name=$1; kernel=$2; options=$3; marker=$4
    d=$out/$name
    mkdir -p "$d/iso/boot/grub"
    cp "$kernel" "$d/iso/boot/absd-kernel"
    sha256sum "$kernel" > "$d/kernel.sha256"
    printf '%s\n' 'set timeout=0' 'menuentry "ABSD FPU admission" {' " multiboot2 /boot/absd-kernel $options" ' boot' '}' > "$d/iso/boot/grub/grub.cfg"
    grub-mkrescue -o "$d/boot.iso" "$d/iso" > "$d/iso.log" 2>&1
    qstatus=0
    python3 scripts/smp-user-qemu.py "$d" > "$d/runner.log" 2>&1 || qstatus=$?
    test "$qstatus" -eq 7
    grep -Fq "$marker" "$d/serial.log"
    if grep -Eq '^ABSD BOOT OK$|^SMP FPU USER |^SMP QUEUE TRANSFER ' "$d/serial.log"; then exit 1; fi
    printf '0\n' > "$d/status"
}
base='smp-user-test smp-user-preempt smp-scheduler-test smp-fpu-migration-test'
one production "$production" "$base" 'SMP USER TEST REQUIRES smp-user-test BUILD'
one no-scheduler "$prototype" 'smp-user-test smp-user-preempt smp-fpu-migration-test' 'FPU migration requires closed preemptive scheduler test'
one no-timer "$prototype" 'smp-user-test smp-scheduler-test smp-fpu-migration-test' 'scheduler requires preemptive qualification'
one timer-mutant "$prototype" "$base smp-timer-disabled" 'timer mutant requires qualification boot'
one user-mutant "$prototype" "$base smp-user-double-claim" 'SMP mutant requires qualification boot'
one handoff-mutant "$prototype" "$base handoff-negative-test" 'FPU migration refuses unrelated handoff mutant'
result=0
