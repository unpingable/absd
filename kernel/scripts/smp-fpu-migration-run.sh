#!/bin/sh
# One fresh closed FXSAVE migration boot. Expected failures retain receipts.
set -eu
kernel=${1:?kernel ELF}; out=${2:?output}; mutant=${3:-}
case "$mutant" in ''|skip-restore|crosswire) ;; *) exit 1;; esac
mkdir "$out"
result=1
finish() { printf '%s\n' "$result" > "$out/status"; }
trap finish EXIT
mkdir -p "$out/iso/boot/grub"
cp "$kernel" "$out/iso/boot/absd-kernel"
sha256sum "$kernel" > "$out/kernel.sha256"
options='smp-user-test smp-user-preempt smp-scheduler-test smp-fpu-migration-test'
if [ -n "$mutant" ]; then options="$options smp-fpu-$mutant"; fi
printf '%s\n' 'set timeout=0' 'menuentry "ABSD FPU migration" {' " multiboot2 /boot/absd-kernel $options" ' boot' '}' > "$out/iso/boot/grub/grub.cfg"
grub-mkrescue -o "$out/boot.iso" "$out/iso" > "$out/iso.log" 2>&1
qstatus=0
python3 scripts/smp-user-qemu.py "$out" > "$out/runner.log" 2>&1 || qstatus=$?
if [ -z "$mutant" ]; then
    test "$qstatus" -eq 3
    python3 scripts/check-smp-fpu-migration.py "$out/serial.log" > "$out/oracle.log" 2>&1
else
    test "$qstatus" -eq 7
    if python3 scripts/check-smp-fpu-migration.py "$out/serial.log" > "$out/oracle.log" 2>&1; then exit 1; fi
    grep -q "SMP FPU INJECT $mutant=1" "$out/serial.log"
    grep -q 'SMP USER FIXTURE FAILED role=61 error=FPU migration live control/arithmetic/XMM state' "$out/serial.log"
    if grep -qx 'ABSD BOOT OK' "$out/serial.log"; then exit 1; fi
fi
result=0
