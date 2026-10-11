#!/bin/sh
# One KVM-only case. All substantial artifacts are in the named scratch root.
set -eu
kernel=${1:?qualified kernel ELF}
out=${2:?new case directory}
option=${3:-smp-user-test}
mkdir "$out"
result=1
finish() {
    printf '%s\n' "$result" > "$out/status.tmp"
    mv "$out/status.tmp" "$out/status"
}
trap finish EXIT
test -c /dev/kvm
test -r /dev/kvm && test -w /dev/kvm
sha256sum "$kernel" > "$out/kernel.sha256"
qemu-system-x86_64 --version > "$out/qemu.version"
uname -a > "$out/host.version"
printf '%s\n' 'accel=kvm vcpus=2 memory=256MiB' "options=$option" > "$out/identity"
mkdir -p "$out/iso/boot/grub"
cp "$kernel" "$out/iso/boot/absd-kernel"
printf '%s\n' 'set timeout=0' 'menuentry "ABSD SMP user test" {' \
    "  multiboot2 /boot/absd-kernel $option" '  boot' '}' > "$out/iso/boot/grub/grub.cfg"
grub-mkrescue -o "$out/boot.iso" "$out/iso" > "$out/iso.log" 2>&1
printf '%s\n' running-kvm > "$out/phase"
qstatus=0
python3 scripts/smp-user-qemu.py "$out" || qstatus=$?
printf '%s\n' "$qstatus" > "$out/qemu.status"
test "$qstatus" -eq 3
case "$option" in
    *smp-scheduler-test*)
        python3 scripts/check-smp-user.py "$out/serial.log" --preemptive --modern > "$out/oracle.log"
        python3 scripts/check-modern-smp.py "$out/serial.log" >> "$out/oracle.log"
        expected_cases=25
        ;;
    *smp-user-preempt*)
        python3 scripts/check-smp-user.py "$out/serial.log" --preemptive > "$out/oracle.log"
        expected_cases=21 ;;
    *)
        python3 scripts/check-smp-user.py "$out/serial.log" > "$out/oracle.log"
        expected_cases=17 ;;
esac
test "$(grep -cx 'SMP USER COOPERATIVE STRUCTURAL OK' "$out/serial.log")" -eq 1
test "$(grep -cx 'ABSD BOOT OK' "$out/serial.log")" -eq 1
test "$(grep -c '^SMP USER OVERLAP cpu=' "$out/serial.log")" -eq 2
test "$(grep -c '^SMP USER CASE id=' "$out/serial.log")" -eq "$expected_cases"
if grep -Eq 'ABSD PANIC:|KERNEL FAULT|FIXTURE FAILED|WORKLOAD FAILED' "$out/serial.log"; then
    echo 'SMP user case failed' >&2
    exit 1
fi
printf '%s\n' terminal > "$out/phase"
result=0
