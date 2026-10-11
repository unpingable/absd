#!/bin/sh
# One fresh bounded development-host KVM receipt; no external execution target.
set -eu
kernel=${1:?qualified ELF}; out=${2:?new directory}; cpus=${3:?2/4/6}; mutant=${4:-}
case "$cpus" in 2|4|6) ;; *) exit 1;; esac
option=''
marker=''
case "$mutant" in
    '') ;;
    restore-sentinel) option=smp-nway-restore-sentinel; marker='SMP NWAY INJECT restore-sentinel=1';;
    duplicate) option=smp-queue-duplicate; marker='duplicate runnable publication';;
    lost) option=smp-queue-lost; marker='runnable task lost queue registration';;
    early-transfer) option=smp-migrate-early; marker='p.is_runnable()';;
    early-ack) option=smp-user-early-ack; marker='CPU claim/model disagreement';;
    early-publication) option=handoff-negative-test; marker='handoff is not on a CPU-owned stack';;
    serialized) option=smp-user-serialized; marker='SMP NWAY SERIALIZATION REFUSED overlap=0 observer-started=1';;
    disabled-timer) option=smp-timer-disabled; marker='N-way all-worker progress';;
    missing-eoi) option=smp-timer-no-eoi; marker='N-way all-worker progress';;
    retained-cancel) option=smp-nway-retained-cancel; marker='blocked migration retained pending destination';;
    terminal-cpu) option=smp-nway-terminal-cpu; marker='composition terminal CPU differs from user witness';;
    *) exit 1;;
esac
mkdir "$out"
result=1
trap 'printf "%s\n" "$result" > "$out/status"' EXIT
mkdir -p "$out/iso/boot/grub"
cp "$kernel" "$out/iso/boot/absd-kernel"
sha256sum "$kernel" > "$out/kernel.sha256"
options="smp-user-test smp-user-preempt smp-scheduler-test smp-nway-test $option"
if [ "$cpus" != 2 ]; then options="$options smp-cpus=$cpus"; fi
printf '%s\n' 'set timeout=0' 'menuentry "ABSD N-way qualification" {' " multiboot2 /boot/absd-kernel $options" ' boot' '}' > "$out/iso/boot/grub/grub.cfg"
grub-mkrescue -o "$out/boot.iso" "$out/iso" > "$out/iso.log" 2>&1
qstatus=0
SMP_BENCH_VCPUS=$cpus python3 scripts/smp-user-qemu.py "$out" > "$out/runner.log" 2>&1 || qstatus=$?
if [ -z "$mutant" ]; then
    test "$qstatus" -eq 3
    python3 scripts/check-smp-nway.py "$out/serial.log" "$out/vcpu-placement.json" > "$out/oracle.log" 2>&1
else
    test "$qstatus" -eq 7
    if python3 scripts/check-smp-nway.py "$out/serial.log" "$out/vcpu-placement.json" > "$out/oracle.log" 2>&1; then exit 1; fi
    grep -Fq "$marker" "$out/serial.log"
    if [ "$mutant" = restore-sentinel ]; then
        grep -Fq 'error=N-way timer register state' "$out/serial.log"
    fi
    if [ "$mutant" = serialized ]; then
        grep -Fxq 'SMP NWAY INJECT serialized-placement=1 cpu=0' "$out/serial.log"
        for role in 129 130; do
            grep -Eq "^SMP NWAY PREEMPT pid=[0-9]+ generation=[0-9]+ role=$role cpu=0 saved=1$" "$out/serial.log"
        done
        grep -Eq '^SMP NWAY OBSERVER phase=2 start=[0-9]+ attempts=[1-9][0-9]* ' "$out/serial.log"
    fi
    if [ "$mutant" = retained-cancel ]; then
        grep -Fxq 'SMP NWAY COMPOSE INJECT retained-cancel=1' "$out/serial.log"
    fi
    if [ "$mutant" = terminal-cpu ]; then
        grep -Fxq 'SMP NWAY COMPOSE INJECT terminal-cpu=0' "$out/serial.log"
    fi
    if grep -qx 'ABSD BOOT OK' "$out/serial.log"; then exit 1; fi
fi
result=0
