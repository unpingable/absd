#!/bin/sh
# Three distinct, init-only substitutions. Direct E9 refusal avoids console
# recursion; exact boot-option custody distinguishes the intended controls.
set -eu
kernel=${1:?qualified ELF}; out=${2:?new output directory}
mkdir "$out"
result=1
trap 'printf "%s\n" "$result" > "$out/status"' EXIT
for control in wrong-id alias uninitialized; do
    case_dir=$out/$control
    mkdir -p "$case_dir/iso/boot/grub"
    cp "$kernel" "$case_dir/iso/boot/absd-kernel"
    sha256sum "$kernel" > "$case_dir/kernel.sha256"
    options="smp-user-test smp-user-preempt smp-scheduler-test cpu-identity-$control"
    printf '%s\n' "$options" > "$case_dir/options"
    printf '%s\n' 'set timeout=0' 'menuentry "CPU identity substitution" {' \
        " multiboot2 /boot/absd-kernel $options" ' boot' '}' > "$case_dir/iso/boot/grub/grub.cfg"
    grub-mkrescue -o "$case_dir/boot.iso" "$case_dir/iso" > "$case_dir/iso.log" 2>&1
    qstatus=0
    python3 scripts/smp-user-qemu.py "$case_dir" -debugcon "file:$case_dir/identity-refusal.log" \
        > "$case_dir/runner.log" 2>&1 || qstatus=$?
    test "$qstatus" -eq 7
    python3 - "$case_dir" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
assert (p/'identity-refusal.log').read_bytes() == b'I'
text = (p/'serial.log').read_text()
assert 'ABSD KERNEL BOOT' in text
assert not any(x in text for x in ('ABSD BOOT OK', 'ABSD PANIC:', 'KERNEL FAULT'))
(p/'oracle.log').write_text('CPU IDENTITY INITIALIZATION CONTROL REJECTED\n')
PY
    printf '%s\n' 0 > "$case_dir/status"
done
result=0
