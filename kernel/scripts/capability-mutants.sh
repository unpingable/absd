#!/bin/sh
# Deterministic correctness controls. Reuse one exact fixture and one kernel build tree.
# A build failure, VM timeout, or unrelated rejection never counts as a catch.
set -eu
cd "$(dirname "$0")/.."
qemu=${1:-qemu-system-x86_64}
work=${2:-build/capability-mutants/$(python3 -c 'import uuid; print(uuid.uuid4())')}
mkdir -p "$work"
work=$(cd "$work" && pwd)
sh scripts/capability-authority-test.sh --prepare "$work/fixture"
run_variant() {
    name=$1
    flags=$2
    mkdir "$work/$name"
    RUSTFLAGS="$flags" make --no-print-directory external-iso \
        EXTERNAL_TARGET="$work/kernel-target" EXTERNAL_USER_ELF="$work/fixture/probe.elf" \
        EXTERNAL_INPUT="$work/fixture/empty" EXTERNAL_EXPECTED="$work/fixture/expected" \
        > "$work/$name/build.log" 2>&1
    cp build/absd-external.iso "$work/$name/boot.iso"
    cp "$work/kernel-target/debug/absd-kernel" "$work/$name/kernel.elf"
    status=0
    timeout 180s "$qemu" -cdrom "$work/$name/boot.iso" -display none \
        -serial "file:$work/$name/serial.log" -no-reboot -no-shutdown \
        -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
        > "$work/$name/qemu.log" 2>&1 || status=$?
    printf '%s\n' "$status" > "$work/$name/qemu.status"
}
run_variant positive ''
test "$status" -eq 3
sh scripts/capability-authority-test.sh --check "$work/positive/serial.log" "$work/fixture/expected" > "$work/positive/oracle.log"
for mutant in absd_mutant_no_rights_check absd_mutant_cell_duplicate_widen absd_mutant_handle_ignore_tag absd_mutant_cell_skip_release; do
    run_variant "$mutant" "--cfg $mutant"
    # Only the kernel's normal success/failure termination is admissible.
    case "$status" in 3|7) ;; *) echo "capability-mutants: unexpected VM termination $status" >&2; exit 1 ;; esac
    if sh scripts/capability-authority-test.sh --check "$work/$mutant/serial.log" "$work/fixture/expected" > "$work/$mutant/oracle.log" 2>&1; then
        echo "capability-mutants: $mutant escaped" >&2; exit 1
    fi
    # The external harness refuses a nonzero workload before publishing END.
    # Validate its contiguous diagnostic chunks and exact failure outcome;
    # this does not substitute for the unchanged positive framed oracle.
    python3 - "$work/$mutant/serial.log" "$work/$mutant/captured.txt" <<'PYCONTROL'
import re, sys
from pathlib import Path
lines = Path(sys.argv[1]).read_bytes().splitlines()
assert lines.count(b"EXTERNAL OUTPUT BEGIN encoding=hex") == 1
assert lines.count(b"EXTERNAL WORKLOAD FAILED") == 1
assert lines.count(b"USER EXIT pid=2 status=1") == 1
assert lines.count(b"USER EXIT pid=1 status=99") == 1
chunks = bytearray()
for line in lines:
    m = re.fullmatch(rb"EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]*)", line)
    if m:
        assert int(m[1], 16) == len(chunks)
        chunks.extend(bytes.fromhex(m[2].decode()))
Path(sys.argv[2]).write_bytes(chunks)
PYCONTROL
    case "$mutant" in
        absd_mutant_no_rights_check|absd_mutant_cell_duplicate_widen) stage=c-attenuation ;;
        absd_mutant_handle_ignore_tag) stage=b-authority-refusal ;;
        absd_mutant_cell_skip_release) stage=a-b-c-census ;;
    esac
    grep -qx "CAP FAILED stage=$stage" "$work/$mutant/captured.txt"
    if grep -q 'PANIC\|KERNEL FAULT' "$work/$mutant/serial.log"; then
        echo "capability-mutants: $mutant produced unrelated kernel failure" >&2; exit 1
    fi
    echo "CAPABILITY MUTANT REJECTED $mutant stage=$stage qemu=$status"
done
echo "CAPABILITY MUTANTS OK controls=4 retained=$work"
