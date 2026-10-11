#!/bin/sh
# A refused return must not conceal a mutation. Compilation/timeouts never count.
set -eu
cd "$(dirname "$0")/.."
qemu=${1:-qemu-system-x86_64}
work=build/authority-effect-mutants/$(python3 -c 'import uuid;print(uuid.uuid4())')
mkdir -p "$work"
work=$(cd "$work" && pwd)
sh scripts/authority-effect-test.sh --prepare "$work/fixture"
for variant in positive absd_mutant_denied_cell_effect absd_mutant_handle_ignore_tag; do
    flags=''; test "$variant" = positive || flags="--cfg $variant"
    mkdir "$work/$variant"
    RUSTFLAGS="$flags" make --no-print-directory external-iso EXTERNAL_TARGET="$work/kernel-target" \
        EXTERNAL_USER_ELF="$work/fixture/probe.elf" EXTERNAL_INPUT="$work/fixture/empty" \
        EXTERNAL_EXPECTED="$work/fixture/expected" > "$work/$variant/build.log" 2>&1
    cp build/absd-external.iso "$work/$variant/boot.iso"
    cp "$work/kernel-target/debug/absd-kernel" "$work/$variant/kernel.elf"
    status=0
    timeout 180s "$qemu" -cdrom "$work/$variant/boot.iso" -display none -serial "file:$work/$variant/serial.log" \
        -no-reboot -no-shutdown -device isa-debug-exit,iobase=0xf4,iosize=0x04 > "$work/$variant/qemu.log" 2>&1 || status=$?
    printf '%s\n' "$status" > "$work/$variant/qemu.status"
    if [ "$variant" = positive ]; then
        test "$status" -eq 3
        sh scripts/authority-effect-test.sh --check "$work/$variant/serial.log" "$work/fixture/expected"
        continue
    fi
    test "$status" -eq 7
    if sh scripts/authority-effect-test.sh --check "$work/$variant/serial.log" "$work/fixture/expected" > "$work/$variant/oracle.log" 2>&1; then
        echo "authority-effect-mutants: control escaped $variant" >&2; exit 1
    fi
    stage=denied-effect; test "$variant" = absd_mutant_denied_cell_effect || stage=aba-effect
    python3 - "$work/$variant/serial.log" "$stage" "$work/$variant/captured.txt" <<'PYCONTROL'
import re,sys
from pathlib import Path
lines=Path(sys.argv[1]).read_bytes().splitlines()
for mark in [b'EXTERNAL OUTPUT BEGIN encoding=hex',b'EXTERNAL WORKLOAD FAILED',b'USER EXIT pid=2 status=1',b'USER EXIT pid=1 status=99']:
    if lines.count(mark)!=1: raise SystemExit('control lacks exact failure provenance')
if any(b'PANIC' in s or b'KERNEL FAULT' in s for s in lines): raise SystemExit('unrelated failure')
if any(s.startswith(b'EXTERNAL OUTPUT END') for s in lines): raise SystemExit('unexpected completed output frame on failed workload')
chunks=bytearray()
for s in lines:
    m=re.fullmatch(rb'EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]*)',s)
    if m:
        if int(m[1],16)!=len(chunks): raise SystemExit('noncontiguous diagnostic')
        chunks.extend(bytes.fromhex(m[2].decode()))
        if len(chunks)>4096: raise SystemExit('oversized failure diagnostic')
Path(sys.argv[3]).write_bytes(chunks)
if chunks.splitlines()[-1]!=('COMPOSE FAILED stage='+sys.argv[2]).encode(): raise SystemExit('wrong effect failure')
PYCONTROL
    echo "AUTHORITY EFFECT MUTANT REJECTED $variant stage=$stage qemu=$status"
done
echo "AUTHORITY EFFECT MUTANTS OK controls=2 retained=$work"
