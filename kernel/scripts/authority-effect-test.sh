#!/bin/sh
# Direct Cell effect/refusal, stale-slot, partial-copy and capacity regression.
# Parent campaign supplies durable supervision and storage admission.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

# Also used by the parent-owned kernel mutation runner. This keeps the
# exact framed-output oracle and final kernel accounting records.
if [ "${1:-}" = --check ]; then
    log=${2:?serial log required}
    expected=${3:-scripts/authority-effect.expected}
    python3 - "$log" "$expected" <<'PYCHECK'
import subprocess, sys
from pathlib import Path
log=Path(sys.argv[1]); expected=Path(sys.argv[2]).read_bytes()
actual=subprocess.check_output([sys.executable,"scripts/check-external-output.py","--print",str(log)])
if actual!=expected: raise SystemExit("composition oracle: exact effect output mismatch")
lines=log.read_bytes().splitlines()
for marker in [b"USER EXIT pid=2 status=0",b"EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0",b"EXTERNAL WORKLOAD OK",b"ABSD BOOT OK"]:
    if lines.count(marker)!=1: raise SystemExit("composition oracle: missing/duplicate final marker")
if any(b"PANIC" in s or b"KERNEL FAULT" in s or b"EXTERNAL WORKLOAD FAILED" in s for s in lines):
    raise SystemExit("composition oracle: unrelated failure")
print("AUTHORITY EFFECT ORACLE OK effect-state=true exact-output=true final-census=zero")
PYCHECK
    exit 0
fi

prepare() {
    work=$1
    mkdir -p "$work"
    work=$(CDPATH= cd -- "$work" && pwd)
    target="$work/user-target"
    flags="-C relocation-model=static -C code-model=large -C link-arg=-nostdlib -C link-arg=-static -C link-arg=-no-pie -C link-arg=-Wl,-T,$root/user/linker.ld"
    # Explicit existing freestanding linker contract. Each output copy is
    # immutable input to the next stage, never a mutable Cargo output alias.
    env -u CARGO_ENCODED_RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
        -u CARGO_BUILD_TARGET -u CARGO_MAKEFLAGS \
        RUSTFLAGS="$flags" cargo build --quiet --release --manifest-path user/Cargo.toml \
        --target-dir "$target" --target x86_64-unknown-linux-gnu --bin authority_effect_child
    cp "$target/x86_64-unknown-linux-gnu/release/authority_effect_child" "$work/child.elf"
    env -u CARGO_ENCODED_RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
        -u CARGO_BUILD_TARGET -u CARGO_MAKEFLAGS \
        RUSTFLAGS="$flags" ABSD_AUTHORITY_EFFECT_CHILD_EMBED="$work/child.elf" \
        cargo build --quiet --release --manifest-path user/Cargo.toml \
        --target-dir "$target" --target x86_64-unknown-linux-gnu --bin authority_effect_probe
    cp "$target/x86_64-unknown-linux-gnu/release/authority_effect_probe" "$work/probe.elf"
    : > "$work/empty"
    cp scripts/authority-effect.expected "$work/expected"
    python3 - "$work" <<'PY'
from pathlib import Path
import hashlib
import json
import subprocess
import sys
root = Path(sys.argv[1])
files = ["child.elf", "probe.elf", "empty", "expected"]
record = {"schema_version": 1,
          "source_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
          "fixture": "direct Cell effect/refusal and stale-slot regression, no ABI changes",
          "files": {name: {"path": str(root / name), "sha256": hashlib.sha256((root/name).read_bytes()).hexdigest()}
                    for name in files}}
with (root / "fixture.json").open("x") as out:
    out.write(json.dumps(record, indent=2) + "\n")
PY
    printf 'AUTHORITY_EFFECT_FIXTURE=%s\n' "$work/fixture.json"
}

if [ "${1:-}" = --prepare ]; then
    prepare "${2:?fresh fixture directory required}"
    exit 0
fi
qemu=${1:-qemu-system-x86_64}
run=$(python3 -c 'import uuid; print(uuid.uuid4())')
work="build/authority-effect-test/$run"
prepare "$work"
# --prepare canonicalizes work to its absolute path.
make --no-print-directory external-iso QEMU="$qemu" \
    EXTERNAL_TARGET="$work/kernel-target" EXTERNAL_USER_ELF="$work/probe.elf" \
    EXTERNAL_INPUT="$work/empty" EXTERNAL_EXPECTED="$work/expected" \
    > "$work/kernel-build.log" 2>&1
cp build/absd-external.iso "$work/authority-effect.iso"
status=0
timeout 180s "$qemu" -cdrom "$work/authority-effect.iso" \
    -display none -serial "file:$work/serial.log" -no-reboot -no-shutdown \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 > "$work/qemu.log" 2>&1 || status=$?
printf '%s\n' "$status" > "$work/qemu.status"
if [ "$status" -ne 3 ]; then
    echo "authority-effect-test: unexpected QEMU exit $status; retained $work" >&2
    exit 1
fi
sh scripts/authority-effect-test.sh --check "$work/serial.log" "$work/expected"
echo "AUTHORITY EFFECT TEST OK retained=$work"
