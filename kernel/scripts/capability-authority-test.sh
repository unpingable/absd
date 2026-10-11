#!/bin/sh
# Focused regression fixture: ordinary Cell rights, process-local handle
# identity, copied grant lifetime, and process-death object cleanup.
# Parent campaign supplies durable supervision and storage admission.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

# Also used by the parent-owned kernel mutation runner. This keeps the
# exact framed-output oracle, with just one explicitly typed PID field.
if [ "${1:-}" = --check ]; then
    log=${2:?serial log required}
    expected=${3:-scripts/capability-authority.expected}
    python3 - "$log" "$expected" <<'PY'
import re
import subprocess
import sys
from pathlib import Path

log = Path(sys.argv[1])
expected = Path(sys.argv[2]).read_bytes()
serial = log.read_bytes().splitlines()
decoded = subprocess.run(
    [sys.executable, "scripts/check-external-output.py", "--print", str(log)],
    check=True, capture_output=True,
).stdout
leaves = re.findall(rb"(?m)^CAP LEAF pid=([1-9][0-9]*)$", decoded)
if len(leaves) != 1 or expected.count(b"{LEAF_PID}") != 1:
    raise SystemExit("capability oracle: missing/duplicate typed leaf identity")
leaf = leaves[0]
if decoded != expected.replace(b"{LEAF_PID}", leaf):
    raise SystemExit("capability oracle: captured output differs from exact fixture")

def one(pattern, description):
    found = [m for line in serial if (m := re.fullmatch(pattern, line))]
    if len(found) != 1:
        raise SystemExit(f"capability oracle: missing/duplicate {description}")
    return found[0]

# The PID is reported by grantor A using its own legitimate child-info
# authority. Bind that data to independently produced kernel ancestry and
# terminal records. Acknowledgement or EOF alone cannot establish exit 0.
grantor = one(rb"SPAWN OK pid=" + leaf + rb" parent=([1-9][0-9]*) program=image",
              "leaf spawn").group(1)
probe = one(rb"SPAWN OK pid=" + grantor + rb" parent=([1-9][0-9]*) program=image",
            "grantor spawn").group(1)
if len({leaf, grantor, probe}) != 3:
    raise SystemExit("capability oracle: invalid process ancestry")
for pid, role in ((leaf, "leaf"), (grantor, "grantor"), (probe, "probe")):
    status = one(rb"USER EXIT pid=" + pid + rb" status=(-?[0-9]+)", role + " exit").group(1)
    if status != b"0":
        raise SystemExit(f"capability oracle: {role} exited nonzero")
    if any(re.match(rb"USER FAULT pid=" + pid + rb"(?: |$)", line) for line in serial):
        raise SystemExit(f"capability oracle: {role} faulted")
for marker in (
    b"EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0",
    b"EXTERNAL WORKLOAD OK", b"ABSD BOOT OK",
):
    if serial.count(marker) != 1:
        raise SystemExit("capability oracle: final canonical marker missing/duplicate")
if any(b"PANIC" in line or b"KERNEL FAULT" in line or b"EXTERNAL WORKLOAD FAILED" in line
       for line in serial):
    raise SystemExit("capability oracle: kernel/boot failure")
print("CAPABILITY AUTHORITY ORACLE OK leaf-exit=0 exact-output=true final-census=zero")
PY
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
        RUSTFLAGS="$flags" ABSD_CAPABILITY_ACTOR_EMBED= \
        cargo build --quiet --release --manifest-path user/Cargo.toml \
        --target-dir "$target" --target x86_64-unknown-linux-gnu --bin capability_actor
    cp "$target/x86_64-unknown-linux-gnu/release/capability_actor" "$work/leaf.elf"
    env -u CARGO_ENCODED_RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
        -u CARGO_BUILD_TARGET -u CARGO_MAKEFLAGS \
        RUSTFLAGS="$flags" ABSD_CAPABILITY_ACTOR_EMBED="$work/leaf.elf" \
        cargo build --quiet --release --manifest-path user/Cargo.toml \
        --target-dir "$target" --target x86_64-unknown-linux-gnu --bin capability_actor
    cp "$target/x86_64-unknown-linux-gnu/release/capability_actor" "$work/actor.elf"
    env -u CARGO_ENCODED_RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
        -u CARGO_BUILD_TARGET -u CARGO_MAKEFLAGS \
        RUSTFLAGS="$flags" ABSD_CAPABILITY_ACTOR_EMBED="$work/actor.elf" \
        cargo build --quiet --release --manifest-path user/Cargo.toml \
        --target-dir "$target" --target x86_64-unknown-linux-gnu --bin capability_probe
    cp "$target/x86_64-unknown-linux-gnu/release/capability_probe" "$work/probe.elf"
    : > "$work/empty"
    cp scripts/capability-authority.expected "$work/expected"
    python3 - "$work" <<'PY'
from pathlib import Path
import hashlib
import json
import subprocess
import sys
root = Path(sys.argv[1])
files = ["leaf.elf", "actor.elf", "probe.elf", "empty", "expected"]
record = {"schema_version": 1,
          "source_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
          "fixture": "existing Cell authority, no ABI changes",
          "files": {name: {"path": str(root / name), "sha256": hashlib.sha256((root/name).read_bytes()).hexdigest()}
                    for name in files}}
with (root / "fixture.json").open("x") as out:
    out.write(json.dumps(record, indent=2) + "\n")
PY
    printf 'CAPABILITY_FIXTURE=%s\n' "$work/fixture.json"
}

if [ "${1:-}" = --prepare ]; then
    prepare "${2:?fresh fixture directory required}"
    exit 0
fi
qemu=${1:-qemu-system-x86_64}
run=$(python3 -c 'import uuid; print(uuid.uuid4())')
work="build/capability-authority-test/$run"
prepare "$work"
# --prepare canonicalizes work to its absolute path.
make --no-print-directory external-iso QEMU="$qemu" \
    EXTERNAL_TARGET="$work/kernel-target" EXTERNAL_USER_ELF="$work/probe.elf" \
    EXTERNAL_INPUT="$work/empty" EXTERNAL_EXPECTED="$work/expected" \
    > "$work/kernel-build.log" 2>&1
cp build/absd-external.iso "$work/capability-authority.iso"
status=0
timeout 180s "$qemu" -cdrom "$work/capability-authority.iso" \
    -display none -serial "file:$work/serial.log" -no-reboot -no-shutdown \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 > "$work/qemu.log" 2>&1 || status=$?
printf '%s\n' "$status" > "$work/qemu.status"
if [ "$status" -ne 3 ]; then
    echo "capability-authority-test: unexpected QEMU exit $status; retained $work" >&2
    exit 1
fi
sh scripts/capability-authority-test.sh --check "$work/serial.log" "$work/expected"
echo "CAPABILITY AUTHORITY TEST OK retained=$work"
