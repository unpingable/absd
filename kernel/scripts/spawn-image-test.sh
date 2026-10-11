#!/bin/sh
# spawn_image (syscall 31): the external workload builds static ELF64 images
# in its own memory, starts one and reads its output through a pipe, and
# requires each refusal's exact error. The kernel's accounting line then
# proves that no refusal and no child left a frame, slot, cell, or pipe.
set -eu
qemu=${1:-qemu-system-x86_64}
cd "$(dirname "$0")/.."
work=build/spawn-image-test
rm -rf "$work"
mkdir -p "$work"
: > "$work/empty"
make --no-print-directory external-build EXTERNAL_USER_ELF= >/dev/null
probe=$(find build/external/target -name image_probe.elf -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2)
test -f "$probe"
cat > "$work/expected" <<'OUT'
SPAWN IMAGE child output=image child ok status=42 program=4294967295
SPAWN IMAGE malformed=-8 truncated=-8 entry=-8 below-window=-8 above-window=-8 interp=-8
SPAWN IMAGE zero=-22 oversize=-22 flags=-22 reserved=-22 count=-22
SPAWN IMAGE fault request=-14 image=-14 handles=-14
SPAWN IMAGE handles stale=-9
SPAWN IMAGE spawn-right child=-1 control=-14
SPAWN IMAGE pids-contiguous=true
SPAWN IMAGE OK
OUT
make --no-print-directory external-test QEMU="$qemu" EXTERNAL_USER_ELF="$probe" \
    EXTERNAL_INPUT="$work/empty" EXTERNAL_EXPECTED="$work/expected" >/dev/null
log=build/external.serial.log
test "$(grep -c '^SPAWN OK pid=[0-9]* parent=[0-9]* program=image$' "$log")" -eq 3
grep -qx 'EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0' "$log"
rm -rf "$work"
echo 'SPAWN IMAGE TEST OK children=3 refusals=16 frames=0 processes=0 cells=0 pipes=0'
