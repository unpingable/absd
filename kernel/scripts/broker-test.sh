#!/bin/sh
# Init-brokered spawning (docs/BROKER.md): a durable worker without the
# spawn right asks init for programs; init starts only what the policy
# permits, narrows every handle, reports each outcome, and reclaims
# everything when the requester ends.
set -eu
# RDRAND backs the boot identity the matrix compares across processes.
qemu="${1:-qemu-system-x86_64} -cpu max,vendor=GenuineIntel,+rdrand"
cd "$(dirname "$0")/.."
work=build/broker-test
rm -rf "$work"
mkdir -p "$work"
: > "$work/empty"
make --no-print-directory external-build EXTERNAL_USER_ELF= >/dev/null
elf() {
    find build/external/target -name "$1.elf" -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2
}
probe=$(elf broker_probe)
# An owner image the kernel's loader refuses: ELF64 magic, nothing else.
legacy=$work/unloadable.elf
printf '\177ELF\002' > "$legacy"
head -c 59 /dev/zero >> "$legacy"
test -f "$probe"

boot() {
    step=$1
    make --no-print-directory durable-iso DURABLE_STEP=$step EXTERNAL_USER_ELF="$probe" \
        EXTERNAL_INPUT="$work/empty" BROKER_POLICY=scripts/broker-policy-test.txt \
        OWNER_4_ELF="$legacy" >/dev/null
    truncate -s 2M "$work/$step.img"
    scripts/durable-boot.sh "build/durable/absd-durable-$step.iso" "$work/$step.img" "$work/$step.log" 180 $qemu
}
clean() {
    grep -q '^DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ' "$work/$1.log"
    grep -q 'BROKER SUMMARY generation=1 .* idle=true' "$work/$1.log"
    ! grep -q 'PANIC\|KERNEL FAULT\|init: FAILED' "$work/$1.log"
}

status=$(boot 1)
test "$status" -eq 3
cat > "$work/expected-1" <<'OUT'
BROKER PROBE worker-spawn=refused
BROKER PROBE refusals=5
BROKER PROBE echo pid=true stdout=ping status=0
BROKER PROBE echo stderr=argv=echo hello spawn=refused block=read-only handles=6 boot-shared=true
BROKER PROBE fault=-1006 exit=7
BROKER PROBE nest status=0 NESTED echo=deep status=0 grandchild=true
BROKER PROBE slots-exhausted=refused
OUT
python3 scripts/check-external-output.py "$work/1.log" "$work/expected-1"
clean 1
grep -q '^DURABLE status=0 .* block_writes=0 ' "$work/1.log"
grep -q 'BROKER SUMMARY generation=1 requests=12 dropped=0 started=5 refused=7 exited=5 reclaimed=0 idle=true' "$work/1.log"
echo 'INIT BROKER SPAWN OK started=5 nested=1'
echo 'INIT BROKER AUTHORITY OK worker-spawn=refused child-spawn=refused child-block=read-only block_writes=0 handles=6'

status=$(boot 4)
test "$status" -eq 3
grep -q 'BROKER REFUSED requester=worker code=3' "$work/4.log"
printf 'BROKER PROBE malformed refused=true then-silent=true\n' > "$work/expected-4"
python3 scripts/check-external-output.py "$work/4.log" "$work/expected-4"
clean 4
echo 'INIT BROKER REFUSAL OK not-permitted=3 slot=3 unstartable=1 malformed=1'

# The requester ends while its child runs (2), while a nested requester
# holds a grandchild (3), right after asking (5: the request is dropped, or
# started and reclaimed at once, depending on who runs first), and
# halfway through a request (6).
for step in 2 3 5 6; do
    status=$(boot $step)
    test "$status" -eq 3
    clean $step
done
grep -q 'BROKER RECLAIMED pid=[0-9]* slot=0 outcome=-1' "$work/2.log"
test "$(grep -c 'BROKER RECLAIMED' "$work/3.log")" -eq 2
grep -q 'BROKER DROPPED\|BROKER RECLAIMED' "$work/5.log"
if grep -q 'BROKER STARTED' "$work/6.log"; then echo 'broker-test: step 6 started a program' >&2; exit 1; fi
echo 'INIT BROKER RECLAIM OK running=1 nested=2 frames=0 processes=0 cells=0 pipes=0'

# The worker fails init's collection (it closes its console and outlives
# init's wait) while its child runs: the boot fails, but the child is
# reclaimed before init gives up, so nothing outlives init.
status=$(boot 7)
test "$status" -eq 7
grep -q '^DURABLE status=99 frames=0 processes=0 cells=0 pipes=0 ' "$work/7.log"
grep -q 'init: FAILED at external workload outcome' "$work/7.log"
grep -q 'BROKER RECLAIMED pid=[0-9]* slot=0 outcome=-1' "$work/7.log"
grep -q 'BROKER SUMMARY generation=1 .* idle=true' "$work/7.log"
echo 'INIT BROKER ABORT RECLAIM OK outcome=failed reclaimed=1 processes=0'

# A requester that stops reading loses its channel whole: every reply it
# reads is complete, then end-of-file, never a torn reply. A refused start
# under pipe pressure leaves init holding no pipe.
status=$(boot 8)
test "$status" -eq 3
printf 'BROKER PROBE reply-flood whole=42 end=closed\n' > "$work/expected-8"
python3 scripts/check-external-output.py "$work/8.log" "$work/expected-8"
clean 8
status=$(boot 9)
test "$status" -eq 3
printf 'BROKER PROBE pipe-pressure refused=true recovered=true\n' > "$work/expected-9"
python3 scripts/check-external-output.py "$work/9.log" "$work/expected-9"
clean 9
echo 'INIT BROKER CHANNEL BOUNDS OK replies=whole pipes=recovered'
rm -rf "$work"
