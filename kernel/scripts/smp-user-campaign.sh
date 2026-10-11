#!/bin/sh
# Durable, serialized matrix body. Recovery resumes supervision, never reruns
# this producer in place. Each subcase requires a new directory.
set -eu
kernel=${1:?kernel}
out=${2:?new campaign directory}
repeat_count=${3:-16}
mkdir "$out"
result=1
finish() { printf '%s\n' "$result" > "$out/status.tmp"; mv "$out/status.tmp" "$out/status"; }
trap finish EXIT
trap 'exit 1' HUP INT TERM
for n in $(seq -w 1 "$repeat_count"); do
    printf 'positive-%s\n' "$n" > "$out/phase"
    sh scripts/smp-user-run.sh "$kernel" "$out/p$n"
done
if [ "$repeat_count" -gt 0 ]; then
    python3 scripts/test-smp-user-oracle.py "$out/p01/serial.log" > "$out/oracle-controls.log"
fi
for mode in rt-test rt-class block-ata block-nvme net guards; do
    printf 'regression-%s\n' "$mode" > "$out/phase"
    sh scripts/smp-user-regression.sh "$kernel" "$out/$mode" "$mode"
done
for mutant in double-claim lost-wake early-ack early-finish serialized early-publication; do
    printf 'negative-%s\n' "$mutant" > "$out/phase"
    options="smp-user-test smp-user-$mutant"
    if [ "$mutant" = early-publication ]; then options='smp-user-test handoff-negative-test'; fi
    if sh scripts/smp-user-run.sh "$kernel" "$out/m-$mutant" "$options"; then
        echo "negative control accepted: $mutant" >&2
        exit 1
    fi
    test -f "$out/m-$mutant/qemu.status"
    test "$(cat "$out/m-$mutant/qemu.status")" -ne 3
    if grep -q '^SMP USER COOPERATIVE STRUCTURAL OK$' "$out/m-$mutant/serial.log"; then
        echo "negative control reached success: $mutant" >&2
        exit 1
    fi
    grep -Eq 'ABSD PANIC:|SMP USER FIXTURE FAILED' "$out/m-$mutant/serial.log"
    printf 'REJECT %s\n' "$mutant" >> "$out/mutants.log"
done
printf '%s\n' terminal > "$out/phase"
result=0
