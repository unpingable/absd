#!/bin/sh
# Bounded durable producer body; launch with the existing user-systemd method.
set -eu
feature=${SMP_BUILD_FEATURE:-smp-user-test}
case "$feature" in smp-user-test|smp-scheduler-test) ;; *) exit 1 ;; esac
out=${1:?scratch output directory}
cd "$(dirname "$0")/.."
result=1
finish() {
    printf '%s\n' "$result" > "$out/build.status.tmp"
    mv "$out/build.status.tmp" "$out/build.status"
}
trap finish EXIT
printf '%s\n' verify-source > "$out/build.phase"
sha256sum -c "$out/source.sha256" > "$out/build.source-check.log"
printf '%s\n' compile > "$out/build.phase"
cargo rustc --offline --features "$feature" --target-dir "$out/target" --bin absd-kernel -- \
    -C relocation-model=static -C code-model=kernel -C no-redzone=yes \
    -C link-arg=-Tlinker.ld -C link-arg=-nostdlib -C link-arg=-no-pie
sha256sum "$out/target/debug/absd-kernel" > "$out/kernel.sha256"
sha256sum -c "$out/source.sha256" > "$out/build.source-postcheck.log"
printf '%s\n' terminal > "$out/build.phase"
result=0
