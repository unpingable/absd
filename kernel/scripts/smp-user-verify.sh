#!/bin/sh
set -eu
feature=${SMP_BUILD_FEATURE:-smp-user-test}
case "$feature" in smp-user-test|smp-scheduler-test) ;; *) exit 1 ;; esac
out=${1:?output directory}
result=1
finish() { printf '%s\n' "$result" > "$out/verify.status.tmp"; mv "$out/verify.status.tmp" "$out/verify.status"; }
trap finish EXIT
sh scripts/smp-user-build.sh "$out"
cp "$out/target/debug/absd-kernel" "$out/qualified.elf"
printf '%s\n' host-tests > "$out/verify.phase"
cargo test --offline --workspace --exclude absd-user --target-dir "$out/target" > "$out/tests.log" 2>&1
cargo fmt --all -- --check > "$out/fmt.log" 2>&1
cargo clippy --offline --workspace --all-targets --features "$feature" --target-dir "$out/target" -- -D warnings > "$out/clippy.log" 2>&1
for feature in ap-startup ap-userspace; do
    if cargo check --offline --bin absd-kernel --features "$feature" --target-dir "$out/target" > "$out/guard-$feature.log" 2>&1; then
        echo "compile refusal removed: $feature" >&2
        exit 1
    fi
    grep -q 'SMP_SERIALIZATION_LIFECYCLE refuses' "$out/guard-$feature.log"
done
printf '%s\n' production-build > "$out/verify.phase"
cargo rustc --offline --target-dir "$out/target" --bin absd-kernel -- \
    -C relocation-model=static -C code-model=kernel -C no-redzone=yes \
    -C link-arg=-Tlinker.ld -C link-arg=-nostdlib -C link-arg=-no-pie > "$out/production-build.log" 2>&1
cp "$out/target/debug/absd-kernel" "$out/production.elf"
sha256sum "$out/qualified.elf" "$out/production.elf" > "$out/qualified.sha256"
sha256sum -c "$out/source.sha256" > "$out/verify.source-postcheck.log"
printf '%s\n' terminal > "$out/verify.phase"
result=0
