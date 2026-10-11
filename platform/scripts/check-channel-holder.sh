#!/bin/sh
# Actual runtime module, bounded syscall substitutions; no guest/server effects.
# The caller owns storage admission, durable execution and artifact disposition.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
out=${1:?usage: check-channel-holder.sh ABSOLUTE_CAMPAIGN_OUTPUT_DIRECTORY}
case "$out" in /*) ;; *) printf '%s\n' 'output must be absolute' >&2; exit 2 ;; esac
mkdir -p "$out"
test ! -e "$out/holder-result.txt"
toolchain=${ABSD_HOLDER_TOOLCHAIN:-1.95.0}
base=c54dc90007fe509c0e118b7ec9c6cbd6ea9aa356
git -C "$root" show "$base:runtime/src/fsd.rs" > "$out/original-fsd.rs"
cp "$root/runtime/src/fsd.rs" "$out/repaired-fsd.rs"
python3 - "$root" "$out" <<'PY'
import json, sys
from pathlib import Path
root, out = map(Path, sys.argv[1:])
for name, source, module in (
    ('original', 'fsd/tests/fixtures/runtime_holder_original.rs', 'original-fsd.rs'),
    ('repaired', 'fsd/tests/runtime_holder_exhaustion.rs', 'repaired-fsd.rs'),
):
    text = (root / source).read_text()
    old = '#[path = "../../runtime/src/fsd.rs"]'
    assert text.count(old) == 1, source
    text = text.replace(old, '#[path = ' + json.dumps(str(out / module)) + ']')
    (out / (name + '-fixture.rs')).write_text(text)
PY
# Match Cargo's test-profile unwind strategy for these standalone host tests.
# Production release binaries retain the workspace's panic=abort policy.
(cd "$root/fsd" && env -u RUSTFLAGS cargo +"$toolchain" build --offline --release \
    --config 'profile.release.panic="unwind"' \
    --target x86_64-unknown-linux-gnu --target-dir "$out/target" -p absd-fsd) \
    > "$out/build.log" 2>&1
for name in original repaired; do
    env -u RUSTFLAGS rustc +"$toolchain" --edition 2024 --test \
        --target x86_64-unknown-linux-gnu "$out/$name-fixture.rs" \
        --extern "absd_fsd=$out/target/x86_64-unknown-linux-gnu/release/libabsd_fsd.rlib" \
        -L "dependency=$out/target/x86_64-unknown-linux-gnu/release/deps" \
        -o "$out/$name-holder" > "$out/$name-compile.log" 2>&1
    result=0
    "$out/$name-holder" --nocapture > "$out/$name.log" 2>&1 || result=$?
    printf '%s\n' "$result" > "$out/$name.status"
    if [ "$name" = original ]; then
        test "$result" -eq 101
        grep -qx 'FSD HOLDER WITNESS duplicate=-24 parent_result=-5 parent_writes=1 child_info_calls=0' "$out/$name.log"
        grep -q '0 passed; 1 failed' "$out/$name.log"
    else
        test "$result" -eq 0
        grep -qx 'FSD HOLDER WITNESS duplicate=-24 parent_result=-11 parent_writes=0 child_info_calls=0' "$out/$name.log"
        grep -q '1 passed; 0 failed' "$out/$name.log"
    fi
done
sha256sum "$out"/*-fsd.rs "$out"/*-fixture.rs "$out"/*-holder > "$out/source-executable.sha256"
printf '%s\n' 'CHANNEL HOLDER ORIGINAL REJECTED WRITE=1' \
    'CHANNEL HOLDER REPAIRED AGAIN WRITE=0' > "$out/holder-result.txt"
cat "$out/holder-result.txt"
