#!/bin/sh
set -eu

if [ "${ABSD_FIXTURE_IMPORT_STOP+x}" = x ]; then
    echo "prepare-and-build: qualification-only ABSD_FIXTURE_IMPORT_STOP must be unset" >&2
    exit 1
fi

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$root/scripts/inputs.sh"
# cargo finds the workspace from the working directory, not from $root.
cd "$root"
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
stage=$root/.staged-sysroot
# Optional source/output binding. A failed build leaves only .pending;
# success is published only after every production step below returns zero.
if [ -n "${ABSD_BUILD_RECEIPT:-}" ]; then
    python3 "$root/scripts/operator_build_receipt.py" begin "$root" "$ABSD_BUILD_RECEIPT" "$toolchain"
fi

# Cargo's build-std fingerprints do not reliably notice replacement of a
# disposable sysroot at the same path. Never reuse std archives across a fresh
# source/patch verification occurrence. ABSD_INCREMENTAL=1 keeps the target
# directory and an already staged sysroot: for rebuilding the same verified
# inputs with another ABSD_RELEASE_ID (scripts/release.py build), never for
# a first build or after an input changed.
if [ "${ABSD_INCREMENTAL:-0}" = 1 ] && [ -d "$stage/lib/rustlib/src/rust/library" ] && [ -d "$root/target" ]; then
    printf '%s\n' "prepare-and-build: incremental (ABSD_INCREMENTAL=1): target and staged sysroot kept"
else
    # The integration workspace's objects are built against this sysroot
    # too: a fresh one invalidates them (scripts/build-integration.sh).
    rm -rf "$root/target" "$root/integration/target"
    "$root/scripts/stage-library.sh"
fi

# SQLite (bundled by rusqlite) is C: compile it freestanding for the ABSD
# target against the declarations in sqlite/include, whose symbols the
# absd-sqlite crate and absd-runtime define. SQLITE_OS_OTHER makes SQLite use
# only the VFS that absd-sqlite registers.
clang_include=$(clang -print-resource-dir)/include

# Source paths remapped so the programs do not depend on the checkout path
# (scripts/inputs.sh, absd_rust_remap); exported for build-ssh.sh too.
absd_rust_remap

env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS \
    -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
ABSD_REAL_RUSTC=$toolchain/bin/rustc \
ABSD_STAGED_SYSROOT=$stage \
RUSTC=$root/scripts/rustc-staged.sh \
RUSTC_BOOTSTRAP=1 \
RUST_TARGET_PATH=$root/targets \
CC_x86_64_unknown_absd=clang \
AR_x86_64_unknown_absd=llvm-ar-18 \
CRATE_CC_NO_DEFAULTS=1 \
CFLAGS_x86_64_unknown_absd="--target=x86_64-unknown-none-elf -ffreestanding -nostdinc -isystem $clang_include -I$root/sqlite/include -mcmodel=large -fno-pic -O2 -ffunction-sections -fdata-sections" \
LIBSQLITE3_FLAGS="-DSQLITE_OS_OTHER=1 -DSQLITE_OMIT_LOCALTIME -USQLITE_ENABLE_LOAD_EXTENSION -DSQLITE_OMIT_LOAD_EXTENSION" \
cargo +1.95.0 --config "$ABSD_RUST_REMAP" build -Z build-std=core,alloc,std,panic_abort \
    --release --locked --offline

cp "$root/target/x86_64-unknown-absd/release/absd-std-probe" "$root/probe.elf"
cp "$root/target/x86_64-unknown-absd/release/absd_logd" "$root/absd-logd.elf"
cp "$root/target/x86_64-unknown-absd/release/exit_std" "$root/exit-std.elf"
cp "$root/target/x86_64-unknown-absd/release/text_stats" "$root/text-stats.elf"
cp "$root/target/x86_64-unknown-absd/release/panic_std" "$root/panic-std.elf"
cp "$root/target/x86_64-unknown-absd/release/fixture_import" "$root/fixture-import.elf"
cp "$root/target/x86_64-unknown-absd/release/broker_requester" "$root/broker-requester.elf"
cp "$root/target/x86_64-unknown-absd/release/broker_echo" "$root/broker-echo.elf"
# Commands installed under /bin by the exec matrix, and its probe (also
# installed as /bin/exec-probe). Symbols are stripped: the files travel
# into the guest filesystem through init's pipe.
rm -rf "$root/commands"
mkdir -p "$root/commands"
for command in echo pwd ls cat printenv uname mkdir rm mv cp head tail wc sha256sum stat df sync man date uptime release sysinfo health net-status terminal-size ps interfaces dmesg logs; do
    llvm-strip-18 -o "$root/commands/$command" "$root/target/x86_64-unknown-absd/release/$command"
done
llvm-strip-18 -o "$root/exec-probe.elf" "$root/target/x86_64-unknown-absd/release/exec_probe"
# The file server matrix's session probe, installed as /bin/fsd-probe.
llvm-strip-18 -o "$root/fsd-probe.elf" "$root/target/x86_64-unknown-absd/release/fsd_probe"
# The shell, installed as /bin/absd-sh, the worker that starts it, and the
# shell matrix's helper command /bin/sh-probe.
llvm-strip-18 -o "$root/commands/absd-sh" "$root/target/x86_64-unknown-absd/release/absd_sh"
cp "$root/commands/absd-sh" "$root/commands/sh"
llvm-strip-18 -o "$root/commands/sh-probe" "$root/target/x86_64-unknown-absd/release/sh_probe"
cp "$root/target/x86_64-unknown-absd/release/sh_launch" "$root/sh-launch.elf"
cp "$root/target/x86_64-unknown-absd/release/netd_probe" "$root/netd-probe.elf"
# The compatibility probe's worker (scripts/run-compat-probe.sh).
cp "$root/target/x86_64-unknown-absd/release/compat_launch" "$root/compat-launch.elf"
# The extended integration programs (other projects' code on ABSD) are
# built only in the full profile: nothing above or below needs them.
if [ "$ABSD_PROFILE" = full ]; then
    "$root/scripts/build-integration.sh"
else
    printf '%s\n' 'ABSD EXTENDED INTEGRATION NOT_BUILT profile=core'
fi
# The SSH server builds from its own workspace (ssh/) with patched sunset.
"$root/scripts/build-ssh.sh"
# Explicit application opt-in; no fixture trust or time is compiled into it.
case "${ABSD_HTTPS_DOCUMENT:-0}" in
    0) ;;
    1) python3 "$root/scripts/build-native-tls-fixture.py" --document-app \
        --stage "${ABSD_TLS_STAGE:?set an owned external ring stage}" \
        --cargo-home "${CARGO_HOME:?set an isolated public Cargo home}" \
        --receipt "${ABSD_HTTPS_DOCUMENT_RECEIPT:?set a fresh build receipt}" ;;
    *) echo 'ABSD_HTTPS_DOCUMENT must be 0 or 1' >&2; exit 1 ;;
esac
# The manual: mdoc sources rendered to plain text for /share/man.
"$root/scripts/render-man.sh"

if [ -n "${ABSD_BUILD_RECEIPT:-}" ]; then
    python3 "$root/scripts/operator_build_receipt.py" finish "$root" "$ABSD_BUILD_RECEIPT"
fi
