#!/bin/sh
# Builds the SSH server (ssh/) for ABSD from its own workspace and lock with
# this repository's staged standard library and compiler wrapper, after
# staging sunset (scripts/stage-ssh.sh). Entropy is getrandom's RDRAND
# backend (`getrandom_backend="rdrand"`), as for every other ABSD program.
# The workspace sits inside this repository, so the repository's
# .cargo/config.toml supplies the target's flags; its relative linker
# script resolves through the ssh/user-linker.ld link.
# Arguments are fixed at build time (`ABSD_PROGRAM_ARGS`) unless a brokered
# start supplies them:
#   sshd.elf                  the server
#   absd-fsd.elf              the file server of its `fsd` boot
#   absd-fsd-regenerate.elf   the same file server started with
#                             --regenerate-host-key
#   sshtest.elf               the matrix's session helper
#   absd-enroll.elf           the enrollment image's key writer
# Requires scripts/stage-library.sh to have staged the sysroot.
# Source paths are remapped (scripts/inputs.sh, absd_rust_remap), so the
# programs do not depend on the checkout path (N3).
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
. "$root/scripts/inputs.sh"
absd_rust_remap
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
sysroot=$root/.staged-sysroot
test -d "$sysroot/lib/rustlib/src/rust/library"
"$root/scripts/stage-ssh.sh"
# As in prepare-and-build.sh: build-std fingerprints do not notice a
# replaced sysroot at the same path, so never reuse this workspace's
# ABSD output.
rm -rf "$root/ssh/target/x86_64-unknown-absd"

# build ARGS BIN:ELF...: one build with ARGS fixed, copying each BIN.
build() {
args=$1
shift
(cd "$root/ssh" && env -u CARGO_ENCODED_RUSTFLAGS -u RUSTFLAGS -u RUSTC_WRAPPER -u RUSTC_WORKSPACE_WRAPPER \
ABSD_REAL_RUSTC=$toolchain/bin/rustc \
ABSD_STAGED_SYSROOT=$sysroot \
RUSTC=$root/scripts/rustc-staged.sh \
RUSTC_BOOTSTRAP=1 \
RUST_TARGET_PATH=$root/targets \
ABSD_PROGRAM_ARGS="$args" \
cargo +1.95.0 --config "$ABSD_RUST_REMAP" build -Z build-std=core,alloc,std,panic_abort \
    --target x86_64-unknown-absd --release --offline ${ABSD_CARGO_LOCKED---locked} --bin sshd --bin sshtest --bin absd-fsd --bin absd-enroll)
for pair in "$@"; do
    bin=${pair%%:*} elf=${pair#*:}
    cp "$root/ssh/target/x86_64-unknown-absd/release/$bin" "$root/$elf"
    printf '%s\n' "ABSD SSH $elf BUILT $(sha256sum "$root/$elf" | cut -d' ' -f1)"
done
}

build "" sshd:sshd.elf absd-fsd:absd-fsd.elf absd-enroll:absd-enroll.elf sshtest:sshtest.unstripped
# The matrix's session helper, installed as /bin/sshtest (symbols stripped:
# it travels through the importer).
llvm-strip-18 -o "$root/sshtest.elf" "$root/sshtest.unstripped"
rm -f "$root/sshtest.unstripped"
build "--regenerate-host-key" absd-fsd:absd-fsd-regenerate.elf
