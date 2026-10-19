#!/bin/sh
# Reconstructs a release from its manifest (docs/RELEASE.md section 11):
#
#   reconstruct-release.sh [--rust-src-tarball T] [--workdir DIR]
#       [--kernel-dir DIR] [--platform-dir DIR] [--platform-products DIR]
#       [--toolchain-only] MANIFEST
#
# (a) Verifies this host's toolchain against the manifest (rustc 1.95.0 and
#     Cargo by binary and verbose identity, the installed rust-src by its
#     fingerprint and, with --rust-src-tarball, the published tarball by its
#     SHA-256 and library fingerprint; the kernel's rustc by commit; clang,
#     LLVM, GRUB and its module trees, xorriso, mtools, QEMU, Python by
#     version and package) and refuses, naming each mismatch.
# (b) Clones both repositories (`git clone --shared --no-checkout` from the
#     manifest's local repositories) at the manifest's commits.
# (c) Builds the platform (prepare-and-build.sh, build-ports.sh, with the
#     release id) and the boot image (`make durable-iso` with the manifest's
#     variables and the rebuilt sshd.elf and absd-fsd.elf).
# (d) Compares: every platform-origin file byte for byte; the ISO by the
#     kernel ELF and grub.cfg extracted from it, the kernel "compared
#     stripped" when its bytes differ only by what its checkout path reaches.
# (e) Writes WORKDIR/reconstruction-receipt.toml with every comparison.
#
# Where the builds happen matters. Platform ELFs embed the platform root,
# the sibling staging directories beside it, and CARGO_HOME, so they are
# byte-identical only when rebuilt at the manifest's build.platform_root:
# that path is used when it does not exist (its siblings, ../absd-std-staged-*,
# are then the shared ones, re-staged as any build does); otherwise
# WORKDIR/<its name>, where the platform files are expected to differ and
# the receipt says so. The kernel is cloned at build.kernel_root when that is
# free (a check-all mktemp clone usually is), else WORKDIR/absd-kernel.
#
# --platform-products DIR skips (b) and (c) for the platform and compares
# DIR's files instead (a kernel-only reconstruction, or a dry run of the
# comparison against existing build products). --toolchain-only stops
# after (a).
#
# SOURCE_DATE_EPOCH is deliberately not set: on this host (GRUB 2.12,
# xorriso 1.5.6, mtools 4.0.43) it does not make grub-mkrescue's image
# reproducible. grub-mkrescue passes xorriso --modification-date from the
# wall clock, which sets the volume UUID and the GPT GUIDs; the embedded
# GRUB EFI core differs run to run too, and mformat picks a random FAT
# serial.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tool="python3 $root/scripts/release_manifest.py"
tarball=
workdir=
kernel_dir=
platform_dir=
products=
toolchain_only=0
while [ "$#" -gt 1 ]; do
    case $1 in
    --rust-src-tarball) tarball=${2:?}; shift 2 ;;
    --workdir) workdir=${2:?}; shift 2 ;;
    --kernel-dir) kernel_dir=${2:?}; shift 2 ;;
    --platform-dir) platform_dir=${2:?}; shift 2 ;;
    --platform-products) products=${2:?}; shift 2 ;;
    --toolchain-only) toolchain_only=1; shift ;;
    *) echo "reconstruct-release.sh: unknown argument $1" >&2; exit 2 ;;
    esac
done
manifest=${1:?usage: reconstruct-release.sh [options] MANIFEST}
manifest=$(realpath "$manifest")
test -f "$manifest"

fail() {
    printf '%s\n' "reconstruct-release: refused: $*" >&2
    exit 1
}

field() {
    python3 -c '
import sys, tomllib
doc = tomllib.load(open(sys.argv[1], "rb"))
for part in sys.argv[2].split("."):
    doc = doc[part]
print(doc)' "$manifest" "$1"
}

# Only this script's own schema: /2 records the kernel feature selection
# (build.kernel_image.EXTERNAL_KERNEL_FEATURES) that /1 lacks.
schema=$(field schema 2>/dev/null) || fail "manifest has no schema"
case $schema in
absd-release-manifest/2) ;;
absd-release-manifest/1)
    fail "an absd-release-manifest/1 manifest is not reconstructed by this script; reconstruct a /1 manifest with reconstruct-release.sh at its own platform commit ($(field source.platform_commit 2>/dev/null || echo unrecorded))" ;;
*) fail "unsupported manifest schema $schema" ;;
esac

# (a) The toolchain.
if ! $tool toolchain-check --manifest "$manifest" ${tarball:+--rust-src-tarball "$tarball"}; then
    fail "this host's toolchain is not the manifest's (each mismatch named above)"
fi
if [ "$toolchain_only" = 1 ]; then
    exit 0
fi

release=$(field release.id)
kernel_commit=$(field source.kernel_commit)
kernel_repo=$(field source.kernel_repository)
platform_commit=$(field source.platform_commit)
platform_repo=$(field source.platform_repository)
recorded_platform=$(field build.platform_root)
recorded_kernel=$(field build.kernel_root)
kernel_rustc=$(field toolchain.kernel_rustc.commit_hash)
step=$(field build.kernel_image.DURABLE_STEP)
options=$(field build.kernel_image.DURABLE_OPTIONS)
worker=$(field build.kernel_image.EXTERNAL_USER_ELF)
server=$(field build.kernel_image.FILE_SERVER_ELF)
wait_ticks=$(field build.kernel_image.NET_WAIT_TICKS)
features=$(field build.kernel_image.EXTERNAL_KERNEL_FEATURES 2>/dev/null) || \
    fail "manifest lacks build.kernel_image.EXTERNAL_KERNEL_FEATURES; the kernel feature selection must be recorded"
test -z "$(field build.kernel_image.EXTERNAL_READER_ELF)" || fail "a reader ELF in the boot image is not reconstructed"
test "$(field build.kernel_image.EXTERNAL_INPUT_sha256)" = \
    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 || \
    fail "a boot image with embedded input is not reconstructed"

if [ -z "$workdir" ]; then
    workdir=$(mktemp -d "$(dirname "$root")/absd-reconstruct.XXXXXX")
else
    mkdir -p "$workdir"
fi
workdir=$(realpath "$workdir")
receipt=$workdir/reconstruction-receipt.toml

clone() {
    repo=$1 commit=$2 dest=$3
    test ! -e "$dest" || fail "$dest exists"
    git clone --quiet --shared --no-checkout "$repo" "$dest"
    git -C "$dest" checkout --quiet --detach "$commit"
    test "$(git -C "$dest" rev-parse HEAD)" = "$commit" || fail "$dest is not at $commit"
    test -z "$(git -C "$dest" status --porcelain --untracked-files=all)" || fail "$dest is not clean"
}

# (b) The kernel.
if [ -z "$kernel_dir" ]; then
    if [ ! -e "$recorded_kernel" ]; then kernel_dir=$recorded_kernel; else kernel_dir=$workdir/absd-kernel; fi
fi
clone "$kernel_repo" "$kernel_commit" "$kernel_dir"
kernel_dir=$(realpath "$kernel_dir")
# The rustc `make` will resolve in this checkout must be the recorded one.
here_rustc=$(cd "$kernel_dir" && rustc --version --verbose | sed -n 's/^commit-hash: //p')
test "$here_rustc" = "$kernel_rustc" || \
    fail "the kernel checkout resolves rustc $here_rustc, the manifest's kernel rustc is $kernel_rustc"

# (b), (c) The platform.
platform_rebuilt=true
if [ -n "$products" ]; then
    platform=$(realpath "$products")
    platform_rebuilt=false
else
    if [ -z "$platform_dir" ]; then
        if [ ! -e "$recorded_platform" ]; then
            platform_dir=$recorded_platform
        else
            platform_dir=$workdir/$(basename "$recorded_platform")
        fi
    fi
    clone "$platform_repo" "$platform_commit" "$platform_dir"
    platform=$(realpath "$platform_dir")
    if [ "$platform" != "$recorded_platform" ]; then
        printf '%s\n' "reconstruct-release: building the platform at $platform, not $recorded_platform: its ELFs embed the root and are expected to differ" >&2
    fi
    # From the clone itself: a build script that runs cargo without
    # changing directory would otherwise build whatever workspace this
    # script was started in.
    (cd "$platform" && ABSD_RELEASE_ID=$release \
    ABSD_PULSE_SOURCE=$(field source.coordination_pins.ABSD_PULSE_SOURCE) \
    ABSD_AG_SOURCE=$(field source.coordination_pins.ABSD_AG_SOURCE) \
    ABSD_NIGHTSHIFT_SOURCE=$(field source.coordination_pins.ABSD_NIGHTSHIFT_SOURCE) \
    ABSD_NQ_SOURCE=$(field source.coordination_pins.ABSD_NQ_SOURCE) \
        "$platform/scripts/prepare-and-build.sh")
    (cd "$platform" && ABSD_RELEASE_ID=$release "$platform/scripts/build-ports.sh")
fi

# (c) The boot image, as scripts/operator_image.py kernel_iso makes it.
input=$workdir/empty-input.bin
: > "$input"
make --no-print-directory -C "$kernel_dir" durable-iso DURABLE_STEP="$step" EXTERNAL_KERNEL_FEATURES="$features" \
    EXTERNAL_USER_ELF="$platform/$worker" EXTERNAL_INPUT="$input" EXTERNAL_READER_ELF= \
    EXTERNAL_READER_INPUT= DURABLE_OPTIONS="$options" FILE_SERVER_ELF="$platform/$server" \
    NET_WAIT_TICKS="$wait_ticks" >"$workdir/kernel-build.log" 2>&1 || \
    { tail -20 "$workdir/kernel-build.log" >&2; fail "the kernel build failed ($workdir/kernel-build.log)"; }
iso=$kernel_dir/build/durable/absd-durable-$step.iso

# (d), (e) Compare and write the receipt.
platform_as_recorded=false
test "$platform" = "$recorded_platform" && platform_as_recorded=true
$tool compare --manifest "$manifest" --platform-root "$platform" --iso "$iso" --kernel-root "$kernel_dir" \
    --receipt "$receipt" --note "platform_root=$platform" --note "platform_root_as_recorded=$platform_as_recorded" \
    --note "platform_rebuilt=$platform_rebuilt" --note "workdir=$workdir" \
    --note "source_date_epoch=not set (does not make grub-mkrescue reproducible on this host)"
