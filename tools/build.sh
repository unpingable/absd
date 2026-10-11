#!/bin/sh
# Builds the kernel, the platform and the operator image from this tree.
#
#   tools/build.sh AUTHORIZED_KEYS [OUT]
#
# AUTHORIZED_KEYS is an OpenSSH authorized_keys file of ssh-ed25519 lines
# without options: the keys that may log in to the image. OUT (default out/)
# receives absd-operator.iso, absd-operator.img and MANIFEST. Run
# tools/fetch.sh first. See platform/man/afterboot.8.
#
# The kernel and platform must be the trees SOURCE-MANIFEST.toml names;
# ABSD_ALLOW_MODIFIED=1 builds changed ones, and MANIFEST then says
# `modified` instead of a commit.
set -eu

top=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
keys=${1:?usage: build.sh AUTHORIZED_KEYS [OUT]}
out=${2:-$top/out}
root=$top/platform
. "$root/scripts/inputs.sh"
# The image build writes into the kernel tree's build/ directory, so it
# works on a verified copy.
run=$top/absd-kernel-std-run.build
rm -rf "$run"
mkdir "$run"
absd_kernel_run "$(absd_source KERNEL)" unused "$run"
ABSD_KERNEL_RUN=$run "$root/scripts/build-operator-image.sh" --authorized-keys "$keys" "$out"
sed -n 1,3p "$out/MANIFEST"
sha256sum "$out/absd-operator.iso" "$out/absd-operator.img"
echo "BUILD OK $out"
