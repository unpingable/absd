#!/bin/sh
# Builds the operator image (scripts/operator_image.py; afterboot(8)):
#
#   build-operator-image.sh --authorized-keys KEYS [--etc DIR] OUT
#   build-operator-image.sh --reconfigure --etc DIR [--authorized-keys KEYS] OUT
#
# KEYS is an OpenSSH authorized_keys file of ssh-ed25519 lines (no
# options). DIR holds /etc files to install in place of operator/etc/'s
# (network.conf, sshd.conf). OUT receives absd-operator.iso,
# absd-operator.img, and MANIFEST. --reconfigure replaces those files on
# OUT's existing image (the machine halted); it refuses an image without
# /absd/selected (built before the release layout). The image is written in
# the release layout (docs/RELEASE.md): /bin and /share under
# /releases/ID/, the record /releases/ID/release, the selection
# /absd/selected, where ID is ABSD_RELEASE_ID (default dev), the id the
# platform build compiles in. ABSD_KERNEL_RUN names a
# disposable kernel checkout at the commit scripts/check-all.sh pins (the
# build writes into its build/). Builds the platform and the ports first
# unless ABSD_SKIP_BUILD=1.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel checkout}
qemu=${ABSD_QEMU:-qemu-system-x86_64}
. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"
mode=build
keys=
etc=
while [ "$#" -gt 1 ]; do
    case $1 in
    --reconfigure) mode=reconfigure; shift ;;
    --authorized-keys) keys=${2:?}; shift 2 ;;
    --etc) etc=${2:?}; shift 2 ;;
    *) echo "build-operator-image.sh: unknown argument $1" >&2; exit 2 ;;
    esac
done
out=${1:?usage: build-operator-image.sh [--reconfigure] [--authorized-keys KEYS] [--etc DIR] OUT}
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ] && [ "$mode" = build ]; then
    "$root/scripts/prepare-and-build.sh"
    "$root/scripts/build-ports.sh"
fi
if [ "$mode" = build ]; then
    exec python3 "$root/scripts/operator_image.py" build --kernel "$kernel" \
        --authorized-keys "${keys:?--authorized-keys is required}" ${etc:+--etc "$etc"} \
        --qemu "$qemu -cpu max,vendor=GenuineIntel,+rdrand" "$out"
fi
exec python3 "$root/scripts/operator_image.py" reconfigure --kernel "$kernel" \
    --etc "${etc:?--reconfigure needs --etc}" ${keys:+--authorized-keys "$keys"} \
    --qemu "$qemu -cpu max,vendor=GenuineIntel,+rdrand" "$out"
