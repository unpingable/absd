#!/bin/sh
# Builds the operator image (scripts/operator_image.py; afterboot(8)):
#
#   build-operator-image.sh --authorized-keys KEYS [--etc DIR]
#       [--disk-profile 128m|2g]
#       [--local-token-file FILE | --local-login-verifier FILE] OUT
#   build-operator-image.sh --reconfigure --etc DIR [--authorized-keys KEYS] OUT
#
# KEYS is an OpenSSH authorized_keys file of ssh-ed25519 lines (no
# options). DIR holds /etc files to install in place of operator/etc/'s
# (network.conf, sshd.conf). OUT receives absd-operator.iso,
# absd-operator.img, and MANIFEST. Fresh builds enroll local login by default:
# only /ssh/local-login enters the image; OUT.local-console-token (0600)
# and its .verifier remain outside OUT. Rebuilds may reuse the verifier. --reconfigure replaces those files on
# OUT's existing image (the machine halted) and updates MANIFEST; it
# refuses an image without /absd/selected (built before the release
# layout), and an operator directory of scripts/release.py install
# (release.py reconfigure is its command). The image is written in
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
local_token=
local_verifier=
disk_profile=
while [ "$#" -gt 1 ]; do
    case $1 in
    --reconfigure) mode=reconfigure; shift ;;
    --authorized-keys) keys=${2:?}; shift 2 ;;
    --etc) etc=${2:?}; shift 2 ;;
    --local-token-file) local_token=${2:?}; shift 2 ;;
    --local-login-verifier) local_verifier=${2:?}; shift 2 ;;
    --disk-profile) disk_profile=${2:?}; shift 2 ;;
    *) echo "build-operator-image.sh: unknown argument $1" >&2; exit 2 ;;
    esac
done
out=${1:?usage: build-operator-image.sh [--reconfigure] [--authorized-keys KEYS] [--etc DIR] OUT}
if [ "$mode" = reconfigure ] && [ -n "$disk_profile" ]; then
    echo 'build-operator-image.sh: --disk-profile is for fresh construction, not reconfigure' >&2
    exit 2
fi
case $disk_profile in
''|128m|2g) ;;
*) echo 'build-operator-image.sh: --disk-profile must be 128m or 2g' >&2; exit 2 ;;
esac
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ] && [ "$mode" = build ]; then
    "$root/scripts/prepare-and-build.sh"
    "$root/scripts/build-ports.sh"
fi
if [ "$mode" = build ]; then
    set -- python3 "$root/scripts/operator_image.py" build --kernel "$kernel" \
        --authorized-keys "${keys:?--authorized-keys is required}" \
        --qemu "$qemu -cpu max,vendor=GenuineIntel,+rdrand"
    if [ -n "$etc" ]; then set -- "$@" --etc "$etc"; fi
    if [ -n "$disk_profile" ]; then set -- "$@" --disk-profile "$disk_profile"; fi
    if [ -n "$local_token" ]; then set -- "$@" --local-token-file "$local_token"; fi
    if [ -n "$local_verifier" ]; then set -- "$@" --local-login-verifier "$local_verifier"; fi
    exec "$@" "$out"
fi
if [ -n "$local_token$local_verifier" ]; then
    echo "build-operator-image.sh: enrollment options apply only to fresh construction" >&2
    exit 2
fi
exec python3 "$root/scripts/operator_image.py" reconfigure --kernel "$kernel" \
    --etc "${etc:?--reconfigure needs --etc}" ${keys:+--authorized-keys "$keys"} \
    --qemu "$qemu -cpu max,vendor=GenuineIntel,+rdrand" "$out"
