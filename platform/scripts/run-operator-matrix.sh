#!/bin/sh
# The operator image (scripts/operator-matrix.py): built with
# scripts/build-operator-image.sh, booted with scripts/boot-operator.sh,
# and driven with the host's /usr/bin/ssh. Needs a kernel with the served
# boot mode in ABSD_KERNEL_RUN. Builds the platform and the ports unless
# ABSD_SKIP_BUILD=1.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel checkout}
qemu=${ABSD_QEMU:-qemu-system-x86_64}
work=$root/.operator-work

. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
    "$root/scripts/build-ports.sh"
fi
rm -rf "${work:?}"
mkdir -p "$work"
python3 "$root/scripts/operator-matrix.py" --work "$work" --kernel "$kernel" \
    --qemu "$qemu -cpu max,vendor=GenuineIntel,+rdrand" | tee "$work.log"
for marker in 'OPERATOR IMAGE OK' 'HOST KEY FINGERPRINT OK' 'ETC CONFIG OK' 'ETC CONFIG MALFORMED REFUSED OK' \
    'LOGS OK' 'FILE TRANSFER OK' 'DATE UPTIME OK' 'OPERATOR MATRIX OK'; do
    grep -q "^$marker" "$work.log" || { echo "run-operator-matrix: no $marker" >&2; exit 1; }
done
rm -rf "${work:?}" "${work:?}.log"
printf '%s\n' 'ABSD RUST OPERATOR OK'
