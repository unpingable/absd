#!/bin/sh
# absd-net over the kernel NIC (kernel docs/NETWORK.md): boots
# netd-probe.elf as a `net` durable worker and plays its peer, first with
# raw frames over `-netdev dgram` (ARP, IPv4, ICMP echo, malformed
# packets), the same with the link down at boot (QMP `set_link`: ready
# with link=down, silent, serving once the link returns), then with
# ordinary host TCP clients through `-netdev user` host forwards (listen,
# streams, backpressure, reset, 200 reconnections). See
# scripts/net-matrix.py. Needs a kernel with the NIC (lane/net or later)
# in ABSD_KERNEL_RUN: not yet the kernel check-all.sh pins.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel checkout}
work=$root/.net-work

. "$root/scripts/inputs.sh"
absd_not_kernel_source "$kernel"
test -f "$kernel/Makefile"
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    "$root/scripts/prepare-and-build.sh"
fi
rm -rf "${work:?}"
mkdir -p "$work"
python3 "$root/scripts/net-matrix.py" "$kernel" "$root/netd-probe.elf" "$work" "$@"
rm -rf "${work:?}"
