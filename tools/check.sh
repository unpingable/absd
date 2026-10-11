#!/bin/sh
# Runs the qualification suites against this tree.
#
#   tools/check.sh [kernel|platform]
#
# kernel:   `make check` in kernel/: formatting, lints, host tests and the
#           kernel's QEMU suites. Software emulation only; no KVM.
# platform: platform/scripts/check-all.sh in its core profile: builds the
#           platform twice, compares the two builds, and runs every matrix
#           that needs nothing but ABSD under QEMU. Needs /dev/kvm (the
#           containment matrix runs hundreds of sessions under KVM), about
#           12 GiB of free disk, and hours on a small machine.
# Both stop at the first failure. The platform's extended integration
# profile, which runs other projects' programs on ABSD, is not part of a
# source release: each of its steps prints NOT_RUN by name, and the last
# line is `ABSD RUST STD CORE MATRIX OK ... extended=NOT_RUN`. For a quick
# check that needs no KVM, use tools/smoke.sh.
set -eu

top=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
what=${1:-all}
case $what in kernel|platform|all) ;; *) echo "usage: check.sh [kernel|platform]" >&2; exit 2 ;; esac
case $what in platform|all)
    test -r /dev/kvm && test -w /dev/kvm ||
        { echo "check.sh: the platform gate needs /dev/kvm; tools/smoke.sh does not" >&2; exit 1; } ;;
esac
case $what in kernel|all) make -C "$top/kernel" check ;; esac
case $what in platform|all) ABSD_PROFILE=core "$top/platform/scripts/check-all.sh" ;; esac
echo "CHECK OK $what"
