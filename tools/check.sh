#!/bin/sh
# Runs the qualification suites against this tree.
#
#   tools/check.sh [kernel|platform|all] [RC1_WORK]
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
test "$#" -le 2 || { echo "usage: check.sh [kernel|platform|all] [RC1_WORK]" >&2; exit 2; }
case $what in kernel|platform|all) ;; *) echo "usage: check.sh [kernel|platform|all] [RC1_WORK]" >&2; exit 2 ;; esac
if [ "$#" -eq 2 ]; then
    # Consume the same prefetched C inputs as rebuild-rc1.sh fetch WORK.
    # No network fetch or fallback into checkout-relative caches here.
    work=$2
    case $work in /*) ;; *) echo 'RC1_WORK must be absolute' >&2; exit 1 ;; esac
    work=$(CDPATH= cd -- "$work" && pwd -P)
    case $work/ in "$top/"*|/) echo 'RC1_WORK must be outside the checkout and not /' >&2; exit 1 ;; esac
    case $work in *[!A-Za-z0-9_./-]*) echo 'RC1_WORK must use letters, digits, _, -, . and / only' >&2; exit 1 ;; esac
    export ABSD_PICOLIBC_PREFIX="$work/picolibc" ABSD_PICOLIBC_VENV="$work/venv"
    export ABSD_CKIT_BUILD="$work/ckit-build" ABSD_CPORTS_BUILD="$work/cports-build"
    export ABSD_USERLAND_UPSTREAM="$work/upstream" ABSD_USERLAND_BUILD="$work/userland-build"
    # The core recovery fixture retains its observation logs after success.
    # Keep them outside the manifest-verified component source, just as the
    # other explicit RC1 work outputs are kept outside it.
    export ABSD_CORE_FSD_WORK="$work/core-fsd-recovery"
    export CARGO_NET_OFFLINE=true ABSD_CARGO_LOCKED=--locked
    launcher=$(mktemp -d "$work/check-python.XXXXXX")
    printf '#!/bin/sh\nexec /usr/bin/python3 -B -X pycache_prefix=%s/cache "$@"\n' "$launcher" > "$launcher/python3"
    chmod 700 "$launcher/python3"
    trap 'rm -f "$launcher/python3"; rmdir "$launcher"' EXIT
    PATH=$launcher:$work/venv/bin:$PATH
    export PATH
fi
printf '%s\n' 'TCC STAGE NOT_RUN: not included in the public source'
python3 -B "$top/tools/check_inputs.py" "$top"
case $what in platform|all)
    test -r /dev/kvm && test -w /dev/kvm ||
        { echo "check.sh: the platform gate needs /dev/kvm; tools/smoke.sh does not" >&2; exit 1; } ;;
esac
case $what in kernel|all) make -C "$top/kernel" check ;; esac
case $what in platform|all)
    ABSD_KERNEL_COMMIT=$(python3 -c 'import sys,tomllib; print(next(c["commit"] for c in tomllib.load(open(sys.argv[1],"rb"))["component"] if c["name"]=="kernel"))' "$top/SOURCE-MANIFEST.toml")
    export ABSD_KERNEL_COMMIT
    ABSD_PROFILE=core "$top/platform/scripts/check-all.sh" ;;
esac
echo "CHECK OK $what"
