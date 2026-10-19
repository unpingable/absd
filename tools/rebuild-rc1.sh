#!/bin/sh
# Public-source reconstruction attempt for the frozen RC1 pair. WORK must
# be a new directory outside this source checkout. See docs/RC1-SOURCE.md.
# Fetch phase (network): tools/rebuild-rc1.sh fetch WORK
# Build phase (offline): tools/rebuild-rc1.sh build WORK
set -eu
test "$(id -u)" -ne 0 || { echo 'Run the build as an unprivileged user' >&2; exit 1; }
top=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
phase=${1:?usage: rebuild-rc1.sh fetch|build WORK}
work=${2:?usage: rebuild-rc1.sh fetch|build WORK}
case $work in /*) ;; *) echo 'WORK must be absolute' >&2; exit 1 ;; esac
mkdir -p "$work"
work=$(CDPATH= cd -- "$work" && pwd -P)
case $work/ in "$top/"*|/) echo 'WORK must be outside the source checkout and not /' >&2; exit 1 ;; esac
case $work in *[!A-Za-z0-9_./-]*) echo 'WORK must use letters, digits, _, -, . and / only' >&2; exit 1 ;; esac
case $phase in fetch|build) ;; *) echo 'usage: rebuild-rc1.sh fetch|build WORK' >&2; exit 2 ;; esac
# Refuse before changing any launcher/cache an existing producer may use.
test ! -e "$work/kernel-media" && test ! -e "$work/kernel-aux" && test ! -e "$work/media" ||
    { echo 'WORK already contains a build attempt; use a fresh occurrence' >&2; exit 1; }
# -B alone still reads existing bytecode. A fresh cache prefix prevents
# those reads; the launcher also covers Python helpers invoked with -I.
mkdir -p "$work/python-bin"
cache=$(mktemp -d "$work/python-cache.XXXXXX")
printf '#!/bin/sh\nexec /usr/bin/python3 -B -X pycache_prefix=%s "$@"\n' "$cache" > "$work/python-bin/python3"
chmod 700 "$work/python-bin/python3"
PATH=$work/python-bin:$work/venv/bin:$PATH
export PATH
root=$top/platform
export ABSD_KERNEL_COMMIT=d208b61bcd4826181bf9f401551ab620d4eabba0
export ABSD_PLATFORM_COMMIT=0fada7ed031bd84e3a469e717c1d0be5dbefedd6
export ABSD_RELEASE_ID=absd-rc1-c12c-20261018t161241z.fvcgzh
export ABSD_PROFILE=core ABSD_CARGO_LOCKED=--locked MAKEFLAGS=-j4
export CARGO_BUILD_JOBS=4 LC_ALL=C CARGO_NET_OFFLINE=true
export ABSD_KERNEL_SOURCE="$top/kernel" ABSD_KERNEL_PROTECTED="$top/kernel"
export ABSD_PICOLIBC_PREFIX="$work/picolibc" ABSD_PICOLIBC_VENV="$work/venv"
export ABSD_CKIT_BUILD="$work/ckit-build" ABSD_CPORTS_BUILD="$work/cports-build"
export ABSD_USERLAND_UPSTREAM="$work/upstream" ABSD_USERLAND_BUILD="$work/userland-build"
unset ABSD_INCREMENTAL ABSD_SKIP_BUILD RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
case $phase in
    fetch)
        unset CARGO_NET_OFFLINE
        sh "$top/tools/fetch.sh"
        python3 -B "$top/tools/fetch-rc1-inputs.py" "$work"
        echo 'RC1 FETCH COMPLETE (no rebuild claim)'
        ;;
    build)
        . "$root/scripts/inputs.sh"
        mkdir "$work/kernel-media" "$work/kernel-aux"
        absd_kernel_run "$top/kernel" unused "$work/kernel-media"
        absd_kernel_run "$top/kernel" unused "$work/kernel-aux"
        python3 -B "$top/tools/rc1_media.py" verify-snapshots --kernel-run "$work/kernel-media" > "$work/SOURCE-ADAPTER.json"
        python3 -B "$top/tools/rc1_notices.py" check \
            --base "$work/absd-rc1-third-party-notices.tar.gz" > "$work/LINKED-NOTICES-CHECK.json"
        ABSD_RELEASE_ID=$ABSD_RELEASE_ID sh "$root/scripts/prepare-and-build.sh"
        sh "$root/scripts/build-picolibc.sh"
        # The frozen C-port catalog was linked with the C runtime's default
        # development identity. Scope the media release id to the platform;
        # inheriting it here changes the linked FSD version-check bytes.
        env -u ABSD_RELEASE_ID sh "$root/scripts/build-c-kit.sh"
        sh "$root/scripts/build-userland.sh"
        sh "$root/scripts/build-ports.sh"
        python3 -B "$top/tools/rc1_media.py" operator-image --profile vm-operator \
            --platform-tree "$root" --kernel-run "$work/kernel-media" \
            --kernel-commit "$ABSD_KERNEL_COMMIT" --platform-commit "$ABSD_PLATFORM_COMMIT" \
            --authorized-keys "$top/docs/rc1/build-authorized-keys.pub" --release-id "$ABSD_RELEASE_ID" --out "$work/media"
        python3 -B "$top/tools/rc1_media.py" operator-validate --profile vm-operator \
            --platform-tree "$root" --kernel-run "$work/kernel-media" --out "$work/media"
        python3 -B "$top/tools/rc1_blank.py" "$work"
        python3 -B "$root/scripts/enroll-matrix.py" --kernel "$work/kernel-aux" \
            --importer "$root/fixture-import.elf" --enroll "$root/absd-enroll.elf" --work "$work/enroll"
        sha256sum "$work/media/absd-operator.iso" "$work/blank/absd-operator.img" "$work/enroll/enroll.iso" > "$work/REBUILT.sha256"
        cat "$work/REBUILT.sha256"
        echo 'RC1 REBUILD FINISHED (compare the artifacts; completion is not correspondence)'
        ;;
    *) echo 'usage: rebuild-rc1.sh fetch|build WORK' >&2; exit 2 ;;
esac
