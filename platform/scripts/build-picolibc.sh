#!/bin/sh
# Builds the Picolibc the C kit links (c/picolibc/PIN, options.txt,
# cross-absd.txt) from the pinned source. Everything lands under
# $ABSD_PICOLIBC_PREFIX (default $camp/picolibc, which build-c-kit.sh reads):
#   dl/       the release tarball (downloaded once; sha256 checked before extraction)
#   src/      the extracted source (replaced on every run)
#   build/    the meson build directory (replaced on every run)
#   install/  lib/libc.a, lib/libm.a, include/ (replaced on every run)
#   buildoptions.json  `meson introspect --buildoptions` of the build
# meson and ninja run from the campaign venv ($camp/venv), installed from the
# wheels pinned in PIN (from $camp/venv/dl when present, else downloaded
# there), each wheel's sha256 checked first. The cross file's
# -fdebug-compilation-dir=. keeps the build directory's absolute path out of
# the archives, so libc.a hashes the same under any prefix; build-c-kit.sh
# compares it with the picolibc-libc.a line of PIN. TMPDIR debug paths are
# additionally normalized by the generated tmpdir-cross.txt (retained input).
set -eu

# Bound Ninja separately from Cargo. Validate before downloads or staging.
# The campaign permits at most four jobs per admitted host build.
case ${ABSD_PICOLIBC_JOBS-4} in
    1|2|3|4) jobs=${ABSD_PICOLIBC_JOBS-4} ;;
    *) echo 'build-picolibc: ABSD_PICOLIBC_JOBS must be 1, 2, 3 or 4' >&2; exit 1 ;;
esac
# LLVM's assembler debug strings include TMPDIR, independently of the build
# prefix. Preserve private temporary storage but map its debug name to the
# historical /tmp spelling used by the unchanged archive PIN.
TMPDIR=${TMPDIR:-/tmp}
export TMPDIR
python3 -I - "$TMPDIR" <<'PYTMP'
import os, re, sys
p = sys.argv[1]
if (not re.fullmatch(r"/[A-Za-z0-9_./-]+", p) or
        os.path.realpath(p) != p or not os.path.isdir(p) or
        not os.access(p, os.W_OK | os.X_OK)):
    sys.exit("build-picolibc: TMPDIR must be an existing writable canonical "
             "absolute path using letters, digits, _, -, . and / only")
PYTMP
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
camp=$(dirname "$root")
pin=$root/c/picolibc/PIN
prefix=${ABSD_PICOLIBC_PREFIX:-$camp/picolibc}
venv=${ABSD_PICOLIBC_VENV:-$camp/venv}   # overridden only to exercise the venv bootstrap

field() { awk -F '\t' -v n="$1" -v f="$2" '$1 == n { print $f }' "$pin"; }
die() { echo "build-picolibc: $*" >&2; exit 1; }
check_sha() {   # file, expected
    got=$(sha256sum "$1" | cut -d' ' -f1)
    [ "$got" = "$2" ] || die "$1: sha256 $got, PIN says $2"
}

# -- meson and ninja --------------------------------------------------------
meson_version=$(field meson 2); ninja_version=$(field ninja 2)
[ -n "$meson_version" ] && [ -n "$ninja_version" ] || die "PIN has no meson/ninja lines"
[ -x "$venv/bin/python3" ] || python3 -m venv "$venv"
# The installed distribution's version (the ninja binary's own --version
# carries a build suffix, e.g. 1.13.0.git.kitware...).
installed() { "$venv/bin/python3" -I -c "import importlib.metadata as m; print(m.version('$1'))" 2>/dev/null || true; }
if [ "$(installed meson)" != "$meson_version" ] || [ "$(installed ninja)" != "$ninja_version" ] ||
   ! [ -x "$venv/bin/meson" ] || ! [ -x "$venv/bin/ninja" ]; then
    mkdir -p "$venv/dl"
    for tool in meson ninja; do
        version=$(field $tool 2)
        if ! ls "$venv/dl/$tool-$version-"*.whl >/dev/null 2>&1; then
            "$venv/bin/pip" download --no-deps --only-binary=:all: -d "$venv/dl" "$tool==$version"
        fi
        set -- "$venv/dl/$tool-$version-"*.whl
        [ $# = 1 ] || die "expected one $tool $version wheel in $venv/dl, found $#"
        check_sha "$1" "$(field $tool 3)"
        "$venv/bin/pip" install --no-index --no-deps "$1"
    done
fi
[ "$(installed meson)" = "$meson_version" ] && [ "$("$venv/bin/meson" --version)" = "$meson_version" ] ||
    die "venv meson is not $meson_version"
[ "$(installed ninja)" = "$ninja_version" ] || die "venv ninja is not $ninja_version"

# -- the source -------------------------------------------------------------
version=$(field picolibc 2); want=$(field picolibc 3); url=$(field picolibc 4)
[ -n "$version" ] && [ -n "$want" ] && [ -n "$url" ] || die "PIN has no picolibc line"
tarball=$prefix/dl/$(basename "$url")
if ! [ -f "$tarball" ]; then
    if [ -d "$prefix/dl" ] && [ -n "$(ls -A "$prefix/dl")" ]; then
        die "$prefix/dl is not empty and holds no $(basename "$url")"
    fi
    mkdir -p "$prefix/dl"
    curl -fsSL -o "$tarball.part" "$url"
    mv "$tarball.part" "$tarball"
fi
check_sha "$tarball" "$want"           # before anything is extracted
rm -rf "$prefix/src" "$prefix/build" "$prefix/install"
mkdir -p "$prefix/src"
tar -xJf "$tarball" -C "$prefix/src" --strip-components=1 --no-same-owner
test -f "$prefix/src/meson.build" || die "the tarball has no meson.build at its top"

# -- configure, build, install ----------------------------------------------
# Pass a second machine file instead of ambient CFLAGS: the cross file owns
# c_args. The restricted TMPDIR spelling is safe as one Meson string literal.
printf "[constants]\nabsd_tmpdir = '%s'\n" "$TMPDIR" > "$prefix/tmpdir-cross.txt"
options=$(grep '^-D' "$root/c/picolibc/options.txt")
# shellcheck disable=SC2086  # one -D option per word
"$venv/bin/meson" setup "$prefix/build" "$prefix/src" \
    --cross-file="$root/c/picolibc/cross-absd.txt" \
    --cross-file="$prefix/tmpdir-cross.txt" --prefix="$prefix/install" \
    -Dlibdir=lib -Dincludedir=include $options > "$prefix/setup.log" 2>&1 ||
    { tail -40 "$prefix/setup.log"; die "meson setup failed (log $prefix/setup.log)"; }
PATH=$venv/bin:$PATH nice -n 10 "$venv/bin/ninja" -j "$jobs" -C "$prefix/build" > "$prefix/build.log" 2>&1 ||
    { tail -40 "$prefix/build.log"; die "ninja failed (log $prefix/build.log)"; }
PATH=$venv/bin:$PATH "$venv/bin/meson" install -C "$prefix/build" --no-rebuild > "$prefix/install.log" 2>&1 ||
    { tail -40 "$prefix/install.log"; die "meson install failed (log $prefix/install.log)"; }
"$venv/bin/meson" introspect --buildoptions "$prefix/build" > "$prefix/buildoptions.json"

# -- the options the kit depends on -----------------------------------------
python3 -I - "$prefix/buildoptions.json" <<'EOF'
import json, sys
options = {o["name"]: o["value"] for o in json.load(open(sys.argv[1]))}
want = {
    "thread-local-storage": "false",   # a combo option in 1.8.12: the string, not boolean False
    "newlib-global-errno": True,
    "single-thread": True,
    "picocrt": False,
    "enable-malloc": False,
    "posix-console": True,
    "format-default": "double",
    "io-long-long": True,
}
bad = {k: options.get(k, "<absent>") for k, v in want.items() if options.get(k, "<absent>") != v
       or type(options.get(k)) is not type(v)}
if bad:
    sys.exit(f"build-picolibc: options differ from the kit's: {bad}")
print(f"ABSD PICOLIBC OPTIONS OK checked={len(want)}")
EOF
test -f "$prefix/install/lib/libc.a" || die "no libc.a installed"
if grep -aq "$prefix" "$prefix/install/lib/libc.a"; then
    die "libc.a names the build prefix $prefix (not reproducible across prefixes)"
fi
printf '%s\n' "ABSD PICOLIBC libc.a $(sha256sum "$prefix/install/lib/libc.a" | cut -d' ' -f1)"
printf '%s\n' "ABSD PICOLIBC libm.a $(sha256sum "$prefix/install/lib/libm.a" | cut -d' ' -f1)"
