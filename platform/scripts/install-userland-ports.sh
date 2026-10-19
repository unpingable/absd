#!/bin/sh
# Installs the base userland's sbase and Toybox ports (userland/README.md) into ports/,
# beside the Rust ports, for /bin: every row of userland/PORTS.tsv names a
# utility, the ELF scripts/build-userland.sh built and gated, and the
# digests both it and the installed file must have. Run by
# scripts/build-ports.sh after the Rust ports; scripts/operator_image.py's
# PORTS names the same utilities, so the operator image, a release
# (scripts/release.py) and the command matrix carry exactly these bytes.
#
# For each row: the build output must hash as GATED_SHA256 (the ELF the
# kit's gate passed, equal in both ABSD rounds); it is stripped with
# llvm-strip-18 into ports/NAME, as the Rust ports are, which must hash as
# SHA256 and be BYTES long, keep the gated ELF's program headers, and pass
# scripts/check-c-elf.py again. A digest that differs is refused, not
# re-pinned: a kit, adapter, patch or source change shows up here, and the
# new digests are recorded in userland/PORTS.tsv on purpose (--print
# prints the rows the current build would need) once that change has been
# reviewed. No name may be a platform command, a shell builtin, another
# port, or a command deliberately not provided, and each needs its manual
# page (scripts/cmds-matrix.py --host-check --without-image-list, run last;
# the command matrix runs the full --host-check, which also requires
# scripts/operator_image.py PORTS to list them).
#
# The userland build is $ABSD_USERLAND_BUILD (default
# <campaign>/userland-build); if it holds no gated ELFs yet,
# scripts/build-userland.sh is run first (it needs the C kit:
# scripts/build-picolibc.sh, scripts/build-c-kit.sh).
# The last line is `USERLAND PORTS INSTALLED n=<n>`.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
# Where the ports go: ports/, or ABSD_PORTS_DIR (scripts/build-ports.sh
# assembles them elsewhere and publishes ports/ when all are in).
ports=${ABSD_PORTS_DIR:-$root/ports}
camp=$(dirname "$root")
out=${ABSD_USERLAND_BUILD:-$camp/userland-build}
table=$root/userland/PORTS.tsv
tab=$(printf '\t')
fail() { printf '%s\n' "install-userland-ports: $*" >&2; exit 1; }
rows() { grep -v '^#' "$table" | grep -v '^[[:space:]]*$'; }

bad=$(rows | awk -F'\t' 'NF != 7 { print $1 }')
[ -z "$bad" ] || fail "userland/PORTS.tsv rows without seven fields: $bad"
built=yes
for build in $(rows | cut -f4); do
    [ -f "$out/$build" ] || built=no
done
if [ "$built" = no ]; then
    sh "$root/scripts/build-userland.sh" >/dev/null ||
        fail "scripts/build-userland.sh failed (it needs the C kit: scripts/build-picolibc.sh, scripts/build-c-kit.sh)"
fi
tmp=$(mktemp -d "${TMPDIR:-/tmp}/install-userland-ports.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

if [ "${1:-}" = --print ]; then
    rows | while IFS="$tab" read -r name upstream source build gated sha bytes; do
        llvm-strip-18 -o "$tmp/$name" "$out/$build"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$upstream" "$source" "$build" \
            "$(sha256sum "$out/$build" | cut -d' ' -f1)" "$(sha256sum "$tmp/$name" | cut -d' ' -f1)" \
            "$(stat -c %s "$tmp/$name")"
    done
    exit 0
fi

mkdir -p "$ports"
n=0
rows > "$tmp/rows"
while IFS="$tab" read -r name upstream source build gated sha bytes; do
    grep -q "^$(printf '%s' "$upstream" | cut -d- -f1)$tab$(printf '%s' "$upstream" | cut -d- -f2-)$tab" "$root/userland/PIN" ||
        fail "$name: upstream $upstream is not a userland/PIN row"
    got=$(sha256sum "$out/$build" | cut -d' ' -f1)
    [ "$got" = "$gated" ] ||
        fail "$name: $out/$build is $got, not the gated $gated (rebuild with scripts/build-userland.sh; if the change is intended, review it and record --print's rows)"
    llvm-strip-18 -o "$ports/$name" "$out/$build"
    got=$(sha256sum "$ports/$name" | cut -d' ' -f1)
    size=$(stat -c %s "$ports/$name")
    [ "$got" = "$sha" ] && [ "$size" = "$bytes" ] ||
        { rm -f "$ports/$name"; fail "$name: ports/$name is $got ($size bytes), not $sha ($bytes bytes)"; }
    readelf -lW "$out/$build" | grep -E '^ +(LOAD|GNU_STACK)' > "$tmp/gated.ph"
    readelf -lW "$ports/$name" | grep -E '^ +(LOAD|GNU_STACK)' > "$tmp/installed.ph"
    cmp -s "$tmp/gated.ph" "$tmp/installed.ph" ||
        { rm -f "$ports/$name"; fail "$name: stripping changed the program headers"; }
    python3 -I "$root/scripts/check-c-elf.py" "$ports/$name" >/dev/null ||
        { rm -f "$ports/$name"; fail "$name: ports/$name fails the ELF gate"; }
    printf '%s\n' "PORT INSTALLED $upstream $name $size $got"
    n=$((n + 1))
done < "$tmp/rows"
python3 -I "$root/scripts/cmds-matrix.py" --host-check --without-image-list
printf '%s\n' "USERLAND PORTS INSTALLED n=$n"
