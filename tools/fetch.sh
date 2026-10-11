#!/bin/sh
# Downloads what the build needs from crates.io and stages the patched
# trees. This is the only step that uses the network; build.sh, smoke.sh and
# check.sh run offline afterwards.
#
#   tools/fetch.sh
#
# Needs the Rust toolchains named in the README. Archives land in cargo's
# own registry cache (CARGO_HOME, default ~/.cargo). Every archive a lock
# file or the port list names is checked against its recorded SHA-256,
# whether it was just downloaded or was already in the cache.
set -eu

top=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
platform=$top/platform
cache=${CARGO_HOME:-$HOME/.cargo}/registry/cache/index.crates.io-1949cf8c6b5b557f
mkdir -p "$cache"

# archives LIST...: make every archive the given roots' lock files and the
# port list name present and verified.
archives() {
    python3 - "$cache" "$platform/compat/programs.tsv" "$@" <<'PY'
import hashlib, os, pathlib, sys, tomllib, urllib.request
cache, ports, roots = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3:]
wanted = {}
for line in ports.read_text().splitlines():
    if line and not line.startswith("#"):
        crate, version, checksum = line.split("\t")[:3]
        wanted[(crate, version)] = checksum
for root in roots:
    for lock in pathlib.Path(root).rglob("*Cargo.lock"):
        if "target" in lock.parts:
            continue
        for package in tomllib.loads(lock.read_text()).get("package", []):
            if package.get("source", "").startswith("registry+") and "checksum" in package:
                wanted[(package["name"], package["version"])] = package["checksum"]
got = 0
for (name, version), checksum in sorted(wanted.items()):
    archive = cache / f"{name}-{version}.crate"
    if not archive.exists():
        data = urllib.request.urlopen(f"https://static.crates.io/crates/{name}/{name}-{version}.crate").read()
        part = archive.with_suffix(".part")
        part.write_bytes(data)
        os.replace(part, archive)
        got += 1
    if hashlib.sha256(archive.read_bytes()).hexdigest() != checksum:
        sys.exit(f"fetch.sh: {archive} does not match its recorded checksum; remove it and run again")
print(f"fetch.sh: {len(wanted)} archives verified, {got} downloaded")
PY
}

# First the archives the staging scripts unpack (the ported programs and
# the two crates the platform patches, which those scripts verify
# themselves), then staging, then the staged trees' own lock files.
archives "$platform"
grep -ho '1949cf8c6b5b557f/[A-Za-z0-9_.-]*\.crate' "$platform"/scripts/stage-*.sh | sort -u |
    sed 's|.*/||; s|\.crate$||; s|^\(.*\)-\([0-9][^-]*\)$|\1 \2|' | while read -r crate version; do
    test -f "$cache/$crate-$version.crate" ||
        curl -fsSL -o "$cache/$crate-$version.crate" "https://static.crates.io/crates/$crate/$crate-$version.crate"
done

"$platform/scripts/stage-library.sh"
for stage in ssh compat; do
    "$platform/scripts/stage-$stage.sh"
done
archives "$platform" "$top"/absd-std-staged-*

# cargo's index entries for every workspace with a lock file, the staged
# ones included. A lock file that is not its own workspace root (a crate
# unpacked inside a staged workspace) is covered by that workspace's lock.
skipped=0
fetch() {
    test "$(cd "$1" && cargo $2 locate-project --workspace --message-format plain 2>/dev/null)" = "$1/Cargo.toml" ||
        return 0
    # Not fatal: the staged workloads carry tools of their own that nothing
    # here builds, some with stale lock files. A crate that is really
    # missing stops the offline build with its name.
    (cd "$1" && cargo $2 fetch --locked) >/dev/null 2>&1 || { echo "fetch.sh: NOT FETCHED $1"; skipped=$((skipped + 1)); }
}
for lock in $(find "$top/kernel" -name Cargo.lock -not -path '*/target/*' -not -path '*/build/*' | sort); do
    fetch "$(dirname "$lock")" ""
done
# The platform's manifests name its custom target and unstable options, so
# cargo needs the build scripts' compiler settings even to resolve them.
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
export RUSTC_BOOTSTRAP=1 RUST_TARGET_PATH="$platform/targets" \
    ABSD_REAL_RUSTC="$toolchain/bin/rustc" ABSD_STAGED_SYSROOT="$platform/.staged-sysroot" \
    RUSTC="$platform/scripts/rustc-staged.sh"
for lock in $(find "$platform" "$top"/absd-std-staged-* -name Cargo.lock \
    -not -path '*/target/*' -not -path '*/pins/*' -not -path '*/vendor/*' | sort); do
    if [ -f "$(dirname "$lock")/Cargo.toml" ]; then
        fetch "$(dirname "$lock")" +1.95.0
    fi
done
echo "FETCH DONE not_fetched=$skipped"
