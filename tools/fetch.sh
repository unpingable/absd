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
ssh_stage=${ABSD_SSH_STAGE:-$platform/.staged-ssh}
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

# The component owns staging locations and the exact core build-std fetch
# closure. Do not duplicate that contract with guessed sibling directories.
archives "$platform"
ABSD_PROFILE=core "$platform/scripts/fetch-crates.sh"

# Kernel workspaces use their own pinned toolchain and configuration. A
# member lock belonging to its enclosing workspace is covered at that root.
# Preserve actual Cargo errors; a required fetch failure is fatal here.
for lock in $(find "$top/kernel" -name Cargo.lock -not -path '*/target/*' -not -path '*/build/*' | sort); do
    directory=$(dirname "$lock")
    test -f "$directory/Cargo.toml" || continue
    workspace=$(cd -- "$directory" && cargo locate-project --workspace --message-format plain)
    if [ "$workspace" = "$directory/Cargo.toml" ]; then
        (cd -- "$directory" && cargo fetch --locked)
    fi
done
# Validate the archives against all declared lock inputs after the owning
# scripts stage them. Compat's existing sibling root is shared with its
# builders and provenance collector; SSH uses its already supported override.
archives "$top/kernel" "$platform" "$ssh_stage" "${platform}.staged-compat"
echo 'FETCH DONE core=FETCHED kernel=FETCHED archives=VERIFIED'
