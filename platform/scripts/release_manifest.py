#!/usr/bin/env python3
"""The canonical record of one ABSD release: `release-manifest.toml` in the
release directory (docs/RELEASE.md section 11).

  release_manifest.py build --kernel K --platform P RELEASE_DIR
      Writes RELEASE_DIR/release-manifest.toml: the release id and identity,
      the kernel and platform commits and the coordination pins, this host's
      toolchain (the platform's rustc 1.95.0 and its rust-src distribution,
      the kernel's own rustc, the C and LLVM tools, GRUB, xorriso, mtools,
      QEMU, Python), the build flags and target specification, how the boot
      image was made, and the SHA-256 of every file in the release directory
      plus the kernel ELF and grub.cfg inside the ISO.

  release_manifest.py verify RELEASE_DIR [--manifest M]
      Recomputes every digest the manifest names (the ISO's kernel and
      grub.cfg extracted with xorriso) and fails naming each mismatch.

  release_manifest.py toolchain-check --manifest M [--rust-src-tarball T]
      Compares this host's toolchain to the manifest's; fails naming each
      mismatch (scripts/reconstruct-release.sh, step a).

  release_manifest.py compare --manifest M --platform-root P --iso ISO
                              --receipt OUT
      Compares a rebuilt platform tree and boot image to the manifest and
      writes the reconstruction receipt (scripts/reconstruct-release.sh).

The release directory is the one `scripts/release.py build` writes: the
ISO, the release record, tree/ (bin and share/man), site-defaults/, and the
importer and services. Every regular file in it is recorded except the
manifest and a reconstruction receipt; each file names its origin in the
platform build (commands/NAME, ports/NAME, manpages/PATH, NAME.elf) when its
bytes equal that file, so a rebuild can be compared file by file.

Integrity, not authenticity: nothing here signs anything (RELEASE.md 11).
"""

import argparse
import datetime
import hashlib
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import absd_inputs
from served_kernel import FEATURES as SERVED_KERNEL_FEATURES

# /2: build.kernel_image records EXTERNAL_KERNEL_FEATURES (reconstruction
# replays it). /1 manifests are reconstructed by reconstruct-release.sh at
# their own platform commit.
SCHEMA = "absd-release-manifest/2"
MANIFEST = "release-manifest.toml"
RECEIPT = "reconstruction-receipt.toml"
ISO = "absd-operator.iso"
# Files of a release directory that the manifest does not record: itself and
# the receipt written beside it.
UNRECORDED = {MANIFEST, RECEIPT}

TOOLCHAIN = pathlib.Path(os.environ.get(
    "ABSD_RUST_TOOLCHAIN", pathlib.Path.home() / ".rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu"))
# The rust-src the platform builds against: the published 1.95.0 component,
# byte-identical (library/ and the whole src/rust tree) to the installed one
# (README.md). The fingerprint is scripts/verify-inputs.sh's.
RUST_SRC_URL = "https://static.rust-lang.org/dist/2026-04-16/rust-src-1.95.0.tar.xz"
RUST_SRC_SHA256 = "67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363"
RUST_SRC_VERSION = "1.95.0 (59807616e 2026-04-14)"
RUST_SRC_COMMIT = "59807616e1fa2540724bfbac14d7976d7e4a3860"
RUST_SRC_TAR_LIBRARY = "rust-src-1.95.0/rust-src/lib/rustlib/src/rust/library"
LIBRARY_FINGERPRINT = "fcb80715180e5a9cc3179b032d2df540bfadb7a3ea35b04f02d4d97e5aafda3b"
# Patched library: 2251 files, 45,920,288 bytes. This is recorded metadata;
# toolchain_check compares stock rust-src fields, not this staged fingerprint.
# The native TLS builder/checker independently compare staged bytes and counts.
STAGED_LIBRARY_FINGERPRINT = "c35493ccdf6cb87a81767902413ad4487caa1bff401d5ccecb1cce9e7a18760c"

STRIP = "llvm-strip-18"
# How the boot image is made (scripts/operator_image.py kernel_iso, step 0
# of a served boot): `make durable-iso` with these variables. The ELF
# variables name platform artifacts; EXTERNAL_INPUT is empty.
KERNEL_MAKE = {"DURABLE_STEP": "0", "DURABLE_OPTIONS": "net fsd served", "EXTERNAL_USER_ELF": "sshd.elf",
               "FILE_SERVER_ELF": "absd-fsd.elf", "EXTERNAL_READER_ELF": "", "EXTERNAL_READER_INPUT": "",
               "NET_WAIT_TICKS": "", "EXTERNAL_KERNEL_FEATURES": SERVED_KERNEL_FEATURES}
KERNEL_NORMALIZATION = f"{STRIP} --strip-all, then the .note.gnu.build-id descriptor zeroed"
HOST_TOOLS = {
    "clang": ["clang", "--version"],
    "llvm_ar": ["llvm-ar-18", "--version"],
    "llvm_strip": [STRIP, "--version"],  # first line names no version: see VERSION_LINE
    "grub_mkrescue": ["grub-mkrescue", "--version"],
    "xorriso": ["xorriso", "-version"],
    "mtools": ["mformat", "--version"],
    "qemu": ["qemu-system-x86_64", "--version"],
    "python3": [sys.executable, "--version"],
}
# Tools whose first line of --version output is not the version line.
VERSION_LINE = {"llvm_strip": "LLVM version"}
HOST_PACKAGES = ["clang-18", "llvm-18", "grub-common", "grub-pc-bin", "grub-efi-amd64-bin", "xorriso", "mtools",
                 "qemu-system-x86", "python3.12"]
GRUB_MODULES = {"i386_pc": "/usr/lib/grub/i386-pc", "x86_64_efi": "/usr/lib/grub/x86_64-efi"}
IDENTITY_KEYS = ["kernel_abi", "fsd_protocol", "fs_format", "app_abi"]
SUPPORT = {
    "environment": "local QEMU, TCG or KVM",
    "architecture": "x86-64",
    "disk": "the primary IDE master or one NVMe namespace",
    "nic": "e1000",
    "physical_machine": False,
}
LIMITATIONS = [
    "Integrity only: the digests detect corruption; nothing signs the manifest (RELEASE.md 11).",
    "The operator image (absd-operator.img) is site state, not a release artifact: it is not recorded.",
    "The ISO is not reproducible bit for bit: grub-mkrescue stamps it with the wall clock (volume UUID, "
    "GPT GUIDs; the embedded GRUB EFI core differs too) and mformat picks a random FAT serial, with or without "
    "SOURCE_DATE_EPOCH; reconstruction compares the kernel ELF and grub.cfg extracted from it.",
    "The kernel ELF carries its checkout path (DWARF, and through it the build-id and local symbol names); "
    "built elsewhere it is compared stripped (artifacts.iso.kernel_normalization).",
    "Platform ELFs embed the platform build root, the sibling staging directories, and CARGO_HOME in panic "
    "locations; they reproduce byte for byte only when rebuilt at build.platform_root.",
    "Host tools are pinned by version string and package version, not by binary digest (except rustc and "
    "cargo).",
]


class Failed(Exception):
    pass


# -- digests --------------------------------------------------------------------

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_fingerprint(base, sub):
    """scripts/verify-inputs.sh's fingerprint: SHA-256 of `sha256sum` over
    every regular file below base/sub, named sub/..., byte-sorted. Returns
    (fingerprint, files, bytes, symlinks)."""
    base = pathlib.Path(base)
    names, total, links = [], 0, 0
    for dirpath, dirnames, filenames in os.walk(base / sub):
        for name in dirnames + filenames:
            path = pathlib.Path(dirpath) / name
            if path.is_symlink():
                links += 1
            elif name in filenames and path.is_file():
                names.append(os.fsencode(path.relative_to(base)))
    names.sort()
    listing = bytearray()
    for name in names:
        path = base / os.fsdecode(name)
        total += path.stat().st_size
        listing += sha256_file(path).encode() + b"  " + name + b"\n"
    return sha256_bytes(bytes(listing)), len(names), total, links


def dot_tree_hash(base):
    """check-all.sh's manual hash: `find . -type f | sort -z | xargs sha256sum
    | sha256sum` run inside base."""
    base = pathlib.Path(base)
    names = sorted(b"./" + os.fsencode(p.relative_to(base)) for p in base.rglob("*") if p.is_file())
    listing = b"".join(sha256_file(base / os.fsdecode(n[2:])).encode() + b"  " + n + b"\n" for n in names)
    return sha256_bytes(listing)


def kernel_normalized(path, strip=STRIP):
    """The kernel ELF without what its checkout path reaches: stripped of all
    symbols and debug information, the GNU build-id descriptor zeroed."""
    with tempfile.TemporaryDirectory(prefix="absd-kernel-norm-") as work:
        out = pathlib.Path(work) / "kernel"
        subprocess.run([strip, "--strip-all", "-o", str(out), str(path)], check=True, capture_output=True)
        data = bytearray(out.read_bytes())
    if data[:5] != b"\x7fELF\x02" or data[5] != 1:
        raise Failed(f"{path}: not a little-endian ELF64")
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)

    def section(index):
        name, kind, _, _, offset, size = struct.unpack_from("<IIQQQQ", data, shoff + index * shentsize)
        return name, kind, offset, size

    _, _, stroff, _ = section(shstrndx)
    for index in range(shnum):
        name, kind, offset, size = section(index)
        end = data.index(b"\0", stroff + name)
        if bytes(data[stroff + name:end]) == b".note.gnu.build-id" and kind == 7:
            namesz, descsz, _ = struct.unpack_from("<III", data, offset)
            desc = offset + 12 + ((namesz + 3) & ~3)
            data[desc:desc + descsz] = bytes(descsz)
    return sha256_bytes(bytes(data))


def iso_extract(iso, dest):
    """The kernel ELF and grub.cfg from the boot image, by xorriso (the tool
    grub-mkrescue writes it with)."""
    if shutil.which("xorriso") is None:
        raise Failed("xorriso is not installed (it is grub-mkrescue's backend)")
    dest = pathlib.Path(dest)
    kernel, cfg = dest / "absd-kernel", dest / "grub.cfg"
    subprocess.run(["xorriso", "-osirrox", "on", "-indev", str(iso), "-extract", "/boot/absd-kernel", str(kernel),
                    "-extract", "/boot/grub/grub.cfg", str(cfg)], check=True, capture_output=True)
    for path in (kernel, cfg):
        if not path.is_file():
            raise Failed(f"{iso}: no {path.name} inside")
    return kernel, cfg


def iso_contents(iso, strip=STRIP):
    with tempfile.TemporaryDirectory(prefix="absd-iso-") as work:
        kernel, cfg = iso_extract(iso, work)
        return {"boot/absd-kernel": sha256_file(kernel), "boot/grub/grub.cfg": sha256_file(cfg),
                "kernel_normalized": kernel_normalized(kernel, strip)}


# -- TOML -------------------------------------------------------------------------

BARE = re.compile(r"^[A-Za-z0-9_-]+$")


def toml_key(key):
    return key if BARE.match(key) else toml_str(key)


def toml_str(value):
    out = ['"']
    for ch in value:
        if ch in '"\\':
            out.append("\\" + ch)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def toml_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return toml_str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(toml_value(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{toml_key(k)} = {toml_value(v)}" for k, v in sorted(value.items())) + " }"
    raise TypeError(f"no TOML form for {value!r}")


def toml_dump(doc):
    """`doc`: top-level scalars, then tables (dicts of scalars, lists and
    inline tables) whose names are dotted paths, in the order given. Keys
    within a table keep their given order; artifact tables are built
    sorted."""
    lines = [f"{toml_key(k)} = {toml_value(v)}" for k, v in doc.items() if not isinstance(v, dict)]
    for name, table in doc.items():
        if not isinstance(table, dict):
            continue
        lines += ["", f"[{'.'.join(toml_key(part) for part in name.split('.'))}]"]
        lines += [f"{toml_key(k)} = {toml_value(v)}" for k, v in table.items()]
    return "\n".join(lines) + "\n"


def load(path):
    with open(path, "rb") as handle:
        return tomllib.load(handle)


def table(doc, dotted):
    for part in dotted.split("."):
        doc = doc.get(part, {})
    return doc


# -- the host -----------------------------------------------------------------------

def run(argv, cwd=None):
    return subprocess.run(argv, check=True, capture_output=True, text=True, cwd=cwd).stdout


def first_line(argv, pick=None):
    try:
        out = subprocess.run(argv, capture_output=True, text=True).stdout
    except FileNotFoundError:
        return "absent"
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    if pick is not None:
        lines = [line for line in lines if pick in line]
    return lines[0] if lines else "absent"


def verbose_fields(text):
    fields = dict(line.split(": ", 1) for line in text.splitlines()[1:] if ": " in line)
    return {"version": text.splitlines()[0], "commit_hash": fields.get("commit-hash", ""),
            "commit_date": fields.get("commit-date", ""), "host": fields.get("host", ""),
            "release": fields.get("release", ""), "llvm": fields.get("LLVM version", ""),
            "verbose_sha256": sha256_bytes(text.encode())}


def platform_rustc():
    rustc = TOOLCHAIN / "bin" / "rustc"
    out = verbose_fields(run([str(rustc), "--version", "--verbose"]))
    out["binary_sha256"] = sha256_file(rustc)
    out["toolchain"] = str(TOOLCHAIN)
    return out


def platform_cargo():
    cargo = TOOLCHAIN / "bin" / "cargo"
    text = run([str(cargo), "--version", "--verbose"])
    fields = verbose_fields(text)
    return {"version": fields["version"], "commit_hash": fields["commit_hash"],
            "verbose_sha256": fields["verbose_sha256"], "binary_sha256": sha256_file(cargo)}


def kernel_toolchain_name(kernel):
    """The rustup toolchain `make` resolves in the kernel checkout (no
    rust-toolchain file today: the default, `stable`)."""
    text = run(["rustup", "show", "active-toolchain"], cwd=kernel) if kernel else ""
    return text.split()[0] if text.split() else "stable"


def kernel_rustc(name):
    out = verbose_fields(run(["rustup", "run", name, "rustc", "--version", "--verbose"]))
    out["rustup_toolchain"] = name
    out["cargo"] = first_line(["rustup", "run", name, "cargo", "--version"])
    return out


def rust_src_table(tarball=None):
    source = TOOLCHAIN / "lib" / "rustlib" / "src" / "rust"
    fingerprint, files, size, links = tree_fingerprint(source, "library")
    out = {"url": RUST_SRC_URL, "sha256": RUST_SRC_SHA256, "component_version": RUST_SRC_VERSION,
           "git_commit": RUST_SRC_COMMIT, "library_fingerprint": fingerprint, "library_files": files,
           "library_bytes": size, "library_symlinks": links, "staged_library_fingerprint": STAGED_LIBRARY_FINGERPRINT}
    if tarball is not None:
        out["tarball_checked"] = tarball_fingerprint(tarball) == fingerprint
    return out


def tarball_fingerprint(tarball):
    """The library fingerprint of the published tarball, after checking its
    SHA-256 against the pin."""
    actual = sha256_file(tarball)
    if actual != RUST_SRC_SHA256:
        raise Failed(f"rust-src tarball {tarball}: SHA-256 {actual}, pinned {RUST_SRC_SHA256}")
    with tempfile.TemporaryDirectory(prefix="absd-rust-src-") as work:
        with tarfile.open(tarball, "r:xz") as tar:
            members = [m for m in tar.getmembers()
                       if m.name == RUST_SRC_TAR_LIBRARY or m.name.startswith(RUST_SRC_TAR_LIBRARY + "/")]
            tar.extractall(work, members=members, filter="data")
        base = pathlib.Path(work) / pathlib.Path(RUST_SRC_TAR_LIBRARY).parent
        return tree_fingerprint(base, "library")[0]


def host_table():
    return {name: first_line(argv, VERSION_LINE.get(name)) for name, argv in HOST_TOOLS.items()}


def packages_table():
    out = {}
    for name in HOST_PACKAGES:
        try:
            version = run(["dpkg-query", "-W", "-f=${Version}", name]).strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            version = "absent"
        out[name] = version or "absent"
    return out


def grub_table():
    out = {}
    for name, path in GRUB_MODULES.items():
        p = pathlib.Path(path)
        out[name] = tree_fingerprint(p.parent, p.name)[0] if p.is_dir() else "absent"
    return out


def toolchain_tables(kernel, tarball=None):
    return {"toolchain.rustc": platform_rustc(), "toolchain.cargo": platform_cargo(),
            "toolchain.rust_src": rust_src_table(tarball),
            "toolchain.kernel_rustc": kernel_rustc(kernel_toolchain_name(kernel)),
            "toolchain.host": host_table(), "toolchain.host_packages": packages_table(),
            "toolchain.grub_modules": grub_table()}


# -- the sources -------------------------------------------------------------------

def git(path, *args):
    return run(["git", "-C", str(path), *args]).strip()


def repository(path):
    common = pathlib.Path(git(path, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    local = common.parent if common.name == ".git" else common
    try:
        remote = git(path, "config", "--get", "remote.origin.url")
    except subprocess.CalledProcessError:
        remote = ""
    return str(local), remote


def coordination(platform, components=None):
    """The workload commits the platform builds (scripts/verify-inputs.sh
    pins them) and, when reachable, the qualified lineage file."""
    text = (platform / "scripts" / "verify-inputs.sh").read_text()
    out = {}
    for name in ("pulse", "ag"):
        m = re.search(r'git -C "\$' + name + r'" rev-parse HEAD\)" = \\\s*([0-9a-f]{40})', text)
        out[f"{name}_commit"] = m.group(1) if m else "unknown"
    for name in ("nightshift", "nq"):
        m = re.search(r'git -C "\$' + name + r'" rev-parse ([0-9a-f]{40})\^\{tree\}\)" = \\\s*([0-9a-f]{40})', text)
        out[f"{name}_commit"], out[f"{name}_tree"] = (m.group(1), m.group(2)) if m else ("unknown", "unknown")
    # Where the workloads were read from (scripts/inputs.sh exports these).
    for name in ("PULSE", "AG", "NIGHTSHIFT", "NQ"):
        found = absd_inputs.source(name)
        out[f"ABSD_{name}_SOURCE"] = str(found) if found else "unknown"
    if components is not None and pathlib.Path(components).is_file():
        doc = load(components)
        out["components_toml"] = str(components)
        out["components_toml_sha256"] = sha256_file(components)
        out["components_qualified_at"] = str(doc.get("qualified_at", ""))
        out["components_note"] = "the last qualified lineage; not a claim that this release was qualified with it"
    return out


def identity(platform, release_dir, given):
    """kernel_abi, fsd_protocol, fs_format, app_abi: the absd-release crate's
    constants, which must equal the release record's fields and any value
    given on the command line."""
    found, sources = {}, []
    lib = platform / "release" / "src" / "lib.rs"
    if lib.is_file():
        text = lib.read_text()
        for key in IDENTITY_KEYS:
            m = re.search(r"pub const " + key.upper() + r": u\d+ = (\d+);", text)
            if m:
                found[key] = int(m.group(1))
        sources.append("release/src/lib.rs")
    record = release_dir / "release"
    if record.is_file():
        fields = dict(line.split("=", 1) for line in record.read_text().splitlines() if "=" in line)
        for key in IDENTITY_KEYS:
            if key in fields:
                value = int(fields[key])
                if key in found and found[key] != value:
                    raise Failed(f"identity {key}: the record says {value}, release/src/lib.rs {found[key]}")
                found[key] = value
        sources.append("release record")
    for key, value in given.items():
        if value is None:
            continue
        if key in found and found[key] != value:
            raise Failed(f"identity {key}: given {value}, the build says {found[key]}")
        found[key] = value
        if "arguments" not in sources:
            sources.append("arguments")
    return found, sources


def release_id(release_dir, given):
    record = release_dir / "release"
    if record.is_file():
        for line in record.read_text().splitlines():
            if line.startswith("release="):
                rid = line.split("=", 1)[1]
                if given and given != rid:
                    raise Failed(f"release id: given {given}, the record says {rid}")
                return rid
    if not given:
        raise Failed(f"{release_dir}: no release record; give --release-id")
    return given


def build_table(platform, kernel, rid, make_vars):
    config = load(platform / ".cargo" / "config.toml")
    out = {
        "platform_root": str(platform),
        "kernel_root": str(kernel),
        "cargo_home": os.environ.get("CARGO_HOME", str(pathlib.Path.home() / ".cargo")),
        "release_id_env": rid,
        "verify_inputs_sha256": sha256_file(platform / "scripts" / "verify-inputs.sh"),
        "cargo_config_sha256": sha256_file(platform / ".cargo" / "config.toml"),
        "build_std": list(config.get("unstable", {}).get("build-std", [])),
        "build_std_features": list(config.get("unstable", {}).get("build-std-features", [])),
        "rustflags": list(config.get("target", {}).get("x86_64-unknown-absd", {}).get("rustflags", [])),
        "cargo_profile": "release, --locked --offline, -Z build-std (scripts/prepare-and-build.sh)",
        "rustc_wrapper_sha256": sha256_file(platform / "scripts" / "rustc-staged.sh"),
        "prepare_and_build_sha256": sha256_file(platform / "scripts" / "prepare-and-build.sh"),
        "user_linker_sha256": sha256_file(platform / "user-linker.ld"),
        "pal_patch_sha256": sha256_file(platform / "patches" / "rust-1.95.0-absd-std.patch"),
        "library_lock_sha256": sha256_file(platform / "pins" / "library.Cargo.lock"),
        "kernel_makefile_sha256": sha256_file(kernel / "Makefile"),
        "kernel_make_target": "durable-iso",
    }
    targets = {p.name: sha256_file(p) for p in sorted((platform / "targets").glob("*.json"))}
    return out, targets, dict(make_vars, EXTERNAL_INPUT_sha256=sha256_bytes(b""))


# -- the artifacts ---------------------------------------------------------------

def release_files(release_dir):
    out = []
    for path in sorted(release_dir.rglob("*")):
        rel = path.relative_to(release_dir).as_posix()
        if path.is_file() and not path.is_symlink() and rel not in UNRECORDED:
            out.append(rel)
    return out


def origin_candidates(rel):
    """Where a release-directory file comes from in a platform build."""
    parts = rel.split("/")
    if len(parts) == 1 and rel.endswith(".elf"):
        return [rel]
    if parts[:2] == ["tree", "bin"] and len(parts) == 3:
        return [f"commands/{parts[2]}", f"ports/{parts[2]}"]
    if parts[:3] == ["tree", "share", "man"]:
        return ["manpages/" + "/".join(parts[3:])]
    if parts[:2] == ["site-defaults", "etc"] and len(parts) == 3:
        return [f"operator/etc/{parts[2]}"]
    return []


def artifacts(release_dir, platform):
    files = {}
    for rel in release_files(release_dir):
        digest = sha256_file(release_dir / rel)
        entry = {"sha256": digest, "bytes": (release_dir / rel).stat().st_size}
        if rel == ISO:
            entry["origin"] = "kernel make durable-iso (compared by contents: artifacts.iso)"
        else:
            for candidate in origin_candidates(rel):
                path = platform / candidate
                if path.is_file() and sha256_file(path) == digest:
                    entry["origin"] = candidate
                    break
            else:
                entry["origin"] = "release tool"
        files[rel] = entry
    return files


def expected_bin(platform):
    """The commands and ports /bin must carry (scripts/operator_image.py)."""
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    try:
        import operator_image as oi
    except Exception:  # its imports need the platform's helpers; fall back
        return [], []
    return list(oi.NATIVE) + ["absd-sh"], list(oi.PORTS)


# -- build ---------------------------------------------------------------------------

def build(release_dir, platform, kernel, rid=None, given=None, tarball=None, components=None, make_vars=None,
          receipts=(), partial=False, built=None, toolchain=None):
    release_dir, platform, kernel = (pathlib.Path(p).resolve() for p in (release_dir, platform, kernel))
    rid = release_id(release_dir, rid)
    ident, ident_sources = identity(platform, release_dir, given or {})
    limitations = list(LIMITATIONS)
    missing = [k for k in IDENTITY_KEYS if k not in ident]
    if missing:
        if not partial:
            raise Failed(f"identity unknown: {', '.join(missing)} (no release/src/lib.rs, record, or argument)")
        limitations.append(f"Partial manifest: identity fields unknown: {', '.join(missing)}.")
    if not (release_dir / ISO).is_file():
        raise Failed(f"{release_dir}: no {ISO}")
    files = artifacts(release_dir, platform)
    native, ports = expected_bin(platform)
    absent = [n for n in native + ports if f"tree/bin/{n}" not in files]
    if absent:
        if not partial:
            raise Failed(f"{release_dir}: tree/bin lacks {', '.join(absent)}")
        limitations.append(f"Partial manifest: tree/bin lacks {', '.join(absent)}.")
    vars_ = dict(KERNEL_MAKE, **(make_vars or {}))
    build_out, targets, kernel_image = build_table(platform, kernel, rid, vars_)
    kernel_local, kernel_remote = repository(kernel)
    platform_local, platform_remote = repository(platform)
    built = built or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    manual = release_dir / "tree" / "share" / "man"
    iso = iso_contents(release_dir / ISO)
    doc = {"schema": SCHEMA}
    doc["release"] = {"id": rid, "built": built, "built_clock": "host (unsynchronized wall clock, UTC)"}
    doc["identity"] = dict({k: ident[k] for k in IDENTITY_KEYS if k in ident}, source=" + ".join(ident_sources))
    doc["source"] = {
        "kernel_commit": git(kernel, "rev-parse", "HEAD"),
        "kernel_tree_clean": git(kernel, "status", "--porcelain", "--untracked-files=all") == "",
        "kernel_repository": kernel_local, "kernel_remote": kernel_remote,
        "platform_commit": git(platform, "rev-parse", "HEAD"),
        "platform_tree_clean": git(platform, "status", "--porcelain", "--untracked-files=all") == "",
        "platform_repository": platform_local, "platform_remote": platform_remote,
    }
    doc["source.coordination_pins"] = coordination(platform, components)
    doc.update(toolchain if toolchain is not None else toolchain_tables(kernel, tarball))
    doc["build"] = build_out
    doc["build.targets"] = targets
    doc["build.kernel_image"] = kernel_image
    doc["artifacts.iso"] = dict(iso, kernel_normalization=KERNEL_NORMALIZATION,
                                embedded_worker=vars_["EXTERNAL_USER_ELF"],
                                embedded_file_server=vars_["FILE_SERVER_ELF"])
    doc["artifacts.files"] = dict(sorted(files.items()))
    doc["artifacts.summary"] = {"files": len(files),
                                "manual_tree_sha256": dot_tree_hash(manual) if manual.is_dir() else "absent"}
    doc["filesystem"] = {"formats_accepted": [ident.get("fs_format", 2)]}
    doc["support"] = dict(SUPPORT)
    doc["qualification"] = {"receipts": list(receipts),
                            "note": "receipt names are filled by the gate record (kernel "
                                    "docs/install-update-recovery/README.md)"}
    doc["limitations"] = {"items": limitations}
    text = toml_dump(doc)
    (release_dir / MANIFEST).write_text(text)
    return text


# -- verify --------------------------------------------------------------------------

def verify(release_dir, manifest=None):
    """Every digest the manifest names, recomputed. Returns the problems
    (empty when the release directory is intact) and the unlisted files."""
    release_dir = pathlib.Path(release_dir).resolve()
    doc = load(manifest or release_dir / MANIFEST)
    problems = []
    files = table(doc, "artifacts.files")
    for rel, entry in sorted(files.items()):
        path = release_dir / rel
        if not path.is_file():
            problems.append(f"missing {rel}")
        elif sha256_file(path) != entry["sha256"]:
            problems.append(f"digest mismatch {rel}")
    unlisted = [rel for rel in release_files(release_dir) if rel not in files]
    problems += [f"unrecorded file {rel}" for rel in unlisted]
    if (release_dir / ISO).is_file():
        want = table(doc, "artifacts.iso")
        got = iso_contents(release_dir / ISO)
        for key in ("boot/absd-kernel", "boot/grub/grub.cfg", "kernel_normalized"):
            if got[key] != want.get(key):
                problems.append(f"digest mismatch {ISO}:{key}")
    return problems


# -- toolchain-check ---------------------------------------------------------------

# What must equal the manifest for a reconstruction on this host.
TOOLCHAIN_CHECKS = {
    "toolchain.rustc": ["commit_hash", "release", "llvm", "host", "verbose_sha256", "binary_sha256"],
    "toolchain.cargo": ["commit_hash", "verbose_sha256", "binary_sha256"],
    "toolchain.rust_src": ["library_fingerprint", "library_files", "library_bytes", "library_symlinks"],
    "toolchain.kernel_rustc": ["commit_hash", "release", "llvm", "host", "verbose_sha256"],
    "toolchain.host": list(HOST_TOOLS),
    "toolchain.host_packages": HOST_PACKAGES,
    "toolchain.grub_modules": list(GRUB_MODULES),
}


def toolchain_mismatches(doc, here):
    out = []
    for name, keys in TOOLCHAIN_CHECKS.items():
        want, got = table(doc, name), here.get(name, {})
        for key in keys:
            if key not in want:
                continue
            if got.get(key) != want[key]:
                out.append(f"{name}.{key}: manifest {want[key]!r}, this host {got.get(key)!r}")
    return out


def toolchain_check(manifest, tarball=None):
    doc = load(manifest)
    name = table(doc, "toolchain.kernel_rustc").get("rustup_toolchain", "stable")
    here = {"toolchain.rustc": platform_rustc(), "toolchain.cargo": platform_cargo(),
            "toolchain.rust_src": rust_src_table(), "toolchain.kernel_rustc": kernel_rustc(name),
            "toolchain.host": host_table(), "toolchain.host_packages": packages_table(),
            "toolchain.grub_modules": grub_table()}
    problems = toolchain_mismatches(doc, here)
    rs = table(doc, "toolchain.rust_src")
    if rs.get("sha256") != RUST_SRC_SHA256 or rs.get("git_commit") != RUST_SRC_COMMIT:
        problems.append("toolchain.rust_src: the manifest names another rust-src distribution than this tool pins")
    if tarball is not None:
        try:
            fingerprint = tarball_fingerprint(tarball)
            if fingerprint != rs.get("library_fingerprint"):
                problems.append(f"toolchain.rust_src: tarball library fingerprint {fingerprint}, manifest "
                                f"{rs.get('library_fingerprint')}")
        except Failed as error:
            problems.append(f"toolchain.rust_src: {error}")
    return problems, here


# -- compare (reconstruction) --------------------------------------------------------

def compare(manifest, platform, iso, built_kernel_root=None, release_dir=None):
    """Each recorded artifact against the rebuild: platform-origin files by
    bytes; the ISO by its kernel ELF (bytes, else normalized) and grub.cfg;
    release-tool files (the record, site defaults) from the original
    release directory when given, else not compared. Returns (results,
    ok)."""
    doc = load(manifest)
    platform = pathlib.Path(platform)
    results = {}
    for rel, entry in sorted(table(doc, "artifacts.files").items()):
        origin = entry.get("origin", "")
        if rel == ISO:
            continue
        if origin and origin != "release tool":
            path = platform / origin
            if not path.is_file():
                results[rel] = {"origin": origin, "result": "missing", "method": "bytes"}
                continue
            same = sha256_file(path) == entry["sha256"]
            results[rel] = {"origin": origin, "result": "identical" if same else "differs", "method": "bytes",
                            "rebuilt_sha256": sha256_file(path)}
        else:
            results[rel] = {"origin": "release tool", "result": "not rebuilt",
                            "method": "generated by scripts/release.py from the identity and site defaults"}
    want = table(doc, "artifacts.iso")
    iso_result = {"origin": "kernel make durable-iso", "rebuilt_sha256": sha256_file(iso)}
    iso_result["whole_image"] = ("identical" if iso_result["rebuilt_sha256"] == table(doc, "artifacts.files")
                                 .get(ISO, {}).get("sha256") else "differs (grub-mkrescue stamps the image)")
    got = iso_contents(iso)
    iso_result["grub_cfg"] = "identical" if got["boot/grub/grub.cfg"] == want.get("boot/grub/grub.cfg") else "differs"
    if got["boot/absd-kernel"] == want.get("boot/absd-kernel"):
        iso_result["kernel"] = "identical"
        iso_result["kernel_method"] = "bytes"
    elif got["kernel_normalized"] == want.get("kernel_normalized"):
        iso_result["kernel"] = "identical when compared stripped"
        iso_result["kernel_method"] = "compared stripped: " + KERNEL_NORMALIZATION
    else:
        iso_result["kernel"] = "differs"
        iso_result["kernel_method"] = "bytes and compared stripped"
    iso_result["rebuilt_kernel_sha256"] = got["boot/absd-kernel"]
    iso_result["rebuilt_kernel_normalized"] = got["kernel_normalized"]
    if built_kernel_root is not None:
        iso_result["kernel_root"] = str(built_kernel_root)
        iso_result["kernel_root_as_recorded"] = str(built_kernel_root) == table(doc, "build").get("kernel_root")
    results[ISO] = iso_result
    ok = all(r["result"] in ("identical", "not rebuilt") for k, r in results.items() if k != ISO)
    ok = ok and iso_result["grub_cfg"] == "identical" and iso_result["kernel"] != "differs"
    return results, ok


def write_receipt(path, manifest, results, ok, toolchain_problems, extra):
    doc = load(manifest)
    out = {"schema": "absd-reconstruction-receipt/1"}
    out["reconstruction"] = dict({
        "manifest": str(pathlib.Path(manifest).resolve()),
        "manifest_sha256": sha256_file(manifest),
        "release": table(doc, "release").get("id", ""),
        "when": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "when_clock": "host (unsynchronized wall clock, UTC)",
        "result": "reconstructed" if ok and not toolchain_problems else "not reconstructed",
        "toolchain": "matches" if not toolchain_problems else "mismatch",
        "toolchain_mismatches": toolchain_problems,
    }, **extra)
    counts = {}
    for rel, r in results.items():
        if rel != ISO:
            counts[r["result"]] = counts.get(r["result"], 0) + 1
    out["summary"] = {k.replace(" ", "_"): v for k, v in sorted(counts.items())}
    out["iso"] = results.get(ISO, {})
    out["files"] = {rel: r for rel, r in sorted(results.items()) if rel != ISO}
    pathlib.Path(path).write_text(toml_dump(out))


# -- command line -------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("--kernel", required=True, help="the kernel checkout the ISO was built in")
    b.add_argument("--platform", required=True, help="the platform build root the artifacts came from")
    b.add_argument("--release-id")
    for key in IDENTITY_KEYS:
        b.add_argument("--" + key.replace("_", "-"), type=int, dest=key)
    b.add_argument("--rust-src-tarball", help="also check the published tarball against the installed tree")
    b.add_argument("--components", default=os.environ.get("ABSD_COMPONENTS_TOML"),
                   help="the qualified-lineage file (default: ABSD_COMPONENTS_TOML; "
                        "no implicit file when unset)")
    b.add_argument("--kernel-make-var", action="append", default=[], metavar="NAME=VALUE",
                   help="a make variable the ISO was built with that differs from operator_image.py's")
    b.add_argument("--receipt", action="append", default=[], help="a qualification receipt name")
    b.add_argument("--partial", action="store_true",
                   help="record an incomplete release (missing identity or /bin entries) under limitations")
    b.add_argument("release_dir")
    v = sub.add_parser("verify")
    v.add_argument("--manifest")
    v.add_argument("release_dir")
    t = sub.add_parser("toolchain-check")
    t.add_argument("--manifest", required=True)
    t.add_argument("--rust-src-tarball")
    c = sub.add_parser("compare")
    c.add_argument("--manifest", required=True)
    c.add_argument("--platform-root", required=True)
    c.add_argument("--iso", required=True)
    c.add_argument("--kernel-root")
    c.add_argument("--receipt", required=True)
    c.add_argument("--toolchain-mismatch", action="append", default=[])
    c.add_argument("--note", action="append", default=[], metavar="KEY=VALUE")
    args = ap.parse_args(argv)
    try:
        if args.command == "build":
            make_vars = dict(item.split("=", 1) for item in args.kernel_make_var)
            given = {k: getattr(args, k) for k in IDENTITY_KEYS}
            components = args.components
            build(args.release_dir, args.platform, args.kernel, args.release_id, given, args.rust_src_tarball,
                  components, make_vars, args.receipt, args.partial)
            print(f"RELEASE MANIFEST WRITTEN {pathlib.Path(args.release_dir) / MANIFEST}")
        elif args.command == "verify":
            problems = verify(args.release_dir, args.manifest)
            for problem in problems:
                print(f"release manifest: {problem}", file=sys.stderr)
            if problems:
                return 1
            doc = load(args.manifest or pathlib.Path(args.release_dir) / MANIFEST)
            print(f"RELEASE MANIFEST VERIFIED files={len(table(doc, 'artifacts.files'))} iso_contents=3")
        elif args.command == "toolchain-check":
            problems, here = toolchain_check(args.manifest, args.rust_src_tarball)
            for problem in problems:
                print(f"toolchain mismatch: {problem}", file=sys.stderr)
            if problems:
                return 1
            print("RELEASE TOOLCHAIN OK rustc={} kernel_rustc={} rust_src={} tarball={}".format(
                here["toolchain.rustc"]["commit_hash"][:9], here["toolchain.kernel_rustc"]["commit_hash"][:9],
                here["toolchain.rust_src"]["library_fingerprint"][:16],
                "checked" if args.rust_src_tarball else "not-given"))
        else:
            results, ok = compare(args.manifest, args.platform_root, args.iso, args.kernel_root)
            extra = dict(item.split("=", 1) for item in args.note)
            write_receipt(args.receipt, args.manifest, results, ok, args.toolchain_mismatch, extra)
            iso = results[ISO]
            counts = {}
            for rel, r in results.items():
                if rel != ISO:
                    counts[r["result"]] = counts.get(r["result"], 0) + 1
            print("RECONSTRUCTION {} files: {} kernel: {} grub_cfg: {} receipt={}".format(
                "OK" if ok and not args.toolchain_mismatch else "FAILED",
                ", ".join(f"{k}={v}" for k, v in sorted(counts.items())), iso["kernel"], iso["grub_cfg"],
                args.receipt))
            return 0 if ok and not args.toolchain_mismatch else 1
    except (Failed, subprocess.CalledProcessError, OSError) as error:
        print(f"release manifest: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
