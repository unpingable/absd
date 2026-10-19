#!/usr/bin/env python3
"""Reproducible boot media for one frozen kernel/platform pair.
Generalises the S4 recipe (the development checkout,
bf8c7583/f8184ca) into a repository-owned entry point with named profiles
(media/<profile>.toml).

    media.py stage    --profile P --work WORK --kernel-commit K --platform-commit C
                      --platform-repo REPO --probe ELF --probe-receipt JSON
                      --input FILE --expected FILE
    media.py kernel   --work WORK
    media.py image    --work WORK --out NEW_DIR
    media.py validate --work WORK --out DIR
    media.py boot     --work WORK --out DIR --results NEW_DIR

WORK is one build root: WORK/kernel is a clean, disposable kernel checkout
at the pair's kernel commit (never the canonical repository), and every
input is copied into WORK/inputs by `stage`, which refuses a mismatched
pair before anything is built. The kernel is built with one Cargo job,
offline, with a private Cargo home and WORK remapped to the profile's root,
so two different WORK paths give identical bytes. `image` assembles regular
files only (no device, mount or sudo) and refuses an existing destination.

Profiles implemented: z2-usb (S4's GPT/EFI USB disk for the Z2's attended
boot) through the commands above, and vm-operator (the operator ISO plus a
separate writable ABSD disk and MANIFEST, as U1-b ran them) through

    media.py operator-image | operator-validate | operator-boot

(scripts/media_operator.py, which documents them).

Reproducibility claim: the same pair, retained runtime inputs and the tool
versions recorded in MEDIA-RECEIPT.json give the same bytes. Nothing here
claims other compiler, GRUB, dosfstools, mtools or gdisk versions.
"""

import argparse
import datetime
import hashlib
import json
import lzma
import os
import pathlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
PROFILES = ROOT / "media"
IMPLEMENTED = ("z2-usb", "vm-operator")
STAGE_RECORD = "STAGE.json"
COMMIT = re.compile(r"[0-9a-f]{40}")
PACKAGES = ("binutils", "gcc-13", "libc6-dev", "grub-common", "grub-efi-amd64-bin", "dosfstools", "mtools",
            "gdisk", "ovmf", "qemu-system-x86", "xz-utils")


class Refused(Exception):
    pass


def sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def run(*argv, env=None, cwd=None):
    subprocess.run([str(a) for a in argv], check=True, env=env, cwd=cwd)


def git(repo, *args):
    return subprocess.run([tool("git"), "-C", str(repo), *args], check=True, capture_output=True,
                          env=clean_env(0)).stdout


def load_profile(name):
    if name not in IMPLEMENTED:
        raise Refused(f"profile_not_implemented {name} (implemented: {', '.join(IMPLEMENTED)})")
    return tomllib.loads((PROFILES / f"{name}.toml").read_text())


def profile_sha(name):
    return sha(PROFILES / f"{name}.toml")


SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
# What this builder does not guarantee (recorded in every receipt and in
# docs/media-20261016/BUILD-BOOT.md).
LIMITS = [
    "make runs by absolute path from its package but its version is not pinned; gcc-13 and binutils are "
    "version-pinned packages, but the cc/ld the kernel build reaches through the system PATH are not "
    "ownership-checked",
    "hard links to regular files are accepted, and check-then-open races on WORK and --out paths are out of "
    "scope: the builder trusts the account it runs as",
    "STAGE.json and KERNEL-BUILD.json are ordinary reads inside WORK, protected by their digests and the "
    "stage checks, not by confinement",
]
# Every external program this builder runs, with the package its file must
# belong to. Programs are found on SYSTEM_PATH only (never the caller's
# PATH) and run by absolute path; tool() refuses one another package owns.
TOOL_PACKAGES = {"grub-mkstandalone": "grub-common", "grub-file": "grub-common", "sgdisk": "gdisk",
                 "mkfs.vfat": "dosfstools", "fsck.fat": "dosfstools", "mcopy": "mtools", "mmd": "mtools",
                 "xz": "xz-utils", "make": "make", "qemu-system-x86_64": "qemu-system-x86",
                 "dpkg-query": "dpkg", "git": "git", "grub-mkrescue": "grub-common", "xorriso": "xorriso",
                 "setarch": "util-linux", "faketime": "faketime", "ssh": "openssh-client"}
_TOOLS = {}


def clean_env(epoch, home="/nonexistent", path=SYSTEM_PATH, **extra):
    """The whole environment of every subprocess this builder runs, checks
    included: the system PATH (or the kernel step's, which adds the rustup
    proxies), a HOME that holds no configuration, a fixed locale, zone and
    epoch, MTOOLSRC=/dev/null, and nothing inherited, so XZ_OPT/XZ_DEFAULTS,
    ~/.mtoolsrc and similar settings cannot change the bytes. Recorded
    whole in the receipt."""
    env = {"PATH": path, "HOME": str(home), "LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": str(epoch),
           "MTOOLSRC": "/dev/null"}
    env.update({k: str(v) for k, v in extra.items()})
    return env


def _owner(path):
    """The package dpkg says installed `path` (trying the /usr-merged and
    unmerged spellings), or None."""
    candidates = [str(path)]
    text = str(path)
    if text.startswith("/usr/"):
        candidates.append(text[4:])
    else:
        candidates.append("/usr" + text)
    for candidate in candidates:
        done = subprocess.run(["/usr/bin/dpkg-query", "-S", candidate], capture_output=True, text=True,
                              env=clean_env(0))
        if done.returncode == 0:
            for line in done.stdout.splitlines():
                packages, _, owned = line.partition(": ")
                if owned.strip() == candidate:
                    return [p.split(":")[0].strip() for p in packages.split(",")]
    return None


def tool(name):
    """The absolute path of `name` on SYSTEM_PATH, after checking that the
    file it resolves to belongs to its package in TOOL_PACKAGES."""
    if name in _TOOLS:
        return _TOOLS[name]["path"]
    package = TOOL_PACKAGES[name]
    found = shutil.which(name, path=SYSTEM_PATH)
    if found is None:
        raise Refused(f"tool_missing {name} (package {package}) is not on {SYSTEM_PATH}")
    real = os.path.realpath(found)
    owners = _owner(real)
    if not owners or package not in owners:
        raise Refused(f"tool_unowned {found} -> {real} belongs to {owners}, not {package}")
    _TOOLS[name] = {"path": found, "real": real, "sha256": sha(real), "package": package}
    return found


def tools_used():
    return {name: dict(entry) for name, entry in sorted(_TOOLS.items())}


def package_versions(packages, env=None):
    result = subprocess.run([tool("dpkg-query"), "-W", "-f", "${Package}=${Version}\\n", *packages],
                            capture_output=True, text=True, env=env or clean_env(0))
    found = dict(line.split("=", 1) for line in result.stdout.split() if "=" in line)
    return found


def rust_toolchain(profile):
    """The kernel's toolchain from the location the profile pins (never the
    caller's PATH or rustup proxies): RUSTUP_HOME/toolchains/NAME/bin must
    hold rustc and cargo at their pinned SHA-256."""
    rust = profile.get("pins", {}).get("rust")
    if not rust:
        raise Refused("pins_missing the profile pins no Rust toolchain")
    home = pathlib.Path(os.path.expanduser(rust["rustup_home"])).resolve()
    bin_dir = home / "toolchains" / rust["toolchain"] / "bin"
    found = {}
    for name in ("rustc", "cargo"):
        path = bin_dir / name
        if path.is_symlink() or not path.is_file():
            raise Refused(f"tool_missing {path} (the pinned {rust['toolchain']} toolchain)")
        found[name] = {"path": str(path), "sha256": sha(path)}
        if found[name]["sha256"] != rust[f"{name}_sha256"]:
            raise Refused(f"pins_mismatch {path} sha256 {found[name]['sha256']}, pinned {rust[name + '_sha256']}")
    return bin_dir, found


def fresh_dir(path):
    """`path` created new and empty; a link there is refused, a directory
    left by an earlier attempt is replaced."""
    path = pathlib.Path(path)
    if path.is_symlink():
        raise Refused(f"path_refused {path} is a link")
    if path.exists():
        shutil.rmtree(path)
    path.mkdir()
    return path


def rust_env(work, epoch, profile, **extra):
    """The kernel step's environment: the pinned toolchain's bin directory
    before the system PATH, a fresh empty HOME inside WORK, and no rustup
    variables (the toolchain's own cargo and rustc run directly)."""
    bin_dir, _ = rust_toolchain(profile)
    home = fresh_dir(pathlib.Path(work) / "home")
    return clean_env(epoch, home=home, path=f"{bin_dir}:{SYSTEM_PATH}", **extra)


def check_pins(profile, kernel_dir=None, env=None):
    """Refuses before building unless every pinned package (and, for the
    kernel step, rustc in the kernel checkout under the environment `env`
    the build will use) has exactly the pinned version. Returns what was
    checked, for the receipt."""
    pins = profile.get("pins", {})
    wanted = pins.get("packages", {})
    found = package_versions(sorted(wanted), env)
    wrong = {name: (version, found.get(name)) for name, version in wanted.items() if found.get(name) != version}
    if wrong:
        raise Refused("pins_mismatch " + ", ".join(f"{n} wants {w} has {h}" for n, (w, h) in sorted(wrong.items())))
    checked = {"packages": {n: found[n] for n in sorted(wanted)}}
    if kernel_dir is not None and pins.get("rustc"):
        rustc = subprocess.run(["rustc", "-V"], cwd=kernel_dir, capture_output=True, text=True, env=env).stdout.strip()
        if rustc != pins["rustc"]:
            raise Refused(f"pins_mismatch rustc wants {pins['rustc']!r} has {rustc!r}")
        checked["rustc"] = rustc
    return checked


def confined(directory, name):
    """A receipt-supplied file name: a plain name of a regular file inside
    `directory`, never a path, a link or a device."""
    if not isinstance(name, str) or not name or "/" in name or name in (".", "..") or "," in name:
        raise Refused(f"path_refused {name!r} is not a plain file name")
    path = pathlib.Path(directory) / name
    if path.is_symlink() or not path.is_file():
        raise Refused(f"path_refused {path} is not a regular file")
    return path


def copy_exact(src, dst, offset, count):
    """Copies exactly `count` bytes from `offset`; a short source is refused."""
    with open(src, "rb") as source, open(dst, "wb") as target:
        source.seek(offset)
        remaining = count
        while remaining:
            block = source.read(min(remaining, 1 << 20))
            if not block:
                raise Refused(f"truncated {src}: {remaining} bytes short at offset {offset + count - remaining}")
            target.write(block)
            remaining -= len(block)


def builder_identity():
    head = subprocess.run([tool("git"), "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True,
                          env=clean_env(0)).stdout.strip()
    dirty = subprocess.run([tool("git"), "-C", str(ROOT), "status", "--porcelain", "--", "scripts", "media"],
                           capture_output=True, text=True, env=clean_env(0)).stdout.strip()
    return {"revision": head or "unknown", "dirty": bool(dirty)}


# -- the pair ----------------------------------------------------------------------

def names(kernel, platform):
    return {"kernel": kernel, "platform": platform, "kernel7": kernel[:7], "platform8": platform[:8]}


def guid(prefix, kernel, platform, index):
    """Deterministic disk/partition GUIDs from the pair (S4's form)."""
    return f"{prefix}-{platform[0:4]}-4{platform[5:8]}-8{kernel[1:4]}-{index:012x}"


def leading_comment(text):
    """A source file's leading block comment and the blank line after it."""
    lines = text.splitlines(keepends=True)
    out = []
    for line in lines:
        out.append(line)
        if line.rstrip().endswith("*/"):
            break
    else:
        raise Refused("notice_source no leading block comment")
    rest = lines[len(out):]
    if rest and not rest[0].strip():
        out.append(rest[0])
    return "".join(out).encode()


def notice_bytes(spec, kernel_dir, platform_repo, platform_commit):
    kind, _, path = spec.partition(":")
    if kind == "kernel":
        return (kernel_dir / path).read_bytes()
    if kind == "kernel-comment":
        return leading_comment((kernel_dir / path).read_text())
    if kind == "platform":
        return git(platform_repo, "show", f"{platform_commit}:{path}")
    if kind == "host":
        return pathlib.Path(path).read_bytes()
    raise Refused(f"notice_source unknown kind {kind!r}")


def stage(args):
    if load_profile(args.profile).get("kind") == "operator":
        raise Refused(f"profile_kind {args.profile} is built with `media.py operator-image`, not `stage`")
    """Copy and check every input into WORK; refuse a mismatched pair."""
    profile = load_profile(args.profile)
    work = pathlib.Path(args.work).resolve()
    kernel_dir = work / "kernel"
    for name, value in (("kernel", args.kernel_commit), ("platform", args.platform_commit)):
        if not COMMIT.fullmatch(value):
            raise Refused(f"pair_invalid {name} commit must be 40 hex digits")
    if kernel_dir.is_symlink() or not (kernel_dir / "Makefile").is_file():
        raise Refused(f"kernel_checkout_missing {kernel_dir} (a clean disposable checkout at {args.kernel_commit[:12]},"
                      " a directory inside WORK, not a link)")
    head = git(kernel_dir, "rev-parse", "HEAD").decode().strip()
    if head != args.kernel_commit:
        raise Refused(f"pair_mismatch kernel checkout is at {head[:12]}, the pair names {args.kernel_commit[:12]}")
    if git(kernel_dir, "status", "--porcelain").strip():
        raise Refused("kernel_checkout_dirty")
    try:
        git(args.platform_repo, "cat-file", "-e", f"{args.platform_commit}^{{commit}}")
    except subprocess.CalledProcessError:
        raise Refused(f"pair_mismatch platform commit {args.platform_commit[:12]} is not in {args.platform_repo}") from None
    receipt = json.loads(pathlib.Path(args.probe_receipt).read_text())
    if receipt.get("requested_source") != args.platform_commit:
        raise Refused(f"pair_mismatch the probe receipt is for platform {str(receipt.get('requested_source'))[:12]}")
    if receipt.get("probe_sha256") != sha(args.probe):
        raise Refused("probe_mismatch the probe ELF is not the one its receipt names")
    if not pathlib.Path(args.probe).read_bytes().startswith(b"\x7fELF\x02"):
        raise Refused("probe_mismatch not an ELF64")
    inputs = work / "inputs"
    if inputs.exists():
        raise Refused(f"stage_exists {inputs}")
    (inputs / "notices").mkdir(parents=True)
    shutil.copyfile(args.probe, inputs / "probe.elf")
    shutil.copyfile(args.input, inputs / "input.txt")
    shutil.copyfile(args.expected, inputs / "expected.txt")
    (inputs / "RUNTIME-CORRESPONDENCE.json").write_bytes(pathlib.Path(args.probe_receipt).read_bytes())
    notices = {}
    for name, spec in sorted(profile["notices"].items()):
        data = notice_bytes(spec, kernel_dir, args.platform_repo, args.platform_commit)
        (inputs / "notices" / name).write_bytes(data)
        notices[name] = {"source": spec, "sha256": hashlib.sha256(data).hexdigest()}
    epoch = int(git(args.platform_repo, "log", "-1", "--format=%ct", args.platform_commit).decode())
    record = {"profile": args.profile, "profile_sha256": profile_sha(args.profile),
              "kernel_commit": args.kernel_commit, "platform_commit": args.platform_commit,
              "platform_repo": str(pathlib.Path(args.platform_repo).resolve()), "source_date_epoch": epoch,
              "notices": notices,
              "inputs": {n: sha(inputs / n) for n in ("probe.elf", "input.txt", "expected.txt",
                                                       "RUNTIME-CORRESPONDENCE.json")}}
    (work / STAGE_RECORD).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"MEDIA STAGED profile={args.profile} kernel={args.kernel_commit[:12]} platform={args.platform_commit[:12]} "
          f"epoch={epoch}", flush=True)


def staged(work):
    work = pathlib.Path(work).resolve()
    try:
        record = json.loads((work / STAGE_RECORD).read_text())
    except OSError:
        raise Refused(f"not_staged {work} (run `media.py stage` first)") from None
    for name, digest in record["inputs"].items():
        if sha(work / "inputs" / name) != digest:
            raise Refused(f"stage_changed inputs/{name}")
    for name, entry in record["notices"].items():
        if sha(work / "inputs" / "notices" / name) != entry["sha256"]:
            raise Refused(f"stage_changed inputs/notices/{name}")
    if profile_sha(record["profile"]) != record["profile_sha256"]:
        raise Refused(f"stage_changed the {record['profile']} profile changed since staging")
    if (work / "kernel").is_symlink():
        raise Refused("stage_changed WORK/kernel is a link")
    head = git(work / "kernel", "rev-parse", "HEAD").decode().strip()
    if head != record["kernel_commit"] or git(work / "kernel", "status", "--porcelain").strip():
        raise Refused("stage_changed the kernel checkout moved or is dirty")
    return work, record, load_profile(record["profile"])


# -- the kernel --------------------------------------------------------------------

KERNEL_BUILD = "KERNEL-BUILD.json"
KERNEL_OUTPUT = "build/external/target/debug/absd-kernel"


def kernel_binding(work, record, profile):
    """The fields that bind a kernel ELF to this stage: the build record
    written by `kernel` must name this stage's pair, tree, features, inputs
    and remap, and the ELF must be the one that build left in the checkout."""
    return {"kernel_commit": record["kernel_commit"],
            "kernel_tree": git(work / "kernel", "rev-parse", "HEAD^{tree}").decode().strip(),
            "features": profile["kernel"]["features"], "remap_root": profile["kernel"]["remap_root"],
            "inputs": record["inputs"], "source_date_epoch": record["source_date_epoch"],
            "profile_sha256": record["profile_sha256"]}


def bound_kernel(work, record, profile):
    inputs = work / "inputs"
    try:
        build = json.loads((inputs / KERNEL_BUILD).read_text())
    except OSError:
        raise Refused("kernel_missing (run `media.py kernel` first)") from None
    expected = kernel_binding(work, record, profile)
    if {k: build.get(k) for k in expected} != expected:
        raise Refused("kernel_unbound the kernel build record is for another stage")
    if not (inputs / "kernel.elf").is_file() or sha(inputs / "kernel.elf") != build.get("elf_sha256"):
        raise Refused("kernel_unbound inputs/kernel.elf is not the ELF its build record names")
    output = work / "kernel" / KERNEL_OUTPUT
    if not output.is_file() or sha(output) != build["elf_sha256"]:
        raise Refused("kernel_unbound the checkout's build output is not the recorded ELF")
    return build


def kernel(args):
    work, record, profile = staged(args.work)
    inputs = work / "inputs"
    os.umask(0o022)
    env = rust_env(work, record["source_date_epoch"], profile, CARGO_BUILD_JOBS="1", CARGO_NET_OFFLINE="true",
                   CARGO_HOME=work / "cargo-home",
                   RUSTFLAGS=f"--remap-path-prefix={work}={profile['kernel']['remap_root']}")
    pins = check_pins(profile, work / "kernel", env)
    run(tool("make"), "--no-print-directory", "-C", work / "kernel", "external-build",
        f"EXTERNAL_KERNEL_FEATURES={','.join(profile['kernel']['features'])}",
        f"EXTERNAL_USER_ELF={inputs / 'probe.elf'}", f"EXTERNAL_INPUT={inputs / 'input.txt'}",
        f"EXTERNAL_EXPECTED={inputs / 'expected.txt'}", env=env)
    shutil.copyfile(work / "kernel" / KERNEL_OUTPUT, inputs / "kernel.elf")
    run(tool("grub-file"), "--is-x86-multiboot2", inputs / "kernel.elf", env=env)
    rustc = subprocess.run(["rustc", "-V"], cwd=work / "kernel", check=True, capture_output=True,
                           text=True, env=env).stdout.strip()
    _, toolchain = rust_toolchain(profile)
    (inputs / "rustc.txt").write_text(rustc + "\n")
    build = dict(kernel_binding(work, record, profile), elf_sha256=sha(inputs / "kernel.elf"), rustc=rustc,
                 pins=pins, environment=env, toolchain=toolchain,
                 tools=tools_used())
    (inputs / KERNEL_BUILD).write_text(json.dumps(build, indent=2, sort_keys=True) + "\n")
    print(f"MEDIA KERNEL sha256={sha(inputs / 'kernel.elf')} {rustc}", flush=True)


# -- the image ---------------------------------------------------------------------

def pair_record(record, profile, inputs):
    """PAIR.JSON: the profile's fixed fields plus the computed identities,
    sorted, two-space indented, as S4's COMPONENTS.json."""
    kernel_bytes = (inputs / "kernel.elf").read_bytes()
    probe = (inputs / "probe.elf").read_bytes()
    offset = kernel_bytes.find(probe)
    if offset < 0 or kernel_bytes.find(probe, offset + 1) >= 0:
        raise Refused("probe_not_embedded the kernel must carry the staged probe exactly once")
    geometry, identity, fixed = profile["geometry"], profile["identity"], profile["pair"]
    remap = profile["kernel"]["remap_root"]
    doc = {
        "boot_modes": fixed["boot_modes"],
        "build_profile": fixed["build_profile"],
        "embedded_runtime_offset": offset,
        "files": {n: {"bytes": (inputs / n).stat().st_size, "sha256": sha(inputs / n)}
                  for n in ("expected.txt", "input.txt", "kernel.elf", "probe.elf")},
        "kernel_features": profile["kernel"]["features"],
        "kernel_rebuild_reproducibility": fixed["kernel_rebuild_reproducibility"].format(remap_root=remap),
        "kernel_source": record["kernel_commit"],
        "layout": {"esp_sectors": geometry["esp_sectors"], "esp_start_lba": geometry["start_lba"], "esp_type": "EF00",
                   "fat_label": identity["fat_label"], "fat_uuid": identity["fat_uuid"], "gpt": True,
                   "logical_bytes": geometry["image_bytes"], "sector_bytes": geometry["sector_bytes"],
                   "unused_remainder": fixed["unused_remainder"]},
        "physical_target": fixed["physical_target"],
        "platform_source": record["platform_commit"],
        "purpose": fixed["purpose"],
        "runtime_correspondence": json.loads((inputs / "RUNTIME-CORRESPONDENCE.json").read_text()),
        "rustc_kernel": (inputs / "rustc.txt").read_text().strip(),
        "schema_version": 1,
        "source_date_epoch": record["source_date_epoch"],
        "storage": fixed["storage"],
        "write_boundary": fixed["write_boundary"],
    }
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode()


def normalize_fat_dates(image, start, epoch):
    """mtools keeps file dates with -m but stamps directory and access dates
    from the clock: set every directory entry's dates to the epoch (S4)."""
    with open(image, "r+b") as f:
        base = start * 512
        f.seek(base)
        boot = f.read(512)
        assert boot[510:] == b"\x55\xaa"
        bps = struct.unpack_from("<H", boot, 11)[0]
        spc = boot[13]
        reserved = struct.unpack_from("<H", boot, 14)[0]
        nfats = boot[16]
        fatsz = struct.unpack_from("<I", boot, 36)[0]
        root = struct.unpack_from("<I", boot, 44)[0]
        assert bps == 512 and nfats == 2 and spc > 0 and fatsz > 0
        f.seek(base + reserved * bps)
        fat = f.read(fatsz * bps)
        data = base + (reserved + nfats * fatsz) * bps
        cluster_bytes = spc * bps
        dt = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
        date = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
        time_ = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
        seen = set()

        def directory(first):
            cluster = first
            while cluster < 0x0ffffff8:
                assert 2 <= cluster < len(fat) // 4 and cluster not in seen
                seen.add(cluster)
                offset = data + (cluster - 2) * cluster_bytes
                f.seek(offset)
                entries = bytearray(f.read(cluster_bytes))
                children, done = [], False
                for i in range(0, cluster_bytes, 32):
                    if entries[i] == 0:
                        done = True
                        break
                    if entries[i] == 0xe5 or entries[i + 11] == 0x0f:
                        continue
                    entries[i + 13] = 0
                    struct.pack_into("<HHH", entries, i + 14, time_, date, date)
                    struct.pack_into("<HH", entries, i + 22, time_, date)
                    if entries[i + 11] & 0x10 and entries[i] != ord("."):
                        hi = struct.unpack_from("<H", entries, i + 20)[0]
                        lo = struct.unpack_from("<H", entries, i + 26)[0]
                        children.append((hi << 16) | lo)
                f.seek(offset)
                f.write(entries)
                for child in children:
                    directory(child)
                if done:
                    break
                cluster = struct.unpack_from("<I", fat, cluster * 4)[0] & 0x0fffffff

        directory(root)


def fat_stage(work, record, profile, out):
    """The ESP's files, in a staging directory."""
    inputs = work / "inputs"
    n = names(record["kernel_commit"], record["platform_commit"])
    stage_dir = out / "fat"
    for d in ("EFI/BOOT", "BOOT", "RUNTIME", "NOTICES"):
        (stage_dir / d).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(inputs / "kernel.elf", stage_dir / "BOOT/KERNEL.ELF")
    for src, dst in (("probe.elf", "PROBE.ELF"), ("input.txt", "INPUT.TXT"), ("expected.txt", "EXPECT.TXT")):
        shutil.copyfile(inputs / src, stage_dir / "RUNTIME" / dst)
    (stage_dir / "PAIR.JSON").write_bytes(pair_record(record, profile, inputs))
    for p in sorted((inputs / "notices").iterdir()):
        shutil.copyfile(p, stage_dir / "NOTICES" / p.name)
    (stage_dir / "README.TXT").write_text(profile["readme"]["text"].format(**n))
    (stage_dir / "BOOT/GRUB.CFG").write_text(profile["grub"]["config"].format(**n))
    early = out / "early.cfg"
    early.write_text(profile["grub"]["early_cfg"].format(fat_uuid=profile["identity"]["fat_uuid"]))
    return stage_dir, early


def copy_order(stage_dir, profile):
    """The ESP's directories and files in copy order, as paths relative to the
    staging directory ("DIR/" for a directory): a pre-order walk, each
    directory entered right after it is created, which is how `mcopy -s`
    places clusters. `mcopy -s` itself takes each subdirectory's entries in
    the build host's readdir order (on ext4 the per-filesystem hash seed),
    so the same files gave different cluster layouts on different hosts.
    The profile may pin the order (`[fat] order`); otherwise names are
    sorted. Either way the order covers exactly the staged entries."""
    staged = sorted(str(p.relative_to(stage_dir)) + ("/" if p.is_dir() else "") for p in stage_dir.rglob("*"))
    pinned = profile.get("fat", {}).get("order")
    if pinned is None:
        order = []

        def walk(directory, prefix):
            for p in sorted(directory.iterdir(), key=lambda q: q.name):
                order.append(prefix + p.name + ("/" if p.is_dir() else ""))
                if p.is_dir():
                    walk(p, prefix + p.name + "/")

        walk(stage_dir, "")
        return order
    if sorted(pinned) != staged:
        missing = sorted(set(staged) - set(pinned))
        extra = sorted(set(pinned) - set(staged))
        raise Refused(f"fat_order does not cover the staged files: missing {missing[:4]} extra {extra[:4]}")
    for index, entry in enumerate(pinned):
        parent = entry.rstrip("/").rpartition("/")[0]
        if parent and parent + "/" not in pinned[:index]:
            raise Refused(f"fat_order lists {entry} before its directory")
    return list(pinned)


def fat_copy(disk, offset, stage_dir, order, env):
    """Creates each directory and copies each file, one at a time, in `order`."""
    target = f"{disk}@@{offset}"
    for entry in order:
        if entry.endswith("/"):
            run(tool("mmd"), "-i", target, "::/" + entry.rstrip("/"), env=env)
        else:
            run(tool("mcopy"), "-m", "-i", target, stage_dir / entry, "::/" + entry, env=env)


def image(args):
    work, record, profile = staged(args.work)
    inputs = work / "inputs"
    kernel_build = bound_kernel(work, record, profile)
    epoch = record["source_date_epoch"]
    env = clean_env(epoch)
    pins = check_pins(profile, env=env)
    os.umask(0o022)
    out = pathlib.Path(args.out).resolve()
    out.mkdir(exist_ok=False)
    geometry, identity = profile["geometry"], profile["identity"]
    start, sectors = geometry["start_lba"], geometry["esp_sectors"]
    stage_dir, early = fat_stage(work, record, profile, out)
    for p in [stage_dir, *stage_dir.rglob("*"), early]:
        os.chmod(p, 0o755 if p.is_dir() else 0o644)
        os.utime(p, (epoch, epoch))
    modules = profile["grub"]["modules"]
    run(tool("grub-mkstandalone"), "-O", "x86_64-efi", "--fonts=", "--locales=", "--themes=",
        f"--install-modules={modules}", f"--modules={modules}",
        "-o", stage_dir / "EFI/BOOT/BOOTX64.EFI", f"boot/grub/grub.cfg={early}", env=env)
    os.utime(stage_dir / "EFI/BOOT/BOOTX64.EFI", (epoch, epoch))
    n = names(record["kernel_commit"], record["platform_commit"])
    disk = out / profile["image_name"].format(**n)
    with open(disk, "xb") as f:
        assert stat.S_ISREG(os.fstat(f.fileno()).st_mode)
        f.truncate(geometry["image_bytes"])
    prefix = identity["guid_prefix"]
    run(tool("sgdisk"), "--clear", f"--disk-guid={guid(prefix, record['kernel_commit'], record['platform_commit'], 1)}",
        f"--new=1:{start}:{start + sectors - 1}", "--typecode=1:ef00",
        f"--change-name=1:{identity['partition_name']}",
        f"--partition-guid=1:{guid(prefix, record['kernel_commit'], record['platform_commit'], 2)}", disk, env=env)
    run(tool("mkfs.vfat"), "--invariant", "-F", "32", "-s", "1", "-i", identity["fat_volume_id"], "-n", identity["fat_label"],
        "-h", str(start), f"--offset={start}", disk, str(sectors // 2), env=env)
    order = copy_order(stage_dir, profile)
    fat_copy(disk, start * 512, stage_dir, order, env)
    normalize_fat_dates(disk, start, epoch)
    run(tool("sgdisk"), "--verify", disk, env=env)
    raw_sha = sha(disk)
    compact = disk.with_name(disk.name + ".xz")
    # The compact copy's preset is part of the profile: the same raw image
    # under another preset is a different (valid) file.
    preset = profile.get("compact", {}).get("xz_preset", 6)
    compact_command = [tool("xz"), "-T1", f"-{preset}", "--check=crc64", "-k"]
    run(*compact_command, disk, env=env)
    (out / "SHA256SUMS").write_text(f"{raw_sha}  {disk.name}\n{sha(compact)}  {compact.name}\n")
    inventory = {str(p.relative_to(stage_dir)): {"sha256": sha(p), "bytes": p.stat().st_size}
                 for p in sorted(stage_dir.rglob("*")) if p.is_file()}
    (out / "FILE-MANIFEST.json").write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    tools = tools_used()
    packages = [f"{name}={version}" for name, version in sorted(package_versions(PACKAGES, env).items())]
    receipt = {"schema": "absd-media-receipt/1", "profile": record["profile"],
               "kernel_commit": record["kernel_commit"], "platform_commit": record["platform_commit"],
               "source_date_epoch": epoch, "image": {"name": disk.name, "bytes": disk.stat().st_size, "sha256": raw_sha},
               "compact": {"name": compact.name, "bytes": compact.stat().st_size, "sha256": sha(compact),
                           "command": " ".join(compact_command)},
               "profile_sha256": record["profile_sha256"],
               "profile_text": (PROFILES / f"{record['profile']}.toml").read_text(),
               "builder": builder_identity(), "copy_order": order,
               "guids": {"disk": guid(prefix, record["kernel_commit"], record["platform_commit"], 1),
                         "partition": guid(prefix, record["kernel_commit"], record["platform_commit"], 2)},
               "environment": env, "umask": "022",
               "mtools_system_config_sha256": sha("/etc/mtools.conf") if pathlib.Path("/etc/mtools.conf").is_file() else None,
               "pins_checked": pins, "kernel_build": kernel_build, "limits": LIMITS,
               "inputs": record["inputs"], "kernel_elf": sha(inputs / "kernel.elf"),
               "rustc_kernel": (inputs / "rustc.txt").read_text().strip(), "notices": record["notices"],
               "tools": tools, "packages": packages,
               "replay": [f"media.py stage --profile {record['profile']} --work WORK --kernel-commit {record['kernel_commit']} "
                          f"--platform-commit {record['platform_commit']} --platform-repo REPO --probe probe.elf "
                          "--probe-receipt RUNTIME-CORRESPONDENCE.json --input input.txt --expected expected.txt",
                          "media.py kernel --work WORK", "media.py image --work WORK --out NEW_DIR"],
               "dispositions": {"built": True, "offline_validated": False, "boot_tested": False,
                                "physical_qualification": False, "release": False}}
    (out / "MEDIA-RECEIPT.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    shutil.rmtree(stage_dir)
    early.unlink()
    print(f"MEDIA IMAGE {disk.name} sha256={raw_sha} compact={sha(compact)}", flush=True)


# -- offline validation ------------------------------------------------------------

PAIR_FILES = ("expected.txt", "input.txt", "kernel.elf", "probe.elf")
IDENTITY_FIELDS = ("profile", "profile_sha256", "kernel_commit", "platform_commit", "source_date_epoch")


def stage_identity(work, record, kernel_build):
    """What an image is bound to: the stage record's bytes, its pair,
    profile and epoch, and the kernel ELF its build record names."""
    identity = {field: record[field] for field in IDENTITY_FIELDS}
    identity.update(stage_sha256=sha(work / STAGE_RECORD), kernel_elf_sha256=kernel_build["elf_sha256"])
    return identity


def check_receipt_identity(receipt, record, kernel_build):
    for field in IDENTITY_FIELDS:
        if receipt.get(field) != record.get(field):
            raise Refused(f"receipt_mismatch {field}: receipt {receipt.get(field)!r}, stage {record.get(field)!r}")
    if (receipt.get("kernel_build") or {}).get("elf_sha256") != kernel_build["elf_sha256"]:
        raise Refused("receipt_mismatch the image was built from another kernel ELF than this stage's")


def check_pair_files(pair, inputs):
    """PAIR.JSON must name exactly the four runtime inputs, each at its
    staged digest; names are looked up in the fixed list, never joined."""
    files = pair.get("files")
    if not isinstance(files, dict) or sorted(files) != sorted(PAIR_FILES):
        raise Refused(f"pairing PAIR.JSON names {sorted(files) if isinstance(files, dict) else files!r}, "
                      f"not exactly {list(PAIR_FILES)}")
    for name in PAIR_FILES:
        entry = files[name]
        if not isinstance(entry, dict) or entry.get("sha256") != sha(confined(inputs, name)):
            raise Refused(f"pairing PAIR.JSON's {name} is not the staged input")


def validate(args):
    work, record, profile = staged(args.work)
    kernel_build = bound_kernel(work, record, profile)
    env = clean_env(record["source_date_epoch"])
    check_pins(profile, env=env)
    out = pathlib.Path(args.out).resolve()
    receipt = json.loads(confined(out, "MEDIA-RECEIPT.json").read_text())
    check_receipt_identity(receipt, record, kernel_build)
    disk = confined(out, receipt["image"]["name"])
    compact = confined(out, receipt["compact"]["name"])
    geometry = profile["geometry"]
    start, sectors = geometry["start_lba"], geometry["esp_sectors"]
    results = {}
    if disk.stat().st_size != geometry["image_bytes"] or disk.stat().st_size != receipt["image"]["bytes"]:
        raise Refused("image_changed the image is not the profile's size")
    if sha(disk) != receipt["image"]["sha256"]:
        raise Refused("image_changed the image differs from its receipt")
    if compact.stat().st_size != receipt["compact"]["bytes"] or sha(compact) != receipt["compact"]["sha256"]:
        raise Refused("compact_changed the .xz differs from its receipt")
    results["gpt"] = subprocess.run([tool("sgdisk"), "--verify", str(disk)], capture_output=True, text=True,
                                    env=env).stdout
    if "No problems found" not in results["gpt"]:
        raise Refused("gpt_invalid " + results["gpt"][-300:])
    # The partition the ESP is read from is the verified table's entry 1,
    # compared field by field with the profile and the pair's GUIDs.
    info = subprocess.run([tool("sgdisk"), "-i", "1", str(disk)], capture_output=True, text=True, env=env).stdout
    table = subprocess.run([tool("sgdisk"), "-p", str(disk)], capture_output=True, text=True, env=env).stdout
    def field(text, label):
        found = [line.split(":", 1)[1].strip() for line in text.splitlines() if line.startswith(label)]
        return found[0].split()[0] if found else None
    kc, pc, prefix = record["kernel_commit"], record["platform_commit"], profile["identity"]["guid_prefix"]
    layout = {"first": field(info, "First sector"), "last": field(info, "Last sector"),
              "type": field(info, "Partition GUID code"), "partition_guid": field(info, "Partition unique GUID"),
              "disk_guid": field(table, "Disk identifier (GUID)")}
    wanted = {"first": str(start), "last": str(start + sectors - 1), "type": "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
              "partition_guid": guid(prefix, kc, pc, 2).upper(), "disk_guid": guid(prefix, kc, pc, 1).upper()}
    if layout != wanted:
        raise Refused(f"layout_mismatch {layout} != {wanted}")
    results["layout"] = layout
    scratch = out / "validate"
    scratch.mkdir(exist_ok=False)
    esp = scratch / "esp.fat"
    copy_exact(disk, esp, int(layout["first"]) * 512, (int(layout["last"]) - int(layout["first"]) + 1) * 512)
    fsck = subprocess.run([tool("fsck.fat"), "-n", str(esp)], capture_output=True, text=True, env=env)
    results["fat"] = fsck.stdout + fsck.stderr
    if fsck.returncode != 0:
        raise Refused("fat_invalid " + results["fat"][-300:])
    extracted = scratch / "extracted"
    extracted.mkdir()
    run(tool("mcopy"), "-s", "-n", "-i", esp, "::/*", extracted, env=env)
    manifest = json.loads(confined(out, "FILE-MANIFEST.json").read_text())
    found = {str(p.relative_to(extracted)): sha(p) for p in sorted(extracted.rglob("*")) if p.is_file()}
    expected = {k: v["sha256"] for k, v in manifest.items()}
    if found != expected:
        raise Refused(f"fat_contents differ: {sorted(set(found.items()) ^ set(expected.items()))[:6]}")
    inputs = work / "inputs"
    staged_files = {"BOOT/KERNEL.ELF": inputs / "kernel.elf", "RUNTIME/PROBE.ELF": inputs / "probe.elf",
                    "RUNTIME/INPUT.TXT": inputs / "input.txt", "RUNTIME/EXPECT.TXT": inputs / "expected.txt"}
    for name, source in staged_files.items():
        if found.get(name) != sha(source):
            raise Refused(f"pairing {name} is not the staged {source.name}")
    for name, entry in record["notices"].items():
        if found.get(f"NOTICES/{name}") != entry["sha256"]:
            raise Refused(f"pairing NOTICES/{name} is not the staged notice")
    pair = json.loads(confined(extracted, "PAIR.JSON").read_text())
    if (pair.get("kernel_source"), pair.get("platform_source")) != (record["kernel_commit"], record["platform_commit"]):
        raise Refused("pairing PAIR.JSON names another pair")
    check_pair_files(pair, inputs)
    run(tool("grub-file"), "--is-x86-multiboot2", extracted / "BOOT/KERNEL.ELF", env=env)
    raw = hashlib.sha256()
    try:
        with lzma.open(compact) as stream:
            for block in iter(lambda: stream.read(1 << 20), b""):
                raw.update(block)
    except (lzma.LZMAError, EOFError) as error:
        raise Refused(f"compact_mismatch the .xz does not decompress: {error}") from None
    if raw.hexdigest() != receipt["image"]["sha256"]:
        raise Refused("compact_mismatch the .xz does not decompress to the image")
    results["files_verified"] = len(found)
    results["pair"] = [record["kernel_commit"], record["platform_commit"]]
    results["image_sha256"] = receipt["image"]["sha256"]
    results["compact_sha256"] = receipt["compact"]["sha256"]
    results["identity"] = stage_identity(work, record, kernel_build)
    results["environment"] = env
    results["tools"] = tools_used()
    shutil.rmtree(scratch)
    (out / "VALIDATION.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    print(f"MEDIA VALIDATED files={len(found)} gpt=ok fat=ok compact=ok pair=ok", flush=True)


# -- bounded UEFI boots ------------------------------------------------------------

OVMF_CODE = pathlib.Path("/usr/share/OVMF/OVMF_CODE_4M.fd")
OVMF_VARS = pathlib.Path("/usr/share/OVMF/OVMF_VARS_4M.fd")


def boot(args):
    """S4's three bounded boots of the exact image, in TCG: the survey with a
    local NVMe fixture, the RAM runtime with USB only, and the RAM runtime
    with the fixture. The image and fixture must be unchanged afterwards."""
    work, record, profile = staged(args.work)
    out = pathlib.Path(args.out).resolve()
    results_dir = pathlib.Path(args.results).resolve()
    results_dir.mkdir(exist_ok=False)
    kernel_build = bound_kernel(work, record, profile)
    receipt = json.loads(confined(out, "MEDIA-RECEIPT.json").read_text())
    check_receipt_identity(receipt, record, kernel_build)
    disk = confined(out, receipt["image"]["name"])
    try:
        validation = json.loads(confined(out, "VALIDATION.json").read_text())
    except Refused:
        raise Refused("not_validated (run `media.py validate` first)") from None
    if validation.get("identity") != stage_identity(work, record, kernel_build):
        raise Refused("not_validated the validation is for another stage, pair, profile or kernel build")
    if validation.get("pair") != [record["kernel_commit"], record["platform_commit"]]:
        raise Refused("not_validated the validation names another pair")
    before = sha(disk)
    if not (before == receipt["image"]["sha256"] == validation.get("image_sha256")):
        raise Refused("not_validated the image is not the one its receipt and validation name")
    env = clean_env(record["source_date_epoch"])
    qemu = tool("qemu-system-x86_64")
    sentinel = results_dir / "nvme-local-fixture.img"
    with open(sentinel, "xb") as f:
        f.truncate(16 * 1024 * 1024)
        f.write(b"ABSD MEDIA LOCAL NVME READ-ONLY FIXTURE\n".ljust(512, b"\xa5"))
    sentinel_before = sha(sentinel)
    import importlib.util
    spec = importlib.util.spec_from_file_location("media_boot", ROOT / "scripts" / "media_boot.py")
    mb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mb)
    checker = work / "kernel/scripts/check-external-output.py"
    expected = work / "inputs/expected.txt"
    for name, mode, fixture in (("survey", "survey", sentinel), ("runtime", "runtime", None),
                                ("runtime-nvme", "runtime", sentinel)):
        try:
            mb.boot(disk, mode, results_dir / name, fixture, OVMF_CODE, OVMF_VARS, checker, expected,
                    qemu=qemu, env=env)
        except (mb.BootFailed, subprocess.CalledProcessError) as error:
            raise Refused(f"boot_failed {name}: {error}") from None
    if sha(disk) != before:
        raise Refused("image_changed during the boots")
    if sha(sentinel) != sentinel_before:
        raise Refused("fixture_changed a boot wrote the NVMe fixture")
    result = {"passed": True, "image_sha256": before, "unchanged_image": True,
              "nvme_fixture_sha256": sentinel_before, "unchanged_nvme_fixture": True,
              "boots": ["survey", "runtime with USB only, no block backend", "runtime plus read-only NVMe"],
              "firmware_code_sha256": sha(OVMF_CODE), "physical_qualification": False,
              "identity": validation["identity"], "environment": env, "tools": tools_used()}
    (results_dir / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"MEDIA BOOTED {json.dumps(result)}", flush=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    s = sub.add_parser("stage")
    s.add_argument("--profile", required=True)
    s.add_argument("--work", required=True)
    s.add_argument("--kernel-commit", required=True)
    s.add_argument("--platform-commit", required=True)
    s.add_argument("--platform-repo", required=True)
    s.add_argument("--probe", required=True)
    s.add_argument("--probe-receipt", required=True)
    s.add_argument("--input", required=True)
    s.add_argument("--expected", required=True)
    for name in ("kernel", "image", "validate", "boot"):
        p = sub.add_parser(name)
        p.add_argument("--work", required=True)
        if name in ("image", "validate", "boot"):
            p.add_argument("--out", required=True)
        if name == "boot":
            p.add_argument("--results", required=True)
    o = sub.add_parser("operator-image")
    for name in ("--profile", "--platform-tree", "--kernel-run", "--kernel-commit", "--platform-commit",
                 "--authorized-keys", "--out"):
        o.add_argument(name, required=True)
    o.add_argument("--etc")
    o.add_argument("--release-id", default="dev")
    v = sub.add_parser("operator-validate")
    for name in ("--profile", "--platform-tree", "--kernel-run", "--out"):
        v.add_argument(name, required=True)
    c = sub.add_parser("operator-compare")
    c.add_argument("--out", required=True)
    c.add_argument("--reference", required=True)
    b = sub.add_parser("operator-boot")
    for name in ("--profile", "--platform-tree", "--kernel-run"):
        b.add_argument(name, required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--results", required=True)
    b.add_argument("--login-key")
    args = ap.parse_args(argv)
    # media_operator reaches this module as `media`; run as a script, that
    # must be this module, not a second copy with its own Refused.
    sys.modules.setdefault("media", sys.modules[__name__])
    import media_operator
    try:
        {"stage": stage, "kernel": kernel, "image": image, "validate": validate, "boot": boot,
         "operator-image": media_operator.operator_image, "operator-validate": media_operator.operator_validate,
         "operator-compare": media_operator.operator_compare,
         "operator-boot": media_operator.operator_boot}[args.command](args)
        return 0
    except Refused as error:
        print(f"MEDIA REFUSED {error}", flush=True)
        return 2


if __name__ == "__main__":
    sys.exit(main())
