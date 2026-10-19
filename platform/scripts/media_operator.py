"""The vm-operator profile of scripts/media.py: the operator deployment U1-b
ran (a boot ISO plus a separate writable ABSD filesystem disk and MANIFEST,
scripts/operator_image.py), built reproducibly for one frozen pair.

    media.py operator-image    --profile vm-operator --platform-tree P --kernel-run K
                               --kernel-commit KC --platform-commit PC
                               --authorized-keys KEYS [--etc DIR] [--release-id ID] --out NEW_DIR
    media.py operator-validate --profile vm-operator --platform-tree P --kernel-run K --out DIR
    media.py operator-boot     --out DIR --results NEW_DIR [--login-key PRIVATE_KEY]

P is the platform checkout at PC, already built (its commands, ports and
ELFs: scripts/prepare-and-build.sh, scripts/build-ports.sh); K is a clean
disposable kernel checkout at KC (never the canonical repository, never a
link). `operator-image` runs the platform's own operator_image.py (whose
importer boots write the disk, each file checked in the guest and read
back by the host's reader), then rebuilds the ISO from the kernel's served
boot tree with the deterministic GRUB recipe below and rewrites MANIFEST's
`iso` line.

Why the ISO is rebuilt: grub-mkrescue (GRUB 2.12) stamps the wall clock
into the volume, the file dates, the GRUB search UUID and the hybrid GPT;
copies every GRUB translation the host has (language packs add files);
and its mformat writes uninitialised process memory into the EFI FAT
image's free space and a time-derived serial into its boot sector. The
recipe: address randomisation off and the libc clock frozen at the pair's
epoch (setarch -R, faketime), SOURCE_DATE_EPOCH for xorriso's GUIDs, fixed
file dates, no locales, then the EFI image normalised in place (serial
derived from the pair, free clusters and slack zeroed). The ISO is built
twice and must come out identical.

What this does not make reproducible: the platform tree's own outputs.
They are inputs here, recorded by digest in MANIFEST; see the receipt's
`host_inputs` for the one known host dependency (uucore embeds the
locales of every uu_* crate unpacked in the build host's Cargo registry).
"""

import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import time

from e1000_rx import wait_rx_setup, RxSetupFailed
from served_ram import served_qemu

ISO = "absd-operator.iso"
IMAGE = "absd-operator.img"
MANIFEST = "MANIFEST"
RECEIPT = "MEDIA-RECEIPT.json"
VALIDATION = "VALIDATION.json"
COMMIT = re.compile(r"[0-9a-f]{40}")
ARTIFACTS = (ISO, IMAGE, MANIFEST)
KERNEL_OUTPUT = "build/external/target/debug/absd-kernel"
# The platform tree's ELFs the build embeds: the served worker and file
# server in the ISO's kernel, the importer in the boots that write the disk.
PLATFORM_ELFS = ("sshd.elf", "absd-fsd.elf", "fixture-import.elf")
GRUB_MODULES = ("/usr/lib/grub/i386-pc", "/usr/lib/grub/x86_64-efi")


def _media():
    import media  # the caller's module; imported lazily to avoid a cycle
    return media


def load_operator_profile(name):
    m = _media()
    profile = m.load_profile(name)
    if profile.get("kind") != "operator":
        raise m.Refused(f"profile_kind {name} is not an operator profile")
    return profile


def operator_module(platform_tree):
    """The platform tree's own operator_image.py (the builder U1-b used)."""
    path = pathlib.Path(platform_tree) / "scripts" / "operator_image.py"
    spec = importlib.util.spec_from_file_location("operator_image_" + hashlib.sha256(str(path).encode()).hexdigest()[:8],
                                                  path)
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(path.parent))
    return module


def checkout_at(path, commit, what):
    m = _media()
    path = pathlib.Path(path)
    if path.is_symlink() or not (path / ".git").exists():
        raise m.Refused(f"{what}_checkout_missing {path} (a checkout at {commit[:12]}, not a link)")
    head = m.git(path, "rev-parse", "HEAD").decode().strip()
    if head != commit:
        raise m.Refused(f"pair_mismatch {what} checkout is at {head[:12]}, not {commit[:12]}")
    if m.git(path, "status", "--porcelain", "--untracked-files=no").strip():
        raise m.Refused(f"{what}_checkout_dirty {path} has modified tracked files")
    return head


def epoch_of(platform_tree, platform_commit):
    return int(_media().git(platform_tree, "log", "-1", "--format=%ct", platform_commit).decode())


def iso_tree_expected(kernel_run, profile):
    """The kernel's served-boot ISO tree (`make durable-iso DURABLE_STEP=0`),
    which operator_image.build leaves in the kernel checkout."""
    m = _media()
    tree = pathlib.Path(kernel_run) / "build" / "durable" / "iso-0"
    found = sorted(str(p.relative_to(tree)) for p in tree.rglob("*") if p.is_file() or p.is_symlink())
    if found != sorted(profile["expect"]["iso_files"]):
        raise m.Refused(f"iso_tree_unexpected {tree}: {found}")
    for p in tree.rglob("*"):
        if p.is_symlink():
            raise m.Refused(f"iso_tree_unexpected {p} is a link")
    cfg = (tree / "boot/grub/grub.cfg").read_text()
    if profile["expect"]["grub_entry"] not in cfg:
        raise m.Refused(f"iso_tree_unexpected grub.cfg lacks {profile['expect']['grub_entry']!r}")
    return tree


def grub_inventory():
    """Every file of the GRUB module directories grub-mkrescue copies from,
    by digest, and one digest over the whole inventory."""
    files = {}
    for directory in GRUB_MODULES:
        for p in sorted(pathlib.Path(directory).iterdir()):
            if p.is_file():
                files[f"{pathlib.Path(directory).name}/{p.name}"] = _media().sha(p)
    digest = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    return {"sha256": digest, "files": len(files)}, files


def expected_grub(profile, modules):
    """The exact /boot/grub file set the profile expects on the ISO: every
    host module file not in `not_copied` (at the host's digest), plus the
    generated files (any bytes) and the font."""
    m = _media()
    grub = profile["iso"]["grub"]
    unknown = sorted(set(grub["not_copied"]) - set(modules))
    if unknown:
        raise m.Refused(f"grub_inventory_unexpected the host lacks files the profile names: {unknown[:5]}")
    copied = {key: digest for key, digest in modules.items() if key not in grub["not_copied"]}
    return copied, set(grub["generated"])


def check_iso_grub(grub_dir, profile, modules, font_sha256):
    """Refuses unless `grub_dir` (the ISO's /boot/grub, extracted) holds
    exactly the expected entries: the top-level names, the copied modules
    at the host's digests, the generated files, the host font, and empty
    roms/ and locale/. Returns the counts checked."""
    m = _media()
    grub_dir = pathlib.Path(grub_dir)
    grub = profile["iso"]["grub"]
    top = sorted(p.name for p in grub_dir.iterdir())
    if top != sorted(grub["top_level"]):
        raise m.Refused(f"iso_grub_unexpected /boot/grub holds {top}, not {sorted(grub['top_level'])}")
    copied, generated = expected_grub(profile, modules)
    found = {}
    for platform_dir in ("i386-pc", "x86_64-efi"):
        for p in (grub_dir / platform_dir).iterdir():
            if p.is_symlink() or not p.is_file():
                raise m.Refused(f"iso_grub_unexpected {platform_dir}/{p.name} is not a regular file")
            found[f"{platform_dir}/{p.name}"] = m.sha(p)
    extra = sorted(set(found) - set(copied) - generated)
    missing = sorted((set(copied) | generated) - set(found))
    changed = sorted(k for k in copied if k in found and found[k] != copied[k])
    if extra or missing or changed:
        raise m.Refused(f"iso_grub_mismatch extra={extra[:5]} missing={missing[:5]} changed={changed[:5]}")
    fonts = sorted(p.name for p in (grub_dir / "fonts").iterdir())
    if fonts != ["unicode.pf2"] or m.sha(grub_dir / "fonts/unicode.pf2") != font_sha256:
        raise m.Refused(f"iso_grub_mismatch fonts/ holds {fonts}, not the host's unicode.pf2")
    for empty in ("roms", "locale"):
        if any((grub_dir / empty).iterdir()):
            raise m.Refused(f"iso_grub_mismatch {empty}/ is not empty")
    return {"modules": len(copied), "generated": len(generated), "font": 1}


def operator_binding(platform, kernel, profile):
    """What a build is bound to, read from the trees themselves: the kernel
    checkout's tree, its served-boot ISO tree (exactly the profile's files)
    and build output (which must be the ISO's kernel), the platform tree
    and the ELFs it lends the build, and the GRUB module inventory. Every
    file is mandatory."""
    m = _media()
    tree = iso_tree_expected(kernel, profile)
    iso_tree = {name: m.sha(m.confined(tree / pathlib.Path(name).parent, pathlib.Path(name).name))
                for name in profile["expect"]["iso_files"]}
    output = pathlib.Path(kernel) / KERNEL_OUTPUT
    if output.is_symlink() or not output.is_file():
        raise m.Refused(f"build_unbound {output} is missing (the kernel checkout's build output)")
    if m.sha(output) != iso_tree["boot/absd-kernel"]:
        raise m.Refused("build_unbound the kernel checkout's build output is not the served-boot kernel")
    elfs = {name: m.sha(m.confined(platform, name)) for name in PLATFORM_ELFS}
    inventory, modules = grub_inventory()
    copied, _ = expected_grub(profile, modules)
    inventory = dict(inventory, iso_expected_sha256=hashlib.sha256(json.dumps(copied, sort_keys=True).encode())
                     .hexdigest(), iso_expected_files=len(copied),
                     font_sha256=m.sha(profile["iso"]["grub"]["font"]))
    return {"kernel_tree": m.git(kernel, "rev-parse", "HEAD^{tree}").decode().strip(),
            "platform_tree": m.git(platform, "rev-parse", "HEAD^{tree}").decode().strip(),
            "iso_tree": iso_tree, "kernel_output_sha256": m.sha(output), "platform_elfs": elfs,
            "grub_inventory": inventory, "remap_root": profile["kernel"]["remap_root"]}


def bound_operator_build(platform, kernel, profile, receipt):
    """Refuses unless the trees still are what the receipt's build record
    names (the operator counterpart of media.bound_kernel)."""
    m = _media()
    checkout_at(platform, receipt["platform_commit"], "platform")
    checkout_at(kernel, receipt["kernel_commit"], "kernel")
    current = operator_binding(platform, kernel, profile)
    recorded = receipt.get("binding")
    if recorded != current:
        changed = sorted(k for k in current if (recorded or {}).get(k) != current[k])
        raise m.Refused(f"build_unbound the trees are not the build's: {changed}")
    return current


def artifact_paths(out, receipt):
    """The three outputs, by their fixed names only: the receipt must name
    exactly them, each entry under its own name."""
    m = _media()
    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, dict) or sorted(artifacts) != sorted(ARTIFACTS) or any(
            not isinstance(artifacts[k], dict) or artifacts[k].get("name") != k for k in ARTIFACTS):
        raise m.Refused(f"receipt_mismatch artifacts must be exactly {list(ARTIFACTS)} under their own names")
    return {name: m.confined(out, name) for name in ARTIFACTS}


def check_iso_tree_names(receipt, profile):
    names = sorted((receipt.get("binding") or {}).get("iso_tree") or {})
    if names != sorted(profile["expect"]["iso_files"]):
        raise _media().Refused(f"receipt_mismatch ISO tree {names} is not exactly the profile's")


def operator_identity(receipt):
    """What a validation and a boot must agree on."""
    return {"profile": receipt["profile"], "profile_sha256": receipt["profile_sha256"],
            "kernel_commit": receipt["kernel_commit"], "platform_commit": receipt["platform_commit"],
            "release_id": receipt["release_id"], "source_date_epoch": receipt["source_date_epoch"],
            "artifacts": {k: receipt["artifacts"][k]["sha256"] for k in ARTIFACTS},
            "binding_sha256": hashlib.sha256(json.dumps(receipt["binding"], sort_keys=True).encode()).hexdigest(),
            "fs_id": receipt["fs_id"]}


def operator_env(work, epoch, profile, kernel, release_id):
    """The build's environment: the pinned toolchain, a fresh HOME and a
    fresh, empty, offline Cargo home inside the build's scratch (no caller
    configuration), the kernel checkout's path remapped to the profile's
    root, one Cargo job."""
    m = _media()
    cargo_home = m.fresh_dir(pathlib.Path(work) / "cargo-home")
    return m.rust_env(work, epoch, profile, CARGO_HOME=cargo_home, CARGO_NET_OFFLINE="true", CARGO_BUILD_JOBS="1",
                      RUSTFLAGS=f"--remap-path-prefix={kernel}={profile['kernel']['remap_root']}",
                      ABSD_RELEASE_ID=release_id)


def efi_serial(prefix, kernel_commit, platform_commit):
    return int(prefix + platform_commit[:2] + kernel_commit[:2], 16)


def normalize_efi(iso, efi_lba, efi_bytes, serial):
    """The EFI FAT image inside the ISO: the volume serial set to `serial`,
    every free cluster and the slack after the last cluster zeroed, so the
    uninitialised memory mformat leaves there cannot reach the bytes. Only
    a FAT12/16 image (what grub-mkrescue makes) is accepted."""
    m = _media()
    with open(iso, "r+b") as f:
        f.seek(efi_lba * 2048)
        fat = bytearray(f.read(efi_bytes))
        if len(fat) != efi_bytes or fat[510:512] != b"\x55\xaa":
            raise m.Refused("efi_image_unexpected no boot sector signature")
        bps, spc, reserved, nfats, root_entries, total16, _, fatsz = struct.unpack_from("<HBHBHHBH", fat, 11)
        total = total16 or struct.unpack_from("<I", fat, 32)[0]
        if bps != 512 or not spc or not fatsz or fat[38] != 0x29 or total * bps > efi_bytes:
            raise m.Refused("efi_image_unexpected not a FAT12/16 image with an extended boot record")
        root_sectors = (root_entries * 32 + bps - 1) // bps
        data_start = reserved + nfats * fatsz + root_sectors
        clusters = (total - data_start) // spc
        fat12 = clusters < 4085
        table = fat[reserved * bps:(reserved + fatsz) * bps]
        for n in range(2, clusters + 2):
            if fat12:
                v = struct.unpack_from("<H", table, n * 3 // 2)[0]
                v = v >> 4 if n & 1 else v & 0xFFF
            else:
                v = struct.unpack_from("<H", table, n * 2)[0]
            if v == 0:
                start = (data_start + (n - 2) * spc) * bps
                fat[start:start + spc * bps] = bytes(spc * bps)
        end = (data_start + clusters * spc) * bps
        fat[end:] = bytes(len(fat) - end)
        struct.pack_into("<I", fat, 39, serial)
        f.seek(efi_lba * 2048)
        f.write(fat)


def iso_layout(iso):
    """{ISO path: (lba, bytes)} from xorriso's report."""
    m = _media()
    out = subprocess.run([m.tool("xorriso"), "-indev", str(iso), "-find", "/", "-exec", "report_lba"],
                         capture_output=True, text=True, check=True, env=m.clean_env(0)).stdout
    layout = {}
    for line in out.splitlines():
        hit = re.match(r"File data lba:\s*\d+\s*,\s*(\d+)\s*,\s*\d+\s*,\s*(\d+)\s*,\s*'(.*)'$", line)
        if hit:
            layout[hit.group(3)] = (int(hit.group(1)), int(hit.group(2)))
    return layout


def build_iso(tree, out_iso, epoch, profile, kernel_commit, platform_commit, scratch):
    """One deterministic ISO from `tree` (copied first, so the source path
    and its dates cannot matter). Returns the command for the receipt."""
    m = _media()
    stamp = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    copy = pathlib.Path(scratch) / "iso-tree"
    shutil.rmtree(copy, ignore_errors=True)
    shutil.copytree(tree, copy, symlinks=False)
    for p in sorted(copy.rglob("*")):
        os.chmod(p, 0o755 if p.is_dir() else 0o644)
        os.utime(p, (epoch, epoch))
    command = [m.tool("setarch"), "x86_64", "-R", m.tool("faketime"), stamp.strftime("%Y-%m-%d %H:%M:%S"),
               m.tool("grub-mkrescue"), f"--locales={profile['iso']['locales']}", "-o", str(out_iso), str(copy),
               "--set_all_file_dates", stamp.strftime("%Y%m%d%H%M%S00")]
    result = subprocess.run(command, env=m.clean_env(epoch), cwd="/", capture_output=True, text=True)
    if result.returncode:
        raise m.Refused(f"iso_build_failed {result.stderr[-400:]}")
    layout = iso_layout(out_iso)
    if "/efi.img" not in layout:
        raise m.Refused("efi_image_unexpected the ISO has no /efi.img")
    lba, size = layout["/efi.img"]
    normalize_efi(out_iso, lba, size, efi_serial(profile["iso"]["efi_serial_prefix"], kernel_commit, platform_commit))
    shown = [c if c != str(copy) else "<tree>" for c in command]
    return [c if c != str(out_iso) else "<iso>" for c in shown]


def registry_neighbours():
    """The uu_* crates unpacked in this host's Cargo registry: uucore's
    build script embeds the locales of every one of them into each uutils
    port, so the ports' bytes depend on this list (recorded, not fixed)."""
    home = pathlib.Path(os.environ.get("CARGO_HOME", pathlib.Path.home() / ".cargo"))
    found = []
    for index in sorted((home / "registry" / "src").glob("*")):
        found += sorted(p.name for p in index.iterdir() if p.name.startswith("uu_"))
    return found


def operator_image(args):
    m = _media()
    profile = load_operator_profile(args.profile)
    for name, value in (("kernel", args.kernel_commit), ("platform", args.platform_commit)):
        if not COMMIT.fullmatch(value):
            raise m.Refused(f"pair_invalid {name} commit {value!r} (40 hex digits)")
    platform = pathlib.Path(args.platform_tree).resolve()
    kernel = pathlib.Path(args.kernel_run)
    checkout_at(platform, args.platform_commit, "platform")
    checkout_at(kernel, args.kernel_commit, "kernel")
    kernel = kernel.resolve()
    pins = m.check_pins(profile, env=m.clean_env(0))
    keys = pathlib.Path(args.authorized_keys).resolve()
    epoch = epoch_of(platform, args.platform_commit)
    os.umask(0o022)
    out = pathlib.Path(args.out).resolve()
    out.mkdir(exist_ok=False)
    # The platform builder compiles the kernel's served boot (make
    # durable-iso) and runs QEMU for the importer boots, all in one recorded
    # environment (operator_env).
    work = out / ".build-home"
    work.mkdir()
    env = operator_env(work, epoch, profile, kernel, args.release_id)
    for name in PLATFORM_ELFS:
        m.confined(platform, name)
    for name in ("make", "qemu-system-x86_64", "grub-mkrescue", "xorriso"):
        m.tool(name)
    command = ["/usr/bin/python3", "-I", "-B", "-X", f"pycache_prefix={work / 'python-cache'}", str(platform / "scripts" / "operator_image.py"), "build", "--kernel", str(kernel),
               "--authorized-keys", str(keys), "--release-id", args.release_id,
               "--qemu", f"{m.tool('qemu-system-x86_64')} -cpu max,vendor=GenuineIntel,+rdrand"]
    if args.etc:
        command += ["--etc", str(pathlib.Path(args.etc).resolve())]
    with open(out / "operator-image.log", "wb") as log:
        built = subprocess.run(command + [str(out)], env=env, cwd=str(platform), stdout=log, stderr=subprocess.STDOUT)
    if built.returncode:
        raise m.Refused(f"operator_image_failed status {built.returncode} (see {out / 'operator-image.log'})")
    tree = iso_tree_expected(kernel, profile)
    binding = operator_binding(platform, kernel, profile)
    nondeterministic = m.sha(out / ISO)
    with tempfile.TemporaryDirectory(prefix="media-iso-", dir=out) as scratch:
        first, second = pathlib.Path(scratch) / "a.iso", pathlib.Path(scratch) / "b.iso"
        iso_command = build_iso(tree, first, epoch, profile, args.kernel_commit, args.platform_commit, scratch)
        build_iso(tree, second, epoch, profile, args.kernel_commit, args.platform_commit, scratch)
        if m.sha(first) != m.sha(second):
            raise m.Refused("iso_not_reproducible two builds of the same tree differ on this host")
        os.replace(first, out / ISO)
    shutil.rmtree(work)
    iso_sha = m.sha(out / ISO)
    lines = (out / MANIFEST).read_text().splitlines()
    if not lines or not any(line.startswith("iso ") for line in lines):
        raise m.Refused("manifest_unexpected no iso line")
    (out / MANIFEST).write_text("\n".join(f"iso {iso_sha}" if line.startswith("iso ") else line
                                          for line in lines) + "\n")
    artifacts = {name: {"name": name, "sha256": m.sha(out / name), "bytes": (out / name).stat().st_size}
                 for name in (ISO, IMAGE, MANIFEST)}
    receipt = {
        "profile": args.profile, "profile_sha256": m.profile_sha(args.profile),
        "profile_text": (m.PROFILES / f"{args.profile}.toml").read_text(),
        "kernel_commit": args.kernel_commit, "platform_commit": args.platform_commit,
        "release_id": args.release_id, "source_date_epoch": epoch,
        "artifacts": artifacts,
        "binding": binding,
        "iso": {"command": iso_command, "replaced_grub_mkrescue_iso_sha256": nondeterministic,
                "efi_serial": f"{efi_serial(profile['iso']['efi_serial_prefix'], args.kernel_commit, args.platform_commit):08x}"},
        "disk": {"writer": "operator_image.py importer boots under the pinned kernel",
                 "authorized_keys_sha256": m.sha(keys),
                 "etc": {p.name: m.sha(p) for p in sorted(pathlib.Path(args.etc).iterdir())} if args.etc else None},
        "fs_id": f"{fs_id_of(out / IMAGE):016x}",
        "host_inputs": {"uucore_registry_neighbours": registry_neighbours(),
                        "note": "the uutils ports in the platform tree embed the locales of these crates; the "
                                "ports are inputs here (MANIFEST digests), built by the platform, not this profile"},
        "environment": env, "umask": "022", "tools": m.tools_used(),
        "pins_checked": pins, "builder": m.builder_identity(), "toolchain": m.rust_toolchain(profile)[1],
        "limits": m.LIMITS + [
            "the platform tree's commands, ports and ELFs are inputs, recorded by digest in MANIFEST (and the three "
            "ELFs the build embeds in the binding), not rebuilt",
            "GRUB's files on the ISO are checked against the host's module directories and their inventory digest; "
            "GRUB's own tools are pinned by package version only",
            "the disk's fs_id is chosen by rdrand in the guest when it formats, so two builds' disks are equal "
            "only apart from it (operator-compare checks that)"],
    }
    (out / RECEIPT).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(f"MEDIA OPERATOR BUILT iso={iso_sha} img={artifacts[IMAGE]['sha256']} "
          f"manifest={artifacts[MANIFEST]['sha256']}", flush=True)


def manifest_parts(text):
    head, files = {}, {}
    for line in text.splitlines():
        kind, _, rest = line.partition(" ")
        if kind == "file":
            digest, _, path = rest.partition(" ")
            files[path] = digest
        else:
            head[kind] = rest
    return head, files


def remove_tree(path):
    """Removes a scratch tree xorriso extracted (its directories are
    read-only); a link is refused, not followed."""
    path = pathlib.Path(path)
    if path.is_symlink():
        raise _media().Refused(f"path_refused {path} is a link")
    if not path.exists():
        return
    for root, dirs, _ in os.walk(path):
        for d in dirs:
            full = pathlib.Path(root) / d
            if not full.is_symlink():
                os.chmod(full, 0o700)
    os.chmod(path, 0o700)
    shutil.rmtree(path)


def operator_validate(args):
    m = _media()
    profile = load_operator_profile(args.profile)
    env = m.clean_env(0)
    pins = m.check_pins(profile, env=env)
    out = pathlib.Path(args.out).resolve()
    receipt = json.loads(m.confined(out, RECEIPT).read_text())
    if receipt.get("profile") != args.profile or receipt.get("profile_sha256") != m.profile_sha(args.profile):
        raise m.Refused("receipt_mismatch the receipt is for another profile or profile text")
    paths = artifact_paths(out, receipt)
    check_iso_tree_names(receipt, profile)
    platform = pathlib.Path(args.platform_tree).resolve()
    kernel = pathlib.Path(args.kernel_run)
    binding = bound_operator_build(platform, kernel, profile, receipt)
    results = {"pins_checked": pins}
    for name, path in paths.items():
        entry = receipt["artifacts"][name]
        if path.stat().st_size != entry["bytes"] or m.sha(path) != entry["sha256"]:
            raise m.Refused(f"artifact_changed {name} differs from its receipt")
    iso, image, manifest = paths[ISO], paths[IMAGE], paths[MANIFEST]
    scratch = out / "validate"
    remove_tree(scratch)
    scratch.mkdir()
    # The ISO: extracted whole. Exactly the profile's kernel and grub.cfg at
    # the bound digests, GRUB's files exactly the host's modules, both boot
    # paths present, the volume dated at the pair's epoch.
    extracted = scratch / "iso"
    done = subprocess.run([m.tool("xorriso"), "-osirrox", "on", "-indev", str(iso), "-extract", "/", str(extracted)],
                          capture_output=True, text=True, env=env)
    if done.returncode:
        raise m.Refused(f"iso_unreadable xorriso status {done.returncode}: {done.stderr.strip()[-200:]}")
    for name, digest in binding["iso_tree"].items():
        if m.sha(extracted / name) != digest:
            raise m.Refused(f"iso_content {name} is not the bound served-boot file")
    _, modules = grub_inventory()
    results["grub_checked"] = check_iso_grub(extracted / "boot/grub", profile, modules,
                                             binding["grub_inventory"]["font_sha256"])
    cfg = (extracted / "boot/grub/grub.cfg").read_text()
    if profile["expect"]["grub_entry"] not in cfg:
        raise m.Refused("iso_content grub.cfg lacks the served-boot entry")
    torito = subprocess.run([m.tool("xorriso"), "-indev", str(iso), "-report_el_torito", "plain"],
                            capture_output=True, text=True, env=env).stdout
    if not re.search(r"El Torito boot img :\s+1\s+BIOS", torito) or not re.search(r"El Torito boot img :\s+2\s+UEFI",
                                                                                 torito):
        raise m.Refused("iso_boot both a BIOS and a UEFI El Torito image are required")
    layout = iso_layout(iso)
    stamp = datetime.datetime.fromtimestamp(receipt["source_date_epoch"], datetime.timezone.utc)
    if f"/.disk/{stamp.strftime('%Y-%m-%d-%H-%M-%S')}-00.uuid" not in layout:
        raise m.Refused("iso_date the GRUB volume UUID is not the pair's epoch")
    if any(path.startswith("/boot/grub/locale/") for path in layout):
        raise m.Refused("iso_content host GRUB translations are on the ISO")
    lba, size = layout["/efi.img"]
    efi = scratch / "efi.img"
    m.copy_exact(iso, efi, lba * 2048, size)
    fsck = subprocess.run([m.tool("fsck.fat"), "-n", str(efi)], capture_output=True, text=True, env=env)
    if fsck.returncode:
        raise m.Refused("efi_image_invalid " + fsck.stdout[-300:])
    results["efi_fsck"] = fsck.stdout.strip().splitlines()[-1:]
    # MANIFEST: the pair, the release, this ISO, and exactly the files the
    # host's independent reader finds on the disk, each at its digest.
    head, files = manifest_parts(manifest.read_text())
    wanted = {"platform": receipt["platform_commit"], "kernel": receipt["kernel_commit"],
              "release": receipt["release_id"], "iso": receipt["artifacts"][ISO]["sha256"]}
    if head != wanted:
        raise m.Refused(f"manifest_mismatch {head} != {wanted}")
    op = operator_module(platform)
    found = op.tree(image)
    on_disk = {path: hashlib.sha256(data).hexdigest() for path, data in found.items()}
    if on_disk != files:
        missing = sorted(set(files) - set(on_disk))
        extra = sorted(set(on_disk) - set(files))
        changed = sorted(p for p in set(files) & set(on_disk) if files[p] != on_disk[p])
        raise m.Refused(f"disk_mismatch missing={missing[:5]} extra={extra[:5]} changed={changed[:5]}")
    if "/absd/selected" not in on_disk:
        raise m.Refused("disk_mismatch no release selection")
    if m.sha(image) != receipt["artifacts"][IMAGE]["sha256"]:
        raise m.Refused("artifact_changed the disk changed while it was read")
    if f"{fs_id_of(image):016x}" != receipt["fs_id"]:
        raise m.Refused("disk_mismatch the disk's fs_id is not the receipt's")
    results.update({"iso_sha256": receipt["artifacts"][ISO]["sha256"], "fs_id": receipt["fs_id"],
                    "image_sha256": receipt["artifacts"][IMAGE]["sha256"],
                    "manifest_sha256": receipt["artifacts"][MANIFEST]["sha256"],
                    "disk_files_verified": len(on_disk), "el_torito": ["BIOS", "UEFI"],
                    "pair": [receipt["kernel_commit"], receipt["platform_commit"]],
                    "identity": operator_identity(receipt), "environment": env, "tools": m.tools_used()})
    remove_tree(scratch)
    (out / VALIDATION).write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    print(f"MEDIA OPERATOR VALIDATED {json.dumps(results, sort_keys=True)}", flush=True)


def captured(serial):
    """The served worker's output as the console carries it: consecutive
    `EXTERNAL OUTPUT CHUNK offset=N data=HEX` lines (scripts/ssh_absd.py)."""
    data = bytearray()
    for hit in re.finditer(rb"EXTERNAL OUTPUT CHUNK offset=([0-9a-f]+) data=([0-9a-f]*)\n", serial):
        if int(hit.group(1), 16) != len(data):
            break
        data.extend(bytes.fromhex(hit.group(2).decode()))
    return data.decode(errors="replace")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def operator_boot(args, timeout=420):
    """A bounded TCG boot of a copy of the disk (the boot writes it: the
    host key, /home, /tmp, /var/log). Passes when sshd listens and answers
    with an SSH banner and no fault marker appears; with --login-key, also
    a session runs `release` and `uname` and `shutdown` halts the machine
    (QEMU status 3). The validated disk itself is never attached. The
    copy holds the guest's private host key after the boot, so it is
    deleted when the boot ends (its digest is kept in RESULT.json)."""
    m = _media()
    profile = load_operator_profile(args.profile)
    out = pathlib.Path(args.out).resolve()
    results = pathlib.Path(args.results).resolve()
    receipt = json.loads(m.confined(out, RECEIPT).read_text())
    if receipt.get("profile") != args.profile or receipt.get("profile_sha256") != m.profile_sha(args.profile):
        raise m.Refused("receipt_mismatch the receipt is for another profile or profile text")
    paths = artifact_paths(out, receipt)
    check_iso_tree_names(receipt, profile)
    bound_operator_build(pathlib.Path(args.platform_tree).resolve(), pathlib.Path(args.kernel_run), profile, receipt)
    try:
        validation = json.loads(m.confined(out, VALIDATION).read_text())
    except m.Refused:
        raise m.Refused("not_validated (run `media.py operator-validate` first)") from None
    if validation.get("identity") != operator_identity(receipt):
        raise m.Refused("not_validated the validation is for another build, pair, profile or artifact")
    image_sha = m.sha(paths[IMAGE])
    iso_sha = m.sha(paths[ISO])
    if not (image_sha == receipt["artifacts"][IMAGE]["sha256"] == validation.get("image_sha256")
            and iso_sha == receipt["artifacts"][ISO]["sha256"] == validation.get("iso_sha256")):
        raise m.Refused("not_validated the ISO or disk is not the one its receipt and validation name")
    for path in (out, results):
        if "," in str(path):
            raise m.Refused(f"path_refused {path} contains a comma")
    results.mkdir(exist_ok=False)
    disk = results / IMAGE
    shutil.copyfile(paths[IMAGE], disk)
    os.chmod(disk, 0o600)
    console = results / "console.log"
    port = free_port()
    env = m.clean_env(receipt["source_date_epoch"])
    command = [*served_qemu([m.tool("qemu-system-x86_64"), "-m", "512"]), "-accel", "tcg", "-cpu", "max,vendor=GenuineIntel,+rdrand", "-rtc", "base=utc",
               "-cdrom", str(paths[ISO]), "-drive", f"file={disk},format=raw,if=ide,index=0",
               "-netdev", f"user,id=n0,net=10.0.2.0/24,hostfwd=tcp:127.0.0.1:{port}-10.0.2.15:22",
               "-device", "e1000,netdev=n0", "-display", "none", "-serial", f"file:{console}",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot"]
    (results / "COMMAND.json").write_text(json.dumps(command, indent=2) + "\n")
    faults = ("ABSD PANIC", "KERNEL FAULT", "SERVED RECOVERY BEGIN", "MACHINE STOP")
    record = {"passed": False, "iso_sha256": iso_sha, "image_sha256": image_sha, "port": port}
    log = open(results / "qemu.log", "wb")
    process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=env)
    try:
        start = time.monotonic()
        text = ""
        while True:
            raw = console.read_bytes() if console.exists() else b""
            text = raw.decode(errors="replace") + "\n" + captured(raw)
            hit = [f for f in faults if f in text]
            if hit:
                raise m.Refused(f"boot_failed fault marker {hit}")
            if process.poll() is not None:
                raise m.Refused(f"boot_failed QEMU exited with {process.returncode} before serving")
            keys = re.findall(r"(?m)^sshd: host key (ssh-ed25519 [A-Za-z0-9+/=]+)$", text)
            if "SSH LISTENING" in text and keys:
                break
            if time.monotonic() - start > timeout:
                raise m.Refused("boot_failed no SSH LISTENING in time")
            time.sleep(1)
        record["seconds_to_listening"] = round(time.monotonic() - start, 1)
        record["host_key"] = keys[0]
        try:
            record["receive_setup_seconds"] = wait_rx_setup(
                lambda: console.read_bytes(), lambda: process.poll() is None, start + timeout)
        except RxSetupFailed as error:
            raise m.Refused("boot_failed " + str(error)) from error
        with socket.create_connection(("127.0.0.1", port), timeout=30) as s:
            s.settimeout(30)
            banner = s.recv(64)
        if not banner.startswith(b"SSH-2.0"):
            raise m.Refused(f"boot_failed no SSH banner: {banner[:32]!r}")
        record["banner"] = banner.split(b"\r\n")[0].decode(errors="replace")
        if args.login_key:
            known = results / "known_hosts"
            known.write_text(f"[127.0.0.1]:{port} {keys[0]}\n")
            ssh = [m.tool("ssh"), "-F", "/dev/null", "-p", str(port), "-i", str(args.login_key), "-o", "IdentitiesOnly=yes",
                   "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known}",
                   "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=30", "-o", "LogLevel=ERROR",
                   "operator@127.0.0.1"]
            session = {}
            for word in ("release", "uname"):
                done = subprocess.run(ssh + [word], capture_output=True, timeout=180, env=env)
                session[word] = {"rc": done.returncode, "out": done.stdout.decode(errors="replace")[-400:]}
                if done.returncode:
                    raise m.Refused(f"boot_failed `{word}` exited {done.returncode}: {done.stderr[-200:]!r}")
            if receipt["release_id"] not in session["release"]["out"]:
                raise m.Refused("boot_failed `release` does not name the image's release")
            subprocess.run(ssh + ["shutdown"], capture_output=True, timeout=180, env=env)
            try:
                status = process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                raise m.Refused("boot_failed shutdown did not halt the machine") from None
            if status != 3:
                raise m.Refused(f"boot_failed shutdown ended QEMU with {status}, not 3 (halt)")
            record["session"] = session
            record["halted"] = True
        record["passed"] = True
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        log.close()
        record["console_sha256"] = m.sha(console) if console.exists() else None
        record["validated_disk_unchanged"] = m.sha(paths[IMAGE]) == image_sha
        if disk.exists():
            record["disk_copy_sha256"] = m.sha(disk)
            disk.unlink()
        record["disk_copy_deleted"] = not disk.exists()
        record["identity"] = validation["identity"]
        record["environment"] = env
        record["scope"] = "QEMU TCG, i440fx, BIOS boot from the ISO, IDE disk copy, user-mode network. No KVM, no physical."
        (results / "RESULT.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    if not record["validated_disk_unchanged"]:
        raise m.Refused("disk_changed the validated disk changed during the boot")
    print(f"MEDIA OPERATOR BOOTED {json.dumps({k: record[k] for k in ('passed', 'banner', 'image_sha256')})}",
          flush=True)


# -- the disk's identity and comparison --------------------------------------------

def superblocks(data):
    """Offsets of every valid ABSD filesystem superblock (sector-aligned,
    `ABSDFSS1`/`ABSDFSS2`, its own SHA-256 over the first 480 bytes)."""
    found = []
    for offset in range(0, len(data) - 511, 512):
        raw = data[offset:offset + 512]
        if raw[:7] == b"ABSDFSS" and hashlib.sha256(raw[:480]).digest() == raw[480:]:
            found.append(offset)
    return found


def fs_id_of(image):
    """The filesystem identity the guest chose with rdrand when it formatted
    the disk (runtime/src/storage.rs): new for every build, by design."""
    data = pathlib.Path(image).read_bytes()
    ids = {struct.unpack_from("<Q", data, sb + 16)[0] for sb in superblocks(data)}
    if len(ids) != 1:
        raise _media().Refused(f"disk_unexpected {len(ids)} filesystem identities in {image}")
    return ids.pop()


def with_fs_id(data, new_id):
    """`data` with its filesystem identity replaced by `new_id` and every
    digest that covers it recomputed: each superblock's image digest (+72)
    and own checksum (+480), and each image header's identity (+16)."""
    m = _media()
    data = bytearray(data)
    sbs = superblocks(bytes(data))
    old = struct.unpack_from("<Q", data, sbs[0] + 16)[0]
    for sb in sbs:
        seq = struct.unpack_from("<Q", data, sb + 24)[0]
        image_len = struct.unpack_from("<I", data, sb + 32)[0]
        headers = [h for h in range(0, len(data) - 31, 512)
                   if data[h:h + 7] == b"ABSDFSI" and struct.unpack_from("<QQ", data, h + 16) == (old, seq)]
        if len(headers) != 1:
            raise m.Refused(f"disk_unexpected superblock seq {seq} has {len(headers)} images")
        struct.pack_into("<Q", data, headers[0] + 16, new_id)
        struct.pack_into("<Q", data, sb + 16, new_id)
        data[sb + 72:sb + 104] = hashlib.sha256(bytes(data[headers[0]:headers[0] + image_len])).digest()
        data[sb + 480:sb + 512] = hashlib.sha256(bytes(data[sb:sb + 480])).digest()
    return bytes(data)


def operator_compare(args):
    """Compares an operator output with a reference directory (one holding
    absd-operator.iso, absd-operator.img and MANIFEST, as U1-b's does) and
    names each difference: the ISO's payload (kernel, grub.cfg), its GRUB
    files, MANIFEST apart from its `iso` line, and the disk exactly or
    apart from the filesystem identity."""
    m = _media()
    out, ref = pathlib.Path(args.out).resolve(), pathlib.Path(args.reference).resolve()
    report = {"out": str(out), "reference": str(ref)}
    for name in (ISO, IMAGE, MANIFEST):
        report[f"{name}_equal"] = m.sha(m.confined(out, name)) == m.sha(m.confined(ref, name))
    with tempfile.TemporaryDirectory(prefix="media-compare-") as scratch:
        trees = {}
        for side, base in (("out", out), ("reference", ref)):
            target = pathlib.Path(scratch) / side
            subprocess.run([m.tool("xorriso"), "-osirrox", "on", "-indev", str(base / ISO), "-extract", "/",
                            str(target)], check=True, capture_output=True, env=m.clean_env(0))
            trees[side] = {str(p.relative_to(target)): m.sha(p) for p in target.rglob("*") if p.is_file()}
    a, b = trees["out"], trees["reference"]
    report["iso_payload_equal"] = all(a.get(n) == b.get(n) and a.get(n) for n in ("boot/absd-kernel",
                                                                               "boot/grub/grub.cfg"))
    report["iso_files_only_in_out"] = sorted(set(a) - set(b))
    report["iso_files_only_in_reference"] = sorted(set(b) - set(a))
    report["iso_files_differing"] = sorted(n for n in set(a) & set(b) if a[n] != b[n])
    ours, theirs = [(out / MANIFEST).read_text().splitlines(), (ref / MANIFEST).read_text().splitlines()]
    report["manifest_lines_differing"] = sorted(set(ours) ^ set(theirs))
    report["manifest_equal_but_iso_line"] = ([l for l in ours if not l.startswith("iso ")] ==
                                             [l for l in theirs if not l.startswith("iso ")])
    disk, reference_disk = (out / IMAGE).read_bytes(), (ref / IMAGE).read_bytes()
    report["fs_id"] = {"out": f"{fs_id_of(out / IMAGE):016x}", "reference": f"{fs_id_of(ref / IMAGE):016x}"}
    report["disk_equal_but_fs_id"] = with_fs_id(disk, fs_id_of(ref / IMAGE)) == reference_disk
    print(json.dumps(report, indent=2, sort_keys=True), flush=True)
    return report
