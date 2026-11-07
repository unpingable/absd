#!/usr/bin/env python3
"""The operator image: the one served-boot deployment an operator runs
(afterboot(8)), built by scripts/build-operator-image.sh and booted by
scripts/boot-operator.sh. The test matrices build their own images; this
one is not a test fixture.

An output directory holds:

  absd-operator.iso   GRUB, the kernel, init, sshd (the served worker), and
                      the file server, as a `net fsd served` durable boot
  absd-operator.img   the disk: an ABSD filesystem holding
                        /bin         every command the platform installs,
                                     the shell, and the ports (uutils, rg)
                        /share/man   the rendered manual
                      (both on the disk under /releases/<id>/, with the
                      release record /releases/<id>/release and the
                      selection /absd/selected: docs/RELEASE.md,
                      scripts/release_record.py; `<id>` is ABSD_RELEASE_ID,
                      default `dev`, and must be the id the platform was
                      built with, or the file server refuses to serve)
                        /etc         network.conf, sshd.conf (operator/etc/
                                     in this repository, or --etc files)
                        /ssh/authorized_keys  the operator's keys
                      The file server adds /home/operator, /tmp, /var/log,
                      and the host key (/ssh/host_ed25519_seed) at the
                      first boot.
  MANIFEST            what was built from what: platform and kernel
                      commits, the release id, and the SHA-256 of every
                      installed file at its path on the disk (so /bin/ls
                      is listed as /releases/<id>/bin/ls)

The image is written the only way ABSD writes a filesystem: importer boots
(fixture-import.elf, steps 1 and 2) under the pinned kernel, each file
checked by its digest inside the guest, and then the whole tree read back
by the host's independent reader (scripts/absd_fs.py). `--reconfigure`
replaces /etc files (and optionally authorized_keys) on an existing image,
whole, as one commit each (importer step 4), with the machine halted; it
refuses an image without /absd/selected (one built before the release
layout, which the file server would refuse to serve anyway). It updates
MANIFEST, and refuses, before writing, a directory without one: an
operator directory of scripts/release.py install (TARGET or RELEASES) is
reconfigured by `release.py reconfigure`, with the selected release's own
importer, and anything else has no record to keep.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
from served_ram import served_qemu
from served_kernel import kernel_make
import operator_cpus
import operator_geometry
import absd_fs  # noqa: E402
import release_record  # noqa: E402
import ssh_absd  # noqa: E402
import c_kit_source  # noqa: E402
import storage_fence_host
import storage_fence_resume
import manual_coverage

spec = importlib.util.spec_from_file_location("exec_matrix", here / "exec-matrix.py")
em = importlib.util.module_from_spec(spec)
spec.loader.exec_module(em)

enroll_spec = importlib.util.spec_from_file_location("local_console_enroll", here / "local-console-enroll.py")
local_console_enroll = importlib.util.module_from_spec(enroll_spec)
enroll_spec.loader.exec_module(local_console_enroll)

ROOT = here.parent
# The writable disk. Its filesystem is the second half (Layout::format), and
# it must stage a successor release of the shipped composition beside the
# installed one: check_successor_headroom() refuses a build whose successor
# peak plus a quarter of it (em.fitted_image_bytes's rule) does not fit.
# 64 MiB stopped fitting when the canonical composition gained
# /bin/https-document (coordination record #28: peak 4448 blocks, free 4188). 128 MiB
# (owner, 2026-11-02: not the smallest size that passes today) leaves room
# for the composition to grow; one that outgrows it is refused at build and
# install, not found by a stage.
IMAGE_BYTES = operator_geometry.DEFAULT_IMAGE_BYTES
DEVICE_SECTORS = IMAGE_BYTES // 512
# storage_fence_resume checks the same disk and cannot import this module.
assert storage_fence_resume.IMAGE_BYTES == IMAGE_BYTES, "operator image size differs from storage_fence_resume's"
# The release id check_successor_headroom() lays a probe successor out under.
SUCCESSOR_PROBE_ID = "successor-capacity-probe"
ISO = "absd-operator.iso"
IMAGE = "absd-operator.img"
# The platform's own commands (commands/NAME) and the ports (ports/NAME:
# uutils and ripgrep): every command /bin carries. No test helper (sshtest,
# fsd-probe, sh-probe, exec-probe) is installed.
NATIVE = ["echo", "pwd", "ls", "cat", "printenv", "uname", "mkdir", "rm", "mv", "cp", "head", "tail",
          "wc", "sha256sum", "stat", "df", "sync", "man", "date", "uptime", "release", "sysinfo", "health", "net-status", "terminal-size", "ps", "interfaces", "dmesg", "logs", "absd-sftp"]
RUST_PORTS = ["basename", "seq", "cut", "fold", "nl", "uniq", "base64", "rg"]
PORTS = ["basename", "seq", "cut", "fold", "nl", "uniq", "base64", "rg",
         # sbase ports (userland/PORTS.tsv, base-userland lane 2026-10-12; owner D-01)
         "printf", "test", "grep", "sort", "sed", "od", "cmp", "ed", "find", "diff", "hexdump", "tar", "tr", "dirname", "tee", "sleep", "rmdir", "paste"]
QEMU = "qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand"


class Failed(Exception):
    pass


KERNEL_MAKE_TAIL_BYTES = 64 * 1024


class KernelBuildFailed(subprocess.CalledProcessError):
    """Keep bounded make diagnostics in tracebacks as well as the run logger."""
    def __str__(self):
        tail = self.output.decode("utf-8", errors="replace")
        return (f"{super().__str__()}\n"
                f"make stdout/stderr tail ({len(self.output)} bytes, limit {KERNEL_MAKE_TAIL_BYTES}):\n{tail}")


def c_ports_installed(root=ROOT):
    """Return canonical-pin/receipt checked buffers from this checkout's
    reader, including for a prebuilt or alternate platform tree."""
    try:
        return c_kit_source.read_installed(root, root / "ports")[1]
    except (c_kit_source.Refused, OSError) as error:
        raise Failed("C KIT SOURCE REFUSED: " + str(error)) from error


def command_names(https_document=False):
    """No-I/O declaration, shared with composition and manual coverage."""
    return NATIVE + ["absd-sh", "sh"] + (["https-document"] if https_document else []) + PORTS


def system_files(root=ROOT):
    """The release's own files at the paths a session sees (/bin, /share);
    release_record.release_layout places them on the disk."""
    cports = c_ports_installed(root)
    if set(cports) != set(PORTS) - set(RUST_PORTS):
        raise Failed("verified C ports do not match the operator image's C-port list")
    document = os.environ.get("ABSD_HTTPS_DOCUMENT", "0")
    if document not in {"0", "1"}:
        raise Failed("ABSD_HTTPS_DOCUMENT must be 0 or 1")
    names = command_names(document == "1")
    files = []
    for name in names:
        if name in cports:
            data = cports[name]
        else:
            directory = "ports" if name in RUST_PORTS else "commands"
            data = (root / directory / name).read_bytes()
        if name == "sh" and data != (root / "commands" / "absd-sh").read_bytes():
            raise Failed("/bin/sh must be byte-identical to /bin/absd-sh")
        files.append((f"/bin/{name}", data))
    files += ssh_absd.manual(root)
    try:
        manual_coverage.check(root, names, files)
    except manual_coverage.Refused as error:
        raise Failed(f"MANUAL COVERAGE REFUSED: {error}") from error
    return files


def etc_files(etc_dir=None, root=ROOT):
    """/etc as operator/etc/ has it, with every regular file of `etc_dir`
    added or put in its place."""
    chosen = {p.name: p for p in sorted((root / "operator" / "etc").iterdir()) if p.is_file()}
    if etc_dir is not None:
        chosen.update({p.name: p for p in sorted(pathlib.Path(etc_dir).iterdir()) if p.is_file()})
    return [(f"/etc/{name}", path.read_bytes()) for name, path in sorted(chosen.items())]


def authorized(path):
    data = pathlib.Path(path).read_bytes()
    lines = [line for line in data.decode().splitlines() if line.strip() and not line.startswith("#")]
    if not lines or any(not line.startswith("ssh-ed25519 ") for line in lines):
        raise Failed(f"{path}: sshd accepts only ssh-ed25519 lines (no options); give at least one")
    return data


def local_login_files(out, token_file=None, verifier=None):
    """One per-image enrollment; only the verifier enters artifact/site bytes.

    Secrets live outside the output directory so recursive artifact copying or
    release-manifest enumeration cannot pick them up. Existing enrollment can
    be reused explicitly; fresh identity creation never overwrites a token.
    """
    out = pathlib.Path(out).resolve()
    if verifier is not None:
        if token_file is not None:
            raise Failed("choose --local-login-verifier or --local-token-file")
        data = pathlib.Path(verifier).read_bytes()
        if not re.fullmatch(rb"ABSD-LOCAL-1 operator [0-9a-f]{64}\n", data):
            raise Failed("local login verifier must be an ABSD-LOCAL-1 operator SHA-256 descriptor")
    else:
        token = pathlib.Path(token_file).resolve() if token_file is not None else out.with_name(out.name + ".local-console-token")
        descriptor = pathlib.Path(str(token) + ".verifier")
        if token.is_relative_to(out) or descriptor.is_relative_to(out):
            raise Failed("local login token and enrollment files must be outside the artifact output directory")
        if token.exists() or descriptor.exists():
            raise Failed("local login enrollment already exists; reuse --local-login-verifier or choose a new external --local-token-file")
        try:
            local_console_enroll.enroll(descriptor, token)
        except OSError as error:
            raise Failed(f"local login enrollment could not be created: {error}") from error
        data = descriptor.read_bytes()
    return [("/ssh/local-login", data)]


def kernel_iso(kernel, step, worker, options="", server="", input_bytes=b"", work=None, operator_smp=False, logger="", log=print):
    input_path = pathlib.Path(work) / f"input-{hashlib.sha256(input_bytes).hexdigest()}.bin"
    input_path.write_bytes(input_bytes)
    command = [*kernel_make(), *(["--operator-smp"] if operator_smp else []), "--no-print-directory", "-C", str(kernel), "durable-iso", f"DURABLE_STEP={step}",
                    f"EXTERNAL_USER_ELF={worker}", f"EXTERNAL_INPUT={input_path}", "EXTERNAL_READER_ELF=",
                    "EXTERNAL_READER_INPUT=", f"DURABLE_OPTIONS={options}", f"FILE_SERVER_ELF={server}", f"LOGD_ELF={logger}", "LOGD_FAULT=0",
                    f"ABSD_LOCAL_CONSOLE={int(step == 0 and 'served' in options.split())}"]
    tail = bytearray()
    # Drain while make runs: neither memory nor a temporary log grows with
    # the full build output. Merging stderr preserves the pipe's byte order.
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as process:
        try:
            while chunk := process.stdout.read(8192):
                tail.extend(chunk)
                del tail[:-KERNEL_MAKE_TAIL_BYTES]
            returncode = process.wait()
        except BaseException:
            # Match subprocess.run's child cleanup on exceptional exits. The
            # context manager reaps it after killing, then preserves the error.
            process.kill()
            raise
    if returncode:
        error = KernelBuildFailed(returncode, command, output=bytes(tail))
        log(str(error))
        raise error
    return pathlib.Path(kernel) / "build" / "durable" / f"absd-durable-{step}.iso"


def import_boots(kernel, image, plan, work, qemu=QEMU, root=ROOT, log=print, *, fresh=False):
    """The importer boots of `plan`. Everything that can refuse without a
    boot runs first, outside the guard: the plan against this image (its
    replacement paths, its capacity) and every boot's ISO, built and kept
    in `work`. Only then does storage_fence_host.mutation mark the image
    dirty; a boot that fails leaves it dirty."""
    try:
        isos = _prepare_boots(kernel, image, plan, work, root, log)
        with storage_fence_host.mutation(image, fresh=fresh):
            return _import_boots(kernel, image, plan, isos, work, qemu, log)
    except (ValueError, absd_fs.Refused) as error:
        raise Failed(str(error)) from error


def _prepare_boots(kernel, image, plan, work, root, log):
    records, capacity = em.inspect_import_plan(image, plan)
    log("OPERATOR IMPORT CAPACITY " + json.dumps(capacity, sort_keys=True))
    log("OPERATOR IMPORT PLAN " + json.dumps(records, sort_keys=True))
    isos = []
    for index, (step, entries) in enumerate(plan, 1):
        try:
            built = kernel_iso(kernel, step, root / "fixture-import.elf", input_bytes=em.stream(entries), work=work, log=log)
        except subprocess.CalledProcessError as error:
            raise Failed(f"importer boot {index} (step {step}): the kernel ISO build failed "
                         f"(exit {error.returncode}); nothing was written\n{error}") from error
        # Every step-N ISO is built at one path in the kernel copy: keep each.
        isos.append(pathlib.Path(shutil.copyfile(built, pathlib.Path(work) / f"import-{index:03d}.iso")))
    return isos


def _import_boots(kernel, image, plan, isos, work, qemu, log):
    for index, ((step, entries), iso) in enumerate(zip(plan, isos), 1):
        serial = pathlib.Path(work) / f"import-{index:03d}.serial.log"
        status = subprocess.run([str(pathlib.Path(kernel) / "scripts" / "durable-boot.sh"), str(iso), str(image),
                                 str(serial), "900", *served_qemu(qemu)], check=True, capture_output=True,
                                text=True).stdout.strip()
        text = ssh_absd.captured(serial.read_bytes())
        if status != "3" or f"FIXTURE IMPORT OK files={len(entries)}" not in text:
            raise Failed(f"importer boot {index} (step {step}): QEMU status {status}\n{text[-1500:]}")
        log(f"operator image: importer boot {index}/{len(plan)} step {step}: {len(entries)} files")


def namespace(image):
    try:
        sectors = storage_fence_resume.image_sectors(image)
    except storage_fence_resume.Refused as error:
        raise absd_fs.Refused(str(error)) from None
    region = absd_fs.fs_region(image, sectors)
    selected = absd_fs.select(region)
    return {path: dict(record, fs_id=selected["fs_id"], kind=2 if record["dir"] else 1)
            for path, record in absd_fs.tree(region, selected).items()}


def verify_import_paths(image, files, log=print):
    """Check all named objects, including empty dirs, under imported trees."""
    expected = {path.rstrip("/") for path, _ in files}
    allowed = set(expected)
    for path in expected:
        allowed.update(str(p) for p in pathlib.PurePosixPath(path).parents)
    roots = set()
    temp_parents = {str(pathlib.PurePosixPath(path).parent) for path in expected} | {"/absd", "/etc"}
    for path in expected:
        parts = path.split("/")
        if len(parts) >= 3 and parts[1] == "releases":
            roots.add("/".join(parts[:3]))
        elif len(parts) >= 2 and parts[1] in ("bin", "share"):
            roots.add("/" + parts[1])
    for path in namespace(image):
        if em.reserved_import_path(path):
            parts = pathlib.PurePosixPath(path).parts
            candidate = next(pathlib.PurePosixPath(*parts[:i + 1]) for i, part in enumerate(parts)
                             if re.fullmatch(r"\.absd-import-[0-9a-fA-F]{4}", part))
            if str(candidate.parent) in temp_parents:
                raise Failed(f"unresolved_import_temp {path}")
            log(f"IMPORT LOOKALIKE path={path}: outside import parents; ownership unestablished; inspect before removal")
        if path not in allowed and any(path == root or path.startswith(root + "/") for root in roots):
            raise Failed(f"unlisted import path {path}")


def tree(image):
    # The disk's own geometry: reading never assumes the creation size.
    try:
        sectors = storage_fence_resume.image_sectors(image)
    except storage_fence_resume.Refused as error:
        raise absd_fs.Refused(str(error)) from None
    region = absd_fs.fs_region(image, sectors)
    if region is None:
        raise absd_fs.Refused("no filesystem region")
    selected = absd_fs.select(region)
    return {path: absd_fs.content(region, selected, record)
            for path, record in absd_fs.tree(region, selected).items()
            if not path.endswith("/") and ssh_absd.record_is_file(region, selected, record)}


def check_successor_headroom(image, logical, release_id="dev"):
    """Refuse an image that cannot stage a successor of its own composition:
    the release's logical files (`/bin/...`, `/share/...`) under another
    release id, plus the resume slot when the disk lacks it, as `release.py
    stage` would import them. Import peaks depend on order, so the files go
    in stage's order: release.py Release._tree_bytes reads tree/ sorted by
    path. The successor's peak extra allocation must fit with a quarter of
    it to spare. Returns check_import_capacity's figures."""
    other = SUCCESSOR_PROBE_ID if release_id != SUCCESSOR_PROBE_ID else SUCCESSOR_PROBE_ID + "-2"
    ordered = sorted(logical, key=lambda item: pathlib.PurePosixPath(item[0]))
    files = release_record.release_layout(ordered, other, select=False)
    state = ssh_absd.storage_fence_state
    if state.RESUME_PATH not in tree(image):
        files.append((state.RESUME_PATH, state.RESUME_NONE))
    try:
        capacity = em.check_import_capacity(image, em.import_plan(files))
    except ValueError as error:
        raise Failed(f"successor_headroom: {error}") from None
    peak = capacity["peak_extra_blocks"]
    need = peak + -(-peak // 4)
    if capacity["free_blocks"] < need:
        raise Failed(f"successor_headroom peak_extra_blocks={peak} free_blocks={capacity['free_blocks']} "
                     f"needs {need} (peak plus a quarter): this operator image "
                     f"cannot stage a successor of this composition")
    return capacity


def verify(image, files):
    found = tree(image)
    for path, data in files:
        if found.get(path) != data:
            raise Failed(f"the host reader sees different bytes at {path}")
    verify_import_paths(image, files)
    return found


def git_head(path):
    try:
        return subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], check=True, capture_output=True,
                              text=True).stdout.strip()
    except subprocess.CalledProcessError:
        return "unknown"


def public_source_identity(path):
    """Checked curated component mapping, distinct from its actual repository.

    The qualified committed SOURCE-MANIFEST supplies upstream provenance;
    this reader verifies its custody and the actual clean component tree.
    It does not re-derive the curation from unavailable upstream history.
    """
    path = pathlib.Path(path).resolve()
    if (path / ".git").exists():
        return None  # Existing standalone checkout behavior is unchanged.
    top = path.parent
    manifest = top / "SOURCE-MANIFEST.toml"
    if not manifest.exists():
        return None
    try:
        def read(*args):
            return subprocess.check_output(["git", "-C", str(top), *args], stderr=subprocess.PIPE)
        if (manifest.is_symlink() or not manifest.is_file()
                or pathlib.Path(read("rev-parse", "--show-toplevel").decode().strip()).resolve() != top):
            raise Failed("public source mapping is outside the actual repository")
        raw = manifest.read_bytes()
        if read("show", "HEAD:SOURCE-MANIFEST.toml") != raw:
            raise Failed("public SOURCE-MANIFEST differs from its committed bytes")
        entries = [entry for entry in tomllib.loads(raw.decode()).get("component", [])
                   if entry.get("path") == path.name]
        if len(entries) != 1 or entries[0].get("name") != path.name:
            raise Failed("public source mapping has no unique matching component")
        entry = entries[0]
        tree = read("rev-parse", "HEAD:" + path.name).decode().strip()
        if tree != entry["tree"] or read("status", "--porcelain", "--untracked-files=all", "--", path.name, "SOURCE-MANIFEST.toml").strip():
            raise Failed("public source component tree or cleanliness differs")
        for key in ("commit", "source_tree", "tree"):
            if not re.fullmatch(r"[0-9a-f]{40}", entry.get(key, "")):
                raise Failed("public source mapping has an invalid " + key)
        return {"schema": "absd-public-component-source/1",
                "repository_commit": read("rev-parse", "HEAD").decode().strip(),
                "repository_tree": read("rev-parse", "HEAD^{tree}").decode().strip(),
                "component_path": path.name, "component_tree": tree,
                "upstream_commit": entry["commit"], "upstream_tree": entry["source_tree"],
                "source_manifest_sha256": hashlib.sha256(raw).hexdigest()}
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError) as error:
        raise Failed("public source mapping refused: " + str(error)) from None


def identity(path):
    """The commit a kernel or platform tree is. A checkout answers for itself.
    In a source release both are directories of one repository, whose HEAD is
    the release and not either component: a disposable kernel copy carries
    what scripts/inputs.sh established when it made it, and a component in
    place is the commit the release's SOURCE-MANIFEST.toml names if it is
    still the tree named there, and `modified` if not."""
    path = pathlib.Path(path).resolve()
    if (path / ".git").exists():
        return git_head(path)
    if (path / ".absd-identity").is_file():
        return (path / ".absd-identity").read_text().strip()
    try:
        source = public_source_identity(path)
    except Failed:
        return "modified"
    return source["upstream_commit"] if source is not None else "unknown"


def manifest(out, kernel, files, release_id, root=ROOT):
    """`files` at their paths on the disk (the release layout)."""
    lines = [f"platform {identity(root)}", f"kernel {identity(kernel)}", f"release {release_id}",
             f"iso {hashlib.sha256((out / ISO).read_bytes()).hexdigest()}"]
    lines += [f"file {hashlib.sha256(data).hexdigest()} {path}" for path, data in sorted(files)]
    (out / "MANIFEST").write_text("\n".join(lines) + "\n")


def manifest_replaced(out, files):
    """MANIFEST's text after a reconfiguration: each replaced file's line
    holds its new digest (a file new to the image gets a line), so the
    manifest keeps naming what the image holds. Read before the importer
    boot, so a MANIFEST that cannot be updated refuses first."""
    lines = (out / "MANIFEST").read_text().splitlines()
    head = [line for line in lines if not line.startswith("file ")]
    entries = {}
    for line in lines:
        if line.startswith("file "):
            words = line.split(" ", 2)
            if len(words) != 3 or not re.fullmatch(r"[0-9a-f]{64}", words[1]):
                raise Failed(f"{out / 'MANIFEST'}: malformed line {line!r}; not reconfiguring")
            entries[words[2]] = words[1]
    entries.update({name: hashlib.sha256(data).hexdigest() for name, data in files})
    return "\n".join(head + [f"file {digest} {name}" for name, digest in sorted(entries.items())]) + "\n"


def manifest_replace(out, files, text=None):
    tmp = out / "MANIFEST.new"
    tmp.write_text(manifest_replaced(out, files) if text is None else text)
    tmp.replace(out / "MANIFEST")


# An operator directory of scripts/release.py (its TARGET and RELEASES):
# reconfigured by `release.py reconfigure`, not here.
RELEASE_TARGET_MARKS = ("TARGET", "RELEASES")


def check_platform_release(root, release_id):
    """The platform's commands/release must carry `release_id` (the id its
    programs were compiled with), as scripts/release.py build checks."""
    command = pathlib.Path(root) / "commands" / "release"
    if command.is_file() and release_id.encode() not in command.read_bytes():
        raise Failed(f"{root} was not built with ABSD_RELEASE_ID={release_id} (commands/release lacks the id); "
                     "set ABSD_RELEASE_ID to the id it was built with")


def build(kernel, out, keys, etc_dir=None, qemu=QEMU, root=ROOT, log=print, release_id=None, disk_profile=None, *, local_token_file=None, local_login_verifier=None, no_local_login=False):
    """Builds the image and the ISO into `out`: the system files in the
    release layout (with the record and the selection) first, then the
    site files (/etc, authorized_keys) in a boot of their own."""
    if no_local_login and (local_token_file is not None or local_login_verifier is not None):
        raise Failed("--no-local-login cannot be combined with local enrollment options")
    cpus = operator_cpus.profile()
    operator_cpus.qemu(qemu)  # Refuse conflicting launch arguments before writing.
    size = IMAGE_BYTES if disk_profile is None else operator_geometry.image_bytes(disk_profile)
    release_id = release_record.release_id_from_env() if release_id is None else release_record.check_id(release_id)
    check_platform_release(root, release_id)
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for name in (IMAGE, ISO, "MANIFEST"):
        if (out / name).exists():
            raise Failed(f"{out / name}: fresh construction requires unused output paths")
    image = out / IMAGE
    system = release_record.release_layout(system_files(root), release_id)
    site = (etc_files(etc_dir, root) + [("/ssh/authorized_keys", authorized(keys))]
            + ([] if no_local_login else local_login_files(out, local_token_file, local_login_verifier))
            + ssh_absd.storage_fence_state.fresh_files())
    with tempfile.TemporaryDirectory(prefix="operator-image-", dir=out) as work:
        # The disk will hold the host's private key (the file server makes
        # it at the first boot): readable by its owner only.
        # Fresh construction only: an existing image's missing/dirty guard
        # is not upgraded or repaired by reseeding. Use a fresh output.
        with open(image, "xb") as handle:
            handle.truncate(size)
        image.chmod(0o600)
        plan = em.import_plan(system)
        import_boots(kernel, image, plan, work, qemu, root, log, fresh=True)
        # The site files: one more creating boot (step 2).
        import_boots(kernel, image, [(2, site)], work, qemu, root, log, fresh=True)
        verify(image, system + site)
        capacity = check_successor_headroom(image, system_files(root), release_id)
        log(f"OPERATOR IMAGE SUCCESSOR HEADROOM peak_extra_blocks={capacity['peak_extra_blocks']} "
            f"free_blocks={capacity['free_blocks']}")
        iso = kernel_iso(kernel, 0, root / "sshd.elf",
                         options="net fsd served" + (f" smp-operator={cpus}" if cpus > 1 else ""),
                         server=root / "absd-fsd.elf", work=work, operator_smp=cpus > 1, logger=root / "absd-logd.elf", log=log)
        shutil.copyfile(iso, out / ISO)
    manifest(out, kernel, system + site, release_id, root)
    log(f"OPERATOR IMAGE BUILT {out / ISO} {out / IMAGE} release={release_id} files={len(system) + len(site)}")
    return system + site


def reconfigure(kernel, out, etc_dir, keys=None, qemu=QEMU, root=ROOT, log=print):
    """Replaces the /etc files of `etc_dir` (and authorized_keys) on the
    existing image, whole (importer step 4). The machine must be halted."""
    out = pathlib.Path(out)
    image = out / IMAGE
    if not image.is_file():
        raise Failed(f"{image}: no image to reconfigure")
    found = tree(image)
    if release_record.SELECTED not in found:
        raise Failed(f"{image} has no {release_record.SELECTED}: it was built before the release layout "
                     "(docs/RELEASE.md) and the file server will not serve it; rebuild it with "
                     "build-operator-image.sh (or install a release with scripts/release.py), then reconfigure")
    try:
        selected = release_record.parse_selected(found[release_record.SELECTED])
    except release_record.Malformed as error:
        raise Failed(f"{image}: {release_record.SELECTED} is malformed ({error.reason}); not reconfiguring")
    files = [(f"/etc/{p.name}", p.read_bytes()) for p in sorted(pathlib.Path(etc_dir).iterdir()) if p.is_file()]
    if keys is not None:
        files.append(("/ssh/authorized_keys", authorized(keys)))
    if not files:
        raise Failed(f"nothing to replace in {etc_dir}")
    # Where the change is recorded, settled before the disk is touched.
    marks = [name for name in RELEASE_TARGET_MARKS if (out / name).exists()]
    if marks:
        raise Failed(f"{out} is an operator directory of scripts/release.py ({' and '.join(marks)}): reconfigure it "
                     f"with `scripts/release.py reconfigure --release <the directory of release {selected}> "
                     f"--kernel <a kernel checkout at its commit> --target {out} --etc {etc_dir}`, which writes "
                     "with that release's verified importer and records a receipt and a ledger line; "
                     "nothing was written")
    if not (out / "MANIFEST").is_file():
        raise Failed(f"{out} has no MANIFEST (build-operator-image.sh) and is no release.py operator directory: "
                     "nothing would record the change; nothing was written")
    def manifest_destination():
        if os.path.lexists(out / "MANIFEST.new"):
            raise Failed(f"{out / 'MANIFEST.new'} exists (a reconfigure that did not finish?); inspect and remove it; "
                         "nothing was written")
        return manifest_replaced(out, files)

    # Refused before the recovery lock, so a refusal writes nothing (not
    # even OUT/recovery/lock); settled again under it.
    manifest_destination()
    # The hand-off boundary with operator-authorized recovery: the recovery
    # lock, the OFD probe, and no pending authorization (release.py
    # Target.mutation; docs/WRITABLE-ENTRY.md "Operator-authorized resume").
    # The lock is held from reading MANIFEST through the importer boot, the
    # read-back and the manifest.
    try:
        with storage_fence_resume.mutation(out, image):
            manifest_text = manifest_destination()
            with tempfile.TemporaryDirectory(prefix="operator-image-", dir=out) as work:
                import_boots(kernel, image, [(4, files)], work, qemu, root, log)
            verify(image, files)
            try:
                manifest_replace(out, files, manifest_text)
            except OSError as error:
                raise Failed(f"{image} HOLDS the new files (imported and read back: "
                             f"{','.join(path for path, _ in files)}), but MANIFEST was not updated: {error}; "
                             "the same reconfigure, run again once the fault is fixed, replaces the same files "
                             "whole and updates it") from error
    except storage_fence_resume.Refused as error:
        raise Failed(str(error)) from None
    log(f"OPERATOR IMAGE RECONFIGURED {image} files={','.join(path for path, _ in files)}")
    return files


def endpoint(image):
    """(guest address, guest port) as the image's /etc files set them, by
    the host's reader: what QEMU's port forward must name."""
    found = tree(image)

    def setting(path, keyword, default):
        for line in found.get(path, b"").decode(errors="replace").splitlines():
            words = line.split()
            if len(words) == 2 and words[0] == keyword:
                return words[1]
        return default

    return (setting("/etc/network.conf", "address", "10.0.2.15"), setting("/etc/sshd.conf", "port", "22"))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("--kernel", required=True)
    b.add_argument("--authorized-keys", required=True)
    b.add_argument("--etc")
    enrollment = b.add_mutually_exclusive_group()
    enrollment.add_argument("--no-local-login", action="store_true",
                            help="omit local-console enrollment for distributable preview media")
    enrollment.add_argument("--local-token-file", help="new owner-only token outside OUT (default: OUT.local-console-token)")
    enrollment.add_argument("--local-login-verifier", help="reuse an existing enrollment descriptor; never supply the token")
    b.add_argument("--qemu", default=QEMU)
    b.add_argument("--release-id", help="the release id the platform was built with "
                   "(default: ABSD_RELEASE_ID, else dev)")
    b.add_argument("--disk-profile", choices=operator_geometry.PROFILES,
                   help="fresh disk size: 128m (default, 64 MiB filesystem) or 2g (1 GiB filesystem)")
    b.add_argument("out")
    r = sub.add_parser("reconfigure")
    r.add_argument("--kernel", required=True)
    r.add_argument("--etc", required=True)
    r.add_argument("--authorized-keys")
    r.add_argument("--qemu", default=QEMU)
    r.add_argument("out")
    e = sub.add_parser("endpoint")
    e.add_argument("image")
    args = ap.parse_args()
    try:
        if args.command == "build":
            build(args.kernel, args.out, args.authorized_keys, args.etc, args.qemu,
                  release_id=args.release_id, disk_profile=args.disk_profile,
                  local_token_file=args.local_token_file, local_login_verifier=args.local_login_verifier,
                  no_local_login=args.no_local_login)
        elif args.command == "reconfigure":
            reconfigure(args.kernel, args.out, args.etc, args.authorized_keys, args.qemu)
        else:
            print(*endpoint(args.image))
    except (Failed, absd_fs.Refused, release_record.Malformed, ValueError) as error:
        print(f"operator image: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
