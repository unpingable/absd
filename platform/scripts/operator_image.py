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
layout, which the file server would refuse to serve anyway).
"""

import argparse
import hashlib
import importlib.util
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
import absd_fs  # noqa: E402
import release_record  # noqa: E402
import ssh_absd  # noqa: E402

spec = importlib.util.spec_from_file_location("exec_matrix", here / "exec-matrix.py")
em = importlib.util.module_from_spec(spec)
spec.loader.exec_module(em)

ROOT = here.parent
IMAGE_BYTES = 64 * 1024 * 1024
DEVICE_SECTORS = IMAGE_BYTES // 512
ISO = "absd-operator.iso"
IMAGE = "absd-operator.img"
# The platform's own commands (commands/NAME) and the ports (ports/NAME:
# uutils and ripgrep): every command /bin carries. No test helper (sshtest,
# fsd-probe, sh-probe, exec-probe) is installed.
NATIVE = ["echo", "pwd", "ls", "cat", "printenv", "uname", "mkdir", "rm", "mv", "cp", "head", "tail",
          "wc", "sha256sum", "stat", "df", "sync", "man", "date", "uptime", "release", "sysinfo", "health", "net-status"]
PORTS = ["basename", "seq", "cut", "fold", "nl", "uniq", "base64", "rg",
         # sbase ports (userland/PORTS.tsv, base-userland lane 2026-10-12; owner D-01)
         "printf", "test", "grep", "sort", "sed", "od", "cmp", "ed", "find", "diff", "hexdump", "tar"]
QEMU = "qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand"


class Failed(Exception):
    pass


def system_files(root=ROOT):
    """The release's own files at the paths a session sees (/bin, /share);
    release_record.release_layout places them on the disk."""
    files = [(f"/bin/{name}", (root / "commands" / name).read_bytes()) for name in NATIVE]
    files.append(("/bin/absd-sh", (root / "commands" / "absd-sh").read_bytes()))
    files += [(f"/bin/{name}", (root / "ports" / name).read_bytes()) for name in PORTS]
    files += ssh_absd.manual(root)
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


def kernel_iso(kernel, step, worker, options="", server="", input_bytes=b"", work=None):
    input_path = pathlib.Path(work) / f"input-{hashlib.sha256(input_bytes).hexdigest()}.bin"
    input_path.write_bytes(input_bytes)
    subprocess.run([*kernel_make(), "--no-print-directory", "-C", str(kernel), "durable-iso", f"DURABLE_STEP={step}",
                    f"EXTERNAL_USER_ELF={worker}", f"EXTERNAL_INPUT={input_path}", "EXTERNAL_READER_ELF=",
                    "EXTERNAL_READER_INPUT=", f"DURABLE_OPTIONS={options}", f"FILE_SERVER_ELF={server}"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    return pathlib.Path(kernel) / "build" / "durable" / f"absd-durable-{step}.iso"


def import_boots(kernel, image, plan, work, qemu=QEMU, root=ROOT, log=print):
    for index, (step, entries) in enumerate(plan, 1):
        iso = kernel_iso(kernel, step, root / "fixture-import.elf", input_bytes=em.stream(entries), work=work)
        serial = pathlib.Path(work) / f"import-{index:03d}.serial.log"
        status = subprocess.run([str(pathlib.Path(kernel) / "scripts" / "durable-boot.sh"), str(iso), str(image),
                                 str(serial), "900", *served_qemu(qemu)], check=True, capture_output=True,
                                text=True).stdout.strip()
        text = ssh_absd.captured(serial.read_bytes())
        if status != "3" or f"FIXTURE IMPORT OK files={len(entries)}" not in text:
            raise Failed(f"importer boot {index} (step {step}): QEMU status {status}\n{text[-1500:]}")
        log(f"operator image: importer boot {index}/{len(plan)} step {step}: {len(entries)} files")


def tree(image):
    region = absd_fs.fs_region(image, DEVICE_SECTORS)
    selected = absd_fs.select(region)
    return {path: absd_fs.content(region, selected, record)
            for path, record in absd_fs.tree(region, selected).items()
            if not path.endswith("/") and ssh_absd.record_is_file(region, selected, record)}


def verify(image, files):
    found = tree(image)
    for path, data in files:
        if found.get(path) != data:
            raise Failed(f"the host reader sees different bytes at {path}")
    return found


def git_head(path):
    try:
        return subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], check=True, capture_output=True,
                              text=True).stdout.strip()
    except subprocess.CalledProcessError:
        return "unknown"


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
    release = path.parent / "SOURCE-MANIFEST.toml"
    if not release.is_file():
        return "unknown"
    entry = next((c for c in tomllib.loads(release.read_text()).get("component", [])
                  if c.get("path") == path.name), None)
    tree = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD:./"], capture_output=True, text=True)
    dirty = subprocess.run(["git", "-C", str(path), "status", "--porcelain", "--", "."], capture_output=True,
                           text=True)
    if entry is None or tree.returncode or dirty.returncode:
        return "unknown"
    return entry["commit"] if tree.stdout.strip() == entry["tree"] and not dirty.stdout.strip() else "modified"


def manifest(out, kernel, files, release_id, root=ROOT):
    """`files` at their paths on the disk (the release layout)."""
    lines = [f"platform {identity(root)}", f"kernel {identity(kernel)}", f"release {release_id}",
             f"iso {hashlib.sha256((out / ISO).read_bytes()).hexdigest()}"]
    lines += [f"file {hashlib.sha256(data).hexdigest()} {path}" for path, data in sorted(files)]
    (out / "MANIFEST").write_text("\n".join(lines) + "\n")


def manifest_replace(out, files):
    """MANIFEST after a reconfiguration: each replaced file's line holds its
    new digest (a file new to the image gets a line), so the manifest keeps
    naming what the image holds."""
    path = out / "MANIFEST"
    lines = path.read_text().splitlines()
    head = [line for line in lines if not line.startswith("file ")]
    entries = {line.split(" ", 2)[2]: line.split(" ", 2)[1] for line in lines if line.startswith("file ")}
    entries.update({name: hashlib.sha256(data).hexdigest() for name, data in files})
    lines = head + [f"file {digest} {name}" for name, digest in sorted(entries.items())]
    tmp = out / "MANIFEST.new"
    tmp.write_text("\n".join(lines) + "\n")
    tmp.replace(path)


def check_platform_release(root, release_id):
    """The platform's commands/release must carry `release_id` (the id its
    programs were compiled with), as scripts/release.py build checks."""
    command = pathlib.Path(root) / "commands" / "release"
    if command.is_file() and release_id.encode() not in command.read_bytes():
        raise Failed(f"{root} was not built with ABSD_RELEASE_ID={release_id} (commands/release lacks the id); "
                     "set ABSD_RELEASE_ID to the id it was built with")


def build(kernel, out, keys, etc_dir=None, qemu=QEMU, root=ROOT, log=print, release_id=None):
    """Builds the image and the ISO into `out`: the system files in the
    release layout (with the record and the selection) first, then the
    site files (/etc, authorized_keys) in a boot of their own."""
    release_id = release_record.release_id_from_env() if release_id is None else release_record.check_id(release_id)
    check_platform_release(root, release_id)
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    image = out / IMAGE
    system = release_record.release_layout(system_files(root), release_id)
    site = etc_files(etc_dir, root) + [("/ssh/authorized_keys", authorized(keys))]
    with tempfile.TemporaryDirectory(prefix="operator-image-", dir=out) as work:
        # The disk will hold the host's private key (the file server makes
        # it at the first boot): readable by its owner only.
        with open(image, "wb") as handle:
            handle.truncate(0)
            handle.truncate(IMAGE_BYTES)
        image.chmod(0o600)
        plan = em.import_plan(system)
        import_boots(kernel, image, plan, work, qemu, root, log)
        # The site files: one more creating boot (step 2).
        import_boots(kernel, image, [(2, site)], work, qemu, root, log)
        verify(image, system + site)
        iso = kernel_iso(kernel, 0, root / "sshd.elf", options="net fsd served",
                         server=root / "absd-fsd.elf", work=work)
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
        release_record.parse_selected(found[release_record.SELECTED])
    except release_record.Malformed as error:
        raise Failed(f"{image}: {release_record.SELECTED} is malformed ({error.reason}); not reconfiguring")
    files = [(f"/etc/{p.name}", p.read_bytes()) for p in sorted(pathlib.Path(etc_dir).iterdir()) if p.is_file()]
    if keys is not None:
        files.append(("/ssh/authorized_keys", authorized(keys)))
    if not files:
        raise Failed(f"nothing to replace in {etc_dir}")
    with tempfile.TemporaryDirectory(prefix="operator-image-", dir=out) as work:
        import_boots(kernel, image, [(4, files)], work, qemu, root, log)
    verify(image, files)
    manifest_replace(out, files)
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
    b.add_argument("--qemu", default=QEMU)
    b.add_argument("--release-id", help="the release id the platform was built with "
                   "(default: ABSD_RELEASE_ID, else dev)")
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
            build(args.kernel, args.out, args.authorized_keys, args.etc, args.qemu, release_id=args.release_id)
        elif args.command == "reconfigure":
            reconfigure(args.kernel, args.out, args.etc, args.authorized_keys, args.qemu)
        else:
            print(*endpoint(args.image))
    except (Failed, absd_fs.Refused, release_record.Malformed) as error:
        print(f"operator image: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
