#!/usr/bin/env python3
"""ABSD releases on the host: build, install, stage, select, accept,
rollback, migrate, backup, restore (docs/RELEASE.md).

A release directory (`release.py build`) holds one release: its boot image
(absd-operator.iso), its tree (tree/bin, tree/share), its release record
(`release`), the site defaults it ships (site-defaults/etc, authorized
keys), the importer and services it was built with, and its manifest
(release-manifest.toml, scripts/release_manifest.py).

An operator directory (`--target OUT`) is one machine: absd-operator.img
(the disk), absd-operator.iso (the selected release's boot image),
releases/<id>/absd-operator.iso for each release the disk holds, TARGET
(the target's identity), RELEASES (the append-only ledger), receipts/.

Every write to the disk is an importer boot of the release's own importer
under the release's kernel (`--kernel`, a checkout at the manifest's
commit), each file one commit; every read is the host's independent reader
(scripts/absd_fs.py). Nothing here writes a filesystem by hand.
"""

import argparse
import datetime
import hashlib
import importlib.util
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import absd_fs  # noqa: E402
import absd_inputs  # noqa: E402
import release_record as rr  # noqa: E402
import ssh_absd  # noqa: E402


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_").replace(".py", ""), here / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


oi = load("operator_image.py")
em = load("exec-matrix.py")
smx = load("ssh-matrix.py")

ROOT = here.parent
# The record, the selection, and the layout: scripts/release_record.py.
IDENTITY = rr.IDENTITY
RECORD_HEADER = rr.RECORD_HEADER
ID_RE = rr.ID_RE
ISO = "absd-operator.iso"
IMAGE = "absd-operator.img"
LEDGER = "RELEASES"
TARGET = "TARGET"
RELEASE_DIRS = ("bin", "share")
SITE_ROOTS = ("/etc", "/ssh", "/home", "/var")
SLOTS = 2
QEMU = oi.QEMU


class Failed(Exception):
    pass


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def toml_dump(data):
    """One flat table per section; strings, ints, bools, lists of strings."""
    out = []
    for section, fields in data.items():
        out.append(f"[{section}]")
        for key, value in fields.items():
            if isinstance(value, bool):
                text = "true" if value else "false"
            elif isinstance(value, int):
                text = str(value)
            elif isinstance(value, (list, tuple)):
                text = "[" + ", ".join('"' + str(v).replace('"', '\\"') + '"' for v in value) + "]"
            else:
                text = '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'
            out.append(f"{key} = {text}")
        out.append("")
    return "\n".join(out)


# -- the release record -------------------------------------------------------

def record_text(release_id):
    try:
        return rr.record_text(release_id)
    except rr.Malformed as error:
        raise Failed(str(error)) from None


def parse_record(data):
    """The record's fields, or Failed with the file server's reason name."""
    try:
        return rr.parse_record(data)
    except rr.Malformed as error:
        raise Failed(error.reason) from None


# -- a release directory ------------------------------------------------------

class Release:
    def __init__(self, path):
        self.path = pathlib.Path(path).resolve()
        record = self.path / "release"
        if not record.is_file():
            raise Failed(f"{self.path}: no release record")
        self.fields = parse_record(record.read_bytes())
        self.id = self.fields["release"]
        for name in (ISO, "fixture-import.elf", "absd-fsd.elf", "absd-fsd-regenerate.elf", "sshd.elf", "tree"):
            if not (self.path / name).exists():
                raise Failed(f"{self.path}: missing {name}")
        self.manifest = self.path / "release-manifest.toml"

    def tree_files(self):
        """The release's tree and record in the release layout, exactly
        as release_record.release_layout places them (no selection). The
        record is the directory's own bytes, which are this tool's
        record_text unless the release was built with another identity."""
        base = self.path / "tree"
        logical = [(f"/{p.relative_to(base)}", p.read_bytes()) for p in sorted(base.rglob("*")) if p.is_file()]
        for path, _ in logical:
            if not any(path.startswith(root + "/") for root in rr.BOUND):
                raise Failed(f"{self.path}: tree/{path[1:]} is outside {' and '.join(rr.BOUND)}")
        files = rr.release_layout(logical, self.id, select=False)
        record_path = f"{rr.tree_root(self.id)}/release"
        assert files[-1][0] == record_path
        files[-1] = (record_path, (self.path / "release").read_bytes())
        return files

    def site_defaults(self):
        base = self.path / "site-defaults"
        files = [(f"/etc/{p.name}", p.read_bytes()) for p in sorted((base / "etc").iterdir()) if p.is_file()]
        keys = base / "authorized_keys"
        if keys.is_file():
            files.append(("/ssh/authorized_keys", keys.read_bytes()))
        return files

    def kernel_commit(self):
        if not self.manifest.is_file():
            raise Failed(f"{self.path}: missing release-manifest.toml")
        try:
            doc = tomllib.loads(self.manifest.read_text())
        except (OSError, ValueError) as error:
            raise Failed(f"{self.path}: malformed release manifest: {error}") from None
        if doc.get("schema") != "absd-release-manifest/1":
            raise Failed(f"{self.path}: unsupported release manifest schema")
        if any(not isinstance(doc.get(name), dict) for name in ("release", "identity", "source")):
            raise Failed(f"{self.path}: malformed release manifest tables")
        if doc.get("release", {}).get("id") != self.id:
            raise Failed(f"{self.path}: manifest release_mismatch")
        if any(type(doc["identity"].get(name)) is not int or doc["identity"][name] != self.fields[name]
               for name in IDENTITY):
            raise Failed(f"{self.path}: manifest identity_mismatch")
        commit = doc.get("source", {}).get("kernel_commit")
        if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise Failed(f"{self.path}: missing or invalid manifest kernel_commit")
        return commit


def check_kernel(kernel, release):
    kernel = pathlib.Path(kernel).resolve()
    if absd_inputs.is_kernel_source(kernel):
        raise Failed("the canonical kernel checkout is never a build target")
    if not (kernel / "Makefile").is_file():
        raise Failed(f"{kernel}: not a kernel checkout")
    head = oi.identity(kernel)
    want = release.kernel_commit()
    if head != want:
        raise Failed(f"kernel checkout is at {head[:12]}, release {release.id} was built from {want[:12]}")
    return kernel


# -- an operator directory ----------------------------------------------------

class Target:
    def __init__(self, out):
        self.out = pathlib.Path(out).resolve()
        self.image = self.out / IMAGE
        self.iso = self.out / ISO
        self.ledger = self.out / LEDGER
        self.receipts = self.out / "receipts"

    def identity(self):
        path = self.out / TARGET
        return path.read_text().strip() if path.is_file() else None

    def region(self):
        if not self.image.is_file():
            raise Failed(f"{self.image}: no disk image")
        return absd_fs.fs_region(self.image, oi.DEVICE_SECTORS)

    def fs_format(self):
        """The format word of the disk's filesystem, from its superblock
        magic (ABSDFSS<n>), or None when the region is blank."""
        region = self.region()
        if region is None:
            raise Failed(f"{self.image}: no layout (not an ABSD disk)")
        raw = region.read(0)
        if raw[:7] == b"ABSDFSS" and raw[7:8].isdigit():
            return int(raw[7:8])
        if not any(raw):
            return None
        raise Failed(f"{self.image}: the filesystem superblock is not ABSD's")

    def tree(self):
        try:
            return oi.tree(self.image)
        except absd_fs.Refused as error:
            raise Failed(f"{self.image}: the host reader refuses the disk: {error}")

    def selected(self, tree=None):
        tree = self.tree() if tree is None else tree
        data = tree.get("/absd/selected")
        if data is None:
            return None
        text = data.decode(errors="replace")
        if not text.endswith("\n") or not rr.valid_id(text[:-1]):
            raise Failed("malformed_selected")
        return text[:-1]

    def trees(self, tree=None):
        tree = self.tree() if tree is None else tree
        ids = set()
        for path in tree:
            m = re.match(r"^/releases/([a-z0-9.-]+)/", path)
            if m:
                ids.add(m.group(1))
        return sorted(ids)

    def record_of(self, release_id, tree=None):
        tree = self.tree() if tree is None else tree
        data = tree.get(f"/releases/{release_id}/release")
        if data is None:
            raise Failed("no_release_tree")
        return parse_record(data)

    def ledger_lines(self):
        return self.ledger.read_text().splitlines() if self.ledger.is_file() else []

    def ledger_append(self, action, release_id, detail=""):
        self.out.mkdir(parents=True, exist_ok=True)
        with open(self.ledger, "a") as handle:
            handle.write(f"{now()} {action} {release_id} {detail}".rstrip() + "\n")

    def last(self, action):
        for line in reversed(self.ledger_lines()):
            words = line.split()
            if len(words) >= 3 and words[1] == action:
                return words[2]
        return None

    def receipt(self, name, data):
        self.receipts.mkdir(parents=True, exist_ok=True)
        path = self.receipts / f"{name}-{now().replace(':', '')}.toml"
        path.write_text(toml_dump(data))
        return path

    def release_iso(self, release_id):
        return self.out / "releases" / release_id / ISO


# -- writing the disk: importer boots -----------------------------------------

def import_files(kernel, release, image, files, log, step_override=None):
    """Writes `files` with the release's importer, one boot per plan step."""
    plan = em.import_plan(files)
    if step_override is not None:
        plan = [(step_override, entries) for _, entries in plan]
    with tempfile.TemporaryDirectory(prefix="release-", dir=image.parent) as work:
        for index, (step, entries) in enumerate(plan, 1):
            iso = oi.kernel_iso(kernel, step, release.path / "fixture-import.elf", input_bytes=em.stream(entries),
                                work=work)
            serial = pathlib.Path(work) / f"import-{index:03d}.serial.log"
            status = subprocess.run([str(kernel / "scripts" / "durable-boot.sh"), str(iso), str(image), str(serial),
                                     "900", *QEMU.split()], check=True, capture_output=True, text=True).stdout.strip()
            text = ssh_absd.captured(serial.read_bytes())
            if status != "3" or f"FIXTURE IMPORT OK files={len(entries)}" not in text:
                raise Failed(f"importer boot {index} (step {step}): QEMU status {status}\n{text[-1500:]}")
            log(f"release: importer boot {index}/{len(plan)} step {step}: {len(entries)} files")
    return len(plan)


def verify_files(target, files):
    found = target.tree()
    for path, data in files:
        if found.get(path) != data:
            raise Failed(f"the host reader sees different bytes at {path}")
    return found


# -- booting and talking to the machine ---------------------------------------

class Boot:
    """One served boot of the target under QEMU, the way boot-operator.sh
    runs it, with the console in OUT/console-<name>.log."""

    def __init__(self, target, iso, name, port):
        self.target, self.iso, self.port = target, pathlib.Path(iso), port
        self.console = target.out / f"console-{name}.log"
        self.stderr_path = target.out / f"qemu-{name}.err"
        # A console left by an earlier boot of this name (or copied with
        # the target) would otherwise satisfy wait_ready before QEMU has
        # even opened the file.
        self.console.unlink(missing_ok=True)
        guest, guest_port = oi.endpoint(target.image)
        net = ".".join(guest.split(".")[:3]) + ".0/24"
        self.proc = subprocess.Popen(
            [*QEMU.split(), "-rtc", "base=utc", "-cdrom", str(self.iso),
             "-drive", f"file={target.image},format=raw,if=ide,index=0",
             "-netdev", f"user,id=n0,net={net},hostfwd=tcp:127.0.0.1:{port}-{guest}:{guest_port}",
             "-device", "e1000,netdev=n0", "-display", "none", "-serial", f"file:{self.console}",
             "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"],
            stdout=subprocess.DEVNULL, stderr=open(self.stderr_path, "wb"), start_new_session=True)
        self.client = smx.Client(target.out, port)

    def serial(self):
        try:
            return self.console.read_bytes().decode(errors="replace")
        except FileNotFoundError:
            return ""

    def worker(self):
        try:
            return ssh_absd.captured(self.console.read_bytes())
        except FileNotFoundError:
            return ""

    def wait_ready(self, release_id, timeout=300):
        """Served readiness: the file server's RELEASE OK for `release_id`
        and sshd's listener record; or the boot's end, reported."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            serial, worker = self.serial(), self.worker()
            if f"RELEASE OK release={release_id}" in serial and "SSH LISTENING" in worker:
                m = re.search(r"SSH HOST KEY (GENERATED|LOADED) (ssh-ed25519 \S+) (SHA256:\S+)", worker)
                if m:
                    self.client.trust(m.group(2))
                    return {"host_key": m.group(2), "fingerprint": m.group(3), "generated": m.group(1) == "GENERATED"}
            if self.proc.poll() is not None:
                raise Failed(f"the boot ended with QEMU status {self.proc.returncode} before readiness:\n"
                             f"{self.refusal_lines()}")
            time.sleep(0.5)
        raise Failed(f"no served readiness within {timeout}s:\n{self.refusal_lines()}")

    def refusal_lines(self):
        keep = ("RELEASE ", "FSD FAILED", "ABI REFUSED", "FSD PROTOCOL", "SERVED RECOVERY", "SERVED SHUTDOWN",
                "init: FAILED", "DURABLE status", "MACHINE ")
        lines = "\n".join(line for line in self.serial().splitlines() if any(k in line for k in keep))[-2000:]
        try:
            qemu = self.stderr_path.read_text(errors="replace").strip()
        except FileNotFoundError:
            qemu = ""
        return lines + (f"\nqemu: {qemu[-600:]}" if qemu else "")

    def ssh(self, key, command, stdin=b"", timeout=120):
        return self.client.run(key, command, stdin=stdin, timeout=timeout)

    def wait_end(self, timeout=240):
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.stop()
            raise Failed("the machine did not end in time")

    def stop(self):
        if self.proc.poll() is None:
            for pid in reversed(ssh_absd.descendants(self.proc.pid)):
                try:
                    subprocess.run(["kill", "-9", str(pid)], check=False)
                except OSError:
                    pass
            self.proc.kill()
            self.proc.wait()


# -- commands -----------------------------------------------------------------

def cmd_build(args, log=print):
    """A release directory from the platform's built artifacts."""
    release_id = args.id
    if not rr.valid_id(release_id):
        raise Failed(f"release id {release_id!r} is not [a-z0-9.-]{{1,64}}")
    root = pathlib.Path(args.platform or ROOT).resolve()
    kernel = pathlib.Path(args.kernel).resolve()
    release_cmd = root / "commands" / "release"
    if not release_cmd.is_file() or release_id.encode() not in release_cmd.read_bytes():
        raise Failed(f"{root} was not built with ABSD_RELEASE_ID={release_id} (commands/release lacks the id)")
    out = pathlib.Path(args.out).resolve()
    if out.exists() and any(out.iterdir()) and not args.replace:
        raise Failed(f"{out} exists; --replace to rebuild it")
    shutil.rmtree(out, ignore_errors=True)
    (out / "tree").mkdir(parents=True)
    for path, data in oi.system_files(root):
        assert path.startswith("/bin/") or path.startswith("/share/")
        dest = out / "tree" / path[1:]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    (out / "site-defaults" / "etc").mkdir(parents=True)
    for path, data in oi.etc_files(args.etc, root):
        (out / "site-defaults" / "etc" / path[len("/etc/"):]).write_bytes(data)
    if args.authorized_keys:
        (out / "site-defaults" / "authorized_keys").write_bytes(oi.authorized(args.authorized_keys))
    for name in ("fixture-import.elf", "absd-fsd.elf", "absd-fsd-regenerate.elf", "sshd.elf"):
        shutil.copyfile(root / name, out / name)
    (out / "release").write_text(record_text(release_id))
    with tempfile.TemporaryDirectory(prefix="release-", dir=out) as work:
        iso = oi.kernel_iso(kernel, 0, root / "sshd.elf", options="net fsd served", server=root / "absd-fsd.elf",
                            work=work)
        shutil.copyfile(iso, out / ISO)
    manifest_tool = here / "release_manifest.py"
    if manifest_tool.is_file():
        subprocess.run([sys.executable, str(manifest_tool), "build", "--kernel", str(kernel), "--platform", str(root),
                        str(out)], check=True)
    else:
        log("release: no release_manifest.py yet; the manifest is not written")
    log(f"RELEASE BUILT id={release_id} dir={out} iso={sha256_file(out / ISO)[:16]}")


def cmd_install(args, log=print):
    release = Release(args.release)
    kernel = check_kernel(args.kernel, release)
    target = Target(args.target)
    if target.image.exists() and not args.replace:
        raise Failed(f"{target.image} exists; --replace to install over it (the disk is destroyed)")
    if target.identity() not in (None, args.target_identity):
        raise Failed(f"target identity is {target.identity()!r}, not {args.target_identity!r}")
    target.out.mkdir(parents=True, exist_ok=True)
    files = release.tree_files() + release.site_defaults() + [(rr.SELECTED, rr.selected_bytes(release.id))]
    if not any(path == "/ssh/authorized_keys" for path, _ in files):
        raise Failed("the release ships no authorized keys and none were given; the machine would be unreachable")
    with open(target.image, "wb") as handle:
        handle.truncate(0)
        handle.truncate(oi.IMAGE_BYTES)
    target.image.chmod(0o600)
    boots = import_files(kernel, release, target.image, files, log)
    verify_files(target, files)
    fmt = target.fs_format()
    if fmt != release.fields["fs_format"]:
        raise Failed(f"the installed disk reads as format {fmt}, the release expects {release.fields['fs_format']}")
    target.release_iso(release.id).parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(release.path / ISO, target.release_iso(release.id))
    shutil.copyfile(release.path / ISO, target.iso)
    (target.out / TARGET).write_text(args.target_identity + "\n")
    receipt = target.receipt(f"install-{release.id}", {
        "install": {"release": release.id, "target": args.target_identity, "image": str(target.image),
                    "time_host": now(), "importer_boots": boots, "fs_format": fmt,
                    "write_gate": "QEMU raw image via the release's importer boots (durable-boot.sh, IDE master)",
                    "verification": "every installed file read back by scripts/absd_fs.py"},
        "identity": {k: release.fields[k] for k in IDENTITY},
        "artifacts": {"iso": sha256_file(release.path / ISO), "fixture_import": sha256_file(release.path / "fixture-import.elf"),
                      "absd_fsd": sha256_file(release.path / "absd-fsd.elf"), "sshd": sha256_file(release.path / "sshd.elf"),
                      "manifest": sha256_file(release.manifest) if release.manifest.is_file() else "none",
                      "files": hashlib.sha256(b"".join(hashlib.sha256(d).digest() for _, d in sorted(files))).hexdigest()},
    })
    target.ledger_append("installed", release.id, f"receipt={receipt.name}")
    target.ledger_append("selected", release.id)
    log(f"RELEASE INSTALLED id={release.id} target={args.target_identity} files={len(files)} receipt={receipt.name}")


def cmd_stage(args, log=print):
    release = Release(args.release)
    kernel = check_kernel(args.kernel, release)
    target = Target(args.target)
    fmt = target.fs_format()
    if fmt != release.fields["fs_format"]:
        raise Failed(f"the disk is format {fmt}; release {release.id} reads format {release.fields['fs_format']}: "
                     f"migrate first (release.py migrate)")
    tree = target.tree()
    present = target.trees(tree)
    selected = target.selected(tree)
    if release.id in present:
        raise Failed(f"release {release.id} is already on the disk; remove it first (release.py remove)")
    if len(present) >= SLOTS:
        raise Failed(f"the disk holds {len(present)} releases ({', '.join(present)}); at most {SLOTS}: "
                     f"remove one that is neither selected ({selected}) nor the last accepted")
    files = release.tree_files()
    boots = import_files(kernel, release, target.image, files, log)
    verify_files(target, files)
    after = target.tree()
    if target.selected(after) != selected:
        raise Failed("staging changed the selection; this must not happen")
    target.release_iso(release.id).parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(release.path / ISO, target.release_iso(release.id))
    receipt = target.receipt(f"stage-{release.id}", {
        "stage": {"release": release.id, "time_host": now(), "importer_boots": boots, "selected_before": selected,
                  "selected_after": target.selected(after), "state": "STAGED"},
        "identity": {k: release.fields[k] for k in IDENTITY},
    })
    target.ledger_append("staged", release.id, f"receipt={receipt.name}")
    log(f"RELEASE STAGED id={release.id} selected={selected} trees={','.join(target.trees(after))}")


def select_release(target, kernel, release, log, action):
    tree = target.tree()
    if release.id not in target.trees(tree):
        raise Failed(f"release {release.id} has no tree on the disk")
    target.record_of(release.id, tree)
    before = target.selected(tree)
    import_files(kernel, release, target.image, [(rr.SELECTED, rr.selected_bytes(release.id))], log,
                 step_override=4)
    after = target.tree()
    if target.selected(after) != release.id:
        raise Failed("the selection did not take")
    if not target.release_iso(release.id).is_file():
        shutil.copyfile(release.path / ISO, target.release_iso(release.id))
    shutil.copyfile(target.release_iso(release.id), target.iso)
    receipt = target.receipt(f"{action}-{release.id}", {
        action: {"release": release.id, "selected_before": before, "time_host": now(), "state": "BOOT_SELECTED",
                 "boot_image": str(target.iso)}})
    target.ledger_append(action, release.id, f"from={before} receipt={receipt.name}")
    log(f"RELEASE {action.upper()} id={release.id} from={before}: boot {target.iso}")


def cmd_select(args, log=print):
    release = Release(args.release)
    kernel = check_kernel(args.kernel, release)
    select_release(Target(args.target), kernel, release, log, "selected")


def cmd_rollback(args, log=print):
    """Back to the last accepted release, which must still have its tree."""
    target = Target(args.target)
    tree = target.tree()
    selected = target.selected(tree)
    accepted = [line.split()[2] for line in target.ledger_lines() if line.split()[1:2] == ["accepted"]]
    candidates = [rid for rid in reversed(accepted) if rid != selected]
    if not candidates:
        raise Failed("no accepted release other than the selected one in the ledger: nothing to roll back to")
    previous = candidates[0]
    if previous not in target.trees(tree):
        raise Failed(f"rollback target {previous} has no tree on the disk (removed, or the disk was migrated: "
                     f"restore the pre-migration image instead)")
    record = target.record_of(previous, tree)
    fmt = target.fs_format()
    if record["fs_format"] != fmt:
        raise Failed(f"rollback target {previous} reads format {record['fs_format']}, the disk is format {fmt}: "
                     f"a rollback across a migration is a restore of the pre-migration image")
    release = Release(args.release) if args.release else None
    if release is None or release.id != previous:
        raise Failed(f"give --release <the directory of {previous}> (its importer writes the selection)")
    kernel = check_kernel(args.kernel, release)
    select_release(target, kernel, release, log, "rolled_back")


def cmd_accept(args, log=print):
    """Boots the selected release and runs the acceptance checks."""
    target = Target(args.target)
    tree = target.tree()
    release_id = target.selected(tree)
    if release_id is None:
        raise Failed("no_selected_release")
    record = target.record_of(release_id, tree)
    if not target.iso.is_file():
        raise Failed(f"{target.iso}: no boot image")
    key = pathlib.Path(args.key).resolve()
    boot = Boot(target, target.iso, f"accept-{release_id}", args.port)
    checks = {}
    try:
        ready = boot.wait_ready(release_id)
        checks["served_ready"] = True
        rc, out, err = boot.ssh(key, "/bin/release")
        checks["release_command"] = out.decode(errors="replace").strip()
        if rc != 0 or f"release={release_id}" not in checks["release_command"]:
            raise Failed(f"release command: rc={rc} {out!r} {err!r}")
        marker = f"accept {release_id} {now()}\n".encode()
        rc, out, err = boot.ssh(key, "/bin/cat > /home/operator/.accept", stdin=marker)
        if rc != 0:
            raise Failed(f"write: rc={rc} {err!r}")
        rc, out, err = boot.ssh(key, "/bin/cat /home/operator/.accept")
        if rc != 0 or out != marker:
            raise Failed(f"read back: rc={rc} {out!r}")
        checks["write_read"] = True
        rc, out, err = boot.ssh(key, "shutdown")
        if rc != 0 or b"going down for halt" not in out:
            raise Failed(f"shutdown: rc={rc} {out!r} {err!r}")
        status = boot.wait_end()
        checks["halt_status"] = status
        serial = boot.serial()
        if status != 3 or "SERVED SHUTDOWN ESCALATED" in serial or "SERVED RECOVERY" in serial:
            raise Failed(f"the halt was not orderly (status {status}):\n{boot.refusal_lines()}")
    finally:
        boot.stop()
    after = target.tree()
    if after.get("/home/operator/.accept") != marker:
        raise Failed("the acceptance marker is not in the committed image")
    receipt = target.receipt(f"accept-{release_id}", {
        "accept": {"release": release_id, "time_host": now(), "state": "ACCEPTED", "console": boot.console.name,
                   "host_key_fingerprint": ready["fingerprint"], "halt_status": checks["halt_status"]},
        "identity": {k: record[k] for k in IDENTITY},
        "checks": {"served_ready": True, "release_command": checks["release_command"], "write_read": True,
                   "no_escalation": True, "image_validated": True},
    })
    target.ledger_append("accepted", release_id, f"receipt={receipt.name}")
    log(f"RELEASE ACCEPTED id={release_id} receipt={receipt.name}")


def host_key_fingerprint(seed):
    """OpenSSH's SHA256 fingerprint of the ed25519 key the seed makes."""
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    public = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + public
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def cmd_backup(args, log=print):
    """A halted backup: the image copied and validated, with its identity."""
    target = Target(args.target)
    dest = pathlib.Path(args.backup).resolve()
    if dest.exists() and any(dest.iterdir()):
        raise Failed(f"{dest} is not empty")
    tree = target.tree()
    fmt = target.fs_format()
    selected = target.selected(tree)
    region = target.region()
    image = absd_fs.select(region)
    dest.mkdir(parents=True, exist_ok=True)
    copy = dest / IMAGE
    shutil.copyfile(target.image, copy)
    copy.chmod(0o600)
    if sha256_file(copy) != sha256_file(target.image):
        raise Failed("the copy differs from the disk")
    found = oi.tree(copy)
    if found != tree:
        raise Failed("the copy's tree differs from the disk's")
    seed = tree.get("/ssh/host_ed25519_seed")
    files_digest = hashlib.sha256(b"".join(p.encode() + b"\0" + hashlib.sha256(d).digest()
                                           for p, d in sorted(tree.items()))).hexdigest()
    record = {
        "backup": {"time_host": now(), "kind": "halted", "live_backup": "unsupported",
                   "source_image": str(target.image), "target": target.identity() or "unknown"},
        "disk": {"image_sha256": sha256_file(copy), "fs_format": fmt, "fs_id": image["fs_id"],
                 "commit_sequence": image["seq"], "files": len(tree), "files_digest": files_digest},
        "release": {"selected": selected or "none", "trees": target.trees(tree)},
        "identity": {"host_key_fingerprint": host_key_fingerprint(seed) if seed else "none (no host key yet)"},
    }
    (dest / "backup.toml").write_text(toml_dump(record))
    for rid in target.trees(tree):
        iso = target.release_iso(rid)
        if iso.is_file():
            (dest / "releases" / rid).mkdir(parents=True, exist_ok=True)
            shutil.copyfile(iso, dest / "releases" / rid / ISO)
    target.ledger_append("backup", selected or "none", f"dir={dest}")
    log(f"BACKUP OK dir={dest} selected={selected} format={fmt} seq={image['seq']} files={len(tree)}")


def read_toml_flat(path):
    """The flat tables toml_dump writes (tomllib when present)."""
    try:
        import tomllib
        return tomllib.loads(pathlib.Path(path).read_text())
    except ImportError:
        raise Failed("python3 without tomllib")


def validate_backup(backup):
    backup = pathlib.Path(backup).resolve()
    meta_path = backup / "backup.toml"
    if not meta_path.is_file():
        raise Failed(f"{backup}: no backup.toml")
    meta = read_toml_flat(meta_path)
    copy = backup / IMAGE
    if not copy.is_file():
        raise Failed(f"{backup}: no image")
    if copy.stat().st_size != oi.IMAGE_BYTES:
        raise Failed(f"{copy}: {copy.stat().st_size} bytes, not an operator image ({oi.IMAGE_BYTES})")
    if sha256_file(copy) != meta["disk"]["image_sha256"]:
        raise Failed("the backup image's digest is not the one backup.toml records")
    scratch = Target(backup)
    fmt = scratch.fs_format()
    if fmt != meta["disk"]["fs_format"]:
        raise Failed(f"the backup image is format {fmt}, backup.toml says {meta['disk']['fs_format']}")
    if fmt not in (IDENTITY["fs_format"],):
        raise Failed(f"the backup image is filesystem format {fmt}; this release reads {IDENTITY['fs_format']}")
    try:
        tree = oi.tree(copy)
    except absd_fs.Refused as error:
        raise Failed(f"the host reader refuses the backup image: {error}")
    region = absd_fs.fs_region(copy, oi.DEVICE_SECTORS)
    image = absd_fs.select(region)
    if image["fs_id"] != meta["disk"]["fs_id"] or image["seq"] != meta["disk"]["commit_sequence"]:
        raise Failed("the backup image's filesystem identity or sequence is not the one backup.toml records")
    selected = scratch.selected(tree)
    if selected != meta["release"]["selected"]:
        raise Failed(f"the backup selects {selected}, backup.toml says {meta['release']['selected']}")
    scratch.record_of(selected, tree)
    return meta, tree, selected


def cmd_restore(args, log=print):
    target = Target(args.target)
    meta, tree, selected = validate_backup(args.backup)
    backup = pathlib.Path(args.backup).resolve()
    iso = backup / "releases" / selected / ISO
    if not iso.is_file() and not target.release_iso(selected).is_file():
        raise Failed(f"no boot image for the selected release {selected} in the backup or the target")
    target.out.mkdir(parents=True, exist_ok=True)
    if target.image.exists() and not args.replace:
        raise Failed(f"{target.image} exists; --replace to restore over it")
    temp = target.image.with_suffix(".img.restoring")
    shutil.copyfile(backup / IMAGE, temp)
    temp.chmod(0o600)
    if sha256_file(temp) != meta["disk"]["image_sha256"]:
        raise Failed("the restored copy differs from the backup")
    temp.replace(target.image)
    if iso.is_file():
        target.release_iso(selected).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(iso, target.release_iso(selected))
    shutil.copyfile(target.release_iso(selected), target.iso)
    if not (target.out / TARGET).is_file():
        (target.out / TARGET).write_text((args.target_identity or meta["backup"]["target"]) + "\n")
    receipt = target.receipt(f"restore-{selected}", {
        "restore": {"backup": str(backup), "release": selected, "time_host": now(), "clone": bool(args.clone),
                    "image_sha256": meta["disk"]["image_sha256"], "fs_format": meta["disk"]["fs_format"]}})
    target.ledger_append("restored", selected, f"from={backup} receipt={receipt.name}")
    log(f"RESTORE COPIED release={selected} format={meta['disk']['fs_format']} seq={meta['disk']['commit_sequence']}")
    if args.clone:
        clone_identity(target, selected, args, log)


def clone_identity(target, release_id, args, log):
    """A second machine from a restored image: a new host key, made by the
    release's regenerate image, then an orderly halt."""
    if not args.release or not args.kernel:
        raise Failed("--clone needs --release <directory of the selected release> and --kernel")
    release = Release(args.release)
    if release.id != release_id:
        raise Failed(f"--release is {release.id}, the restored image selects {release_id}")
    kernel = check_kernel(args.kernel, release)
    key = pathlib.Path(args.key).resolve()
    before = target.tree().get("/ssh/host_ed25519_seed")
    with tempfile.TemporaryDirectory(prefix="release-", dir=target.out) as work:
        iso = oi.kernel_iso(kernel, 0, release.path / "sshd.elf", options="net fsd served",
                            server=release.path / "absd-fsd-regenerate.elf", work=work)
        boot = Boot(target, iso, f"clone-{release_id}", args.port)
        try:
            ready = boot.wait_ready(release_id)
            if not ready["generated"] or "FSD HOST KEY GENERATED" not in boot.serial():
                raise Failed("the regenerate image did not generate a host key")
            rc, out, err = boot.ssh(key, "shutdown")
            if rc != 0:
                raise Failed(f"shutdown after regeneration: rc={rc} {err!r}")
            if boot.wait_end() != 3:
                raise Failed("the clone boot did not halt in order")
        finally:
            boot.stop()
    after = target.tree().get("/ssh/host_ed25519_seed")
    if not after or after == before:
        raise Failed("the host key seed did not change")
    target.ledger_append("cloned", release_id, f"host_key={host_key_fingerprint(after)}")
    log(f"CLONE OK release={release_id} host_key={host_key_fingerprint(after)}")


def cmd_migrate(args, log=print):
    """Read the old image, make a new one with the release's importer, copy
    the site state, install the release, validate, switch; keep the old."""
    release = Release(args.release)
    kernel = check_kernel(args.kernel, release)
    target = Target(args.target)
    old_format = target.fs_format()
    if old_format == release.fields["fs_format"]:
        raise Failed(f"the disk is already format {old_format}; use stage/select")
    old_tree = target.tree()
    site = [(path, data) for path, data in sorted(old_tree.items())
            if any(path == root or path.startswith(root + "/") for root in SITE_ROOTS)]
    files = release.tree_files() + site + [(rr.SELECTED, rr.selected_bytes(release.id))]
    new_image = target.image.with_suffix(".img.migrating")
    with open(new_image, "wb") as handle:
        handle.truncate(0)
        handle.truncate(oi.IMAGE_BYTES)
    new_image.chmod(0o600)
    scratch = Target(target.out)
    scratch.image = new_image
    boots = import_files(kernel, release, new_image, files, log)
    found = scratch.tree()
    for path, data in files:
        if found.get(path) != data:
            raise Failed(f"the migrated image differs at {path}")
    if scratch.fs_format() != release.fields["fs_format"]:
        raise Failed("the migrated image is not the release's format")
    retained = target.image.with_name(f"{IMAGE}.pre-migration-format{old_format}-{now().replace(':', '')}")
    target.image.replace(retained)
    new_image.replace(target.image)
    target.release_iso(release.id).parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(release.path / ISO, target.release_iso(release.id))
    shutil.copyfile(release.path / ISO, target.iso)
    receipt = target.receipt(f"migrate-{release.id}", {
        "migrate": {"release": release.id, "from_format": old_format, "to_format": release.fields["fs_format"],
                    "retained_image": str(retained), "site_files": len(site), "importer_boots": boots,
                    "time_host": now(), "mtime_of_copied_objects": 0,
                    "rollback": "restore the retained image and boot the previous release's image"}})
    target.ledger_append("migrated", release.id, f"from_format={old_format} retained={retained.name} receipt={receipt.name}")
    target.ledger_append("selected", release.id, "by migration")
    log(f"MIGRATED to format {release.fields['fs_format']} release={release.id} site_files={len(site)} retained={retained.name}")


def cmd_remove(args, log=print):
    """Removes a release tree that is neither selected nor last accepted."""
    release = Release(args.release)
    kernel = check_kernel(args.kernel, release)
    target = Target(args.target)
    tree = target.tree()
    rid = args.id
    if rid == target.selected(tree) or rid == target.last("accepted"):
        raise Failed(f"{rid} is selected or the last accepted release; not removable")
    if rid not in target.trees(tree):
        raise Failed(f"{rid} has no tree on the disk")
    # Removal is an importer step 5 (remove a tree) if the importer has one;
    # until then removal is not supported and says so.
    raise Failed("removing a release tree needs an importer removal step; not provided in this gate")


def cmd_status(args, log=print):
    target = Target(args.target)
    tree = target.tree()
    log(f"target={target.identity()} image={target.image} format={target.fs_format()} selected={target.selected(tree)} "
        f"trees={','.join(target.trees(tree))} last_accepted={target.last('accepted')} files={len(tree)}")
    for line in target.ledger_lines()[-10:]:
        log("  " + line)


def cmd_verify_backup(args, log=print):
    meta, tree, selected = validate_backup(args.backup)
    log(f"BACKUP VALID selected={selected} format={meta['disk']['fs_format']} files={len(tree)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    def common(p, release=True, kernel=True, target=True):
        if release:
            p.add_argument("--release", required=False)
        if kernel:
            p.add_argument("--kernel", required=False)
        if target:
            p.add_argument("--target", required=True)

    p = sub.add_parser("build")
    p.add_argument("--kernel", required=True)
    p.add_argument("--platform")
    p.add_argument("--id", required=True)
    p.add_argument("--authorized-keys")
    p.add_argument("--etc")
    p.add_argument("--replace", action="store_true")
    p.add_argument("out")
    p = sub.add_parser("install"); common(p); p.add_argument("--target-identity", required=True); p.add_argument("--replace", action="store_true")
    p = sub.add_parser("stage"); common(p)
    p = sub.add_parser("select"); common(p)
    p = sub.add_parser("rollback"); common(p)
    p = sub.add_parser("accept"); common(p, release=False, kernel=False); p.add_argument("--key", required=True); p.add_argument("--port", type=int, default=2222)
    p = sub.add_parser("backup"); common(p, release=False, kernel=False); p.add_argument("backup")
    p = sub.add_parser("verify-backup"); p.add_argument("backup")
    p = sub.add_parser("restore"); common(p); p.add_argument("backup"); p.add_argument("--replace", action="store_true"); p.add_argument("--clone", action="store_true"); p.add_argument("--key"); p.add_argument("--port", type=int, default=2222); p.add_argument("--target-identity")
    p = sub.add_parser("migrate"); common(p)
    p = sub.add_parser("remove"); common(p); p.add_argument("--id", required=True)
    p = sub.add_parser("status"); common(p, release=False, kernel=False)
    args = ap.parse_args()
    for name, needs in (("install", ("release", "kernel")), ("stage", ("release", "kernel")), ("select", ("release", "kernel")),
                        ("migrate", ("release", "kernel")), ("remove", ("release", "kernel"))):
        if args.command == name:
            for need in needs:
                if getattr(args, need, None) is None:
                    ap.error(f"{name} needs --{need}")
    try:
        globals()["cmd_" + args.command.replace("-", "_")](args)
    except (Failed, absd_fs.Refused, oi.Failed) as error:
        print(f"release: refused: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
