#!/usr/bin/env python3
"""ABSD releases on the host: build, install, stage, select, accept,
rollback, migrate, backup, restore, remove, reconfigure (docs/RELEASE.md).

A release directory (`release.py build`) holds one release: its boot image
(absd-operator.iso), its tree (tree/bin, tree/share), its release record
(`release`), the site defaults it ships (site-defaults/etc, authorized
keys), the importer and services it was built with, and its manifest
(release-manifest.toml, scripts/release_manifest.py).

An operator directory (`--target OUT`) is one machine: absd-operator.img
(the disk), absd-operator.iso (the selected release's boot image),
releases/<id>/absd-operator.iso for each release the disk holds, with
the image that selects it (select.iso, durable-boot.sh, select.toml: the
selection cache), TARGET (the target's identity), RELEASES (the
append-only ledger), receipts/.

Ordinary filesystem writes are importer boots of the release's own importer
under the release's kernel (`--kernel`, a checkout at the manifest's
commit), each file one commit; every read is the host's independent reader
(scripts/absd_fs.py). The shared offline guard transaction writes only its
reserved fixed sector before/after these boots; it never edits filesystem
metadata or ordinary file content.
"""

import argparse
import contextlib
import datetime
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
import time
import uuid

import tomllib

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import absd_fs  # noqa: E402
import absd_inputs  # noqa: E402
import operator_geometry as geometry  # noqa: E402
import release_record as rr  # noqa: E402
import recovery_point
import ssh_absd  # noqa: E402
import storage_fence_host
import storage_fence_resume
import storage_fence_state
from served_ram import served_qemu
from e1000_rx import wait_rx_setup, RxSetupFailed


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
# Explicit release-tool selection; operator_image has its own --qemu option.
QEMU = os.environ.get("ABSD_RELEASE_QEMU", oi.QEMU)


class Failed(Exception):
    pass


class StageFailed(Failed):
    """A caught staging failure, with its conservative effect disposition."""

    def __init__(self, message, state):
        super().__init__(message)
        self.state = state


class ReconfigureFailed(StageFailed):
    """A caught reconfiguration failure, with its outcome state
    (RECONFIGURE_STATES)."""


class ImportFailed(Failed):
    def __init__(self, message, context):
        super().__init__(message)
        self.import_context = context


def disk_sectors(image):
    """storage_fence_resume.image_sectors as this tool's refusal."""
    try:
        return storage_fence_resume.image_sectors(image)
    except storage_fence_resume.Refused as error:
        raise Failed(str(error)) from None


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def toml_string(value):
    # TOML basic strings forbid raw DEL and Unicode surrogate code points.
    # argv/OSError can contain surrogateescape paths; serial text can carry DEL.
    scalar = "".join("\ufffd" if 0xD800 <= ord(char) <= 0xDFFF else char for char in str(value))
    return json.dumps(scalar, ensure_ascii=False).replace("\x7f", "\\u007f")


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
                text = "[" + ", ".join(toml_string(v) for v in value) + "]"
            else:
                text = toml_string(value)
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
        record_text unless the release was built with another identity.
        Not checked against the manifest: importer operations use
        verified_tree_files."""
        logical, record = self._tree_bytes()
        return self._layout(logical, record)

    def verified_tree_files(self):
        """tree_files, with the exact bytes it returns checked against the
        manifest's artifact digests first (section 3 of docs/RELEASE.md):
        every tree file and the record must be listed with the digest of
        the bytes read here, and every tree file the manifest lists must be
        present. The bytes written are the bytes verified; refuses
        `manifest_mismatch` naming each problem, before any write."""
        logical, record = self._tree_bytes()
        digests = self.artifact_digests()
        problems = []
        seen = set()
        for path, data in logical + [(None, record)]:
            name = "release" if path is None else f"tree{path}"
            seen.add(name)
            want = digests.get(name)
            if want is None:
                problems.append(f"unrecorded {name}")
            elif hashlib.sha256(data).hexdigest() != want:
                problems.append(f"digest {name}")
        problems += [f"missing {name}" for name in sorted(digests)
                     if (name.startswith("tree/") or name == "release") and name not in seen]
        if problems:
            raise Failed(f"{self.path}: manifest_mismatch {', '.join(problems)}")
        return self._layout(logical, record)

    def verified_site_defaults(self):
        """site_defaults, each file checked against its manifest digest
        (site-defaults/etc/<name>, site-defaults/authorized_keys), and every
        site default the manifest lists present: install writes these."""
        files = self.site_defaults()
        digests = self.artifact_digests()
        problems, seen = [], set()
        for path, data in files:
            name = ("site-defaults/" + path[len('/ssh/'):] if path.startswith("/ssh/")
                    else f"site-defaults/etc/{path[len('/etc/'):]}")
            seen.add(name)
            want = digests.get(name)
            if want is None:
                problems.append(f"unrecorded {name}")
            elif hashlib.sha256(data).hexdigest() != want:
                problems.append(f"digest {name}")
        problems += [f"missing {name}" for name in sorted(digests)
                     if name.startswith("site-defaults/") and name not in seen]
        if problems:
            raise Failed(f"{self.path}: manifest_mismatch {', '.join(problems)}")
        return files

    def verified_copy(self, name, dest):
        """Copies one release-directory file to `dest` and checks the copy,
        the bytes that will actually be used, against the manifest; a
        mismatching copy is removed and refused `manifest_mismatch`."""
        want = self.artifact_digests().get(name)
        if want is None:
            raise Failed(f"{self.path}: manifest_mismatch unrecorded {name}")
        dest = pathlib.Path(dest)
        shutil.copyfile(self.path / name, dest)
        if sha256_file(dest) != want:
            dest.unlink()
            raise Failed(f"{self.path}: manifest_mismatch digest {name} (as copied to {dest})")
        return dest

    def verify_artifact(self, name):
        """One file of the release directory (the boot image, an importer
        ELF) against its manifest digest; refuses `manifest_mismatch`."""
        want = self.artifact_digests().get(name)
        if want is None:
            raise Failed(f"{self.path}: manifest_mismatch unrecorded {name}")
        if sha256_file(self.path / name) != want:
            raise Failed(f"{self.path}: manifest_mismatch digest {name}")

    def _tree_bytes(self):
        base = self.path / "tree"
        logical = [(f"/{p.relative_to(base)}", p.read_bytes()) for p in sorted(base.rglob("*")) if p.is_file()]
        for path, _ in logical:
            if not any(path.startswith(root + "/") for root in rr.BOUND):
                raise Failed(f"{self.path}: tree/{path[1:]} is outside {' and '.join(rr.BOUND)}")
        return logical, (self.path / "release").read_bytes()

    def _layout(self, logical, record):
        files = rr.release_layout(logical, self.id, select=False)
        record_path = f"{rr.tree_root(self.id)}/release"
        assert files[-1][0] == record_path
        files[-1] = (record_path, record)
        return files

    def site_defaults(self):
        base = self.path / "site-defaults"
        files = [(f"/etc/{p.name}", p.read_bytes()) for p in sorted((base / "etc").iterdir()) if p.is_file()]
        keys = base / "authorized_keys"
        if keys.is_file():
            files.append(("/ssh/authorized_keys", keys.read_bytes()))
        local = base / "local-login"
        if local.is_file():
            files += oi.local_login_files(self.path, verifier=local)
        return files

    def _manifest_doc(self):
        if not self.manifest.is_file():
            raise Failed(f"{self.path}: missing release-manifest.toml")
        try:
            return tomllib.loads(self.manifest.read_text())
        except (OSError, ValueError) as error:
            raise Failed(f"{self.path}: malformed release manifest: {error}") from None

    def artifact_digests(self):
        """{release-directory path: sha256} from the manifest's
        artifacts.files (scripts/release_manifest.py build). A manifest
        without that table cannot verify anything and is refused."""
        artifacts = self._manifest_doc().get("artifacts")
        files = artifacts.get("files") if isinstance(artifacts, dict) else None
        if not isinstance(files, dict) or not files:
            raise Failed(f"{self.path}: manifest_unverifiable no artifacts.files table")
        out = {}
        for name, entry in files.items():
            digest = entry.get("sha256") if isinstance(entry, dict) else None
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise Failed(f"{self.path}: manifest_unverifiable malformed digest for {name}")
            out[name] = digest
        return out

    def kernel_commit(self):
        doc = self._manifest_doc()
        # Installed releases keep the manifest they were built with; the
        # fields read here are the same in /1 and /2.
        if doc.get("schema") not in ("absd-release-manifest/1", "absd-release-manifest/2"):
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
    if kernel is None:
        raise Failed(f"give --kernel <a kernel checkout at {release.kernel_commit()[:12]}> (release {release.id})")
    kernel = pathlib.Path(kernel).resolve()
    if absd_inputs.is_kernel_source(kernel):
        raise Failed("the canonical kernel checkout is never a build target")
    if not (kernel / "Makefile").is_file():
        raise Failed(f"{kernel}: not a kernel checkout")
    want = release.kernel_commit()
    expected_snapshot = release._manifest_doc().get("source", {}).get("kernel_snapshot")
    try:
        actual_snapshot = oi.public_source_identity(kernel)
    except oi.Failed as error:
        raise Failed(f"kernel public source mapping refused: {error}") from None
    if expected_snapshot is not None:
        if (not isinstance(expected_snapshot, dict) or actual_snapshot != expected_snapshot
                or actual_snapshot.get("upstream_commit") != want):
            raise Failed("kernel public source snapshot differs from release mapping")
        return kernel
    if actual_snapshot is not None:
        raise Failed("kernel public source snapshot lacks corresponding release mapping")
    head = oi.identity(kernel)
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
        # The disk's own geometry (coordination record #28), never the creation size.
        return absd_fs.fs_region(self.image, disk_sectors(self.image))

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
        path.write_text(toml_dump(data), encoding="utf-8")
        return path

    def release_iso(self, release_id):
        return self.out / "releases" / release_id / ISO

    @contextlib.contextmanager
    def mutation(self, *, replacing=False):
        """The hand-off boundary with operator-authorized recovery
        (docs/WRITABLE-ENTRY.md "Operator-authorized resume"): every command
        that writes the image or replaces its pathname takes the recovery
        lock for its duration (`tool_busy`), takes and releases QEMU's OFD
        range lock once before any boot of its own (`image_locked`), and
        refuses `recovery_pending` while a record is on the disk or an
        unsuperseded active authorization exists. A replacing command
        (install --replace, restore --replace, migrate) tolerates an image
        the host reader cannot read."""
        try:
            with storage_fence_resume.mutation(self.out, self.image, replacing=replacing):
                yield
        except storage_fence_resume.Refused as error:
            raise Failed(str(error)) from None


# -- writing the disk: importer boots -----------------------------------------

def run_boot(script, iso, image, serial):
    """One durable boot of `iso` against `image` (the kernel's
    durable-boot.sh, or the copy of it a selection cache keeps); QEMU's
    status as text."""
    return subprocess.run([str(script), str(iso), str(image), str(serial), "900", *served_qemu(QEMU)], check=True,
                          capture_output=True, text=True).stdout.strip()


def importer_failure_context(index, count, step, entries, text, plan_record=None):
    context = {"boot": index, "boot_count": count, "step": step,
               "planned_entries": len(entries), "entry_identified": False}
    if plan_record is not None:
        context["plan_json"] = json.dumps(plan_record, sort_keys=True)
    matches = re.findall(r"^FIXTURE ENTRY index=(\d+) path_hex=([0-9a-f]+) step=(\d+)$", text, re.M)
    path = None
    if matches:
        entry, encoded, observed_step = matches[-1]
        entry = int(entry)
        try:
            path = bytes.fromhex(encoded).decode("utf-8")
        except (ValueError, UnicodeError):
            path = None
        if int(observed_step) == step and 1 <= entry <= len(entries) and path == entries[entry - 1][0]:
            context.update(entry_identified=True, entry=entry, entry_path=path)
            if plan_record is not None:
                detail = plan_record["files"][entry - 1]
                for name in ("prefix_bytes", "prefix_sha256", "chunk_bytes", "chunk_sha256",
                             "result_bytes", "result_sha256", "temporary_blocks"):
                    context[name] = detail[name]
    temps = []
    for encoded, final_hex, fsid, serial, kind in re.findall(
            r"^FIXTURE TEMP path_hex=([0-9a-f]+) final_hex=([0-9a-f]+) fs_id=(\d+) serial=(\d+) kind=(Dir|File)$",
            text, re.M):
        try:
            temp_path = bytes.fromhex(encoded).decode("utf-8")
            final = bytes.fromhex(final_hex).decode("utf-8")
        except (ValueError, UnicodeError):
            continue
        if path is not None and final == path:
            temps.append({"path": temp_path, "fs_id": int(fsid), "serial": int(serial), "kind": kind})
    context["temporary_paths"] = [record["path"] for record in temps]
    context["temporary_records_json"] = json.dumps(temps, sort_keys=True)
    return context


def importer_boot(script, iso, image, work, index, count, step, entries, log, plan_record=None, *, fresh=False):
    try:
        with storage_fence_host.mutation(image, fresh=fresh):
            return _importer_boot(script, iso, image, work, index, count, step, entries, log, plan_record)
    except (ValueError, absd_fs.Refused) as error:
        raise Failed(str(error)) from error


def _importer_boot(script, iso, image, work, index, count, step, entries, log, plan_record):
    serial = pathlib.Path(work) / f"import-{index:03d}.serial.log"
    def captured_context():
        text = ssh_absd.captured(serial.read_bytes()) if serial.is_file() else ""
        return text, importer_failure_context(index, count, step, entries, text, plan_record)
    try:
        status = run_boot(script, iso, image, serial)
    except (Exception, KeyboardInterrupt) as error:
        text, context = captured_context()
        if isinstance(error, KeyboardInterrupt):
            error.import_context = context
            raise
        if isinstance(error, subprocess.CalledProcessError):
            message = (f"importer boot {index} (step {step}): {script.name} exited {error.returncode}: "
                       f"{(error.stderr or '').strip()[-600:]}")
        else:
            message = f"importer boot {index} (step {step}): {error}"
        raise ImportFailed(message, context) from error
    text, context = captured_context()
    if status != "3" or f"FIXTURE IMPORT OK files={len(entries)}" not in text:
        raise ImportFailed(f"importer boot {index} (step {step}): QEMU status {status}\n{text[-1500:]}", context)
    log(f"release: importer boot {index}/{count} step {step}: {len(entries)} files")


def import_files(kernel, release, image, files, log, step_override=None, *, fresh=False):
    """Writes `files` with the release's importer, one boot per plan step."""
    plan = em.import_plan(files)
    if step_override is not None:
        plan = [(step_override, entries) for _, entries in plan]
    records = [None] * len(plan)
    if step_override != 5:
        records, capacity = em.inspect_import_plan(image, plan)
        log("RELEASE IMPORT CAPACITY " + json.dumps(capacity, sort_keys=True))
        log("RELEASE IMPORT PLAN " + json.dumps(records, sort_keys=True))
    with tempfile.TemporaryDirectory(prefix="release-", dir=image.parent) as work:
        # The kernel build embeds a private copy checked against the manifest,
        # not the release directory's file, which could change after a check.
        importer = release.verified_copy("fixture-import.elf", pathlib.Path(work) / "fixture-import.elf")
        for index, (step, entries) in enumerate(plan, 1):
            iso = oi.kernel_iso(kernel, step, importer, input_bytes=em.stream(entries), work=work)
            importer_boot(kernel / "scripts" / "durable-boot.sh", iso, image, work, index, len(plan), step, entries,
                          log, plan_record=records[index - 1], fresh=fresh)
    return len(plan)


# -- the selection cache: rollback without a build host -----------------------
#
# A selection is one importer step 4 boot whose input is the selection
# itself, so the image that selects a release is fixed once the release and
# its kernel are: install, stage and migrate build it while they have the
# kernel, and keep it in OUT/releases/<id>/ beside the release's boot image,
# with the kernel's durable-boot.sh that runs it. select.toml, written last,
# names both files and their digests; rollback without --kernel boots that
# image and nothing else, and refuses by name when the cache is missing or
# differs from its record. It never builds one instead.

SELECT_ISO = "select.iso"
SELECT_BOOT = "durable-boot.sh"
SELECT_RECORD = "select.toml"


def selection_entries(release_id):
    plan = em.import_plan([(rr.SELECTED, rr.selected_bytes(release_id))])
    assert len(plan) == 1
    return plan[0][1]


def build_select_cache(kernel, release, work):
    """The step-4 image that selects `release`, built by `kernel` (checked),
    and the kernel's boot script, copied into `work`: nothing in OUT yet."""
    entries = selection_entries(release.id)
    if not (kernel / "scripts" / "durable-boot.sh").is_file():
        raise Failed(f"{kernel}: no scripts/durable-boot.sh to keep with the selection image")
    importer = release.verified_copy("fixture-import.elf", pathlib.Path(work) / "select-importer.elf")
    iso = oi.kernel_iso(kernel, 4, importer, input_bytes=em.stream(entries), work=work)
    staged = pathlib.Path(work) / SELECT_ISO
    shutil.copyfile(iso, staged)
    script = pathlib.Path(work) / SELECT_BOOT
    shutil.copyfile(kernel / "scripts" / "durable-boot.sh", script)
    script.chmod(0o755)
    return {"release": release, "iso": staged, "script": script}


def install_select_cache(target, built):
    """Moves a built cache into OUT/releases/<id>/; its record last."""
    release = built["release"]
    directory = target.out / "releases" / release.id
    directory.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(built["iso"], directory / SELECT_ISO)
    shutil.copyfile(built["script"], directory / SELECT_BOOT)
    (directory / SELECT_BOOT).chmod(0o755)
    fields = {"release": release.id, "step": 4, "iso": SELECT_ISO, "iso_sha256": sha256_file(directory / SELECT_ISO),
              "boot_script": SELECT_BOOT, "boot_script_sha256": sha256_file(directory / SELECT_BOOT),
              "selection_sha256": hashlib.sha256(rr.selected_bytes(release.id)).hexdigest(),
              "importer_sha256": sha256_file(release.path / "fixture-import.elf"),
              "kernel_commit": release.kernel_commit(), "time_host": now()}
    temp = directory / (SELECT_RECORD + ".new")
    temp.write_text(toml_dump({"select_cache": fields}))
    temp.replace(directory / SELECT_RECORD)
    return dict(fields, location=str(directory))


def select_cache(target, release_id):
    """The cached selection of `release_id`, checked against its record and
    the release's boot image present; refusals before any write."""
    directory = target.out / "releases" / release_id
    record = directory / SELECT_RECORD
    if os.environ.get("ABSD_BLOCK_ATTACH", "ata") not in ("ata", "nvme"):
        raise Failed(f"select_cache_laptop_unsupported: the cached {SELECT_BOOT} attaches the disk as ata or nvme "
                     f"only (ABSD_BLOCK_ATTACH={os.environ['ABSD_BLOCK_ATTACH']}); unset it, or give --release "
                     f"<the directory of {release_id}> and --kernel <a kernel checkout at its commit>")
    rebuild = (f"give --release <the directory of {release_id}> and --kernel <a kernel checkout at its commit> to "
               f"select it by an importer boot instead")
    if not record.is_file():
        raise Failed(f"select_cache_missing: {record}: no cached selection image for {release_id}; {rebuild}")
    try:
        fields = tomllib.loads(record.read_text())["select_cache"]
        if not isinstance(fields, dict):
            raise TypeError
    except (OSError, ValueError, KeyError, TypeError):
        raise Failed(f"select_cache_mismatch: {record}: not a selection cache record; {rebuild}") from None
    if (fields.get("release") != release_id or fields.get("step") != 4
            or fields.get("selection_sha256") != hashlib.sha256(rr.selected_bytes(release_id)).hexdigest()):
        raise Failed(f"select_cache_mismatch: {record} does not record the selection of {release_id}; {rebuild}")
    for name, key in ((SELECT_ISO, "iso_sha256"), (SELECT_BOOT, "boot_script_sha256")):
        path = directory / name
        if not path.is_file():
            raise Failed(f"select_cache_missing: {path}: the cached selection of {release_id} is incomplete; {rebuild}")
        if sha256_file(path) != fields.get(key):
            raise Failed(f"select_cache_mismatch: {path}: its digest is not the {key} {record.name} records; {rebuild}")
    if not target.release_iso(release_id).is_file():
        raise Failed(f"select_cache_missing: {target.release_iso(release_id)}: no boot image for {release_id}")
    return dict(fields, location=str(directory))


def import_cached_selection(target, release_id, log):
    """The selection of `release_id` written by its cached step-4 image,
    under its cached boot script: no kernel, no build."""
    directory = target.out / "releases" / release_id
    with tempfile.TemporaryDirectory(prefix="release-", dir=target.out) as work:
        importer_boot(directory / SELECT_BOOT, directory / SELECT_ISO, target.image, work, 1, 1, 4,
                      selection_entries(release_id), log)


def verify_files(target, files):
    found = target.tree()
    for path, data in files:
        if found.get(path) != data:
            raise Failed(f"the host reader sees different bytes at {path}")
    try:
        oi.verify_import_paths(target.image, files)
    except oi.Failed as error:
        raise Failed(str(error)) from None
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
            [*served_qemu(QEMU), "-rtc", "base=utc", "-cdrom", str(self.iso),
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
                    try:
                        wait_rx_setup(self.serial, lambda: self.proc.poll() is None, deadline)
                    except RxSetupFailed as error:
                        raise Failed(str(error)) from error
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

TARGET_MARKERS = (IMAGE, LEDGER, TARGET, "receipts", "recovery")


def refuse_target_directory(out):
    """`build` never removes an operator directory: any of the layout's
    own markers (the image, the ledger, TARGET, receipts/, recovery/) in
    `out` refuses `target_directory`, with or without --replace, whatever
    records exist. A release directory (release, tree/, the ISO) has none."""
    out = pathlib.Path(out)
    if not out.is_dir():
        return
    found = [name for name in TARGET_MARKERS if (out / name).exists()]
    if found:
        raise Failed(f"target_directory: {out} is an operator directory ({', '.join(found)}); build into a "
                     f"release directory instead; nothing was removed")


def cmd_build(args, log=print):
    """A release directory from the platform's built artifacts."""
    release_id = args.id
    # Before anything else: an operator directory is never a build output.
    refuse_target_directory(pathlib.Path(args.out).resolve())
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
    local = oi.local_login_files(out, getattr(args, "local_token_file", None), getattr(args, "local_login_verifier", None))
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
    (out / "site-defaults" / "local-login").write_bytes(dict(local)["/ssh/local-login"])
    if args.authorized_keys:
        (out / "site-defaults" / "authorized_keys").write_bytes(oi.authorized(args.authorized_keys))
    for name in ("fixture-import.elf", "absd-fsd.elf", "absd-fsd-regenerate.elf", "sshd.elf", "absd-logd.elf"):
        shutil.copyfile(root / name, out / name)
    (out / "release").write_text(record_text(release_id))
    with tempfile.TemporaryDirectory(prefix="release-", dir=out) as work:
        iso = oi.kernel_iso(kernel, 0, root / "sshd.elf", options="net fsd served", server=root / "absd-fsd.elf",
                            work=work, logger=out / "absd-logd.elf")
        shutil.copyfile(iso, out / ISO)
    manifest_tool = here / "release_manifest.py"
    if manifest_tool.is_file():
        subprocess.run([sys.executable, str(manifest_tool), "build", "--kernel", str(kernel), "--platform", str(root),
                        str(out)], check=True)
    else:
        log("release: no release_manifest.py yet; the manifest is not written")
    log(f"RELEASE BUILT id={release_id} dir={out} iso={sha256_file(out / ISO)[:16]}")


def install_image_bytes(args):
    profile = getattr(args, "disk_profile", None)
    if profile is None:
        # Preserve the existing Python API default, including small host fixtures.
        return oi.IMAGE_BYTES
    try:
        return geometry.image_bytes(profile)
    except ValueError as error:
        raise Failed(str(error)) from None


def cmd_install(args, log=print):
    install_image_bytes(args)  # Refuse invalid profiles before destination effects.
    release = Release(args.release)
    kernel = check_kernel(args.kernel, release)
    target = Target(args.target)
    if target.image.exists() and not args.replace:
        raise Failed(f"{target.image} exists; --replace to install over it (the disk is destroyed)")
    if target.identity() not in (None, args.target_identity):
        raise Failed(f"target identity is {target.identity()!r}, not {args.target_identity!r}")
    target.out.mkdir(parents=True, exist_ok=True)
    # Replacing an existing disk is a mutation of the operator directory:
    # it waits for the recovery lock and refuses a pending authorization.
    with (target.mutation(replacing=True) if target.image.exists() else contextlib.nullcontext()):
        install(args, release, kernel, target, log)


def install(args, release, kernel, target, log):
    image_bytes = install_image_bytes(args)
    files = (release.verified_tree_files() + release.verified_site_defaults()
             + [(rr.SELECTED, rr.selected_bytes(release.id))] + storage_fence_state.fresh_files())
    release.verify_artifact("fixture-import.elf")
    release.verify_artifact(ISO)
    if not any(path == "/ssh/authorized_keys" for path, _ in files):
        raise Failed("the release ships no authorized keys and none were given; the machine would be unreachable")
    with tempfile.TemporaryDirectory(prefix="release-cache-", dir=target.out) as work:
        # Built before the disk is touched: a kernel that cannot build it
        # refuses here, not after the install.
        built = build_select_cache(kernel, release, work)
        new_image = pathlib.Path(work) / "install.img"
        with open(new_image, "xb") as handle:
            handle.truncate(image_bytes)
        new_image.chmod(0o600)
        scratch = Target(target.out)
        scratch.image = new_image
        boots = import_files(kernel, release, new_image, files, log, fresh=True)
        verify_files(scratch, files)
        fmt = scratch.fs_format()
        if fmt != release.fields["fs_format"]:
            raise Failed(f"the installed disk reads as format {fmt}, the release expects {release.fields['fs_format']}")
        # The installed disk must stage a successor of this release's size
        # (coordination record #28) before it replaces anything.
        try:
            oi.check_successor_headroom(new_image, release._tree_bytes()[0], release.id)
        except oi.Failed as error:
            raise Failed(str(error)) from None
        new_image.replace(target.image)
        target.release_iso(release.id).parent.mkdir(parents=True, exist_ok=True)
        release.verified_copy(ISO, target.release_iso(release.id))
        cache = install_select_cache(target, built)
    release.verified_copy(ISO, target.iso)
    (target.out / TARGET).write_text(args.target_identity + "\n")
    storage_fence_resume.ensure_lock(target.out)
    receipt = target.receipt(f"install-{release.id}", {
        "install": {"release": release.id, "target": args.target_identity, "image": str(target.image),
                    "time_host": now(), "importer_boots": boots, "fs_format": fmt,
                    "write_gate": "QEMU raw image via the release's importer boots (durable-boot.sh, IDE master)",
                    "verification": "every installed file read back by scripts/absd_fs.py",
                    "manifest": sha256_file(release.manifest),
                    "manifest_verified": "tree,record,site-defaults,fixture-import.elf(copy),iso(copies)"},
        "identity": {k: release.fields[k] for k in IDENTITY},
        "artifacts": {"iso": sha256_file(release.path / ISO), "fixture_import": sha256_file(release.path / "fixture-import.elf"),
                      "absd_fsd": sha256_file(release.path / "absd-fsd.elf"), "sshd": sha256_file(release.path / "sshd.elf"),
                      "manifest": sha256_file(release.manifest) if release.manifest.is_file() else "none",
                      "files": hashlib.sha256(b"".join(hashlib.sha256(d).digest() for _, d in sorted(files))).hexdigest()},
        "select_cache": cache,
    })
    target.ledger_append("installed", release.id, f"receipt={receipt.name}")
    target.ledger_append("selected", release.id)
    log(f"RELEASE INSTALLED id={release.id} target={args.target_identity} files={len(files)} receipt={receipt.name}")


def refuse_other_geometry(target, release):
    """Stage writes only to exact supported disk sizes. Other geometries
    (including the historical 64 MiB image) are refused before writes,
    reporting capacity read-only from the disk's own geometry."""
    if not target.image.is_file():
        return
    size = target.image.stat().st_size
    if geometry.is_writable_size(size):
        return
    files = release.verified_tree_files()
    if storage_fence_state.RESUME_PATH not in target.tree():
        files = files + [(storage_fence_state.RESUME_PATH, storage_fence_state.RESUME_NONE)]
    try:
        capacity = em.check_import_capacity(target.image, em.import_plan(files))
        detail = (f"staging {release.id} would need {capacity['peak_extra_blocks']} blocks with "
                  f"{capacity['free_blocks']} free")
    except ValueError as error:
        found = re.search(r"peak_extra_blocks=(\d+) free_blocks=(\d+)", str(error))
        detail = (f"it cannot stage {release.id}: needs {found[1]} blocks, has {found[2]} free" if found
                  else f"it cannot stage {release.id}: {error}")
    raise Failed(f"image_size: {target.image} is a {size} byte ({size / (1 << 20):g} MiB) disk; stage writes only to "
                 f"the supported {geometry.DEFAULT_IMAGE_BYTES} byte (128 MiB) or "
                 f"{geometry.LARGE_IMAGE_BYTES} byte (2 GiB) operator image, and {detail}. "
                 f"Nothing was written; the disk stays usable with the tools that made it")


def cmd_stage(args, log=print):
    target = Target(args.target)
    attempt = uuid.uuid4().hex
    release = None
    phases, phases_effects = ["prepare"], [False]

    def set_phase(name, effects=False):
        phases.append(name)
        phases_effects[0] = phases_effects[0] or effects
    try:
        release = Release(args.release)
        kernel = check_kernel(args.kernel, release)
        refuse_unreconciled(target)
        refuse_other_geometry(target, release)
        # The recovery lock is held through the read-back, the boot image,
        # the selection cache, the receipt and the ledger line.
        with target.mutation():
            boots, cache, selected, after, slot_added = stage(args, target, release, kernel, log, set_phase)
            set_phase("record-staged")
            receipt = target.receipt(f"stage-{release.id}", {
                "stage": {"release": release.id, "time_host": now(), "importer_boots": boots, "selected_before": selected,
                          "selected_after": target.selected(after), "state": "STAGED",
                          "resume_slot": "added" if slot_added else "present",
                          "manifest": sha256_file(release.manifest), "manifest_verified": "tree,record,fixture-import.elf(copy),iso(copy)"},
                "identity": {k: release.fields[k] for k in IDENTITY},
                "select_cache": cache,
            })
            target.ledger_append("staged", release.id, f"receipt={receipt.name}")
        log(f"RELEASE STAGED id={release.id} selected={selected} trees={','.join(target.trees(after))}")
    except (Exception, KeyboardInterrupt) as error:
        # This is an operation outcome, not a claim that the disk rolled back.
        # Do not probe a possibly half-written filesystem to guess success.
        phase = phases[-1]
        effects_possible = phases_effects[0]
        state = "INDETERMINATE" if effects_possible else "REFUSED"
        reason = str(error) or type(error).__name__
        data = {"stage": {
            "attempt": attempt, "state": state, "time_host": now(), "phase": phase,
            "release": release.id if release is not None else "unknown",
            "release_source": str(args.release), "error": reason,
            "target_effects_possible": effects_possible,
        }}
        if hasattr(error, "import_context"):
            data["import_failure"] = error.import_context
        try:
            receipt = target.receipt(f"stage-failed-{attempt}", data)
            detail = f"receipt={receipt}"
        except Exception as receipt_error:
            # An unwritable destination must not hide the original failure or
            # turn an uncertain write into a pre-write refusal.
            detail = f"receipt unavailable: {receipt_error}"
        message = f"{reason}\nstage state={state} phase={phase} {detail}"
        if isinstance(error, KeyboardInterrupt):
            log(message)
            raise
        raise StageFailed(message, state) from error


def stage(args, target, release, kernel, log, set_phase):
    """The staging work under the recovery lock: the disk read, inputs
    verified, the importer boots, the read-back, the boot image and the
    selection cache. A clean image without a resume slot gets one
    (`/var/recovery.resume` = none) in the same importer entries and guard
    transaction (DESIGN-v5 2.7)."""
    def phase(name):
        set_phase(name)
    phase("prepare")
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
    # STAGED promises every file of the tree matches the manifest: the
    # bytes the importer writes are the bytes checked here, before any
    # write, and the host reader compares the disk with them afterwards.
    phase("verify-inputs")
    files = release.verified_tree_files()
    slot_added = storage_fence_state.RESUME_PATH not in tree
    if slot_added:
        files = files + [(storage_fence_state.RESUME_PATH, storage_fence_state.RESUME_NONE)]
    release.verify_artifact("fixture-import.elf")
    release.verify_artifact(ISO)
    oi.verify_import_paths(target.image, files)
    em.check_import_capacity(target.image, em.import_plan(files))
    with tempfile.TemporaryDirectory(prefix="release-cache-", dir=target.out) as work:
        phase("build-selection-cache")
        built = build_select_cache(kernel, release, work)
        phase("import")
        # From this call onward a failed boot may have committed disk changes.
        set_phase("import", effects=True)
        boots = import_files(kernel, release, target.image, files, log)
        phase("verify-target")
        verify_files(target, files)
        after = target.tree()
        if target.selected(after) != selected:
            raise Failed("staging changed the selection; this must not happen")
        if slot_added and after.get(storage_fence_state.RESUME_PATH) != storage_fence_state.RESUME_NONE:
            raise Failed("the resume slot was not added as none; this must not happen")
        phase("copy-boot-image")
        target.release_iso(release.id).parent.mkdir(parents=True, exist_ok=True)
        release.verified_copy(ISO, target.release_iso(release.id))
        phase("install-selection-cache")
        cache = install_select_cache(target, built)
    return boots, cache, selected, after, slot_added


def select_release(target, kernel, release, log, action):
    """The selection of `release` by its importer under `kernel`."""
    def write():
        import_files(kernel, release, target.image, [(rr.SELECTED, rr.selected_bytes(release.id))], log,
                     step_override=4)
    write_selection(target, release.id, write, release.path / ISO, log, action, {"source": "kernel"})


def write_selection(target, release_id, write, boot_image, log, action, detail):
    tree = target.tree()
    if release_id not in target.trees(tree):
        raise Failed(f"release {release_id} has no tree on the disk")
    target.record_of(release_id, tree)
    before = target.selected(tree)
    write()
    after = target.tree()
    if target.selected(after) != release_id:
        raise Failed("the selection did not take")
    if not target.release_iso(release_id).is_file():
        shutil.copyfile(boot_image, target.release_iso(release_id))
    shutil.copyfile(target.release_iso(release_id), target.iso)
    receipt = target.receipt(f"{action}-{release_id}", {
        action: {"release": release_id, "selected_before": before, "time_host": now(), "state": "BOOT_SELECTED",
                 "boot_image": str(target.iso), **detail}})
    target.ledger_append(action, release_id, f"from={before} receipt={receipt.name}")
    log(f"RELEASE {action.upper()} id={release_id} from={before}: boot {target.iso}")


# What a failed `reconfigure` leaves, by the phase it failed in
# (docs/RELEASE.md section 5, Reconfigure).
RECONFIGURE_STATES = {
    "prepare": "REFUSED", "verify-inputs": "REFUSED",
    "import": "INDETERMINATE", "verify-target": "INDETERMINATE", "revalidate": "INDETERMINATE",
    # The receipt is not under its final name: none was published.
    "record-receipt": "RECONFIGURED_UNRECORDED",
    # The receipt is under its final name; its directory entry is not
    # known to be durable. The ledger was not written.
    "sync-receipt": "RECONFIGURED_RECEIPT_UNSYNCED",
    # The ledger append raised: RELEASES may hold no, part of, or the whole line.
    "publish-ledger": "RECONFIGURED_PUBLICATION_UNCERTAIN",
}


def installation_evidence(target, release):
    """The newest install or stage receipt of `release` on this target,
    and the manifest digest it recorded; (None, None) only when there is
    none at all (a migrated or restored release records none). A newest
    receipt that cannot be read, or lacks the release or the manifest,
    refuses: damaged evidence is not absent evidence."""
    pattern = re.compile(rf"(install|stage)-{re.escape(release.id)}-(\d{{4}}-\d\d-\d\dT\d{{6}}Z)\.toml")
    found = sorted(((m.group(2), m.group(1), path) for path in target.receipts.iterdir()
                    if (m := pattern.fullmatch(path.name))), reverse=True)
    if not found:
        return None, None
    _, action, path = found[0]
    try:
        section = read_toml_flat(path).get(action)
    except (OSError, ValueError, UnicodeError) as error:
        raise Failed(f"installation_evidence_unreadable: {path}: {error}") from None
    if (not isinstance(section, dict) or section.get("release") != release.id
            or not isinstance(section.get("manifest"), str) or not re.fullmatch(r"[0-9a-f]{64}", section["manifest"])):
        raise Failed(f"installation_evidence_malformed: {path} does not name release {release.id} and its manifest")
    return path, section["manifest"]


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def cmd_reconfigure(args, log=print):
    """/etc files (and authorized_keys) replaced whole on a halted target,
    one importer step 4 boot of the SELECTED release's verified importer
    under a kernel at its manifest's commit, read back, then a receipt and
    a `reconfigured` ledger line. Everything that can refuse without a boot
    refuses first. A refusal never writes the image, the guard or the
    ledger; it may leave two things: the failure receipt (best effort), and
    OUT/recovery/lock, which Target.mutation creates on a target that
    lacked it and which no tool ever removes (permitted refusal
    bookkeeping, as for every mutator)."""
    target = Target(args.target)
    attempt = uuid.uuid4().hex
    release = selected = None
    phase, receipt, files, temp, line = "prepare", None, [], None, b""
    # The recovery lock (Target.mutation), held from the prepare phase
    # through the ledger and the failure receipt; its refusal is a prepare
    # refusal like any other, with its failure receipt.
    held = contextlib.ExitStack()
    try:
        # Where the result is recorded: a release.py operator directory.
        for name in (TARGET, LEDGER):
            if not (target.out / name).is_file() or (target.out / name).is_symlink():
                raise Failed(f"{target.out / name}: not a regular file; reconfigure records into an operator "
                             "directory of release.py install")
        if os.path.lexists(target.receipts) and (target.receipts.is_symlink() or not target.receipts.is_dir()):
            raise Failed(f"{target.receipts}: not a directory")
        target.receipts.mkdir(exist_ok=True)
        for path in (target.receipts, target.ledger):
            if not os.access(path, os.W_OK):
                raise Failed(f"{path}: not writable")
        release = Release(args.release)
        kernel = check_kernel(args.kernel, release)
        refuse_unreconciled(target)
        held.enter_context(target.mutation())
        refuse_in_use(target.image, "a reconfiguration")
        tree = target.tree()
        selected = target.selected(tree)
        if selected != release.id:
            raise Failed(f"the disk selects {selected}; reconfigure writes with the selected release's importer: "
                         f"give --release <the directory of {selected}> and --kernel at its commit")
        record_path = f"{rr.tree_root(selected)}/release"
        record = tree.get(record_path)
        if record is None:
            raise Failed("no_release_tree")
        if parse_record(record)["release"] != selected:
            raise Failed(f"release_mismatch: {record_path} names another release")
        digests = release.artifact_digests()
        if hashlib.sha256(record).hexdigest() != digests.get("release"):
            raise Failed(f"manifest_mismatch: {record_path} on the disk is not the record of {release.path}")
        evidence, evidence_manifest = installation_evidence(target, release)
        if evidence is not None and evidence_manifest != sha256_file(release.manifest):
            raise Failed(f"manifest_mismatch: {release.manifest} is not the manifest {evidence.name} recorded")
        fmt = target.fs_format()
        if fmt != release.fields["fs_format"]:
            raise Failed(f"the disk is format {fmt}; release {release.id} reads format {release.fields['fs_format']}")
        phase = "verify-inputs"
        files = [(f"/etc/{p.name}", p.read_bytes()) for p in sorted(pathlib.Path(args.etc).iterdir()) if p.is_file()]
        if args.authorized_keys is not None:
            files.append(("/ssh/authorized_keys", oi.authorized(args.authorized_keys)))
        if not files:
            raise Failed(f"nothing to replace in {args.etc}")
        if len(em.import_plan(files)) != 1:
            raise Failed(f"the files exceed one importer boot ({em.IMPORT_BUDGET} bytes); reconfigure replaces "
                         "them in one boot")
        release.verify_artifact("fixture-import.elf")
        oi.verify_import_paths(target.image, files)
        em.check_import_capacity(target.image, [(4, files)])
        # Everything but the replacements and the guard, by content and by
        # name (directories included), to compare after the boot.
        kept = set(dict(files)) | {storage_fence_state.PATH}
        rest = {p: d for p, d in tree.items() if p not in kept}
        names = set(oi.namespace(target.image)) - kept
        phase = "import"
        boots = import_files(kernel, release, target.image, files, log, step_override=4)
        phase = "verify-target"
        verify_files(target, files)
        phase = "revalidate"
        # Exclusive use is the operator's (docs/RELEASE.md section 5): a
        # change by another operation is caught here, not prevented.
        after = target.tree()
        if {p: d for p, d in after.items() if p not in kept} != rest or set(oi.namespace(target.image)) - kept != names:
            raise Failed("a file other than the replacements was added, removed or changed during the "
                         "reconfiguration: another operation used this target")
        phase = "record-receipt"
        # Published by one link of a synced temporary file: a failure before
        # it leaves no receipt under the final name (the temporary is
        # removed, best effort).
        final = target.receipts / f"reconfigure-{selected}-{now().replace(':', '')}.toml"
        temp = target.receipts / f".{final.name}.{attempt}.tmp"
        body = toml_dump({
            "reconfigure": {"release": selected, "target": target.identity(), "image": str(target.image),
                            "time_host": now(), "state": "RECONFIGURED", "importer_boots": boots,
                            "files": [f"{hashlib.sha256(d).hexdigest()} {p}" for p, d in sorted(files)],
                            "selected": selected, "manifest": sha256_file(release.manifest),
                            "installation_evidence": evidence.name if evidence is not None else "none",
                            "manifest_verified": "record(disk),fixture-import.elf(copy)",
                            "verification": "every replaced file read back by scripts/absd_fs.py; every other "
                                            "file and name on the disk unchanged"},
            "identity": {k: release.fields[k] for k in IDENTITY},
            "provenance": {"kernel_commit": release.kernel_commit(),
                           "fixture_import": digests["fixture-import.elf"]},
        }).encode()
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            view = memoryview(body)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.link(temp, final)
        receipt = final
        phase = "sync-receipt"
        os.unlink(temp)
        fsync_directory(target.receipts)
        phase = "publish-ledger"
        line = f"{now()} reconfigured {selected} receipt={receipt.name}\n".encode()
        fd = os.open(target.ledger, os.O_WRONLY | os.O_APPEND)
        try:
            if os.write(fd, line) != len(line):
                raise OSError(f"short write to {target.ledger}")
            os.fsync(fd)
        finally:
            os.close(fd)
    except (Exception, KeyboardInterrupt) as error:
        state = RECONFIGURE_STATES[phase]
        reason = str(error) or type(error).__name__
        data = {"reconfigure": {
            "attempt": attempt, "state": state, "time_host": now(), "phase": phase,
            "release": selected or (release.id if release is not None else "unknown"),
            "files": [p for p, _ in files], "error": reason,
            "receipt": receipt.name if receipt is not None else "none",
            "target_effects_possible": state != "REFUSED",
        }}
        if hasattr(error, "import_context"):
            data["import_failure"] = error.import_context
        try:
            failed = target.receipt(f"reconfigure-failed-{attempt}", data)
            detail = f"failure receipt={failed}"
        except Exception as receipt_error:
            detail = f"failure receipt unavailable: {receipt_error}"
        if phase == "record-receipt":
            try:
                if os.path.lexists(temp):
                    os.unlink(temp)
                detail = "no receipt published; ledger not written; " + detail
            except OSError as cleanup:
                detail = f"no receipt published; temporary {temp} left ({cleanup}): remove it; ledger not written; " + detail
        elif phase == "sync-receipt":
            detail = (f"receipt={receipt} published, its directory not synced"
                      + (f", temporary {temp} still present (remove it)" if os.path.lexists(temp) else "")
                      + "; ledger not written; " + detail)
        elif phase == "publish-ledger":
            detail = (f"receipt={receipt} published; {target.ledger} may hold none, part or all of the line "
                      f"{line.decode().strip()!r}: reconcile it (docs/OPERATOR-RUNBOOK.md section 13); " + detail)
        message = f"{reason}\nreconfigure state={state} phase={phase} {detail}"
        if isinstance(error, KeyboardInterrupt):
            log(message)
            raise
        raise ReconfigureFailed(message, state) from error
    finally:
        held.close()
    # Outside the failure boundary: a reporting fault cannot relabel a
    # published reconfiguration; the receipt and the ledger line are its record.
    try:
        log(f"RELEASE RECONFIGURED id={selected} files={','.join(p for p, _ in files)} receipt={receipt.name}")
    except Exception:
        pass


def cmd_select(args, log=print):
    release = Release(args.release)
    kernel = check_kernel(args.kernel, release)
    target = Target(args.target)
    refuse_unreconciled(target)
    with target.mutation():
        select_release(target, kernel, release, log, "selected")


def cmd_rollback(args, log=print):
    """Back to the last accepted release, which must still have its tree.
    Without --kernel, by the selection image cached for it (no build);
    with --kernel, by its importer built from that kernel."""
    target = Target(args.target)
    refuse_unreconciled(target)
    with target.mutation():
        rollback(args, target, log)


def rollback(args, target, log):
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
    refuse_in_use(target.image, "a rollback")
    if args.kernel is None:
        if release is not None and release.id != previous:
            raise Failed(f"give --release <the directory of {previous}> or no --release (the cached selection "
                         f"image of {previous} writes the selection)")
        cache = select_cache(target, previous)
        write_selection(target, previous, lambda: import_cached_selection(target, previous, log), None, log,
                        "rolled_back", {"source": "cache", "select_iso_sha256": cache["iso_sha256"],
                                        "boot_script_sha256": cache["boot_script_sha256"],
                                        "cache_kernel_commit": cache.get("kernel_commit", "unknown")})
        return
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
    # The acceptance boot is a mutation of the disk: the recovery lock is
    # held for the run and the OFD probe released before QEMU starts.
    with target.mutation():
        accept(args, target, release_id, record, key, log)


def accept(args, target, release_id, record, key, log):
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


def host_key_blob(seed):
    """The OpenSSH public key blob of the ed25519 key the seed makes."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    public = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + public


def host_public_key(seed):
    """`ssh-ed25519 <base64>`, as a known_hosts line carries it."""
    import base64
    return "ssh-ed25519 " + base64.b64encode(host_key_blob(seed)).decode()


def host_key_fingerprint(seed):
    """OpenSSH's SHA256 fingerprint of the ed25519 key the seed makes."""
    import base64
    return "SHA256:" + base64.b64encode(hashlib.sha256(host_key_blob(seed)).digest()).decode().rstrip("=")


def image_holders(image):
    """The processes (pid, name) that hold `image` open, from /proc/*/fd,
    matched by device and inode. Processes whose fds this user cannot read
    are not seen. Without /proc nothing can be told: Failed."""
    proc = pathlib.Path("/proc")
    if not (proc / "self" / "fd").is_dir():
        raise Failed(f"image_in_use: cannot tell whether {image} is in use (no /proc); a backup or a removal needs a halted image")
    want = pathlib.Path(image).stat()
    holders = []
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fds = list((entry / "fd").iterdir())
        except OSError:
            continue
        for fd in fds:
            try:
                found = fd.stat()
            except OSError:
                continue
            if (found.st_dev, found.st_ino) == (want.st_dev, want.st_ino):
                try:
                    name = (entry / "comm").read_text().strip()
                except OSError:
                    name = "?"
                holders.append((int(entry.name), name))
                break
    return sorted(holders)


def refuse_in_use(image, before="a backup"):
    """A halted image (docs/RELEASE.md section 7) for a backup or a
    removal: no process holds it open (a running QEMU, an importer boot,
    another release.py)."""
    holders = image_holders(image)
    if holders:
        raise Failed(f"image_in_use: {image} is open in " + ", ".join(f"pid {pid} ({name})" for pid, name in holders)
                     + f"; halt the machine (shutdown) before {before}")


def cmd_backup(args, log=print):
    """A halted backup: the image copied and validated, with its identity."""
    target = Target(args.target)
    dest = pathlib.Path(args.backup).resolve()
    point = bool(getattr(args, "recovery_point", False))
    if point and (dest.exists() or pathlib.Path(args.backup).is_symlink()):
        raise Failed("recovery_point_destination_exists: a recovery point needs a new backup directory")
    if dest.exists() and any(dest.iterdir()):
        raise Failed(f"{dest} is not empty")
    if not target.image.is_file():
        raise Failed(f"{target.image}: no disk image")
    # Allowed while an authorization is pending (it reads the source and
    # writes a separate copy), but never beside a running boot-operator.sh
    # or another tool: the recovery lock serializes it (`tool_busy`).
    try:
        with storage_fence_resume.recovery_lock(target.out):
            backup(args, target, dest, log)
    except storage_fence_resume.Refused as error:
        raise Failed(str(error)) from None


def backup(args, target, dest, log):
    point = bool(getattr(args, "recovery_point", False))
    refuse_in_use(target.image)
    tree = target.tree()
    fmt = target.fs_format()
    selected = target.selected(tree)
    point_table = None
    point_iso = None
    if point:
        try:
            recovery_point.require_clean(tree)
            recovery_point.source_identity(target.identity())
            point_iso = recovery_point.capture_iso(target.out, selected, ISO)
            point_table = recovery_point.table(tree, selected, point_iso)
        except recovery_point.Refused as error:
            raise Failed(str(error)) from None
    region = target.region()
    image = absd_fs.select(region)
    pending = storage_fence_resume.pending_id(target.out, target.image)
    created = not dest.exists()
    dest.mkdir(mode=0o700, parents=True, exist_ok=not point)
    copy = dest / IMAGE
    try:
        shutil.copyfile(target.image, copy)
        copy.chmod(0o600)
        refuse_in_use(target.image)
        if sha256_file(copy) != sha256_file(target.image):
            raise Failed("the copy differs from the disk")
        found = oi.tree(copy)
        if found != tree:
            raise Failed("the copy's tree differs from the disk's")
    except (Failed, absd_fs.Refused, OSError):
        # No refusal leaves a copy (it carries the host key seed) behind.
        copy.unlink(missing_ok=True)
        if created:
            dest.rmdir()
        raise
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
        # A copy taken after an act carries the record; the label is how
        # the host tells it from the machine (DESIGN-v5 2.3, limit i).
        "recovery": {"pending_id": pending},
    }
    if point:
        record["recovery"] = point_table
    (dest / "backup.toml").write_text(toml_dump(record))
    for rid in target.trees(tree):
        iso = target.release_iso(rid)
        if iso.is_file():
            (dest / "releases" / rid).mkdir(parents=True, exist_ok=True)
            if point and rid == selected:
                (dest / "releases" / rid / ISO).write_bytes(point_iso)
            else:
                shutil.copyfile(iso, dest / "releases" / rid / ISO)
    target.ledger_append("backup", selected or "none", f"dir={dest}")
    log(f"BACKUP OK dir={dest} selected={selected} format={fmt} seq={image['seq']} files={len(tree)}")
    if point:
        log(f"RECOVERY POINT SHA256 {sha256_file(dest / 'backup.toml')} selected={selected}")


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
    # The backup keeps its disk's geometry; restore copies it as it is.
    sectors = disk_sectors(copy)
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
    region = absd_fs.fs_region(copy, sectors)
    image = absd_fs.select(region)
    if image["fs_id"] != meta["disk"]["fs_id"] or image["seq"] != meta["disk"]["commit_sequence"]:
        raise Failed("the backup image's filesystem identity or sequence is not the one backup.toml records")
    selected = scratch.selected(tree)
    if selected != meta["release"]["selected"]:
        raise Failed(f"the backup selects {selected}, backup.toml says {meta['release']['selected']}")
    scratch.record_of(selected, tree)
    return meta, tree, selected


def recovery_snapshot(args):
    # Validated at the point's own geometry; recovery_point still requires
    # exactly that size of the bytes it reads.
    sectors = disk_sectors(pathlib.Path(args.backup) / IMAGE)
    # Preserve the legacy read bound and separately admit the exact large
    # profile. Do not expand this into an arbitrary <=2 GiB whole-image read.
    if (sectors * absd_fs.SECTOR > oi.IMAGE_BYTES
            and sectors * absd_fs.SECTOR != geometry.LARGE_IMAGE_BYTES):
        raise Failed(f"recovery_point_member_size: the image is {sectors * absd_fs.SECTOR} bytes; "
                     f"recovery reads at most {oi.IMAGE_BYTES} bytes or exactly {geometry.LARGE_IMAGE_BYTES} bytes")
    try:
        point = recovery_point.validate(args.backup, getattr(args, "recovery_point_sha256", None),
                                        getattr(args, "expected_release", None), image_name=IMAGE,
                                        image_bytes=sectors * absd_fs.SECTOR, iso_name=ISO,
                                        device_sectors=sectors)
    except recovery_point.Refused as error:
        raise Failed(str(error)) from None
    try:
        refuse_in_use(pathlib.Path(args.backup) / IMAGE, before="a pinned recovery restore")
    except OSError as error:
        raise Failed(f"recovery_point_input_changed: {error.strerror}") from None
    return point


def write_recovery_file(path, data):
    """Exclusive construction from verified bytes; never reopens the backup."""
    with pathlib.Path(path).open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    if sha256_file(path) != recovery_point.digest(data):
        raise Failed("recovery_point_copy_mismatch: constructed bytes differ from the verified snapshot")


def restore_recovery_point(args, log):
    if args.clone or args.replace or args.release or args.kernel:
        raise Failed("recovery_point_mode_conflict: strict recovery is fresh same-machine restore; "
                     "no --replace, --clone, --release or --kernel")
    point = recovery_snapshot(args)  # Complete admission before destination effects.
    source_identity = point.metadata["backup"]["target"]
    if args.target_identity is not None and args.target_identity != source_identity:
        raise Failed("recovery_point_identity: replacement must keep this logical machine identity")
    raw_target = pathlib.Path(args.target)
    target = Target(args.target)
    if raw_target.is_symlink() or target.out.exists():
        raise Failed("recovery_point_target_exists: strict recovery requires a new operator directory")
    try:
        target.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    except FileExistsError:
        raise Failed("recovery_point_target_exists: destination appeared during admission") from None
    # An I/O failure from here is unfinished construction, not served recovery.
    # No old image is replaced and the source point is never modified.
    try:
        write_recovery_file(target.image, point.image)
        target.release_iso(point.selected).parent.mkdir(parents=True)
        write_recovery_file(target.release_iso(point.selected), point.iso)
        write_recovery_file(target.iso, point.iso)
        write_recovery_file(target.out / TARGET, (source_identity + "\n").encode())
        receipt = target.receipt(f"restore-{point.selected}", {
            "restore": {"backup": str(pathlib.Path(args.backup).absolute()), "release": point.selected,
                        "time_host": now(), "clone": False, "fresh_target": True,
                        "recovery_point_schema": recovery_point.SCHEMA,
                        "recovery_point_sha256": point.metadata_sha256,
                        "image_sha256": point.metadata["disk"]["image_sha256"],
                        "fs_format": point.metadata["disk"]["fs_format"],
                        "guard": "copied unchanged from pinned clean point; never reset"}})
        target.ledger_append("restored", point.selected, f"point={point.metadata_sha256} receipt={receipt.name}")
    except (OSError, Failed) as error:
        raise Failed(f"recovery_point_construction_incomplete: {target.out}: {error}; "
                     "reconcile this destination before reuse; the source point is unchanged") from None
    log(f"RESTORE COPIED release={point.selected} recovery_point={point.metadata_sha256} fresh_target=true")


def cmd_restore(args, log=print):
    if (getattr(args, "recovery_point_sha256", None) is not None
            or getattr(args, "expected_release", None) is not None):
        return restore_recovery_point(args, log)
    target = Target(args.target)
    if args.clone and not (args.release and args.kernel and args.key):
        raise Failed("--clone needs --release <directory of the selected release>, --kernel and --key")
    meta, tree, selected = validate_backup(args.backup)
    # A clone boots the copied image writably (a new host key): a write, so
    # only at an exact supported size. A plain restore copies any valid geometry
    # unchanged (coordination record #28).
    size = (pathlib.Path(args.backup) / IMAGE).stat().st_size
    if args.clone and not geometry.is_writable_size(size):
        raise Failed(f"image_size: the backup image is {size} bytes; --clone boots it writably and writes only to the "
                     f"supported {geometry.DEFAULT_IMAGE_BYTES} byte (128 MiB) or {geometry.LARGE_IMAGE_BYTES} byte "
                     f"(2 GiB) operator image. A plain restore keeps its geometry unchanged")
    if "recovery" in meta and set(meta["recovery"]) != {"pending_id"}:
        raise Failed("recovery_point_strict_required: use --recovery-point-sha256 and --expected-release "
                     "with a new operator directory")
    clone = None
    if args.clone:
        # Before the image is replaced: a clone that cannot regenerate the
        # host key would leave the source machine's identity in OUT.
        release = Release(args.release)
        if release.id != selected:
            raise Failed(f"--release is {release.id}, the restored image selects {selected}")
        kernel = check_kernel(args.kernel, release)
        # A second machine is another target: its identity is OUT's TARGET
        # or --target-identity, and never the backup's own.
        source = meta["backup"]["target"]
        identity = target.identity()
        if identity and args.target_identity and identity != args.target_identity:
            raise Failed(f"target identity is {identity!r}, not {args.target_identity!r}")
        identity = identity or args.target_identity
        if not identity or identity == source:
            raise Failed(f"clone_identity_unchanged: the backup is of target {source!r}; a clone needs another "
                         f"(--target-identity <the second machine's identity>, in an operator directory of its own)")
        # The regenerate boot's key is compared with the source's.
        recorded = meta.get("identity")
        if not isinstance(recorded, dict) or not isinstance(recorded.get("host_key_fingerprint"), str):
            raise Failed("backup_identity_missing: backup.toml has no [identity] host_key_fingerprint to compare "
                         "the clone's new host key with")
        clone = (release, kernel)
    backup = pathlib.Path(args.backup).resolve()
    iso = backup / "releases" / selected / ISO
    if not iso.is_file() and not target.release_iso(selected).is_file():
        raise Failed(f"no boot image for the selected release {selected} in the backup or the target")
    if target.image.exists() and not args.replace:
        raise Failed(f"{target.image} exists; --replace to restore over it")
    # Legacy targets without a recovery lock retain their read-only refusal
    # preflight: acquiring mutation() would create recovery/lock. Installed
    # targets already have the lock and must meet tool_busy first. Every
    # admitted replacement still rechecks pending/history under mutation().
    lock = target.out / storage_fence_resume.RECOVERY / storage_fence_resume.LOCK
    if target.image.exists() and not lock.exists():
        refuse_in_use(target.image, before="a legacy replacement restore")
        try:
            storage_fence_resume.refuse_pending(target.out, target.image, replacing=True)
        except storage_fence_resume.Refused as error:
            raise Failed(str(error)) from None
        try:
            recovery_point.require_clean_history(target.tree())
        except (Failed, recovery_point.Refused, absd_fs.Refused, oi.Failed, ValueError) as error:
            raise Failed(f"restore_target_not_clean: {error}; retain this image and use a fresh target") from None
    target.out.mkdir(parents=True, exist_ok=True)
    replacing = target.mutation(replacing=True) if target.image.exists() else contextlib.nullcontext()
    with replacing:
        # The launcher recovery lock is the first existing-target boundary.
        # Keep open-image and clean-history refusals before any restore or
        # clone-cache effects, while retaining the mutation lock throughout.
        if target.image.exists():
            refuse_in_use(target.image, before="a legacy replacement restore")
            try:
                recovery_point.require_clean_history(target.tree())
            except (Failed, recovery_point.Refused, absd_fs.Refused, oi.Failed, ValueError) as error:
                raise Failed(f"restore_target_not_clean: {error}; retain this image and use a fresh target") from None
        cache_work = (tempfile.TemporaryDirectory(prefix="release-cache-", dir=target.out) if clone
                      else contextlib.nullcontext())
        with cache_work as work:
            # A clone keeps its selected release's selection image, as install
            # does; built before the disk is touched (a backup carries none).
            built = build_select_cache(clone[1], clone[0], work) if clone else None
            temp = target.image.with_suffix(".img.restoring")
            shutil.copyfile(backup / IMAGE, temp)
            temp.chmod(0o600)
            if sha256_file(temp) != meta["disk"]["image_sha256"]:
                temp.unlink()
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
            log(f"RESTORE COPIED release={selected} format={meta['disk']['fs_format']} "
                f"seq={meta['disk']['commit_sequence']}")
            if clone:
                clone_identity(target, selected, *clone, args, log, built, meta)


def clone_identity(target, release_id, release, kernel, args, log, built, meta):
    """A second machine from a restored image: a new host key, made by the
    release's regenerate image (`release`, checked against the image's
    selection, under `kernel`, checked against its manifest), then an
    orderly halt; then the selected release's selection cache (`built`)
    moved into OUT, and every other release on the disk without one named
    in the receipt."""
    key = pathlib.Path(args.key).resolve()
    before = target.tree().get("/ssh/host_ed25519_seed")
    with tempfile.TemporaryDirectory(prefix="release-", dir=target.out) as work:
        # Historical releases keep their own boot composition. A declared
        # logger is copied and checked before this regenerate image consumes it.
        logger = ""
        if "absd-logd.elf" in release.artifact_digests():
            logger = release.verified_copy("absd-logd.elf", pathlib.Path(work) / "absd-logd.elf")
        elif release._manifest_doc().get("build", {}).get("kernel_image", {}).get("LOGD_ELF"):
            raise Failed("manifest_mismatch unrecorded logger artifact")
        iso = oi.kernel_iso(kernel, 0, release.path / "sshd.elf", options="net fsd served",
                            server=release.path / "absd-fsd-regenerate.elf", work=work, logger=logger)
        boot = Boot(target, iso, f"clone-{release_id}", args.port)
        try:
            ready = boot.wait_ready(release_id)
            # Served, the file server makes the seed and says so on the
            # serial; sshd reads it from /ssh and always reports LOADED.
            if "FSD HOST KEY GENERATED" not in boot.serial():
                raise Failed("clone_key_not_generated: the regenerate boot's serial has no "
                             "FSD HOST KEY GENERATED")
            source = meta["identity"]["host_key_fingerprint"]
            if ready["fingerprint"] == source:
                raise Failed(f"clone_key_unchanged: the regenerate boot serves the backup's host key {source}")
            rc, out, err = boot.ssh(key, "shutdown")
            if rc != 0:
                raise Failed(f"shutdown after regeneration: rc={rc} {err!r}")
            if boot.wait_end() != 3:
                raise Failed("the clone boot did not halt in order")
        finally:
            boot.stop()
    tree = target.tree()
    after = tree.get("/ssh/host_ed25519_seed")
    if not after or after == before:
        raise Failed("clone_seed_unchanged: the host key seed did not change on the disk")
    cache = install_select_cache(target, built)
    absent = [rid for rid in target.trees(tree)
              if rid != release_id and not (target.out / "releases" / rid / SELECT_RECORD).is_file()]
    fingerprint = host_key_fingerprint(after)
    receipt = target.receipt(f"clone-{release_id}", {
        "clone": {"release": release_id, "target": target.identity(), "source_target": meta["backup"]["target"],
                  "host_key_fingerprint": fingerprint,
                  "source_host_key_fingerprint": meta["identity"]["host_key_fingerprint"], "time_host": now()},
        "select_cache": cache,
        "select_cache_absent": {"releases": absent,
                                "reason": "a backup carries no selection image; a rollback to these needs "
                                          "--release and --kernel"},
    })
    target.ledger_append("cloned", release_id, f"host_key={fingerprint} receipt={receipt.name}")
    log(f"CLONE OK release={release_id} host_key={fingerprint} target={target.identity()} select_cache=present"
        + (f" select_cache_absent={','.join(absent)}" if absent else ""))


def cmd_migrate(args, log=print):
    """Read the old image, make a new one with the release's importer, copy
    the site state, install the release, validate, switch; keep the old."""
    release = Release(args.release)
    kernel = check_kernel(args.kernel, release)
    target = Target(args.target)
    refuse_unreconciled(target)
    with target.mutation(replacing=True):
        migrate(args, release, kernel, target, log)


def migrate(args, release, kernel, target, log):
    old_format = target.fs_format()
    if old_format == release.fields["fs_format"]:
        raise Failed(f"the disk is already format {old_format}; use stage/select")
    old_tree = target.tree()
    # A new backing file excludes old device effects, but does not grant
    # permission to discard logical recovery history or reset its budget.
    # Legacy inputs with that state need an explicit conversion rule.
    history = [path for path in old_tree if path in ("/var/state", "/var/state.new")
               or path.startswith(("/var/state/", "/var/state.new/"))]
    old_guard = old_tree.get(storage_fence_state.PATH)
    if history or old_guard not in (None, storage_fence_state.FRESH):
        raise Failed("migration_recovery_history: existing or unclean recovery state requires an explicit "
                     "new-device conversion; migration never resets it")
    site = [(path, data) for path, data in sorted(old_tree.items())
            if any(path == root or path.startswith(root + "/") for root in SITE_ROOTS)
            and path not in (storage_fence_state.PATH, storage_fence_state.RESUME_PATH)]
    files = (release.verified_tree_files() + site + [(rr.SELECTED, rr.selected_bytes(release.id))]
             + storage_fence_state.fresh_files())
    release.verify_artifact("fixture-import.elf")
    release.verify_artifact(ISO)
    new_image = target.image.with_suffix(".img.migrating")
    with tempfile.TemporaryDirectory(prefix="release-cache-", dir=target.out) as work:
        built = build_select_cache(kernel, release, work)
        with open(new_image, "xb") as handle:
            handle.truncate(oi.IMAGE_BYTES)
        new_image.chmod(0o600)
        scratch = Target(target.out)
        scratch.image = new_image
        boots = import_files(kernel, release, new_image, files, log, fresh=True)
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
        release.verified_copy(ISO, target.release_iso(release.id))
        cache = install_select_cache(target, built)
    release.verified_copy(ISO, target.iso)
    receipt = target.receipt(f"migrate-{release.id}", {
        "migrate": {"release": release.id, "from_format": old_format, "to_format": release.fields["fs_format"],
                    "retained_image": str(retained), "site_files": len(site), "importer_boots": boots,
                    "time_host": now(), "mtime_of_copied_objects": 0,
                    "rollback": "restore the retained image and boot the previous release's image"},
        "select_cache": cache})
    target.ledger_append("migrated", release.id, f"from_format={old_format} retained={retained.name} receipt={receipt.name}")
    target.ledger_append("selected", release.id, "by migration")
    log(f"MIGRATED to format {release.fields['fs_format']} release={release.id} site_files={len(site)} retained={retained.name}")


REMOVING = "REMOVING"


def pending_removal(target):
    """The release id an interrupted removal left in OUT/REMOVING, or None."""
    path = target.out / REMOVING
    if not path.is_file():
        return None
    rid = path.read_text().strip()
    if not rr.valid_id(rid):
        raise Failed(f"removal_unreconciled: {path} is malformed ({rid!r}); inspect the disk with "
                     f"release.py status, then delete it by hand")
    return rid


def refuse_unreconciled(target):
    rid = pending_removal(target)
    if rid is not None:
        raise Failed(f"removal_unreconciled: {target.out / REMOVING} records an interrupted removal of {rid}; "
                     f"run release.py remove --id {rid} to reconcile the operator directory first")


def finish_removal(target, rid, release_id, kernel_commit, removed, boots, status, log):
    """The disk no longer holds the tree: bring the operator directory into
    line, then drop the intent (last, so an interruption here is finished
    by the next remove)."""
    copy = target.out / "releases" / rid
    if copy.is_dir():
        shutil.rmtree(copy)
    after = target.tree()
    receipt = target.receipt(f"remove-{rid}", {
        "remove": {"release": rid, "time_host": now(), "removed_files": removed, "importer_boots": boots,
                   "importer_release": release_id, "kernel_commit": kernel_commit, "importer_status": status,
                   "selected": target.selected(after) or "none", "trees_after": target.trees(after)}})
    target.ledger_append("removed", rid, f"by={release_id} receipt={receipt.name}"
                         + (" reconciled" if status.startswith("interrupted") else ""))
    (target.out / REMOVING).unlink(missing_ok=True)
    return receipt, after


def reconcile_removal(target, rid, release, log):
    """An interrupted removal of `rid`: finished in OUT if the disk no
    longer holds the tree; otherwise the intent is dropped (the disk was
    not changed, or the tree is partly there and remove runs again)."""
    tree = target.tree()
    if rid in target.trees(tree):
        (target.out / REMOVING).unlink()
        log(f"RELEASE REMOVE RECONCILED id={rid}: the disk still holds its tree; nothing to finish")
        return False
    receipt, after = finish_removal(target, rid, release.id, release.kernel_commit(), "unknown", "unknown",
                                    "interrupted after the commit; reconciled", log)
    log(f"RELEASE REMOVE RECONCILED id={rid}: the disk no longer holds it; the operator directory was "
        f"brought into line trees={','.join(target.trees(after))} receipt={receipt.name}")
    return True


def cmd_remove(args, log=print):
    """Removes a release tree that is neither selected nor the last
    accepted release: importer step 5, which removes /releases/<id>/ whole
    in one commit, run by --release's importer under --kernel, on a halted
    image. OUT/REMOVING records the intent before the boot; the operator
    directory's copy of that release (its boot image and selection cache)
    goes only once the host reader sees the tree gone and every other file
    unchanged, and the intent goes last. A removal interrupted after its
    commit is finished by the next remove."""
    release = Release(args.release)
    kernel = check_kernel(args.kernel, release)
    target = Target(args.target)
    rid = args.id
    if not rr.valid_id(rid):
        raise Failed(f"release id {rid!r} is not [a-z0-9.-]{{1,64}}")
    if not target.image.is_file():
        raise Failed(f"{target.image}: no disk image")
    refuse_in_use(target.image, "a removal")
    with target.mutation():
        remove(args, release, kernel, target, rid, log)


def remove(args, release, kernel, target, rid, log):
    pending = pending_removal(target)
    if pending is not None:
        finished = reconcile_removal(target, pending, release, log)
        if pending == rid and finished:
            return
    fmt = target.fs_format()
    if fmt != release.fields["fs_format"]:
        raise Failed(f"the disk is format {fmt}; release {release.id}'s importer writes format "
                     f"{release.fields['fs_format']}: remove with a release that reads the disk")
    tree = target.tree()
    if rid == target.selected(tree) or rid == target.last("accepted"):
        raise Failed(f"{rid} is selected or the last accepted release; not removable")
    if rid not in target.trees(tree):
        raise Failed(f"{rid} has no tree on the disk")
    prefix = f"{rr.tree_root(rid)}/"
    held = sorted(path for path in tree if path.startswith(prefix))
    kept = {path: data for path, data in tree.items() if not path.startswith(prefix)}
    intent = target.out / REMOVING
    temp = target.out / (REMOVING + ".new")
    temp.write_text(rid + "\n")
    temp.replace(intent)
    try:
        boots = import_files(kernel, release, target.image, [(prefix, b"")], log, step_override=5)
        importer_error = None
    except Failed as error:
        boots, importer_error = 1, str(error)
    after = target.tree()
    left = sorted(path for path in after if path.startswith(prefix))
    def expected_dirty(path, data):
        return (importer_error is not None and path == storage_fence_state.PATH
                and storage_fence_state.parse(data) in ("fresh", "clean")
                and after.get(path) == storage_fence_state.encode("dirty"))
    changed = sorted(path for path, data in kept.items()
                     if after.get(path) != data and not expected_dirty(path, data))
    if changed or left:
        # The tree is still listed (whole or in part), or the disk needs a
        # restore: nothing in OUT to finish.
        intent.unlink()
    if changed:
        raise Failed(f"the removal of {rid} changed files outside its tree: {', '.join(changed[:5])}; the operator "
                     f"directory is untouched; restore a backup" + (f"\n{importer_error}" if importer_error else ""))
    if left == held:
        raise Failed(f"{importer_error or 'the importer boot reported success'}\nthe disk still holds {rid} whole; "
                     f"nothing was removed")
    if left:
        raise Failed(f"the removal of {rid} left {len(left)} of its {len(held)} files on the disk; the operator "
                     f"directory is untouched; run remove again" + (f"\n{importer_error}" if importer_error else ""))
    receipt, after = finish_removal(target, rid, release.id, release.kernel_commit(), len(held), boots,
                                    "failed after the commit" if importer_error else "ok", log)
    if importer_error:
        raise Failed(f"the importer boot reported a failure, but the disk no longer holds {rid}; the operator "
                     f"directory was brought into line (ledger: removed {rid}):\n{importer_error}")
    log(f"RELEASE REMOVED id={rid} files={len(held)} trees={','.join(target.trees(after))} receipt={receipt.name}")


def import_temp_identity(target, directory):
    paths = oi.namespace(target.image)
    node = paths.get(directory)
    if node is None or node["kind"] != 2:
        raise Failed(f"REFUSED import_temp_layout {directory}: not an importer directory; inspect this exact path in the guest, remove it there if authorized, or restore a verified backup")
    leaf = directory + "/file"
    children = {path for path in paths if path.startswith(directory + "/")}
    if children not in (set(), {leaf}) or (leaf in paths and paths[leaf]["kind"] != 1):
        raise Failed(f"REFUSED import_temp_layout {directory}: contains unexpected objects; ownership unestablished; inspect this exact path in the guest, remove it there if authorized, or restore a verified backup")
    data = target.tree()[leaf] if leaf in paths else b""
    return {"directory": directory, "fs_id": node["fs_id"], "serial": node["serial"],
            "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "has_file": leaf in paths}


def cmd_discard_import_temp(args, log=print):
    directory = args.directory
    if (not directory or not directory.startswith("/") or directory != str(pathlib.PurePosixPath(directory))
            or not re.fullmatch(r"\.absd-import-[0-9a-fA-F]{4}", pathlib.PurePosixPath(directory).name)
            or em.reserved_import_path(str(pathlib.PurePosixPath(directory).parent))):
        raise Failed("give an exact canonical importer temporary directory")
    target = Target(args.target)
    release = Release(args.release)
    kernel = check_kernel(args.kernel, release)
    refuse_unreconciled(target)
    refuse_in_use(target.image, "temporary-object removal")
    with target.mutation():
        discard_import_temp(args, target, release, kernel, directory, log)


def discard_import_temp(args, target, release, kernel, directory, log):
    if target.fs_format() != release.fields["fs_format"]:
        raise Failed("temporary-object removal requires an importer for the disk's filesystem format")
    identity = import_temp_identity(target, directory)
    for field, expected in (("fs_id", args.fs_id), ("serial", args.serial), ("bytes", args.bytes),
                            ("sha256", args.sha256)):
        if identity[field] != expected:
            raise Failed(f"temporary identity mismatch {field}: inspect and supply the exact current identity")
    before = {path: data for path, data in target.tree().items()
              if path != directory and not path.startswith(directory + "/")}
    refuse_in_use(target.image, "temporary-object removal")
    attempt = uuid.uuid4().hex
    try:
        boots = import_files(kernel, release, target.image, [(directory + "/", b"")], log, step_override=5)
        refuse_in_use(target.image, "temporary-object removal inspection")
        if any(path == directory or path.startswith(directory + "/") for path in oi.namespace(target.image)):
            raise Failed("temporary directory remains after removal")
        if target.tree() != before:
            raise Failed("temporary removal changed files outside its directory")
    except (Exception, KeyboardInterrupt) as error:
        detail = dict(identity, state="INDETERMINATE", error=str(error) or type(error).__name__, time_host=now())
        try:
            receipt = target.receipt(f"discard-import-temp-failed-{attempt}", {"discard_import_temp": detail})
            log(f"IMPORT TEMP INDETERMINATE directory={directory} receipt={receipt}")
        except Exception as receipt_error:
            log(f"IMPORT TEMP INDETERMINATE directory={directory} receipt unavailable: {receipt_error}")
        raise
    receipt = target.receipt(f"discard-import-temp-{attempt}", {
        "discard_import_temp": dict(identity, state="DISCARDED", importer_boots=boots, time_host=now())})
    log(f"IMPORT TEMP DISCARDED directory={directory} receipt={receipt}")


def cmd_recover(args, log=print):
    """Bounded operator-attested writable recovery (docs/WRITABLE-ENTRY.md
    "Operator-authorized resume", OPERATOR-RUNBOOK.md 9a): the act, or
    --status, --revoke, --wait-ready. scripts/storage_fence_resume.py holds
    the mechanism; this is its release-tool entry."""
    target = Target(args.target)
    modes = [name for name in ("status", "revoke", "wait_ready") if getattr(args, name)]
    if len(modes) > 1:
        raise Failed("give one of --status, --revoke, --wait-ready")
    try:
        if args.status:
            storage_fence_resume.status(target.out, log=log)
            return 0
        if args.revoke:
            storage_fence_resume.revoke(target.out, reason=args.reason, log=log)
            return 0
        if args.wait_ready:
            if not args.id:
                raise Failed("--wait-ready needs --id <the id from RECOVERY AUTHORIZED>")
            return storage_fence_resume.wait_ready(target.out, ident=args.id, timeout=args.timeout, log=log)
        storage_fence_resume.act(target.out, attest_sole_instance=args.attest_sole_instance,
                                 accept_committed_state=args.accept_committed_state, reason=args.reason,
                                 target_identity=target.identity(), log=log)
        return 0
    except storage_fence_resume.Refused as error:
        raise Failed(str(error)) from None
    except storage_fence_resume.Fault as error:
        raise Failed(f"fault hook {error} fired; stopped as a crash would") from None


def cmd_status(args, log=print):
    target = Target(args.target)
    tree = target.tree()
    log(f"target={target.identity()} image={target.image} format={target.fs_format()} selected={target.selected(tree)} "
        f"trees={','.join(target.trees(tree))} last_accepted={target.last('accepted')} files={len(tree)}")
    for line in target.ledger_lines()[-10:]:
        log("  " + line)
    for path, node in oi.namespace(target.image).items():
        if re.fullmatch(r"\.absd-import-[0-9a-fA-F]{4}", pathlib.PurePosixPath(path).name):
            try:
                identity = import_temp_identity(target, path)
            except Failed as error:
                log(str(error))
            else:
                log("IMPORT CANDIDATE ownership=unestablished " + json.dumps(identity, sort_keys=True))


def cmd_verify_backup(args, log=print):
    if (getattr(args, "recovery_point_sha256", None) is not None
            or getattr(args, "expected_release", None) is not None):
        point = recovery_snapshot(args)
        log(f"RECOVERY POINT VALID selected={point.selected} sha256={point.metadata_sha256} "
            f"state_roots={','.join(recovery_point.STATE_ROOTS)} files={len(point.tree)}")
        return
    meta, tree, selected = validate_backup(args.backup)
    log(f"BACKUP VALID selected={selected} format={meta['disk']['fs_format']} files={len(tree)}")


def cmd_preview(args, log=print):
    import media
    import preview_bundle
    try:
        out = preview_bundle.compose(args)
    except (OSError, ValueError, subprocess.SubprocessError, media.Refused,
            preview_bundle.c_kit_source.Refused, preview_bundle.absd_try.Refused) as error:
        raise Failed(str(error)) from error
    log(f"PREVIEW BUILT assets={out} work={args.work}; not accepted or published")


def cmd_preview_finalize(args, log=print):
    import preview_bundle
    try:
        out = preview_bundle.finalize(args.out, args.quickstart)
    except (OSError, ValueError, preview_bundle.absd_try.Refused) as error:
        raise Failed(str(error)) from error
    log(f"PREVIEW FINALIZED assets={out}; media unchanged, not accepted or published")


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

    p = sub.add_parser("preview", help="build and seal developer-preview assets through the current media tools")
    for name in ("platform", "kernel", "platform-commit", "kernel-commit", "id", "tag",
                 "repository", "authorized-keys", "notices", "boot-sources", "work", "out"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--profile", default="vm-operator")
    p.add_argument("--limitation", action="append", default=[])
    p.add_argument("--quickstart", help="include an already generated quickstart from the site's generator")
    p = sub.add_parser("preview-finalize", help="attach the generated guide without rebuilding preview media")
    p.add_argument("--out", required=True)
    p.add_argument("--quickstart", required=True)
    p = sub.add_parser("build")
    p.add_argument("--kernel", required=True)
    p.add_argument("--platform")
    p.add_argument("--id", required=True)
    p.add_argument("--authorized-keys")
    p.add_argument("--etc")
    enrollment = p.add_mutually_exclusive_group()
    enrollment.add_argument("--local-token-file")
    enrollment.add_argument("--local-login-verifier")
    p.add_argument("--replace", action="store_true")
    p.add_argument("out")
    p = sub.add_parser("install"); common(p); p.add_argument("--target-identity", required=True); p.add_argument("--replace", action="store_true")
    p.add_argument("--disk-profile", choices=geometry.PROFILES, help="fresh disk geometry (default: 128m)")
    p = sub.add_parser("stage"); common(p)
    p = sub.add_parser("select"); common(p)
    p = sub.add_parser("rollback"); common(p)
    p = sub.add_parser("accept"); common(p, release=False, kernel=False); p.add_argument("--key", required=True); p.add_argument("--port", type=int, default=2222)
    p = sub.add_parser("backup"); common(p, release=False, kernel=False); p.add_argument("backup")
    p.add_argument("--recovery-point", action="store_true")
    p = sub.add_parser("verify-backup"); p.add_argument("backup")
    p.add_argument("--recovery-point-sha256"); p.add_argument("--expected-release")
    p = sub.add_parser("restore"); common(p); p.add_argument("backup"); p.add_argument("--replace", action="store_true"); p.add_argument("--clone", action="store_true"); p.add_argument("--key"); p.add_argument("--port", type=int, default=2222); p.add_argument("--target-identity")
    p.add_argument("--recovery-point-sha256"); p.add_argument("--expected-release")
    p = sub.add_parser("migrate"); common(p)
    p = sub.add_parser("reconfigure"); common(p); p.add_argument("--etc", required=True); p.add_argument("--authorized-keys")
    p = sub.add_parser("remove"); common(p); p.add_argument("--id", required=True)
    p = sub.add_parser("discard-import-temp"); common(p)
    p.add_argument("--directory", required=True)
    p.add_argument("--fs-id", type=int, required=True)
    p.add_argument("--serial", type=int, required=True)
    p.add_argument("--bytes", type=int, required=True)
    p.add_argument("--sha256", required=True)
    p = sub.add_parser("status"); common(p, release=False, kernel=False)
    p = sub.add_parser("recover"); common(p, release=False, kernel=False)
    p.add_argument("--attest-sole-instance", action="store_true")
    p.add_argument("--accept-committed-state", action="store_true")
    p.add_argument("--reason", default="")
    p.add_argument("--status", action="store_true")
    p.add_argument("--revoke", action="store_true")
    p.add_argument("--wait-ready", action="store_true")
    p.add_argument("--id")
    p.add_argument("--timeout", type=float, default=storage_fence_resume.WAIT_TIMEOUT)
    args = ap.parse_args()
    for name, needs in (("install", ("release", "kernel")), ("stage", ("release", "kernel")), ("select", ("release", "kernel")),
                        ("migrate", ("release", "kernel")), ("remove", ("release", "kernel")),
                        ("reconfigure", ("release", "kernel")),
                        ("discard-import-temp", ("release", "kernel"))):
        if args.command == name:
            for need in needs:
                if getattr(args, need, None) is None:
                    ap.error(f"{name} needs --{need}")
    try:
        code = globals()["cmd_" + args.command.replace("-", "_")](args)
    except StageFailed as error:
        print(f"release: {error.state.lower()}: {error}", file=sys.stderr)
        sys.exit(1)
    except (Failed, absd_fs.Refused, oi.Failed, storage_fence_resume.Refused) as error:
        print(f"release: refused: {error}", file=sys.stderr)
        sys.exit(1)
    if code:
        sys.exit(code)


if __name__ == "__main__":
    main()
