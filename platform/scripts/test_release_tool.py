#!/usr/bin/env python3
"""Host tests of scripts/release.py's refusals: every refusal reachable
without a boot, driven by name against a fake operator directory, fake
release directories and fake kernel copies. No QEMU, no kernel build: the
importer boot, the served boot and the ISO build are replaced by tripwires
that fail the test if reached, and the host reader is replaced by a fake
disk whose state is a JSON header in a 64 MiB sparse image file (so copies
and digests behave as on a real image). The success paths of the selection
cache and of removal run against a simulated importer instead (`guest`):
the fake ISO build records the step and the importer's input stream, and
the fake boot applies that stream to the fake disk the way
src/bin/fixture_import.rs does. A clone's success path runs against a
simulated regenerate boot (`clone_boots`). Also checks that every
`python3 -I scripts/release.py ...` line in docs/OPERATOR-RUNBOOK.md parses
with the tool's own argument parser.

    python3 -I scripts/test_release_tool.py

Prints `RELEASE TOOL HOST TEST OK cases=N` when every case passes.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import absd_fs  # noqa: E402
import release_record as rr  # noqa: E402


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_").replace(".py", ""), here / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rel = load("release.py")
RUNBOOK = here.parent / "docs" / "OPERATOR-RUNBOOK.md"
COMMIT_A = "a" * 40
COMMIT_B = "b" * 40
MAGIC = b"FAKEDISK"


# -- the fake disk ------------------------------------------------------------

def write_disk(path, files, fs_format=2, fs_id=7, seq=11, layout=True, refuse=None):
    """A sparse operator-sized image whose first bytes describe the disk."""
    state = {"files": {p: d.decode("latin-1") for p, d in files.items()}, "format": fs_format, "fs_id": fs_id,
             "seq": seq, "layout": layout, "refuse": refuse}
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(MAGIC + json.dumps(state).encode() + b"\n")
        handle.truncate(rel.oi.IMAGE_BYTES)
    return path


def read_disk(path):
    with open(path, "rb") as handle:
        head = handle.read(1 << 20)
    if not head.startswith(MAGIC):
        raise absd_fs.Refused("not a fake disk")
    return json.loads(head[len(MAGIC):head.index(b"\n")])


class FakeRegion:
    def __init__(self, path):
        self.state = read_disk(path)

    def read(self, sector, count=1):
        fmt = self.state["format"]
        return (b"" if fmt is None else b"ABSDFSS%d" % fmt).ljust(512 * count, b"\0")


def fake_fs_region(path, device_sectors):
    state = read_disk(path)
    return FakeRegion(path) if state["layout"] else None


def fake_select(region):
    return {"fs_id": region.state["fs_id"], "seq": region.state["seq"]}


def fake_tree(path):
    state = read_disk(path)
    if state["refuse"]:
        raise absd_fs.Refused(state["refuse"])
    return {p: d.encode("latin-1") for p, d in state["files"].items()}


class GuestBoot(AssertionError):
    pass


def tripwire(*args, **kwargs):
    raise GuestBoot("a refusal path reached a guest boot or a kernel build")


# -- the simulated importer (guest mode) ---------------------------------------

ISO_MAGIC = b"FAKEISO\n"


def fake_kernel_iso(kernel, step, worker, options="", server="", input_bytes=b"", work=None):
    """What the kernel's durable-iso target would make, as a description:
    the step, the worker's digest, and the importer's input stream."""
    path = pathlib.Path(kernel) / "build" / "durable" / f"absd-durable-{step}.iso"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(ISO_MAGIC + json.dumps({"step": step, "worker": sha(worker), "input": input_bytes.hex()}).encode())
    return path


def parse_stream(data):
    assert data[:8] == b"ABSDFIX1"
    at, entries = 8, []
    while True:
        (length,) = struct.unpack_from("<H", data, at)
        at += 2
        if length == 0:
            break
        path = data[at:at + length].decode()
        at += length
        (size,) = struct.unpack_from("<Q", data, at)
        at += 8 + 32
        entries.append((path, data[at:at + size]))
        at += size
    return entries


def apply_importer(image, step, entries):
    """fixture_import.rs on the fake disk: (ok, output)."""
    try:
        state = read_disk(image)
    except absd_fs.Refused:
        if step != 1:
            return False, "step 2 needs a filesystem already on the device"
        state = {"files": {}, "format": 2, "fs_id": 7, "seq": 0, "layout": True, "refuse": None}
    files = {p: d.encode("latin-1") for p, d in state["files"].items()}
    for path, data in entries:
        if step == 5:
            gone = [p for p in files if p.startswith(path)]
            if not path.endswith("/") or path == "/" or not gone:
                return False, f"{path}: not a removable directory"
            for name in gone:
                del files[name]
        elif step == 4:
            files[path] = data
        elif step in (1, 2):
            if path in files:
                return False, f"{path}: File exists"
            files[path] = data
        else:
            return False, f"unknown step {step}"
    write_disk(image, files, fs_format=state["format"], fs_id=state["fs_id"], seq=state["seq"] + 1,
               layout=state["layout"], refuse=state["refuse"])
    return True, f"FIXTURE IMPORT OK files={len(entries)}"


def console(text):
    return f"EXTERNAL OUTPUT CHUNK offset=0 data={text.encode().hex()}\n".encode()


# -- fake releases, kernels, targets ------------------------------------------

def record_bytes(release_id, **identity):
    fields = dict(rr.IDENTITY, **identity)
    body = "".join(line + "\n" for line in
                   [rr.RECORD_HEADER, f"release={release_id}"] + [f"{k}={v}" for k, v in fields.items()])
    return (body + "check=" + hashlib.sha256(body.encode()).hexdigest() + "\n").encode()


def make_release(path, release_id, commit=COMMIT_A, keys=True, manifest=True, schema="absd-release-manifest/1",
                 manifest_id=None, manifest_identity=None, artifacts=True, **identity):
    path = pathlib.Path(path)
    (path / "tree" / "bin").mkdir(parents=True)
    (path / "tree" / "share").mkdir(parents=True)
    (path / "tree" / "bin" / "release").write_bytes(f"release command of {release_id}\n".encode())
    (path / "tree" / "share" / "intro.1").write_bytes(b".Dd manual\n")
    (path / "site-defaults" / "etc").mkdir(parents=True)
    (path / "site-defaults" / "etc" / "network.conf").write_bytes(b"address 10.0.2.15\n")
    if keys:
        (path / "site-defaults" / "authorized_keys").write_bytes(b"ssh-ed25519 AAAAC3Nzfake operator\n")
    for name in (rel.ISO, "fixture-import.elf", "absd-fsd.elf", "absd-fsd-regenerate.elf", "sshd.elf"):
        (path / name).write_bytes(f"{name} of {release_id}\n".encode())
    (path / "release").write_bytes(record_bytes(release_id, **identity))
    if manifest:
        ident = dict(rr.IDENTITY, **identity, **(manifest_identity or {}))
        (path / "release-manifest.toml").write_text(
            f'schema = "{schema}"\n\n[release]\nid = "{manifest_id or release_id}"\n\n[identity]\n'
            + "".join(f"{k} = {v}\n" for k, v in ident.items())
            + f'\n[source]\nkernel_commit = "{commit}"\n')
        if artifacts:
            # As release_manifest.py build records them: every file of the
            # directory but the manifest, by path relative to it.
            with open(path / "release-manifest.toml", "a") as handle:
                for file in sorted(p for p in path.rglob("*") if p.is_file() and p.name != "release-manifest.toml"):
                    name = file.relative_to(path).as_posix()
                    handle.write(f'\n[artifacts.files."{name}"]\nsha256 = "{sha(file)}"\nbytes = {file.stat().st_size}\n')
    return path


def make_kernel(path, commit=COMMIT_A):
    path = pathlib.Path(path)
    path.mkdir(parents=True)
    (path / "Makefile").write_text("# a fake kernel copy: never built\n")
    (path / ".absd-identity").write_text(commit + "\n")
    (path / "scripts").mkdir()
    (path / "scripts" / "durable-boot.sh").write_text(f"#!/bin/sh\n# the durable boot of kernel {commit[:12]}\n")
    return path


def disk_files(*releases, selected=None, extra=None):
    files = {}
    for release in releases:
        files.update(dict(release.tree_files()))
    if selected:
        files[rr.SELECTED] = rr.selected_bytes(selected)
    files["/etc/network.conf"] = b"address 10.0.2.15\n"
    files["/ssh/authorized_keys"] = b"ssh-ed25519 AAAAC3Nzfake operator\n"
    files["/ssh/host_ed25519_seed"] = bytes(range(32))
    files["/home/operator/.accept"] = b"accept marker\n"
    files.update(extra or {})
    return files


class Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)

    def __getattr__(self, name):
        return None


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


# -- the cases ----------------------------------------------------------------

class ReleaseToolRefusals(unittest.TestCase):
    """Each test names the refusal it drives; the release.py function is in
    the test name, the expected text in the assertion."""

    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp(prefix="test-release-tool-"))
        self.saved = []
        for owner, name, value in ((rel.oi, "tree", fake_tree), (rel.absd_fs, "fs_region", fake_fs_region),
                                   (rel.absd_fs, "select", fake_select), (rel, "import_files", tripwire),
                                   (rel, "Boot", tripwire), (rel.oi, "kernel_iso", tripwire),
                                   (rel, "run_boot", tripwire)):
            self.saved.append((owner, name, getattr(owner, name)))
            setattr(owner, name, value)
        self.A = rel.Release(make_release(self.work / "rel-a", "rel-a", COMMIT_A))
        self.B = rel.Release(make_release(self.work / "rel-b", "rel-b", COMMIT_B))
        self.KA = make_kernel(self.work / "kernel-a", COMMIT_A)
        self.KB = make_kernel(self.work / "kernel-b", COMMIT_B)
        self.holder = None
        self.boots = []
        self.boot_fault = None

    def tearDown(self):
        if self.holder is not None:
            self.holder.kill()
            self.holder.wait()
        for owner, name, value in reversed(self.saved):
            setattr(owner, name, value)
        shutil.rmtree(self.work, ignore_errors=True)

    # helpers

    def guest(self, build=True):
        """The simulated importer: importer boots apply their stream to the
        fake disk. With build=False, any ISO build is still a tripwire, so
        a path that compiles fails the test."""
        rel.import_files = self.saved_value(rel, "import_files")
        rel.oi.kernel_iso = fake_kernel_iso if build else tripwire
        rel.run_boot = self.fake_boot

    def saved_value(self, owner, name):
        return next(value for o, n, value in self.saved if o is owner and n == name)

    def fake_boot(self, script, iso, image, serial):
        data = pathlib.Path(iso).read_bytes()
        self.assertTrue(data.startswith(ISO_MAGIC), iso)
        desc = json.loads(data[len(ISO_MAGIC):])
        entries = parse_stream(bytes.fromhex(desc["input"]))
        self.boots.append({"script": pathlib.Path(script), "iso": pathlib.Path(iso), "step": desc["step"],
                           "entries": entries})
        if self.boot_fault == "before":
            ok, text = False, "power cut before the commit"
        elif self.boot_fault == "interrupt-before":
            raise KeyboardInterrupt
        elif self.boot_fault == "script":
            raise subprocess.CalledProcessError(1, [str(script)], stderr="durable-boot.sh: test -f failed\n")
        else:
            ok, text = apply_importer(image, desc["step"], entries)
            if self.boot_fault == "after":
                ok, text = False, "stopped after the commit"
            elif self.boot_fault == "interrupt-after":
                raise KeyboardInterrupt
            elif self.boot_fault == "outside":
                state = read_disk(image)
                state["files"]["/etc/network.conf"] = "address 10.0.2.99\n"
                write_disk(image, {p: d.encode("latin-1") for p, d in state["files"].items()}, seq=state["seq"])
        if self.boot_fault == "partial":
            state = read_disk(image)
            state["files"]["/releases/rel-a/bin/release"] = "left behind"
            write_disk(image, {p: d.encode("latin-1") for p, d in state["files"].items()}, seq=state["seq"])
        pathlib.Path(serial).write_bytes(console(text if ok else f"FIXTURE IMPORT FAILED {text}"))
        return "3" if ok else "7"

    def with_cache(self, out, release, kernel):
        """OUT/releases/<id>/ as install or stage leaves it."""
        saved, rel.oi.kernel_iso = rel.oi.kernel_iso, fake_kernel_iso
        try:
            with tempfile.TemporaryDirectory(dir=out) as work:
                rel.install_select_cache(rel.Target(out), rel.build_select_cache(kernel, release, work))
        finally:
            rel.oi.kernel_iso = saved
        return out / "releases" / release.id

    def target(self, files, ledger=(), **disk):
        out = self.work / "out"
        out.mkdir(exist_ok=True)
        write_disk(out / rel.IMAGE, files, **disk)
        (out / rel.TARGET).write_text("lab-1\n")
        (out / rel.LEDGER).write_text("".join(f"2026-10-12T00:00:0{i}Z {line}\n" for i, line in enumerate(ledger)))
        for rid in ("rel-a", "rel-b"):
            (out / "releases" / rid).mkdir(parents=True, exist_ok=True)
            (out / "releases" / rid / rel.ISO).write_bytes(f"iso of {rid}\n".encode())
        shutil.copyfile(out / "releases" / "rel-a" / rel.ISO, out / rel.ISO)
        return out

    def a_selected(self, ledger=("installed rel-a", "selected rel-a", "accepted rel-a")):
        return self.target(disk_files(self.A, selected="rel-a"), ledger)

    def both(self, selected="rel-b", ledger=("installed rel-a", "selected rel-a", "accepted rel-a", "staged rel-b",
                                             "selected rel-b from=rel-a")):
        return self.target(disk_files(self.A, self.B, selected=selected), ledger)

    def refused(self, func, text, **kw):
        with self.assertRaises(rel.Failed) as caught:
            func(Args(**kw), log=lambda line: None)
        self.assertIn(text, str(caught.exception))
        return str(caught.exception)

    def unchanged(self, out, before, func, text, **kw):
        """The refusal, and the disk image and ledger exactly as before."""
        ledger = (out / rel.LEDGER).read_text()
        message = self.refused(func, text, **kw)
        self.assertEqual(sha(out / rel.IMAGE), before)
        self.assertEqual((out / rel.LEDGER).read_text(), ledger)
        return message

    def hold_open(self, path):
        self.holder = subprocess.Popen(
            [sys.executable, "-I", "-c", "import sys, time\nf = open(sys.argv[1], 'rb')\nprint('held', flush=True)\n"
             "time.sleep(300)\n", str(path)], stdout=subprocess.PIPE)
        self.assertEqual(self.holder.stdout.readline(), b"held\n")
        return self.holder.pid

    def release_holder(self):
        self.holder.kill()
        self.holder.wait()
        self.holder = None

    def backup_of(self, out):
        dest = self.work / "backup"
        rel.cmd_backup(Args(target=str(out), backup=str(dest)), log=lambda line: None)
        return dest

    def edit_toml(self, path, old, new):
        text = path.read_text()
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1))

    # version pair: the kernel copy and the release's manifest (check_kernel, Release.kernel_commit)

    def test_check_kernel_refuses_a_kernel_at_another_commit(self):
        out = self.a_selected()
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_select, f"kernel checkout is at {COMMIT_B[:12]}, "
                       f"release rel-a was built from {COMMIT_A[:12]}", release=str(self.A.path),
                       kernel=str(self.KB), target=str(out))

    def test_check_kernel_refuses_the_canonical_kernel_checkout(self):
        canonical = make_kernel(self.work / "canonical", COMMIT_A)
        (canonical / ".git").write_text("gitdir: elsewhere\n")
        self.refused(rel.cmd_stage, "the canonical kernel checkout is never a build target",
                     release=str(self.A.path), kernel=str(canonical), target=str(self.work / "out"))

    def test_check_kernel_refuses_a_directory_that_is_not_a_kernel(self):
        plain = self.work / "plain"
        plain.mkdir()
        self.refused(rel.cmd_stage, "not a kernel checkout", release=str(self.A.path), kernel=str(plain),
                     target=str(self.work / "out"))

    def test_check_kernel_refuses_a_missing_kernel_option(self):
        out = self.a_selected()
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_stage, f"give --kernel <a kernel checkout at "
                       f"{COMMIT_B[:12]}> (release rel-b)", release=str(self.B.path), target=str(out))

    def test_kernel_commit_refuses_a_manifest_identity_mismatch(self):
        bad = rel.Release(make_release(self.work / "bad", "bad", manifest_identity={"fsd_protocol": 3}))
        self.refused(rel.cmd_install, "manifest identity_mismatch", release=str(bad.path), kernel=str(self.KA),
                     target=str(self.work / "out"), target_identity="lab-1")

    def test_kernel_commit_refuses_a_manifest_release_mismatch(self):
        bad = rel.Release(make_release(self.work / "bad", "bad", manifest_id="other"))
        self.refused(rel.cmd_install, "manifest release_mismatch", release=str(bad.path), kernel=str(self.KA),
                     target=str(self.work / "out"), target_identity="lab-1")

    def test_kernel_commit_refuses_a_missing_manifest(self):
        bad = rel.Release(make_release(self.work / "bad", "bad", manifest=False))
        self.refused(rel.cmd_install, "missing release-manifest.toml", release=str(bad.path), kernel=str(self.KA),
                     target=str(self.work / "out"), target_identity="lab-1")

    def test_kernel_commit_refuses_a_malformed_manifest(self):
        bad = make_release(self.work / "bad", "bad")
        (bad / "release-manifest.toml").write_text("schema = \n")
        self.refused(rel.cmd_install, "malformed release manifest:", release=str(bad), kernel=str(self.KA),
                     target=str(self.work / "out"), target_identity="lab-1")

    def test_kernel_commit_reads_both_manifest_schemas(self):
        # /2 adds the recorded kernel features; an installed /1 release still
        # names its kernel the same way.
        for schema in ("absd-release-manifest/1", "absd-release-manifest/2"):
            release = rel.Release(make_release(self.work / schema.replace("/", "-"), "rel-a", COMMIT_A, schema=schema))
            self.assertEqual(release.kernel_commit(), COMMIT_A)

    def test_kernel_commit_refuses_another_manifest_schema(self):
        bad = make_release(self.work / "bad", "bad", schema="absd-release-manifest/3")
        self.refused(rel.cmd_install, "unsupported release manifest schema", release=str(bad), kernel=str(self.KA),
                     target=str(self.work / "out"), target_identity="lab-1")

    def test_kernel_commit_refuses_missing_manifest_tables(self):
        bad = make_release(self.work / "bad", "bad")
        (bad / "release-manifest.toml").write_text('schema = "absd-release-manifest/1"\n[release]\nid = "bad"\n')
        self.refused(rel.cmd_install, "malformed release manifest tables", release=str(bad), kernel=str(self.KA),
                     target=str(self.work / "out"), target_identity="lab-1")

    def test_kernel_commit_refuses_an_invalid_kernel_commit(self):
        bad = make_release(self.work / "bad", "bad", commit="HEAD")
        self.refused(rel.cmd_install, "missing or invalid manifest kernel_commit", release=str(bad),
                     kernel=str(self.KA), target=str(self.work / "out"), target_identity="lab-1")

    # missing inputs: the release directory (Release)

    def test_release_refuses_a_directory_without_its_importer(self):
        (self.A.path / "fixture-import.elf").unlink()
        self.refused(rel.cmd_stage, "missing fixture-import.elf", release=str(self.A.path), kernel=str(self.KA),
                     target=str(self.work / "out"))

    def test_release_refuses_each_missing_artifact(self):
        for name in (rel.ISO, "absd-fsd.elf", "absd-fsd-regenerate.elf", "sshd.elf", "tree"):
            with self.subTest(name=name):
                path = make_release(self.work / f"miss-{name}", "miss")
                (shutil.rmtree if name == "tree" else pathlib.Path.unlink)(path / name)
                self.refused(rel.cmd_select, f"missing {name}", release=str(path), kernel=str(self.KA),
                             target=str(self.work / "out"))

    def test_release_refuses_a_directory_without_a_record(self):
        (self.A.path / "release").unlink()
        self.refused(rel.cmd_install, "no release record", release=str(self.A.path), kernel=str(self.KA),
                     target=str(self.work / "out"), target_identity="lab-1")

    def test_release_refuses_a_record_whose_check_fails(self):
        data = (self.A.path / "release").read_bytes().replace(b"app_abi=1", b"app_abi=2")
        (self.A.path / "release").write_bytes(data)
        self.refused(rel.cmd_install, "check_mismatch", release=str(self.A.path), kernel=str(self.KA),
                     target=str(self.work / "out"), target_identity="lab-1")

    # install

    def test_install_refuses_an_existing_image_without_replace(self):
        out = self.a_selected()
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_install, "exists; --replace to install over it",
                       release=str(self.A.path), kernel=str(self.KA), target=str(out), target_identity="lab-1")

    def test_install_refuses_another_target_identity(self):
        out = self.a_selected()
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_install, "target identity is 'lab-1', not 'lab-2'",
                       release=str(self.A.path), kernel=str(self.KA), target=str(out), target_identity="lab-2",
                       replace=True)

    def test_install_refuses_a_release_without_authorized_keys(self):
        keyless = rel.Release(make_release(self.work / "keyless", "keyless", keys=False))
        out = self.work / "fresh"
        self.refused(rel.cmd_install, "the release ships no authorized keys", release=str(keyless.path),
                     kernel=str(self.KA), target=str(out), target_identity="lab-1")
        self.assertFalse((out / rel.IMAGE).exists())

    # stage: format, duplicate, slots, the disk itself

    def test_stage_refuses_a_release_of_another_format(self):
        old = rel.Release(make_release(self.work / "old", "old", fs_format=1))
        out = self.a_selected()
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_stage, "the disk is format 2; release old reads format 1: "
                       "migrate first", release=str(old.path), kernel=str(self.KA), target=str(out))

    def test_stage_refuses_a_release_already_on_the_disk(self):
        out = self.a_selected()
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_stage, "release rel-a is already on the disk",
                       release=str(self.A.path), kernel=str(self.KA), target=str(out))

    def test_stage_refuses_a_third_release_with_two_trees(self):
        third = rel.Release(make_release(self.work / "rel-c", "rel-c", COMMIT_A))
        out = self.both()
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_stage, "the disk holds 2 releases (rel-a, rel-b); at most 2",
                       release=str(third.path), kernel=str(self.KA), target=str(out))

    def test_stage_refuses_a_disk_the_host_reader_refuses(self):
        out = self.target(disk_files(self.A, selected="rel-a"), refuse="superblock digest")
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_stage, "the host reader refuses the disk: superblock digest",
                       release=str(self.B.path), kernel=str(self.KB), target=str(out))

    def test_stage_refuses_a_disk_without_a_layout(self):
        out = self.target(disk_files(self.A, selected="rel-a"), layout=False)
        self.refused(rel.cmd_stage, "no layout (not an ABSD disk)", release=str(self.B.path), kernel=str(self.KB),
                     target=str(out))

    def test_stage_refuses_a_missing_disk_image(self):
        out = self.a_selected()
        (out / rel.IMAGE).unlink()
        self.refused(rel.cmd_stage, "no disk image", release=str(self.B.path), kernel=str(self.KB), target=str(out))

    def test_stage_refuses_a_malformed_selection(self):
        out = self.target(disk_files(self.A, extra={rr.SELECTED: b"rel-a"}))
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_stage, "malformed_selected", release=str(self.B.path),
                       kernel=str(self.KB), target=str(out))

    # stage and install against the release manifest (Release.verified_tree_files)

    def assert_stage_refusal_only(self, out, before):
        after = snapshot(out)
        added = set(after) - set(before)
        self.assertEqual(len(added), 1, added)
        name = added.pop()
        self.assertTrue(name.startswith("receipts/stage-failed-"), name)
        receipt = rel.read_toml_flat(out / name)["stage"]
        self.assertEqual(receipt["state"], "REFUSED")
        self.assertFalse(receipt["target_effects_possible"])
        del after[name]
        self.assertEqual(after, before)
        return receipt

    def test_receipt_round_trip_del_surrogates_and_controls(self):
        out = self.a_selected()
        text = 'DEL \x7f surrogate \udcff high \ud800 controls \x00\x08\x0c\x1b\t\r\n quote " slash \\ unicode café'
        expected = text.replace("\udcff", "\ufffd").replace("\ud800", "\ufffd")
        path = rel.Target(out).receipt("round-trip", {"stage": {"error": text, "items": [text]}})
        raw = path.read_bytes()
        self.assertIn(b"\\u007f", raw)
        self.assertNotIn(b"\x7f", raw)
        self.assertIn("café", raw.decode("utf-8"))
        data = rel.read_toml_flat(path)
        self.assertEqual(data, {"stage": {"error": expected, "items": [expected]}})

    def test_stage_non_utf8_source_path_still_records_a_parseable_refusal(self):
        out = self.a_selected()
        before = snapshot(out)
        source = str(self.work / "release-\udcff")
        self.refused(rel.cmd_stage, "stage state=REFUSED", release=source,
                     kernel=str(self.KB), target=str(out))
        receipt = self.assert_stage_refusal_only(out, before)
        self.assertEqual(receipt["release_source"], source.replace("\udcff", "\ufffd"))
        self.assertIn("no release record", receipt["error"])
        self.assertIn("\ufffd", receipt["error"])

    def test_stage_repeated_refusals_keep_distinct_receipts(self):
        self.guest()
        out = self.a_selected()
        (self.B.path / "tree/bin/release").write_bytes(b"changed\n")
        attempts = set()
        for _ in range(2):
            before = snapshot(out)
            self.refused(rel.cmd_stage, "manifest_mismatch digest tree/bin/release",
                         release=str(self.B.path), kernel=str(self.KB), target=str(out))
            receipt = self.assert_stage_refusal_only(out, before)
            self.assertEqual(receipt["release"], "rel-b")
            self.assertEqual(receipt["phase"], "verify-inputs")
            self.assertIn("manifest_mismatch digest tree/bin/release", receipt["error"])
            attempts.add(receipt["attempt"])
        self.assertEqual(len(attempts), 2)
        self.assertEqual(self.boots, [])

    def test_stage_missing_release_has_a_refusal_receipt(self):
        out = self.a_selected()
        before = snapshot(out)
        self.refused(rel.cmd_stage, "no release record", release=str(self.work / "absent"),
                     kernel=str(self.KB), target=str(out))
        receipt = self.assert_stage_refusal_only(out, before)
        self.assertEqual(receipt["release"], "unknown")
        self.assertEqual(receipt["phase"], "prepare")

    def test_stage_importer_failure_is_indeterminate_before_and_after_commit(self):
        self.guest()
        for fault in ("before", "after", "script"):
            with self.subTest(fault=fault):
                out = self.a_selected()
                before = sha(out / rel.IMAGE)
                ledger = (out / rel.LEDGER).read_bytes()
                prior = set((out / "receipts").glob("stage-failed-*.toml"))
                self.boot_fault = fault
                message = self.refused(rel.cmd_stage, "stage state=INDETERMINATE", release=str(self.B.path),
                                       kernel=str(self.KB), target=str(out))
                added = set((out / "receipts").glob("stage-failed-*.toml")) - prior
                self.assertEqual(len(added), 1, message)
                receipt = rel.read_toml_flat(added.pop())["stage"]
                self.assertEqual(receipt["state"], "INDETERMINATE")
                self.assertEqual(receipt["phase"], "import")
                self.assertTrue(receipt["target_effects_possible"])
                self.assertEqual((out / rel.LEDGER).read_bytes(), ledger)
                self.assertEqual(rel.Target(out).selected(), "rel-a")
                self.assertEqual(sha(out / rel.IMAGE) == before, fault != "after")
                self.assertFalse(list((out / "receipts").glob("stage-rel-b-*.toml")))

    def test_stage_interrupt_after_commit_records_uncertainty_and_propagates(self):
        self.guest()
        out = self.a_selected()
        self.boot_fault = "interrupt-after"
        with self.assertRaises(KeyboardInterrupt):
            rel.cmd_stage(Args(release=str(self.B.path), kernel=str(self.KB), target=str(out)), log=lambda _: None)
        path, = (out / "receipts").glob("stage-failed-*.toml")
        receipt = rel.read_toml_flat(path)["stage"]
        self.assertEqual(receipt["state"], "INDETERMINATE")
        self.assertEqual(receipt["error"], "KeyboardInterrupt")
        self.assertTrue(receipt["target_effects_possible"])
        self.assertIn("rel-b", rel.Target(out).trees())

    def test_stage_readback_failure_records_uncertainty(self):
        self.guest()
        out = self.a_selected()
        saved = rel.verify_files
        def fail(*args):
            raise rel.Failed('readback failed\nsecond line "quoted"\twith tab')
        rel.verify_files = fail
        try:
            self.refused(rel.cmd_stage, "stage state=INDETERMINATE", release=str(self.B.path),
                         kernel=str(self.KB), target=str(out))
        finally:
            rel.verify_files = saved
        path, = (out / "receipts").glob("stage-failed-*.toml")
        receipt = rel.read_toml_flat(path)["stage"]
        self.assertEqual(receipt["phase"], "verify-target")
        self.assertEqual(receipt["error"], 'readback failed\nsecond line "quoted"\twith tab')
        self.assertEqual(receipt["state"], "INDETERMINATE")
        self.assertFalse(list((out / "receipts").glob("stage-rel-b-*.toml")))

    def test_stage_receipt_io_failure_preserves_original_error_and_state(self):
        self.guest()
        out = self.a_selected()
        self.boot_fault = "after"
        (out / "receipts").write_bytes(b"not a directory")
        message = self.refused(rel.cmd_stage, "stage state=INDETERMINATE", release=str(self.B.path),
                               kernel=str(self.KB), target=str(out))
        self.assertIn("importer boot 1", message)
        self.assertIn("receipt unavailable:", message)
        self.assertEqual((out / "receipts").read_bytes(), b"not a directory")

    def test_stage_cli_reports_the_effect_disposition(self):
        self.guest()
        original_argv = sys.argv
        for fault, state in ((None, "refused"), ("after", "indeterminate")):
            with self.subTest(state=state):
                out = self.a_selected()
                self.boot_fault = fault
                source = self.B.path if fault else self.work / "absent"
                sys.argv = ["release.py", "stage", "--release", str(source), "--kernel", str(self.KB),
                            "--target", str(out)]
                try:
                    with contextlib.redirect_stderr(io.StringIO()) as err, contextlib.redirect_stdout(io.StringIO()):
                        with self.assertRaises(SystemExit) as caught:
                            rel.main()
                    self.assertEqual(caught.exception.code, 1)
                    self.assertIn(f"release: {state}:", err.getvalue())
                    self.assertIn("receipt=", err.getvalue())
                finally:
                    sys.argv = original_argv

    def test_stage_ledger_failure_keeps_staged_evidence_and_records_uncertainty(self):
        self.guest()
        out = self.a_selected()
        original = rel.Target.ledger_append
        def fail(*args, **kw):
            raise OSError("ledger unavailable")
        rel.Target.ledger_append = fail
        try:
            self.refused(rel.cmd_stage, "stage state=INDETERMINATE", release=str(self.B.path),
                         kernel=str(self.KB), target=str(out))
        finally:
            rel.Target.ledger_append = original
        self.assertEqual(self.receipt_of(out, "stage-rel-b")["stage"]["state"], "STAGED")
        path, = (out / "receipts").glob("stage-failed-*.toml")
        outcome = rel.read_toml_flat(path)["stage"]
        self.assertEqual(outcome["state"], "INDETERMINATE")
        self.assertEqual(outcome["phase"], "record-staged")
        self.assertEqual(outcome["error"], "ledger unavailable")
        self.assertIn("rel-b", rel.Target(out).trees())

    def test_matrix_corrupted_tree_case_requires_valid_receipt_and_unchanged_target(self):
        self.guest()
        matrix = load("release-matrix.py")
        matrix.rel = rel
        out = self.a_selected()
        source = snapshot(self.B.path)
        ok, detail = matrix.corrupt_tree_stage_case(rel.Target(out), self.B, self.KB, self.work)
        self.assertTrue(ok, detail)
        self.assertEqual(snapshot(self.B.path), source)
        self.assertEqual(self.boots, [])
        original = rel.cmd_stage
        for fault in ("extra-file", "receipt-state", "no-receipt"):
            with self.subTest(fault=fault):
                def altered(args, log):
                    try:
                        original(args, log)
                    except rel.StageFailed:
                        if fault == "extra-file":
                            (out / "unexpected").write_text("changed")
                        else:
                            path = max((out / "receipts").glob("stage-failed-*.toml"),
                                       key=lambda p: p.stat().st_mtime_ns)
                            if fault == "no-receipt":
                                path.unlink()
                            else:
                                path.write_text(path.read_text().replace('state = "REFUSED"', 'state = "STAGED"'))
                        raise
                rel.cmd_stage = altered
                try:
                    ok, detail = matrix.corrupt_tree_stage_case(rel.Target(out), self.B, self.KB, self.work)
                finally:
                    rel.cmd_stage = original
                self.assertFalse(ok, (fault, detail))
                (out / "unexpected").unlink(missing_ok=True)
        self.assertEqual(self.boots, [])

    def test_stage_refuses_a_tree_file_that_differs_from_the_manifest(self):
        self.guest()
        out = self.a_selected()
        (self.B.path / "tree" / "bin" / "release").write_bytes(b"tampered after the build\n")
        before = snapshot(out)
        self.refused(rel.cmd_stage, "manifest_mismatch digest tree/bin/release", release=str(self.B.path),
                     kernel=str(self.KB), target=str(out))
        self.assert_stage_refusal_only(out, before)
        self.assertEqual(self.boots, [])

    def test_stage_refuses_a_tree_file_the_manifest_does_not_list(self):
        self.guest()
        out = self.a_selected()
        (self.B.path / "tree" / "bin" / "extra").write_bytes(b"not in the manifest\n")
        before = snapshot(out)
        self.refused(rel.cmd_stage, "manifest_mismatch unrecorded tree/bin/extra", release=str(self.B.path),
                     kernel=str(self.KB), target=str(out))
        self.assert_stage_refusal_only(out, before)
        self.assertEqual(self.boots, [])

    def test_stage_refuses_a_tree_file_the_manifest_lists_but_is_gone(self):
        self.guest()
        out = self.a_selected()
        (self.B.path / "tree" / "share" / "intro.1").unlink()
        self.refused(rel.cmd_stage, "manifest_mismatch missing tree/share/intro.1", release=str(self.B.path),
                     kernel=str(self.KB), target=str(out))
        self.assertEqual(self.boots, [])

    def test_verified_tree_refuses_a_record_changed_after_the_release_was_opened(self):
        # A changed record that still parses is refused earlier (malformed_record,
        # identity_mismatch); this is the window between opening and reading.
        (self.B.path / "release").write_bytes(record_bytes("rel-b") + b"# appended\n")
        with self.assertRaises(rel.Failed) as caught:
            self.B.verified_tree_files()
        self.assertIn("manifest_mismatch digest release", str(caught.exception))

    def test_stage_refuses_an_importer_that_differs_from_the_manifest(self):
        self.guest()
        out = self.a_selected()
        (self.B.path / "fixture-import.elf").write_bytes(b"another importer\n")
        self.refused(rel.cmd_stage, "manifest_mismatch digest fixture-import.elf", release=str(self.B.path),
                     kernel=str(self.KB), target=str(out))
        self.assertEqual(self.boots, [])

    def test_stage_refuses_a_boot_image_that_differs_from_the_manifest(self):
        self.guest()
        out = self.a_selected()
        (self.B.path / rel.ISO).write_bytes(b"another boot image\n")
        self.refused(rel.cmd_stage, f"manifest_mismatch digest {rel.ISO}", release=str(self.B.path),
                     kernel=str(self.KB), target=str(out))
        self.assertEqual(self.boots, [])

    def test_stage_refuses_a_manifest_without_artifact_digests(self):
        self.guest()
        bare = rel.Release(make_release(self.work / "bare", "rel-c", COMMIT_B, artifacts=False))
        out = self.a_selected()
        self.refused(rel.cmd_stage, "manifest_unverifiable no artifacts.files table", release=str(bare.path),
                     kernel=str(self.KB), target=str(out))
        self.assertEqual(self.boots, [])

    def test_stage_records_the_verified_manifest_in_its_receipt(self):
        self.guest()
        out = self.a_selected()
        rel.cmd_stage(Args(release=str(self.B.path), kernel=str(self.KB), target=str(out)), log=lambda line: None)
        receipt = self.receipt_of(out, "stage-rel-b")["stage"]
        self.assertEqual(receipt["manifest"], sha(self.B.manifest))
        self.assertEqual(receipt["manifest_verified"], "tree,record,fixture-import.elf(copy),iso(copy)")
        disk = read_disk(out / rel.IMAGE)["files"]
        self.assertEqual(disk["/releases/rel-b/bin/release"].encode("latin-1"), b"release command of rel-b\n")

    def test_stage_refuses_a_malformed_manifest_digest(self):
        self.guest()
        out = self.a_selected()
        self.edit_toml(self.B.manifest, f'sha256 = "{sha(self.B.path / "tree" / "bin" / "release")}"', 'sha256 = "xyz"')
        self.refused(rel.cmd_stage, "manifest_unverifiable malformed digest for tree/bin/release",
                     release=str(self.B.path), kernel=str(self.KB), target=str(out))
        self.assertEqual(self.boots, [])

    def test_stage_refuses_an_artifacts_entry_that_is_not_a_table(self):
        self.guest()
        bare = make_release(self.work / "flat", "rel-c", COMMIT_B, artifacts=False)
        with open(bare / "release-manifest.toml", "a") as handle:
            handle.write('\nartifacts = "not a table"\n')
        out = self.a_selected()
        self.refused(rel.cmd_stage, "manifest_unverifiable no artifacts.files table", release=str(bare),
                     kernel=str(self.KB), target=str(out))
        self.assertEqual(self.boots, [])

    def test_stage_refuses_a_boot_image_copy_that_differs_from_the_manifest(self):
        # The release directory's ISO checks out, but the bytes that land in
        # the operator directory do not: the copy is what is verified.
        self.guest()
        out = self.a_selected()
        real = rel.shutil.copyfile

        def corrupting(src, dst, *a, **kw):
            result = real(src, dst, *a, **kw)
            if pathlib.Path(src).name == rel.ISO and pathlib.Path(src).parent == self.B.path:
                pathlib.Path(dst).write_bytes(b"changed in transit\n")
            return result
        rel.shutil.copyfile = corrupting
        try:
            message = self.refused(rel.cmd_stage, f"manifest_mismatch digest {rel.ISO} (as copied to",
                                   release=str(self.B.path), kernel=str(self.KB), target=str(out))
        finally:
            rel.shutil.copyfile = real
        self.assertFalse((out / "releases" / "rel-b" / rel.ISO).exists(), message)
        path, = (out / "receipts").glob("stage-failed-*.toml")
        outcome = rel.read_toml_flat(path)["stage"]
        self.assertEqual(outcome["state"], "INDETERMINATE")
        self.assertEqual(outcome["phase"], "copy-boot-image")

    def test_import_files_builds_from_a_verified_copy_of_the_importer(self):
        self.guest()
        out = self.a_selected()
        rel.cmd_stage(Args(release=str(self.B.path), kernel=str(self.KB), target=str(out)), log=lambda line: None)
        self.assertTrue(self.boots)
        (self.B.path / "fixture-import.elf").write_bytes(b"swapped after the check\n")
        self.refused(rel.cmd_select, "manifest_mismatch digest fixture-import.elf", release=str(self.B.path),
                     kernel=str(self.KB), target=str(out))

    def test_migrate_refuses_a_tree_file_that_differs_from_the_manifest(self):
        self.guest()
        out = self.target(disk_files(self.A, selected="rel-a"), ("installed rel-a", "selected rel-a",
                                                                  "accepted rel-a"), fs_format=1)
        (self.B.path / "tree" / "bin" / "release").write_bytes(b"tampered\n")
        before = snapshot(out)
        self.refused(rel.cmd_migrate, "manifest_mismatch digest tree/bin/release", release=str(self.B.path),
                     kernel=str(self.KB), target=str(out))
        self.assertEqual(snapshot(out), before)
        self.assertEqual(self.boots, [])

    def test_install_refuses_authorized_keys_that_differ_from_the_manifest(self):
        self.guest()
        out = self.work / "out"
        (self.A.path / "site-defaults" / "authorized_keys").write_bytes(b"ssh-ed25519 AAAAC3Nzother intruder\n")
        self.refused(rel.cmd_install, "manifest_mismatch digest site-defaults/authorized_keys",
                     release=str(self.A.path), kernel=str(self.KA), target=str(out), target_identity="lab-1")
        self.assertFalse((out / rel.IMAGE).exists())
        self.assertEqual(self.boots, [])

    def test_install_refuses_a_site_default_the_manifest_does_not_list(self):
        self.guest()
        out = self.work / "out"
        (self.A.path / "site-defaults" / "etc" / "sshd.conf").write_bytes(b"port 22\n")
        self.refused(rel.cmd_install, "manifest_mismatch unrecorded site-defaults/etc/sshd.conf",
                     release=str(self.A.path), kernel=str(self.KA), target=str(out), target_identity="lab-1")
        self.assertEqual(self.boots, [])

    def test_install_records_the_verified_manifest_in_its_receipt(self):
        self.guest()
        out = self.work / "out"
        rel.cmd_install(Args(release=str(self.A.path), kernel=str(self.KA), target=str(out), target_identity="lab-1"),
                        log=lambda line: None)
        receipt = self.receipt_of(out, "install-rel-a")["install"]
        self.assertEqual(receipt["manifest"], sha(self.A.manifest))
        self.assertEqual(receipt["manifest_verified"], "tree,record,site-defaults,fixture-import.elf(copy),iso(copies)")
        self.assertEqual(sha(out / rel.ISO), sha(self.A.path / rel.ISO))

    def test_install_refuses_a_tree_file_that_differs_from_the_manifest(self):
        self.guest()
        out = self.work / "out"
        (self.A.path / "tree" / "bin" / "release").write_bytes(b"tampered\n")
        self.refused(rel.cmd_install, "manifest_mismatch digest tree/bin/release", release=str(self.A.path),
                     kernel=str(self.KA), target=str(out), target_identity="lab-1")
        self.assertFalse((out / rel.IMAGE).exists())
        self.assertEqual(self.boots, [])

    # select

    def test_select_refuses_a_release_without_a_tree(self):
        out = self.a_selected()
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_select, "release rel-b has no tree on the disk",
                       release=str(self.B.path), kernel=str(self.KB), target=str(out))

    def test_select_refuses_a_corrupted_staged_record(self):
        files = disk_files(self.A, self.B, selected="rel-a")
        files["/releases/rel-b/release"] = files["/releases/rel-b/release"].replace(b"app_abi=1", b"app_abi=9")
        out = self.target(files)
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_select, "check_mismatch", release=str(self.B.path),
                       kernel=str(self.KB), target=str(out))

    def test_select_refuses_a_partial_stage_without_its_record(self):
        files = disk_files(self.A, self.B, selected="rel-a")
        del files["/releases/rel-b/release"]
        out = self.target(files)
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_select, "no_release_tree", release=str(self.B.path),
                       kernel=str(self.KB), target=str(out))

    # rollback

    def test_rollback_refuses_with_no_other_accepted_release(self):
        out = self.both(ledger=("installed rel-a", "selected rel-a", "staged rel-b", "selected rel-b"))
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_rollback, "nothing to roll back to",
                       release=str(self.A.path), kernel=str(self.KA), target=str(out))

    def test_rollback_refuses_when_only_the_selected_release_was_accepted(self):
        out = self.both(ledger=("installed rel-a", "selected rel-a", "staged rel-b", "selected rel-b",
                                "accepted rel-b"))
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_rollback, "nothing to roll back to",
                       release=str(self.A.path), kernel=str(self.KA), target=str(out))

    def test_rollback_refuses_a_target_without_its_tree(self):
        out = self.target(disk_files(self.B, selected="rel-b"), ("accepted rel-a", "migrated rel-b"))
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_rollback, "rollback target rel-a has no tree on the disk",
                       release=str(self.A.path), kernel=str(self.KA), target=str(out))

    def test_rollback_refuses_a_target_of_another_format(self):
        files = disk_files(self.A, self.B, selected="rel-b")
        files["/releases/rel-a/release"] = record_bytes("rel-a", fs_format=1)
        out = self.target(files, ("accepted rel-a", "selected rel-b"))
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_rollback, "rollback target rel-a reads format 1, the disk "
                       "is format 2: a rollback across a migration is a restore", release=str(self.A.path),
                       kernel=str(self.KA), target=str(out))

    def test_rollback_refuses_another_release_directory(self):
        out = self.both()
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_rollback, "give --release <the directory of rel-a>",
                       release=str(self.B.path), kernel=str(self.KB), target=str(out))

    def test_rollback_refuses_without_a_release_directory(self):
        out = self.both()
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_rollback, "give --release <the directory of rel-a>",
                       kernel=str(self.KA), target=str(out))

    def test_rollback_refuses_the_previous_release_with_the_new_kernel(self):
        out = self.both()
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_rollback, f"release rel-a was built from {COMMIT_A[:12]}",
                       release=str(self.A.path), kernel=str(self.KB), target=str(out))

    # the selection cache: install and stage write it, rollback uses it

    def assert_cache(self, out, release, kernel):
        directory = out / "releases" / release.id
        fields = rel.read_toml_flat(directory / rel.SELECT_RECORD)["select_cache"]
        self.assertEqual(fields["release"], release.id)
        self.assertEqual(fields["step"], 4)
        self.assertEqual(fields["iso_sha256"], sha(directory / rel.SELECT_ISO))
        self.assertEqual(fields["boot_script_sha256"], sha(directory / rel.SELECT_BOOT))
        self.assertEqual(sha(directory / rel.SELECT_BOOT), sha(kernel / "scripts" / "durable-boot.sh"))
        self.assertEqual(fields["kernel_commit"], release.kernel_commit())
        desc = json.loads((directory / rel.SELECT_ISO).read_bytes()[len(ISO_MAGIC):])
        self.assertEqual(desc["step"], 4)
        self.assertEqual(desc["worker"], sha(release.path / "fixture-import.elf"))
        self.assertEqual(parse_stream(bytes.fromhex(desc["input"])), [(rr.SELECTED, rr.selected_bytes(release.id))])
        return fields

    def receipt_of(self, out, action):
        found = sorted((out / "receipts").glob(f"{action}-*.toml"))
        self.assertEqual(len(found), 1, found)
        return rel.read_toml_flat(found[0])

    def test_install_writes_the_selection_cache(self):
        self.guest()
        out = self.work / "out"
        rel.cmd_install(Args(release=str(self.A.path), kernel=str(self.KA), target=str(out), target_identity="lab-1"),
                        log=lambda line: None)
        fields = self.assert_cache(out, self.A, self.KA)
        self.assertEqual(self.receipt_of(out, "install-rel-a")["select_cache"]["iso_sha256"], fields["iso_sha256"])
        self.assertEqual(rel.Target(out).selected(), "rel-a")
        self.assertFalse(list(out.glob("release-cache-*")))

    def test_stage_writes_the_selection_cache(self):
        self.guest()
        out = self.a_selected()
        rel.cmd_stage(Args(release=str(self.B.path), kernel=str(self.KB), target=str(out)), log=lambda line: None)
        fields = self.assert_cache(out, self.B, self.KB)
        self.assertEqual(self.receipt_of(out, "stage-rel-b")["select_cache"]["iso_sha256"], fields["iso_sha256"])
        self.assertEqual(rel.Target(out).trees(), ["rel-a", "rel-b"])
        self.assertFalse(list(out.glob("release-cache-*")))

    def test_stage_refuses_a_kernel_without_its_boot_script_before_writing(self):
        self.guest()
        out = self.a_selected()
        (self.KB / "scripts" / "durable-boot.sh").unlink()
        before = snapshot(out)
        self.refused(rel.cmd_stage, "no scripts/durable-boot.sh", release=str(self.B.path), kernel=str(self.KB),
                     target=str(out))
        self.assert_stage_refusal_only(out, before)
        self.assertEqual(self.boots, [])

    def test_rollback_uses_the_cached_selection_without_a_kernel(self):
        self.guest()
        out = self.work / "out"
        quiet = lambda line: None  # noqa: E731
        rel.cmd_install(Args(release=str(self.A.path), kernel=str(self.KA), target=str(out), target_identity="lab-1"),
                        log=quiet)
        rel.Target(out).ledger_append("accepted", "rel-a")
        rel.cmd_stage(Args(release=str(self.B.path), kernel=str(self.KB), target=str(out)), log=quiet)
        rel.cmd_select(Args(release=str(self.B.path), kernel=str(self.KB), target=str(out)), log=quiet)
        self.assertEqual(rel.Target(out).selected(), "rel-b")
        # No build host from here on: no kernel copies, no release
        # directories, and any ISO build is a tripwire.
        self.guest(build=False)
        for gone in (self.KA, self.KB, self.A.path, self.B.path):
            shutil.rmtree(gone)
        self.boots.clear()
        lines = []
        rel.cmd_rollback(Args(target=str(out)), log=lines.append)
        target = rel.Target(out)
        self.assertEqual(target.selected(), "rel-a")
        self.assertEqual([(b["script"], b["iso"], b["step"]) for b in self.boots],
                         [(out / "releases" / "rel-a" / rel.SELECT_BOOT, out / "releases" / "rel-a" / rel.SELECT_ISO, 4)])
        self.assertEqual(sha(out / rel.ISO), sha(out / "releases" / "rel-a" / rel.ISO))
        self.assertIn("RELEASE ROLLED_BACK id=rel-a from=rel-b", lines[-1])
        receipt = self.receipt_of(out, "rolled_back-rel-a")["rolled_back"]
        self.assertEqual(receipt["source"], "cache")
        self.assertEqual(receipt["select_iso_sha256"], sha(out / "releases" / "rel-a" / rel.SELECT_ISO))
        self.assertTrue(target.ledger_lines()[-1].split()[1:4] == ["rolled_back", "rel-a", "from=rel-b"])
        self.assertFalse([p for p in out.iterdir() if p.name.startswith("release-")])

    def test_rollback_with_a_kernel_builds_even_with_a_cache(self):
        self.guest()
        out = self.both()
        self.with_cache(out, self.A, self.KA)
        rel.cmd_rollback(Args(release=str(self.A.path), kernel=str(self.KA), target=str(out)), log=lambda line: None)
        self.assertEqual(rel.Target(out).selected(), "rel-a")
        self.assertEqual([(b["script"], b["step"]) for b in self.boots], [(self.KA / "scripts" / "durable-boot.sh", 4)])
        self.assertEqual(self.receipt_of(out, "rolled_back-rel-a")["rolled_back"]["source"], "kernel")

    def cache_refused(self, out, text, **kw):
        """A rollback refusal with OUT byte-identical (image, ledger, cache,
        boot images) and no boot."""
        before = snapshot(out)
        message = self.refused(rel.cmd_rollback, text, target=str(out), **kw)
        self.assertEqual(snapshot(out), before)
        self.assertEqual(self.boots, [])
        return message

    def test_rollback_refuses_without_a_cache_rather_than_build(self):
        self.guest()
        out = self.both()
        message = self.cache_refused(out, "select_cache_missing: ")
        self.assertIn("give --release <the directory of rel-a> and --kernel", message)

    def test_rollback_refuses_a_cache_without_its_image(self):
        self.guest()
        out = self.both()
        (self.with_cache(out, self.A, self.KA) / rel.SELECT_ISO).unlink()
        self.cache_refused(out, "select_cache_missing: ")

    def test_rollback_refuses_a_cache_without_its_boot_script(self):
        self.guest()
        out = self.both()
        (self.with_cache(out, self.A, self.KA) / rel.SELECT_BOOT).unlink()
        self.cache_refused(out, "select_cache_missing: ")

    def test_rollback_refuses_a_cached_image_whose_digest_differs(self):
        self.guest()
        out = self.both()
        iso = self.with_cache(out, self.A, self.KA) / rel.SELECT_ISO
        iso.write_bytes(iso.read_bytes().replace(b'"step": 4', b'"step": 2'))
        self.cache_refused(out, "select_cache_mismatch: ")

    def test_rollback_refuses_a_cached_boot_script_whose_digest_differs(self):
        self.guest()
        out = self.both()
        script = self.with_cache(out, self.A, self.KA) / rel.SELECT_BOOT
        script.write_text(script.read_text() + "exit 0\n")
        self.cache_refused(out, "select_cache_mismatch: ")

    def test_rollback_refuses_a_cache_recorded_for_another_release(self):
        self.guest()
        out = self.both()
        cache_a = self.with_cache(out, self.A, self.KA)
        cache_b = self.with_cache(out, self.B, self.KB)
        for name in (rel.SELECT_ISO, rel.SELECT_BOOT, rel.SELECT_RECORD):
            shutil.copyfile(cache_b / name, cache_a / name)
        self.cache_refused(out, "select_cache_mismatch: ")

    def test_rollback_refuses_a_malformed_cache_record(self):
        self.guest()
        out = self.both()
        (self.with_cache(out, self.A, self.KA) / rel.SELECT_RECORD).write_text("[select_cache\n")
        self.cache_refused(out, "select_cache_mismatch: ")

    def test_rollback_from_the_cache_refuses_without_the_boot_image(self):
        self.guest()
        out = self.both()
        self.with_cache(out, self.A, self.KA)
        (out / "releases" / "rel-a" / rel.ISO).unlink()
        self.cache_refused(out, "select_cache_missing: ")

    def test_rollback_from_the_cache_refuses_another_release_directory(self):
        self.guest()
        out = self.both()
        self.with_cache(out, self.A, self.KA)
        self.cache_refused(out, "give --release <the directory of rel-a> or no --release", release=str(self.B.path))

    def test_rollback_refuses_an_image_in_use_from_the_cache(self):
        self.guest()
        out = self.both()
        self.with_cache(out, self.A, self.KA)
        pid = self.hold_open(out / rel.IMAGE)
        message = self.cache_refused(out, "image_in_use: ")
        self.assertIn(f"pid {pid} ", message)
        self.assertIn("before a rollback", message)

    def test_rollback_refuses_an_image_in_use_with_a_kernel(self):
        self.guest()
        out = self.both()
        self.hold_open(out / rel.IMAGE)
        self.cache_refused(out, "before a rollback", release=str(self.A.path), kernel=str(self.KA))

    def test_rollback_from_the_cache_refuses_laptop_attach(self):
        self.guest()
        out = self.both()
        self.with_cache(out, self.A, self.KA)
        saved = rel.os.environ.get("ABSD_BLOCK_ATTACH")
        rel.os.environ["ABSD_BLOCK_ATTACH"] = "laptop"
        try:
            self.cache_refused(out, "select_cache_laptop_unsupported: ")
        finally:
            if saved is None:
                del rel.os.environ["ABSD_BLOCK_ATTACH"]
            else:
                rel.os.environ["ABSD_BLOCK_ATTACH"] = saved

    def test_rollback_names_a_failing_boot_script(self):
        self.guest()
        out = self.both()
        self.with_cache(out, self.A, self.KA)
        self.boot_fault = "script"
        message = self.refused(rel.cmd_rollback, "importer boot 1 (step 4): durable-boot.sh exited 1",
                               target=str(out))
        self.assertIn("test -f failed", message)
        self.assertEqual(rel.Target(out).selected(), "rel-b")

    def test_migrate_writes_the_selection_cache(self):
        self.guest()
        out = self.target(disk_files(self.A, selected="rel-a"), ("installed rel-a", "accepted rel-a"), fs_format=1)
        lines = []
        rel.cmd_migrate(Args(release=str(self.B.path), kernel=str(self.KB), target=str(out)), log=lines.append)
        self.assertIn("MIGRATED to format 2 release=rel-b", lines[-1])
        fields = self.assert_cache(out, self.B, self.KB)
        self.assertEqual(self.receipt_of(out, "migrate-rel-b")["select_cache"]["iso_sha256"], fields["iso_sha256"])
        self.assertEqual(rel.Target(out).selected(), "rel-b")

    # remove

    def test_remove_refuses_the_selected_release(self):
        out = self.both()
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_remove, "rel-b is selected or the last accepted release",
                       release=str(self.A.path), kernel=str(self.KA), target=str(out), id="rel-b")

    def test_remove_refuses_the_last_accepted_release(self):
        out = self.both()
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_remove, "rel-a is selected or the last accepted release",
                       release=str(self.A.path), kernel=str(self.KA), target=str(out), id="rel-a")

    def test_remove_refuses_a_release_without_a_tree(self):
        out = self.both()
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_remove, "rel-c has no tree on the disk",
                       release=str(self.A.path), kernel=str(self.KA), target=str(out), id="rel-c")

    def retired(self):
        """A and B on the disk, B selected and accepted, so A is retired."""
        out = self.both(ledger=("installed rel-a", "selected rel-a", "accepted rel-a", "staged rel-b",
                                "selected rel-b from=rel-a", "accepted rel-b"))
        self.with_cache(out, self.A, self.KA)
        return out

    def remove_refused(self, out, text, **kw):
        before = snapshot(out)
        kw = dict(dict(release=str(self.B.path), kernel=str(self.KB), target=str(out), id="rel-a"), **kw)
        message = self.refused(rel.cmd_remove, text, **kw)
        self.assertEqual(snapshot(out), before)
        return message

    def test_remove_removes_a_retired_release_with_importer_step_5(self):
        self.guest()
        out = self.retired()
        disk = fake_tree(out / rel.IMAGE)
        lines = []
        rel.cmd_remove(Args(release=str(self.B.path), kernel=str(self.KB), target=str(out), id="rel-a"),
                       log=lines.append)
        self.assertEqual([(b["step"], b["entries"]) for b in self.boots], [(5, [("/releases/rel-a/", b"")])])
        after = fake_tree(out / rel.IMAGE)
        self.assertEqual(after, {p: d for p, d in disk.items() if not p.startswith("/releases/rel-a/")})
        self.assertFalse((out / "releases" / "rel-a").exists())
        self.assertTrue((out / "releases" / "rel-b" / rel.ISO).is_file())
        target = rel.Target(out)
        self.assertEqual((target.trees(), target.selected()), (["rel-b"], "rel-b"))
        self.assertEqual(target.ledger_lines()[-1].split()[1:4], ["removed", "rel-a", "by=rel-b"])
        receipt = self.receipt_of(out, "remove-rel-a")["remove"]
        self.assertEqual((receipt["release"], receipt["importer_status"], receipt["trees_after"]),
                         ("rel-a", "ok", ["rel-b"]))
        self.assertIn("RELEASE REMOVED id=rel-a", lines[-1])

    def test_stage_of_a_third_release_after_removal(self):
        self.guest()
        out = self.retired()
        C = rel.Release(make_release(self.work / "rel-c", "rel-c", COMMIT_A))
        self.refused(rel.cmd_stage, "the disk holds 2 releases", release=str(C.path), kernel=str(self.KA),
                     target=str(out))
        rel.cmd_remove(Args(release=str(self.B.path), kernel=str(self.KB), target=str(out), id="rel-a"),
                       log=lambda line: None)
        rel.cmd_stage(Args(release=str(C.path), kernel=str(self.KA), target=str(out)), log=lambda line: None)
        rel.cmd_select(Args(release=str(C.path), kernel=str(self.KA), target=str(out)), log=lambda line: None)
        target = rel.Target(out)
        self.assertEqual((target.trees(), target.selected()), (["rel-b", "rel-c"], "rel-c"))
        self.assertEqual(target.record_of("rel-c")["release"], "rel-c")
        self.assert_cache(out, C, self.KA)

    def test_remove_refuses_an_image_in_use(self):
        out = self.retired()
        pid = self.hold_open(out / rel.IMAGE)
        message = self.remove_refused(out, "image_in_use: ")
        self.assertIn(f"pid {pid} ", message)
        self.assertIn("before a removal", message)

    def test_remove_refuses_with_a_release_of_another_format(self):
        out = self.retired()
        C = rel.Release(make_release(self.work / "rel-c", "rel-c", COMMIT_A, fs_format=3))
        self.remove_refused(out, "the disk is format 2; release rel-c's importer writes format 3",
                            release=str(C.path), kernel=str(self.KA))

    def test_remove_refuses_a_malformed_id(self):
        self.remove_refused(self.retired(), "release id '../rel-a' is not", id="../rel-a")

    def test_remove_refuses_the_previous_known_good_while_the_selected_is_a_candidate(self):
        out = self.both(ledger=("installed rel-a", "selected rel-a", "accepted rel-a", "staged rel-b",
                                "selected rel-b from=rel-a"))
        self.remove_refused(out, "rel-a is selected or the last accepted release")

    def test_remove_refuses_after_a_rollback_both_releases(self):
        out = self.both(selected="rel-a", ledger=("accepted rel-a", "staged rel-b", "selected rel-b", "accepted rel-b",
                                                  "rolled_back rel-a from=rel-b"))
        self.remove_refused(out, "rel-a is selected or the last accepted release", release=str(self.A.path),
                            kernel=str(self.KA))
        self.remove_refused(out, "rel-b is selected or the last accepted release", release=str(self.A.path),
                            kernel=str(self.KA), id="rel-b")

    def test_remove_refuses_when_the_importer_fails_before_its_commit(self):
        self.guest()
        out = self.retired()
        self.boot_fault = "before"
        message = self.remove_refused(out, "the disk still holds rel-a whole; nothing was removed")
        self.assertIn("importer boot 1 (step 5): QEMU status 7", message)

    def test_remove_refuses_with_an_importer_without_step_5(self):
        self.guest()
        out = self.retired()
        saved = rel.run_boot

        def old_importer(script, iso, image, serial):
            pathlib.Path(serial).write_bytes(console("FIXTURE IMPORT FAILED unknown step 5"))
            return "7"
        rel.run_boot = old_importer
        try:
            message = self.remove_refused(out, "nothing was removed")
        finally:
            rel.run_boot = saved
        self.assertIn("unknown step 5", message)

    def test_remove_after_its_commit_brings_the_directory_into_line(self):
        self.guest()
        out = self.retired()
        self.boot_fault = "after"
        message = self.refused(rel.cmd_remove, "the importer boot reported a failure, but the disk no longer holds "
                               "rel-a", release=str(self.B.path), kernel=str(self.KB), target=str(out), id="rel-a")
        self.assertIn("stopped after the commit", message)
        self.assertFalse((out / "releases" / "rel-a").exists())
        self.assertEqual(rel.Target(out).trees(), ["rel-b"])
        self.assertEqual(rel.Target(out).ledger_lines()[-1].split()[1:3], ["removed", "rel-a"])
        self.assertEqual(self.receipt_of(out, "remove-rel-a")["remove"]["importer_status"], "failed after the commit")

    def test_remove_refuses_a_change_outside_the_tree(self):
        self.guest()
        out = self.retired()
        self.boot_fault = "outside"
        ledger = (out / rel.LEDGER).read_text()
        cache = snapshot(out / "releases")
        self.refused(rel.cmd_remove, "changed files outside its tree: /etc/network.conf", release=str(self.B.path),
                     kernel=str(self.KB), target=str(out), id="rel-a")
        self.assertEqual(snapshot(out / "releases"), cache)
        self.assertEqual((out / rel.LEDGER).read_text(), ledger)
        self.assertFalse((out / rel.REMOVING).exists())

    def interrupted(self, fault):
        self.guest()
        out = self.retired()
        self.boot_fault = fault
        with self.assertRaises(KeyboardInterrupt):
            rel.cmd_remove(Args(release=str(self.B.path), kernel=str(self.KB), target=str(out), id="rel-a"),
                           log=lambda line: None)
        self.boot_fault = None
        self.assertEqual((out / rel.REMOVING).read_text(), "rel-a\n")
        self.assertTrue((out / "releases" / "rel-a" / rel.ISO).is_file())
        return out

    def test_an_interrupted_removal_refuses_other_operations_until_reconciled(self):
        out = self.interrupted("interrupt-after")
        C = rel.Release(make_release(self.work / "rel-c", "rel-c", COMMIT_A))
        for func, kw in ((rel.cmd_stage, dict(release=str(C.path), kernel=str(self.KA))),
                         (rel.cmd_select, dict(release=str(self.B.path), kernel=str(self.KB))),
                         (rel.cmd_migrate, dict(release=str(self.B.path), kernel=str(self.KB))),
                         (rel.cmd_rollback, {})):
            with self.subTest(func=func.__name__):
                previous = snapshot(out)
                self.refused(func, "removal_unreconciled: ", target=str(out), **kw)
                if func is rel.cmd_stage:
                    self.assert_stage_refusal_only(out, previous)
                else:
                    self.assertEqual(snapshot(out), previous)

    def test_remove_finishes_a_removal_interrupted_after_its_commit(self):
        out = self.interrupted("interrupt-after")
        self.boots.clear()
        lines = []
        rel.cmd_remove(Args(release=str(self.B.path), kernel=str(self.KB), target=str(out), id="rel-a"),
                       log=lines.append)
        self.assertEqual(self.boots, [])
        self.assertIn("RELEASE REMOVE RECONCILED id=rel-a", lines[-1])
        self.assertFalse((out / "releases" / "rel-a").exists())
        self.assertFalse((out / rel.REMOVING).exists())
        self.assertEqual(rel.Target(out).ledger_lines()[-1].split()[1:3], ["removed", "rel-a"])
        self.assertTrue(rel.Target(out).ledger_lines()[-1].endswith(" reconciled"))
        self.assertEqual(self.receipt_of(out, "remove-rel-a")["remove"]["importer_status"],
                         "interrupted after the commit; reconciled")

    def test_remove_redoes_a_removal_interrupted_before_its_commit(self):
        out = self.interrupted("interrupt-before")
        self.assertEqual(rel.Target(out).trees(), ["rel-a", "rel-b"])
        lines = []
        rel.cmd_remove(Args(release=str(self.B.path), kernel=str(self.KB), target=str(out), id="rel-a"),
                       log=lines.append)
        self.assertTrue(any("RELEASE REMOVE RECONCILED id=rel-a: the disk still holds" in line for line in lines))
        self.assertIn("RELEASE REMOVED id=rel-a", lines[-1])
        self.assertEqual(rel.Target(out).trees(), ["rel-b"])
        self.assertFalse((out / rel.REMOVING).exists())

    def test_remove_refuses_a_partial_removal_and_keeps_the_directory(self):
        self.guest()
        out = self.retired()
        self.boot_fault = "partial"
        ledger = (out / rel.LEDGER).read_text()
        cache = snapshot(out / "releases")
        self.refused(rel.cmd_remove, "left 1 of its", release=str(self.B.path), kernel=str(self.KB), target=str(out),
                     id="rel-a")
        self.assertEqual(snapshot(out / "releases"), cache)
        self.assertEqual((out / rel.LEDGER).read_text(), ledger)
        self.assertEqual(rel.Target(out).trees(), ["rel-a", "rel-b"])

    # accept and migrate, the refusals before any boot

    def test_accept_refuses_a_disk_without_a_selection(self):
        out = self.target(disk_files(self.A))
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_accept, "no_selected_release", target=str(out),
                       key=str(self.work / "key"))

    def test_accept_refuses_without_a_boot_image(self):
        out = self.a_selected()
        (out / rel.ISO).unlink()
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_accept, "no boot image", target=str(out),
                       key=str(self.work / "key"))

    def test_migrate_refuses_a_disk_already_in_the_release_format(self):
        out = self.a_selected()
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_migrate, "the disk is already format 2; use stage/select",
                       release=str(self.B.path), kernel=str(self.KB), target=str(out))

    # backup: the halt guard (image_in_use) and the other refusals

    def test_backup_refuses_an_image_in_use(self):
        out = self.a_selected()
        before = sha(out / rel.IMAGE)
        pid = self.hold_open(out / rel.IMAGE)
        dest = self.work / "backup"
        message = self.unchanged(out, before, rel.cmd_backup, "image_in_use:", target=str(out), backup=str(dest))
        self.assertIn(f"pid {pid} (", message)
        self.assertIn("halt the machine (shutdown) before a backup", message)
        self.assertFalse(dest.exists())
        self.release_holder()
        self.backup_of(out)
        self.assertTrue((dest / "backup.toml").is_file())
        self.assertEqual(sha(dest / rel.IMAGE), before)

    def test_backup_refuses_an_image_held_through_another_path(self):
        out = self.a_selected()
        link = self.work / "alias.img"
        link.symlink_to(out / rel.IMAGE)
        self.hold_open(link)
        self.refused(rel.cmd_backup, "image_in_use:", target=str(out), backup=str(self.work / "backup"))

    def test_backup_refuses_an_image_taken_into_use_during_the_copy(self):
        out = self.a_selected()
        calls = []

        def holders(image):
            calls.append(image)
            return [] if len(calls) == 1 else [(4242, "qemu-system-x86")]
        self.saved.append((rel, "image_holders", rel.image_holders))
        rel.image_holders = holders
        dest = self.work / "backup"
        message = self.refused(rel.cmd_backup, "image_in_use:", target=str(out), backup=str(dest))
        self.assertIn("pid 4242 (qemu-system-x86)", message)
        self.assertEqual(len(calls), 2)
        self.assertFalse(dest.exists())

    def test_backup_leaves_no_copy_when_the_copy_differs(self):
        out = self.a_selected()
        real = rel.sha256_file
        self.saved.append((rel, "sha256_file", real))
        rel.sha256_file = lambda path: "0" * 64 if pathlib.Path(path).parent.name == "backup" else real(path)
        dest = self.work / "backup"
        dest.mkdir()
        self.refused(rel.cmd_backup, "the copy differs from the disk", target=str(out), backup=str(dest))
        self.assertEqual(list(dest.iterdir()), [])

    def test_backup_command_line_names_image_in_use(self):
        out = self.a_selected()
        self.hold_open(out / rel.IMAGE)
        run = subprocess.run([sys.executable, "-I", str(here / "release.py"), "backup", "--target", str(out),
                              str(self.work / "backup")], capture_output=True, text=True)
        self.assertEqual(run.returncode, 1)
        self.assertTrue(run.stderr.startswith("release: refused: image_in_use: "), run.stderr)

    def test_backup_refuses_a_nonempty_destination(self):
        out = self.a_selected()
        dest = self.work / "backup"
        dest.mkdir()
        (dest / "something").write_text("x")
        self.unchanged(out, sha(out / rel.IMAGE), rel.cmd_backup, "is not empty", target=str(out), backup=str(dest))

    def test_backup_refuses_a_missing_image(self):
        out = self.a_selected()
        (out / rel.IMAGE).unlink()
        self.refused(rel.cmd_backup, "no disk image", target=str(out), backup=str(self.work / "backup"))

    # restore and verify-backup with a bad backup (validate_backup, cmd_restore)

    def restore_refused(self, backup, text, verify=True, identity=None, **kw):
        """Restore into a second operator directory refuses and the whole
        directory is byte-identical afterwards; with `verify`, verify-backup
        refuses the same way. With `identity`, the directory has a TARGET."""
        dest = self.work / "restored"
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir()
        write_disk(dest / rel.IMAGE, {"/home/operator/keep": b"keep\n"})
        (dest / rel.LEDGER).write_text("2026-10-12T00:00:00Z installed other\n")
        if identity:
            (dest / rel.TARGET).write_text(identity + "\n")
        before = snapshot(dest)
        self.refused(rel.cmd_restore, text, target=str(dest), backup=str(backup), replace=True, **kw)
        self.assertEqual(snapshot(dest), before)
        if verify:
            self.refused(rel.cmd_verify_backup, text, backup=str(backup))

    def test_restore_refuses_a_backup_without_its_record(self):
        backup = self.backup_of(self.a_selected())
        (backup / "backup.toml").unlink()
        self.restore_refused(backup, "no backup.toml")

    def test_restore_refuses_a_backup_without_its_image(self):
        backup = self.backup_of(self.a_selected())
        (backup / rel.IMAGE).unlink()
        self.restore_refused(backup, "no image")

    def test_restore_refuses_a_truncated_image(self):
        backup = self.backup_of(self.a_selected())
        with open(backup / rel.IMAGE, "r+b") as handle:
            handle.truncate(rel.oi.IMAGE_BYTES // 2)
        self.restore_refused(backup, f"bytes, not an operator image ({rel.oi.IMAGE_BYTES})")

    def test_restore_refuses_an_image_whose_digest_differs(self):
        backup = self.backup_of(self.a_selected())
        with open(backup / rel.IMAGE, "r+b") as handle:
            handle.seek(rel.oi.IMAGE_BYTES - 1)
            handle.write(b"\x01")
        self.restore_refused(backup, "the backup image's digest is not the one backup.toml records")

    def test_restore_refuses_a_format_backup_toml_does_not_record(self):
        backup = self.backup_of(self.a_selected())
        self.edit_toml(backup / "backup.toml", "fs_format = 2", "fs_format = 1")
        self.restore_refused(backup, "the backup image is format 2, backup.toml says 1")

    def test_restore_refuses_a_backup_from_a_later_format(self):
        out = self.target(disk_files(self.A, selected="rel-a"), fs_format=3)
        backup = self.backup_of(out)
        self.restore_refused(backup, "the backup image is filesystem format 3; this release reads 2")

    def test_restore_refuses_an_image_the_host_reader_refuses(self):
        backup = self.backup_of(self.a_selected())
        state = read_disk(backup / rel.IMAGE)
        write_disk(backup / rel.IMAGE, {p: d.encode("latin-1") for p, d in state["files"].items()},
                   refuse="object record checksum")
        self.edit_toml(backup / "backup.toml", read_toml_digest(backup), sha(backup / rel.IMAGE))
        self.restore_refused(backup, "the host reader refuses the backup image: object record checksum")

    def test_restore_refuses_another_filesystem_identity(self):
        backup = self.backup_of(self.a_selected())
        self.edit_toml(backup / "backup.toml", "commit_sequence = 11", "commit_sequence = 12")
        self.restore_refused(backup, "filesystem identity or sequence is not the one backup.toml records")

    def test_restore_refuses_a_selection_backup_toml_does_not_record(self):
        backup = self.backup_of(self.a_selected())
        self.edit_toml(backup / "backup.toml", 'selected = "rel-a"', 'selected = "rel-b"')
        self.restore_refused(backup, "the backup selects rel-a, backup.toml says rel-b")

    def test_restore_refuses_a_backup_whose_selected_record_is_altered(self):
        files = disk_files(self.A, selected="rel-a")
        files["/releases/rel-a/release"] = files["/releases/rel-a/release"].replace(b"kernel_abi=1", b"kernel_abi=2")
        backup = self.backup_of(self.target(files))
        self.restore_refused(backup, "check_mismatch")

    def test_restore_refuses_without_a_boot_image(self):
        backup = self.backup_of(self.a_selected())
        shutil.rmtree(backup / "releases")
        self.restore_refused(backup, "no boot image for the selected release rel-a", verify=False)

    def test_restore_refuses_over_an_existing_image_without_replace(self):
        backup = self.backup_of(self.a_selected())
        dest = self.work / "restored"
        write_disk(dest / rel.IMAGE, {"/home/operator/keep": b"keep\n"})
        before = sha(dest / rel.IMAGE)
        self.refused(rel.cmd_restore, "exists; --replace to restore over it", target=str(dest), backup=str(backup))
        self.assertEqual(sha(dest / rel.IMAGE), before)

    def test_restore_clone_refuses_before_copying_without_its_inputs(self):
        backup = self.backup_of(self.a_selected())
        given = {"release": str(self.A.path), "kernel": str(self.KA), "key": str(self.work / "key")}
        for missing in given:
            with self.subTest(missing=missing):
                kw = {k: v for k, v in given.items() if k != missing}
                self.restore_refused(backup, "--clone needs --release <directory of the selected release>, --kernel "
                                     "and --key", verify=False, clone=True, **kw)

    def test_restore_clone_refuses_another_release_directory_before_copying(self):
        backup = self.backup_of(self.a_selected())
        self.restore_refused(backup, "--release is rel-b, the restored image selects rel-a", verify=False, clone=True,
                             release=str(self.B.path), kernel=str(self.KB), key=str(self.work / "key"))

    def test_restore_clone_refuses_a_kernel_at_another_commit_before_copying(self):
        backup = self.backup_of(self.a_selected())
        self.restore_refused(backup, f"kernel checkout is at {COMMIT_B[:12]}, release rel-a was built from "
                             f"{COMMIT_A[:12]}", verify=False, clone=True, release=str(self.A.path),
                             kernel=str(self.KB), key=str(self.work / "key"))

    def test_restore_clone_refuses_the_backups_own_identity_before_copying(self):
        backup = self.backup_of(self.a_selected())
        clone = {"clone": True, "release": str(self.A.path), "kernel": str(self.KA), "key": str(self.work / "key")}
        for name, identity, given, text in (
                ("none given", None, None, "clone_identity_unchanged: the backup is of target 'lab-1'"),
                ("the backup's own", None, "lab-1", "clone_identity_unchanged: the backup is of target 'lab-1'"),
                ("OUT is the source's", "lab-1", None, "clone_identity_unchanged: the backup is of target 'lab-1'"),
                ("OUT is another's", "lab-2", "lab-3", "target identity is 'lab-2', not 'lab-3'")):
            with self.subTest(case=name):
                self.restore_refused(backup, text, verify=False, identity=identity, target_identity=given, **clone)
        self.assertEqual(self.boots, [])

    def test_restore_clone_refuses_a_backup_without_the_source_key_before_copying(self):
        backup = self.backup_of(self.a_selected())
        meta = backup / "backup.toml"
        clone = {"clone": True, "release": str(self.A.path), "kernel": str(self.KA), "key": str(self.work / "key"),
                 "target_identity": "lab-2"}
        text = meta.read_text()
        for name, edited in (("no [identity]", re.sub(r"\n\[identity\]\n[^\[]*", "\n", text)),
                             ("no fingerprint", re.sub(r"host_key_fingerprint = .*\n", "", text))):
            with self.subTest(case=name):
                self.assertNotEqual(edited, text)
                meta.write_text(edited)
                self.restore_refused(backup, "backup_identity_missing: backup.toml has no [identity] "
                                     "host_key_fingerprint", verify=False, **clone)
        self.assertEqual(self.boots, [])

    def clone_boots(self, seed=bytes(range(1, 33)), served=None, serial="FSD HOST KEY GENERATED\n"):
        """The regenerate boot of clone_identity, simulated as a served boot
        is: the file server writes `seed` to the fake disk and prints
        `serial`; sshd serves the key of `served` (default `seed`) and
        reports it LOADED, never GENERATED; an orderly halt (status 3)."""
        test = self
        served = seed if served is None else served
        self.clone_calls = []

        class CloneBoot:
            def __init__(self, target, iso, name, port):
                self.target = target
                test.boots.append({"iso": pathlib.Path(iso), "name": name,
                                   "step": json.loads(pathlib.Path(iso).read_bytes()[len(ISO_MAGIC):])["step"]})

            def wait_ready(self, release_id):
                state = read_disk(self.target.image)
                state["files"]["/ssh/host_ed25519_seed"] = seed.decode("latin-1")
                write_disk(self.target.image, {p: d.encode("latin-1") for p, d in state["files"].items()},
                           seq=state["seq"] + 1)
                return {"host_key": rel.host_public_key(served), "fingerprint": rel.host_key_fingerprint(served),
                        "generated": False}

            def serial(self):
                return serial

            def ssh(self, key, command):
                test.clone_calls.append(command)
                return 0, b"", b""

            def wait_end(self):
                return 3

            def stop(self):
                test.clone_calls.append("stop")

        rel.Boot = CloneBoot
        rel.oi.kernel_iso = fake_kernel_iso
        return seed

    def test_restore_clone_makes_a_second_machine_with_its_selection_cache(self):
        source = self.both(selected="rel-a", ledger=("installed rel-a", "selected rel-a", "accepted rel-a",
                                                     "staged rel-b"))
        backup = self.backup_of(source)
        before = snapshot(source)
        seed = self.clone_boots()
        dest = self.work / "clone"
        lines = []
        rel.cmd_restore(Args(target=str(dest), backup=str(backup), clone=True, release=str(self.A.path),
                             kernel=str(self.KA), key=str(self.work / "key"), target_identity="lab-2"),
                        log=lines.append)
        target = rel.Target(dest)
        self.assertEqual(target.identity(), "lab-2")
        self.assertEqual(target.tree()["/ssh/host_ed25519_seed"], seed)
        self.assertEqual(rel.select_cache(target, "rel-a")["release"], "rel-a")
        fields = self.assert_cache(dest, self.A, self.KA)
        self.assertEqual([b["step"] for b in self.boots], [0])
        receipt = self.receipt_of(dest, "clone-rel-a")
        self.assertEqual(receipt["clone"]["target"], "lab-2")
        self.assertEqual(receipt["clone"]["source_target"], "lab-1")
        self.assertEqual(receipt["clone"]["host_key_fingerprint"], rel.host_key_fingerprint(seed))
        self.assertEqual(receipt["clone"]["source_host_key_fingerprint"], rel.host_key_fingerprint(bytes(range(32))))
        self.assertEqual(receipt["select_cache"]["iso_sha256"], fields["iso_sha256"])
        self.assertEqual(receipt["select_cache_absent"]["releases"], ["rel-b"])
        self.assertFalse((dest / "releases" / "rel-b" / rel.SELECT_RECORD).exists())
        self.assertEqual(lines[-1], f"CLONE OK release=rel-a host_key={rel.host_key_fingerprint(seed)} target=lab-2 "
                                    f"select_cache=present select_cache_absent=rel-b")
        self.assertEqual(target.ledger_lines()[-1].split()[1:3], ["cloned", "rel-a"])
        self.assertFalse(list(dest.glob("release-cache-*")))
        self.assertEqual(snapshot(source), before)

    def test_restore_clone_keeps_no_cache_when_the_key_does_not_change(self):
        backup = self.backup_of(self.a_selected())
        source = rel.host_key_fingerprint(bytes(range(32)))
        # Refused before the shutdown, the boot is stopped and never asked
        # to halt; the seed check follows an orderly halt.
        for name, boot, text, calls in (
                ("no FSD line", {"serial": "FSD READY\n"},
                 "clone_key_not_generated: the regenerate boot's serial has no FSD HOST KEY GENERATED", ["stop"]),
                ("the backup's key served", {"served": bytes(range(32))},
                 f"clone_key_unchanged: the regenerate boot serves the backup's host key {source}", ["stop"]),
                ("the seed unchanged on the disk", {"seed": bytes(range(32)), "served": bytes(range(1, 33))},
                 "clone_seed_unchanged: the host key seed did not change on the disk", ["shutdown", "stop"])):
            with self.subTest(case=name):
                self.clone_boots(**boot)
                dest = self.work / "clone"
                shutil.rmtree(dest, ignore_errors=True)
                message = self.refused(rel.cmd_restore, text, target=str(dest), backup=str(backup), clone=True,
                                       release=str(self.A.path), kernel=str(self.KA), key=str(self.work / "key"),
                                       target_identity="lab-2")
                self.assertTrue(message.startswith(text.split(":")[0]))
                self.assertEqual(self.clone_calls, calls)
                self.assertFalse((dest / "releases" / "rel-a" / rel.SELECT_RECORD).exists())
                self.assertFalse(list(dest.glob("release-cache-*")))
                self.assertFalse(list(dest.glob("receipts/clone-*")))

    def test_restore_removes_its_temporary_copy_when_the_digest_differs(self):
        backup = self.backup_of(self.a_selected())
        real = rel.sha256_file
        self.saved.append((rel, "sha256_file", real))
        rel.sha256_file = lambda path: "0" * 64 if str(path).endswith(".restoring") else real(path)
        self.restore_refused(backup, "the restored copy differs from the backup", verify=False)

    def test_restore_of_a_good_backup_is_copied(self):
        out = self.a_selected()
        backup = self.backup_of(out)
        lines = []
        rel.cmd_verify_backup(Args(backup=str(backup)), log=lines.append)
        self.assertEqual(lines, ["BACKUP VALID selected=rel-a format=2 files=%d" % len(read_disk(out / rel.IMAGE)
                                                                                        ["files"])])
        dest = self.work / "restored"
        rel.cmd_restore(Args(target=str(dest), backup=str(backup)), log=lines.append)
        self.assertEqual(sha(dest / rel.IMAGE), sha(out / rel.IMAGE))
        self.assertTrue(lines[-1].startswith("RESTORE COPIED release=rel-a format=2 seq=11"))

    # the command line

    def test_main_refuses_a_command_without_its_kernel(self):
        run = subprocess.run([sys.executable, "-I", str(here / "release.py"), "select", "--release", "x", "--target",
                              str(self.work / "out")], capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        self.assertIn("select needs --kernel", run.stderr)

    def test_runbook_commands_parse(self):
        lines = runbook_commands()
        self.assertGreaterEqual(len(lines), 10, lines)
        seen = set()
        for line in lines:
            argv = shlex.split(line)[3:]
            with self.subTest(line=line):
                called = []
                stubs = {name: getattr(rel, name) for name in dir(rel) if name.startswith("cmd_")}
                try:
                    for name in stubs:
                        setattr(rel, name, lambda args, name=name: called.append((name, args)))
                    saved_argv = sys.argv
                    sys.argv = ["release.py", *argv]
                    with contextlib.redirect_stderr(io.StringIO()) as err:
                        try:
                            rel.main()
                        except SystemExit as exit:
                            self.fail(f"exit {exit.code}: {err.getvalue().strip()}")
                finally:
                    sys.argv = saved_argv
                    for name, func in stubs.items():
                        setattr(rel, name, func)
                self.assertEqual([name for name, _ in called], ["cmd_" + argv[0].replace("-", "_")])
                seen.add(argv[0])
        self.assertTrue({"install", "stage", "select", "accept", "rollback", "backup", "verify-backup", "restore",
                         "migrate", "status", "remove"} <= seen, seen)


def snapshot(directory):
    """Every file under `directory` and its digest."""
    return {str(p.relative_to(directory)): sha(p) for p in sorted(pathlib.Path(directory).rglob("*")) if p.is_file()}


def read_toml_digest(backup):
    return rel.read_toml_flat(backup / "backup.toml")["disk"]["image_sha256"]


def runbook_commands():
    """Every `python3 -I scripts/release.py ...` command in the runbook,
    in code blocks and inline code."""
    text = RUNBOOK.read_text()
    found = re.findall(r"^python3 -I scripts/release\.py [^\n`]+$", text, re.M)
    found += re.findall(r"`(python3 -I scripts/release\.py [^`]+)`", text)
    return found


def main():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReleaseToolRefusals)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if not result.wasSuccessful():
        sys.exit(1)
    print(f"RELEASE TOOL HOST TEST OK cases={result.testsRun}")


if __name__ == "__main__":
    main()
