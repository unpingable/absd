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

import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import absd_fs  # noqa: E402
import release_record as rr  # noqa: E402
import storage_fence_state as guard


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


def fake_slot_state(image):
    """The resume slot of this suite's JSON fake disk (storage_fence_resume.slot_state)."""
    files = read_disk(image)["files"]
    if guard.RESUME_PATH not in files:
        return "missing", None
    parsed = guard.parse_resume(files[guard.RESUME_PATH].encode("latin-1"))
    if parsed is None:
        return "corrupt", None
    if parsed == "none":
        return "none", None
    return "record", parsed


@contextlib.contextmanager
def fake_guard_mutation(image, *, fresh=False):
    """Guard state in this suite's JSON fake disk, not real-sector evidence.

    Real host syscall/sector controls live in test_storage_fence_host.py.
    """
    if fresh:
        yield
        return
    state = read_disk(image)
    previous = state['files'].get(guard.PATH, '').encode('latin-1')
    if guard.parse(previous) not in ('fresh', 'clean'):
        raise ValueError('writable guard: unclean image; offline reconstruction required')
    def marker(value):
        current = read_disk(image)
        current['files'][guard.PATH] = value.decode('latin-1')
        write_disk(image, {p:d.encode('latin-1') for p,d in current['files'].items()},
                   fs_format=current['format'], fs_id=current['fs_id'], seq=current['seq'],
                   layout=current['layout'], refuse=current['refuse'])
    marker(guard.encode('dirty'))
    yield
    marker(previous)


# -- a real filesystem image ----------------------------------------------------

fs_vectors = load("test_absd_fs.py")


def real_image(path, files, state="clean"):
    """A real format-2 ABSD filesystem region holding `files` (a path
    ending in / is a directory) and the guard in `state`: the
    format2.sectors fixture's selected image with its records replaced,
    each file's bytes in its own blocks, re-signed (test_absd_fs.resign)."""
    data = fs_vectors.load("format2.sectors")
    geo = absd_fs.geometry(len(data) // absd_fs.SECTOR)
    files = {**files, guard.PATH: guard.encode(state)}
    dirs = {p.rstrip("/") for p in files if p.endswith("/")}
    for p in files:
        dirs.update(str(d) for d in pathlib.PurePosixPath(p.rstrip("/")).parents if str(d) != "/")
    names = sorted(dirs | {p for p in files if not p.endswith("/")}, key=lambda p: (p.count("/"), p))
    raw = fs_vectors.selected_raw(data)[:absd_fs.HEADER_BYTES]
    raw += struct.pack("<QQQBBHIQ", 1, 0, 0, 2, 0, 0, 0, 1790000000)
    serial_of, block = {"/": 1}, 0
    for serial, name in enumerate(names, 2):
        serial_of[name] = serial
        parent = serial_of[str(pathlib.PurePosixPath(name).parent)]
        base = pathlib.PurePosixPath(name).name.encode()
        if name in dirs:
            raw += struct.pack("<QQQBBHIQ", serial, parent, 0, 2, 0, len(base), 0, 1790000000) + base
            continue
        content = files[name]
        count = -(-len(content) // absd_fs.BLOCK)
        refs = list(range(block, block + count))
        for i, ref in enumerate(refs):
            at = (geo["data_first"] + ref * absd_fs.SECTORS_PER_BLOCK) * absd_fs.SECTOR
            data[at:at + absd_fs.BLOCK] = content[i * absd_fs.BLOCK:(i + 1) * absd_fs.BLOCK].ljust(absd_fs.BLOCK, b"\0")
        block += count
        raw += (struct.pack("<QQQBBHIQ", serial, parent, len(content), 1, 0, len(base), count, 1790000000) + base
                + b"".join(struct.pack("<I", ref) for ref in refs))
    struct.pack_into("<Q", raw, 32, len(names) + 2)
    struct.pack_into("<I", raw, 44, len(names) + 1)
    fs_vectors.resign(data, raw)
    pathlib.Path(path).write_bytes(data)
    return path


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


def fake_kernel_iso(kernel, step, worker, options="", server="", input_bytes=b"", work=None,
                    operator_smp=False, logger="", log=print):
    """What the kernel's durable-iso target would make, as a description:
    the step, the worker's digest, and the importer's input stream."""
    assert operator_smp is False, "release fixture models only the default UP profile"
    path = pathlib.Path(kernel) / "build" / "durable" / f"absd-durable-{step}.iso"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(ISO_MAGIC + json.dumps({"step": step, "worker": sha(worker),
                                          "server": sha(server) if server else None,
                                          "logger": sha(logger) if logger else None,
                                          "input": input_bytes.hex()}).encode())
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


def fake_namespace(image):
    state = read_disk(image)
    paths = {}
    for path in state["files"]:
        name = path.rstrip("/")
        paths[name] = {"kind": 2 if path.endswith("/") else 1}
        for parent in pathlib.PurePosixPath(name).parents:
            if str(parent) != "/":
                paths.setdefault(str(parent), {"kind": 2})
    return {path: dict(attr, fs_id=state["fs_id"], serial=i + 2)
            for i, (path, attr) in enumerate(sorted(paths.items()))}


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
    for name in (rel.ISO, "fixture-import.elf", "absd-fsd.elf", "absd-fsd-regenerate.elf", "sshd.elf", "absd-logd.elf"):
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
    files = dict(guard.fresh_files())
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
        for owner, name, value in ((rel.oi, "tree", fake_tree), (rel.oi, "namespace", fake_namespace),
                                   (rel.storage_fence_host, "mutation", fake_guard_mutation),
                                   (rel.storage_fence_resume, "slot_state", fake_slot_state),
                                   (rel.em, "check_import_capacity", lambda image, plan: {}),
                                   # operator_image loads its own exec-matrix: its successor
                                   # headroom check runs on the fake disk with no figures to refuse.
                                   (rel.oi.em, "check_import_capacity",
                                    lambda image, plan: {"peak_extra_blocks": 0, "free_blocks": 0, "data_blocks": 0}),
                                   (rel.em, "inspect_import_plan", lambda image, plan: (rel.em.import_plan_records(plan), {})), (rel.absd_fs, "fs_region", fake_fs_region),
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
        rel.storage_fence_resume.ensure_lock(out)
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

    # operator-authorized recovery (coordination record #63): the hand-off boundary

    def with_slot(self, out, value):
        """The fake disk's resume slot set to `value` (none, a record, bytes)."""
        state = read_disk(out / rel.IMAGE)
        files = {p: d.encode("latin-1") for p, d in state["files"].items()}
        files[guard.RESUME_PATH] = guard.encode_resume(value) if isinstance(value, (str, dict)) else value
        write_disk(out / rel.IMAGE, files, fs_format=state["format"], fs_id=state["fs_id"], seq=state["seq"],
                   layout=state["layout"], refuse=state["refuse"])
        return out

    RECORD = {"id": "a" * 32, "fs": 7, "seq": 11, "image": "e3" * 32, "ledger_seq": 3, "ledger_boot": "0" * 32,
              "previous": "failed", "time": 1761100000}

    def mutators(self, out, release, kernel):
        """The writers of M1 as (name, callable) over `out` (the enrollment
        tool, absd_try.py, has its own test)."""
        key = self.work / "key"
        key.write_text("private key fixture\n")
        quiet = lambda line: None  # noqa: E731
        return [
            ("install --replace", lambda: rel.cmd_install(Args(release=str(release.path), kernel=str(kernel),
                                                             target=str(out), target_identity="lab-1", replace=True),
                                                        log=quiet)),
            ("stage", lambda: rel.cmd_stage(Args(release=str(self.B.path), kernel=str(self.KB), target=str(out)),
                                            log=quiet)),
            ("select", lambda: rel.cmd_select(Args(release=str(release.path), kernel=str(kernel), target=str(out)),
                                              log=quiet)),
            ("rollback", lambda: rel.cmd_rollback(Args(release=None, kernel=None, target=str(out)), log=quiet)),
            ("accept", lambda: rel.cmd_accept(Args(target=str(out), key=str(key), port=2222), log=quiet)),
            ("restore --replace", lambda: rel.cmd_restore(Args(target=str(out), backup=str(self.work / "backup"),
                                                               replace=True, clone=False, release=None, kernel=None,
                                                               key=None, port=2222, target_identity=None), log=quiet)),
            ("migrate", lambda: rel.cmd_migrate(Args(release=str(release.path), kernel=str(kernel), target=str(out)),
                                                log=quiet)),
            ("remove", lambda: rel.cmd_remove(Args(release=str(release.path), kernel=str(kernel), target=str(out),
                                                   id="rel-b"), log=quiet)),
            ("discard-import-temp", lambda: rel.cmd_discard_import_temp(
                Args(release=str(release.path), kernel=str(kernel), target=str(out), directory="/tmp/.absd-import-0001",
                     fs_id=7, serial=1, bytes=0, sha256="0" * 64), log=quiet)),
            # The release-target reconfigure (operator_image.py refuses an
            # operator directory of release.py before the boundary).
            ("release.py reconfigure", lambda: rel.cmd_reconfigure(Args(release=str(release.path), kernel=str(kernel),
                                                                     target=str(out), etc=str(self.work / "etc"),
                                                                     authorized_keys=None), log=quiet)),
        ]

    def test_every_mutator_refuses_recovery_pending_while_a_record_is_on_the_disk(self):
        # M1 (host): the record alone refuses; an intent alone does not.
        out = self.a_selected()
        self.backup_of(out)
        self.with_slot(out, self.RECORD)
        (self.work / "etc").mkdir(exist_ok=True)
        (self.work / "etc" / "motd").write_text("hi\n")
        before = sha(out / rel.IMAGE)
        refused = 0
        for name, run in self.mutators(out, self.A, self.KA):
            with self.subTest(mutator=name):
                with self.assertRaises((rel.Failed, rel.oi.Failed)) as caught:
                    run()
                self.assertIn("recovery_pending: authorization " + "a" * 32, str(caught.exception), name)
                self.assertEqual(sha(out / rel.IMAGE), before)
                refused += 1
        self.assertEqual(refused, 10)
        # The records alone (slot none, active.toml unsuperseded) refuse too.
        self.with_slot(out, "none")
        other = dict(self.RECORD, id="b" * 32)
        active = {"id": other["id"], "time": "2026-10-22T00:00:00Z", "f": [1, 2, rel.oi.IMAGE_BYTES], "hm": "0" * 64,
                  "planned": guard.encode_resume(other).hex(), "fs_id": other["fs"], "fs_seq": other["seq"],
                  "image": other["image"], "ledger_seq": other["ledger_seq"], "ledger_boot": other["ledger_boot"],
                  "previous": other["previous"], "reason": "x", "user": "u", "tool": "t", "platform": "p",
                  "attest_sole_instance": True, "accept_committed_state": True, "state": "authorized"}
        self.assertTrue(rel.storage_fence_resume.valid_authorization(active))
        (out / "recovery" / "active.toml").write_text(rel.storage_fence_resume.toml_dump({"active": active}))
        with self.assertRaises(rel.Failed) as caught:
            rel.cmd_select(Args(release=str(self.A.path), kernel=str(self.KA), target=str(out)), log=lambda line: None)
        self.assertIn("recovery_pending: authorization " + "b" * 32, str(caught.exception))
        (out / "recovery" / "active.toml").unlink()
        # An unsuperseded intent alone does not block (it may refuse for its own reasons).
        (out / "recovery" / f"intent-{'c' * 32}.toml").write_text("[intent]\nid = \"" + "c" * 32 + "\"\n")
        self.guest()
        rel.cmd_select(Args(release=str(self.A.path), kernel=str(self.KA), target=str(out)), log=lambda line: None)
        # backup is allowed beside a record and labels the copy with its id.
        self.with_slot(out, self.RECORD)
        dest = self.work / "labelled"
        rel.cmd_backup(Args(target=str(out), backup=str(dest)), log=lambda line: None)
        self.assertEqual(rel.read_toml_flat(dest / "backup.toml")["recovery"]["pending_id"], "a" * 32)
        plain = self.work / "plain"
        rel.cmd_backup(Args(target=str(self.with_slot(out, "none")), backup=str(plain)), log=lambda line: None)
        self.assertEqual(rel.read_toml_flat(plain / "backup.toml")["recovery"]["pending_id"], "none")

    def test_mutators_refuse_tool_busy_while_the_recovery_lock_is_held(self):
        # M2 (host): a running boot-operator.sh holds OUT/recovery/lock.
        out = self.a_selected()
        self.backup_of(out)
        holder = subprocess.Popen([sys.executable, "-I", "-c",
                                   "import fcntl, os, sys, time\nfd = os.open(sys.argv[1], os.O_RDWR)\n"
                                   "fcntl.flock(fd, fcntl.LOCK_EX)\nprint('held', flush=True)\ntime.sleep(300)\n",
                                   str(out / "recovery" / "lock")], stdout=subprocess.PIPE)
        self.assertEqual(holder.stdout.readline(), b"held\n")
        try:
            for name, run in self.mutators(out, self.A, self.KA)[1:4]:
                with self.subTest(mutator=name), self.assertRaises(rel.Failed) as caught:
                    run()
                self.assertIn("tool_busy", str(caught.exception))
            with self.assertRaises(rel.Failed) as caught:
                rel.cmd_backup(Args(target=str(out), backup=str(self.work / "busy-backup")), log=lambda line: None)
            self.assertIn("tool_busy", str(caught.exception))
        finally:
            holder.kill()
            holder.wait()

    def test_restore_lock_precedes_open_image_refusal(self):
        # M2 has both conditions: the launcher holds the recovery lock and
        # its QEMU holds the image open. With only the latter, keep the
        # standalone image_in_use refusal. No guest or OFD lock is needed.
        out = self.a_selected()
        self.backup_of(out)
        for locked, reason in ((False, "image_in_use"), (True, "tool_busy")):
            with self.subTest(recovery_lock=locked):
                holder = subprocess.Popen(
                    [sys.executable, "-I", "-c",
                     "import fcntl, os, sys\n"
                     "image = open(sys.argv[1], 'rb')\n"
                     "lock = open(sys.argv[2], 'r+b')\n"
                     "if sys.argv[3] == 'yes': fcntl.flock(lock, fcntl.LOCK_EX)\n"
                     "print('held', flush=True)\n"
                     "sys.stdin.readline()\n",
                     str(out / rel.IMAGE), str(out / "recovery" / "lock"),
                     "yes" if locked else "no"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                try:
                    self.assertEqual(holder.stdout.readline(), b"held\n")
                    before = snapshot(out)
                    with self.assertRaises(rel.Failed) as caught:
                        rel.cmd_restore(Args(target=str(out), backup=str(self.work / "backup"),
                                             replace=True, clone=False, release=None, kernel=None,
                                             key=None, port=2222, target_identity=None), log=lambda line: None)
                    self.assertEqual(snapshot(out), before)
                    self.assertIn(reason, str(caught.exception))
                finally:
                    holder.communicate(b"done\n", timeout=10)
                self.assertEqual(holder.returncode, 0)

    def test_stage_adds_the_resume_slot_to_a_clean_image_without_one(self):
        out = self.a_selected()
        state = read_disk(out / rel.IMAGE)
        files = {p: d.encode("latin-1") for p, d in state["files"].items() if p != guard.RESUME_PATH}
        write_disk(out / rel.IMAGE, files, seq=state["seq"])
        self.guest()
        lines = []
        rel.cmd_stage(Args(release=str(self.B.path), kernel=str(self.KB), target=str(out)), log=lines.append)
        self.assertEqual(read_disk(out / rel.IMAGE)["files"][guard.RESUME_PATH].encode("latin-1"), guard.RESUME_NONE)
        receipt = next((out / "receipts").glob("stage-rel-b-*.toml"))
        self.assertIn('resume_slot = "added"', receipt.read_text())
        self.assertTrue(any(line.startswith("RELEASE STAGED id=rel-b") for line in lines))

    def test_build_refuses_an_operator_directory_target(self):
        # M3 through the command: an operator directory (even without records) is never removed.
        out = self.a_selected()
        before = snapshot(out)
        with self.assertRaises(rel.Failed) as caught:
            rel.cmd_build(Args(id="rel-a", platform=str(self.A.path), kernel=str(self.KA), out=str(out), replace=True,
                               authorized_keys=None, etc=None), log=lambda line: None)
        self.assertIn("target_directory", str(caught.exception))
        self.assertEqual(snapshot(out), before)

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
                before_files = fake_tree(out / rel.IMAGE)
                before_seq = read_disk(out / rel.IMAGE)['seq']
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
                self.assertNotEqual(sha(out / rel.IMAGE), before)
                after_files = fake_tree(out / rel.IMAGE)
                self.assertEqual(after_files[guard.PATH], guard.encode('dirty'))
                if fault != 'after':
                    self.assertEqual(after_files, dict(before_files, **{guard.PATH: guard.encode('dirty')}))
                    self.assertEqual(read_disk(out / rel.IMAGE)['seq'], before_seq)
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

    def test_namespace_normalizes_the_real_reader_directory_flag(self):
        # absd_fs.decode_image exports `dir`, not the on-disk kind byte.
        # The previous fake namespace supplied kind directly and hid this gap.
        out = self.a_selected()
        old_region, old_select, old_tree = rel.oi.absd_fs.fs_region, rel.oi.absd_fs.select, rel.oi.absd_fs.tree
        rel.oi.absd_fs.fs_region = lambda *args: object()
        rel.oi.absd_fs.select = lambda region: {"fs_id": 7}
        rel.oi.absd_fs.tree = lambda *args: {
            "/directory": {"dir": True, "serial": 2},
            "/directory/file": {"dir": False, "serial": 3}}
        try:
            nodes = self.saved_value(rel.oi, "namespace")(out / rel.IMAGE)
        finally:
            rel.oi.absd_fs.fs_region, rel.oi.absd_fs.select, rel.oi.absd_fs.tree = old_region, old_select, old_tree
        self.assertEqual((nodes["/directory"]["kind"], nodes["/directory/file"]["kind"]), (2, 1))
        self.assertEqual((nodes["/directory"]["fs_id"], nodes["/directory/file"]["serial"]), (7, 3))

    def test_import_failure_receipt_identifies_boot_entry_plan_and_temp_objects(self):
        self.guest()
        out = self.a_selected()
        original = rel.run_boot
        path = self.B.tree_files()[0][0]
        directory = str(pathlib.PurePosixPath(path).parent / ".absd-import-0000")
        text = (f"FIXTURE ENTRY index=1 path_hex={path.encode().hex()} step=1\n"
                f"FIXTURE TEMP path_hex={directory.encode().hex()} final_hex={path.encode().hex()} "
                "fs_id=7 serial=99 kind=Dir\n"
                f"FIXTURE TEMP path_hex={(directory + '/file').encode().hex()} final_hex={path.encode().hex()} "
                "fs_id=7 serial=100 kind=File\nFIXTURE IMPORT FAILED fixture failure")
        def failed(script, iso, image, serial):
            pathlib.Path(serial).write_bytes(console(text))
            return "7"
        rel.run_boot = failed
        try:
            self.refused(rel.cmd_stage, "stage state=INDETERMINATE", release=str(self.B.path),
                         kernel=str(self.KB), target=str(out))
        finally:
            rel.run_boot = original
        receipt = self.receipt_of(out, "stage-failed")
        context = receipt["import_failure"]
        self.assertEqual((context["boot"], context["step"], context["entry"]), (1, 1, 1))
        self.assertTrue(context["entry_identified"])
        self.assertEqual(context["entry_path"], path)
        self.assertEqual(context["prefix_bytes"], 0)
        self.assertEqual(context["result_sha256"], hashlib.sha256(self.B.tree_files()[0][1]).hexdigest())
        temps = json.loads(context["temporary_records_json"])
        self.assertEqual([(t["path"], t["serial"]) for t in temps], [(directory, 99), (directory + "/file", 100)])

    def temporary_target(self, extra=None):
        directory = "/absd/.absd-import-0000"
        files = {directory + "/": b"", directory + "/file": b"owned candidate"}
        files.update(extra or {})
        out = self.target(disk_files(self.A, selected="rel-a", extra=files))
        identity = rel.import_temp_identity(rel.Target(out), directory)
        args = dict(target=str(out), release=str(self.A.path), kernel=str(self.KA), directory=directory,
                    fs_id=identity["fs_id"], serial=identity["serial"], bytes=identity["bytes"], sha256=identity["sha256"])
        return out, args

    def test_discard_temp_uses_existing_tree_removal_and_preserves_other_bytes(self):
        self.guest()
        out, args = self.temporary_target()
        before = {p: d for p, d in rel.Target(out).tree().items() if not p.startswith(args["directory"] + "/")}
        rel.cmd_discard_import_temp(Args(**args), log=lambda _: None)
        self.assertEqual(rel.Target(out).tree(), before)
        self.assertNotIn(args["directory"], fake_namespace(out / rel.IMAGE))
        self.assertEqual(len(self.boots), 1)
        self.assertEqual(self.boots[0]["step"], 5)
        path, = (out / "receipts").glob("discard-import-temp-*.toml")
        receipt = rel.read_toml_flat(path)["discard_import_temp"]
        self.assertEqual(receipt["state"], "DISCARDED")
        self.assertEqual(receipt["serial"], args["serial"])

    def test_discard_temp_refuses_wrong_identity_size_or_digest(self):
        self.guest()
        for field in ("fs_id", "serial", "bytes", "sha256"):
            out, args = self.temporary_target()
            before = snapshot(out)
            args[field] = "0" * 64 if field == "sha256" else args[field] + 1
            self.refused(rel.cmd_discard_import_temp, "temporary identity mismatch " + field, **args)
            self.assertEqual(snapshot(out), before)
        self.assertEqual(self.boots, [])

    def test_discard_temp_refuses_unrecorded_contents_and_an_open_image(self):
        self.guest()
        out, args = self.temporary_target()
        extra = rel.Target(out).tree()
        extra[args["directory"] + "/other"] = b"unrecorded"
        write_disk(out / rel.IMAGE, extra)
        before = snapshot(out)
        self.refused(rel.cmd_discard_import_temp, "contains unexpected objects", **args)
        self.assertEqual(snapshot(out), before)
        out, args = self.temporary_target()
        self.hold_open(out / rel.IMAGE)
        try:
            self.refused(rel.cmd_discard_import_temp, "image_in_use", **args)
        finally:
            self.release_holder()
        self.assertEqual(self.boots, [])

    def test_discard_empty_directory_after_loss_at_directory_creation(self):
        self.guest()
        directory = "/absd/.absd-import-0000"
        out = self.target(disk_files(self.A, selected="rel-a", extra={directory + "/": b""}))
        identity = rel.import_temp_identity(rel.Target(out), directory)
        args = Args(target=str(out), release=str(self.A.path), kernel=str(self.KA), directory=directory,
                    fs_id=identity["fs_id"], serial=identity["serial"], bytes=0,
                    sha256=hashlib.sha256(b"").hexdigest())
        rel.cmd_discard_import_temp(args, log=lambda _: None)
        self.assertNotIn(directory, fake_namespace(out / rel.IMAGE))

    def test_host_verification_refuses_unlisted_files_and_empty_directories_in_release_tree(self):
        for extra in ["/releases/rel-b/extra", "/releases/rel-b/empty/"]:
            with self.subTest(extra=extra):
                out = self.target(disk_files(self.A, self.B, selected="rel-a", extra={extra: b""}))
                with self.assertRaisesRegex(rel.Failed, "unlisted import path"):
                    rel.verify_files(rel.Target(out), self.B.tree_files())

    def test_host_verification_refuses_temporary_files_and_empty_temp_directories(self):
        for extra in ["/absd/.absd-import-0000/", "/etc/.absd-import-0000/file"]:
            with self.subTest(extra=extra):
                out = self.target(disk_files(self.A, self.B, selected="rel-a", extra={extra: b""}))
                with self.assertRaisesRegex(rel.Failed, "unresolved_import_temp"):
                    rel.verify_files(rel.Target(out), self.B.tree_files())

    def test_lookalike_outside_import_parents_warns_without_blocking_stage(self):
        self.guest()
        path = "/home/operator/.absd-import-0000"
        out = self.target(disk_files(self.A, selected="rel-a", extra={path + "/a": b"guest file", path + "/b": b"another"}),
                          ("installed rel-a", "selected rel-a", "accepted rel-a"))
        messages = []
        rel.oi.verify_import_paths(out / rel.IMAGE, self.B.tree_files(), log=messages.append)
        self.assertTrue(any(path in line and "ownership unestablished" in line for line in messages))
        rel.cmd_stage(Args(release=str(self.B.path), kernel=str(self.KB), target=str(out)), log=lambda _: None)
        self.assertEqual(rel.Target(out).tree()[path + "/a"], b"guest file")
        self.assertEqual(rel.Target(out).tree()[path + "/b"], b"another")

    def test_status_reports_unrecorded_layout_and_discard_names_recovery(self):
        self.guest()
        out, args = self.temporary_target()
        files = rel.Target(out).tree()
        files[args["directory"] + "/other"] = b"guest file"
        write_disk(out / rel.IMAGE, files)
        before = snapshot(out)
        messages = []
        rel.cmd_status(Args(target=str(out)), log=messages.append)
        self.assertTrue(any("REFUSED import_temp_layout" in line and "restore a verified backup" in line
                            for line in messages))
        self.refused(rel.cmd_discard_import_temp, "REFUSED import_temp_layout", **args)
        self.assertEqual(snapshot(out), before)
        self.assertEqual(self.boots, [])

    def test_status_reports_a_guest_file_lookalike_without_claiming_ownership(self):
        path = "/home/operator/.absd-import-1234"
        out = self.target(disk_files(self.A, selected="rel-a", extra={path: b"guest file"}))
        messages = []
        rel.cmd_status(Args(target=str(out)), log=messages.append)
        self.assertTrue(any("REFUSED import_temp_layout" in line and path in line for line in messages))
        self.assertFalse(any(line.startswith("IMPORT CANDIDATE") for line in messages))

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

    def test_migrate_never_discards_existing_private_recovery_state(self):
        self.guest()
        for extra in ({'/var/state/recovery': b'private logical recovery history'},
                      {guard.PATH: guard.encode('dirty')},
                      {'/var/state.new/recovery': b'interrupted initialization'}):
            with self.subTest(extra=extra):
                out = self.target(disk_files(self.A, selected='rel-a', extra=extra), fs_format=1)
                before = snapshot(out)
                self.refused(rel.cmd_migrate, 'migration_recovery_history:', release=str(self.B.path),
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

    def test_release_build_installs_normal_fsd_even_when_regenerate_is_available(self):
        root = self.A.path
        (root / "commands").mkdir()
        (root / "commands/release").write_bytes(b"rel-a")
        out = self.work / "built-release"
        with mock.patch.object(rel.oi, "system_files", return_value=[]), \
                mock.patch.object(rel.oi, "etc_files", return_value=[]), \
                mock.patch.object(rel.oi, "kernel_iso", side_effect=fake_kernel_iso), \
                mock.patch.object(rel.subprocess, "run", return_value=None):
            rel.cmd_build(Args(id="rel-a", platform=str(root), kernel=str(self.KA), out=str(out),
                               replace=False, etc=None, authorized_keys=None), log=lambda _: None)
        desc = json.loads((out / rel.ISO).read_bytes()[len(ISO_MAGIC):])
        self.assertEqual(desc["server"], sha(root / "absd-fsd.elf"))
        self.assertNotEqual(desc["server"], sha(root / "absd-fsd-regenerate.elf"))
        self.assertEqual(desc["logger"], sha(root / "absd-logd.elf"))
        self.assertEqual((out / "absd-logd.elf").read_bytes(), (root / "absd-logd.elf").read_bytes())

    def test_operator_build_installs_normal_fsd_even_when_regenerate_is_available(self):
        out = self.work / "operator"
        with mock.patch.object(rel.oi, "system_files", return_value=[]), \
                mock.patch.object(rel.oi, "etc_files", return_value=[]), \
                mock.patch.object(rel.oi, "authorized", return_value=b"fixture public key\n"), \
                mock.patch.object(rel.oi, "import_boots") as imports, \
                mock.patch.object(rel.oi, "verify"), \
                mock.patch.object(rel.oi, "check_successor_headroom",
                                  return_value={"peak_extra_blocks": 0, "free_blocks": 0}), \
                mock.patch.object(rel.oi, "manifest"), \
                mock.patch.object(rel.oi, "kernel_iso", side_effect=fake_kernel_iso):
            rel.oi.build(self.KA, out, self.work / "public-key", root=self.A.path,
                         release_id="rel-a", log=lambda _: None)
        desc = json.loads((out / rel.oi.ISO).read_bytes()[len(ISO_MAGIC):])
        self.assertEqual(desc["server"], sha(self.A.path / "absd-fsd.elf"))
        self.assertNotEqual(desc["server"], sha(self.A.path / "absd-fsd-regenerate.elf"))
        self.assertEqual(imports.call_count, 2)
        self.assertTrue(all(call.kwargs["fresh"] for call in imports.call_args_list))

    def test_install_refuses_a_disk_without_successor_headroom_before_publishing(self):
        self.guest()
        out = self.work / 'out'
        tight = lambda image, plan: {"peak_extra_blocks": 100, "free_blocks": 124, "data_blocks": 300}
        with mock.patch.object(rel.oi.em, "check_import_capacity", side_effect=tight):
            with self.assertRaisesRegex(rel.Failed, r"successor_headroom peak_extra_blocks=100 free_blocks=124 needs 125"):
                rel.cmd_install(Args(release=str(self.A.path), kernel=str(self.KA), target=str(out),
                                     target_identity='lab-1'), log=lambda _: None)
        self.assertFalse((out / rel.IMAGE).exists())
        self.assertFalse((out / rel.TARGET).exists())

    def test_install_seeds_one_fresh_guard_before_publishing(self):
        self.guest()
        out = self.work / 'out'
        rel.cmd_install(Args(release=str(self.A.path), kernel=str(self.KA), target=str(out),
                             target_identity='lab-1'), log=lambda _:None)
        self.assertEqual(fake_tree(out / rel.IMAGE)[guard.PATH], guard.FRESH)
        seeds = [data for boot in self.boots for path,data in boot['entries'] if path == guard.PATH]
        self.assertEqual(seeds, [guard.FRESH])

    def test_interrupted_replacement_install_preserves_published_old_disk(self):
        self.guest()
        out = self.a_selected()
        before_disk = sha(out / rel.IMAGE)
        before_iso = sha(out / rel.ISO)
        self.boot_fault = 'before'
        with self.assertRaises(rel.ImportFailed):
            rel.cmd_install(Args(release=str(self.B.path), kernel=str(self.KB), target=str(out),
                                 target_identity='lab-1', replace=True), log=lambda _:None)
        self.assertEqual(sha(out / rel.IMAGE), before_disk)
        self.assertEqual(sha(out / rel.ISO), before_iso)
        self.assertEqual(rel.Target(out).selected(), 'rel-a')

    def test_cached_rollback_of_dirty_image_refuses_before_importer(self):
        self.guest()
        out = self.both()
        self.with_cache(out, self.A, self.KA)
        files = fake_tree(out / rel.IMAGE);files[guard.PATH] = guard.encode('dirty')
        write_disk(out / rel.IMAGE, files)
        before = sha(out / rel.IMAGE)
        with self.assertRaisesRegex(rel.Failed, 'unclean image'):
            rel.import_cached_selection(rel.Target(out), 'rel-a', lambda _:None)
        self.assertEqual(self.boots, [])
        self.assertEqual(sha(out / rel.IMAGE), before)

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

    def remove_refused(self, out, text, *, guarded=False, **kw):
        before = snapshot(out)
        before_files = fake_tree(out / rel.IMAGE)
        before_seq = read_disk(out / rel.IMAGE)['seq']
        kw = dict(dict(release=str(self.B.path), kernel=str(self.KB), target=str(out), id="rel-a"), **kw)
        message = self.refused(rel.cmd_remove, text, **kw)
        if guarded:
            after = snapshot(out)
            self.assertNotEqual(after[rel.IMAGE], before[rel.IMAGE])
            self.assertEqual({k:v for k,v in after.items() if k != rel.IMAGE},
                             {k:v for k,v in before.items() if k != rel.IMAGE})
            self.assertEqual(fake_tree(out / rel.IMAGE),
                             dict(before_files, **{guard.PATH: guard.encode('dirty')}))
            self.assertEqual(read_disk(out / rel.IMAGE)['seq'], before_seq)
        else:
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
        message = self.remove_refused(out, "the disk still holds rel-a whole; nothing was removed", guarded=True)
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
            message = self.remove_refused(out, "nothing was removed", guarded=True)
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

    def test_remove_refuses_to_retry_a_removal_interrupted_before_its_commit(self):
        out = self.interrupted("interrupt-before")
        self.assertEqual(rel.Target(out).trees(), ["rel-a", "rel-b"])
        lines = []
        before = len(self.boots)
        with self.assertRaisesRegex(rel.Failed, 'unclean image; offline reconstruction required'):
            rel.cmd_remove(Args(release=str(self.B.path), kernel=str(self.KB), target=str(out), id="rel-a"),
                           log=lines.append)
        self.assertTrue(any("RELEASE REMOVE RECONCILED id=rel-a: the disk still holds" in line for line in lines))
        self.assertEqual(len(self.boots), before)
        self.assertEqual(fake_tree(out / rel.IMAGE)[guard.PATH], guard.encode('dirty'))
        self.assertEqual(rel.Target(out).trees(), ["rel-a", "rel-b"])
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
        run = subprocess.run([sys.executable, "-I", "-B", "-X", f"pycache_prefix={sys.pycache_prefix or ''}", str(here / "release.py"), "backup", "--target", str(out),
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

    def restore_refused(self, backup, text, verify=True, identity=None, target_files=None, **kw):
        """Restore into a second operator directory refuses and the whole
        directory is byte-identical afterwards; with `verify`, verify-backup
        refuses the same way. With `identity`, the directory has a TARGET."""
        dest = self.work / "restored"
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir()
        write_disk(dest / rel.IMAGE, {"/home/operator/keep": b"keep\n", **(target_files or {})})
        (dest / rel.LEDGER).write_text("2026-10-12T00:00:00Z installed other\n")
        if identity:
            (dest / rel.TARGET).write_text(identity + "\n")
        rel.storage_fence_resume.ensure_lock(dest)
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
        # Reads take the image's own size (coordination record #28), so a truncated
        # copy is refused by the digest backup.toml records, before anything
        # is written; a ragged size by the sector check.
        backup = self.backup_of(self.a_selected())
        with open(backup / rel.IMAGE, "r+b") as handle:
            handle.truncate(rel.oi.IMAGE_BYTES // 2)
        self.restore_refused(backup, "the backup image's digest is not the one backup.toml records")
        with open(backup / rel.IMAGE, "r+b") as handle:
            handle.truncate(rel.oi.IMAGE_BYTES // 2 + 100)
        self.restore_refused(backup, "not a whole number of sectors")

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
                                   "server": json.loads(pathlib.Path(iso).read_bytes()[len(ISO_MAGIC):])["server"],
                                   "logger": json.loads(pathlib.Path(iso).read_bytes()[len(ISO_MAGIC):])["logger"],
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
        self.assertEqual(self.boots[0]["server"], sha(self.A.path / "absd-fsd-regenerate.elf"))
        self.assertEqual(self.boots[0]["logger"], sha(self.A.path / "absd-logd.elf"))
        self.assertNotEqual(self.boots[0]["server"], sha(self.A.path / "absd-fsd.elf"))
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
        # A clean halted target reaches the original copy/digest boundary.
        # Fenced and unknown targets now refuse earlier, without a copy.
        golden = here.parent / "fixtures/storage-fence"
        clean = {guard.PATH: guard.encode("clean"), "/var/state/recovery.init": b"",
                 "/var/state/recovery": (golden / "recovery-v1-ledger.bin").read_bytes()}
        clean.update({"/var/state/facts/served-" + name:
                      (golden / ("recovery-v1-" + name + ".bin")).read_bytes()
                      for name in ("ready", "end", "stopped", "completed")})
        self.restore_refused(backup, "the restored copy differs from the backup", verify=False, target_files=clean)

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

    # The case-2 diagnostic binding, using an actual refused boot. These host
    # controls exercise the existing boot predicate; they do not boot QEMU or
    # establish filesystem writes, image preservation or hardware behaviour.

    def release_case2_refusal(self, serial, status=7, worker=None, expected=None):
        matrix = load("release-matrix.py")
        tree = ast.parse((here / "release-matrix.py").read_text())
        calls = [node for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                 and node.func.id == "boot_expect" and len(node.args) > 2
                 and isinstance(node.args[2], ast.Constant) and node.args[2].value == "case2"]
        self.assertEqual(len(calls), 1)
        literal = next(value.value for value in calls[0].keywords if value.arg == "want_refusal")
        self.assertIsInstance(literal, ast.Constant)
        self.assertEqual(literal.value, "FSD FAILED read-only mount: UnsupportedFormat")
        exact = next(value.value for value in calls[0].keywords if value.arg == "whole_line")
        self.assertIsInstance(exact, ast.Constant)
        self.assertIs(exact.value, True)
        stopped = []

        class FinishedBoot:
            def __init__(self, *args):
                self.proc = self

            def poll(self):
                return status

            def serial(self):
                return serial

            def worker(self):
                return worker if worker is not None else matrix.rel.ssh_absd.captured(serial.encode())

            def stop(self):
                stopped.append(True)

        with mock.patch.object(matrix.rel, "Boot", FinishedBoot):
            result = matrix.boot_expect(None, None, "case2", 0,
                                        want_refusal=literal.value if expected is None else expected,
                                        whole_line=exact.value)
        self.assertEqual(stopped, [True])
        return result[0]

    def test_release_case2_accepts_the_recorded_read_only_format_refusal(self):
        fixture = here / "fixtures" / "release-unsupported-format.serial"
        data = fixture.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         "f7aee0776f660e8d0587ee3e927f32036f68a1f2047dc227531cc147d774177b")
        serial = data.decode()
        self.assertTrue(self.release_case2_refusal(serial))
        # This is the old binding's false result on the same captured bytes,
        # not a changed verdict for the original qualification occurrence.
        self.assertFalse(self.release_case2_refusal(serial, expected="FSD FAILED mount"))

    def test_release_case2_keeps_the_existing_refusal_guards(self):
        serial = (here / "fixtures" / "release-unsupported-format.serial").read_text()
        current = "FSD FAILED read-only mount: UnsupportedFormat"
        mutations = [
            (serial, 3, None),
            (serial + "ABSD KERNEL BOOT\n", 7, None),
            (serial + "MACHINE RECOVER RESET pid=1\n", 7, None),
            (serial, 7, "SSH LISTENING port=22"),
            (serial.replace(current, "FSD FAILED mount: UnsupportedFormat"), 7, None),
            (serial.replace(current, "FSD FAILED unrelated: UnsupportedFormat"), 7, None),
            (serial.replace(current, 'FSD FAILED read-only mount: Corrupt("header")'), 7, None),
            (serial.replace(current, "X" + current), 7, None),
            (serial.replace(current, "init: " + current), 7, None),
            (serial.replace(current, current + " suffix"), 7, None),
            (serial.replace(current, current + "\n" + current), 7, None),
        ]
        for changed, status, worker in mutations:
            with self.subTest(status=status, worker=worker, serial=changed[-350:]):
                self.assertFalse(self.release_case2_refusal(changed, status, worker))

    def run_switch_matrix(self, wanted, fault=None, mutant=None):
        """Real matrix/host commands, simulated importer and served boots.

        The captured refusals supply the boot text. The fake disk makes the
        failed history dirty and admits served boots only from a clean/fresh
        guard; no native runtime or hardware conclusion follows.
        """
        matrix = load("release-matrix.py")
        if mutant:
            class WeakerRestoreOracle(ast.NodeTransformer):
                changed = 0

                def visit_Call(self, node):
                    self.generic_visit(node)
                    if (mutant == "omit-retention" and isinstance(node.func, ast.Name)
                            and node.func.id == "record" and isinstance(node.args[0], ast.Constant)
                            and node.args[0].value in (9, 13)):
                        predicate = node.args[2]
                        before = len(predicate.values)
                        predicate.values = [v for v in predicate.values
                                            if not (isinstance(v, ast.Name) and v.id == "retained")]
                        self.changed += before - len(predicate.values)
                    return node

                def visit_Expr(self, node):
                    if (mutant == "in-place" and isinstance(node.value, ast.Call)
                            and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "rename"
                            and len(node.value.args) == 1 and isinstance(node.value.args[0], ast.Name)
                            and node.value.args[0].id == "destroyed"):
                        self.changed += 1
                        return ast.copy_location(ast.Pass(), node)
                    return self.generic_visit(node)

            tree = ast.parse((here / "release-matrix.py").read_text())
            main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
            weaker = WeakerRestoreOracle()
            main = weaker.visit(main)
            self.assertEqual(weaker.changed, 2, mutant)
            exec(compile(ast.fix_missing_locations(ast.Module(body=[main], type_ignores=[])),
                         str(here / "release-matrix.py"), "exec"), matrix.__dict__)
        matrix.rel = rel
        self.guest()
        work = self.work / "switch-matrix"
        shutil.rmtree(work, ignore_errors=True)
        calls = []
        owner = self
        metadata = json.loads((here / "fixtures" / "release-fenced-history.json").read_text())
        for item in metadata["files"]:
            self.assertEqual(sha(here / "fixtures" / item["path"]), item["sha256"])
        failed = (here / "fixtures" / "release-failed-selection.serial").read_text()
        fenced = (here / "fixtures" / "release-fenced-successor.serial").read_text()

        def put(target, name, data):
            state = read_disk(target.image)
            files = {p: d.encode("latin-1") for p, d in state["files"].items()}
            files[name] = data
            write_disk(target.image, files, fs_format=state["format"], fs_id=state["fs_id"], seq=state["seq"])

        class MatrixBoot:
            def __init__(self, target, iso, name, port):
                self.target, self.name, self.proc = target, name, self
                self.console = target.out / f"console-{name}.log"
                self.release_id = target.selected()
                self.before = guard.parse(target.tree()[guard.PATH])
                self.text = failed if name == "case6" else fenced if name == "case6-successor" else ""
                for target_name, stem, diagnostic in (
                        ("case6", "mismatch", "RELEASE REFUSED reason=release_mismatch"),
                        ("case6-successor", "cold", "RECOVERY WRITABLE REFUSED reason=storage_fence previous=not_ready fence=none")):
                    if name == target_name:
                        for suffix, replacement in (("prefix", "X" + diagnostic),
                                                    ("echo", "init: " + diagnostic),
                                                    ("suffix", diagnostic + " suffix"),
                                                    ("duplicate", diagnostic + "\n" + diagnostic)):
                            if fault == stem + "-" + suffix:
                                self.text = self.text.replace(diagnostic, replacement)
                calls.append((name, "start", str(target.out), self.before))
                if name in ("case9", "case13-restored"):
                    destroyed = target.image.with_name(target.image.name + ".destroyed")
                    if fault == "retained-mutation":
                        destroyed.write_bytes(b"changed retained image\n")
                    if fault == "retained-missing":
                        destroyed.unlink()
                if name == "case6":
                    put(target, guard.PATH, guard.encode("dirty"))
                if name == "case6-successor":
                    if fault == "cold-write":
                        self.text = self.text.replace("block_writes=0", "block_writes=1")
                    if fault == "cold-mutation":
                        put(target, "/cold-change", b"changed")
                    if fault == "cold-reset":
                        self.text += "MACHINE RECOVER RESET pid=1\n"
                    if fault == "cold-no-accounting":
                        self.text = "\n".join(x for x in self.text.splitlines() if not x.startswith("DURABLE status="))

            def poll(self):
                return 3 if fault == "cold-status" and self.name == "case6-successor" else 7

            def serial(self):
                if self.name == "case7":
                    if fault == "served-recovery":
                        return "SERVED RECOVERY REFUSED test\n"
                    if fault == "halt-escalated":
                        return "SERVED SHUTDOWN ESCALATED test\n"
                return self.text

            def worker(self):
                text = rel.ssh_absd.captured(self.text.encode())
                return text + "\nSSH LISTENING port=22\n" if fault == "cold-listener" else text

            def wait_ready(self, release_id):
                if self.before not in ("fresh", "clean"):
                    raise rel.Failed("simulated writable boot refused: dirty guard")
                owner.assertEqual(self.release_id, release_id)
                put(self.target, guard.PATH, guard.encode("dirty"))
                return {"fingerprint": rel.host_key_fingerprint(bytes(range(32)))}

            def ssh(self, key, command, stdin=b""):
                calls.append((self.name, command))
                if command == "/bin/release":
                    if fault == "release-status" and self.name == "case7":
                        return 1, f"release={self.release_id}".encode(), b"failed"
                    return 0, f"release={self.release_id}".encode(), b""
                if command == "/bin/cat > /home/operator/.accept":
                    put(self.target, "/home/operator/.accept", stdin)
                    return 0, b"", b""
                if command == "/bin/cat /home/operator/.accept":
                    return 0, self.target.tree()["/home/operator/.accept"], b""
                owner.assertEqual(command, "shutdown")
                if fault == "halt-command" and self.name == "case7":
                    return 1, b"", b"failed"
                if fault == "accepted-b" and self.name == "case7":
                    self.target.ledger_append("accepted", self.release_id, "simulated unexpected acceptance")
                put(self.target, guard.PATH, guard.encode("clean"))
                return 0, b"going down for halt", b""

            def wait_end(self):
                return 7 if fault == "halt-status" and self.name == "case7" else 3

            def stop(self):
                calls.append((self.name, "stop"))

        argv = ["release-matrix.py", "--release-a", str(self.A.path), "--release-b", str(self.B.path),
                "--kernel-a", str(self.KA), "--kernel-b", str(self.KB), "--key", str(self.work / "key"),
                "--work", str(work), "--only", ",".join(map(str, sorted(wanted)))]
        with mock.patch.object(rel, "Boot", MatrixBoot), mock.patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as ended:
            matrix.main()
        return matrix.RESULTS, calls, work, ended.exception.code

    def test_restore_matrix_retains_destroyed_images_and_all_previous_success_predicates(self):
        for wanted in ({9}, {13}, {9, 13}):
            with self.subTest(wanted=wanted):
                results, calls, work, rc = self.run_switch_matrix(wanted)
                self.assertEqual(rc, 0, results)
                self.assertEqual([(x["case"], x["verdict"]) for x in results],
                                 [(case, "PASS") for case in sorted(wanted)])
                for case in wanted:
                    target = rel.Target(work / f"case{case}")
                    destroyed = target.image.with_name(target.image.name + ".destroyed")
                    self.assertEqual(destroyed.read_bytes(), b"\0" * 4096)
                    self.assertEqual(target.selected(), self.A.id)
                    self.assertTrue(target.tree()["/home/operator/.accept"].startswith(b"accept rel-a "))
                    self.assertEqual(guard.parse(target.tree()[guard.PATH]), "clean")

    def test_restore_matrix_cannot_pass_with_changed_or_missing_retained_evidence(self):
        for case in (9, 13):
            for fault in ("retained-mutation", "retained-missing"):
                with self.subTest(case=case, fault=fault):
                    results, calls, work, rc = self.run_switch_matrix({case}, fault)
                    self.assertEqual(rc, 1, results)
                    self.assertEqual([(x["case"], x["verdict"]) for x in results], [(case, "FAIL")])

    def test_restore_matrix_retention_predicate_mutant_accepts_the_negative_controls(self):
        # The same changed/missing evidence must distinguish the real oracle
        # from its weaker predicate, through main's actual case wiring.
        for case in (9, 13):
            for fault in ("retained-mutation", "retained-missing"):
                with self.subTest(case=case, fault=fault):
                    results, calls, work, rc = self.run_switch_matrix({case}, fault, "omit-retention")
                    self.assertEqual(rc, 0, results)
                    self.assertEqual([(x["case"], x["verdict"]) for x in results], [(case, "PASS")])

    def test_restore_matrix_in_place_mutant_still_hits_the_product_refusal(self):
        for case in (9, 13):
            with self.subTest(case=case):
                # Restore refuses the zeroed target, so even the simulated
                # served boot cannot read a disk. No native claim follows.
                with self.assertRaisesRegex(rel.Failed, "not a fake disk"):
                    self.run_switch_matrix({case}, mutant="in-place")

    def test_switch_matrix_keeps_failed_history_fenced_and_rolls_back_a_clean_history(self):
        results, calls, work, rc = self.run_switch_matrix({6, 7, 8})
        self.assertEqual(rc, 0, results)
        self.assertEqual([(x["case"], x["verdict"]) for x in results], [(6, "PASS"), (7, "PASS"), (8, "PASS")])
        starts = {row[0]: row for row in calls if row[1] == "start"}
        self.assertEqual(starts["case6-successor"][2:], (str(work / "case6"), "dirty"))
        self.assertEqual(starts["case7"][2:], (str(work / "case7"), "clean"))
        self.assertEqual(guard.parse(rel.Target(work / "case6").tree()[guard.PATH]), "dirty")
        clean = rel.Target(work / "case7")
        self.assertEqual(clean.selected(), self.A.id)
        self.assertTrue(any(row.split()[1:3] == ["rolled_back", self.A.id] for row in clean.ledger_lines()))
        self.assertFalse(any(row.split()[1:3] == ["accepted", self.B.id] for row in clean.ledger_lines()))
        self.assertEqual(guard.parse(clean.tree()[guard.PATH]), "clean")

    def test_switch_matrix_only_selections_construct_their_own_prerequisites(self):
        for wanted in ({6}, {7}, {8}, {7, 8}):
            with self.subTest(wanted=wanted):
                results, calls, work, rc = self.run_switch_matrix(wanted)
                self.assertEqual(rc, 0, results)
                self.assertEqual([r["case"] for r in results], sorted(wanted))
                names = [row[0] for row in calls if row[1] == "start"]
                self.assertEqual("case6" in names, 6 in wanted)
                self.assertEqual("case7" in names, bool(wanted & {7, 8}))
                self.assertEqual("case8" in names, 8 in wanted)

    def test_switch_matrix_cold_successor_controls_cannot_pass(self):
        for fault in ("cold-write", "cold-mutation", "cold-reset", "cold-listener", "cold-no-accounting", "cold-status",
                      "cold-prefix", "cold-echo", "cold-suffix", "cold-duplicate",
                      "mismatch-prefix", "mismatch-echo", "mismatch-suffix", "mismatch-duplicate"):
            with self.subTest(fault=fault):
                results, calls, work, rc = self.run_switch_matrix({6}, fault)
                self.assertEqual(rc, 1, results)
                self.assertEqual(results[0]["verdict"], "FAIL")

    def test_switch_matrix_requires_successful_release_command_and_clean_halt_before_rollback(self):
        for fault in ("release-status", "halt-command", "halt-status", "served-recovery", "halt-escalated", "accepted-b"):
            with self.subTest(fault=fault):
                results, calls, work, rc = self.run_switch_matrix({7, 8}, fault)
                self.assertEqual(rc, 1, results)
                self.assertEqual([x["verdict"] for x in results], ["FAIL", "FAIL"])
                self.assertEqual(rel.Target(work / "case7").selected(), self.B.id)
                self.assertFalse(any(row[0] == "case8" for row in calls))
                self.assertIn(("case7", "stop"), calls)

    def test_matrix_stops_a_boot_that_refuses_served_readiness(self):
        matrix = load("release-matrix.py")
        stopped = []

        class RefusedBoot:
            def __init__(self, *args):
                pass

            def wait_ready(self, release_id):
                raise matrix.rel.Failed("simulated pre-ready refusal")

            def stop(self):
                stopped.append(True)

        with mock.patch.object(matrix.rel, "Boot", RefusedBoot):
            with self.assertRaisesRegex(matrix.rel.Failed, "simulated pre-ready refusal"):
                matrix.boot_expect(None, None, "refused-ready", 0, release_id="rel-b")
        self.assertEqual(stopped, [True])

    # the command line

    def test_main_refuses_a_command_without_its_kernel(self):
        run = subprocess.run([sys.executable, "-I", "-B", "-X", f"pycache_prefix={sys.pycache_prefix or ''}", str(here / "release.py"), "select", "--release", "x", "--target",
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

    # reconfigure (#63 F2). release.py reconfigure on a release.py
    # operator directory; operator_image.py reconfigure on a
    # build-operator-image.sh output, refusing a release.py directory.

    def etc_dir(self, name="etc-new", content=b"address 10.0.2.20\n"):
        etc = self.work / name
        etc.mkdir(exist_ok=True)
        (etc / "network.conf").write_bytes(content)
        return etc

    def installed(self):
        """A target `release.py install` made (simulated importer), with
        rel-a accepted."""
        self.guest()
        out = self.work / "out"
        rel.cmd_install(Args(release=str(self.A.path), kernel=str(self.KA), target=str(out), target_identity="lab-1"),
                        log=lambda line: None)
        rel.Target(out).ledger_append("accepted", "rel-a")
        # As a served boot and an orderly shutdown leave it: a clean guard.
        files = fake_tree(out / rel.IMAGE)
        files[guard.PATH] = guard.encode("clean")
        write_disk(out / rel.IMAGE, files)
        self.boots.clear()
        return out

    def reconfigure(self, out, release=None, kernel=None, etc=None, log=lambda line: None, **kw):
        return rel.cmd_reconfigure(Args(release=str((release or self.A).path), kernel=str(kernel or self.KA),
                                        target=str(out), etc=str(etc or self.etc_dir()), **kw), log=log)

    def reconfigure_failed(self, out, state):
        with self.assertRaises(rel.ReconfigureFailed) as caught:
            self.reconfigure(out)
        self.assertEqual(caught.exception.state, state, str(caught.exception))
        self.assertEqual(fake_tree(out / rel.IMAGE)["/etc/network.conf"], b"address 10.0.2.20\n")
        self.assertEqual(guard.parse(fake_tree(out / rel.IMAGE)[guard.PATH]), "clean")
        self.assertEqual(self.receipt_of(out, "reconfigure-failed")["reconfigure"]["state"], state)
        return str(caught.exception)

    def published(self, out):
        return sorted((out / "receipts").glob("reconfigure-rel-a-*.toml"))

    def temporaries(self, out):
        return sorted(p.name for p in (out / "receipts").iterdir() if p.name.endswith(".tmp"))

    def reconfigure_refused(self, out, text, state="REFUSED", **kw):
        """The refusal before any importer boot or kernel build: the image,
        the guard, the ledger and every file as they were, plus exactly this
        attempt's failure receipt when receipts/ can take it (none when it
        cannot, and the message says so). Nothing else may be added."""
        rel.oi.kernel_iso, rel.run_boot = tripwire, tripwire
        image, ledger = sha(out / rel.IMAGE), (out / rel.LEDGER).read_bytes() if (out / rel.LEDGER).is_file() else None
        receipts = out / "receipts"
        takes_receipt = (not receipts.exists() or (receipts.is_dir() and not receipts.is_symlink()
                                                   and os.access(receipts, os.W_OK)))
        before = readable_snapshot(out)
        with self.assertRaises(rel.ReconfigureFailed) as caught:
            self.reconfigure(out, **kw)
        message = str(caught.exception)
        self.assertIn(text, message)
        self.assertEqual(caught.exception.state, state)
        self.assertIn(f"reconfigure state={state}", message)
        self.assertEqual(sha(out / rel.IMAGE), image)
        if ledger is not None:
            self.assertEqual((out / rel.LEDGER).read_bytes(), ledger)
        after = readable_snapshot(out)
        self.assertEqual({k: v for k, v in after.items() if k in before}, before)
        added = sorted(set(after) - set(before))
        if not takes_receipt:
            self.assertEqual(added, [])
            self.assertIn("failure receipt unavailable", message)
            return message
        self.assertEqual(len(added), 1, added)
        found = re.fullmatch(r"receipts/reconfigure-failed-([0-9a-f]{32})-[0-9TZ-]+\.toml", added[0])
        self.assertIsNotNone(found, added[0])
        self.assertIn(f"failure receipt={out / added[0]}", message)
        section = rel.read_toml_flat(out / added[0])["reconfigure"]
        phase = re.search(r"reconfigure state=\S+ phase=(\S+)", message).group(1)
        self.assertEqual((section["attempt"], section["state"], section["phase"]), (found.group(1), state, phase))
        self.assertEqual(rel.RECONFIGURE_STATES[phase], state)
        self.assertIs(section["target_effects_possible"], state != "REFUSED")
        self.assertIn(text, section["error"])
        return message

    def test_reconfigure_a_release_installed_target_with_the_selected_release_importer(self):
        out = self.installed()
        self.reconfigure(out)
        target = rel.Target(out)
        disk = fake_tree(target.image)
        self.assertEqual(disk["/etc/network.conf"], b"address 10.0.2.20\n")
        self.assertEqual(guard.parse(disk[guard.PATH]), "clean")
        self.assertFalse((out / "MANIFEST").exists())
        self.assertEqual(self.temporaries(out), [])
        # One step-4 boot of the verified copy of rel-a's importer, under
        # the kernel at rel-a's commit.
        self.assertEqual([(b["step"], b["entries"]) for b in self.boots],
                         [(4, [("/etc/network.conf", b"address 10.0.2.20\n")])])
        desc = json.loads(self.boots[0]["iso"].read_bytes()[len(ISO_MAGIC):])
        self.assertEqual(desc["worker"], self.A.artifact_digests()["fixture-import.elf"])
        self.assertEqual(self.boots[0]["script"], self.KA / "scripts" / "durable-boot.sh")
        receipt = self.receipt_of(out, "reconfigure-rel-a")
        self.assertEqual(receipt["reconfigure"]["state"], "RECONFIGURED")
        self.assertEqual(receipt["reconfigure"]["files"],
                         [hashlib.sha256(b"address 10.0.2.20\n").hexdigest() + " /etc/network.conf"])
        self.assertTrue(receipt["reconfigure"]["installation_evidence"].startswith("install-rel-a-"))
        self.assertEqual(receipt["provenance"], {"kernel_commit": COMMIT_A,
                                                 "fixture_import": self.A.artifact_digests()["fixture-import.elf"]})
        last = target.ledger_lines()[-1].split()
        self.assertEqual(last[1:3], ["reconfigured", "rel-a"])
        self.assertEqual(last[3], "receipt=" + sorted((out / "receipts").glob("reconfigure-rel-a-*.toml"))[0].name)
        self.assertEqual(target.selected(), "rel-a")
        self.assertEqual(target.last("accepted"), "rel-a")

    def test_reconfigure_leaves_acceptance_and_rollback_as_they_were(self):
        out = self.installed()
        quiet = lambda line: None  # noqa: E731
        rel.cmd_stage(Args(release=str(self.B.path), kernel=str(self.KB), target=str(out)), log=quiet)
        rel.cmd_select(Args(release=str(self.B.path), kernel=str(self.KB), target=str(out)), log=quiet)
        self.reconfigure(out, release=self.B, kernel=self.KB)
        target = rel.Target(out)
        self.assertEqual(target.ledger_lines()[-1].split()[1:3], ["reconfigured", "rel-b"])
        self.assertEqual((target.selected(), target.last("accepted")), ("rel-b", "rel-a"))
        rel.cmd_rollback(Args(target=str(out)), log=quiet)
        self.assertEqual(target.selected(), "rel-a")
        self.assertEqual(fake_tree(target.image)["/etc/network.conf"], b"address 10.0.2.20\n")

    def test_reconfigure_refuses_another_release_than_the_selected(self):
        out = self.installed()
        self.reconfigure_refused(out, "the disk selects rel-a", release=self.B, kernel=self.KB)

    def test_reconfigure_refuses_a_kernel_at_another_commit(self):
        out = self.installed()
        self.reconfigure_refused(out, "kernel checkout is at", kernel=self.KB)

    def test_reconfigure_refuses_an_importer_the_manifest_does_not_name(self):
        out = self.installed()
        (self.A.path / "fixture-import.elf").write_bytes(b"another importer\n")
        self.reconfigure_refused(out, "manifest_mismatch digest fixture-import.elf")

    def test_reconfigure_refuses_a_disk_record_that_is_not_the_release_record(self):
        out = self.installed()
        files = fake_tree(out / rel.IMAGE)
        files["/releases/rel-a/release"] = record_bytes("rel-b")
        write_disk(out / rel.IMAGE, files)
        self.reconfigure_refused(out, "release_mismatch")

    def test_reconfigure_refuses_a_manifest_other_than_the_install_recorded(self):
        out = self.installed()
        with open(self.A.manifest, "a") as handle:
            handle.write("\n# edited after the install\n")
        self.reconfigure_refused(out, "is not the manifest install-rel-a-")

    def test_reconfigure_refuses_damaged_installation_evidence(self):
        for case in ("malformed", "unreadable", "missing-manifest", "newer-malformed-stage"):
            with self.subTest(case=case):
                out = self.installed()
                (install,) = sorted((out / "receipts").glob("install-rel-a-*.toml"))
                if case == "malformed":
                    install.write_text("[install\nrelease = \n")
                elif case == "unreadable":
                    if os.geteuid() == 0:
                        self.skipTest("root reads any file")
                    install.chmod(0)
                elif case == "missing-manifest":
                    install.write_text('[install]\nrelease = "rel-a"\n')
                else:
                    # A valid older install receipt is never used in place
                    # of a damaged newer one.
                    (out / "receipts" / "stage-rel-a-2999-01-01T000000Z.toml").write_text("not toml [\n")
                text = {"malformed": "installation_evidence_unreadable", "unreadable": "installation_evidence_unreadable",
                        "missing-manifest": "installation_evidence_malformed",
                        "newer-malformed-stage": "installation_evidence_unreadable"}[case]
                try:
                    self.reconfigure_refused(out, text)
                finally:
                    install.chmod(0o644)
                    shutil.rmtree(out)

    def test_reconfigure_refuses_destinations_it_cannot_record_into(self):
        for case in ("ledger-directory", "receipts-file", "no-target", "no-ledger"):
            with self.subTest(case=case):
                out = self.installed()
                if case == "ledger-directory":
                    (out / rel.LEDGER).unlink()
                    (out / rel.LEDGER).mkdir()
                elif case == "receipts-file":
                    shutil.rmtree(out / "receipts")
                    (out / "receipts").write_text("not a directory\n")
                elif case == "no-target":
                    (out / rel.TARGET).unlink()
                else:
                    (out / rel.LEDGER).unlink()
                self.reconfigure_refused(out, {"ledger-directory": "RELEASES: not a regular file",
                                               "receipts-file": "receipts: not a directory",
                                               "no-target": "TARGET: not a regular file",
                                               "no-ledger": "RELEASES: not a regular file"}[case])
                shutil.rmtree(out)

    def test_reconfigure_refuses_files_that_need_more_than_one_boot(self):
        out = self.installed()
        etc = self.etc_dir("etc-big", b"#" * (rel.em.IMPORT_BUDGET + 1))
        self.reconfigure_refused(out, "exceed one importer boot", etc=etc)

    def test_reconfigure_refuses_tool_busy_while_the_recovery_lock_is_held(self):
        # Target.mutation: another holder of OUT/recovery/lock (a running
        # boot-operator.sh) refuses before any importer boot.
        out = self.installed()
        holder = subprocess.Popen([sys.executable, "-I", "-c",
                                   "import fcntl, os, sys, time\nfd = os.open(sys.argv[1], os.O_RDWR)\n"
                                   "fcntl.flock(fd, fcntl.LOCK_EX)\nprint('held', flush=True)\ntime.sleep(300)\n",
                                   str(out / "recovery" / "lock")], stdout=subprocess.PIPE)
        self.assertEqual(holder.stdout.readline(), b"held\n")
        try:
            message = self.reconfigure_refused(out, "tool_busy")
            self.assertIn("reconfigure state=REFUSED phase=prepare", message)
        finally:
            holder.kill()
            holder.wait()
        self.assertEqual(self.boots, [])

    def test_reconfigure_refuses_recovery_pending_while_a_record_is_on_the_disk(self):
        # Target.mutation: an authorization record on the disk refuses
        # before any importer boot.
        out = self.installed()
        self.with_slot(out, self.RECORD)
        message = self.reconfigure_refused(out, "recovery_pending: authorization " + "a" * 32)
        self.assertIn("reconfigure state=REFUSED phase=prepare", message)
        self.assertEqual(self.boots, [])

    def test_reconfigure_refusal_on_a_target_without_the_recovery_lock_adds_the_lock_and_one_receipt(self):
        # A target installed before the recovery lock existed: the refusal
        # (after Target.mutation, at the selection check) leaves exactly the
        # persistent lock file and one REFUSED failure receipt; nothing else
        # is added or changed, and the lock is not unlinked.
        out = self.installed()
        shutil.rmtree(out / "recovery")
        before = readable_snapshot(out)
        with self.assertRaises(rel.ReconfigureFailed) as caught:
            self.reconfigure(out, release=self.B, kernel=self.KB)
        self.assertEqual(caught.exception.state, "REFUSED")
        self.assertIn("the disk selects rel-a", str(caught.exception))
        after = readable_snapshot(out)
        self.assertEqual({k: v for k, v in after.items() if k in before}, before)
        added = sorted(set(after) - set(before))
        self.assertEqual(len(added), 2, added)
        receipt, lock = added
        self.assertEqual(lock, "recovery/lock")
        self.assertEqual((out / lock).stat().st_size, 0)
        self.assertRegex(receipt, r"^receipts/reconfigure-failed-[0-9a-f]{32}-[0-9TZ-]+\.toml$")
        section = rel.read_toml_flat(out / receipt)["reconfigure"]
        self.assertEqual((section["state"], section["phase"], section["target_effects_possible"]),
                         ("REFUSED", "prepare", False))
        self.assertIn(str(out / receipt), str(caught.exception))
        self.assertEqual(sorted(p.name for p in (out / "recovery").iterdir()), ["lock"])

    def test_reconfigure_refuses_an_in_use_image(self):
        out = self.installed()
        self.hold_open(out / rel.IMAGE)
        self.reconfigure_refused(out, "a reconfiguration")

    def test_reconfigure_a_selection_change_during_the_boot_is_not_recorded(self):
        out = self.installed()
        real = self.fake_boot

        def boot(script, iso, image, serial):
            status = real(script, iso, image, serial)
            state = read_disk(image)
            state["files"][rr.SELECTED] = "rel-b\n"
            write_disk(image, {p: d.encode("latin-1") for p, d in state["files"].items()}, seq=state["seq"])
            return status
        rel.run_boot = boot
        ledger = (out / rel.LEDGER).read_text()
        with self.assertRaises(rel.ReconfigureFailed) as caught:
            self.reconfigure(out)
        self.assertEqual(caught.exception.state, "INDETERMINATE")
        self.assertIn("another operation used this target", str(caught.exception))
        self.assertEqual((out / rel.LEDGER).read_text(), ledger)
        self.assertFalse(list((out / "receipts").glob("reconfigure-rel-a-*")))
        failed = self.receipt_of(out, "reconfigure-failed")["reconfigure"]
        self.assertEqual((failed["state"], failed["phase"], failed["receipt"]), ("INDETERMINATE", "revalidate", "none"))

    def test_reconfigure_a_failed_boot_leaves_the_guard_dirty_and_the_next_attempt_refuses(self):
        out = self.installed()
        self.boot_fault = "after"
        with self.assertRaises(rel.ReconfigureFailed) as caught:
            self.reconfigure(out)
        self.assertEqual(caught.exception.state, "INDETERMINATE")
        self.assertEqual(guard.parse(fake_tree(out / rel.IMAGE)[guard.PATH]), "dirty")
        self.assertEqual(self.receipt_of(out, "reconfigure-failed")["reconfigure"]["phase"], "import")
        self.boot_fault = None
        self.boots.clear()
        with self.assertRaises(rel.ReconfigureFailed) as caught:
            self.reconfigure(out)
        self.assertIn("unclean image", str(caught.exception))
        self.assertEqual(self.boots, [])

    def test_reconfigure_an_added_file_during_the_boot_is_not_recorded(self):
        out = self.installed()
        real = self.fake_boot

        def boot(script, iso, image, serial):
            status = real(script, iso, image, serial)
            state = read_disk(image)
            state["files"]["/releases/rel-a/bin/extra"] = "planted\n"
            write_disk(image, {p: d.encode("latin-1") for p, d in state["files"].items()}, seq=state["seq"])
            return status
        rel.run_boot = boot
        ledger = (out / rel.LEDGER).read_text()
        with self.assertRaises(rel.ReconfigureFailed) as caught:
            self.reconfigure(out)
        self.assertEqual(caught.exception.state, "INDETERMINATE")
        self.assertIn("added, removed or changed", str(caught.exception))
        self.assertEqual((out / rel.LEDGER).read_text(), ledger)
        self.assertEqual(self.published(out), [])

    def test_reconfigure_receipt_write_failures_publish_no_receipt(self):
        write, link, unlink = os.write, os.link, os.unlink

        def partial(fd, data):
            if b"[reconfigure]" in bytes(data):
                write(fd, bytes(data)[:len(data) // 2])
                raise OSError(28, "No space left on device")
            return write(fd, data)

        def no_link(src, dst):
            raise OSError(5, "Input/output error")

        def no_unlink(path, *args, **kwargs):
            if pathlib.Path(path).name.startswith(".reconfigure-rel-a-"):
                raise OSError(13, "Permission denied")
            return unlink(path, *args, **kwargs)
        cases = {"partial-write": [(rel.os, "write", partial)], "link": [(rel.os, "link", no_link)],
                 "link-and-cleanup": [(rel.os, "link", no_link), (rel.os, "unlink", no_unlink)]}
        for case, patches in cases.items():
            with self.subTest(case=case):
                out = self.installed()
                ledger = (out / rel.LEDGER).read_text()
                with contextlib.ExitStack() as stack:
                    for owner, name, value in patches:
                        stack.enter_context(mock.patch.object(owner, name, value))
                    message = self.reconfigure_failed(out, "RECONFIGURED_UNRECORDED")
                self.assertEqual(self.published(out), [])
                self.assertEqual((out / rel.LEDGER).read_text(), ledger)
                self.assertIn("no receipt published", message)
                if case == "link-and-cleanup":
                    self.assertEqual(len(self.temporaries(out)), 1)
                    self.assertIn("left", message)
                else:
                    self.assertEqual(self.temporaries(out), [])
                shutil.rmtree(out)
        self.assertIs(os.link, link)

    def test_reconfigure_an_unsynced_receipt_directory_is_reported_and_the_ledger_not_written(self):
        out = self.installed()
        ledger = (out / rel.LEDGER).read_text()
        with mock.patch.object(rel, "fsync_directory", side_effect=OSError(5, "Input/output error")):
            message = self.reconfigure_failed(out, "RECONFIGURED_RECEIPT_UNSYNCED")
        self.assertEqual(len(self.published(out)), 1)
        self.assertIn(f"receipt={self.published(out)[0]} published", message)
        self.assertEqual((out / rel.LEDGER).read_text(), ledger)

    def test_reconfigure_ledger_failures_are_publication_uncertain(self):
        write, fsync = os.write, os.fsync

        def partial(fd, data):
            if b" reconfigured rel-a receipt=" in bytes(data):
                write(fd, bytes(data)[:len(data) // 2])
                raise OSError(28, "No space left on device")
            return write(fd, data)

        def no_ledger_fsync(fd):
            if os.readlink(f"/proc/self/fd/{fd}").endswith("/" + rel.LEDGER):
                raise OSError(5, "Input/output error")
            return fsync(fd)
        for case, (name, value) in {"partial-write": ("write", partial), "fsync": ("fsync", no_ledger_fsync)}.items():
            with self.subTest(case=case):
                out = self.installed()
                ledger = (out / rel.LEDGER).read_text()
                with mock.patch.object(rel.os, name, value):
                    message = self.reconfigure_failed(out, "RECONFIGURED_PUBLICATION_UNCERTAIN")
                self.assertEqual(len(self.published(out)), 1)
                self.assertIn("may hold none, part or all of the line", message)
                written = (out / rel.LEDGER).read_text()[len(ledger):]
                expected = f"reconfigured rel-a receipt={self.published(out)[0].name}\n"
                if case == "partial-write":
                    self.assertTrue(written and not written.endswith("\n"), written)
                else:
                    self.assertTrue(written.endswith(" " + expected), written)
                shutil.rmtree(out)

    def test_reconfigure_a_reporting_failure_after_publication_is_still_success(self):
        out = self.installed()

        def broken(line):
            if line.startswith("RELEASE RECONFIGURED "):
                raise BrokenPipeError(32, "Broken pipe")
        self.reconfigure(out, log=broken)
        self.assertEqual(rel.Target(out).ledger_lines()[-1].split()[1:3], ["reconfigured", "rel-a"])
        self.assertEqual(len(self.published(out)), 1)
        self.assertEqual(list((out / "receipts").glob("reconfigure-failed-*")), [])

    def test_reconfigure_command_line_needs_release_and_kernel(self):
        run = subprocess.run([sys.executable, "-I", "-B", "-X", f"pycache_prefix={sys.pycache_prefix or ''}", str(here / "release.py"), "reconfigure", "--target", "x",
                              "--etc", "y"], capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        self.assertIn("reconfigure needs --release", run.stderr)

    # operator_image.py reconfigure: only the QEMU process and the kernel
    # build are simulated; its preflight, guard and MANIFEST code are real.

    @contextlib.contextmanager
    def oi_guest(self):
        """durable-boot.sh as a simulated importer applying the ISO's stream
        to the fake disk; each boot records the guard state it ran under."""
        def run(argv, **kwargs):
            iso, image, serial = argv[1], argv[2], argv[3]
            desc = json.loads(pathlib.Path(iso).read_bytes()[len(ISO_MAGIC):])
            entries = parse_stream(bytes.fromhex(desc["input"]))
            self.boots.append({"step": desc["step"], "entries": entries,
                               "guard": guard.parse(fake_tree(image)[guard.PATH])})
            ok, text = apply_importer(image, desc["step"], entries)
            pathlib.Path(serial).write_bytes(console(text if ok else f"FIXTURE IMPORT FAILED {text}"))
            return subprocess.CompletedProcess(argv, 0, stdout="3\n" if ok else "7\n")
        rel.oi.kernel_iso = fake_kernel_iso
        # The fake disk has no real region: plan records without capacity
        # (RealImagePreflight runs the real inspection).
        inspect = lambda image, plan: (rel.oi.em.import_plan_records(plan), {})  # noqa: E731
        with mock.patch.object(rel.oi.subprocess, "run", run), \
                mock.patch.object(rel.oi.em, "inspect_import_plan", inspect):
            yield

    def platform(self):
        platform = self.work / "platform"
        platform.mkdir(exist_ok=True)
        (platform / "fixture-import.elf").write_bytes(b"the platform's importer\n")
        return platform

    def build_output(self, manifest="platform p\nkernel k\nrelease rel-a\niso i\n"):
        out = self.work / "image-out"
        out.mkdir()
        write_disk(out / rel.IMAGE, disk_files(self.A, selected="rel-a"))
        if manifest is not None:
            (out / "MANIFEST").write_text(manifest)
        return out

    def oi_refused(self, out, text):
        before = snapshot(out)
        with self.oi_guest(), self.assertRaises(rel.oi.Failed) as caught:
            rel.oi.reconfigure(self.KA, out, self.etc_dir(), root=self.platform(), log=lambda line: None)
        self.assertIn(text, str(caught.exception))
        self.assertEqual(self.boots, [])
        self.assertEqual(snapshot(out), before)
        return str(caught.exception)

    def test_operator_image_reconfigure_updates_only_the_manifest(self):
        old = hashlib.sha256(b"address 10.0.2.15\n").hexdigest()
        out = self.build_output(f"platform p\nkernel k\nrelease rel-a\niso i\nfile {'0' * 64} /bin/x\n"
                                f"file {old} /etc/network.conf\n")
        with self.oi_guest():
            rel.oi.reconfigure(self.KA, out, self.etc_dir(), root=self.platform(), log=lambda line: None)
        new = hashlib.sha256(b"address 10.0.2.20\n").hexdigest()
        self.assertEqual((out / "MANIFEST").read_text(), f"platform p\nkernel k\nrelease rel-a\niso i\n"
                         f"file {'0' * 64} /bin/x\nfile {new} /etc/network.conf\n")
        self.assertEqual([(b["step"], b["guard"]) for b in self.boots], [(4, "dirty")])
        self.assertEqual(guard.parse(fake_tree(out / rel.IMAGE)[guard.PATH]), "fresh")
        # The only addition is the recovery lock every image writer takes
        # (storage_fence_resume.recovery_lock): one empty file, never unlinked.
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["MANIFEST", rel.IMAGE, "recovery"])
        self.assertEqual(sorted(p.name for p in (out / "recovery").iterdir()), ["lock"])
        self.assertTrue((out / "recovery" / "lock").is_file())
        self.assertEqual((out / "recovery" / "lock").stat().st_size, 0)

    def test_operator_image_reconfigure_refuses_recovery_pending_on_a_manifest_target(self):
        # A build-operator-image.sh output (MANIFEST, no TARGET/RELEASES)
        # with an authorization record on its disk: operator_image.py's own
        # recovery context refuses before any boot, and nothing changes.
        out = self.build_output()
        rel.storage_fence_resume.ensure_lock(out)
        self.with_slot(out, self.RECORD)
        self.oi_refused(out, "recovery_pending: authorization " + "a" * 32)

    def test_operator_image_reconfigure_refuses_tool_busy_on_a_manifest_target(self):
        out = self.build_output()
        lock = rel.storage_fence_resume.ensure_lock(out)
        holder = subprocess.Popen([sys.executable, "-I", "-c",
                                   "import fcntl, os, sys, time\nfd = os.open(sys.argv[1], os.O_RDWR)\n"
                                   "fcntl.flock(fd, fcntl.LOCK_EX)\nprint('held', flush=True)\ntime.sleep(300)\n",
                                   str(lock)], stdout=subprocess.PIPE)
        self.assertEqual(holder.stdout.readline(), b"held\n")
        try:
            self.oi_refused(out, "tool_busy")
        finally:
            holder.kill()
            holder.wait()

    def test_operator_image_reconfigure_refuses_a_release_operator_directory(self):
        for marks in ((rel.TARGET,), (rel.LEDGER,), (rel.TARGET, rel.LEDGER)):
            with self.subTest(marks=marks):
                out = self.build_output(manifest=None)
                for name in marks:
                    (out / name).write_text("x\n")
                message = self.oi_refused(out, "scripts/release.py reconfigure --release <the directory of release rel-a>")
                self.assertIn("nothing was written", message)
                shutil.rmtree(out)

    def test_operator_image_reconfigure_refuses_a_directory_with_no_record(self):
        self.oi_refused(self.build_output(manifest=None), "nothing would record the change")

    def test_operator_image_reconfigure_refuses_manifest_destinations_before_writing(self):
        for case in ("new-file", "new-directory", "malformed"):
            with self.subTest(case=case):
                out = self.build_output("platform p\nfile onlyonefield\n" if case == "malformed" else
                                        "platform p\n")
                if case == "new-file":
                    (out / "MANIFEST.new").write_text("left behind\n")
                elif case == "new-directory":
                    (out / "MANIFEST.new").mkdir()
                self.oi_refused(out, "MANIFEST")
                shutil.rmtree(out)

    def test_operator_image_reconfigure_kernel_build_failure_writes_nothing(self):
        out = self.build_output()

        def failing(*args, **kwargs):
            raise subprocess.CalledProcessError(2, ["make"])
        with self.oi_guest():
            rel.oi.kernel_iso = failing
            before = sha(out / rel.IMAGE)
            with self.assertRaises(rel.oi.Failed) as caught:
                rel.oi.reconfigure(self.KA, out, self.etc_dir(), root=self.platform(), log=lambda line: None)
        self.assertIn("kernel ISO build failed", str(caught.exception))
        self.assertEqual(sha(out / rel.IMAGE), before)
        self.assertEqual(guard.parse(fake_tree(out / rel.IMAGE)[guard.PATH]), "fresh")


class RealImagePreflight(unittest.TestCase):
    """Refusals against a real ABSD filesystem image (scripts/absd_fs.py
    reads it; storage_fence_host's real guard transaction would write its
    sector), before any guard write. Two things are substituted: the
    device-layout lookup (the image is the filesystem region alone) and
    the recovery boundary (storage_fence_resume.mutation, a null context:
    on these sub-layout images it would refuse image_size first). Any
    kernel build or boot is a tripwire. RealBoundaryPreflight repeats the
    capacity and replacement-path refusals with neither substituted."""

    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp(prefix="test-release-real-"))
        self.addCleanup(shutil.rmtree, self.work, True)
        for owner, name, value in ((rel.absd_fs, "fs_region",
                                    lambda path, _: absd_fs.Region(path, 0, pathlib.Path(path).stat().st_size // 512)),
                                   (rel.oi, "kernel_iso", tripwire), (rel, "run_boot", tripwire),
                                   # These images are sub-layout (256 KiB): the recovery boundary's
                                   # refuse_pending reads the guard slot and refuses image_size before
                                   # the preflight under test (import_capacity, replacement paths) is
                                   # reached. Substituted as fake_guard_mutation substitutes the host
                                   # guard; the boundary has its own tests (M1, M2, test_storage_fence_resume).
                                   (rel.storage_fence_resume, "mutation",
                                    lambda *args, **kwargs: contextlib.nullcontext())):
            patcher = mock.patch.object(owner, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.A = rel.Release(make_release(self.work / "rel-a", "rel-a", COMMIT_A))
        self.KA = make_kernel(self.work / "kernel-a", COMMIT_A)
        self.files = {rr.SELECTED: rr.selected_bytes("rel-a"),
                      "/releases/rel-a/release": (self.A.path / "release").read_bytes(),
                      "/releases/rel-a/bin/release": b"release command of rel-a\n",
                      "/etc/network.conf": b"address 10.0.2.15\n"}

    def target(self, files):
        out = self.work / "out"
        out.mkdir()
        real_image(out / rel.IMAGE, files)
        (out / rel.TARGET).write_text("lab-1\n")
        (out / rel.LEDGER).write_text("2026-10-24T00:00:00Z installed rel-a\n")
        (out / "receipts").mkdir()
        return out

    def etc(self, data):
        etc = self.work / "etc"
        etc.mkdir()
        (etc / "network.conf").write_bytes(data)
        return etc

    def refused(self, out, etc, text):
        image = (out / rel.IMAGE).read_bytes()
        self.assertEqual(guard.parse(rel.oi.tree(out / rel.IMAGE)[guard.PATH]), "clean")
        with self.assertRaises(rel.ReconfigureFailed) as caught:
            rel.cmd_reconfigure(Args(release=str(self.A.path), kernel=str(self.KA), target=str(out), etc=str(etc)),
                                log=lambda line: None)
        self.assertIn(text, str(caught.exception))
        self.assertEqual(caught.exception.state, "REFUSED")
        self.assertEqual((out / rel.IMAGE).read_bytes(), image)

    def test_release_reconfigure_refuses_capacity_before_the_guard(self):
        out = self.target(self.files)
        self.refused(out, self.etc(b"#" * (200 * 1024)), "import_capacity")

    def test_release_reconfigure_refuses_a_directory_at_a_replacement_path(self):
        files = dict(self.files)
        del files["/etc/network.conf"]
        files["/etc/network.conf/"] = b""
        out = self.target(files)
        self.refused(out, self.etc(b"address 10.0.2.20\n"), "/etc/network.conf is a directory")

    def test_operator_image_reconfigure_refuses_capacity_before_the_guard(self):
        out = self.work / "image-out"
        out.mkdir()
        real_image(out / rel.IMAGE, self.files)
        (out / "MANIFEST").write_text("platform p\n")
        image = (out / rel.IMAGE).read_bytes()
        platform = self.work / "platform"
        platform.mkdir()
        (platform / "fixture-import.elf").write_bytes(b"importer\n")
        with self.assertRaises(rel.oi.Failed) as caught:
            rel.oi.reconfigure(self.KA, out, self.etc(b"#" * (200 * 1024)), root=platform, log=lambda line: None)
        self.assertIn("import_capacity", str(caught.exception))
        self.assertEqual((out / rel.IMAGE).read_bytes(), image)
        self.assertEqual((out / "MANIFEST").read_text(), "platform p\n")

class RealBoundaryPreflight(unittest.TestCase):
    """The capacity and replacement-path refusals of both reconfigure
    commands on a full-layout image (test_storage_fence_resume.build_image:
    the v3 layout, the real device-layout lookup) with the REAL recovery
    boundary: storage_fence_resume.mutation, its lock, OFD probe and
    pending check, as composed. Only the kernel build and boots are
    tripwires. The control shows the boundary is live and first."""

    RECORD = ReleaseToolRefusals.RECORD

    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp(prefix="test-release-boundary-"))
        self.addCleanup(shutil.rmtree, self.work, True)
        for owner, name, value in ((rel.oi, "kernel_iso", tripwire), (rel, "run_boot", tripwire)):
            patcher = mock.patch.object(owner, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        spec = importlib.util.spec_from_file_location("resume_tests_for_boundary", here / "test_storage_fence_resume.py")
        self.resume = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.resume)
        self.A = rel.Release(make_release(self.work / "rel-a", "rel-a", COMMIT_A))
        self.KA = make_kernel(self.work / "kernel-a", COMMIT_A)

    def files(self, *, full=False, slot=guard.RESUME_NONE, directory_at_network=False):
        files = self.resume.machine_files("ended", guard_state="clean", slot=slot)
        files.update({rr.SELECTED: rr.selected_bytes("rel-a"),
                      "/releases/rel-a/release": (self.A.path / "release").read_bytes(),
                      "/releases/rel-a/bin/release": b"release command of rel-a\n"})
        if directory_at_network:
            del files["/etc/network.conf"]
            files["/etc/network.conf/inner"] = b"x\n"
        if full:
            # Leave fewer free blocks than the 200 KiB replacement needs.
            geo = absd_fs.geometry(self.resume.FS_SECTORS)
            used = sum(-(-len(data) // absd_fs.BLOCK) for data in files.values())
            files["/home/operator/filler"] = bytes((geo["data_blocks"] - used - 8) * absd_fs.BLOCK)
        return files

    def release_target(self, **kw):
        out = self.work / "out"
        out.mkdir()
        self.resume.build_image(out / rel.IMAGE, self.files(**kw))
        (out / rel.TARGET).write_text("lab-1\n")
        (out / rel.LEDGER).write_text("2026-10-24T00:00:00Z installed rel-a\n")
        (out / "receipts").mkdir()
        rel.storage_fence_resume.ensure_lock(out)
        return out

    def manifest_target(self, **kw):
        out = self.work / "image-out"
        out.mkdir()
        self.resume.build_image(out / rel.IMAGE, self.files(**kw))
        (out / "MANIFEST").write_text("platform p\n")
        rel.storage_fence_resume.ensure_lock(out)
        return out

    def etc(self, data):
        etc = self.work / "etc"
        etc.mkdir()
        (etc / "network.conf").write_bytes(data)
        return etc

    def release_refused(self, out, etc, text):
        image = sha(out / rel.IMAGE)
        with self.assertRaises(rel.ReconfigureFailed) as caught:
            rel.cmd_reconfigure(Args(release=str(self.A.path), kernel=str(self.KA), target=str(out), etc=str(etc)),
                                log=lambda line: None)
        self.assertIn(text, str(caught.exception))
        self.assertEqual(caught.exception.state, "REFUSED")
        self.assertEqual(sha(out / rel.IMAGE), image)
        self.assertEqual(guard.parse(rel.oi.tree(out / rel.IMAGE)[guard.PATH]), "clean")
        return str(caught.exception)

    def oi_refused(self, out, etc, text):
        before = snapshot(out)
        platform = self.work / "platform"
        platform.mkdir(exist_ok=True)
        (platform / "fixture-import.elf").write_bytes(b"importer\n")
        with self.assertRaises(rel.oi.Failed) as caught:
            rel.oi.reconfigure(self.KA, out, etc, root=platform, log=lambda line: None)
        self.assertIn(text, str(caught.exception))
        self.assertEqual(snapshot(out), before)

    def test_release_reconfigure_refuses_capacity_inside_the_real_boundary(self):
        self.release_refused(self.release_target(full=True), self.etc(b"#" * (200 * 1024)), "import_capacity")

    def test_release_reconfigure_refuses_a_directory_at_a_replacement_path_inside_the_real_boundary(self):
        self.release_refused(self.release_target(directory_at_network=True), self.etc(b"address 10.0.2.20\n"),
                             "/etc/network.conf is a directory")

    def test_operator_image_reconfigure_refuses_capacity_inside_the_real_boundary(self):
        self.oi_refused(self.manifest_target(full=True), self.etc(b"#" * (200 * 1024)), "import_capacity")

    def test_operator_image_reconfigure_refuses_a_directory_at_a_replacement_path_inside_the_real_boundary(self):
        self.oi_refused(self.manifest_target(directory_at_network=True), self.etc(b"address 10.0.2.20\n"),
                        "/etc/network.conf is a directory")

    def old_disk(self, **kw):
        """A full-layout disk whose v3 descriptor and filesystem were made
        for 64 MiB, as every operator image before coordination record #28."""
        old = 64 << 20
        sectors = old // 512
        with mock.patch.multiple(self.resume, DEVICE_SECTORS=sectors, FS_FIRST=sectors // 2,
                                 FS_SECTORS=sectors - sectors // 2), \
                mock.patch.object(self.resume.sfr, "IMAGE_BYTES", old):
            out = self.release_target(**kw)
        self.assertEqual((out / rel.IMAGE).stat().st_size, old)
        self.assertEqual(struct.unpack_from("<Q", (out / rel.IMAGE).read_bytes()[:512], 16)[0], sectors)
        return out

    def test_a_real_64_mib_disk_is_read_backed_up_and_restored_at_its_own_geometry(self):
        out = self.old_disk()
        image = out / rel.IMAGE
        before = sha(image)
        target = rel.Target(out)
        tree = target.tree()
        self.assertEqual(target.fs_format(), 2)
        self.assertEqual(target.selected(tree), "rel-a")
        self.assertEqual(tree["/releases/rel-a/bin/release"], b"release command of rel-a\n")
        self.assertIn("/releases/rel-a/release", rel.oi.namespace(image))
        rel.storage_fence_resume.read_disk(image)
        lines = []
        rel.cmd_status(Args(target=str(out)), log=lines.append)
        self.assertIn("selected=rel-a", lines[0])
        # The selected release's boot image, which backup copies and restore needs.
        iso = target.release_iso("rel-a")
        iso.parent.mkdir(parents=True, exist_ok=True)
        iso.write_bytes(b"boot image of rel-a\n")
        backup = self.work / "backup"
        rel.cmd_backup(Args(target=str(out), backup=str(backup)), log=lambda line: None)
        self.assertEqual(sha(backup / rel.IMAGE), before)
        _, _, selected = rel.validate_backup(backup)
        self.assertEqual(selected, "rel-a")
        restored = self.work / "restored"
        rel.cmd_restore(Args(target=str(restored), backup=str(backup), replace=False, clone=False, release=None,
                             kernel=None, key=None, port=2222, target_identity=None), log=lambda line: None)
        self.assertEqual((restored / rel.IMAGE).stat().st_size, 64 << 20)
        self.assertEqual(sha(restored / rel.IMAGE), before)
        self.assertEqual(sha(image), before)

    def test_a_new_disk_is_read_at_the_creation_size(self):
        out = self.release_target()
        self.assertEqual((out / rel.IMAGE).stat().st_size, rel.oi.IMAGE_BYTES)
        self.assertEqual(rel.Target(out).selected(), "rel-a")

    def test_a_clone_of_a_64_mib_backup_is_refused_before_the_destination_changes(self):
        out = self.old_disk()
        target = rel.Target(out)
        iso = target.release_iso("rel-a")
        iso.parent.mkdir(parents=True, exist_ok=True)
        iso.write_bytes(b"boot image of rel-a\n")
        backup = self.work / "backup"
        rel.cmd_backup(Args(target=str(out), backup=str(backup)), log=lambda line: None)
        before = sha(backup / rel.IMAGE)
        clone = self.work / "clone"
        with mock.patch.object(rel, "clone_identity", side_effect=AssertionError("clone boot reached")):
            with self.assertRaisesRegex(rel.Failed, r"image_size: the backup image is 67108864 bytes; --clone"):
                rel.cmd_restore(Args(target=str(clone), backup=str(backup), replace=False, clone=True,
                                     release=str(self.A.path), kernel=str(self.KA), key=str(self.work / "key"),
                                     port=2222, target_identity="lab-2"), log=lambda line: None)
        self.assertFalse(clone.exists())
        self.assertEqual(sha(backup / rel.IMAGE), before)

    def test_mismatched_or_damaged_geometry_still_fails_closed(self):
        out = self.old_disk()
        image = out / rel.IMAGE
        pristine = image.read_bytes()
        sizes = {"padded to the creation size": rel.oi.IMAGE_BYTES,
                 "truncated by a MiB": (64 << 20) - (1 << 20),
                 "not whole sectors": (64 << 20) + 100}
        for name, size in sizes.items():
            with self.subTest(case=name):
                image.write_bytes(pristine)
                with image.open("r+b") as handle:
                    handle.truncate(size)
                damaged = sha(image)
                with self.assertRaises((rel.Failed, ValueError, absd_fs.Refused)):
                    rel.Target(out).tree()
                with self.assertRaises((ValueError, absd_fs.Refused)):
                    rel.oi.namespace(image)
                self.assertEqual(sha(image), damaged)
        # A wrong superblock: every ABSDFSS magic in the filesystem region's
        # two superblock slots overwritten.
        region = absd_fs.fs_region(self.old_disk_copy(pristine), (64 << 20) // 512)
        data = bytearray(pristine)
        first = region.first * 512
        hits = 0
        for offset in range(first, first + 4 * absd_fs.BLOCK, 8):
            if data[offset:offset + 7] == b"ABSDFSS":
                data[offset:offset + 8] = b"NOTABSD!"
                hits += 1
        self.assertGreater(hits, 0)
        image.write_bytes(bytes(data))
        damaged = sha(image)
        with self.assertRaises((rel.Failed, ValueError, absd_fs.Refused)):
            rel.Target(out).tree()
        self.assertEqual(sha(image), damaged)

    def old_disk_copy(self, data):
        path = self.work / "old-copy.img"
        path.write_bytes(data)
        return path

    def test_stage_on_a_real_64_mib_disk_is_refused_and_leaves_the_disk_unchanged(self):
        # coordination record #28: a full-layout disk whose v3 descriptor was written
        # for 64 MiB, as every operator image before coordination record #28. The
        # REAL recovery boundary and stage path refuse it, and the disk's
        # bytes are the same before and after (sha256).
        old = 64 << 20
        out = self.old_disk()
        image = out / rel.IMAGE
        before = sha(image)
        B = rel.Release(make_release(self.work / "rel-b", "rel-b", COMMIT_B))
        KB = make_kernel(self.work / "kernel-b", COMMIT_B)
        with self.assertRaises(rel.StageFailed) as caught:
            rel.cmd_stage(Args(release=str(B.path), kernel=str(KB), target=str(out)), log=lambda line: None)
        self.assertEqual(caught.exception.state, "REFUSED")
        text = str(caught.exception)
        self.assertIn("image_size", text)
        self.assertIn("67108864 byte (64 MiB) disk", text)
        self.assertRegex(text, r"(would need \d+ blocks with \d+ free|needs \d+ blocks, has \d+ free)")
        self.assertIn("Nothing was written", text)
        self.assertEqual(sha(image), before)
        self.assertEqual(image.stat().st_size, old)

    def test_control_the_real_boundary_refuses_first(self):
        # The same full disk with an authorization record in its slot: the
        # boundary, not the capacity preflight, refuses, for both commands.
        record = guard.encode_resume(self.RECORD)
        self.release_refused(self.release_target(full=True, slot=record), self.etc(b"#" * (200 * 1024)),
                             "recovery_pending: authorization " + "a" * 32)
        self.oi_refused(self.manifest_target(full=True, slot=record), self.work / "etc",
                        "recovery_pending: authorization " + "a" * 32)


def snapshot(directory):
    """Every file under `directory` and its digest."""
    return {str(p.relative_to(directory)): sha(p) for p in sorted(pathlib.Path(directory).rglob("*")) if p.is_file()}


def readable_snapshot(directory):
    """snapshot, naming a file this user cannot read instead of failing."""
    out = {}
    for p in sorted(pathlib.Path(directory).rglob("*")):
        if p.is_file():
            try:
                out[str(p.relative_to(directory))] = sha(p)
            except PermissionError:
                out[str(p.relative_to(directory))] = "unreadable"
    return out


def read_toml_digest(backup):
    return rel.read_toml_flat(backup / "backup.toml")["disk"]["image_sha256"]


def runbook_commands():
    """Every `python3 -I scripts/release.py ...` command in the runbook,
    in code blocks and inline code."""
    text = RUNBOOK.read_text()
    found = re.findall(r"^python3 -I scripts/release\.py [^\n`]+$", text, re.M)
    found += re.findall(r"`(python3 -I scripts/release\.py [^`]+)`", text)
    return found


class OperatorImageCapacity(unittest.TestCase):
    """coordination record #28: the operator image must stage a successor release of
    the canonical composition (with /bin/https-document) beside the installed
    one. Figures from RC2 run rc2-run-1, resume/s1: the installed release used
    3954 of the 64 MiB image's 8142 data blocks, and staging the next needed a
    peak of 4448 more."""

    USED, PEAK = 8142 - 4188, 4448

    @staticmethod
    def data_blocks(image_bytes):
        sectors = image_bytes // 512
        return absd_fs.geometry(sectors - sectors // 2)["data_blocks"]

    def holds(self, image_bytes, growth):
        used, peak = -(-self.USED * growth // 4), -(-self.PEAK * growth // 4)
        return self.data_blocks(image_bytes) - used >= peak + -(-peak // 4)

    def test_floor_holds_the_successor_with_its_quarter_of_headroom(self):
        # 128 MiB (owner, 2026-11-02) holds today's successor with the quarter
        # check_successor_headroom requires, and still does after the
        # composition grows by half; the guard catches growth beyond that.
        self.assertTrue(self.holds(rel.oi.IMAGE_BYTES, 4))
        self.assertTrue(self.holds(rel.oi.IMAGE_BYTES, 6))
        self.assertFalse(self.holds(rel.oi.IMAGE_BYTES, 8))
        # The old size refused the successor outright (rc2-run-1); 72 MiB
        # would hold it, but not its quarter.
        self.assertLess(self.data_blocks(64 << 20) - self.USED, self.PEAK)
        self.assertFalse(self.holds(72 << 20, 4))

    def test_resume_layout_checks_the_same_size(self):
        self.assertEqual(rel.oi.storage_fence_resume.IMAGE_BYTES, rel.oi.IMAGE_BYTES)
        self.assertEqual(rel.oi.DEVICE_SECTORS * 512, rel.oi.IMAGE_BYTES)

    def headroom(self, free, peak):
        with mock.patch.object(rel.oi, "tree", return_value={}), \
                mock.patch.object(rel.oi.em, "check_import_capacity",
                                  return_value={"peak_extra_blocks": peak, "free_blocks": free, "data_blocks": 1}) as check:
            return rel.oi.check_successor_headroom(pathlib.Path("/nonexistent"), [("/bin/a", b"x")], "dev"), check

    def test_build_guard_refuses_a_successor_without_a_quarter_to_spare(self):
        self.assertEqual(self.headroom(1250, 1000)[0]["free_blocks"], 1250)
        with self.assertRaisesRegex(rel.oi.Failed, r"successor_headroom peak_extra_blocks=1000 free_blocks=1249 needs 1250"):
            self.headroom(1249, 1000)

    def test_build_guard_lays_the_successor_out_under_another_id_with_the_slot(self):
        captured = []
        with mock.patch.object(rel.oi, "tree", return_value={}), \
                mock.patch.object(rel.oi.em, "import_plan", side_effect=lambda files: captured.extend(files) or []), \
                mock.patch.object(rel.oi.em, "check_import_capacity",
                                  return_value={"peak_extra_blocks": 4, "free_blocks": 5, "data_blocks": 9}):
            rel.oi.check_successor_headroom(pathlib.Path("/nonexistent"), [("/bin/a", b"x")], "dev")
        paths = [path for path, _ in captured]
        probe = rr.tree_root(rel.oi.SUCCESSOR_PROBE_ID)
        self.assertIn(probe + "/bin/a", paths)
        self.assertIn(probe + "/release", paths)
        self.assertIn(rel.oi.ssh_absd.storage_fence_state.RESUME_PATH, paths)
        self.assertNotIn("/absd/selected", paths)

    def test_build_guard_plans_the_files_in_stage_order(self):
        # Import peaks depend on order (Codex #28 r1): with these sizes the
        # list order peaks at 3841 blocks and stage's sorted order at 4865.
        # The guard must plan what stage plans, peak for peak.
        mib = 1024 * 1024
        logical = [("/bin/uname", b"u" * (7 * mib)), ("/bin/mkdir", b"m" * (3 * mib)), ("/bin/cp", b"c" * (3 * mib))]
        captured = []
        with mock.patch.object(rel.oi, "tree", return_value={rel.oi.ssh_absd.storage_fence_state.RESUME_PATH: b""}), \
                mock.patch.object(rel.oi.em, "check_import_capacity",
                                  side_effect=lambda image, plan: captured.append(plan)
                                  or {"peak_extra_blocks": 1, "free_blocks": 2, "data_blocks": 3}):
            rel.oi.check_successor_headroom(pathlib.Path("/nonexistent"), logical, "dev")
        probe = rel.oi.SUCCESSOR_PROBE_ID
        stage_order = rr.release_layout(sorted(logical), probe, select=False)
        peak = lambda plan: max(r["peak_extra_blocks"] for r in rel.oi.em.import_plan_records(plan))
        # Compared by digest and peak: a failing equality on 13 MiB plans
        # would spend minutes rendering the diff.
        digest = lambda plan: hashlib.sha256(repr(plan).encode()).hexdigest()
        self.assertTrue(digest(captured[0]) == digest(rel.oi.em.import_plan(stage_order)), "guard plan is not stage's plan")
        self.assertEqual(peak(captured[0]), peak(rel.oi.em.import_plan(stage_order)))
        self.assertNotEqual(peak(rel.oi.em.import_plan(rr.release_layout(logical, probe, select=False))),
                            peak(captured[0]))


def main():
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)
                               for case in (ReleaseToolRefusals, RealImagePreflight, RealBoundaryPreflight,
                                            OperatorImageCapacity))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if not result.wasSuccessful():
        sys.exit(1)
    print(f"RELEASE TOOL HOST TEST OK cases={result.testsRun}")


if __name__ == "__main__":
    main()
