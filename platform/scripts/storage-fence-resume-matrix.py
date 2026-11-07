#!/usr/bin/env python3
"""Operator-authorized writable recovery: the guest matrix (coordination record #63,
ACCEPTANCE-v5), driven by scripts/run-storage-fence-resume.sh.

Every guest case starts on its own freshly installed operator image
(release.py install under the lane's kernel), runs through the release tool
and the launcher exactly as the runbook's section 9a does, and prints its
ACCEPTANCE-v5 marker only when every predicate held. Evidence per case
goes under WORK/<case>/: serial logs, the host-reader tree before and
after every refused boot, Hm and the whole-image SHA-256 before and after,
F before and after, every file under OUT/recovery/ and OUT/receipts/, the
DURABLE accounting record, and one JSON; RESULT.md tabulates the markers
and the observed readiness times.

Predicates (ACCEPTANCE-v5): R (storage_fence_guest.require_refusal,
pinned), R-state, R-served-not-ready, A, Z, D(row), W.

  --host-only   the self-test: every predicate over the retained P14g
                refusal serial (fixtures/storage-fence/serials/) and
                synthetic serials; no QEMU. Prints
                `RESUME HOST-ONLY SELFTEST OK checks=<n>`.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import datetime
import tempfile
import time
import tomllib

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import storage_fence_guest as fence_guest  # noqa: E402
import storage_fence_resume as sfr  # noqa: E402
import storage_fence_state as guard  # noqa: E402
from served_ram import served_qemu  # noqa: E402

ROOT = here.parent
SERIALS = ROOT / "fixtures" / "storage-fence" / "serials"
RETAINED_REFUSAL = SERIALS / "p14g-refused-successor-ata.serial.log"
STATE_REASONS = ("resume_mismatch", "resume_corrupt", "corrupt", "lost", "uninitialized_ledger")
BOOT = b"ABSD KERNEL BOOT\n"
# Provisional readiness timeout (DESIGN-v5 4): the run records the observed
# times and RESULT.md proposes the figure the runbook should adopt.
READY_TIMEOUT_TCG = 180
READY_TIMEOUT_KVM = 60
GUEST_ORDER = ["p0", "p0c", "p0n", "r4a", "r2a", "r2b", "r2c", "r3a", "r3b", "r3c", "r1a", "r1b", "r4b", "r4d", "r4f",
               "l4", "l5", "l6", "l7", "m1", "m2", "m3", "b2", "b3", "b4", "b5", "b6", "b7", "l3", "s1", "s2"]


class CaseFailed(RuntimeError):
    pass


LISTENER = "SSH LISTENING (worker record)"


def _identity(path):
    try:
        info = os.stat(path)
    except FileNotFoundError:
        return None
    return (info.st_dev, info.st_ino)


def launch_console(proc, console):
    """The console of `proc`'s own boot: empty while `console` is still the
    file that was there before a launcher started (boot-operator.sh rotates
    it before QEMU starts), so an earlier boot's lines never count."""
    stale = getattr(proc, "stale_console", None)
    try:
        if stale is not None and _identity(console) == stale:
            return b""
        return console.read_bytes()
    except FileNotFoundError:
        return b""


def _comm(pid):
    try:
        with open(f"/proc/{pid}/comm") as handle:
            return handle.read()
    except OSError:
        return ""


# -- predicates -----------------------------------------------------------------

def boots(raw):
    return raw.split(BOOT)[1:]


def last_boot(raw):
    parts = boots(raw)
    if not parts:
        raise CaseFailed("no ABSD KERNEL BOOT in the console")
    return BOOT + parts[-1]


def accounting_zero(serial):
    if fence_guest.accounting(serial) != (0, 0, 0):
        raise CaseFailed("the refused boot issued a write, flush or error")


def require_state_refusal(raw, status, reason, image_before=None, image_after=None):
    """R-state: R's terminal checks with the named line exactly
    `RECOVERY STATE REFUSED reason=<r>`; never the fence line in its place."""
    if reason not in STATE_REASONS:
        raise CaseFailed(f"not a state reason: {reason}")
    serial = raw.decode(errors="replace")
    if status != "7" or serial.count("ABSD KERNEL BOOT\n") != 1:
        raise CaseFailed(f"state refusal needs one failed boot: status={status}")
    if not re.search(r"(?m)^STORAGE FENCE fence=none reason=not_declared$", serial):
        raise CaseFailed("missing exact kernel not-established reason")
    line = f"RECOVERY STATE REFUSED reason={reason}"
    if not re.search(rf"(?m)^{re.escape(line)}$", serial):
        raise CaseFailed(f"missing the exact state refusal {line!r}: " + serial[-1500:])
    if "RECOVERY WRITABLE REFUSED" in serial:
        raise CaseFailed("the fence line appeared in place of the state refusal")
    combined = serial + "\n" + fence_guest.captured_complete(raw)
    for word in ("FSD READY ", "SSH LISTENING", "MACHINE RECOVER RESET", "RECOVERY WRITABLE RESUMED"):
        if word in combined:
            raise CaseFailed(f"the refused boot printed {word!r}")
    accounting_zero(serial)
    if image_before is not None and image_before != image_after:
        raise CaseFailed("the refused boot changed the image")
    return line


def require_served_refusal(raw, status, previous="failed"):
    """R-served-not-ready / R(served): R with `previous`, init's exact
    SERVED RECOVERY REFUSED generation_not_ready and sshd's no_server."""
    line = fence_guest.require_refusal(raw, status, previous, "not_declared")
    serial, worker = raw.decode(errors="replace"), fence_guest.captured_complete(raw)
    if not re.search(rf"(?m)^{re.escape(fence_guest.INIT_REFUSED)}$", serial):
        raise CaseFailed("init did not refuse the not-ready generation by name")
    if not re.search(rf"(?m)^{re.escape(fence_guest.NO_SERVER)}$", worker):
        raise CaseFailed("sshd did not refuse for want of a server")
    for absent in ("SSH HOST KEY", "SSH RECOVERY ", "SSH NET ", "RECOVERY WRITABLE RESUMED"):
        if absent in worker + serial:
            raise CaseFailed(f"the refused successor printed {absent!r}")
    return line


def require_admission(raw, ident, previous, fs_seq=None):
    """A: exactly one RECOVERY WRITABLE RESUMED with the active record's id,
    then FSD RECOVERY (seq=m+1, previous=p), FSD STORAGE FENCE fence=none,
    RELEASE OK, FSD READY, the listener; the kernel fence line. Returns
    the parsed fields."""
    segment = last_boot(raw)
    serial = segment.decode(errors="replace")
    worker = fence_guest.captured_complete(segment)
    resumed = re.findall(rf"(?m)^RECOVERY WRITABLE RESUMED id={re.escape(ident)} previous=(\w+) fs_seq=(\d+) ledger_seq=(\d+)$", serial)
    if len(resumed) != 1:
        raise CaseFailed(f"expected exactly one RESUMED line for {ident}, found {len(resumed)}: " + serial[-1500:])
    found_previous, found_seq, ledger_seq = resumed[0]
    if found_previous != previous:
        raise CaseFailed(f"RESUMED names previous={found_previous}, expected {previous}")
    if fs_seq is not None and int(found_seq) != fs_seq:
        raise CaseFailed(f"RESUMED names fs_seq={found_seq}, expected {fs_seq}")
    recovery = re.search(r"(?m)^FSD RECOVERY seq=(\d+) streak=(\d+) previous=(\w+)$", serial)
    if recovery is None or int(recovery.group(1)) != int(ledger_seq) + 1 or recovery.group(3) != previous:
        raise CaseFailed(f"FSD RECOVERY does not follow the resumed ledger: {recovery and recovery.group(0)}")
    # The file server's own order (ssh/src/fsd_server.rs, unchanged by
    # this lane): RESUMED after consumption, then RELEASE OK (release
    # selection), FSD RECOVERY and FSD STORAGE FENCE, then FSD READY.
    order = ["RECOVERY WRITABLE RESUMED id=", "RELEASE OK release=", "FSD RECOVERY seq=", "FSD STORAGE FENCE fence=none ",
             "FSD READY "]
    positions = [serial.find(word) for word in order]
    if any(at < 0 for at in positions) or positions != sorted(positions):
        raise CaseFailed(f"admission lines missing or out of order: {positions}")
    if "SSH LISTENING" not in worker:
        raise CaseFailed("no listener record in the resumed boot")
    if not re.search(r"(?m)^STORAGE FENCE fence=none reason=not_declared$", serial):
        raise CaseFailed("missing the kernel fence line")
    if serial.count("RECOVERY WRITABLE RESUMED") != 1:
        raise CaseFailed("more than one RESUMED line in the boot")
    return {"previous": found_previous, "fs_seq": int(found_seq), "ledger_seq": int(ledger_seq),
            "streak": int(recovery.group(2))}


def require_refused_tool(run, reason, before, out=None, *, receipt=None, phase="prepare"):
    """Z: the tool refused by name, and (with `before` from snapshot(out),
    taken immediately before this one invocation) the slot bytes, Hm, F,
    the whole image and the files under OUT/recovery/ and OUT/receipts/
    are exactly as before. `receipt` names the operation (stage or
    reconfigure) whose own refusal receipt this invocation must add:
    exactly one, of this attempt, at `phase` (refusal_additions_problem).
    Without it, nothing may be added."""
    if run.returncode == 0:
        raise CaseFailed(f"the tool succeeded where {reason} was expected:\n{run.stdout}")
    if reason not in run.stderr + run.stdout:
        raise CaseFailed(f"the tool did not name {reason}:\n{run.stderr}\n{run.stdout}")
    if before is None:
        raise CaseFailed("Z needs the snapshot taken before the tool ran")
    if out is None:
        raise CaseFailed("require_refused_tool needs `out` to compare with `before`")
    after = snapshot(out, "after-refusal")
    for key in ("slot", "hm", "f", "image_sha256", "guard"):
        if after[key] != before[key]:
            raise CaseFailed(f"the refused tool changed {key}: {before[key]!r} -> {after[key]!r}")
    for name, digest in before["files"].items():
        if after["files"].get(name) != digest:
            raise CaseFailed(f"the refused tool changed or removed {name}")
    added = sorted(set(after["files"]) - set(before["files"]))
    problem = refusal_additions_problem(out, added, receipt, phase, reason, run.stderr + run.stdout)
    if problem is not None:
        raise CaseFailed(f"the refused tool's additions are not its documented refusal bookkeeping: {problem}")
    return run.stderr


# The operations whose refusal writes its own receipt, by its name and table.
REFUSAL_RECEIPT_OPERATIONS = ("stage", "reconfigure")


def refusal_additions_problem(out, added, operation, phase, reason, output):
    """None when `added` (paths under OUT, new since this invocation's own
    baseline) is exactly the documented bookkeeping of a refused
    `operation`: one `receipts/<operation>-failed-<attempt>-<time>.toml`
    whose `[<operation>]` table has that attempt, state REFUSED, `phase`,
    target_effects_possible false and the refusal `reason` in its error,
    and which the tool's own `output` names. With `operation` None nothing
    may be added. No intent, active or archive record, no other
    operation's receipt and no second receipt is ever permitted."""
    if operation is None:
        return f"added {', '.join(added)} (nothing may be added)" if added else None
    if operation not in REFUSAL_RECEIPT_OPERATIONS:
        raise ValueError(f"{operation} writes no refusal receipt")
    if len(added) != 1:
        return f"expected exactly one {operation} refusal receipt, found {added}"
    name = added[0]
    found = re.fullmatch(rf"receipts/{operation}-failed-([0-9a-f]{{32}})-[0-9TZ-]+\.toml", name)
    if found is None:
        return f"{name} is not a {operation} refusal receipt"
    try:
        section = toml(out / name).get(operation)
    except (OSError, ValueError) as error:
        return f"{name} does not parse: {error}"
    if not isinstance(section, dict):
        return f"{name} has no [{operation}] table"
    want = {"attempt": found.group(1), "state": "REFUSED", "phase": phase, "target_effects_possible": False}
    differ = {key: section.get(key) for key, value in want.items() if section.get(key) != value
              or (key == "target_effects_possible" and section.get(key) is not False)}
    if differ:
        return f"{name}: {differ} (want {want})"
    if reason and reason not in str(section.get("error", "")):
        return f"{name}: its error does not name {reason}"
    if pathlib.PurePosixPath(name).name not in output:
        return f"{name}: the tool's output does not name this receipt"
    return None


def require_row(out, row_name, console=None):
    """D(row): precheck and --status both report exactly the row name."""
    status = release(out, "recover", "--status")
    if status.returncode != 0:
        raise CaseFailed(f"--status failed:\n{status.stderr}")
    found = re.search(r"(?m)^state=(\S+) last=(.*) history=(\d+)", status.stdout)
    if found is None or found.group(1) != row_name:
        raise CaseFailed(f"--status reports {found and found.group(0)!r}, expected state={row_name}:\n{status.stdout}")
    precheck = subprocess.run([sys.executable, "-I", str(here / "storage_fence_resume.py"), "precheck", str(out)]
                              + (["--console", str(console)] if console else []), capture_output=True, text=True)
    match = re.search(r"(?m)^precheck: state=(\S+)", precheck.stdout)
    if match is None or match.group(1) != row_name:
        raise CaseFailed(f"precheck reports {match and match.group(0)!r}, expected {row_name}:\n{precheck.stdout}")
    return status.stdout


def observe_readiness(out, ident, timeout, launcher=None):
    """The timing evidence DESIGN-v5 4 asks for: the wall-clock seconds
    from the `launched` record to the first appearance of each of the
    three readiness records of `ident` in this launch's console (polled
    every 100 ms, so each figure is an upper bound within 0.1 s). Returns
    the dict; a boot end before readiness or the timeout is recorded, not
    asserted (W asserts)."""
    console = out / "console.log"
    active_path = out / "recovery" / sfr.ACTIVE
    deadline = time.monotonic() + timeout
    launch_epoch = None
    while time.monotonic() < deadline and launch_epoch is None:
        if active_path.is_file():
            active = toml(active_path)["active"]
            if active.get("state") == "launched" and active["id"] == ident:
                launch_epoch = float(active["launch_epoch"])
        time.sleep(0.1)
    # Both ends on one clock (time.time(), launch_epoch to the millisecond).
    # Each figure is the first poll that saw the line, so it is an upper
    # bound within the 0.1 s poll interval provided observation began
    # before the line appeared; `observer_start` (seconds after launch) is
    # recorded so a figure no greater than it is known to be that bound only.
    seen = {"resumed": None, "release_ok": None, "listener": None, "launched_epoch": launch_epoch, "ended": None,
            "observer_start": round(time.time() - (launch_epoch or time.time()), 3), "poll_seconds": 0.1}
    while time.monotonic() < deadline:
        raw = console.read_bytes() if console.exists() else b""
        segment = sfr.latest_boot(raw) if raw else None
        if segment is not None:
            stamp = round(time.time() - (launch_epoch or time.time()), 3)
            if seen["resumed"] is None and re.search(rb"(?m)^RECOVERY WRITABLE RESUMED id=" + ident.encode(), segment):
                seen["resumed"] = stamp
            if seen["release_ok"] is None and b"\nRELEASE OK release=" in segment:
                seen["release_ok"] = stamp
            if seen["listener"] is None and sfr.listener_position(segment) is not None:
                seen["listener"] = stamp
            word, line = sfr.readiness(segment, ident)
            if word == "ended":
                seen["ended"] = line
                break
            if all(seen[k] is not None for k in ("resumed", "release_ok", "listener")):
                break
        if launcher is not None and launcher.poll() is not None:
            seen["ended"] = f"launcher exited {launcher.returncode}"
            break
        time.sleep(0.1)
    return seen


# -- helpers -----------------------------------------------------------------------

def toml(path):
    return tomllib.loads(pathlib.Path(path).read_text())


def sha256_file(path):
    with open(path, "rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


SNAPSHOTS = {}


def snapshot(out, label=None):
    """Everything Z and D compare: slot bytes, Hm, F, the guard, the whole
    image, recovery/ and receipts/. An image the host reader refuses (R3)
    or a directory without an image (M3) keeps what can be compared: the
    whole-image digest (or its absence) and the record files.

    Every snapshot is also retained as a primary artifact (ACCEPTANCE-v5
    evidence): OUT/../snapshots/NNN-<caller>-<label>.json with these values
    and the host reader's tree (every file's path, length and SHA-256),
    numbered in the order taken, so each before/after pair is on disk."""
    image = out / sfr.IMAGE
    slot = hm = guard_state = f = digest = None
    tree = None
    if image.is_file():
        digest = sha256_file(image)
        f = list(sfr.identity_of(image) or ())
        try:
            disk = sfr.read_disk(image)
        except sfr.Refused:
            disk = None
        if disk is not None and disk["slot"] is not None and disk["slot"].get("shape") == "ok":
            fd = os.open(image, os.O_RDONLY)
            try:
                hm = sfr.masked_hash(fd, disk["slot"]["offset"])
            finally:
                os.close(fd)
            slot = disk["slot"]["bytes"].hex()
        guard_state = disk["guard"] if disk is not None else None
        if disk is not None:
            tree = {"seq": disk.get("seq"), "files": {path: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                                                      for path, data in sorted(disk["files"].items())}}
        else:
            tree = "host_reader_refused"
    files = {}
    for directory in ("recovery", "receipts"):
        for path in sorted((out / directory).rglob("*")):
            if path.is_file():
                files[str(path.relative_to(out))] = sha256_file(path)
    taken = {"slot": slot, "hm": hm, "f": f, "image_sha256": digest, "files": files, "guard": guard_state}
    retain_snapshot(out, label, dict(taken, host_reader_tree=tree))
    return taken


def snapshot_image(image, directory, label):
    """A retained snapshot of an image outside an operator directory (an
    absd-try machine's disk.img): whole-image SHA-256, F, guard, slot, Hm
    and the host reader's tree, written beside the case's other snapshots;
    returns the compared values."""
    image = pathlib.Path(image)
    view = {"image": str(image), "image_sha256": sha256_file(image), "f": list(sfr.identity_of(image) or ())}
    try:
        disk = sfr.read_disk(image)
    except sfr.Refused:
        disk = None
    view["guard"] = disk["guard"] if disk is not None else None
    slot = disk["slot"] if disk is not None else None
    view["slot"] = slot["bytes"].hex() if slot is not None and slot.get("shape") == "ok" else None
    view["hm"] = None
    if view["slot"] is not None:
        fd = os.open(image, os.O_RDONLY)
        try:
            view["hm"] = sfr.masked_hash(fd, slot["offset"])
        finally:
            os.close(fd)
    tree = ({"seq": disk.get("seq"), "files": {path: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                                                for path, data in sorted(disk["files"].items())}}
            if disk is not None else "host_reader_refused")
    retain_snapshot(pathlib.Path(directory) / "x", label, dict(view, host_reader_tree=tree))
    return dict(view, host_reader_tree=tree)


def retain_snapshot(out, label, record):
    import inspect
    caller = next((frame.function for frame in inspect.stack()[2:] if frame.function not in ("snapshot", "require_refused_tool")),
                  "snapshot")
    directory = pathlib.Path(out).resolve().parent / "snapshots"
    directory.mkdir(exist_ok=True)
    index = SNAPSHOTS.get(str(directory), 0) + 1
    SNAPSHOTS[str(directory)] = index
    name = f"{index:03d}-{caller}-{label or 'before'}.json"
    record = dict(record, out=str(out), time=f"{time.time():.3f}", caller=caller, label=label or "before")
    (directory / name).write_text(json.dumps(record, indent=2, default=str) + "\n")


def release(out, *words, env=None, check=False):
    run = subprocess.run([sys.executable, "-I", str(here / "release.py"), *words, "--target", str(out)]
                         if "--target" not in words and words[0] != "build" else
                         [sys.executable, "-I", str(here / "release.py"), *words],
                         capture_output=True, text=True, env=env)
    if check and run.returncode != 0:
        raise CaseFailed(f"release.py {' '.join(words)} failed:\n{run.stderr}\n{run.stdout}")
    return run


class Lane:
    """The lane's inputs: platform, kernel copy, release directory, key,
    work directory, QEMU words, and per-case evidence."""

    def __init__(self, args):
        self.root = pathlib.Path(args.platform).resolve()
        self.kernel = pathlib.Path(args.kernel).resolve()
        self.release = pathlib.Path(args.release).resolve()
        self.other = pathlib.Path(args.other_release).resolve() if args.other_release else None
        self.key = pathlib.Path(args.key).resolve()
        self.work = pathlib.Path(args.work).resolve()
        self._enroll_iso = None
        self.qemu = args.qemu
        self.accel = args.accel
        self.timeout = READY_TIMEOUT_KVM if args.accel == "kvm" else READY_TIMEOUT_TCG
        self.port = args.port
        self.results = {}
        self.readiness = []
        self.started = []
        self.launches = 0
        self.pending_seen = b""
        self.last_launch = {}
        self.env = dict(os.environ, ABSD_QEMU=self.qemu.split()[0])

    def case_dir(self, name):
        directory = self.work / name
        directory.mkdir(parents=True, exist_ok=False)
        return directory

    def install(self, name, probe=True):
        """A fresh operator directory with the lane release installed and,
        for the cases that measure the pending-write boundary, the probe."""
        out = self.case_dir(name) / "out"
        run = release(out, "install", "--release", str(self.release), "--kernel", str(self.kernel),
                      "--target-identity", f"resume-{name}", check=True)
        self.note(name, "install", run.stdout)
        disk = sfr.read_disk(out / sfr.IMAGE)
        if disk["slot"]["parsed"] != "none" or disk["guard"] != "fresh":
            raise CaseFailed("install did not seed the guard fresh and the slot none")
        if probe:
            self.add_probe(name, out)
        return out

    def add_probe(self, name, out):
        """`/bin/fsd-probe` on the disk: the measurement contract's own
        program (open without truncation, acknowledged WRITE_AT, alive and
        unsynced; `src/bin/fsd_probe.rs`, as core-fsd-recovery.py uses it),
        which the operator image does not ship. It is added to the release
        tree on the disk by the release's own importer under the host guard
        transaction, before any boot, and read back by the host reader; the
        record on the disk still names the release, so the file server
        serves it. The addition is recorded in the case JSON."""
        spec = importlib.util.spec_from_file_location("release_for_resume_probe", here / "release.py")
        rel = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(rel)
        probe = self.root / "fsd-probe.elf"
        if not probe.is_file():
            raise CaseFailed(f"{probe} is missing: build the platform first")
        release_obj = rel.Release(self.release)
        path = f"{rel.rr.tree_root(release_obj.id)}/bin/fsd-probe"
        data = probe.read_bytes()
        boots = rel.import_files(self.kernel, release_obj, out / sfr.IMAGE, [(path, data)], lambda line: None)
        found = sfr.read_disk(out / sfr.IMAGE)
        if found["files"].get(path) != data or found["guard"] != "fresh":
            raise CaseFailed("the probe was not added, or the guard changed")
        self.note(name, "probe_added", {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "boots": boots})

    def enroll_iso(self):
        """The enrollment image (absd-enroll.elf as the step-1 worker, its
        keys streamed over the console: ENROLL_STREAM=1), built once by the
        kernel copy with enroll-matrix.py's own make()."""
        if self._enroll_iso is None:
            spec = importlib.util.spec_from_file_location("enroll_matrix_for_resume_iso", here / "enroll-matrix.py")
            enroll = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(enroll)
            work = self.work / "iso-work"
            work.mkdir(exist_ok=True)
            empty = work / "enroll-empty-input.bin"
            empty.write_bytes(b"")
            self._enroll_iso = work / "enroll.iso"
            enroll.make(self.kernel, self._enroll_iso, work / "enroll-build.log", EXTERNAL_USER_ELF=self.root / "absd-enroll.elf",
                        EXTERNAL_INPUT=empty, ENROLL_STREAM=1, DURABLE_STEP=1)
        return self._enroll_iso

    def machine_dir(self, name, out):
        """An absd-try machine directory holding a copy of `out`'s disk with
        a manifest that load_manifest accepts, so that `absd_try.py enroll`
        reaches its recovery boundary (and, with the real enroll image, the
        guest)."""
        machine = out.parent / f"machine-{name}"
        machine.mkdir()
        shutil.copyfile(out / sfr.IMAGE, machine / "disk.img")
        (machine / "disk.img").chmod(0o600)
        shutil.copyfile(self.enroll_iso(), machine / "enroll.iso")
        shutil.copyfile(out / "absd-operator.iso", machine / "operator.iso")
        shutil.copytree(out / "recovery", machine / "recovery", dirs_exist_ok=True)

        def asset(path):
            return {"name": path.name, "sha256": sha256_file(path), "bytes": path.stat().st_size}
        disk = asset(machine / "disk.img")
        disk.update(raw_sha256=disk["sha256"], raw_bytes=disk["bytes"])
        doc = {"schema": "absd-preview-manifest/1", "release": {"id": release_id_of(self)},
               "assets": {"operator_iso": asset(machine / "operator.iso"), "enroll_iso": asset(machine / "enroll.iso"),
                          "disk": disk}, "signature": "unsigned"}
        lines = [f'schema = "{doc["schema"]}"', 'signature = "unsigned"', "", "[release]", f'id = "{doc["release"]["id"]}"']
        for role, entry in doc["assets"].items():
            lines += ["", f"[assets.{role}]"] + [f'{k} = {json.dumps(v)}' for k, v in entry.items()]
        (machine / "MANIFEST.toml").write_text("\n".join(lines) + "\n")
        (machine / ".absd-try-machine").write_text("absd-try machine for the resume matrix\n")
        return machine

    def note(self, name, key, value):
        self.results.setdefault(name, {})[key] = value

    def write_json(self, name):
        (self.work / name).mkdir(parents=True, exist_ok=True)  # B5's legs live in b5-<sub>/
        (self.work / name / "case.json").write_text(json.dumps(self.results.get(name, {}), indent=2, default=str))

    # -- boots ------------------------------------------------------------------

    def launcher(self, out, port=None):
        """boot-operator.sh in the background; returns the Popen. The
        console the previous boot left (`stale_console`, its device and
        inode) is recorded before the launch: the launcher rotates it, and
        until then its lines are not this launch's."""
        stale = _identity(out / "console.log")
        began = time.time()
        # The launcher's own output (precheck, QEMU's stderr, the exit
        # classification) is kept per launch beside OUT, never in an
        # unread pipe.
        self.launches += 1
        log = out.parent / f"launcher-{self.launches:03d}.log"
        with open(log, "w") as sink:
            proc = subprocess.Popen([str(here / "boot-operator.sh"), str(out), str(port or self.port)],
                                    stdout=sink, stderr=subprocess.STDOUT, text=True, env=self.env,
                                    start_new_session=True)
        proc.log_path = log
        self.last_launch[str(out)] = (began, proc)
        proc.stale_console = stale
        self.started.append(proc)
        return proc

    def descendants(self, pid):
        """Every live descendant pid of `pid`, nearest first."""
        found, pending = [], [str(pid)]
        while pending:
            parent = pending.pop(0)
            children = subprocess.run(["pgrep", "-P", parent], capture_output=True, text=True).stdout.split()
            found += [int(child) for child in children]
            pending += children
        return found

    def stop_leftovers(self, name):
        """After a case: any launcher or durable boot this case started that
        is still alive (a failed case leaves them) is ended by exact pid,
        its QEMU first, then the rest of its own descendants, then itself.
        Nothing this matrix did not start is signalled."""
        stopped = []
        for proc in self.started:
            if proc.poll() is not None:
                continue
            tree = self.descendants(proc.pid)
            qemus = [pid for pid in tree if "qemu" in _comm(pid)]
            for pid in qemus + [pid for pid in tree if pid not in qemus] + [proc.pid]:
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)
                    stopped.append(pid)
            with contextlib.suppress(Exception):
                proc.wait(timeout=30)
        self.started = []
        if stopped:
            print(f"RESUME CLEANUP case={name} killed_pids={','.join(map(str, stopped))}", file=sys.stderr, flush=True)

    def qemu_of(self, launcher):
        """The exact QEMU descendant of a launcher: boot-operator.sh's
        served_ram exec keeps its pid as a direct child; durable-boot.sh
        runs QEMU under timeout(1), one level further down."""
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            pending = [str(launcher.pid)]
            while pending:
                parent = pending.pop(0)
                children = subprocess.run(["pgrep", "-P", parent], capture_output=True, text=True).stdout.split()
                for pid in children:
                    try:
                        with open(f"/proc/{pid}/comm") as handle:
                            if "qemu" in handle.read():
                                return int(pid)
                    except OSError:
                        continue
                    pending.append(pid)
            time.sleep(0.2)
        raise CaseFailed("no QEMU descendant of the launcher appeared")

    def wait_ready(self, out, ident, timeout=None):
        """W, as the runbook runs it: after boot-operator.sh has recorded
        this launch. W refuses (7, "no launch recorded") when no `launched`
        record exists yet, by design; so after a launch from this matrix
        the record of *that* launch (launch_epoch not before the launcher
        started) is awaited first, up to 60 s or the launcher's end."""
        launch = self.last_launch.get(str(out))
        if launch is not None:
            began, proc = launch
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                with contextlib.suppress(FileNotFoundError, KeyError, ValueError, tomllib.TOMLDecodeError):
                    active = toml(out / "recovery" / sfr.ACTIVE)["active"]
                    if active.get("state") == "launched" and float(active.get("launch_epoch", 0)) >= began - 0.001:
                        break
                if proc.poll() is not None:
                    break
                time.sleep(0.05)
        started = time.monotonic()
        run = release(out, "recover", "--wait-ready", "--id", ident, "--timeout", str(timeout or self.timeout))
        elapsed = time.monotonic() - started
        self.readiness.append({"out": str(out), "id": ident, "code": run.returncode, "seconds": round(elapsed, 1)})
        return run, elapsed

    def ssh_pending(self, out, port, command, marker, timeout=120, poll=0.05):
        """A session that stays open: the command is started and its stdout
        watched for `marker`; the Popen is returned alive (the probe's
        recovery-pending loops until the machine dies)."""
        spec = importlib.util.spec_from_file_location("ssh_matrix_for_resume_pending", here / "ssh-matrix.py")
        smx = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(smx)
        client = smx.Client(out, port)
        proc = subprocess.Popen(client.base(self.key) + [command], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + timeout
        seen = b""
        os.set_blocking(proc.stdout.fileno(), False)
        while time.monotonic() < deadline:
            try:
                chunk = proc.stdout.read()
            except BlockingIOError:
                chunk = None
            if chunk:
                seen += chunk
                if marker.encode() in seen:
                    self.pending_seen = seen
                    return proc
            if proc.poll() is not None:
                raise CaseFailed(f"the pending session ended before {marker!r}: {seen!r} {proc.stderr.read()!r}")
            time.sleep(poll)
        proc.kill()
        raise CaseFailed(f"no {marker!r} within {timeout}s: {seen!r}")

    def ssh(self, out, port, command, stdin=b"", timeout=120):
        spec = importlib.util.spec_from_file_location("ssh_matrix_for_resume", here / "ssh-matrix.py")
        smx = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(smx)
        client = smx.Client(out, port)
        known = out / "known_hosts"
        if not known.is_file():
            worker = fence_guest.captured_complete((out / "console.log").read_bytes())
            key = re.search(r"SSH HOST KEY (?:GENERATED|LOADED) (ssh-ed25519 \S+)", worker)
            if key is None:
                raise CaseFailed("no host key line to trust")
            client.trust(key.group(1))
        return client.run(self.key, command, stdin=stdin, timeout=timeout)

    def durable_boot(self, out, name, *, served=True, iso=None, env=None, timeout=300, kill_on=None):
        """A boot through the kernel's durable-boot.sh (precheck bypassed),
        the release's ISO; optionally killed on a console line."""
        log = out.parent / f"{name}.serial.log"
        environment = dict(os.environ, ABSD_BLOCK_ATTACH="ata")
        environment.update(env or {})
        argv = [str(self.kernel / "scripts" / "durable-boot.sh"), str(iso or out / "absd-operator.iso"), str(out / sfr.IMAGE),
                str(log), str(timeout), *served_qemu(self.qemu), "-netdev", "user,id=n0,net=10.0.2.0/24", "-device",
                "e1000,netdev=n0"]
        snapshot(out, f"{name}-before-boot")
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, text=True, env=environment, start_new_session=True)
        self.started.append(proc)
        if kill_on is not None:
            self.kill_on(proc, log, kill_on)
        status = proc.communicate(timeout=timeout + 60)[0].strip()
        snapshot(out, f"{name}-after-boot-status-{status}")
        return log.read_bytes(), status, log

    def kill_on(self, proc, log, needle):
        """Kills the exact QEMU child the moment `needle` is in this boot's
        console (a launcher's stale console, before its rotation, is not).
        LISTENER names the listener record, which is hex in the worker
        chunks rather than a console line."""
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            raw = launch_console(proc, log)
            found = (sfr.listener_position(raw) is not None) if needle == LISTENER else needle.encode() in raw
            if found:
                pid = self.qemu_of(proc)
                os.kill(pid, signal.SIGKILL)
                return pid
            if proc.poll() is not None:
                raise CaseFailed(f"the boot ended before {needle!r}")
            time.sleep(0.05)
        raise CaseFailed(f"{needle!r} never appeared")


# -- cases ------------------------------------------------------------------------

F1, F2, F3 = "/home/operator/F1", "/home/operator/F2", "/home/operator/F3"
F_SIZE = 4097  # two blocks: a boundary inside the file, as core-fsd-recovery.py measures


def probe_bytes(size, pending=False):
    """The probe's own data patterns (src/bin/fsd_probe.rs): `write` is
    i % 251, `recovery-pending` is (i + 17) % 251."""
    return bytes(((i + 17) if pending else i) % 251 for i in range(size))


def classify_sectors(data, size):
    """old / new / mixed-by-sector for F2 after recovery, per 512-byte sector."""
    old, new = probe_bytes(size), probe_bytes(size, pending=True)
    if len(data) != size:
        return "size_changed"
    kinds = set()
    for at in range(0, size, 512):
        chunk = data[at:at + 512]
        kinds.add("old" if chunk == old[at:at + 512] else "new" if chunk == new[at:at + 512] else "other")
    if kinds == {"old"}:
        return "old"
    if kinds == {"new"}:
        return "new"
    return "mixed-by-sector" if kinds <= {"old", "new"} else "indeterminate"


def serve_and_stop_unclean(lane, name, out, previous="failed", boundary_mode=None):
    """P0's history: a served boot through the launcher, F1 written and
    synced, F2 an unsynced overwrite in progress, then SIGKILL of the exact
    QEMU. `not_ready`: the unclean end is RELEASE REFUSED (another
    release's ISO on this disk) killed before readiness is impossible, so
    the served boot runs with the wrong ISO and ends unready by itself."""
    port = lane.port
    if previous == "failed":
        launcher = lane.launcher(out, port)
        run, elapsed = wait_any_ready(lane, out, launcher)
        lane.note(name, "first_boot_ready_seconds", elapsed)
        # F1: written and synced by the probe (exact afterwards).
        rc, out_text, err = lane.ssh(out, port, f"/bin/fsd-probe write {F1} {F_SIZE}")
        if rc != 0 or f"write: {F_SIZE} bytes ".encode() not in out_text:
            raise CaseFailed(f"F1 write: rc={rc} {out_text!r} {err!r}")
        # F2: first written and synced (the old bytes), then overwritten in
        # place by the probe's recovery-pending: open without truncation,
        # WRITE_AT acknowledged, the handle alive, unsynced, when QEMU dies.
        rc, out_text, err = lane.ssh(out, port, f"/bin/fsd-probe write {F2} {F_SIZE}")
        if rc != 0 or f"write: {F_SIZE} bytes ".encode() not in out_text:
            raise CaseFailed(f"F2 write: rc={rc} {out_text!r} {err!r}")
        pid = lane.qemu_of(launcher)
        if boundary_mode is None:
            # Every other case: the plain acknowledged overwrite, killed on
            # its marker (no boundary claim is made for these cases).
            pending = lane.ssh_pending(out, port, f"/bin/fsd-probe recovery-pending {F2} {F_SIZE}",
                                       f"RECOVERY PENDING write_accepted bytes={F_SIZE}", poll=0.002)
            os.kill(pid, signal.SIGKILL)
            launcher.wait(timeout=60)
            pending.kill()
            pending.wait()
            lane.note(name, "unclean_stop", {"qemu_pid": pid, "launcher_status": launcher.returncode,
                                             "pending_marker": "RECOVERY PENDING write_accepted"})
        else:
            observe_boundary(lane, name, out, port, launcher, pid, boundary_mode)
    else:
        # P0n: release B's ISO on A's disk: fsd arms and charges, then RELEASE REFUSED.
        other = lane.other / "absd-operator.iso" if lane.other else None
        if other is None or not other.is_file():
            raise CaseFailed("P0n needs the second release (--other-release; run-storage-fence-resume.sh builds it)")
        raw, status, log = lane.durable_boot(out, f"{name}-wrong-release", iso=other)
        if status != "7" or b"RELEASE REFUSED" not in raw:
            raise CaseFailed(f"the wrong-release boot did not refuse: status={status}")
    disk = sfr.read_disk(out / sfr.IMAGE)
    state = sfr.recovery_state(disk["files"], disk["guard"])
    if disk["guard"] != "dirty" or state["previous"] != previous:
        raise CaseFailed(f"the unclean history is guard={disk['guard']} previous={state['previous']}, expected dirty/{previous}")


# P0's commit boundary (coordination record #63, owner direction 2026-10-23).
# The overwrite GROWS F2 (F_SIZE -> F_SIZE + P0_GROW bytes, one acknowledged
# WRITE_AT from offset 0): Fs::write_at sets the new size and marks the
# file system dirty unconditionally when a write extends a file
# (fs/src/lib.rs write_at, `if end > size`), and every commit encodes each
# linked record's size (Fs::commit -> linked_records). So the overwrite's
# metadata differs from the committed record whatever the guest clock says,
# and the probe observes it: after the write it stats F2 through the server
# with the handle open and prints the in-memory size. A committed state
# that still records F2's old size after QEMU is gone was committed before
# the overwrite: the overwrite was uncommitted at termination. Data is not
# a discriminator: the file system writes file data in place to the device
# as it is written (Fs::store -> write_run), so the image holds new sectors
# whether or not they were committed (DESIGN-v5 5: unsynced in-place
# overwrites are indeterminate per sector).
P0_GROW = 512
P0_OBSERVED = re.compile(rb"RECOVERY PENDING OBSERVED write_accepted bytes=(\d+) size=(\d+) mtime=(\S+)\n")
P0_PRECOMMIT = re.compile(rb"RECOVERY PENDING PRECOMMIT seq=(\d+)\n")


def committed_view(image):
    """The committed state the host reader selects: superblock seq and
    F2's record (size, blocks, mtime), read-only, no lock."""
    import absd_fs
    region = absd_fs.fs_region(image, sfr.DEVICE_SECTORS)
    selected = absd_fs.select(region)
    record = absd_fs.tree(region, selected).get(F2) or {}
    return {"seq": selected["seq"], "f2": {key: record.get(key) for key in ("size", "blocks", "mtime")}}


def p0_oracle(memory, before, at_marker, after):
    """The boundary verdict from observations only. `memory` is the
    probe's in-memory F2 (size, mtime) after the acknowledged write;
    `before`/`at_marker`/`after` the committed views before the
    overwrite, after the marker (QEMU running) and after termination.
    Returns (verdict, reason): `uncommitted_at_termination` only when the
    observed in-memory size differs from the committed size and the state
    committed at termination still records the old size and is the state
    committed at the marker."""
    if memory["size"] == before["f2"]["size"]:
        return "commit_boundary_unproven", "in-memory size equals the committed size: no observed discriminator"
    if after["f2"]["size"] == memory["size"]:
        return "committed_before_termination", "the state committed at termination records the overwrite's size"
    if after["f2"] != before["f2"] or at_marker["f2"] != before["f2"]:
        return "commit_boundary_unproven", "F2's committed record changed, but not to the overwrite's size"
    if after["seq"] != at_marker["seq"]:
        return "commit_boundary_unproven", "a commit happened between the marker read and termination"
    return "uncommitted_at_termination", "committed size at termination is the pre-overwrite size; in-memory size differs"


def observe_boundary(lane, name, out, port, launcher, pid, mode):
    """`observed` (P0): the growing overwrite, observed, killed at once. The
    probe commits what its own session left pending before it writes, so
    the overwrite is the only uncommitted change when the host kills.
    Controls the oracle must refuse: `same` writes F2's own bytes at its own
    size (no metadata change: the same-metadata variant); `committed`
    grows F2 as P0 does, then runs /bin/sync in a second session before the
    kill (the already-committed variant)."""
    size, pattern = (F_SIZE, "write") if mode == "same" else (F_SIZE + P0_GROW, "pending")
    before = committed_view(out / sfr.IMAGE)
    sent = time.time()
    pending = lane.ssh_pending(out, port, f"/bin/fsd-probe recovery-pending-observed {F2} {size} {pattern}",
                               f"RECOVERY PENDING OBSERVED write_accepted bytes={size} ", poll=0.002)
    seen = time.time()
    at_marker = committed_view(out / sfr.IMAGE)
    synced = None
    if mode == "committed":
        rc, text, err = lane.ssh(out, port, "/bin/sync")
        synced = {"rc": rc, "stdout": text.decode(errors="replace"), "stderr": err.decode(errors="replace")}
    marked = time.time()
    os.kill(pid, signal.SIGKILL)
    killed = time.time()
    launcher.wait(timeout=60)
    pending.kill()
    stdout = pending.stdout.read() or b""
    pending.wait()
    after = committed_view(out / sfr.IMAGE)
    marker = P0_OBSERVED.search(lane.pending_seen + stdout)
    if marker is None:
        raise CaseFailed("the observed marker did not parse")
    memory = {"size": int(marker.group(2)), "mtime": marker.group(3).decode()}
    precommit = P0_PRECOMMIT.search(lane.pending_seen + stdout)
    if precommit is None:
        raise CaseFailed("the probe did not report its commit before the overwrite")
    verdict, reason = p0_oracle(memory, before, at_marker, after)
    record = {"mode": mode, "qemu_pid": pid, "launcher_status": launcher.returncode,
              "marker": marker.group(0).decode(), "precommit_seq": int(precommit.group(1)), "in_memory": memory, "committed_before_overwrite": before,
              "committed_at_marker": at_marker, "committed_after_termination": after, "sync_control": synced,
              "sent_epoch": f"{sent:.3f}", "marker_epoch": f"{seen:.3f}", "kill_epoch": f"{killed:.3f}",
              "marker_to_kill_s": round(killed - seen, 3), "verdict": verdict, "reason": reason}
    lane.note(name, "unclean_stop", record)
    print(f"RESUME P0 BOUNDARY case={name} mode={mode} verdict={verdict} in_memory_size={memory['size']} "
          f"in_memory_mtime={memory['mtime']} committed_size_before={before['f2']['size']} "
          f"committed_size_at_marker={at_marker['f2']['size']} committed_size_after={after['f2']['size']} "
          f"seq_before={before['seq']} precommit_seq={precommit.group(1).decode()} "
          f"seq_at_marker={at_marker['seq']} seq_after={after['seq']} "
          f"marker_to_kill_s={killed - seen:.3f} reason={reason!r}", flush=True)
    return verdict


def wait_any_ready(lane, out, launcher, timeout=None):
    """Readiness of a normal (non-resumed) launch: RELEASE OK + SSH LISTENING
    + the receive setup, as release.py's own Boot.wait_ready does."""
    spec = importlib.util.spec_from_file_location("release_for_resume_matrix", here / "release.py")
    rel = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rel)
    console = out / "console.log"
    deadline = time.monotonic() + (timeout or lane.timeout)
    started = time.monotonic()
    while time.monotonic() < deadline:
        raw = launch_console(launcher, console)
        serial = raw.decode(errors="replace")
        worker = fence_guest.captured_complete(raw) if raw else ""
        if "RELEASE OK release=" in serial and "SSH LISTENING" in worker:
            rel.wait_rx_setup(lambda: launch_console(launcher, console), lambda: launcher.poll() is None, deadline)
            return None, time.monotonic() - started
        if launcher.poll() is not None:
            raise CaseFailed(f"the launcher ended before readiness: {launcher.returncode}")
        time.sleep(0.5)
    raise CaseFailed("no readiness within the timeout")


def recover(lane, name, out, reason="matrix"):
    run = release(out, "recover", "--attest-sole-instance", "--accept-committed-state", "--reason", reason, check=True)
    match = re.search(r"RECOVERY AUTHORIZED id=([0-9a-f]{32}) target=\S+ previous=(\w+) fs_seq=(\d+) hm=([0-9a-f]{64})", run.stdout)
    if match is None:
        raise CaseFailed(f"no RECOVERY AUTHORIZED line:\n{run.stdout}")
    lane.note(name, "authorized", match.group(0))
    return match.group(1), match.group(2), int(match.group(3))


def positive(lane, name, previous):
    out = lane.install(name)
    serve_and_stop_unclean(lane, name, out, previous, boundary_mode="observed" if name == "p0" else None)
    if name == "p0":
        verdict = lane.results[name]["unclean_stop"]["verdict"]
        if verdict != "uncommitted_at_termination":
            raise CaseFailed(f"P0's overwrite is not shown uncommitted at termination: {verdict} "
                             f"({lane.results[name]['unclean_stop']['reason']}); commit boundary unproven")
    # R: the served cold boot of the unclean image is refused.
    raw, status, log = lane.durable_boot(out, f"{name}-refused")
    if previous == "failed":
        fence_guest.require_served_successor_refusal(raw, status)
    else:
        require_served_refusal(raw, status, "not_ready")
    before = snapshot(out)
    backup = out.parent / "backup"
    release(out, "backup", str(backup), check=True)
    if toml(backup / "backup.toml")["recovery"]["pending_id"] != "none":
        raise CaseFailed("a backup before the act carries a pending id")
    ident, found_previous, fs_seq = recover(lane, name, out)
    if found_previous != previous:
        raise CaseFailed(f"recover reports previous={found_previous}")
    require_row(out, "authorized")
    (out / "console.log").write_text("stale console to be rotated\n")
    launcher = lane.launcher(out)
    timings = observe_readiness(out, ident, lane.timeout, launcher)
    lane.readiness.append(dict(timings, case=name, id=ident))
    lane.note(name, "readiness_lines_seconds_after_launched", timings)
    run, elapsed = lane.wait_ready(out, ident)
    if run.returncode != 0:
        raise CaseFailed(f"--wait-ready exited {run.returncode}:\n{run.stdout}\n{run.stderr}")
    if not list(out.glob("console-*.log")):
        raise CaseFailed("the launcher did not rotate the previous console")
    admitted = require_admission((out / "console.log").read_bytes(), ident, previous, fs_seq)
    lane.note(name, "admission", admitted)
    stop = lane.results.get(name, {}).get("unclean_stop", {})
    if name == "p0":
        # The recovered (admitted) state is the committed state at the kill,
        # which did not include the overwrite.
        if admitted["fs_seq"] != stop["committed_after_termination"]["seq"]:
            raise CaseFailed(f"RESUMED fs_seq={admitted['fs_seq']} is not the committed seq at termination "
                             f"({stop['committed_after_termination']['seq']})")
        print(f"RESUME P0 RECOVERED case={name} fs_seq={admitted['fs_seq']} = seq_after "
              f"(committed F2 size {stop['committed_after_termination']['f2']['size']}, "
              f"in-memory size before termination {stop['in_memory']['size']})", flush=True)
    lane.note(name, "readiness_seconds", round(elapsed, 1))
    disk = sfr.read_disk(out / sfr.IMAGE)
    if disk["slot"]["parsed"] != "none" or disk["guard"] != "dirty":
        raise CaseFailed("after admission the slot is not none or the guard not dirty")
    if sfr.identity_of(out / sfr.IMAGE) != tuple(before["f"]):
        raise CaseFailed("F changed through the recovery")
    if previous == "failed":
        rc, data, _ = lane.ssh(out, lane.port, f"/bin/cat {F1}")
        if rc != 0 or data != probe_bytes(F_SIZE):
            raise CaseFailed(f"F1 is not exact: rc={rc} {len(data)} bytes")
        rc, data, _ = lane.ssh(out, lane.port, f"/bin/cat {F2}")
        if rc != 0:
            raise CaseFailed(f"F2 read: rc={rc}")
        outcome = classify_sectors(data, F_SIZE)
        if outcome in ("size_changed", "indeterminate"):
            raise CaseFailed(f"F2 is {outcome}: the pending overwrite left bytes outside old/new per sector")
        lane.note(name, "F2", {"outcome": outcome, "sha256": hashlib.sha256(data).hexdigest()})
        print(f"RESUME F2 case={name} outcome={outcome}", flush=True)
    rc, out_text, err = lane.ssh(out, lane.port, f"/bin/fsd-probe write {F3} 4097")
    if rc != 0 or b"write: 4097 bytes " not in out_text:
        raise CaseFailed(f"F3 write: rc={rc} {out_text!r} {err!r}")
    rc, data, _ = lane.ssh(out, lane.port, f"/bin/cat {F3}")
    if rc != 0 or data != probe_bytes(4097):
        raise CaseFailed(f"F3 read-back differs: rc={rc} {len(data)} bytes")
    rc, health, _ = lane.ssh(out, lane.port, "/bin/health")
    if f"previous={previous}".encode() not in health or b"streak=" not in health:
        raise CaseFailed(f"health does not report the recovered history: {health!r}")
    rc, down, _ = lane.ssh(out, lane.port, "shutdown")
    launcher.wait(timeout=300)
    serial = (out / "console.log").read_bytes().decode(errors="replace")
    # A served halt's finalization lines (survival-recovery.py checks the
    # same pair); `FSD SHUTDOWN FINALIZED` is the bounded boot's line only.
    if launcher.returncode != 0 or "FSD FINALIZED boot=" not in serial or "SERVED SHUTDOWN FINALIZED status=0" not in serial:
        raise CaseFailed(f"the halt was not orderly: launcher {launcher.returncode}")
    if sfr.read_disk(out / sfr.IMAGE)["guard"] != "clean":
        raise CaseFailed("the guard is not clean after the orderly end")
    if not (out / "recovery" / f"consumed-{ident}.toml").is_file() or (out / "recovery" / sfr.ACTIVE).exists():
        raise CaseFailed("the exit path did not retire the consumed record")
    status = require_row(out, "none")
    if f"last=consumed {ident}" not in status:
        raise CaseFailed("--status does not name the consumed act")
    if not (out / "recovery" / f"intent-{ident}.toml").is_file():
        raise CaseFailed("the intent was deleted")
    # The next boot is a normal clean+ended admission.
    launcher = lane.launcher(out)
    wait_any_ready(lane, out, launcher)
    serial = (out / "console.log").read_bytes().decode(errors="replace")
    if "FSD STORAGE FENCE fence=none previous=ended assessed=ended" not in serial:
        raise CaseFailed("the boot after recovery is not previous=ended")
    lane.ssh(out, lane.port, "shutdown")
    launcher.wait(timeout=300)
    lane.write_json(name)
    print(f"RESUME POSITIVE OK case={name} boots=4", flush=True)


def case_p0(lane):
    positive(lane, "p0", "failed")


def case_p0c(lane):
    """The P0 oracle's controls, run on the guest: it must refuse the
    same-metadata variant (F2's own bytes at its own size: nothing for the
    commit to differ by) and the already-committed variant (P0's growing
    overwrite, then /bin/sync before the kill)."""
    verdicts = {}
    for mode, want in (("same", "commit_boundary_unproven"), ("committed", "committed_before_termination")):
        name = f"p0c-{mode}"
        out = lane.install(name)
        serve_and_stop_unclean(lane, name, out, boundary_mode=mode)
        verdicts[mode] = lane.results[name]["unclean_stop"]["verdict"]
        lane.write_json(name)
        if verdicts[mode] != want:
            raise CaseFailed(f"the P0 oracle did not refuse the {mode} control: {verdicts[mode]}, expected {want}")
    print(f"RESUME P0 CONTROLS OK case=p0c same={verdicts['same']} committed={verdicts['committed']}", flush=True)


def case_p0n(lane):
    positive(lane, "p0n", "not_ready")


def authorized_image(lane, name, previous="failed"):
    out = lane.install(name)
    serve_and_stop_unclean(lane, name, out, previous)
    ident, _, fs_seq = recover(lane, name, out)
    return out, ident, fs_seq


def case_l3(lane):
    out, ident, _ = authorized_image(lane, "l3")
    first = lane.launcher(out, lane.port)
    first_launch = lane.last_launch[str(out)]
    time.sleep(0.05)
    second = lane.launcher(out, lane.port + 1)
    second.wait(timeout=120)
    lane.last_launch[str(out)] = first_launch  # W follows the launch that serves
    second_out = second.log_path.read_text(errors="replace")
    if second.returncode == 0:
        raise CaseFailed("the second launcher served too")
    if "tool_busy" not in second_out and "lock" not in second_out:
        raise CaseFailed(f"the second launcher did not name tool_busy or QEMU's lock:\n{second_out}")
    run, _ = lane.wait_ready(out, ident)
    if run.returncode != 0:
        raise CaseFailed("the first launcher did not reach readiness")
    require_admission((out / "console.log").read_bytes(), ident, "failed")
    if toml(out / "recovery" / sfr.ACTIVE)["active"].get("launches", 0) != 1 if (out / "recovery" / sfr.ACTIVE).exists() else False:
        raise CaseFailed("more than one launched record")
    lane.ssh(out, lane.port, "shutdown")
    first.wait(timeout=300)
    print("RESUME RACE OK case=l3", flush=True)


def case_l4(lane):
    out, ident, _ = authorized_image(lane, "l4")
    env = dict(lane.env, ABSD_QEMU=str(out.parent / "missing-qemu"))
    launcher = subprocess.run([str(here / "boot-operator.sh"), str(out), str(lane.port)], capture_output=True, text=True,
                              env=env)
    if launcher.returncode == 0 or "launched" in launcher.stdout and "launch_failed" not in launcher.stdout:
        raise CaseFailed("a QEMU that cannot exec produced a launch")
    lane.note("l4", "missing_qemu_launcher", {"status": launcher.returncode, "stdout": launcher.stdout,
                                              "stderr": launcher.stderr})
    # F1: a classified launch_failed is the launcher's own exit 6 and
    # message, never the bookkeeping failure.
    if launcher.returncode != 6 or "boot-operator: launch failed:" not in launcher.stderr \
            or "exit classification failed" in launcher.stderr:
        raise CaseFailed(f"launch_failed was not reported as a failed launch (6):\n{launcher.stdout}\n{launcher.stderr}")
    require_row(out, "authorized")
    # W after the failed launch: the record is back to authorized, so W
    # ends 7 without waiting.
    run = release(out, "recover", "--wait-ready", "--id", ident, "--timeout", "5")
    lane.note("l4", "wait_after_launch_failed", {"status": run.returncode, "stdout": run.stdout, "stderr": run.stderr})
    if run.returncode != 7 or not re.search(rf"(?m)^wait-ready: id={ident} launch_failed status=\S+: the last launch "
                                            r"\(pid \d+, .*\) ended without ABSD KERNEL BOOT in .*; the authorization is intact",
                                            run.stdout):
        raise CaseFailed(f"W after launch_failed did not name the boot end ({run.returncode}):\n{run.stdout}")
    iso = out / "absd-operator.iso"
    kept = out.parent / "iso.kept"
    iso.rename(kept)
    # boot-operator.sh's `test -f OUT/absd-operator.iso` under set -e: it
    # exits before the lock, the rotation and the precheck, silently. The
    # launch never happened, so nothing may be recorded: the records and
    # the console are exactly as before.
    before = snapshot(out)
    console_before = _identity(out / "console.log")
    launcher = subprocess.run([str(here / "boot-operator.sh"), str(out), str(lane.port)], capture_output=True, text=True,
                              env=lane.env)
    lane.note("l4", "missing_iso_launcher", {"status": launcher.returncode, "stdout": launcher.stdout,
                                             "stderr": launcher.stderr})
    if launcher.returncode == 0:
        raise CaseFailed("a launcher without its ISO succeeded")
    after = snapshot(out)
    if after["files"] != before["files"] or after["slot"] != before["slot"] or _identity(out / "console.log") != console_before:
        raise CaseFailed(f"a launcher without its ISO changed the records or the console:\n{launcher.stdout}\n{launcher.stderr}")
    run = release(out, "recover", "--wait-ready", "--id", ident, "--timeout", "5")
    lane.note("l4", "wait_after_missing_iso", {"status": run.returncode, "stdout": run.stdout})
    if run.returncode != 7 or f"wait-ready: id={ident} launch_failed status=" not in run.stdout:
        raise CaseFailed(f"W after the missing-ISO launcher did not name the recorded boot end:\n{run.stdout}")
    kept.rename(iso)
    require_row(out, "authorized")
    launcher = lane.launcher(out)
    run, _ = lane.wait_ready(out, ident)
    if run.returncode != 0:
        raise CaseFailed("the normal launch after launch_failed did not reach readiness")
    require_admission((out / "console.log").read_bytes(), ident, "failed")
    lane.ssh(out, lane.port, "shutdown")
    launcher.wait(timeout=300)
    print("RESUME LAUNCH OK case=l4", flush=True)


def case_l5(lane):
    # A prior launch is established through the launcher (killed on ABSD
    # KERNEL BOOT), then the precheck-bypassing boot is killed the same way.
    out, ident, _ = authorized_image(lane, "l5")
    launcher = lane.launcher(out)
    lane.kill_on(launcher, out / "console.log", "ABSD KERNEL BOOT")
    launcher.wait(timeout=60)
    require_row(out, "launched")
    raw, status, log = lane.durable_boot(out, "l5-bypass", kill_on="ABSD KERNEL BOOT")
    disk = sfr.read_disk(out / sfr.IMAGE)
    if disk["slot"]["parsed"] is None or disk["slot"]["parsed"] == "none":
        raise CaseFailed("the killed boot consumed the record")
    require_row(out, "launched")
    launcher = lane.launcher(out)
    run, _ = lane.wait_ready(out, ident)
    if run.returncode != 0:
        raise CaseFailed("the relaunch did not reach readiness")
    require_admission((out / "console.log").read_bytes(), ident, "failed")
    lane.ssh(out, lane.port, "shutdown")
    launcher.wait(timeout=300)
    print("RESUME LAUNCH OK case=l5", flush=True)


def case_l6(lane):
    # (a) the wrapper dies while the recovered machine serves: every mutator
    # still refuses on QEMU's lock; once QEMU is gone, --status classifies
    # from slot, F and records alone: row 10, then none last=consumed.
    out, ident, _ = authorized_image(lane, "l6")
    launcher = lane.launcher(out)
    run, _ = lane.wait_ready(out, ident)
    if run.returncode != 0:
        raise CaseFailed("no readiness")
    qemu = lane.qemu_of(launcher)
    os.kill(launcher.pid, signal.SIGKILL)
    launcher.wait()
    time.sleep(0.5)
    before = snapshot(out)
    run = release(out, "stage", "--release", str(lane.release), "--kernel", str(lane.kernel))
    require_refused_tool(run, "image_locked", before, out, receipt="stage")
    before = snapshot(out)
    run = release(out, "backup", str(out.parent / "backup-while-running"))
    require_refused_tool(run, "image_in_use", before, out)
    os.kill(qemu, signal.SIGKILL)
    time.sleep(1)
    status = require_row(out, "none")
    if f"last=consumed {ident}" not in status or not (out / "recovery" / f"consumed-{ident}.toml").is_file():
        raise CaseFailed("the lost launcher's consumed authorization was not retired by --status")
    lane.note("l6", "status_after_launcher_loss", status)
    # (b) launcher loss before the guest consumed: the wrapper is killed
    # first while its QEMU lives (mutators still refuse image_locked), then
    # the exact QEMU; the record stays launched.
    out, ident, _ = authorized_image(lane, "l6b")
    launcher = lane.launcher(out)
    console = out / "console.log"
    deadline = time.monotonic() + 600
    while b"ABSD KERNEL BOOT" not in launch_console(launcher, console):
        if time.monotonic() > deadline or launcher.poll() is not None:
            raise CaseFailed("the launch never reached ABSD KERNEL BOOT")
        time.sleep(0.05)
    qemu = lane.qemu_of(launcher)
    os.kill(launcher.pid, signal.SIGKILL)
    launcher.wait()
    try:
        os.kill(qemu, 0)
    except ProcessLookupError:
        raise CaseFailed("QEMU did not survive the launcher's loss") from None
    before = snapshot(out)
    run = release(out, "stage", "--release", str(lane.release), "--kernel", str(lane.kernel))
    require_refused_tool(run, "image_locked", before, out, receipt="stage")
    os.kill(qemu, signal.SIGKILL)
    time.sleep(1)
    status = require_row(out, "launched")
    if sfr.read_disk(out / sfr.IMAGE)["slot"]["parsed"] in (None, "none"):
        raise CaseFailed("the record was consumed before the launcher was lost; the leg did not measure its row")
    print("RESUME LAUNCHER LOSS OK case=l6", flush=True)


def case_l7(lane):
    out, ident, _ = authorized_image(lane, "l7")
    # (c) a stale complete console in place before the launch.
    stale = (out.parent / "p0-like-ready.log")
    listener = b"SSH LISTENING port=22 authorized_keys=1 preauth_per_source=4\n"
    (out / "console.log").write_bytes(b"ABSD KERNEL BOOT\nNETWORK LINK OK rx_descriptors=32 tx_descriptors=16 "
                                      b"buffer_bytes=2048\nRECOVERY WRITABLE RESUMED id=" + ident.encode()
                                      + b" previous=failed fs_seq=1 ledger_seq=1\nRELEASE OK release=x\n"
                                      + b"EXTERNAL OUTPUT CHUNK offset=0000000000000000 data=" + listener.hex().encode()
                                      + b"\n")
    if sfr.readiness(sfr.latest_boot((out / "console.log").read_bytes()), ident)[0] != "ready":
        raise CaseFailed("the stale console fixture is not a complete earlier readiness")
    launcher = lane.launcher(out)
    # (a) --timeout 1 against a normal launch: 124, then the full wait: 0.
    run, _ = lane.wait_ready(out, ident, timeout=1)
    if run.returncode != 124:
        raise CaseFailed(f"--timeout 1 exited {run.returncode}, expected 124")
    run, _ = lane.wait_ready(out, ident)
    if run.returncode != 0:
        raise CaseFailed(f"the full wait exited {run.returncode}")
    lane.ssh(out, lane.port, "shutdown")
    launcher.wait(timeout=300)
    # (b) an explicit fixture reaching the guest's resume_mismatch without
    # weakening precheck: a second disk's record transplanted raw, then a
    # launch through durable-boot.sh (precheck bypassed by construction).
    other, other_id, _ = authorized_image(lane, "l7-donor")
    donor = sfr.read_disk(other / sfr.IMAGE)["slot"]["bytes"]
    victim = lane.install("l7-victim")
    serve_and_stop_unclean(lane, "l7-victim", victim)
    disk = sfr.read_disk(victim / sfr.IMAGE)
    with open(victim / sfr.IMAGE, "r+b") as handle:
        handle.seek(disk["slot"]["offset"])
        handle.write(donor)
    # The launcher itself refuses this disk at row 5 (record-unreceipted):
    # the precheck is not weakened by the fixture.
    require_row(victim, "record-unreceipted")
    # W against the refusal: the donor's authorization records make the
    # victim a launched machine whose launch facts (time, console) are
    # recorded *before* the boot that produces the refusal, as the
    # launcher records them; W keeps its console-age check.
    log = victim.parent / "l7b-mismatch.serial.log"
    for name in ("recovery/active.toml", f"recovery/intent-{other_id}.toml"):
        shutil.copyfile(other / name, victim / name)
    active = toml(victim / "recovery" / sfr.ACTIVE)["active"]
    launched = dict(active, state="launched", launch_pid=1, launch_time=sfr.now(),
                    launch_epoch=f"{time.time():.3f}", launch_console=str(log), launches=1)
    sfr.publish(victim / "recovery" / sfr.ACTIVE, sfr.toml_dump({"active": launched}))
    before = sha256_file(victim / sfr.IMAGE)
    raw, status, log = lane.durable_boot(victim, "l7b-mismatch")
    require_state_refusal(raw, status, "resume_mismatch", before, sha256_file(victim / sfr.IMAGE))
    run, _ = lane.wait_ready(victim, other_id, timeout=5)
    if run.returncode != 7 or "RECOVERY STATE REFUSED reason=resume_mismatch" not in run.stdout:
        raise CaseFailed(f"W did not exit 7 with the refusal line: {run.returncode}\n{run.stdout}")
    release(victim, "recover", "--revoke", "--reason", "l7b", check=True)
    print("RESUME WAIT OK case=l7", flush=True)


MUTATORS = ("install --replace", "stage", "select", "rollback", "accept", "restore --replace", "migrate", "remove",
            "discard-import-temp", "release.py reconfigure", "operator_image.py reconfigure (MANIFEST target)",
            "enrollment")


def case_m1(lane):
    out, ident, _ = authorized_image(lane, "m1")
    backup = out.parent / "backup"
    refused = 0
    commands = {
        "install --replace": ["install", "--release", str(lane.release), "--kernel", str(lane.kernel), "--target-identity",
                              "resume-m1", "--replace"],
        "stage": ["stage", "--release", str(lane.release), "--kernel", str(lane.kernel)],
        "select": ["select", "--release", str(lane.release), "--kernel", str(lane.kernel)],
        "rollback": ["rollback"],
        "accept": ["accept", "--key", str(lane.key)],
        "restore --replace": ["restore", str(backup), "--replace"],
        "migrate": ["migrate", "--release", str(lane.release), "--kernel", str(lane.kernel)],
        "remove": ["remove", "--release", str(lane.release), "--kernel", str(lane.kernel), "--id", "other"],
        "discard-import-temp": ["discard-import-temp", "--release", str(lane.release), "--kernel", str(lane.kernel),
                                "--directory", "/tmp/.absd-import-0001", "--fs-id", "1", "--serial", "1", "--bytes", "0",
                                "--sha256", "0" * 64],
    }
    run = release(out, "backup", str(backup), check=True)
    if toml(backup / "backup.toml")["recovery"]["pending_id"] != ident:
        raise CaseFailed("backup.toml does not label the pending authorization")
    for name, words in commands.items():
        # Each invocation against its own baseline: one command's refusal
        # receipt never excuses another's additions.
        before = snapshot(out, "m1-before-" + name.replace(" ", "").replace("--", "-"))
        run = release(out, *words)
        require_refused_tool(run, f"recovery_pending: authorization {ident}", before, out,
                             receipt="stage" if name == "stage" else None)
        refused += 1
    etc = out.parent / "etc"
    etc.mkdir(exist_ok=True)
    (etc / "sshd.conf").write_text("port 22\n")
    # The release-target reconfigure is release.py's (operator_image.py
    # refuses an operator directory of release.py before the boundary).
    reconfigure = ["reconfigure", "--release", str(lane.release), "--kernel", str(lane.kernel), "--etc", str(etc)]
    before = snapshot(out, "m1-before-reconfigure")
    run = release(out, *reconfigure)
    require_refused_tool(run, f"recovery_pending: authorization {ident}", before, out, receipt="reconfigure")
    refused += 1
    # operator_image.py reconfigure keeps its own recovery context on a
    # build-operator-image.sh output: a MANIFEST directory (no TARGET or
    # RELEASES) holding a copy of this disk and its recovery records.
    manifest_out = lane.case_dir("m1-manifest")
    shutil.copyfile(out / sfr.IMAGE, manifest_out / sfr.IMAGE)
    shutil.copytree(out / "recovery", manifest_out / "recovery")
    (manifest_out / "MANIFEST").write_text("platform resume-m1\n")
    before = snapshot(manifest_out, "m1-before-operator-image-reconfigure")
    run = subprocess.run([sys.executable, "-I", str(here / "operator_image.py"), "reconfigure", "--kernel", str(lane.kernel),
                          "--etc", str(etc), str(manifest_out)], capture_output=True, text=True)
    require_refused_tool(run, f"recovery_pending: authorization {ident}", before, manifest_out)
    if (manifest_out / "MANIFEST").read_text() != "platform resume-m1\n":
        raise CaseFailed("the refused operator_image.py reconfigure changed MANIFEST")
    refused += 1
    # Enrollment (absd_try.py enroll) on a preview machine directory holding
    # a copy of this disk and its records, with a manifest load_manifest
    # accepts, so that the refusal is the recovery boundary's.
    machine = lane.machine_dir("m1", out)
    machine_before = snapshot_image(machine / "disk.img", out.parent, "m1-enroll-before")
    run = subprocess.run([sys.executable, "-I", str(here / "absd_try.py"), "enroll", str(machine), "--key",
                          str(lane.key.with_suffix(".pub")), "--accel", lane.accel], capture_output=True, text=True)
    machine_after = snapshot_image(machine / "disk.img", out.parent, "m1-enroll-after-refusal")
    if machine_after != machine_before:
        raise CaseFailed("the refused enrollment changed the machine's disk")
    if run.returncode == 0 or f"recovery_pending" not in run.stderr + run.stdout or "manifest" in run.stderr:
        raise CaseFailed(f"enrollment did not refuse at the recovery boundary:\n{run.stderr}\n{run.stdout}")
    if not (machine / "enroll-console.log").exists():
        pass  # the boundary refused before any boot: no console, as required
    else:
        raise CaseFailed("enrollment booted although the boundary should have refused first")
    refused += 1
    # The intent-only control: the same eleven operations with only an
    # unsuperseded intent (the B3 after-intent state) are not refused by
    # recovery_pending (they may refuse for their own reasons: this disk is
    # unclean). The authorization is revoked first and a slot-none backup
    # taken for restore; restore and install --replace run last.
    release(out, "recover", "--revoke", "--reason", "m1 intent-only control", check=True)
    clean_backup = out.parent / "backup-none"
    release(out, "backup", str(clean_backup), check=True)
    env = dict(os.environ, ABSD_RECOVER_FAULT="after-intent")
    run = release(out, "recover", "--attest-sole-instance", "--accept-committed-state", "--reason", "m1", env=env)
    if run.returncode == 0:
        raise CaseFailed("the after-intent act completed")
    require_row(out, "intent-only")
    commands["restore --replace"] = ["restore", str(clean_backup), "--replace"]
    order = [name for name in commands if name not in ("restore --replace", "install --replace")] + \
        ["restore --replace", "install --replace"]
    not_refused = 0
    for name in order[:-2]:
        run = release(out, *commands[name])
        if "recovery_pending" in run.stderr + run.stdout:
            raise CaseFailed(f"{name} refused recovery_pending with only an intent")
        not_refused += 1
    run = release(out, *reconfigure)
    if "recovery_pending" in run.stderr + run.stdout:
        raise CaseFailed("reconfigure refused recovery_pending with only an intent")
    not_refused += 1
    shutil.rmtree(machine)
    machine = lane.machine_dir("m1-intent", out)
    snapshot_image(machine / "disk.img", out.parent, "m1-intent-enroll-before")
    run = subprocess.run([sys.executable, "-I", str(here / "absd_try.py"), "enroll", str(machine), "--key",
                          str(lane.key.with_suffix(".pub")), "--accel", lane.accel], capture_output=True, text=True,
                         timeout=900)
    snapshot_image(machine / "disk.img", out.parent, f"m1-intent-enroll-after-rc-{run.returncode}")
    if "recovery_pending" in run.stderr + run.stdout:
        raise CaseFailed("enrollment refused recovery_pending with only an intent")
    not_refused += 1
    for name in order[-2:]:
        run = release(out, *commands[name])
        if "recovery_pending" in run.stderr + run.stdout:
            raise CaseFailed(f"{name} refused recovery_pending with only an intent")
        not_refused += 1
    if not_refused != 11:
        raise CaseFailed(f"the intent-only control ran {not_refused} operations, not eleven")
    print(f"RESUME MUTATOR OK case=m1 refused={refused}", flush=True)
    print(f"RESUME MUTATOR NOTE case=m1 intent_only_not_refused={not_refused}", flush=True)


def case_m2(lane):
    out = lane.install("m2")
    # restore validates its backup before the lock: a real backup, taken
    # before the launch, makes the lock the boundary it meets.
    release(out, "backup", str(out.parent / "backup-before"), check=True)
    launcher = lane.launcher(out)
    wait_any_ready(lane, out, launcher)
    before = snapshot(out)
    run = release(out, "backup", str(out.parent / "backup"))
    require_refused_tool(run, "tool_busy", before, out)
    lane.note("m2", "backup_refusal", run.stderr.strip())
    before = snapshot(out)
    run = release(out, "restore", str(out.parent / "backup-before"), "--replace")
    require_refused_tool(run, "tool_busy", before, out)
    lane.note("m2", "restore_refusal", run.stderr.strip())
    # release.py reconfigure (C7) meets the same lock: tool_busy at prepare,
    # with its own refusal receipt and nothing else.
    etc = out.parent / "etc-m2"
    etc.mkdir(exist_ok=True)
    (etc / "sshd.conf").write_text("port 22\n")
    before = snapshot(out, "m2-before-reconfigure")
    run = release(out, "reconfigure", "--release", str(lane.release), "--kernel", str(lane.kernel), "--etc", str(etc))
    require_refused_tool(run, "tool_busy", before, out, receipt="reconfigure")
    lane.note("m2", "reconfigure_refusal", run.stderr.strip())
    lane.ssh(out, lane.port, "shutdown")
    launcher.wait(timeout=300)
    print("RESUME MUTATOR OK case=m2", flush=True)


def case_m3(lane):
    out, ident, _ = authorized_image(lane, "m3")
    clean = lane.install("m3-clean")
    targets = {"a": out, "b": clean}
    for letter, marker in (("c", "TARGET"), ("d", "RELEASES"), ("e", "receipts")):
        directory = lane.case_dir(f"m3-{letter}")
        if marker == "receipts":
            (directory / marker).mkdir()
        else:
            (directory / marker).write_text("x\n")
        targets[letter] = directory
    for letter, directory in targets.items():
        listing = sorted(str(p) for p in directory.rglob("*"))
        before = snapshot(directory)
        run = release(directory, "build", "--kernel", str(lane.kernel), "--id", "resume-m3", "--replace", str(directory))
        require_refused_tool(run, "target_directory", before, directory)
        if sorted(str(p) for p in directory.rglob("*")) != listing:
            raise CaseFailed(f"build removed something from {directory}")
    fresh = lane.case_dir("m3-f")
    run = release(fresh, "build", "--kernel", str(lane.kernel), "--platform", str(lane.root), "--id",
                  release_id_of(lane), str(fresh / "release-dir"))
    if run.returncode != 0 or "RELEASE BUILT" not in run.stdout:
        raise CaseFailed(f"build into a fresh directory failed:\n{run.stderr}")
    run = release(fresh, "build", "--kernel", str(lane.kernel), "--platform", str(lane.root), "--id",
                  release_id_of(lane), "--replace", str(fresh / "release-dir"))
    if run.returncode != 0 or "RELEASE BUILT" not in run.stdout:
        raise CaseFailed(f"rebuild of a release directory failed:\n{run.stderr}")
    lookalike = lane.case_dir("m3-ledger")
    (lookalike / "ledger").write_text("x\n")
    run = release(lookalike, "build", "--kernel", str(lane.kernel), "--platform", str(lane.root), "--id",
                  release_id_of(lane), "--replace", str(lookalike))
    if "target_directory" in run.stderr:
        raise CaseFailed("a file named ledger was taken for the RELEASES marker")
    print("RESUME MUTATOR OK case=m3", flush=True)


def release_id_of(lane, directory=None):
    directory = lane.release if directory is None else directory
    record = directory / "release"
    if record.is_file():
        for line in record.read_text().splitlines():
            if line.startswith("release="):  # absd-release 1: `release=<id>`
                return line.split("=", 1)[1]
    return "dev"


def case_r1a(lane):
    d1, ident, _ = authorized_image(lane, "r1a-d1")
    record = sfr.read_disk(d1 / sfr.IMAGE)["slot"]["bytes"]
    d2 = lane.install("r1a-d2")
    serve_and_stop_unclean(lane, "r1a-d2", d2)
    d3, _, _ = authorized_image(lane, "r1a-d3")
    launcher = lane.launcher(d3)
    run, _ = lane.wait_ready(d3, toml(d3 / "recovery" / sfr.ACTIVE)["active"]["id"])
    if run.returncode != 0:
        raise CaseFailed(f"D3's recovery boot did not reach readiness ({run.returncode}): "
                         + launcher.log_path.read_text(errors="replace")[-1500:])
    lane.ssh(d3, lane.port, "/bin/cat > /home/operator/commit", stdin=b"x\n")
    lane.ssh(d3, lane.port, "/bin/sync")
    os.kill(lane.qemu_of(launcher), signal.SIGKILL)
    launcher.wait(timeout=60)
    for name, out in (("d2", d2), ("d3", d3)):
        disk = sfr.read_disk(out / sfr.IMAGE)
        with open(out / sfr.IMAGE, "r+b") as handle:
            handle.seek(disk["slot"]["offset"])
            handle.write(record)
        before = sha256_file(out / sfr.IMAGE)
        raw, status, log = lane.durable_boot(out, f"r1a-{name}")
        require_state_refusal(raw, status, "resume_mismatch", before, sha256_file(out / sfr.IMAGE))
    print("RESUME REFUSAL OK case=r1a", flush=True)


def case_r1b(lane):
    d1, ident, fs_seq = authorized_image(lane, "r1b")
    copy = d1.parent / "copy"
    release(d1, "backup", str(copy), check=True)
    if toml(copy / "backup.toml")["recovery"]["pending_id"] != ident:
        raise CaseFailed("the copy is not labelled with the pending id")
    shutil.copyfile(d1 / "absd-operator.iso", copy / "absd-operator.iso")
    raw, status, log = lane.durable_boot(copy, "r1b-copy", timeout=lane.timeout + 60, kill_on=LISTENER)
    require_admission(raw, ident, "failed", fs_seq)
    lane.note("r1b", "limit", "a copy carrying R is admitted by the guest exactly like the original (DESIGN-v5 2.3 i)")
    print("RESUME LIMIT RECORDED case=r1b", flush=True)


def served_instance(lane, out):
    """A served boot of `out` that only QEMU holds: durable-boot.sh (its
    default -no-reboot -no-shutdown) in the background with the launcher's
    port forward, console at OUT/console.log. boot-operator.sh would also
    hold OUT/recovery/lock for the run, and `recover` would then refuse
    tool_busy (M2) before it reaches the image's QEMU lock, which R2
    measures."""
    words = subprocess.run([sys.executable, str(here / "operator_image.py"), "endpoint", str(out / sfr.IMAGE)],
                           capture_output=True, text=True, check=True).stdout.split()
    guest, guest_port = words[0], words[1]
    net = ".".join(guest.split(".")[:3]) + ".0/24"
    console = out / "console.log"
    with contextlib.suppress(FileNotFoundError):
        console.unlink()
    argv = [str(lane.kernel / "scripts" / "durable-boot.sh"), str(out / "absd-operator.iso"), str(out / sfr.IMAGE),
            str(console), "600", *served_qemu(lane.qemu), "-rtc", "base=utc", "-netdev",
            f"user,id=n0,net={net},hostfwd=tcp:127.0.0.1:{lane.port}-{guest}:{guest_port}", "-device", "e1000,netdev=n0"]
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, text=True, env=dict(os.environ, ABSD_BLOCK_ATTACH="ata"),
                            start_new_session=True)
    lane.started.append(proc)
    return proc


def case_r2(lane, letter):
    out = lane.install(f"r2{letter}")
    instance = served_instance(lane, out)
    wait_any_ready(lane, out, instance)
    qemu = lane.qemu_of(instance)
    if letter == "b":
        os.kill(qemu, signal.SIGSTOP)
    elif letter == "c":
        lane.ssh(out, lane.port, "reboot")
        # -no-reboot -no-shutdown: the restart becomes a pause; QEMU lives.
        time.sleep(5)
        if instance.poll() is not None:
            raise CaseFailed("QEMU exited on the guest reboot; the stopped instance was not measured")
    before = snapshot(out)
    run = release(out, "recover", "--attest-sole-instance", "--accept-committed-state", "--reason", "r2")
    require_refused_tool(run, "image_locked", before, out)
    lane.note(f"r2{letter}", "refusal", run.stderr.strip())
    # ACCEPTANCE-v5 R2: the holder listed (the OFD refusal names the QEMU).
    if f"holders: pid {qemu} (qemu-system-" not in run.stderr:
        raise CaseFailed(f"image_locked does not list the holder pid {qemu}:\n{run.stderr}")
    if letter == "b":
        os.kill(qemu, signal.SIGCONT)
        lane.ssh(out, lane.port, "shutdown")
        status = instance.communicate(timeout=300)[0].strip()
        if status != "3":
            raise CaseFailed(f"the resumed guest did not halt cleanly: status={status}")
    else:
        os.kill(qemu, signal.SIGKILL)
        instance.communicate(timeout=60)
    print(f"RESUME REFUSAL OK case=r2{letter}", flush=True)


def case_r3a(lane):
    out = lane.install("r3a")
    serve_and_stop_unclean(lane, "r3a", out)
    image = out / sfr.IMAGE
    geo = __import__("absd_fs").geometry(sfr.DEVICE_SECTORS // 2)
    seq = sfr.read_disk(image)["seq"]
    superblock = (sfr.DEVICE_SECTORS // 2 + seq % 2) * 512
    with open(image, "r+b") as handle:
        handle.seek(superblock + 72)
        digest = bytearray(handle.read(32))
        digest[0] ^= 1
        handle.seek(superblock + 72)
        handle.write(digest)
        handle.seek(superblock)
        sector = bytearray(handle.read(512))
        sector[480:] = hashlib.sha256(bytes(sector[:480])).digest()
        handle.seek(superblock)
        handle.write(sector)
    before = snapshot(out)
    run = release(out, "recover", "--attest-sole-instance", "--accept-committed-state", "--reason", "r3a")
    require_refused_tool(run, "host_reader_refused", before, out)
    require_row(out, "slot-unreadable")
    before = sha256_file(image)
    raw, status, log = lane.durable_boot(out, "r3a-guest")
    fence_guest.require_refusal(raw, status, "failed", "not_declared", allow_corrupt=True)
    if before != sha256_file(image):
        raise CaseFailed("the refused boot changed the image")
    print("RESUME REFUSAL OK case=r3a", flush=True)


def case_r3b(lane):
    out = lane.install("r3b")
    serve_and_stop_unclean(lane, "r3b", out)
    image = out / sfr.IMAGE
    import absd_fs
    region = absd_fs.fs_region(image, sfr.DEVICE_SECTORS)
    selected = absd_fs.select(region)
    geo = selected["geometry"]
    half = (region.first + absd_fs.META_FIRST + (selected["seq"] % 2) * geo["half_sectors"]) * 512
    image_len = absd_fs.superblock(region.read(selected["seq"] % 2), selected["seq"] % 2, geo)["image_len"]
    import struct
    with open(image, "r+b") as handle:
        handle.seek(half)
        raw = bytearray(handle.read(image_len))
        # Duplicate a block reference: the first file's first block into the second file's.
        offset = absd_fs.HEADER_BYTES
        files = []
        for _ in range(len(selected["records"])):
            serial, parent, size, kind, flags, name_len, block_count = struct.unpack_from("<QQQBBHI", raw, offset)
            at = offset + 40 + name_len
            if kind == 1 and block_count:
                files.append(at)
            offset = at + 4 * block_count
        if len(files) < 2:
            raise CaseFailed("the fixture needs two files with blocks")
        raw[files[1]:files[1] + 4] = raw[files[0]:files[0] + 4]
        handle.seek(half)
        handle.write(raw)
        superblock = (region.first + selected["seq"] % 2) * 512
        handle.seek(superblock)
        sector = bytearray(handle.read(512))
        sector[72:104] = hashlib.sha256(bytes(raw)).digest()
        sector[480:] = hashlib.sha256(bytes(sector[:480])).digest()
        handle.seek(superblock)
        handle.write(sector)
    before = snapshot(out)
    run = release(out, "recover", "--attest-sole-instance", "--accept-committed-state", "--reason", "r3b")
    require_refused_tool(run, "host_reader_refused", before, out)
    if "block reference" not in run.stderr:
        raise CaseFailed(f"the reader did not name the duplicate block: {run.stderr}")
    before = sha256_file(image)
    raw, status, log = lane.durable_boot(out, "r3b-guest")
    fence_guest.require_refusal(raw, status, "failed", "not_declared", allow_corrupt=True)
    if before != sha256_file(image):
        raise CaseFailed("the refused boot changed the image")
    print("RESUME REFUSAL OK case=r3b", flush=True)


def case_r3c(lane):
    # The ledger, init marker and state directory are files of the
    # filesystem: the fixtures are raw edits of their data blocks, found
    # through the host reader's allocation.
    import absd_fs
    for sub, reason, guest_reason in (("i", "corrupt", "corrupt"), ("ii", "lost", "lost"),
                                      ("iii", "uninitialized_ledger", "uninitialized_ledger"),
                                      ("iv", "first_boot_interrupted", None)):
        out = lane.install(f"r3c-{sub}")
        if sub != "iv":
            serve_and_stop_unclean(lane, f"r3c-{sub}", out)
        image = out / sfr.IMAGE
        region = absd_fs.fs_region(image, sfr.DEVICE_SECTORS)
        selected = absd_fs.select(region)
        tree = absd_fs.tree(region, selected)
        geo = selected["geometry"]

        def block_offset(path):
            record = tree[path]
            return (region.first + geo["data_first"] + record["blocks"][0] * 8) * 512

        if sub == "i":
            offset = block_offset("/var/state/recovery")
            with open(image, "r+b") as handle:
                handle.seek(offset)
                data = bytearray(handle.read(128))
                data[data.index(b"fnv=") + 5] ^= 1
                handle.seek(offset)
                handle.write(data)
        elif sub == "iv":
            # Install leaves fresh; a dirty guard with no /var/state is the
            # interrupted first start: arm the guard raw.
            with open(image, "r+b") as handle:
                handle.seek(block_offset(guard.PATH))
                handle.write(guard.encode("dirty"))
        else:
            # (ii) ledger absent, (iii) init absent: the record is renamed
            # out of /var/state by rewriting its parent to the root (a
            # structurally valid namespace: a top-level file).
            path = "/var/state/recovery" if sub == "ii" else "/var/state/recovery.init"
            half = (region.first + absd_fs.META_FIRST + (selected["seq"] % 2) * geo["half_sectors"]) * 512
            sb = absd_fs.superblock(region.read(selected["seq"] % 2), selected["seq"] % 2, geo)
            with open(image, "r+b") as handle:
                handle.seek(half)
                raw = bytearray(handle.read(sb["image_len"]))
                offset = absd_fs.HEADER_BYTES
                import struct
                for record in selected["records"]:
                    serial, parent, size, kind, flags, name_len, block_count = struct.unpack_from("<QQQBBHI", raw, offset)
                    if serial == tree[path]["serial"]:
                        new_name = (b"recovery.moved" if sub == "ii" else b"recovery.init.moved")[:name_len].ljust(name_len, b"x")
                        struct.pack_into("<Q", raw, offset + 8, 1)
                        raw[offset + 40:offset + 40 + name_len] = new_name
                        break
                    offset += 40 + name_len + 4 * block_count
                handle.seek(half)
                handle.write(raw)
                superblock = (region.first + selected["seq"] % 2) * 512
                handle.seek(superblock)
                sector = bytearray(handle.read(512))
                sector[72:104] = hashlib.sha256(bytes(raw)).digest()
                sector[480:] = hashlib.sha256(bytes(sector[:480])).digest()
                handle.seek(superblock)
                handle.write(sector)
        before = snapshot(out)
        run = release(out, "recover", "--attest-sole-instance", "--accept-committed-state", "--reason", "r3c")
        want = "recovery_state_refused" if sub != "iv" else "first_boot_interrupted"
        require_refused_tool(run, want, before, out)
        if sub != "iv" and reason not in run.stderr:
            raise CaseFailed(f"the tool did not name {reason}: {run.stderr}")
        before = sha256_file(image)
        raw, status, log = lane.durable_boot(out, f"r3c-{sub}-guest")
        if guest_reason:
            require_state_refusal(raw, status, guest_reason, before, sha256_file(image))
        else:
            fence_guest.require_refusal(raw, status, "none", "not_declared")
    print("RESUME REFUSAL OK case=r3c", flush=True)


def release_iso(lane, options, server="absd-fsd.elf"):
    """A boot image of the lane release's own programs with other durable
    options (`net fsd` plain, `storage-fence=external`) or the regenerate
    file server, built by the kernel copy as storage_fence_guest.cold_boot
    builds its ISOs."""
    spec = importlib.util.spec_from_file_location("operator_image_for_resume", here / "operator_image.py")
    oi = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oi)
    work = lane.work / "iso-work"
    work.mkdir(exist_ok=True)
    built = oi.kernel_iso(lane.kernel, 0, lane.release / "sshd.elf", options=options, server=lane.release / server,
                         work=work, logger=lane.release / "absd-logd.elf")
    kept = work / (options.replace(" ", "-").replace("=", "-") + "-" + server + ".iso")
    shutil.copyfile(built, kept)
    return kept


def case_r4a(lane):
    # R exactly as storage-fence-matrix.py ata-undeclared: the served cold
    # boot, the plain `net fsd` boot, the `storage-fence=external` retry and
    # the regenerate program's retry are all refused with zero writes.
    out = lane.install("r4a")
    serve_and_stop_unclean(lane, "r4a", out)
    raw, status, log = lane.durable_boot(out, "r4a-served")
    fence_guest.require_served_successor_refusal(raw, status)
    raw, status, log = lane.durable_boot(out, "r4a-plain", iso=release_iso(lane, "net fsd"))
    fence_guest.require_refusal(raw, status, "failed")
    raw, status, log = lane.durable_boot(out, "r4a-external", iso=release_iso(lane, "net fsd served storage-fence=external"))
    fence_guest.require_refusal(raw, status, "failed", "external_unverified")
    raw, status, log = lane.durable_boot(out, "r4a-regenerate",
                                         iso=release_iso(lane, "net fsd served", "absd-fsd-regenerate.elf"))
    fence_guest.require_refusal(raw, status, "failed")
    print("RESUME REFUSAL OK case=r4a", flush=True)


def case_r4b(lane):
    out = lane.install("r4b")
    serve_and_stop_unclean(lane, "r4b", out)
    image = out / sfr.IMAGE
    record = sfr.read_disk(image)
    good = guard.encode_resume({"id": "a" * 32, "fs": record["fs_id"], "seq": record["seq"], "image": record["image"],
                                "ledger_seq": 3, "ledger_boot": "0" * 32, "previous": "failed", "time": 1})
    bad_fnv = bytearray(good)
    bad_fnv[good.index(b"fnv=") + 5] ^= 1
    forged = [bytes(bad_fnv), good.replace(b"v1", b"v2", 1), good.replace(b" seq=", b" sq=", 1),
              good[:good.index(b"\n") + 1] + b"x" + good[good.index(b"\n") + 2:],
              (ROOT / "fixtures/storage-fence/resume-v1-torn-40.bin").read_bytes(),
              (ROOT / "fixtures/storage-fence/resume-v1-torn-200.bin").read_bytes()]
    for index, bytes_ in enumerate(forged):
        with open(image, "r+b") as handle:
            handle.seek(sfr.read_disk(image)["slot"]["offset"] if index == 0 else record["slot"]["offset"])
            handle.write(bytes_)
        require_row(out, "corrupt-slot")
        before = sha256_file(image)
        raw, status, log = lane.durable_boot(out, f"r4b-{index}")
        require_state_refusal(raw, status, "resume_corrupt", before, sha256_file(image))
        run = release(out, "recover", "--revoke", "--reason", "forged", check=True)
        if "revoked_corrupt" not in run.stdout:
            raise CaseFailed("--revoke did not report revoked_corrupt")
        if sfr.read_disk(image)["slot"]["parsed"] != "none":
            raise CaseFailed("--revoke did not rewrite none")
    recover(lane, "r4b", out)
    print("RESUME REFUSAL OK case=r4b", flush=True)


def case_r4d(lane):
    out, ident, _ = authorized_image(lane, "r4d")
    image = out / sfr.IMAGE
    disk = sfr.read_disk(image)
    saved = disk["slot"]["bytes"]
    launcher = lane.launcher(out)
    run, _ = lane.wait_ready(out, ident)
    if run.returncode != 0:
        raise CaseFailed("no readiness")
    os.kill(lane.qemu_of(launcher), signal.SIGKILL)
    launcher.wait(timeout=60)
    with open(image, "r+b") as handle:
        handle.seek(disk["slot"]["offset"])
        handle.write(saved)
    before = sha256_file(image)
    raw, status, log = lane.durable_boot(out, "r4d-replay")
    require_state_refusal(raw, status, "resume_mismatch", before, sha256_file(image))
    print("RESUME REFUSAL OK case=r4d", flush=True)


def case_r4f(lane):
    out, ident, _ = authorized_image(lane, "r4f")
    image = out / sfr.IMAGE
    before = sha256_file(image)
    # The finalizer: the release ISO run with --finalize is init's own
    # continuation; a cold boot of the finalize program on a dirty disk is
    # refused by the guard (GuardCorrupt): the kernel's finalize entry is
    # not separately bootable, so this leg is the enrollment image and the
    # host transaction; the finalizer leg is covered by cargo test (R4f).
    # The enrollment program (Resume::Never) on the authorized disk, driven
    # as enroll-matrix.py drives it (the key stream over the console socket):
    # refused by the guard before any write; the image stays as it was. The
    # leg is mandatory.
    spec = importlib.util.spec_from_file_location("enroll_matrix_for_resume", here / "enroll-matrix.py")
    enroll = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(enroll)
    payload = enroll.stream(enroll.record(enroll.KEYS, lane.key.with_suffix(".pub").read_bytes()))
    enroll_iso = lane.enroll_iso()
    # The primary artifacts of the enrollment leg: retained before and after.
    before_enroll = snapshot(out, "before-enrollment")
    status, raw, killed = enroll.boot_enroll(enroll_iso, image, out.parent / "r4f-enroll.serial.log", payload)
    after_enroll = snapshot(out, f"after-enrollment-status-{status}")
    for key in ("slot", "hm", "f", "image_sha256", "guard", "files"):
        if after_enroll[key] != before_enroll[key]:
            raise CaseFailed(f"the refused enrollment changed {key}")
    text = enroll.worker_text(raw)
    if status != 7 or killed or "ENROLL OK" in text or "ENROLL REFUSED reason=writable-guard" not in text:
        raise CaseFailed(f"enrollment did not refuse the authorized image: status={status} killed={killed}\n{text[-800:]}")
    if sha256_file(image) != before:
        raise CaseFailed("the refused enrollment changed the image")
    before_snapshot = after_enroll
    run = release(out, "stage", "--release", str(lane.release), "--kernel", str(lane.kernel))
    require_refused_tool(run, "recovery_pending", before_snapshot, out, receipt="stage")
    if sfr.read_disk(image)["slot"]["parsed"]["id"] != ident or before != sha256_file(image):
        raise CaseFailed("the record did not survive the refused writers")
    print("RESUME REFUSAL OK case=r4f", flush=True)


def case_b2(lane):
    for previous in ("failed", "not_ready"):
        for needle, expect in (("ABSD KERNEL BOOT", "intact"), ("RECOVERY WRITABLE RESUMED", "consumed"),
                               ("FSD RECOVERY seq=", "consumed"), ("FSD READY", "consumed")):
            name = f"b2-{previous}-{needle.split()[0].lower()}-{needle.split()[-1].lower().rstrip('=')}"
            out, ident, _ = authorized_image(lane, name, previous)
            launcher = lane.launcher(out)
            lane.kill_on(launcher, out / "console.log", needle)
            launcher.wait(timeout=60)
            console = (out / "console.log").read_bytes()
            if b"FSD READY" in console and b"RECOVERY WRITABLE RESUMED" not in console:
                raise CaseFailed("FSD READY without a preceding RESUMED")
            disk = sfr.read_disk(out / sfr.IMAGE)
            if expect == "intact":
                if disk["slot"]["parsed"] == "none" or disk["slot"]["parsed"] is None:
                    raise CaseFailed("the record did not survive a kill at ABSD KERNEL BOOT")
                require_row(out, "launched")
                launcher = lane.launcher(out)
                run, _ = lane.wait_ready(out, ident)
                if run.returncode != 0:
                    raise CaseFailed("the relaunch did not reach readiness")
                require_admission((out / "console.log").read_bytes(), ident, previous)
                lane.ssh(out, lane.port, "shutdown")
                launcher.wait(timeout=300)
            else:
                if disk["slot"]["parsed"] != "none":
                    raise CaseFailed("the killed boot left the record")
                # The expected assessment is derived from the landed ledger
                # and matching facts (Codex v5 change 1), not from p.
                state = sfr.recovery_state(disk["files"], disk["guard"])
                raw, status, log = lane.durable_boot(out, f"{name}-refused")
                require_served_refusal(raw, status, state["previous"])
                lane.note(name, "assessment", state["previous"])
                status_text = require_row(out, "none")
                if f"last=consumed {ident}" not in status_text:
                    raise CaseFailed("row 10 retirement did not happen")
    print("RESUME INTERRUPT OK case=b2", flush=True)


B3_STEPS = ("after-intent", "short-write:8", "short-write:40", "short-write:120", "short-write:200", "short-write:400",
            "after-pwrite", "fsync-fail", "after-slot", "after-active")


def case_b3(lane):
    for step in B3_STEPS:
        name = "b3-" + step.replace(":", "-")
        out = lane.install(name)
        serve_and_stop_unclean(lane, name, out)
        env = dict(os.environ, ABSD_RECOVER_FAULT=step)
        run = release(out, "recover", "--attest-sole-instance", "--accept-committed-state", "--reason", "b3", env=env)
        if run.returncode == 0:
            raise CaseFailed(f"the act completed under fault {step}")
        if step in ("after-intent", "short-write:8"):
            require_row(out, "intent-only")
            recover(lane, name, out)
        elif step in ("short-write:40", "short-write:120", "short-write:200"):
            require_row(out, "corrupt-slot")
            before = sha256_file(out / sfr.IMAGE)
            raw, status, log = lane.durable_boot(out, f"{name}-guest")
            require_state_refusal(raw, status, "resume_corrupt", before, sha256_file(out / sfr.IMAGE))
            release(out, "recover", "--revoke", "--reason", "b3", check=True)
            recover(lane, name, out)
        else:
            status = release(out, "recover", "--status", check=True)
            require_row(out, "authorized")
            if step == "after-active" and "recovered" not in (out / sfr.LEDGER).read_text():
                raise CaseFailed("the ledger line was not reconciled")
    print("RESUME INTERRUPT OK case=b3 steps=10", flush=True)


def case_b4(lane):
    out, ident, _ = authorized_image(lane, "b4")
    launcher = lane.launcher(out)
    run, _ = lane.wait_ready(out, ident)
    if run.returncode != 0:
        raise CaseFailed("no readiness")
    lane.ssh(out, lane.port, "/bin/cat > /home/operator/second", stdin=b"second\n")
    lane.ssh(out, lane.port, "/bin/sync")
    os.kill(lane.qemu_of(launcher), signal.SIGKILL)
    launcher.wait(timeout=60)
    raw, status, log = lane.durable_boot(out, "b4-refused")
    fence_guest.require_served_successor_refusal(raw, status)
    second, _, _ = recover(lane, "b4", out)
    if second == ident:
        raise CaseFailed("the second act reused the id")
    launcher = lane.launcher(out)
    run, _ = lane.wait_ready(out, second)
    require_admission((out / "console.log").read_bytes(), second, "failed")
    lane.ssh(out, lane.port, "shutdown")
    launcher.wait(timeout=300)
    if sfr.read_disk(out / sfr.IMAGE)["guard"] != "clean":
        raise CaseFailed("the guard is not clean")
    print("RESUME REPEAT OK case=b4 acts=2", flush=True)


def case_b5(lane):
    # (a) a flipped data byte; (b1) pre-authorization copy; (b2) post-
    # authorization copy; (c) cp + rename. Through the launcher first, then
    # bypassing it.
    import absd_fs
    outcomes = {}
    for sub in ("a", "b1", "b2", "c"):
        out = lane.install(f"b5-{sub}")
        serve_and_stop_unclean(lane, f"b5-{sub}", out)
        pre = out.parent / "pre"
        release(out, "backup", str(pre), check=True)
        ident, _, _ = recover(lane, f"b5-{sub}", out)
        post = out.parent / "post"
        release(out, "backup", str(post), check=True)
        image = out / sfr.IMAGE
        if sub == "a":
            region = absd_fs.fs_region(image, sfr.DEVICE_SECTORS)
            selected = absd_fs.select(region)
            record = absd_fs.tree(region, selected)["/home/operator/F1"]
            offset = (region.first + selected["geometry"]["data_first"] + record["blocks"][0] * 8) * 512
            with open(image, "r+b") as handle:
                handle.seek(offset)
                byte = handle.read(1)
                handle.seek(offset)
                handle.write(bytes([byte[0] ^ 1]))
            launcher_row, launcher_reason = "mismatch", "recovery_image_changed (hm)"
        elif sub == "b1":
            shutil.copyfile(pre / sfr.IMAGE, out.parent / "b1.img")
            (out.parent / "b1.img").replace(image)
            launcher_row, launcher_reason = "replaced", "recovery_image_replaced F="
        elif sub == "b2":
            shutil.copyfile(post / sfr.IMAGE, out.parent / "b2.img")
            (out.parent / "b2.img").replace(image)
            launcher_row, launcher_reason = "mismatch", "recovery_image_changed (F)"
        else:
            shutil.copyfile(image, out.parent / "c.img")
            (out.parent / "c.img").replace(image)
            launcher_row, launcher_reason = "mismatch", "recovery_image_changed (F)"
        status = require_row(out, launcher_row)
        if launcher_reason not in status:
            raise CaseFailed(f"{sub}: --status does not name {launcher_reason}:\n{status}")
        launcher = subprocess.run([str(here / "boot-operator.sh"), str(out), str(lane.port)], capture_output=True,
                                  text=True, env=lane.env)
        if launcher.returncode != 7:
            raise CaseFailed(f"{sub}: the launcher did not refuse")
        # Bypassing the launcher.
        before = sha256_file(image)
        raw, status_word, log = lane.durable_boot(out, f"b5-{sub}-bypass", timeout=lane.timeout + 60,
                                                  kill_on=LISTENER if sub != "b1" else None)
        if sub == "b1":
            fence_guest.require_served_successor_refusal(raw, status_word)
            if b"resume_mismatch" in raw:
                raise CaseFailed("b1 was refused as resume_mismatch, expected the ordinary fence refusal")
            run = release(out, "recover", "--revoke", "--reason", "b5", check=True)
            archive = toml(out / "recovery" / f"revoked-{ident}.toml")["archive"]
            if archive["disposition"] != "image_replaced":
                raise CaseFailed("the archive does not carry reason=image_replaced")
            require_row(out, "none")
        else:
            require_admission(raw, ident, "failed")
            outcomes[sub] = "admitted (limit recorded)"
    lane.note("b5", "limits", outcomes)
    print("RESUME INTERRUPT OK case=b5", flush=True)


def case_b6(lane):
    out, ident, _ = authorized_image(lane, "b6")
    launcher = lane.launcher(out)
    run, _ = lane.wait_ready(out, ident)
    if run.returncode != 0:
        raise CaseFailed(f"no readiness ({run.returncode}): " + launcher.log_path.read_text(errors="replace")[-1500:])
    lane.ssh(out, lane.port, "shutdown")
    launcher.wait(timeout=300)
    consumed = [ident]
    for _ in range(2):
        launcher = lane.launcher(out)
        wait_any_ready(lane, out, launcher)
        lane.ssh(out, lane.port, "shutdown")
        launcher.wait(timeout=300)
        status = require_row(out, "none")
        if f"last=consumed {ident}" not in status:
            raise CaseFailed("a later status forgot the consumed act")
    launcher = lane.launcher(out)
    wait_any_ready(lane, out, launcher)
    os.kill(lane.qemu_of(launcher), signal.SIGKILL)
    launcher.wait(timeout=60)
    second, _, _ = recover(lane, "b6", out)
    consumed.append(second)
    # Consumption through durable-boot.sh with active still authorized.
    raw, status_word, log = lane.durable_boot(out, "b6-bypass", timeout=lane.timeout + 60, kill_on=LISTENER)
    require_admission(raw, second, "failed")
    status = require_row(out, "none")
    archive = toml(out / "recovery" / f"consumed-{second}.toml")["archive"]
    if archive["disposition"] != "consumed_unwitnessed":
        raise CaseFailed("the bypassed consumption is not consumed_unwitnessed")
    if len(list((out / "recovery").glob("consumed-*.toml"))) != 2:
        raise CaseFailed("not one consumed archive per act")
    print("RESUME PENDING OK case=b6", flush=True)


def case_b7(lane):
    # The host unit tests (test_storage_fence_resume.py B7) cover every
    # record shape on built images; here the same shapes on a real
    # installed disk, through the command line.
    out, ident, _ = authorized_image(lane, "b7")
    for name in (sfr.ACTIVE, f"intent-{ident}.toml"):
        (out / "recovery" / name).unlink()
    require_row(out, "record-unreceipted")
    release(out, "recover", "--revoke", "--reason", "b7", check=True)
    ident, _, _ = recover(lane, "b7", out)
    (out / "recovery" / sfr.ACTIVE).write_text("[active\n")
    require_row(out, "corrupt-receipt")
    release(out, "recover", "--revoke", "--reason", "b7", check=True)
    (out / "recovery" / sfr.ACTIVE).write_text("[active\n")
    require_row(out, "none")
    ident, _, _ = recover(lane, "b7", out)
    launcher = lane.launcher(out)
    run, _ = lane.wait_ready(out, ident)
    if run.returncode != 0:
        raise CaseFailed(f"no readiness ({run.returncode}): " + launcher.log_path.read_text(errors="replace")[-1500:])
    lane.ssh(out, lane.port, "shutdown")
    launcher.wait(timeout=300)
    status = require_row(out, "none")
    if f"last=consumed {ident}" not in status:
        raise CaseFailed("the consumed act is not the last")
    print("RESUME RECORDS OK case=b7", flush=True)


def case_s1(lane):
    """Slot preservation across all seven operations: a served boot and
    halt, reconfigure, stage (the other release), select, rollback (cached),
    remove, and enrollment through absd_try.py with the real enroll image."""
    if lane.other is None:
        raise CaseFailed("s1 needs --other-release (run-storage-fence-resume.sh builds it)")
    out = lane.install("s1", probe=False)
    identity = sfr.read_disk(out / sfr.IMAGE)["slot"]["identity"]
    ops = []

    def check(op):
        after = sfr.read_disk(out / sfr.IMAGE)["slot"]
        if after["identity"] != identity or after["parsed"] != "none":
            raise CaseFailed(f"the slot's identity or bytes changed after {op}")
        ops.append(op)
    launcher = lane.launcher(out)
    wait_any_ready(lane, out, launcher)
    lane.ssh(out, lane.port, "shutdown")
    launcher.wait(timeout=300)
    check("served-boot-halt")
    etc = out.parent / "etc"
    etc.mkdir()
    (etc / "sshd.conf").write_text("port 22\n")
    # A release target is reconfigured by release.py reconfigure, with the
    # selected release's importer (no MANIFEST is supplied).
    run = release(out, "reconfigure", "--release", str(lane.release), "--kernel", str(lane.kernel), "--etc", str(etc))
    if run.returncode != 0:
        raise CaseFailed(f"reconfigure failed:\n{run.stderr}")
    check("reconfigure")
    release(out, "accept", "--key", str(lane.key), "--port", str(lane.port), check=True)
    accept_ok = sfr.read_disk(out / sfr.IMAGE)["slot"]
    if accept_ok["identity"] != identity or accept_ok["parsed"] != "none":
        raise CaseFailed("the slot's identity or bytes changed after accept")
    release(out, "stage", "--release", str(lane.other), "--kernel", str(lane.kernel), check=True)
    check("stage")
    release(out, "select", "--release", str(lane.other), "--kernel", str(lane.kernel), check=True)
    check("select")
    release(out, "rollback", check=True)
    check("rollback")
    release(out, "remove", "--release", str(lane.release), "--kernel", str(lane.kernel), "--id", release_id_of(lane, lane.other),
            check=True)
    check("remove")
    machine = lane.machine_dir("s1", out)
    key = out.parent / "s1-key.pub"
    key.write_bytes(lane.key.with_suffix(".pub").read_bytes())
    snapshot_image(machine / "disk.img", out.parent, "s1-enroll-before")
    run = subprocess.run([sys.executable, "-I", str(here / "absd_try.py"), "enroll", str(machine), "--key", str(key),
                          "--accel", lane.accel], capture_output=True, text=True, timeout=900)
    snapshot_image(machine / "disk.img", out.parent, f"s1-enroll-after-rc-{run.returncode}")
    if run.returncode != 0 or "ENROLLED" not in run.stdout:
        raise CaseFailed(f"enrollment failed:\n{run.stderr}\n{run.stdout}")
    after = sfr.read_disk(machine / "disk.img")["slot"]
    if after["identity"] != identity or after["parsed"] != "none":
        raise CaseFailed("the slot's identity or bytes changed after enrollment")
    ops.append("enrollment")
    if len(ops) != 7:
        raise CaseFailed(f"S1 ran {ops}, not the seven operations of ACCEPTANCE-v5")
    lane.note("s1", "operations", ops + ["accept (additional, reported separately)"])
    print(f"RESUME SLOT OK case=s1 ops={len(ops)}", flush=True)
    print("RESUME SLOT NOTE case=s1 additional=accept slot_unchanged=true", flush=True)


def move_record_to_root(image, path, new_leaf):
    """A raw, re-signed metadata edit: the record of `path` reparented to
    the root under `new_leaf` (the namespace stays structurally valid), so
    that a clean image without the slot (or the guard) can be made from
    an install: the previous release's layouts are not inputs of this lane."""
    import absd_fs
    import struct
    region = absd_fs.fs_region(image, sfr.DEVICE_SECTORS)
    selected = absd_fs.select(region)
    geo = selected["geometry"]
    slot = selected["seq"] % 2
    length = absd_fs.superblock(region.read(slot), slot, geo)["image_len"]
    half = (region.first + absd_fs.META_FIRST + slot * geo["half_sectors"]) * 512
    serial = absd_fs.tree(region, selected)[path]["serial"]
    with open(image, "r+b") as handle:
        handle.seek(half)
        raw = bytearray(handle.read(length))
        offset = absd_fs.HEADER_BYTES
        for _ in range(len(selected["records"])):
            found, parent, size, kind, flags, name_len, block_count = struct.unpack_from("<QQQBBHI", raw, offset)
            if found == serial:
                if len(new_leaf) != name_len:
                    raise CaseFailed("the new leaf must keep the record's name length")
                struct.pack_into("<Q", raw, offset + 8, 1)
                raw[offset + 40:offset + 40 + name_len] = new_leaf
                break
            offset += 40 + name_len + 4 * block_count
        handle.seek(half)
        handle.write(raw)
        superblock = (region.first + slot) * 512
        handle.seek(superblock)
        sector = bytearray(handle.read(512))
        sector[72:104] = hashlib.sha256(bytes(raw)).digest()
        sector[480:] = hashlib.sha256(bytes(sector[:480])).digest()
        handle.seek(superblock)
        handle.write(sector)


# Replacement leaves of the same length as the records they rename
# (move_record_to_root keeps the name length): 15 and 14 bytes.
SLOT_AWAY = b"recovery.moved1"
GUARD_AWAY = b"recovery.gmovd"
assert len(SLOT_AWAY) == len(guard.RESUME_PATH.rsplit("/", 1)[1]) == 15
assert len(GUARD_AWAY) == len(guard.PATH.rsplit("/", 1)[1]) == 14


def require_shape(image, *, slot, guard):
    """The fixture is what S2 measures: slot and guard present or absent
    at their paths, the moved records under the root, the reader content."""
    disk = sfr.read_disk(image)
    if (disk["slot"] is not None) != slot:
        raise CaseFailed(f"the slot is {'absent' if slot else 'still present'} at {guard_path(True)}")
    if disk["guard_missing"] == guard:
        raise CaseFailed(f"the guard is {'absent' if guard else 'still present'} at {guard_path(False)}")
    if not slot and "/" + SLOT_AWAY.decode() not in disk["records"]:
        raise CaseFailed("the moved slot record is not under the root")
    if not guard and "/" + GUARD_AWAY.decode() not in disk["records"]:
        raise CaseFailed("the moved guard record is not under the root")


def guard_path(slot):
    return guard.RESUME_PATH if slot else guard.PATH


def case_s2(lane):
    """Slot-less staging and conversion. (a) a clean image without a slot
    (the slot record moved out of /var) gets one from `stage`
    (`resume_slot = "added"`); (b) a dirty slot-less image is refused by
    `stage`; (c) the legacy converter on a clean guard-less, slot-less disk
    (made from a clean halt by moving both records out) seeds guard and
    slot and passes its widened comparisons; (d) a source holding a slot is
    refused by the converter."""
    if lane.other is None:
        raise CaseFailed("s2 needs --other-release (run-storage-fence-resume.sh builds it)")
    # (a)
    out = lane.install("s2a", probe=False)
    move_record_to_root(out / sfr.IMAGE, guard.RESUME_PATH, SLOT_AWAY)
    require_shape(out / sfr.IMAGE, slot=False, guard=True)
    run = release(out, "stage", "--release", str(lane.other), "--kernel", str(lane.kernel), check=True)
    disk = sfr.read_disk(out / sfr.IMAGE)
    if disk["slot"] is None or disk["slot"]["parsed"] != "none":
        raise CaseFailed("stage did not add the slot as none")
    receipt = sorted((out / "receipts").glob("stage-*.toml"))[-1].read_text()
    if 'resume_slot = "added"' not in receipt:
        raise CaseFailed("the stage receipt does not record resume_slot = added")
    # (b)
    out = lane.install("s2b", probe=False)
    move_record_to_root(out / sfr.IMAGE, guard.RESUME_PATH, SLOT_AWAY)
    require_shape(out / sfr.IMAGE, slot=False, guard=True)
    with open(out / sfr.IMAGE, "r+b") as handle:
        import absd_fs
        region = absd_fs.fs_region(out / sfr.IMAGE, sfr.DEVICE_SECTORS)
        selected = absd_fs.select(region)
        record = absd_fs.tree(region, selected)[guard.PATH]
        handle.seek((region.first + selected["geometry"]["data_first"] + record["blocks"][0] * 8) * 512)
        handle.write(guard.encode("dirty"))
    before = snapshot_slotless(out, "before-dirty-slotless-stage")
    run = release(out, "stage", "--release", str(lane.other), "--kernel", str(lane.kernel))
    if run.returncode == 0 or "unclean" not in run.stderr:
        raise CaseFailed(f"stage did not refuse the dirty slot-less image:\n{run.stderr}")
    if snapshot_slotless(out, "after-dirty-slotless-stage") != before:
        raise CaseFailed("the refused stage changed the image")
    # (c) and (d)
    out = lane.install("s2c", probe=False)
    launcher = lane.launcher(out)
    wait_any_ready(lane, out, launcher)
    lane.ssh(out, lane.port, "shutdown")
    launcher.wait(timeout=300)
    console = (out / "console.log").read_text(errors="replace")
    legacy = out.parent / "legacy.img"
    shutil.copyfile(out / sfr.IMAGE, legacy)
    work = out.parent / "convert-work"
    converter = [sys.executable, "-I", str(here / "seed-writable-guard.py"), "--clean-console", str(out / "console.log"),
                 "--kernel", str(lane.kernel), "--attest-no-writes-since-halt"]
    # (d) a source holding a slot (and a guard) is refused.
    run = subprocess.run([*converter, "--source", str(out / sfr.IMAGE), "--output", str(out.parent / "refused.img"),
                          "--work", str(out.parent / "refused-work"), "--halt-image-sha256", sha256_file(out / sfr.IMAGE)],
                         capture_output=True, text=True)
    if run.returncode == 0 or "existing guard" not in run.stderr + run.stdout:
        raise CaseFailed(f"the converter did not refuse a source holding the slot:\n{run.stderr}")
    move_record_to_root(legacy, guard.RESUME_PATH, SLOT_AWAY)
    move_record_to_root(legacy, guard.PATH, GUARD_AWAY)
    require_shape(legacy, slot=False, guard=False)
    halt_hash = sha256_file(legacy)
    run = subprocess.run([*converter, "--source", str(legacy), "--output", str(out.parent / "converted.img"),
                          "--work", str(work), "--halt-image-sha256", halt_hash], capture_output=True, text=True)
    if run.returncode != 0 or "GUARD CONVERSION PREPARED_UNACTIVATED" not in run.stdout:
        raise CaseFailed(f"the converter failed:\n{run.stderr}\n{run.stdout}")
    converted = sfr.read_disk(out.parent / "converted.img")
    if converted["guard"] != "clean" or converted["slot"] is None or converted["slot"]["parsed"] != "none":
        raise CaseFailed("the converted disk does not carry a clean guard and a none slot")
    print("RESUME SLOT OK case=s2", flush=True)


def snapshot_slotless(out, label):
    """What S2(b) compares (the image and the record names), taken through
    the retained snapshot so the before/after artifacts are on disk."""
    taken = snapshot(out, label)
    return (taken["image_sha256"], sorted(p.name for p in (out / "recovery").iterdir()))


CASES = {"p0": case_p0, "p0c": case_p0c, "p0n": case_p0n, "l3": case_l3, "l4": case_l4, "l5": case_l5, "l6": case_l6, "l7": case_l7,
         "m1": case_m1, "m2": case_m2, "m3": case_m3, "r1a": case_r1a, "r1b": case_r1b,
         "r2a": lambda lane: case_r2(lane, "a"), "r2b": lambda lane: case_r2(lane, "b"),
         "r2c": lambda lane: case_r2(lane, "c"), "r3a": case_r3a, "r3b": case_r3b, "r3c": case_r3c, "r4a": case_r4a,
         "r4b": case_r4b, "r4d": case_r4d, "r4f": case_r4f, "b2": case_b2, "b3": case_b3, "b4": case_b4, "b5": case_b5,
         "b6": case_b6, "b7": case_b7, "s1": case_s1, "s2": case_s2}


# -- the host-only self-test ----------------------------------------------------------

def synthetic(ident="a" * 32, previous="failed", *, state=None, served=True, resumed=True):
    """A synthetic serial: one boot, the kernel fence line, and either the
    admission lines (A) or a refusal."""
    lines = ["ABSD KERNEL BOOT", "BLOCK DEVICE OK sectors=131072", "STORAGE FENCE fence=none reason=not_declared",
             "NETWORK LINK OK rx_descriptors=32 tx_descriptors=16 buffer_bytes=2048", "EXTERNAL OUTPUT BEGIN encoding=hex"]
    worker = b""
    if state:
        lines += [f"RECOVERY STATE REFUSED reason={state}", "USER EXIT pid=2 status=3"]
        worker = fence_guest.NO_SERVER.encode() + b"\n"
        lines += [f"EXTERNAL OUTPUT CHUNK offset=0000000000000000 data={worker.hex()}",
                  "SERVED RECOVERY REFUSED generation_not_ready", "init: FAILED at served worker fault",
                  "DURABLE status=99 frames=0 processes=0 cells=0 pipes=0 block_reads=8 block_writes=0 block_flushes=0 block_errors=0 block_waits=1 block_irqs=1 ticks=1"]
        return ("\n".join(lines) + "\n").encode(), "7"
    if resumed:
        lines.append(f"RECOVERY WRITABLE RESUMED id={ident} previous={previous} fs_seq=14 ledger_seq=3")
    lines += ["RELEASE OK release=dev", f"FSD RECOVERY seq=4 streak=2 previous={previous}",
              "FSD STORAGE FENCE fence=none previous=failed assessed=failed",
              "FSD READY channels=11 slots=10 fs_seq=14 formatted=false fs_objects=40"]
    worker = b"SSH HOST KEY LOADED ssh-ed25519 AAAA SHA256:x\nSSH LISTENING port=22 authorized_keys=1 preauth_per_source=4\n"
    lines.append(f"EXTERNAL OUTPUT CHUNK offset=0000000000000000 data={worker.hex()}")
    return ("\n".join(lines) + "\n").encode(), None


def host_only():
    checks = 0

    def expect_failure(func, *args):
        nonlocal checks
        try:
            func(*args)
        except (CaseFailed, RuntimeError):
            checks += 1
            return
        raise CaseFailed(f"{func.__name__} accepted {args[:1]}")

    retained = RETAINED_REFUSAL.read_bytes()
    parts = boots(retained)
    if len(parts) != 2:
        raise CaseFailed("the retained serial does not hold two boots")
    successor = BOOT + parts[1]
    # R-served (pinned helper) over the retained P14g refusal serial.
    fence_guest.require_served_successor_refusal(successor, "7")
    checks += 1
    require_served_refusal(successor, "7", "failed")
    checks += 1
    expect_failure(require_served_refusal, successor, "7", "not_ready")
    expect_failure(require_state_refusal, successor, "7", "resume_mismatch")
    expect_failure(require_admission, successor, "a" * 32, "failed")
    # R-state over synthetic refusals, every reason; the fence line never substitutes.
    for reason in STATE_REASONS:
        raw, status = synthetic(state=reason)
        require_state_refusal(raw, status, reason)
        checks += 1
        other = "corrupt" if reason != "corrupt" else "lost"
        expect_failure(require_state_refusal, raw, status, other)
        expect_failure(require_state_refusal, raw, "3", reason)
    expect_failure(require_state_refusal, successor, "7", "corrupt")
    # A over a synthetic admission; wrong id, wrong previous, missing listener, two RESUMED lines.
    raw, _ = synthetic()
    found = require_admission(raw, "a" * 32, "failed", 14)
    if found != {"previous": "failed", "fs_seq": 14, "ledger_seq": 3, "streak": 2}:
        raise CaseFailed(f"A parsed {found}")
    checks += 1
    expect_failure(require_admission, raw, "b" * 32, "failed")
    expect_failure(require_admission, raw, "a" * 32, "not_ready")
    expect_failure(require_admission, raw, "a" * 32, "failed", 15)
    expect_failure(require_admission, synthetic(resumed=False)[0], "a" * 32, "failed")
    doubled = raw.replace(b"RELEASE OK", b"RECOVERY WRITABLE RESUMED id=" + b"a" * 32 + b" previous=failed fs_seq=14 ledger_seq=3\nRELEASE OK")
    expect_failure(require_admission, doubled, "a" * 32, "failed")
    # The server's order: RELEASE OK before FSD RECOVERY; any other is refused.
    reordered = raw.replace(b"RELEASE OK release=dev\n", b"").replace(b"FSD READY ", b"RELEASE OK release=dev\nFSD READY ")
    expect_failure(require_admission, reordered, "a" * 32, "failed")
    not_ready, _ = synthetic(previous="not_ready")
    require_admission(not_ready, "a" * 32, "not_ready")
    checks += 1
    # W over synthetic consoles: latest boot only, in order, ended lines.
    ready = raw
    word, positions = sfr.readiness(sfr.latest_boot(ready), "a" * 32)
    if word != "ready" or list(positions) != sorted(positions):
        raise CaseFailed("W did not accept the synthetic readiness in order")
    checks += 1
    stale_then_new = ready + b"ABSD KERNEL BOOT\n"
    if sfr.readiness(sfr.latest_boot(stale_then_new), "a" * 32) != (None, None):
        raise CaseFailed("W accepted readiness from an earlier boot")
    checks += 1
    # The listener before RELEASE OK is not readiness (the full ordering).
    lines = ready.split(b"\n")
    chunk = next(line for line in lines if line.startswith(b"EXTERNAL OUTPUT CHUNK"))
    lines.remove(chunk)
    lines.insert(lines.index(b"RELEASE OK release=dev"), chunk)
    out_of_order = b"\n".join(lines)
    if sfr.readiness(sfr.latest_boot(out_of_order), "a" * 32)[0] == "ready":
        raise CaseFailed("W accepted the listener before RELEASE OK")
    checks += 1
    word, line = sfr.readiness(sfr.latest_boot(synthetic(state="resume_mismatch")[0]), "a" * 32)
    if word != "ended" or "resume_mismatch" not in line:
        raise CaseFailed("W did not report the refusal line")
    checks += 1
    word, _ = sfr.readiness(successor, "a" * 32)
    if word != "ended":
        raise CaseFailed("W did not end on the retained refusal")
    checks += 1
    # Z's permitted refusal bookkeeping: exactly the invoking operation's
    # own REFUSED receipt of this attempt at the expected phase, named by
    # the tool's output; positive controls, then one negative control each.
    with tempfile.TemporaryDirectory(prefix="resume-z-") as scratch:
        out = pathlib.Path(scratch)
        (out / "receipts").mkdir()
        attempt, other = "a" * 32, "b" * 32

        def receipt(operation, ident=attempt, *, named=None, table=None, state="REFUSED", phase="prepare",
                    effects="false", error="recovery_pending: authorization x"):
            name = f"receipts/{operation}-failed-{named or ident}-2026-10-22T120000Z.toml"
            (out / name).write_text(f'[{table or operation}]\nattempt = "{ident}"\nstate = "{state}"\n'
                                    f'phase = "{phase}"\ntarget_effects_possible = {effects}\nerror = "{error}"\n')
            return name

        def judged(added, operation, output=None):
            names = [pathlib.PurePosixPath(n).name for n in added]
            return refusal_additions_problem(out, added, operation, "prepare", "recovery_pending",
                                             " ".join(names) if output is None else output)

        def clear():
            for path in (out / "receipts").iterdir():
                path.unlink()

        for operation in REFUSAL_RECEIPT_OPERATIONS:
            clear()
            if judged([receipt(operation)], operation) is not None:
                raise CaseFailed(f"Z refuses {operation}'s own refusal receipt")
            checks += 1
        negatives = {
            "unrelated-command receipt": lambda: ([receipt("stage")], "reconfigure", None),
            "duplicate receipts": lambda: ([receipt("reconfigure"), receipt("reconfigure", other)], "reconfigure", None),
            "wrong table": lambda: ([receipt("reconfigure", table="stage")], "reconfigure", None),
            "effects=true": lambda: ([receipt("reconfigure", effects="true")], "reconfigure", None),
            "state INDETERMINATE": lambda: ([receipt("reconfigure", state="INDETERMINATE")], "reconfigure", None),
            "phase import": lambda: ([receipt("reconfigure", phase="import")], "reconfigure", None),
            "attempt mismatch": lambda: ([receipt("reconfigure", other, named=attempt)], "reconfigure", None),
            "another refusal reason": lambda: ([receipt("reconfigure", error="tool_busy: held")], "reconfigure", None),
            "not named by the tool": lambda: ([receipt("reconfigure")], "reconfigure", "release: refused"),
            "a receipt where none is permitted": lambda: ([receipt("stage")], None, None),
            "a recovery record": lambda: (["recovery/active.toml"], None, None),
            "no receipt where one is required": lambda: ([], "stage", None),
        }
        for label, make in negatives.items():
            clear()
            added, operation, output = make()
            if judged(added, operation, output) is None:
                raise CaseFailed(f"Z permits {label}")
            checks += 1
        # S2's metadata edit on a real built image: equal-length leaves and
        # the slot-less / guard-less shapes it must produce.
        spec = importlib.util.spec_from_file_location("resume_tests_for_selftest", here / "test_storage_fence_resume.py")
        tests = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tests)
        image = tests.build_image(out / "s2.img", tests.machine_files("ended", guard_state="clean"))
        move_record_to_root(image, guard.RESUME_PATH, SLOT_AWAY)
        require_shape(image, slot=False, guard=True)
        move_record_to_root(image, guard.PATH, GUARD_AWAY)
        require_shape(image, slot=False, guard=False)
        checks += 2
    # The P0 boundary oracle over synthetic observations: it accepts only an
    # observed size difference that the state committed at termination does
    # not record, and refuses the same-metadata, committed and moved-commit
    # variants.
    old = {"seq": 7, "f2": {"size": 4097, "blocks": [1, 2], "mtime": 100}}
    grown = {"seq": 8, "f2": {"size": 4609, "blocks": [1, 2], "mtime": 101}}
    for memory, at, after, want in (({"size": 4609}, old, old, "uncommitted_at_termination"),
                                    ({"size": 4097}, old, old, "commit_boundary_unproven"),
                                    ({"size": 4609}, old, grown, "committed_before_termination"),
                                    ({"size": 4609}, grown, grown, "committed_before_termination"),
                                    ({"size": 4609}, old, dict(old, seq=8), "commit_boundary_unproven")):
        if p0_oracle(memory, old, at, after)[0] != want:
            raise CaseFailed(f"P0 oracle wrong for {memory} {at} {after}")
        checks += 1
    # The host decision table on built images is test_storage_fence_resume.py's.
    print(f"RESUME HOST-ONLY SELFTEST OK checks={checks}", flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host-only", action="store_true")
    parser.add_argument("--platform")
    parser.add_argument("--kernel")
    parser.add_argument("--release")
    parser.add_argument("--other-release", help="a second release directory (P0n's ISO, S1/S2 staging)")
    parser.add_argument("--key")
    parser.add_argument("--work")
    parser.add_argument("--qemu", default="qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand")
    parser.add_argument("--accel", default="tcg", choices=("tcg", "kvm"))
    parser.add_argument("--port", type=int, default=2422)
    parser.add_argument("--cases", default=",".join(GUEST_ORDER))
    args = parser.parse_args()
    if args.host_only:
        return host_only()
    for name in ("platform", "kernel", "release", "key", "work"):
        if getattr(args, name) is None:
            parser.error(f"--{name} is required for guest cases")
    names = args.cases.split(",")
    unknown = [name for name in names if name not in CASES]
    if unknown:
        parser.error(f"unknown cases {unknown}; known: {','.join(CASES)}")
    lane = Lane(args)
    lane.work.mkdir(parents=True, exist_ok=False)
    passed = []
    for name in names:
        try:
            CASES[name](lane)
            passed.append(name)
        except (CaseFailed, RuntimeError, OSError, subprocess.SubprocessError) as error:
            # The pinned P14g helpers raise RuntimeError; a timeout or a
            # vanished process is a case failure too, recorded by name.
            import traceback
            traceback.print_exc()
            print(f"RESUME CASE FAILED case={name}: {type(error).__name__}: {error}", file=sys.stderr, flush=True)
            raise SystemExit(1)
        finally:
            lane.stop_leftovers(name)
            lane.write_json(name) if name in lane.results else None
    (lane.work / "readiness.json").write_text(json.dumps(lane.readiness, indent=2))
    print(f"STORAGE FENCE RESUME MATRIX OK cases={len(passed)} readiness_timeout_provisional={lane.timeout}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
