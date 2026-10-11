#!/usr/bin/env python3
"""Real NQ-NG `nq --config C --json diagnostics qualify ID` on ABSD against
its Linux twin, on the frozen Linux fixture (fixtures/nq).

Provenance: the real NQ-NG 8057441 (debug build, real procfs helper)
produced the store and artifact on Linux; the store bytes travel into the
guest as an opaque input stream; the guest importer writes them through the
ABSD filesystem; then, in later boots, init runs the real `nq` as a second
process holding only a read-only duplicate of the block handle. Its
provenance must equal the Linux `nq`'s stdout byte for byte, and the device
image must be byte-identical before and after every `nq` boot. Hostile
inputs go through both, which must refuse with the same exit status and the
same NQ error line.

Error lines are compared with one normalization, stated here so it cannot
hide a difference: the Linux run's scratch directory prefix is removed from
paths (the guest paths are /nq/...), and an operating-system error
description at the end of the line is compared by its `io::ErrorKind`:
Linux `No such file or directory (os error 2)` and ABSD `ABSD path not
found` both read as <NotFound>. Everything NQ itself wrote must be equal;
both full lines are printed.
"""

import argparse
import hashlib
import json
import os
import pathlib
import re
import sqlite3
import subprocess
import sys
import tempfile

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import absd_fs  # noqa: E402
import absd_inputs  # noqa: E402
import importlib.util  # noqa: E402

spec = importlib.util.spec_from_file_location("nightshift_matrix", here / "nightshift-matrix.py")
nsm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nsm)

ARTIFACT = "sha256:bddd0a9e1e29fad5c066ab0fb3cfd6c32408e6f1ad8d3f38ec79235a5a83bbd3"
UNKNOWN = "sha256:" + "0" * 64
STORE = "/nq/nq.db"
CONFIG = "/nq/nq.toml"
LINUX_OS_ERROR = re.compile(r"[^:]*\(os error (\d+)\)$")
LINUX_KIND = {2: "NotFound", 13: "PermissionDenied", 17: "AlreadyExists", 20: "NotADirectory",
              21: "IsADirectory", 30: "ReadOnlyFilesystem"}
# The ABSD standard library's descriptions (std/src/sys/fs/absd.rs).
ABSD_KIND = {"ABSD path not found": "NotFound",
             "ABSD storage handle lacks the right": "PermissionDenied",
             "ABSD object is read-only or not opened for this": "PermissionDenied",
             "ABSD path already exists": "AlreadyExists",
             "ABSD path component is not a directory": "NotADirectory",
             "ABSD path is a directory": "IsADirectory",
             "ABSD filesystem is mounted read-only": "ReadOnlyFilesystem"}


def fail(message):
    print(f"NQ MATRIX FAILED: {message}", file=sys.stderr)
    sys.exit(1)


def require(condition, message):
    if not condition:
        fail(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class Matrix(nsm.Matrix):
    def __init__(self, args):
        self.kernel = pathlib.Path(args.kernel).resolve()
        self.importer = pathlib.Path(args.importer).resolve()
        self.nq = {"reference": pathlib.Path(args.nq).resolve(),
                   "unknown": pathlib.Path(args.nq_unknown).resolve()}
        self.linux = {"pristine": args.linux_nq, "patched": args.linux_patched_nq}
        self.fixture = pathlib.Path(args.fixture).resolve()
        self.work = pathlib.Path(args.work).resolve()
        self.qemu = args.qemu
        self.work.mkdir(parents=True, exist_ok=True)
        self.boots = 0
        if absd_inputs.is_kernel_source(self.kernel):
            fail("refusing to build in the canonical kernel checkout")
        self.manifest = json.loads((self.fixture / "manifest.json").read_bytes())

    def native(self, name, image, which="reference"):
        """Boot the importer as a no-op worker and `nq` as the read-only reader."""
        self.resolver = self.nq[which]
        before = sha256(pathlib.Path(image).read_bytes())
        status, serial, captured = self.boot(f"{name}.nq", 0, image, b"", b"")
        after = sha256(pathlib.Path(image).read_bytes())
        require(before == after, f"{name}: the nq boot changed the device ({before} -> {after})")
        require(b"DURABLE READER START" in serial and b"rights=read" in serial,
                f"{name}: nq did not start as the read-only reader")
        require("NQ READONLY AUTHORITY OK" in captured and "write=refused-by-kernel" in captured,
                f"{name}: read-only authority probe missing\n{captured}")
        outcome = [line for line in serial.decode(errors="replace").splitlines()
                   if "DURABLE READER OUTCOME" in line]
        require(len(outcome) == 1, f"{name}: reader outcome missing\n{captured}")
        exit_status = int(outcome[0].rsplit("status=", 1)[1])
        lines = captured.splitlines(keepends=True)
        answers = [line for line in lines if line.startswith("{")]
        errors = [line.rstrip("\n") for line in lines if line.startswith("nq: ")]
        require(len(answers) <= 1, f"{name}: more than one answer line\n{captured}")
        return exit_status, (answers[0].encode() if answers else None), \
            (errors[0] if errors else None), before, captured

    def linux_run(self, binary, files, artifact=ARTIFACT, config=True):
        """The Linux `nq` on the same files, in a read-only directory."""
        with tempfile.TemporaryDirectory() as scratch:
            base = pathlib.Path(scratch)
            for path, data in files:
                target = base / path.lstrip("/")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data.replace(b'"/nq/', f'"{scratch}/nq/'.encode())
                                  if path == CONFIG else data)
                target.chmod(0o444)
            (base / "nq").mkdir(exist_ok=True)
            (base / "nq").chmod(0o555)
            try:
                result = subprocess.run([binary, "--config", str(base / "nq" / "nq.toml"), "--json",
                                         "diagnostics", "qualify", artifact],
                                        stdin=subprocess.DEVNULL, capture_output=True, check=False)
            finally:
                (base / "nq").chmod(0o755)
        stderr = result.stderr.decode(errors="replace").replace(scratch, "")
        errors = [line for line in stderr.splitlines() if line.startswith("nq: ")]
        return result.returncode, (result.stdout or None), (errors[0] if errors else None)

    def import_files(self, name, files):
        if not files:
            files = [("/nq/.keep", b"")]
        return self.import_store(name, files)


def comparable(line):
    if not line:
        return line
    match = LINUX_OS_ERROR.search(line)
    if match and int(match.group(1)) in LINUX_KIND:
        return line[: match.start()].rstrip() + f" <{LINUX_KIND[int(match.group(1))]}>"
    for detail, kind in ABSD_KIND.items():
        if line.endswith(detail):
            return line[: -len(detail)].rstrip() + f" <{kind}>"
    return line


def fixture_files(m, config=True, store=None):
    files = []
    if config:
        files.append((CONFIG, (m.fixture / "nq.toml").read_bytes()))
    files.append((STORE, (m.fixture / "store" / "nq.db").read_bytes() if store is None else store))
    return files


def both_linux(m, files, artifact=ARTIFACT):
    pristine = m.linux_run(m.linux["pristine"], files, artifact)
    patched = m.linux_run(m.linux["patched"], files, artifact)
    require(pristine == patched, f"the Unix build of the patched tree differs: {pristine} vs {patched}")
    return pristine


def scenario_reference(m):
    for name, entry in m.manifest["files"].items():
        require(sha256((m.fixture / name).read_bytes()) == entry["sha256"], f"fixture file {name} drifted")
    reference = (m.fixture / "reference" / "provenance.json").read_bytes()
    files = fixture_files(m)
    status, stdout, error = both_linux(m, files)
    require(status == 0 and stdout == reference,
            f"Linux nq does not reproduce the reference provenance: {status} {error}")
    print(f"NQ LINUX REFERENCE OK provenance={sha256(reference)} unix_patched=identical")
    image = m.import_files("reference", files)
    hashes = set()
    for boot in range(2):
        status, answer, error, image_hash, captured = m.native(f"reference-{boot}", image)
        require(status == 0 and answer == reference,
                f"native provenance differs (exit {status}, {error})\n{answer!r}\n{captured}")
        hashes.add(image_hash)
    require(len(hashes) == 1, "the image changed between nq boots")
    provenance = json.loads(reference)
    print(f"NQ NATIVE QUALIFY OK schema={provenance['schema']} disposition={provenance['disposition']} "
          f"bytes={len(reference)} sha256={sha256(reference)}")
    print(f"NQ STORE UNCHANGED OK image={hashes.pop()} boots=2")
    print("NQ READONLY AUTHORITY OK write=refused-by-kernel")


def wal_variant(data):
    with tempfile.TemporaryDirectory() as scratch:
        path = pathlib.Path(scratch) / "nq.db"
        path.write_bytes(data)
        connection = sqlite3.connect(path)
        require(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal", "cannot set WAL")
        connection.close()
        return path.read_bytes()


def scenario_wal(m):
    """The same store in WAL mode with no -wal file. A read-only mount
    serves the absent WAL as empty; Linux needs a writable directory."""
    reference = (m.fixture / "reference" / "provenance.json").read_bytes()
    data = wal_variant((m.fixture / "store" / "nq.db").read_bytes())
    files = fixture_files(m, store=data)
    with tempfile.TemporaryDirectory() as scratch:
        base = pathlib.Path(scratch)
        (base / "nq").mkdir()
        (base / "nq" / "nq.db").write_bytes(data)
        (base / "nq" / "nq.toml").write_bytes(
            (m.fixture / "nq.toml").read_bytes().replace(b'"/nq/', f'"{scratch}/nq/'.encode()))
        result = subprocess.run([m.linux["pristine"], "--config", str(base / "nq" / "nq.toml"), "--json",
                                 "diagnostics", "qualify", ARTIFACT], stdin=subprocess.DEVNULL,
                                capture_output=True, check=False)
    require(result.returncode == 0 and result.stdout == reference,
            f"Linux nq on the WAL store (writable directory): {result.returncode} {result.stderr!r}")
    read_only = m.linux_run(m.linux["pristine"], files)
    require(read_only[0] != 0, "Linux nq qualified a WAL store in a read-only directory")
    image = m.import_files("wal", files)
    status, answer, error, _, captured = m.native("wal", image)
    require(status == 0 and answer == reference, f"native WAL store: exit {status} {error}\n{captured}")
    print(f"NQ WAL STORE OK native=identical linux_read_only_dir=refused(exit {read_only[0]})")


def mutate(data, how, completed_at=None):
    if how == "truncated":
        return data[: len(data) // 2]
    if how == "not-sqlite":
        return b"\x00" * 4096
    if how == "tampered-artifact":
        # One byte of the stored artifact's completion time (its last
        # whole-seconds digit): SQLite is intact, NQ's own history check
        # must refuse.
        marker = f'"completed_at":"{completed_at[:18]}'.encode()
        digit = completed_at[18:19].encode()
        offset = data.index(marker) + len(marker)
        require(data.count(marker) >= 1 and digit.isdigit() and data[offset:offset + 1] == digit,
                "artifact marker moved")
        tampered = bytearray(data)
        tampered[offset] = ord("8" if digit == b"9" else "9")
        return bytes(tampered)
    with tempfile.TemporaryDirectory() as scratch:
        path = pathlib.Path(scratch) / "nq.db"
        path.write_bytes(data)
        connection = sqlite3.connect(path)
        if how == "old-schema":
            connection.execute("PRAGMA user_version=6")
        elif how == "foreign-application":
            connection.execute("PRAGMA application_id=1")
        connection.commit()
        connection.close()
        return path.read_bytes()


def scenario_hostile(m):
    store = (m.fixture / "store" / "nq.db").read_bytes()
    completed_at = json.loads((m.fixture / "artifact.json").read_bytes())["completed_at"]
    cases = [
        ("unknown-artifact", fixture_files(m), "unknown", UNKNOWN),
        ("missing-config", fixture_files(m, config=False), "reference", ARTIFACT),
        ("missing-store", fixture_files(m)[:1], "reference", ARTIFACT),
    ]
    for how in ("truncated", "not-sqlite", "tampered-artifact", "old-schema", "foreign-application"):
        cases.append((how, fixture_files(m, store=mutate(store, how, completed_at)), "reference", ARTIFACT))
    results = []
    for name, files, which, artifact in cases:
        linux_status, linux_answer, linux_error = both_linux(m, files, artifact)
        require(linux_status != 0 and linux_answer is None and linux_error,
                f"{name}: Linux did not refuse: {linux_status} {linux_answer!r}")
        image = m.import_files(f"hostile-{name}", files)
        status, answer, error, _, captured = m.native(f"hostile-{name}", image, which)
        require(status == linux_status and answer is None and comparable(error) == comparable(linux_error),
                f"{name}: ABSD (exit {status}, {error!r}) differs from Linux "
                f"(exit {linux_status}, {linux_error!r})\n{captured}")
        results.append(name)
        print(f"NQ HOSTILE {name} exit={status}\n  absd:  {error}\n  linux: {linux_error}")
    print(f"NQ HOSTILE INPUTS OK cases={len(results)}")


WATCHER = b"""
[[watchers]]
instance_id = "host-local"
carrier = "stdio"
subject = "host:local"
capability_ceiling = ["read_procfs", "read_system_info"]
checkpoint_policy = "disabled"

[watchers.command]
executable = "/nq/nq-host-helper"
args = []
env = {}
execution_account = "1000"
allow_same_identity_in_debug = true
working_directory = "/nq"

[watchers.profile]
id = "nq.host"
version = 1

[watchers.scope]
kind = "host"
value = { id = "local" }

[watchers.vantage]
kind = "local"
value = {}
"""


def scenario_watcher_config(m):
    """No helper can be launched on ABSD because no configuration naming a
    watcher loads: its execution account cannot be resolved. This is an
    ABSD-only refusal (Linux resolves the account and qualifies)."""
    files = [(CONFIG, (m.fixture / "nq.toml").read_bytes() + WATCHER)] + fixture_files(m)[1:]
    image = m.import_files("watcher-config", files)
    status, answer, error, _, captured = m.native("watcher-config", image)
    require(status == 1 and answer is None and error and "ABSD has no local account database" in error,
            f"a watcher configuration loaded on ABSD: exit {status} {error}\n{captured}")
    print(f"NQ WATCHER CONFIG REFUSED OK exit={status}\n  absd:  {error}")


def main():
    parser = argparse.ArgumentParser()
    for name in ("--kernel", "--importer", "--nq", "--nq-unknown", "--linux-nq", "--linux-patched-nq",
                 "--fixture", "--work", "--qemu"):
        parser.add_argument(name, required=True)
    parser.add_argument("--only", default="")
    args = parser.parse_args()
    m = Matrix(args)
    only = set(filter(None, args.only.split(",")))
    if not only or "reference" in only:
        scenario_reference(m)
    if not only or "wal" in only:
        scenario_wal(m)
    if not only or "hostile" in only:
        scenario_hostile(m)
    if not only or "watcher-config" in only:
        scenario_watcher_config(m)
    if not only:
        print(f"NQ MATRIX OK boots={m.boots}")
        print("NQ NATIVE PROGRAM OK")


if __name__ == "__main__":
    main()
