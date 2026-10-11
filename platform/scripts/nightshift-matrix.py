#!/usr/bin/env python3
"""Real Nightshift observation resolver on ABSD against the frozen Linux
fixture (fixtures/nightshift).

Provenance: the real Nightshift writer produced the store on Linux; its
bytes travel into the guest as an opaque input stream; the guest importer
writes them through the ABSD filesystem; then, in later boots, init runs
the real resolver as a second process holding only a read-only duplicate of
the block handle. Every answer must equal the Linux resolver's answer byte
for byte, and the device image must be byte-identical before and after
every resolver boot. Hostile variants of the store bytes go through both
resolvers, which must agree.
"""

import argparse
import hashlib
import importlib.util
import json
import pathlib
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import absd_fs  # noqa: E402
import absd_inputs  # noqa: E402

spec = importlib.util.spec_from_file_location("durable_matrix", here / "durable-matrix.py")
dm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dm)

IMAGE_BYTES = 16 * 1024 * 1024
DEVICE_SECTORS = IMAGE_BYTES // 512
STORE_PATH = "/nightshift/nightshift.sqlite"


def fail(message):
    print(f"NIGHTSHIFT MATRIX FAILED: {message}", file=sys.stderr)
    sys.exit(1)


def require(condition, message):
    if not condition:
        fail(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def stream(files):
    """The importer's input: opaque (path, bytes) pairs."""
    out = bytearray(b"ABSDFIX1")
    for path, data in files:
        name = path.encode()
        out += struct.pack("<H", len(name)) + name + struct.pack("<Q", len(data))
        out += hashlib.sha256(data).digest() + data
    out += struct.pack("<H", 0)
    return bytes(out)


class Matrix:
    def __init__(self, args):
        self.kernel = pathlib.Path(args.kernel).resolve()
        self.importer = pathlib.Path(args.importer).resolve()
        self.resolver = pathlib.Path(args.resolver).resolve()
        self.linux_resolver = args.linux_resolver
        self.fixture = pathlib.Path(args.fixture).resolve()
        self.work = pathlib.Path(args.work).resolve()
        self.qemu = args.qemu
        self.work.mkdir(parents=True, exist_ok=True)
        self.boots = 0
        if absd_inputs.is_kernel_source(self.kernel):
            fail("refusing to build in the canonical kernel checkout")
        self.manifest = json.loads((self.fixture / "manifest.json").read_bytes())

    def iso(self, step, input_bytes, request, worker=None):
        # The kernel build embeds these files and notices a changed path, not
        # changed content at the same path, so each name carries the digest.
        input_path = self.work / f"input-{sha256(input_bytes)}.bin"
        input_path.write_bytes(input_bytes)
        variables = [f"DURABLE_STEP={step}", f"EXTERNAL_USER_ELF={worker or self.importer}",
                     f"EXTERNAL_INPUT={input_path}"]
        if request is not None:
            request_path = self.work / f"request-{sha256(request)}.json"
            request_path.write_bytes(request)
            variables += [f"EXTERNAL_READER_ELF={self.resolver}", f"EXTERNAL_READER_INPUT={request_path}"]
        else:
            variables += ["EXTERNAL_READER_ELF=", "EXTERNAL_READER_INPUT="]
        subprocess.run(["make", "--no-print-directory", "-C", str(self.kernel), "durable-iso", *variables],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        return self.kernel / "build" / "durable" / f"absd-durable-{step}.iso"

    def boot(self, name, step, image, input_bytes=b"", request=None, worker=None):
        iso = self.iso(step, input_bytes, request, worker)
        self.boots += 1
        log = self.work / f"{name}.{self.boots:03d}.serial.log"
        result = subprocess.run(
            [str(self.kernel / "scripts" / "durable-boot.sh"), str(iso), str(image), str(log), "300",
             *self.qemu.split()], check=True, capture_output=True, text=True)
        serial = log.read_bytes()
        require(b"PANIC" not in serial and b"KERNEL FAULT" not in serial, f"{name}: kernel fault")
        return int(result.stdout.strip()), serial, dm.Harness.captured(serial)

    def image(self, name):
        path = self.work / f"{name}.img"
        with open(path, "wb") as handle:
            handle.truncate(IMAGE_BYTES)
        return path

    def import_store(self, name, files):
        image = self.image(name)
        status, serial, captured = self.boot(f"{name}.import", 1, image, stream(files))
        require(status == 3 and f"FIXTURE IMPORT OK files={len(files)}" in captured,
                f"{name}: import status {status}\n{captured}")
        require(b"DURABLE READER" not in serial, f"{name}: a reader ran during import")
        # Independent host reader: the filesystem holds exactly these bytes.
        region = absd_fs.fs_region(image, DEVICE_SECTORS)
        tree = absd_fs.tree(region, absd_fs.select(region))
        for path, data in files:
            require(path in tree and absd_fs.content(region, absd_fs.select(region), tree[path]) == data,
                    f"{name}: host reader sees different bytes at {path}")
        return image

    def resolve(self, name, image, request):
        before = sha256(pathlib.Path(image).read_bytes())
        status, serial, captured = self.boot(f"{name}.resolve", 0, image, b"", request)
        after = sha256(pathlib.Path(image).read_bytes())
        require(before == after, f"{name}: the resolver boot changed the device ({before} -> {after})")
        require(b"DURABLE READER START" in serial and b"rights=read" in serial,
                f"{name}: the reader did not start with read rights")
        require("NIGHTSHIFT READONLY AUTHORITY OK" in captured and "write=refused-by-kernel" in captured,
                f"{name}: read-only authority probe missing\n{captured}")
        lines = [line for line in captured.splitlines() if line.startswith("{")]
        require(len(lines) <= 1, f"{name}: more than one answer line\n{captured}")
        errors = [line for line in captured.splitlines() if line.startswith("Error: ")]
        outcome = [line for line in serial.decode(errors="replace").splitlines()
                   if "DURABLE READER OUTCOME" in line]
        require(len(outcome) == 1, f"{name}: reader outcome missing\n{captured}")
        exit_status = int(outcome[0].rsplit("status=", 1)[1])
        return exit_status, (lines[0] if lines else None), captured, before, (errors[0] if errors else None)

    def linux(self, store_files, request):
        with tempfile.TemporaryDirectory() as scratch:
            for path, data in store_files:
                (pathlib.Path(scratch) / pathlib.Path(path).name).write_bytes(data)
            result = subprocess.run(
                [self.linux_resolver, "--store", str(pathlib.Path(scratch) / "nightshift.sqlite"),
                 "--resolver-id", "nightshift-observation-resolver/v1", "--default-ttl-ms", "600000"],
                input=request, capture_output=True, check=False)
        stdout = result.stdout.decode().strip()
        errors = [line for line in result.stderr.decode().splitlines() if line.startswith("Error: ")]
        return result.returncode, (stdout or None), (errors[0] if errors else None)


def store_files(fixture):
    return [(f"/nightshift/{path.name}", path.read_bytes()) for path in sorted((fixture / "store").iterdir())]


def scenario_reference(m):
    files = store_files(m.fixture)
    for path, data in files:
        name = pathlib.PurePosixPath(path).name
        require(sha256(data) == m.manifest["store"][name]["sha256"], f"fixture file {name} drifted")
    image = m.import_store("reference", files)
    answers = {}
    hashes = set()
    for request_path in sorted((m.fixture / "requests").iterdir()):
        name = request_path.stem
        status, line, captured, image_hash, _ = m.resolve(f"reference-{name}", image, request_path.read_bytes())
        require(status == 0 and line is not None, f"{name}: resolver failed ({status})\n{captured}")
        answers[name] = line
        hashes.add(image_hash)
    answers_path = m.work / "answers.json"
    answers_path.write_text(json.dumps(answers))
    subprocess.run([sys.executable, str(here / "nightshift_reference.py"), "compare",
                    "--fixture", str(m.fixture), "--answers", str(answers_path)], check=True)
    require(len(hashes) == 1, "the image changed between resolver boots")
    print(f"NIGHTSHIFT RESOLVER OK answers={len(answers)}")
    print("NIGHTSHIFT READONLY AUTHORITY OK")
    print(f"NIGHTSHIFT STORE UNCHANGED OK image={hashes.pop()}")


def mutate(files, how):
    data = dict(files)[STORE_PATH]
    if how == "page-byte":
        page = bytearray(data)
        page[4096 * 3 + 100] ^= 0xff
        return [(STORE_PATH, bytes(page))]
    if how == "truncated":
        return [(STORE_PATH, data[: len(data) // 2])]
    if how == "not-sqlite":
        return [(STORE_PATH, b"\x00" * 4096)]
    with tempfile.TemporaryDirectory() as scratch:
        path = pathlib.Path(scratch) / "nightshift.sqlite"
        path.write_bytes(data)
        connection = sqlite3.connect(path)
        if how == "missing-row":
            connection.execute("DELETE FROM canonical_observation_cycles")
        elif how == "old-schema":
            connection.execute("ALTER TABLE canonical_observation_cycles RENAME COLUMN observation_id TO observation_ref")
        elif how == "empty-store":
            for (table,) in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
                connection.execute(f'DROP TABLE "{table}"')
        elif how == "wal-pending":
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA wal_autocheckpoint=0")
            connection.commit()
            # The pending transaction changes what the resolver reads, so a
            # reader that skipped the real WAL would answer differently.
            connection.execute("DELETE FROM canonical_observation_cycles")
            connection.commit()
            wal = pathlib.Path(str(path) + "-wal")
            out = [(STORE_PATH, path.read_bytes()), (STORE_PATH + "-wal", wal.read_bytes())]
            # Leave the WAL uncheckpointed: copy before closing.
            connection.close()
            return out
        connection.commit()
        connection.close()
        return [(STORE_PATH, path.read_bytes())]


def scenario_hostile(m):
    files = store_files(m.fixture)
    request = (m.fixture / "requests" / "current.json").read_bytes()
    results = []
    for how in ["page-byte", "truncated", "not-sqlite", "missing-row", "old-schema", "empty-store", "wal-pending"]:
        variant = mutate(files, how)
        linux_status, linux_line, linux_error = m.linux(variant, request)
        if how == "wal-pending":
            # The case must discriminate: the store without its WAL answers
            # differently from the store with it.
            _, without_wal, _ = m.linux(variant[:1], request)
            require(without_wal != linux_line, "wal-pending: the WAL does not change the answer")
        image = m.import_store(f"hostile-{how}", variant)
        status, line, captured, _, error = m.resolve(f"hostile-{how}", image, request)
        # Refusals agree only for the same reason: the resolver's outermost
        # error context (Nightshift's own text) must match, not just "failed".
        require(status == linux_status and line == linux_line and error == linux_error,
                f"{how}: ABSD (exit {status}, {line!r}, {error!r}) differs from "
                f"Linux (exit {linux_status}, {linux_line!r}, {linux_error!r})\n{captured}")
        verdict = json.loads(line)["status"] if line else f"refused(exit {status}, {error})"
        results.append((how, verdict))
    print(f"NIGHTSHIFT HOSTILE STORES OK cases={len(results)} results={results}")


def schema(path):
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        tables = connection.execute("SELECT type, name, sql FROM sqlite_master ORDER BY name").fetchall()
        rows = {name: connection.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0]
                for kind, name, _ in tables if kind == "table"}
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        connection.close()
    return tables, rows, integrity


# Every owner port the posture cycle reaches is a separate program. ABSD
# cannot start a program, so the native writer's spawn fails; the Linux twin
# is given owner paths that do not exist, so its spawn fails the same way.
# Only the operating system's text for the spawn error differs.
ABSENT_OWNER = ("Error: NQ-NG admission provenance refused or was unavailable: "
                "NQ admission query failed to start: ")
# SQLite's file change counter and version-valid-for number (header offsets
# 24 and 92) count write transactions on the database file: a crash between
# checkpoints legitimately adds one. Nothing else may differ.
HEADER_COUNTERS = ((24, 28), (92, 96))


def error_lines(text):
    return [line for line in text.splitlines() if line.startswith("Error: ")]


def run_linux_writer(m, posture, owners):
    with tempfile.TemporaryDirectory() as scratch:
        root = pathlib.Path(scratch)
        (root / "owners").mkdir()
        if owners == "refusing":
            for name in ("nq", "pulse-support-resolver"):
                (root / "owners" / name).write_text("#!/bin/sh\nexit 1\n")
                (root / "owners" / name).chmod(0o700)
            (root / "owners" / "nq.toml").write_text("{}")
        store = root / "linux" / "nightshift.sqlite"
        store.parent.mkdir()
        (root / "posture-request.json").write_bytes(posture)
        linux = subprocess.run([m.linux_writer, "--store", str(store), "cycle", "run",
                                "--request", str(root / "posture-request.json"),
                                "--present-evidence-resolver", str(root / "owners" / "pulse-support-resolver"),
                                "--nq-program", str(root / "owners" / "nq"),
                                "--nq-config", str(root / "owners" / "nq.toml"),
                                "--nq-source-id", "nq-node:fixture"], capture_output=True, check=False)
        files = [(f"/nightshift/{path.name}", path.read_bytes()) for path in sorted(store.parent.iterdir())]
        shape = schema(store)
    return linux.returncode, error_lines(linux.stderr.decode(errors="replace")), files, shape


def linux_twin(m, posture):
    """The Linux writer with absent owners (spawn fails, as on ABSD): exit
    status, refusal, exact store bytes, shape, and the resolver's answer. An
    owner that starts and refuses must leave the very same bytes."""
    status, errors, files, shape = run_linux_writer(m, posture, "missing")
    require(status == 1 and len(errors) == 1 and errors[0].startswith(ABSENT_OWNER),
            f"Linux writer did not refuse for the absent NQ owner: {status} {errors}")
    refusing_status, refusing_errors, refusing_files, _ = run_linux_writer(m, posture, "refusing")
    require(refusing_status == 1 and refusing_files == files and len(refusing_errors) == 1
            and "NQ-NG admission" in refusing_errors[0],
            f"a refusing NQ owner left a different store or status: {refusing_status} {refusing_errors}")
    require([path for path, _ in files] == [STORE_PATH] and shape[2] == "ok",
            f"Linux store files: {[path for path, _ in files]} {shape[2]}")
    request = (m.fixture / "requests" / "current.json").read_bytes()
    answer_status, answer, _ = m.linux(files, request)
    require(answer_status == 0 and json.loads(answer)["status"] == "absent", f"Linux twin answer: {answer_status} {answer}")
    return {"status": status, "files": files, "shape": shape, "answer": answer}


def native_store(image):
    region = absd_fs.fs_region(image, DEVICE_SECTORS)
    fs_image = absd_fs.select(region)
    tree = absd_fs.tree(region, fs_image)
    return [(path, absd_fs.content(region, fs_image, record)) for path, record in sorted(tree.items())
            if path.startswith("/nightshift/nightshift.sqlite")]


def without_counters(data):
    out = bytearray(data)
    for start, end in HEADER_COUNTERS:
        out[start:end] = bytes(end - start)
    return bytes(out)


def check_native(m, name, image, captured, serial, twin, exact):
    """The native writer's run must match the Linux twin: same exit status,
    the same refusal, the same files with the same bytes (exactly, or up to
    SQLite's write counters after a crash), and the same answer from the
    native resolver and from the Linux resolver on the native bytes."""
    text = serial.decode(errors="replace")
    worker = [line for line in text.splitlines() if "DURABLE WORKER OUTCOME" in line]
    reader = [line for line in text.splitlines() if "DURABLE READER OUTCOME" in line]
    require(len(worker) == 1 and worker[0].endswith(f"status={twin['status']}")
            and "NIGHTSHIFT WRITER MOUNT OK" in captured,
            f"{name}: writer outcome {worker}, Linux exit {twin['status']}\n{captured}")
    errors = error_lines(captured)
    require(len(errors) == 1 and errors[0].startswith(ABSENT_OWNER),
            f"{name}: writer did not refuse for the absent owner: {errors}\n{captured}")
    require(len(reader) == 1 and reader[0].endswith("status=0"), f"{name}: reader {reader}\n{captured}")
    answer = [line for line in captured.splitlines() if line.startswith("{")]
    require(answer == [twin["answer"]], f"{name}: native answer {answer} differs from Linux {twin['answer']}")
    files = native_store(image)
    require([path for path, _ in files] == [path for path, _ in twin["files"]],
            f"{name}: native store files {[path for path, _ in files]} differ from Linux")
    normalize = (lambda data: data) if exact else without_counters
    for (path, data), (_, linux_data) in zip(files, twin["files"]):
        require(normalize(data) == normalize(linux_data),
                f"{name}: native {path} bytes differ from Linux ({sha256(data)} vs {sha256(linux_data)})")
    with tempfile.TemporaryDirectory() as scratch:
        for path, data in files:
            (pathlib.Path(scratch) / pathlib.PurePosixPath(path).name).write_bytes(data)
        shape = schema(pathlib.Path(scratch) / "nightshift.sqlite")
    require(shape == twin["shape"], f"{name}: native store {shape[1:]} differs from Linux {twin['shape'][1:]}")
    cross_status, cross_answer, _ = m.linux(files, (m.fixture / "requests" / "current.json").read_bytes())
    require(cross_status == 0 and cross_answer == twin["answer"],
            f"{name}: Linux resolver on native store: {cross_answer}")
    return files


def check_crashed(m, name, image, request):
    """The store as the machine stop left it, before any recovery: the
    native resolver (read-only) and the Linux resolver on the same bytes
    must agree exactly, whether they answer or refuse."""
    files = native_store(image)
    # With no file yet, the Linux resolver is given an empty directory.
    linux_status, linux_line, linux_error = m.linux(files, request)
    status, line, captured, _, error = m.resolve(name, image, request)
    require(status == linux_status and line == linux_line and error == linux_error,
            f"{name}: crashed store: ABSD (exit {status}, {line!r}, {error!r}) differs from "
            f"Linux (exit {linux_status}, {linux_line!r}, {linux_error!r})\n{captured}")
    kinds = "+".join(pathlib.PurePosixPath(path).name for path, _ in files) or "no-store"
    return kinds, (json.loads(line)["status"] if line else f"refused(exit {status}, {error})")


def scenario_writer_crash(m):
    """Machine stops at sampled filesystem writes inside the native writer's
    run: Fibonacci points forward from its first write and backward from
    its last (where its final commit, checkpoint, and WAL removal are). Each
    stopped store is read by both resolvers before recovery; the next boot
    runs the writer and the reader again and must reach the Linux twin's
    store bytes (up to SQLite's write counters) and answer."""
    posture = m.posture_request.read_bytes()
    request = (m.fixture / "requests" / "current.json").read_bytes()
    twin = linux_twin(m, posture)
    base = m.import_store("writer-crash", [("/nightshift/posture-request.json", posture)])

    def stops(point, keep=False):
        image = m.work / f"writer-crash-{point}.img"
        shutil.copyfile(base, image)
        status, serial, captured = m.boot(f"writer-crash-{point}", point, image, b"", request, m.writer)
        if status == 4 * 43 + 3:
            require(b"MACHINE STOP code=43" in serial, f"writer-crash-{point}: unexpected stop")
            return image
        # The writer finished before this write: past its last write.
        check_native(m, f"writer-crash-{point}.complete", image, captured, serial, twin, exact=True)
        if not keep:
            image.unlink()
        return None

    # Forward Fibonacci points until the writer completes.
    forward, point, last = [], 1, 1
    while stops(point) is not None:
        forward.append(point)
        point, last = point + last, point
    # The last write: bisect between the last stop and the first completion.
    low, high = forward[-1], point
    while high - low > 1:
        middle = (low + high) // 2
        if stops(middle) is not None:
            low = middle
        else:
            high = middle
    final = low
    backward, step = [], 1
    while final - step + 1 > forward[-1]:
        backward.append(final - step + 1)
        step *= 2
    points = sorted(set(forward) | set(backward))
    crashed = {}
    for point in points:
        image = stops(point)
        require(image is not None, f"writer-crash-{point}: the writer did not stop")
        crashed[point] = check_crashed(m, f"writer-crash-{point}.crashed", image, request)
        status, serial, captured = m.boot(f"writer-crash-{point}.recover", 0, image, b"", request, m.writer)
        check_native(m, f"writer-crash-{point}.recover", image, captured, serial, twin, exact=False)
        image.unlink()
    print(f"NIGHTSHIFT WRITER CRASH OK writes={final} points={points} recovered={len(points)} "
          f"store=linux-bytes")
    print(f"NIGHTSHIFT CRASHED STORE READS OK points={len(points)} results="
          f"{sorted(set(crashed.values()))}")


def scenario_native_writer(m):
    """The real Nightshift writer runs natively; its owners (NQ, present
    evidence, AG) are separate programs ABSD cannot start, so each is
    unavailable. The Linux writer is given owner paths that do not exist.
    Both must exit alike, refuse alike, and leave byte-identical stores, and
    the resolver must answer the same on both, natively and on Linux."""
    request = (m.fixture / "requests" / "current.json").read_bytes()
    posture = m.posture_request.read_bytes()
    twin = linux_twin(m, posture)
    image = m.import_store("native-writer", [("/nightshift/posture-request.json", posture)])
    status, serial, captured = m.boot("native-writer.write", 0, image, b"", request, m.writer)
    files = check_native(m, "native-writer", image, captured, serial, twin, exact=True)
    tables, rows, integrity = twin["shape"]
    print(f"NIGHTSHIFT NATIVE WRITER OK tables={len(rows)} rows={sum(rows.values())} owners=unavailable "
          f"exit={twin['status']}")
    print(f"NIGHTSHIFT NATIVE STORE OK integrity={integrity} bytes=identical sha256={sha256(files[0][1])}")
    print(f"NIGHTSHIFT CROSS PLATFORM STORE OK answer={json.loads(twin['answer'])['status']}")



def main():
    parser = argparse.ArgumentParser()
    for name in ("--kernel", "--importer", "--resolver", "--linux-resolver", "--fixture", "--work", "--qemu"):
        parser.add_argument(name, required=True)
    parser.add_argument("--writer")
    parser.add_argument("--linux-writer")
    parser.add_argument("--posture-request")
    parser.add_argument("--only", default="")
    args = parser.parse_args()
    m = Matrix(args)
    only = set(filter(None, args.only.split(",")))
    if not only or "reference" in only:
        scenario_reference(m)
    if not only or "hostile" in only:
        scenario_hostile(m)
    if (not only or "native-writer" in only) and args.writer:
        m.writer = pathlib.Path(args.writer).resolve()
        m.linux_writer = args.linux_writer
        m.posture_request = pathlib.Path(args.posture_request)
        scenario_native_writer(m)
    if (not only or "writer-crash" in only) and args.writer:
        m.writer = pathlib.Path(args.writer).resolve()
        m.linux_writer = args.linux_writer
        m.posture_request = pathlib.Path(args.posture_request)
        scenario_writer_crash(m)
    print(f"NIGHTSHIFT MATRIX OK boots={m.boots}")


if __name__ == "__main__":
    main()
