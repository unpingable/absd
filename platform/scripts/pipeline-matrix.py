#!/usr/bin/env python3
"""The real Nightshift observation pipeline on ABSD with real owner processes
(fixtures/nightshift-pipeline, Linux side in its README-linux.md).

One boot imports the Linux-produced inputs as opaque bytes: the sealed cycle
request over a real Linux NQ artifact, NQ-NG's real store and config, and the
Pulse deployment config with a real Linux receipt. The next boot runs the real
Nightshift writer as the durable worker. It has no spawn right: `nq` and
`pulse-support-resolver` run as separate processes that init starts on its
request under a fixed policy, each with a read-only block handle. When the
writer exits, init runs the real observation resolver with a read-only
handle. Later boots ask the resolver the Linux reference's other questions.

The receipt is stamped on a Linux boot clock, so the native Pulse resolver,
on the ABSD boot clock, answers `unknown`; the Linux reference for that path
is its empty-receipts run. The native store, normalized by the Linux side's
normalizer, must equal the reference exactly; the resolver answers must
agree on status, basis, fresh_until_unix_ms and currentness.
"""

import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import sqlite3
import subprocess
import sys
import tempfile

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
from served_ram import served_qemu
from served_kernel import kernel_make
import absd_fs  # noqa: E402

spec = importlib.util.spec_from_file_location("nightshift_matrix", here / "nightshift-matrix.py")
nm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nm)

SOURCE_ID = "nq-store-genesis:26373050-17aa-4ed9-8a41-cc27f3bcfb1f"
POLICY = """\
# The native observation pipeline: the writer may start exactly NQ's qualify
# (one free argument, the artifact id) and Pulse's support resolver (no
# arguments), each with a read-only block handle. Pulse gets its whole
# environment from here.
slots worker 4
allow worker /owners/nq owner-1 read 1 --config /owners/nq.toml --json diagnostics qualify
allow worker /owners/pulse-support-resolver owner-2 read 0
env owner-2 PULSE_LOAD_SUPPORT_CONFIG=/owners/pulse/config.json
"""
REQUESTS = ["current", "current-edge", "stale-edge", "absent", "wrong-subject"]


def fail(message):
    print(f"NIGHTSHIFT PIPELINE FAILED: {message}", file=sys.stderr)
    sys.exit(1)


def require(condition, message):
    if not condition:
        fail(message)


def inputs(fixture):
    """The deployment's files at their ABSD paths. Only paths change; every
    identity field of both configs stays byte-equal to the Linux side's."""
    nq_config = (fixture / "nq" / "nq.toml").read_text()
    nq_config = re.sub(r'database_path = ".*"', 'database_path = "/owners/nq/nq.db"', nq_config)
    nq_config = re.sub(r'admissions_dir = ".*"', 'admissions_dir = "/owners/nq/admissions"', nq_config)
    pulse = json.loads((fixture / "pulse" / "config.json").read_bytes())
    for key, path in [("outgoing_directory", "/owners/pulse/outgoing"),
                      ("receipt_directory", "/owners/pulse/receipts"),
                      ("producer_private_key_path", "/owners/pulse/absent-producer-key")]:
        pulse[key] = path
    files = [
        ("/nightshift/cycle-request.json", (fixture / "request" / "cycle-request.json").read_bytes()),
        ("/owners/nq.toml", nq_config.encode()),
        ("/owners/nq/nq.db", (fixture / "nq" / "store" / "nq.db").read_bytes()),
        ("/owners/pulse/config.json", json.dumps(pulse, sort_keys=True, separators=(",", ":")).encode()),
    ]
    for receipt in sorted((fixture / "pulse" / "receipts").iterdir()):
        files.append((f"/owners/pulse/receipts/{receipt.name}", receipt.read_bytes()))
    return files


def cell(value):
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, (dict, list)):
                return {"json": parsed}
        except ValueError:
            pass
    return value


def dump(store_files):
    """The Linux side's store dump (its tools/dump-and-resolve.py), over the
    bytes the host's own reader extracted from the ABSD image."""
    with tempfile.TemporaryDirectory() as scratch:
        for name, data in store_files.items():
            (pathlib.Path(scratch) / name).write_bytes(data)
        db = sqlite3.connect(pathlib.Path(scratch) / "nightshift.sqlite")
        schema = [dict(zip(("type", "name", "tbl_name", "sql"), row)) for row in
                  db.execute("select type,name,tbl_name,sql from sqlite_master order by type,name")]
        tables = {}
        for (table,) in db.execute("select name from sqlite_master where type='table' order by name"):
            cursor = db.execute(f'select * from "{table}" order by rowid')
            columns = [column[0] for column in cursor.description]
            tables[table] = [{c: cell(v) for c, v in zip(columns, row)} for row in cursor.fetchall()]
        pragmas = {p: db.execute(f"pragma {p}").fetchone()[0]
                   for p in ("user_version", "journal_mode", "application_id")}
        db.close()
    return {"schema": schema, "pragmas": pragmas, "tables": tables}


def extract_store(image):
    region = absd_fs.fs_region(image, nm.DEVICE_SECTORS)
    selected = absd_fs.select(region)
    tree = absd_fs.tree(region, selected)
    return {path.rsplit("/", 1)[1]: absd_fs.content(region, selected, record)
            for path, record in tree.items() if path.startswith("/nightshift/nightshift.sqlite")}


def normalize(fixture, dumped, work):
    path = work / "native-store-dump.json"
    path.write_text(json.dumps(dumped, indent=1, sort_keys=True))
    result = subprocess.run([sys.executable, str(fixture / "tools" / "normalize.py"), str(path)],
                            check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser()
    for name in ("--kernel", "--importer", "--writer", "--resolver", "--nq", "--pulse",
                 "--fixture", "--work", "--qemu"):
        parser.add_argument(name, required=True)
    args = parser.parse_args()
    fixture = pathlib.Path(args.fixture).resolve()
    reference = fixture / "reference" / "empty-receipts"
    m = nm.Matrix(argparse.Namespace(kernel=args.kernel, importer=args.importer, resolver=args.resolver,
                                     linux_resolver=None, fixture=pathlib.Path(args.fixture).parent / "nightshift",
                                     work=args.work, qemu=args.qemu))
    policy = m.work / "pipeline-policy.txt"
    policy.write_text(POLICY)

    files = inputs(fixture)
    image = m.import_store("pipeline", files)

    # The pipeline boot: the writer, its brokered owners, then the reader.
    # Step 0: the writer's test hook arms a machine stop for any other step.
    request = (reference / "resolver" / "current.request.json").read_bytes()
    request_path = m.work / f"request-{nm.sha256(request)}.json"
    request_path.write_bytes(request)
    empty = m.work / "empty-input.bin"
    empty.write_bytes(b"")
    subprocess.run([*kernel_make(), "--no-print-directory", "-C", str(m.kernel), "durable-iso", "DURABLE_STEP=0",
                    f"EXTERNAL_USER_ELF={pathlib.Path(args.writer).resolve()}", f"EXTERNAL_INPUT={empty}",
                    f"EXTERNAL_READER_ELF={m.resolver}", f"EXTERNAL_READER_INPUT={request_path}",
                    f"BROKER_POLICY={policy}", f"OWNER_1_ELF={pathlib.Path(args.nq).resolve()}",
                    f"OWNER_2_ELF={pathlib.Path(args.pulse).resolve()}"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    iso = m.kernel / "build" / "durable" / "absd-durable-0.iso"
    log = m.work / "pipeline.serial.log"
    result = subprocess.run([str(m.kernel / "scripts" / "durable-boot.sh"), str(iso), str(image), str(log),
                             "900", *served_qemu(m.qemu)], check=True, capture_output=True, text=True)
    serial = log.read_bytes()
    text = serial.decode(errors="replace")
    captured = nm.dm.Harness.captured(serial)
    (m.work / "pipeline.captured.txt").write_text(captured)
    status = int(result.stdout.strip())
    require(b"PANIC" not in serial and b"KERNEL FAULT" not in serial, "kernel fault")
    require(status == 3, f"pipeline boot status {status}\n{captured[-3000:]}")

    # Owners ran as separate brokered processes, and only those.
    started = re.findall(r"BROKER STARTED requester=worker slot=(\d) path=(\S+) program=(\S+) pid=\d+ block=(\S+)",
                         text)
    require([(p, prog, b) for _, p, prog, b in started] ==
            [("/owners/nq", "owner-1", "read"), ("/owners/pulse-support-resolver", "owner-2", "read")],
            f"unexpected brokered starts {started}")
    exited = re.findall(r"BROKER EXITED pid=\d+ slot=(\d) status=(-?\d+)", text)
    require(exited == [("0", "0"), ("1", "0")], f"owner outcomes {exited}")
    require(re.search(r"BROKER SUMMARY generation=1 requests=2 dropped=0 started=2 refused=0 exited=2 "
                      r"reclaimed=0 idle=true", text), "broker summary")
    require(re.search(r"DURABLE WORKER OUTCOME generation=1 pid=\d+ status=0", text), "writer outcome")
    require(re.search(r"^DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 ", text, re.M),
            "resource accounting after the boot")
    require("NIGHTSHIFT READONLY AUTHORITY OK" in captured, "reader authority probe")
    print("NIGHTSHIFT OWNERS NATIVE OK owners=nq,pulse-support-resolver brokered=2 block=read-only "
          "writer-spawn=none")

    # The writer's own result line against the Linux writer's.
    outcome = [line for line in captured.splitlines() if line.startswith('{"posture_only"')]
    require(len(outcome) == 1, f"writer outcome line\n{captured[-3000:]}")
    native_outcome = json.loads(outcome[0])
    linux_outcome = json.loads((reference / "stdout.json").read_bytes())
    observation = native_outcome["posture_only"]["cycle"]["observation"]
    support = observation["support"]
    require(support["standing"] == "unknown", f"support standing {support['standing']}")
    require(support["evaluated_at"]["clock_id"].startswith("pulse-absd-boot:sha256:"),
            f"support clock {support['evaluated_at']['clock_id']}")
    linux_admissions = linux_outcome["posture_only"]["cycle"]["observation"]["source_admissions"]
    require(observation["source_admissions"] == linux_admissions,
            "NQ admission provenance differs from the Linux writer's")
    provenance = json.loads((fixture / "nq" / "qualify-provenance.json").read_bytes())
    require(provenance in [entry.get("provenance", entry) for entry in observation["source_admissions"]]
            or json.dumps(provenance, sort_keys=True) in json.dumps(observation["source_admissions"], sort_keys=True),
            "native NQ provenance is not the Linux nq's")
    print(f"NIGHTSHIFT REAL OBSERVATION OK nq=linux-procfs support=unknown "
          f"clock={support['evaluated_at']['clock_id'][:36]}... admissions=linux-identical")

    # The store, extracted by the host's own filesystem reader.
    native = normalize(fixture, dump(extract_store(image)), m.work)
    expected = json.loads((reference / "store-normalized.json").read_bytes())
    if native != expected:
        (m.work / "native-store-normalized.json").write_text(json.dumps(native, indent=1, sort_keys=True))
        fail("normalized native store differs from the Linux empty-receipts store "
             f"(see {m.work}/native-store-normalized.json)")

    # The resolver: the first answer came from the pipeline boot's reader.
    answers = {}
    first = [line for line in captured.splitlines() if line.startswith('{"') and '"status"' in line
             and not line.startswith('{"posture_only"')]
    require(len(first) == 1, "reader answer in the pipeline boot")
    answers["current"] = json.loads(first[0])
    for name in REQUESTS[1:]:
        exit_status, line, _, _, _ = m.resolve(f"pipeline-{name}",
                                                image, (reference / "resolver" / f"{name}.request.json").read_bytes())
        require(exit_status == 0 and line, f"resolver {name}: exit {exit_status}")
        answers[name] = json.loads(line)
    for name in REQUESTS:
        linux = json.loads((reference / "resolver" / f"{name}.answer.json").read_bytes())
        for field in ("status", "basis", "fresh_until_unix_ms"):
            require(answers[name].get(field) == linux.get(field),
                    f"resolver {name}: {field} {answers[name].get(field)!r} != {linux.get(field)!r}")
    statuses = ",".join(f"{name}={answers[name]['status']}" for name in REQUESTS)
    print(f"NIGHTSHIFT NATIVE PIPELINE OK store=normalized-identical answers=[{statuses}] "
          f"boots={m.boots + 1}")


if __name__ == "__main__":
    main()
