#!/usr/bin/env python3
"""AG's real `ag-loopctl` natively on ABSD, standalone, qualified against Linux.

Reference (fixtures/ag-native, the Linux run `i-fresh-ag` of
scripts/make-reference-fixture.sh): on Linux the real Nightshift writer
called the real `ag-loopctl init` and `ag-loopctl record-proposal`, and AG's
own call to the real `nightshift-observation-resolver` (through the runtime
profile's pinned wrapper) answered `current`.

Here, on ABSD, for two deployments of the same resolver (its default TTL
is a deployment argument fixed in the image, as in the Linux wrapper):
`deployment` (one day, the reference's) and `short-ttl` (ten minutes):

- importer boots carry opaque bytes into the real filesystem: the
  reference's Nightshift store, AG's catalog, Docket trust, boundary
  command, issuer key, the exact genesis and proposal documents Nightshift
  handed AG (read out of the reference store), and a runtime profile sealed
  at ABSD paths by the real Linux `ag-loopctl`. It pins the resolver at
  `/ag/config/observation-resolver`, whose bytes the host proves equal to
  the catalog image init starts;
- `ag-loopctl init` runs as the durable worker;
- `ag-loopctl record-proposal` runs as the durable worker, with no spawn
  right: AG checks the resolver's path and digest, and init's broker starts
  the catalog resolver with a read-only block handle. After it, init runs
  the same image as the read-only reader on a request the Linux twin sent,
  so the native resolver's own answer is compared with Linux's.

The verdict does not depend on the date. `now` is the kernel's RTC. The Linux
twin (real Linux `ag-loopctl` and resolver, the same bytes at the same paths
in a private mount namespace, CLOCK_REALTIME pinned by an LD_PRELOAD shim)
replays each native run at the native instants, and exit status, stdout,
`Error:` lines, and the store must be equal. When the observation is
current, the store records the native instant exactly (`path=current`), and
the native state is also compared with the Linux reference itself: only the
resolution instant and the digests binding it may differ. When it is not,
AG refuses and records nothing, so no output carries the instant: the twin
replays at both ends of the host clock window around the boot, both must
agree (else the window straddled `fresh_until` and the run cannot be
judged), and the native outcome must equal them (`path=stale`). The
`deployment` variant takes the current path until one day after the
reference's evaluation instant (2026-10-11T23:16:28Z as produced) and the
stale path after; `short-ttl` takes the stale path.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
from served_ram import served_qemu
from served_kernel import kernel_make
import absd_fs  # noqa: E402

spec = importlib.util.spec_from_file_location("nightshift_matrix", here / "nightshift-matrix.py")
nm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nm)

# The resolver image (about 5.4 MB, symbols stripped) is carried inside the
# filesystem, which gets the second half of the device. Formatting reads
# every data sector of that half and each imported sector costs several
# timer ticks on the debug kernel's ATA path, while init gives a worker
# 120,000 ticks: the device stays at the default 16 MiB.
nm.IMAGE_BYTES = 16 * 1024 * 1024
nm.DEVICE_SECTORS = nm.IMAGE_BYTES // 512

# Where the reference run was produced (scripts/reference_fixture.py): its
# sealed profile and its store name these paths, so the twin mounts the
# reference there again.
REFERENCE_ROOT = "/tmp/absd-reference/runs/i-fresh-ag"
RESOLVER_PATH = "/ag/config/observation-resolver"
RESOLVER_ID = "nightshift-observation-resolver/v1"
RESOLVER_ARGS = ["--store", "/nightshift/nightshift.sqlite", "--resolver-id", RESOLVER_ID,
                 "--default-ttl-ms", "86400000"]
INIT_ARGS = ["init", "--database", "/ag/state/ag.sqlite", "--genesis", "/ag/genesis.json",
             "--runtime-profile", "/ag/config/runtime-profile.json"]
RECORD_ARGS = ["record-proposal", "--database", "/ag/state/ag.sqlite", "--input", "/ag/proposal.json",
               "--observation-resolver", RESOLVER_PATH, "--expected-observation-resolver-id", RESOLVER_ID]
POLICY = f"""\
# ag-loopctl record-proposal may start exactly the runtime profile's pinned
# observation resolver, with no arguments (its deployment arguments are
# fixed in the image), holding a read-only block handle. Nothing else: no
# Docket, standing, executor, or boundary command.
slots worker 1
allow worker {RESOLVER_PATH} owner-1 read 0
"""


def fail(message):
    print(f"AG NATIVE MATRIX FAILED: {message}", file=sys.stderr)
    sys.exit(1)


def require(condition, message):
    if not condition:
        fail(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def jcs(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def verify_fixture(fixture, linux_fixture):
    manifest = json.loads((fixture / "manifest.json").read_bytes())
    for relative, entry in manifest["files"].items():
        require(sha256((fixture / relative).read_bytes()) == entry["sha256"], f"fixture drift: {relative}")
    for relative, entry in manifest["linux_binaries"].items():
        require(sha256((linux_fixture / relative).read_bytes()) == entry["sha256"],
                f"Linux binary drift: {relative}")
    return manifest


def ag_documents(store):
    """The exact genesis and proposal documents Nightshift passed to
    `ag-loopctl` (it writes serde_jcs of each to a temp file), read from the
    prepared AG request the reference store recorded."""
    # A copy, read as immutable: SQLite must not leave -shm/-wal files next
    # to the fixture.
    with tempfile.TemporaryDirectory() as scratch:
        copy = pathlib.Path(scratch) / "nightshift.sqlite"
        shutil.copy(store, copy)
        return _ag_documents(copy)


def _ag_documents(store):
    db = sqlite3.connect(f"file:{store}?mode=ro&immutable=1", uri=True)
    requests = set()
    for (snapshot,) in db.execute("select snapshot_json from canonical_cycle_events order by sequence"):
        prepared = json.loads(snapshot).get("prepared_ag_request")
        if prepared:
            exact = prepared["exact_request"]
            requests.add((jcs(exact["mode"]["genesis"]["genesis"]), jcs(exact["proposal_input"])))
    db.close()
    require(len(requests) == 1, f"expected one prepared AG request, found {len(requests)}")
    return requests.pop()


def dump(files):
    """Every table and row of an AG store, read by the host's own SQLite
    from the database and WAL bytes (letting it recover the WAL)."""
    with tempfile.TemporaryDirectory() as scratch:
        for name, data in files.items():
            (pathlib.Path(scratch) / name).write_bytes(data)
        db = sqlite3.connect(pathlib.Path(scratch) / "ag.sqlite")
        tables = {}
        for (table,) in db.execute("select name from sqlite_master where type='table' order by name"):
            cursor = db.execute(f'select * from "{table}" order by rowid')
            columns = [column[0] for column in cursor.description]
            tables[table] = [{c: (v.hex() if isinstance(v, bytes) else v) for c, v in zip(columns, row)}
                             for row in cursor.fetchall()]
        schema = db.execute("select type,name,sql from sqlite_master order by type,name").fetchall()
        db.close()
    return {"schema": schema, "tables": tables}


def store_files(directory):
    return {p.name: p.read_bytes() for p in sorted(pathlib.Path(directory).iterdir())
            if p.name in ("ag.sqlite", "ag.sqlite-wal") and p.stat().st_size > 0}


def instants(dumped):
    rows = dumped["tables"]["transitions"]
    return [(row["transition_kind"], row["recorded_at_unix_ms"]) for row in rows]


def diff(a, b, path=""):
    """Paths where two JSON values differ."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for key in sorted(set(a) | set(b)):
            out += diff(a.get(key), b.get(key), f"{path}/{key}")
        return out
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        out = []
        for index, (x, y) in enumerate(zip(a, b)):
            out += diff(x, y, f"{path}/{index}")
        return out
    return [] if a == b else [path]


class Twin:
    """The real Linux binaries in a private mount namespace (bwrap) whose
    root holds the host's system directories read-only and the deployment's
    tree at its own absolute paths."""

    def __init__(self, work, linux_fixture, shim):
        self.work = work
        self.loopctl = linux_fixture / "bin" / "ag-loopctl"
        self.resolver = linux_fixture / "bin" / "nightshift-observation-resolver"
        self.shim = shim

    def run(self, binds, argv, now_ms=None, exec_map=None, spawn_log=None, stdin=None, ro_binds=()):
        command = ["bwrap", "--die-with-parent", "--unshare-pid", "--tmpfs", "/",
                   "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
                   "--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin", "--ro-bind", "/etc", "/etc",
                   "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
                   "--ro-bind", str(self.loopctl), "/twin/ag-loopctl",
                   "--ro-bind", str(self.resolver), "/twin/nightshift-observation-resolver",
                   "--ro-bind", str(self.shim), "/twin/twin-shim.so"]
        for source, target in binds:
            command += ["--bind", str(source), target]
        for source, target in ro_binds:
            command += ["--ro-bind", str(source), target]
        if spawn_log is not None:
            command += ["--bind", str(spawn_log.parent), "/twin-log"]
        env = {"PATH": "/usr/bin:/bin", "LD_PRELOAD": "/twin/twin-shim.so"}
        if now_ms is not None:
            env["AG_TWIN_NOW_MS"] = str(now_ms)
        if exec_map is not None:
            env["AG_TWIN_EXEC"] = exec_map
        if spawn_log is not None:
            env["AG_TWIN_SPAWN_LOG"] = f"/twin-log/{spawn_log.name}"
        command += ["--clearenv"]
        for key, value in env.items():
            command += ["--setenv", key, value]
        command += argv
        return subprocess.run(command, input=stdin, capture_output=True, check=False)


def reference_self_check(m, twin, fixture, genesis, proposal):
    """The twin reproduces the Linux reference run at the reference's own
    paths and instants: same stdout as `ag-loopctl status` there, same
    store row for row."""
    source = fixture / "reference" / "i-fresh-ag"
    reference = dump(store_files(source / "state"))
    moments = dict(instants(reference))
    tree = m.work / "reference-twin"
    shutil.copytree(source / "ag", tree / "ag")
    (tree / "state").mkdir(parents=True)
    shutil.copy(source / "state" / "nightshift.sqlite", tree / "state" / "nightshift.sqlite")
    (tree / "input").mkdir()
    (tree / "input" / "genesis.json").write_bytes(genesis)
    (tree / "input" / "proposal.json").write_bytes(proposal)
    wrapper = tree / "ag" / "config" / "observation-resolver"
    # The reference wrapper execs the Linux resolver at its fixture path;
    # inside the namespace that path is the twin's copy of the same binary.
    binds = [(tree, REFERENCE_ROOT)]
    ro = [(twin.resolver, str(pathlib.Path(REFERENCE_ROOT).parents[1] / "bin" / "nightshift-observation-resolver"))]
    require(f'exec "{pathlib.Path(REFERENCE_ROOT).parents[1]}/bin/nightshift-observation-resolver"'
            in wrapper.read_text(), "reference wrapper shape")
    database = f"{REFERENCE_ROOT}/state/ag.sqlite"
    first = twin.run(binds, ["/twin/ag-loopctl", "init", "--database", database,
                             "--genesis", f"{REFERENCE_ROOT}/input/genesis.json",
                             "--runtime-profile", f"{REFERENCE_ROOT}/ag/config/runtime-profile.json"],
                     now_ms=moments["campaign_created"], ro_binds=ro)
    require(first.returncode == 0, f"reference twin init: {first.stderr.decode()[-2000:]}")
    second = twin.run(binds, ["/twin/ag-loopctl", "record-proposal", "--database", database,
                              "--input", f"{REFERENCE_ROOT}/input/proposal.json",
                              "--observation-resolver", f"{REFERENCE_ROOT}/ag/config/observation-resolver",
                              "--expected-observation-resolver-id", RESOLVER_ID],
                      now_ms=moments["proposal_recorded"], ro_binds=ro)
    require(second.returncode == 0, f"reference twin record-proposal: {second.stderr.decode()[-2000:]}")
    status = (source / "ag-status.json").read_bytes()
    require(second.stdout == status, "reference twin state differs from the reference's `ag-loopctl status`")
    require(dump(store_files(tree / "state")) == reference, "reference twin store differs from the reference store")
    print(f"AG LINUX TWIN REFERENCE OK instants={moments['campaign_created']},{moments['proposal_recorded']} "
          f"state={json.loads(status)['state_digest']} store=row-identical")




def common_tree(m, fixture, genesis, proposal):
    """The deployment files every variant shares, at their ABSD paths."""
    source = fixture / "reference" / "i-fresh-ag"
    tree = m.work / "common-tree"
    (tree / "ag" / "config").mkdir(parents=True)
    (tree / "ag" / "secrets").mkdir()
    (tree / "ag" / "state").mkdir()
    (tree / "nightshift").mkdir()
    for name in ("boundary-command", "catalog.json", "docket-trust.json"):
        shutil.copy(source / "ag" / "config" / name, tree / "ag" / "config" / name)
    shutil.copy(source / "ag" / "secrets" / "issuer.pk8", tree / "ag" / "secrets" / "issuer.pk8")
    os.chmod(tree / "ag" / "config" / "boundary-command", 0o700)
    os.chmod(tree / "ag" / "secrets" / "issuer.pk8", 0o600)
    shutil.copy(source / "state" / "nightshift.sqlite", tree / "nightshift" / "nightshift.sqlite")
    (tree / "ag" / "genesis.json").write_bytes(genesis)
    (tree / "ag" / "proposal.json").write_bytes(proposal)
    return tree


def variant_tree(m, fixture, twin, common, variant):
    """The common files plus this variant's resolver image at the pinned
    path, and a runtime profile sealed there by the real Linux `ag-loopctl`
    from the reference enrollment with only its locators moved."""
    source = fixture / "reference" / "i-fresh-ag"
    tree = m.work / f"{variant['name']}-tree"
    shutil.copytree(common, tree)
    shutil.copy(variant["elf"], tree / "ag" / "config" / "observation-resolver")
    os.chmod(tree / "ag" / "config" / "observation-resolver", 0o700)
    enrollment = json.loads((source / "ag" / "config" / "enrollment.json").read_bytes())
    text = json.dumps(enrollment).replace(f"{REFERENCE_ROOT}/ag", "/ag")
    require(REFERENCE_ROOT not in text, "enrollment names a path outside the AG tree")
    (tree / "ag" / "config" / "enrollment.json").write_bytes(jcs(json.loads(text)))
    binds = [(tree / "ag", "/ag"), (tree / "nightshift", "/nightshift")]
    sealed = twin.run(binds, ["/twin/ag-loopctl", "seal-runtime-profile", "--enrollment",
                              "/ag/config/enrollment.json", "--output", "/ag/config/runtime-profile.json"])
    require(sealed.returncode == 0, f"seal: {sealed.stderr.decode()}")
    (tree / "ag" / "config" / "enrollment.json").unlink()  # a Linux sealing input, not a deployment file
    profile = json.loads((tree / "ag" / "config" / "runtime-profile.json").read_bytes())
    reference = json.loads((source / "ag" / "config" / "runtime-profile.json").read_bytes())
    changed = diff(reference, profile)
    locators = {path for path in changed if path.endswith("/path") or path == "/docket/state_directory"}
    require(set(changed) - locators == {"/observation_resolver/identity"},
            f"the native profile differs from the reference beyond locators and the resolver: {changed}")
    require(profile["observation_resolver"]["identity"] == f"sha256:{sha256(variant['elf'].read_bytes())}",
            "the profile does not pin the ABSD resolver image")
    print(f"AG RUNTIME PROFILE SEALED variant={variant['name']} "
          f"receipt={json.loads(sealed.stdout)['profile_digest']} "
          f"differs_from_reference=locators,observation_resolver.identity")
    return tree


def files_of(tree, only=None):
    out = []
    for path in sorted(tree.rglob("*")):
        relative = "/" + path.relative_to(tree).as_posix()
        if only is not None and relative not in only:
            continue
        if path.is_dir():
            if not any(path.iterdir()):
                out.append((relative + "/", b""))
        else:
            out.append((relative, path.read_bytes()))
    return out


def image_files(image):
    region = absd_fs.fs_region(image, nm.DEVICE_SECTORS)
    selected = absd_fs.select(region)
    tree = absd_fs.tree(region, selected)
    return {path: absd_fs.content(region, selected, record) for path, record in tree.items()}, tree


def native_store(image):
    files, _ = image_files(image)
    return {path.rsplit("/", 1)[1]: data for path, data in files.items()
            if path in ("/ag/state/ag.sqlite", "/ag/state/ag.sqlite-wal") and data}


def import_image(m, name, files, step, image):
    """One fixture importer boot (nightshift-matrix's, with this matrix's
    host timeout: init's image embeds the whole stream, and the kernel's
    boot-time spawn tests copy it several times before the worker starts).
    Step 1 formats the device; 2 adds new files; 3 appends to existing ones."""
    stream = nm.stream(files)
    input_path = m.work / f"input-{sha256(stream)}.bin"
    input_path.write_bytes(stream)
    variables = [f"DURABLE_STEP={step}", f"EXTERNAL_USER_ELF={m.importer}", f"EXTERNAL_INPUT={input_path}",
                 "EXTERNAL_READER_ELF=", "EXTERNAL_READER_INPUT=", "BROKER_POLICY=", "OWNER_1_ELF="]
    subprocess.run([*kernel_make(), "--no-print-directory", "-C", str(m.kernel), "durable-iso", *variables],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    iso = m.kernel / "build" / "durable" / f"absd-durable-{step}.iso"
    m.boots += 1
    log = m.work / f"{name}.import-{m.boots:02d}-step{step}.serial.log"
    result = subprocess.run([str(m.kernel / "scripts" / "durable-boot.sh"), str(iso), str(image), str(log),
                             "1800", *served_qemu(m.qemu)], check=True, capture_output=True, text=True)
    serial = log.read_bytes()
    captured = nm.dm.Harness.captured(serial)
    require(b"PANIC" not in serial and b"KERNEL FAULT" not in serial, f"{name}: kernel fault")
    status = int(result.stdout.strip())
    require(status == 3 and f"FIXTURE IMPORT OK files={len(files)}" in captured,
            f"{name}: import status {status}\n{captured[-3000:]}")
    ticks = re.search(r"^DURABLE status=0 .* ticks=(\d+)", serial.decode(errors="replace"), re.M)
    print(f"AG FIXTURE IMPORT {name} step={step} files={len(files)} bytes={sum(len(d) for _, d in files)} "
          f"ticks={ticks.group(1) if ticks else '?'}")


class Outcome:
    """What one ag-loopctl invocation left: exit status, stdout, the
    `Error:` lines of stderr (the console also carries the platform's mount
    line), and, for a native boot, the host clock window around it."""

    def __init__(self, status, stdout, errors, before=None, after=None):
        self.status, self.stdout, self.errors = status, stdout, errors
        self.before, self.after = before, after

    def same(self, other):
        return (self.status, self.stdout, self.errors) == (other.status, other.stdout, other.errors)

    def __repr__(self):
        return f"status={self.status} stdout={self.stdout[:120]!r} errors={self.errors}"


def boot(m, name, worker, image, policy=None, owner=None, reader_request=None):
    variables = ["DURABLE_STEP=0", f"EXTERNAL_USER_ELF={worker}", f"EXTERNAL_INPUT={m.work / 'empty.bin'}"]
    if reader_request is not None:
        request_path = m.work / f"reader-request-{sha256(reader_request)}.json"
        request_path.write_bytes(reader_request)
        variables += [f"EXTERNAL_READER_ELF={owner}", f"EXTERNAL_READER_INPUT={request_path}"]
    else:
        variables += ["EXTERNAL_READER_ELF=", "EXTERNAL_READER_INPUT="]
    variables += [f"BROKER_POLICY={policy or ''}", f"OWNER_1_ELF={owner or ''}"]
    subprocess.run([*kernel_make(), "--no-print-directory", "-C", str(m.kernel), "durable-iso", *variables],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    iso = m.kernel / "build" / "durable" / "absd-durable-0.iso"
    log = m.work / f"{name}.serial.log"
    before = time.time()
    result = subprocess.run([str(m.kernel / "scripts" / "durable-boot.sh"), str(iso), str(image), str(log),
                             "1800", *served_qemu(m.qemu)], check=True, capture_output=True, text=True)
    after = time.time()
    serial = log.read_bytes()
    text = serial.decode(errors="replace")
    captured = nm.dm.Harness.captured(serial)
    (m.work / f"{name}.captured.txt").write_text(captured)
    require(b"PANIC" not in serial and b"KERNEL FAULT" not in serial, f"{name}: kernel fault")
    worker = re.findall(r"DURABLE WORKER OUTCOME generation=(\d+) pid=\d+ status=(-?\d+)", text)
    require(len(worker) == 1 and worker[0][0] == "1", f"{name}: one worker generation expected: {worker}")
    status = int(worker[0][1])
    boot_status = int(result.stdout.strip())
    # init ends the boot orderly (3) on a worker's 0 and as a failed
    # workload (7) on any other exit; resources are reclaimed either way.
    require(boot_status == (3 if status == 0 else 7), f"{name}: boot status {boot_status} for worker {status}\n"
            f"{captured[-3000:]}")
    require(re.search(r"^DURABLE status=\d+ frames=0 processes=0 cells=0 pipes=0 ", text, re.M),
            f"{name}: resource accounting after the boot")
    require("AG LOOPCTL MOUNT OK" in captured, f"{name}: mount line")
    lines = captured.splitlines()
    stdout = b"".join(line.encode() + b"\n" for line in lines if line.startswith('{"prior_state_digest"'))
    errors = [line for line in lines if line.startswith("Error:")]
    answers = [line for line in lines if line.startswith('{"basis"')]
    return Outcome(status, stdout, errors, before, after), text, captured, answers


class Twin2:
    """The Linux twin of one variant at chosen instants: the variant's tree
    with an empty state directory, the real Linux ag-loopctl, and the pinned
    resolver path mapped to the Linux resolver with the variant's deployment
    arguments. A wrapper keeps the exact request and answer."""

    def __init__(self, m, twin, tree, variant):
        self.m, self.twin, self.tree, self.variant = m, twin, tree, variant

    def run(self, now_init, now_record, label):
        root = self.m.work / f"twin-{self.variant['name']}-{label}"
        shutil.copytree(self.tree, root / "tree")
        io = root / "io"
        io.mkdir()
        wrapper = root / "resolver"
        wrapper.mkdir()
        args = " ".join(self.variant["args"])
        (wrapper / "observation-resolver").write_text(
            "#!/bin/sh\nset -e\ntee /twin-io/request.json | /twin/nightshift-observation-resolver "
            f"{args} > /twin-io/answer.json\ncat /twin-io/answer.json\n")
        os.chmod(wrapper / "observation-resolver", 0o700)
        binds = [(root / "tree" / "ag", "/ag"), (root / "tree" / "nightshift", "/nightshift"),
                 (wrapper, "/twin-resolver"), (io, "/twin-io")]
        exec_map = f"{RESOLVER_PATH}=/twin-resolver/observation-resolver"
        spawns = root / "spawns.log"
        first = self.twin.run(binds, ["/twin/ag-loopctl", *INIT_ARGS], now_ms=now_init, exec_map=exec_map,
                              spawn_log=spawns)
        init_spawns = spawns.read_text() if spawns.exists() else ""
        second = self.twin.run(binds, ["/twin/ag-loopctl", *RECORD_ARGS], now_ms=now_record,
                               exec_map=exec_map, spawn_log=spawns)
        record_spawns = (spawns.read_text() if spawns.exists() else "")[len(init_spawns):]
        require(init_spawns == "", f"twin init spawned {init_spawns!r}")
        started = [line.split()[1] for line in record_spawns.splitlines()]
        require(started[:1] == [RESOLVER_PATH] and all(
            pathlib.Path(path).name in ("tee", "cat", "nightshift-observation-resolver") for path in started[1:]),
            f"twin record-proposal started {started}")

        def outcome(result):
            errors = [line for line in result.stderr.decode().splitlines() if line.startswith("Error:")]
            return Outcome(result.returncode, result.stdout, errors)

        return {"init": outcome(first), "record": outcome(second),
                "store": dump(store_files(root / "tree" / "ag" / "state")),
                "request": (io / "request.json").read_bytes(),
                "answer": (io / "answer.json").read_bytes().strip()}


def run_variant(m, fixture, twin, common_image, common, variant, record_elf, init_elf):
    name = variant["name"]
    tree = variant_tree(m, fixture, twin, common, variant)
    image = m.work / f"{name}.img"
    shutil.copy(common_image, image)
    # The resolver image travels in thirds (see the importer): created with
    # its first third, beside the sealed profile, then two appends.
    resolver_bytes = (tree / "ag" / "config" / "observation-resolver").read_bytes()
    profile_bytes = (tree / "ag" / "config" / "runtime-profile.json").read_bytes()
    third = -(-len(resolver_bytes) // 3)
    parts = [resolver_bytes[index * third:(index + 1) * third] for index in range(3)]
    import_image(m, name, [("/ag/config/runtime-profile.json", profile_bytes), (RESOLVER_PATH, parts[0])], 2, image)
    for part in parts[1:]:
        import_image(m, name, [(RESOLVER_PATH, part)], 3, image)
    on_disk, _ = image_files(image)
    for path, data in files_of(tree):
        require(path.endswith("/") or on_disk.get(path) == data, f"{name}: host reader sees different bytes at {path}")
    digest = sha256(variant["elf"].read_bytes())
    require(sha256(on_disk[RESOLVER_PATH]) == digest, f"{name}: resolver file differs from the catalog image")
    print(f"AG RESOLVER IDENTITY OK variant={name} path={RESOLVER_PATH} fs_sha256={digest} "
          f"catalog_sha256={digest} bytes={len(on_disk[RESOLVER_PATH])}")
    twin2 = Twin2(m, twin, tree, variant)

    # Boot: ag-loopctl init; no broker policy at all.
    init, text, _, _ = boot(m, f"{name}.init", init_elf, image)
    require("BROKER STARTED" not in text, f"{name}: init started a brokered process")
    require(init.status == 0, f"{name}: native init {init}")
    moments = instants(dump(native_store(image)))
    require([kind for kind, _ in moments] == ["campaign_created"], f"{name}: init transitions")
    init_now = moments[0][1]
    require(init_now % 1000 == 0, f"{name}: init instant {init_now} is not whole RTC seconds")
    require(init.before - 2 <= init_now / 1000 <= init.after + 2,
            f"{name}: init instant {init_now} outside the host clock window [{init.before}, {init.after}]")

    # Boot: ag-loopctl record-proposal; its resolver call goes through init.
    # After the worker, init runs the same resolver image as the read-only
    # reader on the request the Linux twin sends at the boot's first second,
    # so the native resolver's own answer is on record whichever path runs.
    probe_now = int(time.time()) * 1000
    probe = twin2.run(init_now, probe_now, "probe")
    policy = m.work / "ag-native-policy.txt"
    policy.write_text(POLICY)
    record, text, captured, answers = boot(m, f"{name}.record-proposal", record_elf, image, policy,
                                           variant["elf"], reader_request=probe["request"])
    started = re.findall(r"BROKER STARTED requester=worker slot=(\d) path=(\S+) program=(\S+) pid=\d+ block=(\S+)",
                         text)
    require([(p, prog, b) for _, p, prog, b in started] == [(RESOLVER_PATH, "owner-1", "read")],
            f"{name}: unexpected brokered starts {started}")
    require(re.findall(r"BROKER EXITED pid=\d+ slot=(\d) status=(-?\d+)", text) == [("0", "0")],
            f"{name}: resolver outcome")
    require(re.search(r"BROKER SUMMARY generation=1 requests=1 dropped=0 started=1 refused=0 exited=1 "
                      r"reclaimed=0 idle=true", text), f"{name}: broker summary")
    require(b"DURABLE READER START" in pathlib.Path(m.work / f"{name}.record-proposal.serial.log").read_bytes()
            and "NIGHTSHIFT READONLY AUTHORITY OK" in captured, f"{name}: reader authority probe")
    require(len(answers) == 1 and answers[0].encode() == probe["answer"],
            f"{name}: native resolver answer to the probe request differs from Linux:\n{answers}\n{probe['answer']}")
    probe_status = json.loads(probe["answer"])["status"]
    print(f"AG RESOLVER ANSWER OK variant={name} now={probe_now} status={probe_status} native=linux-identical "
          f"reader=read-only")
    store = native_store(image)
    native = dump(store)
    moments = instants(native)

    if record.status == 0:
        # The current path: the observation was current at the native
        # instant, which the store records exactly.
        require([kind for kind, _ in moments] == ["campaign_created", "proposal_recorded"],
                f"{name}: native transitions")
        record_now = moments[1][1]
        require(record_now % 1000 == 0, f"{name}: record instant {record_now} is not whole RTC seconds")
        require(record.before - 2 <= record_now / 1000 <= record.after + 2,
                f"{name}: record instant {record_now} outside the host clock window")
        twins = [twin2.run(init_now, record_now, "exact")]
        state = json.loads(record.stdout)
        observation = state["state"]["proposal_recorded"]["observation"]
        require(observation["resolved_at_unix_ms"] == record_now, "resolution instant is not AG's now")
        require(observation["status"] == "current", f"{name}: recorded status {observation['status']}")
        path, instants_text = "current", f"now_record={record_now}"
    else:
        # Not current at the native instant: AG refuses and records nothing,
        # so no output carries that instant. The twin replays at both ends of
        # the host clock window around the boot; any second inside it gives
        # the same outcome only if both ends agree (a window that straddles
        # the resolver's fresh_until cannot be judged and fails).
        require(moments == [("campaign_created", init_now)],
                f"{name}: a refused record-proposal changed the campaign: {moments}")
        low, high = (int(record.before) - 2) * 1000, (int(record.after) + 3) * 1000
        twins = [twin2.run(init_now, low, "window-start"), twin2.run(init_now, high, "window-end")]
        require(twins[0]["record"].same(twins[1]["record"]) and twins[0]["store"] == twins[1]["store"],
                f"{name}: the host window [{low}, {high}] straddles a change in the answer; rerun")
        statuses = {json.loads(t["answer"])["status"] for t in twins}
        require(len(statuses) == 1 and "current" not in statuses, f"{name}: twin statuses {statuses}")
        path, instants_text = statuses.pop(), f"window=[{low},{high}]"
    for replay in twins:
        require(replay["init"].same(init), f"{name}: native init {init} differs from Linux {replay['init']}")
        require(replay["record"].same(record),
                f"{name}: native record-proposal {record} differs from Linux {replay['record']}")
        require(replay["store"] == native, f"{name}: native AG store differs from the Linux twin's")
    if path == "current":
        answer = json.loads(twins[0]["answer"])
        require(json.loads(record.stdout)["state"]["proposal_recorded"]["observation"] == answer,
                f"{name}: AG recorded something other than the Linux resolver's answer")
    # The unpatched Linux ag-loopctl accepts the native store.
    with tempfile.TemporaryDirectory() as scratch:
        for file_name, data in store.items():
            (pathlib.Path(scratch) / file_name).write_bytes(data)
        database = str(pathlib.Path(scratch) / "ag.sqlite")
        status = subprocess.run([str(twin.loopctl), "status", "--database", database], capture_output=True)
        replay = subprocess.run([str(twin.loopctl), "replay", "--database", database], capture_output=True)
    require(status.returncode == 0 and replay.returncode == 0, f"{name}: Linux status/replay of the native store")
    current_state = json.loads(status.stdout)
    require(json.loads(replay.stdout).get("current_state_digest") == current_state["state_digest"],
            f"{name}: Linux replay state digest")
    if path == "current":
        require(status.stdout == record.stdout, f"{name}: Linux `status` of the native store")
    fresh_until = json.loads(twins[0]["answer"])["fresh_until_unix_ms"]
    print(f"AG LOOPCTL NATIVE OK variant={name} path={path} subcommands=init,record-proposal worker-spawn=none "
          f"clock=rtc now_init={init_now} {instants_text} fresh_until={fresh_until} "
          f"record_exit={record.status} errors={record.errors or 'none'} pc={next(iter(current_state['state']))}")
    print(f"AG NESTED RESOLVER OK variant={name} path={RESOLVER_PATH} program=owner-1 brokered=1 block=read-only "
          f"exited=0 boundary_commands=not-invoked")
    print(f"AG STORE EQUIVALENCE OK variant={name} path={path} linux_twin=exit,stdout,errors,store-row-identical "
          f"instants={len(twins)} linux_status=accepted linux_replay=verified")
    return path, record, native, twins


def reference_equivalence(fixture, record, native):
    """On the current path, the native state against the Linux reference at
    its own instant: only the resolution instant and the digests binding it
    may differ."""
    source = fixture / "reference" / "i-fresh-ag"
    reference_state = json.loads((source / "ag-status.json").read_bytes())
    state = json.loads(record.stdout)
    changed = diff(reference_state, state)
    time_bound = {"/state/proposal_recorded/observation/resolved_at_unix_ms", "/state_digest"}
    require(set(changed) <= time_bound,
            f"native state differs from the reference beyond the wall-clock instant: {changed}")
    require(state["prior_state_digest"] == reference_state["prior_state_digest"], "genesis state digest")
    table_changes = diff(dump(store_files(source / "state"))["tables"], native["tables"])
    for path in table_changes:
        require(re.search(r"/(runtime_profile/0/(profile_jcs|profile_digest)|transitions/[01]/"
                          r"(recorded_at_unix_ms|evidence_jcs|evidence_digest|event_digest|previous_event_digest|"
                          r"successor_snapshot_jcs|successor_state_digest)|campaigns/0/(event_head_digest|"
                          r"current_state_digest)|occurrences/0/(snapshot_jcs|state_digest))$", path),
                f"unexpected store difference from the reference at {path}")
    print(f"AG REFERENCE EQUIVALENCE OK path=current state_diff={','.join(changed) or 'none'} "
          f"store_cells={len(table_changes)}(profile-locators,instants,chained-digests) "
          f"reference_resolved_at={reference_state['state']['proposal_recorded']['observation']['resolved_at_unix_ms']}")


def main():
    parser = argparse.ArgumentParser()
    for name in ("--kernel", "--importer", "--init", "--record", "--resolver", "--resolver-short-ttl",
                 "--fixture", "--linux-fixture", "--shim-source", "--work", "--qemu"):
        parser.add_argument(name, required=True)
    args = parser.parse_args()
    fixture = pathlib.Path(args.fixture).resolve()
    linux_fixture = pathlib.Path(args.linux_fixture).resolve()
    m = nm.Matrix(argparse.Namespace(kernel=args.kernel, importer=args.importer, resolver=args.resolver,
                                     linux_resolver=None, fixture=fixture.parent / "nightshift",
                                     work=args.work, qemu=args.qemu))
    (m.work / "empty.bin").write_bytes(b"")
    verify_fixture(fixture, linux_fixture)
    shim = m.work / "twin-shim.so"
    subprocess.run(["gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Werror", "-o", str(shim), args.shim_source,
                    "-ldl"], check=True)
    twin = Twin(m.work, linux_fixture, shim)
    genesis, proposal = ag_documents(fixture / "reference" / "i-fresh-ag" / "state" / "nightshift.sqlite")
    reference_self_check(m, twin, fixture, genesis, proposal)

    common = common_tree(m, fixture, genesis, proposal)
    common_image = m.image("common")
    import_image(m, "common", files_of(common), 1, common_image)
    base = ["--store", "/nightshift/nightshift.sqlite", "--resolver-id", RESOLVER_ID, "--default-ttl-ms"]
    variants = [
        # The reference deployment: current for one day after the
        # reference's evaluation instant, not current after it; the matrix
        # holds on whichever path the date gives.
        {"name": "deployment", "elf": pathlib.Path(args.resolver).resolve(), "args": base + ["86400000"]},
        # The same resolver deployed with a ten-minute TTL (as
        # nightshift-resolver.elf is): its answer stopped being current ten
        # minutes after that instant, so this variant runs the not-current
        # path.
        {"name": "short-ttl", "elf": pathlib.Path(args.resolver_short_ttl).resolve(), "args": base + ["600000"]},
    ]
    paths = {}
    for variant in variants:
        path, record, native, _ = run_variant(m, fixture, twin, common_image, common, variant,
                                              pathlib.Path(args.record).resolve(), pathlib.Path(args.init).resolve())
        paths[variant["name"]] = path
        if path == "current":
            reference_equivalence(fixture, record, native)
    require(paths["short-ttl"] != "current", "the ten-minute deployment answered current")
    print(f"AG NATIVE MATRIX OK paths={','.join(f'{k}={v}' for k, v in paths.items())}")


if __name__ == "__main__":
    main()
