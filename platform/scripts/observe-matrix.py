#!/usr/bin/env python3
"""ABSD as an observed host: the ABSD-owned frame-pressure support family
(`pulse.absd_host_frame_pressure.v1`, question `absd.host.frame_pressure/v1`,
documents in observe/) end to end on ABSD.

In one boot the durable worker is the family's cycle image: Pulse's own
producer reads the kernel's frame allocator counts (`frame_stats`) and signs
an evidence envelope on the ABSD boot clock, then Pulse's own receiver
stamps its receipt on the same clock; init then runs the family's
`pulse-support-resolver` as the read-only reader. Nothing is made on Linux:
the host only generates a test signing key and the configuration, and
reads the device back.

The host checks every native evidence frame independently (exact JCS,
identities, the ed25519 signature, the state re-derived from the raw
counts in Python integers, the boot-clock custody and the 60 s expiry),
and the host reference (the same family library, `resolve_with` with an
injected clock) must reproduce every native answer byte for byte at the
native instant.
"""

import argparse
import hashlib
import json
import pathlib
import re
import struct
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import absd_fs  # noqa: E402
import absd_inputs  # noqa: E402

IMAGE_BYTES = 16 * 1024 * 1024
DEVICE_SECTORS = IMAGE_BYTES // 512
ROOT = "/observe"
CONFIG_PATH = f"{ROOT}/support-config.json"
KEY_PATH = f"{ROOT}/producer.key"
OUTGOING = f"{ROOT}/outgoing"
RECEIPTS = f"{ROOT}/receipts"
FAMILY = "pulse.absd_host_frame_pressure.v1"
SOURCE_BASIS = "absd_kernel_frame_stats_v1"
VALIDITY_MS = 60_000
THRESHOLD_PER_MILLE = 125
DOMAIN = b"pulse/absd-host-frame-pressure-support/evidence/v1\0"
ABSD_CLOCK = re.compile(r"^pulse-absd-boot:sha256:[0-9a-f]{64}$")
CHUNK = re.compile(rb"EXTERNAL OUTPUT CHUNK offset=([0-9a-f]{16}) data=([0-9a-f]*)")
READER = re.compile(r"PULSE FRAME PRESSURE READONLY AUTHORITY OK fs_seq=\d+ write=refused-by-kernel "
                    r"test_config=(true|false)\n")
OUTCOME = re.compile(r"DURABLE (WORKER|READER) OUTCOME .*status=(-?\d+)")
SUPPORT_FIELDS = ["schema", "support_id", "authority_id", "query_id", "observation_cycle_id", "request_nonce",
                  "observation_id", "diagnostic_inputs_id", "subject_id", "scope_id", "artifact_ids",
                  "evaluated_at", "expiry", "standing", "evidence_refs", "contradiction_refs"]


def fail(message):
    print(f"OBSERVE MATRIX FAILED: {message}", file=sys.stderr)
    sys.exit(1)


def require(condition, message):
    if not condition:
        fail(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def digest(text):
    return "sha256:" + sha256(text.encode())


def jcs(value):
    # Objects, arrays, ASCII strings, integers and null only.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def object_id(value, field):
    preimage = dict(value)
    preimage.pop(field, None)
    return "sha256:" + sha256(jcs(preimage))


def occurrence(acquisition_id):
    return "sha256-" + sha256(acquisition_id.encode()) + ".json"


def stream(files):
    out = bytearray(b"ABSDFIX1")
    for path, data in files:
        name = path.encode()
        out += struct.pack("<H", len(name)) + name + struct.pack("<Q", len(data))
        out += hashlib.sha256(data).digest() + data
    out += struct.pack("<H", 0)
    return bytes(out)


def captured(serial):
    data = bytearray()
    for match in CHUNK.finditer(serial):
        require(int(match.group(1), 16) == len(data), "non-contiguous captured output")
        data.extend(bytes.fromhex(match.group(2).decode("ascii")))
    return data.decode("utf-8", errors="replace")


def derive(evidence):
    """The family's state from its raw counts, written from
    observe/profile.v1.json and observe/threshold-policy.v1.json, not from
    the Rust code; None when the reading cannot carry the question."""
    free, allocated, limit = evidence["free_frames"], evidence["allocated_frames"], evidence["allocation_limit"]
    if evidence["frame_bytes"] != 4096:
        return None
    tracked = free + allocated
    if limit is None:
        capacity, headroom = tracked, free
    else:
        if allocated > limit:
            return None
        capacity, headroom = min(tracked, limit), min(free, limit - allocated)
    if capacity == 0:
        return None
    return "present" if headroom * 1000 < capacity * THRESHOLD_PER_MILLE else "explicitly_absent"


class Family:
    """The test deployment: key, configuration and queries."""

    def __init__(self, root):
        documents = {name: "sha256:" + sha256((root / "observe" / f"{name}.v1.json").read_bytes())
                     for name in ("question", "profile", "threshold-policy")}
        self.documents = documents
        semantic = {"schema": "absd.observation_semantic_id.v1", "question": documents["question"],
                    "profile": documents["profile"], "threshold_policy": documents["threshold-policy"]}
        self.semantic_id = "sha256:" + sha256(jcs(semantic))
        key = Ed25519PrivateKey.generate()
        self.private_hex = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                             serialization.NoEncryption()).hex()
        self.public = key.public_key()
        self.public_hex = self.public.public_bytes(serialization.Encoding.Raw,
                                                   serialization.PublicFormat.Raw).hex()

    def config(self, expected_state="explicitly_absent", root=ROOT):
        return {
            "schema": "pulse.absd_host_frame_pressure_support_config.v1",
            "authority_id": "pulse-authority:absd-frame-pressure-test",
            "support_family": FAMILY,
            "producer_id": "pulse-producer:absd-frame-pressure-test",
            "producer_key_id": "pulse-key:sha256:" + sha256(bytes.fromhex(self.public_hex)),
            "producer_public_key_hex": self.public_hex,
            "producer_private_key_path": f"{root}/producer.key",
            "subject_id": "host:absd-local",
            "scope_id": digest("absd-observe/test-scope/v1"),
            "vantage_id": "absd.vantage.kernel-frame-stats",
            "question": {"id": "absd.host.frame_pressure", "version": "1", "digest": self.documents["question"]},
            "profile": {"id": "absd.host", "version": "1", "digest": self.documents["profile"]},
            "profile_semantic_id": self.semantic_id,
            "threshold_policy": {"id": "absd.host.frame_pressure.threshold_policy", "version": "1",
                                 "digest": self.documents["threshold-policy"]},
            "outgoing_directory": f"{root}/outgoing",
            "receipt_directory": f"{root}/receipts",
            "expected_diagnostic": {
                "diagnostic_inputs_id": digest("absd-observe/test-diagnostic-inputs/v1"),
                "artifact_ids": [digest("absd-observe/test-artifact/v1")],
                "expected_state": expected_state,
            },
        }

    def query(self, nonce="support-query:absd-observe-1", **overrides):
        config = self.config()
        value = {
            "schema": "nightshift.present_evidence_query.v1",
            "query_id": "",
            "observation_cycle_id": "cycle:absd-observe",
            "request_nonce": nonce,
            "observation_id": digest("absd-observe/test-observation/v1"),
            "diagnostic_inputs_id": config["expected_diagnostic"]["diagnostic_inputs_id"],
            "subject_id": config["subject_id"],
            "scope_id": config["scope_id"],
            "artifact_ids": config["expected_diagnostic"]["artifact_ids"],
        }
        value.update(overrides)
        value["query_id"] = object_id(value, "query_id")
        return jcs(value)

    def files(self, expected_state="explicitly_absent", receipts=None):
        files = [(CONFIG_PATH, jcs(self.config(expected_state))), (KEY_PATH, self.private_hex.encode()),
                 (f"{OUTGOING}/", b"")]
        if receipts:
            files += [(f"{RECEIPTS}/{name}", data) for name, data in sorted(receipts.items())]
        else:
            files.append((f"{RECEIPTS}/", b""))
        return files


class Matrix:
    def __init__(self, args):
        self.root = pathlib.Path(args.root).resolve()
        self.kernel = pathlib.Path(args.kernel).resolve()
        self.old_kernel = pathlib.Path(args.old_kernel).resolve() if args.old_kernel else None
        self.importer = pathlib.Path(args.importer).resolve()
        self.cycle = pathlib.Path(args.cycle).resolve()
        self.resolver = pathlib.Path(args.resolver).resolve()
        self.deployment = pathlib.Path(args.deployment_resolver).resolve()
        self.reference = pathlib.Path(args.reference).resolve()
        self.linux = pathlib.Path(args.linux).resolve()
        self.work = pathlib.Path(args.work).resolve()
        self.qemu = args.qemu.split()
        self.work.mkdir(parents=True, exist_ok=True)
        self.boots = 0
        for kernel in (self.kernel, self.old_kernel):
            require(kernel is None or not absd_inputs.is_kernel_source(kernel), "refusing the canonical kernel checkout")
        self.family = Family(self.root)

    # --- ABSD -----------------------------------------------------------
    def write_input(self, data):
        path = self.work / f"input-{sha256(data)}.bin"
        path.write_bytes(data)
        return path

    def iso(self, kernel, step, worker, worker_input, reader=None, reader_input=b""):
        subprocess.run(["make", "--no-print-directory", "-C", str(kernel), "durable-iso", f"DURABLE_STEP={step}",
                        f"EXTERNAL_USER_ELF={worker}", f"EXTERNAL_INPUT={self.write_input(worker_input)}",
                        f"EXTERNAL_READER_ELF={reader or ''}",
                        f"EXTERNAL_READER_INPUT={self.write_input(reader_input) if reader else ''}"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        return kernel / "build" / "durable" / f"absd-durable-{step}.iso"

    def raw_boot(self, name, kernel, iso, image, memory=None):
        self.boots += 1
        log = self.work / f"{name}.{self.boots:03d}.serial.log"
        qemu = self.qemu + (["-m", memory] if memory else [])
        result = subprocess.run([str(kernel / "scripts" / "durable-boot.sh"), str(iso), str(image), str(log),
                                 "300", *qemu], check=True, capture_output=True, text=True)
        serial = log.read_bytes()
        require(b"PANIC" not in serial and b"KERNEL FAULT" not in serial, f"{name}: kernel fault")
        return int(result.stdout.strip()), serial.decode(errors="replace"), captured(serial)

    def import_files(self, name, files, kernel=None):
        kernel = kernel or self.kernel
        image = self.work / f"{name}.img"
        with open(image, "wb") as handle:
            handle.truncate(IMAGE_BYTES)
        iso = self.iso(kernel, 1, self.importer, stream(files))
        status, _, text = self.raw_boot(f"{name}.import", kernel, iso, image)
        require(status == 3 and f"FIXTURE IMPORT OK files={len(files)}" in text,
                f"{name}: import status {status}\n{text}")
        tree = self.tree(image)
        for path, data in files:
            if path.endswith("/"):
                require(path[:-1] in tree, f"{name}: host reader misses directory {path}")
            else:
                require(self.read(image, path) == data, f"{name}: host reader sees different bytes at {path}")
        return image

    def tree(self, image):
        region = absd_fs.fs_region(image, DEVICE_SECTORS)
        return absd_fs.tree(region, absd_fs.select(region))

    def read(self, image, path):
        region = absd_fs.fs_region(image, DEVICE_SECTORS)
        selected = absd_fs.select(region)
        tree = absd_fs.tree(region, selected)
        return absd_fs.content(region, selected, tree[path]) if path in tree else None

    def listing(self, image, directory):
        prefix = directory + "/"
        return sorted(p[len(prefix):] for p in self.tree(image) if p.startswith(prefix) and p != directory)

    def boot(self, name, image, worker, worker_input, reader, reader_input, kernel=None, memory=None):
        """One boot: returns (worker status, worker text, reader status,
        reader test_config marker, reader body)."""
        kernel = kernel or self.kernel
        iso = self.iso(kernel, 0, worker, worker_input, reader, reader_input)
        status, serial, text = self.raw_boot(name, kernel, iso, image, memory)
        outcomes = OUTCOME.findall(serial)
        require([o[0] for o in outcomes] == ["WORKER", "READER"], f"{name}: outcomes {outcomes}\n{serial[-3000:]}")
        markers = list(READER.finditer(text))
        require(markers, f"{name}: no reader marker\n{text}")
        last = markers[-1]
        worker_text = text[:last.start()]
        if worker == self.resolver or worker == self.deployment:
            require(len(markers) == 2 and markers[0].start() == 0, f"{name}: worker marker\n{text}")
            worker_text = text[markers[0].end():last.start()]
        return (int(outcomes[0][1]), worker_text, int(outcomes[1][1]), last.group(1), text[last.end():])

    # --- host -----------------------------------------------------------
    def host_tree(self, scratch, receipts, expected_state="explicitly_absent"):
        root = pathlib.Path(scratch)
        (root / "receipts").mkdir(parents=True, exist_ok=True)
        (root / "outgoing").mkdir(parents=True, exist_ok=True)
        for name, data in receipts.items():
            (root / "receipts" / name).write_bytes(data)
        key = root / "producer.key"
        key.write_bytes(self.family.private_hex.encode())
        key.chmod(0o600)
        path = root / "config.json"
        path.write_bytes(jcs(self.family.config(expected_state, str(root))))
        return path

    def reference_resolve(self, receipts, query, clock_id, tick, expected_state="explicitly_absent"):
        with tempfile.TemporaryDirectory() as scratch:
            config = self.host_tree(scratch, receipts, expected_state)
            result = subprocess.run([str(self.reference), "--config", str(config), "--clock-id", clock_id,
                                     "--tick", str(tick)], input=query, capture_output=True)
        return outcome(result)

    def linux_resolve(self, receipts, query):
        with tempfile.TemporaryDirectory() as scratch:
            config = self.host_tree(scratch, receipts)
            link = pathlib.Path(scratch) / "pulse-support-resolver"
            link.symlink_to(self.linux)
            result = subprocess.run([str(link)], input=query, capture_output=True,
                                    env={"PULSE_FRAME_PRESSURE_SUPPORT_CONFIG": str(config)})
        return outcome(result)

    def linux_role(self, role):
        with tempfile.TemporaryDirectory() as scratch:
            config = self.host_tree(scratch, {})
            link = pathlib.Path(scratch) / f"pulse-frame-pressure-{role}"
            link.symlink_to(self.linux)
            result = subprocess.run([str(link), "--config", str(config), "--acquisition-id", "absd-observe:linux"],
                                    capture_output=True)
            left = sorted(p.name for p in pathlib.Path(scratch, "outgoing").iterdir()) + \
                sorted(p.name for p in pathlib.Path(scratch, "receipts").iterdir())
        return outcome(result), left


def outcome(result):
    if result.returncode == 0:
        return (0, "answer", result.stdout.decode())
    return (result.returncode, "refusal", result.stderr.decode().split("\n", 1)[0])


def fields(answer):
    value = json.loads(answer)
    require(set(value) <= set(SUPPORT_FIELDS), f"unexpected support fields {sorted(value)}")
    require(jcs(value) == answer.encode(), "support answer is not exact JCS")
    return value


def verify_receipt(m, name, receipt_bytes, envelope_bytes, acquisition_id):
    """Independent check of one native evidence frame and its receipt."""
    receipt = json.loads(receipt_bytes)
    require(jcs(receipt) == receipt_bytes, f"{name}: receipt is not exact JCS")
    envelope = json.loads(envelope_bytes)
    require(jcs(envelope) == envelope_bytes, f"{name}: envelope is not exact JCS")
    require(receipt["schema"] == "pulse.absd_host_frame_pressure_support_receipt.v1", f"{name}: receipt schema")
    require(receipt["receipt_id"] == object_id(receipt, "receipt_id"), f"{name}: receipt id")
    require(receipt["evidence"] == envelope, f"{name}: receipt does not carry the producer's exact envelope")
    require(envelope["schema"] == "pulse.absd_host_frame_pressure_support_envelope.v1", f"{name}: envelope schema")
    evidence = envelope["evidence"]
    config = m.family.config()
    require(evidence["schema"] == "pulse.absd_host_frame_pressure_support_evidence.v1"
            and evidence["support_family"] == FAMILY and evidence["source_basis"] == SOURCE_BASIS
            and evidence["acquisition_id"] == acquisition_id
            and evidence["headroom_threshold_per_mille"] == THRESHOLD_PER_MILLE
            and all(evidence[k] == config[k] for k in ("producer_id", "producer_key_id", "subject_id",
                                                      "vantage_id", "question", "profile",
                                                      "profile_semantic_id", "threshold_policy")),
            f"{name}: evidence identities {evidence}")
    require(evidence["evidence_id"] == object_id(evidence, "evidence_id"), f"{name}: evidence id")
    try:
        m.family.public.verify(bytes.fromhex(envelope["signature_hex"]), DOMAIN + jcs(evidence))
    except Exception as error:  # noqa: BLE001
        fail(f"{name}: ed25519 signature does not verify on the host: {error}")
    state = derive(evidence)
    require(state is not None and state == evidence["state"], f"{name}: state {evidence['state']} != {state}")
    observed, received = evidence["observed_at"], receipt["received_at"]
    require(ABSD_CLOCK.match(observed["clock_id"]) and observed["clock_id"] == received["clock_id"],
            f"{name}: custody clocks {observed} {received}")
    require(observed["tick_ms"] <= received["tick_ms"], f"{name}: received before observed")
    require(receipt["expiry_tick_ms"] == received["tick_ms"] + VALIDITY_MS, f"{name}: expiry")
    return receipt, evidence


def cycle_input(acquisition_id, ballast=0, hold=0):
    return jcs({"config": CONFIG_PATH, "acquisition_id": acquisition_id, "ballast_frames": ballast,
                "hold_ms": hold})


def observe(m, name, expected_state="explicitly_absent", hold=0, ballast=0, memory=None, reader=None,
            reader_query=None):
    """Import a fresh deployment, then one boot: the cycle as worker, the
    resolver as reader. Returns the image, the verified receipt and
    evidence, the receipt bytes, and the reader's result."""
    image = m.import_files(name, m.family.files(expected_state))
    acquisition = f"absd-observe:{name}"
    query = reader_query or m.family.query()
    status, text, reader_status, test_config, body = m.boot(
        f"{name}.cycle", image, m.cycle, cycle_input(acquisition, ballast, hold), reader or m.resolver, query,
        memory=memory)
    require(status == 0, f"{name}: cycle status {status}\n{text}")
    require("PULSE FRAME PRESSURE CYCLE MOUNT OK" in text and f"PULSE FRAME PRESSURE CYCLE OK held_ms={hold}" in text,
            f"{name}: cycle markers\n{text}")
    produced = re.search(r"PULSE FRAME PRESSURE PRODUCED evidence_id=(sha256:[0-9a-f]{64}) ballast_frames=(\d+)",
                         text)
    received = re.search(r"PULSE FRAME PRESSURE RECEIVED receipt_id=(sha256:[0-9a-f]{64})", text)
    require(produced and received and int(produced.group(2)) == ballast, f"{name}: cycle ids\n{text}")
    file = occurrence(acquisition)
    require(m.listing(image, OUTGOING) == [file] and m.listing(image, RECEIPTS) == [file],
            f"{name}: device holds {m.listing(image, OUTGOING)} {m.listing(image, RECEIPTS)}")
    receipt_bytes = m.read(image, f"{RECEIPTS}/{file}")
    receipt, evidence = verify_receipt(m, name, receipt_bytes, m.read(image, f"{OUTGOING}/{file}"), acquisition)
    require(evidence["evidence_id"] == produced.group(1) and receipt["receipt_id"] == received.group(1),
            f"{name}: printed ids differ from the device")
    return image, receipt, evidence, {file: receipt_bytes}, (reader_status, test_config, body), query


def check_answer(m, name, answer, query, receipts, standing, receipt, evidence, expected_state="explicitly_absent"):
    native = fields(answer)
    require(native["standing"] == standing, f"{name}: standing {native['standing']} != {standing}\n{answer}")
    clock, tick = native["evaluated_at"]["clock_id"], native["evaluated_at"]["tick"]
    replay = m.reference_resolve(receipts, query, clock, tick, expected_state)
    require(replay == (0, "answer", answer), f"{name}: reference at the native instant differs\n{replay}\n{answer}")
    if receipt is not None and standing in ("current", "expired", "contradictory"):
        require(clock == receipt["received_at"]["clock_id"], f"{name}: evaluated on another clock")
        require(tick >= receipt["received_at"]["tick_ms"], f"{name}: evaluated before receipt")
    if standing == "current":
        require(tick < receipt["expiry_tick_ms"] and native["expiry"] == {"clock_id": clock,
                                                                         "tick": receipt["expiry_tick_ms"]}
                and native["evidence_refs"] == [evidence["evidence_id"]], f"{name}: current shape {native}")
    if standing == "expired":
        require(tick >= receipt["expiry_tick_ms"] and native["expiry"]["tick"] == receipt["expiry_tick_ms"]
                and native["evidence_refs"] == [evidence["evidence_id"]], f"{name}: expired shape {native}")
    if standing == "contradictory":
        require("expiry" not in native and native["contradiction_refs"] == [evidence["evidence_id"]],
                f"{name}: contradictory shape {native}")
    if standing == "unknown":
        require(ABSD_CLOCK.match(clock) and "expiry" not in native and "evidence_refs" not in native,
                f"{name}: unknown shape {native}")
    return native


def edges(m, name, receipts, receipt, query, expected_state="explicitly_absent"):
    """The same library at the edges of the receipt's own clock."""
    clock, expiry = receipt["received_at"]["clock_id"], receipt["expiry_tick_ms"]
    got = {}
    for label, tick in (("received", receipt["received_at"]["tick_ms"]), ("expiry-1", expiry - 1),
                        ("expiry", expiry)):
        status, _, text = m.reference_resolve(receipts, query, clock, tick, expected_state)
        require(status == 0, f"{name}: reference refused at {label}: {text}")
        got[label] = json.loads(text)["standing"]
    return got


def scenario_current(m, results):
    image, receipt, evidence, receipts, reader, query = observe(m, "current")
    status, test_config, body = reader
    require(status == 0 and test_config == "true", f"current: reader {reader}")
    check_answer(m, "current", body, query, receipts, "current", receipt, evidence)
    edge = edges(m, "current", receipts, receipt, query)
    require(edge == {"received": "current", "expiry-1": "current", "expiry": "expired"}, f"current: edges {edge}")
    linux = m.linux_resolve(receipts, query)
    require(linux[0] == 0 and json.loads(linux[2])["standing"] == "unknown", f"current: Linux resolver {linux}")
    tracked = evidence["free_frames"] + evidence["allocated_frames"]
    results["current"] = {"clock_id": receipt["received_at"]["clock_id"], "evidence": {
        k: evidence[k] for k in ("free_frames", "allocated_frames", "allocation_limit", "frame_bytes", "state",
                                 "observed_at")}, "received_at": receipt["received_at"],
        "expiry_tick_ms": receipt["expiry_tick_ms"], "answer": json.loads(body), "edges": edge,
        "linux_resolver": "unknown"}
    print(f"ABSD NATIVE EVIDENCE OK state={evidence['state']} free={evidence['free_frames']} "
          f"allocated={evidence['allocated_frames']} tracked={tracked} limit=none "
          f"signature=ed25519-verified-on-host derivation=recomputed")
    print(f"ABSD SUPPORT CURRENT OK same_boot=true observed={evidence['observed_at']['tick_ms']} "
          f"received={receipt['received_at']['tick_ms']} evaluated={json.loads(body)['evaluated_at']['tick']} "
          f"expiry={receipt['expiry_tick_ms']} reference=byte-identical edges=current,current,expired")
    print("ABSD SUPPORT ON LINUX UNKNOWN OK linux_resolver=unknown")
    return image, receipt, evidence, receipts, tracked


def scenario_other_boot(m, results, image, receipt, evidence, receipts):
    before = sha256(image.read_bytes())
    second = m.family.query(nonce="support-query:absd-observe-2")
    status, worker, reader_status, test_config, body = m.boot(
        "other-boot", image, m.resolver, m.family.query(), m.deployment, second)
    require(sha256(image.read_bytes()) == before, "other-boot: a resolver boot changed the device")
    require(status == 0, f"other-boot: worker {status} {worker}")
    native = check_answer(m, "other-boot.worker", worker, m.family.query(), receipts, "unknown", receipt, evidence)
    require(native["evaluated_at"]["clock_id"] != receipt["received_at"]["clock_id"],
            "other-boot: the second boot has the first boot's clock")
    require(reader_status == 2 and test_config == "false"
            and body.split("\n", 1)[0] == "PULSE_FRAME_PRESSURE_SUPPORT_CONFIG is required",
            f"other-boot: deployment reader {reader_status} {body!r}")
    results["other_boot"] = {"clock_id": native["evaluated_at"]["clock_id"], "standing": "unknown",
                             "deployment_without_environment": "refused"}
    print("ABSD SUPPORT OTHER BOOT UNKNOWN OK receipts_clock!=boot_clock image=unchanged")
    print("ABSD DEPLOYMENT RESOLVER REFUSED OK reason=PULSE_FRAME_PRESSURE_SUPPORT_CONFIG-is-required")


def scenario_expired(m, results):
    hold = VALIDITY_MS + 1_000
    image, receipt, evidence, receipts, reader, query = observe(m, "expired", hold=hold)
    status, _, body = reader
    require(status == 0, f"expired: reader {reader}")
    native = check_answer(m, "expired", body, query, receipts, "expired", receipt, evidence)
    results["expired"] = {"received_at": receipt["received_at"], "expiry_tick_ms": receipt["expiry_tick_ms"],
                          "evaluated_at": native["evaluated_at"]}
    print(f"ABSD SUPPORT EXPIRED OK same_boot=true received={receipt['received_at']['tick_ms']} "
          f"expiry={receipt['expiry_tick_ms']} evaluated={native['evaluated_at']['tick']}")


def scenario_contradictory(m, results):
    image, receipt, evidence, receipts, reader, query = observe(m, "contradictory", expected_state="present")
    status, _, body = reader
    require(status == 0 and evidence["state"] == "explicitly_absent", f"contradictory: {reader} {evidence}")
    check_answer(m, "contradictory", body, query, receipts, "contradictory", receipt, evidence, "present")
    results["contradictory"] = {"evidence_state": evidence["state"], "expected_state": "present"}
    print("ABSD SUPPORT CONTRADICTORY OK evidence=explicitly_absent expected=present")


def scenario_present(m, results, memory, ballast):
    image, receipt, evidence, receipts, reader, query = observe(m, "present", expected_state="present",
                                                                ballast=ballast, memory=memory)
    status, _, body = reader
    require(status == 0 and evidence["state"] == "present", f"present: {reader} {evidence}")
    check_answer(m, "present", body, query, receipts, "current", receipt, evidence, "present")
    free, allocated = evidence["free_frames"], evidence["allocated_frames"]
    results["present"] = {"memory": memory, "ballast_frames": ballast, "free_frames": free,
                          "allocated_frames": allocated}
    print(f"ABSD PRESSURE PRESENT CURRENT OK memory={memory} ballast_frames={ballast} free={free} "
          f"allocated={allocated} tracked={free + allocated}")


def scenario_unavailable(m, results):
    """A kernel without the facility (the canonical pin bc97503: before
    frame_stats, syscall 35, and before abi_version, syscall 42). Every
    program's runtime asks abi_version before `main` and refuses a kernel
    that is not generation KERNEL_ABI (docs/RELEASE.md section 2), so on
    this kernel the producer ends with status 103 before init can write
    its input, so the boot stops and the resolver never starts: no evidence is made and no answer is invented.
    Before the release gate the producer ran and met frame_stats' -38
    instead; the invariant (no evidence, no fabricated standing) is the
    same, reached one step earlier. The device is imported by the current
    kernel, as for every other scenario."""
    name = "unavailable"
    if m.old_kernel is None:
        # No earlier kernel was given (a kernel source without history
        # cannot make one): the case is not run, and says so.
        results[name] = {"skipped": "no kernel without frame_stats was given"}
        print("ABSD SOURCE UNAVAILABLE SKIPPED reason=no-old-kernel (the kernel source is a snapshot; "
              "this case needs a kernel before frame_stats)")
        return
    image = m.import_files(name, m.family.files())
    before = m.tree(image)
    iso = m.iso(m.old_kernel, 0, m.cycle, cycle_input("absd-observe:unavailable"), m.resolver, m.family.query())
    status, serial, text = m.raw_boot(f"{name}.cycle", m.old_kernel, iso, image)
    # The producer refuses before init has written its input, so init
    # stops there and the reader is never started; the kernel's own lines
    # are the witness (the refusal's stderr line is not yet captured).
    spawned = re.search(r"^SPAWN OK pid=(\d+) parent=1 program=external-workload$", serial, re.M)
    require(spawned and re.search(rf"^USER EXIT pid={spawned.group(1)} status=103$", serial, re.M),
            f"{name}: the producer did not end with the ABI refusal (103)\n{serial[-2000:]}")
    require("DURABLE READER" not in serial and re.search(r"^DURABLE status=\S+ .* block_writes=0 ", serial, re.M),
            f"{name}: the reader ran or the device was written\n{serial[-2000:]}")
    require(m.listing(image, OUTGOING) == [] and m.listing(image, RECEIPTS) == [],
            f"{name}: evidence was left on the device")
    require(m.tree(image).keys() == before.keys(), f"{name}: the device changed")
    results[name] = {"abi_refused": True, "producer_status": 103, "reader": "not started", "block_writes": 0}
    print("ABSD SOURCE UNAVAILABLE REFUSED OK producer=103 reader=not-started block_writes=0 evidence=none")


def reseal(receipt, mutate):
    value = json.loads(receipt)
    mutate(value)
    evidence = value["evidence"]["evidence"]
    evidence["evidence_id"] = object_id(evidence, "evidence_id")
    value["receipt_id"] = object_id(value, "receipt_id")
    return jcs(value)


def scenario_hostile(m, results, receipts):
    (name, data), = receipts.items()

    def signature(value):
        signature_hex = value["evidence"]["signature_hex"]
        value["evidence"]["signature_hex"] = ("0" if signature_hex[0] != "0" else "1") + signature_hex[1:]

    def state(value):
        evidence = value["evidence"]["evidence"]
        evidence["state"] = "present" if evidence["state"] == "explicitly_absent" else "explicitly_absent"

    def validity(value):
        value["expiry_tick_ms"] = value["received_at"]["tick_ms"] + 300_000

    cases = [("signature", signature, "producer signature verification failed"),
             ("flipped-state", state, "derived frame-pressure state does not match the retained raw basis"),
             ("widened-validity", validity, "support receipt custody or receiver-clock binding is invalid")]
    wrong_subject = m.family.query(subject_id="host:other")
    for label, mutate, expected in cases:
        hostile = {name: reseal(data, mutate)}
        image = m.import_files(f"hostile-{label}", m.family.files(receipts=hostile))
        before = sha256(image.read_bytes())
        status, worker, reader_status, _, body = m.boot(
            f"hostile-{label}", image, m.resolver, wrong_subject, m.resolver, m.family.query())
        require(sha256(image.read_bytes()) == before, f"hostile-{label}: device changed")
        first = worker.split("\n", 1)[0]
        require(status == 2 and first == "query does not match the one configured diagnostic basis",
                f"hostile-{label}: wrong-subject worker {status} {worker!r}")
        line = body.split("\n", 1)[0]
        require(reader_status == 2 and line == expected, f"hostile-{label}: {reader_status} {body!r}")
        reference = m.reference_resolve(hostile, m.family.query(), "pulse-absd-boot:sha256:" + "0" * 64, 1)
        require(reference == (2, "refusal", expected), f"hostile-{label}: reference {reference}")
        print(f"ABSD HOSTILE RECEIPT REFUSED OK case={label} exit=2 reference=same-line")
    results["hostile"] = [c[0] for c in cases] + ["wrong-subject"]


def scenario_torn(m, results):
    """Partial files a crash can leave. A torn producer envelope for the
    cycle's acquisition: the producer refuses instead of reading around it,
    no receipt is made, and the resolver answers unknown (never absent). A
    torn receipt beside a fresh good one: the resolver refuses outright
    rather than answering from the rest of the store."""
    acquisition = "absd-observe:torn"
    file = occurrence(acquisition)
    envelope = [f for f in m.family.files() if f[0] != f"{OUTGOING}/"] + [(f"{OUTGOING}/{file}", b'{"evidence":{"')]
    image = m.import_files("torn-envelope", envelope)
    status, text, reader_status, _, body = m.boot("torn-envelope", image, m.cycle, cycle_input(acquisition),
                                                  m.resolver, m.family.query())
    require(status == 2 and "EOF while parsing" in text and "PULSE FRAME PRESSURE PRODUCED" not in text,
            f"torn-envelope: cycle {status}\n{text}")
    require(m.listing(image, RECEIPTS) == [], "torn-envelope: a receipt was made")
    require(reader_status == 0, f"torn-envelope: reader {reader_status} {body}")
    check_answer(m, "torn-envelope", body, m.family.query(), {}, "unknown", None, None)
    torn = occurrence("absd-observe:torn-earlier")
    receipt = [f for f in m.family.files() if f[0] != f"{RECEIPTS}/"] + [(f"{RECEIPTS}/{torn}", b'{"evid')]
    image = m.import_files("torn-receipt", receipt)
    status, text, reader_status, _, body = m.boot("torn-receipt", image, m.cycle, cycle_input(acquisition),
                                                  m.resolver, m.family.query())
    require(status == 0 and m.listing(image, RECEIPTS) == sorted([torn, file]), f"torn-receipt: cycle {status}")
    line = body.split("\n", 1)[0]
    require(reader_status == 2 and line.startswith("EOF while parsing"), f"torn-receipt: {reader_status} {body!r}")
    results["torn"] = {"envelope": "unknown", "receipt": "refused"}
    print("ABSD TORN ENVELOPE UNKNOWN OK cycle=refused receipt=none standing=unknown")
    print("ABSD TORN RECEIPT REFUSED OK resolver=exit-2 good_receipt_not_used=true")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--old-kernel")
    for name in ("root", "kernel", "importer", "cycle", "resolver", "deployment-resolver",
                 "reference", "linux", "work", "qemu", "results", "present-memory"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--present-ballast", type=int, required=True)
    args = parser.parse_args()
    m = Matrix(args)
    results = {"family": FAMILY, "question": m.family.documents["question"],
               "profile": m.family.documents["profile"], "threshold_policy": m.family.documents["threshold-policy"],
               "profile_semantic_id": m.family.semantic_id}
    for role in ("producer", "receiver"):
        (status, kind, line), left = m.linux_role(role)
        require(status == 2 and "observes an ABSD kernel and is unsupported on this host" in line and not left,
                f"Linux {role}: {status} {line} {left}")
    print("ABSD FAMILY LINUX ROLES REFUSED OK producer=refused receiver=refused evidence=none")
    image, receipt, evidence, receipts, tracked = scenario_current(m, results)
    scenario_other_boot(m, results, image, receipt, evidence, receipts)
    scenario_expired(m, results)
    scenario_contradictory(m, results)
    scenario_present(m, results, args.present_memory, args.present_ballast)
    scenario_unavailable(m, results)
    scenario_hostile(m, results, receipts)
    scenario_torn(m, results)
    results["boots"] = m.boots
    pathlib.Path(args.results).write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    print("ABSD OBSERVATION OK source=absd_kernel_frame_stats_v1 evidence=native-signed-verified")
    print(f"ABSD PULSE SUPPORT CURRENT OK family={FAMILY} current=same-boot expired=after-60s "
          f"unknown=other-boot,{'' if m.old_kernel is None else 'no-source,'}torn-envelope contradictory=explicit")
    print(f"OBSERVE MATRIX OK boots={m.boots}")


if __name__ == "__main__":
    main()
