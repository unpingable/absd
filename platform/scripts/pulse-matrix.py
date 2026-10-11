#!/usr/bin/env python3
"""Real Pulse `pulse-support-resolver` on ABSD against its Linux twin and an
independent host reference (fixtures/pulse).

Provenance: the real pinned Linux producer and receiver made the receipts on
this host's boot clock (scripts/make-pulse-fixture.sh). The configuration
and receipts travel into the guest as opaque bytes; the guest importer
writes them through the ABSD filesystem. In each later boot init runs the
resolver twice, as the durable worker and then as the read-only reader,
each with one query on stdin. Both mount through a read-only duplicate of
the block handle, and the image must be byte-identical afterwards.

The resolver evaluates on the ABSD boot clock
(`pulse-absd-boot:sha256:<sha256(kernel boot id)>`), so receipts stamped on
a Linux boot clock never match it: the honest answer is `unknown`.
`current`, `expired` and `contradictory` are not reachable natively with
foreign evidence; the host reference shows the same library code computes
them for receipts on their own clock, through the same injected-clock seam.
"""

import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import absd_fs  # noqa: E402
import absd_inputs  # noqa: E402
import pulse_fixture as pf  # noqa: E402

spec = importlib.util.spec_from_file_location("durable_matrix", here / "durable-matrix.py")
dm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dm)

IMAGE_BYTES = 16 * 1024 * 1024
DEVICE_SECTORS = IMAGE_BYTES // 512
CONFIG_PATH = "/pulse/support-config.json"
RECEIPTS = "/pulse/receipts"
MARKER = re.compile(r"PULSE ABSD READONLY AUTHORITY OK fs_seq=\d+ write=refused-by-kernel test_config=(true|false)\n")
ABSD_CLOCK = re.compile(r"^pulse-absd-boot:sha256:[0-9a-f]{64}$")
SUPPORT_FIELDS = ["schema", "support_id", "authority_id", "query_id", "observation_cycle_id", "request_nonce",
                  "observation_id", "diagnostic_inputs_id", "subject_id", "scope_id", "artifact_ids",
                  "evaluated_at", "expiry", "standing", "evidence_refs", "contradiction_refs"]


def fail(message):
    print(f"PULSE MATRIX FAILED: {message}", file=sys.stderr)
    sys.exit(1)


def require(condition, message):
    if not condition:
        fail(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def stream(files):
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
        self.deployment = pathlib.Path(args.deployment_resolver).resolve()
        self.linux = pathlib.Path(args.linux).resolve()
        self.reference = pathlib.Path(args.reference).resolve()
        self.fixture = pathlib.Path(args.fixture).resolve()
        self.work = pathlib.Path(args.work).resolve()
        self.qemu = args.qemu
        self.work.mkdir(parents=True, exist_ok=True)
        self.boots = 0
        require(not absd_inputs.is_kernel_source(self.kernel), "refusing the canonical kernel checkout")
        self.manifest = json.loads((self.fixture / "manifest.json").read_bytes())
        self.config = (self.fixture / "config.json").read_bytes()
        self.receipts = {p.name: p.read_bytes() for p in sorted((self.fixture / "receipts").iterdir())}
        self.query = (self.fixture / "query.json").read_bytes()
        require(sha256(self.config) == self.manifest["config_sha256"], "fixture config drifted")
        require(sha256(self.query) == self.manifest["query_sha256"], "fixture query drifted")
        for name, data in self.receipts.items():
            require(sha256(data) == self.manifest["receipts"][name]["sha256"], f"fixture receipt {name} drifted")
        self.linux_clock = self.manifest["host"]["linux_clock_id"]

    # --- ABSD -----------------------------------------------------------
    def iso(self, input_bytes, reader_input, elf):
        paths = []
        for kind, data in (("input", input_bytes), ("request", reader_input)):
            path = self.work / f"{kind}-{sha256(data)}.bin"
            path.write_bytes(data)
            paths.append(path)
        subprocess.run(["make", "--no-print-directory", "-C", str(self.kernel), "durable-iso", "DURABLE_STEP=0",
                        f"EXTERNAL_USER_ELF={elf}", f"EXTERNAL_INPUT={paths[0]}",
                        f"EXTERNAL_READER_ELF={elf}", f"EXTERNAL_READER_INPUT={paths[1]}"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        return self.kernel / "build" / "durable" / "absd-durable-0.iso"

    def raw_boot(self, name, iso, image):
        self.boots += 1
        log = self.work / f"{name}.{self.boots:03d}.serial.log"
        result = subprocess.run([str(self.kernel / "scripts" / "durable-boot.sh"), str(iso), str(image), str(log),
                                 "300", *self.qemu.split()], check=True, capture_output=True, text=True)
        serial = log.read_bytes()
        require(b"PANIC" not in serial and b"KERNEL FAULT" not in serial, f"{name}: kernel fault")
        return int(result.stdout.strip()), serial, dm.Harness.captured(serial)

    def import_files(self, name, files):
        image = self.work / f"{name}.img"
        with open(image, "wb") as handle:
            handle.truncate(IMAGE_BYTES)
        subprocess.run(["make", "--no-print-directory", "-C", str(self.kernel), "durable-iso", "DURABLE_STEP=1",
                        f"EXTERNAL_USER_ELF={self.importer}",
                        f"EXTERNAL_INPUT={self.write_input(stream(files))}",
                        "EXTERNAL_READER_ELF=", "EXTERNAL_READER_INPUT="],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        status, serial, captured = self.raw_boot(f"{name}.import", self.kernel / "build" / "durable" /
                                                 "absd-durable-1.iso", image)
        require(status == 3 and f"FIXTURE IMPORT OK files={len(files)}" in captured,
                f"{name}: import status {status}\n{captured}")
        region = absd_fs.fs_region(image, DEVICE_SECTORS)
        selected = absd_fs.select(region)
        tree = absd_fs.tree(region, selected)
        for path, data in files:
            if path.endswith("/"):
                require(path[:-1] in tree, f"{name}: host reader misses directory {path}")
                require(not [p for p in tree if p.startswith(path)], f"{name}: {path} is not empty")
            else:
                require(path in tree and absd_fs.content(region, selected, tree[path]) == data,
                        f"{name}: host reader sees different bytes at {path}")
        return image

    def write_input(self, data):
        path = self.work / f"input-{sha256(data)}.bin"
        path.write_bytes(data)
        return path

    def resolve(self, name, image, worker_query, reader_query, elf=None):
        """One boot, two resolver runs: returns [(status, kind, text)] for
        worker then reader, where kind is 'answer' (stdout JCS) or 'refusal'
        (first stderr line)."""
        elf = elf or self.resolver
        before = sha256(pathlib.Path(image).read_bytes())
        status, serial, captured = self.raw_boot(f"{name}.resolve", self.iso(worker_query, reader_query, elf), image)
        after = sha256(pathlib.Path(image).read_bytes())
        require(before == after, f"{name}: a resolver boot changed the device ({before} -> {after})")
        text = serial.decode(errors="replace")
        statuses = [int(line.rsplit("status=", 1)[1]) for line in text.splitlines()
                    if "DURABLE WORKER OUTCOME" in line or "DURABLE READER OUTCOME" in line]
        require(len(statuses) == 2, f"{name}: expected two resolver outcomes\n{text[-2000:]}")
        markers = MARKER.findall(captured)
        segments = MARKER.split(captured)
        require(len(markers) == 2 and segments[0] == "", f"{name}: read-only authority markers\n{captured}")
        test_config = "true" if elf == self.resolver else "false"
        require(all(m == test_config for m in markers), f"{name}: test_config marker {markers}")
        runs = []
        for status_code, body in zip(statuses, segments[2::2]):
            if status_code == 0:
                require(body.startswith("{") and "\n" not in body, f"{name}: answer shape {body!r}")
                runs.append((0, "answer", body))
            else:
                runs.append((status_code, "refusal", body.split("\n", 1)[0]))
        return runs, before

    # --- Linux twin and host reference ----------------------------------
    def host_config(self, scratch, receipts, config=None):
        """The fixture configuration with its paths moved under a scratch
        root: the only difference between the host and ABSD deployments."""
        value = json.loads(config or self.config)
        root = pathlib.Path(scratch)
        for key in ("outgoing_directory", "receipt_directory", "producer_private_key_path"):
            value[key] = str(root) + value[key][len("/pulse"):]
        if receipts is not None:
            directory = pathlib.Path(value["receipt_directory"])
            directory.mkdir(parents=True, exist_ok=True)
            for filename, data in receipts.items():
                (directory / filename).write_bytes(data)
        path = root / "config.json"
        path.write_bytes(pf.jcs(value))
        return path

    def linux_resolve(self, receipts, query, env=True, config=None):
        with tempfile.TemporaryDirectory() as scratch:
            config_path = self.host_config(scratch, receipts, config)
            link = pathlib.Path(scratch) / "pulse-support-resolver"
            link.symlink_to(self.linux)
            result = subprocess.run([str(link)], input=query, capture_output=True,
                                    env={"PULSE_LOAD_SUPPORT_CONFIG": str(config_path)} if env else {})
        return self.outcome(result)

    def reference_resolve(self, receipts, query, clock_id, tick, config=None):
        with tempfile.TemporaryDirectory() as scratch:
            config_path = self.host_config(scratch, receipts, config)
            result = subprocess.run([str(self.reference), "--config", str(config_path), "--clock-id", clock_id,
                                     "--tick", str(tick)], input=query, capture_output=True)
        return self.outcome(result)

    @staticmethod
    def outcome(result):
        if result.returncode == 0:
            return (0, "answer", result.stdout.decode())
        return (result.returncode, "refusal", result.stderr.decode().split("\n", 1)[0])


def fields(answer):
    value = json.loads(answer)
    require(set(value) <= set(SUPPORT_FIELDS), f"unexpected support fields {sorted(value)}")
    return value


def compare_except(native, reference, skip, label):
    """Field by field; `skip` fields are reported, never silently equal."""
    for key in SUPPORT_FIELDS:
        if key in skip:
            continue
        require(native.get(key) == reference.get(key),
                f"{label}: field {key} differs: native {native.get(key)!r} reference {reference.get(key)!r}")


def check_unknown(m, label, answer, query, receipts, expect_ticks=None):
    """A native answer: `unknown` on the ABSD boot clock, byte-identical to
    the host reference at the same instant, and field-identical (but for
    the clock and the support id bound to it) to the reference on another
    ABSD-shaped clock."""
    native = fields(answer)
    clock = native["evaluated_at"]["clock_id"]
    require(native["standing"] == "unknown" and "expiry" not in native and "evidence_refs" not in native
            and "contradiction_refs" not in native, f"{label}: not unknown: {answer}")
    require(ABSD_CLOCK.match(clock) and clock != m.linux_clock, f"{label}: not the ABSD boot clock: {clock}")
    replay = m.reference_resolve(receipts, query, clock, native["evaluated_at"]["tick"])
    require(replay == (0, "answer", answer), f"{label}: reference at the native instant differs\n{replay}\n{answer}")
    other = "pulse-absd-boot:sha256:" + sha256(bytes(16))
    status, kind, text = m.reference_resolve(receipts, query, other, 1)
    require(status == 0, f"{label}: reference refused: {text}")
    reference = fields(text)
    compare_except(native, reference, {"support_id", "evaluated_at"}, label)
    require(native["support_id"] != reference["support_id"], f"{label}: support ids should differ with the clock")
    return clock, native["evaluated_at"]["tick"]


def scenario_retained(m, results):
    files = [(CONFIG_PATH, m.config)] + [(f"{RECEIPTS}/{n}", d) for n, d in m.receipts.items()]
    image = m.import_files("retained", files)
    second = pf.jcs(pf.query(nonce="support-query:absd-lane-c-2", cycle="cycle:absd-lane-c-2"))
    clocks, hashes = [], set()
    for boot in (1, 2):
        runs, image_hash = m.resolve(f"retained-{boot}", image, m.query, second)
        hashes.add(image_hash)
        require([r[0] for r in runs] == [0, 0], f"retained-{boot}: {runs}")
        worker = check_unknown(m, f"retained-{boot}.worker", runs[0][2], m.query, m.receipts)
        reader = check_unknown(m, f"retained-{boot}.reader", runs[1][2], second, m.receipts)
        require(worker[0] == reader[0], f"retained-{boot}: one boot, two clocks {worker[0]} {reader[0]}")
        require(worker[1] <= reader[1], f"retained-{boot}: tick went backwards {worker[1]} > {reader[1]}")
        clocks.append((worker, reader))
    require(clocks[0][0][0] != clocks[1][0][0], "two boots share a clock id")
    require(len(hashes) == 1, "the image changed between resolver boots")
    results["retained"] = {"boots": [{"clock_id": w[0], "worker_tick_ms": w[1], "reader_tick_ms": r[1]}
                                     for w, r in clocks], "standing": "unknown", "image": hashes.pop()}
    print(f"PULSE RETAINED LINUX RECEIPTS UNKNOWN OK boots=2 runs=4 clocks={[c[0][0][-12:] for c in clocks]}")
    print("PULSE BOOT CLOCK OK same-boot=same-clock two-boots=two-clocks")
    return image


def scenario_empty(m, results):
    image = m.import_files("empty", [(CONFIG_PATH, m.config), (f"{RECEIPTS}/", b"")])
    runs, _ = m.resolve("empty", image, m.query, m.query)
    require([r[0] for r in runs] == [0, 0], f"empty: {runs}")
    for index, run in enumerate(runs):
        check_unknown(m, f"empty.{index}", run[2], m.query, {})
    linux = m.linux_resolve({}, m.query)
    require(linux[0] == 0 and json.loads(linux[2])["standing"] == "unknown", f"empty: Linux {linux}")
    compare_except(fields(runs[0][2]), fields(linux[2]), {"support_id", "evaluated_at"}, "empty vs Linux")
    results["empty"] = {"standing": "unknown", "linux": "unknown"}
    print("PULSE EMPTY RECEIPTS UNKNOWN OK native=unknown linux=unknown")


def queries_hostile():
    wrong_subject = pf.query(subject_id="host:other")
    stale_id = pf.query()
    stale_id["request_nonce"] = "support-query:changed-after-sealing"
    wrong_artifact = pf.query(artifact_ids=["sha256:" + "c" * 64])
    return [("malformed", b"{not json"), ("wrong-subject", pf.jcs(wrong_subject)),
            ("stale-query-id", pf.jcs(stale_id)), ("wrong-artifact", pf.jcs(wrong_artifact))]


def scenario_refusals(m, image, results):
    cases = queries_hostile()
    seen = []
    for index in range(0, len(cases), 2):
        (a, qa), (b, qb) = cases[index], cases[index + 1]
        runs, _ = m.resolve(f"refuse-{a}-{b}", image, qa, qb)
        for (name, query), native in zip(((a, qa), (b, qb)), runs):
            linux = m.linux_resolve(m.receipts, query)
            require(native[1] == "refusal" and native == linux,
                    f"{name}: ABSD {native} differs from Linux {linux}")
            seen.append((name, native[2]))
    tampered = []
    first = sorted(m.receipts)[0]
    receipt = json.loads(m.receipts[first])
    signature = receipt["evidence"]["signature_hex"]
    flipped = dict(receipt, evidence=dict(receipt["evidence"],
                                          signature_hex=("0" if signature[0] != "0" else "1") + signature[1:]))
    # The state flipped against its raw load basis, with every id resealed,
    # so the derived-state check (not an id check) is what refuses it.
    state = json.loads(m.receipts[first])
    evidence = state["evidence"]["evidence"]
    evidence["state"] = "present" if evidence["state"] == "explicitly_absent" else "explicitly_absent"
    evidence["evidence_id"] = pf.object_id(evidence, "evidence_id")
    state["receipt_id"] = pf.object_id(state, "receipt_id")
    tampered.append(("tampered-signature", pf.jcs(flipped)))
    tampered.append(("tampered-noncanonical", m.receipts[first] + b"\n"))
    tampered.append(("tampered-state", pf.jcs(state)))
    for name, data in tampered:
        receipts = dict(m.receipts, **{first: data})
        files = [(CONFIG_PATH, m.config)] + [(f"{RECEIPTS}/{n}", d) for n, d in receipts.items()]
        hostile = m.import_files(name, files)
        runs, _ = m.resolve(name, hostile, m.query, m.query)
        linux = m.linux_resolve(receipts, m.query)
        require(linux[1] == "refusal" and runs == [linux, linux], f"{name}: ABSD {runs} differs from Linux {linux}")
        seen.append((name, linux[2]))
    results["refusals"] = [{"case": name, "exit": 2, "first_stderr_line": line} for name, line in seen]
    print(f"PULSE REFUSALS MATCH LINUX OK cases={len(seen)}")
    for name, line in seen:
        print(f"  {name}: exit 2 {line!r}")


def scenario_deployment(m, image, results):
    """The deployment image reads its configuration path only from the
    environment; with no startup record ABSD gives it none, so it refuses
    exactly as Linux does with an empty environment."""
    runs, _ = m.resolve("deployment-no-env", image, m.query, m.query, elf=m.deployment)
    linux = m.linux_resolve(m.receipts, m.query, env=False)
    require(linux[1] == "refusal" and runs == [linux, linux], f"deployment: ABSD {runs} vs Linux {linux}")
    results["deployment_without_environment"] = linux[2]
    print(f"PULSE DEPLOYMENT BUILD NO ENVIRONMENT OK {linux[2]!r}")


def scenario_reference(m, results):
    """Host-only: the same library code, through the same injected-clock
    seam, on the receipts' own (Linux) boot clock. Not reachable natively."""
    latest = max(m.manifest["receipts"].values(), key=lambda r: (r["received_at"]["tick_ms"], r["receipt_id"]))
    linux_answer = (m.fixture / "linux-answer.json").read_bytes().decode()
    at = json.loads(linux_answer)["evaluated_at"]
    replay = m.reference_resolve(m.receipts, m.query, at["clock_id"], at["tick"])
    require(replay == (0, "answer", linux_answer), f"reference does not reproduce the Linux answer\n{replay}")
    received, expiry = latest["received_at"]["tick_ms"], latest["expiry_tick_ms"]
    present = json.loads(m.config)
    present["expected_diagnostic"]["expected_state"] = "present"
    cases = [("current", received + 1_000, None), ("current-edge", expiry - 1, None),
             ("expired-edge", expiry, None), ("expired", expiry + 60_000, None),
             ("contradictory", received + 1_000, pf.jcs(present))]
    table = {}
    for name, tick, config in cases:
        status, kind, text = m.reference_resolve(m.receipts, m.query, m.linux_clock, tick, config)
        require(status == 0, f"reference {name}: {text}")
        value = fields(text)
        standing = value["standing"]
        require(standing == name.split("-")[0], f"reference {name}: standing {standing}")
        if standing in ("current", "expired"):
            require(value["expiry"]["tick"] == expiry and value["evidence_refs"] == [latest["evidence_id"]],
                    f"reference {name}: {text}")
        else:
            require(value["contradiction_refs"] == [latest["evidence_id"]], f"reference {name}: {text}")
        table[name] = {"tick": tick, "standing": standing}
    results["host_reference_on_receipt_clock"] = table
    print(f"PULSE HOST REFERENCE OK linux-answer=reproduced {[(n, t['standing']) for n, t in table.items()]}")
    print("PULSE NATIVE LIMIT: current/expired/contradictory need receipts on the ABSD boot clock; "
          "no ABSD producer exists, so they are not reachable natively")


def main():
    parser = argparse.ArgumentParser()
    for name in ("--kernel", "--importer", "--resolver", "--deployment-resolver", "--linux", "--reference",
                 "--fixture", "--work", "--qemu", "--results"):
        parser.add_argument(name, required=True)
    args = parser.parse_args()
    m = Matrix(args)
    results = {"fixture_id": m.manifest["fixture_id"]}
    scenario_reference(m, results)
    image = scenario_retained(m, results)
    scenario_empty(m, results)
    scenario_refusals(m, image, results)
    scenario_deployment(m, image, results)
    results["boots"] = m.boots
    pathlib.Path(args.results).write_text(json.dumps(results, indent=1, sort_keys=True) + "\n")
    print(f"PULSE MATRIX OK boots={m.boots}")
    print("PULSE SUPPORT RESOLVER NATIVE OK")


if __name__ == "__main__":
    main()
