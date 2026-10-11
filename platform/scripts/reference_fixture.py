#!/usr/bin/env python3
"""The Linux reference for the native Nightshift pipeline and the native AG
path (fixtures/nightshift-pipeline, fixtures/ag-native), produced by the
real pinned, unpatched Linux programs. No ABSD code is involved.

`make` (driven by scripts/make-reference-fixture.sh) takes the NQ fixture
(fixtures/nq: one real `nq.diagnostic_execution.v2` artifact and the store
that admitted it) and, under REFERENCE_ROOT:

- builds the sealed cycle request around the artifact (the request
  builder, fixtures/nightshift-pipeline/tools/request-builder);
- writes a Pulse deployment configuration pinned to that request and runs
  the real Pulse producer and receiver for two acquisitions (real
  /proc/loadavg, the real Linux boot clock);
- runs the real `nightshift cycle run` with the real `nq`, the real
  `pulse-support-resolver` and the real `ag-loopctl`: twice with no
  receipts (`empty-receipts`, the reference a native run must match, and a
  second run that checks the normalizer) and once with a fresh receipt
  (`i-fresh-ag`, which opens an AG occurrence);
- dumps each store and asks the real observation resolver the reference
  questions.

Every name a deployment chooses is a fixed synthetic one: the labels carry
`refhost`, the recorded host is `refhost`, the tree lives at REFERENCE_ROOT
and both keys are derived from published seeds (they are test keys, not
credentials). The request's instants are fixed offsets from the NQ
artifact's, so the cycle is evaluated at the same instant whenever this
runs; AG checks an observation's currentness against its own wall clock, so
CLOCK_REALTIME is pinned for the cycle's process tree, PINNED_AFTER_MS after
that instant, by the twin shim (tools/ag-linux-twin), as the AG matrix's
Linux twin does.
What still varies between two productions: the cycle id and request nonce
(uuid v4), the Linux boot clock and load figures in the Pulse receipts,
and everything derived from them.
"""

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import sqlite3
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REFERENCE_ROOT = "/tmp/absd-reference"
HOST_LABEL = "refhost"
# The pinned wall clock: 27 minutes 4 seconds after the request's
# evaluated_at, inside the deployment resolver's one-day TTL.
PINNED_AFTER_MS = 1_624_000
ISSUER_SEED_TEXT = "ABSD test fixture key, not a credential"
PRODUCER_SEED_TEXT = "ABSD test fixture Pulse producer key, not a credential"
RESOLVER_ID = "nightshift-observation-resolver/v1"
BINARIES = ["ag-loopctl", "nightshift", "nightshift-observation-resolver", "nq", "pulse-nq-load-support"]
PULSE_ROLES = ["pulse-load-pressure-producer", "pulse-load-pressure-receiver", "pulse-support-resolver"]
SOURCES = {
    "ag": {"commit": "21c8da079f2465a2466c54431cc315699fc57cbe", "tree": "3c44f564e2be9add17224954f6e5bb45ccdec84c",
           "build": "cargo +1.94.0 build --release --locked --offline -p ag-app --bin ag-loopctl"},
    "nightshift": {"commit": "e2675dd854dbfe633bf14456595d722e88bf92bc",
                   "tree": "bd7afe042251fc4f007413871589a01d26e0583f",
                   "build": "cargo build --release --locked --offline -p nightshiftd --bin nightshift "
                            "--bin nightshift-observation-resolver (rustc 1.98.0)"},
    "nq-ng": {"commit": "80574417f0188afd37992db7ac764a6f0f72ff62", "tree": "13c0b6b36ec26b941adc586088275df248360492",
              "build": "cargo build --locked --offline -p nq-app --bin nq (debug; rust-toolchain 1.94.0)"},
    "pulse": {"commit": "81c2354674990679f43be4f207349ff1b2429bc7", "tree": "b3f746c4e16b5303d0fd7bf98b327bfa14382951",
              "build": "cargo build --release --locked --offline -p pulse-nq-load-support (rustc 1.98.0)"},
}


def fail(message):
    sys.exit(f"REFERENCE FIXTURE FAILED: {message}")


def require(condition, message):
    if not condition:
        fail(message)


def jcs(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def test_key(seed_text):
    """The Ed25519 key whose seed is SHA-256 of a published string."""
    seed = hashlib.sha256(seed_text.encode()).digest()
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return seed, public


def write_private(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(descriptor, data)
    os.close(descriptor)


def linux_clock():
    boot_id = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    return "sha256:" + sha256(boot_id.encode())


def uptime():
    return float(pathlib.Path("/proc/uptime").read_text().split()[0])


def wall():
    result = subprocess.run(["date", "-u", "+%Y-%m-%dT%H:%M:%S.%3NZ"], capture_output=True, text=True, check=True)
    return result.stdout.strip()


class Production:
    def __init__(self, args):
        self.root = pathlib.Path(REFERENCE_ROOT)
        self.bin = self.root / "bin"
        self.fixtures = pathlib.Path(args.fixtures).resolve()
        self.linux_bin = pathlib.Path(args.linux_bin).resolve()
        self.builder = pathlib.Path(args.request_builder).resolve()
        self.shim = pathlib.Path(args.shim).resolve()

    # ------------------------------------------------------------ inputs

    def programs(self):
        self.bin.mkdir()
        self.binaries = {}
        for name in BINARIES:
            source = self.linux_bin / name
            require(source.is_file(), f"missing Linux program {source}")
            data = source.read_bytes()
            self.binaries[f"bin/{name}"] = {"bytes": len(data), "sha256": sha256(data)}
            (self.bin / name).symlink_to(source)
        for role in PULSE_ROLES:
            (self.bin / role).symlink_to("pulse-nq-load-support")

    def nq(self):
        source = self.fixtures / "nq"
        target = self.root / "nq"
        (target / "store").mkdir(parents=True)
        shutil.copy(source / "artifact.json", target / "artifact.json")
        shutil.copy(source / "store" / "nq.db", target / "store" / "nq.db")
        # Qualify must stay read-only: a 0444 store in a 0555 directory.
        os.chmod(target / "store" / "nq.db", 0o444)
        os.chmod(target / "store", 0o555)
        (target / "nq.toml").write_text(
            'schema = "nq.config.v1"\n'
            f'database_path = "{target}/store/nq.db"\n'
            f'admissions_dir = "{target}/nonexistent-admissions"\n')
        artifact = json.loads((target / "artifact.json").read_bytes())
        result = subprocess.run([str(self.bin / "nq"), "--config", str(target / "nq.toml"), "--json",
                                 "diagnostics", "qualify", artifact["artifact_id"]], capture_output=True)
        require(result.returncode == 0, f"nq qualify: {result.stderr.decode()[-2000:]}")
        require(result.stdout == (source / "reference" / "provenance.json").read_bytes(),
                "nq qualify differs from the NQ fixture's reference provenance")
        (target / "qualify-provenance.json").write_bytes(result.stdout)

    def request(self):
        target = self.root / "request"
        subprocess.run([str(self.builder), "--artifact", str(self.root / "nq" / "artifact.json"),
                        "--out-dir", str(target)], check=True, stdout=subprocess.DEVNULL)
        self.derived = json.loads((target / "request-derived.json").read_bytes())
        self.now_ms = self.derived["evaluated_at_unix_ms"] + PINNED_AFTER_MS

    # ------------------------------------------------------------- Pulse

    def pulse_config(self):
        pulse = self.root / "pulse"
        (pulse / "keys").mkdir(parents=True, mode=0o700)
        seed, public = test_key(PRODUCER_SEED_TEXT)
        write_private(pulse / "keys" / "producer-key.hex", seed.hex().encode())
        (pulse / "producer-public.hex").write_text(public.hex())
        d = self.derived

        def config(outgoing, receipts):
            return {
                "schema": "pulse.nq_host_load_pressure_support_config.v1",
                "authority_id": f"pulse-authority:laned-{HOST_LABEL}-load-pressure-v1",
                "support_family": "pulse.nq_host_load_pressure.v1",
                "producer_id": f"pulse-producer:laned-{HOST_LABEL}-v1",
                "producer_key_id": "pulse-key:sha256:" + sha256(public),
                "producer_public_key_hex": public.hex(),
                "producer_private_key_path": str(pulse / "keys" / "producer-key.hex"),
                "subject_id": d["subject_id"], "scope_id": d["scope_id"], "vantage_id": d["vantage_id"],
                "question": {"id": "nq.host.load_pressure", "version": "1",
                             "digest": "sha256:7de797da3d9d3a6ae8e21e5d77b95095453336cd38f606ffb3eb29ff6a32e2cf"},
                "profile": {"id": "nq.host", "version": "1",
                            "digest": "sha256:c8c10fed1cc5598d953b4defbc98e8c106fc59e035c249d43681698a5c7b4ff9"},
                "profile_semantic_id": "sha256:382b8dac14ef9353a3603757d60fc8fbc727e1bcaf088c9aab4bdf895d3f6ab1",
                "threshold_policy": {"id": "nq.host.load_pressure.threshold_policy", "version": "1",
                                     "digest": "sha256:52b815509d26878fad1f88c6352bcd17537452f704072e56664e18434fee855e"},
                "outgoing_directory": str(pulse / outgoing), "receipt_directory": str(pulse / receipts),
                "expected_diagnostic": {"diagnostic_inputs_id": d["diagnostic_inputs_id"],
                                        "artifact_ids": d["artifact_ids"], "expected_state": d["expected_state"]},
            }

        (pulse / "config.json").write_bytes(jcs(config("outgoing", "receipts")))
        (pulse / "config-empty.json").write_bytes(jcs(config("outgoing-empty", "receipts-empty")))
        for name in ("outgoing", "receipts", "outgoing-empty", "receipts-empty", "acquisitions"):
            (pulse / name).mkdir()

    def acquire(self, name):
        """One acquisition by the real producer, then the real receiver."""
        pulse = self.root / "pulse"
        acquisition = f"support:laned-{HOST_LABEL}-{name}"
        config = str(pulse / "config.json")
        clock = linux_clock()
        load = pathlib.Path("/proc/loadavg").read_text().split()[:3]
        moments = [(wall(), uptime())]
        identities = []
        for role in PULSE_ROLES[:2]:
            result = subprocess.run([str(self.bin / role), "--config", config, "--acquisition-id", acquisition],
                                    capture_output=True, text=True)
            require(result.returncode == 0, f"{role} {acquisition}: {result.stderr}")
            identities.append(result.stdout.strip())
            moments.append((wall(), uptime()))
        (pulse / "acquisitions" / f"{name}.json").write_bytes(jcs({
            "acquisition_id": acquisition, "host": HOST_LABEL, "boot_id_sha256": clock,
            "clock_id": f"pulse-linux-boottime:{clock}", "loadavg_before": " ".join(load), "nproc": os.cpu_count(),
            "producer": {"wall_before": moments[0][0], "uptime_before_s": moments[0][1], "evidence_id": identities[0]},
            "receiver": {"wall_before": moments[1][0], "uptime_before_s": moments[1][1], "receipt_id": identities[1],
                         "wall_after": moments[2][0], "uptime_after_s": moments[2][1]}}) + b"\n")
        return identities[1]

    # -------------------------------------------------------------- runs

    def enroll(self, run):
        """An AG deployment for one run: the catalog, an empty Docket trust
        file, a boundary command nothing before authorization invokes, the
        real observation resolver behind the deployment wrapper, and the
        test issuer key; sealed by the real `ag-loopctl`."""
        config = run / "ag" / "config"
        secrets = run / "ag" / "secrets"
        for directory in (run / "state", config, secrets):
            directory.mkdir(parents=True, mode=0o700)
        (run / "tmp").mkdir()
        store = run / "state" / "nightshift.sqlite"
        command = config / "boundary-command"
        command.write_text("#!/bin/sh\nexit 0\n")
        command.chmod(0o700)
        wrapper = config / "observation-resolver"
        wrapper.write_text(f'#!/bin/sh\nexec "{self.bin}/nightshift-observation-resolver" --store "{store}" '
                           f"--resolver-id {RESOLVER_ID} --default-ttl-ms 86400000\n")
        wrapper.chmod(0o700)
        d = self.derived
        (config / "catalog.json").write_bytes(jcs({
            "schema": "ag.governed-loop.exact-work-catalog/v1",
            "entries": {"example.exact-work/v1": {
                "work_schema": "example.exact-work/v1", "subject": d["ag_subject_digest"], "scope": d["scope_id"],
                "precondition": {"required": [], "forbidden": []}}}}))
        (config / "docket-trust.json").write_bytes(jcs({}))
        (config / "enrollment.json").write_bytes(jcs({
            "schema": "ag.governed-loop.runtime-profile-enrollment/v1",
            "profile_label": f"laned-{HOST_LABEL}-reference",
            "observation_resolver": str(wrapper), "observation_resolver_id": RESOLVER_ID,
            "standing_resolver": str(command), "standing_resolver_id": "fixture-standing/v1",
            "max_standing_ttl_ms": 60000, "exact_work_catalog": str(config / "catalog.json"),
            "controlling_review": None,
            "docket": {"schema": "ag.governed-loop.docket-root-enrollment/v1", "docket_program": str(command),
                       "state_directory": str(run / "ag" / "docket"),
                       "trust_config": str(config / "docket-trust.json"), "standing_resolver": str(command),
                       "executor_adapter": str(command), "issuer_principal": "fixture-ag",
                       "issuer_key_id": "fixture-key-1", "issuer_key": str(secrets / "issuer.pk8")},
            "human_verifier": None}))
        # AG signs with ring, which takes an Ed25519 key as PKCS#8 v2 (seed
        # and public key).
        seed, public = test_key(ISSUER_SEED_TEXT)
        write_private(secrets / "issuer.pk8", bytes.fromhex("3053020101300506032b657004220420") + seed
                      + bytes.fromhex("a123032100") + public)
        (secrets / "issuer.pub.der").write_bytes(bytes.fromhex("302a300506032b6570032100") + public)
        sealed = subprocess.run([str(self.bin / "ag-loopctl"), "seal-runtime-profile", "--enrollment",
                                 str(config / "enrollment.json"), "--output", str(config / "runtime-profile.json")],
                                capture_output=True)
        require(sealed.returncode == 0, f"seal: {sealed.stderr.decode()}")
        (run / "ag" / "seal-receipt.json").write_bytes(sealed.stdout)

    def pinned(self, extra=None):
        env = {"PATH": "/usr/bin:/bin", "LD_PRELOAD": str(self.shim), "AG_TWIN_NOW_MS": str(self.now_ms)}
        env.update(extra or {})
        return env

    def run(self, name, pulse_config):
        """One real `nightshift cycle run` on a fresh store."""
        run = self.root / "runs" / name
        self.enroll(run)
        clock = linux_clock()
        before = (wall(), uptime())
        result = subprocess.run(
            [str(self.bin / "nightshift"), "--store", str(run / "state" / "nightshift.sqlite"), "cycle", "run",
             "--request", str(self.root / "request" / "cycle-request.json"),
             "--present-evidence-resolver", str(self.bin / "pulse-support-resolver"),
             "--nq-program", str(self.bin / "nq"), "--nq-config", str(self.root / "nq" / "nq.toml"),
             "--nq-source-id", self.derived["nq_source_id"],
             "--ag-loopctl", str(self.bin / "ag-loopctl"), "--ag-database", str(run / "state" / "ag.sqlite"),
             "--ag-observation-resolver", str(run / "ag" / "config" / "observation-resolver"),
             "--ag-observation-resolver-id", RESOLVER_ID,
             "--ag-runtime-profile", str(run / "ag" / "config" / "runtime-profile.json")],
            env=self.pinned({"PULSE_LOAD_SUPPORT_CONFIG": str(pulse_config), "TMPDIR": str(run / "tmp")}),
            capture_output=True)
        after = (wall(), uptime())
        (run / "stdout.json").write_bytes(result.stdout)
        (run / "stderr.txt").write_bytes(result.stderr)
        (run / "run.json").write_bytes(jcs({
            "name": name, "pulse_config": str(pulse_config), "exit_status": result.returncode, "host": HOST_LABEL,
            "clock_id": f"pulse-linux-boottime:{clock}", "pinned_wall_unix_ms": self.now_ms,
            "produced_wall_start": before[0], "produced_wall_end": after[0],
            "uptime_start_s": before[1], "uptime_end_s": after[1]}) + b"\n")
        require(result.returncode == 0, f"{name}: nightshift exit {result.returncode}: {result.stderr.decode()[-2000:]}")
        if (run / "state" / "ag.sqlite").exists():
            status = subprocess.run([str(self.bin / "ag-loopctl"), "status", "--database",
                                     str(run / "state" / "ag.sqlite")], capture_output=True)
            require(status.returncode == 0, f"{name}: ag-loopctl status: {status.stderr.decode()}")
            (run / "ag-status.json").write_bytes(status.stdout)
        self.dump_and_resolve(run)
        return json.loads(result.stdout)

    def dump_and_resolve(self, run):
        """The store, every row; the observation record; and the real
        observation resolver's answers to AG-style requests."""
        dumped = dump_nightshift(run / "state")
        (run / "store-dump.json").write_text(json.dumps(dumped, indent=1, sort_keys=True))
        normalized = subprocess.run([sys.executable, str(self.fixtures / "nightshift-pipeline" / "tools" /
                                                         "normalize.py"), str(run / "store-dump.json")],
                                    check=True, capture_output=True, text=True).stdout
        (run / "store-normalized.json").write_text(normalized)
        d = self.derived
        found = []

        def walk(value):
            if isinstance(value, dict):
                if value.get("observation_id") == d["observation"] and "posture" in value:
                    found.append(value)
                    return
                for item in value.values():
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)

        walk(dumped["tables"])
        unique = {jcs(item): item for item in found}
        (run / "observation-record.json").write_text(json.dumps(list(unique.values()), indent=1, sort_keys=True))

        evaluated = d["evaluated_at_unix_ms"]
        base = {"schema": "ag.governed-loop.observation-request/v1",
                "key": {"campaign": d["campaign"], "occurrence": d["occurrence"]},
                "observation": d["observation"], "subject": d["ag_subject_digest"]}
        ttl = 600_000
        requests = {
            "current": ({**base, "now_unix_ms": evaluated + 300_000}, ttl),
            "current-edge": ({**base, "now_unix_ms": evaluated + ttl - 1}, ttl),
            "stale-edge": ({**base, "now_unix_ms": evaluated + ttl}, ttl),
            "absent": ({**base, "observation": "sha256:" + "e" * 64, "now_unix_ms": evaluated + 300_000}, ttl),
            "wrong-subject": ({**base, "subject": "sha256:" + "c" * 64, "now_unix_ms": evaluated + 300_000}, ttl),
            "deployment-wall-at-run-end": ({**base, "now_unix_ms": self.now_ms}, 86_400_000),
        }
        (run / "resolver").mkdir()
        answers = {}
        for name, (request, default_ttl) in requests.items():
            with tempfile.TemporaryDirectory() as scratch:
                for path in (run / "state").glob("nightshift.sqlite*"):
                    shutil.copy(path, scratch)
                result = subprocess.run(
                    [str(self.bin / "nightshift-observation-resolver"), "--store",
                     str(pathlib.Path(scratch) / "nightshift.sqlite"), "--resolver-id", RESOLVER_ID,
                     "--default-ttl-ms", str(default_ttl)], input=jcs(request), capture_output=True)
            (run / "resolver" / f"{name}.request.json").write_bytes(jcs(request))
            (run / "resolver" / f"{name}.answer.json").write_bytes(result.stdout)
            try:
                status = json.loads(result.stdout)["status"]
            except ValueError:
                status = None
            answers[name] = {"exit": result.returncode, "status": status, "default_ttl_ms": default_ttl,
                             "sha256": sha256(result.stdout), "stderr": result.stderr.decode()[-500:]}
        (run / "resolver" / "summary.json").write_text(json.dumps(answers, indent=1, sort_keys=True))
        return {name: answer["status"] for name, answer in answers.items()}

    # ------------------------------------------------------------ checks

    def ag_replay(self):
        """AG alone reproduces the reference: `init` and `record-proposal`
        on the documents Nightshift handed it, at the reference's paths and
        instant, leave the same store row for row and the same state. This
        is the check the AG matrix's Linux twin starts with."""
        run = self.root / "runs" / "i-fresh-ag"
        kept = self.root / "runs" / "i-fresh-ag.produced"
        reference = dump_ag(run / "state")
        status = (run / "ag-status.json").read_bytes()
        genesis, proposal = ag_documents(run / "state" / "nightshift.sqlite")
        run.rename(kept)
        try:
            shutil.copytree(kept / "ag", run / "ag")
            (run / "state").mkdir(mode=0o700)
            shutil.copy(kept / "state" / "nightshift.sqlite", run / "state" / "nightshift.sqlite")
            (run / "input").mkdir()
            (run / "input" / "genesis.json").write_bytes(genesis)
            (run / "input" / "proposal.json").write_bytes(proposal)
            database = str(run / "state" / "ag.sqlite")
            first = subprocess.run([str(self.bin / "ag-loopctl"), "init", "--database", database, "--genesis",
                                    str(run / "input" / "genesis.json"), "--runtime-profile",
                                    str(run / "ag" / "config" / "runtime-profile.json")],
                                   env=self.pinned(), capture_output=True)
            require(first.returncode == 0, f"AG replay init: {first.stderr.decode()[-2000:]}")
            second = subprocess.run([str(self.bin / "ag-loopctl"), "record-proposal", "--database", database,
                                     "--input", str(run / "input" / "proposal.json"), "--observation-resolver",
                                     str(run / "ag" / "config" / "observation-resolver"),
                                     "--expected-observation-resolver-id", RESOLVER_ID],
                                    env=self.pinned(), capture_output=True)
            require(second.returncode == 0, f"AG replay record-proposal: {second.stderr.decode()[-2000:]}")
            require(second.stdout == status, "AG replay state differs from the reference's `ag-loopctl status`")
            require(dump_ag(run / "state") == reference, "AG replay store differs from the reference store")
        finally:
            shutil.rmtree(run, ignore_errors=True)
            kept.rename(run)
        return json.loads(status)["state_digest"]

    # ----------------------------------------------------------- install

    def install(self, a1_receipt):
        pipeline = self.fixtures / "nightshift-pipeline"
        native = self.fixtures / "ag-native"
        root = self.root

        def put(source, target):
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

        for stale in (pipeline / "pulse", pipeline / "request", pipeline / "reference", native / "reference"):
            shutil.rmtree(stale, ignore_errors=True)
        for name in ("artifact.json", "nq.toml", "qualify-provenance.json", "store/nq.db"):
            put(root / "nq" / name, pipeline / "nq" / name)
        for name in ("cycle-request.json", "request-derived.json"):
            put(root / "request" / name, pipeline / "request" / name)
        for name in ("config.json", "producer-public.hex", "acquisitions/a1.json", "acquisitions/a2.json"):
            put(root / "pulse" / name, pipeline / "pulse" / name)
        # The native run filters every receipt out by its clock; the first
        # acquisition's receipt is carried so the directory is not empty.
        carried = [path for path in sorted((root / "pulse" / "receipts").iterdir())
                   if json.loads(path.read_bytes())["receipt_id"] == a1_receipt]
        require(len(carried) == 1, "the first acquisition's receipt")
        put(carried[0], pipeline / "pulse" / "receipts" / carried[0].name)
        empty = root / "runs" / "empty-receipts"
        for path in sorted(empty.rglob("*")):
            relative = path.relative_to(empty)
            if path.is_file() and relative.parts[0] not in ("ag", "state", "tmp"):
                put(path, pipeline / "reference" / "empty-receipts" / relative)

        fresh = root / "runs" / "i-fresh-ag"
        kept = ["ag-status.json", "observation-record.json", "run.json", "stderr.txt", "stdout.json",
                "resolver/current.answer.json", "resolver/current.request.json", "resolver/summary.json",
                "ag/seal-receipt.json", "state/ag.sqlite", "state/nightshift.sqlite"]
        kept += [str(path.relative_to(fresh)) for path in sorted((fresh / "ag").rglob("*"))
                 if path.is_file() and path.parent.name in ("config", "secrets")]
        files = {}
        for relative in sorted(set(kept)):
            put(fresh / relative, native / "reference" / "i-fresh-ag" / relative)
            data = (fresh / relative).read_bytes()
            files[f"reference/i-fresh-ag/{relative}"] = {"bytes": len(data), "sha256": sha256(data)}
        for relative in ("ag/config/boundary-command", "ag/config/observation-resolver"):
            os.chmod(native / "reference" / "i-fresh-ag" / relative, 0o755)
        manifest = {
            "schema": "absd.ag-native-fixture/v2",
            "source": "scripts/make-reference-fixture.sh, run i-fresh-ag",
            "reference_root": f"{REFERENCE_ROOT}/runs/i-fresh-ag",
            "pinned_wall_unix_ms": self.now_ms,
            "issuer_key": {"seed": f"SHA-256 of the ASCII string {ISSUER_SEED_TEXT!r}",
                           "public_key_sha256": sha256(test_key(ISSUER_SEED_TEXT)[1])},
            "sources": SOURCES,
            "linux_binaries": {name: self.binaries[name] for name in
                               ("bin/ag-loopctl", "bin/nightshift-observation-resolver")},
            "produced_with": self.binaries,
            "files": files,
        }
        (native / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")


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


def dump_nightshift(state):
    with tempfile.TemporaryDirectory() as scratch:
        for path in pathlib.Path(state).glob("nightshift.sqlite*"):
            shutil.copy(path, scratch)
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


def dump_ag(state):
    with tempfile.TemporaryDirectory() as scratch:
        for path in pathlib.Path(state).glob("ag.sqlite*"):
            shutil.copy(path, scratch)
        db = sqlite3.connect(pathlib.Path(scratch) / "ag.sqlite")
        tables = {}
        for (table,) in db.execute("select name from sqlite_master where type='table' order by name"):
            cursor = db.execute(f'select * from "{table}" order by rowid')
            columns = [column[0] for column in cursor.description]
            tables[table] = [dict(zip(columns, row)) for row in cursor.fetchall()]
        schema = db.execute("select type,name,sql from sqlite_master order by type,name").fetchall()
        db.close()
    return {"schema": schema, "tables": tables}


def ag_documents(store):
    """The genesis and proposal documents Nightshift passed to `ag-loopctl`,
    read from the prepared AG request the store recorded."""
    with tempfile.TemporaryDirectory() as scratch:
        copy = pathlib.Path(scratch) / "nightshift.sqlite"
        shutil.copy(store, copy)
        db = sqlite3.connect(f"file:{copy}?mode=ro&immutable=1", uri=True)
        requests = set()
        for (snapshot,) in db.execute("select snapshot_json from canonical_cycle_events order by sequence"):
            prepared = json.loads(snapshot).get("prepared_ag_request")
            if prepared:
                exact = prepared["exact_request"]
                requests.add((jcs(exact["mode"]["genesis"]["genesis"]), jcs(exact["proposal_input"])))
        db.close()
    require(len(requests) == 1, f"expected one prepared AG request, found {len(requests)}")
    return requests.pop()


def make(args):
    p = Production(args)
    require(not p.root.exists(), f"refusing to overwrite {p.root}")
    p.root.mkdir(mode=0o755)
    p.programs()
    p.nq()
    p.request()
    p.pulse_config()
    a1 = p.acquire("a1")
    outcomes = {}
    for name in ("empty-receipts", "empty-receipts-2"):
        outcomes[name] = p.run(name, p.root / "pulse" / "config-empty.json")
    a2 = p.acquire("a2")
    outcomes["i-fresh-ag"] = p.run("i-fresh-ag", p.root / "pulse" / "config.json")
    require(a1 != a2, "the two acquisitions produced one receipt")

    require(all(next(iter(outcomes[name])) == "posture_only" for name in ("empty-receipts", "empty-receipts-2")),
            "a run without receipts did not end posture_only")
    require(next(iter(outcomes["i-fresh-ag"])) == "ag_occurrence_opened",
            f"i-fresh-ag ended {next(iter(outcomes['i-fresh-ag']))}")
    runs = p.root / "runs"
    require((runs / "empty-receipts" / "store-normalized.json").read_bytes() ==
            (runs / "empty-receipts-2" / "store-normalized.json").read_bytes(),
            "two runs without receipts do not normalize identically")
    require(not (runs / "empty-receipts" / "state" / "ag.sqlite").exists(), "a posture-only run reached AG")
    answers = {name: {key: value["status"] for key, value in
                      json.loads((runs / name / "resolver" / "summary.json").read_bytes()).items()}
               for name in ("empty-receipts", "i-fresh-ag")}
    require(answers["empty-receipts"] == {
        "current": "contradictory", "current-edge": "contradictory", "stale-edge": "contradictory",
        "absent": "absent", "wrong-subject": "contradictory", "deployment-wall-at-run-end": "contradictory"},
        f"empty-receipts resolver answers {answers['empty-receipts']}")
    require(answers["i-fresh-ag"] == {
        "current": "current", "current-edge": "current", "stale-edge": "stale", "absent": "absent",
        "wrong-subject": "contradictory", "deployment-wall-at-run-end": "current"},
        f"i-fresh-ag resolver answers {answers['i-fresh-ag']}")
    state = p.ag_replay()
    p.install(a1)
    print(f"REFERENCE FIXTURE OK root={REFERENCE_ROOT} request={p.derived['request_id']} "
          f"runs=empty-receipts,empty-receipts-2(normalized-identical),i-fresh-ag "
          f"ag_replay=row-identical state={state} issuer_public_sha256={sha256(test_key(ISSUER_SEED_TEXT)[1])}")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    m = sub.add_parser("make")
    for name in ("--linux-bin", "--request-builder", "--shim", "--fixtures"):
        m.add_argument(name, required=True)
    args = parser.parse_args()
    make(args)


if __name__ == "__main__":
    main()
