#!/usr/bin/env python3
"""Pulse support fixture helpers (Linux host side; no ABSD code).

`make` runs the real pinned Linux `pulse-nq-load-support` producer and
receiver roles under a test deployment and retains public outputs with
provenance. The deployment pins mirror the NQ fixture's artifact
(fixtures/nq: subject, scope, vantage, artifact id);
the diagnostic inputs id is a test pin, since no Nightshift cycle exists
here to compute it.
"""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# From the NQ fixture (fixtures/nq/manifest.json: nq.diagnostic_execution.v2,
# scripts/make-nq-fixture.sh).
NQ_ARTIFACT_ID = "sha256:bddd0a9e1e29fad5c066ab0fb3cfd6c32408e6f1ad8d3f38ec79235a5a83bbd3"
NQ_SUBJECT_ID = "host:local"
NQ_SCOPE_DIGEST = "sha256:63018d3e968fd57925529baf0dcd668ad7f83994bdf912afd1c88a9a1d206908"
NQ_VANTAGE_ID = "nq.vantage.local.nq-store-genesis:26373050-17aa-4ed9-8a41-cc27f3bcfb1f.host-local"
TEST_DIAGNOSTIC_INPUTS_ID = "sha256:" + hashlib.sha256(b"absd-pulse-lane-c/test-diagnostic-inputs/v1").hexdigest()

ABSD_ROOT = "/pulse"
# The producing machine is not named: provenance records this label.
HOST_LABEL = "refhost"
ACQUISITIONS = ["support:absd-lane-c-1", "support:absd-lane-c-2"]


def jcs(value):
    # Objects, arrays, ASCII strings and integers only: sorted keys and
    # compact separators are exactly JCS for them.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def object_id(value, field):
    preimage = {k: v for k, v in value.items() if k != field}
    return "sha256:" + hashlib.sha256(jcs(preimage)).hexdigest()


def sha256_file(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def config_for(public_hex, root, expected_state="explicitly_absent"):
    root = str(root)
    return {
        "schema": "pulse.nq_host_load_pressure_support_config.v1",
        "authority_id": "pulse-authority:absd-lane-c-test-v1",
        "support_family": "pulse.nq_host_load_pressure.v1",
        "producer_id": "pulse-producer:absd-lane-c-test-v1",
        "producer_key_id": "pulse-key:sha256:" + hashlib.sha256(bytes.fromhex(public_hex)).hexdigest(),
        "producer_public_key_hex": public_hex,
        "producer_private_key_path": f"{root}/producer.key",
        "subject_id": NQ_SUBJECT_ID,
        "scope_id": NQ_SCOPE_DIGEST,
        "vantage_id": NQ_VANTAGE_ID,
        "question": {"id": "nq.host.load_pressure", "version": "1",
                     "digest": "sha256:7de797da3d9d3a6ae8e21e5d77b95095453336cd38f606ffb3eb29ff6a32e2cf"},
        "profile": {"id": "nq.host", "version": "1",
                    "digest": "sha256:c8c10fed1cc5598d953b4defbc98e8c106fc59e035c249d43681698a5c7b4ff9"},
        "profile_semantic_id": "sha256:382b8dac14ef9353a3603757d60fc8fbc727e1bcaf088c9aab4bdf895d3f6ab1",
        "threshold_policy": {"id": "nq.host.load_pressure.threshold_policy", "version": "1",
                             "digest": "sha256:52b815509d26878fad1f88c6352bcd17537452f704072e56664e18434fee855e"},
        "outgoing_directory": f"{root}/outgoing",
        "receipt_directory": f"{root}/receipts",
        "expected_diagnostic": {
            "diagnostic_inputs_id": TEST_DIAGNOSTIC_INPUTS_ID,
            "artifact_ids": [NQ_ARTIFACT_ID],
            "expected_state": expected_state,
        },
    }


def query(nonce="support-query:absd-lane-c-1", cycle="cycle:absd-lane-c-1", **overrides):
    value = {
        "schema": "nightshift.present_evidence_query.v1",
        "query_id": "",
        "observation_cycle_id": cycle,
        "request_nonce": nonce,
        "observation_id": "sha256:" + hashlib.sha256(b"absd-pulse-lane-c/test-observation/v1").hexdigest(),
        "diagnostic_inputs_id": TEST_DIAGNOSTIC_INPUTS_ID,
        "subject_id": NQ_SUBJECT_ID,
        "scope_id": NQ_SCOPE_DIGEST,
        "artifact_ids": [NQ_ARTIFACT_ID],
    }
    value.update(overrides)
    value["query_id"] = object_id(value, "query_id")
    return value


def linux_clock():
    boot_id = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    uptime = pathlib.Path("/proc/uptime").read_text().split()[0]
    return "pulse-linux-boottime:sha256:" + hashlib.sha256(boot_id.encode()).hexdigest(), uptime


def role(binary, name, work):
    link = work / "bin" / name
    link.parent.mkdir(exist_ok=True)
    if not link.exists():
        link.symlink_to(binary)
    return link


def make(args):
    binary = pathlib.Path(args.binary).resolve()
    work = pathlib.Path(args.work).resolve()
    out = pathlib.Path(args.out).resolve()
    secrets = work / "deploy"
    secrets.mkdir(mode=0o700, parents=True)
    key = Ed25519PrivateKey.generate()
    private_hex = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                    serialization.NoEncryption()).hex()
    public_hex = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    descriptor = os.open(secrets / "producer.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(descriptor, private_hex.encode())
    os.close(descriptor)
    linux_config = config_for(public_hex, secrets)
    (work / "config.json").write_bytes(jcs(linux_config))
    config_path = str(work / "config.json")
    started_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    clock_id, uptime_before = linux_clock()
    events = []
    for acquisition in ACQUISITIONS:
        for name in ("pulse-load-pressure-producer", "pulse-load-pressure-receiver"):
            result = subprocess.run([str(role(binary, name, work)), "--config", config_path,
                                     "--acquisition-id", acquisition], capture_output=True, text=True)
            if result.returncode != 0:
                sys.exit(f"{name} {acquisition} failed: {result.stderr}")
            events.append({"role": name, "acquisition_id": acquisition, "identity": result.stdout.strip(),
                           "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                           "uptime_s": linux_clock()[1]})
        time.sleep(2)
    query_bytes = jcs(query())
    answer = subprocess.run([str(role(binary, "pulse-support-resolver", work))], input=query_bytes,
                            capture_output=True, env={"PULSE_LOAD_SUPPORT_CONFIG": config_path})
    if answer.returncode != 0:
        sys.exit(f"Linux resolver refused: {answer.stderr!r}")
    clock_after, uptime_after = linux_clock()
    if clock_after != clock_id:
        sys.exit("the host rebooted during fixture production")

    out.mkdir(parents=True)
    for directory in ("receipts", "outgoing"):
        (out / directory).mkdir()
        for path in sorted((secrets / directory).iterdir()):
            (out / directory / path.name).write_bytes(path.read_bytes())
    (out / "config.json").write_bytes(jcs(config_for(public_hex, ABSD_ROOT)))
    (out / "query.json").write_bytes(query_bytes)
    (out / "linux-answer.json").write_bytes(answer.stdout)
    receipts = {}
    for path in sorted((out / "receipts").iterdir()):
        receipt = json.loads(path.read_bytes())
        evidence = receipt["evidence"]["evidence"]
        receipts[path.name] = {
            "sha256": sha256_file(path), "receipt_id": receipt["receipt_id"],
            "evidence_id": evidence["evidence_id"], "acquisition_id": evidence["acquisition_id"],
            "state": evidence["state"], "load_1m_token": evidence["load_1m_token"],
            "logical_cpu_count": evidence["logical_cpu_count"],
            "received_at": receipt["received_at"], "expiry_tick_ms": receipt["expiry_tick_ms"],
        }
    manifest = {
        "schema": "absd.pulse-support-fixture/v1",
        "pulse_commit": args.pulse_commit,
        "binary": {"crate": "pulse-nq-load-support", "unpatched": True, "sha256": sha256_file(binary),
                   "rustc": subprocess.run(["rustc", "--version"], capture_output=True, text=True).stdout.strip()},
        "host": {"hostname": HOST_LABEL, "kernel": platform.release(),
                 "linux_clock_id": clock_id, "uptime_s_before": uptime_before, "uptime_s_after": uptime_after,
                 "started_utc": started_utc},
        "deployment": {
            "key": "ed25519 generated for this fixture; private key discarded",
            "config_paths": "produced under a scratch root; retained config.json names the ABSD mount /pulse",
            "pins": "subject, scope, vantage and artifact id from the campaign NQ artifact; "
                    "diagnostic_inputs_id is a test pin",
        },
        "events": events,
        "receipts": receipts,
        "config_sha256": sha256_file(out / "config.json"),
        "query_sha256": sha256_file(out / "query.json"),
        "linux_answer": {"sha256": sha256_file(out / "linux-answer.json"),
                         "standing": json.loads(answer.stdout)["standing"]},
    }
    manifest["fixture_id"] = object_id(manifest, "fixture_id")
    (out / "manifest.json").write_bytes(jcs(manifest) + b"\n")
    print(f"PULSE FIXTURE {manifest['fixture_id']} standing={manifest['linux_answer']['standing']} "
          f"receipts={len(receipts)} clock={clock_id}")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    m = sub.add_parser("make")
    for name in ("--binary", "--work", "--out", "--pulse-commit"):
        m.add_argument(name, required=True)
    args = parser.parse_args()
    if args.command == "make":
        make(args)


if __name__ == "__main__":
    main()
