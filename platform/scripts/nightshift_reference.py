#!/usr/bin/env python3
"""Nightshift fixture reference: record the Linux resolver's answers, or
compare an ABSD resolver's answers with them.

`record` runs the real Linux `nightshift-observation-resolver` (its own
process, its own SQLite) against a scratch copy of the frozen store for a
fixed set of AG observation requests, and writes requests, answers, and a
manifest binding store bytes and source revisions. `compare` checks answers
from another platform byte for byte.
"""

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

RESOLVER_ID = "nightshift-observation-resolver/v1"
TTL_MS = 600_000


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def requests(cycle):
    evaluated = cycle["evaluated_at_unix_ms"]
    base = {
        "schema": "ag.governed-loop.observation-request/v1",
        "key": {"campaign": "sha256:" + "a" * 64, "occurrence": "00000000-0000-4000-8000-000000000000"},
        "observation": cycle["observation"],
        "subject": cycle["subject"],
    }
    return {
        "current": {**base, "now_unix_ms": evaluated + 300_000},
        "current-edge": {**base, "now_unix_ms": evaluated + TTL_MS - 1},
        "stale-edge": {**base, "now_unix_ms": evaluated + TTL_MS},
        "absent": {**base, "observation": "sha256:" + "e" * 64, "now_unix_ms": evaluated + 300_000},
        "wrong-subject": {**base, "subject": "sha256:" + "c" * 64, "now_unix_ms": evaluated + 300_000},
    }


def run_resolver(resolver, store_dir, request):
    with tempfile.TemporaryDirectory() as scratch:
        # The resolver opens read-only, but the frozen bytes are never handed
        # to any process: it reads a copy.
        for path in pathlib.Path(store_dir).iterdir():
            shutil.copy(path, scratch)
        result = subprocess.run(
            [resolver, "--store", str(pathlib.Path(scratch) / "nightshift.sqlite"),
             "--resolver-id", RESOLVER_ID, "--default-ttl-ms", str(TTL_MS)],
            input=canonical(request), capture_output=True, check=False)
    return result.returncode, result.stdout


def record(args):
    fixture = pathlib.Path(args.fixture)
    cycle = json.loads((fixture / "cycle.json").read_bytes())
    (fixture / "requests").mkdir()
    (fixture / "reference").mkdir()
    answers = {}
    for name, request in requests(cycle).items():
        (fixture / "requests" / f"{name}.json").write_bytes(canonical(request))
        code, stdout = run_resolver(args.resolver, fixture / "store", request)
        if code != 0:
            sys.exit(f"Linux resolver failed on {name}: exit {code}")
        (fixture / "reference" / f"{name}.json").write_bytes(stdout)
        answers[name] = {"status": json.loads(stdout)["status"], "sha256": sha256(stdout)}
    expected = {"current": "current", "current-edge": "current", "stale-edge": "stale",
                "absent": "absent", "wrong-subject": "contradictory"}
    got = {name: answer["status"] for name, answer in answers.items()}
    if got != expected:
        sys.exit(f"Linux resolver answers {got} differ from Nightshift's own contract {expected}")
    store = {path.name: {"sha256": sha256(path.read_bytes()), "bytes": path.stat().st_size}
             for path in sorted((fixture / "store").iterdir())}
    body = {
        "schema": "absd.nightshift-fixture/v1",
        "nightshift_commit": args.nightshift_commit,
        "ag_commit": args.ag_commit,
        "writer": "nightshiftd CanonicalRuntime::run_cycle via tools/nightshift-fixture; AG port real ag-loopctl; "
                  "present evidence: Nightshift pulse-support-resolver fixture; NQ admission: Nightshift test authority",
        "slot_due": args.due,
        "resolver_id": RESOLVER_ID,
        "default_ttl_ms": TTL_MS,
        "cycle": cycle,
        "store": store,
        "answers": answers,
    }
    manifest = {"fixture_id": "sha256:" + sha256(canonical(body)), **body}
    (fixture / "manifest.json").write_bytes(canonical(manifest) + b"\n")
    print(f"NIGHTSHIFT_FIXTURE_ID {manifest['fixture_id']}")


def compare(args):
    fixture = pathlib.Path(args.fixture)
    manifest = json.loads((fixture / "manifest.json").read_bytes())
    answers = json.loads(pathlib.Path(args.answers).read_bytes())
    # The requests and reference answers on disk must be the ones the
    # manifest binds: requests derive from the recorded cycle, answers by
    # digest.
    body = {key: value for key, value in manifest.items() if key != "fixture_id"}
    if manifest["fixture_id"] != "sha256:" + sha256(canonical(body)):
        sys.exit("manifest does not match its fixture_id")
    derived = requests(manifest["cycle"])
    if sorted(derived) != sorted(manifest["answers"]):
        sys.exit("manifest answers do not cover exactly the derived requests")
    for name, request in derived.items():
        if (fixture / "requests" / f"{name}.json").read_bytes() != canonical(request):
            sys.exit(f"request {name} differs from the one derived from the recorded cycle")
    for name, reference in manifest["answers"].items():
        got = answers.get(name)
        expected = (fixture / "reference" / f"{name}.json").read_bytes()
        if sha256(expected) != reference["sha256"]:
            sys.exit(f"reference answer {name} differs from the manifest digest")
        if got is None or got.encode() + b"\n" != expected:
            sys.exit(f"answer {name} differs from the Linux reference:\n  got {got!r}\n  want {expected!r}")
    print(f"NIGHTSHIFT RESOLVER EQUIVALENCE OK fixture={manifest['fixture_id']} answers={len(manifest['answers'])}")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    rec = sub.add_parser("record")
    rec.add_argument("--resolver", required=True)
    rec.add_argument("--fixture", required=True)
    rec.add_argument("--nightshift-commit", required=True)
    rec.add_argument("--ag-commit", required=True)
    rec.add_argument("--due", required=True)
    cmp_ = sub.add_parser("compare")
    cmp_.add_argument("--fixture", required=True)
    cmp_.add_argument("--answers", required=True)
    args = parser.parse_args()
    record(args) if args.command == "record" else compare(args)


if __name__ == "__main__":
    main()
