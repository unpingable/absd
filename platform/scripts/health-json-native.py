#!/usr/bin/env python3
"""Add health observations to the unchanged served recovery qualification.

Uses its existing boot/fault/normal-end checks. Only the files installed and
the observation callback change; none of its transition predicates change.
"""
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


recovery = module("health_recovery", ROOT / "scripts/survival-recovery.py")
validator = module("health_validator", ROOT / "scripts/validate-health-json.py")
OriginalTarget = recovery.RecoveryTarget
original_check = recovery.serve_and_check


class HealthTarget(OriginalTarget):
    def files(self, authorized):
        files = super().files(authorized)
        files.append(("/bin/health", (self.root / "commands/health").read_bytes()))
        return files


def check(target, client, key, index, runner_pid, marker, args, streak, previous):
    boot = original_check(target, client, key, index, runner_pid, marker, args, streak, previous)
    result = recovery.ssh(client, key, "/bin/health --json", timeout=90)
    # An acquisition timeout is failure outside the document, never complete.
    if result.returncode != 0 or result.stderr:
        raise RuntimeError(f"health JSON acquisition refused rc={result.returncode} stderr={result.stderr!r}")
    if validator.validate(result.stdout) != "complete":
        raise RuntimeError("native served health is partial")
    doc = json.loads(result.stdout)
    facts = {f["id"]: f for f in doc["facts"]}
    value = facts["fsd.recovery"]["value"]
    if doc["boot_id"] != boot or value["boot_id"] != boot or value["streak"] != str(streak) or value["previous"] != previous:
        raise RuntimeError("health does not describe the checked boot/recovery outcome")
    # Compare the independently acquired public log summary, not only the
    # renderer's own fields. The existing parser is still the owning grammar.
    current = recovery.ssh(client, key, "/bin/cat /var/log/fsd")
    rotated = recovery.ssh(client, key, "/bin/cat /var/log/fsd.0")
    needle = f"FSD RECOVERY seq={value['seq']} streak={streak} previous={previous}".encode()
    if current.returncode != 0 or needle not in rotated.stdout + current.stdout:
        raise RuntimeError("health summary differs from public retained log")
    human = recovery.ssh(client, key, "/bin/health")
    expected = f"recovery: previous={previous} streak={streak} seq={value['seq']}".encode()
    if human.returncode != 0 or human.stderr or expected not in human.stdout:
        raise RuntimeError("human health differs from JSON recovery")
    directory = Path(args.work) / "health-observations"
    directory.mkdir(exist_ok=True)
    path = directory / f"{boot}.json"
    with path.open("xb") as out:
        out.write(result.stdout)
    (directory / f"{boot}.human.txt").write_bytes(human.stdout)
    print(f"HEALTH JSON NATIVE OK boot={boot} previous={previous} streak={streak} seq={value['seq']} validator={validator.SCHEMA}", flush=True)
    return boot


if __name__ == "__main__":
    recovery.RecoveryTarget = HealthTarget
    recovery.serve_and_check = check
    recovery.main()
