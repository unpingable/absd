#!/usr/bin/env python3
"""Stage the exact private ring source for the admitted TLS fixture only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parent.parent
PREFIX = "index.crates.io-1949cf8c6b5b557f"


def file_manifest(directory):
    files = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise SystemExit("staged ring contains a non-regular source object")
        if path.is_file():
            files[path.relative_to(directory).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return files


def stage(destination, cargo_home):
    destination = destination.resolve()
    if destination == ROOT or ROOT in destination.parents:
        raise SystemExit("TLS staging must be outside the source worktree")
    packages = json.loads((ROOT / "tls/PIN.json").read_text())["packages"]
    expected = next(x["checksum"] for x in packages if x["name"] == "ring")
    archive = cargo_home / "registry/cache" / PREFIX / "ring-0.17.14.crate"
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise SystemExit("ring archive checksum differs from the reviewed pin")
    patches = [ROOT / "patches/ring-absd.patch", ROOT / "patches/ring-absd-tls-fixture-rng.patch"]
    receipt = {"schema_version": 1, "ring_archive_sha256": expected,
               "patches": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in patches}}
    if destination.exists():
        recorded = destination / "STAGE.json"
        if not recorded.is_file():
            raise SystemExit("existing TLS staging has no receipt")
        previous = json.loads(recorded.read_text())
        recorded_manifest = destination / "STAGED-FILES.json"
        if not recorded_manifest.is_file() or previous.get("source_manifest_sha256") != hashlib.sha256(recorded_manifest.read_bytes()).hexdigest():
            raise SystemExit("staged ring source manifest is missing or changed")
        receipt["source_manifest_sha256"] = previous["source_manifest_sha256"]
        if previous != receipt:
            raise SystemExit("existing TLS staging has a different identity; preserve and choose a new path")
    else:
        destination.mkdir(parents=True)
        with tarfile.open(archive) as source:
            source.extractall(destination, filter="data")
        (destination / "ring-0.17.14").rename(destination / "ring")
        env = {**os.environ, "GIT_CEILING_DIRECTORIES": str(destination)}
        for patch in patches:
            subprocess.run(["git", "apply", "--check", str(patch)], cwd=destination / "ring", env=env, check=True)
            subprocess.run(["git", "apply", str(patch)], cwd=destination / "ring", env=env, check=True)
        manifest = destination / "STAGED-FILES.json"
        manifest.write_text(json.dumps(file_manifest(destination / "ring"), indent=2) + "\n")
        receipt["source_manifest_sha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
        (destination / "STAGE.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if file_manifest(destination / "ring") != json.loads((destination / "STAGED-FILES.json").read_text()):
        raise SystemExit("staged ring exact file set or content differs from its sealed source manifest")
    for patch in reversed(patches):
        subprocess.run(["git", "apply", "--reverse", "--check", str(patch)], cwd=destination / "ring",
                       env={**os.environ, "GIT_CEILING_DIRECTORIES": str(destination)}, check=True)
    link = ROOT / "tls/tree/ring"
    link.parent.mkdir(exist_ok=True)
    if link.is_symlink():
        if link.resolve() != destination / "ring":
            raise SystemExit("TLS ring link names another staging path; do not replace it")
    elif link.exists():
        raise SystemExit("TLS ring path is not the expected staging link")
    else:
        link.symlink_to(destination / "ring", target_is_directory=True)
    print("TLS RING STAGE OK", destination)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True, type=Path)
    parser.add_argument("--cargo-home", required=True, type=Path)
    args = parser.parse_args()
    stage(args.stage, args.cargo_home.resolve())
