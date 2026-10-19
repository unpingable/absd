#!/usr/bin/env python3
"""Check declared private QUIC pins against its lock and admitted ring inputs.

This checks the declared PIN rows. It does not infer active target selection,
licence inventory, linking or execution from Cargo.lock's larger package set.
"""
import hashlib
import json
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
RING_PATCHES = {"ring-absd.patch", "ring-absd-tls-fixture-rng.patch"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inputs(root):
    pin = json.loads((root / "quic/PIN.json").read_bytes())
    lock = tomllib.loads((root / "quic/Cargo.lock").read_text())
    manifest = tomllib.loads((root / "quic/Cargo.toml").read_text())
    tls = json.loads((root / "tls/PIN.json").read_bytes())
    ring = next(row for row in pin["packages"] if row["name"] == "ring")
    require(set(ring["existing_patches"]) == RING_PATCHES, "ring patch names differ")
    patches = {name: hashlib.sha256((root / "patches" / name).read_bytes()).hexdigest()
               for name in ring["existing_patches"]}
    return pin, lock, manifest, tls, patches


def verify(pin, lock, manifest, tls, patches):
    require(pin["schema_version"] == 1 and lock["version"] == 4, "pin/lock schema")
    declared, locked = {}, {}
    for row in pin["packages"]:
        key = row["name"], row["version"]
        require(key not in declared, "duplicate PIN package")
        require(re.fullmatch("[0-9a-f]{64}", row["archive_sha256"]), "PIN checksum format")
        declared[key] = row
    require(declared, "empty PIN package set")
    for row in lock["package"]:
        key = row["name"], row["version"]
        require(key not in locked, "ambiguous lock package")
        require(row.get("source") in (None, REGISTRY), "unexpected lock source")
        locked[key] = row
    checked, path_patched = [], []
    for key, row in declared.items():
        require(key in locked, "PIN package absent from lock: " + repr(key))
        actual = locked[key]
        if key[0] == "ring":
            require(key == ("ring", "0.17.14") and "source" not in actual
                    and "checksum" not in actual, "ring must remain path patched")
            require(manifest["patch"]["crates-io"]["ring"] == {"path": "tree/ring"}, "ring path differs")
            admitted = [item for item in tls["packages"]
                        if (item["name"], item["version"]) == key]
            require(len(admitted) == 1 and admitted[0]["checksum"] == row["archive_sha256"],
                    "ring archive differs from admitted TLS pin")
            require(set(patches) == RING_PATCHES and row["existing_patches"] == patches,
                    "ring patches differ from declared admitted inputs")
            path_patched.append({"name": key[0], "version": key[1], "archive_sha256": row["archive_sha256"]})
        else:
            require(actual.get("source") == REGISTRY and actual.get("checksum") == row["archive_sha256"],
                    "PIN/lock checksum differs: " + repr(key))
            checked.append({"name": key[0], "version": key[1], "checksum": actual["checksum"]})
    require(len(path_patched) == 1, "declared ring pin missing")
    for alias, item in manifest["dependencies"].items():
        if isinstance(item, dict) and "path" in item:
            continue
        version = item if isinstance(item, str) else item["version"]
        name = alias if isinstance(item, str) else item.get("package", alias)
        require(version.startswith("=") and (name, version[1:]) in declared,
                "direct dependency lacks an exact declared pin: " + alias)
    unselected = [{"name": name, "version": version, "checksum": row["checksum"]}
                  for (name, version), row in locked.items()
                  if row.get("source") == REGISTRY and (name, version) not in declared]
    return {"schema_version": 1, "disposition": "PASS", "checked_registry_packages": checked,
            "path_patched_packages": path_patched, "lock_only_registry_packages": unselected,
            "scope": "Every declared PIN and exact direct dependency agrees with lock; ring archive/patches agree with admitted TLS inputs. Lock-only entries are reported, not proven inactive. Target selection and licence inventory remain separate."}


if __name__ == "__main__":
    print(json.dumps(verify(*inputs(ROOT)), sort_keys=True))
