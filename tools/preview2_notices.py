#!/usr/bin/env python3
"""Check Preview 2 linked-input notice coverage and prepare an additive correction.

The source fingerprints are an audit boundary: a changed build input needs
a new inventory review, not an automatic assertion that the old texts cover
it. This supplements the existing Cargo/boot inventory; it does not infer
license derivation from symbols or turn a notice bundle into legal advice.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile

REQUIRED_SOURCES = {
    "kernel/src/i219.rs", "platform/c/bin/absd-cc", "platform/c/picolibc/PIN",
    "platform/userland/PIN", "platform/userland/PORTS.tsv", "platform/userland/Makefile",
    "platform/scripts/operator_image.py",
}
REQUIRED_SUPPLEMENTS = {"docs/preview2/notices/" + name for name in (
    "Picolibc-1.8.12-COPYING.txt", "FreeBSD-if_em-BSD-2-Clause.txt",
    "libm-0.2.16-LICENSE.txt", "libm-0.2.16-UPSTREAM-NOTICES.txt",
    "LLVM-compiler-rt-copyright.txt", "Apache-2.0.txt", "TEXT-PROVENANCE.json",
    "C-LINK-CORRESPONDENCE.json", "PUBLIC-MEMBER-HASHES.json",
    "simd_license.txt", "fluent_license.txt", "fluent_apache.txt", "plural_mit.txt", "plural_apache.txt",
)}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check(root, base):
    root, base = Path(root), Path(base)
    directory = root / "docs/preview2/notices"
    raw = (directory / "NOTICE-INPUTS.json").read_bytes()
    inventory = json.loads(raw)
    if inventory["schema"] != "absd-linked-notices/1":
        raise ValueError("unknown linked-notice inventory schema")
    if set(inventory["source_sha256"]) != REQUIRED_SOURCES:
        raise ValueError("required Preview 2 source coverage differs")
    if set(inventory["supplement_sha256"]) != REQUIRED_SUPPLEMENTS:
        raise ValueError("required Preview 2 supplement coverage differs")
    for field in ("source_sha256", "supplement_sha256"):
        for name, expected in inventory[field].items():
            rel = Path(name)
            if rel.is_absolute() or ".." in rel.parts:
                raise ValueError("notice inventory path escapes source root")
            path = root / rel
            if (path.is_symlink() or not path.resolve().is_relative_to(root.resolve())
                    or not path.is_file() or sha(path.read_bytes()) != expected):
                raise ValueError(f"notice input missing or changed: {name}")
    driver = (root / "platform/c/bin/absd-cc").read_text()
    offered = set(re.findall(r"\$kit/lib/([A-Za-z0-9_.+-]+)", driver))
    offered.update(re.findall(r"\b(libclang_rt\.builtins-[A-Za-z0-9_-]+\.a)\b", driver))
    if offered != set(inventory["c_link_inputs"]):
        raise ValueError(f"C linker inputs differ from classified inventory: {sorted(offered)}")
    makefile = (root / "platform/userland/Makefile").read_text()
    offered_userland = set(re.findall(r"\b(lib(?:absd-posix|utf|util)\.a)\b", makefile))
    if offered_userland != set(inventory["c_userland_archives"]):
        raise ValueError("C userland archive classification differs")
    if sha(base.read_bytes()) != inventory["base_archive"]["sha256"]:
        raise ValueError("base notices archive differs from the published RC1 asset")
    with tarfile.open(base) as archive:
        members = {}
        for item in archive:
            if not item.isfile() or item.name in members:
                raise ValueError("base archive has unexpected entry type or duplicate name")
            members[item.name] = sha(archive.extractfile(item).read())
    if members != inventory["base_archive"]["regular_members_sha256"]:
        raise ValueError("base notices member inventory differs")
    sun = (directory / "libm-0.2.16-UPSTREAM-NOTICES.txt").read_text()
    if not all(text in sun for text in ("Sun Microsystems", "Permission to use, copy, modify", "provided that this notice")):
        raise ValueError("libm per-file Sun permission notice is absent")
    if_em = (directory / "FreeBSD-if_em-BSD-2-Clause.txt").read_text()
    if not all(text in if_em for text in ("BSD-2-Clause", "Nicole Graziano", "Kevin Bowling", "Intel Corporation")):
        raise ValueError("if_em copyright coverage is absent")
    return inventory, {"schema": "absd-linked-notices-check/1", "result": "PASS",
                       "release_id": inventory["release_id"], "inventory_sha256": sha(raw),
                       "source_inputs": len(inventory["source_sha256"]),
                       "supplement_files": len(inventory["supplement_sha256"]),
                       "base_regular_files": len(members), "classified_c_link_inputs": sorted(offered),
                       "limits": inventory["scope"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check",))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--base", type=Path, required=True)
    args = parser.parse_args()
    try:
        _, receipt = check(args.root, args.base)
        print(json.dumps(receipt, indent=2, sort_keys=True))
    except (ValueError, OSError, tarfile.TarError) as exc:
        raise SystemExit(f"linked notices refused: {exc}") from exc


if __name__ == "__main__":
    main()
