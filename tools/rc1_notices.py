#!/usr/bin/env python3
"""Check RC1 linked-input notice coverage and prepare an additive correction.

The source fingerprints are an audit boundary: a changed build input needs
a new inventory review, not an automatic assertion that the old texts cover
it. This supplements the existing Cargo/boot inventory; it does not infer
license derivation from symbols or turn a notice bundle into legal advice.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile

REQUIRED_SOURCES = {
    "kernel/src/i219.rs", "platform/c/bin/absd-cc", "platform/c/picolibc/PIN",
    "platform/userland/PIN", "platform/userland/PORTS.tsv", "platform/userland/Makefile",
    "platform/scripts/operator_image.py",
}
REQUIRED_SUPPLEMENTS = {"docs/rc1/notices/" + name for name in (
    "Picolibc-1.8.12-COPYING.txt", "FreeBSD-if_em-BSD-2-Clause.txt",
    "libm-0.2.16-LICENSE.txt", "libm-0.2.16-UPSTREAM-NOTICES.txt",
    "LLVM-compiler-rt-copyright.txt", "Apache-2.0.txt", "TEXT-PROVENANCE.json",
    "C-LINK-CORRESPONDENCE.json",
)}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check(root, base):
    root, base = Path(root), Path(base)
    directory = root / "docs/rc1/notices"
    raw = (directory / "NOTICE-INPUTS.json").read_bytes()
    inventory = json.loads(raw)
    if inventory["schema"] != "absd-linked-notices/1":
        raise ValueError("unknown linked-notice inventory schema")
    if set(inventory["source_sha256"]) != REQUIRED_SOURCES:
        raise ValueError("required RC1 source coverage differs")
    if set(inventory["supplement_sha256"]) != REQUIRED_SUPPLEMENTS:
        raise ValueError("required RC1 supplement coverage differs")
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


def package(root, base, out):
    inventory, receipt = check(root, base)
    directory = Path(root) / "docs/rc1/notices"
    files = {Path(name).name: (Path(root) / name).read_bytes() for name in inventory["supplement_sha256"]}
    if len(files) != len(inventory["supplement_sha256"]):
        raise ValueError("supplement filenames collide")
    files["NOTICE-INPUTS.json"] = (directory / "NOTICE-INPUTS.json").read_bytes()
    files["README.md"] = (
        "# RC1 third-party notice correction 1\n\n"
        "Prepared additive correction; publication requires its separate authorization.\n"
        "Keep this supplement beside the original published RC1 notices archive.\n"
        f"Original asset: {inventory['base_archive']['name']}\n"
        f"Original SHA-256: {inventory['base_archive']['sha256']}\n\n"
        "This adds the complete Picolibc 1.8.12 copyright aggregate, the BSD-2-Clause\n"
        "if_em.c notice cited by the I219 derivation, and per-file libm 0.2.16 notices\n"
        "including Sun's permission text. LLVM compiler-rt text is included conservatively\n"
        "for the builtins archive offered by the C linker driver. The 12 exact RC1 C\n"
        "port maps selected libc.a members, including libm_common classification helpers;\n"
        "they selected no libm.a or libclang_rt.builtins archive members.\n"
        "The complete Picolibc aggregate describes additional unbuilt files, too;\n"
        "including it does not assert all its licenses apply to the shipped objects.\n"
        "TEXT-PROVENANCE.json records the exact upstream inputs and extraction scope.\n"
        "NOTICE-INPUTS.json classifies C link inputs and binds the base/supplement texts.\n"
        "No existing published file or binary is replaced or changed. The original\n"
        "Rust, kernel and boot notices and corresponding-source archive remain required.\n"
    ).encode()
    files["CHECK.json"] = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    files["SHA256SUMS"] = "".join(f"{sha(data)}  {name}\n" for name, data in sorted(files.items())).encode()
    with Path(out).open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for name, data in sorted(files.items()):
                    item = tarfile.TarInfo("rc1-notices-correction-1/" + name)
                    item.size, item.mode, item.mtime = len(data), 0o644, 0
                    archive.addfile(item, io.BytesIO(data))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "package"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "package":
            if args.out is None:
                parser.error("package requires --out (a new file)")
            receipt = package(args.root, args.base, args.out)
        else:
            _, receipt = check(args.root, args.base)
        print(json.dumps(receipt, indent=2, sort_keys=True))
    except (ValueError, OSError, tarfile.TarError) as exc:
        raise SystemExit(f"linked notices refused: {exc}") from exc


if __name__ == "__main__":
    main()
