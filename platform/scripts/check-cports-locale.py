#!/usr/bin/env python3
"""Build real C ports under C and en_US.UTF-8; compare all retained products.

Uses the existing builder and its two clean rounds, not substituted tools.
Requires an isolated ABSD_CPORTS_BUILD, staged inputs and an empty result path.
Does not start a guest or update historical references.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

REFERENCES = Path(__file__).resolve().parent.parent / "pins/cports-demand.sha256"


def check_references(hashes):
    expected = {}
    for line in REFERENCES.read_text().splitlines():
        digest, name = line.split()
        if name in expected:
            raise ValueError("duplicate demand reference: " + name)
        expected[name] = digest
    if set(expected) != {"absd/lua.demand", "absd/speedtest1.demand", "absd/sqlite3.demand"}:
        raise ValueError("incomplete demand reference set")
    for name, digest in expected.items():
        if hashes.get(name) != digest:
            raise ValueError("demand reference changed: " + name)
    return expected


def snapshot(output, destination):
    products = output / "absd"
    demands = sorted(products.glob("*.demand"))
    if not demands:
        raise ValueError("builder produced no demand artifacts")
    paths = sorted(p for p in products.iterdir() if p.is_file())
    paths.append(output / "lib/libabsd-posix.a")
    hashes = {}
    canonical = True
    for path in paths:
        relative = path.relative_to(output)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        data = target.read_bytes()
        hashes[str(relative)] = hashlib.sha256(data).hexdigest()
        if path.suffix == ".demand":
            names = data.splitlines()
            canonical &= data == b"".join(name + b"\n" for name in sorted(set(names)))
    check_references(hashes)
    return {"hashes": hashes, "demands": len(demands), "canonical_order": canonical}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-output", type=Path)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--check-results", type=Path,
                        help="check pinned demand bytes in a retained successful comparison; no build")
    args = parser.parse_args()
    if args.check_results:
        if args.build_output or args.results:
            parser.error("--check-results is separate from a new build")
        saved = json.loads((args.check_results / "result.json").read_text())
        if saved["disposition"] != "PASS":
            raise ValueError("retained comparison did not pass")
        for label in ("C", "en_US"):
            expected = check_references(saved["cases"][label]["hashes"])
            for name, digest in expected.items():
                if hashlib.sha256((args.check_results / label / name).read_bytes()).hexdigest() != digest:
                    raise ValueError("retained demand bytes changed: " + name)
        print("CPORTS DEMAND REFERENCES OK files=6")
        return
    if args.build_output is None or args.results is None:
        parser.error("a new comparison requires --build-output and --results")
    output, results = args.build_output.resolve(), args.results.resolve()
    if output == results or output in results.parents or results in output.parents:
        parser.error("build and result directories must be separate")
    results.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parent.parent
    record = {"source": subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip(),
        "builder_sha256": hashlib.sha256(
            (root / "scripts/build-cports.sh").read_bytes()).hexdigest(),
        "references_sha256": hashlib.sha256(REFERENCES.read_bytes()).hexdigest(),
        "source_status": subprocess.check_output(
            ["git", "-C", str(root), "status", "--porcelain"], text=True),
        "build_output": str(output), "cases": {}, "disposition": "FAIL"}
    try:
        if record["source_status"]:
            raise ValueError("comparison requires a clean source checkout")
        for label, locale in (("C", "C"), ("en_US", "en_US.UTF-8")):
            env = dict(os.environ, LC_ALL=locale, LANG=locale,
                       ABSD_CPORTS_BUILD=str(output))
            probe = subprocess.run(["locale", "charmap"], env=env,
                                   capture_output=True, text=True)
            if probe.returncode or probe.stderr:
                raise ValueError(f"required locale unavailable: {locale}")
            destination = results / label
            destination.mkdir()
            started = time.monotonic()
            with (destination / "build.log").open("wb") as log:
                cp = subprocess.run(["sh", str(root / "scripts/build-cports.sh")],
                                    cwd=root, env=env, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=1800)
            case = {"locale": locale, "exit_code": cp.returncode,
                    "seconds": time.monotonic() - started}
            record["cases"][label] = case
            if cp.returncode:
                raise ValueError(f"{label} builder failed: {cp.returncode}")
            case.update(snapshot(output, destination))
        first, second = (record["cases"][k] for k in ("C", "en_US"))
        names = sorted(set(first["hashes"]) | set(second["hashes"]))
        record["different"] = [n for n in names
                               if first["hashes"].get(n) != second["hashes"].get(n)]
        if record["different"] or not all(c["canonical_order"] for c in (first, second)):
            raise ValueError("cross-locale products differ or demand is not in byte order")
        record["disposition"] = "PASS"
        print(f"CPORTS LOCALE OK artifacts={len(names)} locales=2 clean_rounds=4")
    except Exception as error:
        record["error"] = str(error)
        raise
    finally:
        (results / "result.json").write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
