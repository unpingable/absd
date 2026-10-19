#!/usr/bin/env python3
"""Fetch the RC1 C-userland inputs from public pins, before offline builds.

Crates and index entries are handled separately by fetch.sh. This script
does not compile or fetch unrelated optional C-port workloads.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.request


def fetch(url, path, checksum):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        part = path.with_name(path.name + ".part")
        with urllib.request.urlopen(url) as source, part.open("xb") as output:
            for block in iter(lambda: source.read(1 << 20), b""):
                output.write(block)
        if hashlib.sha256(part.read_bytes()).hexdigest() != checksum:
            raise SystemExit(f"checksum differs (unaccepted download retained): {part}")
        os.replace(part, path)
    if hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
        raise SystemExit(f"checksum differs: {path}")
    print(f"PUBLIC INPUT OK {checksum} {path}", flush=True)


def main():
    top = Path(__file__).resolve().parents[1]
    work = Path(sys.argv[1]).resolve()
    notices = json.loads((top / "docs/rc1/notices/NOTICE-INPUTS.json").read_text())["base_archive"]
    fetch(notices["url"], work / notices["name"], notices["sha256"])
    for line in (top / "platform/userland/PIN").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        name, version, url, checksum, license_name = line.split("\t")
        fetch(url, work / "upstream" / name / "dl" / url.rsplit("/", 1)[1], checksum)
    pins = {}
    for line in (top / "platform/c/picolibc/PIN").read_text().splitlines():
        if line and not line.startswith("#"):
            row = line.split("\t")
            pins[row[0]] = row[1:]
    version, checksum, url = pins["picolibc"]
    fetch(url, work / "picolibc/dl" / url.rsplit("/", 1)[1], checksum)
    for name in ("meson", "ninja"):
        version, checksum = pins[name]
        metadata = json.load(urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json"))
        matches = [x for x in metadata["urls"] if x["digests"]["sha256"] == checksum
                   and x["filename"].endswith(".whl")]
        if len(matches) != 1:
            raise SystemExit(f"public PyPI metadata does not identify exactly one pinned {name} wheel")
        item = matches[0]
        fetch(item["url"], work / "venv/dl" / item["filename"], checksum)


if __name__ == "__main__":
    main()
