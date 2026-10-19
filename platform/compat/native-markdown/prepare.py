#!/usr/bin/env python3
"""Stage the pinned S3 example; --check verifies every upstream source byte.

Only Cargo.toml's target runtime stanza and the additive lock may differ.
This fixture does not resolve dependencies or rewrite any application source.
"""
import argparse
import hashlib
import os
from pathlib import Path
import tarfile
import tomllib

NAME = "pulldown-cmark-0.13.4"
SHA256 = "e9f068eba8e7071c5f9511831b44f32c740d5adf574e990f946ddb53db2f314e"
ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
                        / "registry/cache/index.crates.io-1949cf8c6b5b557f")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    archive = args.cache / f"{NAME}.crate"
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise SystemExit("upstream archive checksum mismatch")
    stage = args.stage.resolve()
    stanza = ('\n[target.\'cfg(target_os = "absd")\'.dependencies.absd-runtime]\n'
              f'path = {str(ROOT / "runtime")!r}\n').encode()
    with tarfile.open(archive) as package:
        if not args.check:
            stage.mkdir(parents=True, exist_ok=False)
            for target in ("linux", "absd"):
                package.extractall(stage / target, filter="data")
            manifest = stage / "absd" / NAME / "Cargo.toml"
            manifest.write_bytes(manifest.read_bytes() + stanza)
            (stage / "absd" / NAME / "Cargo.lock").write_bytes(
                (ROOT / "pins/native-app" / f"{NAME}.Cargo.lock").read_bytes())
        paths = {member.name for member in package.getmembers() if member.isfile()}
        for target in ("linux", "absd"):
            actual = {str(path.relative_to(stage / target))
                      for path in (stage / target).rglob("*") if path.is_file()}
            if actual != paths:
                raise SystemExit(f"{target} source file set changed")
        checked = 0
        for member in package.getmembers():
            if not member.isfile():
                continue
            original = package.extractfile(member).read()
            if (stage / "linux" / member.name).read_bytes() != original:
                raise SystemExit(f"Linux reference changed: {member.name}")
            expected = original + stanza if member.name == f"{NAME}/Cargo.toml" else original
            if member.name == f"{NAME}/Cargo.lock":
                continue
            if (stage / "absd" / member.name).read_bytes() != expected:
                raise SystemExit(f"ABSD source changed: {member.name}")
            checked += 1
        def packages(data):
            return {(p["name"], p["version"], p.get("source"), p.get("checksum"))
                    for p in tomllib.loads(data.decode())["package"]}
        upstream = packages(package.extractfile(f"{NAME}/Cargo.lock").read())
        lock = (stage / "absd" / NAME / "Cargo.lock").read_bytes()
        pinned = (ROOT / "pins/native-app" / f"{NAME}.Cargo.lock").read_bytes()
        if lock != pinned or not upstream <= packages(lock):
            raise SystemExit("lock differs from the pin or changes an upstream package identity")
    print(f"NATIVE APP SOURCE OK files={checked} upstream-packages={len(upstream)} "
          f"added={len(packages(lock) - upstream)} archive={SHA256}")


if __name__ == "__main__":
    main()
