#!/usr/bin/env python3
"""Compare the current catalog with the existing installer's actual --print.

Post-kit only: requires already-built userland products and their original
source/kit/POSIX receipts. Does not build, install, re-pin or accept a guest.
"""
from pathlib import Path
import os
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import c_kit_source as source

FIELDS = ("NAME", "UPSTREAM", "SOURCE", "BUILD", "GATED_SHA256", "SHA256", "BYTES")


def compare_rows(expected, printed):
    actual = [line.split("\t") for line in printed.splitlines() if line and not line.startswith("#")]
    if len(actual) != len(expected):
        raise source.Refused(f"PORTS.tsv rows={len(expected)}, installer rows={len(actual)}")
    for wanted, got in zip(expected, actual):
        if len(wanted) != 7 or len(got) != 7:
            raise source.Refused("PORTS.tsv or installer row does not have seven fields")
        for field, left, right in zip(FIELDS, wanted, got):
            if left != right:
                raise source.Refused(f"{wanted[0]} {field} catalog={left} installer={right}")
    return len(actual)


def check(root):
    expected = list(source.rows(root))
    out = Path(os.environ.get("ABSD_USERLAND_BUILD", root.parent / "userland-build"))
    # --print normally builds absent inputs. This boundary is explicitly
    # post-build: never turn a missing product into new preflight work.
    for row in expected:
        if not (out / row[3]).is_file():
            raise source.Refused(f"post-kit product missing: {out / row[3]}")
    kit = Path(os.environ.get("ABSD_CKIT_BUILD", root.parent / "ckit-build")) / "kit"
    posix = Path(os.environ.get("ABSD_CPORTS_BUILD", root.parent / "cports-build")) / "lib/libabsd-posix.a"
    identity = source.kit_identity(root, kit)
    source.verify(root, identity, out, posix)
    result = subprocess.run(["sh", str(root / "scripts/install-userland-ports.sh"), "--print"],
                            env=dict(os.environ, ABSD_PORTS_REQUIRE_BUILT="1"),
                            capture_output=True, text=True)
    if result.returncode:
        raise source.Refused("installer --print failed: " + result.stderr.strip())
    return compare_rows(expected, result.stdout)


def main():
    if len(sys.argv) != 2:
        print("usage: check-post-kit.py ROOT", file=sys.stderr)
        return 2
    try:
        count = check(Path(sys.argv[1]).resolve())
    except (source.Refused, OSError, ValueError) as error:
        print(f"ABSD POST-KIT REFUSED {error}", file=sys.stderr)
        return 2
    print(f"ABSD POST-KIT OK catalog=installer-output ports={count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
