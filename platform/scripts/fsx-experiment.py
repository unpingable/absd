#!/usr/bin/env python3
"""The exclusive-writer tripwire on ABSD (docs/FILESYSTEM.md): imports
fsx-probe as /bin/fsx-probe, boots it as the durable worker (it starts its
own image with a write-capable block copy), prints the captured stream, and
reads the device afterwards with the host's own filesystem reader. An
experiment, not a matrix: it reports and exits 0 if the boot ran."""

import argparse
import importlib.util
import pathlib
import sys

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import absd_fs  # noqa: E402

spec = importlib.util.spec_from_file_location("exec_matrix", here / "exec-matrix.py")
em = importlib.util.module_from_spec(spec)
spec.loader.exec_module(em)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--importer", required=True)
    parser.add_argument("--probe", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--qemu", required=True)
    args = parser.parse_args()
    args.commands, args.expected = args.work, "/dev/null"
    matrix = em.Matrix(args)
    image = matrix.work / "fsx.img"
    with open(image, "wb") as handle:
        handle.truncate(em.IMAGE_BYTES)
    probe = matrix.probe.read_bytes()
    matrix.install(image, [("/bin/fsx-probe", probe)])
    region = absd_fs.fs_region(image, em.DEVICE_SECTORS)
    print(f"FSX HOST before: seq={absd_fs.select(region)['seq']}")
    status, serial, captured = matrix.boot("fsx", 4, image, b"", matrix.probe)
    (matrix.work / "fsx.serial.log").write_bytes(serial)
    print(f"FSX HOST boot status={status}")
    print(captured, end="")
    text = serial.decode(errors="replace")
    for line in text.splitlines():
        if line.startswith(("SPAWN OK", "DURABLE status", "USER ")):
            print(f"  kernel| {line}")
    region = absd_fs.fs_region(image, em.DEVICE_SECTORS)
    try:
        selected = absd_fs.select(region)
    except Exception as error:  # the host reader refuses like mount does
        print(f"FSX HOST after: host reader refuses: {error!r}")
        return
    print(f"FSX HOST after: seq={selected['seq']}")
    tree = absd_fs.tree(region, selected)
    for path in sorted(tree):
        if path.startswith("/bin"):
            continue
        content = absd_fs.content(region, selected, tree[path]) if path in ("/parent", "/child") else None
        shown = "" if content is None else f" len={len(content)} first={chr(content[0]) if content else '-'}"
        print(f"FSX HOST after: {path}{shown}")
    print(f"FSX HOST after: names={sorted(p for p in tree if not p.startswith('/bin'))}")


if __name__ == "__main__":
    main()
