#!/usr/bin/env python3
"""Host oracle for the AHCI qualification boots.

Reads a raw image file QEMU backed an AHCI disk with and checks it
independently of the guest: the listed LBAs hold exactly the pattern
src/ahci_check.rs writes, and every other sector is still zero, so no write
landed anywhere else.

    ahci-image-check.py IMAGE [--written LIST]

LIST is comma separated LBAs or ranges (`1024-1031`); `last` is the final
sector. No list: the whole image must be zero.
"""

import argparse
import sys

SECTOR = 512
HEADER = b"ABSD AHCI QUALIFY lba="
WRITE_BOOT = "0,1,7,1024-1031,2048,last"


def pattern(lba):
    data = bytearray(((lba * 37 + i * 11 + (i >> 8)) & 0xFF) for i in range(SECTOR))
    data[: len(HEADER)] = HEADER
    data[len(HEADER) : len(HEADER) + 20] = f"{lba:020d}".encode()
    return bytes(data)


def parse(spec, sectors):
    written = set()
    for item in filter(None, spec.split(",")):
        if item == "last":
            written.add(sectors - 1)
        elif "-" in item:
            first, last = (int(part) for part in item.split("-"))
            written.update(range(first, last + 1))
        else:
            written.add(int(item))
    return written


def check(image, spec=""):
    """Returns the patterned LBAs; raises ValueError on any other content."""
    if len(image) % SECTOR:
        raise ValueError("ahci image: size is not whole sectors")
    sectors = len(image) // SECTOR
    written = parse(spec, sectors)
    for lba in range(sectors):
        got = image[lba * SECTOR : (lba + 1) * SECTOR]
        want = pattern(lba) if lba in written else bytes(SECTOR)
        if got != want:
            raise ValueError(
                f"ahci image: lba {lba} differs from the expected {'pattern' if lba in written else 'zeros'}"
            )
    return sorted(written)


def self_test():
    sectors = 4096
    image = bytearray(sectors * SECTOR)
    for lba in parse(WRITE_BOOT, sectors):
        image[lba * SECTOR : (lba + 1) * SECTOR] = pattern(lba)
    assert len(check(bytes(image), WRITE_BOOT)) == 13
    negatives = {
        "stray write": (image[: 3 * SECTOR] + b"x" + image[3 * SECTOR + 1 :], WRITE_BOOT),
        "missing write": (image, WRITE_BOOT + ",9"),
        "wrong lba pattern": (image[:SECTOR] + pattern(0) + image[2 * SECTOR :], WRITE_BOOT),
        "patterned image read as zero": (image, ""),
        "odd size": (image + b"\0", WRITE_BOOT),
    }
    for name, (data, spec) in negatives.items():
        try:
            check(bytes(data), spec)
        except ValueError:
            continue
        raise AssertionError("negative survived: " + name)
    print(f"AHCI IMAGE ORACLE OK controls={len(negatives)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("image", nargs="?")
    parser.add_argument("--written", default="")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.image:
        parser.error("IMAGE is required")
    try:
        written = check(open(args.image, "rb").read(), args.written)
    except ValueError as error:
        sys.exit(str(error))
    print(f"AHCI IMAGE OK patterned={written}")


if __name__ == "__main__":
    main()
