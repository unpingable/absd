#!/usr/bin/env python3
"""Checks the block-probe image on the host after QEMU has exited.

The guest's own readback shares QEMU's process with the writes; this check
does not. It requires the bytes the probe wrote through `block_write_many`
(sectors 64..72), through `block_write` right after them (72..80), a
three-sector `block_write_many` at 96..99, and the single-sector tail
pattern (the last four sectors) to be on the image, and the sectors around
each written span to be still zero.
"""
import sys

SECTOR = 512
MULTI = 8
MULTI_BASE = 64
PARTIAL_BASE = 96
PARTIAL = 3


def pattern(lba, index):
    return ((lba * 31 + index * 7) & 0xff) | 1


def multi_pattern(base, index):
    return pattern(base + index // SECTOR, index % SECTOR) | 0x80


def main(path):
    with open(path, "rb") as handle:
        image = handle.read()
    if len(image) % SECTOR:
        sys.exit(f"block-probe-image-check: {path}: not whole sectors")
    sectors = len(image) // SECTOR
    failures = []

    def expect(name, lba, expected):
        actual = image[lba * SECTOR:(lba + 1) * SECTOR]
        if actual != expected:
            failures.append(f"{name}: sector {lba} differs")

    for span, base in (("block_write_many", MULTI_BASE), ("block_write", MULTI_BASE + MULTI)):
        for index in range(MULTI):
            expected = bytes(multi_pattern(base, index * SECTOR + offset) for offset in range(SECTOR))
            expect(span, base + index, expected)
    for index in range(PARTIAL):
        expected = bytes(multi_pattern(PARTIAL_BASE, index * SECTOR + offset) for offset in range(SECTOR))
        expect("partial block_write_many", PARTIAL_BASE + index, expected)
    for lba in range(sectors - 4, sectors):
        expect("tail", lba, bytes(pattern(lba, offset) for offset in range(SECTOR)))
    for lba in (MULTI_BASE - 1, MULTI_BASE + 2 * MULTI, PARTIAL_BASE - 1, PARTIAL_BASE + PARTIAL, sectors - 5):
        expect("untouched", lba, bytes(SECTOR))
    if failures:
        sys.exit("block-probe-image-check: " + "; ".join(failures))
    print(f"block-probe-image-check: multi-sector and single-sector spans present on {path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: block-probe-image-check.py IMAGE")
    main(sys.argv[1])
