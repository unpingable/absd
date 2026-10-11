#!/usr/bin/env python3
"""Host oracle for the NVMe qualification boots.

Reads the raw image file QEMU backed the namespace with and checks it
independently of the guest: the qualification LBAs hold exactly the
pattern src/nvme_check.rs writes, and every other sector is still zero, so
no write landed anywhere else.

    nvme-image-check.py IMAGE
"""

import sys

SECTOR = 512
HEADER = b"ABSD NVME QUALIFY lba="


def pattern(lba):
    data = bytearray(((lba * 37 + i * 11 + (i >> 8)) & 0xFF) for i in range(SECTOR))
    data[: len(HEADER)] = HEADER
    data[len(HEADER) : len(HEADER) + 20] = f"{lba:020d}".encode()
    return bytes(data)


def main():
    image = open(sys.argv[1], "rb").read()
    if len(image) % SECTOR:
        sys.exit("nvme image: size is not whole sectors")
    sectors = len(image) // SECTOR
    written = {0, 1, 7, 2048, sectors - 1}
    for lba in range(sectors):
        got = image[lba * SECTOR : (lba + 1) * SECTOR]
        want = pattern(lba) if lba in written else bytes(SECTOR)
        if got != want:
            sys.exit(f"nvme image: lba {lba} differs from the expected {'pattern' if lba in written else 'zeros'}")
    print(f"NVME IMAGE OK sectors={sectors} patterned={sorted(written)}")


if __name__ == "__main__":
    main()
