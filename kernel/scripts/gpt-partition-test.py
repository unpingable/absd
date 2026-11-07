#!/usr/bin/env python3
"""QEMU qualification of `block-partition=GUID` (coordination record #123;
docs/hardware/GPT-PARTITION.md).

Every boot attaches QEMU's `ich9-ahci` with one `ide-hd` disk, serial
`absd`, on a disposable 128 MiB raw image. The partition table is written
by `sgdisk` (GPT fdisk) with fixed disk and partition GUIDs, so images are
reproducible: a protective MBR, primary and backup GPT, partition 1 an EFI
System Partition (filled by this script with a deterministic non-zero
pattern), partition 2 the ABSD partition (fixed unique GUID, the ABSD type
7AF614A7-2C5B-4EBA-B8F6-217AEC90357A). The negative variants start from
that image; this script's own GPT code applies only the corruption sgdisk
cannot express. The cases, in order:

  read                ahci-disk=absd block-partition=GUID, the qualification
                      boot: block_info is the partition's length, its LBA 0
                      and last LBA read the host-seeded sectors, requests at
                      the length are refused, writes and flush refused
  write-selected      the same with ahci-write=absd: writable only because
                      the backend was selected writable; nothing written
  wrong-guid          a GUID no entry carries: not-found, no device
  wrong-type          the GUID on a Linux-type partition (sgdisk): wrong-type
  header-crc          primary header CRC corrupted
  entries-crc         a primary entry changed without its array CRC
  no-mbr              no protective MBR
  overlap             the ESP's entry extended into the ABSD partition
  duplicate           a second entry with the ABSD GUID
  unselected-overlap  two other partitions overlapping each other
  unselected-inverted another partition with LastLBA < FirstLBA
  unselected-duplicate two other partitions sharing a unique GUID
  hybrid-mbr          a FAT32 MBR record beside the 0xEE one
  mbr-zero-size       the 0xEE record's size zero
  header-reserved     the primary header's reserved word nonzero (resealed)
  backup-overlap      both headers CRC-valid, LastUsableLBA the last sector
  backup-header-crc   backup header CRC corrupted
  backup-entries-crc  a backup entry changed without its array CRC
  backup-disagree     backup header CRC-valid, its LastUsableLBA one lower
  backup-disk-guid    backup header CRC-valid, another disk GUID
  backup-misplaced    a whole backup header one sector early, nothing at
                      AlternateLBA
  backup-array-gap    backup array one sector lower, its header pointing
                      at it (CRC-valid, not adjacent)
  backup-missing      backup array and header all zero
  backup-same-crc     the backup array's ABSD FirstLBA changed, four name
                      bytes solved to keep its CRC32
  backup-header-size  a 96-byte backup header beside a 92-byte primary
  malformed           block-partition=not-a-guid: refused before any
                      controller
  durable             the kernel's block-probe workload on a 4096-sector
                      ABSD partition, selected by ahci-write

Every refusal leaves no device. After every boot the host checks that the
proving read's digest is the image's own LBA 0, that the ESP is
byte-identical to its pattern, that every byte outside the ABSD partition
(both GPTs included) is unchanged, and that the partition itself is
unchanged or holds exactly block-probe's bytes at partition-relative LBAs
(scripts/block-probe-image-check.py on the extracted partition).

`--platform-iso PATH` adds a `platform` case: a platform durable ISO built
elsewhere whose kernel line carries `ahci-write=absd block-partition=GUID`;
afterwards the ABSD layout descriptor (ABSDLAY1 v3) must sit at the
partition's first sector with device_sectors = the partition's length
(`--absd-image` names the platform repository's scripts/absd_image.py for
the full v3 table check; it is imported read-only).

`--self-test` (no QEMU; needs sgdisk) builds every image and requires
`sgdisk --verify`, this script's independent two-copy GPT reader and, with
`--rust`, the kernel's own parser (`--cargo`, default `cargo`, runs
gpt::tests::external_image; CARGO_TARGET_DIR is honoured)
to agree with each variant's expected verdict; then it judges synthetic
logs and runs the host image checks against simulated outcomes, each with
negative controls.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shlex
import struct
import shutil
import subprocess
import tempfile
import zlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SECTOR = 512
DISK_SECTORS = 262144                      # 128 MiB
ESP_FIRST, ESP_SECTORS = 2048, 65536       # 1 MiB .. 33 MiB
ABSD_FIRST = 67584                         # 33 MiB, 1 MiB aligned
ABSD_SECTORS = 131072                      # 64 MiB
# block-probe's workload scans the whole device twice; the durable case
# uses a 2 MiB partition so its expected output (sectors=4096) and run time
# are the existing block-probe-test's.
DURABLE_SECTORS = 4096
ENTRIES, ENTRY_BYTES = 128, 128
ARRAY_SECTORS = ENTRIES * ENTRY_BYTES // SECTOR
FIRST_USABLE = 2 + ARRAY_SECTORS
LAST_USABLE = DISK_SECTORS - 1 - ARRAY_SECTORS - 1

ESP_TYPE = 'C12A7328-F81F-11D2-BA4B-00A0C93EC93B'
ESP_GUID = '0f6a2e4c-8b1d-4f3a-a5c7-9e2b4d6f8a1c'
# The ABSD partition type (owner decision; src/gpt.rs ABSD_TYPE).
ABSD_TYPE = '7AF614A7-2C5B-4EBA-B8F6-217AEC90357A'
# Linux filesystem data: the wrong-type case's ABSD partition.
LINUX_TYPE = '0FC63DAF-8483-4772-8E79-3D69D8477DE4'
ABSD_GUID = '5a8b3c2d-1e4f-4a6b-8c9d-0e1f2a3b4c5d'
WRONG_GUID = '5a8b3c2d-1e4f-4a6b-8c9d-0e1f2a3b4c5e'
DISK_GUID = '3e7d9a1b-2c4f-4b6e-8a0d-1f3c5e7a9b2d'
# The kernel's rule (src/block.rs `publish`): a partition is writable
# exactly when the backend was selected writable. False was the first,
# read-only step's rule.
PARTITION_WRITES = True


def guid_bytes(text):
    """Canonical text to on-disk bytes: first three fields little-endian."""
    parts = text.split('-')
    assert [len(part) for part in parts] == [8, 4, 4, 4, 12], text
    return (int(parts[0], 16).to_bytes(4, 'little') + int(parts[1], 16).to_bytes(2, 'little')
            + int(parts[2], 16).to_bytes(2, 'little') + bytes.fromhex(parts[3] + parts[4]))


def fnv1a(data):
    value = 0xcbf29ce484222325
    for byte in data:
        value = ((value ^ byte) * 0x100000001b3) & 0xffffffffffffffff
    return value


FILLER = bytes(((index * 7) & 0xff) | 1 for index in range(SECTOR))


def esp_sector(lba):
    """The ESP's pattern: non-zero, distinct per sector."""
    prefix = b'ABSD GPT TEST ESP lba=%012d\n' % lba
    return prefix + FILLER[len(prefix):]


def marker(text, fill):
    data = text.encode()
    return data + bytes([fill]) * (SECTOR - len(data))


FIRST_SEED = marker('ABSD GPT PARTITION FIRST SECTOR', 0xa5)
LAST_SEED = marker('ABSD GPT PARTITION LAST SECTOR', 0x5a)
AFTER_SEED = marker('ABSD GPT SENTINEL AFTER THE PARTITION', 0x3c)


def sgdisk_path():
    found = shutil.which('sgdisk') or ('/usr/sbin/sgdisk' if Path('/usr/sbin/sgdisk').is_file() else None)
    if found is None:
        raise SystemExit('gpt-partition-test: sgdisk (GPT fdisk) is required to build the images')
    return found


def sgdisk(*arguments):
    return subprocess.run([sgdisk_path(), *arguments], check=True, capture_output=True, text=True).stdout


def sgdisk_verify(path):
    """True when `sgdisk --verify` finds no problems. sgdisk exits 0 even
    then, and falls back to a good copy with a caution, so any caution,
    warning, problem or corruption notice counts against the table."""
    done = subprocess.run([sgdisk_path(), '--verify', str(path)], capture_output=True, text=True)
    out = done.stdout + done.stderr
    return (done.returncode == 0 and 'No problems found' in out
            and not any(word in out for word in ('Caution', 'Warning', 'Problem', 'corrupt', 'CRC')))


# Negative variants: sgdisk builds the standard table, then this script's
# own GPT code applies the one corruption sgdisk cannot express.
VARIANTS = {
    # name: the kernel's refusal, or None for a table the kernel serves
    'standard': None,
    'wrong-type': 'wrong-type',
    'header-crc': 'header-crc-mismatch',
    'entries-crc': 'entries-crc-mismatch',
    'no-mbr': 'no-protective-mbr',
    'overlap': 'entry-overlap a=0 b=1',
    'duplicate': 'duplicate-guid a=1 b=2',
    'unselected-overlap': 'entry-overlap a=2 b=3',
    'unselected-inverted': 'entry-range index=2',
    'unselected-duplicate': 'duplicate-guid a=2 b=3',
    'hybrid-mbr': 'hybrid-mbr',
    'mbr-zero-size': 'bad-protective-mbr field=size',
    'header-reserved': 'bad-header field=reserved',
    'backup-overlap': 'bad-header field=last-usable',
    'backup-header-crc': 'backup-header-crc-mismatch',
    'backup-entries-crc': 'backup-entries-crc-mismatch',
    'backup-disagree': 'bad-backup field=last-usable',
    'backup-disk-guid': 'bad-backup field=disk-guid',
    'backup-misplaced': 'bad-backup field=signature',
    'backup-array-gap': 'bad-backup field=entries-lba',
    'backup-missing': 'bad-backup field=signature',
    'backup-same-crc': 'backup-entries-differ',
    'backup-header-size': 'bad-backup field=header-size',
}
# Variants whose GPT is structurally whole (both copies valid and equal):
# the defect is in the selection, which only the kernel judges.
# Of those, the ones whose table breaks a whole-table rule.
TABLE_DEFECTS = {'overlap', 'duplicate', 'unselected-overlap', 'unselected-inverted', 'unselected-duplicate'}
STRUCTURALLY_VALID = {'standard', 'wrong-type', 'overlap', 'duplicate', 'unselected-overlap',
                      'unselected-inverted', 'unselected-duplicate'}
# Variants `sgdisk --verify` (1.0.10) passes as clean. Beyond the two good
# tables, sgdisk checks neither unique-GUID duplicates, nor a usable range
# reaching the backup GPT, nor the protective record's size, the headers'
# reserved word or a header-size difference between the copies, nor the
# backup array's bytes once its CRC32 matches; the kernel refuses all of
# them.
SGDISK_CLEAN = {'standard', 'wrong-type', 'duplicate', 'backup-overlap', 'unselected-duplicate',
                'mbr-zero-size', 'header-reserved', 'backup-same-crc', 'backup-header-size'}
PRIMARY_LBA, BACKUP_LBA = 1, DISK_SECTORS - 1
BACKUP_ARRAY = BACKUP_LBA - ARRAY_SECTORS


OTHER_GUIDS = ('aaaaaaaa-0000-4000-8000-000000000001', 'bbbbbbbb-0000-4000-8000-000000000002')


def crc_patch(data, at, want):
    """The four bytes at `at` that make zlib.crc32(data) == want (CRC32 is
    affine over GF(2): solve for the 32 patch bits)."""
    base = bytearray(data)
    base[at:at + 4] = bytes(4)
    zero = zlib.crc32(bytes(base))
    rows = []
    for bit in range(32):
        probe = bytearray(base)
        probe[at + bit // 8] ^= 1 << (bit % 8)
        rows.append([zlib.crc32(bytes(probe)) ^ zero, 1 << bit])
    target = [want ^ zero, 0]
    for pivot in range(32):
        mask = 1 << pivot
        found = next((row for row in range(pivot, 32) if rows[row][0] & mask), None)
        if found is None:
            continue
        rows[pivot], rows[found] = rows[found], rows[pivot]
        value, bits = rows[pivot]
        for row in range(32):
            if row != pivot and rows[row][0] & mask:
                rows[row][0] ^= value
                rows[row][1] ^= bits
        if target[0] & mask:
            target[0] ^= value
            target[1] ^= bits
    assert target[0] == 0, 'no CRC patch'
    return struct.pack('<I', target[1])


def reseal(image, lba):
    """Recomputes the CRC32 of the header at `lba` (92 bytes)."""
    offset = lba * SECTOR
    size = struct.unpack_from('<I', image, offset + 12)[0]
    image[offset + 16:offset + 20] = bytes(4)
    image[offset + 16:offset + 20] = struct.pack('<I', zlib.crc32(bytes(image[offset:offset + size])))


def put64(image, offset, value):
    image[offset:offset + 8] = struct.pack('<Q', value)


def rewrite_arrays(image, change):
    """Applies `change(array)` to both entry arrays and reseals both headers
    with the new array CRC: a consistent table sgdisk would not write."""
    for header, array_lba in ((PRIMARY_LBA, 2), (BACKUP_LBA, BACKUP_ARRAY)):
        offset = array_lba * SECTOR
        array = bytearray(image[offset:offset + ENTRIES * ENTRY_BYTES])
        change(array)
        image[offset:offset + len(array)] = array
        image[header * SECTOR + 88:header * SECTOR + 92] = struct.pack('<I', zlib.crc32(bytes(array)))
        reseal(image, header)


def corrupt(image, variant, layout):
    primary, backup = PRIMARY_LBA * SECTOR, BACKUP_LBA * SECTOR
    if variant == 'header-crc':
        image[primary + 16] ^= 0xff
    elif variant == 'entries-crc':
        image[2 * SECTOR + ENTRY_BYTES + 60] ^= 1          # entry 2's name, primary only
    elif variant == 'no-mbr':
        image[510:512] = bytes(2)
    elif variant == 'overlap':
        rewrite_arrays(image, lambda array: put64(array, 40, ABSD_FIRST))   # the ESP's LastLBA
    elif variant == 'duplicate':
        def duplicate(array):
            array[2 * ENTRY_BYTES:2 * ENTRY_BYTES + 48] = (
                guid_bytes(ABSD_TYPE) + guid_bytes(ABSD_GUID) + struct.pack('<QQ', layout.end + 16, layout.end + 31))
        rewrite_arrays(image, duplicate)
    elif variant == 'backup-overlap':
        for header in (primary, backup):
            put64(image, header + 48, DISK_SECTORS - 1)
            reseal(image, header // SECTOR)
    elif variant == 'backup-header-crc':
        image[backup + 16] ^= 0xff
    elif variant == 'backup-entries-crc':
        image[BACKUP_ARRAY * SECTOR + ENTRY_BYTES + 60] ^= 1
    elif variant == 'backup-disagree':
        put64(image, backup + 48, LAST_USABLE - 1)
        reseal(image, BACKUP_LBA)
    elif variant == 'backup-disk-guid':
        image[backup + 56] ^= 1
        reseal(image, BACKUP_LBA)
    elif variant == 'backup-misplaced':
        # A whole backup header one sector early, nothing at AlternateLBA.
        image[backup - SECTOR:backup] = image[backup:backup + SECTOR]
        image[backup:backup + SECTOR] = bytes(SECTOR)
    elif variant == 'backup-array-gap':
        # The array one sector lower, the header pointing at it: CRC-valid,
        # self-consistent, not adjacent.
        offset = BACKUP_ARRAY * SECTOR
        array = bytes(image[offset:offset + ENTRIES * ENTRY_BYTES])
        image[offset:offset + len(array)] = bytes(len(array))
        image[offset - SECTOR:offset - SECTOR + len(array)] = array
        put64(image, backup + 72, BACKUP_ARRAY - 1)
        reseal(image, BACKUP_LBA)
    elif variant in ('unselected-overlap', 'unselected-inverted', 'unselected-duplicate'):
        # Two more Linux partitions after the ABSD one: overlapping each
        # other, the first inverted, or sharing a unique GUID.
        start = layout.end + 1000
        ranges = {'unselected-overlap': ((start, start + 99), (start + 50, start + 149)),
                  'unselected-inverted': ((start + 99, start), (start + 200, start + 299)),
                  'unselected-duplicate': ((start, start + 99), (start + 100, start + 199))}[variant]
        uniques = [OTHER_GUIDS[0], OTHER_GUIDS[0 if variant == 'unselected-duplicate' else 1]]

        def extra(array):
            for slot, ((first, last), unique) in enumerate(zip(ranges, uniques), start=2):
                array[slot * ENTRY_BYTES:slot * ENTRY_BYTES + 48] = (
                    guid_bytes(LINUX_TYPE) + guid_bytes(unique) + struct.pack('<QQ', first, last))
        rewrite_arrays(image, extra)
    elif variant == 'hybrid-mbr':
        # A second MBR record: a FAT32 partition over the ESP.
        image[446 + 16:446 + 32] = bytes([0, 0, 0, 0, 0x0c, 0, 0, 0]) + struct.pack('<II', ESP_FIRST, ESP_SECTORS)
    elif variant == 'mbr-zero-size':
        image[446 + 12:446 + 16] = bytes(4)
    elif variant == 'header-reserved':
        image[primary + 20] = 1
        reseal(image, PRIMARY_LBA)
    elif variant == 'backup-header-size':
        # A 96-byte backup header (the extra word zero, inside its CRC).
        image[backup + 12:backup + 16] = struct.pack('<I', 96)
        reseal(image, BACKUP_LBA)
    elif variant == 'backup-same-crc':
        # The review's forgery: the ABSD entry's FirstLBA changed in the
        # backup array, four name bytes chosen to keep its CRC32.
        offset = BACKUP_ARRAY * SECTOR
        array = bytearray(image[offset:offset + ENTRIES * ENTRY_BYTES])
        want = zlib.crc32(bytes(array))
        put64(array, ENTRY_BYTES + 32, ABSD_FIRST + 1)
        at = ENTRY_BYTES + 56
        array[at:at + 4] = crc_patch(bytes(array), at, want)
        assert zlib.crc32(bytes(array)) == want
        image[offset:offset + len(array)] = array
    elif variant == 'backup-missing':
        image[BACKUP_ARRAY * SECTOR:] = bytes(DISK_SECTORS * SECTOR - BACKUP_ARRAY * SECTOR)
    elif variant not in ('standard', 'wrong-type'):
        raise ValueError(f'unknown variant {variant}')


class Layout:
    """One test image: which variant, how large the ABSD partition is, and
    whether its first and last sectors are seeded."""

    def __init__(self, variant='standard', absd_sectors=ABSD_SECTORS, seed=True):
        assert variant in VARIANTS, variant
        self.variant, self.absd_sectors, self.seed = variant, absd_sectors, seed

    @property
    def end(self):
        return ABSD_FIRST + self.absd_sectors

    def sgdisk_arguments(self, path):
        kind = LINUX_TYPE if self.variant == 'wrong-type' else ABSD_TYPE
        return ['--clear', '--disk-guid', DISK_GUID,
                '--new', f'1:{ESP_FIRST}:{ESP_FIRST + ESP_SECTORS - 1}', '--typecode', f'1:{ESP_TYPE}',
                '--partition-guid', f'1:{ESP_GUID}', '--change-name', '1:EFI system partition',
                '--new', f'2:{ABSD_FIRST}:{self.end - 1}', '--typecode', f'2:{kind}',
                '--partition-guid', f'2:{ABSD_GUID}', '--change-name', '2:ABSD', str(path)]

    def write(self, path):
        with open(path, 'wb') as image:
            image.truncate(DISK_SECTORS * SECTOR)
        sgdisk(*self.sgdisk_arguments(path))
        with open(path, 'r+b') as image:
            image.seek(ESP_FIRST * SECTOR)
            image.write(b''.join(esp_sector(lba) for lba in range(ESP_FIRST, ESP_FIRST + ESP_SECTORS)))
            data = {self.end: AFTER_SEED}
            if self.seed:
                data.update({ABSD_FIRST: FIRST_SEED, self.end - 1: LAST_SEED})
            for lba, sector in sorted(data.items()):
                image.seek(lba * SECTOR)
                image.write(sector)
        if self.variant not in ('standard', 'wrong-type'):
            image = bytearray(Path(path).read_bytes())
            corrupt(image, self.variant, self)
            Path(path).write_bytes(image)


def read_gpt(image):
    """An independent reader of both copies of the image's GPT, with the
    kernel's rules: returns the entries [(type, unique, first, last)] or
    raises ValueError."""
    def sector(lba):
        return image[lba * SECTOR:(lba + 1) * SECTOR]
    last = len(image) // SECTOR - 1
    mbr = sector(0)
    records = [mbr[446 + 16 * index:462 + 16 * index] for index in range(4)]
    protective = [record for record in records if record[4] == 0xee]
    if mbr[510:512] != b'\x55\xaa' or len(protective) != 1:
        raise ValueError('protective MBR')
    if sum(1 for record in records if any(record)) != 1:
        raise ValueError('hybrid MBR')
    if struct.unpack_from('<II', protective[0], 8) != (1, min(last, 0xffffffff)):
        raise ValueError('protective record extent')
    copies = []
    for lba, mine, other in ((1, 1, last), (last, last, 1)):
        header = sector(lba)
        size = struct.unpack_from('<I', header, 12)[0]
        stored = struct.unpack_from('<I', header, 16)[0]
        if header[:8] != b'EFI PART' or struct.unpack_from('<I', header, 8)[0] != 0x00010000 \
                or not 92 <= size <= SECTOR:
            raise ValueError(f'header at {lba}')
        if zlib.crc32(header[:16] + bytes(4) + header[20:size]) != stored:
            raise ValueError(f'header crc at {lba}')
        if header[20:24] != bytes(4) or any(header[size:]):
            raise ValueError(f'reserved bytes at {lba}')
        my_lba, alternate, first_usable, last_usable = struct.unpack_from('<QQQQ', header, 24)
        disk_guid = header[56:72]
        array_lba, count, entry_bytes, array_crc = struct.unpack_from('<QIII', header, 72)
        array_sectors = -(-count * entry_bytes // SECTOR)
        if (my_lba, alternate) != (mine, other):
            raise ValueError(f'self/alternate LBA at {lba}')
        if lba == 1 and not (array_lba >= 2 and array_lba + array_sectors <= first_usable):
            raise ValueError('primary array placement')
        if lba == last and array_lba + array_sectors != last:
            raise ValueError('backup array not adjacent')
        if not first_usable <= last_usable < last - array_sectors:
            raise ValueError(f'usable range at {lba}')
        array = image[array_lba * SECTOR:array_lba * SECTOR + count * entry_bytes]
        if zlib.crc32(array) != array_crc:
            raise ValueError(f'array crc for header {lba}')
        copies.append(((first_usable, last_usable, bytes(disk_guid), count, entry_bytes, array_crc, size), array))
    if copies[0][0] != copies[1][0]:
        raise ValueError('backup header disagrees with the primary')
    if copies[0][1] != copies[1][1]:
        raise ValueError('backup entries differ')
    array, entry_bytes = copies[0][1], copies[0][0][4]
    entries = []
    for index in range(copies[0][0][3]):
        entry = array[index * entry_bytes:(index + 1) * entry_bytes]
        if entry[:16] != bytes(16):
            entries.append((bytes(entry[:16]), bytes(entry[16:32])) + struct.unpack_from('<QQ', entry, 32))
    return entries


def table_defect(entries, image):
    """The kernel's whole-table rules over every used entry, independently:
    a nonzero unique GUID, a range inside the usable range, no duplicate
    unique GUID, no two ranges intersecting. None, or the defect."""
    first_usable, last_usable = struct.unpack_from('<QQ', image, SECTOR + 40)
    for index, (_, unique, first, last) in enumerate(entries):
        if unique == bytes(16):
            return 'zero guid'
        if not first_usable <= first <= last <= last_usable:
            return f'range {index}'
    uniques = [entry[1] for entry in entries]
    if len(set(uniques)) != len(uniques):
        return 'duplicate'
    spans = sorted((entry[2], entry[3]) for entry in entries)
    if any(earlier[1] >= later[0] for earlier, later in zip(spans, spans[1:])):
        return 'overlap'
    return None


# ---------------------------------------------------------------- the boots

def literal(line):
    return (re.escape(line), line)


# The backends' proving read of the whole disk's LBA 0. Its digest is
# judged against the image's own LBA 0 after the boot (`check_proving_read`):
# sgdisk writes that sector, so it is not a constant here.
PROVING_READ = (r'AHCI READ OK lba=0 fnv1a=0x[0-9a-f]{16}', 'AHCI READ OK lba=0 fnv1a=0x0123456789abcdef')


def check_proving_read(log, image):
    want = f'AHCI READ OK lba=0 fnv1a=0x{fnv1a(image[:SECTOR]):016x}'
    found = [line for line in log.splitlines() if line.startswith('AHCI READ OK lba=0 ')]
    if found and found != [want]:
        raise ValueError(f'proving read {found} is not the image LBA 0 ({want})')


def disk_line(access):
    return literal(f'AHCI DISK lba_bytes=512 sectors={DISK_SECTORS} access={access}')


RO = 'read-only'
RW = 'read-write (selected by ahci-write)'
WRITABLE = 'read-write (selected writable by ahci-write)'
NO_DEVICE = literal('block: no device')
QUALIFY_NO_DEVICE = literal('BLOCK PARTITION QUALIFY FAILED no device lba=0')


def partition_line(sectors):
    return literal(f'BLOCK PARTITION guid={ABSD_GUID} first_lba={ABSD_FIRST} sectors={sectors} '
                   f'(of device_sectors={DISK_SECTORS})')


def served(layout, access, partition_access, backend_access, fence):
    return [disk_line(access), PROVING_READ,
            partition_line(layout.absd_sectors), literal(f'BLOCK PARTITION access={partition_access}'),
            literal(f'BLOCK DEVICE OK sectors={layout.absd_sectors}'),
            literal(f'BLOCK BACKEND ahci access={backend_access}'),
            literal(f'STORAGE FENCE fence=none reason={fence}')]


def qualified(layout):
    sectors = layout.absd_sectors
    return [literal(f'BLOCK PARTITION READ OK lba=0 fnv1a=0x{fnv1a(FIRST_SEED):016x}'),
            literal(f'BLOCK PARTITION READ OK lba={sectors - 1} fnv1a=0x{fnv1a(LAST_SEED):016x}'),
            literal(f'BLOCK PARTITION BOUNDS OK lba={sectors} kernel=OutOfRange device_commands=unchanged')]


def refused(layout, reason):
    return [disk_line(RO), PROVING_READ,
            literal(f'BLOCK PARTITION REFUSED {reason}'), NO_DEVICE, QUALIFY_NO_DEVICE]


SERVED_FORBIDDEN = ['BLOCK PARTITION REFUSED', 'BLOCK PARTITION QUALIFY FAILED', 'AHCI UNAVAILABLE',
                    'RETIRED', 'WITHDRAWN', 'block: no device']
REFUSED_FORBIDDEN = ['BLOCK PARTITION guid=', 'BLOCK DEVICE OK', 'BLOCK BACKEND', 'BLOCK PARTITION READ OK']
DURABLE_LINE = (r'DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 block_reads=[1-9][0-9]* '
                r'block_writes=[1-9][0-9]* block_flushes=3 block_errors=[0-9]* block_waits=[0-9]* '
                r'block_irqs=[0-9]* ticks=[0-9]*',
                'DURABLE status=0 frames=0 processes=0 cells=0 pipes=0 block_reads=4123 block_writes=40 '
                'block_flushes=3 block_errors=9 block_waits=0 block_irqs=0 ticks=12')


def case_table():
    """name: (ISO name, layout, exit, required lines in order, forbidden
    substrings, the host's image check)."""
    standard = Layout()
    read_only = 'read-only' if PARTITION_WRITES else 'read-only (prototype)'
    read_only_served = qualified(standard) + [literal('BLOCK PARTITION READ ONLY OK')]
    table = {
        'read': ('read', standard, 3,
                 served(standard, RO, read_only, 'read-only', 'read_only') + read_only_served,
                 SERVED_FORBIDDEN, 'unchanged'),
        'write-selected': ('write-selected', standard, 3,
                           served(standard, RW, WRITABLE, 'read-write', 'not_declared') + qualified(standard)
                           if PARTITION_WRITES else
                           served(standard, RW, read_only, 'read-only', 'read_only') + read_only_served,
                           SERVED_FORBIDDEN + (['BLOCK PARTITION READ ONLY OK'] if PARTITION_WRITES else []),
                           'unchanged'),
        'wrong-guid': ('wrong-guid', standard, 7, refused(standard, 'not-found'), REFUSED_FORBIDDEN, 'unchanged'),
    }
    for variant, reason in VARIANTS.items():
        if reason is None:
            continue
        layout = Layout(variant)
        table[variant] = ('read', layout, 7, refused(layout, reason), REFUSED_FORBIDDEN, 'unchanged')
    table['malformed'] = ('malformed', standard, 7,
                          [literal('BLOCK PARTITION REFUSED malformed-guid'), NO_DEVICE, QUALIFY_NO_DEVICE],
                          REFUSED_FORBIDDEN + ['AHCI DISK', 'AHCI CONTROLLER', 'AHCI READ'], 'unchanged')
    if not PARTITION_WRITES:
        return table
    durable = Layout(absd_sectors=DURABLE_SECTORS, seed=False)
    table['durable'] = ('durable', durable, 3,
                        served(durable, RW, WRITABLE, 'read-write', 'not_declared')
                        # The worker's own lines (BLOCK PROBE step=0 sectors=...) arrive
                        # hex-encoded in EXTERNAL OUTPUT chunks; check-external-output.py
                        # decodes and checks them after the boot.
                        + [DURABLE_LINE,
                           literal('DURABLE WORKLOAD OK'), literal('ABSD BOOT OK')],
                        SERVED_FORBIDDEN + ['DURABLE WORKLOAD FAILED'], 'durable')
    return table


CASES = case_table()
ALWAYS_FORBIDDEN = ['PANIC', 'KERNEL FAULT']


def platform_case(exit_status):
    layout = Layout(seed=False)
    return ('platform', layout, exit_status,
            [disk_line(RW), partition_line(layout.absd_sectors),
             literal(f'BLOCK PARTITION access={WRITABLE}'),
             literal(f'BLOCK DEVICE OK sectors={layout.absd_sectors}'),
             literal('BLOCK BACKEND ahci access=read-write')],
            SERVED_FORBIDDEN, 'platform')


def judge(name, case, log, status):
    _, _, want, required, forbidden, _ = case
    if status != want:
        raise ValueError(f'{name}: exit {status}, expected {want}')
    lines = log.splitlines()
    positions = []
    for pattern, _ in required:
        found = [index for index, line in enumerate(lines) if re.fullmatch(pattern, line)]
        if len(found) != 1:
            raise ValueError(f'{name}: expected exactly one line matching {pattern!r}, found {len(found)}')
        positions.append(found[0])
    if positions != sorted(positions):
        raise ValueError(f'{name}: required lines out of order')
    for token in forbidden + ALWAYS_FORBIDDEN:
        if token in log:
            raise ValueError(f'{name}: unexpected {token!r}')


def sample(case):
    return '\n'.join(['ABSD KERNEL BOOT'] + [example for _, example in case[3]] + [''])


def controls(name, case, log, status):
    """Negative controls on a passing log: each must be rejected."""
    _, _, _, required, forbidden, _ = case
    negatives = {'wrong exit': (log, status ^ 4)}
    lines = log.splitlines()
    for pattern, _ in required:
        line = next(line for line in lines if re.fullmatch(pattern, line))
        negatives['missing ' + line] = (log.replace(line + '\n', '', 1), status)
        negatives['repeated ' + line] = (log + line + '\n', status)
    first = next(line for line in lines if re.fullmatch(required[0][0], line))
    last = next(line for line in lines if re.fullmatch(required[-1][0], line))
    if first != last:
        negatives['order'] = (log.replace(first, '\0').replace(last, first).replace('\0', last), status)
    for token in forbidden + ALWAYS_FORBIDDEN:
        negatives['forbidden ' + token] = (log + token + '\n', status)
    # A digest of the wrong sector (the whole disk's LBA 0, or the sector
    # before the partition) must not pass for the partition's.
    for wrong in (fnv1a(b'\0' * SECTOR), fnv1a(esp_sector(ABSD_FIRST - 1))):
        for good in (fnv1a(FIRST_SEED), fnv1a(LAST_SEED)):
            token = f'fnv1a=0x{good:016x}'
            if token in log:
                negatives[f'digest {wrong:x}'] = (log.replace(token, f'fnv1a=0x{wrong:016x}'), status)
    for label, (negative, code) in negatives.items():
        try:
            judge(name, case, negative, code)
        except ValueError:
            continue
        raise ValueError(f'{name}: negative survived: {label}')
    return len(negatives)


# --------------------------------------------------------- the image checks

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def regions(image, layout):
    """The image bytes before, inside, and after the ABSD partition."""
    return (image[:ABSD_FIRST * SECTOR], image[ABSD_FIRST * SECTOR:layout.end * SECTOR],
            image[layout.end * SECTOR:])


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check_esp(image):
    for lba in range(ESP_FIRST, ESP_FIRST + ESP_SECTORS):
        if image[lba * SECTOR:(lba + 1) * SECTOR] != esp_sector(lba):
            raise ValueError(f'ESP sector {lba} changed')


def block_probe_check(partition):
    """scripts/block-probe-image-check.py over the extracted partition."""
    checker = load(HERE / 'block-probe-image-check.py', 'block_probe_image_check')
    with tempfile.NamedTemporaryFile(suffix='.img') as extracted:
        extracted.write(partition)
        extracted.flush()
        try:
            checker.main(extracted.name)
        except SystemExit as error:
            raise ValueError(f'partition content: {error}') from None


def layout_descriptor(sector, device_sectors, absd_image=None):
    """ABSDLAY1 v3 at the partition's first sector, written for the
    partition's length. With the platform's absd_image.py the full v3 table
    is checked; otherwise its header fields and checksum."""
    if absd_image is not None:
        try:
            if load(absd_image, 'absd_image').parse_layout_sector(sector, device_sectors) is None:
                raise ValueError('no layout descriptor')
        except ValueError as error:
            raise ValueError(f'layout descriptor: {error}') from None
        return
    if sector[:8] != b'ABSDLAY1':
        raise ValueError('layout descriptor: magic')
    version, _ = struct.unpack_from('<II', sector, 8)
    written_for = struct.unpack_from('<Q', sector, 16)[0]
    check = struct.unpack_from('<Q', sector, SECTOR - 8)[0]
    if version != 3 or check != fnv1a(sector[:SECTOR - 8]):
        raise ValueError('layout descriptor: version or checksum')
    if written_for != device_sectors:
        raise ValueError(f'layout descriptor: device_sectors={written_for}, partition has {device_sectors}')


def check_image(kind, layout, before, image, absd_image=None):
    """The host's verdict on the image after one boot. `before` is the
    image's bytes before it."""
    old, new = regions(before, layout), regions(image, layout)
    if len(image) != len(before):
        raise ValueError('image size changed')
    check_esp(image)
    if new[0] != old[0]:
        raise ValueError('bytes before the ABSD partition changed')
    if new[2] != old[2]:
        raise ValueError('bytes after the ABSD partition changed')
    if kind == 'unchanged':
        if new[1] != old[1]:
            raise ValueError('the ABSD partition changed on a boot that must not write')
    elif kind == 'durable':
        block_probe_check(new[1])
    elif kind == 'platform':
        layout_descriptor(new[1][:SECTOR], layout.absd_sectors, absd_image)
    else:
        raise ValueError(f'unknown check {kind}')
    return {'before': sha(old[0]), 'partition_before': sha(old[1]), 'partition_after': sha(new[1]),
            'after': sha(old[2])}


def simulate_block_probe(image, base, sectors):
    """The bytes block-probe leaves (scripts/block-probe-image-check.py's
    expectations, written at `base`), for the self-test."""
    checker = load(HERE / 'block-probe-image-check.py', 'block_probe_image_check')
    image = bytearray(image)

    def put(lba, data):
        image[(base + lba) * SECTOR:(base + lba + 1) * SECTOR] = data

    for start in (checker.MULTI_BASE, checker.MULTI_BASE + checker.MULTI):
        for index in range(checker.MULTI):
            put(start + index, bytes(checker.multi_pattern(start, index * SECTOR + offset)
                                     for offset in range(SECTOR)))
    for index in range(checker.PARTIAL):
        put(checker.PARTIAL_BASE + index, bytes(checker.multi_pattern(checker.PARTIAL_BASE, index * SECTOR + offset)
                                                for offset in range(SECTOR)))
    for lba in range(sectors - 4, sectors):
        put(lba, bytes(checker.pattern(lba, offset) for offset in range(SECTOR)))
    put(0, b'ledger'.ljust(SECTOR, b'\x01'))
    return bytes(image)


def descriptor(device_sectors):
    sector = bytearray(SECTOR)
    sector[:24] = b'ABSDLAY1' + struct.pack('<IIQ', 3, 0, device_sectors)
    sector[SECTOR - 8:] = struct.pack('<Q', fnv1a(bytes(sector[:SECTOR - 8])))
    return bytes(sector)


def makefile_guid():
    found = re.findall(r'^GPT_PARTITION_GUID := (\S+)$', (ROOT / 'Makefile').read_text(), re.M)
    if found != [ABSD_GUID]:
        raise ValueError(f'Makefile GPT_PARTITION_GUID {found} is not {ABSD_GUID}')


def image_of(layout, temporary, name):
    path = Path(temporary) / f'{name}.img'
    layout.write(path)
    return path.read_bytes()


def rust_verdict(path, cargo):
    """The kernel's parser (src/gpt.rs, through the env-gated host test
    gpt::tests::external_image) on one image: 'first:sectors' or the
    refusal's name."""
    # An expectation that never matches makes the test print the verdict.
    command = shlex.split(cargo) + ['test', '--quiet', '--lib', 'gpt::tests::external_image', '--', '--exact']
    try:
        done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                              env=dict(os.environ, ABSD_GPT_IMAGE=str(path), ABSD_GPT_EXPECT='?'))
    except FileNotFoundError:
        raise SystemExit(f'gpt-partition-test: --rust needs cargo ({command[0]} not found; see --cargo)') from None
    found = re.search(r'left: "([^"]*)"', done.stdout + done.stderr)
    if found is None:
        raise AssertionError(f'no verdict from the Rust parser on {path}:\n{done.stdout}{done.stderr}')
    return found.group(1)


def self_test(rust=None):
    makefile_guid()
    assert guid_bytes(ESP_TYPE).hex() == '28732ac11ff8d211ba4b00a0c93ec93b'
    assert guid_bytes(ABSD_TYPE).hex() == 'a714f67a5b2cba4eb8f6217aec90357a'
    assert ABSD_FIRST % 2048 == 0 and ESP_FIRST % 2048 == 0 and LAST_USABLE >= ABSD_FIRST + ABSD_SECTORS
    total = 0
    agreement = []
    with tempfile.TemporaryDirectory() as temporary:
        # sgdisk's images are reproducible: the same bytes twice.
        first = image_of(Layout(), temporary, 'again')
        standard = Layout()
        before = image_of(standard, temporary, 'standard')
        assert sha(first) == sha(before), 'sgdisk image not reproducible'
        del first
        entries = read_gpt(before)
        assert entries == [(guid_bytes(ESP_TYPE), guid_bytes(ESP_GUID), ESP_FIRST, ESP_FIRST + ESP_SECTORS - 1),
                           (guid_bytes(ABSD_TYPE), guid_bytes(ABSD_GUID), ABSD_FIRST, ABSD_FIRST + ABSD_SECTORS - 1)]
        check_esp(before)
        assert before[ABSD_FIRST * SECTOR:(ABSD_FIRST + 1) * SECTOR] == FIRST_SEED

        # Every variant and the two other positive layouts: sgdisk --verify,
        # this script's reader and (with --rust) the kernel's parser must
        # agree on whether the table is whole.
        layouts = [(name, Layout(name)) for name in VARIANTS] + [
            ('durable', Layout(absd_sectors=DURABLE_SECTORS, seed=False)),
            ('platform', Layout(seed=False))]
        for name, layout in layouts:
            path = Path(temporary) / f'{name}.img'
            layout.write(path)
            image = path.read_bytes()
            variant = layout.variant
            whole = variant in STRUCTURALLY_VALID
            try:
                found = read_gpt(image)
                reader = True
            except ValueError:
                found, reader = None, False
            verified = sgdisk_verify(path)
            if reader != whole:
                raise AssertionError(f'{name}: reader says whole={reader}, expected {whole}')
            defect = table_defect(found, image) if reader else None
            if (defect is not None) != (variant in TABLE_DEFECTS):
                raise AssertionError(f'{name}: table check says {defect}')
            if verified != (variant in SGDISK_CLEAN):
                raise AssertionError(f'{name}: sgdisk --verify says clean={verified}')
            if variant == 'overlap':
                assert found[0][3] >= found[1][2], 'overlap variant does not overlap'
            if variant == 'duplicate':
                assert [entry[1] for entry in found].count(guid_bytes(ABSD_GUID)) == 2
            if variant == 'wrong-type':
                assert found[1][0] == guid_bytes(LINUX_TYPE)
            if rust:
                want = VARIANTS[variant]
                want = f'{ABSD_FIRST}:{layout.absd_sectors}' if want is None else want
                verdict = rust_verdict(path, rust)
                if verdict != want:
                    raise AssertionError(f'{name}: the Rust parser says {verdict}, expected {want}')
            agreement.append(f'{name}:sgdisk={"clean" if verified else "problem"}'
                             f':reader={"refused" if not reader or defect else "whole"}')
            total += 1
            del image

        # The proving read's digest is the image's own LBA 0, nothing else.
        good = f'AHCI READ OK lba=0 fnv1a=0x{fnv1a(before[:SECTOR]):016x}\n'
        check_proving_read(good, before)
        for bad in (fnv1a(bytes(SECTOR)), fnv1a(before[SECTOR:2 * SECTOR])):
            try:
                check_proving_read(f'AHCI READ OK lba=0 fnv1a=0x{bad:016x}\n', before)
            except ValueError:
                total += 1
                continue
            raise AssertionError('proving-read negative survived')

        # Image checks and their negative controls; each negative image is
        # built only when checked.
        def changed(base, offset, value=None):
            image = bytearray(base)
            image[offset] = image[offset] ^ 1 if value is None else value
            return bytes(image)

        check_image('unchanged', standard, before, before)
        durable = Layout(absd_sectors=DURABLE_SECTORS, seed=False)
        durable_before = image_of(durable, temporary, 'durable')
        check_image('durable', durable, durable_before,
                    simulate_block_probe(durable_before, ABSD_FIRST, DURABLE_SECTORS))
        platform = Layout(seed=False)
        platform_before = image_of(platform, temporary, 'platform')

        def with_descriptor(lba, device_sectors, flip=None):
            image = bytearray(platform_before)
            image[lba * SECTOR:(lba + 1) * SECTOR] = descriptor(device_sectors)
            if flip is not None:
                image[lba * SECTOR + flip] ^= 1
            return bytes(image)

        check_image('platform', platform, platform_before, with_descriptor(ABSD_FIRST, ABSD_SECTORS))
        negatives = {
            'ESP byte changed': ('unchanged', standard, before,
                                 lambda: changed(before, (ESP_FIRST + 5) * SECTOR + 100)),
            'sentinel after the partition changed': ('unchanged', standard, before,
                                                     lambda: changed(before, standard.end * SECTOR)),
            'partition changed on a read boot': ('unchanged', standard, before,
                                                 lambda: changed(before, (ABSD_FIRST + 10) * SECTOR, 1)),
            'gap before the ESP changed': ('unchanged', standard, before,
                                           lambda: changed(before, (ESP_FIRST - 1) * SECTOR, 1)),
            'backup GPT changed': ('unchanged', standard, before,
                                   lambda: changed(before, (DISK_SECTORS - 1) * SECTOR + 3)),
            'block-probe at device LBAs': ('durable', durable, durable_before,
                                           lambda: simulate_block_probe(durable_before, 0, DURABLE_SECTORS)),
            'block-probe one sector late': ('durable', durable, durable_before,
                                            lambda: simulate_block_probe(durable_before, ABSD_FIRST + 1,
                                                                         DURABLE_SECTORS)),
            'block-probe past the partition': ('durable', durable, durable_before,
                                               lambda: simulate_block_probe(durable_before, ABSD_FIRST,
                                                                            DURABLE_SECTORS + 1)),
            'nothing written': ('durable', durable, durable_before, lambda: durable_before),
            'descriptor for the whole disk': ('platform', platform, platform_before,
                                              lambda: with_descriptor(ABSD_FIRST, DISK_SECTORS)),
            'descriptor at device LBA 0': ('platform', platform, platform_before,
                                           lambda: with_descriptor(0, ABSD_SECTORS)),
            'no descriptor': ('platform', platform, platform_before, lambda: platform_before),
            'descriptor checksum': ('platform', platform, platform_before,
                                    lambda: with_descriptor(ABSD_FIRST, ABSD_SECTORS, flip=30)),
        }
        for label, (kind, layout, base, build) in negatives.items():
            try:
                check_image(kind, layout, base, build())
            except ValueError:
                total += 1
                continue
            raise AssertionError(f'image negative survived: {label}')

    cases = dict(CASES, platform=platform_case(3)) if PARTITION_WRITES else CASES
    for name, case in cases.items():
        log = sample(case)
        judge(name, case, log, case[2])
        total += controls(name, case, log, case[2])
    print('GPT IMAGE AGREEMENT ' + ' '.join(agreement))
    print(f'GPT PARTITION ORACLE OK cases={len(cases)} controls={total}'
          + (' rust=agrees' if rust else ''))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--qemu', default='qemu-system-x86_64',
                        help='QEMU command, possibly a multi-word wrapper (split like a shell would)')
    parser.add_argument('--cases', default=','.join(CASES))
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--platform-iso', type=Path)
    parser.add_argument('--platform-exit', type=int, default=3)
    parser.add_argument('--absd-image', type=Path)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--rust', action='store_true',
                        help='with --self-test: also run the kernel parser (cargo test) on every image')
    parser.add_argument('--cargo', default='cargo',
                        help='the cargo command for --rust (CARGO_TARGET_DIR is honoured)')
    args = parser.parse_args()
    if args.self_test:
        self_test(args.cargo if args.rust else None)
        return
    makefile_guid()
    cases = dict(CASES)
    if args.platform_iso and not PARTITION_WRITES:
        parser.error('--platform-iso needs a writable partition (PARTITION_WRITES)')
    if args.platform_iso:
        cases['platform'] = platform_case(args.platform_exit)
    names = args.cases.split(',') + (['platform'] if args.platform_iso else [])
    unknown = [name for name in names if name not in cases]
    if unknown:
        parser.error(f'unknown cases {unknown}')
    build = ROOT / 'build'
    records = []
    with tempfile.TemporaryDirectory(prefix='gpt-partition-', dir=build) as temporary:
        for name in names:
            case = cases[name]
            iso_name, layout = case[0], case[1]
            iso = args.platform_iso if name == 'platform' else build / f'absd-gpt-{iso_name}.iso'
            if not iso.is_file():
                raise SystemExit(f'missing {iso}: make gpt-partition-iso')
            image = Path(temporary) / f'{name}.img'
            layout.write(image)
            before = image.read_bytes()
            serial = build / f'gpt-{name}.serial.log'
            serial.unlink(missing_ok=True)
            command = shlex.split(args.qemu) + [
                '-cdrom', str(iso), '-boot', 'd',
                '-device', 'ich9-ahci,id=ahci',
                '-drive', f'if=none,id=disk,file={image},format=raw',
                '-device', 'ide-hd,drive=disk,bus=ahci.0,serial=absd',
                '-display', 'none', '-serial', 'file:' + str(serial), '-no-reboot',
                '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
            with (build / f'gpt-{name}.qemu.log').open('w') as out:
                done = subprocess.run(command, stdout=out, stderr=subprocess.STDOUT, timeout=args.timeout)
            log = serial.read_text(errors='replace')
            judge(name, case, log, done.returncode)
            check_proving_read(log, before)
            count = controls(name, case, log, done.returncode)
            if case[5] == 'durable':
                expected = (ROOT / 'tests/block-probe-expected.txt').read_text().replace(
                    'sectors=4096', f'sectors={layout.absd_sectors}')
                with tempfile.NamedTemporaryFile('w', suffix='.txt') as handle:
                    handle.write(expected)
                    handle.flush()
                    subprocess.run(['python3', str(HERE / 'check-external-output.py'), str(serial), handle.name],
                                   check=True)
            hashes = check_image(case[5], layout, before, image.read_bytes(), args.absd_image)
            records.append({'case': name, 'iso': str(iso), 'iso_sha256': sha(iso.read_bytes()),
                            'exit': done.returncode, 'controls': count, 'image_check': case[5],
                            'serial_sha256': sha(serial.read_bytes()), 'regions_sha256': hashes,
                            'command': command})
            print(f'GPT CASE OK case={name} exit={done.returncode} controls={count} image={case[5]}')
    (build / 'gpt-partition-result.json').write_text(json.dumps(records, indent=2) + '\n')
    print(f'GPT PARTITION TEST OK cases={len(records)} esp=unchanged outside=unchanged')


if __name__ == '__main__':
    main()
