"""Host reader tests against images the Rust library wrote.

`fs/testdata/format1.sectors` was written by the format-1 library and
`fs/testdata/format2.sectors` by the current one (`fs/src/tests.rs`, which
also checks that the format-2 file is still what the library writes). Each
is a header line and one `LBA HEX` line per nonzero sector of the region.

Run: `python3 -m pytest scripts/test_absd_fs.py`, or
`python3 scripts/test_absd_fs.py` without pytest.
"""

import hashlib
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import absd_fs  # noqa: E402

TESTDATA = pathlib.Path(__file__).resolve().parent.parent / "fs" / "testdata"
FIXTURE_ID = 0x0123_4567_89AB_CDEF


def load(name):
    lines = (TESTDATA / name).read_text().splitlines()
    sectors = int(lines[0].removeprefix("absd-fs sectors "))
    data = bytearray(sectors * absd_fs.SECTOR)
    for line in lines[1:]:
        lba, hexed = line.split(" ")
        data[int(lba) * absd_fs.SECTOR:(int(lba) + 1) * absd_fs.SECTOR] = bytes.fromhex(hexed)
    return data


def region(data):
    return absd_fs.Region.of_bytes(bytes(data))


def pattern(seed, length):
    return bytes((seed + (index * 7 % 251)) % 256 for index in range(length))


def newest(data):
    reg = region(data)
    geo = absd_fs.geometry(reg.sectors)
    slots = [absd_fs.superblock(reg.read(slot), slot, geo) for slot in (0, 1)]
    return max(slots, key=lambda sb: sb["seq"]), geo


def resign(data, raw):
    """Puts `raw` in place of the selected image and re-signs it, so only
    the image's own structural checks can refuse it."""
    sb, geo = newest(data)
    slot = sb["seq"] % 2
    first = (absd_fs.META_FIRST + slot * geo["half_sectors"]) * absd_fs.SECTOR
    half = geo["half_sectors"] * absd_fs.SECTOR
    assert len(raw) <= half
    data[first:first + half] = bytes(raw).ljust(half, b"\0")
    sector = bytearray(data[slot * absd_fs.SECTOR:(slot + 1) * absd_fs.SECTOR])
    struct.pack_into("<I", sector, 32, len(raw))
    sector[72:104] = hashlib.sha256(bytes(raw)).digest()
    sector[480:] = hashlib.sha256(bytes(sector[:480])).digest()
    data[slot * absd_fs.SECTOR:(slot + 1) * absd_fs.SECTOR] = sector


def selected_raw(data):
    sb, geo = newest(data)
    first = (absd_fs.META_FIRST + (sb["seq"] % 2) * geo["half_sectors"]) * absd_fs.SECTOR
    return bytearray(data[first:first + sb["image_len"]])


def with_directories(data, record_bytes, names):
    """The selected image plus one empty directory under the root for each
    name: records appended in serial order, header count and serial
    counter adjusted."""
    raw = selected_raw(data)
    count, serial = struct.unpack_from("<I", raw, 44)[0], struct.unpack_from("<Q", raw, 32)[0]
    for name in names:
        head = struct.pack("<QQQBBHI", serial, 1, 0, 2, 0, len(name), 0)
        raw += head.ljust(record_bytes, b"\0") + name
        serial, count = serial + 1, count + 1
    struct.pack_into("<Q", raw, 32, serial)
    struct.pack_into("<I", raw, 44, count)
    return raw


def used_bytes(data, record_bytes):
    image = absd_fs.select(region(data))
    return absd_fs.HEADER_BYTES + sum(record_bytes + len(r["name"]) for r in image["records"])


class Reader(unittest.TestCase):
    def test_format_two_is_read_with_mtime(self):
        reg = region(load("format2.sectors"))
        image = absd_fs.select(reg)
        self.assertEqual(image["format"], 2)
        self.assertEqual(absd_fs.format(reg), 2)
        self.assertEqual(image["fs_id"], FIXTURE_ID)
        files = absd_fs.tree(reg, image)
        self.assertEqual(sorted(files), ["/d", "/d/f", "/g"])
        self.assertEqual(absd_fs.content(reg, image, files["/d/f"]), b"hello, world\n")
        self.assertEqual(absd_fs.content(reg, image, files["/g"]), pattern(3, 600))
        self.assertTrue(files["/g"]["readonly"])
        self.assertEqual({path: r["mtime"] for path, r in files.items()},
                         {"/d": 1_790_000_000, "/d/f": 1_790_000_100, "/g": 1_790_000_000})
        self.assertEqual(image["records"][0]["mtime"], 1_790_000_000)

    def test_format_one_is_still_read(self):
        reg = region(load("format1.sectors"))
        image = absd_fs.select(reg)
        self.assertEqual(image["format"], 1)
        self.assertEqual(absd_fs.format(reg), 1)
        files = absd_fs.tree(reg, image)
        self.assertEqual(sorted(files), ["/d", "/d/f", "/g"])
        self.assertEqual(absd_fs.content(reg, image, files["/d/f"]), b"hello\n")
        self.assertEqual(absd_fs.content(reg, image, files["/g"]), pattern(3, 600))
        # Format 1 records no time at all: not 0 ("unknown"), absent.
        self.assertTrue(all(r["mtime"] is None for r in image["records"]))

    def test_a_blank_region_has_no_format(self):
        reg = region(bytearray(512 * absd_fs.SECTOR))
        self.assertIsNone(absd_fs.select(reg))
        self.assertIsNone(absd_fs.format(reg))

    def test_another_version_is_refused_by_name(self):
        for name in ("format1.sectors", "format2.sectors"):
            data = load(name)
            for slot in (0, 1):
                sector = bytearray(data[slot * 512:(slot + 1) * 512])
                sector[7:8] = b"3"
                sector[480:] = hashlib.sha256(bytes(sector[:480])).digest()
                data[slot * 512:(slot + 1) * 512] = sector
            with self.assertRaisesRegex(absd_fs.Refused, "unsupported filesystem format"):
                absd_fs.select(region(data))

    def test_slots_of_two_formats_are_refused(self):
        one, two = load("format1.sectors"), load("format2.sectors")
        mixed = bytearray(two)
        mixed[0:512] = one[0:512]
        with self.assertRaisesRegex(absd_fs.Refused, "superblocks disagree"):
            absd_fs.select(region(mixed))

    def test_structural_checks_hold_in_both_formats(self):
        for name, record_bytes in (("format1.sectors", 32), ("format2.sectors", 40)):
            data = load(name)
            raw = selected_raw(data)
            # The third record (a file) given a parent that does not exist.
            offset = absd_fs.HEADER_BYTES
            for _ in range(2):
                name_len, blocks = struct.unpack_from("<HI", raw, offset + 26)
                offset += record_bytes + name_len + 4 * blocks
            struct.pack_into("<Q", raw, offset + 8, 999)
            resign(data, raw)
            with self.assertRaises(absd_fs.Refused, msg=name):
                absd_fs.select(region(data))

    def test_trailing_bytes_are_refused(self):
        data = load("format2.sectors")
        resign(data, selected_raw(data) + b"\0" * 8)
        with self.assertRaisesRegex(absd_fs.Refused, "image length or budget"):
            absd_fs.select(region(data))

    def test_the_object_budget_counts_each_format_record_size(self):
        """`OBJECT_BUDGET` covers the header and every record's fixed bytes
        and name, as the library counts them (fs/src/image.rs): an image
        at exactly the budget is read, one byte over is refused."""
        for name, record_bytes in (("format1.sectors", 32), ("format2.sectors", 40)):
            data = load(name)
            room = absd_fs.OBJECT_BUDGET - used_bytes(data, record_bytes)
            per = record_bytes + 8
            count = room // per - 1
            last = room - count * per - record_bytes
            for extra, accepted in ((0, True), (1, False)):
                names = [b"%08d" % index for index in range(count)] + [b"z" * (last + extra)]
                trial = bytearray(data)
                resign(trial, with_directories(data, record_bytes, names))
                if accepted:
                    self.assertEqual(used_bytes(trial, record_bytes), absd_fs.OBJECT_BUDGET, name)
                else:
                    with self.assertRaisesRegex(absd_fs.Refused, "budget", msg=name):
                        absd_fs.select(region(trial))


if __name__ == "__main__":
    unittest.main()
