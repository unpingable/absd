"""Independent host reader of the experimental ABSD filesystem, formats 1
and 2 (`docs/FILESYSTEM.md`). The superblock magic selects the format
(`ABSDFSS1`/`ABSDFSI1` or `ABSDFSS2`/`ABSDFSI2`, version word to match);
format 2 records carry `mtime`, format 1 records have none (`None`).
Any other version of the family is refused by name. The guest library
mounts format 2 only; reading format 1 here is what migration needs.

Written from the format description, not from the Rust code paths: it
selects the committed superblock by the same rule (both slots valid,
consecutive sequences, take the newer, never fall back), checks the image
structurally, and extracts files. `ag_oracle` then hands the extracted AG
database and WAL to the host's own SQLite, which performs its own WAL
recovery, and recomputes the logical authority digest independently.
"""

import hashlib
import json
import pathlib
import sqlite3
import struct
import tempfile

import absd_image

SECTOR = 512
BLOCK = 4096
SECTORS_PER_BLOCK = BLOCK // SECTOR
HEADER_BYTES = 64
# Fixed bytes of an object record, by format; the name and block list
# follow. Format 2 appends `u64 mtime` to format 1's 32 bytes.
RECORD_BYTES_BY_FORMAT = {1: 32, 2: 40}
# The current format's (the one the guest library writes).
RECORD_BYTES = RECORD_BYTES_BY_FORMAT[2]
OBJECT_BUDGET = 64 * 1024
META_FIRST = 8
ROOT = 1


class Refused(Exception):
    pass


def geometry(region_sectors):
    estimate = region_sectors // SECTORS_PER_BLOCK
    half = -(-(HEADER_BYTES + OBJECT_BUDGET + 4 * estimate) // SECTOR)
    data_first = META_FIRST + 2 * half
    data_first += (-data_first) % SECTORS_PER_BLOCK
    if region_sectors <= data_first + SECTORS_PER_BLOCK:
        raise Refused("region too small")
    return {"region_sectors": region_sectors, "half_sectors": half, "data_first": data_first,
            "data_blocks": (region_sectors - data_first) // SECTORS_PER_BLOCK}


class Region:
    def __init__(self, image_path, first, sectors):
        self.data = pathlib.Path(image_path).read_bytes()
        self.first, self.sectors = first, sectors

    @classmethod
    def of_bytes(cls, data, first=0, sectors=None):
        """A region over bytes already in memory (tests, fixtures)."""
        region = cls.__new__(cls)
        region.data = data
        region.first = first
        region.sectors = len(data) // SECTOR - first if sectors is None else sectors
        return region

    def read(self, lba, count=1):
        if lba < 0 or lba + count > self.sectors:
            raise Refused("read outside the region")
        start = (self.first + lba) * SECTOR
        return self.data[start:start + count * SECTOR]


def superblock(raw, slot, geo):
    if raw == bytes(SECTOR):
        return None
    if raw[:7] == b"ABSDFSS" and raw[7:8] not in (b"1", b"2"):
        raise Refused(f"unsupported filesystem format {raw[:8]!r}")
    if raw[:7] != b"ABSDFSS" or hashlib.sha256(raw[:480]).digest() != raw[480:]:
        raise Refused("superblock checksum")
    fmt = int(raw[7:8])
    version, parity, fs_id, seq, image_len, reserved = struct.unpack_from("<IIQQII", raw, 8)
    region, half, data_first, blocks = struct.unpack_from("<QQQQ", raw, 40)
    if version != fmt:
        raise Refused(f"unsupported filesystem format: magic {raw[:8]!r}, version {version}")
    if reserved or any(raw[104:480]):
        raise Refused("superblock version or reserved bytes")
    if seq % 2 != slot or parity != slot:
        raise Refused("superblock slot parity")
    if (region, half, data_first, blocks) != (geo["region_sectors"], geo["half_sectors"],
                                             geo["data_first"], geo["data_blocks"]):
        raise Refused("superblock geometry")
    return {"format": fmt, "fs_id": fs_id, "seq": seq, "image_len": image_len, "digest": raw[72:104]}


def valid_name(name):
    return 0 < len(name) <= 255 and name not in (b".", b"..") and b"/" not in name and b"\0" not in name


def decode_image(raw, sb, geo):
    fmt = sb["format"]
    record_bytes = RECORD_BYTES_BY_FORMAT[fmt]
    if len(raw) < HEADER_BYTES or raw[:8] != b"ABSDFSI%d" % fmt:
        raise Refused("image header")
    version, reserved, fs_id, seq, next_serial, blocks, count, region, half = struct.unpack_from(
        "<IIQQQIIQQ", raw, 8)
    if version != fmt or reserved or fs_id != sb["fs_id"] or seq != sb["seq"]:
        raise Refused("image header fields")
    if (blocks, region, half) != (geo["data_blocks"], geo["region_sectors"], geo["half_sectors"]):
        raise Refused("image geometry")
    offset, budget, records = HEADER_BYTES, HEADER_BYTES, []
    for _ in range(count):
        if len(raw) < offset + record_bytes:
            raise Refused("truncated record")
        serial, parent, size, kind, flags, name_len, block_count = struct.unpack_from("<QQQBBHI", raw, offset)
        mtime = struct.unpack_from("<Q", raw, offset + 32)[0] if fmt == 2 else None
        offset += record_bytes
        name = raw[offset:offset + name_len]
        offset += name_len
        if offset + 4 * block_count > len(raw):
            raise Refused("truncated record")
        refs = list(struct.unpack_from(f"<{block_count}I", raw, offset)) if block_count else []
        offset += 4 * block_count
        if offset > len(raw) or kind not in (1, 2) or flags not in (0, 1):
            raise Refused("record fields")
        budget += record_bytes + name_len
        records.append({"serial": serial, "parent": parent, "size": size, "dir": kind == 2,
                        "readonly": flags == 1, "name": name, "blocks": refs, "mtime": mtime})
    if offset != len(raw) or budget > OBJECT_BUDGET:
        raise Refused("image length or budget")
    serials = [r["serial"] for r in records]
    if serials != sorted(set(serials)) or not records:
        raise Refused("serial order")
    root = records[0]
    if (root["serial"], root["parent"], root["name"], root["dir"], root["readonly"], root["size"],
            root["blocks"]) != (ROOT, 0, b"", True, False, 0, []):
        raise Refused("root record")
    if next_serial <= serials[-1]:
        raise Refused("next serial")
    by_serial = {r["serial"]: r for r in records}
    seen, names = set(), set()
    for r in records[1:]:
        parent = by_serial.get(r["parent"])
        if not valid_name(r["name"]) or parent is None or not parent["dir"]:
            raise Refused("entry name or parent")
        if (r["parent"], r["name"]) in names:
            raise Refused("duplicate entry")
        names.add((r["parent"], r["name"]))
        if r["dir"] and (r["size"] or r["blocks"] or r["readonly"]):
            raise Refused("directory contents")
        if not r["dir"] and len(r["blocks"]) != -(-r["size"] // BLOCK):
            raise Refused("file length")
        for b in r["blocks"]:
            if b >= blocks or b in seen:
                raise Refused("block reference")
            seen.add(b)
        cursor, steps = r["parent"], 0
        while cursor != ROOT:
            steps += 1
            if steps > len(records):
                raise Refused("cycle")
            if cursor not in by_serial:
                raise Refused("entry name or parent")
            cursor = by_serial[cursor]["parent"]
    return {"format": fmt, "fs_id": fs_id, "seq": seq, "next_serial": next_serial, "records": records}


def select(region):
    geo = geometry(region.sectors)
    slots = [superblock(region.read(slot), slot, geo) for slot in (0, 1)]
    if slots == [None, None] or (slots[1] is None and slots[0] is not None and slots[0]["seq"] == 0):
        return None  # unformatted, or an interrupted format that committed nothing
    if None in slots:
        raise Refused("one superblock slot is blank")
    zero, one = slots
    if zero["fs_id"] != one["fs_id"] or zero["format"] != one["format"]:
        raise Refused("superblocks disagree")
    if one["seq"] == zero["seq"] + 1:
        newest = one
    elif zero["seq"] == one["seq"] + 1:
        newest = zero
    else:
        raise Refused("superblock sequences are not consecutive")
    if newest["image_len"] > geo["half_sectors"] * SECTOR:
        raise Refused("image longer than its half")
    first = META_FIRST + (newest["seq"] % 2) * geo["half_sectors"]
    raw = region.read(first, -(-newest["image_len"] // SECTOR))[:newest["image_len"]]
    if hashlib.sha256(raw).digest() != newest["digest"]:
        raise Refused("image digest")
    image = decode_image(raw, newest, geo)
    image["geometry"] = geo
    return image


def format(region):
    """The filesystem format (1 or 2) of a region's committed state, after
    the same checks as `select`; None when the region is unformatted."""
    image = select(region)
    return None if image is None else image["format"]


def fs_region(image_path, device_sectors):
    regions = absd_image.parse_layout(image_path, device_sectors)
    if regions is None:
        return None
    region = absd_image.region_of_kind(regions, absd_image.KIND_FS)
    return Region(image_path, region.first, region.sectors)


def tree(region, image):
    """path -> record, for every named object."""
    by_serial = {r["serial"]: r for r in image["records"]}

    def path(r):
        parts = []
        while r["serial"] != ROOT:
            parts.append(r["name"].decode())
            r = by_serial[r["parent"]]
        return "/" + "/".join(reversed(parts))

    return {path(r): r for r in image["records"][1:]}


def content(region, image, record):
    geo = image["geometry"]
    out = bytearray()
    for b in record["blocks"]:
        out += region.read(geo["data_first"] + b * SECTORS_PER_BLOCK, SECTORS_PER_BLOCK)
    return bytes(out[:record["size"]])


def jcs(value):
    # The values here are objects, arrays, strings, integers, booleans and
    # null: sorted keys and compact separators are exactly JCS for them.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def ag_oracle(image_path, device_sectors, database="/ag/store.db"):
    """Host view of the AG store: None without a filesystem or database."""
    region = fs_region(image_path, device_sectors)
    if region is None:
        return None
    image = select(region)
    if image is None:
        return None
    files = tree(region, image)
    if database not in files:
        return {"fs_seq": image["seq"], "files": files, "admitted": None}
    with tempfile.TemporaryDirectory() as scratch:
        for suffix in ("", "-wal"):
            if database + suffix in files:
                (pathlib.Path(scratch) / ("store.db" + suffix)).write_bytes(
                    content(region, image, files[database + suffix]))
        db = sqlite3.connect(str(pathlib.Path(scratch) / "store.db"))
        try:
            integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise Refused(f"host SQLite integrity: {integrity}")
            sequence = db.execute("SELECT sequence FROM chain_head").fetchone()[0]
            events = db.execute("SELECT count(*), max(sequence) FROM events").fetchone()
            if events[0] != sequence or (events[1] or 0) != sequence:
                raise Refused("event chain does not end at the head")
            rows = db.execute("SELECT entity_id, state_jcs FROM materialized_state "
                              "WHERE entity_id LIKE 'admission/%' ORDER BY entity_id").fetchall()
            origin = db.execute("SELECT state_jcs FROM materialized_state WHERE entity_id = "
                                "'authority/origin'").fetchone()
            blobs = {row[0]: row[1] for row in db.execute("SELECT digest, byte_length FROM blobs")}
        finally:
            db.close()
    records = [json.loads(state) for _, state in rows]
    for index, (entity, _) in enumerate(rows):
        if entity != f"admission/{index + 1:08d}" or records[index]["admission"] != index + 1:
            raise Refused(f"admission entities not contiguous at {entity}")
    admitted = len(records)
    result = {"fs_seq": image["seq"], "files": files, "admitted": admitted, "chain": sequence,
              "blobs": blobs}
    if origin is None:
        return result
    origin = json.loads(origin[0])
    books = records[-1]["books"] if records else {k: [] for k in ("standing", "custody", "obligation", "capacity")}
    authority = {"schema": 1, "origin": origin, "admitted": admitted, **books}
    result["authority"] = hashlib.sha256(jcs(authority)).hexdigest()
    # Every catalogued blob is a complete, read-only, singly named file.
    for digest, length in blobs.items():
        hexd = digest.split(":", 1)[1]
        path = f"/ag/blobs/{hexd[:2]}/{hexd[2:]}"
        record = files.get(path)
        if record is None or not record["readonly"] or record["size"] != length:
            raise Refused(f"catalogued blob {digest} missing or incomplete")
        if "sha256:" + hashlib.sha256(content(region, image, record)).hexdigest() != digest:
            raise Refused(f"blob {digest} content differs")
    result["temp_files"] = sorted(p for p in files if "/.tmp" in p)
    return result
