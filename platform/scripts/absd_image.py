"""Host-side, independent reader of ABSD's persistent layout.

Parses the layout descriptor, generation headers, and activation slots
straight from a raw image and applies the recovery rule on its own, so the
crash harness never takes the guest's word for what the bytes say.
"""

import hashlib
import struct

SECTOR = 512
LAYOUT_MAGIC = b"ABSDLAY1"
GENERATION_MAGIC = b"ABSDGEN1"
ACTIVATION_MAGIC = b"ABSDACT1"
KIND_ACTIVATION, KIND_LEDGER, KIND_GENERATION, KIND_LOG, KIND_FS = 1, 2, 3, 4, 5
SEGMENT_MAGIC = b"ABSDSEG1"
EVENT_MAGIC = b"ABSDEVT1"


def fnv1a(data):
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def read_sector(image, lba):
    with open(image, "rb") as f:
        f.seek(lba * SECTOR)
        return f.read(SECTOR)


def read_bytes(image, offset, length):
    with open(image, "rb") as f:
        f.seek(offset)
        return f.read(length)


def write_bytes(image, offset, data):
    with open(image, "r+b") as f:
        f.seek(offset)
        f.write(data)


class Region:
    def __init__(self, rid, kind, first, sectors):
        self.id, self.kind, self.first, self.sectors = rid, kind, first, sectors

    @property
    def offset(self):
        return self.first * SECTOR

    @property
    def bytes(self):
        return self.sectors * SECTOR

    def __repr__(self):
        return f"Region(id={self.id}, kind={self.kind}, first={self.first}, sectors={self.sectors})"


def parse_layout(image, device_sectors):
    sector = read_sector(image, 0)
    if sector == bytes(SECTOR):
        return None
    if sector[:8] != LAYOUT_MAGIC:
        raise ValueError("layout magic")
    version, count = struct.unpack_from("<II", sector, 8)
    written_for = struct.unpack_from("<Q", sector, 16)[0]
    check = struct.unpack_from("<Q", sector, SECTOR - 8)[0]
    if version != 3 or check != fnv1a(sector[: SECTOR - 8]) or written_for != device_sectors:
        raise ValueError("layout descriptor invalid")
    regions = []
    for index in range(count):
        rid, kind, first, sectors = struct.unpack_from("<IIQQ", sector, 24 + index * 32)
        regions.append(Region(rid, kind, first, sectors))
    # independent bounds and overlap check
    spans = sorted((r.first, r.first + r.sectors, r.id) for r in regions)
    for (a0, a1, aid), (b0, b1, bid) in zip(spans, spans[1:]):
        if a1 > b0:
            raise ValueError(f"regions {aid} and {bid} overlap")
    for r in regions:
        if r.first == 0 or r.sectors == 0 or r.first + r.sectors > device_sectors:
            raise ValueError(f"region {r.id} out of bounds")
    if len({r.id for r in regions}) != len(regions):
        raise ValueError("duplicate region ids")
    if any(sector[24 + count * 32: SECTOR - 8]):
        raise ValueError("bytes after the region table")
    # version 3 has exactly one table per device size: the v2 proportions
    # in the first half, one filesystem region in the second
    half = device_sectors // 2
    slot = half // 4
    segment = slot // 4
    v3 = [(1, KIND_ACTIVATION, 1, 2), (2, KIND_LEDGER, 16, slot - 16),
          (3, KIND_GENERATION, half - 2 * slot, slot), (4, KIND_GENERATION, half - slot, slot),
          (5, KIND_LOG, slot, segment), (6, KIND_LOG, slot + segment, segment),
          (7, KIND_LOG, slot + 2 * segment, segment), (8, KIND_LOG, slot + 3 * segment, segment),
          (9, KIND_FS, half, device_sectors - half)]
    if [(r.id, r.kind, r.first, r.sectors) for r in regions] != v3:
        raise ValueError("not the v3 table for this device")
    return regions


def region_of_kind(regions, kind, index=0):
    return [r for r in regions if r.kind == kind][index]


def region_by_id(regions, rid):
    return next(r for r in regions if r.id == rid)


def sha256(data):
    return hashlib.sha256(data).digest()


def parse_generation(image, region):
    """(header dict, reason) — header is None with a reason when invalid."""
    sector = read_sector(image, region.first)
    if sector == bytes(SECTOR):
        return None, "empty"
    if sector[:8] != GENERATION_MAGIC:
        return None, "magic"
    if sector[60:92] != sha256(sector[:60]) or any(sector[92:]):
        return None, "header digest"
    generation, length = struct.unpack_from("<QQ", sector, 8)
    body_digest = sector[24:56]
    consumer = struct.unpack_from("<I", sector, 56)[0]
    if length > (region.sectors - 1) * SECTOR:
        return None, "body length exceeds region"
    body = read_bytes(image, region.offset + SECTOR, length)
    if sha256(body) != body_digest:
        return None, "body digest"
    return {"generation": generation, "length": length, "digest": body_digest,
            "consumer": consumer, "body": body}, None


def parse_activation(image, activation_region, slot):
    sector = read_sector(image, activation_region.first + slot)
    if sector == bytes(SECTOR):
        return None, "empty"
    if sector[:8] != ACTIVATION_MAGIC:
        return None, "magic"
    if sector[60:92] != sha256(sector[:60]) or any(sector[92:]):
        return None, "record digest"
    sequence = struct.unpack_from("<Q", sector, 8)[0]
    region = struct.unpack_from("<I", sector, 16)[0]
    generation = struct.unpack_from("<Q", sector, 20)[0]
    return {"sequence": sequence, "region": region, "generation": generation,
            "digest": sector[28:60]}, None


def encode_activation(sequence, region, generation, digest):
    sector = bytearray(SECTOR)
    sector[:8] = ACTIVATION_MAGIC
    struct.pack_into("<QIQ", sector, 8, sequence, region, generation)
    sector[28:60] = digest
    sector[60:92] = sha256(sector[:60])
    return bytes(sector)


def select(image, regions):
    """The recovery rule, implemented independently of the guest.

    Returns dict(selected=(generation, region_id, sequence) or None,
    refused=bool, rolled_back=bool, newest=int or None, slots=[...]).
    """
    activation = region_of_kind(regions, KIND_ACTIVATION)
    slots = []
    newest = None
    for r in regions:
        if r.kind == KIND_GENERATION:
            sector = read_sector(image, r.first)
            if sector[:8] == GENERATION_MAGIC and sector[60:92] == sha256(sector[:60]) and not any(sector[92:]):
                newest = max(newest or 0, struct.unpack_from("<Q", sector, 8)[0])
    for slot in range(2):
        record, reason = parse_activation(image, activation, slot)
        if record is None:
            slots.append(("invalid" if reason != "empty" else "empty", reason))
            continue
        newest = max(newest or 0, record["generation"])
        usable = None
        try:
            region = region_by_id(regions, record["region"])
            if region.kind != KIND_GENERATION:
                usable = "activation names no generation region"
            else:
                header, why = parse_generation(image, region)
                if header is None:
                    usable = why
                elif header["generation"] != record["generation"] or header["digest"] != record["digest"]:
                    usable = "generation does not match activation"
        except StopIteration:
            usable = "activation names no generation region"
        slots.append(("record", record, usable))
    # Highest sequence first; equal sequences prefer the lower slot, the
    # same deterministic tie-break the guest applies.
    ordered = sorted(((-s[1]["sequence"], i) for i, s in enumerate(slots) if s[0] == "record"))
    selected, rolled_back = None, False
    for rank, (_, index) in enumerate(ordered):
        record, usable = slots[index][1], slots[index][2]
        if usable is None:
            selected = (record["generation"], record["region"], record["sequence"], index)
            rolled_back = rank > 0
            break
    refused = selected is None and any(s[0] != "empty" for s in slots)
    return {"selected": selected, "refused": refused, "rolled_back": rolled_back,
            "newest": newest, "slots": slots}


def region_hash(image, region):
    return hashlib.sha256(read_bytes(image, region.offset, region.bytes)).hexdigest()


def parse_segment(image, region):
    """Committed records of one log segment, applying the log's own rule.

    Returns dict(header=None|{epoch, first}, events=[(seq, body)],
    torn=bool, refused=None|reason).
    """
    result = {"header": None, "events": [], "torn": False, "refused": None, "stale_max": None}
    sector = read_sector(image, region.first)
    if sector == bytes(SECTOR):
        # A blank header over nonzero sectors is a reclaim interrupted after
        # the header was zeroed: any record still parseable there is stale.
        # The composed rule refuses if such a record exceeds the checkpoint.
        stale_max = None
        for index in range(1, region.sectors):
            body = read_sector(image, region.first + index)
            if body != bytes(SECTOR):
                if body[:8] == EVENT_MAGIC and body[52:84] == sha256(body[:52]) and not any(body[84:]):
                    stale_max = max(stale_max or 0, struct.unpack_from("<Q", body, 8)[0])
                else:
                    stale_max = max(stale_max or 0, 0)
        result["stale_max"] = stale_max
        return result
    if sector[:8] != SEGMENT_MAGIC or sector[24:56] != sha256(sector[:24]) or any(sector[56:]):
        result["refused"] = "segment header"
        return result
    epoch, first = struct.unpack_from("<QQ", sector, 8)
    result["header"] = {"epoch": epoch, "first": first}
    index, expected = 1, first
    while index < region.sectors:
        sector = read_sector(image, region.first + index)
        if sector == bytes(SECTOR):
            for rest in range(index + 1, region.sectors):
                if read_sector(image, region.first + rest) != bytes(SECTOR):
                    result["refused"] = "bytes after the last record"
                    return result
            break
        if sector[:8] != EVENT_MAGIC or sector[52:84] != sha256(sector[:52]) or any(sector[84:]):
            result["refused"] = "event header"
            return result
        sequence, length = struct.unpack_from("<QI", sector, 8)
        digest = sector[20:52]
        if sequence != expected:
            result["refused"] = "record sequence out of order"
            return result
        body_sectors = (length + SECTOR - 1) // SECTOR
        if index + body_sectors >= region.sectors:
            result["refused"] = "record extends past its segment"
            return result
        raw = read_bytes(image, region.offset + (index + 1) * SECTOR, body_sectors * SECTOR)
        body, padding = raw[:length], raw[length:]
        if sha256(body) != digest or any(padding):
            for rest in range(index + body_sectors + 1, region.sectors):
                if read_sector(image, region.first + rest) != bytes(SECTOR):
                    result["refused"] = "damaged record followed by more records"
                    return result
            # Sectors land in write order: a torn append never wrote its
            # last body sector, so a written last sector means damage.
            if any(raw[-SECTOR:]):
                result["refused"] = "damaged last record whose final sector was written"
                return result
            result["torn"] = True
            break
        result["events"].append((sequence, body))
        expected += 1
        index += 1 + body_sectors
    return result


def parse_log(image, regions):
    """The whole log chain: dict(events={seq: body}, refused=None|reason,
    earliest=int|None, next=int, live=[(epoch, region_id)])."""
    segments = []
    stale_max = None
    for region in regions:
        if region.kind != KIND_LOG:
            continue
        parsed = parse_segment(image, region)
        if parsed["refused"]:
            return {"events": {}, "refused": f"segment {region.id}: {parsed['refused']}", "earliest": None,
                    "next": None, "live": [], "stale_max": None}
        if parsed["stale_max"] is not None:
            stale_max = max(stale_max or 0, parsed["stale_max"])
        if parsed["header"]:
            segments.append((parsed["header"]["epoch"], region.id, parsed))
    segments.sort()
    events, expected = {}, None
    for rank, (epoch, rid, parsed) in enumerate(segments):
        if parsed["torn"] and rank + 1 < len(segments):
            return {"events": {}, "refused": "torn record inside a superseded segment", "earliest": None,
                    "next": None, "live": []}
        first = parsed["header"]["first"]
        if expected is not None and first != expected:
            return {"events": {}, "refused": "segment chain has a gap or overlap", "earliest": None,
                    "next": None, "live": []}
        for sequence, body in parsed["events"]:
            events[sequence] = body
        expected = (parsed["events"][-1][0] + 1) if parsed["events"] else first
    return {"events": events, "refused": None, "earliest": min(events) if events else None,
            "next": expected if expected is not None else 1, "live": [(e, r) for e, r, _ in segments],
            "stale_max": stale_max}


def checkpoint_recovery(image, regions):
    """Compose checkpoint selection with the log: which admissions must a
    correct recovery reproduce? Returns dict(checkpoint=int (0 none),
    events=[seq...], refused=None|reason)."""
    selection = select(image, regions)
    if selection["refused"]:
        return {"checkpoint": None, "events": [], "refused": "checkpoint refused"}
    covered = 0
    if selection["selected"]:
        region = region_by_id(regions, selection["selected"][1])
        header, _ = parse_generation(image, region)
        import json
        image_body = json.loads(header["body"].decode())
        covered = image_body["admitted"]
        if any(len(image_body[book]) != covered for book in ("standing", "custody", "obligation", "capacity")):
            return {"checkpoint": None, "events": [], "refused": "authority image shape"}
    log = parse_log(image, regions)
    if log["refused"]:
        return {"checkpoint": covered, "events": [], "refused": log["refused"]}
    if log["stale_max"] is not None and log["stale_max"] > covered:
        return {"checkpoint": covered, "events": [], "refused": "stale record beyond the checkpoint"}
    needed = sorted(seq for seq in log["events"] if seq > covered)
    if needed and needed[0] != covered + 1:
        return {"checkpoint": covered, "events": [], "refused": "log prefix after the checkpoint is missing"}
    if log["earliest"] is not None and covered == 0 and log["earliest"] != 1:
        return {"checkpoint": 0, "events": [], "refused": "log start reclaimed without a checkpoint"}
    if needed != list(range(covered + 1, covered + 1 + len(needed))):
        return {"checkpoint": covered, "events": [], "refused": "log suffix has a gap"}
    if log["next"] != covered + 1 + len(needed):
        return {"checkpoint": covered, "events": [], "refused": "log does not follow the checkpoint"}
    return {"checkpoint": covered, "events": needed, "refused": None}


def encode_generation_header(generation, body, consumer=0x41475631):
    sector = bytearray(SECTOR)
    sector[:8] = GENERATION_MAGIC
    struct.pack_into("<QQ", sector, 8, generation, len(body))
    sector[24:56] = sha256(body)
    struct.pack_into("<I", sector, 56, consumer)
    sector[60:92] = sha256(sector[:60])
    return bytes(sector)


def live_log_segments(image, regions):
    return [r for r in regions if r.kind == KIND_LOG and read_sector(image, r.first)[:8] == SEGMENT_MAGIC]

