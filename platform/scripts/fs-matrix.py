#!/usr/bin/env python3
"""Crash, ENOSPC, lock, identity, corruption, and equivalence matrix for the
real AG SQLite store on the experimental ABSD filesystem.

Every scenario is a sequence of QEMU boots of `ag_sqlite` against one raw
image. Crash points are exact: the guest stops the machine (or kills only
its own process) immediately before a chosen filesystem sector write, so a
sweep over write counts visits every point of an operation. After every boot
the host independently parses the filesystem, hands the extracted database
and WAL to the host's own SQLite, and recomputes the authority digest; guest
and host must agree.

Failure model: abrupt loss of all guest state with every device-acknowledged
sector retained, applied in order. Host power loss is not modelled, except
by the `powercut` scenario, which applies the device law of
docs/POWER-LOSS.md below the filesystem inside the guest: every unit
written since the last completed flush ends in one of its states, chosen
by a seeded policy, before the machine stops.
"""

import argparse
import hashlib
import importlib.util
import os
import pathlib
import re
import shutil
import struct
import sys

here = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(here))
import absd_fs  # noqa: E402

spec = importlib.util.spec_from_file_location("durable_matrix", here / "durable-matrix.py")
dm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dm)

IMAGE_BYTES = 16 * 1024 * 1024
DEVICE_SECTORS = IMAGE_BYTES // 512
CRASH_CODE = 40
HOLD_CODE = 41
POWER_CUT_CODE = 42
# ag_sqlite kinds 8 and 9: the tens digit of `flags` selects the unit and
# whether the cut precedes a write or replaces the flush after `writes`.
CUT_ADMISSION, CUT_CLOSE = 8, 9
CUT_TENS = {(1, False): 1, (1, True): 2, (8, False): 8, (8, True): 9}
MIRROR, DIE, IN_CLOSE = 1, 2, 4
# Stop after the SQLite commit and before Route B's append of the same
# admission: the two stores are then exactly one admission apart.
SPLIT = 99_999
RECOVERED = re.compile(r"AG SQLITE RECOVERED admitted=(\d+) chain=(\d+) authority=([0-9a-f]{64}) witness=(\S+)")


def fail(message):
    print(f"FS MATRIX FAILED: {message}", file=sys.stderr)
    sys.exit(1)


def require(condition, message):
    if not condition:
        fail(message)


def step(kind, flags=0, count=0, writes=0):
    return kind * 10_000_000_000 + flags * 100_000_000 + count * 100_000 + writes


class Matrix:
    def __init__(self, args):
        self.h = dm.Harness(args)
        self.work = self.h.work
        self.boots = 0
        self.deep = args.deep

    def image(self, name, source=None):
        path = self.work / f"{name}.img"
        if source is None:
            with open(path, "wb") as handle:
                handle.truncate(IMAGE_BYTES)
        else:
            shutil.copyfile(source, path)
        return path

    def boot(self, name, word, image):
        self.boots += 1
        status, serial, captured, log = self.h.boot(name, word, image)
        return status, serial, captured

    def orderly(self, name, word, image):
        status, serial, captured = self.boot(name, word, image)
        require(status == 3 and "AG SQLITE STEP OK" in captured,
                f"{name}: status {status}\n{captured}")
        return captured, serial

    def stopped(self, name, word, image, code=CRASH_CODE):
        status, serial, captured = self.boot(name, word, image)
        require(status == 4 * code + 3 and f"MACHINE STOP code={code}\n".encode() in serial,
                f"{name}: expected stop {code}, status {status}\n{captured}")
        require("AG SQLITE STEP OK" not in captured, f"{name}: finished despite the stop")
        return captured, serial

    def refused(self, name, word, image, needle):
        status, serial, captured = self.boot(name, word, image)
        require(status == 7 and "AG SQLITE STEP FAILED" in captured and needle in captured,
                f"{name}: expected refusal containing {needle!r}, status {status}\n{captured}")
        return captured

    def host(self, name, image):
        try:
            return absd_fs.ag_oracle(image, DEVICE_SECTORS)
        except absd_fs.Refused as error:
            fail(f"{name}: host refused a guest-accepted image: {error}")

    def agree(self, name, captured, image):
        """Guest's recovered authority equals the host's independent view."""
        found = RECOVERED.findall(captured)
        require(found, f"{name}: no recovery line\n{captured}")
        admitted, chain, authority, _ = found[0]
        view = self.host(name, image)
        require(view["admitted"] is not None, f"{name}: host found no database")
        # The guest's first recovery ran before this boot's own admissions;
        # compare the host with the guest's final recovered state when the
        # boot ended with a verify, else just the first line's shape.
        return int(admitted), int(chain), authority, view

    def verify(self, name, image):
        captured, _ = self.orderly(name, step(3), image)
        admitted, chain, authority, view = self.agree(name, captured, image)
        require(view["admitted"] == admitted and view["authority"] == authority and view["chain"] == chain,
                f"{name}: guest admitted={admitted} chain={chain} authority={authority} but host {view}")
        return admitted, authority, view


def writes_of(captured, admission):
    found = re.findall(rf"AG ADMISSION WRITES admission={admission} writes=(\d+)", captured)
    require(found, f"no write count for admission {admission}")
    return int(found[0])


def points(total, deep):
    if deep:
        return list(range(1, total + 1))
    fixed = {1, 2, 3, 4, total - 3, total - 2, total - 1, total}
    fixed |= {max(1, total * i // 16) for i in range(1, 16)}
    return sorted(p for p in fixed if 1 <= p <= total)


def scenario_store(m, base):
    image = m.image("store", base)
    admitted, authority, view = m.verify("store.verify0", image)
    captured, _ = m.orderly("store.admit", step(2, count=2), image)
    after, authority2, view2 = m.verify("store.verify", image)
    require(after == admitted + 2 and authority2 != authority, "store: admissions did not persist")
    require(not view2["temp_files"], f"store: temp files left behind {view2['temp_files']}")
    print(f"AG SQLITE STORE OK admitted={after} authority={authority2}")


def sweep(m, label, base, flags, writes_total, expect_crash):
    """Crash at sampled or all write points of one admission (or close)."""
    before, _, _ = m.verify(f"{label}.base", m.image(f"{label}.base", base))
    outcomes, leftovers = [], 0
    for point in points(writes_total, m.deep):
        image = m.image(f"{label}.{point}", base)
        word = step(2, flags=flags, count=1, writes=point)
        if flags & DIE:
            captured, serial = m.orderly(f"{label}.{point}", word, image)
            dm.expect_generations(f"{label}.{point}", serial, [dm.WORKER_ABORT_STATUS, 0])
            require("FS LOCK OWNER DEATH OK" in captured, f"{label}.{point}: replacement did not reopen")
            recovered = [int(r[0]) for r in RECOVERED.findall(captured)]
            # first line: the dying worker's pre-admission recovery; second:
            # the replacement's recovery from the device alone
            require(len(recovered) == 2, f"{label}.{point}: recoveries {recovered}")
            got = recovered[1]
        else:
            m.stopped(f"{label}.{point}", word, image)
            got, _, view = m.verify(f"{label}.{point}.verify", image)
            # AG never removes a temp blob a crash interrupted; count them.
            leftovers += len(view["temp_files"])
        # A crash in the close follows an acknowledged admission.
        allowed = (before + 1,) if flags & IN_CLOSE else (before, before + 1)
        require(got in allowed, f"{label}.{point}: recovered {got}, expected one of {allowed}")
        outcomes.append((point, got))
        if flags & DIE:
            after, _, _ = m.verify(f"{label}.{point}.verify", image)
            require(after == got + 1, f"{label}.{point}: replacement admission missing ({after})")
    # The commit is one point: once an admission survives a crash it
    # survives every later crash point too.
    seen = [got for _, got in outcomes]
    require(seen == sorted(seen), f"{label}: recovered counts not monotonic in the crash point {outcomes}")
    if not flags & IN_CLOSE:
        # The first point precedes any commit; the last lands after the
        # acknowledged admission (in the close).
        require(seen[0] == before and seen[-1] == before + 1, f"{label}: {outcomes}")
    print(f"{expect_crash} points={len(outcomes)} writes={writes_total} temp_files_left={leftovers} "
          f"outcomes={outcomes}")


def scenario_powercut(m, base, per_admission, close_writes):
    """Power cuts under the device law at sampled points of one admission
    and of the checkpoint on close, under both unit sizes and five
    policies: all unflushed writes lost (seed 0), none lost (1), and three
    per-unit choices. Every cut must leave a mountable filesystem whose
    recovered authority the host confirms, with the admission count in
    {before, before + 1} (admission) or exactly before + 1 (close, since
    the admission was acknowledged), and no duplicated admission.

    A cut before write `n + 1` follows every flush issued after write `n`,
    so it never sees a commit's superblock sector unflushed: the flush cut
    after `per_admission` writes (the commit's final flush never completes)
    is the point where the policy alone decides the admission's fate."""
    before, _, _ = m.verify("powercut.base", m.image("powercut.base", base))
    policies = [(unit, seed) for unit in (1, 8) for seed in (0, 1, 2, 5, 7)]
    admission_points = sorted({max(1, per_admission // 5), max(1, per_admission * 3 // 5), per_admission})
    close_points = sorted({max(1, close_writes // 3), max(1, close_writes * 2 // 3)})
    outcomes = {"admission": [], "admission_flush": [], "close": [], "close_flush": []}
    leftovers = 0

    def cut(label, kind, point, unit, seed, at_flush=False):
        nonlocal leftovers
        image = m.image(label, base)
        word = step(kind, flags=CUT_TENS[(unit, at_flush)] * 10 + seed, count=1, writes=point)
        captured, _ = m.stopped(label, word, image, code=POWER_CUT_CODE)
        # The complete arming line must be in the transcript and the
        # transcript must end on a line boundary: a line cut off means init's
        # drain of the worker's stdout lost frames to the stop (ag_sqlite
        # sleeps for the drain after announcing and after the last
        # admission's report, so a cut in the close sees whole lines).
        armed = (f"AG ARMED power cut after {point} writes unit={unit} seed={seed} "
                 f"at_flush={'true' if at_flush else 'false'}\n")
        require(armed in captured, f"{label}: the cut was never armed, or the arming line was lost\n{captured}")
        require(captured.endswith("\n"), f"{label}: transcript cut off mid-line\n{captured}")
        got, _, view = m.verify(f"{label}.verify", image)
        leftovers += len(view["temp_files"])
        return got

    for point in admission_points:
        for unit, seed in policies:
            got = cut(f"powercut.admission.{point}.u{unit}.s{seed}", CUT_ADMISSION, point, unit, seed)
            require(got in (before, before + 1), f"powercut admission {point} U={unit} seed={seed}: recovered {got}")
            outcomes["admission"].append((point, unit, seed, got))
    for unit, seed in policies:
        got = cut(f"powercut.admission-flush.u{unit}.s{seed}", CUT_ADMISSION, per_admission, unit, seed, at_flush=True)
        # Only the superblock sector is unflushed: seed 0 must lose the
        # admission and seed 1 must keep it; any other seed does one or the other.
        expected = {0: (before,), 1: (before + 1,)}.get(seed, (before, before + 1))
        require(got in expected, f"powercut admission flush U={unit} seed={seed}: recovered {got}, expected {expected}")
        outcomes["admission_flush"].append((per_admission, unit, seed, got))
    for point in close_points:
        for unit, seed in policies:
            got = cut(f"powercut.close.{point}.u{unit}.s{seed}", CUT_CLOSE, point, unit, seed)
            require(got == before + 1, f"powercut close {point} U={unit} seed={seed}: recovered {got}, expected {before + 1}")
            outcomes["close"].append((point, unit, seed, got))
    for unit, seed in [(1, 0), (1, 1), (1, 2), (8, 0), (8, 1), (8, 2)]:
        got = cut(f"powercut.close-flush.u{unit}.s{seed}", CUT_CLOSE, close_writes, unit, seed, at_flush=True)
        require(got == before + 1, f"powercut close flush U={unit} seed={seed}: recovered {got}, expected {before + 1}")
        outcomes["close_flush"].append((close_writes, unit, seed, got))
    # Under the deterministic policies the outcome is monotonic in the cut
    # point: seed 1 is the plain crash model, seed 0 is that model with
    # every unflushed write dropped, and neither can lose a completed flush.
    for unit in (1, 8):
        for seed in (0, 1):
            seen = [got for point, u, s, got in outcomes["admission"] if u == unit and s == seed]
            require(seen == sorted(seen), f"powercut U={unit} seed={seed}: not monotonic {seen}")
    cuts = sum(len(v) for v in outcomes.values())
    print(f"AG SQLITE POWER CUT OK cuts={cuts} admission_points={admission_points} close_points={close_points} "
          f"units=(1,8) seeds=(0,1,2,5,7) temp_files_left={leftovers} "
          f"admission_outcomes={outcomes['admission']} admission_flush_outcomes={outcomes['admission_flush']} "
          f"close_outcomes={outcomes['close']} close_flush_outcomes={outcomes['close_flush']}")


def scenario_lock(m, base):
    image = m.image("lock-reboot", base)
    status, serial, captured = m.boot("lock-reboot.hold", step(4), image)
    require("FS EXCLUSIVE LOCK OK" in captured, f"lock: exclusive check missing\n{captured}")
    require(status == 4 * HOLD_CODE + 3, f"lock: expected hold stop, status {status}")
    m.verify("lock-reboot.verify", image)
    print("FS LOCK REBOOT CLEAR OK")
    image = m.image("lock-death", base)
    captured, serial = m.orderly("lock-death", step(4, flags=DIE), image)
    dm.expect_generations("lock-death", serial, [dm.WORKER_ABORT_STATUS, 0])
    require("FS LOCK OWNER DEATH OK" in captured, "lock-death: replacement could not take the fence")
    m.verify("lock-death.verify", image)
    print("FS LOCK OWNER DEATH OK")


def scenario_identity(m, base):
    image = m.image("identity", base)
    captured, _ = m.orderly("identity", step(5), image)
    require("FS IDENTITY STALE REFUSED OK" in captured and "FS RETAINED WRITE REFUSED OK" in captured,
            f"identity\n{captured}")
    m.verify("identity.verify", image)
    print("FS IDENTITY STALE REFUSED OK")
    print("FS RETAINED WRITE REFUSED OK")


def scenario_poison(m, base, flushes):
    """Every flush of an admission fails in turn. The worker cannot know
    whether its commit reached the device, so it must exit for replacement;
    the replacement recovers exactly one durable truth and continues, and
    nothing is admitted twice."""
    before, _, _ = m.verify("poison.base", m.image("poison.base", base))
    outcomes = []
    for flush in range(1, flushes + 1):
        image = m.image(f"poison.{flush}", base)
        captured, serial = m.orderly(f"poison.{flush}", step(10, count=1, writes=flush), image)
        dm.expect_generations(f"poison.{flush}", serial, [dm.WORKER_ABORT_STATUS, 0])
        require("AG WORKER POISONED" in captured, f"poison.{flush}: worker did not stop on the device failure")
        require(f"AG SQLITE ADMITTED admission={before + 1} " not in captured.split("AG WORKER REPLACED")[0],
                f"poison.{flush}: the failed admission was acknowledged")
        recovered = [int(r[0]) for r in RECOVERED.findall(captured)]
        require(len(recovered) == 2 and recovered[1] in (before, before + 1),
                f"poison.{flush}: recoveries {recovered}")
        after, _, _ = m.verify(f"poison.{flush}.verify", image)
        require(after == recovered[1] + 1, f"poison.{flush}: replacement admission missing ({after})")
        outcomes.append((flush, recovered[1]))
    seen = {got for _, got in outcomes}
    require(seen == {before, before + 1}, f"poison: both durable outcomes must occur {outcomes}")
    print(f"AG WORKER POISON RECOVERY OK flushes={flushes} outcomes={outcomes}")


def scenario_poison_close(m, base, flushes):
    """Every flush of the close (the checkpoint after an acknowledged
    admission) fails in turn: the worker must still exit for replacement,
    and the acknowledged admission must survive."""
    before, _, _ = m.verify("poison-close.base", m.image("poison-close.base", base))
    for flush in range(1, flushes + 1):
        image = m.image(f"poison-close.{flush}", base)
        captured, serial = m.orderly(f"poison-close.{flush}", step(11, count=1, writes=flush), image)
        dm.expect_generations(f"poison-close.{flush}", serial, [dm.WORKER_ABORT_STATUS, 0])
        require("AG WORKER POISONED" in captured, f"poison-close.{flush}: worker did not stop")
        recovered = [int(r[0]) for r in RECOVERED.findall(captured)]
        require(len(recovered) == 2 and recovered[1] == before + 1,
                f"poison-close.{flush}: acknowledged admission lost {recovered}")
        after, _, _ = m.verify(f"poison-close.{flush}.verify", image)
        require(after == before + 2, f"poison-close.{flush}: replacement admission missing ({after})")
    print(f"AG WORKER POISON CLOSE OK flushes={flushes}")


def scenario_authority(m, base):
    image = m.image("authority", base)
    before = hashlib.sha256(pathlib.Path(image).read_bytes()).hexdigest()
    captured, _ = m.orderly("authority", step(7), image)
    require("FS READ ONLY AUTHORITY OK" in captured, f"authority\n{captured}")
    after = hashlib.sha256(pathlib.Path(image).read_bytes()).hexdigest()
    require(before == after, "authority: a read-only boot changed the device")
    print("FS READ ONLY AUTHORITY OK device unchanged")


def scenario_enospc(m, base):
    image = m.image("enospc", base)
    captured, _ = m.orderly("enospc", step(6), image)
    for marker in ("FS ENOSPC SAFE OK", "SQLITE ENOSPC SAFE OK"):
        require(marker in captured, f"enospc: {marker} missing\n{captured}")
    outcomes = re.findall(r"AG ENOSPC ATTEMPT freed=(\d+) outcome=(\S+)", captured)
    classes = {outcome for _, outcome in outcomes}
    require("storage-full" in classes and "admitted" in classes, f"enospc: outcomes {outcomes}")
    admitted, _, view = m.verify("enospc.verify", image)
    require(view["admitted"] == admitted, "enospc: host disagrees")
    print(f"FS ENOSPC SAFE OK outcomes={outcomes} temp_files={len(view['temp_files'])}")
    print("SQLITE ENOSPC SAFE OK")


def scenario_equivalence(m):
    image = m.image("equivalence")
    captured, _ = m.orderly("equivalence.init", step(1, flags=MIRROR, count=3), image)
    captured, _ = m.orderly("equivalence.more", step(2, flags=MIRROR, count=2), image)
    require("AG STORAGE EQUIVALENCE OK admitted=3" in captured, f"equivalence after 3\n{captured}")
    captured, _ = m.orderly("equivalence.verify", step(3, flags=MIRROR), image)
    found = re.findall(r"AG STORAGE EQUIVALENCE OK admitted=(\d+) authority=([0-9a-f]{64})", captured)
    require(found and found[0][0] == "5", f"equivalence after 5\n{captured}")
    view = m.host("equivalence", image)
    require(view["authority"] == found[0][1], "equivalence: host authority differs from both stores")
    # A crash between the two stores' commits leaves them one admission
    # apart, never disagreeing on their common history.
    split = m.image("equivalence-split", image)
    m.stopped("equivalence.split", step(2, flags=MIRROR, count=1, writes=SPLIT), split)
    captured, _ = m.orderly("equivalence.split.recover", step(3, flags=MIRROR), split)
    require("AG STORAGE PREFIX OK sqlite=6 route_b=5" in captured, f"equivalence.split\n{captured}")
    print(f"AG STORAGE EQUIVALENCE OK admitted=5 authority={found[0][1]}")


def resign(image, region, change):
    """Rewrite the selected metadata image through `change` with a valid
    digest and superblock, so only structural checks can refuse it."""
    data = bytearray(pathlib.Path(image).read_bytes())
    geo = absd_fs.geometry(region.sectors)
    sbs = [absd_fs.superblock(region.read(s), s, geo) for s in (0, 1)]
    newest = max(sbs, key=lambda sb: sb["seq"])
    slot = newest["seq"] % 2
    first = region.first + absd_fs.META_FIRST + slot * geo["half_sectors"]
    raw = bytearray(data[first * 512:first * 512 + newest["image_len"]])
    raw = change(raw)
    data[first * 512:first * 512 + geo["half_sectors"] * 512] = bytes(raw).ljust(geo["half_sectors"] * 512, b"\0")
    sector = bytearray(data[(region.first + slot) * 512:(region.first + slot + 1) * 512])
    struct.pack_into("<I", sector, 32, len(raw))
    sector[72:104] = hashlib.sha256(bytes(raw)).digest()
    sector[480:] = hashlib.sha256(bytes(sector[:480])).digest()
    data[(region.first + slot) * 512:(region.first + slot + 1) * 512] = sector
    pathlib.Path(image).write_bytes(bytes(data))


def records_at(raw):
    """(offset, fields) of each record in an encoded image."""
    count = struct.unpack_from("<I", raw, 44)[0]
    offset, out = absd_fs.HEADER_BYTES, []
    for _ in range(count):
        serial, parent, size, kind, flags, name_len, blocks = struct.unpack_from("<QQQBBHI", raw, offset)
        out.append((offset, serial, parent, size, kind, name_len, blocks))
        offset += absd_fs.RECORD_BYTES + name_len + 4 * blocks
    return out


def scenario_corruption(m, base):
    def file_record(raw, index=0):
        files = [r for r in records_at(raw) if r[4] == 1 and r[6] > 0]
        return files[index]

    def blocks_offset(rec):
        return rec[0] + absd_fs.RECORD_BYTES + rec[5]

    def dup_allocation(raw):
        a, b = file_record(raw, 0), file_record(raw, 1)
        raw[blocks_offset(b):blocks_offset(b) + 4] = raw[blocks_offset(a):blocks_offset(a) + 4]
        return raw

    def out_of_range(raw):
        rec = file_record(raw)
        struct.pack_into("<I", raw, blocks_offset(rec), 0xFFFFFF)
        return raw

    def impossible_length(raw):
        rec = file_record(raw)
        struct.pack_into("<Q", raw, rec[0] + 16, 10 ** 9)
        return raw

    def dangling(raw):
        rec = records_at(raw)[2]
        struct.pack_into("<Q", raw, rec[0] + 8, 999_999)
        return raw

    def malformed_name(raw):
        rec = records_at(raw)[2]
        raw[rec[0] + absd_fs.RECORD_BYTES] = ord("/")
        return raw

    def stale_serial(raw):
        struct.pack_into("<Q", raw, 32, records_at(raw)[-1][1])
        return raw

    def damaged_kind(raw):
        rec = records_at(raw)[2]
        raw[rec[0] + 24] = 7
        return raw

    region = absd_fs.fs_region(base, DEVICE_SECTORS)
    geo = absd_fs.geometry(region.sectors)
    newest = max((absd_fs.superblock(region.read(s), s, geo) for s in (0, 1)), key=lambda sb: sb["seq"])

    def flip(offset):
        def edit(image):
            data = bytearray(pathlib.Path(image).read_bytes())
            data[offset] ^= 0x01
            pathlib.Path(image).write_bytes(bytes(data))
        return edit

    newest_slot, older_slot = newest["seq"] % 2, (newest["seq"] + 1) % 2
    image_first = region.first + absd_fs.META_FIRST + newest_slot * geo["half_sectors"]
    cases = [
        ("newest-superblock", flip((region.first + newest_slot) * 512 + 30)),
        ("older-superblock", flip((region.first + older_slot) * 512 + 30)),
        ("image-byte", flip(image_first * 512 + 70)),
        ("duplicate-allocation", lambda image: resign(image, region, dup_allocation)),
        ("block-out-of-range", lambda image: resign(image, region, out_of_range)),
        ("impossible-length", lambda image: resign(image, region, impossible_length)),
        ("dangling-entry", lambda image: resign(image, region, dangling)),
        ("malformed-name", lambda image: resign(image, region, malformed_name)),
        ("stale-serial-counter", lambda image: resign(image, region, stale_serial)),
        ("damaged-object-kind", lambda image: resign(image, region, damaged_kind)),
    ]
    for label, edit in cases:
        image = m.image(f"corrupt-{label}", base)
        edit(image)
        try:
            absd_fs.ag_oracle(image, DEVICE_SECTORS)
            fail(f"corrupt-{label}: host parser accepted the fixture")
        except absd_fs.Refused:
            pass
        m.refused(f"corrupt-{label}", step(3), image, "Corrupt(")
    print(f"FS CORRUPTION REFUSED OK cases={len(cases)}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--elf", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--deep", action="store_true", help="every crash point, not a sample")
    parser.add_argument("--only", default="")
    args = parser.parse_args()
    m = Matrix(args)
    only = set(filter(None, args.only.split(",")))

    def wanted(name):
        return not only or name in only

    base = m.image("base")
    captured, _ = m.orderly("base.init", step(1, count=2), base)
    require("FS MOUNT OK formatted=true" in captured, "base: filesystem was not formatted")
    admitted, authority, view = m.verify("base.verify", base)
    require(admitted == 2, f"base: admitted {admitted}")
    print(f"FS FORMAT OK FS MOUNT OK FS RECOVERY OK admitted={admitted}")
    probe = m.image("probe", base)
    captured, _ = m.orderly("probe.admit", step(2, count=1), probe)
    per_admission = writes_of(captured, 3)
    flushes = int(re.findall(r"AG ADMISSION FLUSHES admission=3 flushes=(\d+)", captured)[0])
    close_flushes = int(re.findall(r"AG SQLITE CLOSED FLUSHES flushes=(\d+)", captured)[0])
    amplification = re.findall(r"AG ADMISSION WRITES admission=3 writes=(\d+) commits=(\d+) image_bytes=(\d+)", captured)
    captured, _ = m.orderly("probe.close", step(2, count=1), probe)
    close_writes = int(re.findall(r"AG SQLITE CLOSED writes=(\d+)", captured)[0])
    if amplification:
        writes, commits, image_bytes = amplification[0]
        print(f"AG ADMISSION AMPLIFICATION writes={writes} commits={commits} image_bytes={image_bytes} "
              f"data_bytes={int(writes) * 512 - int(image_bytes) - int(commits) * 512}")
    if wanted("store"):
        scenario_store(m, base)
    if wanted("crash"):
        sweep(m, "crash-admission", base, 0, per_admission, "AG SQLITE CRASH RECOVERY OK")
    if wanted("close"):
        # Closing the last connection checkpoints the WAL into the database
        # and removes the WAL; crash anywhere in that.
        sweep(m, "crash-checkpoint", base, IN_CLOSE, close_writes, "AG SQLITE CHECKPOINT CRASH OK")
    if wanted("die"):
        sweep(m, "die-admission", base, DIE, per_admission, "AG PROCESS DEATH RECOVERY OK")
    if wanted("powercut"):
        scenario_powercut(m, base, per_admission, close_writes)
    if wanted("lock"):
        scenario_lock(m, base)
    if wanted("identity"):
        scenario_identity(m, base)
    if wanted("poison"):
        scenario_poison(m, base, flushes)
        scenario_poison_close(m, base, close_flushes)
    if wanted("authority"):
        scenario_authority(m, base)
    if wanted("enospc"):
        scenario_enospc(m, base)
    if wanted("equivalence"):
        scenario_equivalence(m)
    if wanted("corruption"):
        scenario_corruption(m, base)
    print(f"FS MATRIX OK boots={m.boots}")


if __name__ == "__main__":
    main()
