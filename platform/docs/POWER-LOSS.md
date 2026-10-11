# Block contract and power-loss device law

Status: frozen for the power-loss tranche (2026-09-25). This states what the
ABSD block device promises, what the tested crash model has so far relied
on, and the stronger device law the power-loss harness enforces.

## What the block device actually promises

1. **A completed write** (ATA `WRITE SECTORS` finished without ERR/DF) means
   the device accepted the sector. It is readable back at once. It is **not**
   a durability statement: ATA devices may hold it in a volatile write cache.
   Under QEMU 8.2 with `-drive format=raw,if=ide` (default `cache=writeback`,
   `aio=threads`) completion means QEMU's host `pwrite` returned, so the bytes
   sit in the host page cache: they survive a QEMU exit, not host power loss.
2. **A completed flush** (ATA `FLUSH CACHE`) means every write completed before
   the flush was issued is on stable media. Under QEMU this is a host
   `fdatasync` of the image file.
3. ABSD exposes write, read, and flush. There is no FUA, no barrier other
   than flush, and no ordering promise between unflushed writes.
4. **Atomicity** is not stated by ATA. It is **assumed** here that a device
   writes an aligned physical unit (512 bytes, or 4 KiB on 4Kn/512e media;
   NVMe reports its guarantee as AWUPF) all or nothing. On 512e media a 512-byte write is a read-modify-write of the 4 KiB
   physical unit, which is still atomic as a unit.
5. **QEMU artifacts** the earlier crash model relied on: "acknowledged sectors
   retained, in issue order" is true only because killing QEMU leaves the host
   page cache intact. Nothing in ABSD's own contract gives it.

## What the filesystem and SQLite rely on

- Commit writes the image, flushes, writes the superblock sector, flushes. A
  data write before a commit is covered by the commit's first flush. So the
  filesystem relies on **flush ordering only**, never on the order of
  unflushed writes.
- It relies on the **superblock write being atomic**: the commit sector is
  either the old or the new version. Superblock slots 0 and 1 are adjacent
  sectors, so on 4 KiB-unit media they share one physical unit.
- SQLite `synchronous=FULL` relies on `xSync` returning only when prior writes
  are durable (the commit's final flush) and on nothing reaching stable
  storage out of order across an `xSync` (flush ordering). The VFS claims
  `POWERSAFE_OVERWRITE`: a write never changes bytes outside its range. That
  holds under unit atomicity; it fails only for a torn unit.

## Device law for the harness

Units: aligned groups of `U` sectors, `U = 1` (512 B) or `U = 8` (4 KiB).

- A write replaces its sector in the unit's cached image (read-modify-write
  of the unit) and completes at once.
- A completed flush makes every unit's cached image stable.
- **Power cut:** each unit written since the last completed flush ends up in
  any one of its states since that flush: its stable state, or its image after
  any one of the writes to it. Units are chosen independently, which covers
  loss of any subset of unflushed writes and any reordering among them.
  Units not written since the flush keep their stable state.
- A failed flush completes nothing: the device is poisoned for the process.
- **Excluded by the law:** a torn unit (content that is none of its states),
  and loss of anything a completed flush covered. The torn unit is tested
  separately, only to characterize what mount does, and is not part of
  any claim.

## What a passing campaign would justify

"On a block device whose volatile cache may lose or reorder any writes not
covered by a completed flush, and which writes each aligned 512-byte or 4 KiB
unit atomically, a power cut at any point leaves the ABSD filesystem mounting
exactly one committed state (the last acknowledged sync, or the one whose
commit was in flight), and the AG store recovering its committed authority."
It would not cover media that tear units, media corruption, or any claim about
a specific drive honouring `FLUSH CACHE`.

## Result (2026-09-25): outcome A, the format survives unchanged

- **Host, every cut point, every or a sample of the legal outcomes** (`fs/src/tests.rs`,
  `device_law_*`): for each namespace operation, write/truncate/grow with
  sync, AG's blob installation sequence, format, and 12 random 30-operation
  histories, at `U = 1` and `U = 8`, the choice of every dirty unit's version
  is enumerated when there are at most 4096 combinations and otherwise
  sampled (256, always including all-stable and all-latest): about 1.6
  million judged outcomes. Every one mounts, names either the last commit
  whose final flush completed or the commit whose superblock write was
  already issued, matches that commit's namespace, serials, kinds, sizes, and
  read-only flags exactly, and keeps every synced object's content exact.
  Negative control: removing the flush between the image and the superblock
  makes the test fail (a new superblock over a lost image).
- **Guest, below the filesystem** (`storage::arm_power_cut`, fs-matrix
  `powercut`): 66 cuts inside an admission and inside the checkpoint on
  close, five policies (all lost, all kept, three per-unit mixes), both unit
  sizes. The AG store always recovers either the prior or the new authority
  (asserted exactly, lost for all-lost and kept for all-kept, only at the
  cut of the commit's final flush), an acknowledged admission always
  survives the checkpoint's reordering, and the host reader, host SQLite, and authority
  digest agree after every cut.
- **Torn unit (outside the law, characterized only):** a garbage superblock
  is always refused (`superblock checksum`, or `one superblock slot is blank`
  for zeros); a torn image sector or data unit never yields a mixed
  generation: mount gives the old commit, or garbage only inside an object
  with an unsynced write. With 4 KiB units the two superblock slots share
  one unit, so one torn unit destroys both.
- Filesystem format 2 (`mtime`, 40-byte object records; `FILESYSTEM.md`)
  changes what an image contains, not how it is committed: the commit
  protocol and the law are unchanged, the host sweeps above pass on format
  2 unmodified, and the guest results were measured on format 1.

### Torn commit sector: the safety and availability tradeoff

Mount refuses when either superblock is invalid. Falling back to the other
slot would be safe after a torn commit write (that commit never returned, its
half is untouched, and no block it freed has been reused), but a torn write
and later corruption of a committed newest superblock look identical, and
after corruption the fallback silently rolls back an acknowledged sync onto
blocks that may have been reused. Refusal is therefore kept: a torn commit
sector costs availability (an operator must intervene), never correctness.
A safe fallback would need blocks freed by commit N+1 to stay unreused until
N+2 is durable, plus slots in separate physical units; that trades silent
rollback of a corrupted newest superblock for availability, a product
decision not taken here. The law's claim therefore rests on the stated
assumption that the device writes an aligned 512-byte or 4 KiB unit
atomically (NVMe reports this as AWUPF; ATA does not state it).

### Review fixes (Opus hostile review)

- Free-after-commit was not exercised: the harness skipped the content of a
  truncated object and random histories never wrap the allocator, so reusing
  a truncated file's blocks before its commit passed every test. A shrink is
  no longer counted as a data write, and a directed test fills the data area,
  truncates, grows another file, and crashes; it fails on that mutant.
  Tripwire: the random histories still never wrap the allocator.
- A writable mount now flushes before selecting a superblock, so a
  replacement worker acts only on durable state, not on a superblock its
  predecessor left in a volatile cache.
- A flush failing during the close (SQLite's checkpoint) now also makes the
  worker exit for replacement; `poison` covers every flush of an admission
  and of the close.
- The guest model asserts it is armed only right after a completed flush.
- Tripwires: guest coverage is sampled (a few write points per admission and
  close); the content of objects written since the last commit is not
  checked against the law's per-unit images.

### Write amplification (tripwire metric)

One AG admission over a 9-object namespace: 197 sector writes, 7 commits,
each rewriting the whole 719-byte image (2 sectors) plus one superblock:
11 of 197 sectors (5.6%) are metadata. Whole-image commits cost
O(namespace) per commit; revisit only when a workload's namespace makes that
fraction material.
