# Durable append substrate: implementation note

## What the real Pulse journal requires (source archaeology)

`pulse-runtime/src/journal.rs` (`HistoricalJournal`, pinned Pulse `81c2354`):

- One append-only byte sequence per journal. No rotation, rename, seek,
  truncate, or multiple files. The path is chosen by the caller.
- Record = data frame (95-byte header with magic, version, kind, sequence,
  payload length, prior-frame digest; JSON payload; 79-byte trailer with
  magic and frame digest) followed by a separate 158-byte commit marker
  (magic, sequence, frame digest, commit checksum).
- Append order: header, payload, trailer (each written in two halves with a
  hook between), `flush`, `sync_data`/`sync_all`, commit marker in two halves,
  `flush`, sync, then the acknowledgement is constructed. A record is
  committed only when its commit marker is complete and binds the frame.
- Recovery: read the whole file, scan from byte 0 with expected sequence 1
  and the genesis prior digest; stop at the first defect. Torn or missing
  suffix after at least one committed record -> `RecoveredThroughValidPrefix`
  (history projectable, not appendable, operator action). Interior defect or
  damage before the first record -> `Refused`. Exact EOF -> `Clean`.
- Identity: contiguous `record_sequence` from 1, prior-digest chain, and
  immutable payload identities (event/receipt id) that must not repeat.
  Replay is idempotent through `project_history` dedup on those identities.
- Filesystem surface actually used: `OpenOptions::create_new/append/read`,
  `write_all`, `flush` (no-op on `File`), `sync_data`, `sync_all`,
  `metadata().len()`, `read_to_end`, and `File::open(parent).sync_all()`.
  The parent-directory sync is only "the name binding is durable".
- `std::time::Instant::now()` is used for latency metrics inside `append`.

Application-required semantics: append, observed length, read-all, a
durability barrier at two points per record. Unix-shaped details: pathnames,
directories, seekable offsets, permissions, `create_new` on a namespace.

## Persistent medium

QEMU `-drive if=ide,index=0,format=raw` on the piix3 primary channel, driven
by polled ATA PIO (LBA28, 512-byte sectors, `READ SECTORS`, `WRITE SECTORS`,
`FLUSH CACHE`, `IDENTIFY`). Chosen over virtio-blk because it needs no PCI
enumeration, no DMA-visible memory, no virtqueues, and no interrupt plumbing:
about 200 lines against roughly 600 plus a PCI scan. A write completes when
the device clears BSY after the host `write()` returned; FLUSH CACHE reaches
QEMU's `blk_flush` (host `fdatasync`). virtio-blk is the tripwire for a second
device or throughput need, not for this workload.

## Kernel substrate

`src/block.rs`: probe at boot (`BLOCK DEVICE OK sectors=N` or `block: no
device`), synchronous single-sector and bounded multi-sector read/write
(up to eight consecutive sectors in one device command), flush, error
detection. `Object::Block` with read/write rights; syscalls `block_info`,
`block_read`, `block_write`, `block_flush` (24..27), `block_read_many`,
`block_write_many` (43, 44) and `stop` (28, Durable boot mode only:
abrupt QEMU exit through the debug-exit device at a named point). Init gets
the block handle in RSI when a device is present.

## Failure model tested

Abrupt loss of all guest state (CPU, RAM, device registers) at a named
application point, via the debug-exit device, then a fresh QEMU process over
the same raw image. Every sector write the device acknowledged before the
stop is retained; nothing else is. FLUSH CACHE is issued and traced but adds
no observable distinction under this model, because QEMU's completion already
implies the host page cache holds the sector. Host power loss, volatile
device write caches, reordering, and sub-sector tearing are NOT modelled;
those cases are covered only by content-mutation fixtures on the image
between boots (truncated tail, zeroed commit marker, garbage suffix).

## Append region ("ledger")

The userspace-owned append region is the whole device minus nothing: bytes
map linearly onto sectors. The observed length after a restart is one past
the last nonzero byte. This is sound for the Pulse format because every
frame and every commit marker ends in a 71-byte ASCII digest, so a complete
record never ends in zero, and every torn-tail class the file scanner would
report maps to the same class or a shorter truncation of the same suffix.
The image must start zero-filled (`create_new` requires observed length 0).

## What the crash matrix established

Every one of Pulse's seven write stages, stopped abruptly during record 2 of
3, recovers as the scanner contract predicts: torn header, payload, trailer,
and commit marker, and the two uncommitted-suffix cases, leave record 1
committed and record 2 definitely absent; only the stop after the commit
marker's sync leaves record 2 committed. A stop inside the first record
refuses the journal (no valid prefix), and the verdict for every sequence is
INDETERMINATE. Content-mutation fixtures produce the classes the tested
failure model cannot: short garbage is an unexpected trailing suffix, long
garbage and a flipped payload byte are interior corruption (refused, no
projection), a zeroed commit marker is an uncommitted suffix. A torn journal
is never appendable until the documented operator repair truncates the
region to the valid prefix. Worker replacement inside one boot resumes from
the journal scan alone, including after an unacknowledged but synced commit,
and refuses a torn tail rather than truncating it.

Under this model the stages "frame written before sync" and "data frame
synced" are indistinguishable, as are "commit marker written" and "commit
marker synced": QEMU's completion already implies the host page cache holds
the sector. Distinguishing them needs a volatile-write-cache model that is
not modelled here.

## Not built, on purpose

No checkpoint or compaction: the pinned Pulse journal has no rotation or
compaction, so the checkpoint-under-crash question did not arise from the
workload. No second region, no names, no truncation API, no virtio.

## Formalization candidates (notes only, no Lean yet)

1. Recovery never classifies a sequence as committed unless the durable
   bytes reachable after reboot contain a complete data frame whose trailer
   digest matches its header and payload, followed by a complete commit
   marker binding that exact sequence and digest, with every earlier
   sequence committed and chained through the prior-frame digest.
2. Under the acknowledged-sector failure model, the observed length after
   reboot is at least the length of every acknowledged append, so an
   append whose acknowledgement was returned is always recovered as
   committed, and an append whose commit sync did not complete is never
   recovered as committed.
3. A replacement worker's first appended sequence is exactly one past the
   recovered committed prefix, so no committed sequence is repeated and no
   sequence is skipped across process replacement or machine restart.

## Adversarial review (Opus, 2026-09-24)

Question asked: can any ordering, crash, torn-write, stale-generation, or
flush assumption make recovery report a record committed without support,
or lose or double-apply a committed record? Result: nothing BLOCKING under
the tested model. Fixed at once: a failed device write left unacknowledged
bytes in the ledger's tail buffer that a later append could carry to disk
(now latched: appends refuse until a fresh scan); a `durable=` value above
2^56 lost its high bits in init's argument word (now refused at boot); the
leading records of a refused scan were labelled committed although the
contract only structurally validates them (now `VALIDATED_UNREPLAYABLE`).
Test gaps closed in the harness: a no-op flush would have passed (device
flush counts are now required), acknowledgement-to-recovery identity was
checked only by count, recovery boots were not required to be read-only,
and the operator repair offset was not checked against the bytes on disk.
Recorded tripwires, none of which the tested model exercises: the trailing
zero rule is specific to formats whose crash points never end in 0x00; the
tail sector rewrite could destroy a synced commit marker under host power
loss or a torn sector write; there is no "journal exists" bit, so a
never-created journal reads as clean and empty; any process in a durable
boot may call `stop`; nothing enforces a single writer; the image size and
Pulse's file bound are separate constants; a timed-out write may still land.
Not covered: device error injection and duplicate-identity refusal across a
retried append.

# Multi-region generations (second tranche, 2026-09-24)

## Persistent layout

Everything below the kernel's block object is userspace. Sector 0 of the
device holds a layout descriptor (`ABSDLAY1`, version, the device size it
was written for, a table of regions with explicit sector bounds, an FNV-1a
check). Zero sector 0 means unformatted; a descriptor for another device
size, an overlapping or out-of-bounds table, or a bad check refuses every
consumer. The fixed v1 table is: region 1 activation (sectors 1..3), region 2
the Pulse ledger (sector 16 to the first generation slot), regions 3 and 4
two equal generation slots (the last half of the device). Every read and
write is bounded by its region before the device is touched; there are no
names, paths, directories, or permissions. The kernel did not change for
this; only its block probe gained a two-process writer control.

## Generation protocol

A candidate is built in the region that does not hold the selected
generation: body sectors, flush, then a header (`ABSDGEN1`, generation
number, body length, body SHA-256, consumer tag, header SHA-256), flush, then
a read-back validation. Activation writes one record (`ABSDACT1`, activation
sequence, region id, generation number, body digest, record digest) into the
activation slot that does not hold the newest valid record, then flushes.
Recovery reads both slots and selects the highest-sequence record whose
named region holds a header and body that validate against it. A record
whose generation does not validate is skipped, so an older activation can be
selected and is reported as a rollback; with activation evidence but nothing
validating, recovery refuses. A generation number is never a selection
criterion by itself, and the newest generation number observed anywhere is
reported separately from the selected one so rollback protection can be
added later without changing the evidence.

## Reclamation rule

A region may be overwritten only when it does not hold the selected
generation, and the check is made against the device (a fresh selection),
not against memory. Reclamation zeroes the header first, so a half-reclaimed
region can never be selected. The stress cycle alternates the two regions
across activation and reclamation stops.

## Second consumer

The real AG authority state: the lifecycle origin plus every committed entry
of the four family books, canonicalized with the JCS encoding AG itself uses
for materialized state, replaced wholesale on every admission the way AG's
store replaces a materialized revision. Recovery replays the entries through
unmodified `ag-kernel` books and proves the latest crossing still admits and
reconstructs authority. It shares the device with the Pulse ledger; the
harness hashes each region on the host to show that neither consumer's boots
touch the other's bytes and that damage to one is invisible to the other.

## Crash model, unchanged

Abrupt loss of all guest state with every device-acknowledged sector
retained. The protocol keeps the write and flush steps distinct
(`ActivationWritten` and `ActivationFlushed` are separate points) even
though this model cannot tell them apart. Before any host-power-loss claim,
introduce a model in which acknowledged-but-unflushed writes can vanish or
reorder.

## Formalization candidates (notes only)

1. Activation never makes the previously selected generation unreachable
   until the candidate is itself recoverable: the candidate's header and body
   validate on the device before its activation record is written, and the
   previous region is only overwritten after a fresh selection names the
   candidate.
2. Recovery never selects a generation whose validity and activation are not
   both established by surviving bytes: selection requires a structurally
   valid activation record and a header and body that validate against it.
3. Activation never overwrites the activation record of the selected
   generation. The record goes into the slot that does not hold the
   *selected* record, which after a rollback is the slot of the newest,
   unusable record, not the slot the newest record left free.

## Generation review (2026-09-24)

An independent review of the generation protocol (platform repository, all
userspace) found one defect against rule 3 and several fail-closed gaps.
The platform fixes landed with the review patch and the generation matrix was rerun against them.

- Activation chose its slot as "not the newest structurally valid record".
  After a rollback that newest record is the unusable one, so the next
  activation overwrote the record of the selected generation. The candidate
  was valid, so selection stayed correct, but the fallback was gone: the
  next corruption of the new generation turned a rollback into a refusal
  with a valid older generation still on the device.
- `activate` did not re-validate the candidate on the device, so a candidate
  changed between `build` and `activate` could be activated. With the slot
  defect, that removed the only usable record.
- A read error on a generation region was treated as an invalid generation
  and skipped. That could select an older record and let `build` or
  `reclaim` target the newer generation. Device errors now fail selection
  closed.
- `build` and `reclaim` accepted any layout region (the ledger, the
  activation slots) and ran while recovery was refused.
- `Layout::format_v1` checked only sector 0. A lost descriptor over
  surviving activation records, generations, or ledger bytes was formatted
  into believed state. Formatting now requires a blank device.
- The descriptor accepted any valid table. Version 1 now requires exactly
  the v1 table for the device size, on the guest and in the host parser.

Recorded tripwires: the generation protocol assumes a single writer, and
the kernel enforces only handle rights (two writers interleaving `build`
and `reclaim` can refuse every generation); the activation record binds
the generation number and body digest but not the consumer tag; a torn or
damaged newest record is not reported as a rollback (compare
`newest_observed_generation`); a store failure does not latch the way the
ledger does; reclamation right after activation (workload mode 1) leaves no
fallback by design.

# Log plus checkpoint (third tranche, 2026-09-24)

## Route decision: FILESYSTEM TRIPWIRE FIRED for the real AG store

The pinned AG store (`ag-store` at `21c8da0`) cannot run over bounded regions
without a filesystem in disguise. From source: it refuses any journal mode
but WAL (`PRAGMA journal_mode=WAL`, error "SQLite refused WAL journal mode"),
which needs the `-wal` and `-shm` sidecars and shared memory; it fences its
single writer with an exclusive `flock` on a separate lock file; it binds the
database file to inode, device, uid, gid, mode and link count, opens with
`O_NOFOLLOW`, and requires the parent directory to canonicalize to itself; it
installs content-addressed blobs through `NamedTempFile` and
`persist_noclobber` (create, write, rename); its offline backup enumerates
directories, creates them, writes temp files and syncs parents. That is
multiple dynamically named durable objects, create/rename/unlink, a lock
namespace, directory enumeration and shared memory together. The real store
was therefore not ported (Route A). Route B was built instead: the same
storage shape with real AG semantics and an honest, non-AG format.

## Layout, version 2

Sector 0 descriptor as before; the table is now exactly: activation (2
sectors), Pulse ledger (sector 16 to the first quarter), four equal event-log
segments (second quarter), two generation slots (last half). Any other table
refuses. Formatting still requires an all-zero device.

## Event log

Each segment starts with a header (epoch, first sequence, digest). Events
are one header sector (sequence, length, body digest, header digest) plus
body sectors, appended write-through and flushed before the sequence is
returned. Live segments are ordered by epoch and must chain contiguously.
An incomplete record at the end of the newest segment is uncommitted and is
erased before the next append; damage anywhere else, a gap, or bytes after a
record refuse the log. A blank header over nonzero sectors is a reclaim that
lost the machine after zeroing the header: its parseable records are stale,
recovery refuses if any exceeds the checkpoint, otherwise the segment is
covered garbage finished by the next reclaim.

## Checkpoint, activation, retirement

A checkpoint is the whole AG authority image (origin plus every committed
entry, `admitted` = K) built and activated as a generation exactly as in the
second tranche. Recovery selects the checkpoint by the generation rule, then
requires every log event above K to be present and contiguous and replays
them through the real books, proving the latest admission; with no
checkpoint the log must start at 1. The retirement rule is executable:
`reclaimable(K)` names only non-current segments whose every event is at
most K, where K comes from a fresh device selection made after activation,
and reclaim zeroes the header first. Rotation opens a fresh segment after a
checkpoint so the covered segment stops growing and becomes reclaimable by
the next one, which bounds live segments to two in steady state.

## Worker replacement

Init now adds one to the step word's replacement digit instead of changing
its kind, so a replacement of any workload step knows it is a replacement
and resumes from the device: an AG worker that died after an acknowledged
event resumes at that count, one that died mid-append finds the torn record
uncommitted.

## Crash model, unchanged

Abrupt guest-state loss with acknowledged sectors retained, written in
order. Because body sectors reach the device in order, a torn append never
wrote its last body sector, so a final record whose digest fails but whose
last sector is nonzero is damage to a possibly acknowledged event and
refuses; only a final record whose last body sector is entirely zero is
treated as an uncommitted torn append and erased before the next append.
The review found and fixed a rotation that left such a torn record behind
(every later recovery refused a recoverable store), and recovery now also
requires the log's next sequence to follow the checkpoint plus its replayed
suffix exactly. Host power loss stays deferred behind the same trigger as
before.

## Tranche 4: a userspace filesystem for the real AG SQLite store

The tripwire recorded above led to the smallest filesystem the pinned AG
store demands, built in the Rust platform repository (`fs/`, documented in
its `docs/FILESYSTEM.md`). It is a userspace library linked into the one
process init gives the block handle to; this kernel is unchanged and still
exports only the bounded block object and handle rights. Placement follows
from the workload: AG runs one writer process, init's one-worker-at-a-time
exclusive-writer rule makes that process's memory the complete lock and SQLite
shared-memory state, and no second process needs the mounted filesystem, so
the filesystem-server tripwire has not fired. A read-only mount uses
`SYS_DUPLICATE` with read rights only, so the kernel refuses its writes.

A second durable process now exists: when a build embeds `external-reader`
(`EXTERNAL_READER_ELF`, with its own input), init runs it after the worker's
final outcome, clean or not, with a `SYS_DUPLICATE` of the block handle
narrowed to read and the same step cell. Before it starts, and before any
replacement worker, init requires that no descendant of the worker is still
live (`durable worker left a live descendant`), because an orphan would
still hold write rights. The reader is sequential, not concurrent, so
the exclusive-writer rule still holds. `make durable-reader-test` covers both
paths; Nightshift's resolver is the real reader (Rust platform repository,
`scripts/run-nightshift-matrix.sh`).

Format 1 (experimental, no compatibility promise) commits a whole metadata
image into the inactive of two halves and switches one superblock sector;
namespace operations are durable on return, file data is written through,
and a sync commits all pending lengths. Mount takes the newer of two
consecutive valid superblocks or refuses; it never repairs or rolls back.
Object identity is a filesystem id plus a never-reused serial. The real AG
store (`ag-store` at `21c8da0`, only its Unix imports swapped for a
platform seam) runs on it in WAL mode through a native SQLite VFS, survives
machine stops and worker deaths at every sampled filesystem write of an
admission and of the checkpoint on close, stays consistent under ENOSPC, and
reconstructs the same logical authority as Route B for the same history.

Recorded tripwires: a second process that must share the mounted
filesystem (server boundary); a claim beyond guest-state loss (host power
loss needs a model where acknowledged but unflushed writes may vanish or
reorder, and data blocks carry no checksum); executing programs from the
filesystem, which remains out of scope.
