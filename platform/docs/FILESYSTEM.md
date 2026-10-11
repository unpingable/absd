# Experimental ABSD filesystem (format 2)

Status: **experimental**. The current format is 2 ("Format 2" below): the
library mounts nothing else. Format 1 is still read by the host reader
(`scripts/absd_fs.py`) and by nothing on the target; a format change is a
host-side migration into a new image, never an in-place upgrade.

The filesystem exists because AG's real SQLite store needs it (see the route
decision in the kernel's `docs/DURABLE-JOURNAL.md`). It implements exactly the
naming, identity, installation, sync, and locking semantics that workload
demonstrated, and nothing else.

> **Present design invariant: exclusive writer.** Any check-then-act
> sequence in the filesystem, the SQLite VFS, or their callers that is not
> itself one atomic operation is sound only because exactly one process
> writes the filesystem region: init hands the read-write block handle to
> one worker at a time, or, in an `fsd` boot, to the file server
> (`absd-fsd`), which alone links the library over it; everyone else gets
> a read-only duplicate or a file server channel. The server trigger has
> fired (below); the revalidation is recorded under "File server".

## Placement

A userspace library (`fs/`, crate `absd-fs`) linked into the one process that
holds the block handle. The kernel is unchanged: it still exports a bounded
block object with read, write, flush, and handle rights. Init hands the
read-write handle to one process at a time: in a qualification durable boot
to one worker, with a replacement only after the previous worker's exit; in
an `fsd` boot to the file server for the whole boot, so a served generation
is replaced only by a machine reset (kernel `docs/PROCESS-STARTUP.md`,
"Served boot and orderly shutdown"). One process's memory is the whole lock
and open-handle state. The `std::fs` PAL forwards to runtime hooks
(`runtime/src/storage.rs`); SQLite uses a native VFS (`sqlite/`) over the same
mounted instance. `absd-fs` is `no_std` behind a four-method sector-device
trait, so its host tests enumerate every crash point of every operation
(the rump-kernel pattern from `DESIGN-INFLUENCES.md`, now triggered).

Server tripwire (fired 2026-09-26; measured by `fs/tests/multiwriter.rs`
and `scripts/fsx-experiment.py`): SSH sessions must write, at
the same time, with authority narrower than the device. Two processes
that each mount one region writable lose updates, alias blocks, and can
leave a superblock pair no mount accepts, silently; a reader beside a
writer reads reused blocks. So in an `fsd` boot the library is linked
into one server process and nowhere else.

## File server

`absd-fsd` (`fsd/`: protocol, mount lists, dispatcher, host-tested;
`ssh/src/fsd_main.rs`: the process) serves every other process over pipe
channels init minted at boot. Each channel carries a mount list and an
open-file table in the server; clients send paths and their own handle
numbers, never block addresses. The `std::fs` hooks of a process whose
startup record names channels and no block handle go there
(`runtime/src/fsd.rs`).

Revalidation of the exclusive-writer invariant for this shape:

- One request is one library call (or, for `close` of a written file, a
  call and a commit), run to completion before the next request of any
  channel. Every client therefore sees one namespace and one set of file
  contents; a stale view does not exist.
- Concurrent mutation is defined by that order: `write_at` requests are
  applied whole, the later one winning for the bytes both cover; create
  with `create_new` has exactly one winner (the other gets `-17`); rename
  replaces atomically and no-clobber rename refuses; locks are the
  library's per-handle `flock` locks across all channels. A client's own
  sequence of requests (stat, then create) is not atomic against another
  client's, exactly as on Unix; the atomic primitives above are what a
  client relies on. Nothing was added to make tests pass.
- Durability: namespace changes commit before the reply, as before; file
  data commits when its writer closes it, on `sync`, when a session is
  released, and at most 200 ms (`COMMIT_TICKS`) after an unsynced write.
- A session killed mid-write leaves every whole `write_at` it sent and
  nothing of a request cut off mid-frame; the release commits what it
  wrote. Every frame carries its holder's sequence word and a check over
  the whole frame (`fsd/src/proto.rs`), so the bytes a dead holder left
  can never be completed by the next holder's, on a lent channel included:
  the hybrid fails its check and is dropped, and the next holder's whole
  request is found behind it. Bytes that are no frame (`fsd-probe
  garbage`) are dropped the same way; nothing is dropped while the frame
  at the head may still complete, so a slow writer is never cut off. A
  release discards no whole request the session sent while bound: one
  still waiting is read and refused (`-13`); once the released channel is
  quiet, what can never complete is dropped and the channel settles. Only
  the slot's next binding discards what predates it (`fsd/src/inbox.rs`,
  `Server::release` and `Server::bind`). Before it first serves, the file
  server sweeps `/tmp` whole (`FSD SWEEP`), so scratch of sessions a reset
  left bound does not outlive their boot, and it keeps a reserve of the
  object budget (`SCRATCH_RESERVE`) that only a session's scratch
  directory may use, so a filesystem the sessions filled still binds a
  session for the operator to delete from.
- The SQLite VFS still needs a mount in its own process (`with_fs`); SQLite
  over a file server channel is not built.

## On-disk layout

Layout version 3 gives the second half of the device to one filesystem
region. Inside it:

| Sectors | Content |
| --- | --- |
| 0, 1 | superblock slots (sequence parity selects the slot) |
| 2..8 | zero |
| 8.. | metadata half 0, then half 1 |
| data_first.. | 4 KiB data blocks |

A superblock names a sequence, the image length and SHA-256, the fs instance
id, and the geometry, and carries its own SHA-256. The **metadata image** is
the whole namespace: header (fs id, sequence, next object serial) and one
record per named object `{serial, parent serial, size, kind, read-only,
mtime, name, block list}`. There is no allocation bitmap: the allocated set is the
union of referenced blocks, and a duplicate or out-of-range reference refuses
the mount.

## Format 2

Format 2 is format 1 with an explicit version and one new field per
object (`docs/RELEASE.md` section 6 in the coordination tree has the
release side):

- The superblock magic is `ABSDFSS2` and the image magic `ABSDFSI2`; the
  version word after each (offset 8, `u32`) is 2. Format 1 was
  `ABSDFSS1`/`ABSDFSI1` and 1.
- An object record grows from 32 to 40 fixed bytes: `serial`, `parent`,
  `size` (u64 each), `kind` (u8), `read-only` (u8), name length (u16),
  block count (u32), then `mtime` (u64) at offset 32, then the name and the
  block list. Everything else (header, superblock, geometry, commit) is
  unchanged.
- The object budget stays 64 KiB and counts 40 bytes plus the name per
  object (`record_bytes`), so the same region holds fewer objects than
  under format 1 (about 1,300 objects with 10-byte names instead of 1,560). The
  host reader counts the same way for each format.

**Refusal.** A superblock of the family (`ABSDFSS` and a version digit)
with any other digit, or `ABSDFSS2` whose checksum holds but whose version
word is not 2, is `Error::UnsupportedFormat`: named, distinct from
`Corrupt`, errno `-95` from the file server and the runtime. Mount never
reads such a region, never repairs it, and never falls back; `format`
refuses it as not blank, and a served boot stops with `FSD FAILED mount:
UnsupportedFormat: ...` instead of formatting. A format-2 superblock that
fails its checksum is still `Corrupt`. Every structural check of format 1
holds unchanged.

**`mtime`.** Unix seconds of the last change to a file's content or size,
or to a directory's entries. The value comes from a clock the caller sets
(`Fs::set_clock`); the library never reads one. 0 means unknown, never the
epoch: it is what an operation records when the clock is unavailable or
refused, and what every object gets from a process that sets no clock.

- Set: at creation (create, mkdir); on `write_at` that changes the size or
  any byte in its range; on `set_len` (and open with truncate) that
  changes the size; on the parent directory for create, mkdir, unlink,
  rmdir, and tree removal (the surviving directory whose entries changed);
  on both parents for rename. A rewrite of identical bytes is no change:
  the library compares the bytes it is about to write with the device's,
  sector by sector, and only while the new `mtime` would differ from the
  stored one, so a burst of writes in one second costs at most one
  comparison read per sector until the first difference. `set_len` to the
  current size, and an empty write, change nothing.
- Not set: on the renamed object itself, on `set_readonly`, on open, read,
  stat, sync, or close.
- Durability: like size, an `mtime` changed by a write is made durable by
  the next commit; an in-place write that changes `mtime` makes the next
  sync a commit instead of only a flush (at most once per object per clock
  value). The crash and power-loss sweeps run with no clock, so they judge
  the same images as before; mtime itself is covered by unit tests.
- Clock: only the file server sets it, from the kernel's `wall_clock`
  (CMOS RTC, whole seconds, UTC), before each request and before its own
  work (startup directories, sweeps, releases, its log). A reading is
  reused for changes within 250 ticks (`CLOCK_TICKS`, about 250 ms), so a
  value lags the RTC by less than that plus the RTC's own second. Processes
  that link the library directly (the image importer, durable workers in
  non-`fsd` boots) record 0.
- Exposed in the file server's `attr` payload (`fsd/src/proto.rs`,
  `ATTR_BYTES` 48, the last word), and by the host reader as each record's
  `mtime` (`None` for format-1 records, which have none). No access or
  change time exists.

**Migration** is host-side and never in place: read the old image with
the host reader (which reads format 1), create a new image with the new
release's importer (format 2), copy every file across, validate the new
image with the reader, and switch to it, keeping the old image as the only
way back. The importer sets no clock, so migrated objects get `mtime` 0.
The library has no format-1 code path at all; the fixture
`fs/testdata/format1.sectors`, written by the format-1 library, is the
evidence that it refuses one.

## Commit and recovery

Commit N+1 writes the whole image into half (N+1) mod 2, flushes, writes
superblock slot (N+1) mod 2, and flushes. That one sector write is the
linearization and durability point. Mount requires both superblocks valid
with consecutive sequences, takes the newer, and requires its image to match
its digest and pass every structural check (root, parents, cycles, unique
names, name syntax, block ownership, `blocks == ceil(size / 4096)`, serial
counter above every serial). Anything else is **refused**; mount never
repairs and never falls back to the older superblock, whose half and blocks
may already be reused. The one state treated as unformatted besides two
blank slots is an interrupted format (slot 0 at sequence 0, slot 1 blank):
it committed nothing, and format may overwrite the superblock slots and
metadata halves it left, still refusing any nonzero data sector.

Free-after-commit: a block dropped in memory (truncate, unlink, replaced
rename target) becomes allocatable only after the commit that drops it is
durable. An object unlinked while open keeps its blocks in memory until its
last handle closes and is absent from every image.

The object-record budget (64 KiB) plus 4 bytes per data block of capacity
fits in one half by construction, so a sync can never fail for metadata
space; namespace operations past the budget fail with `StorageFull`.

## Operation contract

| Operation | Returns after | Crash before return | Crash after return |
| --- | --- | --- | --- |
| create (incl. `create_new`), mkdir, unlink, rmdir, rename, rename-no-clobber, set read-only | commit | old namespace | new namespace |
| write | data acknowledged by the device | any prefix of the written sectors may be visible (in-order model); any subset of written units (power-loss law) | same, until a sync |
| set_len / growth | memory only | old length | old length until a sync |
| sync (file or directory, any object) | commit of everything pending + flush | as before the sync | every completed write and length durable |

A directory sync therefore has nothing left to do; it is still a commit or a
flush. Growth zero-fills newly exposed bytes; a write never changes bytes
outside its range (sector read-modify-write on an atomic-sector device), which
is SQLite's `POWERSAFE_OVERWRITE`. File data has no checksum: metadata
corruption is refused, content corruption is not detected by the filesystem
(SQLite WAL frames and AG's blob digests detect their own).

Rename is one commit: after a crash the namespace is the old one or the new
one, never one missing both names and never a partial file under the final
name. No-clobber rename checks absence and moves in that same commit and
fails with `AlreadyExists` otherwise. A replacing rename (file over file)
detaches the target in the same commit.

## Identity

An object is `(filesystem id, serial)`. The id is random at format; serials
come from a persisted counter and are never reused, whatever storage a new
object lands on. Link count is 1 while named and 0 once unlinked but open.
AG's platform seam reports these as `dev`, `ino`, and `nlink`. ABSD has no
owners: `uid` and `gid` are 0 for every object, and the only permission is
read-only, reported by AG's seam as mode `0o400` (read-only) or `0o600`.
Nightshift's seam reports `0o444` or `0o666` instead: any process holding
the storage handle reads every file, so its checks that a credential is
private to its owner refuse rather than pass. `O_NOFOLLOW` and
`O_CLOEXEC` carry no bits: there are no symlinks and no exec.
Canonicalization is path normalization of an existing object; `.` and `..`
are invalid path components, and paths are absolute.

## Rights are checked at each operation

Every write, resize, and namespace change checks the handle's rights and
the object's current state (read-only flag, kind, poisoned mount) when it
runs; nothing relies on an earlier check. Making an object read-only
therefore withdraws writing from handles opened before it. Handles are
process memory and die with the process, so no restart can revive one; a
handle names an object (serial), not a path, so it can never act on a later
object at the same name. Check-then-act sequences that are not one
operation (rename-no-clobber is: existence check and move are one commit)
rely on the exclusive-writer rule init enforces: no other process holds a
write-capable handle to the region, so nothing can intervene between them.

## Locks

`std::fs::File::{lock, try_lock, lock_shared, unlock}` are flock-shaped
advisory locks per open handle, held in process memory, released by unlock,
close, or process death, never persisted. There is no waiting: contention is
`WouldBlock` (a single-threaded process would wait forever). AG's writer
fence (`Flock::lock(.., LockExclusiveNonblock)`) maps onto `try_lock`.

## SQLite VFS

SQLite is the bundled 3.49.2 amalgamation built with `SQLITE_OS_OTHER`,
`SQLITE_OMIT_LOCALTIME`, and `SQLITE_OMIT_LOAD_EXTENSION`; everything else is
rusqlite's configuration. The `absd` VFS maps: files to filesystem files by
absolute path; `xSync` to a filesystem sync; `xDelete` to unlink (durable on
return); `xAccess(EXISTS)` false for empty files as in the Unix VFS; SQLite's
five-level file locks to a per-serial table in memory; WAL shared memory to
zeroed heap regions per database serial, shared by the process's
connections and discarded when the last detaches (a fresh wal-index is
rebuilt from the WAL, as after any crash; there is no `-shm` file);
`xRandomness` to RDRAND; `xSleep` returns at once (nothing else in the
process can release a lock, so `SQLITE_BUSY` after AG's busy timeout is an
application error, reached quickly); `xCurrentTime` fails (no wall clock).
Region memory is allocated per 32 KiB region and never moves while mapped. Unnamed temporary files live in memory. SQLite's mutexes are
real ownership counters (rusqlite refuses no-op mutexes); the process has one
thread, so contention aborts.

## Explicit non-features

Not in the format or the library, and not provided above it: symlinks,
hard links, owners, groups, modes beyond read-only, timestamps other than
`mtime` (no change, access, or creation time is recorded),
sparse files, extended attributes, ACLs, quotas, device nodes, sockets or
pipes in the namespace, mmap, directory renames over existing
directories, read-only directories, and any repair tool (on the target or
the host: `scripts/absd_fs.py` reads only an image the mount accepts, or
a format-1 image that passes the same checks).

Not in the library, but provided above it (so not non-features of the
system): mounts, as the file server's per-channel mount lists
(`fsd/`, README "Storage for SSH sessions"); a current directory and
relative paths, resolved by each process's runtime (`runtime/src/cwd.rs`)
before a request leaves it; and executable loading from the filesystem,
where the runtime reads the image through `std::fs` and the kernel's
`spawn_image` starts it (kernel `docs/PROCESS-STARTUP.md`). The library
itself still sees only absolute paths and never executes anything.

## Failure model

Two models are qualified. First, abrupt loss of all guest volatile state (or
of just the worker process) with every device-acknowledged sector retained
and applied in order. Second, the power-loss device law in
[POWER-LOSS.md](POWER-LOSS.md): any write not covered by a completed flush
may be lost or reordered, per aligned 512-byte or 4 KiB unit, which the
device must write atomically. The second is enforced by a model below the
filesystem, on the host and in the guest; no real power was cut, no
particular drive's honouring of `FLUSH CACHE` is claimed, and a torn unit
(outside the law) makes a torn superblock refuse the mount.

A device failure poisons the mount. The AG workload then exits for
replacement instead of continuing, also when the failure happens while it
closes the store: it cannot know whether its last commit reached the device.
A writable mount flushes before it selects a superblock, so init's
replacement acts only on state the device has made durable.

**Device runs.** The library hands the device runs of up to eight
consecutive sectors (`Device::read_run`/`write_run`): a metadata half in
page-sized pieces, a file's bytes one run per 4 KiB block (never crossing
a block), and format's blank scan in eight-sector steps from wherever it
starts. On ABSD a run is one `block_read_many`/`block_write_many` request
(syscalls 43 and 44), one device command instead of eight; a kernel
without them answers `-38` and the runtime falls back to single sectors
for the rest of the process. A run is not atomic. After a failed write
some subset of its sectors is on the device (a leading run on ATA PIO and
on QEMU's NVMe model, which is what a failed sequence of single writes
could already leave; the NVMe specification promises no prefix), and the
library treats every case alike: the mount is poisoned, the
superblocks and the committed metadata half are untouched, and file bytes
being rewritten in place, committed or not, are indeterminate per sector
until the next commit, as before. Blocks are region-relative: the layout
puts the filesystem region at half the device, which need not be a
multiple of eight sectors, so a run is eight sectors of the medium, not
necessarily one aligned page of it; nothing here relies on page-aligned
tearing. The crash and power-loss sweeps keep their sector-granular
points: a stop or cut armed inside a run makes the runtime issue that run
sector by sector, and a cut's history records every sector of a run, so
the cut resolves each unit of it independently, as for single writes.

## Recorded tripwires

- A crash between AG's temp-blob create (a committed namespace change) and
  its no-clobber rename leaves `/ag/blobs/xx/.tmp*`; AG never removes them.
  Each holds object-record budget and blocks, so repeated crashes could end
  in `StorageFull`. The crash sweeps report how many they left.
- AG's offline backup publication seals directories read-only (`0o555`);
  ABSD has no read-only directories, so that path fails closed. The
  workload does not use it.
- The host oracle reads the database and its WAL only; a rollback-journal
  database with a live `-journal` would need it too. AG enables WAL before
  creating its schema, so this does not arise.
- A sync whose superblock write lands before a reported flush error makes
  a transaction SQLite reported as failed durable: an ambiguous outcome, at
  most one admission ahead of what the worker acknowledged.
