# Writable entry and the recovery ledger

**Platform 14 does not support writable crash-resume.** An unclean image is
refused before writes, including ordinary restarts and host reconfiguration.
No automatic or unsafe fence-clearing mechanism is provided. A checked clean
shutdown permits writable restart; read-only extraction is a separate path.
“Crash = replace the machine” states the current limitation, not a qualified
recovery procedure. A replacement-and-restore must independently satisfy its
workload's state-preservation contract before it can be called recovery.
P14f is at best accepted with these limits, never as satisfying the original
writable crash-recovery guarantee. Bounded operator-attested writable recovery
is platform 15's "Operator-authorized resume" below (coordination record #63): an
explicit, recorded act bound to one committed state of one file, consumed
once by the next serving boot; an operator assertion alone is still
insufficient, and nothing is automatic.


This platform-14 contract implements the owner's storage-fence decision (b).
It applies to the file server's normal and finalizer writable mounts, with or
without `served`. Trusted direct-block construction and qualification tools
remain separate authorities; this is not a new restriction on every holder of
the kernel's generic block-write capability. Such a tool must not be used to
resume an unclean product image under a claim that this guard established a
device fence.

## Record v1

`/var/recovery.guard` is a private ordinary file of exactly 512 bytes, in one
preallocated filesystem block. Its entire first sector is one of these ASCII
lines followed by zero bytes to length 512:

```
absd-writable v1 fresh\n
absd-writable v1 dirty\n
absd-writable v1 clean\n
```

Here `\n` denotes one LF byte. No whitespace, version, length or padding
variation is accepted. The Rust and Python implementations independently
match the shared sectors in `fixtures/storage-fence/guard-v1-*.bin`.
Missing, truncated, read-only, malformed or unknown-version records refuse
writable entry. Runtime never creates, resizes, unlinks, renames or repairs
this file. A session cannot bind it or an ancestor in its mount list.

This extends the private recovery-state schema, without changing the
filesystem or device-layout format. It is not native Rust object layout.
A future version needs explicit conversion preconditions and qualification;
there is no automatic inverse or downgrade. An older platform ignores the
guard and does not provide this contract, even with a newer kernel.

## Construction and entry

Only the controlled fresh-image constructor seeds `fresh` on its exclusively
owned new disk. It finishes and verifies those
imports before starting a file server. Constructor failure does not publish a
bootable deployment. The SSH fixture and operator-image builders refuse an
existing output image instead of reseeding it. Reconfiguration never adds the
record. Existing images without it refuse ordinary updates and writable entry.
The explicit copy-only conversion below constructs a separate backing file;
adding a marker in place is not a fence. The same constructors seed the
resume slot `/var/recovery.resume` as `none` beside the guard.

Read-only assessment permits `fresh` only with an absent recovery ledger and
`clean` only with a completed predecessor. Every other combination refuses
before a writable mount and issues no write or flush. In particular, `dirty`
plus an absent ledger means an interrupted startup, not a first boot.

After assessment the writable mount retains its existing flush-before-mount
rule. Before any directory, host-key, log, ledger or user-data mutation, the
server rechecks the assessment, writes the same `dirty` sector, and flushes.
`Fs::transition_sector_marker` checks the exact old bytes and fixed allocation;
it writes no metadata and allocates nothing. If its write or flush fails,
the filesystem is poisoned and no other mutation follows. A delayed dirty
effect only writes the reserved marker. Ledger creation/charge follows arming
and precedes all other filesystem work, so failure before ledger creation
still leaves a dirty guard.

Neither `external` nor `controller` boot declarations prove command retirement.
NVMe disable cannot identify the backing service. The current kernel emits
no established fence, and the platform rejects unverified words from older
kernels too. There is no boot-argument override for a dirty or missing guard.

## Read-only extraction after refusal

The host reader in `scripts/absd_fs.py` reads the raw image into memory and
selects a committed filesystem view. `fs_region(image, device_sectors)` locates
the filesystem, `select(region)` validates and selects its records,
`tree(region, selected)` names the objects, and
`content(region, selected, record)` extracts the exact file bytes. These calls
open the input for reading and perform no image writes, guard transitions,
ledger repair or boot. Use the actual image geometry and a halted, exclusively
owned input so the read has one stable source identity. Extract only the
needed paths into appropriately private custody; an operator image also holds
private host-key material.

`scripts/core-fsd-recovery.py::refuse_recovery` demonstrates this path on each
of three deliberately interrupted images. It calls `AbsdTarget.tree()` before
the refused cold boot and again afterwards; that method uses the host reader
above. The full extracted path-to-bytes view must remain equal, then the
independent original content oracle is applied again to the extracted bytes:
whole previous or candidate data for an open unsynced write, exact committed
data for a synced write, and the exact replacement namespace for a rename.
The shared `storage_fence_guest.refused_cold_boot` also requires the named
failed boot, no readiness or reset, zero writes/flushes/errors and an unchanged
whole-image SHA-256. Thus the data check occurs after an actual refusal,
without clearing the fence. Each interruption case starts on its own freshly
constructed image; the next case never obtains write authority from a failed
predecessor.

This is bounded read-only data extraction, not writable crash-resume or a
qualified replacement-and-restore. It assumes the existing ordered guest-write
model and checks three histories; it establishes no physical storage fence or
exhaustive power-loss guarantee. The earlier core test expected a new writable
file server to serve the recovered bytes. That expectation and its failed run
remain historical evidence; these fence-specific tests qualify a narrower
contract. Candidate acceptance requires independent evidence for clean writable
restart, zero-write refusal, refusal of stale or unauthorized authority, and
read-only extraction, with the lost writable guarantee disclosed.

## Recovery budget under the fence

Owner decision, 2026-10-19 (coordination record #63): init's three-reset served
recovery budget is retained but inert. A served recovery reset is not a
finalized end, so the next generation is refused before readiness (status 7,
`RECOVERY WRITABLE REFUSED reason=storage_fence previous=failed fence=none`,
`FSD PROTOCOL REFUSED reason=no_server status=-5`, zero writes and flushes,
no further reset). The budget therefore never counts down past its first
reset and never reaches its named stop. Writable recovery after an unclean
stop is unsupported; #63 owns its future. The qualification harnesses
(`scripts/link-matrix.py` `disabled-nic-budget`, `scripts/survival-recovery.py`
fault loop) check the first fault and reset and then that refusal, and print
`AUTOMATIC WRITABLE RECOVERY UNSUPPORTED (owner 2026-10-19; #63: operator act
only)` for the countdown (the pinned helper `storage_fence_guest.py` keeps its
historical `WRITABLE RECOVERY UNSUPPORTED (owner 2026-10-19; #63)` text). That
line discloses a capability that cannot be exercised; it is never a pass. The
operator act of the next section is the only writable recovery.

## Operator-authorized resume (coordination record #63)

Path (e) of the contract, platform 15: an explicit, recorded operator
authorization that admits one unclean image once, for exactly the committed
state the operator saw. It changes nothing above: in the absence of a valid
authorization record every refusal stays as it is, and the new arm replaces
exactly the `(dirty, failed | not_ready)` refusal of the serving file server
when, and only when, a record checks. The finalizer, enrollment and bounded
updates never consult the record (`write_guard::Resume::Never`). The guard
stays `dirty` through the recovery and is cleaned only by the same-boot
finalizer after an orderly end. Nothing is automatic. Scope S-R1: a raw
regular image file on a local filesystem, attached as the primary IDE
master, booted by local QEMU with its default image locking, one host and
one user. No controller fence is claimed (the kernel keeps reporting
`fence=none`); NBD, shared storage, physical machines, interrupted first
starts, slot-less images and `restore --clone` are outside it.

### The record: `/var/recovery.resume` (schema v1, 512 bytes)

A second private fixed sector beside the guard, seeded `absd-resume v1
none\n` (zero-padded) by the fresh-image constructor (`release.py
install`, the SSH fixture, `operator_image.py build`), added to a clean
slot-less image by `release.py stage` and by the legacy converter, never
created, resized, renamed or removed by a running service, and refused in
any session's mount list. A record is one line, zero-padded, `fnv` the
FNV-1a 64 check of the preceding text:

```
absd-resume v1 id=<32 hex> fs=<16 hex> seq=<n> image=<64 hex> ledger_seq=<n> ledger_boot=<32 hex> previous=failed|not_ready time=<unix s> fnv=<16 hex>\n
```

Both encodings share the prefix `absd-resume v1 `; anything else at the
slot is corrupt: the guest refuses `RECOVERY STATE REFUSED
reason=resume_corrupt` before any write, the host classifies `corrupt-slot`,
and only `recover --revoke` rewrites `none`. Rust (`fsd/src/resume.rs`) and
Python (`scripts/storage_fence_state.py`) match the golden sectors
`fixtures/storage-fence/resume-v1-{none,record,torn-40,torn-200}.bin`.

The guest admits a dirty guard with history `failed` or `not_ready` only if
the record's five fields equal what its own read-only mount selected: the
filesystem identity (`Fs::fs_id`), the commit sequence (`Fs::sequence`),
the selected superblock's image digest (`Fs::image_digest`), and the
canonical ledger line's sequence and boot. Anything else is
`resume_mismatch`, refused before any write. On admission `begin` leaves
the guard alone and consumes the record (`transition_sector_marker(slot,
R, none)` plus its flush) as the first device write of the boot; a failed
write or flush poisons the mount and nothing else is written; a delayed
effect only writes `none`. Then `recovery::charge` and the line `RECOVERY
WRITABLE RESUMED id=<id> previous=<p> fs_seq=<n> ledger_seq=<m>` on the
console and in `/var/log/fsd`, before `FSD RECOVERY`, `RELEASE OK` and
`FSD READY`. After consumption the slot is `none` and the guard `dirty`, so
a successor is admitted only by the unchanged arms (`clean` + `ended` after
an orderly end) or by a new act.

### The act on the host

`python3 -I scripts/release.py recover --target OUT --attest-sole-instance
--accept-committed-state --reason TEXT` (`scripts/storage_fence_resume.py`
holds the mechanism). In order, each a named refusal before any write:
the image opened `O_RDWR|O_NOFOLLOW` and checked (a regular file, one
link, the layout's size, a local filesystem by `statfs`: `image_not_regular`,
`image_linked`, `image_size`, `image_not_local`); the recovery lock
`OUT/recovery/lock` (`flock`, `tool_busy`); QEMU's own OFD write lock over
bytes 100-299 of the image, held for the whole act (`image_locked` while
any default-locking QEMU holds the image, running, paused or stopped, by
any user; the refusal lists the holders the `/proc` scan sees, or
`unknown`); no other holder (`/proc`, `image_in_use`, the tool's own one
descriptor excluded); the independent host reader, with no repair (the
superblocks and image digest, every structural check, every file's bytes:
`host_reader_refused`; the ledger and facts: `recovery_state_refused:
corrupt | lost | uninitialized_ledger`, `first_boot_interrupted`); the
guard read as the guest reads it (one sector, not read-only, else
`guard_corrupt`) and exactly `dirty` (`not_unclean` otherwise), the history
`failed` or `not_ready`. A failed `pwrite` of the record is
`slot_write_failed` (nothing published); a failed `fsync` or readback is
`authorization_unverified` (`--status` then finalizes or reports the row
the landed bytes make). The act prints the summary (previous, boot, ledger sequence and
streak, the selected release, the file count, the newest files under
`/home/operator`, the unsynced-overwrite caveat) and then publishes, each
record by temp file, `fsync`, rename and directory `fsync`: the intent
`OUT/recovery/intent-<id>.toml` (F = `(st_dev, st_ino, size)`, Hm, the five
state fields, the planned bytes, both flags, the reason, user, tool and
platform commit); one 512-byte `pwrite` of the record at the slot (the
pathname's identity rechecked, the current bytes `none`), `fsync`, a
readback; Hm recomputed and equal; `OUT/recovery/active.toml` with
`state = "authorized"` (the publication of the authorization); the receipt
and the ledger line `recovered <release> id=<id> previous=<p>`. Console:
`RECOVERY AUTHORIZED id=… target=… previous=… fs_seq=… hm=…`.

Hm is the SHA-256 of the image with the slot's sector zeroed; with the
record it is the content commitment `(Hm, R)`, which holds while the record
is present because the recovery arm performs no protocol byte mutation while
the record remains. F is bound separately and evaluated first in every
classification.

### Launch, the launcher and every other tool

`scripts/boot-operator.sh` takes the recovery lock on an open descriptor
for its whole run, rotates the previous `OUT/console.log` to
`OUT/console-<time>.log`, runs the precheck (`storage_fence_resume.py
precheck`: the image, the OFD lock, the decision table, the lock released),
starts QEMU in the background without the lock descriptor, records
`launched` (PID, time, console) only after the process exists, and on exit
classifies again: no `ABSD KERNEL BOOT` in this launch's console is
`launch_failed` (the authorization stays, the record names the failed
launch, `--wait-ready` reports it, and the launcher exits 6, distinct from
1 for its own failed bookkeeping); a consumed record is retired
with this console's `RECOVERY WRITABLE RESUMED` line as its witness; an
intact record stays `launched`. `release.py recover --wait-ready --id ID
[--timeout S]` reads the launched record, watches only that launch's
console, binds the three readiness records (`RESUMED` with the id,
`RELEASE OK`, the listener) to the latest `ABSD KERNEL BOOT` segment, runs
the receive-setup check, and re-reads the console afterwards: the boot
generation and the segment's readiness must be unchanged (a reset in
between is refused with 7). The records must appear in order: `RESUMED`,
then `RELEASE OK`, then the listener. It exits 0 (`READY`), 7 with the
refusal or boot-end line, or 124 on timeout. A `launched` publication or an
exit classification that fails fails the launcher (QEMU is stopped first
in the former case).

After preparing arguments, the shell execs `boot_operator_supervisor.py`
with the recovery lock still held. Its HUP/INT/TERM handlers only record
interruption intent. One synchronous owner publishes the launch record after
spawn using the existing `launched` function, and reaps QEMU before calling
the existing `exit_path` recovery classifier. QEMU does not inherit the lock.
TERM has a two-second grace period before KILL; reap still waits if the host
cannot complete it. Closed terminal output cannot stop cleanup or change the
classification. An interruption latched when wait returns selects 130 even
when QEMU handles the same signal by exiting 0; guest halt status 3 still maps
to wrapper 0. The selected outcome survives later cleanup signals. This attended
launcher handles HUP even if inherited ignored, including under `nohup`.
SIGKILL or host failure still requires reconciliation of the exact child and
image holders; see
[OPERATOR-RUNBOOK.md section 9a](OPERATOR-RUNBOOK.md#9a-recover-a-writable-machine-after-an-unclean-stop-operator-act).

Every command that writes the image or replaces its pathname (`install
--replace`, `stage`, `select`, `rollback`, `accept`, `restore --replace`,
`migrate`, `remove`, `discard-import-temp`, `reconfigure`,
`operator_image.py reconfigure`, `absd_try.py enroll`) enters
`Target.mutation()`: the
recovery lock for the command's duration (`tool_busy`), the OFD lock taken
and released once before any boot of its own (`image_locked`, which also
covers a launcher that died while its QEMU lives), and `recovery_pending`
whenever the slot holds a record or an unsuperseded `active.toml` exists.
Legacy `restore --replace` validates the backup first, then takes this
mutation boundary before inspecting an installed target's open-image and
clean-history conditions. A live launcher therefore refuses `tool_busy`
before `image_in_use`; an open image without the recovery lock still
refuses before any restore or clone-cache effects. Legacy targets without
a recovery lock retain read-only preflight refusals without creating that
lock; an admitted replacement still enters the mutation boundary and
rechecks pending recovery and clean history.
An unsuperseded intent alone does not block a mutator. `release.py build`
refuses `target_directory` whenever its output holds any operator-directory
marker (`absd-operator.img`, `RELEASES`, `TARGET`, `receipts/`,
`recovery/`). `backup` is allowed beside a record and labels the copy
(`backup.toml` `recovery.pending_id`). `recover --status` reads without any
lock and takes the recovery lock only to write a reconciliation.

### The decision table

The current transaction T is the newest unsuperseded record: `active.toml`
if present and unsuperseded, else the unsuperseded intent with the greatest
time, else none. An archive (`consumed-`, `revoked-`, `stale-`,
`superseded-<id>.toml`) supersedes the intent and any active record with
its own id and nothing else; every older or superseded record is history,
listed by `--status` and never consulted. Precondition rows 0-3 run before
T. Top to bottom, first match wins (`precheck`, the launcher's exit path and
`--status` all evaluate the same function):

| # | F | Slot | Records | Row | Launcher |
|---|---|---|---|---|---|
| 0 | unreadable | any | any | identity-unreadable | refuse `identity_unreadable` |
| 1 | any | unreadable (reader refuses) | any | slot-unreadable | refuse `host_reader_refused` |
| 2 | any | corrupt | any (terminal; records not consulted) | corrupt-slot | refuse `resume_slot_corrupt` |
| 3 | any | any | an unparsable intent or active | corrupt-receipt | slot `none`: quarantine to `corrupt-<time>-…`, continue; slot R: refuse `corrupt_receipt` |
| 4 | any | any | active whose id has an archive | retirement-incomplete | remove `active.toml`, continue |
| 5 | any | R | T = none | record-unreceipted | refuse `record_unreceipted` |
| 6 | equal | R = T.planned, Hm equal | T = intent | authorized-unpublished | finalize (F, bytes, Hm, `fsync`, readback), publish active, then row 8 |
| 7 | any | R | T = intent, 6 unmatched | mismatch | refuse `recovery_image_changed (F,hm,bytes)` |
| 8 | equal | R = T.bytes, Hm equal | T = active | authorized / launched | launch; `launched` after the process exists |
| 9 | any | R | T = active, 8 unmatched | mismatch | refuse `recovery_image_changed (…)` |
| 10 | equal | none | T = active | consumed-pending | retire (`consumed-<id>` with the witness or `consumed_unwitnessed`, remove active, receipt), then row 14 |
| 11 | differs | none | T = active | replaced | refuse `recovery_image_replaced F=old->new` |
| 12 | equal | none | T = intent | intent-only | launch (P14g rules apply in the guest) |
| 13 | differs | none | T = intent | stale-intent | archive `stale-<id>`, then row 14 |
| 14 | any | none | T = none | none | launch |

`--status` observes without a lock, then takes the recovery lock, re-probes
and reclassifies under it before any side effect (a concurrent command may
have retired or published meanwhile; every action revalidates the file it
touches), and prints `state=<row> last=<newest archive> history=<count>`:
the reconciled state once reconciliation ran (`observed=<row first seen>
reconciliation=done`), the observed row when the lock was busy
(`pending=<predicted> reconciliation=deferred`), and the observed row with
`reconciliation=failed reason=<r>` when a reconciliation failed (for
example finalization's `record_unverified`): a failed reconciliation is
never reported as its predicted row, and precheck refuses with that
reason, so the launcher never starts QEMU on it. A host record that fails
the full schema (both attestations recorded true, a nonempty reason, F,
the hashes, the planned sector naming exactly the recorded state fields,
the launch facts of a launched record) is an unparsable record: the
corrupt-receipt row. Retirement is idempotent and ordered (archive, remove
active, receipt and ledger line); interrupted after the archive, row 4
completes it; during it, row 10 runs again. The derived events are
reconciled independently from the durable evidence on every `--status`,
precheck and launcher exit: an active or consumed record owes the
authorization receipt and the `recovered` ledger line, a consumed archive
the consumption receipt and the `consumed` line, a revoked archive the
revoke receipt and the `revoked` line; each is written when missing, after
the removal of `active.toml` too. Intents
are never deleted; a new act supersedes the previous unsuperseded intent as
`superseded-<id>`. Fresh authorization is required after rows 2, 5, 7, 9,
11 (all via `--revoke`), 12, 13, 14 and after every consumption.

### Interruption boundaries

For the original history p in {failed, not_ready} (the ledger and facts of
the old boot stay the old boot's until the new ledger lands; once it lands
no fact matches the new boot and the assessment is `not_ready`):

| Boundary | Slot | Ledger and facts | Next assessment | Successor admitted? |
|---|---|---|---|---|
| consumption write not landed | R | old | p, R valid | yes, the identical state |
| consumption landed, charge not started | none | old | p | no |
| charge's ledger write failed before landing | none | old | p | no |
| ledger landed, facts not cleared | none | new ledger, old facts | not_ready | no |
| charge's sync failed | none | as landed | p or not_ready | no |
| charge synced | none | charged | after an orderly end `ended` (admitted); after another unclean stop `failed` (ready fact) or `not_ready` | only after an orderly end |

`fsd/src/write_guard.rs` runs every row for both histories against the
fake device at every write and flush offset (B1), with the ready fact of
the recovered boot established before `failed` is expected (h).

### Limits

Identity is logical-state matching plus host binding to F and, while a
record is present, `(Hm, R)`: byte-identical copies are indistinguishable
by content; a backup taken after authorization carries the record and is
admitted if booted (`backup.toml` labels it; never boot a copy as the
machine); the pre-charge replay window exists under raw host writes (R4e).
Saved execution state, `locking=off` instances, invisible holders and
writers in the OFD-release-to-open gap are excluded only by
`--attest-sole-instance`. File data is unchecksummed; unsynced in-place
overwrites are indeterminate per sector; growth is lost; up to 200 ms of
acknowledged writes may be absent. The act's sector write assumes sector
atomicity as the device law does: a torn write is refused as corrupt. A
wrong-release boot after authorization consumes it. The recovered
generation inherits what the failed one committed. The readiness timeout
(180 s under TCG, 60 s under KVM) is provisional until measured. The
three-reset budget stays inert. The model (`scripts/model-storage-fence.py`)
adds the act, consumption and charge progress and two controls (a record
admits only the exact state; a delayed consumption effect can only refuse).

## Clean legacy conversion

For a guard-less format-2 raw disk, `scripts/seed-writable-guard.py` prepares
a separate guarded copy. Halt the legacy machine with `shutdown` and retain
its complete successful console, and record the whole-image SHA-256 after
the halt has completed and before any other writer runs. The tool requires
`--attest-no-writes-since-halt`, which is off by default: the operator must
attest that no enrollment, importer, host update or other writer ran after
that halt. It also requires the previously recorded `--halt-image-sha256`.
Current image bytes must match that hash before any allocation. The tool
requires the canonical checked
ledger, initialization marker, and matching ready, halt-request, stopped and
completed facts. The final console boot must name the same ledger sequence,
streak and finalized boot identity, with successful drained service shutdown
and bootstrap completion. Missing, malformed, unready, mismatched or staging
state refuses before allocation. An existing guard always refuses conversion.
The shared ledger/fact vectors are exercised by Rust and Python.

Example, using the current built platform and its kernel checkout:

```sh
sha256sum old/absd-operator.img > old/shutdown.image.sha256
# Record the preceding hash immediately after the awaited legacy halt.
# If any writer ran afterwards, refuse this conversion; do not reseal it.
python3 -I scripts/seed-writable-guard.py \
  --source old/absd-operator.img --clean-console old/shutdown.serial.log \
  --output converted.img --work conversion-work --kernel /path/to/current-kernel \
  --attest-no-writes-since-halt --halt-image-sha256 HASH_RECORDED_AT_HALT
```

The source must be a halted, exclusively owned regular raw file, with no open
consumer or hard links. Work and output must be on the same explicitly chosen
filesystem, with capacity for the copy and importer build outputs. The tool
creates its private work directory exclusively, copies every input byte to a
new file, and uses the current importer to add only the fixed `clean` marker.
It verifies all existing contents, recovery history, object identities and
data mappings, permitting only the new child and `/var` directory mtime to
change. It rechecks source identity and SHA-256 before exclusive publication.
It never resets the logical recovery budget or modifies the source.

The result is `PREPARED_UNACTIVATED`: no boot ISO, old selection cache or
operator ledger is copied. Use the current guard-aware release's boot image
to inspect and activate it. An older service ignores the guard and cannot
provide this contract; returning to it is not a qualified downgrade. Keep
the original file and its old boot image as the pre-activation rollback.
Restoring that file after new external effects does not undo those effects.

Legacy consoles do not contain a final whole-device hash. Matching ledger
and halt facts alone cannot exclude a later non-ledger writer. The explicit
operator attestation is a construction assumption, not a mechanically proved
history. Hashing an unknown current image does not establish it as clean.
If the original halt hash or writer history is unavailable, conversion
refuses; obtain a new qualified clean legacy halt only if its recovery
policy permits it. Never attest merely because the old facts still match.

Clean shutdown evidence does not prove physical command retirement. Distinct
backing files keep any late effect on the old backing from reaching the new
copy; this is an offline raw-file construction rule, not hardware transfer.
Before publication, failure leaves no output. A crash or I/O error at or after
the exclusive link can leave the verified but unactivated output; inspect
its identity and result before any retry. The named work directory can contain an
incomplete private image and importer logs. After reconciling its importer's
termination, its operator owns exact cleanup. On success retain the result,
source identity and shutdown log for conversion review, then retire the work
directory when no replay or recovery dependency remains. Never archive its
private disk as ordinary evidence.

## Completion

Init retains the block authority and regrants it only for same-boot
finalization after successful service termination and descendant drainage.
The finalizer assesses read-only before its writable mount. It requires a
dirty guard, the current boot's ledger, its stopped fact, and no completed
fact. A served completion also requires that boot's ready and requested-end
facts. A bounded `net fsd` completion follows a successful worker and server
and no live descendant; its completed fact explicitly carries
`action=bounded` in the existing v1 fact encoding. It does not assert an SSH
readiness or operator-requested shutdown. Previous-generation facts cannot
authorize either path.

The finalizer rechecks, writes its completion fact, syncs all filesystem
work, then transitions the marker to `clean` and flushes as its last mutation.
Failure before that clean write leaves dirty. A failed clean write may arrive
later, but no older filesystem command is outstanding at its issue point
under the device law below. Startup cannot write merely because init or the
file server exited successfully; the record and history must agree.

The same-boot finalizer invocation is an explicit continuation of init's
retained authority. It does not revive fenced handles or rebind authority to
an old generation. A new generation re-derives its state from the records.

## Offline updates and enrollment

Product-image importers are writers too. The shared host transaction in
`storage_fence_host.py` covers release staging, selection, cached rollback,
removal and operator reconfiguration. On a halted exclusively owned image it
requires the existing exact `fresh` or `clean` marker, verifies its fixed
identity/allocation, writes and fsyncs `dirty` before starting an importer,
and leaves it dirty on any error or interruption. Only successful importer
completion followed by an ordered image fsync permits restoring the original
marker, as the last write and fsync. It never upgrades an unknown image by
seeding a missing marker. An interrupted removal may reconcile its operator
directory but cannot retry device writes while dirty.

Native SSH-key enrollment assesses through a read-only block duplicate,
arms the same marker before its one filesystem commit, verifies its result
and unchanged recovery history, then syncs and restores the original marker
last. Its bounded-update finish grants no authority to another writer and
does not fabricate a served completion. Clone host-key regeneration uses the
normal guarded file-server entry point; a dirty clone cannot regenerate.

Release installation constructs a unique candidate disk with a fresh marker
and publishes it only after complete import/verification; an interrupted
replacement preserves the previous disk. Legacy format migration constructs
a different backing file, preserves the old disk and site data, and seeds a
new fresh record. It refuses an existing private recovery ledger/staging
history or an unclean old marker: device separation is not permission to
discard logical recovery history or reset its budget. Such inputs need an
explicit state conversion/reconstruction rule, which this change does not
implement. It never repairs or reseeds the old device. Failed candidate
construction is not bootable output.

The host transaction assumes the existing successful ordered-write/flush law
and a terminated successful importer, just as native finalization does. It
does not assert that a failed import retired its commands. Its raw writes
touch only the private fixed marker, never filesystem metadata or ordinary
file data. The filesystem primitive is public because the guard protocol is
in a separate crate; it requires existing full-write authority and is not a
session operation or an ordinary atomic-file replacement API.

## Scope and evidence

The source precheck `python3 -I scripts/check-storage-fence-frozen.py` keeps
the frozen base `0414342f` and the pinned guest helper. The current reviewed
versions of `run-storage-fence-matrix.sh`, `storage-fence-ghost.py`, and
`served-matrix.py` must match their exact whole-file Git blob pins in that
checker. Their base versions omit required #94/#119 controls and are refused.
This preserves required lines, their counts, order, and surrounding context;
it does not infer semantic equivalence from a vocabulary of permitted lines.
Other historical allowances remain per-line checks against the same base and
do not establish exact patch structure. The host controls in
`scripts/test_storage_fence_frozen.py`, also run by `scripts/check-all.sh`,
exercise the real checker in a temporary Git repository: reviewed positive,
omission, substitution, duplication, reordering, changed bytes, extra lines,
and missing files. Three immutable base-file fixtures preserve the reviewed
diff inputs without requiring private component history. Their temporary
fixture commit is passed explicitly with `--base`; it is not `0414342f`, and
the production default stays unchanged. A passing source check establishes the checked bytes at
that time; runtime consumption and historical evidence need their own
identities. This prospective repair changes no historical observation or
qualification verdict.

The bounded model explores two boots with served, plain and update writers,
first-boot failures, delayed dirty, clean and filesystem effects, and
interrupted flushes. Four negative controls restore declaration admission,
the served-only bypass, admission from ledger absence and an unguarded update.
Source tests exercise real filesystem operations and
failure at every finalizer write/flush, dirty write/flush and seed shape.
Guest matrix and retained-write controls still need their own recorded runs.

Assumptions are exclusive authorized construction and file-server write
authority, fixed marker allocation, at most one eventual sector effect per
retained command, and the existing ordered successful-write/flush device law.
The record does not establish physical controller retirement, repair data,
undo external effects or guarantee safety with repeated writes, a concurrent
writer, a moved marker, or a backend that lies about successful flushes.
Those cases are not qualified by the model. RC1's frozen source and image
recipe are unchanged; integration and exact-pair acceptance remain separate.
