# Preview 2 replacement and restore: proposed contract

Design proposal for the owner-admitted lane, not a qualification result.
Base: platform `03479a3e090e847ccdfa647dce44e7b16d035988`, kernel
`0f770fe5469861e5d6a55652a2153c75ba834ffe`. Root S2 is the sole holder.

## Recovery point and declared state

Use the existing `release.py backup` and `restore` image-copy mechanism.
A recovery point is taken after orderly shutdown, with no image holder and
the existing writable guard in `clean` state. It contains the complete disk
and selected release's boot image. No guard or recovery-history record is
rewritten. The interrupted original is retained separately and remains
refused for writable entry.

The declared application/site state is the path and file-content inventory
under `/home`, `/etc` and `/ssh`, including operator data, configuration,
authorized keys and the same logical machine's host identity. The complete
checkpoint image also preserves filesystem metadata and recovery history as
they stood at the recovery point. Boot-time logs and accounting under `/var`
may advance normally after reconstruction; they are not byte-equality claims
about a running successor. Directory presence and file contents are checked;
old kernel handles and grants are never restored.

Only one instance of that logical identity may serve. The operator retires the
original and any earlier replacement before serving its successor. The host
tool cannot discover every copy; concurrent serving restores of one point are
unsupported. Fresh-destination and clone-conflict refusals are local checks,
not distributed fencing.

RPO is the last successful halted recovery point: every subsequent change,
including a committed write on the later interrupted original, can be lost.
There is no live-backup, zero-loss or extraction-from-dirty-image claim.

## Minimal product change

Add an opt-in recovery-point mode to `backup`, extending `backup.toml` with
a versioned `absd-recovery-point/1` table, declared roots and the selected ISO's
size/digest. Record the existing disk digest, selected release, format,
filesystem identity/sequence and public host-key fingerprint. Print the exact
metadata SHA-256 for the operator to retain independently of the backup.
The pin is a trusted operator input, not a signature or a new authority grant.

Add strict restore options for that external pin and the expected source
release. Read bounded immutable metadata/image/ISO snapshots; validate the
pin, schema, image integrity/structure, clean guard, release identity and ISO
digest before creating or writing the replacement. Publish those same
verified bytes, rather than reopening unverified paths. Strict mode requires
a new operator directory and rejects `--replace` and clone-mode combinations.
Existing unsealed backup/restore consumers keep their current contract.
Use the existing independent reader, including its in-memory region support;
no filesystem format or kernel ABI change is planned.

Corrupt, truncated, substituted or wrong-release inputs get a named refusal
with the replacement unchanged. A copy/I/O interruption after valid admission
is an unfinished construction, never a served recovery result. The operator
reconciles it separately; the source recovery point and original stay intact.

## Operator and update sequence

1. Halt A cleanly, take and independently pin the recovery point, then resume
   service. Keep the backup private: it contains the host seed and site state.
2. After an unclean stop, retain the original as fenced evidence. Restore the
   pinned A point to a new directory; boot A, authenticate with its pinned
   host identity, verify declared state, and demonstrate a new durable write.
3. For update, restore the A point to a fresh replacement, then use the
   existing validated `stage`/`select` path for a distinct newer B release.
   Verify B's state and writable service independently.
4. If B refuses, retain its failed image and restore the A point to another
   fresh replacement. Never select A on a dirty B image or clear its guard.
   Rollback discards changes after the A recovery point. Downgrade of B's
   newly written state needs a separately qualified conversion and is refused
   by this workflow; it is not an inverse of update.

## Qualification matrix and evidence

- Host controls: malformed/missing schema or pin, truncated image/metadata,
  image or ISO mutation, rehashed local metadata against an unchanged external
  pin, wrong release/format, dirty guard and existing destination. Assert the
  named reason and unchanged destination; exercise the actual CLI boundary.
  Dirty/malformed guards, not-ready/failed history and image holders are
  refused at point creation and restore. A file-substitution control proves refusal or publication of the
  originally validated bytes. Each new control is checked against the base
  or a named deliberate mutant when the base lacks the feature.
- Native recovery: data and empty-directory inventory, clean point, later
  committed marker, unclean stop, original cold writable refusal with unchanged
  image, fresh A restore, served readiness and state readback. The later marker
  is absent as declared by RPO; a new write survives clean halt and restart.
- Native update: fresh A restore to B, state equality and durable new write;
  refused B and fresh A rollback. Original and failed B remain fenced.
- Reuse release-matrix 9/10 mechanisms and preserve their results. Run the new
  matrix on a disposable Vultr VM after consequential-change/oracle review.
  Collector custody retains raw serial, command results, public inventories,
  exact source/artifact identities and terminal/cleanup records. Private keys,
  recovery images and private backup bytes stay in scoped VM custody.

## Formalization and replacement limits

Record a small bounded transition model for pinned-point admission, exclusive
new destination, constructed/served acceptance, refusal and rollback from an
unchanged A point. It establishes only those transitions under trusted operator
custody, not hardware fencing or physical power-loss durability. Native tests
establish the actual service/data correspondence. The external operator and
collector decide replacement success; a successor does not accept itself.
Live kernel replacement, authority transfer, in-place writable recovery and
format conversion remain outside this lane. Steward review owns the final
scope decision before qualification.
