# Pinned recovery points and replacement service

This procedure uses the opt-in pinned recovery-point mode of `release.py`.
Host construction is distinct from a served recovery result: the latter needs
an independent readiness, state and writable-restart qualification receipt.
The existing release disclosure remains unchanged until the steward composes
and accepts this lane. In-place writable recovery is outside this procedure.

## State, recovery point and loss bound

Take a point only after the running A machine completes an orderly `shutdown`
and its QEMU process ends. The tool refuses an image with a holder or any
guard state other than `clean`, including `dirty`, `fresh` and malformed bytes.
The canonical recovery ledger and same-boot facts must also establish `Ended`;
`not_ready` and `failed` are refused history values, not guard states. The host
reader checks the existing v1 ledger checksum, initialization and ended facts,
including the native bounded-completion case, against shared golden vectors.
It never repairs or resets a guard or history. Keep the point in private operator custody:
the complete image contains site data and the SSH host-key seed.

The declared site/application state is the path and file-content inventory
under `/home`, `/etc` and `/ssh`, including empty directory presence and the
same logical host identity. The point also copies all disk bytes, filesystem
metadata and recovery history as they existed at that time. After a successor
boots, ordinary logs and boot accounting under `/var` can advance; they are
not promised byte-identical to an earlier running generation.

The RPO is exactly the last successful halted point. Every later change may
be lost, **including a committed write made before the later unclean stop**.
Memory, active commands, channels, grants and boot identities are not restored.
There is no live-backup, zero-loss or dirty-image salvage claim.

## Create and independently retain a point

Examples use selected release ID `preview2-a`, a source operator directory
`operator/a`, a new private backup directory `points/a`, and a separately
retained digest `POINT_SHA256`. Replace that token with the exact 64 lowercase
hex digits reported by a successful point creation.

```sh
python3 -I scripts/release.py backup --target operator/a points/a --recovery-point
```

Success includes `RECOVERY POINT SHA256 <digest> selected=preview2-a`. Retain
that digest in a trusted operator record outside the backup. Do not later
derive the expected pin from the backup being checked. The pin binds the exact
`backup.toml`, which binds the complete disk, selected boot image, release,
filesystem identity/sequence and declared roots. This detects substitution
against that trusted input; it is not a release signature or proof of origin.

```sh
python3 -I scripts/release.py verify-backup points/a --recovery-point-sha256 POINT_SHA256 --expected-release preview2-a
```

Refusal names the failed boundary, such as `recovery_point_pin_mismatch`,
`recovery_point_image_digest`, `recovery_point_iso_digest`,
`recovery_point_unclean`, `recovery_point_release_mismatch` or `image_in_use`.
Malformed, oversized, truncated and structurally invalid members are refused.
Input checks precede writes to a replacement.

## Recover after an unclean stop

1. Stop and retire the original execution. Retain its interrupted image as
   fenced evidence. A cold writable attempt must still refuse without writes;
   do not clear its guard, history, or recovery budget. It is not the restore
   destination.
2. Retire any earlier replacement execution too. Only one copy of this logical
   identity may serve. The tool cannot find every image copy or remote guest;
   concurrent serving restores of a single point are unsupported.
3. Restore to a new operator directory, then use the existing operator boot
   and pinned-SSH procedure. `--expected-release` names the source point's A,
   not a desired later B.

```sh
python3 -I scripts/release.py restore points/a --target operator/recovered-a --recovery-point-sha256 POINT_SHA256 --expected-release preview2-a
scripts/boot-operator.sh operator/recovered-a 2222
```

The fresh destination must not exist, even as an empty directory. Strict mode
refuses `--replace`, `--clone`, `--release` and `--kernel` combinations.
Legacy restore refuses a backup carrying the recovery table, so omitting the
pin cannot enter its replacement path. Legacy `--replace` also refuses a held
image or a target without clean, ended admission. Unsealed legacy backups can
still replace clean halted targets; this is not the pinned recovery procedure.
A new physical instance with a different host identity is
the separate clone operation, not this same-machine reconstruction.

`RESTORE COPIED` means construction only. Establish `RELEASE OK`, listener
readiness, authenticated SSH using A's retained public host fingerprint, and
declared-state readback. Confirm the expected absence of a known post-point
marker. Then create and sync a new application file, halt cleanly, boot the
same replacement again and read the new bytes back. These observations, not
the image-copy message, establish writable-service recovery. The boot and SSH
commands are documented in [OPERATOR-RUNBOOK.md](OPERATOR-RUNBOOK.md).

An I/O failure after admission leaves unfinished construction, not a recovery
result. Keep its receipt/logs and reconcile the exact destination; it cannot
be retried as a fresh directory. The source point and interrupted original
remain unchanged. An abrupt host loss can prevent a terminal receipt.

## Update and refused-update rollback

Restore the A point into another fresh destination, with old executions
retired. While that replacement is halted, use the existing manifest-checked
stage/select path for a distinct newer compatible release B:

```sh
python3 -I scripts/release.py restore points/a --target operator/update-b --recovery-point-sha256 POINT_SHA256 --expected-release preview2-a
python3 -I scripts/release.py stage --target operator/update-b --release B --kernel KB
python3 -I scripts/release.py select --target operator/update-b --release B --kernel KB
scripts/boot-operator.sh operator/update-b 2222
```

`B` is a complete release directory, and `KB` is its disposable exact kernel
checkout. Verify B's actual selected release, unchanged declared state, a new
write, clean halt and durable restart. Compatibility is the tested current
filesystem and application-state schema; no format conversion is implied.

If B refuses, retain and retire that execution. A failed served boot may leave
its image fenced. Do not select A on that image. Instead reconstruct A from
the pinned A point into a different fresh directory and repeat the recovery
checks above. Rollback therefore has the same RPO: changes after the A point
are discarded. This does not downgrade B's newly written state; admitting a
B point as an A point refuses by expected release. A future cross-version
state conversion needs its own schema/preconditions and qualification.

## Evidence and limits

Retain the source/artifact identities, external pin, public inventories and
fingerprints, named refusals, raw command/serial results, original and failed-B
fence observations, and new-write restart results in collector custody.
Private keys, seed-bearing images and backup bytes remain private; their
custodian retires them once the exact replay/recovery dependency ends.

`test_recovery_point.py` exercises host construction on a small complete
device with real filesystem records. `test_recovery_point_mutants.py` checks
every control against a named weaker implementation and three base-tool
projections. `model_recovery_point.py` explores three target generations and
16-step traces, with explicit negative transition histories. The model assumes
trusted point/pin custody and operator retirement; it does not prove actual
service readiness, physical power-loss durability, hardware fencing, global
duplicate detection, or live kernel replacement. Native receipts must supply
the actual recovery/update correspondence.

The native matrix is `scripts/recovery-point-matrix.py`. Supply complete A
and B release directories, their independently recorded platform revisions,
the exact disposable kernel checkout, an existing campaign key, a new private
work directory and a separate new public-evidence directory. A uses the
dispatched base `03479a3e`; B uses a distinct later source revision and release
ID. The oracle must execute from that exact clean B revision. Both manifests
must record clean source and kernel trees. Supply an independently pinned
`p2-source-ancestry/1` receipt of the local A-to-B Git ancestry check. P00 binds
it and records the A/B manifest guest-tree digests and changed files. The original accepted tranche used a release ID rebuild; its results exercise
stage, select and rollback without qualifying a guest content update. A new
candidate run may add `--require-binary-change tree/bin/https-document` to
require different manifest-verified ELF content in B (including a newly added
executable). P00 records the exact A/B content hashes or explicit absence in
A, and refuses unchanged, missing, non-ELF or mismatched B bytes. Existing
install/stage verification checks the bytes written against those manifests.
This uses the same internal A baseline and kernel; it is not a published RC1
upgrade. The actual HTTPS body/receipt lifecycle is qualified separately
against the final candidate. Historical results do not gain this claim.

Cases P00–P08 cover inputs, a clean pinned point, corrupt-input refusals,
the interrupted original's fence, recovered A, updated B, refused B's fence,
fresh A rollback, and the original/failed-B images remaining unchanged.
Every served replacement writes new bytes and reads them after clean restart.
The runner preserves raw served, importer, refusal and SSH output, public
inventories, pins and release manifests. `/ssh` content digests stay private;
internal exact comparison and the public pinned host fingerprint still apply.
It exports no image or private key. The original's post-stop inventory records
the later marker or an honest unreadable result. Native refusal controls cover
legacy replacement over the fenced original and existing/symlinked targets.
`test_recovery_matrix_oracle.py` checks its acceptance predicates against
deliberately incomplete evidence and disabled checks. The stubbed sequence in
`test_recovery_matrix_flow.py` also exercises Matrix methods and omissions of
the fence, RPO, readback, reason, state and final-image checks. These host controls do
not establish a native result. Collector custody and independent acceptance
remain separate from the runner's terminal report.
