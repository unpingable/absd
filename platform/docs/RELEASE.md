# ABSD releases: identity, install, update, rollback, backup, restore

The successor heap counterexample, attribution and bounded allocator repair
are recorded in [SSH-HEAP.md](SSH-HEAP.md). That qualification does not by
itself accept or seal a successor pair.

Status: the design and operating contract of the `INSTALL_UPDATE_RECOVERY`
gate (kernel `docs/USABILITY-ROADMAP.md`, U1 "Paired update and rollback"
and "Backup, restore, recovery"). Everything here is for the supported
environment of this gate: the operator image under local QEMU, the disk as
the primary IDE master or one NVMe namespace, TCG or KVM. Nothing here
claims a physical machine; see `docs/MATURITY-BACKLOG.md` (kernel) items
4, 7, 9, 14, 15, and 17 for what this gate decides and what it leaves.

With frame-admission-v0, served QEMU boots require at least **256 MiB guest
RAM**. Platform launchers use `scripts/served_ram.py` beside the build-time
feature policy in `scripts/served_kernel.py`. The default is `-m 256M`;
`ABSD_GUEST_RAM=512M`, a launcher's explicit memory argument, or an existing
larger QEMU `-m` can raise it. Every supplied size below 256M is refused on
the host; larger existing sizes are preserved. This is the runner floor,
not a workload-capacity guarantee. The observation matrix's non-served 32M
pressure probe retains its qualification configuration.

The served matrix includes one deliberate 128M negative boot, requiring
status 7 and `SERVED FRAME BOOT REFUSED reason=ram_below_minimum` with
measured usable/minimum byte counts, before any service starts or reset.
`run-served-matrix.sh --only ram-below-minimum` selects that case; its
normal full run also includes it. Qualification must separately demonstrate
256M workload feasibility and a served boot above 256M (for example repeat
with `ABSD_GUEST_RAM=512M`). Host tests cannot establish either result.

## 1. The release unit

One ABSD release is the pair the operator boots and the tree it serves:

| Part | Contents | Where it lives | Mutable in place |
|---|---|---|---|
| boot image | one Multiboot kernel: the kernel, `init`, the catalog, and the embedded file server (`absd-fsd`) and SSH server (`sshd`), on a GRUB ISO | `<release>/absd-operator.iso` on the host; external media on a machine | never |
| release tree | the commands (`bin/`), the manual (`share/`), the release record (`release`) | `/releases/<id>/` on the disk | never, once installed |
| site state | `/etc` (configuration), `/ssh` (host key seed, authorized keys), `/home`, `/var`, `/tmp` | the disk, outside every release tree | by the operator and the services |
| filesystem format | the on-disk format the boot image's file server reads and the host reader validates | the disk's filesystem region | by migration only |

The boot image and the release tree are built together and carry the same
release id; neither is useful with the other's neighbour. Site state belongs
to the machine, not to a release: an update keeps it, a rollback keeps it,
a backup carries it, a clone must regenerate the parts of it that are
identity (section 10).

The kernel's own catalog (`init`, probes) is part of the boot image and is
never separately installed; the kernel never reads the disk.

## 2. Release identity

Machine-readable, in the release record `/releases/<id>/release` on the
disk and compiled into the boot image's services:

```
absd-release 1
release=<id>
kernel_abi=<n>
fsd_protocol=<n>
fs_format=<n>
app_abi=<n>
check=<sha256 of the lines above, hex>
```

Lines are `key=value`, in this order, one each, no others; `<id>` is
`[a-z0-9.-]+`. Any deviation is a malformed record.

| Field | Meaning | Match rule | Checked by |
|---|---|---|---|
| `release` | the release id, same for the boot image and the tree | exactly equal to the file server's and sshd's compiled id | file server at boot (section 3); sshd against the file server's answer |
| `kernel_abi` | the kernel syscall ABI generation (`absd-abi`) | exactly equal to the runtime's compiled generation | every program's runtime at start, against the kernel's `abi_version` syscall; the file server also compares the record's value to its own |
| `fsd_protocol` | the file-server wire protocol (frame format and ops) | exactly equal | the file server against its own; every client at its first exchange (section 3) |
| `fs_format` | the filesystem format the release reads | exactly equal to the format the file server's library mounts, and equal to the format found on the disk | the filesystem library at mount; the host reader before install, update, restore |
| `app_abi` | the startup record, broker, and session-control conventions the release's programs were built to | exactly equal (recorded for the boot image's own consistency; no range is admitted yet) | the file server against its own |

No field admits a range in this gate: the components are built together,
and a compatible-range rule would be a promise with no second release to
test it against. A later release that wants a range must add the rule and
the test together.

Incompatibility means any field differs, the record is missing or
malformed, or the selected id has no tree. The consequence is refusal
before ordinary operation, never a fallback (section 3).

## 3. Compatibility fails by refusal

The checks run before the component they protect does ordinary work:

1. **Filesystem format.** The library mounts only format 2 (section 6). A
   format it does not know refuses the mount with a named error, the file
   server prints `FSD FAILED mount: <error>` and exits non-zero, and init's
   pre-ready refusal fails the boot (`SERVED RECOVERY REFUSED
   generation_not_ready`, QEMU status 7, no reset).
2. **Release record.** After mounting and before `FSD READY`, the file
   server reads `/absd/selected` (one line, the selected id) and
   `/releases/<id>/release`, parses the record strictly, verifies `check`,
   and compares every field to its own. It prints `RELEASE OK release=<id>`
   or `RELEASE REFUSED reason=<reason>` and exits 3, with these reasons:
   `no_selected_release`, `malformed_selected`, `no_release_tree`,
   `malformed_record`, `check_mismatch`, `release_mismatch`,
   `kernel_abi_mismatch`, `fsd_protocol_mismatch`, `fs_format_mismatch`,
   `app_abi_mismatch`. The boot then fails as in 1.
3. **Release tree binding.** The file server serves `/bin` and `/share` as
   the selected release's `/releases/<id>/bin` and `/releases/<id>/share`;
   nothing else reaches `/releases`. The binding is made once, from the
   record that passed, and never changes during a boot.
4. **Kernel ABI.** The kernel answers `abi_version` (syscall 42) with its
   generation. Every program's runtime asks at start and refuses with
   status 103 and the console line `ABI REFUSED kernel=<n> required=<m>`
   when they differ, or when the kernel has no such syscall (`-38`, an older
   kernel). sshd and the file server therefore refuse before they serve.
5. **File-server protocol.** A client's first exchange on a channel is a
   `VERSION` request; the reply names the server's protocol and release.
   The runtime refuses the process (status 104, `FSD PROTOCOL REFUSED`)
   when they differ, and treats no reply within a bounded wait as the same
   refusal: a server that cannot parse the frame never answers. sshd makes
   the same check on its control channel before it listens, so a mismatch
   there ends the boot pre-ready.

Nothing infers compatibility from a file name, a build directory, or the
fact that two artifacts sit together. Each check is exercised by a negative
control in `scripts/release-matrix.py` (section 12).

Importer operations also require a parseable `release-manifest.toml` of the
current schema, matching release/ABI identity fields and a full exact kernel
revision. Missing, malformed or mismatched source metadata refuses before an
importer writes; an absent manifest never disables the source-pair check.
Install, stage and migrate also check what they are about to write against
the manifest's `artifacts.files` digests, before any importer boot: every
file of the release tree and the release record, and for install the site
defaults (`/etc` files and `authorized_keys`). Each check is on the exact
bytes the importer then writes. The importer `fixture-import.elf` is copied
into a private directory and that copy, the one the kernel build embeds, is
checked. Every copy of the boot image into the operator directory is checked
after copying, and a mismatching copy is removed. A file that differs, a file
the manifest does not list, a listed file that is gone, a malformed digest, or
a manifest without an `artifacts.files` table refuses (`manifest_mismatch …`
or `manifest_unverifiable …`, naming every file).
`release_manifest.py verify` remains the whole-directory check, including
the boot image's contents.

## 4. Boot-failure semantics

| Failure | Where it is seen | Resulting state |
|---|---|---|
| incompatible release pair | file server, before READY | boot fails pre-ready: `RELEASE REFUSED`, QEMU 7, halted, disk untouched, the other release tree still bootable with its own image |
| missing disk or image | kernel/init (`no block device`) | boot fails: `init: FAILED at no block device`, halted |
| invalid filesystem version | library at mount | boot fails pre-ready: `FSD FAILED mount: UnsupportedFormat`, halted, disk untouched |
| failed image validation (host) | the host reader before install, update, restore | the operation refuses before writing anything |
| malformed release metadata | file server, before READY | as "incompatible release pair", reason `malformed_record` or `check_mismatch` |
| incomplete update (staging cut short) | the host reader: the record is absent or its check fails; or the file server if it was selected | staging refuses to select; if already selected, the boot refuses pre-ready and the previous release is selected again by the operator |
| rollback target unavailable | the host tool | the rollback refuses; nothing is written |

Every one of these fails closed with one reason line, repairs nothing by
guessing, and keeps the previously bootable release where one exists. A
pre-ready failure never resets, so there is no reboot loop and the console
evidence survives.

## 5. Install, update, acceptance, rollback

**Slots.** The disk holds at most two release trees under `/releases/`. `scripts/release.py remove` retires a tree that is neither selected nor the ledger's last accepted release, on a halted image: importer step 5 removes `/releases/<id>/` whole in one commit (a stop leaves the whole tree or none of it), the host reader confirms it gone and every other file unchanged, and only then does the operator directory drop that release's boot image and selection cache; a third release can then be staged; removing a release gives up rollback to it.
`/absd/selected` names the one the file server binds at boot; the boot
image booted must be that release's. The host tool keeps a ledger
(`RELEASES` in the operator directory) of every release it installed,
selected, accepted, or rolled back, with the receipts. Procedure: [OPERATOR-RUNBOOK.md](OPERATOR-RUNBOOK.md).

**Install** (`scripts/release.py install`): formats the target image,
installs the release tree, the site defaults (`/etc` from the operator's
directory, `/ssh/authorized_keys`), and `/absd/selected`, verifies the
result with the host reader, and writes an install receipt. The target is
identified explicitly (section 9). The write path is the existing one: the
release's own fixture-importer boots, each file one commit, under the
existing QEMU and `nvme-write` conventions.

**Update** (`scripts/release.py stage`, `select`): with release A selected
and accepted, B's tree is staged into `/releases/B/` by B's importer (B's
image must read the disk's format; otherwise migrate first, section 6).
Staging never touches `/releases/A/` or `/absd/selected`. B's tree and
record are checked against B's manifest before the first write (section 3),
and afterwards the host reader compares every staged file with those
verified bytes and verifies B's record. `select B` rewrites `/absd/selected` whole, in one
commit. The operator then boots B's image.

Every caught staging failure writes `receipts/stage-failed-<attempt>-<time>.toml`,
with a unique attempt id, release source, error, phase and effect disposition.
`REFUSED` means staging did not enter its importer call; the disk, existing
release images, selection cache and ledger were not written. A private build
scratch directory may have been created and removed. `INDETERMINATE` means the
importer call began or a later step failed; files may already be committed,
even when a boot reports failure. It is not rollback, and the tool does not
infer a successful stage from a failed boot. Inspect the halted target with
`status` and the host reader before recovery. Failure receipts do not append a
`staged` ledger entry. An error after the STAGED receipt was written can leave
that receipt alongside a later INDETERMINATE operation outcome; the phase
identifies the unfinished bookkeeping.

The command reports the receipt path with its error. If the receipt destination
is unwritable, it reports `receipt unavailable` with the original failure and
effect disposition; it cannot promise durable evidence in that case. Receipts
use UTF-8, escape control characters including DEL, and replace surrogate code
points in diagnostic strings with U+FFFD. A caught
keyboard interrupt records the same conservative outcome and propagates the
interrupt. An abrupt process or host loss can prevent a terminal receipt.
These are staging attempt receipts; other commands retain their existing
receipt behavior.

Importer steps 1-3 still write new files or append chunks at their final paths
and verify afterwards; only step 4 uses write-verify-rename. A failed stage can
therefore leave a partial tree. Atomic new-file and append construction is a
separate follow-on with space, worker-deadline and interruption qualification.

The states, and exactly when each holds:

| State | Holds when |
|---|---|
| `REFUSED` | staging stopped before its importer call; see the failure receipt and any receipt-write error |
| `INDETERMINATE` | a staging failure occurred after its importer call began; target effects need inspection |
| `STAGED` | `/releases/B/release` is present, well-formed, and verified by the host reader, and every file of B's tree matches the release manifest |
| `BOOT_SELECTED` | `/absd/selected` reads `B` (one commit) and B's image is the one to boot |
| `BOOTING` | B's image has been started against the disk |
| `SERVED_READY` | the console shows `RELEASE OK release=B` and the listener record, and the pre-ready window is over |
| `ACCEPTED` | `scripts/release.py accept` has run against the served machine: an authenticated session, `release` reports B, a write to `/home/operator` and its read-back, the host console shows no `SERVED SHUTDOWN ESCALATED` and no `SERVED RECOVERY` line, and the halted image validates; the ledger records B as known good |
| `FAILED` | any step above refused, or a served fault occurred before acceptance |
| `ROLLED_BACK` | `/absd/selected` reads `A` again and A's image boots to `SERVED_READY` |

"Kernel booted" is never acceptance. A release that has reached
`SERVED_READY` but not `ACCEPTED` is still a candidate; the previous
accepted release remains known good until B is accepted.

**Rollback** (`scripts/release.py rollback`): refuses unless the ledger's
last accepted release other than the selected one has its tree on the disk; otherwise rewrites
`/absd/selected` to it, in one commit, and tells the operator which image
to boot. State created under B stays on the disk (B wrote under the same
format into the same site directories); nothing of it is rolled back, and
nothing of it is interpreted by A except through the format both read. Install, stage and migrate keep each release's selection image (the importer step 4 image that selects it, built by its kernel) with the kernel's boot script in `releases/<id>/` of the operator directory, their digests in `releases/<id>/select.toml` and the receipt, so `rollback` without `--kernel` boots that image and needs no build host; it refuses `select_cache_missing` or `select_cache_mismatch` rather than build one, and `--release` with `--kernel` remains the explicit way to build the selection.

**Rollback across a format migration** is not a selection: the migration
retains the pre-migration image file, and rolling back means restoring
that file (section 7), which discards every change made after the
migration. `scripts/release.py` says so when it refuses to `rollback` to a
release whose format differs from the disk's.

## 6. Filesystem format 2

Format 2 is format 1 (`docs/FILESYSTEM.md`) with an explicit version and
one new field per object: `mtime`. The superblock magic is `ABSDFSS2`, the
image magic `ABSDFSI2`, the version word 2 in both; the object record grows
by eight bytes. The library mounts format 2 only; a format-1 region is
refused with `UnsupportedFormat` (named, not `Invalid`), never read, never
repaired. The host reader reads both formats and names which it found.

Migration is host-side, `scripts/release.py migrate`: read the old image
with the host reader (format 1), create a new image with the new release's
importer (format 2), copy every file of the site state and install the
release tree, validate the new image with the reader, and switch the
operator directory to the new image. The old image is retained as the
rollback target. Objects copied by migration get `mtime` 0 (section 8). No
in-place upgrade exists.

## 7. Backup and restore

A **halted backup** is supported; a live backup is not. `scripts/release.py
backup`: the machine is halted (an orderly `shutdown`; the file server's
final commit is the quiescence point), the image file is copied, the copy
is validated with the host reader, and `backup.toml` records the selected
release, the filesystem format, the filesystem id and commit sequence, the
host key fingerprint, the file list digest, and the image digest.

**Restore** (`scripts/release.py restore`): refuses unless the backup's
image validates, its format is one the named release reads, and its
record matches `backup.toml`; then copies it into place and the operator
boots the named release's image. Restore evidence is the served boot: the
file server mounts the restored state, `RELEASE OK`, the listener record,
an authenticated session, and representative persisted content read back.
Byte-equal copies are a precondition, not the evidence.

Negative controls (section 12): a truncated image, a format-1 image
offered to a format-2 release, a corrupted superblock, an altered object
record, an altered release record, a backup record that names another
image, and a backup from a later format.

## 8. `mtime`

- Clock: the kernel's `wall_clock` (CMOS RTC, whole seconds, declared UTC,
  `docs/TERMINOLOGY.md` "Time"). Precision one second.
- Value: seconds since the Unix epoch of the last change to the object's
  content or size (files), or to its entries (directories); set at
  creation.
- When the wall clock is unavailable or refused, the value is 0, which
  means "unknown", never "the epoch".
- Operations that set it: create, `write_at` that changes bytes or size,
  `set_len`, and for the parent directory: create, unlink, rmdir, mkdir,
  and rename (both parents). `rename` does not change the renamed object's
  own `mtime`; `set_readonly` does not either.
- Migration from format 1 gives every object 0.
- Exposed through `stat`/`fstat` and `std::fs::Metadata::modified`; shown
  by `ls -l` and `stat`.
- No `atime`, no `ctime`.

## 9. Durability vocabulary and the write contract

| Term | Meaning here |
|---|---|
| written | the request was accepted: by the file server into memory, or by the kernel into a pipe |
| flushed | `block_flush` returned after the device reported its cache flush |
| committed | the filesystem wrote the next image and its superblock and flushed both; the superblock sector write is the linearization point |
| durable | survives the stated failure model; in this gate, the model is a guest reset or an orderly halt under QEMU, and durable means committed |
| validated | the host reader selected a superblock pair, decoded the image, and passed every structural check |
| atomically replaced | a `rename` with a target, or an importer step (whole file, one commit): either the old or the new state is what a mount sees, never a mixture |
| recoverable after restart | a mount after a reset selects the newest consistent superblock; an interrupted commit leaves the previous one |

For the operations install, update, rollback, backup, and restore use,
"if the machine loses power immediately after this reports success":

| Operation | Guaranteed after restart |
|---|---|
| importer step (install, stage, select) | the file is wholly present or wholly absent; `select` therefore names the old or the new release, never neither |
| file server `sync`, `COMMIT`, release of a session | every write acknowledged before it is committed |
| write acknowledged but not yet synced | may be present or absent on remount (at most `COMMIT_TICKS` of exposure) |
| halted backup | the copy was taken after the final commit; it is the committed state |
| restore (host copy) | the host filesystem's own guarantee; the target is validated before any boot |

Only **logical durability** is established: the commit protocol under
QEMU, whose disk is host-cached. **Physical power-loss durability** on a
controller with a volatile cache is not demonstrated and is not claimed
(`docs/POWER-LOSS.md` has the model the format is designed for; the
qualification is `POWER_LOSS_DURABILITY_QUALIFICATION`, not this gate).

## 10. Machine identity

| Item | Lives | Update, rollback | Backup, restore same machine | Clone |
|---|---|---|---|---|
| SSH host key seed `/ssh/host_ed25519_seed` | site state | kept | kept: the restored machine is the same machine to its clients | must be regenerated (`absd-fsd --regenerate-host-key`, the existing regenerate image); a copied image that boots without regeneration is a cloned identity |
| authorized keys `/ssh/authorized_keys` | site state | kept | kept | operator decision; kept by default |
| configuration `/etc` | site state | kept | kept | kept; the address in `network.conf` is the operator's to change |
| release trees, `/absd/selected` | release | per the operation | kept | kept |
| boot identity | per boot (RDRAND) | n/a | n/a | n/a |
| installation identifier | none exists | | | a later gate may add one; cloning is detected by nothing today |

Restore-same-machine is a restore; clone-into-a-second-machine is a restore
followed by host-key regeneration, and `scripts/release.py restore
--clone` does both. Full second-machine operation remains U3. A clone takes a target identity other than the backup's, refused before the image is replaced, and keeps the selected release's selection image (section 5) built by that release's kernel; a backup carries no selection image, so the clone's receipt names every other release on the disk as without one, and a rollback to it needs `--release` and `--kernel`.

## 11. Release manifest, reconstruction, integrity

The canonical record of a release is `release-manifest.toml` in the release
directory: the id and identity fields; the kernel and platform commits and
the coordination pins; the toolchain (rustc commit, the `rust-src`
distribution tarball's URL and SHA-256, the LLVM tools, GRUB, QEMU, Python)
and the build flags and target specification; the SHA-256 of every
artifact that belongs together (the ISO, the kernel ELF inside it, the
services, the commands, the manual); the filesystem format accepted; the
support envelope; the qualification receipts; the known limitations.
`docs/RELEASE.md` (this file) and the operator pages render it; they do not
duplicate it.

Reconstruction (`scripts/reconstruct-release.sh`): from a clean clone of
both repositories at the manifest's commits and the pinned toolchain, build
and compare every artifact's digest to the manifest. The boot-image recipe
records `build.kernel_image.EXTERNAL_KERNEL_FEATURES`, including an explicitly
empty selection. Reconstruction uses that recorded selection rather than the
current served builder's policy and refuses a manifest without the field.
The schema is `absd-release-manifest/2`; reconstruct a /1 manifest with
reconstruct-release.sh at its own platform commit.
ELFs and commands are
byte-identical (the platform's reproducibility gate) when rebuilt at the
manifest's `build.platform_root`: they embed that root, the sibling staging
directories, and `CARGO_HOME` in panic locations, so a rebuild elsewhere is
expected to differ and the receipt says where it was built. The ISO is
compared by its contents (the kernel ELF and `grub.cfg` extracted from it),
because `grub-mkrescue` stamps the image; `SOURCE_DATE_EPOCH` does not
change that on the build host (GRUB 2.12 passes xorriso a modification date
from the wall clock, which sets the volume UUID and the GPT GUIDs; the
embedded GRUB EFI core also differs run to run, and mformat picks a random
FAT serial). The
kernel ELF is byte-identical when rebuilt in a checkout at the same path;
elsewhere its DWARF, local symbol names, and build-id differ, and it is
compared stripped (`llvm-strip-18 --strip-all`, the build-id descriptor
zeroed), which is reported as such. Both normalizations are recorded in the
manifest, not assumed. The toolchain check also pins the kernel's own rustc
(rustup `stable` today) by commit.

Integrity: the manifest's SHA-256 digests detect corruption of any named
artifact, and `check` in the release record detects corruption of the
record. Authenticity is not claimed: nothing signs the manifest, the only
party trusted to produce a release is the operator running the build on
the build host, and a signature would today only bind to that host's key
with no verifier that does not also trust the host. Signing is deferred
until a second party verifies releases.

## 12. Evidence

For a successor using a different kernel, `scripts/release-matrix.py` accepts
`--kernel-a OLD_CHECKOUT --kernel-b NEW_CHECKOUT`: A installation/rollback uses
A's manifest revision; B staging/selection/migration uses B's. Existing
`--kernel CHECKOUT` remains the same-kernel default. Neither selector relaxes
the release tool's exact source check or rebuilds the previous sealed release.
The aggregate `scripts/check-all.sh` accepts `ABSD_KERNEL_COMMIT` as an explicit
full revision; its default remains the previous accepted kernel. The source
repository selector alone never selects a moving HEAD.

Formalization consideration: these host-tool changes preserve each release's
exact source/identity boundary under two-kernel replay. Missing metadata was
previously treated as an absent constraint; it now refuses. Existing manifest,
record and paired-update oracles plus explicit negative metadata checks suffice
for this bounded gate; no runtime state machine, migration format or new model
is introduced. Actual successor acceptance still requires all paired gates.

`scripts/release-matrix.py` exercises, each as a QEMU boot or a host
operation with a named expected refusal: mismatched kernel and release
tree; an unsupported filesystem format; a missing update artifact; a
corrupted staged release (a release directory whose tree differs from its
manifest is refused by `stage`, and a record altered on the disk is refused
by `select`); failure before the selection switch; failure
after selection before served readiness; a failed served boot and manual
rollback; the previous release selected again; restore from a known-good
backup; restore from a corrupt backup; migration from format 1; an
attempted rollback across the migration boundary. The gate record in the
kernel repository (`docs/install-update-recovery/README.md`) lists the
results and the receipts. Optional case 16 (`--only 16`) alters a source tree
file after the build and requires a named `manifest_mismatch` refusal, one
parseable REFUSED receipt, and identical hashes for every pre-existing target
file. Case 4 retains its corrupted-source and corrupted-staged-record checks;
its pre-write refusal permits only the additional failure receipt.
