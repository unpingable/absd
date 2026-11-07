# ABSD releases: identity, install, update, rollback, backup, restore

## Build a developer-preview bundle

On the build host, `scripts/release.py preview` builds operator and enrollment
media through the current media tools and seals a downloadable preview bundle.
It starts importer/enrollment guests, so run it only inside the existing admitted
execution profile. It does not compile native platform products, publish assets,
sign them or accept a candidate.

Supply a clean platform checkout with matching native outputs, manuals and
source-bound C-port seal, and a disposable full kernel clone at the final commit.
Use the same final source pair throughout. The work and output directories must
be new, separate, and outside both source trees. The public key file is a build
input; never give this command a private key. Supply the reviewed notices rather
than copying an older release's licensing claims.

```sh
python3 -B scripts/release.py preview \
  --platform "$PLATFORM" --platform-commit "$PLATFORM_COMMIT" \
  --kernel "$KERNEL_RUN" --kernel-commit "$KERNEL_COMMIT" \
  --id "$RELEASE_ID" --tag "$RELEASE_TAG" --repository "$REPOSITORY_URL" \
  --authorized-keys "$PUBLIC_KEYS" --notices "$NOTICES" --boot-sources "$BOOT_SOURCES" \
  --work "$NEW_WORK" --out "$NEW_ASSETS"
```

The command passes `--no-local-login` to the preview producer, validates the
operator media, binds the embedded sshd, fsd and logger to the supplied native
bytes, builds the enrollment matrix, and blanks the shipped disk's SSH key file
using the existing importer. The existing helper checks blankness before
compression and again after decompression. A local-login verifier, missing C-port
seal, mismatched source or changed input refuses the composition. Disk size and
raw digest come from the actual output; the builder enforces current geometry
and successor headroom.

The output contains `operator.iso`, `enroll.iso`, `disk.img.xz`, the four helper
modules, `boot-corresponding-source.tar`, `NOTICES.md`, `BUILD-INPUTS.json`, `QUICKSTART-INPUT.json`,
`MANIFEST.toml` and `SHA256SUMS`. The manifest uses the existing
`absd-preview-manifest/1` schema. `SHA256SUMS` includes the manifest; the manifest
does not include itself. `absd_try.verify_assets` verifies the completed set.
Use repeatable `--limitation TEXT` arguments for the candidate's actual limits.

`--boot-sources` names an existing local directory containing the exact files
listed in `media/boot-source-pins.json`, including its `unifont/` subdirectory.
The command does not download sources. The pin set carries GRUB source packages
`grub2` and `grub2-unsigned` version `2.12-1ubuntu7.3`, Unifont source version
`1:15.1.01-1build1`, the upstream detached signature, and the retained copyright,
GPL text and source-verification record. Missing or changed files refuse before
media work begins; the completed archive is read back against the same pins.

The build host must have the profile's GRUB packages and exact pinned module
inventory. The checker extracts `/boot/grub` from the supplied operator ISO and
calls the existing `media_operator.check_iso_grub`: copied modules must match the
pinned package inventory, and `unicode.pf2` must match the source-attributed font
SHA256. A version string alone is insufficient. The generated `eltorito.img`
and EFI boot image remain covered by the existing media builder/validation
contract, not an independent source-rebuild proof from this attachment step.
This check does not independently establish enrollment ISO correspondence.

The source/hash pins migrate the RC1 attachment's 14-member, 13-checksum archive
validation. Their historical source is the authenticated Ubuntu archive and
font reproduction recorded in the bundled `grub-source/VERIFICATION-RC1.md`;
that historical narrative is not a verification of the new candidate. The
pinned full module inventory and copied ISO inventory come from the same RC1
media receipt. Source tar SHA256:
`5ea66ab67e865f5fe78199ccb6844c45666e44926b97b4fa65cf06898dcac1dd`.
This module is the supported validator; historical campaign scripts are evidence
only. Updating these pins requires corresponding package/source evidence and
media checks, not merely a new installed package label.

For an existing operator ISO, the same host-only step can be exercised without
building or booting media (the output parent must exist):

```sh
python3 -B scripts/boot_corresponding_source.py \
  --sources "$BOOT_SOURCES" --operator-iso "$OPERATOR_ISO" --out "$NEW_SOURCE_TAR"
```

Preview composition calls this implementation before sealing, records the
checked versions/counts in `BUILD-INPUTS.json`, and adds the archive as the
`boot_source` manifest asset and a `SHA256SUMS` entry. The standalone command
writes only the checked archive; it does not reseal an existing preview.
The archive contains `grub-source/SHA256SUMS` for its members. It accompanies
reviewed notices and does not replace first-party source delivery or release
acceptance.

The site still owns `release_docs.quickstart(record, manifest)`. Load `record`
from `QUICKSTART-INPUT.json` and the emitted TOML manifest to generate its guide;
the input contains the exact tag, source pair and proposed download URLs, with
no self-referential digests. `--quickstart FILE` can include an already generated
guide when composing a final set. Its proposed download list includes
`QUICKSTART.md` before that file exists, so adding the generated guide does not
change its generation inputs. An initial set without that guide is preparation
for documentation, not a complete public release set. The site release checks must verify the guide
against that final set before publication. A successful composition is `built`,
not qualification or publication authority.

Generate the guide using the site's pinned source, then attach it without
rebuilding media. Run these on the build host, with `SITE_SOURCE` naming that
site checkout and `NEW_GUIDE` a new path outside the asset directory:

```sh
python3 -B - "$SITE_SOURCE" "$NEW_ASSETS" "$NEW_GUIDE" <<'PY'
import importlib.util, json, pathlib, sys, tomllib
site, assets, guide = map(pathlib.Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location("preview_docs", site / "release_docs.py")
docs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(docs)
record = json.loads((assets / "QUICKSTART-INPUT.json").read_text())["record"]
manifest = tomllib.loads((assets / "MANIFEST.toml").read_text())
with guide.open("x") as output:
    output.write(docs.quickstart(record, manifest))
PY
python3 -B scripts/release.py preview-finalize --out "$NEW_ASSETS" --quickstart "$NEW_GUIDE"
```

Finalize first verifies the existing bundle and refuses an existing guide or
unlisted assets. It adds the guide, uses the same manifest/checksum writer as
composition and verifies the final bundle. The operator ISO, enrollment ISO
and compressed disk hashes must remain unchanged. It starts no media tool or
guest, and changes only the guide and sealing metadata. It does not advance
the artifact's qualification or publication standing.

Composition's provenance check receives `--peer` with the same kernel source
path. The caller supplies the steward-verified source and archive locations
through `ABSD_CARGO_REGISTRY` and `ABSD_CRATE_ARCHIVES`; both exact values are
recorded in `BUILD-INPUTS.json`. Missing or unverified inputs remain a refusal,
not a reason to bypass the paired audit.

Work contains tool logs, the validated reference disk, blank/decompressed disks,
matrix outputs and the exact final operator kernel/GRUB replay bytes. The caller
owns these intermediates through review and replay, then retires them under the
campaign's existing lifecycle checks. On failure, retain the named work directory
for diagnosis; use new paths for another admitted attempt. Nothing is overwritten
or automatically retried.

The successor heap counterexample, attribution and bounded allocator repair
are recorded in [SSH-HEAP.md](SSH-HEAP.md). That qualification does not by
itself accept or seal a successor pair.

Status: the design and operating contract of the `INSTALL_UPDATE_RECOVERY`
gate (kernel `docs/USABILITY-ROADMAP.md`, U1 "Paired update and rollback"
and "Backup, restore, recovery"). The implementation admits local QEMU configurations including TCG/KVM and
IDE/NVMe, subject to each launcher's checks. The release manifest declares
local QEMU TCG with the primary IDE master; broader implementation admission
is not an independently qualified or published support claim. Qualification
belongs to exact release/environment receipts. KVM/IDE has the recorded #74
deadline limitation; kernel-specific targeted results do not qualify the whole
release. KVM/NVMe needs its own qualification. Nothing here
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
   server prints `FSD FAILED read-only mount: <error>` and exits non-zero, and init's
   pre-ready refusal fails the boot (`SERVED RECOVERY REFUSED
   generation_not_ready`, QEMU status 7, no reset).
2. **Release record.** After the writable mount has armed the writable guard ([WRITABLE-ENTRY.md](WRITABLE-ENTRY.md)) and before `FSD READY`, the file
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
   refusal: a server that cannot parse the frame never answers. The wait
   (`absd_fsd::version::ANSWER_TICKS`, about 60 s) covers the file server's
   own startup, since init starts its clients at the same time as the
   server and the server answers only once it serves. Ordinary clients check
   before main. The logs startup name defers this check until an actual
   filesystem request, so kernel-only --volatile inspection does not wait for
   FSD. This name grants no protocol bypass: the common framed-request boundary
   enforces admission even for raw client requests. Channel installation and
   the explicit bounded logs probe invalidate cached admission. A failed generic
   diagnostic recheck preserves an installation that already passed VERSION,
   so the separate health command can finish its per-source error report.
   It cannot admit a process that never passed VERSION. logs --health uses a
   checked 1000-tick optional VERSION probe; refusal reports the retained sample
   unavailable and leaves current health unknown while kernel observations
   remain available. This bound covers VERSION only; subsequent ordinary
   sample I/O may still wait if the server stalls after answering VERSION.
   Actual sample I/O failures remain errors. The named logd
   keeps its eager 1000-tick check and timeout status 75; other clients keep the
   ordinary bound and refusal status 104. sshd makes the same check on its
   control channel before it listens, so a mismatch there ends the boot
   pre-ready.

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
| incompatible release pair | file server, after arming the writable guard, before READY | boot fails pre-ready: `RELEASE REFUSED`, QEMU 7, halted, disk left dirty: every later boot of either release refuses pre-ready (`RECOVERY WRITABLE REFUSED reason=storage_fence previous=not_ready fence=none`) and `select` and `rollback` refuse (`writable guard: unclean image`); retain the failed image and restore a backup taken before this boot into a fresh operator directory |
| missing disk or image | kernel/init (`no block device`) | boot fails: `init: FAILED at no block device`, halted |
| invalid filesystem version | library at mount | boot fails pre-ready: `FSD FAILED read-only mount: UnsupportedFormat`, halted, disk untouched |
| failed image validation (host) | the host reader before install, update, restore | the operation refuses before writing anything |
| malformed release metadata | file server, before READY | as "incompatible release pair", reason `malformed_record` or `check_mismatch` |
| incomplete update (staging cut short) | the host reader: the record is absent or its check fails; or the file server if it was selected | staging refuses to select; if already selected, as "incompatible release pair" |
| rollback target unavailable | the host tool | the rollback refuses; nothing is written |

Every one of these fails closed with one reason line, repairs nothing by
guessing, and keeps the previously bootable release where one exists, except that a `RELEASE REFUSED` boot leaves the disk dirty (above). A
pre-ready failure never resets, so there is no reboot loop and the console
evidence survives.

## 5. Install, update, acceptance, rollback

**Slots.** The disk holds at most two release trees under `/releases/`. `scripts/release.py remove` retires a tree that is neither selected nor the ledger's last accepted release, on a halted image: importer step 5 removes `/releases/<id>/` whole in one commit (a stop leaves the whole tree or none of it), the host reader confirms it gone and every other file unchanged, and only then does the operator directory drop that release's boot image and selection cache; a third release can then be staged; removing a release gives up rollback to it.
`/absd/selected` names the one the file server binds at boot; the boot
image booted must be that release's. The host tool keeps a ledger
(`RELEASES` in the operator directory) of every release it installed,
selected, accepted, or rolled back, and of every reconfiguration, with the receipts. Procedure: [OPERATOR-RUNBOOK.md](OPERATOR-RUNBOOK.md).

**Reconfigure** (`scripts/release.py reconfigure`) replaces site
configuration (`/etc` files, optionally `/ssh/authorized_keys`) on a
halted target. It is an importer operation like the others: one step-4
boot of the **selected** release's importer, as a private copy checked
against that release's manifest. The boot runs under a kernel at the
manifest's commit (section 3), and the release must be the one
`/absd/selected` names, with the record the manifest lists. All of these
are checked before the guard is marked dirty: the operator directory's
records (`TARGET` and `RELEASES` regular files, `receipts/` a directory),
the files' fit in one boot, the replacement paths, and the filesystem
capacity. A newest install or stage receipt of the release that cannot be
read refuses; only a release with none at all (migrated or restored) is
accepted without one, recorded as `installation_evidence = "none"`.
After the read-back, the whole disk is compared with its state before the
boot, leaving out only the replacements and the guard. Only then is the
receipt published, atomically, and a `reconfigured <id>` line appended to
the ledger in one synced write. Acceptance and rollback do not read that
line. The runbook's section 13 lists the failure states, says which
persistence each confirms and which it leaves uncertain, and gives the
manual ledger reconciliation. The image, the receipt and the ledger are
not one transaction. Like every other command that writes the image, it
holds the recovery lock for its duration and refuses `tool_busy` and
`recovery_pending` (and `image_locked`) before it writes the image, the
guard or the ledger. A refusal may leave its best-effort failure receipt
and, on a target that had none, the recovery lock's file `recovery/lock`,
which is created on first use and never removed. Exclusive use beyond the
lock, against a writer outside the ABSD tools, is the operator's.
`scripts/operator_image.py reconfigure` (afterboot(8)) is for
build-operator-image.sh outputs. Its behaviour changed with this command:
it prepares every boot before it marks the guard dirty, and it refuses an
operator directory of this tool, where it used to import and then fail. Procedure: [OPERATOR-RUNBOOK.md](OPERATOR-RUNBOOK.md).

**Install** (`scripts/release.py install`): formats the target image,
installs the release tree, `/etc` and `/ssh/authorized_keys` from the
release's `site-defaults`, and `/absd/selected`, verifies the
result with the host reader, and writes an install receipt. The target is
identified explicitly (section 9). The write path is the existing one: the
release's own fixture-importer boots, each file one commit, under the
existing QEMU and `nvme-write` conventions.
The default disk is 128 MiB; `--disk-profile 2g` explicitly selects a fresh
2 GiB disk. This option does not resize an existing installation (section 6).

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

Importer steps 1-4 construct each file in an exclusively created temporary
directory, sync and verify its file's readback, then commit by rename. Steps 1/2 use
rename without replacement; step 3 copies the current writable prefix and
verifies both prefix and suffix before replacement. Append temporarily needs
space for the complete successor alongside the old file. Each committed chunk
is a verified prefix; whole-file manifest verification still decides STAGED.
An uncertain append must be reconciled against the recorded plan before retry,
since blind replay could append twice. Temporary files left by process loss
are inspected separately and never removed just because their name matches.
Host verification rejects reserved names at planned import parents, `/absd`
and `/etc`. It also rejects every unlisted object, including empty directories,
inside imported release/bin/share trees. Other reserved-name lookalikes produce
an explicit ownership warning and do not block unrelated staging.
`status` prints candidate directory identities without asserting ownership;
non-importer layouts report `REFUSED import_temp_layout` with the exact path
and recovery action. Inspect and remove such guest objects in the guest if
authorized, or restore a verified backup; host discard does not delete arbitrary
contents. Temporary records in failure receipts are best-effort: early stdin
closure can suppress worker output (kernel item 274658159). Missing receipt
fields do not prove absence of a temporary object. After matching the
attempt's receipt, `discard-import-temp --directory PATH --fs-id ID --serial N
--bytes N --sha256 HEX` (with the usual `--target`, `--release`, `--kernel`)
checks that identity and the directory's exact single-file contents, invokes
existing step 5, and confirms other bytes unchanged. It refuses extra objects
or an open image. Empty directories left before file creation use size zero
and SHA-256 of the empty string. Failures after starting removal are
INDETERMINATE. No directory is discarded automatically from its name.
See [the construction and recovery design](fixture-import-atomic/DESIGN.md).

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
in-place upgrade exists. Migration refuses `migration_recovery_history` when
`/var/state` or `/var/state.new` recovery history (including children) exists
or the old guard is neither absent nor fresh. It does
not provide the explicit new-device conversion rule needed for those inputs;
preserve them rather than clearing history or resetting recovery state.

**Operator image size.** Fresh operator disks have two explicit profiles
(coordination record #28): `128m`, the unchanged 128 MiB default, and opt-in `2g`, a
2 GiB disk. Select `--disk-profile 2g` with `build-operator-image.sh`,
`operator_image.py build`, or `release.py install`. Their filesystem regions
are 64 MiB and 1 GiB respectively; metadata and installed files consume part
of that space. The filesystem, the disk's second half, must hold the installed release
and stage a complete successor of the same composition beside it, with a
quarter of the successor's peak allocation to spare. `operator_image.py`
and `release.py install` refuse a composition that loses that headroom
(`successor_headroom`). A profile selects only a fresh image's size; the tool reads
every disk at the disk's own size, which the layout descriptor must match.
A 64 MiB disk (RC1 and earlier) can therefore be identified, inspected
(`status`), backed up, and restored unchanged as a 64 MiB disk. The tool
writes only to validated 128 MiB or 2 GiB operator disks: `stage` refuses a 64 MiB disk before
writing anything (`image_size`, with the blocks staging would need and the
blocks free; the canonical composition, with `/bin/https-document`, does
not fit), the other mutating commands refuse it at the recovery boundary
(`image_size`), and `restore --clone`, which boots the copy writably,
refuses a backup outside those two sizes. Pinned recovery retains the
previous bound for images at most 128 MiB and separately admits an exact
2 GiB image; intermediate larger sizes are not admitted.
No conversion or in-place resize
exists; the layout and filesystem bind their geometry to the device size.
A 128 MiB descriptor padded to 2 GiB is invalid. Migration keeps its existing
format and recovery-history restrictions and still creates the default size.
Host readers and pinned recovery materialize the whole image in memory;
budget at least the backing size for each snapshot, plus parsing and file
buffers. Backup and restore can allocate full-size copies of sparse inputs.

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

- Clock: fallible boot-local software civil time, truncated to whole Unix
  seconds. RTC bootstrap before the fixed 2026 build floor is unknown; eligible
  RTC bootstrap is unverified. Operator and configured unauthenticated
  estimates can correct this anchor without changing the raw RTC or monotonic
  deadlines. Precision is one second, not an accuracy guarantee. Unknown time
  records 0; the infallible Rust SystemTime bootstrap coordinate is not an
  mtime source. See kernel `docs/CIVIL-TIME.md`.
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
| SSH host key seed `/ssh/host_ed25519_seed` | site state | kept | kept: the restored machine is the same machine to its clients | must be regenerated (the dedicated `absd-fsd-regenerate.elf`); a copied image that boots without regeneration is a cloned identity |
| authorized keys `/ssh/authorized_keys` | site state | kept | kept | operator decision; kept by default |
| configuration `/etc` | site state | kept | kept | kept; the address in `network.conf` is the operator's to change |
| release trees, `/absd/selected` | release | per the operation | kept | kept |
| boot identity | per boot (RDRAND) | n/a | n/a | n/a |
| installation identifier | none exists | | | a later gate may add one; cloning is detected by nothing today |

Restore-same-machine is a restore; clone-into-a-second-machine is a restore
followed by host-key regeneration, and `scripts/release.py restore
--clone` does both. Full second-machine operation remains U3. A clone takes a target identity other than the backup's, refused before the image is replaced, and keeps the selected release's selection image (section 5) built by that release's kernel; a backup carries no selection image, so the clone's receipt names every other release on the disk as without one, and a rollback to it needs `--release` and `--kernel`.

`scripts/build-ssh.sh` enables the `regenerate-host-key` Cargo feature only
for the dedicated file-server artifact. Clone construction uses it for the
regeneration boot; ordinary operator and release images use `absd-fsd.elf`.
The dedicated program regenerates while serving even when the parent's
startup record supplies other arguments, such as `--storage-fence=none`.
The record still controls argv; the runtime does not merge build-time
fallback arguments into it. A normal file server keeps a valid existing seed
unless explicitly given `--regenerate-host-key`.

The dedicated program still accepts either explicit finalization operation
without generating another key. It refuses conflicting finalizers, an
explicit finalizer with regeneration or a qualification fault control, and
serving regeneration with a qualification fault control before filesystem
writes. Its existing clean/fresh write guard, seed write protocol and clone
key-change checks remain required. Choosing a different program does not
grant storage authority. A clone establishes a different machine identity;
this operation does not transfer a live service generation, revive fenced
handles or promise rollback after the new identity becomes visible.

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

For curated public snapshots, use the public repository’s `tools/rebuild-release.sh`
recipe documented in its README. The generic script refuses public snapshot
manifest descriptors before toolchain checks, cloning or output creation: upstream
component commits need not exist in the curated public repository.

Separate-component reconstruction (`scripts/reconstruct-release.sh`): from a clean clone of
both repositories at the manifest's commits and the pinned toolchain, build
and compare every artifact's digest to the manifest. The boot-image recipe
records `build.kernel_image.EXTERNAL_KERNEL_FEATURES`, including an explicitly
empty selection. Reconstruction uses that recorded selection rather than the
current served builder's policy and refuses a manifest without the field.
The schema is `absd-release-manifest/2`; reconstruct a /1 manifest with
reconstruct-release.sh at its own platform commit.
Earlier /2 manifests without `LOGD_ELF` and `LOGD_FAULT` also require
reconstruct-release.sh at their own recorded platform commit. The current
logging release build copies its logger artifact into the release directory
and embeds that exact copy; its manifest records both the logger and the
zero fault-injection policy. The normal SSH/served/recovery boot builders
pass the logger too, rather than collecting evidence for a different boot.
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
after selection before served readiness, followed by a fenced cold successor;
a served but unaccepted B release, clean halt and manual rollback to accepted A
on an independent clean history; the previous release selected again; restore from a known-good
backup; restore from a corrupt backup; migration from format 1; an
attempted rollback across the migration boundary. The gate record in the
kernel repository (`docs/install-update-recovery/README.md`) lists the
results and the receipts. Optional case 16 (`--only 16`) alters a source tree
file after the build and requires a named `manifest_mismatch` refusal, one
parseable REFUSED receipt, and identical hashes for every pre-existing target
file. Case 4 retains its corrupted-source and corrupted-staged-record checks;
its pre-write refusal permits only the additional failure receipt.
Case 6's cold successor must refuse without writes, flushes, errors or image
changes. Cases 7 and 8 never reuse that failed-boot image or clear its guard.
They exercise rollback after an orderly halt with acceptance withheld; writable
recovery or rollback after a failed served boot remains unsupported. Selecting
case 8 alone includes the clean B-serve, halt and rollback prerequisites.


### Optional HTTPS document release selection

An App A release must use the same explicit opt-in for the native build, image
assembly and manifest generation. See [the App A build and reconstruction
contract](NATIVE-HTTPS-DOCUMENT.md#build-and-configuration). Reconstruction pins
that selection rather than inheriting it from the caller. Qualify the actual
installed command and its dependency notices before claiming an enabled release;
ordinary release construction remains disabled by default.


### Curated public source identity

A curated source release has one public repository HEAD, while each kernel or
platform directory maps to an upstream component revision through the committed
`SOURCE-MANIFEST.toml`. Those identities are distinct. For a public kernel,
`source.kernel_commit` names the checked upstream component revision;
`source.kernel_repository_commit` and `source.kernel_repository_tree` retain the
actual public repository HEAD and tree. `source.kernel_snapshot` binds that
repository identity, the exact component path/tree, upstream revision/tree and
source-manifest digest. `source.platform_commit` remains the actual producer
repository HEAD used by the native App A build receipt; `source.platform_snapshot`
records its separate upstream component correspondence.

The manifest reader requires the source manifest's exact committed bytes, a
unique matching named component and the actual clean component tree. It relies
on the qualified source assembly for the truth of upstream curation; it does
not reconstruct omitted development history. Kernel admission requires an exact
matching public snapshot descriptor. A standalone private checkout or a copied
`.absd-identity` marker cannot substitute for that public mapping. Existing
standalone checkout admission is unchanged for standalone-built releases.

Keep the input public source checkout protected. For importer or recovery work,
clone the complete public repository into a second disposable directory and use
its `kernel/` subdirectory as `--kernel`. The two complete clean clones must
have the same public HEAD/tree and component mapping. Do not initialize a new
kernel-only repository, synthesize an upstream commit, or bypass the protected
source check. A modified manifest, component, mapping or repository identity
refuses before the importer can write a target.

For an existing standalone-built release, the supported `absd_kernel_run`
snapshot-delivery path remains distinct. Start from the qualified committed
public source, run its source-cleanliness check, and copy its manifest-verified
kernel into a fresh external run directory using `scripts/inputs.sh`. The
existing `.absd-identity` names the checked upstream component for that legacy
admission path. It does not turn the public HEAD into private Git history or
claim that the curated tree equals the unfiltered private source. Preserve the
public component tree and curation correspondence with the build/recovery
receipt. Actual nominated artifacts remain the inputs to install and recovery;
public rebuilt counterparts are compared separately. A private-source A/B
qualification still needs its real private ancestry and exact oracle source.

### Local operator enrollment in release builds

Fresh `release.py build` enrolls local login by default. Only the verifier is
written to `site-defaults/local-login`, checked against the release manifest
and installed at `/ssh/local-login`. The raw token is kept outside the release
directory at `OUT.local-console-token`; its reusable descriptor is alongside it
with `.verifier` appended. Both host files are mode 0600. They are not release
artifacts and must be transferred separately through existing private access.
Use `--local-token-file FILE` to select an external token destination, or
`--local-login-verifier FILE` to reuse enrollment when rebuilding. Existing
paths are never overwritten. Served kernels enable local console explicitly;
all importer kernels disable it, independent of inherited environment.

### Supported readable waits

`wait_readable` (0x7fa8) is additive to kernel ABI 1. The ABI generation stays
1, so existing binaries remain compatible. New FSD service startup probes the
call with an empty set before channel validation or writable startup. A kernel
without the call returns -38; FSD prints `FSD FAILED kernel lacks wait_readable`
and exits 3. It never falls back to polling. Finalization modes remain independent
of this serving-only dependency. Pair the new FSD with a kernel supporting the
call; see `wait_readable(2)` and [readable waits](WAIT-READABLE.md).
