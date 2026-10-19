# Operator runbook: paired releases on one machine

This is the procedure for the host tool `scripts/release.py`. The contract
it carries out is [RELEASE.md](RELEASE.md); where the two seem to differ,
RELEASE.md and the tool's code decide, and this page is wrong. Every claim
below cites the line it rests on: `release.py:N` is `scripts/release.py`,
`RELEASE.md:N` is `docs/RELEASE.md`.

Scope is the contract's: the operator image under local QEMU, the disk as
the primary IDE master or one NVMe namespace, TCG or KVM; no physical
machine is claimed (RELEASE.md:9-13). Everything here runs on the build
host against a halted disk image, operator-driven. Nothing on the machine
updates, rolls back, or falls back by itself.

## 0. Conventions

Names used in the commands:

| Name | What it is |
|---|---|
| `A`, `B` | release directories made by `release.py build` (release.py:5-9, 515-553); `A` is installed first, `B` is the update |
| `KA`, `KB` | disposable kernel checkouts at the commit each release's manifest names (section 1) |
| `OUT` | the operator directory: one machine (release.py:11-16) |
| `KEY` | the operator's private key; its public half is in the release's site defaults or was given at build (release.py:538-539, 154-156) |
| `BACKUP` | an empty or absent directory for a halted backup |

Commands run from the top of the platform checkout. Every command prints
its result line on standard output. A refusal prints
`release: refused: <reason>` on standard error and exits 1
(release.py:1268-1272); the reasons are quoted below as the tool prints
them. A command missing `--release` or `--kernel` where it needs one
exits 2 with `<command> needs --<option>` (release.py:1262-1267).

What the tool leaves in `OUT` (release.py:11-16, 62-65):

- `absd-operator.img`, the disk, mode 0600 (release.py:572-575).
- `absd-operator.iso`, the boot image of the selected release
  (release.py:584, 661).
- `releases/<id>/absd-operator.iso`, each release's own boot image
  (release.py:281-282, 581-582).
- `releases/<id>/select.iso`, `releases/<id>/durable-boot.sh` and
  `releases/<id>/select.toml`, the release's selection cache: the importer
  step 4 image that selects that release, the kernel's boot script that
  runs it, and the record of both digests, written last
  (release.py:322-375). Install, stage and migrate write it
  (release.py:568-583, 621-630, 1059-1079); `rollback` without `--kernel` boots it
  (section 7).
- `TARGET`, the target identity given at install (release.py:585).
- `RELEASES`, the append-only ledger, one line per event:
  `<UTC time> <action> <id> <detail>` (release.py:263-266).
- `receipts/<action>-<id>-<UTC time>.toml`, one per operation that writes
  a receipt (release.py:275-279).

Rules that hold for every step:

- **The machine is halted for every disk operation.** Each write is a QEMU
  boot of the release's own importer against `OUT/absd-operator.img`
  (release.py:18-21, 287-319). Halt the machine with `shutdown` over SSH
  before `install`, `stage`, `select`, `rollback`, `accept`, `backup`,
  `restore`, `migrate`, or `remove`. The tool itself checks that no
  process holds the image open only for `backup`, `rollback` and `remove`
  (release.py:820-827); for the others the halt is the operator's to
  ensure (section 11).
- **One operation per kernel copy at a time.** Every importer boot builds
  its ISO inside the kernel copy at `build/durable/absd-durable-<step>.iso`
  (scripts/operator_image.py:108-115), so two operations on one copy
  overwrite each other's image. `install`, `stage` and `migrate` each also
  build one more image there, the release's step-4 selection image for the
  cache (release.py:344-356), so each takes one `make durable-iso` longer
  than its importer boots alone. A rollback from the selection cache uses
  no kernel copy (section 7).
- **At most two release trees on the disk** (release.py:68;
  RELEASE.md:134-135). Make room for a third by removing a retired one
  (section 5, "Make room").

## 1. Prepare a kernel copy for a release

Every disk write needs `--kernel`, a kernel checkout at the exact commit
the release's manifest names (release.py:159-178, 181-193; RELEASE.md:109-113).
The canonical kernel checkout is never accepted (release.py:185-186);
make a disposable one, the way `scripts/inputs.sh` does
(scripts/inputs.sh:224-232):

```sh
commit=$(python3 -I -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["source"]["kernel_commit"])' A/release-manifest.toml)
git clone --quiet --shared --no-checkout /path/to/kernel KA
git -C KA checkout --quiet --detach "$commit"
```

A copy without `.git` is accepted when it carries the commit in
`.absd-identity` (scripts/operator_image.py:155-166).

Refusals (each before any write):

- `give --kernel <a kernel checkout at <commit>> (release <id>)` (release.py:182-183)
- `the canonical kernel checkout is never a build target` (release.py:185-186)
- `<KA>: not a kernel checkout` (release.py:187-188)
- `kernel checkout is at <head>, release <id> was built from <commit>` (release.py:189-192)
- from the release's manifest: `missing release-manifest.toml`,
  `malformed release manifest: …`, `unsupported release manifest schema`,
  `malformed release manifest tables`, `manifest release_mismatch`,
  `manifest identity_mismatch`, `missing or invalid manifest kernel_commit`
  (release.py:159-178)
- from the release directory itself: `no release record`, the record's
  malformation reason (`malformed_record`, `check_mismatch`, …), or
  `missing <file>` for the ISO, `fixture-import.elf`, `absd-fsd.elf`,
  `absd-fsd-regenerate.elf`, `sshd.elf` or `tree` (release.py:122-133,
  112-117)

## 2. Install a paired release

```sh
python3 -I scripts/release.py install --release A --kernel KA --target OUT --target-identity lab-1
```

What it does: writes a blank 64 MiB image, installs A's tree, the site
defaults (`/etc`, `/ssh/authorized_keys`) and `/absd/selected`, one
importer boot per plan step, reads every file back with the host reader,
checks the disk's format against A's record, and copies A's boot image
into place (release.py:556-585; RELEASE.md:140-146). Before it touches the
disk it builds A's selection cache in a temporary directory under `OUT`
and moves it to `OUT/releases/<A>/` once the install is verified
(release.py:568-583, 344-375).

Success prints one `release: importer boot <i>/<n> step <s>: <k> files`
line per boot (release.py:305), then
`RELEASE INSTALLED id=<A> target=lab-1 files=<n> receipt=<name>`
(release.py:600).

Receipt: `receipts/install-<A>-<time>.toml` with the importer boot count,
the format, the identity fields, and the digests of the ISO, the importer,
the services, the manifest, and the file set, and a `[select_cache]` table
with the cache's location, file names and digests and the kernel commit
(release.py:586-597, 367-375). Ledger:
`installed <A>` then `selected <A>` (release.py:598-599).

Refusals:

- `<OUT>/absd-operator.img exists; --replace to install over it (the disk is destroyed)` (release.py:560-561)
- `target identity is '<old>', not '<given>'` (release.py:562-563)
- `the release ships no authorized keys and none were given; the machine would be unreachable` (release.py:566-567)
- `<KA>: no scripts/durable-boot.sh to keep with the selection image`, before the disk is touched (release.py:348-349)
- `importer boot <i> (step <s>): QEMU status <n>` (release.py:303-304)
- `the host reader sees different bytes at <path>` (release.py:420-424)
- `the installed disk reads as format <n>, the release expects <m>` (release.py:578-580)
- every refusal of section 1

## 3. Boot and verify readiness over SSH

```sh
scripts/boot-operator.sh OUT 2222
```

QEMU runs in the foreground with `OUT/absd-operator.iso` (the selected
release's image) and `OUT/absd-operator.img`, the console in
`OUT/console.log` (scripts/boot-operator.sh:20-31). It prints
`boot-operator: ssh -p 2222 operator@127.0.0.1 reaches <guest>:<port>; …`
(scripts/boot-operator.sh:25).

Ready means the console shows `RELEASE OK release=<id>` and the listener
record, and the pre-ready window is over (RELEASE.md:162). From a second
terminal:

```sh
grep -a 'RELEASE OK release=' OUT/console.log
grep -a '^sshd: host key' OUT/console.log
```

The first line names the selected release (RELEASE.md:79-83). The second
gives the host key's fingerprint and public key in plain text
(man/afterboot.8:81-91); put the public key in a known_hosts file and
connect with strict checking (man/afterboot.8:98-103):

```sh
echo "[127.0.0.1]:2222 ssh-ed25519 AAAA…" > known_hosts
ssh -p 2222 -i KEY -o UserKnownHostsFile=known_hosts -o StrictHostKeyChecking=yes operator@127.0.0.1 release
```

`release` prints `release=<id> kernel_abi=1 fsd_protocol=2 fs_format=2
app_abi=1`: the file server's own answer for the id, protocol and format
(src/bin/release.rs:1-9, 21-29; RELEASE.md:40-51); the four numbers are
`IDENTITY` (scripts/release_record.py:34). The id must be the one you
selected. Then halt:

```sh
ssh -p 2222 -i KEY -o UserKnownHostsFile=known_hosts -o StrictHostKeyChecking=yes operator@127.0.0.1 shutdown
```

`boot-operator.sh` prints `boot-operator: the machine halted` and exits 0
(scripts/boot-operator.sh:33). Any other status is printed and returned; 7
is a boot that failed before readiness (scripts/boot-operator.sh:34; table
in section 9).

This boot is an inspection. It is not acceptance: "kernel booted" and a
served boot without `accept` leave the release a candidate (RELEASE.md:167-169).
The machine must be halted before the next step, which boots its own QEMU
on the same image and the same default port (release.py:727, 1254).

## 4. Accept the served release

```sh
python3 -I scripts/release.py accept --target OUT --key KEY
```

What it does: boots `OUT/absd-operator.iso` against the disk, waits for
`RELEASE OK release=<selected>` and `SSH LISTENING` (release.py:465-480),
runs `/bin/release` and requires `release=<selected>` (release.py:732-735),
writes `/home/operator/.accept` and reads it back (release.py:736-743),
asks for `shutdown` and requires `going down for halt` (release.py:744-746),
requires QEMU status 3 and no `SERVED SHUTDOWN ESCALATED` or
`SERVED RECOVERY` line on the console (release.py:747-751), and reads the
marker from the committed image with the host reader (release.py:754-756).
This is the `ACCEPTED` state (RELEASE.md:163).

Success prints `RELEASE ACCEPTED id=<id> receipt=<name>` (release.py:765).
Receipt: `receipts/accept-<id>-<time>.toml` with the host key fingerprint,
the halt status, the identity fields and each check (release.py:757-763).
Ledger: `accepted <id>` (release.py:764); this line is what `rollback`
reads (release.py:685). The console of this boot is
`OUT/console-accept-<id>.log` (release.py:436, 727).

Refusals (each leaves the release a candidate, state `FAILED`,
RELEASE.md:164):

- `no_selected_release` (release.py:721-722); `no_release_tree` or a record malformation (release.py:723, 253-258)
- `<OUT>/absd-operator.iso: no boot image` (release.py:724-725)
- `the boot ended with QEMU status <n> before readiness:` followed by the console's refusal lines (release.py:476-478, 482-490)
- `no served readiness within 300s:` (release.py:465, 480)
- `release command: rc=…` (release.py:734-735); `write: rc=…` (release.py:738-739); `read back: rc=…` (release.py:741-742); `shutdown: rc=…` (release.py:745-746)
- `the halt was not orderly (status <n>):` (release.py:750-751); `the machine did not end in time` (release.py:495-500)
- `the acceptance marker is not in the committed image` (release.py:755-756)

## 5. Stage an update

With A selected and accepted:

```sh
python3 -I scripts/release.py stage --release B --kernel KB --target OUT
```

What it does: B's importer writes B's tree into `/releases/<B>/`; it never
touches `/releases/<A>/` or `/absd/selected`; the host reader verifies
every file; B's boot image is kept as `OUT/releases/<B>/absd-operator.iso`
and B's selection cache, built before the importer boots, in
`OUT/releases/<B>/` (release.py:603-630; RELEASE.md:148-153). This is `STAGED`
(RELEASE.md:159).

Success prints `RELEASE STAGED id=<B> selected=<A> trees=<A>,<B>`
(release.py:638). Receipt: `receipts/stage-<B>-<time>.toml` with
`selected_before`, `selected_after`, `state = "STAGED"` and the
`[select_cache]` table (release.py:631-636). Ledger: `staged <B>` (release.py:637).

Refusals (before any write unless noted):

- `the disk is format <n>; release <B> reads format <m>: migrate first (release.py migrate)` (release.py:608-611)
- `release <B> is already on the disk; remove it first (release.py remove)` (release.py:615-616)
- `the disk holds 2 releases (<x>, <y>); at most 2: remove one that is neither selected (<s>) nor the last accepted` (release.py:617-619)
- `importer boot …` and `the host reader sees different bytes at <path>` (release.py:303-304, 423-424), after a partial write: the selection is unchanged, A still boots, and a later `select B` refuses (RELEASE.md:124)
- `staging changed the selection; this must not happen` (release.py:626-627)
- `<KB>: no scripts/durable-boot.sh to keep with the selection image`, before any write (release.py:348-349)
- every refusal of section 1; the disk's own refusals: `no disk image`, `no layout (not an ABSD disk)`, `the filesystem superblock is not ABSD's`, `the host reader refuses the disk: …`, `malformed_selected` (release.py:210-242)

### Make room: remove a retired release

With two trees on the disk, staging a third refuses (release.py:617-619).
Once B is selected and accepted, A is retired: it is neither selected
nor the ledger's last accepted release. Remove it with the importer of a
release whose format is the disk's, normally the selected one, under that
release's kernel copy:

```sh
python3 -I scripts/release.py remove --release B --kernel KB --target OUT --id A
```

What it does: refuses unless the image is halted, by the same check
`backup` uses (release.py:1163-1165, 789-827). It refuses unless A is on
the disk and is neither selected nor last accepted (release.py:1175-1179).
Then one importer boot of step 5 removes `/releases/<A>/` and everything
below it in one commit, so a stop at any point leaves the whole tree or
none of it (release.py:1180-1188; src/bin/fixture_import.rs:22-26, 76-99).
Before the boot it writes the intent, `OUT/REMOVING` holding `<A>`
(release.py:1183-1186); the intent goes last, after the operator
directory is brought into line (release.py:1114-1129).
The host reader then requires every file of A's tree gone and every
other file unchanged (release.py:1192-1207). Only then does the tool
delete `OUT/releases/<A>/`, A's boot image and selection cache
(release.py:1208-1209, 1118-1120). Removing A also removes the way back to A: a
later rollback goes to the last accepted release other than the selected
one, and refuses `has no tree on the disk (removed, …)` if that is A
(release.py:690-692).

Success prints `RELEASE REMOVED id=<A> files=<n> trees=<B> receipt=<name>`
(release.py:1213). Receipt: `receipts/remove-<A>-<time>.toml` with the
file count, the importer's release and kernel commit, the importer's
status, the selection and the trees after (release.py:1122-1125). Ledger:
`removed <A> by=<B>` (release.py:1126-1127). Then stage C as above.

**An interrupted removal.** If the tool is stopped after the intent is
written (a host crash, an interrupt, a failure in the operator directory)
`OUT/REMOVING` remains. `stage`, `select`, `migrate` and `rollback` then
refuse `removal_unreconciled: <OUT>/REMOVING records an interrupted
removal of <A>; run release.py remove --id <A> to reconcile the operator
directory first` (release.py:1107-1111; 607, 673, 682, 1050). Run the same
`remove` command again. It reconciles before anything else
(release.py:1166-1170, 1132-1145). If the disk no longer holds A, it
finishes the operator directory with no boot, prints
`RELEASE REMOVE RECONCILED id=<A>: the disk no longer holds it; …`, and
ledgers `removed <A> by=<B> receipt=… reconciled` with `importer_status =
"interrupted after the commit; reconciled"`. If the disk still holds A,
it drops the intent, prints `RELEASE REMOVE RECONCILED id=<A>: the disk
still holds its tree; nothing to finish`, and carries on with the
removal. A malformed `OUT/REMOVING` refuses `removal_unreconciled: … is
malformed`; check `status` and delete the file by hand
(release.py:1100-1103).

Refusals, each with the disk and `OUT` unchanged:

- `release id '<x>' is not [a-z0-9.-]{1,64}` (release.py:1161-1162); `<OUT>/absd-operator.img: no disk image` (release.py:1163-1164)
- `image_in_use: <OUT>/absd-operator.img is open in pid <n> (<name>); halt the machine (shutdown) before a removal` (release.py:1165, 820-827)
- `the disk is format <n>; release <B>'s importer writes format <m>: remove with a release that reads the disk` (release.py:1171-1174)
- `<A> is selected or the last accepted release; not removable` (release.py:1176-1177): the selected release, and the known-good one, which while the selected release is not yet accepted is the one a rollback goes to
- `<A> has no tree on the disk` (release.py:1178-1179)
- every refusal of section 1 for B and `KB`
- `importer boot 1 (step 5): QEMU status <n>` followed by `the disk still holds <A> whole; nothing was removed` (release.py:1187-1191, 1202-1204). An importer built before step 5 existed refuses this way (`FIXTURE IMPORT FAILED unknown step 5`); remove with a release built since.

Refusals after the importer boot that are not a clean no-op:

- `the removal of <A> left <k> of its <n> files on the disk; the operator directory is untouched; run remove again` (release.py:1205-1207). The filesystem removes a tree in one commit, so this is not expected; the tree is still listed and a second `remove` finishes it.
- `the removal of <A> changed files outside its tree: …; the operator directory is untouched; restore a backup` (release.py:1199-1201).
- `the importer boot reported a failure, but the disk no longer holds <A>; the operator directory was brought into line (ledger: removed <A>)` (release.py:1210-1212): the commit landed and the tool finished the removal in `OUT`, with `importer_status = "failed after the commit"` in the receipt; read the console lines it prints.

## 6. Select and boot the update

```sh
python3 -I scripts/release.py select --release B --kernel KB --target OUT
```

What it does: checks B's tree and record on the disk, rewrites
`/absd/selected` whole in one importer step 4 commit, checks the
selection took, and copies B's boot image to `OUT/absd-operator.iso`
(release.py:641-666; RELEASE.md:152-153, 258). This is `BOOT_SELECTED`
(RELEASE.md:160).

Success prints `RELEASE SELECTED id=<B> from=<A>: boot <OUT>/absd-operator.iso`
(release.py:666). Receipt: `receipts/selected-<B>-<time>.toml` with
`selected_before`, `state = "BOOT_SELECTED"` and `source = "kernel"`
(release.py:662-664, 646). Ledger: `selected <B> from=<A>` (release.py:665).

Refusals: `release <B> has no tree on the disk` (release.py:651-652); a
malformed or missing record on the disk, by the file server's reason name
(release.py:653, 253-258); `the selection did not take` (release.py:657-658);
every refusal of section 1.

Then boot and verify B as in section 3 (`BOOTING`, `SERVED_READY`,
RELEASE.md:161-162), halt it, and accept it as in section 4. Until B is
accepted, A remains the known-good release (RELEASE.md:167-169).

## 7. Roll back to the previous pair

No build host is needed: the rollback boots the selection image cached
when the previous release was installed or staged.

```sh
python3 -I scripts/release.py rollback --target OUT
```

What it does: finds the ledger's last `accepted` release other than the
selected one, requires its tree on the disk and its format equal to the
disk's (release.py:677-697; RELEASE.md:171-176). It then checks that
release's selection cache: `select.toml` must name that release, step 4
and the digest of its selection, and `select.iso` and `durable-boot.sh`
must have the digests it records. The release's boot image must also be
in `OUT/releases/<A>/` (release.py:378-408, 704). Before either form
writes, it refuses an image that any process holds open, by the check
`backup` uses (release.py:699, 789-827): a B left running, or a QEMU
paused by a guest restart, must be stopped first. The cached boot script
attaches the disk as `ata` (the default) or `nvme` only; with
`ABSD_BLOCK_ATTACH=laptop` the cached form refuses by name (use the
`--kernel` form there). Then it boots
`select.iso` under the cached `durable-boot.sh`, one importer step 4
commit, and checks the selection took, as `select` does (release.py:411-417,
649-666, 705-709). No kernel copy, release directory or `make` is used.
State created under B stays on the disk (RELEASE.md:174-176).

The explicit alternative, for a release staged before the cache existed
or a cache refused below, builds the selection from the release's
importer under its kernel, as `select` does (release.py:710-713):

```sh
python3 -I scripts/release.py rollback --release A --kernel KA --target OUT
```

Success prints `RELEASE ROLLED_BACK id=<A> from=<B>: boot <OUT>/absd-operator.iso`
(release.py:666). Receipt: `receipts/rolled_back-<A>-<time>.toml` with
`source = "cache"` and the digests of the cached image and boot script and
the kernel commit it was built from, or `source = "kernel"`
(release.py:662-664, 706-708, 646). Ledger: `rolled_back <A> from=<B>`
(release.py:665).

Then boot A as in section 3 and accept it as in section 4. `ROLLED_BACK`
holds when A's image boots to `SERVED_READY` (RELEASE.md:165).

Refusals (each before any write):

- `no accepted release other than the selected one in the ledger: nothing to roll back to` (release.py:685-688)
- `rollback target <A> has no tree on the disk (removed, or the disk was migrated: restore the pre-migration image instead)` (release.py:690-692)
- `rollback target <A> reads format <n>, the disk is format <m>: a rollback across a migration is a restore of the pre-migration image` (release.py:693-697; RELEASE.md:178-182)
- `image_in_use: <OUT>/absd-operator.img is open in pid <n> (<name>); halt the machine (shutdown) before a rollback`, either form (release.py:699, 820-827)
- `removal_unreconciled: <OUT>/REMOVING records an interrupted removal of <X>; …` (release.py:682, 1107-1111; section 5, "Make room")
- without `--kernel`, with `ABSD_BLOCK_ATTACH` other than `ata` or `nvme`: `select_cache_laptop_unsupported: …` (release.py:383-386)
- without `--kernel`: `select_cache_missing: <OUT>/releases/<A>/select.toml: no cached selection image for <A>; give --release <the directory of <A>> and --kernel <a kernel checkout at its commit> to select it by an importer boot instead` (release.py:381-390). The same name covers a missing `select.iso` or `durable-boot.sh` (release.py:402-403) or a missing boot image (release.py:406-407).
- without `--kernel`: `select_cache_mismatch: …` when `select.toml` is malformed (release.py:391-396), names another release, step or selection (release.py:397-399), or when `select.iso` or `durable-boot.sh` differs from the digest it records (release.py:404-405). The tool never builds a replacement: use the `--kernel` form.
- without `--kernel`, with `--release` naming another release: `give --release <the directory of <A>> or no --release (…)` (release.py:701-703)
- with `--kernel`: `give --release <the directory of <A>> (its importer writes the selection)` (release.py:710-711), and every refusal of section 1 for A and `KA` (release.py:712)
- `importer boot 1 (step 4): QEMU status <n>` from either boot (release.py:303-304), or `importer boot 1 (step 4): durable-boot.sh exited <n>: …` when the boot script itself fails (release.py:297-301); `the selection did not take` (release.py:657-658)

## 8. Back up and restore the halted image

### Back up

The machine must be halted by an orderly `shutdown`; the file server's
final commit is the quiescence point. A live backup is not supported
(RELEASE.md:203-205). The tool refuses an image that any process holds
open, before it reads the disk and again right after the copy, before
the copy is checked (release.py:789-827, 838, 850): a running `boot-operator.sh`, an `accept` or importer
boot, another `release.py`. It sees only processes whose `/proc/<pid>/fd`
this user can read (release.py:789-792, 801-804); run it as the user that
runs QEMU.

```sh
python3 -I scripts/release.py backup --target OUT BACKUP
```

What it does: copies the image, requires the copy's digest and its tree
(by the host reader) to equal the disk's, writes `BACKUP/backup.toml`, and
copies the boot image of each release on the disk (release.py:830-878;
RELEASE.md:203-208). No kernel is needed (release.py:1255).

Success prints `BACKUP OK dir=<BACKUP> selected=<id> format=<n> seq=<n> files=<n>`
(release.py:880). Record: `BACKUP/backup.toml` with the time, `kind =
"halted"`, the source image, the target, the image digest, the format, the
filesystem id and commit sequence, the file count and file-list digest,
the selected release and trees, and the host key fingerprint
(release.py:865-873). `BACKUP/absd-operator.img` is mode 0600
(release.py:846-849); `BACKUP/releases/<id>/absd-operator.iso` per tree
(release.py:874-878). Ledger: `backup <selected> dir=<BACKUP>`
(release.py:879). No file is written under `OUT/receipts/`.

Refusals: `<BACKUP> is not empty` (release.py:834-835);
`<OUT>/absd-operator.img: no disk image` (release.py:836-837);
`image_in_use: <OUT>/absd-operator.img is open in pid <n> (<name>); halt the machine (shutdown) before a backup`
(release.py:820-827, 838), and the same right after the copy
(release.py:850); `image_in_use: cannot tell whether … (no
/proc)` where there is no `/proc` (release.py:793-795); the disk's own
refusals (release.py:210-242); `the copy differs from the disk`
(release.py:851-852); `the copy's tree differs from the disk's`
(release.py:853-855). Every refusal after the copy exists deletes the
copy, which carries the host key seed, and the backup directory if the
command created it (release.py:844-861).

### Verify a backup

```sh
python3 -I scripts/release.py verify-backup BACKUP
```

Success prints `BACKUP VALID selected=<id> format=<n> files=<n>`
(release.py:1225-1227). It runs the same checks as `restore` (below) and
writes nothing.

### Restore

```sh
python3 -I scripts/release.py restore --target OUT BACKUP --replace
```

`--replace` is needed when `OUT/absd-operator.img` exists
(release.py:961-962). What it does: validates the backup, copies the image
to `absd-operator.img.restoring`, checks its digest, renames it over the
disk, and puts the selected release's boot image in place
(release.py:926-989; RELEASE.md:210-213). No kernel is needed unless
`--clone` (release.py:929-930, 933-955, 988-989).

Success prints `RESTORE COPIED release=<id> format=<n> seq=<n>`
(release.py:986-987). Receipt: `receipts/restore-<id>-<time>.toml` with the
backup, the release, `clone`, the image digest and the format
(release.py:982-984). Ledger: `restored <id> from=<BACKUP>`
(release.py:985). `TARGET` is written only if absent (release.py:980-981).

The byte copy is a precondition, not the evidence: boot and verify as in
section 3, and read back something you know the image holds
(RELEASE.md:213-216).

Refusals (each before the disk is touched, and with no file left in
`OUT`; release.py:892-923, 957-974):

- `<BACKUP>: no backup.toml` (release.py:895-896); `<BACKUP>: no image` (release.py:899-900)
- `<image>: <n> bytes, not an operator image (67108864)` (release.py:901-902)
- `the backup image's digest is not the one backup.toml records` (release.py:903-904)
- `the backup image is format <n>, backup.toml says <m>` (release.py:906-908)
- `the backup image is filesystem format <n>; this release reads 2` (release.py:909-910)
- `the host reader refuses the backup image: …` (release.py:911-914)
- `the backup image's filesystem identity or sequence is not the one backup.toml records` (release.py:915-918)
- `the backup selects <x>, backup.toml says <y>` (release.py:919-921); the selected release's record missing or malformed (release.py:922)
- `no boot image for the selected release <id> in the backup or the target` (release.py:957-959)
- `<OUT>/absd-operator.img exists; --replace to restore over it` (release.py:961-962)
- `the restored copy differs from the backup`; the `.restoring` copy is
  deleted (release.py:972-974)

### Restore as a second machine (clone)

```sh
python3 -I scripts/release.py restore --target OUT2 BACKUP --clone --release A --kernel KA --key KEY --target-identity lab-2
```

`OUT2` is an operator directory of its own, and `--target-identity`
names the second machine; the backup's own target identity is refused
(release.py:940-949). Before the disk is touched the clone builds the
selected release's selection image with `KA`, as install does
(release.py:963-968). After the copy it boots the release's regenerate
image and requires the file server's `FSD HOST KEY GENERATED` on the
serial and a served host key other than the backup's (sshd itself reads
the seed and reports `SSH HOST KEY LOADED`); then it halts in order and
requires the seed on the disk to have changed (release.py:992-1025;
RELEASE.md:274, 281-283).
Only then does it move the selection cache into `OUT2/releases/<id>/`
(release.py:1026). It prints `CLONE OK release=<id> host_key=<fingerprint>
target=<identity> select_cache=present`, followed by
`select_cache_absent=<ids>` when the disk holds other releases
(release.py:1040-1041). Receipt: `receipts/clone-<id>-<time>.toml` with
the target and the source target, both host key fingerprints,
`[select_cache]` and `[select_cache_absent]` (release.py:1030-1038).
Ledger: `cloned <id> host_key=<fingerprint> receipt=…` (release.py:1039).

A backup carries no selection image. The clone therefore has one for its
selected release only. A rollback to any other release on the cloned disk
needs `--release` and `--kernel`, and the receipt names those releases.
The clone's ledger starts with `restored` and `cloned` and records no
`accepted` line, so `rollback` refuses `nothing to roll back to` until a
release has been accepted on this machine (section 4).

Refusals before the disk is touched, with `OUT2` unchanged:

- `--clone needs --release <directory of the selected release>, --kernel and --key` (release.py:929-930)
- `--release is <x>, the restored image selects <y>` (release.py:936-938)
- every refusal of section 1 for that release and `KA`, the kernel at
  another commit among them (release.py:939)
- `target identity is '<x>', not '<y>'` when `OUT2` already has another
  `TARGET` (release.py:944-945)
- `clone_identity_unchanged: the backup is of target '<x>'; a clone needs
  another …` when no identity is given, or the identity given or found in
  `OUT2` is the backup's own (release.py:946-949)
- `backup_identity_missing: backup.toml has no [identity]
  host_key_fingerprint …` (release.py:950-954): the clone compares the
  new host key with the source's
- `<KA>: no scripts/durable-boot.sh to keep with the selection image`
  (release.py:968, 348-349)

These come first because the restore has already replaced the image by
the time the regenerate boot runs (release.py:975, 988-989). Refusals
after that point leave `OUT2` holding the restored image, its `TARGET`,
the restore receipt and a `restored` ledger line (release.py:970-986).
What host key that image holds is not known: a refusal before the
orderly halt (readiness, the two key checks, shutdown, halt) can come
after the regenerate boot has written a new seed, and the tool then
stops QEMU, killing it if it still runs (release.py:1021, 502-510); only `clone_seed_unchanged` follows an orderly halt, and there
the seed is still the source machine's. Treat the image as a cloned
identity (RELEASE.md:274): do not boot it on a network the source
machine is on. Restore again with `--clone --replace` (without
`--replace` the restore refuses `… exists; --replace to restore over
it`, release.py:961-962; `OUT2`'s `TARGET` now names the second machine,
so `--target-identity` may be left out or must match it), or discard
`OUT2`. No selection cache and no clone receipt are written in that case:

- `clone_key_not_generated: the regenerate boot's serial has no FSD HOST KEY GENERATED` (release.py:1009-1011)
- `clone_key_unchanged: the regenerate boot serves the backup's host key <fingerprint>` (release.py:1012-1014)
- `shutdown after regeneration: rc=…` (release.py:1015-1017)
- `the clone boot did not halt in order` (release.py:1018-1019)
- `clone_seed_unchanged: the host key seed did not change on the disk` (release.py:1022-1025)
- the readiness refusals of section 4 (release.py:1006, 465-480)

The clone's served readiness under its new key is release-matrix case 15.
It failed once on the `release.py` defect fixed at `af76b231` and passed on
`31c21a14` (docs/l0-deploy-20261012/RECORD.md, "Guest results").

## 9. What the console says when a boot fails

The machine reports a refused boot on its console only (`OUT/console.log`
for `boot-operator.sh`, `OUT/console-<name>.log` for the tool's boots,
release.py:436). No session can read these lines after the fact.

| Console line | Meaning | Boot status | Operator action |
|---|---|---|---|
| `RELEASE REFUSED reason=<reason>` (ten reasons) | the record on the disk does not match the booted image (RELEASE.md:79-87) | 7, halted, disk untouched (RELEASE.md:119) | boot the selected release's own image (`OUT/releases/<id>/absd-operator.iso`), or select or roll back |
| `FSD FAILED mount: UnsupportedFormat` | the disk's filesystem format is not the release's (RELEASE.md:74-78, 121) | 7, disk untouched | migrate (section 10) or restore |
| `ABI REFUSED kernel=<n> required=<m>` | kernel ABI generation differs (RELEASE.md:92-96) | program status 103; the boot fails pre-ready | the image and tree are not a pair; rebuild or roll back |
| `FSD PROTOCOL REFUSED` | file-server protocol differs (RELEASE.md:97-103) | program status 104; pre-ready | as above |
| `init: FAILED at no block device` | no disk (RELEASE.md:120) | halted | attach the disk |
| `SERVED RECOVERY REFUSED generation_not_ready` | a service failed before readiness (RELEASE.md:77-78) | 7, no reset | read the lines above it |

A pre-ready failure never resets: there is no reboot loop, and the
console evidence survives (RELEASE.md:127-130).

**After readiness**, init's recovery budget applies: at most three
whole-machine resets after post-ready failures; the fourth stops the
machine with `SERVED RECOVERY ESCALATED reason=recovery_budget_exhausted …
code=20` (kernel `docs/service-lifecycle-20261008/RECOVERY-BUDGET.md:3-9,
127-133`). The streak lives under `/var`, which is site state
(RELEASE.md:23): `select`, `rollback` and `restore` do not reset it
(release.py:644-645 writes only `/absd/selected`; a restore copies the
whole image). A boot after a budget stop starts at streak 4 and keeps the
rule; only an orderly `shutdown` or `reboot` clears the streak
(RECOVERY-BUDGET.md:141-148). `accept` ends in an orderly shutdown
(release.py:744-751), so accepting the rolled-back release also clears it.

## 10. Migrate the filesystem format

Only when a release reads a format the disk is not in (`stage` refuses
with `migrate first`, release.py:608-611):

```sh
python3 -I scripts/release.py migrate --release B --kernel KB --target OUT
```

It reads the old disk, writes a new image with B's importer containing
B's tree and the site state, verifies every file, renames the old image to
`absd-operator.img.pre-migration-format<n>-<time>` and the new one into
place, keeps B's selection cache as stage does, and selects B
(release.py:1044-1080; RELEASE.md:193-199). It prints
`MIGRATED to format <m> release=<B> site_files=<n> retained=<name>`
(release.py:1089). Receipt: `receipts/migrate-<B>-<time>.toml`, whose
`rollback` field says the way back: restore the retained image and boot
the previous release's image, and whose `[select_cache]` table records B's
selection cache (release.py:1081-1086; RELEASE.md:178-182).
Ledger: `migrated <B>` then `selected <B> by migration`
(release.py:1087-1088). Refusals: `the disk is already format <n>; use
stage/select` (release.py:1052-1053); `the migrated image differs at <path>`
(release.py:1069-1071); `the migrated image is not the release's format`
(release.py:1072-1073).

## 11. Limits

- **Two trees.** With two trees on the disk, staging a third refuses
  (release.py:617-619) until a retired one is removed (section 5, "Make
  room"). Removal needs an importer with step 5: a release built before
  it cannot remove anything. A guest run of A → B → C is release-matrix
  case 14, which passed (docs/l0-deploy-20261012/receipts/run-14.log).
- **Select compiles; rollback need not.** `select`, and `rollback` with
  `--kernel`, boot the release's importer through `make durable-iso` in
  the kernel copy (release.py:641-646, 314-318;
  scripts/operator_image.py:108-115). `rollback` without `--kernel` boots
  the cached selection image and needs neither (section 7). The cache is
  in `OUT` only: `backup` copies each release's boot image but not its
  selection cache (release.py:874-878). After a plain restore into a
  fresh `OUT`, a rollback therefore refuses `select_cache_missing` and needs
  the `--kernel` form. A `--clone` builds the cache for its selected
  release only (section 8).
- **The tool checks the halt for three operations only.** `backup`,
  `rollback` (either form) and `remove` refuse `image_in_use` when any
  process this user can see holds the image open (release.py:789-827).
  `install`, `stage`, `select`, `accept`, `migrate` and `restore
  --replace` trust the operator to have halted the machine.
- **The cached rollback attaches the disk as `ata` or `nvme` only.** With
  `ABSD_BLOCK_ATTACH=laptop` it refuses `select_cache_laptop_unsupported`;
  use the `--kernel` form (release.py:383-386).
- **Status.** `python3 -I scripts/release.py status --target OUT` prints
  `target=… image=… format=… selected=… trees=… last_accepted=… files=…`
  and the last ten ledger lines (release.py:1216-1222).
- **Credential custody.** The disk and every backup of it carry the host
  key seed `/ssh/host_ed25519_seed` (release.py:862, 871;
  man/afterboot.8:114-117); anyone holding either can impersonate the
  machine. The tool sets mode 0600 on the image and the backup image
  (release.py:575, 849); the backup directory, `backup.toml` and
  `receipts/` take the host's umask. A restored copy that boots on a
  second machine without `--clone` is a cloned identity (RELEASE.md:274).
- **Durability.** Logical durability under QEMU only; physical power-loss
  durability is not claimed (RELEASE.md:253-268).
- **Signing.** Nothing signs a release; integrity is by digest only
  (RELEASE.md:318-324).

## 12. What this runbook does not cover

- **EXACT_HARDWARE_QUALIFICATION.** No physical machine, NIC, writable
  NVMe install, rollback after power loss, or restore onto a named machine
  class is qualified (RELEASE.md:9-13, 264-268). Nothing here is a
  procedure for a physical machine.
- **On-box configuration write.** `/etc` is read-only to sessions;
  configuration changes are host-side (`scripts/operator_image.py
  reconfigure`, scripts/operator_image.py:243; man/afterboot.8:377-380).
- **Key rotation.** There is no on-box host-key or authorized-key
  rotation; a new host key comes only from the regenerate image on the
  host (`restore --clone`, release.py:992-1041; RELEASE.md:274).
- **The previous boot's exit cause.** Init's refusal and recovery lines are
  on the console only (section 9); nothing reports them over SSH.
- **Automatic fallback.** Nothing boots the previous release by itself:
  a refused or failed boot halts, and selecting the previous release again
  is the operator's `rollback` (RELEASE.md:66-68, 124-130, 171-176). There
  is no boot counting, watchdog, or on-box update agent.
