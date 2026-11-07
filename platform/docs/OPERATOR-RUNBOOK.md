# Operator runbook: paired releases on one machine

This is the procedure for the host tool `scripts/release.py`. The contract
it carries out is [RELEASE.md](RELEASE.md); where the two seem to differ,
RELEASE.md and the tool's code decide, and this page is wrong. Older numeric citations below describe their original source revision and may
have moved. Use the named command and current implementation when checking a
successor: `release.py` is `scripts/release.py`, and `RELEASE.md` is
`docs/RELEASE.md`. Numeric citations are not current-source qualification evidence.

The release manifest declares local QEMU with TCG and the primary IDE master.
Actual qualification is specific to the release and its execution receipts. KVM with IDE has the known #74 deadline limitation; its results do
not transfer from the TCG qualification. KVM with one NVMe namespace needs
separate qualification before it is claimed. No physical machine is claimed. Everything here runs on the build
host against a halted disk image, operator-driven. Nothing on the machine
updates, rolls back, or falls back by itself.

The local-enabled operator image also provides [managed local login and read-only kernel maintenance](LOCAL-CONSOLE.md), including enrollment and recovery without Ethernet.

## 0. Conventions

Names used in the commands:

| Name | What it is |
|---|---|
| `A`, `B` | release directories made by `release.py build` (release.py:5-9, 515-553); `A` is installed first, `B` is the update |
| `KA`, `KB` | disposable kernel checkouts at the commit each release's manifest names (section 1) |
| `OUT` | the operator directory: one machine (release.py:11-16) |
| `KEY` | the operator's private key; its public half is in the release's site defaults or was given at build (release.py:538-539, 154-156) |
| `BACKUP` | an empty or absent directory for a halted backup |

Commands run from the top of the platform checkout. Ordinary success prints
its result line on standard output. An ordinary refusal prints
`release: refused: <reason>` on standard error and exits 1
(release.py:1268-1272); the reasons are quoted below as the tool prints
them. Stage and reconfigure failures instead print a lowercase state prefix
(`release: indeterminate: …`, for example), followed by a state/phase/receipt
line. Their failure receipt can be missing after an output or storage fault;
see the state tables in RELEASE.md and section 13. A command missing `--release` or `--kernel` where it needs one
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
  `restore`, `migrate`, `remove`, or `reconfigure`. The tool itself checks that no
  process holds the image open for `backup`, `rollback`, `remove`,
  `reconfigure`, `discard-import-temp`, and legacy replacement restore. Strict recovery restore separately checks
  holders of the recovery point's own image, not the absent fresh target.
  For the other operations the halt is the operator's to
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
  RELEASE.md:163-164). Make room for a third by removing a retired one
  (section 5, "Make room").

## 1. Prepare a kernel copy for a release

Importer writes that construct an ISO need `--kernel`. For a standalone-built
release, use a kernel checkout at the exact commit
the release's manifest names (release.py:159-178, 181-193; RELEASE.md:126-129).
The canonical kernel checkout is never accepted (release.py:185-186);
make a disposable one, the way `scripts/inputs.sh` does
(scripts/inputs.sh:224-232):

```sh
commit=$(python3 -I -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["source"]["kernel_commit"])' A/release-manifest.toml)
git clone --quiet --shared --no-checkout /path/to/kernel KA
git -C KA checkout --quiet --detach "$commit"
```

For a release with `source.kernel_snapshot`, do not try to check out the
upstream component commit from the public repository: its HEAD is distinct.
Follow [Curated public source identity](RELEASE.md#curated-public-source-identity):
keep the source checkout protected and use the `kernel/` directory of a second
complete, clean matching public clone for construction.

For a standalone-built release, `check_kernel` admits a matching commit
identity, including a `.absd-identity` marker in a delivered snapshot. That
comparison alone does not verify the snapshot bytes. The established
`scripts/inputs.sh` delivery step supplies the manifest-verified snapshot
correspondence described in RELEASE.md; retain its receipt. A copied marker
cannot satisfy a public-snapshot mapping. No fabricated Git history is needed.

Refusals (each before any write):

- `kernel public source mapping refused: …`, `kernel public source snapshot differs from release mapping`, or `kernel public source snapshot lacks corresponding release mapping`: retain the inputs and use the matching committed public source and mapping.
- `manifest_mismatch …` or `manifest_unverifiable …`: a release-directory artifact or tree cannot be verified against its release manifest. These are release-artifact checks, not kernel-snapshot correspondence checks.
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

What it does: writes a blank 128 MiB image, installs A's tree, the site
defaults (`/etc`, `/ssh/authorized_keys`), `/absd/selected`, and fresh writable
guard/resume files, one
importer boot per plan step, reads every file back with the host reader,
checks the disk's format against A's record, and copies A's boot image
into place (release.py:556-585; RELEASE.md:201-207). Before it touches the
disk it builds A's selection cache in a temporary directory under `OUT`
and moves it to `OUT/releases/<A>/` once the install is verified
(release.py:568-583, 344-375).
For a larger fresh image, add `--disk-profile 2g` to the install command:
this creates a 2 GiB device with a 1 GiB filesystem region. The default
`128m` profile has a 64 MiB filesystem region. Metadata and installed files
consume part of that space. This does not resize an existing image.

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

### SMP operator image (QEMU)

The candidate operator profiles accept exactly 2, 4 or 6 CPUs. Use the same
setting at build and boot, on the host running QEMU; this example selects 4:

```sh
ABSD_OPERATOR_CPUS=4 ABSD_KERNEL_RUN=KERNEL_COPY scripts/build-operator-image.sh --authorized-keys KEYS OUT
ABSD_OPERATOR_CPUS=4 scripts/boot-operator.sh OUT 2222
```

The kernel checkout must support `smp-operator` and the selected count. Only
the final served ISO gets the feature and exact `smp-operator=N` boot word;
importer boots remain single-CPU. The launcher reads the actual ISO, requires
that count in its canonical GRUB command, and supplies the pinned topology
`-smp N,sockets=1,cores=N,threads=1`, including for N=2. It refuses unsupported,
padded or compound count settings, duplicate/mixed boot words, cross-count
ISO mismatches and caller-supplied QEMU `-smp`/`--smp` forms before launch
bookkeeping. The kernel requires a matching validated MADT and refuses a
topology mismatch.

Unset or `ABSD_OPERATOR_CPUS=1` retains the existing single-CPU profile with
no SMP boot word or added QEMU CPU option. Roll back by building/selecting a
matching UP ISO and unsetting the variable (or setting 1), or by selecting
the preserved accepted two-CPU pair with setting 2. The release-tool recipe
remains UP; this setting does not opt its releases into SMP.

Host binding tests establish count propagation and refusal, not runtime
qualification. Four and six are candidate profiles until each exact
kernel/platform pair has its own operator runtime evidence and independent
acceptance; a two-CPU result does not qualify four or six. Admit four first,
then six with four preserved. These profiles make no physical hardware or
six-core scaling claim. CPU0 dispatch independence, physical RT timing and
FADT+SMP remain NOT ASSESSED.

Local console login is enrolled by default during fresh image/release construction.
Only the SHA-256 descriptor is installed at `/ssh/local-login`. The builder
keeps the owner-only token at `OUT.local-console-token` and the reusable
nonsecret descriptor at `OUT.local-console-token.verifier`, both outside `OUT`.
Transfer the token separately through the operator's existing private access
path; never place it in an image, release directory, log or release archive.
`--local-token-file FILE` chooses another external owner-only token path;
`--local-login-verifier FILE` reuses an existing descriptor for a rebuild and
creates no new token. Existing enrollment paths refuse rather than overwrite.
The final served ISO enables local console; importer ISOs explicitly disable it.
See `man local-console` for login, session switching and kernel maintenance.

## 3. Boot and verify readiness over SSH

After readiness, use `logs --health`, `logs --list-boots` and
`logs -u sshd -n 20` through the authenticated session to inspect retained
service diagnostics. `logs --volatile` and `dmesg` read the independent bounded
kernel ring when persistent history is unavailable. Counters cover the boot/PID collector generation, reset on restart, and do not
claim a durable aggregate. Pending records retry in order in bounded memory;
unacknowledged eviction is counted conservatively. A request timeout means
completion is unconfirmed. `logs --health` labels persistence at the sample
and collector liveness unknown. A retained health record
is a sample, so compare its tick/sequence and the current boot identity rather
than treating it as proof that a collector is alive. Init independently
supervises logd and reports refusal, backoff and exhausted restart budget in
the ring. Resource refusals back off without consuming a crash restart. An
uncertain OPEN/CLOSE or logger handshake, or exhausted logger handles, ends the
collector with transient status 75; init reaps that child before retrying the
attachment. The new handshake retires prior-generation handles. Four successful
replacements following actual crashes are permitted per boot; transient exits
neither add to nor refund that count. Ordinary RPCs allow 100 ticks; COMMIT and
the attachment handshake allow 1000 ticks within the unchanged 4000-tick pass
and 1000-tick shutdown deadlines. Shutdown immediately retries pending backoff
once and stops on no progress. The logger's pre-main VERSION request is also
bounded to 1000 ticks; only its transport timeout requests transient reattachment.
Unproductive attempts retry after 1, 2, 4, 8, 16, 30, then 60 seconds, with 60
seconds as the continuing cap. No storage-outage retry limit permanently disables
logging. Init resets this count only after the exact child reports a first
new-record sync and a later new-record sync at least 60 seconds afterward in
the same generation. READY, heartbeats and lifetime alone do not reset it.
The collector emits at most one collection notice per minute after the first.
After initial transitions, retry summaries appear every 60th unproductive
attempt; genuine fault outcomes and bounded child output remain visible.
`logs --health` leads with current persistence, errors and retry count unknown.
Every file field is labeled `sample_`; a read-only current-boot kernel-ring scan
may add the latest retained supervisor count with its boot, tick and sequence.
That observation can be overwritten or unavailable and is not an authoritative
live count. Later exhaustion, quarantine and unconfirmed-child observations
replace older retry/collection observations and report unavailable counts as
unknown. The logs command defers FSD negotiation until filesystem use;
`--volatile` sends no FSD request. `--health` tries a checked 1000-tick VERSION
probe before reading its optional retained sample. This bounds VERSION only;
subsequent sample I/O uses ordinary filesystem waits and can still wait if the
server stalls after answering VERSION. Use `--volatile` for no FSD request.
A protocol refusal reports
that sample unavailable and still shows unknown current health and independent
kernel supervisor observations. Status 0 for this partial diagnostic report
is not a health or persistence acceptance. A real retained-sample file I/O
error remains visible and returns status 1 after the diagnostics. Normal
retained queries validate the protocol before any filesystem request and
refuse with status 104 on failed negotiation. See [logs(1)](../man/logs.1) for exact retention, escaping, rate
suppression and flush limitations; abrupt power loss can lose unflushed records.


`logs -b -1` and explicit boot identities require a retained identity; an
unavailable selection fails instead of silently selecting the current boot.
A known selected boot with no matching records succeeds with empty output.
`logs --health -b BOOT` also requires the acquired health sample to name that
retained boot. Current-boot supervisor observations cannot fill in a historical
boot's missing observation. Health displays retain the entire recorded error
under `sample_error`, including optional-value wrappers; exact `None` becomes
`none`, and the collector PID uses a number or `unknown` when recorded that way.
A refused optional health acquisition reports its reason with current state
unknown and still attempts the independent ring observation. Only a successfully
acquired empty sample is described as empty. Actual health-file read errors fail,
even if the display pipe also closes; refusal and read failure cannot satisfy
an explicit boot selection. Closing a display pipe otherwise ends quietly, while
input, notice and explicit file-export failures remain visible.


```sh
scripts/boot-operator.sh OUT 2222
```

QEMU runs in the foreground with `OUT/absd-operator.iso` (the selected
release's image) and `OUT/absd-operator.img`, the console in
`OUT/console.log` (scripts/boot-operator.sh:20-31). It prints
`boot-operator: ssh -p 2222 operator@127.0.0.1 reaches <guest>:<port>; …`
(scripts/boot-operator.sh:25).

SSH readiness means the console shows `RELEASE OK release=<id>` and the listener
record, and the pre-ready window is over (RELEASE.md:279). From a second
terminal:

```sh
grep -a 'RELEASE OK release=' OUT/console.log
grep -a '^sshd: host key' OUT/console.log
```

The first line names the selected release (RELEASE.md:96-101). The second
gives the host key's fingerprint and public key in plain text
(man/afterboot.8:81-91); put the public key in a known_hosts file and
connect with strict checking (man/afterboot.8:98-103):

```sh
echo "[127.0.0.1]:2222 ssh-ed25519 AAAA…" > known_hosts
ssh -p 2222 -i KEY -o UserKnownHostsFile=known_hosts -o StrictHostKeyChecking=yes operator@127.0.0.1 release
```

`release` prints `release=<id> kernel_abi=1 fsd_protocol=2 fs_format=2
app_abi=1`: the file server's own answer for the id, protocol and format
(src/bin/release.rs:1-9, 21-29; RELEASE.md:57-68); the four numbers are
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
served boot without `accept` leave the release a candidate (RELEASE.md:284-286).
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
This is the `ACCEPTED` state (RELEASE.md:280).

Success prints `RELEASE ACCEPTED id=<id> receipt=<name>` (release.py:765).
Receipt: `receipts/accept-<id>-<time>.toml` with the host key fingerprint,
the halt status, the identity fields and each check (release.py:757-763).
Ledger: `accepted <id>` (release.py:764); this line is what `rollback`
reads (release.py:685). The console of this boot is
`OUT/console-accept-<id>.log` (release.py:436, 727).

Refusals (each leaves the release a candidate, state `FAILED`,
RELEASE.md:281):

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
`OUT/releases/<B>/` (release.py:603-630; RELEASE.md:209-216). This is `STAGED`
(RELEASE.md:276).

Success prints `RELEASE STAGED id=<B> selected=<A> trees=<A>,<B>`
(release.py:638). Receipt: `receipts/stage-<B>-<time>.toml` with
`selected_before`, `selected_after`, `state = "STAGED"` and the
`[select_cache]` table (release.py:631-636). Ledger: `staged <B>` (release.py:637).

Staging outcomes are `REFUSED` before its importer call, or `INDETERMINATE`
once that call began or a later step failed. The latter can contain committed
files; it is not rollback. Keep the state/phase line and
`receipts/stage-failed-<attempt>-<time>.toml`, halt and inspect with `status`
and the host reader before recovery. `receipt unavailable` or abrupt process
loss means the terminal receipt may be absent. A failed readback after import
is an indeterminate operation, not proof that A remains bootable. See
[staging effect semantics](RELEASE.md#5-install-update-acceptance-rollback).

Refusals (before any write unless noted):

- `the disk is format <n>; release <B> reads format <m>: migrate first (release.py migrate)` (release.py:608-611)
- `release <B> is already on the disk; remove it first (release.py remove)` (release.py:615-616)
- `the disk holds 2 releases (<x>, <y>); at most 2: remove one that is neither selected (<s>) nor the last accepted` (release.py:617-619)
- `importer boot …` (release.py:483-490): selection is expected unchanged but must be confirmed with `status`; the failed importer can leave `/var/recovery.guard` dirty (WRITABLE-ENTRY.md:225-233), so A's boot refuses pre-ready (`RECOVERY WRITABLE REFUSED reason=storage_fence …`) and `stage`, `select` and `rollback` refuse `writable guard: unclean image; offline reconstruction required`; keep the receipt and failed image, and restore a backup into a fresh operator directory (section 8)
- `the host reader sees different bytes at <path>` (release.py:618), after a partial write: the outcome is INDETERMINATE; inspect the actual halted state rather than assuming A still boots, and a later `select B` refuses (RELEASE.md:153)
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
`OUT/REMOVING` remains. `stage`, `select`, `migrate`, `rollback`,
`reconfigure` and `discard-import-temp` then
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
removal only if the writable guard permits it. On platform14+, an interrupted
import leaves `/var/recovery.guard` dirty: directory reconciliation never
clears it, and retry refuses before writing. Keep the failed receipt and use
separately authorized offline reconstruction onto a different backing file;
do not reseed or edit the old marker. A malformed `OUT/REMOVING` refuses `removal_unreconciled: … is
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
(release.py:641-666; RELEASE.md:215-216, 375). This is `BOOT_SELECTED`
(RELEASE.md:277).

Success prints `RELEASE SELECTED id=<B> from=<A>: boot <OUT>/absd-operator.iso`
(release.py:666). Receipt: `receipts/selected-<B>-<time>.toml` with
`selected_before`, `state = "BOOT_SELECTED"` and `source = "kernel"`
(release.py:662-664, 646). Ledger: `selected <B> from=<A>` (release.py:665).

Refusals: `release <B> has no tree on the disk` (release.py:651-652); a
malformed or missing record on the disk, by the file server's reason name
(release.py:653, 253-258); `the selection did not take` (release.py:657-658);
every refusal of section 1.

Then boot and verify B as in section 3 (`BOOTING`, `SERVED_READY`,
RELEASE.md:278-279), halt it, and accept it as in section 4. Until B is
accepted, A remains the known-good release (RELEASE.md:284-286).

## 7. Roll back to the previous pair

No build host is needed: the rollback boots the selection image cached
when the previous release was installed or staged.

```sh
python3 -I scripts/release.py rollback --target OUT
```

What it does: finds the ledger's last `accepted` release other than the
selected one, requires its tree on the disk and its format equal to the
disk's (release.py:677-697; RELEASE.md:288-293). It then checks that
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
State created under B stays on the disk (RELEASE.md:291-293).

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
holds when A's image boots to `SERVED_READY` (RELEASE.md:282).

Refusals (each before any write):

- `no accepted release other than the selected one in the ledger: nothing to roll back to` (release.py:685-688)
- `rollback target <A> has no tree on the disk (removed, or the disk was migrated: restore the pre-migration image instead)` (release.py:690-692)
- `rollback target <A> reads format <n>, the disk is format <m>: a rollback across a migration is a restore of the pre-migration image` (release.py:693-697; RELEASE.md:295-299)
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
(RELEASE.md:320-322). The tool refuses an image that any process holds
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
RELEASE.md:320-325). No kernel is needed (release.py:1255).

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
(release.py:926-989; RELEASE.md:327-330). No kernel is needed unless
`--clone` (release.py:929-930, 933-955, 988-989).

Success prints `RESTORE COPIED release=<id> format=<n> seq=<n>`
(release.py:986-987). Receipt: `receipts/restore-<id>-<time>.toml` with the
backup, the release, `clone`, the image digest and the format
(release.py:982-984). Ledger: `restored <id> from=<BACKUP>`
(release.py:985). `TARGET` is written only if absent (release.py:980-981).

The byte copy is a precondition, not the evidence: boot and verify as in
section 3, and read back something you know the image holds
(RELEASE.md:330-333).

Refusals below precede replacement of the image. Existing target metadata and
lock files can remain; do not infer an absent target directory from refusal.

- `image_in_use … before a legacy replacement restore`, `recovery_pending`, or
  `restore_target_not_clean`: retain the failed target and restore into a fresh
  operator directory. `--replace` is limited to clean, ended targets
  (`recovery_point.require_clean_history`, including `require_ended_history`).
- `recovery_point_strict_required`: use the pinned strict-point procedure in
  [P2-REPLACEMENT-RESTORE.md](P2-REPLACEMENT-RESTORE.md), not legacy restore.

- `<BACKUP>: no backup.toml` (release.py:895-896); `<BACKUP>: no image` (release.py:899-900)
- `<image> is <n> bytes, not a whole number of sectors` (a truncated or padded copy that is not whole sectors; any other truncation fails the digest below)
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
RELEASE.md:391, 398-400).
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
identity (RELEASE.md:391): do not boot it on a network the source
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
`31c21a14` (docs/l0-deploy-20261012/RECORD.md, "Guest results"). This is
a historical result, not a qualification of the current release pair.

## 9. What the console says when a boot fails

Preserve the console for refused boots (`OUT/console.log` for
`boot-operator.sh`, `OUT/console-<name>.log` for the tool's boots,
release.py:436). Available service records may also be retained by `logs`,
but a failure before collection or persistence can leave console-only
evidence. Do not infer a complete past failure history from the journal.

| Console line | Meaning | Boot status | Operator action |
|---|---|---|---|
| `RELEASE REFUSED reason=<reason>` (ten reasons) | the record on the disk does not match the booted image (RELEASE.md:96-105) | 7, halted, disk left dirty: the guard is armed before the check (RELEASE.md:148) | the selected release's own image now refuses too (`RECOVERY WRITABLE REFUSED reason=storage_fence previous=not_ready fence=none`), as do `select` and `rollback` (`writable guard: unclean image; offline reconstruction required`): keep the console and failed image, and restore a backup taken before this boot into a fresh operator directory (section 8). Boot only `OUT/releases/<id>/absd-operator.iso` for the selected `<id>` |
| `FSD FAILED read-only mount: UnsupportedFormat` | the disk's filesystem format is not the release's (RELEASE.md:75, 91-95, 150) | 7, disk untouched | migrate (section 10) or restore |
| `ABI REFUSED kernel=<n> required=<m>` | kernel ABI generation differs (RELEASE.md:109-113) | program status 103; the boot fails pre-ready | the image and tree are not a pair; rebuild or roll back |
| `FSD PROTOCOL REFUSED` | file-server protocol differs (RELEASE.md:114-120) | program status 104; pre-ready | as above |
| `init: FAILED at no block device` | no disk (RELEASE.md:149) | halted | attach the disk |
| `SERVED RECOVERY REFUSED generation_not_ready` | a service failed before readiness in the headless profile (RELEASE.md:94-95) | 7, no reset; local-enabled images can hold read-only maintenance instead | read the preceding evidence; see LOCAL-CONSOLE.md |
| `RECOVERY WRITABLE REFUSED reason=storage_fence previous=failed\|not_ready fence=none` | the previous generation stopped uncleanly; the guard is dirty and no authorization record is on the disk (WRITABLE-ENTRY.md) | headless: 7; local-enabled: read-only maintenance; filesystem entry refuses writes | section 9a: back up, `release.py recover`, boot, `--wait-ready` |
| `RECOVERY STATE REFUSED reason=resume_mismatch\|resume_corrupt` | an authorization record is on the disk but names another state, or the slot is corrupt | headless: 7; local-enabled: read-only maintenance; filesystem entry refuses writes | `release.py recover --revoke`, then decide (section 9a) |

A pre-ready failure does not authorize an automatic reset. A local-enabled
image keeps init's read-only kernel maintenance available; a headless image
can stop with the named failure. After readiness, essential-service failure
uses bounded cleanup and the recorded recovery budget may permit a visible
whole-machine reset of the same selected release. An unknown or exhausted
budget, or a refused reset, leaves local-enabled init in maintenance.
Leaving that held state requires an external operator reboot; a dirty writable
image may still require section 9a recovery. This is not in-place service
replacement or automatic selection of a previous release. The dedicated log
collector has its own bounded process-restart policy; see `logs(1)`.

**Platform14+ writable recovery:** every normal and finalizer file-server
entry assesses the private versioned guard before any write or flush. A
power loss, liveness kill, failed update, nonzero server exit or finalizer
failure leaves dirty. A missing guard on an older image also refuses. The
console names `RECOVERY WRITABLE REFUSED` or `RECOVERY STATE REFUSED`; init
refuses served startup: local-enabled init holds read-only maintenance;
a headless image can halt pre-ready with status7. Neither `storage-fence=external` nor
`storage-fence=controller` permits a retry. The one way back to writable
service on the same image is the explicit operator act of section 9a
(platform 15); otherwise preserve the failed receipt and reconstruct offline
onto a separately owned new backing file; no command here repairs the old
marker by itself. [WRITABLE-ENTRY.md](WRITABLE-ENTRY.md) defines the
record, construction, host-update, enrollment and resume contracts.

A cleanly shut-down guard-less format-2 disk can instead use the explicit
`seed-writable-guard.py` copy-only conversion described in that document's
"Clean legacy conversion" section. It requires the matching successful
shutdown console, canonical facts, whole-image hash recorded at that halt,
and explicit `--attest-no-writes-since-halt` (off by default). The operator
must establish that no writer ran afterwards; stale facts alone cannot do
that. A changed image refuses before allocation. It preserves the ledger and all existing
objects, and prepares a different raw file without an old boot ISO or cache.
Activate it with the current guarded release; keep the original halted for
pre-activation rollback. Dirty or incomplete history is not repaired by this
conversion. Do not run the original and successor as the same machine.

The existing three-reset budget remains an upper bound, but no current
backend establishes the fence needed to admit an unclean writable successor:
after a post-ready reset its next boot refuses pre-ready. Successful orderly
`shutdown` or `reboot` records a completed generation and a clean guard, so
the next boot can proceed. A rollback changes the selection, not a dirty
guard or the previous boot's history. These platform14 rules do not change
RC1's frozen image recipe or its historical recovery qualification.

## 9a. Recover a writable machine after an unclean stop (operator act)

Precondition: `OUT/console.log` of the last boot contains
`RECOVERY WRITABLE REFUSED reason=storage_fence previous=failed fence=none`
(or `previous=not_ready`). A headless boot can exit 7. A local-enabled boot
can instead keep init's read-only maintenance running, with the launcher and
QEMU still alive; the refusal is not proof of a halted machine. That
filesystem entry refused writes. Before host recovery, inspect the available
kernel diagnostics and preserve the console, then stop the exact owned
launcher from a second management terminal using its recorded PID (SIGTERM)
or its owning service unit. Let its existing cleanup stop its QEMU and classify
the exit; an externally interrupted launcher can report 130 instead of 7.
With `--console`, QEMU stdio has `signal=off`: Ctrl-C is guest input and does
not stop the launcher. The default file-console mode still lets Ctrl-C stop
the wrapper. Verify both launcher and QEMU have ended and no process holds
this image before backup or authorization. If ownership or termination is
unclear, reconcile it first; do not launch a duplicate or clear the guard.
The act is explicit and recorded; nothing is automatic; it covers
the runbook's own deployment only (a raw image file on a local filesystem,
IDE, local QEMU, one host and user: [WRITABLE-ENTRY.md](WRITABLE-ENTRY.md),
"Operator-authorized resume"). `boot-operator.sh` runs QEMU and blocks until
the machine stops, so use **two terminals** (A for the machine, B for
everything else), or the single-terminal form below. The readiness wait uses
a **provisional** timeout of 180 s under TCG (60 s under KVM); the guest run
of this lane records the observed readiness times and this figure follows
them.

Terminal B, before anything else:

```sh
cd PLATFORM
pgrep -af "OUT/absd-operator.img" || echo "no process names the image"
#   anything listed: reconcile exact ownership; stop this machine's launcher, or let its tool finish
#   process names alone do not prove quiescence; backup/recover also check image holders and locks
python3 -I scripts/release.py backup --target OUT BACKUP
#   the fenced state as the way back (BACKUP: a new directory, dated); take it BEFORE authorizing,
#   so the copy carries no authorization
python3 -I scripts/release.py recover --target OUT --status
#   state=none last=<none or the previous recovery> history=<n>
#   previous=failed boot=<id> ledger_seq=<n> streak=<k> release=<id> files=<n> newest=<paths@mtimes> guard=dirty
#   caveat: synced files exact; a file being overwritten may hold a mix of old and new sectors; growth lost
python3 -I scripts/release.py recover --target OUT --attest-sole-instance --accept-committed-state --reason "host power loss 2026-10-22"
#   RECOVERY AUTHORIZED id=<id> target=<identity> previous=failed fs_seq=<n> hm=<64 hex>
```

After precheck and argument preparation, the launcher execs its Python
supervisor, retaining the recovery lock. The supervisor records HUP, INT or
TERM as interruption intent, stops and reaps its exact QEMU child, then runs
the existing recovery classification under that lock. Interruption chooses
status 130 when latched as the child wait returns, including when QEMU's own
signal handler exits 0. A guest halt (child status 3) keeps wrapper status 0.
Once selected, the outcome survives later cleanup or classification signals.
This attended console/SSH launcher handles HUP even when its caller ignored
HUP (including `nohup`); `nohup` does not detach this supervisor from hangup
cleanup. Further signals and closed terminal output cannot abort cleanup or
release the lock midway.
QEMU gets a two-second TERM grace period, followed by KILL and reap if needed.
A host task stuck in uninterruptible I/O can delay reap; the supervisor keeps
the recovery lock while waiting. SIGKILL of the supervisor, host failure and
power loss cannot run cleanup: reconcile the exact child and image holders
before recovery. Keep `scripts/boot_operator_supervisor.py` and the recovery
modules with `boot-operator.sh`; run the launcher from the platform source tree.


Terminal A (stays busy until the machine halts; it rotates the old console
first, so `OUT/console.log` holds only this launch):

```sh
cd PLATFORM && scripts/boot-operator.sh OUT 2222
#   prints the ssh line, then "boot-operator: launched id=<id> pid=<n> console=OUT/console.log", and blocks
```

Terminal B, after Terminal A printed `launched`:

```sh
ID=<the id from RECOVERY AUTHORIZED>
python3 -I scripts/release.py recover --target OUT --wait-ready --id "$ID" --timeout 180
#   reads the launched record, watches that launch's console for, in order: RECOVERY WRITABLE RESUMED id=$ID,
#   RELEASE OK release=, the listener record, all in the latest ABSD KERNEL BOOT segment; then runs the
#   receive-setup/liveness check the release tool's own boot does before SSH; prints READY and exits 0;
#   exits 7 with the refusal or boot-end line if the boot ended first; exits 124 on timeout
ssh -p 2222 -i KEY -o UserKnownHostsFile=known_hosts -o StrictHostKeyChecking=yes operator@127.0.0.1 health
#   recovery: previous=failed streak=1 ...  (truthful; the streak clears only by a clean shutdown)
#   check your own data now; then keep working, or halt:
ssh -p 2222 -i KEY -o UserKnownHostsFile=known_hosts -o StrictHostKeyChecking=yes operator@127.0.0.1 shutdown
#   Terminal A prints "boot-operator: the machine halted" and exits 0
python3 -I scripts/release.py recover --target OUT --status
#   state=none last=consumed <id> <time> witness=yes
```

If `--wait-ready` exits 7: read the line it printed. `RECOVERY WRITABLE
REFUSED …` or `RECOVERY STATE REFUSED reason=…` → the row for that reason
below; no `ABSD KERNEL BOOT` in the console → `launch_failed` row. If it
exits 124: do not SSH; run `--status`; if the console shows `ABSD KERNEL
BOOT` but none of the three lines, the machine is still booting or hung
before readiness: wait once more with `--timeout 180`; if still nothing,
stop the default file-console launcher from Terminal A (Ctrl-C ends the
wrapper; the script kills its QEMU and classifies the records). With
`--console`, use the second-terminal stop procedure above instead. Verify
quiescence, then run `--status` and act on its row
(`authorized`/`launched` → just boot again).

Single-terminal form. `--wait-ready` reads the `launched` record of this
launch, which the wrapper writes only after QEMU exists; started earlier it
exits 7 (`no launch recorded`). So wait for this launch's `launched` line
(the output file is new for each launch) before `--wait-ready`:

```sh
cd PLATFORM
ID=<the id from RECOVERY AUTHORIZED>
scripts/boot-operator.sh OUT 2222 > OUT/boot-operator.out 2>&1 & BOOT=$!
until grep -q "^boot-operator: launched id=$ID " OUT/boot-operator.out; do
    kill -0 $BOOT 2>/dev/null || break   # the wrapper ended before launching: read OUT/boot-operator.out
    sleep 1
done
grep "^boot-operator: launched id=$ID " OUT/boot-operator.out &&
    python3 -I scripts/release.py recover --target OUT --wait-ready --id "$ID" --timeout 180
```

then the remaining Terminal-B commands above (SSH, `shutdown`), then
`wait $BOOT; echo status=$?`: 0 = halted; 7 = refused before QEMU (precheck,
lock) or a boot refused before readiness (read `OUT/console.log`); 6 =
`launch_failed` (QEMU never booted; the authorization is intact); 1 = the
wrapper's own bookkeeping failed (run `--status`).

Every unclean stop needs the whole sequence again; nothing is automatic.
Never edit the image by hand, never boot a backup copy as the machine, never
start two QEMUs on one image, never `release.py build` into an operator
directory.

Refusals and states, one action each (`--status` always prints the state
and this action):

| Printed (tool, launcher, `--status` state, or guest) | Action |
|---|---|
| `image_in_use: pid N (comm)` | stop that process (QEMU of this machine: `kill N`; an importer or `release.py`: let it finish); retry |
| `image_locked` (`holders: pid N (comm)` or `unknown`) | a QEMU holds the image (possibly another user's, or one whose launcher died): stop the listed pid (or find it); nothing to delete |
| `tool_busy` | another tool or a running `boot-operator.sh` holds the recovery lock: wait or halt the machine |
| `image_not_local` / `image_not_regular` / `image_linked` / `image_size` / state `identity-unreadable` | the image is not one plain local regular file of the layout's size: restore that condition, then `--status` |
| `image_replaced` (during `recover`) | the pathname changed under the tool: nothing was written; `--status`, then `recover` again |
| `slot_write_failed` / `authorization_unverified` | the host write or its flush failed: `--status` reports `intent-only`, finalizes the record, or names the row the landed bytes make; then `recover` or `--revoke` |
| `guard_corrupt` | the guard file is not one writable sector (as the guest would refuse it): restore a backup or extract read-only |
| `target_directory` (from `build`) | you pointed `build` at an operator directory: use a release directory |
| `not_unclean` | guard `fresh`/`clean`: no recovery needed; boot |
| `first_boot_interrupted` | the first start never completed: `release.py install --replace` |
| `previous_not_recoverable` | a dirty guard with an `ended` history (the clean marker never landed): restore a backup or extract read-only |
| `resume_slot_missing` | image built before this release: after a clean halt `release.py stage` this release (adds the slot) or reinstall; a dirty slot-less image can only be extracted read-only (WRITABLE-ENTRY.md) |
| `host_reader_refused: …` / `recovery_state_refused: …` / state `slot-unreadable` | the committed state or ledger is not consistent; nothing repairs: retain OUT and restore a backup into a fresh operator directory (section 8), or extract read-only |
| `attestation_required` | a flag or the reason is missing: give both flags only if both statements are true |
| `launch_failed` (launcher exit 6; `--wait-ready` prints `launch_failed status=…`) | QEMU never booted (missing ISO, bad QEMU path): fix the cause; the authorization is intact; boot again |
| `boot-operator: the exit classification failed` (launcher exit 1) | the wrapper's own bookkeeping failed: run `--status` and act on its row |
| state `intent-only` | nothing was written: run `recover` again (when `recover` would act; otherwise `--status` prints the refusal path, as for state `none` below) |
| state `stale-intent` (shown once in `last=`) | an interrupted act preceded a reinstall or restore: nothing to do; `recover` only if the new file is itself unclean |
| state `authorized-unpublished` | `--status` finalizes it (`finalized id=`) or reports `record_unverified`: then `--revoke`, `recover` |
| state `record-unreceipted` | `--revoke --reason "…"`, then `recover` |
| state `authorized` / `recovery_pending` | boot (Terminal A); or `--revoke` if you changed your mind; every other tool refuses until then |
| state `launched` | a launch happened and the record is still unconsumed: boot again; `--status` shows the launches |
| state `none` with `guard=dirty` and `previous=failed` or `not_ready` | `recover` (the sequence above) |
| state `none` with `guard=fresh` or `guard=clean` | no recovery needed; boot (`--status` prints `action: guard clean: no recovery needed; boot`; `recover` would refuse `not_unclean`) |
| state `none` where `recover` would refuse on the disk | `--status` never prints `recover`; it prints the refusal and its row's action above: `action: previous_not_recoverable: restore a backup or extract read-only` (a dirty guard with an `ended` history), `guard_corrupt: …`, `first_boot_interrupted: release.py install --replace`, `recovery_state_refused: …`, or `guard_missing: the image has no writable guard; it predates the fence` |
| `last=consumed` with state `none` | done; after a clean `shutdown` the next boot is normal; after another unclean stop start over |
| state `replaced` / `recovery_image_replaced` | the backing file was replaced while an authorization was pending or just consumed: `--revoke`, then decide whether to `recover` on the file now in place |
| state `corrupt-slot` / `resume_slot_corrupt` | `--revoke --reason "…"`, then `recover` |
| state `mismatch` / `recovery_image_changed (F,hm,bytes)` | the image changed while the record was pending: `--revoke`, then decide whether to `recover` |
| state `corrupt-receipt` / `corrupt_receipt` | slot `none`: nothing authorized (the file was quarantined), boot; slot holds a record: `--revoke`, then `recover` |
| `reconciliation=failed reason=record_unverified` | finalizing an interrupted act failed (the device refused the flush or the bytes changed): nothing was published and the launcher refuses; `--status` again once the host storage is healthy, or `--revoke`, then `recover` |
| `retirement_completed` / `reconciliation deferred: tool_busy` | informational; nothing to do (deferred: `--status` printed the observed row and `pending=` the state it will reconcile to; run it again after the machine halts) |
| guest `RECOVERY STATE REFUSED reason=resume_mismatch` | the record does not match this disk's state: `--revoke`, then `recover` |
| guest `RECOVERY STATE REFUSED reason=resume_corrupt` | as `corrupt-slot` |
| guest `RECOVERY WRITABLE REFUSED … previous=failed|not_ready` after a recovery | another unclean stop or a boot that consumed the record before readiness: start again from `backup` and `recover` |

Limits, disclosed: identity is logical-state matching plus the host's
binding to the file and, while a record is present, to its content;
byte-identical copies are indistinguishable by content (a backup taken
after the act carries the record and is admitted if booted; `backup.toml`
labels it); saved execution state, `locking=off` instances, invisible
holders and the pre-charge raw replay window are excluded only by the
attestation; file data is unchecksummed and unsynced overwrites are
indeterminate per sector; the recovered generation inherits what the failed
one committed; the timeout is provisional until measured.

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
(release.py:1044-1080; RELEASE.md:310-316). It prints
`MIGRATED to format <m> release=<B> site_files=<n> retained=<name>`
(release.py:1089). Receipt: `receipts/migrate-<B>-<time>.toml`, whose
`rollback` field says the way back: restore the retained image and boot
the previous release's image, and whose `[select_cache]` table records B's
selection cache (release.py:1081-1086; RELEASE.md:295-299).
Ledger: `migrated <B>` then `selected <B> by migration`
(release.py:1087-1088). Refusals: `the disk is already format <n>; use
stage/select` (release.py:1052-1053); `the migrated image differs at <path>`
(release.py:1069-1071); `the migrated image is not the release's format`
(release.py:1072-1073). It also refuses `migration_recovery_history` if
any `/var/state` or `/var/state.new` history (including children) exists or the guard is neither absent nor fresh.
Migration does not reset a recovery budget. Such an input needs an explicit
new-device conversion rule, which this command does not provide; preserve it
and do not clear history to make migration proceed.

## 11. Limits

- **Image size.** Fresh operator images default to 128 MiB; explicit
  `--disk-profile 2g` selects 2 GiB. Their filesystem regions are 64 MiB
  and 1 GiB. Each must hold the installed
  release and a staged successor of the same composition
  (docs/RELEASE.md, "Operator image size"). A 64 MiB disk from an earlier
  release (RC1) is read at its own size: `status`, `backup` and a plain
  `restore` work and leave it unchanged. Commands that write refuse it
  (`image_size`) before changing anything, `stage` with the capacity it
  would need; it cannot be upgraded in place.
  The host validates each disk's actual geometry. Padding an old image
  does not grow it. Whole-image host readers and pinned recovery need
  memory for the full backing size plus parsing buffers, and backup or
  restore may allocate a full copy of a sparse image.

- **Two trees.** With two trees on the disk, staging a third refuses
  (release.py:617-619) until a retired one is removed (section 5, "Make
  room"). Removal needs an importer with step 5: a release built before
  it cannot remove anything. A guest run of A → B → C is release-matrix
  case 14, which passed historically
  (docs/l0-deploy-20261012/receipts/run-14.log), not a current-pair result.
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
- **Image-holder checks are bounded to visible processes.** `backup`,
  `rollback` (either form), `remove`, `reconfigure`, `discard-import-temp`,
  and legacy replacement restore refuse
  `image_in_use` when any
  process this user can see holds the target image open. Strict recovery
  restore separately checks the point's image (`… before a pinned recovery
  restore`); an input inspection error becomes `recovery_point_input_changed`.
  Every command that writes the image or replaces its pathname also takes
  the recovery lock (`tool_busy` beside a running `boot-operator.sh` or
  another tool) and probes QEMU's own image lock once (`image_locked`
  while any default-locking QEMU holds the image), and refuses
  `recovery_pending` while a resume authorization is on the disk (section
  9a); beyond that, `install`, `stage`, `select`, `accept`, `migrate` and
  fresh legacy restore trust the operator to have halted the machine.
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
  (release.py:575, 849); a newly created backup directory and a strict-restore operator directory
  are created with mode 0700 (further restricted by the umask). An existing
  empty legacy backup directory keeps its mode; parent directories and
  `backup.toml` and `receipts/` follow the host's umask. A restored copy that boots on a
  second machine without `--clone` is a cloned identity (RELEASE.md:391).
- **Durability.** Logical durability under QEMU only; physical power-loss
  durability is not claimed (RELEASE.md:370-385).
- **Signing.** Nothing signs a release; integrity is by digest only
  (RELEASE.md:460-466).

## 12. What this runbook does not cover

- **EXACT_HARDWARE_QUALIFICATION.** No physical machine, NIC, writable
  NVMe install, rollback after power loss, or restore onto a named machine
  class is qualified (RELEASE.md:9-13, 381-385). Nothing here is a
  procedure for a physical machine.
- **On-box configuration write.** `/etc` is read-only to sessions;
  configuration changes are host-side, on the halted machine: section 13
  for a target this runbook installed. `build-operator-image.sh
  --reconfigure` (man/afterboot.8, Configuration) is for
  build-operator-image.sh outputs only and refuses an operator directory
  of `release.py` before writing (scripts/operator_image.py:356-404).
- **Key rotation.** There is no on-box host-key or authorized-key
  rotation; a new host key comes only from the regenerate image on the
  host (`restore --clone`, release.py:992-1041; RELEASE.md:391).
- **Complete previous-boot cause.** `logs --list-boots` and `logs -b -1 -u init`
  can expose retained init/service evidence over an authenticated session.
  Retention gaps, failed persistence and final fault output can still leave
  the cause unknown. Preserve console evidence as well (section 9); a retained
  log is not a complete cause or power-loss-durability guarantee.
- **Automatic fallback.** Nothing boots the previous release by itself:
  bounded fault recovery can reset the same selected release, or leave
  local-enabled init in read-only maintenance; selecting a previous release
  remains the operator's `rollback` while the disk is clean. A boot that left
  it dirty needs explicit writable recovery (section 9a) where admitted, or
  restoration into a fresh operator directory (section 8). The recovery
  streak and service liveness checks do not provide automatic release
  selection or an on-box update agent.

## 13. Change the site configuration

```sh
python3 -I scripts/release.py reconfigure --release A --kernel KA --target OUT --etc DIR
```

Halt the machine first. Each regular file of `DIR` replaces its namesake
in `/etc` whole; `--authorized-keys KEYS` also replaces
`/ssh/authorized_keys` (only `ssh-ed25519` lines). Nothing else on the
disk changes. `--release` must be the directory of the release the disk
selects, and `KA` a kernel copy at that release's commit (section 1):
after section 6 selects B, that is `--release B --kernel KB`.

What it does (release.py:976-1132):

1. Checks, before any write, that `OUT/TARGET` and `OUT/RELEASES` are
   regular files and `OUT/receipts` is a directory (created if absent),
   all writable. A directory with only one of `TARGET` and `RELEASES` is
   refused. It also checks that no removal is pending, takes the
   recovery lock for the rest of the command, as every command that writes
   the image does, and checks that no process holds the image. The lock
   refuses `tool_busy` beside a running `boot-operator.sh` or another
   tool, `image_locked` while a QEMU holds the image, and
   `recovery_pending` while a resume authorization is on the disk (section
   9a); each is `REFUSED`, with a failure receipt. Taking the lock creates
   `OUT/recovery/lock` if it is absent (a target installed before the
   lock existed), even when the command then refuses; the file stays, and
   no tool removes it. It then checks the release against the disk:
   - `/absd/selected` names the release;
   - `/releases/<id>/release` names it and is the record the release
     manifest lists;
   - the manifest is the one the newest install or stage receipt of that
     release recorded. If that newest receipt cannot be read, or does not
     name the release and a manifest digest, the command refuses: it never
     falls back to an older receipt. Only a release with no install or
     stage receipt at all is accepted without one (one that came by
     `migrate` or `restore`, which record no manifest). The success
     receipt then says `installation_evidence = "none"`, and nothing
     pins the release directory to the one installed;
   - the kernel is at the manifest's commit;
   - the disk is in the release's format;
   - the files fit one importer boot (1 MiB);
   - the release's `fixture-import.elf` matches the manifest;
   - no replacement path is a directory or an import temporary, and the
     filesystem has room for the replacement.
2. Builds the step-4 ISO around a private copy of the release's importer
   that it has checked against the manifest. Only then does it mark the
   guard dirty and boot the importer once (release.py:499-517, 467-472).
   Each file is its own commit.
3. Reads every replaced file back with the host reader. Then, immediately
   before recording, it compares the whole disk with its state before the
   boot, leaving out only the replaced files and the guard. A file or
   name that was added, removed or changed anywhere (including
   `/absd/selected` and the release trees) refuses the recording.
4. Writes the receipt to a temporary file in `receipts/`, syncs it, and
   publishes it as `receipts/reconfigure-<id>-<time>.toml` with one hard
   link. It then removes the temporary and syncs the directory. The
   receipt holds the file digests, the importer digest and kernel commit
   it ran, and the install evidence.
5. Appends `<UTC time> reconfigured <id> receipt=<name>` to `RELEASES` in
   one write and syncs it. `status` lists the line. Acceptance and
   rollback do not read it.

The recovery lock, held from step 1 through step 5, serializes this
command with every other `release.py` writer, `operator_image.py`,
`absd_try.py enroll` and a running `boot-operator.sh` on one `OUT`.
Exclusive use beyond the lock is the operator's: a writer outside these
tools is not locked out. The image-holder check runs once, before the
boot. The step 3 check catches a change made by such a writer in the
meantime and refuses to record. It does not prevent one, and a change
after step 3 goes unseen.

Success prints `RELEASE RECONFIGURED id=<id> files=<paths> receipt=<name>`
after the ledger is synced. If printing fails, the command still
succeeds: the receipt and the ledger line are the record.

A failure prints `release: <state lowercase>: <reason>` and then
`reconfigure state=<state> phase=<phase> …`. It also tries to write
`receipts/reconfigure-failed-<attempt>-<time>.toml` with the state, the
phase, the files and any importer context. That write is best effort: it
can be missing or, after a storage fault, partial. Only
`RECONFIGURED_PUBLICATION_UNCERTAIN` can have written to `RELEASES`.

| State | Confirmed | Uncertain | What to do |
|---|---|---|---|
| `REFUSED` | The image, the guard and `RELEASES` are unchanged. No success receipt. | — | Fix the cause named and run the command again. |
| `INDETERMINATE` | No success receipt; `RELEASES` unchanged. | The disk. A failure in the kernel ISO build or the importer copy wrote nothing. A failed boot leaves the guard dirty, and files before the failing one may already be replaced. A failed read-back, or a change found in step 3, means the boot completed. | Run `status`. A dirty guard makes every later write refuse (`writable guard: unclean image`) and the next boot refuse pre-ready. Recover as section 9's platform14+ rules say. With a clean guard, find what changed before running again. |
| `RECONFIGURED_UNRECORDED` | Every file replaced and read back; the guard as before. No receipt under its final name. `RELEASES` unchanged. | Only the temporary file. The message says it was removed, or names it if it was left (`receipts/.reconfigure-…tmp`): remove that by hand. | Fix the fault (often a full host disk) and run the same command again. It replaces the same bytes whole and records them. |
| `RECONFIGURED_RECEIPT_UNSYNCED` | As above, and the receipt is under its final name, which the message gives. `RELEASES` unchanged. | Whether the receipt survives a host crash before the directory is synced. A temporary the message names may remain. | Run `sync`. Check that the receipt is there and parses, then reconcile `RELEASES` as below. |
| `RECONFIGURED_PUBLICATION_UNCERTAIN` | As above, with the receipt published and synced. | `RELEASES` may hold none, part, or all of the line the message gives. | Reconcile `RELEASES` as below. Do not run the command again first. |

Reconciling `RELEASES` by hand, for the last two states:

1. The receipt the message names must exist and parse
   (`python3 -I -c 'import sys, tomllib; tomllib.load(open(sys.argv[1], "rb"))' RECEIPT`).
   Its `[reconfigure]` table must have `state = "RECONFIGURED"`, the
   `release` that `status` shows as selected, the `target` in
   `OUT/TARGET`, and the `image` `OUT/absd-operator.img`. Each `files`
   digest must equal the file on the disk:
   `python3 -I -c 'import sys, hashlib; sys.path.insert(0, "scripts"); import operator_image as o; print(hashlib.sha256(o.tree(sys.argv[1])[sys.argv[2]]).hexdigest())' OUT/absd-operator.img /etc/network.conf`.
   If any of this fails, stop. The receipt does not describe this target;
   keep it as evidence and do not append.
2. Read the end of `RELEASES` (`tail -c 512 OUT/RELEASES | od -c`). If its
   last line is the complete line `… reconfigured <id> receipt=<name>`,
   ending in a newline, the ledger is already published: do nothing.
3. If the file does not end in a newline, its last fragment is a partial
   line. When that fragment is a prefix of the expected line, cut it off:
   truncate the file to just after its last newline. Otherwise stop: the
   ledger was changed by something else.
4. Only now append exactly one line:
   `<UTC time> reconfigured <id> receipt=<name>`, ending in a newline. Use
   the time of the receipt's `time_host`, then `sync`.

Limit: the image, the receipt and the ledger are not one transaction. A
host crash, power loss, or storage failure can leave any of these states
with no failure receipt. The host reader, `status`, `receipts/` and the
end of `RELEASES` are then the evidence, used as above.

Changed behaviour of `scripts/operator_image.py reconfigure`
(`build-operator-image.sh --reconfigure`): it now builds every importer
ISO, and checks capacity and replacement paths, before it marks the guard
dirty (scripts/operator_image.py:149-176). A failure there leaves the image
untouched; before this change it could leave the guard dirty with
nothing imported. It now also refuses, before writing, an `OUT` that holds
`TARGET` or `RELEASES`, naming this section's command. Before this
change it imported the files there and then failed for want of a
`MANIFEST` (#63 follow-on F2).

## App A replacement recovery

For the optional `https-document` command, preserve the published `body` and
`receipt` together with `/etc/https-document.conf` and the issuer certificate.
Follow [the App A replacement procedure](NATIVE-HTTPS-DOCUMENT.md#replacement-recovery-of-a-published-bundle)
and [the strict point procedure](P2-REPLACEMENT-RESTORE.md). The point is taken
only after an orderly halt; a later interrupted or wrong-release machine is
preserved and retired, then replaced from that point into a fresh directory.
The loss bound is the point, including loss of later committed writes.

After replacement, check the retained SSH host fingerprint and intended
release, exact old body/receipt/configuration, then sample and attest the new
boot before a new fetch. Prove the new body/receipt and an additional new write
survive a clean restart. Restoring ordinary files does not restore a session,
grant, live TLS connection or current clock attestation. A wrong-release refusal
uses the same documented fresh replacement procedure, not an in-place guard
reset or a generic filesystem-only recovery result.

## Shell and terminal use over SSH

The installed `/bin/sh` is byte-identical to `/bin/absd-sh`. See
[absd-sh(1)](../man/absd-sh.1) for scripting, quoting, functions, pipelines,
redirections, limits and refused forms; [ed(1)](../man/ed.1) covers the
line editor. Interactive prompts support cursor editing and session-local
history. Application input follows the foreground command without shell
read-ahead. `terminal-size` reports the SSH client's current PTY dimensions;
`terminal-size --watch` observes subsequent changes. Unknown dimensions are
reported as unknown, not assumed. This is line-mode input, not raw terminal
or full-screen editor support.

## build_host access to the enrolled local console

The explicit launcher `--local-only --console` path boots the existing ISO and
disk with no emulated NIC. It does not read the malformed network address to
construct a host port forward. The default launch remains the normal NIC and
file-console path. `--local-only` requires `--console`; an unattended file log
alone is not an interactive repair path.

From the **client**, use the existing authenticated SSH connection to build_host and
allocate a terminal (replace both paths with their locations on build_host):

```sh
ssh -tt build_host 'cd /path/to/platform && scripts/boot-operator.sh --local-only --console /path/to/OUT'
```

The launcher and emulator run on **build_host**. The serial terminal is carried by
that SSH session; no public console listener or build_host-local URL is created.
Use the existing [local token login](LOCAL-CONSOLE.md). QEMU stdio has signals
disabled, so control bytes, including Ctrl-C, reach the guest shell rather
than stopping the launcher. The same UART output is kept
in `OUT/console.log`. A terminal hangup delivered to the launcher stops this owned guest and
runs the existing exit classification; the disk recovery lock remains held by
the launcher for its lifetime.

Inside the **guest**, the enrolled shell can inspect diagnostics and prepare
replacement files under `/home/operator`. This slice has no live configuration
trial commands. For startup-only configuration repair, halt the guest with
`shutdown -p now`, wait for the launcher to finish, preserve the console and
back up the stopped image, then follow [offline site reconfiguration](#13-change-the-site-configuration).
A storage-fence refusal instead follows section 9a; the no-NIC profile does not
clear a guard or authorize writes.

After offline repair, launch normally on **build_host**, through the client SSH
terminal:

```sh
ssh -tt build_host 'cd /path/to/platform && scripts/boot-operator.sh --console /path/to/OUT'
```

This restores the ordinary emulated NIC and retains the UART console. A reboot
inside the `--local-only` emulator keeps its no-NIC hardware profile; halt and
relaunch normally to restore the device. Neither route rebuilds the image.
Verify actual new SSH authentication and the intended endpoint before treating
network recovery as successful. Keep both paths bound to the exact installed
release and current resource admission; this example grants no build_host guest slot.

## Files over the operator SSH endpoint

The stock image ships the bounded `absd-sftp(8)` subsystem. From the client,
use OpenSSH `sftp` or default modern `scp` with the same reachable endpoint,
login key and host key pinning as SSH. Relative SFTP paths start in
`/home/operator`. No terminal is needed. The installed manual owns request,
size and metadata limits; legacy `scp -O` and preservation options are not
served. The non-PTY `ssh ... cat` route remains available. A disconnect may
leave a partial upload; compare independent hashes after a transfer.
