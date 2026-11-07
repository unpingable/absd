# Native installer software pilot (#143)

The supported pilot is a blank, 512-byte-sector QEMU SATA disk, selected by
IDENTIFY serial **and model and exact sector count**, with one AHCI controller
and exactly one possibly occupied implemented AHCI port (DET != 0, regardless
of readiness or signature). The base is accepted kernel `82e470de` / platform
`2eb2240e`; the candidate adds the native block writer and a native filesystem boot fixture.
Physical hardware_fixture remains dependent on independently accepted AMD-Vi/named-disk
AHCI containment from `lane/hardware_fixture-served-20261104` (`52cae2a`). That branch is
read for context, not merged or required for this QEMU candidate.

Use [FreeBSD's install sequence](https://docs.freebsd.org/en/books/handbook/bsdinstall/)
(plan, explicit destructive commit, verify, installed boot) and
[OpenBSD's response-file approach](https://man.openbsd.org/autoinstall.8)
for deterministic supplied answers. No source is imported. A Linux installer
would defeat native writes; a new FAT writer would duplicate working media
machinery. Instead, the existing `install_disk.py` GPT/ESP recipe stages a
sparse immutable boot payload, embedded in a dedicated kernel by the existing
build owner. GRUB loads that kernel into reserved RAM; no USB driver or network
server is needed. `PLAN.json` carries disk identity, geometry, source revisions,
ESP file hashes and artifact SHA-256 identities.

The layout is unchanged: protective MBR and both GPT copies; 256 MiB FAT32 ESP
at LBA 2048; 2 GiB ABSD state at LBA 526336; the rest unallocated. The state size
uses the existing [measurement](storage-sizing-20261102/RESULTS.md). The ESP
contains `/EFI/BOOT/BOOTX64.EFI`, kernel and GRUB configuration. Firmware loads
the removable-path EFI loader on the installed disk without an NVRAM edit.
The installed kernel runs a fixture through the existing filesystem/storage
owners used by FSD. They format the bounded state region on its first writable
mount. The fixture creates and syncs `/native-installer-143`, then verifies
those bytes on its next boot. A normal FSD served boot additionally needs the
existing release importer to provision its selected release; that is deferred.
There is no SSH daemon, baked-in login key or network configuration in this pilot;
operator-supplied enrollment and a normal served boot remain #143/#123 work.

The shipped `installer.iso` boots **inspection only**. It prints the selected
IDENTIFY identity and proposed layout and reports `REFUSED consent`. Installation
requires an explicit `install-consent=CRC32` bound to the embedded exact-disk
payload plus `ahci-write=SERIAL`. The E2E runner creates that consent-bearing
boot configuration only for its disposable fixture. The native engine checks
the entire disk is zero before writing anything; unsupported, ambiguous,
nonempty, mismatched or damaged inputs refuse. No overwrite of preexisting data
is implemented. Payload records may touch only boot metadata/ESP and backup GPT.
It writes, flushes and verifies ESP and backup GPT before the primary GPT,
writes the protective MBR at LBA 0 last, then flushes and reads those back.
`INSTALLED` means both flush/readback passes
completed; `REFUSED` means no installation write was attempted; `INCOMPLETE`
means a write or later barrier/readback failed. Interrupted disks remain
nonempty and refuse automatic retry: retain the disk and media for offline
inspection, then prepare a new disposable blank target. There is no resume or
rollback promise after an external write.

CRC32 detects accidental media damage, not hostile replacement; trusted media
is an assumption and Secure Boot is deferred. Identity and consent last only
for this boot. There is no authority transfer, live replacement or schema
conversion; the private sparse format is `ABSDINS1`, bounded to 64 MiB. Existing
block timeout retirement remains in charge. Practical negative tests cover this
single-writer straight-line flow; a concurrency model adds no present coverage.
The reviewer/steward owns acceptance of the exact candidate and boot evidence.

Build the platform core with `ABSD_SSH_STAGE="$PWD/.staged-ssh"`, build an installed
kernel with `ABSD_EXTERNAL_USER_ELF=.../install_persist` and no
`ABSD_FILE_SERVER_ELF`, then run `scripts/native_installer.py --help`.
The builder refuses dirty platform or kernel source trees, including untracked
files, before creating output. Commit source changes before building artifacts.
Run `python3 -B -I scripts/test_native_installer.py` for host tests. Prepare the
OVMF sequence with `scripts/native-installer-e2e.py --artifact DIR --expected-plan-sha256 ACCEPTED_SHA256 --work NEW`;
the digest must be supplied independently from the reviewed artifact. It creates
`COMMANDS.json` and executes no VM. Execution retains `RECEIPT.json` with each
observed exit, unfinished cases, and host GPT, boot payload, ESP and persisted
file verdicts, including failures and timeouts. Only after independent apparatus
review and host admission, add `--execute` with a fresh work directory. It
requires explicit ABSD_PROTECTED_HOST and refuses that host; QEMU 8.2.2 is required. Use an admitted bare-metal KVM host through
`vm-admit --profile absd-noble`; nested KVM is unsuitable for the filesystem
worker's 120,000-tick deadline. The sequence uses one 1-vCPU guest at a time,
with 512 MiB by default. The shared RAM policy permits `ABSD_GUEST_RAM` to
raise that request, rejects malformed or below-floor values, and records the
selected size in `COMMANDS.json`; host admission must cover that size. It runs eight boots,
300 seconds per boot, fresh OVMF variables each time, and no raw devices. It
independently checks GPT, ESP files, refusal byte identity, the persisted file
through the existing host filesystem reader, and both cold boots
with the installer ISO removed. CD media has explicit `bootindex=0`; the
installed disk has `bootindex=1`. The install case also requires exactly two
native FLUSH CACHE EXT commands in the QEMU ATA trace after `INSTALL PLAN`,
independent of guest reports or PASS.json. This observes command submission,
not power-loss durability. `APPARATUS.json` records the actual QEMU version on
execution; offline preparation marks it unobserved and invokes no QEMU.
Linux parent-death SIGKILL ties QEMU's lifetime to the runner, including abrupt
runner death. Keep at least 60 GiB free plus an 8 GiB forecast.

Physical use still requires re-IDENTIFY immediately before the first write;
the full blank scan leaves a hot-swap interval. Consent media is currently
created only by the disposable E2E fixture, not an operator installation flow.
Wrong model/size have host negative coverage only, and the unallocated tail
between state and backup GPT has no separate runtime zero check. Positive
host filesystem inspection is first exercised by boot 7 (`cold-first`). These
limits do not grant physical admission or a normal served-boot claim.
