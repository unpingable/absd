# ABSD

ABSD is an experimental operating system, written in Rust, built to find out
what a system looks like when authority, execution and failure are bounded
explicitly and can be inspected. It boots under QEMU, runs isolated
processes, keeps files across reboots, runs some unmodified Rust programs,
and is administered over stock OpenSSH.

It is a research system. It is not production-ready, it supports no physical
hardware, and it is not a Unix: there is no `fork`, there are no user IDs,
and existing Unix or Linux software does not run without porting.

> **Preview 2 corresponding source, 2026-11-07.** Components are
> kernel `919f0676` and platform `0b002f73`. Development records are filtered
> by the recorded export configuration; no private Git history is included.
> The export configuration records hash-bound adaptations of private labels,
> host guards, optional artifact lookups and explicit execution inputs.
> Source preparation repaired six public-recipe defects in staging, pinned
> checker wheels, Git discovery, fetch delegation, Python bytecode handling
> and the enrollment incremental-build setting. The preceding clean-room
> attempt failed before compilation; that failure remains recorded.
> This corrected source payload passed a separate source review and a fresh
> cloud construction using its public instructions: operator media validated
> 145 files, blank-disk checks passed, and enrollment passed 16 cases/61 checks.
> Its operator ISO matches the local construction. All 45 embedded program
> ELFs in each reconstructed operator and enrollment kernel match the sealed
> reference. All three raw media differ from the sealed release; the cloud
> enrollment ISO also differs from the local construction, and packaging
> outside its extracted kernel and GRUB remains unexamined. Correspondence is
> bounded; whole-image and runtime equivalence are not established.
> `tools/check.sh kernel` still fails at the preserved Clippy `collapsible_if`
> lint. The cloud all/platform checks could not run without KVM. The separate
> `fuzz-test` fails on its legacy-entry self-test; the valid 64-copy capacity
> case remains unexercised in this preview. Later diagnostic results do not
> make the full public kernel check pass. See the release notes for details.
> The licensing examination records its methods and limits; it is not legal
> certification. The binary pair passed an accepted scripted newcomer
> rehearsal under QEMU TCG with private staging; an outsider public-download
> journey and hardware execution were not performed. The earlier kernel
> candidate's console-framing refusal remains recorded separately.
> See `SOURCE-MANIFEST.toml` for incomplete qualification and
> `docs/PREVIEW2-SOURCE.md` for reconstruction instructions.

The exported execution helpers require public, explicit inputs. Set
`ABSD_APP_A_SSH_TARGET` and `ABSD_APP_A_SSH_IDENTITY` for the App A runner;
neither has a lab default. SSH agent use and forwarding remain disabled,
and strict host-key checks remain enabled. No private identity is supplied.
For the ACPI reset observer and an executing native-installer experiment,
set `ABSD_PROTECTED_HOST` to the host where execution must be refused.
An unset policy refuses execution. An explicitly empty value is appropriate
only inside an isolated disposable VM with no protected host in that scope.
Kernel wrappers retain canonical-source and protected-checkout refusal via
`ABSD_KERNEL_SOURCE`, `ABSD_KERNEL_PROTECTED` and `scripts/inputs.sh`. The
SMP application collector also requires an explicit `ABSD_KERNEL_SOURCE`
and refuses that canonical checkout. The optional physical bring-up ISO
requires explicit `HARDWARE_FIXTURE_AHCI` and `HARDWARE_FIXTURE_RTL8125` BDFs;
it has no configured lab devices. Physical hardware remains unsupported by
this preview.

Retained-artifact tests are opt-in: `ABSD_S4_CANDIDATE`,
`ABSD_TEST_OPERATOR_ISO`, `ABSD_TEST_OPERATOR_EXTRACTION`, and
`ABSD_TEST_USERLAND_BUILD` select the corresponding inputs. Unset inputs
skip the checks that require them. Release-manifest lineage is present only
with explicit `--components` or `ABSD_COMPONENTS_TOML`. Archived labels in
fixtures have been rewritten; packet bytes, embedded content hashes,
schemas and historical verdicts are preserved. Five guest-network literal
lines and one bare-header negative fixture have scan exceptions bound to
their file and exact content hashes.

This repository is a **source release**: the kernel, the userspace, the
build and image tooling and the tests, at the revisions named in
[`SOURCE-MANIFEST.toml`](SOURCE-MANIFEST.toml). Development happens
elsewhere; see [`RELEASING.md`](RELEASING.md) and
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## What is here

| Path | What it is |
|---|---|
| `kernel/` | The kernel: x86-64 (and a 64-bit ARM port that has run only in virtual machines), its boot path, its own test programs and test matrices. |
| `platform/` | Everything above the kernel: the port of the Rust standard library, the runtime, the file server, the network and SSH servers, the shell and commands, the manual, the image builder, and the platform test matrices. |
| `tools/` | Entry points for fetching, building, booting and checking this tree, and the tool that assembled it. |
| `docs/` | A map of the documentation, which lives with each component. |

## What it does, and how far that has been checked

- **Isolation.** Every program is a separate process in its own address
  space, started by `spawn`. A process can act only on itself and its
  children; a few whole-system counts are readable by any process
  (`kernel/docs/SYSCALL-DISCLOSURE.md`).
- **Explicit authority.** A process can touch only what it was handed:
  handles to kernel objects, with rights that can be dropped and never
  added. This is the capability model of earlier systems (KeyKOS, EROS,
  seL4, Zircon), not an invention.
- **Stated bounds.** Limits are fixed and written down (processes in the
  system, SSH connections, per-process resources). "Bounded" means that, not
  a timing guarantee.
- **Failure is stated, not absorbed.** The manual says when a file is
  durable (on close, on `sync`, at session end, or shortly after a write;
  `platform/man/afterboot.8`), and service lifecycle and bounded logger recovery are reported
  to the operator. A separate served-recovery budget (at most three
  whole-machine resets, then a stop that names its reason) is demonstrated
  by its own test and is not part of the gate.

What has been qualified, in which environment, with what evidence, is
recorded per release at <https://absd.dev/status/>. The short version:

- There, qualified means the recorded checks passed under **QEMU** (x86-64, one CPU,
  emulated e1000 network card, IDE disk model; NVMe is covered by the
  kernel's and the filesystem's tests, not by the operator image) and were
  re-examined by separate AI model sessions. Those review records are not
  in this repository.
- Several-CPU scheduling, the ARM port and some drivers are
  **experimental**: present in the source, exercised by their own tests,
  switched off or absent in the operator image. `kernel/README.md` lists
  what is in the gate, what is demonstrated by test only, and what is
  unqualified.
- **Not established:** any physical machine, unattended operation over long
  periods, behaviour under hostile network traffic, side channels, and
  anything a security review would establish. Passing tests under an
  emulator does not imply any of these.

### How it was made

One developer directs the work and accepts or rejects results. AI coding
agents wrote most of the code, tests and documentation, including this file.
Review is also done by AI sessions separate from the ones that did the work.
No outside person has audited the design, the code or the tests. Read
"qualified" and "validated" anywhere in this repository as "the recorded
checks passed and were re-examined by a separate AI session", and nothing
stronger. Publishing the source is what makes independent checking possible;
no independent outside audit or reproduction is claimed here.

## Build, boot, test

The host that has been used is Ubuntu 24.04 on x86-64. `tools/Containerfile`
is that environment as a container definition; the packages and toolchains
it installs are the requirements:

- Rust 1.95.0 (platform) and 1.98.0 (kernel), each with `rust-src`,
  `rustfmt` and `clippy`, installed with rustup under `~/.rustup`
  (`ABSD_RUST_TOOLCHAIN` names the 1.95.0 toolchain directory if it is
  elsewhere); the platform gate also uses 1.94.0 for one workload's Linux
  reference build;
- the 1.98.0 targets `aarch64-unknown-none` and
  `aarch64-unknown-none-softfloat` for the kernel gate's ARM64 build;
- clang and LLVM 18, GRUB 2.12 with xorriso and mtools, QEMU 8.2, Python
  3.12 with `python3-cryptography`, OpenSSH client tools, bubblewrap, git,
  make, curl, and `groff-base` 1.23.0 (not the full `groff`
  package: the manual is rendered from a macro tree pinned by digest).
- `xfonts-base` for the kernel framebuffer check's X11 misc-fixed 8x13
  PCF font. The host oracle reads the font independently of the kernel's
  committed glyph table; this package does not add a font to the RC1 media.

The platform build checks the Rust compiler, cargo, the standard-library
source and the groff macro tree by digest and refuses others. The preview media
profile additionally checks exact package versions and the kernel Rust
binaries; see `platform/media/vm-operator.toml`. clang and Python are not
fully pinned by that profile.

For this release's source build, follow
[`docs/PREVIEW2-SOURCE.md`](docs/PREVIEW2-SOURCE.md) and
`tools/rebuild-preview2.sh`. The recipe includes the C userland inputs,
uses the recorded Preview 2 release ID and public construction key, and
checks the manifest-bound public snapshots. Its exact clean-room result
is recorded separately; construction alone does not establish reproduction.
The historical RC1 recipe is linked from `docs/RC1-SOURCE.md`.


For the downloaded preview's SSH workflow, use its `QUICKSTART.md`.
The reconstruction outputs use the published construction public key and
are comparison artifacts. `platform/man/afterboot.8` describes the image,
its configuration and what survives a reboot.

The qualification suites are separate and much heavier:

```sh
tools/check.sh kernel /absolute/path/preview2-work     # the kernel's suite; software emulation, no KVM
tools/check.sh platform /absolute/path/preview2-work   # the platform gate; hours, 12 GiB of disk, needs /dev/kvm
```

KVM is needed only by the platform gate, whose containment matrix runs
hundreds of sessions. The tests build what they test from this tree.

What `check.sh platform` runs is the **core** profile: everything that needs
nothing but ABSD. Development also runs an **extended integration** profile,
in which programs from other projects (Pulse, AG, Nightshift, NQ) are built
for ABSD and run on it as demanding workloads. Neither those projects'
sources nor the test programs written against them are in this repository,
so that profile does not run here: each of its steps
prints `NOT_RUN` by name, and the gate's last line says so. Two things
follow, and they are stated rather than hidden:

- the guest filesystem crash matrix is in the extended profile, because the
  program it crashes is AG's store. The filesystem library's own crash
  tests (every crash point of every operation, on a host sector device) are
  in the core profile;
- a claim on <https://absd.dev> that rests on an extended step was
  established in development, with those sources, and cannot be re-run from
  this repository alone.

The build and the checks refuse a `kernel/` or `platform/` that is not the
tree `SOURCE-MANIFEST.toml` names. `ABSD_ALLOW_MODIFIED=1` runs them on your
changes, and what they produce says `modified`.

**Reproducibility.** Two source assemblies must have identical Git trees.
That check does not compile or execute ABSD. The platform gate builds its own programs and the manual
twice and fails if the two builds differ (the ported programs are built
once, and images are not compared), so those builds are repeatable on one
machine. Whether two
different machines reconstruct the published RC1 images from this public
tree has not been established. The RC1 media path compares two deterministic
operator ISOs using pinned GRUB packages and a fixed epoch. The enrollment
ISO uses the older wall-clock-stamped path; byte equality is not promised.

## Licence

ABSD's own source is under the Apache License 2.0 ([`LICENSE`](LICENSE)).
Third-party material in the tree keeps its own terms and is listed in
[`THIRD-PARTY.md`](THIRD-PARTY.md); [`LICENSING.md`](LICENSING.md) says what
applies to what, including what a built image additionally contains.

## Questions and corrections

Open an issue. A statement in this repository or on <https://absd.dev> that
its evidence does not support is a bug, and reports of them are welcome.
