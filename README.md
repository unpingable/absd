# ABSD

ABSD is an experimental operating system, written in Rust, built to find out
what a system looks like when authority, execution and failure are bounded
explicitly and can be inspected. It boots under QEMU, runs isolated
processes, keeps files across reboots, runs some unmodified Rust programs,
and is administered over stock OpenSSH.

It is a research system. It is not production-ready, it supports no physical
hardware, and it is not a Unix: there is no `fork`, there are no user IDs,
and existing Unix or Linux software does not run without porting.

> **Technical preview, 2026-10-10.** From a fresh clone in a stock Ubuntu
> 24.04 container this release fetched its dependencies, built the kernel,
> the platform and the operator image offline, booted twice under QEMU's
> software emulation and served an SSH session. **The qualification suites
> have not been run on these revisions**: not the kernel suite, not the
> platform gate. They are scheduled after 2026-10-17, when a week-long
> unattended observation occupying the test host ends. `SOURCE-MANIFEST.toml`
> lists what was not run under `not_run`. Earlier revisions were qualified;
> that is recorded at <https://absd.dev/status/> and is not a claim about
> this tree.

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
  `platform/man/afterboot.8`), and nothing is restarted behind the
  operator's back. A separate served-recovery budget (at most three
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
it has not happened yet.

## Build, boot, test

The host that has been used is Ubuntu 24.04 on x86-64. `tools/Containerfile`
is that environment as a container definition; the packages and toolchains
it installs are the requirements:

- Rust 1.95.0 (platform) and 1.98.0 (kernel), each with `rust-src`,
  `rustfmt` and `clippy`, installed with rustup under `~/.rustup`
  (`ABSD_RUST_TOOLCHAIN` names the 1.95.0 toolchain directory if it is
  elsewhere); the platform gate also uses 1.94.0 for one workload's Linux
  reference build;
- clang and LLVM 18, GRUB 2.12 with xorriso and mtools, QEMU 8.2, Python
  3.12 with `python3-cryptography`, OpenSSH client tools, bubblewrap, git,
  make, curl, and `groff-base` 1.23.0 (not the full `groff`
  package: the manual is rendered from a macro tree pinned by digest).

The platform build checks the Rust compiler, cargo, the standard-library
source and the groff macro tree by digest and refuses others. clang, GRUB,
QEMU and Python are not checked; the versions above are the ones used.

```sh
ssh-keygen -t ed25519 -N "" -f ~/absd-key   # the key that may log in to the image
tools/fetch.sh                  # downloads and verifies crates; the only network step
tools/build.sh ~/absd-key.pub   # kernel, platform, operator image -> out/
tools/smoke.sh ~/absd-key       # two boots and an SSH session; no KVM needed
```

`smoke.sh` is the quick, independent check: under QEMU's software emulation
it boots the image, logs in, reads the manual, writes a file, shuts down,
boots again and finds the file. To use the system yourself:

```sh
tools/boot.sh                                  # QEMU in the foreground
ssh -p 2222 -i ~/absd-key operator@127.0.0.1   # from another terminal
```

In the session, `man intro` is the place to start; `shutdown` halts the
machine. `platform/man/afterboot.8` describes the image, its configuration
files and what survives a reboot.

The qualification suites are separate and much heavier:

```sh
tools/check.sh kernel     # the kernel's suite; software emulation, no KVM
tools/check.sh platform   # the platform gate; hours, 12 GiB of disk, needs /dev/kvm
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

**Reproducibility.** The platform gate builds its own programs and the manual
twice and fails if the two builds differ (the ported programs are built
once, and images are not compared), so those builds are repeatable on one
machine. Whether two
different machines produce identical images has not been measured, and the
boot ISO includes GRUB files from the host's package, so it is not expected.

## Licence

ABSD's own source is under the Apache License 2.0 ([`LICENSE`](LICENSE)).
Third-party material in the tree keeps its own terms and is listed in
[`THIRD-PARTY.md`](THIRD-PARTY.md); [`LICENSING.md`](LICENSING.md) says what
applies to what, including what a built image additionally contains.

## Questions and corrections

Open an issue. A statement in this repository or on <https://absd.dev> that
its evidence does not support is a bug, and reports of them are welcome.
