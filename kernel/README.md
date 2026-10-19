# ABSD kernel prototype

ABSD is an experimental operating system written in Rust. Its code is
written largely by AI coding agents from public specifications and their own
knowledge of existing systems, with no formal separation from existing
implementations; docs/PROVENANCE.md records what third-party material it
contains and what is not established about the rest. This
repository is its current kernel implementation path: a small `no_std` x86_64
Rust kernel booted by GRUB's Multiboot2 path.

This repository is only the operating system. Constellation is a separate
project; its programs (AG, Pulse, NQ, Nightshift) are workloads that ABSD can
run, they live above the OS, and nothing in this kernel depends on them. The kernel has a reclaimable process model, handles to kernel objects
(console, processes, cells, pipes, one block device, one NIC, the machine), a
tick clock, and an interactive shell. By design it has no in-kernel
filesystem, sockets, or service manager: the filesystem (`absd-fsd`), TCP
(`absd-net` over the e1000 frame driver), the SSH server and the service
lifecycle live in userspace on the Rust platform (`absd-rust-std`). See
"What exists now" below for what is default, experimental, demonstrated by
test only, or unqualified.
Terms are defined in [docs/TERMINOLOGY.md](docs/TERMINOLOGY.md).

## Prerequisites

`cargo`, `rustc`, a C toolchain linker (`cc`/`ld`), `grub-mkrescue`,
`xorriso`, `qemu-system-x86_64`, and `python3` (for `make shell-test`)
must be available locally. `rust-toolchain.toml` pins the toolchain
(1.98.0). For the default x86_64 build no network download or extra Rust
target is needed: the kernel and the userspace programs are both built for the
host target as static, freestanding binaries. The ARM64 build
(`scripts/build-arm64.sh`) additionally needs the `aarch64-unknown-none` and
`aarch64-unknown-none-softfloat` targets.

## Run

```
make run
```

Expected serial output includes `ABSD KERNEL BOOT` and `ABSD BOOT OK`. The
kernel reports its Multiboot2 information block and supplied memory-map entry
count, then exits QEMU through the emulated debug-exit device, so the run is
deterministic and noninteractive.

## Smoke test

```
make check
```

That runs the unit tests, `cargo fmt --all -- --check`, workspace clippy
with warnings denied, and the deterministic QEMU boots (`smoke`,
`fault-test`, `kernel-fault-test`, `framebuffer-test`, `shell-test`,
`fuzz-test`, `hostile-test`, `machine-recover-test`, `debug`).
The fuzz boot throws thousands of random syscalls at the kernel from ring 3
and requires it to survive and reclaim everything. Its syscall-22 rounds use
real descriptor arrays, with deterministic rollback and resource-invariant
checks gated by `SPAWN HANDLE FUZZ OK`.
`make check` passes on the current tree.

The [qualification map](docs/QUALIFICATION.md) identifies portable, KVM,
release, hardware and research gates, including the separate loader,
disclosure and FPU targets. The [ownership boundaries](docs/OWNERSHIP-BOUNDARIES.md)
record target semantic constraints without opening implementation work.

The smoke test requires exact serial milestones and QEMU's expected debug-exit
status. It retains the physical-memory, paging, IDT, PIT, and heap checks, then
starts a userspace `init` process that spawns, waits for, and reaps hundreds
of short-lived ELF64 processes in independent address spaces. The kernel also
starts this same init as PID 1 for shell and fuzz boots; a bounded startup word
selects the workload, which init launches and reaps through ordinary syscalls.

Serial markers are compact diagnostics over executable checks, not a count of
independent proofs. Userspace failures propagate through process outcomes;
kernel reclamation assertions, CPU fault metadata, owner-tagged accounting,
negative probes, and QEMU exit status decide whether a test passes.

The default boot also loads a local IDT and proves the breakpoint path. A
separate controlled, recovering page-fault path is available with `make
fault-test`; it is intentionally not part of the default smoke boot.

Before any page-table mutation, the kernel installs page-fault and double-fault
gates. The double-fault gate uses IST1 from a loaded x86_64 TSS and a dedicated
16 KiB stack. `make debug` keeps the normal deterministic boot configuration
but adds QEMU's `-no-reboot -d int,cpu_reset` trace at `build/qemu-debug.log`.

The default boot also remaps and masks the legacy PIC, programs the PIT, then
proves five or more timer interrupts before restoring the CPU to an
interrupt-disabled state (`TIMER OK ticks=N`).

A one-page temporary mapping also hosts a tiny aligned bump/free allocator
test. It writes through the mapped heap, frees the allocation, verifies reuse,
then unmaps and restores the original identity mapping (`HEAP OK`).

Every physical frame carries an owner tag (kernel, or a process's page table,
user page, or kernel stack), frames can be freed and reused, and double frees
or ownership mismatches are refused. A process owns its PML4, PDPT, page
directory, page tables, mapped user frames, and kernel stack; all of them are
returned when it exits or faults, and only PID, parent, and outcome remain
until the parent reaps it with `wait`.

Ring-3 programs use a documented register ABI through `int 0x80`: 42
syscalls (numbers 1..=44; 23 is unassigned and 28 retired, both answering
`-38`) covering `write`, `yield`, `exit`, `getpid`,
`spawn`, `spawn_many_copy`, `spawn_image`, `wait`, `map`, `unmap`, `close`,
the cell and pipe calls, the block device (single- and multi-sector reads
and writes, flush, info), the NIC, the wall clock, `frame_stats`,
`resource_census`, the machine object (`machine_stop`, `machine_restart`,
`machine_recover`) and `abi_version` (`abi/src/syscall.rs` is the
authoritative list; HANDOFF.md has the semantics). The optional
`frame-admission-v0` feature adds bootstrap-only calls 45/46; its
[implementation status](docs/FRAME-ADMISSION-V0-IMPLEMENTATION.md) records
build separation, host checks and the remaining RAM/guest qualification gates. Kernel objects are reached only through opaque
per-process handles: the console at entry, child processes from `spawn`,
cells, and pipes; stale, guessed, or wrong-kind handles fail. A pipe is a
bounded byte stream with blocking `read` and `write`, end of file when the
last writer is gone, and a refused write when the last reader is gone.
The PIT tick counter is the clock: `time`, `sleep`, and timeouts on `wait`
and `cell_wait`, with the kernel halting when nothing is runnable. Serial
input arrives by interrupt and `read` on the console blocks for it.
Spawned process handles carry wait and kill rights, which `duplicate` can
narrow independently. They remain local to the parent and cannot be passed
through either spawn ABI.

## Block storage probe

```
make block-probe-test                  # ATA PIO (the default attach)
make block-probe-test BLOCK_DEVICE=nvme
make nvme-test
```

At every boot the kernel probes NVMe first and falls back to ATA PIO; NVMe is
written only when the boot names the controller (`nvme-write=SERIAL`). Both
backends move 1..=8 sectors per command (syscalls 43/44).

Attaches a zero-filled 2 MiB raw image on the primary IDE channel and runs
the userspace block probe: sector writes and reads, the device flush, range
and rights refusals, and recovery of the append region's length after a
fresh scan. The default `make check` boots carry no drive and report
`block: no device`. `make durable-iso DURABLE_STEP=N` plus
`scripts/durable-boot.sh` boot one durable step against a caller-owned image;
the crash matrix that drives them (a Pulse journal workload) lives in the
experimental Rust platform repository.

## Shell

Booting with `shell` on the kernel command line asks userspace init to start an
interactive shell on the serial console. The shell runs any catalog program by
name with an optional numeric argument and reports how it ended. `make shell-test`
drives a scripted session through a QEMU serial socket; `make shell` boots
it on your terminal. A trailing `&` runs a program as a background job, a
trailing `|` captures its output through a pipe, and `kill N` ends a job. A cell is a versioned value
whose `cell_transition` succeeds only from the version the caller names,
the first ABSD-native conditional state transition. Legacy `spawn` can hand
one handle to the child; `spawn_many_copy` copies an ordered array of
rights-narrowed handles atomically. The suite uses it to give one child a
write-only cell and a write-only pipe console, then validates both captured
output and the exact cell transition (`HANDLE TRANSFER OK`, `PIPE CELL
COMPOSE OK`). Three children racing on a shared cell also reach an exact
final state because stale transitions are refused, not lost. The kernel validates user
ranges page by page, including a successful buffer spanning two pages and
refusal of a supervisor address. Unknown syscalls return `-ENOSYS`. Spawning
into a full process table fails closed with `-EAGAIN`; exhausting the
monotonic PID space is a distinct `-75` failure (PIDs are not recycled;
the only rewinds are of boot-time self-test and startup-actor PIDs that no
process can hold, audit finding A4). A process cannot reap another
process's child. Successful wait-any reports the exact reaped PID to
identify the outcome, not as a handle or new authority.

The same boot repeatedly stresses cell/pipe lifetime across child exit, kill,
and reap (`HANDLE LIFETIME STRESS OK`), verifies wait-only and kill-only
process views (`PROCESS RIGHTS OK`), and proves immediate reuse after process,
handle, cell, and pipe capacity refusal (`PROCESS CAPACITY OK`,
`HANDLE CAPACITY OK`, `OBJECT CAPACITY OK`). Final success still requires all
children reaped and every frame, cell, pipe, and process slot reclaimed.
PID 1 also adopts both live and terminal grandchildren from an exiting child,
identifies and reaps their original outcomes, and proves that adoption gave PID 1
no handle to the adopted processes (so no wait or kill right on them) (`WAIT ANY PID OK`, `ORPHAN ADOPTION OK`, `INIT
REAPER OK`).
The suite's bounded userspace supervision probe passes only a write-only cell
handle to a fresh worker, observes an exact fault, starts a distinct replacement
against the same versioned cell, checks its exit and state transition, proves a
healthy long-lived instance obeys a cell-mediated graceful-stop request, proves
a stuck instance is bounded by request/wait/kill/reap, and stops restarting
(escalates, i.e. reports failure upward) after a worker faults twice in a row
on a cell set up to make it fail. The startup word carries each replacement
generation, and diagnostics pair that generation with its fresh PID.
Replacement creation is reported separately from the bounded recovery check;
no kernel restart mechanism is involved
(`SUPERVISOR REPLACEMENT SPAWNED`, `SUPERVISOR RECONCILE OK`, `SUPERVISOR
GRACEFUL STOP OK`, `SUPERVISOR STOP FALLBACK OK`, `SUPERVISOR TIMED WAIT OK`,
`SUPERVISOR ESCALATION OK`, `SUPERVISOR RECLAIM OK`).
The same policy is exercised at process capacity: an applied request survives
its worker's fault, the reconciler is refused without changing the cell,
then succeeds immediately after one filler is reaped (`RECOVERY RESOURCE
REFUSAL OK`, `SUPERVISOR RESOURCE REFUSAL OK`).
The bounded recovery-worker cases distinguish failure before mutation from a
lost reply after the request was applied, using a request ID in the shared
versioned cell.
Fresh replacements retry once, reconcile an already-applied request without a
second transition, and complete normally; the same protocol is refused and
then succeeds at process capacity (`SERVICE RECOVERY OK`, `NO DOUBLE APPLY
OK`, `RECOVERY RESOURCE REFUSAL OK`). An older-generation probe proves the
replacement generation is diagnostic rather than fencing authority. This remains
volatile userspace policy.

A separate long-lived client now survives nine fresh worker replacement
generations over three stable cells. A status cell names the current phase, generation, and
worker PID; a request/control cell carries explicit request and event
generation; the third cell holds the service state and is the only record of
whether a request was applied. The client retries
only a proved-unapplied request, reconciles a lost reply without double apply,
refuses an obsolete-generation event, observes bounded unavailability, and
resumes after capacity returns. A contrasted admission-control experiment
shows that ordinary userspace policy can preserve one process slot for current
recovery needs without creating a kernel reservation mechanism.

The ELF loader accepts only static little-endian x86-64 executables with
bounded `PT_LOAD` segments. It copies file bytes, zero-fills BSS, translates
R/W/X flags, reserves a 1024-page (4 MiB) grow-down stack with the top two
pages initially mapped, and rejects unsupported headers. A write fault on the
page directly below the mapped stack maps one page at a time; the guard below
the reservation remains unmapped. `stack-grow` descends ten pages (nine
resumable faults) with GPR/XMM state preserved, and `overflow` grows through
the whole reservation and then faults on the guard (`USER STACK GROW OK`;
`STACK GROW pages=1031` counts every page grown in the boot).
An independent `stack-jump` probe skips the adjacent growth page without
moving RSP and must remain an ordinary fault (`STACK GROW ISOLATION OK`).
A failed load returns every frame it touched. `init` spawns two programs that
are timer-preempted, one that exits with status 7, and one that faults in ring
3 and is reported as `Faulted` without stopping the kernel; it then fills the
process table to prove bounded spawn failure and runs 200 spawn/exit/reap
cycles. The boot passes only if the frame count returns exactly to its
pre-`init` baseline (`PROCESS RECLAIM OK`).

The workspace has four crates (the kernel, `abi/`, `fbcon/`, `user/`), 49
user program sources in `user/src/bin`, and a 44-entry embedded program
catalog (`abi/src/program.rs`; the other programs are loaded as images by
the matrices): the kernel,
`abi/` (syscall numbers, layout,
program catalog, and outcome encoding shared by both sides), and `user/`
(the freestanding Rust userspace support library plus the embedded programs).
Run `make user` to build and inspect the programs under `build/user`. See
[docs/USERSPACE.md](docs/USERSPACE.md) for the ABI and exact ELF restrictions and
[docs/TERMINOLOGY.md](docs/TERMINOLOGY.md) for the canonical terms. See [HANDOFF.md](HANDOFF.md) for the exact address layout,
context frame, memory ownership, exception behavior, and current stable
boundary. Non-binding, trigger-based notes on possible design influences are
in [docs/DESIGN-INFLUENCES.md](docs/DESIGN-INFLUENCES.md). `make smoke`, `make fault-test`, and `make
debug` remain the deterministic QEMU entry points.

`make external-test` is a separate, opt-in integration boot. It embeds an
input file, passes it to the generic multi-start `external-workload` over a
read-only pipe, hex-frames captured output, and compares the decoded bytes
exactly. `EXTERNAL_USER_ELF`, `EXTERNAL_INPUT`, and `EXTERNAL_EXPECTED` may
replace the default echo fixture; this target is not part of `make check`.
`make external-live-test` instead waits for an explicit userspace readiness
line and delivers a bounded credit-driven stream after boot over serial input.
`make external-live-negative` proves malformed and truncated host streams fail
closed while reclaiming the child, handles, pipes, and frames.

The sibling `absd-pulse` integration uses this generic boundary to
run the Pulse replay evaluator (a Constellation workload) in ring 3. Its pinned
`make pulse-test` compares the output with a recorded reference report
byte-for-byte; `make pulse-traces` compares all 18 recorded traces against the
same Pulse revision's output on the Linux host. Pulse source and
application adaptation remain outside this kernel repository.

The same integration also evaluates real Linux `/proc` frames produced by the
pinned Pulse agent. Its bounded live tests prove three-frame continuity and
hostile `1,3,2` gap/replay handling.

## What exists now

The default boot is a uniprocessor x86_64 suite under QEMU. Everything the
kernel does beyond that is opt-in by boot word or build feature, and each
item below carries the class `docs/QUALIFICATION.md` gives it.

- **Default (QEMU):** the UP kernel suite (`make check`), ATA PIO and polled
  NVMe block backends with multi-sector transfers, the seven object kinds,
  the 42-syscall ABI, the Rust platform's `x86_64-unknown-absd` std target,
  the userspace filesystem library and `absd-fsd`, `absd-sh` and 22 native
  commands plus 8 ports under `/bin`.
- **Experimental configurations (QEMU, UP):** the `net`, `fsd` and `served`
  boot words: a single e1000 frame driver (`make net-test`, not in `make
  check`), TCP through `absd-net`/smoltcp, the SSH server and the operator
  image, operation with the link down at boot or lost later
  (`NIC LINK DOWN AT PROBE`, `docs/NETWORK.md`).
- **Demonstrated by test only:** the served recovery budget (at most three
  automatic resets, then `machine_stop(20)`; an unknown streak stops with
  21; qualified by the
  platform's `survival-recovery.py`, outside `make check`); SMP fixtures for
  2, 4 and 6 CPUs behind the `smp-user-test`/`smp-scheduler-test` features
  and `smp-cpus=N` (AP userspace is refused in production boots, the default
  stays UP); the platform on NVMe; ARM64 B1-B4 (`make arm64-build`, QEMU
  `virt` and HVF, GICv2; `docs/ARM64.md`).
- **Unqualified:** production SMP, served boots with an application
  processor (`served` together with the kernel-only AP option is refused at
  boot), ARM64 filesystem/served/physical boots,
  and any boot on physical hardware: first read-only boots on one physical
  machine have been observed and are not qualification (the survey records
  are development records, not part of a source release).

An isolated experimental Rust platform (the `absd-rust-std` repository) runs an ordinary `std`
probe and the same Pulse replay without adding kernel or POSIX surfaces.
