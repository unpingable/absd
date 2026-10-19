# ABSD Kernel Handoff

## Selective channel repair — 2026-10-05

The platform Holder/constructor-order repair is canonical at `60388b0`, with
focused kernel regression coverage qualified at `4dc54d6`. See
the exact integration receipt (development record, not in a source release).
Failed tracking preserves an outstanding borrow as terminal local quarantine:
ordinary parent requests, reuse and DERIVE through the affected channel are
refused with zero parent effect.
Process replacement alone does not retire surviving adopted endpoints.
Exceptional local availability loss and raw/trusted exclusions remain explicit.
Affected-surface qualification and post-merge replay pass. That integration
occurrence remains globally red for the inherited guarded RT case-9 selector
failure; subsequent corrected RT fixture qualification is recorded separately. Sealed
`absd-20261003.1` pins remain unchanged; active research stays isolated.

## CPU-local identity and next physical evidence — 2026-10-05

Selective integration is accepted after bounded RT state reconciliation (development record, not in a source release).
The exact executable `973c61d` passes matched default-KVM RT fixtures and
canonical checks. Earlier red receipts remain intact; physical RT stays pending.

The selective port (development record, not in a source release) brings checked x86
GDT/CpuLocal identity onto the ARM-integrated baseline. It changes no scheduler
policy or BKL release. ARM identity and shared policy remain intact.
Scaling stays mixed (development record, not in a source release); production AP
guards remain enabled, and strict development-host RT timing remains unresolved.
The next meaningful evidence belongs to the
physical Z2 lane (development record, not in a source release), starting with
an attached USB controller cycle. Internal storage writes remain owner-gated.
Sealed release pins are unchanged. Exact-port acceptance is recorded in the
integration receipt, rather than inferred from donor lane success.

## What works now

This repository boots a `no_std` x86_64 Rust kernel through GRUB Multiboot2 in
QEMU. It has serial diagnostics and panic reporting, mirrored to a Multiboot2
linear framebuffer console when GRUB provides one, consumes the Multiboot2
memory map, allocates physical frames, mutates and restores page tables, loads
an IDT, handles breakpoints and page faults, gives double faults a dedicated
IST stack, drives the PIT through the legacy PIC, and exercises a one-page
kernel heap.

Userspace is real ring 3 execution with a reclaimable process model. The
kernel always starts one embedded static ELF64 program, `init`, through the
same `spawn` path userspace uses. A bounded startup word tells init whether to
run the suite or launch the shell/fuzzer through ordinary userspace calls.
A 16-slot process table records PID, parent, address space, kernel/user
stacks, saved context and FPU image, handle table, lifecycle state, and
outcome. Every physical frame carries an owner tag; a process's page
tables, user frames, and kernel stack are all returned when it exits or
faults, and the parent reaps the remaining metadata with `wait`. Any CPU
exception in ring 3 is that process's failure, reported by vector.

Kernel objects are reached only through opaque per-process handles with
rights: the console (serial output and interrupt-driven input), child
processes, versioned cells with a conditional transition and blocking on
change, and bounded pipes with blocking read/write, end of file, and
broken-pipe detection. The machine itself is an object too: the kernel
gives init the one machine handle (stop and restart rights) and nobody
else, so ending or restarting the machine is a right init grants, never
ambient. Legacy `spawn` hands one handle and an argument word;
`spawn_many_copy` atomically copies an ordered array of narrowed handles and
can replace the child's console; `spawn_image` does the same for a static
ELF64 image held in the caller's own memory instead of a catalog entry
(docs/PROCESS-STARTUP.md). Process handles carry independently
narrowable wait and kill rights but cannot be transferred; genealogy and
reaping remain parent-local. `duplicate` narrows rights; the last handle frees
the object.
Each process also has a 32 MiB anonymous `map`/`unmap` window (it was
4 MiB, and a process had at most 8 page tables, 16 MiB of mapped address
space; AG's pinned-file check reads a multi-megabyte resolver image whole,
so the bounds are now 32 MiB and 32 tables). The PIT is
the clock: `time`, `sleep`, timeouts on `wait` and `cell_wait`, and an idle
loop that halts until an interrupt.

A `net` boot adds one network interface (docs/NETWORK.md): a polled Intel
82540EM (QEMU `-device e1000`) moving whole Ethernet frames through a NIC
handle (`nic_info`, `nic_send`, `nic_receive`, syscalls 32–34). The
kernel keeps the descriptors, the static DMA buffers, and every
device-written field; a malformed descriptor is refused and recycled, and
a device head register outside its ring disables the NIC. There are no
kernel sockets: ARP, IPv4, ICMP, and TCP run in the one process init hands
the NIC to (smoltcp, in the Rust platform repository's `absd-net`).

The wall clock is separate and read-only: `wall_clock` (syscall 30,
`src/rtc.rs`) returns seconds since the Unix epoch from the CMOS RTC. It
requires two identical consecutive register snapshots taken outside an
update cycle, validates every BCD/binary field and the calendar date, and
refuses with `ERROR_IO` rather than substitute a value. Precision is one
second. The RTC carries no time zone or century: ABSD reads the year as
2000..=2099 and declares the clock to hold UTC, which is what QEMU's
default `-rtc base=utc` seeds from the host. A physical machine's RTC holds
whatever its firmware or last operating system wrote (often UTC, local time
on machines set up by Windows) and drifts uncorrected; ABSD cannot tell
these apart and never adjusts the reading. The default boot reads it,
requires it to advance across a 1,100-tick sleep (`WALL CLOCK OK`), and
`make smoke` requires the value to lie within two seconds of the host's
clock around the QEMU run.

Userspace is a `no_std` Rust crate with syscall wrappers and 49
program sources (44 in the embedded catalog). The default boot runs `init`, which spawns every demonstration
program and checks its outcome, stresses handle lifetimes and split process
rights, fills and immediately reuses the process, handle, cell, and pipe
tables, races children on a shared cell, composes a captured pipe with a
shared cell, streams a larger-than-capacity input through narrowed pipe
handles, performs one bounded userspace supervision/restart experiment
with replacement-generation/PID diagnostics and graceful-stop-before-kill policy,
grows a bounded user stack, streams a pipe, exercises timeouts,
and runs 200 spawn/terminate/reap cycles; the boot
passes only if every counter matches and the allocated frames, cells, and
pipes are all back to zero. In shell and fuzz boots, init launches the
selected program, waits for its exact outcome, drains adopted descendants
with identified timed waits, and exits
only after userspace cleanup. The `shell` boot is interactive over the serial
console.

Pulse, AG, NQ, and Nightshift, named below, are Constellation programs that
ABSD runs as workloads; they live above the OS and nothing in the kernel
depends on them. The generic external-workload boot has run the Pulse replay
evaluator in ring 3 through the separate `absd-pulse` integration.
Its demo report matches a recorded reference report byte-for-byte, and all 18
recorded traces match reports produced by the same pinned Pulse revision on
the Linux host. Real Linux `/proc` frames also exercise first/continuous
ingestion and hostile gap/replay ordering through one native evaluator
process. Each run exits normally and returns kernel resources to baseline. Pulse
source and adaptation remain outside this repository; the kernel only supplies
its generic allocator, stack, pipe, process, and capture mechanisms.

An opt-in `external-live` boot can also accept generic bytes after init is
running. Its host protocol uses explicit readiness, 64-byte credits, a 128 KiB
bound, timeouts, and an explicit EOF record before init relays bytes into the
existing child pipe. Captured child output remains separately hex-framed.
Malformed and truncated ingress deterministically fail the workload and still
return all resources to baseline.

The kernel also probes one block storage device at boot: one NVMe namespace
(polled, found by PCI class) or, failing that, a raw QEMU image on the
primary IDE channel, driven by polled ATA PIO with IRQ14 wakeups. The
device layer knows sectors, requests, completion, and flush; nothing above
that knows which backend is present. A request is one sector
(`block_read`/`block_write`) or up to eight consecutive sectors in one
device command (`block_read_many`/`block_write_many`, syscalls 43/44: ATA
`READ/WRITE SECTORS` with a sector count, NVMe `NLB`); either way
completion is the device's acceptance and `block_flush` is the only
durability barrier. In a durable boot (`block-probe` or
`durable=N` on the command line) init receives the device as a handle and
passes it to the selected multi-start workload together with the boot's step
value N in a read-only cell (the step cell). The step value is opaque to the
kernel and init; the workload uses it to decide what this boot does, for
example where to stop the machine. `machine_stop` ends the machine
abruptly through the debug-exit device at a named application point; its
authority is a machine handle with the stop right, which the kernel gives
only to init and init copies, stop-only, only to a qualification durable
worker (docs/PROCESS-STARTUP.md, "Machine authority"). A `served` boot
(`durable=N net fsd served`) runs its SSH worker with no deadline. An
operator can request orderly shutdown (halt or restart). Init records the
request when it reaps the worker; an orderly end that then cannot finish
as asked (an unreaped orphan, a file server that exits non-zero or does
not stop, a failure in the worker's stream) escalates with `SERVED
SHUTDOWN ESCALATED`: a requested halt stops the machine (`machine_stop`
17, 18, or 19), a requested restart takes the recovery reset once the
generation was ready and stops before that; it never takes the fault
path. After the
served generation is ready, an sshd or FSD fault during service takes
init's bounded stop/wait and whole-machine reset path, under a durable
budget: fsd owns the ledger `/var/state/recovery`, at most
`SERVED_RECOVERY_BUDGET` (3) consecutive resets are automatic, the next
qualifying failure stops the machine with code 20
(`recovery_budget_exhausted`), an unreadable or missing ledger stops with 21,
and the streak clears only after an orderly end that init completed
(`abi/src/program.rs`, `user/src/bin/init.rs` `recover_served`,
`docs/service-lifecycle-20261008/RECOVERY-BUDGET.md`; qualified by the
platform's `survival-recovery.py`, outside `make check`). A pre-ready failure
refuses automatic reset (docs/PROCESS-STARTUP.md,
"Served boot and orderly shutdown";
qualification record (development record, not in a source release)). The historical
experimental Rust platform pairing ran the Pulse journal over this substrate
through a `std::fs` that could open exactly one file name; see the "Block
storage and durable boots" section. Its evidence describes that isolated
pairing, not the later accepted platform main or successor release candidate.

## Canonical verification

Run these from the repository root:

```sh
cargo test --workspace --exclude absd-user
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
make smoke
make fault-test
make kernel-fault-test
make framebuffer-test
make shell-test
make fuzz-test
make hostile-test
make machine-recover-test
make debug
```

`make check` runs all of them in that order. `make fuzz-test` boots with
`fuzz` on the command line: PID 1 is init, which launches the `fuzz` program;
the latter issues 4000
syscalls with pseudo-random numbers and arguments from a fixed seed. Syscall
22 receives real small descriptor arrays, preceded by deterministic valid and
hostile transfer/rollback cases (`SPAWN HANDLE FUZZ OK`) plus a recursive
rights-narrowing chain (`RIGHTS CHAIN FUZZ OK`); waits always carry timeouts,
console reads are skipped, and the fuzzer never closes its console.
It then kills and collects the children it happened to start; the
boot passes only if the kernel never faulted or panicked, the fuzzer
exited 0, every refusal class was exercised, and frames, cells, pipes,
and process slots are all back to zero (`FUZZ OK`, `build/fuzz.serial.log`). `make shell-test` boots with
`shell` on the command line and drives a scripted interactive session
through a QEMU serial socket with `scripts/shell-session.py` (needs
`python3`); it requires each command's reported outcome, at least seven
prompts, `SHELL SESSION status=0 frames=0 ...`, `SHELL SESSION OK`, and
`ABSD BOOT OK`. Its serial log is `build/shell.serial.log`; the fault
boots log to `build/fault.serial.log` and `build/kernel-fault.serial.log`.

`absd-user` is excluded from `cargo test` because its freestanding runtime
shims cannot link against the host test harness; clippy still checks it.
The full canonical `make check` passes on the current tree. Supervisor writes
are protected by CR0.WP, and debug builds assert that syscall, user-exception,
and user-timer entry occurs with interrupts disabled.

Native Pulse integration is an opt-in cross-repository gate, not part of
`make check`: `absd-pulse` pins the adapted Pulse source at
`81c2354` and an exact clean ABSD revision.
Run `make pulse-test` there for the recorded demo report and `make
pulse-traces` for all 18 recorded traces (`PULSE TRACES OK count=18`). Its
`pulse-live-sequence` and `pulse-live-reorder` targets use real agent frames.

Historical probe evidence came from the isolated Rust platform pairing at
the `absd-rust-std` repository, which pinned its exact
compiler and otherwise-unversioned rust-src snapshot by content. That pairing
reconstructed twice from clean inputs, passed its ordinary-program and
panic-abort matrix, and passed `ABSD RUST STD PROBE OK` and
`ABSD RUST STD PULSE OK`. It was an experimental compatibility pairing, not
an upstream-supported Rust target. Later, the accepted release pinned platform main
`e70af640`, including keeper-departure refusal `b4eda83` and the BIND
settlement change `b0cb9da`. Current canonical platform main
`c54dc90007fe509c0e118b7ec9c6cbd6ea9aa356` includes exact kernel
revision selection and the qualified allocator repair below. Its predecessor
`4ac76cab82adc1591a2a996292126e765134534b`, paired with kernel
`c406d803f202f72c5c154da09804c0db3b2e2891` failed the successor
300-session capacity gate: frames 753 → 770 and sshd mapped heap pages
314 → 331. Process/handle/pipe/cell counts and normalized filesystem object
counts returned; final halt reclaimed all guest frames. Subsequent bounded
allocation diagnostics identified fragmentation followed by retained free
pool capacity: a 65,552-byte normalized FSD reply clone could not fit the
largest 65,424-byte region despite 79,504 free bytes, so it mapped 17 pages.
Settled live bytes/count stayed unchanged; all added bytes were free. The
sealed `.3` services also grew on a newly prepared disk, without rewriting
that release's historical acceptance.

Integrated platform repair `c54dc90007fe509c0e118b7ec9c6cbd6ea9aa356` returns
dedicated temporary allocation pages. Three fresh 300-session runs and one
same-boot 600-session run passed the original equality and teardown oracle;
requested checkpoints held 595 guest frames and 218 sshd mapped heap pages.
The bounded receipt and independent review are in
`build/ssh-heap-20261003-94eb7cb4685a`; no oracle allowances were added.
This establishes the scoped repair, not generic allocator, SMP or RT timing
correctness. Whole-platform replay `4d8660cf-e799-46a6-bea5-4d013191fcb9`
passed and was independently accepted, using frozen kernel `f2c200b` and
platform `c54dc90`: 193 host test executions, all 26 runtime targets,
66 containment cases and the unchanged 300-session oracle. That run's own
baseline/final values were 594 frames, 218 SSH heap pages and 12 FSD heap
pages; original resource equality and zero teardown held. Compatibility
matched its existing ledger (19 agreeing cases and six documented
divergences). Receipt: `build/successor-platform-replay-20261003-4d8660cfe799`;
independent acceptance SHA-256:
`97002cc86883f5fe3b627e168f00a0511254a4259bf882d83c479622a9a8f33e`.
Platform main fast-forwarded to that exact seven-file repair, with no
active research merged. Historical `a2b08686-91b1-4f82-b473-58019f1fd984`
remains a failed pre-build occurrence, with exact receipts in
`build/successor-release-20261003-a2b0868691b1`; no later pass erases it.

Fresh chain `dcfd9e69-bda7-486d-b6df-820a6dd9aee4` used kernel
`fcfbab9867da40eebb0c4dd266b82484ae7e76c5` and platform `c54dc90`.
It built B, completed 28 steps including accepted A → B / B → A rollback
with site state and halted B backup/restore, then failed the actual-release
ELF first-template census: `[5,80,30,1,627]` → `[5,78,30,1,625]`
(processes, handles, pipes, cells, frames). Hash guards held; that original
chain is rejected and its decrease's unique cause remains unknown. Receipt:
`build/successor-release-20261004-dcfd9e69bda7`.

Separate startup-fenced replay `65121112-4a3e-4d85-a4eb-2a440df011f0`
passed all three unchanged probe bodies on the original B archive/services:
87 ELF cases with full per-case census, valid controls and sentinel;
28 disclosure checks; existing spawn assertions; all three clean served
halts with zero final census. Independent acceptance SHA-256:
`ecff1cc074071ed3fc71496a6679aaeafadf5867617cc5e8f7aae51098f4853e`.
The test-only fence follows current parent-spawn completion; it neither
proves global service quiescence nor uniquely attributes the prior decrease.
The preceding `e06dc33d` fixture compile failure is separately preserved.

Served continuation `9a88f33c-ebf4-4982-9dd4-ccd3a59ca29d` completed
all six existing gates at 2026-10-04 06:37Z; independent scoped acceptance
`7d5f5f06dc20d6c255d4d55052a8523e36471ada4b5233df6f29c2f9138fb941`
verifies all 13 containment cases, actual-B 300-cycle equality at 594 frames/
218 SSH pages/12 FSD pages, framing/load and both service recovery cases.
Full reconstruction `5048b8a2-0294-448f-ad6c-a58564c3ee39` then completed
at 07:16Z: toolchain matches, 54 files byte-identical, two generated release
records not rebuilt under existing doctrine, GRUB exact, kernel identical
under existing stripped/build-id normalization. ISO wrapper bytes differ.
Independent reconstruction acceptance `07f9b1bb` and overall exact-pair
acceptance `87cda7d9` now accept the composed scopes. `absd-20261003.1` is
**validated and sealed locally**; prior `.3` remains immutable and the
qualified rollback target. See the successor record (development record, not in a source release).
No kernel defect is established, and no original predicate
was weakened. The [qualification map](docs/QUALIFICATION.md) records scoped
source/receipt correspondence and the formalization decision. Halted rollback,
startup ordering and reconstruction establish no safe live hardware transfer
or post-effect rollback.

`make block-probe-test` boots `block-probe` against a zero-filled 2 MiB scratch
image (`BLOCK_DEVICE=ata`, the default, or `BLOCK_DEVICE=nvme`), requires
`BLOCK DEVICE OK sectors=4096` and the matching `BLOCK BACKEND`, the exact
captured probe output (`tests/block-probe-expected.txt`, including the
multi-sector section: a full eight-sector request written and read back
whole, cross-checked sector by sector, partial requests, and the refusals
of an empty, oversize, straddling, or read-only request), the host-side
image check after QEMU has exited (`scripts/block-probe-image-check.py`:
the bytes written through both paths are on the image file, neighbouring
sectors still zero), and the
`DURABLE status=0 ...` accounting line with its block request, wait, and
interrupt counters (interrupts only for ATA; NVMe is polled). It is
not part of `make check` because it needs a disk image; `make check` boots
carry no drive and print `block: no device`. `make durable-iso
DURABLE_STEP=N EXTERNAL_USER_ELF=...` builds one ISO per step value and
`scripts/durable-boot.sh` boots it against a caller-owned image
(`ABSD_BLOCK_ATTACH=nvme` attaches it as a QEMU NVMe namespace instead of
the IDE master); the crash matrix that uses them lives with the journal
workload in the Rust platform repository (`scripts/durable-matrix.py`,
`scripts/fs-matrix.py`). `make nvme-test` is the kernel-level NVMe gate;
see "Block storage and durable boots".
`make broker-test` checks init-brokered spawning (docs/BROKER.md): a
durable worker without the spawn right asks init for catalog programs; init
starts only what its embedded policy permits, with narrowed handles, and
reclaims them when the requester ends (`INIT BROKER SPAWN|AUTHORITY|REFUSAL|
RECLAIM OK`).
`make spawn-image-test` checks `spawn_image` (docs/PROCESS-STARTUP.md):
the external workload builds images in its own memory, starts one and reads
its output through a pipe, requires the exact error of every refusal it can
provoke and that none consumed a PID, and requires complete reclamation
(`SPAWN IMAGE TEST OK`).

`make elf-matrix-test` (docs/ADVERSARIAL-ELF.md) runs the adversarial image
matrix through `spawn_image`, and `make disclosure-probe-test`
(docs/SYSCALL-DISCLOSURE.md) runs the copyout/stale-handle/register
disclosure probe; both pin their own accounting line and are not in
`make check`.
`make net-test` is the kernel-level NIC gate (docs/NETWORK.md): the
`net-probe` boot's refusals and a byte-exact layer-2 reflection against a
host harness on `-netdev dgram` (`scripts/nic-reflect.py`), 1515..1518-byte
frames refused, an out-of-ring head register injected into the device
disabling the NIC, and a `net-probe` boot without a NIC failing. It is not
part of `make check`.
`make durable-reader-test` checks init's second durable process: a reader
started after the worker with a read-only block handle, and refused while
the worker left a live descendant (docs/DURABLE-JOURNAL.md).

`make framebuffer-test` boots the kernel-fault case with `halt-on-exit`,
takes a QEMU screendump, and requires every pixel of the screen to equal
the host's own rendering of the serial stream (`scripts/framebuffer-check.py`
renders from the X11 PCF font, not the kernel's rasterizer), including the
red fault report and the `ABSD HALT code=2` notice.

`make smoke` and `make fault-test` require QEMU to return status 3, the encoded
success value from the ISA debug-exit device. `make kernel-fault-test` boots
with `kernel-fault-test` on the command line, raises an unarmed ring-0 page
fault, and requires the `KERNEL FAULT vector=14 ...` diagnostic plus status
11 (`exit_qemu(2)`). `make debug` uses the same
deterministic boot plus `-no-reboot -d int,cpu_reset` and writes
`build/qemu-debug.log` so reset or triple-fault behavior is visible.

## Serial success markers

Markers are compact pass/fail diagnostics, not independent proof counts. The
checks that actually decide a pass are userspace assertions propagated through nonzero exit,
kernel lifecycle and reclamation checks, CPU-supplied fault metadata,
owner-tagged frame accounting, negative behavioral probes, and QEMU's exit
status. Several markers may summarize the same underlying assertion chain.

The default smoke path requires these milestones (along with frame addresses
and the individual user-process messages):

```text
ABSD KERNEL BOOT
FRAMEBUFFER CONSOLE OK width=W height=H ...
IDT BREAKPOINT OK
PAGE MAP OK
TIMER OK ticks=N
HEAP OK
SPAWN EXHAUSTION OK
PROCESS MODEL OK
SYSCALL NEGATIVE CONTROLS OK
MULTI HANDLE SPAWN OK
CHILD CONSOLE RIGHTS OK
HANDLE TRANSFER OK
PIPE CELL COMPOSE OK
INPUT STREAM OK
HANDLE LIFETIME STRESS OK
PROCESS HANDLE REAP OK
PROCESS RIGHTS OK
WAIT ANY PARENTAGE OK
WAIT ANY PID OK
ORPHAN ADOPTION OK
ADOPTION HANDLE PRESSURE OK
INIT REAPER OK
SUPERVISOR OBSERVED FAULT
SUPERVISOR REPLACEMENT SPAWNED
SUPERVISOR RECONCILE OK
SUPERVISOR CLOSURE OK
SUPERVISOR RESTART OK
SUPERVISOR GRACEFUL STOP OK
GRACEFUL STOP OK
SUPERVISOR STOP FALLBACK OK
SUPERVISOR TIMED WAIT OK
FORCED STOP OK
SUPERVISOR RECLAIM OK
SUPERVISOR ESCALATION OK
SUPERVISOR RESOURCE REFUSAL OK
SERVICE GENERATION OK
REQUEST IDENTITY OK
CONDITIONAL SERVICE UPDATE OK
RECOVERY NOT PERFORMED OK
RESTART BEFORE RECOVERY OK
RECOVERY RECONCILE OK
NO DOUBLE APPLY OK
RECOVERY NORMAL COMPLETION OK
SERVICE STATE SURVIVES RESTART OK
RECOVERY REPLACEMENT REFUSED
RECOVERY RESOURCE REFUSAL OK
SERVICE RECOVERY OK
CLIENT GENERATION CONTRACT OK
CLIENT SERVICE OBJECTS STABLE OK
CLIENT GENERATION CHANGE OK
STALE GENERATION REFUSED OK
CLIENT RETRY NOT PERFORMED OK
CLIENT RECONCILE COMPLETED OK
CLIENT NO DOUBLE APPLY OK
CLIENT NORMAL COMPLETION OK
CLIENT SURVIVES SERVICE RESTART OK
MULTI GENERATION SERVICE OK
CLIENT SERVICE UNAVAILABLE OK
CLIENT SERVICE RESUME OK
RECOVERY HEADROOM PRESERVED OK
RECOVERY HEADROOM EXHAUSTED OK
PROCESS CAPACITY OK
HANDLE CAPACITY OK
OBJECT CAPACITY OK
USER STACK GROW OK
STACK GROW pages=1031
STACK GROW ISOLATION OK
init: demonstration outcomes verified
init: spawn capacity bounded and reaped
init: lifecycle stress complete
FRAMES baseline=N peak=N final=N spawns=N reaps=N
OBJECT TABLES EMPTY OK
SYSCALL ABI OK
USER MEMORY VALIDATION OK
PROCESS HANDLE ISOLATION OK
PROCESS EXIT OK
PROCESS FAULT ISOLATION OK
USER PREEMPTION OK
SPAWN OK
SPAWN BOUNDED OK
REAP OK
PROCESS RECLAIM OK
PROCESS STRESS OK
USER PROCESSES OK
USER SCHEDULER OK
ABSD BOOT OK
```

The separate fuzz boot additionally requires `SPAWN HANDLE FUZZ OK`, its
round summary, complete reclamation, `FUZZ OK`, and `ABSD BOOT OK`; numeric
counter totals remain executable suite invariants rather than documentation.

The suite also emits one `SPAWN OK pid=N parent=P program=NAME` line per
spawn (`pid=1 parent=0 program=init`, then `pid=2..5` for `hello-a`,
`hello-b`, `exit7`, `fault`), at least two `USER PREEMPT pid=X -> pid=Y`
lines, `USER EXIT pid=N status=S` for every exit, `USER FAULT pid=N
address=... error=0x...0007` for every fault, and a `COUNTERS` line with the
runtime statistics the final check evaluates. The dedicated fault boot adds
`PAGE FAULT OK` before running the same process suite.

## Framebuffer console

The Multiboot2 header asks GRUB (optionally) for a 1024x768x32 linear
framebuffer; GRUB sets it through VBE or GOP and reports it in boot tag 8.
`src/framebuffer.rs` accepts 24/32-bit direct colour, maps it uncached
(`src/mmio.rs`: a kernel window of 2 MiB UC pages at 256 GiB virtual, shared
by every address space, reaching any physical address), and clears it before
`ABSD KERNEL BOOT`. From then on `serial::byte_out` draws every console byte
there too; serial output is unchanged. The rasterizer is the separate crate
`fbcon/` (host unit tests, built with optimization because it runs per
byte): 8x13 cells from the public-domain X11 `8x13` font, 2x on screens
1600 pixels wide or more, deferred wrap, and a ring of rows instead of
scrolling (a newline clears the row it enters and the next, only as far as
text was drawn), so framebuffer reads are never needed.

At boot the kernel draws every printable character (`FRAMEBUFFER PROBE`),
reads the framebuffer back, and prints `FRAMEBUFFER CONSOLE OK ...` only if
every pixel of every cell is exact. Panics and ring-0 fault reports switch
to white on red first. `exit_qemu` draws a screen-only `ABSD HALT code=N`
line; with the `halt-on-exit` option it then halts instead of writing the
debug-exit port, as a machine without that device does. The boot's first
command-line word selects the mode; later words are options
(`halt-on-exit`, `nvme-write=SERIAL`).

## Block storage and durable boots

Backend selection (`src/block.rs`) is deterministic: an NVMe namespace if an
NVMe controller is present and usable, otherwise the ATA primary master. A
present but refused or failed NVMe controller prints `NVME UNAVAILABLE
<reason>` and the ATA probe runs as if it were absent. The sector size (512),
syscalls, counters, and error codes are the same for both.

`src/nvme.rs` finds the controller by PCI class 01/08/02 (`src/pci.rs`,
ports 0xcf8/0xcfc), maps BAR0 uncached, resets and enables it with one admin
and one I/O queue pair (16 entries) in static page-aligned kernel memory,
identifies the controller, the first active namespace, and its LBA format
(only 512-byte LBAs without metadata; anything else is refused by name),
and moves one to eight blocks per command through a static bounce page
(one page, so PRP1 alone describes it). Completion is
polled on the phase tag with INTx masked, falling back to `sti; hlt; cli`
per tick, bounded by 5000 ticks per command. `flush` is an NVMe FLUSH
waited to completion. A namespace is writable only when the boot option
`nvme-write=SERIAL` names its controller's serial; otherwise the driver
refuses writes and flushes and init receives a read-only block handle.
QEMU test ISOs name `absd`, the serial `make` and `scripts/durable-boot.sh`
give the scratch controller. Under QEMU an NVMe write completes after the
host `pwrite` returned and FLUSH becomes `fdatasync`, the same completion
semantics as the ATA path below.

`make nvme-test` makes four boots of three check ISOs over one 2 MiB
image:
`nvme-qualify-write nvme-write=absd` (fresh image reads zero, five known
LBAs written and read back: `NVME BLOCK OK`; one FLUSH completes and is
counted: `NVME FLUSH OK`; past-the-end LBAs refused by the kernel without a
command and by the device with status 0x0080: `NVME BOUNDS OK`), then
`scripts/nvme-image-check.py` checks the image file sector by sector, then
`nvme-qualify-verify` on a fresh boot (`NVME REINIT OK`, `NVME READ ONLY
OK`), a boot naming another serial (must stay read-only), and a 4 KiB-LBA
namespace (must be refused); the image hash must not change after the
first boot.

`src/ata.rs` speaks polled ATA PIO to the primary master (LBA28, 512-byte
sectors, `IDENTIFY`, `READ SECTORS`, `WRITE SECTORS`, `FLUSH CACHE`). It was
chosen over virtio-blk because it needs no PCI enumeration, DMA-visible
memory, virtqueues, or interrupt-driven completion plumbing; virtio is the
tripwire for a second device or a throughput need. Polling the status port in
a tight loop starves QEMU's main loop, which delivers completions, so every
poll pass ends in `sti; hlt; cli` and IRQ14 (unmasked only once a device is
found) wakes the driver; the ring-0 timer path only counts ticks, so the halt
inside a syscall cannot reschedule. The data phase uses one `rep insw` or
`rep outsw` per sector.

Completion semantics under QEMU: a `WRITE SECTORS` command completes only
after QEMU's host `write()` of that sector returned, so every acknowledged
sector survives an abrupt QEMU exit. `FLUSH CACHE` becomes a host
`fdatasync`; it is issued honestly and counted, but the tested failure model
is abrupt loss of all guest state with acknowledged sectors retained. Host
power loss, volatile device write caches, reordering, and sub-sector tearing
are not modelled by anything in this repository.

Userspace sees the device as `Object::Block` with read and write rights.
`block_info` reports `{sector_count, sector_bytes}`, `block_read` and
`block_write` move exactly one sector between the device and validated user
memory, `block_read_many`/`block_write_many` (43/44) move 1..=8 sectors in
one command on both backends (the write returns only after the device reports completion),
`block_flush` issues the device barrier, a device not selected writable is
granted without the write right, and every LBA is range-checked
against the probed size before the device is touched. `machine_stop(handle,
code)` (codes 16 through 63) needs a machine handle with the stop right;
QEMU then exits at once with status `4 * code + 3` and no later guest
instruction runs. The boot mode grants nothing.

`user/src/ledger.rs` is the append region the workloads actually need: bytes
map linearly onto sectors from LBA 0, every `append` reaches the device
before it returns, `flush` asks for the barrier, and the observed length
after a restart is one past the last nonzero byte on the whole device. The
image must therefore start zero-filled, and the rule is sound for the Pulse
frame format because every frame and commit marker ends in an ASCII digest.
It is not a filesystem: one region, no name, no seek for writers, no
truncation. The durable accounting line reports block requests, sleeps,
errors, and interrupts so a host harness can see that a flush was issued
before a stop.

In a durable boot init runs the selected workload as a worker process. A
worker that exits with status 97 is replaced, up to four worker
generations per boot; the replacement's step value is the old one plus
`DURABLE_REPLACEMENT_UNIT` (10^12), so it can tell it is a replacement. It
gets fresh pipes and a fresh cell and resumes from what the device holds
alone. Every generation is announced on the console (`DURABLE WORKER
GENERATION`, `DURABLE WORKER OUTCOME`) with its PID so a host can check that
PIDs and generations stay distinct and that no in-memory state carried over.

## Source map

- `src/block.rs`: backend selection, range and write checks, and the
  request/interrupt counters shared by both backends; `WRITES_BUILT` is
  false in the `block-read-only` build, which the NVMe submission path
  (an opcode allow-list) and the ATA driver also honour.
- `src/ata.rs`: the ATA PIO backend: probe, single- and multi-sector (1..=8) transfers, flush.
- `src/nvme.rs`, `src/pci.rs`: the polled NVMe backend and the minimal PCI
  access it needs (with one-owner-per-function claims); `src/nvme_check.rs`:
  the kernel-level NVMe check boots.
- `src/e1000.rs`, `src/e1000_ring.rs`, `src/syscalls/nic.rs`: the polled
  e1000 NIC, its host-tested descriptor rules, and the frame syscalls
  (docs/NETWORK.md); `scripts/nic-reflect.py` is `make net-test`'s harness.
- `src/framebuffer.rs`, `src/mmio.rs`, `fbcon/`: the framebuffer console,
  uncached device mappings, and the host-tested rasterizer and font
  (`scripts/font-8x13.py` regenerates the font).
- `scripts/laptop-boot.py`: the laptop-shaped QEMU machine and the
  screen-only console reader; `scripts/laptop-test.sh`,
  `scripts/laptop-matrix.sh`, and `scripts/physical-iso-gate.sh` drive it
  and the physical ISO's safety gate.
- `src/main.rs`: boot sequence, hardware setup, page/heap demonstrations,
  IDT/TSS installation, panic reporting, and QEMU exit.
- `src/sched.rs`: process runtime: the global tables and counters, spawn
  and load, context switching, bounded stack growth, sleeping and the idle loop, terminal
  disposition and reaping, and ring-3 fault handling.
- `src/syscalls.rs`: the `int 0x80` dispatcher and every handler: handles
  and objects, memory, pipes, console I/O, cells, and waits, plus the
  wake-up routines for pipes, console, and cells.
- `src/suite.rs`: how a boot ends: the counter and reclamation evaluation
  for the default suite, and the shell session check.
- `src/vm.rs`: the global frame allocator instance, user address-space
  construction, page mapping, translation, and teardown.
- `src/serial.rs`: COM1 output helpers, a `core::fmt::Write` sink, and the
  256-byte input ring filled by the COM1 interrupt.
- `src/boot.S`: Multiboot2 header and long-mode entry, boot GDT/page tables and
  stacks, exception/interrupt/syscall stubs, the kernel-context trampoline
  used for terminal cleanup, context restore, and `iretq`.
- `src/arch.rs`: GDT/TSS selectors and descriptor encodings.
- `src/memory.rs`: frame ownership table/allocator with free and reuse,
  page-table value types, and the temporary `TinyHeap` allocator.
- `src/process.rs`: process/task/address-space records, lifecycle states, the
  FXSAVE image, and the slot-based process table with wait/child queries.
- `src/user_memory.rs`: user page-table walk plus bounded copy helpers.
- `src/elf.rs`: deliberately small static ELF64 parser and load-segment checks,
  reading through an `ImageSource` (a catalog slice, or the caller's memory
  for `spawn_image`).
- `src/user_program.rs`: the embedded program catalog, asserted to match
  `absd_abi::program`.
- `abi/` (`absd-abi`): syscall numbers and errors, saved-frame offsets, the
  `wait` outcome record encoding, the fixed user virtual layout, and the
  program catalog order. The kernel re-exports it as `layout`, `program`,
  and `syscall`; the user crate depends on it directly.
- `user/` (`absd-user`): `src/lib.rs` has the `int 0x80` wrappers, the
  `entry!`/`multi_entry!` macros, panic handler, and libc-free memory shims;
  `src/bin/` contains 49 program sources (44 in the catalog); `linker.ld`
  places images in the user window and captures the large-code-model `.l*`
  sections.
- `build.rs` and `scripts/build-user.sh`: run a nested `cargo build` of
  `absd-user` (host target, static, non-PIE, large code model, no libc)
  under `OUT_DIR` and make each ELF available to the kernel build.
- `Makefile`: reproducible build, ISO, smoke, fault, and debug entry points.
- `docs/USERSPACE.md`: concise ELF and userspace ABI reference.
- `docs/PROCESS-STARTUP.md`: the process startup ABI: `spawn_image`, the
  startup vector and record (argv, environment, working directory, roles),
  and what the Rust platform's `std::process` does with them.
- `docs/TERMINOLOGY.md`: canonical terms, the layering rule, and retained
  names with their preferred meaning.

## Current syscall ABI

This is a **provisional bring-up ABI**, not a compatibility promise.

Software enters through the DPL-3 interrupt gate at vector `0x80`. `RAX` holds
the syscall number; `RDI`, `RSI`, and `RDX` hold arguments 0–2. The signed
result is returned in `RAX`; negative errors use Linux-like values solely as a
convenient bring-up convention.

| Number | Name | Arguments | Result and current semantics |
|---:|---|---|---|
| 1 | `write` | `RDI=console or pipe handle`, `RSI=user address`, `RDX=length` | Requires the write right and dispatches on the object. Console: writes 1–256 validated user bytes to COM1 and returns the length. Pipe: appends up to the free space (partial writes allowed), blocks (`wait_pipe`) while the pipe is full and a reader remains, and returns `-32` once no reader is left. |
| 2 | `yield` | none | Returns zero when the process is next resumed; immediately invokes the same round-robin selector used by preemption. |
| 3 | `exit` | `RDI=status` | Records the low signed 32-bit status, marks the process exited, releases its frames, and never returns to it. |
| 4 | `getpid` | none | Returns the process's stable PID. |
| 5 | `spawn` | `RDI=program index, optionally with SPAWN_CONSOLE (bit 32) and SPAWN_NO_SPAWN (bit 33)`, `RSI=handle to hand over or 0`, `RDX=argument word` | Reserves a handle slot, resolves a non-process handed-over handle, loads the catalog program into a new address space with the caller as parent, duplicates that handle into the child, and returns a process handle carrying wait and kill rights. The default console derives from the parent's held console rights and never exceeds them; no held console means `RDI=0`. Process handles cannot be transferred because genealogy and reaping remain parent-local. With `SPAWN_CONSOLE` the handle must be a writable console, or a pipe end holding the write right and not the read right. Failures occur before publication and release partial resources. |
| 6 | `wait` | `RDI=child handle or 0 for any`, `RSI=user address of a 32-byte record`, `RDX=timeout ticks or 0` | Resolves the handle to a child PID, blocks (`Waiting`, with `wake_at` set for a timeout) until a matching child is terminal or the deadline passes (`-110`), writes `{kind, status or vector, fault address, fault error}`, closes the caller's handles to that child, releases the child's slot, and returns the reaped PID. `-14` if the record is not writable user memory (checked without writing); `-9`/`-1` for a bad handle or missing right; `-10` if the caller has no matching child. The PID identifies the outcome but is not a handle. |
| 7 | `map` | `RDI=page count` | Maps 1–64 zeroed, user/writable/NX pages at the lowest free run of the caller's heap window and returns the address. `-22` for a bad count, `-12` if the window or frame pool is exhausted; a partial mapping is rolled back. |
| 8 | `unmap` | `RDI=address`, `RSI=page count` | Returns mapped heap pages to the frame pool and invalidates their TLB entries. The whole range is validated first; `-22` leaves the address space untouched. |
| 9 | `close` | `RDI=handle` | Releases the handle slot; the value never resolves again. Closing a process handle leaves the child alive and reapable by `wait(0)`; closing the last handle to a cell frees it. |
| 10 | `cell_create` | `RDI=initial value` | Reserves a handle slot, allocates a cell at version 0 in the kernel table, and returns a handle with read and write rights. `-24` if the handle table is full, `-12` if the cell table is full. |
| 11 | `cell_read` | `RDI=cell handle`, `RSI=user address of a 16-byte record` | Writes `{version, value}`. Requires the read right. |
| 12 | `cell_transition` | `RDI=cell handle`, `RSI=expected version`, `RDX=new value` | If the cell is at `expected`, stores the value, advances the version by one, and returns the new version; otherwise returns `-116` and changes nothing. Requires the write right. |
| 13 | `duplicate` | `RDI=handle`, `RSI=rights` | Issues a second handle to the same object holding only `rights`, which must be a subset of the original's and of the known rights (`-1` otherwise, `-24` if the table is full). A duplicated cell handle takes its own reference. |
| 14 | `cell_wait` | `RDI=cell handle`, `RSI=version seen`, `RDX=timeout ticks or 0` | Returns the current version at once if it differs from `RSI`; otherwise marks the process `Waiting` on that cell (`wait_cell`, optional `wake_at`) and switches away. Every successful `cell_transition` wakes all processes waiting on that cell with the new version in `RAX`; a deadline wakes with `-110`. Requires the read right; the waiter's handle keeps the cell alive. |
| 15 | `read` | `RDI=console or pipe handle`, `RSI=user address`, `RDX=length` | Requires the read right and dispatches on the object. Pipe: moves up to `min(length, available, 256)` bytes into validated user memory, blocks (`WaitKind::Pipe`) while empty and a writer remains, returns 0 when empty with no writer. Console: hands over banked serial input, or blocks (`WaitKind::Console`) until a byte arrives. |
| 16 | `pipe_create` | none | Reserves a handle slot, allocates a pipe, and returns a handle with read and write rights. `-24` or `-12` when a table is full. |
| 17 | `time` | none | The PIT tick counter (`timer_ticks`, ~1 kHz) since boot. |
| 18 | `sleep` | `RDI=ticks` | Zero ticks yields. Otherwise marks the process `Waiting` (`WaitKind::Sleep`, `wake_at = now + ticks + 1` so at least `ticks` full ticks pass; a value too large to ever arrive means no deadline) and switches away; returns 0 once woken. |
| 19 | `info` | `RDI=process handle or 0 for self`, `RSI=user address of a 32-byte record` | Requires the wait right and writes `{pid, parent, program index, state}` for a child named by handle; zero names the caller. State is 1 while runnable, 2 once terminal and unreaped, and 3 while blocked/waiting. |
| 21 | `transfer` | `RDI=pipe or console handle`, `RSI=user address of a 24-byte record {address, length, timeout}`, `RDX=direction (0 read, 1 write)` | Copies the record in, then runs exactly the `read` or `write` path with `wake_at` set from the timeout; a deadline wakes the blocked transfer with `-110` and nothing moved. |
| 20 | `kill` | `RDI=child handle` | Requires the kill right and `has_child`. A live child is marked `Killed`, its wait state dropped, and its resources are released; the outcome remains for a wait-right handle to collect. Idempotent on an already terminal child; `-9` once reaped. |
| 22 | `spawn_many_copy` | `RDI=program index`, `RSI=user pointer to count records {source, rights, flags}`, `RDX=count` | Validates up to 64 descriptors, rejects process sources, copies each remaining source with narrowed rights, permits duplicates, and optionally replaces the console. The returned process handle has wait and kill rights. The child stays `Created` until that handle is installed; every failure rolls back handles, references, frames, slot, and PID. |
| 23 | — | — | Unassigned; returns `-38`. |
| 24 | `block_info` | `RDI=block handle`, `RSI=user address of a 16-byte record` | Requires the read right and writes `{sector_count, sector_bytes}`. `-9` for a non-block handle; `-5` if no device was probed. |
| 25 | `block_read` | `RDI=block handle`, `RSI=LBA`, `RDX=user address of 512 bytes` | Requires the read right; validates the user range before touching the device; `-22` for an LBA past the device; `-5` for a device error or timeout. |
| 26 | `block_write` | `RDI=block handle`, `RSI=LBA`, `RDX=user address of 512 bytes` | Requires the write right; copies the sector in first, then returns only after the device reports the write complete. Same errors as `block_read`. |
| 27 | `block_flush` | `RDI=block handle` | Requires the write right; issues the device flush (ATA `FLUSH CACHE`, NVMe `FLUSH`) and returns after it completes. |
| 28 | — | — | Retired (`stop(code)`, gated on the boot mode, not a handle); returns `-38`. See 37. |
| 29 | `boot_id` | `RDI=user address of 16 bytes` | Writes this boot's 16-byte identity, drawn once from RDRAND and the same for every process of the boot; `-38` without RDRAND, `-14` for a bad address. |
| 30 | `wall_clock` | none | Returns seconds since the Unix epoch read from the CMOS RTC (whole seconds, declared UTC); `-5` when no stable, valid reading can be taken. The kernel never substitutes a value. |
| 31 | `spawn_image` | `RDI=user pointer to a 32-byte {image, image_bytes, handles, handle_count} record`, `RSI=flags (SPAWN_NO_SPAWN only)`, `RDX=0` | `spawn_many_copy` for a static ELF64 image (at most 32 MiB) in the caller's memory: requires the spawn right, validates the record, the image range, and every descriptor before claiming a slot, loads through the catalog's loader straight from the caller's page tables, and rolls every failure back. The child is multi-start and `info` reports program index `0xffff_ffff`. `-8` for an image the loader refuses; see docs/PROCESS-STARTUP.md for the complete order of refusals. |
| 32 | `nic_info` | `RDI=nic handle`, `RSI=user address of a 64-byte record` | Read right; `{mac, flags, rx_frames, rx_refused, rx_missed, tx_frames, tx_refused, tx_errors}` (docs/NETWORK.md). |
| 33 | `nic_send` | `RDI=nic handle`, `RSI=frame`, `RDX=length 14..=1514` | Write right; returns 0 once the device reports the frame sent. `-22` bad length (nothing reaches the device), `-5` once the NIC is disabled. |
| 34 | `nic_receive` | `RDI=nic handle`, `RSI=1514-byte buffer`, `RDX=timeout ticks` | Read right; the next whole, error-free frame's length. Timeout 0 polls (`-11` when empty); otherwise blocks (`WaitKind::Nic`) at most that long (`-110`). `-5` once disabled. |
| 35 | `frame_stats` | `RDI=address of a 32-byte record` | No handle, no rights: stores the physical frame allocator's counts (free, allocated, limit, frame bytes) as one consistent state taken with interrupts disabled. `-14` for an unwritable record. Whole-machine counts visible to any process (audit finding B3, documented ambient observation). |
| 36 | `pipe_info` | `RDI=pipe handle`, `RSI=address of the record` | Any handle to the pipe, whatever its rights: how full the pipe is and how many handles can read and write it, without moving a byte or blocking. `-9` stale or not a pipe, `-14` unwritable record. |
| 37 | `machine_stop` | `RDI=machine handle`, `RSI=code (16..=63)` | Requires a machine handle with `MACHINE_RIGHT_STOP` (`-9` without one, `-1` without the right, each logged `MACHINE REQUEST REFUSED pid=P error=E`); `-22` for a code outside the range. Prints `MACHINE STOP code=N` and exits QEMU immediately with status `4 * code + 3`. |
| 38 | `machine_restart` | `RDI=machine handle` | Requires `MACHINE_RIGHT_RESTART`; arms a reset for the end of the boot (after init exits and the end-of-boot accounting passes, `MACHINE RESTART`; a failed accounting halts instead). Returns 0. |
| 39 | `rt_next` | none | Completes the current RT instance and waits for its next phase release; refused unless the kernel configuration admitted the caller; grants no priority. |
| 40 | `machine_recover` | `RDI=machine handle` | Requires `MACHINE_RIGHT_RECOVER` and nothing else (no PID or boot-mode check; `-9`/`-1` refusals logged like 37 and 38). Prints the kernel census (`SERVED RECOVERY CENSUS`, `SERVED RECOVERY PROCESS`) and `MACHINE RECOVER RESET pid=P`, then resets at once: no end-of-boot accounting, no process drain. Qualified by `make machine-recover-test`. |
| 41 | `resource_census` | `RDI=address of a 40-byte record` | No handle, no rights: one snapshot of occupied process slots (including Created/terminal), live handle entries, live pipes, live cells, and tracked allocated 4 KiB frames; instantaneous counts, no PIDs or event totals. `-14` for an unwritable record. Whole-kernel counts visible to any process (audit finding B3). |
| 42 | `abi_version` | none (ignored) | Returns `absd_abi::KERNEL_ABI` (1), the syscall ABI generation. No handle, no rights, no state: a constant compiled into the kernel. A kernel older than the syscall answers `-38`. This is the one generation number the platform's hand-copied syscall table must equal: its runtime compiles in the same value and refuses to start with status 103 and `ABI REFUSED kernel=<n> required=<m>` when the kernel answers anything else (including `-38`). `KERNEL_ABI` increments when a change would make a program built against the previous `absd-abi` misbehave; adding a syscall old programs never call does not. Init asserts it at boot (`ABI VERSION OK n=1`, required by `make smoke`). |
| 43 | `block_read_many` | `RDI=block handle`, `RSI=first sector`, `RDX=count 1..=8`, `R10=buffer` | Read right; one command for the whole run, validated before the device is touched. Zero means every sector completed; on an error nothing is copied out. `-22` for zero sectors, more than the bound, or a span past the device; otherwise `block_read`'s errors; `-38` from an older kernel. |
| 44 | `block_write_many` | as 43 | Write right; a failed write has put an indeterminate subset of its sectors on the device (a leading run with ATA PIO and QEMU's NVMe model; the NVMe specification does not promise one), so only a read or a fresh scan resolves it. Completion is acceptance, not durability: `block_flush` remains the only barrier. |

Errors currently include `-1` (missing right), `-2`, `-5` (block device error), `-8` (`spawn_image`: not an image the loader accepts), `-9` (unknown, stale,
or wrong-kind handle), `-10` (no such child), `-11` (no process slot), `-12`,
`-14` (invalid user range), `-22` (invalid length/argument), `-24` (handle
table full), `-32` (pipe has no reader), `-38` (unknown syscall), `-75` (PID space exhausted), `-110`
(timeout), and `-116` (stale transition).

The assembly stubs save all 15 general-purpose registers in this order as
viewed from the resulting frame: `R15, R14, R13, R12, RBP, RBX, R11, R10, R9,
R8, RDI, RSI, RDX, RCX, RAX`, followed by the CPU's `RIP, CS, RFLAGS, RSP, SS`
privilege-transition frame. Syscalls preserve that frame except for the stated
`RAX` result or a scheduling transition.

## Handle model

`src/handle.rs` gives each process a 64-slot `HandleTable` seeded by its
PID. A handle value is `(tag << 8) | index`; the tag comes from a per-table
counter, so every issue of a slot has a fresh value and a stale value
(closed or reaped) fails. Lookup happens only in the caller's own table, so
a value taken from another process can at most name one of the caller's
own objects, never the other process's. The PID-derived tag seed is diagnostic
convenience, not a security boundary. Objects today are
`Console` (the kernel grants init read/write; later default grants derive from
the parent's held console rights, and its value reaches the
program in `RDI`), `Process(pid)` (issued by `spawn` with wait and kill rights),
`Cell(id)`, and `Pipe(id)`. Every
syscall that takes a handle resolves it in the caller's table, checks the
object kind (`-9` on mismatch), then the right (`-1`). Handles are
unforgeable per-process references with rights; there is no general
capability system beyond that. Per-kind masks reject rights that do
not describe that object, and every live cell or pipe handle owns exactly one
counted reference taken and released with the same rights. Legacy `spawn` copies one handle;
`spawn_many_copy` copies an ordered batch with per-record rights narrowing,
legal duplicate non-process sources, and at most one console replacement.
Process handles may be narrowed locally into wait-only or kill-only views but
are not transferable. The wait right is targeting authority for a named
handle; wait-any follows parentage and does not require a
wait-capable handle. The parent
retains its sources. The pipe+cell composition proves a child can receive a
write-only cell and pipe console together while forbidden reads fail
(`CHILD CONSOLE RIGHTS OK`, `HANDLE TRANSFER OK`, `PIPE CELL COMPOSE OK`).
There is no global object graph.

The smoke suite repeatedly closes parent sources while children retain cell
and pipe references, checks EOF and broken-pipe transitions around exit/kill
and reap (`HANDLE LIFETIME STRESS OK`), and proves full process, handle, cell,
and pipe tables refuse without overwrite and become reusable after teardown
(`PROCESS CAPACITY OK`, `HANDLE CAPACITY OK`, `OBJECT CAPACITY OK`).
Orphan adoption by PID 1 consumes no handle slot even while its table is full;
adoption does not grant info or kill authority.

`src/object.rs` holds the kernel cell table (32 slots) and pipe table (16
slots, 1 KiB ring each). A pipe counts its handles by right: `retain` and
`release` take the handle's rights, so the pipe knows its reader and
writer counts; the last writer leaving wakes blocked readers with 0 and the
last reader leaving wakes blocked writers with `-32`. A blocked pipe
transfer is recorded in the process's `wait_pipe` and completed by the
kernel, against the waiter's own memory, from whichever syscall changes
the pipe (`wake_pipe_waiters`). `try_pipe_transfer` is the single place
that moves bytes for both the direct and the deferred path.

`src/object.rs` also holds the cell table. A cell is
reference counted by handles; `close` or process termination (which drains
the handle table) releases references, and the last release frees the slot
and bumps its slot generation so a stale `CellId` cannot alias a later cell.
`transition(id, expected, value)` is the conditional state transition: it
advances the version only from the version the caller names. The end-of-
suite check requires zero live cells.

## Current privilege transition

The boot GDT contains kernel code/data selectors plus user code selector
`0x2b` and user data/stack selector `0x33`, both with RPL/DPL 3. TSS selector
`0x18` is loaded with `ltr`. TSS `RSP0` is updated to the selected task's
32 KiB kernel-stack top before entering or resuming that task. TSS IST1
points at a separate 16 KiB double-fault stack.

Initial ring-3 entry and every resume are built as a 20-word saved frame and
completed by `iretq`. The `int 0x80` interrupt gate is present at DPL 3 and
enters on the current process's TSS `RSP0` kernel stack. Ordinary exception and
timer gates remain DPL 0. These are interrupt gates, so interrupt delivery is
disabled during the entry path until restored by `iretq`.

## Current virtual-memory layout

| Virtual range/address | Current use | Properties |
|---|---|---|
| `0x0010_0000` and upward | kernel image and boot-time data | identity-mapped, supervisor-only |
| first 1 GiB (PML4 entry 0) | boot identity mapping, shared by every address space | 2 MiB supervisor pages; never modified by user mappings |
| `0x0000_0080_0000_0000` + 1 GiB (PML4 entry 1) | the user region; one process-owned PDPT and page directory | everything a process maps lives here |
| `0x0000_0080_0040_0000..0x0000_0080_0400_0000` | accepted ELF `PT_LOAD` image window | per-process 4 KiB user pages; writable and NX follow segment flags |
| `0x0000_0080_0800_0000..+0x400000` | reserved grow-down user stack | 1024 pages (4 MiB) maximum; top two initially mapped user/writable/NX; permanent guard immediately below the base |
| `0x0000_0080_1000_0000..+32 MiB` | anonymous heap window | `map`/`unmap` pages; at most sixteen page tables |
| `0x2000_0000` | boot page-map roundtrip | temporary kernel test mapping, removed and original huge mapping restored |
| `0x2020_0000` | temporary heap page | temporary kernel mapping, removed and original huge mapping restored |
| `0x0000_8000_0000_0000` | user-pointer upper bound | addresses at or above this value are rejected by copy helpers |

`abi/src/layout.rs` defines these values and `user/linker.ld` matches them. The
user region sits in PML4 entry 1 so user page tables can never shadow the
identity map the kernel uses to reach physical frames, and so "kernel-global
versus process-owned" is decided by PML4 index alone. User processes receive
distinct roots and backing frames but use the same virtual image and stack
layout.

## Current task/context model

`PROCESSES` (`src/sched.rs`) is a 16-slot table. PIDs are monotonic within a
boot and slots are reused; the one exception is `rewind_newest_pid`, which
hands back the newest PID of a process that never ran or that the kernel's own
boot-time self-tests spawned and killed (`sched::exhaustion_test` mints and
rewinds PID 1 before init, so sealed logs show `SPAWN OK pid=1` twice;
`smp_startup` rewinds its startup actors). No handle to a rewound process can
exist (architecture audit 2026-10-02, finding A4; the allocation comment now
records the exception, and self-test behaviour is unchanged). Each live entry owns a PID, parent PID, program index,
address-space record, a 32 KiB contiguous kernel stack, a 1024-page reserved
user stack with its lowest mapped page, a 20-word saved frame, an FXSAVE image, a handle table, lifecycle
state, and (while `Waiting`) either the awaited child and record address
or the awaited cell and version. Lifecycle: `Created -> Runnable -> Running
-> (Waiting -> Runnable)* -> Exited | Faulted | Killed -> Empty`. The kernel spawns
only `init` (PID 1, parent 0); everything else is spawned by userspace.

The PIT runs at approximately 1 kHz. On a timer interrupt from ring 3, the stub
saves every general-purpose register, and the CPU has already saved the five
`iretq` words. The stub then executes `fxsave` into `user_fpu_scratch`
before any Rust code runs, and every return to ring 3 ends with `fxrstor`
from that area; the scheduler copies the 512-byte image into and out of the
process's `Task::fpu`, so x87/MXCSR/XMM state is preserved across syscalls,
preemption, and blocking. A fresh process starts with FCW `0x37f` and MXCSR
`0x1f80`. The `fpu` user program verifies this with two interleaved SSE users. Rust copies all 20 words into the current task, chooses the next
runnable entry round-robin, copies that entry's context into the active kernel
frame, updates TSS `RSP0`, returns the next CR3, and the stub restores it and
executes `iretq`. A voluntary yield uses the same selection logic.

Blocking and time: every `Waiting` entry records a `WaitKind` (child,
cell, pipe, console, or sleep) and an optional `wake_at` tick. `wake_sleepers`
runs on every scheduling decision and in the idle loop; a sleep whose
deadline passed returns 0 and any other timed wait returns `-110`. When
no process is runnable the scheduler enters `idle_loop` on the kernel
entry stack (`enter_kernel_idle` in `boot.S`), which halts with
interrupts enabled until an interrupt, wakes what it can, and resumes the
first runnable process; if no waiting process has a deadline or is
reading the console, nothing can ever wake and the boot ends. Pipe and
untimed waits cannot be cancelled.

Boot modes select validation policy and the startup word passed to PID 1;
they do not select a kernel-spawned application. Init runs the suite directly
or launches shell/fuzz with ordinary `spawn`, requires a normal status-zero
outcome, drains adopted descendants with identified timed wait-any, and exits.
The kernel then requires init status 0, complete reclamation, and mode-specific
checks such as a blocked console read.

`exit` and a ring-3 exception both mark the entry terminal and then jump to
`reap_current_and_schedule` on the dedicated kernel entry stack with the boot
CR3 loaded (`enter_kernel_context_and_reap` / `exception_common` in
`boot.S`), so the process's own kernel stack and page tables are never freed
while in use. It calls `sched::terminate`, which returns all frames and drains
the complete handle table and its object authority before any parent
notification. It then reparents both live and terminal children to a live
userspace PID 1 when available (otherwise terminal children are released and
live ones are reparented to the kernel), then either releases the slot immediately
(kernel-owned parent), wakes a parent blocked in `wait` on it (delivering the
outcome record and reaped PID in `RAX`), or leaves the metadata for a
later `wait`. `kill` calls the same `terminate` for a child from the
parent's syscall context, which is safe because the child is not running.
`terminate` deliberately avoids by-value `Process` copies: the debug build's
stack frames are large, and a kernel-stack overflow there once corrupted
the frames below it. The smoke suite ends through the QEMU debug-exit
device when no runnable process remains; it passes only if `init` exited 0,
every spawn was reaped, the counters match, and the allocated-frame count is
exactly the pre-`init` baseline.

## Current memory model

`FrameAllocator` (`src/memory.rs`) keeps one 32-bit tag per tracked 4 KiB
frame: a built-in table for 256 MiB (`TRACKED_PHYSICAL_LIMIT`, what ARM64 and
host tests use), or on x86 a boot-placed table sized to the highest usable
frame up to the 64 GiB bound (`PHYSICAL_TRACKING_BOUND`;
docs/x86-whole-ram-20261015/RESULT.md). Each tag is unavailable, free, or allocated to
`Kernel`, `PageTable(pid)`, `UserPage(pid)`, or `KernelStack(pid)`. Type-1
Multiboot2 ranges become free frames; low memory below 1 MiB, the kernel
image, and the Multiboot information block are reserved before any
allocation. `allocate`/`allocate_contiguous` scan from a hint; `free` requires
the caller to name the owner it believes holds the frame and rejects free,
untracked, or differently owned frames, so double frees and ownership
confusion surface immediately. An optional quota (`set_quota`) refuses
allocations above a ceiling; the boot uses it in `sched::exhaustion_test`
to make `spawn` fail at every allocation of a load in turn (quota one
frame larger each time until the load succeeds) and prove that each
failure returns `NoMemory`, gives back every frame, and leaves no process
slot or PID behind, and that the one success reclaims when ended
(`SPAWN EXHAUSTION frames_per_process=N`, then `SPAWN EXHAUSTION OK`). Counters expose allocated, free, and peak
frames and the number of frames owned by a PID. Usable RAM above the bound,
and the sub-2 MiB edges of usable rows above 1 GiB, are clipped; the boot
discloses it on `FRAMES TRACKED usable=.. limit=.. clipped=..`. The instance
is a single global in `src/vm.rs`.

Boot assembly identity-maps the first GiB with 2 MiB supervisor pages;
`src/whole_ram.rs` adds supervisor, no-execute 2 MiB identity mappings of
every tracked page above it in the same boot PDPT, so every tracked frame is
reachable at its physical address from every CR3. Each
user address space (`vm::create`) allocates a PML4 whose entry 0 points at
the shared boot PDPT (supervisor only, never owned) and whose entry 1 leads to
a process-owned PDPT and page directory; user page tables are installed on
demand for ELF and stack pages (at most eight). The kernel reaches page-table
and backing frames through the identity map. ELF file bytes are copied
eagerly and the pre-zeroed backing frames provide BSS zero-fill.
`vm::destroy` walks the owned page tables and returns every present user
frame, each page table, the directory, the PDPT, and the root; it works on
partially built spaces so failed loads reclaim cleanly. It must not run on
the active CR3.

The two boot demonstrations map a temporary page, invalidate it with
`invlpg`, restore the original huge-page PDE, and free their frames. CR3
writes provide address-space switching and the associated non-global TLB
flush. The `TinyHeap` is only a one-page boot-time allocator test; it is not a
general kernel allocator and its mapping is removed afterward.

## Exception and fault semantics

- Every CPU exception vector 0–31 has a gate (`exception_stub_table` in
  `boot.S`); vectors 3, 8, and 14 use dedicated stubs, the rest share
  `exception_common`. Vectors without a hardware error code push a zero so
  the frame is always `[vector][error][RIP][CS][RFLAGS][RSP][SS]`.
- Breakpoint vector 3 (DPL 0) sets a test flag and returns with `iretq`; boot
  requires the flag before continuing. A ring-3 `int3` therefore raises #GP.
- A ring-3 page fault resumes only for bounded stack growth: error code
  exactly `0x6`, the page directly below the mapped stack, and saved RSP
  in that page or within the 128-byte SysV red zone above the fault. The stub
  preserves every GPR and the FPU/XMM image, maps one zeroed owned page,
  invalidates it, and retries. Allocation failure, the permanent guard below
  the 1024-page reservation, and every other page fault use normal isolation;
  teardown reclaims all grown pages. `stack-grow` preserves R10/XMM15 across
  nine resumable faults and `overflow` faults after all 1022 possible
  growths (`USER STACK GROW OK`, `STACK GROW pages=1031`).
  `stack-jump` separately writes two pages below the lowest mapped page without
  moving RSP; its exact `0x6` fault proves skipped pages are not demand-mapped
  (`STACK GROW ISOLATION OK`).
- Any other ring-3 exception switches to the boot CR3 and the kernel
  entry stack and calls `user_exception(vector, error, rip)`, which records
  the vector, CR2 (page faults) or the faulting RIP (everything else), and
  the error code, marks the process `Faulted`, prints `USER FAULT pid=N
  vector=V address=... error=...`, releases its frames, notifies or defers to
  the parent, and schedules the next runnable process. `init` checks a page
  fault from `fault` (vector 14, error bits `0x7`), #UD from `trap`
  (vector 6), and #GP from `privileged` (vector 13). Three `shared`
  children race on one cell handed over at spawn and its final state is
  exact regardless of interleaving.
- Page-fault vector 14 in ring 0 recovers only while `kernel_fault_expected`
  is armed, which the `fault-test` boot does immediately before its
  controlled fault (`PAGE FAULT OK`). Any other ring-0 exception, and a
  double fault (vector 8, IST1), calls `kernel_exception_report` on its own
  8 KiB report stack, which prints `KERNEL FAULT vector=... error=...
  rip=... cr2=...` and exits QEMU with status 2; a fault during the report
  exits immediately instead of re-entering. `make kernel-fault-test` proves
  that path.
- Vector 36 (COM1, IRQ4) is `serial_stub`: it saves the caller-clobbered
  registers and its own FXSAVE image, banks every byte the UART holds into
  the input ring (`serial::drain_input`), acknowledges the PIC, and
  returns. It never schedules; `wake_console_readers` completes the first
  blocked console read at the next scheduling decision or from the idle
  loop, which `hlt` leaves on the interrupt. IRQ0 and IRQ4 are the only
  unmasked lines.
- Vectors 39 and 47 (spurious PIC interrupts) return immediately without an
  EOI. NMI (vector 2) and machine check (vector 18) take the ordinary
  exception path: in ring 3 they terminate the running process even though
  it did not cause them, in ring 0 they are reported as kernel faults. That
  is a bring-up policy, not a design.

A non-growable user fault is therefore a process failure with full resource
reclamation and a parent-visible outcome that names the exception. Init has one
bounded supervision experiment, but there is no general restart service.
Kernel panics print their message and location before exiting QEMU with status
1.

## Known hardcoded/demo assumptions

- a 44-entry embedded program catalog addressed by index, and a 16-slot
  process table;
- fixed ELF image window, user-stack address, stack sizes, and a 64 GiB
  tracked-physical-memory bound on x86 (256 MiB on ARM64);
- fixed-capacity arrays for processes, ELF segments, and page tables;
- seven object kinds (console, child process, cell, pipe, block device, NIC, machine) in a
  fixed 64-slot handle table, a 32-slot cell table, and a 48-slot pipe table;
  non-process handle transfer only at spawn;
- statically linked Rust user programs embedded into the kernel build, built
  for the host target with the large code model because the user window sits
  above 4 GiB and no bare-metal `rust-std` is installed;
- identity-mapped physical memory and a global mutable process table and
  frame allocator; default boots are UP, while the opt-in kernel-only AP
  fixture serializes shared table/allocator access with the big kernel
  lock and checks the actual CPU owner;
- an eager image loader with no general demand paging or shared pages; bounded
  user-stack growth is the sole demand-mapped exception;
- O(frames) allocator scans; correctness and visibility over speed;
- PIT/PIC scheduling and QEMU debug-exit as the only completion environment
  (`halt-on-exit` halts instead, for machines without the device);
- raw console input with a 256-byte ring that drops on overflow, and no
  echo or line discipline; the one global COM1 endpoint is intentional
  bring-up ambient authority, not a mature object identity/lifetime model;
- the smoke suite's expected counters are hardcoded in `finish_process_suite`.

The bounded RT scheduler closure is `8bc81ef` (`docs/rt-class/README.md`).
The UP-only CPU-local handoff preparation was committed as `a8f2691`
(record (development record, not in a source release)); it moved transition, return,
termination, and idle off an outgoing task's stack/CR3/TSS before runnable
publication or reclamation. BSP CPU-local state remains addressed directly
because ring-3 can reload GS and no swap/restore entry contract exists.

The subsequent kernel-only AP serialization and lifecycle lane (development record, not in a source release)
starts CPU 1 only for bounded CPL0 lock/stop fixtures. A big kernel lock
serializes shared process/object mutations; ATA/NVMe/e1000 interruptible
waits release it with a pinned, exact process claim and validate on return.
BSP PIT/PIC/COM1/device ownership and CPU0-only RT eligibility remain.
An AP exact-token stop is acknowledged only after its stack, CR3, TSS, and
handler references have departed; a terminal `wait` remains a total drain
and reclamation fence. The real return guard still refuses ordinary and RT
AP userspace. The default boot remains UP; the opt-in two-vCPU local VM
does not qualify ordinary multicore process execution, migration, AP
preemption, or a production stop-latency bound. The file-server BIND
keeper-departure fix `b4eda83` subsequently joined accepted platform
`e70af640`; that release also contains the distinct settlement-accounting
fix `b0cb9da`. The earlier isolated-lane statement describes its checkpoint.
The exact-kernel selector subsequently supports the accepted successor pair
`fcfbab9` / `c54dc90`; its separate paired-release receipt is linked above.
Selector support alone establishes no acceptance.

The closed multicore SMP lane (development record, not in a source release) is now
integrated as guarded regression infrastructure; its
integration record (development record, not in a source release) identifies
103 development-host KVM captures, 2,417 emitted receipt controls and 131 host tests,
canonical/FPU/strict RT regressions and 18 guarded KVM controls. Production AP
userspace remains refused and default boot remains UP. Queue ownership,
migration/stealing, lifecycle fences and CPU0↔CPU1 FXSAVE transfer are qualified
within those fixtures; scaling, a BKL split and AP guard removal remain unearned.
Integration repaired one preexisting exact-repeat stop race after AP departure,
with a deterministic original-ordering control; an RT negative-control selector
was adapted to optional idle diagnostics without weakening its checks. Failed
RT preparation and strict SMP ordinary-progress receipts remain recorded.
The closed common-path research (development record, not in a source release) is selectively
retained as protocol/model and offline receipt regression infrastructure.
`BKL_SPLIT_NOT_EARNED` and `SMP_SCALING_MIXED` describe its measured scope;
positive real-pipeline scaling against equally optimized UP remains unearned.
CPU-identity caching, observer hooks and benchmark polling changes are excluded.
The active successor lifetime-protocol and native-storage lanes stay isolated. Sealed `.1`
remains `fcfbab9` / `c54dc90`; this newer main is not release-pinned.

The subsequent served-boot survival lane (development record, not in a source release)
qualifies the UP FSD/SSH dependency and reset boundary, exact 300-session
reusable capacity, fixed-limit refusal and reuse, and timeout/source limits
in local VMs. Adopted live residue remains visible before the reset; the
machine transition is not an in-boot total reclamation fence. A served boot
combined with the controlled CPU 1 option refuses before AP startup.

The [usability roadmap](docs/USABILITY-ROADMAP.md) now places sustained
named-machine operation, install/update/rollback/recovery, and native
Constellation workloads ahead of further SMP work. Before removing the AP
userspace guard, measure a KVM UP performance/concurrency matrix and decide
whether the bottleneck justifies that step; native/KVM memory-order
qualification and an exact machine envelope remain prerequisites. RT
placement and governed admission stay separate later research tasks.

## Known limitations

- only a narrow static ELF64 `PT_LOAD` subset; no dynamic linking,
  relocations, TLS, or general binary ABI. The kernel never reads a file:
  filesystem execution is userspace reading an image and handing it to
  `spawn_image`; argv, environment, and working directory are the startup
  record's, interpreted by the platform runtime (docs/PROCESS-STARTUP.md);
- no generic file descriptors, IPC beyond pipes and cells, validated public syscall-buffer abstraction,
  or user-to-user memory operations;
- `spawn`/`spawn_many_copy` start only the embedded catalog, `spawn_image`
  only an image the caller already holds; no fork, no exec replacing a
  running image, no general service manager;
- no kernel heap; user memory is only the bounded grow-down stack and anonymous
  heap window (no shared/file backing or protection changes);
- one block device, one append region, no filesystem, no namespace, no
  checkpoint or compaction in the kernel (the filesystem is the platform's
  userspace `absd-fs`/`absd-fsd`); no kernel sockets (networking is one
  opt-in e1000 frame driver, TCP is the platform's `absd-net`); SMP only as
  guarded test fixtures with the default boot UP; no capability/object model
  beyond the handle table; the durability claim is bounded by the QEMU
  failure model described above.

## Native hardware preparation

`make physical-iso` builds `build/absd-physical.iso`, a hybrid BIOS+EFI
image whose kernel is built with the `block-read-only` cargo feature (in
`build/physical/target`): it submits no block write, flush, or NVMe
command other than Identify, Create I/O queue, and Read, whatever the
command line says (`BLOCK WRITES DISABLED: read-only build`; an
`nvme-write=` option prints `NVME WRITE OPTION IGNORED: read-only build`).
`make physical-iso-test` boots that exact file under SeaBIOS and OVMF with
a patterned NVMe namespace attached and requires the full screen to match
serial, the namespace to be identified read-only, and the image to be
unchanged. `make physical-iso-gate` adds the safety gate: the ISO's own
kernel and `grub.cfg` checked, then that kernel booted with
`nvme-write=<matching serial>` against NVMe and ATA scratch images with
QEMU device traces, requiring unchanged images and read-only command
traces (`PHYSICAL ISO GATE OK iso_sha256=... kernel_sha256=...`).
`docs/PHYSICAL-BOOT.md` is the first-boot checklist;
`docs/PHYSICAL-BOOT-PACKAGE.md` has the pins, the exact expected screen,
the failure table, and the USB and rollback instructions;
`docs/NATIVE-WRITE-EXPERIMENT.md` fixes the conditions for a later
scratch-device write (plan only). Physical boots have not been run.

Pinned build (docs/PHYSICAL-BOOT-PACKAGE.md, "Pins"): built at
`ac4322b`, read-only kernel ELF
SHA-256 `450665ba538ed9da780560753754df11558030a0ec995b06779d4ce62f2bb0ae`,
ISO SHA-256 `073467abffe2f01a06b817be460c1e729441c70fe52c110fa1f3326daac9b30f`
(`grub-mkrescue` output is not byte-reproducible; that file, kept read-only as
`physical/absd-physical-073467abffe2.iso`, is
the gated and laptop-tested one).

The physical survey ISO is a separate artifact with its own pin
(docs/hardware/HP-Z2-MINI-G3-FIRST-BOOT.md, first target the HP Z2 Mini
G3): `make survey-iso` puts the same read-only kernel behind a default
entry `survey halt-on-exit`, followed by the suite and postmortem entries.
The `survey` mode word reads CPUID (and one RDRAND draw), the Multiboot2
tags, and PCI configuration space, and ends on a summary sized to stay on
the screen (`PHYSICAL SURVEY COMPLETE`, `ABSD BOOT OK`, `SAFE TO POWER
OFF`); it diverges before the block probe and the `net` option, and
`survey::forbid` panics on any PCI configuration write, device claim, or
block probe while it runs. Per-function PCI detail goes to serial only as
`RECORD PCI ...` lines, which `scripts/framebuffer-check.py` leaves out of
its screen model. `make survey-gate` (scripts/survey-gate.sh) checks the
ISO's entries, boots the default entry under SeaBIOS and OVMF and an
edited `survey net nvme-write=absd` line with NVMe, e1000, and ATA
attached, and requires QEMU's device traces after the kernel's first line
to show writes only to the UART, PICs, PIT, and PCI address latch (a
`kernel-fault-test net` positive control shows the check seeing NVMe and
NIC initialization); then the laptop machine from the screen alone; then
`physical-iso-gate.sh` on the same ISO. Pinned build: kernel `913d338`,
ELF SHA-256 `875b7969e4fc740e69938ce3f8d7d945217e9e0c4e359c134a33ffaf2ad7a15f`,
ISO SHA-256 `9773e8b64ffeb97c22c3df9cbb58d83c86645894efc264854ca77d5844575e5d`,
kept read-only as
`physical/absd-physical-survey-v1-9773e8b64ffe.iso`.
Qualification label vocabulary: docs/hardware/QUALIFICATION.md.

`make laptop-test` checks a laptop-shaped QEMU machine
(`scripts/laptop-boot.py` profile `thinkpad`: `-nodefaults` q35, OVMF, the
ISO as a USB stick on xHCI, NVMe as the only disk, VGA, no serial port or
debug-exit device). All output is read from the screen: the host polls
screendumps, pausing the guest for each and running it in short slices
between them, decodes every cell against the X11 font,
merges screens into a transcript (gaps counted), and checks the final
screen pixel for pixel. It prints `FRAMEBUFFER ONLY BOOT OK`,
`NO SERIAL DEPENDENCY OK`, `TIMER PREEMPTION OK`, and `EFI NVME BOOT OK`
(write, flush, read back; fresh boot and warm reset verify read-only).
`ABSD_BLOCK_ATTACH=laptop scripts/durable-boot.sh` runs a durable ISO on
the same machine, with the screen transcript as its log. `make
laptop-matrix` varies one legacy assumption at a time; last results
(physical ISO default entry, OVMF unless noted):

| Variant | Outcome |
|---|---|
| base, SeaBIOS, AHCI CD-ROM boot (OVMF and SeaBIOS), `hpet=off`, `sata=off`, `smbus=off`, `i8042=off` + USB keyboard, `-cpu max`/`Skylake-Client-v4`/`EPYC-v4`, `-smp 4`, 128 MiB, 4 GiB, `bochs-display`, `virtio-vga`, two NVMe controllers | `ABSD BOOT OK`, 1143 lines, no gaps, screen exact, NVMe image unchanged; the first controller in PCI order is used |
| `pit=off`, `pic=off` | `TIMER FAILED ticks=0 (no PIT interrupts through the 8259 within the TSC bound)`, `ABSD HALT code=1` on screen: the tripwire fires as designed |
| `ramfb` | blind boot: the framebuffer is RAM below 1 GiB, `framebuffer: unavailable Map(InFirstGigabyte)` goes only to the (absent) serial port; the suite itself passes |
| NVMe with 4 KiB LBAs | `NVME UNAVAILABLE Refused(LbaFormat { lba_bytes: 4096, ... })`, `block: no device`, boot OK |
| no NVMe | `block: no device`, boot OK |

The real AG SQLite workload also runs on the laptop machine:
`ABSD_BLOCK_ATTACH=laptop scripts/fs-matrix.py --only store,crash,powercut`
(platform repository at `da6f125`, run read-only against this branch at
`1024beb`) passed all 187 boots with every transcript read from the screen
alone (`AG SQLITE STORE OK`, `AG SQLITE CRASH RECOVERY OK points=23`,
`AG SQLITE POWER CUT OK cuts=66`, `FS MATRIX OK boots=187`), each showing
`BLOCK BACKEND nvme access=read-write`. The `ag-sqlite.elf` used was built
in the `absd-rust-std-review-e` checkout (SHA-256 `21f7ba99...fcbf`), whose
source differs from `da6f125` only in Nightshift files.

Also learned: test ISOs without `insmod all_video` stop in GRUB under OVMF
(`error: no suitable video mode found`), so the NVMe and durable ISOs now
load it; HMP `system_reset` under `-no-reboot` is a shutdown. An isolated,
unpromoted branch (`lane/laptop-lapic`) shows the LAPIC timer counting and
delivering vector 32 under `pit=off` and `pic=off`; nothing requires it
yet (docs/DESIGN-INFLUENCES.md, "Native hardware tripwires").

The real AG SQLite workload from the Rust platform repository has run over
NVMe: `ABSD_BLOCK_ATTACH=nvme scripts/fs-matrix.py --only
store,crash,powercut` against a clone of this branch at `cbc8aee` passed
all 187 boots (`AG SQLITE STORE OK`, `AG SQLITE CRASH RECOVERY OK` at 23
points, `AG SQLITE POWER CUT OK` with 66 cuts, `FS MATRIX OK boots=187`),
each serial log showing `BLOCK BACKEND nvme access=read-write`, with the
host's independent filesystem and SQLite oracle agreeing with the guest
after every recovery.

## Development guardrails

Working code, tests, and QEMU execution are what count for disposable local
development. Do not add project-process artifacts (review records, approval
workflows, per-run budgets) to this repository; they belong to the separate
Constellation project, whose components should not be imported merely because
they exist. The operator opened networking for the SSH tranche (2026-09-26):
a kernel frame driver for one NIC and a userspace protocol stack
(docs/NETWORK.md). Kernel sockets, a general driver framework, IPv6, UDP,
DNS, and DHCP remain out, as do filesystems in the kernel and a capability
system. Do not make everything a file or a per-process namespace (the
Plan 9 model); add a named object only when a workload needs it.

Potential long-horizon patterns and the concrete triggers for reconsidering
them are cataloged as non-binding notes in
[`docs/DESIGN-INFLUENCES.md`](docs/DESIGN-INFLUENCES.md). Its deferred
"Dogfooding Constellation on ABSD development" guidepost is not a
prerequisite for current work.

## Current stable boundary

The reclaimable process model (frame ownership, address-space teardown,
spawn, blocking wait/reap, terminal cleanup, the 200-cycle spawn/exit/reap
leak check),
FPU state preservation, full exception routing, the Rust userspace crate,
the bounded anonymous `map`/`unmap` window, the per-process handle table,
the cell object with conditional transition, atomic multi-handle copy at spawn,
rights reduction through `duplicate`, blocking on a cell change, the
bounded pipe with blocking read/write, the tick clock with sleep, timed
waits, and the idle loop, interrupt-driven console input, the
interactive shell boot mode with background jobs, `info`, console
replacement at spawn, the spawn exhaustion proof, `kill`, timed
transfers, the fuzz boot, captured pipe+cell composition, and bounded grow-down
stack, split wait/kill process rights, repeated handle-lifetime stress, and
process/handle/object capacity reuse proofs, PID 1 identified orphan cleanup,
and bounded userspace supervision have landed and must not be reimplemented.

Hostile-userspace qualification is complete and closed: phase 1 (fault
containment, commit `60b4323`) and phase 2 (state transitions and resource
lifetime, commit `582f0af`) found no kernel defects; every defect surfaced
was a test-side expectation bug, fixed on the test side. The full evidence
record is `docs/HOSTILE-USERSPACE.md`. Two follow-on spikes are also complete and in regression coverage through
their make targets (`elf-matrix-test`, `disclosure-probe-test`; not in
`make check`): adversarial ELF parsing through `spawn_image` and a syscall
information-disclosure audit (docs/ADVERSARIAL-ELF.md,
docs/SYSCALL-DISCLOSURE.md). They found no kernel defects. Remaining
questions are named future conditions, not blockers: frame exhaustion midway
through `spawn_image`, concurrent ordinary/AP userspace and its cross-CPU
TOCTOU cases, ELF/disclosure execution beyond the recorded UP/TCG
and startup-fenced served configurations, broader hardware execution beyond
the qualified FPU KVM host, and longer soak. The original ELF/disclosure spikes were UP/TCG results; later KVM FPU and guarded kernel-only AP controls are separate
evidence. Crafted FPU/MXCSR isolation from `19ecacd` was replayed onto kernel
`5b05da6bfd317b08a65847f8b293e54ff4a0d6c7` as implementation commit
`7567b04e6a7fd66d24a1e75b6e9370e3aa77316d`, using mode 17 and the
CPU-local restore path. Its original 20/20 KVM runs remain historical
evidence; the integrated KVM oracle, both FPU mutants, canonical
checks, RT/RT-class oracles and guarded kernel-only SMP controls passed at
their recorded source revisions; these controls do not qualify AP userspace.
See `docs/HOSTILE-USERSPACE.md` for exact source and evidence identities and
`docs/QUALIFICATION.md` for the recurring gates. Limits still include
general production cross-CPU FPU handoff beyond the separately qualified
CPU0↔CPU1 fixture, AVX/AVX-512, broader x87 data/exception behavior beyond
its stated control/arithmetic checks,
and execution beyond the qualified KVM host. One architectural fact carries forward: two adjacent
userspace syscalls are never atomic with respect to timer preemption (a child
can run and exit between its parent's `spawn` and `kill`; the kernel's no-op
kill of a terminal child is correct by design). Next ABSD work returns to
feature/architecture development unless new evidence reopens this lane.

## ARM64 bounded canonical integration — 2026-10-05

Accepted ARM source `15651dc` is replayed on canonical `bd2a34d` in a fresh
isolated integration branch. Exact combined executable source `bab71f7` has
passed B1–B4 and current x86 gates, independent acceptance `fec0e2d`, and the
fresh source fast-forward to `d2827ae`. New post-merge native captures and
independent follow-up `4e2e73b` pass. Nothing pushed. Prior ARM evidence/review and new replay custody stay separate.
See integration source and qualification (development record, not in a source release).
B5 is NOT STARTED; sealed release pins and inherited Limited RT standing remain.
