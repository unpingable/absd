# Minimal ABSD userspace

`user/` is a `no_std` Rust crate: `src/lib.rs` provides the syscall wrappers,
the `entry!` macro, and the runtime shims; `src/bin/*.rs` are the programs.
`scripts/build-user.sh` builds them for the host target with a static,
non-PIE, large-code-model link against `user/linker.ld`, and the kernel
embeds the resulting ELF64 bytes because this stage has no filesystem.
`make user` runs the script by hand; `make smoke` and `cargo test` run it
automatically through `build.rs`. Constants both sides depend on live in
`abi/` (`absd-abi`).

## Program catalog

`spawn` names a program by its index in `src/user_program.rs`:

| Index | Program | Role |
|---:|---|---|
| 0 | `init` | the sole kernel-started program; drives the suite or launches and reaps the selected shell/fuzz workload |
| 1 | `hello-a` | negative controls, cross-page buffer write, preemption filler |
| 2 | `hello-b` | yield plus preemption filler |
| 3 | `exit7` | checks BSS zero-fill, exits with status 7 |
| 4 | `fault` | writes a supervisor address and is terminated by the kernel |
| 5 | `fpu` | keeps PID-derived patterns in XMM registers across yields and preemption |
| 6 | `trap` | executes `ud2`; reported as vector 6 |
| 7 | `privileged` | executes `hlt` from ring 3; reported as vector 13 |
| 8 | `heap` | map/unmap cycles, zero-fill on reuse, window exhaustion, refused bad ranges |
| 9 | `unmapped` | maps, unmaps, then touches the page; faults at exactly that address |
| 10 | `overflow` | grows through the bounded stack reservation, then faults on its permanent guard |
| 11 | `cell` | conditional transitions on a kernel cell, stale refusal, close, table bound |
| 12 | `shared` | one of three children racing on a cell handed over at spawn |
| 13 | `readonly` | holds a read-only duplicate of a cell; transition is refused for lack of the write right |
| 14 | `watcher` | blocks on a cell with `cell_wait` until the parent drives it to a stop mark |
| 15 | `piper` | streams numbered lines into a pipe write end handed over at spawn |
| 16 | `sleeper` | sleeps for its argument in ticks and checks the kernel clock advanced |
| 17 | `shell` | interactive: runs the named program with an optional argument (a trailing `&` makes it a background job, a trailing `\|` captures its output through a pipe), `jobs` lists jobs, `kill N` ends one, `wait` collects them, `quit` ends the session |
| 18 | `fuzz` | issues thousands of fixed-seed random syscalls, including real syscall-22 descriptor arrays, path-level rights chains, and deterministic rollback checks; the kernel must survive and reclaim (`SPAWN HANDLE FUZZ OK`, `RIGHTS CHAIN FUZZ OK`, `make fuzz-test`) |
| 19 | `multi-handle` | validates ordered narrowed copies, then composes a captured pipe console with a shared cell |
| 20 | `stack-grow` | descends ten pages (nine lazy stack-growth faults) while preserving GPR/XMM sentinel values |
| 21 | `stack-jump` | writes two pages below the mapped stack without moving RSP; must fault instead of allocating |
| 22 | `orphaner` | leaves either a terminal or live child for PID 1 to adopt and reap |
| 23 | `supervised-worker` | exercises generation-tagged transition/replacement and read-only graceful-stop/fallback modes for init's bounded supervision experiment |
| 24 | `recovery-worker` | classifies a versioned request cell as pre-request, applied to the named request, or conflicting for bounded retry/reconciliation tests |
| 25 | `service-client` | remains alive across nine worker instances and validates explicit generation, request, unavailable, reconciliation, and bounded-stop states |
| 26 | `client-service-worker` | receives narrowed views of three stable cells and performs one generation's fault, conditional update, reconciliation, stale refusal, or orderly stop behavior |
| 27 | `alloc-probe` | exercises the reusable userspace allocator with collections, resize, free/reuse, and larger repeated allocations |
| 28 | `isolation` | keeps PID-derived heap and stack patterns intact while two address spaces use the same virtual addresses |
| 29 | `input-stream` | consumes an exact larger-than-capacity stream through a read-only pipe and reports its byte count and digest through a captured write-only console |
| 30 | `external-workload` | generic multi-start echo fixture; an opt-in build may replace its ELF without adding kernel semantics |
| 40 | `hostile-probe` | the hostile qualification battery and one hostile act per case; init's `hostile` boot checks every refusal and exception (docs/HOSTILE-USERSPACE.md, `make hostile-test`) |

## Private MWM presentation experiment

With `mwm-experiment`, `scripts/build-user.sh` builds a separate `mwm.elf` and an init coordinator. `make mwm-demo-iso` and `make mwm-fault-iso` select that exact MWM image through `ABSD_EXTERNAL_USER_ELF` into the existing `EXTERNAL_WORKLOAD` slot, and write four-artifact SHA-256 receipts for MWM, init, kernel, and ISO. Neither target launches QEMU. Ordinary builds omit MWM and retain the catalog routing above.

The fixture grants a generation-tagged display handle to one MWM child, uses bounded copied rectangles rather than framebuffer mappings, masks on last writable close, and opens one successor with a new generation. Init and MWM share the existing Console byte stream only for host `GO\n` observation barriers; no raw-input or client-surface protocol is introduced. The calls, records, refusal semantics, and evidence limits are in [`MWM-G1-PRESENTATION.md`](MWM-G1-PRESENTATION.md). This is not supported ABI or a production compositor.

## External workload boot

`make external-test` boots init in a dedicated mode, copies embedded input
through a read-only pipe, and captures the selected multi-start program's
write-only console. The normal build uses the catalog's echo fixture. Set
`EXTERNAL_USER_ELF`, `EXTERNAL_INPUT`, and `EXTERNAL_EXPECTED` to exercise a
different static ELF and byte-for-byte oracle; canonical `make check` never
depends on those files.

`make external-live-test` exercises the same generic process and pipe boundary
with bytes supplied after userspace init announces readiness. The host sends a
bounded `absd-stream-v1` chunk stream over the serial input direction; init
applies explicit credits before relaying each chunk into the child's existing
read-only pipe. A zero-length chunk closes the pipe and supplies ordinary EOF.
Serial output remains hex-framed as described below, so application input,
captured output, and kernel diagnostics stay distinguishable. The protocol is
an opt-in integration harness, not a kernel ABI or a device abstraction.
`EXTERNAL_LIVE_INPUT` may name a regular file or FIFO independently of the
regular build-time placeholder used by `EXTERNAL_INPUT`.
`make external-live-reject` is the corresponding negative application gate:
the host stream must complete, the selected child must fail, and init must
still prove a zero-resource baseline before the boot reports failure.

When a worker closes its stdin reader early, init stops writing that pipe and
drains its independent captured stdout to EOF before collecting the worker's
actual outcome. Incomplete input still fails, including when the worker exits
zero. An ordinary terminal input refusal can therefore have a complete output
frame and a failed boot. Plain external workers report `EXTERNAL WORKLOAD
OUTCOME pid=... status=...`, as durable workers and readers already do.
Nonzero worker outcomes and configured readers retain the existing stream
continuation rules; a replacement never inherits a closed pipe handle.

The kernel's pipe capacity, rights and stream credits are unchanged. The
ordinary worker deadline still bounds the drain; served workers reuse their
10,000-tick post-worker output bound after early stdin closure. Deadline or
output-device failures can still leave a partial capture. If stdout ends first
with stdin open and incomplete, init ends and reaps the worker before closing
the input writer: refused enrollment input must never look like ordinary EOF
to a live reader. Closing the writer after `BrokenPipe` is different: the
kernel has already established that no input readers remain. No durable
effects are rolled back by collecting output or reporting failure.
Readiness observed after an input failure is ignored, so draining a late
ready marker cannot turn a pre-ready served refusal into a recovery reset.
Live input still feeds before stdout draining begins; a peer that fills stdout
before consuming input can reach the existing deadline. This repair starts
when the input reader closes, not at that earlier duplex-streaming limit.

`make external-input-close-test` runs fifteen native controls using a fixture
that writes 4,096 deterministic bytes, four times the pipe capacity. It covers
embedded and live input, exit 96 and exit zero with unconsumed input, complete
input, output EOF before input completion, and durable reader continuation. A worker that keeps stdout open after closing
stdin must time out, report its actual forced outcome, reclaim all resources,
and leave no complete-output footer. That qualification case uses the existing
`NET_WAIT_TICKS=1000` override on an emulated-NIC durable boot; default deadlines
remain unchanged.
The fixture is behind `input-close-fixture` and is absent from normal catalog
builds. The control runner can target a separate kernel tree with the same
fixture ELF to demonstrate failure on sealed kernel
`d208b61bcd4826181bf9f401551ab620d4eabba0`.

Formalization consideration (kernel archived work item): the proposition is that
reader closure does not discard the independent output pipe, while refusing
incomplete input never introduces EOF to a live reader. The ordering above and
actual native controls, including the pre-fix failure and the reader-waits-for-
EOF control, are sufficient for this repair without a second abstract copy of
the supervisor. The kill-before-close ordering rests on source inspection;
the embedded and durable EOF controls observe behavior on their schedules,
and do not establish that a swapped-order mutant would fail. No such mutant
has been qualified. This is conditional on existing pipe reference counts,
handle-right enforcement, scheduling and deadlines; it does not prove output
completion after arbitrary device failures or unbounded worker output. Process
and pipe identities remain unchanged until collection; successor workers still
get fresh pipes. No kernel generation replacement or authority reconstruction
is introduced. The lane producer owns this consideration, with independent
Claude semantic/oracle review required before composition; the canonical card
records the exact resulting source and evidence identities.

One shipped image uses the same stream: the **enrollment build**
(`make ENROLL_STREAM=1 durable-iso`, owner ruling 2026-10-16 on coordination record
#31). The choice is made when the image is built, so no boot option or kernel
ABI selects it, and an ordinary image never reads its durable worker's input
from the serial line. In an enrollment image, init runs only a plain durable
boot, with exactly one worker generation and the absd-stream-v1 input. It
refuses to start if the image also carries embedded input, a broker policy, a
reader or a file server, or if it was granted a NIC. An aborted worker ends
the boot instead of being replaced. The worker that image carries is the
platform's enroll-only key writer. The serial line is trusted only inside the
user's own local QEMU or bootstrap environment. It is not a remote or
unattended enrollment service.

Captured bytes never mix raw with kernel diagnostics. Init emits one complete
line per serial write: an `EXTERNAL OUTPUT BEGIN encoding=hex` boundary,
contiguous `EXTERNAL OUTPUT CHUNK offset=<16 hex digits> data=<hex bytes>`
records, then `EXTERNAL OUTPUT END bytes=<decimal> digest=<FNV-1a32 hex>`.
Each chunk contains at most 96 bytes, keeping its whole line below the
256-byte syscall limit. The host decoder verifies boundaries, offsets, count,
digest, and exact decoded content before accepting `EXTERNAL WORKLOAD OK`.

## Entry and syscall ABI

Programs enter at the ELF `e_entry` address with a 16-byte-aligned user stack;
the top two pages of a 1024-page (4 MiB) reservation are initially mapped. The
legacy `entry!` convention receives the console in `RDI`, one copied handle
in `RSI` (zero for none), and an argument word in `RDX`; `RCX` is zero
except for init in a `net` boot, where it is the kernel's NIC grant
(`Start.nic`, docs/NETWORK.md).
`spawn_many_copy` programs use `multi_entry!`: `RDI` is the console, `RSI`
points to the ordered vector of new child handle values, and `RDX` is its
count. The catalog records which entry convention each program uses, and the
kernel refuses launching one through the wrong spawn syscall; an image
started by `spawn_image` is always multi-start. There is no kernel `argc`,
environment, working directory, auxiliary vector, libc, or POSIX process
ABI: argv, environment, and working directory travel in the startup record
on the first handle, which the platform runtime interprets
(docs/PROCESS-STARTUP.md). In Rust,
`absd_user::entry!(main)` defines `_start`, calls `main(Start) -> i32` with
the legacy values; `multi_entry!` calls `main(MultiStart) -> i32` with the
ordered slice. Both exit with the result; a panic exits with status 101.
Programs may use SSE and x87 freely: the kernel saves and restores that state
on every switch and resumable stack fault.

Syscalls use `int 0x80`:

| Register | Meaning |
|---|---|
| `RAX` | syscall number on entry; signed result on return |
| `RDI`, `RSI`, `RDX` | arguments 0, 1, and 2 |

| Number | Call | Arguments | Result |
|---:|---|---|---|
| 1 | `write` | console or pipe handle, user pointer, byte length (1–256) | bytes written or negative error; a pipe write may be partial, blocks while the pipe is full and a reader remains, and fails with `-32` once no reader is left |
| 2 | `yield` | none | zero |
| 3 | `exit` | signed 32-bit status | does not return |
| 4 | `getpid` | none | stable PID |
| 5 | `spawn` | program index, optionally OR-ed with `SPAWN_CONSOLE` (bit 32) and `SPAWN_NO_SPAWN` (bit 33), handle to hand over (0 = none), argument word | handle to the child process (wait and kill rights), or negative error; the default console never exceeds the parent's held console rights and is zero if it holds none; the child receives a duplicate of a non-process handle with the same rights, either as `Start.handle` or, with `SPAWN_CONSOLE`, as its console (a writable pipe or console handle), so its ordinary output flows there |
| 6 | `wait` | child handle (0 = any child), pointer to a 32-byte outcome record, timeout in ticks (0 = none) | reaped child PID after the record is written, `-110` if the timeout passed first, or negative error |
| 7 | `map` | page count (1–64) | address of that many zeroed, writable, non-executable pages at the lowest free run of the heap window, or negative error |
| 8 | `unmap` | address, page count | zero after every page is returned; the whole range is checked first, so a bad range changes nothing |
| 9 | `close` | handle | zero; the value is never valid again |
| 10 | `cell_create` | initial value | handle (read and write rights) to a new cell at version 0 |
| 11 | `cell_read` | cell handle, pointer to a 16-byte record | zero after `{version, value}` is written |
| 12 | `cell_transition` | cell handle, expected version, new value | the new version if the cell was still at the expected version; `-116` (stale) otherwise, changing nothing |
| 13 | `duplicate` | handle, rights | a second handle to the same object holding only those rights, which must be a subset of the original's (`-1` otherwise) |
| 14 | `cell_wait` | cell handle, version already seen, timeout in ticks (0 = none) | the current version as soon as it differs from the one seen, blocking until a transition moves it if necessary (read right); `-110` if the timeout passed first |
| 15 | `read` | console or pipe handle, user pointer, byte length (1–256) | bytes read. Pipe: blocks while empty and a writer remains, zero once empty with no writer left. Console: blocks until at least one byte of serial input has arrived |
| 16 | `pipe_create` | none | handle (read and write rights) to a new empty pipe |
| 17 | `time` | none | ticks of the ~1 kHz kernel timer since boot |
| 18 | `sleep` | ticks | zero after at least that many full ticks; zero ticks just yields |
| 19 | `info` | process handle with wait right (0 = self), pointer to a 32-byte record | zero after `{pid, parent, program index, state}` is written; state is 1 (runnable or running), 2 (ended, not yet reaped), or 3 (blocked waiting on a child, cell, pipe, console input, or sleep) |
| 20 | `kill` | child handle with kill right | zero; the child ends at once wherever it was blocked, everything it held is released, and `wait` later reports kind 3 (killed). A child that already ended is left alone |
| 21 | `transfer` | pipe or console handle, pointer to a 24-byte `{address, length, timeout}` record, direction (0 read, 1 write) | as `read` or `write`, but `-110` once the timeout in ticks passes with nothing moved (zero: no timeout) |
| 22 | `spawn_many_copy` | program index (optionally OR-ed with `SPAWN_NO_SPAWN`), pointer to `count` 24-byte `{source, rights, flags}` records, count (0–64) | wait-and-kill-capable child process handle or negative error; copies each non-process source with narrowed rights, optionally replacing the console with one flagged record, and gives the child the ordered result vector |
| 23 | — | — | unassigned: `-38` |
| 24 | `block_info` | block handle with read right, pointer to a 16-byte record | zero after `{sector_count, sector_bytes}` is written; `-9` for a non-block handle, `-5` if no device was probed |
| 25 | `block_read` | block handle with read right, sector number (LBA), pointer to 512 bytes | zero after the sector is copied out; `-22` past the end of the device, `-5` device error or timeout |
| 26 | `block_write` | block handle with write right, sector number, pointer to 512 bytes | zero once the device reports the write complete; same errors as `block_read` |
| 27 | `block_flush` | block handle with write right | zero once the device's cache flush completes |
| 28 | `stop` | retired | `-38`; `machine_stop` (37) replaced it |
| 29 | `boot_id` | pointer to 16 bytes | zero after this boot's identity is written: drawn once from RDRAND, the same for every process of one boot; `-38` without RDRAND |
| 30 | `wall_clock` | none | seconds since the Unix epoch from the CMOS RTC (whole seconds, read as UTC); `-5` when no stable valid reading can be taken |
| 31 | `spawn_image` | pointer to a 32-byte `{image, image_bytes, handles, handle_count}` record, flags (`SPAWN_NO_SPAWN` only), 0 | as `spawn_many_copy`, but the program is a static ELF64 image of at most 32 MiB in the caller's memory, loaded by the same loader; `-8` for an image it refuses. `absd_user::spawn_image` wraps it; docs/PROCESS-STARTUP.md has the whole contract |
| 42 | `abi_version` | none (ignored) | `absd_abi::KERNEL_ABI`, the generation of this syscall interface (currently 1): a constant of the kernel build, not an observation of state, the same on every call. A kernel older than the syscall answers `-38`. It is the one number the platform's hand-copied syscall table must equal; the platform runtime refuses to start (status 103, `ABI REFUSED kernel=<n> required=<m>`) on any other answer. `absd_user::abi_version` wraps it; init checks it (`ABI VERSION OK n=1`) |
| 43 | `block_read_many` | block handle with read right, pointer to a 16-byte `{lba, sectors}` record, pointer to `sectors * 512` bytes | zero after `sectors` (1–8) consecutive sectors, moved by one device command, are copied out; `-22` for zero sectors, more than eight, or a span past the end of the device; `-14` for a bad record or buffer address (checked before the device is touched); `-5` device error or timeout, in which case nothing is copied out. Additive to the single-sector calls: an older kernel answers `-38` |
| 44 | `block_write_many` | block handle with write right, the same record, pointer to `sectors * 512` bytes | zero once the device reports the whole command complete; same errors as `block_read_many`. After an error zero or more of the leading sectors may be on the device (an indeterminate effect a read or a fresh scan resolves). Completion is the device's acceptance, not durability: `block_flush` is still the only barrier |

`wait` blocks until a matching child terminates, then writes the record,
releases the child's retained metadata, and closes the caller's handles to
it. Only the parent can wait for or kill a child; process handles may be
narrowed locally but cannot be transferred at spawn.
The outcome record is four little-endian 64-bit words: kind (1 exited,
2 faulted, 3 killed), exit status or exception vector, fault address (CR2
for page faults, otherwise the faulting instruction), and hardware error
code. Any CPU exception a program raises terminates only that program.

Current errors are `-1` handle lacks the required right, `-2` unknown
program, `-8` an image `spawn_image` refuses, `-9` invalid handle (unknown, stale, or the wrong kind of object),
`-10` no such child, `-11` no free process slot, `-12` out of frames, heap
window, or object table, `-14` invalid user memory, `-22` invalid argument
or range, `-24` handle table full, `-32` pipe without a reader, `-38`
unknown syscall, `-75` exhausted non-reused PID space, `-100` no carrier (`nic_send` only:
the frame was not reported done and the NIC stays enabled; later sends are
refused with `-100` at once until the held descriptor's done bit is seen or
carrier returns, after which it gets one fresh bound and an expiry with
carrier present is a device outcome that disables the NIC, docs/NETWORK.md),
`-110` timed out, and
`-116` stale transition, and `-5` block device error (or no device). `write` accepts
1–256 bytes. User ranges are validated through the current process page
tables on every byte; supervisor, unmapped, and overflowing ranges fail
without terminating the kernel.

## Supported ELF subset

- ELF64, little endian, `ET_EXEC`, x86-64, current ELF version;
- static freestanding images with at most eight `PT_LOAD` headers;
- load addresses from `0x0000_0080_0040_0000` up to (but not including)
  `0x0000_0080_0400_0000` (`abi/src/layout.rs`; `user/linker.ld` matches);
- page-backed file copying, BSS zero-fill, and R/W/X-to-page translation;
- an entry point inside an executable load segment.

Dynamic linking, `PT_INTERP`, shared libraries, relocations, TLS, general or
file-backed demand paging, and POSIX startup are unsupported and refused
rather than approximated. The kernel never loads from persistent storage:
a program on the filesystem runs because userspace read its bytes and
passed them to `spawn_image` (docs/PROCESS-STARTUP.md).

## Handles

Every process has a table of at most 128 handles. A handle is an opaque
64-bit value: its low byte is a slot index and the rest is a tag unique to
that issue of the slot, so a closed or reaped handle never resolves, and a
value copied from another process can at most name one of the caller's own
objects, never the other process's. The kernel checks the object kind and
the handle's rights on every use. Today there are seven object kinds: console,
child process, versioned cell, pipe, the one block device, the network
interface, and the machine. Handles are
unforgeable per-process references with rights; there is no general
capability system beyond that. The kernel grants init a read/write
console; a child's default console is derived from the console rights held by
its parent and can never exceed them (or is zero if the parent holds none).
Child handles carry wait and kill, and newly created cells and pipes carry
read and write. Each object kind has an enforced rights mask, so unrelated
bits cannot be inserted even by an internal kernel path. `close` releases any
of them; closing a child handle does
not affect the child, and `wait(0)` can still reap it. Cells and pipes are
reference counted by handles: every live handle contributes exactly one
reference with the same rights used on release, and the last close or process
termination frees the object. Non-process handles cross a process boundary only at spawn;
process handles may be narrowed locally but remain parent-local. Legacy
`spawn` copies at most one; `spawn_many_copy` accepts up to 64 descriptors.
Every descriptor names a source, requested rights, and flags. Rights may only
narrow, duplicate source entries are legal and create distinct child handles,
and at most one record may replace the child's console. Results arrive in
descriptor order through `MultiStart.handles`; the parent retains every
source. The PID-based tag seed makes traces easier to read but is not a
security boundary; userspace must keep every handle value opaque.

The kernel validates the whole descriptor range and every source/right before
publishing the child. It builds the process in `Created`, installs the entire
batch, writes the startup vector, takes object references, and only becomes
`Runnable` after the parent's process handle is installed. Any load,
destination-capacity, or publication failure rolls back handles, references,
frames, process slot, and PID, so no child-visible partial state escapes.
`duplicate` mints a second handle with a subset of the rights (write `1`,
wait `2`, read `4`, kill `8`); rights only ever narrow along a chain of duplicates,
so a parent can hand a child a read-only view of a cell. The spawn right is
not one of these handle rights: it is a per-process attribute, held by init,
inherited by a child unless its spawn carries `SPAWN_NO_SPAWN`, and never
regained (`docs/BROKER.md`). A process without it gets `-1` from every spawn
call.
`absd_user::spawn_captured` hands a pipe's write end over as the child's
console: the child writes as usual and the parent reads its output.
`info` reports runnable/live state as 1, terminal/unreaped as 2, and a blocked
`Waiting` process as 3. Tests poll this state before killing or waking a
blocked child, so timing alone is not their oracle.

## Pipes

A pipe is a bounded (1 KiB) first-in first-out byte stream held by the
kernel. `pipe_create` returns one handle with both rights; the usual
pattern is to `duplicate` a read end and a write end, close the original,
and hand one end to a child at spawn. Handles with the read right count as
readers and handles with the write right as writers: `read` returns zero
once the pipe is empty and no writer remains (the child's exit is enough),
and `write` fails with `-32` once no reader remains. Both block otherwise,
and the kernel completes the blocked transfer itself when the pipe
changes. Transfers are at most 256 bytes per call and writes may be
partial; `absd_user::Pipe::write_all` loops. The kernel keeps at most 48
pipes.

The default suite composes existing objects without a new type: a child gets
one write-only cell handle and one write-only pipe endpoint as its console.
It proves reads are denied, conditionally changes the cell, and writes a
deterministic record. The parent drains the pipe through stable EOF, checks
the exact cell version/value, reaps the child, and closes every retained
source (`HANDLE TRANSFER OK`, `PIPE CELL COMPOSE OK`).

The default suite also repeats ownership transitions across child exit, kill,
and reap (`HANDLE LIFETIME STRESS OK`), splits process authority into wait-only
and kill-only handles while rejecting process-handle transfer (`PROCESS RIGHTS
OK`). A wait right is targeting authority for targeted wait through a handle;
wait-any follows parentage and remains available without a
wait-capable handle (`WAIT ANY PARENTAGE OK`). The suite also fills then
reuses the process, per-process handle, cell, and pipe
tables (`PROCESS CAPACITY OK`, `HANDLE CAPACITY OK`, `OBJECT CAPACITY OK`).
Final acceptance checks balanced lifecycle counters and complete resource
reclamation rather than relying on a documented numeric transcript.
The `orphaner` probe shows that a live PID 1 adopts both terminal and live
grandchildren and can identify and reap their preserved outcomes. Two
same-outcome orphans prove wait-any identity, while guessed PIDs remain invalid
for info and kill. Adoption while PID 1's handle table is full proves reparenting
consumes no handle slot (`WAIT ANY PID OK`, `ORPHAN ADOPTION OK`,
`ADOPTION HANDLE PRESSURE OK`, `INIT REAPER OK`). Adoption makes PID 1 the
parent for wait and reap only, not a supervisor; the kernel-parent cleanup path remains the fallback
when PID 1 exits or is absent.

The default suite also contains one deliberately small userspace supervision
experiment. Init retains a cell, gives each fresh worker only a write-only
duplicate, observes an exact vector-6 failure, and explicitly starts a new
instance that completes the next conditional transition. Replacement spawn is
not declared recovery until the exact instance terminates and retained state is
reconciled. A deliberately stuck worker proves supervision waits have deadlines
and are followed by explicit kill/reap. Before that fallback, both a healthy
and a stuck instance receive the same versioned-cell stop request; the healthy
one exits normally within the bound, while only the stuck one is killed. The
existing startup word carries a bounded replacement generation, and both sides
log generation with PID. A separate two-restart budget proves that the
supervisor stops restarting and reports failure (escalates) instead of looping. Process handles are consumed by wait and all cell
handles are closed. `SUPERVISOR CLOSURE OK` is emitted only after the
replacement survived, recovery state resolved, and fresh cell/process/handle
allocation proved slack for the next operation (`SUPERVISOR OBSERVED FAULT`,
`SUPERVISOR REPLACEMENT SPAWNED`, `SUPERVISOR RECONCILE OK`, `SUPERVISOR GRACEFUL STOP OK`,
`SUPERVISOR STOP FALLBACK OK`, `SUPERVISOR TIMED WAIT OK`, `SUPERVISOR
ESCALATION OK`, `SUPERVISOR RECLAIM OK`). This is ordinary process/cell policy,
not kernel restart magic.
The same accepted stop paths also emit the concise aliases `GRACEFUL STOP OK`
after `Exited(0)` and `FORCED STOP OK` only after timeout, kill, and `Killed`.
The process-capacity phase starts with a worker that applies its request and
faults before reply. It then refuses the higher-generation reconciler with
exactly `Again` while all slots are occupied, keeps the applied cell
inspectable and unchanged, and completes reconciliation after one filler is
reaped (`RECOVERY RESOURCE REFUSAL OK`, `SUPERVISOR RESOURCE REFUSAL OK`).

A separate bounded recovery workload passes each fresh worker exactly one
explicit read/write cell handle plus immutable replacement generation, request ID, and
mode startup data. It proves fault-before-mutation permits one retry,
fault-after-apply reconciles without double application, and normal
completion performs one conditional update. The shared cell is the only
record of the request's state across fresh PIDs; this is an in-memory userspace
experiment, not durable service recovery. An older-generation reconciliation
probe leaves the applied request unchanged: generation is diagnostic startup
data, not authority or a fencing token (`SERVICE RECOVERY OK`, `NO DOUBLE APPLY
OK`, `RECOVERY REPLACEMENT REFUSED`, `RECOVERY RESOURCE REFUSAL OK`).

The surviving-client workload uses three cells whose object identities remain
stable for the client's entire lifetime. The supervisor-written status cell
encodes `{phase, replacement generation, current worker PID}`. The request/control cell
carries `{phase, event generation, request ID}`, where the event generation is
the replacement generation a request is addressed to; the state cell's version
and last request are the only record of whether a mutation occurred. Cell
versions are not replacement generations, and PID is never the logical service
identity. The client receives read-only status/state views plus read/write
request authority; each worker receives read-only status/request views plus a
read/write state view. Process handles remain in init.

One client PID observes fault-before-mutation and same-ID retry, lost reply
after mutation and reconciliation, normal completion, obsolete-generation
refusal, explicit orderly stop, replacement refusal at full process capacity,
and later resumption. Nine worker PIDs are fresh and generations increase
monotonically. A comparison run admits optional fillers only while leaving one
process slot, which is sufficient for the current fixed-footprint replacement;
this is userspace admission control, not a reservation guarantee
(`CLIENT SURVIVES SERVICE RESTART OK`, `RECOVERY HEADROOM EXHAUSTED OK`,
`RECOVERY HEADROOM PRESERVED OK`).

Possible future influences are recorded as non-binding, trigger-based notes in
[`DESIGN-INFLUENCES.md`](DESIGN-INFLUENCES.md).

## Cells and conditional transition

A cell is the first ABSD-native object with state: a 64-bit value and a
version that starts at 0 and advances by exactly one per successful
transition. `cell_transition(handle, expected, value)` stores `value` only
if the cell is still at `expected`; otherwise it changes nothing and
reports `-116`. Read the version, decide, then transition naming that
version: an intervening change makes the transition fail instead of
silently overwriting. `cell_wait(handle, seen, timeout)` blocks until the
version differs from `seen`, so a process can sleep on a change instead of
polling; several transitions may be coalesced into one wake-up. A nonzero
timeout bounds the wait. The kernel keeps at most 32 cells.

## Time

`time` returns the kernel's tick counter (about 1 kHz from the PIT) and
`sleep` blocks for a number of ticks. `wait` and `cell_wait` take an
optional timeout in the same unit, and `transfer` is `read`/`write` with
one; all fail with `-110` when it passes first, so every blocking call can
be bounded. When nothing is runnable the
kernel halts until the timer wakes a sleeper, expires a timed wait, or a
serial byte arrives for a blocked console reader.

## Console input and the shell

The console handle carries both rights: `write` sends bytes to COM1 and
`read` returns bytes received on COM1, blocking until at least one has
arrived. Input is raw: no echo, no line editing, no end of file. The kernel
currently treats the one global COM1 endpoint as intentional bring-up ambient
authority; its handles do not yet represent distinct device identity or
lifetime. That is revisited only when multiple consoles or real delegation
exist. The kernel always starts init as PID 1 and passes a bounded startup mode
in `Start.arg`.
With `shell` on the kernel command line, init launches and later reaps the
shell through ordinary process syscalls. `make shell-test` drives a scripted
session over QEMU's serial socket (`scripts/shell-session.py`, needs `python3`),
sending each command only after the prompt appears; `make shell` boots the
shell on the current terminal for a human.

For the opt-in x86 USB keyboard, use `shell usb-keyboard` to feed the same
Console FIFO from one root-port HID boot keyboard. COM1 input remains available.
`xhci-pci=BB:DD.F` chooses one xHCI controller, for example
`shell usb-keyboard xhci-pci=00:05.0`. All fields are hexadecimal, with exactly
two bus digits, two device digits (00–1f), and one function digit (0–7);
letters may be either case. With no selector, the first xHCI function in
bus/device/function order remains the default. Each probe logs every
`XHCI CANDIDATE bdf=...` before it claims anything and reports the selected BDF.

A malformed or repeated selector, a missing BDF, or a BDF of another class
refuses the USB path before claim, BAR sizing or controller MMIO. Repeated
values are refused even if identical. Missing and wrong-class refusals also
print the requested BDF. Serial input continues. No failure of the selected
controller switches to another controller. The selector also applies to the
existing `xhci-probe` and `xhci-controller` diagnostic boots; it has no effect
when no xHCI mode is enabled. Only one controller uses the existing static
DMA/IRQ pool. See [USB selection and E5 reference](NATIVE-USB-STAGE2.md#explicit-controller-selection-2026-11-03)
for the reference census, lifecycle boundaries and focused runtime recipe.

## Memory

Each process reserves 1024 grow-down pages (4 MiB) from `USER_STACK_BASE` to
`USER_STACK_TOP`; only the top two are mapped initially. A ring-3 page fault
maps exactly one page only when its error code is `0x6` (non-present user
write), its page is directly below the mapped stack, and saved RSP is in
that page or no more than the 128-byte SysV red zone above the fault. The
handler saves/restores every GPR and the FPU/XMM image, maps one zeroed owned
frame, invalidates the new translation, and resumes the faulting instruction.
Allocation failure or any other fault remains an ordinary process fault.
The page immediately below `USER_STACK_BASE` is never mapped. `stack-grow`
descends ten pages (nine growth faults) and returns with GPR/XMM sentinels
intact; `overflow` reaches the 1024-page maximum and faults on that guard
(`USER STACK GROW OK`, `STACK GROW pages=1031`).
Address-space teardown reclaims every
mapped stack page. `stack-jump` additionally proves that skipping the
adjacent candidate remains an ordinary exact-address `0x6` fault (`STACK GROW
ISOLATION OK`). Anonymous pages come from the 32 MiB heap window at
`USER_HEAP_BASE` (`abi/src/layout.rs`): `absd_user::map(pages)` returns the
lowest free run, pages are zeroed on every mapping, and `unmap` returns them
to the kernel's frame pool. Touching an unmapped heap page is a
not-present user page fault at that address (`unmapped`). The window and
the per-call limit of 64 pages are the rest of the memory API for now; there
is no `brk`, file mapping, or shared memory.

`MapAllocator` provides a reusable `GlobalAlloc` implementation over these
anonymous mappings. It grows in bounded chunks, reuses and coalesces freed
extents, and leaves its mapped chunks to normal process teardown. Kernel calls
that write an output record require a writable user range: a mapped read-only
buffer returns `Fault` and remains byte-for-byte unchanged.

## Opt-in QEMU Q35 FADT reset

The default-off `acpi-reset-qemu` kernel feature and the exact
`acpi-reset-qemu` boot option jointly request a FADT-first reset attempt.
The option alone or feature alone leaves the legacy reset path selected.
Discovery validates the required ACPI walk and unique FADT before caching
an immutable boot-local plan. Only a supported, complete System I/O GAS
with width 8, offset 0, access size 0 or 1, address `0xcf9`, and reset value
`0x0f` is accepted. Other descriptions never select FADT-specific I/O. This is a
QEMU Q35 compatibility profile; physical reset behavior is unqualified.

Discovery never resets the machine. An existing authorized machine reset
request first completes AP retirement, disables interrupts, then acquires
the plan. It records `ACPI RESET ATTEMPT`, drains the UART with a finite
poll bound, and writes the one byte once. If execution continues after the
finite spin bound, `ACPI RESET RETURNED fallback=legacy` precedes the
existing legacy reset sequence. Disabled, missing or refused plans report
`ACPI RESET UNAVAILABLE reason=... fallback=legacy`. A returned attempt is
not successful reset or rollback. Reset does not require S5 DSDT/PM1
eligibility and grants no additional machine right.

The operator option policy admits the exact `acpi-reset-qemu` token with
`smp-operator=2`, `4` or `6`; it does not enable the default-off reset feature.
FADT+SMP remains NOT ASSESSED and needs separate real retirement/missing-ACK
and reset evidence. The focused UP consumer and exact runtime controls are in
[RESET-TEST.md](x86-acpi-20261015/RESET-TEST.md).

<a id="opt-in-two-cpu-operator-boot"></a>

## Opt-in operator boot (2/4/6 CPU candidate)

The `smp-operator` kernel feature and exactly one canonical `smp-operator=N`
option, where N is 2, 4 or 6, select the candidate QEMU/OVMF operator profile.
Four/six-CPU support remains a candidate until each count has independent VM
acceptance; host tests alone do not promote a count. Build with
`frame-admission-v0,smp-operator`; the final served image uses
`durable=0 net fsd served smp-operator=2`. The existing Makefile's
`nvme-write=absd` token is also admitted without changing its storage serial
check. `acpi`, `acpi-poweroff`, exact `acpi-reset-qemu` and `halt-on-exit`
are the only other ordinary options. Diagnostic reset/S5 tokens remain rejected.
Unknown or duplicate options, missing `net fsd served`, malformed
counts, USB/native-device/RT/migration/qualification options, and conflicting
qualification (including `spawn-image-rollback-test`), read-only and PCM build
features refuse. Compiling the feature alone leaves importer and ordinary
boots UP. The generic `ap-startup` and
`ap-userspace` compile-time refusals remain.

The launcher owns exactly `-smp N,sockets=1,cores=N,threads=1`, including N=2.
Before SIPI or MMIO freeze, validated ACPI MADT must describe exactly N
enabled xAPIC records, IDs 0 through N-1, distinct processor UIDs, BSP ID 0, and a
LAPIC address matching the APIC MSR. Missing, duplicate, disabled, x2APIC or
mismatched topology refuses. AP startup and local timer readiness have separate
bounded waits. The fixed SIPI page remains `0x7000`. Its complete 4 KiB must be type-1
Multiboot RAM with no reserved-range, kernel, Multiboot-block or module
overlap; the allocator separately reserves the whole first MiB until shutdown.
Legacy BIOS boots still require the page below a nonzero EBDA pointer. EFI
boots may omit that legacy pointer only with exactly one well-formed EFI
system-table tag, one framed descriptor-version-1 EFI memory-map tag, and no tag 18
(live boot services). Duplicate, truncated or conflicting handoffs refuse.
EFI loader/boot-services memory is reusable after ExitBootServices, but is
never substituted for the Multiboot RAM proof; EFI reserved/runtime overlaps
still refuse. See [Multiboot2 EFI boot services tag](https://www.gnu.org/software/grub/manual/multiboot2/multiboot.html)
and [UEFI 2.10 memory use after ExitBootServices](https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html#memory-type-usage-after-exitbootservices).
A refusal retains `SMP AP LOW PAGE REFUSED` and adds a preceding
`SMP AP LOW PAGE DETAIL reason=...` diagnostic. This rule was derived from the
captured OVMF handoff replayed by `src/ap_page.rs`; a host pass does not by
itself establish AP startup.

The count is immutable before topology use. Shared-trampoline startup remains
sequential: each ONLINE fence precedes the next patch. Every admitted AP must
finish its local calibration and publish READY before native scheduling begins.
Physical machines, hotplug, migration, RT timing, CPU0 dispatch independence
(kernel #5), FADT+SMP and lock removal remain NOT ASSESSED. Six vCPUs on a
four-host-CPU machine establish overcommit behavior, not six-core scaling.

Catalog init, FSD and sshd stay on CPU0. Dynamic `program::IMAGE` tasks use
APs 1 through N-1 in publication-order round robin only if they are non-RT
and have no Console, Block, Nic or Machine handles at Created publication.
BSP-pinned publications do not consume the cursor. N=2 still chooses CPU1.
Pipe consoles are eligible. The PID and CPU placement
remain fixed until final slot release; closing a device handle cannot migrate
a task. Every AP selection and return revalidates current authority. Existing
spawn-time copied handles are considered before publication; `SYS_TRANSFER`
still transfers bytes and introduces no live capability-transfer operation.
The common BKL, task claim epochs, address-space checks, FPU save/restore and
stop/departure fences remain. PIT time and hardware waiters remain BSP-owned;
the AP uses a calibrated local timer for ordinary task preemption.

Operator mode creates no synthetic process, shared qualification mapping,
pressure reservation or private `0x7fff` syscall behavior. The existing served
userspace drain, FSD sync, and kernel frame/object accounting still decide
clean termination. Shutdown, reboot and immediate recovery then hold the BSP
BKL, publish a sticky machine stop, and wait for every attempted AP's terminal ACK, even an AP that never
published ONLINE. Every retirement entry attempts bounded nonasserting IPI
delivery to all missing APs; a delivery failure cannot fabricate an ACK. AP
interrupt, calibration, idle and pre-acquire paths pivot with CLI to CPU-owned
stack/TSS and boot CR3, mask the timer, verify actual CR3/RSP/TSS/IF and timer mask/count readbacks,
publish the ACK with Release ordering,
and halt permanently. BSP observes it with Acquire ordering. No AP lock,
process-table access, serial output or reap occurs in that park path.
`SMP RETIREMENT PARKED cpu=N` reports the checked per-CPU departure boundary only;
immediate recovery still abandons process accounting and does not imply drain
or sync. Missing ACK prints
`SMP RETIREMENT REFUSED cpu=N reason=missing-ack` names the first missing
attempted CPU, then BSP halts with
interrupts disabled without reset, S5 or successful machine completion.

An operator AP Rust panic or reported kernel exception first publishes sticky
first-failed raw CPU identity and halts silently, before framebuffer or serial
diagnostics. Valid Rust identity/refusal backstops use that same path. An
invalid raw AP ID is reported as 255, never indexed or acknowledged. The two
pre-Rust damaged-stack assembly exits remain explicit failed local-VM exits. It emits
no parked ACK and does not release BKL or task resources. The BSP checks this
failure while acquiring BKL, at fatal reporting entry and during retirement,
then emits `SMP RETIREMENT REFUSED cpu=N reason=ap-failed` and halts with IF
clear. Retirement BKL acquisition is also bounded; without a published AP
failure, expiry emits `SMP RETIREMENT REFUSED cpu=0 reason=lock-timeout` and
halts. These last-resort records use bounded raw COM1 polls, without BKL or
framebuffer access. Failure publication is not hardware departure, reclaim or
transfer evidence; no reset, S5 or success follows it. This covers the admitted
virtual profile's Rust fatal entries, not arbitrary hardware corruption.
Healthy peers that observe the failure silently CLI/HLT without PARKED, reclaim
or authority transfer. This does not promise instantaneous global quiescence.

Normal BSP fatal diagnostics require the first fatal entry and BKL ownership
by CPU0. An unowned or reentrant BSP fatal instead emits
`SMP RETIREMENT REFUSED cpu=0 reason=bsp-fatal` through bounded raw COM1
polls, then halts with interrupts disabled, without reset or reclamation.
AP failure observed before that BSP decision takes priority and replaces the
BSP diagnostic with `reason=ap-failed`. The selected raw refusal reason stays
fixed through output and halt. A BSP fatal refusal does not establish AP
quiescence or safe resource reclamation. Ordinary retirement does not consume
the fatal-entry flag and retains its existing parked-ACK fence.

Serial records after `SPAWN EXHAUSTION OK` are machine-readable:

- `SMP OPERATOR PLACE cpu=N pid=N epoch=0`: immutable publication.
- `SMP OPERATOR TRAP cpu=N pid=N epoch=N`: first actual CPL3 syscall trap,
  with checked CPU claim and owned CR3.
- `SMP OPERATOR TIMER cpu=N pid=N epoch=N`: first task-specific CPL3 timer.
- `SMP OPERATOR DEPART cpu=N pid=N epoch=N`: terminal/stop hardware departure.
- `SMP OPERATOR TERMINAL cpu=N pid=N epoch=N state=exited|faulted|killed status=N`:
  terminal accounting before resource teardown. The ordinary outcome and final
  accounting records establish successful reclamation; this line alone does not.

Beside first TRAP/TIMER and each TERMINAL,
`SMP-OPERATOR CLOCK kind=TRAP|TIMER|TERMINAL cpu=N pid=N epoch=N tick=N`
samples `sched::now()` under BKL, the same BSP clock as SYS_TIME/uptime. It
supports guest-time service-I/O bracketing, not continuous CPU execution or a
new stable trace ABI. Instrumented SMP observations add serial overhead absent
from ordinary UP. Summary counters cover every admitted CPU; old two-CPU
record and fixture counter interfaces remain intact.

The initial allocation-exhaustion probe can reuse PID 1 and therefore emits
no operator task evidence. Runtime claim epochs may advance between trap,
timer and terminal records. `SMP OPERATOR SUMMARY` reports syscall counts,
AP contention and user timer counts at retirement. Native command output over authenticated SSH and
concurrent independent FSD I/O must be correlated with these records; a
placement record alone is not proof of AP execution.

For a dedicated negative-control image, add `smp-operator-controls` to the
features and append exactly one of these options to the same served line.
Existing AP controls target N-1 (CPU1 at N=2):

- `smp-operator-start-interrupt`: stops AP during local-timer calibration;
  expect `SMP OPERATOR REFUSED reason=interrupted-start` and a parked ACK,
  without `SMP OPERATOR READY` or userspace entry.
- `smp-operator-retire-no-ack`: AP performs the safe pivot but withholds its
  ACK; request ordinary shutdown/reboot/recovery and require the named
  missing-ACK refusal, no ACK for that AP or overall summary, and no reset or S5. Earlier healthy
  APs may have individual PARKED records.
- `smp-operator-ap-panic-held` or `smp-operator-ap-panic-unheld`: panic once
  on the first native AP kernel entry, immediately after or before BKL
  acquisition respectively. The BSP identifies the selected variant with
  `SMP OPERATOR CONTROL ap-panic=held` or `ap-panic=unheld`. After observing
  the AP failure, the BSP emits the corresponding
  `SMP OPERATOR CONTROL ap-panic-consumed=held` or `ap-panic-consumed=unheld`
  record only if the AP hook atomically consumed that control. Require the
  final named `ap-failed` refusal, no parked ACK and no reset or success.
  Arming a control alone is not proof that the AP reached it.
- `smp-operator-start-missing` (N=4/6): AP1 starts, AP2 is attempted but
  receives no INIT/SIPI, and AP3+ are never attempted. Require startup-timeout
  then missing-ACK for CPU2; healthy AP1 may park. No machine success follows.
- `smp-operator-ap-backstop`: the last AP enters the actual Rust
  `ap::fail_closed` backstop under BKL; the consumed label is
  `SMP OPERATOR CONTROL ap-panic-consumed=backstop`, followed by ap-failed.
- `smp-operator-ap-panic-held-peers` (N=6): AP5 panics under BKL only after
  two distinct other APs own live Running IMAGE claims with a first user TIMER
  already observed. It never waits under BKL. Each witness is
  `SMP OPERATOR CONTROL peer cpu=N pid=N epoch=N`; epoch is the current live
  claim, which may be newer than the first TIMER epoch. Correlate TIMER and
  witness by boot/PID/immutable CPU placement. The consumed label is
  `SMP OPERATOR CONTROL ap-panic-consumed=held-peers`. The controls-only ELF
  byte `SMP_OPERATOR_PEER_FAILURE_OBSERVED` records each peer's silent abort
  branch after CLI; it proves neither normal parking nor authority transfer.
- `smp-operator-bsp-panic-unheld`: after operator readiness, panic once
  immediately after the BSP releases BKL for an interruptible device wait.
  The BSP arms the control with `SMP OPERATOR CONTROL bsp-panic=unheld`;
  this record alone does not prove hook consumption. The raw refusal path
  emits `SMP OPERATOR CONTROL bsp-panic-consumed=unheld` only after the hook
  atomically consumed the control. Require the final named `bsp-fatal`
  refusal, with no parked ACK, reset or success.

A one-vCPU launch of the ordinary two-CPU image is a topology negative control
and must refuse before any AP start. The controls are refused by ordinary
operator builds. These are development controls, not alternate acceptance
criteria or a replacement qualification harness.

Rollback of this candidate is a reboot with the matching prior kernel/image
pair and its admitted CPU count, or the UP image without an operator count.
There is no runtime CPU removal, task migration, state export or generation
replacement protocol here. Placement and claim state remain boot-local native
state, not a replacement schema; any future replacement must explicitly fence
APs and reconstruct authority before retirement. Terminal machine ACKs cannot
serve as task-reclaim or post-effect rollback evidence.

## Private managed-console presentation

Experimental syscall `0x7fc4(console, mode, reserved)` accepts mode 0 (kernel
presentation) or 1 (managed local presentation), with reserved=0. It requires
root init (PID1, kernel parent, init program) and a currently owned Console
WRITE handle; zero, Diagnostics, pipes, read-only and stale handles refuse.
It grants no input, diagnostic-read, process-control or machine authority.
Boot defaults to kernel presentation. This is private paired-image machinery,
not a promoted application ABI.

The ARM64 UART backend has no physical-input/presentation owner. It applies
the same authority and argument checks, then returns not implemented (-38)
for a valid presentation request. Ordinary ARM64 diagnostics stay enabled;
this interface does not establish an ARM64 local console.

Init claims managed presentation before constructing the served local UI,
and retains it through read-only maintenance. Ordinary kernel diagnostics
continue into the bounded ring but are not replayed unsolicited to COM1 or
the framebuffer. Userspace Console writes, including init's selected terminal
and maintenance rendering, still reach the display and do not feed the ring.
No text parsing or escape-byte convention chooses this policy.

Claim first bounds and accounts any pending transmit prefix before UI output.
Init releases presentation for deliberate shutdown/reset; init exit or fault
also restores kernel presentation. Kernel panic and kernel-exception reporting
explicitly restore presentation before formatting fatal details. The existing
lock-independent bounded raw fatal path remains independent of this mode.
Headless and historical profiles that never claim ownership retain ordinary
physical diagnostics. The console evidence digest covers presented bytes;
retained-only kernel records are not silent UART losses.

Local presentation starts only after init publishes the unfiltered worker
startup prefix, recognizes its complete SSH LISTENING or LOCAL READY line,
and subsequently drains FSD output to idle at complete-line boundaries. Raw
FSD startup lines use one bounded Console write per complete line so another
init record cannot split an anchored recovery witness. Oversize display lines
are explicitly omitted; the service journal retains their original bytes.
Physical input before this handoff is discarded except for read-only kernel
maintenance selection. Maintenance remains available while startup is held.
An unenrolled LOCAL READY can show the disabled-login view; presentation does
not grant recovery authority or satisfy the host's network-ready predicate.

After the handoff, ordinary service bytes continue into the journal while
local display carries the selected terminal. The raw serial worker capture
is then a startup prefix only: original offsets are preserved, physical
framing never resumes after an omitted range, and no complete-stream END is
emitted. Internal byte count/digest still cover all read service bytes. A
non-local boot retains its full original framing and END contract. The frame
formatter itself splits both stdout and stderr into at most 96-byte chunks.

This boot-local mode does not establish live replacement. A successor would
need to quiesce terminal input/output, reconcile the pending transmit prefix,
validate and reconstruct the owner authority and presentation mode before
commit, and explicitly retire the old generation. A native Rust layout or
a numeric PID alone is not an authority-transfer protocol. No such transfer
or post-effect rollback is qualified here.
## Ordinary served limits

The ordinary served profile has 32 process slots, 128 pipes and 32 cells.
A single startup/spawn vector remains limited to 64 handle transfers; the
per-process table is larger so init can assemble service channels before
closing its copies. Diagnostic observation query 257 (v1 kind 4) reports the
actual limits. Existing process rows still use queries 0 through the reported
process count minus one; kind 3 remains reserved for NIC candidates.
