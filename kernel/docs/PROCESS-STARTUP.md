# Process startup ABI

This is the shared contract for starting a program on ABSD: the kernel's
`spawn_image` call, the startup vector and startup record a program is
entered with, and what the Rust platform's runtime and `std` make of them
(argv, environment, working directory, standard streams, the filesystem
view). Network, SSH, and shell work consume it; change it here first.

Layers (docs/DESIGN-INFLUENCES.md, "Linux compatibility as a personality"):
the kernel ABI below is native. argv, environment, working directory, and
`std::process` are the Unix-style personality, implemented entirely in
userspace (the platform repository's `runtime/` and its `std` patch). The
kernel knows none of them: to the kernel a program is an image, an ordered
vector of handles, and a console.

## Three ways to start a program

| Route | Program | Who may use it |
|---|---|---|
| `spawn` (5), `spawn_many_copy` (22) | an index into the embedded catalog | a process holding the spawn right; init uses it for boot, rescue, and qualification workloads |
| `spawn_image` (31) | a static ELF64 image in the caller's own memory | a process holding the spawn right |
| init's broker (docs/BROKER.md) | a catalog program named by an exact path in init's policy | a durable worker without the spawn right |

The catalog stays: init and every qualification boot still start from it.
There is no `fork` and no `exec` that replaces a running image: a new
program is always a new process.

## `spawn_image` (syscall 31)

    spawn_image(RDI = request, RSI = flags, RDX = 0) -> process handle or error

`request` points to a 32-byte record of four little-endian words
(`absd_abi::syscall::SpawnImageRequest`):

| Offset | Field | Meaning |
|---:|---|---|
| 0 | `image` | address of the ELF image in the caller's memory |
| 8 | `image_bytes` | its length, 1 to `MAX_SPAWN_IMAGE_BYTES` (32 MiB, the size of the heap window a caller holds a file in) |
| 16 | `handles` | address of `handle_count` 24-byte `{source, rights, flags}` records, exactly as `spawn_many_copy` takes them |
| 24 | `handle_count` | 0 to 64 |

`flags` may carry only `SPAWN_NO_SPAWN` (bit 33): the child, and anything it
could start, has no spawn right. The third argument is reserved and must be
zero.

The kernel checks, in this order, and refuses with nothing changed:

| Check | Result |
|---|---|
| unknown flag bits, nonzero reserved argument | `-22` |
| the caller lacks the spawn right | `-1` |
| the caller's handle table is full (no room for the process handle) | `-24` |
| the request record is not readable user memory | `-14` |
| `image_bytes` is 0 or above 32 MiB, `handle_count` above 64 | `-22` |
| the image range is not mapped, readable user memory | `-14` |
| the handle records: unreadable (`-14`), unknown flag (`-22`), unknown rights bit or rights not held (`-1`), stale or process handle (`-9`), a bad console record (`-9`/`-1`) | as for `spawn_many_copy` |
| no free process slot, PID space exhausted | `-11`, `-75` |
| the image is not one the loader accepts | `-8` (`ERROR_NOT_EXECUTABLE`) |
| frames run out while loading | `-12` |
| the child's handle table cannot take the batch | `-24` |

The loader is the catalog's (`src/elf.rs`, `src/sched.rs`): ELF64, little
endian, `ET_EXEC`, x86-64, at most eight `PT_LOAD` headers (`PT_NULL` is
skipped, every other type, `PT_INTERP` and `PT_DYNAMIC` included, is refused),
every segment inside the user image window
`0x0000_0080_0040_0000..0x0000_0080_0400_0000`, file ranges inside the image,
and an entry point inside an executable segment. It reads the image straight
from the caller's page tables, the ELF header and one program header at a
time and then one destination page at a time, so the image is never
resident in kernel memory. Every refusal after the process slot is claimed
releases every frame, handle, reference, the slot, and the PID (a refused
spawn consumes no PID).

On success the caller gets a process handle with the wait and kill rights,
and the child is a **multi-start** program: `RDI` is its console (the
record flagged as console, else a console derived from the caller's own
console rights, else 0), `RSI` points to the ordered vector of its new
handle values, `RDX` is their count. `info` reports its program index as
`absd_abi::program::IMAGE` (`0xffff_ffff`), and the kernel logs
`SPAWN OK pid=N parent=P program=image`. Waiting, killing, reaping, and
orphan adoption are exactly as for any other child.

What `spawn_image` deliberately does not do:

- **No dynamic linking, interpreter, relocation, or TLS.** A `PT_INTERP`
  image is refused (`-8`), not handed to a loader.
- **No `#!` scripts.** A text file is not an ELF image (`-8`).
- **No execute permission.** ABSD files have no mode bits and the kernel
  never reads a file: it is handed bytes. What stands in for `x` is the
  spawn right the caller holds (which only narrows) plus whatever policy
  the userspace personality applies before it reads a file (today: the
  file must be a regular file on the filesystem the caller can read).
- **No filesystem in the kernel.** Reading the file is the caller's
  business (the platform's `absd-fs` library over its block handle).

`make spawn-image-test` (`user/src/bin/image_probe.rs`) builds images byte
by byte in its own memory, starts one whose output comes back through a
pipe, requires the exact code of every refusal above that userspace can
provoke (malformed, truncated, entry outside executable memory, segments
below and above the window, `PT_INTERP`, zero and oversized lengths, bad
flags, nonzero reserved word, too many records, bad request, image, and
record pointers, a stale handle, and a child without the spawn right),
checks that the refusals consumed no PID, and requires the kernel's
`EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0` afterwards.

## Startup vector and startup record

A multi-start program built on the Rust platform recognises three vector
shapes (the runtime's CRT, `runtime/src/lib.rs`):

- 2 handles: `[stdin, console]` (the external boot);
- 4 handles: `[stdin, block, step cell, console]` (a durable reader; a
  durable worker until the machine handle, which comes by record);
- 5 or more: `[startup, ..., console]`, where `startup` is a pipe carrying
  the **startup record** and every position between the first and the last
  carries exactly one role the record names.

The console is always the last handle and is the program's stdout.

The startup record is everything on the startup pipe until end-of-file
(at most 8192 bytes; the CRT closes the pipe after reading it). Integers are
little-endian:

    "ABSDSU01"
    u16 role_count, role_count x { u8 role, u8 index }
    u16 argc, argc x { u16 length, bytes }           arguments after argv[0]
    [u16 envc, envc x { u16 length, "KEY=VALUE" }]   optional environment
    [u16 length, working directory]                  optional, only after an environment
    [u16 length, program name]                       optional, only after a working directory

Roles:

| Role | Name | Handle |
|---:|---|---|
| 1 | stdin | read end of the standard input |
| 2 | stdout | the stdout write end (the same pipe or console as the last handle) |
| 3 | stderr | the standard error write end |
| 4 | block | the block device, as init hands it to a durable worker |
| 5 | step | the step cell (read-only) |
| 6, 7 | request, reply | init's broker channel (docs/BROKER.md) |
| 8, 9, 10 | slot stdin, stdout, stderr | broker slots |
| 11 | fs | a read-only block handle the runtime mounts, read-only, as this process's view of the filesystem before `main` |
| 12 | nic | the NIC of a `net` boot, as init hands it to a durable worker (docs/NETWORK.md) |
| 13 | fs request | one file server channel's request pipe: the write end for a client, the read end for the server ("File server" below) |
| 14 | fs reply | the same channel's reply pipe: the read end for a client, the write end for the server |
| 15 | machine | a machine handle with the stop right only, as init hands it to a qualification durable worker ("Machine authority" below) |
| 16 | session events | a session control channel's events pipe, read end: what the session's server (sshd) tells the session's shell ("Session control" below) |
| 17 | session requests | the same channel's requests pipe, write end: what the shell asks the server |

A record may not name both `block` and `fs`, nor `fs` and a file server
channel. Roles 13 and 14 may repeat; the n-th request pairs with the n-th
reply (at most 16 channels), and a record whose counts differ is refused.
Roles 16 and 17 come together or not at all. The sections are validated
strictly (the broker crate's `parse_startup`, host-tested): at most 32
arguments and 32 environment entries (each at most 1024 bytes, a non-empty
unique key before the first `=`), no NUL anywhere, a working directory that
is absolute, at most 1024 bytes, and free of empty, `.`, and `..`
components (only `/` itself ends in `/`), a non-empty name of at most 1024
bytes. A malformed record, or a vector that does not match it, ends the
program with status 102 before `main`.

Compatibility: records init's broker writes (no working directory or name)
parse exactly as before. The new sections are optional and trailing; a
runtime built before them refuses a record that carries them, so a new
parent must not start an image built by an older platform.

## What the runtime makes of it

- **argv.** `argv[0]` is the record's program name when present (the path
  the parent's `Command` named), else the name fixed at build time
  (`ABSD_PROGRAM_NAME`). When the record names the program its arguments
  are exactly the record's, even none; otherwise an empty argument list
  falls back to `ABSD_PROGRAM_ARGS` fixed at build time (the older
  catalog-image convention).
- **Environment.** Read-only for the life of the process (`std::env::var`,
  `vars`); `set_var` and `remove_var` stay `Unsupported`. A child started
  from a file inherits the parent's environment with the `Command`'s
  changes (`env`, `env_remove`, `env_clear`). A key must be non-empty and
  free of `=` (`InvalidInput` otherwise).
- **Working directory.** Process memory in the runtime, from the record
  (else `/`). `std::env::current_dir` returns it; `set_current_dir`
  resolves its argument lexically, requires an existing directory on the
  mounted filesystem (only `/` without one), and replaces it. Relative
  paths given to `std::fs` are resolved against it in the runtime before
  the filesystem sees them (`.` and empty components dropped, `..` taken
  lexically, never above `/`; exact because ABSD has no symbolic links);
  absolute paths reach the filesystem unchanged. The kernel has no working
  directory.
- **PID.** `std::process::id` is the kernel's PID.

## `std::process::Command` on ABSD

A process with broker handles (a brokered worker) uses init's broker,
unchanged (docs/BROKER.md). Any other process starts files itself; this
needs the spawn right, else the kernel's `-1` surfaces as
`PermissionDenied`.

1. **Program path.** Absolute, or relative with a `/` (resolved against the
   parent's working directory). A bare name is refused with `InvalidInput`:
   there is no PATH search yet. It is deferred until a consumer needs one;
   a shell can search its own PATH and pass the result.
2. **Image.** The runtime reads the whole regular file through the mounted
   filesystem (`NotFound`, `IsADirectory` for a directory, `FileTooLarge`
   above 32 MiB) and passes it to `spawn_image`; a refused image is
   `InvalidData`.
3. **Child vector.** `[startup, stdin, stdout, stderr, (fs), console]` with
   roles 1, 2, 3, (11); the console is the stdout end again. The record
   carries the arguments, the environment, the working directory (the
   `Command`'s, resolved against the parent's and required to be an
   existing directory, `NotFound`/`NotADirectory` otherwise; else the
   parent's), and the program path as the name. The parent writes the
   record after the kernel has started the child and closes the pipe.
4. **Streams.** `piped` gives the parent the other end; `null` stdin is a
   pipe whose writer the parent closes at once (EOF); `null` stdout or
   stderr is a pipe the parent drains and discards while it waits (closing
   it would turn the child's writes into broken-pipe errors); `inherit`
   copies the parent's own stdin, stdout, or stderr handle into the child,
   so the child writes where the parent writes. `io::stdout()` and
   `io::stderr()` as a child's stream likewise name the parent's own
   handle. A pipe end the parent holds (`Stdio::from` a `ChildStdout`,
   `ChildStdin`, or `ChildStderr`) is copied into the child with only its
   stream's right (read for stdin, write for stdout and stderr; the kernel
   refuses a right the end lacks), and a successful spawn consumes it: the
   parent's copy is closed at once, so end-of-file and broken pipe depend
   on the children alone. This is how a shell composes `a | b`; a writer
   whose readers are all gone gets `-32`, `io::ErrorKind::BrokenPipe` in
   `std`, and no signal. Files as stdio are `Unsupported` (a file is not a
   kernel handle; a shell redirects by copying between a pipe and a file
   it opened itself).
5. **Outcome.** `wait`, `try_wait` (a one-tick bounded wait), `output`, and
   `wait_with_output` use the kernel's `wait` on the process handle. The
   exit status is the broker's encoding: the child's status, `-1000 -
   vector` for a fault, `-1` when killed; `code()` is `Some` only for a
   non-negative status. `kill` is the kernel's `kill`.

The spawn right is the personality's only execution authority. A parent
can withhold it from the children it starts:
`absd_runtime::process::deny_spawn_to_children(true)` makes later
`Command` children start with `SPAWN_NO_SPAWN`, so neither they nor their
descendants can start anything (a server can use this for untrusted
sessions).

## The child's filesystem view

A parent with a block handle gives every child it starts from a file a
read-only duplicate in the `fs` role; the child's runtime mounts it
read-only before `main`. A write through the view fails in the filesystem
library (`ReadOnlyFilesystem`) and, beneath it, in the kernel (`-1`), so
the exclusive-writer rule (the platform's `docs/FILESYSTEM.md`) is
untouched: the writer stays the one process init gave the read-write handle
to. A mount that fails leaves the child without a filesystem.

The view is the filesystem's last commit when the child mounted it. It is
coherent only while the writer does not free and reuse blocks the view
still refers to: a parent that deletes, truncates, or replaces a file a
running child is reading can make the child read reused blocks. Short-lived
commands mount at start and are done before the parent writes again;
anything longer-lived needs the file server (below), not this.

Lending the writable view to a child is refused: `Command` has no way to
ask for it. A child that must write gets a file server channel instead
(an `fsd` boot, below); there the server, not the view, is what a
session reads through, so no reader can see blocks reused under it.

## File server

A read-only view is not enough once a session must write, and two
processes that each link the filesystem library over one writable device
destroy it (the platform's lane-D measurements: lost updates, block
aliasing, unmountable superblock pairs). So in an `fsd` durable boot
the file server is the active filesystem writer, and clients reach storage
through it over pipes. Init retains its read-write block handle and NIC
handle. In a served boot it regrants the block handle to the file server's
finalize run after the original server ends and the orderly drain succeeds.
Exclusive writing depends on this trusted init sequence; it is not a
kernel-enforced single-holder rule (audit B4; REPAIR.md section 7). The kernel
knows nothing of files here either: it provides pipes, the handle rights
on them, and `pipe_info`.

**Boot.** `durable=N net fsd` (`DURABLE_OPTIONS="net fsd"`, the image in
`FILE_SERVER_ELF`, catalog program `file-server`, 38). Init
(`run_durable_fsd`) refuses the boot without a file server image, with a
broker policy, or with a reader. It mints the control channel and
`FILE_SERVER_SLOTS` (10) client slots before anything starts, because a
handle can reach a process only when it is spawned: each channel is a
request pipe and a reply pipe, split into ends. Then:

- the file server is started without the spawn right with
  `[startup, block (read-write), (request reader, reply writer) per
  channel, console]`, roles 4, 13, 14; its console is init's own, so its
  lines go straight to the serial log;
- init closes its copies of the server ends and starts the worker (sshd)
  with `[startup, input, step, nic, (request writer, reply reader) per
  channel, console]` and the spawn right: no block handle, no `fs` view;
- init closes its copies of the client ends. From here the worker's copies
  are the only source of client ends in the system.

Init supervises the worker as a network worker (an hour in a qualification
boot, none in a served boot; orphan reaping).
If the file server ends while the worker runs, init ends the worker and
the boot fails (`file server ended while the worker ran`). When the
worker ends, the control channel's last writer is gone, the server reads
end of file there, commits, and exits; init reports `FILE SERVER OUTCOME
pid=N status=S` and requires status 0 and no live descendant.

**Channels are capabilities.** The server keeps, per channel, a record: a
mount list (subtrees, each read-only or read-write) and an open-file
table. A client names paths and its own table's handle numbers; the server
resolves paths under the mount list (lexically: `..` cannot leave it, and
there are no symbolic links) and refuses anything else. The control
channel's holder (sshd) binds a slot to a session's mounts (`BIND slot
{mounts} spares`) before starting the session's first process with that
slot's ends, and releases it (`RELEASE slot`) once that process has ended;
the server refuses any binding that includes `/ssh`. A session process
may bind one of its spares for a child, with its own mounts or fewer
(`DERIVE`). An explicit list must grant no more effective read/write access
at any path than the parent's longest matching mount: dropping a nested
read-only carve-out under a wider writable mount is refused. A broader
read-only overlay or a narrower subtree is allowed.

For namespace changes, a channel cannot rename either endpoint or remove a
directory that is a strict ancestor of one of its mounts (`-16`, busy).
This prevents the channel moving a nested read-only carve-out into a wider
writable mount. These are pathname permissions: another channel with wider
authority retains its own rights, and no object-identity binding is implied.

**Recycling a slot, and why `pipe_info` exists.** A slot must never carry
one session's authority to a process an earlier session started (an
orphaned grandchild still holding the slot's ends would get the next
session's files and could read its replies). End of file cannot say that
the earlier holders are gone: the keeper (sshd) must keep its own copy of
every slot's client ends to hand them to the next session, so the request
pipe always has a writer. The kernel therefore reports counts:

    pipe_info(RDI = pipe handle, RSI = 32-byte record, RDX = 0) -> 0

(syscall 36, `absd_abi::syscall::PipeInfo`: bytes available, space, and
the number of handles in every process with the read right and with the
write right). It needs only a handle to the pipe, whatever its rights,
never blocks, and moves no byte; `-9` for a stale or non-pipe handle,
`-14` for a record that is not writable user memory. The server binds a
slot only when its request pipe has one writer and its reply pipe one
reader (the keeper's) and no reply bytes are waiting, and a spare only
when the keeper and the session process are its only holders. `RELEASE`
withdraws the session's authority at once: whatever an ended session left
running is then refused (`-13`) until it ends, and the slot is bound again
only after that. `make smoke` checks the call (`PIPE INFO OK`: counts
across processes and duplicates, a rights-less handle, end of file,
refusals).

The counts are a snapshot, and the binding checks rely on only this:
while no process but the keeper holds an end with a right, none can come
to hold one. Handles reach a process only at spawn, copied from its
parent's table with no more rights than the parent's handle (`duplicate`
cannot widen either), so a new holder needs a live holder with the right,
which the count already includes; a child still being built counts too; a
child that ended has already released its handles (they are released at
termination, not at the parent's `wait`). Both pipes are counted, each for the right that uses it (write
on the request pipe, read on the reply pipe), so a process that kept only
one of the two ends is still seen. Two limits follow from counting
handles, not naming holders. A rights-less duplicate is not counted and
can do nothing but ask `pipe_info`, so a process an earlier session left
with one can watch the fill levels of the slot's next session (not its
bytes). And a spare's check counts two holders, not which two: it is
sound while the session process holds its copy, which the runtime never
closes; between the session process's end and sshd's `RELEASE`, a child
lent the session's own channel could rebind a spare a sibling still
holds, to the session's authority or less, never beyond it.

### Served boot and orderly shutdown

`durable=N net fsd served` (`DURABLE_OPTIONS="net fsd served"`) is the
same composition with its own lifecycle contract: **serve until told to
stop**. The kernel refuses `served` without `fsd` (`SERVED BOOT NEEDS
fsd`) and otherwise only forwards it to init as its own mode
(`INIT_MODE_SERVED_FSD`); the policy is init's. Qualification boots keep
theirs: the NIC worker's deadline (an hour, or `NET_WAIT_TICKS=<ticks>`
at `make durable-iso`, which a harness shortens to watch it act) still
ends a qualification boot with `external workload deadline`.

In a served boot the worker (sshd) has no deadline. The boot ends only
through the worker's own exit, which is a request to init:

| worker outcome | init |
|---|---|
| exit 0 | halt requested: the orderly end below |
| exit `SERVED_WORKER_RESTART_STATUS` (98) | restart requested: the orderly end below |
| any other exit, a fault, a kill after the generation is ready | fault during service: init attempts bounded service stop and child reap, reports pre-reset residue, then requests a whole-machine recovery reset while the generation's recovery streak is under the budget (below), and stops the machine with code 20 at the budget |
| the worker's or the file server's liveness cell unchanged for `SERVED_LIVENESS_TICKS` (60 000) after the generation is ready | the same fault path, named `served worker unresponsive` or `file server unresponsive` after one `SERVED LIVENESS STALE component=<sshd|fsd> idle_ticks= bound= sshd_idle_ticks= fsd_idle_ticks=` line; the file server is named when both are stale (docs/service-lifecycle-20261008/LIVENESS.md) |

In a served boot init also creates one kernel cell per essential service
before starting either, and hands each service a copy with read and write
rights through startup-record role 18 (`ROLE_LIVENESS`, docs/BROKER.md).
The services transition their cell once per loop pass. Once the generation
is ready, init reads both cells in its orphan-reap pass (every
`ORPHAN_REAP_TICKS`) and judges them with `program::ServedLiveness`: a
cell unchanged for the bound is the service's fault above; an interval
longer than `SERVED_LIVENESS_GAP_TICKS` between two of init's own passes
(init itself did not run: a stopped guest, a device wait inside the kernel)
prints `SERVED LIVENESS GAP ticks=` and is not judged. Before readiness
nothing is judged. Init releases both cells at the orderly end, so the
end-of-boot accounting is unchanged. The judgment is init's and uses
nothing new in the kernel; the contract and its qualification are in
docs/service-lifecycle-20261008/LIVENESS.md.

An orderly end begins once init has reaped the worker's exit 0 or 98:
init records the request at that moment, so a failure after it (in init's
handling of the worker's stream, of the file server, or of the drain)
finishes the orderly end and never takes the fault path (`SERVED RECOVERY
BEGIN`). Every orderly end prints exactly one `SERVED SHUTDOWN action=`
line (the shutdown line). It has exactly one of these terminal outcomes,
decided inside init's `end_served`; a requested halt never ends in a
reset, and nothing resets before the generation was ready:

| requested | observed | markers, in order | machine | QEMU status |
|---|---|---|---|---|
| halt | file server status 0, drained | `SERVED SHUTDOWN action=halt worker_status=0 file_server_status=F orphans_reaped=N drained=D` with F=0, D=true | init returns 0; end-of-boot accounting halts | 3 |
| restart | file server status 0, drained | `SERVED SHUTDOWN action=restart worker_status=98 file_server_status=F orphans_reaped=N drained=D` with F=0, D=true; `MACHINE RESTART ARMED pid=1`; `MACHINE RESTART` | init returns 0; accounting passes; reset | 0 under `ABSD_QEMU_REBOOT=exit` |
| halt | orphan alive after `SERVED_DRAIN_TICKS` | shutdown line (F=0, D=false), `SERVED SHUTDOWN UNREAPED adopted_child_residue=true`, `SERVED SHUTDOWN ESCALATED requested=halt reason=unreaped outcome=stop code=17`, `MACHINE STOP code=17` | `machine_stop` 17 | 71 |
| restart, ready | orphan alive after `SERVED_DRAIN_TICKS` | shutdown line (F=0, D=false), `SERVED SHUTDOWN UNREAPED adopted_child_residue=true`, `SERVED SHUTDOWN ESCALATED requested=restart reason=unreaped outcome=recovery_reset code=17`, `SERVED RECOVERY CENSUS ...`, `MACHINE RECOVER RESET pid=1` | `machine_recover` | 0 under `ABSD_QEMU_REBOOT=exit` |
| halt | orphan wait failed other than by timeout | shutdown line (F=0, D=false), `SERVED SHUTDOWN ESCALATED requested=halt reason=drain_wait outcome=stop code=17`, `MACHINE STOP code=17` | `machine_stop` 17 | 71 |
| restart, ready | orphan wait failed other than by timeout | shutdown line (F=0, D=false), `SERVED SHUTDOWN ESCALATED requested=restart reason=drain_wait outcome=recovery_reset code=17`, `SERVED RECOVERY CENSUS ...`, `MACHINE RECOVER RESET pid=1` | `machine_recover` | 0 under `ABSD_QEMU_REBOOT=exit` |
| halt | file server exit status not 0 | `FILE SERVER OUTCOME pid=P status=S`, shutdown line (F=S, N=0, D=false), `SERVED SHUTDOWN ESCALATED requested=halt reason=file_server_status outcome=stop code=18`, `MACHINE STOP code=18` | `machine_stop` 18 | 75 |
| restart, ready | file server exit status not 0 | `FILE SERVER OUTCOME pid=P status=S`, shutdown line (F=S, N=0, D=false), `SERVED SHUTDOWN ESCALATED requested=restart reason=file_server_status outcome=recovery_reset code=18`, `SERVED RECOVERY CENSUS ...`, `MACHINE RECOVER RESET pid=1` | `machine_recover` | 0 under `ABSD_QEMU_REBOOT=exit` |
| halt | file server not ended after `FSD_STOP_TICKS` | shutdown line (F=-1, N=0, D=false), `SERVED SHUTDOWN ESCALATED requested=halt reason=file_server_timeout outcome=stop code=18`, `MACHINE STOP code=18` | `machine_stop` 18 | 75 |
| restart, ready | file server not ended after `FSD_STOP_TICKS` | shutdown line (F=-1, N=0, D=false), `SERVED SHUTDOWN ESCALATED requested=restart reason=file_server_timeout outcome=recovery_reset code=18`, `SERVED RECOVERY CENSUS ...`, `MACHINE RECOVER RESET pid=1` | `machine_recover` | 0 under `ABSD_QEMU_REBOOT=exit` |
| halt | file server wait failed other than by timeout | shutdown line (F=-1, N=0, D=false), `SERVED SHUTDOWN ESCALATED requested=halt reason=file_server_wait outcome=stop code=18`, `MACHINE STOP code=18` | `machine_stop` 18 | 75 |
| restart, ready | file server wait failed other than by timeout | shutdown line (F=-1, N=0, D=false), `SERVED SHUTDOWN ESCALATED requested=restart reason=file_server_wait outcome=recovery_reset code=18`, `SERVED RECOVERY CENSUS ...`, `MACHINE RECOVER RESET pid=1` | `machine_recover` | 0 under `ABSD_QEMU_REBOOT=exit` |
| halt | worker reaped, then its stream failed (output held past `SERVED_POST_WORKER_OUTPUT_TICKS`, a console write or close error); file server 0, drained | `SERVED SHUTDOWN STREAM FAILED step=...`, `FILE SERVER OUTCOME pid=P status=0`, shutdown line (F=0, D=true), `SERVED SHUTDOWN ESCALATED requested=halt reason=worker_stream outcome=stop code=19`, `MACHINE STOP code=19` | `machine_stop` 19 | 79 |
| restart, ready | worker reaped, then its stream failed (output held past `SERVED_POST_WORKER_OUTPUT_TICKS`, a console write or close error); file server 0, drained | `SERVED SHUTDOWN STREAM FAILED step=...`, `FILE SERVER OUTCOME pid=P status=0`, shutdown line (F=0, D=true), `SERVED SHUTDOWN ESCALATED requested=restart reason=worker_stream outcome=recovery_reset code=19`, `SERVED RECOVERY CENSUS ...`, `MACHINE RECOVER RESET pid=1` | `machine_recover` | 0 under `ABSD_QEMU_REBOOT=exit` |
| restart, not ready | any of the above | shutdown line, `SERVED SHUTDOWN ESCALATED requested=restart reason=<reason>_before_ready outcome=stop code=<code>`, `MACHINE STOP code=<code>` | `machine_stop` with the reason's code | 71, 75, or 79 |

The shutdown line is `SERVED SHUTDOWN action=halt|restart worker_status=0|98
file_server_status=F orphans_reaped=N drained=D`; `F=-1` means the file
server did not end. Stop codes: 17 `SERVED_UNREAPED_STOP_CODE`,
18 `SERVED_FILE_SERVER_STOP_CODE`, 19 `SERVED_WORKER_STREAM_STOP_CODE`,
20 `SERVED_RECOVERY_BUDGET_STOP_CODE`, 21 `SERVED_RECOVERY_UNKNOWN_STOP_CODE`
(QEMU status `4 * code + 3`). `code` in the ESCALATED marker is the
reason's code (`program::ServedEndFailure::code`): the stop code when the
outcome is `stop`, and the same number, for the record, when it is
`recovery_reset`. `abi/src/program.rs`
(`served_end_escalation_never_restarts_a_requested_halt`,
`served_failure_after_a_request_finishes_the_orderly_end`) checks the
reason, code, outcome, and routing. A console write failure inside
`end_served` does not change the outcome. If the kernel refused init's
own stop, restart, or recover, init would print `SERVED SHUTDOWN
ESCALATION REFUSED error=E` and exit 99 without a reset; init holds all
three rights for the whole served boot, so that is unreachable by
construction, and it is not a qualified outcome.

An FSD fault or exit after the served generation is ready takes the same
recovery path. Init recognizes readiness only after the current generation's
complete SSH listener record (`SSH LISTENING port=P authorized_keys=K
preauth_per_source=S`, all decimal, with `K` not zero: a generation nobody
can log into is not ready); a startup failure before that record refuses
automatic reset with `SERVED RECOVERY REFUSED generation_not_ready` and
fails the boot. Readiness is a bounded limitation, not a witness: the
record is sshd's self-report on its captured output, not an observed
listening socket, and init does not parse `FSD READY`; file-server
readiness is only implied by sshd having mounted its filesystem through
the file server before it prints the record. This prevents an unchanged bad image or configuration from
automatically repeating a pre-ready reset. The fault path uses init's
machine recover right (`machine_recover`, below); the kernel consults no
PID and no boot mode. It is separate from the orderly `machine_restart`
arm above: it resets the whole
machine even if an adopted live child cannot be reaped. Its
`children_drained` report describes child wait results, not total process,
handle, frame, pipe, or filesystem reclamation. Completed filesystem syncs
retain their durability contract; unsynced file data may reflect a subset of
prior writes, and damaged committed metadata may cause the second mount to
refuse. The local qualification runs two post-ready sshd faults and two FSD
exits, each followed by a distinct ready boot and authenticated command;
they do not qualify a silent service stall or a kernel/device hang.

**Recovery budget.** The fault path resets the machine at most
`SERVED_RECOVERY_BUDGET` (3) times in a row. The count is kept on disk by
the file server, which charges it at startup, before `FSD READY`, in the
same place it checks the release record (`FSD RECOVERY seq=N streak=K
previous=none|ended|failed|not_ready`): the ledger entry already counts
the new generation as not ended, so no failing service has to record
its own failure. sshd repeats the streak before its listener record
(`SSH RECOVERY streak=K`, taken by the same probe as readiness) and
leaves a readiness fact before `SSH LISTENING`; the streak is cleared
only when the previous generation left sshd's requested-end fact (the
last act of an orderly `shutdown` or `reboot`), the file server's own
stopped fact, and init's completed fact, which the file server writes
in its finalize mode (`--finalize`, started by init with the block
handle after the drain succeeded: `FSD FINALIZED boot=`, `SERVED
SHUTDOWN FINALIZED status=0`, before `MACHINE RESTART ARMED` or the
halt). An unexpected sshd exit 0 therefore does not clear it, nor does
a requested end that escalates (codes 17–19), nor an sshd fault after
its requested-end fact. The ledger and its facts are fixed-size files
under `/var/state` overwritten in place, so a charge allocates nothing
and a full disk still serves; sshd reaches the ledger read-only and
writes only `/var/state/facts`, and the file server refuses either path
in any session mount list.
On a post-ready fault init prints `SERVED RECOVERY BEGIN reason=R
file_server_status=S` (`R` names the component: `served worker fault`,
or `file server ended while the worker ran` with the file server's
status), then with `streak < 3` the reset line `SERVED RECOVERY RESET
reaped=N children_drained=D streak=K budget=3
durability=completed_sync_only` and `machine_recover`; with `streak >= 3`
`SERVED RECOVERY ESCALATED reason=recovery_budget_exhausted streak=K
budget=3 reaped=N children_drained=D outcome=stop code=20` and
`machine_stop` 20 (QEMU status 83); with no streak advertised before
readiness `SERVED RECOVERY ESCALATED reason=recovery_budget_unknown
streak=unknown budget=3 reaped=N children_drained=D outcome=stop code=21`
(QEMU status 87). Three
resets are permitted; the fourth qualifying failure stops. The last
permitted generation serves normally until it fails; after the stop an
operator needs the console. Missing or corrupt ledger state on a disk
where it was once established is a pre-ready refusal (`RECOVERY STATE
REFUSED reason=lost|corrupt|uninitialized_ledger`, exit 3), never a
fresh count. The contract, its persistence assumptions and its
acceptance are in `docs/service-lifecycle-20261008/RECOVERY-BUDGET.md`;
the platform's `absd_fsd::recovery` and `scripts/survival-recovery.py`
implement and exercise it.

The chain of authority for an orderly end is session → sshd → init.
The operator asks from an authenticated SSH session (an `exec` of
`shutdown` or `reboot`, or the same words typed to the session's shell,
which forwards them on its session control channel, below); sshd's policy is that the operator identity may
ask, and sshd acts by ending its sessions and exiting with the status
above. No session process, and not sshd, holds a machine handle; sshd's
only machine-ending act is its own exit, which already ended the boot
before served boots existed. Init holds the machine handle and decides.

Order of the orderly end (the platform README, "SSH", has sshd's side):

1. sshd stops listening, tells each session, closes each session child's
   stdin once what the client sent before is delivered, gives the
   children a bounded grace to finish (their sessions close as usual:
   EOF, exit status, close), ends what is left, and releases every slot:
   the file server commits each released session's files.
2. sshd exits. Its control channel's last writer is gone: the file server
   commits everything and exits 0 (`FSD STOPPED`).
3. Init reports `FILE SERVER OUTCOME`, reaps the orphans the sessions
   left for at most `SERVED_DRAIN_TICKS` (20 s), and reports `SERVED
   SHUTDOWN action=halt|restart worker_status=S file_server_status=0
   orphans_reaped=N drained=true`; then, the end having completed, runs
   the file server once more in finalize mode to record that verdict for
   the recovery ledger (`FSD FINALIZED boot=`, `SERVED SHUTDOWN
   FINALIZED status=0`; a failure there is reported and changes nothing
   else). An orphan still running then cannot be
   ended by init (adoption grants no handle), so the end escalates (the
   table above), after the file server has committed: a requested halt
   stops the machine with `machine_stop` code 17 (QEMU status 71); a
   requested restart takes the recovery reset, which skips the
   end-of-boot accounting and so does not count the orphan as a failed
   boot.
4. Init exits 0; the kernel checks that every process, frame, cell, and
   pipe is back (`DURABLE WORKLOAD OK`, `ABSD BOOT OK`) and halts, or, if
   the restart was armed, prints `MACHINE RESTART` and resets.

In-flight writes: every write the file server acknowledged before it
stopped is committed (a released session's files at release, all others
at the final commit). For a writer that sshd ends after the grace, the
one request it was waiting on is indeterminate to it: the server performs
each request whole or not at all, and if it performed it, it is
committed; the writer never saw the answer. A process left running past
its session's release is refused by the file server from then on.

**Halt and restart under QEMU and on hardware.** A halt is the ordinary
end of a boot: QEMU's `isa-debug-exit` device with the success code
(status 3), or, with `halt-on-exit` or on a machine without that device,
`cli; hlt` with `ABSD HALT code=0` on the screen. It is not ACPI power-off:
the kernel parses no ACPI tables, so a physical machine stays powered
with its CPU halted. A restart writes the PIIX/ICH reset control register
(port 0xcf9, value 6), then pulses the 8042 keyboard controller's reset
line (0xfe to port 0x64), then triple-faults (an empty IDT and `int3`).
QEMU's i440fx machine resets on the first. Under the harness's default
`-no-reboot -no-shutdown` QEMU turns the reset into a shutdown request and
then pauses instead of exiting (the host timeout ends it);
`scripts/durable-boot.sh` with `ABSD_QEMU_REBOOT=exit` drops
`-no-shutdown`, so a restart ends QEMU with status 0, and with
`ABSD_QEMU_REBOOT=allow` also `-no-reboot`, so the machine really resets
and boots the same image again. On
physical hardware none of the three is tested.

### Machine authority

The machine is a kernel object (`Object::Machine`) reached only through a
handle. The kernel issues exactly one, to init, in every boot (init's
fifth entry argument, `R8`), with three object-local rights:
`MACHINE_RIGHT_STOP` (the kill bit), `MACHINE_RIGHT_RESTART` (the write
bit), and `MACHINE_RIGHT_RECOVER` (the wait bit). No other process holds
one unless init copies it:

    machine_stop(RDI = machine handle, RSI = code 16..=63)      syscall 37
    machine_restart(RDI = machine handle)                       syscall 38
    machine_recover(RDI = machine handle)                       syscall 40

`machine_stop` is the abrupt stop at a named point (QEMU status
`4 * code + 3`); `machine_restart` arms a reset for the end of the boot
and returns 0 (the end-of-boot accounting must still pass, or the machine
halts with the failure code); `machine_recover` resets the machine at
once, with no end-of-boot accounting and no process drain: the kernel
prints `SERVED RECOVERY CENSUS` and one `SERVED RECOVERY PROCESS` line per
occupied slot (the names predate the right; they describe what the reset
abandons in any boot), then `MACHINE RECOVER RESET pid=P`, and resets.
Each right is checked alone: restart does not imply recover, and recover
implies neither stop nor restart. The handle is the whole authority: no
call consults the caller's PID or the boot mode, and `make
machine-recover-test` qualifies that a child (not PID 1) of an ordinary
(not served) boot holding a recover-only copy resets the machine. `-9`
without a machine handle (none, a stale one, another kind, or another
process's value), `-1` without the right, `-22` for a code outside the
range. Every refusal is logged: `MACHINE REQUEST REFUSED pid=P error=E`. The boot-mode-gated `stop`
(syscall 28), which any process of a durable boot could call, is retired
and answers `-38`.

Init's policy: a qualification durable worker (without `fsd`) gets a copy
with the stop right only, by startup record role 15, because the crash
matrices stop the machine at named write points; `fsd` boots, served or
not, give the worker none, and a served boot's init keeps the recover
right for its own use; init never copies the recover right except to the
`machine-recover-test` probe; the suite checks the refusals
(`MACHINE RIGHT OK`) and closes it; the other modes close it at start.
The platform runtime's `stop(code)` passes the handle its record named,
or none. Why a handle and not a per-process attribute like the spawn
right: it names the object it acts on, narrows per operation (stop versus
restart), reaches a process only as an explicit copy, and is released
with its holder; a flag would be one more ambient bit that children
inherit unless someone remembers to clear it.

What was deliberately not built: handle passing over pipes, a wait on
many objects (the server blocks on one channel at a time for at most a
tick), per-file capabilities, revocation, and process-tree kill. Under
QEMU's TCG this `pipe_info` costs about ten times a trivial syscall
(about 2.6 ms against 0.2 ms, measured from a guest program), so the server
calls it only to check a binding, never to poll.

### Session control

An interactive session needs two things its standard streams cannot
carry: ^C must reach the shell even while the shell is not reading its
input (it is waiting for a command), and the shell must be able to ask
sshd for things only sshd decides (`shutdown`, `reboot`, a listing of the
session). Neither goes through stdin, which belongs to the commands the
shell starts. So sshd gives each interactive shell a **session control
channel**: two pipes it creates before it starts the shell (a handle
reaches a process only when it is spawned), whose shell-side ends are
roles 16 (events: read end, sshd writes ^C and answers) and 17 (requests:
write end, the shell writes requests). sshd keeps the opposite ends. The
runtime passes them only to the one child they were armed for and closes
the parent's copies of the child's ends right after that spawn; a process
that received them never passes them on (`std::process` gives a child only
what the parent names). An `exec` session gets none: its program is sshd's
own child, which sshd ends itself on ^C. The kernel knows nothing of
sessions here: it provides pipes, process handles, and timed waits. The
frames are the platform's (`ssh/src/control.rs`).

**Interruption without signals.** ^C typed on the terminal (sshd's line
discipline) becomes an interrupt event. The shell discards whatever waits
in the channel each time it reads a line (a ^C typed at the prompt is not
meant for the next command) and, while a pipeline runs,
alternates a one-tick timed `wait` on each child it has not reaped with a
timed read (at most 4 ticks) of the events pipe; on an interrupt it kills
every child still running with the process handle it holds, reaps them,
and prompts again (status 130). There are no signals, process groups, or
job control, and ending a child does not end the child's own children
(no process-tree kill): those are adopted by init and keep what they hold.

**Why a timed wait, not a wait on many objects.** The shell is the only
consumer that must wait on a child and a pipe at once; alternating bounded
waits costs at most a few ticks of latency in either direction and needs
no kernel change. Tripwire: a second real consumer that needs such
heterogeneous waits is the point to reconsider a native wait-on-any.

**Observation.** A session's listing (`ps` in the shell) is answered by
sshd for the session whose channel carried the request: the channel names
the session, so there is no way to ask about another. sshd names the one
process of the session it holds a handle to (its shell) and counts, with
`pipe_info` on the ends it keeps, any further holders of the session's
input pipe and file server channels (what an interrupted command's
children still hold). Kernel `info` is unchanged: it still answers only
for oneself and for handles one holds.

## File descriptors

Deferred. Every current consumer is a Rust `std` program, and `std`'s own
types (`File`, `ChildStdin`, `Stdio`, the standard streams) carry handles
directly; nothing needs integer descriptors. When a C/libc program or a
crate that insists on `RawFd` arrives, the descriptor table is a userspace
table over handles in the runtime, never a kernel object, and descriptor
numbers are a compatibility representation that must not weaken handle
staleness (docs/DESIGN-INFLUENCES.md, "Identity mapping").

## Checks

- Kernel: `make spawn-image-test` (above).
- Platform: `scripts/run-exec-matrix.sh` installs `echo`, `pwd`, `ls`,
  `cat`, `printenv`, `uname`, and the probe under `/bin` through the fixture
  importer, then runs the probe as the durable worker and prints `FS EXEC
  OK`, `ARGV ENV OK`, `CWD OK`, and `FS SPAWN OK` only when the whole
  captured stream matches, every image appears in the kernel's spawn log,
  the kernel reports `DURABLE status=0 frames=0 processes=0 cells=0
  pipes=0`, and the device holds the parent's write and none of the
  children's. `scripts/run-broker.sh` and `scripts/run-pipeline-matrix.sh`
  show the broker path unchanged.
