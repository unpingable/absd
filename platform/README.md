# ABSD experimental Rust `std` target

## What this is now (2026-10-10)

This repository is the ABSD platform: the `x86_64-unknown-absd` Rust `std`
target and everything built on it, pinned to one kernel commit by
`scripts/check-all.sh` (currently kernel `260b4a2`, the source-distribution
lane; the pair has not passed the gate yet). The sections below
are a lab notebook in the order the work was done; this summary states what
exists and how far each part is qualified (classes as in the kernel's
`docs/QUALIFICATION.md`).

- **Default (QEMU, UP):** the std target (rustc 1.95.0, `-Z build-std`, a
  staged sysroot), the runtime and its startup record (argv, environment,
  cwd, handles), the userspace filesystem library `absd-fs` (format 2, records
  `mtime`) and the file server `absd-fsd`, `absd-sh`, 22 native commands
  plus `absd-sh` and `sh-probe` (24), 8 ports (7 uutils plus ripgrep), 20
  manual pages, the operator image. `check-all.sh` hashes 57 artifacts and
  ends `ABSD RUST STD MATRIX OK programs=56`.
- **Experimental configurations (QEMU, UP, IDE for served boots):** `net`,
  `fsd` and `served` kernel boots; `absd-net` (smoltcp 0.14, static IPv4)
  over the e1000 frame driver; sshd on sunset; operation with the link down
  at boot or lost later (`LINK DOWN BOOT OK`, `NETWORK LINK OK`).
- **Demonstrated by test only:** the served recovery budget (three resets,
  then `machine_stop` 20; 21 when no streak was advertised; qualified by
  `scripts/survival-recovery.py`, outside `check-all.sh`); the platform on
  NVMe (`ABSD_BLOCK_ATTACH=nvme`, historic fs-matrix runs; the operator image
  is IDE-only); the U1 endurance *preparation* (`scripts/u1-endurance.py`,
  rehearsed, not a U1 acceptance).
- **Unqualified:** served boots on more than one CPU (the kernel refuses
  `served` with an AP; `u1-endurance.py` profiles B-D are declared
  unsupportable), anything on ARM64 (nothing here targets aarch64), halt and
  restart on physical hardware, any physical boot at all.

This isolated experiment builds a custom, experimental target from an
upstream compiler and its own published standard-library source:

- compiler: `rustc 1.95.0`, commit
  `59807616e1fa2540724bfbac14d7976d7e4a3860` (2026-04-14), LLVM 22.1.2;
- library input: the `rust-src` component installed under that toolchain
  directory, which is the published 1.95.0 distribution
  `https://static.rust-lang.org/dist/2026-04-16/rust-src-1.95.0.tar.xz`
  (SHA-256 `67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363`,
  as rustup's channel manifest for 2026-04-16 records it; its `version` file
  says `1.95.0 (59807616e 2026-04-14)` and its `git-commit-hash` is the
  compiler's commit). The tarball's `rust-src/lib/rustlib/src/rust` tree was
  compared file for file with the installed one (`diff -rq`, 2026-10-02):
  identical, `library/` and all. That is the durable identity: tarball URL,
  SHA-256, and rustc commit. The `1.99.0` in the
  `rustc-std-workspace-{core,alloc,std}` manifests is upstream's own
  placeholder (it is in the tarball), and the installed files' dates are
  install time; neither marks a later snapshot.

The build gate hashes the complete input snapshot before copying it. The
accepted snapshot contains 2,236 regular files and 45,837,761 bytes; its
deterministic content fingerprint is
`fcb80715180e5a9cc3179b032d2df540bfadb7a3ea35b04f02d4d97e5aafda3b`.
That fingerprint is the SHA-256 of the byte-sorted `sha256sum` manifest for all
regular files below `library/`. The compiler's complete `--version --verbose`
output and compiler binary are likewise pinned by SHA-256, and the accepted
source has no symlinks. These checks reject local source or compiler drift.
With `ABSD_RUST_SRC_TARBALL` naming a downloaded copy of the tarball,
`scripts/verify-inputs.sh` also checks its SHA-256 and that its `library/`
has the same fingerprint, and its `ABSD RUST INPUTS OK` line names the
identity either way. (The 77 files under `src/llvm-project/libunwind/` are
outside the fingerprint; the `diff -rq` above found them identical too.)

The kernel (`ABSD_KERNEL_SOURCE`) pins its own toolchain in
`rust-toolchain.toml` (1.98.0), which is not this compiler; a release records
that compiler's exact version and commit (`scripts/release_manifest.py`,
`[toolchain.kernel_rustc]`, resolved with `rustup show active-toolchain` in
the kernel checkout) and `scripts/reconstruct-release.sh` refuses a host where
it resolves to another.

The experiment does not modify the Rust toolchain or canonical ABSD kernel
checkout. `scripts/prepare-and-build.sh` copies the verified library snapshot
into disposable staging, requires `git apply --check` to accept the PAL patch
without fuzzy context matching, and builds the custom
`x86_64-unknown-absd` target offline. Patch line offsets are permitted only
after the complete input fingerprint matches.

`scripts/verify-inputs.sh` mechanically verifies the compiler and Cargo
binaries and verbose identities, full source-tree fingerprint, PAL patch,
target JSON and normalized target interpretation, Cargo build flags, linker
script, compiler wrapper, both lockfiles, vendored build crate, Pulse commit,
and retained input/oracle. `scripts/stage-library.sh` then verifies the exact
post-patch tree and reverse applicability. The library lock is checked in; the
build no longer resolves a new lock from whatever happens to be in the local
cache. See [PATCH_AUDIT.md](PATCH_AUDIT.md) for every carried hunk.

The PAL is deliberately narrow: UTF-8 startup arguments, handle-backed standard
input/output, process exit, and `System` allocator hooks. Threads,
`std::net`, and environment mutation remain on Rust's unsupported
implementations. The filesystem, the working directory, process spawn (from
a file, or through init's broker), and TCP through `absd-net` came later,
each with the workload that needed it (below). Signals have no API because this
target is not Unix.

The next-workload experiment adds one narrower randomness contract for ordinary
dependencies that use `getrandom` 0.3: the target opts into that crate's
upstream RDRAND backend. It is not a kernel syscall, a persistent entropy pool,
or a claim about physical media. The QEMU runner therefore pins an Intel vendor
identity and exposes emulated RDRAND; QEMU's default CPU has no acceptable
source, while its default old-family AMD identity is deliberately rejected by
the upstream backend's safety check. Rust `std`'s internal unsupported random
backend is unchanged.

The CRT adapts ABSD's multi-start ABI to Rust's language-start ABI. It validates
the initial stack alignment, direction/interrupt flags, and exact two-handle
startup vector, supplies one deterministic UTF-8 argument (`absd-std-probe`),
connects the first copied handle to stdin and the replacement console to
stdout/stderr, and uses the
existing anonymous-map allocator copied from `absd-user`. At that stage it
added no environment, filesystem, Unix file descriptors, signals, threads,
networking, dynamic linking, or Linux compatibility layer; the startup record
(argv, environment, cwd, "Spawning through init's broker"), the `std::fs`
backend ("Filesystem execution") and `absd-net` came later and are described
in their own sections. Signals, threads and dynamic linking are still absent.

The patch also removes target-specific dependency declarations for non-ABSD
platforms whose crates are absent from this host's offline Cargo cache. Those
manifest-only hunks are build-resolution scaffolding; they add no ABSD runtime
semantics and are unnecessary when building from a fully vendored Rust tree.
Cargo also insists on building `proc_macro`; because the local offline cache is
missing `rustc-literal-escaper` 0.0.7, this repository carries the compatible
0.0.5 source already vendored by the locally cached `proc-macro2` 1.0.107. That
crate is build-only and is not linked into either executable.

The custom target is a restricted standard-library target. Top-level binaries
opt in explicitly; for unmodified ordinary dependencies the compiler wrapper
injects the same gate only into ABSD target crates that actually link `std`.
It excludes the staged sysroot, host/build crates, and known `no_std` crates.
This is experimental compiler scaffolding, not an ABSD runtime semantic. The
Pulse replay libraries therefore retain
their existing `no_std + alloc` feature boundary, while the thin `pulse_std`
adapter uses ordinary `std::io` for input/output and the standard Rust `main`.
This keeps Pulse independent of ABSD and avoids an ABSD-specific Pulse fork.

## Terminology

Shared ABSD terms (process, task, handle, rights, cell, pipe, generation,
activation record, commit, recovery, and the layering rule) are defined in
the kernel's `docs/TERMINOLOGY.md`; this repository uses them unchanged.
Terms that exist only here:

- **Layout, region:** sector 0 of the block device describes fixed,
  bounded regions; every access is checked against its region.
- **Ledger:** the append region the Pulse journal's one file maps onto.
- **Generation slot, activation record:** two regions that hold whole
  replaced images, and the flushed record that selects one of them.
- **Event log, segment, checkpoint:** an append log split into reclaimable
  segments, with a checkpoint stored as a generation.
- **Filesystem commit:** the superblock write that switches the metadata
  image; a device error poisons the mount and the worker exits for
  replacement. A read-only mount goes through a read-only duplicate of the
  block handle.
- **Startup vector, startup record:** the ordered handles a program starts
  with, and the record on its first pipe that names their roles.
- **Step word, step cell, replacement worker:** the boot's workload
  selector, the cell carrying it, and the new process init starts for the
  next worker generation.

AG, Pulse, NQ, and Nightshift keep their own vocabulary (admission,
standing, custody, authority, evidence) in their patches, fixtures, and
markers. Those words describe the application, not the platform.

## Next real Constellation workload

The smallest current-source workload with exactly one new platform dependency
is AG's pure authority kernel at commit
`21c8da079f2465a2466c54431cc315699fc57cbe`. The copied source input remains
unmodified. `ag-primitives::LifecycleNonce::random` supplies a real daemon
lifecycle nonce through `rand`/`getrandom`; the workload then replays the four
AG books, admits an exact effect crossing, commits it, and reconstructs
process-local authority with `ag-kernel`. It emits:

```text
AG AUTHORITY RANDOM OK
NEXT REAL CONSTELLATION WORKLOAD OK
```

This selection avoids pretending that larger current components need only
stdio:

- Pulse runtime journal custody requires create-new, append, reopen/scan,
  metadata length, data/file sync, and parent-directory sync. Its transport
  custody additionally combines key-file custody, OS randomness, and UDP.
- Nightshift's observation resolver opens its canonical SQLite store read-only
  and may read binding paths. The writable runtime owns SQLite WAL/schema
  migration, so it is a persistence/SQLite/filesystem cliff.
- Docket `gwr-core`/`gwr-runtime` are pure but add no new platform semantic;
  `gwr-local` combines SQLite, filesystem artifacts, process execution,
  wall-clock identity, and signature glue.
- NQ protocol/profile code is pure and similarly adds no new platform
  semantic. NQ core/store/app currently couple admission to filesystem locks,
  SQLite, Unix helpers/processes, Tokio threads, timers, and sockets.

Accordingly this tranche accepts randomness alone and does not begin a false
filesystem or SQLite substrate. A real journal remains the first persistence
candidate, but only after ABSD has an honest durable-storage contract.

Run the deterministic probes against an isolated kernel clone (never the
canonical checkout):

```sh
git clone --shared "$ABSD_KERNEL_SOURCE" ../absd-kernel-std-run
scripts/run-probe.sh
scripts/run-pulse.sh
scripts/run-panic.sh
scripts/run-ag-authority.sh
```

Set `ABSD_KERNEL_RUN` when using a different disposable clone path. The run
scripts reject the kernel source itself (`ABSD_KERNEL_SOURCE`, as resolved
below).

**Profiles and inputs.** `scripts/inputs.sh`, which every script sources,
sets `ABSD_PROFILE`. `core` is ABSD alone: the kernel, this tree and
crates.io; it builds everything installed on an image and runs every matrix
that needs nothing else. `full` adds the extended integration programs
(`integration/`, `scripts/build-integration.sh`), which run other projects'
code on ABSD (Pulse, AG, Nightshift, NQ) and need those projects' sources at
the pinned revisions. `full` is the default in a development checkout and is
the gate as it has always been; `core` is the default in a source release,
names each extended step `NOT_RUN`, and ends with a different line, so it
cannot be read as the full gate. Nothing in the scripts or manifests names a
machine's paths: the kernel and the four workload sources come from the
environment variable (`ABSD_KERNEL_SOURCE`, `ABSD_PULSE_SOURCE`,
`ABSD_AG_SOURCE`, `ABSD_NIGHTSHIFT_SOURCE`, `ABSD_NQ_SOURCE`), for the
kernel `../kernel` in a source release, or an untracked
`../absd-inputs.local.sh`, a file of plain `NAME=path` lines that a
development machine keeps beside its checkouts; otherwise the script that
needs the input fails, naming the variable. An input may be a Git checkout,
read through its pinned commit, or a plain directory (a snapshot), checked
by the Git tree identity of its files against the pinned commit's tree. A
kernel snapshot must be the tree the release's `SOURCE-MANIFEST.toml` names
(`ABSD_ALLOW_MODIFIED=1` to test a changed one). The Rust
toolchain is `ABSD_RUST_TOOLCHAIN`, by default rustup's 1.95.0 under
`$HOME`. The root workspace reads Pulse and AG from staged copies beside
this tree (`scripts/stage-pulse-source.sh`, `scripts/stage-ag.sh`).

The complete clean reconstruction is:

```sh
scripts/check-all.sh
```

It enforces a storage gate, builds twice from clean output and compares all
57 output hashes (`ABSD RUST REPRODUCIBLE OK ... commands=24`), creates a
disposable shared clone at the pinned kernel commit (`kernel_commit=` in the
script; kernel main `2b4abb428e5020198848a5ed885077cbfa5aa93a` at this
writing), runs every
QEMU workload, and
removes its staging, targets, ELFs, host oracle build, and kernel clone on both
success and failure.

Run scripts use `set -eu`, so every check must be effective under `set -e`:
never write a bare `! cmd` mid-script (it never fails the script); write
`if grep -q X log; then echo "script: unexpected X" >&2; exit 1; fi`, and do
not pipe a command whose status matters into `grep` or `tee`.

The ordinary probe checks formatting, `String`, `Vec`, `Box`, arguments,
zero-length I/O, stdin and EOF, stdout/stderr, mapped-heap growth, stack growth,
aligned `System` allocation, free-list reuse, normal
`Result` termination, a monotonic `Instant`, the one-name filesystem
(`NotFound` for any other name and for `ledger` without a block device,
`Unsupported` for directories and removal), unsupported thread and network
errors, `Command` refusing a bare name and an unmounted path, and `/` as the
working directory. A second program calls `std::process::exit(0)` directly, and a panic
probe requires abort status 101 with complete resource reclamation. A small text
statistics program exercises ordinary `BTreeMap` application code. The Pulse
probe runs real Pulse source commit
`81c2354674990679f43be4f207349ff1b2429bc7` and compares all 29,302 output bytes
with the retained public demo report. The same trace is independently replayed
by the ordinary host `std` Pulse binary from that commit; its output must first
match the retained oracle exactly. The AG authority probe uses unmodified
current AG libraries and the explicitly selected RDRAND backend. All target
programs use ABSD's generic external-test, which also proves process, frame,
pipe, and handle reclamation.

The stdio PAL maps defined ABSD rights, not-found, would-block, out-of-memory,
invalid-input, handle-quota, broken-pipe, unsupported, and timeout failures to
corresponding `std::io::ErrorKind` values; unknown kernel results remain
`Other`.

## Real Pulse journal over native storage

`integration/src/bin/pulse_journal_std.rs` runs the unmodified `pulse-runtime`
`HistoricalJournal` (pinned Pulse `81c2354`) over ABSD's block device. The
platform grew exactly what that workload demonstrated it needs: a `std::fs`
backend with one openable name (`ledger`) over the runtime's append region,
`Instant` from the kernel tick counter, and CRT hooks for the block handle,
the step cell, and the abrupt `stop` syscall. `ctrlc` is replaced by a
no-signal substitute (`vendor/ctrlc-stub`) because `pulse-agent` links it;
`getrandom 0.2` (via `rand_core 0.6`) uses its explicit RDRAND fallback.

The runtime stays `Unbound`: v1 qualified-generation activation measures the
running executable and is qualified only on Linux, so the journaled
certificate events carry the judgment the real evaluator reaches without a
binding, and every restart obeys the restart law (`standing=Unknown`, no
evidence, no deadlines).

`scripts/run-pulse-journal.sh` drives `scripts/durable-matrix.py` against a
disposable kernel checkout: a fresh journal; abrupt machine stops at each of
Pulse's seven write stages of record 2, during the first record, and during
the third; append across a clean stop; content-mutation fixtures (garbage,
lost commit marker, payload flip, operator truncation); worker death after an
acknowledgement, after an unacknowledged synced commit, and mid-frame with
init's replacement worker resuming from the journal alone; and a bounded
append / stop / recover / replace stress loop. Each recovery boot classifies
every sequence `COMMITTED`, `ABSENT`, or `INDETERMINATE` and reports
`PULSE DURABLE JOURNAL OK` only when the scan projects and the recovered
runtime obeys the restart law. The failure model is abrupt loss of all guest
state with every device-acknowledged sector retained; host power loss is not
modelled. The stops go through `absd_runtime::stop`, which passes the machine
handle init gave the worker in its startup record (role 15, the stop right
only; kernel `docs/PROCESS-STARTUP.md`, "Machine authority"): the crash
matrices hold that right because init grants it to a qualification durable
worker, and no other process of the boot does.

## Bounded regions and replaceable generations

The block device now carries a userspace layout (`runtime/src/layout.rs`):
sector 0 describes bounded regions, and every region access is checked
against its own bounds before the device is touched. The Pulse ledger is one
region; the other consumer, the real AG authority state
(`durable/src/ag_image.rs`), lives in two equal generation slots and is
replaced by the two-slot protocol in `durable/src/generation.rs`: build the
candidate in the inactive slot, flush, header, flush, validate by read-back,
then one flushed activation record in the activation slot that does not
hold the newest valid record. Recovery selects the highest-sequence
activation whose generation validates against it, reports rollback and the
newest generation observed separately, refuses when nothing validates, and
never treats a generation number as evidence. A region may be reused only
when a fresh selection on the device no longer names it.

`scripts/absd_image.py` is the host's independent reader of that layout and
its own implementation of the recovery rule; `scripts/durable-matrix.py`
compares the guest's selection with it after every boot, mutates images
between boots, hashes each region to prove the two consumers never touch
each other's bytes, and runs the activation crash points, corruption and
rollback fixtures, reuse cycles, the composed worker/journal/generation
sequence, and the multi-region stress loop. Full listing:
`scripts/run-pulse-journal.sh`, part of `check-all.sh`.

## Event log with checkpoints (Route B)

AG's real store could not be ported without a filesystem: the pinned source
refuses any journal mode but WAL, fences its writer with `flock` on a lock
file, binds the database to inode and ownership, installs blobs by temp
file and rename, and enumerates directories for backups. So
`durable/src/eventlog.rs` and the `logstore` steps of the workload build the
same storage shape honestly: real AG admissions as events in four
reclaimable log segments (layout version 2), checkpoints as whole-image
generations, and the retirement rule that a segment may be zeroed only when
every event in it is at or below the checkpoint a fresh device selection
names. Recovery selects the checkpoint, requires the log suffix above it to
be contiguous, replays it through the unmodified `ag-kernel` books, and
refuses a trimmed log, a gap, interior damage, or a half-reclaimed segment
holding a newer record. `scripts/absd_image.py` applies the same composed
rule on the host and the matrix compares both after every boot:
`logstore`, `ckpt-matrix` (ten stop points), `ckpt-validity`,
`compaction`, and `agproc` (worker death and replacement composed with
checkpoints and machine loss).


## Filesystem and the real AG SQLite store

The Route B shape above was an honest substitute; the real AG store needs a
filesystem. `fs/` (`absd-fs`) is the smallest one that store demands, as a
userspace library over the layout's filesystem region (layout version 3
gives it the second half of the device). The kernel is unchanged. `std::fs`
reaches it through the runtime's storage hooks, and SQLite through a native
VFS (`sqlite/`). The bundled SQLite amalgamation compiles freestanding with
`SQLITE_OS_OTHER`, and its ~20 C library symbols come from `absd-sqlite` and
`absd-runtime`. AG's store is `git archive` of the pinned commit plus
`patches/ag-store-absd.patch`, which only swaps its Unix imports for a
platform seam (see [PATCH_AUDIT.md](PATCH_AUDIT.md)). Contract, layout,
identity, rename, lock, and VFS details: [docs/FILESYSTEM.md](docs/FILESYSTEM.md).

`integration/src/bin/ag_sqlite.rs` runs the real store through its daemon path
(`open_activated`, writer fence, custody checks, WAL, full sync): every
admission is the real four-book crossing recorded as a chained event with
its materialized books and admission commit, and the commit evidence is
installed as an immutable blob by temp file, no-clobber rename, and
directory sync. Recovery verifies the chain and replays every record through
the real books. `scripts/fs-matrix.py` (run by `scripts/run-fs-matrix.sh`,
part of `check-all.sh`) sweeps machine stops and worker deaths across the
exact filesystem write points of an admission and of the WAL checkpoint on
close, and covers lock exclusion and release, stale identity, a read-only
mount the kernel enforces, ENOSPC, ten corruption fixtures, and equivalence
with Route B for the same history. After every boot `scripts/absd_fs.py`,
an independent host reader of the format, extracts the database and WAL,
lets the host's own SQLite recover them, and recomputes the authority
digest the guest reported. `fs/src/tests.rs` enumerates every crash point
of each filesystem operation on the host.

## Spawning through init's broker

A process never gets the kernel's spawn right; a durable worker asks init
(kernel `docs/BROKER.md`). A startup vector of five or more handles carries
a startup record on its first handle: the CRT reads it to end-of-file,
refuses anything malformed with exit 102, and takes stdin, stderr, block,
step, the NIC, the request/reply channel and slots from the roles it names, runtime
argv (else the build-time `ABSD_PROGRAM_ARGS`), and a read-only,
policy-given environment for `std::env`. The two- and four-handle shapes are
unchanged. The codecs live in `broker/` (host-tested by `check-all.sh`).

`std::process::Command` then spends one slot per request: the program path
exactly as given, its arguments, no environment or working directory
(`Unsupported`). Piped stdio is the slot's pipes; null or inherited
stdout/stderr is drained while the parent waits; `output` reads both
streams with one-tick-bounded reads; `kill` is `Unsupported`. See
PATCH_AUDIT.md for the whole contract. `scripts/run-broker.sh` boots
`broker-requester.elf` as the worker under `broker-policy.txt` with
`broker-echo.elf` as the one permitted program, on a broker-mode kernel given
in `ABSD_KERNEL_RUN` (`check-all.sh` runs it against the kernel it pins).

## Networking: `absd-net`

The kernel (main, `docs/NETWORK.md` there) moves whole Ethernet frames
through a NIC handle and nothing more. `absd-net` (`net/`) is the protocol
stack a program links: smoltcp 0.14.0 with `alloc`, `medium-ethernet`,
`proto-ipv4`, `socket-tcp`, `socket-icmp`, and `auto-icmp-echo-reply`;
static IPv4 only (no IPv6, UDP, DNS, DHCP, or fragment reassembly). It is
`no_std + alloc` and usable from a `std` program. It is **not** behind
`std::net`: `std::net` stays unsupported, and a program uses this API
directly. A connection is a smoltcp socket inside the process; there is no
kernel socket.

A `net` durable boot hands the worker the NIC as startup-record role 12;
the runtime keeps it (`absd_runtime::nic::handle()`, with raw `info`,
`send`, `receive` there) and `NicLink::from_startup()` opens it (MAC from
`nic_info`; only a disabled NIC refuses to open, a link that is down does
not: a stack opened over it is complete, and on QEMU serves once carrier
returns with nothing re-opened; `Stack::link_up()` reads the live flag and
`Stack::disabled()` the fail-closed latch, which never clears in a boot.
Whether a physical NIC completes transmit descriptors without carrier is
an open per-device obligation recorded in the kernel's docs/NETWORK.md).
The API, for the SSH server:

- `Stack::open(link, Config)`: `Config::qemu_user()` is 10.0.2.15/24 via
  10.0.2.2 with 64 KiB receive and send buffers per connection.
- `listen(port, backlog 1..=8) -> Listener`; `accept(listener) ->
  Option<Connection>` hands out a connection whose handshake finished and
  refills the backlog. `connect(ip, port, local_port)` also exists.
  `unlisten(listener)` spends the handle: a later `listen` reuses the
  vacated table slot instead of growing the table, and a spent handle
  never names a live listener again.
- `recv(connection, buffer)`: `Ok(n)`, `Ok(0)` for nothing now,
  `Err(Finished)` after the peer's FIN, `Err(Closed)` after a reset or
  timeout. `send(connection, bytes)`: queues what fits, `Ok(0)` under
  backpressure. `send_room`, `send_queue`, `may_recv`, `state`, `remote`.
- `close(connection)` sends FIN after queued data, `abort` sends RST; both
  spend the handle, and the stack releases the socket when the close
  finishes (at most 30 s later). A connection that receives nothing for
  60 s is aborted, a passive idle one included;
  `disable_transport_timeout(connection)` opts an accepted connection out
  when the service enforces its own idle deadline (sshd does).
  `socket_count()`, `listener_count()`, and `stats()` report what is held.
- `poll()` runs smoltcp once at `boot_millis()`; `wait(max_ms)` blocks in
  `nic_receive` for min(smoltcp's `poll_delay`, `max_ms`, 10) ms, at least
  one tick, and keeps an arriving frame for the next `poll`. A link that
  fails instead of blocking (a disabled NIC answers at once) still waits
  out the bound on the local clock: the loop degrades to the idle cadence,
  never to a spin, and the failure is counted in `stats().link_errors`.
  Nothing else blocks. The loop is `poll`, serve connections, `wait(10)`.
- `divert(Some(ethertype))`, `raw_receive`, `raw_send`: frames of one
  EtherType bypass the stack (the matrix's control channel).

`net/src/tests.rs` (host, `check-all.sh`) runs two stacks over an
in-memory wire: 300 KB echoed through 8 KiB windows with uneven writes, the
same with every 13th frame dropped, 40 sequential connections with the
socket count back to the listeners each time, a reset, refusals of spent
handles, filtered peers, and bad configurations, the close and timeout
bounds (an unfinished close aborted after 30 s, and a connection aborted
after 60 s of inbound silence — stalled transmit, passive idle, or a
half-open backlog socket that is then re-listened), and a dead link's
bounded wait cadence.

`src/bin/netd_probe.rs` is the qualification workload and
`scripts/run-net-matrix.sh` (`scripts/net-matrix.py`) its matrix, on the
kernel `check-all.sh` pins in `ABSD_KERNEL_RUN`.
Step 1 plays raw frames over `-netdev dgram`: `ARP OK`, `IPV4 OK` (a
correct reply header; ten malformed or misaddressed packets unanswered
while the guest's frame counter rises by exactly ten), `ICMP ECHO OK`
(0..1472-byte payloads byte-exact). The same boot is then run with the
link set down over QMP before the kernel probes (`LINK DOWN OK`): the
worker reports ready with `link=down`, the wire stays silent, the harness
raises the link, the worker reports `NETD LINK UP` with nothing re-opened,
step 1 passes on that boot, and its frame counters equal the healthy
boot's. Step 2 uses `-netdev user` host
forwards and Python clients: `TCP LISTEN OK`, `TCP STREAM OK` (2 MiB echo
with random write and read sizes and a half-close, 1 MiB server-sent and
server-closed, a 32 MiB stream whose client stops reading until the host
writes stall and the guest's echoed count stops moving, then all of it
intact, and a reset), `TCP RECONNECT OK` (200 connections; no connection
socket left, heap pages unchanged since connection 20). Step 3 boots with
the kernel's `nic-ring-fault` injection (`DEAD NIC OK`): the device
disables itself at the first poll and two seconds of poll/wait then make
one pass per 5..=20 ms (neither a spin nor a stall), every pass a counted
link error, with `Stack::disabled()` reporting it. All four boots end
with `DURABLE status=0 frames=0 processes=0 cells=0 pipes=0`.

Inputs: smoltcp and its dependencies come from the local Cargo registry
cache, pinned by `Cargo.lock` (whose SHA-256 `verify-inputs.sh` pins);
Cargo checks each archive against these checksums:

| crate | version | SHA-256 (`.crate`) |
|---|---|---|
| smoltcp | 0.14.0 | `b6f8b28ad56c6e35524a37dd492af5d1a47e31e1a4d175cd12f89c075f01980f` |
| managed | 0.8.0 | `0ca88d725a0a943b096803bd34e73a4437208b6077654cc4ecb2947a5f91618d` |
| heapless | 0.9.3 | `25ba4bd83f9415b58b4ed8dc5714c76e626a105be4646c02630ad730ad3b5aa4` |
| hash32 | 0.3.1 | `47d60b12902ba28e2730cd37e95b8c9223af2808df9e902d4df49588d1470606` |
| stable_deref_trait | 1.2.1 | `6ce2be8dc25455e1f91df71bfa12ad37d7af1092ae736f3a6cd0e37bc7810596` |
| bitflags | 1.3.2 | `bef38d45163c2f1dde094a7dfd33ccf595c92905c8f8f4fdc18d06fb1037718a` |
| byteorder | 1.5.0 | `1fd0f2584146f6f2ef48085050886acf353beff7305ebd1ae69500e27c67f64b` |
| cfg-if | 1.0.4 (already locked) | `9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801` |

The lock also names `defmt` 1.1.1, `defmt-macros` 1.1.1, and
`defmt-parser` 1.0.0: optional smoltcp/heapless dependencies Cargo locks
but never builds here (the `defmt` feature is off).

## Real Nightshift on ABSD

Nightshift (pinned `e2675dd`, `git archive` plus
`patches/nightshiftd-absd.patch`, staged by `scripts/stage-nightshift.sh`)
builds as two ABSD programs, `nightshift-resolver.elf` and
`nightshift-writer.elf` (`scripts/build-nightshift.sh`). Its rusqlite links
a different `libsqlite3-sys` than AG's, so it builds in its own staged
workspace with its own lock (`pins/nightshift-absd.Cargo.lock`). Started
directly by init, each program's argv is fixed at build time through
`ABSD_PROGRAM_ARGS`; a brokered start can supply it at run time instead.

The fixture (`fixtures/nightshift/`, `NIGHTSHIFT_FIXTURE_ID
sha256:94ffea09…6661`) is produced on Linux by the real pinned writer and
the real pinned AG (`scripts/make-nightshift-fixture.sh`); no ABSD code
touches it. `manifest.json` binds the store bytes, the five AG requests, and
the Linux resolver's answers. The store reaches ABSD as an opaque byte
stream: `fixture_import` (a guest program) creates, writes, syncs, and
re-reads it through the real filesystem, and the host checks the imported
bytes with `scripts/absd_fs.py`.

`scripts/run-nightshift-matrix.sh` (part of `check-all.sh`) then shows, on a
kernel whose init runs a second durable process after the worker:

- the resolver, holding a block handle narrowed to read, answers all five
  requests byte-identically to Linux; the kernel refuses its write, and the
  image hash is unchanged across resolver boots;
- seven hostile stores (truncated, not SQLite, old schema, empty, missing
  row, page damage, pending WAL) get the same exit status and first error
  line as the Linux resolver;
- the writer, with no owner processes available (ABSD cannot spawn them),
  exits with Linux's status and Linux's refusal (a failed NQ spawn; the
  Linux twin's owner paths do not exist) and leaves a store byte-identical
  to the Linux twin's, which the Linux resolver reads;
- machine stops at Fibonacci write points counted forward from the
  writer's first write and backward from its last (its final commit,
  checkpoint, and WAL removal): each stopped store gets the same answer or
  refusal from the native and the Linux resolver before recovery, and each
  recovers to the Linux twin's bytes up to SQLite's file change counter.

A read-only mount opens without a WAL file: SQLite treats a missing WAL as
an empty one, so the VFS serves it as an empty volatile read-only file.
Linux Nightshift cannot open the same store in a read-only directory.

## Real Pulse present-support resolver on ABSD

Pulse's real `pulse-support-resolver` (crate `pulse-nq-load-support`,
pinned `81c2354`, `git archive` plus
`patches/pulse-nq-load-support-absd.patch`, staged by
`scripts/stage-pulse.sh`) builds for ABSD in its own staged workspace with
its own lock (`pins/pulse-absd.Cargo.lock`; `scripts/build-pulse.sh`). The
binary selects its role by argv[0] as on Linux; ABSD has no exec, so the
runtime gives an image its name at build time (`ABSD_PROGRAM_NAME`). Only the
resolver role runs on ABSD: the producer and receiver observe a Linux host
(`/proc/loadavg`, the Linux boot clock) and are refused. Nothing Linux is
relayed or imitated.

Support custody is bound to the observing host's boot clock. On ABSD that is
`pulse-absd-boot:sha256:<hex(sha256(boot id))>`, where the boot id is the
kernel's 16-byte per-boot identity (`SYS_BOOT_ID`, drawn from RDRAND once
per boot; the runtime's `boot_id()`), and the tick is milliseconds since
boot from the PIT counter (`boot_millis()`: divisor 1193, about 1000.15 Hz,
converted exactly and floored; one-tick resolution; it counts delivered
interrupts, so under emulation it can run slow against host time; it
restarts every boot). Receipts made on a Linux host are therefore never on
this clock, and the resolver answers `unknown` for them. That is the correct
answer, not a gap: `current`, `expired` and `contradictory` need receipts on
the ABSD boot clock, and no ABSD producer exists.

Two images are built. `pulse-support-resolver.elf` is the deployment build:
its configuration path comes only from `PULSE_LOAD_SUPPORT_CONFIG` in the
environment, which ABSD provides only through a brokered startup record;
without one it refuses exactly as Linux does with an empty environment.
`pulse-support-resolver-test.elf` is **test only**
(`--cfg pulse_absd_test_config`): the path `/pulse/support-config.json` is
fixed into the image and the environment is never read. It exists for
standalone qualification and is not a deployment.

The fixture (`fixtures/pulse/`, `manifest.json` with provenance) was made on
Linux by the real pinned, unpatched Linux producer and receiver under a test
deployment and a test key generated for it (the private key was discarded):
`scripts/make-pulse-fixture.sh`. `scripts/run-pulse-matrix.sh` then shows,
with init running the resolver as both the durable worker and the read-only
reader in each boot:

- the retained Linux receipts resolve to `unknown` with `evaluated_at` on the
  ABSD boot clock; the two runs of one boot share a clock id, two boots have
  two;
- an explicitly empty receipt directory resolves to `unknown` (Linux agrees);
- a malformed query, queries that do not match the configuration or their
  own id, and tampered receipts (signature, non-canonical bytes, derived
  state) are refused with exit 2 and the same first stderr line as Linux;
- the host reference (`tools/pulse-support-reference`: the same patched
  library, `resolve_with` with an injected clock) reproduces every native
  answer byte for byte at the native instant, matches it field by field on
  another ABSD-shaped clock (only `evaluated_at` and the `support_id` bound
  to it differ), reproduces the Linux resolver's answer byte for byte, and
  computes `current`, `expired` (including both edges) and `contradictory`
  for the receipts on their own clock;
- the device image is byte-identical across every resolver boot, and each
  run's write through its block handle is refused by the kernel.

## Real NQ-NG `diagnostics qualify` on ABSD

Nightshift admits an NQ artifact by running exactly
`nq --config C --json diagnostics qualify ID` (stdin closed; stdout one
`NqAdmissionProvenance`; nonzero exit is a refusal). That `nq` is NQ-NG
(pinned `8057441`, tree `13c0b6b3`), and it now runs natively: the real
binary crate (`crates/nq-app/src/bin/nq.rs` and the whole `nq-app` library
except the resident `nqd` server) over the real `nq-core`, `nq-store`,
`nq-profiles`, and `nq-protocol`, on Tokio's current-thread runtime.

The route is chosen by one constraint. `qualify` re-validates the store's
history against the profile digest compiled into the binary, and
`nq-profiles`'s build script computes that digest over the nq-profiles and
nq-protocol sources and every NQ manifest, `Cargo.lock`, and
`rust-toolchain.toml`. So `scripts/stage-nq.sh` applies
`patches/nq-absd.patch` to a `git archive` of the commit and refuses a patch
that touches any of those inputs; the patch changes only Rust sources in
nq-core, nq-store, nq-helper-sandbox, and nq-app (see
[PATCH_AUDIT.md](PATCH_AUDIT.md)). The build runs from a separate consumer
workspace (`nq/Cargo.toml`, staged as `absd-nq/`, lock
`pins/nq-absd.Cargo.lock`) whose one package is `nq-app` with its sources
taken from the staged tree and its own dependency declarations: Tokio with
`rt`, `macros`, `sync`, `time` instead of `full`, `nix` and
`tracing-subscriber` (used only by `nqd`) Unix-only, and the ABSD runtime
and SQLite VFS. The consumer lock resolves no version NQ's lock does not
pin (checked at staging). The digest the ABSD image compiles
(`nq-profile-digest.txt`, `sha256:b140f63b…afbc6`) equals the unpatched
Linux build's and the patched Unix build's (checked by the matrix). Two
residual differences are recorded, not hidden: the ABSD image is built by
rustc 1.95.0 (the only compiler the ABSD standard library supports) while
the hashed toolchain file names 1.94.0, and `nq-app`'s own manifest is not
the one the digest hashed. Neither is an input of the law-bearing crates.

The fixture store was admitted by a debug NQ build under the debug-only
same-identity helper exception, which NQ accepts only with debug
assertions on, so the ABSD release profile keeps debug assertions and
overflow checks on, like the Linux reference build.

`scripts/build-nq.sh` builds `nq.elf` with the fixture's qualify command
fixed at build time and `nq-unknown.elf` with a well-formed artifact id the
store lacks. `nq` reads its arguments only through `std::env::args`, so a
start through the broker, whose startup record carries runtime arguments
that replace the build-time ones in the CRT, needs no change to `nq`. On ABSD
`nq` first mounts the filesystem through a read-only duplicate of its
storage handle and observes the kernel refuse a write
(`NQ READONLY AUTHORITY OK`).

`fixtures/nq/` is the Linux reference NQ input: the store (a
`journal_mode=DELETE` copy), the artifact, the qualify-only config with guest
paths, and the Linux `nq`'s provenance, produced by
`scripts/make-nq-fixture.sh` on a synthetic host (`refhost`, account
`operator`). `scripts/run-nq-matrix.sh` (part of
`check-all.sh`) shows:

- the unpatched Linux `nq` and the patched Unix `nq` reproduce the reference
  provenance; native `nq` prints the same 1,659 bytes on two boots, and the
  device image is byte-identical before and after every `nq` boot;
- the same store in WAL mode without a `-wal` file qualifies natively (a
  read-only mount serves the absent WAL as empty); Linux `nq` refuses it in
  a read-only directory and qualifies it in a writable one;
- eight hostile inputs (unknown artifact, missing config, missing store,
  truncated, not SQLite, a one-byte change to the stored artifact, old
  schema version, foreign application id) get the same exit status and the
  same NQ error line on both; the only normalization is that an operating
  system's error description is compared by `io::ErrorKind`;
- a configuration naming a watcher does not load on ABSD (no account
  database), which is why no helper launch is reachable there.

It prints `NQ NATIVE PROGRAM OK` only when all of that holds. Not
covered: V2 and V3 provenance (continuity and origin intents), and a
source-id mismatch, which Nightshift checks, not `nq`.

## The Nightshift pipeline with real owner processes

The kernel's init now brokers spawning (kernel `docs/BROKER.md`): a durable
worker has no spawn right, and asks init for a program by exact path and
argv; init starts what its embedded policy permits, as its own child, with a
read-only block handle and a policy-given environment, and reclaims it when
the requester ends. On this side `std::process::Command` speaks that
protocol (`broker/`, the std patch), and `std::env` reads the policy's
environment. `scripts/run-broker.sh` checks the std side.

`scripts/run-pipeline-matrix.sh` (part of `check-all.sh`) then runs the
real Nightshift writer with its real owners as separate processes: NQ-NG's
`nq diagnostics qualify` and Pulse's `pulse-support-resolver`, over inputs
made on Linux by the real pinned tools from a real host observation
(`fixtures/nightshift-pipeline`, provenance in its `README-linux.md`,
produced by `scripts/make-reference-fixture.sh`). The
receipt is on a Linux boot clock, so the native Pulse resolver answers
`unknown`; that is the Linux reference's empty-receipts path. The native
store, normalized by the Linux side's normalizer, equals the reference, and
the read-only resolver's five answers agree with Linux. AG is not reached:
Nightshift calls it only on current support, which a foreign observation
cannot have here.

## ABSD as an observed host: frame pressure

The Pulse resolver above can only answer `unknown` on ABSD, because its
evidence observes a Linux host. This section gives ABSD its own observation
basis, so one bounded question can be `current` on ABSD itself. It does not
reuse Linux `/proc` semantics, it claims no equivalence with
`nq.host.load_pressure/v1`, and it is qualified on its own.

**The question** (`observe/question.v1.json`, `absd.host.frame_pressure/v1`,
ABSD-owned) asks: on this ABSD boot, when the kernel serves `frame_stats`,
is the frame allocator's headroom below one eighth of its capacity?

**The source.** Kernel syscall 35 `frame_stats` (on kernel main since the
observe lane merged) returns the physical frame allocator's free and
allocated counts, its allocation limit (none outside the kernel's own
exhaustion test), and the frame size. The kernel reads them with
interrupts disabled on its one CPU, so each reading is one exact allocator
state at one instant. The counts cover tracked frames only: frames the
memory map marked usable, below 256 MiB, minus the boot reservations. The
observing process's own frames count as allocated. The kernel keeps no
history, average, or rate. The runtime exposes the reading as
`absd_runtime::frame_stats()`.

**The profile** (`observe/profile.v1.json`, source basis
`absd_kernel_frame_stats_v1`) defines the state in exact integer
arithmetic:

- `capacity` = free + allocated, capped by the limit when one is set;
- `headroom` = free, capped by limit minus allocated when a limit is set;
- `present` iff `headroom * 1000 < capacity * 125`
  (`observe/threshold-policy.v1.json`); equality is `explicitly_absent`.

**Unavailable readings.** The producer emits no evidence, and the resolver
answers `unknown`, when:

- the kernel refuses the call;
- the frame size is not 4096;
- free plus allocated is zero, or the capacity is zero;
- allocated exceeds the limit.

No count is ever substituted.

**Clock and validity.** All custody is on the ABSD boot clock described
above. Support lapses 60 s of receiver boot clock after receipt, because
the reading is an instantaneous sample that every map and exit changes.

**The family.** `pulse.absd_host_frame_pressure.v1` is ABSD-owned and built
from Pulse's own code. `patches/pulse-absd-frame-pressure.patch` copies the
ported `pulse-nq-load-support` crate to `crates/pulse-absd-frame-pressure`
and changes only the family (see PATCH_AUDIT.md). `scripts/build-pulse-observe.sh`
builds three images in their own staged tree:

- `pulse-frame-pressure-cycle.elf`: the durable worker. It runs Pulse's
  `produce` and then Pulse's `ingest`, each with its own boot-clock read.
  Both run in this one process because ABSD has one writer per boot.
- `pulse-frame-pressure-resolver.elf`: `pulse-support-resolver`, the
  deployment build. It takes its configuration path only from
  `PULSE_FRAME_PRESSURE_SUPPORT_CONFIG`.
- `pulse-frame-pressure-resolver-test.elf`: the resolver for tests only,
  with `/observe/support-config.json` fixed into the image.

On Linux the family's producer and receiver are refused, and its resolver
answers `unknown` for ABSD receipts.

**Qualification.** `scripts/run-observe-matrix.sh` (`observe-matrix.py`)
takes two kernel clones, one with `frame_stats` and one without. The host
only generates a test key and the configuration, then reads the device
back. It checks every native evidence frame independently:

- the evidence is exact JCS and carries the pinned identities;
- the ed25519 signature verifies on the host;
- the state, re-derived in Python from the raw counts, matches;
- the observation and receipt are on one ABSD boot clock;
- the expiry is the receipt time plus 60,000 ms.

The host reference (the family library, `resolve_with` with an injected
clock) reproduces each native answer byte for byte. In 21 boots it shows:

- **current on one boot:** evidence observed at 91 ms, received at 215 ms,
  resolved at 316 ms, expiry at 60,215 ms. The reference agrees at
  `expiry - 1` (current) and at `expiry` (expired).
- **expired on the same boot:** the worker holds for 61 s after receipt.
- **unknown on another boot:** the image is unchanged, and the deployment
  build without an environment refuses exactly.
- **contradictory:** the configuration expects `present` and the evidence
  is `explicitly_absent`.
- **present:** under `-m 32M`, with the worker holding 6000 real frames,
  free is 701 of 7001, so the evidence is `present` and the answer
  `current`.
- **unknown without a source:** on a kernel without the call (the matrix
  boots the older pinned kernel `bc97503` for this case) the producer refuses
  to start (status 103, `ABI REFUSED`, before any `frame_stats` call), leaves
  no evidence, and the resolver answers `unknown`
  (`ABSD SOURCE UNAVAILABLE REFUSED OK producer=103`).
- **three tampered receipts** (signature, flipped state, widened validity)
  and a wrong-subject query are refused with the reference's exact line.
- **torn files:** a truncated producer envelope makes the producer refuse,
  leaves no receipt, and the answer is `unknown`; a truncated receipt beside
  a good one makes the resolver refuse outright (it never answers from the
  rest of the store, and it stays refused until the file is removed).

**Not covered: NQ.** No NQ-NG profile exists for this question, and none
can be added from here. NQ-NG's profiles are compiled into `nq-profiles`
through a two-entry static registry, and every profile's semantic identity
hashes that crate's source. A new profile is therefore a change to the
separately owned NQ-NG, and it rotates every existing profile's identity.
`nq.host/v1` itself is defined over procfs and sysinfo(2), so reusing it
would claim Linux equivalence. So there is no NQ artifact for this
question. The resolver's diagnostic pins (`diagnostic_inputs_id` and
`artifact_ids`) are test pins, and Nightshift is not run on this family.

## AG's `ag-loopctl` natively, and the wall clock

AG's real `ag-loopctl` (pinned `21c8da0`) runs on ABSD standalone, as the
durable worker, with the subcommands the Linux reference ran: `init` and
`record-proposal`. It builds from its own staged tree
(`scripts/stage-ag-loopctl.sh`: `git archive` plus
`patches/ag-store-absd.patch` and `patches/ag-loopctl-absd.patch`) through a
consumer workspace (`ag/Cargo.toml`, lock `pins/ag-absd.Cargo.lock`), with
ring's build script taught to assemble its ELF x86_64 code for ABSD
(`patches/ring-absd.patch`); see PATCH_AUDIT.md. A durable worker runs the
arguments fixed at build time, so `scripts/build-ag-loopctl.sh` builds the
one source twice, `ag-loopctl-init.elf` and
`ag-loopctl-record-proposal.elf`.

AG reads `SystemTime::now`. ABSD now has a wall clock: the kernel's
`wall_clock` syscall (kernel `src/rtc.rs`) reads the CMOS RTC and std's
`SystemTime::now` returns it. Precision is one second (the sub-second part
is zero); the RTC has no time zone, so ABSD declares it UTC, which is what
QEMU's `-rtc base=utc` seeds from the host. A physical machine's RTC may
hold local time (machines set up by Windows) and drifts uncorrected; ABSD
cannot tell and never adjusts it. A refused reading makes `now` panic: no
time is invented. SQLite's own date functions still fail (the VFS has no
clock); AG does not use them.

`record-proposal` must call the runtime profile's pinned observation
resolver. AG checks the exact path and the digest of the bytes there, then
spawns it; ABSD executes no file, so the path is a name in init's broker
policy (`allow worker /ag/config/observation-resolver owner-1 read 0`) and
init starts the catalog image `nightshift-ag-resolver.elf` (the real
resolver with the Linux wrapper's arguments fixed in the image) as its own
child with a read-only block handle. The file at that path on the ABSD
filesystem is the same image, byte for byte; the harness proves it. AG's
execute-bit test has nothing to test on ABSD and is true there (the one
semantic seam of the port; PATCH_AUDIT.md).

`scripts/run-ag-native.sh` (`scripts/ag-native-matrix.py`, fixture
`fixtures/ag-native`, the Linux reference run `i-fresh-ag`) runs two
deployments of the same resolver, differing only in the default TTL fixed
in the image: `deployment` (one day, the reference's, built as
`nightshift-ag-resolver.elf`) and `short-ttl` (ten minutes,
`nightshift-ag-resolver-short-ttl.elf`). Its verdict does not depend on the
date:

- a Linux twin (the real unpatched Linux `ag-loopctl` and resolver in a
  private mount namespace, with an LD_PRELOAD shim that pins
  CLOCK_REALTIME and maps the pinned resolver path to the Linux resolver)
  first reproduces the reference run itself at its own paths and instants:
  the same `status` bytes and the same store row for row
  (`AG LINUX TWIN REFERENCE OK`);
- per variant, the real Linux `ag-loopctl seal-runtime-profile` seals the
  profile at ABSD paths; it differs from the reference's only in locators
  and the resolver identity;
- importer boots carry the deployment in as opaque bytes (the resolver
  image, 5.4 MB with its symbol table stripped, is created with its first
  third and completed by two appends, `fixture_import` steps 2 and 3,
  because streaming it through init's pipe in one boot does not fit init's
  120,000-tick worker deadline under TCG); the host reads the filesystem
  back and requires the resolver file to equal the catalog image
  (`AG RESOLVER IDENTITY OK`);
- `init` and `record-proposal` run as durable workers; exactly one process
  is brokered, the resolver, with a read-only handle, and it exits 0; no
  Docket, standing, executor, or boundary command starts. After the worker,
  init runs the same resolver image as the read-only reader on a request
  the Linux twin sent; its answer must equal the Linux resolver's
  (`AG RESOLVER ANSWER OK`, `AG NESTED RESOLVER OK`);
- the twin replays the native run at the native instants: exit status,
  stdout, `Error:` lines, and the AG store must be identical, and the Linux
  `ag-loopctl status` and `replay` must accept the native store
  (`AG LOOPCTL NATIVE OK path=...`, `AG STORE EQUIVALENCE OK`). On the
  current path the store records the native instant exactly, and the state
  is also compared with the reference: only `resolved_at_unix_ms` and the
  state digest binding it differ, and the store only in profile locators,
  instants, and chained digests (`AG REFERENCE EQUIVALENCE OK`). On the
  stale path AG refuses (`Error: observation is not fresh/current`, exit 1)
  and records nothing, so no output carries the instant; the twin replays
  at both ends of the host clock window around the boot, and both must
  agree with each other and with the native run.

The `deployment` variant is current until the reference's evaluation
instant plus one day (2026-10-11T23:16:28Z for the reference as produced)
and stale after; `short-ttl` has been stale since 2026-10-10T23:26:28Z, so
both paths are qualified within a day of producing the reference, and only
the stale path after the deployment's `fresh_until`.

AG measures a pinned file by reading it whole, so `record-proposal` holds
the 5.4 MB resolver image in memory. That needed two platform changes: the
runtime allocator now serves a request larger than one 256 KiB map call by
mapping adjacent chunks, and the kernel (merged to main) widens a
process's heap window from 4 to 32 MiB and its page tables from 8 to 32.
Those are resource bounds, not new semantics.

## Filesystem execution and the Unix-style startup

A process holding the kernel's spawn right runs programs from the ABSD
filesystem itself (kernel `docs/PROCESS-STARTUP.md`, which owns the
contract): `std::process::Command` reads the file at the program path
through the mounted filesystem and starts it with the kernel's
`spawn_image` (syscall 31), an image the kernel copies from the caller's
memory with the loader the catalog uses. There is no execute permission,
no interpreter or `#!`, no dynamic linking, and no PATH search (a bare
name is refused). The child's startup record carries argv (with the path
as `argv[0]`), the environment (the parent's with the `Command`'s
changes), and the working directory; `std::env::current_dir` and
`set_current_dir` work on the runtime's working directory, against which
`std::fs` resolves relative paths. The child gets a read-only view of the
filesystem (a read-only duplicate of the block handle its runtime mounts
before `main`), so the exclusive writer is unchanged; stdio may be piped,
null, inherited, or a pipe end the parent holds (`Stdio::from` a
`ChildStdout`, given with only the stream's right and consumed, closed in
the parent, by the successful spawn); `wait`, `try_wait`, `kill`, and
`output` are the kernel's. `absd_runtime::process::deny_spawn_to_children` starts later
children without the spawn right, and `merge_output_for_children` gives
later children with piped stdout and stderr one pipe for both (the SSH
terminal). A brokered worker keeps using init's
broker, unchanged. Integer file descriptors are deferred: every consumer
so far is a `std` program.

For this matrix the platform builds six small commands (the full `/bin` set is
24 commands plus 8 ports, "Commands under /bin"), `echo`, `pwd`, `ls`, `cat`,
`printenv`, and `uname` (`src/bin/`, stripped into `commands/`), and
`exec-probe.elf`. `scripts/run-exec-matrix.sh` (`scripts/exec-matrix.py`)
imports them under `/bin` with the fixture importer (the host reads them
back byte for byte), then boots the probe as the durable worker: it runs
the commands through `Command` with arguments, environments, working
directories (given, relative, inherited, changed with `set_current_dir`),
piped, null, and inherited streams, exit statuses, and `kill`; a command
starting further commands; a child's refused write (library and kernel);
a child without the spawn right; each refusal from `NotFound` to the
kernel's exact codes for mutated images; and the child's view of the
parent's file before and after the parent's sync. It prints `FS EXEC OK`,
`ARGV ENV OK`, `CWD OK`, and `FS SPAWN OK` only when the whole captured
stream equals `exec-expected.txt`, all 27 started images appear in the
kernel's spawn log, the kernel reports `DURABLE status=0 frames=0
processes=0 cells=0 pipes=0`, and the device holds the parent's file and
nothing a child tried to write.

## absd-sh, the minimal command shell

`absd-sh` (`src/bin/absd_sh.rs`; logic in `sh/src/lib.rs`, host-tested;
platform in `src/sh_host.rs`) is the session shell for the SSH server:
line-based; it knows nothing of terminals (on a PTY session sshd does the
echo and line editing). No existing shell fits (the Rust line editors and
shells need termios, fork, or libc), so it is written here and kept small.
A line is a list of pipelines joined by `;`, `&&` (the next runs if the
status is 0), and `||` (if not), run left to right; `exit`, ^C, and the
session's end stop the list. A pipeline is commands joined by `|`, each
with optional `< file`, `> file`, `>> file`, `2> file`, `2>> file`. Words
split on whitespace with `"..."` grouping (`\"` and `\\` escape inside
quotes; a quoted `|`, `<`, `>`, `;`, `&` is ordinary text). Builtins:
`cd [dir]`, `pwd`, `echo [-n]`, `exit [n]`, `status` (the last status),
`help` (the grammar on one screen); `pwd`, `echo`, `status`, `help` may
head a pipeline
(the shell writes their output into the next command's input) or take
`>`/`>>`/`2>`, `cd` and `exit` take neither. In a shell sshd started
for an interactive session, `ps`, `shutdown`, and `reboot` are builtins
that ask sshd on the session control channel (below, "Session control");
any other shell answers `no session control channel`. Anything else runs as a
filesystem executable through `std::process::Command`: the word as a path
when it contains `/`, else `/bin/<name>` (one fixed directory, no PATH).
The child gets the shell's working directory; a stream not piped or
redirected is the shell's own. A missing command reports `not found`
(127), a refused one `cannot run` (126), a non-zero exit of the last
command `exit status N`; a pipeline's status is its last command's. Syntax
errors (an empty command, `>` with no file, a stream redirected twice,
output both to a file and a pipe, `2>&1`, an empty list element, any
single `&` outside quotes) are status 2 and start nothing.
Without arguments it prompts `absd$ ` before every line and exits with the
last status at end of input; `absd-sh -c LINE` runs one line. No globbing,
variables, descriptor duplication, job control, scripting, or signals; ^C
in an SSH session ends the running line (status 130) through the session
control channel. Children inherit stdin, but lines the shell has already buffered are not
visible to them.

**Pipes.** A pipe is a kernel object with separately granted read and
write ends. For `a | b` the runtime makes the pipe when it starts `a` with
a piped stdout, gives `a` the write end, and closes its own copy of it at
once; the read end comes back as `ChildStdout` and is given to `b` with
`Stdio::from`, and `b`'s successful spawn consumes it (the `std`
personality closes the shell's copy then, not when the `Command` is
dropped; a refused spawn consumes nothing, and dropping it gives `a` a
broken pipe). Each child's copy carries only its stream's right (the
kernel refuses a write end offered as stdin). Once both run, `b` sees
end-of-file exactly when `a` is done and `a` gets a typed broken pipe
exactly when `b` is gone: the kernel's `-32` on the write, which `std`
reports as `io::ErrorKind::BrokenPipe`. There is no asynchronous signal
and no implicit inheritance of any other handle; nothing here emulates
POSIX descriptors or SIGPIPE. (A future Unix personality can number
native handles as descriptors entirely above the kernel; there is no
kernel descriptor table.)

**Redirection and authority.** The shell opens every target itself, with
its own filesystem authority, before anything starts, and never gives a
child a file: ABSD files are the `absd-fs` library's objects inside the
process that mounted them, not kernel handles. For `< f` the child's stdin
is a pipe the shell fills from `f`; for `> f`, `>> f`, `2> f` the child's
stream is a pipe the shell copies into `f` (`src/sh_host.rs`, the copier
writes through `std::fs`). The child holds exactly one pipe end per
redirected stream. The invariant: **the SSH session's authority is the
ceiling; the shell's authority is derived from it; a command's authority
is derived from the shell's and may only narrow.** A command whose stdout
goes to a file gains no authority over that file or any other. In an SSH
session the shell writes through the file server (below) with its
session's mounts, so `>`/`>>`/`2>` work under `/home/operator` and the
session's `/tmp/session-N` and are refused elsewhere before anything
starts (`absd-sh: F: cannot write: read-only here`, or `not found`
outside every mount; status 1). A started command gets, by default, a
spare file server channel bound to the shell's own mounts (a Unix-like
default: the shell's authority, never more); `ro CMD` gives it the same
mounts read-only and `nofs CMD` no filesystem at all. While the shell
copies a redirection it uses its own channel, so then no command borrows
it: each gets a spare or is refused. The redirection is the shell's
authority check; the child only ever holds the pipe.

`scripts/run-sh-matrix.sh` (`scripts/sh-matrix.py`, on a kernel with
`spawn_image`) installs the `/bin` commands, `/bin/absd-sh`,
`/bin/sh-probe` (`src/bin/sh_probe.rs`: `flood`, `count`, `head`,
`escape`), `/etc/motd`, and a 20000-byte `/etc/big`, then boots
`sh-launch.elf` as the worker, which holds write authority (children get
read-only views). It runs the shell from the filesystem on the scripted
session `sh-input.txt` (pipelines of two and three commands, 64 KiB and
20000-byte transfers, `<`, a writer whose reader exits early, refused
`>`/`>>`/`2>`, syntax errors) and as `absd-sh -c "ls /"`; then checks the
pipe discipline with negative controls (the shell's copy is closed by the
consuming spawn; a retained writer copy keeps the reader from end-of-file
until it is closed; a retained reader copy keeps the writer blocked until
it is closed and the writer then gets `BrokenPipe` and keeps running; the
raw write gets `-32`; a write end offered as stdin is refused and not
consumed); then runs the shell's executor in the worker, with the
worker's own write authority, for `>`, `>>`, and `2>` with a child that
tries to create another file, append to its own redirection target, and
write the block device. The captured stream must equal `sh-expected.txt`,
the kernel must log 32 image spawns with a zero accounting line, and the
device must hold exactly the redirected files and nothing a child or the
refused session redirections tried to write; then it prints `SHELL PIPE
OK`, `SHELL BROKEN PIPE OK`, `SHELL REDIRECT OK executor=writer-hosted`
(`>` works where the shell holds write authority; sessions refuse it), and
`SHELL AUTHORITY NARROWING OK`. `check-all.sh` runs the shell's host tests.

## Source portability: unmodified crates.io programs

[docs/COMPATIBILITY-LEDGER.md](docs/COMPATIBILITY-LEDGER.md) records how far
conventional source travels on this `std`. Nineteen published programs
(`compat/programs.tsv`: uutils utilities, ripgrep, b3sum, jsonxf, hexyl,
sd, jaq, xsv, fd) are built for ABSD from their registry archives with no
source change: `scripts/stage-compat.sh` appends only an ABSD-only
`absd-runtime` dependency and pins a lock that may add packages but never
changes an upstream pin, and `scripts/build-compat.sh` builds them with the
compiler wrapper's `ABSD_RESTRICTED_STD_ALL=1` mode (gate every crate that
links `std`, force-link the runtime). Ten build; nine fail, each at a wall
the ledger names and classifies (rustix first, then integer descriptors,
signals, a C allocator).

`scripts/run-compat-probe.sh` installs the ten under `/bin`, boots
`compat-launch` as the durable worker, runs the 25 cases of
`compat/cases.tsv` through `Command`, and compares each with the same
program built for Linux: 19 equal byte for byte, and the six in
`compat/divergences.txt` (b3sum's thread pool, `rg -j2`, rg's stdin probe,
one error message) must differ. It prints `COMPAT PROBE OK built=10 ran=9`.

## SSH: `sshd` on sunset

`ssh/` is an SSH server: sunset 0.6.0's sans-IO core (the protocol and
RustCrypto primitives; no SSH or cryptography is implemented here) driven by
a single-threaded loop over the network and each session child's pipes. It
builds from its own workspace and lock (`scripts/build-ssh.sh`, part of
`prepare-and-build.sh`) as `sshd.elf`, the file server `absd-fsd.elf`
and `absd-fsd-regenerate.elf` (the same server started with
`--regenerate-host-key`), and the matrix's helper `sshtest.elf`. The same sources build for Linux, where the matrix first
qualifies them as a reference.

sunset is the registry archive plus `patches/sunset-server-channel.patch`
(PATCH_AUDIT.md): upstream has no server call to end a session (EOF,
`exit-status`, close) and answers a client's EOF with its own at once. The
patch adds the three calls and stops the server echo; the server sends EOF,
`exit-status`, then close once the child's stdout and stderr have ended and
it has exited.

**Boot.** sshd is the durable worker of a `net fsd` boot
(`DURABLE_OPTIONS="net fsd"`, `FILE_SERVER_ELF=absd-fsd.elf`): init hands
it the e1000 NIC (startup role 12), the file server's control channel and
ten client slots (roles 13 and 14), and no block handle; with no broker
policy it keeps the spawn right. The file server (below) holds the block
handle. Init supervises it as a network worker: in a qualification boot
it runs for at most an hour (`NET_WAIT_TICKS`), after which init ends it
and the boot fails; in a served boot (`DURABLE_OPTIONS="net fsd served"`,
below) it runs until the operator asks for the end. Either way init reaps
an orphan once it ends; it has no right to end one (a session leaves none
unless its shell is killed before it can end its commands, below). The TCP/IP stack is `absd-net` in the same process;
sshd listens on port 22 (QEMU: `-netdev user,hostfwd=tcp:127.0.0.1:P-:22
-device e1000,netdev=n0`). The loop polls the stack, serves every
connection's runner, reads child pipes with one-tick bounded `transfer`s
(`std::os::absd::process::AsRawHandle` plus the runtime's
`read_within`/`write_within`), and otherwise sleeps in `nic_receive`
(at most 10 ms, 1 ms while a session runs). Auth and idle timeouts come from
`Instant` (defaults 30 s and 30 min); at most four connections, one session
channel each. On ABSD these, the port, and the address come from `/etc`
(below, "The operator image"); the flags `--auth-timeout-ms` and
`--idle-timeout-ms` remain for the Linux reference. While every connection
is taken, a further client's TCP handshake is still completed by the stack
(up to the listener's backlog, which equals the connection limit), but the
connection is refused at the transport boundary at once — reset with no
banner and no session slot, `SSH GLOBAL REFUSED` on the console — so stock
`ssh` reports the reset and exits 255 rather than waiting out a
`ConnectTimeout`.
A source address holds at most two unauthenticated connections at once
(`SSH PREAUTH REFUSED ... reason=source-limit` past that), so whoever can
reach the port (QEMU's forward binds 127.0.0.1, so that is a host user)
cannot hold every slot without authenticating; authenticated sessions do
not consume the per-source allowance but still count against the four.

**Entropy.** `getrandom` 0.4 with the target's existing
`getrandom_backend="rdrand"`: its upstream RDRAND backend refuses unless
CPUID reports RDRAND and the instruction passes its self-test. sunset draws
every ephemeral key from it and sshd the host key seed; nothing is seeded,
mixed, or generated here. sshd refuses to start without it
(`SSH ENTROPY OK source=rdrand`). The qualified source is RDRAND of QEMU's
pinned `-cpu max,vendor=GenuineIntel,+rdrand` model; on QEMU's default CPU
the backend refuses and so does sshd.

**Host key custody.** An ed25519 seed at `/ssh/host_ed25519_seed` on the
file server's filesystem. The file server creates it when it is absent
(or, built as `absd-fsd-regenerate.elf`, replaces it): 32 bytes from
RDRAND (`getrandom`), written to `host_ed25519_seed.new` create-new,
synced, and renamed over the seed (`FSD HOST KEY GENERATED|PRESENT`).
sshd reads it once at start through its control channel, whose mounts are
`/ssh`, `/bin`, and `/etc` read-only and `/var/log` read-write (`SSH
STORAGE VIA FILE SERVER OK block=none
control=/ssh:ro,/bin:ro,/etc:ro,/var/log:rw`), and keeps the key in memory.
It prints the key's fingerprint and public key in plain text on the console
(`sshd: host key 256 SHA256:... (ED25519)`, through the file server's
`NOTICE`, below) and in `/var/log/sshd`. No session binding
can include `/ssh` (the server refuses one that does): a session, and
anything it starts, cannot open, list, or reach it by `..`; the matrices
check this from exec commands, the shell, and the shell's children and
grandchildren. The seed is still an ordinary file to anyone holding the
disk image; the matrix's host verifies the key by reading the seed back
with its own filesystem reader and its own ed25519. sshd never gives its
control channel to a child (its runtime's default child policy is no
filesystem, and each session gets exactly its slot).

**Authentication.** Public key only, `ssh-ed25519` lines of
`/ssh/authorized_keys` (options or other key types refuse the whole file).
sunset verifies signatures; sshd compares keys. No passwords, keyboard
interactive, PAM, or accounts; the username is logged and not used. Six
refused attempts end the connection. The boundary this claims is exactly:
one operator identity (the keys in that file) gets bounded sessions. There
is no separation between users.

**Sessions.** `shell` starts `/bin/absd-sh`, with or without a PTY
(`pty-req` is accepted before `shell` or `exec`, below; `env` is refused).
`exec` splits the command on ASCII whitespace with no quoting and
runs the first word as a program (a bare name is `/bin/<name>`) as sshd's
own child; a program that cannot be started is reported as a shell would,
`sshd: <word>: <error>` on stderr and status 127 (not found) or 126. Running
exec commands directly, rather than through `absd-sh -c`, keeps every exec
process sshd's own child, so a client that disconnects mid-command gets it
killed and reclaimed at once, and gives it no spawn right. The exception is
a command using the shell's syntax (`|`, `<`, `>`, `;`, `&`, or `"`): it
runs as
`absd-sh -c COMMAND` with a shell's authority (the spawn right and spares),
so `ssh host 'cat > FILE' < local` works; that is the file transfer path
(below). Such a shell gets the session control channel like an
interactive one, so a disconnect ends its commands the same way (End,
below). Subsystems (so `sftp` and OpenSSH 9's `scp`), forwarding, agent
and X11 requests are refused.

A session child gets exactly: its three pipes (stdin, stdout, stderr), one
file server slot bound to the session's mounts (`/home/operator` and
`/tmp/session-N` read-write, `/bin`, `/etc`, and `/share` read-only; a shell also
gets up to two spare slots for its commands, fewer when sessions are
many: sshd keeps a slot and a spare free for every further connection it
may accept, so each of four simultaneous shells has at least one), the working directory `/`,
sshd's (empty) environment, and the spawn right and a session control
channel only when it is the shell. The shell starts its own commands
without the spawn right (`deny_spawn_to_children`, `src/bin/absd_sh.rs`):
a command cannot start programs, so a session is its shell and the shell's
children, and a kill right covers every edge.
The vector's final multi-start slot, which would be the console, is its
stdout pipe again (docs/PROCESS-STARTUP.md), so it has no console. It gets
no NIC, no block handle of any kind, no step cell, and no broker channel.
When its child has ended sshd releases the slot: the session's open files
are closed and committed, its `/tmp/session-N` is removed, and whatever
the session left running is refused by the server from then on. A release
ends the binding but discards nothing the session sent while it was
bound: a request already waiting on the channel is still read and refused
(`-13`), and bytes that break framing are still reported (`FSD CHANNEL
BROKEN`), before the channel goes quiet. The slot is bound to a new
session only once nothing but sshd holds its ends and that work is
consumed: a bind arriving before then is answered busy (`FSD BIND
DEFERRED`; sshd takes another slot) rather than discard it. The binding
then discards whatever predates it, so no request of an earlier session
runs under a later one. Ending a session (client disconnect, idle
timeout, shutdown grace over) never kills a shell first: sshd writes `END`
on its control channel, closes its input, and reads and drops its output;
the shell kills and reaps every command it runs and exits (`SSH SESSION
END pid=N sent=1 exited=true forced=false ms=T read=R`, R the
milliseconds until the shell read `END`). sshd kills the shell itself
only if it has not exited `END_GRACE` (1 s) after reading `END`, or has
not read it within `END_UNREAD_LIMIT` (10 s): a shell inside a program
load or a file server request reads it only when that returns, and the
file server may be busy with another session. A `forced=true` line is the
tripwire: the commands that shell was running can then outlive the
session. Init adopts them but has no right to end them; they run until
they end on their own (`INIT ORPHAN REAPED pid=N` then), each keeps the
file server channel it was given out of use until then, and a served
`shutdown` that finds one still running stops the machine (QEMU status
71) instead of halting, while a `reboot` records the escalation
(`SERVED SHUTDOWN ESCALATED ... outcome=recovery_reset`) and takes the
whole-machine recovery reset. A child without the channel (an `exec` program, no
spawn right, no children) is killed and reaped at once. The protocol and
its falsifying experiment are `scripts/contain-matrix.py` (below).

**Terminal (PTY).** Stock `ssh host` asks for a PTY and puts its own
terminal in raw mode, so something must echo and edit lines. That is a
line discipline inside sshd (`ssh/src/tty.rs`), between the channel and
the child's pipes; the kernel has no terminal object and none was added
(the session needs no isolation or lifecycle the pipes do not give). The
child is started as without a PTY, except that its stdout and stderr are
one pipe (below). Input is edited a line at a time and echoed:
CR or LF ends a line (the child reads `text\n`), DEL or BS erases one
character (a whole UTF-8 sequence), ^U the line, escape sequences
(arrow, function, and Alt keys: `ESC [ ... final`, `ESC O x`, `ESC x`)
are dropped whole without echo, other control
characters are kept and echoed as `^X`, and a line holds at most 4095
bytes. ^D on an empty line closes the child's stdin: a pipe has no one-shot
end of file, so this ends input for the whole session (^D while `cat` runs
under the shell ends `cat` and then the shell). ^C discards the line being
typed; if the session is an `exec` command, which is sshd's own child,
sshd also ends it (the kernel's parent-on-child kill) and the channel
closes without an exit status. In a shell session the running command is
the shell's child, not sshd's: sshd tells the shell (below), and the shell
ends it. Output: LF becomes CR LF. On a terminal
stdout and stderr are one screen, so a PTY session's child gets one pipe
for both (`absd_runtime::process::merge_output_for_children`: its stderr
slot is a second copy of its stdout writer) and sshd sends it as ordinary
channel data, in the order written; the shell's children inherit it. The
control characters are fixed: the terminal modes, `TERM`, and the window
size sent with `pty-req` are not read, and `window-change` is declined by
sunset (OpenSSH wants no reply), because nothing in a session uses them:
there is no environment for `COLUMNS`/`LINES`, no program that lays out
to a width, and no ioctl. No process groups, controlling terminal, job
control, termios, or pty ioctls. The SSH matrix drives stock `/usr/bin/ssh`
on a host pseudo-terminal (raw mode, keystrokes, exact screen bytes) and
prints `PTY ALLOC OK`, `PTY IO OK`, `SSH PTY OK`, and
`SSH INTERACTIVE SHELL OK`; it also resizes the client's terminal
mid-session and checks the session carries on, but prints no resize marker
because nothing uses the size.

**Session control: ^C, `ps`, `shutdown`.** An interactive shell (a
`shell` request, with or without a PTY) gets one more thing than an `exec`
program: a session control channel, two pipes sshd creates before it
starts the shell (handles reach a process only at spawn), passed as
startup roles 16 (events, sshd to shell) and 17 (requests, shell to sshd)
(`absd_runtime::session`; kernel `docs/PROCESS-STARTUP.md`, "Session
control"). The runtime gives them to that one child only and closes
sshd's copies of the child's ends right after the spawn; the shell never
hands them on. Frames are `ssh/src/control.rs` (host-tested): an
interrupt, a reply, the session's end (`END`), and the requests `MACHINE`
and `LIST`.

- ^C: sshd's line discipline discards the line and sshd writes an
  interrupt event. While a pipeline runs, the shell alternates a one-tick
  timed `wait` on each unreaped child with a timed read of the events pipe
  (at most 4 ticks, `CONTROL_TICKS` in `src/sh_host.rs`); on an interrupt
  it kills every running child with the handle it holds, reaps it, and
  prompts again with status 130. A ^C typed at the prompt only discards
  the line: the shell discards whatever waits in the channel each time it
  reads a line. (A first design tagged each ^C with the count of lines
  sshd had delivered; it failed in the matrix because a command such as
  `cat` reads lines too, so the shell's count and sshd's disagree.) The
  cost: a ^C that reaches sshd in the same keystroke batch as the Enter
  before it, before the shell has read that line, is discarded too. There are no signals, process groups, or job
  control, and no native wait on several objects: the shell is the only
  consumer that waits on a child and a pipe at once (tripwire: a second
  such consumer is the point to reconsider a kernel wait-on-any). A
  command has no children of its own (no spawn right), so none is left.
  Non-PTY sessions have no ^C; a shell without the channel waits on its
  children as before.
- End: the same kill and reap, then the shell exits without reading
  another line (`Host::ended`); what a redirection copied so far stays and
  is committed at release.
- `shutdown`, `reboot` typed to the shell: forwarded words, decided by
  `conn::machine_request` exactly as the `exec` below; the shell prints
  the answer and then sees its input end like every other session.
- `ps`: sshd answers for the session whose channel carried it and for no
  other (the channel is the session; the request names nothing). It names
  the process it holds a handle to, the shell (which has no command running
  while it asks), and counts with `pipe_info`, on the ends sshd keeps, any
  further holders of the session's input pipe and file server channels:
  `other holders: input N, file server channels M`, the leftovers of an
  interrupted command. Kernel `info` is unchanged.

The Linux reference sshd gives no control channel (its `/bin/sh` has pipes,
no terminal and no job control); these checks run against ABSD only:
`SSH INTERRUPT OK` (^C ends `sshtest sleep`, `cat` blocked on the session's
input, and a two-command pipeline blocked on a pipe; the shell survives,
prompts, and keeps its session; ^C at the prompt still discards only the
line; the interrupt latency is printed), and `SESSION LIST OK` (two
simultaneous shells each list exactly their own shell's PID, never the
other's; a nested `absd-sh -c` runs but its own start is refused, and
nothing is left to count).

**Served boot, shutdown, reboot.** A `net fsd served` boot serves until
told to stop (kernel `docs/PROCESS-STARTUP.md`, "Served boot and orderly
shutdown"). The operator tells it from any authenticated session:

    ssh -p P operator@host shutdown     # also: shutdown now, shutdown -h now, shutdown -p now
    ssh -p P operator@host reboot       # also: shutdown -r now

sshd takes these `exec` requests itself (`conn::machine_request`); no
program runs, and any other arguments to those words are refused with
status 2. The authority chain is session → sshd → init: sshd's policy is
that the operator identity (every authenticated session) may ask; sshd
acts only by ending its sessions and exiting, 0 for a halt, 98 for a
restart; init holds the machine handle and does the rest. No session
process holds any machine right (`/bin/sshtest stop` in a session: the
runtime's `stop` is refused `-9`, the retired `stop` syscall `-38`, and
each attempt is in the serial log as `MACHINE REQUEST REFUSED`). In an
interactive shell the same words go to sshd over the session control
channel (above) and are decided the same way.

What the operator sees: the requesting session prints `ABSD is going down
for halt: sessions are told and end, the file server commits and stops,
then the machine halts.` and exits 0. Every other session gets `sshd: the
system is going down for halt; this session ends` (stderr, or the screen
on a PTY) and its child's stdin closes after what the client already
sent: a shell, or a command reading its input, finishes and the session
ends with its status as usual. After 10 s (`SHUTDOWN_GRACE`) sshd ends
what still runs; that session closes without an exit status (OpenSSH
reports 255). New connections are refused from the request on (sshd
stops listening; the stack answers a SYN with a reset). The serial log:
`SSH SHUTDOWN REQUESTED`, `SSH SHUTDOWN GRACE OVER` (only if something
had to be ended), `SSH SHUTDOWN COMPLETE`, `FSD STOPPED`, `FILE SERVER
OUTCOME ... status=0`, `SERVED SHUTDOWN action=halt ... drained=true`,
`DURABLE WORKLOAD OK`, `ABSD BOOT OK`; under QEMU status 3. A restart adds
`MACHINE RESTART ARMED pid=1` and `MACHINE RESTART`, and the same image
boots again when QEMU may reboot (`ABSD_QEMU_REBOOT=allow` to the
kernel's `durable-boot.sh`); with `ABSD_QEMU_REBOOT=exit` QEMU exits 0
instead, and under the harness default `-no-reboot -no-shutdown` it
pauses until the host timeout.

In-flight writes: every write the file server acknowledged is committed,
a released session's files at release and the rest at the file server's
final commit. A command sshd ends after the grace may have one request
outstanding whose result it never saw; the server performed it whole or
not at all. A command a shell is running at the grace's end is killed by
its shell on `END`, so init finds nothing left and halts or restarts. If
something were left (a shell sshd had to kill, `forced=true`, or sshd
itself ending with sessions running), init records the escalation 20 s
after the file server stopped (`SERVED SHUTDOWN UNREAPED`, `SERVED
SHUTDOWN ESCALATED requested=... reason=unreaped`), storage already
committed, and then stops the machine with its own right for a requested
halt (`machine_stop` code 17, QEMU status 71) or takes the recovery reset
for a requested restart. A file server that fails or does not stop at the
end escalates the same way with code 18 (shutdown(8), and the outcome
table in the kernel's docs/PROCESS-STARTUP.md).

A failure *during* service (sshd or the file server ends, faults, or is
killed after `SSH LISTENING`) is not an orderly end: init resets the
whole machine, at most three times in a row. The file server keeps that
count in `/var/state/recovery` (`absd_fsd::recovery`) and charges it at
startup, before `FSD READY`, so no failing service records its own
failure; sshd repeats it before its listener record (`SSH RECOVERY
streak=K`) and leaves a readiness fact first. The count clears only when
sshd's requested-end fact (written as the last act of `shutdown` or
`reboot`), the file server's stopped fact, and init's completed fact
(the file server run once more by init in `--finalize` mode after the
drain succeeded) all name the previous boot; an end that escalates, or
an sshd fault after its request, leaves it uncleared; the fourth failure in a row stops the machine with `machine_stop`
code 20 (QEMU status 83, `SERVED RECOVERY ESCALATED
reason=recovery_budget_exhausted`); a post-ready failure in a boot that never
advertised its streak (`SSH RECOVERY streak=`) stops with code 21 (QEMU
status 87), and a ledger that cannot be read before readiness is a named
refusal (`RECOVERY STATE REFUSED reason=...`, no reset). This is qualified by
`scripts/survival-recovery.py`, which `check-all.sh` does not run. The ledger and facts are fixed-size
files overwritten in place (a charge allocates nothing; a full disk
still serves). sshd reads `/var/state` read-only and writes only
`/var/state/facts`, both on its control channel; the file server refuses
either in any session's mount list. `scripts/survival-recovery.py`
exercises the resets, the stop, the clear, and the exit-0 case; the
contract is the kernel's docs/service-lifecycle-20261008/RECOVERY-BUDGET.md.

Halt under QEMU is the debug-exit device; on hardware the CPU halts
(`cli; hlt`, `ABSD HALT code=0` on the screen) and the machine stays
powered: there is no ACPI power-off. Restart is the 0xcf9 reset register,
then the keyboard controller, then a triple fault; none is tested on
physical hardware.

`scripts/run-served-matrix.sh` (`scripts/served-matrix.py`) builds the
sshd boots with a 30 000-tick qualification deadline and prints `SERVED
BOOT OK` (a served boot serves past it, by guest ticks), `STOP RIGHT OK`,
`ORDERLY SHUTDOWN OK` (a shell mid-`cat > file` with its input open, an
idle PTY shell, and a never-ending command, closed; the host reads every
byte written), `LEFTOVER REBOOT OK` (`reboot` while a shell's command
never ends: the shell ends it on `END`, drained, restart), `REBOOT OK` (reset, same
image, the file written before is served after, halt on `shutdown`; and
exit 0 with `ABSD_QEMU_REBOOT=exit`), `SHELL SHUTDOWN OK` (the second
boot is halted by `shutdown` typed to a PTY shell, after refused forms
changed nothing; the `exit` variant's restart is `reboot` typed to a shell
without a terminal; both reach sshd on the session control channel), and
`QUALIFICATION DEADLINE KEPT OK` (the same deadline still ends a
qualification boot, status 7), `LINK DOWN BOOT OK` (a served boot whose NIC
link is down from the start serves once the link comes up) and
`NETWORK LINK OK` (link lost and restored after readiness without spending the
recovery budget).

## Storage for SSH sessions: the file server (`absd-fsd`)

Sessions write, several at once, and none of them holds a block handle.
One process, `absd-fsd` (`ssh/src/fsd_main.rs` over the `fsd/` crate),
holds the only read-write block handle of the boot and all mutable
filesystem state; init starts it before sshd and mints every channel both
will ever use (kernel `docs/PROCESS-STARTUP.md`, "File server"; the fired
tripwire and the revalidation in [docs/FILESYSTEM.md](docs/FILESYSTEM.md)).
A channel is a request pipe and a reply pipe; its record in the server is
a mount list and an open-file table, so a channel is a capability:

| channel | holder | mounts |
|---|---|---|
| control (0) | sshd | `/ssh`, `/bin`, `/etc` read-only, `/var/log` read-write; binds and releases slots; `NOTICE` |
| slot, bound per session | the session's first process | `/home/operator`, `/tmp/session-N` read-write; `/bin`, `/etc`, `/share`, `/var/log` read-only |
| spare of a session | a command the shell starts | the shell's, or fewer (`ro`, explicit lists) |

Paths resolve in the server, lexically, under the mount list: `..` cannot
leave it, nothing outside it exists for the client (`not found`), a
read-only mount refuses writes (`ReadOnlyFilesystem`), and the directories
leading to mount points list only the way down. No binding may include
`/ssh`. Every request runs to completion before the next, so all sessions
see one namespace: writes land in arrival order (the later wins for bytes
both cover, each `write_at` whole), `create_new` has one winner, rename is
atomic, locks are shared across channels. A file is committed when its
writer closes it, on `sync`, when its session is released, and at most
200 ms after an unsynced write. `/tmp/session-N` starts empty when bound
and is removed at release.

The protocol (`fsd/src/proto.rs`) is length-prefixed frames, one request
outstanding per channel; `runtime/src/fsd.rs` turns every `std::fs` hook
of a process with a channel (startup roles 13 and 14, no block handle)
into one exchange, and `std::process::Command` gives each child a spare
(bound by the server to the parent's authority or less), lends the
parent's own channel when no spare is free (the parent's own requests then
wait with `WouldBlock` until that child has ended), or gives it none. A
request body larger than a frame (a path of tens of KiB) is refused by
the client (`InvalidInput`) before anything is sent, since the server
could only stop reading that channel. The
server loop blocks at most a tick on one served channel at a time, streams
replies while the client drains them, and uses `pipe_info` only for the
binding checks. Measured under TCG with the kernel built at opt-level 2
(`scripts/run-perf-matrix.sh`): a stat round trip is about 0.2 ms, file
reads move about 3.9 MB/s, `cat` starts and returns to the prompt in
0.09 s and the 1.5 MB uutils `nl` in 0.45 s. With the kernel unoptimized
(before kernel c93a259) the same figures were 10 ms, 66 KB/s, 2.9 s, and
22 s: every syscall, pipe transfer, and switch cost ten to fifty times
more, which the 1 KiB pipes and 256-byte transfers multiplied.

`scripts/run-perf-matrix.sh` (`scripts/perf-matrix.py`) boots the command
matrix's image plus a 1 MiB file and times, in one PTY session, `cat`,
`basename`, and `nl` from Enter to the next prompt, and with
`/bin/fsd-probe` a 1 MiB read, a read of `/bin/nl`, 50 stats, and 50
one-byte pipe round trips (medians of three). Against `perf/baseline.json`
(the unoptimized kernel's figures) it prints
`FSD THROUGHPUT OK before=<KB/s> after=<KB/s>` only when the 1 MiB read and
the image read are at least five times faster, and
`COMMAND START OK native=<s> port=<s>` only when no command starts slower.

`scripts/run-fsd-matrix.sh` (`scripts/fsd-matrix.py`, needs the kernel's
`fsd` boot mode) boots sshd with the file server, installs
`/bin/fsd-probe` (`src/bin/fsd_probe.rs`) and `mkdir`, `rm`, `mv`, and
drives stock `/usr/bin/ssh` with strict host key checking; the host reads
the image back after each claim about the device. It prints `SESSION
WRITE OK`, `SYSTEM WRITE REFUSED OK`, `RAW BLOCK REFUSED OK`,
`SESSION WRITE PERSISTENCE OK` (reconnect and reboot), `SSH HOST KEY
ISOLATED OK`, `SHELL AUTHORITY NARROWING OK` (over SSH: a redirected `ro`
or `nofs` command writes nothing but its pipe), `SSH MULTI SESSION OK`,
`FS MULTI SESSION COHERENCE OK` (independent cwd and `/tmp`, simultaneous
reads, writes to different files, competing create-new and rename, a
session killed mid-write, one faulting while another writes, reconnect
after churn), and `SESSION FAILURE ISOLATION OK` (a session that breaks
its channel's framing stops only that channel, and the break is reported
even when the server reads it after the session's release; the slot
serves again). `scripts/run-fsd-release-load.sh` is the loaded form of that
last case, not part of `check-all.sh`: with CPU hogs pinned to the host CPUs
QEMU runs on (`taskset`; the guest itself is UP), many sessions write garbage
or a request and exit, and every one
must be reported or refused, with another session unaffected and every
slot rebound.
`check-all.sh` runs it after the SSH matrix, and the dispatcher's host
tests (`fsd/src/tests.rs`).

**Release identity and binding** (the design is `docs/RELEASE.md`
sections 2 to 4; the record and the compiled identity are the
`absd-release` crate, `release/`). After it has mounted, prepared its
directories and the host key, and swept scratch, and before `FSD READY`,
the server reads `/absd/selected` (one id, `[a-z0-9.-]+`, at most 64
bytes, and at most one newline) and the record `/releases/<id>/release`,
parses the record strictly (the header `absd-release 1`, `release`,
`kernel_abi`, `fsd_protocol`, `fs_format`, `app_abi` in that order, then
`check=`, the lowercase SHA-256 of every byte before that line; each line
ends in one `\n`), and compares every field to what it was built as
(`ABSD_RELEASE_ID` at build time, `dev` without it; generations 1, 2, 2,
1). It prints `RELEASE OK release=<id>`, or `RELEASE REFUSED
reason=<reason>` and exits 3, so init's pre-ready refusal ends the boot;
the reasons are `no_selected_release`, `malformed_selected`,
`no_release_tree`, `malformed_record`, `check_mismatch`,
`release_mismatch`, `kernel_abi_mismatch`, `fsd_protocol_mismatch`,
`fs_format_mismatch`, and `app_abi_mismatch` (a selection or record that
exists but cannot be read whole counts as malformed). From then on, for
the rest of the boot, every filesystem operation on a path at or below
`/bin` or `/share` goes to `/releases/<id>/bin` or `/releases/<id>/share`
(`Server::physical`); a listing of `/` shows `bin` and `share` as that
tree's. `/releases` itself is reached by no channel and no spelling: no
mount covers it, no directory listing shows it, and no binding or child
binding may name it (like `/ssh`). Everything else is site state.

**Who is serving** (`op::VERSION`, 23). Any channel, bound or not, may ask;
the reply payload is `u32 fsd_protocol`, `u32 fs_format`, `u16 length`, and
the release id, a constant of the server's build. Every process with a
channel asks on its own channel before `main` and waits at most 5000
ticks (about 5 s; a server that cannot parse the frame never answers,
and one older than the op answers `-95`); unless the protocol is its own
it prints one of `FSD PROTOCOL REFUSED server=<n> required=<m>`,
`... reason=no_answer`, `... reason=refused status=<code>`,
`... reason=no_server status=<code>`, or `... reason=malformed_answer`
and exits 104. sshd asks again on its control channel before it reads
anything through it, also requiring the server's release to be its own
(`... server_release=<id> required_release=<id>`), and prints `SSH
RELEASE OK release=<id> fsd_protocol=<n>`. Before either, every program's
runtime asks the kernel for its syscall ABI generation (`abi_version`,
syscall 42) and exits 103 after `ABI REFUSED kernel=<n> required=1` unless
it is 1 (`-38` from an older kernel). `release` prints the served
release's identity (release(1)).

Not built: SQLite over a channel (the VFS still mounts in its own
process), handle passing, a wait on many objects, per-file capabilities,
users or modes, revocation beyond releasing a slot, and a second server.

## Commands under /bin

The commands an SSH session finds under `/bin` are for looking after the
system from a shell, and each one does only what the mechanisms under it
really provide. Two kinds are installed:

- The platform's own small `std` programs (`src/bin/<name>.rs`, stripped
  into `commands/`): `echo`, `pwd`, `ls`, `cat`, `printenv`, `uname`,
  `mkdir`, `rm`, `mv`, `cp`, `head`, `tail`, `wc`, `sha256sum`, `stat`,
  `df`, `sync`, `date`, `uptime`, `release`, `sysinfo`, and `man` (below,
  "Manual pages").
- Unmodified crates.io programs from their registry archives, the ones
  the source-portability probe found to build and agree with Linux: uutils
  0.12.0 `basename`, `seq`, `cut`, `fold`, `nl`, `uniq`, and `base64`, and
  ripgrep 15.2.0 as `rg` (rg(1); the search tool, there being no `grep`).
  `scripts/build-ports.sh` builds them into `ports/` from the same staged
  trees and pinned locks as `scripts/build-compat.sh`, sized for the image
  (LTO, `opt-level=z`: about 30% smaller, 0.56 to 2.3 MB each), since
  every byte of a program crosses the file server when it starts. That
  cost is real: measured under TCG from typing to the next prompt
  (`COMMAND START SECONDS` of the command matrix, 2026-10-08, kernel
  4212fff, two runs), a native command takes 0.1 to 0.2 s, `basename`
  (0.56 MB) 0.3 to 0.4 s, `nl` (1.5 MB) 0.8 s, and `rg` (2.3 MB) 1.2 to
  3.2 s depending on host load (the figures were 2 to 4 s, 22 s, and 65 s
  before the kernel's opt-level and transfer work). They are
  installed because they are the real utilities; the bound is the file
  server's transfer path (1 KiB pipes, 256-byte transfers), not the
  programs. `rg` keeps ripgrep's two target-specific differences from the
  ledger: a piped standard input must be named as `-` (ripgrep's test for
  a readable stdin exists only for Unix and Windows, so a bare `rg
  PATTERN` searches `./`), and `-j2` on a directory is refused (`rg:
  unsupported platform`, status 2) because there are no threads; without
  `-j` it uses one. Files are read through the file server, never
  memory-mapped (memmap2's stub for this target fails, and ripgrep falls
  back). Only the flags the matrix below exercises are qualified.
  `build-ports.sh` stops ripgrep's build script from reading the git
  repository that encloses the staging area (`GIT_CEILING_DIRECTORIES`),
  so `rg --version` carries no host revision and the port rebuilds
  identically.

What each native command means here:

- `cp [-r] SOURCE DEST` or `cp [-r] SOURCE... DIRECTORY` copies bytes
  through the caller's own view, so it writes only where that binding is
  writable. Owners, modes, and times do not exist to copy, and the
  read-only flag is not carried. Copying a file onto itself (same
  filesystem id and object serial) or a directory into itself is refused.
  A file copy that fails part way (the filesystem full, say) removes the
  new destination it had created; a destination that already existed is
  reported as left incomplete, its old bytes gone. `-r` reports each
  object it cannot copy and goes on with the rest, keeping what it did
  copy.
- `head` and `tail` take `-n LINES` or `-c BYTES`; `tail` reads a file
  backwards from its end, so only the tail crosses the file server. There
  is no `tail -f`: nothing reports that a file grew.
- `wc [-l] [-w] [-c]` counts newlines, words (runs of non-whitespace
  bytes), and bytes; columns are right-aligned to the widest number
  printed (not GNU's width rule).
- `sha256sum [FILE...]` and `sha256sum -c LIST` use the `sha2` crate and
  GNU's line format.
- `stat PATH...` prints what the filesystem records: kind, size, the
  read-only flag, identity (filesystem id and object serial, never
  reused), links, and the mount of this session's binding that holds the
  path and whether it is writable here. No owner, mode, or times exist.
- `df` asks the file server for the filesystem's space (`SPACE`, op 21):
  data blocks from the format's geometry, blocks in use by the committed
  image or by accepted changes, free blocks, and the commit sequence on the
  device; then the session's mounts and their access. Every mount is a
  view of the one filesystem and every session shares its space: there
  are no quotas, and metadata lives in reserved regions outside the data
  blocks.
- `sync [-v]` asks the file server to commit everything it has accepted,
  from every session, and flush the device (`COMMIT`, op 22), and returns
  when that is done; `-v` prints the commit sequence now durable. Without
  it the server commits when a written file closes, when a session ends,
  and at most about 200 ms after an unsynced write. It orders nothing
  still in flight in another process.
- `rm` and `mv` refuse a mount point of the session up front (the server
  keeps mount points), and `rm -r` also refuses a directory with a mount
  point below it (`/home`, `/tmp`, `/`): it would otherwise empty the
  mount, which is writable, before the server refused the mount point.
  `rm` without `-r` refuses a directory. `mv FROM DIR` moves FROM into an
  existing directory under its own name, and a directory into itself is
  refused by name.
- For `ls`, `cat`, `cp`, `mv`, `rm`, and `mkdir`, options come first,
  `--` ends them, and an option the command does not have is a usage
  error (status 2), never a path. `cat -` reads standard input; `cat f |
  head` ends `cat` quietly when `head` is done (there is no SIGPIPE), and
  so for `ls`.
- `ls -l` adds kind (`d` or `-`), the read-only flag (`ro` or `--`), links,
  size. No owner or mode exists; the filesystem records a modification time
  (format 2, `mtime`), which `ls`, `stat` and `cp` do not yet show or copy.
- `date [-u] [+%s]` prints the kernel's RTC reading (`wall_clock`): UTC,
  whole seconds, never set or corrected; `uptime` prints the boot tick
  counter as days and time plus the raw ticks, and the kernel's boot
  identity (`boot_id`). Neither can set anything.
- `sysinfo` prints five lines, each a live answer at the moment it was
  asked and none from a log: the release (the file server's `VERSION`),
  this boot and its age (`boot_id`, the tick counter), the kernel's frame
  allocator (`frame_stats`, syscall 35: frames free and allocated, 4 KiB
  each, among the frames it tracks: usable memory below 256 MiB less the
  boot's reservations, so not the machine's RAM), the kernel's object census
  (`resource_census`, 41: process slots in use, handles, pipes, cells,
  across the system and counting `sysinfo` itself), and the filesystem's
  space as `df` reports it. A source that refuses is said so in place
  and the status is 1. Nothing names another session or process: no
  system-wide process list exists, and there is no per-process resource
  accounting to show.
- `release` prints `release=<id> kernel_abi=<n> fsd_protocol=<n>
  fs_format=<n> app_abi=<n>`: the release id, protocol, and format from
  the file server's `VERSION` answer, the two ABI generations this
  command was built for (the runtime has already found the kernel to
  match). `uname -r` prints the id the command itself was built as, and
  `uname -a` includes it.

**No editor, and why (2026-10-08 investigation).** A screen editor of
the vi family (nvi, levee, busybox vi, or a native vi-like program) is
blocked by the session, not by the filesystem:

- A program's only keyboard is its standard input pipe, and on a PTY
  session sshd's line discipline (`ssh/src/tty.rs`) sits in front of it:
  it delivers whole lines on CR or LF, echoes and edits them itself,
  turns ^C into a control-channel event and ^D into end of input for the
  whole session. There is no raw, cbreak, or no-echo mode in any form.
- Nothing tells a program the terminal's type or size: `pty-req` is
  accepted without reading its modes, TERM, or dimensions, and
  `window-change` is declined (ssh/src/conn.rs). A program cannot tell
  keyboard input from piped data (`IsTerminal` is always false); the
  kernel has no terminal object and no right for one (its handle rights
  are write, wait, read, kill).
- The C editors need a C runtime ABSD does not have (termios, signals,
  curses or termcap, fork for `!`); Rust terminal crates stop at rustix
  (`docs/COMPATIBILITY-LEDGER.md`).
- Output is not the obstacle: only LF becomes CR LF, and escape sequences
  pass through, so a screen could be drawn; it could not be read from.

A screen editor therefore needs a raw pass-through mode in sshd's
session and a way to learn the window size: a session-protocol and
authority design, not a user-tools change. An `ed`-class line editor
needs none of that (commands on standard input, output on standard
output, `ed FILE < script` works) and could be a native program over
`std::fs` with the atomic write path the file server already gives
(`create_new` a sibling, `sync_all`, `rename` over the target); no Rust
`ed` is a crates.io binary the ports mechanism could take unmodified. It
would edit `/home/operator` and the session's `/tmp` only (`/etc` is
read-only in a session), ^C would kill it with its buffer, and `!cmd`
would be impossible (commands cannot spawn). That is the next editing
step, not started here.

`df` and `sync` need the file server: a process with no channel (`nofs`)
is told so. Neither op needs more authority than a bound channel: `SPACE`
reports the one filesystem's totals, the same for every session, and
`COMMIT` makes durable only what the server had already accepted.

Not provided, on purpose (`scripts/cmds-matrix.py` checks each is absent):

- `/bin/ps`, `kill`, `top`: the kernel's `info` covers a process itself
  and its own children, and a `/bin` command is a child of the shell, so a
  `/bin/ps` could only list itself. A list of other processes would be a
  new kernel mechanism and a new authority decision (parentage,
  supervision, and sponsorship are separate graphs). `ps` is instead a
  shell builtin that sshd answers for the asking session only (ps(1),
  "Session control" above); `kill` stays the parent's alone.
- `chmod`, `chown`, `touch`, `ln`: no modes, owners, times, or links exist.
  (The one permission, the read-only flag, has no command yet.)
- `mount`: bindings are the file server's, fixed per session by sshd.
- `env` with a command, `b3sum`, and the uutils `wc`, `head`, `cat`,
  `sort`: bare-name `PATH` search is deferred (so `env CMD` could not
  start `CMD`); b3sum always builds a thread pool; the uutils four stop at
  rustix (docs/COMPATIBILITY-LEDGER.md). (`rg` was on this list until
  2026-10-08 for its stdin divergence and its size; it is installed now
  with that divergence documented, since a search tool is worth 2.3 MB.)

`scripts/run-cmds-matrix.sh` (`scripts/cmds-matrix.py`) installs the whole
set with fixtures on a 32 MiB image, boots `net fsd`, and drives an
interactive shell on a host PTY with `/usr/bin/ssh`: every command against
its exact expected output (errors included; for `rg`: one file, several,
a tree, stdin as `-`, a pipeline into `wc`, a binary file with and without
`-a`, no match, a missing path, a bad flag, no pattern, `/ssh`, a `nofs`
child, and `-j2`); writes by `cp`, `mkdir`,
`mv` (between the session's two writable mounts), and `rm`, then the host
reads the device; refusals into `/bin`, `/etc`, `/ssh`, mount points,
through `ro` and `nofs` children, and from a second session into the
first's `/tmp`, with `/bin`, `/etc`, and `/ssh` unchanged on the device;
`sha256sum` against the host's hashlib; `sync -v` against the commit
sequence the host reads, `df` against the image's geometry and block
references, and `sysinfo` against uptime, release, df, and the kernel's
frame arithmetic. It prints `COMMAND OUTPUT OK`, `COMMAND WRITES OK`,
`COMMAND REFUSALS OK`, `COMMAND SPACE OK`, `COMMAND ABSENCES OK`,
`MAN PAGES OK pages=...` (below), and `COMMAND SET OK names=...`.

## Manual pages

The operator's manual is real `mdoc(7)` source in `man/NAME.S`: intro(1),
absd-sh(1), date(1), man(1), ps(1), release(1), rg(1), sysinfo(1), uptime(1),
ata(4), e1000(4), nvme(4),
network.conf(5), sshd.conf(5), filesystem(7), handles(7), process(7),
afterboot(8), reboot(8), and shutdown(8). ABSD has no roff: `scripts/render-man.sh`
(run by `prepare-and-build.sh`) lints each page with `groff -mdoc -ww -z`
(any warning fails), renders it on the build host with
`groff -mdoc -Tascii -P-cbou -rHY=0 -dAD=l` (plain printable ASCII: no
escapes, no overstriking, no hyphenation) into `manpages/catS/NAME.0`, and
writes the index `manpages/whatis` from each page's `.Nd`. The renderer is
GNU groff 1.23.0 (Debian groff-base 1.23.0-3build2); `verify-inputs.sh`
pins its binaries, its whole macro and font tree, and the site macro
files, and `check-all.sh` requires the two builds' rendered trees to be
identical. `scripts/ssh_absd.py` installs the pages as
`/share/man/catS/NAME.0` and `/share/man/whatis` in every SSH image, and
sshd binds `/share` read-only into every session.

`man` (`src/bin/man.rs`) is a native command that only locates and copies:
`man [SECTION] NAME` prints the first of `/share/man/catS/NAME.0` in the
section order 1, 8, 6, 2, 3, 5, 7, 4, 9 (or only the given section);
`man -k WORD` prints the index lines containing WORD, ASCII case ignored.
No pager (pipe through `head`/`tail`), no options, no `MANPATH`. A name
that is not a page name (a path, `..`) is refused with status 2, a missing
page with `man: no entry for NAME in the manual` and status 1, and a
process that cannot see `/share/man` (under `nofs`) says so instead of
reporting every page missing.

Pages describe only what the qualified `net fsd` boot does, and label what
is not provided yet. Per-command pages exist for absd-sh, date, man, ps,
release, rg, sysinfo and uptime; the other commands and sshd(8) are not
written.

The command matrix drives it over SSH: on the PTY `man intro`,
`man 7 handles`, and four more pages print exactly the host-rendered
text; pages whose examples contain the prompt (`absd-sh`, `afterboot`,
`man`) are compared through `| sha256sum`; every page is also compared
byte for byte from an exec session (`ssh host man afterboot`); the
refusals above, `man -k`, and writes into `/share` (refused) are checked,
and the device's `/share` must be exactly the rendered tree before and
after. It prints `MAN PAGES OK pages=...` only then.

## The operator image

One deployment is the operator's: `scripts/build-operator-image.sh`
(`scripts/operator_image.py`) builds it and `scripts/boot-operator.sh` boots
it; afterboot(8) is its guide. The test matrices keep building their own
images; this one carries no test helper.

- `OUT/absd-operator.iso`: the kernel at the pinned commit
  (`ABSD_KERNEL_RUN`), init, `absd-fsd`, and `sshd` as a `net fsd served`
  durable boot.
- `OUT/absd-operator.img`, 64 MiB: `/bin` (every native command, `absd-sh`,
  the eight ports: seven from uutils and ripgrep), `/share/man`, `/etc/network.conf` and
  `/etc/sshd.conf` (`operator/etc/`, or the files of `--etc DIR`), and
  `/ssh/authorized_keys` (`--authorized-keys`, ssh-ed25519 lines only). It
  is written by importer boots (`fixture-import.elf` steps 1 and 2; the
  site files in a boot of their own) and read back whole by the host's
  reader before the build succeeds. The first boot adds `/home/operator`,
  `/tmp`, `/var/log`, and the host key (generated by the file server; see
  "Host key custody").
- `OUT/MANIFEST`: platform and kernel commits, the ISO's and every file's
  SHA-256.
- `--reconfigure --etc DIR [--authorized-keys KEYS] OUT` replaces those files
  on the halted machine's image whole, one commit each (importer step 4:
  `PATH.new` written, synced, checked, renamed over `PATH`), keeping
  everything else. It is the only way `/etc` changes: sessions see it
  read-only, so no session can lock the operator out.

`boot-operator.sh OUT [PORT]` runs QEMU in the foreground (RDRAND CPU, the
ISO, the disk on IDE, e1000 on user networking with 127.0.0.1:PORT
forwarded to the address and port the image's `/etc` files name, which the
host reads from the image), the serial console in `OUT/console.log`, and
exits 0 when the machine halts; a reboot boots the same image again.

**Configuration** (`ssh/src/etc.rs`, host-tested). sshd reads
`/etc/network.conf` (`address`, `netmask`, optional `gateway`) and
`/etc/sshd.conf` (`port`, `max-connections` 1-8, `login-grace-time`,
`idle-timeout`, `max-auth-tries`) through its control channel at start:
`keyword value` lines, `#` comments, each keyword once. A missing file is
the built-in defaults (QEMU user networking; 22, 4, 30 s, 1800 s, 6). A
malformed file (unknown keyword, duplicate, missing or extra value, out of
range, an address that is not a host of its network or a gateway outside
it, non-printable bytes, over 4 KiB) refuses the start: sshd prints the
file, line, and reason on the console and exits 1, and the served boot
fails (QEMU status 7). No default ever replaces a value the operator wrote.
At every start sshd prints what it uses and where it came from. There is no
general configuration framework: two files, one reader, one process.

**Console lines from sshd.** sshd has no console (init relays its stderr
as hex-framed `EXTERNAL OUTPUT CHUNK` records, the qualification format),
so the few lines an operator must read before any session exists (the
configuration in use or refused, the host key fingerprint and public key)
go through the file server: `NOTICE` (op 34, control channel only, at most
400 bytes, non-printable bytes shown as `?`) makes `absd-fsd`, which has
init's console, print the line as is.

**Logs.** Each process that logs writes its own file under `/var/log`
through the ordinary filesystem; there is no log daemon. `absd-fsd` writes
`/var/log/fsd` into its own filesystem (its start with the boot identity,
host key, ready, bindings and releases, broken channels, stop; per-command
`FSD DERIVE` stays on the console, so a command's start never writes the
disk); sshd writes `/var/log/sshd` through its control channel (every line
it logs; `ssh/src/oplog.rs`), queued in memory (at most 16 KiB, then lines
are dropped and counted) and written once per pass of its loop, the file
kept open so the file server's idle commit covers it. Lines are
`YYYY-MM-DDTHH:MM:SSZ PROGRAM: TEXT` (the RTC's UTC second, `-` if the kernel
refuses a reading; at most 512 bytes; printable ASCII). Bound
(`fsd/src/log.rs`, host-tested): a log that would pass 64 KiB is renamed to
`NAME.0` (replacing the previous) and restarted, so each keeps at most
128 KiB, the newest lines; a write the filesystem refuses (full) drops the
line, and the next line written first says `log: N lines dropped`. Clients
add lines before they authenticate (the connection, the user name, a
refused key), so a run of connections can rotate older lines out. Every
line also still goes where it went before (the console). Sessions get
`/var/log` read-only. Init's lines and everything before the file server
starts are console-only (init holds no channel and starts first).

**File transfer.** One path, over stock OpenSSH's exec: `ssh host 'cat >
FILE' < local` (the shell's redirection copier writes the file through the
session's own channel; committed when `cat` ends) and `ssh host cat FILE >
local` (sshd's own child, bytes through the session's stdout pipe). Both
are byte-exact for binary data without a PTY. No `scp`/`sftp`: sunset
passes a subsystem request, but serving SFTP would be a new server, and
OpenSSH 9's `scp` speaks SFTP.

**Time.** `date` and `uptime` (above, "Commands under /bin"). The
filesystem records a modification time per object since format 2
(docs/FILESYSTEM.md), but `ls`, `stat` and `cp` do not yet show or copy it.

`scripts/run-operator-matrix.sh` (`scripts/operator-matrix.py`) builds the
image with the documented script and non-default `/etc` files (address
10.0.2.20, port 2200, three connections, 20 s login grace, 45 s idle
timeout), boots it with the documented boot script, and drives it with the
host's `/usr/bin/ssh`, `ssh-keyscan`, and `ssh-keygen`. It prints
`HOST KEY FINGERPRINT OK` (the console's plain fingerprint equals
`ssh-keyscan | ssh-keygen -lf -` and the host's own ed25519 over the image's
seed; the console's public key line, trusted as is, connects under strict
checking), `ETC CONFIG OK` (each setting observed acting: the forward to
10.0.2.20:2200, a raw connection dropped at 20 s, a fourth client refused
outright at the global cap of three (`SSH GLOBAL REFUSED`; a connection is
admitted or ended, never queued), a silent session closed at 45 s),
`FILE TRANSFER OK` (0 B to 1 MiB of every byte value up and down, `>>`,
refusals, the host reads the files after shutdown), `DATE UPTIME OK` (inside
the host's clock window; the boot identity changes on reboot), `LOGS OK`
(stamped lines, read-only to sessions, survive reboot, `tail`, rotation to
`sshd.0` at the bound), `OPERATOR IMAGE OK` (exact contents, boots, serves
the command set and manual, halts with status 0), and
`ETC CONFIG MALFORMED REFUSED OK` (a malformed `sshd.conf` and
`network.conf`, each put in place with `--reconfigure`, stop the boot with
the file, line, and reason in plain text; replacing the file recovers).
