# Retained kernel diagnostics

`src/kernel_log.rs` owns a static boot-scoped ring of 128 complete records,
each containing at most 480 message bytes and a 16-byte source. It needs no
heap or filesystem. Records have a commit sequence, optional monotonic timer
ticks, severity, source, and truncation/partial/emergency flags. The first
Rust console output is retained; firmware and assembly before Rust are outside
capture. `KLOG userspace handoff retained early message` is emitted before init
runs. Time is unavailable until scheduler startup, after boot timer reset and
calibration; no wall clock is inferred. Sequences order completed captures,
not cross-CPU causality or the start of fragmented lines.

Kernel `serial::byte_out` retains streamed diagnostics before display. Existing
fragmented print calls remain serialized by their existing BKL/BSP ownership.
A newline commits one record; excess bytes are discarded until newline and the
prefix is marked truncated. An explicit fatal flush publishes a partial line.
An incomplete ordinary line is not visible until newline or fatal flush.
Existing prefixes supply an inferred initial subsystem token (up to 16 ASCII
alphanumeric, dash or underscore bytes). PANIC, FAILED/ERROR and WARN hints map
to severity 2, 3 and 4; other streamed text is informational (6). Streamed
metadata carries INFERRED=8 on the wire. Typed emit metadata does not. This is a
compatibility adapter, not a claim that every old producer has structured
metadata. Explicit `Log::emit` producers supply their own source and severity.
Kernel device initialization, NIC carrier/fault reports, storage error reports
and scheduler process failures already emitted through serial enter this path.
Userspace Console writes use `display_byte_out`, deliberately bypassing the
ring. Reading and displaying logs therefore cannot recursively produce logs.

Writers and readers attempt the ring lock once. No operation waits for a
consumer or allocates. Complete `emit` calls support concurrent CPUs and
interrupt reentry; a failed write increments an atomic contention counter.
Fragmented byte streams require their existing console serialization. A byte
lost to contention is included in the counter and marks the next committed
streamed fragment LOSS=16. A lost newline can merge fragments, but the result
is marked damaged, with unknown source and conservative informational
severity; no guessed subsystem is claimed for damaged text.
Each call copies/scans at most one bounded record; retention overwrites the
oldest complete record. Readers hold no ring state between calls. A cursor
that has fallen behind reports the exact number of overwritten sequences;
starting from zero reports retained oldest, including an overwritten prefix.
The contention counter counts byte callbacks or complete emit attempts, not
necessarily complete messages. It is distinct from overwritten sequence loss.

On x86-64, `serial::fatal_raw` attempts one emergency record, then writes at most 1024
bytes directly to the UART with the existing finite per-byte polling limit.
It does not acquire the BKL, allocate, recurse through framebuffer output or
wait for the ring. A busy ring can lose this record, and UART absence or a
failed device can lose emergency display. The normal panic path attempts this
fallback before formatted panic display. Pending fragments are flushed before
the emergency record, so completed capture order remains explicit. The bounded
raw fallback has a fixed emergency banner; the detailed reason uses the ordinary
formatted path and is not guaranteed if that path fails. NMI, corrupt stack/address space,
unrecoverable CPU failure, arbitrary concurrent raw-UART writers, and a failed
ordinary framebuffer path do not have a universal complete-panic guarantee.
The existing ARM UART output polling remains outside this x86-64 emergency
claim; only its retention/read compatibility is compiled here.
Existing terminal guards can choose raw output and halt. Emergency retention
and raw fallback have distinct availability and loss accounting.

## Worker output on the boot console

Init's console projection buffers stdout and stderr independently, up to 1024
payload bytes per stream. Complete newline-terminated lines within that bound
are published together; their bytes cannot be inserted inside another stream's
complete line. Ordering within each stream is preserved. Order between streams
follows completed publication rather than the order of individual pipe reads.
Raw journal service records retain their existing stream identities and read
order. The per-worker publisher is fixed-size, at most 2200 bytes including its
two buffers and accounting; this is not a whole-process memory measurement.

A full buffer without newline, an unterminated EOF tail, a pending fragment
before local-console handoff, or an aborted producer emits a greppable notice:

```text
EXTERNAL OUTPUT SPLIT stream=stdout reason=limit offset=0000000000000000 bytes=1024
```

`stream` is `stdout` or `stderr`; `reason` is `limit`, `eof`, `read-error`,
`pre-prompt`, or `abort`. `read-error` labels a pending stderr fragment flushed
after a failed read; it does not claim normal EOF. Offset and length identify
the preceding payload fragment. Forced
fragments can interleave with the other stream; the notice explicitly limits
the intact-line claim. The notice is console metadata outside the hex payload.
It adds no bytes to the worker's captured output or its final count/digest.
Single-stream capture, including binary output and missing final newlines,
therefore retains its exact bytes. Existing capture readers continue to read
the same contiguous-offset hex frames; they do not reconstruct individual
streams from forced fragments. The final count and FNV digest describe emitted
payload order. A failed or partial console write is not retried or called a
complete capture. Abort flushing is best-effort and has no successful END.

Pending startup fragments are flushed before physical presentation ownership
passes to the local prompt. Later runtime output remains outside that physical
startup capture. This does not change readiness grammar, SSH key trust,
authority, grants, or the independent raw journal capture.

`python3 scripts/test-worker-console-lines.py` runs the actual init publisher
with finite host pipe/console adapters and the strict kernel capture reader.
Pass `--platform /path/to/pinned/platform` to also exercise its unchanged
`ssh_absd` and storage-recovery readers on the same conformance cases. These
host tests do not establish guest execution or kernel ownership enforcement.

## Read boundary and consumers

Experimental syscall `0x7fc0(handle, frame, 0)` reads one nondestructive frame.
Ordinary consumers must own an explicit `Object::Diagnostics` with RIGHT_READ.
The object accepts no write, wait or kill rights and cannot read console input,
write physical display, or operate a Machine. Root init (PID1, direct kernel
parent, INIT program role) alone may fall back to its writable Console. A
nonzero handle is checked exactly; zero scans only actual owned Diagnostics
READ or the permitted root-init Console fallback. A Pipe confers no diagnostic
authority, and stdout-console replacement removes the old default Console as
before. Missing, closed, wrong-kind and missing-read handles refuse before
memory. There is no clear operation. Existing console text can contain device
and kernel addresses: delegate Diagnostics only to trusted workloads. New
producers must exclude credentials and key material.

Root-init-only experimental syscall `0x7fc3(console_write, 0, 0)` mints a
Diagnostics READ grant after validating root role and the existing Console
write handle. The served SSH worker receives it as startup role20, not as a console.
Logging also delegates READ to logd and the guarded FSD finalizer, both
actual ring consumers. A normal FSD receives it only when the external
logger is absent and its own local Collector runs. The platform parser stores it separately,
and runtime process spawning copies the grant with RIGHT_READ to children as
role20 throughout the runtime child tree, including children without file
access. This operator profile has no per-spawn Diagnostics exclusion; it is
unsuitable for workloads that must be denied kernel diagnostics. The network-facing
SSH worker holds it before authentication; its runtime children retain READ
under ro and nofs and without spawn authority. The grant exposes retained
kernel/device observations, including hardware identity, to those holders. The real
kernel spawn transfer installer retires the replaced Console
and retains the separate grant; a pipe never mints one. Withholding or closing
the grant denies reads. Creating an INIT-image child and subsequently orphaning
it cannot mint or append because the root role also requires PID1.

The fixed 576-byte little-endian frame is branch-local version 1. This is not a
supported-ABI promotion. Requests zero every byte except u32 version at 0 and
u64 cursor at 8. Responses contain u32 present at 4; u64 next/oldest/end/lost/
contention total at 8/16/24/32/40; sequence/ticks at 48/56 (MAX means time
unavailable); u32 record flags at 64; u8 severity/source length at 68/69;
u16 message length at 70; source[16] at 72 and message[480] at 88. The last
eight bytes are zero. Flags are truncated=1, partial=2, emergency=4, inferred=8, damaged=16. Busy is
-11, future cursor or malformed requests -22, invalid user memory -14.

The actual encoder and platform decoder share the exact
`tests/fixtures/kernel-log-v1.hex` conformance vector. Userspace collectors
maintain independent cursors; a dead file server cannot hold the kernel ring.
The platform `dmesg(1)` command provides snapshots, follow, severity/source
filters and safe single-line escaping. The companion init local-console maintenance consumer is composed separately;
it must read through its root-init fallback or explicit Diagnostics grant
without network or filesystem. This component alone does not install that view.
The platform owns its packaging and operator manual.

In the ordinary served boot, init mints a read-only Diagnostics handle just
before spawning the SSH worker, includes role20 in its startup record, and
closes its own temporary handle after the spawn attempt. The worker inherits
no Console from that grant. Native runtime startup stores the role and native
child spawning copies only READ authority. Normal FSD with a private logger channel does not receive this grant.
Non-served workers retain their existing startup authority.

Experimental syscall `0x7fc2(console, frame, 0)` now has its concrete logging
consumer. It accepts up to 256-byte service chunks only from the actual root
init role (PID1, direct kernel parent and INIT image), with Console WRITE.
The live role/object/right is checked before user-memory access. Frame296 is
little-endian u64 version=1, PID, service (1 sshd, 2 fsd, 3 logd), stream
(1 stdout, 2 stderr, 3 lifecycle), length and zero-padded payload256. Init
asserts the supervised child's identity; payload bytes cannot choose attribution.
The kernel assigns service.sshd/service.fsd/service.logd and a PID/stream prefix.
The supervised collector and private FSD channel own persistence and admission;
the kernel ring remains volatile. Init retains a separate read grant for repeated logd spawn, legacy local
collection and guarded FSD finalization. The ordinary
worker's transient grant and child READ inheritance remain as described above.

The exact concurrency proposition is one-shot exclusive publication of a
bounded record and independent read positions in this boot. Host tests exercise
concurrent writers/readers, deterministic nested-lock refusal, wraparound,
truncation, fragments, authority and the wire golden. These practical tests and
the short Acquire/Release critical section suffice for this bounded
implementation; they do not establish hardware timing or fatal-context
completeness. A new kernel generation starts an empty ring and cursor namespace.
No live state/authority transfer, post-effect rollback or downgrade protocol is
provided by this change; such replacement must fence writers/readers and
explicitly transfer or retire boot-scoped diagnostic state under the existing
architecture rules.

### Private collector attachment recovery

Init's logger policy permits four successfully created replacements following
actual crashes per boot. It charges after the spawn syscall creates a child;
pre-spawn resource refusals back off without consuming the budget. An exact
child reaped with private lifecycle v1 exit status 75 requests a free attachment
retry after 1000 ticks. The count of genuine crash replacements remains
monotonic across transient exits. The next exclusive LOGGER_BEGIN retires the
previous generation's FSD handles; it does not revive old handles or authority.
No live child may be replaced. Unknown post-spawn identity/reap outcomes stop
automatic replacement and retain the exact child handle for bounded supervision.

The shared golden `tests/fixtures/logd-lifecycle-v1.txt` binds status 75 in the
kernel policy and platform RpcStore/logd consumer. Host transition tests cover
resource refusal, actual creation, transient exit, mixed crashes, four charged
replacements and orderly stop. They do not establish guest process occupancy,
frame admission or storage latency. Stable logical service identity remains
logd; generations share only the explicit kernel-ring cursor and parsed J1
persisted prefix, with bounded overwrite and RAM-only lifecycle loss disclosed.
No native Rust state transfer or downgrade claim is introduced. Practical
finite transition tests and actual RPC/FSD tests suffice for this small policy;
there is no new replacement authority mechanism or hardware transfer claim.

Round 3 extends the private logger's existing startup record with the already
supported empty environment, cwd `/` and explicit name `logd`. Shared
`tests/fixtures/logd-startup-v1.hex` is checked against the actual kernel
emitter and platform parser. The runtime gives only that named logger's
pre-main VERSION exchange 1000 ticks and maps only transport NoAnswer to 75;
all protocol/malformed refusals and genuine fault/kill outcomes remain
chargeable. Other clients retain 60000 ticks and the logger watchdog remains
5000 ticks.

Consecutive unproductive attempts saturate and drive 1, 2, 4, 8, 16, 30, 60
second backoff, continuing at 60 seconds with summarized notices. There is no
terminal storage-transient budget. The first complete, exact-child COLLECTED
line starts a productivity interval. Only a later new-record sync in that same
generation at least 60 seconds afterward resets the count. The collector emits
at most one such notice per minute and never repeats a notice for old data.
Lifetime, READY and heartbeats alone do not reset it. Crash history is never
refunded. After the initial transitions, retry summaries appear every 60th
unproductive attempt, including after count saturation. Every non-75 outcome
and all bounded logger output remain visible even when transient notices are
summarized. The shared supervision-v1 golden
binds the actual notification parser, supervisor formatter, typed kernel
lifecycle prefix and platform health consumer. These are retained observations,
not a new live status authority. Exhaustion, quarantine and unconfirmed-child
notices replace older retry/collection observations; their unavailable counts
remain unknown.

A non-timeout exact-wait error for an unknown PID quarantines the retained
raw identity. No later wait/kill/reuse action uses it. Known worker/server
reaping continues; unmatched adopted outcomes are explicitly unclassified and
never prove that the logger was reaped. Cleanup visibly refuses an unresolved
identity. Host injected disposition tests and native type checks cover source
semantics; actual init syscall execution and guest scheduling remain unverified.
