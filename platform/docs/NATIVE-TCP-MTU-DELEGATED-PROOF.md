# Delegated native IPv4 TCP MTU refusal

This source-only fixture closes the LocalPipe-only consumer gap in existing
#34 and reuses the bounded
parent/child capability construction from
#29. No build, artifact
control, native execution or acceptance is implied by source preparation.
The existing genuine-router and malformed-advice proofs remain unchanged.

## Construction and behavior

The dedicated owner retains the NIC and one Stack at `192.0.2.100/24`, gateway
`192.0.2.1`. It calls the existing
`stream::channel::Channel::grant_mtu_refusal`; its child uses the existing
`stream::Client::new_mtu_refusal` over actual `KernelPipe` handles. No kernel,
ABI, engine or dependency change is required. A new optional feature uses the
already-existing optional broker dependency; lockfiles are unchanged.

Each child receives only the startup reader, protocol reader, protocol writer
and diagnostic writer. Its diagnostic writer is also the fallback diagnostic
destination, distinct from the protocol stream. Existing `STDIN`, `STDOUT`
and `STDERR` roles and `SPAWN_NO_SPAWN` are used. The child obtains its protocol
pair through `startup_stream_handles()`, which refuses missing explicit roles
and never substitutes the fallback diagnostic console. The legacy
`standard_stream_handles()` output is that fallback destination and is unsuitable
for this split. The child verifies its NIC
handle is absent and its input is not a NIC. All unneeded parent copies of
child pipe ends are closed before work. Child logical numbers 1 and 2 select
two separately constructed grants and processes; they are not implementation
generations or a rebind of fenced authority.

The owner has one original 30000 ms outer budget. Refusal child 1 uses
`7100 -> 198.51.100.2:42100` and an outer deadline of start + 12000 ms. It
connects, submits all 1024 bytes `i % 251`, and reads until actual typed
`FragmentationNeeded { mtu: 576 }` (code 17). Both a subsequent read and write
must return Stale 8 with unchanged observed pipe-call and byte counters. The
child then closes its protocol handles and reports its buffered observations.

The Channel stays available to flush the complete framed terminal reply.
Existing Channel polling subsequently observes actual request EOF and invokes
its existing revoke behavior. `REAP` explicitly records `eof_revoked=1`; the
fixture does not claim the reservation survives that EOF. After normal reap
and true result EOF the owner explicitly revokes again, closes its exact pipe
and result handles, polls and requires zero sockets and restoration of the
process/handle/pipe/cell census.

Only then does the owner construct positive child 2 and a fresh grant,
`7101 -> 198.51.100.2:42101`. Its new at-most-10000 ms deadline must fit inside
the unchanged whole budget. This child sends bytes 0 through 63, half-closes,
reads their exact echo and actual EOF, then exits normally. Protocol EOF-driven
cleanup and final explicit revoke are recorded as for child 1. No accepted
CLOSE/TIME_WAIT, memory restoration, automatic recovery or authority revival
is inferred. Allocator frames are observations, excluded from object equality.

Each GRANT records the consumer deadline, the pre-construction clock sample
and requested remaining lifetime. The Stack's separate private construction
clock/expiry are not exported or inferred. Parent clock checks surround I/O,
wait and terminal processing; child Client uses its existing monotone-clock
checks. All successful work must finish before the original phase deadline.
Failure cleanup has a separate bounded drain and cannot turn failure into PASS.

## Exact observed bytes

The owner first writes a fixed 20-byte bootstrap on the reply pipe: `MTUD`,
version byte 1, child byte 1 or 2, four IPv4 peer bytes, two big-endian peer
port bytes and eight big-endian consumer-deadline bytes. It is retained in both
actual pipe ledgers at reply-stream offset 0. After those 20 bytes, ordinary
experimental-v4 RPC messages use their existing two-byte big-endian framing.
The child argument must agree with the bootstrap logical number. The bootstrap
does not itself grant network authority; only the owner's construction does.

All records start `TCP MTU DELEGATED <KIND> v=1`. Key groups are:

| Kind | Fields after v |
| --- | --- |
| BEGIN | start_ms, until_ms, refusal_until_ms, guest, router, peer |
| GRANT | child, phase, local_port, peer_port, at_ms, until_ms, lifetime_ms |
| SPAWN | child, phase, process_handle, at_ms, no_spawn, nic_copies, protocol_handles, diagnostic_handles |
| BOOTSTRAP | child, phase, at_ms, bytes, hex |
| PIPE | observer, child, phase, direction, ordinal, offset, at_ms, bytes, hex |
| PIPE_SEAL | observer, child, phase, records, request_bytes, reply_bytes, read_calls, write_calls, request_eof, reply_eof, failed |
| FRAME | direction, ordinal, phase, at_ms, bytes, hex |
| FRAME_SEAL | phase, records, tx, rx |
| REAP | child, phase, reaped_ms, at_ms, kind, status, request_eof_ms, result_eof_ms, channel_live, eof_revoked |
| RETIRED | child, phase, explicit_revoke_ms, channel_live_before_explicit, channel_live, process_handle_live, protocol_handles, result_handles, sockets, objects_restored |
| POSITIVE | at_ms, until_ms, child, fresh_grant, old_child_retired |
| CENSUS | label, processes, handles, pipes, cells, frames |
| DONE | at_ms, children, sockets, negative_bytes, positive_bytes |

`observer=owner|child`, `phase=refusal|positive` and
`direction=request|reply` identify pipe streams. Every successful actual I/O
chunk retains its bytes, per-direction ordinal and offset. A real zero-byte
read is an EOF observation with `bytes=0 hex=none`; timeouts and non-progress
are counted calls, never EOF. Each observer has at most 512 successful chunks
and at most 65536 bytes per direction. The owner uses the existing at-most-256
byte Channel polling calls and unchanged 250 ms framing deadline. No 40 ms
pause is inserted between partial-frame calls.

The two observers' reassembled request streams must match exactly, as must
their reply streams including bootstrap, independently of chunk boundaries.
After bootstrap, reconstruct the real version-4/family-0 request/reply frames,
the exact granted tuple and typed code-17/detail-576 reply. Child `CHILD_BEGIN`,
`CHILD_CONNECTED`, `CHILD_QUEUED`, `CHILD_REFUSED`, `CHILD_FENCED`,
`CHILD_OBSERVED`, `CHILD_EOF` and `CHILD_DONE` records retain outcomes and actual
boot timestamps. `CHILD_FENCED` contains before/after request/reply byte and
read/write-call counts for both Stale operations.

Pipe and NIC ledgers are buffered and published after their phase I/O. Their
timestamps describe observations, not publication order. Do not infer a
cross-process causal order merely from output-line order or post-call times.
Use exact stream bytes, ordinals, explicit marker construction and source
correspondence. Full successful native TX and actual RX are retained with
per-direction ordinals, at most 256 each. Failure paths retain partial child
reports and ledgers, exact cleanup observations and their failed outcome.

## Offhost proof and build contract

The future oracle should reuse the genuine Linux topology from
`NATIVE-TCP-MTU-PROOF.md`: router egress MTU 576, peer MTU 1500, two ordinary
TCP listeners, no raw ICMP construction. Require the actual DF 1024-byte
submission, exact matching Linux-generated ICMP quote, full two-leg capture,
both actual kernel-pipe ledgers, typed child refusal and no old-flow TX from
consumed error through owner retirement. Negative peer application bytes must
be zero; fresh positive peer echo must be exactly 64 bytes with FIN/EOF.
Only the existing narrowly defined TX ARP/TCP zero-padding relations apply;
RX remains exact. Guest, host and capture clocks are never subtracted.

Build on the separately authorized compiler VM:

```sh
scripts/build-native-tcp-mtu-delegated.sh
```

Retain both actual `tcp-mtu-delegated-client.elf` and
`tcp-mtu-delegated-service-probe.elf`, with exact child bytes embedded in the
owner. Move completed generated ELFs into evidence before strict source-AFTER
checks. Then use the unchanged served kernel wrapper and selected kernel to
embed that exact owner, retaining actual Cargo metadata, staged std inventory,
build commands/receipts, kernel ELF and ISO extents. The dedicated feature is
`native-tcp-mtu-delegated-probe`; existing features/default behavior are intact.
No new proof runner or host execution is provided by this source-only step.

## Formalization and disposition

The proposed finite claim is actual delegated transport of an existing typed
terminal reason, no further child pipe I/O after Client fencing, then normal
reap/true EOF/owner cleanup before explicitly constructed fresh authority.
Existing source mechanics plus future literal checker mutations, real Linux
capture and independent raw readback are appropriate. No mechanized proof,
authenticated ICMP origin, PMTU recovery, physical timing, all-memory/DMA
quiescence or live replacement is claimed. A missing observation must fail.

Creator `quic_next_tranche` owns source run
`90077044-7b65-453d-b54c-53de4e452443`. Root owns composition, aggregate storage
and sequencing; steward acceptance remains separate. Retain this isolated
source worktree only for composition/review/rollback, with creator retirement
when those dependencies end or review at 2026-10-19T00:00Z. No VM, credential,
compiler target or current-resource hold is created by this source task.
