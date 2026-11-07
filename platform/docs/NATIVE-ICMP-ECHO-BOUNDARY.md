# Native IPv4 Echo boundary fixture

This opt-in source follow-up belongs to issue #34. The existing runtime
consumers are `ping_once` and `echo_service_probe`. This fixture adds a
pipe-only refusal child and a separate owner parent; their implementation
uses the existing public `echo::Owner`, `Channel` and `transact` APIs.
Production networking, the kernel ABI, dependencies and the default positive
binaries are unchanged. All new host/build/native execution is UNRUN at this
source freeze. Old native results retain their own source and verdicts.

The feature is `native-echo-boundary-probe`. The binary names are
`echo_boundary_client` and `echo_boundary_service_probe`. The boundary child
receives the same 13-byte version/peer/absolute-deadline bootstrap as
`ping-once`, no NIC, no spawn authority and only its startup/protocol/result
pipes. Its seven actual transactions use the fixed vectors in
`fixtures/native-echo/boundary-v1.txt`. Version, operation and both reserved
byte cases return Invalid (1); wrong-peer START, OBSERVE and CLOSE return
Denied (2). Every response is exactly 48 bytes with a zero body. After fully
consuming and comparing all responses, the child writes the single byte
`00` and waits for the parent to kill it. It never issues an authorized START.

The owner first runs seven peer denials, two lifetime denials, two entropy
refusals, one actual slot exhaustion and one closed-endpoint Stale refusal.
These calls allocate no successful network request and do not poll the stack.
One temporary valid grant is closed, a new negative grant is issued, and its
socket remains present through all malformed IPC. The parent records exactly
57 actual input bytes (seven requests plus `00`) and 336 actual output bytes.
The 13 bootstrap bytes are separately recorded and excluded from that ledger.
The delegating pipe wrapper returns the actual read bytes unchanged and
records `Some(0)` separately from no input or timeout. A fixture-local Link
wrapper counts calls before delegating actual sends unchanged, including a
failed call; the counter must still be zero before positive activation.

After observing the one-byte read, the parent kills that exact child, requires
killed wait kind 3/status 0, and obtains true EOF. Channel must then return
false and the socket must already be absent, before any fallback fence.
The prefix's pre-poll timestamp anchors the original 250 ms frame budget;
actual read, kill, reap, EOF and retirement all precede that bound and the
negative grant's original expiry. Timeout retirement cannot substitute for
EOF. The old endpoint must return Stale. Every potentially blocking operation
has monotone post-I/O checks; the terminal observations are checked too.

Only after closing all negative-owned handles does the parent issue fresh
positive authority and delegate to the unchanged `ping-once`. It performs the
existing genuine Linux-kernel ARP/Echo exchange, one observation, CLOSE,
normal exit and true protocol/result EOF. The positive child's actual epoch
is printed in its original `PING` observation; fresh authority is additionally
checked by old/new Endpoint inequality, without exposing private fields.
The whole fixture has an explicit 20 s bound, its negative grant an original
8 s bound, and its separately constructed positive grant an original 8 s
bound that must fit inside the whole bound. No frame or grant is renewed.

The three syscall-41 censuses surround the negative and positive child
lifetimes. Processes, handles, pipes and cells must restore exactly after the
owned handles are closed. Physical frames are observations only: parent
allocator growth is not full-memory restoration. The 27 versioned boundary
records precede the unchanged two `PING` lines. The independent oracle checks
complete chunk offsets/END/FNV, exact ledgers, timing, original positive
fields and the full Linux-kernel capture. A strict full capture rejects any
extra Echo request; source-level zero send counts are not a wire substitute.

## Minimal off-host execution

Use the exact frozen product and separately committed oracle from this lane,
plus kernel `2775bbaf6c1b8ebbaec66579b39d1fd78d71e57b` (tree
`8763f164ddfed11aa2f55626bd8e85123c595a08`). The served-RAM wrapper digest is
`e3822e288d37e49a4efff2e30e35178d4c895c944ce43b4b690179565c6d51d2`.
The resource operator records canonical archives, authentic toolchain/std,
locked offline dependencies, source before/after and the actual build logs.
No compiler, guest or tests run on build_host for this source task.

Run both net host variants with fresh targets, locked offline JSON output,
single-thread harnesses and actual harness retention:

```
cargo +1.95.0 test --manifest-path net/Cargo.toml --lib --target x86_64-unknown-linux-gnu --locked --offline --message-format=json -- --test-threads=1
cargo +1.95.0 test --manifest-path net/Cargo.toml --features dhcpv4 --lib --target x86_64-unknown-linux-gnu --locked --offline --message-format=json -- --test-threads=1
```

There are eight new fixture methods in `net/src/echo/boundary_tests.rs`.
Actual full counts come from executed harness summaries, not this inventory.
Run the existing artifact guards and Root's additive boundary controls too.
Build with `ABSD_PROFILE=core scripts/build-native-echo-boundary.sh`; it builds
and strips the unchanged positive child, the negative child, then the parent
with the exact `ABSD_PING_CLIENT_ELF` and `ABSD_ECHO_BOUNDARY_CLIENT_ELF` buffers.
Outputs are `ping-once.elf`, `echo-boundary-client.elf` and
`echo-boundary-service-probe.elf`. The two child ELFs must each be uniquely
embedded in the parent and served kernel. Build a single exact served-RAM
kernel/ISO using the existing measured wrapper and retain the actual commands,
ELFs, ISO, metadata, source and receipts. Do not fabricate a build receipt.

Run `scripts/native-echo-matrix.py` using profile `ipv4-echo-boundary-v1`,
`--elf echo-boundary-service-probe.elf`, `--client-elf ping-once.elf`, and
`--boundary-client-elf echo-boundary-client.elf`, together with the existing
required kernel/ISO/output arguments shown by the exact runner. Root owns
that separately pinned oracle and its 21 authored controls; no default profile
criterion is replaced. The peer is the actual Linux kernel in the owned
network namespace, not a userspace responder.

The boundary profile selects the accepted directional ARP predicates: the
pinned smoltcp guest broadcasts both the Ethernet destination and ARP target
hardware, while Linux requests retain zero target hardware and may use a
directed Ethernet destination. The controls include an independently retained
actual guest frame and refuse the earlier zero-target-hardware guest fixture.
This corrects a source-only predecessor profile; it was not executed or
transferred, and no historical native verdict changes.

## Limits and evolution

The malformed cases are IPC framing and authority checks, not malformed wire
reply qualification. No wire replay, connected-data or pending-reply
interruption, native frame timeout/link/device/clock fault, physical timing,
authentication, full memory restoration or live SSH coexistence is established.
The fixture observes logical owner-instance/epoch fencing in the current
implementation. An authorized same-peer successor is a new grant, not revival
of a closed pipe or proof that arbitrary old packets cannot reappear.

No replacement or state-transfer mechanism is introduced. A future generation
must quiesce pipes and queued work, reconstruct authority explicitly, and
validate a versioned exported schema; native Rust layout is not a transfer
format. Practical exact vectors, actual-method host controls and native
syscall/pipe/capture observations are proportionate for this bounded claim.
They do not prove arbitrary schedules or physical generation transfer.
Independent review and steward acceptance remain separate from this source
handoff.

Root is the lane storage allocator and the integration steward owns aggregate
campaign storage. The source worktree is forecast at 40 MB; actual allocation
and capacity are recorded in the lane receipt, with 60 GiB free on each of `/`
and `/data`. This is not a per-lane quota. Retain source/commits for integration
and rollback until their dependency ends or Root review on
2026-10-19T00:00:00Z. No local compiler target, VM, key or runtime is created by
this source task.
