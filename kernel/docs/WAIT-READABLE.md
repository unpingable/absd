# Bounded readable waits

`wait_readable(handles_ptr, count, timeout_ticks)` is supported syscall `0x7fa8`,
additive to ABI 1. `KERNEL_ABI` remains 1 and kernel-log read remains `0x7fc0`.
The number was checked against intended kernel `10c3a43a` before promotion.
The common ABI constants are `WAIT_READABLE_MAX = 11` and
`WAIT_READABLE_POLL = u64::MAX`; absd-user, platform runtime and C kit expose
matching bindings. Older kernels return -38 even for empty sets: wrappers
always issue the call. See the platform's `wait_readable(2)` manual.

## Contract

Copy 1 through 11 little-endian u64 handle values once from readable user
memory. The result is a positional mask, including duplicate positions. Every
member must resolve to a current Pipe or Console handle with READ rights.
Validate the entire set before returning any readiness. Pipe data or zero
writers is level-ready; Console buffered input is ready. No bytes are consumed
and a later read may block or fail. Invalid/stale/type is -9, missing READ -1,
invalid count or overflowing deadline -22, and invalid user range -14.

Timeout zero is indefinite. `u64::MAX` polls, returning zero when idle. Other
values expire at checked `now + timeout_ticks + 1`, in delivered timer ticks,
with -110. The first serialized data/error/timeout completion wins. There is
no preference for data at a simultaneous deadline and no wall-clock promise.
Every completion re-resolves full handle and Pipe generations. A stale or
revoked member fails the entire wait even if another is ready. Stop or task
retirement clears the fixed wait state; stopped or CPU-owned tasks cannot wake.

The existing kernel lock covers readiness check through registration and
context-switch departure. The BSP publishes Console ring availability as an
atomic level; a wake scan acquires kernel serialization before publishing a
runnable task. The scheduler rechecks after CPU departure and for authority
changes. An indefinite readable wait keeps a single-CPU boot alive only if
its captured set still contains a Console handle with READ rights. Pipe-only
wait cycles do not keep that boot alive. Finite deadlines, existing Console,
StopFence and RT liveness remain unchanged.

## Consumers and composition

FSD is the current serving consumer. The intended base has 18 client channels,
a control channel and an optional logger channel: 20 in total. Each serving
pass polls all active channels. An idle pass waits on at most 11 eligible
handles; advancing the existing cursor by 11 covers all 20 within two idle
waits. Omitted data or EOF is polled on the next serving pass. The cost is at
most one extra finite idle wait, with timeout argument 1 (up to two delivered
ticks plus scheduling). Pending replies keep bounded retry, complete buffered
work prevents sleeping, ended requests leave the set, and rebinding resets
quiet/EOF state. Quiet recovery still requires two ticks after the first empty
poll. No performance or idle-CPU benefit is claimed for this new pair.

New FSD startup, after independent finalization modes and before channel or
writable-startup effects, probes an empty set. -22 establishes support; -38
prints `FSD FAILED kernel lacks wait_readable` and exits 3. Other answers
refuse explicitly. No silent fallback is provided.

## State, authority and evidence scope

The proposition is bounded: a fixed per-process captured set completes once
under current kernel serialization and full-generation validation. Host tests
exercise actual HandleTable, PipeTable, Process and owner-lock state, including
lost-wake, EOF, generation, revocation, timeout and boot-liveness controls.
These bounded state-transition tests and explicit source lock audit suffice
for this change; they do not establish physical SMP timing or Console hardware
behavior. Native final-pair correctness and old-kernel FSD refusal remain
separate required evidence. The steward owns independent acceptance.

This is transient wait state, not a persistent subscription or transferable
object identity. A future kernel replacement must quiesce/fence the waiter and
complete/refuse it, or reconstruct its explicit handle array and deadline
against authorized successor generations. Native Rust layout is not a transfer
schema. No new live replacement, hardware transfer, downgrade guarantee or
post-effect rollback is implemented. No callbacks, allocation in the wait path,
write-readiness or general event API is added.

## Wake-call ownership audit on the intended base

Audited from K10c3a43a plus the supported-wait delta. `wake_pipe_waiters`
first accesses `sched::table()`, which asserts current lock ownership when
serialization is active. It calls `wake_readable_waiters` before returning;
that routine asserts ownership again and accesses the same guarded table and
PipeTable. Neither path releases serialization between these assertions.

| Direct caller | Ownership path |
| --- | --- |
| `syscall_read`, after a successful Pipe transfer | user dispatch enters through the BSP/AP/ARM lock entry, then guarded table and PipeTable access |
| `syscall_write`, after a successful Pipe write | same dispatch and guarded tables; no device wait in the Pipe arm |
| `release_object`, Pipe arm after reference release | guarded `pipes()` before release; syscall close, duplicate/creation rollback, scheduler startup restriction, abort-spawn and terminal reclamation callers already use guarded tables |
| `smp_fixture::stopped_pipe_wake_control` | explicit `assert_held(BSP)` at entry, then guarded process/pipe access |

Release paths were traced separately: startup actor restriction asserts BSP
ownership; abort-spawn first resolves the Created child through `table()`;
terminal reclamation resolves its unowned terminal process through `table()`
and releases each handle without retaining a borrow across the wake call.
The syscall rollback paths reach the same guarded tables. The Cell-only
rollback cannot invoke the Pipe wake arm.

On x86 BSP `boot.S` calls `bsp_kernel_enter` before user dispatch and leaves
only after dispatch or the committed context-switch path. `ap_user.S` uses
`ap_user_kernel_enter`, which acquires the current CPU's lock, before dispatch;
its final return releases it. `commit_cpu_switch` reconciles and scans while
still owning serialization after hardware departure. Idle device waiting
releases and reacquires the lock before scanning shared tables again.
The ARM exception path acquires for user synchronous exceptions before
calling dispatch; its lock assertion also requires disabled interrupts.

Inactive early boot is distinct: x86 `assert_current_owner` returns while
ACTIVE is false; bootstrap runs alone with interrupts disabled, and
`activate_on_bsp` publishes ownership before AP admission. ARM inactive
assertions require BSP identity and disabled interrupts. This audit does not
claim that an inactive lock assertion itself proves serialization, nor that
host tests prove physical SMP behavior. No new unguarded wake caller was found.
