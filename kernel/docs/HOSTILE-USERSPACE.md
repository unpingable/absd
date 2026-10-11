# Hostile userspace qualification

Qualification spike against the userspace/kernel boundary: can a hostile,
buggy, or nonsensical ring-3 task corrupt kernel state, corrupt another task,
fault or hang the kernel, cross the memory-isolation boundary, defeat syscall
argument validation, or leave the scheduler incoherent after it is terminated?

The invariant under test:

> A hostile userspace task may destroy itself, but it must not destroy the
> kernel, another task, or the kernel's ability to explain what happened.

Result: **the boundary held in every case attempted, across both spikes. No
kernel defect was found.** All repairs were to test expectations and test
tooling. The exact containment envelope demonstrated is below; the unproven
list at the end is part of the result.

Two spikes are documented here: fault containment (cases 0-13) and the
state-machine/lifetime/resource/scheduler-integrity campaign (cases 14-25 and
init phases S1-S5), which extends the same boot.

## Trust boundary (as implemented)

Verified against source, not intent documents:

- **Ring 3 → kernel entry is only through the IDT.** The `int 0x80` gate is
  the sole user-callable gate (`IdtEntry::user_handler`, `src/main.rs:818`);
  exception vectors 0-31 and the timer IRQ all have their own gates.
  `syscall_stub` (`src/boot.S:321`) saves 15 GPRs plus FXSAVE state, calls
  `user_syscall_dispatch`, and reloads CR3 from its return value: the syscall
  handler runs under the *user* CR3, and kernel memory stays reachable only
  because every user PML4 shares entry 0 → the kernel PDPT as supervisor-only
  (`src/vm.rs:91`: `ENTRY_PRESENT | ENTRY_WRITABLE`, no `ENTRY_USER`).
- **Syscall ABI**: RAX = number, RDI/RSI/RDX = arguments (docs/USERSPACE.md).
  Dispatch is a `match` on the full 64-bit number; unknown numbers return
  `-38` and bump `unknown_refusals` (`src/syscalls.rs`).
- **No raw userspace pointer is ever dereferenced in kernel mode.** Every
  pointer-taking handler routes through `copy_from_user` / `copy_to_user` /
  `check_user_range` (`src/user_memory.rs`). These walk the *target process's*
  page tables, require present+user at all four levels (plus writable at all
  four when the kernel will write), refuse huge pages, and copy through the
  physical identity map. `checked_range` rejects empty ranges, supervisor
  start addresses, `ptr + len` wraparound, and ends past
  `USER_ADDRESS_LIMIT` (`0x0000_8000_0000_0000`, `abi/src/layout.rs:33`).
- **User vs kernel virtual ranges**: the user region occupies PML4 entry 1
  only; PML4 entries 2-255 of a user root are absent (the "gap"); entry 0 is
  the shared supervisor kernel map. Address 0 is therefore a *present
  supervisor mapping*, not an unmapped null page.
- **Supervisor protections**: NXE on (`src/boot.S:99`), CR0.WP on
  (`src/main.rs`), heap mapped non-executable, ELF R/W/X flags translate to
  page permissions, `.text` read-only.
- **Fault discrimination**: `exception_common` tests the saved CS RPL
  (`src/boot.S:295-310`). A ring-3 fault switches to the boot CR3 and a
  kernel stack, records the outcome, prints
  `USER FAULT pid=.. vector=.. address=.. error=..`, reaps the task, and
  schedules. A ring-0 fault prints `KERNEL FAULT ..` and exits QEMU with
  status 2. A fault while servicing a syscall *is* a ring-0 fault — by
  construction it cannot be caused by a bad user pointer, because the copy
  paths resolve to physical addresses through the identity map and never
  touch the user virtual address.
- **After a kill/termination**: `terminate` (`src/sched.rs`) releases frames,
  handles, and object references, delivers or stores the outcome, and
  reparents; the scheduler picks the next runnable task or idles. End of
  boot, `finish_process_suite` (`src/suite.rs`) asserts the frame count is
  back at baseline and the process/object tables are empty.

## Test vehicle

One new catalog program, `hostile-probe` (index 40,
`user/src/bin/hostile_probe.rs`), selected by its start argument:

- `0` — non-fatal battery: must be refused cleanly, then exits 0.
- `1`-`12` — one fatal act each; the kernel must terminate exactly this
  process with exactly the derived exception. Returning alive exits
  `90 + case`, which fails the boot.
- `13` — invalid-syscall flood, runs until init kills it.
- `14`-`25` — the state-machine spike (second campaign): handle/object
  lifetime abuse, process/VM/object-table exhaustion, scheduler churn, and
  blocked-child helpers for init's kill paths (see below).

Init's `hostile` boot mode (`INIT_MODE_HOSTILE`, `run_hostile` in
`user/src/bin/init.rs`) spawns a well-behaved `hello-b` witness first and
keeps it alive across the whole battery, then checks both witnesses exited
normally at the end. `make hostile-test` boots it under a 60 s timeout with
`-no-reboot -no-shutdown`: a kernel hang, a `KERNEL FAULT`, or a `PANIC`
fails the target instead of passing silently.

Expected exceptions were derived from the page tables and the Intel SDM
*before* running; a disagreement is recorded as a finding, never pinned from
observation (see "Defects and findings").

## Cases and results

Non-fatal battery (probe arg 0) — all refused with the defined error, process
and kernel state coherent afterwards (positive controls pass after each
class): undefined numbers 0 / 23 / 999 / `u64::MAX` with garbage argument
registers (`-38`); garbage handle/rights/size arguments on write, kill, info,
duplicate, map, wait (`-3`/`-4`/`-22` as defined); write pointers null,
supervisor (`0x10_0000`), gap, limit-crossing, at-limit, near-`u64::MAX`
(`-14`); write lengths 0 and 257 (`-22`); a write straddling a mapped page
into an unmapped one (`-14`); output records (`wait`, `transfer`,
`frame_stats`) at null/gap/limit-crossing addresses (`-14`); a record in
read-only memory refused before one byte changes (sentinel verified); a
record straddling into an unmapped page refused whole (sentinel verified);
`unmap` of null, `.text`, stack, unmapped heap, and a wraparound page count
(`-22`); pipe write/read through null pointers (`-14`); 100 000 repeated
invalid syscalls under timer preemption, every one returning `-38`. Kernel
counter: exactly 17 pointer refusals. **Pass.**

Fatal cases — each spawned fresh, expected = observed:

| # | Act | Expected (derived) | Observed |
|---:|---|---|---|
| 1 | read `0x10_0000` (present supervisor) | #PF, error 0x5, CR2 = target | as expected |
| 2 | write `0x10_0000` | #PF, error 0x7, CR2 = target | as expected |
| 3 | execute `0x10_0000` | #PF, error 0x15, CR2 = target | as expected |
| 4 | execute planted `ret` on NX heap page | #PF, error 0x15, CR2 = heap page | as expected |
| 5 | write own read-only `.text` | #PF, error 0x7, CR2 = text address | as expected |
| 6 | read address 0 (present supervisor, not an unmapped null page) | #PF, error 0x5, CR2 = 0 | as expected |
| 7 | read gap `0x81_0000_0000` (PML4 entries 2-255 absent) | #PF, error 0x4, CR2 = target | as expected |
| 8 | divide by zero | vector 0 | as expected |
| 9 | `out 0x43, al` (PIT reprogram attempt) from ring 3 | #GP(0) | as expected |
| 10 | `lidt` from ring 3 | #GP(0) | as expected |
| 11 | `int3` from ring 3 | #GP with IDT error 0x1a | as expected (finding 1) |
| 12 | read noncanonical `0x8000_0000_0000_0000` | platform-dependent; see finding 2 | #PF, error 0x5, CR2 = address |

Scheduler interaction: 32 crash/relaunch cycles (divide-by-zero) each faulted
identically and were reaped completely; the witness stayed schedulable
throughout. The syscall flood (probe arg 13) ran concurrently with a second
`hello-b`; the witness exited 0 inside its bounded wait, init killed the
flood task (outcome `Killed`), and the first witness was then reaped with
status 0. **Pass.**

The phase-1 counters are unchanged in the extended boot; the full pinned
receipt is at the end of the state-machine section below.

## State machine, lifetime, resources, scheduler (second spike)

Second campaign against the same boundary: can a hostile ring-3 process drive
legal or deliberately invalid syscall *sequences*, resource churn, lifecycle
transitions, and preemption points to corrupt kernel bookkeeping, leak
resources, confuse ownership, wedge progress, or affect an unrelated process?
Same boot, extended: phase 1 is byte-identical (control); probe cases 14-25
and init phases S1-S5 follow.

Stateful surfaces audited from source: the per-process handle table
(`src/handle.rs`: tagged values, 64 slots, rights narrow only); the object
tables (`src/object.rs`: 32 cells, 48 pipes, references counted by rights);
the process table (`src/process.rs`, `src/sched.rs`: 16 slots, PIDs never
reused within a boot, claim/reap accounting); the heap window
(`src/vm.rs`, `syscall_map`/`syscall_unmap`: 64 pages per call, 8192-page
window, every page validated before any is changed); termination
(`terminate`: release frames, drain handles one at a time, reparent to live
init, deliver or store the outcome); blocked waits and deadlines
(`wake_sleepers`: only non-sleep waits count a timeout).

Scenarios (all pass; probe arg — content):

- **14 — handle/object lifetime.** Read-only duplicate outliving the closed
  original (writes refused `-1`, EOF read, reader/writer counts exact);
  close twice and use-after-close (`-9`); a closed value never aliases the
  object reissued into its slot; crafted values (0, 1, `u64::MAX`, a live
  value with one tag bit flipped, a table-size value) refused by `close` and
  `duplicate` (`-9`); rights never widen along a duplicate chain (widen,
  alien bit, and chain re-widen all `-1`; a zero-rights duplicate is inert);
  a process handle is refused as a spawn transfer (`-9`), alone or inside a
  `spawn_many_copy` vector that then fails whole; spawn validation (unknown
  program `-2`, alien flag bits `-22`, copy count 65 `-22`, empty image
  `-22`, garbage ELF `-8`); a bounded transfer on an own empty pipe times out
  (`-110`) and the pipe then works; the handle table fills at exactly 62
  duplicates (console + one pipe held), the next is `-24`, and an otherwise
  valid spawn with a full table is `-24`; a pipe round trip works after
  every refusal class. 23 handle refusals.
- **15 — process-table exhaustion.** Spawn never-waking sleepers until
  `-11`: exactly 13 fit (init, the probe, and the terminal-unreaped
  witness #1 hold the other three of 16 slots) — the boot's one spawn
  refusal; all 13 then killed and reaped `Killed`; a fresh spawn by init
  works immediately after.
- **16 — VM churn.** 512 map(1-8 pages)/sentinel/unmap cycles return the
  frame counters to the post-warmup baseline exactly (page-table frames
  persist across `unmap` by design; the baseline is taken after warmup);
  refused unmaps (misaligned address, partially-mapped range) leave live
  mappings byte-identical; the lowest free run is reused and the surviving
  neighbour keeps its bytes; the whole 8192-page heap window fills
  (128 × `map(64)`), after which even a one-page map is `-12`; every region
  touched, all unmapped, and a 64-page map works again. 4 map refusals here,
  12 with the battery's 8.
- **17 / 18 — VM lifetime at death.** Own 96 touched heap pages, then fault
  (17) or spin until init kills it (18). Init's frame counters before the
  spawn and after the reap are equal in both cases: reclamation is complete
  on the fault path and the kill path.
- **19 / 20 — object-table exhaustion.** Fill cells to exactly 32 / pipes to
  exactly 48; the next create is `-12`; a kept object still works; the probe
  exits holding everything, so termination drains 32/48 references at once;
  init's frame oracle holds and a positive control (pipe round trip, cell
  create/transition/read) works immediately after.
- **21 / 22 — scheduler churn.** Per cycle: spawn and reap exit7 (exactly
  `Exited(7)`), map/fill/unmap 4 pages, a 16-byte pipe round trip, and a cell
  create/transition(0→v+1)/close — with no yields, so the PIT preempts
  mid-sequence. 21 runs 200 cycles concurrently with an `isolation` witness
  that finishes `Exited(0)` inside its bounded wait; 22 runs unbounded until
  init kills it after 50 ticks (`Killed`); its in-flight exit7 child is
  adopted by init and drains through `wait_any`.
- **23 — fault with child and pipe.** The probe holds a transferred pipe
  write end and a live sleeper child, then faults (divide error). Init
  observes `Faulted` vector 0, EOF on the pipe (termination released the
  write end), and adopts and reaps the sleeper (`Exited(0)`).
- **24 — killed while blocked in `wait`.** Init polls `info` until the probe
  is observably Waiting, then kills it; the probe's own sleeper child is
  adopted and reaps `Exited(0)`.
- **25 — killed while blocked in a pipe read.** Init kills the observably
  Waiting reader; the surviving write end then fails with `-32`
  (BrokenPipe): the read end was released, not leaked.
- **S2 — init-side lifecycle edges.** `wait_any` with zero children is
  refused `-10`; a kill landing on a live child reports `Killed` exactly
  once (with a no-yield spawn→kill window the child has normally never been
  scheduled; a preemption there lets exit7 exit first, which the kernel
  answers with a no-op kill and `Exited(7)` — the bounded retry makes both
  paths exact); a second kill of the terminal child is a no-op; after the
  reap, kill/wait/info on the consumed handle are all `-9`; a narrowed
  wait-only duplicate cannot kill (`-1`) while the original still can, and
  reaping closes every duplicate of the child's handle; a bounded wait on a
  live child times out (`-110`) and leaves it alive (not terminal).

End-of-boot receipt (pinned by `src/suite.rs` and the Makefile):

```
HOSTILE status=0 frames=0 faults=46 kills=21 preempts=1795 refused unknown=152596 pointer=17 handle=33 wait=2 spawn=1 map=12 cell=1 pipe=1 timeouts=2
HOSTILE OK
ABSD BOOT OK
```

Every pinned counter was derived from the handler source before the boot
first ran green: 44 phase-1 faults plus cases 17 and 23; 21 kills (the flood,
13 fork-bomb children, seven lifecycle/kill cases); 17 pointer refusals;
33 handle refusals (battery 5, case 14 gives 23, init lifecycle edges 5);
2 wait refusals (the empty `wait_any` and the drain loop's final `NoChild`);
1 spawn refusal (the 14th bomb child); 12 map refusals; 1 cell and 1 pipe
exhaustion refusal; 2 timeouts (bounded transfer, bounded wait). `preempts`
and `unknown` stay lower bounds (the flood's rate is timing-dependent), and
`exits`/`reaps` stay unpinned (the churn-forever kill lands mid-sequence at
a nondeterministic point). `frames=0` above baseline, process and object
tables empty: every hostile task's frames, handles, kernel stacks, and
objects were reclaimed.

## Copyin/copyout audit

Every kernel path that reads or writes userspace-controlled memory was
traced. The abstraction already exists (`src/user_memory.rs`) and there is no
bypass: `src/syscalls.rs`, `src/syscalls/nic.rs`, and the three
wait-completion paths in `src/sched.rs` all route through it; the only raw
dereferences anywhere in the kernel are of kernel-internal structures,
MMIO/device registers, and physical frames the kernel itself allocated.

- Range validation checks start, end, and `ptr + len` overflow
  (`checked_add` → `UserMemoryError::Overflow`), not just the start.
- The whole range is validated per page at copy time, one walk per page;
  there is no validate-then-use gap, because the translation is redone for
  every page actually touched.
- Writability is required at all four levels when the kernel writes;
  read-only targets are refused before a byte changes (demonstrated by the
  read-only record sentinel case).
- A fault in privileged context from a bad user pointer is structurally
  absent: the copy goes through the physical identity map, never the user
  virtual address, so the only failure is a returned `UserMemoryError`.
- Partial copies: a mid-range failure can leave earlier pages copied, but the
  destination is a caller-local buffer discarded on error (`copy_from_user`),
  or user-visible bytes of a request that is then failed with `-14`
  (`copy_to_user`). `nic_receive` validates the whole maximum frame before
  anything is taken off the ring, so a frame is never consumed and then lost
  (`src/syscalls/nic.rs:93`).
- A task dying mid-request: synchronous calls run while the owning task is
  suspended, so its mappings cannot change under the copy; blocked transfers
  (`nic_receive`, pipe reads) re-resolve the task's wait state at wake time,
  and a killed task is no longer waiting, so nothing is delivered into a dead
  task's space.
- No defect found; no new primitive was needed.

## Defects and findings

No kernel defect. Four findings, all repaired on the test side or documented:

1. **`int3` from ring 3 delivers #GP, not #BP.** The initial derivation said
   vector 3. The correct architectural derivation (which the hardware also
   makes): a software interrupt from CPL 3 through an IDT gate with DPL 0
   fails the DPL check, so vector 3's DPL-0 gate raises #GP with the
   IDT-referencing error code `(3 << 3) | 0b010 = 0x1a`. The kernel contained
   the act correctly all along; the test expectation was wrong and was
   corrected (init.rs case 11, Makefile).
2. **Noncanonical-address behavior diverges between the SDM and the qualified
   execution environment.** Intel SDM derives #GP(0) for a read of
   `0x8000_0000_0000_0000`. QEMU 8.2.2 (Ubuntu TCG) instead performs the page
   walk: the address's PML4 index (bits 47:39) is 0, and user PML4 entry 0 is
   the shared supervisor kernel PDPT, so the walk lands on present
   supervisor-only mappings and reports a supervisor protection #PF
   (error 0x5) with CR2 set to the address. Both outcomes contain the act and
   terminate exactly the offending task. The test pins the TCG-derived
   outcome; the SDM-derived #GP on KVM/physical hardware is **unproven**.
3. **`boot_id` cannot serve as a pointer-abuse vehicle under the qualified
   environment.** It draws RDRAND before validating its record pointer, and
   QEMU's default CPU has no RDRAND, so it returns `-38` regardless of the
   pointer. The pointer is still validated before any use, so this is a
   validation-order observation, not a boundary violation; the battery uses
   `frame_stats` for record abuse instead.
4. **Two latent test-tooling bugs** (not kernel bugs): the Makefile pinned
   `vector=0` faults at 32, but the true count is 33 (32 crash cycles plus
   the fatal divide-zero case) — visible only once the boot first ran to
   completion; and three clippy lints in the probe (unused import,
   manual `ok()`, zero-pointer idiom). Both fixed.

Second-spike findings — again no kernel defect; all three were test-side
expectation bugs, fixed on the test side:

5. **A child blocked in `sleep` reports `INFO_STATE_WAITING`, not LIVE.**
   `syscall_info` maps `ProcessState::Waiting` to WAITING regardless of wait
   kind. The intended post-timeout assertion was "not terminal"; the test
   now asserts exactly that.
6. **Case 25's first form could never see BrokenPipe.** Init kept the
   original read|write pipe handle, so a read-capable handle (its own)
   always remained and the reader count never reached zero. Restructured to
   duplicate write-only/read-only ends and close the original, matching
   case 23's ownership shape.
7. **"Kill before first run" is a race from userspace.** With no yield
   between spawn and kill the child has normally never been scheduled — but
   the PIT can preempt init in that window and let exit7 exit on its own
   first. The kernel's behavior in the lost race is correct by design (kill
   of a terminal child is a no-op, no kill counted, outcome `Exited(7)`);
   the first failing run showed exactly that signature. The test now retries
   until the kill demonstrably lands on a live child, keeping every counter
   exact. The never-scheduled sub-case is the overwhelmingly likely winning
   path but is not separately distinguished from "killed mid-first-timeslice".
  General rule for future tests and userspace code: two adjacent userspace
  syscalls are never atomic with respect to timer preemption; any sequence
  that assumes otherwise has a race window.

Defense-in-depth note: `UserMemoryError::Overflow` (u64 `ptr + len` wrap) is
unreachable through current syscalls because every length is capped far below
the wrap point and every address is below 2^47 first; the check and its unit
test stay as a guard against future wider interfaces.

## Unproven / not demonstrated

This list records the original two spikes' scope. The ELF and disclosure
candidates below were subsequently completed; see "Follow-on qualification
spikes". FPU/MXCSR isolation was separately completed as noted below.

- **SMP and cross-CPU TOCTOU (original spike scope).** At the original
  UP/TCG spike source, syscall handlers ran on the owner's kernel stack with
  interrupts off, so a second CPU could not mutate table or mapping state
  mid-handler. Uniprocessor preemption interleavings were exercised hard
  (the churn cases cross timer boundaries constantly, and the spawn→kill
  race showed a real preemption window). Later kernel-only AP serialization
  and stop controls do not qualify ordinary AP userspace, migration, or
  cross-CPU userspace mutation; those remain outside the demonstrated scope.
- **KVM and physical hardware (original spike scope).** The original two
  spikes ran under QEMU 8.2.2 TCG. The noncanonical case is expected to
  #GP(0) per the SDM, while that TCG configuration reports #PF. Later KVM
  FPU and guarded kernel-only AP results are separately scoped below; no
  physical-machine result follows from them.
- **Resource exhaustion is qualified single-tenant.** The bomber/fillers
  observe their own refusals. A concurrent live process watching another
  task's held fill is not in the suite: witnesses run concurrently only with
  the churn cases, which hold nothing between cycles.
- **Identifier reuse.** PIDs allocated to processes that ran are never
  reused within a boot (`process::tests::slots_are_reused_but_pids_are_not`);
  the kernel rewinds only the newest PID of a never-run or boot-time self-test
  process, which no process can hold (audit finding A4), so rapid create/reap
  cycles cannot produce stale-PID aliasing; slot reuse itself is covered by
  the crash/churn cycles. Handle values are tagged; stale values after close
  or reap are refused (cases 14 and S2).
- **Adversarial ELF parsing — historical candidate, now completed.**
  `spawn_image` parses up to 32 MiB of caller-controlled structured bytes and
  turns them directly into address-space construction: segment layout, sizes,
  permissions, and the entry point. Garbage images are refused with `-8`,
  but a systematic parser/mapping battery was not run: truncation, integer
  overflow, overlapping or adjacent segments, malformed headers,
  pathological alignment, `filesz > memsz`, zero-sized pieces, entry outside
  every executable mapping, permission combinations, conflicting
  descriptors, and cleanup after partial failure. The loader's refusal
  order is documented in docs/PROCESS-STARTUP.md. If this lane is reopened
  it should be one compact matrix with exact expected refusal/cleanup
  behavior, not open-ended ELF fuzzing.
- **Crafted FPU/MXCSR state.** Qualified at `19ecacd` (20/20 KVM runs and
  two rejected mutants), then integrated and requalified on main. See
  "FPU/MXCSR process isolation" below for both historical and integrated
  results. AVX/AVX-512, x87 data registers and x87 exception behavior, and
  cross-CPU userspace FPU handoff remain unproven; the FCW check is limited
  evidence and does not qualify the broader x87 state.
- **Info-disclosure audit — historical candidate, now completed.** Nothing
  observed suggests a syscall returns kernel pointers or another task's
  interior state, but "syscalls never disclose privileged addresses" was
  never asserted as a property: the
  info/wait/handle queries were checked for state correctness, not for what
  their payloads could reveal.
- **Stack exhaustion/guard** is covered by the existing `overflow` and
  `stack-jump` programs under `make smoke`, not by this spike.
- **Soak** beyond one boot's 46 faults + 21 kills + hundreds of spawn/reap
  cycles + ~150k refusals + one 60 s run was not run. `sleep(u64::MAX)`'s
  no-deadline behavior is no longer merely documented: the fork-bomb and
  lifecycle sleepers rely on it and are killed while sleeping.

## Follow-on qualification spikes

Two later spikes, run from kernel 4212fff, cover candidates the original
scope lists as unproven. They are complete and in regression coverage through
their own make targets (not part of `make check`); neither found a kernel
defect.

- **Adversarial ELF** (`docs/ADVERSARIAL-ELF.md`): adversarial ELF parsing is
  qualified for the current loader implementation, revalidated after
  integration on main as recorded below. Deterministic malformed images fail
  closed; partial load failure restores kernel resources and
  accounting; valid loading works afterwards. This is not a claim of generic
  ELF parser security. Frame exhaustion midway through `spawn_image` and
  ordinary userspace execution across CPUs remain unproven. Observations,
  not defects under the recorded contract: the
  loader has no W^X policy and follows segment flags, the segment R flag is
  not enforced, and load-window validation carries the page-rounding
  overflow-safety invariant.
- **Syscall disclosure** (`docs/SYSCALL-DISCLOSURE.md`): all current syscall
  copyout surfaces were audited and the probe was revalidated on main; tested
  records are fully initialized;
  refused operations did not leak partial unauthorized output; stale handles
  did not expose replacement-object state; register inheritance did not leak
  parent registers. Intentional or known exposures: the page-fault error code
  reveals whether a fixed-layout supervisor address is mapped; `frame_stats`
  and `resource_census` expose whole-machine counts to any process without a
  handle (architecture audit 2026-10-02 finding B3: documented here as ambient
  observation rather than gated; a cross-session occupancy side channel); `block_info` and
  `nic_info` may partially write caller-authorized data before refusing; QEMU
  TCG reports the tested noncanonical load as #PF where hardware raises #GP.

### Integration revalidation and formalization consideration

At the time of this integration revalidation, the source was
`34f25db73ead234ff68e8bf842655a056b5f529c`, tree
`99570d073a11f2e98be7f97125317970f560a146`. It already contains ELF
qualification `8a82c91395ffc2ebbfae83cd99e21a5ca75b4625`, disclosure
qualification `b54a0081a5eae0acaef8a0c4a2f468efbe60f741`, and the stale-handle
slot-reuse repair `eeb063518641038203145140a8d1162a268a7266`. Since the spike
base `4212fff26bb0b160eac718c26fcc7ed5d67034a7`, no production kernel
implementation changed; the additions to `src/elf.rs` are host unit tests.

The propositions being revalidated are bounded to this implementation and
the existing fixtures: failed image construction restores the resource
census and PID accounting, a valid control image starts after each case,
and the unreaped sentinel retains its outcome. Tested copyout records must
be fully initialized; tested refusals must preserve output and pending
results; stale handles must refuse while their slots hold working successor
objects; and a child must start with the defined clean register state despite
parent register poisoning. The documented caller-authorized partial writes
from `block_info` and `nic_info` remain outside the atomic-refusal claim.

Decision owner: integration supervisor `/root`. Source review, deterministic
regression cases, and the previously demonstrated negative controls are
sufficient for these bounded implementation claims. No new formal model is
chosen because this integration changes no runtime state machine and makes
no universal parsing or disclosure claim. The slot-reuse repair is the
known counterexample to treating an empty-slot refusal as proof of
replacement-object non-aliasing. Frame exhaustion midway through
`spawn_image`, SMP/concurrent image mutation, and dynamic device copyout
behavior remain outside the demonstrated scope; existing documents retain
the other execution-environment and coverage limits.

Revalidation on the development host, 2026-10-03, used the unchanged qualification source
above. Every command exited 0:

| Command | Result |
|---|---|
| `make elf-matrix-test` | 87 cases, 115 image children; census/control/PID/sentinel assertions held |
| `make disclosure-probe-test` | 28 checks; initialized records, refusal preservation, actual slot reuse, and clean child registers held |
| `make spawn-image-test` | 3 image children, 16 refusals; complete reclamation |
| `make check` | 108 host tests, formatting, clippy, and every canonical VM/debug target passed |
| `make mutants` | All three existing smoke mutants rejected with QEMU status 7 and their expected failure markers |

Each focused boot ended with zero frames, processes, cells, and pipes.
No kernel defect or new semantic adaptation was found. The ELF/disclosure
temporary mutants recorded in their spike documents are not wired into
`make mutants`; those historical results remain unchanged.
Logs and separately preserved serial streams are in
`build/integration-regression-20261003-3af28ed235fd/`; its `evidence.sha256`
has SHA-256
`795fa0d9a50c40bd9c782634fc6c48faa61a491e031363d1a712372545150160`.
These local logs support this revalidation; the checked-in fixtures and
oracles remain the durable regression infrastructure.

## FPU/MXCSR process isolation

`make fpu-test` boots `fpu-test`. Init runs the `fpu-mxcsr` probe in
these roles, one after another:

- **Isolation.** Tasks A and B run concurrently. A uses MXCSR `0xff80`
  (round toward zero, FTZ); B uses `0x3fc0` (round down, DAZ). Each
  holds its own 64-bit sentinels in XMM0 and XMM7. Over 400 rounds each
  task checks its MXCSR control bits and both sentinels, then runs two
  `cvtss2si` conversions whose results depend on its own rounding mode,
  plus one exact `addss`. Each round ends with a yield and a non-yielding
  spin. A mismatch exits the task with status 97.
- **#XM.** A task clears MXCSR.ZM and divides 1.0 by 0.0. It must fault on
  vector 19 with error 0, and only that task may end.
- **Witnesses.** A fresh task is spawned after the #XM fault, after a normal
  exit with dirty state (MXCSR `0xdf80`, XMM3/XMM5), and after a kill with
  dirty state (MXCSR `0xbf80`, XMM1/XMM6). Each witness must read MXCSR
  `0x1f80` and FCW `0x037f`.

The kernel pins the boot: init exits 0, frames return to baseline, every
table is empty, there is exactly one fault and one kill, and there are at
least two timer preemptions directly between two `fpu-mxcsr` tasks.
`scripts/check-fpu.py` checks the marker order, the A/B readbacks, all
three witnesses, the single vector-19 fault, and the counters.

Results under KVM (`-enable-kvm -cpu host`), 2026-10-02: 20 of 20 runs
passed. Each run had 502–565 timer preemptions directly from A to B or
B to A, plus 800 voluntary yields. The #XM case faulted on vector 19 and
reaped cleanly every time. No kernel defect was found.

Two test-side defects were fixed. The per-round MXCSR check included the
six exception status flags (bits 0–5), which the probe's own `cvtss2si`
sets as precision-inexact. The kernel was correctly preserving those
flags, so every run failed at round 1 until the comparison ignored them.
The other was a type error in two of init's `wait` matches.

Negative controls (`make fpu-mutants`; each must fail the oracle *and*
show its specific evidence):

- `absd_mutant_skip_fpu_restore`: the original lane suppressed the copy in
  `install_frame`; the integrated control suppresses the current CPU-local
  restore in `resume_process`. The incoming task resumes
  with the outgoing task's state. Rejected: task A read B's MXCSR (`0x3fe0`)
  and B saw A's XMM0 sentinel (`CORRUPTED`).
- `absd_mutant_fresh_fpu_dirty`: a fresh process starts with MXCSR `0xff80`
  and FCW `0x027f` instead of `FpuState::INITIAL`. Rejected by the first
  witness (`CONTAMINATED`).

Limits:

- **KVM only.** QEMU TCG never raises #XM for an unmasked SSE exception;
  this held for `-cpu max`, `Haswell`, and `qemu64`. The divide completes,
  and the boot fails. `fpu-test` refuses to run without `/dev/kvm`, so it is
  not part of the TCG-portable `make check`.
- **What is covered.** MXCSR control bits and FCW are checked everywhere.
  XMM data is checked only through the XMM0/XMM7 sentinels and the
  conversion scratch registers of the isolation tasks. A witness cannot
  check XMM data, because the Rust code that runs before its first
  instruction may legitimately use XMM registers.
- **Not covered by these FPU runs.** AVX/AVX-512 (no XSAVE support), x87
  data registers or x87 exceptions, AP userspace, and cross-CPU FPU handoff.
  Kernel-only AP controls are recorded separately in the integration result.
- **One KVM host.** Every run used the same host; this does not establish a
  broader hardware envelope.

### Integration qualification, 2026-10-03

Verdict at integration time: **FPU_PROCESS_ISOLATION_VALIDATED on canonical
main**, within the limits above. Replayed
`19ecacde21e61817e4791676763fc4f46a1c18a7` onto
`5b05da6bfd317b08a65847f8b293e54ff4a0d6c7`; mode 13 was already occupied by
SMP lifecycle, so FPU uses 17. The probe and Python oracle are unchanged.
The current CPU-owned stack/CR3/TSS handoff and AP-return refusals remain;
restore suppression moved to `resume_process`'s `cpu::user_fpu()` copy, and
peer-preemption accounting follows the pending-preemption flag in
`commit_cpu_switch`. No obsolete switch or global scratch implementation
was restored.

Qualified source candidate before result-only documentation: staged tree
`9d9eb75f4641a3dc55befe6fc1c246bb34dec793`, source/protocol manifest SHA-256
`dde957d592919c14d38ed80697b64dd71ae4b8102235fa79d3723759f51f1a12`.
Production ELF SHA-256:
`72be3a5f0e82edf6d7b5877cfabdfc667255cece44f18d8ad87a4f971f5255be`.
development-host KVM: A/B preserved 400 rounds each; 461 direct peer preemptions;
one vector-19 fault; one kill; three default-state witnesses; frames zero.
The original 20/20 result above is the lane's historical result, not a
claim that 20 integrated runs were performed.

All commands exited 0: `make fpu-test`, `make fpu-mutants`, `make check`,
`make rt-test`, `python3 scripts/test-rt-oracle.py build/rt.serial.log`,
`make rt-class-test`,
`python3 scripts/test-rt-class-oracle.py build/rtc.serial.log`,
`make elf-matrix-test`, `make disclosure-probe-test`,
`make spawn-image-test`, `make mutants`, and the existing
the development KVM driver script (a development record, not in a source release)
(18/18 controls, kernel-only AP). Both FPU mutants were rejected with
QEMU status 7 and actual `CORRUPTED`/`CONTAMINATED` evidence. The RT
negative oracles rejected their six/eight altered traces, including in the
KVM driver. All prior boundary/accounting assertions held. No kernel defect
was discovered; this does not qualify AP userspace FPU transfer or SMT RT
timing from another lane.

Logs: `build/fpu-integration-20261003-8676a47bbea5/`; guarded SMP logs:
`/tank/nfs/afpu-8676a47bbea5/`. The 101-entry `evidence.sha256` manifest has
SHA-256 `af7c88496558720d9df22799e7b8e0262eb4ce88bbcd55040040819a6bff268d`;
each entry was independently verified. Disposable ISOs and scratch device
images may be reclaimed after terminal review; the qualified executable,
source and scoped logs retain their evidence dependency.

Formalization consideration, controller decision: this replay preserves
the current handoff state machine and relocates observation/negative-control
hooks to its actual restore and commit boundaries. Source correspondence,
unchanged oracles, specific mutation evidence and existing handoff/stop/pipe
models suffice for this bounded integration; no new model is introduced.
Cross-CPU FPU ownership, wider register state and physical timing remain
outside the model and run scopes. Replacement barriers remain the existing
departure/fencing checks; no generation-transfer mechanism is admitted.

## Subsequent guarded multicore qualification

The original phases and ELF/disclosure/FPU records above remain closed and
retain their historical UP or kernel-only AP scope. The subsequently closed
multicore lane is now integrated and requalified (development record, not in a source release).
Its separate CPU0↔CPU1 FXSAVE/SSE and x87 control/arithmetic migration oracle
and both actual transfer controls passed. This narrows that named gap within
the guarded fixture; it does not qualify production AP userspace, arbitrary
CPU-pair transfer, AVX/XSAVE or the original UP probes under general concurrency.
The stop-repeat defect found during this integration does not alter the
original spikes' no-defect results. Production AP guards remain enabled and
sealed release pins remain unchanged.

## Reproduction

```
make hostile-test    # the qualification boot (build/hostile.serial.log)
make check           # canonical suite; includes hostile-test
make mutants         # boundary mutants, incl. user-memory writability
make elf-matrix-test        # adversarial ELF matrix (not in check)
make disclosure-probe-test  # syscall disclosure probe (not in check)

make fpu-test        # FPU/MXCSR isolation (KVM; build/fpu.serial.log)
make fpu-mutants     # FPU restore-skip and dirty-fresh-image mutants (KVM)
```

## Disposition

`hostile-test` is part of the canonical `make check`. The qualification
claims rest on the pinned boot receipt: exact fault vectors, error codes and
CR2 values per case, exact fault/kill/refusal/timeout counters, the witnesses
reaped with status 0, frames back at baseline, tables empty, and the boot
ending on its own before the timeout.

### Successor release boundary, 2026-10-03–04

Component qualification above remains closed and integrated. Historical
successor run `a2b08686-91b1-4f82-b473-58019f1fd984` (kernel `c406d803`,
platform `4ac76ca`) failed the original 300-session capacity equality:
frames 753 → 770 and sshd mapped pages 314 → 331. Other reusable counts
returned and final halt reclaimed all guest frames; B was unbuilt at that
checkpoint. Later bounded diagnostics identified fragmentation and retained
free pool capacity. Qualified J repair became platform `c54dc90`, whose
whole-platform run `4d8660cf-e799-46a6-bea5-4d013191fcb9` was independently
accepted with the original oracle; its own 300-session frame/SSH/FSD page
values stayed 594/218/12. These results do not rewrite the failure or `.3` seal.

Fresh original chain `dcfd9e69-bda7-486d-b6df-820a6dd9aee4` (kernel
`fcfbab9867da40eebb0c4dd266b82484ae7e76c5`, platform `c54dc90`) built B
and completed 28 steps, including accepted A → B / B → A state-preserving
rollback and halted backup/restore, before the actual-release ELF gate
failed at the first-template global census: handles 80 → 78 and frames
627 → 625; processes/pipes/cells stayed 5/30/1. That chain is rejected;
its scoped passes remain evidence, and the decrease's unique cause is unknown.

Separate replay `65121112-4a3e-4d85-a4eb-2a440df011f0` was independently
accepted on the same archived B ISO/kernel/services, using test-only current
startup/stdin fencing before unchanged probe bodies. All 87 ELF cases,
full per-case census, valid post-case controls and sentinel held; all 28
disclosure checks and existing spawn assertions held, with clean drain and
zero final census in all three boots. Acceptance SHA-256:
`ecff1cc074071ed3fc71496a6679aaeafadf5867617cc5e8f7aae51098f4853e`.
This is bounded parent-spawn ordering, not general service quiescence or
unique cause attribution. The preceding `e06dc33d` fixture build failed
before any VM because a direct local ABI dependency was omitted; preserved
receipts distinguish that failure from runtime qualification.

Six-step served continuation `9a88f33c-ebf4-4982-9dd4-ccd3a59ca29d`
completed all existing gates at 2026-10-04 06:37Z. Independent acceptance
`7d5f5f06dc20d6c255d4d55052a8523e36471ada4b5233df6f29c2f9138fb941`
covers exact 300-cycle resource return (594/218/12 frames/SSH/FSD pages),
all 13 containment cases, framing/load and both service recovery cases.
Full recorded-input reconstruction `5048b8a2` completed at 07:16Z with
54 byte-identical files, two generated records not rebuilt, matching GRUB
and existing normalized kernel comparison; ISO wrapper bytes differ.
Independent reconstruction acceptance `07f9b1bb` and overall exact-pair
acceptance `87cda7d9` now accept these composed scopes. B is validated and
sealed locally as `absd-20261003.1`; prior `.3` remains immutable with a
qualified B → A rollback relation. See the successor record (development record, not in a source release).
No kernel
defect is established by the census decrease; no original qualification
result or equality/refusal predicate was weakened. See [the qualification
map](QUALIFICATION.md) for exact receipts, scope and live-evolution limits.
