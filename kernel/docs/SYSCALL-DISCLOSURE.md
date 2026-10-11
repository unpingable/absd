# Syscall information-disclosure audit

Bounded audit, 2026-10-02, from kernel `main` 4212fff. The question: can any
syscall or result record expose kernel virtual or physical addresses, stale
kernel or object memory, uninitialized bytes or padding, another process's
private state, or internal metadata beyond what the ABI intends?

Result: **no cross-boundary information leak found.** Every output path was
read from source. The few properties source alone did not settle were
checked by `make disclosure-probe-test` (`user/src/bin/disclosure_probe.rs`,
28 checks), and two kernel mutants show that the probe detects the
corresponding defects. No kernel code was repaired. After integration one
test was: see "Integration repair".

## Output inventory

Userspace sees kernel-produced bytes through three channels: the RAX result,
the registers a child starts with, and `copy_to_user`. There are exactly 14
`copy_to_user` sites (`src/syscalls.rs`, `src/syscalls/nic.rs`,
`src/sched.rs`).

Integration revalidation corrected the original count of 13: there are ten
calls in `src/syscalls.rs`, two in `src/syscalls/nic.rs`, and two in
`src/sched.rs`. All were already covered by the inventory below; no copyout
path was added since the spike base.

| Syscall | Output | Origin of the bytes | Classification |
|---|---|---|---|
| `write` 1, `yield` 2, `exit` 3, `sleep` 18, `rt_next` 39 | RAX count / 0 / never returns | — | intended |
| `getpid` 4 | RAX: own PID | process slot | intended (PIDs are global and monotonic apart from boot-time rewinds of self-test PIDs, audit A4, so they reveal how many processes have been created; not claimed secret) |
| `spawn` 5, `spawn_many_copy` 22, `spawn_image` 31 | RAX: process handle; the child's handle vector on its own stack | `HandleTable::insert`; a zeroed local array, only `8 * count` bytes copied | intended |
| `wait` 6 | 32-byte outcome record; RAX child PID | `Outcome::to_bytes`: explicit four-word encoding, unused words zero | intended; fault fields below |
| `map` 7 | RAX: user address | `find_unmapped_run` in the heap window; frames zeroed by `map_user_page` | intended (user value, probed) |
| `unmap` 8, `close` 9, `kill` 20, `block_write` 26, `block_flush` 27, `nic_send` 33, `machine_*` 37/38/40, `block_write_many` 44 | RAX status | — | intended |
| `cell_create` 10, `pipe_create` 16, `duplicate` 13 | RAX: handle | `encode(index, tag)`, tag = `(own pid << 24) | issue counter` | harmless, ABI-visible: a handle value carries the holder's own PID and issue count, nothing about another process |
| `cell_read` 11 | `{version, value}` | zeroed local, both words set | intended; reuse probed |
| `cell_transition` 12, `cell_wait` 14 | RAX version | cell slot | intended |
| `read` 15 (pipe / console), `transfer` 21 | bytes | zeroed 256-byte local; only the `read` count copied; pipe ring read only below `len` | intended; refusal probed |
| `time` 17 | RAX ticks | timer counter | intended |
| `info` 19 | `{pid, parent, program, state}` | self (handle 0) or a child named by a process handle the caller holds | intended; process handles cannot be inherited (`read_transfers`, legacy `spawn`), so this is parent-scoped (probed) |
| `block_info` 24 | `{sector_count, 512}` | zeroed local | intended (see refusal note) |
| `block_read` 25 | one sector | zeroed local filled by the device; range checked first | intended (device data) |
| `block_read_many` 43 | up to eight sectors | static kernel staging page; only the `sectors * 512` bytes the device just filled are copied, and only after the whole command completed; record, span, and buffer range checked first | intended (device data) |
| `boot_id` 29 | 16 RDRAND bytes, the same for every process in one boot | `BOOT_ID` | intended (ABI says so) |
| `wall_clock` 30 | RAX seconds | CMOS | intended |
| `nic_info` 32 | MAC, flags, six counters | `NicInfo::to_bytes`, explicit | intended; no BAR or DMA address (see refusal note) |
| `nic_receive` 34 | one frame | the device's descriptor length, at most `NIC_FRAME_MAX`; range checked first | intended (device data) |
| `frame_stats` 35 | free/allocated/limit/page size | allocator counters, explicit encoding | intended, documented as a whole-machine count visible to anyone; no rights (architecture audit finding B3: ambient observation, cross-session side channel, not gated) |
| `pipe_info` 36 | available, space, readers, writers | pipe slot | intended: counts for a shared object the caller holds |
| `resource_census` 41 | processes, handles, pipes, cells, frames | whole-kernel counts, explicit encoding | intended, documented as whole-kernel; no rights (audit finding B3, as for `frame_stats`; accepted, docs/architecture-audit-20261002/B3-DECISION.md) |
| `abi_version` 42 | RAX constant | compiled in | intended |

No syscall returns a kernel virtual address, a physical address, or an
object-table index other than the handle slot index in the caller's own
handle value. No record is a Rust struct copied as raw memory: every
encoder builds a zeroed byte array or a word array, so padding cannot
reach userspace.

### Registers

- A child's saved context is `[0; SAVED_FRAME_WORDS]` (and its slot was reset
  to `Process::EMPTY` at claim) with only RIP, CS, RFLAGS, RSP, SS, and the
  documented entry arguments set. Its FPU image is `FpuState::INITIAL`.
- `syscall_stub`, `timer_stub`, the stack-fault path, and
  `resume_user_context` restore all 15 GPRs and the FXSAVE image from that
  task's own frame. A syscall changes only RAX.
- e1000 transmit zero-pads frames shorter than the wire minimum
  (`buffer[bytes..wire].fill(0)`), so there is no padding leak of old buffer
  bytes.

### Object reuse

- Cells: `create` sets version 0 and the given value; `release` bumps the
  generation and clears both.
- Pipes: `create` and `release` reset `head`/`len`. Old ring bytes stay in
  memory but are unreachable, since reads stop at `len`.
- Handles: slots carry a monotonically increasing tag, so a stale value fails
  `-9` instead of naming the object that replaced it.
- Frames: `map_user_page` zeroes every frame it maps (image, BSS, stack,
  stack growth, heap), and page-table frames are zeroed. Freed frames are not
  scrubbed, but no path hands one to userspace without zeroing it.

## Dynamic probes

`make disclosure-probe-test`, one QEMU boot; the kernel's closing accounting
line must read `frames=0 processes=0 cells=0 pipes=0`.

| Check | What it shows |
|---|---|
| `info-self`, `info-child`, `cell-read`, `pipe-info`, `frame-stats`, `resource-census`, `wait-exited`, `wait-faulted` | Two runs with prefill 0xa5 and 0x5a agree on every record byte (0 unwritten), and 16 guard bytes either side are untouched. |
| `boot-id` | QEMU's default CPU has no RDRAND: `-38` with the record untouched. Coverage on hardware rests on source. |
| `*-refused` (info, cell_read, pipe_info, frame_stats, census, wait, pipe read) | A record straddling into an unmapped page, or in read-only text, is `-14` with the mapped bytes unchanged. The refused `wait` leaves the child unreaped, and the refused pipe read leaves all 16 bytes in the pipe. |
| `process-handle-not-inherited` | `spawn_image` copying a process handle is refused (`-9`). |
| `stale-process-handle`, `stale-cell-handle`, `stale-pipe-handle` | After reap or close, the old value answers `-9` while the successor works; a successor cell is `(0, 7)` and a successor pipe is empty although its predecessor died holding 16 unread bytes. |
| `child-entry-registers` | The parent loads a pattern into RBX, RBP, RCX, R8-R15, and XMM0-15 and issues `spawn_image` with `int 0x80` directly. The child sees every undefined GPR and every XMM register at zero and MXCSR at 0x1f80. |
| `fault-*` | A page fault reports exactly the address the child chose. |
| `map-address` | `map` returns an address in the user heap window. |

Mutants, each applied temporarily and reverted:

| Mutant | Detected as |
|---|---|
| `info` copies 24 of its 32 bytes | `info-self`/`info-child` `unwritten=8` |
| `populate` leaves the kernel stack top in the child's R8 | `child-entry-registers` exit 1 |

## Integration repair

Commit eeb0635 repaired a partly vacuous check. In the integrated run the
pipe successor took slot 2 (freed by closing the cell successor) while the
stale pipe handle named slot 3, so `stale-pipe-handle` only showed an empty
slot refusing. The cell successor is now kept open until after the pipe
successor, and all three stale-handle checks assert that the successor
reuses the stale handle's slot (`(successor & 0xff) == (old & 0xff)`), so the
tag, not an empty slot, is what refuses the old value. No kernel change.

## Classified observations

- **Harmless, ABI-visible.** The page-fault error code's present bit
  tells a parent whether a supervisor address is mapped: the identity map at
  0x100000 reports `0x5`, while the user-half gap and the kernel half report
  `0x4`. A child can thus probe the kernel's virtual layout through its own
  death. That layout is fixed and documented (`abi/src/layout.rs`), and no
  ABSD document claims KASLR, so nothing is disclosed that the ABI does not
  already state.
- **Harmless, ABI-visible.** `frame_stats` and `resource_census` show
  whole-machine occupancy to any process, so another process's allocations
  are observable in aggregate. They are documented that way.
- **Not a leak; refusal is not atomic.** `block_info` and `nic_info` do not
  call `check_user_range` before `copy_to_user`, which copies page by page.
  A record straddling into an unmapped page receives its first bytes and
  then `-14`. Those bytes are fully initialized and the caller holds the
  read right, so this discloses nothing, but it differs from every other
  record, which is validated whole first. It was not exercised dynamically
  because this boot has neither device.
- **Test artifact.** A load from 0x8000_0000_0000_0000 reports #PF with
  error `0x5` under QEMU TCG. TCG truncates the non-canonical address to 48
  bits and walks PML4 entry 0; hardware raises #GP and the record would
  carry the child's RIP. The probe accepts either and checks that the
  address is the child's own value.

## Residual uncertainty

- Timing and counter side channels (`time`, `frame_stats`, `resource_census`,
  scheduling) were not assessed; nothing claims their absence.
- Device-sourced bytes (`block_read`, `nic_receive`) are trusted to be what
  the device wrote. A device that reports a longer length than it wrote
  could return stale DMA-buffer bytes; the driver bounds the length but
  does not scrub buffers between frames.
- `boot_id`, `block_*`, and `nic_*` were not dynamically exercised in this
  boot.
- Single CPU only: the cross-CPU FPU and register hand-off is not covered
  here (see the FPU/MXCSR lane, which is KVM-only).
- QEMU/TCG only.
