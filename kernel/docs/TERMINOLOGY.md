# ABSD terminology

ABSD uses ordinary operating-system terms wherever its semantics match
them. A kernel engineer should be able to read the ABI, the diagnostics,
and these docs without learning any other project's vocabulary.

**Do not coin a new ABSD term when a conventional OS term describes the same
semantics accurately.** Keep an ABSD-specific term only for a concept that
is materially different, and define it here.

## Execution

- **Process:** the unit of address space, handle table, PID, parent, and
  lifecycle (`Created`, `Runnable`, `Running`, `Waiting`, then `Exited`,
  `Faulted`, or `Killed`, and `Empty` once reaped and its slot freed). PIDs are monotonic within a boot and
  process-table slots are reused; the kernel rewinds only the newest PID of a
  process that never ran or that a boot-time self-test spawned and killed, so
  PID 1 appears twice in boot logs (audit finding A4).
- **Task:** a process's saved schedulable context (register frame, FPU
  image, kernel and user stacks; `Task` in `src/process.rs`). Every process
  has exactly one task, and there are no threads. This is the thread-like
  sense of "task", not Mach's resource-container sense.
- **Parent, child, wait, reap:** `spawn` makes the caller the parent. `wait`
  collects a terminal child's outcome and frees its slot (reaping).
  Wait-any follows parentage; a targeted wait also needs the wait right.
- **Multi-start program:** a program entered with an ordered vector of the
  handles its parent copied (`spawn_many_copy`, `spawn_image`), instead of
  one handle and one argument word; `multi_entry!` receives it.
- **Catalog program, image:** `spawn` and `spawn_many_copy` start a program
  from the kernel's embedded catalog by index; `spawn_image` starts an
  image, the bytes of a static ELF64 executable held in the caller's
  memory (typically read from a file). The kernel never reads files.
- **Startup vector, startup record:** the ordered handles a multi-start
  program is entered with, and the record on its first handle that names
  their roles and carries argv, the environment, the working directory,
  and the program name (docs/PROCESS-STARTUP.md).
- **Working directory:** userspace process state in the platform runtime
  (from the startup record, else `/`); relative paths are resolved against
  it before the filesystem sees them. The kernel has none.
- **Orphan adoption:** when a process terminates, its children are
  reparented to a live PID 1 (else to the kernel, which frees terminal
  ones). Adoption lets PID 1 reap them. It grants no handle, no info or
  kill right, and no supervision role.
- **Supervisor, worker, instance, replacement:** userspace policy, not
  kernel objects. A supervisor starts a worker; each start is a new process
  (an instance). Starting a new instance after the previous one ended is a
  restart, and that instance is a replacement.
- **Generation** has three distinct senses; write the qualified form
  wherever the context does not make the sense obvious:
  - *replacement generation*: the sequence number (1, 2, 3, ...) of a
    worker instance, passed in its startup word. It is diagnostic data,
    not a fencing token or a right. The client experiment's *event
    generation* is the replacement generation a request is addressed to.
    A durable worker receives its replacement generation encoded in its
    step value instead (each replacement adds `DURABLE_REPLACEMENT_UNIT`);
    it is the same sense, carried differently.
  - *slot generation*: a cell or pipe table slot's reuse counter (see
    Kernel objects).
  - *storage generation*: one complete version of replaced durable state
    (see Storage).
- **Escalation:** a supervisor that has used up its restart budget stops
  restarting and reports failure to its caller.
- **Service:** a userspace convention for a long-lived worker and the
  cells it serves through. The kernel has no service object.

## Authority

- **Handle:** an opaque per-process value that names one kernel object.
  It is looked up only in the caller's own table; stale, guessed, and
  wrong-kind values fail.
- **Rights:** read, write, wait, and kill, carried per handle. Rights only
  narrow: through `duplicate` and through handle copies at spawn. Handles
  are unforgeable per-process references with rights; there is no general
  capability system beyond that.
- **Spawn right:** not a handle right but a per-process attribute. Init
  has it; a child inherits it unless its spawn carries `SPAWN_NO_SPAWN`;
  nothing restores it. Without it every spawn call (`spawn`,
  `spawn_many_copy`, `spawn_image`) returns `-1`.
- **Authority** is prose for the handles and rights a process holds. There
  is no authority object, and parentage, adoption, a PID, or a generation
  never grants a right.
- **Handle transfer** happens only at spawn and is always a copy
  (`spawn`, `spawn_many_copy`). Process handles are never transferred.
- **Broker:** init starting programs on behalf of a worker that lacks the
  spawn right, under a fixed policy (`docs/BROKER.md`). A **broker slot** is
  one set of three preallocated pipes for one brokered child. It is not a
  handle.

## Kernel objects

- **Object:** anything a handle can name: console, process, cell, pipe,
  block device, NIC.
- **Cell:** a versioned shared cell. It holds a 64-bit value and a version.
  `cell_transition` is a conditional transition (compare-and-swap on the
  version), and `cell_wait` blocks until the version changes.
- **Pipe:** a bounded byte stream with reader/writer counts, end of file,
  and broken-pipe refusal.
- **Console:** the serial console, currently one global device.
- **Block device:** sectors, one-sector reads and writes, and a flush.
- **NIC:** the one probed network interface in a `net` boot: whole
  Ethernet frames (14..=1514 bytes, no FCS) sent and received through a
  NIC handle (docs/NETWORK.md). **Frame** always means an Ethernet frame
  here, never a physical memory frame; **socket** and **connection** are
  userspace (smoltcp) terms, not kernel objects.
- **Slot:** an entry in a fixed kernel table. A cell or pipe slot's
  *slot generation* is a reuse counter that stops a stale id from naming a
  later object (a generational index).

## Memory

- **Physical frame:** one 4 KiB page of physical memory held by the frame
  allocator (`src/memory.rs`). Outside the NIC's context "frame" means
  this. A frame the allocator tracks is **free** or **allocated** (tagged
  with its owner: a process, or the kernel); frames the firmware marked
  unusable, frames above the tracked limit (256 MiB), and the ranges
  reserved at boot are not tracked and never counted.
- **Frame counts:** `frame_stats` returns the free and allocated counts,
  the allocation limit (none except during the kernel's own exhaustion
  test), and the frame size, read with interrupts disabled on the one
  CPU: one exact allocator state at the instant of the call, including
  the caller's own frames. The kernel keeps no history, average, or rate
  of them.

## Time

- **Tick:** one PIT interrupt, about 1 ms; `time` counts them since boot.
  Monotonic within a boot; it restarts at every boot.
- **Wall clock:** `wall_clock` reads the CMOS RTC: whole seconds since the
  Unix epoch, declared UTC. It is a hardware reading, not a synchronized
  clock, and it is refused rather than guessed when unreadable.
- **Boot identity:** 16 random bytes drawn once per boot (`boot_id`); with
  ticks it names an instant on this boot's clock.
- **Clock epoch:** a boot identity plus its tick count is one monotonic
  clock epoch. Evidence tied to monotonic time carries the epoch it was
  measured under. An epoch never silently claims continuity across a state
  restoration that can rewind it: restoring a VM snapshot restores the old
  boot identity and tick count together, and ABSD has no witness the
  snapshot does not also rewind, so it cannot detect the restore. Snapshot
  restore is therefore outside the clock-validity model today. Suspend,
  pausing the virtual machine, and lost ticks under emulation lengthen an
  epoch rather than break it; ticks measure guest time, never wall time.
  Human time (the wall clock, dates, file times) is a separate question.

## Storage

Everything above the block device is userspace (the Rust platform repository).

- **Acknowledged write:** `block_write` returned after the device reported
  completion. **Flush:** the device's cache-flush barrier.
- **Commit:** only where a protocol names an explicit commit point (a
  journal commit marker, a filesystem superblock write, an activation
  record). **Durable:** survives the stated failure model, which each
  document names.
- **Storage generation:** one complete version of replaced durable state,
  stored in a generation region. An **activation record** is the durable
  record that selects which storage generation is current.
- **Step value, step cell:** in a durable boot (`durable=N`), N is the
  boot's step value. Init passes it to the workload in a read-only cell,
  the step cell; the value means nothing to the kernel or init. A
  replacement worker gets the step value plus `DURABLE_REPLACEMENT_UNIT`
  (10^12), so it can tell it is a replacement. Older text calls the value
  the "step word" and that unit the "replacement digit".
- **Recovery:** reading durable or retained state after a failure and
  reconstructing or reconciling it enough to justify continuing.
- **Exclusive writer:** init gives a write-capable block handle to one
  process at a time. This is init's policy. The kernel enforces only
  handle rights.

## Failure and result language

- **Outcome:** how a process ended: `Exited(status)`, `Faulted` (vector,
  address, error), or `Killed`. **Status** is the exit status. A syscall
  **result** is its return value (negative for errors).
- **Completed, acknowledged, committed, durable** are different claims.
  Use the weakest one the evidence supports.
- **Refused:** rejected with nothing changed (fail closed).
- **Indeterminate:** recovery cannot decide between committed and absent.
  Use it only for that three-way case.
- **Restart and replacement are not recovery.** A replacement process
  exists once it is spawned. Recovery is claimed only after its outcome
  and the retained state have been reconciled.
- **Reconcile:** compare retained state with a request, then apply it
  once, skip it because it was already applied, or refuse it. A request
  that changed a cell was *applied*; reserve *committed* for storage.
- **Mapped pages:** the grow-down stack maps pages on demand; it does not
  "commit" them in the storage sense.
- **Stop:** `machine_stop` ends the whole machine abruptly at a named
  point, through a machine handle with the stop right (init's, or the
  stop-only copy init gives a qualification durable worker). A graceful
  or forced stop of a worker is a userspace request followed by wait, or
  by kill and reap.
- **Machine handle:** the handle to the machine object. The kernel issues
  one, to init; its rights are stop (now, abruptly), restart (at the end
  of the boot, after accounting), and recover (a reset now, with no
  accounting). The handle alone authorizes each; no PID or boot mode is
  consulted.
- **Qualification boot / served boot:** a qualification boot is a test
  run with deadlines, ending by its workload's outcome or its deadline. A
  served boot (`fsd served`) serves until the operator asks for its end;
  its worker has no deadline.
- **Halt, restart, orderly shutdown:** a halt is the kernel's normal end
  of a boot after init exits (debug-exit under QEMU, `cli; hlt`
  otherwise; not ACPI power-off). A restart is a reset armed by
  `machine_restart` and taken at that end. An orderly shutdown is the
  userspace sequence before either: sessions end, the file server
  commits and stops, init reaps.

## Hardware

- **Qualification labels:** EMULATOR-QUALIFIED, EXACT-HARDWARE-QUALIFIED,
  MACHINE-CONFIGURATION-QUALIFIED, and HARDWARE-FAMILY-SUPPORTED, defined
  with their rules in docs/hardware/QUALIFICATION.md. Subsystems earn them
  independently, each on named evidence.
- **Boots to identity:** the record a successful physical survey boot
  (`survey`) makes for one machine, firmware version, and boot path. It is
  not a label and advances no subsystem.
- **Does not write media / does nothing stateful to the controller:** two
  different promises. The physical ISO's suite entry keeps the first (no
  block write or flush can be issued) but resets and enables the NVMe
  controller, creates queues, and reads one sector. The survey entry keeps
  both: it never claims, maps, or starts a storage or network controller.

## Layering rule

ABSD owns mechanisms: processes, handles, rights, cells, pipes, block
devices, and the userspace storage formats built on them. ABSD can run
Constellation programs (AG, Pulse, NQ, Nightshift). Their vocabulary
(warrant, standing, admission, testimony, issuance, settlement,
jurisdiction, governed effect, operator acceptance, custody) belongs to
those programs, so it appears only in their ports, patches, fixtures, and
markers, or in explicit design comparisons. ABSD semantics are never
defined in those terms. Constellation may interpret ABSD mechanisms, but
ABSD does not interpret Constellation semantics.

## Retained names

These names predate this glossary and are kept because renaming them would
touch the ABI, a Rust API that other code uses, or an established test
artifact:

- `transfer` (syscall 21, `SYS_TRANSFER`) is a timed `read`/`write`. It is
  not handle transfer.
- `activate_spawn` (kernel-internal) publishes a fully built child from
  `Created` to `Runnable`. It is unrelated to a storage activation record.
- The catalog program `recovery-worker` and `recovery_arg` are the request
  reconciliation experiment. The name is accurate only because that
  program reconciles state.
- `INFO_STATE_LIVE` (1) means runnable or running.
- In the platform repository, `storage::mount_read_only_authority` means
  "mount through a read-only duplicate of the block handle", and the
  `FS READ ONLY AUTHORITY OK` and `NQ READONLY AUTHORITY OK` markers mean
  the kernel refused a write through that handle.
- In the supervision tests, "admission control" means admitting optional
  processes against process-table capacity. It is the conventional
  resource-control term, not Constellation admission.
