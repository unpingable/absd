//! Process runtime: spawn and load, context switching, sleeping and idling,
//! wait/reap, and fault disposition. Syscall handlers live in `syscalls`;
//! the end-of-boot evaluation in `suite`.
//!
//! Terminal cleanup always runs on the kernel entry stack with the boot page
//! tables active, so a process's own kernel stack and page tables are never
//! freed while in use. Only PID, parent, and outcome survive termination.

use crate::cpu;
use crate::serial;
#[path = "sched_rt.rs"]
mod rt_runtime;
use crate::suite::finish_process_suite;
use crate::syscalls::{release_object, retain_object, wake_console_readers, wake_nic_receivers};
use crate::vm;

pub(crate) use crate::arch_runtime::enter_kernel_context_and_reap;
use crate::arch_runtime::{assert_departed, enter_cpu_switch, resume_user_context, save_frame};
use absd_kernel::arch::ExecutionState;
use absd_kernel::elf::{self, ImageSource, PF_EXECUTE, PF_WRITE};
use absd_kernel::handle::{Object, RIGHT_READ, RIGHT_WRITE};
use absd_kernel::layout::{
    KERNEL_STACK_PAGES, USER_IMAGE_MAX, USER_IMAGE_MIN, USER_STACK_PAGES, USER_STACK_TOP,
};
use absd_kernel::memory::{Frame, FrameAllocator, FrameOwner, MAX_OWNER_ID, PAGE_SIZE};
use absd_kernel::object::{CellTable, PipeTable};
use absd_kernel::process::{
    AddressSpace, ClaimError, FpuState, KERNEL_PARENT, MAX_PROCESSES, Process, ProcessState,
    ProcessTable, WaitKind, stack_growth_page,
};
use absd_kernel::syscall::{
    ERROR_AGAIN, ERROR_FAULT, ERROR_INVALID, ERROR_NO_CHILD, ERROR_NO_MEMORY, ERROR_NOT_FOUND,
    ERROR_PID_EXHAUSTED, ERROR_TIMEOUT, ERROR_TOO_MANY_HANDLES, MAX_SPAWN_HANDLES,
};
use absd_kernel::user_memory::{copy_from_user, copy_to_user};
use absd_kernel::user_program::{PROGRAMS, uses_multi_start};
pub(crate) use rt_runtime::{
    arm_fixture as rt_arm_fixture, complete as rt_complete, flush as flush_rt_trace, make_runnable,
};

/// Init's machine handle: stop now, restart at the end of the boot, and
/// reset now without accounting.
const INIT_MACHINE_RIGHTS: u8 = (absd_kernel::syscall::MACHINE_RIGHT_STOP
    | absd_kernel::syscall::MACHINE_RIGHT_RESTART
    | absd_kernel::syscall::MACHINE_RIGHT_RECOVER) as u8;

/// `Process::program` for a child started by `spawn_image`.
pub(crate) const IMAGE_PROGRAM: usize = absd_kernel::program::IMAGE as usize;

pub(crate) const KERNEL_STACK_BYTES: u64 = KERNEL_STACK_PAGES as u64 * PAGE_SIZE;

/// Fresh kernel stacks are filled with this byte; the deepest overwritten
/// address at release time is the stack's high-water mark.
const KERNEL_STACK_CANARY: u8 = 0xa5;

pub static mut PROCESSES: ProcessTable = ProcessTable::new();

/// Kernel-global cell objects, reference counted by process handles.
static mut CELLS: CellTable = CellTable::new();

/// Kernel-global pipes, reference counted by process handles.
static mut PIPES: PipeTable = PipeTable::new();

/// Final validation policy. PID 1 is always userspace init; its startup word
/// selects the suite or the child program appropriate to this mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootMode {
    Suite,
    RtTest,
    RtClass,
    Shell,
    /// Init runs `fuzz`: the kernel must survive random syscalls and reclaim.
    Fuzz,
    /// Init launches the opt-in embedded multi-start workload through pipes.
    External,
    /// External-style workload plus the block device; `stop` is permitted.
    Durable,
    /// Init runs the kernel's NIC qualification program with the NIC.
    NetProbe,
    /// Init runs the hostile-userspace qualification battery; the kernel
    /// must contain every case and reclaim (docs/HOSTILE-USERSPACE.md).
    Hostile,
    /// Controlled kernel-only AP ownership and stop-fence qualification.
    SmpLifecycle,
    /// Stop a BSP spawner after Created child/handle installation.
    SmpCreatedStop,
    /// Init runs the FPU/MXCSR state-isolation qualification
    /// (docs/HOSTILE-USERSPACE.md).
    FpuTest,
}

static mut BOOT_MODE: BootMode = BootMode::Suite;
static mut HANDOFF_NEGATIVE: bool = false;

pub fn arm_handoff_negative() {
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(HANDOFF_NEGATIVE), true) }
}

fn take_handoff_negative() -> bool {
    unsafe {
        let flag = core::ptr::addr_of_mut!(HANDOFF_NEGATIVE);
        let value = core::ptr::read_volatile(flag);
        core::ptr::write_volatile(flag, false);
        value
    }
}

pub fn set_boot_mode(mode: BootMode) {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(BOOT_MODE), mode);
    }
}

pub(crate) fn boot_mode() -> BootMode {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BOOT_MODE)) }
}

#[derive(Default)]
pub struct RuntimeStats {
    pub preempts: u64,
    /// Timer preemptions from one fpu-mxcsr task directly to another: the
    /// fpu-test isolation tasks never block, so each crossed a timer switch.
    pub fpu_peer_preempts: u64,
    pub writes: u64,
    pub unknown_refusals: u64,
    pub pointer_refusals: u64,
    pub handle_refusals: u64,
    pub wait_refusals: u64,
    pub spawns: u64,
    pub spawn_refusals: u64,
    pub exits: u64,
    pub faults: u64,
    pub kills: u64,
    pub reaps: u64,
    pub maps: u64,
    pub unmaps: u64,
    pub map_refusals: u64,
    pub transitions: u64,
    pub stale_transitions: u64,
    pub cell_refusals: u64,
    pub cell_waits: u64,
    pub cell_wakeups: u64,
    pub pipe_reads: u64,
    pub pipe_writes: u64,
    pub pipe_waits: u64,
    pub pipe_wakeups: u64,
    pub pipe_refusals: u64,
    pub sleeps: u64,
    pub timeouts: u64,
    pub idle_entries: u64,
    pub console_reads: u64,
    pub console_waits: u64,
    pub stack_grows: u64,
    pub init_status: Option<i32>,
    pub frame_baseline: usize,
    /// Deepest kernel-stack use observed across every released process.
    pub kernel_stack_peak: u64,
}

pub static mut STATS: RuntimeStats = RuntimeStats {
    preempts: 0,
    fpu_peer_preempts: 0,
    writes: 0,
    unknown_refusals: 0,
    pointer_refusals: 0,
    handle_refusals: 0,
    wait_refusals: 0,
    spawns: 0,
    spawn_refusals: 0,
    exits: 0,
    faults: 0,
    kills: 0,
    reaps: 0,
    maps: 0,
    unmaps: 0,
    map_refusals: 0,
    transitions: 0,
    stale_transitions: 0,
    cell_refusals: 0,
    cell_waits: 0,
    cell_wakeups: 0,
    pipe_reads: 0,
    pipe_writes: 0,
    pipe_waits: 0,
    pipe_wakeups: 0,
    pipe_refusals: 0,
    sleeps: 0,
    timeouts: 0,
    idle_entries: 0,
    console_reads: 0,
    console_waits: 0,
    stack_grows: 0,
    init_status: None,
    frame_baseline: 0,
    kernel_stack_peak: 0,
};

/// Physical address of the boot PDPT shared by every address space.
static mut KERNEL_PDPT: u64 = 0;

pub(crate) unsafe fn table() -> &'static mut ProcessTable {
    crate::kernel_lock::assert_current_owner();
    unsafe { &mut *core::ptr::addr_of_mut!(PROCESSES) }
}

pub(crate) unsafe fn cells() -> &'static mut CellTable {
    crate::kernel_lock::assert_current_owner();
    unsafe { &mut *core::ptr::addr_of_mut!(CELLS) }
}

pub(crate) unsafe fn pipes() -> &'static mut PipeTable {
    crate::kernel_lock::assert_current_owner();
    unsafe { &mut *core::ptr::addr_of_mut!(PIPES) }
}

/// Central end-of-boot reclamation check for every reference-counted object
/// table. New object kinds must join this one boundary.
pub(crate) unsafe fn object_tables_empty() -> bool {
    unsafe { cells().live() == 0 && pipes().live() == 0 }
}

pub(crate) unsafe fn stats() -> &'static mut RuntimeStats {
    crate::kernel_lock::assert_current_owner();
    unsafe { &mut *core::ptr::addr_of_mut!(STATS) }
}

fn next_runnable(current: usize) -> Option<usize> {
    if crate::modern_smp::enabled() {
        crate::modern_smp::select(current, cpu::id(), true)
    } else if crate::smp_user::enabled() {
        crate::smp_user::next_runnable(current, cpu::id())
    } else {
        unsafe { table() }.next_runnable_after(current)
    }
}

/// Records the boot page-table roots and the frame-accounting baseline
/// against which reclamation is judged.
pub unsafe fn init() {
    unsafe {
        KERNEL_PDPT = crate::arch_runtime::kernel_table();
        stats().frame_baseline = vm::frames().allocated_frames();
    }
}
pub(crate) unsafe fn spawn_startup_actor() -> u64 {
    unsafe { spawn_startup_actor_role(31) }
}
pub(crate) unsafe fn spawn_startup_actor_role(role: u64) -> u64 {
    assert!(crate::smp_startup::active());
    crate::kernel_lock::assert_held(0);
    assert!(
        role == 31
            || (crate::smp_app_pressure::startup_mode() && crate::smp_app_pressure::role(role))
    );
    assert_eq!(cpu::current(), cpu::NO_TASK);
    assert!((1..cpu::count()).all(|c| crate::smp_user::calls_on(c) == 0));
    let pid =
        unsafe { spawn_with_arg(absd_kernel::program::SMP_USER as usize, KERNEL_PARENT, role) }
            .unwrap();
    let slot = unsafe { table() }.slot_of(pid).unwrap();
    // AP is parked until its command is published; no runnable consumer can
    // observe the actor before these qualification-only restrictions finish.
    while let Some(handle) = unsafe { table() }.entries[slot].handles.take_any() {
        unsafe {
            release_object(handle.object, handle.rights);
        }
    }
    let p = &mut unsafe { table() }.entries[slot];
    p.may_spawn = false;
    p.task.context.set_argument(4, 0);
    pid
}

/// Proves the bounded failure model of `spawn`: with a frame quota one
/// frame larger each time, a load fails at every allocation it makes (page
/// tables, image pages, stack pages, kernel stack) until it finally
/// succeeds. Every failure must return `NoMemory` and leave the
/// allocated-frame count and process table exactly as they were; the one
/// success is ended and must reclaim to baseline too. Runs before the first
/// real spawn.
pub unsafe fn exhaustion_test(program: usize) -> bool {
    let frames = unsafe { vm::frames() };
    let baseline = frames.allocated_frames();
    // Enough for every image page plus page tables and stacks: the bound
    // follows the program instead of assuming a small image.
    let image_pages = PROGRAMS[program].bytes.len().div_ceil(4096);
    let bound = image_pages + 64;
    let mut shortfall = 0;
    let ok = loop {
        frames.set_quota(Some(baseline + shortfall));
        let result = unsafe { spawn(program, KERNEL_PARENT) };
        let table = unsafe { table() };
        match result {
            Err(SpawnError::NoMemory)
                if frames.allocated_frames() == baseline && table.occupied_count() == 0 =>
            {
                shortfall += 1;
                if shortfall > bound {
                    serial::write("SPAWN EXHAUSTION FAILED: never succeeded\n");
                    break false;
                }
            }
            Ok(pid) => {
                // The load that fit is ended like a killed child.
                let Some(index) = table.slot_of(pid) else {
                    break false;
                };
                table.entries[index].state = ProcessState::Killed;
                unsafe { terminate(index) };
                // Leave no trace: the real first process must still be PID 1
                // and its status must not be confused with this one's.
                table.rewind_newest_pid(pid);
                unsafe {
                    let stats = stats();
                    stats.init_status = None;
                    stats.spawns -= 1;
                    stats.reaps -= 1;
                }
                let reclaimed =
                    frames.allocated_frames() == baseline && table.occupied_count() == 0;
                if !reclaimed {
                    serial::write("SPAWN EXHAUSTION FAILED: success not reclaimed\n");
                }
                serial::write("SPAWN EXHAUSTION frames_per_process=");
                serial::decimal(shortfall as u64);
                serial::write("\n");
                break reclaimed;
            }
            _ => {
                serial::write("SPAWN EXHAUSTION FAILED at quota +");
                serial::decimal(shortfall as u64);
                serial::write("\n");
                break false;
            }
        }
    };
    frames.set_quota(None);
    ok
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpawnError {
    UnknownProgram,
    NoSlot,
    PidExhausted,
    NoHandles,
    NoMemory,
    BadImage,
}

impl SpawnError {
    pub(crate) const fn code(self) -> i64 {
        match self {
            Self::UnknownProgram => ERROR_NOT_FOUND,
            Self::NoSlot => ERROR_AGAIN,
            Self::PidExhausted => ERROR_PID_EXHAUSTED,
            Self::NoHandles => ERROR_TOO_MANY_HANDLES,
            Self::NoMemory => ERROR_NO_MEMORY,
            Self::BadImage => ERROR_INVALID,
        }
    }
}

/// Creates a runnable process from an embedded program image, building it
/// in place in its table slot. Every frame the loader touched is returned
/// and the slot released if any step fails.
pub unsafe fn spawn(program: usize, parent: u64) -> Result<u64, SpawnError> {
    unsafe { spawn_with_arg(program, parent, 0) }
}

/// Creates and atomically activates a legacy-entry program with an explicit
/// startup argument. The kernel uses this to start init with its boot mode;
/// userspace spawn reaches the same build-then-activate boundary.
pub unsafe fn spawn_with_arg(program: usize, parent: u64, arg: u64) -> Result<u64, SpawnError> {
    let pid = unsafe { spawn_with(program, parent, None, arg)? };
    unsafe { activate_spawn(pid) };
    Ok(pid)
}

/// A handle duplicated into a child at spawn, with the rights it carries.
/// With `as_console` it replaces the child's console (slot 0) so the
/// program's ordinary output flows into it; otherwise it arrives in `RSI`.
#[derive(Clone, Copy)]
pub struct Transfer {
    pub object: Object,
    pub rights: u8,
    pub as_console: bool,
}

impl Transfer {
    pub const EMPTY: Self = Self {
        object: Object::None,
        rights: 0,
        as_console: false,
    };
}

/// `spawn` plus the child's entry arguments: an optional duplicated handle
/// (`RSI`, or zero) and one argument word (`RDX`). The reference a
/// transferred cell handle carries is taken before the child can run.
pub unsafe fn spawn_with(
    program: usize,
    parent: u64,
    transfer: Option<Transfer>,
    arg: u64,
) -> Result<u64, SpawnError> {
    let one = [transfer.unwrap_or(Transfer::EMPTY)];
    let transfers = if transfer.is_some() { &one[..] } else { &[] };
    unsafe { spawn_transferred(program, parent, transfers, arg, false) }
}

/// Creates a child with an ordered, explicitly copy-only set of handles.
/// The child starts with `RSI` pointing to its ordered handle-value vector
/// near the top of its own stack and `RDX` holding the vector length.
pub unsafe fn spawn_many_copy(
    program: usize,
    parent: u64,
    transfers: &[Transfer],
) -> Result<u64, SpawnError> {
    if transfers.len() > MAX_SPAWN_HANDLES {
        return Err(SpawnError::NoHandles);
    }
    unsafe { spawn_transferred(program, parent, transfers, 0, true) }
}

#[cfg(feature = "frame-admission-v0")]
pub unsafe fn spawn_many_copy_reserved(
    program: usize,
    parent: u64,
    transfers: &[Transfer],
    total: usize,
) -> Result<u64, SpawnError> {
    let image = PROGRAMS.get(program).ok_or(SpawnError::UnknownProgram)?;
    if !uses_multi_start(program) {
        return Err(SpawnError::BadImage);
    }
    let parsed = elf::parse(image.bytes).map_err(|_| SpawnError::BadImage)?;
    let minimum =
        absd_kernel::frame_admission::construction_frames(&parsed).ok_or(SpawnError::BadImage)?;
    if total < minimum {
        return Err(SpawnError::BadImage);
    }
    unsafe {
        spawn_from_budget(
            program,
            image.bytes,
            parent,
            transfers,
            0,
            true,
            Some(total),
        )
    }
}

/// An image in the calling process's memory (`spawn_image`). The caller
/// has already checked that the whole range is mapped user memory; the
/// loader copies from it through the parent's page tables, a header or
/// one page at a time, so the image is never resident in kernel memory.
pub struct UserImage {
    pub space: AddressSpace,
    pub address: u64,
    pub length: usize,
}

impl ImageSource for UserImage {
    fn len(&self) -> usize {
        self.length
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), elf::ElfError> {
        if out.is_empty() {
            return Ok(());
        }
        if offset
            .checked_add(out.len())
            .is_none_or(|end| end > self.length)
        {
            return Err(elf::ElfError::HeaderTooSmall);
        }
        unsafe { copy_from_user(&self.space, self.address + offset as u64, out) }
            .map_err(|_| elf::ElfError::Unreadable)
    }
}

/// Creates a multi-start child from an image in the parent's memory, with
/// the same ordered handle copies as `spawn_many_copy`. The child is
/// recorded with the program index `IMAGE`.
pub unsafe fn spawn_image(
    image: &UserImage,
    parent: u64,
    transfers: &[Transfer],
) -> Result<u64, SpawnError> {
    if transfers.len() > MAX_SPAWN_HANDLES {
        return Err(SpawnError::NoHandles);
    }
    unsafe { spawn_from(IMAGE_PROGRAM, image, parent, transfers, 0, true) }
}

/// Experimental image admission shares the normal loader and teardown.
#[cfg(feature = "frame-reservation-experiment")]
pub unsafe fn spawn_image_reserved(
    image: &UserImage,
    parent: u64,
    transfers: &[Transfer],
    total: usize,
) -> Result<u64, SpawnError> {
    if transfers.len() > MAX_SPAWN_HANDLES {
        return Err(SpawnError::NoHandles);
    }
    unsafe {
        spawn_from_budget(
            IMAGE_PROGRAM,
            image,
            parent,
            transfers,
            0,
            true,
            Some(total),
        )
    }
}

unsafe fn spawn_transferred(
    program: usize,
    parent: u64,
    transfers: &[Transfer],
    arg: u64,
    vector_start: bool,
) -> Result<u64, SpawnError> {
    let Some(image) = PROGRAMS.get(program) else {
        return Err(SpawnError::UnknownProgram);
    };
    if uses_multi_start(program) != vector_start {
        return Err(SpawnError::BadImage);
    }
    unsafe { spawn_from(program, image.bytes, parent, transfers, arg, vector_start) }
}

#[cfg(feature = "frame-reservation-experiment")]
pub unsafe fn spawn_reserved(
    program: usize,
    parent: u64,
    total: usize,
    transfer: Option<Transfer>,
) -> Result<u64, SpawnError> {
    let image = PROGRAMS.get(program).ok_or(SpawnError::UnknownProgram)?;
    let one = [transfer.unwrap_or(Transfer::EMPTY)];
    let transfers = if transfer.is_some() { &one[..] } else { &[] };
    unsafe {
        spawn_from_budget(
            program,
            image.bytes,
            parent,
            transfers,
            0,
            uses_multi_start(program),
            Some(total),
        )
    }
}

unsafe fn spawn_from<S: ImageSource + ?Sized>(
    program: usize,
    image: &S,
    parent: u64,
    transfers: &[Transfer],
    arg: u64,
    vector_start: bool,
) -> Result<u64, SpawnError> {
    unsafe { spawn_from_budget(program, image, parent, transfers, arg, vector_start, None) }
}

unsafe fn spawn_from_budget<S: ImageSource + ?Sized>(
    program: usize,
    image: &S,
    parent: u64,
    transfers: &[Transfer],
    arg: u64,
    vector_start: bool,
    budget: Option<usize>,
) -> Result<u64, SpawnError> {
    #[cfg(not(feature = "frame-admission-core"))]
    let _ = budget;
    let table = unsafe { table() };
    // PID 0 is the kernel's single root grant to init. Every userspace child
    // derives its default console authority from console handles the parent
    // actually holds; parentage alone never mints console rights.
    let default_console_rights = if parent == 0 {
        RIGHT_READ | RIGHT_WRITE
    } else {
        table
            .slot_of(parent)
            .map(|index| table.entries[index].handles.console_rights())
            .unwrap_or(0)
    };
    let index = match table.claim_with_max_pid(parent, program, MAX_OWNER_ID as u64) {
        Ok(index) => index,
        Err(ClaimError::Full) => {
            unsafe {
                stats().spawn_refusals += 1;
            }
            return Err(SpawnError::NoSlot);
        }
        Err(ClaimError::PidExhausted) => {
            unsafe {
                stats().spawn_refusals += 1;
            }
            return Err(SpawnError::PidExhausted);
        }
    };
    if crate::smp_app_pressure::bsp_mode() {
        crate::smp_app_pressure::bsp_occupied(
            table
                .entries
                .iter()
                .filter(|p| p.state != ProcessState::Empty)
                .count(),
        );
    }
    let process = &mut table.entries[index];
    let pid = process.pid;
    // Every caller that reaches here holds the spawn right, so the child
    // starts with it; the spawn syscalls clear it when asked.
    process.may_spawn = true;
    let frames = unsafe { vm::frames() };
    #[cfg(feature = "frame-admission-core")]
    if let Some(total) = budget
        && frames.admit(pid as u32, total).is_err()
    {
        table.unclaim(index);
        return Err(SpawnError::NoMemory);
    }
    if let Err(error) = unsafe { load_process(frames, process, image, default_console_rights) } {
        unsafe { release_resources(frames, process) };
        table.unclaim(index);
        return Err(error);
    }
    // The kernel's root grant to init also carries the block device in a
    // durable boot when one was probed; children only ever receive it as a
    // copied handle. Other boot modes keep init's handle table unchanged.
    // A device not selected writable at boot is granted read-only.
    let block_rights =
        if parent == 0 && boot_mode() == BootMode::Durable && crate::block::writable() {
            RIGHT_READ | RIGHT_WRITE
        } else {
            RIGHT_READ
        };
    if parent == 0
        && boot_mode() == BootMode::Durable
        && crate::block::sector_count().is_some()
        && let Ok(handle) = process.handles.insert(Object::Block, block_rights)
    {
        process.task.context.set_argument(1, handle);
    }
    // Likewise the NIC, probed only in a `net` boot, in RCX (init's fourth
    // entry argument). Init hands it to exactly one child at a time.
    if parent == 0
        && matches!(boot_mode(), BootMode::Durable | BootMode::NetProbe)
        && crate::nic_device::present()
        && let Ok(handle) = process
            .handles
            .insert(Object::Nic, RIGHT_READ | RIGHT_WRITE)
    {
        process.task.context.set_argument(3, handle);
    }
    // The machine object, in R8 (init's fifth entry argument), in every
    // boot: the authority to stop, restart, or recover the machine starts
    // at init and reaches another process only as a handle init chose to
    // copy.
    if parent == 0
        && let Ok(handle) = process.handles.insert(Object::Machine, INIT_MACHINE_RIGHTS)
    {
        process.task.context.set_argument(4, handle);
    }
    let console_index = transfers.iter().position(|transfer| transfer.as_console);
    if console_index.is_some() {
        // The transferred console replaces the default one before the
        // atomic batch insert, making its destination slot available.
        let default_console = process.task.context.argument(0);
        let _ = process.handles.close(default_console);
    }
    let mut requested = [(Object::None, 0); MAX_SPAWN_HANDLES];
    for (slot, transfer) in requested.iter_mut().zip(transfers.iter()) {
        *slot = (transfer.object, transfer.rights);
    }
    let mut issued = [0u64; MAX_SPAWN_HANDLES];
    if process
        .handles
        .insert_batch(
            &requested[..transfers.len()],
            &mut issued[..transfers.len()],
        )
        .is_err()
    {
        unsafe { release_resources(frames, process) };
        table.unclaim(index);
        return Err(SpawnError::NoHandles);
    }
    if vector_start && !transfers.is_empty() {
        let byte_count = transfers.len() * core::mem::size_of::<u64>();
        let address = USER_STACK_TOP - byte_count as u64;
        let mut bytes = [0u8; MAX_SPAWN_HANDLES * core::mem::size_of::<u64>()];
        for (index, handle) in issued[..transfers.len()].iter().enumerate() {
            let offset = index * core::mem::size_of::<u64>();
            bytes[offset..offset + core::mem::size_of::<u64>()]
                .copy_from_slice(&handle.to_le_bytes());
        }
        if unsafe { copy_to_user(&process.address_space, address, &bytes[..byte_count]) }.is_err() {
            for &handle in &issued[..transfers.len()] {
                let _ = process.handles.close(handle);
            }
            unsafe { release_resources(frames, process) };
            table.unclaim(index);
            return Err(SpawnError::BadImage);
        }
        // Keep the startup vector above the initial stack pointer so the
        // entry stub's call cannot overwrite it.
        process.task.context.set_stack(address & !0xf);
        process.task.context.set_argument(1, address);
        process.task.context.set_argument(2, transfers.len() as u64);
    } else if vector_start {
        process.task.context.set_argument(1, 0);
        process.task.context.set_argument(2, 0);
    } else {
        process.task.context.set_argument(2, arg);
    }
    for transfer in transfers {
        unsafe { retain_object(transfer.object, transfer.rights) };
    }
    if let Some(console_index) = console_index {
        process.task.context.set_argument(0, issued[console_index]);
    }
    if !vector_start
        && let Some((index, _)) = transfers
            .iter()
            .enumerate()
            .find(|(_, transfer)| !transfer.as_console)
    {
        process.task.context.set_argument(1, issued[index]);
    }
    Ok(pid)
}

/// Publishes a completely built child to the scheduler. Syscall callers do
/// this only after the parent's process handle has been installed.
pub unsafe fn activate_spawn(pid: u64) {
    let table = unsafe { table() };
    let index = table.slot_of(pid).expect("activate unknown spawn");
    let process = &mut table.entries[index];
    if process.state != ProcessState::Created {
        panic!("activate pid {pid} outside Created state");
    }
    crate::smp_user::prepare_process(index, process);
    process.state = ProcessState::Runnable;
    rt_runtime::configure(index, process, process.task.context.argument(2));
    crate::modern_smp::register(
        index,
        process,
        crate::smp_user::initial_placement(index, process),
    );
    crate::smp_app_scale::activated(index, process);
    crate::modern_smp::publish(process);
    crate::modern_smp::mutate_publication(process);
    unsafe { stats().spawns += 1 };
    serial::write("SPAWN OK pid=");
    serial::decimal(pid);
    serial::write(" parent=");
    serial::decimal(process.parent);
    serial::write(" program=");
    serial::write(program_name(process.program));
    serial::write("\n");
    crate::smp_user::notify_runnable();
}

/// The catalog name of a program index, or `image` for a process started
/// from an image in its parent's memory.
pub(crate) fn program_name(program: usize) -> &'static str {
    PROGRAMS.get(program).map_or("image", |entry| entry.name)
}

/// Abandons a fully built but unpublished child. Object references are
/// released one at a time, then all frames and the table claim are returned.
pub unsafe fn abort_spawn(pid: u64) {
    let index = unsafe { table() }
        .slot_of(pid)
        .expect("abort unknown spawn");
    if unsafe { table() }.entries[index].state != ProcessState::Created {
        panic!("abort pid {pid} outside Created state");
    }
    while let Some(handle) = unsafe { table() }.entries[index].handles.take_any() {
        unsafe { release_object(handle.object, handle.rights) };
    }
    let table = unsafe { table() };
    let frames = unsafe { vm::frames() };
    unsafe { release_resources(frames, &mut table.entries[index]) };
    table.unclaim(index);
}

/// Fills a `Created` entry: address space, image, stacks, and initial
/// context. On error the entry keeps whatever it allocated so the caller can
/// release it.
unsafe fn load_process<S: ImageSource + ?Sized>(
    frames: &mut FrameAllocator,
    process: &mut Process,
    bytes: &S,
    console_rights: u8,
) -> Result<(), SpawnError> {
    let owner = process.pid as u32;
    let image = elf::parse_source(bytes).map_err(|_| SpawnError::BadImage)?;
    process.address_space =
        unsafe { vm::create(frames, owner, KERNEL_PDPT) }.ok_or(SpawnError::NoMemory)?;
    unsafe { populate(frames, process, &image, bytes)? };
    // When present, slot 0 is the default console and its opaque value reaches
    // the program in RDI. A process with no inherited console receives zero.
    process.task.context.set_argument(
        0,
        if console_rights == 0 {
            0
        } else {
            process
                .handles
                .insert(Object::Console, console_rights)
                .map_err(|_| SpawnError::BadImage)?
        },
    );
    Ok(())
}

unsafe fn populate<S: ImageSource + ?Sized>(
    frames: &mut FrameAllocator,
    process: &mut Process,
    image: &elf::Image,
    bytes: &S,
) -> Result<(), SpawnError> {
    let owner = process.pid as u32;
    for segment in &image.segments[..image.segment_count] {
        let end = segment
            .virtual_address
            .checked_add(segment.memory_size as u64)
            .ok_or(SpawnError::BadImage)?;
        if segment.virtual_address < USER_IMAGE_MIN || end > USER_IMAGE_MAX {
            return Err(SpawnError::BadImage);
        }
        let start = segment.virtual_address & !(PAGE_SIZE - 1);
        let end = (end + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let mut page = start;
        while page < end {
            let writable = segment.flags & PF_WRITE != 0;
            let executable = segment.flags & PF_EXECUTE != 0;
            let mapped = unsafe {
                vm::map_user_page(
                    frames,
                    &mut process.address_space,
                    owner,
                    page,
                    writable,
                    executable,
                )
            };
            match mapped {
                Ok(_) => {}
                Err(vm::MapError::NoMemory) => return Err(SpawnError::NoMemory),
                // Overlapping or misplaced segments are the image's fault.
                Err(_) => return Err(SpawnError::BadImage),
            }
            page += PAGE_SIZE;
        }
        // One translation per destination page; the source copies straight
        // into the child's frame through the identity map.
        let mut offset = 0usize;
        while offset < segment.file_size {
            let address = segment.virtual_address + offset as u64;
            let physical = unsafe { vm::translate(&process.address_space, address) }
                .ok_or(SpawnError::BadImage)?;
            let page_left = (PAGE_SIZE - (address & (PAGE_SIZE - 1))) as usize;
            let take = page_left.min(segment.file_size - offset);
            let destination = unsafe { core::slice::from_raw_parts_mut(physical as *mut u8, take) };
            bytes
                .read(segment.offset + offset, destination)
                .map_err(|_| SpawnError::BadImage)?;
            offset += take;
        }
    }
    let user_stack_bottom = USER_STACK_TOP - USER_STACK_PAGES as u64 * PAGE_SIZE;
    for page in 0..USER_STACK_PAGES {
        let mapped = unsafe {
            vm::map_user_page(
                frames,
                &mut process.address_space,
                owner,
                user_stack_bottom + page as u64 * PAGE_SIZE,
                true,
                false,
            )
        };
        if mapped.is_err() {
            return Err(SpawnError::NoMemory);
        }
    }
    let kernel_stack = frames
        .allocate_contiguous(KERNEL_STACK_PAGES, FrameOwner::KernelStack(owner))
        .ok_or(SpawnError::NoMemory)?;
    for page in 0..KERNEL_STACK_PAGES {
        unsafe {
            vm::fill_frame(
                Frame(kernel_stack.start_address() + page as u64 * PAGE_SIZE),
                KERNEL_STACK_CANARY,
            );
        }
    }
    let task = &mut process.task;
    task.tid = process.pid;
    task.fpu = FpuState::INITIAL;
    crate::arch_runtime::fresh_fpu(task);
    task.kernel_stack_base = kernel_stack.start_address();
    task.kernel_stack_top = kernel_stack.start_address() + KERNEL_STACK_BYTES;
    task.user_stack_top = USER_STACK_TOP;
    task.user_stack_bottom = user_stack_bottom;
    task.context = crate::arch_runtime::initial_context(image.entry, USER_STACK_TOP);
    task.context_valid = true;
    crate::arch_runtime::sync_executable(&process.address_space, image);
    Ok(())
}

/// Returns every frame a process owns: its address space and kernel stack.
/// Must not run while that process's CR3 or kernel stack is active.
unsafe fn release_resources(frames: &mut FrameAllocator, process: &mut Process) {
    #[cfg(feature = "frame-admission-v0")]
    {
        process.may_admit_frames = false;
        unsafe { crate::syscalls::retire_frame_bootstrap(process.pid) };
    }

    assert!(
        process.cpu_owner.is_none(),
        "reclaim while CPU owns address space"
    );
    assert!(
        !matches!(
            process.stop,
            absd_kernel::process::StopState::Requested | absd_kernel::process::StopState::Observed
        ),
        "reclaim before stop departure"
    );
    crate::smp_app_pressure::check_terminal_frames(process, frames);
    crate::smp_user::restore_fixture_page(process);
    rt_runtime::remove(process);
    let owner = process.pid as u32;
    if let Err(error) = unsafe { vm::destroy(frames, &mut process.address_space, owner) } {
        panic!(
            "address-space teardown for pid {} failed: {error:?}",
            process.pid
        );
    }
    if process.task.kernel_stack_base != 0 {
        let used = unsafe { kernel_stack_used(process.task.kernel_stack_base) };
        let stats = unsafe { stats() };
        stats.kernel_stack_peak = stats.kernel_stack_peak.max(used);
        for page in 0..KERNEL_STACK_PAGES {
            let frame = Frame(process.task.kernel_stack_base + page as u64 * PAGE_SIZE);
            if let Err(error) = frames.free(frame, FrameOwner::KernelStack(owner)) {
                panic!(
                    "kernel-stack release for pid {} failed: {error:?}",
                    process.pid
                );
            }
        }
        process.task.kernel_stack_base = 0;
        process.task.kernel_stack_top = 0;
    }
    #[cfg(feature = "frame-admission-core")]
    frames
        .retire_reservation(owner)
        .expect("reservation retired before frames returned");
    let remaining = frames.frames_owned_by(owner);
    if remaining != 0 {
        panic!(
            "pid {} still owns {remaining} frames after release",
            process.pid
        );
    }
}

/// Bytes of a kernel stack that were ever written, judged by the lowest
/// address whose canary is gone. The stack is not in use when this runs.
unsafe fn kernel_stack_used(base: u64) -> u64 {
    let bytes = base as *const u8;
    for offset in 0..KERNEL_STACK_BYTES {
        if unsafe { core::ptr::read_volatile(bytes.add(offset as usize)) } != KERNEL_STACK_CANARY {
            return KERNEL_STACK_BYTES - offset;
        }
    }
    0
}

/// Runs the first runnable process. Never returns.
pub unsafe fn start() -> ! {
    unsafe {
        prepare_runnable();
        let Some(index) = next_runnable(MAX_PROCESSES - 1) else {
            finish_process_suite();
        };
        resume_process(index, 0)
    }
}

unsafe fn resume_process(index: usize, previous_pid: u64) -> ! {
    // Every ordinary and RT user return passes this entry.  The controlled
    // AP has its own CPL0-only descriptor set and may never touch BSP state.
    if !cpu::is_bootstrap_processor() && !crate::smp_user::enabled() {
        cpu::refuse_application_processor();
    }
    unsafe {
        if crate::smp_user::enabled() {
            crate::smp_user::assert_selection(index);
        }
        let table = table();
        cpu::set_current(index);
        let claim = table.entries[index].claim_cpu(cpu::id());
        crate::modern_smp::claimed(index, claim, &table.entries[index]);
        crate::smp_bench::dispatch();
        crate::smp_timer::reset_quantum();
        rt_runtime::dispatch(&mut table.entries[index], previous_pid);
        let process = &table.entries[index];
        // Negative control: resume with the outgoing CPU scratch image.
        #[cfg(not(absd_mutant_skip_fpu_restore))]
        if !crate::smp_fpu::skip_restore(process) {
            core::ptr::write_volatile(cpu::user_fpu(), process.task.fpu);
        }
        crate::smp_fpu::restore_negative(process);
        crate::smp_nway::restore_negative(index, process);
        crate::smp_timer::restore_negative();
        crate::set_kernel_stack(process.task.kernel_stack_top);
        resume_user_context(
            process.task.context.as_ptr(),
            process.address_space.root,
            process.task.kernel_stack_top,
        )
    }
}

/// A controlled AP command invokes the actual ordinary/RT user-return
/// boundary with an invalid slot. The CPU identity guard must refuse before
/// any table access; this does not enter ring 3.
pub fn ap_resume_guard_negative() -> ! {
    assert!(!cpu::is_bootstrap_processor());
    unsafe { resume_process(usize::MAX, 0) }
}

/// Captures the interrupted register frame and the FXSAVE image the entry
/// stub stored before any Rust code could touch XMM state.
/// Save the task-owned trap frame, but keep the task non-runnable while this
/// CPU still uses its stack, CR3 and TSS.rsp0. Assembly then abandons every
/// task-stack call frame and enters `commit_cpu_switch` on CPU-owned storage.
pub(crate) unsafe fn switch_from_frame(frame: *mut u64, preempted: bool) -> ! {
    unsafe {
        let table = table();
        let current = cpu::current();
        save_frame(&mut table.entries[current], frame);
        crate::smp_fpu::saved(current, &table.entries[current], preempted);
        crate::smp_nway::saved(current, &table.entries[current], preempted);
        crate::smp_app_pressure::saved(current, &table.entries[current], preempted);
        crate::smp_app_scale::saved(current, &table.entries[current], preempted);
        crate::smp_user::blocked_frame(&table.entries[current]);
        rt_runtime::outgoing(&mut table.entries[current], preempted);
        if preempted
            && cpu::id() == 0
            && table.entries[current].class.rt().is_none()
            && table.entries[current].program == absd_kernel::program::RT_PROBE as usize
        {
            for process in &mut table.entries {
                if process.is_live()
                    && let Some(rt) = process.class.rt_mut()
                {
                    rt.normal_ticks += 1;
                }
            }
        }
        crate::smp_user::block_gap();
        cpu::set_pending_preempt(preempted);
        if take_handoff_negative() {
            assert_departed(current);
        }
        enter_cpu_switch()
    }
}

/// This runs only after assembly has left the outgoing task's stack, CR3 and
/// TSS.rsp0. No outgoing trap-frame pointer crosses the handoff boundary.
#[unsafe(no_mangle)]
pub extern "C" fn commit_cpu_switch() -> ! {
    crate::debug_assert_interrupts_disabled();
    unsafe {
        let current = cpu::current();
        assert_departed(current);
        let claim = table().entries[current]
            .cpu_owner
            .expect("switch without CPU owner");
        assert_eq!(claim.cpu, cpu::id());
        crate::smp_user::departure(current, claim);
        table().entries[current].depart_cpu(claim);
        crate::modern_smp::departed(current, claim);
        cpu::set_current(cpu::NO_TASK);
        let preempted = cpu::take_pending_preempt();
        if preempted {
            crate::smp_bench::preempt();
        }
        let previous_pid = table().entries[current].pid;
        if table().entries[current].stop == absd_kernel::process::StopState::Departed {
            finish_departed_stop(current, claim);
        }
        let table = table();
        if table.entries[current].state == ProcessState::Running {
            table.entries[current].state = ProcessState::Runnable;
        }
        crate::modern_smp::publish(&table.entries[current]);
        prepare_runnable();
        let Some(next) = next_runnable(current) else {
            idle_loop();
        };
        if preempted && next != current {
            crate::smp_timer::switched(previous_pid, table.entries[next].pid);
            stats().preempts += 1;
            let fpu = absd_kernel::program::FPU_MXCSR as usize;
            if table.entries[current].program == fpu && table.entries[next].program == fpu {
                stats().fpu_peer_preempts += 1;
            }
            if stats().preempts <= 8 {
                serial::write("USER PREEMPT pid=");
                serial::decimal(previous_pid);
                serial::write(" -> pid=");
                serial::decimal(table.entries[next].pid);
                serial::write("\n");
            }
        }
        resume_process(next, previous_pid)
    }
}

/// Check hardware ownership at the publication/reclamation boundary, rather
/// than trusting a scheduler flag. The entry and transition stacks are both
/// CPU-owned and mapped by the boot root.
/// All selection paths resolve phase releases before ordinary hardware/time wakes.
unsafe fn prepare_runnable() {
    unsafe {
        drain_ap_departures();
        wake_sleepers();
        // IRQ/device rings remain BSP-owned, including their waiter scans.
        // The AP can prepare ordinary object/time waits under serialization,
        // but must never read BSP interrupt input or enter a NIC controller.
        if cpu::is_bootstrap_processor() {
            #[cfg(target_arch = "x86_64")]
            crate::xhci::keyboard_progress();
            wake_console_readers();
            wake_nic_receivers();
        }
        for entry in &table().entries {
            rt_runtime::assert_bridge(entry);
        }
    }
}

/// An AP IPI handler never mutates the process table. Its Release ACK is
/// consumed here under BKL, after the AP's assembly has left victim RSP,
/// CR3, TSS.rsp0 and callback frames. Exact token comparison prevents a
/// reused slot or a prior claim from authorizing reclamation.
unsafe fn drain_ap_departures() {
    if cpu::id() > 0 {
        return;
    }
    crate::kernel_lock::assert_held(crate::kernel_lock::BSP);
    while let Some(token) = crate::ap::poll_departed() {
        assert!(token.slot < MAX_PROCESSES);
        {
            let process = &mut unsafe { table() }.entries[token.slot];
            assert_eq!(process.pid, token.pid, "stale AP departure PID");
            assert_eq!(process.cpu_owner, Some(token.claim), "stale AP claim epoch");
            assert_eq!(process.state, ProcessState::Running);
            assert!(matches!(
                process.stop,
                absd_kernel::process::StopState::Requested
                    | absd_kernel::process::StopState::Observed
            ));
            process.depart_cpu(token.claim);
        }
        crate::modern_smp::departed(token.slot, token.claim);
        unsafe { finish_departed_stop(token.slot, token.claim) };
        if boot_mode() == BootMode::SmpLifecycle {
            crate::smp_fixture::on_drain(token);
        }
        crate::ap::complete_drain(token);
    }
}

/// Current tick of the ~1 kHz boot timer.
pub fn now() -> u64 {
    crate::timer_ticks.load(core::sync::atomic::Ordering::Relaxed)
}

/// Absolute wake tick for a relative timeout; zero means no deadline.
/// The wake tick is one past `now + timeout` so that at least `timeout`
/// full ticks elapse. A timeout too large to ever arrive is no deadline at
/// all, so the idle loop does not wait on it forever.
pub(crate) fn deadline(timeout: u64) -> Option<u64> {
    if timeout == 0 {
        return None;
    }
    now()
        .checked_add(timeout)
        .and_then(|tick| tick.checked_add(1))
}

/// Wakes every `Waiting` process whose deadline has passed: a sleep ends
/// with 0, any other wait is cut short with `-110`.
unsafe fn wake_sleepers() {
    let tick = now();
    let table = unsafe { table() };
    // Release all tasks first; only then resolve coincident ordinary wakes.
    if cpu::is_bootstrap_processor() {
        for entry in table.entries.iter_mut() {
            rt_runtime::release_due(entry, tick);
        }
    }
    for entry in table.entries.iter_mut() {
        if rt_runtime::pending_pid(entry.pid) {
            continue;
        }
        // CPU0 owns every RT phase/budget transition. An AP scan must not
        // roll the phase while CPU0 still executes the outgoing RT task.
        if !cpu::is_bootstrap_processor() && entry.class.rt().is_some() {
            continue;
        }
        if !entry.can_wake() {
            continue;
        }
        let Some(wake_at) = entry.wake_at else {
            continue;
        };
        if wake_at > tick {
            continue;
        }
        if entry.wait_kind == WaitKind::StopFence {
            panic!("remote stop did not reach departure ACK before PIT deadline");
        }
        let rt_release = entry.wait_kind == WaitKind::RtRelease;
        let result = if entry.wait_kind == WaitKind::Sleep || rt_release {
            0
        } else {
            unsafe {
                stats().timeouts += 1;
            }
            ERROR_TIMEOUT
        };
        entry.clear_wait();
        if !rt_release {
            entry.task.context.set_result((result as u64) as i64);
        }
        make_runnable(entry);
    }
}

/// Nothing is runnable. Halt until the timer wakes a sleeper or a timed
/// wait expires; if nothing can ever wake, the boot is over.
#[unsafe(no_mangle)]
pub extern "C" fn idle_loop() -> ! {
    unsafe {
        stats().idle_entries += 1;
        loop {
            prepare_runnable();
            crate::smp_user::notify_runnable();
            let table = table();
            if let Some(next) = next_runnable(MAX_PROCESSES - 1) {
                resume_process(next, 0);
            }
            // Hardware deadlines/console input can wake tasks. RT phases
            // still advance while an ordinary RT blocking condition is pending.
            if crate::smp_user::enabled()
                && (cpu::id() > 0 || table.entries.iter().any(|p| p.is_live()))
            {
                if cpu::id() == 0 && boot_mode() == BootMode::RtClass {
                    rt_runtime::idle();
                }
                crate::smp_user::idle_wait();
                continue;
            }
            if !table.entries.iter().any(|entry| {
                entry.state == ProcessState::Waiting
                    && (entry.wake_at.is_some()
                        || matches!(entry.wait_kind, WaitKind::Console | WaitKind::StopFence)
                        || entry.class.rt().is_some())
            }) {
                #[cfg(target_arch = "x86_64")]
                if crate::xhci::keyboard_stop_before_finish() {
                    crate::kernel_lock::idle_wait();
                    continue;
                }
                finish_process_suite();
            }
            if boot_mode() == BootMode::RtClass {
                rt_runtime::idle();
            }
            crate::kernel_lock::idle_wait();
        }
    }
}

/// Copies a terminal child's outcome to its parent, closes the parent's
/// handles to it, releases the slot, and returns its positive PID. Copy
/// failure remains an error even though the terminal child is still reaped.
pub(crate) unsafe fn deliver_outcome(child: usize, parent: usize, record: u64) -> i64 {
    let table = unsafe { table() };
    let Some(outcome) = table.entries[child].outcome() else {
        return ERROR_NO_CHILD;
    };
    let child_pid = table.entries[child].pid;
    let parent_space = table.entries[parent].address_space;
    let result = if unsafe { copy_to_user(&parent_space, record, &outcome.to_bytes()) }.is_ok() {
        child_pid as i64
    } else {
        ERROR_FAULT
    };
    table.entries[parent].handles.close_process(child_pid);
    table.release(child);
    unsafe {
        stats().reaps += 1;
    }
    result
}

/// Terminal disposition for the current process. Runs on the kernel entry
/// stack with the boot page tables active. Never returns.
#[unsafe(no_mangle)]
pub extern "C" fn reap_current_and_schedule() -> ! {
    unsafe {
        let current = cpu::current();
        assert_departed(current);
        let claim = table().entries[current]
            .cpu_owner
            .expect("reap without CPU owner");
        assert_eq!(claim.cpu, cpu::id());
        crate::smp_user::departure(current, claim);
        table().entries[current].depart_cpu(claim);
        crate::modern_smp::departed(current, claim);
        cpu::set_current(cpu::NO_TASK);
        if table().entries[current].stop == absd_kernel::process::StopState::Departed {
            finish_departed_stop(current, claim);
        } else {
            terminate(current);
        }
        prepare_runnable();
        let Some(next) = next_runnable(current) else {
            idle_loop();
        };
        resume_process(next, 0)
    }
}

/// Only after the owner's departure may a requested stop publish a terminal
/// result and wake its caller. The caller carries the PID in its continuation,
/// so a released/reused victim slot is never used to resolve the fence.
unsafe fn finish_departed_stop(index: usize, claim: absd_kernel::process::CpuClaim) {
    let (pid, parent) = {
        let process = &mut unsafe { table() }.entries[index];
        assert!(process.cpu_owner.is_none());
        assert_eq!(process.stop, absd_kernel::process::StopState::Departed);
        let identity = (process.pid, process.parent);
        process.clear_wait();
        process.state = ProcessState::Killed;
        identity
    };
    unsafe { stats().kills += 1 };
    unsafe { terminate(index) };
    crate::smp_user::reclaimed(index, pid, claim);
    if boot_mode() == BootMode::SmpCreatedStop && claim.cpu == crate::kernel_lock::BSP {
        crate::smp_fixture::on_bsp_spawner_departed(crate::ap::StopToken {
            slot: index,
            pid,
            claim,
        });
    }
    if let Some(parent_index) = unsafe { table() }.slot_of(parent) {
        let waiter = &mut unsafe { table() }.entries[parent_index];
        if waiter.state == ProcessState::Waiting
            && waiter.wait_kind == WaitKind::StopFence
            && waiter.wait_target == pid
            && waiter.stop == absd_kernel::process::StopState::Active
        {
            waiter.clear_wait();
            waiter.task.context.set_result(0);
            make_runnable(waiter);
        }
    }
}

/// Finishes a process that is already marked terminal and is not running:
/// returns its frames and object references, disposes of its children,
/// and either hands its outcome to a waiting parent, keeps the record for
/// a later `wait`, or drops it when the kernel is the parent.
pub(crate) unsafe fn terminate(current: usize) {
    unsafe {
        let table = table();
        let frames = vm::frames();
        assert!(
            table.entries[current].cpu_owner.is_none(),
            "terminate while CPU-owned"
        );
        assert!(
            !matches!(
                table.entries[current].stop,
                absd_kernel::process::StopState::Requested
                    | absd_kernel::process::StopState::Observed
            ),
            "terminate before stop departure"
        );
        let pid = table.entries[current].pid;
        let parent = table.entries[current].parent;
        if !table.entries[current].is_terminal() {
            panic!("reap requested for live pid {pid}");
        }
        crate::smp_app_pressure::bsp_before_remove(current, &table.entries[current]);
        crate::smp_app_scale::before_remove(current, &table.entries[current]);
        crate::modern_smp::remove(current);
        release_resources(frames, &mut table.entries[current]);
        // One handle at a time: releasing a pipe handle may wake other
        // processes through the table, so no borrow is held across it.
        while let Some(handle) = self::table().entries[current].handles.take_any() {
            release_object(handle.object, handle.rights);
        }
        crate::smp_app_pressure::bsp_after_release(current, &table.entries[current]);
        crate::smp_app_scale::reclaimed(&table.entries[current]);

        // A live userspace init adopts orphans, including terminal children
        // that still need an outcome collected. If init is absent,
        // terminal, or itself exiting, preserve the kernel fallback.
        if table.reparent_children_to_live_init(pid).is_none() {
            for index in 0..MAX_PROCESSES {
                let child = &mut table.entries[index];
                if child.state == ProcessState::Empty || child.parent != pid {
                    continue;
                }
                if child.is_terminal() {
                    table.release(index);
                    stats().reaps += 1;
                } else {
                    child.parent = KERNEL_PARENT;
                }
            }
        }

        if parent == KERNEL_PARENT {
            if pid == 1 {
                stats().init_status = table.entries[current].exit_status.into();
                if table.entries[current].state != ProcessState::Exited {
                    stats().init_status = Some(-1);
                }
            }
            table.release(current);
            stats().reaps += 1;
        } else if let Some(waiter) = table.slot_of(parent) {
            let parent_entry = &table.entries[waiter];
            let awaited = parent_entry.is_waiting_for_child()
                && (parent_entry.wait_target == 0 || parent_entry.wait_target == pid);
            let record = parent_entry.wait_record;
            if awaited {
                let result = deliver_outcome(current, waiter, record);
                let parent_entry = &mut self::table().entries[waiter];
                parent_entry.clear_wait();
                parent_entry.task.context.set_result((result as u64) as i64);
                make_runnable(parent_entry);
            }
            // Otherwise the terminal record waits for the parent's `wait`.
        } else {
            table.release(current);
            stats().reaps += 1;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn user_timer_schedule(frame: *mut u64) -> ! {
    crate::smp_measure::tag(crate::smp_measure::TIMER);
    crate::debug_assert_interrupts_disabled();
    unsafe { switch_from_frame(frame, true) }
}
pub(crate) fn ap_timer_rt_negative() {
    // Test-only deterministic attempt to violate BSP-owned RT progression.
    assert!(crate::smp_timer::enabled() && crate::cpu::id() > 0);
    let mut process = absd_kernel::process::Process::EMPTY;
    rt_runtime::release_due(&mut process, now());
}

/// Attempts the single permitted demand action: mapping the page directly
/// below a running process's user stack. Called from the page-fault entry
/// while the process CR3 and kernel stack are still active. Returning one
/// resumes the exact faulting frame; zero takes normal fault isolation.
#[unsafe(no_mangle)]
pub extern "C" fn user_stack_page_fault(
    frame_base: u64,
    address: u64,
    error: u64,
    user_rsp: u64,
) -> u64 {
    crate::smp_measure::tag(crate::smp_measure::FAULT);
    unsafe {
        let table = table();
        let current = cpu::current();
        let process = &mut table.entries[current];
        if process.state != ProcessState::Running
            || !crate::arch_runtime::owns_fault_frame(frame_base, process)
        {
            return 0;
        }
        let Some(page) =
            stack_growth_page(error, address, user_rsp, process.task.user_stack_bottom)
        else {
            return 0;
        };
        let owner = process.pid as u32;
        if vm::map_user_page(
            vm::frames(),
            &mut process.address_space,
            owner,
            page,
            true,
            false,
        )
        .is_err()
        {
            return 0;
        }
        process.task.user_stack_bottom = page;
        stats().stack_grows += 1;
        crate::invalidate_page(page);
        1
    }
}

/// The resumable page-fault path reaches this final serialized boundary
/// before restoring user state. A stop committed while a prior bounded
/// continuation yielded must leave on the terminal CPU-owned reaper path.
#[unsafe(no_mangle)]
pub extern "C" fn bsp_pagefault_stop_guard() {
    crate::kernel_lock::assert_held(cpu::id());
    unsafe {
        let current = cpu::current();
        let process = &mut table().entries[current];
        if process.stop != absd_kernel::process::StopState::Active {
            process.state = ProcessState::Killed;
            enter_kernel_context_and_reap();
        }
    }
}

/// Any ring-3 CPU exception. Entered on the kernel entry stack with the boot
/// CR3 loaded, so the faulting process's resources can be released at once.
#[unsafe(no_mangle)]
pub extern "C" fn user_exception(vector: u64, error: u64, rip: u64) -> ! {
    crate::smp_measure::tag(crate::smp_measure::FAULT);
    crate::debug_assert_interrupts_disabled();
    let address = crate::arch_runtime::fault_address(vector, rip);
    let fault = absd_kernel::arch::normalize_user_exception(vector, error, address);
    let disposition = absd_kernel::process::user_fault_disposition(fault)
        .expect("non-user metadata at userspace fault boundary");
    unsafe {
        let table = table();
        let current = cpu::current();
        let process = &mut table.entries[current];
        process.state = disposition;
        process.fault_vector = vector;
        process.fault_address = address;
        process.fault_error = error;
        stats().faults += 1;
        serial::write("FAULT1 pid=");
        serial::decimal(process.pid);
        serial::write(" kind=");
        serial::write(fault.class.label());
        serial::write(" access=");
        serial::write(fault.access.map_or("none", |access| access.label()));
        serial::write(" user=1 address=");
        serial::hex(fault.address);
        serial::write("\n");
        serial::write("USER FAULT pid=");
        serial::decimal(process.pid);
        serial::write(" vector=");
        serial::decimal(vector);
        serial::write(" address=");
        serial::hex(address);
        serial::write(" error=");
        serial::hex(error);
        serial::write("\n");
        reap_current_and_schedule()
    }
}
