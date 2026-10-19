//! The `int 0x80` handlers: dispatch, handle and object operations, memory,
//! pipes, console I/O, cells, and waits. Every handler runs on the calling
//! process's kernel stack with interrupts disabled and either returns a
//! result for `RAX` or blocks the process with the state needed to finish
//! the operation later.

use crate::block;
use crate::sched::{
    Transfer, UserImage, abort_spawn, activate_spawn, cells, deadline, deliver_outcome,
    enter_kernel_context_and_reap, now, pipes, spawn_image, spawn_many_copy, spawn_with, stats,
    switch_from_frame, table, terminate,
};
use crate::serial;
use crate::vm;
use absd_kernel::arch::ExecutionState;
use absd_kernel::handle::{
    ALL_RIGHTS, HandleError, Object, RIGHT_KILL, RIGHT_READ, RIGHT_WAIT, RIGHT_WRITE,
};
use absd_kernel::layout::{USER_HEAP_BASE, USER_HEAP_END};
use absd_kernel::memory::PAGE_SIZE;
use absd_kernel::object::{CellError, CellId, PipeId, PipeStatus};
use absd_kernel::process::{MAX_PROCESSES, ProcessState, TransferWait, WaitKind};
use absd_kernel::syscall::{
    BLOCK_INFO_BYTES, BLOCK_MAX_TRANSFER_SECTORS, BLOCK_SECTOR_BYTES, BLOCK_TRANSFER_BYTES,
    BOOT_ID_BYTES, BlockTransfer, ERROR_IO, MACHINE_RIGHT_RECOVER, MACHINE_RIGHT_RESTART,
    MACHINE_RIGHT_STOP, RESOURCE_CENSUS_BYTES, ResourceCensus, STOP_CODE_MAX, STOP_CODE_MIN,
    SYS_ABI_VERSION, SYS_BLOCK_FLUSH, SYS_BLOCK_INFO, SYS_BLOCK_READ, SYS_BLOCK_READ_MANY,
    SYS_BLOCK_WRITE, SYS_BLOCK_WRITE_MANY, SYS_BOOT_ID, SYS_MACHINE_RECOVER, SYS_MACHINE_RESTART,
    SYS_MACHINE_STOP, SYS_RESOURCE_CENSUS, SYS_WALL_CLOCK,
};
use absd_kernel::syscall::{
    CELL_RECORD_BYTES, ERROR_BAD_HANDLE, ERROR_FAULT, ERROR_INVALID, ERROR_NO_CHILD,
    ERROR_NO_MEMORY, ERROR_NOT_IMPLEMENTED, ERROR_PIPE, ERROR_RIGHTS, ERROR_STALE,
    ERROR_TOO_MANY_HANDLES, MAX_MAP_PAGES, MAX_TRANSFER, OUTCOME_BYTES, SYS_CELL_CREATE,
    SYS_CELL_READ, SYS_CELL_TRANSITION, SYS_CELL_WAIT, SYS_CLOSE, SYS_DUPLICATE, SYS_EXIT,
    SYS_GETPID, SYS_MAP, SYS_PIPE_CREATE, SYS_READ, SYS_SLEEP, SYS_SPAWN, SYS_TIME, SYS_UNMAP,
    SYS_WAIT, SYS_WRITE, SYS_YIELD,
};
use absd_kernel::syscall::{
    ERROR_NOT_EXECUTABLE, MAX_SPAWN_IMAGE_BYTES, PIPE_INFO_BYTES, PipeInfo,
    SPAWN_IMAGE_REQUEST_BYTES, SYS_PIPE_INFO, SYS_SPAWN_IMAGE, SpawnImageRequest,
};
use absd_kernel::syscall::{FRAME_LIMIT_NONE, FRAME_STATS_BYTES, FrameStats, SYS_FRAME_STATS};
use absd_kernel::syscall::{
    INFO_BYTES, INFO_STATE_LIVE, INFO_STATE_TERMINAL, INFO_STATE_WAITING, MAX_SPAWN_HANDLES,
    ProcessInfo, SPAWN_CONSOLE, SPAWN_HANDLE_COPY_BYTES, SPAWN_HANDLE_COPY_CONSOLE, SPAWN_NO_SPAWN,
    SPAWN_PROGRAM_MASK, SYS_INFO, SYS_KILL, SYS_SPAWN_MANY_COPY, SYS_TRANSFER, SpawnHandleCopy,
    TRANSFER_BYTES, TRANSFER_READ, TRANSFER_WRITE,
};
use absd_kernel::user_memory::{check_user_range, copy_from_user, copy_to_user};

const MAX_USER_WRITE: usize = 256;
/// Qualification-time stop observation deadline in BSP PIT ticks. Expiry
/// fails closed; it never presents an unfenced termination as completed.
const STOP_OBSERVE_TICKS: u64 = 1_000;

#[path = "syscalls/nic.rs"]
mod nic;
#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64/syscall_platform.rs"]
mod platform;
#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64/syscall_platform.rs"]
mod platform;
pub(crate) use nic::wake_nic_receivers;

#[unsafe(no_mangle)]
pub extern "C" fn user_syscall_dispatch(frame: *mut u64) -> u64 {
    crate::debug_assert_interrupts_disabled();
    unsafe {
        let number = crate::arch_runtime::syscall_number(frame);
        crate::smp_measure::syscall(number);
        // Take what the arms need up front so no table borrow is held across
        // the calls below, each of which re-derives its own.
        let (current, pid, root, program) = {
            let table = table();
            let current = crate::cpu::current();
            let process = &table.entries[current];
            (
                current,
                process.pid,
                process.address_space.root,
                process.program,
            )
        };
        if table().entries[current].stop != absd_kernel::process::StopState::Active {
            switch_from_frame(frame, false);
        }
        crate::smp_user::syscall_entry(frame, number);
        crate::smp_app_pressure::refusal_entry(pid, program, number);
        let [arg0, arg1, arg2] = crate::arch_runtime::frame_arguments(frame);
        #[cfg(feature = "frame-admission-v0")]
        let supported = absd_kernel::frame_admission::dispatch(
            number,
            || supported_admit_self(current, arg0, arg1, arg2),
            || supported_spawn_reserved(current, arg0, arg1, arg2),
        );
        #[cfg(not(feature = "frame-admission-v0"))]
        let supported: Option<i64> = None;
        let result = if let Some(result) = supported {
            result
        } else {
            match number {
                0x7fff => crate::smp_user::test_call(arg0, arg1, arg2),
                #[cfg(feature = "frame-reservation-experiment")]
                0x7ff0 => {
                    if arg1 != 0 || arg2 != 0 {
                        ERROR_INVALID
                    } else {
                        match vm::frames().admit(pid as u32, arg0 as usize) {
                            Ok(()) => 0,
                            Err(
                                absd_kernel::memory::AdmissionError::NoCapacity
                                | absd_kernel::memory::AdmissionError::NoRecord,
                            ) => ERROR_NO_MEMORY,
                            Err(_) => ERROR_INVALID,
                        }
                    }
                }
                #[cfg(feature = "frame-reservation-experiment")]
                0x7ff1 => experimental_spawn(current, arg0, arg1, arg2),
                #[cfg(feature = "frame-reservation-experiment")]
                0x7ff2 => {
                    if arg1 != 0 || arg2 != 0 {
                        ERROR_INVALID
                    } else {
                        let frames = vm::frames();
                        match arg0 {
                            0 => frames.frames_owned_by(pid as u32) as i64,
                            1 => frames.idle_reserved_frames() as i64,
                            2 => frames.reservation(pid as u32).map_or(0, |r| r.0 as i64),
                            3 => {
                                1 | if cfg!(feature = "frame-admission-qualification") {
                                    2
                                } else {
                                    0
                                }
                            }
                            _ => ERROR_INVALID,
                        }
                    }
                }

                #[cfg(feature = "frame-reservation-experiment")]
                0x7ff3 => {
                    syscall_spawn_image_inner(current, arg0, arg1, 0, Some(arg2 as usize), false)
                }
                #[cfg(feature = "frame-admission-qualification")]
                0x7ff4 => {
                    syscall_spawn_image_inner(current, arg0, arg1, 0, Some(arg2 as usize), true)
                }
                SYS_WRITE => match syscall_write(current, arg0, arg1, arg2, 0) {
                    WaitOutcome::Done(result) => result,
                    WaitOutcome::Blocked => {
                        crate::arch_runtime::set_frame_result(frame, 0);
                        switch_from_frame(frame, false);
                    }
                },
                SYS_YIELD => {
                    crate::arch_runtime::set_frame_result(frame, 0);
                    switch_from_frame(frame, false);
                }
                SYS_EXIT => {
                    let process = &mut table().entries[current];
                    process.exit_status = arg0 as i32;
                    process.state = ProcessState::Exited;
                    stats().exits += 1;
                    serial::write("USER EXIT pid=");
                    serial::decimal(pid);
                    serial::write(" status=");
                    serial::signed(arg0 as i32);
                    serial::write("\n");
                    enter_kernel_context_and_reap()
                }
                SYS_GETPID => pid as i64,
                SYS_SPAWN => syscall_spawn(current, arg0, arg1, arg2),
                SYS_SPAWN_MANY_COPY => syscall_spawn_many_copy(current, arg0, arg1, arg2),
                SYS_SPAWN_IMAGE => syscall_spawn_image(current, arg0, arg1, arg2),
                SYS_MAP => syscall_map(current, arg0),
                SYS_UNMAP => syscall_unmap(current, arg0, arg1),
                SYS_CLOSE => syscall_close(current, arg0),
                SYS_DUPLICATE => syscall_duplicate(current, arg0, arg1),
                SYS_PIPE_CREATE => syscall_pipe_create(current),
                SYS_PIPE_INFO => syscall_pipe_info(current, arg0, arg1),
                SYS_CELL_CREATE => syscall_cell_create(current, arg0),
                SYS_READ => match syscall_read(current, arg0, arg1, arg2, 0) {
                    WaitOutcome::Done(result) => result,
                    WaitOutcome::Blocked => {
                        crate::arch_runtime::set_frame_result(frame, 0);
                        switch_from_frame(frame, false);
                    }
                },
                SYS_CELL_READ => syscall_cell_read(current, arg0, arg1),
                SYS_CELL_TRANSITION => syscall_cell_transition(current, arg0, arg1, arg2),
                SYS_WAIT => match syscall_wait(current, arg0, arg1, arg2) {
                    WaitOutcome::Done(result) => result,
                    WaitOutcome::Blocked => {
                        crate::arch_runtime::set_frame_result(frame, 0);
                        switch_from_frame(frame, false);
                    }
                },
                SYS_TIME => now() as i64,
                SYS_BLOCK_INFO => syscall_block_info(current, arg0, arg1),
                SYS_BLOCK_READ => syscall_block_read(current, arg0, arg1, arg2),
                SYS_BLOCK_WRITE => syscall_block_write(current, arg0, arg1, arg2),
                SYS_BLOCK_FLUSH => syscall_block_flush(current, arg0),
                SYS_BLOCK_READ_MANY => syscall_block_read_many(current, arg0, arg1, arg2),
                SYS_BLOCK_WRITE_MANY => syscall_block_write_many(current, arg0, arg1, arg2),
                SYS_MACHINE_STOP => syscall_machine_stop(current, pid, arg0, arg1),
                SYS_MACHINE_RESTART => syscall_machine_restart(current, pid, arg0),
                SYS_MACHINE_RECOVER => syscall_machine_recover(current, pid, arg0),
                SYS_BOOT_ID => syscall_boot_id(current, arg0),
                SYS_WALL_CLOCK => syscall_wall_clock(),
                SYS_FRAME_STATS => syscall_frame_stats(current, arg0),
                SYS_RESOURCE_CENSUS => syscall_resource_census(current, arg0),
                SYS_ABI_VERSION => absd_abi::KERNEL_ABI as i64,
                absd_kernel::nic::SYS_NIC_INFO => nic::syscall_nic_info(current, arg0, arg1),
                absd_kernel::nic::SYS_NIC_SEND => nic::syscall_nic_send(current, arg0, arg1, arg2),
                absd_kernel::nic::SYS_NIC_RECEIVE => {
                    match nic::syscall_nic_receive(current, arg0, arg1, arg2) {
                        WaitOutcome::Done(result) => result,
                        WaitOutcome::Blocked => {
                            crate::arch_runtime::set_frame_result(frame, 0);
                            switch_from_frame(frame, false);
                        }
                    }
                }
                SYS_INFO => syscall_info(current, arg0, arg1),
                SYS_KILL => match syscall_kill(current, arg0) {
                    WaitOutcome::Done(result) => result,
                    WaitOutcome::Blocked => {
                        crate::arch_runtime::set_frame_result(frame, 0);
                        switch_from_frame(frame, false);
                    }
                },
                SYS_TRANSFER => match syscall_transfer(current, arg0, arg1, arg2) {
                    WaitOutcome::Done(result) => result,
                    WaitOutcome::Blocked => {
                        crate::arch_runtime::set_frame_result(frame, 0);
                        switch_from_frame(frame, false);
                    }
                },
                absd_kernel::syscall::SYS_RT_NEXT => {
                    if arg0 != 0
                        || arg1 != 0
                        || arg2 != 0
                        || table().entries[current].class.rt().is_none()
                    {
                        ERROR_INVALID
                    } else {
                        crate::sched::rt_complete(&mut table().entries[current]);
                        crate::arch_runtime::set_frame_result(frame, 0);
                        switch_from_frame(frame, false);
                    }
                }
                SYS_SLEEP => {
                    if arg0 == 0 {
                        crate::arch_runtime::set_frame_result(frame, 0);
                        switch_from_frame(frame, false);
                    }
                    let waiter = &mut table().entries[current];
                    waiter.state = ProcessState::Waiting;
                    waiter.wait_kind = WaitKind::Sleep;
                    waiter.wake_at = deadline(arg0);
                    crate::sched::rt_arm_fixture(table(), current);
                    stats().sleeps += 1;
                    crate::arch_runtime::set_frame_result(frame, 0);
                    switch_from_frame(frame, false);
                }
                SYS_CELL_WAIT => match syscall_cell_wait(current, arg0, arg1, arg2) {
                    WaitOutcome::Done(result) => result,
                    WaitOutcome::Blocked => {
                        crate::arch_runtime::set_frame_result(frame, 0);
                        switch_from_frame(frame, false);
                    }
                },
                _ => {
                    stats().unknown_refusals += 1;
                    ERROR_NOT_IMPLEMENTED
                }
            }
        };
        crate::smp_user::commit_gap(number);
        // A stop committed while a bounded handler yielded serialization
        // retires the handler and pivots off its task resources. No result
        // (including a spawn publication) reaches user mode afterward.
        if table().entries[current].stop != absd_kernel::process::StopState::Active {
            crate::arch_runtime::set_frame_result(frame, 0);
            switch_from_frame(frame, false);
        }
        crate::arch_runtime::set_frame_result(frame, (result as u64) as i64);
        root
    }
}

/// Keep the production counter identical; closed BSP tests also attribute
/// each original increment to immutable, CPU-local syscall entry identity.
unsafe fn count_handle_refusal(site: u64) {
    if crate::smp_app_pressure::omit_refusal(site) {
        return;
    }
    unsafe { stats().handle_refusals += 1 };
    crate::smp_app_pressure::refusal(site);
}

/// Maps a handle-table failure onto the ABI, counting the refusal.
unsafe fn handle_error(error: HandleError) -> i64 {
    unsafe {
        count_handle_refusal(0);
    }
    match error {
        HandleError::Rights => ERROR_RIGHTS,
        HandleError::Invalid => ERROR_BAD_HANDLE,
        HandleError::Full => ERROR_TOO_MANY_HANDLES,
    }
}

/// `spawn(program | flags, handle, arg)`: starts a child and returns a
/// wait-and-kill-capable handle to it in the caller's table. `handle` (zero for
/// none) is duplicated into the child with the same rights; with
/// `SPAWN_CONSOLE` it must be a writable console or pipe and becomes the
/// child's console. `arg` is passed through. Everything is validated
/// before the process is created, so a refusal has no side effects.
unsafe fn syscall_spawn(current: usize, program: u64, handle: u64, arg: u64) -> i64 {
    let flags = program & !SPAWN_PROGRAM_MASK;
    if flags & !(SPAWN_CONSOLE | SPAWN_NO_SPAWN) != 0 {
        return ERROR_INVALID;
    }
    let as_console = flags & SPAWN_CONSOLE != 0;
    let no_spawn = flags & SPAWN_NO_SPAWN != 0;
    let program = (program & SPAWN_PROGRAM_MASK) as usize;
    let table = unsafe { table() };
    if !table.entries[current].may_spawn {
        return unsafe { handle_error(HandleError::Rights) };
    }
    let pid = table.entries[current].pid;
    if !table.entries[current].handles.has_free_slot() {
        unsafe {
            count_handle_refusal(1);
        }
        return ERROR_TOO_MANY_HANDLES;
    }
    let transfer = if handle == 0 {
        if as_console {
            return unsafe { handle_error(HandleError::Invalid) };
        }
        None
    } else {
        match table.entries[current].handles.lookup(handle) {
            Ok(found) => {
                // Process control is parent-local: genealogy and reaping are
                // not transferable to another process.
                if matches!(found.object, Object::Process(_)) {
                    return unsafe { handle_error(HandleError::Invalid) };
                }
                if as_console {
                    if !matches!(found.object, Object::Console | Object::Pipe(_)) {
                        return unsafe { handle_error(HandleError::Invalid) };
                    }
                    if let Err(error) = found.require(RIGHT_WRITE) {
                        return unsafe { handle_error(error) };
                    }
                    // A pipe console must be the write end only: a child
                    // that also reads its own console could wait for ever
                    // on a full pipe once the parent stops draining it.
                    if matches!(found.object, Object::Pipe(_)) && found.rights & RIGHT_READ != 0 {
                        return unsafe { handle_error(HandleError::Rights) };
                    }
                }
                Some(Transfer {
                    object: found.object,
                    rights: found.rights,
                    as_console,
                })
            }
            Err(error) => return unsafe { handle_error(error) },
        }
    };
    let child = match unsafe { spawn_with(program, pid, transfer, arg) } {
        Ok(child) => child,
        Err(error) => return error.code(),
    };
    unsafe { publish_child(current, child, no_spawn) }
}

#[cfg(feature = "frame-reservation-experiment")]
unsafe fn experimental_spawn(current: usize, program: u64, total: u64, cell: u64) -> i64 {
    if program & !SPAWN_PROGRAM_MASK & !SPAWN_NO_SPAWN != 0 {
        return ERROR_INVALID;
    }
    let parent = unsafe { table() };
    if !parent.entries[current].may_spawn {
        return ERROR_RIGHTS;
    }
    if !parent.entries[current].handles.has_free_slot() {
        return ERROR_TOO_MANY_HANDLES;
    }
    let pid = parent.entries[current].pid;
    let transfer = if cell == 0 {
        None
    } else {
        match parent.entries[current].handles.lookup(cell) {
            Ok(found) if matches!(found.object, Object::Cell(_)) => Some(Transfer {
                object: found.object,
                rights: found.rights,
                as_console: false,
            }),
            Ok(_) => return ERROR_INVALID,
            Err(error) => return unsafe { handle_error(error) },
        }
    };
    match unsafe {
        crate::sched::spawn_reserved(
            (program & SPAWN_PROGRAM_MASK) as usize,
            pid,
            total as usize,
            transfer,
        )
    } {
        Ok(child) => unsafe { publish_child(current, child, program & SPAWN_NO_SPAWN != 0) },
        Err(error) => error.code(),
    }
}

#[cfg(feature = "frame-admission-v0")]
static mut FRAME_BOOTSTRAP: absd_kernel::frame_admission::BootstrapAdmission =
    absd_kernel::frame_admission::BootstrapAdmission::new();

#[cfg(feature = "frame-admission-v0")]
pub(crate) unsafe fn designate_frame_bootstrap(pid: u64) {
    unsafe { (*core::ptr::addr_of_mut!(FRAME_BOOTSTRAP)).designate(pid) };
    let index = unsafe { table() }.slot_of(pid).unwrap();
    unsafe { table() }.entries[index].grant_bootstrap_frame_admission();
}
#[cfg(feature = "frame-admission-v0")]
pub(crate) unsafe fn retire_frame_bootstrap(pid: u64) {
    unsafe { (*core::ptr::addr_of_mut!(FRAME_BOOTSTRAP)).retire(pid) };
}
#[cfg(feature = "frame-admission-v0")]
unsafe fn frame_admission_allowed(current: usize) -> bool {
    let p = &unsafe { table() }.entries[current];
    unsafe { (*core::ptr::addr_of!(FRAME_BOOTSTRAP)).allowed(p.pid, p.may_admit_frames) }
}
#[cfg(feature = "frame-admission-v0")]
unsafe fn supported_admit_self(current: usize, total: u64, reserved1: u64, reserved2: u64) -> i64 {
    let allowed = unsafe { frame_admission_allowed(current) };
    let pid = unsafe { table() }.entries[current].pid;
    absd_kernel::frame_admission::admit_self(
        unsafe { vm::frames() },
        pid as u32,
        allowed,
        total,
        reserved1,
        reserved2,
    )
}
#[cfg(feature = "frame-admission-v0")]
unsafe fn supported_spawn_reserved(
    current: usize,
    request: u64,
    reserved1: u64,
    reserved2: u64,
) -> i64 {
    let allowed = unsafe { frame_admission_allowed(current) };
    let request =
        match absd_kernel::frame_admission::read_request(allowed, reserved1, reserved2, |raw| {
            let space = unsafe { table() }.entries[current].address_space;
            let copied = unsafe { copy_from_user(&space, request, raw) }.is_ok();
            if !copied {
                unsafe {
                    stats().pointer_refusals += 1;
                }
            }
            copied
        }) {
            Ok(request) => request,
            Err(code) => return code,
        };
    unsafe {
        syscall_spawn_many_copy_inner(
            current,
            request.program_and_flags,
            request.copies_address,
            request.copies_count,
            Some(request.total_frames as usize),
        )
    }
}

/// `spawn_many_copy(program, records, count)`: atomically creates a child
/// and copies an ordered array of narrowed handles into it. The parent keeps
/// every source. The child receives the ordered child-handle vector through
/// its multi-start ABI (`RSI` pointer, `RDX` count); one flagged record may
/// also replace its console (`RDI`). Duplicate sources are explicitly valid.
unsafe fn syscall_spawn_many_copy(current: usize, program: u64, records: u64, count: u64) -> i64 {
    unsafe { syscall_spawn_many_copy_inner(current, program, records, count, None) }
}
unsafe fn syscall_spawn_many_copy_inner(
    current: usize,
    program: u64,
    records: u64,
    count: u64,
    reservation: Option<usize>,
) -> i64 {
    #[cfg(not(feature = "frame-admission-v0"))]
    let _ = reservation;

    if program & !SPAWN_PROGRAM_MASK & !SPAWN_NO_SPAWN != 0 || count > MAX_SPAWN_HANDLES as u64 {
        return ERROR_INVALID;
    }
    let no_spawn = program & SPAWN_NO_SPAWN != 0;
    let program = program & SPAWN_PROGRAM_MASK;
    let count = count as usize;
    let table = unsafe { table() };
    if !table.entries[current].may_spawn {
        return unsafe { handle_error(HandleError::Rights) };
    }
    if !table.entries[current].handles.has_free_slot() {
        unsafe { count_handle_refusal(2) };
        return ERROR_TOO_MANY_HANDLES;
    }
    let mut transfers = [Transfer::EMPTY; MAX_SPAWN_HANDLES];
    if let Err(code) = unsafe { read_transfers(current, records, &mut transfers[..count]) } {
        return code;
    }
    let parent = table.entries[current].pid;
    #[cfg(feature = "frame-admission-v0")]
    let result = match reservation {
        Some(total) => unsafe {
            crate::sched::spawn_many_copy_reserved(
                program as usize,
                parent,
                &transfers[..count],
                total,
            )
        },
        None => unsafe { spawn_many_copy(program as usize, parent, &transfers[..count]) },
    };
    #[cfg(not(feature = "frame-admission-v0"))]
    let result = unsafe { spawn_many_copy(program as usize, parent, &transfers[..count]) };
    let child = match result {
        Ok(child) => child,
        Err(crate::sched::SpawnError::NoHandles) => {
            unsafe { count_handle_refusal(3) };
            return ERROR_TOO_MANY_HANDLES;
        }
        Err(error) => return error.code(),
    };
    #[cfg(feature = "frame-admission-v0")]
    if reservation.is_some() && !unsafe { frame_admission_allowed(current) } {
        unsafe { abort_spawn(child) };
        return ERROR_RIGHTS;
    }
    let result = unsafe { publish_child(current, child, no_spawn) };
    #[cfg(feature = "frame-admission-v0")]
    if result > 0 && program == absd_kernel::program::EXTERNAL_WORKLOAD {
        // Fixed served catalog policy: only the designated init can bind,
        // and the first successful worker construction owns this generation.
        if let Some(Transfer {
            object: Object::Pipe(id),
            ..
        }) = transfers[..count].iter().find(|t| t.as_console)
        {
            unsafe { (*core::ptr::addr_of_mut!(FRAME_BOOTSTRAP)).bind(parent, *id) };
        }
    }
    result
}

/// `spawn_image(request, flags, 0)`: `spawn_many_copy` for a static ELF64
/// image in the caller's own memory. The request record names the image
/// and the descriptor array; everything is validated (spawn right, flags,
/// pointers, image bound, descriptors) before a process slot is claimed,
/// the image is copied by the ordinary loader, and every later failure
/// rolls the child back completely. ELF refusals are `ERROR_NOT_EXECUTABLE`.
unsafe fn syscall_spawn_image(current: usize, request: u64, flags: u64, reserved: u64) -> i64 {
    unsafe { syscall_spawn_image_inner(current, request, flags, reserved, None, false) }
}

unsafe fn syscall_spawn_image_inner(
    current: usize,
    request: u64,
    flags: u64,
    reserved: u64,
    reservation: Option<usize>,
    qualification_abort: bool,
) -> i64 {
    #[cfg(not(feature = "frame-reservation-experiment"))]
    let _ = reservation;
    if flags & !SPAWN_NO_SPAWN != 0 || reserved != 0 && !cfg!(feature = "spawn-image-rollback-test")
    {
        return ERROR_INVALID;
    }
    // The qualification build accepts a bounded per-call frame allowance in
    // the otherwise reserved word. All validation below runs before the quota
    // is installed; the BKL keeps other allocations out until it is removed.
    #[cfg(feature = "spawn-image-rollback-test")]
    if reserved > 64 {
        return ERROR_INVALID;
    }
    let no_spawn = flags & SPAWN_NO_SPAWN != 0;
    let table = unsafe { table() };
    if !table.entries[current].may_spawn {
        return unsafe { handle_error(HandleError::Rights) };
    }
    if !table.entries[current].handles.has_free_slot() {
        unsafe { count_handle_refusal(4) };
        return ERROR_TOO_MANY_HANDLES;
    }
    let space = table.entries[current].address_space;
    let mut raw = [0u8; SPAWN_IMAGE_REQUEST_BYTES];
    if unsafe { copy_from_user(&space, request, &mut raw) }.is_err() {
        unsafe { stats().pointer_refusals += 1 };
        return ERROR_FAULT;
    }
    let mut words = [0u64; 4];
    for (index, word) in words.iter_mut().enumerate() {
        let mut encoded = [0u8; 8];
        encoded.copy_from_slice(&raw[index * 8..index * 8 + 8]);
        *word = u64::from_le_bytes(encoded);
    }
    let request = SpawnImageRequest::from_words(words);
    if request.image_bytes == 0
        || request.image_bytes > MAX_SPAWN_IMAGE_BYTES
        || request.handle_count > MAX_SPAWN_HANDLES as u64
    {
        return ERROR_INVALID;
    }
    let length = request.image_bytes as usize;
    if unsafe { check_user_range(&space, request.image, length, false) }.is_err() {
        unsafe { stats().pointer_refusals += 1 };
        return ERROR_FAULT;
    }
    let count = request.handle_count as usize;
    let mut transfers = [Transfer::EMPTY; MAX_SPAWN_HANDLES];
    if let Err(code) = unsafe { read_transfers(current, request.handles, &mut transfers[..count]) }
    {
        return code;
    }
    let image = UserImage {
        space,
        address: request.image,
        length,
    };
    let parent = table.entries[current].pid;
    #[cfg(feature = "spawn-image-rollback-test")]
    if reserved != 0 {
        let frames = unsafe { vm::frames() };
        assert!(frames.quota().is_none());
        // The legacy failure-injection ceiling cannot withdraw other PIDs'
        // admitted backing. Refuse this test configuration before mutation.
        #[cfg(feature = "frame-reservation-experiment")]
        if frames.idle_reserved_frames() != 0 {
            return ERROR_INVALID;
        }
        frames.set_quota(Some(frames.allocated_frames() + reserved as usize));
    }
    #[cfg(feature = "frame-reservation-experiment")]
    let result = if let Some(total) = reservation {
        unsafe { crate::sched::spawn_image_reserved(&image, parent, &transfers[..count], total) }
    } else {
        unsafe { spawn_image(&image, parent, &transfers[..count]) }
    };
    #[cfg(not(feature = "frame-reservation-experiment"))]
    let result = unsafe { spawn_image(&image, parent, &transfers[..count]) };
    #[cfg(feature = "spawn-image-rollback-test")]
    if reserved != 0 {
        unsafe { vm::frames() }.set_quota(None);
    }
    let child = match result {
        Ok(child) => child,
        Err(crate::sched::SpawnError::NoHandles) => {
            unsafe { count_handle_refusal(5) };
            return ERROR_TOO_MANY_HANDLES;
        }
        Err(crate::sched::SpawnError::BadImage) => return ERROR_NOT_EXECUTABLE,
        Err(error) => return error.code(),
    };
    unsafe { publish_child_inner(current, child, no_spawn, qualification_abort) }
}

/// Copies and validates `transfers.len()` `SpawnHandleCopy` records from
/// the caller: each names a non-process handle the caller holds with at
/// least the requested rights; at most one replaces the console, and it
/// must be a writable console or a write-only pipe end.
unsafe fn read_transfers(
    current: usize,
    records: u64,
    transfers: &mut [Transfer],
) -> Result<(), i64> {
    let table = unsafe { table() };
    let count = transfers.len();
    let mut bytes = [0u8; MAX_SPAWN_HANDLES * SPAWN_HANDLE_COPY_BYTES];
    let byte_count = count * SPAWN_HANDLE_COPY_BYTES;
    if count != 0
        && unsafe {
            check_user_range(
                &table.entries[current].address_space,
                records,
                byte_count,
                false,
            )
        }
        .is_err()
    {
        unsafe { stats().pointer_refusals += 1 };
        return Err(ERROR_FAULT);
    }
    if count != 0
        && unsafe {
            copy_from_user(
                &table.entries[current].address_space,
                records,
                &mut bytes[..byte_count],
            )
        }
        .is_err()
    {
        unsafe { stats().pointer_refusals += 1 };
        return Err(ERROR_FAULT);
    }

    let mut console_seen = false;
    for (index, transfer) in transfers.iter_mut().enumerate() {
        let offset = index * SPAWN_HANDLE_COPY_BYTES;
        let raw = &bytes[offset..offset + SPAWN_HANDLE_COPY_BYTES];
        let mut words = [0u64; 3];
        for (word_index, word) in words.iter_mut().enumerate() {
            let offset = word_index * 8;
            let chunk = &raw[offset..offset + 8];
            let mut encoded = [0u8; 8];
            encoded.copy_from_slice(chunk);
            *word = u64::from_le_bytes(encoded);
        }
        let request = SpawnHandleCopy::from_words(words);
        if request.flags & !SPAWN_HANDLE_COPY_CONSOLE != 0 {
            return Err(ERROR_INVALID);
        }
        if request.rights & !(ALL_RIGHTS as u64) != 0 {
            return Err(unsafe { handle_error(HandleError::Rights) });
        }
        let source = match table.entries[current].handles.lookup(request.source) {
            Ok(source) => source,
            Err(error) => return Err(unsafe { handle_error(error) }),
        };
        // Process handles may be narrowed locally, but cannot be inherited:
        // child genealogy and reaping stay owned by the actual parent.
        if matches!(source.object, Object::Process(_)) {
            return Err(unsafe { handle_error(HandleError::Invalid) });
        }
        let rights = request.rights as u8;
        if let Err(error) = source.require(rights) {
            return Err(unsafe { handle_error(error) });
        }
        let as_console = request.flags & SPAWN_HANDLE_COPY_CONSOLE != 0;
        if as_console {
            if console_seen || !matches!(source.object, Object::Console | Object::Pipe(_)) {
                return Err(unsafe { handle_error(HandleError::Invalid) });
            }
            if rights & RIGHT_WRITE == 0
                || (matches!(source.object, Object::Pipe(_)) && rights & RIGHT_READ != 0)
            {
                return Err(unsafe { handle_error(HandleError::Rights) });
            }
            console_seen = true;
        }
        *transfer = Transfer {
            object: source.object,
            rights,
            as_console,
        };
    }
    Ok(())
}

/// Installs the parent's wait-and-kill handle to a fully built child and
/// only then makes the child runnable; if the handle cannot be installed
/// the child is abandoned whole.
unsafe fn publish_child(current: usize, child: u64, no_spawn: bool) -> i64 {
    unsafe { publish_child_inner(current, child, no_spawn, false) }
}

unsafe fn publish_child_inner(
    current: usize,
    child: u64,
    no_spawn: bool,
    qualification_abort: bool,
) -> i64 {
    #[cfg(not(feature = "frame-admission-qualification"))]
    let _ = qualification_abort;
    let stopped = {
        let table = unsafe { self::table() };
        table.entries[current].stop != absd_kernel::process::StopState::Active
    };
    if stopped {
        unsafe { abort_spawn(child) };
        return ERROR_INVALID;
    }
    if no_spawn {
        let table = unsafe { self::table() };
        if let Some(index) = table.slot_of(child) {
            table.entries[index].may_spawn = false;
        }
    }
    let inserted = unsafe { self::table() }.entries[current]
        .handles
        .insert(Object::Process(child), RIGHT_WAIT | RIGHT_KILL);
    match inserted {
        Ok(handle) => {
            // Private deterministic control: fully constructed child, copied
            // object references and parent handle exist, but no activation.
            #[cfg(feature = "frame-admission-qualification")]
            if qualification_abort {
                unsafe { discard_unpublished_child(current, child, handle) };
                return absd_kernel::syscall::ERROR_AGAIN;
            }
            // A controlled qualification gap may yield serialization here.
            // The Created child remains invisible until the exact commit.
            unsafe { prepublication_fixture_gap(current, child, handle) };
            crate::smp_user::created_gap();
            #[cfg(feature = "frame-admission-v0")]
            if unsafe { vm::frames() }.reservation(child as u32).is_some()
                && !unsafe { frame_admission_allowed(current) }
            {
                unsafe { discard_unpublished_child(current, child, handle) };
                return ERROR_RIGHTS;
            }
            if unsafe { self::table() }.entries[current].stop
                != absd_kernel::process::StopState::Active
            {
                unsafe { discard_unpublished_child(current, child, handle) };
                return ERROR_INVALID;
            }
            unsafe { activate_spawn(child) };
            if crate::sched::boot_mode() == crate::sched::BootMode::SmpLifecycle {
                crate::smp_fixture::after_publication(current, child);
            }
            handle as i64
        }
        Err(error) => {
            unsafe { abort_spawn(child) };
            unsafe { handle_error(error) }
        }
    }
}

/// Shared by real stopped-parent refusal and the private abort control.
unsafe fn discard_unpublished_child(current: usize, child: u64, handle: u64) {
    let closed = unsafe { self::table() }.entries[current]
        .handles
        .close(handle)
        .expect("new child handle vanished before publication");
    unsafe { release_object(closed.object, closed.rights) };
    unsafe { abort_spawn(child) };
}

/// No scheduling gap is admitted on the ordinary path. The kernel-only AP
/// fixture replaces this hook with a bounded, exact stop/publication race.
unsafe fn prepublication_fixture_gap(current: usize, child: u64, handle: u64) {
    if crate::sched::boot_mode() == crate::sched::BootMode::SmpCreatedStop {
        crate::smp_fixture::prepublication_gap(current, child, handle);
    }
}

/// `info(handle, record)`: metadata about the caller (`handle` zero) or a
/// child named by a process handle: PID, parent, program index, and whether
/// it is live or terminal. The record is validated before anything is
/// written.
unsafe fn syscall_info(current: usize, handle: u64, record: u64) -> i64 {
    let table = unsafe { table() };
    let index = if handle == 0 {
        current
    } else {
        let pid = match table.entries[current].handles.process(handle, RIGHT_WAIT) {
            Ok(pid) => pid,
            Err(error) => return unsafe { handle_error(error) },
        };
        match table.slot_of(pid) {
            Some(index) => index,
            None => return unsafe { handle_error(HandleError::Invalid) },
        }
    };
    let subject = &table.entries[index];
    let info = ProcessInfo {
        pid: subject.pid,
        parent: subject.parent,
        program: subject.program as u64,
        state: if subject.is_terminal() {
            INFO_STATE_TERMINAL
        } else if subject.state == ProcessState::Waiting {
            INFO_STATE_WAITING
        } else {
            INFO_STATE_LIVE
        },
    };
    let space = table.entries[current].address_space;
    if unsafe { check_user_range(&space, record, INFO_BYTES, true) }.is_err()
        || unsafe { copy_to_user(&space, record, &info.to_bytes()) }.is_err()
    {
        unsafe {
            stats().pointer_refusals += 1;
        }
        return ERROR_FAULT;
    }
    0
}

/// `transfer(handle, record, direction)`: `read` (direction 0) or `write`
/// (1) whose address, length, and timeout in ticks come from a 24-byte user
/// record, so a pipe or console transfer can be bounded; `-110` when the
/// timeout passes first. Zero timeout means none.
unsafe fn syscall_transfer(
    current: usize,
    handle: u64,
    record: u64,
    direction: u64,
) -> WaitOutcome {
    let space = unsafe { table() }.entries[current].address_space;
    let mut bytes = [0u8; TRANSFER_BYTES];
    if unsafe { copy_from_user(&space, record, &mut bytes) }.is_err() {
        unsafe {
            stats().pointer_refusals += 1;
        }
        return WaitOutcome::Done(ERROR_FAULT);
    }
    let word = |index: usize| {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
        u64::from_le_bytes(raw)
    };
    let (address, length, timeout) = (word(0), word(1), word(2));
    match direction {
        TRANSFER_READ => unsafe { syscall_read(current, handle, address, length, timeout) },
        TRANSFER_WRITE => unsafe { syscall_write(current, handle, address, length, timeout) },
        _ => WaitOutcome::Done(ERROR_INVALID),
    }
}

/// `kill(handle)`: ends a child now, wherever it is blocked, and releases
/// everything it owned; its outcome becomes `Killed` for a later `wait`.
/// A child that has already ended is left as it is and the call succeeds.
unsafe fn syscall_kill(current: usize, handle: u64) -> WaitOutcome {
    let table = unsafe { table() };
    let caller = table.entries[current].pid;
    let pid = match table.entries[current].handles.process(handle, RIGHT_KILL) {
        Ok(pid) => pid,
        Err(error) => return WaitOutcome::Done(unsafe { handle_error(error) }),
    };
    let Some(index) = table.slot_of(pid) else {
        return WaitOutcome::Done(unsafe { handle_error(HandleError::Invalid) });
    };
    if !table.has_child(caller, pid) {
        unsafe {
            stats().wait_refusals += 1;
        }
        return WaitOutcome::Done(ERROR_NO_CHILD);
    }
    let child = &mut table.entries[index];
    if child.is_terminal() {
        return WaitOutcome::Done(0);
    }
    // This closed fixture counts active-victim stop fences, rather than
    // the equally valid termination of an already departed runnable child.
    // Rights, parentage and terminal checks precede this side-effect-free gate.
    #[cfg(any(feature = "smp-scheduler-test", feature = "arm64-smp-qualification"))]
    if child.cpu_owner.is_none() && crate::smp_nway::requires_running_stop(current, index) {
        return WaitOutcome::Done(absd_kernel::syscall::ERROR_AGAIN);
    }
    if let Some(owner) = child.cpu_owner {
        crate::modern_smp::before_stop(child);
        let first_request = child.stop == absd_kernel::process::StopState::Active;
        if first_request {
            child.stop = absd_kernel::process::StopState::Requested;
        }
        let waiter = &mut table.entries[current];
        waiter.state = ProcessState::Waiting;
        waiter.wait_kind = WaitKind::StopFence;
        waiter.wait_target = pid;
        waiter.wake_at = deadline(STOP_OBSERVE_TICKS);
        if first_request {
            if crate::sched::boot_mode() == crate::sched::BootMode::SmpLifecycle {
                crate::smp_fixture::record_remote_request(crate::ap::StopToken {
                    slot: index,
                    pid,
                    claim: owner,
                });
            }
            crate::kernel_lock::signal_remote_stop(index, pid, owner);
        }
        return WaitOutcome::Blocked;
    }
    // The caller is the running process, so the child is runnable or
    // blocked: its stack and page tables are not in use.
    child.clear_wait();
    child.state = ProcessState::Killed;
    unsafe {
        stats().kills += 1;
    }
    serial::write("USER KILLED pid=");
    serial::decimal(pid);
    serial::write(" by=");
    serial::decimal(caller);
    serial::write("\n");
    unsafe { terminate(index) };
    WaitOutcome::Done(0)
}

/// `close(handle)`: releases a handle; the value is never valid again.
/// Closing a process handle does not affect the child, which `wait(0)` can
/// still reap. Closing the last handle to a cell frees the cell.
unsafe fn syscall_close(current: usize, handle: u64) -> i64 {
    let table = unsafe { table() };
    match table.entries[current].handles.close(handle) {
        Ok(closed) => {
            unsafe { release_object(closed.object, closed.rights) };
            0
        }
        Err(error) => unsafe { handle_error(error) },
    }
}

/// `duplicate(handle, rights)`: a second handle to the same object holding
/// only `rights`, which may not exceed the original's. Rights can only
/// narrow along a chain of duplicates.
unsafe fn syscall_duplicate(current: usize, handle: u64, rights: u64) -> i64 {
    let Ok(rights) = u8::try_from(rights) else {
        return unsafe { handle_error(HandleError::Rights) };
    };
    let table = unsafe { table() };
    match table.entries[current].handles.duplicate(handle, rights) {
        Ok((issued, object)) => {
            unsafe { retain_object(object, rights) };
            issued as i64
        }
        Err(error) => unsafe { handle_error(error) },
    }
}

/// Takes the reference a new handle with `rights` holds on a kernel object.
pub(crate) unsafe fn retain_object(object: Object, rights: u8) {
    match object {
        Object::Cell(id) => {
            if let Err(error) = unsafe { cells() }.retain(id) {
                panic!("cell retain failed: {error:?}");
            }
        }
        Object::Pipe(id) => {
            let reads = rights & RIGHT_READ != 0;
            let writes = rights & RIGHT_WRITE != 0;
            if let Err(error) = unsafe { pipes() }.retain(id, reads, writes) {
                panic!("pipe retain failed: {error:?}");
            }
        }
        Object::None
        | Object::Console
        | Object::Process(_)
        | Object::Block
        | Object::Nic
        | Object::Machine => {}
    }
}

/// Drops the reference a handle with `rights` held on a kernel object.
/// Losing the last reader or writer of a pipe wakes the other side.
pub(crate) unsafe fn release_object(object: Object, rights: u8) {
    match object {
        Object::Cell(id) => {
            if cfg!(absd_mutant_cell_skip_release) {
                return;
            }
            if let Err(error) = unsafe { cells() }.release(id) {
                panic!("cell release failed: {error:?}");
            }
        }
        Object::Pipe(id) => {
            let reads = rights & RIGHT_READ != 0;
            let writes = rights & RIGHT_WRITE != 0;
            match unsafe { pipes() }.release(id, reads, writes) {
                Ok(Some(status)) => unsafe { wake_pipe_waiters(id, status) },
                Ok(None) => {}
                Err(error) => panic!("pipe release failed: {error:?}"),
            }
        }
        Object::None
        | Object::Console
        | Object::Process(_)
        | Object::Block
        | Object::Nic
        | Object::Machine => {}
    }
}

/// `pipe_create()`: an empty pipe, returned as a handle with read and write
/// rights. Split the ends with `duplicate` and close the original.
unsafe fn syscall_pipe_create(current: usize) -> i64 {
    let table = unsafe { table() };
    if !table.entries[current].handles.has_free_slot() {
        unsafe {
            count_handle_refusal(6);
        }
        return ERROR_TOO_MANY_HANDLES;
    }
    let rights = RIGHT_READ | RIGHT_WRITE;
    let id = match unsafe { pipes() }.create(rights) {
        Ok(id) => id,
        Err(_) => {
            unsafe {
                stats().pipe_refusals += 1;
            }
            return ERROR_NO_MEMORY;
        }
    };
    match table.entries[current]
        .handles
        .insert(Object::Pipe(id), rights)
    {
        Ok(handle) => handle as i64,
        Err(error) => {
            unsafe { release_object(Object::Pipe(id), rights) };
            unsafe { handle_error(error) }
        }
    }
}

/// `pipe_info(handle, record)`: the pipe's fill level and how many handles
/// can read and write it. Needs no right beyond holding a handle to the
/// pipe; never blocks and moves no byte.
unsafe fn syscall_pipe_info(current: usize, handle: u64, record: u64) -> i64 {
    let table = unsafe { table() };
    let found = match table.entries[current].handles.lookup(handle) {
        Ok(found) => found,
        Err(error) => return unsafe { handle_error(error) },
    };
    let Object::Pipe(id) = found.object else {
        return ERROR_BAD_HANDLE;
    };
    let Ok(status) = (unsafe { pipes() }).status(id) else {
        return ERROR_BAD_HANDLE;
    };
    let info = PipeInfo {
        available: status.available as u64,
        space: status.space as u64,
        readers: u64::from(status.readers),
        writers: u64::from(status.writers),
    };
    let space = &table.entries[current].address_space;
    if unsafe { check_user_range(space, record, PIPE_INFO_BYTES, true) }.is_err()
        || unsafe { copy_to_user(space, record, &info.to_bytes()) }.is_err()
    {
        unsafe {
            stats().pointer_refusals += 1;
        }
        return ERROR_FAULT;
    }
    0
}

/// Tries a pipe transfer against `space`. `Ok(Some(n))` moved `n` bytes,
/// `Ok(None)` means the pipe cannot proceed yet, and `Err` is final.
unsafe fn try_pipe_transfer(
    current: usize,
    space: &absd_kernel::process::AddressSpace,
    id: PipeId,
    address: u64,
    length: usize,
    write: bool,
) -> Result<Option<usize>, i64> {
    #[cfg(not(feature = "frame-admission-v0"))]
    let _ = current;
    let pipes = unsafe { pipes() };
    let scope = crate::smp_leaf_measure::Scope::begin(crate::smp_leaf_measure::STATUS);
    let status = pipes.status(id);
    scope.finish(0);
    let status = status.map_err(|_| ERROR_BAD_HANDLE)?;
    let mut bytes = [0u8; MAX_TRANSFER as usize];
    if write {
        if status.readers == 0 {
            return Err(ERROR_PIPE);
        }
        let count = length.min(status.space);
        if count == 0 {
            return Ok(None);
        }
        let scope = crate::smp_leaf_measure::Scope::begin(crate::smp_leaf_measure::FROM_USER);
        let copied = unsafe { copy_from_user(space, address, &mut bytes[..count]) };
        scope.finish(if copied.is_ok() { count } else { 0 });
        if copied.is_err() {
            return Err(ERROR_FAULT);
        }
        let scope = crate::smp_leaf_measure::Scope::begin(crate::smp_leaf_measure::WRITE);
        let written = pipes.write(id, &bytes[..count]);
        scope.finish(written.as_ref().copied().unwrap_or(0));
        let written = written.map_err(|_| ERROR_BAD_HANDLE)?;
        unsafe {
            stats().pipe_writes += 1;
        }
        Ok(Some(written))
    } else {
        let count = length.min(status.available);
        if count == 0 {
            // Nothing to read: end of file once no writer remains.
            return if status.writers == 0 {
                Ok(Some(0))
            } else {
                Ok(None)
            };
        }
        let scope = crate::smp_leaf_measure::Scope::begin(crate::smp_leaf_measure::READ);
        let read = pipes.read(id, &mut bytes[..count]);
        scope.finish(read.as_ref().copied().unwrap_or(0));
        let read = read.map_err(|_| ERROR_BAD_HANDLE)?;
        let scope = crate::smp_leaf_measure::Scope::begin(crate::smp_leaf_measure::TO_USER);
        let copied = unsafe { copy_to_user(space, address, &bytes[..read]) };
        scope.finish(if copied.is_ok() { read } else { 0 });
        if copied.is_err() {
            // The bytes are consumed; a bad buffer loses them, as the
            // caller was told to validate its own memory.
            return Err(ERROR_FAULT);
        }
        unsafe {
            #[cfg(feature = "frame-admission-v0")]
            {
                let process = &mut table().entries[current];
                if (*core::ptr::addr_of_mut!(FRAME_BOOTSTRAP)).delivered(
                    process.pid,
                    id,
                    &bytes[..read],
                ) {
                    process.may_admit_frames = false;
                }
            }
            stats().pipe_reads += 1;
        }
        Ok(Some(read))
    }
}

/// Shared entry for `read` and `write` on a pipe: validate the buffer, try
/// once, and otherwise block with the transfer recorded for retry.
unsafe fn pipe_operation(
    current: usize,
    id: PipeId,
    address: u64,
    length: u64,
    write: bool,
    timeout: u64,
) -> WaitOutcome {
    let Ok(length) = usize::try_from(length) else {
        return WaitOutcome::Done(ERROR_INVALID);
    };
    if length == 0 || length > MAX_TRANSFER as usize {
        return WaitOutcome::Done(ERROR_INVALID);
    }
    let table = unsafe { table() };
    let space = table.entries[current].address_space;
    if unsafe { check_user_range(&space, address, length, !write) }.is_err() {
        unsafe {
            stats().pointer_refusals += 1;
        }
        return WaitOutcome::Done(ERROR_FAULT);
    }
    match unsafe { try_pipe_transfer(current, &space, id, address, length, write) } {
        Ok(Some(count)) => WaitOutcome::Done(count as i64),
        Err(error) => WaitOutcome::Done(error),
        Ok(None) => {
            let waiter = &mut table.entries[current];
            waiter.state = ProcessState::Waiting;
            waiter.wait_kind = WaitKind::Pipe;
            waiter.wake_at = deadline(timeout);
            waiter.wait_pipe = Some(id);
            waiter.wait_transfer = Some(TransferWait {
                address,
                length,
                write,
            });
            unsafe {
                stats().pipe_waits += 1;
            }
            WaitOutcome::Blocked
        }
    }
}

/// Retries every transfer blocked on `id` that can now proceed, completing
/// it against the waiter's own memory and making the waiter runnable.
pub(crate) unsafe fn wake_pipe_waiters(id: PipeId, _status: PipeStatus) {
    let scope = crate::smp_leaf_measure::Scope::begin(crate::smp_leaf_measure::WAKE);
    let table = unsafe { table() };
    for index in 0..MAX_PROCESSES {
        let entry = &table.entries[index];
        if !entry.can_wake() {
            continue;
        }
        if entry.wait_pipe != Some(id) {
            continue;
        }
        let Some(wait) = entry.wait_transfer else {
            continue;
        };
        let space = entry.address_space;
        let result = match unsafe {
            try_pipe_transfer(index, &space, id, wait.address, wait.length, wait.write)
        } {
            Ok(Some(count)) => count as i64,
            Err(error) => error,
            Ok(None) => continue,
        };
        let entry = &mut table.entries[index];
        entry.clear_wait();
        entry.task.context.set_result((result as u64) as i64);
        crate::sched::make_runnable(entry);
        unsafe {
            stats().pipe_wakeups += 1;
        }
    }
    scope.finish(0);
}

/// `read(handle, buffer, length)`: from the console (serial input) or a
/// pipe, decided by the handle's object; requires the read right. Returns
/// the bytes moved (at most 256). A pipe read blocks while the pipe is empty
/// and a writer remains and returns 0 once it is empty with no writer left;
/// a console read blocks until at least one byte has arrived.
unsafe fn syscall_read(
    current: usize,
    handle: u64,
    address: u64,
    length: u64,
    timeout: u64,
) -> WaitOutcome {
    let table = unsafe { table() };
    let found = match table.entries[current].handles.lookup(handle) {
        Ok(found) => found,
        Err(error) => return WaitOutcome::Done(unsafe { handle_error(error) }),
    };
    if let Err(error) = found.require(RIGHT_READ) {
        return WaitOutcome::Done(unsafe { handle_error(error) });
    }
    let id = match found.object {
        Object::Pipe(id) => id,
        Object::Console => return unsafe { console_read(current, address, length, timeout) },
        _ => return WaitOutcome::Done(unsafe { handle_error(HandleError::Invalid) }),
    };
    let outcome = unsafe { pipe_operation(current, id, address, length, false, timeout) };
    if let WaitOutcome::Done(count) = outcome
        && count > 0
        && let Ok(status) = unsafe { pipes() }.status(id)
    {
        unsafe { wake_pipe_waiters(id, status) };
    }
    outcome
}

/// Console input: hand over whatever has arrived, or block until a byte
/// does. The interrupt only banks bytes; the wake-up happens here and in
/// `wake_console_readers`.
unsafe fn console_read(current: usize, address: u64, length: u64, timeout: u64) -> WaitOutcome {
    let Ok(length) = usize::try_from(length) else {
        return WaitOutcome::Done(ERROR_INVALID);
    };
    if length == 0 || length > MAX_TRANSFER as usize {
        return WaitOutcome::Done(ERROR_INVALID);
    }
    let table = unsafe { table() };
    let space = table.entries[current].address_space;
    if unsafe { check_user_range(&space, address, length, true) }.is_err() {
        unsafe {
            stats().pointer_refusals += 1;
        }
        return WaitOutcome::Done(ERROR_FAULT);
    }
    if serial::input_available() != 0 {
        return WaitOutcome::Done(unsafe { deliver_console_input(&space, address, length) });
    }
    let waiter = &mut table.entries[current];
    waiter.state = ProcessState::Waiting;
    waiter.wait_kind = WaitKind::Console;
    waiter.wake_at = deadline(timeout);
    waiter.wait_transfer = Some(TransferWait {
        address,
        length,
        write: false,
    });
    unsafe {
        stats().console_waits += 1;
        // Shell is a qualification boot mode. Its host may inject an entire
        // line at once, so a printed prompt is not a blocked-read receipt.
        // State and transfer registration are complete; this path now
        // unconditionally returns Blocked before input can be delivered.
        if stats().console_waits == 1 && crate::sched::boot_mode() == crate::sched::BootMode::Shell
        {
            serial::write("\nSHELL CONSOLE BLOCKED\n");
        }
    }
    WaitOutcome::Blocked
}

unsafe fn deliver_console_input(
    space: &absd_kernel::process::AddressSpace,
    address: u64,
    length: usize,
) -> i64 {
    let mut bytes = [0u8; MAX_TRANSFER as usize];
    let count = serial::take_input(&mut bytes[..length]);
    if unsafe { copy_to_user(space, address, &bytes[..count]) }.is_err() {
        return ERROR_FAULT;
    }
    unsafe {
        stats().console_reads += 1;
    }
    count as i64
}

/// Read-only qualification observation for the explicit USB Console race
/// fixture. No table borrow escapes into the driver or ISR.
#[cfg(target_arch = "x86_64")]
pub(crate) fn usb_keyboard_test_deadline() -> Option<u64> {
    crate::debug_assert_interrupts_disabled();
    crate::kernel_lock::assert_held(crate::kernel_lock::BSP);
    let now = now();
    unsafe { table() }
        .entries
        .iter()
        .filter_map(|entry| {
            if entry.state != ProcessState::Waiting || entry.wait_kind != WaitKind::Console {
                return None;
            }
            entry
                .wake_at
                .filter(|&deadline| deadline > now && deadline - now <= 1000)
        })
        .min()
}

/// Completes the console read of the first blocked reader. The byte stream
/// is not split between multiple waiters in one scan.
pub(crate) unsafe fn wake_console_readers() {
    if serial::input_available() == 0 {
        return;
    }
    let table = unsafe { table() };
    for index in 0..MAX_PROCESSES {
        let entry = &table.entries[index];
        if !entry.can_wake() || entry.wait_kind != WaitKind::Console {
            continue;
        }
        let Some(wait) = entry.wait_transfer else {
            continue;
        };
        let space = entry.address_space;
        let result = unsafe { deliver_console_input(&space, wait.address, wait.length) };
        let entry = &mut table.entries[index];
        entry.clear_wait();
        entry.task.context.set_result((result as u64) as i64);
        crate::sched::make_runnable(entry);
        return;
    }
}

/// `cell_create(value)`: a new cell at version 0 holding `value`, returned
/// as a handle with read and write rights.
unsafe fn syscall_cell_create(current: usize, value: u64) -> i64 {
    let table = unsafe { table() };
    if !table.entries[current].handles.has_free_slot() {
        unsafe {
            count_handle_refusal(7);
        }
        return ERROR_TOO_MANY_HANDLES;
    }
    let rights = RIGHT_READ | RIGHT_WRITE;
    let id = match unsafe { cells() }.create(value, rights) {
        Ok(id) => id,
        Err(_) => {
            unsafe {
                stats().cell_refusals += 1;
            }
            return ERROR_NO_MEMORY;
        }
    };
    match table.entries[current]
        .handles
        .insert(Object::Cell(id), rights)
    {
        Ok(handle) => handle as i64,
        Err(error) => {
            unsafe { release_object(Object::Cell(id), rights) };
            unsafe { handle_error(error) }
        }
    }
}

/// `cell_read(handle, record)`: stores `{version, value}` at `record`.
unsafe fn syscall_cell_read(current: usize, handle: u64, record: u64) -> i64 {
    let table = unsafe { table() };
    let process = &table.entries[current];
    let id = match process.handles.cell(handle, RIGHT_READ) {
        Ok(id) => id,
        Err(error) => return unsafe { handle_error(error) },
    };
    let (version, value) = match unsafe { cells() }.read(id) {
        Ok(state) => state,
        Err(_) => return unsafe { handle_error(HandleError::Invalid) },
    };
    let mut bytes = [0u8; CELL_RECORD_BYTES];
    bytes[..8].copy_from_slice(&version.to_le_bytes());
    bytes[8..].copy_from_slice(&value.to_le_bytes());
    // Check the whole record first so a refusal writes nothing.
    if unsafe { check_user_range(&process.address_space, record, CELL_RECORD_BYTES, true) }.is_err()
        || unsafe { copy_to_user(&process.address_space, record, &bytes) }.is_err()
    {
        unsafe {
            stats().pointer_refusals += 1;
        }
        return ERROR_FAULT;
    }
    0
}

/// `cell_transition(handle, expected, value)`: stores `value` only if the
/// cell is still at version `expected`, returning the new version. A stale
/// expectation changes nothing.
unsafe fn syscall_cell_transition(current: usize, handle: u64, expected: u64, value: u64) -> i64 {
    let table = unsafe { table() };
    let id = match table.entries[current].handles.cell(handle, RIGHT_WRITE) {
        Ok(id) => id,
        Err(error) => {
            #[cfg(absd_mutant_denied_cell_effect)]
            if error == HandleError::Rights {
                if let Ok(id) = table.entries[current].handles.cell(handle, 0) {
                    let _ = unsafe { cells() }.transition(id, expected, value);
                }
            }
            return unsafe { handle_error(error) };
        }
    };
    match unsafe { cells() }.transition(id, expected, value) {
        Ok(version) => {
            unsafe {
                stats().transitions += 1;
                wake_cell_waiters(id, version);
            }
            version as i64
        }
        Err(CellError::Stale { .. }) => {
            unsafe {
                stats().stale_transitions += 1;
            }
            ERROR_STALE
        }
        Err(_) => unsafe { handle_error(HandleError::Invalid) },
    }
}

/// `write(handle, buffer, length)`: to the console (serial) or a pipe,
/// decided by the handle's object. Pipe writes may be partial, block while
/// the pipe is full and a reader remains, and fail with `-32` once no
/// reader is left.
unsafe fn syscall_write(
    current: usize,
    handle: u64,
    address: u64,
    length: u64,
    timeout: u64,
) -> WaitOutcome {
    let table = unsafe { table() };
    let found = match table.entries[current].handles.lookup(handle) {
        Ok(found) => found,
        Err(error) => return WaitOutcome::Done(unsafe { handle_error(error) }),
    };
    if let Err(error) = found.require(RIGHT_WRITE) {
        return WaitOutcome::Done(unsafe { handle_error(error) });
    }
    match found.object {
        Object::Console => WaitOutcome::Done(unsafe { console_write(current, address, length) }),
        Object::Pipe(id) => {
            let outcome = unsafe { pipe_operation(current, id, address, length, true, timeout) };
            if let WaitOutcome::Done(count) = outcome
                && count > 0
                && let Ok(status) = unsafe { pipes() }.status(id)
            {
                unsafe { wake_pipe_waiters(id, status) };
            }
            outcome
        }
        _ => WaitOutcome::Done(unsafe { handle_error(HandleError::Invalid) }),
    }
}

unsafe fn console_write(current: usize, address: u64, length: u64) -> i64 {
    let process = unsafe { &table().entries[current] };
    let Ok(length) = usize::try_from(length) else {
        return ERROR_INVALID;
    };
    if length == 0 || length > MAX_USER_WRITE {
        return ERROR_INVALID;
    }
    let mut bytes = [0u8; MAX_USER_WRITE];
    if unsafe { copy_from_user(&process.address_space, address, &mut bytes[..length]) }.is_err() {
        unsafe {
            stats().pointer_refusals += 1;
        }
        return ERROR_FAULT;
    }
    for byte in &bytes[..length] {
        serial::byte_out(*byte);
    }
    unsafe {
        stats().writes += 1;
    }
    length as i64
}

/// `map(pages)`: maps `pages` zeroed, writable, non-executable anonymous
/// pages at the lowest free run of the caller's heap window and returns
/// their address. Fails closed without mapping anything on a bad count or
/// a full window; frames already mapped are unmapped again if the frame
/// pool runs out part way.
unsafe fn syscall_map(current: usize, pages: u64) -> i64 {
    if pages == 0 || pages > MAX_MAP_PAGES {
        unsafe {
            stats().map_refusals += 1;
        }
        return ERROR_INVALID;
    }
    let table = unsafe { table() };
    let process = &mut table.entries[current];
    let pid = process.pid as u32;
    let Some(base) = (unsafe {
        vm::find_unmapped_run(&process.address_space, USER_HEAP_BASE, USER_HEAP_END, pages)
    }) else {
        unsafe {
            stats().map_refusals += 1;
        }
        return ERROR_NO_MEMORY;
    };
    let frames = unsafe { vm::frames() };
    for index in 0..pages {
        let address = base + index * PAGE_SIZE;
        let mapped = unsafe {
            vm::map_user_page(
                frames,
                &mut process.address_space,
                pid,
                address,
                true,
                false,
            )
        };
        if mapped.is_err() {
            for undo in 0..index {
                let address = base + undo * PAGE_SIZE;
                if let Err(error) =
                    unsafe { vm::unmap_user_page(frames, &mut process.address_space, pid, address) }
                {
                    panic!("map rollback for pid {pid} failed: {error:?}");
                }
                crate::invalidate_page(address);
            }
            unsafe {
                stats().map_refusals += 1;
            }
            return ERROR_NO_MEMORY;
        }
    }
    unsafe {
        stats().maps += 1;
    }
    base as i64
}

/// `unmap(address, pages)`: returns `pages` mapped heap pages starting at
/// `address`. Every page is checked before any is released, so a bad range
/// changes nothing.
unsafe fn syscall_unmap(current: usize, address: u64, pages: u64) -> i64 {
    let table = unsafe { table() };
    let process = &mut table.entries[current];
    let pid = process.pid as u32;
    let valid = pages != 0
        && pages <= MAX_MAP_PAGES
        && address.is_multiple_of(PAGE_SIZE)
        && address >= USER_HEAP_BASE
        && address
            .checked_add(pages * PAGE_SIZE)
            .is_some_and(|end| end <= USER_HEAP_END)
        && (0..pages).all(|index| unsafe {
            vm::is_mapped(&process.address_space, address + index * PAGE_SIZE)
        });
    if !valid {
        unsafe {
            stats().map_refusals += 1;
        }
        return ERROR_INVALID;
    }
    let frames = unsafe { vm::frames() };
    for index in 0..pages {
        let page = address + index * PAGE_SIZE;
        if let Err(error) =
            unsafe { vm::unmap_user_page(frames, &mut process.address_space, pid, page) }
        {
            panic!("unmap for pid {pid} failed: {error:?}");
        }
        crate::invalidate_page(page);
    }
    unsafe {
        stats().unmaps += 1;
    }
    0
}

enum WaitOutcome {
    Done(i64),
    Blocked,
}

/// `cell_wait(handle, seen)`: returns the cell's version as soon as it
/// differs from `seen`, blocking until a transition moves it if necessary.
/// Requires the read right. The blocked process keeps its handle, so the
/// cell cannot be freed underneath it.
unsafe fn syscall_cell_wait(current: usize, handle: u64, seen: u64, timeout: u64) -> WaitOutcome {
    let table = unsafe { table() };
    let id = match table.entries[current].handles.cell(handle, RIGHT_READ) {
        Ok(id) => id,
        Err(error) => return WaitOutcome::Done(unsafe { handle_error(error) }),
    };
    let (version, _) = match unsafe { cells() }.read(id) {
        Ok(state) => state,
        Err(_) => return WaitOutcome::Done(unsafe { handle_error(HandleError::Invalid) }),
    };
    if version != seen {
        return WaitOutcome::Done(version as i64);
    }
    let waiter = &mut table.entries[current];
    waiter.state = ProcessState::Waiting;
    waiter.wait_kind = WaitKind::Cell;
    waiter.wait_cell = Some((id, seen));
    waiter.wake_at = deadline(timeout);
    unsafe {
        stats().cell_waits += 1;
    }
    WaitOutcome::Blocked
}

/// Makes every process blocked on `id` runnable with the new version.
unsafe fn wake_cell_waiters(id: CellId, version: u64) {
    let table = unsafe { table() };
    for entry in table.entries.iter_mut() {
        if entry.can_wake() && entry.wait_cell.is_some_and(|(cell, _)| cell == id) {
            entry.clear_wait();
            entry.task.context.set_result((version) as i64);
            crate::sched::make_runnable(entry);
            unsafe {
                stats().cell_wakeups += 1;
            }
        }
    }
}

/// `wait(handle, record)`: reap one terminal child, writing its outcome
/// record to `record`. `handle` names a child through the caller's table;
/// zero means any child. Blocks while a matching child is still live; fails
/// immediately when there is nothing to wait for.
unsafe fn syscall_wait(current: usize, handle: u64, record: u64, timeout: u64) -> WaitOutcome {
    let table = unsafe { table() };
    let caller = table.entries[current].pid;
    let space = table.entries[current].address_space;
    // Validate the record address without writing it: a refused wait must
    // leave the caller's memory untouched, and a later wake-up must not
    // fail on the address.
    if unsafe { check_user_range(&space, record, OUTCOME_BYTES, true) }.is_err() {
        unsafe {
            stats().pointer_refusals += 1;
        }
        return WaitOutcome::Done(ERROR_FAULT);
    }
    let target = if handle == 0 {
        0
    } else {
        match table.entries[current].handles.process(handle, RIGHT_WAIT) {
            Ok(pid) => pid,
            Err(error) => return WaitOutcome::Done(unsafe { handle_error(error) }),
        }
    };
    if !table.has_child(caller, target) {
        unsafe {
            stats().wait_refusals += 1;
        }
        return WaitOutcome::Done(ERROR_NO_CHILD);
    }
    if let Some(child) = table.terminal_child(caller, target) {
        return WaitOutcome::Done(unsafe { deliver_outcome(child, current, record) });
    }
    let waiter = &mut table.entries[current];
    waiter.state = ProcessState::Waiting;
    waiter.wait_kind = WaitKind::Child;
    waiter.wait_target = target;
    waiter.wait_record = record;
    waiter.wake_at = deadline(timeout);
    WaitOutcome::Blocked
}

fn block_error(error: block::BlockError) -> i64 {
    match error {
        block::BlockError::OutOfRange => ERROR_INVALID,
        // Unreachable through a handle: a read-only device is granted
        // without the write right.
        block::BlockError::ReadOnly => ERROR_RIGHTS,
        block::BlockError::Absent | block::BlockError::Device | block::BlockError::Timeout => {
            ERROR_IO
        }
    }
}

/// Resolves a block handle carrying `rights`.
unsafe fn block_handle(current: usize, handle: u64, rights: u8) -> Result<(), i64> {
    let table = unsafe { table() };
    let found = table.entries[current]
        .handles
        .lookup(handle)
        .map_err(|error| unsafe { handle_error(error) })?;
    if found.object != Object::Block {
        return Err(unsafe { handle_error(HandleError::Invalid) });
    }
    found
        .require(rights)
        .map_err(|error| unsafe { handle_error(error) })
}

/// `block_info(handle, record)`: stores `{sector_count, sector_bytes}`.
unsafe fn syscall_block_info(current: usize, handle: u64, record: u64) -> i64 {
    if let Err(error) = unsafe { block_handle(current, handle, RIGHT_READ) } {
        return error;
    }
    let Some(sectors) = block::sector_count() else {
        return ERROR_IO;
    };
    let mut bytes = [0u8; BLOCK_INFO_BYTES];
    bytes[..8].copy_from_slice(&sectors.to_le_bytes());
    bytes[8..].copy_from_slice(&(BLOCK_SECTOR_BYTES as u64).to_le_bytes());
    let space = unsafe { table() }.entries[current].address_space;
    if unsafe { copy_to_user(&space, record, &bytes) }.is_err() {
        unsafe {
            stats().pointer_refusals += 1;
        }
        return ERROR_FAULT;
    }
    0
}

/// `block_read(handle, lba, buffer)`: one sector into 512 bytes of user
/// memory. The range is validated before the device is touched.
unsafe fn syscall_block_read(current: usize, handle: u64, lba: u64, address: u64) -> i64 {
    if let Err(error) = unsafe { block_handle(current, handle, RIGHT_READ) } {
        return error;
    }
    let space = unsafe { table() }.entries[current].address_space;
    if unsafe { check_user_range(&space, address, BLOCK_SECTOR_BYTES, true) }.is_err() {
        unsafe {
            stats().pointer_refusals += 1;
        }
        return ERROR_FAULT;
    }
    let mut sector = [0u8; BLOCK_SECTOR_BYTES];
    if let Err(error) = block::read_sector(lba, &mut sector) {
        return block_error(error);
    }
    if unsafe { table() }.entries[current].stop != absd_kernel::process::StopState::Active {
        // The device command can finish while a remote stop is pending, but
        // no new user-memory transfer is committed after that request.
        return ERROR_IO;
    }
    if unsafe { copy_to_user(&space, address, &sector) }.is_err() {
        return ERROR_FAULT;
    }
    0
}

/// `block_write(handle, lba, buffer)`: 512 user bytes to one sector. Returns
/// only after the device reports the write complete.
unsafe fn syscall_block_write(current: usize, handle: u64, lba: u64, address: u64) -> i64 {
    if let Err(error) = unsafe { block_handle(current, handle, RIGHT_WRITE) } {
        return error;
    }
    let space = unsafe { table() }.entries[current].address_space;
    let mut sector = [0u8; BLOCK_SECTOR_BYTES];
    if unsafe { copy_from_user(&space, address, &mut sector) }.is_err() {
        unsafe {
            stats().pointer_refusals += 1;
        }
        return ERROR_FAULT;
    }
    match block::write_sector(lba, &sector) {
        Ok(()) => 0,
        Err(error) => block_error(error),
    }
}

/// Kernel staging for one `block_*_many` request. Device access is BSP-only
/// under the kernel lock and one block command is outstanding at a time
/// (the assumption the NVMe bounce page already makes), so one page
/// suffices; the user range is validated before the device is touched.
const BLOCK_TRANSFER_MAX_BYTES: usize = BLOCK_MAX_TRANSFER_SECTORS as usize * BLOCK_SECTOR_BYTES;
#[repr(C, align(4096))]
struct TransferPage([u8; BLOCK_TRANSFER_MAX_BYTES]);
static mut TRANSFER: TransferPage = TransferPage([0; BLOCK_TRANSFER_MAX_BYTES]);

/// Reads and bounds a [`BlockTransfer`] record and checks the user buffer
/// it describes (`writable` for a read that will fill it). Returns the
/// request and its byte length.
unsafe fn block_transfer_request(
    current: usize,
    request: u64,
    buffer: u64,
    writable: bool,
) -> Result<(BlockTransfer, usize), i64> {
    let space = unsafe { table() }.entries[current].address_space;
    let mut record = [0u8; BLOCK_TRANSFER_BYTES];
    if unsafe { copy_from_user(&space, request, &mut record) }.is_err() {
        unsafe {
            stats().pointer_refusals += 1;
        }
        return Err(ERROR_FAULT);
    }
    let transfer = BlockTransfer::from_bytes(&record);
    if transfer.sectors == 0 || transfer.sectors > BLOCK_MAX_TRANSFER_SECTORS {
        return Err(ERROR_INVALID);
    }
    let bytes = transfer.sectors as usize * BLOCK_SECTOR_BYTES;
    if unsafe { check_user_range(&space, buffer, bytes, writable) }.is_err() {
        unsafe {
            stats().pointer_refusals += 1;
        }
        return Err(ERROR_FAULT);
    }
    Ok((transfer, bytes))
}

/// `block_read_many(handle, request, buffer)`: up to a page of consecutive
/// sectors in one device command, copied out only after the whole command
/// completed. The range is validated before the device is touched.
unsafe fn syscall_block_read_many(current: usize, handle: u64, request: u64, buffer: u64) -> i64 {
    if let Err(error) = unsafe { block_handle(current, handle, RIGHT_READ) } {
        return error;
    }
    let (transfer, bytes) = match unsafe { block_transfer_request(current, request, buffer, true) }
    {
        Ok(found) => found,
        Err(error) => return error,
    };
    let page = unsafe { &mut *core::ptr::addr_of_mut!(TRANSFER) };
    let staging = &mut page.0[..bytes];
    if let Err(error) = block::read_sectors(transfer.lba, staging) {
        return block_error(error);
    }
    if unsafe { table() }.entries[current].stop != absd_kernel::process::StopState::Active {
        // As for `block_read`: no user-memory transfer after a pending stop.
        return ERROR_IO;
    }
    let space = unsafe { table() }.entries[current].address_space;
    if unsafe { copy_to_user(&space, buffer, staging) }.is_err() {
        return ERROR_FAULT;
    }
    0
}

/// `block_write_many(handle, request, buffer)`: up to a page of consecutive
/// sectors in one device command. Returns only after the device reports the
/// whole command complete; an error leaves zero or more leading sectors on
/// the device, and completion is acceptance, not durability.
unsafe fn syscall_block_write_many(current: usize, handle: u64, request: u64, buffer: u64) -> i64 {
    if let Err(error) = unsafe { block_handle(current, handle, RIGHT_WRITE) } {
        return error;
    }
    let (transfer, bytes) = match unsafe { block_transfer_request(current, request, buffer, false) }
    {
        Ok(found) => found,
        Err(error) => return error,
    };
    let page = unsafe { &mut *core::ptr::addr_of_mut!(TRANSFER) };
    let staging = &mut page.0[..bytes];
    let space = unsafe { table() }.entries[current].address_space;
    if unsafe { copy_from_user(&space, buffer, staging) }.is_err() {
        unsafe {
            stats().pointer_refusals += 1;
        }
        return ERROR_FAULT;
    }
    match block::write_sectors(transfer.lba, staging) {
        Ok(()) => 0,
        Err(error) => block_error(error),
    }
}

/// `block_flush(handle)`: the device's own durability barrier.
unsafe fn syscall_block_flush(current: usize, handle: u64) -> i64 {
    if let Err(error) = unsafe { block_handle(current, handle, RIGHT_WRITE) } {
        return error;
    }
    match block::flush() {
        Ok(()) => 0,
        Err(error) => block_error(error),
    }
}

/// `stop(code)`: abrupt machine stop for the durable qualification boots.
/// Refused in every other boot mode so no ordinary workload can end a run.
static mut BOOT_ID: Option<[u8; BOOT_ID_BYTES]> = None;

/// One RDRAND draw, retried a bounded number of times as the SDM advises;
/// `None` when the CPU has no RDRAND or it keeps failing.
pub(crate) use platform::rdrand64;

/// `boot_id(address)`: this boot's identity (see the ABI).
unsafe fn syscall_boot_id(current: usize, address: u64) -> i64 {
    let id = match unsafe { BOOT_ID } {
        Some(id) => id,
        None => {
            let (Some(high), Some(low)) = (rdrand64(), rdrand64()) else {
                return ERROR_NOT_IMPLEMENTED;
            };
            let mut id = [0u8; BOOT_ID_BYTES];
            id[..8].copy_from_slice(&high.to_le_bytes());
            id[8..].copy_from_slice(&low.to_le_bytes());
            unsafe { BOOT_ID = Some(id) };
            id
        }
    };
    let space = unsafe { &table().entries[current].address_space };
    if unsafe { check_user_range(space, address, BOOT_ID_BYTES, true) }.is_err()
        || unsafe { copy_to_user(space, address, &id) }.is_err()
    {
        unsafe { stats().pointer_refusals += 1 };
        return ERROR_FAULT;
    }
    0
}

/// `frame_stats(address)`: the frame allocator's counts (see the ABI).
unsafe fn syscall_frame_stats(current: usize, address: u64) -> i64 {
    let frames = unsafe { vm::frames() };
    let record = FrameStats {
        free_frames: frames.free_frames() as u64,
        allocated_frames: frames.allocated_frames() as u64,
        allocation_limit: frames
            .quota()
            .map_or(FRAME_LIMIT_NONE, |limit| limit as u64),
        frame_bytes: PAGE_SIZE,
    };
    let space = unsafe { &table().entries[current].address_space };
    if unsafe { check_user_range(space, address, FRAME_STATS_BYTES, true) }.is_err()
        || unsafe { copy_to_user(space, address, &record.to_bytes()) }.is_err()
    {
        unsafe { stats().pointer_refusals += 1 };
        return ERROR_FAULT;
    }
    0
}

/// A fixed-size one-instant kernel occupancy record for served churn and
/// named limit qualification. No count is reset or accumulated by reading.
unsafe fn syscall_resource_census(current: usize, address: u64) -> i64 {
    let table = unsafe { table() };
    let record = ResourceCensus {
        processes: table.occupied_count() as u64,
        handles: table
            .entries
            .iter()
            .map(|entry| entry.handles.live_count() as u64)
            .sum(),
        pipes: unsafe { pipes() }.live() as u64,
        cells: unsafe { cells() }.live() as u64,
        frames: unsafe { vm::frames() }.allocated_frames() as u64,
    };
    let space = &table.entries[current].address_space;
    if unsafe { check_user_range(space, address, RESOURCE_CENSUS_BYTES, true) }.is_err()
        || unsafe { copy_to_user(space, address, &record.to_bytes()) }.is_err()
    {
        unsafe { stats().pointer_refusals += 1 };
        return ERROR_FAULT;
    }
    0
}

use platform::syscall_wall_clock;

/// Resolves a machine handle carrying `rights`. Every refusal is written to
/// the serial log with the caller's PID, so a host sees an attempt to end
/// the machine that the kernel refused.
unsafe fn machine_handle(current: usize, pid: u64, handle: u64, rights: u64) -> Result<(), i64> {
    let table = unsafe { table() };
    let result = match table.entries[current].handles.lookup(handle) {
        Ok(found) if found.object != Object::Machine => {
            Err(unsafe { handle_error(HandleError::Invalid) })
        }
        Ok(found) => found
            .require(rights as u8)
            .map_err(|error| unsafe { handle_error(error) }),
        Err(error) => Err(unsafe { handle_error(error) }),
    };
    if let Err(code) = result {
        serial::write("MACHINE REQUEST REFUSED pid=");
        serial::decimal(pid);
        serial::write(" error=");
        serial::signed(code as i32);
        serial::write("\n");
    }
    result
}

/// `machine_stop(handle, code)`: the abrupt stop at a named application
/// point. The authority is the machine handle's stop right, which init
/// holds and grants narrowly, never the boot mode.
unsafe fn syscall_machine_stop(current: usize, pid: u64, handle: u64, code: u64) -> i64 {
    if let Err(error) = unsafe { machine_handle(current, pid, handle, MACHINE_RIGHT_STOP) } {
        return error;
    }
    if !(STOP_CODE_MIN..=STOP_CODE_MAX).contains(&code) {
        return ERROR_INVALID;
    }
    serial::write("MACHINE STOP code=");
    serial::decimal(code);
    serial::write("\n");
    crate::exit_qemu(code as u32)
}

/// `machine_restart(handle)`: arms a reset for the end of the boot. The
/// kernel knows nothing of why: whoever holds the right decided.
unsafe fn syscall_machine_restart(current: usize, pid: u64, handle: u64) -> i64 {
    if let Err(error) = unsafe { machine_handle(current, pid, handle, MACHINE_RIGHT_RESTART) } {
        return error;
    }
    crate::suite::arm_restart();
    serial::write("MACHINE RESTART ARMED pid=");
    serial::decimal(pid);
    serial::write("\n");
    0
}

/// `machine_recover(handle)`: an immediate whole-machine reset. The
/// authority is the machine handle's recover right alone, never the PID or
/// the boot mode. Unlike `machine_restart` it skips the end-of-boot
/// accounting and makes no process-drain claim; it prints the census of
/// what the reset abandons.
unsafe fn syscall_machine_recover(current: usize, pid: u64, handle: u64) -> i64 {
    if let Err(error) = unsafe { machine_handle(current, pid, handle, MACHINE_RIGHT_RECOVER) } {
        return error;
    }
    let table = unsafe { table() };
    let handles: usize = table
        .entries
        .iter()
        .map(|entry| entry.handles.live_count())
        .sum();
    serial::write("SERVED RECOVERY CENSUS processes=");
    serial::decimal(table.occupied_count() as u64);
    serial::write(" handles=");
    serial::decimal(handles as u64);
    serial::write(" pipes=");
    serial::decimal(unsafe { pipes() }.live() as u64);
    serial::write(" cells=");
    serial::decimal(unsafe { cells() }.live() as u64);
    serial::write(" frames=");
    serial::decimal(unsafe { vm::frames() }.allocated_frames() as u64);
    serial::write("\n");
    for entry in &table.entries {
        if entry.state == ProcessState::Empty {
            continue;
        }
        serial::write("SERVED RECOVERY PROCESS pid=");
        serial::decimal(entry.pid);
        serial::write(" parent=");
        serial::decimal(entry.parent);
        serial::write(" state=");
        serial::write(match entry.state {
            ProcessState::Empty => "empty",
            ProcessState::Created => "created",
            ProcessState::Runnable => "runnable",
            ProcessState::Running => "running",
            ProcessState::Waiting => "waiting",
            ProcessState::Exited => "exited",
            ProcessState::Faulted => "faulted",
            ProcessState::Killed => "killed",
        });
        serial::write(" handles=");
        serial::decimal(entry.handles.live_count() as u64);
        serial::write(" cpu=");
        match entry.cpu_owner {
            Some(claim) => serial::decimal(u64::from(claim.cpu)),
            None => serial::write("none"),
        }
        serial::write("\n");
    }
    serial::write("MACHINE RECOVER RESET pid=");
    serial::decimal(pid);
    serial::write("\n");
    crate::machine_reset()
}
