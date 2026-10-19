//! The NIC calls (`absd_abi::nic`): frames move between user memory and the
//! driver's static buffers (`src/e1000.rs`); no user address reaches the
//! device. A receive that finds nothing waits on `WaitKind::Nic`, and the
//! timer path (`wake_nic_receivers`) completes it when a frame arrives.

use super::{WaitOutcome, handle_error};
use crate::nic_device as e1000;
use crate::sched::{deadline, stats, table};
use absd_kernel::arch::ExecutionState;
use absd_kernel::handle::{HandleError, Object, RIGHT_READ, RIGHT_WRITE};
use absd_kernel::nic::{NIC_FRAME_MAX, NIC_INFO_BYTES};
use absd_kernel::process::{AddressSpace, MAX_PROCESSES, ProcessState, TransferWait, WaitKind};
use absd_kernel::syscall::{
    ERROR_AGAIN, ERROR_FAULT, ERROR_INVALID, ERROR_IO, ERROR_NO_CARRIER, ERROR_TIMEOUT,
};
use absd_kernel::user_memory::{check_user_range, copy_from_user, copy_to_user};

/// Resolves a NIC handle carrying `rights`.
unsafe fn nic_handle(current: usize, handle: u64, rights: u8) -> Result<(), i64> {
    let found = unsafe { table() }.entries[current]
        .handles
        .lookup(handle)
        .map_err(|error| unsafe { handle_error(error) })?;
    if found.object != Object::Nic {
        return Err(unsafe { handle_error(HandleError::Invalid) });
    }
    found
        .require(rights)
        .map_err(|error| unsafe { handle_error(error) })
}

fn pointer_refused() -> i64 {
    unsafe { stats().pointer_refusals += 1 };
    ERROR_FAULT
}

/// `nic_info(handle, record)`.
pub(super) unsafe fn syscall_nic_info(current: usize, handle: u64, record: u64) -> i64 {
    if let Err(error) = unsafe { nic_handle(current, handle, RIGHT_READ) } {
        return error;
    }
    let Some(info) = e1000::info() else {
        return ERROR_IO;
    };
    let space = unsafe { table() }.entries[current].address_space;
    let bytes: [u8; NIC_INFO_BYTES] = info.to_bytes();
    if unsafe { copy_to_user(&space, record, &bytes) }.is_err() {
        return pointer_refused();
    }
    0
}

/// `nic_send(handle, frame, length)`.
pub(super) unsafe fn syscall_nic_send(current: usize, handle: u64, frame: u64, length: u64) -> i64 {
    if let Err(error) = unsafe { nic_handle(current, handle, RIGHT_WRITE) } {
        return error;
    }
    let space = unsafe { table() }.entries[current].address_space;
    let result = e1000::send(length, |buffer| unsafe {
        copy_from_user(&space, frame, buffer).is_ok()
    });
    match result {
        Ok(()) => 0,
        Err(e1000::SendError::Length) => ERROR_INVALID,
        Err(e1000::SendError::Copy) => pointer_refused(),
        Err(e1000::SendError::Disabled) => ERROR_IO,
        Err(e1000::SendError::NoCarrier) => ERROR_NO_CARRIER,
    }
}

/// Moves the next accepted frame into `address` of `space`: its length,
/// `None` when nothing is waiting, or `ERROR_IO` once the NIC is disabled.
unsafe fn deliver(space: &AddressSpace, address: u64) -> Option<i64> {
    match e1000::take_frame(|frame| unsafe { copy_to_user(space, address, frame) }.is_ok()) {
        Ok(Some(bytes)) => Some(bytes as i64),
        Ok(None) => None,
        Err(_) => Some(ERROR_IO),
    }
}

/// `nic_receive(handle, buffer, timeout)`.
pub(super) unsafe fn syscall_nic_receive(
    current: usize,
    handle: u64,
    address: u64,
    timeout: u64,
) -> WaitOutcome {
    if let Err(error) = unsafe { nic_handle(current, handle, RIGHT_READ) } {
        return WaitOutcome::Done(error);
    }
    // Once the NIC is disabled, every receive is `ERROR_IO`; the buffer
    // check must not outrank that (docs/NETWORK.md).
    if e1000::disabled() {
        return WaitOutcome::Done(ERROR_IO);
    }
    let table = unsafe { table() };
    let space = table.entries[current].address_space;
    // The whole maximum frame must be writable before anything is taken
    // off the ring, so a frame is never consumed and then lost.
    if unsafe { check_user_range(&space, address, NIC_FRAME_MAX, true) }.is_err() {
        return WaitOutcome::Done(pointer_refused());
    }
    if let Some(result) = unsafe { deliver(&space, address) } {
        return WaitOutcome::Done(result);
    }
    if timeout == 0 {
        return WaitOutcome::Done(ERROR_AGAIN);
    }
    let Some(wake_at) = deadline(timeout) else {
        return WaitOutcome::Done(ERROR_TIMEOUT);
    };
    let waiter = &mut table.entries[current];
    waiter.state = ProcessState::Waiting;
    waiter.wait_kind = WaitKind::Nic;
    waiter.wake_at = Some(wake_at);
    waiter.wait_transfer = Some(TransferWait {
        address,
        length: NIC_FRAME_MAX,
        write: false,
    });
    WaitOutcome::Blocked
}

/// Completes receives blocked on the NIC while frames are waiting. Called
/// from the scheduler and the idle loop on every tick; with no receiver
/// waiting it does not touch the device.
pub(crate) unsafe fn wake_nic_receivers() {
    let table = unsafe { table() };
    for index in 0..MAX_PROCESSES {
        let entry = &table.entries[index];
        if !entry.can_wake() || entry.wait_kind != WaitKind::Nic {
            continue;
        }
        let Some(wait) = entry.wait_transfer else {
            continue;
        };
        let space = entry.address_space;
        let Some(result) = (unsafe { deliver(&space, wait.address) }) else {
            return;
        };
        let entry = &mut table.entries[index];
        entry.clear_wait();
        entry.task.context.set_result(result);
        crate::sched::make_runnable(entry);
    }
}
