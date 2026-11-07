//! Bounded readiness entry and wake path. All callers hold the BKL.
use super::*;
use absd_kernel::readable_wait::{self, MAX_HANDLES, ReadWait};

pub(super) unsafe fn call(current: usize, address: u64, count: u64, timeout: u64) -> WaitOutcome {
    crate::kernel_lock::assert_current_owner();
    if count == 0 || count > MAX_HANDLES as u64 {
        return WaitOutcome::Done(ERROR_INVALID);
    }
    let count = count as usize;
    let space = unsafe { table() }.entries[current].address_space;
    let mut bytes = [0u8; MAX_HANDLES * 8];
    if unsafe { copy_from_user(&space, address, &mut bytes[..count * 8]) }.is_err() {
        unsafe {
            stats().pointer_refusals += 1;
        }
        return WaitOutcome::Done(ERROR_FAULT);
    }
    let mut handles = [0; MAX_HANDLES];
    for (index, word) in bytes[..count * 8].as_chunks::<8>().0.iter().enumerate() {
        handles[index] = u64::from_le_bytes(*word);
    }
    let wait = match ReadWait::capture(&handles[..count], timeout, now()) {
        Ok(wait) => wait,
        Err(error) => return WaitOutcome::Done(error),
    };
    // The lock remains held across the level check and wait publication.
    // Console IRQ arrival publishes its atomic level; its wake scan must
    // acquire this same lock, so arrival cannot fall through that boundary.
    let process = &mut unsafe { table() }.entries[current];
    match wait.register(process, unsafe { pipes() }, serial::input_readable()) {
        Ok(Some(mask)) => WaitOutcome::Done(mask as i64),
        Ok(None) => WaitOutcome::Blocked,
        Err(error) => WaitOutcome::Done(error),
    }
}

pub(crate) unsafe fn wake_readable_waiters() {
    crate::kernel_lock::assert_current_owner();
    let console_ready = serial::input_readable();
    let table = unsafe { table() };
    for process in &mut table.entries {
        let Some(result) = readable_wait::completion(process, unsafe { pipes() }, console_ready)
        else {
            continue;
        };
        process.clear_wait();
        process.task.context.set_result(result);
        crate::sched::make_runnable(process);
    }
}
