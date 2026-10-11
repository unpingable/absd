//! One bounded request/reconciliation subject. The only inherited service
//! authority is one explicit cell handle; generation, request, and mode are
//! immutable startup data supplied by the userspace supervisor.
#![no_std]
#![no_main]

use absd_user::{Cell, Error, Start, getpid, program};
use core::arch::asm;

absd_user::entry!(main);

fn intentional_fault() -> ! {
    unsafe { asm!("ud2", options(noreturn, nostack)) }
}

fn main(start: Start) -> i32 {
    if start.handle == 0 {
        return 90;
    }
    let mode = start.arg >> program::RECOVERY_MODE_SHIFT;
    let generation =
        (start.arg >> program::RECOVERY_GENERATION_SHIFT) & program::RECOVERY_GENERATION_MASK;
    let request = start.arg & program::RECOVERY_REQUEST_MASK;
    if generation == 0 || request == 0 {
        return 91;
    }
    let pid = getpid();
    let _ = absd_user::cprintln!(
        start.console,
        "SERVICE START service=test generation={} pid={} request={}",
        generation,
        pid,
        request
    );
    let cell = Cell::from_raw(start.handle);
    match mode {
        program::RECOVERY_MODE_FAULT_BEFORE => intentional_fault(),
        program::RECOVERY_MODE_APPLY_THEN_FAULT => {
            if cell.read() != Ok((0, 0)) || cell.transition(0, request) != Ok(1) {
                return 92;
            }
            intentional_fault()
        }
        program::RECOVERY_MODE_RECONCILE => {
            // Applied(request) is authoritative. Retrying expected version
            // zero must be stale and must not apply the request twice.
            if cell.read() != Ok((1, request))
                || cell.transition(0, request) != Err(Error::Stale)
                || cell.read() != Ok((1, request))
            {
                return 93;
            }
            0
        }
        program::RECOVERY_MODE_NORMAL => {
            if cell.read() != Ok((0, 0)) || cell.transition(0, request) != Ok(1) {
                return 94;
            }
            0
        }
        _ => 95,
    }
}
