//! A deliberately tiny supervision subject. Transition instances receive only
//! write authority; stop-test instances receive only read/wait authority. No
//! process handle or process-local state survives replacement.
#![no_std]
#![no_main]

use absd_user::{Cell, Error, Start, getpid, program, sleep};
use core::arch::asm;

absd_user::entry!(main);

fn intentional_fault() -> ! {
    // Invalid opcode is deterministic and carries no architecture error code.
    unsafe { asm!("ud2", options(noreturn, nostack)) }
}

fn main(start: Start) -> i32 {
    if start.handle == 0 {
        return 90;
    }
    let cell = Cell::from_raw(start.handle);
    let mode = start.arg >> program::SUPERVISED_MODE_SHIFT;
    let generation = start.arg & program::SUPERVISED_GENERATION_MASK;
    if generation == 0 {
        return 98;
    }
    let pid = getpid();
    let _ = absd_user::cprintln!(
        start.console,
        "WORKER START generation={} pid={}",
        generation,
        pid
    );
    match mode {
        program::SUPERVISED_MODE_TRANSITION => {
            // The supervisor deliberately withheld observation authority. The
            // worker may attempt only these two recovery-state transitions.
            if cell.read() != Err(Error::Rights) {
                return 91;
            }
            match cell.transition(0, 1) {
                Ok(1) => intentional_fault(),
                Err(Error::Stale) => match cell.transition(1, 2) {
                    Ok(2) => 0,
                    Err(Error::Stale) => intentional_fault(),
                    _ => 92,
                },
                _ => 92,
            }
        }
        program::SUPERVISED_MODE_GRACEFUL_STOP => {
            if cell.transition(0, 0) != Err(Error::Rights) {
                return 93;
            }
            let stopped = match cell.read() {
                Ok((1, program::SUPERVISED_STOP_VALUE)) => true,
                Ok((0, _)) => {
                    cell.wait_change_timeout(0, 1_000) == Ok(1)
                        && cell.read() == Ok((1, program::SUPERVISED_STOP_VALUE))
                }
                _ => false,
            };
            if !stopped {
                return 94;
            }
            let _ = absd_user::cprintln!(
                start.console,
                "WORKER STOP generation={} pid={}",
                generation,
                pid
            );
            0
        }
        program::SUPERVISED_MODE_STUCK => {
            if cell.transition(0, 0) != Err(Error::Rights) {
                return 95;
            }
            sleep(u64::MAX);
            96
        }
        _ => 97,
    }
}
