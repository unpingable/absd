//! Yields once, then burns time so preemption can be observed.
#![no_std]
#![no_main]

use absd_user::{Error, Start, yield_now};

absd_user::entry!(main);

fn main(start: Start) -> i32 {
    let console = start.console;
    if start.arg == 1 {
        return match console.read_once(&mut [0u8; 1]) {
            Err(Error::Rights) => 0,
            _ => 85,
        };
    }
    let _ = console.write_str("user-B: hello from ELF userspace\n");
    yield_now();
    for _ in 0..2_000_000u32 {
        unsafe { core::arch::asm!("pause", options(nomem, nostack)) };
    }
    0
}
