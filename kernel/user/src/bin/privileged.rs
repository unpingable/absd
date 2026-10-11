//! Executes a privileged instruction from ring 3; the kernel must report
//! `#GP` (vector 13) to the parent rather than honour or escalate it.
#![no_std]
#![no_main]

use absd_user::Start;

absd_user::entry!(main);

fn main(start: Start) -> i32 {
    let console = start.console;
    let _ = console.write_str("user-privileged: executing hlt\n");
    unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    95
}
