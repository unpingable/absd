//! Executes an undefined instruction; the kernel must report `#UD` (vector 6)
//! to the parent and reclaim this process without touching anything else.
#![no_std]
#![no_main]

use absd_user::Start;

absd_user::entry!(main);

fn main(start: Start) -> i32 {
    let console = start.console;
    let _ = console.write_str("user-trap: executing ud2\n");
    unsafe { core::arch::asm!("ud2", options(nomem, nostack)) };
    96
}
