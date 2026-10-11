//! Writes a supervisor-only address; the kernel must terminate only this
//! process and report a present/write/user page fault to the parent.
#![no_std]
#![no_main]

use absd_user::Start;

absd_user::entry!(main);

fn main(start: Start) -> i32 {
    let console = start.console;
    let _ = console.write_str("user-fault: requesting isolated fault\n");
    unsafe { core::ptr::write_volatile(0x10_0000 as *mut u64, 1) };
    98
}
