//! Checks that BSS arrives zero-filled (also on reused frames) and exits 7.
#![no_std]
#![no_main]

use absd_user::Start;

absd_user::entry!(main);

static mut ZERO_FILL: u64 = 0;

fn main(start: Start) -> i32 {
    let console = start.console;
    if unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ZERO_FILL)) } != 0 {
        return 99;
    }
    let _ = console.write_str("user-exit7: exiting nonzero\n");
    7
}
