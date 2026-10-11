//! Tries to skip the sole stack-growth candidate without moving RSP. The
//! kernel must isolate this as an ordinary page fault, not demand-map it.
#![no_std]
#![no_main]

use absd_abi::layout::USER_STACK_TOP;
use absd_user::Start;

absd_user::entry!(main);

fn main(_start: Start) -> i32 {
    // Initially only the top two pages are mapped. This target is two
    // more pages below that bottom, leaving the adjacent candidate untouched.
    const TARGET: u64 = USER_STACK_TOP - 4 * 4096;
    unsafe {
        core::ptr::write_volatile(TARGET as *mut u64, 0xabad_1dea);
    }
    85
}
