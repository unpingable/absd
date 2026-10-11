//! Maps a page, unmaps it, then touches it: the kernel must report a
//! not-present user page fault at exactly that address.
#![no_std]
#![no_main]

use absd_user::{Start, map, unmap};

absd_user::entry!(main);

fn main(start: Start) -> i32 {
    let console = start.console;
    let Ok(page) = map(1) else {
        return 93;
    };
    unsafe { core::ptr::write_volatile(page, 1) };
    if unmap(page, 1).is_err() {
        return 93;
    }
    let _ = console.write_str("user-unmapped: touching an unmapped page\n");
    let _ = unsafe { core::ptr::read_volatile(page) };
    92
}
