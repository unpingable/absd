//! Grows through every reserved stack page, then faults on the permanent
//! guard page immediately below the maximum stack region.
#![no_std]
#![no_main]

use absd_user::Start;

absd_user::entry!(main);

fn main(start: Start) -> i32 {
    let console = start.console;
    let _ = console.write_str("user-overflow: descending into stack guard\n");
    unsafe {
        core::arch::asm!(
            "2:",
            "sub rsp, 4096",
            "mov qword ptr [rsp], 0",
            "jmp 2b",
            options(noreturn),
        );
    }
}
