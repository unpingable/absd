//! A real workload that descends ten pages, crossing below the old eight-page
//! stack ceiling, then restores RSP and returns normally.
#![no_std]
#![no_main]

use absd_user::Start;

absd_user::entry!(main);

#[inline(never)]
fn cross_growth_boundaries() -> (u64, u64, u64) {
    let deepest: u64;
    let gpr_seen: u64;
    let xmm_seen: u64;
    unsafe {
        core::arch::asm!(
            "mov r11, rsp",
            "mov r10, 0x13579bdf2468ace0",
            "mov r9, 0xfedcba9876543210",
            "movq xmm15, r9",
            "mov ecx, 10",
            "2:",
            "sub rsp, 4096",
            "mov qword ptr [rsp], rcx",
            "loop 2b",
            "mov {deepest}, rsp",
            "mov {gpr_seen}, r10",
            "movq {xmm_seen}, xmm15",
            "mov rsp, r11",
            deepest = lateout(reg) deepest,
            gpr_seen = lateout(reg) gpr_seen,
            xmm_seen = lateout(reg) xmm_seen,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
            lateout("rcx") _,
            lateout("xmm15") _,
        );
    }
    (deepest, gpr_seen, xmm_seen)
}

fn main(start: Start) -> i32 {
    let before: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) before, options(nomem, preserves_flags));
    }
    let (deepest, gpr_seen, xmm_seen) = cross_growth_boundaries();
    if before.saturating_sub(deepest) < 10 * 4096
        || gpr_seen != 0x1357_9bdf_2468_ace0
        || xmm_seen != 0xfedc_ba98_7654_3210
    {
        return 86;
    }
    let _ = start.console.write_str("USER STACK GROW OK\n");
    0
}
