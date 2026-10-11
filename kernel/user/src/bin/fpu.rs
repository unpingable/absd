//! Keeps two PID-derived patterns in XMM registers across hundreds of yields
//! and timer preemptions while another instance does the same with different
//! patterns. Any switch that fails to save and restore SSE state is caught.
//! The loop lives in one asm block so the compiler cannot touch XMM0/XMM7.
#![no_std]
#![no_main]

use absd_abi::syscall::SYS_YIELD;
use absd_user::{Start, getpid};

absd_user::entry!(main);

fn main(start: Start) -> i32 {
    let console = start.console;
    let pattern = getpid().wrapping_mul(0x0101_0101_0101_0101);
    let corrupted: u64;
    unsafe {
        core::arch::asm!(
            "movq xmm0, {pattern}",
            "mov rax, {pattern}",
            "not rax",
            "movq xmm7, rax",
            "mov r14, 200",
            "2:",
            "mov rax, {yield_nr}",
            "int 0x80",
            "mov ecx, 20000",
            "3:",
            "pause",
            "loop 3b",
            "movq rax, xmm0",
            "cmp rax, {pattern}",
            "jne 4f",
            "movq rax, xmm7",
            "mov rdx, {pattern}",
            "not rdx",
            "cmp rax, rdx",
            "jne 4f",
            "dec r14",
            "jnz 2b",
            "xor {corrupted:e}, {corrupted:e}",
            "jmp 5f",
            "4:",
            "mov {corrupted:e}, 1",
            "5:",
            pattern = in(reg) pattern,
            yield_nr = const SYS_YIELD,
            corrupted = out(reg) corrupted,
            out("rax") _, out("rcx") _, out("rdx") _, out("r14") _,
            out("xmm0") _, out("xmm7") _,
            options(nostack),
        );
    }
    if corrupted != 0 {
        let _ = console.write_str("user-fpu: XMM STATE CORRUPTED\n");
        return 97;
    }
    let _ = console.write_str("user-fpu: xmm state preserved\n");
    0
}
