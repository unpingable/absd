pub unsafe fn syscall3(number: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    let raw: u64;
    unsafe {
        core::arch::asm!("svc #0", in("x8") number, inout("x0") a0 => raw,
        in("x1") a1, in("x2") a2, options(nostack));
    }
    raw as i64
}
pub fn halt_after_exit() {
    unsafe {
        core::arch::asm!("brk #0", options(nomem, nostack));
    }
}
#[macro_export]
macro_rules! arch_entry {
    () => {
        ::core::arch::global_asm!(".globl _start", "_start:", "bl __absd_main", "brk #0");
    };
}
pub fn fp_state_probe(seed: u64) -> bool {
    let result: u64;
    unsafe {
        core::arch::asm!(
 "mrs x17, fpcr", "and x5, x4, #3", "lsl x5, x5, #22", "msr fpcr, x5",
 "dup v0.2d, x4", "dup v7.2d, x4", "dup v31.2d, x4", "mov x6, #5",
 "2:", "mov x7, #60000", "movk x7, #90, lsl #16",
 "3:", "subs x7, x7, #1", "b.ne 3b", "mov x8, #2", "svc #0",
 "umov x9, v0.d[0]", "cmp x9, x4", "b.ne 4f",
 "umov x9, v7.d[1]", "cmp x9, x4", "b.ne 4f",
 "umov x9, v31.d[0]", "cmp x9, x4", "b.ne 4f",
 "mrs x9, fpcr", "cmp x9, x5", "b.ne 4f", "subs x6, x6, #1", "b.ne 2b",
 "mov x0, #1", "b 5f", "4:", "mov x0, #0", "5:", "msr fpcr, x17",
 in("x4")seed,lateout("x0")result,out("x5")_,out("x6")_,out("x7")_,out("x8")_,out("x9")_,out("x17")_,out("v0")_,out("v7")_,out("v31")_);
    }
    result == 1
}

pub fn probe_read(address: u64) {
    unsafe {
        core::arch::asm!("ldr x9, [x0]", in("x0") address, out("x9") _, options(nostack));
    }
}
pub fn probe_write(address: u64) {
    unsafe {
        core::arch::asm!("mov x9, #1", "str x9, [x0]", in("x0") address, out("x9") _, options(nostack));
    }
}
pub fn probe_execute(page: *mut u8) {
    unsafe {
        core::ptr::write_unaligned(page.cast::<u32>(), 0xd65f03c0);
        core::arch::asm!("blr x0", in("x0") page, clobber_abi("C"));
    }
}
pub fn probe_undefined() {
    unsafe {
        core::arch::asm!(".inst 0x00000000", options(nomem, nostack));
    }
}
pub fn probe_alignment(page: *mut u8) {
    unsafe {
        core::arch::asm!("ldxr x9, [x0]", in("x0") page, out("x9") _, options(nostack));
    }
}
pub fn probe_stack(address: u64) {
    unsafe {
        core::arch::asm!("mov x10, sp", "mov sp, x0", "mov x9, #1", "str x9, [sp]", "mov sp, x10", in("x0") address, out("x9") _, out("x10") _);
    }
}
