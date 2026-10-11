pub unsafe fn syscall3(number: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    let raw: i64;
    unsafe {
        core::arch::asm!("int 0x80", inout("rax") number => raw, in("rdi") a0,
        in("rsi") a1, in("rdx") a2, options(nostack, preserves_flags));
    }
    raw
}
pub fn halt_after_exit() {
    unsafe {
        core::arch::asm!("ud2", options(nomem, nostack));
    }
}
#[macro_export]
macro_rules! arch_entry {
    () => {
        ::core::arch::global_asm!(".globl _start", "_start:", "call __absd_main", "ud2");
    };
}
pub fn fp_state_probe(seed: u64) -> bool {
    let result: u64;
    unsafe {
        core::arch::asm!(
 "movq xmm0, rdi", "movq xmm7, rdi", "movq xmm15, rdi", "mov r8, 5",
 "2:", "mov rcx, 6000000", "3:", "pause", "dec rcx", "jnz 3b", "mov rax, 2", "int 0x80",
 "movq rdx, xmm0", "cmp rdx, rdi", "jne 4f", "movq rdx, xmm7", "cmp rdx, rdi", "jne 4f",
 "movq rdx, xmm15", "cmp rdx, rdi", "jne 4f", "dec r8", "jnz 2b", "mov rax,1", "jmp 5f", "4:", "xor rax,rax", "5:",
 in("rdi")seed,lateout("rax")result,out("rcx")_,out("rdx")_,out("r8")_,out("xmm0")_,out("xmm7")_,out("xmm15")_);
    }
    result == 1
}

pub fn probe_read(address: u64) {
    unsafe {
        core::arch::asm!("mov rax, [rdi]", in("rdi") address, out("rax") _, options(nostack));
    }
}
pub fn probe_write(address: u64) {
    unsafe {
        core::arch::asm!("mov qword ptr [rdi], 1", in("rdi") address, options(nostack));
    }
}
pub fn probe_execute(page: *mut u8) {
    unsafe {
        core::ptr::write(page, 0xc3);
        core::arch::asm!("call rdi", in("rdi") page, clobber_abi("C"));
    }
}
pub fn probe_undefined() {
    unsafe {
        core::arch::asm!("ud2", options(nomem, nostack));
    }
}
pub fn probe_alignment(page: *mut u8) {
    unsafe {
        core::arch::asm!("movaps xmm0, [rdi]", in("rdi") page, out("xmm0") _, options(nostack));
    }
}
pub fn probe_stack(address: u64) {
    unsafe {
        core::arch::asm!("mov r10, rsp", "mov rsp, rdi", "mov qword ptr [rsp], 1", "mov rsp, r10", in("rdi") address, out("r10") _);
    }
}
