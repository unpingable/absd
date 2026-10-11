use crate::cpu;
use crate::sched::table;
use absd_kernel::process::{Process, SAVED_FRAME_WORDS};
use core::arch::asm;
unsafe extern "C" {
    #[link_name = "resume_user_context"]
    fn bsp_resume_user_context(frame: *const u64, root: u64, kernel_stack_top: u64) -> !;
    #[link_name = "enter_cpu_switch"]
    fn bsp_enter_cpu_switch() -> !;
    #[link_name = "enter_kernel_context_and_reap"]
    fn bsp_enter_kernel_context_and_reap() -> !;
    static boot_pml4: u8;
}

pub(crate) unsafe fn resume_user_context(frame: *const u64, root: u64, top: u64) -> ! {
    unsafe {
        if cpu::id() > 0 {
            crate::smp_user::ap_resume_user_context(frame, root, top)
        } else {
            bsp_resume_user_context(frame, root, top)
        }
    }
}
pub(crate) unsafe fn enter_cpu_switch() -> ! {
    unsafe {
        if cpu::id() > 0 {
            crate::smp_user::ap_enter_cpu_switch()
        } else {
            bsp_enter_cpu_switch()
        }
    }
}
pub(crate) unsafe fn enter_kernel_context_and_reap() -> ! {
    unsafe {
        if cpu::id() > 0 {
            crate::smp_user::ap_enter_kernel_context_and_reap()
        } else {
            bsp_enter_kernel_context_and_reap()
        }
    }
}
pub(crate) unsafe fn save_frame(process: &mut Process, frame: *const u64) {
    for word in 0..SAVED_FRAME_WORDS {
        process.task.context[word] = unsafe { core::ptr::read_volatile(frame.add(word)) };
    }
    process.task.fpu = unsafe { core::ptr::read_volatile(cpu::user_fpu()) };
    process.task.context_valid = true;
}

pub(crate) unsafe fn assert_departed(index: usize) {
    let process = unsafe { &table().entries[index] };
    let rsp: u64;
    let cr3: u64;
    unsafe {
        asm!("mov {}, rsp", out(reg) rsp, options(nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
    }
    let tss_rsp0 = cpu::tss_rsp0();
    let base = process.task.kernel_stack_base;
    let top = process.task.kernel_stack_top;
    assert!(base != 0 && top > base, "outgoing task has no kernel stack");
    assert!(
        cpu::on_cpu_stack(rsp),
        "handoff is not on a CPU-owned stack"
    );
    assert!(rsp < base || rsp >= top, "CPU still uses outgoing stack");
    assert!(
        tss_rsp0 < base || tss_rsp0 > top,
        "TSS still names outgoing stack"
    );
    assert_eq!(
        tss_rsp0,
        cpu::entry_stack_top(),
        "TSS is not on CPU entry stack"
    );
    assert_ne!(
        cr3, process.address_space.root,
        "CPU still loads outgoing CR3"
    );
    assert_eq!(cr3, core::ptr::addr_of!(boot_pml4) as u64);
}

pub(crate) fn fresh_fpu(_task: &mut absd_kernel::process::Task) {
    // Negative control for the fpu-test witness: a fresh process starts
    // with non-default control state (round toward zero, FTZ, FCW 0x27f).
    #[cfg(absd_mutant_fresh_fpu_dirty)]
    {
        _task.fpu.0[0] = 0x7f;
        _task.fpu.0[1] = 0x02;
        _task.fpu.0[24] = 0x80;
        _task.fpu.0[25] = 0xff;
    }
}

pub(crate) const FAULT_FRAME_BYTES: u64 = 21 * 8;
pub(crate) fn kernel_table() -> u64 {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(boot_pml4).cast::<u64>())
            & crate::vm::ADDRESS_MASK
    }
}
pub(crate) fn initial_context(entry: u64, stack: u64) -> absd_kernel::arch::ExecutionContext {
    let mut c = [0; 20];
    c[15] = entry;
    c[16] = absd_kernel::arch::USER_CODE_SELECTOR;
    c[17] = 0x202;
    c[18] = stack;
    c[19] = absd_kernel::arch::USER_DATA_SELECTOR;
    c
}
pub(crate) fn fault_address(vector: u64, pc: u64) -> u64 {
    if vector != absd_kernel::syscall::VECTOR_PAGE_FAULT {
        return pc;
    }
    let address: u64;
    unsafe {
        asm!("mov {}, cr2",out(reg)address,options(nostack,preserves_flags));
    }
    address
}
pub(crate) unsafe fn syscall_number(frame: *const u64) -> u64 {
    unsafe { core::ptr::read_volatile(frame.add(14)) }
}
pub(crate) unsafe fn frame_arguments(frame: *const u64) -> [u64; 3] {
    unsafe {
        [
            core::ptr::read_volatile(frame.add(10)),
            core::ptr::read_volatile(frame.add(11)),
            core::ptr::read_volatile(frame.add(12)),
        ]
    }
}
pub(crate) unsafe fn set_frame_result(frame: *mut u64, value: i64) {
    unsafe {
        core::ptr::write_volatile(frame.add(14), value as u64);
    }
}

pub(crate) fn sync_executable(_: &absd_kernel::process::AddressSpace, _: &absd_kernel::elf::Image) {
}

pub(crate) fn owns_fault_frame(frame: u64, process: &Process) -> bool {
    frame >= process.task.kernel_stack_base
        && frame
            .checked_add(FAULT_FRAME_BYTES)
            .is_some_and(|end| end <= process.task.kernel_stack_top)
}
