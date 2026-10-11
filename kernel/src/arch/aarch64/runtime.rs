use absd_kernel::arch::{ExecutionContext, ExecutionState};
use absd_kernel::process::Process;
use core::arch::asm;
pub(crate) const FAULT_FRAME_BYTES: u64 = 800;
pub(crate) fn kernel_table() -> u64 {
    unsafe { crate::KERNEL_TABLE }
}
pub(crate) fn initial_context(entry: u64, stack: u64) -> ExecutionContext {
    ExecutionContext::entry(entry, stack, [0; 5])
}
pub(crate) fn fresh_fpu(_: &mut absd_kernel::process::Task) {}
pub(crate) unsafe fn syscall_number(frame: *const u64) -> u64 {
    unsafe { (*(frame.cast::<ExecutionContext>())).syscall().0 }
}
pub(crate) unsafe fn frame_arguments(frame: *const u64) -> [u64; 3] {
    unsafe { (*(frame.cast::<ExecutionContext>())).syscall().1 }
}
pub(crate) unsafe fn set_frame_result(frame: *mut u64, value: i64) {
    unsafe {
        (*(frame.cast::<ExecutionContext>())).set_result(value);
    }
}
pub(crate) unsafe fn save_frame(p: &mut Process, frame: *const u64) {
    unsafe {
        p.task.context = core::ptr::read(frame.cast());
        p.task.fpu = core::ptr::read(frame.cast::<u8>().add(272).cast());
        p.task.context_valid = true;
    }
}
pub(crate) unsafe fn resume_user_context(frame: *const u64, root: u64, top: u64) -> ! {
    unsafe { crate::arm_enter(frame.cast(), crate::cpu::user_fpu(), top, root) }
}
pub(crate) unsafe fn enter_cpu_switch() -> ! {
    unsafe { crate::arm_depart(crate::BOOT_ROOT, crate::sched::commit_cpu_switch) }
}
pub(crate) unsafe fn enter_kernel_context_and_reap() -> ! {
    unsafe { crate::arm_depart(crate::BOOT_ROOT, crate::sched::reap_current_and_schedule) }
}
pub(crate) unsafe fn assert_departed(index: usize) {
    unsafe {
        let p = &crate::sched::table().entries[index];
        let sp: u64;
        let root: u64;
        asm!("mov {}, sp",out(reg)sp);
        asm!("mrs {}, ttbr0_el1",out(reg)root);
        assert!(
            sp < p.task.kernel_stack_base || sp >= p.task.kernel_stack_top,
            "CPU uses outgoing task stack"
        );
        let boot_root = crate::BOOT_ROOT;
        assert_eq!(root, boot_root, "CPU uses outgoing root");
        assert_ne!(root, p.address_space.root);
        assert!(
            crate::cpu::on_cpu_stack(sp),
            "departure outside CPU-owned stack"
        );
    }
}
pub(crate) fn fault_address(_: u64, pc: u64) -> u64 {
    let esr: u64;
    let address: u64;
    unsafe {
        asm!("mrs {}, esr_el1",out(reg)esr);
        asm!("mrs {}, far_el1",out(reg)address);
    }
    if matches!(esr >> 26, 0x20 | 0x24) {
        address
    } else {
        pc
    }
}

pub(crate) fn sync_executable(
    space: &absd_kernel::process::AddressSpace,
    image: &absd_kernel::elf::Image,
) {
    unsafe {
        let ctr: u64;
        asm!("mrs {}, ctr_el0",out(reg)ctr);
        let line = 4u64 << ((ctr >> 16) & 15);
        for segment in &image.segments[..image.segment_count] {
            for va in (segment.virtual_address & !4095
                ..(segment.virtual_address + segment.memory_size as u64 + 4095) & !4095)
                .step_by(4096)
            {
                let physical = crate::vm::translate(space, va).unwrap();
                for at in (physical..physical + 4096).step_by(line as usize) {
                    asm!("dc cvau, {}",in(reg)at);
                }
            }
        }
        asm!("dsb ish", "ic ialluis", "dsb ish", "isb");
    }
}

pub(crate) fn owns_fault_frame(frame: u64, process: &Process) -> bool {
    // arm_enter sets SP_EL1 to this task stack; departure uses a CPU stack.
    frame >= process.task.kernel_stack_base
        && frame
            .checked_add(FAULT_FRAME_BYTES)
            .is_some_and(|end| end <= process.task.kernel_stack_top)
}
