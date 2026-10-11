//! EL1-owned per-CPU storage. Userspace cannot change TPIDR_EL1.
use absd_kernel::arch::FpuState;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::{arch::asm, mem::offset_of};
pub const MAX_CPUS: usize = 4;
pub const NO_TASK: usize = usize::MAX;
pub const STACK_BYTES: usize = 65536;
#[repr(C, align(4096))]
pub struct CpuLocal {
    current: usize,
    preempt: bool,
    fp: FpuState,
    fault: (u64, u64, u64),
    entry_stack: [u8; STACK_BYTES],
    transition_stack: [u8; STACK_BYTES],
}
impl CpuLocal {
    const EMPTY: Self = Self {
        current: NO_TASK,
        preempt: false,
        fp: FpuState::INITIAL,
        fault: (0, 0, 0),
        entry_stack: [0; STACK_BYTES],
        transition_stack: [0; STACK_BYTES],
    };
}
#[unsafe(no_mangle)]
pub static mut ARM_CPU_LOCAL: [CpuLocal; MAX_CPUS] = [const { CpuLocal::EMPTY }; MAX_CPUS];
pub const LOCAL_BYTES: usize = core::mem::size_of::<CpuLocal>();
pub const ENTRY_TOP: usize = offset_of!(CpuLocal, entry_stack) + STACK_BYTES;
pub const TRANSITION_TOP: usize = offset_of!(CpuLocal, transition_stack) + STACK_BYTES;
static COUNT: AtomicUsize = AtomicUsize::new(1);
pub fn configure(n: usize) {
    assert!(matches!(n, 1 | 2 | 4));
    COUNT.store(n, Ordering::Release);
}
pub fn count() -> usize {
    COUNT.load(Ordering::Acquire)
}
pub fn id() -> u8 {
    let v: u64;
    unsafe {
        asm!("mrs {}, mpidr_el1",out(reg)v,options(nostack));
    }
    let id = (v & 0xff) as u8;
    assert!((id as usize) < count());
    id
}
fn local() -> *mut CpuLocal {
    let p: u64;
    unsafe {
        asm!("mrs {}, tpidr_el1",out(reg)p,options(nostack));
    }
    let expected = unsafe {
        core::ptr::addr_of_mut!(ARM_CPU_LOCAL)
            .cast::<CpuLocal>()
            .add(id() as usize)
    };
    assert_eq!(p, expected as u64, "CPU affinity/storage identity mismatch");
    expected
}
pub fn is_bootstrap_processor() -> bool {
    id() == 0
}
pub fn refuse_application_processor() -> ! {
    panic!("ARM AP userspace refused outside qualification gate")
}
pub fn current() -> usize {
    unsafe { (*local()).current }
}
pub fn set_current(v: usize) {
    unsafe {
        (*local()).current = v;
    }
}
pub fn set_pending_preempt(v: bool) {
    unsafe {
        (*local()).preempt = v;
    }
}
pub fn take_pending_preempt() -> bool {
    unsafe {
        let p = local();
        let v = (*p).preempt;
        (*p).preempt = false;
        v
    }
}
pub fn user_fpu() -> *mut FpuState {
    unsafe { core::ptr::addr_of_mut!((*local()).fp) }
}
pub fn set_fault(v: (u64, u64, u64)) {
    unsafe {
        (*local()).fault = v;
    }
}
pub fn fault() -> (u64, u64, u64) {
    unsafe { (*local()).fault }
}
pub fn on_cpu_stack(sp: u64) -> bool {
    let base = local() as u64;
    [
        (ENTRY_TOP - STACK_BYTES, ENTRY_TOP),
        (TRANSITION_TOP - STACK_BYTES, TRANSITION_TOP),
    ]
    .iter()
    .any(|(lo, hi)| sp >= base + *lo as u64 && sp < base + *hi as u64)
}
