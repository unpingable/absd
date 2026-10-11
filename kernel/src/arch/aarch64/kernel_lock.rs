//! Same Release/Acquire ownership primitive as x86, with EL1 CPU identity.
use absd_kernel::{
    owner_lock::{FREE, OwnerLock},
    process::CpuClaim,
};
use core::sync::atomic::{AtomicBool, Ordering};
pub const BSP: u8 = 0;
static ACTIVE: AtomicBool = AtomicBool::new(false);
static OWNER: OwnerLock = OwnerLock::new();
pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}
pub fn activate() {
    assert_eq!(crate::cpu::id(), BSP);
    OWNER.initialize(BSP);
    ACTIVE.store(true, Ordering::Release);
}
pub fn acquire(cpu: u8) {
    crate::debug_assert_interrupts_disabled();
    assert_eq!(cpu, crate::cpu::id());
    if !active() {
        assert_eq!(cpu, BSP);
        return;
    }
    assert_ne!(OWNER.load(Ordering::Relaxed), cpu, "recursive kernel lock");
    while OWNER.try_acquire(cpu).is_err() {
        core::hint::spin_loop();
    }
}
pub fn release(cpu: u8) {
    assert_eq!(cpu, crate::cpu::id());
    if active() {
        OWNER.release(cpu);
    } else {
        assert_eq!(cpu, BSP);
    }
}
pub fn assert_current_owner() {
    crate::debug_assert_interrupts_disabled();
    assert_held(crate::cpu::id());
}
pub fn assert_held(cpu: u8) {
    assert_eq!(cpu, crate::cpu::id());
    if active() {
        assert_eq!(
            OWNER.load(Ordering::Acquire),
            cpu,
            "kernel serialization absent"
        );
    } else {
        assert_eq!(cpu, BSP);
    }
}
pub fn signal_remote_stop(slot: usize, pid: u64, claim: CpuClaim) {
    crate::smp::signal_stop(slot, pid, claim);
}
pub fn idle_wait() {
    crate::smp::idle_wait();
}
#[unsafe(no_mangle)]
pub extern "C" fn arm_kernel_leave() {
    release(crate::cpu::id());
}
pub fn owner() -> Option<u8> {
    let v = OWNER.load(Ordering::Acquire);
    if v == FREE { None } else { Some(v) }
}
