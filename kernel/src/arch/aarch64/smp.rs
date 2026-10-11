//! Mechanisms for the explicit ARM SMP qualification gate. Policy stays shared.
use absd_kernel::{
    arch::ExecutionState,
    process::{CpuClaim, MAX_PROCESSES, Process, StopState},
};
use core::{
    arch::asm,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
const MAX: usize = crate::cpu::MAX_CPUS;
static ENABLED: AtomicBool = AtomicBool::new(false);
static ROOT: AtomicU64 = AtomicU64::new(0);
static READY: AtomicBool = AtomicBool::new(false);
static RUN: AtomicBool = AtomicBool::new(false);
static HALT: AtomicBool = AtomicBool::new(false);
static ONLINE: [AtomicBool; MAX] = [const { AtomicBool::new(false) }; MAX];
static PARKED: [AtomicBool; MAX] = [const { AtomicBool::new(false) }; MAX];
static TIMERS: [AtomicU64; MAX] = [const { AtomicU64::new(0) }; MAX];
static IPIS: [AtomicU64; MAX] = [const { AtomicU64::new(0) }; MAX];
static REQUEST: [AtomicBool; MAX] = [const { AtomicBool::new(false) }; MAX];
static STOP_SLOT: [AtomicU64; MAX] = [const { AtomicU64::new(0) }; MAX];
static STOP_PID: [AtomicU64; MAX] = [const { AtomicU64::new(0) }; MAX];
static STOP_EPOCH: [AtomicU64; MAX] = [const { AtomicU64::new(0) }; MAX];
static mut ROLES: [u64; MAX_PROCESSES] = [0; MAX_PROCESSES];
static mut LAST_PID: [u64; MAX_PROCESSES] = [0; MAX_PROCESSES];
static mut LAST_CPU: [u8; MAX_PROCESSES] = [0; MAX_PROCESSES];
static mut DISPATCHES: [u64; MAX] = [0; MAX];
static mut MIGRATIONS: [u64; 2] = [0; 2];
static mut STOPS: u64 = 0;
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}
pub fn configure(board: &super::fdt::Board) {
    if board.smp_request == 0 {
        assert_eq!(
            board.cpu_count, 1,
            "extra CPUs require explicit SMP qualification request"
        );
        return;
    }
    if !cfg!(feature = "arm64-smp-qualification") {
        panic!("ARM SMP feature absent");
    }
    assert_eq!(
        board.smp_request, board.cpu_count,
        "SMP topology/request mismatch"
    );
    crate::cpu::configure(board.cpu_count);
    ENABLED.store(true, Ordering::Release);
}
unsafe extern "C" {
    fn arm_secondary_entry();
}
pub fn bring_up() {
    if !enabled() {
        return;
    }
    crate::kernel_lock::activate();
    ROOT.store(unsafe { crate::BOOT_ROOT }, Ordering::Release);
    READY.store(true, Ordering::Release);
    unsafe {
        asm!("dc cvac, {}","dc cvac, {}","dsb sy",in(reg)core::ptr::addr_of!(ROOT),in(reg)core::ptr::addr_of!(READY));
    }
    ONLINE[0].store(true, Ordering::Release);
    for cpu in 1..crate::cpu::count() {
        let result: u64;
        unsafe {
            asm!("hvc #0",inlateout("x0")0xc4000003u64=>result,in("x1")cpu as u64,in("x2")arm_secondary_entry as *const ()as u64,in("x3")cpu as u64,options(nostack));
        }
        assert_eq!(result, 0, "PSCI CPU_ON refused");
    }
    let end = super::virtio::counter() + super::virtio::frequency() * 3;
    while !(0..crate::cpu::count()).all(|i| ONLINE[i].load(Ordering::Acquire)) {
        assert!(super::virtio::counter() < end, "secondary bring-up timeout");
        core::hint::spin_loop();
    }
    crate::out("ARM SMP ONLINE cpus=");
    crate::number(crate::cpu::count() as u64);
    crate::out("\n");
    for target in 0..crate::cpu::count() {
        send_ipi(target as u8, 1);
    }
    unsafe {
        asm!("msr daifclr, #2");
    }
    while !(0..crate::cpu::count())
        .all(|i| IPIS[i].load(Ordering::Acquire) > 0 && TIMERS[i].load(Ordering::Acquire) > 0)
    {
        assert!(super::virtio::counter() < end, "timer/SGI progress timeout");
        core::hint::spin_loop();
    }
    unsafe {
        asm!("msr daifset, #2");
    }
    crate::out("ARM SMP TIMER IPI OK\n");
    crate::litmus::primary();
}
#[unsafe(no_mangle)]
pub extern "C" fn arm_secondary(context: u64) -> ! {
    while !READY.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }

    unsafe {
        crate::enable_root(ROOT.load(Ordering::Acquire));
        assert_eq!(
            crate::cpu::id() as u64,
            context,
            "PSCI context/affinity mismatch"
        );
        crate::gic_cpu();
        crate::timer();
        asm!("msr daifclr, #2");
    }
    ONLINE[context as usize].store(true, Ordering::Release);
    while !RUN.load(Ordering::Acquire) {
        crate::litmus::secondary(context as usize);
        core::hint::spin_loop();
    }
    unsafe {
        asm!("msr daifset, #2");
    }
    crate::kernel_lock::acquire(context as u8);
    crate::sched::idle_loop()
}
pub fn start_execution() {
    if enabled() {
        RUN.store(true, Ordering::Release);
        for i in 1..crate::cpu::count() {
            send_ipi(i as u8, 1);
        }
    }
}
pub fn send_ipi(target: u8, number: u32) {
    assert!((target as usize) < crate::cpu::count());
    crate::write32(
        unsafe { crate::GICD } + 0xf00,
        ((1u32 << target) << 16) | number,
    );
}
pub fn irq(irq: u32) {
    let id = crate::cpu::id() as usize;
    if irq == 27 {
        TIMERS[id].fetch_add(1, Ordering::Relaxed);
    } else if matches!(irq, 1 | 2) {
        IPIS[id].fetch_add(1, Ordering::Relaxed);
    }
}
pub fn prepare_process(slot: usize, p: &mut Process) {
    if enabled() {
        unsafe {
            ROLES[slot] = p.task.context.argument(2);
            LAST_PID[slot] = p.pid;
            LAST_CPU[slot] = u8::MAX;
        }
    }
}
fn placement(slot: usize, p: &Process) -> u8 {
    if p.pid == 1 || p.class.rt().is_some() {
        0
    } else if unsafe { matches!(ROLES[slot], 3 | 4) } {
        ((p.claim_epoch + 1) % crate::cpu::count() as u64) as u8
    } else {
        ((slot % (crate::cpu::count() - 1)) + 1) as u8
    }
}
pub fn next_runnable(current: usize, cpu: u8) -> Option<usize> {
    unsafe { crate::sched::table() }.next_runnable_after_if(current, |i, p| placement(i, p) == cpu)
}
pub fn assert_selection(slot: usize) {
    let table = unsafe { crate::sched::table() };
    let p = &table.entries[slot];
    let id = crate::cpu::id();
    assert!(enabled());
    assert_eq!(placement(slot, p), id);
    for other in &table.entries {
        if other.cpu_owner.is_some() {
            assert_ne!(
                other.address_space.root, p.address_space.root,
                "double-active address space"
            );
        }
    }
    unsafe {
        DISPATCHES[id as usize] += 1;
        if LAST_PID[slot] == p.pid
            && LAST_CPU[slot] != u8::MAX
            && LAST_CPU[slot] != id
            && matches!(ROLES[slot], 3 | 4)
        {
            MIGRATIONS[(ROLES[slot] - 3) as usize] += 1;
        }
        LAST_CPU[slot] = id;
    }
}
pub fn notify_runnable() {
    if enabled() {
        for i in 0..crate::cpu::count() {
            if i != crate::cpu::id() as usize {
                send_ipi(i as u8, 1);
            }
        }
    }
}
pub fn notify_process(p: &Process) {
    if p.is_runnable() {
        notify_runnable();
    }
}
pub fn idle_wait() {
    let id = crate::cpu::id();
    assert_eq!(crate::cpu::current(), crate::cpu::NO_TASK);
    crate::kernel_lock::release(id);
    if HALT.load(Ordering::Acquire) {
        PARKED[id as usize].store(true, Ordering::Release);
        loop {
            unsafe {
                asm!("msr daifset, #15", "wfi");
            }
        }
    }
    unsafe {
        asm!(
            "msr daifclr, #2",
            "wfi",
            "msr daifset, #2",
            options(nostack)
        );
    }
    crate::kernel_lock::acquire(id);
}
pub fn signal_stop(slot: usize, pid: u64, claim: CpuClaim) {
    assert!(enabled());
    assert_ne!(claim.cpu, crate::cpu::id());
    let id = claim.cpu as usize;
    assert!(
        !REQUEST[id].load(Ordering::Acquire),
        "second stop outstanding"
    );
    STOP_SLOT[id].store(slot as u64, Ordering::Relaxed);
    STOP_PID[id].store(pid, Ordering::Relaxed);
    STOP_EPOCH[id].store(claim.epoch, Ordering::Relaxed);
    REQUEST[id].store(true, Ordering::Release);
    log_stop("REQUEST", slot, pid, claim);
    send_ipi(claim.cpu, 2);
}
fn log_stop(phase: &str, slot: usize, pid: u64, claim: CpuClaim) {
    use core::fmt::Write;
    let _ = writeln!(
        crate::Serial,
        "ARM STOP {phase} cpu={} slot={slot} pid={pid} epoch={}",
        claim.cpu,
        claim.epoch
    );
}
pub fn observe_stop() -> bool {
    if !enabled() {
        return false;
    }
    let id = crate::cpu::id() as usize;
    let slot = crate::cpu::current();
    if slot == crate::cpu::NO_TASK {
        return false;
    }
    let p = &mut unsafe { crate::sched::table() }.entries[slot];
    if p.stop != StopState::Requested {
        return false;
    }
    let claim = p.cpu_owner.unwrap();
    assert!(REQUEST[id].load(Ordering::Acquire));
    assert_eq!(STOP_SLOT[id].load(Ordering::Relaxed), slot as u64);
    assert_eq!(STOP_PID[id].load(Ordering::Relaxed), p.pid);
    assert_eq!(STOP_EPOCH[id].load(Ordering::Relaxed), claim.epoch);
    p.stop = StopState::Observed;
    log_stop("OBSERVE", slot, p.pid, claim);
    true
}
pub fn departure(slot: usize, claim: CpuClaim) {
    if !enabled() {
        return;
    }
    let p = &unsafe { crate::sched::table() }.entries[slot];
    if matches!(p.stop, StopState::Requested | StopState::Observed) {
        let id = claim.cpu as usize;
        assert!(REQUEST[id].load(Ordering::Acquire));
        assert_eq!(STOP_PID[id].load(Ordering::Relaxed), p.pid);
        assert_eq!(STOP_SLOT[id].load(Ordering::Relaxed), slot as u64);
        assert_eq!(STOP_EPOCH[id].load(Ordering::Relaxed), claim.epoch);
        log_stop("DEPART", slot, p.pid, claim);
        log_stop("ACK", slot, p.pid, claim);
        REQUEST[id].store(false, Ordering::Release);
        unsafe {
            STOPS += 1;
        }
    }
}
pub fn reclaimed(slot: usize, pid: u64, claim: CpuClaim) {
    if enabled() {
        assert!(!REQUEST[claim.cpu as usize].load(Ordering::Acquire));
        log_stop("RECLAIM", slot, pid, claim);
        notify_runnable();
    }
}
pub fn requires_running_stop(_: usize, slot: usize) -> bool {
    enabled() && unsafe { ROLES[slot] == 6 }
}
pub fn finish() {
    if !enabled() {
        return;
    }
    assert_eq!(crate::cpu::id(), 0, "only BSP may finish SMP suite");
    unsafe {
        for dispatches in (&*core::ptr::addr_of!(DISPATCHES))
            .iter()
            .take(crate::cpu::count())
        {
            assert!(*dispatches > 0, "CPU did not execute userspace");
        }
        assert!(
            (&*core::ptr::addr_of!(MIGRATIONS)).iter().all(|m| *m > 0),
            "missing controlled FP migration"
        );
        assert!(STOPS > 0, "no cross-CPU departure/reclaim witness");
    }
    assert!((0..crate::cpu::count()).all(|i| !REQUEST[i].load(Ordering::Acquire)));
    HALT.store(true, Ordering::Release);
    for i in 1..crate::cpu::count() {
        send_ipi(i as u8, 1);
    }
    crate::kernel_lock::release(0);
    let end = super::virtio::counter() + super::virtio::frequency() * 3;
    while !(1..crate::cpu::count()).all(|i| PARKED[i].load(Ordering::Acquire)) {
        assert!(super::virtio::counter() < end, "CPU park timeout");
        core::hint::spin_loop();
    }
    crate::kernel_lock::acquire(0);
    use core::fmt::Write;
    unsafe {
        for i in 0..crate::cpu::count() {
            let _ = writeln!(
                crate::Serial,
                "ARM SMP CPU cpu={i} dispatches={} timers={} ipis={}",
                DISPATCHES[i],
                TIMERS[i].load(Ordering::Acquire),
                IPIS[i].load(Ordering::Acquire)
            );
        }
        let fp3 = MIGRATIONS[0];
        let fp4 = MIGRATIONS[1];
        let stops = STOPS;
        let _ = writeln!(
            crate::Serial,
            "ARM SMP MIGRATION fp3={fp3} fp4={fp4} stops={stops}"
        );
    }
    crate::out("ARM SMP PARK RECLAIM OK\nARM B1 OK\n");
}
