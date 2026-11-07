// Hardware-boundary fixture for scripts/test-smp-startup-drain.py.
// Scheduler function bodies below are supplied from their owning source files.
#![allow(dead_code, unused_imports)]
extern crate self as absd_abi;
extern crate self as absd_kernel;
#[path = "SOURCE_ROOT/src/arch.rs"]
pub mod arch;
#[path = "SOURCE_ROOT/src/elf.rs"]
pub mod elf;
#[path = "SOURCE_ROOT/src/frame_geometry.rs"]
pub mod frame_geometry;
#[path = "SOURCE_ROOT/src/handle.rs"]
pub mod handle;
#[path = "SOURCE_ROOT/abi/src/layout.rs"]
pub mod layout;
#[path = "SOURCE_ROOT/src/memory.rs"]
pub mod memory;
#[path = "SOURCE_ROOT/src/object.rs"]
pub mod object;
#[path = "SOURCE_ROOT/src/owner_lock.rs"]
pub mod owner_lock;
#[path = "SOURCE_ROOT/src/process.rs"]
pub mod process;
#[path = "SOURCE_ROOT/src/readable_wait.rs"]
pub mod readable_wait;
#[path = "SOURCE_ROOT/src/rt.rs"]
pub mod rt;
#[path = "SOURCE_ROOT/src/run_queue.rs"]
pub mod run_queue;
#[path = "SOURCE_ROOT/abi/src/syscall.rs"]
pub mod syscall;
use process::{CpuClaim, MAX_PROCESSES, Process, ProcessState, ProcessTable, StopState, WaitKind};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

mod cpu {
    use std::sync::atomic::{AtomicU8, Ordering};
    pub static CURRENT: AtomicU8 = AtomicU8::new(0);
    pub fn id() -> u8 {
        CURRENT.load(Ordering::Relaxed)
    }
    pub fn count() -> usize {
        2
    }
    pub fn is_bootstrap_processor() -> bool {
        id() == 0
    }
}
mod kernel_lock {
    pub const BSP: u8 = 0;
    static LOCK: crate::owner_lock::OwnerLock = crate::owner_lock::OwnerLock::new();
    pub fn acquire() {
        assert!(LOCK.try_acquire(crate::cpu::id()).is_ok());
    }
    pub fn release() {
        LOCK.release(crate::cpu::id());
    }
    pub fn assert_held(cpu: u8) {
        assert_eq!(LOCK.load(core::sync::atomic::Ordering::Acquire), cpu);
    }
    pub fn assert_current_owner() {
        assert_held(crate::cpu::id());
    }
}
mod clock {
    use super::*;
    pub static TICKS: AtomicU64 = AtomicU64::new(100);
    pub fn tsc() -> u64 {
        (TICKS.load(Ordering::Relaxed) - 100) << 32
    }
}
mod smp_startup {
    pub fn active() -> bool {
        true
    }
}
mod smp_fixture {
    pub fn on_drain(_: crate::ap::StopToken) {
        panic!("outside scope")
    }
}
mod ap {
    use super::*;
    #[derive(Clone, Copy)]
    pub struct StopToken {
        pub slot: usize,
        pub pid: u64,
        pub claim: CpuClaim,
    }
    pub static IPIS: AtomicUsize = AtomicUsize::new(0);
    pub static OMIT: AtomicBool = AtomicBool::new(false);
    pub fn poll_departed() -> Option<StopToken> {
        None
    }
    pub fn complete_drain(_: StopToken) {
        panic!("outside scope")
    }
    pub fn send_task_ipi(cpu: u8) {
        assert_eq!(cpu, 1);
        if !OMIT.load(Ordering::Relaxed) {
            IPIS.fetch_add(1, Ordering::Relaxed);
        }
    }
}
mod smp_operator {
    use super::*;
    pub fn enabled() -> bool {
        false
    }
    pub fn placement_of(_: &Process) -> u8 {
        panic!("outside scope")
    }
}
mod smp_user {
    use super::*;
    pub static IDLE: [AtomicBool; 2] = [AtomicBool::new(false), AtomicBool::new(true)];
    static MUTANT: AtomicU64 = AtomicU64::new(0);
    pub fn enabled() -> bool {
        true
    }
    static STOP: AtomicU64 = AtomicU64::new(0);
    fn shared(index: usize) -> &'static AtomicU64 {
        assert_eq!(index, 32);
        &STOP
    }
    // STARTUP_STOP
    struct Fixture {
        pid: u64,
        cpu: u8,
    }
    fn fixture(_: usize) -> Fixture {
        panic!("registered queue placement required")
    }
    fn native_app(_: &Process) -> bool {
        false
    }
    fn native_cpu() -> u8 {
        1
    }
    // NOTIFY_PROCESS
    // QUIESCENT
    pub fn notify_cpu(_: u8) {
        panic!("no stealing")
    }
    pub fn negative_selection(_: u8) -> Option<usize> {
        None
    }
    pub fn startup_assert_fence() {
        assert!(startup_quiescent());
        assert!(unsafe { crate::modern_smp::queues() }.key(1).is_none());
    }
    pub fn idle_wait() {
        kernel_lock::assert_held(0);
        kernel_lock::release();
        // A BSP PIT interrupt during CPL0 only advances ticks. An AP can run
        // after an IPI, never just because the fixture clock has advanced.
        clock::TICKS.fetch_add(1, Ordering::Relaxed);
        if ap::IPIS.swap(0, Ordering::Relaxed) > 0 {
            cpu::CURRENT.store(1, Ordering::Relaxed);
            kernel_lock::acquire();
            let selected = crate::modern_smp::select(MAX_PROCESSES - 1, 1, false);
            assert_eq!(selected, Some(1));
            let q = unsafe { crate::modern_smp::queues() };
            let key = q.candidate(1, 1).expect("IPI without runnable membership");
            let p = &mut unsafe { sched::table() }.entries[1];
            let claim = p.claim_cpu(1);
            q.claim(key, 1, claim.epoch);
            assert_eq!(STOP.load(Ordering::Acquire), 1);
            p.state = ProcessState::Exited;
            p.depart_cpu(claim);
            q.depart(key, 1, claim.epoch);
            q.remove(key);
            unsafe { sched::table() }.release(1);
            kernel_lock::release();
            cpu::CURRENT.store(0, Ordering::Relaxed);
        }
        kernel_lock::acquire();
    }
}
mod modern_smp {
    use super::*;
    use run_queue::{Key, Queues};
    static mut QUEUES: Queues = Queues::new();
    static mut PENDING: [u8; MAX_PROCESSES] = [u8::MAX; MAX_PROCESSES];
    static mut STEAL: [bool; MAX_PROCESSES] = [false; MAX_PROCESSES];
    pub static OMIT: AtomicBool = AtomicBool::new(false);
    pub fn enabled() -> bool {
        true
    }
    pub unsafe fn queues() -> &'static mut Queues {
        unsafe { &mut *core::ptr::addr_of_mut!(QUEUES) }
    }
    fn transfer(_: Key, _: &Process, _: u8, _: bool) {
        panic!("no transfer")
    }
    pub fn departed(_: usize, _: CpuClaim) {
        panic!("no remote stop")
    }
    // KEY_FOR
    // PLACEMENT
    // PUBLISH
    // ASSERT_ALL
    // SELECT
}
mod rt_runtime {
    use super::*;
    use rt::State;
    pub fn pending_pid(_: u64) -> bool {
        false
    }
    pub fn release_due(p: &mut Process, _: u64) {
        assert!(p.class.rt().is_none());
    }
    fn transition(_: &mut Process, _: State, _: &str) {
        panic!("ordinary actors only")
    }
    fn park(_: &mut Process) {
        panic!("ordinary actors only")
    }
    // MAKE_RUNNABLE
}
mod sched {
    use super::*;
    use arch::ExecutionState;
    use rt_runtime::make_runnable;
    use syscall::{ERROR_TIMEOUT, FRAME_RAX};
    static mut TABLE: ProcessTable = ProcessTable::new();
    pub unsafe fn table() -> &'static mut ProcessTable {
        unsafe { &mut *core::ptr::addr_of_mut!(TABLE) }
    }
    struct Stats {
        timeouts: u64,
    }
    static mut STATS: Stats = Stats { timeouts: 0 };
    unsafe fn stats() -> &'static mut Stats {
        unsafe { &mut *core::ptr::addr_of_mut!(STATS) }
    }
    #[derive(PartialEq)]
    enum BootMode {
        Ordinary,
        SmpLifecycle,
    }
    fn boot_mode() -> BootMode {
        BootMode::Ordinary
    }
    unsafe fn finish_departed_stop(_: usize, _: CpuClaim) {
        panic!("no remote stop")
    }
    pub fn now() -> u64 {
        clock::TICKS.load(Ordering::Relaxed)
    }
    // DEADLINE
    // DRAIN_DEPARTURES
    // WAKE_SLEEPERS
    // STARTUP_DRAIN
}
fn wait_single() {
    // SINGLE_WAIT
}
fn wait_multicore() {
    // MULTICORE_WAIT
}
fn main() {
    let case = std::env::args().nth(1).unwrap();
    kernel_lock::acquire();
    let t = unsafe { sched::table() };
    let q = unsafe { modern_smp::queues() };
    // One AP, two actors. The even actor has already departed and retired;
    // the odd actor slept at tick100 at the end of its fourth round.
    for slot in 0..2 {
        t.entries[slot] = Process::EMPTY;
        t.entries[slot].pid = (slot + 1) as u64;
        t.entries[slot].state = ProcessState::Runnable;
        let key = q.register(slot, (slot + 1) as u64, 1, 2, false);
        q.publish(key);
        let claim = t.entries[slot].claim_cpu(1);
        q.claim(key, 1, claim.epoch);
        t.entries[slot].state = if slot == 0 {
            ProcessState::Exited
        } else {
            ProcessState::Waiting
        };
        t.entries[slot].depart_cpu(claim);
        q.depart(key, 1, claim.epoch);
        if slot == 0 {
            q.remove(key);
            t.release(slot);
        }
    }
    t.entries[1].wait_kind = WaitKind::Sleep;
    t.entries[1].wake_at = sched::deadline(1);
    assert_eq!(t.entries[1].wake_at, Some(102));
    match case.as_str() {
        "due" | "single" => {}
        "not-due" => t.entries[1].wake_at = Some(200),
        "retired" => {
            let old = q.key(1).unwrap();
            q.remove(old);
            t.release(1);
            // Same slot, new identity, later deadline: no cached deadline or
            // retired key may revive the old actor or wake its successor.
            t.entries[1] = Process::EMPTY;
            t.entries[1].pid = 3;
            t.entries[1].state = ProcessState::Waiting;
            t.entries[1].wait_kind = WaitKind::Sleep;
            t.entries[1].wake_at = Some(200);
            let new = q.register(1, 3, 1, 2, false);
            assert_ne!(old.generation, new.generation);
        }
        "stop-requested" => t.entries[1].stop = StopState::Requested,
        "owned" => t.entries[1].cpu_owner = Some(CpuClaim { cpu: 1, epoch: 2 }),
        "no-publish" => modern_smp::OMIT.store(true, Ordering::Relaxed),
        "no-notify" => ap::OMIT.store(true, Ordering::Relaxed),
        _ => panic!("unknown case"),
    }
    // Expected refusals are checked by exact panic reason below. Restore the
    // ordinary hook before assertions so unexpected failures remain visible.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(if case == "single" {
        wait_single
    } else {
        wait_multicore
    });
    std::panic::set_hook(hook);
    if case == "due" || case == "single" {
        assert!(
            result.is_ok(),
            "due sleeper was stranded by startup departure wait"
        );
        assert_eq!(unsafe { sched::table() }.occupied_count(), 0);
    } else {
        let error = result.expect_err("negative control unexpectedly drained");
        let message = error
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| error.downcast_ref::<&str>().copied())
            .unwrap_or("");
        if case == "no-publish" {
            assert!(
                message.contains("lost/extra runnable membership"),
                "unexpected refusal: {message}"
            );
        } else {
            assert_eq!(message, "startup departure fence");
        }
        assert_eq!(unsafe { sched::table() }.occupied_count(), 1);
        assert_eq!(ap::IPIS.load(Ordering::Relaxed), 0);
        if matches!(
            case.as_str(),
            "not-due" | "retired" | "stop-requested" | "owned"
        ) {
            assert_eq!(
                unsafe { sched::table() }.entries[1].state,
                ProcessState::Waiting
            );
            let q = unsafe { modern_smp::queues() };
            assert!(!q.queued(q.key(1).unwrap()));
        }
    }
    println!("startup drain {case}: PASS");
}
