//! Single-owner kernel serialization for the BSP and the kernel-only AP.
//!
//! IRQs used for device progress do not acquire this lock. A driver that
//! sleeps for an interrupt publishes its BSP continuation, releases the lock,
//! waits, then reacquires and validates the continuation before touching
//! shared kernel state again. AP code cannot enter a device path.

use absd_kernel::process::{CpuClaim, ProcessState, StopState};
use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};

const FREE: u8 = u8::MAX;
pub const BSP: u8 = 0;
pub const FIXTURE_AP: u8 = 1;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitSite {
    None = 0,
    Ata = 1,
    Nvme = 2,
    NicProbe = 3,
    NicSend = 4,
    Idle = 5,
}

static ACTIVE: AtomicBool = AtomicBool::new(false);
static OWNER: absd_kernel::owner_lock::OwnerLock = absd_kernel::owner_lock::OwnerLock::new();
static BSP_APIC_ID: AtomicU8 = AtomicU8::new(FREE);
static AP_APIC_ID: [AtomicU8; crate::cpu::MAX_CPUS] =
    [const { AtomicU8::new(FREE) }; crate::cpu::MAX_CPUS];
static BSP_WAIT: AtomicU8 = AtomicU8::new(WaitSite::None as u8);
static BSP_WAIT_SLOT: AtomicUsize = AtomicUsize::new(crate::cpu::NO_TASK);
static BSP_WAIT_PID: AtomicU64 = AtomicU64::new(0);
static BSP_WAIT_EPOCH: AtomicU64 = AtomicU64::new(0);
static WAIT_ENTERED: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];
static WAIT_PIT_PROGRESS: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];
static WAIT_REVALIDATED: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitEvidence {
    pub entered: u64,
    pub pit_progress: u64,
    pub revalidated: u64,
}

pub fn wait_evidence(site: WaitSite) -> WaitEvidence {
    let index = site as usize;
    assert!(index != 0 && index < WAIT_ENTERED.len());
    WaitEvidence {
        entered: WAIT_ENTERED[index].load(Ordering::Acquire),
        pit_progress: WAIT_PIT_PROGRESS[index].load(Ordering::Acquire),
        revalidated: WAIT_REVALIDATED[index].load(Ordering::Acquire),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WaitPin {
    slot: usize,
    pid: u64,
    claim: CpuClaim,
}

/// The process remains CPU-owned throughout a released-lock continuation;
/// stop may become Requested but reclamation must wait for its later hardware
/// departure. No `&mut Process` or table reference escapes this function.
fn current_wait_pin() -> Option<WaitPin> {
    let slot = crate::cpu::current();
    if slot == crate::cpu::NO_TASK {
        return None;
    }
    let process = &unsafe { crate::sched::table() }.entries[slot];
    assert_eq!(process.state, ProcessState::Running);
    let claim = process.cpu_owner.expect("device wait without CPU owner");
    assert_eq!(claim.cpu, BSP);
    Some(WaitPin {
        slot,
        pid: process.pid,
        claim,
    })
}

/// Bootstrap initialization runs alone with IF=0. Publish lock ownership
/// before admitting the AP; all later shared process/object mutation uses it.
pub fn activate_on_bsp() {
    assert!(crate::cpu::is_bootstrap_processor());
    assert!(!ACTIVE.load(Ordering::Relaxed));
    assert_eq!(OWNER.load(Ordering::Relaxed), FREE);
    let apic_id = local_apic_id();
    assert_ne!(apic_id, FREE, "BSP APIC ID collides with free sentinel");
    BSP_APIC_ID.store(apic_id, Ordering::Relaxed);
    OWNER.initialize(BSP);
    ACTIVE.store(true, Ordering::Release);
}

fn local_apic_id() -> u8 {
    (core::arch::x86_64::__cpuid(1).ebx >> 24) as u8
}

/// BSP records the one AP admitted for kernel-only fixtures before SIPI.
pub fn register_kernel_only_ap(id: u8) {
    assert_held(BSP);
    assert!(
        id > 0 && (id as usize) < crate::cpu::count(),
        "unadmitted AP APIC ID"
    );
    assert_ne!(id, FREE, "AP APIC ID collides with free sentinel");
    assert_ne!(id, BSP_APIC_ID.load(Ordering::Acquire));
    assert_eq!(AP_APIC_ID[id as usize].swap(id, Ordering::AcqRel), FREE);
}

fn assert_cpu_identity(cpu: u8) {
    if !active() {
        assert_eq!(cpu, BSP);
        return;
    }
    let expected = match cpu {
        BSP => BSP_APIC_ID.load(Ordering::Acquire),
        cpu if (cpu as usize) < crate::cpu::count() => {
            AP_APIC_ID[cpu as usize].load(Ordering::Acquire)
        }
        _ => panic!("unregistered CPU"),
    };
    assert_ne!(expected, FREE, "unregistered CPU");
    assert_eq!(crate::cpu::id(), cpu, "kernel lock wrong CPU");
}

pub fn assert_current_owner() {
    if !active() {
        return;
    }
    let cpu = crate::cpu::id();
    assert_cpu_identity(cpu);
    assert_held(cpu);
}

pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

pub fn owner() -> Option<u8> {
    let owner = OWNER.load(Ordering::Acquire);
    (owner != FREE).then_some(owner)
}

pub fn bsp_wait_site() -> WaitSite {
    match BSP_WAIT.load(Ordering::Acquire) {
        0 => WaitSite::None,
        1 => WaitSite::Ata,
        2 => WaitSite::Nvme,
        3 => WaitSite::NicProbe,
        4 => WaitSite::NicSend,
        5 => WaitSite::Idle,
        _ => panic!("invalid BSP wait site"),
    }
}

pub fn acquire(cpu: u8) {
    assert_cpu_identity(cpu);
    if !active() {
        assert_eq!(cpu, BSP, "AP cannot enter before kernel serialization");
        return;
    }
    // The retained kernel-only mapping continuation acquires with IF=1.
    // Only this measurement boot requires IF=0 to delimit completed spans.
    if crate::smp_bench::scale() || crate::smp_app_scale::enabled() {
        let flags: u64;
        unsafe {
            asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
        }
        assert_eq!(flags & (1 << 9), 0, "scale serialization requires IF clear");
    }
    assert_ne!(OWNER.load(Ordering::Relaxed), cpu, "recursive kernel lock");
    let mut attempt = crate::smp_measure::begin();
    let mut wait_start = None;
    loop {
        match OWNER.try_acquire(cpu) {
            Ok(_) => break,
            Err(owner) => {
                if attempt.epoch != 0 {
                    attempt.retries += 1;
                    attempt.contended |= owner != FREE;
                }
                if crate::smp_bench::mode() != 0 && wait_start.is_none() {
                    wait_start = Some(unsafe { core::arch::x86_64::_rdtsc() });
                }
                crate::smp_user::note_contention(cpu);
                core::hint::spin_loop();
            }
        }
    }
    crate::smp_measure::acquired(cpu, attempt);
    if let Some(start) = wait_start {
        crate::smp_bench::waited(
            cpu,
            unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start),
        );
    }
}

pub fn release(cpu: u8) {
    assert_cpu_identity(cpu);
    if !active() {
        assert_eq!(cpu, BSP);
        return;
    }
    assert_eq!(
        OWNER.load(Ordering::Relaxed),
        cpu,
        "kernel lock owner mismatch"
    );
    crate::smp_measure::release(cpu);
    OWNER.release(cpu);
}

pub fn assert_held(cpu: u8) {
    if active() {
        assert_eq!(OWNER.load(Ordering::Acquire), cpu, "kernel lock absent");
    }
}

/// Called only by BSP user-entry stubs after the complete trap frame is
/// present, before any process-table or object access.
#[unsafe(no_mangle)]
pub extern "C" fn bsp_kernel_enter() {
    acquire(BSP);
}

/// Called by the final BSP return path after shared state and return data
/// have been committed. An owned task remains pinned until departure.
#[unsafe(no_mangle)]
pub extern "C" fn bsp_kernel_leave() {
    release(BSP);
}

/// PIC devices and the COM1 console belong to the BSP throughout this gate.
/// The AP has no device-call path even while the BSP has yielded its lock.
pub fn assert_bsp_device_access() {
    if !active() || crate::cpu::id() == BSP {
        return;
    }
    crate::cpu::refuse_application_processor();
}

/// A released-lock pre-issue poll must not turn a newly requested stop into
/// another device command. Boot-time probes have no process owner and cannot
/// receive a process stop.
pub fn current_stop_requested() -> bool {
    assert_held(BSP);
    let Some(pin) = current_wait_pin() else {
        return false;
    };
    let process = &unsafe { crate::sched::table() }.entries[pin.slot];
    assert!(matches!(
        process.stop,
        StopState::Active | StopState::Requested | StopState::Observed
    ));
    process.stop != StopState::Active
}

/// Common interruptible wait. `site` is the BSP-owned continuation kind;
/// its live task and device resources remain pinned until the enclosing
/// bounded handler finishes or explicitly disables the device. No mutable
/// process-table reference may cross this call.
pub fn wait_for_irq(site: WaitSite) {
    assert_bsp_device_access();
    assert!(site != WaitSite::None && site != WaitSite::Idle);
    if active() {
        assert_held(BSP);
        assert_eq!(bsp_wait_site(), WaitSite::None);
        let tick_before = crate::sched::now();
        WAIT_ENTERED[site as usize].fetch_add(1, Ordering::AcqRel);
        let pin = current_wait_pin();
        BSP_WAIT_SLOT.store(
            pin.map_or(crate::cpu::NO_TASK, |pin| pin.slot),
            Ordering::Relaxed,
        );
        BSP_WAIT_PID.store(pin.map_or(0, |pin| pin.pid), Ordering::Relaxed);
        BSP_WAIT_EPOCH.store(pin.map_or(0, |pin| pin.claim.epoch), Ordering::Relaxed);
        BSP_WAIT.store(site as u8, Ordering::Release);
        let ap_before = crate::smp_user::ap_calls();
        crate::smp_startup::snapshot_before_wait(site);
        release(BSP);
        crate::smp_user::device_window(site as usize, ap_before);
        unsafe { asm!("sti", "hlt", "cli", options(nomem, nostack)) };
        acquire(BSP);
        crate::smp_measure::tag(crate::smp_measure::DEVICE);
        assert_eq!(bsp_wait_site(), site, "device continuation changed");
        assert_eq!(current_wait_pin(), pin, "device wait owner changed");
        if let Some(pin) = pin {
            let process = &unsafe { crate::sched::table() }.entries[pin.slot];
            // An already-issued command may complete after Requested. Its
            // owner remains pinned until the handler retires; the final
            // entry/return stop gate suppresses userspace resumption.
            assert!(matches!(
                process.stop,
                StopState::Active | StopState::Requested | StopState::Observed
            ));
        }
        assert_eq!(
            BSP_WAIT_SLOT.load(Ordering::Relaxed),
            pin.map_or(crate::cpu::NO_TASK, |pin| pin.slot)
        );
        assert_eq!(
            BSP_WAIT_PID.load(Ordering::Relaxed),
            pin.map_or(0, |pin| pin.pid)
        );
        assert_eq!(
            BSP_WAIT_EPOCH.load(Ordering::Relaxed),
            pin.map_or(0, |pin| pin.claim.epoch)
        );
        if crate::sched::now() > tick_before {
            WAIT_PIT_PROGRESS[site as usize].fetch_add(1, Ordering::AcqRel);
        }
        WAIT_REVALIDATED[site as usize].fetch_add(1, Ordering::AcqRel);
        BSP_WAIT.store(WaitSite::None as u8, Ordering::Release);
        return;
    }
    unsafe { asm!("sti", "hlt", "cli", options(nomem, nostack)) };
}

/// Idle owns no task or device continuation. Returning from the interrupt
/// reacquires serialization before reading the run table or timers.
pub fn idle_wait() {
    let tick_before = crate::sched::now();
    if active() {
        assert_held(BSP);
        assert_eq!(bsp_wait_site(), WaitSite::None);
        WAIT_ENTERED[WaitSite::Idle as usize].fetch_add(1, Ordering::AcqRel);
        BSP_WAIT.store(WaitSite::Idle as u8, Ordering::Release);
        release(BSP);
    }
    unsafe { asm!("sti", "hlt", "cli", options(nomem, nostack)) };
    if active() {
        acquire(BSP);
        crate::smp_measure::tag(crate::smp_measure::IDLE);
        assert_eq!(bsp_wait_site(), WaitSite::Idle);
        if crate::sched::now() > tick_before {
            WAIT_PIT_PROGRESS[WaitSite::Idle as usize].fetch_add(1, Ordering::AcqRel);
        }
        WAIT_REVALIDATED[WaitSite::Idle as usize].fetch_add(1, Ordering::AcqRel);
        BSP_WAIT.store(WaitSite::None as u8, Ordering::Release);
    }
}

/// BKL-owned request publication precedes the AP IPI. The AP may observe it
/// without taking serialization, but only its post-pivot ACK permits drain.
pub fn signal_remote_stop(slot: usize, pid: u64, owner: CpuClaim) {
    if crate::smp_user::enabled() {
        assert_current_owner();
        crate::smp_user::signal_stop(slot, pid, owner);
    } else {
        assert_held(BSP);
        crate::ap::signal_stop(slot, pid, owner);
    }
}
