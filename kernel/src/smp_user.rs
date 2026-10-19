//! Fixed-placement AP userspace qualification. This is inert
//! unless both the compile feature and the exact qualification boot are set.
use absd_kernel::process::{CpuClaim, MAX_PROCESSES, Process, ProcessState, StopState};
use absd_kernel::syscall::{ERROR_NOT_IMPLEMENTED, FRAME_RDX};
use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub const SHARED_ADDRESS: u64 = absd_kernel::layout::USER_REGION_BASE + 0x0c00_0000;
static ENABLED: AtomicBool = AtomicBool::new(false);
static STANDALONE: AtomicBool = AtomicBool::new(true);
static IGNORE_RESERVATION: AtomicBool = AtomicBool::new(false);
static NATIVE_APP: AtomicBool = AtomicBool::new(false);
static NATIVE_CPU: AtomicU64 = AtomicU64::new(1);
static NATIVE_PID: AtomicU64 = AtomicU64::new(0);
static NATIVE_CALLS: AtomicU64 = AtomicU64::new(0);
static NATIVE_TIMERS: AtomicU64 = AtomicU64::new(0);
static NATIVE_EXITS: AtomicU64 = AtomicU64::new(0);
static MUTANT: AtomicU64 = AtomicU64::new(0);
pub fn set_mutant(value: u64) {
    assert!(enabled() && standalone() && (1..=5).contains(&value));
    MUTANT.store(value, Ordering::Release);
    if value == 5 {
        crate::kernel_lock::assert_current_owner();
        if crate::smp_nway::enabled() {
            crate::serial::write("SMP NWAY INJECT serialized-placement=1 cpu=0\n");
        } else {
            crate::serial::write("SMP USER INJECT serialized-placement=1 cpu=0\n");
        }
    }
}
pub fn serialized_nway() -> bool {
    crate::smp_nway::enabled() && MUTANT.load(Ordering::Acquire) == 5
}
#[repr(C, align(4096))]
struct Shared([AtomicU64; 512]);
static SHARED: Shared = Shared([const { AtomicU64::new(0) }; 512]);
pub fn nway_epoch_pointer() -> u64 {
    core::ptr::addr_of!(SHARED) as u64 + 400 * 8
}
pub fn nway_sample(word: usize) -> u64 {
    assert!((410..456).contains(&word) || (480..493).contains(&word));
    shared(word).load(Ordering::Acquire)
}
#[derive(Clone, Copy)]
struct Fixture {
    pid: u64,
    cpu: u8,
    role: u64,
    pte: u64,
    original: u64,
}
const EMPTY: Fixture = Fixture {
    pid: 0,
    cpu: 0,
    role: 0,
    pte: 0,
    original: 0,
};
static mut FIXTURES: [Fixture; MAX_PROCESSES] = [EMPTY; MAX_PROCESSES];
static CALLS: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];
static CONTENTION: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];
static IDLE: [AtomicBool; crate::cpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::cpu::MAX_CPUS];
static IDLE_COUNT: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];
static REQUEST_PID: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];
static REQUEST_EPOCH: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];
static REQUEST_SLOT: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];
static REQUEST: [AtomicBool; crate::cpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::cpu::MAX_CPUS];
static NEXT_GAP: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];
static mut SEQUENCE: u64 = 0;
static mut CASES: u64 = 0;
static mut STOPS: [u64; crate::cpu::MAX_CPUS] = [0; crate::cpu::MAX_CPUS];
static DEVICE_WINDOWS: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];
static DEVICE_FIRST_POLLS: AtomicU64 = AtomicU64::new(0);
static NVME_SKIP_FIRST_POLL: AtomicBool = AtomicBool::new(false);
static TIMER_FAULTS: AtomicU64 = AtomicU64::new(0);
static TIMER_EXITS: AtomicU64 = AtomicU64::new(0);
/// Reuse the foundation's post-doorbell, unchecked-completion wait fixture.
/// KVM may complete TX or an NVMe command before its polling threshold.
/// Explicitly cross this pinned boundary once per site during a task-owned
/// command. Initial probes cannot consume the witness before AP startup.
pub fn skip_nvme_first_poll() {
    assert!(enabled() && !standalone() && crate::smp_timer::enabled());
    assert!(!NVME_SKIP_FIRST_POLL.swap(true, Ordering::AcqRel));
}
pub fn device_first_poll(site: crate::kernel_lock::WaitSite) {
    if !enabled() || standalone() || crate::cpu::current() == crate::cpu::NO_TASK {
        return;
    }
    let (bit, name) = match site {
        crate::kernel_lock::WaitSite::Nvme => (1 << 2, "nvme"),
        crate::kernel_lock::WaitSite::NicSend => (1 << 4, "nic-send"),
        _ => return,
    };
    assert_eq!(crate::cpu::id(), crate::kernel_lock::BSP);
    crate::kernel_lock::assert_held(crate::kernel_lock::BSP);
    if DEVICE_FIRST_POLLS.fetch_or(bit, Ordering::AcqRel) & bit != 0 {
        return;
    }
    if site == crate::kernel_lock::WaitSite::Nvme && NVME_SKIP_FIRST_POLL.load(Ordering::Acquire) {
        crate::serial::write("SMP USER DEVICE WAIT INJECT site=nvme first-poll=omitted\n");
        return;
    }
    let before = crate::kernel_lock::wait_evidence(site);
    let calls = ap_calls();
    crate::kernel_lock::wait_for_irq(site);
    let after = crate::kernel_lock::wait_evidence(site);
    assert!(ap_calls() > calls);
    assert_eq!(after.entered - before.entered, 1);
    assert_eq!(after.revalidated - before.revalidated, 1);
    assert!(after.pit_progress > before.pit_progress);
    crate::serial::write("SMP USER DEVICE WAIT site=");
    crate::serial::write(name);
    crate::serial::write(" mode=injected-first-poll revalidated=1 completion=unchecked\n");
}
pub fn ap_calls() -> u64 {
    CALLS[1].load(Ordering::Acquire)
}
pub fn calls_on(cpu: usize) -> u64 {
    assert!(cpu < crate::cpu::count());
    CALLS[cpu].load(Ordering::Acquire)
}
/// Test-only timing pressure while the BSP continuation is pinned and the
/// BKL is released. No kernel object/table reference crosses this interval.
pub fn device_window(site: usize, before: u64) {
    if !enabled()
        || standalone()
        || (crate::cpu::current() == crate::cpu::NO_TASK && !crate::smp_startup::active())
    {
        return;
    }
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    while ap_calls() == before {
        assert!(
            unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < 1 << 32,
            "AP made no syscall progress during pinned wait"
        );
        core::hint::spin_loop();
    }
    DEVICE_WINDOWS[site].fetch_add(1, Ordering::Relaxed);
    crate::smp_startup::window(site);
}
pub fn pressure_finish() {
    if !enabled() || standalone() {
        return;
    }
    assert_eq!(crate::cpu::id(), 0);
    crate::modern_smp::finish();
    assert!((1..crate::cpu::count()).all(|cpu| IDLE[cpu].load(Ordering::Acquire)));
    assert!(ap_calls() > 0 && shared(32).load(Ordering::Acquire) == 1);
    crate::serial::write("SMP USER PRESSURE calls1=");
    crate::serial::decimal(ap_calls());
    for (name, site) in [
        (" ata=", 1),
        (" nvme=", 2),
        (" nic-probe=", 3),
        (" nic-send=", 4),
        (" idle=", 5),
    ] {
        crate::serial::write(name);
        crate::serial::decimal(DEVICE_WINDOWS[site].load(Ordering::Acquire));
    }
    crate::serial::write("\n");
    crate::smp_timer::report();
    crate::smp_app_pressure::report();
    if NATIVE_APP.load(Ordering::Acquire) {
        assert!(NATIVE_CALLS.load(Ordering::Acquire) > 0);
        assert_eq!(NATIVE_EXITS.load(Ordering::Acquire), 1);
        if crate::smp_app_pressure::enabled() {
            assert!(
                NATIVE_TIMERS.load(Ordering::Acquire) > 0,
                "native application lacked task-specific preemption"
            );
        }
        crate::serial::write("SMP APP SUMMARY cpu=");
        crate::serial::decimal(native_cpu() as u64);
        crate::serial::write(" pid=");
        crate::serial::decimal(NATIVE_PID.load(Ordering::Acquire));
        crate::serial::write(" calls=");
        crate::serial::decimal(NATIVE_CALLS.load(Ordering::Acquire));
        crate::serial::write(" timer-irqs=");
        crate::serial::decimal(NATIVE_TIMERS.load(Ordering::Acquire));
        crate::serial::write(" exited=1 faults=0 departed=1\n");
    }
}
fn stop_path(path: &str, pid: u64, claim: CpuClaim) {
    crate::serial::write("SMP USER STOP PATH cpu=");
    crate::serial::decimal(claim.cpu as u64);
    crate::serial::write(" pid=");
    crate::serial::decimal(pid);
    crate::serial::write(" epoch=");
    crate::serial::decimal(claim.epoch);
    crate::serial::write(" path=");
    crate::serial::write(path);
    crate::serial::write("\n");
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}
pub fn configure() {
    if !cfg!(feature = "smp-user-test") {
        panic!("SMP USER TEST REQUIRES smp-user-test BUILD");
    }
    assert!(crate::cpu::is_bootstrap_processor());
    assert!(!ENABLED.swap(true, Ordering::AcqRel));
}
pub fn controller_role() -> u64 {
    if crate::smp_nway::enabled() {
        120
    } else if crate::smp_fpu::enabled() {
        66
    } else {
        0
    }
}
fn max_role() -> u64 {
    if crate::smp_app_scale::enabled() {
        355
    } else if crate::smp_bench::scale() {
        317
    } else if crate::smp_app_pressure::enabled() {
        199 + crate::smp_app_pressure::reservation()
    } else if crate::smp_nway::enabled() {
        196
    } else if crate::smp_fpu::enabled() {
        66
    } else if crate::modern_smp::enabled() {
        60
    } else {
        55
    }
}
pub fn shared_load(index: usize) -> u64 {
    shared(index).load(Ordering::Acquire)
}
pub fn idle_count() -> usize {
    (1..crate::smp_bench::cpus())
        .filter(|cpu| IDLE[*cpu].load(Ordering::Acquire))
        .count()
}
pub fn fixture_role(slot: usize) -> u64 {
    fixture(slot).role
}
pub fn fpu_nonvoluntary_interval() -> bool {
    let begin = shared(202).load(Ordering::Acquire);
    begin != 0
        && matches!(shared(200).load(Ordering::Acquire), 1 | 3)
        && unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(begin) < 1 << 29
}
pub fn fpu_peer_progress() -> u64 {
    shared(221).load(Ordering::Acquire)
}
pub fn standalone() -> bool {
    STANDALONE.load(Ordering::Acquire)
}
pub fn pressure_mode() {
    STANDALONE.store(false, Ordering::Release);
}
pub fn native_app_mode(cpu: u8) {
    assert!(enabled() && !standalone() && crate::smp_timer::enabled());
    assert!((1..crate::cpu::count() as u8).contains(&cpu));
    assert!(cpu == 1 || crate::smp_app_pressure::enabled());
    NATIVE_CPU.store(cpu as u64, Ordering::Release);
    assert!(!NATIVE_APP.swap(true, Ordering::AcqRel));
}
fn native_cpu() -> u8 {
    NATIVE_CPU.load(Ordering::Acquire) as u8
}
fn native_app(process: &Process) -> bool {
    NATIVE_APP.load(Ordering::Acquire)
        && process.program == absd_kernel::program::EXTERNAL_WORKLOAD as usize
}
pub fn pressure_reservation() -> u64 {
    if enabled() && !standalone() {
        if crate::smp_app_pressure::enabled() {
            crate::smp_app_pressure::reservation()
        } else if crate::smp_timer::enabled() {
            2
        } else {
            1
        }
    } else {
        0
    }
}
pub fn ignore_reservation() {
    assert!(enabled() && !standalone());
    IGNORE_RESERVATION.store(true, Ordering::Release);
}
fn shared(index: usize) -> &'static AtomicU64 {
    &SHARED.0[index]
}
pub fn pressure_preempt_publish(cpu: u8) {
    assert!(crate::smp_app_pressure::enabled() && (1..crate::cpu::count() as u8).contains(&cpu));
    shared(460 + cpu as usize - 1).store(1, Ordering::Release);
}
fn fixture(index: usize) -> Fixture {
    crate::kernel_lock::assert_current_owner();
    unsafe { (*core::ptr::addr_of!(FIXTURES))[index] }
}
fn log_event(label: &str, index: usize, pid: u64, claim: CpuClaim) {
    crate::kernel_lock::assert_current_owner();
    unsafe {
        SEQUENCE += 1;
    }
    crate::serial::write("SMP USER ");
    crate::serial::write(label);
    crate::serial::write(" seq=");
    crate::serial::decimal(unsafe { SEQUENCE });
    crate::serial::write(" cpu=");
    crate::serial::decimal(u64::from(claim.cpu));
    crate::serial::write(" slot=");
    crate::serial::decimal(index as u64);
    crate::serial::write(" pid=");
    crate::serial::decimal(pid);
    crate::serial::write(" epoch=");
    crate::serial::decimal(claim.epoch);
    crate::serial::write("\n");
}

/// Install only a dedicated shared qualification page. Its leaf temporarily
/// substitutes kernel-owned scratch for a private allocated page; retain the
/// original leaf and restore it before normal ownership-based teardown. This
/// address lies outside ELF, stack and anonymous-map windows. No syscall can
/// unmap it. No private task frame is shared, and roots remain independent.
pub fn prepare_process(index: usize, process: &mut Process) {
    crate::smp_app_scale::prepare(index, process);
    if !enabled() || process.program != absd_kernel::program::SMP_USER as usize {
        return;
    }
    let role = process.task.context[FRAME_RDX];
    assert!(role <= max_role(), "unknown AP fixture placement");
    if crate::smp_bench::mode() != 0 {
        assert!(
            role == 0
                || if crate::smp_app_scale::enabled() {
                    (350..=355).contains(&role)
                } else if crate::smp_bench::scale() {
                    (300..=317).contains(&role)
                } else {
                    (50..=55).contains(&role)
                }
        );
    }
    assert_eq!(process.state, ProcessState::Created);
    let cpu = if crate::smp_app_scale::enabled() {
        crate::smp_app_scale::placement(process).expect("application fixture placement")
    } else if crate::smp_bench::scale() {
        if role == 0 {
            0
        } else {
            ((role - 300) as usize % 6 % crate::smp_bench::cpus()) as u8
        }
    } else if crate::smp_app_pressure::enabled() {
        crate::smp_app_pressure::placement(role)
    } else if crate::smp_nway::enabled() {
        crate::smp_nway::placement(role)
    } else if crate::smp_fpu::enabled() && (61..=66).contains(&role) {
        if matches!(role, 61 | 66) { 0 } else { 1 }
    } else if (crate::modern_smp::enabled() && role >= 56) || crate::smp_bench::mode() == 1 {
        0
    } else {
        (role & 1) as u8
    };
    // The intended role/placement has been validated above. Mutant5 is a
    // closed single-CPU placement substitution, never a return-permit policy.
    let cpu = if !crate::smp_nway::enabled() && MUTANT.load(Ordering::Acquire) == 5 {
        0
    } else {
        cpu
    };
    unsafe {
        crate::vm::map_user_page(
            crate::vm::frames(),
            &mut process.address_space,
            process.pid as u32,
            SHARED_ADDRESS,
            true,
            false,
        )
        .expect("fixture map");
        let directory_index = ((SHARED_ADDRESS >> 21) & 0x1ff) as usize;
        let slot = process
            .address_space
            .page_tables
            .iter()
            .find(|s| s.frame != 0 && s.directory_index == directory_index)
            .unwrap();
        let pte = slot.frame + ((SHARED_ADDRESS >> 12) & 0x1ff) * 8;
        let original = core::ptr::read_volatile(pte as *const u64);
        let scratch = core::ptr::addr_of!(SHARED) as u64;
        assert_eq!(scratch & 4095, 0);
        core::ptr::write_volatile(
            pte as *mut u64,
            scratch | (original & !crate::vm::ADDRESS_MASK),
        );
        (*core::ptr::addr_of_mut!(FIXTURES))[index] = Fixture {
            pid: process.pid,
            cpu,
            role,
            pte,
            original,
        };
    }
    crate::smp_app_pressure::prepare_frames(process, role);
}
pub fn restore_fixture_page(process: &Process) {
    crate::smp_app_scale::terminal(process);
    if !enabled() {
        return;
    }
    if native_app(process) && process.state != ProcessState::Created {
        assert!(process.cpu_owner.is_none());
        assert_eq!(NATIVE_PID.load(Ordering::Acquire), process.pid);
        assert_eq!(process.state, ProcessState::Exited);
        assert_eq!(process.exit_status, 0);
        assert_eq!(NATIVE_EXITS.fetch_add(1, Ordering::AcqRel), 0);
        crate::smp_app_pressure::app_end();
    }
    unsafe {
        for i in 0..MAX_PROCESSES {
            let f = fixture(i);
            if f.pid == process.pid && f.pid != 0 {
                assert!(process.cpu_owner.is_none());
                crate::smp_nway::terminal(i, process, f.role);
                crate::smp_app_pressure::terminal(process, f.role);
                if f.role == 47 {
                    assert_eq!(process.state, ProcessState::Faulted);
                    assert_eq!(process.fault_vector, 14);
                    TIMER_FAULTS.fetch_add(1, Ordering::Relaxed);
                }
                if f.role == 49 {
                    assert_eq!(process.state, ProcessState::Exited);
                    assert_eq!(process.exit_status, 7);
                    TIMER_EXITS.fetch_add(1, Ordering::Relaxed);
                }
                assert_eq!(
                    core::ptr::read_volatile(f.pte as *const u64) & crate::vm::ADDRESS_MASK,
                    core::ptr::addr_of!(SHARED) as u64
                );
                core::ptr::write_volatile(f.pte as *mut u64, f.original);
                (*core::ptr::addr_of_mut!(FIXTURES))[i] = EMPTY;
                return;
            }
        }
    }
}
pub fn initial_placement(index: usize, process: &Process) -> u8 {
    if let Some(cpu) = crate::smp_app_scale::placement(process) {
        return cpu;
    }
    let f = fixture(index);
    if f.pid == process.pid && f.pid != 0 {
        f.cpu
    } else {
        if native_app(process) { native_cpu() } else { 0 }
    }
}
fn placement(index: usize, process: &Process) -> u8 {
    crate::modern_smp::placement(index, process.pid)
        .unwrap_or_else(|| initial_placement(index, process))
}
pub fn assert_selection(index: usize) {
    assert!(index < MAX_PROCESSES, "invalid AP fixture selection");
    let table = unsafe { crate::sched::table() };
    let p = &table.entries[index];
    for other in &table.entries {
        if other.cpu_owner.is_some() {
            assert_ne!(
                other.address_space.root, p.address_space.root,
                "double active CR3"
            );
        }
    }
    assert_eq!(
        placement(index, p),
        crate::cpu::id(),
        "fixed placement mismatch"
    );
    if crate::cpu::id() > 0 {
        assert!(
            (p.program == absd_kernel::program::SMP_USER as usize
                || native_app(p)
                || crate::smp_app_scale::permits(p))
                && p.class.rt().is_none(),
            "AP ordinary/RT return refused outside designated fixture"
        );
    }
}
pub fn next_runnable(current: usize, cpu: u8) -> Option<usize> {
    if crate::modern_smp::enabled() {
        return crate::modern_smp::select(current, cpu, false);
    }
    if let Some(index) = negative_selection(cpu) {
        return Some(index);
    }
    let t = unsafe { crate::sched::table() };
    t.next_runnable_after_if(current, |i, p| placement(i, p) == cpu)
}
pub fn notify_runnable() {
    if !enabled() {
        return;
    }
    // One table and one BKL, no queue or placement API.
    for cpu in 0..crate::cpu::count() as u8 {
        if cpu != crate::cpu::id()
            && IDLE[cpu as usize].load(Ordering::Acquire)
            && (next_runnable(MAX_PROCESSES - 1, cpu).is_some()
                || crate::modern_smp::steal_available(cpu))
        {
            crate::ap::send_task_ipi(cpu);
        }
    }
    if !STANDALONE.load(Ordering::Acquire) && !crate::smp_startup::active() {
        let t = unsafe { crate::sched::table() };
        if !t
            .entries
            .iter()
            .any(|p| p.is_live() && p.program != absd_kernel::program::SMP_USER as usize)
        {
            shared(32).store(1, Ordering::Release);
        }
    }
}
/// Called by the existing common wake gate while serialized. Never derives
/// another table reference while the caller holds a process borrow.
pub fn notify_process(process: &Process) {
    if !enabled() || !process.is_runnable() {
        return;
    }
    let target = crate::modern_smp::placement_of_pid(process.pid).unwrap_or_else(|| {
        (0..MAX_PROCESSES)
            .map(fixture)
            .find(|f| f.pid != 0 && f.pid == process.pid)
            .map_or(if native_app(process) { native_cpu() } else { 0 }, |f| {
                f.cpu
            })
    });
    if target != crate::cpu::id() && IDLE[target as usize].load(Ordering::Acquire) {
        if target == 1 && MUTANT.load(Ordering::Acquire) == 2 {
            return; // Deterministic omitted wake IPI.
        }
        crate::ap::send_task_ipi(target);
    }
}
pub fn idle_wait() {
    crate::smp_timer::stop();
    let cpu = crate::cpu::id() as usize;
    assert_eq!(crate::cpu::current(), crate::cpu::NO_TASK);
    if cpu > 0 {
        let (root, stack): (u64, u64);
        unsafe {
            asm!("mov {}, cr3", out(reg) root, options(nostack, preserves_flags));
            asm!("mov {}, rsp", out(reg) stack, options(nostack, preserves_flags));
        }
        unsafe extern "C" {
            static boot_pml4: u8;
        }
        assert_eq!(root, core::ptr::addr_of!(boot_pml4) as u64);
        assert!(crate::cpu::on_cpu_stack(stack));
        assert_eq!(crate::cpu::tss_rsp0(), crate::cpu::entry_stack_top());
    }
    IDLE_COUNT[cpu].fetch_add(1, Ordering::Relaxed);
    IDLE[cpu].store(true, Ordering::Release);
    crate::kernel_lock::release(cpu as u8);
    unsafe {
        asm!("sti", "hlt", "cli", options(nomem, nostack));
    }
    crate::kernel_lock::acquire(cpu as u8);
    crate::smp_measure::tag(crate::smp_measure::IDLE);
    IDLE[cpu].store(false, Ordering::Release);
}
pub fn startup_stop() {
    assert!(crate::smp_startup::active());
    shared(32).store(1, Ordering::Release);
}
pub fn startup_quiescent() -> bool {
    crate::kernel_lock::assert_held(0);
    unsafe { crate::sched::table() }.occupied_count() == 0
        && (1..crate::cpu::count()).all(|cpu| IDLE[cpu].load(Ordering::Acquire))
}
pub fn startup_clear() {
    startup_assert_fence();
    shared(32).store(0, Ordering::Release);
}
pub fn startup_assert_fence() {
    assert!(startup_quiescent());
    assert!((0..crate::cpu::count()).all(|cpu| !REQUEST[cpu].load(Ordering::Acquire)));
    assert!((0..MAX_PROCESSES).all(|i| fixture(i).pid == 0));
}
pub fn start_ap() -> ! {
    assert!(enabled());
    crate::smp_timer::start_ap();
    crate::smp_app_pressure::calibration_ready();
    crate::kernel_lock::acquire(crate::cpu::id());
    crate::smp_timer::report_start();
    crate::cpu::set_current(crate::cpu::NO_TASK);
    unsafe { ap_enter_user_idle() }
}
#[unsafe(no_mangle)]
pub extern "C" fn ap_user_idle() -> ! {
    crate::sched::idle_loop()
}
pub fn note_contention(cpu: u8) {
    if enabled() {
        CONTENTION[cpu as usize].fetch_add(1, Ordering::Relaxed);
    }
}
pub fn counters() -> ([u64; 2], [u64; 2]) {
    (
        core::array::from_fn(|i| CALLS[i].load(Ordering::Acquire)),
        core::array::from_fn(|i| CONTENTION[i].load(Ordering::Acquire)),
    )
}
pub fn contention_on(cpu: usize) -> u64 {
    CONTENTION[cpu].load(Ordering::Acquire)
}
pub fn scale_ready() {
    for i in 0..6 {
        assert_eq!(shared(110 + i).load(Ordering::Acquire), 1);
    }
    assert_eq!(shared(118).load(Ordering::Acquire), 0);
}
pub fn scale_results(phase: u64, units: u64) {
    for i in 0..6 {
        assert_eq!(
            shared(120 + i).load(Ordering::Acquire),
            units,
            "scale work shortfall"
        );
        let checksum = shared(130 + i).load(Ordering::Acquire);
        assert_eq!(
            checksum,
            if phase == 1 {
                units * (units - 1) / 2 + i as u64
            } else {
                0
            },
            "scale checksum"
        );
        crate::serial::write("SMP SCALE WORK");
        for (key, value) in [
            (" phase=", phase),
            (" index=", i as u64),
            (" units=", units),
            (" checksum=", checksum),
        ] {
            crate::serial::write(key);
            crate::serial::decimal(value);
        }
        crate::serial::write("\n");
    }
}
pub fn bench_results(phase: u64, units: u64) {
    assert_eq!(shared(116).load(Ordering::Acquire), units);
    assert_eq!(shared(117).load(Ordering::Acquire), units);
    if phase == 1 {
        for i in 0..2 {
            assert_eq!(
                shared(118 + i).load(Ordering::Acquire),
                units * (units - 1) / 2 + i as u64
            );
        }
    }
}
pub fn syscall_entry(frame: *mut u64, number: u64) {
    if !enabled() {
        return;
    }
    let cpu = crate::cpu::id();
    crate::kernel_lock::assert_held(cpu);
    let slot = crate::cpu::current();
    let p = &unsafe { crate::sched::table() }.entries[slot];
    assert_eq!(p.cpu_owner.unwrap().cpu, cpu);
    crate::modern_smp::before_block_entry(p, number);
    assert_eq!(placement(slot, p), cpu);
    let root: u64;
    unsafe {
        asm!("mov {}, cr3", out(reg) root, options(nostack, preserves_flags));
    }
    assert_eq!(root, p.address_space.root, "entry root mismatch");
    assert_eq!(unsafe { frame.add(16).read() } & 3, 3, "not a user trap");
    crate::smp_app_scale::trap(slot, p);
    crate::smp_app_pressure::bsp_trap(slot, p);
    if native_app(p) {
        assert_eq!(cpu, native_cpu());
        let previous = NATIVE_PID.compare_exchange(0, p.pid, Ordering::AcqRel, Ordering::Acquire);
        assert!(
            previous.is_ok() || previous == Err(p.pid),
            "second native AP task"
        );
        if NATIVE_CALLS.fetch_add(1, Ordering::AcqRel) == 0 {
            crate::smp_app_pressure::app_begin();
            crate::serial::write("SMP APP TRAP cpu=");
            crate::serial::decimal(cpu as u64);
            crate::serial::write(" pid=");
            crate::serial::decimal(p.pid);
            crate::serial::write(" cpl=3 cr3=owned catalog=external-workload\n");
        }
    }
    crate::smp_app_pressure::trap(slot, p, fixture(slot).role);
    let count = CALLS[cpu as usize].fetch_add(1, Ordering::Relaxed);
    if count == 0 {
        log_event("TRAP", slot, p.pid, p.cpu_owner.unwrap());
    }
}
pub fn signal_stop(slot: usize, pid: u64, claim: CpuClaim) {
    let cpu = claim.cpu as usize;
    assert!(
        !REQUEST[cpu].load(Ordering::Acquire),
        "second outstanding stop"
    );
    REQUEST_PID[cpu].store(pid, Ordering::Relaxed);
    REQUEST_SLOT[cpu].store(slot as u64, Ordering::Relaxed);
    REQUEST_EPOCH[cpu].store(claim.epoch, Ordering::Relaxed);
    REQUEST[cpu].store(true, Ordering::Release);
    log_event("REQUEST", slot, pid, claim);
    if MUTANT.load(Ordering::Acquire) == 3 {
        unsafe { crate::sched::table() }.entries[slot].depart_cpu(claim);
        log_event("ACK", slot, pid, claim); // Deliberate ownership release before hardware departure.
    }
    crate::ap::send_task_ipi(claim.cpu);
}
pub fn departure(slot: usize, claim: CpuClaim) {
    if !enabled() {
        return;
    }
    let p = &unsafe { crate::sched::table() }.entries[slot];
    if p.stop == StopState::Requested || p.stop == StopState::Observed {
        let cpu = claim.cpu as usize;
        assert!(REQUEST[cpu].load(Ordering::Acquire));
        assert_eq!(REQUEST_PID[cpu].load(Ordering::Relaxed), p.pid);
        assert_eq!(REQUEST_SLOT[cpu].load(Ordering::Relaxed), slot as u64);
        assert_eq!(REQUEST_EPOCH[cpu].load(Ordering::Relaxed), claim.epoch);
        if p.stop == StopState::Requested {
            stop_path("departure-guard", p.pid, claim);
            log_event("OBSERVE", slot, p.pid, claim);
        }
        log_event("DEPART", slot, p.pid, claim); // scheduler has checked hardware departure
        log_event("ACK", slot, p.pid, claim);
        REQUEST[cpu].store(false, Ordering::Release);
        unsafe {
            STOPS[cpu] += 1;
        }
    }
}
pub fn reclaimed(slot: usize, pid: u64, claim: CpuClaim) {
    if enabled() {
        crate::serial::write("SMP USER RECLAIM cpu=");
        crate::serial::decimal(claim.cpu as u64);
        crate::serial::write(" slot=");
        crate::serial::decimal(slot as u64);
        crate::serial::write(" pid=");
        crate::serial::decimal(pid);
        crate::serial::write(" epoch=");
        crate::serial::decimal(claim.epoch);
        crate::serial::write("\n");
        notify_runnable();
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn ap_user_kernel_enter() {
    assert!(enabled());
    crate::smp_timer::pause();
    crate::kernel_lock::acquire(crate::cpu::id());
}
#[unsafe(no_mangle)]
pub extern "C" fn ap_user_kernel_leave() {
    crate::kernel_lock::release(crate::cpu::id());
    crate::smp_timer::user_return();
}
pub fn timer_stop_observe() {
    crate::kernel_lock::assert_current_owner();
    let cpu = crate::cpu::id() as usize;
    let slot = crate::cpu::current();
    let p = &mut unsafe { crate::sched::table() }.entries[slot];
    assert_eq!(p.cpu_owner.unwrap().cpu as usize, cpu);
    if p.stop != StopState::Requested {
        return;
    }
    assert!(REQUEST[cpu].load(Ordering::Acquire));
    assert_eq!(REQUEST_PID[cpu].load(Ordering::Relaxed), p.pid);
    assert_eq!(REQUEST_SLOT[cpu].load(Ordering::Relaxed), slot as u64);
    assert_eq!(
        REQUEST_EPOCH[cpu].load(Ordering::Relaxed),
        p.cpu_owner.unwrap().epoch
    );
    stop_path("timer-stop", p.pid, p.cpu_owner.unwrap());
    log_event("OBSERVE", slot, p.pid, p.cpu_owner.unwrap());
    p.stop = StopState::Observed;
}
pub fn timer_entry(frame: *mut u64) {
    crate::smp_measure::tag(crate::smp_measure::TIMER);
    crate::kernel_lock::assert_current_owner();
    assert!(crate::cpu::id() > 0);
    let slot = crate::cpu::current();
    assert!(slot < MAX_PROCESSES);
    let p = &unsafe { crate::sched::table() }.entries[slot];
    assert_eq!(p.state, ProcessState::Running);
    assert_eq!(p.cpu_owner.unwrap().cpu, crate::cpu::id());
    assert_eq!(placement(slot, p), crate::cpu::id());
    assert!(p.class.rt().is_none(), "AP timer may not charge RT state");
    let root: u64;
    unsafe {
        asm!("mov {}, cr3", out(reg) root, options(nostack, preserves_flags));
    }
    assert_eq!(root, p.address_space.root);
    assert_eq!(unsafe { frame.add(16).read() } & 3, 3);
    if native_app(p) {
        assert_eq!(crate::cpu::id(), native_cpu());
        if !crate::smp_app_pressure::skip_native_timer(p.pid) {
            NATIVE_TIMERS.fetch_add(1, Ordering::Relaxed);
        }
    }
}
pub fn probe_switch(from: u64, to: u64) -> bool {
    let roles = unsafe { &*core::ptr::addr_of!(FIXTURES) };
    let from_role = roles.iter().find(|f| f.pid == from).map(|f| f.role);
    let to_role = roles.iter().find(|f| f.pid == to).map(|f| f.role);
    matches!(
        (from_role, to_role),
        (Some(33), Some(35)) | (Some(35), Some(33))
    ) && shared(if from_role == Some(33) { 64 } else { 65 }).load(Ordering::Acquire) == 1
}
#[unsafe(no_mangle)]
pub extern "C" fn user_stop_ipi(frame: *mut u64) {
    crate::ap::task_eoi();
    if !enabled() || unsafe { frame.add(16).read() } & 3 == 0 {
        return;
    }
    let cpu = crate::cpu::id() as usize;
    if !REQUEST[cpu].load(Ordering::Acquire) {
        return;
    }
    crate::kernel_lock::acquire(cpu as u8);
    crate::smp_measure::tag(crate::smp_measure::STOP);
    let current = crate::cpu::current();
    let p = &mut unsafe { crate::sched::table() }.entries[current];
    assert_eq!(p.pid, REQUEST_PID[cpu].load(Ordering::Relaxed));
    assert_eq!(
        p.cpu_owner.unwrap().epoch,
        REQUEST_EPOCH[cpu].load(Ordering::Relaxed)
    );
    assert_eq!(p.stop, StopState::Requested);
    stop_path("ring3-ipi", p.pid, p.cpu_owner.unwrap());
    log_event("OBSERVE", current, p.pid, p.cpu_owner.unwrap());
    p.stop = StopState::Observed;
    unsafe {
        crate::sched::switch_from_frame(frame, false);
    }
}

/// Deterministic bounded continuation: no table/allocator borrow crosses
/// release. The fixture's parent requests stop while the handler is pinned.
fn gap() {
    let cpu = crate::cpu::id();
    let slot = crate::cpu::current();
    let (pid, claim) = {
        let p = &unsafe { crate::sched::table() }.entries[slot];
        (p.pid, p.cpu_owner.unwrap())
    };
    shared(20).store(pid, Ordering::Release);
    crate::kernel_lock::release(cpu);
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    while !REQUEST[cpu as usize].load(Ordering::Acquire) {
        assert!(
            unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < 1 << 34,
            "fixture gap deadline"
        );
        core::hint::spin_loop();
    }
    crate::kernel_lock::acquire(cpu);
    let p = &mut unsafe { crate::sched::table() }.entries[slot];
    assert_eq!(p.pid, pid);
    assert_eq!(p.cpu_owner, Some(claim));
    assert_eq!(p.stop, StopState::Requested);
    stop_path("bounded-continuation", pid, claim);
    log_event("OBSERVE", slot, pid, claim);
    p.stop = StopState::Observed;
}
pub fn commit_gap(number: u64) {
    if enabled()
        && number != 0
        && NEXT_GAP[crate::cpu::id() as usize]
            .compare_exchange(number, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        gap();
    }
}
pub fn blocked_frame(p: &Process) {
    if enabled()
        && p.state == ProcessState::Waiting
        && matches!(p.wait_kind, absd_kernel::process::WaitKind::Pipe)
    {
        shared(30).store(p.pid, Ordering::Release);
    }
}
pub fn block_gap() {
    commit_gap(u64::MAX);
}
pub fn created_gap() {
    commit_gap(0xffff);
}
pub fn test_call(op: u64, a: u64, b: u64) -> i64 {
    if !enabled() {
        return ERROR_NOT_IMPLEMENTED;
    }
    let slot = crate::cpu::current();
    if crate::smp_app_scale::enabled() && op != 0 {
        return if (42..=47).contains(&op) {
            crate::smp_app_scale::call(slot, op, a, b)
        } else {
            ERROR_NOT_IMPLEMENTED
        };
    }
    if op == 12 && !standalone() {
        let t = unsafe { crate::sched::table() };
        let p = &t.entries[slot];
        if p.pid != 1 || p.program != absd_kernel::program::INIT as usize {
            return ERROR_NOT_IMPLEMENTED;
        }
        if a == 1 {
            return if crate::smp_app_pressure::enabled() {
                crate::cpu::count() as i64
            } else {
                ERROR_NOT_IMPLEMENTED
            };
        }
        if a != 0 || b != 0 {
            return ERROR_NOT_IMPLEMENTED;
        }
        let count = (0..MAX_PROCESSES)
            .filter(|&i| {
                let f = fixture(i);
                f.pid != 0
                    && (matches!(f.role, 31 | 45) || crate::smp_app_pressure::role(f.role))
                    && t.entries[i].is_live()
                    && t.entries[i].parent == absd_kernel::process::KERNEL_PARENT
            })
            .count() as u64;
        assert_eq!(count, pressure_reservation());
        if crate::smp_app_pressure::enabled() {
            let mut seen = [false; 10];
            for i in 0..MAX_PROCESSES {
                let f = fixture(i);
                if f.pid != 0 && crate::smp_app_pressure::role(f.role) {
                    let index = (f.role - 200) as usize;
                    assert!(!seen[index]);
                    seen[index] = true;
                    assert_eq!(f.cpu, crate::smp_app_pressure::placement(f.role));
                    assert_eq!(f.pid, t.entries[i].pid);
                    assert!(t.entries[i].is_live());
                }
            }
            assert!(seen[..count as usize].iter().all(|present| *present));
            let census = t.entries.iter().filter(|p| p.is_live()).count() as u64;
            assert_eq!(census, 1 + count);
            crate::serial::write("SMP APP PRESSURE RESERVE pid=1 cpus=");
            crate::serial::decimal(crate::cpu::count() as u64);
            crate::serial::write(" reserved=");
            crate::serial::decimal(count);
            crate::serial::write(" census=");
            crate::serial::decimal(census);
            crate::serial::write("\n");
        }
        return if IGNORE_RESERVATION.load(Ordering::Acquire) {
            0
        } else {
            count as i64
        };
    }
    if fixture(slot).pid == 0 || fixture(slot).role > max_role() {
        return ERROR_NOT_IMPLEMENTED;
    }
    match op {
        38 if crate::smp_bench::mode() != 0 => {
            if crate::smp_bench::scale() {
                6
            } else {
                2
            }
        }
        39 if crate::smp_bench::scale() => crate::smp_bench::short_work() as i64,
        40 if crate::smp_bench::scale() => crate::smp_bench::cpus() as i64,
        41 if crate::smp_bench::scale() => crate::smp_bench::actor(slot),
        37 if crate::smp_app_pressure::enabled() => {
            crate::smp_app_pressure::resumed(slot, &unsafe { crate::sched::table() }.entries[slot])
        }
        34 if crate::smp_nway::enabled() && fixture(slot).role == 120 => {
            if a == 1 {
                crate::serial::write(
                    "SMP USER FIXTURE FAILED role=120 error=N-way all-worker progress\n",
                );
            }
            crate::serial::write("SMP NWAY CONTROLLER FAILURE progress=");
            crate::serial::decimal(a);
            crate::serial::write("\n");
            crate::smp_nway::observer_snapshot();
            if MUTANT.load(Ordering::Acquire) == 5 {
                crate::smp_nway::serialization_refusal(a);
            }
            panic!("N-way controller reported fixture failure");
        }
        30 if crate::smp_nway::enabled() => crate::cpu::count() as i64,
        31 if crate::smp_nway::enabled() => crate::smp_nway::witness(slot, a, b),
        33 if crate::smp_nway::enabled() && matches!(fixture(slot).role, 120 | 196) => {
            crate::smp_nway::preempts(a)
        }
        35 if crate::smp_nway::enabled() && fixture(slot).role == 128 => {
            crate::smp_nway::overlap(slot)
        }
        36 if crate::smp_nway::enabled() && fixture(slot).role == 120 => {
            crate::smp_nway::compose_timers(a, b)
        }
        27 => crate::smp_fpu::enabled() as i64,
        28 if crate::smp_fpu::enabled() => crate::smp_fpu::observe(slot, a),
        29 if crate::smp_fpu::enabled() && fixture(slot).role == 66 => crate::smp_fpu::continued(a),
        19 => crate::modern_smp::enabled() as i64,
        20 if crate::modern_smp::enabled() && fixture(slot).role == controller_role() => {
            crate::modern_smp::request(a, b as u8)
        }
        21 if crate::modern_smp::enabled() && fixture(slot).role == controller_role() => {
            crate::modern_smp::arm_steal(a)
        }
        22 if crate::modern_smp::enabled() => crate::modern_smp::witness(a),
        24 if crate::modern_smp::enabled() && fixture(slot).role == controller_role() => {
            crate::modern_smp::arm_cancel(a, 2)
        }
        26 if crate::modern_smp::enabled() && fixture(slot).role == controller_role() => {
            crate::modern_smp::arm_cancel(a, 1)
        }
        23 if crate::modern_smp::enabled() && fixture(slot).role == controller_role() => {
            crate::modern_smp::verify();
            0
        }
        16 => crate::smp_bench::mode() as i64,
        17 | 18 => {
            assert!(crate::smp_bench::mode() != 0 && fixture(slot).role == 0);
            assert_eq!(unsafe { crate::sched::table() }.entries[slot].pid, 1);
            if op == 17 {
                crate::smp_bench::start(a);
            } else {
                crate::smp_bench::done(a);
            }
            0
        }
        15 => {
            if crate::smp_startup::active() {
                assert_eq!(fixture(slot).role, 31);
                crate::smp_startup::actor_failure() as i64
            } else {
                ERROR_NOT_IMPLEMENTED
            }
        }
        14 => {
            assert!(crate::smp_timer::enabled());
            assert_eq!(unsafe { crate::sched::stats() }.faults, 49);
            assert_eq!(TIMER_FAULTS.load(Ordering::Acquire), 16);
            assert_eq!(TIMER_EXITS.load(Ordering::Acquire), 16);
            crate::serial::write("SMP TIMER TERMINAL faults=16 exits=16 bsp-continued=16\n");
            0
        }
        13 => {
            assert!(crate::smp_timer::enabled());
            for i in 0..8 {
                assert!(shared(80 + i).load(Ordering::Acquire) >= 128);
                assert_eq!(shared(96 + i).load(Ordering::Acquire), 1);
            }
            crate::serial::write("SMP FAIRNESS tasks=8 cpu0=4 cpu1=4 progress=8 completed=8\n");
            0
        }
        11 => crate::smp_timer::user_irqs() as i64,
        8 => crate::smp_timer::enabled() as i64,
        9 => {
            crate::smp_timer::arm_probe();
            0
        }
        10 => {
            crate::smp_timer::verify_probe(
                shared(72).load(Ordering::Acquire),
                shared(73).load(Ordering::Acquire),
            );
            0
        }
        0 => {
            let cpu = crate::cpu::id();
            if MUTANT.load(Ordering::Acquire) == 5
                && !crate::smp_nway::enabled()
                && fixture(slot).role == 1
            {
                let p = &unsafe { crate::sched::table() }.entries[slot];
                assert_eq!(fixture(slot).pid, p.pid);
                assert_eq!(p.cpu_owner.unwrap().cpu, 0);
                assert_eq!(cpu, 0);
                crate::serial::write("SMP USER SERIALIZED CPU cpu=0 pid=");
                crate::serial::decimal(p.pid);
                crate::serial::write(" role=1 cpl=3\n");
            }
            cpu as i64
        }
        1 => {
            // A user rendezvous report is checked against kernel-owned CPU identity.
            assert_eq!(a, crate::cpu::id() as u64);
            assert!(b >= 128, "no simultaneous user progress");
            crate::serial::write("SMP USER OVERLAP cpu=");
            crate::serial::decimal(a);
            crate::serial::write(" peer_changes=");
            crate::serial::decimal(b);
            crate::serial::write("\n");
            0
        }
        2 => {
            unsafe {
                assert_eq!(a, CASES + 1, "duplicate/missing case");
                CASES += 1;
            }
            crate::serial::write("SMP USER CASE id=");
            crate::serial::decimal(a);
            crate::serial::write(" cpu=");
            crate::serial::decimal(crate::cpu::id() as u64);
            crate::serial::write("\n");
            0
        }
        3 => {
            NEXT_GAP[crate::cpu::id() as usize].store(a, Ordering::Release);
            0
        }
        4 => {
            let start = unsafe { core::arch::x86_64::_rdtsc() };
            shared(21).store(1, Ordering::Release);
            while unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < 1 << 25 {
                core::hint::spin_loop();
            }
            0
        }
        5 => {
            gap();
            0
        }
        6 => (1..crate::cpu::count()).all(|cpu| IDLE[cpu].load(Ordering::Acquire)) as i64,
        7 => {
            assert!(
                (1..crate::cpu::count()).all(|cpu| IDLE[cpu].load(Ordering::Acquire)),
                "wake did not start from AP idle"
            );
            0
        }
        _ => ERROR_NOT_IMPLEMENTED,
    }
}
pub fn finish() -> ! {
    assert_eq!(crate::cpu::id(), 0, "AP attempted machine completion");
    let t = unsafe { crate::sched::table() };
    assert_eq!(t.occupied_count(), 0, "machine completion with live AP");
    if crate::smp_bench::mode() != 1 {
        assert!(
            (1..crate::cpu::count()).all(|cpu| IDLE[cpu].load(Ordering::Acquire)),
            "AP not quiescent"
        );
    }
    assert!((0..crate::cpu::count()).all(|cpu| !REQUEST[cpu].load(Ordering::Acquire)));
    let stats = unsafe { crate::sched::stats() };
    assert_eq!(
        unsafe { crate::vm::frames() }.allocated_frames(),
        stats.frame_baseline
    );
    assert!(unsafe { crate::sched::object_tables_empty() });
    if crate::smp_app_scale::enabled() {
        crate::modern_smp::finish();
        crate::smp_app_scale::finish();
    }
    if crate::smp_bench::mode() != 0 {
        crate::modern_smp::finish();
        crate::smp_bench::finish();
    }
    crate::modern_smp::finish();
    assert_eq!(stats.init_status, Some(0));
    if crate::smp_nway::enabled() {
        assert_eq!(unsafe { CASES }, 1);
        assert_eq!(stats.faults, 2 * crate::cpu::count() as u64 - 1);
        assert_eq!(stats.kills, 17 * crate::cpu::count() as u64 - 1);
        for cpu in 0..crate::cpu::count() {
            let expected = if cpu == 0 { 16 } else { 17 };
            assert_eq!(unsafe { STOPS[cpu] }, expected);
            assert!(CALLS[cpu].load(Ordering::Acquire) > 0);
            crate::serial::write("SMP NWAY STOP CPU cpu=");
            crate::serial::decimal(cpu as u64);
            crate::serial::write(" stops=");
            crate::serial::decimal(expected);
            crate::serial::write("\n");
        }
        crate::serial::write("SMP NWAY QUIESCENCE cpus=");
        crate::serial::decimal(crate::cpu::count() as u64);
        crate::serial::write(" idle-mask=");
        crate::serial::decimal((crate::cpu::mask() & !1) as u64);
        crate::serial::write(" pending=0 contexts=0 roots=0\n");
        crate::smp_timer::report();
        crate::serial::write("SMP NWAY SUMMARY terminal=0 cases=1 resources=0\nABSD BOOT OK\n");
        crate::exit_qemu(0)
    }
    if crate::smp_fpu::enabled() {
        assert_eq!(unsafe { CASES }, 1);
        assert_eq!((unsafe { STOPS })[..2], [0, 1]);
        assert!((unsafe { STOPS })[2..].iter().all(|n| *n == 0));
        assert_eq!(stats.faults, 1);
        assert_eq!(stats.kills, 1);
        assert!(CALLS[0].load(Ordering::Acquire) > 0 && CALLS[1].load(Ordering::Acquire) > 0);
        crate::smp_fpu::finish();
        crate::smp_timer::report();
        crate::serial::write(
            "SMP FPU SUMMARY terminal=0 cases=1 faults=1 kills=1 resources=0\nABSD BOOT OK\n",
        );
        crate::exit_qemu(0)
    }
    assert!(CALLS[0].load(Ordering::Acquire) > 0 && CALLS[1].load(Ordering::Acquire) > 0);
    assert_eq!(
        unsafe { CASES },
        if crate::modern_smp::enabled() {
            25
        } else if crate::smp_timer::enabled() {
            21
        } else {
            17
        }
    );
    assert_eq!(
        (unsafe { STOPS })[..2],
        if crate::smp_timer::enabled() {
            if crate::modern_smp::enabled() {
                [1, 151]
            } else {
                [1, 135]
            }
        } else {
            [1, 7]
        }
    );
    assert!(CONTENTION[1].load(Ordering::Acquire) > 0);
    assert!(IDLE_COUNT[1].load(Ordering::Acquire) > 0);
    crate::serial::write("SMP USER SUMMARY calls0=");
    crate::serial::decimal(CALLS[0].load(Ordering::Acquire));
    crate::serial::write(" calls1=");
    crate::serial::decimal(CALLS[1].load(Ordering::Acquire));
    crate::serial::write(" contention0=");
    crate::serial::decimal(CONTENTION[0].load(Ordering::Acquire));
    crate::serial::write(" contention1=");
    crate::serial::decimal(CONTENTION[1].load(Ordering::Acquire));
    crate::serial::write(" idle0=");
    crate::serial::decimal(IDLE_COUNT[0].load(Ordering::Acquire));
    crate::serial::write(" idle1=");
    crate::serial::decimal(IDLE_COUNT[1].load(Ordering::Acquire));
    crate::serial::write(" cases=");
    crate::serial::decimal(unsafe { CASES });
    crate::serial::write(" stops0=");
    crate::serial::decimal(unsafe { STOPS[0] });
    crate::serial::write(" stops1=");
    crate::serial::decimal(unsafe { STOPS[1] });
    crate::serial::write("\n");
    crate::smp_timer::report();
    crate::serial::write("SMP USER COOPERATIVE STRUCTURAL OK\nABSD BOOT OK\n");
    crate::exit_qemu(0)
}

unsafe extern "C" {
    pub fn ap_resume_user_context(frame: *const u64, root: u64, top: u64) -> !;
    pub fn ap_enter_cpu_switch() -> !;
    pub fn ap_enter_kernel_context_and_reap() -> !;
    fn ap_enter_user_idle() -> !;
    static ap_user_syscall_stub: u8;
    static ap_user_stop_stub: u8;
    static ap_user_timer_stub: u8;
    static ap_user_spurious_stub: u8;
    static ap_user_exception_table: [u64; 32];
}
#[repr(C, packed)]
struct Gate {
    low: u16,
    selector: u16,
    options: u16,
    middle: u16,
    high: u32,
    reserved: u32,
}
pub unsafe fn install_ap_idt(idt: *mut u8) {
    unsafe {
        use absd_kernel::interrupt_vector as v;
        for vector in (0u8..32).chain([v::SYSCALL, v::AP_TIMER, v::AP_IPI, v::APIC_SPURIOUS]) {
            let address = match vector {
                v::SYSCALL => core::ptr::addr_of!(ap_user_syscall_stub) as u64,
                v::AP_IPI => core::ptr::addr_of!(ap_user_stop_stub) as u64,
                v::AP_TIMER => core::ptr::addr_of!(ap_user_timer_stub) as u64,
                v::APIC_SPURIOUS => core::ptr::addr_of!(ap_user_spurious_stub) as u64,
                _ => (*core::ptr::addr_of!(ap_user_exception_table))[usize::from(vector)],
            };
            let gate = Gate {
                low: address as u16,
                selector: 8,
                options: absd_kernel::arch::interrupt_gate_options(
                    if vector == 8 || vector == v::APIC_SPURIOUS {
                        1
                    } else if vector == v::AP_IPI {
                        2
                    } else {
                        0
                    },
                ) | if vector == v::SYSCALL { 0x6000 } else { 0 },
                middle: (address >> 16) as u16,
                high: (address >> 32) as u32,
                reserved: 0,
            };
            core::ptr::write_unaligned(idt.cast::<Gate>().add(usize::from(vector)), gate);
        }
    }
}
global_asm!(include_str!("cpu_identity.S"), include_str!("smp_epoch.S"), include_str!("ap_user.S"),
    cpu_local_bytes = const crate::cpu::LOCAL_BYTES,
    cpu_gdt = const crate::cpu::GDT_OFFSET,
    cpu_identity_id = const crate::cpu::ID_OFFSET,
    cpu_identity_ready = const crate::cpu::ID_READY_OFFSET,
    cpu_user_fpu = const crate::cpu::USER_FPU_OFFSET,
    cpu_serial_fpu = const crate::cpu::SERIAL_FPU_OFFSET,
    cpu_tss_rsp0 = const crate::cpu::TSS_RSP0_OFFSET,
    cpu_entry_stack_top = const crate::cpu::ENTRY_STACK_TOP_OFFSET,
    cpu_report_stack_top = const crate::cpu::REPORT_STACK_TOP_OFFSET,
    cpu_transition_stack_top = const crate::cpu::TRANSITION_STACK_TOP_OFFSET,
    cpu_return_frame = const crate::cpu::RETURN_FRAME_OFFSET,
    options(att_syntax));

pub fn notify_cpu(target: u8) {
    if enabled() && target != crate::cpu::id() && IDLE[target as usize].load(Ordering::Acquire) {
        crate::ap::send_task_ipi(target);
    }
}

pub fn negative_selection(cpu: u8) -> Option<usize> {
    let t = unsafe { crate::sched::table() };
    if cpu == 0
        && MUTANT.load(Ordering::Acquire) == 1
        && let Some(i) = t
            .entries
            .iter()
            .position(|p| p.cpu_owner.is_some_and(|c| c.cpu == 1))
    {
        return Some(i);
    }
    if cpu == 0
        && MUTANT.load(Ordering::Acquire) == 4
        && t.entries
            .iter()
            .any(|p| p.cpu_owner.is_some_and(|c| c.cpu == 1))
    {
        finish(); // Deliberately evaluate completion while AP owns live work.
    }
    None
}
