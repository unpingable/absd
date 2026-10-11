//! Closed application qualification, not application placement policy.
//! All evidence mutations occur under the existing kernel serialization.
use absd_kernel::process::{Process, ProcessState};
use core::sync::atomic::{AtomicBool, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(false);
static BSP_MODE: AtomicBool = AtomicBool::new(false);
static STARTUP_MODE: AtomicBool = AtomicBool::new(false);
pub fn startup_mode() -> bool {
    enabled() && STARTUP_MODE.load(Ordering::Acquire)
}
static FRAME_MUTANT: AtomicBool = AtomicBool::new(false);
static REFUSAL_MUTANT: AtomicBool = AtomicBool::new(false);
static REFUSAL_INJECTED: AtomicBool = AtomicBool::new(false);
pub fn refusal_mutant() {
    assert!(bsp_mode());
    assert!(!REFUSAL_MUTANT.swap(true, Ordering::AcqRel));
}
/// Deliberately omit one generic supervised-worker accounting event. Rights
/// refusal and user-visible result are unchanged; this is not a STUCK-race
/// reproduction (the first matching worker may be graceful generation3).
pub fn omit_refusal(site: u64) -> bool {
    if !bsp_mode() || !REFUSAL_MUTANT.load(Ordering::Acquire) {
        return false;
    }
    crate::kernel_lock::assert_current_owner();
    let (pid, program, number) = unsafe { REFUSAL_ENTRY[crate::cpu::id() as usize] };
    if program != absd_kernel::program::SUPERVISED_WORKER
        || number != 12
        || site != 0
        || REFUSAL_INJECTED.swap(true, Ordering::AcqRel)
    {
        return false;
    }
    crate::serial::write("SMP BSP REFUSAL INJECT pid=");
    crate::serial::decimal(pid);
    crate::serial::write(" program=23 syscall=12 site=0 omitted=1 result=unchanged\n");
    true
}

// Sealed SMP_USER image: 15 RX + 1 RW pages; 3 upper + 3 leaf tables;
// 2 initial user-stack + 8 kernel-stack pages; 1 retained scratch leaf.
// Re-derive this test-fixture budget if that image/layout changes. Ordinary
// processes retain the suite's existing 24-frame allowance.
pub(crate) const ACTOR_FRAMES: usize = 16 + 3 + 3 + 2 + 8 + 1;
static mut FRAME_PIDS: [u64; 10] = [0; 10];
// A bounded test-only attribution receipt. Per-CPU immutable entry identity
// survives pinned lock-release waits; no handler/table borrow is re-derived.
static mut REFUSAL_ENTRY: [(u64, u64, u64); crate::cpu::MAX_CPUS] =
    [(0, 0, 0); crate::cpu::MAX_CPUS];
static mut REFUSALS: [(u64, u64, u64, u64, u64); 256] = [(0, 0, 0, 0, 0); 256];
pub fn refusal_entry(pid: u64, program: usize, number: u64) {
    if !bsp_mode() {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    unsafe { REFUSAL_ENTRY[crate::cpu::id() as usize] = (pid, program as u64, number) };
}
pub fn refusal(site: u64) {
    if !bsp_mode() {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    let (pid, program, number) = unsafe { REFUSAL_ENTRY[crate::cpu::id() as usize] };
    assert!(pid > 0 && site < 8);
    let rows = unsafe { &mut *core::ptr::addr_of_mut!(REFUSALS) };
    let index = rows
        .iter()
        .position(|row| row.0 == pid && row.1 == program && row.2 == number && row.3 == site)
        .or_else(|| rows.iter().position(|row| row.0 == 0))
        .expect("BSP refusal attribution budget");
    let row = &mut rows[index];
    if row.0 == 0 {
        *row = (pid, program, number, site, 0);
    }
    row.4 = row.4.checked_add(1).unwrap();
}
fn report_refusals() {
    crate::kernel_lock::assert_current_owner();
    let rows = unsafe { &*core::ptr::addr_of!(REFUSALS) };
    let mut events = 0;
    let mut kinds = 0;
    for row in rows.iter().filter(|r| r.0 != 0) {
        crate::serial::write("SMP BSP REFUSAL pid=");
        for (name, value) in [
            ("", row.0),
            (" program=", row.1),
            (" syscall=", row.2),
            (" site=", row.3),
            (" count=", row.4),
        ] {
            crate::serial::write(name);
            crate::serial::decimal(value);
        }
        crate::serial::write("\n");
        events += row.4;
        kinds += 1;
    }
    assert_eq!(
        events,
        unsafe { crate::sched::stats() }.handle_refusals,
        "BSP refusal attribution differs from exact counter"
    );
    crate::serial::write("SMP BSP REFUSAL SUMMARY events=");
    crate::serial::decimal(events);
    crate::serial::write(" kinds=");
    crate::serial::decimal(kinds);
    crate::serial::write(" tracked=1\n");
}

static SKIP_TIMER: AtomicBool = AtomicBool::new(false);
static TIMER_INJECTED: AtomicBool = AtomicBool::new(false);
static CALIBRATION_READY: [AtomicBool; crate::cpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::cpu::MAX_CPUS];
static CALIBRATION_RELEASE: AtomicBool = AtomicBool::new(false);
#[derive(Clone, Copy)]
struct Actor {
    pid: u64,
    generation: u64,
    calls: u64,
    preempted: bool,
    resumed: bool,
    exited: bool,
}
const EMPTY: Actor = Actor {
    pid: 0,
    generation: 0,
    calls: 0,
    preempted: false,
    resumed: false,
    exited: false,
};
static mut ACTORS: [Actor; 10] = [EMPTY; 10];
static mut BEFORE: [u64; crate::cpu::MAX_CPUS] = [0; crate::cpu::MAX_CPUS];
static mut DURING: [u64; crate::cpu::MAX_CPUS] = [0; crate::cpu::MAX_CPUS];
static mut APP_STARTED: bool = false;
static mut APP_ENDED: bool = false;
#[derive(Clone, Copy)]
struct BspObserver {
    slot: usize,
    pid: u64,
    generation: u64,
    calls: u64,
    terminal_generation: u64,
    peak_slots: usize,
    exited: bool,
}
static mut BSP: BspObserver = BspObserver {
    slot: usize::MAX,
    pid: 0,
    generation: 0,
    calls: 0,
    terminal_generation: 0,
    peak_slots: 0,
    exited: false,
};

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}
pub fn bsp_mode() -> bool {
    enabled() && BSP_MODE.load(Ordering::Acquire)
}
pub fn frame_mutant() {
    assert!(bsp_mode());
    assert!(!FRAME_MUTANT.swap(true, Ordering::AcqRel));
}
pub fn prepare_frames(p: &Process, role: u64) {
    if !bsp_mode() && !startup_mode() {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    assert!(self::role(role));
    assert_eq!(p.state, ProcessState::Created);
    assert_eq!(p.parent, absd_kernel::process::KERNEL_PARENT);
    let frames = unsafe { crate::vm::frames() }.frames_owned_by(p.pid as u32);
    let expected = ACTOR_FRAMES - usize::from(FRAME_MUTANT.load(Ordering::Acquire));
    if FRAME_MUTANT.load(Ordering::Acquire) {
        crate::serial::write("SMP BSP FRAME BUDGET INJECT expected=");
        crate::serial::decimal(expected as u64);
        crate::serial::write(" actual=");
        crate::serial::decimal(frames as u64);
        crate::serial::write("\n");
    }
    assert_eq!(frames, expected, "reserved pressure actor frame budget");
    let pids = unsafe { &mut *core::ptr::addr_of_mut!(FRAME_PIDS) };
    let index = (role - 200) as usize;
    assert!(p.pid != 0 && !pids.contains(&p.pid));
    assert_eq!(pids[index], 0);
    pids[index] = p.pid;
    crate::serial::write(if startup_mode() {
        "SMP STARTUP FRAME RESERVATION role="
    } else {
        "SMP BSP FRAME RESERVATION role="
    });
    crate::serial::decimal(role);
    crate::serial::write(" pid=");
    crate::serial::decimal(p.pid);
    crate::serial::write(" frames=");
    crate::serial::decimal(frames as u64);
    crate::serial::write("\n");
}
pub fn check_terminal_frames(p: &Process, frames: &absd_kernel::memory::FrameAllocator) {
    if (!bsp_mode() && !startup_mode())
        || p.program != absd_kernel::program::SMP_USER as usize
        || p.state == ProcessState::Created
    {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    assert!(unsafe { (*core::ptr::addr_of!(FRAME_PIDS)).contains(&p.pid) });
    assert_eq!(
        frames.frames_owned_by(p.pid as u32),
        ACTOR_FRAMES,
        "reserved pressure actor changed frame ownership"
    );
}
pub fn reserved_frames() -> usize {
    assert!(bsp_mode() || startup_mode());
    crate::kernel_lock::assert_current_owner();
    let actors = reservation() as usize;
    let pids = unsafe { &*core::ptr::addr_of!(FRAME_PIDS) };
    assert!(pids[..actors].iter().all(|pid| *pid != 0));
    assert!(pids[actors..].iter().all(|pid| *pid == 0));
    actors * ACTOR_FRAMES
}
/// The local timer has completed calibration and is masked before readiness
/// is published. No AP may claim work until the BSP observes every such fence.
pub fn calibration_ready() {
    if !enabled() {
        return;
    }
    let cpu = crate::cpu::id() as usize;
    assert!(cpu > 0 && cpu < crate::cpu::count());
    assert_eq!(crate::cpu::current(), crate::cpu::NO_TASK);
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    assert!(!CALIBRATION_READY[cpu].swap(true, Ordering::AcqRel));
    loop {
        assert!(
            unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < 1 << 34,
            "application calibration release deadline"
        );
        if CALIBRATION_RELEASE.load(Ordering::Acquire) {
            break;
        }
        core::hint::spin_loop();
    }
}
/// Keep every task unclaimed while AP-local calibration completes. The
/// existing IRQ-enabled idle wait releases serialization and
/// holds no process/table borrow; CPL0 PIT entry cannot start a user task.
pub fn calibrate_before_users() {
    if !enabled() {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    assert_eq!(crate::cpu::id(), 0);
    assert_eq!(crate::cpu::current(), crate::cpu::NO_TASK);
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    while !(1..crate::cpu::count()).all(|cpu| CALIBRATION_READY[cpu].load(Ordering::Acquire)) {
        assert!(
            unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < 1 << 34,
            "application calibration readiness deadline"
        );
        crate::kernel_lock::idle_wait();
    }
    assert!(unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < 1 << 34);
    assert!(
        unsafe { crate::sched::table() }
            .entries
            .iter()
            .all(|p| p.cpu_owner.is_none())
    );
    assert!(unsafe { (*core::ptr::addr_of!(ACTORS)).iter().all(|a| a.calls == 0) });
    assert!(!unsafe { APP_STARTED });
    crate::serial::write("SMP APP PRESSURE CALIBRATED cpus=");
    crate::serial::decimal(crate::cpu::count() as u64);
    crate::serial::write(" ready-mask=");
    crate::serial::decimal((crate::cpu::mask() & !1) as u64);
    crate::serial::write(" owners=0 actor-calls=0 phase=before-user\n");
    assert!(!CALIBRATION_RELEASE.swap(true, Ordering::AcqRel));
}
pub fn configure(app_cpu: u8, skip_timer: bool) {
    assert!((1..crate::cpu::count() as u8).contains(&app_cpu));
    configure_observer(app_cpu, false, skip_timer);
}
pub fn configure_bsp() {
    configure_observer(0, true, false);
}
pub fn configure_startup() {
    assert!(!STARTUP_MODE.swap(true, Ordering::AcqRel));
    configure_observer(0, false, false);
}
pub fn startup_ready() -> bool {
    assert!(startup_mode());
    crate::kernel_lock::assert_current_owner();
    let actors = unsafe { &*core::ptr::addr_of!(ACTORS) };
    actors[..reservation() as usize]
        .iter()
        .enumerate()
        .all(|(i, actor)| {
            actor.pid > 0 && actor.calls > 0 && (i & 1 == 0 || (actor.preempted && actor.resumed))
        })
}
fn configure_observer(app_cpu: u8, bsp: bool, skip_timer: bool) {
    assert!(crate::modern_smp::enabled() && crate::smp_timer::enabled());
    assert!(crate::smp_user::enabled() && !crate::smp_user::standalone());
    BSP_MODE.store(bsp, Ordering::Release);
    assert!(!ENABLED.swap(true, Ordering::AcqRel));
    SKIP_TIMER.store(skip_timer, Ordering::Release);
    crate::serial::write(if startup_mode() {
        "SMP STARTUP PRESSURE CONFIG cpus="
    } else if bsp {
        "SMP BSP PRESSURE CONFIG cpus="
    } else {
        "SMP APP PRESSURE CONFIG cpus="
    });
    crate::serial::decimal(crate::cpu::count() as u64);
    crate::serial::write(" reserved=");
    crate::serial::decimal(reservation());
    if startup_mode() {
        crate::serial::write(" observer=device-probe");
    } else {
        crate::serial::write(" app-cpu=");
        crate::serial::decimal(app_cpu as u64);
    }
    crate::serial::write(" quantum-tsc=");
    crate::serial::decimal(crate::smp_timer::APP_QUANTUM_TSC);
    crate::serial::write(" reference=ap-local-tsc");
    if bsp {
        crate::serial::write(" observer=init");
    }
    crate::serial::write("\n");
}
/// Bind only the real, executing INIT. The earlier exhaustion-test PID1 is
/// fully published but never enters userspace and must not bind this observer.
pub fn bsp_trap(slot: usize, p: &Process) {
    if !bsp_mode() || p.pid != 1 || p.program != absd_kernel::program::INIT as usize {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    assert_eq!(crate::cpu::id(), 0);
    assert_eq!(p.cpu_owner.unwrap().cpu, 0);
    assert_eq!(p.parent, absd_kernel::process::KERNEL_PARENT);
    assert_eq!(p.state, ProcessState::Running);
    assert!(p.class.rt().is_none());
    let generation = crate::modern_smp::generation(slot);
    let observer = unsafe { &mut *core::ptr::addr_of_mut!(BSP) };
    if observer.pid == 0 {
        assert!(generation > 0);
        observer.slot = slot;
        observer.pid = p.pid;
        observer.generation = generation;
        observer.peak_slots = reservation() as usize + 1;
        app_begin();
        crate::serial::write("SMP BSP TRAP cpu=0");
        for (name, value) in [
            (" slot=", slot as u64),
            (" pid=", p.pid),
            (" generation=", generation),
        ] {
            crate::serial::write(name);
            crate::serial::decimal(value);
        }
        crate::serial::write(" cpl=3 cr3=owned catalog=init\n");
    }
    assert_eq!(
        (observer.slot, observer.pid, observer.generation),
        (slot, p.pid, generation)
    );
    assert!(!observer.exited && observer.terminal_generation == 0);
    observer.calls = observer.calls.checked_add(1).unwrap();
}
/// Count occupied slots, including Created and terminal-unreaped instances.
/// The caller supplies the census from its existing serialized table borrow.
pub fn bsp_occupied(occupied: usize) {
    if !bsp_mode() {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    assert!(occupied <= absd_kernel::process::MAX_PROCESSES);
    let observer = unsafe { &mut *core::ptr::addr_of_mut!(BSP) };
    if observer.pid != 0 && !observer.exited {
        observer.peak_slots = observer.peak_slots.max(occupied);
    }
}
/// Capture queue generation before terminate removes registration. No table
/// reference is re-derived while the caller holds the outgoing process.
pub fn bsp_before_remove(slot: usize, p: &Process) {
    if !bsp_mode() || p.pid != 1 || p.program != absd_kernel::program::INIT as usize {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    let observer = unsafe { &mut *core::ptr::addr_of_mut!(BSP) };
    if observer.pid == 0 {
        return;
    }
    let generation = crate::modern_smp::generation(slot);
    assert_eq!(
        (observer.slot, observer.pid, observer.generation),
        (slot, p.pid, generation)
    );
    assert!(p.cpu_owner.is_none());
    assert_eq!(p.state, ProcessState::Exited);
    assert_eq!(p.exit_status, 0);
    assert!(!observer.exited && observer.terminal_generation == 0);
    observer.terminal_generation = generation;
}
/// Observe the bound INIT after its frames and handles have been released.
/// This is orchestration-lifetime evidence, not child-specific timer evidence.
pub fn bsp_after_release(slot: usize, p: &Process) {
    if !bsp_mode() || p.pid != 1 || p.program != absd_kernel::program::INIT as usize {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    let observer = unsafe { &mut *core::ptr::addr_of_mut!(BSP) };
    if observer.pid == 0 {
        return;
    }
    assert_eq!((observer.slot, observer.pid), (slot, p.pid));
    assert_eq!(observer.terminal_generation, observer.generation);
    assert!(observer.generation > 0 && observer.calls > 0 && !observer.exited);
    assert!(p.cpu_owner.is_none() && p.address_space.root == 0 && p.task.kernel_stack_base == 0);
    assert_eq!(p.state, ProcessState::Exited);
    assert_eq!(p.exit_status, 0);
    observer.exited = true;
    app_end();
}
pub fn skip_native_timer(pid: u64) -> bool {
    if !enabled() || !SKIP_TIMER.load(Ordering::Acquire) {
        return false;
    }
    crate::kernel_lock::assert_current_owner();
    if !TIMER_INJECTED.swap(true, Ordering::AcqRel) {
        crate::serial::write("SMP APP PRESSURE INJECT timer-witness-omitted=1 cpu=");
        crate::serial::decimal(crate::cpu::id() as u64);
        crate::serial::write(" pid=");
        crate::serial::decimal(pid);
        crate::serial::write("\n");
    }
    true
}
pub fn reservation() -> u64 {
    2 * (crate::cpu::count() as u64 - 1)
}
pub fn role(role: u64) -> bool {
    enabled() && (200..200 + reservation()).contains(&role)
}
pub fn placement(role: u64) -> u8 {
    assert!(self::role(role), "unknown multicore pressure role");
    ((role - 200) / 2 + 1) as u8
}
fn counts() -> [u64; crate::cpu::MAX_CPUS] {
    crate::kernel_lock::assert_current_owner();
    let mut counts = [0; crate::cpu::MAX_CPUS];
    for (i, actor) in unsafe { (*core::ptr::addr_of!(ACTORS)).iter().enumerate() } {
        counts[i / 2 + 1] += actor.calls;
    }
    counts
}
pub fn trap(slot: usize, p: &Process, role: u64) {
    if !self::role(role) {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    assert_eq!(p.parent, absd_kernel::process::KERNEL_PARENT);
    assert_eq!(p.cpu_owner.unwrap().cpu, placement(role));
    let generation = crate::modern_smp::generation(slot);
    let actor = unsafe { &mut (*core::ptr::addr_of_mut!(ACTORS))[(role - 200) as usize] };
    if actor.pid == 0 {
        *actor = Actor {
            pid: p.pid,
            generation,
            calls: 0,
            preempted: false,
            resumed: false,
            exited: false,
        };
        crate::serial::write("SMP APP PRESSURE ACTOR cpu=");
        crate::serial::decimal(placement(role) as u64);
        for (name, value) in [
            (" pid=", p.pid),
            (" generation=", generation),
            (" role=", role),
        ] {
            crate::serial::write(name);
            crate::serial::decimal(value);
        }
        crate::serial::write(" cpl=3 cr3=owned\n");
    }
    assert_eq!((actor.pid, actor.generation), (p.pid, generation));
    assert!(!actor.exited);
    actor.calls = actor.calls.checked_add(1).unwrap();
}
/// Count the inspected non-voluntary assembly interval only after its integer
/// and FXSAVE images have been saved into the task. The shared completion word
/// belongs to this closed fixture; it is not a protected general tracing ABI.
pub fn saved(slot: usize, p: &Process, preempted: bool) {
    if !enabled() || !preempted {
        return;
    }
    let role = crate::smp_user::fixture_role(slot);
    if !self::role(role) || role & 1 == 0 {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    let cpu = placement(role);
    let image = if (cpu - 1) & 1 == 0 {
        [0x1357_9bdf_2468_ace0, 0xfedc_ba98_7654_3210]
    } else {
        [0x0246_8ace_1357_9bdf, 0x0123_4567_89ab_cdef]
    };
    let live = p.task.context[3] == (0x1122_3344_5566_7788 ^ role)
        && u64::from_le_bytes(p.task.fpu.0[400..408].try_into().unwrap()) == image[0]
        && u64::from_le_bytes(p.task.fpu.0[408..416].try_into().unwrap()) == image[1];
    if !live {
        return;
    }
    assert_eq!(p.state, ProcessState::Running);
    assert!(p.task.context_valid);
    assert_eq!(p.cpu_owner.unwrap().cpu, crate::cpu::id());
    assert_eq!(crate::cpu::id(), cpu);
    assert_eq!(p.parent, absd_kernel::process::KERNEL_PARENT);
    let actor = unsafe { &mut (*core::ptr::addr_of_mut!(ACTORS))[(role - 200) as usize] };
    assert_eq!(
        (actor.pid, actor.generation),
        (p.pid, crate::modern_smp::generation(slot))
    );
    assert!(!actor.exited);
    if actor.preempted {
        return;
    }
    actor.preempted = true;
    evidence("PREEMPT", cpu, p.pid, actor.generation, role);
    crate::smp_user::pressure_preempt_publish(cpu);
}
fn evidence(kind: &str, cpu: u8, pid: u64, generation: u64, role: u64) {
    crate::serial::write("SMP APP PRESSURE ");
    crate::serial::write(kind);
    for (name, value) in [
        (" cpu=", cpu as u64),
        (" pid=", pid),
        (" generation=", generation),
        (" role=", role),
    ] {
        crate::serial::write(name);
        crate::serial::decimal(value);
    }
    crate::serial::write(" saved=1 live=1\n");
}
pub fn resumed(slot: usize, p: &Process) -> i64 {
    crate::kernel_lock::assert_current_owner();
    let role = crate::smp_user::fixture_role(slot);
    assert!(self::role(role) && role & 1 == 1);
    assert_eq!(p.state, ProcessState::Running);
    assert_eq!(p.cpu_owner.unwrap().cpu, placement(role));
    assert_eq!(crate::cpu::id(), placement(role));
    let actor = unsafe { &mut (*core::ptr::addr_of_mut!(ACTORS))[(role - 200) as usize] };
    assert_eq!(
        (actor.pid, actor.generation),
        (p.pid, crate::modern_smp::generation(slot))
    );
    assert!(actor.preempted && !actor.resumed && !actor.exited);
    actor.resumed = true;
    evidence("RESUME", placement(role), p.pid, actor.generation, role);
    if startup_mode() && role == 201 && crate::smp_startup::actor_failure() {
        crate::serial::write("SMP STARTUP INJECT role=201 resume-result=refused\n");
        return -1;
    }
    0
}
pub fn terminal(p: &Process, role: u64) {
    if !self::role(role) || p.state == ProcessState::Created {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    assert!(p.cpu_owner.is_none());
    assert_eq!(p.state, ProcessState::Exited);
    assert_eq!(p.exit_status, 0, "pressure actor terminal status");
    let actor = unsafe { &mut (*core::ptr::addr_of_mut!(ACTORS))[(role - 200) as usize] };
    assert_eq!(actor.pid, p.pid);
    assert!(actor.calls > 0 && !actor.exited);
    if role & 1 == 1 {
        assert!(
            actor.preempted && actor.resumed,
            "pressure actor lacked saved timer/resume witness"
        );
    }
    actor.exited = true;
}
pub fn app_begin() {
    if !enabled() {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    unsafe {
        assert!(!APP_STARTED && !APP_ENDED);
        BEFORE = counts();
        APP_STARTED = true;
    }
}
pub fn app_end() {
    if !enabled() {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    let after = counts();
    unsafe {
        assert!(APP_STARTED && !APP_ENDED);
        for cpu in 1..crate::cpu::count() {
            DURING[cpu] = after[cpu].checked_sub(BEFORE[cpu]).unwrap();
            assert!(
                DURING[cpu] > 0,
                "AP pressure absent during observed interval"
            );
        }
        APP_ENDED = true;
    }
}
pub fn report() {
    if !enabled() {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    assert!(unsafe { APP_STARTED && APP_ENDED });
    let counts = counts();
    for cpu in 1..crate::cpu::count() {
        for index in 2 * (cpu - 1)..2 * cpu {
            let actor = unsafe { (*core::ptr::addr_of!(ACTORS))[index] };
            assert!(actor.pid > 0 && actor.generation > 0 && actor.calls > 0 && actor.exited);
        }
        crate::serial::write(if startup_mode() {
            "SMP STARTUP PRESSURE CPU cpu="
        } else {
            "SMP APP PRESSURE CPU cpu="
        });
        crate::serial::decimal(cpu as u64);
        crate::serial::write(" actors=2 calls=");
        crate::serial::decimal(counts[cpu]);
        crate::serial::write(if startup_mode() {
            " probe-calls="
        } else {
            " app-calls="
        });
        crate::serial::decimal(unsafe { DURING[cpu] });
        crate::serial::write(" exited=2 departed=2\n");
    }
    if bsp_mode() {
        let observer = unsafe { *core::ptr::addr_of!(BSP) };
        assert!(observer.exited && observer.calls > 0);
        assert_eq!(observer.terminal_generation, observer.generation);
        crate::serial::write("SMP BSP SUMMARY cpu=0");
        for (name, value) in [
            (" slot=", observer.slot as u64),
            (" pid=", observer.pid),
            (" generation=", observer.generation),
            (" calls=", observer.calls),
            (" peak-slots=", observer.peak_slots as u64),
        ] {
            crate::serial::write(name);
            crate::serial::decimal(value);
        }
        crate::serial::write(" exited=1 faults=0 departed=1\n");
        report_refusals();
    }
}
