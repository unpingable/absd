//! Narrow opt-in 2/4/6-CPU operator runtime. BKL owns placement and evidence.
use absd_kernel::{
    operator_policy::{Lifecycle, Placement, PlacementCursor},
    process::{MAX_PROCESSES, Process, ProcessState},
};
use core::sync::atomic::{AtomicBool, Ordering};
static LIFE: Lifecycle = Lifecycle::new();
static mut CURSOR: PlacementCursor = PlacementCursor::new();
#[cfg(feature = "smp-operator-controls")]
#[unsafe(no_mangle)]
pub static SMP_OPERATOR_PEER_FAILURE_OBSERVED: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(0);
static ENABLED: AtomicBool = AtomicBool::new(false);
static OBSERVING: AtomicBool = AtomicBool::new(false);
static BSP_FATAL_ENTERED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "smp-operator-controls")]
static NO_ACK: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "smp-operator-controls")]
static INTERRUPT_START: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "smp-operator-controls")]
static MISSING_START: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "smp-operator-controls")]
static PANIC_CONTROL: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
static mut PLACEMENT: [Placement; MAX_PROCESSES] = [Placement::EMPTY; MAX_PROCESSES];
static mut TRAPPED: [bool; MAX_PROCESSES] = [false; MAX_PROCESSES];
static mut TIMED: [bool; MAX_PROCESSES] = [false; MAX_PROCESSES];
const BOUND: u64 = absd_kernel::operator_policy::RETIREMENT_BOUND_TSC;
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}
/// First operation at Rust fatal entries. Raw hardware identity avoids GDT
/// anchor assertions recursively entering panic. Default/qualification paths
/// remain unchanged. Failure is not a parked ACK and permits no reclamation.
pub fn fatal_guard() {
    if !enabled() {
        return;
    }
    fail_if_ap();
    // Observed AP failure wins before the BSP decision. Once selected, the
    // raw refusal reason stays fixed through terminal output and halt.
    check_bsp_failure(None);
    let reentered = BSP_FATAL_ENTERED.swap(true, Ordering::AcqRel);
    if !absd_kernel::operator_policy::bsp_fatal_may_report(crate::kernel_lock::owner(), reentered) {
        fatal_refusal("bsp-fatal");
    }
}

/// AP fatal entry and unexpected AP retirement both fail silently. Ordinary
/// BSP retirement must not consume the BSP fatal-entry flag.
fn fail_if_ap() {
    if !crate::cpu::raw_is_bootstrap_processor() {
        unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
        LIFE.fail(raw_apic_id(), crate::cpu::count() as u8);
        halt();
    }
}

fn raw_apic_id() -> u8 {
    (core::arch::x86_64::__cpuid(1).ebx >> 24) as u8
}
/// Valid Rust-entry backstop; never asks private identity, BKL or normal output.
pub fn raw_backstop() -> ! {
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
    fail_if_ap();
    check_bsp_failure(None);
    fatal_refusal("bsp-fatal")
}
fn validated_ap() -> u8 {
    let raw = raw_apic_id();
    let bit = Lifecycle::bit(raw, crate::cpu::count() as u8);
    if crate::cpu::raw_is_bootstrap_processor()
        || bit.is_none()
        || LIFE.attempted() & bit.unwrap_or(0) == 0
        || crate::cpu::id() != raw
    {
        raw_backstop();
    }
    raw
}
fn peer_failure() {
    if LIFE.failed() != 0 && !crate::cpu::raw_is_bootstrap_processor() {
        unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
        #[cfg(feature = "smp-operator-controls")]
        if let Some(bit) = Lifecycle::bit(raw_apic_id(), crate::cpu::count() as u8) {
            SMP_OPERATOR_PEER_FAILURE_OBSERVED.fetch_or(bit, Ordering::Release);
        }
        halt();
    }
}

/// Called before BKL acquisition assertions, before each try, after acquiring,
/// and throughout retirement. This never touches protected kernel state.
pub fn check_bsp_failure(lock_start: Option<u64>) {
    if !enabled() {
        return;
    }
    peer_failure();
    let interval = lock_start.map(|start| (start, unsafe { core::arch::x86_64::_rdtsc() }));
    if let Some(reason) =
        absd_kernel::operator_policy::retirement_refusal(LIFE.failed() != 0, interval)
        && crate::cpu::raw_is_bootstrap_processor()
    {
        fatal_refusal(reason);
    }
}

/// BSP-only terminal output, including when any AP permanently retains BKL.
/// No lock acquisition, ownership assertion, formatting or framebuffer path.
fn fatal_refusal(reason: &'static str) -> ! {
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
    crate::serial::fatal_raw(b"\n");
    #[cfg(feature = "smp-operator-controls")]
    if reason == "ap-failed" {
        match PANIC_CONTROL.load(Ordering::Acquire) {
            3 => crate::serial::fatal_raw(b"SMP OPERATOR CONTROL ap-panic-consumed=unheld\n"),
            4 => crate::serial::fatal_raw(b"SMP OPERATOR CONTROL ap-panic-consumed=held\n"),
            8 => crate::serial::fatal_raw(b"SMP OPERATOR CONTROL ap-panic-consumed=backstop\n"),
            10 => crate::serial::fatal_raw(b"SMP OPERATOR CONTROL ap-panic-consumed=held-peers\n"),
            _ => {}
        }
    }
    #[cfg(feature = "smp-operator-controls")]
    if reason == "bsp-fatal" && PANIC_CONTROL.load(Ordering::Acquire) == 6 {
        crate::serial::fatal_raw(b"SMP OPERATOR CONTROL bsp-panic-consumed=unheld\n");
    }
    crate::serial::fatal_raw(b"SMP RETIREMENT REFUSED cpu=");
    let failed = LIFE.failed();
    let cpu = if reason == "ap-failed" { failed } else { 0 };
    if cpu == 255 {
        crate::serial::fatal_raw(b"255");
    } else {
        crate::serial::fatal_raw(&[b'0' + cpu]);
    }
    crate::serial::fatal_raw(b" reason=");
    crate::serial::fatal_raw(reason.as_bytes());
    crate::serial::fatal_raw(b"\n");
    halt()
}
pub fn configure(line: &[u8]) {
    let count = match absd_kernel::operator_policy::admit_compiled_count(line) {
        Ok(None) => return,
        Ok(Some(count)) => count,
        Err(reason) => refuse(reason),
    };
    ENABLED.store(true, Ordering::Release);
    crate::cpu::configure_count(count as usize);
    #[cfg(feature = "smp-operator-controls")]
    let words = || line.split(|b| *b == b' ');
    #[cfg(feature = "smp-operator-controls")]
    NO_ACK.store(
        words().any(|w| w == b"smp-operator-retire-no-ack"),
        Ordering::Release,
    );
    #[cfg(feature = "smp-operator-controls")]
    INTERRUPT_START.store(
        words().any(|w| w == b"smp-operator-start-interrupt"),
        Ordering::Release,
    );
    crate::smp_timer::configure();
    crate::serial::write("SMP OPERATOR ADMITTED cpus=");
    crate::serial::decimal(count as u64);
    crate::serial::write(" placement=fixed global-time=CPU0\n");
    #[cfg(feature = "smp-operator-controls")]
    MISSING_START.store(
        words().any(|w| w == b"smp-operator-start-missing"),
        Ordering::Release,
    );
    #[cfg(feature = "smp-operator-controls")]
    for (word, mode, label) in [
        (b"smp-operator-ap-panic-unheld".as_slice(), 1, "unheld"),
        (b"smp-operator-ap-panic-held".as_slice(), 2, "held"),
        (b"smp-operator-ap-backstop".as_slice(), 7, "backstop"),
        (
            b"smp-operator-ap-panic-held-peers".as_slice(),
            9,
            "held-peers",
        ),
    ] {
        if words().any(|w| w == word) {
            PANIC_CONTROL.store(mode, Ordering::Release);
            crate::serial::write("SMP OPERATOR CONTROL ap-panic=");
            crate::serial::write(label);
            crate::serial::write("\n");
        }
    }
    #[cfg(feature = "smp-operator-controls")]
    if words().any(|w| w == b"smp-operator-bsp-panic-unheld") {
        PANIC_CONTROL.store(5, Ordering::Release);
        crate::serial::write("SMP OPERATOR CONTROL bsp-panic=unheld\n");
    }
}
/// One-shot control immediately after the BSP releases BKL for a real device
/// wait. Readiness excludes startup; the actual panic path is under test.
#[cfg(feature = "smp-operator-controls")]
pub fn bsp_panic_control() {
    if enabled()
        && LIFE.all_ready(crate::cpu::count() as u8)
        && crate::kernel_lock::active()
        && crate::cpu::raw_is_bootstrap_processor()
        && PANIC_CONTROL
            .compare_exchange(5, 6, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        panic!("operator BSP panic control unheld");
    }
}
/// One-shot negative control at the first AP userspace kernel entry. Every
/// operator AP task is a published native IMAGE; no table access is needed
/// on the unheld side. The real panic handler remains the subject under test.
#[cfg(feature = "smp-operator-controls")]
pub fn panic_control(held: bool) {
    if !enabled() || crate::cpu::raw_id() as usize != crate::cpu::count() - 1 {
        return;
    }
    if held
        && PANIC_CONTROL
            .compare_exchange(7, 8, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        crate::ap::operator_backstop_control();
    }
    if held && PANIC_CONTROL.load(Ordering::Acquire) == 9 {
        crate::kernel_lock::assert_current_owner();
        let table = unsafe { crate::sched::table() };
        let timed = unsafe { &*core::ptr::addr_of!(TIMED) };
        let mut peers = [None; 2];
        let mut count = 0;
        for (slot, p) in table.entries.iter().enumerate() {
            if p.state != ProcessState::Running
                || !absd_kernel::operator_policy::eligible(p)
                || !timed[slot]
            {
                continue;
            }
            let Some(claim) = p.cpu_owner else {
                continue;
            };
            if claim.cpu == 0
                || claim.cpu == 5
                || claim.epoch != p.claim_epoch
                || peers.iter().flatten().any(|&(cpu, _, _)| cpu == claim.cpu)
            {
                continue;
            }
            validate(slot, p, claim.cpu);
            peers[count] = Some((claim.cpu, p.pid, claim.epoch));
            count += 1;
            if count == 2 {
                break;
            }
        }
        if count == 2 {
            PANIC_CONTROL.store(10, Ordering::Release);
            for (cpu, pid, epoch) in peers.into_iter().flatten() {
                crate::serial::write("SMP OPERATOR CONTROL peer cpu=");
                crate::serial::decimal(cpu as u64);
                crate::serial::write(" pid=");
                crate::serial::decimal(pid);
                crate::serial::write(" epoch=");
                crate::serial::decimal(epoch);
                crate::serial::write("\n");
            }
            panic!("operator AP panic control held-peers");
        }
    }
    if PANIC_CONTROL
        .compare_exchange(
            if held { 2 } else { 1 },
            if held { 4 } else { 3 },
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
    {
        panic!("operator AP panic control held={held}");
    }
}
pub fn refuse(reason: &str) -> ! {
    crate::serial::write("SMP OPERATOR REFUSED reason=");
    crate::serial::write(reason);
    crate::serial::write("\n");
    crate::exit_qemu(1)
}
pub fn begin_users() {
    if enabled() {
        OBSERVING.store(true, Ordering::Release);
    }
}
fn record(label: &str, p: &Process, cpu: u8, epoch: u64) {
    if !OBSERVING.load(Ordering::Acquire) {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    crate::serial::write("SMP OPERATOR ");
    crate::serial::write(label);
    crate::serial::write(" cpu=");
    crate::serial::decimal(cpu as u64);
    crate::serial::write(" pid=");
    crate::serial::decimal(p.pid);
    crate::serial::write(" epoch=");
    crate::serial::decimal(epoch);
    if label == "TERMINAL" {
        crate::serial::write(" state=");
        crate::serial::write(match p.state {
            ProcessState::Exited => "exited",
            ProcessState::Faulted => "faulted",
            ProcessState::Killed => "killed",
            _ => "invalid",
        });
        crate::serial::write(" status=");
        crate::serial::signed(p.exit_status);
    }
    crate::serial::write("\n");
    if matches!(label, "TRAP" | "TIMER" | "TERMINAL") {
        crate::serial::write("SMP-OPERATOR CLOCK kind=");
        crate::serial::write(label);
        crate::serial::write(" cpu=");
        crate::serial::decimal(cpu as u64);
        crate::serial::write(" pid=");
        crate::serial::decimal(p.pid);
        crate::serial::write(" epoch=");
        crate::serial::decimal(epoch);
        crate::serial::write(" tick=");
        crate::serial::decimal(crate::sched::now());
        crate::serial::write("\n");
    }
}
pub fn publish(slot: usize, p: &Process) {
    if !enabled() {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    let cpu = unsafe {
        (&mut *core::ptr::addr_of_mut!(CURSOR)).publish(
            &mut (&mut *core::ptr::addr_of_mut!(PLACEMENT))[slot],
            p,
            crate::cpu::count() as u8,
        )
    }
    .expect("operator publication");
    record("PLACE", p, cpu, 0);
}
pub fn placement(slot: usize, p: &Process) -> u8 {
    crate::kernel_lock::assert_current_owner();
    unsafe { (&*core::ptr::addr_of!(PLACEMENT))[slot].cpu(p) }.expect("operator stale placement")
}
pub fn placement_of(p: &Process) -> u8 {
    crate::kernel_lock::assert_current_owner();
    unsafe { &*core::ptr::addr_of!(PLACEMENT) }
        .iter()
        .find_map(|pin| pin.cpu(p).ok())
        .expect("operator missing placement")
}
pub fn validate(slot: usize, p: &Process, cpu: u8) {
    crate::kernel_lock::assert_current_owner();
    unsafe { (&*core::ptr::addr_of!(PLACEMENT))[slot].validate(p, cpu) }
        .expect("operator return refused");
}
pub fn trap(slot: usize, p: &Process, timer: bool) {
    if !enabled() {
        return;
    }
    let claim = p.cpu_owner.expect("operator trap claim");
    validate(slot, p, claim.cpu);
    let seen = unsafe {
        if timer {
            &mut *core::ptr::addr_of_mut!(TIMED)
        } else {
            &mut *core::ptr::addr_of_mut!(TRAPPED)
        }
    };
    if !seen[slot] {
        seen[slot] = true;
        record(
            if timer { "TIMER" } else { "TRAP" },
            p,
            claim.cpu,
            claim.epoch,
        );
    }
}
pub fn departure(slot: usize, p: &Process, claim: absd_kernel::process::CpuClaim) {
    if enabled() && (p.is_terminal() || p.stop != absd_kernel::process::StopState::Active) {
        validate(slot, p, claim.cpu);
        record("DEPART", p, claim.cpu, claim.epoch);
    }
}
pub fn terminal(p: &Process) {
    if !enabled() || p.state == ProcessState::Created {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    let pins = unsafe { &*core::ptr::addr_of!(PLACEMENT) };
    let slot = pins
        .iter()
        .position(|pin| pin.cpu(p).is_ok())
        .expect("operator terminal placement");
    record("TERMINAL", p, pins[slot].cpu(p).unwrap(), p.claim_epoch);
}
pub fn release(slot: usize, p: &Process) {
    if !enabled() {
        return;
    }
    crate::kernel_lock::assert_current_owner();
    unsafe { (&mut *core::ptr::addr_of_mut!(PLACEMENT))[slot].retire(p.pid) }
        .expect("operator final release");
    unsafe {
        (&mut *core::ptr::addr_of_mut!(TRAPPED))[slot] = false;
        (&mut *core::ptr::addr_of_mut!(TIMED))[slot] = false;
    }
}
pub fn attempted(id: u8) {
    if enabled() {
        crate::kernel_lock::assert_held(0);
        check_bsp_failure(None);
        if !LIFE.attempt(id, crate::cpu::count() as u8) {
            raw_backstop();
        }
    }
}
pub fn suppress_start(id: u8) -> bool {
    #[cfg(feature = "smp-operator-controls")]
    {
        enabled() && id == 2 && MISSING_START.load(Ordering::Acquire)
    }
    #[cfg(not(feature = "smp-operator-controls"))]
    {
        let _ = id;
        false
    }
}
/// Negative control stops only the last AP after arming its calibration timer.
pub fn calibration_control() {
    #[cfg(feature = "smp-operator-controls")]
    if enabled()
        && INTERRUPT_START.load(Ordering::Acquire)
        && raw_apic_id() as usize == crate::cpu::count() - 1
    {
        let id = validated_ap();
        LIFE.calibrate(id, crate::cpu::count() as u8);
        loop {
            check_stop();
            core::hint::spin_loop();
        }
    }
}
pub fn ready() {
    if enabled() {
        check_stop();
        if !LIFE.ready(validated_ap(), crate::cpu::count() as u8) {
            raw_backstop();
        }
    }
}
pub fn check_stop() {
    if !enabled() {
        return;
    }
    peer_failure();
    if LIFE.stopped() && !crate::cpu::raw_is_bootstrap_processor() {
        validated_ap();
        unsafe extern "C" {
            fn ap_operator_park() -> !;
        }
        unsafe { ap_operator_park() }
    }
}
/// Executed only after CLI and the assembly pivot. No BKL, process table,
/// serial, FPU state, task accounting, allocator or task stack is touched.
#[unsafe(no_mangle)]
pub extern "C" fn ap_operator_parked() -> ! {
    peer_failure();
    let raw = validated_ap();
    crate::smp_timer::stop();
    let (root, stack, flags): (u64, u64, u64);
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) root, options(nostack, preserves_flags));
        core::arch::asm!("mov {}, rsp", out(reg) stack, options(nostack, preserves_flags));
        core::arch::asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    }
    unsafe extern "C" {
        static boot_pml4: u8;
    }
    if root != core::ptr::addr_of!(boot_pml4) as u64
        || !crate::cpu::on_cpu_stack(stack)
        || crate::cpu::tss_rsp0() != crate::cpu::entry_stack_top()
        || flags & (1 << 9) != 0
        || crate::ap::lapic_read(0x320) & (1 << 16) == 0
        || crate::ap::lapic_read(0x380) != 0
        || crate::ap::lapic_read(0x390) != 0
    {
        raw_backstop();
    }
    crate::cpu::set_current(crate::cpu::NO_TASK);
    peer_failure();
    #[cfg(feature = "smp-operator-controls")]
    if NO_ACK.load(Ordering::Acquire) && raw as usize == crate::cpu::count() - 1 {
        halt();
    }
    if !LIFE.park(raw, crate::cpu::count() as u8) {
        peer_failure();
        raw_backstop();
    }
    halt()
}
fn halt() -> ! {
    loop {
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}
/// Terminal machine fence. The BSP keeps its BKL and any recovery census
/// references throughout. A parked AP cannot reacquire or return to a task.
pub fn retire() {
    if !enabled() {
        return;
    }
    fail_if_ap();
    check_bsp_failure(None);
    if LIFE.attempted() == 0 {
        return;
    }
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }
    if crate::kernel_lock::owner() != Some(0) {
        crate::kernel_lock::acquire_for_retirement(unsafe { core::arch::x86_64::_rdtsc() });
    }
    check_bsp_failure(None);
    let first = !LIFE.stopped();
    if !LIFE.stop(crate::kernel_lock::owner()) {
        raw_backstop();
    }
    let attempted = LIFE.attempted();
    for id in 1..crate::cpu::count() {
        if attempted & !LIFE.parked() & (1 << id) != 0 {
            let _ = crate::ap::send_retirement_ipi(id as u8);
        }
    }
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    let mut reported = if first { 0 } else { LIFE.parked() };
    loop {
        check_bsp_failure(None);
        let parked = LIFE.parked();
        for id in 1..crate::cpu::count() {
            if parked & !reported & (1 << id) != 0 {
                crate::serial::write("SMP RETIREMENT PARKED cpu=");
                crate::serial::decimal(id as u64);
                crate::serial::write("\n");
                reported |= 1 << id;
            }
        }
        if LIFE.complete(crate::kernel_lock::owner(), reported) {
            break;
        }
        if unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) >= BOUND {
            check_bsp_failure(None);
            // ACKs may have arrived after this iteration's reporting snapshot.
            // Drain a freshly complete set before considering a timeout; only
            // the top-of-loop reported mask can authorize normal completion.
            let parked = LIFE.parked();
            let Some(missing) = LIFE.missing_from(parked) else {
                continue;
            };
            check_bsp_failure(None);
            crate::serial::write("SMP RETIREMENT REFUSED cpu=");
            crate::serial::decimal(missing as u64);
            crate::serial::write(" reason=missing-ack\n");
            halt();
        }
        core::hint::spin_loop();
    }
    check_bsp_failure(None);
    if first && attempted != 0 {
        crate::serial::write("SMP OPERATOR SUMMARY");
        for id in 0..crate::cpu::count() {
            crate::serial::write(" calls");
            crate::serial::decimal(id as u64);
            crate::serial::write("=");
            crate::serial::decimal(crate::smp_user::calls_on(id));
        }
        for id in 1..crate::cpu::count() {
            crate::serial::write(" contention");
            crate::serial::decimal(id as u64);
            crate::serial::write("=");
            crate::serial::decimal(crate::smp_user::contention_on(id));
            crate::serial::write(" timer");
            crate::serial::decimal(id as u64);
            crate::serial::write("=");
            crate::serial::decimal(crate::smp_timer::per_cpu_irqs(id));
        }
        crate::serial::write("\n");
    }
}
pub fn wait_ready() {
    if !enabled() {
        return;
    }
    crate::kernel_lock::assert_held(0);
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    while !LIFE.all_ready(crate::cpu::count() as u8) {
        check_bsp_failure(None);
        if LIFE.calibrating() != 0 {
            refuse("interrupted-start");
        }
        if unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) >= BOUND {
            refuse("timer-ready-timeout");
        }
        core::hint::spin_loop();
    }
    check_bsp_failure(None);
    for id in 1..crate::cpu::count() {
        crate::serial::write("SMP OPERATOR READY cpu=");
        crate::serial::decimal(id as u64);
        crate::serial::write(" timer=calibrated\n");
    }
}
