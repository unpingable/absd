//! Qualification-only local AP preemption. Global PIT time remains BSP-owned.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const VECTOR: u32 = 0xe0;
const MASK: u32 = 1 << 16;
static ENABLED: AtomicBool = AtomicBool::new(false);
static MUTANT: AtomicU64 = AtomicU64::new(0);
static INITIAL: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];
// Accepted calibration endpoints: (BSP tick A, LAPIC count A, tick B, count B).
static CALIBRATION: [[AtomicU64; 4]; crate::cpu::MAX_CPUS] =
    [const { [const { AtomicU64::new(0) }; 4] }; crate::cpu::MAX_CPUS];
static LOCAL_CALIBRATION: [[AtomicU64; 6]; crate::cpu::MAX_CPUS] =
    [const { [const { AtomicU64::new(0) }; 6] }; crate::cpu::MAX_CPUS];
pub const APP_QUANTUM_TSC: u64 = 1 << 24;
const LOCAL_SAMPLE_TSC: u64 = 1 << 25;
const MAX_SAMPLE_JITTER: u64 = 1 << 18;
static REMAINING: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];
static RUNNING: [AtomicBool; crate::cpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::cpu::MAX_CPUS];
static IRQS: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];
static USER_IRQS: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];
static SWITCHES: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];
static PROBE_IRQS: AtomicU64 = AtomicU64::new(0);
static PROBE_SWITCHES: AtomicU64 = AtomicU64::new(0);
static PROBE_PAIRS: AtomicU64 = AtomicU64::new(0);
static PROBED: AtomicBool = AtomicBool::new(false);
static ARMED: AtomicBool = AtomicBool::new(false);

/// Explicit qualification operating points; no production/RT timing claim.
fn quantum_ticks() -> u64 {
    if crate::smp_nway::enabled() { 8 } else { 2 }
}
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}
pub fn user_irqs() -> u64 {
    USER_IRQS[1].load(Ordering::Acquire)
}
pub fn per_cpu_irqs(cpu: usize) -> u64 {
    USER_IRQS[cpu].load(Ordering::Acquire)
}
pub fn configure() {
    assert!(cfg!(feature = "smp-user-test") && crate::smp_user::enabled());
    assert_eq!(crate::cpu::id(), 0);
    assert!(!ENABLED.swap(true, Ordering::AcqRel));
}
pub fn set_mutant(id: u64) {
    assert!(enabled() && crate::smp_user::standalone() && (1..=6).contains(&id));
    MUTANT.store(id, Ordering::Release);
}

/// Calibrate before taking serialization: PIT delivery must be able to run
/// on CPU0 while CPU1 waits. No task or mutable kernel reference is held here.
pub fn start_ap() {
    if !enabled() {
        return;
    }
    assert!(crate::cpu::id() > 0);
    if crate::smp_app_pressure::enabled()
        || crate::smp_bench::scale()
        || crate::smp_app_scale::enabled()
    {
        calibrate_local();
        return;
    }
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    let first = crate::sched::now();
    while crate::sched::now() == first {
        assert!(unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < 1 << 34);
        core::hint::spin_loop();
    }
    crate::ap::lapic_write(0x320, MASK | VECTOR);
    crate::ap::lapic_write(0x3e0, 3); // Divide by 16.
    crate::ap::lapic_write(0x380, u32::MAX);
    // Both endpoints observe the already-running counter within one stable
    // BSP tick. Programming/descheduling time is not included in only one
    // side of the ratio. Tick phase still bounds the calibration precision;
    // this is a local qualification quantum, not an RT timing promise.
    let (tick_a, count_a) = calibration_sample(start);
    while crate::sched::now().wrapping_sub(tick_a) < 8 {
        assert!(unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < 1 << 34);
        core::hint::spin_loop();
    }
    let (tick_b, count_b) = calibration_sample(start);
    let ticks = tick_b
        .checked_sub(tick_a)
        .expect("AP calibration tick wrap");
    let elapsed = count_a
        .checked_sub(count_b)
        .expect("AP calibration counter wrap");
    assert!(
        ticks >= 8 && elapsed > 0 && count_b > 0,
        "AP calibration empty interval"
    );
    let initial = u64::from(elapsed).checked_mul(quantum_ticks()).unwrap() / ticks;
    assert!(
        initial > 0 && initial <= u64::from(u32::MAX),
        "AP timer calibration"
    );
    for (i, value) in [tick_a, u64::from(count_a), tick_b, u64::from(count_b)]
        .into_iter()
        .enumerate()
    {
        CALIBRATION[crate::cpu::id() as usize][i].store(value, Ordering::Release);
    }
    INITIAL[crate::cpu::id() as usize].store(initial, Ordering::Release);
    stop();
}
/// Closed application operating point in local TSC units. Delivered BSP PIT
/// ticks are intentionally absent from this ratio. No wall-time/RT claim.
fn ordered_tsc() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!(
            "mfence", "lfence", "rdtsc", "lfence",
            out("eax") low, out("edx") high,
            options(nostack, preserves_flags),
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}
fn local_sample(start: u64) -> (u64, u64, u32) {
    loop {
        let before = ordered_tsc();
        assert!(
            before
                .checked_sub(start)
                .is_some_and(|delta| delta < 1 << 34)
        );
        let count = crate::ap::lapic_read(0x390);
        let after = ordered_tsc();
        assert!(
            after
                .checked_sub(start)
                .is_some_and(|delta| delta < 1 << 34)
        );
        let jitter = after
            .checked_sub(before)
            .expect("local timer TSC went backward");
        if jitter <= MAX_SAMPLE_JITTER {
            return (before, after, count);
        }
        core::hint::spin_loop();
    }
}
fn calibrate_local() {
    let start = ordered_tsc();
    crate::ap::lapic_write(0x320, MASK | VECTOR);
    crate::ap::lapic_write(0x3e0, 3);
    crate::ap::lapic_write(0x380, u32::MAX);
    let (a_before, a_after, count_a) = local_sample(start);
    loop {
        let now = ordered_tsc();
        assert!(now.checked_sub(start).is_some_and(|delta| delta < 1 << 34));
        if now
            .checked_sub(a_after)
            .expect("local sample TSC went backward")
            >= LOCAL_SAMPLE_TSC
        {
            break;
        }
        core::hint::spin_loop();
    }
    let (b_before, b_after, count_b) = local_sample(start);
    assert!(
        b_before
            .checked_sub(a_after)
            .is_some_and(|delta| delta >= LOCAL_SAMPLE_TSC),
        "local calibration endpoint order"
    );
    let midpoint_a = a_before + (a_after - a_before) / 2;
    let midpoint_b = b_before + (b_after - b_before) / 2;
    let span = midpoint_b
        .checked_sub(midpoint_a)
        .expect("local calibration TSC wrap");
    let elapsed = count_a
        .checked_sub(count_b)
        .expect("local calibration counter wrap");
    assert!(span >= LOCAL_SAMPLE_TSC && elapsed > 0 && count_b > 0);
    let initial = u64::from(elapsed).checked_mul(APP_QUANTUM_TSC).unwrap() / span;
    assert!(
        initial > 0 && initial <= u64::from(u32::MAX),
        "local AP timer calibration"
    );
    for (i, value) in [
        a_before,
        a_after,
        u64::from(count_a),
        b_before,
        b_after,
        u64::from(count_b),
    ]
    .into_iter()
    .enumerate()
    {
        LOCAL_CALIBRATION[crate::cpu::id() as usize][i].store(value, Ordering::Release);
    }
    INITIAL[crate::cpu::id() as usize].store(initial, Ordering::Release);
    stop();
}
fn calibration_sample(start: u64) -> (u64, u32) {
    loop {
        assert!(
            unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < 1 << 34,
            "AP calibration sample deadline"
        );
        let before = crate::sched::now();
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        let count = crate::ap::lapic_read(0x390);
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        let after = crate::sched::now();
        assert!(
            unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < 1 << 34,
            "AP calibration sample deadline"
        );
        if before == after {
            return (before, count);
        }
        core::hint::spin_loop();
    }
}
pub fn stop() {
    if enabled() && crate::cpu::id() > 0 {
        RUNNING[crate::cpu::id() as usize].store(false, Ordering::Release);
        crate::ap::lapic_write(0x320, MASK | VECTOR);
        crate::ap::lapic_write(0x380, 0);
    }
}
pub fn pause() {
    if enabled()
        && crate::cpu::id() > 0
        && RUNNING[crate::cpu::id() as usize].load(Ordering::Acquire)
    {
        REMAINING[crate::cpu::id() as usize]
            .store(u64::from(crate::ap::lapic_read(0x390)), Ordering::Release);
        stop();
    }
}
pub fn reset_quantum() {
    if enabled() && crate::cpu::id() > 0 {
        REMAINING[crate::cpu::id() as usize].store(
            INITIAL[crate::cpu::id() as usize].load(Ordering::Acquire),
            Ordering::Release,
        );
    }
}
/// The remaining local countdown starts at the user-return boundary, excluding
/// serialization contention and scheduler service time. A pending IRR entry
/// may survive masking; CPL0 retires it without scheduling the continuation.
pub fn user_return() {
    if enabled() && crate::cpu::id() > 0 && MUTANT.load(Ordering::Acquire) != 1 {
        if MUTANT.load(Ordering::Acquire) == 6 && PROBED.load(Ordering::Acquire) {
            reset_quantum(); // Deliberately replenish on every syscall return.
        }
        crate::ap::lapic_write(0x320, VECTOR);
        crate::ap::lapic_write(
            0x380,
            REMAINING[crate::cpu::id() as usize]
                .load(Ordering::Acquire)
                .max(1) as u32,
        );
        RUNNING[crate::cpu::id() as usize].store(true, Ordering::Release);
    }
}
pub fn report_start() {
    if enabled() {
        crate::kernel_lock::assert_current_owner();
        crate::serial::write("SMP TIMER START cpu=");
        crate::serial::decimal(crate::cpu::id() as u64);
        crate::serial::write(" vector=224 divide=16 initial=");
        crate::serial::decimal(INITIAL[crate::cpu::id() as usize].load(Ordering::Acquire));
        if crate::smp_app_pressure::enabled()
            || crate::smp_bench::scale()
            || crate::smp_app_scale::enabled()
        {
            for (i, label) in [
                " tsc-a-before=",
                " tsc-a-after=",
                " count-a=",
                " tsc-b-before=",
                " tsc-b-after=",
                " count-b=",
            ]
            .into_iter()
            .enumerate()
            {
                crate::serial::write(label);
                crate::serial::decimal(
                    LOCAL_CALIBRATION[crate::cpu::id() as usize][i].load(Ordering::Acquire),
                );
            }
            crate::serial::write(" quantum-tsc=");
            crate::serial::decimal(APP_QUANTUM_TSC);
            crate::serial::write(" sample-tsc=");
            crate::serial::decimal(LOCAL_SAMPLE_TSC);
            crate::serial::write(" max-jitter=");
            crate::serial::decimal(MAX_SAMPLE_JITTER);
            crate::serial::write(" reference=ap-local-tsc global-time=CPU0 rt-time=CPU0\n");
            return;
        }
        for (i, label) in [" tick-a=", " count-a=", " tick-b=", " count-b="]
            .into_iter()
            .enumerate()
        {
            crate::serial::write(label);
            crate::serial::decimal(
                CALIBRATION[crate::cpu::id() as usize][i].load(Ordering::Acquire),
            );
        }
        crate::serial::write(" quantum-ticks=");
        crate::serial::decimal(quantum_ticks());
        crate::serial::write(" global-time=CPU0 rt-time=CPU0\n");
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ap_user_timer(frame: *mut u64) {
    assert!(enabled());
    assert!(crate::cpu::id() > 0);
    let mutant = MUTANT.load(Ordering::Acquire);
    stop();
    if mutant != 3 {
        crate::ap::task_eoi();
    }
    IRQS[crate::cpu::id() as usize].fetch_add(1, Ordering::Relaxed);
    // Interruptible pinned waits may execute ring-0 with IF set. Retire
    // their IRQ without recursing into serialization or switching stacks.
    if unsafe { frame.add(16).read() } & 3 == 0 {
        return;
    }
    USER_IRQS[crate::cpu::id() as usize].fetch_add(1, Ordering::Relaxed);
    if mutant == 2 {
        reset_quantum();
        user_return();
        return;
    }
    crate::smp_user::ap_user_kernel_enter();
    crate::smp_user::timer_entry(frame);
    if mutant == 4 {
        crate::sched::ap_timer_rt_negative();
    }
    crate::smp_user::timer_stop_observe();
    crate::sched::user_timer_schedule(frame)
}

pub fn switched(from: u64, to: u64) {
    if enabled() {
        crate::kernel_lock::assert_current_owner();
        SWITCHES[crate::cpu::id() as usize].fetch_add(1, Ordering::Relaxed);
        if crate::cpu::id() > 0
            && ARMED.load(Ordering::Acquire)
            && crate::smp_user::probe_switch(from, to)
        {
            PROBE_PAIRS.fetch_add(1, Ordering::Relaxed);
            crate::serial::write("SMP TIMER PAIR from=");
            crate::serial::decimal(from);
            crate::serial::write(" to=");
            crate::serial::decimal(to);
            crate::serial::write(" source-loop=1\n");
        }
    }
}
pub fn arm_probe() {
    assert!(enabled() && !PROBED.load(Ordering::Acquire));
    assert!(!ARMED.swap(true, Ordering::AcqRel));
    PROBE_IRQS.store(USER_IRQS[1].load(Ordering::Acquire), Ordering::Release);
    PROBE_SWITCHES.store(SWITCHES[1].load(Ordering::Acquire), Ordering::Release);
}
pub fn restore_negative() {
    if crate::cpu::id() > 0 && ARMED.load(Ordering::Acquire) && MUTANT.load(Ordering::Acquire) == 5
    {
        // XMM15's 16-byte FXSAVE slot. Leave the control registers intact.
        unsafe {
            core::ptr::write_bytes(crate::cpu::user_fpu().cast::<u8>().add(400), 0, 16);
        }
    }
}
pub fn verify_probe(a: u64, b: u64) {
    let irqs = USER_IRQS[1].load(Ordering::Acquire) - PROBE_IRQS.load(Ordering::Acquire);
    let switches = SWITCHES[1].load(Ordering::Acquire) - PROBE_SWITCHES.load(Ordering::Acquire);
    assert_eq!((a, b), (1, 1), "AP independent preemption failed");
    assert!(
        irqs >= 3 && switches >= 3 && PROBE_PAIRS.load(Ordering::Acquire) >= 3,
        "AP involuntary switch evidence"
    );
    assert!(!PROBED.swap(true, Ordering::AcqRel));
    crate::serial::write("SMP TIMER PROOF cpu=1 tasks=2 registers=2 user-irqs=");
    crate::serial::decimal(irqs);
    crate::serial::write(" switches=");
    crate::serial::decimal(switches);
    crate::serial::write(" voluntary-traps=0\n");
}
pub fn report() {
    if !enabled() {
        return;
    }
    if crate::smp_user::standalone() && !crate::smp_fpu::enabled() && !crate::smp_nway::enabled() {
        assert!(PROBED.load(Ordering::Acquire));
    } else {
        assert!(
            USER_IRQS[1].load(Ordering::Acquire) > 0 && SWITCHES[1].load(Ordering::Acquire) > 0,
            "pressure lacked AP timer preemption"
        );
    }
    for cpu in 1..crate::cpu::count() {
        crate::serial::write("SMP TIMER SUMMARY cpu=");
        crate::serial::decimal(cpu as u64);
        crate::serial::write(" irqs=");
        crate::serial::decimal(IRQS[cpu].load(Ordering::Acquire));
        crate::serial::write(" user-irqs=");
        crate::serial::decimal(USER_IRQS[cpu].load(Ordering::Acquire));
        crate::serial::write(" switches0=");
        crate::serial::decimal(SWITCHES[0].load(Ordering::Acquire));
        crate::serial::write(" switches1=");
        crate::serial::decimal(SWITCHES[cpu].load(Ordering::Acquire));
        crate::serial::write("\n");
    }
}
