//! Fixed-work qualification measurements; no placement API or policy change.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
static MODE: AtomicU64 = AtomicU64::new(0);
static PHASE: AtomicU64 = AtomicU64::new(0);
static WAIT: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];
static DISPATCH: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];
static PREEMPT: [AtomicU64; crate::cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS];
static mut START: (u64, [u64; 10]) = (0, [0; 10]);
pub fn mode() -> u64 {
    MODE.load(Ordering::Acquire)
}
pub fn configure(up: bool, scale: bool, meter_off: bool, control: u64) {
    assert!(cfg!(feature = "smp-user-test") && crate::smp_user::enabled());
    assert_eq!(MODE.swap(if up { 1 } else { 2 }, Ordering::AcqRel), 0);
    SCALE.store(scale, Ordering::Release);
    METER.store(scale && !meter_off, Ordering::Release);
    CONTROL.store(control, Ordering::Release);
}
pub fn waited(cpu: u8, cycles: u64) {
    WAIT[cpu as usize].fetch_add(cycles, Ordering::Relaxed);
}
pub fn dispatch() {
    if mode() != 0 {
        DISPATCH[crate::cpu::id() as usize].fetch_add(1, Ordering::Relaxed);
    }
}
pub fn preempt() {
    if mode() != 0 {
        PREEMPT[crate::cpu::id() as usize].fetch_add(1, Ordering::Relaxed);
    }
}
fn counters() -> [u64; 10] {
    let (calls, contention) = crate::smp_user::counters();
    [
        calls[0],
        calls[1],
        contention[0],
        contention[1],
        WAIT[0].load(Ordering::Acquire),
        WAIT[1].load(Ordering::Acquire),
        DISPATCH[0].load(Ordering::Acquire),
        DISPATCH[1].load(Ordering::Acquire),
        PREEMPT[0].load(Ordering::Acquire),
        PREEMPT[1].load(Ordering::Acquire),
    ]
}
pub fn start(phase: u64) {
    if scale() {
        scale_start(phase);
        return;
    }
    assert!(mode() != 0 && (1..=3).contains(&phase));
    assert_eq!(PHASE.swap(phase, Ordering::AcqRel), phase - 1);
    crate::serial::write("SMP BENCH START phase=");
    crate::serial::decimal(phase);
    crate::serial::write(" vcpus=");
    crate::serial::decimal(mode());
    crate::serial::write("\n");
    unsafe {
        START = (core::arch::x86_64::_rdtsc(), counters());
    }
}
pub fn done(phase: u64) {
    if scale() {
        scale_done(phase);
        return;
    }
    assert_eq!(PHASE.load(Ordering::Acquire), phase);
    let elapsed = unsafe { core::arch::x86_64::_rdtsc().wrapping_sub(START.0) };
    let after = counters();
    let before = unsafe { START.1 };
    let units = match phase {
        1 => 1 << 26,
        2 => 10_000,
        3 => 2_000,
        _ => panic!("benchmark phase"),
    };
    crate::smp_user::bench_results(phase, units);
    crate::serial::write("SMP BENCH DONE phase=");
    crate::serial::decimal(phase);
    crate::serial::write(" vcpus=");
    crate::serial::decimal(mode());
    crate::serial::write(" units=");
    crate::serial::decimal(units * 2);
    crate::serial::write(" tsc=");
    crate::serial::decimal(elapsed);
    for (name, index) in [
        (" calls0=", 0),
        (" calls1=", 1),
        (" contention0=", 2),
        (" contention1=", 3),
        (" wait-tsc0=", 4),
        (" wait-tsc1=", 5),
        (" dispatch0=", 6),
        (" dispatch1=", 7),
        (" preempt0=", 8),
        (" preempt1=", 9),
    ] {
        crate::serial::write(name);
        crate::serial::decimal(after[index].wrapping_sub(before[index]));
    }
    crate::serial::write("\n");
}
pub fn finish() {
    if scale() {
        scale_finish();
    }
    assert_eq!(PHASE.load(Ordering::Acquire), 3);
    let stats = unsafe { crate::sched::stats() };
    assert_eq!(stats.init_status, Some(0));
    assert_eq!(
        (
            stats.spawns,
            stats.exits,
            stats.faults,
            stats.kills,
            stats.reaps
        ),
        (7, 7, 0, 0, 7)
    );
    if mode() == 2 {
        assert!(crate::smp_timer::user_irqs() > 0);
    }
    crate::serial::write("SMP BENCH OK phases=3 tasks=6 work=exact reclaimed=1\nABSD BOOT OK\n");
    crate::exit_qemu(0)
}

static SCALE: AtomicBool = AtomicBool::new(false);
static METER: AtomicBool = AtomicBool::new(false);
static CONTROL: AtomicU64 = AtomicU64::new(0);
static mut SCALE_START: (u64, [[u64; 4]; crate::cpu::MAX_CPUS]) =
    (0, [[0; 4]; crate::cpu::MAX_CPUS]);
static mut ACTORS: [u8; 3] = [0; 3];
pub fn scale() -> bool {
    SCALE.load(Ordering::Acquire)
}
pub fn meter() -> bool {
    METER.load(Ordering::Acquire) || crate::smp_app_scale::enabled()
}
pub fn omit_meter_path() -> bool {
    CONTROL.load(Ordering::Acquire) == 1
}
pub fn wrong_meter_path() -> bool {
    CONTROL.load(Ordering::Acquire) == 3
}
pub fn short_work() -> bool {
    CONTROL.load(Ordering::Acquire) == 2
}
pub fn cpus() -> usize {
    if mode() == 1 { 1 } else { crate::cpu::count() }
}
fn snapshot() -> [[u64; 4]; crate::cpu::MAX_CPUS] {
    core::array::from_fn(|cpu| {
        if cpu >= cpus() {
            [0; 4]
        } else {
            [
                crate::smp_user::calls_on(cpu),
                crate::smp_user::contention_on(cpu),
                DISPATCH[cpu].load(Ordering::Acquire),
                PREEMPT[cpu].load(Ordering::Acquire),
            ]
        }
    })
}
pub fn actor(slot: usize) -> i64 {
    assert!(scale());
    let role = crate::smp_user::fixture_role(slot);
    assert!((300..=317).contains(&role));
    let phase = (role - 300) / 6 + 1;
    let index = (role - 300) % 6;
    let cpu = crate::cpu::id();
    assert_eq!(cpu as usize, index as usize % cpus());
    let p = &unsafe { crate::sched::table() }.entries[slot];
    assert_eq!(p.cpu_owner.unwrap().cpu, cpu);
    unsafe {
        let seen = &mut (*core::ptr::addr_of_mut!(ACTORS))[(phase - 1) as usize];
        assert_eq!(*seen & (1 << index), 0);
        *seen |= 1 << index;
    }
    crate::serial::write("SMP SCALE ACTOR");
    for (key, value) in [
        (" phase=", phase),
        (" index=", index),
        (" role=", role),
        (" cpu=", u64::from(cpu)),
        (" pid=", p.pid),
        (
            " generation=",
            if crate::modern_smp::enabled() {
                crate::modern_smp::generation(slot)
            } else {
                0
            },
        ),
        (" cpl=", 3),
    ] {
        crate::serial::write(key);
        crate::serial::decimal(value);
    }
    crate::serial::write("\n");
    0
}
fn scale_start(phase: u64) {
    crate::kernel_lock::assert_held(0);
    assert!((1..=3).contains(&phase));
    assert_eq!(PHASE.swap(phase, Ordering::AcqRel), phase - 1);
    assert_eq!(unsafe { ACTORS[(phase - 1) as usize] }, 63);
    crate::smp_user::scale_ready();
    if phase == 1 {
        crate::serial::write(
            "SMP SCALE CONFIG workers=6 phases=3 clock=guest-tsc coverage=completed-spans scheduling=",
        );
        crate::serial::write(if mode() == 1 {
            "up-scan"
        } else {
            "per-cpu-queues"
        });
        for (key, value) in [
            (" vcpus=", cpus() as u64),
            (" meter=", u64::from(meter())),
            (" control=", CONTROL.load(Ordering::Acquire)),
        ] {
            crate::serial::write(key);
            crate::serial::decimal(value);
        }
        crate::serial::write("\n");
    }
    crate::serial::write("SMP SCALE START");
    for (key, value) in [
        (" phase=", phase),
        (" vcpus=", cpus() as u64),
        (" workers=", 6),
    ] {
        crate::serial::write(key);
        crate::serial::decimal(value);
    }
    crate::serial::write("\n");
    unsafe {
        SCALE_START = (crate::smp_measure::clock(), snapshot());
    }
    crate::smp_measure::arm(phase);
}
fn scale_done(phase: u64) {
    crate::kernel_lock::assert_held(0);
    assert_eq!(PHASE.load(Ordering::Acquire), phase);
    let elapsed = crate::smp_measure::clock()
        .checked_sub(unsafe { SCALE_START.0 })
        .unwrap();
    crate::smp_measure::disarm(phase);
    let units = match phase {
        1 => 1 << 26,
        2 => 10_000,
        3 => 2_000,
        _ => panic!("scale phase"),
    };
    crate::smp_user::scale_results(phase, units);
    let stats = unsafe { crate::sched::stats() };
    assert_eq!(
        (stats.spawns, stats.exits, stats.reaps),
        (1 + 6 * phase, 6 * phase, 6 * phase)
    );
    assert_eq!(unsafe { crate::sched::table() }.occupied_count(), 1);
    let before = unsafe { SCALE_START.1 };
    let after = snapshot();
    for cpu in 0..cpus() {
        let delta: [u64; 4] =
            core::array::from_fn(|i| after[cpu][i].checked_sub(before[cpu][i]).unwrap());
        assert!(delta[0] > 0 && delta[2] > 0);
        if phase == 1 && cpu > 0 {
            assert!(delta[3] > 0, "scale compute lacked local preemption");
        }
        crate::serial::write("SMP SCALE CPU");
        for (key, value) in [
            (" phase=", phase),
            (" cpu=", cpu as u64),
            (" calls=", delta[0]),
            (" cas-retries=", delta[1]),
            (" dispatch=", delta[2]),
            (" preempt=", delta[3]),
        ] {
            crate::serial::write(key);
            crate::serial::decimal(value);
        }
        crate::serial::write("\n");
    }
    crate::smp_measure::report(phase);
    crate::serial::write("SMP SCALE DONE");
    for (key, value) in [
        (" phase=", phase),
        (" vcpus=", cpus() as u64),
        (" units=", units * 6),
        (" tsc=", elapsed),
    ] {
        crate::serial::write(key);
        crate::serial::decimal(value);
    }
    crate::serial::write("\n");
}
fn scale_finish() -> ! {
    assert_eq!(PHASE.load(Ordering::Acquire), 3);
    let stats = unsafe { crate::sched::stats() };
    assert_eq!(stats.init_status, Some(0));
    assert_eq!(
        (
            stats.spawns,
            stats.exits,
            stats.faults,
            stats.kills,
            stats.reaps
        ),
        (19, 19, 0, 0, 19)
    );
    crate::serial::write(
        "SMP SCALE OK phases=3 workers=6 tasks=18 work=exact table=empty objects=empty frames=baseline ap=idle\nABSD BOOT OK\n",
    );
    crate::exit_qemu(0)
}
