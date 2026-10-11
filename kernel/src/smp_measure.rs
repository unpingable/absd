//! Closed scale-test BKL interval accounting, not a tracing or locking policy.
//! An entry tag attributes the entire held interval (including scheduler work).
//! Boundary/unfinished spans and time asleep outside BKL are outside coverage.
use core::sync::atomic::{AtomicU64, Ordering};

pub const OTHER: usize = 0;
pub const GETPID: usize = 1;
pub const CELL_READ: usize = 2;
pub const CELL_TRANSITION: usize = 3;
pub const CELL_WAIT: usize = 4;
pub const SYSCALL: usize = 5;
pub const TIMER: usize = 6;
pub const FAULT: usize = 7;
pub const STOP: usize = 8;
pub const IDLE: usize = 9;
pub const DEVICE: usize = 10;
const PATHS: usize = 11;
const NAMES: [&str; PATHS] = [
    "other",
    "getpid",
    "cell-read",
    "cell-transition",
    "cell-wait",
    "syscall",
    "timer",
    "fault",
    "stop",
    "idle",
    "device-reacquire",
];
static EPOCH: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub struct Attempt {
    pub epoch: u64,
    pub start: u64,
    pub retries: u64,
    pub contended: bool,
}
#[derive(Clone, Copy)]
struct Pending {
    attempt: Attempt,
    acquired: u64,
    path: usize,
}
const EMPTY: Pending = Pending {
    attempt: Attempt {
        epoch: 0,
        start: 0,
        retries: 0,
        contended: false,
    },
    acquired: 0,
    path: OTHER,
};
#[derive(Clone, Copy, Default)]
struct Counts {
    spans: u64,
    contended: u64,
    retries: u64,
    wait: u64,
    hold: u64,
    wait_max: u64,
    hold_max: u64,
}
const ZERO: Counts = Counts {
    spans: 0,
    contended: 0,
    retries: 0,
    wait: 0,
    hold: 0,
    wait_max: 0,
    hold_max: 0,
};
// Accesses use raw copied values, never a reference across release. Pending is
// written only after CAS succeeds; all stats mutations are BKL-owned.
static mut WRONG_INJECTED: bool = false;
static mut PENDING: [Pending; crate::cpu::MAX_CPUS] = [EMPTY; crate::cpu::MAX_CPUS];
static mut COUNTS: [[[Counts; PATHS + 1]; crate::cpu::MAX_CPUS]; 3] =
    [[[ZERO; PATHS + 1]; crate::cpu::MAX_CPUS]; 3];

pub fn clock() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("lfence", "rdtsc", "lfence", out("eax") lo, out("edx") hi, options(nostack, preserves_flags));
    }
    (u64::from(hi) << 32) | u64::from(lo)
}
pub fn epoch() -> u64 {
    EPOCH.load(Ordering::Acquire)
}
pub fn begin() -> Attempt {
    let epoch = if (crate::smp_bench::scale() || crate::smp_app_scale::enabled())
        && crate::smp_bench::meter()
    {
        EPOCH.load(Ordering::Acquire)
    } else {
        0
    };
    Attempt {
        epoch,
        start: if epoch != 0 { clock() } else { 0 },
        retries: 0,
        contended: false,
    }
}
pub fn acquired(cpu: u8, attempt: Attempt) {
    if !(crate::smp_bench::scale() || crate::smp_app_scale::enabled()) || !crate::smp_bench::meter()
    {
        return;
    }
    crate::kernel_lock::assert_held(cpu);
    crate::smp_leaf_measure::acquired(cpu);
    let pending = if attempt.epoch != 0 && EPOCH.load(Ordering::Acquire) == attempt.epoch {
        Pending {
            attempt,
            acquired: clock(),
            path: OTHER,
        }
    } else {
        EMPTY
    };
    unsafe {
        core::ptr::addr_of_mut!(PENDING)
            .cast::<Pending>()
            .add(cpu as usize)
            .write(pending);
    }
}
pub fn tag(path: usize) {
    if !(crate::smp_bench::scale() || crate::smp_app_scale::enabled()) || !crate::smp_bench::meter()
    {
        return;
    }
    assert!(path < PATHS);
    let cpu = crate::cpu::id();
    crate::kernel_lock::assert_held(cpu);
    unsafe {
        let ptr = core::ptr::addr_of_mut!(PENDING)
            .cast::<Pending>()
            .add(cpu as usize);
        let mut p = ptr.read();
        let wrong = crate::smp_bench::wrong_meter_path()
            && p.attempt.epoch == 2
            && path == GETPID
            && cpu as usize == crate::smp_bench::cpus() - 1
            && !WRONG_INJECTED;
        if wrong {
            WRONG_INJECTED = true;
            crate::serial::write("SMP SCALE INJECT kind=wrong-path phase=2 cpu=");
            crate::serial::decimal(u64::from(cpu));
            crate::serial::write(" from=getpid to=other once=1\n");
        }
        p.path = if wrong { OTHER } else { path };
        ptr.write(p);
    }
}
pub fn syscall(number: u64) {
    tag(match number {
        4 => GETPID,
        11 => CELL_READ,
        12 => CELL_TRANSITION,
        14 => CELL_WAIT,
        _ => SYSCALL,
    });
}
fn add(c: &mut Counts, p: Pending, end: u64) {
    let wait = p
        .acquired
        .checked_sub(p.attempt.start)
        .expect("meter wait clock order");
    let hold = end.checked_sub(p.acquired).expect("meter hold clock order");
    c.spans += 1;
    c.contended += u64::from(p.attempt.contended);
    c.retries += p.attempt.retries;
    c.wait += wait;
    c.hold += hold;
    c.wait_max = c.wait_max.max(wait);
    c.hold_max = c.hold_max.max(hold);
}
pub fn release(cpu: u8) {
    if !(crate::smp_bench::scale() || crate::smp_app_scale::enabled()) || !crate::smp_bench::meter()
    {
        return;
    }
    // End before counter aggregation: reporting overhead is not hold time.
    let end = clock();
    unsafe {
        let ptr = core::ptr::addr_of_mut!(PENDING)
            .cast::<Pending>()
            .add(cpu as usize);
        let p = ptr.read();
        ptr.write(EMPTY);
        let eligible = p.attempt.epoch != 0 && EPOCH.load(Ordering::Acquire) == p.attempt.epoch;
        crate::smp_leaf_measure::released(
            cpu,
            eligible,
            if eligible {
                end.checked_sub(p.acquired).unwrap()
            } else {
                0
            },
        );
        if !eligible {
            return;
        }
        let row =
            &mut (*core::ptr::addr_of_mut!(COUNTS))[(p.attempt.epoch - 1) as usize][cpu as usize];
        add(&mut row[PATHS], p, end);
        if !crate::smp_bench::omit_meter_path() {
            add(&mut row[p.path], p, end);
        }
    }
}
pub fn arm(phase: u64) {
    crate::kernel_lock::assert_held(0);
    assert!((1..=3).contains(&phase));
    assert_eq!(
        EPOCH.swap(
            if crate::smp_bench::meter() { phase } else { 0 },
            Ordering::AcqRel
        ),
        0
    );
}
pub fn disarm(phase: u64) {
    crate::kernel_lock::assert_held(0);
    assert_eq!(
        EPOCH.swap(0, Ordering::AcqRel),
        if crate::smp_bench::meter() { phase } else { 0 }
    );
}
pub fn report(phase: u64) {
    crate::kernel_lock::assert_held(0);
    assert_eq!(EPOCH.load(Ordering::Acquire), 0);
    for cpu in 0..crate::smp_bench::cpus() {
        let row = unsafe { (*core::ptr::addr_of!(COUNTS))[(phase - 1) as usize][cpu] };
        let total = row[PATHS];
        let fields: [fn(Counts) -> u64; 5] = [
            |c: Counts| c.spans,
            |c: Counts| c.contended,
            |c: Counts| c.retries,
            |c: Counts| c.wait,
            |c: Counts| c.hold,
        ];
        for field in fields {
            assert_eq!(
                row[..PATHS].iter().copied().map(field).sum::<u64>(),
                field(total),
                "meter path sum mismatch"
            );
        }
        assert_eq!(
            row[..PATHS].iter().map(|c| c.wait_max).max().unwrap(),
            total.wait_max
        );
        assert_eq!(
            row[..PATHS].iter().map(|c| c.hold_max).max().unwrap(),
            total.hold_max
        );
        if crate::smp_bench::cpus() == 1 || !crate::smp_bench::meter() {
            assert_eq!(total.spans, 0);
        } else {
            assert!(total.spans > 0, "scale CPU lacked completed lock spans");
        }
        if crate::smp_bench::cpus() > 1 && crate::smp_bench::meter() && matches!(phase, 2 | 3) {
            let workers = (0..6)
                .filter(|i| i % crate::smp_bench::cpus() == cpu)
                .count() as u64;
            let (path, units) = if phase == 2 {
                (GETPID, 10_000)
            } else {
                (CELL_TRANSITION, 2_000)
            };
            assert_eq!(
                row[path].spans,
                workers * units,
                "meter path work count mismatch"
            );
        }
        for (path, c) in row.iter().copied().enumerate() {
            crate::serial::write("SMP SCALE LOCK");
            for (name, value) in [
                (" phase=", phase),
                (" cpu=", cpu as u64),
                (" spans=", c.spans),
                (" contended=", c.contended),
                (" retries=", c.retries),
                (" wait-tsc=", c.wait),
                (" hold-tsc=", c.hold),
                (" wait-max=", c.wait_max),
                (" hold-max=", c.hold_max),
            ] {
                crate::serial::write(name);
                crate::serial::decimal(value);
            }
            crate::serial::write(" path=");
            crate::serial::write(if path == PATHS { "total" } else { NAMES[path] });
            crate::serial::write("\n");
        }
    }
}
