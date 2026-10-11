//! Optional closed application measurements; no exclusion or ownership change.
//! Samples are staged with the existing BKL span and credited only on its
//! eligible release. Wake elapsed subtracts its five nested child regions.
use core::sync::atomic::{AtomicBool, Ordering};

pub const STATUS: usize = 0;
pub const READ: usize = 1;
pub const WRITE: usize = 2;
pub const FROM_USER: usize = 3;
pub const TO_USER: usize = 4;
pub const WAKE: usize = 5;
const REGIONS: usize = 6;
const NAMES: [&str; REGIONS] = [
    "transfer-status",
    "ring-read",
    "ring-write",
    "copy-from",
    "copy-to",
    "wake-bookkeeping",
];
static ENABLED: AtomicBool = AtomicBool::new(false);
#[derive(Clone, Copy)]
struct Counts {
    calls: u64,
    units: u64,
    ticks: u64,
    max: u64,
}
const ZERO: Counts = Counts {
    calls: 0,
    units: 0,
    ticks: 0,
    max: 0,
};
static mut STAGED: [[Counts; REGIONS]; crate::cpu::MAX_CPUS] =
    [[ZERO; REGIONS]; crate::cpu::MAX_CPUS];
static mut COUNTS: [[Counts; REGIONS]; crate::cpu::MAX_CPUS] =
    [[ZERO; REGIONS]; crate::cpu::MAX_CPUS];
static mut OPEN: [u8; crate::cpu::MAX_CPUS] = [0; crate::cpu::MAX_CPUS];
static mut EXCLUDED: [u64; crate::cpu::MAX_CPUS] = [0; crate::cpu::MAX_CPUS];

pub fn configure() {
    assert!(crate::smp_app_scale::enabled() && cfg!(feature = "smp-user-test"));
    assert!(!ENABLED.swap(true, Ordering::AcqRel));
}
pub fn enabled() -> bool {
    cfg!(feature = "smp-user-test") && ENABLED.load(Ordering::Acquire)
}
fn add(to: &mut Counts, from: Counts) {
    to.calls = to.calls.checked_add(from.calls).unwrap();
    to.units = to.units.checked_add(from.units).unwrap();
    to.ticks = to.ticks.checked_add(from.ticks).unwrap();
    to.max = to.max.max(from.max);
}
fn child_ticks(cpu: usize) -> u64 {
    let row = unsafe { (*core::ptr::addr_of!(STAGED))[cpu] };
    row[..WAKE].iter().map(|c| c.ticks).sum()
}
pub struct Scope {
    active: bool,
    cpu: u8,
    region: usize,
    start: u64,
    children: u64,
}
impl Scope {
    pub fn begin(region: usize) -> Self {
        assert!(region < REGIONS);
        if !enabled() || crate::smp_measure::epoch() == 0 {
            return Self {
                active: false,
                cpu: 0,
                region,
                start: 0,
                children: 0,
            };
        }
        assert_eq!(crate::smp_measure::epoch(), 1);
        let cpu = crate::cpu::id();
        crate::kernel_lock::assert_held(cpu);
        let flags: u64;
        unsafe {
            core::arch::asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
            assert_eq!(flags & 0x200, 0);
            let mask = &mut (*core::ptr::addr_of_mut!(OPEN))[cpu as usize];
            assert_eq!(*mask & (1 << region), 0, "nested leaf region");
            assert_eq!(*mask & ((1 << WAKE) - 1), 0, "overlapping child regions");
            if region == WAKE {
                assert_eq!(*mask, 0, "nested wake region");
            }
            *mask |= 1 << region;
        }
        let children = if region == WAKE {
            child_ticks(cpu as usize)
        } else {
            0
        };
        Self {
            active: true,
            cpu,
            region,
            start: crate::smp_measure::clock(),
            children,
        }
    }
    pub fn finish(self, units: usize) {
        if !self.active {
            return;
        }
        let end = crate::smp_measure::clock();
        assert_eq!(crate::cpu::id(), self.cpu);
        crate::kernel_lock::assert_held(self.cpu);
        let flags: u64;
        unsafe {
            core::arch::asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
        }
        assert_eq!(flags & 0x200, 0, "leaf scope changed interrupt state");
        assert_eq!(
            crate::smp_measure::epoch(),
            1,
            "leaf scope crossed measurement boundary"
        );
        let mut ticks = end.checked_sub(self.start).unwrap();
        if self.region == WAKE {
            assert_eq!(
                unsafe { (*core::ptr::addr_of!(OPEN))[self.cpu as usize] },
                1 << WAKE
            );
            let children = child_ticks(self.cpu as usize)
                .checked_sub(self.children)
                .unwrap();
            ticks = ticks
                .checked_sub(children)
                .expect("wake child time exceeded parent");
            assert_eq!(units, 0);
        }
        let sample = Counts {
            calls: 1,
            units: units as u64,
            ticks,
            max: ticks,
        };
        unsafe {
            let mask = &mut (*core::ptr::addr_of_mut!(OPEN))[self.cpu as usize];
            assert_ne!(*mask & (1 << self.region), 0);
            *mask &= !(1 << self.region);
            add(
                &mut (*core::ptr::addr_of_mut!(STAGED))[self.cpu as usize][self.region],
                sample,
            );
            // The UP path has no Pending BKL interval. Its scopes are serial,
            // epoch-matched observations and are credited directly.
            if crate::smp_bench::cpus() == 1 {
                add(
                    &mut (*core::ptr::addr_of_mut!(COUNTS))[self.cpu as usize][self.region],
                    sample,
                );
            }
        }
    }
}
pub fn acquired(cpu: u8) {
    if !enabled() {
        return;
    }
    unsafe {
        assert_eq!((*core::ptr::addr_of!(OPEN))[cpu as usize], 0);
        (*core::ptr::addr_of_mut!(STAGED))[cpu as usize] = [ZERO; REGIONS];
    }
}
pub fn released(cpu: u8, eligible: bool, hold: u64) {
    if !enabled() {
        return;
    }
    unsafe {
        assert_eq!(
            (*core::ptr::addr_of!(OPEN))[cpu as usize],
            0,
            "leaf scope crossed BKL release"
        );
        let staged = (*core::ptr::addr_of!(STAGED))[cpu as usize];
        (*core::ptr::addr_of_mut!(STAGED))[cpu as usize] = [ZERO; REGIONS];
        if eligible {
            assert!(
                staged.iter().map(|c| c.ticks).sum::<u64>() <= hold,
                "exclusive leaf regions exceeded eligible hold"
            );
            for (region, sample) in staged.into_iter().enumerate() {
                add(
                    &mut (*core::ptr::addr_of_mut!(COUNTS))[cpu as usize][region],
                    sample,
                );
            }
        } else {
            assert_eq!(
                staged.iter().map(|c| c.units).sum::<u64>(),
                0,
                "work-bearing leaf span excluded at boundary"
            );
            (*core::ptr::addr_of_mut!(EXCLUDED))[cpu as usize] +=
                staged.iter().map(|c| c.calls).sum::<u64>();
        }
    }
}
pub fn report_config() {
    if enabled() {
        crate::serial::write(
            "SMP APP LEAF CONFIG regions=6 coverage=exclusive-completed units=successful-bytes\n",
        );
    }
}
pub fn report() {
    if !enabled() {
        return;
    }
    crate::kernel_lock::assert_held(0);
    assert_eq!(crate::smp_measure::epoch(), 0);
    let mut units = [0u64; REGIONS];
    for cpu in 0..crate::smp_bench::cpus() {
        let row = unsafe { (*core::ptr::addr_of!(COUNTS))[cpu] };
        let mut total = ZERO;
        for (i, c) in row.iter().copied().enumerate() {
            add(&mut total, c);
            units[i] += c.units;
        }
        for (i, c) in row.into_iter().chain([total]).enumerate() {
            crate::serial::write("SMP APP LEAF");
            for (name, value) in [
                (" phase=", 1),
                (" cpu=", cpu as u64),
                (" calls=", c.calls),
                (" units=", c.units),
                (" tsc=", c.ticks),
                (" max=", c.max),
                (" excluded-calls=", unsafe {
                    (*core::ptr::addr_of!(EXCLUDED))[cpu]
                }),
            ] {
                crate::serial::write(name);
                crate::serial::decimal(value);
            }
            crate::serial::write(" region=");
            crate::serial::write(if i == REGIONS { "total" } else { NAMES[i] });
            crate::serial::write("\n");
        }
    }
    assert_eq!(
        units,
        [0, 6_685_314, 6_685_314, 6_685_314, 6_685_314, 0],
        "leaf transfer byte census"
    );
}
