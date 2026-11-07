//! Fixed operator placement and boot admission, shared with host tests.
use crate::{
    acpi::{Cpu, CpuKind},
    process::{Process, ProcessState},
};

pub const RETIREMENT_BOUND_TSC: u64 = 1 << 34;

/// Normal fatal diagnostics need BSP ownership and are never reentrant.
/// AP failure priority is checked before this BSP-only decision.
pub fn bsp_fatal_may_report(owner: Option<u8>, reentered: bool) -> bool {
    owner == Some(0) && !reentered
}

/// Failure never grants ownership or a parked ACK. The optional interval is
/// only for retirement's BKL acquisition, not ordinary scheduling latency.
pub fn retirement_refusal(ap_failed: bool, lock_wait: Option<(u64, u64)>) -> Option<&'static str> {
    if ap_failed {
        Some("ap-failed")
    } else if lock_wait.is_some_and(|(start, now)| now.wrapping_sub(start) >= RETIREMENT_BOUND_TSC)
    {
        Some("lock-timeout")
    } else {
        None
    }
}

/// The runtime and feature-enabled host regressions use the same build gate.
/// No request leaves the normal UP boot path unchanged, even in test builds.
pub fn admit_compiled(line: &[u8]) -> Result<bool, &'static str> {
    Ok(admit_compiled_count(line)?.is_some())
}
pub fn admit_compiled_count(line: &[u8]) -> Result<Option<u8>, &'static str> {
    let count = admit_count(
        line,
        cfg!(feature = "smp-operator"),
        cfg!(feature = "frame-admission-v0"),
        cfg!(feature = "smp-operator-controls"),
    )?;
    if count.is_none() {
        return Ok(None);
    }
    if cfg!(any(
        feature = "spawn-image-rollback-test",
        feature = "smp-user-test",
        feature = "frame-reservation-experiment",
        feature = "native-pcm-experiment",
        feature = "block-read-only",
        feature = "builder-large-envelope"
    )) {
        return Err("conflicting-build");
    }
    Ok(count)
}

pub fn admit(line: &[u8], build: bool, frames: bool, controls: bool) -> Result<bool, &'static str> {
    Ok(admit_count(line, build, frames, controls)?.is_some())
}
pub fn admit_count(
    line: &[u8],
    build: bool,
    frames: bool,
    controls: bool,
) -> Result<Option<u8>, &'static str> {
    let words = || line.split(|b| *b == b' ').filter(|w| !w.is_empty());
    if !words().any(|w| w.starts_with(b"smp-operator")) {
        return Ok(None);
    }
    if !build || !frames {
        return Err("build-gate");
    }
    let mut words_iter = words();
    let mode = words_iter.next().ok_or("mode")?;
    let digits = mode.strip_prefix(b"durable=").ok_or("mode")?;
    if digits.is_empty() || digits.len() > 19 || !digits.iter().all(u8::is_ascii_digit) {
        return Err("mode");
    }
    let step = digits
        .iter()
        .try_fold(0u64, |n, b| {
            n.checked_mul(10)?.checked_add(u64::from(*b - b'0'))
        })
        .ok_or("mode")?;
    if step > crate::program::INIT_STEP_MAX {
        return Err("mode");
    }
    let mut count = None;
    for word in words_iter {
        if let Some(value) = word.strip_prefix(b"smp-operator=") {
            let n = match value {
                b"2" => 2,
                b"4" => 4,
                b"6" => 6,
                _ => return Err("option"),
            };
            if count.replace(n).is_some() {
                return Err("duplicate");
            }
        }
        let allowed = matches!(
            word,
            b"net"
                | b"fsd"
                | b"served"
                | b"smp-operator=2"
                | b"smp-operator=4"
                | b"smp-operator=6"
                | b"acpi-reset-qemu"
                | b"acpi"
                | b"acpi-poweroff"
                | b"halt-on-exit"
                | b"nvme-write=absd"
        ) || (controls
            && matches!(
                word,
                b"smp-operator-retire-no-ack"
                    | b"smp-operator-start-interrupt"
                    | b"smp-operator-ap-panic-held"
                    | b"smp-operator-ap-panic-unheld"
                    | b"smp-operator-bsp-panic-unheld"
                    | b"smp-operator-start-missing"
                    | b"smp-operator-ap-backstop"
                    | b"smp-operator-ap-panic-held-peers"
            ));
        if !allowed {
            return Err("option");
        }
        if words().filter(|w| *w == word).count() != 1 {
            return Err("duplicate");
        }
    }
    for required in [b"net".as_slice(), b"fsd", b"served"] {
        if !words().any(|w| w == required) {
            return Err("required-option");
        }
    }
    if words()
        .filter(|w| {
            matches!(
                *w,
                b"smp-operator-retire-no-ack"
                    | b"smp-operator-start-interrupt"
                    | b"smp-operator-ap-panic-held"
                    | b"smp-operator-ap-panic-unheld"
                    | b"smp-operator-bsp-panic-unheld"
                    | b"smp-operator-start-missing"
                    | b"smp-operator-ap-backstop"
                    | b"smp-operator-ap-panic-held-peers"
            )
        })
        .count()
        > 1
    {
        return Err("conflicting-controls");
    }
    let count = count.ok_or("required-option")?;
    if (words().any(|w| w == b"smp-operator-start-missing") && count == 2)
        || (words().any(|w| w == b"smp-operator-ap-panic-held-peers") && count != 6)
    {
        return Err("control-count");
    }
    Ok(Some(count))
}

pub fn topology(
    cpus: &[Cpu],
    bsp: u32,
    madt_base: u64,
    msr_base: u64,
    count: usize,
) -> Result<(), &'static str> {
    if !matches!(count, 2 | 4 | 6)
        || bsp != 0
        || madt_base != msr_base
        || madt_base == 0
        || cpus.len() != count
    {
        return Err("topology");
    }
    let mut ids = 0u8;
    for (i, cpu) in cpus.iter().enumerate() {
        if cpu.kind != CpuKind::Xapic
            || cpu.flags != 1
            || cpu.apic >= count as u32
            || cpus[..i]
                .iter()
                .any(|prior| prior.apic == cpu.apic || prior.uid == cpu.uid)
        {
            return Err("topology");
        }
        ids |= 1 << cpu.apic;
    }
    if ids != (1 << count) - 1 {
        return Err("topology");
    }
    Ok(())
}
pub fn eligible(p: &Process) -> bool {
    p.program == crate::program::IMAGE as usize
        && p.class.rt().is_none()
        && !p.handles.has_bsp_authority()
}
#[derive(Clone, Copy)]
pub struct Placement {
    pid: u64,
    cpu: u8,
}
impl Placement {
    pub const EMPTY: Self = Self { pid: 0, cpu: 0 };
    pub fn publish(&mut self, p: &Process) -> Result<u8, &'static str> {
        self.publish_to(p, u8::from(eligible(p)), 2)
    }
    pub fn publish_to(&mut self, p: &Process, target: u8, count: u8) -> Result<u8, &'static str> {
        if !matches!(count, 2 | 4 | 6) || target >= count || (target != 0) != eligible(p) {
            return Err("target");
        }
        // Construction authority is complete before Runnable publication.
        if self.pid != 0 || p.pid == 0 || p.state != ProcessState::Created {
            return Err("publication");
        }
        self.pid = p.pid;
        self.cpu = target;
        Ok(self.cpu)
    }
    pub fn cpu(&self, p: &Process) -> Result<u8, &'static str> {
        if self.pid == 0 || self.pid != p.pid {
            return Err("stale-pid");
        }
        Ok(self.cpu)
    }
    pub fn validate(&self, p: &Process, cpu: u8) -> Result<(), &'static str> {
        if self.cpu(p)? != cpu {
            return Err("placement");
        }
        if p.cpu_owner.is_some_and(|claim| {
            claim.cpu != cpu || claim.epoch == 0 || claim.epoch != p.claim_epoch
        }) {
            return Err("stale-claim");
        }
        if cpu != 0 && !eligible(p) {
            return Err("authority");
        }
        Ok(())
    }
    pub fn retire(&mut self, pid: u64) -> Result<(), &'static str> {
        if self.pid == 0 || self.pid != pid {
            return Err("stale-pid");
        }
        *self = Self::EMPTY;
        Ok(())
    }
}

/// BSP-owned publication cursor. A rejected or pinned publication consumes no AP.
pub struct PlacementCursor(u8);
impl Default for PlacementCursor {
    fn default() -> Self {
        Self::new()
    }
}
impl PlacementCursor {
    pub const fn new() -> Self {
        Self(1)
    }
    pub fn publish(
        &mut self,
        pin: &mut Placement,
        p: &Process,
        count: u8,
    ) -> Result<u8, &'static str> {
        if !matches!(count, 2 | 4 | 6) || self.0 == 0 || self.0 >= count {
            return Err("target");
        }
        let target = if eligible(p) { self.0 } else { 0 };
        pin.publish_to(p, target, count)?;
        if target != 0 {
            self.0 = if target + 1 == count { 1 } else { target + 1 };
        }
        Ok(target)
    }
}

/// Atomic boot-lifetime state shared by runtime and bounded host exploration.
/// Attempt/STOP writers are serialized by BSP BKL; APs only publish their bits.
/// No method grants task reclaim or transfers lock authority.
pub struct Lifecycle {
    attempted: core::sync::atomic::AtomicU8,
    ready: core::sync::atomic::AtomicU8,
    calibrating: core::sync::atomic::AtomicU8,
    parked: core::sync::atomic::AtomicU8,
    failed: core::sync::atomic::AtomicU8,
    stop: core::sync::atomic::AtomicBool,
}
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}
impl Lifecycle {
    pub const fn new() -> Self {
        Self {
            attempted: AtomicU8::new(0),
            ready: AtomicU8::new(0),
            calibrating: AtomicU8::new(0),
            parked: AtomicU8::new(0),
            failed: AtomicU8::new(0),
            stop: AtomicBool::new(false),
        }
    }
    pub fn bit(raw: u8, count: u8) -> Option<u8> {
        if matches!(count, 2 | 4 | 6) && raw > 0 && raw < count {
            Some(1 << raw)
        } else {
            None
        }
    }
    pub fn attempt(&self, raw: u8, count: u8) -> bool {
        let Some(bit) = Self::bit(raw, count) else {
            return false;
        };
        if self.stopped() || self.failed() != 0 {
            return false;
        }
        self.attempted.fetch_or(bit, Ordering::Release);
        true
    }
    pub fn attempted(&self) -> u8 {
        self.attempted.load(Ordering::Acquire)
    }
    fn attempted_bit(&self, raw: u8, count: u8) -> Option<u8> {
        Self::bit(raw, count).filter(|bit| self.attempted() & bit != 0)
    }
    pub fn ready(&self, raw: u8, count: u8) -> bool {
        let Some(bit) = self.attempted_bit(raw, count) else {
            return false;
        };
        if self.stopped() || self.failed() != 0 {
            return false;
        }
        self.ready.fetch_or(bit, Ordering::Release);
        true
    }
    pub fn calibrate(&self, raw: u8, count: u8) -> bool {
        let Some(bit) = self.attempted_bit(raw, count) else {
            return false;
        };
        self.calibrating.fetch_or(bit, Ordering::Release);
        true
    }
    pub fn calibrating(&self) -> u8 {
        self.calibrating.load(Ordering::Acquire)
    }
    pub fn all_ready(&self, count: u8) -> bool {
        matches!(count, 2 | 4 | 6)
            && !self.stopped()
            && self.failed() == 0
            && self.ready.load(Ordering::Acquire) == (1 << count) - 2
    }
    pub fn stop(&self, owner: Option<u8>) -> bool {
        if owner != Some(0) {
            return false;
        }
        self.stop.store(true, Ordering::Release);
        true
    }
    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }
    pub fn park(&self, raw: u8, count: u8) -> bool {
        let Some(bit) = self.attempted_bit(raw, count) else {
            return false;
        };
        if !self.stopped() || self.failed() != 0 {
            return false;
        }
        self.parked.fetch_or(bit, Ordering::Release);
        true
    }
    pub fn parked(&self) -> u8 {
        self.parked.load(Ordering::Acquire)
    }
    /// A complete snapshot needs a reporting/failure-check iteration, never
    /// a fabricated missing CPU from trailing_zeros(0).
    pub fn missing_from(&self, parked: u8) -> Option<u8> {
        let missing = self.attempted() & !parked;
        (missing != 0).then(|| missing.trailing_zeros() as u8)
    }
    /// The completion snapshot must include every required PARKED record;
    /// a later ACK load alone cannot authorize SUMMARY ahead of those records.
    pub fn complete(&self, owner: Option<u8>, reported: u8) -> bool {
        owner == Some(0)
            && self.stopped()
            && self.attempted() & !reported == 0
            && self.attempted() & !self.parked() == 0
            && self.failed() == 0
    }
    pub fn fail(&self, raw: u8, count: u8) {
        let identity = if Self::bit(raw, count).is_some() {
            raw
        } else {
            255
        };
        let _ = self
            .failed
            .compare_exchange(0, identity, Ordering::Release, Ordering::Relaxed);
    }
    pub fn failed(&self) -> u8 {
        self.failed.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        handle::{Object, RIGHT_READ},
        process::{Process, ProcessState},
        rt::{BoundedRt, Priority, SchedulingClass},
    };
    fn child(pid: u64) -> Process {
        let mut p = Process::EMPTY;
        p.pid = pid;
        p.state = ProcessState::Created;
        p.program = crate::program::IMAGE as usize;
        p
    }
    #[test]
    fn candidate_counts_and_ordinary_reset_admit() {
        extern crate std;
        for n in [2, 4, 6] {
            let line = std::format!("durable=0 net fsd served smp-operator={n}");
            assert_eq!(admit(line.as_bytes(), true, true, false), Ok(true));
            let reset = std::format!("{line} acpi-reset-qemu");
            assert_eq!(admit(reset.as_bytes(), true, true, false), Ok(true));
        }
    }
    #[test]
    fn candidate_topology_accepts_four_and_six() {
        extern crate std;
        for n in [4, 6] {
            let cpus: std::vec::Vec<_> = (0..n)
                .map(|apic| Cpu {
                    kind: CpuKind::Xapic,
                    uid: apic,
                    apic,
                    flags: 1,
                })
                .collect();
            assert_eq!(
                topology(&cpus, 0, 0xfee00000, 0xfee00000, n as usize),
                Ok(())
            );
        }
    }
    #[test]
    fn placement_round_robin_skips_bsp_and_failed_publications() {
        let mut cursor = PlacementCursor::new();
        for (count, expected) in [
            (2, &[1, 1, 1, 1, 1, 1][..]),
            (4, &[1, 2, 3, 1, 2, 3][..]),
            (6, &[1, 2, 3, 4, 5, 1][..]),
        ] {
            cursor = PlacementCursor::new();
            for (i, &cpu) in expected.iter().enumerate() {
                let mut bsp = child(100 + i as u64);
                bsp.program = crate::program::INIT as usize;
                let mut bsp_pin = Placement::EMPTY;
                assert_eq!(cursor.publish(&mut bsp_pin, &bsp, count), Ok(0));
                let mut p = child(200 + i as u64);
                let mut pin = Placement::EMPTY;
                assert_eq!(cursor.publish(&mut pin, &p, count), Ok(cpu));
                assert!(cursor.publish(&mut pin, &p, count).is_err());
                p.state = ProcessState::Waiting;
                assert_eq!(pin.validate(&p, cpu), Ok(()));
                p.state = ProcessState::Runnable;
                assert_eq!(pin.validate(&p, cpu), Ok(()));
                assert!(pin.validate(&p, if cpu == 1 { 2 } else { 1 }).is_err());
            }
        }
        for count in [0, 1, 3, 5, 7, 255] {
            let mut pin = Placement::EMPTY;
            assert!(cursor.publish(&mut pin, &child(999), count).is_err());
        }
    }
    #[test]
    fn lifecycle_all_subsets_need_every_ready_and_attempted_ack() {
        for (count, full) in [(2, 2u8), (4, 14), (6, 62)] {
            for attempted in (0..=full).filter(|m| m & !full == 0) {
                for observed in (0..=full).filter(|m| m & !full == 0) {
                    let life = Lifecycle::new();
                    for cpu in 1..count {
                        if attempted & (1 << cpu) != 0 {
                            assert!(life.attempt(cpu, count));
                        }
                        if observed & (1 << cpu) != 0 {
                            life.ready(cpu, count);
                        }
                    }
                    assert_eq!(life.all_ready(count), attempted == full && observed == full);
                    assert!(!life.complete(Some(0), life.parked()));
                    assert!(!life.stop(Some(1)));
                    assert!(life.stop(Some(0)));
                    assert!(life.stop(Some(0)));
                    for cpu in 1..count {
                        assert!(!life.attempt(cpu, count));
                        if observed & (1 << cpu) != 0 {
                            life.park(cpu, count);
                        }
                    }
                    assert_eq!(
                        life.complete(Some(0), life.parked()),
                        attempted & !observed == 0
                    );
                    assert!(!life.complete(None, life.parked()));
                    assert!(!life.complete(Some(1), life.parked()));
                    for failed in 1..count {
                        life.fail(failed, count);
                        assert!(!life.complete(Some(0), life.parked()));
                        assert!(!life.all_ready(count));
                    }
                }
            }
        }
    }
    #[test]
    fn retirement_reports_late_acks_before_summary_even_at_deadline() {
        extern crate std;
        let life = Lifecycle::new();
        for cpu in 1..4 {
            assert!(life.attempt(cpu, 4));
        }
        assert!(life.stop(Some(0)));
        assert!(life.park(1, 4));
        assert!(
            !life.complete(Some(0), 14),
            "records cannot substitute for ACKs"
        );
        let parked = life.parked();
        assert_eq!(life.missing_from(parked), Some(2));
        let mut reported = parked;
        let mut records = std::vec![1];

        // Deterministic fr02 interleaving: CPU2/3 ACK after the reporting
        // snapshot, before the production completion decision reloads ACKs.
        assert!(life.park(2, 4));
        assert!(life.park(3, 4));
        if life.complete(Some(0), reported) {
            records.push(0);
        } // 0 = SUMMARY
        assert_eq!(records, [1], "late ACKs must be reported before SUMMARY");

        // At an expired deadline the fresh complete set requires another
        // reporting iteration, never a false missing-ACK refusal.
        assert_eq!(life.missing_from(life.parked()), None);
        assert!(life.complete(Some(0), life.parked()));
        let parked = life.parked();
        for cpu in 1..4 {
            if parked & !reported & (1 << cpu) != 0 {
                records.push(cpu);
                reported |= 1 << cpu;
            }
        }
        assert!(life.complete(Some(0), reported));
        records.push(0);
        assert_eq!(records, [1, 2, 3, 0]);

        // A repeated terminal entry inherits the already reported complete
        // set; no duplicate AP record is needed and failure still wins.
        assert!(life.stop(Some(0)));
        assert_eq!(life.parked() & !reported, 0);
        assert!(life.complete(Some(0), reported));
        assert!(!life.complete(None, reported));
        assert!(!life.complete(Some(1), reported));
        life.fail(3, 4);
        assert_eq!(life.missing_from(life.parked()), None);
        assert_eq!(
            retirement_refusal(life.failed() != 0, Some((0, RETIREMENT_BOUND_TSC))),
            Some("ap-failed")
        );
        assert!(!life.complete(Some(0), reported));
        assert!(!life.complete(Some(0), life.parked()));
    }
    #[test]
    fn failure_identity_is_first_sticky_and_invalid_never_indexes() {
        for raw in [0, 1, 2, 3, 4, 5, 6, 254, 255] {
            let life = Lifecycle::new();
            life.fail(raw, 6);
            assert_eq!(life.failed(), if (1..6).contains(&raw) { raw } else { 255 });
            life.fail(2, 6);
            assert_eq!(life.failed(), if (1..6).contains(&raw) { raw } else { 255 });
            assert!(!life.park(raw, 6));
            assert_eq!(life.parked(), 0);
        }
    }
    #[test]
    fn admission_matrix_rejects_mixed_malformed_and_diagnostic_options() {
        extern crate std;
        for n in [2, 4, 6] {
            let base = std::format!("durable=0 net fsd served smp-operator={n}");
            assert_eq!(admit_count(base.as_bytes(), true, true, false), Ok(Some(n)));
            for word in [
                "smp-cpus=4",
                "acpi-reset-qemu-extra",
                "acpi-reset-qemu=1",
                "acpi-reset-test",
                "acpi-s5-test",
                "smp-operator=",
                "smp-operator=02",
                "smp-operator=1",
                "smp-operator=3",
                "smp-operator=8",
                "smp-operator=+4",
                "smp-operator=4x",
            ] {
                let line = std::format!("{base} {word}");
                assert!(admit(line.as_bytes(), true, true, true).is_err(), "{line}");
            }
            for other in [2, 4, 6] {
                let line = std::format!("{base} smp-operator={other}");
                assert!(admit(line.as_bytes(), true, true, true).is_err());
            }
            let controls = [
                "smp-operator-retire-no-ack",
                "smp-operator-start-interrupt",
                "smp-operator-ap-panic-held",
                "smp-operator-ap-panic-unheld",
                "smp-operator-bsp-panic-unheld",
                "smp-operator-start-missing",
                "smp-operator-ap-backstop",
                "smp-operator-ap-panic-held-peers",
            ];
            for control in controls {
                let line = std::format!("{base} {control}");
                assert!(admit(line.as_bytes(), true, true, false).is_err());
                assert_eq!(
                    admit(line.as_bytes(), true, true, true).is_ok(),
                    !(control == "smp-operator-start-missing" && n == 2
                        || control == "smp-operator-ap-panic-held-peers" && n != 6)
                );
                for other in controls {
                    let line = std::format!("{line} {other}");
                    assert!(admit(line.as_bytes(), true, true, true).is_err());
                }
            }
        }
        for line in [
            b"".as_slice(),
            b"durable=0 net fsd served",
            b"smp-user-preempt smp-cpus=6",
        ] {
            assert_eq!(admit_count(line, false, false, false), Ok(None));
        }
    }
    #[test]
    fn topology_permutations_and_each_invalid_record_refuse() {
        extern crate std;
        fn permutations(cpus: &mut [Cpu], start: usize) {
            if start == cpus.len() {
                assert_eq!(
                    topology(cpus, 0, 0xfee00000, 0xfee00000, cpus.len()),
                    Ok(())
                );
                return;
            }
            for i in start..cpus.len() {
                cpus.swap(start, i);
                permutations(cpus, start + 1);
                cpus.swap(start, i);
            }
        }
        for n in [2, 4, 6] {
            let cpus: std::vec::Vec<_> = (0..n)
                .map(|apic| Cpu {
                    kind: CpuKind::Xapic,
                    uid: apic + 10,
                    apic,
                    flags: 1,
                })
                .collect();
            permutations(&mut cpus.clone(), 0);
            for index in 0..n as usize {
                for bad in [
                    Cpu {
                        flags: 0,
                        ..cpus[index]
                    },
                    Cpu {
                        flags: 2,
                        ..cpus[index]
                    },
                    Cpu {
                        flags: 3,
                        ..cpus[index]
                    },
                    Cpu {
                        kind: CpuKind::X2apic,
                        ..cpus[index]
                    },
                    Cpu {
                        apic: n,
                        ..cpus[index]
                    },
                    Cpu {
                        apic: u32::MAX,
                        ..cpus[index]
                    },
                    Cpu {
                        uid: cpus[(index + 1) % n as usize].uid,
                        ..cpus[index]
                    },
                    Cpu {
                        apic: cpus[(index + 1) % n as usize].apic,
                        ..cpus[index]
                    },
                ] {
                    let mut bad_cpus = cpus.clone();
                    bad_cpus[index] = bad;
                    assert!(topology(&bad_cpus, 0, 0xfee00000, 0xfee00000, n as usize).is_err());
                }
            }
            for (bsp, madt, msr) in [
                (1, 0xfee00000, 0xfee00000),
                (0, 0, 0),
                (0, 0xfee00000, 0xfee01000),
            ] {
                assert!(topology(&cpus, bsp, madt, msr, n as usize).is_err());
            }
            assert!(
                topology(
                    &cpus[..cpus.len() - 1],
                    0,
                    0xfee00000,
                    0xfee00000,
                    n as usize
                )
                .is_err()
            );
            let mut extra = cpus.clone();
            extra.push(cpus[0]);
            assert!(topology(&extra, 0, 0xfee00000, 0xfee00000, n as usize).is_err());
        }
    }
    #[test]
    fn placement_rejects_stale_claim_epoch_and_invalid_targets() {
        let mut p = child(44);
        let mut pin = Placement::EMPTY;
        for (target, count) in [(0, 6), (6, 6), (255, 6), (1, 1), (1, 3), (1, 255)] {
            assert!(pin.publish_to(&p, target, count).is_err());
        }
        pin.publish_to(&p, 5, 6).unwrap();
        p.state = ProcessState::Running;
        p.claim_epoch = 8;
        p.cpu_owner = Some(crate::process::CpuClaim { cpu: 5, epoch: 7 });
        assert_eq!(pin.validate(&p, 5), Err("stale-claim"));
        p.cpu_owner = Some(crate::process::CpuClaim { cpu: 5, epoch: 8 });
        assert_eq!(pin.validate(&p, 5), Ok(()));
        p.cpu_owner = Some(crate::process::CpuClaim { cpu: 3, epoch: 8 });
        assert_eq!(pin.validate(&p, 5), Err("stale-claim"));
    }
    #[test]
    fn concurrent_ap_publications_preserve_all_bits_and_first_failure() {
        extern crate std;
        use std::sync::{Arc, Barrier};
        for count in [2, 4, 6] {
            let life = Arc::new(Lifecycle::new());
            for cpu in 1..count {
                assert!(life.attempt(cpu, count));
            }
            let barrier = Arc::new(Barrier::new(count as usize - 1));
            std::thread::scope(|scope| {
                for cpu in 1..count {
                    let life = &life;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        assert!(life.calibrate(cpu, count));
                        assert!(life.ready(cpu, count));
                    });
                }
            });
            assert!(life.all_ready(count));
            assert_eq!(
                life.calibrating(),
                match count {
                    2 => 2,
                    4 => 14,
                    _ => 62,
                }
            );
            assert!(life.stop(Some(0)));
            std::thread::scope(|scope| {
                for cpu in 1..count {
                    let life = &life;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        assert!(life.park(cpu, count));
                    });
                }
            });
            assert!(life.complete(Some(0), life.parked()));
            assert!(life.stop(Some(0)));
            assert!(life.complete(Some(0), life.parked()));
            std::thread::scope(|scope| {
                for cpu in 1..count {
                    let life = &life;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        life.fail(cpu, count);
                    });
                }
            });
            let first = life.failed();
            assert!((1..count).contains(&first));
            life.fail(255, count);
            assert_eq!(life.failed(), first);
            assert!(!life.complete(Some(0), life.parked()));
        }
    }
    #[test]
    fn only_first_bsp_fatal_with_bkl_ownership_may_report() {
        use core::sync::atomic::{AtomicBool, Ordering};
        for owner in [None, Some(0), Some(1)] {
            let entered = AtomicBool::new(false);
            assert_eq!(
                bsp_fatal_may_report(owner, entered.swap(true, Ordering::AcqRel)),
                owner == Some(0)
            );
            // Even subsequent BSP ownership cannot rehabilitate a fatal entry.
            for later_owner in [Some(0), None, Some(1)] {
                assert!(!bsp_fatal_may_report(
                    later_owner,
                    entered.swap(true, Ordering::AcqRel)
                ));
            }
        }
    }
    #[test]
    fn failed_ap_refuses_without_granting_lock_ownership() {
        use core::sync::atomic::{AtomicBool, Ordering};
        let lock = crate::owner_lock::OwnerLock::new();
        lock.initialize(1);
        let failed = AtomicBool::new(false);
        assert_eq!(
            retirement_refusal(failed.load(Ordering::Acquire), None),
            None
        );
        assert_eq!(lock.try_acquire(0), Err(1));
        failed.store(true, Ordering::Release);
        for wait in [None, Some((0, 0)), Some((0, RETIREMENT_BOUND_TSC))] {
            assert_eq!(
                retirement_refusal(failed.load(Ordering::Acquire), wait),
                Some("ap-failed")
            );
            assert_eq!(lock.load(Ordering::Acquire), 1);
            assert_eq!(lock.try_acquire(0), Err(1));
        }
    }
    #[test]
    fn retirement_lock_deadline_is_bounded_and_wrap_safe() {
        for start in [0, 17, u64::MAX - 3] {
            for elapsed in [
                0,
                RETIREMENT_BOUND_TSC - 1,
                RETIREMENT_BOUND_TSC,
                RETIREMENT_BOUND_TSC + 1,
            ] {
                assert_eq!(
                    retirement_refusal(false, Some((start, start.wrapping_add(elapsed)))),
                    if elapsed < RETIREMENT_BOUND_TSC {
                        None
                    } else {
                        Some("lock-timeout")
                    }
                );
            }
        }
        assert_eq!(retirement_refusal(false, None), None);
    }
    #[test]
    #[cfg(all(
        feature = "smp-operator",
        feature = "frame-admission-v0",
        feature = "spawn-image-rollback-test"
    ))]
    fn compiled_operator_build_refuses_rollback_qualification() {
        assert_eq!(
            admit_compiled(b"durable=0 net fsd served smp-operator=2"),
            Err("conflicting-build")
        );
    }
    #[test]
    #[cfg(all(
        feature = "smp-operator",
        feature = "frame-admission-v0",
        not(any(
            feature = "spawn-image-rollback-test",
            feature = "smp-user-test",
            feature = "frame-reservation-experiment",
            feature = "native-pcm-experiment",
            feature = "block-read-only",
            feature = "builder-large-envelope"
        ))
    ))]
    fn compiled_supported_operator_build_admits() {
        assert_eq!(
            admit_compiled(b"durable=0 net fsd served smp-operator=2"),
            Ok(true)
        );
        for line in [
            b"durable=0 net fsd served smp-operator=2 smp-operator-ap-panic-held".as_slice(),
            b"durable=0 net fsd served smp-operator=2 smp-operator-ap-panic-unheld",
            b"durable=0 net fsd served smp-operator=2 smp-operator-bsp-panic-unheld",
        ] {
            assert_eq!(
                admit_compiled(line),
                if cfg!(feature = "smp-operator-controls") {
                    Ok(true)
                } else {
                    Err("option")
                }
            );
        }
    }
    #[test]
    fn panic_controls_require_controls_build_and_remain_exclusive() {
        extern crate std;
        let base = "durable=0 net fsd served smp-operator=2";
        let controls = [
            "smp-operator-retire-no-ack",
            "smp-operator-start-interrupt",
            "smp-operator-ap-panic-held",
            "smp-operator-ap-panic-unheld",
            "smp-operator-bsp-panic-unheld",
        ];
        for control in controls {
            let line = std::format!("{base} {control}");
            assert_eq!(admit(line.as_bytes(), true, true, true), Ok(true));
            assert_eq!(admit(line.as_bytes(), true, true, false), Err("option"));
            assert_eq!(admit(line.as_bytes(), false, true, true), Err("build-gate"));
            assert_eq!(admit(line.as_bytes(), true, false, true), Err("build-gate"));
            for other in controls {
                let line = std::format!("{base} {control} {other}");
                assert_eq!(
                    admit(line.as_bytes(), true, true, true),
                    Err(if control == other {
                        "duplicate"
                    } else {
                        "conflicting-controls"
                    })
                );
            }
        }
        assert_eq!(
            admit(
                b"durable=0 net fsd served smp-operator=2 smp-operator-ap-panic-held-extra",
                true,
                true,
                true
            ),
            Err("option")
        );
        assert_eq!(admit(b"durable=1", true, true, true), Ok(false));
    }
    #[test]
    fn compiled_build_without_operator_request_stays_up() {
        assert_eq!(admit_compiled(b"durable=1"), Ok(false));
    }
    #[test]
    fn admission_requires_both_gates_and_exact_profile() {
        let line = b"durable=0 net fsd served smp-operator=2";
        assert_eq!(admit(line, true, true, false), Ok(true));
        assert!(admit(line, false, true, false).is_err());
        assert!(admit(line, true, false, false).is_err());
        assert_eq!(
            admit(
                b"durable=0 net fsd served smp-operator=2 nvme-write=absd",
                true,
                true,
                false
            ),
            Ok(true)
        );
        for control in [
            b"durable=0 net fsd served smp-operator=2 smp-operator-retire-no-ack".as_slice(),
            b"durable=0 net fsd served smp-operator=2 smp-operator-start-interrupt",
        ] {
            assert!(admit(control, true, true, false).is_err());
            assert_eq!(admit(control, true, true, true), Ok(true));
        }
        assert!(admit(b"durable=0 net fsd served smp-operator=2 smp-operator-retire-no-ack smp-operator-start-interrupt", true, true, true).is_err());
        assert!(
            admit(
                b"durable=9999999999999999999 net fsd served smp-operator=2",
                true,
                true,
                false
            )
            .is_err()
        );
        assert_eq!(
            admit(b"durable=0 net fsd served", true, true, false),
            Ok(false)
        );
        for line in [
            b"durable=0 net fsd served smp-operator=3".as_slice(),
            b"durable=0 net fsd served smp-operator=2 smp-operator=2",
            b"durable=0 net fsd smp-operator=2",
            b"durable=0 net fsd served smp-operator=2 smp-user-pressure",
            b"durable=0 net fsd served smp-operator=2 usb-keyboard",
            b"durable=0 net fsd served smp-operator=2 surprise",
            b"shell net fsd served smp-operator=2",
            b"durable=0 net fsd served smp-operator",
            b"durable=0 net fsd served smp-operator-retire-no-ack",
        ] {
            assert!(admit(line, true, true, false).is_err(), "{line:?}");
        }
    }
    #[test]
    fn placement_pins_construction_authority_and_closure_never_migrates() {
        for object in [Object::Console, Object::Block, Object::Nic, Object::Machine] {
            let mut p = child(42);
            let h = p
                .handles
                .insert(
                    object,
                    if object == Object::Machine {
                        crate::handle::RIGHT_WAIT
                    } else {
                        RIGHT_READ
                    },
                )
                .unwrap();
            let mut pin = Placement::EMPTY;
            assert_eq!(pin.publish(&p), Ok(0));
            p.state = ProcessState::Runnable;
            p.handles.close(h).unwrap();
            assert_eq!(pin.cpu(&p), Ok(0));
            assert_eq!(pin.publish(&p), Err("publication"));
        }
    }
    #[test]
    fn image_only_non_rt_and_late_authority_refuses() {
        let mut p = child(43);
        let mut pin = Placement::EMPTY;
        assert_eq!(pin.publish(&p), Ok(1));
        p.state = ProcessState::Running;
        assert_eq!(pin.validate(&p, 1), Ok(()));
        p.handles.insert(Object::Nic, RIGHT_READ).unwrap();
        assert_eq!(pin.validate(&p, 1), Err("authority"));
        let mut catalog = child(44);
        for program in [
            crate::program::INIT,
            crate::program::FILE_SERVER,
            crate::program::EXTERNAL_WORKLOAD,
        ] {
            catalog.program = program as usize;
            let mut catalog_pin = Placement::EMPTY;
            assert_eq!(catalog_pin.publish(&catalog), Ok(0));
        }
        let mut rt = child(45);
        rt.class = SchedulingClass::BoundedRt(BoundedRt::new(Priority::RtLow, 0, 20, 5));
        let mut rt_pin = Placement::EMPTY;
        assert_eq!(rt_pin.publish(&rt), Ok(0));
    }
    #[test]
    fn slot_reuse_needs_exact_retirement_and_publication() {
        let first = child(100);
        let second = child(101);
        let mut pin = Placement::EMPTY;
        pin.publish(&first).unwrap();
        assert!(pin.cpu(&second).is_err());
        assert!(pin.publish(&second).is_err());
        assert!(pin.retire(second.pid).is_err());
        pin.retire(first.pid).unwrap();
        assert!(pin.cpu(&first).is_err());
        pin.publish(&second).unwrap();
        assert_eq!(pin.cpu(&second), Ok(1));
        assert!(pin.cpu(&first).is_err());
    }
    #[test]
    fn topology_is_exact_enabled_xapic_pair() {
        use crate::acpi::{Cpu, CpuKind};
        let cpu = |apic| Cpu {
            kind: CpuKind::Xapic,
            uid: apic,
            apic,
            flags: 1,
        };
        let pair = [cpu(0), cpu(1)];
        assert!(topology(&pair, 0, 0xfee00000, 0xfee00000, 2).is_ok());
        for cpus in [
            [cpu(0), cpu(0)],
            [cpu(1), cpu(2)],
            [cpu(0), Cpu { flags: 0, ..cpu(1) }],
            [
                cpu(0),
                Cpu {
                    kind: CpuKind::X2apic,
                    ..cpu(1)
                },
            ],
        ] {
            assert!(topology(&cpus, 0, 0xfee00000, 0xfee00000, 2).is_err());
        }
        assert!(topology(&pair[..1], 0, 0xfee00000, 0xfee00000, 2).is_err());
        assert!(topology(&pair, 1, 0xfee00000, 0xfee00000, 2).is_err());
        assert!(topology(&pair, 0, 0xfee01000, 0xfee00000, 2).is_err());
    }
}
