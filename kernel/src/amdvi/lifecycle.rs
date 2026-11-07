//! Increments 4 and 5 (#111 DESIGN §3–§4): the unit's health, the fault
//! record, the revocation steps R1–R5 with their claims, and the target's
//! disjoint buffer sets. Pure decisions, host-tested; src/amdvi_hw.rs
//! performs the actions and feeds these the observations.

/// Why the unit is `Failed`. The first reason is kept.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailReason {
    /// A COMPLETION_WAIT whose store value was not read back in time.
    InvalidationTimeout,
    /// An event that says the unit's own command or table processing
    /// failed (event code, Table 42).
    Event(u8),
    /// The Event Log Tail register read back an offset outside the
    /// configured ring (an all-ones read, say): the log cannot be walked.
    EventTail,
}

impl FailReason {
    pub fn word(self) -> &'static str {
        match self {
            FailReason::InvalidationTimeout => "invalidation-timeout",
            FailReason::EventTail => "event-tail-invalid",
            FailReason::Event(3) => "dev-tab-hw-error",
            FailReason::Event(4) => "page-tab-hw-error",
            FailReason::Event(5) => "illegal-command",
            FailReason::Event(6) => "command-hw-error",
            FailReason::Event(7) => "iotlb-inv-timeout",
            FailReason::Event(_) => "event",
        }
    }
}

/// Event codes that make the unit `Failed` (Table 42; DESIGN §3, oracle
/// interface v3 A.5 as extended by the coordinator 2026-10-31): 3
/// DEV_TAB_HW_ERROR and 4 PAGE_TAB_HW_ERROR (the unit cannot read its own
/// tables: fail closed), 5 ILLEGAL_COMMAND_ERROR, 6 COMMAND_HW_ERROR, 7
/// IOTLB_INV_TIMEOUT. IO_PAGE_FAULT (2) and ILLEGAL_DEV_TABLE_ENTRY (1) are
/// faults the unit handled.
pub fn fails_unit(code: u8) -> bool {
    let table_error = matches!(code, 3 | 4) && !cfg!(absd_mutant_amdvi_ignore_table_errors);
    (table_error || matches!(code, 5..=7)) && !cfg!(absd_mutant_amdvi_ignore_unit_errors)
}

/// The unit's health for the rest of the boot: once `Failed`, always
/// failed; a failed unit refuses every arm and every grant.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Health {
    failed: Option<FailReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnitFailed(pub FailReason);

impl Health {
    pub fn failed(&self) -> Option<FailReason> {
        self.failed
    }

    pub fn fail(&mut self, reason: FailReason) {
        if self.failed.is_none() {
            self.failed = Some(reason);
        }
    }

    /// A completion read back (`ok`) or not; returns `ok`.
    pub fn completion(&mut self, ok: bool) -> bool {
        if !ok {
            self.fail(FailReason::InvalidationTimeout);
        }
        ok
    }

    pub fn event(&mut self, code: u8) {
        if fails_unit(code) {
            self.fail(FailReason::Event(code));
        }
    }

    /// Whether anything may be armed or granted.
    pub fn admit(&self) -> Result<(), UnitFailed> {
        match self.failed {
            Some(reason) if !cfg!(absd_mutant_amdvi_failed_admits) => Err(UnitFailed(reason)),
            _ => Ok(()),
        }
    }
}

/// Who observed a fault (DESIGN §3 labeling).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observer {
    AbsdEventLog,
    OracleMemoryRead,
    QemuTrace,
    HostIommu,
}

impl Observer {
    pub fn word(self) -> &'static str {
        match self {
            Observer::AbsdEventLog => "absd-event-log",
            Observer::OracleMemoryRead => "oracle-memory-read",
            Observer::QemuTrace => "qemu-trace",
            Observer::HostIommu => "host-iommu",
        }
    }
}

/// The environment, from CPUID leaf 1 ECX[31] (hypervisor present) and the
/// leaf 4000_0000h vendor signature.
pub fn environment(hypervisor: bool, vendor: &[u8; 12]) -> &'static str {
    match (hypervisor, vendor) {
        (false, _) => "bare-metal",
        (true, b"TCGTCGTCGTCG") => "qemu-tcg",
        (true, b"KVMKVMKVM\0\0\0") => "kvm",
        (true, _) => "hypervisor-other",
    }
}

/// What may be said about faults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Absence {
    /// The log overflowed at some point: no claim may rely on the absence
    /// of faults, however many were seen.
    Unclaimable,
    /// No fault seen and the record is complete.
    NoneObserved,
    /// Faults seen, record complete.
    Observed(u64),
}

/// The fault record of one observer in one environment. EventOverflow
/// makes it incomplete for the rest of the boot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultRecord {
    pub observer: Observer,
    pub environment: &'static str,
    seen: u64,
    complete: bool,
}

impl FaultRecord {
    pub fn new(observer: Observer, environment: &'static str) -> FaultRecord {
        FaultRecord {
            observer,
            environment,
            seen: 0,
            complete: true,
        }
    }

    /// One drain: `faults` events consumed, `overflow` = Status
    /// EventOverflow after it.
    pub fn observe(&mut self, faults: u64, overflow: bool) {
        self.seen += faults;
        if overflow && !cfg!(absd_mutant_amdvi_overflow_forgotten) {
            self.complete = false;
        }
    }

    pub fn complete(&self) -> bool {
        self.complete
    }

    pub fn absence(&self) -> Absence {
        match (self.complete, self.seen) {
            (false, _) => Absence::Unclaimable,
            (true, 0) => Absence::NoneObserved,
            (true, n) => Absence::Observed(n),
        }
    }
}

/// #81's claim split.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Claim {
    SoftwareClosed,
    Contained,
    Settled,
    Reclaimable,
}

impl Claim {
    pub const ALL: [Claim; 4] = [
        Claim::SoftwareClosed,
        Claim::Contained,
        Claim::Settled,
        Claim::Reclaimable,
    ];

    pub fn word(self) -> &'static str {
        match self {
            Claim::SoftwareClosed => "software_closed",
            Claim::Contained => "contained",
            Claim::Settled => "settled",
            Claim::Reclaimable => "reclaimable",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimState {
    Established,
    Unestablished,
}

impl ClaimState {
    pub fn word(self) -> &'static str {
        match self {
            ClaimState::Established => "ESTABLISHED",
            ClaimState::Unestablished => "UNESTABLISHED",
        }
    }
}

/// What R4 found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reset {
    NotAttempted,
    /// The function has no reset ABSD can use (edu: none).
    Unavailable,
    Done,
}

/// One revocation of the target, R1–R5 (DESIGN §4), each step with its own
/// evidence. Steps must run in order; a step out of order is refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Revocation {
    closed: bool,
    stopped: Option<bool>,
    contained: bool,
    reset: Reset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepRefusal {
    OutOfOrder,
}

/// R3's observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Blocked {
    /// The DTE was written in the blocked form and the old set's leaves
    /// zeroed.
    pub written: bool,
    /// INVALIDATE_DEVTAB_ENTRY + INVALIDATE_IOMMU_PAGES(domain) +
    /// COMPLETION_WAIT, store value read back.
    pub completed: bool,
    /// The fault record is still complete (no overflow).
    pub record_complete: bool,
    /// The unit is not failed.
    pub unit_ok: bool,
}

impl Revocation {
    pub const START: Revocation = Revocation {
        closed: false,
        stopped: None,
        contained: false,
        reset: Reset::NotAttempted,
    };

    /// R1: the driver closed submission (code path). Supports only
    /// `software_closed`.
    pub fn r1_closed(&mut self) {
        self.closed = true;
    }

    /// R2: device stop request and BME clear; `bme_clear` is the config
    /// read-back. Supports no claim by itself (BME=0 is not settlement).
    pub fn r2_stopped(&mut self, bme_clear: bool) -> Result<(), StepRefusal> {
        if !self.closed {
            return Err(StepRefusal::OutOfOrder);
        }
        self.stopped = Some(bme_clear);
        Ok(())
    }

    /// R3: `contained` for this DeviceID from here on only when every
    /// observation holds.
    pub fn r3_blocked(&mut self, blocked: Blocked) -> Result<bool, StepRefusal> {
        if self.stopped.is_none() {
            return Err(StepRefusal::OutOfOrder);
        }
        self.contained =
            (blocked.written && blocked.completed && blocked.record_complete && blocked.unit_ok)
                || cfg!(absd_mutant_amdvi_contained_unchecked);
        Ok(self.contained)
    }

    /// R4: device reset; device state only, never memory settlement.
    pub fn r4_reset(&mut self, reset: Reset) -> Result<(), StepRefusal> {
        if self.stopped.is_none() {
            return Err(StepRefusal::OutOfOrder);
        }
        self.reset = reset;
        Ok(())
    }

    pub fn reset(&self) -> Reset {
        self.reset
    }

    pub fn bme_clear(&self) -> Option<bool> {
        self.stopped
    }

    /// The claims this revocation supports. R5 has no mechanism in v1:
    /// `settled` and `reclaimable` are always UNESTABLISHED.
    pub fn claim(&self, claim: Claim) -> ClaimState {
        let established = match claim {
            Claim::SoftwareClosed => self.closed,
            Claim::Contained => self.contained,
            Claim::Settled | Claim::Reclaimable => cfg!(absd_mutant_amdvi_settles),
        };
        if established {
            ClaimState::Established
        } else {
            ClaimState::Unestablished
        }
    }
}

/// N, the target's disjoint buffer sets (DESIGN §4).
pub const SETS: usize = 2;

/// The custodian of a retained set: the `dma` seam, never the driver or a
/// PID.
pub const CUSTODIAN: &str = "dma";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetState {
    Unused,
    Active,
    /// Retained for the rest of the boot by [`CUSTODIAN`]: never freed,
    /// never re-granted.
    Retained,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartRefusal {
    UnitFailed(FailReason),
    /// A set is active: revoke it first.
    Active,
    /// Every set is retained.
    ContainedButUnusable,
}

impl StartRefusal {
    pub fn word(self) -> &'static str {
        match self {
            StartRefusal::UnitFailed(_) => "unit-failed",
            StartRefusal::Active => "active",
            StartRefusal::ContainedButUnusable => "contained-but-unusable",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sets {
    state: [SetState; SETS],
}

impl Default for Sets {
    fn default() -> Self {
        Sets::NEW
    }
}

impl Sets {
    pub const NEW: Sets = Sets {
        state: [SetState::Unused; SETS],
    };

    pub fn state(&self, set: usize) -> SetState {
        self.state[set]
    }

    pub fn active(&self) -> Option<usize> {
        self.state.iter().position(|&s| s == SetState::Active)
    }

    /// Whether `set` may be mapped for the device: only an unused set.
    pub fn grantable(&self, set: usize) -> bool {
        self.state[set] == SetState::Unused || cfg!(absd_mutant_amdvi_regrant_retained)
    }

    /// The custodian of `set`, when retained.
    pub fn custodian(&self, set: usize) -> Option<&'static str> {
        (self.state[set] == SetState::Retained).then_some(CUSTODIAN)
    }

    /// `CONTAINED_BUT_UNUSABLE`: every set retained.
    pub fn unusable(&self) -> bool {
        self.state.iter().all(|&s| s == SetState::Retained)
    }

    /// The set the next (re)start uses: an unused one (DESIGN §4: a restart
    /// after R1–R4 switches to an unused set). Whether the last revocation
    /// established `contained` does not gate it: the old set is retained
    /// either way and never mapped again, and `contained` stays reported as
    /// it was (interface v3 A.3 has no such refusal).
    pub fn start(&mut self, health: &Health) -> Result<usize, StartRefusal> {
        if let Err(UnitFailed(reason)) = health.admit() {
            return Err(StartRefusal::UnitFailed(reason));
        }
        if self.active().is_some() {
            return Err(StartRefusal::Active);
        }
        let Some(set) = (0..SETS).find(|&set| self.grantable(set)) else {
            return Err(StartRefusal::ContainedButUnusable);
        };
        self.state[set] = SetState::Active;
        Ok(set)
    }

    /// After R3: the active set is retained (its leaves were zeroed and
    /// invalidated in R3). Retained whether or not `contained` was
    /// established: a set the device may still reach is never reused.
    pub fn retire_active(&mut self) -> Option<usize> {
        let set = self.active()?;
        self.state[set] = SetState::Retained;
        Some(set)
    }
}

// --- Operator mode (design sections 8 and 10) -------------------------------

/// What an event in a running `dma-contain` boot calls for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorAction {
    /// Report and count it; another requester's blocked access.
    Report,
    /// A contained target faulted: that device's R1-R4, its pages retained.
    RevokeTarget(u16),
}

pub fn operator_event_action(event: &super::Event, targets: &[u16]) -> OperatorAction {
    if let super::Event::IoPageFault { devid, .. } = *event
        && targets.contains(&devid)
        && !cfg!(absd_mutant_operator_target_fault_ignored)
    {
        return OperatorAction::RevokeTarget(devid);
    }
    OperatorAction::Report
}

/// Every overflow is terminal: lost events may include one that should have
/// acted, and restarting the log cannot recover them.
pub fn operator_log_terminal(overflow: bool, unit_failed: bool) -> bool {
    (overflow && !cfg!(absd_mutant_operator_overflow_ignored)) || unit_failed
}

/// What the forbidden-transfer check observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckFacts {
    /// The event log was drained just before the forbidden command.
    pub drained: bool,
    pub permitted_ok: bool,
    /// The forbidden command actually reached PxCI.
    pub submitted: bool,
    pub canary_unchanged: bool,
    /// An attributed fault arrived after the drain ([`fault_attributes`]).
    pub fault_matches: bool,
    pub completed: bool,
    pub port_retired: bool,
    pub bme_clear: bool,
    pub later_read_matches: bool,
    pub record_complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckOutcome {
    DeniedCompleted,
    /// A denial only: it does not show that the denial caused the
    /// retirement, or that recovery works.
    DeniedPortRetired,
    Failed,
}

impl CheckOutcome {
    pub fn word(self) -> &'static str {
        match self {
            CheckOutcome::DeniedCompleted => "denied-completed",
            CheckOutcome::DeniedPortRetired => "denied-port-retired",
            CheckOutcome::Failed => "FAILED",
        }
    }
}

pub fn check_verdict(facts: &CheckFacts) -> CheckOutcome {
    let submitted = facts.submitted || cfg!(absd_mutant_check_ignores_submission);
    let denied = facts.drained
        && facts.permitted_ok
        && submitted
        && facts.canary_unchanged
        && facts.fault_matches
        && facts.record_complete;
    if denied && facts.completed && facts.later_read_matches {
        return CheckOutcome::DeniedCompleted;
    }
    if denied && !facts.completed && facts.port_retired && facts.bme_clear {
        return CheckOutcome::DeniedPortRetired;
    }
    if cfg!(absd_mutant_check_retired_passes) && facts.port_retired {
        return CheckOutcome::DeniedPortRetired;
    }
    CheckOutcome::Failed
}

/// How strictly a fault is matched to the forbidden transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Attribution {
    /// This DeviceID and domain, not an interrupt, inside the canary page.
    Address,
    /// This DeviceID only: QEMU 10.2.1 reports addresses as 0, and its
    /// access type outside the RW bit. Only in a fixture build.
    DevidOnly,
}

impl Attribution {
    pub fn for_build() -> Self {
        if cfg!(feature = "contain-qemu-fixture") {
            Attribution::DevidOnly
        } else {
            Attribution::Address
        }
    }

    pub fn word(self) -> &'static str {
        match self {
            Attribution::Address => "address",
            Attribution::DevidOnly => "devid-only",
        }
    }
}

/// The targets one drain found faulting: the drain consumes the log, so none
/// may be forgotten.
#[derive(Clone, Copy, Debug)]
pub struct RevokeSet {
    ids: [u16; 2],
    len: usize,
}

impl RevokeSet {
    pub const EMPTY: Self = RevokeSet {
        ids: [0; 2],
        len: 0,
    };

    pub fn add(&mut self, id: u16) {
        if cfg!(absd_mutant_operator_last_fault_only) {
            self.ids[0] = id;
            self.len = 1;
            return;
        }
        if !self.ids().contains(&id) && self.len < self.ids.len() {
            self.ids[self.len] = id;
            self.len += 1;
        }
    }

    pub fn ids(&self) -> &[u16] {
        &self.ids[..self.len]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorNext {
    Nothing,
    Revoke,
    Terminal,
}

/// A failed unit ends everything, so it comes before any one target's revoke.
pub fn operator_next(terminal: bool, set: &RevokeSet) -> OperatorNext {
    if terminal {
        OperatorNext::Terminal
    } else if set.ids().is_empty() {
        OperatorNext::Nothing
    } else {
        OperatorNext::Revoke
    }
}

/// Whether a fault is the forbidden transfer's. RW counts only with PR=1,
/// where the specification makes it meaningful: the canary is never mapped,
/// so its fault has PR=0.
pub fn fault_attributes(
    event: &super::Event,
    target: u16,
    domain: u16,
    canary_page: u64,
    attribution: Attribution,
) -> bool {
    let super::Event::IoPageFault {
        devid,
        domain: faulted,
        address,
        write,
        present,
        interrupt,
        ..
    } = *event
    else {
        return false;
    };
    match attribution {
        Attribution::Address => {
            devid == target
                && faulted == domain
                && !interrupt
                && (write || !present)
                && address & !(super::PAGE - 1) == canary_page
        }
        Attribution::DevidOnly => devid == target,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contained() -> Revocation {
        let mut r = Revocation::START;
        r.r1_closed();
        r.r2_stopped(true).unwrap();
        let ok = Blocked {
            written: true,
            completed: true,
            record_complete: true,
            unit_ok: true,
        };
        assert_eq!(r.r3_blocked(ok), Ok(true));
        r.r4_reset(Reset::Unavailable).unwrap();
        r
    }

    #[test]
    fn unit_errors_fail_the_unit_for_good() {
        for code in 0..16u8 {
            let mut health = Health::default();
            health.event(code);
            assert_eq!(health.admit().is_err(), (3..=7).contains(&code), "{code}");
        }
        let mut health = Health::default();
        assert!(health.completion(true));
        assert_eq!(health.admit(), Ok(()));
        assert!(!health.completion(false));
        health.event(5);
        // The first reason is kept; nothing clears it.
        assert_eq!(
            health.admit(),
            Err(UnitFailed(FailReason::InvalidationTimeout))
        );
        assert!(health.completion(true));
        assert!(health.admit().is_err());
        assert_eq!(FailReason::Event(5).word(), "illegal-command");
        // Table hardware errors fail the unit too, for good.
        for code in [3u8, 4] {
            let mut health = Health::default();
            health.event(code);
            assert_eq!(health.admit(), Err(UnitFailed(FailReason::Event(code))));
            health.event(2);
            assert!(health.admit().is_err());
        }
        assert_eq!(FailReason::Event(3).word(), "dev-tab-hw-error");
        assert_eq!(FailReason::Event(4).word(), "page-tab-hw-error");
    }

    #[test]
    fn overflow_makes_fault_absence_unclaimable_for_good() {
        let mut record = FaultRecord::new(Observer::AbsdEventLog, "qemu-tcg");
        assert_eq!(record.absence(), Absence::NoneObserved);
        record.observe(2, false);
        assert_eq!(record.absence(), Absence::Observed(2));
        record.observe(0, true);
        assert_eq!(record.absence(), Absence::Unclaimable);
        // Overflow cleared later: still incomplete.
        record.observe(0, false);
        assert!(!record.complete());
        assert_eq!(record.absence(), Absence::Unclaimable);
        assert_eq!(record.observer.word(), "absd-event-log");
    }

    #[test]
    fn environments_are_named() {
        assert_eq!(environment(false, b"TCGTCGTCGTCG"), "bare-metal");
        assert_eq!(environment(true, b"TCGTCGTCGTCG"), "qemu-tcg");
        assert_eq!(environment(true, b"KVMKVMKVM\0\0\0"), "kvm");
        assert_eq!(environment(true, b"Microsoft Hv"), "hypervisor-other");
    }

    #[test]
    fn revocation_steps_support_only_their_claims() {
        let mut r = Revocation::START;
        assert_eq!(r.r2_stopped(true), Err(StepRefusal::OutOfOrder));
        r.r1_closed();
        assert_eq!(r.claim(Claim::SoftwareClosed), ClaimState::Established);
        assert_eq!(r.claim(Claim::Contained), ClaimState::Unestablished);
        assert!(
            r.r3_blocked(Blocked {
                written: true,
                completed: true,
                record_complete: true,
                unit_ok: true
            })
            .is_err()
        );
        r.r2_stopped(true).unwrap();
        // BME clear alone supports nothing more.
        assert_eq!(r.claim(Claim::Contained), ClaimState::Unestablished);
        let all = Blocked {
            written: true,
            completed: true,
            record_complete: true,
            unit_ok: true,
        };
        for broken in [
            Blocked {
                written: false,
                ..all
            },
            Blocked {
                completed: false,
                ..all
            },
            Blocked {
                record_complete: false,
                ..all
            },
            Blocked {
                unit_ok: false,
                ..all
            },
        ] {
            let mut copy = r;
            assert_eq!(copy.r3_blocked(broken), Ok(false));
            assert_eq!(copy.claim(Claim::Contained), ClaimState::Unestablished);
        }
        let r = contained();
        assert_eq!(r.claim(Claim::Contained), ClaimState::Established);
        // R5 has no mechanism: never settled, never reclaimable.
        assert_eq!(r.claim(Claim::Settled), ClaimState::Unestablished);
        assert_eq!(r.claim(Claim::Reclaimable), ClaimState::Unestablished);
    }

    #[test]
    fn restarts_use_unused_sets_and_retain_old_ones() {
        let health = Health::default();
        let mut sets = Sets::NEW;
        assert_eq!(sets.start(&health), Ok(0));
        assert_eq!(sets.start(&health), Err(StartRefusal::Active));
        assert_eq!(sets.retire_active(), Some(0));
        assert_eq!(sets.custodian(0), Some("dma"));
        assert!(!sets.grantable(0));
        assert_eq!(sets.start(&health), Ok(1));
        assert_eq!(sets.retire_active(), Some(1));
        assert!(sets.unusable());
        assert_eq!(sets.start(&health), Err(StartRefusal::ContainedButUnusable));
        // Retained sets stay retained: never granted again.
        for set in 0..SETS {
            assert_eq!(sets.state(set), SetState::Retained);
            assert!(!sets.grantable(set));
        }
    }

    #[test]
    fn a_failed_unit_refuses_every_start() {
        let mut health = Health::default();
        health.event(6);
        let mut sets = Sets::NEW;
        assert_eq!(
            sets.start(&health),
            Err(StartRefusal::UnitFailed(FailReason::Event(6)))
        );
        assert_eq!(sets.state(0), SetState::Unused);
    }
}
