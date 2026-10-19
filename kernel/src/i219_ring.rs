//! I219 queue-zero completion rules. No offloads or extended descriptors.
//! DD transfers a TX buffer back to software, but is not proof of delivery.

use crate::e1000_ring::{TX_COMMAND, TxCounters, TxOutcome, TxPort, TxSlots};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxCompletion {
    Pending,
    Done,
    Failed(u8),
}

pub fn tx_completion(status: u8) -> TxCompletion {
    if status & 1 == 0 {
        TxCompletion::Pending
    } else if status & 0x0e != 0 {
        TxCompletion::Failed(status & 0x0e)
    } else {
        TxCompletion::Done
    }
}

/// Device STATUS bits consulted by the carrier decision.
pub const STATUS_LINK_UP: u32 = 1 << 1;
pub const STATUS_FULL_DUPLEX: u32 = 1;
pub const STATUS_SPEED_MASK: u32 = 3 << 6;
pub const STATUS_SPEED_1000: u32 = 2 << 6;
/// Interrupt cause read register and its latched link-status-change bit.
pub const ICR: u32 = 0xc0;
pub const ICR_LSC: u32 = 1 << 2;

/// Why the carrier decision retires the backend; the device maps these to
/// its own `Disabled` reasons one-for-one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierFault {
    LinkProfile,
    Activation,
}

/// The next step the polling backend takes for one carrier sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierStep {
    /// Retire the backend with this reason.
    Fault(CarrierFault),
    /// Active and the carrier changed since the last poll: re-read the link
    /// through the PHY (`i219::refresh_link`) and report what it returns.
    Refresh,
    /// No carrier; the NIC stays idle and is not retired.
    Down,
    /// Gigabit carrier on an inactive backend: run the one-time activation.
    Activate,
    /// Active with unchanged gigabit full-duplex carrier.
    Up,
}

/// Carrier decision over register values. `read_icr` is called at most once,
/// and only after STATUS is known not to be all-ones: ICR is read-to-clear,
/// so the read is not issued for a function that has stopped decoding.
/// Interrupts are masked, but ICR still latches link-status changes; it is
/// consulted as well as the sampled carrier to catch a down/up cycle between
/// polls. No other ICR cause drives this polling backend.
pub fn carrier(
    status: u32,
    read_icr: impl FnOnce() -> u32,
    active: bool,
    last_link_up: bool,
) -> CarrierStep {
    if status == u32::MAX {
        return CarrierStep::Fault(CarrierFault::LinkProfile);
    }
    let changed = read_icr() & ICR_LSC != 0;
    let up = status & STATUS_LINK_UP != 0;
    if active && (changed || up != last_link_up) {
        return CarrierStep::Refresh;
    }
    if !up {
        return CarrierStep::Down;
    }
    if active
        && status & (STATUS_SPEED_MASK | STATUS_FULL_DUPLEX)
            != (STATUS_SPEED_1000 | STATUS_FULL_DUPLEX)
    {
        return CarrierStep::Fault(CarrierFault::LinkProfile);
    }
    if !active {
        return CarrierStep::Activate;
    }
    CarrierStep::Up
}

/// Outcome of a `Refresh` step: the PHY's link answer, or retirement when the
/// PHY cannot be read or reports an unsupported link.
pub fn refreshed(result: Result<bool, crate::i219::Error>) -> Result<bool, CarrierFault> {
    result.map_err(|_| CarrierFault::LinkProfile)
}

/// Outcome of `i219::enable_legacy` in an `Activate` step: `Ok(true)` proceeds
/// to bus mastering; a PHY that does not (yet) report link leaves the backend
/// idle and inactive; any other refusal retires it.
pub fn activated(result: Result<(), crate::i219::Error>) -> Result<bool, CarrierFault> {
    match result {
        Ok(()) => Ok(true),
        Err(crate::i219::Error::LinkDown) => Ok(false),
        Err(_) => Err(CarrierFault::Activation),
    }
}

/// After requesting bus mastering, the PCI command register must show it.
pub fn bus_master(command: u32) -> Result<(), CarrierFault> {
    if command & 4 == 0 {
        Err(CarrierFault::Activation)
    } else {
        Ok(())
    }
}

/// Only untagged frames in the existing ABI, with legacy descriptor format.
/// RX checksum offload is disabled; all reported errors remain refusals.
pub use crate::e1000_ring::{classify_rx, head_in_ring, next, send_length};

/// Once a fragment appears, discard through EOP, even across polling calls.
/// The final fragment's DD/EOP bits do not make it a whole Ethernet frame.
#[derive(Default)]
pub struct RxChain {
    discarding: bool,
}

impl RxChain {
    pub fn classify(
        &mut self,
        status: u8,
        errors: u8,
        length: u16,
    ) -> crate::e1000_ring::RxVerdict {
        use crate::e1000_ring::{RxRefusal, RxVerdict};
        if status & 1 == 0 {
            return RxVerdict::Empty;
        }
        let was_fragment = self.discarding;
        self.discarding = status & 2 == 0;
        if was_fragment {
            RxVerdict::Refused(RxRefusal::Fragment)
        } else {
            classify_rx(status, errors, length)
        }
    }
}

/// Queue-zero registers the transmit port reaches. `src/i219_device.rs`
/// names the same offsets and asserts at compile time that they agree.
pub const STATUS: u32 = 0x8;
/// Transmit control. Its enable bit is written only by `i219::enable_legacy`
/// (the Activate step of the carrier decision, which every post follows,
/// since a send posts only after `ensure_active` returned `Ok(true)`) and
/// cleared only by the device's `disable`. The transmit port never writes
/// `TCTL`: there is no I219 transmit-hold fixture.
pub const TCTL: u32 = 0x400;
pub const TDT: u32 = 0x3818;
/// One transmit bound: at most `TX_POLLS` polls about 1 ms apart, ended
/// early once `TX_TICKS` timer ticks have passed (the values of the send
/// loop before C3, `d5daafd` `src/i219_device.rs:411-435`).
pub const TX_POLLS: u32 = 100;
pub const TX_TICKS: u64 = 100;

/// What the transmit port reaches: the MMIO window and the static
/// queue-zero ring in `src/i219_device.rs`, a fake under `cargo test`.
pub trait TxRing {
    fn read32(&mut self, offset: u32) -> u32;
    fn write32(&mut self, offset: u32, value: u32);
    /// Descriptor `index`'s second word (length, command, status), one
    /// volatile read. The first word, the buffer address, is written once
    /// at probe and never again.
    fn status_word(&mut self, index: usize) -> u64;
    /// Writes descriptor `index`'s second word.
    fn set_status_word(&mut self, index: usize, word: u64);
    /// A full fence (`fence(SeqCst)` on the device).
    fn fence(&mut self);
    fn ticks(&mut self) -> u64;
    /// The device's PIT-paced delay; false when the clock has stalled.
    fn delay_ms(&mut self, milliseconds: u32) -> bool;
}

/// What `TxPort` cannot carry, kept for the caller to read after
/// `TxSlots` returns.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TxFaults {
    /// Completion-error bits (EC/LC/TU) of the first done bit seen with
    /// any: the descriptor is done (and counted, ruling iii), and the NIC
    /// must then be disabled.
    pub failed: Option<u8>,
    /// `delay_ms` reported a stalled clock inside a bound, which ended it.
    pub clock: bool,
}

/// T6's `TxPort` over the I219's queue zero.
pub struct I219Tx<R> {
    pub ring: R,
    pub faults: TxFaults,
}

impl<R> I219Tx<R> {
    pub fn new(ring: R) -> Self {
        Self {
            ring,
            faults: TxFaults::default(),
        }
    }

    /// The disable a fault demands. A stalled clock comes first: a bound it
    /// ended proves nothing about carrier, so it is never `NoCarrier`.
    pub fn fault(&self) -> Option<TxFault> {
        if self.faults.clock {
            Some(TxFault::Clock)
        } else {
            self.faults.failed.map(TxFault::Error)
        }
    }
}

impl<R: TxRing> TxPort for I219Tx<R> {
    /// `STATUS.LU` alone: not ICR (read-to-clear; the carrier decision owns
    /// its LSC latch) and not the PHY. All-ones (a function that stopped
    /// decoding) reads as carrier, so an expiry is a device outcome.
    fn link_up(&mut self) -> bool {
        self.ring.read32(STATUS) & STATUS_LINK_UP != 0
    }

    /// DD hands the descriptor and its buffer back; the fence orders that
    /// observation before any reuse. Error bits still mean done (counted
    /// once by `TxSlots`) and are kept in `faults.failed` for the caller.
    fn done(&mut self, index: usize) -> bool {
        match tx_completion((self.ring.status_word(index) >> 32) as u8) {
            TxCompletion::Pending => false,
            TxCompletion::Done => {
                self.ring.fence();
                true
            }
            TxCompletion::Failed(bits) => {
                self.ring.fence();
                if self.faults.failed.is_none() {
                    self.faults.failed = Some(bits);
                }
                true
            }
        }
    }

    /// Length and command into word 1 (clearing DD), fence, then the tail:
    /// the device may fetch the descriptor once `TDT` moves.
    fn post(&mut self, index: usize, wire: usize, tail: usize) {
        self.ring
            .set_status_word(index, wire as u64 | (u64::from(TX_COMMAND) << 24));
        self.ring.fence();
        self.ring.write32(TDT, tail as u32);
    }

    /// At most `TX_POLLS` polls 1 ms apart and `TX_TICKS` ticks; reads
    /// `STATUS.LU` at every poll that does not see the done bit. A stalled
    /// clock ends the bound at once and is kept in `faults.clock`.
    fn wait_done(&mut self, index: usize, carrier_lost: &mut bool) -> bool {
        let start = self.ring.ticks();
        for _ in 0..TX_POLLS {
            if self.done(index) {
                return true;
            }
            if !self.link_up() {
                *carrier_lost = true;
            }
            if self.ring.ticks().wrapping_sub(start) >= TX_TICKS {
                return false;
            }
            if !self.ring.delay_ms(1) {
                self.faults.clock = true;
                return false;
            }
        }
        false
    }
}

/// A transmit fault that disables the NIC; the device maps these to its
/// own `Disabled` reasons one-for-one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxFault {
    /// A whole bound ran with carrier present and expired (T6's
    /// `DeviceFailed`).
    Timeout,
    /// A done bit carried completion-error bits; the frame was counted.
    Error(u8),
    /// The clock stalled inside a bound.
    Clock,
}

/// What one I219 send decided (kernel record
/// docs/service-lifecycle-20261008/DEGRADED-OPERATION-LIVENESS.md §10).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendStep {
    /// The posted descriptor's done bit was seen clean.
    Sent,
    /// A link outcome (`ERROR_NO_CARRIER`): no carrier before posting
    /// (nothing posted, nothing counted), a held descriptor with carrier
    /// still absent, or a bound that saw carrier absent. The NIC stays
    /// enabled; a held descriptor stays the device's.
    NoCarrier,
    /// `fill` could not copy the frame; nothing was posted.
    Copy,
    /// The carrier decision refused (the NIC is, or has just been,
    /// retired); nothing was read or posted.
    Retired,
    /// Disable the NIC for this reason.
    Disable(TxFault),
}

/// Counts a held descriptor whose done bit has appeared, once, and frees
/// it (`TxSlots::reap`); returns the disable an errored done bit demands.
/// Reads one descriptor word; writes nothing.
pub fn reap_held<R: TxRing>(
    slots: &mut TxSlots,
    port: &mut I219Tx<R>,
    counters: &mut TxCounters,
) -> Option<TxFault> {
    port.faults = TxFaults::default();
    slots.reap(port, counters);
    port.fault()
}

/// One send. `carrier` is the device's carrier decision for this send
/// (`Nic::ensure_active`, then the ring heads when it is `Ok(true)`). A
/// refusal touches nothing; otherwise a held descriptor whose done bit has
/// appeared is reaped first; then without carrier the send ends at once as
/// a link outcome, before anything is read from or posted to the ring;
/// with carrier, T6's `TxSlots` decides, and the port's faults decide over
/// it. `fill` copies the frame into the buffer of the descriptor it is
/// given and reports whether it could.
pub fn send_step<R: TxRing, E>(
    carrier: Result<bool, E>,
    slots: &mut TxSlots,
    port: &mut I219Tx<R>,
    counters: &mut TxCounters,
    wire: usize,
    fill: impl FnOnce(usize) -> bool,
) -> SendStep {
    let Ok(carrier_up) = carrier else {
        return SendStep::Retired;
    };
    if let Some(fault) = reap_held(slots, port, counters) {
        return SendStep::Disable(fault);
    }
    if !carrier_up {
        // No carrier before posting: a link outcome (-100), not ERROR_IO.
        return SendStep::NoCarrier;
    }
    let index = match slots.before_post(port, counters) {
        Ok(index) => index,
        Err(outcome) => return judge(port, outcome),
    };
    if let Some(fault) = port.fault() {
        return SendStep::Disable(fault);
    }
    if !fill(index) {
        return SendStep::Copy;
    }
    let outcome = slots.transmit(port, index, wire, counters);
    judge(port, outcome)
}

/// `TxSlots`'s outcome, overridden by any fault the port kept.
fn judge<R>(port: &I219Tx<R>, outcome: TxOutcome) -> SendStep {
    if let Some(fault) = port.fault() {
        return SendStep::Disable(fault);
    }
    match outcome {
        TxOutcome::Sent => SendStep::Sent,
        TxOutcome::NoCarrier => SendStep::NoCarrier,
        TxOutcome::DeviceFailed => SendStep::Disable(TxFault::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_requires_dd_and_reports_transmission_errors() {
        for errors in 0..8 {
            assert_eq!(tx_completion(errors << 1), TxCompletion::Pending);
        }
        assert_eq!(tx_completion(1), TxCompletion::Done);
        for errors in 1..8 {
            assert_eq!(
                tx_completion(1 | errors << 1),
                TxCompletion::Failed(errors << 1)
            );
        }
    }

    #[test]
    fn inherited_frame_contract_and_ring_wrap_are_preserved() {
        use crate::e1000_ring::{RxRefusal, RxVerdict};
        assert_eq!(classify_rx(3, 0, 1514), RxVerdict::Frame(1514));
        assert_eq!(
            classify_rx(3, 0, 1518),
            RxVerdict::Refused(RxRefusal::Length(1518))
        );
        assert_eq!(
            classify_rx(1, 0, 64),
            RxVerdict::Refused(RxRefusal::Fragment)
        );
        assert_eq!(send_length(u64::MAX), None);
        assert_eq!(send_length(14), Some((14, 60)));
        assert_eq!(next(15, 16), 0);
        assert!(!head_in_ring(u32::MAX, 32));
    }

    #[test]
    fn fragment_tail_never_becomes_a_frame_across_poll_boundaries() {
        use crate::e1000_ring::{RxRefusal, RxVerdict};
        let mut chain = RxChain::default();
        assert_eq!(
            chain.classify(1, 0, 2048),
            RxVerdict::Refused(RxRefusal::Fragment)
        );
        assert_eq!(chain.classify(0, 0, 0), RxVerdict::Empty);
        assert_eq!(
            chain.classify(3, 0, 64),
            RxVerdict::Refused(RxRefusal::Fragment)
        );
        assert_eq!(chain.classify(3, 0, 64), RxVerdict::Frame(64));
    }

    const GIGABIT_UP: u32 = STATUS_LINK_UP | STATUS_SPEED_1000 | STATUS_FULL_DUPLEX;

    fn step(status: u32, icr: u32, active: bool, last: bool) -> CarrierStep {
        let mut reads = 0;
        let out = carrier(
            status,
            || {
                reads += 1;
                icr
            },
            active,
            last,
        );
        assert_eq!(reads, 1, "ICR is read exactly once for a decoding function");
        out
    }

    #[test]
    fn carrier_present_activates_once_then_reports_up() {
        assert_eq!(step(GIGABIT_UP, 0, false, false), CarrierStep::Activate);
        assert_eq!(step(GIGABIT_UP, 0, true, true), CarrierStep::Up);
        // Inactive: profile and the ICR latch are left to activation.
        assert_eq!(
            step(GIGABIT_UP, ICR_LSC, false, false),
            CarrierStep::Activate
        );
        assert_eq!(step(STATUS_LINK_UP, 0, false, false), CarrierStep::Activate);
        assert_eq!(activated(Ok(())), Ok(true));
        assert_eq!(bus_master(0x0006), Ok(()));
        assert_eq!(refreshed(Ok(true)), Ok(true));
    }

    #[test]
    fn carrier_absent_is_idle_not_disabled() {
        for status in [0, GIGABIT_UP & !STATUS_LINK_UP, STATUS_SPEED_MASK] {
            assert_eq!(step(status, 0, false, false), CarrierStep::Down);
            assert_eq!(step(status, 0, true, false), CarrierStep::Down);
        }
        // Inactive: a latched change does not matter until activation.
        assert_eq!(step(0, ICR_LSC, false, false), CarrierStep::Down);
        // Active: loss of carrier, or a latched change, is re-read via the PHY.
        assert_eq!(step(0, 0, true, true), CarrierStep::Refresh);
        assert_eq!(step(0, ICR_LSC, true, false), CarrierStep::Refresh);
        assert_eq!(step(GIGABIT_UP, 0, true, false), CarrierStep::Refresh);
        // A down/up cycle between polls: LU unchanged, LSC latched.
        assert_eq!(step(GIGABIT_UP, ICR_LSC, true, true), CarrierStep::Refresh);
        // Only the LSC cause matters.
        assert_eq!(step(GIGABIT_UP, !ICR_LSC, true, true), CarrierStep::Up);
        assert_eq!(refreshed(Ok(false)), Ok(false));
    }

    #[test]
    fn phy_not_ready_leaves_the_backend_idle() {
        assert_eq!(activated(Err(crate::i219::Error::LinkDown)), Ok(false));
    }

    #[test]
    fn disabled_register_combinations() {
        // All-ones STATUS retires the backend in every state, before ICR.
        for (active, last) in [(false, false), (true, false), (true, true)] {
            assert_eq!(
                carrier(u32::MAX, || panic!("ICR read"), active, last),
                CarrierStep::Fault(CarrierFault::LinkProfile)
            );
        }
        // Active, unchanged carrier up, not 1000/full.
        for speed in [0, 1 << 6, 3 << 6] {
            for duplex in [0, STATUS_FULL_DUPLEX] {
                assert_eq!(
                    step(STATUS_LINK_UP | speed | duplex, 0, true, true),
                    CarrierStep::Fault(CarrierFault::LinkProfile)
                );
            }
        }
        assert_eq!(
            step(STATUS_LINK_UP | STATUS_SPEED_1000, 0, true, true),
            CarrierStep::Fault(CarrierFault::LinkProfile)
        );
        // A PHY refresh failure, an activation refusal other than LinkDown,
        // and bus mastering that does not stick.
        use crate::i219::Error;
        for error in [
            Error::MdioTimeout,
            Error::UnsupportedLink,
            Error::SemaphoreBusy,
        ] {
            assert_eq!(refreshed(Err(error)), Err(CarrierFault::LinkProfile));
            assert_eq!(activated(Err(error)), Err(CarrierFault::Activation));
        }
        // Unlike activation, a refresh that reports LinkDown retires the backend.
        assert_eq!(
            refreshed(Err(Error::LinkDown)),
            Err(CarrierFault::LinkProfile)
        );
        assert_eq!(bus_master(0x0002), Err(CarrierFault::Activation));
    }
}

/// The I219 transmit port against T6's unchanged `TxSlots`: the same
/// ownership and accounting rules as `e1000_ring`'s transmit-rule tests,
/// driven through a fake queue zero instead of the private `Model`.
#[cfg(test)]
mod tx_tests {
    extern crate std;
    use super::*;
    use crate::e1000_ring::{TX_DESCRIPTORS, TxCounters, TxOutcome, TxSlots};
    use std::vec::Vec;

    const UP: u32 = STATUS_LINK_UP | STATUS_SPEED_1000 | STATUS_FULL_DUPLEX;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Op {
        Read(u32),
        Write(u32, u32),
        Word(usize),
        SetWord(usize, u64),
        Fence,
        Delay,
    }

    /// A fake queue zero. `status` is STATUS. Moving TDT hands the
    /// descriptor at the old tail to the device (`owned`); when `completes`,
    /// the device completes a descriptor it owns at its first poll, with
    /// status byte `completion`. `drop_link_in_wait` / `raise_link_in_wait`
    /// clear / set LU at each delay; `clock_ok` false makes each delay
    /// report a stalled clock; each delay advances `ticks` by `tick_step`.
    /// A read of any register but STATUS, or a write to any but TDT,
    /// panics; a word written over a device-owned descriptor is recorded
    /// (I3).
    #[derive(Default)]
    struct Ring {
        status: u32,
        completes: bool,
        completion: u8,
        drop_link_in_wait: bool,
        raise_link_in_wait: bool,
        clock_ok: bool,
        tick_step: u64,
        ticks: u64,
        tail: usize,
        words: [u64; TX_DESCRIPTORS],
        owned: [bool; TX_DESCRIPTORS],
        posted: u64,
        delays: u32,
        overwrote_owned: bool,
        trace: Vec<Op>,
    }

    impl Ring {
        fn up() -> Self {
            Self {
                status: UP,
                completes: true,
                completion: 1,
                clock_ok: true,
                tick_step: 1,
                ..Self::default()
            }
        }

        fn down() -> Self {
            Self {
                status: UP & !STATUS_LINK_UP,
                completes: false,
                ..Self::up()
            }
        }

        /// The device completes `index` after its bound, with `completion`.
        fn complete_late(&mut self, index: usize) {
            assert!(
                self.owned[index],
                "only a device-owned descriptor completes"
            );
            self.owned[index] = false;
            self.words[index] |= u64::from(self.completion) << 32;
        }
    }

    impl TxRing for Ring {
        fn read32(&mut self, offset: u32) -> u32 {
            self.trace.push(Op::Read(offset));
            assert_eq!(offset, STATUS, "the transmit port reads only STATUS");
            self.status
        }

        fn write32(&mut self, offset: u32, value: u32) {
            self.trace.push(Op::Write(offset, value));
            assert_eq!(offset, TDT, "the transmit port writes only TDT");
            let index = self.tail;
            assert_eq!(
                value as usize,
                next(index, TX_DESCRIPTORS),
                "TDT moves one descriptor"
            );
            self.owned[index] = true;
            self.posted += 1;
            self.tail = value as usize;
        }

        fn status_word(&mut self, index: usize) -> u64 {
            self.trace.push(Op::Word(index));
            if self.completes && self.owned[index] {
                self.complete_late(index);
            }
            self.words[index]
        }

        fn set_status_word(&mut self, index: usize, word: u64) {
            self.trace.push(Op::SetWord(index, word));
            self.overwrote_owned |= self.owned[index];
            self.words[index] = word;
        }

        fn fence(&mut self) {
            self.trace.push(Op::Fence);
        }

        fn ticks(&mut self) -> u64 {
            self.ticks
        }

        fn delay_ms(&mut self, milliseconds: u32) -> bool {
            self.trace.push(Op::Delay);
            assert_eq!(milliseconds, 1);
            self.delays += 1;
            self.ticks += self.tick_step;
            if self.drop_link_in_wait {
                self.status &= !STATUS_LINK_UP;
            }
            if self.raise_link_in_wait {
                self.status |= STATUS_LINK_UP;
            }
            self.clock_ok
        }
    }

    type Port = I219Tx<Ring>;

    fn send(slots: &mut TxSlots, port: &mut Port, counters: &mut TxCounters) -> TxOutcome {
        match slots.before_post(port, counters) {
            Err(outcome) => outcome,
            Ok(index) => slots.transmit(port, index, 60, counters),
        }
    }

    /// I1 and I3, as `e1000_ring`'s tests check them: every posted
    /// descriptor is counted done, held, or abandoned by a device outcome;
    /// none was rewritten while device-owned.
    fn ledger(slots: &TxSlots, port: &Port, counters: &TxCounters, abandoned: u64) {
        assert_eq!(
            port.ring.posted,
            counters.frames + u64::from(slots.held().is_some()) + abandoned,
            "I1: posted = frames + held + abandoned"
        );
        assert!(
            !port.ring.overwrote_owned,
            "I3: a device-owned descriptor was rewritten"
        );
    }

    /// One send whose whole bound runs without carrier: descriptor 0 held.
    fn one_held() -> (TxSlots, Port, TxCounters) {
        let (mut slots, mut port, mut counters) = (
            TxSlots::new(),
            I219Tx::new(Ring::down()),
            TxCounters::default(),
        );
        assert_eq!(
            send(&mut slots, &mut port, &mut counters),
            TxOutcome::NoCarrier
        );
        assert_eq!(slots.held(), Some(0));
        assert_eq!(
            counters,
            TxCounters {
                frames: 0,
                errors: 1
            }
        );
        assert_eq!(port.ring.delays, TX_POLLS, "a whole bound ran");
        (slots, port, counters)
    }

    #[test]
    fn carrier_present_sends_complete_and_count_once_across_ring_wraps() {
        let (mut slots, mut port, mut counters) = (
            TxSlots::new(),
            I219Tx::new(Ring::up()),
            TxCounters::default(),
        );
        for sent in 1..=40u64 {
            assert_eq!(send(&mut slots, &mut port, &mut counters), TxOutcome::Sent);
            assert_eq!(
                counters,
                TxCounters {
                    frames: sent,
                    errors: 0
                }
            );
        }
        assert_eq!(slots.held(), None);
        assert_eq!(port.ring.tail, 40 % TX_DESCRIPTORS);
        assert_eq!(port.ring.delays, 0, "done at the first poll waits nothing");
        assert_eq!(port.faults, TxFaults::default());
        ledger(&slots, &port, &counters, 0);
    }

    #[test]
    fn a_post_fences_before_the_tail_and_a_done_bit_is_fenced_before_reuse() {
        let (mut slots, mut port, mut counters) = (
            TxSlots::new(),
            I219Tx::new(Ring::up()),
            TxCounters::default(),
        );
        assert_eq!(send(&mut slots, &mut port, &mut counters), TxOutcome::Sent);
        assert_eq!(
            port.ring.trace,
            [
                Op::Read(STATUS),
                Op::SetWord(0, 60 | (u64::from(TX_COMMAND) << 24)),
                Op::Fence,
                Op::Write(TDT, 1),
                Op::Word(0),
                Op::Fence,
            ]
        );
    }

    #[test]
    fn carrier_is_status_lu_alone_and_all_ones_reads_as_carrier() {
        for (status, up) in [
            (UP, true),
            (STATUS_LINK_UP, true),
            (UP & !STATUS_LINK_UP, false),
            (0, false),
            (u32::MAX, true),
        ] {
            let mut port = I219Tx::new(Ring {
                status,
                ..Ring::up()
            });
            assert_eq!(port.link_up(), up, "STATUS {status:#x}");
            assert_eq!(port.ring.trace, [Op::Read(STATUS)]);
        }
    }

    #[test]
    fn bound_expiry_without_carrier_holds_the_descriptor() {
        let (slots, port, counters) = one_held();
        assert_eq!(port.ring.posted, 1);
        assert!(port.ring.owned[0], "the held descriptor stays the device's");
        assert_eq!(port.faults, TxFaults::default());
        ledger(&slots, &port, &counters, 0);
    }

    #[test]
    fn sends_while_held_without_carrier_post_nothing_and_wait_nothing() {
        let (mut slots, mut port, mut counters) = one_held();
        port.ring.trace.clear();
        for _ in 0..3 {
            assert_eq!(
                send(&mut slots, &mut port, &mut counters),
                TxOutcome::NoCarrier
            );
        }
        assert_eq!(
            counters,
            TxCounters {
                frames: 0,
                errors: 1
            }
        );
        assert_eq!(port.ring.posted, 1);
        assert!(
            port.ring
                .trace
                .iter()
                .all(|op| matches!(op, Op::Word(0) | Op::Read(STATUS))),
            "{:?}",
            port.ring.trace
        );
        ledger(&slots, &port, &counters, 0);
    }

    #[test]
    fn a_late_done_bit_is_reaped_once_then_posting_resumes() {
        let (mut slots, mut port, mut counters) = one_held();
        port.ring.complete_late(0);
        slots.reap(&mut port, &mut counters);
        slots.reap(&mut port, &mut counters);
        assert_eq!(slots.held(), None);
        assert_eq!(
            counters,
            TxCounters {
                frames: 1,
                errors: 1
            }
        );
        port.ring.status = UP;
        port.ring.completes = true;
        assert_eq!(send(&mut slots, &mut port, &mut counters), TxOutcome::Sent);
        assert!(
            port.ring.trace.contains(&Op::Write(TDT, 2)),
            "descriptor 1 is posted next"
        );
        assert_eq!(
            counters,
            TxCounters {
                frames: 2,
                errors: 1
            }
        );
        ledger(&slots, &port, &counters, 0);
    }

    #[test]
    fn the_fresh_bound_after_carrier_returns_is_bounded() {
        for (tick_step, delays) in [(0, TX_POLLS), (1, TX_POLLS), (10, 10)] {
            let (mut slots, mut port, mut counters) = one_held();
            port.ring.status = UP;
            port.ring.tick_step = tick_step;
            port.ring.delays = 0;
            assert_eq!(
                send(&mut slots, &mut port, &mut counters),
                TxOutcome::DeviceFailed
            );
            assert_eq!(port.ring.delays, delays, "tick_step {tick_step}");
            assert_eq!(
                port.ring.posted, 1,
                "nothing posted over the held descriptor"
            );
            assert_eq!(slots.held(), Some(0), "abandoned in place, never reused");
            assert_eq!(
                counters,
                TxCounters {
                    frames: 0,
                    errors: 2
                }
            );
            ledger(&slots, &port, &counters, 0);
        }
    }

    #[test]
    fn carrier_lost_during_the_fresh_bound_stays_a_link_outcome() {
        let (mut slots, mut port, mut counters) = one_held();
        port.ring.status = UP;
        port.ring.drop_link_in_wait = true;
        assert_eq!(
            send(&mut slots, &mut port, &mut counters),
            TxOutcome::NoCarrier
        );
        assert_eq!(
            (slots.held(), counters),
            (
                Some(0),
                TxCounters {
                    frames: 0,
                    errors: 1
                }
            )
        );
        assert_eq!(port.ring.posted, 1);
        ledger(&slots, &port, &counters, 0);
    }

    #[test]
    fn bound_expiry_with_carrier_is_a_device_failure() {
        let (mut slots, mut counters) = (TxSlots::new(), TxCounters::default());
        let mut port = I219Tx::new(Ring {
            completes: false,
            ..Ring::up()
        });
        assert_eq!(
            send(&mut slots, &mut port, &mut counters),
            TxOutcome::DeviceFailed
        );
        assert_eq!(
            (slots.held(), counters),
            (
                None,
                TxCounters {
                    frames: 0,
                    errors: 1
                }
            )
        );
        assert_eq!(port.ring.delays, TX_POLLS);
        ledger(&slots, &port, &counters, 1);
    }

    #[test]
    fn an_errored_done_bit_is_done_and_kept_for_the_driver() {
        for errors in 1..8u8 {
            let (mut slots, mut counters) = (TxSlots::new(), TxCounters::default());
            let mut port = I219Tx::new(Ring {
                completion: 1 | (errors << 1),
                ..Ring::up()
            });
            assert_eq!(send(&mut slots, &mut port, &mut counters), TxOutcome::Sent);
            assert_eq!(
                counters,
                TxCounters {
                    frames: 1,
                    errors: 0
                },
                "ruling iii: the done bit is counted"
            );
            assert_eq!(
                port.faults,
                TxFaults {
                    failed: Some(errors << 1),
                    clock: false
                }
            );
            assert_eq!(port.ring.trace.last(), Some(&Op::Fence));
        }
    }

    #[test]
    fn a_stalled_clock_ends_the_bound_at_once_and_is_kept_for_the_driver() {
        for link in [true, false] {
            let (mut slots, mut counters) = (TxSlots::new(), TxCounters::default());
            let ring = if link { Ring::up() } else { Ring::down() };
            let mut port = I219Tx::new(Ring {
                completes: false,
                clock_ok: false,
                ..ring
            });
            let outcome = send(&mut slots, &mut port, &mut counters);
            assert_eq!(
                outcome,
                if link {
                    TxOutcome::DeviceFailed
                } else {
                    TxOutcome::NoCarrier
                }
            );
            assert_eq!(port.ring.delays, 1);
            assert!(port.faults.clock, "the driver must see the stalled clock");
        }
    }

    #[test]
    fn the_port_writes_only_tdt_and_never_the_transmitter_enable() {
        let (mut slots, mut port, mut counters) = (
            TxSlots::new(),
            I219Tx::new(Ring::up()),
            TxCounters::default(),
        );
        assert_eq!(send(&mut slots, &mut port, &mut counters), TxOutcome::Sent);
        port.ring.status = UP & !STATUS_LINK_UP;
        port.ring.completes = false;
        assert_eq!(
            send(&mut slots, &mut port, &mut counters),
            TxOutcome::NoCarrier
        );
        port.ring.complete_late(1);
        port.ring.status = UP;
        port.ring.completes = true;
        assert_eq!(send(&mut slots, &mut port, &mut counters), TxOutcome::Sent);
        assert!(
            !port
                .ring
                .trace
                .iter()
                .any(|op| matches!(op, Op::Read(TCTL) | Op::Write(TCTL, _)))
        );
        assert!(port.ring.trace.iter().all(|op| match op {
            Op::Write(offset, _) => *offset == TDT,
            Op::Read(offset) => *offset == STATUS,
            _ => true,
        }));
        assert_eq!(
            counters,
            TxCounters {
                frames: 3,
                errors: 1
            }
        );
        ledger(&slots, &port, &counters, 0);
    }

    fn step(
        slots: &mut TxSlots,
        port: &mut Port,
        counters: &mut TxCounters,
        carrier: Result<bool, ()>,
    ) -> SendStep {
        send_step(carrier, slots, port, counters, 60, |_| true)
    }

    /// A send whose bound expires after carrier drops mid-bound: descriptor
    /// 0 held, the NIC not disabled, carrier now absent.
    fn held_by_step() -> (TxSlots, Port, TxCounters) {
        let (mut slots, mut counters) = (TxSlots::new(), TxCounters::default());
        let mut port = I219Tx::new(Ring {
            completes: false,
            drop_link_in_wait: true,
            ..Ring::up()
        });
        assert_eq!(
            step(&mut slots, &mut port, &mut counters, Ok(true)),
            SendStep::NoCarrier
        );
        assert_eq!(
            (slots.held(), counters),
            (
                Some(0),
                TxCounters {
                    frames: 0,
                    errors: 1
                }
            )
        );
        port.ring.drop_link_in_wait = false;
        (slots, port, counters)
    }

    /// The mutation target (Step 4): before C3 a send without carrier was
    /// `SendError::Disabled` (`ERROR_IO`).
    #[test]
    fn carrier_down_before_post_is_no_carrier_and_touches_nothing() {
        let (mut slots, mut port, mut counters) = (
            TxSlots::new(),
            I219Tx::new(Ring::down()),
            TxCounters::default(),
        );
        assert_eq!(
            step(&mut slots, &mut port, &mut counters, Ok(false)),
            SendStep::NoCarrier
        );
        assert!(
            port.ring.trace.is_empty(),
            "nothing read, posted or waited: {:?}",
            port.ring.trace
        );
        assert_eq!((slots.held(), counters), (None, TxCounters::default()));
    }

    #[test]
    fn a_retired_backend_touches_nothing_even_while_held() {
        let (mut slots, mut port, mut counters) = (
            TxSlots::new(),
            I219Tx::new(Ring::up()),
            TxCounters::default(),
        );
        assert_eq!(
            step(&mut slots, &mut port, &mut counters, Err(())),
            SendStep::Retired
        );
        assert!(port.ring.trace.is_empty());
        let (mut slots, mut port, mut counters) = held_by_step();
        port.ring.complete_late(0);
        port.ring.trace.clear();
        assert_eq!(
            step(&mut slots, &mut port, &mut counters, Err(())),
            SendStep::Retired
        );
        assert!(
            port.ring.trace.is_empty(),
            "a retired NIC's descriptors are not consulted"
        );
        assert_eq!(
            counters,
            TxCounters {
                frames: 0,
                errors: 1
            }
        );
    }

    /// `Nic::disable` replaces `TxSlots` with `TxSlots::new()` (the grep
    /// gate holds it there). Behaviourally: a hold that a stale `TxSlots`
    /// would act on (a done-bit read, a fresh bound, a disable) is gone after
    /// that reset; the abandoned descriptor is never reaped or counted, even
    /// once its done bit appears; a send with carrier on a fresh ring is
    /// decided by the fresh state alone, never refused by the stale hold.
    #[test]
    fn the_disable_reset_drops_the_hold_and_never_reaps_or_refuses_from_it() {
        // Control: the stale hold decides a send with carrier back.
        let (mut stale, mut port, mut counters) = held_by_step();
        port.ring.status = UP;
        assert_eq!(
            step(&mut stale, &mut port, &mut counters, Ok(true)),
            SendStep::Disable(TxFault::Timeout)
        );

        let (slots, mut port, mut counters) = held_by_step();
        assert_eq!(slots.held(), Some(0));
        // What `Nic::disable` does to the held state.
        let mut slots = TxSlots::new();
        assert_eq!(slots.held(), None);
        port.ring.complete_late(0);
        port.ring.status = UP;
        port.ring.trace.clear();
        assert_eq!(reap_held(&mut slots, &mut port, &mut counters), None);
        assert!(
            port.ring.trace.is_empty(),
            "the abandoned descriptor's done bit is not read: {:?}",
            port.ring.trace
        );
        assert_eq!(
            counters,
            TxCounters {
                frames: 0,
                errors: 1
            },
            "the abandoned descriptor is never counted"
        );
        assert_eq!(
            step(&mut slots, &mut port, &mut counters, Ok(false)),
            SendStep::NoCarrier
        );
        assert!(
            port.ring.trace.is_empty(),
            "no stale done-bit read: {:?}",
            port.ring.trace
        );

        // A send with carrier on a fresh ring: the fresh state alone decides.
        let mut fresh = I219Tx::new(Ring::up());
        let mut fresh_counters = TxCounters::default();
        assert_eq!(
            step(&mut slots, &mut fresh, &mut fresh_counters, Ok(true)),
            SendStep::Sent
        );
        assert_eq!(fresh.ring.delays, 0, "no fresh bound for a stale hold");
        assert_eq!(fresh.ring.posted, 1);
        assert_eq!(
            fresh_counters,
            TxCounters {
                frames: 1,
                errors: 0
            }
        );
        ledger(&slots, &fresh, &fresh_counters, 0);
    }

    #[test]
    fn carrier_up_sends_complete() {
        let (mut slots, mut port, mut counters) = (
            TxSlots::new(),
            I219Tx::new(Ring::up()),
            TxCounters::default(),
        );
        for sent in 1..=20u64 {
            assert_eq!(
                step(&mut slots, &mut port, &mut counters, Ok(true)),
                SendStep::Sent
            );
            assert_eq!(
                counters,
                TxCounters {
                    frames: sent,
                    errors: 0
                }
            );
        }
        ledger(&slots, &port, &counters, 0);
    }

    #[test]
    fn expiry_without_carrier_holds_then_later_sends_refuse_at_once() {
        let (mut slots, mut port, mut counters) = held_by_step();
        port.ring.trace.clear();
        port.ring.delays = 0;
        for _ in 0..3 {
            assert_eq!(
                step(&mut slots, &mut port, &mut counters, Ok(false)),
                SendStep::NoCarrier
            );
        }
        assert_eq!(port.ring.delays, 0);
        assert_eq!(port.ring.posted, 1);
        assert!(
            port.ring.trace.iter().all(|op| *op == Op::Word(0)),
            "only the held done bit is read: {:?}",
            port.ring.trace
        );
        assert_eq!(
            counters,
            TxCounters {
                frames: 0,
                errors: 1
            }
        );
        ledger(&slots, &port, &counters, 0);
    }

    #[test]
    fn carrier_back_and_a_fresh_bound_without_completion_disables_as_timeout() {
        let (mut slots, mut port, mut counters) = held_by_step();
        port.ring.status = UP;
        port.ring.delays = 0;
        assert_eq!(
            step(&mut slots, &mut port, &mut counters, Ok(true)),
            SendStep::Disable(TxFault::Timeout)
        );
        assert_eq!(port.ring.delays, TX_POLLS, "one bounded fresh bound");
        assert_eq!(port.ring.posted, 1);
        assert_eq!(
            counters,
            TxCounters {
                frames: 0,
                errors: 2
            }
        );
    }

    #[test]
    fn carrier_back_with_the_held_descriptor_done_resumes_in_order() {
        let (mut slots, mut port, mut counters) = held_by_step();
        port.ring.complete_late(0);
        port.ring.status = UP;
        port.ring.completes = true;
        assert_eq!(
            step(&mut slots, &mut port, &mut counters, Ok(true)),
            SendStep::Sent
        );
        assert_eq!(
            counters,
            TxCounters {
                frames: 2,
                errors: 1
            }
        );
        assert!(
            port.ring.trace.contains(&Op::Write(TDT, 2)),
            "descriptor 1 is posted after 0 completed"
        );
        ledger(&slots, &port, &counters, 0);
    }

    #[test]
    fn an_errored_done_bit_is_counted_then_disables() {
        let (mut slots, mut counters) = (TxSlots::new(), TxCounters::default());
        let mut port = I219Tx::new(Ring {
            completion: 1 | (1 << 2),
            ..Ring::up()
        });
        assert_eq!(
            step(&mut slots, &mut port, &mut counters, Ok(true)),
            SendStep::Disable(TxFault::Error(1 << 2))
        );
        assert_eq!(
            counters,
            TxCounters {
                frames: 1,
                errors: 0
            }
        );
    }

    #[test]
    fn an_errored_late_done_bit_disables_even_without_carrier() {
        let (mut slots, mut port, mut counters) = held_by_step();
        port.ring.completion = 1 | (1 << 3);
        port.ring.complete_late(0);
        assert_eq!(
            step(&mut slots, &mut port, &mut counters, Ok(false)),
            SendStep::Disable(TxFault::Error(1 << 3))
        );
        assert_eq!(
            counters,
            TxCounters {
                frames: 1,
                errors: 1
            }
        );
        let (mut slots, mut port, mut counters) = held_by_step();
        port.ring.completion = 1 | (1 << 1);
        port.ring.complete_late(0);
        assert_eq!(
            reap_held(&mut slots, &mut port, &mut counters),
            Some(TxFault::Error(1 << 1))
        );
        assert_eq!(
            reap_held(&mut slots, &mut port, &mut counters),
            None,
            "reaped once"
        );
        assert_eq!(
            counters,
            TxCounters {
                frames: 1,
                errors: 1
            }
        );
    }

    #[test]
    fn a_stalled_clock_disables_as_clock_never_as_no_carrier() {
        let (mut slots, mut counters) = (TxSlots::new(), TxCounters::default());
        let mut port = I219Tx::new(Ring {
            completes: false,
            drop_link_in_wait: true,
            clock_ok: false,
            ..Ring::up()
        });
        assert_eq!(
            step(&mut slots, &mut port, &mut counters, Ok(true)),
            SendStep::Disable(TxFault::Clock)
        );
        assert_eq!(
            slots.held(),
            Some(0),
            "TxSlots itself read the bound as a link outcome"
        );
    }

    #[test]
    fn a_refused_copy_posts_nothing_and_keeps_the_slot() {
        let (mut slots, mut port, mut counters) = (
            TxSlots::new(),
            I219Tx::new(Ring::up()),
            TxCounters::default(),
        );
        let mut offered = None;
        assert_eq!(
            send_step(
                Ok::<bool, ()>(true),
                &mut slots,
                &mut port,
                &mut counters,
                60,
                |index| {
                    offered = Some(index);
                    false
                }
            ),
            SendStep::Copy
        );
        assert_eq!(
            (offered, port.ring.posted, counters),
            (Some(0), 0, TxCounters::default())
        );
        assert_eq!(
            step(&mut slots, &mut port, &mut counters, Ok(true)),
            SendStep::Sent
        );
        assert!(
            port.ring.trace.contains(&Op::Write(TDT, 1)),
            "descriptor 0 is posted by the next send"
        );
    }

    #[test]
    fn faults_never_carry_over_between_calls() {
        let (mut slots, mut port, mut counters) = (
            TxSlots::new(),
            I219Tx::new(Ring::up()),
            TxCounters::default(),
        );
        port.faults = TxFaults {
            failed: Some(2),
            clock: true,
        };
        assert_eq!(
            step(&mut slots, &mut port, &mut counters, Ok(true)),
            SendStep::Sent
        );
        port.faults = TxFaults {
            failed: Some(2),
            clock: true,
        };
        assert_eq!(reap_held(&mut slots, &mut port, &mut counters), None);
    }

    /// Carried from the Task 1 review: a stalled clock with the link down
    /// is a link outcome to `TxSlots` (it holds the descriptor), but the
    /// send is a device outcome, `Clock`, never `NoCarrier`; both on a
    /// first send and on the fresh bound for a held descriptor.
    #[test]
    fn a_stalled_clock_with_the_link_down_disables_as_clock_never_as_no_carrier() {
        let (mut slots, mut counters) = (TxSlots::new(), TxCounters::default());
        let mut port = I219Tx::new(Ring {
            clock_ok: false,
            ..Ring::down()
        });
        assert_eq!(
            step(&mut slots, &mut port, &mut counters, Ok(true)),
            SendStep::Disable(TxFault::Clock)
        );
        assert_eq!(slots.held(), Some(0), "TxSlots read it as NoCarrier");
        assert_eq!(port.ring.delays, 1);

        let (mut slots, mut port, mut counters) = held_by_step();
        port.ring.status = UP;
        port.ring.drop_link_in_wait = true;
        port.ring.clock_ok = false;
        port.ring.delays = 0;
        assert_eq!(
            step(&mut slots, &mut port, &mut counters, Ok(true)),
            SendStep::Disable(TxFault::Clock)
        );
        assert_eq!(port.ring.delays, 1, "the fresh bound ended at once");
        assert_eq!(port.ring.posted, 1, "nothing posted over the held slot");
    }
}
