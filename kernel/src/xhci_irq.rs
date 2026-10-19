//! Bounded IRQ accounting and MSI-X register separation for stage 1.
//! Only BSP foreground code arms/retires a generation with IF clear. The
//! ISR records delivery; it cannot establish which transfer completed.
use crate::{
    pci_interrupt::{self, Msix},
    xhci_ring::Layout,
};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub const INTERRUPT_BUDGET: u64 = 64;

/// Register operations implemented by the hardware route and by ordering
/// fixtures. The caller has already acquired the function and validated
/// the complete table mapping. No BAR or ownership discovery happens here.
pub trait MsixAccess {
    fn config_read(&mut self, offset: u8) -> u32;
    fn config_write(&mut self, offset: u8, value: u32);
    fn entry_read(&mut self, index: u16, word: u8) -> u32;
    fn entry_write(&mut self, index: u16, word: u8, value: u32);
}

fn control(access: &mut impl MsixAccess, capability: u8, enable: bool, masked: bool) {
    let before = access.config_read(capability);
    access.config_write(
        capability,
        (before & !0xc000_0000) | ((enable as u32) << 31) | ((masked as u32) << 30),
    );
}

pub fn configure_msix(
    access: &mut impl MsixAccess,
    msix: Msix,
    msi: Option<u8>,
    destination: u8,
    vector: u8,
) -> Result<(), Error> {
    control(access, msix.capability, false, true);
    if access.config_read(msix.capability) & 0xc000_0000 != 0x4000_0000 {
        return Err(Error::Readback);
    }
    if let Some(at) = msi {
        let before = access.config_read(at);
        access.config_write(at, before & !(1 << 16));
        if access.config_read(at) & (1 << 16) != 0 {
            return Err(Error::Readback);
        }
    }
    for n in 0..msix.vectors {
        let before = access.entry_read(n, 3);
        access.entry_write(n, 3, before | 1);
        if access.entry_read(n, 3) & 1 == 0 {
            return Err(Error::Readback);
        }
    }
    let message = 0xfee0_0000 | (u32::from(destination) << 12);
    access.entry_write(0, 0, message);
    access.entry_write(0, 1, 0);
    access.entry_write(0, 2, u32::from(vector));
    if access.entry_read(0, 0) != message
        || access.entry_read(0, 1) != 0
        || access.entry_read(0, 2) != u32::from(vector)
    {
        return Err(Error::Readback);
    }
    Ok(())
}

pub fn enable_msix(access: &mut impl MsixAccess, msix: Msix, masked: bool) -> Result<(), Error> {
    control(access, msix.capability, true, false);
    if !masked {
        access.entry_write(0, 3, 0);
    }
    if access.config_read(msix.capability) & 0xc000_0000 != 0x8000_0000
        || access.entry_read(0, 3) & 1 != u32::from(masked)
    {
        return Err(Error::Readback);
    }
    Ok(())
}

pub fn disable_msix(access: &mut impl MsixAccess, msix: Msix) -> Result<(), Error> {
    let before = access.entry_read(0, 3);
    access.entry_write(0, 3, before | 1);
    let masked = access.entry_read(0, 3) & 1 != 0;
    control(access, msix.capability, false, true);
    let disabled = access.config_read(msix.capability) & 0xc000_0000 == 0x4000_0000;
    if masked && disabled {
        Ok(())
    } else {
        Err(Error::Readback)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Capabilities(pci_interrupt::Error),
    MissingMsix,
    OtherBar,
    Interrupters { vectors: u16, max: u16 },
    RegisterOverlap,
    Apic,
    Map,
    Readback,
    InterruptStorm,
    CompletedWithoutInterrupt,
    Drain,
}

/// Extended-capability span is the conservative minimum/maximum of all
/// words read during traversal, including the legacy register pair.
pub fn validate(
    msix: Msix,
    layout: Layout,
    max_intrs: u16,
    extended: (u64, u64),
) -> Result<(), Error> {
    if max_intrs == 0 || max_intrs > 1024 || msix.vectors != max_intrs {
        return Err(Error::Interrupters {
            vectors: msix.vectors,
            max: max_intrs,
        });
    }
    if msix.table.bar != 0 || msix.pending.bar != 0 {
        return Err(Error::OtherBar);
    }
    msix.validate_regions([Some(layout.bar_bytes), None, None, None, None, None])
        .map_err(Error::Capabilities)?;
    let blocks = [
        (0, layout.operational),
        (
            layout.operational,
            layout.operational + 0x400 + 16 * u64::from(layout.max_ports),
        ),
        (
            layout.runtime,
            layout.runtime + 0x20 + 32 * u64::from(max_intrs),
        ),
        (
            layout.doorbells,
            layout.doorbells + 4 * (u64::from(layout.max_slots) + 1),
        ),
        extended,
    ];
    for region in [msix.table, msix.pending] {
        for (start, end) in blocks {
            if start < end && region.offset < end && start < region.offset + region.bytes {
                return Err(Error::RegisterOverlap);
            }
        }
    }
    Ok(())
}

pub struct State {
    generation: AtomicU64,
    armed: AtomicBool,
    count: AtomicU64,
    late: AtomicU64,
    since_ack: AtomicU64,
    acknowledged: AtomicU64,
    storm: AtomicBool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub generation: u64,
    pub count: u64,
    pub late: u64,
    pub storm: bool,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
impl State {
    pub const fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            armed: AtomicBool::new(false),
            count: AtomicU64::new(0),
            late: AtomicU64::new(0),
            since_ack: AtomicU64::new(0),
            acknowledged: AtomicU64::new(0),
            storm: AtomicBool::new(false),
        }
    }
    /// Requires transport masked, previous IRQ drain established, and IF clear.
    pub fn arm(&self, generation: u64) {
        assert!(!self.armed.load(Ordering::Acquire));
        assert!(generation > self.generation.load(Ordering::Acquire));
        self.count.store(0, Ordering::Relaxed);
        self.since_ack.store(0, Ordering::Relaxed);
        self.acknowledged.store(0, Ordering::Relaxed);
        self.storm.store(false, Ordering::Relaxed);
        self.generation.store(generation, Ordering::Release);
        self.armed.store(true, Ordering::Release);
    }
    pub fn retire(&self) {
        self.armed.store(false, Ordering::Release);
    }
    /// Credit starts at the last event-ring acknowledgement, not at the
    /// next wait: an IRQ may arrive during a port-reset or observation wait.
    pub fn credit_baseline(&self) -> u64 {
        self.acknowledged.load(Ordering::Acquire)
    }
    /// True means the runtime ISR must mask the physical MSI-X entry.
    pub fn interrupt(&self) -> bool {
        if !self.armed.load(Ordering::Acquire) {
            self.late.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        if self.since_ack.fetch_add(1, Ordering::Relaxed) >= INTERRUPT_BUDGET {
            self.storm.store(true, Ordering::Release);
            true
        } else {
            false
        }
    }
    pub fn check(&self) -> Result<(), Error> {
        if self.storm.load(Ordering::Acquire) {
            Err(Error::InterruptStorm)
        } else {
            Ok(())
        }
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            generation: self.generation.load(Ordering::Acquire),
            count: self.count.load(Ordering::Acquire),
            late: self.late.load(Ordering::Acquire),
            storm: self.storm.load(Ordering::Acquire),
        }
    }
    /// IF is clear. Record delivery before writing ERDP/EHB, which permits
    /// the controller to raise the next interrupt. Reset the delivery
    /// budget at the same boundary, including IRQs outside event waits.
    pub fn acknowledge(&self) {
        self.acknowledged
            .store(self.count.load(Ordering::Acquire), Ordering::Release);
        self.since_ack.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::pci_interrupt::BarRegion;
    use std::vec::Vec;

    struct Registers {
        config: [u32; 64],
        table: [[u32; 4]; 16],
        writes: Vec<(u8, u16, u8, u32)>,
        stuck: bool,
    }
    impl Registers {
        fn new() -> Self {
            Self {
                config: [0; 64],
                table: [[0; 4]; 16],
                writes: Vec::new(),
                stuck: false,
            }
        }
    }
    impl MsixAccess for Registers {
        fn config_read(&mut self, offset: u8) -> u32 {
            self.config[usize::from(offset / 4)]
        }
        fn config_write(&mut self, offset: u8, value: u32) {
            self.writes.push((0, u16::from(offset), 0, value));
            if !self.stuck {
                self.config[usize::from(offset / 4)] = value;
            }
        }
        fn entry_read(&mut self, index: u16, word: u8) -> u32 {
            self.table[usize::from(index)][usize::from(word)]
        }
        fn entry_write(&mut self, index: u16, word: u8, value: u32) {
            self.writes.push((1, index, word, value));
            self.table[usize::from(index)][usize::from(word)] = value;
        }
    }
    #[test]
    fn actual_transport_protocol_masks_before_programming_and_unmasks_last() {
        let (msix, _) = fixture();
        let mut r = Registers::new();
        r.config[0x70 / 4] = 1 << 16;
        assert_eq!(configure_msix(&mut r, msix, Some(0x70), 3, 0xd0), Ok(()));
        assert_eq!(r.writes[0], (0, 0x90, 0, 0x4000_0000));
        assert_eq!(r.writes[1], (0, 0x70, 0, 0));
        for n in 0..16 {
            assert_eq!(r.writes[n + 2], (1, n as u16, 3, 1));
        }
        assert_eq!(r.table[0], [0xfee0_3000, 0, 0xd0, 1]);
        assert_eq!(enable_msix(&mut r, msix, false), Ok(()));
        assert_eq!(r.writes[r.writes.len() - 2], (0, 0x90, 0, 0x8000_0000));
        assert_eq!(r.writes[r.writes.len() - 1], (1, 0, 3, 0));
        let start = r.writes.len();
        assert_eq!(disable_msix(&mut r, msix), Ok(()));
        assert_eq!(r.writes[start], (1, 0, 3, 1));
        assert_eq!(r.writes[start + 1], (0, 0x90, 0, 0x4000_0000));
    }
    #[test]
    fn rejected_function_mask_never_programs_a_table() {
        let (msix, _) = fixture();
        let mut r = Registers::new();
        r.stuck = true;
        assert_eq!(
            configure_msix(&mut r, msix, None, 0, 0xd0),
            Err(Error::Readback)
        );
        assert_eq!(r.writes.len(), 1);
        assert_eq!(r.table, [[0; 4]; 16]);
    }
    #[test]
    fn masked_vector_control_keeps_entry_zero_masked() {
        let (msix, _) = fixture();
        let mut r = Registers::new();
        configure_msix(&mut r, msix, None, 0, 0xd0).unwrap();
        enable_msix(&mut r, msix, true).unwrap();
        assert_eq!(r.table[0][3], 1);
        assert_eq!(r.writes.last().unwrap(), &(0, 0x90, 0, 0x8000_0000));
    }
    fn fixture() -> (Msix, Layout) {
        (
            Msix {
                capability: 0x90,
                enabled: false,
                function_masked: false,
                vectors: 16,
                table: BarRegion {
                    bar: 0,
                    offset: 0x3000,
                    bytes: 256,
                },
                pending: BarRegion {
                    bar: 0,
                    offset: 0x3800,
                    bytes: 8,
                },
            },
            crate::xhci_ring::layout(0x40, (8 << 24) | (16 << 8) | 64, 1, 0x2000, 0x1000, 0x4000)
                .unwrap(),
        )
    }
    #[test]
    fn regions_exclude_every_register_block_and_extended_words() {
        let (mut m, l) = fixture();
        assert_eq!(validate(m, l, 16, (0x800, 0x820)), Ok(()));
        for offset in [0, 0x40, 0x440, 0x800, 0x1000, 0x1200, 0x2000, 0x2100] {
            m.pending.offset = offset;
            assert_eq!(
                validate(m, l, 16, (0x800, 0x820)),
                Err(Error::RegisterOverlap)
            );
        }
    }
    #[test]
    fn different_bar_and_interrupter_mismatch_refuse() {
        let (mut m, l) = fixture();
        for max in [0, 1, 15, 17, 1025] {
            assert!(matches!(
                validate(m, l, max, (0, 0)),
                Err(Error::Interrupters { .. })
            ));
        }
        m.pending.bar = 2;
        assert_eq!(validate(m, l, 16, (0, 0)), Err(Error::OtherBar));
    }
    #[test]
    fn retirement_and_rearm_do_not_credit_late_delivery() {
        let s = State::new();
        s.arm(1);
        let before = s.credit_baseline();
        assert_eq!(before, 0);
        assert!(!s.interrupt());
        s.retire();
        assert!(!s.interrupt());
        assert_eq!(
            s.snapshot(),
            Snapshot {
                generation: 1,
                count: 1,
                late: 1,
                storm: false
            }
        );
        s.arm(2);
        assert_eq!(s.snapshot().count, 0);
        assert_eq!(s.snapshot().late, 1);
        assert!(!s.interrupt());
        assert_eq!(s.snapshot().generation, 2);
    }
    #[test]
    fn storm_is_sticky_and_crosses_on_the_first_excess_irq() {
        let s = State::new();
        s.arm(1);
        for _ in 0..INTERRUPT_BUDGET {
            assert!(!s.interrupt());
        }
        assert!(s.interrupt());
        assert_eq!(s.check(), Err(Error::InterruptStorm));
        s.acknowledge();
        assert_eq!(s.check(), Err(Error::InterruptStorm));
        s.retire();
        s.arm(2);
        assert_eq!(s.check(), Ok(()));
    }
    #[test]
    fn delivery_before_an_event_wait_retains_credit_until_acknowledgement() {
        let s = State::new();
        s.arm(1);
        // Delivery during port reset, before the next wait starts.
        assert!(!s.interrupt());
        assert!(s.snapshot().count > s.credit_baseline());
        s.acknowledge();
        assert_eq!(s.snapshot().count, s.credit_baseline());
        // A new event without a new IRQ cannot use the old delivery.
        assert_eq!(s.credit_baseline(), 1);
        assert!(!s.interrupt());
        assert!(s.snapshot().count > s.credit_baseline());
    }
    #[test]
    fn storm_budget_spans_non_event_waits_and_resets_only_on_ack() {
        let s = State::new();
        s.arm(1);
        for _ in 0..INTERRUPT_BUDGET {
            assert!(!s.interrupt());
            let _ = s.credit_baseline(); // Starting a wait grants no budget.
        }
        s.acknowledge();
        for _ in 0..INTERRUPT_BUDGET {
            assert!(!s.interrupt());
        }
        assert!(s.interrupt());
    }
}
