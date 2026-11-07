//! RTL8125B ring rules for the opt-in `net-rtl8125` NIC (docs/RTL8125.md,
//! "Ring state"), kept apart from the MMIO backend (`src/rtl8125_device.rs`)
//! so they run under `cargo test` on the host. coordination record #109 corrective
//! increment: findings F1, F2, F5, F6 and F10 of the 2026-10-30 review.
//!
//! - RX: every refill writes the slot's own buffer address and a zero
//!   extended status before handing the descriptor back with OWN (the chip
//!   clears the address quadword when it writes a descriptor back).
//! - RX: a frame is delivered only if the interrupt status read after its
//!   descriptor was seen done shows no receive trouble (descriptor
//!   unavailable, FIFO overflow, system error), and only if its FCS is the
//!   CRC-32 of its bytes. Trouble disables the NIC for the boot and leaves
//!   both rings exactly as they are (re-review 1): no ABSD operation shows
//!   that the chip's earlier writes have stopped arriving, so the rings are
//!   never rebuilt or offered again (the device quarantines them).
//! - TX: sends are synchronous through `e1000_ring::TxSlots` (the ABI's
//!   `SYS_NIC_SEND`); a descriptor that completes with TXERR or excessive
//!   collisions is a transmit error, not a frame, and disables the NIC; a
//!   collision count alone is a sent frame, counted in `collisions`.
//! - All-ones from the chip (ISR, or a PHY read the device reports as
//!   `DeviceGone`) is a vanished device, never carrier.

use crate::e1000_ring::{TX_DESCRIPTORS, TxCounters, TxOutcome, TxPort, TxSlots, send_length};
use crate::nic::{NIC_FRAME_MAX, NIC_FRAME_MIN, NicInfo};
use crate::rtl8125::{
    self, EOR, ISR_RX_DESC_UNAVAIL, ISR_RX_FIFO_OFLOW, ISR_SYSTEM_ERR, RxSlot, TxSlot,
};

/// RX descriptors (the e1000's 32: the ABI's 24-frame burst fits).
pub const RX_SLOTS: usize = 32;
/// TX descriptors: `TxSlots` addresses the e1000's ring geometry.
pub const TX_SLOTS: usize = TX_DESCRIPTORS;
/// Bytes each RX descriptor offers and each TX buffer holds.
pub const BUFFER: usize = 2048;
/// The FCS the chip leaves on every received frame.
pub const FCS: usize = 4;
/// ISR bits that mean the receive ring can no longer be trusted to be in
/// step with the chip (review F2; runs x1-x5 of the corrective log).
/// What ends the NIC for the boot, whatever the ring holds. Descriptor-unavailable
/// alone does not: on reference_host-vfio the chip raised it with free slots and every frame
/// intact. It does when no slot is left: see [`Nic::take`].
pub const ISR_RX_TROUBLE: u32 = ISR_RX_FIFO_OFLOW | ISR_SYSTEM_ERR;
/// Polls in a row that may see descriptor-unavailable with no frame to show for
/// it. Past this the chip is saying something nothing here explains, and that
/// is treated as trouble: this must not become an endless retry.
pub const RX_STALL_LIMIT: u32 = 64;
/// One transmit bound: polls 1 ms apart after a short spin.
pub const TX_BOUND_MS: u32 = 10;
/// Descriptor reads before the first 1 ms delay of a bound.
pub const TX_SPIN: u32 = 2_000;

const _: () = assert!(NIC_FRAME_MAX + FCS <= BUFFER && RX_SLOTS * 32 <= 4096);

/// What the ring logic needs from the device: descriptor memory and buffers
/// (`DMA` in `src/rtl8125_device.rs`), the chip's MMIO, and a clock. A model
/// under `cargo test`.
pub trait Port {
    fn rx_cmdsts(&mut self, slot: usize) -> u32;
    fn set_rx_cmdsts(&mut self, slot: usize, value: u32);
    fn set_rx_extsts(&mut self, slot: usize, value: u32);
    fn set_rx_address(&mut self, slot: usize, address: u64);
    /// The device address of RX buffer `slot`.
    fn rx_buffer_address(&self, slot: usize) -> u64;
    /// The first `len` bytes of RX buffer `slot`.
    fn rx_bytes(&self, slot: usize, len: usize) -> &[u8];
    fn tx_cmdsts(&mut self, slot: usize) -> u32;
    fn set_tx_cmdsts(&mut self, slot: usize, value: u32);
    fn set_tx_address(&mut self, slot: usize, address: u64);
    fn tx_buffer_address(&self, slot: usize) -> u64;
    fn tx_buffer(&mut self, slot: usize) -> &mut [u8];
    /// A full fence (`fence(SeqCst)` on the device).
    fn fence(&mut self);
    /// TXSTART.
    fn doorbell(&mut self);
    fn isr(&mut self) -> u32;
    /// Writes `bits` to ISR (write one to clear).
    fn ack_isr(&mut self, bits: u32);
    /// Carrier from the PHY's BMSR (`rtl8125::cable_link`).
    fn carrier(&mut self) -> Result<bool, rtl8125::Error>;
    /// A measured delay; false when the clock has stalled.
    fn delay_ms(&mut self, ms: u32) -> bool;
}

/// The DMA surface as (first page, pages) per part, each starting on its own
/// page so no page holds two roles (design section 7).
#[derive(Clone, Copy, Debug)]
pub struct Surface {
    pub tx_ring: (usize, usize),
    pub rx_ring: (usize, usize),
    pub tx_buffers: (usize, usize),
    pub rx_buffers: (usize, usize),
}

const fn pages_for(bytes: usize) -> usize {
    bytes.div_ceil(4096)
}

const TX_RING_PAGES: usize = pages_for(TX_SLOTS * crate::rtl8125::DESCRIPTOR_BYTES);
const RX_RING_PAGES: usize = pages_for(RX_SLOTS * crate::rtl8125::DESCRIPTOR_BYTES);
const TX_BUFFER_PAGES: usize = pages_for(TX_SLOTS * BUFFER);
const RX_BUFFER_PAGES: usize = pages_for(RX_SLOTS * BUFFER);

pub const SURFACE: Surface = Surface {
    tx_ring: (0, TX_RING_PAGES),
    rx_ring: (TX_RING_PAGES, RX_RING_PAGES),
    tx_buffers: (TX_RING_PAGES + RX_RING_PAGES, TX_BUFFER_PAGES),
    rx_buffers: (
        TX_RING_PAGES + RX_RING_PAGES + TX_BUFFER_PAGES,
        RX_BUFFER_PAGES,
    ),
};

impl Surface {
    pub const fn pages(&self) -> usize {
        self.rx_buffers.0 + self.rx_buffers.1
    }

    /// The device writes descriptors back, reads only what it transmits and
    /// writes only what it receives.
    pub fn perm_of(&self, page: usize) -> crate::amdvi::Perm {
        if page >= self.rx_buffers.0 {
            crate::amdvi::Perm::WRITE
        } else if page >= self.tx_buffers.0 {
            crate::amdvi::Perm::READ
        } else {
            crate::amdvi::Perm::READ_WRITE
        }
    }
}

/// Why the NIC was disabled. The device maps these into its log line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    /// A whole transmit bound ran with carrier present and expired.
    TxTimeout,
    /// A transmit descriptor came back with error bits (kept).
    TxError(u32),
    /// The clock stalled inside a bound.
    Clock,
    /// ISR or a PHY register read all ones: the function stopped decoding.
    DeviceGone,
    /// A PHY read failed in another way (timeout).
    PhyRead(rtl8125::Error),
    /// Receive trouble (ISR bits kept): descriptor unavailable, FIFO
    /// overflow or system error. RX is dead for the boot, visibly.
    RxTrouble(u32),
    /// `dma-contain`: the unit failed or the target was revoked.
    ContainmentLost,
}

/// What one send decided (the e1000/I219 outcomes, docs/NETWORK.md).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Send {
    /// The descriptor came back done without error bits.
    Sent,
    /// Length outside the ABI's range; nothing reached the device.
    Length,
    /// `fill` could not copy the frame; nothing was posted.
    Copy,
    /// A link outcome (`ERROR_NO_CARRIER`); the NIC stays enabled.
    NoCarrier,
    /// The NIC is disabled (`ERROR_IO`): before this send or by it.
    Disabled,
}

/// What a receive poll found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Take {
    /// A frame of this many bytes (FCS removed) was delivered.
    Frame(usize),
    /// Nothing complete is waiting (or `deliver` declined it).
    Empty,
}

/// Ethernet's CRC-32 (reflected 0x04c11db7), as the FCS carries it.
pub fn crc32(bytes: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut crc = i as u32;
            let mut bit = 0;
            while bit < 8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
                bit += 1;
            }
            table[i] = crc;
            i += 1;
        }
        table
    };
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc = TABLE[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

/// Whether `frame` (as received, FCS last) carries the right FCS.
pub fn fcs_ok(frame: &[u8]) -> bool {
    let Some(split) = frame.len().checked_sub(FCS) else {
        return false;
    };
    let (body, fcs) = frame.split_at(split);
    crc32(body).to_le_bytes() == [fcs[0], fcs[1], fcs[2], fcs[3]]
}

/// Hands RX descriptor `slot` back to the chip, as rge_newbuf does: its own
/// buffer address and a zero extended status first, a fence, then the
/// command word with OWN (and EOR on the last slot).
pub fn offer_rx(port: &mut impl Port, slot: usize) {
    let address = port.rx_buffer_address(slot);
    port.set_rx_address(slot, address);
    port.set_rx_extsts(slot, 0);
    port.fence();
    port.set_rx_cmdsts(slot, rtl8125::rx_cmdsts(BUFFER, slot == RX_SLOTS - 1));
}

/// Builds both rings for the chip: every RX slot offered, every TX slot the
/// kernel's (its address written, no OWN, EOR on the last).
pub fn build_rings(port: &mut impl Port) {
    for slot in 0..RX_SLOTS {
        offer_rx(port, slot);
    }
    for slot in 0..TX_SLOTS {
        let address = port.tx_buffer_address(slot);
        port.set_tx_address(slot, address);
        port.set_tx_cmdsts(slot, if slot == TX_SLOTS - 1 { EOR } else { 0 });
    }
    port.fence();
}

/// Who may touch the static DMA memory (descriptors and buffers). It moves
/// Kernel -> Device when bus mastering is armed and never back: no ABSD
/// operation shows that a write the chip already issued has landed, so a
/// stop (however well confirmed) and a bus-master fence end in
/// `Quarantined` for the boot (re-review 2). The memory is static and is
/// never handed to anyone else, so a late write can land only in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Custody {
    Kernel,
    Device,
    Quarantined,
}

impl Custody {
    /// Arming bus mastering: only memory the kernel holds may be armed.
    pub fn arm(self) -> Option<Custody> {
        (self == Custody::Kernel).then_some(Custody::Device)
    }

    /// The stop and fence after a run, whatever they showed: armed memory
    /// is quarantined, never returned. Unarmed memory stays the kernel's.
    pub fn release(self, _stop_confirmed: bool, _bus_master_clear: bool) -> Custody {
        match self {
            Custody::Kernel => Custody::Kernel,
            Custody::Device | Custody::Quarantined => Custody::Quarantined,
        }
    }

    /// Whether the kernel may write (scrub, rebuild, reuse) the memory.
    pub fn writable(self) -> bool {
        self == Custody::Kernel
    }
}

/// Whether a descriptor's buffer may be read after a diagnostic run. Only
/// one the chip handed back: OWN clear in a descriptor that was offered.
/// The chip writes a descriptor back only after the frame's data, and both
/// are posted writes from the same function, which PCIe keeps in order
/// unless Relaxed Ordering is enabled. Arming requires Relaxed Ordering
/// and No Snoop disabled in Device Control (the driver clears them and
/// reads back, and `arm` re-reads them), so the data is in place once OWN
/// reads clear. Every descriptor's status word may be read; the buffer of
/// one still OWN (or never offered) is not, since the chip may still write
/// it.
pub fn inspectable(offered: bool, cmdsts: u32) -> bool {
    offered && cmdsts & rtl8125::OWN == 0
}

/// The NIC's ring state and counters; one per boot, polled on the BSP.
#[derive(Clone, Copy, Debug)]
pub struct Nic {
    pub info: NicInfo,
    rx_next: usize,
    tx: TxSlots,
    fault: Option<Fault>,
    /// Polls in a row with descriptor-unavailable and no frame.
    rx_stall: u32,
    /// Slots handed back since the last ISR read.
    refills_since_isr: u32,
    /// Collisions reported by sent frames (rge's `if_collisions`; not in
    /// the ABI record).
    pub collisions: u64,
}

impl Nic {
    /// After `build_rings` and before the chip is started.
    pub const fn new(mac: [u8; 6]) -> Self {
        Self {
            info: NicInfo {
                mac,
                flags: 0,
                rx_frames: 0,
                rx_refused: 0,
                rx_missed: 0,
                tx_frames: 0,
                tx_refused: 0,
                tx_errors: 0,
            },
            rx_next: 0,
            rx_stall: 0,
            refills_since_isr: 0,
            tx: TxSlots::new(),
            fault: None,
            collisions: 0,
        }
    }

    pub const fn fault(&self) -> Option<Fault> {
        self.fault
    }
    pub const fn rx_next(&self) -> usize {
        self.rx_next
    }
    pub const fn held(&self) -> Option<usize> {
        self.tx.held()
    }

    /// Marks the NIC disabled; the device stops the chip and fences bus
    /// mastering when this returns a new fault.
    pub fn disable(&mut self, fault: Fault) {
        if self.fault.is_none() {
            self.fault = Some(fault);
        }
    }

    /// Carrier, with a vanished device or a failed PHY read disabling the
    /// NIC rather than reading as link.
    pub fn carrier(&mut self, port: &mut impl Port) -> Result<bool, Fault> {
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        match port.carrier() {
            Ok(up) => Ok(up),
            Err(rtl8125::Error::DeviceGone) => {
                self.disable(Fault::DeviceGone);
                Err(Fault::DeviceGone)
            }
            Err(error) => {
                self.disable(Fault::PhyRead(error));
                Err(Fault::PhyRead(error))
            }
        }
    }

    /// ISR, with all ones disabling the NIC.
    fn isr(&mut self, port: &mut impl Port) -> Result<u32, Fault> {
        let isr = port.isr();
        if isr == u32::MAX {
            self.disable(Fault::DeviceGone);
            return Err(Fault::DeviceGone);
        }
        Ok(isr)
    }

    /// Receive trouble: a FIFO overflow or a stall past [`RX_STALL_LIMIT`] is
    /// counted as missed, since nothing shows otherwise (it gives no count), and
    /// the NIC is disabled. Nothing in either ring is touched: the frames
    /// still there are neither delivered nor re-offered, and no descriptor
    /// is rebuilt, because a write the chip issued before it was stopped
    /// could still land on a re-offered descriptor and pass as a current
    /// frame (re-review 1). The device stops the chip, fences bus mastering
    /// and keeps the memory quarantined.
    fn trouble(&mut self, isr: u32) -> Fault {
        if isr & (ISR_RX_DESC_UNAVAIL | ISR_RX_FIFO_OFLOW) != 0 {
            self.info.rx_missed += 1;
        }
        let fault = Fault::RxTrouble(isr);
        self.disable(fault);
        fault
    }

    /// One receive poll. `deliver` copies the frame (FCS removed) and
    /// reports whether it could; a declined frame stays counted as nothing
    /// and its slot is recycled (as in the e1000 backend).
    pub fn take(
        &mut self,
        port: &mut impl Port,
        deliver: impl FnOnce(&[u8]) -> bool,
    ) -> Result<Take, Fault> {
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        for _ in 0..RX_SLOTS {
            let slot = self.rx_next;
            let cmdsts = port.rx_cmdsts(slot);
            // The descriptor is observed before ISR, and both before the
            // buffer: a descriptor written after trouble began is never
            // delivered, because the ISR read that follows it shows it.
            port.fence();
            let isr = self.isr(port)?;
            if isr & ISR_RX_TROUBLE != 0 {
                return Err(self.trouble(isr));
            }
            let refills = core::mem::take(&mut self.refills_since_isr);
            let unavailable = isr & ISR_RX_DESC_UNAVAIL != 0;
            if unavailable {
                // The bit alone does not say the ring ran out: the chip raises it
                // with slots free. No slot left does, and past that point reference_host
                // showed frames out of order, so that stays terminal. A slot handed
                // back since the last ISR read may have come after the chip ran out,
                // so it does not count as free.
                //
                // Cleared first, so a later one can be told from this one, and
                // only this bit. The read flushes the write. Running out before
                // that was erased from ISR but shows in the scan below; running
                // out after it raises the bit again for the next poll.
                port.ack_isr(ISR_RX_DESC_UNAVAIL);
                let after = self.isr(port)?;
                port.fence();
                if after & ISR_RX_TROUBLE != 0 {
                    return Err(self.trouble(after));
                }
                let free = (0..RX_SLOTS)
                    .filter(|&at| port.rx_cmdsts(at) & rtl8125::OWN != 0)
                    .count() as u32;
                if free <= refills && !cfg!(absd_mutant_rtl8125_exhaustion_ignored) {
                    return Err(self.trouble(isr));
                }
            } else {
                self.rx_stall = 0;
            }
            match rtl8125::rx_slot(cmdsts, BUFFER) {
                RxSlot::Owned => {
                    if unavailable {
                        self.rx_stall += 1;
                        if self.rx_stall >= RX_STALL_LIMIT
                            && !cfg!(absd_mutant_rtl8125_stall_unbounded)
                        {
                            return Err(self.trouble(isr));
                        }
                    }
                    return Ok(Take::Empty);
                }
                RxSlot::Frame(len)
                    if (NIC_FRAME_MIN + FCS..=NIC_FRAME_MAX + FCS).contains(&len)
                        && fcs_ok(port.rx_bytes(slot, len)) =>
                {
                    let bytes = len - FCS;
                    let copied = deliver(port.rx_bytes(slot, bytes));
                    port.fence();
                    offer_rx(port, slot);
                    self.refills_since_isr += 1;
                    self.rx_next = (slot + 1) % RX_SLOTS;
                    self.rx_stall = 0;
                    if !copied {
                        return Ok(Take::Empty);
                    }
                    self.info.rx_frames += 1;
                    return Ok(Take::Frame(bytes));
                }
                _ => {
                    self.info.rx_refused += 1;
                    port.fence();
                    offer_rx(port, slot);
                    self.refills_since_isr += 1;
                    self.rx_next = (slot + 1) % RX_SLOTS;
                }
            }
        }
        Ok(Take::Empty)
    }

    /// One synchronous send (`SYS_NIC_SEND`): `Sent` only once the posted
    /// descriptor came back without error bits; the §10 link and device
    /// outcomes of `TxSlots` otherwise.
    pub fn send(
        &mut self,
        port: &mut impl Port,
        length: u64,
        fill: impl FnOnce(&mut [u8]) -> bool,
    ) -> Send {
        if self.fault.is_some() {
            return Send::Disabled;
        }
        let Some((bytes, wire)) = send_length(length) else {
            self.info.tx_refused += 1;
            return Send::Length;
        };
        let Ok(carrier) = self.carrier(port) else {
            return Send::Disabled;
        };
        let mut counters = TxCounters {
            frames: self.info.tx_frames,
            errors: self.info.tx_errors,
        };
        let mut tx = self.tx;
        let mut adapter = Tx {
            port,
            failed: None,
            clock: false,
            gone: None,
            collisions: 0,
        };
        tx.reap(&mut adapter, &mut counters);
        let step = if adapter.fault().is_some() {
            None
        } else if !carrier {
            // No carrier before posting: a link outcome, nothing posted.
            Some(TxOutcome::NoCarrier)
        } else {
            match tx.before_post(&mut adapter, &mut counters) {
                Err(outcome) => Some(outcome),
                Ok(_) if adapter.fault().is_some() => None,
                Ok(index) => {
                    let buffer = adapter.port.tx_buffer(index);
                    if fill(&mut buffer[..bytes]) {
                        buffer[bytes..wire].fill(0);
                        Some(tx.transmit(&mut adapter, index, wire, &mut counters))
                    } else {
                        self.tx = tx;
                        (self.info.tx_frames, self.info.tx_errors) =
                            (counters.frames, counters.errors);
                        return Send::Copy;
                    }
                }
            }
        };
        self.collisions += adapter.collisions;
        let fault = adapter.fault();
        if let Some(Fault::TxError(_)) = fault {
            // TxSlots counted the errored descriptor as done; it was not a
            // frame (review Codex 2).
            counters.frames -= 1;
            counters.errors += 1;
        }
        self.tx = tx;
        (self.info.tx_frames, self.info.tx_errors) = (counters.frames, counters.errors);
        if let Some(fault) = fault {
            self.disable(fault);
            return Send::Disabled;
        }
        match step {
            Some(TxOutcome::Sent) => Send::Sent,
            Some(TxOutcome::NoCarrier) => Send::NoCarrier,
            Some(TxOutcome::DeviceFailed) | None => {
                self.disable(Fault::TxTimeout);
                Send::Disabled
            }
        }
    }

    /// `nic_info`: a late done bit of a held descriptor is counted first;
    /// link is reported only from a successful BMSR read.
    pub fn info(&mut self, port: &mut impl Port) -> NicInfo {
        let mut out = self.info;
        out.flags = 0;
        if self.fault.is_none() {
            let mut counters = TxCounters {
                frames: self.info.tx_frames,
                errors: self.info.tx_errors,
            };
            let mut adapter = Tx {
                port: &mut *port,
                failed: None,
                clock: false,
                gone: None,
                collisions: 0,
            };
            self.tx.reap(&mut adapter, &mut counters);
            self.collisions += adapter.collisions;
            let fault = adapter.fault();
            if let Some(Fault::TxError(_)) = fault {
                counters.frames -= 1;
                counters.errors += 1;
            }
            (self.info.tx_frames, self.info.tx_errors) = (counters.frames, counters.errors);
            if let Some(fault) = fault {
                self.disable(fault);
            }
            if let Ok(true) = self.carrier(port) {
                out.flags |= crate::nic::NIC_FLAG_LINK_UP;
            }
            out.tx_frames = self.info.tx_frames;
            out.tx_errors = self.info.tx_errors;
        }
        if self.fault.is_some() {
            out.flags = crate::nic::NIC_FLAG_DISABLED;
        }
        out
    }
}

/// `TxSlots`'s port over the RTL8125 TX ring. Faults it cannot return
/// through `TxPort` are kept for `Nic::send` to judge.
struct Tx<'a, P> {
    port: &'a mut P,
    failed: Option<u32>,
    clock: bool,
    gone: Option<Fault>,
    collisions: u64,
}

impl<P: Port> Tx<'_, P> {
    /// A vanished device first, then a stalled clock, then error bits.
    fn fault(&self) -> Option<Fault> {
        if let Some(fault) = self.gone {
            Some(fault)
        } else if self.clock {
            Some(Fault::Clock)
        } else {
            self.failed.map(Fault::TxError)
        }
    }
}

impl<P: Port> TxPort for Tx<'_, P> {
    /// BMSR; a failed read is kept as a fault and reads as carrier, so a
    /// bound it ends is never a link outcome.
    fn link_up(&mut self) -> bool {
        match self.port.carrier() {
            Ok(up) => up,
            Err(rtl8125::Error::DeviceGone) => {
                self.gone.get_or_insert(Fault::DeviceGone);
                true
            }
            Err(error) => {
                self.gone.get_or_insert(Fault::PhyRead(error));
                true
            }
        }
    }

    fn done(&mut self, index: usize) -> bool {
        let cmdsts = self.port.tx_cmdsts(index);
        match rtl8125::tx_slot(cmdsts) {
            TxSlot::Owned => false,
            TxSlot::Sent => {
                self.port.fence();
                self.collisions += u64::from(rtl8125::tx_collisions(cmdsts));
                true
            }
            TxSlot::Failed(bits) => {
                self.port.fence();
                self.failed.get_or_insert(bits);
                true
            }
        }
    }

    /// The buffer address again (the chip may clear it on write-back, as
    /// it does for RX), the command word with OWN, a fence, the doorbell.
    fn post(&mut self, index: usize, wire: usize, _tail: usize) {
        let address = self.port.tx_buffer_address(index);
        self.port.set_tx_address(index, address);
        self.port.fence();
        self.port
            .set_tx_cmdsts(index, rtl8125::tx_cmdsts(wire, index == TX_SLOTS - 1));
        self.port.fence();
        self.port.doorbell();
    }

    fn wait_done(&mut self, index: usize, carrier_lost: &mut bool) -> bool {
        for _ in 0..TX_SPIN {
            if self.done(index) {
                return true;
            }
        }
        for _ in 0..TX_BOUND_MS {
            if self.done(index) {
                return true;
            }
            if !self.link_up() {
                *carrier_lost = true;
            }
            if self.gone.is_some() {
                return false;
            }
            if !self.port.delay_ms(1) {
                self.clock = true;
                return false;
            }
        }
        self.done(index)
    }
}

#[cfg(test)]
pub(crate) mod model {
    //! A model of the chip's ring behaviour, including the defects the
    //! review and the corrective experiments observed on reference_host.
    extern crate std;
    use super::*;
    pub use crate::rtl8125::OWN;
    use std::collections::VecDeque;
    use std::vec::Vec;

    pub const RX_BASE: u64 = 0x0010_0000;
    pub const TX_BASE: u64 = 0x0020_0000;

    #[derive(Clone, Copy, Default)]
    pub struct Desc {
        pub cmdsts: u32,
        pub extsts: u32,
        pub address: u64,
    }

    pub struct Chip {
        pub rx: [Desc; RX_SLOTS],
        pub tx: [Desc; TX_SLOTS],
        pub rx_buffers: Vec<[u8; BUFFER]>,
        pub tx_buffers: Vec<[u8; BUFFER]>,
        /// The chip's own RX position.
        pub rx_head: usize,
        pub isr: u32,
        pub link: bool,
        pub gone: bool,
        /// Frames the wire offers, delivered by `arrive`.
        pub wire: VecDeque<Vec<u8>>,
        /// Frames the chip put on the wire.
        pub sent: Vec<Vec<u8>>,
        /// TX completes with these bits instead of 0.
        pub tx_error_bits: u32,
        /// TX descriptors never complete.
        pub tx_stuck: bool,
        /// After an overflow the chip skips the descriptor it was refused
        /// (x1: slot 13 left offered while 14.. were written).
        pub skip_after_overflow: bool,
        /// Every DMA write lands at a descriptor's address field.
        pub dma_writes: Vec<u64>,
        /// Writes the chip issued for a slot before it was stopped, still in
        /// flight: `land_late` completes them, whatever software has done to
        /// the ring since (re-review 1: nothing excludes this ordering).
        pub late: Vec<(usize, Vec<u8>)>,
        pub doorbells: u32,
        pub delays: u32,
        pub clock_stops_after: Option<u32>,
        /// The link drops once this many delays have run.
        pub link_down_after_delays: Option<u32>,
        pub isr_reads: u32,
        pub arrive_before_ack: bool,
        pub isr_before_ack: u32,
        pub arrive_after_ack: bool,
        pub isr_after_ack: u32,
    }

    impl Chip {
        pub fn new() -> Self {
            Self {
                rx: [Desc::default(); RX_SLOTS],
                tx: [Desc::default(); TX_SLOTS],
                rx_buffers: std::vec![[0; BUFFER]; RX_SLOTS],
                tx_buffers: std::vec![[0; BUFFER]; TX_SLOTS],
                rx_head: 0,
                isr: 0,
                link: true,
                gone: false,
                wire: VecDeque::new(),
                sent: Vec::new(),
                tx_error_bits: 0,
                tx_stuck: false,
                skip_after_overflow: false,
                dma_writes: Vec::new(),
                late: Vec::new(),
                doorbells: 0,
                delays: 0,
                clock_stops_after: None,
                link_down_after_delays: None,
                isr_reads: 0,
                arrive_before_ack: false,
                isr_before_ack: 0,
                arrive_after_ack: false,
                isr_after_ack: 0,
            }
        }

        /// A frame with a correct FCS, as the wire delivers it.
        pub fn frame(seq: u32, len: usize) -> Vec<u8> {
            let mut f: Vec<u8> = (0..len)
                .map(|i| (i as u32 ^ seq.wrapping_mul(131)) as u8)
                .collect();
            f[14..18].copy_from_slice(&seq.to_be_bytes());
            let crc = crc32(&f);
            f.extend_from_slice(&crc.to_le_bytes());
            f
        }

        /// The chip receives one frame from the wire, as reference_host's 8125B was
        /// seen to: into the descriptor at its head if offered, writing the
        /// frame to that descriptor's address, then writing the descriptor
        /// back with the address quadword cleared. With no offered
        /// descriptor it raises descriptor-unavailable and FIFO overflow.
        pub fn arrive(&mut self) -> bool {
            let Some(frame) = self.wire.pop_front() else {
                return false;
            };
            let slot = self.rx_head;
            let d = self.rx[slot];
            if d.cmdsts & OWN == 0 {
                self.isr |= ISR_RX_DESC_UNAVAIL | ISR_RX_FIFO_OFLOW;
                if self.skip_after_overflow {
                    self.rx_head = (slot + 1) % RX_SLOTS;
                }
                return false;
            }
            self.dma_writes.push(d.address);
            let index = ((d.address - RX_BASE) / BUFFER as u64) as usize;
            assert!(
                d.address >= RX_BASE && index < RX_SLOTS && d.address.is_multiple_of(BUFFER as u64),
                "DMA to an address that is not an RX buffer: {:#x}",
                d.address
            );
            self.rx_buffers[index][..frame.len()].copy_from_slice(&frame);
            let end = d.cmdsts & EOR;
            self.rx[slot] = Desc {
                cmdsts: end | 0x0300_0000 | 0x0040_0000 | frame.len() as u32,
                extsts: 0x0700_0000,
                address: 0,
            };
            self.isr |= 1;
            self.rx_head = (slot + 1) % RX_SLOTS;
            true
        }

        /// Completes every late write: the frame lands in the buffer the
        /// slot had when the write was issued, and the descriptor is written
        /// back done, over whatever software put there meanwhile.
        pub fn land_late(&mut self) {
            for (slot, frame) in core::mem::take(&mut self.late) {
                self.rx_buffers[slot][..frame.len()].copy_from_slice(&frame);
                let end = self.rx[slot].cmdsts & EOR;
                self.rx[slot] = Desc {
                    cmdsts: end | 0x0300_0000 | frame.len() as u32,
                    extsts: 0,
                    address: 0,
                };
            }
        }

        pub fn arrive_all(&mut self) {
            while !self.wire.is_empty() {
                self.arrive();
            }
        }

        /// The chip's transmit side after a doorbell.
        fn transmit(&mut self) {
            if self.tx_stuck {
                return;
            }
            for slot in 0..TX_SLOTS {
                let d = self.tx[slot];
                if d.cmdsts & OWN == 0 {
                    continue;
                }
                let len = (d.cmdsts & 0xffff) as usize;
                let index = ((d.address - TX_BASE) / BUFFER as u64) as usize;
                assert_eq!(d.address, TX_BASE + (slot * BUFFER) as u64);
                self.sent.push(self.tx_buffers[index][..len].to_vec());
                self.tx[slot].cmdsts = self.tx_error_bits;
            }
        }
    }

    impl Port for Chip {
        fn rx_cmdsts(&mut self, slot: usize) -> u32 {
            self.rx[slot].cmdsts
        }
        fn set_rx_cmdsts(&mut self, slot: usize, value: u32) {
            self.rx[slot].cmdsts = value;
        }
        fn set_rx_extsts(&mut self, slot: usize, value: u32) {
            self.rx[slot].extsts = value;
        }
        fn set_rx_address(&mut self, slot: usize, address: u64) {
            self.rx[slot].address = address;
        }
        fn rx_buffer_address(&self, slot: usize) -> u64 {
            RX_BASE + (slot * BUFFER) as u64
        }
        fn rx_bytes(&self, slot: usize, len: usize) -> &[u8] {
            &self.rx_buffers[slot][..len]
        }
        fn tx_cmdsts(&mut self, slot: usize) -> u32 {
            self.tx[slot].cmdsts
        }
        fn set_tx_cmdsts(&mut self, slot: usize, value: u32) {
            self.tx[slot].cmdsts = value;
        }
        fn set_tx_address(&mut self, slot: usize, address: u64) {
            self.tx[slot].address = address;
        }
        fn tx_buffer_address(&self, slot: usize) -> u64 {
            TX_BASE + (slot * BUFFER) as u64
        }
        fn tx_buffer(&mut self, slot: usize) -> &mut [u8] {
            &mut self.tx_buffers[slot]
        }
        fn fence(&mut self) {}
        fn doorbell(&mut self) {
            self.doorbells += 1;
            self.transmit();
        }
        fn isr(&mut self) -> u32 {
            self.isr_reads += 1;
            if self.gone { u32::MAX } else { self.isr }
        }
        fn ack_isr(&mut self, bits: u32) {
            // What the chip does before the write reaches it can only be
            // cleared by that write; what it does after, the write leaves set.
            if self.arrive_before_ack {
                self.arrive_all();
                self.isr |= self.isr_before_ack;
            }
            self.isr &= !bits;
            if self.arrive_after_ack {
                self.arrive_all();
                self.isr |= self.isr_after_ack;
            }
        }
        fn carrier(&mut self) -> Result<bool, rtl8125::Error> {
            if self.gone {
                Err(rtl8125::Error::DeviceGone)
            } else {
                Ok(self.link)
            }
        }
        fn delay_ms(&mut self, _ms: u32) -> bool {
            self.delays += 1;
            if self
                .link_down_after_delays
                .is_some_and(|n| self.delays >= n)
            {
                self.link = false;
            }
            self.clock_stops_after.is_none_or(|n| self.delays <= n)
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::model::{Chip, OWN, RX_BASE, TX_BASE};
    use super::*;
    use std::vec::Vec;

    fn armed() -> (Nic, Chip) {
        let mut chip = Chip::new();
        build_rings(&mut chip);
        (Nic::new([2, 0, 0, 0, 0, 1]), chip)
    }

    fn drain(nic: &mut Nic, chip: &mut Chip) -> Vec<Vec<u8>> {
        let mut got = Vec::new();
        loop {
            let mut frame = Vec::new();
            match nic.take(chip, |bytes| {
                frame = bytes.to_vec();
                true
            }) {
                Ok(Take::Frame(_)) => got.push(frame),
                Ok(Take::Empty) => return got,
                Err(fault) => panic!("{fault:?}"),
            }
        }
    }

    fn seq(frame: &[u8]) -> u32 {
        u32::from_be_bytes([frame[14], frame[15], frame[16], frame[17]])
    }

    #[test]
    fn crc32_matches_the_ethernet_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        let f = Chip::frame(7, 60);
        assert!(fcs_ok(&f));
        let mut bad = f.clone();
        bad[20] ^= 1;
        assert!(!fcs_ok(&bad));
        assert!(!fcs_ok(&[1, 2, 3]));
    }

    #[test]
    fn built_rings_offer_every_rx_buffer_and_own_no_tx_slot() {
        let (_, chip) = armed();
        for slot in 0..RX_SLOTS {
            let d = chip.rx[slot];
            assert_eq!(d.address, RX_BASE + (slot * BUFFER) as u64);
            assert_eq!(d.cmdsts & OWN, OWN);
            assert_eq!(d.cmdsts & EOR != 0, slot == RX_SLOTS - 1);
            assert_eq!(d.cmdsts & 0x3fff, BUFFER as u32);
        }
        for slot in 0..TX_SLOTS {
            assert_eq!(chip.tx[slot].cmdsts & OWN, 0);
            assert_eq!(chip.tx[slot].cmdsts & EOR != 0, slot == TX_SLOTS - 1);
            assert_eq!(chip.tx[slot].address, TX_BASE + (slot * BUFFER) as u64);
        }
    }

    /// F1: the chip clears a written-back descriptor's address quadword; a
    /// recycled descriptor must carry its own buffer address again (and a
    /// zero extended status) before OWN is set.
    #[test]
    fn a_recycled_descriptor_carries_its_own_buffer_address() {
        let (mut nic, mut chip) = armed();
        // Several laps of the ring, one frame at a time.
        for n in 0..(3 * RX_SLOTS as u32 + 5) {
            chip.wire.push_back(Chip::frame(n, 60 + n as usize));
            chip.arrive();
            let slot = nic.rx_next();
            assert_eq!(chip.rx[slot].address, 0, "the model clears it");
            let got = drain(&mut nic, &mut chip);
            assert_eq!(got.len(), 1);
            assert_eq!(seq(&got[0]), n);
            let d = chip.rx[slot];
            assert_eq!(d.address, RX_BASE + (slot * BUFFER) as u64, "slot {slot}");
            assert_eq!(d.extsts, 0);
            assert_eq!(d.cmdsts & OWN, OWN);
        }
        assert!(chip.dma_writes.iter().all(|&a| a != 0));
    }

    #[test]
    fn frames_are_delivered_in_order_without_fcs_across_ring_wraps() {
        let (mut nic, mut chip) = armed();
        let mut want = 0;
        for burst in 0..20u32 {
            for k in 0..20 {
                let n = burst * 20 + k;
                chip.wire
                    .push_back(Chip::frame(n, 60 + (n as usize * 37) % 1455));
            }
            chip.arrive_all();
            for frame in drain(&mut nic, &mut chip) {
                assert_eq!(seq(&frame), want);
                assert_eq!(frame.len(), 60 + (want as usize * 37) % 1455);
                want += 1;
            }
        }
        assert_eq!(want, 400);
        assert_eq!(nic.info.rx_frames, 400);
        assert_eq!(
            (nic.info.rx_refused, nic.info.rx_missed, nic.fault()),
            (0, 0, None)
        );
    }

    /// F2 / re-review 1: an overrun raises descriptor-unavailable and FIFO
    /// overflow. Nothing in the ring is delivered, the episode is counted,
    /// the NIC is disabled visibly, and no descriptor is touched afterwards.
    #[test]
    fn an_overrun_disables_and_leaves_both_rings_untouched() {
        let (mut nic, mut chip) = armed();
        chip.skip_after_overflow = true;
        for n in 0..40 {
            chip.wire.push_back(Chip::frame(n, 100));
        }
        chip.arrive_all();
        assert_ne!(chip.isr & ISR_RX_FIFO_OFLOW, 0);
        let rx_before = chip.rx.map(|d| (d.cmdsts, d.address));
        let tx_before = chip.tx.map(|d| (d.cmdsts, d.address));
        let isr = 1 | ISR_RX_DESC_UNAVAIL | ISR_RX_FIFO_OFLOW;
        assert_eq!(nic.take(&mut chip, |_| true), Err(Fault::RxTrouble(isr)));
        assert_eq!(nic.fault(), Some(Fault::RxTrouble(isr)));
        assert_eq!((nic.info.rx_frames, nic.info.rx_missed), (0, 1));
        assert_eq!(chip.rx.map(|d| (d.cmdsts, d.address)), rx_before);
        assert_eq!(chip.tx.map(|d| (d.cmdsts, d.address)), tx_before);
        // Disabled for good: receive, send and info all say so.
        assert_eq!(nic.take(&mut chip, |_| true), Err(Fault::RxTrouble(isr)));
        assert_eq!(nic.send(&mut chip, 60, |_| true), Send::Disabled);
        assert_eq!(chip.doorbells, 0);
        assert_eq!(nic.info(&mut chip).flags, crate::nic::NIC_FLAG_DISABLED);
        assert_eq!(chip.rx.map(|d| (d.cmdsts, d.address)), rx_before);
    }

    /// Descriptor-unavailable alone is not loss: on reference_host-vfio the chip raised it
    /// with free slots left and every frame intact (lane rtl8125-rx-diag). The
    /// frames waiting are delivered, in order, and the NIC stays up.
    #[test]
    fn descriptor_unavailable_alone_delivers_what_is_there() {
        let (mut nic, mut chip) = armed();
        for n in 0..24 {
            chip.wire.push_back(Chip::frame(n, 100));
        }
        chip.arrive_all();
        chip.isr |= ISR_RX_DESC_UNAVAIL;
        let got = drain(&mut nic, &mut chip);
        assert_eq!(
            got.iter().map(|f| seq(f)).collect::<Vec<_>>(),
            (0..24).collect::<Vec<_>>()
        );
        assert_eq!(nic.fault(), None);
        assert_eq!((nic.info.rx_frames, nic.info.rx_missed), (24, 0));
    }

    #[test]
    fn descriptor_unavailable_is_cleared_so_a_new_one_can_be_told_apart() {
        let (mut nic, mut chip) = armed();
        chip.isr |= ISR_RX_DESC_UNAVAIL;
        assert_eq!(nic.take(&mut chip, |_| true), Ok(Take::Empty));
        assert_eq!(chip.isr & ISR_RX_DESC_UNAVAIL, 0);
    }

    /// Other bits stay as the chip left them: only this bit is acknowledged.
    #[test]
    fn clearing_it_touches_no_other_bit() {
        let (mut nic, mut chip) = armed();
        chip.isr |= ISR_RX_DESC_UNAVAIL | 1;
        assert_eq!(nic.take(&mut chip, |_| true), Ok(Take::Empty));
        assert_eq!(chip.isr & 1, 1);
    }

    /// No forward progress: the chip keeps saying it has no descriptor while
    /// nothing arrives. That is unexplained, and it stays fatal, within a bound.
    #[test]
    fn descriptor_unavailable_with_no_progress_disables_within_a_bound() {
        let (mut nic, mut chip) = armed();
        let mut polls = 0;
        loop {
            chip.isr |= ISR_RX_DESC_UNAVAIL;
            polls += 1;
            assert!(polls <= RX_STALL_LIMIT, "never disabled");
            if nic.take(&mut chip, |_| true).is_err() {
                break;
            }
        }
        assert_eq!(polls, RX_STALL_LIMIT);
        assert_eq!(nic.fault(), Some(Fault::RxTrouble(ISR_RX_DESC_UNAVAIL)));
        assert_eq!(nic.info.rx_missed, 1);
    }

    #[test]
    fn a_delivered_frame_restores_the_bound() {
        let (mut nic, mut chip) = armed();
        for round in 0..3u32 {
            for _ in 0..RX_STALL_LIMIT - 1 {
                chip.isr |= ISR_RX_DESC_UNAVAIL;
                assert_eq!(nic.take(&mut chip, |_| true), Ok(Take::Empty));
            }
            chip.wire.push_back(Chip::frame(round, 100));
            chip.arrive_all();
            assert!(matches!(nic.take(&mut chip, |_| true), Ok(Take::Frame(_))));
        }
        assert_eq!(nic.fault(), None);
    }

    /// reference_host, overloaded past the ring with only this bit set: frames came back
    /// out of order. So the bit does not mark real exhaustion; the ring does. With
    /// no slot left for the chip it stops, as for any overflow, and what is waiting
    /// is not delivered.
    #[test]
    fn descriptor_unavailable_with_no_free_slot_is_terminal() {
        let (mut nic, mut chip) = armed();
        for n in 0..RX_SLOTS as u32 {
            chip.wire.push_back(Chip::frame(n, 100));
        }
        chip.arrive_all();
        chip.isr = ISR_RX_DESC_UNAVAIL;
        let mut delivered = 0;
        assert_eq!(
            nic.take(&mut chip, |_| {
                delivered += 1;
                true
            }),
            Err(Fault::RxTrouble(ISR_RX_DESC_UNAVAIL))
        );
        assert_eq!(delivered, 0);
        assert_eq!(nic.info.rx_missed, 1);
    }

    /// The chip can run out just as the driver refills: one slot then looks free
    /// though the ring was exhausted when the bit was raised.
    #[test]
    fn a_refill_cannot_hide_exhaustion() {
        let (mut nic, mut chip) = armed();
        chip.wire.push_back(Chip::frame(0, 100));
        chip.arrive_all();
        // Delivered and refilled: the bit was clear when this take read ISR.
        assert!(matches!(nic.take(&mut chip, |_| true), Ok(Take::Frame(_))));
        // Every other slot now fills, and the chip says it has none. Only the
        // slot just refilled is free.
        for n in 1..RX_SLOTS as u32 {
            chip.wire.push_back(Chip::frame(n, 100));
        }
        chip.arrive_all();
        chip.isr = ISR_RX_DESC_UNAVAIL;
        assert_eq!(
            nic.take(&mut chip, |_| true),
            Err(Fault::RxTrouble(ISR_RX_DESC_UNAVAIL))
        );
    }

    /// Running the chip out with the bit already set, while the driver is between
    /// reading ISR and clearing it: the write erases the only sign in ISR.
    fn last_slot_goes_at_ack() -> (Nic, Chip) {
        let (nic, mut chip) = armed();
        for n in 0..RX_SLOTS as u32 - 1 {
            chip.wire.push_back(Chip::frame(n, 100));
        }
        chip.arrive_all();
        chip.isr = ISR_RX_DESC_UNAVAIL;
        chip.wire.push_back(Chip::frame(99, 100));
        (nic, chip)
    }

    #[test]
    fn exhaustion_before_the_acknowledgement_is_not_erased() {
        let (mut nic, mut chip) = last_slot_goes_at_ack();
        chip.arrive_before_ack = true;
        chip.isr_before_ack = ISR_RX_DESC_UNAVAIL;
        let mut delivered = 0;
        assert_eq!(
            nic.take(&mut chip, |_| {
                delivered += 1;
                true
            }),
            Err(Fault::RxTrouble(ISR_RX_DESC_UNAVAIL))
        );
        assert_eq!(delivered, 0);
    }

    #[test]
    fn exhaustion_after_the_acknowledgement_is_terminal() {
        let (mut nic, mut chip) = last_slot_goes_at_ack();
        chip.arrive_after_ack = true;
        chip.isr_after_ack = ISR_RX_DESC_UNAVAIL;
        let mut delivered = 0;
        assert_eq!(
            nic.take(&mut chip, |_| {
                delivered += 1;
                true
            }),
            Err(Fault::RxTrouble(ISR_RX_DESC_UNAVAIL))
        );
        assert_eq!(delivered, 0);
    }

    /// An overflow that lands while the benign bit is being cleared is not read
    /// past: the frame this poll observed was seen before it.
    #[test]
    fn overflow_during_the_acknowledgement_is_terminal() {
        let (mut nic, mut chip) = armed();
        chip.wire.push_back(Chip::frame(0, 100));
        chip.arrive_all();
        chip.isr = ISR_RX_DESC_UNAVAIL;
        chip.arrive_after_ack = true;
        chip.isr_after_ack = ISR_RX_FIFO_OFLOW;
        let mut delivered = 0;
        assert_eq!(
            nic.take(&mut chip, |_| {
                delivered += 1;
                true
            }),
            Err(Fault::RxTrouble(ISR_RX_FIFO_OFLOW))
        );
        assert_eq!(delivered, 0);
    }

    /// With no refill since the last look, one free slot is just one free slot.
    #[test]
    fn a_free_slot_counts_once_a_clean_read_has_passed() {
        let (mut nic, mut chip) = armed();
        chip.wire.push_back(Chip::frame(0, 100));
        chip.arrive_all();
        assert!(matches!(nic.take(&mut chip, |_| true), Ok(Take::Frame(_))));
        assert_eq!(nic.take(&mut chip, |_| true), Ok(Take::Empty));
        for n in 1..RX_SLOTS as u32 - 1 {
            chip.wire.push_back(Chip::frame(n, 100));
        }
        chip.arrive_all();
        chip.isr = ISR_RX_DESC_UNAVAIL;
        assert!(matches!(nic.take(&mut chip, |_| true), Ok(Take::Frame(_))));
        assert_eq!(nic.fault(), None);
    }

    /// Isolated indications with clean polls between them are not a stall.
    #[test]
    fn a_clean_poll_restores_the_bound() {
        let (mut nic, mut chip) = armed();
        for _ in 0..RX_STALL_LIMIT * 3 {
            chip.isr |= ISR_RX_DESC_UNAVAIL;
            assert_eq!(nic.take(&mut chip, |_| true), Ok(Take::Empty));
            assert_eq!(nic.take(&mut chip, |_| true), Ok(Take::Empty));
        }
        assert_eq!(nic.fault(), None);
    }

    #[test]
    fn one_free_slot_is_not_exhaustion() {
        let (mut nic, mut chip) = armed();
        for n in 0..RX_SLOTS as u32 - 1 {
            chip.wire.push_back(Chip::frame(n, 100));
        }
        chip.arrive_all();
        chip.isr = ISR_RX_DESC_UNAVAIL;
        let got = drain(&mut nic, &mut chip);
        assert_eq!(got.len(), RX_SLOTS - 1);
        assert_eq!(nic.fault(), None);
    }

    /// Fifo overflow and system error stay terminal, with or without it, and
    /// with frames waiting: those frames are still not delivered.
    #[test]
    fn real_trouble_stays_terminal_with_frames_waiting() {
        for bits in [
            ISR_RX_FIFO_OFLOW,
            ISR_SYSTEM_ERR,
            ISR_RX_FIFO_OFLOW | ISR_RX_DESC_UNAVAIL,
            ISR_SYSTEM_ERR | ISR_RX_DESC_UNAVAIL,
        ] {
            let (mut nic, mut chip) = armed();
            chip.wire.push_back(Chip::frame(1, 100));
            chip.arrive_all();
            chip.isr |= bits;
            let isr = chip.isr;
            let mut delivered = false;
            assert_eq!(
                nic.take(&mut chip, |_| {
                    delivered = true;
                    true
                }),
                Err(Fault::RxTrouble(isr))
            );
            assert!(!delivered);
        }
    }

    /// Re-review 1: a write the chip issued before trouble was handled lands
    /// afterwards, on a descriptor the driver might have offered again. It
    /// carries a whole old frame with a valid FCS. It must never be
    /// delivered as current. (A recovery that rebuilds and re-offers the
    /// ring, as 9dfff5a did, delivers it: see the corrective mutants.)
    #[test]
    fn a_late_write_after_trouble_is_never_delivered() {
        let (mut nic, mut chip) = armed();
        for n in 0..RX_SLOTS as u32 {
            chip.wire.push_back(Chip::frame(n, 100));
        }
        chip.arrive_all();
        chip.wire.push_back(Chip::frame(999, 100));
        chip.arrive();
        chip.late.push((0, Chip::frame(999, 100)));
        let mut delivered = Vec::new();
        for _ in 0..4 {
            let _ = nic.take(&mut chip, |frame| {
                delivered.push(seq(frame));
                true
            });
            chip.land_late();
        }
        assert!(!delivered.contains(&999), "{delivered:?}");
        assert!(matches!(nic.fault(), Some(Fault::RxTrouble(_))));
    }

    /// F2: trouble that appears while the reader is idle (the ring head
    /// still offered) disables too, not left until a frame arrives; a
    /// system error disables without counting a miss.
    #[test]
    fn trouble_seen_with_an_empty_ring_still_disables() {
        let (mut nic, mut chip) = armed();
        chip.isr = ISR_RX_FIFO_OFLOW;
        assert_eq!(
            nic.take(&mut chip, |_| true),
            Err(Fault::RxTrouble(ISR_RX_FIFO_OFLOW))
        );
        assert_eq!(nic.info.rx_missed, 1);
        let (mut nic, mut chip) = armed();
        chip.isr = ISR_SYSTEM_ERR;
        assert_eq!(
            nic.take(&mut chip, |_| true),
            Err(Fault::RxTrouble(ISR_SYSTEM_ERR))
        );
        assert_eq!(nic.info.rx_missed, 0, "a system error is not a miss");
    }

    /// The review's soak-3/x4 symptom: a descriptor whose length belongs to
    /// one frame over a buffer holding another. The FCS check refuses it.
    #[test]
    fn a_descriptor_over_stale_buffer_bytes_is_refused_by_the_fcs() {
        let (mut nic, mut chip) = armed();
        let old = Chip::frame(133, 616);
        chip.rx_buffers[0][..old.len()].copy_from_slice(&old);
        // The chip wrote the 64-byte descriptor but the data went elsewhere.
        chip.rx[0] = model::Desc {
            cmdsts: 0x0340_0040,
            extsts: 0x0700_0000,
            address: 0,
        };
        let mut delivered = false;
        assert_eq!(
            nic.take(&mut chip, |_| {
                delivered = true;
                true
            }),
            Ok(Take::Empty)
        );
        assert!(!delivered);
        assert_eq!((nic.info.rx_frames, nic.info.rx_refused), (0, 1));
        assert_eq!(
            chip.rx[0].address, RX_BASE,
            "and the slot is re-offered whole"
        );
    }

    #[test]
    fn errored_short_long_and_fragment_descriptors_are_refused_and_recycled() {
        let (mut nic, mut chip) = armed();
        let f = Chip::frame(1, 100);
        for (slot, cmdsts) in [
            (0, 0x0310_0068u32),                           // RXERRSUM
            (1, 0x0200_0068),                              // SOF only
            (2, 0x0300_0000 | (NIC_FRAME_MIN + 3) as u32), // runt
            (3, 0x0300_0000 | (NIC_FRAME_MAX + 5) as u32), // too long
        ] {
            chip.rx_buffers[slot][..f.len()].copy_from_slice(&f);
            chip.rx[slot].cmdsts = cmdsts;
        }
        assert_eq!(nic.take(&mut chip, |_| true), Ok(Take::Empty));
        assert_eq!((nic.info.rx_refused, nic.info.rx_frames), (4, 0));
        for slot in 0..4 {
            assert_eq!(chip.rx[slot].cmdsts & OWN, OWN);
            assert_eq!(chip.rx[slot].address, RX_BASE + (slot * BUFFER) as u64);
        }
    }

    #[test]
    fn all_ones_isr_is_a_vanished_device_not_a_frame_or_trouble() {
        let (mut nic, mut chip) = armed();
        chip.wire.push_back(Chip::frame(1, 60));
        chip.arrive();
        chip.gone = true;
        assert_eq!(nic.take(&mut chip, |_| true), Err(Fault::DeviceGone));
        assert_eq!(nic.info.rx_frames, 0);
    }

    /// F6: a vanished device is never carrier: the send is refused as
    /// disabled, not posted, and `nic_info` reports disabled, not link.
    #[test]
    fn a_vanished_device_disables_instead_of_reading_as_link() {
        let (mut nic, mut chip) = armed();
        chip.gone = true;
        assert_eq!(nic.send(&mut chip, 60, |_| true), Send::Disabled);
        assert_eq!(chip.doorbells, 0);
        assert_eq!(nic.fault(), Some(Fault::DeviceGone));
        let info = nic.info(&mut chip);
        assert_eq!(info.flags, crate::nic::NIC_FLAG_DISABLED);
    }

    /// F5: `Sent` only after the descriptor came back; the frame is the
    /// filled bytes, zero-padded to 60.
    #[test]
    fn a_send_returns_sent_only_after_completion() {
        let (mut nic, mut chip) = armed();
        for n in 0..(3 * TX_SLOTS) {
            let outcome = nic.send(&mut chip, 20 + n as u64, |buf| {
                buf.fill(n as u8 | 1);
                true
            });
            assert_eq!(outcome, Send::Sent);
            let frame = chip.sent.last().unwrap();
            assert_eq!(frame.len(), 60.max(20 + n));
            assert!(frame[..20 + n].iter().all(|&b| b == n as u8 | 1));
            assert!(frame[20 + n..].iter().all(|&b| b == 0));
        }
        assert_eq!((nic.info.tx_frames, nic.info.tx_errors), (48, 0));
    }

    /// F5 (Codex 2): with carrier up and a descriptor that never completes,
    /// the very send that posted it must not report success.
    #[test]
    fn a_descriptor_that_never_completes_fails_the_send_that_posted_it() {
        let (mut nic, mut chip) = armed();
        chip.tx_stuck = true;
        assert_eq!(nic.send(&mut chip, 60, |_| true), Send::Disabled);
        assert_eq!(nic.fault(), Some(Fault::TxTimeout));
        assert_eq!((nic.info.tx_frames, nic.info.tx_errors), (0, 1));
        assert_eq!(nic.info(&mut chip).flags, crate::nic::NIC_FLAG_DISABLED);
    }

    #[test]
    fn without_carrier_a_send_is_a_link_outcome_and_holds_the_descriptor() {
        let (mut nic, mut chip) = armed();
        chip.link = false;
        assert_eq!(nic.send(&mut chip, 60, |_| true), Send::NoCarrier);
        assert_eq!(chip.doorbells, 0, "nothing posted without carrier");
        // Carrier drops while the posted descriptor waits: held, not
        // disabled, counted once as a transmit error.
        chip.link = true;
        chip.tx_stuck = true;
        chip.link_down_after_delays = Some(chip.delays + 1);
        assert_eq!(nic.send(&mut chip, 60, |_| true), Send::NoCarrier);
        assert_eq!(nic.held(), Some(0));
        assert_eq!(nic.fault(), None);
        assert_eq!((nic.info.tx_frames, nic.info.tx_errors), (0, 1));
        // Still no carrier: refused at once, nothing posted, nothing counted.
        let doorbells = chip.doorbells;
        assert_eq!(nic.send(&mut chip, 60, |_| true), Send::NoCarrier);
        assert_eq!(chip.doorbells, doorbells);
        assert_eq!(nic.info.tx_errors, 1);
        // Carrier back and the held descriptor done: counted, then a new send.
        chip.link_down_after_delays = None;
        chip.link = true;
        chip.tx_stuck = false;
        chip.tx[0].cmdsts = 0;
        assert_eq!(nic.send(&mut chip, 60, |_| true), Send::Sent);
        assert_eq!((nic.info.tx_frames, nic.info.tx_errors), (2, 1));
        assert_eq!(nic.held(), None);
    }

    /// F5 (Codex 2): a descriptor that returns with error bits is counted
    /// as a transmit error, not a frame, and the send does not succeed.
    #[test]
    fn an_errored_completion_is_an_error_not_a_frame() {
        let (mut nic, mut chip) = armed();
        assert_eq!(nic.send(&mut chip, 60, |_| true), Send::Sent);
        chip.tx_error_bits = 0x0080_0000; // TXERR
        assert_eq!(nic.send(&mut chip, 60, |_| true), Send::Disabled);
        assert_eq!(nic.fault(), Some(Fault::TxError(0x0080_0000)));
        assert_eq!((nic.info.tx_frames, nic.info.tx_errors), (1, 1));
    }

    #[test]
    fn a_stalled_clock_in_a_bound_disables_rather_than_guesses() {
        let (mut nic, mut chip) = armed();
        chip.tx_stuck = true;
        chip.clock_stops_after = Some(2);
        assert_eq!(nic.send(&mut chip, 60, |_| true), Send::Disabled);
        assert_eq!(nic.fault(), Some(Fault::Clock));
    }

    #[test]
    fn length_and_copy_refusals_touch_nothing() {
        let (mut nic, mut chip) = armed();
        assert_eq!(nic.send(&mut chip, 13, |_| true), Send::Length);
        assert_eq!(nic.send(&mut chip, 1515, |_| true), Send::Length);
        assert_eq!(nic.send(&mut chip, 60, |_| false), Send::Copy);
        assert_eq!(chip.doorbells, 0);
        assert_eq!((nic.info.tx_refused, nic.info.tx_frames), (2, 0));
        assert_eq!(nic.send(&mut chip, 60, |_| true), Send::Sent);
    }

    /// Re-review 3: a completion with only collision information is a sent
    /// frame (counted as collisions); excessive collisions are not.
    #[test]
    fn collision_only_completions_are_sent_frames() {
        let (mut nic, mut chip) = armed();
        chip.tx_error_bits = 0x0003_0000; // three collisions, then sent
        assert_eq!(nic.send(&mut chip, 60, |_| true), Send::Sent);
        assert_eq!(nic.send(&mut chip, 60, |_| true), Send::Sent);
        assert_eq!((nic.info.tx_frames, nic.info.tx_errors), (2, 0));
        assert_eq!(nic.collisions, 6);
        assert_eq!(nic.fault(), None);
        chip.tx_error_bits = 0x0010_0000; // EXCESSCOLL: given up
        assert_eq!(nic.send(&mut chip, 60, |_| true), Send::Disabled);
        assert_eq!(nic.fault(), Some(Fault::TxError(0x0010_0000)));
        assert_eq!((nic.info.tx_frames, nic.info.tx_errors), (2, 1));
    }

    /// Re-review 2: after arming, no release, however clean, gives the
    /// memory back for writing; unarmed memory stays the kernel's.
    #[test]
    fn armed_memory_is_never_returned_to_the_kernel() {
        let armed = Custody::Kernel.arm().unwrap();
        for (stop, fence) in [(true, true), (true, false), (false, true), (false, false)] {
            let after = armed.release(stop, fence);
            assert_eq!(after, Custody::Quarantined, "{stop} {fence}");
            assert!(!after.writable());
            assert_eq!(after.arm(), None, "quarantined memory is never re-armed");
            assert_eq!(after.release(true, true), Custody::Quarantined);
        }
        assert_eq!(Custody::Kernel.release(true, true), Custody::Kernel);
        assert!(Custody::Kernel.writable());
        assert_eq!(armed.arm(), None);
    }

    /// Re-review 2: only offered descriptors the chip handed back are read.
    #[test]
    fn only_handed_back_descriptors_are_inspectable() {
        assert!(inspectable(true, 0x0340_0040));
        assert!(!inspectable(true, OWN | 0x0800));
        assert!(!inspectable(true, OWN | EOR | 0x0800));
        assert!(!inspectable(false, 0x0340_0040), "never offered");
        assert!(!inspectable(false, EOR));
    }
}

#[cfg(test)]
mod surface_tests {
    use super::*;
    use crate::amdvi::{MAX_GRANT, Perm};

    #[test]
    fn every_page_of_the_surface_has_one_role() {
        assert_eq!(SURFACE.pages(), 1 + 1 + 8 + 16);
        for page in 0..SURFACE.pages() {
            let roles = [
                SURFACE.tx_ring,
                SURFACE.rx_ring,
                SURFACE.tx_buffers,
                SURFACE.rx_buffers,
            ]
            .iter()
            .filter(|(first, count)| *first <= page && page < first + count)
            .count();
            assert_eq!(roles, 1, "page {page}");
        }
    }

    #[test]
    fn each_part_holds_what_the_rings_need() {
        assert!(SURFACE.tx_ring.1 * 4096 >= TX_SLOTS * crate::rtl8125::DESCRIPTOR_BYTES);
        assert!(SURFACE.rx_ring.1 * 4096 >= RX_SLOTS * crate::rtl8125::DESCRIPTOR_BYTES);
        assert!(SURFACE.tx_buffers.1 * 4096 >= TX_SLOTS * BUFFER);
        assert!(SURFACE.rx_buffers.1 * 4096 >= RX_SLOTS * BUFFER);
    }

    #[test]
    fn the_device_gets_the_least_each_role_needs() {
        assert_eq!(SURFACE.perm_of(SURFACE.tx_ring.0), Perm::READ_WRITE);
        assert_eq!(SURFACE.perm_of(SURFACE.rx_ring.0), Perm::READ_WRITE);
        assert_eq!(SURFACE.perm_of(SURFACE.tx_buffers.0), Perm::READ);
        assert_eq!(SURFACE.perm_of(SURFACE.rx_buffers.0), Perm::WRITE);
        assert_eq!(
            SURFACE.perm_of(SURFACE.rx_buffers.0 + SURFACE.rx_buffers.1 - 1),
            Perm::WRITE
        );
    }

    #[test]
    fn the_surface_fits_one_grant() {
        assert!(SURFACE.pages() <= MAX_GRANT);
    }

    #[test]
    fn exposure_makes_every_later_release_quarantine() {
        let exposed = Custody::Kernel.arm().unwrap();
        assert_eq!(exposed.release(true, true), Custody::Quarantined);
        assert!(!exposed.writable());
        assert_eq!(exposed.arm(), None);
        // Before exposure nothing has changed.
        assert_eq!(Custody::Kernel.release(true, true), Custody::Kernel);
    }
}
