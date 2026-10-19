//! Opt-in SPT I219-LM backend. Queue storage is pinned for the entire boot.
//! No physical execution has qualified this backend. No reset/reprobe after DMA.
//! Uses the existing BSP-only NIC frame ABI, with one legacy RX/TX queue.

use crate::{
    e1000::{Identity, SendError},
    mmio, pci,
};
use absd_kernel::e1000_ring::{
    BUFFER_BYTES, RX_DESCRIPTORS, RxVerdict, TX_DESCRIPTORS, TxCounters, TxSlots,
};
use absd_kernel::i219::{self, Io};
use absd_kernel::i219_pci;
use absd_kernel::i219_ring::{self, CarrierFault, CarrierStep, I219Tx, SendStep, TxFault, TxRing};
use absd_kernel::nic::{NIC_FLAG_DISABLED, NIC_FLAG_LINK_UP, NicInfo};
use core::sync::atomic::{Ordering, fence};

const STATUS: u32 = 0x8;
const RCTL: u32 = 0x100;
const TCTL: u32 = 0x400;
const IMC: u32 = 0xd8;
const RDH: u32 = 0x2810;
const RDT: u32 = 0x2818;
const TDH: u32 = 0x3810;
const TDT: u32 = 0x3818;
const MPC: u32 = 0x4010;
// The transmit port (`i219_ring::I219Tx`) names the same registers.
const _: () =
    assert!(STATUS == i219_ring::STATUS && TCTL == i219_ring::TCTL && TDT == i219_ring::TDT);

#[allow(dead_code)] // Nested refusal details are emitted through Debug.
#[derive(Clone, Copy, Debug)]
pub enum Error {
    Absent,
    QualificationOnly,
    AlreadyAttempted,
    Pci(i219_pci::Refusal),
    Claim(pci::ClaimError),
    Map(mmio::MapError),
    Initialization(i219::Error),
    BusMaster,
    Activation(Disabled),
}

#[allow(dead_code)] // TX error bits are retained in the diagnostic reason.
#[derive(Clone, Copy, Debug)]
pub enum Disabled {
    Head,
    TxTimeout,
    TxError(u8),
    LinkProfile,
    Activation,
    Clock,
}

struct Registers {
    base: u64,
    function: pci::Function,
}
impl Io for Registers {
    fn read32(&mut self, offset: u32) -> u32 {
        debug_assert!(offset & 3 == 0 && u64::from(offset) < i219_pci::REGISTER_BYTES);
        unsafe { core::ptr::read_volatile((self.base + u64::from(offset)) as *const u32) }
    }
    fn write32(&mut self, offset: u32, value: u32) {
        debug_assert!(offset & 3 == 0 && u64::from(offset) < i219_pci::REGISTER_BYTES);
        unsafe { core::ptr::write_volatile((self.base + u64::from(offset)) as *mut u32, value) }
    }
    fn read_config32(&mut self, offset: u8) -> u32 {
        pci::read32(self.function, offset)
    }
    fn delay_ms(&mut self, ms: u32) -> bool {
        delay_ms(ms)
    }
}

/// The already-probed PIT supplies minimum delays; TSC bounds a stalled PIT.
/// Like the boot timer probe, spin with interrupts enabled instead of an
/// unbounded HLT. Only UP is admitted, and IRQs cannot switch a kernel frame.
fn delay_ms(ms: u32) -> bool {
    if ms > 2_000 {
        return false;
    }
    let start = ticks();
    let tsc = unsafe { core::arch::x86_64::_rdtsc() };
    let bound = (u64::from(ms) + 1) * (1 << 28);
    unsafe {
        core::arch::asm!("sti", options(nostack));
    }
    let ok = loop {
        // One extra tick avoids an arbitrarily short first partial interval.
        if ticks().wrapping_sub(start) > u64::from(ms) {
            break true;
        }
        if unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(tsc) > bound {
            break false;
        }
        core::hint::spin_loop();
    };
    unsafe {
        core::arch::asm!("cli", options(nostack));
    }
    ok
}
fn ticks() -> u64 {
    crate::timer_ticks.load(Ordering::Relaxed)
}

#[repr(C, align(4096))]
struct Ring([u64; 512]);
#[repr(C, align(4096))]
struct RxBuffers([[u8; BUFFER_BYTES]; RX_DESCRIPTORS]);
#[repr(C, align(4096))]
struct TxBuffers([[u8; BUFFER_BYTES]; TX_DESCRIPTORS]);
static mut RX: Ring = Ring([0; 512]);
static mut TX: Ring = Ring([0; 512]);
static mut RX_BUFFERS: RxBuffers = RxBuffers([[0; BUFFER_BYTES]; RX_DESCRIPTORS]);
static mut TX_BUFFERS: TxBuffers = TxBuffers([[0; BUFFER_BYTES]; TX_DESCRIPTORS]);
static mut ATTEMPTED: bool = false;
static mut NIC: Option<Nic> = None;
fn rx() -> *mut u64 {
    unsafe { core::ptr::addr_of_mut!(RX.0).cast() }
}
fn tx() -> *mut u64 {
    unsafe { core::ptr::addr_of_mut!(TX.0).cast() }
}
fn rx_buffer(index: usize) -> *mut u8 {
    unsafe { core::ptr::addr_of_mut!(RX_BUFFERS.0[index]).cast() }
}
fn tx_buffer(index: usize) -> *mut u8 {
    unsafe { core::ptr::addr_of_mut!(TX_BUFFERS.0[index]).cast() }
}
/// The queue-zero transmit ring and register window as
/// `i219_ring::I219Tx` reaches them. Descriptor word 0 (the buffer
/// address) is written once by `probe` and never again.
struct MmioRing<'a> {
    io: &'a mut Registers,
}
impl TxRing for MmioRing<'_> {
    fn read32(&mut self, offset: u32) -> u32 {
        self.io.read32(offset)
    }
    fn write32(&mut self, offset: u32, value: u32) {
        self.io.write32(offset, value)
    }
    fn status_word(&mut self, index: usize) -> u64 {
        debug_assert!(index < TX_DESCRIPTORS);
        unsafe { core::ptr::read_volatile(tx().add(index * 2 + 1)) }
    }
    fn set_status_word(&mut self, index: usize, word: u64) {
        debug_assert!(index < TX_DESCRIPTORS);
        unsafe { core::ptr::write_volatile(tx().add(index * 2 + 1), word) }
    }
    fn fence(&mut self) {
        fence(Ordering::SeqCst)
    }
    fn ticks(&mut self) -> u64 {
        ticks()
    }
    fn delay_ms(&mut self, ms: u32) -> bool {
        delay_ms(ms)
    }
}
fn tx_disabled(fault: TxFault) -> Disabled {
    match fault {
        TxFault::Timeout => Disabled::TxTimeout,
        TxFault::Error(bits) => Disabled::TxError(bits),
        TxFault::Clock => Disabled::Clock,
    }
}
struct Nic {
    io: Registers,
    info: NicInfo,
    rx_next: usize,
    rx_chain: i219_ring::RxChain,
    /// Transmit ring ownership (T6's `TxSlots`): at most one descriptor
    /// held without its done bit after a bound expired without carrier.
    tx: TxSlots,
    active: bool,
    last_link_up: bool,
    disabled: Option<Disabled>,
}
fn nic() -> Option<&'static mut Nic> {
    crate::kernel_lock::assert_bsp_device_access();
    unsafe { (*core::ptr::addr_of_mut!(NIC)).as_mut() }
}

fn initialize_device() -> Result<(Registers, i219::Initialized, Identity), Error> {
    crate::kernel_lock::assert_bsp_device_access();
    if crate::smp_user::enabled() || crate::smp_startup::enabled() {
        return Err(Error::QualificationOnly);
    }
    if unsafe { *core::ptr::addr_of!(ATTEMPTED) } {
        return Err(Error::AlreadyAttempted);
    }
    unsafe {
        *core::ptr::addr_of_mut!(ATTEMPTED) = true;
    }
    let function = pci::find_id(i219_pci::VENDOR, i219_pci::DEVICE).ok_or(Error::Absent)?;
    let bar = i219_pci::admit(|offset| pci::read32(function, offset)).map_err(Error::Pci)?;
    pci::claim(function, "i219-spt").map_err(Error::Claim)?;
    let base =
        mmio::map(bar, i219_pci::REGISTER_BYTES, mmio::Cache::Uncached).map_err(Error::Map)?;
    let mut io = Registers { base, function };
    let initialized = match i219::initialize(&mut io) {
        Ok(value) => value,
        Err(error) => {
            if matches!(
                error,
                i219::Error::ResetRecoveryRequired | i219::Error::ResetTimeout
            ) {
                // An indeterminate reset forbids further MMIO. Fence new bus
                // requests using config space only; this is not proof that
                // old DMA completed. No retry or memory reclamation follows.
                let command = pci::read32(function, 4) as u16 & !4;
                pci::write32(function, 4, u32::from(command));
                let _ = pci::read32(function, 4);
            }
            return Err(Error::Initialization(error));
        }
    };
    // initialize has drained the MAC and left GIO master disable asserted.
    // Keep PCI mastering off as well until the complete owned rings are ready.
    let command = (pci::read32(function, 4) as u16 & !4) | (1 << 10);
    pci::write32(function, 4, u32::from(command));
    if pci::read32(function, 4) as u16 & 4 != 0 {
        return Err(Error::BusMaster);
    }
    let identity = Identity {
        pci: function,
        mac: initialized.mac,
    };
    Ok((io, initialized, identity))
}

/// Hardware bring-up only: no ring addresses installed and no DMA enabled.
/// This lets the operator qualify initialization before admitting frame DMA.
pub fn initialize_only() -> Result<(Identity, u32, bool), Error> {
    let (_io, initialized, identity) = initialize_device()?;
    Ok((identity, initialized.phy_id, initialized.link_up))
}

pub fn probe() -> Result<Identity, Error> {
    let (mut io, initialized, identity) = initialize_device()?;
    for index in 0..RX_DESCRIPTORS {
        unsafe {
            core::ptr::write_volatile(rx().add(index * 2), rx_buffer(index) as u64);
            core::ptr::write_volatile(rx().add(index * 2 + 1), 0);
        }
    }
    for index in 0..TX_DESCRIPTORS {
        unsafe {
            core::ptr::write_volatile(tx().add(index * 2), tx_buffer(index) as u64);
            core::ptr::write_volatile(tx().add(index * 2 + 1), 0);
        }
    }
    fence(Ordering::SeqCst);
    i219::configure_legacy_rings(
        &mut io,
        tx() as u64,
        TX_DESCRIPTORS as u16,
        rx() as u64,
        RX_DESCRIPTORS as u16,
    )
    .map_err(Error::Initialization)?;
    // Publication does not depend on carrier. No user pointer is ever a DMA address.
    let mut device = Nic {
        io,
        info: NicInfo {
            mac: initialized.mac,
            ..NicInfo::default()
        },
        rx_next: 0,
        rx_chain: i219_ring::RxChain::default(),
        tx: TxSlots::new(),
        active: false,
        last_link_up: false,
        disabled: None,
    };
    device.ensure_active().map_err(Error::Activation)?;
    unsafe {
        *core::ptr::addr_of_mut!(NIC) = Some(device);
    }
    Ok(identity)
}

impl Nic {
    fn disable(&mut self, why: Disabled) {
        // This requests stop; it does NOT establish DMA exclusion. Rings and
        // buffers are never freed, reused, or reprobed after this transition.
        self.io.write32(IMC, u32::MAX);
        self.io.write32(RCTL, 0);
        self.io.write32(TCTL, 0);
        let _ = self.io.read32(STATUS);
        self.disabled = Some(why);
        // Nothing of the transmit ring outlives the disable: a held
        // descriptor is abandoned for the boot, never reaped, counted or
        // reused.
        self.tx = TxSlots::new();
        use core::fmt::Write;
        struct Log;
        impl core::fmt::Write for Log {
            fn write_str(&mut self, text: &str) -> core::fmt::Result {
                crate::serial::write(text);
                Ok(())
            }
        }
        let _ = writeln!(Log, "I219 DISABLED reason={why:?}");
    }
    fn retire(&mut self, fault: CarrierFault) -> Disabled {
        let why = match fault {
            CarrierFault::LinkProfile => Disabled::LinkProfile,
            CarrierFault::Activation => Disabled::Activation,
        };
        self.disable(why);
        why
    }
    fn ensure_active(&mut self) -> Result<bool, Disabled> {
        if let Some(why) = self.disabled {
            return Err(why);
        }
        let status = self.io.read32(STATUS);
        let io = &mut self.io;
        match i219_ring::carrier(
            status,
            || io.read32(i219_ring::ICR),
            self.active,
            self.last_link_up,
        ) {
            CarrierStep::Fault(fault) => Err(self.retire(fault)),
            CarrierStep::Refresh => match i219_ring::refreshed(i219::refresh_link(&mut self.io)) {
                Ok(now_up) => {
                    self.last_link_up = now_up;
                    Ok(now_up)
                }
                Err(fault) => Err(self.retire(fault)),
            },
            CarrierStep::Down => Ok(false),
            CarrierStep::Up => Ok(true),
            CarrierStep::Activate => {
                match i219_ring::activated(i219::enable_legacy(&mut self.io)) {
                    Ok(true) => {}
                    Ok(false) => return Ok(false),
                    Err(fault) => return Err(self.retire(fault)),
                }
                pci::enable_polled_dma(self.io.function);
                if let Err(fault) = i219_ring::bus_master(pci::read32(self.io.function, 4)) {
                    return Err(self.retire(fault));
                }
                self.active = true;
                self.last_link_up = true;
                Ok(true)
            }
        }
    }
    fn heads(&mut self) -> Result<(), Disabled> {
        if let Some(why) = self.disabled {
            return Err(why);
        }
        if !i219_ring::head_in_ring(self.io.read32(RDH), RX_DESCRIPTORS)
            || !i219_ring::head_in_ring(self.io.read32(TDH), TX_DESCRIPTORS)
        {
            self.disable(Disabled::Head);
            return Err(Disabled::Head);
        }
        Ok(())
    }
    fn recycle(&mut self) {
        let index = self.rx_next;
        unsafe {
            core::ptr::write_volatile(rx().add(index * 2 + 1), 0);
        }
        fence(Ordering::SeqCst);
        self.io.write32(RDT, index as u32);
        self.rx_next = i219_ring::next(index, RX_DESCRIPTORS);
    }
    /// Counts a held transmit descriptor whose done bit has appeared (once,
    /// in `tx_frames`) and frees it; one with completion-error bits then
    /// disables the NIC. Reads one descriptor word; writes nothing.
    fn reap_held(&mut self) {
        let mut counters = TxCounters {
            frames: self.info.tx_frames,
            errors: self.info.tx_errors,
        };
        let mut port = I219Tx::new(MmioRing { io: &mut self.io });
        let fault = i219_ring::reap_held(&mut self.tx, &mut port, &mut counters);
        (self.info.tx_frames, self.info.tx_errors) = (counters.frames, counters.errors);
        if let Some(fault) = fault {
            self.disable(tx_disabled(fault));
        }
    }
}

pub fn present() -> bool {
    nic().is_some()
}
pub fn disabled() -> bool {
    nic().is_some_and(|n| n.disabled.is_some())
}
pub fn link_up() -> bool {
    nic().is_some_and(|n| n.ensure_active().unwrap_or(false))
}

pub fn take_frame(deliver: impl FnOnce(&[u8]) -> bool) -> Result<Option<usize>, Disabled> {
    let Some(n) = nic() else {
        return Ok(None);
    };
    if !n.ensure_active()? {
        return Ok(None);
    }
    n.heads()?;
    for _ in 0..RX_DESCRIPTORS {
        let index = n.rx_next;
        let word = unsafe { core::ptr::read_volatile(rx().add(index * 2 + 1)) };
        match n
            .rx_chain
            .classify((word >> 32) as u8, (word >> 40) as u8, word as u16)
        {
            RxVerdict::Empty => return Ok(None),
            RxVerdict::Refused(_) => {
                n.info.rx_refused += 1;
                n.recycle();
            }
            RxVerdict::Frame(bytes) => {
                fence(Ordering::SeqCst);
                let frame = unsafe { core::slice::from_raw_parts(rx_buffer(index), bytes) };
                let copied = deliver(frame);
                n.recycle();
                if !copied {
                    return Ok(None);
                }
                n.info.rx_frames += 1;
                return Ok(Some(bytes));
            }
        }
    }
    Ok(None)
}

/// Sends one frame of `length` bytes that `fill` copies into the transmit
/// buffer, under the §10 rule (`i219_ring::send_step` over T6's
/// `TxSlots`): no carrier before posting, or a bound that saw carrier
/// absent, is `NoCarrier` with the NIC left enabled and any posted
/// descriptor left the device's; a bound that expires with carrier present,
/// a done bit with error bits, or a stalled clock disables the NIC.
pub fn send(length: u64, fill: impl FnOnce(&mut [u8]) -> bool) -> Result<(), SendError> {
    let Some(n) = nic() else {
        return Err(SendError::Disabled);
    };
    if n.disabled.is_some() {
        return Err(SendError::Disabled);
    }
    let Some((bytes, wire)) = i219_ring::send_length(length) else {
        n.info.tx_refused += 1;
        return Err(SendError::Length);
    };
    // The carrier decision, and with carrier the ring heads, before any
    // descriptor is read or posted. Link loss itself does not retire the
    // NIC, and receive can resume once gigabit carrier returns.
    let carrier = match n.ensure_active() {
        Ok(true) => n.heads().map(|()| true),
        other => other,
    };
    let mut counters = TxCounters {
        frames: n.info.tx_frames,
        errors: n.info.tx_errors,
    };
    let mut port = I219Tx::new(MmioRing { io: &mut n.io });
    let step = i219_ring::send_step(
        carrier,
        &mut n.tx,
        &mut port,
        &mut counters,
        wire,
        |index| {
            let buffer = unsafe { core::slice::from_raw_parts_mut(tx_buffer(index), BUFFER_BYTES) };
            if !fill(&mut buffer[..bytes]) {
                return false;
            }
            buffer[bytes..wire].fill(0);
            true
        },
    );
    (n.info.tx_frames, n.info.tx_errors) = (counters.frames, counters.errors);
    match step {
        SendStep::Sent => n.heads().map_err(|_| SendError::Disabled),
        SendStep::NoCarrier => Err(SendError::NoCarrier),
        SendStep::Copy => Err(SendError::Copy),
        SendStep::Retired => Err(SendError::Disabled),
        SendStep::Disable(fault) => {
            n.disable(tx_disabled(fault));
            Err(SendError::Disabled)
        }
    }
}

pub fn info() -> Option<NicInfo> {
    let n = nic()?;
    let link = n.ensure_active().unwrap_or(false);
    if n.disabled.is_none() {
        n.info.rx_missed += u64::from(n.io.read32(MPC));
        // A late done bit is counted here too, as `e1000::info` does, so
        // `tx_frames` is current without waiting for the next send. A
        // disabled NIC's descriptors are not consulted.
        n.reap_held();
    }
    let mut out = n.info;
    // Reaping may retire the NIC after the carrier observation above.
    out.flags = if n.disabled.is_none() && link {
        NIC_FLAG_LINK_UP
    } else {
        0
    };
    if n.disabled.is_some() {
        out.flags |= NIC_FLAG_DISABLED;
    }
    Some(out)
}
