//! The network interface: one Intel 82540EM (QEMU `-device e1000`),
//! polled, whole Ethernet frames only.
//!
//! The controller is found by PCI vendor and device identifiers, claimed
//! (`pci::claim`), reset, and given one receive ring of 32 and one transmit
//! ring of 16 legacy descriptors, each descriptor owning one 2 KiB buffer.
//! Rings and buffers are static, page-aligned kernel memory
//! (identity-mapped, so each static's address is its bus address); no user
//! address ever reaches the device. Interrupts stay masked: receive is
//! noticed by polling the next descriptor's done bit from the timer path,
//! and a send polls its own descriptor, bounded in ticks.
//!
//! Everything the device writes is checked (`absd_kernel::e1000_ring`): a
//! receive descriptor that is not one whole, error-free frame of 14..=1514
//! bytes is counted and recycled, never delivered, and a head register
//! outside its ring disables the NIC for the rest of the boot.
//! A disabled NIC has receive and transmit turned off and fails every later
//! call. A transmit bound that expires without carrier is not a device
//! failure (`e1000_ring::TxSlots`, the service-lifecycle record's §10): the
//! send returns `NoCarrier`, the descriptor stays the device's until its
//! done bit is seen, and the NIC stays enabled.
//!
//! The NIC is probed only when the boot command line carries `net`, so no
//! other boot (and no physical boot) touches a network device.

use core::sync::atomic::{Ordering, fence};

use absd_kernel::e1000_ring::{
    BUFFER_BYTES, RX_DESCRIPTORS, RxRefusal, RxVerdict, TX_COMMAND, TX_DESCRIPTORS, TX_STATUS_DD,
    TxCounters, TxOutcome, TxPort, TxSlots, accept_rx_destination, classify_rx, head_in_ring, next,
    send_length,
};
use absd_kernel::nic::{NIC_FLAG_DISABLED, NIC_FLAG_LINK_UP, NicInfo};

use crate::{mmio, pci, serial};

const VENDOR_INTEL: u16 = 0x8086;
const DEVICE_82540EM: u16 = 0x100e;
const REGISTER_BYTES: u64 = 0x2_0000;

const CTRL: u64 = 0x0000;
const STATUS: u64 = 0x0008;
const ICR: u64 = 0x00c0;
const IMC: u64 = 0x00d8;
const RCTL: u64 = 0x0100;
const TCTL: u64 = 0x0400;
const TIPG: u64 = 0x0410;
const RDBAL: u64 = 0x2800;
const RDBAH: u64 = 0x2804;
const RDLEN: u64 = 0x2808;
const RDH: u64 = 0x2810;
const RDT: u64 = 0x2818;
const TDBAL: u64 = 0x3800;
const TDBAH: u64 = 0x3804;
const TDLEN: u64 = 0x3808;
const TDH: u64 = 0x3810;
const TDT: u64 = 0x3818;
const MPC: u64 = 0x4010;
const MTA: u64 = 0x5200;
const RAL0: u64 = 0x5400;
const RAH0: u64 = 0x5404;

const CTRL_ASDE: u32 = 1 << 5;
const CTRL_SLU: u32 = 1 << 6;
const CTRL_RST: u32 = 1 << 26;
const STATUS_LU: u32 = 1 << 1;
const RAH_AV: u32 = 1 << 31;
/// Receiver enabled, broadcast accepted, CRC stripped; BSIZE 0 is 2048
/// bytes; long packets, promiscuous modes, and bad packets stay off.
const RCTL_VALUE: u32 = (1 << 1) | (1 << 15) | (1 << 26);
/// Transmitter enabled, short packets padded, collision threshold 0x10,
/// collision distance 0x40 (full duplex).
const TCTL_VALUE: u32 = (1 << 1) | (1 << 3) | (0x10 << 4) | (0x40 << 12);
/// IPGT 10, IPGR1 8, IPGR2 6: the 82540EM manual's values for copper.
const TIPG_VALUE: u32 = 10 | (8 << 10) | (6 << 20);
/// TCTL.EN: the transmitter runs. Cleared only by the qualification
/// fixture ([`TxHold`]) and by `disable`.
const TCTL_EN: u32 = 1 << 1;

/// Timer ticks (~1 ms) a reset or link-up may take.
const SETUP_TICKS: u64 = 2_000;
/// Timer ticks one transmit descriptor may take to report done.
const TX_TICKS: u64 = 100;
const SPIN_LIMIT: u32 = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NicError {
    Absent,
    Claim(pci::ClaimError),
    Bar(pci::BarError),
    Map {
        error: mmio::MapError,
        bar: u64,
    },
    /// The reset bit never cleared. (A link that is not up is not a
    /// refusal: see [`link_up`].)
    Timeout(&'static str),
    /// Receive address 0 is not marked valid: no MAC address to use.
    NoMacAddress,
}

/// Why a probed NIC was turned off.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disabled {
    RxHead(u32),
    TxHead(u32),
    TxTimeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendError {
    /// Length outside 14..=1514; nothing reached the device.
    Length,
    /// The frame could not be copied in.
    Copy,
    /// The NIC is disabled for the rest of the boot (`ERROR_IO`).
    Disabled,
    /// A link outcome (`ERROR_NO_CARRIER`): the frame was not reported done
    /// because the link has no carrier. The NIC is not disabled; a
    /// descriptor may still be device-owned, and later sends are refused
    /// this way, at once, until it completes or carrier returns.
    NoCarrier,
}

#[repr(C, align(4096))]
struct RingPage([u64; 512]);

#[repr(C, align(4096))]
struct RxBuffers([[u8; BUFFER_BYTES]; RX_DESCRIPTORS]);

#[repr(C, align(4096))]
struct TxBuffers([[u8; BUFFER_BYTES]; TX_DESCRIPTORS]);

// Each ring gets a whole page: descriptor `i` is words `2i` (buffer
// address) and `2i + 1` (length, status, and command fields).
static mut RX_RING: RingPage = RingPage([0; 512]);
static mut TX_RING: RingPage = RingPage([0; 512]);
static mut RX_BUFFERS: RxBuffers = RxBuffers([[0; BUFFER_BYTES]; RX_DESCRIPTORS]);
static mut TX_BUFFERS: TxBuffers = TxBuffers([[0; BUFFER_BYTES]; TX_DESCRIPTORS]);

#[derive(Clone, Copy, Debug)]
pub struct Identity {
    pub pci: pci::Function,
    pub mac: [u8; 6],
}

#[derive(Clone, Copy, Debug)]
struct Nic {
    registers: u64,
    identity: Identity,
    rx_next: usize,
    tx: TxSlots,
    /// Qualification fixture state ([`TxHold`]): the transmitter is paused
    /// (TCTL.EN clear) or, for the software kind, done bits are withheld.
    tx_paused: bool,
    disabled: Option<Disabled>,
    info: NicInfo,
}

static mut NIC: Option<Nic> = None;

fn nic() -> Option<&'static mut Nic> {
    crate::kernel_lock::assert_bsp_device_access();
    unsafe { (*core::ptr::addr_of_mut!(NIC)).as_mut() }
}

fn ticks() -> u64 {
    crate::timer_ticks.load(core::sync::atomic::Ordering::Relaxed)
}

/// Sleeps until the next interrupt; spinning on a device register instead
/// starves QEMU's main loop (see `block::wait_for_interrupt`).
fn pause(site: crate::kernel_lock::WaitSite) {
    crate::kernel_lock::wait_for_irq(site);
}

fn read32(registers: u64, offset: u64) -> u32 {
    unsafe { core::ptr::read_volatile((registers + offset) as *const u32) }
}

fn write32(registers: u64, offset: u64, value: u32) {
    unsafe { core::ptr::write_volatile((registers + offset) as *mut u32, value) }
}

fn rx_ring() -> *mut u64 {
    unsafe { core::ptr::addr_of_mut!(RX_RING.0) as *mut u64 }
}

fn tx_ring() -> *mut u64 {
    unsafe { core::ptr::addr_of_mut!(TX_RING.0) as *mut u64 }
}

fn rx_buffer(index: usize) -> *mut u8 {
    unsafe { core::ptr::addr_of_mut!(RX_BUFFERS.0[index]) as *mut u8 }
}

fn tx_buffer(index: usize) -> *mut u8 {
    unsafe { core::ptr::addr_of_mut!(TX_BUFFERS.0[index]) as *mut u8 }
}

fn wait_until(
    registers: u64,
    what: &'static str,
    done: impl Fn(u64) -> bool,
) -> Result<(), NicError> {
    crate::smp_startup::first_poll(crate::kernel_lock::WaitSite::NicProbe);
    let start = ticks();
    while !done(registers) {
        if ticks().wrapping_sub(start) > SETUP_TICKS {
            return Err(NicError::Timeout(what));
        }
        pause(crate::kernel_lock::WaitSite::NicProbe);
    }
    Ok(())
}

/// Finds, claims, resets, and starts the first 82540EM.
pub fn prepare_qualification_mapping() -> Result<(), NicError> {
    assert!(crate::smp_startup::enabled());
    crate::kernel_lock::assert_bsp_device_access();
    let function = pci::find_id(VENDOR_INTEL, DEVICE_82540EM).ok_or(NicError::Absent)?;
    let bar = pci::memory_bar(function, 0).map_err(NicError::Bar)?;
    mmio::map(bar, REGISTER_BYTES, mmio::Cache::Uncached)
        .map_err(|error| NicError::Map { error, bar })?;
    Ok(())
}
/// Driver ownership and device initialization still begin at this claim.
pub fn probe() -> Result<Identity, NicError> {
    crate::kernel_lock::assert_bsp_device_access();
    let function = pci::find_id(VENDOR_INTEL, DEVICE_82540EM).ok_or(NicError::Absent)?;
    pci::claim(function, "e1000").map_err(NicError::Claim)?;
    let bar = pci::memory_bar(function, 0).map_err(NicError::Bar)?;
    let registers = mmio::map(bar, REGISTER_BYTES, mmio::Cache::Uncached)
        .map_err(|error| NicError::Map { error, bar })?;
    pci::enable_polled_dma(function);

    // Reset: firmware (or an earlier boot stage) may have left rings of its
    // own. Everything below is rebuilt from scratch.
    write32(registers, IMC, u32::MAX);
    write32(registers, RCTL, 0);
    write32(registers, TCTL, 0);
    write32(registers, CTRL, read32(registers, CTRL) | CTRL_RST);
    wait_until(registers, "reset", |registers| {
        read32(registers, CTRL) & CTRL_RST == 0
    })?;
    write32(registers, IMC, u32::MAX);
    let _ = read32(registers, ICR);

    let low = read32(registers, RAL0);
    let high = read32(registers, RAH0);
    if high & RAH_AV == 0 {
        return Err(NicError::NoMacAddress);
    }
    let mut mac = [0u8; 6];
    mac[..4].copy_from_slice(&low.to_le_bytes());
    mac[4..].copy_from_slice(&(high as u16).to_le_bytes());
    // The set of solicited-node MAC suffixes spans every MTA hash bit.
    // UPE and MPE remain clear; take_frame narrows the hardware's multicast
    // reception to the fixed all-nodes / solicited-node Ethernet policy.
    for index in 0..128 {
        write32(registers, MTA + 4 * index, u32::MAX);
    }

    let rx = rx_ring();
    let tx = tx_ring();
    for word in 0..512 {
        unsafe {
            core::ptr::write_volatile(rx.add(word), 0);
            core::ptr::write_volatile(tx.add(word), 0);
        }
    }
    for index in 0..RX_DESCRIPTORS {
        unsafe { core::ptr::write_volatile(rx.add(2 * index), rx_buffer(index) as u64) };
    }
    for index in 0..TX_DESCRIPTORS {
        unsafe { core::ptr::write_volatile(tx.add(2 * index), tx_buffer(index) as u64) };
    }
    fence(Ordering::SeqCst);
    let rx_base = rx as u64;
    let tx_base = tx as u64;
    write32(registers, RDBAL, rx_base as u32);
    write32(registers, RDBAH, (rx_base >> 32) as u32);
    write32(registers, RDLEN, (RX_DESCRIPTORS * 16) as u32);
    write32(registers, RDH, 0);
    // The device owns every descriptor but one: head == tail means empty.
    write32(registers, RDT, (RX_DESCRIPTORS - 1) as u32);
    write32(registers, TDBAL, tx_base as u32);
    write32(registers, TDBAH, (tx_base >> 32) as u32);
    write32(registers, TDLEN, (TX_DESCRIPTORS * 16) as u32);
    write32(registers, TDH, 0);
    write32(registers, TDT, 0);
    write32(registers, TIPG, TIPG_VALUE);
    write32(registers, TCTL, TCTL_VALUE);
    write32(registers, RCTL, RCTL_VALUE);
    write32(
        registers,
        CTRL,
        read32(registers, CTRL) | CTRL_SLU | CTRL_ASDE,
    );
    // Link up is asked for and given SETUP_TICKS, but a link that is not
    // up by then is not a refusal: the device initialized, so it is granted
    // with the link down (`NIC LINK DOWN AT PROBE`), `nic_info` reads the
    // link live from `STATUS.LU`, and frames flow once carrier returns
    // without any re-probe. Connectivity is a facility of the machine, not
    // the condition for owning the NIC.
    let _ = wait_until(registers, "link", |registers| {
        read32(registers, STATUS) & STATUS_LU != 0
    });
    let _ = read32(registers, MPC);

    let identity = Identity { pci: function, mac };
    unsafe {
        *core::ptr::addr_of_mut!(NIC) = Some(Nic {
            registers,
            identity,
            rx_next: 0,
            tx: TxSlots::new(),
            tx_paused: false,
            disabled: None,
            info: NicInfo {
                mac,
                ..NicInfo::default()
            },
        });
    }
    Ok(identity)
}

pub fn present() -> bool {
    nic().is_some()
}

/// Whether the link is up right now (`STATUS.LU`, read live); false for a
/// disabled NIC, whose registers are no longer consulted.
pub fn link_up() -> bool {
    match nic() {
        Some(nic) => nic.disabled.is_none() && read32(nic.registers, STATUS) & STATUS_LU != 0,
        None => false,
    }
}

/// Whether the NIC has disabled itself (a ring fault or a send timeout).
/// Once true, every send and receive is refused with `ERROR_IO` before any
/// other argument is looked at (docs/NETWORK.md).
pub fn disabled() -> bool {
    match nic() {
        Some(nic) => nic.disabled.is_some(),
        None => false,
    }
}

impl Nic {
    fn disable(&mut self, reason: Disabled) {
        write32(self.registers, RCTL, 0);
        write32(self.registers, TCTL, 0);
        write32(self.registers, IMC, u32::MAX);
        if self.disabled.is_none() {
            serial::write("NIC DISABLED reason=");
            match reason {
                Disabled::RxHead(head) => {
                    serial::write("rx-head-outside-ring head=");
                    serial::decimal(u64::from(head));
                }
                Disabled::TxHead(head) => {
                    serial::write("tx-head-outside-ring head=");
                    serial::decimal(u64::from(head));
                }
                Disabled::TxTimeout => serial::write("tx-timeout"),
            }
            serial::write("\n");
        }
        self.disabled = Some(reason);
    }

    fn check_heads(&mut self) -> Result<(), Disabled> {
        if let Some(reason) = self.disabled {
            return Err(reason);
        }
        let head = read32(self.registers, RDH);
        if !head_in_ring(head, RX_DESCRIPTORS) {
            self.disable(Disabled::RxHead(head));
            return Err(Disabled::RxHead(head));
        }
        let head = read32(self.registers, TDH);
        if !head_in_ring(head, TX_DESCRIPTORS) {
            self.disable(Disabled::TxHead(head));
            return Err(Disabled::TxHead(head));
        }
        Ok(())
    }

    /// Counts a held transmit descriptor whose done bit has appeared (once,
    /// in `tx_frames`) and frees it; reads one done bit, writes nothing but
    /// the fixture's resume.
    fn reap_held(&mut self) {
        let mut counters = TxCounters {
            frames: self.info.tx_frames,
            errors: self.info.tx_errors,
        };
        let mut port = MmioTx {
            registers: self.registers,
            paused: &mut self.tx_paused,
        };
        port.resume();
        self.tx.reap(&mut port, &mut counters);
        (self.info.tx_frames, self.info.tx_errors) = (counters.frames, counters.errors);
    }

    /// Returns the descriptor at `rx_next` to the device and moves on.
    fn recycle(&mut self) {
        let index = self.rx_next;
        let descriptor = rx_ring();
        unsafe {
            core::ptr::write_volatile(descriptor.add(2 * index), rx_buffer(index) as u64);
            core::ptr::write_volatile(descriptor.add(2 * index + 1), 0);
        }
        fence(Ordering::SeqCst);
        write32(self.registers, RDT, index as u32);
        self.rx_next = next(index, RX_DESCRIPTORS);
    }
}

/// Hands the next accepted frame to `deliver`, which copies it out and
/// returns whether it could. Refused descriptors on the way are counted and
/// recycled. `Ok(None)` when no whole frame is waiting.
pub fn take_frame(deliver: impl FnOnce(&[u8]) -> bool) -> Result<Option<usize>, Disabled> {
    let Some(nic) = nic() else {
        return Ok(None);
    };
    nic.check_heads()?;
    for _ in 0..RX_DESCRIPTORS {
        let index = nic.rx_next;
        let word = unsafe { core::ptr::read_volatile(rx_ring().add(2 * index + 1)) };
        let length = word as u16;
        let status = (word >> 32) as u8;
        let errors = (word >> 40) as u8;
        match classify_rx(status, errors, length) {
            RxVerdict::Empty => return Ok(None),
            RxVerdict::Refused(refusal) => {
                nic.info.rx_refused += 1;
                if nic.info.rx_refused <= 4 {
                    serial::write("NIC RX REFUSED ");
                    match refusal {
                        RxRefusal::Fragment => serial::write("fragment"),
                        RxRefusal::DeviceError(bits) => {
                            serial::write("errors=0x");
                            serial::hex_digits(u64::from(bits), 2);
                        }
                        RxRefusal::Length(length) => {
                            serial::write("length=");
                            serial::decimal(u64::from(length));
                        }
                    }
                    serial::write("\n");
                }
                nic.recycle();
            }
            RxVerdict::Frame(bytes) => {
                // The device's writes to the buffer precede its status write.
                fence(Ordering::SeqCst);
                let frame = unsafe { core::slice::from_raw_parts(rx_buffer(index), bytes) };
                let destination = [frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]];
                if !accept_rx_destination(destination, nic.identity.mac) {
                    nic.info.rx_refused += 1;
                    // Keep the same bounded diagnostic budget as descriptor
                    // refusals, but identify destination filtering separately.
                    // The shared NicInfo counter and wire ABI are unchanged.
                    if nic.info.rx_refused <= 4 {
                        serial::write("NIC RX FILTERED dst=");
                        for (index, byte) in destination.iter().enumerate() {
                            if index != 0 {
                                serial::write(":");
                            }
                            serial::hex_digits(u64::from(*byte), 2);
                        }
                        serial::write("\n");
                    }
                    nic.recycle();
                    continue;
                }
                let delivered = deliver(frame);
                nic.recycle();
                if !delivered {
                    return Ok(None);
                }
                nic.info.rx_frames += 1;
                return Ok(Some(bytes));
            }
        }
    }
    Ok(None)
}

/// Qualification only (`nic-tx-hold`, `nic-tx-hold-stuck`; docs/NETWORK.md
/// "Verification"): QEMU's device completes a transmit descriptor without
/// carrier, so the §10 link branch is unreachable there. Armed, a
/// descriptor posted while `STATUS.LU` is clear is held by pausing the
/// transmitter (TCTL.EN clear) before the tail moves; `Release` resumes it
/// once carrier is back, `Stuck` never does. It models a device that holds
/// descriptors without carrier; it is not one, and shows the driver's rule,
/// not any device's behaviour. Unarmed (every boot without the option), it
/// is inert: `tx_hold()` is `None` and no fixture branch runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxHold {
    Release,
    Stuck,
}

static mut TX_HOLD: Option<TxHold> = None;

/// Arms the fixture; called once from the probe, before init starts.
pub fn arm_tx_hold(mode: TxHold) {
    crate::kernel_lock::assert_bsp_device_access();
    unsafe { *core::ptr::addr_of_mut!(TX_HOLD) = Some(mode) };
}

fn tx_hold() -> Option<TxHold> {
    unsafe { *core::ptr::addr_of!(TX_HOLD) }
}

/// The transmit ring as `TxSlots` reaches it.
struct MmioTx<'a> {
    registers: u64,
    paused: &'a mut bool,
}

impl MmioTx<'_> {
    /// Fixture only: a paused transmitter resumes once carrier is back,
    /// unless the hold is `Stuck`.
    fn resume(&mut self) {
        if *self.paused && tx_hold() == Some(TxHold::Release) && self.link_up() {
            write32(self.registers, TCTL, TCTL_VALUE);
            *self.paused = false;
        }
    }
}

impl TxPort for MmioTx<'_> {
    fn link_up(&mut self) -> bool {
        read32(self.registers, STATUS) & STATUS_LU != 0
    }

    fn done(&mut self, index: usize) -> bool {
        let word = unsafe { core::ptr::read_volatile(tx_ring().add(2 * index + 1)) };
        (word >> 32) as u8 & TX_STATUS_DD != 0
    }

    fn post(&mut self, index: usize, wire: usize, tail: usize) {
        let descriptor = tx_ring();
        let command = u64::from(wire as u16) | (u64::from(TX_COMMAND) << 24);
        unsafe {
            core::ptr::write_volatile(descriptor.add(2 * index), tx_buffer(index) as u64);
            core::ptr::write_volatile(descriptor.add(2 * index + 1), command);
        }
        fence(Ordering::SeqCst);
        if tx_hold().is_some() && !*self.paused && !self.link_up() {
            write32(self.registers, TCTL, TCTL_VALUE & !TCTL_EN);
            *self.paused = true;
        }
        write32(self.registers, TDT, tail as u32);
    }

    /// The spin phase reads only the descriptor (memory); `STATUS.LU` is
    /// read at each tick-paced poll after it, and `transmit` has already
    /// read it at post and reads it again at expiry.
    fn wait_done(&mut self, index: usize, carrier_lost: &mut bool) -> bool {
        self.resume();
        crate::smp_fixture::device_first_poll(crate::kernel_lock::WaitSite::NicSend);
        let start = ticks();
        let mut spins = 0u32;
        loop {
            if self.done(index) {
                return true;
            }
            if spins < SPIN_LIMIT {
                spins += 1;
                core::hint::spin_loop();
                continue;
            }
            if !self.link_up() {
                *carrier_lost = true;
            }
            if ticks().wrapping_sub(start) > TX_TICKS {
                return false;
            }
            pause(crate::kernel_lock::WaitSite::NicSend);
        }
    }
}

/// Sends one frame of `length` bytes that `fill` copies into the transmit
/// buffer. Returns once the device reports the descriptor done, or with the
/// §10 outcome (`e1000_ring::TxSlots`): a bound that expires without
/// carrier is `NoCarrier` and leaves the descriptor device-owned and the
/// NIC enabled; one that expires with carrier present disables the NIC.
pub fn send(length: u64, fill: impl FnOnce(&mut [u8]) -> bool) -> Result<(), SendError> {
    let Some(nic) = nic() else {
        return Err(SendError::Disabled);
    };
    // Once disabled, every send is refused as `Disabled` before any
    // argument is validated: fail-closed means no counter moves either.
    nic.check_heads().map_err(|_| SendError::Disabled)?;
    let Some((bytes, wire)) = send_length(length) else {
        nic.info.tx_refused += 1;
        return Err(SendError::Length);
    };
    let mut counters = TxCounters {
        frames: nic.info.tx_frames,
        errors: nic.info.tx_errors,
    };
    let mut port = MmioTx {
        registers: nic.registers,
        paused: &mut nic.tx_paused,
    };
    let outcome = match nic.tx.before_post(&mut port, &mut counters) {
        Err(outcome) => Some(outcome),
        Ok(index) => {
            let buffer = unsafe { core::slice::from_raw_parts_mut(tx_buffer(index), BUFFER_BYTES) };
            if fill(&mut buffer[..bytes]) {
                buffer[bytes..wire].fill(0);
                Some(nic.tx.transmit(&mut port, index, wire, &mut counters))
            } else {
                None
            }
        }
    };
    (nic.info.tx_frames, nic.info.tx_errors) = (counters.frames, counters.errors);
    match outcome {
        None => Err(SendError::Copy),
        Some(TxOutcome::Sent) => nic.check_heads().map_err(|_| SendError::Disabled),
        Some(TxOutcome::NoCarrier) => Err(SendError::NoCarrier),
        Some(TxOutcome::DeviceFailed) => {
            // A device outcome (counted by `TxSlots`, except a misused
            // `transmit`, which counts nothing). The ring state is rebuilt
            // so nothing of it outlives the disable.
            nic.disable(Disabled::TxTimeout);
            nic.tx = TxSlots::new();
            nic.tx_paused = false;
            Err(SendError::Disabled)
        }
    }
}

/// The record `nic_info` returns. The device's missed-packet counter clears
/// on read, so it is accumulated here.
pub fn info() -> Option<NicInfo> {
    let nic = nic()?;
    if nic.disabled.is_none() {
        nic.info.rx_missed += u64::from(read32(nic.registers, MPC));
        // A late done bit is counted here too, so the counters `nic_info`
        // returns are current without waiting for the next send. A disabled
        // NIC's registers and descriptors are no longer consulted; its held
        // descriptor stays abandoned.
        nic.reap_held();
    }
    let mut info = nic.info;
    info.mac = nic.identity.mac;
    info.flags = 0;
    if nic.disabled.is_none() && read32(nic.registers, STATUS) & STATUS_LU != 0 {
        info.flags |= NIC_FLAG_LINK_UP;
    }
    if nic.disabled.is_some() {
        info.flags |= NIC_FLAG_DISABLED;
    }
    Some(info)
}

/// Qualification only (`nic-ring-fault` beside `net-probe` or `net`, under
/// QEMU, whose device skips a descriptor with a null buffer): writes an out-of-ring
/// value into the device's receive head register, as a faulty device
/// would report it. The driver must find it on its next poll and disable
/// the NIC before anything is received. Returns the value written.
pub fn inject_rx_head_fault() -> Option<u32> {
    let nic = nic()?;
    let head = (RX_DESCRIPTORS + 3) as u32;
    write32(nic.registers, RDH, head);
    Some(head)
}
