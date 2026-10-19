//! A bounded xHCI bring-up: one controller, one USB device's
//! device descriptor. Admitted for the lanes recorded in
//! docs/xhci-20261010/RECORD.md and docs/xhci-hw-readiness-20261010/RECORD.md
//! only; this is not a USB stack. There is no hub, configuration,
//! interface, class driver, bulk/interrupt endpoint, or user-visible USB
//! object.
//!
//! The controller follows the kernel's device pattern (src/nvme.rs,
//! src/e1000.rs): found by PCI class (serial bus, USB, xHCI), claimed
//! (`pci::claim`) before its BAR is sized or mapped; BAR0 mapped uncached
//! through `mmio`; every register offset checked against the sized BAR
//! (`absd_kernel::xhci_ring::layout`) before the first operational access.
//!
//! Ownership comes before any change to the controller. Until ABSD owns
//! it, the driver only reads registers (and sizes BAR0, a configuration
//! access restored as found). It owns the controller when the extended
//! capability list (walked with bounds, `absd_kernel::xhci_legacy::walk`)
//! has no USB Legacy Support capability, or when the BIOS-to-OS handoff
//! (`xhci_legacy::handoff`) has observed the firmware's semaphore clear and
//! its own set; only then are legacy SMIs disabled. A controller whose
//! ownership could not be established (firmware kept it, the semaphores
//! contradicted each other, or the layout or capability list could not be
//! trusted) is left exactly as found, bus mastering included, and reported
//! `XHCI PRESERVED`. A controller ABSD owns and then refuses or fails is
//! halted (bounded) and taken off the bus (`XHCI DMA OFF`).
//!
//! Firmware may hand the controller over running, with its own rings live
//! and bus mastering on (SeaBIOS does): this driver enables bus mastering
//! itself only after it has halted and reset the controller.
//! DMA reaches only static, page-aligned kernel pages inside the kernel
//! image, which is identity-mapped below 1 GiB (each page's address is its
//! bus address; `xhci_scratch::check_page` checks that range, the
//! alignment, and 4 GiB for a controller without 64-bit addressing). x86
//! keeps those write-back pages coherent with bus-master DMA; a full fence
//! orders TRB and context writes before each doorbell and each event's
//! cycle bit before its other words.
//!
//! Scratchpad buffers come from one static pool of
//! `xhci_scratch::POOL_PAGES` 4 KiB pages with its own lifecycle
//! (`xhci_scratch::Pool`): prepared (zeroed, array built) while the
//! controller is halted and reset and before bus mastering, installed in
//! DCBAA entry 0 before DCBAAP and Run/Stop, reclaimed only once the
//! controller is halted and reset or off the bus, and quarantined for the
//! boot if it was never seen to stop.
//!
//! `xhci-probe` keeps interrupts off and polls; `xhci-controller` uses one
//! BSP MSI-X vector (xhci_interrupt.rs). INTx stays masked in both modes.
//! Every wait is bounded in PIT ticks, and the
//! number of events consumed per wait is bounded too, so a controller that
//! stops answering or floods the ring ends in a named error, never a hang.
//! At most one command or one control transfer is outstanding. An event
//! that does not answer it, a TRB on the event ring that is not an event,
//! a timeout, or USBSTS.HSE/HCE marks the controller failed: nothing more
//! is submitted and it is halted. A command the controller completes with
//! an error code is reported by name and is not fatal.
//!
//! The bring-up runs only in the `xhci-probe` boot, on the bootstrap CPU,
//! before any application processor or process exists. Every round ends
//! with a halt attempt (Run/Stop cleared, HCHalted awaited within its
//! bound, `halted=no` reported otherwise), the bring-up ends with bus
//! mastering cleared, and the boot then continues whatever happened.

use core::cell::Cell;
use core::fmt::Write;
use core::sync::atomic::{Ordering, fence};

use absd_kernel::xhci_legacy::{
    self as legacy, CapabilitySpace, ContentRefusal, HandoffError, LegacyAccess, WalkError,
    model::Firmware,
};
use absd_kernel::xhci_ring::{
    self as rules, COMMAND_RING_TRBS, Consumer, DescriptorError, DeviceDescriptor, EVENT_RING_TRBS,
    Event, Layout, LayoutError, Malformed, Producer, TRANSFER_RING_TRBS, Verdict, Wait,
};
use absd_kernel::xhci_scratch::{
    self as scratch, AddressError, PageSizeError, Pool, PoolError, PoolState, Quiescence,
};

pub use absd_kernel::xhci_legacy::model::Behaviour;

#[path = "xhci_keyboard.rs"]
mod keyboard;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyboardRecoveryTest {
    None,
    LateEntry,
    ResetTimeout,
    EnumerationHold,
}

pub fn initialize_keyboard(
    observe: bool,
    masked: bool,
    test_race: bool,
    recover: bool,
    recovery_test: KeyboardRecoveryTest,
) {
    keyboard::initialize(observe, masked, test_race, recover, recovery_test);
}

pub fn keyboard_progress() {
    keyboard::progress();
}

pub fn keyboard_stop_before_finish() -> bool {
    keyboard::stop_before_finish()
}

use crate::{mmio, pci, serial, xhci_interrupt};
use absd_kernel::xhci_irq;

const CLASS_SERIAL_BUS: u8 = 0x0c;
const SUBCLASS_USB: u8 = 0x03;
const INTERFACE_XHCI: u8 = 0x30;

const CAP_CAPLENGTH: u64 = 0x00;
const CAP_HCSPARAMS1: u64 = 0x04;
const CAP_HCSPARAMS2: u64 = 0x08;
const CAP_HCCPARAMS1: u64 = 0x10;
const CAP_DBOFF: u64 = 0x14;
const CAP_RTSOFF: u64 = 0x18;

const OP_USBCMD: u64 = 0x00;
const OP_USBSTS: u64 = 0x04;
const OP_PAGESIZE: u64 = 0x08;
const OP_CRCR: u64 = 0x18;
const OP_DCBAAP: u64 = 0x30;
const OP_CONFIG: u64 = 0x38;
const OP_PORTS: u64 = 0x400;
/// Qualification only: where the firmware model's capability is placed,
/// inside the operational block's reserved span (0x3C..0x3FF), which no
/// driver access touches.
const OP_MODEL: u64 = 0x100;

const IR_IMAN: u64 = 0x00;
const IR_IMOD: u64 = 0x04;
const IR_ERSTSZ: u64 = 0x08;
const IR_ERSTBA: u64 = 0x10;
const IR_ERDP: u64 = 0x18;
const ERDP_EHB: u64 = 1 << 3;

const USBCMD_RUN: u32 = 1;
const USBCMD_RESET: u32 = 1 << 1;
const USBCMD_INTE: u32 = 1 << 2;
const USBSTS_EINT: u32 = 1 << 3;
const USBSTS_HALTED: u32 = 1;
const USBSTS_HOST_SYSTEM_ERROR: u32 = 1 << 2;
const USBSTS_NOT_READY: u32 = 1 << 11;
const USBSTS_HOST_CONTROLLER_ERROR: u32 = 1 << 12;

/// The identity map covers the first GiB (src/mmio.rs).
const IDENTITY_LIMIT: u64 = 1 << 30;

/// Device slots the driver enables (CONFIG.MaxSlotsEn).
const SLOTS_ENABLED: u8 = 1;
/// The endpoint zero Device Context Index, its doorbell target.
const EP0: u8 = 1;
const SLOT_STATE_ADDRESSED: u32 = 2;

/// Polls before each wait for the next timer tick.
const SPIN_LIMIT: u32 = 10_000;
/// Timer ticks (~1 ms) for each bounded wait.
const READY_TICKS: u64 = 1_000;
const HALT_TICKS: u64 = 200;
const COMMAND_TICKS: u64 = 500;
const IRQ_WAIT_TICKS: u64 = 20;
const TRANSFER_TICKS: u64 = 1_000;
const PORT_RESET_TICKS: u64 = 500;
/// After setting PORTSC.PP: the bit must read back set, then power is
/// given this long to become good (USB 2 hub-style 20 ms).
const PORT_POWER_TICKS: u64 = 20;
const HOTPLUG_TICKS: u64 = 30_000;
/// From the OS-semaphore request until firmware must have released the
/// controller (Linux's quirk waits 1 s too, then forces it; this driver
/// does not force).
const HANDOFF_TICKS: u64 = 1_000;
/// Qualification only: how long the controller is left running for the
/// host's observer to pause the guest and read its structures.
const OBSERVE_TICKS: u64 = 3_000;
/// Events one wait may consume before the controller is judged to be
/// flooding the ring.
const EVENT_BUDGET: u32 = 64;
/// No-op commands per round: enough to wrap the command ring (15 usable
/// TRBs) and the event ring (16) at least twice.
const NOOPS: u32 = 40;
/// Device descriptor reads per enumeration after the first: three TRBs
/// each on a seven-TRB ring, so the transfer ring wraps, with some
/// transfers crossing its Link TRB.
const REREADS: u32 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    None,
    MaskedVector,
    InterruptStorm,
    LateMsi,
    /// Pretend BAR0 decodes only 64 bytes.
    BarBounds,
    /// Never set Run/Stop, then wait for the controller to run.
    RunTimeout,
    /// Submit a no-op command without ringing the doorbell.
    CommandTimeout,
    /// Substitute a Command Completion event for a TRB never submitted.
    ForeignEvent,
    /// Substitute a TRB whose type is not an event.
    MalformedEvent,
    /// Address a device slot that was never enabled.
    BadSlot,
    /// Substitute a Command Completion for the previous, already completed
    /// command (a stale or duplicate completion).
    StaleEvent,
    /// Ask for a 64-byte device descriptor, which the device answers with
    /// 18: a real short data stage, which must be refused by name.
    ShortRead,
    /// In round 1 only, the scratchpad page halfway through the array fails
    /// its DMA check: preparation must be rolled back before the controller
    /// sees any of it.
    ScratchpadAlloc,
    /// While the controller runs with scratchpads installed, ask the pool
    /// to reclaim them: the pool must refuse.
    EarlyReclaim,
}

impl Fault {
    pub fn parse(name: &[u8]) -> Option<Self> {
        Some(match name {
            b"masked-vector" => Self::MaskedVector,
            b"interrupt-storm" => Self::InterruptStorm,
            b"late-msi" => Self::LateMsi,
            b"bar-bounds" => Self::BarBounds,
            b"run-timeout" => Self::RunTimeout,
            b"command-timeout" => Self::CommandTimeout,
            b"foreign-event" => Self::ForeignEvent,
            b"malformed-event" => Self::MalformedEvent,
            b"bad-slot" => Self::BadSlot,
            b"stale-event" => Self::StaleEvent,
            b"short-read" => Self::ShortRead,
            b"scratchpad-alloc" => Self::ScratchpadAlloc,
            b"early-reclaim" => Self::EarlyReclaim,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Plan {
    pub interrupts: bool,
    pub rounds: u32,
    pub fault: Fault,
    /// Wait for the enumerated device to be detached and a device to be
    /// attached again, and enumerate that one (driven by the host harness).
    pub hotplug: bool,
    /// Qualification only: a modeled firmware owning the controller through
    /// a USB Legacy Support capability spliced into the list at read time.
    pub firmware: Option<Behaviour>,
    /// Qualification only: Max Scratchpad Buffers substituted into
    /// HCSPARAMS2 as it is read.
    pub scratchpads: Option<u32>,
    /// Qualification only: a PAGESIZE value substituted as it is read.
    pub pagesize: Option<u32>,
    /// Qualification only: after Run/Stop, announce the controller's
    /// structures and keep it running for `OBSERVE_TICKS` so the host can
    /// read them from guest memory and the device.
    pub observe: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    Claim(pci::ClaimError),
    Bar(pci::BarError),
    Map {
        error: mmio::MapError,
        bar: u64,
    },
    Layout(LayoutError),
    /// PAGESIZE lacks 4 KiB pages.
    PageSize(u32),
    /// Scratchpads are required and PAGESIZE offers more than one size.
    PageSizes(u32),
    /// The extended capability list could not be walked safely.
    Capabilities(WalkError),
    /// The USB Legacy Support handoff did not give ABSD the controller.
    Handoff(HandoffError),
    /// The scratchpad pool cannot provide what the controller asks for.
    Scratchpads(PoolError),
    /// A DMA page failed its address check.
    Address(AddressError),
    /// A Supported Protocol capability defines its own speed IDs (PSIC);
    /// only the default speed IDs are understood.
    ProtocolSpeeds {
        major: u8,
    },
    /// A Supported Protocol capability names no port, or ports past
    /// MaxPorts.
    PortRange {
        first: u8,
        count: u8,
    },
    /// With Port Power Control, this port's power did not come on.
    PortPower(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XhciError {
    Absent,
    Keyboard(absd_kernel::usb_keyboard::Error),
    Interrupt(xhci_irq::Error),
    Refused(Refusal),
    Timeout(&'static str),
    /// USBSTS reported Host System Error or Host Controller Error.
    ControllerError(u32),
    /// A command completed with this code (`kind` is its TRB type).
    Command {
        kind: u32,
        code: u8,
    },
    /// A control transfer completed with this code.
    Transfer {
        code: u8,
    },
    Malformed(Malformed),
    Unexpected(Event),
    EventStorm,
    /// An earlier error left the controller in an unknown state.
    Failed,
    SlotId(u8),
    UnsupportedSpeed(u8),
    PortNotEnabled(u32),
    /// The device's slot did not reach the Addressed state.
    NotAddressed(u32),
    Descriptor(DescriptorError),
    /// A repeated read returned a different descriptor.
    DescriptorChanged,
    /// The data stage moved fewer bytes than asked for.
    Short {
        expected: u16,
        got: u32,
    },
    /// The legacy semaphores stopped showing ABSD as owner after the
    /// handoff: firmware may be using the controller again.
    OwnershipLost(HandoffError),
}

#[repr(C, align(4096))]
struct Page([u8; 4096]);

static mut DCBAA: Page = Page([0; 4096]);
static mut COMMAND_RING: Page = Page([0; 4096]);
static mut EVENT_RING: Page = Page([0; 4096]);
static mut ERST: Page = Page([0; 4096]);
static mut INPUT_CONTEXT: Page = Page([0; 4096]);
static mut DEVICE_CONTEXT: Page = Page([0; 4096]);
static mut EP0_RING: Page = Page([0; 4096]);
static mut DATA: Page = Page([0; 4096]);
static mut KEYBOARD_RING: Page = Page([0; 4096]);
static mut KEYBOARD_REPORT: Page = Page([0; 4096]);
/// The Scratchpad Buffer Array (at most POOL_PAGES entries: 512 bytes).
static mut SCRATCHPAD_ARRAY: Page = Page([0; 4096]);
/// The scratchpad pool: written only while `Pool::writable`.
static mut SCRATCHPADS: [Page; scratch::POOL_PAGES] =
    [const { Page([0; 4096]) }; scratch::POOL_PAGES];

fn page(which: *mut Page) -> u64 {
    which as u64
}

fn pages() -> [*mut Page; 11] {
    [
        core::ptr::addr_of_mut!(DCBAA),
        core::ptr::addr_of_mut!(COMMAND_RING),
        core::ptr::addr_of_mut!(EVENT_RING),
        core::ptr::addr_of_mut!(ERST),
        core::ptr::addr_of_mut!(INPUT_CONTEXT),
        core::ptr::addr_of_mut!(DEVICE_CONTEXT),
        core::ptr::addr_of_mut!(EP0_RING),
        core::ptr::addr_of_mut!(DATA),
        core::ptr::addr_of_mut!(SCRATCHPAD_ARRAY),
        core::ptr::addr_of_mut!(KEYBOARD_RING),
        core::ptr::addr_of_mut!(KEYBOARD_REPORT),
    ]
}

fn scratchpad(index: usize) -> *mut Page {
    assert!(index < scratch::POOL_PAGES);
    unsafe { core::ptr::addr_of_mut!(SCRATCHPADS[index]) }
}

/// The memory ABSD knows to be its own and identity-mapped: the kernel
/// image, which the frame allocator reserves and the boot page tables map
/// one-to-one below 1 GiB.
fn owned_range() -> (u64, u64) {
    unsafe extern "C" {
        static __kernel_start: u8;
        static __kernel_end: u8;
    }
    let start = core::ptr::addr_of!(__kernel_start) as u64;
    let end = core::ptr::addr_of!(__kernel_end) as u64;
    (start, end.min(IDENTITY_LIMIT))
}

fn word(which: *mut Page, byte: u64) -> *mut u32 {
    assert!(byte.is_multiple_of(4) && byte < 4096);
    (page(which) + byte) as *mut u32
}

fn zero(which: *mut Page) {
    for byte in (0..4096).step_by(4) {
        unsafe { core::ptr::write_volatile(word(which, byte), 0) };
    }
}

/// Writes a TRB: the three parameter/status words, then (ordered after
/// them) the control word that carries the cycle bit.
fn write_trb(ring: *mut Page, index: usize, trb: [u32; 4]) {
    let base = index as u64 * rules::TRB_BYTES;
    for (at, value) in trb.iter().take(3).enumerate() {
        unsafe { core::ptr::write_volatile(word(ring, base + 4 * at as u64), *value) };
    }
    fence(Ordering::SeqCst);
    unsafe { core::ptr::write_volatile(word(ring, base + 12), trb[3]) };
}

fn with_cycle(control: u32, cycle: bool) -> u32 {
    (control & !rules::TRB_CYCLE) | u32::from(cycle)
}

fn link_trb(ring: *mut Page, cycle: bool) -> [u32; 4] {
    let base = page(ring);
    [
        base as u32,
        (base >> 32) as u32,
        0,
        with_cycle(
            rules::control(rules::TRB_LINK) | rules::LINK_TOGGLE_CYCLE,
            cycle,
        ),
    ]
}

fn ticks() -> u64 {
    crate::timer_ticks.load(Ordering::Relaxed)
}

/// Sleeps until the next interrupt (the ~1 kHz PIT at the latest). The
/// bring-up runs before the kernel lock is active, on the bootstrap CPU.
fn wait_tick() {
    assert!(!crate::kernel_lock::active());
    unsafe { core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack)) };
}

#[derive(Clone, Copy, Debug, Default)]
struct Ports {
    usb2: Option<(u8, u8)>,
    usb3: Option<(u8, u8)>,
}

/// Qualification only: the firmware model and where its capability sits.
#[derive(Clone, Copy, Debug)]
struct Model {
    firmware: Firmware,
    /// BAR offset of the modeled USBLEGSUP (a second, duplicate capability
    /// follows 16 bytes later for `Behaviour::Duplicate`).
    offset: u64,
    /// Whether the walk has been pointed at the model.
    spliced: bool,
}

impl Model {
    fn duplicate(&self) -> bool {
        self.firmware.behaviour == Behaviour::Duplicate
    }
}

/// Who answers for the controller after a refusal or failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Custody {
    /// ABSD owned it: halted (bounded) and taken off the bus.
    Released,
    /// ABSD never established ownership (firmware kept it, or its state
    /// could not be established): left exactly as found.
    Preserved(&'static str),
    /// Ownership was established then lost; leave current device state
    /// alone. This is not preservation of its original firmware state.
    Abandoned,
}

struct Controller {
    function: pci::Function,
    /// BAR0's physical base, for reports.
    bar: u64,
    registers: u64,
    layout: Layout,
    interrupt: Option<xhci_interrupt::Route>,
    extended_reads: Cell<(u64, u64)>,
    ports: Ports,
    /// The USB Legacy Support capability (real or modeled), if any.
    legacy: Option<u64>,
    /// Qualification only (interior mutability: register reads advance it).
    model: Cell<Option<Model>>,
    /// Max Scratchpad Buffers, and the pool that provides them.
    scratchpads: u32,
    pool: Pool,
    /// Qualification only: PAGESIZE substituted as read.
    pagesize: Option<u32>,
    /// Whether this round has armed the controller (bus mastering enabled,
    /// DMA structures about to be programmed); from then on a failure is
    /// not contained.
    armed_this_round: bool,
    round: u32,
    observe: bool,
    command: Producer,
    events: Consumer,
    ep0: Producer,
    failed: bool,
    /// Qualification only: the next event the controller writes is read as
    /// this TRB instead (its cycle bit kept), standing in for a controller
    /// that wrote a wrong event at that position.
    substitute: Option<[u32; 4]>,
    fault: Fault,
    /// The residual a Short Packet event reported for the data stage of the
    /// control transfer in flight.
    short: Option<u32>,
    /// The bus address of the last command TRB that completed.
    last_command: u64,
    commands: u64,
    transfers: u64,
    events_seen: u64,
    port_events: u64,
}

impl Controller {
    fn record_extended(&self, offset: u64, bytes: u64) {
        let (start, end) = self.extended_reads.get();
        self.extended_reads.set((
            if end == 0 { offset } else { start.min(offset) },
            end.max(offset + bytes),
        ));
    }
    fn read32(&self, offset: u64) -> u32 {
        assert!(offset.is_multiple_of(4) && offset + 4 <= self.layout.bar_bytes);
        if let Some(value) = self.model_read(offset) {
            return value;
        }
        unsafe { core::ptr::read_volatile((self.registers + offset) as *const u32) }
    }

    fn write32(&self, offset: u64, value: u32) {
        assert!(offset.is_multiple_of(4) && offset + 4 <= self.layout.bar_bytes);
        if self.model_write(offset, value) {
            return;
        }
        self.changing("mmio write", offset);
        unsafe { core::ptr::write_volatile((self.registers + offset) as *mut u32, value) }
    }

    /// One byte store: only the OS semaphore (USBLEGSUP byte 3) is written
    /// this way, so firmware's byte is never part of the store.
    fn write8(&self, offset: u64, value: u8) {
        assert!(offset < self.layout.bar_bytes);
        if let Some(mut model) = self.model.get()
            && let Some(byte) = offset.checked_sub(model.offset)
            && byte < 4
        {
            model.firmware.write_legsup_byte(byte, value, ticks());
            self.model.set(Some(model));
            return;
        }
        self.changing("mmio byte write", offset);
        unsafe { core::ptr::write_volatile((self.registers + offset) as *mut u8, value) }
    }

    /// Qualification only: the modeled capability's registers.
    fn model_read(&self, offset: u64) -> Option<u32> {
        let mut model = self.model.get()?;
        let at = offset.checked_sub(model.offset)?;
        let value = match at {
            0 => model.firmware.read_legsup(ticks()) | if model.duplicate() { 4 << 8 } else { 0 },
            4 => model.firmware.read_control(ticks()),
            16 if model.duplicate() => legacy::EXT_LEGACY,
            20 if model.duplicate() => 0,
            _ => return None,
        };
        self.model.set(Some(model));
        Some(value)
    }

    fn model_write(&self, offset: u64, value: u32) -> bool {
        let Some(mut model) = self.model.get() else {
            return false;
        };
        match offset.checked_sub(model.offset) {
            Some(0) => model.firmware.write_legsup(value, ticks()),
            Some(4) => model.firmware.write_control(value, ticks()),
            Some(16 | 20) if model.duplicate() => {}
            _ => return false,
        }
        self.model.set(Some(model));
        true
    }

    /// Every change ABSD makes to the controller (a register write, a PCI
    /// command change) passes here first; the firmware model, when present,
    /// records it as a violation unless the OS owns the controller.
    fn changing(&self, what: &'static str, offset: u64) {
        if let Some(mut model) = self.model.get() {
            model.firmware.controller_write(what, offset, ticks());
            self.model.set(Some(model));
        }
    }

    fn bus_master_on(&self) {
        self.changing("pci bus master on", 4);
        pci::enable_polled_dma(self.function);
    }

    fn bus_master_off(&self) {
        self.changing("pci bus master off", 4);
        pci::disable_dma(self.function);
    }

    /// Masks INTx (memory decoding stays on): only once ABSD owns it.
    fn mask_intx(&self) {
        self.changing("pci intx mask", 4);
        pci::enable_memory(self.function);
    }

    /// Re-checks ownership before a change to the controller.
    fn ownership_holds(&self) -> Result<(), XhciError> {
        let Some(offset) = self.legacy else {
            return Ok(());
        };
        legacy::holds(&mut Legacy {
            controller: self,
            offset,
        })
        .map_err(XhciError::OwnershipLost)
    }

    /// What the pool needs to know to reclaim.
    fn quiescence(&self, reset: bool) -> Quiescence {
        Quiescence {
            halted: self.halted(),
            bus_master: pci::bus_master(self.function),
            reset,
        }
    }

    /// Zeroes the scratchpad pages and builds the array, checking every
    /// page. On any failure the array is cleared and the pool abandoned:
    /// the controller has seen none of it. Called only while the controller
    /// is halted and HCRST-complete (DCBAAP cleared), before this round
    /// arms it; bus mastering may already be on.
    fn prepare_scratchpads(&mut self, page_bytes: u64) -> Result<(), XhciError> {
        let required = self.scratchpads;
        self.pool
            .prepare(required)
            .map_err(|error| XhciError::Refused(Refusal::Scratchpads(error)))?;
        assert!(self.pool.writable());
        let array = core::ptr::addr_of_mut!(SCRATCHPAD_ARRAY);
        zero(array);
        let owned = owned_range();
        let addresses_64 = self.layout.addresses_64;
        let mut built = Ok(());
        for index in 0..required {
            let buffer = scratchpad(index as usize);
            let mut address = page(buffer);
            if self.fault == Fault::ScratchpadAlloc && self.round == 1 && index == required / 2 {
                serial::write("XHCI FAULT INJECTED scratchpad-alloc\n");
                // Stand in for a page that is not ABSD's identity-mapped
                // memory (what a failed allocation would hand back).
                address = owned.1.next_multiple_of(page_bytes);
            }
            if let Err(error) =
                scratch::check_page(index, address, page_bytes, page_bytes, owned, addresses_64)
            {
                built = Err(error);
                break;
            }
            zero(buffer);
            unsafe {
                core::ptr::write_volatile(
                    (page(array) + 8 * u64::from(index)) as *mut u64,
                    address,
                );
            }
        }
        if let Err(error) = built {
            zero(array);
            self.pool.abandon().expect("prepared pool");
            serial::write("XHCI SCRATCHPAD ABANDONED required=");
            serial::decimal(u64::from(required));
            report(" error=", XhciError::Refused(Refusal::Address(error)));
            return Err(XhciError::Refused(Refusal::Address(error)));
        }
        Ok(())
    }

    /// After a round: the pool is returned if the controller is quiescent,
    /// otherwise quarantined for the boot.
    fn release_scratchpads(&mut self, reset: bool) {
        if !matches!(self.pool.state(), PoolState::Installed { .. }) {
            return;
        }
        let seen = self.quiescence(reset);
        match self.pool.reclaim(seen) {
            Ok(()) => {
                serial::write("XHCI SCRATCHPAD RELEASED state=free installs=");
                serial::decimal(self.pool.installs());
                serial::write("\n");
            }
            Err(error) => {
                self.pool.quarantine();
                serial::write("XHCI SCRATCHPAD QUARANTINED ");
                let _ = write!(serial::Serial, "{error:?} {:?}", self.pool.state());
                serial::write("\n");
            }
        }
    }

    /// Low half first: the controller acts on the high half's write.
    fn write64(&self, offset: u64, value: u64) {
        self.write32(offset, value as u32);
        self.write32(offset + 4, (value >> 32) as u32);
    }

    fn operational(&self, register: u64) -> u64 {
        self.layout.operational + register
    }

    fn interrupter0(&self, register: u64) -> u64 {
        self.layout.runtime + 0x20 + register
    }

    fn portsc(&self, port: u8) -> u64 {
        assert!(port >= 1 && port <= self.layout.max_ports);
        self.operational(OP_PORTS + 0x10 * u64::from(port - 1))
    }

    fn doorbell(&self, target: u8, value: u32) {
        assert!(target <= self.layout.max_slots);
        fence(Ordering::SeqCst);
        self.write32(self.layout.doorbells + 4 * u64::from(target), value);
    }

    fn status(&self) -> u32 {
        self.read32(self.operational(OP_USBSTS))
    }

    /// HCHalted, with an all-ones read (the function not answering) taken
    /// as not halted.
    fn halted(&self) -> bool {
        let status = self.status();
        status != u32::MAX && status & USBSTS_HALTED != 0
    }

    fn fail<T>(&mut self, error: XhciError) -> Result<T, XhciError> {
        self.failed = true;
        Err(error)
    }

    /// Polls `done` until it holds or `limit` ticks pass.
    fn wait_until(
        &self,
        what: &'static str,
        limit: u64,
        mut done: impl FnMut(&Self) -> bool,
    ) -> Result<(), XhciError> {
        let start = ticks();
        let mut spins = 0u32;
        loop {
            if done(self) {
                return Ok(());
            }
            if spins < SPIN_LIMIT {
                spins += 1;
                core::hint::spin_loop();
                continue;
            }
            if ticks().wrapping_sub(start) > limit {
                return Err(XhciError::Timeout(what));
            }
            wait_tick();
        }
    }

    /// Clears Run/Stop and waits for HCHalted. Whether it halted.
    fn halt(&mut self) -> bool {
        let command = self.read32(self.operational(OP_USBCMD));
        self.write32(self.operational(OP_USBCMD), command & !USBCMD_RUN);
        self.wait_until("halt", HALT_TICKS, |c| c.halted()).is_ok()
    }

    /// With Port Power Control, ports come out of reset unpowered: power
    /// available port (neutral write-back plus PP), then allow the power-good
    /// delay. Controller qualification requires every PP readback; keyboard
    /// selection may skip unpowered/over-current ports. Without PPC no write
    /// is needed. Never attempt to enable a port while OCA is asserted.
    fn power_ports(&mut self, port_local: bool) -> Result<(), XhciError> {
        if !self.layout.port_power_control {
            return Ok(());
        }
        for port in 1..=self.layout.max_ports {
            self.ownership_holds()?;
            let offset = self.portsc(port);
            let value = self.read32(offset);
            if rules::port_power_on_needed(value, self.layout.port_power_control) {
                self.write32(offset, rules::portsc_neutral(value) | rules::PORTSC_PP);
            }
        }
        if !port_local {
            let powered = self.wait_until("port power", PORT_POWER_TICKS, |c| {
                (1..=c.layout.max_ports)
                    .all(|port| c.read32(c.portsc(port)) & rules::PORTSC_PP != 0)
            });
            if powered.is_err() {
                let port = (1..=self.layout.max_ports)
                    .find(|&port| self.read32(self.portsc(port)) & rules::PORTSC_PP == 0)
                    .unwrap_or(0);
                return Err(XhciError::Refused(Refusal::PortPower(port)));
            }
        }
        let start = ticks();
        while ticks().wrapping_sub(start) <= PORT_POWER_TICKS {
            wait_tick();
        }
        Ok(())
    }

    /// Reset, scratchpads, rings, and Run/Stop. Everything below is rebuilt
    /// from scratch on every round. The order is the contract: ownership
    /// re-checked before the first change; halt and reset; the previous
    /// round's scratchpads reclaimed (halted and reset); PAGESIZE checked;
    /// scratchpads prepared (memory only) while the controller is halted
    /// and HCRST-complete, so DCBAAP is cleared and it cannot reach them
    /// whatever bus mastering says (firmware may have left BME on, and
    /// from round 2 it stays on); bus mastering then (re-)enabled; DCBAA
    /// entry 0 written before DCBAAP; ownership re-checked before Run/Stop.
    fn start(&mut self, fault: Fault) -> Result<(), XhciError> {
        self.start_with_port_policy(fault, false)
    }

    /// Keyboard selection can skip an unavailable root port. Controller
    /// qualification retains its original all-ports-powered requirement.
    fn start_with_port_policy(&mut self, fault: Fault, port_local: bool) -> Result<(), XhciError> {
        self.failed = false;
        self.armed_this_round = false;
        self.wait_until("controller not ready", READY_TICKS, |c| {
            c.status() & USBSTS_NOT_READY == 0
        })?;
        self.ownership_holds()?;
        if !self.halted() && !self.halt() {
            return Err(XhciError::Timeout("halt before reset"));
        }
        self.write32(self.operational(OP_USBCMD), USBCMD_RESET);
        self.wait_until("reset", READY_TICKS, |c| {
            c.read32(c.operational(OP_USBCMD)) & USBCMD_RESET == 0
                && c.status() & USBSTS_NOT_READY == 0
        })?;
        // Halted and reset: the controller holds no scratchpad state now.
        self.release_scratchpads(true);
        let page_size = match self.pagesize {
            Some(value) => value,
            None => self.read32(self.operational(OP_PAGESIZE)),
        };
        serial::write("XHCI PAGESIZE round=");
        serial::decimal(u64::from(self.round));
        serial::write(" value=");
        serial::hex_digits(u64::from(page_size), 8);
        serial::write(if self.pagesize.is_some() {
            " source=substituted\n"
        } else {
            " source=device\n"
        });
        let page_bytes =
            scratch::page_bytes(page_size, self.scratchpads).map_err(|error| match error {
                PageSizeError::No4KiB(value) => XhciError::Refused(Refusal::PageSize(value)),
                PageSizeError::Ambiguous(value) => XhciError::Refused(Refusal::PageSizes(value)),
            })?;
        if self.scratchpads != 0 {
            self.prepare_scratchpads(page_bytes)?;
        }
        // Halted and reset: nothing firmware set up is live any more, so the
        // controller may now reach memory, and only this driver's pages.
        // Bus mastering may already be on (firmware's, or round 1's); what
        // kept the controller from the pages until now is halt + HCRST.
        self.armed_this_round = true;
        self.bus_master_on();
        self.power_ports(port_local)?;
        for which in &pages()[..8] {
            zero(*which);
        }
        self.command = Producer::new(COMMAND_RING_TRBS);
        self.events = Consumer::new(EVENT_RING_TRBS);
        self.ep0 = Producer::new(TRANSFER_RING_TRBS);
        let command_ring = core::ptr::addr_of_mut!(COMMAND_RING);
        write_trb(
            command_ring,
            self.command.link_index(),
            link_trb(command_ring, false),
        );

        self.write32(self.operational(OP_CONFIG), u32::from(SLOTS_ENABLED));
        let dcbaa = core::ptr::addr_of_mut!(DCBAA);
        if self.scratchpads != 0 {
            let array = page(core::ptr::addr_of_mut!(SCRATCHPAD_ARRAY));
            unsafe { core::ptr::write_volatile(page(dcbaa) as *mut u64, array) };
            fence(Ordering::SeqCst);
            self.pool.install().expect("prepared pool");
            serial::write("XHCI SCRATCHPAD INSTALLED round=");
            serial::decimal(u64::from(self.round));
            serial::write(" count=");
            serial::decimal(u64::from(self.scratchpads));
            serial::write(" page_bytes=");
            serial::decimal(page_bytes);
            serial::write(" array=");
            serial::hex(array);
            serial::write(" dcbaa=");
            serial::hex(page(dcbaa));
            serial::write("\n");
        }
        self.write64(self.operational(OP_DCBAAP), page(dcbaa));
        // Ring Cycle State 1, matching the producer's first cycle.
        self.write64(self.operational(OP_CRCR), page(command_ring) | 1);
        let events = page(core::ptr::addr_of_mut!(EVENT_RING));
        let erst = core::ptr::addr_of_mut!(ERST);
        unsafe {
            core::ptr::write_volatile(word(erst, 0), events as u32);
            core::ptr::write_volatile(word(erst, 4), (events >> 32) as u32);
            core::ptr::write_volatile(word(erst, 8), EVENT_RING_TRBS as u32);
        }
        fence(Ordering::SeqCst);
        // The probe stays polled; the controller mode arms MSI-X only after
        // all DMA structures exist and ownership has been rechecked.
        self.write32(self.interrupter0(IR_IMAN), 1);
        self.write32(self.interrupter0(IR_IMOD), 0);
        self.write32(self.interrupter0(IR_ERSTSZ), 1);
        self.write64(self.interrupter0(IR_ERDP), events);
        self.write64(self.interrupter0(IR_ERSTBA), page(erst));
        self.ownership_holds()?;
        if self.interrupt.is_some() {
            self.changing("msix configure", 0);
            self.interrupt
                .as_mut()
                .unwrap()
                .configure(u64::from(self.round))
                .map_err(XhciError::Interrupt)?;
            self.ownership_holds()?;
            self.changing("msix enable", 0);
            self.interrupt
                .as_mut()
                .unwrap()
                .enable(fault == Fault::MaskedVector)
                .map_err(XhciError::Interrupt)?;
            self.ownership_holds()?;
            self.write32(self.operational(OP_USBSTS), USBSTS_EINT);
            self.write32(self.interrupter0(IR_IMAN), 3);
            if self.read32(self.interrupter0(IR_IMAN)) & 2 == 0 {
                return self.fail(XhciError::Interrupt(xhci_irq::Error::Readback));
            }
        }
        self.ownership_holds()?;
        if fault != Fault::RunTimeout {
            self.write32(
                self.operational(OP_USBCMD),
                USBCMD_RUN
                    | if self.interrupt.is_some() {
                        USBCMD_INTE
                    } else {
                        0
                    },
            );
        }
        self.wait_until("run", HALT_TICKS, |c| c.status() & USBSTS_HALTED == 0)?;
        let status = self.status();
        if status & (USBSTS_HOST_SYSTEM_ERROR | USBSTS_HOST_CONTROLLER_ERROR) != 0 {
            return self.fail(XhciError::ControllerError(status));
        }
        Ok(())
    }

    fn event_available(&self) -> bool {
        let ring = core::ptr::addr_of_mut!(EVENT_RING);
        self.events.owned(unsafe {
            core::ptr::read_volatile(word(
                ring,
                self.events.dequeue() as u64 * rules::TRB_BYTES + 12,
            ))
        })
    }

    fn shutdown_interrupts(&mut self) -> Result<bool, XhciError> {
        self.ownership_holds()?;
        self.write32(self.interrupter0(IR_IMAN), 1);
        let interrupt_off = self.read32(self.interrupter0(IR_IMAN)) & 2 == 0;
        let command = self.read32(self.operational(OP_USBCMD));
        self.write32(self.operational(OP_USBCMD), command & !USBCMD_INTE);
        let controller_off = self.read32(self.operational(OP_USBCMD)) & USBCMD_INTE == 0;
        self.ownership_holds()?;
        self.changing("msix disable", 0);
        let transport = self.interrupt.as_mut().unwrap().disable();
        let halted = self.halt();
        self.ownership_holds()?;
        self.bus_master_off();
        let dma_off = !pci::bus_master(self.function);
        let _ = self.read32(self.operational(OP_USBSTS));
        let start = ticks();
        let tsc = unsafe { core::arch::x86_64::_rdtsc() };
        while self.interrupt.as_ref().unwrap().pending() {
            if ticks().wrapping_sub(start) > HALT_TICKS
                || unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(tsc) > 1 << 34
            {
                return Err(XhciError::Interrupt(xhci_irq::Error::Drain));
            }
            wait_tick();
        }
        if !interrupt_off || !controller_off || !dma_off {
            return Err(XhciError::Interrupt(xhci_irq::Error::Readback));
        }
        transport.map_err(XhciError::Interrupt)?;
        let seen = xhci_interrupt::STATE.snapshot();
        serial::write("XHCI IRQ DRAINED generation=");
        serial::decimal(seen.generation);
        serial::write(" count=");
        serial::decimal(seen.count);
        serial::write(" late=");
        serial::decimal(seen.late);
        serial::write("\n");
        Ok(halted)
    }

    /// Leave a real device MSI pending in IRR while IF is clear. Retirement
    /// then drains that delivery through the retained ISR as a late IRQ.
    fn post_late_msi(&mut self) -> Result<(), XhciError> {
        let ring = core::ptr::addr_of_mut!(COMMAND_RING);
        let slot = self.command.claim();
        write_trb(
            ring,
            slot.index,
            [
                0,
                0,
                0,
                with_cycle(rules::control(rules::TRB_NOOP_COMMAND), slot.cycle),
            ],
        );
        if let Some(cycle) = slot.link {
            write_trb(ring, self.command.link_index(), link_trb(ring, cycle));
        }
        self.ownership_holds()?;
        self.doorbell(0, 0);
        let start = unsafe { core::arch::x86_64::_rdtsc() };
        while !self.interrupt.as_ref().unwrap().pending() {
            if unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) > 1 << 32 {
                return Err(XhciError::Interrupt(xhci_irq::Error::Drain));
            }
            core::hint::spin_loop();
        }
        serial::write("XHCI LATE MSI PENDING source=device\n");
        Ok(())
    }

    fn irq_quiet(&self) -> bool {
        let before = xhci_interrupt::STATE.snapshot();
        let start = ticks();
        while ticks().wrapping_sub(start) < 20 {
            wait_tick();
        }
        let after = xhci_interrupt::STATE.snapshot();
        let pending = self.interrupt.as_ref().is_some_and(|route| route.pending());
        let quiet = before == after && !pending;
        serial::write(if quiet {
            "XHCI IRQ QUIET generation="
        } else {
            "XHCI IRQ NOT QUIET generation="
        });
        serial::decimal(after.generation);
        serial::write(" late=");
        serial::decimal(after.late);
        serial::write("\n");
        quiet
    }

    /// Consumes and decodes the event at the dequeue position, if the
    /// controller has written one. A TRB that is not an event fails the
    /// controller.
    fn take_event(&mut self) -> Result<Option<Event>, XhciError> {
        let ring = core::ptr::addr_of_mut!(EVENT_RING);
        let base = self.events.dequeue() as u64 * rules::TRB_BYTES;
        let control = unsafe { core::ptr::read_volatile(word(ring, base + 12)) };
        if !self.events.owned(control) {
            return Ok(None);
        }
        // The cycle bit is read first; the rest is read after it.
        fence(Ordering::SeqCst);
        let mut trb = [0u32; 4];
        for (at, value) in trb.iter_mut().take(3).enumerate() {
            *value = unsafe { core::ptr::read_volatile(word(ring, base + 4 * at as u64)) };
        }
        trb[3] = control;
        if let Some(substitute) = self.substitute.take() {
            trb = [
                substitute[0],
                substitute[1],
                substitute[2],
                with_cycle(substitute[3], control & rules::TRB_CYCLE != 0),
            ];
        }
        self.events.advance();
        let next = page(ring) + self.events.dequeue() as u64 * rules::TRB_BYTES;
        if self.interrupt.is_some() {
            self.write32(self.operational(OP_USBSTS), USBSTS_EINT);
            self.write32(self.interrupter0(IR_IMAN), 3);
        }
        if self.interrupt.is_some() {
            xhci_interrupt::STATE.acknowledge();
        }
        self.write64(self.interrupter0(IR_ERDP), next | ERDP_EHB);
        self.events_seen += 1;
        match rules::decode(trb) {
            Ok(event) => Ok(Some(event)),
            Err(malformed) => self.fail(XhciError::Malformed(malformed)),
        }
    }

    /// Consumes events until the one answering `wait` arrives. Returns its
    /// completion code and slot ID.
    fn wait_event(
        &mut self,
        wait: Wait,
        limit: u64,
        what: &'static str,
    ) -> Result<(u8, u8), XhciError> {
        let ep0 = page(core::ptr::addr_of_mut!(EP0_RING));
        let ep0_end = ep0 + self.ep0.link_index() as u64 * rules::TRB_BYTES;
        let start = ticks();
        let mut spins = 0u32;
        let mut consumed = 0u32;
        let irq_start = if self.interrupt.is_some() {
            let count = xhci_interrupt::STATE.credit_baseline();
            if self.fault == Fault::InterruptStorm {
                serial::write("XHCI FAULT INJECTED interrupt-storm source=software-entry\n");
                xhci_interrupt::inject_storm();
            }
            Some(count)
        } else {
            None
        };
        loop {
            if let Some(before) = irq_start {
                if let Err(error) = xhci_interrupt::STATE.check() {
                    return self.fail(XhciError::Interrupt(error));
                }
                if self.event_available() && xhci_interrupt::STATE.snapshot().count == before {
                    let irq_start = ticks();
                    while xhci_interrupt::STATE.snapshot().count == before {
                        wait_tick();
                        if let Err(error) = xhci_interrupt::STATE.check() {
                            return self.fail(XhciError::Interrupt(error));
                        }
                        if ticks().wrapping_sub(irq_start) > IRQ_WAIT_TICKS {
                            return self.fail(XhciError::Interrupt(
                                xhci_irq::Error::CompletedWithoutInterrupt,
                            ));
                        }
                    }
                }
            }
            if let Some(event) = self.take_event()? {
                consumed += 1;
                if consumed > EVENT_BUDGET {
                    return self.fail(XhciError::EventStorm);
                }
                match rules::judge(event, wait, (ep0, ep0_end)) {
                    Verdict::Complete { code, slot, .. } => return Ok((code, slot)),
                    Verdict::PortChange { .. } => self.port_events += 1,
                    Verdict::Short { residual } => self.short = Some(residual),
                    Verdict::Unexpected(event) => return self.fail(XhciError::Unexpected(event)),
                }
                continue;
            }
            let status = self.status();
            if status & (USBSTS_HOST_SYSTEM_ERROR | USBSTS_HOST_CONTROLLER_ERROR) != 0 {
                return self.fail(XhciError::ControllerError(status));
            }
            if spins < SPIN_LIMIT {
                spins += 1;
                core::hint::spin_loop();
                continue;
            }
            if ticks().wrapping_sub(start) > limit {
                return self.fail(XhciError::Timeout(what));
            }
            wait_tick();
        }
    }

    /// Consumes whatever is already on the event ring while nothing is
    /// outstanding: only port status changes may be there.
    fn drain(&mut self) -> Result<(), XhciError> {
        for _ in 0..EVENT_BUDGET {
            match self.take_event()? {
                None => return Ok(()),
                Some(Event::PortStatusChange { .. }) => self.port_events += 1,
                Some(event) => return self.fail(XhciError::Unexpected(event)),
            }
        }
        self.fail(XhciError::EventStorm)
    }

    /// Submits one command TRB and waits for its completion. Returns the
    /// slot ID the completion names.
    fn command(&mut self, trb: [u32; 4], ring_doorbell: bool) -> Result<u8, XhciError> {
        if self.failed {
            return Err(XhciError::Failed);
        }
        let ring = core::ptr::addr_of_mut!(COMMAND_RING);
        let kind = rules::trb_type(trb[3]);
        let slot = self.command.claim();
        write_trb(
            ring,
            slot.index,
            [trb[0], trb[1], trb[2], with_cycle(trb[3], slot.cycle)],
        );
        if let Some(cycle) = slot.link {
            write_trb(ring, self.command.link_index(), link_trb(ring, cycle));
        }
        if ring_doorbell {
            self.doorbell(0, 0);
        }
        let pointer = page(ring) + slot.index as u64 * rules::TRB_BYTES;
        let (code, slot_id) =
            self.wait_event(Wait::Command { trb: pointer }, COMMAND_TICKS, "command")?;
        self.commands += 1;
        self.last_command = pointer;
        if code != rules::COMPLETION_SUCCESS {
            return Err(XhciError::Command { kind, code });
        }
        Ok(slot_id)
    }

    /// Writes one TRB on the endpoint-zero ring; returns its bus address
    /// and the control word that hands it to the controller. With `hold`
    /// the TRB is written with the inverted cycle bit, so the controller
    /// does not own it until the caller writes that control word.
    fn push_ep0(&mut self, trb: [u32; 4], hold: bool) -> (u64, u32) {
        let ring = core::ptr::addr_of_mut!(EP0_RING);
        let slot = self.ep0.claim();
        let owned = with_cycle(trb[3], slot.cycle);
        let written = if hold {
            with_cycle(trb[3], !slot.cycle)
        } else {
            owned
        };
        write_trb(ring, slot.index, [trb[0], trb[1], trb[2], written]);
        if let Some(cycle) = slot.link {
            write_trb(ring, self.ep0.link_index(), link_trb(ring, cycle));
        }
        (page(ring) + slot.index as u64 * rules::TRB_BYTES, owned)
    }

    /// One control transfer with an IN data stage of `length` bytes into
    /// the DATA page. A transfer that ends in any code but Success leaves
    /// endpoint zero halted; no endpoint recovery is implemented, so that
    /// fails the controller.
    fn control_in(&mut self, slot_id: u8, setup: u64, length: u16) -> Result<(), XhciError> {
        if self.failed {
            return Err(XhciError::Failed);
        }
        let data = core::ptr::addr_of_mut!(DATA);
        zero(data);
        let buffer = page(data);
        // The Setup TRB is held (inverted cycle) until the whole transfer is
        // written, then handed over in one store before the doorbell.
        let (first, setup_control) = self.push_ep0(
            [
                setup as u32,
                (setup >> 32) as u32,
                8,
                rules::control(rules::TRB_SETUP) | rules::TRB_IDT | rules::SETUP_IN_DATA,
            ],
            true,
        );
        let (data_trb, _) = self.push_ep0(
            [
                buffer as u32,
                (buffer >> 32) as u32,
                u32::from(length),
                rules::control(rules::TRB_DATA) | rules::DIRECTION_IN | rules::TRB_ISP,
            ],
            false,
        );
        // Status stage OUT (direction bit clear) after an IN data stage.
        let (last, _) = self.push_ep0(
            [0, 0, 0, rules::control(rules::TRB_STATUS) | rules::TRB_IOC],
            false,
        );
        fence(Ordering::SeqCst);
        unsafe { core::ptr::write_volatile((first + 12) as *mut u32, setup_control) };
        self.short = None;
        self.doorbell(slot_id, u32::from(EP0));
        let wait = Wait::Transfer {
            first,
            data: data_trb,
            last,
            slot: slot_id,
            endpoint: EP0,
        };
        let (code, _) = self.wait_event(wait, TRANSFER_TICKS, "transfer")?;
        if code != rules::COMPLETION_SUCCESS {
            return self.fail(XhciError::Transfer { code });
        }
        let got = self.short.take().map_or(u32::from(length), |residual| {
            u32::from(length).saturating_sub(residual)
        });
        if got != u32::from(length) {
            // The transfer itself completed; the ring is consistent, so
            // this is a refusal of the data, not a controller failure.
            return Err(XhciError::Short {
                expected: length,
                got,
            });
        }
        self.transfers += 1;
        Ok(())
    }

    fn read_descriptor(&mut self, slot_id: u8, length: u16) -> Result<[u8; 18], XhciError> {
        self.control_in(
            slot_id,
            rules::get_descriptor_setup(rules::DESCRIPTOR_DEVICE, 0, length),
            length,
        )?;
        let mut bytes = [0u8; 18];
        let data = core::ptr::addr_of!(DATA) as *const u8;
        for (index, byte) in bytes.iter_mut().enumerate().take(usize::from(length)) {
            *byte = unsafe { core::ptr::read_volatile(data.add(index)) };
        }
        Ok(bytes)
    }

    fn context(&self, which: *mut Page, index: u64, dword: u64) -> *mut u32 {
        word(which, index * self.layout.context_bytes + 4 * dword)
    }

    /// Port reset for a USB 2 port; a USB 3 port enables itself when its
    /// link trains, so one already enabled is left alone.
    fn reset_port(&mut self, port: u8) -> Result<u32, XhciError> {
        let offset = self.portsc(port);
        let value = self.read32(offset);
        if value & rules::PORTSC_PED != 0 {
            return Ok(value);
        }
        self.write32(offset, rules::portsc_neutral(value) | rules::PORTSC_PR);
        self.wait_until("port reset", PORT_RESET_TICKS, |c| {
            c.read32(offset) & rules::PORTSC_PRC != 0
        })?;
        let value = self.read32(offset);
        self.write32(offset, rules::portsc_neutral(value) | rules::PORTSC_PRC);
        if value & rules::PORTSC_PED == 0 {
            return Err(XhciError::PortNotEnabled(value));
        }
        Ok(value)
    }

    /// Enable Slot, Address Device, and the device descriptor. Leaves the
    /// slot enabled; returns its ID with the descriptor.
    fn enumerate(&mut self, port: u8) -> Result<(u8, u32, DeviceDescriptor), XhciError> {
        let portsc = self.reset_port(port)?;
        let speed = rules::port_speed(portsc);
        let initial = rules::initial_max_packet(speed).ok_or(XhciError::UnsupportedSpeed(speed))?;
        let slot_id = self.command([0, 0, 0, rules::control(rules::TRB_ENABLE_SLOT)], true)?;
        if slot_id == 0 || slot_id > SLOTS_ENABLED {
            return self.fail(XhciError::SlotId(slot_id));
        }
        let input = core::ptr::addr_of_mut!(INPUT_CONTEXT);
        let output = core::ptr::addr_of_mut!(DEVICE_CONTEXT);
        let ring = core::ptr::addr_of_mut!(EP0_RING);
        zero(input);
        zero(output);
        zero(ring);
        self.ep0 = Producer::new(TRANSFER_RING_TRBS);
        write_trb(ring, self.ep0.link_index(), link_trb(ring, false));
        let ep0 = |max_packet: u16| -> [u32; 5] {
            let dequeue = page(ring) | 1;
            [
                0,
                // Max Packet Size, EP Type 4 (control), CErr 3.
                (u32::from(max_packet) << 16) | (4 << 3) | (3 << 1),
                dequeue as u32,
                (dequeue >> 32) as u32,
                // Average TRB Length.
                8,
            ]
        };
        unsafe {
            // Input Control Context: add the slot and endpoint zero.
            core::ptr::write_volatile(self.context(input, 0, 1), 0b11);
            // Slot Context: one context entry, the port's speed, root port.
            core::ptr::write_volatile(
                self.context(input, 1, 0),
                (1 << 27) | (u32::from(speed) << 20),
            );
            core::ptr::write_volatile(self.context(input, 1, 1), u32::from(port) << 16);
            for (dword, value) in ep0(initial).iter().enumerate() {
                core::ptr::write_volatile(self.context(input, 2, dword as u64), *value);
            }
            let entry = page(core::ptr::addr_of_mut!(DCBAA)) + 8 * u64::from(slot_id);
            core::ptr::write_volatile(entry as *mut u64, page(output));
        }
        fence(Ordering::SeqCst);
        let address_device = |slot: u8| {
            [
                page(input) as u32,
                (page(input) >> 32) as u32,
                0,
                rules::control(rules::TRB_ADDRESS_DEVICE) | (u32::from(slot) << 24),
            ]
        };
        self.command(address_device(slot_id), true)?;
        let state = unsafe { core::ptr::read_volatile(self.context(output, 0, 3)) };
        if state >> 27 != SLOT_STATE_ADDRESSED || state & 0xff == 0 {
            return self.fail(XhciError::NotAddressed(state));
        }
        let address = state & 0xff;

        let prefix = self.read_descriptor(slot_id, 8)?;
        let max_packet = rules::max_packet0(&prefix).map_err(XhciError::Descriptor)?;
        if max_packet != initial {
            // Full speed: endpoint zero's real packet size, by Evaluate
            // Context with only endpoint zero's add flag.
            zero(input);
            unsafe {
                core::ptr::write_volatile(self.context(input, 0, 1), 0b10);
                for (dword, value) in ep0(max_packet).iter().enumerate().take(2) {
                    core::ptr::write_volatile(self.context(input, 2, dword as u64), *value);
                }
            }
            fence(Ordering::SeqCst);
            let mut evaluate = address_device(slot_id);
            evaluate[3] = rules::control(rules::TRB_EVALUATE_CONTEXT) | (u32::from(slot_id) << 24);
            self.command(evaluate, true)?;
            serial::write("XHCI EP0 PACKET UPDATED from=");
            serial::decimal(u64::from(initial));
            serial::write(" to=");
            serial::decimal(u64::from(max_packet));
            serial::write("\n");
        }
        if self.fault == Fault::ShortRead {
            serial::write("XHCI FAULT INJECTED short-read\n");
            let setup = rules::get_descriptor_setup(rules::DESCRIPTOR_DEVICE, 0, 64);
            match self.control_in(slot_id, setup, 64) {
                Err(XhciError::Short { expected, got }) => {
                    serial::write("XHCI SHORT REFUSED expected=");
                    serial::decimal(u64::from(expected));
                    serial::write(" got=");
                    serial::decimal(u64::from(got));
                    serial::write("\n");
                }
                Ok(()) => serial::write("XHCI SHORT ACCEPTED\n"),
                Err(other) => return Err(other),
            }
        }
        let bytes = self.read_descriptor(slot_id, rules::DEVICE_DESCRIPTOR_BYTES)?;
        let descriptor = rules::device_descriptor(&bytes).map_err(XhciError::Descriptor)?;
        for _ in 0..REREADS {
            if self.read_descriptor(slot_id, rules::DEVICE_DESCRIPTOR_BYTES)? != bytes {
                return self.fail(XhciError::DescriptorChanged);
            }
        }
        Ok((slot_id, address, descriptor))
    }

    fn disable_slot(&mut self, slot_id: u8) -> Result<(), XhciError> {
        self.command(
            [
                0,
                0,
                0,
                rules::control(rules::TRB_DISABLE_SLOT) | (u32::from(slot_id) << 24),
            ],
            true,
        )?;
        let entry = page(core::ptr::addr_of_mut!(DCBAA)) + 8 * u64::from(slot_id);
        unsafe { core::ptr::write_volatile(entry as *mut u64, 0) };
        Ok(())
    }

    /// Every root port: reported, its change bits cleared. The first port
    /// with a device connected.
    fn scan(&mut self, round: u32) -> Option<u8> {
        let mut first = None;
        let mut connected = 0;
        for port in 1..=self.layout.max_ports {
            let offset = self.portsc(port);
            let value = self.read32(offset);
            self.write32(
                offset,
                rules::portsc_neutral(value) | (value & rules::PORTSC_CHANGES),
            );
            if value & rules::PORTSC_CCS == 0 {
                continue;
            }
            connected += 1;
            first.get_or_insert(port);
            serial::write("XHCI PORT round=");
            serial::decimal(u64::from(round));
            serial::write(" port=");
            serial::decimal(u64::from(port));
            serial::write(" connected speed=");
            serial::write(rules::speed_name(rules::port_speed(value)));
            serial::write(" protocol=");
            serial::write(self.protocol(port));
            serial::write(if value & rules::PORTSC_PP != 0 {
                " power=1"
            } else {
                " power=0"
            });
            serial::write("\n");
        }
        serial::write("XHCI PORTS round=");
        serial::decimal(u64::from(round));
        serial::write(" connected=");
        serial::decimal(connected);
        serial::write("\n");
        first
    }

    fn protocol(&self, port: u8) -> &'static str {
        let within = |range: Option<(u8, u8)>| {
            range.is_some_and(|(first, count)| {
                port >= first && u16::from(port) < u16::from(first) + u16::from(count)
            })
        };
        if within(self.ports.usb3) {
            "usb3"
        } else if within(self.ports.usb2) {
            "usb2"
        } else {
            "unknown"
        }
    }

    /// Waits for `port` (or any port, if `None`) to reach `connected`,
    /// consuming port-change events meanwhile.
    fn await_port(&mut self, port: Option<u8>, connected: bool) -> Result<u8, XhciError> {
        let start = ticks();
        loop {
            self.drain()?;
            for candidate in 1..=self.layout.max_ports {
                if port.is_some_and(|port| port != candidate) {
                    continue;
                }
                let offset = self.portsc(candidate);
                let value = self.read32(offset);
                if (value & rules::PORTSC_CCS != 0) == connected {
                    self.write32(
                        offset,
                        rules::portsc_neutral(value) | (value & rules::PORTSC_CHANGES),
                    );
                    return Ok(candidate);
                }
            }
            if ticks().wrapping_sub(start) > HOTPLUG_TICKS {
                return Err(XhciError::Timeout(if connected {
                    "attach"
                } else {
                    "detach"
                }));
            }
            wait_tick();
        }
    }

    fn round(&mut self, round: u32, plan: Plan) -> Result<(), XhciError> {
        self.round = round;
        if let Err(error) = self.start(plan.fault) {
            if matches!(self.pool.state(), PoolState::Prepared { .. }) {
                // Prepared but never installed: the controller was never
                // given DCBAAP with it, so it comes back at once.
                zero(core::ptr::addr_of_mut!(SCRATCHPAD_ARRAY));
                self.pool.abandon().expect("prepared pool");
                serial::write("XHCI SCRATCHPAD ABANDONED state=prepared\n");
            }
            return Err(error);
        }
        line("XHCI RUNNING round=", round, "");
        if self.observe {
            self.observed(round);
        }
        if plan.fault == Fault::EarlyReclaim {
            serial::write("XHCI FAULT INJECTED early-reclaim\n");
            let seen = self.quiescence(false);
            match self.pool.reclaim(seen) {
                Err(PoolError::Live(seen)) => {
                    serial::write("XHCI SCRATCHPAD RECLAIM REFUSED state=installed halted=");
                    serial::decimal(u64::from(seen.halted));
                    serial::write(" bus_master=");
                    serial::decimal(u64::from(seen.bus_master));
                    serial::write("\n");
                }
                Ok(()) => serial::write("XHCI SCRATCHPAD RECLAIMED WHILE RUNNING\n"),
                Err(other) => {
                    serial::write("XHCI SCRATCHPAD RECLAIM ");
                    let _ = write!(serial::Serial, "{other:?}");
                    serial::write("\n");
                }
            }
        }
        let noop = [0, 0, 0, rules::control(rules::TRB_NOOP_COMMAND)];
        match plan.fault {
            Fault::CommandTimeout => {
                serial::write("XHCI FAULT INJECTED command-timeout\n");
                self.command(noop, false)?;
            }
            Fault::ForeignEvent => {
                let link = page(core::ptr::addr_of_mut!(COMMAND_RING))
                    + self.command.link_index() as u64 * rules::TRB_BYTES;
                serial::write("XHCI FAULT INJECTED foreign-event\n");
                self.drain()?;
                self.substitute = Some([
                    link as u32,
                    (link >> 32) as u32,
                    u32::from(rules::COMPLETION_SUCCESS) << 24,
                    rules::control(rules::EVENT_COMMAND_COMPLETION),
                ]);
                self.command(noop, true)?;
            }
            Fault::MalformedEvent => {
                serial::write("XHCI FAULT INJECTED malformed-event\n");
                self.drain()?;
                self.substitute = Some([0, 0, 0, rules::control(rules::TRB_NORMAL)]);
                self.command(noop, true)?;
            }
            _ => {}
        }
        for _ in 0..NOOPS {
            self.command(noop, true)?;
        }
        serial::write("XHCI COMMAND RING OK round=");
        serial::decimal(u64::from(round));
        serial::write(" noops=");
        serial::decimal(u64::from(NOOPS));
        serial::write(" command_ring_wraps=");
        serial::decimal(self.command.wraps());
        serial::write(" event_ring_wraps=");
        serial::decimal(self.events.wraps());
        serial::write("\n");
        if plan.fault == Fault::StaleEvent {
            serial::write("XHCI FAULT INJECTED stale-event\n");
            self.drain()?;
            let stale = self.last_command;
            self.substitute = Some([
                stale as u32,
                (stale >> 32) as u32,
                u32::from(rules::COMPLETION_SUCCESS) << 24,
                rules::control(rules::EVENT_COMMAND_COMPLETION),
            ]);
            self.command(noop, true)?;
        }
        if plan.fault == Fault::BadSlot {
            // Address Device for a slot never enabled: the controller's own
            // refusal, which must not disturb what follows.
            let input = page(core::ptr::addr_of_mut!(INPUT_CONTEXT));
            match self.command(
                [
                    input as u32,
                    (input >> 32) as u32,
                    0,
                    rules::control(rules::TRB_ADDRESS_DEVICE)
                        | (u32::from(SLOTS_ENABLED + 1) << 24),
                ],
                true,
            ) {
                Err(XhciError::Command { code, .. }) => {
                    serial::write("XHCI BAD SLOT REFUSED code=");
                    serial::write(rules::completion_name(code));
                    serial::write("(");
                    serial::decimal(u64::from(code));
                    serial::write(")\n");
                }
                Ok(_) => serial::write("XHCI BAD SLOT ACCEPTED\n"),
                Err(other) => return Err(other),
            }
        }
        let Some(port) = self.scan(round) else {
            line("XHCI NO DEVICE round=", round, "");
            return Ok(());
        };
        let (slot_id, _) = self.enumerated(round, port)?;
        if plan.hotplug {
            line("XHCI AWAIT DETACH port=", u32::from(port), "");
            let port = self.await_port(Some(port), false)?;
            line("XHCI DETACHED port=", u32::from(port), "");
            self.disable_slot(slot_id)?;
            line("XHCI AWAIT ATTACH round=", round, "");
            let port = self.await_port(None, true)?;
            line("XHCI ATTACHED port=", u32::from(port), "");
            let (slot_id, _) = self.enumerated(round, port)?;
            self.disable_slot(slot_id)?;
        } else {
            self.disable_slot(slot_id)?;
        }
        Ok(())
    }

    /// Qualification only: names the controller's structures and keeps it
    /// running long enough for the host to pause the guest and read them
    /// (scripts/xhci-observe.py), from the device's own DCBAAP onwards.
    fn observed(&mut self, round: u32) {
        serial::write("XHCI OBSERVE READY round=");
        serial::decimal(u64::from(round));
        serial::write(" bar=");
        serial::hex(self.bar);
        serial::write(" operational=");
        serial::hex(self.layout.operational);
        serial::write(" scratchpads=");
        serial::decimal(u64::from(self.scratchpads));
        serial::write("\n");
        let start = ticks();
        while ticks().wrapping_sub(start) <= OBSERVE_TICKS {
            wait_tick();
        }
        line("XHCI OBSERVE DONE round=", round, "");
    }

    fn enumerated(&mut self, round: u32, port: u8) -> Result<(u8, DeviceDescriptor), XhciError> {
        let (slot_id, address, descriptor) = self.enumerate(port)?;
        serial::write("XHCI DEVICE round=");
        serial::decimal(u64::from(round));
        serial::write(" port=");
        serial::decimal(u64::from(port));
        serial::write(" slot=");
        serial::decimal(u64::from(slot_id));
        serial::write(" address=");
        serial::decimal(u64::from(address));
        serial::write(" usb=");
        serial::hex_digits(u64::from(descriptor.usb), 4);
        serial::write(" class=");
        serial::hex_digits(u64::from(descriptor.class), 2);
        serial::write(" vendor=");
        serial::hex_digits(u64::from(descriptor.vendor), 4);
        serial::write(" product=");
        serial::hex_digits(u64::from(descriptor.product), 4);
        serial::write(" max_packet0=");
        serial::decimal(u64::from(descriptor.max_packet0));
        serial::write(" configurations=");
        serial::decimal(u64::from(descriptor.configurations));
        serial::write("\n");
        serial::write("XHCI EP0 OK round=");
        serial::decimal(u64::from(round));
        serial::write(" reads=");
        serial::decimal(u64::from(REREADS) + 2);
        serial::write(" transfer_ring_wraps=");
        serial::decimal(self.ep0.wraps());
        serial::write("\n");
        Ok((slot_id, descriptor))
    }
}

fn line(prefix: &str, value: u32, suffix: &str) {
    serial::write(prefix);
    serial::decimal(u64::from(value));
    serial::write(suffix);
    serial::write("\n");
}

fn report(prefix: &str, error: XhciError) {
    serial::write(prefix);
    let _ = write!(serial::Serial, "{error:?}");
    serial::write("\n");
}

/// The handoff's view of the legacy registers (real, or the model's).
struct Legacy<'a> {
    controller: &'a Controller,
    offset: u64,
}

impl LegacyAccess for Legacy<'_> {
    fn read_legsup(&mut self) -> u32 {
        self.controller.read32(self.offset)
    }
    fn request_os(&mut self) {
        self.controller.write8(self.offset + 3, 1);
    }
    fn withdraw_os(&mut self) {
        self.controller.write8(self.offset + 3, 0);
    }
    fn read_control(&mut self) -> u32 {
        self.controller.read32(self.offset + 4)
    }
    fn write_control(&mut self, value: u32) {
        self.controller.write32(self.offset + 4, value);
    }
    fn now(&mut self) -> u64 {
        ticks()
    }
    fn pause(&mut self) {
        wait_tick();
    }
}

/// The walk's view of the extended capabilities. Every header is reported.
/// With the firmware model, the last device capability's Next pointer is
/// redirected (as read) to the model's capability.
struct Space<'a>(&'a Controller);

impl CapabilitySpace for Space<'_> {
    fn header(&mut self, offset: u64) -> u32 {
        let controller = self.0;
        controller.record_extended(offset, 4);
        let mut value = controller.read32(offset);
        let mut source = " source=device";
        if let Some(mut model) = controller.model.get() {
            let modeled =
                offset == model.offset || (model.duplicate() && offset == model.offset + 16);
            if modeled {
                source = " source=model";
            } else if !model.spliced && offset < model.offset && (value >> 8) & 0xff == 0 {
                let gap = (model.offset - offset) / 4;
                if gap <= 0xff {
                    value |= (gap as u32) << 8;
                    model.spliced = true;
                    controller.model.set(Some(model));
                    source = " source=device next=substituted";
                }
            }
        }
        serial::write("XHCI EXTCAP offset=");
        serial::hex_digits(offset, 4);
        serial::write(" id=");
        serial::decimal(u64::from(value & 0xff));
        serial::write(" header=");
        serial::hex_digits(u64::from(value), 8);
        serial::write(source);
        serial::write("\n");
        value
    }

    fn word(&mut self, offset: u64) -> u32 {
        self.0.record_extended(offset, 4);
        self.0.read32(offset)
    }
}

/// Why `probe` did not return a controller, and what was done about it.
struct Failure {
    error: XhciError,
    /// The claimed function (None: never claimed).
    function: Option<pci::Function>,
    custody: Custody,
    /// USBCMD when the controller was left, if its registers were usable.
    usbcmd: Option<u32>,
    model: Option<Firmware>,
    /// USBLEGSUP and USBLEGCTLSTS as left, after any withdrawal.
    legacy: Option<(u32, u32)>,
    /// ABSD turned memory decoding on; a preserving refusal turns it off.
    restore_decode: bool,
}

impl Failure {
    fn unclaimed(error: XhciError) -> Self {
        Self {
            error,
            function: None,
            custody: Custody::Preserved("unclaimed"),
            usbcmd: None,
            model: None,
            legacy: None,
            restore_decode: false,
        }
    }
}

/// Finds, claims, sizes and maps the controller, checks its register
/// layout, walks its extended capabilities, settles ownership, and checks
/// its requirements. Until ownership is settled it only reads (BAR sizing
/// aside, restored as found); a refusal then leaves the controller as
/// found. Once ABSD owns it, a refusal halts it (bounded) and takes it off
/// the bus.
// Called once per boot; a larger error value costs nothing that matters here.
#[allow(clippy::result_large_err)]
fn probe(plan: Plan) -> Result<Controller, Failure> {
    let fault = plan.fault;
    let function = pci::find(CLASS_SERIAL_BUS, SUBCLASS_USB, INTERFACE_XHCI)
        .ok_or(Failure::unclaimed(XhciError::Absent))?;
    pci::claim(function, "xhci")
        .map_err(|error| Failure::unclaimed(XhciError::Refused(Refusal::Claim(error))))?;
    serial::write("XHCI CLAIMED pci_command=");
    serial::hex_digits(u64::from(pci::command(function)), 4);
    serial::write("\n");
    // Until ownership is known, a refusal changes nothing (memory decode,
    // if ABSD had to turn it on to read, is turned off again).
    let decode_by_absd = Cell::new(false);
    let preserve = |error, usbcmd, model: Option<Firmware>| Failure {
        error,
        function: Some(function),
        custody: Custody::Preserved("indeterminate"),
        usbcmd,
        model,
        legacy: None,
        restore_decode: decode_by_absd.get(),
    };
    let bar = pci::memory_bar0(function)
        .map_err(|error| preserve(XhciError::Refused(Refusal::Bar(error)), None, None))?;
    let mut bar_bytes = pci::memory_bar_size(function, 0)
        .map_err(|error| preserve(XhciError::Refused(Refusal::Bar(error)), None, None))?;
    if fault == Fault::BarBounds {
        bar_bytes = 0x40;
    }
    // Registers are readable only with memory decoding on. Firmware that
    // drives the controller has it on already; turning it on otherwise
    // changes nothing firmware can be using, and a preserving refusal
    // turns it off again.
    if !pci::memory_enabled(function) {
        pci::enable_memory_decode(function);
        decode_by_absd.set(true);
    }
    let registers = mmio::map(bar, bar_bytes, mmio::Cache::Uncached)
        .map_err(|error| preserve(XhciError::Refused(Refusal::Map { error, bar }), None, None))?;
    let read = |offset: u64| {
        assert!(offset + 4 <= bar_bytes);
        unsafe { core::ptr::read_volatile((registers + offset) as *const u32) }
    };
    let layout = rules::layout(
        read(CAP_CAPLENGTH) as u8,
        read(CAP_HCSPARAMS1),
        read(CAP_HCCPARAMS1),
        read(CAP_DBOFF),
        read(CAP_RTSOFF),
        bar_bytes,
    )
    .map_err(|error| preserve(XhciError::Refused(Refusal::Layout(error)), None, None))?;
    let device_hcsparams2 = read(CAP_HCSPARAMS2);
    let hcsparams2 = match plan.scratchpads {
        Some(count) => {
            let count = count.min(scratch::COUNT_LIMIT);
            (device_hcsparams2 & !((0x1f << 21) | (0x1f << 27)))
                | ((count >> 5) << 21)
                | ((count & 0x1f) << 27)
        }
        None => device_hcsparams2,
    };
    let model = plan.firmware.map(|behaviour| {
        let offset = layout.operational + OP_MODEL;
        assert!(offset + 24 <= layout.operational + 0x400 && offset + 24 <= bar_bytes);
        Model {
            firmware: Firmware::new(behaviour),
            offset,
            spliced: false,
        }
    });
    let mut controller = Controller {
        function,
        bar,
        registers,
        layout,
        interrupt: None,
        extended_reads: Cell::new((0, 0)),
        ports: Ports::default(),
        legacy: None,
        model: Cell::new(model),
        scratchpads: scratch::count(hcsparams2),
        pool: Pool::new(scratch::POOL_PAGES as u32),
        pagesize: plan.pagesize,
        armed_this_round: false,
        round: 0,
        observe: plan.observe,
        command: Producer::new(COMMAND_RING_TRBS),
        events: Consumer::new(EVENT_RING_TRBS),
        ep0: Producer::new(TRANSFER_RING_TRBS),
        failed: false,
        substitute: None,
        fault,
        short: None,
        last_command: 0,
        commands: 0,
        transfers: 0,
        events_seen: 0,
        port_events: 0,
    };
    let usbcmd = |c: &Controller| c.read32(c.operational(OP_USBCMD));
    let firmware = |c: &Controller| c.model.get().map(|model| model.firmware);
    serial::write("XHCI FOUND usbcmd=");
    serial::hex_digits(u64::from(usbcmd(&controller)), 8);
    serial::write(" usbsts=");
    serial::hex_digits(u64::from(controller.status()), 8);
    serial::write(" pci_command=");
    serial::hex_digits(u64::from(pci::command(function)), 4);
    serial::write("\n");
    serial::write("XHCI SCRATCHPADS required=");
    serial::decimal(u64::from(controller.scratchpads));
    serial::write(if scratch::restore(hcsparams2) {
        " spr=1"
    } else {
        " spr=0"
    });
    serial::write(" hcsparams2=");
    serial::hex_digits(u64::from(hcsparams2), 8);
    serial::write(" device_hcsparams2=");
    serial::hex_digits(u64::from(device_hcsparams2), 8);
    serial::write(if plan.scratchpads.is_some() {
        " source=substituted\n"
    } else {
        " source=device\n"
    });

    let found = legacy::walk(
        &mut Space(&controller),
        layout.extended,
        layout.bar_bytes,
        layout.max_ports,
    )
    .map_err(|error| {
        preserve(
            XhciError::Refused(Refusal::Capabilities(error)),
            Some(usbcmd(&controller)),
            firmware(&controller),
        )
    })?;
    controller.legacy = found.legacy;
    if let Some(offset) = found.legacy {
        controller.record_extended(offset, 8);
    }
    controller.ports = Ports {
        usb2: found.usb2,
        usb3: found.usb3,
    };
    match found.legacy {
        None => serial::write("XHCI OWNERSHIP os-default legacy_capability=none\n"),
        Some(offset) => {
            serial::write("XHCI LEGACY offset=");
            serial::hex_digits(offset, 4);
            serial::write(" legsup=");
            serial::hex_digits(u64::from(controller.read32(offset)), 8);
            serial::write(" control=");
            serial::hex_digits(u64::from(controller.read32(offset + 4)), 8);
            serial::write("\n");
            let start = ticks();
            let outcome = legacy::handoff(
                &mut Legacy {
                    controller: &controller,
                    offset,
                },
                HANDOFF_TICKS,
            );
            match outcome {
                Ok(done) => {
                    serial::write("XHCI OWNERSHIP CONFIRMED requested=");
                    serial::decimal(u64::from(done.requested));
                    serial::write(" waited_ticks=");
                    serial::decimal(done.waited);
                    serial::write(" initial=");
                    serial::hex_digits(u64::from(done.initial), 8);
                    serial::write(" smi_before=");
                    serial::hex_digits(u64::from(done.smi_before), 8);
                    serial::write(" smi_after=");
                    serial::hex_digits(u64::from(done.smi_after), 8);
                    serial::write("\n");
                }
                Err(error) if error.absd_owns() => {
                    return Err(release(
                        &mut controller,
                        XhciError::Refused(Refusal::Handoff(error)),
                    ));
                }
                Err(error) => {
                    serial::write("XHCI OWNERSHIP NOT ESTABLISHED elapsed_ticks=");
                    serial::decimal(ticks().wrapping_sub(start));
                    serial::write("\n");
                    // The handoff has withdrawn any request of ABSD's; what
                    // the semaphores say now decides the custody label.
                    let after = (controller.read32(offset), controller.read32(offset + 4));
                    return Err(Failure {
                        custody: Custody::Preserved(legacy::custody(error, after.0)),
                        legacy: Some(after),
                        ..preserve(
                            XhciError::Refused(Refusal::Handoff(error)),
                            Some(usbcmd(&controller)),
                            firmware(&controller),
                        )
                    });
                }
            }
        }
    }
    // ABSD owns the controller from here on.
    controller.mask_intx();
    if let Some(content) = found.content {
        return Err(release(
            &mut controller,
            XhciError::Refused(match content {
                ContentRefusal::PortRange { first, count } => Refusal::PortRange { first, count },
                ContentRefusal::ProtocolSpeeds { major } => Refusal::ProtocolSpeeds { major },
            }),
        ));
    }
    if controller.scratchpads > scratch::POOL_PAGES as u32 {
        let error = PoolError::Exhausted {
            required: controller.scratchpads,
            limit: scratch::POOL_PAGES as u32,
        };
        return Err(release(
            &mut controller,
            XhciError::Refused(Refusal::Scratchpads(error)),
        ));
    }
    let owned = owned_range();
    for (index, which) in pages().iter().enumerate() {
        if let Err(error) = scratch::check_page(
            0x100 + index as u32,
            page(*which),
            4096,
            4096,
            owned,
            layout.addresses_64,
        ) {
            return Err(release(
                &mut controller,
                XhciError::Refused(Refusal::Address(error)),
            ));
        }
    }
    if plan.interrupts {
        controller
            .ownership_holds()
            .map_err(|error| release(&mut controller, error))?;
        let route = xhci_interrupt::Route::prepare(
            function,
            registers,
            layout,
            read(CAP_HCSPARAMS1),
            controller.extended_reads.get(),
        );
        controller.interrupt =
            Some(route.map_err(|error| release(&mut controller, XhciError::Interrupt(error)))?);
    }
    Ok(controller)
}

/// A refusal of a controller ABSD owns: halted (bounded) and off the bus.
fn release(controller: &mut Controller, error: XhciError) -> Failure {
    if let Err(lost) = controller.ownership_holds() {
        return abandon_failure(controller, lost);
    }
    if !controller.halted() {
        controller.halt();
    }
    if let Err(lost) = controller.ownership_holds() {
        return abandon_failure(controller, lost);
    }
    controller.bus_master_off();
    Failure {
        error,
        function: Some(controller.function),
        custody: Custody::Released,
        usbcmd: Some(controller.read32(controller.operational(OP_USBCMD))),
        model: controller.model.get().map(|model| model.firmware),
        legacy: None,
        restore_decode: false,
    }
}

fn abandon_failure(controller: &mut Controller, error: XhciError) -> Failure {
    xhci_interrupt::STATE.retire();
    controller.pool.quarantine();
    Failure {
        error,
        function: Some(controller.function),
        custody: Custody::Abandoned,
        usbcmd: Some(controller.read32(controller.operational(OP_USBCMD))),
        model: controller.model.get().map(|model| model.firmware),
        legacy: None,
        restore_decode: false,
    }
}

fn report_abandoned(function: pci::Function, usbcmd: Option<u32>) {
    serial::write("XHCI ABANDONED owner=ownership-lost usbcmd=");
    if let Some(command) = usbcmd {
        serial::hex_digits(u64::from(command), 8);
    } else {
        serial::write("unread");
    }
    serial::write(" pci_command=");
    serial::hex_digits(u64::from(pci::command(function)), 4);
    serial::write(if pci::bus_master(function) {
        " bus_master=1 statics=reserved\n"
    } else {
        " bus_master=0 statics=reserved\n"
    });
}

/// A controller ABSD did not take: its command register and USBCMD as
/// left, which must equal what was found.
fn report_preserved(
    function: pci::Function,
    owner: &str,
    usbcmd: Option<u32>,
    legacy: Option<(u32, u32)>,
) {
    serial::write("XHCI PRESERVED owner=");
    serial::write(owner);
    serial::write(" usbcmd=");
    match usbcmd {
        Some(value) => serial::hex_digits(u64::from(value), 8),
        None => serial::write("unread"),
    }
    serial::write(" pci_command=");
    serial::hex_digits(u64::from(pci::command(function)), 4);
    serial::write(if pci::bus_master(function) {
        " bus_master=1"
    } else {
        " bus_master=0"
    });
    if let Some((legsup, control)) = legacy {
        serial::write(" legsup=");
        serial::hex_digits(u64::from(legsup), 8);
        serial::write(" legctlsts=");
        serial::hex_digits(u64::from(control), 8);
    }
    serial::write("\n");
}

/// Qualification only: what the firmware model saw.
fn report_model(model: Option<Firmware>) {
    let Some(firmware) = model else {
        return;
    };
    let (legsup, control) = firmware.registers();
    serial::write("XHCI FIRMWARE MODEL behaviour=");
    let _ = write!(serial::Serial, "{:?}", firmware.behaviour);
    serial::write(" violations=");
    serial::decimal(u64::from(firmware.violations));
    serial::write(" legsup=");
    serial::hex_digits(u64::from(legsup), 8);
    serial::write(" control=");
    serial::hex_digits(u64::from(control), 8);
    serial::write(" requests=");
    serial::decimal(u64::from(firmware.requests));
    serial::write(" withdrawals=");
    serial::decimal(u64::from(firmware.withdrawals));
    serial::write("\n");
    if let Some((what, offset)) = firmware.first_violation {
        serial::write("XHCI FIRMWARE MODEL VIOLATION first=");
        serial::write(what);
        serial::write(" offset=");
        serial::hex_digits(offset, 4);
        serial::write("\n");
    }
}

/// Reports the function's command register after the bring-up let go of
/// it: whether it can still master the bus.
fn report_dma(function: pci::Function) {
    serial::write(if pci::bus_master(function) {
        "XHCI DMA ON bus_master=1 command="
    } else {
        "XHCI DMA OFF bus_master=0 command="
    });
    serial::hex_digits(u64::from(pci::command(function)), 4);
    serial::write("\n");
}

/// The `xhci-probe` boot's bring-up: probe, then `plan.rounds` rounds of
/// reset, start, command-ring exercise, port scan and (with a device)
/// enumeration, each ending halted. Reports everything on the serial
/// console and returns; the boot goes on whatever happened.
pub fn qualify(plan: Plan) {
    crate::kernel_lock::assert_bsp_device_access();
    assert!(!crate::kernel_lock::active());
    let mut controller = match probe(plan) {
        Ok(controller) => controller,
        Err(failure) => {
            report("XHCI UNAVAILABLE ", failure.error);
            if let Some(function) = failure.function {
                match failure.custody {
                    Custody::Released => report_dma(function),
                    Custody::Abandoned => report_abandoned(function, failure.usbcmd),
                    Custody::Preserved(owner) => {
                        if failure.restore_decode {
                            pci::disable_memory_decode(function);
                            serial::write("XHCI MEMORY DECODE RESTORED off\n");
                        }
                        report_preserved(function, owner, failure.usbcmd, failure.legacy)
                    }
                }
            }
            report_model(failure.model);
            return;
        }
    };
    let function = controller.function;
    let (vendor, device) = pci::ids(function);
    let version = controller.read32(0) >> 16;
    serial::write("XHCI CONTROLLER pci=");
    serial::hex_digits(u64::from(function.bus), 2);
    serial::write(":");
    serial::hex_digits(u64::from(function.device), 2);
    serial::write(".");
    serial::hex_digits(u64::from(function.function), 1);
    serial::write(" vendor=");
    serial::hex_digits(u64::from(vendor), 4);
    serial::write(" device=");
    serial::hex_digits(u64::from(device), 4);
    serial::write(" version=");
    serial::hex_digits(u64::from(version), 4);
    serial::write(" bar_bytes=");
    serial::decimal(controller.layout.bar_bytes);
    serial::write(" slots=");
    serial::decimal(u64::from(controller.layout.max_slots));
    serial::write(" ports=");
    serial::decimal(u64::from(controller.layout.max_ports));
    serial::write(" context_bytes=");
    serial::decimal(controller.layout.context_bytes);
    serial::write(if controller.layout.port_power_control {
        " ppc=1"
    } else {
        " ppc=0"
    });
    serial::write("\n");
    for (name, range) in [
        ("usb2", controller.ports.usb2),
        ("usb3", controller.ports.usb3),
    ] {
        if let Some((first, count)) = range {
            serial::write("XHCI PROTOCOL ");
            serial::write(name);
            serial::write(" ports=");
            serial::decimal(u64::from(first));
            serial::write("-");
            serial::decimal(u64::from(first) + u64::from(count) - 1);
            serial::write("\n");
        }
    }
    // What the controller looked like when the kernel took it over (left
    // running or halted by firmware, or fresh from QEMU's reset).
    serial::write("XHCI HANDOFF usbcmd=");
    serial::hex_digits(
        u64::from(controller.read32(controller.operational(OP_USBCMD))),
        8,
    );
    serial::write(" usbsts=");
    serial::hex_digits(u64::from(controller.status()), 8);
    serial::write(" pci_command=");
    serial::hex_digits(u64::from(pci::command(function)), 4);
    serial::write("\n");
    match pci::claim(function, "xhci-second") {
        Err(pci::ClaimError::Owned(owner)) => {
            serial::write("XHCI SECOND CLAIM REFUSED owner=");
            serial::write(owner);
            serial::write("\n");
        }
        other => {
            serial::write("XHCI SECOND CLAIM NOT REFUSED ");
            let _ = write!(serial::Serial, "{other:?}");
            serial::write("\n");
        }
    }
    for round in 1..=plan.rounds {
        let mut result = controller.round(round, plan);
        let late_before = xhci_interrupt::STATE.snapshot().late;
        if result.is_ok() && plan.interrupts && plan.fault == Fault::LateMsi {
            result = controller.post_late_msi();
        }
        let halted = if matches!(result, Err(XhciError::OwnershipLost(_))) {
            false
        } else if plan.interrupts {
            match controller.shutdown_interrupts() {
                Ok(halted) => halted,
                Err(error) => {
                    controller.pool.quarantine();
                    result = Err(error);
                    false
                }
            }
        } else {
            controller.halt()
        };
        if plan.interrupts
            && plan.fault == Fault::LateMsi
            && result.is_ok()
            && xhci_interrupt::STATE.snapshot().late <= late_before
        {
            result = Err(XhciError::Interrupt(xhci_irq::Error::Drain));
        }
        if let Err(error @ XhciError::OwnershipLost(_)) = result {
            xhci_interrupt::STATE.retire();
            // Firmware has the controller again: ABSD changes nothing more,
            // and pages the controller may have been given stay untouched.
            serial::write("XHCI FAILED round=");
            serial::decimal(u64::from(round));
            report(" error=", error);
            if controller.scratchpads != 0 {
                // Installed pages are never written again this boot; pages
                // the controller was never given stay free.
                controller.pool.quarantine();
                serial::write("XHCI SCRATCHPAD STATE ");
                let _ = write!(serial::Serial, "{:?}", controller.pool.state());
                serial::write("\n");
            }
            // Not a preservation: ABSD may already have reset the controller,
            // enabled bus mastering and pointed DCBAAP, CRCR and ERSTBA at its
            // statics. Firmware owns it again, so ABSD changes nothing, and
            // every xHCI static (rings, contexts, DCBAA, array, pool) stays
            // reserved for this boot.
            serial::write("XHCI ABANDONED owner=firmware-reacquired usbcmd=");
            serial::hex_digits(
                u64::from(controller.read32(controller.operational(OP_USBCMD))),
                8,
            );
            serial::write(" pci_command=");
            serial::hex_digits(u64::from(pci::command(function)), 4);
            serial::write(if pci::bus_master(function) {
                " bus_master=1 statics=reserved\n"
            } else {
                " bus_master=0 statics=reserved\n"
            });
            report_model(controller.model.get().map(|model| model.firmware));
            return;
        }
        match result {
            Ok(()) => line("XHCI ROUND OK round=", round, ""),
            Err(error) => {
                serial::write("XHCI FAILED round=");
                serial::decimal(u64::from(round));
                report(" error=", error);
            }
        }
        serial::write("XHCI HALTED round=");
        serial::decimal(u64::from(round));
        serial::write(if halted { " halted=yes" } else { " halted=no" });
        serial::write(" commands=");
        serial::decimal(controller.commands);
        serial::write(" transfers=");
        serial::decimal(controller.transfers);
        serial::write(" events=");
        serial::decimal(controller.events_seen);
        serial::write(" port_events=");
        serial::decimal(controller.port_events);
        serial::write("\n");
        // Only a refusal of the controller's requirements made before the
        // round armed it is contained; a timeout (CNR, halt, HCRST) is not.
        let contained = matches!(
            result,
            Err(XhciError::Refused(
                Refusal::PageSize(_)
                    | Refusal::PageSizes(_)
                    | Refusal::Scratchpads(_)
                    | Refusal::Address(_)
            ))
        ) && halted
            && !controller.armed_this_round
            && controller.pool.state() == PoolState::Free;
        if contained && round < plan.rounds {
            // Failed before this round enabled bus mastering or installed
            // anything, and halted: the next round starts from reset.
            line("XHCI ROUND CONTAINED round=", round, "");
            continue;
        }
        if result.is_err() || !halted {
            // Fail closed: no further round touches this controller, and it
            // is taken off the bus (the only stop left if it did not halt).
            serial::write("XHCI STOPPED\n");
            if !plan.interrupts {
                if let Err(lost) = controller.ownership_holds() {
                    report("XHCI FAILED shutdown error=", lost);
                    let _ = abandon_failure(&mut controller, lost);
                    report_abandoned(
                        function,
                        Some(controller.read32(controller.operational(OP_USBCMD))),
                    );
                    report_model(controller.model.get().map(|model| model.firmware));
                    return;
                }
                controller.bus_master_off();
            }
            controller.release_scratchpads(false);
            report_dma(function);
            report_model(controller.model.get().map(|model| model.firmware));
            if plan.interrupts {
                controller.irq_quiet();
            }
            return;
        }
    }
    if !plan.interrupts {
        line("XHCI DONE rounds=", plan.rounds, "");
    }
    if !plan.interrupts {
        if let Err(lost) = controller.ownership_holds() {
            report("XHCI FAILED shutdown error=", lost);
            let _ = abandon_failure(&mut controller, lost);
            report_abandoned(
                function,
                Some(controller.read32(controller.operational(OP_USBCMD))),
            );
            report_model(controller.model.get().map(|model| model.firmware));
            return;
        }
        controller.bus_master_off();
    }
    controller.release_scratchpads(false);
    report_dma(function);
    report_model(controller.model.get().map(|model| model.firmware));
    if plan.interrupts {
        if controller.irq_quiet() {
            line("XHCI DONE rounds=", plan.rounds, "");
        } else {
            report(
                "XHCI FAILED shutdown error=",
                XhciError::Interrupt(xhci_irq::Error::Drain),
            );
            serial::write("XHCI STOPPED\n");
        }
    }
}
