//! The first AMD-Vi domain on hardware (#111 increment 3): one translated
//! domain for one admitted PCI function, every other DeviceID blocked.
//! Encodings and decisions are `absd_kernel::amdvi` (host-tested); this file
//! writes them to memory and the unit's MMIO registers, in the order the
//! specification requires, and reports each step.
//!
//! Boot word `amdvi-enforce-test` (q35 + `amd-iommu` + `edu`): after ACPI
//! discovery reached its result line, the boot selects the `Enforced` DMA
//! profile, reads the unit's live registers, admits the table (deviations
//! only under a registered quirk, consumed fields agreeing with the live
//! EFR and capability header) and the `edu` function (alias-closure rule),
//! builds the device table (every entry valid; only `edu` translated), the
//! domain's page tables (granted pages only, IOVA = physical), a command
//! buffer and an event log, enables the unit, invalidates and waits for a
//! completion store whose value it reads back, and only then arms `edu`
//! through `dma::arm_contained`. It then checks itself (one permitted
//! transfer each way, one write the domain forbids) and reports the event
//! log. Nothing here runs in any other boot.
//!
//! #116 adds a second contained target, a QEMU NVMe; #123 alternatively the
//! AHCI controller at 00:07.0 when the boot names a disk (`ahci-disk=` or
//! `ahci-write=`), never both. With the AHCI target the enforce boot also
//! runs [`ahci_check`] and ends with the no-UART evidence line
//! (docs/hardware/NO-UART-EVIDENCE.md).
//!
//! MMIO registers (§3.4): 0000h device table base, 0008h command buffer
//! base, 0010h event log base, 0018h control, 0030h EFR, 2000h/2008h command
//! head/tail, 2010h/2018h event head/tail, 2020h status.

use crate::pci::{self, Function};
use crate::serial::Serial;
use absd_kernel::ahci_command::{Completion, Selection};
use absd_kernel::amdvi::lifecycle::{
    self, Blocked, Claim, FaultRecord, Health, Observer, Reset, Revocation, Sets, StartRefusal,
};
use absd_kernel::amdvi::{
    self, DEVICE_TABLE_ENTRIES, DOMAIN, Event, PAGE, Perm, RING_ENTRIES, Step, Tables, acquire_live,
};
use absd_kernel::memory::FrameOwner;
use core::fmt::Write;

pub mod contain;

const DEVTAB_BASE: u64 = 0x0000;
const CMD_BASE: u64 = 0x0008;
const EVENT_BASE: u64 = 0x0010;
const CONTROL: u64 = 0x0018;
const CMD_HEAD: u64 = 0x2000;
const CMD_TAIL: u64 = 0x2008;
const EVENT_HEAD: u64 = 0x2010;
const EVENT_TAIL: u64 = 0x2018;
const STATUS: u64 = 0x2020;

const CONTROL_IOMMU_EN: u64 = 1;
const CONTROL_EVENT_LOG_EN: u64 = 1 << 2;
const CONTROL_CMD_BUF_EN: u64 = 1 << 12;
const CONTROL_COHERENT: u64 = 1 << 10;
const CONTROL_HT_TUN_EN: u64 = 1 << 1;
/// Capability Offset 00h bit 25: HtTunnel.
const CAP_HT_TUNNEL: u32 = 1 << 25;
const STATUS_EVENT_LOG_RUN: u64 = 1 << 3;
const STATUS_CMD_BUF_RUN: u64 = 1 << 4;
/// MMIO 016Ch bit 13 PerfOptEn (present when EFR PerfOptSup).
const PERF_OPT: u64 = 0x016c;
const PERF_OPT_EN: u32 = 1 << 13;
/// Control bits 21:18 (CRW) are read-only.
const CONTROL_READ_ONLY: u64 = 0xf << 18;
const EXCLUSION_BASE: u64 = 0x0020;
const EXCLUSION_LIMIT: u64 = 0x0028;
const STATUS_EVENT_OVERFLOW: u64 = 1;
const RING_BYTES: u64 = (RING_ENTRIES * 16) as u64;

/// QEMU `edu` (PCI 1234:11e8): BAR0 registers 80h DMA source, 88h
/// destination, 90h count, 98h command (bit 0 run, bit 1 direction:
/// 1 = device to RAM); internal buffer at 40000h, 4 KiB; DMA addresses are
/// masked to 28 bits, so every granted page lies below 256 MiB.
const EDU_IDS: (u16, u16) = (0x1234, 0x11e8);
const EDU_FUNCTION: Function = Function {
    bus: 0,
    device: 5,
    function: 0,
};
const EDU_SRC: u64 = 0x80;
const EDU_DST: u64 = 0x88;
const EDU_CNT: u64 = 0x90;
const EDU_CMD: u64 = 0x98;
const EDU_BUFFER: u64 = 0x40000;
const EDU_REACH: u64 = 1 << 28;
const WAIT_CYCLES: u64 = 1 << 35;

/// Proof that a domain is live for one function: made only by
/// [`enforce_test`] after the tables are written, the unit is enabled, and
/// the completion store that follows their invalidation has been read back.
pub struct Contained {
    devid: u16,
    domain: u16,
    function: Function,
}

impl Contained {
    pub fn devid(&self) -> u16 {
        self.devid
    }

    pub fn domain(&self) -> u16 {
        self.domain
    }

    pub fn function(&self) -> Function {
        self.function
    }
}

/// Which driver a contained device belongs to (#116: the edu target and,
/// in the two-device boot, the NVMe controller or, #123, the AHCI
/// controller at 00:07.0).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Edu,
    Nvme,
    Ahci,
}

/// Pages one buffer set may hold: the largest of the drivers' sets (edu 3,
/// NVMe 6, AHCI 4).
const MAX_PAGES: usize = if crate::nvme::DMA_PAGES > crate::ahci_block::DMA_PAGES {
    crate::nvme::DMA_PAGES
} else {
    crate::ahci_block::DMA_PAGES
};

/// The AHCI boot option, read by src/main.rs: `ahci-disk=SERIAL` or
/// `ahci-write=SERIAL` (#123), none, or a selection error.
pub type AhciSelection =
    Result<Option<Selection<'static>>, absd_kernel::ahci_command::SelectionError>;

/// One buffer set's pages, as granted (IOVA = physical).
#[derive(Clone, Copy)]
struct Grant {
    pages: [(u64, Perm); MAX_PAGES],
    len: usize,
}

impl Grant {
    fn of(pages: &[(u64, Perm)]) -> Grant {
        let mut grant = Grant {
            pages: [(0, Perm::READ); MAX_PAGES],
            len: pages.len().min(MAX_PAGES),
        };
        grant.pages[..grant.len].copy_from_slice(&pages[..grant.len]);
        grant
    }

    fn pages(&self) -> &[(u64, Perm)] {
        &self.pages[..self.len]
    }
}

/// Buffer set `set` of a device kind: the edu's static pages, the NVMe
/// driver's declared DMA surface (`nvme::dma_pages`), every page read and
/// write (queues, identify and bounce are each written by one side and
/// read by the other), or the AHCI backend's (`ahci_block::dma_pages`),
/// each page with its role's permission (`amdvi::AHCI_ROLES`).
fn device_set(kind: Kind, set: usize) -> Grant {
    match kind {
        Kind::Edu => Grant::of(&set_pages(set)),
        Kind::Ahci => {
            let pages = crate::ahci_block::dma_pages(set);
            let mut grant = Grant::of(&[]);
            for (at, &page) in pages.iter().enumerate() {
                grant.pages[at] = (page, amdvi::AHCI_ROLES[at].1);
            }
            grant.len = pages.len();
            grant
        }
        Kind::Nvme => {
            let pages = crate::nvme::dma_pages(set);
            let mut grant = Grant::of(&[]);
            for (at, &page) in pages.iter().enumerate() {
                grant.pages[at] = (page, Perm::READ_WRITE);
            }
            grant.len = pages.len();
            grant
        }
    }
}

/// QEMU NVMe: class 01h/08h/02h; the two-device boot's second target.
const NVME_CLASS: (u8, u8, u8) = (0x01, 0x08, 0x02);
/// AHCI: class 01h/06h/01h; the second target only at [`AHCI_FUNCTION`].
const AHCI_CLASS: (u8, u8, u8) = (0x01, 0x06, 0x01);
const AHCI_FUNCTION: Function = Function {
    bus: amdvi::AHCI_PIN.0,
    device: amdvi::AHCI_PIN.1,
    function: amdvi::AHCI_PIN.2,
};

#[repr(C, align(4096))]
struct Page([u8; 4096]);

/// The grant: the device may read `SOURCE` and write `TARGET` and
/// `SECOND`. `CANARY` and `CANARY2` are never granted, mapped for any
/// device, or otherwise used; `MAILBOX` is the oracle protocol's page.
static mut SOURCE: Page = Page([0; 4096]);
static mut TARGET: Page = Page([0; 4096]);
static mut SECOND: Page = Page([0; 4096]);
static mut CANARY: Page = Page([0; 4096]);
static mut CANARY2: Page = Page([0; 4096]);
static mut MAILBOX: Page = Page([0; 4096]);
/// Set 2 (DESIGN §4, N = 2): same shape as set 1, disjoint from it; mapped
/// only by a RESTART after a device revoke.
static mut SOURCE2: Page = Page([0; 4096]);
static mut TARGET2: Page = Page([0; 4096]);
static mut SECOND2: Page = Page([0; 4096]);

fn page_address(page: *const Page) -> u64 {
    page as u64
}

/// Page-table pages from the frame allocator (physical == virtual).
struct Frames;

impl Tables for Frames {
    fn allocate(&mut self) -> Option<u64> {
        let frames = unsafe { crate::vm::frames() };
        let frame = frames.allocate(FrameOwner::Kernel)?;
        let address = frame.start_address();
        unsafe { core::ptr::write_bytes(address as *mut u8, 0, PAGE as usize) };
        Some(address)
    }
    fn read(&self, table: u64, index: usize) -> u64 {
        unsafe { core::ptr::read_volatile((table as *const u64).add(index)) }
    }
    fn write(&mut self, table: u64, index: usize, value: u64) {
        unsafe { core::ptr::write_volatile((table as *mut u64).add(index), value) }
    }
}

struct Mmio(u64);

impl Mmio {
    fn read(&self, offset: u64) -> u64 {
        unsafe { core::ptr::read_volatile((self.0 + offset) as *const u64) }
    }
    fn write(&self, offset: u64, value: u64) {
        unsafe { core::ptr::write_volatile((self.0 + offset) as *mut u64, value) }
    }
    fn read32(&self, offset: u64) -> u32 {
        unsafe { core::ptr::read_volatile((self.0 + offset) as *const u32) }
    }
    fn write32(&self, offset: u64, value: u32) {
        unsafe { core::ptr::write_volatile((self.0 + offset) as *mut u32, value) }
    }
}

fn fence() {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    unsafe { core::arch::asm!("mfence", options(nostack, preserves_flags)) };
}

fn tsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

struct Rings {
    mmio: Mmio,
    command: u64,
    tail: u64,
    events: u64,
    head: u64,
    store: u64,
    sequence: u64,
    /// The data of the last COMPLETION_WAIT.
    last: u64,
}

impl Rings {
    fn submit(&mut self, command: [u32; 4]) {
        let slot = (self.command + self.tail) as *mut u32;
        for (index, word) in command.iter().enumerate() {
            unsafe { core::ptr::write_volatile(slot.add(index), *word) };
        }
        fence();
        self.tail = (self.tail + 16) % RING_BYTES;
        self.mmio.write(CMD_TAIL, self.tail);
    }

    /// COMPLETION_WAIT with a value unique to this call (and to the boot);
    /// true only when that exact value is read back from the store (bounded
    /// wait). The value is `self.last`.
    fn wait(&mut self, label: &str) -> bool {
        self.sequence += 1;
        let value = 0x4142_5344_0000_0000 | self.sequence;
        self.last = value;
        unsafe { core::ptr::write_volatile(self.store as *mut u64, 0) };
        fence();
        if !cfg!(absd_mutant_amdvi_skip_wait) {
            self.submit(amdvi::completion_wait(self.store, value));
        }
        let start = tsc();
        let observed = loop {
            let observed = unsafe { core::ptr::read_volatile(self.store as *const u64) };
            if observed == value || tsc().wrapping_sub(start) > WAIT_CYCLES {
                break observed;
            }
            core::hint::spin_loop();
        };
        if !label.is_empty() {
            let _ = writeln!(
                Serial,
                "AMDVI COMPLETION step={label} expected={value:#x} observed={observed:#x} result={}",
                if observed == value { "ok" } else { "timeout" }
            );
        }
        observed == value
    }

    /// The only reader of the Event Log Tail and of Status EventOverflow:
    /// [`amdvi::observe_log`] (its invariant). Returns the tail a drain may
    /// consume up to (none when the tail is invalid: unit failed, record
    /// incomplete) and Status EventOverflow as read.
    fn observe_log(&self, health: &mut Health, record: &mut FaultRecord) -> (Option<u64>, bool) {
        let raw_tail = self.mmio.read(EVENT_TAIL);
        let overflow = self.mmio.read(STATUS) & STATUS_EVENT_OVERFLOW != 0;
        let events = self.events;
        let tail = amdvi::observe_log(
            raw_tail,
            overflow,
            self.head,
            RING_BYTES,
            health,
            record,
            |at| {
                let word = unsafe { core::ptr::read_volatile((events + at + 4) as *const u32) };
                (word >> 28) as u8
            },
        );
        if tail.is_none() {
            let _ = writeln!(
                Serial,
                "AMDVI EVENT-LOG tail=invalid raw={raw_tail:#x} record=incomplete unit=failed"
            );
        }
        (tail, overflow)
    }

    /// Reports and consumes every event up to the observed tail (none past
    /// an invalid one); returns how many, and Status EventOverflow read
    /// after consuming (through the same entry point).
    fn drain(
        &mut self,
        health: &mut Health,
        record: &mut FaultRecord,
        report: &mut dyn FnMut(&Event, [u32; 4]),
    ) -> (usize, bool) {
        let (tail, overflow) = self.observe_log(health, record);
        let Some(tail) = tail else {
            return (0, overflow);
        };
        let mut count = 0;
        for _ in 0..RING_ENTRIES {
            if self.head == tail {
                break;
            }
            let slot = (self.events + self.head) as *const u32;
            let mut raw = [0u32; 4];
            for (index, word) in raw.iter_mut().enumerate() {
                *word = unsafe { core::ptr::read_volatile(slot.add(index)) };
            }
            let event = Event::decode(raw);
            report(&event, raw);
            count += 1;
            self.head = (self.head + 16) % RING_BYTES;
        }
        self.mmio.write(EVENT_HEAD, self.head);
        let (_, overflow) = self.observe_log(health, record);
        if overflow {
            crate::serial::write("AMDVI EVENT-LOG overflow=yes record=incomplete\n");
        }
        (count, overflow)
    }
}

/// One line per event, decoded per the specification, with the raw words
/// (QEMU 10.2.1's encoder departs from Figure 56: DeviceID without the bus,
/// address always 0, access type outside the RW bit; the raw words show
/// exactly what the unit wrote).
fn report_event(event: &Event, raw: [u32; 4], record: &FaultRecord) {
    let (observer, env) = (record.observer.word(), record.environment);
    let _ = match *event {
        Event::IoPageFault {
            devid,
            domain,
            address,
            write,
            permission,
            present,
            interrupt,
        } => writeln!(
            Serial,
            "AMDVI EVENT observer={observer} env={env} io-page-fault devid={} domain={domain} address={address:#x} rw={} pe={} pr={} i={} raw={:#010x}:{:#010x}:{:#010x}:{:#010x}",
            Id(devid),
            u8::from(write),
            u8::from(permission),
            u8::from(present),
            u8::from(interrupt),
            raw[0],
            raw[1],
            raw[2],
            raw[3]
        ),
        Event::IllegalDevTableEntry { devid, address } => writeln!(
            Serial,
            "AMDVI EVENT observer={observer} env={env} illegal-dev-table-entry devid={} address={address:#x} raw={:#010x}:{:#010x}:{:#010x}:{:#010x}",
            Id(devid),
            raw[0],
            raw[1],
            raw[2],
            raw[3]
        ),
        Event::Other { code, raw } => writeln!(
            Serial,
            "AMDVI EVENT observer={observer} env={env} code={code} devid={} flags={:#x} address={:#x} raw={:#010x}:{:#010x}:{:#010x}:{:#010x}",
            Id(raw[0] as u16),
            (raw[1] >> 16) & 0xfff,
            u64::from(raw[2]) | (u64::from(raw[3]) << 32),
            raw[0],
            raw[1],
            raw[2],
            raw[3]
        ),
    };
}

struct Id(u16);

impl core::fmt::Display for Id {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}.{}",
            self.0 >> 8,
            (self.0 >> 3) & 0x1f,
            self.0 & 7
        )
    }
}

fn devid(function: Function) -> u16 {
    (u16::from(function.bus) << 8)
        | (u16::from(function.device) << 3)
        | u16::from(function.function)
}

fn refuse(stage: &str, reason: core::fmt::Arguments<'_>) -> ! {
    let _ = writeln!(Serial, "AMDVI ENFORCE REFUSED stage={stage} {reason}");
    crate::serial::write("AMDVI ENFORCE FAILED\n");
    crate::exit_qemu(1)
}

/// The `edu` function's registers.
struct Edu(u64);

impl Edu {
    fn write(&self, offset: u64, value: u64) {
        unsafe { core::ptr::write_volatile((self.0 + offset) as *mut u64, value) }
    }
    fn read(&self, offset: u64) -> u64 {
        unsafe { core::ptr::read_volatile((self.0 + offset) as *const u64) }
    }

    /// One `edu` DMA: RAM `address` to the device buffer (`to_ram` false) or
    /// back. Returns whether the device finished within the bound.
    fn dma(&self, address: u64, bytes: u64, to_ram: bool) -> bool {
        if to_ram {
            self.write(EDU_SRC, EDU_BUFFER);
            self.write(EDU_DST, address);
        } else {
            self.write(EDU_SRC, address);
            self.write(EDU_DST, EDU_BUFFER);
        }
        self.write(EDU_CNT, bytes);
        self.write(EDU_CMD, 1 | (u64::from(to_ram) << 1));
        let start = tsc();
        while self.read(EDU_CMD) & 1 != 0 {
            if tsc().wrapping_sub(start) > WAIT_CYCLES {
                return false;
            }
            core::hint::spin_loop();
        }
        true
    }
}

/// One contained device and its domain. Before #116 these fields were the
/// session itself (abstraction leak L1: unit state and domain state were
/// one structure).
#[derive(Clone, Copy)]
struct Device {
    kind: Kind,
    owner: &'static str,
    target: u16,
    function: Function,
    domain: u16,
    root: u64,
    /// The device's interrupt remapping table (512 basic IRTEs): the edu's
    /// holds its one grant, the NVMe's is all zero (deny-all).
    ir_table: u64,
    grant: Grant,
    revoked: [bool; MAX_PAGES],
    /// The device is revoked (REVOKE_DEVICE since READY or since the last
    /// RESTART).
    device_revoked: bool,
    sets: Sets,
    /// The last device revocation (R1–R5).
    revocation: Option<Revocation>,
    /// ABSD has the device's Bus Master Enable set.
    armed: bool,
}

impl Device {
    fn contained(&self) -> Contained {
        Contained {
            devid: self.target,
            domain: self.domain,
            function: self.function,
        }
    }

    /// The DomainID whole-domain and page invalidations name. (Negative
    /// control: every invalidation names the edu's domain, the
    /// single-domain assumption the second device must not inherit.)
    fn invalidation_domain(&self) -> u16 {
        if cfg!(absd_mutant_amdvi_domain_constant) {
            DOMAIN
        } else {
            self.domain
        }
    }
}

/// The NVMe identity the two-device boot reports.
#[derive(Clone, Copy)]
struct NvmeFacts {
    namespace: u32,
    sectors: u64,
    ioqid: u16,
    qsize: u16,
}

/// The NVMe I/O completion queue's MSI-X vector in the oracle boot (#116
/// ADD-7); never unmasked by ABSD.
const NVME_IOCQ_VECTOR: u16 = 1;

/// The order of `nvme::dma_pages`, for the oracle's GRANT lines.
const NVME_ROLES: [&str; crate::nvme::DMA_PAGES] =
    ["asq", "acq", "iosq", "iocq", "identify", "bounce"];

/// The AHCI identity the two-device AHCI boot reports.
#[derive(Clone, Copy)]
struct AhciFacts {
    port: u8,
    sectors: u64,
}

fn ahci_facts_of(identity: &crate::ahci_block::Identity) -> AhciFacts {
    AhciFacts {
        port: identity.port,
        sectors: identity.sectors,
    }
}

/// Set by [`oracle`]: the oracle boot (the enforce-test boot is not).
static ORACLE_BOOT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn facts_of(identity: &crate::nvme::Identity) -> NvmeFacts {
    let (ioqid, qsize) = crate::nvme::io_queue().unwrap_or((0, 0));
    NvmeFacts {
        namespace: identity.namespace,
        sectors: identity.sectors,
        ioqid,
        qsize,
    }
}

/// The oracle boot only (#116 ADD-7): MSI-X on the NVMe enabled with its
/// function mask set, before the controller is enabled, so the I/O CQ can
/// be created with interrupts on a stated vector while the driver polls.
/// Configuration writes to the MSI-X capability only; read back.
fn nvme_msix_masked(function: Function) -> bool {
    if !ORACLE_BOOT.load(core::sync::atomic::Ordering::Relaxed) {
        crate::nvme::iocq_interrupt_on(None);
        return true;
    }
    let Some(cap) = amdvi::find_capability(|at| pci::read32(function, at), 0x11) else {
        return false;
    };
    let header = pci::read32(function, cap);
    pci::write32(function, cap, amdvi::msix_enable_masked(header));
    let control = pci::read32(function, cap) >> 16;
    let ok = control & 0xc000 == 0xc000 || cfg!(absd_mutant_amdvi_msix_unmasked);
    if ok {
        crate::nvme::iocq_interrupt_on(Some(NVME_IOCQ_VECTOR));
    }
    ok
}

/// The live unit and its contained devices (after [`setup`]): index 0 is
/// the edu, index 1 the NVMe in the two-device boot.
struct Session {
    rings: Rings,
    tables: Frames,
    /// The granted IRTE's destination (the BSP's APIC ID).
    ir_dest: u8,
    devtab: u64,
    health: Health,
    record: FaultRecord,
    devices: [Option<Device>; amdvi::MAX_TARGETS],
    nvme: Option<NvmeFacts>,
    ahci: Option<AhciFacts>,
    /// The disk selection the AHCI target was probed with (a restart
    /// probes again with it).
    ahci_selection: Option<Selection<'static>>,
}

impl Session {
    /// COMPLETION_WAIT with a unique store value; a timeout fails the unit.
    /// Every completion boundary (each map or DTE change) then observes the
    /// current overflow and pending unit errors (`observe_pending`), so a
    /// failure that arrived meanwhile is acted on before anything is
    /// acknowledged or armed.
    fn complete(&mut self, label: &str) -> bool {
        let ok = self.rings.wait(label);
        if !self.health.completion(ok) {
            self.unit_failed();
        }
        self.observe_pending();
        ok
    }

    /// Drains the event log: every event reported (`each`), unit errors and
    /// an invalid tail fail the unit, overflow or an invalid tail make the
    /// fault record incomplete for good.
    fn drain(&mut self, each: &mut dyn FnMut(&Event, [u32; 4], &FaultRecord)) -> (u64, bool) {
        let was_ok = self.health.failed().is_none();
        let snapshot = self.record;
        let (count, overflow) =
            self.rings
                .drain(&mut self.health, &mut self.record, &mut |event, raw| {
                    each(event, raw, &snapshot)
                });
        self.record.observe(count as u64, false);
        if was_ok && self.health.failed().is_some() {
            self.unit_failed();
        }
        (count as u64, overflow)
    }

    /// Observes, without consuming the log (the oracle's SYNC alone drains
    /// it), through the one entry point: pending unit errors and an invalid
    /// tail fail the unit, overflow or an invalid tail latch the record. For
    /// revocation steps and restarts, which must act on current evidence.
    fn observe_pending(&mut self) {
        let was_ok = self.health.failed().is_none();
        let _ = self.rings.observe_log(&mut self.health, &mut self.record);
        if was_ok && self.health.failed().is_some() {
            self.unit_failed();
        }
    }

    fn device(&self, which: usize) -> Device {
        self.devices[which].expect("device index")
    }

    fn device_mut(&mut self, which: usize) -> &mut Device {
        self.devices[which].as_mut().expect("device index")
    }

    /// The unit is Failed: clear Bus Master Enable on every contained
    /// function (before #116, the one target; leak L5) and drop their live
    /// domains from the dma seam. R2 only: this establishes neither
    /// `contained` nor `settled`.
    fn unit_failed(&mut self) {
        let reason = self.health.failed().map_or("unknown", |r| r.word());
        for device in self.devices.iter_mut().flatten() {
            pci::disable_dma(device.function);
            crate::dma::release_contained(device.function);
            let bme = pci::bus_master(device.function);
            device.armed = false;
            let _ = writeln!(
                Serial,
                "AMDVI UNIT FAILED reason={reason} devid={} bme={} step=R2 claims=none",
                Id(device.target),
                if bme { "on" } else { "clear" }
            );
        }
    }

    /// R1–R5 for device `which` (DESIGN §4). Returns whether R3 completed.
    /// The other device's domain, tables and arm are untouched.
    fn revoke_device(&mut self, which: usize) -> bool {
        let device = self.device(which);
        let mut revocation = Revocation::START;
        let mut reset = Reset::Unavailable;
        // R1: ABSD submits nothing more for the device. The oracle boot never
        // programs the edu; the NVMe driver is withdrawn (its controller
        // taken). R2 then clears Bus Master Enable, R3 blocks the domain,
        // and only then R4 asks the NVMe controller to disable.
        revocation.r1_closed();
        let (withdrawn, withdrawn_ahci) = match device.kind {
            Kind::Nvme => (crate::nvme::withdraw(), None),
            Kind::Ahci => (None, crate::ahci_block::withdraw()),
            Kind::Edu => (None, None),
        };
        // R2: Bus Master Enable clear, read back.
        pci::disable_dma(device.function);
        crate::dma::release_contained(device.function);
        self.device_mut(which).armed = false;
        let bme_clear = !pci::bus_master(device.function);
        let _ = revocation.r2_stopped(bme_clear);
        // R3: the one blocked form; the active set's leaves zeroed (absent
        // for the rest of the boot); DTE and whole-domain invalidation and
        // a completion read back.
        let entry = amdvi::dte_blocked(amdvi::BLOCKED_DOMAIN, amdvi::Interrupts::Abort);
        write_dte(self.devtab, device.target, entry);
        let mut written = true;
        for (at, &(page, _)) in device.grant.pages().iter().enumerate() {
            if !device.revoked[at] {
                written &= amdvi::unmap(&mut self.tables, device.root, page).is_ok();
                self.device_mut(which).revoked[at] = true;
            }
        }
        // Interrupts too (increment 7): the edu's granted IRTE zeroed
        // (RemapEn=0: target abort), invalidated with the rest; never
        // re-granted. The NVMe's table is all zero from the start.
        if device.kind == Kind::Edu {
            write_irte(device.ir_table, amdvi::IR_INDEX, 0);
        }
        fence();
        self.rings.submit(amdvi::invalidate_devtab(device.target));
        self.rings
            .submit(amdvi::invalidate_domain(device.invalidation_domain()));
        // (Negative control: the revoke without its interrupt-table
        // invalidation; the irq smoke must catch it.)
        if !cfg!(absd_mutant_amdvi_irq_revoke_no_invalidate) {
            self.rings
                .submit(amdvi::invalidate_interrupt_table(device.target));
        }
        // `complete` observes overflow and pending unit errors: R3 uses
        // current evidence.
        let completed = self.complete("revoke-device");
        let _ = revocation.r3_blocked(Blocked {
            written,
            completed,
            record_complete: self.record.complete(),
            unit_ok: self.health.failed().is_none(),
        });
        // R4: edu has no reset ABSD can use; the NVMe's controller disable
        // (CC.EN=0, bounded wait for RDY=0) and the AHCI port's engine stop
        // (ST then FRE off, bounded waits for CR and FR) come after its
        // domain is blocked (register evidence only).
        let stop = match device.kind {
            Kind::Nvme => Some(withdrawn.map(crate::nvme::Withdrawn::reset)),
            Kind::Ahci => Some(withdrawn_ahci.map(crate::ahci_block::Withdrawn::reset)),
            Kind::Edu => None,
        };
        if let Some(stopped) = stop {
            reset = match stopped {
                Some(true) => Reset::Done,
                Some(false) | None => Reset::NotAttempted,
            };
        }
        let _ = revocation.r4_reset(reset);
        // The set is retained by the dma seam whatever R3 found.
        let owner = device.owner;
        let kind = device.kind;
        if let Some(set) = self.device_mut(which).sets.retire_active() {
            let grant = device_set(kind, set);
            let mut pages = [0u64; MAX_PAGES];
            for (at, &(page, _)) in grant.pages().iter().enumerate() {
                pages[at] = page;
            }
            crate::dma::retain(owner, set + 1, &pages[..grant.len]);
        }
        let device = self.device_mut(which);
        device.device_revoked = true;
        device.revocation = Some(revocation);
        let target = device.target;
        let _ = writeln!(
            Serial,
            "AMDVI REVOKE devid={} R1=closed R2=bme-{} R3={} R4={} R5=no-mechanism",
            Id(target),
            if bme_clear { "clear" } else { "on" },
            if completed { "completed" } else { "timeout" },
            match reset {
                Reset::Done => "reset-requested-stop-confirmed",
                Reset::NotAttempted => "reset-unconfirmed",
                Reset::Unavailable => "reset-unavailable",
            }
        );
        for claim in Claim::ALL {
            let _ = writeln!(
                Serial,
                "AMDVI CLAIM devid={} {}={}",
                Id(target),
                claim.word(),
                revocation.claim(claim).word()
            );
        }
        completed
    }

    /// RESTART of device `which` (DESIGN §4, interface v3 A.3): refusals in
    /// order unit-failed, not-revoked, CONTAINED_BUT_UNUSABLE; otherwise the
    /// next unused set mapped, the DTE translated and invalidated, a
    /// completion, then BME (the NVMe: its driver re-probed on the new set,
    /// which arms through the dma seam).
    fn restart(&mut self, which: usize) -> Result<usize, &'static str> {
        self.observe_pending();
        if self.health.admit().is_err() {
            return Err("unit-failed");
        }
        let device = self.device(which);
        if !device.device_revoked {
            return Err("not-revoked");
        }
        let health = self.health;
        let set = match self.device_mut(which).sets.start(&health) {
            Ok(set) => set,
            Err(StartRefusal::ContainedButUnusable) => return Err("CONTAINED_BUT_UNUSABLE"),
            Err(refusal) => return Err(refusal.word()),
        };
        let pages = device_set(device.kind, set);
        for &(page, perm) in pages.pages() {
            if amdvi::map(&mut self.tables, device.root, page, page, perm).is_err() {
                self.health.fail(lifecycle::FailReason::InvalidationTimeout);
                self.unit_failed();
                return Err("unit-failed");
            }
        }
        write_dte(
            self.devtab,
            device.target,
            // The interrupt table stays all-zero: a restart does not
            // re-grant interrupts (DESIGN §4a).
            amdvi::dte_translated(device.domain, device.root, device.ir_table),
        );
        fence();
        self.rings.submit(amdvi::invalidate_devtab(device.target));
        self.rings
            .submit(amdvi::invalidate_domain(device.invalidation_domain()));
        if !self.complete("restart") {
            return Err("unit-failed");
        }
        if self.health.admit().is_err() {
            return Err("unit-failed");
        }
        let contained = device.contained();
        match device.kind {
            Kind::Edu => {
                if crate::dma::arm_contained(device.function, "edu", &contained).is_err() {
                    return Err("arm-refused");
                }
            }
            Kind::Nvme => {
                if !crate::dma::register_contained(&contained) {
                    return Err("arm-refused");
                }
                match crate::nvme::probe_set(None, set) {
                    Ok(identity) if identity.pci == device.function => {
                        self.nvme = Some(facts_of(&identity));
                    }
                    _ => {
                        crate::dma::release_contained(device.function);
                        pci::disable_dma(device.function);
                        return Err("nvme-probe");
                    }
                }
            }
            Kind::Ahci => {
                if !crate::dma::register_contained(&contained) {
                    return Err("arm-refused");
                }
                let probed = match self.ahci_selection {
                    Some(selection) => {
                        crate::ahci_block::probe_function(device.function, selection, set)
                    }
                    None => Err(crate::ahci_block::AhciError::Absent),
                };
                match probed {
                    Ok(identity) if identity.pci == device.function => {
                        self.ahci = Some(ahci_facts_of(&identity));
                    }
                    _ => {
                        pci::disable_dma(device.function);
                        crate::dma::release_contained(device.function);
                        return Err("ahci-probe");
                    }
                }
            }
        }
        let device = self.device_mut(which);
        device.armed = true;
        device.grant = pages;
        device.revoked = [false; MAX_PAGES];
        device.device_revoked = false;
        Ok(set)
    }
}

/// Why a boot cannot contain DMA: a short word for the oracle's
/// `UNAVAILABLE` line and the details for the log.
struct Unavailable(&'static str);

fn unavailable(word: &'static str, detail: core::fmt::Arguments<'_>) -> Unavailable {
    let _ = writeln!(Serial, "AMDVI ENFORCE REFUSED stage={word} {detail}");
    Unavailable(word)
}

fn grant_pages() -> [(u64, Perm); 3] {
    set_pages(0)
}

/// The pages of buffer set `set` (0 = set 1, 1 = set 2).
fn set_pages(set: usize) -> [(u64, Perm); 3] {
    if set == 0 {
        [
            (page_address(core::ptr::addr_of!(SOURCE)), Perm::READ),
            (page_address(core::ptr::addr_of!(TARGET)), Perm::WRITE),
            (page_address(core::ptr::addr_of!(SECOND)), Perm::WRITE),
        ]
    } else {
        [
            (page_address(core::ptr::addr_of!(SOURCE2)), Perm::READ),
            (page_address(core::ptr::addr_of!(TARGET2)), Perm::WRITE),
            (page_address(core::ptr::addr_of!(SECOND2)), Perm::WRITE),
        ]
    }
}

/// The environment name for fault observations (CPUID).
fn environment() -> &'static str {
    use core::arch::x86_64::__cpuid;
    let hypervisor = __cpuid(1).ecx & (1 << 31) != 0;
    let mut vendor = [0u8; 12];
    if hypervisor {
        let leaf = __cpuid(0x4000_0000);
        vendor[..4].copy_from_slice(&leaf.ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&leaf.ecx.to_le_bytes());
        vendor[8..].copy_from_slice(&leaf.edx.to_le_bytes());
    }
    lifecycle::environment(hypervisor, &vendor)
}

fn zeroed_frame() -> Option<u64> {
    let frames = unsafe { crate::vm::frames() };
    let frame = frames.allocate(FrameOwner::Kernel)?;
    let address = frame.start_address();
    unsafe { core::ptr::write_bytes(address as *mut u8, 0, PAGE as usize) };
    Some(address)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Gate {
    /// Capability Enable=1 with the IVHD base (as found, or as ABSD set it).
    Established,
    /// Enable=0 and the base registers do not take writes (QEMU: read-only
    /// capability registers, MMIO decoded at a fixed address regardless).
    /// The specified gate is not established; ABSD proceeds only when the
    /// window then answers as this unit, and says so.
    Unprogrammable,
}

/// Establishes Capability Offset 04h[Enable] with the IVHD base: when clear,
/// writes base high, then base low with Enable (RW1S; locks the block), and
/// reads both back.
fn base_gate(unit: &absd_kernel::ivrs::Unit) -> Result<Gate, Unavailable> {
    let iommu = Function {
        bus: (unit.devid >> 8) as u8,
        device: ((unit.devid >> 3) & 0x1f) as u8,
        function: (unit.devid & 7) as u8,
    };
    let Some([_, low_at, high_at]) = unit.capability_registers() else {
        return Err(unavailable(
            "base-gate",
            format_args!("reason=capability-offset"),
        ));
    };
    let read = || {
        let low = pci::read32(iommu, low_at);
        let high = pci::read32(iommu, high_at);
        (
            low & 1 != 0,
            (u64::from(high) << 32) | u64::from(low & 0xffff_c000),
        )
    };
    let (enabled, base) = read();
    if enabled {
        if base != unit.base {
            return Err(unavailable(
                "base-gate",
                format_args!("reason=enabled-elsewhere base={base:#x}"),
            ));
        }
        let _ = writeln!(
            Serial,
            "AMDVI BASE-GATE enable=1 base={base:#x} set-by=firmware"
        );
        return Ok(Gate::Established);
    }
    pci::write32(iommu, high_at, (unit.base >> 32) as u32);
    pci::write32(iommu, low_at, (unit.base as u32 & 0xffff_c000) | 1);
    let (enabled, base) = read();
    if enabled && base == unit.base {
        let _ = writeln!(
            Serial,
            "AMDVI BASE-GATE enable=1 base={base:#x} set-by=absd"
        );
        return Ok(Gate::Established);
    }
    if enabled {
        return Err(unavailable(
            "base-gate",
            format_args!("reason=base-mismatch base={base:#x}"),
        ));
    }
    let _ = writeln!(
        Serial,
        "AMDVI BASE-GATE enable=0 programmable=no base-registers={base:#x} gate=unestablished decode=checked-by-efr"
    );
    Ok(Gate::Unprogrammable)
}

/// Discovery result to a live, contained domain for `edu`, or the reason it
/// cannot be. The `Enforced` profile is already selected, so on refusal no
/// function can be armed.
/// A unit whose table is admitted and whose registers answer, not yet
/// programmed. Shared by the test boots and the operator boot.
struct OpenUnit {
    unit: &'static absd_kernel::ivrs::Unit,
    mmio: Mmio,
    live: amdvi::Live,
    deviations: usize,
    quirked: usize,
}

/// Discovery to an admitted table: base gate, live registers, handoff state,
/// table admission, quirks. Nothing is enabled.
fn open_unit() -> Result<OpenUnit, Unavailable> {
    let Some((unit, discovered)) = crate::acpi_boot::discovered() else {
        return Err(unavailable(
            "discovery",
            format_args!("reason=no-usable-ivrs"),
        ));
    };

    // The capability's base gate (§3.2, Capability Offset 04h[Enable]):
    // MMIO is accepted at the base only with Enable=1.
    let gate = base_gate(unit)?;

    // Live registers: capability header (from discovery), EFR, control,
    // status. The window is mapped only in this boot.
    let mmio = match crate::mmio::map(unit.base, unit.window(), crate::mmio::Cache::Uncached) {
        Ok(address) => Mmio(address),
        Err(error) => return Err(unavailable("mmio", format_args!("reason={error:?}"))),
    };
    // EFR only with live EFRSup; Counter Configuration only after that and
    // with image and live PCSup (`amdvi::acquire_live`).
    let live = acquire_live(unit, discovered.cap_header, |offset| mmio.read(offset));
    let control = mmio.read(CONTROL);
    let _ = writeln!(
        Serial,
        "AMDVI LIVE cap-header={:#010x} efr={:#018x} control={control:#018x} status={:#x} ia-sup={}",
        live.cap_header,
        live.efr,
        mmio.read(STATUS),
        u8::from(live.ia_sup())
    );
    if control & CONTROL_IOMMU_EN != 0 {
        // Unknown tables, possibly live translations: not taken over.
        return Err(unavailable(
            "handoff",
            format_args!("reason=iommu-already-enabled"),
        ));
    }

    // Admission: the table, then the device.
    let admission = match amdvi::admit_table(unit, &discovered.validation, &live) {
        Ok(admission) => admission,
        Err(refusal) => {
            return Err(unavailable(
                "admit-table",
                format_args!("reason={refusal:?}"),
            ));
        }
    };
    // Without the specified gate, decode is accepted only when the window
    // has answered as this unit: admission compared its live EFR with the
    // table's (which needs EFRSup).
    if gate == Gate::Unprogrammable && !unit.efr_sup() {
        return Err(unavailable(
            "base-gate",
            format_args!("reason=window-not-observed"),
        ));
    }
    for finding in unit.findings.items() {
        if let Some(quirk) = amdvi::quirk_for(unit, finding, &live) {
            let _ = writeln!(
                Serial,
                "AMDVI QUIRK name={} version={} block={:02x}h offset={:#x} field={} {}",
                quirk.name,
                quirk.version,
                finding.block,
                finding.offset,
                finding.field.name(),
                finding.detail
            );
        }
    }
    let _ = writeln!(
        Serial,
        "AMDVI ADMIT table=ok deviations={} quirked={}",
        discovered.validation.deviations, admission.quirked
    );
    Ok(OpenUnit {
        unit,
        mmio,
        live,
        deviations: discovered.validation.deviations,
        quirked: admission.quirked,
    })
}

fn setup(ahci: AhciSelection) -> Result<Session, Unavailable> {
    let OpenUnit {
        unit, mmio, live, ..
    } = open_unit()?;
    // The target is the function at 00:05.0 (oracle INTERFACE v1 §2), and
    // it must be an `edu`; other `edu` functions elsewhere stay blocked.
    let function = EDU_FUNCTION;
    if pci::ids(function) != EDU_IDS {
        return Err(unavailable(
            "device",
            format_args!("reason=no-edu-at-00:05.0"),
        ));
    }
    let target = devid(function);
    if let Err(refusal) = amdvi::admit_device(unit, target) {
        return Err(unavailable(
            "admit-device",
            format_args!("devid={} reason={refusal:?}", Id(target)),
        ));
    }
    let _ = writeln!(Serial, "AMDVI ADMIT device={} closure=own-only", Id(target));
    if pci::claim(function, "edu").is_err() {
        return Err(unavailable("device", format_args!("reason=claimed")));
    }
    // #116: a QEMU NVMe controller, when present, is the second target in
    // its own domain. It must be on bus 0 (QEMU drops the bus from fault
    // DeviceIDs; the alias-closure rule is the same as the edu's). Its
    // driver claims it at probe. #123: with an AHCI disk selected, the
    // second target is instead the AHCI controller at 00:07.0, and only
    // there (q35's built-in controller at 00:1f.2 holds the boot CD and
    // stays an inherited master the sweep blocks); never both.
    let ahci_selection = match ahci {
        Ok(selection) => selection,
        Err(error) => {
            return Err(unavailable(
                "ahci-target",
                format_args!("reason=selection-{error:?}"),
            ));
        }
    };
    let nvme_found = pci::find(NVME_CLASS.0, NVME_CLASS.1, NVME_CLASS.2);
    let code = pci::read32(AHCI_FUNCTION, 0x08);
    let ahci_pinned = pci::ids(AHCI_FUNCTION).0 != 0xffff
        && ((code >> 24) as u8, (code >> 16) as u8, (code >> 8) as u8) == AHCI_CLASS;
    let second_kind =
        match amdvi::second_target(nvme_found.is_some(), ahci_selection.is_some(), ahci_pinned) {
            Ok(amdvi::Second::None) => None,
            Ok(amdvi::Second::Nvme) => Some(Kind::Nvme),
            Ok(amdvi::Second::Ahci) => Some(Kind::Ahci),
            Err(refusal) => {
                return Err(unavailable(
                    "ahci-target",
                    format_args!("reason={}", refusal.word()),
                ));
            }
        };
    let second = match (second_kind, nvme_found) {
        (None, _) => None,
        (Some(Kind::Nvme), Some(f)) if f.bus != 0 => {
            return Err(unavailable(
                "admit-device",
                format_args!("devid={} reason=nvme-not-on-bus-0", Id(devid(f))),
            ));
        }
        (Some(kind), found) => {
            let f = match (kind, found) {
                (Kind::Nvme, Some(f)) => f,
                _ => AHCI_FUNCTION,
            };
            if let Err(refusal) = amdvi::admit_device(unit, devid(f)) {
                return Err(unavailable(
                    "admit-device",
                    format_args!("devid={} reason={refusal:?}", Id(devid(f))),
                ));
            }
            let _ = writeln!(
                Serial,
                "AMDVI ADMIT device={} closure=own-only driver={}",
                Id(devid(f)),
                if kind == Kind::Ahci { "ahci" } else { "nvme" }
            );
            Some((kind, f))
        }
    };

    // Memory the unit uses; the grant may not touch it, the canaries or the
    // mailbox.
    let grant = grant_pages();
    let frames = unsafe { crate::vm::frames() };
    let pages = DEVICE_TABLE_ENTRIES * amdvi::DTE_BYTES / PAGE as usize;
    let Some(table) = frames.allocate_contiguous(pages, FrameOwner::Kernel) else {
        return Err(unavailable("memory", format_args!("reason=device-table")));
    };
    let devtab = table.start_address();
    let (Some(command), Some(events), Some(store), Some(ir_table)) = (
        zeroed_frame(),
        zeroed_frame(),
        zeroed_frame(),
        zeroed_frame(),
    ) else {
        return Err(unavailable("memory", format_args!("reason=rings")));
    };
    let mut tables = Frames;
    let Some(root) = tables.allocate() else {
        return Err(unavailable("memory", format_args!("reason=page-table")));
    };
    // The second domain's page-table root and its deny-all interrupt table
    // (all zero: RemapEn=0 everywhere). Its own frame, never the edu's: a
    // shared table would hand the second device the edu's granted index.
    let (second_root, second_ir_table) = match second {
        None => (0, 0),
        Some(_) => {
            let (Some(r), Some(t)) = (tables.allocate(), zeroed_frame()) else {
                return Err(unavailable("memory", format_args!("reason=second-domain")));
            };
            let root = if cfg!(absd_mutant_amdvi_shared_root) {
                root
            } else {
                r
            };
            let ir = if cfg!(absd_mutant_amdvi_shared_irtable) {
                ir_table
            } else {
                t
            };
            (root, ir)
        }
    };
    let devtab_end = devtab + (DEVICE_TABLE_ENTRIES * amdvi::DTE_BYTES) as u64;
    let canary = page_address(core::ptr::addr_of!(CANARY));
    let canary2 = page_address(core::ptr::addr_of!(CANARY2));
    let mailbox = page_address(core::ptr::addr_of!(MAILBOX));
    let reserved = [
        (devtab, devtab_end),
        (command, command + PAGE),
        (events, events + PAGE),
        (store, store + PAGE),
        (root, root + PAGE),
        (ir_table, ir_table + PAGE),
        (canary, canary + PAGE),
        (canary2, canary2 + PAGE),
        (mailbox, mailbox + PAGE),
        // Empty ranges without a second domain.
        (
            second_root,
            second_root + if second.is_some() { PAGE } else { 0 },
        ),
        (
            second_ir_table,
            second_ir_table + if second.is_some() { PAGE } else { 0 },
        ),
    ];
    if let Err(error) = amdvi::check_grant(&grant, EDU_REACH, &reserved) {
        return Err(unavailable("grant", format_args!("reason={error:?}")));
    }
    // Set 2: the same shape, disjoint from set 1 and everything above.
    let [(a, _), (b, _), (c, _)] = grant;
    let mut reserved2 = [(0, 0); 14];
    reserved2[..11].copy_from_slice(&reserved);
    reserved2[11..].copy_from_slice(&[(a, a + PAGE), (b, b + PAGE), (c, c + PAGE)]);
    if let Err(error) = amdvi::check_grant(&set_pages(1), EDU_REACH, &reserved2) {
        return Err(unavailable("grant", format_args!("reason=set2-{error:?}")));
    }
    // The second device's two sets: whole 64-bit reach (IOVA limit; the
    // AHCI backend refuses a controller without 64-bit addressing when a
    // buffer needs it), the same reserved memory, and no page shared with
    // any edu set or each other (#116: overlap refused at admission).
    if let Some((kind, _)) = second {
        let (nvme1, nvme2) = (device_set(kind, 0), device_set(kind, 1));
        let names = if kind == Kind::Ahci {
            ["ahci-set1", "ahci-set2"]
        } else {
            ["nvme-set1", "nvme-set2"]
        };
        for (name, set) in [(names[0], nvme1), (names[1], nvme2)] {
            if let Err(error) = amdvi::check_grant(set.pages(), amdvi::IOVA_LIMIT, &reserved) {
                return Err(unavailable(
                    "grant",
                    format_args!("reason={name}-{error:?}"),
                ));
            }
        }
        let edu2 = set_pages(1);
        if let Err(error) = amdvi::check_disjoint(&[&grant, &edu2, nvme1.pages(), nvme2.pages()]) {
            return Err(unavailable(
                "grant",
                format_args!("reason=overlap-{error:?}"),
            ));
        }
    }

    // Page tables: granted pages only.
    for &(page, perm) in &grant {
        if let Err(error) = amdvi::map(&mut tables, root, page, page, perm) {
            return Err(unavailable(
                "map",
                format_args!("page={page:#x} reason={error:?}"),
            ));
        }
    }

    if let Some((kind, _)) = second {
        for &(page, perm) in device_set(kind, 0).pages() {
            if let Err(error) = amdvi::map(&mut tables, second_root, page, page, perm) {
                return Err(unavailable(
                    "map",
                    format_args!("page={page:#x} reason={error:?}"),
                ));
            }
        }
    }

    // Device table: every entry, the target's included, written blocked
    // before the unit is enabled. The grant (the target's translated
    // entry) is written only after the deny-by-default sweep (below).
    for id in 0..DEVICE_TABLE_ENTRIES {
        write_dte(devtab, id as u16, amdvi::dte_initial(unit, id as u16));
    }
    fence();
    let _ = writeln!(
        Serial,
        "AMDVI DOMAIN id={DOMAIN} devid={} mode={} root={root:#x} devtab={devtab:#x} entries={DEVICE_TABLE_ENTRIES} blocked={} blocked-form=v1-tv0",
        Id(target),
        amdvi::MODE,
        DEVICE_TABLE_ENTRIES - 1
    );
    for &(page, perm) in &grant {
        let _ = writeln!(
            Serial,
            "AMDVI GRANT devid={} iova={page:#x} page={page:#x} bytes={PAGE} perm={}",
            Id(target),
            perm_word(perm)
        );
    }
    if let Some((kind, f)) = second {
        let _ = writeln!(
            Serial,
            "AMDVI DOMAIN id={} devid={} mode={} root={second_root:#x} ir-table={second_ir_table:#x} interrupts=deny-all",
            amdvi::SECOND_DOMAIN,
            Id(devid(f)),
            amdvi::MODE
        );
        for (at, &(page, perm)) in device_set(kind, 0).pages().iter().enumerate() {
            // The AHCI lines name each page's role (its permission differs
            // by role); the NVMe lines stay as #116 printed them.
            let _ = writeln!(
                Serial,
                "AMDVI GRANT devid={} iova={page:#x} page={page:#x} bytes={PAGE} perm={}{}",
                Id(devid(f)),
                perm_word(perm),
                if kind == Kind::Ahci {
                    Role(kind, at)
                } else {
                    Role(Kind::Edu, at)
                }
            );
        }
    }

    let (mut rings, enabled_tsc) = enable_unit(mmio, &live, devtab, command, events, store)?;
    // Every entry was written before IommuEn, so nothing can be cached; the
    // invalidations make that explicit. INVALIDATE_IOMMU_ALL only when the
    // live EFR has IASup. Every one of the 65 536 DeviceIDs, not only the
    // functions PCI enumeration found, gets its own INVALIDATE_DEVTAB_ENTRY,
    // completed before the target is armed: the specification asks for it
    // after a DTE is written, and QEMU 10.2.1 (dma-remap=on) moves a
    // function off its passthrough region only on that command
    // (INVALIDATE_IOMMU_ALL does not). Until it completes nothing is armed;
    // firmware-left masters are not cleared on this path (increment 6): the
    // inherited IDs are invalidated first, so their gap is one completion.
    let ir_dest = bsp_apic_id();
    let mut health = Health::default();
    // The fault record exists from the first observation, so overflow or
    // an invalid tail seen during setup stays latched in it.
    let mut record = FaultRecord::new(Observer::AbsdEventLog, environment());
    let (priority, count) = inherited_priority(unit);
    let mut invalidated = 0u32;
    let mut inherited_tsc = None;
    let mut targets = [(target, DOMAIN), (0, 0)];
    let target_count = if let Some((_, f)) = second {
        targets[1] = (devid(f), amdvi::SECOND_DOMAIN);
        2
    } else {
        1
    };
    for step in amdvi::enforcement_plan(live.ia_sup(), &targets[..target_count], &priority[..count])
    {
        match step {
            Step::Submit(command) => {
                rings.submit(command);
                if inherited_tsc.is_some() || count == 0 {
                    invalidated += u32::from(command[1] >> 28 == 0x2);
                }
            }
            Step::Complete(label) => {
                if cfg!(absd_inject_setup_unit_error) && label == "invalidate" {
                    // Fault injection (negative control build only): an
                    // illegal command at the end of the sweep.
                    rings.submit([0, 0xf << 28, 0, 0]);
                }
                if !health.completion(rings.wait(label)) {
                    return Err(unavailable(
                        "invalidate",
                        format_args!("reason=no-completion step={label}"),
                    ));
                }
                if label == "inherited" {
                    inherited_tsc = Some(tsc());
                    let _ = writeln!(
                        Serial,
                        "AMDVI INHERITED-FIRST invalidated={count} iommu-en-to-completion-cycles={}",
                        inherited_tsc.unwrap_or(0).wrapping_sub(enabled_tsc)
                    );
                }
                // Every completion boundary observes pending unit errors
                // (without consuming the log): nothing is granted or armed
                // on a failed unit.
                let _ = rings.observe_log(&mut health, &mut record);
                if let Some(reason) = health.failed() {
                    return Err(unavailable(
                        "unit-failed",
                        format_args!("reason={} step={label}", reason.word()),
                    ));
                }
            }
            Step::GrantTarget(1) => {
                // The second target: translated through its own root, its
                // interrupts remapped through its own all-zero table.
                let (id, domain) = targets[1];
                write_dte(
                    devtab,
                    id,
                    amdvi::dte_translated(domain, second_root, second_ir_table),
                );
                fence();
                let _ = writeln!(Serial, "AMDVI GRANTED devid={}", Id(id));
            }
            Step::GrantTarget(_) => {
                // Deny-by-default established: every DeviceID's blocked
                // entry invalidated and completed. Only now the grant.
                report_window(enabled_tsc, tsc());
                let _ = writeln!(
                    Serial,
                    "AMDVI DENY-BY-DEFAULT devtab-invalidated={invalidated} of={DEVICE_TABLE_ENTRIES}"
                );
                if invalidated as usize != DEVICE_TABLE_ENTRIES {
                    return Err(unavailable(
                        "invalidate",
                        format_args!("reason=incomplete invalidated={invalidated}"),
                    ));
                }
                // Increment 7: the one interrupt grant, then the DTE that
                // remaps through the 512-entry table (every other entry
                // zero: RemapEn=0, target abort).
                write_irte(
                    ir_table,
                    amdvi::IR_INDEX,
                    amdvi::irte_basic(amdvi::IR_VECTOR, ir_dest),
                );
                write_dte(
                    devtab,
                    target,
                    amdvi::dte_translated(DOMAIN, root, ir_table),
                );
                fence();
                let _ = writeln!(Serial, "AMDVI GRANTED devid={}", Id(target));
            }
        }
    }
    // Current evidence once more before the initial arm.
    let _ = rings.observe_log(&mut health, &mut record);
    if let Some(reason) = health.failed() {
        return Err(unavailable(
            "unit-failed",
            format_args!("reason={} step=arm", reason.word()),
        ));
    }
    let mut sets = Sets::NEW;
    if sets.start(&health) != Ok(0) {
        return Err(unavailable("sets", format_args!("reason=first-start")));
    }
    // #116: the NVMe's domain is live and invalidated: the dma seam learns
    // it, the legacy PIT starts (the driver's waits and timeouts run on its
    // ticks; the AMD-Vi boots start no timer before the sweep, leak L-env;
    // the 8259 path does not cross the IOMMU), and the driver probes on set
    // 1, arming through `dma::arm` like every other boot.
    // #123: the AHCI controller the same way, on its own buffer set 1,
    // probed at its pinned function only.
    let mut second_device = None;
    let mut nvme_facts = None;
    let mut ahci_facts = None;
    if let Some((kind, f)) = second {
        let mut second_sets = Sets::NEW;
        if second_sets.start(&health) != Ok(0) {
            return Err(unavailable(
                "sets",
                format_args!(
                    "reason={}-first-start",
                    if kind == Kind::Ahci { "ahci" } else { "nvme" }
                ),
            ));
        }
        let device = Device {
            kind,
            owner: if kind == Kind::Ahci { "ahci" } else { "nvme" },
            target: devid(f),
            function: f,
            domain: amdvi::SECOND_DOMAIN,
            root: second_root,
            ir_table: second_ir_table,
            grant: device_set(kind, 0),
            revoked: [false; MAX_PAGES],
            device_revoked: false,
            sets: second_sets,
            revocation: None,
            armed: false,
        };
        if !crate::dma::register_contained(&device.contained()) {
            return Err(unavailable("arm", format_args!("reason=registry-full")));
        }
        let ticks = crate::timer_test();
        let _ = writeln!(
            Serial,
            "AMDVI TIMER pit-ticks={ticks} purpose={}-driver",
            device.owner
        );
        if ticks < 5 {
            crate::dma::release_contained(f);
            return Err(unavailable("timer", format_args!("ticks={ticks}")));
        }
        if kind == Kind::Nvme {
            if !nvme_msix_masked(f) {
                crate::dma::release_contained(f);
                return Err(unavailable(
                    "msix",
                    format_args!("devid={} reason=no-msix", Id(devid(f))),
                ));
            }
            match crate::nvme::probe_set(None, 0) {
                Ok(identity) if identity.pci == f => {
                    nvme_facts = Some(facts_of(&identity));
                }
                Ok(_) | Err(_) => {
                    crate::dma::release_contained(f);
                    pci::disable_dma(f);
                    return Err(unavailable(
                        "nvme-probe",
                        format_args!("devid={}", Id(devid(f))),
                    ));
                }
            }
        } else {
            // The selection is present: `second_target` chose the AHCI
            // controller only with one.
            let probed = match ahci_selection {
                Some(selection) => crate::ahci_block::probe_function(f, selection, 0),
                None => Err(crate::ahci_block::AhciError::Absent),
            };
            match probed {
                Ok(identity) if identity.pci == f => {
                    ahci_facts = Some(ahci_facts_of(&identity));
                }
                other => {
                    // Bus mastering off first, then the registration.
                    pci::disable_dma(f);
                    crate::dma::release_contained(f);
                    return Err(unavailable(
                        "ahci-probe",
                        format_args!(
                            "devid={} result={:?}",
                            Id(devid(f)),
                            other.map(|identity| identity.pci)
                        ),
                    ));
                }
            }
        }
        let _ = writeln!(
            Serial,
            "AMDVI CONTAINED devid={} domain={} bme={} profile=enforced driver={}",
            Id(devid(f)),
            amdvi::SECOND_DOMAIN,
            if pci::bus_master(f) { "on" } else { "clear" },
            device.owner
        );
        second_device = Some(Device {
            armed: true,
            ..device
        });
    }
    // The target's MSI capability: address 0xfee00000 (destination from the
    // IRTE), data = the granted index (fixed delivery), MSI enabled; before
    // bus mastering is set.
    if !program_msi(function, amdvi::IR_INDEX, ir_dest) {
        return Err(unavailable("msi", format_args!("reason=no-msi-capability")));
    }
    let _ = writeln!(
        Serial,
        "AMDVI IRGRANT devid={} index={:#x} vector={:#x} dest={ir_dest:#x} table={ir_table:#x} entries={} intctl=remap",
        Id(target),
        amdvi::IR_INDEX,
        amdvi::IR_VECTOR,
        amdvi::IR_TABLE_ENTRIES
    );
    let contained = Contained {
        devid: target,
        domain: DOMAIN,
        function,
    };
    if let Err(refused) = crate::dma::arm_contained(function, "edu", &contained) {
        return Err(unavailable("arm", format_args!("reason={refused:?}")));
    }
    let _ = writeln!(
        Serial,
        "AMDVI CONTAINED devid={} domain={DOMAIN} bme=on profile=enforced",
        Id(target)
    );
    // Every fault line of this boot, the oracle protocol's FAULT lines
    // included, is this observer's in this environment.
    let _ = writeln!(
        Serial,
        "AMDVI FAULT-RECORD observer={} env={} covers=AMDVI-EVENT,AMDVI-ORACLE-FAULT",
        record.observer.word(),
        record.environment
    );
    let edu = Device {
        kind: Kind::Edu,
        owner: "edu",
        target,
        function,
        domain: DOMAIN,
        root,
        ir_table,
        grant: Grant::of(&grant),
        revoked: [false; MAX_PAGES],
        device_revoked: false,
        sets,
        revocation: None,
        armed: true,
    };
    Ok(Session {
        rings,
        tables,
        devtab,
        ir_dest,
        health,
        record,
        devices: [Some(edu), second_device, None],
        nvme: nvme_facts,
        ahci: ahci_facts,
        ahci_selection,
    })
}

/// Registers, then enable, for a device table already written. Returns the
/// running rings and the TSC at IommuEn.
fn enable_unit(
    mmio: Mmio,
    live: &amdvi::Live,
    devtab: u64,
    command: u64,
    events: u64,
    store: u64,
) -> Result<(Rings, u64), Unavailable> {
    // Registers, then enable. Control is written to a known value rather
    // than read-modify-written: IommuEn, CmdBufEn and EventLogEn off, every
    // other feature off (no exclusion range, device-table segments, MARC,
    // PPR, GA, guest translation, interrupts), Coherent=1 written
    // explicitly (the IVHD flag is not consumed), and HtTunEn=1 when the
    // capability header reports a HyperTransport tunnel, so tunnel traffic
    // is translated too. Then: wait until CmdBufRun and EventLogRun are
    // clear (§2.4.10, MMIO 2020h: ring registers may be changed only
    // then); clear the exclusion range (ExEn=0, Allow=0, limit 0); clear
    // PerfOptEn when the live EFR has PerfOptSup (MMIO 016Ch: privileged
    // devices bypass the IOMMU); read every one of these back.
    let quiet = CONTROL_COHERENT
        | if live.cap_header & CAP_HT_TUNNEL != 0 {
            CONTROL_HT_TUN_EN
        } else {
            0
        };
    mmio.write(CONTROL, quiet);
    let start = tsc();
    while mmio.read(STATUS) & (STATUS_CMD_BUF_RUN | STATUS_EVENT_LOG_RUN) != 0 {
        if tsc().wrapping_sub(start) > WAIT_CYCLES {
            return Err(unavailable(
                "control",
                format_args!("reason=not-quiesced status={:#x}", mmio.read(STATUS)),
            ));
        }
        core::hint::spin_loop();
    }
    mmio.write(EXCLUSION_BASE, 0);
    mmio.write(EXCLUSION_LIMIT, 0);
    let perf_opt = live.perf_opt_sup();
    if perf_opt {
        // Every other bit of this register is reserved: write zero.
        mmio.write32(PERF_OPT, 0);
    }
    fence();
    let readback = (
        mmio.read(CONTROL) & !CONTROL_READ_ONLY,
        mmio.read(EXCLUSION_BASE),
        mmio.read(EXCLUSION_LIMIT),
        if perf_opt {
            mmio.read32(PERF_OPT) & PERF_OPT_EN
        } else {
            0
        },
    );
    if readback != (quiet, 0, 0, 0) {
        return Err(unavailable(
            "control",
            format_args!(
                "reason=not-initialized control={:#x} exclusion={:#x}:{:#x} perf-opt={:#x}",
                readback.0, readback.1, readback.2, readback.3
            ),
        ));
    }
    let _ = writeln!(
        Serial,
        "AMDVI QUIESCED control={quiet:#x} status={:#x} exclusion=off perf-opt={} ht-tunnel={}",
        mmio.read(STATUS),
        if perf_opt { "cleared" } else { "unsupported" },
        if quiet & CONTROL_HT_TUN_EN != 0 {
            "translated"
        } else {
            "absent"
        }
    );
    mmio.write(DEVTAB_BASE, devtab | amdvi::DEVICE_TABLE_SIZE_FIELD);
    mmio.write(CMD_BASE, command | (amdvi::RING_LENGTH_CODE << 56));
    mmio.write(EVENT_BASE, events | (amdvi::RING_LENGTH_CODE << 56));
    mmio.write(CMD_HEAD, 0);
    mmio.write(CMD_TAIL, 0);
    mmio.write(EVENT_HEAD, 0);
    mmio.write(EVENT_TAIL, 0);
    fence();
    let control = quiet | CONTROL_CMD_BUF_EN | CONTROL_EVENT_LOG_EN;
    mmio.write(CONTROL, control);
    // The inherited bus masters once more, right before the unit is enabled
    // (configuration reads only; nothing changes, nothing is printed).
    crate::dma::snapshot_inherited();
    if crate::dma::inherited_overflow() {
        // More inherited masters than recorded: disclosure and the
        // inherited-first invalidation would be incomplete. Fail closed.
        return Err(unavailable(
            "inherited-overflow",
            format_args!("max={}", crate::dma::MAX_INHERITED),
        ));
    }
    mmio.write(CONTROL, control | CONTROL_IOMMU_EN);
    let enabled_tsc = tsc();
    let rings = Rings {
        mmio,
        command,
        tail: 0,
        events,
        head: 0,
        store,
        sequence: 0,
        last: 0,
    };
    let _ = writeln!(
        Serial,
        "AMDVI ENABLED control={:#x} status={:#x}",
        rings.mmio.read(CONTROL),
        rings.mmio.read(STATUS)
    );
    Ok((rings, enabled_tsc))
}

/// Inherited bus masters first (increment 6): their DeviceIDs and the IDs
/// their requests arrive as (IVRS aliases).
fn inherited_priority(unit: &absd_kernel::ivrs::Unit) -> ([u16; amdvi::SWEEP_BATCH], usize) {
    let mut priority = [0u16; amdvi::SWEEP_BATCH];
    let mut count = 0usize;
    for i in crate::dma::inherited() {
        let id = devid(i.function);
        let alias = match unit.source(id) {
            absd_kernel::ivrs::Source::Alias(to) => Some(to),
            _ => None,
        };
        for id in core::iter::once(id).chain(alias) {
            if count < priority.len() && !priority[..count].contains(&id) {
                priority[count] = id;
                count += 1;
            }
        }
    }
    (priority, count)
}

/// The DeviceID an event names.
fn event_requester(event: &Event) -> u16 {
    match *event {
        Event::IllegalDevTableEntry { devid, .. } | Event::IoPageFault { devid, .. } => devid,
        _ => 0,
    }
}

/// The pre-enable window (#111 increment 6): from kernel entry to IommuEn,
/// and to the end of the deny-by-default sweep. Until IommuEn, and on QEMU
/// 10.2.1 until each function's own DTE invalidation, a firmware-left bus
/// master is uncontained; after it, its DMA is blocked whatever its Bus
/// Master Enable (ABSD does not clear it in the enforced path).
fn report_window(enabled: u64, swept: u64) {
    let entry = crate::ENTRY_TSC.load(core::sync::atomic::Ordering::Relaxed);
    // Origin: the first instruction of `kernel_main`, after the assembly
    // entry, early paging and stack painting (src/boot.S), not the
    // multiboot hand-off itself. The AMD-Vi boots do not calibrate the TSC
    // before enabling the unit (no PIT activity first), so the window is in
    // TSC cycles; the oracle measures its own wall-clock window.
    let _ = writeln!(
        Serial,
        "AMDVI PREENABLE-WINDOW kernel-main-to-iommu-en-cycles={} kernel-main-to-deny-by-default-cycles={} tsc-rate=unmeasured inherited-masters=uncontained-in-window",
        enabled.wrapping_sub(entry),
        swept.wrapping_sub(entry),
    );
}

/// The inherited bus masters, after the unit is enabled (or refused): the
/// boot report's `DMA INHERITED` list and, in the oracle boot, one
/// `AMDVI-ORACLE INHERITED` line each (interface v3.2 §B).
/// `targets`: the enforced session's granted targets (`None` when setup was
/// refused).
fn report_inherited(oracle: bool, targets: Option<&Session>) {
    let enforced = targets.is_some();
    if oracle {
        for i in crate::dma::inherited() {
            let _ = writeln!(
                Serial,
                "AMDVI-ORACLE INHERITED devid={:#06x} bme=1",
                devid(i.function)
            );
        }
    }
    crate::dma::report_inherited();
    let count = crate::dma::inherited().count();
    if !enforced {
        let _ = writeln!(
            Serial,
            "AMDVI INHERITED count={count} after-enable=not-contained (enforcement unavailable)"
        );
        return;
    }
    // An inherited master that is also one of the session's translated
    // targets (the AHCI at 00:07.0, which firmware left bus-mastering, or an
    // edu left so) now has its grant, and its driver may have changed its
    // Bus Master Enable: only the others are blocked and untouched. The
    // session's own target list decides, not the live-domain registry,
    // which the edu (armed through `dma::arm_contained`) never enters.
    let session = targets.expect("enforced report has a session");
    let translated = crate::dma::inherited()
        .filter(|i| {
            session
                .devices
                .iter()
                .flatten()
                .any(|device| device.function == i.function)
        })
        .count();
    let _ = writeln!(
        Serial,
        "AMDVI INHERITED count={count} translated-targets={translated} after-enable=others-blocked-whatever-bme others-bme=unchanged"
    );
}

/// The refusal path only (steward decision 2026-10-31): no unit contains
/// the inherited bus masters, so clearing their Bus Master Enable is the one
/// fail-closed action a test boot has. R2 only: it stops new requests from
/// those functions and establishes no claim (not containment, not
/// settlement). Every bus-mastering function except IOMMUs (class 0806h)
/// and host bridges (0600h) is cleared. Never on the enforced path, where
/// the deny-by-default sweep is the containment being judged.
fn close_inherited_masters_on_refusal() {
    let mut closed = 0u32;
    pci::each(|function| {
        let class = pci::read32(function, 0x08) >> 16;
        if class == 0x0806 || class == 0x0600 || !pci::bus_master(function) {
            return;
        }
        pci::disable_dma(function);
        closed += 1;
    });
    let _ = writeln!(
        Serial,
        "AMDVI INHERITED-BME closed={closed} path=refusal step=R2 claims=none"
    );
}

/// One basic IRTE.
fn write_irte(table: u64, index: u16, irte: u32) {
    unsafe {
        core::ptr::write_volatile(
            (table + u64::from(index) * amdvi::IRTE_BYTES as u64) as *mut u32,
            irte,
        )
    };
}

/// The BSP's initial APIC ID (CPUID leaf 1 EBX[31:24]).
fn bsp_apic_id() -> u8 {
    (core::arch::x86_64::__cpuid(1).ebx >> 24) as u8
}

/// Programs the function's MSI capability for one message: address
/// 0xfee00000 with `dest` in bits 19:12 (the IRTE decides the destination
/// for remapped fixed interrupts), data `index`, MSI enabled. Configuration
/// writes to the MSI capability only.
fn program_msi(function: Function, index: u16, dest: u8) -> bool {
    let Some(cap) = amdvi::find_capability(|at| pci::read32(function, at), 0x05) else {
        return false;
    };
    let header = pci::read32(function, cap);
    let address = 0xfee0_0000 | (u32::from(dest) << 12);
    let Some((writes, used)) = amdvi::msi_writes(cap, header, address, index) else {
        return false;
    };
    for &(offset, value) in &writes[..used] {
        pci::write32(function, offset, value);
    }
    // Read every programmed register back: address, address-high (64-bit),
    // data, and the enable with one message.
    let wide = header & (1 << 23) != 0;
    let data_at = if wide { cap + 0x0c } else { cap + 0x08 };
    let control = pci::read32(function, cap);
    pci::read32(function, cap + 0x04) == address
        && (!wide || pci::read32(function, cap + 0x08) == 0)
        && pci::read32(function, data_at) & 0xffff == u32::from(index)
        && control & (1 << 16) != 0
        && control & (0b111 << 20) == 0
}

fn write_dte(devtab: u64, id: u16, entry: [u64; 4]) {
    let slot = (devtab + u64::from(id) * amdvi::DTE_BYTES as u64) as *mut u64;
    for (index, word) in entry.iter().enumerate() {
        unsafe { core::ptr::write_volatile(slot.add(index), *word) };
    }
}

/// ` role=<r>` on an NVMe or AHCI grant line (wire v4 ADD-1); nothing for
/// the edu.
struct Role(Kind, usize);

impl core::fmt::Display for Role {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            Kind::Nvme => write!(f, " role={}", NVME_ROLES[self.1]),
            Kind::Ahci => write!(f, " role={}", amdvi::AHCI_ROLES[self.1].0),
            Kind::Edu => Ok(()),
        }
    }
}

fn perm_word(perm: Perm) -> &'static str {
    match (perm.read, perm.write) {
        (true, true) => "rw",
        (true, false) => "r",
        _ => "w",
    }
}

/// The enforce-test boot: [`setup`], then the producer's own self-check
/// (one permitted transfer each way, writes the domain forbids; with an
/// AHCI target, [`ahci_check`] too). Never returns.
pub fn enforce_test(ahci: AhciSelection) -> ! {
    crate::serial::write("AMDVI ENFORCE START\n");
    crate::dma::enforce();
    // The deny-by-default sweep is the first DMA-relevant action apart from
    // the containment setup itself (the IOMMU's capability base gate and
    // MMIO programming; #111 increment 6, DESIGN §5).
    let mut session = match setup(ahci) {
        Ok(session) => {
            report_inherited(false, Some(&session));
            session
        }
        Err(_) => {
            report_inherited(false, None);
            close_inherited_masters_on_refusal();
            crate::serial::write("AMDVI ENFORCE FAILED\n");
            crate::exit_qemu(1)
        }
    };
    let bar = match pci::memory_bar(session.device(0).function, 0) {
        Ok(bar) => bar,
        Err(error) => refuse("device", format_args!("reason=bar-{error:?}")),
    };
    let edu = match crate::mmio::map(bar, 1 << 20, crate::mmio::Cache::Uncached) {
        Ok(address) => Edu(address),
        Err(error) => refuse("device", format_args!("reason=bar-map-{error:?}")),
    };
    let edu_grant = session.device(0).grant;
    let (source, target_page) = (edu_grant.pages()[0].0, edu_grant.pages()[1].0);
    let canary = page_address(core::ptr::addr_of!(CANARY));
    let pattern = |seed: u8| -> [u8; 64] { core::array::from_fn(|i| seed ^ (i as u8)) };
    let source_ptr = source as *mut u8;
    let target_ptr = target_page as *mut u8;
    let canary_ptr = canary as *mut u8;
    unsafe {
        core::ptr::copy_nonoverlapping(pattern(0x5a).as_ptr(), source_ptr, 64);
        core::ptr::write_bytes(target_ptr, 0, 64);
        core::ptr::write_bytes(canary_ptr, 0xcc, 64);
    }
    fence();
    let mut ok = edu.dma(source, 64, false) && edu.dma(target_page, 64, true);
    let copied = unsafe { core::slice::from_raw_parts(target_ptr, 64) } == pattern(0x5a);
    let _ = writeln!(
        Serial,
        "AMDVI SELFCHECK permitted read={} write={} payload={}",
        if ok { "done" } else { "timeout" },
        if ok { "done" } else { "timeout" },
        if copied { "match" } else { "mismatch" }
    );
    ok &= copied;
    // Writes the domain forbids: into the never-granted canary and into the
    // read-only page. First stage a pattern neither page holds in the
    // device buffer, through the readable page, and verify the staging by a
    // permitted write to TARGET; then put SOURCE back to its own pattern.
    unsafe {
        core::ptr::copy_nonoverlapping(pattern(0xa5).as_ptr(), source_ptr, 64);
        core::ptr::write_bytes(target_ptr, 0, 64);
    }
    fence();
    let staged = edu.dma(source, 64, false)
        && edu.dma(target_page, 64, true)
        && unsafe { core::slice::from_raw_parts(target_ptr, 64) } == pattern(0xa5);
    unsafe {
        core::ptr::copy_nonoverlapping(pattern(0x5a).as_ptr(), source_ptr, 64);
    }
    fence();
    let _ = writeln!(
        Serial,
        "AMDVI SELFCHECK staged device-buffer={}",
        if staged { "verified" } else { "unverified" }
    );
    let forbidden_done = staged && edu.dma(canary, 64, true) && edu.dma(source, 64, true);
    let canary_intact = unsafe { core::slice::from_raw_parts(canary_ptr, 64) }
        .iter()
        .all(|&b| b == 0xcc);
    let source_intact = unsafe { core::slice::from_raw_parts(source_ptr, 64) } == pattern(0x5a);
    let _ = writeln!(
        Serial,
        "AMDVI SELFCHECK forbidden device={} canary={} read-only-page={}",
        if forbidden_done { "done" } else { "timeout" },
        if canary_intact { "intact" } else { "written" },
        if source_intact { "intact" } else { "written" }
    );
    ok &= forbidden_done && canary_intact && source_intact;
    let target = session.device(0).target;
    let mut from_target = 0usize;
    let (count, overflow) = session.drain(&mut |event, raw, record| {
        report_event(event, raw, record);
        from_target +=
            usize::from(matches!(event, Event::IoPageFault { devid, .. } if *devid == target));
    });
    let _ = writeln!(
        Serial,
        "AMDVI SELFCHECK events={count} io-page-faults-from-target={from_target} overflow={}",
        if overflow { "yes" } else { "no" }
    );
    // #123: the AHCI target's own checks, while the unit is healthy (the
    // edu's lifetime check below ends by failing the unit).
    let ahci = session.devices[1]
        .is_some_and(|device| device.kind == Kind::Ahci)
        .then(|| ahci_check(&mut session));
    if let Some(verdicts) = ahci {
        ok &= verdicts.ok();
    }
    ok &= lifetime_check(&mut session, &edu);
    crate::serial::write(if ok {
        "AMDVI ENFORCE OK\n"
    } else {
        "AMDVI ENFORCE FAILED\n"
    });
    if let Some(verdicts) = ahci {
        evidence(ok, &verdicts);
    }
    crate::exit_qemu(if ok { 0 } else { 1 })
}

/// The AHCI self-check's verdicts (#123), for the final result and the
/// screen summary.
#[derive(Clone, Copy)]
struct AhciVerdicts {
    permitted: bool,
    forbidden: bool,
    faults: usize,
    revoke: bool,
    lifetime: bool,
}

impl AhciVerdicts {
    fn ok(&self) -> bool {
        self.permitted && self.forbidden && self.revoke && self.lifetime
    }
}

fn completion_word(
    result: &Result<(u64, Completion), crate::ahci_block::AhciError>,
) -> &'static str {
    match result {
        Ok((_, Completion::Done)) => "done",
        Ok((_, Completion::TaskFile { .. })) => "device-error",
        Ok((_, Completion::ShortTransfer { .. })) => "short-transfer",
        Ok((_, Completion::Timeout)) => "timeout",
        Err(crate::ahci_block::AhciError::Refused(crate::ahci_block::Refusal::NotContained)) => {
            "refused-not-contained"
        }
        Err(crate::ahci_block::AhciError::OutOfRange) => "refused-out-of-range",
        Err(crate::ahci_block::AhciError::Absent) => "refused-no-port",
        Err(crate::ahci_block::AhciError::Retired) => "refused-retired",
        Err(_) => "refused",
    }
}

fn pattern_page(address: u64, seed: u8) {
    let page = address as *mut u8;
    for at in 0..PAGE as usize {
        unsafe {
            page.add(at)
                .write_volatile(seed ^ (at as u8) ^ ((at >> 8) as u8))
        };
    }
}

fn page_holds(address: u64, seed: u8) -> bool {
    let page = address as *const u8;
    (0..PAGE as usize)
        .all(|at| unsafe { page.add(at).read_volatile() } == seed ^ (at as u8) ^ ((at >> 8) as u8))
}

/// The AHCI target's self-check (#123), device 1 of the session: a
/// permitted read of LBA 0 through the bounce page; a read whose PRDT
/// address is an ungranted canary (the canary must not change, and the
/// unit's IO page faults from the controller are counted); revoke (R1–R4)
/// with a later read refused; restart on set 2, reading LBA 0 again to the
/// same data; a read aimed at the retained set 1's bounce page (unchanged);
/// revoke again and a second restart refused CONTAINED_BUT_UNUSABLE.
fn ahci_check(session: &mut Session) -> AhciVerdicts {
    let target = session.device(1).target;
    let function = session.device(1).function;
    let mut first = [0u8; 512];
    let permitted = crate::ahci_block::read_sector(0, &mut first).is_ok();
    let digest = crate::block::fnv1a(&first);
    let _ = writeln!(
        Serial,
        "AMDVI AHCI permitted lba=0 read={} fnv1a={digest:#018x}",
        if permitted { "done" } else { "failed" }
    );
    // Forbidden: the PRDT entry aimed at a page no domain grants. Events
    // before it are reported and not counted.
    let canary = page_address(core::ptr::addr_of!(CANARY2));
    pattern_page(canary, 0xc3);
    fence();
    let _ = session.drain(&mut |event, raw, record| report_event(event, raw, record));
    let aimed = crate::ahci_block::read_raw(0, 1, Some(canary));
    fence();
    let unchanged = page_holds(canary, 0xc3);
    let mut faults = 0usize;
    let _ = session.drain(&mut |event, raw, record| {
        report_event(event, raw, record);
        faults +=
            usize::from(matches!(event, Event::IoPageFault { devid, .. } if *devid == target));
    });
    // Liveness: the port still serves, with the same data.
    let mut again = [0u8; 512];
    let live = crate::ahci_block::read_sector(0, &mut again).is_ok() && again == first;
    let _ = writeln!(
        Serial,
        "AMDVI AHCI forbidden dba={canary:#x} status={} canary={} io-page-faults-from-target={faults} liveness={}",
        completion_word(&aimed),
        if unchanged { "unchanged" } else { "written" },
        if live { "ok" } else { "failed" }
    );
    // QEMU reports a PRDT write the domain denied as a completed command:
    // anything but Done (a timeout retires the port) fails the check, as
    // does a denial the unit did not report.
    let forbidden = matches!(aimed, Ok((_, Completion::Done))) && unchanged && faults > 0 && live;
    // Revoke (R1–R4): nothing is served afterwards.
    let first_revoke = session.revoke_device(1);
    let mut later = [0u8; 512];
    let refused = crate::ahci_block::read_sector(0, &mut later).is_err();
    let bme_clear = !pci::bus_master(function);
    let uncontained = crate::dma::contained(function).is_none();
    let _ = writeln!(
        Serial,
        "AMDVI AHCI REVOKED r3={} later-read={} bme={} contained-registry={}",
        if first_revoke { "completed" } else { "timeout" },
        if refused { "refused" } else { "served" },
        if bme_clear { "clear" } else { "on" },
        if uncontained { "released" } else { "held" }
    );
    let revoke = first_revoke && refused && bme_clear && uncontained;
    // Restart on set 2: the same LBA reads the same data.
    let restarted = session.restart(1);
    let mut second = [0u8; 512];
    let matched = restarted == Ok(1)
        && crate::ahci_block::read_sector(0, &mut second).is_ok()
        && second == first;
    // The retained set 1's bounce page, aimed at from set 2: the command
    // completes (Done), the page is unchanged, the unit reports the denial,
    // and a permitted read afterwards returns the same data.
    let old_bounce = crate::ahci_block::dma_pages(0)[3];
    pattern_page(old_bounce, 0x77);
    fence();
    let _ = session.drain(&mut |event, raw, record| report_event(event, raw, record));
    let aimed_old = if restarted == Ok(1) {
        crate::ahci_block::read_raw(0, 1, Some(old_bounce))
    } else {
        Err(crate::ahci_block::AhciError::Absent)
    };
    fence();
    let old_unchanged = page_holds(old_bounce, 0x77);
    let mut retained_faults = 0usize;
    let _ = session.drain(&mut |event, raw, record| {
        report_event(event, raw, record);
        retained_faults +=
            usize::from(matches!(event, Event::IoPageFault { devid, .. } if *devid == target));
    });
    let mut after = [0u8; 512];
    let after_match = restarted == Ok(1)
        && crate::ahci_block::read_sector(0, &mut after).is_ok()
        && after == first;
    let retained = matches!(aimed_old, Ok((_, Completion::Done)))
        && old_unchanged
        && retained_faults > 0
        && after_match;
    let second_revoke = session.revoke_device(1);
    let exhausted = session.restart(1);
    let _ = writeln!(
        Serial,
        "AMDVI AHCI LIFETIME restart={} read={} retained-set1={} retained-status={} retained-faults={retained_faults} after={} second-restart={}",
        match restarted {
            Ok(1) => "set2",
            Ok(_) => "wrong-set",
            Err(reason) => reason,
        },
        if matched { "match" } else { "mismatch" },
        if old_unchanged {
            "unchanged"
        } else {
            "written"
        },
        completion_word(&aimed_old),
        if after_match { "match" } else { "mismatch" },
        exhausted.err().unwrap_or("accepted")
    );
    let lifetime = matched
        && retained
        && second_revoke
        && exhausted == Err("CONTAINED_BUT_UNUSABLE")
        && !pci::bus_master(function);
    AhciVerdicts {
        permitted,
        forbidden,
        faults,
        revoke,
        lifetime,
    }
}

/// A short line built on the stack, for the screen-only summary.
struct Line {
    bytes: [u8; 96],
    len: usize,
}

impl Line {
    fn new() -> Line {
        Line {
            bytes: [0; 96],
            len: 0,
        }
    }

    fn text(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("?")
    }
}

impl core::fmt::Write for Line {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let room = self.bytes.len() - self.len;
        if text.len() > room {
            return Err(core::fmt::Error);
        }
        self.bytes[self.len..self.len + text.len()].copy_from_slice(text.as_bytes());
        self.len += text.len();
        Ok(())
    }
}

/// No-UART evidence (docs/hardware/NO-UART-EVIDENCE.md): the digest of
/// every console byte before this line, on serial and screen, then a
/// screen-only summary of the verdicts.
fn evidence(ok: bool, verdicts: &AhciVerdicts) {
    let (bytes, digest) = crate::serial::evidence();
    let dropped = crate::serial::tx_dropped();
    let _ = writeln!(
        Serial,
        "EVIDENCE DIGEST bytes={bytes} fnv1a={digest:016x} tx-dropped={dropped}"
    );
    let word = |pass: bool| if pass { "ok" } else { "FAILED" };
    let mut line = Line::new();
    let _ = write!(
        line,
        "AHCI CONTAINMENT {} permitted={} forbidden={} revoke={} lifetime={} faults=",
        if ok { "OK" } else { "FAILED" },
        word(verdicts.permitted),
        word(verdicts.forbidden),
        word(verdicts.revoke),
        word(verdicts.lifetime)
    );
    crate::framebuffer::notice(line.text(), verdicts.faults as u64);
    let mut line = Line::new();
    let _ = write!(line, "AHCI EVIDENCE digest={digest:016x} bytes=");
    crate::framebuffer::notice(line.text(), bytes);
}

/// Increments 4–5 in the self-check: revoke (R1–R5), restart onto set 2
/// (DMA there works, the retained set 1 stays unreachable), revoke again,
/// restart refused CONTAINED_BUT_UNUSABLE; then an illegal command fails the
/// unit (BME cleared, R2 only) and every later restart is refused.
fn lifetime_check(session: &mut Session, edu: &Edu) -> bool {
    let pattern = |seed: u8| -> [u8; 64] { core::array::from_fn(|i| seed ^ (i as u8)) };
    let old_target = session.device(0).grant.pages()[1].0;
    let first = session.revoke_device(0);
    let restarted = session.restart(0);
    let mut set2_ok = false;
    let mut old_intact = false;
    if let Ok(1) = restarted {
        let edu_grant = session.device(0).grant;
        let (source, target) = (edu_grant.pages()[0].0, edu_grant.pages()[1].0);
        unsafe {
            core::ptr::copy_nonoverlapping(pattern(0x3c).as_ptr(), source as *mut u8, 64);
            core::ptr::write_bytes(target as *mut u8, 0, 64);
            core::ptr::write_bytes(old_target as *mut u8, 0x77, 64);
        }
        fence();
        set2_ok = edu.dma(source, 64, false)
            && edu.dma(target, 64, true)
            && unsafe { core::slice::from_raw_parts(target as *const u8, 64) } == pattern(0x3c);
        // The device buffer now holds the pattern; a write to the retained
        // set must not land.
        let done = edu.dma(old_target, 64, true);
        old_intact = done
            && unsafe { core::slice::from_raw_parts(old_target as *const u8, 64) }
                .iter()
                .all(|&b| b == 0x77);
    }
    let _ = writeln!(
        Serial,
        "AMDVI LIFETIME restart={} set2-transfer={} retained-set1-write={}",
        match restarted {
            Ok(set) =>
                if set == 1 {
                    "set2"
                } else {
                    "wrong-set"
                },
            Err(reason) => reason,
        },
        if set2_ok { "match" } else { "failed" },
        if old_intact {
            "blocked"
        } else {
            "landed-or-timeout"
        }
    );
    let second = session.revoke_device(0);
    let exhausted = session.restart(0);
    let _ = writeln!(
        Serial,
        "AMDVI LIFETIME second-restart={} unusable={}",
        exhausted.err().unwrap_or("accepted"),
        if session.device(0).sets.unusable() {
            "CONTAINED_BUT_UNUSABLE"
        } else {
            "no"
        }
    );
    // A failed unit: an illegal command (opcode 0Fh) on the ring.
    session.rings.submit([0, 0xf << 28, 0, 0]);
    let _ = session.rings.wait("illegal-command");
    let _ = session.drain(&mut |event, raw, record| report_event(event, raw, record));
    let after_failure = session.restart(0);
    let _ = writeln!(
        Serial,
        "AMDVI LIFETIME unit={} restart-after-failure={} bme={}",
        session.health.failed().map_or("ok", |r| r.word()),
        after_failure.err().unwrap_or("accepted"),
        if pci::bus_master(session.device(0).function) {
            "on"
        } else {
            "clear"
        }
    );
    first
        && second
        && restarted == Ok(1)
        && set2_ok
        && old_intact
        && exhausted == Err("CONTAINED_BUT_UNUSABLE")
        && session.health.failed().is_some()
        && after_failure == Err("unit-failed")
        && !pci::bus_master(session.device(0).function)
}

// --- The oracle protocol (amdvi-oracle INTERFACE.md, version 2) ------------

const MAILBOX_MAGIC: u64 = 0x3145_4c43_4152_4f41;
/// Mailbox u64 slots by index (byte offset / 8): seq 08h, opcode 10h,
/// arg0 18h, ack_seq 40h, status 48h.
const SLOT_SEQ: usize = 1;
const SLOT_OPCODE: usize = 2;
const SLOT_ARG0: usize = 3;
const SLOT_ACK: usize = 8;
const SLOT_STATUS: usize = 9;

/// Interrupts off, `hlt` forever.
fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

fn mailbox() -> *mut u64 {
    core::ptr::addr_of_mut!(MAILBOX) as *mut u64
}

fn slot(index: usize) -> u64 {
    unsafe { core::ptr::read_volatile(mailbox().add(index)) }
}

fn set_slot(index: usize, value: u64) {
    unsafe { core::ptr::write_volatile(mailbox().add(index), value) }
}

/// Mailbox slots added for opcode 6 (NVME_READ, #116): block count 28h,
/// PRP1 30h (0: the driver's own bounce page). Opcode 7 (AHCI_READ, #123)
/// uses the same slots for its block count and PRDT data base address.
const SLOT_BLOCKS: usize = 5;
const SLOT_PRP1: usize = 6;

/// The oracle boot (`amdvi-oracle=1`): [`setup`] without any self-check,
/// the declared lines, then mailbox commands until FINISH. ABSD does not
/// touch `edu` after `READY`. Never returns. With an NVMe controller present
/// (#116 two-device mode) the grant lines name their device and opcodes 2
/// and 5 take a device selector in arg0, opcode 6 reads through the NVMe
/// driver; without one every line and opcode is exactly interface v3.3.
/// With the AHCI controller as the second target (#123, `ahci-disk=`) the
/// AHCI line replaces the NVME line and opcode 7 reads through the AHCI
/// backend instead of opcode 6.
pub fn oracle(ahci: AhciSelection) -> ! {
    ORACLE_BOOT.store(true, core::sync::atomic::Ordering::Relaxed);
    crate::dma::enforce();
    crate::serial::write("AMDVI-ORACLE HELLO version=2\n");
    unsafe { core::ptr::write_bytes(mailbox() as *mut u8, 0, PAGE as usize) };
    set_slot(0, MAILBOX_MAGIC);
    fence();
    let mailbox_pa = page_address(core::ptr::addr_of!(MAILBOX));
    let mut session = match setup(ahci) {
        Ok(session) => {
            let two = session.devices[1].is_some();
            // Wire v4 draft §3: in two-device mode INHERITED precedes the
            // TARGET lines (single-edu keeps the v3.3 order, below).
            if two {
                report_inherited(true, Some(&session));
            }
            for device in session.devices.iter().flatten() {
                let _ = writeln!(
                    Serial,
                    "AMDVI-ORACLE TARGET devid={:#06x} domain={:#06x}",
                    device.target, device.domain
                );
                for (at, &(page, perm)) in device.grant.pages().iter().enumerate() {
                    if two {
                        let _ = writeln!(
                            Serial,
                            "AMDVI-ORACLE GRANT devid={:#06x} iova={page:#x} pa={page:#x} perm={}{}",
                            device.target,
                            perm_word(perm),
                            Role(device.kind, at)
                        );
                    } else {
                        let _ = writeln!(
                            Serial,
                            "AMDVI-ORACLE GRANT iova={page:#x} pa={page:#x} perm={}",
                            perm_word(perm)
                        );
                    }
                }
            }
            // Interrupt grant (interface v3.3 `irq`): the edu only.
            let _ = writeln!(
                Serial,
                "AMDVI-ORACLE IRGRANT devid={:#06x} index={:#x} vector={:#x} dest={:#x}",
                session.device(0).target,
                amdvi::IR_INDEX,
                amdvi::IR_VECTOR,
                session.ir_dest
            );
            if let (Some(device), Some(facts)) = (session.devices[1], session.nvme) {
                let _ = writeln!(
                    Serial,
                    "AMDVI-ORACLE NVME devid={:#06x} namespace={} sectors={} lba-bytes=512 ioqid={} qsize={} msix=masked iocq-vector={NVME_IOCQ_VECTOR}",
                    device.target, facts.namespace, facts.sectors, facts.ioqid, facts.qsize
                );
            }
            if let (Some(device), Some(facts)) = (session.devices[1], session.ahci) {
                let _ = writeln!(
                    Serial,
                    "AMDVI-ORACLE AHCI devid={:#06x} port={} sectors={} lba-bytes=512",
                    device.target, facts.port, facts.sectors
                );
            }
            for canary in [
                page_address(core::ptr::addr_of!(CANARY)),
                page_address(core::ptr::addr_of!(CANARY2)),
            ] {
                let _ = writeln!(Serial, "AMDVI-ORACLE CANARY pa={canary:#x}");
            }
            Some(session)
        }
        Err(Unavailable(word)) => {
            let _ = writeln!(Serial, "AMDVI-ORACLE UNAVAILABLE reason={word}");
            None
        }
    };
    // Inherited bus masters, now that the unit is enabled (or refused).
    if !session.as_ref().is_some_and(|s| s.devices[1].is_some()) {
        report_inherited(true, session.as_ref());
    }
    // Enforced path: inherited masters are left as they are (the sweep is
    // the containment judged; the decoy is the oracle's). Refusal path:
    // nothing contains them, so they are closed, R2 only.
    if session.is_none() {
        close_inherited_masters_on_refusal();
    }
    let _ = writeln!(Serial, "AMDVI-ORACLE MAILBOX pa={mailbox_pa:#x}");
    // The mailbox was zeroed before it was announced, so any seq the oracle
    // writes from here on differs from this.
    let mut last = slot(SLOT_SEQ);
    fence();
    crate::serial::write("AMDVI-ORACLE READY\n");
    loop {
        let seq = slot(SLOT_SEQ);
        if seq == last {
            core::hint::spin_loop();
            continue;
        }
        last = seq;
        fence();
        let opcode = slot(SLOT_OPCODE);
        let arg0 = slot(SLOT_ARG0);
        let second = session
            .as_ref()
            .and_then(|s| s.devices[1])
            .map(|device| device.kind);
        let done = match (opcode, session.as_mut()) {
            (4, _) => {
                let _ = writeln!(Serial, "AMDVI-ORACLE BYE seq={seq}");
                set_slot(SLOT_STATUS, 0);
                fence();
                set_slot(SLOT_ACK, seq);
                // INTERFACE v2 §4: halt, never exit QEMU; the oracle still
                // reads the mailbox and registers and stops QEMU itself.
                halt()
            }
            (1, Some(session)) => revoke_page(session, seq, arg0),
            (2, Some(session)) => match select(session, seq, arg0) {
                Some(which) => revoke_device(session, seq, which),
                None => false,
            },
            (3, Some(session)) => sync(session, seq),
            (5, Some(session)) => match select(session, seq, arg0) {
                Some(which) => restart(session, seq, which),
                None => false,
            },
            (6, Some(session)) if second == Some(Kind::Nvme) => nvme_read(session, seq, arg0),
            (7, Some(session)) if second == Some(Kind::Ahci) => ahci_read(session, seq, arg0),
            (1..=3 | 5, None) => {
                let _ = writeln!(Serial, "AMDVI-ORACLE REFUSED seq={seq} reason=unavailable");
                false
            }
            _ => {
                let _ = writeln!(
                    Serial,
                    "AMDVI-ORACLE REFUSED seq={seq} reason=unknown-opcode"
                );
                false
            }
        };
        set_slot(SLOT_STATUS, if done { 0 } else { 1 });
        fence();
        set_slot(SLOT_ACK, seq);
    }
}

/// The device opcodes 2 and 5 act on. Single-edu boots ignore arg0 (v3.3:
/// it carries nothing); the two-device boot reads it as a DeviceID, 0 for
/// the edu (wire v4 draft).
fn select(session: &Session, seq: u64, arg0: u64) -> Option<usize> {
    let Some(second) = session.devices[1] else {
        return Some(0);
    };
    if arg0 == 0 || arg0 == u64::from(session.device(0).target) {
        Some(0)
    } else if arg0 == u64::from(second.target) {
        Some(1)
    } else {
        let _ = writeln!(Serial, "AMDVI-ORACLE REFUSED seq={seq} reason=not-a-target");
        None
    }
}

fn revoke_page(session: &mut Session, seq: u64, iova: u64) -> bool {
    // Grants are disjoint (refused at admission otherwise), so the IOVA
    // names its device.
    let found = (0..amdvi::MAX_TARGETS).find_map(|which| {
        let device = session.devices[which]?;
        device
            .grant
            .pages()
            .iter()
            .position(|&(page, _)| page == iova)
            .map(|at| (which, at))
    });
    let Some((which, at)) = found else {
        let _ = writeln!(Serial, "AMDVI-ORACLE REFUSED seq={seq} reason=not-granted");
        return false;
    };
    let device = session.device(which);
    if device.revoked[at] || device.device_revoked {
        let _ = writeln!(
            Serial,
            "AMDVI-ORACLE REFUSED seq={seq} reason=already-revoked"
        );
        return false;
    }
    // #123: the AHCI command list and FIS area are used from a mapping the
    // controller takes when ST and FRE are set; revoking one alone would be
    // acknowledged without being enforced. Refused, the grant left intact
    // (device revocation stops the engine in R4).
    if device.kind == Kind::Ahci && !amdvi::ahci_page_revocable(at) {
        let _ = writeln!(
            Serial,
            "AMDVI-ORACLE REFUSED seq={seq} reason=engine-cached-page"
        );
        return false;
    }
    if amdvi::unmap(&mut session.tables, device.root, iova).is_err() {
        let _ = writeln!(Serial, "AMDVI-ORACLE REFUSED seq={seq} reason=not-mapped");
        return false;
    }
    fence();
    session
        .rings
        .submit(amdvi::invalidate_page(device.invalidation_domain(), iova));
    if !session.complete("revoke-page") {
        let _ = writeln!(
            Serial,
            "AMDVI-ORACLE REFUSED seq={seq} reason=no-completion"
        );
        return false;
    }
    session.device_mut(which).revoked[at] = true;
    let _ = writeln!(
        Serial,
        "AMDVI-ORACLE REVOKED seq={seq} scope=page iova={iova:#x} cw-store={:#x} cw-data={:#x}",
        session.rings.store, session.rings.last
    );
    true
}

fn revoke_device(session: &mut Session, seq: u64, which: usize) -> bool {
    if session.device(which).device_revoked {
        let _ = writeln!(
            Serial,
            "AMDVI-ORACLE REFUSED seq={seq} reason=already-revoked"
        );
        return false;
    }
    if !session.revoke_device(which) {
        let _ = writeln!(
            Serial,
            "AMDVI-ORACLE REFUSED seq={seq} reason=no-completion"
        );
        return false;
    }
    let _ = writeln!(
        Serial,
        "AMDVI-ORACLE REVOKED seq={seq} scope=device devid={:#06x} cw-store={:#x} cw-data={:#x}",
        session.device(which).target,
        session.rings.store,
        session.rings.last
    );
    true
}

fn restart(session: &mut Session, seq: u64, which: usize) -> bool {
    let two = session.devices[1].is_some();
    match session.restart(which) {
        Ok(set) => {
            let device = session.device(which);
            for (at, &(page, perm)) in device.grant.pages().iter().enumerate() {
                if two {
                    let _ = writeln!(
                        Serial,
                        "AMDVI-ORACLE GRANT seq={seq} set={} devid={:#06x} iova={page:#x} pa={page:#x} perm={}{}",
                        set + 1,
                        device.target,
                        perm_word(perm),
                        Role(device.kind, at)
                    );
                } else {
                    let _ = writeln!(
                        Serial,
                        "AMDVI-ORACLE GRANT seq={seq} set={} iova={page:#x} pa={page:#x} perm={}",
                        set + 1,
                        perm_word(perm)
                    );
                }
            }
            if two {
                let _ = writeln!(
                    Serial,
                    "AMDVI-ORACLE RESTARTED seq={seq} set={} devid={:#06x} domain={:#06x} cw-store={:#x} cw-data={:#x}",
                    set + 1,
                    device.target,
                    device.domain,
                    session.rings.store,
                    session.rings.last
                );
            } else {
                let _ = writeln!(
                    Serial,
                    "AMDVI-ORACLE RESTARTED seq={seq} set={} domain={DOMAIN:#06x} cw-store={:#x} cw-data={:#x}",
                    set + 1,
                    session.rings.store,
                    session.rings.last
                );
            }
            true
        }
        Err(reason) => {
            let _ = writeln!(Serial, "AMDVI-ORACLE REFUSED seq={seq} reason={reason}");
            false
        }
    }
}

/// Opcode 6, NVME_READ (#116 wire v4 draft): one READ through the NVMe
/// driver's real queues, `lba` = arg0, blocks from slot 28h, PRP1 from slot
/// 30h (0: the bounce page). The PRP1 is not checked by ABSD: the NVMe's
/// domain alone decides what the controller reaches (the hostile leg).
/// Status 0 whenever the command completed, whatever its NVMe status.
fn nvme_read(session: &mut Session, seq: u64, lba: u64) -> bool {
    let device = session.device(1);
    let refuse = |reason: &str| {
        let _ = writeln!(Serial, "AMDVI-ORACLE REFUSED seq={seq} reason={reason}");
        false
    };
    if session.health.failed().is_some() {
        return refuse("unit-failed");
    }
    if device.device_revoked {
        return refuse("revoked");
    }
    let blocks = slot(SLOT_BLOCKS);
    let prp1 = slot(SLOT_PRP1);
    if !(1..=8).contains(&blocks) {
        return refuse("out-of-range");
    }
    match crate::nvme::read_raw(lba, blocks as usize, (prp1 != 0).then_some(prp1)) {
        Ok((used, status)) => {
            let _ = writeln!(
                Serial,
                "AMDVI-ORACLE NVMEREAD seq={seq} devid={:#06x} lba={lba:#x} blocks={blocks} prp1={used:#x} status={status:#x}",
                device.target
            );
            true
        }
        Err(crate::nvme::NvmeError::Refused(crate::nvme::Refusal::NotContained)) => {
            refuse("not-contained")
        }
        Err(crate::nvme::NvmeError::OutOfRange) => refuse("out-of-range"),
        Err(crate::nvme::NvmeError::Absent) => refuse("revoked"),
        Err(_) => refuse("timeout"),
    }
}

/// Opcode 7, AHCI_READ (#123): one READ DMA EXT through the AHCI backend's
/// port, `lba` = arg0, blocks from slot 28h, the PRDT data base address
/// from slot 30h (0: the bounce page). The address is not checked by ABSD:
/// the AHCI's domain alone decides what the controller reaches. Status is
/// the completion (`done`, `device-error`, `short-transfer`, `timeout`).
fn ahci_read(session: &mut Session, seq: u64, lba: u64) -> bool {
    let device = session.device(1);
    let refuse = |reason: &str| {
        let _ = writeln!(Serial, "AMDVI-ORACLE REFUSED seq={seq} reason={reason}");
        false
    };
    if session.health.failed().is_some() {
        return refuse("unit-failed");
    }
    if device.device_revoked {
        return refuse("revoked");
    }
    let blocks = slot(SLOT_BLOCKS);
    let dba = slot(SLOT_PRP1);
    if !(1..=8).contains(&blocks) {
        return refuse("out-of-range");
    }
    let result = crate::ahci_block::read_raw(lba, blocks as usize, (dba != 0).then_some(dba));
    match result {
        Ok((used, _)) => {
            let _ = writeln!(
                Serial,
                "AMDVI-ORACLE AHCIREAD seq={seq} devid={:#06x} lba={lba:#x} blocks={blocks} dba={used:#x} status={}",
                device.target,
                completion_word(&result)
            );
            true
        }
        Err(crate::ahci_block::AhciError::Refused(crate::ahci_block::Refusal::NotContained)) => {
            refuse("not-contained")
        }
        Err(crate::ahci_block::AhciError::OutOfRange) => refuse("out-of-range"),
        Err(crate::ahci_block::AhciError::Absent) => refuse("revoked"),
        Err(crate::ahci_block::AhciError::Retired) => refuse("retired"),
        Err(_) => refuse("refused"),
    }
}

fn sync(session: &mut Session, seq: u64) -> bool {
    let (faults, overflow) = session.drain(&mut |_, raw, _| {
        let _ = writeln!(
            Serial,
            "AMDVI-ORACLE FAULT seq={seq} code={:#x} devid={:#06x} domain={:#06x} addr={:#x} flags={:#x}",
            raw[1] >> 28,
            raw[0] & 0xffff,
            raw[1] & 0xffff,
            u64::from(raw[2]) | (u64::from(raw[3]) << 32),
            (raw[1] >> 16) & 0xfff
        );
    });
    let _ = writeln!(
        Serial,
        "AMDVI-ORACLE SYNCED seq={seq} faults={faults} overflow={} record={} unit={}",
        u8::from(overflow),
        if session.record.complete() {
            "complete"
        } else {
            "incomplete"
        },
        if session.health.failed().is_some() {
            "failed"
        } else {
            "ok"
        }
    );
    true
}
