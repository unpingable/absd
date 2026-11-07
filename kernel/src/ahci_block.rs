//! One SATA disk behind one AHCI port as the block device (coordination record #45,
//! #123 step 3): polled, one command at a time, no NCQ.
//!
//! Probed only when the boot names a disk by its IDENTIFY serial number:
//! `ahci-disk=SERIAL` (read-only) or `ahci-write=SERIAL` (read-write, the
//! only way an AHCI disk becomes writable). Neither NVMe nor the ATA PIO
//! master is tried then, so a missing or refused disk leaves the boot with
//! no block device rather than a different one. Until AMD-Vi containment of
//! the controller exists (#123), no controller is taken over outside a VM
//! (CPUID hypervisor bit clear) or unless it is QEMU's emulated ICH9
//! (`ahci_command::emulated_controller`), in either access mode, and a disk
//! is served writable only if it is QEMU's or the boot contains the controller
//! (`write_admitted`): neither an ordinary physical boot nor a VM with a
//! passed-through controller gets bus mastering or a write without a domain.
//! These are identity checks that stop operator error, not forgery.
//!
//! Exclusive takeover of a dedicated controller (owner decision, #123): the
//! backend owns the whole controller or none of it, never shares it with
//! firmware. A controller must first be shown available by configuration
//! and register reads alone, with nothing written: memory decoding must
//! already be on (turning it on would be a write), INTx and bus mastering
//! are left as found, and the ABAR is not yet sized
//! (sizing writes configuration space), with only the register span the
//! AHCI specification guarantees mapped. It is refused as the census
//! refuses (RAID class or Intel RST RAID ids, non-AHCI interfaces,
//! BIOS-owned HBAs, AHCI mode off), without 64-bit addressing when a buffer
//! needs it, with a port implemented beyond CAP.NP, and when any
//! implemented port is not idle (a command issued or queued, PxCI or
//! PxSACT). A controller refused there keeps its PCI command and port state
//! as found, and the refusal reports the configuration and AHCI register
//! writes counted since the checks began. Only then does the takeover write
//! anything: bus mastering off (firmware may have left it on), the ABAR
//! sized and required to hold every implemented port, INTx masked, and idle
//! engines firmware left running stopped. A failure after that point
//! leaves bus mastering off and the changed state as it stands. Stopped
//! engines stay stopped for the rest of the boot, whether or not a disk is
//! then served, because the controller is ABSD's alone. The HBA is never
//! reset and AHCI mode is never turned on. Each port with an active link,
//! an ATA signature and FIS-based switching off gets IDENTIFY DEVICE
//! through this module's static command list, FIS area, command table and
//! bounce page (identity-mapped, so each static's address is its bus
//! address). The first whose serial matches becomes the block device and
//! keeps those buffers with its engine running; every other probed port
//! gets the firmware's bases, interrupt enables and command bits back with
//! its engines off (only the PxIS/PxSERR status IDENTIFY cleared stays
//! cleared). The disk must report LBA48 and 512-byte logical sectors
//! (`ahci_command::admit_device`).
//!
//! Transfers are READ DMA EXT and WRITE DMA EXT of one to eight sectors
//! through the one bounce page (one PRDT entry), and FLUSH CACHE EXT for
//! `flush`. Completion is polled on PxCI and PxIS.TFES with the port's
//! interrupts off (PxIE = 0, INTx masked in the PCI command). Polls spin
//! and never halt, so the TSC backstop bounds every wait even if no
//! interrupt ever arrives; the tick bound applies while the timer runs. A
//! completed transfer must report the whole byte count (PRDBC), and Device
//! Fault is never a success.
//!
//! Failure (`ahci_command::recover`): the engine is stopped (ST off, CR
//! clear within the bound). A device error on an engine shown stopped,
//! with the device idle, restarts the engine and fails only that request.
//! A timeout, a device left busy, or a stop that cannot be shown retires
//! the port for the rest of the boot with bus mastering off before anything
//! is printed. After a failed stop the buffers are retired as well and
//! nothing is handed to a controller again, not even by a later probe (the
//! census's `survey_facts::ahci_after_stop` rule). There is no COMRESET and
//! no restart of a retired port.
//!
//! Buffer sets and AMD-Vi containment (#123, docs/hardware/SATA-AHCI-BLOCK.md
//! "Containment"): the command list, received FIS, command table and
//! bounce page are one page each, in `DMA_SETS` sets of `DMA_PAGES`
//! (`dma_pages`). Every ordinary boot uses set 0 only. The AMD-Vi boot
//! (`amdvi-enforce-test` or `amdvi-oracle=1` with `ahci-disk=`) grants one
//! set at a time to the controller's own domain, probes exactly the pinned
//! function (`probe_function`), and revokes as the NVMe driver does:
//! `withdraw` (R1: nothing more is issued), then, after the caller has
//! cleared bus mastering (R2) and blocked the domain (R3),
//! `Withdrawn::reset` (R4: ST then FRE off, bounded). A restart probes again
//! on the next set; a revoked set is never handed to a controller again.
//! The slice gates above apply unchanged in that boot too.
//!
//! Contract with the block layer (src/block.rs): a write returns after the
//! device reported the command complete (QEMU: after its host write
//! returned); `flush` returns after FLUSH CACHE EXT completed (QEMU: host
//! `fdatasync`), so every write completed before it is stable.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering, fence};

use absd_kernel::ahci_command::{self as rules, Completion, Op, Recovery, Selection, Stop};
use absd_kernel::amdvi::{self, scope::Driver};
use absd_kernel::dma_policy;
use absd_kernel::survey_facts as facts;
use absd_kernel::syscall::BLOCK_SECTOR_BYTES;

use crate::ahci::{
    ABAR, BOHC_BOS, CAP2_BOH, CLASS_MASS_STORAGE, CMD_CR, CMD_FR, CMD_FRE, CMD_ST, FBS_EN, GHC_AE,
    INTERFACE_AHCI, MAX_PORTS, PORT_BASE, PORT_STRIDE, PX_CI, PX_CLB, PX_CLBU, PX_CMD, PX_FB,
    PX_FBS, PX_FBU, PX_IS, PX_SERR, PX_SIG, PX_SSTS, PX_TFD, REG_BOHC, REG_CAP, REG_CAP2, REG_GHC,
    REG_PI, RST_RAID_IDS, SIG_ATA, STOP_TICKS, SUBCLASS_RAID, SUBCLASS_SATA, TSC_PER_TICK_BACKSTOP,
};
use crate::{mmio, pci, serial};

const PX_IE: u64 = 0x14;
const PX_SACT: u64 = 0x34;
/// The ABAR register span for 32 ports: what is mapped before the BAR may
/// be sized.
const ABAR_SPAN: u64 = PORT_BASE + MAX_PORTS * PORT_STRIDE;
/// AHCI port register writes this boot (every one goes through
/// `Regs::write`): evidence that eligibility wrote nothing.
static AHCI_WRITES: AtomicU64 = AtomicU64::new(0);
const CAP_S64A: u32 = 1 << 31;
/// Ticks (~1 ms) a READ, WRITE or FLUSH may take; IDENTIFY gets the same
/// (a drive may spin up before it answers).
const COMMAND_TICKS: u64 = 10_000;
const PAGE: usize = 4096;

#[repr(C, align(4096))]
struct Page([u8; PAGE]);

/// Pages in one buffer set, in this order: command list, received FIS,
/// command table, bounce page. Each is a whole page so an AMD-Vi domain
/// can grant exactly these and nothing else (#123: the AHCI controller's
/// grant is its static DMA pages).
pub const DMA_PAGES: usize = 4;
/// Set 0 is the one every boot uses; set 1 exists only for a restart after
/// a revocation in the AMD-Vi boot (a restart never reuses a revoked set).
pub const DMA_SETS: usize = 2;
const COMMAND_LIST: usize = 0;
const RECEIVED_FIS: usize = 1;
const COMMAND_TABLE: usize = 2;
const BOUNCE: usize = 3;

/// The backend's whole DMA surface: nothing else is ever handed to a
/// controller, and the takeover leaves no other port's command engine or
/// FIS receive running while its bus mastering is on.
static mut DMA: [[Page; DMA_PAGES]; DMA_SETS] =
    [const { [const { Page([0; PAGE]) }; DMA_PAGES] }; DMA_SETS];
/// Set when an engine that had the buffers was not shown stopped. One flag
/// for every set: after a failed stop nothing is handed to a controller
/// again, on any set.
static BUFFERS_RETIRED: AtomicBool = AtomicBool::new(false);

/// Qualification fixtures (src/ahci_check.rs only), each consumed once:
/// the next command is judged a timeout after it completed, and the next
/// recovery's stop is judged failed. QEMU's engine always completes and
/// always stops, so these are the only way to drive those paths there.
static PRETEND_TIMEOUT: AtomicBool = AtomicBool::new(false);
static PRETEND_STUCK_STOP: AtomicBool = AtomicBool::new(false);
/// Qualification fixture (`ahci-pretend-pending=N`): admission judges port N
/// not idle, so QEMU, whose firmware leaves no command issued, exercises the
/// refusal before any controller-wide write. Consumed by the first
/// controller admitted.
static PRETEND_PENDING_PORT: AtomicU64 = AtomicU64::new(u64::MAX);
/// Qualification fixture (`ahci-pretend-decode-off`): admission judges the
/// controller's memory decoding off (SeaBIOS leaves it on).
static PRETEND_DECODE_OFF: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    Selection(rules::SelectionError),
    /// Every AHCI-class function was refused (RAID, mode, ownership, claim).
    NoController,
    /// No probed port's IDENTIFY serial matched the selection.
    NotFound,
    Device(rules::DeviceRefusal),
    /// Outside a VM, before AMD-Vi containment (#123): no controller is
    /// taken over in either access mode.
    OutsideVm,
    /// `ahci-write=` naming a disk that is not QEMU's, outside a containment
    /// domain (`ahci_command::write_admitted`).
    WriteNotEmulated,
    /// [`read_raw`] on a function no ABSD AMD-Vi domain contains now.
    NotContained,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AhciError {
    /// No SATA or RAID mass-storage function at all.
    Absent,
    Refused(Refusal),
    /// The device failed this command; the port recovered and still serves.
    Command(Completion),
    /// The port is out of service for the rest of the boot.
    Retired,
    /// The disk was not selected with `ahci-write=`.
    ReadOnly,
    OutOfRange,
}

#[derive(Clone, Copy, Debug)]
pub struct Identity {
    pub pci: pci::Function,
    pub vendor: u16,
    pub device: u16,
    pub port: u8,
    serial: [u8; 20],
    serial_length: usize,
    model: [u8; 40],
    model_length: usize,
    pub sectors: u64,
    pub writable: bool,
}

impl Identity {
    pub fn serial(&self) -> &[u8] {
        &self.serial[..self.serial_length]
    }

    pub fn model(&self) -> &[u8] {
        &self.model[..self.model_length]
    }
}

/// One port's registers.
#[derive(Clone, Copy)]
struct Regs {
    registers: u64,
    index: u64,
}

impl Regs {
    fn read(&self, offset: u64) -> u32 {
        let at = self.registers + PORT_BASE + self.index * PORT_STRIDE + offset;
        unsafe { core::ptr::read_volatile(at as *const u32) }
    }

    fn write(&self, offset: u64, value: u32) {
        AHCI_WRITES.fetch_add(1, Ordering::Relaxed);
        let at = self.registers + PORT_BASE + self.index * PORT_STRIDE + offset;
        unsafe { core::ptr::write_volatile(at as *mut u32, value) }
    }

    /// Polls until `done` for at most `bound` ticks, or the TSC backstop.
    /// It never halts: a halted CPU waits for an interrupt that may never
    /// come (a dead timer), and then no bound would end the wait.
    fn poll(&self, bound: u64, done: impl Fn(&Regs) -> bool) -> bool {
        let start = ticks();
        let start_tsc = tsc();
        let backstop = bound.saturating_mul(TSC_PER_TICK_BACKSTOP);
        loop {
            if done(self) {
                return true;
            }
            if ticks().wrapping_sub(start) > bound || tsc().wrapping_sub(start_tsc) > backstop {
                return false;
            }
            core::hint::spin_loop();
        }
    }

    fn clear(&self, offset: u64, mask: u32, bound: u64) -> bool {
        self.poll(bound, |regs| regs.read(offset) & mask == 0)
    }

    /// ST off, then CR clear within the bound.
    fn stop_engine(&self) -> bool {
        self.write(PX_CMD, self.read(PX_CMD) & !CMD_ST);
        self.clear(PX_CMD, CMD_CR, STOP_TICKS)
    }

    /// FRE off, then FR clear within the bound.
    fn stop_fis(&self) -> bool {
        self.write(PX_CMD, self.read(PX_CMD) & !CMD_FRE);
        self.clear(PX_CMD, CMD_FR, STOP_TICKS)
    }
}

fn ticks() -> u64 {
    crate::timer_ticks.load(Ordering::Relaxed)
}

fn tsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Page `index` of buffer set `set`: identity-mapped, so its address is
/// its bus address.
fn page(set: usize, index: usize) -> u64 {
    unsafe { core::ptr::addr_of_mut!(DMA[set][index]) as u64 }
}
fn list(set: usize) -> u64 {
    page(set, COMMAND_LIST)
}
fn received(set: usize) -> u64 {
    page(set, RECEIVED_FIS)
}
fn table(set: usize) -> u64 {
    page(set, COMMAND_TABLE)
}
fn bounce(set: usize) -> u64 {
    page(set, BOUNCE)
}

/// The physical (= bus) addresses of buffer set `set`, in the order command
/// list, received FIS, command table, bounce page: the backend's declared
/// grant for an AMD-Vi domain (#123).
pub fn dma_pages(set: usize) -> [u64; DMA_PAGES] {
    core::array::from_fn(|index| page(set, index))
}

fn zero(address: u64, bytes: usize) {
    let base = address as *mut u8;
    for offset in 0..bytes {
        unsafe { base.add(offset).write_volatile(0) };
    }
}

/// The firmware's port state, written back when a probed port is released.
#[derive(Clone, Copy)]
struct Saved {
    clb: (u32, u32),
    fb: (u32, u32),
    cmd: u32,
    ie: u32,
}

/// Why taking a port failed.
enum Acquire {
    /// The engine was not shown stopped before the bases were written: they
    /// are untouched, and the engine still runs on the firmware's list.
    StopFailed,
    /// The device stayed busy (BSY or DRQ) with FIS receive on; the port was
    /// released.
    Busy(Stop),
}

/// Stops the port's engines, points it at buffer set `set` with its
/// interrupts off, and starts it (AHCI 1.3 §10.3.1: BSY and DRQ clear
/// before ST).
fn acquire(regs: &Regs, set: usize) -> Result<Saved, Acquire> {
    let saved = Saved {
        clb: (regs.read(PX_CLB), regs.read(PX_CLBU)),
        fb: (regs.read(PX_FB), regs.read(PX_FBU)),
        cmd: regs.read(PX_CMD),
        ie: regs.read(PX_IE),
    };
    if !regs.stop_engine() || !regs.stop_fis() {
        return Err(Acquire::StopFailed);
    }
    for index in 0..DMA_PAGES {
        zero(page(set, index), PAGE);
    }
    regs.write(PX_IE, 0);
    regs.write(PX_CLB, list(set) as u32);
    regs.write(PX_CLBU, (list(set) >> 32) as u32);
    regs.write(PX_FB, received(set) as u32);
    regs.write(PX_FBU, (received(set) >> 32) as u32);
    regs.write(PX_SERR, u32::MAX);
    regs.write(PX_IS, u32::MAX);
    regs.write(PX_CMD, regs.read(PX_CMD) | CMD_FRE);
    if !regs.clear(PX_TFD, rules::TFD_BSY | rules::TFD_DRQ, STOP_TICKS) {
        return Err(Acquire::Busy(release(regs, saved)));
    }
    regs.write(PX_CMD, regs.read(PX_CMD) | CMD_ST);
    Ok(saved)
}

/// Stops both engines and, only if both stopped, writes the firmware's
/// bases, interrupt enables and command bits (ST and FRE off) back. A
/// failed stop leaves the bases on the static buffers and retires them.
fn release(regs: &Regs, saved: Saved) -> Stop {
    let stopped = regs.stop_engine() && regs.stop_fis();
    if !stopped {
        BUFFERS_RETIRED.store(true, Ordering::Relaxed);
        return Stop::Failed;
    }
    regs.write(PX_CLB, saved.clb.0);
    regs.write(PX_CLBU, saved.clb.1);
    regs.write(PX_FB, saved.fb.0);
    regs.write(PX_FBU, saved.fb.1);
    regs.write(PX_IE, saved.ie);
    regs.write(PX_CMD, saved.cmd & !(CMD_ST | CMD_FRE));
    Stop::Confirmed
}

/// Issues `op` in slot 0 of a running port on buffer set `set` and polls it
/// to an end. Data moves through the one PRDT entry's address `data`: the
/// set's bounce page for every block-layer command (the caller fills it
/// before a write and reads it after a read), another address only for
/// [`read_raw`].
fn issue(regs: &Regs, set: usize, op: Op, data: u64) -> Completion {
    LAST_SUBMITTED.store(false, Ordering::Relaxed);
    if regs.read(PX_TFD) & (rules::TFD_BSY | rules::TFD_DRQ) != 0 {
        // A device that is not idle before the command: nothing issued,
        // and the rule retires the port as for a timeout.
        return Completion::Timeout;
    }
    let header = list(set) as *mut u32;
    let table = table(set);
    unsafe {
        header.write_volatile(rules::header_dw0(op));
        header.add(1).write_volatile(0);
        header.add(2).write_volatile(table as u32);
        header.add(3).write_volatile((table >> 32) as u32);
    }
    zero(table, 256);
    let cfis = table as *mut u8;
    for (offset, byte) in rules::register_fis(op).iter().enumerate() {
        unsafe { cfis.add(offset).write_volatile(*byte) };
    }
    if let Some(count) = rules::prdt_dbc(op) {
        let prdt = (table + 0x80) as *mut u32;
        unsafe {
            prdt.write_volatile(data as u32);
            prdt.add(1).write_volatile((data >> 32) as u32);
            prdt.add(2).write_volatile(0);
            prdt.add(3).write_volatile(count);
        }
    }
    regs.write(PX_IS, u32::MAX);
    // The header, FIS and data must be in memory before the HBA sees CI.
    fence(Ordering::SeqCst);
    regs.write(PX_CI, 1);
    LAST_SUBMITTED.store(true, Ordering::Relaxed);
    regs.poll(COMMAND_TICKS, |regs| {
        regs.read(PX_CI) & 1 == 0 || regs.read(PX_IS) & rules::IS_TFES != 0
    });
    fence(Ordering::SeqCst);
    let issued_clear = regs.read(PX_CI) & 1 == 0;
    let is = regs.read(PX_IS);
    let tfd = regs.read(PX_TFD);
    let prdbc = unsafe { header.add(1).read_volatile() };
    let completion = rules::judge(op, issued_clear, is, tfd, prdbc);
    if completion == Completion::Done && PRETEND_TIMEOUT.swap(false, Ordering::Relaxed) {
        return Completion::Timeout;
    }
    completion
}

/// IDENTIFY's 256 words, from set `set`'s bounce page.
fn identify_words(set: usize) -> [u16; 256] {
    let bytes = bounce(set) as *const u8;
    core::array::from_fn(|index| unsafe {
        u16::from_le_bytes([
            bytes.add(2 * index).read_volatile(),
            bytes.add(2 * index + 1).read_volatile(),
        ])
    })
}

#[derive(Clone, Copy)]
struct Port {
    regs: Regs,
    identity: Identity,
    retired: bool,
    /// The buffer set this port was given at probe.
    set: usize,
}

static mut PORT: Option<Port> = None;
/// Commands completed successfully, FLUSH CACHE EXT among them, and
/// failed commands after which the port recovered.
static mut COMPLETED: u64 = 0;
static mut FLUSHES: u64 = 0;
static mut RECOVERED: u64 = 0;

fn port() -> Option<&'static mut Port> {
    crate::kernel_lock::assert_bsp_device_access();
    unsafe { (*core::ptr::addr_of_mut!(PORT)).as_mut() }
}

/// `(completed commands, completed FLUSH CACHE EXT commands, recoveries)`.
pub fn completed() -> (u64, u64, u64) {
    crate::kernel_lock::assert_bsp_device_access();
    unsafe {
        (
            core::ptr::read_volatile(core::ptr::addr_of!(COMPLETED)),
            core::ptr::read_volatile(core::ptr::addr_of!(FLUSHES)),
            core::ptr::read_volatile(core::ptr::addr_of!(RECOVERED)),
        )
    }
}

/// Whether the serving port was retired, and whether the buffers were.
pub fn retired() -> (bool, bool) {
    (
        port().is_some_and(|found| found.retired),
        BUFFERS_RETIRED.load(Ordering::Relaxed),
    )
}

/// The selected controller's PCI function, if a port is serving or retired.
pub fn function() -> Option<pci::Function> {
    port().map(|found| found.identity.pci)
}

/// Arms the qualification fixtures (src/ahci_check.rs).
pub fn pretend_timeout() {
    PRETEND_TIMEOUT.store(true, Ordering::Relaxed);
}
pub fn pretend_stuck_stop() {
    PRETEND_STUCK_STOP.store(true, Ordering::Relaxed);
}
pub fn pretend_pending(port: u64) {
    PRETEND_PENDING_PORT.store(port, Ordering::Relaxed);
}
pub fn pretend_decode_off() {
    PRETEND_DECODE_OFF.store(true, Ordering::Relaxed);
}

impl Port {
    /// Runs one command; a failure goes through the recovery rule.
    fn execute(&mut self, op: Op) -> Result<(), AhciError> {
        if self.retired {
            return Err(AhciError::Retired);
        }
        // The read-only build issues IDENTIFY and READ DMA EXT only.
        if !crate::block::WRITES_BUILT && !op.reads_only() {
            return Err(AhciError::ReadOnly);
        }
        if !op.valid() {
            return Err(AhciError::OutOfRange);
        }
        match issue(&self.regs, self.set, op, bounce(self.set)) {
            Completion::Done => {
                unsafe {
                    *core::ptr::addr_of_mut!(COMPLETED) += 1;
                    if op == Op::Flush {
                        *core::ptr::addr_of_mut!(FLUSHES) += 1;
                    }
                }
                Ok(())
            }
            failed => Err(self.recover(failed)),
        }
    }

    fn recover(&mut self, completion: Completion) -> AhciError {
        let regs = self.regs;
        let stopped = regs.stop_engine() && !PRETEND_STUCK_STOP.swap(false, Ordering::Relaxed);
        let stop = if stopped {
            regs.write(PX_SERR, u32::MAX);
            regs.write(PX_IS, u32::MAX);
            Stop::Confirmed
        } else {
            Stop::Failed
        };
        let tfd = regs.read(PX_TFD);
        match rules::recover(completion, stop, tfd) {
            Recovery::Restart => {
                regs.write(PX_CMD, regs.read(PX_CMD) | CMD_ST);
                unsafe { *core::ptr::addr_of_mut!(RECOVERED) += 1 };
                AhciError::Command(completion)
            }
            Recovery::Retire { buffers_reusable } => {
                // Containment first: bus mastering off before anything else.
                pci::disable_dma(self.identity.pci);
                self.retired = true;
                if crate::contain::active() {
                    BUFFERS_RETIRED.store(true, Ordering::Relaxed);
                    crate::contain::retire(Driver::Ahci);
                }
                let fis_stopped = stop == Stop::Confirmed && regs.stop_fis();
                let reusable = buffers_reusable && fis_stopped;
                if !reusable {
                    BUFFERS_RETIRED.store(true, Ordering::Relaxed);
                }
                serial::write("AHCI PORT ");
                serial::decimal(regs.index);
                serial::write(" RETIRED after=");
                serial::write(match completion {
                    Completion::Timeout => "timeout",
                    Completion::TaskFile { .. } => "device-error",
                    Completion::ShortTransfer { .. } => "short-transfer",
                    Completion::Done => "done",
                });
                serial::write(" tfd=");
                serial::hex_digits(u64::from(tfd), 8);
                serial::write(if stopped {
                    " stop=confirmed"
                } else {
                    " stop=failed"
                });
                serial::write(if reusable {
                    " buffers=reusable"
                } else {
                    " buffers=retired"
                });
                serial::write(if pci::bus_master(self.identity.pci) {
                    " dma=on\n"
                } else {
                    " dma=off\n"
                });
                AhciError::Retired
            }
        }
    }

    fn check(&self, lba: u64, bytes: usize) -> Result<u32, AhciError> {
        let sectors = crate::block::transfer_sectors(bytes).map_err(|_| AhciError::OutOfRange)?;
        let end = lba
            .checked_add(sectors as u64)
            .ok_or(AhciError::OutOfRange)?;
        if end > self.identity.sectors {
            return Err(AhciError::OutOfRange);
        }
        Ok(sectors as u32)
    }
}

fn out_function(function: pci::Function) {
    serial::hex_digits(u64::from(function.bus), 2);
    serial::write(":");
    serial::hex_digits(u64::from(function.device), 2);
    serial::write(".");
    serial::hex_digits(u64::from(function.function), 1);
}

fn refuse_controller(function: pci::Function, reason: &str) {
    serial::write("AHCI CONTROLLER pci=");
    out_function(function);
    serial::write(" REFUSED ");
    serial::write(reason);
    serial::write("\n");
}

fn quoted(bytes: &[u8]) {
    serial::write("\"");
    for &byte in bytes {
        serial::byte_out(if (0x20..0x7f).contains(&byte) && byte != b'"' {
            byte
        } else {
            b'?'
        });
    }
    serial::write("\"");
}

fn copy(field: &[u8], into: &mut [u8]) -> usize {
    let length = field.len().min(into.len());
    into[..length].copy_from_slice(&field[..length]);
    length
}

/// The gates every probe passes first: no port held, buffers not retired,
/// and inside a VM.
fn probe_gates() -> Result<(), AhciError> {
    crate::kernel_lock::assert_bsp_device_access();
    if port().is_some() || BUFFERS_RETIRED.load(Ordering::Relaxed) {
        return Err(AhciError::Retired);
    }
    // CPUID.1:ECX bit 31, "hypervisor present".
    let in_vm = core::arch::x86_64::__cpuid(1).ecx & (1 << 31) != 0;
    // In a `dma-contain` boot the seam decides: no live domain, no arm.
    if !in_vm && !crate::contain::active() {
        return Err(AhciError::Refused(Refusal::OutsideVm));
    }
    Ok(())
}

fn ahci_class(function: pci::Function) -> bool {
    let value = pci::read32(function, 0x08);
    let (class_code, subclass) = ((value >> 24) as u8, (value >> 16) as u8);
    class_code == CLASS_MASS_STORAGE && (subclass == SUBCLASS_RAID || subclass == SUBCLASS_SATA)
}

static mut LAST_DISK: Option<(Identity, bool)> = None;

/// The last disk IDENTIFY answered, and whether it was the selected one.
pub fn last_disk() -> Option<(Identity, bool)> {
    unsafe { *core::ptr::addr_of!(LAST_DISK) }
}

/// Whether the last command issued actually reached PxCI: `issue` can time
/// out before that, and a retirement then proves nothing about a denial.
static LAST_SUBMITTED: AtomicBool = AtomicBool::new(false);

pub fn last_command_submitted() -> bool {
    LAST_SUBMITTED.load(Ordering::Relaxed)
}

/// Retires the buffers for the boot: the surface stays exposed.
pub fn retire_buffers() {
    BUFFERS_RETIRED.store(true, Ordering::Relaxed);
}

/// The `dma-contain` entry: only the named function, on buffer set 0. A
/// failure after the surface was exposed retires it for the boot.
pub fn probe_contained(
    function: pci::Function,
    selection: Selection,
) -> Result<Identity, AhciError> {
    let result = probe_function(function, selection, 0);
    if result.is_err() {
        pci::disable_dma(function);
        if crate::contain::exposed(Driver::Ahci) {
            BUFFERS_RETIRED.store(true, Ordering::Relaxed);
            crate::contain::retire(Driver::Ahci);
        }
    }
    result
}

/// Finds the selected disk and makes its port the block device, on buffer
/// set 0.
pub fn probe(selection: Selection) -> Result<Identity, AhciError> {
    probe_gates()?;
    let mut functions: [Option<pci::Function>; 8] = [None; 8];
    let mut count = 0usize;
    pci::each(|function| {
        if ahci_class(function) && count < functions.len() {
            functions[count] = Some(function);
            count += 1;
        }
    });
    if count == 0 {
        return Err(AhciError::Absent);
    }
    let mut eligible = 0u32;
    for function in functions[..count].iter().flatten().copied() {
        match controller(function, selection, 0, &mut eligible) {
            Ok(Some(identity)) => return Ok(identity),
            Ok(None) => {}
            Err(error) => return Err(error),
        }
    }
    Err(AhciError::Refused(if eligible == 0 {
        Refusal::NoController
    } else {
        Refusal::NotFound
    }))
}

/// [`probe`] for exactly one PCI function on buffer set `set` (the AMD-Vi
/// boot, #123): the same gates, eligibility, takeover and port search, and
/// no other function is looked at. A set above 0 re-probes a controller
/// this backend already claimed (a restart after a revocation, whose
/// withdrawal released the port but not the claim).
pub fn probe_function(
    function: pci::Function,
    selection: Selection,
    set: usize,
) -> Result<Identity, AhciError> {
    if set >= DMA_SETS {
        return Err(AhciError::OutOfRange);
    }
    probe_gates()?;
    if !ahci_class(function) {
        return Err(AhciError::Absent);
    }
    let mut eligible = 0u32;
    match controller(function, selection, set, &mut eligible)? {
        Some(identity) => Ok(identity),
        None => Err(AhciError::Refused(if eligible == 0 {
            Refusal::NoController
        } else {
            Refusal::NotFound
        })),
    }
}

/// One controller, on buffer set `set`: Some when the selected disk is on
/// it, None to go on to the next one, Err to end the probe (a refused disk,
/// or a port whose engine was not shown stopped).
fn controller(
    function: pci::Function,
    selection: Selection,
    set: usize,
    eligible: &mut u32,
) -> Result<Option<Identity>, AhciError> {
    let value = pci::read32(function, 0x08);
    let (subclass, interface) = ((value >> 16) as u8, (value >> 8) as u8);
    let (vendor, device) = pci::ids(function);
    if subclass == SUBCLASS_RAID || RST_RAID_IDS.contains(&(vendor, device)) {
        refuse_controller(function, "mode=raid: firmware RAID owns these disks");
        return Ok(None);
    }
    if interface != INTERFACE_AHCI {
        refuse_controller(function, "mode=sata-non-ahci");
        return Ok(None);
    }
    // Only QEMU's emulated controller is taken over in this slice, in either
    // access mode (configuration reads only).
    // A `dma-contain` boot judges identity in device scope instead, and takes
    // only the named function.
    if !crate::contain::active()
        && !rules::emulated_controller(vendor, device, pci::read32(function, 0x2c))
    {
        refuse_controller(
            function,
            "not QEMU's emulated controller: no takeover before AMD-Vi containment",
        );
        return Ok(None);
    }
    match pci::claim(function, "ahci") {
        Ok(()) => {}
        // A restart on a later set: this backend already owns it.
        Err(pci::ClaimError::Owned("ahci")) if set > 0 => {}
        Err(_) => {
            refuse_controller(function, "claim: another driver owns it");
            return Ok(None);
        }
    }
    let Ok(bar) = pci::memory_bar(function, ABAR) else {
        refuse_controller(function, "ABAR (BAR5) is not an assigned memory BAR");
        return Ok(None);
    };
    // No BAR sizing yet: sizing writes configuration space, and nothing is
    // written before the controller is shown eligible. The mapping covers
    // the register span of 32 ports; eligibility reads only the ports
    // CAP.NP declares, which the ABAR covers by the AHCI specification, and
    // the aperture is sized and checked once the takeover starts.
    let Ok(registers) = mmio::map(bar, ABAR_SPAN, mmio::Cache::Uncached) else {
        refuse_controller(function, "ABAR could not be mapped");
        return Ok(None);
    };
    // Eligibility for exclusive takeover, by configuration and register
    // reads only (no INTx mask, bus mastering as found): no configuration or
    // AHCI register write until every check below has passed. A controller refused here keeps its PCI
    // command and port state as found; the refusal line reports the writes
    // counted since the checks began.
    let config_before = pci::config_writes();
    let ahci_before = AHCI_WRITES.load(Ordering::Relaxed);
    // Memory decoding off means turning it on, a configuration write, before
    // the controller could be shown eligible: refused instead.
    let decoding =
        pci::memory_enabled(function) && !PRETEND_DECODE_OFF.swap(false, Ordering::Relaxed);
    let refuse = |reason: &str| {
        serial::write("AHCI CONTROLLER pci=");
        out_function(function);
        serial::write(" REFUSED ");
        serial::write(reason);
        serial::write(" command=");
        serial::hex_digits(u64::from(pci::read32(function, 0x04) & 0xffff), 4);
        serial::write(" pci_config_writes=");
        serial::decimal(pci::config_writes() - config_before);
        serial::write(" ahci_register_writes=");
        serial::decimal(AHCI_WRITES.load(Ordering::Relaxed) - ahci_before);
        serial::write(" (left as found)\n");
    };
    if !decoding {
        refuse("memory decoding off: enabling it would write before eligibility");
        return Ok(None);
    }
    let read =
        |offset: u64| unsafe { core::ptr::read_volatile((registers + offset) as *const u32) };
    let cap = read(REG_CAP);
    if read(REG_CAP2) & CAP2_BOH != 0 && read(REG_BOHC) & BOHC_BOS != 0 {
        refuse("firmware owns the HBA (BOHC.BOS)");
        return Ok(None);
    }
    if read(REG_GHC) & GHC_AE == 0 {
        refuse("firmware left AHCI mode off (GHC.AE=0)");
        return Ok(None);
    }
    if cap & CAP_S64A == 0 && dma_pages(set).iter().any(|a| a >> 32 != 0) {
        refuse("no 64-bit addressing (CAP.S64A) for the buffers");
        return Ok(None);
    }
    let pi = read(REG_PI);
    let ports = u64::from((cap & 0x1f) + 1);
    // Every implemented port must be one CAP.NP declares: a PI bit beyond it
    // is geometry this backend cannot vouch for, so nothing is read there.
    if ports < 32 && pi >> ports != 0 {
        refuse("ports implemented beyond CAP.NP");
        return Ok(None);
    }
    let implemented = |index: u64| pi & (1 << index) != 0;
    let fixture = PRETEND_PENDING_PORT.swap(u64::MAX, Ordering::Relaxed);
    for index in (0..MAX_PORTS).filter(|&index| implemented(index)) {
        let regs = Regs { registers, index };
        let (ci, sact) = (regs.read(PX_CI), regs.read(PX_SACT));
        let state = if index == fixture {
            rules::PortState::Pending
        } else {
            rules::port_state(regs.read(PX_CMD), ci, sact)
        };
        if state == rules::PortState::Pending {
            serial::write("AHCI PORT ");
            serial::decimal(index);
            serial::write(" PENDING ci=");
            serial::hex_digits(u64::from(ci), 8);
            serial::write(" sact=");
            serial::hex_digits(u64::from(sact), 8);
            serial::write(if index == fixture {
                " fixture=pretend-pending\n"
            } else {
                "\n"
            });
            refuse("a port is not idle: no exclusive takeover");
            return Ok(None);
        }
    }
    // Eligible: the takeover starts. Bus mastering off first (firmware may
    // have left it on, SeaBIOS does), then INTx masked, then idle engines
    // firmware left running are stopped; they stay stopped, because this
    // controller is now ABSD's alone.
    let inherited = pci::bus_master(function);
    // Design section 5, steps 1 to 3: scope, bus mastering clear with the
    // DTE still blocked, ordering corrected.
    if crate::contain::active() && !crate::contain::take(Driver::Ahci, function) {
        refuse_controller(function, "contain: not taken");
        return Ok(None);
    }
    if !cfg!(absd_mutant_contain_skip_bme_clear) {
        pci::disable_dma(function);
    }
    if pci::bus_master(function) && !cfg!(absd_mutant_contain_skip_bme_clear) {
        refuse_controller(function, "bus mastering could not be turned off");
        return Ok(None);
    }
    if inherited {
        serial::write("AHCI CONTROLLER pci=");
        out_function(function);
        serial::write(" bus mastering found on: turned off at takeover\n");
    }
    // The aperture must hold every implemented port's registers.
    let size = pci::memory_bar_size(function, ABAR).unwrap_or(0);
    let last = u64::from(31 - pi.leading_zeros().min(31));
    if pi == 0 || size < PORT_BASE + (last + 1) * PORT_STRIDE {
        refuse_controller(
            function,
            "ABAR does not cover every implemented port: bus mastering stays off",
        );
        return Ok(None);
    }
    pci::enable_memory(function);
    for index in (0..MAX_PORTS).filter(|&index| implemented(index)) {
        let regs = Regs { registers, index };
        let cmd = regs.read(PX_CMD);
        if rules::port_state(cmd, regs.read(PX_CI), regs.read(PX_SACT)) != rules::PortState::Running
        {
            continue;
        }
        if !regs.stop_engine() || !regs.stop_fis() {
            refuse_controller(
                function,
                "a port's idle engines did not stop (CR/FR): bus mastering stays off",
            );
            return Ok(None);
        }
        serial::write("AHCI PORT ");
        serial::decimal(index);
        serial::write(" STOPPED idle engines firmware left running cmd=");
        serial::hex_digits(u64::from(cmd), 8);
        serial::write("\n");
    }
    *eligible += 1;
    // Steps 4 to 6: the surface is zeroed statics no device has reached, so
    // the grant follows. Exposed from here for the rest of the boot.
    if crate::contain::active() {
        let pages = dma_pages(set);
        let mut grant = [(0, amdvi::Perm::READ); DMA_PAGES];
        for (at, slot) in grant.iter_mut().enumerate() {
            *slot = (pages[at], amdvi::AHCI_ROLES[at].1);
        }
        if !crate::contain::expose(Driver::Ahci, function, &grant)
            || !crate::contain::admit(Driver::Ahci, function)
        {
            refuse_controller(function, "contain: not granted");
            return Ok(None);
        }
    }
    if let Err(refused) = crate::dma::arm(function, &dma_policy::AHCI_BLOCK) {
        serial::write("AHCI DMA REFUSED state=");
        serial::write(refused.state.name());
        serial::write("\n");
        return Ok(None);
    }
    for index in (0..MAX_PORTS).filter(|&index| implemented(index)) {
        let regs = Regs { registers, index };
        let ssts = regs.read(PX_SSTS);
        let (det, ipm) = (ssts & 0xf, (ssts >> 8) & 0xf);
        if det != 3 || ipm != 1 || regs.read(PX_FBS) & FBS_EN != 0 || regs.read(PX_SIG) != SIG_ATA {
            continue;
        }
        match port_candidate(function, vendor, device, regs, selection, set) {
            Ok(Some(identity)) => return Ok(Some(identity)),
            Ok(None) => {}
            Err(error) => {
                // A refusal, or a failed stop: bus mastering off, nothing
                // is restarted.
                pci::disable_dma(function);
                return Err(error);
            }
        }
    }
    pci::disable_dma(function);
    Ok(None)
}

/// IDENTIFY on one port; keeps the port when its serial is the selected
/// one and the disk is admissible, releases it otherwise.
fn port_candidate(
    function: pci::Function,
    vendor: u16,
    device: u16,
    regs: Regs,
    selection: Selection,
    set: usize,
) -> Result<Option<Identity>, AhciError> {
    let saved = match acquire(&regs, set) {
        Ok(saved) => saved,
        Err(Acquire::StopFailed) => {
            stage_failed(function, regs.index, "engine did not stop before IDENTIFY");
            return Err(AhciError::Retired);
        }
        Err(Acquire::Busy(Stop::Confirmed)) if crate::contain::active() => {
            return Err(AhciError::Retired);
        }
        Err(Acquire::Busy(Stop::Confirmed)) => return Ok(None),
        Err(Acquire::Busy(Stop::Failed)) => {
            stage_failed(
                function,
                regs.index,
                "engine did not stop after a busy device",
            );
            return Err(AhciError::Retired);
        }
    };
    let completion = issue(&regs, set, Op::Identify, bounce(set));
    let words = identify_words(set);
    let finish = |result: Result<Option<Identity>, AhciError>| match release(&regs, saved) {
        Stop::Confirmed => result,
        Stop::Failed => {
            stage_failed(function, regs.index, "engine did not stop after IDENTIFY");
            Err(AhciError::Retired)
        }
    };
    if completion != Completion::Done {
        // After exposure a failure ends the surface: no other port reuses it.
        if crate::contain::active() {
            return finish(Err(AhciError::Retired));
        }
        return finish(Ok(None));
    }
    let (model, serial_number, _) = facts::ata_identify_strings(&words);
    let mut identity = Identity {
        pci: function,
        vendor,
        device,
        port: regs.index as u8,
        serial: [0; 20],
        serial_length: 0,
        model: [0; 40],
        model_length: 0,
        sectors: facts::ata_identify_sectors(&words),
        writable: selection.writable,
    };
    identity.serial_length = copy(rules::trim(serial_number), &mut identity.serial);
    identity.model_length = copy(model, &mut identity.model);
    let selected = rules::serial_matches(identity.serial(), selection.serial);
    // For the contain summary: the disk is what the operator needs to read off
    // the screen to select it.
    unsafe { *core::ptr::addr_of_mut!(LAST_DISK) = Some((identity, selected)) };
    serial::write("AHCI DISK pci=");
    out_function(function);
    serial::write(" port=");
    serial::decimal(regs.index);
    serial::write(" serial=");
    quoted(identity.serial());
    serial::write(" model=");
    quoted(identity.model());
    serial::write(if selected {
        " selected=yes\n"
    } else {
        " selected=no\n"
    });
    if !selected {
        return finish(Ok(None));
    }
    if selection.writable
        && !rules::write_admitted(identity.model(), crate::contain::exposed(Driver::Ahci))
    {
        return finish(Err(AhciError::Refused(Refusal::WriteNotEmulated)));
    }
    match rules::admit_device(&words) {
        Ok(sectors) => identity.sectors = sectors,
        Err(refusal) => return finish(Err(AhciError::Refused(Refusal::Device(refusal)))),
    }
    unsafe {
        *core::ptr::addr_of_mut!(PORT) = Some(Port {
            regs,
            identity,
            retired: false,
            set,
        });
    }
    Ok(Some(identity))
}

/// Fail closed: bus mastering off before the line is printed; the probe
/// then ends without a backend.
fn stage_failed(function: pci::Function, index: u64, stage: &str) {
    pci::disable_dma(function);
    serial::write("AHCI PORT ");
    serial::decimal(index);
    serial::write(" FAILED ");
    serial::write(stage);
    serial::write(if BUFFERS_RETIRED.load(Ordering::Relaxed) {
        ": bus mastering off, buffers retired\n"
    } else {
        ": bus mastering off, bases untouched\n"
    });
}

/// A proving read failed before the block backend became available: the
/// port is retired (engine stopped, bus mastering off) and no backend is
/// published. The PCI claim and, if its stop failed, the buffers stay held.
pub fn withdraw_failed_probe() {
    let Some(found) = port() else {
        return;
    };
    pci::disable_dma(found.identity.pci);
    found.retired = true;
    if crate::contain::active() {
        BUFFERS_RETIRED.store(true, Ordering::Relaxed);
        crate::contain::retire(Driver::Ahci);
    }
    let stopped = found.regs.stop_engine() && found.regs.stop_fis();
    if !stopped {
        BUFFERS_RETIRED.store(true, Ordering::Relaxed);
    }
    serial::write(if stopped {
        "AHCI PORT WITHDRAWN reason=first-read stop=confirmed"
    } else {
        "AHCI PORT WITHDRAWN reason=first-read stop=failed"
    });
    serial::write(if pci::bus_master(found.identity.pci) {
        " dma=on\n"
    } else {
        " dma=off\n"
    });
}

/// Revocation, R1 (#123, as `nvme::withdraw`): the port is taken out of
/// service, so nothing more is issued to it. The caller clears Bus Master
/// Enable (R2) and blocks the domain (R3) before [`Withdrawn::reset`] (R4).
/// `None` when no port was held. Its buffer set stays with the caller's
/// custodian; the PCI claim stays with this backend.
pub fn withdraw() -> Option<Withdrawn> {
    crate::kernel_lock::assert_bsp_device_access();
    let previous = unsafe { (*core::ptr::addr_of_mut!(PORT)).take() }?;
    serial::write("AHCI PORT WITHDRAWN reason=revoke\n");
    Some(Withdrawn(previous))
}

/// A port taken out of service by [`withdraw`] (R1): nothing more is issued
/// to it. [`Withdrawn::reset`] is its R4.
pub struct Withdrawn(Port);

impl Withdrawn {
    /// Stops the command engine (ST off, CR clear within the bound), then,
    /// only if that was shown, FIS receive (FRE off, FR clear), with bus
    /// mastering kept clear throughout. Returns whether both stops were
    /// confirmed. A stop that is not shown retires every buffer set, as
    /// for any other failed stop. Register evidence only; no COMRESET, no
    /// HBA reset.
    pub fn reset(self) -> bool {
        let found = self.0;
        pci::disable_dma(found.identity.pci);
        let stopped = found.regs.stop_engine() && found.regs.stop_fis();
        if !stopped {
            BUFFERS_RETIRED.store(true, Ordering::Relaxed);
        }
        pci::disable_dma(found.identity.pci);
        serial::write(if stopped {
            "AHCI PORT CLEANUP stop=confirmed"
        } else {
            "AHCI PORT CLEANUP stop=unconfirmed"
        });
        serial::write(if pci::bus_master(found.identity.pci) {
            " dma=on\n"
        } else {
            " dma=off\n"
        });
        stopped
    }
}

/// One READ DMA EXT of `blocks` (1..=8) sectors from `lba` with the one
/// PRDT entry's data base address `dba` (`None`: this set's bounce page),
/// for the AMD-Vi boot's self-check and oracle (#123). Refused unless an
/// ABSD domain contains the function right now: the address is not checked
/// against any grant here, and that domain alone decides what the device
/// reaches. The address must be dword aligned and the transfer must stay
/// inside its page (`ahci_command::raw_read_shape`). The LBA is not checked
/// against the disk's size: the device's own refusal is reported.
///
/// Returns the address used and the completion. A failed completion goes
/// through the backend's recovery rule unchanged (`ahci_command::recover`):
/// a device error or short transfer on an idle device restarts the engine
/// and the port keeps serving; a timeout, a Device Fault or a stop that is
/// not shown retires the port (and, after a failed stop, every buffer set),
/// because a command whose outcome is unknown may still own the buffers.
/// Either way the completion is reported, not hidden.
pub fn read_raw(lba: u64, blocks: usize, dba: Option<u64>) -> Result<(u64, Completion), AhciError> {
    let found = port().ok_or(AhciError::Absent)?;
    if crate::dma::domain_for(found.identity.pci, dma_policy::AHCI_BLOCK.owner).is_none() {
        return Err(AhciError::Refused(Refusal::NotContained));
    }
    if found.retired {
        return Err(AhciError::Retired);
    }
    let data = dba.unwrap_or_else(|| bounce(found.set));
    let sectors = u32::try_from(blocks).map_err(|_| AhciError::OutOfRange)?;
    let op = Op::Read { lba, sectors };
    if !rules::raw_read_shape(sectors, data) || !op.valid() {
        return Err(AhciError::OutOfRange);
    }
    let completion = issue(&found.regs, found.set, op, data);
    if completion == Completion::Done {
        unsafe { *core::ptr::addr_of_mut!(COMPLETED) += 1 };
    } else {
        let _ = found.recover(completion);
    }
    Ok((data, completion))
}

pub fn read_sector(lba: u64, buffer: &mut [u8; BLOCK_SECTOR_BYTES]) -> Result<(), AhciError> {
    read_sectors(lba, buffer)
}

/// Reads `buffer.len() / 512` consecutive sectors from `lba` with one READ
/// DMA EXT through the bounce page.
pub fn read_sectors(lba: u64, buffer: &mut [u8]) -> Result<(), AhciError> {
    let found = port().ok_or(AhciError::Absent)?;
    let sectors = found.check(lba, buffer.len())?;
    found.execute(Op::Read { lba, sectors })?;
    let data = unsafe { &(*core::ptr::addr_of!(DMA[found.set][BOUNCE])).0 };
    buffer.copy_from_slice(&data[..buffer.len()]);
    Ok(())
}

pub fn write_sector(lba: u64, buffer: &[u8; BLOCK_SECTOR_BYTES]) -> Result<(), AhciError> {
    write_sectors(lba, buffer)
}

/// Writes `buffer.len() / 512` consecutive sectors from `lba` with one
/// WRITE DMA EXT through the bounce page.
pub fn write_sectors(lba: u64, buffer: &[u8]) -> Result<(), AhciError> {
    let found = port().ok_or(AhciError::Absent)?;
    let sectors = found.check(lba, buffer.len())?;
    if !found.identity.writable {
        return Err(AhciError::ReadOnly);
    }
    if found.retired {
        return Err(AhciError::Retired);
    }
    let data = unsafe { &mut (*core::ptr::addr_of_mut!(DMA[found.set][BOUNCE])).0 };
    data[..buffer.len()].copy_from_slice(buffer);
    found.execute(Op::Write { lba, sectors })
}

pub fn flush() -> Result<(), AhciError> {
    let found = port().ok_or(AhciError::Absent)?;
    if !found.identity.writable {
        return Err(AhciError::ReadOnly);
    }
    found.execute(Op::Flush)
}

/// A one-sector read with no range check, so qualification can see the
/// device's own refusal of an LBA past the disk.
pub fn read_unchecked(lba: u64) -> Result<(), AhciError> {
    port()
        .ok_or(AhciError::Absent)?
        .execute(Op::Read { lba, sectors: 1 })
}

/// Installer-only conservative census. Ordinary disk selection is unchanged.
/// Refuse multiple AHCI functions or possibly occupied ports, including duplicate
/// serials: this software pilot never chooses the first of several targets.
pub fn installer_identity() -> Option<(Identity, bool)> {
    let found = port()?;
    let mut controllers = 0;
    pci::each(|function| {
        if ahci_class(function) {
            controllers += 1;
        }
    });
    let mut disks = 0;
    let pi = unsafe { core::ptr::read_volatile((found.regs.registers + REG_PI) as *const u32) };
    for index in (0..MAX_PORTS).filter(|index| pi & (1 << index) != 0) {
        let regs = Regs {
            registers: found.regs.registers,
            index,
        };
        if rules::installer_port_present(regs.read(PX_SSTS)) {
            disks += 1;
        }
    }
    Some((found.identity, controllers == 1 && disks == 1))
}
