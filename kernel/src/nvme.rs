//! One NVMe namespace as the block device: polled, one command at a time.
//!
//! The controller is found by PCI class (mass storage, NVM, NVMe), reset,
//! and enabled with one admin queue pair and one I/O queue pair in static,
//! page-aligned kernel memory (identity-mapped, so each static's address is
//! its bus address). Every transfer is one to eight 512-byte logical blocks
//! through a single PRP entry into a static bounce page (one page, so PRP1
//! alone describes it). Completion is polled on the
//! completion queue's phase tag; interrupts stay masked. A command that
//! does not complete within its bound is a timeout, never a hang.
//!
//! Contract with the block layer (src/block.rs): a write returns only after
//! its completion entry reports success, which QEMU posts after the host
//! `pwrite` returned; `flush` issues an NVMe FLUSH for the namespace and
//! returns only after it completes (QEMU: host `fdatasync`), so every write
//! completed before it is stable. Only 512-byte LBA formats without
//! metadata are accepted; anything else is refused by name.
//!
//! Writes are refused unless the boot names this controller's serial number
//! with `nvme-write=SERIAL`: a physical machine's disk is read-only unless
//! the operator explicitly selects it as a sacrificial target.

use core::sync::atomic::{Ordering, fence};

use absd_kernel::syscall::BLOCK_SECTOR_BYTES;

use crate::{mmio, pci};

const CLASS_MASS_STORAGE: u8 = 0x01;
const SUBCLASS_NVM: u8 = 0x08;
const INTERFACE_NVME: u8 = 0x02;

const REG_CAP: u64 = 0x00;
const REG_VS: u64 = 0x08;
const REG_INTMS: u64 = 0x0c;
const REG_CC: u64 = 0x14;
const REG_CSTS: u64 = 0x1c;
const REG_AQA: u64 = 0x24;
const REG_ASQ: u64 = 0x28;
const REG_ACQ: u64 = 0x30;
const DOORBELLS: u64 = 0x1000;

const CC_ENABLE: u32 = 1;
/// I/O completion entries are 16 bytes (2^4), submission entries 64 (2^6).
const CC_QUEUE_ENTRY_SIZES: u32 = (4 << 20) | (6 << 16);
const CSTS_READY: u32 = 1;
const CSTS_FATAL: u32 = 1 << 1;

const ADMIN_CREATE_SQ: u8 = 0x01;
const ADMIN_CREATE_CQ: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;
const IO_FLUSH: u8 = 0x00;
const IO_WRITE: u8 = 0x01;
const IO_READ: u8 = 0x02;

const IDENTIFY_NAMESPACE: u32 = 0;
const IDENTIFY_CONTROLLER: u32 = 1;
const IDENTIFY_ACTIVE_NAMESPACES: u32 = 2;

const QUEUE_ENTRIES: u16 = 16;
const IO_QUEUE: u16 = 1;
const PAGE: usize = 4096;
/// Polls of the phase tag before each wait for the next timer tick.
const SPIN_LIMIT: u32 = 50_000;
/// Timer ticks (~1 ms) an admin or I/O command may take.
const COMMAND_TICKS: u64 = 5_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// Another driver owns the function.
    Claim(pci::ClaimError),
    Bar(pci::BarError),
    Map {
        error: mmio::MapError,
        bar: u64,
    },
    /// CAP.CSS lacks the NVM command set.
    NoNvmCommandSet,
    /// The controller cannot use 4 KiB memory pages.
    PageSize,
    NoNamespace,
    /// Only 512-byte LBAs without metadata are supported.
    LbaFormat {
        lba_bytes: u64,
        metadata_bytes: u16,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NvmeError {
    Absent,
    Refused(Refusal),
    /// CSTS.RDY never reached the expected value, or a command never
    /// completed, within its bound.
    Timeout(&'static str),
    /// CSTS.CFS was set, or an earlier timeout left the queues unusable.
    Fatal,
    /// A completion with nonzero status (`SCT << 8 | SC`), or one that
    /// answers a different command.
    Command {
        opcode: u8,
        status: u16,
    },
    /// No `nvme-write=` option named this controller.
    ReadOnly,
    OutOfRange,
}

#[repr(C, align(4096))]
struct Page([u8; PAGE]);

static mut ADMIN_SQ: Page = Page([0; PAGE]);
static mut ADMIN_CQ: Page = Page([0; PAGE]);
static mut IO_SQ: Page = Page([0; PAGE]);
static mut IO_CQ: Page = Page([0; PAGE]);
static mut IDENTIFY: Page = Page([0; PAGE]);
static mut BOUNCE: Page = Page([0; PAGE]);

fn address(page: *mut Page) -> u64 {
    page as u64
}

#[derive(Clone, Copy, Debug)]
struct Queue {
    id: u16,
    submission: u64,
    completion: u64,
    entries: u16,
    tail: u16,
    head: u16,
    phase: u32,
}

impl Queue {
    const fn new(id: u16, submission: u64, completion: u64, entries: u16) -> Self {
        Self {
            id,
            submission,
            completion,
            entries,
            tail: 0,
            head: 0,
            phase: 1,
        }
    }
}

/// What the controller and namespace said about themselves.
#[derive(Clone, Copy, Debug)]
pub struct Identity {
    pub pci: pci::Function,
    pub vendor: u16,
    pub device: u16,
    pub version: u32,
    pub serial: [u8; 20],
    pub model: [u8; 40],
    pub volatile_write_cache: bool,
    pub namespace: u32,
    pub sectors: u64,
    pub writable: bool,
}

impl Identity {
    /// The serial number without its trailing space padding.
    pub fn serial(&self) -> &[u8] {
        trim(&self.serial)
    }

    pub fn model(&self) -> &[u8] {
        trim(&self.model)
    }
}

fn trim(field: &[u8]) -> &[u8] {
    let end = field
        .iter()
        .rposition(|&byte| byte != b' ' && byte != 0)
        .map_or(0, |last| last + 1);
    &field[..end]
}

#[derive(Clone, Copy, Debug)]
struct Controller {
    registers: u64,
    stride: u64,
    admin: Queue,
    io: Queue,
    next_command: u16,
    identity: Identity,
    /// Set by a timeout or a completion for the wrong command: the queue
    /// positions are no longer known, so every later command fails at once.
    failed: bool,
}

static mut CONTROLLER: Option<Controller> = None;
/// Commands completed successfully, and FLUSH commands among them.
static mut COMPLETED: u64 = 0;
static mut FLUSHES: u64 = 0;

fn controller() -> Option<&'static mut Controller> {
    crate::kernel_lock::assert_bsp_device_access();
    unsafe { (*core::ptr::addr_of_mut!(CONTROLLER)).as_mut() }
}

/// `(completed commands, completed FLUSH commands)` since boot.
pub fn completed() -> (u64, u64) {
    crate::kernel_lock::assert_bsp_device_access();
    unsafe {
        (
            core::ptr::read_volatile(core::ptr::addr_of!(COMPLETED)),
            core::ptr::read_volatile(core::ptr::addr_of!(FLUSHES)),
        )
    }
}

fn ticks() -> u64 {
    crate::timer_ticks.load(core::sync::atomic::Ordering::Relaxed)
}

impl Controller {
    fn read32(&self, offset: u64) -> u32 {
        unsafe { core::ptr::read_volatile((self.registers + offset) as *const u32) }
    }

    fn write32(&self, offset: u64, value: u32) {
        unsafe { core::ptr::write_volatile((self.registers + offset) as *mut u32, value) }
    }

    fn read64(&self, offset: u64) -> u64 {
        u64::from(self.read32(offset)) | (u64::from(self.read32(offset + 4)) << 32)
    }

    fn write64(&self, offset: u64, value: u64) {
        self.write32(offset, value as u32);
        self.write32(offset + 4, (value >> 32) as u32);
    }

    fn wait_ready(&self, ready: bool, limit: u64) -> Result<(), NvmeError> {
        crate::smp_startup::first_poll(crate::kernel_lock::WaitSite::Nvme);
        let start = ticks();
        loop {
            let status = self.read32(REG_CSTS);
            if status & CSTS_FATAL != 0 && ready {
                return Err(NvmeError::Fatal);
            }
            if (status & CSTS_READY != 0) == ready {
                return Ok(());
            }
            if ticks().wrapping_sub(start) > limit {
                return Err(NvmeError::Timeout(if ready { "enable" } else { "disable" }));
            }
            crate::block::wait_for_interrupt(crate::kernel_lock::WaitSite::Nvme);
        }
    }

    /// Submits one command on `io` (or the admin queue) and polls for its
    /// completion. Returns completion dword 0.
    fn execute(&mut self, io: bool, mut command: [u32; 16]) -> Result<u32, NvmeError> {
        if self.failed {
            return Err(NvmeError::Fatal);
        }
        // The read-only build submits nothing but these, on either queue:
        // no write, flush, format, or any other command can reach a device.
        if !crate::block::WRITES_BUILT
            && !matches!(
                (io, command[0] as u8),
                (false, ADMIN_IDENTIFY | ADMIN_CREATE_CQ | ADMIN_CREATE_SQ) | (true, IO_READ)
            )
        {
            return Err(NvmeError::ReadOnly);
        }
        let identifier = self.next_command;
        self.next_command = self.next_command.wrapping_add(1);
        let opcode = command[0] as u8;
        command[0] = u32::from(opcode) | (u32::from(identifier) << 16);
        let stride = self.stride;
        let registers = self.registers;
        let queue = if io { &mut self.io } else { &mut self.admin };
        let slot = (queue.submission + u64::from(queue.tail) * 64) as *mut u32;
        for (index, word) in command.iter().enumerate() {
            unsafe { core::ptr::write_volatile(slot.add(index), *word) };
        }
        queue.tail = (queue.tail + 1) % queue.entries;
        // The entry must be in memory before the controller sees the tail.
        fence(Ordering::SeqCst);
        let doorbell = registers + DOORBELLS + u64::from(2 * queue.id) * stride;
        unsafe { core::ptr::write_volatile(doorbell as *mut u32, u32::from(queue.tail)) };
        crate::smp_fixture::device_first_poll(crate::kernel_lock::WaitSite::Nvme);

        let entry = (queue.completion + u64::from(queue.head) * 16) as *const u32;
        let start = ticks();
        let mut spins = 0u32;
        let status_word = loop {
            let word = unsafe { core::ptr::read_volatile(entry.add(3)) };
            if (word >> 16) & 1 == queue.phase {
                break word;
            }
            if spins < SPIN_LIMIT {
                spins += 1;
                core::hint::spin_loop();
                continue;
            }
            if ticks().wrapping_sub(start) > COMMAND_TICKS {
                self.failed = true;
                return Err(NvmeError::Timeout("command"));
            }
            crate::block::wait_for_interrupt(crate::kernel_lock::WaitSite::Nvme);
        };
        fence(Ordering::SeqCst);
        let result = unsafe { core::ptr::read_volatile(entry) };
        queue.head = (queue.head + 1) % queue.entries;
        if queue.head == 0 {
            queue.phase ^= 1;
        }
        let doorbell = registers + DOORBELLS + u64::from(2 * queue.id + 1) * stride;
        unsafe { core::ptr::write_volatile(doorbell as *mut u32, u32::from(queue.head)) };
        let status = ((status_word >> 17) & 0x7ff) as u16;
        if status_word & 0xffff != u32::from(identifier) {
            self.failed = true;
            return Err(NvmeError::Command {
                opcode,
                status: 0xffff,
            });
        }
        if status != 0 {
            return Err(NvmeError::Command { opcode, status });
        }
        unsafe {
            *core::ptr::addr_of_mut!(COMPLETED) += 1;
            if io && opcode == IO_FLUSH {
                *core::ptr::addr_of_mut!(FLUSHES) += 1;
            }
        }
        Ok(result)
    }

    fn identify(
        &mut self,
        structure: u32,
        namespace: u32,
    ) -> Result<&'static [u8; PAGE], NvmeError> {
        let mut command = [0u32; 16];
        command[0] = u32::from(ADMIN_IDENTIFY);
        command[1] = namespace;
        let data = address(core::ptr::addr_of_mut!(IDENTIFY));
        command[6] = data as u32;
        command[7] = (data >> 32) as u32;
        command[10] = structure;
        self.execute(false, command)?;
        Ok(unsafe { &(*core::ptr::addr_of!(IDENTIFY)).0 })
    }

    /// One I/O command over `sectors` logical blocks from `lba`, staged in
    /// the one bounce page (so at most a page, which PRP1 alone covers).
    fn transfer(&mut self, opcode: u8, lba: u64, sectors: usize) -> Result<(), NvmeError> {
        let mut command = [0u32; 16];
        command[0] = u32::from(opcode);
        command[1] = self.identity.namespace;
        if opcode != IO_FLUSH {
            if sectors == 0 || sectors * BLOCK_SECTOR_BYTES > PAGE {
                return Err(NvmeError::OutOfRange);
            }
            let data = address(core::ptr::addr_of_mut!(BOUNCE));
            command[6] = data as u32;
            command[7] = (data >> 32) as u32;
            command[10] = lba as u32;
            command[11] = (lba >> 32) as u32;
            // Number of logical blocks, zero-based.
            command[12] = (sectors - 1) as u32;
        }
        self.execute(true, command).map(|_| ())
    }
}

fn zero(page: *mut Page) {
    unsafe {
        let bytes = page as *mut u8;
        for index in 0..PAGE {
            core::ptr::write_volatile(bytes.add(index), 0);
        }
    }
}

/// Finds, resets, and enables the first NVMe controller and its first
/// active namespace. `write_serial` is the `nvme-write=` option, if any.
pub fn prepare_qualification_mapping() -> Result<(), NvmeError> {
    assert!(crate::smp_startup::enabled());
    crate::kernel_lock::assert_bsp_device_access();
    let function =
        pci::find(CLASS_MASS_STORAGE, SUBCLASS_NVM, INTERFACE_NVME).ok_or(NvmeError::Absent)?;
    let bar =
        pci::memory_bar0(function).map_err(|error| NvmeError::Refused(Refusal::Bar(error)))?;
    // Both existing probe requests, including maximum DSTRD=15. Rounded
    // coverage may span two huge pages; finalize that before AP startup.
    mmio::map(bar, DOORBELLS + 4 * (4 << 15), mmio::Cache::Uncached)
        .map_err(|error| NvmeError::Refused(Refusal::Map { error, bar }))?;
    Ok(())
}
/// Driver ownership still begins with probe's PCI claim.
pub fn probe(write_serial: Option<&[u8]>) -> Result<Identity, NvmeError> {
    crate::kernel_lock::assert_bsp_device_access();
    let function =
        pci::find(CLASS_MASS_STORAGE, SUBCLASS_NVM, INTERFACE_NVME).ok_or(NvmeError::Absent)?;
    let (vendor, device) = pci::ids(function);
    pci::claim(function, "nvme").map_err(|error| NvmeError::Refused(Refusal::Claim(error)))?;
    let bar =
        pci::memory_bar0(function).map_err(|error| NvmeError::Refused(Refusal::Bar(error)))?;
    let map = |length| {
        mmio::map(bar, length, mmio::Cache::Uncached)
            .map_err(|error| NvmeError::Refused(Refusal::Map { error, bar }))
    };
    let registers = map(DOORBELLS + 0x1000)?;
    pci::enable_polled_dma(function);
    let mut found = Controller {
        registers,
        stride: 4,
        admin: Queue::new(
            0,
            address(core::ptr::addr_of_mut!(ADMIN_SQ)),
            address(core::ptr::addr_of_mut!(ADMIN_CQ)),
            QUEUE_ENTRIES,
        ),
        io: Queue::new(
            IO_QUEUE,
            address(core::ptr::addr_of_mut!(IO_SQ)),
            address(core::ptr::addr_of_mut!(IO_CQ)),
            QUEUE_ENTRIES,
        ),
        next_command: 1,
        identity: Identity {
            pci: function,
            vendor,
            device,
            version: 0,
            serial: [b' '; 20],
            model: [b' '; 40],
            volatile_write_cache: false,
            namespace: 0,
            sectors: 0,
            writable: false,
        },
        failed: false,
    };
    let capabilities = found.read64(REG_CAP);
    if (capabilities >> 37) & 1 == 0 {
        return Err(NvmeError::Refused(Refusal::NoNvmCommandSet));
    }
    if (capabilities >> 48) & 0xf != 0 {
        return Err(NvmeError::Refused(Refusal::PageSize));
    }
    found.stride = 4 << ((capabilities >> 32) & 0xf);
    // Doorbells for the admin and one I/O queue pair. A larger request may
    // come back as a new alias, so the registers move to it.
    found.registers = map(DOORBELLS + 4 * found.stride)?;
    let entries = QUEUE_ENTRIES.min(((capabilities & 0xffff) as u16).saturating_add(1));
    found.admin.entries = entries;
    found.io.entries = entries;
    // CAP.TO is in 500 ms units; the PIT ticks at about 1 kHz.
    let ready_limit = (((capabilities >> 24) & 0xff) * 500).max(500);
    found.identity.version = found.read32(REG_VS);

    // Reset: firmware may have left the controller enabled with its own
    // queues. Everything below is rebuilt from scratch.
    found.write32(REG_CC, 0);
    found.wait_ready(false, ready_limit)?;
    for page in [
        core::ptr::addr_of_mut!(ADMIN_SQ),
        core::ptr::addr_of_mut!(ADMIN_CQ),
        core::ptr::addr_of_mut!(IO_SQ),
        core::ptr::addr_of_mut!(IO_CQ),
    ] {
        zero(page);
    }
    found.write32(REG_INTMS, u32::MAX);
    let size = u32::from(entries - 1);
    found.write32(REG_AQA, (size << 16) | size);
    found.write64(REG_ASQ, found.admin.submission);
    found.write64(REG_ACQ, found.admin.completion);
    fence(Ordering::SeqCst);
    found.write32(REG_CC, CC_QUEUE_ENTRY_SIZES | CC_ENABLE);
    found.wait_ready(true, ready_limit)?;

    let controller_data = found.identify(IDENTIFY_CONTROLLER, 0)?;
    found
        .identity
        .serial
        .copy_from_slice(&controller_data[4..24]);
    found
        .identity
        .model
        .copy_from_slice(&controller_data[24..64]);
    found.identity.volatile_write_cache = controller_data[525] & 1 != 0;

    // The first active namespace; controllers older than NVMe 1.1 may not
    // list them, and then namespace 1 is tried.
    let namespace = match found.identify(IDENTIFY_ACTIVE_NAMESPACES, 0) {
        Ok(list) => u32::from_le_bytes([list[0], list[1], list[2], list[3]]),
        Err(NvmeError::Command { .. }) => 1,
        Err(other) => return Err(other),
    };
    if namespace == 0 {
        return Err(NvmeError::Refused(Refusal::NoNamespace));
    }
    let data = found.identify(IDENTIFY_NAMESPACE, namespace)?;
    let sectors = u64::from_le_bytes(data[0..8].try_into().unwrap_or([0; 8]));
    if sectors == 0 {
        return Err(NvmeError::Refused(Refusal::NoNamespace));
    }
    // FLBAS bits 3:0 select the format, and bits 6:5 extend the index when
    // the namespace offers more than 16 formats (NLBAF is zero-based).
    let flbas = data[26];
    let format = usize::from(flbas & 0xf) | (usize::from((flbas >> 5) & 3) << 4);
    if format > usize::from(data[25]) {
        return Err(NvmeError::Refused(Refusal::LbaFormat {
            lba_bytes: 0,
            metadata_bytes: 0,
        }));
    }
    let descriptor = 128 + 4 * format;
    let metadata_bytes = u16::from_le_bytes([data[descriptor], data[descriptor + 1]]);
    let lba_shift = data[descriptor + 2];
    if lba_shift != 9 || metadata_bytes != 0 {
        return Err(NvmeError::Refused(Refusal::LbaFormat {
            lba_bytes: 1u64.checked_shl(u32::from(lba_shift)).unwrap_or(0),
            metadata_bytes,
        }));
    }
    found.identity.namespace = namespace;
    found.identity.sectors = sectors;

    let queue_size = u32::from(entries - 1) << 16;
    let mut create = [0u32; 16];
    create[0] = u32::from(ADMIN_CREATE_CQ);
    create[6] = found.io.completion as u32;
    create[7] = (found.io.completion >> 32) as u32;
    create[10] = queue_size | u32::from(IO_QUEUE);
    // Physically contiguous; interrupts disabled.
    create[11] = 1;
    found.execute(false, create)?;
    create[0] = u32::from(ADMIN_CREATE_SQ);
    create[6] = found.io.submission as u32;
    create[7] = (found.io.submission >> 32) as u32;
    create[11] = (u32::from(IO_QUEUE) << 16) | 1;
    found.execute(false, create)?;

    // An empty option or an all-blank serial never selects a namespace.
    found.identity.writable = crate::block::WRITES_BUILT
        && write_serial.is_some_and(|name| !name.is_empty() && name == found.identity.serial());
    let identity = found.identity;
    unsafe {
        *core::ptr::addr_of_mut!(CONTROLLER) = Some(found);
    }
    Ok(identity)
}

/// The controller, once `bytes` worth of whole sectors from `lba` are
/// checked to lie inside the namespace; returns it with the sector count.
fn ready(lba: u64, bytes: usize) -> Result<(&'static mut Controller, usize), NvmeError> {
    let found = controller().ok_or(NvmeError::Absent)?;
    let sectors = crate::block::transfer_sectors(bytes).map_err(|_| NvmeError::OutOfRange)?;
    let end = lba
        .checked_add(sectors as u64)
        .ok_or(NvmeError::OutOfRange)?;
    if end > found.identity.sectors {
        return Err(NvmeError::OutOfRange);
    }
    Ok((found, sectors))
}

pub fn read_sector(lba: u64, buffer: &mut [u8; BLOCK_SECTOR_BYTES]) -> Result<(), NvmeError> {
    read_sectors(lba, buffer)
}

/// Reads `buffer.len() / 512` consecutive sectors from `lba` with one READ
/// command through the bounce page.
pub fn read_sectors(lba: u64, buffer: &mut [u8]) -> Result<(), NvmeError> {
    let (found, sectors) = ready(lba, buffer.len())?;
    found.transfer(IO_READ, lba, sectors)?;
    let bounce = unsafe { &*core::ptr::addr_of!(BOUNCE) };
    buffer.copy_from_slice(&bounce.0[..buffer.len()]);
    Ok(())
}

pub fn write_sector(lba: u64, buffer: &[u8; BLOCK_SECTOR_BYTES]) -> Result<(), NvmeError> {
    write_sectors(lba, buffer)
}

/// Writes `buffer.len() / 512` consecutive sectors from `lba` with one
/// WRITE command through the bounce page.
pub fn write_sectors(lba: u64, buffer: &[u8]) -> Result<(), NvmeError> {
    let (found, sectors) = ready(lba, buffer.len())?;
    if !found.identity.writable {
        return Err(NvmeError::ReadOnly);
    }
    let bounce = unsafe { &mut *core::ptr::addr_of_mut!(BOUNCE) };
    bounce.0[..buffer.len()].copy_from_slice(buffer);
    found.transfer(IO_WRITE, lba, sectors)
}

pub fn flush() -> Result<(), NvmeError> {
    let found = controller().ok_or(NvmeError::Absent)?;
    if !found.identity.writable {
        return Err(NvmeError::ReadOnly);
    }
    found.transfer(IO_FLUSH, 0, 0)
}

/// A one-sector read with no range check, so qualification can see the
/// device's own refusal of an LBA past the namespace.
pub fn read_unchecked(lba: u64) -> Result<(), NvmeError> {
    controller()
        .ok_or(NvmeError::Absent)?
        .transfer(IO_READ, lba, 1)
}
