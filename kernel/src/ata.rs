//! Block backend: polled ATA PIO on the primary channel's master.
//!
//! QEMU attaches the device with `-drive if=ide,index=0,format=raw`.
//!
//! Completion semantics under QEMU: a `WRITE SECTORS` command completes
//! (BSY clears without ERR/DF) only after QEMU's host `write()` of that
//! sector returned, so an acknowledged sector survives an abrupt QEMU exit.
//! `FLUSH CACHE` becomes a host `fdatasync`; it is issued honestly but this
//! kernel makes no claim about host power loss.

use core::arch::asm;

use crate::block::{BlockError, wait_for_interrupt};
use crate::kernel_lock::WaitSite;
use crate::serial::{inb, outb};
use absd_kernel::syscall::BLOCK_SECTOR_BYTES;

const DATA: u16 = 0x1f0;
const SECTOR_COUNT: u16 = 0x1f2;
const LBA_LOW: u16 = 0x1f3;
const LBA_MID: u16 = 0x1f4;
const LBA_HIGH: u16 = 0x1f5;
const DRIVE: u16 = 0x1f6;
const STATUS: u16 = 0x1f7;
const COMMAND: u16 = 0x1f7;
const CONTROL: u16 = 0x3f6;

const STATUS_ERR: u8 = 0x01;
const STATUS_DRQ: u8 = 0x08;
const STATUS_DF: u8 = 0x20;
const STATUS_BSY: u8 = 0x80;

const COMMAND_READ_SECTORS: u8 = 0x20;
const COMMAND_WRITE_SECTORS: u8 = 0x30;
const COMMAND_FLUSH_CACHE: u8 = 0xe7;
const COMMAND_IDENTIFY: u8 = 0xec;

/// Master drive, LBA addressing; the low nibble carries LBA bits 24..27.
const DRIVE_MASTER_LBA: u8 = 0xe0;
/// Device control with interrupts enabled: completion raises IRQ14, which
/// only wakes the driver's `hlt`; the driver still polls the status.
const CONTROL_IRQ: u8 = 0x00;
/// The largest LBA28 address plus one.
const LBA28_LIMIT: u64 = 1 << 28;
/// Bounded polling so a wedged device becomes an error, never a hang. Each
/// pass sleeps until an interrupt, so this is at least this many timer ticks.
const POLL_LIMIT: u32 = 20_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Device {
    sectors: u64,
}

static mut DEVICE: Option<Device> = None;

fn device() -> Option<Device> {
    crate::kernel_lock::assert_bsp_device_access();
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DEVICE)) }
}

unsafe fn inw(port: u16) -> u16 {
    let value: u16;
    unsafe {
        asm!("in ax, dx", in("dx") port, out("ax") value, options(nomem, nostack, preserves_flags));
    }
    value
}

/// The ~400ns settle the ATA spec requires after selecting a drive: four
/// reads of the alternate status register.
fn settle() {
    for _ in 0..4 {
        unsafe {
            inb(CONTROL);
        }
    }
}

fn wait_not_busy() -> Result<u8, BlockError> {
    for _ in 0..POLL_LIMIT {
        let status = unsafe { inb(STATUS) };
        if status & STATUS_BSY == 0 {
            return Ok(status);
        }
        wait_for_interrupt(WaitSite::Ata);
    }
    Err(BlockError::Timeout)
}

/// Waits for the data phase of a PIO command: DRQ set with no error.
fn wait_data_request() -> Result<(), BlockError> {
    for _ in 0..POLL_LIMIT {
        let status = unsafe { inb(STATUS) };
        if status & STATUS_BSY != 0 {
            wait_for_interrupt(WaitSite::Ata);
            continue;
        }
        if status & (STATUS_ERR | STATUS_DF) != 0 {
            return Err(BlockError::Device);
        }
        if status & STATUS_DRQ != 0 {
            return Ok(());
        }
        wait_for_interrupt(WaitSite::Ata);
    }
    Err(BlockError::Timeout)
}

/// Waits for command completion: BSY clear, no error bits, and no data
/// phase left over. DRQ still set after the last expected block means the
/// device and the driver disagree about the transfer's length; the command
/// is reported failed rather than complete.
fn wait_complete() -> Result<(), BlockError> {
    let status = wait_not_busy()?;
    if status & (STATUS_ERR | STATUS_DF | STATUS_DRQ) != 0 {
        Err(BlockError::Device)
    } else {
        Ok(())
    }
}

fn select(lba: u64) {
    unsafe {
        outb(DRIVE, DRIVE_MASTER_LBA | ((lba >> 24) as u8 & 0x0f));
    }
    settle();
}

/// Programs the task file for `sectors` (1..=255) sectors from `lba` and
/// issues `command`. The device then raises one data phase per sector.
fn issue(lba: u64, sectors: u8, command: u8) {
    unsafe {
        outb(SECTOR_COUNT, sectors);
        outb(LBA_LOW, lba as u8);
        outb(LBA_MID, (lba >> 8) as u8);
        outb(LBA_HIGH, (lba >> 16) as u8);
        outb(COMMAND, command);
    }
}

/// Looks for an ATA drive on the primary master and records its size. A
/// missing device is not an error: the boot simply has no block object.
pub fn probe() -> Result<u64, BlockError> {
    crate::kernel_lock::assert_bsp_device_access();
    unsafe {
        // Probe with the device's interrupt line quiet; IRQ14 is unmasked
        // only once a device is known to exist.
        outb(CONTROL, 0x02);
        outb(DRIVE, 0xa0);
    }
    settle();
    let floating = unsafe { inb(STATUS) };
    if floating == 0xff {
        return Err(BlockError::Absent);
    }
    unsafe {
        outb(SECTOR_COUNT, 0);
        outb(LBA_LOW, 0);
        outb(LBA_MID, 0);
        outb(LBA_HIGH, 0);
        outb(COMMAND, COMMAND_IDENTIFY);
    }
    if unsafe { inb(STATUS) } == 0 {
        return Err(BlockError::Absent);
    }
    crate::smp_startup::first_poll(WaitSite::Ata);
    wait_not_busy()?;
    // An ATAPI or SATA signature in the LBA registers is not a plain ATA
    // disk; this driver deliberately speaks only to one.
    if unsafe { inb(LBA_MID) } != 0 || unsafe { inb(LBA_HIGH) } != 0 {
        return Err(BlockError::Absent);
    }
    wait_data_request().map_err(|_| BlockError::Absent)?;
    let mut identity = [0u16; 256];
    for word in identity.iter_mut() {
        *word = unsafe { inw(DATA) };
    }
    let sectors = u64::from(identity[60]) | (u64::from(identity[61]) << 16);
    if sectors == 0 || sectors > LBA28_LIMIT {
        return Err(BlockError::Absent);
    }
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(DEVICE), Some(Device { sectors }));
        // Unmask the PIC cascade and IRQ14 on the slave; every other line
        // keeps the mask the boot sequence chose.
        outb(0x21, inb(0x21) & !0x04);
        outb(0xa1, inb(0xa1) & !0x40);
        outb(CONTROL, CONTROL_IRQ);
    }
    Ok(sectors)
}

/// Checks that `sectors` consecutive sectors from `lba` lie on the device
/// and fit one task-file count; returns the count.
fn check_span(lba: u64, bytes: usize) -> Result<u8, BlockError> {
    let device = device().ok_or(BlockError::Absent)?;
    let sectors = crate::block::transfer_sectors(bytes)?;
    let end = lba
        .checked_add(sectors as u64)
        .ok_or(BlockError::OutOfRange)?;
    if end > device.sectors {
        return Err(BlockError::OutOfRange);
    }
    u8::try_from(sectors).map_err(|_| BlockError::OutOfRange)
}

/// Reads one sector into `buffer`.
pub fn read_sector(lba: u64, buffer: &mut [u8; BLOCK_SECTOR_BYTES]) -> Result<(), BlockError> {
    read_sectors(lba, buffer)
}

/// Reads `buffer.len() / 512` consecutive sectors from `lba` with one `READ
/// SECTORS` command: one data phase per sector, then one completion.
pub fn read_sectors(lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
    let sectors = check_span(lba, buffer.len())?;
    wait_not_busy()?;
    if crate::kernel_lock::current_stop_requested() {
        return Err(BlockError::Device);
    }
    select(lba);
    issue(lba, sectors, COMMAND_READ_SECTORS);
    crate::smp_fixture::device_first_poll(WaitSite::Ata);
    for sector in buffer.as_chunks_mut::<BLOCK_SECTOR_BYTES>().0 {
        wait_data_request()?;
        // One string instruction moves the sector: QEMU then handles the
        // 256 words in a single exit instead of one exit per word.
        unsafe {
            asm!(
                "cld",
                "rep insw",
                in("dx") DATA,
                inout("rdi") sector.as_mut_ptr() => _,
                inout("rcx") BLOCK_SECTOR_BYTES / 2 => _,
                options(nostack),
            );
        }
        // Real ATA may show the previous block's DRQ for up to 400 ns.
        settle();
    }
    wait_complete()
}

/// Writes one sector from `buffer`. Returns only once the device reports
/// the command complete.
pub fn write_sector(lba: u64, buffer: &[u8; BLOCK_SECTOR_BYTES]) -> Result<(), BlockError> {
    write_sectors(lba, buffer)
}

/// Writes `buffer.len() / 512` consecutive sectors from `lba` with one
/// `WRITE SECTORS` command. Returns only once the device reports the whole
/// command complete; a failure after the first data phase leaves zero or
/// more leading sectors on the device.
pub fn write_sectors(lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
    if !crate::block::WRITES_BUILT {
        return Err(BlockError::ReadOnly);
    }
    let sectors = check_span(lba, buffer.len())?;
    wait_not_busy()?;
    if crate::kernel_lock::current_stop_requested() {
        return Err(BlockError::Device);
    }
    select(lba);
    issue(lba, sectors, COMMAND_WRITE_SECTORS);
    for sector in buffer.as_chunks::<BLOCK_SECTOR_BYTES>().0 {
        wait_data_request()?;
        unsafe {
            asm!(
                "cld",
                "rep outsw",
                in("dx") DATA,
                inout("rsi") sector.as_ptr() => _,
                inout("rcx") BLOCK_SECTOR_BYTES / 2 => _,
                options(nostack, readonly),
            );
        }
        settle();
    }
    wait_complete()
}

/// `FLUSH CACHE`: asks the device to make every completed write durable.
pub fn flush() -> Result<(), BlockError> {
    if !crate::block::WRITES_BUILT {
        return Err(BlockError::ReadOnly);
    }
    device().ok_or(BlockError::Absent)?;
    wait_not_busy()?;
    if crate::kernel_lock::current_stop_requested() {
        return Err(BlockError::Device);
    }
    select(0);
    unsafe {
        outb(COMMAND, COMMAND_FLUSH_CACHE);
    }
    wait_complete()
}
