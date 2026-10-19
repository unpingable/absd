//! The one block device, behind one of two backends.
//!
//! This layer knows sectors, requests, completion, and flush. It does not
//! know what any sector contains, and nothing above it (syscalls, init,
//! workloads) knows which backend is present: the sector size is always
//! 512 bytes, the counters are the same, and errors are the same
//! `BlockError` values.
//!
//! Backend selection is deterministic: an NVMe namespace (`src/nvme.rs`)
//! if a controller is present and usable, otherwise the primary ATA master
//! (`src/ata.rs`). An NVMe controller that is present but refused or failed
//! is reported on the console and the ATA probe runs as if it were absent.
//! Boots with neither probe as "no device" and expose nothing.
//!
//! Contract: a completed `write_sector` means the device accepted the
//! sector (QEMU: its host write returned, so it survives an abrupt QEMU
//! exit); a completed `flush` means the device reported every previously
//! completed write stable (ATA `FLUSH CACHE`, NVMe `FLUSH`; QEMU: host
//! `fdatasync`). Host power loss is not modelled here.

use core::fmt::Write;

use absd_kernel::syscall::{BLOCK_MAX_TRANSFER_SECTORS, BLOCK_SECTOR_BYTES};

use crate::kernel_lock::{self, WaitSite};
use crate::serial::{self, Serial};
use crate::{ata, nvme};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockError {
    /// No device answered the probe, or no device was ever found.
    Absent,
    /// The requested sector is outside the device.
    OutOfRange,
    /// The device reported an error for this request.
    Device,
    /// The device did not reach the expected state within the poll bound.
    Timeout,
    /// The device was not selected as writable at boot.
    ReadOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    Ata,
    Nvme,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Device {
    backend: Backend,
    sectors: u64,
    writable: bool,
}

static mut DEVICE: Option<Device> = None;

/// False in the `block-read-only` build: no write or flush reaches any
/// backend, and no boot option can change that.
pub const WRITES_BUILT: bool = !cfg!(feature = "block-read-only");

/// Largest request `read_sectors`/`write_sectors` accept: one page.
pub const MAX_TRANSFER_SECTORS: usize = BLOCK_MAX_TRANSFER_SECTORS as usize;

/// Completion interrupts observed; incremented by `block_stub` (ATA only;
/// the NVMe backend polls with interrupts masked).
#[unsafe(no_mangle)]
pub static mut block_interrupts: u64 = 0;

/// Request counters for the boot's final accounting line.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockStats {
    pub reads: u64,
    pub writes: u64,
    pub flushes: u64,
    pub errors: u64,
    /// Times the driver slept for an interrupt while a request was pending.
    pub waits: u64,
}

static mut STATS: BlockStats = BlockStats {
    reads: 0,
    writes: 0,
    flushes: 0,
    errors: 0,
    waits: 0,
};

pub fn stats() -> BlockStats {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STATS)) }
}

pub fn interrupts() -> u64 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(block_interrupts)) }
}

fn count(update: impl FnOnce(&mut BlockStats)) {
    unsafe {
        let mut current = stats();
        update(&mut current);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(STATS), current);
    }
}

fn counted<T>(result: Result<T, BlockError>, update: fn(&mut BlockStats)) -> Result<T, BlockError> {
    match result {
        Ok(value) => {
            count(update);
            Ok(value)
        }
        Err(error) => {
            count(|stats| stats.errors += 1);
            Err(error)
        }
    }
}

/// Sleeps until the next interrupt (a device completion, or the timer).
/// Spinning on a device register instead starves QEMU's main loop, which is
/// what delivers the completion, so every backend's poll ends here.
pub fn wait_for_interrupt(site: WaitSite) {
    count(|stats| stats.waits += 1);
    kernel_lock::wait_for_irq(site);
}

fn device() -> Option<Device> {
    kernel_lock::assert_bsp_device_access();
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DEVICE)) }
}

/// Sector count of the probed device, if any.
pub fn sector_count() -> Option<u64> {
    device().map(|found| found.sectors)
}

/// Whether the probed device accepts writes and flushes.
pub fn writable() -> bool {
    device().is_some_and(|found| found.writable)
}

pub fn backend() -> Option<Backend> {
    device().map(|found| found.backend)
}

fn nvme_error(error: nvme::NvmeError) -> BlockError {
    match error {
        nvme::NvmeError::Absent => BlockError::Absent,
        nvme::NvmeError::OutOfRange => BlockError::OutOfRange,
        nvme::NvmeError::ReadOnly => BlockError::ReadOnly,
        nvme::NvmeError::Timeout(_) => BlockError::Timeout,
        nvme::NvmeError::Refused(_) | nvme::NvmeError::Fatal | nvme::NvmeError::Command { .. } => {
            BlockError::Device
        }
    }
}

fn print_field(bytes: &[u8]) {
    for &byte in bytes {
        serial::byte_out(if byte.is_ascii_graphic() || byte == b' ' {
            byte
        } else {
            b'?'
        });
    }
}

/// Selects the backend. `nvme_write` is the serial number named by the
/// `nvme-write=` boot option, the only way an NVMe namespace becomes
/// writable.
pub fn probe(nvme_write: Option<&[u8]>) -> Result<u64, BlockError> {
    kernel_lock::assert_bsp_device_access();
    crate::survey::forbid("block device probe");
    if !WRITES_BUILT && nvme_write.is_some() {
        serial::write("NVME WRITE OPTION IGNORED: read-only build\n");
    }
    let nvme_write = if WRITES_BUILT { nvme_write } else { None };
    match nvme::probe(nvme_write) {
        Ok(identity) => {
            let function = identity.pci;
            serial::write("NVME CONTROLLER pci=");
            serial::hex_digits(u64::from(function.bus), 2);
            serial::write(":");
            serial::hex_digits(u64::from(function.device), 2);
            serial::write(".");
            serial::hex_digits(u64::from(function.function), 1);
            serial::write(" vendor=");
            serial::hex_digits(u64::from(identity.vendor), 4);
            serial::write(" device=");
            serial::hex_digits(u64::from(identity.device), 4);
            serial::write(" version=");
            serial::hex_digits(u64::from(identity.version), 8);
            serial::write(" vwc=");
            serial::decimal(u64::from(identity.volatile_write_cache));
            serial::write(" serial=");
            print_field(identity.serial());
            serial::write(" model=");
            print_field(identity.model());
            serial::write("\n");
            serial::write("NVME NAMESPACE nsid=");
            serial::decimal(u64::from(identity.namespace));
            serial::write(" lba_bytes=512 sectors=");
            serial::decimal(identity.sectors);
            serial::write(if identity.writable {
                " access=read-write (selected by nvme-write)\n"
            } else {
                " access=read-only\n"
            });
            // One read through the I/O queue proves the data path even on a
            // boot that never writes.
            let mut sector = [0u8; BLOCK_SECTOR_BYTES];
            match nvme::read_sector(0, &mut sector) {
                Ok(()) => {
                    serial::write("NVME READ OK lba=0 fnv1a=");
                    serial::hex(fnv1a(&sector));
                    serial::write("\n");
                }
                Err(error) => {
                    serial::write("NVME READ FAILED lba=0 ");
                    let _ = write!(Serial, "{error:?}");
                    serial::write("\n");
                    nvme::withdraw_failed_probe();
                    return Err(nvme_error(error));
                }
            }
            unsafe {
                *core::ptr::addr_of_mut!(DEVICE) = Some(Device {
                    backend: Backend::Nvme,
                    sectors: identity.sectors,
                    writable: identity.writable,
                });
            }
            return Ok(identity.sectors);
        }
        Err(nvme::NvmeError::Absent) => {}
        Err(error) => {
            serial::write("NVME UNAVAILABLE ");
            let _ = write!(Serial, "{error:?}");
            serial::write("\n");
        }
    }
    let sectors = ata::probe()?;
    unsafe {
        *core::ptr::addr_of_mut!(DEVICE) = Some(Device {
            backend: Backend::Ata,
            sectors,
            writable: WRITES_BUILT,
        });
    }
    Ok(sectors)
}

pub fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

fn check_range(lba: u64) -> Result<Device, BlockError> {
    let found = device().ok_or(BlockError::Absent)?;
    if lba >= found.sectors {
        return Err(BlockError::OutOfRange);
    }
    Ok(found)
}

/// The sector count a whole-sector buffer of `bytes` describes, bounded to
/// one request. Anything else is a malformed request, reported like a
/// range error.
pub fn transfer_sectors(bytes: usize) -> Result<usize, BlockError> {
    let sectors = bytes / BLOCK_SECTOR_BYTES;
    if bytes == 0 || !bytes.is_multiple_of(BLOCK_SECTOR_BYTES) || sectors > MAX_TRANSFER_SECTORS {
        return Err(BlockError::OutOfRange);
    }
    Ok(sectors)
}

/// Checks that `sectors` consecutive sectors from `lba` lie on the device.
fn check_span(lba: u64, sectors: usize) -> Result<Device, BlockError> {
    let found = device().ok_or(BlockError::Absent)?;
    let end = lba
        .checked_add(sectors as u64)
        .ok_or(BlockError::OutOfRange)?;
    if end > found.sectors {
        return Err(BlockError::OutOfRange);
    }
    Ok(found)
}

/// Reads one sector into `buffer`.
pub fn read_sector(lba: u64, buffer: &mut [u8; BLOCK_SECTOR_BYTES]) -> Result<(), BlockError> {
    let result = check_range(lba).and_then(|found| match found.backend {
        Backend::Ata => ata::read_sector(lba, buffer),
        Backend::Nvme => nvme::read_sector(lba, buffer).map_err(nvme_error),
    });
    counted(result, |stats| stats.reads += 1)
}

/// Writes one sector from `buffer`. Returns only once the device reports
/// the command complete.
pub fn write_sector(lba: u64, buffer: &[u8; BLOCK_SECTOR_BYTES]) -> Result<(), BlockError> {
    let result = check_range(lba).and_then(|found| {
        if !WRITES_BUILT || !found.writable {
            return Err(BlockError::ReadOnly);
        }
        match found.backend {
            Backend::Ata => ata::write_sector(lba, buffer),
            Backend::Nvme => nvme::write_sector(lba, buffer).map_err(nvme_error),
        }
    });
    counted(result, |stats| stats.writes += 1)
}

/// Reads `buffer.len() / 512` consecutive sectors from `lba` in one device
/// command (`transfer_sectors` bounds the buffer). One result covers the
/// request: on an error the buffer's content is unspecified.
pub fn read_sectors(lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
    let result = transfer_sectors(buffer.len())
        .and_then(|sectors| check_span(lba, sectors))
        .and_then(|found| match found.backend {
            Backend::Ata => ata::read_sectors(lba, buffer),
            Backend::Nvme => nvme::read_sectors(lba, buffer).map_err(nvme_error),
        });
    counted(result, |stats| stats.reads += 1)
}

/// Writes `buffer.len() / 512` consecutive sectors from `lba` in one device
/// command. Returns only once the device reports the whole command
/// complete; on an error some subset of the sectors may have reached the
/// device (a leading run on ATA PIO and QEMU's NVMe; indeterminate by the
/// NVMe specification). Completion is acceptance, not durability: `flush`
/// is still the barrier.
pub fn write_sectors(lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
    let result = transfer_sectors(buffer.len())
        .and_then(|sectors| check_span(lba, sectors))
        .and_then(|found| {
            if !WRITES_BUILT || !found.writable {
                return Err(BlockError::ReadOnly);
            }
            match found.backend {
                Backend::Ata => ata::write_sectors(lba, buffer),
                Backend::Nvme => nvme::write_sectors(lba, buffer).map_err(nvme_error),
            }
        });
    counted(result, |stats| stats.writes += 1)
}

/// Asks the device to make every completed write durable.
pub fn flush() -> Result<(), BlockError> {
    let result = device().ok_or(BlockError::Absent).and_then(|found| {
        if !WRITES_BUILT || !found.writable {
            return Err(BlockError::ReadOnly);
        }
        match found.backend {
            Backend::Ata => ata::flush(),
            Backend::Nvme => nvme::flush().map_err(nvme_error),
        }
    });
    counted(result, |stats| stats.flushes += 1)
}
