//! The one block device, behind one of three backends.
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
//! A boot that names a SATA disk (`ahci-disk=SERIAL` or `ahci-write=SERIAL`,
//! `src/ahci_block.rs`) uses the AHCI backend and nothing else: NVMe and
//! ATA are not probed, so a disk that is missing or refused leaves the boot
//! with no device instead of another, possibly writable, one.
//!
//! A boot may name one GPT partition (`block-partition=GUID`,
//! docs/hardware/GPT-PARTITION.md). The device is then that partition:
//! `sector_count` is its length, every LBA above this layer is relative to
//! its first sector, and the range checks bound every request to it before
//! the base is added. A partition that cannot be validated leaves the boot
//! with no device, never the whole disk.
//!
//! Contract: a completed `write_sector` means the device accepted the
//! sector (QEMU: its host write returned, so it survives an abrupt QEMU
//! exit); a completed `flush` means the device reported every previously
//! completed write stable (ATA `FLUSH CACHE`, NVMe `FLUSH`, AHCI `FLUSH
//! CACHE EXT`; QEMU: host `fdatasync`). Host power loss is not modelled here.

use core::fmt::Write;

use absd_kernel::amdvi::scope::Driver;
use absd_kernel::syscall::{BLOCK_MAX_TRANSFER_SECTORS, BLOCK_SECTOR_BYTES};

use absd_kernel::storage_fence::{self, Declaration, Fence};

use crate::kernel_lock::{self, WaitSite};
use crate::serial::{self, Serial};
use crate::{ahci_block, ata, nvme};
use absd_kernel::ahci_command;
use absd_kernel::gpt;

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
    Ahci,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Device {
    backend: Backend,
    /// The device LBA of this device's sector 0: a selected partition's
    /// first sector, otherwise 0.
    base: u64,
    /// Whether `base` and `sectors` describe a GPT partition.
    partitioned: bool,
    /// Sectors addressable through this layer: the partition's length when
    /// one is selected, otherwise the whole device.
    sectors: u64,
    writable: bool,
    fence: Fence,
}

static mut DEVICE: Option<Device> = None;

/// False in the `block-read-only` build: no write or flush reaches any
/// backend, and no boot option can change that.
pub const WRITES_BUILT: bool = !cfg!(feature = "block-read-only");

/// Largest request `read_sectors`/`write_sectors` accept: one page.
pub const MAX_TRANSFER_SECTORS: usize = BLOCK_MAX_TRANSFER_SECTORS as usize;

/// Completion interrupts observed; incremented by `block_stub` (ATA only;
/// the NVMe and AHCI backends poll with interrupts masked).
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
    crate::contain::poll();
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

/// Whether the device is a GPT partition selected by `block-partition=`.
pub fn partitioned() -> bool {
    device().is_some_and(|found| found.partitioned)
}

/// This boot's storage fence (`absd_kernel::storage_fence`); not
/// established without a device.
pub fn fence() -> Fence {
    device().map_or(
        Fence::NotEstablished(storage_fence::Reason::ReadOnly),
        |found| found.fence,
    )
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

fn ahci_error(error: ahci_block::AhciError) -> BlockError {
    match error {
        ahci_block::AhciError::Absent => BlockError::Absent,
        ahci_block::AhciError::OutOfRange => BlockError::OutOfRange,
        ahci_block::AhciError::ReadOnly => BlockError::ReadOnly,
        ahci_block::AhciError::Command(ahci_command::Completion::Timeout) => BlockError::Timeout,
        ahci_block::AhciError::Refused(_)
        | ahci_block::AhciError::Command(_)
        | ahci_block::AhciError::Retired => BlockError::Device,
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

/// The SATA disk a boot names, from the `ahci-disk=` and `ahci-write=`
/// options.
#[derive(Clone, Copy, Debug, Default)]
pub struct AhciOptions<'a> {
    pub disk: Option<&'a [u8]>,
    pub write: Option<&'a [u8]>,
    /// `ahci-pretend-pending=N` and `ahci-pretend-decode-off`:
    /// qualification only (src/ahci_block.rs).
    pub pretend_pending: Option<u32>,
    pub pretend_decode_off: bool,
}

/// Selects the backend. `nvme_write` is the serial number named by the
/// `nvme-write=` boot option, the only way an NVMe namespace becomes
/// writable; `ahci` names a SATA disk, which then is the only candidate;
/// `declaration` is the `storage-fence=` option, classified against the
/// backend found.
///
/// `partition` is the `block-partition=` value: the backend is selected
/// and proved exactly as without it, then the device becomes that GPT
/// partition or, if it cannot be validated, no device at all.
pub fn probe(
    nvme_write: Option<&[u8]>,
    ahci: AhciOptions,
    declaration: Declaration,
    partition: Option<&[u8]>,
) -> Result<u64, BlockError> {
    // A `dma-contain` boot has no storage fallback: only the named target.
    if crate::contain::active()
        && (crate::contain::named(Driver::Ahci).is_none()
            || (ahci.disk.is_none() && ahci.write.is_none()))
    {
        return Err(BlockError::Absent);
    }
    kernel_lock::assert_bsp_device_access();
    crate::survey::forbid("block device probe");
    let partition = match partition.map(gpt::Guid::parse) {
        None => None,
        Some(Some(guid)) => Some(guid),
        Some(None) => {
            // Refused before any controller is touched.
            serial::write("BLOCK PARTITION REFUSED malformed-guid\n");
            return Err(BlockError::Absent);
        }
    };
    if ahci.disk.is_some() || ahci.write.is_some() {
        if nvme_write.is_some() {
            serial::write("NVME WRITE OPTION IGNORED: an AHCI disk is selected\n");
        }
        return probe_ahci(ahci, declaration, partition);
    }
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
            return publish(
                Device {
                    backend: Backend::Nvme,
                    base: 0,
                    partitioned: false,
                    sectors: identity.sectors,
                    writable: identity.writable,
                    // A probe that returned the identity completed the
                    // disable handshake (nvme::disable_before_probe) before
                    // rebuilding its queues or enabling DMA.
                    fence: storage_fence::classify(
                        storage_fence::Backend::Nvme,
                        identity.writable,
                        declaration,
                        true,
                    ),
                },
                partition,
            );
        }
        Err(nvme::NvmeError::Absent) => {}
        Err(error) => {
            serial::write("NVME UNAVAILABLE ");
            let _ = write!(Serial, "{error:?}");
            serial::write("\n");
        }
    }
    let sectors = ata::probe()?;
    publish(
        Device {
            backend: Backend::Ata,
            base: 0,
            partitioned: false,
            sectors,
            writable: WRITES_BUILT,
            // The PIO driver issues no reset of its own.
            fence: storage_fence::classify(
                storage_fence::Backend::Ata,
                WRITES_BUILT,
                declaration,
                false,
            ),
        },
        partition,
    )
}

fn probe_ahci(
    options: AhciOptions,
    declaration: Declaration,
    partition: Option<gpt::Guid>,
) -> Result<u64, BlockError> {
    if !WRITES_BUILT && options.write.is_some() {
        serial::write("AHCI WRITE OPTION IGNORED: read-only build\n");
    }
    let selection = match ahci_command::select(options.disk, options.write, WRITES_BUILT) {
        Ok(Some(selection)) => selection,
        Ok(None) => return Err(BlockError::Absent),
        Err(error) => {
            serial::write("AHCI UNAVAILABLE ");
            let _ = write!(
                Serial,
                "{:?}",
                ahci_block::AhciError::Refused(ahci_block::Refusal::Selection(error))
            );
            serial::write("\n");
            return Err(BlockError::Absent);
        }
    };
    if let Some(port) = options.pretend_pending {
        ahci_block::pretend_pending(u64::from(port));
    }
    if options.pretend_decode_off {
        ahci_block::pretend_decode_off();
    }
    let found = match crate::contain::named(Driver::Ahci) {
        Some(function) => ahci_block::probe_contained(function, selection),
        None => ahci_block::probe(selection),
    };
    let identity = match found {
        Ok(identity) => identity,
        Err(error) => {
            serial::write("AHCI UNAVAILABLE ");
            let _ = write!(Serial, "{error:?}");
            serial::write("\n");
            return Err(BlockError::Absent);
        }
    };
    serial::write("AHCI CONTROLLER pci=");
    serial::hex_digits(u64::from(identity.pci.bus), 2);
    serial::write(":");
    serial::hex_digits(u64::from(identity.pci.device), 2);
    serial::write(".");
    serial::hex_digits(u64::from(identity.pci.function), 1);
    serial::write(" vendor=");
    serial::hex_digits(u64::from(identity.vendor), 4);
    serial::write(" device=");
    serial::hex_digits(u64::from(identity.device), 4);
    serial::write(" port=");
    serial::decimal(u64::from(identity.port));
    serial::write(" serial=");
    print_field(identity.serial());
    serial::write(" model=");
    print_field(identity.model());
    serial::write("\n");
    serial::write("AHCI DISK lba_bytes=512 sectors=");
    serial::decimal(identity.sectors);
    serial::write(if identity.writable {
        " access=read-write (selected by ahci-write)\n"
    } else {
        " access=read-only\n"
    });
    let mut sector = [0u8; BLOCK_SECTOR_BYTES];
    match ahci_block::read_sector(0, &mut sector) {
        Ok(()) => {
            serial::write("AHCI READ OK lba=0 fnv1a=");
            serial::hex(fnv1a(&sector));
            serial::write("\n");
        }
        Err(error) => {
            serial::write("AHCI READ FAILED lba=0 ");
            let _ = write!(Serial, "{error:?}");
            serial::write("\n");
            ahci_block::withdraw_failed_probe();
            return Err(ahci_error(error));
        }
    }
    publish(
        Device {
            backend: Backend::Ahci,
            base: 0,
            partitioned: false,
            sectors: identity.sectors,
            writable: identity.writable,
            // Port stop and start only: no COMRESET, no HBA reset.
            fence: storage_fence::classify(
                storage_fence::Backend::Ahci,
                identity.writable,
                declaration,
                false,
            ),
        },
        partition,
    )
}

/// Device-absolute reads for the GPT walk, before the device is published:
/// uncounted, like each backend's proving read.
fn read_whole_device(backend: Backend, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
    match backend {
        Backend::Ata => ata::read_sectors(lba, buffer),
        Backend::Nvme => nvme::read_sectors(lba, buffer).map_err(nvme_error),
        Backend::Ahci => ahci_block::read_sectors(lba, buffer).map_err(ahci_error),
    }
}

/// Publishes the probed whole device or, with `partition`, the partition
/// it names. A refusal publishes nothing: the boot has no device, and the
/// backend, proved but unpublished, is never issued another command.
fn publish(whole: Device, partition: Option<gpt::Guid>) -> Result<u64, BlockError> {
    let Some(target) = partition else {
        unsafe {
            *core::ptr::addr_of_mut!(DEVICE) = Some(whole);
        }
        return Ok(whole.sectors);
    };
    let found = match gpt::locate(whole.sectors, &target, |lba, buffer: &mut [u8]| {
        read_whole_device(whole.backend, lba, buffer)
    }) {
        Ok(found) => found,
        Err(refusal) => {
            let _ = writeln!(Serial, "BLOCK PARTITION REFUSED {refusal}");
            return Err(BlockError::Absent);
        }
    };
    serial::write("BLOCK PARTITION guid=");
    for byte in found.guid.text() {
        serial::byte_out(byte);
    }
    serial::write(" first_lba=");
    serial::decimal(found.first_lba);
    serial::write(" sectors=");
    serial::decimal(found.sectors);
    serial::write(" (of device_sectors=");
    serial::decimal(whole.sectors);
    serial::write(")\n");
    // The partition is writable exactly when the backend was selected
    // writable by the existing rules; every request is still bounded to it
    // by `check_range`/`check_span` before the base is added.
    let writable = whole.writable;
    serial::write(if !writable {
        "BLOCK PARTITION access=read-only\n"
    } else {
        match whole.backend {
            Backend::Ahci => {
                "BLOCK PARTITION access=read-write (selected writable by ahci-write)\n"
            }
            Backend::Nvme => {
                "BLOCK PARTITION access=read-write (selected writable by nvme-write)\n"
            }
            Backend::Ata => {
                "BLOCK PARTITION access=read-write (selected writable by the ATA default)\n"
            }
        }
    });
    let selected = Device {
        base: found.first_lba,
        partitioned: true,
        sectors: found.sectors,
        writable,
        fence: if writable {
            whole.fence
        } else {
            Fence::NotEstablished(storage_fence::Reason::ReadOnly)
        },
        ..whole
    };
    unsafe {
        *core::ptr::addr_of_mut!(DEVICE) = Some(selected);
    }
    Ok(found.sectors)
}

pub fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// Checks that `lba` lies on the device (the partition, if one is
/// selected); returns the device and the LBA the backend is given.
fn check_range(lba: u64) -> Result<(Device, u64), BlockError> {
    crate::contain::poll();
    let found = device().ok_or(BlockError::Absent)?;
    if lba >= found.sectors {
        return Err(BlockError::OutOfRange);
    }
    Ok((found, absolute(&found, lba)?))
}

/// The backend's LBA for the device's `lba`, already checked relative to
/// the device. With no partition `base` is 0 and this is `lba` itself.
fn absolute(found: &Device, lba: u64) -> Result<u64, BlockError> {
    found.base.checked_add(lba).ok_or(BlockError::OutOfRange)
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

/// Checks that `sectors` consecutive sectors from `lba` lie on the device
/// (the partition, if one is selected); returns the device and the LBA the
/// backend is given.
fn check_span(lba: u64, sectors: usize) -> Result<(Device, u64), BlockError> {
    crate::contain::poll();
    let found = device().ok_or(BlockError::Absent)?;
    let end = lba
        .checked_add(sectors as u64)
        .ok_or(BlockError::OutOfRange)?;
    if end > found.sectors {
        return Err(BlockError::OutOfRange);
    }
    Ok((found, absolute(&found, lba)?))
}

/// Reads one sector into `buffer`.
pub fn read_sector(lba: u64, buffer: &mut [u8; BLOCK_SECTOR_BYTES]) -> Result<(), BlockError> {
    let result = check_range(lba).and_then(|(found, lba)| match found.backend {
        Backend::Ata => ata::read_sector(lba, buffer),
        Backend::Nvme => nvme::read_sector(lba, buffer).map_err(nvme_error),
        Backend::Ahci => ahci_block::read_sector(lba, buffer).map_err(ahci_error),
    });
    counted(result, |stats| stats.reads += 1)
}

/// Writes one sector from `buffer`. Returns only once the device reports
/// the command complete.
pub fn write_sector(lba: u64, buffer: &[u8; BLOCK_SECTOR_BYTES]) -> Result<(), BlockError> {
    let result = check_range(lba).and_then(|(found, lba)| {
        if !WRITES_BUILT || !found.writable {
            return Err(BlockError::ReadOnly);
        }
        match found.backend {
            Backend::Ata => ata::write_sector(lba, buffer),
            Backend::Nvme => nvme::write_sector(lba, buffer).map_err(nvme_error),
            Backend::Ahci => ahci_block::write_sector(lba, buffer).map_err(ahci_error),
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
        .and_then(|(found, lba)| match found.backend {
            Backend::Ata => ata::read_sectors(lba, buffer),
            Backend::Nvme => nvme::read_sectors(lba, buffer).map_err(nvme_error),
            Backend::Ahci => ahci_block::read_sectors(lba, buffer).map_err(ahci_error),
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
        .and_then(|(found, lba)| {
            if !WRITES_BUILT || !found.writable {
                return Err(BlockError::ReadOnly);
            }
            match found.backend {
                Backend::Ata => ata::write_sectors(lba, buffer),
                Backend::Nvme => nvme::write_sectors(lba, buffer).map_err(nvme_error),
                Backend::Ahci => ahci_block::write_sectors(lba, buffer).map_err(ahci_error),
            }
        });
    counted(result, |stats| stats.writes += 1)
}

/// Asks the device to make every completed write durable.
pub fn flush() -> Result<(), BlockError> {
    crate::contain::poll();
    let result = device().ok_or(BlockError::Absent).and_then(|found| {
        if !WRITES_BUILT || !found.writable {
            return Err(BlockError::ReadOnly);
        }
        match found.backend {
            Backend::Ata => ata::flush(),
            Backend::Nvme => nvme::flush().map_err(nvme_error),
            Backend::Ahci => ahci_block::flush().map_err(ahci_error),
        }
    });
    counted(result, |stats| stats.flushes += 1)
}
