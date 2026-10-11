//! Bounded persistent regions over the one block device, kept entirely in
//! userspace above the kernel's generic block object.
//!
//! Sector 0 holds a layout descriptor: a magic, a version, the device size it
//! was written for, and a table of regions with explicit sector bounds. A
//! zero-filled sector 0 means an unformatted device. Every region access is
//! checked against the region's own bounds, so no consumer can extend into
//! another's storage by accident, and a fresh boot rebuilds the same layout
//! from the descriptor alone. There are no names, paths, or directories:
//! regions are numbered and kinded.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::{
    SYS_BLOCK_FLUSH, SYS_BLOCK_INFO, SYS_BLOCK_READ, SYS_BLOCK_READ_MANY, SYS_BLOCK_WRITE,
    SYS_BLOCK_WRITE_MANY, syscall3,
};

pub const SECTOR_BYTES: usize = 512;
/// Largest `read_run_raw`/`write_run_raw` request: the kernel's bound, one
/// page of sectors.
pub const MAX_RUN_SECTORS: u64 = 8;
/// Bytes in a full run.
pub const RUN_BYTES: usize = MAX_RUN_SECTORS as usize * SECTOR_BYTES;
/// The kernel's answer to a syscall it does not have.
const NOSYS: i64 = -38;
const MAGIC: &[u8; 8] = b"ABSDLAY1";
const VERSION: u32 = 3;
const ENTRY_BYTES: usize = 32;
const HEADER_BYTES: usize = 24;
const CHECK_OFFSET: usize = SECTOR_BYTES - 8;
pub const MAX_REGIONS: usize = (CHECK_OFFSET - HEADER_BYTES) / ENTRY_BYTES;

/// What a region is for; the layout layer enforces only bounds.
pub const KIND_ACTIVATION: u32 = 1;
pub const KIND_LEDGER: u32 = 2;
pub const KIND_GENERATION: u32 = 3;
/// One segment of a reclaimable event log; several segments form the log.
pub const KIND_LOG: u32 = 4;
pub const LOG_SEGMENTS: usize = 4;
/// The filesystem's region; its internal structure belongs to `absd-fs`.
pub const KIND_FS: u32 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Region {
    pub id: u32,
    pub kind: u32,
    pub first: u64,
    pub sectors: u64,
}

impl Region {
    pub const fn bytes(&self) -> u64 {
        self.sectors * SECTOR_BYTES as u64
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layout {
    pub device_sectors: u64,
    count: usize,
    regions: [Region; MAX_REGIONS],
}

/// Layout errors use the same negative codes as the block syscalls so the
/// standard-library hooks can map them uniformly: `-2` unformatted, `-22`
/// malformed or out of bounds, `-17` already formatted, `-5` device.
pub const UNFORMATTED: i64 = -2;
pub const MALFORMED: i64 = -22;
pub const EXISTS: i64 = -17;

fn check(raw: i64) -> Result<u64, i64> {
    if raw < 0 { Err(raw) } else { Ok(raw as u64) }
}

pub fn device_sectors(block: u64) -> Result<u64, i64> {
    let mut record = [0u8; 16];
    check(unsafe { syscall3(SYS_BLOCK_INFO, block, record.as_mut_ptr() as u64, 0) })?;
    let sectors = u64::from_le_bytes(record[..8].try_into().unwrap());
    let sector_bytes = u64::from_le_bytes(record[8..].try_into().unwrap());
    if sector_bytes != SECTOR_BYTES as u64 || sectors == 0 {
        return Err(MALFORMED);
    }
    Ok(sectors)
}

pub fn read_raw(block: u64, lba: u64, buffer: &mut [u8; SECTOR_BYTES]) -> Result<(), i64> {
    check(unsafe { syscall3(SYS_BLOCK_READ, block, lba, buffer.as_mut_ptr() as u64) }).map(|_| ())
}

pub fn write_raw(block: u64, lba: u64, buffer: &[u8; SECTOR_BYTES]) -> Result<(), i64> {
    check(unsafe { syscall3(SYS_BLOCK_WRITE, block, lba, buffer.as_ptr() as u64) }).map(|_| ())
}

/// Set once the kernel has answered `-38` to a multi-sector request: every
/// later run goes sector by sector through `block_read`/`block_write`.
static SINGLE_SECTOR_ONLY: AtomicBool = AtomicBool::new(false);

/// Whether runs have fallen back to single sectors on this kernel.
pub fn single_sector_only() -> bool {
    SINGLE_SECTOR_ONLY.load(Ordering::Relaxed)
}

fn run_record(lba: u64, bytes: usize) -> Result<[u8; 16], i64> {
    let sectors = bytes / SECTOR_BYTES;
    if bytes == 0 || !bytes.is_multiple_of(SECTOR_BYTES) || sectors as u64 > MAX_RUN_SECTORS {
        return Err(MALFORMED);
    }
    let mut record = [0u8; 16];
    record[..8].copy_from_slice(&lba.to_le_bytes());
    record[8..].copy_from_slice(&(sectors as u64).to_le_bytes());
    Ok(record)
}

/// Reads `buffer.len() / SECTOR_BYTES` consecutive sectors (at most
/// `MAX_RUN_SECTORS`) from `lba` in one kernel request. On an error the
/// buffer's content is unspecified.
pub fn read_run_raw(block: u64, lba: u64, buffer: &mut [u8]) -> Result<(), i64> {
    let record = run_record(lba, buffer.len())?;
    if !single_sector_only() {
        let raw = unsafe {
            syscall3(SYS_BLOCK_READ_MANY, block, record.as_ptr() as u64, buffer.as_mut_ptr() as u64)
        };
        if raw != NOSYS {
            return check(raw).map(|_| ());
        }
        SINGLE_SECTOR_ONLY.store(true, Ordering::Relaxed);
    }
    for (index, sector) in buffer.chunks_exact_mut(SECTOR_BYTES).enumerate() {
        read_raw(block, lba + index as u64, sector.try_into().unwrap())?;
    }
    Ok(())
}

/// Writes `buffer.len() / SECTOR_BYTES` consecutive sectors (at most
/// `MAX_RUN_SECTORS`) from `lba` in one kernel request. Completion is the
/// device's acceptance of the whole run, not durability (`flush` is the
/// barrier); after an error some subset of the sectors may be on the
/// device: a leading run on ATA PIO and QEMU's NVMe model, as after a
/// failed sequence of single writes, but the NVMe specification leaves a
/// failed command's range indeterminate, so no caller relies on a prefix.
pub fn write_run_raw(block: u64, lba: u64, buffer: &[u8]) -> Result<(), i64> {
    let record = run_record(lba, buffer.len())?;
    if !single_sector_only() {
        let raw = unsafe {
            syscall3(SYS_BLOCK_WRITE_MANY, block, record.as_ptr() as u64, buffer.as_ptr() as u64)
        };
        if raw != NOSYS {
            return check(raw).map(|_| ());
        }
        SINGLE_SECTOR_ONLY.store(true, Ordering::Relaxed);
    }
    for (index, sector) in buffer.chunks_exact(SECTOR_BYTES).enumerate() {
        write_raw(block, lba + index as u64, sector.try_into().unwrap())?;
    }
    Ok(())
}

pub fn flush(block: u64) -> Result<(), i64> {
    check(unsafe { syscall3(SYS_BLOCK_FLUSH, block, 0, 0) }).map(|_| ())
}

/// The runs that cover `sectors` consecutive sectors in order, as
/// `(offset, length)` pairs of at most `MAX_RUN_SECTORS` each, with one
/// run ending exactly after `split` sectors when `1..=sectors` holds it:
/// a caller that must act between two particular sectors (a crash hook)
/// acts after the run that ends at `split`.
pub fn runs(sectors: u64, split: u64) -> impl Iterator<Item = (u64, u64)> {
    let mut offset = 0;
    core::iter::from_fn(move || {
        if offset >= sectors {
            return None;
        }
        let mut length = (sectors - offset).min(MAX_RUN_SECTORS);
        if offset < split && split < offset + length {
            length = split - offset;
        }
        let run = (offset, length);
        offset += length;
        Some(run)
    })
}

/// The bytes of run `(offset, length)` of a body laid out from sector 0:
/// `bytes` zero-padded to whole sectors, zeros past its end.
pub fn run_bytes<'a>(run: &'a mut [u8; RUN_BYTES], bytes: &[u8], offset: u64, length: u64) -> &'a [u8] {
    let run = &mut run[..length as usize * SECTOR_BYTES];
    let start = (offset as usize * SECTOR_BYTES).min(bytes.len());
    let end = (start + run.len()).min(bytes.len());
    run[..end - start].copy_from_slice(&bytes[start..end]);
    run[end - start..].fill(0);
    run
}

/// FNV-1a over the descriptor: a corruption and identity check, not a
/// security boundary.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

impl Layout {
    pub fn regions(&self) -> &[Region] {
        &self.regions[..self.count]
    }

    pub fn region(&self, id: u32) -> Option<Region> {
        self.regions().iter().copied().find(|region| region.id == id)
    }

    pub fn first_of_kind(&self, kind: u32) -> Option<Region> {
        self.regions().iter().copied().find(|region| region.kind == kind)
    }

    /// The fixed v3 table for one device. The first half keeps the v2
    /// proportions: two activation sectors, a ledger (to the first eighth),
    /// four equal event-log segments (second eighth), and two generation
    /// slots of equal size (second quarter). The second half is one
    /// filesystem region.
    pub fn v3(device_sectors: u64) -> Result<Self, i64> {
        if device_sectors < 512 {
            return Err(MALFORMED);
        }
        let half = device_sectors / 2;
        let slot = half / 4;
        let segment = slot / LOG_SEGMENTS as u64;
        let ledger_first = 16;
        let log_first = slot;
        let ledger_sectors = log_first - ledger_first;
        let mut table = [
            Region { id: 1, kind: KIND_ACTIVATION, first: 1, sectors: 2 },
            Region { id: 2, kind: KIND_LEDGER, first: ledger_first, sectors: ledger_sectors },
            Region { id: 3, kind: KIND_GENERATION, first: half - 2 * slot, sectors: slot },
            Region { id: 4, kind: KIND_GENERATION, first: half - slot, sectors: slot },
            Region { id: 5, kind: KIND_LOG, first: log_first, sectors: segment },
            Region { id: 6, kind: KIND_LOG, first: log_first + segment, sectors: segment },
            Region { id: 7, kind: KIND_LOG, first: log_first + 2 * segment, sectors: segment },
            Region { id: 8, kind: KIND_LOG, first: log_first + 3 * segment, sectors: segment },
            Region { id: 9, kind: KIND_FS, first: half, sectors: device_sectors - half },
        ];
        table.sort_unstable_by_key(|region| region.id);
        let mut regions = [Region { id: 0, kind: 0, first: 0, sectors: 0 }; MAX_REGIONS];
        regions[..table.len()].copy_from_slice(&table);
        let layout = Self { device_sectors, count: table.len(), regions };
        layout.validate()?;
        Ok(layout)
    }

    /// Regions of one kind in id order.
    pub fn of_kind(&self, kind: u32) -> impl Iterator<Item = Region> + '_ {
        self.regions().iter().copied().filter(move |region| region.kind == kind)
    }

    /// Bounds, uniqueness, and non-overlap; sector 0 is never a region.
    pub fn validate(&self) -> Result<(), i64> {
        if self.count == 0 || self.count > MAX_REGIONS {
            return Err(MALFORMED);
        }
        for (index, region) in self.regions().iter().enumerate() {
            if region.sectors == 0
                || region.first == 0
                || region.first.checked_add(region.sectors).is_none_or(|end| end > self.device_sectors)
                || !matches!(region.kind, KIND_ACTIVATION | KIND_LEDGER | KIND_GENERATION | KIND_LOG | KIND_FS)
            {
                return Err(MALFORMED);
            }
            for other in &self.regions()[..index] {
                let disjoint = region.first + region.sectors <= other.first
                    || other.first + other.sectors <= region.first;
                if other.id == region.id || !disjoint {
                    return Err(MALFORMED);
                }
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> [u8; SECTOR_BYTES] {
        let mut sector = [0u8; SECTOR_BYTES];
        sector[..8].copy_from_slice(MAGIC);
        sector[8..12].copy_from_slice(&VERSION.to_le_bytes());
        sector[12..16].copy_from_slice(&(self.count as u32).to_le_bytes());
        sector[16..24].copy_from_slice(&self.device_sectors.to_le_bytes());
        for (index, region) in self.regions().iter().enumerate() {
            let at = HEADER_BYTES + index * ENTRY_BYTES;
            sector[at..at + 4].copy_from_slice(&region.id.to_le_bytes());
            sector[at + 4..at + 8].copy_from_slice(&region.kind.to_le_bytes());
            sector[at + 8..at + 16].copy_from_slice(&region.first.to_le_bytes());
            sector[at + 16..at + 24].copy_from_slice(&region.sectors.to_le_bytes());
        }
        let check = fnv1a(&sector[..CHECK_OFFSET]);
        sector[CHECK_OFFSET..].copy_from_slice(&check.to_le_bytes());
        sector
    }

    pub fn decode(sector: &[u8; SECTOR_BYTES], device_sectors: u64) -> Result<Self, i64> {
        if sector.iter().all(|byte| *byte == 0) {
            return Err(UNFORMATTED);
        }
        if &sector[..8] != MAGIC
            || u32::from_le_bytes(sector[8..12].try_into().unwrap()) != VERSION
            || u64::from_le_bytes(sector[CHECK_OFFSET..].try_into().unwrap())
                != fnv1a(&sector[..CHECK_OFFSET])
        {
            return Err(MALFORMED);
        }
        let count = u32::from_le_bytes(sector[12..16].try_into().unwrap()) as usize;
        let written_for = u64::from_le_bytes(sector[16..24].try_into().unwrap());
        if count == 0 || count > MAX_REGIONS || written_for != device_sectors {
            return Err(MALFORMED);
        }
        let mut regions = [Region { id: 0, kind: 0, first: 0, sectors: 0 }; MAX_REGIONS];
        for (index, region) in regions[..count].iter_mut().enumerate() {
            let at = HEADER_BYTES + index * ENTRY_BYTES;
            *region = Region {
                id: u32::from_le_bytes(sector[at..at + 4].try_into().unwrap()),
                kind: u32::from_le_bytes(sector[at + 4..at + 8].try_into().unwrap()),
                first: u64::from_le_bytes(sector[at + 8..at + 16].try_into().unwrap()),
                sectors: u64::from_le_bytes(sector[at + 16..at + 24].try_into().unwrap()),
            };
        }
        for byte in &sector[HEADER_BYTES + count * ENTRY_BYTES..CHECK_OFFSET] {
            if *byte != 0 {
                return Err(MALFORMED);
            }
        }
        let layout = Self { device_sectors, count, regions };
        layout.validate()?;
        // Version 3 has exactly one table per device size; anything else is
        // a descriptor this code never wrote (kind confusion, extra regions).
        if layout != Self::v3(device_sectors)? {
            return Err(MALFORMED);
        }
        Ok(layout)
    }

    /// Reads and validates the descriptor on the device.
    pub fn open(block: u64) -> Result<Self, i64> {
        let device_sectors = device_sectors(block)?;
        let mut sector = [0u8; SECTOR_BYTES];
        read_raw(block, 0, &mut sector)?;
        Self::decode(&sector, device_sectors)
    }

    /// Writes the v3 descriptor onto a blank device and flushes it. Refuses
    /// a device with any nonzero sector: a zero sector 0 over surviving
    /// activation records, generations, or ledger bytes (a lost descriptor,
    /// or an earlier layout) must not be formatted into believed state.
    pub fn format(block: u64) -> Result<Self, i64> {
        let device_sectors = device_sectors(block)?;
        let mut run = [0u8; MAX_RUN_SECTORS as usize * SECTOR_BYTES];
        let mut lba = 0;
        while lba < device_sectors {
            let sectors = (device_sectors - lba).min(MAX_RUN_SECTORS) as usize;
            read_run_raw(block, lba, &mut run[..sectors * SECTOR_BYTES])?;
            if run[..sectors * SECTOR_BYTES].iter().any(|byte| *byte != 0) {
                return Err(EXISTS);
            }
            lba += sectors as u64;
        }
        let layout = Self::v3(device_sectors)?;
        write_raw(block, 0, &layout.encode())?;
        flush(block)?;
        Ok(layout)
    }

    /// Reads one sector of `region`; `index` is region-relative.
    pub fn read(&self, block: u64, region: &Region, index: u64, buffer: &mut [u8; SECTOR_BYTES]) -> Result<(), i64> {
        self.bounded(region, index)?;
        read_raw(block, region.first + index, buffer)
    }

    /// Reads `buffer.len() / SECTOR_BYTES` consecutive sectors of `region`
    /// (at most `MAX_RUN_SECTORS`) from region-relative `index` in one
    /// request; the whole run must lie inside the region.
    pub fn read_run(&self, block: u64, region: &Region, index: u64, buffer: &mut [u8]) -> Result<(), i64> {
        let sectors = (buffer.len() / SECTOR_BYTES) as u64;
        if buffer.is_empty() || !buffer.len().is_multiple_of(SECTOR_BYTES) || sectors > MAX_RUN_SECTORS {
            return Err(MALFORMED);
        }
        self.bounded(region, index)?;
        if index.checked_add(sectors).is_none_or(|end| end > region.sectors) {
            return Err(MALFORMED);
        }
        read_run_raw(block, region.first + index, buffer)
    }

    /// Writes `buffer.len() / SECTOR_BYTES` consecutive sectors of `region`
    /// (at most `MAX_RUN_SECTORS`) from region-relative `index` in one
    /// request. Completion is acceptance, not durability; a failed run may
    /// have put any subset of its sectors on the device.
    pub fn write_run(&self, block: u64, region: &Region, index: u64, buffer: &[u8]) -> Result<(), i64> {
        let sectors = (buffer.len() / SECTOR_BYTES) as u64;
        if buffer.is_empty() || !buffer.len().is_multiple_of(SECTOR_BYTES) || sectors > MAX_RUN_SECTORS {
            return Err(MALFORMED);
        }
        self.bounded(region, index)?;
        if index.checked_add(sectors).is_none_or(|end| end > region.sectors) {
            return Err(MALFORMED);
        }
        write_run_raw(block, region.first + index, buffer)
    }

    /// Writes one sector of `region`; `index` is region-relative.
    pub fn write(&self, block: u64, region: &Region, index: u64, buffer: &[u8; SECTOR_BYTES]) -> Result<(), i64> {
        self.bounded(region, index)?;
        write_raw(block, region.first + index, buffer)
    }

    fn bounded(&self, region: &Region, index: u64) -> Result<(), i64> {
        if self.region(region.id) != Some(*region) || index >= region.sectors {
            return Err(MALFORMED);
        }
        Ok(())
    }
}
