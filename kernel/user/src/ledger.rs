//! An append region over the block device: one growing byte sequence whose
//! bytes map linearly onto sectors from LBA 0.
//!
//! This is the file-shaped contract an append-only journal actually needs:
//! append, flush, read, and an observed length after a restart. It is not a
//! filesystem: there is one region, no name, no seek for writers, and no
//! truncation.
//!
//! The observed length after a restart is one past the last nonzero byte on
//! the device, so the region must start zero-filled. Every write goes to the
//! device before `append` returns; only `flush` asks the device for its own
//! durability barrier.

use crate::{BLOCK_MAX_TRANSFER_SECTORS, BLOCK_SECTOR_BYTES, Block, Error};

const SECTOR: u64 = BLOCK_SECTOR_BYTES as u64;
/// The scan reads a full request of sectors at a time.
const SCAN_BYTES: usize = BLOCK_SECTOR_BYTES * BLOCK_MAX_TRANSFER_SECTORS as usize;

pub struct Ledger {
    block: Block,
    sectors: u64,
    length: u64,
    /// Content of the sector holding byte `length` (zero past `length`).
    tail: [u8; BLOCK_SECTOR_BYTES],
    /// A device write failed: the device may hold bytes past `length` that
    /// this handle never acknowledged, so it refuses to append again. Only a
    /// fresh `open` (a new scan) re-establishes the extent.
    failed: bool,
}

impl Ledger {
    /// Recovers the region's observed length by scanning every sector.
    pub fn open(block: Block) -> Result<Self, Error> {
        let info = block.info()?;
        if info.sector_bytes != SECTOR || info.sectors == 0 {
            return Err(Error::Invalid);
        }
        let mut buffer = [0u8; SCAN_BYTES];
        let mut length = 0u64;
        let mut lba = 0u64;
        while lba < info.sectors {
            let sectors = (info.sectors - lba).min(BLOCK_MAX_TRANSFER_SECTORS) as usize;
            let span = &mut buffer[..sectors * BLOCK_SECTOR_BYTES];
            block.read_sectors(lba, span)?;
            if let Some(last) = span.iter().rposition(|byte| *byte != 0) {
                length = lba * SECTOR + last as u64 + 1;
            }
            lba += sectors as u64;
        }
        let mut tail = [0u8; BLOCK_SECTOR_BYTES];
        if !length.is_multiple_of(SECTOR) {
            block.read_sector(length / SECTOR, &mut tail)?;
            for byte in &mut tail[(length % SECTOR) as usize..] {
                *byte = 0;
            }
        }
        Ok(Self {
            block,
            sectors: info.sectors,
            length,
            tail,
            failed: false,
        })
    }

    pub const fn len(&self) -> u64 {
        self.length
    }

    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub const fn capacity(&self) -> u64 {
        self.sectors * SECTOR
    }

    pub const fn block(&self) -> Block {
        self.block
    }

    /// Appends `bytes`, writing each touched sector once. A partial final
    /// sector is written with zeros beyond the new length. Fails without
    /// writing anything when the region cannot hold every byte. After a
    /// device error the handle is latched failed: a partial append may have
    /// reached the device, so every later append is refused.
    pub fn append(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Io);
        }
        let end = self
            .length
            .checked_add(bytes.len() as u64)
            .ok_or(Error::Invalid)?;
        if end > self.capacity() {
            return Err(Error::NoMemory);
        }
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let offset = (self.length % SECTOR) as usize;
            let room = BLOCK_SECTOR_BYTES - offset;
            let take = room.min(remaining.len());
            self.tail[offset..offset + take].copy_from_slice(&remaining[..take]);
            let lba = self.length / SECTOR;
            if let Err(error) = self.block.write_sector(lba, &self.tail) {
                // Keep the zero-past-length invariant of `tail` and refuse
                // further appends: the sector may or may not have landed.
                self.tail[offset..].fill(0);
                self.failed = true;
                return Err(error);
            }
            self.length += take as u64;
            remaining = &remaining[take..];
            if self.length.is_multiple_of(SECTOR) {
                self.tail = [0u8; BLOCK_SECTOR_BYTES];
            }
        }
        Ok(())
    }

    /// The device's durability barrier for every completed write.
    pub fn flush(&self) -> Result<(), Error> {
        self.block.flush()
    }

    /// Reads from `offset`, bounded by the observed length; returns the
    /// number of bytes copied.
    pub fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize, Error> {
        if offset >= self.length {
            return Ok(0);
        }
        let available = (self.length - offset).min(buffer.len() as u64) as usize;
        let mut copied = 0usize;
        let mut sector = [0u8; BLOCK_SECTOR_BYTES];
        while copied < available {
            let position = offset + copied as u64;
            let lba = position / SECTOR;
            let start = (position % SECTOR) as usize;
            self.block.read_sector(lba, &mut sector)?;
            let take = (BLOCK_SECTOR_BYTES - start).min(available - copied);
            buffer[copied..copied + take].copy_from_slice(&sector[start..start + take]);
            copied += take;
        }
        Ok(copied)
    }
}
