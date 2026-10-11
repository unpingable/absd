//! The append region behind `std::fs` on ABSD: one growing byte sequence
//! mapped linearly onto the sectors of its bounded layout region.
//!
//! Copied in spirit from `absd-user`'s `ledger` module so the platform stays
//! self-contained; the contract is identical. The observed length after a
//! restart is one past the last nonzero byte, so the region must start
//! zero-filled. Every `append` reaches the device before it returns; only
//! `flush` requests the device's own durability barrier.

use crate::layout::{Layout, MAX_RUN_SECTORS, Region, SECTOR_BYTES};

const SECTOR: u64 = SECTOR_BYTES as u64;
const RUN_BYTES: usize = MAX_RUN_SECTORS as usize * SECTOR_BYTES;

pub struct Ledger {
    block: u64,
    layout: Layout,
    region: Region,
    length: u64,
    tail: [u8; SECTOR_BYTES],
    /// A device write failed; the device may hold unacknowledged bytes past
    /// `length`, so appends are refused until a fresh process rescans.
    failed: bool,
}

impl Ledger {
    /// Recovers the region's observed length by scanning every sector of
    /// its bounded region, a run at a time; nothing outside the region is
    /// read.
    pub fn open(block: u64, layout: Layout, region: Region) -> Result<Self, i64> {
        let mut run = [0u8; RUN_BYTES];
        let mut length = 0u64;
        let mut index = 0u64;
        while index < region.sectors {
            let sectors = (region.sectors - index).min(MAX_RUN_SECTORS) as usize;
            let bytes = &mut run[..sectors * SECTOR_BYTES];
            layout.read_run(block, &region, index, bytes)?;
            if let Some(last) = bytes.iter().rposition(|byte| *byte != 0) {
                length = index * SECTOR + last as u64 + 1;
            }
            index += sectors as u64;
        }
        let mut tail = [0u8; SECTOR_BYTES];
        if !length.is_multiple_of(SECTOR) {
            layout.read(block, &region, length / SECTOR, &mut tail)?;
            for byte in &mut tail[(length % SECTOR) as usize..] {
                *byte = 0;
            }
        }
        Ok(Self { block, layout, region, length, tail, failed: false })
    }

    pub const fn len(&self) -> u64 {
        self.length
    }

    pub const fn capacity(&self) -> u64 {
        self.region.bytes()
    }

    /// Appends `bytes`, writing each touched sector once; refuses without
    /// writing when the region cannot hold every byte.
    pub fn append(&mut self, bytes: &[u8]) -> Result<(), i64> {
        if self.failed {
            return Err(-5);
        }
        let end = self.length.checked_add(bytes.len() as u64).ok_or(-22)?;
        if end > self.capacity() {
            return Err(-28);
        }
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let offset = (self.length % SECTOR) as usize;
            let take = (SECTOR_BYTES - offset).min(remaining.len());
            self.tail[offset..offset + take].copy_from_slice(&remaining[..take]);
            if let Err(code) = self.layout.write(self.block, &self.region, self.length / SECTOR, &self.tail) {
                self.tail[offset..].fill(0);
                self.failed = true;
                return Err(code);
            }
            self.length += take as u64;
            remaining = &remaining[take..];
            if self.length.is_multiple_of(SECTOR) {
                self.tail = [0u8; SECTOR_BYTES];
            }
        }
        Ok(())
    }

    pub fn flush(&self) -> Result<(), i64> {
        crate::layout::flush(self.block)
    }

    /// Reads from `offset`, bounded by the observed length.
    pub fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize, i64> {
        if offset >= self.length {
            return Ok(0);
        }
        let available = (self.length - offset).min(buffer.len() as u64) as usize;
        let mut copied = 0usize;
        let mut sector = [0u8; SECTOR_BYTES];
        while copied < available {
            let position = offset + copied as u64;
            let start = (position % SECTOR) as usize;
            self.layout.read(self.block, &self.region, position / SECTOR, &mut sector)?;
            let take = (SECTOR_BYTES - start).min(available - copied);
            buffer[copied..copied + take].copy_from_slice(&sector[start..start + take]);
            copied += take;
        }
        Ok(copied)
    }
}
