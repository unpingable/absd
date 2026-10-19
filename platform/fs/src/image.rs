//! On-disk encoding: superblocks, geometry, and the metadata image.
//!
//! Region layout (sectors, relative to the region):
//!
//! ```text
//! 0        superblock slot 0
//! 1        superblock slot 1
//! 2..8     reserved, zero
//! 8..      metadata half 0, then metadata half 1 (`half_sectors` each)
//! data_first..  data blocks of 4 KiB
//! ```
//!
//! This is format 2: format 1 (magics `ABSDFSS1`/`ABSDFSI1`, version 1,
//! 32-byte object records) plus a `u64 mtime` at the end of every record.
//! Only format 2 is read; a superblock of the family (`ABSDFSS` and a
//! version digit) with any other version is [`Error::UnsupportedFormat`].
//!
//! A superblock names one sequence number and the digest of the image in
//! the half with the same parity. The image is the whole namespace; the
//! allocated block set is derived from it, never stored.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use crate::{Error, Kind, SECTOR};

pub const BLOCK: usize = 4096;
pub const SECTORS_PER_BLOCK: u64 = (BLOCK / SECTOR) as u64;
pub const VERSION: u32 = 2;
const SUPER_MAGIC: &[u8; 8] = b"ABSDFSS2";
/// Every format's superblock starts with this and a version digit.
const SUPER_FAMILY: &[u8; 7] = b"ABSDFSS";
const IMAGE_MAGIC: &[u8; 8] = b"ABSDFSI2";
pub const HEADER_BYTES: usize = 64;
/// Fixed bytes of an object record: serial, parent, size, kind, flags,
/// name length, block count, mtime. The name and block list follow.
pub const RECORD_BYTES: usize = 40;
pub const MAX_NAME: usize = 255;
/// Bytes of every image reserved for object records; block references get
/// their own worst-case reservation, so a commit can never overflow a half.
pub const OBJECT_BUDGET: usize = 64 * 1024;
const META_FIRST: u64 = 8;
const CHECK_OFFSET: usize = SECTOR - 32;
pub const ROOT: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    pub region_sectors: u64,
    pub half_sectors: u64,
    pub data_first: u64,
    pub data_blocks: u32,
}

impl Geometry {
    pub fn for_region(region_sectors: u64) -> Result<Self, Error> {
        let estimate = region_sectors / SECTORS_PER_BLOCK;
        let half_bytes = HEADER_BYTES as u64 + OBJECT_BUDGET as u64 + 4 * estimate;
        let half_sectors = half_bytes.div_ceil(SECTOR as u64);
        let data_first = (META_FIRST + 2 * half_sectors).next_multiple_of(SECTORS_PER_BLOCK);
        if region_sectors <= data_first + SECTORS_PER_BLOCK {
            return Err(Error::Invalid);
        }
        let blocks = (region_sectors - data_first) / SECTORS_PER_BLOCK;
        let data_blocks = u32::try_from(blocks).map_err(|_| Error::Invalid)?;
        Ok(Self { region_sectors, half_sectors, data_first, data_blocks })
    }

    pub fn half_first(&self, half: u64) -> u64 {
        META_FIRST + half * self.half_sectors
    }

    pub fn block_sector(&self, block: u32) -> u64 {
        self.data_first + u64::from(block) * SECTORS_PER_BLOCK
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Superblock {
    pub fs_id: u64,
    pub seq: u64,
    pub image_len: u32,
    pub digest: [u8; 32],
    pub geometry: Geometry,
}

fn put(bytes: &mut [u8], offset: usize, value: &[u8]) {
    bytes[offset..offset + value.len()].copy_from_slice(value);
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

impl Superblock {
    pub fn encode(&self) -> [u8; SECTOR] {
        let mut sector = [0u8; SECTOR];
        put(&mut sector, 0, SUPER_MAGIC);
        put(&mut sector, 8, &VERSION.to_le_bytes());
        put(&mut sector, 12, &((self.seq % 2) as u32).to_le_bytes());
        put(&mut sector, 16, &self.fs_id.to_le_bytes());
        put(&mut sector, 24, &self.seq.to_le_bytes());
        put(&mut sector, 32, &self.image_len.to_le_bytes());
        put(&mut sector, 40, &self.geometry.region_sectors.to_le_bytes());
        put(&mut sector, 48, &self.geometry.half_sectors.to_le_bytes());
        put(&mut sector, 56, &self.geometry.data_first.to_le_bytes());
        put(&mut sector, 64, &u64::from(self.geometry.data_blocks).to_le_bytes());
        put(&mut sector, 72, &self.digest);
        let check = sha256(&sector[..CHECK_OFFSET]);
        put(&mut sector, CHECK_OFFSET, &check);
        sector
    }

    /// `None` for an all-zero (never written) slot.
    pub fn decode(sector: &[u8; SECTOR], slot: u64) -> Result<Option<Self>, Error> {
        if sector.iter().all(|byte| *byte == 0) {
            return Ok(None);
        }
        // Another version of the family is refused by name before anything
        // else of it is interpreted: its layout is not this one.
        if &sector[..7] == SUPER_FAMILY && sector[..8] != SUPER_MAGIC[..] {
            return Err(Error::UnsupportedFormat);
        }
        if &sector[..8] != SUPER_MAGIC
            || sha256(&sector[..CHECK_OFFSET])[..] != sector[CHECK_OFFSET..]
        {
            return Err(Error::Corrupt("superblock checksum"));
        }
        if u32_at(sector, 8) != VERSION {
            return Err(Error::UnsupportedFormat);
        }
        if sector[104..CHECK_OFFSET].iter().any(|byte| *byte != 0) || u32_at(sector, 36) != 0 {
            return Err(Error::Corrupt("superblock reserved bytes"));
        }
        let seq = u64_at(sector, 24);
        if seq % 2 != slot || u64::from(u32_at(sector, 12)) != slot {
            return Err(Error::Corrupt("superblock slot parity"));
        }
        let blocks = u64_at(sector, 64);
        let geometry = Geometry {
            region_sectors: u64_at(sector, 40),
            half_sectors: u64_at(sector, 48),
            data_first: u64_at(sector, 56),
            data_blocks: u32::try_from(blocks).map_err(|_| Error::Corrupt("superblock geometry"))?,
        };
        Ok(Some(Self {
            fs_id: u64_at(sector, 16),
            seq,
            image_len: u32_at(sector, 32),
            digest: sector[72..104].try_into().unwrap(),
            geometry,
        }))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub serial: u64,
    pub parent: u64,
    pub name: Vec<u8>,
    pub kind: Kind,
    pub readonly: bool,
    pub size: u64,
    pub blocks: Vec<u32>,
    /// Unix seconds; 0 is unknown.
    pub mtime: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Image {
    pub fs_id: u64,
    pub seq: u64,
    pub next_serial: u64,
    pub geometry: Geometry,
    /// Sorted by serial.
    pub records: Vec<Record>,
}

pub fn record_bytes(name_len: usize) -> usize {
    RECORD_BYTES + name_len
}

pub fn valid_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name != b"."
        && name != b".."
        && !name.iter().any(|byte| *byte == b'/' || *byte == 0)
}

/// Borrowed fields for one synchronous encoding pass, never a transfer layout.
#[derive(Clone, Copy)]
pub(crate) struct RecordRef<'a> {
    pub serial: u64,
    pub parent: u64,
    pub name: &'a [u8],
    pub kind: Kind,
    pub readonly: bool,
    pub size: u64,
    pub blocks: &'a [u32],
    pub mtime: u64,
}

impl<'a> From<&'a Record> for RecordRef<'a> {
    fn from(record: &'a Record) -> Self {
        Self {
            serial: record.serial,
            parent: record.parent,
            name: &record.name,
            kind: record.kind,
            readonly: record.readonly,
            size: record.size,
            blocks: &record.blocks,
            mtime: record.mtime,
        }
    }
}

/// The immutable record sequence is counted and sized before encoding.
/// Callers keep its source borrowed until the output buffer is complete.
pub(crate) fn encode_records<'a>(
    fs_id: u64,
    seq: u64,
    next_serial: u64,
    geometry: Geometry,
    records: impl Iterator<Item = RecordRef<'a>> + Clone,
) -> Vec<u8> {
    let count = records.clone().count();
    // The complete generation is already known. Avoid temporary small
    // buffers and doubling while commits serialize large block maps.
    let length = HEADER_BYTES
        + records.clone().map(|record| {
            record_bytes(record.name.len()) + record.blocks.len() * size_of::<u32>()
        }).sum::<usize>();
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(IMAGE_MAGIC);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&fs_id.to_le_bytes());
    bytes.extend_from_slice(&seq.to_le_bytes());
    bytes.extend_from_slice(&next_serial.to_le_bytes());
    bytes.extend_from_slice(&geometry.data_blocks.to_le_bytes());
    bytes.extend_from_slice(&(count as u32).to_le_bytes());
    bytes.extend_from_slice(&geometry.region_sectors.to_le_bytes());
    bytes.extend_from_slice(&geometry.half_sectors.to_le_bytes());
    debug_assert_eq!(bytes.len(), HEADER_BYTES);
    for record in records {
        bytes.extend_from_slice(&record.serial.to_le_bytes());
        bytes.extend_from_slice(&record.parent.to_le_bytes());
        bytes.extend_from_slice(&record.size.to_le_bytes());
        bytes.push(match record.kind {
            Kind::File => 1,
            Kind::Dir => 2,
        });
        bytes.push(u8::from(record.readonly));
        bytes.extend_from_slice(&(record.name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(record.blocks.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&record.mtime.to_le_bytes());
        bytes.extend_from_slice(record.name);
        for block in record.blocks {
            bytes.extend_from_slice(&block.to_le_bytes());
        }
    }
    bytes
}

impl Image {
    pub fn encode(&self) -> Vec<u8> {
        encode_records(self.fs_id, self.seq, self.next_serial, self.geometry,
                       self.records.iter().map(RecordRef::from))
    }

    /// Decodes and checks every structural rule a mount relies on. Anything
    /// that does not hold is refused, never repaired.
    pub fn decode(bytes: &[u8], expect: &Superblock) -> Result<Self, Error> {
        let corrupt = Error::Corrupt;
        if bytes.len() < HEADER_BYTES || &bytes[..8] != IMAGE_MAGIC {
            return Err(corrupt("image header"));
        }
        if u32_at(bytes, 8) != VERSION || u32_at(bytes, 12) != 0 {
            return Err(corrupt("image version"));
        }
        let fs_id = u64_at(bytes, 16);
        let seq = u64_at(bytes, 24);
        let next_serial = u64_at(bytes, 32);
        let data_blocks = u32_at(bytes, 40);
        let count = u32_at(bytes, 44) as usize;
        let geometry = Geometry {
            region_sectors: u64_at(bytes, 48),
            half_sectors: u64_at(bytes, 56),
            data_first: expect.geometry.data_first,
            data_blocks,
        };
        if fs_id != expect.fs_id || seq != expect.seq || geometry != expect.geometry {
            return Err(corrupt("image does not match its superblock"));
        }
        let mut records: Vec<Record> = Vec::new();
        let mut offset = HEADER_BYTES;
        let mut object_bytes = HEADER_BYTES;
        for _ in 0..count {
            if bytes.len() < offset + RECORD_BYTES {
                return Err(corrupt("truncated object record"));
            }
            let serial = u64_at(bytes, offset);
            let parent = u64_at(bytes, offset + 8);
            let size = u64_at(bytes, offset + 16);
            let kind = match bytes[offset + 24] {
                1 => Kind::File,
                2 => Kind::Dir,
                _ => return Err(corrupt("object kind")),
            };
            let readonly = match bytes[offset + 25] {
                0 => false,
                1 => true,
                _ => return Err(corrupt("object flags")),
            };
            let name_len = u16::from_le_bytes(bytes[offset + 26..offset + 28].try_into().unwrap());
            let name_len = usize::from(name_len);
            let block_count = u32_at(bytes, offset + 28) as usize;
            let mtime = u64_at(bytes, offset + 32);
            offset += RECORD_BYTES;
            let name_end = offset + name_len;
            let end = block_count
                .checked_mul(4)
                .and_then(|block_bytes| name_end.checked_add(block_bytes))
                .ok_or(corrupt("object record length"))?;
            if bytes.len() < end {
                return Err(corrupt("truncated object record"));
            }
            let name = bytes[offset..name_end].to_vec();
            let blocks = bytes[name_end..end]
                .chunks_exact(4)
                .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
                .collect();
            offset = end;
            object_bytes += record_bytes(name_len);
            records.push(Record { serial, parent, name, kind, readonly, size, blocks, mtime });
        }
        if offset != bytes.len() {
            return Err(corrupt("trailing image bytes"));
        }
        if object_bytes > OBJECT_BUDGET {
            return Err(corrupt("object records exceed their budget"));
        }
        let image = Self { fs_id, seq, next_serial, geometry, records };
        image.validate()?;
        Ok(image)
    }

    fn validate(&self) -> Result<(), Error> {
        let corrupt = Error::Corrupt;
        let records = &self.records;
        if records.windows(2).any(|pair| pair[0].serial >= pair[1].serial) {
            return Err(corrupt("object serials not strictly ordered"));
        }
        let Some(root) = records.first() else { return Err(corrupt("no root")) };
        if root.serial != ROOT
            || root.parent != 0
            || !root.name.is_empty()
            || root.kind != Kind::Dir
            || root.readonly
            || root.size != 0
            || !root.blocks.is_empty()
        {
            return Err(corrupt("root record"));
        }
        let last = records.last().unwrap().serial;
        if self.next_serial <= last {
            return Err(corrupt("next serial does not exceed every serial"));
        }
        let find = |serial: u64| records.binary_search_by_key(&serial, |record| record.serial);
        let mut used = alloc::vec![0u64; (self.geometry.data_blocks as usize).div_ceil(64)];
        let mut names: Vec<(u64, &[u8])> = Vec::with_capacity(records.len());
        for record in &records[1..] {
            if !valid_name(&record.name) {
                return Err(corrupt("object name"));
            }
            let parent = find(record.parent).map_err(|_| corrupt("dangling parent"))?;
            if records[parent].kind != Kind::Dir {
                return Err(corrupt("parent is not a directory"));
            }
            names.push((record.parent, &record.name));
            match record.kind {
                Kind::Dir => {
                    if record.size != 0 || !record.blocks.is_empty() || record.readonly {
                        return Err(corrupt("directory with contents"));
                    }
                }
                Kind::File => {
                    let expected = record.size.div_ceil(BLOCK as u64);
                    if record.blocks.len() as u64 != expected {
                        return Err(corrupt("file length does not match its blocks"));
                    }
                }
            }
            for block in &record.blocks {
                if *block >= self.geometry.data_blocks {
                    return Err(corrupt("block outside the data area"));
                }
                let (word, bit) = (*block as usize / 64, *block % 64);
                if used[word] & (1 << bit) != 0 {
                    return Err(corrupt("block referenced twice"));
                }
                used[word] |= 1 << bit;
            }
        }
        names.sort_unstable();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(corrupt("duplicate directory entry"));
        }
        // Every object must reach the root; a parent chain longer than the
        // object count is a cycle.
        for record in &records[1..] {
            let mut cursor = record.parent;
            let mut steps = 0usize;
            while cursor != ROOT {
                steps += 1;
                if steps > records.len() {
                    return Err(corrupt("directory cycle"));
                }
                cursor = records[find(cursor).map_err(|_| corrupt("dangling parent"))?].parent;
            }
        }
        Ok(())
    }
}
