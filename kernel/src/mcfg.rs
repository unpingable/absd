//! MCFG and PCIe extended capabilities (design section 4): enough to read
//! the facts legacy configuration space cannot show about a contained
//! function. Pure and read-only. A function whose extended space cannot be
//! read is reported as such, never as having no capabilities.

const HEADER_BYTES: usize = 44;
const ENTRY_BYTES: usize = 16;
const MAX_REGIONS: usize = 8;
const EXTENDED_START: u16 = 0x100;
const MAX_STEPS: usize = 64;
/// The last dword of a function's 4 KiB configuration space.
const LAST_DWORD: u16 = 0xffc;

const CAP_ATS: u16 = 0x000f;
const CAP_SRIOV: u16 = 0x0010;
const CAP_PRI: u16 = 0x0013;
const CAP_PASID: u16 = 0x001b;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McfgError {
    Signature,
    Length,
    Checksum,
    Alignment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtError {
    /// The header reads all ones: nothing answered.
    Unreadable,
    /// A next pointer below 100h, misaligned, or a list that does not end.
    Malformed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtFacts {
    pub ats_enabled: bool,
    pub pasid_enabled: bool,
    pub pri_enabled: bool,
    pub sriov_vfs_enabled: bool,
}

#[derive(Clone, Copy, Debug)]
struct Region {
    base: u64,
    start: u8,
    end: u8,
}

/// Segment 0's ECAM regions.
#[derive(Clone, Copy, Debug)]
pub struct Regions {
    regions: [Option<Region>; MAX_REGIONS],
}

impl Regions {
    /// The physical address of a function's 4 KiB configuration page. The
    /// MCFG base address is that of bus 0, whatever bus the region starts at.
    pub fn config_page(&self, bus: u8, device: u8, function: u8) -> Option<u64> {
        if device > 0x1f || function > 7 {
            return None;
        }
        let region = self
            .regions
            .iter()
            .flatten()
            .find(|r| r.start <= bus && bus <= r.end)?;
        region.base.checked_add(
            (u64::from(bus) << 20) | (u64::from(device) << 15) | (u64::from(function) << 12),
        )
    }
}

pub fn parse(table: &[u8]) -> Result<Regions, McfgError> {
    if table.len() < HEADER_BYTES {
        return Err(McfgError::Length);
    }
    if &table[..4] != b"MCFG" {
        return Err(McfgError::Signature);
    }
    let declared = u32::from_le_bytes([table[4], table[5], table[6], table[7]]) as usize;
    if declared > table.len()
        || declared < HEADER_BYTES
        || !(declared - HEADER_BYTES).is_multiple_of(ENTRY_BYTES)
    {
        return Err(McfgError::Length);
    }
    let body = &table[..declared];
    if body.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0 {
        return Err(McfgError::Checksum);
    }
    let mut regions = [None; MAX_REGIONS];
    let mut count = 0;
    for entry in body[HEADER_BYTES..].as_chunks::<ENTRY_BYTES>().0 {
        if u16::from_le_bytes([entry[8], entry[9]]) != 0 {
            continue;
        }
        if count == MAX_REGIONS {
            return Err(McfgError::Length);
        }
        let mut base = [0; 8];
        base.copy_from_slice(&entry[..8]);
        let base = u64::from_le_bytes(base);
        // ECAM is aligned to at least 1 MiB; the reader relies on this.
        if !base.is_multiple_of(1 << 20) {
            return Err(McfgError::Alignment);
        }
        regions[count] = Some(Region {
            base,
            start: entry[10],
            end: entry[11],
        });
        count += 1;
    }
    Ok(Regions { regions })
}

/// Walks the extended capability list through `read`, a dword read at a
/// configuration offset.
pub fn extended_facts(mut read: impl FnMut(u16) -> u32) -> Result<ExtFacts, ExtError> {
    let mut facts = ExtFacts {
        ats_enabled: false,
        pasid_enabled: false,
        pri_enabled: false,
        sriov_vfs_enabled: false,
    };
    let mut at = EXTENDED_START;
    for _ in 0..MAX_STEPS {
        let header = read(at);
        if header == 0xffff_ffff {
            if cfg!(absd_mutant_mcfg_unreadable_absent) {
                return Ok(facts);
            }
            return Err(ExtError::Unreadable);
        }
        if header == 0 {
            return Ok(facts);
        }
        let register = |offset: u16| {
            let register = at + offset;
            (register <= LAST_DWORD).then_some(register)
        };
        match header as u16 {
            CAP_ATS => {
                let at = register(4).ok_or(ExtError::Malformed)?;
                facts.ats_enabled = read(at) & (1 << 31) != 0;
            }
            CAP_PASID => {
                let at = register(4).ok_or(ExtError::Malformed)?;
                facts.pasid_enabled = read(at) & (1 << 16) != 0;
            }
            CAP_PRI => {
                let at = register(4).ok_or(ExtError::Malformed)?;
                facts.pri_enabled = read(at) & 1 != 0;
            }
            CAP_SRIOV => {
                let at = register(8).ok_or(ExtError::Malformed)?;
                facts.sriov_vfs_enabled = read(at) & 1 != 0;
            }
            _ => {}
        }
        let next = (header >> 20) as u16;
        if next == 0 {
            return Ok(facts);
        }
        if next < EXTENDED_START || !next.is_multiple_of(4) {
            return Err(ExtError::Malformed);
        }
        at = next;
    }
    Err(ExtError::Malformed)
}

#[cfg(test)]
mod tests;
