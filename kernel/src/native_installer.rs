//! Bounded blank-disk software installer. Payload is trusted boot-media data;
//! CRC32 detects damage, not a malicious replacement of boot media.
use crate::gpt::crc32;

pub const ABSD_FIRST: u64 = 526_336;
pub const ABSD_END: u64 = ABSD_FIRST + 4_194_304;
pub const MIN_SECTORS: u64 = ABSD_END + 33;
const HEADER: usize = 128;
const RUN: usize = 4096;

pub struct Device<'a> {
    pub serial: &'a [u8],
    pub model: &'a [u8],
    pub sectors: u64,
    pub unique: bool,
    pub writable: bool,
}
#[derive(Debug, Clone, Copy)]
pub struct IoError;

pub trait Disk {
    fn read(&mut self, lba: u64, bytes: &mut [u8]) -> Result<(), IoError>;
    fn write(&mut self, lba: u64, bytes: &[u8]) -> Result<(), IoError>;
    fn flush(&mut self) -> Result<(), IoError>;
}
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Installed,
    Refused(&'static str),
    Incomplete(&'static str),
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn unpad(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len())]
}
fn records(payload: &[u8]) -> impl Iterator<Item = (u64, &[u8])> {
    let mut at = HEADER;
    core::iter::from_fn(move || {
        if at == payload.len() {
            return None;
        }
        let lba = u64_at(payload, at);
        let length = u32_at(payload, at + 8) as usize;
        let data = &payload[at + 16..at + 16 + length];
        at += 16 + length;
        Some((lba, data))
    })
}
fn validate(payload: &[u8], device: &Device<'_>) -> Result<(), &'static str> {
    if payload.len() < HEADER || payload.len() > 64 * 1024 * 1024 || &payload[..8] != b"ABSDINS1" {
        return Err("payload-header");
    }
    if !device.unique
        || !device.writable
        || device.sectors < MIN_SECTORS
        || device.sectors > (512u64 << 30) / 512
        || device.sectors != u64_at(payload, 8)
        || device.serial.is_empty()
        || device.serial != unpad(&payload[20..40])
        || device.model != unpad(&payload[40..80])
        || payload[80..HEADER].iter().any(|b| *b != 0)
    {
        return Err("disk-identity");
    }
    let count = u32_at(payload, 16);
    if count == 0 || count > 65_536 {
        return Err("record-count");
    }
    let mut at = HEADER;
    let mut end = 0;
    for _ in 0..count {
        if payload.len() - at < 16 {
            return Err("record-header");
        }
        let lba = u64_at(payload, at);
        let length = u32_at(payload, at + 8) as usize;
        if length == 0
            || length > RUN
            || !length.is_multiple_of(512)
            || u32_at(payload, at + 12) != 0
            || length > payload.len() - at - 16
        {
            return Err("record-length");
        }
        let Some(next) = lba.checked_add((length / 512) as u64) else {
            return Err("record-range");
        };
        // Only boot metadata/ESP and backup GPT, never the state partition
        // or the unallocated span. The first 34 sectors commit last.
        if lba < end
            || next > device.sectors
            || !(next <= ABSD_FIRST || lba >= device.sectors - 33)
            || (lba < 34 && next > 34)
        {
            return Err("record-range");
        }
        end = next;
        at += 16 + length;
    }
    if at != payload.len() {
        return Err("payload-trailing");
    }
    Ok(())
}

pub fn install(
    disk: &mut impl Disk,
    payload: &[u8],
    device: Device<'_>,
    consent: Option<u32>,
) -> Outcome {
    let Some(consent) = consent else {
        return Outcome::Refused("consent");
    };
    if crc32(payload) != consent {
        return Outcome::Refused("payload-crc");
    }
    if let Err(reason) = validate(payload, &device) {
        return Outcome::Refused(reason);
    }
    let mut buffer = [0u8; RUN];
    let mut lba = 0;
    // Full-disk preflight: a blank head never implies an unused disk.
    while lba < device.sectors {
        let sectors = (device.sectors - lba).min(8) as usize;
        let bytes = &mut buffer[..sectors * 512];
        if disk.read(lba, bytes).is_err() {
            return Outcome::Refused("preflight-read");
        }
        if bytes.iter().any(|b| *b != 0) {
            return Outcome::Refused("not-blank");
        }
        lba += sectors as u64;
    }
    // The boot commit (primary GPT, then MBR) follows flushed, verified ESP and
    // backup GPT. No retry or success is inferred from partial completion.
    for primary in [false, true] {
        for (lba, data) in records(payload).filter(|(lba, _)| (*lba < 34) == primary) {
            // A sparse record can include both LBA 0 and primary GPT sectors.
            // Defer only the MBR sector, preserving the remaining record bytes.
            let (lba, data) = if lba == 0 {
                (1, &data[512..])
            } else {
                (lba, data)
            };
            if !data.is_empty() && disk.write(lba, data).is_err() {
                return Outcome::Incomplete("write");
            }
        }
        if primary
            && let Some((_, data)) = records(payload).find(|(lba, _)| *lba == 0)
            && disk.write(0, &data[..512]).is_err()
        {
            return Outcome::Incomplete("write");
        }
        if disk.flush().is_err() {
            return Outcome::Incomplete("flush");
        }
        for (lba, data) in records(payload).filter(|(lba, _)| (*lba < 34) == primary) {
            let bytes = &mut buffer[..data.len()];
            if disk.read(lba, bytes).is_err() || bytes != data {
                return Outcome::Incomplete("readback");
            }
        }
    }
    Outcome::Installed
}
