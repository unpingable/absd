//! Locating one GPT partition by its unique partition GUID
//! (docs/hardware/GPT-PARTITION.md; coordination record #123 step 3).
//!
//! Pure code over a sector reader, so the host tests drive it with byte
//! images. It validates, in order and before anything is published:
//!
//! - the standard protective MBR at LBA 0 (one 0xEE record from LBA 1
//!   covering the disk, the other records empty);
//! - the primary header at LBA 1 (signature, revision, size, header CRC32,
//!   reserved word and padding zero, MyLBA, AlternateLBA as the device's
//!   last sector, the entry geometry, the usable range between the primary
//!   array and the backup array);
//! - the primary entry array's CRC32;
//! - the backup header at AlternateLBA (its own seal, MyLBA and
//!   AlternateLBA swapped, every shared field and the header size equal to
//!   the primary's, its entry array ending just before it);
//! - the backup entry array: CRC32 equal to the primary's, and byte for
//!   byte the primary's;
//! - every used entry: a nonzero unique GUID, a range inside the usable
//!   range, no duplicate unique GUID, no two ranges intersecting;
//!
//! then finds the used entry whose unique GUID matches and requires the
//! ABSD partition type. Nothing is repaired: any copy damaged or
//! disagreeing is a refusal.

/// Sector size this module reads: the block layer's only one.
pub const SECTOR_BYTES: usize = 512;
/// Largest single read the module asks for: eight sectors (one page).
pub const RUN_SECTORS: usize = 8;
const RUN_BYTES: usize = SECTOR_BYTES * RUN_SECTORS;
/// Bounds on the entry array: at most this many entries, each 128 * 2^n
/// bytes and no larger than one run, so no entry straddles a run.
pub const MAX_ENTRIES: u32 = 1024;
pub const MAX_ENTRY_BYTES: u32 = RUN_BYTES as u32;
const MIN_ENTRY_BYTES: u32 = 128;
/// `EFI PART`, revision 1.0, and the header's defined length.
const SIGNATURE: &[u8; 8] = b"EFI PART";
const REVISION: u32 = 0x0001_0000;
const MIN_HEADER_BYTES: u32 = 92;

/// The ABSD partition type GUID (owner decision, coordination record #123):
/// 7AF614A7-2C5B-4EBA-B8F6-217AEC90357A, in on-disk byte order. A
/// partition is selected by its unique GUID and must carry this type.
pub const ABSD_TYPE: Guid = Guid([
    0xA7, 0x14, 0xF6, 0x7A, 0x5B, 0x2C, 0xBA, 0x4E, 0xB8, 0xF6, 0x21, 0x7A, 0xEC, 0x90, 0x35, 0x7A,
]);

/// CRC-32 (IEEE 802.3, reflected polynomial 0xEDB88320), as GPT uses.
#[derive(Clone, Copy, Debug)]
pub struct Crc32(u32);

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 != 0 {
                (value >> 1) ^ 0xEDB8_8320
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = crc_table();

impl Crc32 {
    pub const fn new() -> Self {
        Self(0xFFFF_FFFF)
    }

    pub fn update(&mut self, bytes: &[u8]) {
        let mut value = self.0;
        for &byte in bytes {
            value = CRC_TABLE[((value ^ u32::from(byte)) & 0xff) as usize] ^ (value >> 8);
        }
        self.0 = value;
    }

    pub const fn finish(self) -> u32 {
        !self.0
    }
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(bytes);
    crc.finish()
}

/// A GUID in its on-disk byte order: the first three fields little-endian,
/// the last two as written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Guid(pub [u8; 16]);

/// Where each text byte pair lands on disk, in text order.
const TEXT_ORDER: [usize; 16] = [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15];
const DASHES: [usize; 4] = [8, 13, 18, 23];

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

impl Guid {
    pub const ZERO: Self = Self([0; 16]);

    /// The canonical text form `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, any
    /// case; anything else (braces, missing dashes, other lengths) is `None`.
    pub fn parse(text: &[u8]) -> Option<Self> {
        if text.len() != 36 {
            return None;
        }
        let mut digits = [0u8; 32];
        let mut count = 0;
        for (position, &byte) in text.iter().enumerate() {
            if DASHES.contains(&position) {
                if byte != b'-' {
                    return None;
                }
                continue;
            }
            digits[count] = hex_value(byte)?;
            count += 1;
        }
        let mut bytes = [0u8; 16];
        for (pair, &slot) in TEXT_ORDER.iter().enumerate() {
            bytes[slot] = (digits[2 * pair] << 4) | digits[2 * pair + 1];
        }
        Some(Self(bytes))
    }

    /// The canonical text form, lowercase.
    pub fn text(&self) -> [u8; 36] {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = [b'-'; 36];
        let mut position = 0;
        for &slot in &TEXT_ORDER {
            while DASHES.contains(&position) {
                position += 1;
            }
            out[position] = HEX[usize::from(self.0[slot] >> 4)];
            out[position + 1] = HEX[usize::from(self.0[slot] & 0xf)];
            position += 2;
        }
        out
    }

    fn from_slice(bytes: &[u8]) -> Self {
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&bytes[..16]);
        Self(guid)
    }
}

/// The selected partition, in device sectors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Partition {
    pub guid: Guid,
    pub first_lba: u64,
    pub sectors: u64,
    /// Zero-based index in the entry array.
    pub index: u32,
}

/// Why no partition was selected. Each is printed by name
/// (`Display` gives the exact text the kernel prints).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal<E> {
    /// The device is too small to hold a GPT at all.
    DeviceTooSmall,
    /// LBA 0 has no 55AA signature or no 0xEE partition record.
    NoProtectiveMbr,
    /// A 0xEE record beside another non-empty record: a hybrid MBR.
    HybridMbr,
    /// The 0xEE record does not cover the disk from LBA 1.
    BadProtectiveMbr(&'static str),
    /// The primary header's fields are not a GPT header this module accepts.
    BadHeader(&'static str),
    HeaderCrc,
    EntriesCrc,
    /// The backup header is missing, malformed, misplaced, or disagrees
    /// with the primary in the named field.
    BadBackup(&'static str),
    BackupHeaderCrc,
    /// The backup entry array's CRC32 is not the primary array's.
    BackupEntriesCrc,
    /// The backup entry array's bytes differ from the primary's (CRC32
    /// equal or not).
    BackupEntriesDiffer,
    /// More used entries than the table check holds.
    TooManyEntries,
    /// A used entry with a zero unique GUID.
    ZeroGuid {
        index: u32,
    },
    /// A used entry whose range is inverted or outside the usable range.
    EntryRange {
        index: u32,
    },
    /// Two used entries whose ranges intersect.
    EntryOverlap {
        a: u32,
        b: u32,
    },
    /// Two used entries carrying the same unique GUID.
    Duplicate {
        a: u32,
        b: u32,
    },
    NotFound,
    /// The entry carrying the GUID is not of the ABSD partition type.
    WrongType,
    /// A sector read failed.
    Read(E),
}

impl<E> Refusal<E> {
    pub fn name(&self) -> &'static str {
        match self {
            Self::DeviceTooSmall => "device-too-small",
            Self::NoProtectiveMbr => "no-protective-mbr",
            Self::HybridMbr => "hybrid-mbr",
            Self::BadProtectiveMbr(_) => "bad-protective-mbr",
            Self::BadHeader(_) => "bad-header",
            Self::HeaderCrc => "header-crc-mismatch",
            Self::EntriesCrc => "entries-crc-mismatch",
            Self::BadBackup(_) => "bad-backup",
            Self::BackupHeaderCrc => "backup-header-crc-mismatch",
            Self::BackupEntriesCrc => "backup-entries-crc-mismatch",
            Self::BackupEntriesDiffer => "backup-entries-differ",
            Self::TooManyEntries => "too-many-entries",
            Self::ZeroGuid { .. } => "entry-zero-guid",
            Self::EntryRange { .. } => "entry-range",
            Self::EntryOverlap { .. } => "entry-overlap",
            Self::Duplicate { .. } => "duplicate-guid",
            Self::NotFound => "not-found",
            Self::WrongType => "wrong-type",
            Self::Read(_) => "read-failed",
        }
    }

    /// The field at fault, for the MBR and header refusals.
    pub fn detail(&self) -> Option<&'static str> {
        match self {
            Self::BadHeader(field) | Self::BadBackup(field) | Self::BadProtectiveMbr(field) => {
                Some(field)
            }
            _ => None,
        }
    }
}

impl<E: core::fmt::Debug> core::fmt::Display for Refusal<E> {
    /// `name`, then `field=F`, `index=N`, `a=N b=M` or `error=E`.
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        out.write_str(self.name())?;
        match self {
            Self::ZeroGuid { index } | Self::EntryRange { index } => write!(out, " index={index}"),
            Self::EntryOverlap { a, b } | Self::Duplicate { a, b } => write!(out, " a={a} b={b}"),
            Self::Read(error) => write!(out, " error={error:?}"),
            _ => match self.detail() {
                Some(field) => write!(out, " field={field}"),
                None => Ok(()),
            },
        }
    }
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

/// Checks that `sector` (LBA 0) is the standard protective MBR for a
/// device of `device_sectors`: the 55AA signature, one partition record of
/// type 0xEE starting at LBA 1 and covering min(device_sectors - 1,
/// 0xFFFFFFFF) sectors, and the other three records all zero. The record's
/// status byte and CHS fields are not checked: tools write different
/// values there (sgdisk 1.0.10: status 0, start CHS 0/0/2, end CHS from the
/// disk size), and UEFI firmware ignores them. The boot code area and disk
/// signature are not checked either.
pub fn protective_mbr<E>(
    sector: &[u8; SECTOR_BYTES],
    device_sectors: u64,
) -> Result<(), Refusal<E>> {
    if sector[510] != 0x55 || sector[511] != 0xAA {
        return Err(Refusal::NoProtectiveMbr);
    }
    let record = |index: usize| &sector[446 + 16 * index..446 + 16 * (index + 1)];
    let Some(protective) = (0..4).find(|&index| record(index)[4] == 0xEE) else {
        return Err(Refusal::NoProtectiveMbr);
    };
    if (0..4).any(|index| index != protective && record(index).iter().any(|&byte| byte != 0)) {
        return Err(Refusal::HybridMbr);
    }
    let found = record(protective);
    if u32_at(found, 8) != 1 {
        return Err(Refusal::BadProtectiveMbr("start-lba"));
    }
    let size = (device_sectors - 1).min(0xFFFF_FFFF);
    if u64::from(u32_at(found, 12)) != size {
        return Err(Refusal::BadProtectiveMbr("size"));
    }
    Ok(())
}

/// The fields of a validated header this module uses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub size: u32,
    pub my_lba: u64,
    pub alternate: u64,
    pub first_usable: u64,
    pub last_usable: u64,
    pub disk_guid: Guid,
    pub entries_lba: u64,
    pub entry_count: u32,
    pub entry_bytes: u32,
    pub entries_crc: u32,
}

impl Header {
    fn array_sectors(&self) -> u64 {
        (u64::from(self.entry_count) * u64::from(self.entry_bytes)).div_ceil(SECTOR_BYTES as u64)
    }

    fn parse(sector: &[u8; SECTOR_BYTES]) -> Self {
        Self {
            size: u32_at(sector, 12),
            my_lba: u64_at(sector, 24),
            alternate: u64_at(sector, 32),
            first_usable: u64_at(sector, 40),
            last_usable: u64_at(sector, 48),
            disk_guid: Guid::from_slice(&sector[56..72]),
            entries_lba: u64_at(sector, 72),
            entry_count: u32_at(sector, 80),
            entry_bytes: u32_at(sector, 84),
            entries_crc: u32_at(sector, 88),
        }
    }
}

/// Signature, revision, size and CRC32 (CRC field zeroed), the checks both
/// copies share; `bad` and `crc` name the copy in a refusal.
fn sealed<E>(
    sector: &[u8; SECTOR_BYTES],
    bad: fn(&'static str) -> Refusal<E>,
    crc: Refusal<E>,
) -> Result<Header, Refusal<E>> {
    if &sector[..8] != SIGNATURE {
        return Err(bad("signature"));
    }
    if u32_at(sector, 8) != REVISION {
        return Err(bad("revision"));
    }
    let size = u32_at(sector, 12);
    if !(MIN_HEADER_BYTES..=SECTOR_BYTES as u32).contains(&size) {
        return Err(bad("header-size"));
    }
    let mut copy = *sector;
    copy[16..20].fill(0);
    if crc32(&copy[..size as usize]) != u32_at(sector, 16) {
        return Err(crc);
    }
    if u32_at(sector, 20) != 0 {
        return Err(bad("reserved"));
    }
    // UEFI: the rest of the block after HeaderSize is reserved and zero.
    if sector[size as usize..].iter().any(|&byte| byte != 0) {
        return Err(bad("header-padding"));
    }
    Ok(Header::parse(sector))
}

/// Validates the primary header in `sector` (read from LBA 1) against a
/// device of `device_sectors`.
pub fn header<E>(sector: &[u8; SECTOR_BYTES], device_sectors: u64) -> Result<Header, Refusal<E>> {
    let found = sealed(sector, Refusal::BadHeader, Refusal::HeaderCrc)?;
    if found.my_lba != 1 {
        return Err(Refusal::BadHeader("my-lba"));
    }
    // The backup header must be the device's last sector: the usable range
    // is then bounded below the backup GPT the header itself describes.
    if device_sectors.checked_sub(1) != Some(found.alternate) {
        return Err(Refusal::BadHeader("alternate-lba"));
    }
    let bytes = found.entry_bytes;
    if !(MIN_ENTRY_BYTES..=MAX_ENTRY_BYTES).contains(&bytes) || !bytes.is_power_of_two() {
        return Err(Refusal::BadHeader("entry-size"));
    }
    if found.entry_count == 0 || found.entry_count > MAX_ENTRIES {
        return Err(Refusal::BadHeader("entry-count"));
    }
    // The array lies after the header and before the first usable sector;
    // the usable range is non-empty and on the device.
    let array_end = found
        .entries_lba
        .checked_add(found.array_sectors())
        .ok_or(Refusal::BadHeader("entries-lba"))?;
    if found.entries_lba < 2 || array_end > found.first_usable {
        return Err(Refusal::BadHeader("entries-lba"));
    }
    if found.first_usable > found.last_usable {
        return Err(Refusal::BadHeader("usable-range"));
    }
    // The backup entry array occupies the `array_sectors` sectors just
    // before the backup header; no usable sector (so no partition, so no
    // write through one) may reach it or the header.
    let backup_array = found
        .alternate
        .checked_sub(found.array_sectors())
        .ok_or(Refusal::BadHeader("last-usable"))?;
    if found.last_usable >= backup_array {
        return Err(Refusal::BadHeader("last-usable"));
    }
    Ok(found)
}

/// Validates the backup header in `sector` (read from the primary's
/// AlternateLBA, the device's last sector) against the validated
/// `primary`: its own seal, the swapped self/alternate LBAs, every shared
/// field equal, and its entry array ending immediately before it.
pub fn backup_header<E>(
    sector: &[u8; SECTOR_BYTES],
    primary: &Header,
) -> Result<Header, Refusal<E>> {
    let found = sealed(sector, Refusal::BadBackup, Refusal::BackupHeaderCrc)?;
    let disagreement = if found.size != primary.size {
        Some("header-size")
    } else if found.my_lba != primary.alternate {
        Some("my-lba")
    } else if found.alternate != primary.my_lba {
        Some("alternate-lba")
    } else if found.first_usable != primary.first_usable {
        Some("first-usable")
    } else if found.last_usable != primary.last_usable {
        Some("last-usable")
    } else if found.disk_guid != primary.disk_guid {
        Some("disk-guid")
    } else if found.entry_count != primary.entry_count {
        Some("entry-count")
    } else if found.entry_bytes != primary.entry_bytes {
        Some("entry-size")
    } else if found.entries_crc != primary.entries_crc {
        Some("entries-crc")
    } else if found.entries_lba.checked_add(found.array_sectors()) != Some(found.my_lba) {
        Some("entries-lba")
    } else {
        None
    };
    match disagreement {
        Some(field) => Err(Refusal::BadBackup(field)),
        None => Ok(found),
    }
}

/// One entry's fields this module uses.
#[derive(Clone, Copy, Debug)]
struct Entry {
    type_guid: Guid,
    unique: Guid,
    first: u64,
    last: u64,
}

impl Entry {
    fn parse(bytes: &[u8]) -> Self {
        Self {
            type_guid: Guid::from_slice(&bytes[0..16]),
            unique: Guid::from_slice(&bytes[16..32]),
            first: u64_at(bytes, 32),
            last: u64_at(bytes, 40),
        }
    }

    fn used(&self) -> bool {
        self.type_guid != Guid::ZERO
    }
}

/// Reads the entry array `found` describes in runs of at most
/// `RUN_SECTORS`, giving each run's bytes (exactly `entry_count *
/// entry_bytes` in all) and its first entry's index to `visit`, and returns
/// the array's CRC32.
fn runs<E>(
    found: &Header,
    read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), E>,
    mut visit: impl FnMut(u32, &[u8]) -> Result<(), Refusal<E>>,
) -> Result<u32, Refusal<E>> {
    let mut crc = Crc32::new();
    let total = u64::from(found.entry_count) * u64::from(found.entry_bytes);
    let mut buffer = [0u8; RUN_BYTES];
    let mut done = 0u64;
    let mut lba = found.entries_lba;
    while done < total {
        let want = (total - done).min(RUN_BYTES as u64) as usize;
        let sectors = want.div_ceil(SECTOR_BYTES);
        let run = &mut buffer[..sectors * SECTOR_BYTES];
        read(lba, run).map_err(Refusal::Read)?;
        crc.update(&run[..want]);
        let first = (done / u64::from(found.entry_bytes)) as u32;
        visit(first, &run[..want])?;
        done += want as u64;
        lba += sectors as u64;
    }
    Ok(crc.finish())
}

/// Used entries the table check holds: as many as sgdisk's default array
/// (128 entries), so every table sgdisk writes by default fits. 40 bytes
/// each on x86-64 (a u32 index padded to 8, a 16-byte GUID, two u64 LBAs),
/// 5 KiB in all.
pub const MAX_USED_ENTRIES: usize = 128;

#[derive(Clone, Copy, Default)]
struct Used {
    index: u32,
    unique: [u8; 16],
    first: u64,
    last: u64,
}

/// What the primary array's one pass established.
struct Survey<E> {
    crc: u32,
    /// The first defect of the whole table, judged only once both copies
    /// are known to be sound.
    defect: Option<Refusal<E>>,
    selected: Option<(u32, Entry)>,
}

/// One pass over the primary array: its CRC, the selected entry, and the
/// whole-table rules for every used entry (nonzero unique GUID, range
/// inside the usable range, no duplicate unique GUID, no two ranges
/// intersecting).
#[inline(never)]
fn survey<E: Copy>(
    found: &Header,
    target: &Guid,
    read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<Survey<E>, Refusal<E>> {
    let mut table = [Used::default(); MAX_USED_ENTRIES];
    let mut used = 0usize;
    let mut defect = None;
    let mut selected = None;
    let entry_bytes = found.entry_bytes as usize;
    let crc = runs(found, read, |first, bytes| {
        for (offset, chunk) in bytes.chunks_exact(entry_bytes).enumerate() {
            let index = first + offset as u32;
            let entry = Entry::parse(chunk);
            if !entry.used() {
                continue;
            }
            if entry.unique == *target && selected.is_none() {
                selected = Some((index, entry));
            }
            if defect.is_some() {
                continue;
            }
            if entry.unique == Guid::ZERO {
                defect = Some(Refusal::ZeroGuid { index });
            } else if entry.first > entry.last
                || entry.first < found.first_usable
                || entry.last > found.last_usable
            {
                defect = Some(Refusal::EntryRange { index });
            } else if used == MAX_USED_ENTRIES {
                defect = Some(Refusal::TooManyEntries);
            } else {
                for other in &table[..used] {
                    if other.unique == entry.unique.0 {
                        defect = Some(Refusal::Duplicate {
                            a: other.index,
                            b: index,
                        });
                        break;
                    }
                    if other.first <= entry.last && entry.first <= other.last {
                        defect = Some(Refusal::EntryOverlap {
                            a: other.index,
                            b: index,
                        });
                        break;
                    }
                }
                table[used] = Used {
                    index,
                    unique: entry.unique.0,
                    first: entry.first,
                    last: entry.last,
                };
                used += 1;
            }
        }
        Ok(())
    })?;
    Ok(Survey {
        crc,
        defect,
        selected,
    })
}

/// The backup array, run by run, against the primary array's same run read
/// again: its CRC32 must be the primary's (`backup-entries-crc-mismatch`)
/// and, CRC32 equal, its bytes too (`backup-entries-differ`).
#[inline(never)]
fn compare_backup<E>(
    primary: &Header,
    backup: &Header,
    read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<(), Refusal<E>> {
    let mut copy = [0u8; RUN_BYTES];
    let mut again = [0u8; RUN_BYTES];
    let mut crc = Crc32::new();
    let mut differ = false;
    let total = u64::from(backup.entry_count) * u64::from(backup.entry_bytes);
    let mut done = 0u64;
    let mut offset = 0u64;
    while done < total {
        let want = (total - done).min(RUN_BYTES as u64) as usize;
        let sectors = want.div_ceil(SECTOR_BYTES);
        let run = &mut copy[..sectors * SECTOR_BYTES];
        read(backup.entries_lba + offset, run).map_err(Refusal::Read)?;
        crc.update(&run[..want]);
        let mirror = &mut again[..sectors * SECTOR_BYTES];
        read(primary.entries_lba + offset, mirror).map_err(Refusal::Read)?;
        differ |= run[..want] != mirror[..want];
        done += want as u64;
        offset += sectors as u64;
    }
    if crc.finish() != primary.entries_crc {
        return Err(Refusal::BackupEntriesCrc);
    }
    if differ {
        return Err(Refusal::BackupEntriesDiffer);
    }
    Ok(())
}

/// Finds the partition whose unique GUID is `target` on a device of
/// `device_sectors` 512-byte sectors. `read(lba, buffer)` fills `buffer`
/// (a whole number of sectors, at most `RUN_SECTORS`) from `lba`.
///
/// Reads: LBA 0, LBA 1, the primary array once (CRC, every used entry
/// checked, the target found), the backup header, then the backup array
/// with the primary array read again beside it, run by run. Every check
/// on both copies and on the whole table passes before the selection is
/// judged.
pub fn locate<E: Copy>(
    device_sectors: u64,
    target: &Guid,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<Partition, Refusal<E>> {
    // LBA 0, LBA 1, and one usable sector at the least.
    if device_sectors < 3 {
        return Err(Refusal::DeviceTooSmall);
    }
    let mut sector = [0u8; SECTOR_BYTES];
    read(0, &mut sector).map_err(Refusal::Read)?;
    protective_mbr(&sector, device_sectors)?;
    read(1, &mut sector).map_err(Refusal::Read)?;
    let found = header(&sector, device_sectors)?;

    let surveyed = survey(&found, target, &mut read)?;
    if surveyed.crc != found.entries_crc {
        return Err(Refusal::EntriesCrc);
    }
    // Both copies, before any table or selection result: the backup header
    // at the device's last sector, then its entry array, byte for byte the
    // primary's (read again) and with the primary's CRC.
    read(found.alternate, &mut sector).map_err(Refusal::Read)?;
    let backup = backup_header(&sector, &found)?;
    compare_backup(&found, &backup, &mut read)?;
    if let Some(defect) = surveyed.defect {
        return Err(defect);
    }
    let Some((index, entry)) = surveyed.selected else {
        return Err(Refusal::NotFound);
    };
    if entry.type_guid != ABSD_TYPE {
        return Err(Refusal::WrongType);
    }
    // The table check placed every used entry inside the usable range,
    // which ends below the backup GPT and so on the device.
    Ok(Partition {
        guid: *target,
        first_lba: entry.first,
        sectors: entry.last - entry.first + 1,
        index,
    })
}

#[cfg(test)]
mod tests;
