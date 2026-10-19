//! Read-only, fail-closed ACPI table reading (docs/x86-acpi-20261015).
//!
//! Pure parsing over a [`Memory`] that hands out physical byte ranges, so
//! the whole walk runs in host tests over a synthetic image. The kernel
//! supplies the physical access (src/acpi_boot.rs). Nothing here writes to
//! a table, interprets AML, or trusts a length or count it has not bounded.
//!
//! Policy: the RSDP and the root table (XSDT, else RSDT) must validate or
//! nothing is read. A listed table that fails its own length or checksum
//! check is refused alone and disclosed; MADT, FADT and DSDT are consumed
//! only when they validate, and only when exactly one MADT and one FADT are
//! listed. The \_S5 sleep type comes from a bounded byte scan of the DSDT
//! for a single `Name (_S5_, Package () {...})` with plain integer
//! elements; anything else refuses power-off.

/// The largest table read, the DSDT included.
pub const MAX_TABLE_BYTES: usize = 2 << 20;
/// The most tables a root table may list.
pub const MAX_TABLES: usize = 64;
pub const MAX_CPUS: usize = 256;
pub const MAX_IOAPICS: usize = 16;
pub const MAX_ISOS: usize = 32;
pub const HEADER_BYTES: usize = 36;

/// Physical memory as the walk sees it: `length` bytes at `physical`, or
/// `None` when the range cannot be reached (refused, unmapped, too large).
pub trait Memory {
    fn bytes(&mut self, physical: u64, length: usize) -> Option<&[u8]>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    RsdpLength,
    RsdpSignature,
    RsdpChecksum,
    RsdpExtendedLength,
    RsdpExtendedChecksum,
    RootAddress,
    Unreachable,
    Signature,
    TableLength,
    Checksum,
    RootEntries,
    TooManyTables,
    Duplicate,
    Missing,
    MadtEntry,
    MadtTooMany,
    MadtDuplicateApic,
    FadtLength,
}

fn sum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rsdp {
    pub revision: u8,
    pub rsdt: u32,
    /// Present only for revision 2 or later with a nonzero address.
    pub xsdt: Option<u64>,
}

/// Validates an RSDP copy (the body of a Multiboot2 ACPI old/new tag):
/// signature, the 20-byte checksum, and for revision 2 or later the
/// declared length and the extended checksum.
pub fn parse_rsdp(bytes: &[u8]) -> Result<Rsdp, Error> {
    let first = bytes.get(..20).ok_or(Error::RsdpLength)?;
    if &first[..8] != b"RSD PTR " {
        return Err(Error::RsdpSignature);
    }
    if sum(first) != 0 {
        return Err(Error::RsdpChecksum);
    }
    let revision = first[15];
    let rsdt = u32_at(first, 16).ok_or(Error::RsdpLength)?;
    let mut xsdt = None;
    if revision >= 2 {
        let length = u32_at(bytes, 20).ok_or(Error::RsdpExtendedLength)? as usize;
        if !(36..=bytes.len()).contains(&length) || length > 4096 {
            return Err(Error::RsdpExtendedLength);
        }
        if sum(&bytes[..length]) != 0 {
            return Err(Error::RsdpExtendedChecksum);
        }
        let address = u64_at(bytes, 24).ok_or(Error::RsdpExtendedLength)?;
        if address != 0 {
            xsdt = Some(address);
        }
    }
    Ok(Rsdp {
        revision,
        rsdt,
        xsdt,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
}

/// Reads and validates one table at `physical`: the header first, then the
/// whole declared length (bounded) and its checksum. `expected` checks the
/// signature when given. Returns the validated bytes.
pub fn read_table<'m, M: Memory>(
    memory: &'m mut M,
    physical: u64,
    expected: Option<&[u8; 4]>,
) -> Result<(Header, &'m [u8]), Error> {
    if physical == 0 {
        return Err(Error::RootAddress);
    }
    let length = {
        let head = memory
            .bytes(physical, HEADER_BYTES)
            .ok_or(Error::Unreachable)?;
        if expected.is_some_and(|sig| head[..4] != sig[..]) {
            return Err(Error::Signature);
        }
        u32_at(head, 4).ok_or(Error::TableLength)? as usize
    };
    if !(HEADER_BYTES..=MAX_TABLE_BYTES).contains(&length) {
        return Err(Error::TableLength);
    }
    let bytes = memory.bytes(physical, length).ok_or(Error::Unreachable)?;
    if bytes.len() != length {
        return Err(Error::TableLength);
    }
    if expected.is_some_and(|sig| bytes[..4] != sig[..]) {
        return Err(Error::Signature);
    }
    if sum(bytes) != 0 {
        return Err(Error::Checksum);
    }
    let header = Header {
        signature: [bytes[0], bytes[1], bytes[2], bytes[3]],
        length: length as u32,
        revision: bytes[8],
    };
    Ok((header, bytes))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableEntry {
    pub address: u64,
    /// The signature bytes as found, before validation (zero when the
    /// header could not be reached); only used to refuse by name.
    pub signature: [u8; 4],
    /// The validated header, or why the table was refused.
    pub header: Result<Header, Error>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Root {
    pub xsdt: bool,
    pub address: u64,
    pub count: usize,
    pub tables: [TableEntry; MAX_TABLES],
}

/// Reads the XSDT when the RSDP names one, else the RSDT, and validates
/// every table it lists. A bad root refuses the whole walk; a bad listed
/// table is refused alone (its entry carries the error).
pub fn read_root<M: Memory>(memory: &mut M, rsdp: &Rsdp) -> Result<Root, Error> {
    let (xsdt, address, signature, width) = match rsdp.xsdt {
        Some(address) => (true, address, b"XSDT", 8usize),
        None => (false, u64::from(rsdp.rsdt), b"RSDT", 4usize),
    };
    let mut addresses = [0u64; MAX_TABLES];
    let count = {
        let (_, bytes) = read_table(memory, address, Some(signature))?;
        let body = &bytes[HEADER_BYTES..];
        if body.len() % width != 0 {
            return Err(Error::RootEntries);
        }
        let count = body.len() / width;
        if count > MAX_TABLES {
            return Err(Error::TooManyTables);
        }
        for (index, slot) in addresses.iter_mut().enumerate().take(count) {
            *slot = if width == 8 {
                u64_at(body, index * 8).ok_or(Error::RootEntries)?
            } else {
                u64::from(u32_at(body, index * 4).ok_or(Error::RootEntries)?)
            };
        }
        count
    };
    let mut root = Root {
        xsdt,
        address,
        count,
        tables: [TableEntry {
            address: 0,
            signature: [0; 4],
            header: Err(Error::Missing),
        }; MAX_TABLES],
    };
    for (slot, &address) in root.tables.iter_mut().zip(&addresses[..count]) {
        let signature = memory
            .bytes(address, 4)
            .filter(|_| address != 0)
            .map_or([0; 4], |raw| [raw[0], raw[1], raw[2], raw[3]]);
        *slot = TableEntry {
            address,
            signature,
            header: read_table(memory, address, None).map(|(header, _)| header),
        };
    }
    Ok(root)
}

impl Root {
    pub fn entries(&self) -> &[TableEntry] {
        &self.tables[..self.count]
    }

    /// The one validated table with `signature`. Two listed tables with
    /// that signature refuse as ambiguous; a listed one that failed
    /// validation refuses with its error.
    pub fn find(&self, signature: &[u8; 4]) -> Result<u64, Error> {
        let mut found = None;
        for entry in self.entries() {
            if &entry.signature != signature {
                continue;
            }
            let header = entry.header?;
            if &header.signature != signature || found.replace(entry.address).is_some() {
                return Err(Error::Duplicate);
            }
        }
        found.ok_or(Error::Missing)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuKind {
    Xapic,
    X2apic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cpu {
    pub kind: CpuKind,
    pub uid: u32,
    pub apic: u32,
    pub flags: u32,
}

impl Cpu {
    pub fn enabled(&self) -> bool {
        self.flags & 1 != 0
    }
    pub fn online_capable(&self) -> bool {
        self.flags & 2 != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoApic {
    pub id: u8,
    pub address: u32,
    pub gsi_base: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Override {
    pub bus: u8,
    pub source: u8,
    pub gsi: u32,
    pub flags: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Madt {
    pub lapic_address: u64,
    pub flags: u32,
    pub cpu_count: usize,
    pub cpus: [Cpu; MAX_CPUS],
    pub ioapic_count: usize,
    pub ioapics: [IoApic; MAX_IOAPICS],
    pub iso_count: usize,
    pub isos: [Override; MAX_ISOS],
    /// Entries of other types (NMI sources, LAPIC NMI, ...), counted only.
    pub other: usize,
}

impl Madt {
    pub fn cpus(&self) -> &[Cpu] {
        &self.cpus[..self.cpu_count]
    }
    pub fn ioapics(&self) -> &[IoApic] {
        &self.ioapics[..self.ioapic_count]
    }
    pub fn isos(&self) -> &[Override] {
        &self.isos[..self.iso_count]
    }
    pub fn enabled(&self) -> usize {
        self.cpus().iter().filter(|cpu| cpu.enabled()).count()
    }
    pub fn online_capable(&self) -> usize {
        self.cpus()
            .iter()
            .filter(|cpu| !cpu.enabled() && cpu.online_capable())
            .count()
    }
    pub fn has_apic(&self, apic: u32) -> bool {
        self.cpus()
            .iter()
            .any(|cpu| cpu.apic == apic && (cpu.enabled() || cpu.online_capable()))
    }
}

/// Parses a validated MADT. Every entry must have exactly its type's
/// length (the ones this reader consumes) or at least two bytes (others),
/// must lie inside the table, and the counts are bounded. Two usable
/// processors with one APIC ID refuse.
pub fn parse_madt(bytes: &[u8]) -> Result<Madt, Error> {
    if bytes.len() < HEADER_BYTES + 8 || &bytes[..4] != b"APIC" {
        return Err(Error::MadtEntry);
    }
    let mut madt = Madt {
        lapic_address: u64::from(u32_at(bytes, 36).ok_or(Error::MadtEntry)?),
        flags: u32_at(bytes, 40).ok_or(Error::MadtEntry)?,
        cpu_count: 0,
        cpus: [Cpu {
            kind: CpuKind::Xapic,
            uid: 0,
            apic: 0,
            flags: 0,
        }; MAX_CPUS],
        ioapic_count: 0,
        ioapics: [IoApic {
            id: 0,
            address: 0,
            gsi_base: 0,
        }; MAX_IOAPICS],
        iso_count: 0,
        isos: [Override {
            bus: 0,
            source: 0,
            gsi: 0,
            flags: 0,
        }; MAX_ISOS],
        other: 0,
    };
    let mut offset = HEADER_BYTES + 8;
    while offset < bytes.len() {
        let kind = bytes[offset];
        let length = *bytes.get(offset + 1).ok_or(Error::MadtEntry)? as usize;
        if length < 2 {
            return Err(Error::MadtEntry);
        }
        let entry = bytes.get(offset..offset + length).ok_or(Error::MadtEntry)?;
        let exact = |want: usize| {
            if length == want {
                Ok(())
            } else {
                Err(Error::MadtEntry)
            }
        };
        match kind {
            0 => {
                exact(8)?;
                push_cpu(
                    &mut madt,
                    Cpu {
                        kind: CpuKind::Xapic,
                        uid: u32::from(entry[2]),
                        apic: u32::from(entry[3]),
                        flags: u32_at(entry, 4).ok_or(Error::MadtEntry)?,
                    },
                )?;
            }
            9 => {
                exact(16)?;
                push_cpu(
                    &mut madt,
                    Cpu {
                        kind: CpuKind::X2apic,
                        apic: u32_at(entry, 4).ok_or(Error::MadtEntry)?,
                        flags: u32_at(entry, 8).ok_or(Error::MadtEntry)?,
                        uid: u32_at(entry, 12).ok_or(Error::MadtEntry)?,
                    },
                )?;
            }
            1 => {
                exact(12)?;
                if madt.ioapic_count == MAX_IOAPICS {
                    return Err(Error::MadtTooMany);
                }
                madt.ioapics[madt.ioapic_count] = IoApic {
                    id: entry[2],
                    address: u32_at(entry, 4).ok_or(Error::MadtEntry)?,
                    gsi_base: u32_at(entry, 8).ok_or(Error::MadtEntry)?,
                };
                madt.ioapic_count += 1;
            }
            2 => {
                exact(10)?;
                if madt.iso_count == MAX_ISOS {
                    return Err(Error::MadtTooMany);
                }
                madt.isos[madt.iso_count] = Override {
                    bus: entry[2],
                    source: entry[3],
                    gsi: u32_at(entry, 4).ok_or(Error::MadtEntry)?,
                    flags: u16_at(entry, 8).ok_or(Error::MadtEntry)?,
                };
                madt.iso_count += 1;
            }
            5 => {
                exact(12)?;
                madt.lapic_address = u64_at(entry, 4).ok_or(Error::MadtEntry)?;
            }
            _ => madt.other += 1,
        }
        offset += length;
    }
    Ok(madt)
}

fn push_cpu(madt: &mut Madt, cpu: Cpu) -> Result<(), Error> {
    if madt.cpu_count == MAX_CPUS {
        return Err(Error::MadtTooMany);
    }
    let usable = cpu.enabled() || cpu.online_capable();
    if usable
        && madt
            .cpus()
            .iter()
            .any(|other| other.apic == cpu.apic && (other.enabled() || other.online_capable()))
    {
        return Err(Error::MadtDuplicateApic);
    }
    madt.cpus[madt.cpu_count] = cpu;
    madt.cpu_count += 1;
    Ok(())
}

/// An ACPI generic address structure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Gas {
    pub space: u8,
    pub width: u8,
    pub offset: u8,
    pub access: u8,
    pub address: u64,
}

pub const SPACE_MEMORY: u8 = 0;
pub const SPACE_IO: u8 = 1;
pub const SPACE_PCI: u8 = 2;

fn gas_at(bytes: &[u8], offset: usize) -> Option<Gas> {
    let raw = bytes.get(offset..offset + 12)?;
    Some(Gas {
        space: raw[0],
        width: raw[1],
        offset: raw[2],
        access: raw[3],
        address: u64_at(raw, 4)?,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fadt {
    pub revision: u8,
    pub length: usize,
    pub flags: u32,
    pub dsdt: u32,
    pub x_dsdt: u64,
    pub sci: u16,
    pub smi_cmd: u32,
    pub acpi_enable: u8,
    pub pm1a_cnt: u32,
    pub pm1b_cnt: u32,
    pub pm1_cnt_len: u8,
    pub x_pm1a_cnt: Option<Gas>,
    pub x_pm1b_cnt: Option<Gas>,
    /// The reset register and value, when the table is long enough to hold
    /// them; `flags` bit 10 says whether firmware claims support.
    pub reset: Option<(Gas, u8)>,
}

pub const FADT_RESET_REG_SUP: u32 = 1 << 10;
pub const FADT_HW_REDUCED: u32 = 1 << 20;

/// Parses a validated FADT. Fields beyond the table's length are absent,
/// never read.
pub fn parse_fadt(bytes: &[u8]) -> Result<Fadt, Error> {
    if bytes.len() < 116 || &bytes[..4] != b"FACP" {
        return Err(Error::FadtLength);
    }
    let field32 = |offset| u32_at(bytes, offset).ok_or(Error::FadtLength);
    let flags = field32(112)?;
    let reset = match (gas_at(bytes, 116), bytes.get(128)) {
        (Some(gas), Some(&value)) => Some((gas, value)),
        _ => None,
    };
    let nonzero = |gas: Option<Gas>| gas.filter(|gas| gas.address != 0);
    Ok(Fadt {
        revision: bytes[8],
        length: bytes.len(),
        flags,
        dsdt: field32(40)?,
        x_dsdt: if bytes.len() >= 148 {
            u64_at(bytes, 140).unwrap_or(0)
        } else {
            0
        },
        sci: u16_at(bytes, 46).ok_or(Error::FadtLength)?,
        smi_cmd: field32(48)?,
        acpi_enable: bytes[52],
        pm1a_cnt: field32(64)?,
        pm1b_cnt: field32(68)?,
        pm1_cnt_len: bytes[89],
        x_pm1a_cnt: nonzero(gas_at(bytes, 172)),
        x_pm1b_cnt: nonzero(gas_at(bytes, 184)),
        reset,
    })
}

impl Fadt {
    /// The DSDT address. Both fields nonzero and different is ambiguous.
    pub fn dsdt_address(&self) -> Option<u64> {
        match (self.dsdt, self.x_dsdt) {
            (0, 0) => None,
            (legacy, 0) => Some(u64::from(legacy)),
            (0, x) => Some(x),
            (legacy, x) if u64::from(legacy) == x => Some(x),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerError {
    HardwareReduced,
    Pm1aAbsent,
    Pm1Ambiguous,
    Pm1NotIo,
    Pm1Width,
}

/// The I/O ports of the PM1a and PM1b control registers. Only 16-bit
/// system I/O blocks are accepted; an extended block that disagrees with
/// the legacy one refuses.
pub fn pm1_ports(fadt: &Fadt) -> Result<(u16, Option<u16>), PowerError> {
    if fadt.flags & FADT_HW_REDUCED != 0 {
        return Err(PowerError::HardwareReduced);
    }
    if fadt.pm1_cnt_len != 2 {
        return Err(PowerError::Pm1Width);
    }
    let pick = |legacy: u32, x: Option<Gas>| -> Result<Option<u16>, PowerError> {
        let x = match x {
            None => None,
            Some(gas) => {
                if gas.space != SPACE_IO {
                    return Err(PowerError::Pm1NotIo);
                }
                if (gas.width != 16 && gas.width != 0) || gas.offset != 0 {
                    return Err(PowerError::Pm1Width);
                }
                Some(gas.address)
            }
        };
        let address = match (legacy, x) {
            (0, None) => return Ok(None),
            (legacy, None) => u64::from(legacy),
            (0, Some(x)) => x,
            (legacy, Some(x)) if u64::from(legacy) == x => x,
            _ => return Err(PowerError::Pm1Ambiguous),
        };
        u16::try_from(address)
            .ok()
            .filter(|&port| port <= 0xfffe)
            .map(Some)
            .ok_or(PowerError::Pm1NotIo)
    };
    let a = pick(fadt.pm1a_cnt, fadt.x_pm1a_cnt)?.ok_or(PowerError::Pm1aAbsent)?;
    let b = pick(fadt.pm1b_cnt, fadt.x_pm1b_cnt)?;
    Ok((a, b))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum S5Error {
    NotFound,
    Ambiguous,
    NotNamePackage,
    PackageLength,
    Elements,
    ElementEncoding,
    Value,
}

/// SLP_TYPa and SLP_TYPb from `Name (_S5_, Package (n) {a, b, ...})` in a
/// validated DSDT, by a byte scan bounded by the table. The name must occur
/// exactly once in the AML body, as a NameOp (optionally root-prefixed)
/// whose object is a package of at least two plain integers that fit the
/// three-bit field. Anything else refuses; no AML is interpreted.
pub fn s5_sleep_types(dsdt: &[u8]) -> Result<(u8, u8), S5Error> {
    let body = dsdt.get(HEADER_BYTES..).ok_or(S5Error::NotFound)?;
    let mut found = None;
    for (index, window) in body.windows(4).enumerate() {
        if window == b"_S5_" && found.replace(index).is_some() {
            return Err(S5Error::Ambiguous);
        }
    }
    let at = found.ok_or(S5Error::NotFound)?;
    let named = match at {
        0 => false,
        1 => body[0] == 0x08,
        _ => body[at - 1] == 0x08 || (body[at - 1] == 0x5c && body[at - 2] == 0x08),
    };
    if !named || body.get(at + 4) != Some(&0x12) {
        return Err(S5Error::NotNamePackage);
    }
    let start = at + 5;
    let lead = *body.get(start).ok_or(S5Error::PackageLength)?;
    let follow = usize::from(lead >> 6);
    let length = if follow == 0 {
        usize::from(lead & 0x3f)
    } else {
        if lead & 0x30 != 0 {
            return Err(S5Error::PackageLength);
        }
        let mut length = usize::from(lead & 0x0f);
        for byte in 0..follow {
            let next = *body.get(start + 1 + byte).ok_or(S5Error::PackageLength)?;
            length |= usize::from(next) << (4 + 8 * byte);
        }
        length
    };
    // The package length counts itself and everything after it.
    let package = body
        .get(start..start.checked_add(length).ok_or(S5Error::PackageLength)?)
        .ok_or(S5Error::PackageLength)?;
    let mut cursor = 1 + follow;
    let elements = *package.get(cursor).ok_or(S5Error::PackageLength)?;
    if elements < 2 {
        return Err(S5Error::Elements);
    }
    cursor += 1;
    let mut values = [0u8; 2];
    for value in &mut values {
        let opcode = *package.get(cursor).ok_or(S5Error::PackageLength)?;
        let (number, size) = match opcode {
            0x00 => (0u64, 1usize),
            0x01 => (1, 1),
            0x0a => (
                u64::from(*package.get(cursor + 1).ok_or(S5Error::PackageLength)?),
                2,
            ),
            0x0b => (
                u64::from(u16_at(package, cursor + 1).ok_or(S5Error::PackageLength)?),
                3,
            ),
            0x0c => (
                u64::from(u32_at(package, cursor + 1).ok_or(S5Error::PackageLength)?),
                5,
            ),
            0x0e => (
                u64_at(package, cursor + 1).ok_or(S5Error::PackageLength)?,
                9,
            ),
            _ => return Err(S5Error::ElementEncoding),
        };
        if number > 7 {
            return Err(S5Error::Value);
        }
        *value = number as u8;
        cursor += size;
    }
    Ok((values[0], values[1]))
}

/// The value written to a PM1 control register to enter a sleep state:
/// the current value with SLP_TYP replaced, and SLP_EN when `enable`.
pub fn pm1_sleep_value(current: u16, sleep_type: u8, enable: bool) -> u16 {
    let value = (current & !(0x7 << 10 | 1 << 13)) | (u16::from(sleep_type & 7) << 10);
    if enable { value | 1 << 13 } else { value }
}

/// The boot identity map's end: below it, tables are read in place.
pub const IDENTITY_LIMIT: u64 = 1 << 30;
/// The kernel's scratch view above the identity map: this many 2 MiB pages,
/// remapped per read, so one read may span at most 4 MiB of pages.
pub const WINDOW_PAGE: u64 = 2 << 20;
pub const WINDOW_PAGES: u64 = 2;
const PHYSICAL_LIMIT: u64 = 1 << 52;
pub const MEMORY_RESERVED: u32 = 2;
pub const MEMORY_ACPI_RECLAIM: u32 = 3;
pub const MEMORY_ACPI_NVS: u32 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Access {
    /// Read through the identity map at the physical address.
    Identity,
    /// Map `pages` 2 MiB pages from `base` into the scratch view and read
    /// at `offset` within it.
    Window { base: u64, pages: u64, offset: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    Empty,
    /// The range crosses the end of the identity map.
    Straddle,
    /// The range needs more pages than the scratch view has.
    TooLong,
    NoMemoryMap,
    /// Some byte of the range is not typed reserved, ACPI reclaim or ACPI
    /// NVS by the Multiboot2 memory map (a BAR, RAM in use, or a hole).
    NotFirmwareMemory,
}

/// `(base, length, type)` rows of a whole Multiboot2 memory-map tag (type
/// 6), or none when its header is malformed.
pub fn memory_map_entries(tag: &[u8]) -> impl Iterator<Item = (u64, u64, u32)> + '_ {
    let entry_size = u32_at(tag, 8).map_or(0, |size| size as usize);
    let valid = tag.len() >= 16 && entry_size >= 24 && (tag.len() - 16).is_multiple_of(entry_size);
    let rows = if valid {
        (tag.len() - 16) / entry_size
    } else {
        0
    };
    (0..rows).filter_map(move |row| {
        let at = 16 + row * entry_size;
        Some((
            u64_at(tag, at)?,
            u64_at(tag, at + 8)?,
            u32_at(tag, at + 16)?,
        ))
    })
}

/// How the kernel may read `length` bytes at `physical`: in place below
/// the identity-map limit, or through the scratch view when the whole range
/// is firmware memory by the boot memory map. Everything else refuses.
pub fn admit(
    physical: u64,
    length: usize,
    memory_map: Option<&[u8]>,
) -> Result<Access, AccessError> {
    if physical == 0 || length == 0 {
        return Err(AccessError::Empty);
    }
    let end = physical
        .checked_add(length as u64)
        .filter(|&end| end <= PHYSICAL_LIMIT)
        .ok_or(AccessError::TooLong)?;
    if end <= IDENTITY_LIMIT {
        return Ok(Access::Identity);
    }
    if physical < IDENTITY_LIMIT {
        return Err(AccessError::Straddle);
    }
    let base = physical & !(WINDOW_PAGE - 1);
    let pages = (end - base).div_ceil(WINDOW_PAGE);
    if pages > WINDOW_PAGES {
        return Err(AccessError::TooLong);
    }
    let map = memory_map.ok_or(AccessError::NoMemoryMap)?;
    // Walk the range through firmware-typed rows; each step must advance.
    let mut cursor = physical;
    for _ in 0..memory_map_entries(map).count() {
        let next = memory_map_entries(map)
            .filter(|&(_, _, kind)| {
                matches!(
                    kind,
                    MEMORY_RESERVED | MEMORY_ACPI_RECLAIM | MEMORY_ACPI_NVS
                )
            })
            .filter_map(|(start, length, _)| Some((start, start.checked_add(length)?)))
            .find(|&(start, stop)| start <= cursor && cursor < stop)
            .map(|(_, stop)| stop);
        cursor = next.ok_or(AccessError::NotFirmwareMemory)?;
        if cursor >= end {
            return Ok(Access::Window {
                base,
                pages,
                offset: physical - base,
            });
        }
    }
    Err(AccessError::NotFirmwareMemory)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// A flat physical image starting at physical 0.
    struct Image(Vec<u8>);

    impl Memory for Image {
        fn bytes(&mut self, physical: u64, length: usize) -> Option<&[u8]> {
            let start = usize::try_from(physical).ok()?;
            self.0.get(start..start.checked_add(length)?)
        }
    }

    impl Image {
        fn put(&mut self, at: usize, bytes: &[u8]) {
            if self.0.len() < at + bytes.len() {
                self.0.resize(at + bytes.len(), 0);
            }
            self.0[at..at + bytes.len()].copy_from_slice(bytes);
        }
    }

    fn fix(bytes: &mut [u8], at: usize) {
        bytes[at] = 0;
        bytes[at] = 0u8.wrapping_sub(sum(bytes));
    }

    fn table(signature: &[u8; 4], revision: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER_BYTES];
        bytes[..4].copy_from_slice(signature);
        let length = (HEADER_BYTES + body.len()) as u32;
        bytes[4..8].copy_from_slice(&length.to_le_bytes());
        bytes[8] = revision;
        bytes[10..16].copy_from_slice(b"ABSDTS");
        bytes.extend_from_slice(body);
        fix(&mut bytes, 9);
        bytes
    }

    fn rsdp_v2(xsdt: u64, rsdt: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; 36];
        bytes[..8].copy_from_slice(b"RSD PTR ");
        bytes[15] = 2;
        bytes[16..20].copy_from_slice(&rsdt.to_le_bytes());
        bytes[20..24].copy_from_slice(&36u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&xsdt.to_le_bytes());
        bytes[8] = 0u8.wrapping_sub(sum(&bytes[..20]));
        fix(&mut bytes, 32);
        bytes
    }

    fn rsdp_v1(rsdt: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; 20];
        bytes[..8].copy_from_slice(b"RSD PTR ");
        bytes[16..20].copy_from_slice(&rsdt.to_le_bytes());
        fix(&mut bytes, 8);
        bytes
    }

    fn madt_body(entries: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0xfee0_0000u32.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        for entry in entries {
            body.extend_from_slice(entry);
        }
        body
    }

    fn lapic(uid: u8, apic: u8, flags: u32) -> Vec<u8> {
        let mut entry = vec![0, 8, uid, apic];
        entry.extend_from_slice(&flags.to_le_bytes());
        entry
    }

    fn x2apic(apic: u32, flags: u32, uid: u32) -> Vec<u8> {
        let mut entry = vec![9, 16, 0, 0];
        entry.extend_from_slice(&apic.to_le_bytes());
        entry.extend_from_slice(&flags.to_le_bytes());
        entry.extend_from_slice(&uid.to_le_bytes());
        entry
    }

    fn ioapic(id: u8, address: u32, base: u32) -> Vec<u8> {
        let mut entry = vec![1, 12, id, 0];
        entry.extend_from_slice(&address.to_le_bytes());
        entry.extend_from_slice(&base.to_le_bytes());
        entry
    }

    fn iso(source: u8, gsi: u32, flags: u16) -> Vec<u8> {
        let mut entry = vec![2, 10, 0, source];
        entry.extend_from_slice(&gsi.to_le_bytes());
        entry.extend_from_slice(&flags.to_le_bytes());
        entry
    }

    fn fadt_body(dsdt: u32, pm1a: u32, pm1b: u32, length: usize) -> Vec<u8> {
        let mut table = vec![0u8; length];
        table[40..44].copy_from_slice(&dsdt.to_le_bytes());
        table[64..68].copy_from_slice(&pm1a.to_le_bytes());
        table[68..72].copy_from_slice(&pm1b.to_le_bytes());
        table[89] = 2;
        if length >= 129 {
            table[112..116].copy_from_slice(&FADT_RESET_REG_SUP.to_le_bytes());
            table[116] = SPACE_IO;
            table[117] = 8;
            table[120..128].copy_from_slice(&0xcf9u64.to_le_bytes());
            table[128] = 6;
        }
        table[HEADER_BYTES..].to_vec()
    }

    fn s5_dsdt(aml: &[u8]) -> Vec<u8> {
        table(b"DSDT", 2, aml)
    }

    const S5_QEMU: &[u8] = &[0x08, b'_', b'S', b'5', b'_', 0x12, 0x06, 0x04, 0, 0, 0, 0];

    /// A complete machine: RSDP v2 -> XSDT -> {FACP, APIC, junk}, DSDT.
    fn machine(cpus: u8) -> (Image, Vec<u8>) {
        let mut image = Image(vec![0; 0x10000]);
        let mut entries: Vec<Vec<u8>> = (0..cpus).map(|id| lapic(id, id, 1)).collect();
        entries.push(ioapic(0, 0xfec0_0000, 0));
        entries.push(iso(0, 2, 0));
        entries.push(iso(9, 9, 0xd));
        entries.push(vec![4, 6, 0xff, 0, 0, 1]);
        let refs: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
        image.put(0x2000, &table(b"APIC", 3, &madt_body(&refs)));
        image.put(
            0x3000,
            &table(b"FACP", 5, &fadt_body(0x4000, 0x604, 0, 244)),
        );
        let mut aml = vec![0x10, 0x05, b'\\', b'_', b'S', b'B', b'_'];
        aml.extend_from_slice(S5_QEMU);
        image.put(0x4000, &s5_dsdt(&aml));
        let mut xsdt_body = Vec::new();
        for address in [0x3000u64, 0x2000] {
            xsdt_body.extend_from_slice(&address.to_le_bytes());
        }
        image.put(0x1000, &table(b"XSDT", 1, &xsdt_body));
        (image, rsdp_v2(0x1000, 0))
    }

    #[test]
    fn full_walk_reads_topology_reset_and_s5() {
        let (mut image, rsdp) = machine(4);
        let rsdp = parse_rsdp(&rsdp).unwrap();
        assert_eq!(rsdp.xsdt, Some(0x1000));
        let root = read_root(&mut image, &rsdp).unwrap();
        assert!(root.xsdt);
        assert_eq!(root.entries().len(), 2);
        let madt_at = root.find(b"APIC").unwrap();
        let (_, bytes) = read_table(&mut image, madt_at, Some(b"APIC")).unwrap();
        let madt = parse_madt(bytes).unwrap();
        assert_eq!(madt.enabled(), 4);
        assert_eq!(madt.ioapics().len(), 1);
        assert_eq!(madt.isos().len(), 2);
        assert_eq!(madt.other, 1);
        assert!(madt.has_apic(3) && !madt.has_apic(4));
        let fadt_at = root.find(b"FACP").unwrap();
        let (_, bytes) = read_table(&mut image, fadt_at, Some(b"FACP")).unwrap();
        let fadt = parse_fadt(bytes).unwrap();
        assert_eq!(fadt.dsdt_address(), Some(0x4000));
        assert_eq!(pm1_ports(&fadt), Ok((0x604, None)));
        let (gas, value) = fadt.reset.unwrap();
        assert_eq!((gas.space, gas.address, value), (SPACE_IO, 0xcf9, 6));
        let (_, dsdt) = read_table(&mut image, 0x4000, Some(b"DSDT")).unwrap();
        assert_eq!(s5_sleep_types(dsdt), Ok((0, 0)));
    }

    #[test]
    fn rsdt_used_without_xsdt() {
        let (mut image, _) = machine(1);
        let mut body = Vec::new();
        for address in [0x2000u32, 0x3000] {
            body.extend_from_slice(&address.to_le_bytes());
        }
        image.put(0x5000, &table(b"RSDT", 1, &body));
        let rsdp = parse_rsdp(&rsdp_v1(0x5000)).unwrap();
        assert_eq!(rsdp.xsdt, None);
        let root = read_root(&mut image, &rsdp).unwrap();
        assert!(!root.xsdt);
        assert_eq!(root.find(b"APIC"), Ok(0x2000));
    }

    #[test]
    fn rsdp_refusals() {
        assert_eq!(parse_rsdp(&[0; 10]), Err(Error::RsdpLength));
        let mut bad = rsdp_v1(0x5000);
        bad[0] = b'X';
        assert_eq!(parse_rsdp(&bad), Err(Error::RsdpSignature));
        let mut bad = rsdp_v1(0x5000);
        bad[16] ^= 1;
        assert_eq!(parse_rsdp(&bad), Err(Error::RsdpChecksum));
        let mut bad = rsdp_v2(0x1000, 0);
        bad[24] ^= 1;
        assert_eq!(parse_rsdp(&bad), Err(Error::RsdpExtendedChecksum));
        // A v2 RSDP truncated to its v1 part, or claiming more than given.
        let good = rsdp_v2(0x1000, 0);
        assert_eq!(parse_rsdp(&good[..20]), Err(Error::RsdpExtendedLength));
        let mut long = good.clone();
        long[20..24].copy_from_slice(&40u32.to_le_bytes());
        assert_eq!(parse_rsdp(&long), Err(Error::RsdpExtendedLength));
    }

    #[test]
    fn table_refusals() {
        let (mut image, _) = machine(2);
        // Checksum.
        image.0[0x2000 + 50] ^= 0x40;
        assert_eq!(
            read_table(&mut image, 0x2000, Some(b"APIC")).map(|(h, _)| h),
            Err(Error::Checksum)
        );
        // Signature.
        assert_eq!(
            read_table(&mut image, 0x3000, Some(b"APIC")).map(|(h, _)| h),
            Err(Error::Signature)
        );
        // Length below the header, above the cap, and past the memory.
        for length in [10u32, (MAX_TABLE_BYTES + 1) as u32, 0xf000] {
            image.0[0x3004..0x3008].copy_from_slice(&length.to_le_bytes());
            assert!(read_table(&mut image, 0x3000, None).is_err());
        }
        assert_eq!(
            read_table(&mut image, 0, None).map(|(h, _)| h),
            Err(Error::RootAddress)
        );
        assert_eq!(
            read_table(&mut image, 0xfff0, None).map(|(h, _)| h),
            Err(Error::Unreachable)
        );
    }

    #[test]
    fn root_refusals() {
        let (mut image, rsdp) = machine(2);
        let rsdp = parse_rsdp(&rsdp).unwrap();
        // A bad listed table is refused alone; the walk continues.
        image.0[0x3000 + 60] ^= 1;
        let root = read_root(&mut image, &rsdp).unwrap();
        assert_eq!(root.entries()[0].header, Err(Error::Checksum));
        assert_eq!(root.entries()[0].signature, *b"FACP");
        assert_eq!(root.find(b"FACP"), Err(Error::Checksum));
        assert_eq!(root.find(b"HPET"), Err(Error::Missing));
        assert_eq!(root.find(b"APIC"), Ok(0x2000));
        // A ragged XSDT body refuses the whole walk.
        image.put(0x1000, &table(b"XSDT", 1, &[0; 12]));
        assert_eq!(
            read_root(&mut image, &rsdp).map(|r| r.count),
            Err(Error::RootEntries)
        );
        // Too many entries.
        image.put(0x1000, &table(b"XSDT", 1, &vec![0; 8 * (MAX_TABLES + 1)]));
        assert_eq!(
            read_root(&mut image, &rsdp).map(|r| r.count),
            Err(Error::TooManyTables)
        );
        // A duplicate MADT is ambiguous.
        let mut body = Vec::new();
        for address in [0x2000u64, 0x2000] {
            body.extend_from_slice(&address.to_le_bytes());
        }
        image.put(0x1000, &table(b"XSDT", 1, &body));
        let root = read_root(&mut image, &rsdp).unwrap();
        assert_eq!(root.find(b"APIC"), Err(Error::Duplicate));
        // A root with a bad checksum refuses.
        image.0[0x1000 + 40] ^= 1;
        assert_eq!(
            read_root(&mut image, &rsdp).map(|r| r.count),
            Err(Error::Checksum)
        );
    }

    fn madt(entries: &[Vec<u8>]) -> Vec<u8> {
        let refs: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
        table(b"APIC", 3, &madt_body(&refs))
    }

    #[test]
    fn madt_entries() {
        let parsed = parse_madt(&madt(&[
            lapic(0, 0, 1),
            lapic(1, 1, 0),
            lapic(2, 2, 2),
            x2apic(300, 1, 7),
            ioapic(1, 0xfec0_0000, 0),
            iso(0, 2, 0),
            vec![5, 12, 0, 0, 0, 0, 0xe0, 0xfe, 0, 0, 0, 0],
        ]))
        .unwrap();
        assert_eq!(parsed.cpus().len(), 4);
        assert_eq!(parsed.enabled(), 2);
        assert_eq!(parsed.online_capable(), 1);
        assert_eq!(parsed.cpus()[3].kind, CpuKind::X2apic);
        assert_eq!(parsed.cpus()[3].uid, 7);
        assert!(parsed.has_apic(300) && parsed.has_apic(2) && !parsed.has_apic(1));
        assert_eq!(parsed.lapic_address, 0xfee0_0000);
    }

    #[test]
    fn madt_refusals() {
        // Zero, short and overlong entries; a wrong length for a known type.
        for bad in [
            vec![7, 0],
            vec![7, 1],
            vec![0, 6, 0, 0, 1, 0],
            vec![1, 10, 0, 0, 0, 0, 0xc0, 0xfe, 0, 0],
            vec![7, 40, 0, 0],
        ] {
            let mut bytes = madt(&[lapic(0, 0, 1)]);
            bytes.extend_from_slice(&bad);
            let length = bytes.len() as u32;
            bytes[4..8].copy_from_slice(&length.to_le_bytes());
            fix(&mut bytes, 9);
            assert!(parse_madt(&bytes).is_err(), "{bad:?}");
        }
        // Duplicate usable APIC IDs, but a disabled duplicate is fine.
        assert_eq!(
            parse_madt(&madt(&[lapic(0, 0, 1), lapic(1, 0, 1)])).map(|m| m.cpu_count),
            Err(Error::MadtDuplicateApic)
        );
        assert!(parse_madt(&madt(&[lapic(0, 0, 1), lapic(1, 0, 0)])).is_ok());
        // Too many entries.
        let many: Vec<Vec<u8>> = (0..=MAX_IOAPICS as u8).map(|i| ioapic(i, 0, 0)).collect();
        assert_eq!(
            parse_madt(&madt(&many)).map(|m| m.cpu_count),
            Err(Error::MadtTooMany)
        );
        let many: Vec<Vec<u8>> = (0..=MAX_CPUS as u32).map(|i| x2apic(i, 0, i)).collect();
        assert_eq!(
            parse_madt(&madt(&many)).map(|m| m.cpu_count),
            Err(Error::MadtTooMany)
        );
    }

    #[test]
    fn fadt_fields_and_refusals() {
        // A revision-1 FADT has no reset register and no X fields.
        let short = table(b"FACP", 1, &fadt_body(0x4000, 0x604, 0, 116));
        let fadt = parse_fadt(&short).unwrap();
        assert_eq!(fadt.reset, None);
        assert_eq!(fadt.x_pm1a_cnt, None);
        assert_eq!(pm1_ports(&fadt), Ok((0x604, None)));
        assert_eq!(
            parse_fadt(&table(b"FACP", 1, &[0; 40])).map(|f| f.length),
            Err(Error::FadtLength)
        );
        let mut body = fadt_body(0x4000, 0x604, 0x608, 244);
        // X_PM1a agreeing with the legacy port is fine; disagreeing refuses.
        let put_x = |body: &mut Vec<u8>, at: usize, space: u8, width: u8, address: u64| {
            let at = at - HEADER_BYTES;
            body[at] = space;
            body[at + 1] = width;
            body[at + 4..at + 12].copy_from_slice(&address.to_le_bytes());
        };
        put_x(&mut body, 172, SPACE_IO, 16, 0x604);
        let fadt = parse_fadt(&table(b"FACP", 5, &body)).unwrap();
        assert_eq!(pm1_ports(&fadt), Ok((0x604, Some(0x608))));
        put_x(&mut body, 172, SPACE_IO, 16, 0x704);
        let fadt = parse_fadt(&table(b"FACP", 5, &body)).unwrap();
        assert_eq!(pm1_ports(&fadt), Err(PowerError::Pm1Ambiguous));
        put_x(&mut body, 172, SPACE_MEMORY, 16, 0x604);
        let fadt = parse_fadt(&table(b"FACP", 5, &body)).unwrap();
        assert_eq!(pm1_ports(&fadt), Err(PowerError::Pm1NotIo));
        put_x(&mut body, 172, SPACE_IO, 32, 0x604);
        let fadt = parse_fadt(&table(b"FACP", 5, &body)).unwrap();
        assert_eq!(pm1_ports(&fadt), Err(PowerError::Pm1Width));
        // Hardware-reduced and absent PM1a.
        let mut body = fadt_body(0x4000, 0, 0, 244);
        let fadt = parse_fadt(&table(b"FACP", 5, &body)).unwrap();
        assert_eq!(pm1_ports(&fadt), Err(PowerError::Pm1aAbsent));
        body[112 - HEADER_BYTES..116 - HEADER_BYTES]
            .copy_from_slice(&FADT_HW_REDUCED.to_le_bytes());
        let fadt = parse_fadt(&table(b"FACP", 5, &body)).unwrap();
        assert_eq!(pm1_ports(&fadt), Err(PowerError::HardwareReduced));
        // Disagreeing DSDT pointers are ambiguous.
        let mut body = fadt_body(0x4000, 0x604, 0, 244);
        body[140 - HEADER_BYTES..148 - HEADER_BYTES].copy_from_slice(&0x5000u64.to_le_bytes());
        let fadt = parse_fadt(&table(b"FACP", 5, &body)).unwrap();
        assert_eq!(fadt.dsdt_address(), None);
    }

    #[test]
    fn s5_scan() {
        let with = |aml: &[u8]| s5_sleep_types(&s5_dsdt(aml));
        assert_eq!(with(S5_QEMU), Ok((0, 0)));
        // Root-prefixed, byte-prefixed values, two-byte package length.
        assert_eq!(
            with(&[
                0x08, b'\\', b'_', b'S', b'5', b'_', 0x12, 0x49, 0x00, 0x04, 0x0a, 0x07, 0x0a,
                0x05, 0, 0
            ]),
            Ok((7, 5))
        );
        assert_eq!(
            with(&[
                0x08, b'_', b'S', b'5', b'_', 0x12, 0x06, 0x02, 0x0b, 0x05, 0x00, 0x01
            ]),
            Ok((5, 1))
        );
        // Absent, twice, a method, too few elements, a non-integer element,
        // a value wider than SLP_TYP, and truncated packages.
        assert_eq!(with(&[0x5b, 0x80]), Err(S5Error::NotFound));
        let mut twice = S5_QEMU.to_vec();
        twice.extend_from_slice(S5_QEMU);
        assert_eq!(with(&twice), Err(S5Error::Ambiguous));
        assert_eq!(
            with(&[0x14, 0x09, b'_', b'S', b'5', b'_', 0x00, 0xa4, 0x00]),
            Err(S5Error::NotNamePackage)
        );
        assert_eq!(
            with(&[0x08, b'_', b'S', b'5', b'_', 0x12, 0x04, 0x01, 0x0a, 0x05]),
            Err(S5Error::Elements)
        );
        assert_eq!(
            with(&[
                0x08, b'_', b'S', b'5', b'_', 0x12, 0x05, 0x02, 0x70, 0x00, 0x00
            ]),
            Err(S5Error::ElementEncoding)
        );
        assert_eq!(
            with(&[
                0x08, b'_', b'S', b'5', b'_', 0x12, 0x05, 0x02, 0x0a, 0x08, 0x00
            ]),
            Err(S5Error::Value)
        );
        assert_eq!(
            with(&[0x08, b'_', b'S', b'5', b'_', 0x12, 0x30, 0x02, 0x00, 0x00]),
            Err(S5Error::PackageLength)
        );
        assert_eq!(
            with(&[0x08, b'_', b'S', b'5', b'_', 0x12, 0x06, 0x02, 0x0a]),
            Err(S5Error::PackageLength)
        );
        assert_eq!(
            with(&[0x08, b'_', b'S', b'5', b'_', 0x12]),
            Err(S5Error::PackageLength)
        );
        assert_eq!(with(b"_S5_"), Err(S5Error::NotNamePackage));
        assert_eq!(s5_sleep_types(&[0; 10]), Err(S5Error::NotFound));
    }

    fn memory_map(rows: &[(u64, u64, u32)]) -> Vec<u8> {
        let mut tag = vec![6, 0, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0];
        for &(base, length, kind) in rows {
            tag.extend_from_slice(&base.to_le_bytes());
            tag.extend_from_slice(&length.to_le_bytes());
            tag.extend_from_slice(&kind.to_le_bytes());
            tag.extend_from_slice(&0u32.to_le_bytes());
        }
        let size = tag.len() as u32;
        tag[4..8].copy_from_slice(&size.to_le_bytes());
        tag
    }

    #[test]
    fn access_policy() {
        const G: u64 = 1 << 30;
        const M: u64 = 1 << 20;
        // q35 at -m 2G: tables at the top of low RAM, typed reserved, with
        // ordinary RAM below and the PCI hole above.
        let map = memory_map(&[
            (0x10_0000, 0x7fe0_0000 - 0x10_0000, 1),
            (0x7ffe_0000, 0x2_0000, MEMORY_RESERVED),
            (0x8000_0000, 2 * M, 1),
            (3 * G, 4 * M, MEMORY_ACPI_RECLAIM),
            (3 * G + 4 * M, 2 * M, MEMORY_ACPI_NVS),
            (5 * G, 8 * M, MEMORY_ACPI_RECLAIM),
        ]);
        let map = Some(map.as_slice());
        assert_eq!(admit(0x7fe_0040, 0x2000, map), Ok(Access::Identity));
        assert_eq!(admit(G - 36, 36, None), Ok(Access::Identity));
        assert_eq!(admit(0, 36, map), Err(AccessError::Empty));
        assert_eq!(admit(G, 0, map), Err(AccessError::Empty));
        assert_eq!(admit(G - 4, 36, map), Err(AccessError::Straddle));
        assert_eq!(
            admit(0x7ffe_0040, 0x2400, map),
            Ok(Access::Window {
                base: 0x7fe0_0000,
                pages: 1,
                offset: 0x1_e0040
            })
        );
        // Reserved row below 2 GiB but above 1 GiB.
        let low = memory_map(&[(0x7ffe_0000, 0x2_0000, MEMORY_RESERVED)]);
        assert_eq!(
            admit(0x7ffe_0040, 0x2400, Some(&low)),
            Ok(Access::Window {
                base: 0x7fe0_0000,
                pages: 1,
                offset: 0x1_e0040
            })
        );
        // Past the row's end, and with no memory map at all.
        assert_eq!(
            admit(0x7fff_f000, 0x2000, Some(&low)),
            Err(AccessError::NotFirmwareMemory)
        );
        assert_eq!(admit(0x7ffe_0040, 36, None), Err(AccessError::NoMemoryMap));
        // Usable RAM (or a BAR, absent from the map) is never mapped.
        assert_eq!(
            admit(0x8000_0000, 36, map),
            Err(AccessError::NotFirmwareMemory)
        );
        assert_eq!(admit(4 * G, 36, map), Err(AccessError::NotFirmwareMemory));
        // Adjacent reclaim and NVS rows cover one range across them; an
        // unaligned range spans two pages.
        assert_eq!(
            admit(3 * G + 3 * M, 2 << 20, map),
            Ok(Access::Window {
                base: 3 * G + 2 * M,
                pages: 2,
                offset: M
            })
        );
        // A range needing three pages is too long for the scratch view,
        // even inside firmware memory; the largest table never needs more
        // than two.
        assert_eq!(
            admit(5 * G + M, 4 << 20, Some(&memory_map(&[(5 * G, 8 * M, 3)]))),
            Err(AccessError::TooLong)
        );
        assert_eq!(admit(5 * G + M, MAX_TABLE_BYTES, map).map(|_| ()), Ok(()));
        // Overflow and the physical limit.
        assert_eq!(admit(u64::MAX - 8, 36, map), Err(AccessError::TooLong));
        // A malformed memory map has no rows.
        let mut bad = memory_map(&[(3 * G, 4 * M, 3)]);
        bad[8] = 20;
        assert_eq!(memory_map_entries(&bad).count(), 0);
        assert_eq!(
            admit(3 * G, 36, Some(&bad)),
            Err(AccessError::NotFirmwareMemory)
        );
        // A gap between rows refuses.
        let gap = memory_map(&[(3 * G, M, 3), (3 * G + 2 * M, M, 3)]);
        assert_eq!(
            admit(3 * G, (2 << 20) + 36, Some(&gap)),
            Err(AccessError::NotFirmwareMemory)
        );
    }

    #[test]
    fn pm1_value_keeps_other_bits() {
        assert_eq!(pm1_sleep_value(0x0001, 5, false), 0x1401);
        assert_eq!(pm1_sleep_value(0x3c01, 0, true), 0x2001);
        assert_eq!(pm1_sleep_value(0xffff, 7, true), 0xffff);
    }
}
