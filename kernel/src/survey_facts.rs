//! Pure decoding for the physical survey boot (`survey`, docs/hardware/):
//! Multiboot2 tags, the memory map, the CPUID signature, and PCI class
//! names. No hardware access here, so every rule is host-tested.

/// Multiboot2 tag types the survey reports by presence.
pub const TAG_COMMAND_LINE: u32 = 1;
pub const TAG_LOADER_NAME: u32 = 2;
pub const TAG_MEMORY_MAP: u32 = 6;
pub const TAG_FRAMEBUFFER: u32 = 8;
pub const TAG_EFI32: u32 = 11;
pub const TAG_EFI64: u32 = 12;
pub const TAG_SMBIOS: u32 = 13;
pub const TAG_ACPI_OLD: u32 = 14;
pub const TAG_ACPI_NEW: u32 = 15;
pub const TAG_EFI_MEMORY_MAP: u32 = 17;
pub const TAG_EFI_BOOT_SERVICES: u32 = 18;

/// The tags of a Multiboot2 information block as `(type, whole tag)`,
/// stopping at the end tag or at the first malformed one.
pub fn tags(info: &[u8]) -> impl Iterator<Item = (u32, &[u8])> {
    let mut offset = 8usize;
    core::iter::from_fn(move || {
        let header = info.get(offset..offset.checked_add(8)?)?;
        let kind = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
        if kind == 0 || size < 8 {
            return None;
        }
        let tag = info.get(offset..offset.checked_add(size)?)?;
        offset = offset.checked_add((size + 7) & !7)?;
        Some((kind, tag))
    })
}

pub fn has_tag(info: &[u8], kind: u32) -> bool {
    tags(info).any(|(found, _)| found == kind)
}

/// A tag's NUL-terminated string payload (command line, loader name).
pub fn tag_string(info: &[u8], kind: u32) -> Option<&[u8]> {
    let (_, tag) = tags(info).find(|(found, _)| *found == kind)?;
    let body = &tag[8..];
    Some(
        &body[..body
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(body.len())],
    )
}

/// The firmware memory map as GRUB passed it (tag 6), summarized.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryMap {
    pub entries: u32,
    pub usable_regions: u32,
    pub usable_bytes: u64,
    pub reserved_bytes: u64,
    pub acpi_reclaimable_bytes: u64,
    pub acpi_nvs_bytes: u64,
    pub bad_bytes: u64,
    /// One past the highest address of any entry.
    pub highest_end: u64,
}

pub fn memory_map(info: &[u8]) -> Option<MemoryMap> {
    let (_, tag) = tags(info).find(|(kind, _)| *kind == TAG_MEMORY_MAP)?;
    let word = |at: usize| {
        tag.get(at..at + 4)
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    };
    let quad = |at: usize| {
        tag.get(at..at + 8).map(|bytes| {
            let mut value = [0u8; 8];
            value.copy_from_slice(bytes);
            u64::from_le_bytes(value)
        })
    };
    let entry_size = word(8)? as usize;
    if entry_size < 24 || !(tag.len() - 16).is_multiple_of(entry_size) {
        return None;
    }
    let mut map = MemoryMap::default();
    let mut at = 16;
    while at < tag.len() {
        let base = quad(at)?;
        let length = quad(at + 8)?;
        let kind = word(at + 16)?;
        map.entries += 1;
        map.highest_end = map.highest_end.max(base.saturating_add(length));
        let bucket = match kind {
            1 => {
                map.usable_regions += 1;
                &mut map.usable_bytes
            }
            3 => &mut map.acpi_reclaimable_bytes,
            4 => &mut map.acpi_nvs_bytes,
            5 => &mut map.bad_bytes,
            _ => &mut map.reserved_bytes,
        };
        *bucket = bucket.saturating_add(length);
        at += entry_size;
    }
    Some(map)
}

/// `(family, model, stepping)` from CPUID leaf 1 EAX, with the extended
/// fields applied as the Intel SDM and AMD APM define them.
pub fn cpu_signature(eax: u32) -> (u32, u32, u32) {
    let stepping = eax & 0xf;
    let base_model = (eax >> 4) & 0xf;
    let base_family = (eax >> 8) & 0xf;
    let family = if base_family == 0xf {
        base_family + ((eax >> 20) & 0xff)
    } else {
        base_family
    };
    let model = if base_family == 0x6 || base_family == 0xf {
        (((eax >> 16) & 0xf) << 4) | base_model
    } else {
        base_model
    };
    (family, model, stepping)
}

/// What a mass-storage (class 01) function is, and whether an ABSD driver
/// would claim it. The survey starts none of them.
pub fn storage_kind(subclass: u8, interface: u8) -> (&'static str, &'static str) {
    match (subclass, interface) {
        (0x08, 0x02) => ("NVMe", "nvme"),
        (0x01, _) => ("IDE", "ata"),
        (0x06, 0x01) => ("AHCI SATA", "none"),
        (0x06, _) => ("SATA", "none"),
        (0x04, _) => ("RAID", "none"),
        (0x00, _) => ("SCSI", "none"),
        (0x07, _) => ("SAS", "none"),
        (0x08, _) => ("NVM", "none"),
        (0x80, _) => ("other storage", "none"),
        _ => ("storage", "none"),
    }
}

/// The only network function the kernel's e1000 driver accepts.
pub const E1000_IDS: (u16, u16) = (0x8086, 0x100e);

/// Width of one compact PCI cell on the summary screen:
/// `BB:DD.F VVVV:DDDD CCSSPP` and two spaces.
pub const PCI_CELL: usize = 26;

pub fn pci_cells_per_row(columns: usize) -> usize {
    (columns / PCI_CELL).max(1)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn tag(kind: u32, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&(8 + body.len() as u32).to_le_bytes());
        out.extend_from_slice(body);
        while out.len() % 8 != 0 {
            out.push(0);
        }
        out
    }

    fn info(parts: &[Vec<u8>]) -> Vec<u8> {
        let mut body: Vec<u8> = parts.concat();
        body.extend(tag(0, &[]));
        let mut out = Vec::new();
        out.extend_from_slice(&(8 + body.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend(body);
        out
    }

    fn map_tag(rows: &[(u64, u64, u32)]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&24u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        for &(base, length, kind) in rows {
            body.extend_from_slice(&base.to_le_bytes());
            body.extend_from_slice(&length.to_le_bytes());
            body.extend_from_slice(&kind.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes());
        }
        tag(TAG_MEMORY_MAP, &body)
    }

    #[test]
    fn memory_map_sums_by_type() {
        let block = info(&[map_tag(&[
            (0, 0x9fc00, 1),
            (0x9fc00, 0x400, 2),
            (0x10_0000, 0x7ff0_0000, 1),
            (0x7ff0_0000, 0x1000, 3),
            (0x7ff0_1000, 0x1000, 4),
            (0x1_0000_0000, 0x1000, 5),
        ])]);
        let map = memory_map(&block).unwrap();
        assert_eq!(map.entries, 6);
        assert_eq!(map.usable_regions, 2);
        assert_eq!(map.usable_bytes, 0x9fc00 + 0x7ff0_0000);
        assert_eq!(map.reserved_bytes, 0x400);
        assert_eq!(map.acpi_reclaimable_bytes, 0x1000);
        assert_eq!(map.acpi_nvs_bytes, 0x1000);
        assert_eq!(map.bad_bytes, 0x1000);
        assert_eq!(map.highest_end, 0x1_0000_1000);
    }

    #[test]
    fn malformed_map_is_refused() {
        let mut bad = map_tag(&[(0, 0x1000, 1)]);
        bad[8] = 20; // entry size below 24
        assert_eq!(memory_map(&info(&[bad])), None);
        assert_eq!(memory_map(&info(&[])), None);
    }

    #[test]
    fn tags_and_strings() {
        let block = info(&[
            tag(TAG_COMMAND_LINE, b"survey halt-on-exit\0"),
            tag(TAG_LOADER_NAME, b"GRUB 2.12\0"),
            tag(TAG_EFI64, &[0; 8]),
            tag(TAG_ACPI_NEW, &[0; 36]),
        ]);
        assert_eq!(
            tag_string(&block, TAG_COMMAND_LINE),
            Some(&b"survey halt-on-exit"[..])
        );
        assert_eq!(tag_string(&block, TAG_LOADER_NAME), Some(&b"GRUB 2.12"[..]));
        assert!(has_tag(&block, TAG_EFI64));
        assert!(!has_tag(&block, TAG_EFI32));
        assert!(has_tag(&block, TAG_ACPI_NEW));
        assert!(!has_tag(&block, TAG_ACPI_OLD));
        // A truncated tag ends the walk instead of reading past the block.
        let mut short = block.clone();
        short.truncate(20);
        assert_eq!(tags(&short).count(), 0);
    }

    #[test]
    fn cpu_signatures() {
        // Skylake-S client/Xeon E3 v5 style: family 6, extended model 5.
        assert_eq!(cpu_signature(0x0005_06e3), (6, 0x5e, 3));
        // AMD family 15h (base 0xf, extended 6).
        assert_eq!(cpu_signature(0x0060_0f20), (0x15, 0x02, 0));
        // Family 5: extended model is not applied.
        assert_eq!(cpu_signature(0x0001_0543), (5, 4, 3));
    }

    #[test]
    fn storage_kinds() {
        assert_eq!(storage_kind(0x08, 0x02), ("NVMe", "nvme"));
        assert_eq!(storage_kind(0x06, 0x01), ("AHCI SATA", "none"));
        assert_eq!(storage_kind(0x01, 0x8a).1, "ata");
        assert_eq!(storage_kind(0x04, 0x00).0, "RAID");
    }

    #[test]
    fn cells_per_row() {
        assert_eq!(pci_cells_per_row(128), 4);
        assert_eq!(pci_cells_per_row(80), 3);
        assert_eq!(pci_cells_per_row(10), 1);
    }
}

// ---------------------------------------------------------------------------
// Clock 6a: the TSC measured against the PIT (docs/clock-contract-20261015 §3).
// The arithmetic and the line's format live here so the host tests cover them
// and the kernel and the survey print the same line.

/// The 8254's input clock is the NTSC colour burst over three, exactly
/// 3 579 545 / 3 Hz (1 193 181.67 Hz), and `timer_test()` programs the
/// divisor 0x04a9 = 1193: one tick is 3 · 1193 / 3 579 545 s, about 1 ms.
pub const PIT_INPUT_HZ_TIMES_3: u64 = 3_579_545;
pub const PIT_DIVISOR: u64 = 1193;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CalibrationSummary {
    pub median: u64,
    pub min: u64,
    pub max: u64,
}

/// Median (the upper middle of an even count), min and max of the samples,
/// which are sorted in place. None for no samples.
pub fn calibration_summary(samples: &mut [u64]) -> Option<CalibrationSummary> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_unstable();
    Some(CalibrationSummary {
        median: samples[samples.len() / 2],
        min: samples[0],
        max: samples[samples.len() - 1],
    })
}

/// `max − min` in whole percent of the median; u64::MAX for a zero median.
pub fn spread_percent(summary: &CalibrationSummary) -> u64 {
    if summary.median == 0 {
        return u64::MAX;
    }
    (summary.max - summary.min).saturating_mul(100) / summary.median
}

/// TSC frequency implied by TSC cycles per PIT tick: cycles · 3 579 545 / (3 · 1193).
pub fn tsc_hz(tsc_per_tick: u64) -> u64 {
    (u128::from(tsc_per_tick) * u128::from(PIT_INPUT_HZ_TIMES_3) / u128::from(3 * PIT_DIVISOR))
        as u64
}

/// Whether a CPUID leaf may be read: basic leaves up to leaf 0's EAX,
/// extended leaves (0x8000_0000 and up) up to leaf 0x8000_0000's EAX, which
/// must itself lie in the extended range. Out-of-range leaves return another
/// leaf's data on real CPUs, so this guard comes before every read.
pub fn cpuid_leaf_available(max_basic: u32, max_extended: u32, leaf: u32) -> bool {
    if leaf >= 0x8000_0000 {
        max_extended >= 0x8000_0000 && leaf <= max_extended
    } else {
        max_basic < 0x8000_0000 && leaf <= max_basic
    }
}

/// What a guarded CPUID leaf said: out of range, present but all zero, or a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leaf<T> {
    Absent,
    Zero,
    Present(T),
}

/// One `TIMER CALIBRATION` line's content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerCalibration {
    pub tsc_per_tick: u64,
    pub min: u64,
    pub max: u64,
    pub samples: u64,
    pub ticks: u64,
    pub tsc_hz: u64,
    /// CPUID.1:ECX[31].
    pub virtualized: bool,
    /// CPUID.15H: (numerator, denominator, crystal Hz; the crystal may be 0).
    pub cpuid15: Leaf<(u32, u32, u32)>,
    /// CPUID.16H EAX[15:0], the base frequency in MHz.
    pub cpuid16_mhz: Leaf<u32>,
    /// CPUID.80000007H:EDX[8] when the leaf exists.
    pub invariant: Option<bool>,
    /// The interrupts-off stall fixture was active between two sample edges.
    pub fixture_stall: bool,
}

struct Buffer<'a> {
    bytes: &'a mut [u8],
    len: usize,
}
impl core::fmt::Write for Buffer<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let b = s.as_bytes();
        let end = self.len.checked_add(b.len()).ok_or(core::fmt::Error)?;
        if end > self.bytes.len() {
            return Err(core::fmt::Error);
        }
        self.bytes[self.len..end].copy_from_slice(b);
        self.len = end;
        Ok(())
    }
}

/// The longest line any u64 values can produce, with every field at its widest.
pub const TIMER_CALIBRATION_LINE_MAX: usize = 320;

/// The line, without its newline, into `buf` (`TIMER_CALIBRATION_LINE_MAX`
/// bytes always suffice; None if `buf` is too small).
pub fn format_timer_calibration<'a>(c: &TimerCalibration, buf: &'a mut [u8]) -> Option<&'a str> {
    use core::fmt::Write;
    let len = {
        let mut w = Buffer { bytes: buf, len: 0 };
        write!(
            w,
            "TIMER CALIBRATION tsc_per_tick={} min={} max={} samples={} ticks={} tsc_hz={} virtualized={}",
            c.tsc_per_tick,
            c.min,
            c.max,
            c.samples,
            c.ticks,
            c.tsc_hz,
            if c.virtualized { "yes" } else { "no" }
        )
        .ok()?;
        match c.cpuid15 {
            Leaf::Present((num, den, crystal)) => {
                write!(w, " cpuid15={num}/{den}@{crystal}").ok()?
            }
            Leaf::Zero => w.write_str(" cpuid15=zero").ok()?,
            Leaf::Absent => w.write_str(" cpuid15=absent").ok()?,
        }
        match c.cpuid16_mhz {
            Leaf::Present(mhz) => write!(w, " cpuid16={mhz}MHz").ok()?,
            Leaf::Zero => w.write_str(" cpuid16=zero").ok()?,
            Leaf::Absent => w.write_str(" cpuid16=absent").ok()?,
        }
        w.write_str(match c.invariant {
            Some(true) => " invariant=yes",
            Some(false) => " invariant=no",
            None => " invariant=unknown",
        })
        .ok()?;
        if c.fixture_stall {
            w.write_str(" fixture=stall").ok()?;
        }
        w.len
    };
    core::str::from_utf8(&buf[..len]).ok()
}

/// The decoder for the line (hosts, gates and the survey reader): every
/// field but `fixture` exactly once, in any order, no other words.
pub fn parse_timer_calibration(line: &str) -> Option<TimerCalibration> {
    let rest = line.strip_prefix("TIMER CALIBRATION ")?;
    let mut c = TimerCalibration {
        tsc_per_tick: 0,
        min: 0,
        max: 0,
        samples: 0,
        ticks: 0,
        tsc_hz: 0,
        virtualized: false,
        cpuid15: Leaf::Absent,
        cpuid16_mhz: Leaf::Absent,
        invariant: None,
        fixture_stall: false,
    };
    const KEYS: [&str; 11] = [
        "tsc_per_tick",
        "min",
        "max",
        "samples",
        "ticks",
        "tsc_hz",
        "virtualized",
        "cpuid15",
        "cpuid16",
        "invariant",
        "fixture",
    ];
    const MANDATORY: u32 = (1 << 10) - 1;
    let mut seen = 0u32;
    for word in rest.split(' ').filter(|w| !w.is_empty()) {
        let (key, value) = word.split_once('=')?;
        let index = KEYS.iter().position(|k| *k == key)?;
        if seen & (1 << index) != 0 {
            return None;
        }
        seen |= 1 << index;
        match key {
            "tsc_per_tick" => c.tsc_per_tick = value.parse().ok()?,
            "min" => c.min = value.parse().ok()?,
            "max" => c.max = value.parse().ok()?,
            "samples" => c.samples = value.parse().ok()?,
            "ticks" => c.ticks = value.parse().ok()?,
            "tsc_hz" => c.tsc_hz = value.parse().ok()?,
            "virtualized" => c.virtualized = yes_no(value)?,
            "cpuid15" => {
                c.cpuid15 = match value {
                    "absent" => Leaf::Absent,
                    "zero" => Leaf::Zero,
                    _ => {
                        let (ratio, crystal) = value.split_once('@')?;
                        let (num, den) = ratio.split_once('/')?;
                        Leaf::Present((num.parse().ok()?, den.parse().ok()?, crystal.parse().ok()?))
                    }
                }
            }
            "cpuid16" => {
                c.cpuid16_mhz = match value {
                    "absent" => Leaf::Absent,
                    "zero" => Leaf::Zero,
                    _ => Leaf::Present(value.strip_suffix("MHz")?.parse().ok()?),
                }
            }
            "invariant" => {
                c.invariant = match value {
                    "unknown" => None,
                    other => Some(yes_no(other)?),
                }
            }
            "fixture" => {
                if value != "stall" {
                    return None;
                }
                c.fixture_stall = true;
            }
            _ => return None,
        }
    }
    (seen & MANDATORY == MANDATORY).then_some(c)
}

fn yes_no(value: &str) -> Option<bool> {
    match value {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

// ATA IDENTIFY DEVICE decoding (the AHCI census): pure word
// arithmetic, host-tested, used by src/ahci.rs.

/// IDENTIFY strings are stored two characters per word, high byte first.
fn ata_string(words: &[u16; 256], start: usize, count: usize, out: &mut [u8]) -> usize {
    let mut length = 0;
    for (i, word) in words[start..start + count].iter().enumerate() {
        out[2 * i] = (word >> 8) as u8;
        out[2 * i + 1] = *word as u8;
        length = 2 * i + 2;
    }
    // Trim the space padding and anything unprintable at the end.
    while length > 0 && (out[length - 1] == b' ' || out[length - 1] == 0) {
        length -= 1;
    }
    length
}

static mut ATA_STRINGS: [u8; 40 + 20 + 8] = [0; 68];

/// `(model, serial, firmware)` from words 27–46, 10–19 and 23–26, trimmed.
/// Returns slices of one static buffer: one call's result at a time.
pub fn ata_identify_strings(words: &[u16; 256]) -> (&'static [u8], &'static [u8], &'static [u8]) {
    let buffer = unsafe { &mut *core::ptr::addr_of_mut!(ATA_STRINGS) };
    let model = ata_string(words, 27, 20, &mut buffer[..40]);
    let serial = ata_string(words, 10, 10, &mut buffer[40..60]);
    let firmware = ata_string(words, 23, 4, &mut buffer[60..68]);
    let buffer = unsafe { &*core::ptr::addr_of!(ATA_STRINGS) };
    (
        &buffer[..model],
        &buffer[40..40 + serial],
        &buffer[60..60 + firmware],
    )
}

/// Word 0 bit 2: the response is incomplete (power-up in standby); the
/// other fields are not to be trusted.
pub fn ata_identify_incomplete(words: &[u16; 256]) -> bool {
    words[0] & (1 << 2) != 0
}

/// Word 83 bit 10, the 48-bit address feature set, counted only when the
/// word is valid (bits 15:14 == 01).
pub fn ata_identify_lba48(words: &[u16; 256]) -> bool {
    words[83] >> 14 == 0b01 && words[83] & (1 << 10) != 0
}

/// Addressable sectors: words 100–103 with LBA48, else words 60–61.
pub fn ata_identify_sectors(words: &[u16; 256]) -> u64 {
    if ata_identify_lba48(words) {
        u64::from(words[100])
            | (u64::from(words[101]) << 16)
            | (u64::from(words[102]) << 32)
            | (u64::from(words[103]) << 48)
    } else {
        u64::from(words[60]) | (u64::from(words[61]) << 16)
    }
}

/// Logical sector size: words 117–118 when word 106 says so, else 512; None
/// when the words claim a size that cannot be (the kernel prints it, it
/// does not trust it).
pub fn ata_identify_logical_sector_bytes(words: &[u16; 256]) -> Option<u32> {
    let w106 = words[106];
    if w106 & (1 << 14) != 0 && w106 & (1 << 15) == 0 && w106 & (1 << 12) != 0 {
        let words_per_sector = u32::from(words[117]) | (u32::from(words[118]) << 16);
        if words_per_sector < 256 {
            return None;
        }
        return words_per_sector.checked_mul(2);
    }
    Some(512)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rotation {
    NonRotating,
    Rpm(u16),
    Unknown,
}

/// Word 217: 1 = non-rotating (solid state), 0x0401–0xfffe = RPM.
pub fn ata_identify_rotation(words: &[u16; 256]) -> Rotation {
    match words[217] {
        1 => Rotation::NonRotating,
        rpm @ 0x0401..=0xfffe => Rotation::Rpm(rpm),
        _ => Rotation::Unknown,
    }
}

#[cfg(test)]
mod calibration_tests {
    use super::*;

    #[test]
    fn summary_is_median_min_max() {
        let mut s = [3_000_000u64, 2_990_000, 3_010_000, 2_980_000, 3_020_000];
        let summary = calibration_summary(&mut s).unwrap();
        assert_eq!(
            summary,
            CalibrationSummary {
                median: 3_000_000,
                min: 2_980_000,
                max: 3_020_000
            }
        );
        assert_eq!(spread_percent(&summary), 1);
        assert_eq!(calibration_summary(&mut []), None);
        let mut stalled = [3_000_000u64, 3_000_000, 4_500_000, 3_000_000, 3_000_000];
        assert_eq!(
            spread_percent(&calibration_summary(&mut stalled).unwrap()),
            50
        );
        assert_eq!(
            spread_percent(&CalibrationSummary {
                median: 0,
                min: 0,
                max: 0
            }),
            u64::MAX
        );
    }

    #[test]
    fn tsc_hz_follows_the_pit_divisor() {
        // 1 ms ticks at exactly 3 GHz: 3 000 000 cycles per 1193/1193182 s.
        assert_eq!(tsc_hz(3_000_000), 3_000_456_831);
        // The approximation 1 193 182 Hz would say 3 000 457 669: 0.28 ppm high.
        assert!(tsc_hz(3_000_000) < 3_000_457_669);
        assert_eq!(tsc_hz(0), 0);
        assert!(tsc_hz(u64::MAX / 2) > tsc_hz(u64::MAX / 4));
    }

    #[test]
    fn cpuid_leaf_guard_refuses_out_of_range_leaves() {
        assert!(cpuid_leaf_available(0x16, 0x8000_0008, 0x15));
        assert!(cpuid_leaf_available(0x16, 0x8000_0008, 0x16));
        assert!(!cpuid_leaf_available(0x0d, 0x8000_0008, 0x15));
        assert!(!cpuid_leaf_available(0x0d, 0x8000_0008, 0x16));
        assert!(cpuid_leaf_available(0x0d, 0x8000_0008, 0x8000_0007));
        assert!(!cpuid_leaf_available(0x0d, 0x8000_0004, 0x8000_0007));
        // A CPU with no extended leaves answers 0x8000_0000 with basic data.
        assert!(!cpuid_leaf_available(0x0d, 0x0000_000d, 0x8000_0007));
        // A nonsensical maximum basic leaf in the extended range is not trusted.
        assert!(!cpuid_leaf_available(0x8000_0000, 0x8000_0008, 0x15));
    }

    #[test]
    fn line_round_trips() {
        let c = TimerCalibration {
            tsc_per_tick: 2_999_880,
            min: 2_990_111,
            max: 3_010_222,
            samples: 5,
            ticks: 100,
            tsc_hz: tsc_hz(2_999_880),
            virtualized: true,
            cpuid15: Leaf::Present((2, 1, 24_000_000)),
            cpuid16_mhz: Leaf::Present(2400),
            invariant: Some(true),
            fixture_stall: false,
        };
        let mut buf = [0u8; 256];
        let line = format_timer_calibration(&c, &mut buf).unwrap();
        assert_eq!(
            line,
            "TIMER CALIBRATION tsc_per_tick=2999880 min=2990111 max=3010222 samples=5 ticks=100 tsc_hz=3000336813 virtualized=yes cpuid15=2/1@24000000 cpuid16=2400MHz invariant=yes"
        );
        assert_eq!(parse_timer_calibration(line), Some(c));
        let absent = TimerCalibration {
            cpuid15: Leaf::Absent,
            cpuid16_mhz: Leaf::Zero,
            invariant: None,
            fixture_stall: true,
            ..c
        };
        let line = format_timer_calibration(&absent, &mut buf).unwrap();
        assert!(line.ends_with(" cpuid15=absent cpuid16=zero invariant=unknown fixture=stall"));
        assert_eq!(parse_timer_calibration(line), Some(absent));
        let zero = TimerCalibration {
            cpuid15: Leaf::Zero,
            ..c
        };
        let line = format_timer_calibration(&zero, &mut buf).unwrap();
        assert!(line.contains(" cpuid15=zero "));
        assert_eq!(parse_timer_calibration(line), Some(zero));
        let mut small = [0u8; 40];
        assert_eq!(format_timer_calibration(&c, &mut small), None);
        // The widest line any values can produce fits the stated maximum.
        let widest = TimerCalibration {
            tsc_per_tick: u64::MAX,
            min: u64::MAX,
            max: u64::MAX,
            samples: u64::MAX,
            ticks: u64::MAX,
            tsc_hz: u64::MAX,
            virtualized: false,
            cpuid15: Leaf::Present((u32::MAX, u32::MAX, u32::MAX)),
            cpuid16_mhz: Leaf::Present(u32::MAX),
            invariant: None,
            fixture_stall: true,
        };
        let mut exact = [0u8; TIMER_CALIBRATION_LINE_MAX];
        assert!(format_timer_calibration(&widest, &mut exact).is_some());
    }

    #[test]
    fn decoder_refuses_incomplete_or_foreign_lines() {
        assert_eq!(parse_timer_calibration("TIMER OK ticks=5"), None);
        assert_eq!(
            parse_timer_calibration("TIMER CALIBRATION tsc_per_tick=1 min=1"),
            None
        );
        assert_eq!(
            parse_timer_calibration(
                "TIMER CALIBRATION tsc_per_tick=1 min=1 max=1 samples=5 ticks=100 tsc_hz=1 virtualized=maybe cpuid15=absent cpuid16=absent invariant=no"
            ),
            None
        );
        assert_eq!(
            parse_timer_calibration(
                "TIMER CALIBRATION tsc_per_tick=1 min=1 max=1 samples=5 ticks=100 tsc_hz=1 virtualized=no cpuid15=absent cpuid16=absent invariant=no extra=1"
            ),
            None
        );
        // A missing mandatory field is not papered over by the fixture word.
        assert_eq!(
            parse_timer_calibration(
                "TIMER CALIBRATION tsc_per_tick=1 min=1 max=1 samples=5 ticks=100 tsc_hz=1 virtualized=no cpuid15=absent cpuid16=absent fixture=stall"
            ),
            None
        );
        // Repeated keys and unknown fixtures are refused.
        assert_eq!(
            parse_timer_calibration(
                "TIMER CALIBRATION tsc_per_tick=1 tsc_per_tick=1 min=1 max=1 samples=5 ticks=100 tsc_hz=1 virtualized=no cpuid15=absent cpuid16=absent invariant=no"
            ),
            None
        );
        assert_eq!(
            parse_timer_calibration(
                "TIMER CALIBRATION tsc_per_tick=1 min=1 max=1 samples=5 ticks=100 tsc_hz=1 virtualized=no cpuid15=absent cpuid16=absent invariant=no fixture=other"
            ),
            None
        );
    }
}

#[cfg(test)]
mod ata_identify_tests {
    use super::*;

    fn identify() -> [u16; 256] {
        let mut w = [0u16; 256];
        let put = |w: &mut [u16; 256], start: usize, count: usize, s: &str| {
            let mut bytes = [b' '; 64];
            bytes[..s.len()].copy_from_slice(s.as_bytes());
            for (i, pair) in bytes[..2 * count].chunks(2).enumerate() {
                w[start + i] = (u16::from(pair[0]) << 8) | u16::from(pair[1]);
            }
        };
        put(&mut w, 27, 20, "QEMU HARDDISK");
        put(&mut w, 10, 10, "QM00005");
        put(&mut w, 23, 4, "2.5+");
        w[83] = (0b01 << 14) | (1 << 10);
        w[100] = 0x1000;
        w[60] = 0xffff;
        w[61] = 0x0fff;
        w[217] = 1;
        w
    }

    #[test]
    fn strings_are_swapped_and_trimmed() {
        let (model, serial, firmware) = ata_identify_strings(&identify());
        assert_eq!(model, b"QEMU HARDDISK");
        assert_eq!(serial, b"QM00005");
        assert_eq!(firmware, b"2.5+");
    }

    #[test]
    fn sectors_follow_lba48_when_present() {
        let mut w = identify();
        assert!(ata_identify_lba48(&w));
        assert_eq!(ata_identify_sectors(&w), 0x1000);
        w[83] = 0;
        assert_eq!(ata_identify_sectors(&w), 0x0fff_ffff);
        // An invalid word 83 (bits 15:14 not 01) does not claim LBA48.
        w[83] = (0b11 << 14) | (1 << 10);
        assert!(!ata_identify_lba48(&w));
        assert!(!ata_identify_incomplete(&w));
        w[0] = 1 << 2;
        assert!(ata_identify_incomplete(&w));
    }

    #[test]
    fn sector_size_and_rotation_decode() {
        let mut w = identify();
        assert_eq!(ata_identify_logical_sector_bytes(&w), Some(512));
        w[106] = (1 << 14) | (1 << 12);
        w[117] = 2048;
        assert_eq!(ata_identify_logical_sector_bytes(&w), Some(4096));
        w[117] = 0xffff;
        w[118] = 0xffff;
        assert_eq!(ata_identify_logical_sector_bytes(&w), None);
        w[117] = 100;
        w[118] = 0;
        assert_eq!(ata_identify_logical_sector_bytes(&w), None);
        w[106] = (1 << 15) | (1 << 14) | (1 << 12);
        assert_eq!(ata_identify_logical_sector_bytes(&w), Some(512));
        assert_eq!(ata_identify_rotation(&w), Rotation::NonRotating);
        w[217] = 7200;
        assert_eq!(ata_identify_rotation(&w), Rotation::Rpm(7200));
        w[217] = 0;
        assert_eq!(ata_identify_rotation(&w), Rotation::Unknown);
    }
}

// ---------------------------------------------------------------------------
// AHCI port engine stop handling: what the census may do
// after it tried to stop a port's command engine (PxCMD.CR) and FIS receive
// (PxCMD.FR). Pure, host-tested, used by src/ahci.rs.

/// Whether a port's engines were shown quiescent, and if not, when.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AhciStop {
    /// CR and FR both read clear within the bound.
    Quiescent,
    /// The stop before IDENTIFY failed: the census never wrote the port's
    /// bases, and the engine still runs on the firmware's command list.
    FailedBeforeCommand,
    /// The stop after IDENTIFY failed: the engine may still own the census's
    /// static command list, FIS area and data buffer.
    FailedAfterCommand,
}

/// What the census does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AhciStopAction {
    /// Write the firmware's PxCLB/PxFB back.
    pub restore_bases: bool,
    /// Probe the controller's remaining ports.
    pub continue_controller: bool,
    /// Turn the function's bus mastering off before anything else.
    pub disable_bus_master_now: bool,
    /// Later IDENTIFYs (on any controller) may use the static buffers.
    pub buffers_reusable: bool,
}

/// Fail closed at controller level: an engine not shown quiescent ends that
/// controller's walk with bus mastering off at once. Bases are restored only
/// under a quiescent engine; after a failed post-command stop they are left
/// as they are, and the static buffers are retired for the rest of the census.
pub fn ahci_after_stop(stop: AhciStop) -> AhciStopAction {
    match stop {
        AhciStop::Quiescent => AhciStopAction {
            restore_bases: true,
            continue_controller: true,
            disable_bus_master_now: false,
            buffers_reusable: true,
        },
        AhciStop::FailedBeforeCommand => AhciStopAction {
            restore_bases: false,
            continue_controller: false,
            disable_bus_master_now: true,
            buffers_reusable: true,
        },
        AhciStop::FailedAfterCommand => AhciStopAction {
            restore_bases: false,
            continue_controller: false,
            disable_bus_master_now: true,
            buffers_reusable: false,
        },
    }
}

#[cfg(test)]
mod ahci_stop_tests {
    use super::*;

    #[test]
    fn only_a_quiescent_engine_continues_or_gets_its_bases_back() {
        let ok = ahci_after_stop(AhciStop::Quiescent);
        assert!(
            ok.restore_bases
                && ok.continue_controller
                && ok.buffers_reusable
                && !ok.disable_bus_master_now
        );
        for stop in [AhciStop::FailedBeforeCommand, AhciStop::FailedAfterCommand] {
            let action = ahci_after_stop(stop);
            assert!(!action.restore_bases, "{stop:?} restores bases");
            assert!(
                !action.continue_controller,
                "{stop:?} keeps probing the controller"
            );
            assert!(
                action.disable_bus_master_now,
                "{stop:?} leaves bus mastering on"
            );
        }
    }

    #[test]
    fn buffers_retire_only_after_the_engine_saw_them() {
        assert!(ahci_after_stop(AhciStop::FailedBeforeCommand).buffers_reusable);
        assert!(!ahci_after_stop(AhciStop::FailedAfterCommand).buffers_reusable);
    }
}
