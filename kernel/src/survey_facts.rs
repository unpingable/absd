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
