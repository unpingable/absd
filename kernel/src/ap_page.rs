//! Fixed SIPI-page admission. The first MiB remains allocator-reserved;
//! reservation alone does not establish usable RAM or firmware departure.
pub const PAGE: u32 = 0x7000;
const TOP: u64 = PAGE as u64 + 4096;
fn word(bytes: &[u8], offset: usize) -> Result<u32, &'static str> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or("bounds")?
            .try_into()
            .unwrap(),
    ))
}
fn quad(bytes: &[u8], offset: usize) -> Result<u64, &'static str> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or("bounds")?
            .try_into()
            .unwrap(),
    ))
}
fn overlaps(start: u64, end: u64) -> bool {
    start < TOP && u64::from(PAGE) < end
}

/// All inputs are observations from the same boot. The caller continues to
/// reserve the admitted page until machine termination; this copies no bytes.
pub fn validate(
    info: &[u8],
    info_address: u64,
    kernel: (u64, u64),
    ebda_segment: u16,
) -> Result<u32, &'static str> {
    if info.len() < 16 || word(info, 0)? as usize != info.len() || word(info, 4)? != 0 {
        return Err("bounds");
    }
    if overlaps(
        info_address,
        info_address
            .checked_add(info.len() as u64)
            .ok_or("bounds")?,
    ) || kernel.0 >= kernel.1
        || overlaps(kernel.0, kernel.1)
    {
        return Err("boot-overlap");
    }
    let mut usable = false;
    let mut memory_map = false;
    let mut efi_system = false;
    let mut efi_map = false;
    let mut ended = false;
    let mut offset = 8usize;
    while offset.checked_add(8).is_some_and(|end| end <= info.len()) {
        let kind = word(info, offset)?;
        let size = word(info, offset + 4)? as usize;
        if size < 8 {
            return Err("bounds");
        }
        let tag = info
            .get(offset..offset.checked_add(size).ok_or("bounds")?)
            .ok_or("bounds")?;
        if kind == 0 {
            if size != 8 || offset + 8 != info.len() {
                return Err("bounds");
            }
            ended = true;
            break;
        }
        match kind {
            3 => {
                let start = u64::from(word(tag, 8)?);
                let end = u64::from(word(tag, 12)?);
                if start > end || overlaps(start, end) {
                    return Err("module-overlap");
                }
            }
            6 => {
                if memory_map {
                    return Err("memory-map");
                }
                memory_map = true;
                let stride = word(tag, 8)? as usize;
                if size < 16
                    || stride < 24
                    || word(tag, 12)? != 0
                    || !(size - 16).is_multiple_of(stride)
                {
                    return Err("memory-map");
                }
                for row in tag[16..].chunks_exact(stride) {
                    let base = quad(row, 0)?;
                    let end = base.checked_add(quad(row, 8)?).ok_or("memory-map")?;
                    let entry_kind = word(row, 16)?;
                    if base <= u64::from(PAGE) && TOP <= end && entry_kind == 1 {
                        usable = true;
                    } else if entry_kind != 1 && overlaps(base, end) {
                        return Err("reserved-overlap");
                    }
                }
            }
            11 | 12 => {
                // Exactly one EFI system-table tag, of its defined width.
                if efi_system || size != if kind == 11 { 12 } else { 16 } {
                    return Err("efi-handoff");
                }
                let address = if kind == 11 {
                    u64::from(word(tag, 8)?)
                } else {
                    quad(tag, 8)?
                };
                if address == 0 {
                    return Err("efi-handoff");
                }
                efi_system = true;
            }
            17 => {
                // Validate descriptor framing, without promoting EFI memory
                // types into RAM authority. Tag 6 must still admit the page.
                let stride = word(tag, 8)? as usize;
                if efi_map
                    || size <= 16
                    || stride < 40
                    || !stride.is_multiple_of(8)
                    || word(tag, 12)? != 1
                    || !(size - 16).is_multiple_of(stride)
                {
                    return Err("efi-handoff");
                }
                for row in tag[16..].chunks_exact(stride) {
                    let base = quad(row, 8)?;
                    let length = quad(row, 24)?.checked_mul(4096).ok_or("efi-handoff")?;
                    let end = base.checked_add(length).ok_or("efi-handoff")?;
                    // A contradictory handoff cannot erase a firmware-owned
                    // region. Only loader, boot-services or conventional
                    // memory is reusable after ExitBootServices (UEFI 2.10,
                    // table 7.6); runtime attributes remain excluded.
                    if overlaps(base, end)
                        && (!matches!(word(row, 0)?, 1..=4 | 7) || quad(row, 32)? & (1 << 63) != 0)
                    {
                        return Err("efi-reserved-overlap");
                    }
                }
                efi_map = true;
            }
            // Multiboot2 section 3.6.20: presence means boot services have
            // NOT terminated. Absence is required before admitting any AP.
            18 => return Err("efi-boot-services"),
            _ => {}
        }
        offset = offset
            .checked_add(size.checked_add(7).ok_or("bounds")? & !7)
            .ok_or("bounds")?;
    }
    if !ended {
        return Err("bounds");
    }
    if efi_system != efi_map {
        return Err("efi-handoff");
    }
    let ebda_start = u64::from(ebda_segment) * 16;
    // Legacy BIOS still requires its EBDA bound. EFI may omit the BDA,
    // but only a complete, unambiguous exited handoff permits that absence.
    if (ebda_start == 0 && !efi_system) || (ebda_start != 0 && TOP > ebda_start) {
        return Err("ebda");
    }
    if !usable {
        return Err("not-usable");
    }
    Ok(PAGE)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{vec, vec::Vec};
    // Exact diagnostic-03 OVMF/GRUB handoff, 8432 bytes, MBI physical 0x50000.
    // SHA256 b8c82ddddbd7fce35f4b0e15a07dd3f804ccb6e2ba36996b8a83feda1600e6ed.
    // BDA 0x40e and 0x413 were both zero. Allocated ELF section bounds below.
    fn captured() -> Vec<u8> {
        include_str!("../tests/fixtures/smp-operator-ovmf-multiboot.hex")
            .split_ascii_whitespace()
            .flat_map(|line| {
                (0..line.len())
                    .step_by(2)
                    .map(move |i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
            })
            .collect()
    }
    const KERNEL: (u64, u64) = (0x100000, 0x6c60d4);
    fn check(info: &[u8], ebda: u16) -> Result<u32, &'static str> {
        validate(info, 0x50000, KERNEL, ebda)
    }
    fn tags(info: &[u8]) -> Vec<Vec<u8>> {
        crate::survey_facts::tags(info)
            .map(|(_, b)| b.to_vec())
            .collect()
    }
    fn pack(tags: Vec<Vec<u8>>) -> Vec<u8> {
        let mut info = vec![0; 8];
        for tag in tags {
            info.extend(tag);
            info.resize(info.len().next_multiple_of(8), 0);
        }
        info.extend([0, 0, 0, 0, 8, 0, 0, 0]);
        let size = info.len() as u32;
        info[..4].copy_from_slice(&size.to_le_bytes());
        info
    }
    fn tag(kind: u32, body: &[u8]) -> Vec<u8> {
        let mut tag = kind.to_le_bytes().to_vec();
        tag.extend(((8 + body.len()) as u32).to_le_bytes());
        tag.extend(body);
        tag
    }
    fn replace(info: &[u8], kind: u32, replacement: Option<Vec<u8>>) -> Vec<u8> {
        let mut all = tags(info);
        all.retain(|t| word(t, 0).unwrap() != kind);
        if let Some(t) = replacement {
            all.push(t);
        }
        pack(all)
    }
    fn map(rows: &[(u64, u64, u32)]) -> Vec<u8> {
        let mut body = 24u32.to_le_bytes().to_vec();
        body.extend(0u32.to_le_bytes());
        for &(base, length, kind) in rows {
            body.extend(base.to_le_bytes());
            body.extend(length.to_le_bytes());
            body.extend(kind.to_le_bytes());
            body.extend(0u32.to_le_bytes());
        }
        tag(6, &body)
    }
    #[test]
    fn captured_ovmf_handoff_with_absent_legacy_ebda_is_admitted() {
        let info = captured();
        assert_eq!(info.len(), 8432);
        assert_eq!(check(&info, 0), Ok(PAGE));
    }
    #[test]
    fn bios_still_requires_ebda_and_excludes_its_range() {
        let bios = pack(vec![map(&[(0, 0xa0000, 1)])]);
        assert_eq!(check(&bios, 0x9fc0), Ok(PAGE));
        assert_eq!(check(&bios, 0), Err("ebda"));
        assert_eq!(check(&bios, 0x7ff), Err("ebda"));
        assert_eq!(check(&bios, 0x800), Ok(PAGE));
        assert_eq!(check(&captured(), 0x7ff), Err("ebda"));
    }
    #[test]
    fn efi_requires_unambiguous_well_formed_exited_handoff() {
        let info = captured();
        for kind in [12, 17] {
            assert!(check(&replace(&info, kind, None), 0).is_err());
        }
        for extra in [
            tag(18, &[]),
            tag(11, &1u32.to_le_bytes()),
            tags(&info)
                .into_iter()
                .find(|t| word(t, 0) == Ok(12))
                .unwrap(),
            tags(&info)
                .into_iter()
                .find(|t| word(t, 0) == Ok(17))
                .unwrap(),
        ] {
            let mut all = tags(&info);
            all.push(extra);
            let bad = pack(all);
            assert!(check(&bad, 0x9fc0).is_err());
            assert!(check(&bad, 0).is_err());
        }
        for body in [vec![], vec![0; 8], vec![1; 4], vec![1; 16]] {
            assert!(check(&replace(&info, 12, Some(tag(12, &body))), 0x9fc0).is_err());
        }
        let original = tags(&info)
            .into_iter()
            .find(|t| word(t, 0) == Ok(17))
            .unwrap();
        for (at, value) in [(8, 0u32), (8, 32), (12, 0)] {
            let mut bad = original.clone();
            bad[at..at + 4].copy_from_slice(&value.to_le_bytes());
            assert!(check(&replace(&info, 17, Some(bad)), 0x9fc0).is_err());
        }
    }
    #[test]
    fn efi_reclaimability_never_overrides_ram_or_runtime_exclusions() {
        let info = captured();
        assert!(check(&replace(&info, 6, None), 0).is_err());
        let original = tags(&info)
            .into_iter()
            .find(|t| word(t, 0) == Ok(17))
            .unwrap();
        let row = 16 + word(&original, 8).unwrap() as usize;
        assert_eq!(quad(&original, row + 8), Ok(0x1000));
        for kind in [0u32, 5, 6, 9, 10, 11, 12] {
            let mut bad = original.clone();
            bad[row..row + 4].copy_from_slice(&kind.to_le_bytes());
            assert_eq!(
                check(&replace(&info, 17, Some(bad)), 0),
                Err("efi-reserved-overlap")
            );
        }
        let mut runtime = original.clone();
        runtime[row + 32..row + 40].copy_from_slice(&(1u64 << 63).to_le_bytes());
        assert_eq!(
            check(&replace(&info, 17, Some(runtime)), 0),
            Err("efi-reserved-overlap")
        );
        for field in [row + 8, row + 24] {
            let mut overflow = original.clone();
            overflow[field..field + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            assert!(check(&replace(&info, 17, Some(overflow)), 0).is_err());
        }
    }
    #[test]
    fn complete_usable_page_and_all_reserved_overlaps_are_required() {
        let info = captured();
        for rows in [
            vec![],
            vec![(0, 0x7fff, 1)],
            vec![(0x7001, 0x1000, 1)],
            vec![(0x7000, 0x1000, 2)],
            vec![(0, 0xa0000, 1), (0x7fff, 1, 2)],
            vec![(u64::MAX, 2, 1)],
        ] {
            assert!(check(&replace(&info, 6, Some(map(&rows))), 0x9fc0).is_err());
        }
        assert_eq!(
            check(
                &replace(&info, 6, Some(map(&[(0x7000, 0x1000, 1), (0x8000, 1, 2)]))),
                0x9fc0
            ),
            Ok(PAGE)
        );
        let mut all = tags(&info);
        all.push(map(&[(0, 0xa0000, 1)]));
        assert!(check(&pack(all), 0x9fc0).is_err());
    }
    #[test]
    fn boot_owned_spans_remain_excluded() {
        let info = captured();
        assert!(validate(&info, 0x7000, KERNEL, 0x9fc0).is_err());
        assert!(validate(&info, u64::MAX - 10, KERNEL, 0x9fc0).is_err());
        assert!(validate(&info, 0x50000, (0x7fff, 0x9000), 0x9fc0).is_err());
        for (start, end) in [(0x7000u32, 0x8000u32), (0x7fff, 0x8001), (0x8000, 0x7000)] {
            let mut body = start.to_le_bytes().to_vec();
            body.extend(end.to_le_bytes());
            body.push(0);
            assert!(check(&replace(&info, 3, Some(tag(3, &body))), 0x9fc0).is_err());
        }
    }
    #[test]
    fn malformed_handoff_cannot_hide_a_later_exclusion() {
        let info = captured();
        for length in [0, 7, 8, info.len() - 1, info.len() - 8] {
            assert!(check(&info[..length], 0x9fc0).is_err());
        }
        let mut bad = info.clone();
        bad[..4].copy_from_slice(&16u32.to_le_bytes());
        assert!(check(&bad, 0x9fc0).is_err());
        let mut bad = info.clone();
        bad[12..16].copy_from_slice(&0u32.to_le_bytes());
        assert!(check(&bad, 0x9fc0).is_err());
        let mut malformed_map = map(&[(0, 0xa0000, 1)]);
        malformed_map[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert!(check(&replace(&info, 6, Some(malformed_map)), 0x9fc0).is_err());
    }
}
