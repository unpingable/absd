//! Host tests for the first AMD-Vi domain's encodings and decisions.

extern crate std;
use super::*;
use crate::ivrs::{self, Entries, Error};
use std::boxed::Box;
use std::collections::BTreeMap;
use std::vec;
use std::vec::Vec;

// --- IVRS fixtures ----------------------------------------------------------

fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

fn table(revision: u8, ivinfo: u32, blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"IVRS".to_vec();
    out.extend_from_slice(&[0; 4]);
    out.push(revision);
    out.push(0);
    out.extend_from_slice(b"ABSD  SYNTHIVR");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(b"ABSD");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&ivinfo.to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    for block in blocks {
        out.extend_from_slice(block);
    }
    let length = out.len() as u32;
    out[4..8].copy_from_slice(&length.to_le_bytes());
    out[9] = 0u8.wrapping_sub(checksum(&out));
    out
}

#[allow(clippy::too_many_arguments)]
fn ivhd(
    kind: u8,
    flags: u8,
    devid: u16,
    base: u64,
    word: u32,
    efr: u64,
    entries: &[u8],
) -> Vec<u8> {
    let header = if kind == 0x10 { 24 } else { 40 };
    let mut out = vec![kind, flags];
    out.extend_from_slice(&((header + entries.len()) as u16).to_le_bytes());
    out.extend_from_slice(&devid.to_le_bytes());
    out.extend_from_slice(&0x40u16.to_le_bytes());
    out.extend_from_slice(&base.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&word.to_le_bytes());
    if header == 40 {
        out.extend_from_slice(&efr.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
    }
    out.extend_from_slice(entries);
    out
}

fn select(devid: u16) -> Vec<u8> {
    let id = devid.to_le_bytes();
    vec![2, id[0], id[1], 0]
}

fn ioapic(handle: u8, source: u16) -> Vec<u8> {
    let s = source.to_le_bytes();
    vec![0x48, 0, 0, 0, handle, s[0], s[1], 1]
}

/// QEMU 10.2.1's own table for q35 + amd-iommu, observed on execution_host
/// (corrective evidence `inc3/qemu-10.2.1-ivrs/`), with an `edu` function
/// at 00:05.0 added to the device list as QEMU lists every present
/// function: IVinfo EFRSup | PAsize 40; 10h flags d1h, feature 44h; 11h
/// flags 11h, attributes 0, EFR image 29d3h.
const QEMU_EFR: u64 = 0x29d3;
const QEMU_IOMMU: u16 = 0x0010;
const EDU: u16 = 0x0028;

fn qemu_10_2_1(edu: bool) -> Vec<u8> {
    let mut ids = vec![0x0000, 0x0008, QEMU_IOMMU];
    if edu {
        ids.push(EDU);
    }
    ids.extend([0x00f8, 0x00fa, 0x00fb]);
    let mut entries: Vec<u8> = ids.into_iter().flat_map(select).collect();
    entries.extend(ioapic(0, 0x00a0));
    table(
        1,
        0x2801,
        &[
            ivhd(0x10, 0xd1, QEMU_IOMMU, 0xfed8_0000, 0x44, 0, &entries),
            ivhd(0x11, 0x11, QEMU_IOMMU, 0xfed8_0000, 0, QEMU_EFR, &entries),
        ],
    )
}

fn parse(bytes: &[u8]) -> (Result<Validation, Error>, Box<Unit>) {
    let mut unit = Box::new(Unit::EMPTY);
    let mut scratch = Box::new(Entries::EMPTY);
    let result = ivrs::parse(bytes, &mut unit, &mut scratch);
    (result, unit)
}

/// QEMU's capability header: EFRSup (bit 27) set.
const QEMU_CAP: u32 = 0x1f03_000f;
const LIVE_QEMU: Live = Live {
    cap_header: QEMU_CAP,
    efr: QEMU_EFR,
    counters: None,
};

#[test]
fn the_observed_qemu_10_2_1_table_matches_the_fixture() {
    // The bytes dumped from QEMU 10.2.1 (no edu): same blocks as the
    // fixture without edu, apart from the OEM fields.
    let observed: [u8; 176] = [
        0x49, 0x56, 0x52, 0x53, 0xb0, 0x00, 0x00, 0x00, 0x01, 0x74, 0x42, 0x4f, 0x43, 0x48, 0x53,
        0x20, 0x42, 0x58, 0x50, 0x43, 0x20, 0x20, 0x20, 0x20, 0x01, 0x00, 0x00, 0x00, 0x42, 0x58,
        0x50, 0x43, 0x01, 0x00, 0x00, 0x00, 0x01, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x10, 0xd1, 0x38, 0x00, 0x10, 0x00, 0x40, 0x00, 0x00, 0x00, 0xd8, 0xfe,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x02, 0x08, 0x00, 0x00, 0x02, 0x10, 0x00, 0x00, 0x02, 0xf8, 0x00, 0x00, 0x02, 0xfa,
        0x00, 0x00, 0x02, 0xfb, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x01, 0x11,
        0x11, 0x48, 0x00, 0x10, 0x00, 0x40, 0x00, 0x00, 0x00, 0xd8, 0xfe, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd3, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x08,
        0x00, 0x00, 0x02, 0x10, 0x00, 0x00, 0x02, 0xf8, 0x00, 0x00, 0x02, 0xfa, 0x00, 0x00, 0x02,
        0xfb, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x01,
    ];
    let fixture = qemu_10_2_1(false);
    assert_eq!(&observed[36..], &fixture[36..]);
    let (result, unit) = parse(&observed);
    assert_eq!(result.unwrap().deviations, 1);
    assert_eq!(
        admit_table(&unit, &result.unwrap(), &LIVE_QEMU),
        Ok(TableAdmission { quirked: 1 })
    );
}

// --- Device table entries ---------------------------------------------------

#[test]
fn device_table_entries_are_bit_exact() {
    // Blocked: V=1, TV=0 (Mode, root zero); IR=IW=0; DomainID; IV=1,
    // IntCtl=00b (or IV=0 for special sources).
    assert_eq!(dte_blocked(0, Interrupts::Abort), [1, 0, 1, 0]);
    assert_eq!(dte_blocked(7, Interrupts::Pass), [1, 7, 0, 0]);
    let entry = dte_translated(DOMAIN, 0x0012_3000, 0x0045_6000);
    assert_eq!(entry[0] & 0b11, 0b11);
    assert_eq!((entry[0] >> 9) & 7, 3, "Mode 011b");
    assert_eq!(entry[0] & 0x000f_ffff_ffff_f000, 0x0012_3000);
    assert_eq!(entry[0] >> 61 & 3, 0b11, "IR, IW");
    assert_eq!(entry[0] & (1 << 63), 0, "reserved bit 63");
    assert_eq!(entry[0] & (0b11 << 2), 0, "reserved bits 3:2");
    assert_eq!(
        entry[0] & (0x1ff << 52),
        0,
        "PPR, GPRP, GIoV, GV, GLX, GCR3 clear"
    );
    assert_eq!(
        entry[1],
        u64::from(DOMAIN),
        "I, SE, SA, IoCtl, Cache... clear"
    );
    // Interrupts: IV=1, IntTabLen 1001b (512), root 0x456000 in bits 51:6,
    // IG=0, IntCtl=10b, every pass bit clear.
    assert_eq!(entry[2], 1 | (0b1001 << 1) | 0x0045_6000 | (0b10 << 60));
    assert_eq!(entry[2] & DTE_PASS_BITS, 0);
    assert_eq!(entry[3], 0);
}

#[test]
fn every_initial_entry_is_blocked_the_target_included() {
    let (_, unit) = parse(&qemu_10_2_1(true));
    for devid in 0..=u16::MAX {
        let entry = dte_initial(&unit, devid);
        if devid == 0x00a0 {
            assert_eq!(entry, dte_blocked(BLOCKED_DOMAIN, Interrupts::Pass));
        } else {
            assert_eq!(
                entry,
                dte_blocked(BLOCKED_DOMAIN, Interrupts::Abort),
                "{devid:#x}"
            );
        }
        // V=1 (never untranslated pass-through), TV=0, IR=IW=0.
        assert_eq!(entry[0] & 0b11, 0b01);
        assert_eq!(entry[0] >> 61 & 3, 0);
    }
}

// --- Page tables ------------------------------------------------------------

#[derive(Default)]
struct Memory {
    pages: BTreeMap<u64, Box<[u64; 512]>>,
    next: u64,
    limit: usize,
}

impl Tables for Memory {
    fn allocate(&mut self) -> Option<u64> {
        if self.limit != 0 && self.pages.len() == self.limit {
            return None;
        }
        self.next += PAGE;
        let address = 0x10_0000_0000 + self.next;
        self.pages.insert(address, Box::new([0; 512]));
        Some(address)
    }
    fn read(&self, table: u64, index: usize) -> u64 {
        self.pages[&table][index]
    }
    fn write(&mut self, table: u64, index: usize, value: u64) {
        self.pages.get_mut(&table).unwrap()[index] = value;
    }
}

#[test]
fn only_granted_pages_translate_with_their_permissions() {
    let mut memory = Memory::default();
    let root = memory.allocate().unwrap();
    let grant = [
        (0x0020_0000, Perm::READ),
        (0x0020_1000, Perm::WRITE),
        (0x0400_0000, Perm::READ_WRITE),
    ];
    for &(page, perm) in &grant {
        map(&mut memory, root, page, page, perm).unwrap();
    }
    for &(page, perm) in &grant {
        assert_eq!(translate(&memory, root, page), Some((page, perm)));
        assert_eq!(translate(&memory, root, page + 0xfff), Some((page, perm)));
    }
    for iova in [
        0,
        0x001f_f000,
        0x0020_2000,
        0x03ff_f000,
        0x0400_1000,
        1 << 38,
        IOVA_LIMIT,
    ] {
        assert_eq!(translate(&memory, root, iova), None, "{iova:#x}");
    }
    // Root, one level-2 and two level-1 tables: 0x200000 and 0x4000000 share
    // a level-2 table (both below 1 GiB) but not a level-1 table.
    assert_eq!(memory.pages.len(), 4);
    // Entries are bit-exact: PDE NextLevel, leaf NextLevel 0, FC=0.
    let l2 = memory.read(root, 0);
    assert_eq!((l2 >> 9) & 7, 2);
    assert_eq!(l2 & 1, 1);
    let l1 = memory.read(l2 & 0x000f_ffff_ffff_f000, index(0x0020_0000, 2));
    assert_eq!((l1 >> 9) & 7, 1);
    let leaf = memory.read(l1 & 0x000f_ffff_ffff_f000, index(0x0020_1000, 1));
    assert_eq!(leaf, 1 | 0x0020_1000 | (1 << 62));
    // Refusals.
    assert_eq!(
        map(&mut memory, root, 0x0020_0000, 0x0020_0000, Perm::READ),
        Err(MapError::Mapped)
    );
    assert_eq!(
        map(&mut memory, root, 0x0020_0800, 0x0020_0800, Perm::READ),
        Err(MapError::Unaligned)
    );
    assert_eq!(
        map(&mut memory, root, IOVA_LIMIT, 0x1000, Perm::READ),
        Err(MapError::OutOfRange)
    );
    let mut full = Memory {
        limit: 1,
        ..Memory::default()
    };
    let root = full.allocate().unwrap();
    assert_eq!(
        map(&mut full, root, 0x1000, 0x1000, Perm::READ),
        Err(MapError::NoTable)
    );
}

#[test]
fn level_indices_follow_table_15() {
    let iova = (0x1a5 << 30) | (0x0c3 << 21) | (0x17f << 12) | 0x123;
    assert_eq!(
        (index(iova, 3), index(iova, 2), index(iova, 1)),
        (0x1a5, 0x0c3, 0x17f)
    );
}

#[test]
fn grants_are_checked() {
    let reach = 1 << 28;
    let ok = [(0x0010_0000, Perm::READ), (0x0010_1000, Perm::WRITE)];
    assert_eq!(check_grant(&ok, reach, &[]), Ok(()));
    assert_eq!(check_grant(&[], reach, &[]), Err(GrantError::Empty));
    let many: Vec<(u64, Perm)> = (1..=MAX_GRANT as u64 + 1)
        .map(|n| (n * PAGE, Perm::READ))
        .collect();
    assert_eq!(check_grant(&many, reach, &[]), Err(GrantError::TooMany));
    assert_eq!(
        check_grant(&[(0x1800, Perm::READ)], reach, &[]),
        Err(GrantError::Unaligned(0x1800))
    );
    assert_eq!(
        check_grant(&[(0, Perm::READ)], reach, &[]),
        Err(GrantError::Forbidden(0))
    );
    assert_eq!(
        check_grant(&[(reach, Perm::READ)], reach, &[]),
        Err(GrantError::Forbidden(reach))
    );
    for page in [MSI_START, MSI_END - PAGE, IOVA_LIMIT - PAGE + PAGE] {
        assert_eq!(
            check_grant(&[(page, Perm::READ)], 1 << 40, &[]),
            Err(GrantError::Forbidden(page)),
            "{page:#x}"
        );
    }
    assert_eq!(check_grant(&[(MSI_END, Perm::READ)], 1 << 40, &[]), Ok(()));
    assert_eq!(
        check_grant(
            &[(
                0x5000,
                Perm {
                    read: false,
                    write: false
                }
            )],
            reach,
            &[]
        ),
        Err(GrantError::Forbidden(0x5000))
    );
    assert_eq!(
        check_grant(&[(0x5000, Perm::READ)], reach, &[(0x4000, 0x6000)]),
        Err(GrantError::Reserved(0x5000))
    );
    assert_eq!(
        check_grant(&[(0x5000, Perm::READ), (0x5000, Perm::WRITE)], reach, &[]),
        Err(GrantError::Duplicate(0x5000))
    );
}

// --- Commands and events ----------------------------------------------------

#[test]
fn commands_are_bit_exact() {
    assert_eq!(
        completion_wait(0x0012_3458, 0x1122_3344_5566_7788),
        [0x0012_3458 | 0b101, 0x1000_0000, 0x5566_7788, 0x1122_3344]
    );
    assert_eq!(completion_wait(0x0000_0001_0000_0000, 0)[1], 0x1000_0001);
    assert_eq!(invalidate_devtab(0x0028), [0x28, 0x2000_0000, 0, 0]);
    assert_eq!(
        invalidate_domain(1),
        [0, 0x3000_0001, 0xffff_f003, 0x7fff_ffff]
    );
    assert_eq!(
        invalidate_page(1, 0x0020_1000),
        [0, 0x3000_0001, 0x0020_1002, 0]
    );
    assert_eq!(invalidate_all(), [0, 0x8000_0000, 0, 0]);
}

#[test]
fn events_decode() {
    let fault = [
        0x0028,
        (0b0010 << 28) | (1 << 21) | (1 << 20) | 0x0001,
        0xdead_b000,
        0,
    ];
    assert_eq!(
        Event::decode(fault),
        Event::IoPageFault {
            devid: 0x28,
            domain: 1,
            address: 0xdead_b000,
            write: true,
            permission: false,
            present: true,
            interrupt: false
        }
    );
    assert_eq!(
        Event::decode([0x10, 1 << 28, 0x1007, 1]),
        Event::IllegalDevTableEntry {
            devid: 0x10,
            address: 0x1_0000_1004
        }
    );
    assert!(matches!(
        Event::decode([0, 0x5000_0000, 0, 0]),
        Event::Other { code: 5, .. }
    ));
}

// --- Admission ----------------------------------------------------------------

#[test]
fn qemu_10_2_1_is_admitted_only_under_its_quirk_and_live_registers() {
    let bytes = qemu_10_2_1(true);
    let (result, unit) = parse(&bytes);
    let validation = result.unwrap();
    assert_eq!(validation.deviations, 1);
    assert_eq!(
        admit_table(&unit, &validation, &LIVE_QEMU),
        Ok(TableAdmission { quirked: 1 })
    );
    let finding = &unit.findings.items()[0];
    assert_eq!(
        quirk_for(&unit, finding, &LIVE_QEMU).map(|q| q.name),
        Some("qemu-superseded-10h-hats")
    );
    // Live HATS other than the image's: the quirk does not apply, and the
    // consumed-field agreement fails first.
    let live = Live {
        efr: QEMU_EFR & !(3 << 10),
        ..LIVE_QEMU
    };
    assert_eq!(
        admit_table(&unit, &validation, &live),
        Err(TableRefusal::EfrMismatch)
    );
    for efr in [
        QEMU_EFR & !EFR_IA_SUP,
        QEMU_EFR | (1 << 9),
        QEMU_EFR | EFR_PERF_OPT_SUP,
    ] {
        let live = Live { efr, ..LIVE_QEMU };
        assert_eq!(
            admit_table(&unit, &validation, &live),
            Err(TableRefusal::EfrMismatch),
            "{efr:#x}"
        );
    }
    // The capability header must agree on EFRSup.
    let live = Live {
        cap_header: QEMU_CAP & !(1 << 27),
        ..LIVE_QEMU
    };
    assert_eq!(
        admit_table(&unit, &validation, &live),
        Err(TableRefusal::EfrSupMismatch)
    );
    // Unrelated EFR bits do not matter (not consumed).
    let live = Live {
        efr: QEMU_EFR | (1 << 40),
        ..LIVE_QEMU
    };
    assert!(admit_table(&unit, &validation, &live).is_ok());
}

#[test]
fn the_quirk_covers_exactly_its_deviation() {
    let quirk = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut bytes = qemu_10_2_1(true);
        edit(&mut bytes);
        bytes[9] = 0;
        bytes[9] = 0u8.wrapping_sub(checksum(&bytes));
        let (result, unit) = parse(&bytes);
        result.map(|validation| admit_table(&unit, &validation, &LIVE_QEMU))
    };
    // 10h HATS 01b instead of 00b: a different disagreement, uncovered.
    assert_eq!(
        quirk(&|b| b[48 + 23] |= 0x40),
        Ok(Err(TableRefusal::Uncovered(0)))
    );
    // A second deviation beside the covered one: refused at the second.
    assert_eq!(quirk(&|b| b[44] = 1), Ok(Err(TableRefusal::Uncovered(0))));
    // No deviation at all (10h HATS fixed to 10b): admitted, nothing quirked.
    assert_eq!(
        quirk(&|b| b[48 + 23] |= 0x80),
        Ok(Ok(TableAdmission { quirked: 0 }))
    );
}

#[test]
fn qemu_8_2_2_is_refused_on_efrsup() {
    // 10h only, IVinfo EFRSup clear, feature field 44h (reserved).
    let bytes = table(
        1,
        0x2800,
        &[ivhd(
            0x10,
            0xd1,
            0x0008,
            0xfed8_0000,
            0x44,
            0,
            &[select(0x0008), select(EDU)].concat(),
        )],
    );
    let (result, unit) = parse(&bytes);
    let validation = result.unwrap();
    assert_eq!(
        admit_table(
            &unit,
            &validation,
            &Live {
                cap_header: QEMU_CAP,
                efr: 0,
                counters: None,
            }
        ),
        Err(TableRefusal::EfrSupMismatch)
    );
}

#[test]
fn the_alias_closure_rule() {
    let (_, unit) = parse(&qemu_10_2_1(true));
    assert_eq!(admit_device(&unit, EDU), Ok(()));
    assert_eq!(admit_device(&unit, QEMU_IOMMU), Err(DeviceRefusal::Iommu));
    assert_eq!(admit_device(&unit, 0x0030), Err(DeviceRefusal::Undescribed));
    // A special source is never admitted.
    let bytes = table(
        1,
        0x2801,
        &[ivhd(
            0x10,
            0xd1,
            QEMU_IOMMU,
            0xfed8_0000,
            0x8000_0044,
            0,
            &[select(EDU), select(0x0030), ioapic(0, EDU)].concat(),
        )],
    );
    let (_, unit) = parse(&bytes);
    assert_eq!(admit_device(&unit, EDU), Err(DeviceRefusal::SpecialSource));
    assert_eq!(admit_device(&unit, 0x0030), Ok(()));
    // Another function aliasing onto the device: shared requester ID.
    let alias = |first: u16, target: u16| {
        let f = first.to_le_bytes();
        let t = target.to_le_bytes();
        vec![0x42, f[0], f[1], 0, 0, t[0], t[1], 0]
    };
    let bytes = table(
        1,
        0x2801,
        &[ivhd(
            0x10,
            0xd1,
            QEMU_IOMMU,
            0xfed8_0000,
            0x8000_0044,
            0,
            &[select(EDU), alias(0x0100, EDU)].concat(),
        )],
    );
    let (_, unit) = parse(&bytes);
    assert_eq!(
        admit_device(&unit, EDU),
        Err(DeviceRefusal::SharedRequester(0x0100))
    );
    assert_eq!(
        admit_device(&unit, 0x0100),
        Err(DeviceRefusal::Aliased(EDU))
    );
    // The tolerated tail alias: its bus and its target are excluded, the
    // rest of the range is not.
    let range = |first: u16, last: u16| {
        let f = first.to_le_bytes();
        let l = last.to_le_bytes();
        vec![3, f[0], f[1], 0, 4, l[0], l[1], 0]
    };
    let alias_range = |first: u16, last: u16, target: u16| {
        let f = first.to_le_bytes();
        let l = last.to_le_bytes();
        let t = target.to_le_bytes();
        vec![0x43, f[0], f[1], 0, 0, t[0], t[1], 0, 4, l[0], l[1], 0]
    };
    let bytes = table(
        1,
        0x2801,
        &[ivhd(
            0x10,
            0xd1,
            0x0002,
            0xfed8_0000,
            0x8000_0044,
            0,
            &[range(0x0018, 0x7ffe), alias_range(0x7f00, 0x7fff, 0x0040)].concat(),
        )],
    );
    let (result, unit) = parse(&bytes);
    assert_eq!(result.unwrap().deviations, 1);
    assert_eq!(admit_device(&unit, 0x0100), Ok(()));
    for devid in [0x7f00, 0x7f10, 0x7fff, 0x0040] {
        assert_eq!(
            admit_device(&unit, devid),
            Err(DeviceRefusal::TouchesToleratedAlias),
            "{devid:#x}"
        );
    }
}

#[test]
fn a_revoked_page_stops_translating_and_the_rest_stay() {
    let mut memory = Memory::default();
    let root = memory.allocate().unwrap();
    let grant = [
        (0x0020_0000, Perm::READ),
        (0x0020_1000, Perm::WRITE),
        (0x0020_2000, Perm::WRITE),
    ];
    for &(page, perm) in &grant {
        map(&mut memory, root, page, page, perm).unwrap();
    }
    assert_eq!(unmap(&mut memory, root, 0x0020_1000), Ok(()));
    assert_eq!(translate(&memory, root, 0x0020_1000), None);
    assert_eq!(
        translate(&memory, root, 0x0020_0000),
        Some((0x0020_0000, Perm::READ))
    );
    assert_eq!(
        translate(&memory, root, 0x0020_2000),
        Some((0x0020_2000, Perm::WRITE))
    );
    assert_eq!(
        unmap(&mut memory, root, 0x0020_1000),
        Err(MapError::NotMapped)
    );
    assert_eq!(
        unmap(&mut memory, root, 0x4000_0000),
        Err(MapError::NotMapped)
    );
    assert_eq!(
        unmap(&mut memory, root, 0x0020_0800),
        Err(MapError::Unaligned)
    );
    // An empty root (the blocked domain) translates nothing.
    let empty = memory.allocate().unwrap();
    for iova in [0, 0x0020_0000, 0x0020_1000] {
        assert_eq!(translate(&memory, empty, iova), None);
    }
}

#[test]
fn perf_opt_sup_must_agree_both_ways() {
    // Image with PerfOptSup, live without: refused.
    let mut bytes = qemu_10_2_1(true);
    let efr_at = 48 + 24 + 7 * 4 + 8 + 24;
    let image = u64::from_le_bytes(bytes[efr_at..efr_at + 8].try_into().unwrap());
    assert_eq!(image, QEMU_EFR, "fixture layout");
    bytes[efr_at..efr_at + 8].copy_from_slice(&(QEMU_EFR | EFR_PERF_OPT_SUP).to_le_bytes());
    bytes[9] = 0;
    bytes[9] = 0u8.wrapping_sub(checksum(&bytes));
    let (result, unit) = parse(&bytes);
    let validation = result.unwrap();
    assert_eq!(unit.perf_opt_sup(), Some(true));
    assert_eq!(
        admit_table(&unit, &validation, &LIVE_QEMU),
        Err(TableRefusal::EfrMismatch)
    );
    let live = Live {
        efr: QEMU_EFR | EFR_PERF_OPT_SUP,
        ..LIVE_QEMU
    };
    assert!(admit_table(&unit, &validation, &live).is_ok());
}

#[test]
fn deny_by_default_invalidates_every_device_id_exactly_once() {
    for ia_sup in [false, true] {
        let commands: Vec<[u32; 4]> = deny_by_default_invalidations(ia_sup, EDU).collect();
        assert_eq!(commands.first() == Some(&invalidate_all()), ia_sup);
        let mut seen = vec![0u8; 1 << 16];
        for command in &commands {
            if command[1] >> 28 == 0x2 {
                assert_eq!(command[1], 0x2 << 28);
                seen[command[0] as usize] += 1;
            }
        }
        // A DeviceID left out would stay on QEMU 10.2.1's passthrough region.
        let missing: Vec<usize> = (0..seen.len()).filter(|&id| seen[id] != 1).collect();
        assert!(
            missing.is_empty(),
            "not invalidated exactly once: {} ids, first {:#x?}",
            missing.len(),
            missing.first()
        );
        assert_eq!(commands.len(), (1 << 16) + usize::from(ia_sup));
    }
}

#[test]
fn the_grant_follows_the_whole_deny_by_default_sweep() {
    for ia_sup in [false, true] {
        let plan: Vec<Step> = enforcement_plan(ia_sup, &[(EDU, DOMAIN)], &[]).collect();
        let grant = plan
            .iter()
            .position(|s| *s == Step::GrantTarget(0))
            .unwrap();
        assert_eq!(
            plan.iter().filter(|s| **s == Step::GrantTarget(0)).count(),
            1
        );
        // Before the grant: every DeviceID invalidated, then a completion
        // (the sweep's own), and nothing else but sweep commands.
        let devtab = |s: &Step| matches!(s, Step::Submit(c) if c[1] == 0x2 << 28);
        assert_eq!(plan[..grant].iter().filter(|s| devtab(s)).count(), 1 << 16);
        assert_eq!(plan[grant - 1], Step::Complete("invalidate"));
        // Each batch of at most SWEEP_BATCH commands is completed.
        let mut pending = 0;
        for step in &plan[..grant] {
            match step {
                Step::Submit(_) => pending += 1,
                Step::Complete(_) => pending = 0,
                Step::GrantTarget(_) => unreachable!(),
            }
            assert!(pending <= SWEEP_BATCH);
        }
        // After it: the target's own invalidation, the whole domain, a
        // completion, and nothing more.
        assert_eq!(
            plan[grant + 1..],
            [
                Step::Submit(invalidate_devtab(EDU)),
                Step::Submit(invalidate_domain(DOMAIN)),
                Step::Submit(invalidate_interrupt_table(EDU)),
                Step::Complete("grant"),
            ]
        );
    }
}

#[test]
fn two_targets_are_each_granted_in_their_own_domain_after_the_sweep() {
    const NVME: u16 = 0x0038;
    let targets = [(EDU, DOMAIN), (NVME, SECOND_DOMAIN)];
    let plan: Vec<Step> = enforcement_plan(true, &targets, &[]).collect();
    let first = plan
        .iter()
        .position(|s| *s == Step::GrantTarget(0))
        .unwrap();
    let second = plan
        .iter()
        .position(|s| *s == Step::GrantTarget(1))
        .unwrap();
    assert_eq!(plan[first - 1], Step::Complete("invalidate"));
    let devtab = |s: &Step| matches!(s, Step::Submit(c) if c[1] == 0x2 << 28);
    assert_eq!(plan[..first].iter().filter(|s| devtab(s)).count(), 1 << 16);
    // Each grant is followed by its own DeviceID, its own domain and its
    // own interrupt table; one completion closes both.
    assert_eq!(
        plan[first..],
        [
            Step::GrantTarget(0),
            Step::Submit(invalidate_devtab(EDU)),
            Step::Submit(invalidate_domain(DOMAIN)),
            Step::Submit(invalidate_interrupt_table(EDU)),
            Step::GrantTarget(1),
            Step::Submit(invalidate_devtab(NVME)),
            Step::Submit(invalidate_domain(SECOND_DOMAIN)),
            Step::Submit(invalidate_interrupt_table(NVME)),
            Step::Complete("grant"),
        ]
    );
    assert_eq!(second, first + 4);
    // A fourth target is never granted.
    let three = [(EDU, 1), (NVME, 2), (0x0040, 3), (0x0048, 4)];
    let plan: Vec<Step> = enforcement_plan(false, &three, &[]).collect();
    assert!(!plan.contains(&Step::GrantTarget(3)));
}

#[test]
fn grants_of_different_devices_must_be_disjoint() {
    let edu = [(0x10_0000, Perm::READ), (0x10_1000, Perm::WRITE)];
    let nvme = [(0x20_0000, Perm::READ_WRITE), (0x20_1000, Perm::READ_WRITE)];
    let edu2 = [(0x10_2000, Perm::READ)];
    assert_eq!(check_disjoint(&[&edu, &edu2, &nvme]), Ok(()));
    // Same page, any permission, in either order.
    let shared = [(0x20_0000, Perm::READ), (0x30_0000, Perm::READ)];
    assert_eq!(
        check_disjoint(&[&edu, &shared, &nvme]),
        Err(GrantError::Overlap(0x20_0000))
    );
    assert_eq!(
        check_disjoint(&[&nvme, &edu, &[(0x10_1000, Perm::READ)]]),
        Err(GrantError::Overlap(0x10_1000))
    );
    assert_eq!(check_disjoint(&[&edu]), Ok(()));
}

// --- Firmware-shaped quirks (synthetic values) -------------------------------

const FW_EFR: u64 = (2 << 10) | (1 << 9) | (1 << 6) | (1 << 1);
const FW_FEATURE: u32 = (2 << 30) | (2 << 17) | (4 << 13) | (1 << 5);
/// PNBanks 2 in 22:17, the counter count 4 misplaced at 10:7.
const FW_ATTRIBUTES: u32 = (2 << 17) | (4 << 7);
const FW_LIVE: Live = Live {
    cap_header: QEMU_CAP,
    efr: FW_EFR,
    counters: Some((2 << 12) | (4 << 7)),
};

/// 10h, 11h and 40h; 10h flags byte (PPRSup | Coherent) copied into the
/// wide blocks; attributes with the misplaced count; a tail alias.
fn firmware_shaped(edit: &dyn Fn(&mut [u8; 2], &mut u32)) -> Vec<u8> {
    firmware_shaped_targets(edit, 0x0040)
}

/// As [`firmware_shaped`], with the superseded 10h block's alias target
/// `target_10h` (the wide blocks keep 0x0040).
fn firmware_shaped_targets(edit: &dyn Fn(&mut [u8; 2], &mut u32), target_10h: u16) -> Vec<u8> {
    let range = |first: u16, last: u16| {
        let f = first.to_le_bytes();
        let l = last.to_le_bytes();
        vec![3, f[0], f[1], 0, 4, l[0], l[1], 0]
    };
    let alias_range = |first: u16, last: u16, target: u16| {
        let f = first.to_le_bytes();
        let l = last.to_le_bytes();
        let t = target.to_le_bytes();
        vec![0x43, f[0], f[1], 0, 0, t[0], t[1], 0, 4, l[0], l[1], 0]
    };
    let entries_for = |target: u16| {
        [
            range(0x0018, 0x7ffe),
            alias_range(0x7f00, 0x7fff, target),
            ioapic(5, 0x0038),
        ]
        .concat()
    };
    let entries = entries_for(0x0040);
    let entries_10h = entries_for(target_10h);
    let mut flags = [0xa0u8, 0xa0];
    let mut attributes = FW_ATTRIBUTES;
    edit(&mut flags, &mut attributes);
    let base = 0xf7f8_0000;
    table(
        2,
        (52 << 8) | 1,
        &[
            ivhd(0x10, flags[0], 0x0011, base, FW_FEATURE, 0, &entries_10h),
            ivhd(0x11, flags[1], 0x0011, base, attributes, FW_EFR, &entries),
            ivhd(0x40, flags[1], 0x0011, base, attributes, FW_EFR, &entries),
        ],
    )
}

fn admit(bytes: &[u8], live: &Live) -> Result<TableAdmission, TableRefusal> {
    let (result, unit) = parse(bytes);
    admit_table(&unit, &result.unwrap(), live)
}

#[test]
fn firmware_shaped_deviations_are_covered_only_exactly() {
    let bytes = firmware_shaped(&|_, _| {});
    let (result, unit) = parse(&bytes);
    // Two flags, two attributes and three tail-alias deviations.
    assert_eq!(result.unwrap().deviations, 7);
    let names: Vec<&str> = unit
        .findings
        .items()
        .iter()
        .map(|f| quirk_for(&unit, f, &FW_LIVE).map_or("none", |q| q.name))
        .collect();
    assert_eq!(
        names,
        [
            "alias-over-range-tail-scoped",
            "wide-flags-ppr-copy",
            "wide-attributes-counters-misplaced",
            "alias-over-range-tail-scoped",
            "wide-flags-ppr-copy",
            "wide-attributes-counters-misplaced",
            "alias-over-range-tail-scoped",
        ]
    );
    assert_eq!(admit(&bytes, &FW_LIVE), Ok(TableAdmission { quirked: 7 }));
    // The device rule still excludes the aliased bus and its target.
    assert_eq!(admit_device(&unit, 0x0100), Ok(()));
    assert_eq!(
        admit_device(&unit, 0x7f10),
        Err(DeviceRefusal::TouchesToleratedAlias)
    );

    // Q-L1 negatives: live PPRSup clear; bit 6 too; wide flags differ from 10h.
    let live = Live {
        efr: FW_EFR & !(1 << 1),
        ..FW_LIVE
    };
    assert!(matches!(
        admit(&bytes, &live),
        Err(TableRefusal::Uncovered(_))
    ));
    assert!(matches!(
        admit(&firmware_shaped(&|f, _| f[1] = 0xe0), &FW_LIVE),
        Err(TableRefusal::Uncovered(_))
    ));
    assert!(matches!(
        admit(&firmware_shaped(&|f, _| f[0] = 0xa1), &FW_LIVE),
        Err(TableRefusal::Uncovered(_))
    ));
    // Bit 6 as well, with the flags still equal: only bit 7 is covered.
    assert!(matches!(
        admit(
            &firmware_shaped(&|f, _| {
                f[0] = 0xe0;
                f[1] = 0xe0;
            }),
            &FW_LIVE
        ),
        Err(TableRefusal::Uncovered(_))
    ));
    // Q-L2 negatives: no counter register read; NCounter or banks differ;
    // a reserved attribute bit outside 10:7; PNCounters not empty.
    let live = Live {
        counters: None,
        ..FW_LIVE
    };
    assert!(matches!(
        admit(&bytes, &live),
        Err(TableRefusal::Uncovered(_))
    ));
    let live = Live {
        counters: Some((2 << 12) | (3 << 7)),
        ..FW_LIVE
    };
    assert!(matches!(
        admit(&bytes, &live),
        Err(TableRefusal::Uncovered(_))
    ));
    let live = Live {
        counters: Some((1 << 12) | (4 << 7)),
        ..FW_LIVE
    };
    assert!(matches!(
        admit(&bytes, &live),
        Err(TableRefusal::Uncovered(_))
    ));
    assert!(matches!(
        admit(&firmware_shaped(&|_, a| *a |= 1 << 1), &FW_LIVE),
        Err(TableRefusal::Uncovered(_))
    ));
    assert!(matches!(
        admit(&firmware_shaped(&|_, a| *a |= 1 << 13), &FW_LIVE),
        Err(TableRefusal::Uncovered(_))
    ));
    // NCounter 1 is reserved, even when table and live agree on it.
    let live = Live {
        counters: Some((2 << 12) | (1 << 7)),
        ..FW_LIVE
    };
    assert!(matches!(
        admit(&firmware_shaped(&|_, a| *a = (2 << 17) | (1 << 7)), &live),
        Err(TableRefusal::Uncovered(_))
    ));
    // Without the deviations the table needs only the alias rule.
    assert_eq!(
        admit(
            &firmware_shaped(&|f, a| {
                f[1] = 0x20;
                *a = (2 << 17) | (4 << 13);
            }),
            &FW_LIVE
        ),
        Ok(TableAdmission { quirked: 3 })
    );
}

#[test]
fn a_superseded_blocks_alias_target_is_excluded_too() {
    // The 10h block aliases the bus to 0x0028; the selected block to 0x0040.
    let bytes = firmware_shaped_targets(&|_, _| {}, 0x0028);
    let (result, unit) = parse(&bytes);
    assert_eq!(result.unwrap().deviations, 7);
    assert_eq!(
        admit_table(&unit, &parse(&bytes).0.unwrap(), &FW_LIVE),
        Ok(TableAdmission { quirked: 7 })
    );
    for devid in [0x0028, 0x0040, 0x7f00] {
        assert!(admit_device(&unit, devid).is_err(), "{devid:#x}");
    }
    assert_eq!(
        admit_device(&unit, 0x0028),
        Err(DeviceRefusal::TouchesToleratedAlias)
    );
    assert_eq!(admit_device(&unit, 0x0100), Ok(()));
}

#[test]
fn counter_configuration_is_read_only_after_its_prerequisites() {
    let (_, unit) = parse(&firmware_shaped(&|_, _| {}));
    assert!(unit.counters());
    let trace = |unit: &Unit, cap: u32, efr: u64| {
        let mut reads = Vec::new();
        let live = acquire_live(unit, cap, |offset| {
            reads.push(offset);
            match offset {
                MMIO_EFR => efr,
                _ => (2 << 12) | (4 << 7),
            }
        });
        (reads, live)
    };
    // All prerequisites hold: EFR, then Counter Configuration.
    let (reads, live) = trace(&unit, QEMU_CAP, FW_EFR);
    assert_eq!(reads, [MMIO_EFR, MMIO_COUNTER_CONFIG]);
    assert_eq!(live, FW_LIVE);
    // Live PCSup clear: no counter read.
    let (reads, live) = trace(&unit, QEMU_CAP, FW_EFR & !(1 << 9));
    assert_eq!(reads, [MMIO_EFR]);
    assert_eq!(live.counters, None);
    // Capability EFRSup clear, the reserved 0030h answering PCSup: neither
    // EFR nor Counter Configuration is read.
    let (reads, live) = trace(&unit, QEMU_CAP & !(1 << 27), FW_EFR);
    assert_eq!(reads, []);
    assert_eq!((live.efr, live.counters), (0, None));
    assert!(!counter_config_readable(
        &unit,
        QEMU_CAP & !(1 << 27),
        FW_EFR
    ));
    // An image without PCSup maps 16 KiB: no counter read whatever the
    // live EFR says.
    let (_, small) = parse(&qemu_10_2_1(true));
    assert!(!small.counters());
    let (reads, _) = trace(&small, QEMU_CAP, FW_EFR);
    assert_eq!(reads, [MMIO_EFR]);
}

#[test]
fn inherited_masters_are_invalidated_first() {
    let inherited = [0x0030u16, 0x00fa, 0x00a5];
    for ia_sup in [false, true] {
        let plan: Vec<Step> = enforcement_plan(ia_sup, &[(EDU, DOMAIN)], &inherited).collect();
        // The first steps: each inherited ID's own invalidation, then a
        // completion, before any sweep command or the grant.
        for (at, &id) in inherited.iter().enumerate() {
            assert_eq!(plan[at], Step::Submit(invalidate_devtab(id)));
        }
        assert_eq!(plan[inherited.len()], Step::Complete("inherited"));
        // The full sweep still follows: every DeviceID before the grant.
        let grant = plan
            .iter()
            .position(|s| *s == Step::GrantTarget(0))
            .unwrap();
        let devtab = |s: &Step| matches!(s, Step::Submit(c) if c[1] == 0x2 << 28);
        assert_eq!(
            plan[..grant].iter().filter(|s| devtab(s)).count(),
            (1 << 16) + inherited.len()
        );
        assert_eq!(plan[grant - 1], Step::Complete("invalidate"));
    }
    // No inherited master: the plan is exactly as before.
    let plain: Vec<Step> = enforcement_plan(true, &[(EDU, DOMAIN)], &[]).collect();
    assert!(!plain.contains(&Step::Complete("inherited")));
}

#[test]
fn interrupt_remapping_encodings_are_bit_exact() {
    // Figure 15: RemapEn=1, SupIOPF=0, IntType=000b, RqEoi=0, DM=0,
    // GuestMode=0, Destination 15:8, Vector 23:16.
    assert_eq!(irte_basic(0x41, 0x00), 0x0041_0001);
    assert_eq!(irte_basic(0x41, 0x03), 0x0041_0301);
    assert_eq!(
        irte_basic(IR_VECTOR, 0) & 0b1111_1110,
        0,
        "SupIOPF, IntType, RqEoi, DM, GuestMode clear"
    );
    // Figure 48: DeviceID, opcode 05h.
    assert_eq!(
        invalidate_interrupt_table(0x0028),
        [0x28, 0x5000_0000, 0, 0]
    );
    // The grant index is a fixed-delivery message (data bits 10:8 zero) and
    // lies inside the 512-entry table.
    assert_eq!(IR_INDEX & 0x700, 0);
    assert!(usize::from(IR_INDEX) < IR_TABLE_ENTRIES);
    assert_eq!(IR_TABLE_ENTRIES * IRTE_BYTES, 2048);
}

#[test]
fn deny_by_default_blocks_every_interrupt_path() {
    let (_, unit) = parse(&qemu_10_2_1(true));
    for devid in 0..=u16::MAX {
        let entry = dte_initial(&unit, devid);
        // No pass bit anywhere (NMI, INIT, ExtInt, LINT0/1).
        assert_eq!(entry[2] & DTE_PASS_BITS, 0, "{devid:#x}");
        // IntCtl never 01b (forward unmapped) or 11b.
        let intctl = (entry[2] >> 60) & 3;
        assert!(intctl == 0, "{devid:#x}");
        if devid != 0x00a0 {
            // IV=1, IntCtl=00b: fixed and arbitrated target-aborted.
            assert_eq!(entry[2] & 1, 1, "{devid:#x}");
        }
    }
}

#[test]
fn msi_capability_is_found_and_programmed() {
    // A config space with status bit 4, a PM capability at 0x40 and MSI
    // (64-bit) at 0x50.
    let mut space = [0u32; 64];
    space[0x04 / 4] = 1 << (16 + 4);
    space[0x34 / 4] = 0x40;
    space[0x40 / 4] = 0x5001; // PM, next 0x50
    space[0x50 / 4] = (1 << 23) | 0x0005; // MSI, 64-bit, next 0
    let read = |at: u8| space[usize::from(at) / 4];
    assert_eq!(find_capability(read, 0x05), Some(0x50));
    assert_eq!(find_capability(read, 0x11), None);
    // A loop is bounded.
    let mut looping = space;
    looping[0x50 / 4] = 0x5005 & 0xff | (0x40 << 8);
    looping[0x40 / 4] = 0x5001;
    assert_eq!(
        find_capability(|at| looping[usize::from(at) / 4], 0x11),
        None
    );
    // 64-bit: address-high zeroed (whatever it held), data at +0x0c; MSI
    // enable set, MME cleared.
    let (writes, used) =
        msi_writes(0x50, (1 << 23) | (0b101 << 20) | 0x0005, 0xfee0_0000, 0x10).unwrap();
    assert_eq!(
        &writes[..used],
        &[
            (0x54, 0xfee0_0000),
            (0x58, 0),
            (0x5c, 0x10),
            (0x50, (1 << 23) | (1 << 16) | 0x0005)
        ]
    );
    // Applied to a space whose address-high was nonzero, the result is the
    // complete address.
    let mut msi = [0u32; 64];
    msi[0x58 / 4] = 0xdead_beef;
    for &(at, value) in &writes[..used] {
        msi[usize::from(at) / 4] = value;
    }
    assert_eq!(
        (msi[0x54 / 4], msi[0x58 / 4], msi[0x5c / 4]),
        (0xfee0_0000, 0, 0x10)
    );
    // 32-bit: data at +0x08, three writes.
    let (writes, used) = msi_writes(0x50, 0x0005, 0xfee0_0000, 0x10).unwrap();
    assert_eq!(
        &writes[..used],
        &[
            (0x54, 0xfee0_0000),
            (0x58, 0x10),
            (0x50, (1 << 16) | 0x0005)
        ]
    );
    // Extent: the whole capability must fit below 100h, else nothing.
    let wide = 1 << 23;
    let masking = 1 << 24;
    assert!(msi_writes(0xf0, wide | 5, 0xfee0_0000, 0x10).is_some());
    assert!(msi_writes(0xf4, wide | 5, 0xfee0_0000, 0x10).is_none());
    assert!(msi_writes(0xf4, 5, 0xfee0_0000, 0x10).is_some());
    assert!(msi_writes(0xf8, 5, 0xfee0_0000, 0x10).is_none());
    assert!(msi_writes(0xfc, 5, 0xfee0_0000, 0x10).is_none());
    assert!(msi_writes(0xe8, wide | masking | 5, 0xfee0_0000, 0x10).is_some());
    assert!(msi_writes(0xec, wide | masking | 5, 0xfee0_0000, 0x10).is_none());
    assert!(msi_writes(0xec, masking | 5, 0xfee0_0000, 0x10).is_some());
    assert!(msi_writes(0xf0, masking | 5, 0xfee0_0000, 0x10).is_none());
    // Below 40h or misaligned: refused.
    assert!(msi_writes(0x3c, 5, 0xfee0_0000, 0x10).is_none());
    assert!(msi_writes(0x52, 5, 0xfee0_0000, 0x10).is_none());
}

#[test]
fn event_tail_outside_the_ring_is_refused() {
    let ring = 4096;
    assert_eq!(event_tail(0, ring), Some(0));
    assert_eq!(event_tail(0xff0, ring), Some(0xff0));
    // Low bits 3:0 and bits above 18 are not the offset.
    assert_eq!(event_tail(0xfff_f00f | 0x10, ring), None);
    assert_eq!(event_tail(0x0000_0f1f, ring), Some(0xf10));
    // At or past the ring's end: unreachable by a wrapping cursor.
    assert_eq!(event_tail(0x1000, ring), None);
    assert_eq!(event_tail(0x7fff0, ring), None);
    // An all-ones read (a unit gone from the bus).
    assert_eq!(event_tail(0xffff_ffff, ring), None);
    assert_eq!(event_tail(u64::MAX, ring), None);
    // A valid tail is reached from any 16-aligned head within the ring's
    // entries.
    for head in (0..ring).step_by(16) {
        let tail = event_tail(0x0a0, ring).unwrap();
        let mut at = head;
        let mut steps = 0;
        while at != tail {
            at = (at + 16) % ring;
            steps += 1;
        }
        assert!(steps < (ring / 16) as usize);
    }
}

#[test]
fn the_event_log_observation_keeps_its_invariant() {
    use super::lifecycle::{FailReason, FaultRecord, Health, Observer};
    let fresh = || {
        (
            Health::default(),
            FaultRecord::new(Observer::AbsdEventLog, "enforced"),
        )
    };
    // Valid tail, no overflow: codes walked head..tail (wrapping), nothing
    // latched; a page fault does not fail the unit.
    let (mut health, mut record) = fresh();
    let mut seen = std::vec::Vec::new();
    let tail = observe_log(0x20, false, 0xfe0, 4096, &mut health, &mut record, |at| {
        seen.push(at);
        2
    });
    assert_eq!(tail, Some(0x20));
    assert_eq!(seen, [0xfe0, 0xff0, 0x000, 0x010]);
    assert!(record.complete());
    assert_eq!(health.failed(), None);
    // A unit-error code fails the unit.
    assert_eq!(
        observe_log(0x10, false, 0, 4096, &mut health, &mut record, |_| 5),
        Some(0x10)
    );
    assert_eq!(health.failed(), Some(FailReason::Event(5)));
    // Overflow latches the record; the unit stays as it was.
    let (mut health, mut record) = fresh();
    assert_eq!(
        observe_log(0, true, 0, 4096, &mut health, &mut record, |_| 0),
        Some(0)
    );
    assert!(!record.complete());
    assert_eq!(health.failed(), None);
    // Invalid tails (past the end, the last offset, all ones): no tail, so
    // nothing consumed; nothing walked; unit failed; record latched; a
    // later valid observation heals neither.
    for raw in [0x1000, 0x7fff0, u64::MAX] {
        let (mut health, mut record) = fresh();
        let mut walked = 0;
        let tail = observe_log(raw, false, 0x40, 4096, &mut health, &mut record, |_| {
            walked += 1;
            0
        });
        assert_eq!(tail, None, "{raw:#x}");
        assert_eq!(walked, 0);
        assert_eq!(health.failed(), Some(FailReason::EventTail));
        assert!(health.admit().is_err());
        assert!(!record.complete());
        assert_eq!(
            observe_log(0, false, 0, 4096, &mut health, &mut record, |_| 0),
            Some(0)
        );
        assert_eq!(health.failed(), Some(FailReason::EventTail));
        assert!(!record.complete());
    }
}

/// Source tripwire for the event-log invariant in the producer
/// (src/amdvi_hw.rs, which host tests cannot execute). It is a guard
/// against the listed classes of edit, not a proof: line and block comments
/// are stripped and text compared with whitespace removed (not parsed
/// tokens), so commented-out or re-spaced code does not satisfy it, but a
/// determined rewrite could. The
/// executable guarantee is `the_event_log_observation_keeps_its_invariant`
/// on the one entry point; this checks that the producer has one reader and
/// that the paths reach it.
fn strip_comments(source: &str) -> std::string::String {
    // Block comments (`/* */`, nested) first, then line comments. String
    // literals in the producer contain neither marker.
    let mut out = std::string::String::new();
    let mut depth = 0usize;
    let mut rest = source;
    while !rest.is_empty() {
        if rest.starts_with("/*") {
            depth += 1;
            rest = &rest[2..];
        } else if depth > 0 && rest.starts_with("*/") {
            depth -= 1;
            rest = &rest[2..];
        } else {
            let c = rest.chars().next().unwrap();
            if depth == 0 || c == '\n' {
                out.push(c);
            }
            rest = &rest[c.len_utf8()..];
        }
    }
    out.lines()
        .map(|line| match line.find("//") {
            Some(at) => &line[..at],
            None => line,
        })
        .collect::<std::vec::Vec<_>>()
        .join("\n")
}

fn compact(text: &str) -> std::string::String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// The body of the function whose header starts with `header` (first
/// match), up to the next line starting `fn `/`    fn ` at the same or
/// lower indentation.
fn body<'a>(source: &'a str, header: &str) -> Result<&'a str, std::string::String> {
    let start = source.find(header).ok_or(std::format!("no {header:?}"))?;
    let indent = header.len() - header.trim_start().len();
    let rest = &source[start + header.len()..];
    let mut end = rest.len();
    let mut offset = 0;
    for line in rest.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let lead = line.len() - trimmed.len();
        if offset > 0
            && lead <= indent
            && (trimmed.starts_with("fn ")
                || trimmed.starts_with("pub fn ")
                || trimmed.starts_with("impl ")
                || trimmed.starts_with("struct "))
        {
            end = offset;
            break;
        }
        offset += line.len();
    }
    Ok(&rest[..end])
}

fn check_event_log_callers(raw: &str) -> Result<(), std::string::String> {
    use std::format;
    let source = strip_comments(raw);
    let all = compact(&source);
    let reader = compact(body(
        &source,
        "    fn observe_log(&self, health: &mut Health, record: &mut FaultRecord)",
    )?);
    // One reader and interpreter of the tail and the overflow bit; the
    // only other uses are the constants and the tail reset at init.
    for (token, allowed_elsewhere) in [
        (
            "EVENT_TAIL",
            &["constEVENT_TAIL:u64", "mmio.write(EVENT_TAIL,0)"][..],
        ),
        (
            "STATUS_EVENT_OVERFLOW",
            &["constSTATUS_EVENT_OVERFLOW:u64"][..],
        ),
    ] {
        let in_reader = reader.matches(token).count();
        let elsewhere = all.matches(token).count() - in_reader;
        let expected: usize = allowed_elsewhere
            .iter()
            .map(|a| all.matches(a).count())
            .sum();
        if in_reader != 1 || elsewhere != expected || expected != allowed_elsewhere.len() {
            return Err(format!(
                "{token}: {in_reader} in the reader, {elsewhere} elsewhere"
            ));
        }
    }
    if !reader.contains("amdvi::observe_log(raw_tail,overflow,self.head,RING_BYTES,health,record,")
    {
        return Err("Rings::observe_log does not pass its reads to amdvi::observe_log".into());
    }
    // Event memory is read only by the reader's code closure and by drain.
    let drain = compact(body(
        &source,
        "    fn drain(\n        &mut self,\n        health",
    )?);
    // (The one other use: the reserved range `(events, events + PAGE)`.)
    let event_reads = all.matches("events+").count() - all.matches("(events,events+PAGE)").count();
    if event_reads != reader.matches("events+").count() + drain.matches("self.events+").count()
        || drain.matches("self.events+").count() != 1
    {
        return Err(format!(
            "event memory read outside the reader and drain ({event_reads})"
        ));
    }
    // Drain: observe first, return on no tail, consume only to that tail,
    // observe again after consuming; `tail` never reassigned.
    for needle in [
        "let(tail,overflow)=self.observe_log(health,record);letSome(tail)=tailelse{return(0,overflow);};",
        "ifself.head==tail{break;}",
        "self.mmio.write(EVENT_HEAD,self.head);let(_,overflow)=self.observe_log(health,record);",
    ] {
        if !drain.contains(needle) {
            return Err(format!("drain lacks {needle:?}"));
        }
    }
    if drain.matches("tail=").count() != 0 {
        return Err("drain reassigns its tail".into());
    }
    // Setup: the record exists before the first observation, is never
    // replaced, and both observations gate on health.
    let setup = compact(body(&source, "fn setup(")?);
    let observe = "let_=rings.observe_log(&muthealth,&mutrecord);";
    let gate = "ifletSome(reason)=health.failed(){returnErr(unavailable(\"unit-failed\",";
    let created = setup
        .find("letmutrecord=FaultRecord::new(")
        .ok_or("setup: record not created")?;
    let first = setup.find(observe).ok_or("setup: no observation")?;
    if created > first || setup.matches("FaultRecord::new(").count() != 1 {
        return Err("setup: record created after observing, or more than once".into());
    }
    if setup.matches("record=").count() != 1 || setup.matches("record:").count() != 0 {
        return Err("setup: record replaced".into());
    }
    if setup.matches(&format!("{observe}{gate}")[..]).count() != 2
        || setup.matches(observe).count() != 2
    {
        return Err("setup: not exactly two gated observations".into());
    }
    if !setup.contains("health,record,devices:") {
        return Err("setup: the session does not keep the record".into());
    }
    // Session: observe_pending observes and acts; complete (every
    // completion boundary, revoke included) and restart call it; SYNC
    // drains through Rings::drain.
    let pending = compact(body(&source, "    fn observe_pending(")?);
    if !pending.contains("let_=self.rings.observe_log(&mutself.health,&mutself.record);ifwas_ok&&self.health.failed().is_some(){self.unit_failed();}") {
        return Err("observe_pending does not observe and act".into());
    }
    for header in [
        "    fn complete(&mut self, label: &str)",
        "    fn restart(&mut self, which: usize)",
    ] {
        if !compact(body(&source, header)?).contains("self.observe_pending();") {
            return Err(format!("{header:?} does not observe"));
        }
    }
    let complete = compact(body(&source, "    fn complete(&mut self, label: &str)")?);
    let revoke = compact(body(
        &source,
        "    fn revoke_device(&mut self, which: usize)",
    )?);
    if !revoke.contains("self.complete(\"revoke-device\")")
        || !complete.contains("self.observe_pending();ok")
    {
        return Err("revoke does not reach the observation".into());
    }
    let session_drain = compact(body(&source, "    fn drain(&mut self, each")?);
    if !session_drain.contains(".drain(&mutself.health,&mutself.record,") {
        return Err("Session::drain bypasses Rings::drain".into());
    }
    // SYNC drains through Session::drain.
    if !compact(body(&source, "fn sync(session: &mut Session, seq: u64)")?)
        .starts_with("->bool{let(faults,overflow)=session.drain(")
    {
        return Err("SYNC does not drain through Session::drain".into());
    }
    // Exactly these call sites of the reader.
    let calls = all.matches(".observe_log(&mut").count()
        + all.matches("self.observe_log(health,record)").count();
    if calls != 5 {
        return Err(format!(
            "{calls} call sites of Rings::observe_log, expected 5"
        ));
    }
    Ok(())
}

#[test]
fn every_event_log_caller_goes_through_the_one_entry_point() {
    let source = include_str!("../../src/amdvi_hw.rs");
    check_event_log_callers(source).unwrap();
    let setup_obs = "let _ = rings.observe_log(&mut health, &mut record);";
    let first = source.find(setup_obs).unwrap();
    let second = first + 1 + source[first + 1..].find(setup_obs).unwrap();
    let at = |at: usize, len: usize, with: &str| {
        let mut m = std::string::String::from(source);
        m.replace_range(at..at + len, with);
        m
    };
    let mutants: std::vec::Vec<(&str, std::string::String)> = std::vec![
        ("setup batch observation dropped", at(first, setup_obs.len(), "")),
        ("setup pre-arm observation dropped", at(second, setup_obs.len(), "")),
        ("setup batch observation commented out", at(first, 0, "// ")),
        ("setup pre-arm observation commented out", at(second, 0, "// ")),
        ("observe_pending dropped", source.replacen("let _ = self.rings.observe_log(&mut self.health, &mut self.record);", "", 1)),
        ("observe_pending dropped from complete", source.replacen("        self.observe_pending();\n        ok", "        ok", 1)),
        ("observe_pending dropped from restart", {
            let r = source.find("    fn restart(&mut self, which: usize)").unwrap();
            let o = r + source[r..].find("self.observe_pending();").unwrap();
            at(o, "self.observe_pending();".len(), "")
        }),
        ("record reset before the session", source.replacen("    Ok(Session {\n        rings,", "    let record = FaultRecord::new(Observer::AbsdEventLog, environment());\n    Ok(Session {\n        rings,", 1)),
        ("record created after the first observation", source.replacen("    let mut record = FaultRecord::new(Observer::AbsdEventLog, environment());\n", "", 1).replacen("    Ok(Session {\n        rings,", "    let record = FaultRecord::new(Observer::AbsdEventLog, environment());\n    Ok(Session {\n        rings,", 1)),
        ("a re-spaced second tail reader", source.replacen("fn unit_failed(&mut self) {", "fn unit_failed(&mut self) {\n        let _ = self.rings.mmio.read( EVENT_TAIL );", 1)),
        ("a second overflow interpreter", source.replacen("fn unit_failed(&mut self) {", "fn unit_failed(&mut self) {\n        let _ = self.rings.mmio.read(STATUS) & STATUS_EVENT_OVERFLOW;", 1)),
        ("drain consumes past the observed tail", source.replacen("        let mut count = 0;\n        for _ in 0..RING_ENTRIES {", "        let tail = (tail + 16) % RING_BYTES;\n        let mut count = 0;\n        for _ in 0..RING_ENTRIES {", 1)),
        ("drain consumes without observing", source.replacen("let (tail, overflow) = self.observe_log(health, record);", "let (tail, overflow) = (Some(0), false);", 1)),
        ("setup gate removed", source.replacen("let _ = rings.observe_log(&mut health, &mut record);\n                if let Some(reason) = health.failed() {", "let _ = rings.observe_log(&mut health, &mut record);\n                if let Some(reason) = None::<lifecycle::FailReason> {", 1)),
        ("reader bypasses the entry point", source.replacen("amdvi::observe_log(", "amdvi::event_tail_only(", 1)),
        ("event memory read elsewhere", source.replacen("fn unit_failed(&mut self) {", "fn unit_failed(&mut self) {\n        let _ = self.rings.events + 4;", 1)),
        ("observe_pending body block-commented", source.replacen("let _ = self.rings.observe_log(&mut self.health, &mut self.record);", "/* let _ = self.rings.observe_log(&mut self.health, &mut self.record); */", 1)),
        ("SYNC does not drain", source.replacen("fn sync(session: &mut Session, seq: u64) -> bool {\n    let (faults, overflow) = session.drain(", "fn sync(session: &mut Session, seq: u64) -> bool {\n    let (faults, overflow) = (0, false);\n    let _unused = session.drain(", 1)),
        ("Session::drain bypasses Rings::drain", source.replacen(".drain(&mut self.health, &mut self.record,", ".drain_raw(&mut self.health, &mut self.record,", 1)),
    ];
    for (name, mutant) in &mutants {
        assert_ne!(mutant.as_str(), source, "mutant {name} did not apply");
        assert!(
            check_event_log_callers(mutant).is_err(),
            "mutant not caught: {name}"
        );
    }
}

#[test]
fn msix_is_enabled_only_with_the_function_mask() {
    // Header as QEMU's NVMe presents it: ID 11h, next 0, table size 64.
    let header = 0x003f_0011;
    let written = msix_enable_masked(header);
    assert_eq!(
        written & 0xffff,
        0x0011,
        "capability ID and next pointer kept"
    );
    assert_eq!((written >> 16) & 0x7ff, 0x3f, "table size kept");
    assert_eq!(written >> 30, 0b11, "enable and function mask together");
}

// --- #123: the AHCI controller as the second target --------------------------

#[test]
fn the_second_target_is_one_device_and_the_ahci_only_at_its_pin() {
    // #116 unchanged: without a selected AHCI disk the NVMe is the target
    // when present, whatever sits at the pin.
    assert_eq!(second_target(false, false, false), Ok(Second::None));
    assert_eq!(second_target(false, false, true), Ok(Second::None));
    assert_eq!(second_target(true, false, false), Ok(Second::Nvme));
    assert_eq!(second_target(true, false, true), Ok(Second::Nvme));
    assert_eq!(second_target(false, true, true), Ok(Second::Ahci));
    assert_eq!(
        second_target(false, true, false),
        Err(SecondRefusal::AhciNotPinned)
    );
    assert_eq!(
        second_target(true, true, false),
        Err(SecondRefusal::AhciNotPinned)
    );
    assert_eq!(
        second_target(true, true, true),
        Err(SecondRefusal::NvmeAndAhci)
    );
    assert_eq!(SecondRefusal::AhciNotPinned.word(), "ahci-not-at-00:07.0");
    assert_eq!(SecondRefusal::NvmeAndAhci.word(), "nvme-and-ahci");
    // 00:07.0 is DeviceID 0x0038; q35's built-in controller (00:1f.2) is not
    // the pin.
    let (bus, device, function) = AHCI_PIN;
    let devid = (u16::from(bus) << 8) | (u16::from(device) << 3) | u16::from(function);
    assert_eq!(devid, 0x0038);
    assert_ne!(AHCI_PIN, (0, 0x1f, 2));
}

#[test]
fn ahci_roles_grant_the_least_each_page_needs() {
    let roles: Vec<&str> = AHCI_ROLES.iter().map(|&(role, _)| role).collect();
    assert_eq!(roles, ["cl", "fis", "ctba", "bounce"]);
    assert_eq!(AHCI_ROLES[0].1, Perm::READ_WRITE);
    assert_eq!(AHCI_ROLES[1].1, Perm::READ_WRITE);
    // The command table is only read by the controller.
    assert_eq!(AHCI_ROLES[2].1, Perm::READ);
    assert_eq!(AHCI_ROLES[3].1, Perm::READ_WRITE);
    // Every role's page is mapped with exactly its permission.
    let mut tables = Memory::default();
    let root = tables.allocate().unwrap();
    let pages: Vec<(u64, Perm)> = AHCI_ROLES
        .iter()
        .enumerate()
        .map(|(at, &(_, perm))| (0x20_0000 + at as u64 * PAGE, perm))
        .collect();
    assert_eq!(check_grant(&pages, IOVA_LIMIT, &[]), Ok(()));
    for &(page, perm) in &pages {
        map(&mut tables, root, page, page, perm).unwrap();
        assert_eq!(translate(&tables, root, page), Some((page, perm)));
    }
    assert_eq!(translate(&tables, root, 0x20_0000 + 4 * PAGE), None);
}

#[test]
fn engine_cached_ahci_pages_are_not_revocable_alone() {
    let revocable: Vec<bool> = (0..AHCI_ROLES.len()).map(ahci_page_revocable).collect();
    // cl and fis are cached by the engine; ctba and bounce are per command.
    assert_eq!(revocable, [false, false, true, true]);
    assert!(!ahci_page_revocable(4));
}

mod operator_policy {
    use super::super::lifecycle::*;
    use super::*;

    const AHCI_ID: u16 = 0x0501;
    const NIC_ID: u16 = 0x0100;
    const TARGETS: [u16; 2] = [AHCI_ID, NIC_ID];

    fn fault(devid: u16) -> Event {
        Event::IoPageFault {
            devid,
            domain: 2,
            address: 0x1000,
            write: true,
            permission: false,
            present: false,
            interrupt: false,
        }
    }

    #[test]
    fn a_fault_from_a_target_revokes_only_that_target() {
        assert_eq!(
            operator_event_action(&fault(NIC_ID), &TARGETS),
            OperatorAction::RevokeTarget(NIC_ID)
        );
    }

    #[test]
    fn a_fault_from_another_requester_is_only_reported() {
        assert_eq!(
            operator_event_action(&fault(0x0403), &TARGETS),
            OperatorAction::Report
        );
    }

    #[test]
    fn overflow_and_unit_failure_are_terminal() {
        assert!(operator_log_terminal(true, false));
        assert!(operator_log_terminal(false, true));
        assert!(!operator_log_terminal(false, false));
    }

    fn facts() -> CheckFacts {
        CheckFacts {
            drained: true,
            permitted_ok: true,
            submitted: true,
            canary_unchanged: true,
            fault_matches: true,
            completed: true,
            port_retired: false,
            bme_clear: false,
            later_read_matches: true,
            record_complete: true,
        }
    }

    #[test]
    fn a_completed_denial_passes_with_every_fact() {
        assert_eq!(check_verdict(&facts()), CheckOutcome::DeniedCompleted);
    }

    #[test]
    fn a_retired_denial_passes_only_as_a_denial() {
        let retired = CheckFacts {
            completed: false,
            port_retired: true,
            bme_clear: true,
            later_read_matches: false,
            ..facts()
        };
        assert_eq!(check_verdict(&retired), CheckOutcome::DeniedPortRetired);
    }

    #[test]
    fn each_missing_fact_fails_the_check() {
        let cases: [fn(&mut CheckFacts); 6] = [
            |f| f.drained = false,
            |f| f.permitted_ok = false,
            |f| f.submitted = false,
            |f| f.canary_unchanged = false,
            |f| f.fault_matches = false,
            |f| f.record_complete = false,
        ];
        for change in cases {
            let mut f = facts();
            change(&mut f);
            assert_eq!(check_verdict(&f), CheckOutcome::Failed);
        }
        let mut f = facts();
        f.later_read_matches = false;
        assert_eq!(check_verdict(&f), CheckOutcome::Failed);
    }

    #[test]
    fn a_retirement_with_no_submission_or_fault_is_not_a_denial() {
        let retired = CheckFacts {
            completed: false,
            port_retired: true,
            bme_clear: true,
            later_read_matches: false,
            ..facts()
        };
        for change in [
            (|f: &mut CheckFacts| f.submitted = false) as fn(&mut CheckFacts),
            |f| f.fault_matches = false,
            |f| f.bme_clear = false,
        ] {
            let mut f = retired;
            change(&mut f);
            assert_eq!(check_verdict(&f), CheckOutcome::Failed);
        }
    }

    #[test]
    fn neither_completed_nor_retired_fails() {
        let f = CheckFacts {
            completed: false,
            ..facts()
        };
        assert_eq!(check_verdict(&f), CheckOutcome::Failed);
    }

    fn event(
        devid: u16,
        domain: u16,
        address: u64,
        write: bool,
        present: bool,
        interrupt: bool,
    ) -> Event {
        Event::IoPageFault {
            devid,
            domain,
            address,
            write,
            permission: false,
            present,
            interrupt,
        }
    }

    #[test]
    fn attribution_needs_this_requester_domain_and_page() {
        let at = |e: Event| fault_attributes(&e, AHCI_ID, 2, 0x5000, Attribution::Address);
        assert!(at(event(AHCI_ID, 2, 0x5000, true, false, false)));
        assert!(at(event(AHCI_ID, 2, 0x5200, true, false, false)));
        assert!(!at(event(AHCI_ID, 2, 0x6000, true, false, false)));
        assert!(!at(event(NIC_ID, 2, 0x5000, true, false, false)));
        assert!(!at(event(AHCI_ID, 3, 0x5000, true, false, false)));
        assert!(!at(event(AHCI_ID, 2, 0x5000, true, false, true)));
    }

    /// The specification makes RW meaningful only with PR=1. A canary is
    /// never mapped, so its fault has PR=0 and RW must not decide it.
    #[test]
    fn rw_decides_attribution_only_for_a_present_page() {
        let at = |e: Event| fault_attributes(&e, AHCI_ID, 2, 0x5000, Attribution::Address);
        assert!(at(event(AHCI_ID, 2, 0x5000, false, false, false)));
        assert!(!at(event(AHCI_ID, 2, 0x5000, false, true, false)));
        assert!(at(event(AHCI_ID, 2, 0x5000, true, true, false)));
    }

    #[test]
    fn every_faulting_target_is_collected() {
        let mut set = RevokeSet::EMPTY;
        set.add(AHCI_ID);
        set.add(NIC_ID);
        set.add(AHCI_ID);
        assert_eq!(set.ids(), &[AHCI_ID, NIC_ID]);
    }

    #[test]
    fn terminal_takes_precedence_over_revocation() {
        let mut set = RevokeSet::EMPTY;
        set.add(AHCI_ID);
        assert_eq!(operator_next(true, &set), OperatorNext::Terminal);
        assert_eq!(operator_next(false, &set), OperatorNext::Revoke);
        assert_eq!(
            operator_next(false, &RevokeSet::EMPTY),
            OperatorNext::Nothing
        );
    }

    #[cfg(not(feature = "contain-qemu-fixture"))]
    #[test]
    fn a_physical_build_requires_the_address() {
        assert_eq!(Attribution::for_build(), Attribution::Address);
    }

    #[cfg(feature = "contain-qemu-fixture")]
    #[test]
    fn the_fixture_build_labels_its_weaker_match() {
        assert_eq!(Attribution::for_build(), Attribution::DevidOnly);
        assert_eq!(Attribution::for_build().word(), "devid-only");
        let zero = Event::IoPageFault {
            devid: AHCI_ID,
            domain: 0,
            address: 0,
            write: false,
            permission: false,
            present: false,
            interrupt: false,
        };
        assert!(fault_attributes(
            &zero,
            AHCI_ID,
            2,
            0x5000,
            Attribution::DevidOnly
        ));
    }
}
