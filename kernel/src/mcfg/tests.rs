extern crate std;
use super::*;
use std::vec::Vec;

fn table(entries: &[(u64, u16, u8, u8)]) -> Vec<u8> {
    let mut t = std::vec![0u8; 44];
    t[..4].copy_from_slice(b"MCFG");
    for &(base, segment, start, end) in entries {
        t.extend_from_slice(&base.to_le_bytes());
        t.extend_from_slice(&segment.to_le_bytes());
        t.push(start);
        t.push(end);
        t.extend_from_slice(&[0; 4]);
    }
    let len = t.len() as u32;
    t[4..8].copy_from_slice(&len.to_le_bytes());
    let sum = t.iter().fold(0u8, |s, b| s.wrapping_add(*b));
    t[9] = 0u8.wrapping_sub(sum);
    t
}

#[test]
fn the_config_page_is_counted_from_bus_zero_of_the_base() {
    let regions = parse(&table(&[(0xe000_0000, 0, 0, 0x3f)])).unwrap();
    assert_eq!(regions.config_page(5, 0, 1), Some(0xe050_1000));
    assert_eq!(regions.config_page(1, 0, 0), Some(0xe010_0000));
    let late = parse(&table(&[(0xe000_0000, 0, 4, 0x3f)])).unwrap();
    assert_eq!(late.config_page(5, 0, 1), Some(0xe050_1000));
    assert_eq!(late.config_page(3, 0, 0), None);
}

#[test]
fn a_bus_outside_the_range_or_segment_has_no_page() {
    let regions = parse(&table(&[(0xe000_0000, 0, 0, 0x3f)])).unwrap();
    assert_eq!(regions.config_page(0x40, 0, 0), None);
    let other = parse(&table(&[(0xe000_0000, 1, 0, 0xff)])).unwrap();
    assert_eq!(other.config_page(5, 0, 1), None);
    assert_eq!(regions.config_page(5, 0x20, 0), None);
    assert_eq!(regions.config_page(5, 0, 8), None);
}

#[test]
fn bad_tables_refuse() {
    let good = table(&[(0xe000_0000, 0, 0, 0x3f)]);
    let mut sum = good.clone();
    sum[50] ^= 1;
    assert_eq!(parse(&sum).err(), Some(McfgError::Checksum));
    assert_eq!(parse(&good[..20]).err(), Some(McfgError::Length));
    let mut long = good.clone();
    long[4] = 0xff;
    assert_eq!(parse(&long).err(), Some(McfgError::Length));
    let mut partial = table(&[]);
    partial.extend_from_slice(&[0; 8]);
    let len = partial.len() as u32;
    partial[4..8].copy_from_slice(&len.to_le_bytes());
    partial[9] = 0;
    let sum = partial.iter().fold(0u8, |s, b| s.wrapping_add(*b));
    partial[9] = 0u8.wrapping_sub(sum);
    assert_eq!(parse(&partial).err(), Some(McfgError::Length));
    let mut wrong = good;
    wrong[0] = b'X';
    assert_eq!(parse(&wrong).err(), Some(McfgError::Signature));
}

/// Configuration space as dwords by offset.
fn space(dwords: &[(u16, u32)]) -> impl FnMut(u16) -> u32 + '_ {
    move |at| {
        dwords
            .iter()
            .find(|(offset, _)| *offset == at)
            .map_or(0, |(_, value)| *value)
    }
}

const NONE: ExtFacts = ExtFacts {
    ats_enabled: false,
    pasid_enabled: false,
    pri_enabled: false,
    sriov_vfs_enabled: false,
};

#[test]
fn an_empty_list_has_nothing_enabled() {
    assert_eq!(extended_facts(space(&[])), Ok(NONE));
}

#[test]
fn present_but_disabled_capabilities_are_not_enabled() {
    let list = [
        (0x100, 0x1401_000f),
        (0x140, 0x1801_001b),
        (0x180, 0x1c01_0013),
        (0x1c0, 0x0001_0010),
    ];
    assert_eq!(extended_facts(space(&list)), Ok(NONE));
}

#[test]
fn each_enable_bit_is_read_from_its_own_register() {
    let ats = [(0x100, 0x0001_000f), (0x104, 1 << 31)];
    assert!(extended_facts(space(&ats)).unwrap().ats_enabled);
    let pasid = [(0x100, 0x0001_001b), (0x104, 1 << 16)];
    assert!(extended_facts(space(&pasid)).unwrap().pasid_enabled);
    let pri = [(0x100, 0x0001_0013), (0x104, 1)];
    assert!(extended_facts(space(&pri)).unwrap().pri_enabled);
    let sriov = [(0x100, 0x0001_0010), (0x108, 1)];
    assert!(extended_facts(space(&sriov)).unwrap().sriov_vfs_enabled);
    // Capability bits, not enable bits.
    let ats_cap_only = [(0x100, 0x0001_000f), (0x104, 0xffff)];
    assert!(!extended_facts(space(&ats_cap_only)).unwrap().ats_enabled);
}

#[test]
fn a_later_capability_in_the_list_is_seen() {
    let list = [(0x100, 0x1401_0001), (0x140, 0x0001_000f), (0x144, 1 << 31)];
    assert!(extended_facts(space(&list)).unwrap().ats_enabled);
}

#[test]
fn an_unreadable_space_is_not_absent() {
    assert_eq!(extended_facts(|_| 0xffff_ffff), Err(ExtError::Unreadable));
}

#[test]
fn a_broken_list_refuses() {
    let below = [(0x100, 0x0801_0001)];
    assert_eq!(extended_facts(space(&below)), Err(ExtError::Malformed));
    let misaligned = [(0x100, 0x1421_0001)];
    assert_eq!(extended_facts(space(&misaligned)), Err(ExtError::Malformed));
    let looping = [(0x100, 0x1001_0001)];
    assert_eq!(extended_facts(space(&looping)), Err(ExtError::Malformed));
}

#[test]
fn an_unaligned_base_refuses() {
    assert_eq!(
        parse(&table(&[(0xe000_0004, 0, 0, 0x3f)])).err(),
        Some(McfgError::Alignment)
    );
    assert_eq!(
        parse(&table(&[(0xe008_0000, 0, 0, 0x3f)])).err(),
        Some(McfgError::Alignment)
    );
}

#[test]
fn a_capability_register_past_the_function_refuses() {
    // ATS control is at +4: 0x1000 would be the next function's space.
    let ats = [(0x100, 0xffc0_0001), (0xffc, 0x0001_000f)];
    assert_eq!(extended_facts(space(&ats)), Err(ExtError::Malformed));
    // SR-IOV control is at +8.
    let sriov = [(0x100, 0xff80_0001), (0xff8, 0x0001_0010)];
    assert_eq!(extended_facts(space(&sriov)), Err(ExtError::Malformed));
    // A capability ABSD does not read may end the space.
    let other = [(0x100, 0xffc0_0001), (0xffc, 0x0001_0001)];
    assert_eq!(extended_facts(space(&other)), Ok(NONE));
}
