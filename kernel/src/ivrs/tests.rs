//! Host tests over synthetic IVRS tables.
//!
//! `syn()` is structurally representative of the firmware table the
//! backend targets (owner decision 4 on coordination record#111): one IOMMU
//! described by 10h, 11h and 40h blocks; a flat range with an alias range
//! covering one whole bus over its tail and one ID past its end; a
//! reserved all-zero entry; an HPET and two IOAPIC specials, two sharing a
//! source; four ACPI-HID entries with string UIDs and one DeviceID; the
//! IOMMU's own DeviceID undescribed; performance counters, so a 512 KiB
//! window. Every value in it (base, EFR, feature and attribute words,
//! IVinfo, DeviceIDs, handles, HIDs, UIDs) is invented for this file and
//! conforms to rev 3.11. The retained private table is checked against the
//! parser outside the repo (lane record), never committed.
//!
//! `qemu()` reproduces the table QEMU 8.2.2 generates for `-device
//! amd-iommu` on q35 (public emulator values).

extern crate std;
use super::*;
use std::boxed::Box;
use std::vec;
use std::vec::Vec;

fn e4(kind: u8, devid: u16, setting: u8) -> Vec<u8> {
    let id = devid.to_le_bytes();
    vec![kind, id[0], id[1], setting]
}

fn e8(kind: u8, devid: u16, setting: u8, b4: u8, devid_b: u16, b7: u8) -> Vec<u8> {
    let mut entry = e4(kind, devid, setting);
    entry.push(b4);
    entry.extend_from_slice(&devid_b.to_le_bytes());
    entry.push(b7);
    entry
}

fn range(first: u16, last: u16, setting: u8) -> Vec<u8> {
    [e4(3, first, setting), e4(4, last, 0)].concat()
}

fn alias_range(first: u16, last: u16, target: u16) -> Vec<u8> {
    [e8(0x43, first, 0, 0, target, 0), e4(4, last, 0)].concat()
}

fn extended_range(first: u16, last: u16, extended: u32) -> Vec<u8> {
    let mut start = e4(0x47, first, 0);
    start.extend_from_slice(&extended.to_le_bytes());
    [start, e4(4, last, 0)].concat()
}

fn special(variety: u8, handle: u8, source: u16, setting: u8) -> Vec<u8> {
    e8(0x48, 0, setting, handle, source, variety)
}

fn hid_entry(devid: u16, setting: u8, name: &[u8; 8], cid: &[u8; 8], uid: &[u8]) -> Vec<u8> {
    let mut entry = e4(0xf0, devid, setting);
    entry.extend_from_slice(name);
    entry.extend_from_slice(cid);
    entry.push(if uid.is_empty() { 0 } else { 2 });
    entry.push(uid.len() as u8);
    entry.extend_from_slice(uid);
    entry
}

fn hid(devid: u16, setting: u8, name: &[u8; 8], uid: &[u8]) -> Vec<u8> {
    hid_entry(devid, setting, name, &[0; 8], uid)
}

#[derive(Clone)]
struct Block {
    kind: u8,
    flags: u8,
    devid: u16,
    capability: u16,
    base: u64,
    segment: u16,
    info: u16,
    word: u32,
    efr: u64,
    efr2: u64,
    entries: Vec<u8>,
}

impl Block {
    fn bytes(&self) -> Vec<u8> {
        let header = if self.kind == 0x10 { 24 } else { 40 };
        let length = (header + self.entries.len()) as u16;
        let mut out = vec![self.kind, self.flags];
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&self.devid.to_le_bytes());
        out.extend_from_slice(&self.capability.to_le_bytes());
        out.extend_from_slice(&self.base.to_le_bytes());
        out.extend_from_slice(&self.segment.to_le_bytes());
        out.extend_from_slice(&self.info.to_le_bytes());
        out.extend_from_slice(&self.word.to_le_bytes());
        if header == 40 {
            out.extend_from_slice(&self.efr.to_le_bytes());
            out.extend_from_slice(&self.efr2.to_le_bytes());
        }
        out.extend_from_slice(&self.entries);
        out
    }
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
    assert_eq!(out.len(), HEADER_BYTES);
    for block in blocks {
        out.extend_from_slice(block);
    }
    seal(&mut out);
    out
}

/// Rewrites the length and checksum after an edit.
fn seal(bytes: &mut [u8]) {
    let length = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&length.to_le_bytes());
    bytes[9] = 0;
    bytes[9] = 0u8.wrapping_sub(checksum(bytes));
}

/// EFR image: HATS = 10b (6 levels), PCSup, IASup, PPRSup; nothing else.
const SYN_EFR: u64 = (2 << 10) | (1 << 9) | (1 << 6) | (1 << 1);
/// 10h feature field: HATS = 10b, PNBanks 1, PNCounters 2, IASup.
const SYN_FEATURE: u32 = (2 << 30) | (1 << 17) | (2 << 13) | (1 << 5);
/// 11h/40h attributes: PNBanks 1, PNCounters 2.
const SYN_ATTRIBUTES: u32 = (1 << 17) | (2 << 13);
/// IVinfo: PAsize 52, EFRSup.
const SYN_IVINFO: u32 = (52 << 8) | IVINFO_EFR_SUP;
const SYN_BASE: u64 = 0xf7f8_0000;
const SYN_DEVID: u16 = 0x0011;
const SYN_CAP: u16 = 0x50;
/// The alias target (00:08.0) and the specials' sources.
const SYN_TARGET: u16 = 0x0040;
const SYN_SOURCE: u16 = 0x0038;

fn syn_fixed() -> Vec<u8> {
    [
        range(0x0018, 0x7ffe, 0),
        alias_range(0x7f00, 0x7fff, SYN_TARGET),
        vec![0; 4],
        special(2, 1, SYN_SOURCE, 0),
        special(1, 5, SYN_SOURCE, 0x01),
        special(1, 6, SYN_SOURCE + 1, 0),
    ]
    .concat()
}

fn syn_block(kind: u8) -> Block {
    let mut entries = syn_fixed();
    if kind == 0x40 {
        for uid in [b"\\_SB.SYN0", b"\\_SB.SYN1", b"\\_SB.SYN2", b"\\_SB.SYN3"] {
            entries.extend(hid(SYN_TARGET, 0x80, b"ABSD0001", uid));
        }
    }
    Block {
        kind,
        flags: 0x20,
        devid: SYN_DEVID,
        capability: SYN_CAP,
        base: SYN_BASE,
        segment: 0,
        info: 0,
        word: if kind == 0x10 {
            SYN_FEATURE
        } else {
            SYN_ATTRIBUTES
        },
        efr: SYN_EFR,
        efr2: 0,
        entries,
    }
}

fn syn_with(edit: impl Fn(&mut [Block; 3])) -> Vec<u8> {
    let mut blocks = [syn_block(0x10), syn_block(0x11), syn_block(0x40)];
    edit(&mut blocks);
    let bytes: Vec<Vec<u8>> = blocks.iter().map(Block::bytes).collect();
    table(2, SYN_IVINFO, &bytes)
}

fn syn() -> Vec<u8> {
    syn_with(|_| {})
}

fn qemu_block() -> Block {
    Block {
        kind: 0x10,
        flags: 0xd1,
        devid: 0x0008,
        capability: 0x40,
        base: 0xfed8_0000,
        segment: 0,
        info: 0,
        word: 0x44,
        efr: 0,
        efr2: 0,
        entries: [
            e4(2, 0x0000, 0),
            e4(2, 0x0008, 0),
            e4(2, 0x00f8, 0),
            e4(2, 0x00fa, 0),
            e4(2, 0x00fb, 0),
            special(1, 0, 0x00a0, 0),
        ]
        .concat(),
    }
}

/// QEMU 8.2.2's table: revision 1, EFRSup clear, one 10h whose feature
/// field (reserved without EFRSup) is 44h.
fn qemu() -> Vec<u8> {
    table(1, 0x0000_2800, &[qemu_block().bytes()])
}

/// The same with the reserved feature field zero.
fn qemu_conforming() -> Vec<u8> {
    let mut block = qemu_block();
    block.word = 0;
    table(1, 0x0000_2800, &[block.bytes()])
}

/// The unit when not refused, deviations or not.
fn parse_boxed(bytes: &[u8]) -> Result<Box<Unit>, Error> {
    let mut unit = Box::new(Unit::EMPTY);
    let mut scratch = Box::new(Entries::EMPTY);
    parse(bytes, &mut unit, &mut scratch).map(|_| unit)
}

/// The outcome and the unit as left by `parse`.
fn parse_full(bytes: &[u8]) -> (Result<Validation, Error>, Box<Unit>) {
    let mut unit = Box::new(Unit::EMPTY);
    let mut scratch = Box::new(Entries::EMPTY);
    let result = parse(bytes, &mut unit, &mut scratch);
    (result, unit)
}

fn refused(bytes: &[u8]) -> Error {
    match parse_boxed(bytes) {
        Ok(unit) => panic!("accepted: {unit:?}"),
        Err(error) => error,
    }
}

fn entry_problem(bytes: &[u8]) -> EntryProblem {
    match refused(bytes) {
        Error::Entry { problem, .. } => problem,
        other => panic!("not an entry refusal: {other:?}"),
    }
}

/// The tolerated overlap's deviation, which every `syn()`-based table
/// carries once per block.
const TAIL: Field = Field::AliasOverRangeTail;

/// The deviations other than the tolerated overlap, in order; panics unless
/// the table is structurally valid with deviations and a described unit.
fn findings(bytes: &[u8]) -> Vec<Field> {
    let (result, unit) = parse_full(bytes);
    assert_eq!(deviations(&result), unit.findings.total());
    assert!(unit.findings.total() > 0);
    assert_eq!(unit.devid, bytes_devid(bytes), "unit described");
    let fields: Vec<Field> = unit
        .findings
        .items()
        .iter()
        .map(|f| f.field)
        .filter(|&f| f != TAIL)
        .collect();
    assert!(!fields.is_empty(), "only the tolerated overlap");
    fields
}

/// Not refused, and no deviation but the tolerated overlap.
fn clean(bytes: &[u8]) -> Box<Unit> {
    let (result, unit) = parse_full(bytes);
    assert!(result.is_ok(), "{result:?}");
    let other: Vec<Field> = unit
        .findings
        .items()
        .iter()
        .map(|f| f.field)
        .filter(|&f| f != TAIL)
        .collect();
    assert_eq!(other, [], "unexpected deviations");
    assert_eq!(deviations(&result), unit.findings.total());
    unit
}

/// The deviation count of a parse that was not refused; also checks the
/// other properties every such result carries.
fn deviations(result: &Result<Validation, Error>) -> usize {
    let validation = result.as_ref().expect("not refused");
    assert_eq!(validation.dma_admission, Admission::NotEstablished);
    assert_eq!(validation.validated, VALIDATED_FIELDS);
    assert_eq!(validation.unvalidated, UNVALIDATED_FIELDS);
    validation.deviations
}

/// No deviation at all within the validated subset.
fn deviation_free(bytes: &[u8]) -> Box<Unit> {
    let (result, unit) = parse_full(bytes);
    assert_eq!(deviations(&result), 0, "{:?}", unit.findings.items());
    unit
}

fn bytes_devid(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[HEADER_BYTES + 4], bytes[HEADER_BYTES + 5]])
}

#[test]
fn synthetic_shape_is_one_unit_whose_tail_alias_is_a_deviation() {
    let (result, unit) = parse_full(&syn());
    // The tolerated overlap is accepted and reported, once per block, as a
    // named deviation: such a table never reports zero deviations.
    assert_eq!(
        result,
        Ok(Validation {
            deviations: unit.findings.total(),
            validated: VALIDATED_FIELDS,
            unvalidated: UNVALIDATED_FIELDS,
            dma_admission: Admission::NotEstablished
        })
    );
    let mut at = HEADER_BYTES;
    for (kind, finding) in [0x10u8, 0x11, 0x40].into_iter().zip(unit.findings.items()) {
        let header = if kind == 0x10 { 24 } else { 40 };
        assert_eq!(
            *finding,
            Finding {
                block: kind,
                // The 43h entry follows the 8-byte plain range.
                offset: (at + header + 8) as u32,
                field: TAIL,
                detail: Detail::AliasRange {
                    first: 0x7f00,
                    last: 0x7fff,
                    target: SYN_TARGET,
                    end_offset: (at + header + 16) as u32,
                },
            }
        );
        at += syn_block(kind).bytes().len();
    }
    assert_eq!(unit.findings.total(), 3);
    assert_eq!(TAIL.rule(), "tolerated-overlap");
    assert_eq!(
        (unit.devid, unit.capability, unit.base),
        (SYN_DEVID, SYN_CAP as u8, SYN_BASE)
    );
    assert_eq!((unit.used, unit.present, unit.revision), (0x11, 0b111, 2));
    assert_eq!(unit.efr, Some(SYN_EFR));
    assert_eq!(unit.attributes, Some(SYN_ATTRIBUTES));
    assert_eq!(unit.feature, Some(SYN_FEATURE));
    assert_eq!(unit.host_levels(), Some(6));
    assert!(unit.counters());
    assert_eq!(unit.window(), 512 << 10);
    assert!(!unit.pre_boot_protection());
    assert_eq!(
        unit.capability_registers(),
        Some([0x50, 0x54, 0x58]),
        "header, base low, base high"
    );
    // Functions inside the flat range keep their own requester IDs.
    for id in [0x0018, 0x0118, 0x0300, 0x7eff, SYN_TARGET] {
        assert_eq!(unit.source(id), Source::Own, "{id:#x}");
    }
    // The aliased bus: the alias wins over the range, and its last ID
    // (one past the range) is aliased too.
    for id in [0x7f00, 0x7ffe, 0x7fff] {
        assert_eq!(unit.source(id), Source::Alias(SYN_TARGET), "{id:#x}");
    }
    // Below the range (the IOMMU itself included) and above the bus.
    for id in (0..0x18).chain([0x8000, 0xffff]) {
        assert_eq!(unit.source(id), Source::Undescribed, "{id:#x}");
    }
    assert_eq!(unit.aliased(), 256);
    assert_eq!(unit.entries.spans().len(), 2);
    assert_eq!(unit.entries.padding, 1);
    let specials = unit.entries.specials();
    assert_eq!(specials.len(), 3);
    assert_eq!(
        specials[1],
        Special {
            variety: Variety::IoApic,
            handle: 5,
            source: SYN_SOURCE,
            setting: 0x01
        }
    );
    let hids = unit.entries.hids();
    assert_eq!(hids.len(), 4);
    assert_eq!(&hids[3].hid, b"ABSD0001");
    assert_eq!(hids[3].uid(), b"\\_SB.SYN3");
    assert_eq!((hids[0].devid, hids[0].setting), (SYN_TARGET, 0x80));
}

#[test]
fn without_the_alias_the_synthetic_shape_has_no_deviation() {
    let bytes = syn_with(|blocks| {
        for block in blocks.iter_mut() {
            let tail = alias_range(0x7f00, 0x7fff, SYN_TARGET);
            let at = 8;
            block.entries.drain(at..at + tail.len());
        }
    });
    let unit = deviation_free(&bytes);
    assert_eq!(unit.source(0x7f00), Source::Own);
    assert_eq!(unit.source(0x7fff), Source::Undescribed);
}

#[test]
fn qemu_8_2_2_table_deviates_in_its_reserved_feature_field() {
    let (result, unit) = parse_full(&qemu());
    assert_eq!(
        result,
        Ok(Validation {
            deviations: unit.findings.total(),
            validated: VALIDATED_FIELDS,
            unvalidated: UNVALIDATED_FIELDS,
            dma_admission: Admission::NotEstablished
        })
    );
    assert_eq!(
        unit.findings.items(),
        [Finding {
            block: 0x10,
            offset: 48 + 20,
            field: Field::FeatureReserved,
            detail: Detail::Bits {
                raw: 0x44,
                unexpected: 0x44
            },
        }]
    );
    assert_eq!(Field::FeatureReserved.rule(), "reserved");
    // Described for the report all the same.
    assert_eq!(
        (unit.devid, unit.base, unit.used, unit.present),
        (0x0008, 0xfed8_0000, 0x10, 1)
    );
    assert_eq!(unit.entries.spans().len(), 5);
    assert_eq!(unit.entries.specials().len(), 1);
    // With that field zero there is no deviation.
    let unit = deviation_free(&qemu_conforming());
    assert_eq!((unit.efr, unit.attributes), (None, None));
    assert_eq!(unit.host_levels(), None);
    assert_eq!(unit.window(), 16 << 10);
    assert_eq!(unit.source(0x0008), Source::Own);
    assert_eq!(unit.source(0x0028), Source::Undescribed);
    assert_eq!(unit.entries.hids().len(), 0);
}

#[test]
fn every_reserved_field_is_a_finding() {
    // A 10h flags byte (PPRSup in bit 7) copied into 11h and 40h, where
    // bit 7 is reserved, and a reserved attribute bit set in both.
    let copied = syn_with(|blocks| {
        for block in &mut blocks[1..] {
            block.flags = 0xa0;
            block.word |= 1 << 9;
        }
        blocks[0].flags = 0xa0;
    });
    assert_eq!(
        findings(&copied),
        [
            Field::FlagsReserved,
            Field::AttributesReserved,
            Field::FlagsReserved,
            Field::AttributesReserved
        ]
    );
    // 10h flags bits 7:6 are PPRSup/PreFSup, not reserved.
    let ten = syn_with(|blocks| blocks[0].flags = 0xe0);
    clean(&ten);

    let header = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut bytes = syn();
        edit(&mut bytes);
        seal(&mut bytes);
        findings(&bytes)
    };
    assert_eq!(header(&|b| b[44] = 1), [Field::HeaderReserved]);
    assert_eq!(header(&|b| b[36] |= 0b100), [Field::IvinfoReserved]);
    assert_eq!(header(&|b| b[39] |= 0x80), [Field::IvinfoReserved]);
    let all = |edit: &dyn Fn(&mut Block)| syn_with(|blocks| blocks.iter_mut().for_each(edit));
    for bit in [5, 6, 7, 13, 14, 15] {
        assert_eq!(
            findings(&all(&|b| b.info |= 1 << bit)),
            [Field::InfoReserved; 3],
            "info bit {bit}"
        );
    }
    // UnitID and MsiNum are defined.
    clean(&all(&|b| b.info = 0x1f1f));
    for bit in [1, 12, 28, 31] {
        let bytes = syn_with(|blocks| blocks[1..].iter_mut().for_each(|b| b.word |= 1 << bit));
        assert_eq!(
            findings(&bytes),
            [Field::AttributesReserved; 2],
            "attribute bit {bit}"
        );
    }
    for bit in [26, 27, 30, 57, 60] {
        let bytes = syn_with(|blocks| blocks[1..].iter_mut().for_each(|b| b.efr |= 1 << bit));
        assert_eq!(findings(&bytes), [Field::EfrReserved; 2], "EFR bit {bit}");
    }
    // Defined EFR bits next to the reserved ones.
    for bit in [25, 28, 29, 31, 56, 61] {
        let bytes = syn_with(|blocks| blocks[1..].iter_mut().for_each(|b| b.efr |= 1 << bit));
        clean(&bytes);
    }
    for bit in [0, 10, 17, 63] {
        let bytes = syn_with(|blocks| blocks[1..].iter_mut().for_each(|b| b.efr2 |= 1 << bit));
        assert_eq!(findings(&bytes), [Field::Efr2Reserved; 2], "EFR2 bit {bit}");
    }
    // Defined EFR2 fields are carried, not validated: an image with every
    // defined bit set, reserved encodings of NumIntRemapSup (11b) and
    // SNPAVICSup (111b) included, raises no deviation. That is the stated
    // limit of the validated subset, not a claim that the image conforms.
    let unit = clean(&syn_with(|blocks| {
        blocks[1..].iter_mut().for_each(|b| b.efr2 = 0x1_fbfe)
    }));
    assert_eq!(unit.efr2, Some(0x1_fbfe));
    // Entry bytes that must be zero.
    let in_entries = |extra: Vec<u8>| {
        all(&|block| {
            let fixed = syn_fixed();
            let mut entries = [fixed, extra.clone()].concat();
            if block.kind == 0x40 {
                entries.extend(hid(SYN_TARGET, 0, b"ABSD0001", b"\\_SB.SYN0"));
            }
            block.entries = entries;
        })
    };
    assert_eq!(
        findings(&in_entries(e8(0x42, 0x8100, 0, 1, SYN_TARGET + 1, 0))),
        [Field::AliasReserved; 3]
    );
    assert_eq!(
        findings(&in_entries(e8(0x42, 0x8100, 0, 0, SYN_TARGET + 1, 4))),
        [Field::AliasReserved; 3]
    );
    let mut nonzero_devid = special(1, 9, SYN_SOURCE, 0);
    nonzero_devid[1] = 1;
    assert_eq!(
        findings(&in_entries(nonzero_devid)),
        [Field::SpecialDeviceId; 3]
    );
}

#[test]
fn reserved_and_constraint_rules_in_10h_and_hid_entries() {
    let only_10h = |flags: u8, word: u32| {
        let mut block = syn_block(0x10);
        block.flags = flags;
        block.word = word;
        table(2, SYN_IVINFO, &[block.bytes()])
    };
    // GATS set while GTSup is clear (Table 94); legal with GTSup set.
    assert_eq!(
        findings(&only_10h(0x20, SYN_FEATURE | (1 << 28))),
        [Field::GatsWithoutGtsup]
    );
    clean(&only_10h(0x20, SYN_FEATURE | (1 << 28) | FEATURE_GTSUP));
    // MsiNumPPR set while PPRSup (10h flags bit 7) is clear.
    assert_eq!(
        findings(&only_10h(0x20, SYN_FEATURE | (3 << 23))),
        [Field::MsiNumPprWithoutPprSup]
    );
    clean(&only_10h(0xa0, SYN_FEATURE | (3 << 23)));
    // Under EFRSup = 0 the whole field is reserved, whatever it says.
    let mut block = syn_block(0x10);
    block.word = SYN_FEATURE;
    block.base = 0xfed8_0000;
    assert_eq!(
        findings(&table(1, 0x3400, &[block.bytes()])),
        [Field::FeatureReserved]
    );

    let with_hid = |ivinfo: u32, entry: Vec<u8>| {
        let mut fixed = syn_block(0x11);
        fixed.entries = e4(1, 0, 0);
        let mut mixed = syn_block(0x40);
        mixed.entries = [e4(1, 0, 0), entry].concat();
        table(2, ivinfo, &[fixed.bytes(), mixed.bytes()])
    };
    let ok = |entry: Vec<u8>| clean(&with_hid(SYN_IVINFO, entry));
    // Integer, ACPI ID and PNP ID forms (Table 110 note 2).
    ok(hid(0x40, 0, &[0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0], b""));
    ok(hid(0x40, 0, b"ABSD0001", b""));
    ok(hid(0x40, 0, b"PNP0A0F\0", b""));
    ok(hid_entry(0x40, 0, b"ABSD0001", b"PNP0C02\0", b""));
    for bad in [[0xff; 8], [0; 8], *b"absd0001", *b"ABSD00G1", *b"AB_D0001"] {
        assert_eq!(
            findings(&with_hid(SYN_IVINFO, hid(0x40, 0, &bad, b""))),
            [Field::HidFormat],
            "{bad:?}"
        );
    }
    // Encoding constraints carry the whole value, not a bit subset.
    let (_, unit) = parse_full(&with_hid(SYN_IVINFO, hid(0x40, 0, &[0xff; 8], b"")));
    assert_eq!(
        unit.findings.items()[0].detail,
        Detail::Encoding { raw: u64::MAX }
    );
    let (_, unit) = parse_full(&with_hid(
        SYN_IVINFO | IVINFO_DMA_REMAP,
        hid(0x40, 0, b"ABSD0001", b""),
    ));
    assert_eq!(unit.findings.items()[0].detail, Detail::Encoding { raw: 0 });
    assert_eq!(
        findings(&with_hid(
            SYN_IVINFO,
            hid_entry(0x40, 0, b"ABSD0001", &[0xff; 8], b"")
        )),
        [Field::CidFormat]
    );
    // Pre-boot DMA protection: F0h entries need string UIDs (Table 88).
    let preboot = SYN_IVINFO | IVINFO_DMA_REMAP;
    assert_eq!(
        findings(&with_hid(preboot, hid(0x40, 0, b"ABSD0001", b""))),
        [Field::UidNotString]
    );
    let mut integer_uid = hid(0x40, 0, b"ABSD0001", b"\x01");
    integer_uid[20] = 1;
    assert_eq!(
        findings(&with_hid(preboot, integer_uid.clone())),
        [Field::UidNotString]
    );
    clean(&with_hid(SYN_IVINFO, integer_uid));
    let unit = parse_boxed(&with_hid(preboot, hid(0x40, 0, b"ABSD0001", b"\\_SB.SYN0")))
        .expect("string UID under pre-boot protection");
    assert!(unit.pre_boot_protection());
    // Extended setting bits 30:3.
    let mut block = syn_block(0x11);
    let mut select = e4(0x46, 0x10, 0);
    select.extend_from_slice(&0x08u32.to_le_bytes());
    block.entries = select;
    assert_eq!(
        findings(&table(2, SYN_IVINFO, &[block.bytes()])),
        [Field::ExtendedReserved]
    );
    // AtsDisabled (31) and CXLDevice (2:0) are defined.
    let mut select = e4(0x46, 0x10, 0);
    select.extend_from_slice(&0x8000_0007u32.to_le_bytes());
    block.entries = select;
    clean(&table(2, SYN_IVINFO, &[block.bytes()]));
}

#[test]
fn capability_offset_must_hold_the_whole_block() {
    assert_eq!(capability_registers(0x40), Some([0x40, 0x44, 0x48]));
    assert_eq!(capability_registers(0xe8), Some([0xe8, 0xec, 0xf0]));
    for bad in [0, 0x3c, 0x42, 0xec, 0xf0, 0xf4, 0xf8, 0xfc, 0x100, 0xffff] {
        assert_eq!(capability_registers(bad), None, "{bad:#x}");
    }
    // Through the parser, every offset: accepted exactly when the block
    // fits, and then each register the kernel reads is in config space.
    for cap in 0..=0x1ffu16 {
        let mut block = qemu_block();
        block.word = 0;
        block.capability = cap;
        let bytes = table(1, 0x2800, &[block.bytes()]);
        let fits = (0x40..=0xe8).contains(&cap) && cap % 4 == 0;
        match parse_boxed(&bytes) {
            Ok(unit) => {
                assert!(fits, "{cap:#x} accepted");
                let registers = unit.capability_registers().expect("registers");
                assert!(registers.iter().all(|&r| usize::from(r) + 4 <= 0x100));
            }
            Err(error) => {
                assert!(!fits, "{cap:#x} refused: {error:?}");
                assert_eq!(
                    error,
                    Error::CapabilityOffset {
                        offset: 48,
                        capability: cap
                    }
                );
                assert_eq!(error.class(), Class::Malformed);
            }
        }
    }
    // A wide block is checked too.
    let bytes = syn_with(|blocks| blocks[2].capability = 0xfc);
    assert!(matches!(
        refused(&bytes),
        Error::CapabilityOffset {
            capability: 0xfc,
            ..
        }
    ));
}

#[test]
fn header_refusals() {
    let good = syn();
    assert_eq!(refused(&good[..40]), Error::Short);
    let mut bytes = good.clone();
    bytes[0] = b'X';
    seal(&mut bytes);
    assert_eq!(refused(&bytes), Error::Signature);
    // Truncated: the header claims more bytes than were handed in.
    assert_eq!(refused(&good[..good.len() - 1]), Error::Length);
    let mut bytes = good.clone();
    bytes[60] ^= 1;
    assert_eq!(refused(&bytes), Error::Checksum);
    for revision in [0, 3, 0xff] {
        let mut bytes = good.clone();
        bytes[8] = revision;
        seal(&mut bytes);
        assert_eq!(refused(&bytes), Error::Revision(revision));
    }
    assert_eq!(refused(&table(2, SYN_IVINFO, &[])), Error::NoIvhd);
    for error in [
        Error::Short,
        Error::Signature,
        Error::Length,
        Error::Checksum,
        Error::Revision(3),
        Error::NoIvhd,
    ] {
        assert_eq!(error.class(), Class::Malformed, "{error:?}");
    }
}

fn ivmd(kind: u8, flags: u8) -> Vec<u8> {
    let mut block = vec![kind, flags, 32, 0];
    block.resize(32, 0);
    block[16..24].copy_from_slice(&0x10_0000u64.to_le_bytes());
    block[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
    block
}

#[test]
fn block_refusals() {
    for kind in [0x20, 0x21, 0x22] {
        let bytes = table(2, SYN_IVINFO, &[syn_block(0x11).bytes(), ivmd(kind, 0x07)]);
        let error = refused(&bytes);
        assert!(matches!(error, Error::Ivmd { kind: k, .. } if k == kind));
        assert_eq!(error.class(), Class::Unsupported);
    }
    // IVMD reserved flags, reserved bytes, reserved IDs, unity without
    // access: malformed, not merely unsupported.
    let mut reserved_bytes = ivmd(0x21, 0x07);
    reserved_bytes[12] = 1;
    let mut reserved_aux = ivmd(0x21, 0x07);
    reserved_aux[6] = 1;
    let mut reserved_id = ivmd(0x20, 0x07);
    reserved_id[4] = 1;
    for block in [
        ivmd(0x20, 0x17),
        reserved_bytes,
        reserved_aux,
        reserved_id,
        ivmd(0x22, 0x01),
    ] {
        let bytes = table(2, SYN_IVINFO, &[syn_block(0x11).bytes(), block]);
        let error = refused(&bytes);
        assert!(matches!(error, Error::IvmdMalformed { .. }), "{error:?}");
        assert_eq!(error.class(), Class::Malformed);
    }
    // Exclusion overrides IR/IW/Unity.
    let bytes = table(2, SYN_IVINFO, &[syn_block(0x11).bytes(), ivmd(0x20, 0x09)]);
    assert!(matches!(refused(&bytes), Error::Ivmd { .. }));
    let bytes = table(
        2,
        SYN_IVINFO,
        &[syn_block(0x11).bytes(), vec![0x30, 0, 8, 0, 0, 0, 0, 0]],
    );
    assert!(matches!(
        refused(&bytes),
        Error::UnknownBlock { kind: 0x30, .. }
    ));
    // Declared length past the table end, and below the header size.
    let mut block = syn_block(0x11).bytes();
    block[2] = 0xff;
    assert!(matches!(
        refused(&table(2, SYN_IVINFO, &[block])),
        Error::BlockLength { .. }
    ));
    let mut block = syn_block(0x11).bytes();
    block[2] = 39;
    block[3] = 0;
    assert!(matches!(
        refused(&table(2, SYN_IVINFO, &[block])),
        Error::BlockLength { .. }
    ));
    // A trailing fragment shorter than a block header.
    let mut bytes = syn();
    bytes.extend_from_slice(&[0x10, 0]);
    seal(&mut bytes);
    assert!(matches!(refused(&bytes), Error::BlockLength { .. }));
    // 40h in a revision 1 table; 11h without EFRSup.
    let bytes = table(
        1,
        SYN_IVINFO,
        &[syn_block(0x11).bytes(), syn_block(0x40).bytes()],
    );
    assert!(matches!(
        refused(&bytes),
        Error::BlockNotAllowed { kind: 0x40, .. }
    ));
    let bytes = table(2, SYN_IVINFO & !IVINFO_EFR_SUP, &[syn_block(0x11).bytes()]);
    assert!(matches!(
        refused(&bytes),
        Error::BlockNotAllowed { kind: 0x11, .. }
    ));
    // A block with only reserved entries.
    let mut block = syn_block(0x11);
    block.entries = vec![0; 4];
    assert!(matches!(
        refused(&table(2, SYN_IVINFO, &[block.bytes()])),
        Error::NoEntries { .. }
    ));
}

#[test]
fn single_block_tables_are_accepted() {
    let only_11h = table(2, SYN_IVINFO, &[syn_block(0x11).bytes()]);
    assert_eq!(parse_boxed(&only_11h).unwrap().used, 0x11);
    let only_10h = table(2, SYN_IVINFO, &[syn_block(0x10).bytes()]);
    let unit = parse_boxed(&only_10h).unwrap();
    assert_eq!(
        (unit.used, unit.host_levels(), unit.window()),
        (0x10, Some(6), 512 << 10)
    );
    // A 40h block alone describes the population (§5.2): used, with its
    // own HIDs.
    let only_40h = table(2, SYN_IVINFO, &[syn_block(0x40).bytes()]);
    let unit = parse_boxed(&only_40h).expect("40h only");
    assert_eq!((unit.used, unit.present), (0x40, 0b100));
    assert_eq!(unit.entries.hids().len(), 4);
    assert_eq!(unit.source(0x7f10), Source::Alias(SYN_TARGET));
    // 10h + 40h without 11h: 10h used, flags not compared across meanings.
    let ten_forty = syn_with(|blocks| blocks[0].flags = 0xa0);
    let mut blocks = [syn_block(0x10), syn_block(0x40)];
    blocks[0].flags = 0xa0;
    let bytes: Vec<Vec<u8>> = blocks.iter().map(Block::bytes).collect();
    let unit = parse_boxed(&table(2, SYN_IVINFO, &bytes)).expect("10h + 40h");
    assert_eq!((unit.used, unit.entries.hids().len()), (0x10, 4));
    clean(&ten_forty);
}

#[test]
fn unit_refusals() {
    // A second IOMMU: another DeviceID, or another capability block.
    let second = syn_with(|blocks| blocks[2].devid = SYN_DEVID + 1);
    assert!(matches!(refused(&second), Error::SecondUnit { .. }));
    let second = syn_with(|blocks| blocks[1].capability = 0x60);
    let error = refused(&second);
    assert!(matches!(error, Error::SecondUnit { .. }));
    assert_eq!(error.class(), Class::Unsupported);
    let bytes = syn_with(|blocks| blocks[0].base = SYN_BASE + (512 << 10));
    let error = refused(&bytes);
    assert_eq!(
        error,
        Error::Inconsistent {
            offset: 48 + syn_block(0x10).bytes().len(),
            field: "base"
        }
    );
    assert_eq!(error.class(), Class::Unsupported);
    // Segment: unsupported in 10h, malformed in 11h/40h (value 0000h).
    let mut ten = syn_block(0x10);
    ten.segment = 1;
    let error = refused(&table(2, SYN_IVINFO, &[ten.bytes()]));
    assert!(matches!(error, Error::Segment { segment: 1, .. }));
    assert_eq!(error.class(), Class::Unsupported);
    let error = refused(&syn_with(|blocks| blocks[1].segment = 1));
    assert!(matches!(error, Error::Segment { kind: 0x11, .. }));
    assert_eq!(error.class(), Class::Malformed);
    let error = refused(&table(
        2,
        SYN_IVINFO,
        &[syn_block(0x11).bytes(), syn_block(0x11).bytes()],
    ));
    assert!(matches!(error, Error::DuplicateBlock { .. }));
    assert_eq!(error.class(), Class::Unsupported);
    // 40h disagreeing with 11h.
    let bytes = syn_with(|blocks| blocks[2].efr ^= 1 << 40);
    assert!(matches!(
        refused(&bytes),
        Error::Inconsistent { field: "efr", .. }
    ));
    let bytes = syn_with(|blocks| blocks[2].word |= 1 << 18);
    assert!(matches!(
        refused(&bytes),
        Error::Inconsistent {
            field: "attributes",
            ..
        }
    ));
    let bytes = syn_with(|blocks| blocks[2].flags |= 1);
    assert!(matches!(
        refused(&bytes),
        Error::Inconsistent { field: "flags", .. }
    ));
    // The last special's DTE setting.
    let bytes = syn_with(|blocks| blocks[2].entries[43] = 0x80);
    assert!(matches!(
        refused(&bytes),
        Error::Inconsistent {
            field: "entries",
            ..
        }
    ));
    // The same fixed entries in another order agree.
    let reordered = syn_with(|blocks| {
        let fixed = syn_fixed();
        let hids = blocks[2].entries[fixed.len()..].to_vec();
        blocks[2].entries = [
            special(1, 6, SYN_SOURCE + 1, 0),
            special(2, 1, SYN_SOURCE, 0),
            alias_range(0x7f00, 0x7fff, SYN_TARGET),
            range(0x0018, 0x7ffe, 0),
            special(1, 5, SYN_SOURCE, 0x01),
            vec![0; 4],
            hids,
        ]
        .concat();
    });
    clean(&reordered);
    // Base: zero, not 512 KiB aligned with counters, beyond 52 bits.
    let set_base =
        |base: u64| syn_with(move |blocks| blocks.iter_mut().for_each(|b| b.base = base));
    assert_eq!(refused(&set_base(0)), Error::BaseRange(0));
    let error = refused(&set_base(SYN_BASE + 0x4000));
    assert_eq!(error, Error::BaseAlignment(SYN_BASE + 0x4000));
    assert_eq!(error.class(), Class::Malformed);
    assert!(matches!(refused(&set_base(1 << 52)), Error::BaseRange(_)));
    // Without counters 16 KiB alignment is enough, 4 KiB is not.
    let mut block = qemu_block();
    block.word = 0;
    block.base = 0xfed8_4000;
    clean(&table(1, 0x2800, &[block.bytes()]));
    block.base = 0xfed8_1000;
    assert_eq!(
        refused(&table(1, 0x2800, &[block.bytes()])),
        Error::BaseAlignment(0xfed8_1000)
    );
    // HATDis (valid, unsupported); HATS reserved (11b, malformed).
    let bytes = syn_with(|blocks| {
        blocks[1..]
            .iter_mut()
            .for_each(|b| b.word |= ATTRIBUTE_HAT_DIS)
    });
    let eleven = 48 + syn_block(0x10).bytes().len();
    let error = refused(&bytes);
    assert_eq!(
        error,
        Error::HostTranslationDisabled {
            offset: eleven + 20,
            kind: 0x11,
            raw: u64::from(SYN_ATTRIBUTES | ATTRIBUTE_HAT_DIS)
        }
    );
    assert_eq!(error.offset(), Some(eleven + 20));
    assert_eq!(error.class(), Class::Unsupported);
    let bytes = syn_with(|blocks| blocks[1..].iter_mut().for_each(|b| b.efr |= 3 << 10));
    let error = refused(&bytes);
    assert_eq!(
        error,
        Error::HatsReserved {
            offset: eleven + 24,
            kind: 0x11,
            raw: SYN_EFR | (3 << 10)
        }
    );
    assert_eq!(error.class(), Class::Malformed);
}

fn with_entries(entries: Vec<u8>) -> Vec<u8> {
    let mut block = syn_block(0x11);
    block.entries = entries;
    table(2, SYN_IVINFO, &[block.bytes()])
}

#[test]
fn entry_type_and_shape_refusals() {
    for kind in [0x05, 0x3f, 0x49, 0x7f, 0x80, 0xef, 0xf1] {
        let entry = if kind < 0x40 {
            e4(kind, 0x10, 0)
        } else if kind < 0x80 {
            e8(kind, 0x10, 0, 0, 0, 0)
        } else {
            hid(0x10, 0, b"ABSD0001", b"")
        };
        let mut entries = [e4(2, 0x08, 0), entry].concat();
        if kind >= 0x80 {
            entries[4] = kind;
        }
        let problem = entry_problem(&with_entries(entries));
        assert_eq!(problem, EntryProblem::UnknownType(kind), "{kind:#x}");
        assert_eq!(problem.class(), Class::Malformed);
    }
    // The reserved entries Tables 105 and 107 give as zero: skipped when
    // zero, malformed otherwise.
    for (kind, size) in [(0, 4), (0x40, 8), (0x41, 8), (0x44, 8), (0x45, 8)] {
        let mut entry = vec![0u8; size];
        entry[0] = kind;
        let unit = parse_boxed(&with_entries([e4(2, 8, 0), entry.clone()].concat()))
            .expect("zero reserved entry");
        assert_eq!(unit.entries.padding, 1, "{kind:#x}");
        entry[size - 1] = 1;
        assert_eq!(
            entry_problem(&with_entries([e4(2, 8, 0), entry].concat())),
            EntryProblem::Padding,
            "{kind:#x}"
        );
    }
    // A start followed by anything but an end, an end alone, a block that
    // stops inside a range, an end before its start.
    let unpaired = [e4(3, 0x10, 0), e4(2, 0x30, 0), e4(4, 0x20, 0)].concat();
    assert_eq!(
        entry_problem(&with_entries(unpaired)),
        EntryProblem::Unpaired
    );
    assert_eq!(
        entry_problem(&with_entries([e4(2, 8, 0), e4(4, 0x20, 0)].concat())),
        EntryProblem::Unpaired
    );
    assert_eq!(
        entry_problem(&with_entries([e4(2, 8, 0), e4(3, 0x10, 0)].concat())),
        EntryProblem::Unpaired
    );
    let open_alias = [e4(2, 0x40, 0), e8(0x43, 0x10, 0, 0, 0x40, 0)].concat();
    assert_eq!(
        entry_problem(&with_entries(open_alias)),
        EntryProblem::Unpaired
    );
    assert_eq!(
        entry_problem(&with_entries(range(0x20, 0x10, 0))),
        EntryProblem::Reversed
    );
    assert_eq!(
        entry_problem(&with_entries([e4(3, 0x10, 0), e4(4, 0x20, 1)].concat())),
        EntryProblem::EndSetting
    );
    // An 8-byte entry cut by the block end.
    assert_eq!(
        entry_problem(&with_entries([e4(2, 8, 0), e4(0x42, 0x10, 0)].concat())),
        EntryProblem::Truncated
    );
}

#[test]
fn special_and_hid_refusals() {
    let base = e4(2, 8, 0);
    assert_eq!(
        entry_problem(&with_entries(
            [base.clone(), special(3, 0, 0x38, 0)].concat()
        )),
        EntryProblem::SpecialVariety(3)
    );
    assert_eq!(
        entry_problem(&with_entries(
            [base.clone(), special(0, 0, 0x38, 0)].concat()
        )),
        EntryProblem::SpecialVariety(0)
    );
    let twice = [base.clone(), special(1, 5, 0x38, 0), special(1, 5, 0x39, 0)].concat();
    let problem = entry_problem(&with_entries(twice));
    assert_eq!(problem, EntryProblem::SpecialDuplicate);
    assert_eq!(problem.class(), Class::Unsupported);
    // The same handle as IOAPIC and as HPET is two devices.
    let both = [base.clone(), special(1, 0, 0x38, 0), special(2, 0, 0x38, 0)].concat();
    clean(&with_entries(both));
    // F0h outside a 40h block.
    let in_fixed = [base.clone(), hid(0x40, 0, b"ABSD0001", b"\\_SB.SYN0")].concat();
    assert_eq!(
        entry_problem(&with_entries(in_fixed)),
        EntryProblem::HidInFixedBlock
    );
    let mixed = |entries: Vec<u8>| {
        let mut fixed = syn_block(0x11);
        fixed.entries = e4(1, 0, 0);
        let mut mixed = syn_block(0x40);
        mixed.entries = entries;
        table(2, SYN_IVINFO, &[fixed.bytes(), mixed.bytes()])
    };
    let after = [
        e4(1, 0, 0),
        hid(0x40, 0, b"ABSD0001", b"\\_SB.SYN0"),
        e4(2, 8, 0),
    ]
    .concat();
    assert_eq!(entry_problem(&mixed(after)), EntryProblem::FixedAfterHid);
    let mut format = hid(0x40, 0, b"ABSD0001", b"\\_SB.SYN0");
    format[20] = 0;
    assert_eq!(
        entry_problem(&mixed([e4(1, 0, 0), format].concat())),
        EntryProblem::HidUid
    );
    let mut format = hid(0x40, 0, b"ABSD0001", b"\\_SB.SYN0");
    format[20] = 3;
    assert_eq!(
        entry_problem(&mixed([e4(1, 0, 0), format].concat())),
        EntryProblem::HidUid
    );
    // A valid UID longer than this parser keeps: unsupported, not malformed.
    let long = hid(0x40, 0, b"ABSD0001", &[b'x'; MAX_UID + 1]);
    let problem = entry_problem(&mixed([e4(1, 0, 0), long].concat()));
    assert_eq!(problem, EntryProblem::UidCapacity);
    assert_eq!(problem.class(), Class::Unsupported);
    let mut cut = hid(0x40, 0, b"ABSD0001", b"\\_SB.SYN0");
    cut.truncate(25);
    assert_eq!(
        entry_problem(&mixed([e4(1, 0, 0), cut].concat())),
        EntryProblem::Truncated
    );
    let short = hid(0x40, 0, b"ABSD0001", b"")[..20].to_vec();
    assert_eq!(
        entry_problem(&mixed([e4(1, 0, 0), short].concat())),
        EntryProblem::Truncated
    );
    // A UID-less entry is 22 bytes and fine.
    let bare = [e4(1, 0, 0), hid(0x40, 0, b"ABSD0001", b"")].concat();
    clean(&mixed(bare));
}

#[test]
fn the_tail_alias_is_the_only_overlap_accepted() {
    let accepted = |entries: Vec<u8>| {
        let unit = parse_boxed(&with_entries(entries)).expect("tail alias accepted");
        assert_eq!(unit.aliased(), 256);
    };
    let overlap = |entries: Vec<u8>, why: &str| {
        let problem = entry_problem(&with_entries(entries));
        assert_eq!(problem, EntryProblem::Overlap, "{why}");
        assert_eq!(problem.class(), Class::Malformed);
    };
    // Accepted: the alias bus over the range's tail, ending past it, at
    // it, or with the range ending inside the bus.
    accepted([range(0x0018, 0x7ffe, 0), alias_range(0x7f00, 0x7fff, 0x40)].concat());
    accepted([range(0x0018, 0x7fff, 0), alias_range(0x7f00, 0x7fff, 0x40)].concat());
    accepted([range(0x0018, 0x7f00, 0), alias_range(0x7f00, 0x7fff, 0x40)].concat());
    // Either order in the block.
    accepted([alias_range(0x7f00, 0x7fff, 0x40), range(0x0018, 0x7ffe, 0)].concat());
    let tail = || alias_range(0x7f00, 0x7fff, 0x40);
    // Refused: plain over plain, even an equal restatement.
    overlap(
        [e4(1, 0, 0), e4(2, 0x0008, 0)].concat(),
        "All + Select, equal settings",
    );
    overlap(
        [range(0x08, 0xff, 0), e4(2, 0x10, 0)].concat(),
        "Range + Select, equal settings",
    );
    overlap(
        [range(0x08, 0xff, 0), e4(2, 0x10, 0x01)].concat(),
        "Range + Select, different settings",
    );
    overlap(
        [range(0x08, 0xff, 0), extended_range(0x80, 0x1ff, 0)].concat(),
        "Range + extended range",
    );
    // Refused: the alias over anything but a type 3 range's tail.
    overlap(
        [e4(1, 0, 0), e8(0x42, 0x0128, 0, 0, 0x0120, 0)].concat(),
        "alias select over All",
    );
    overlap([e4(1, 0, 0), tail()].concat(), "alias range over All");
    overlap(
        [range(0x0018, 0x7ffe, 0), e8(0x42, 0x7f10, 0, 0, 0x40, 0)].concat(),
        "alias select over a range",
    );
    overlap(
        [range(0x0018, 0x7eff, 0), e4(2, 0x7f10, 0), tail()].concat(),
        "alias range over a select",
    );
    overlap(
        [extended_range(0x0018, 0x7ffe, 0), tail()].concat(),
        "alias range over an extended range",
    );
    overlap(
        [range(0x7f00, 0x7ffe, 0), tail(), e4(2, 0x40, 0)].concat(),
        "alias over the range's start",
    );
    overlap(
        [range(0x0018, 0x8100, 0), tail()].concat(),
        "alias inside the range, not its tail",
    );
    overlap(
        [range(0x0018, 0x7ffe, 0), alias_range(0x7f80, 0x7fff, 0x40)].concat(),
        "alias not one whole bus",
    );
    overlap(
        [range(0x0018, 0x7ffe, 0), alias_range(0x7e00, 0x7fff, 0x40)].concat(),
        "alias over two buses",
    );
    overlap(
        [
            range(0x0018, 0x7ffe, 0),
            e8(0x43, 0x7f00, 0x01, 0, 0x40, 0),
            e4(4, 0x7fff, 0),
        ]
        .concat(),
        "different DTE setting",
    );
    overlap(
        [
            range(0x0018, 0x7ffe, 0),
            tail(),
            range(0x8010, 0x81fe, 0),
            alias_range(0x8100, 0x81ff, 0x40),
        ]
        .concat(),
        "a second tail alias",
    );
    // Two aliases over one DeviceID, even to the same target.
    assert_eq!(
        entry_problem(&with_entries(
            [
                range(0x0018, 0x00ff, 0),
                alias_range(0x0100, 0x01ff, 0x40),
                e8(0x42, 0x0110, 0, 0, 0x40, 0)
            ]
            .concat()
        )),
        EntryProblem::AliasOverlap
    );
    // Alias target not in the device list, or itself aliased.
    let undeclared = [range(0x100, 0x1ff, 0), alias_range(0x200, 0x2ff, 0x00b4)].concat();
    assert_eq!(
        entry_problem(&with_entries(undeclared)),
        EntryProblem::AliasTargetUndeclared
    );
    let chain = [
        range(0x0018, 0x00ff, 0),
        e8(0x42, 0x0100, 0, 0, 0x0200, 0),
        e8(0x42, 0x0200, 0, 0, 0x0030, 0),
    ]
    .concat();
    assert_eq!(
        entry_problem(&with_entries(chain)),
        EntryProblem::AliasTargetUndeclared
    );
    let chain = [
        range(0x0018, 0x00ff, 0),
        e8(0x42, 0x0100, 0, 0, 0x0101, 0),
        e8(0x42, 0x0101, 0, 0, 0x0030, 0),
    ]
    .concat();
    assert_eq!(
        entry_problem(&with_entries(chain)),
        EntryProblem::AliasTargetUndeclared
    );
    let chain = [
        range(0x0018, 0x7ffe, 0),
        alias_range(0x7f00, 0x7fff, 0x7f20),
    ]
    .concat();
    assert_eq!(
        entry_problem(&with_entries(chain)),
        EntryProblem::AliasChain
    );
    // Aliases that overlap nothing are ordinary.
    let separate = [
        range(0x0018, 0x00ff, 0),
        alias_range(0x0100, 0x01ff, 0x40),
        e8(0x42, 0x0200, 0, 0, 0x41, 0),
    ]
    .concat();
    clean(&with_entries(separate));
}

#[test]
fn bounded_entry_counts() {
    let many: Vec<u8> = (0..=MAX_SPANS as u16)
        .flat_map(|id| e4(2, 8 + id, 0))
        .collect();
    let problem = entry_problem(&with_entries(many));
    assert_eq!(problem, EntryProblem::TooMany);
    assert_eq!(problem.class(), Class::Unsupported);
    let specials: Vec<u8> = [e4(2, 8, 0)]
        .into_iter()
        .chain((0..=MAX_SPECIALS as u8).map(|h| special(1, h, 0x38, 0)))
        .flatten()
        .collect();
    assert_eq!(
        entry_problem(&with_entries(specials)),
        EntryProblem::TooMany
    );
    // Every finding is kept up to MAX_FINDINGS; past it the table is
    // refused rather than reported incompletely.
    let reserved_aliases = |n: u16| -> Vec<u8> {
        (0..n)
            .flat_map(|id| e8(0x42, 0x100 + id, 0, 1, 0x40, 0))
            .chain(e4(2, 0x40, 0))
            .collect()
    };
    let mut block = syn_block(0x11);
    block.entries = reserved_aliases(20);
    let (result, unit) = parse_full(&table(2, SYN_IVINFO, &[block.bytes()]));
    assert_eq!(
        result,
        Ok(Validation {
            deviations: unit.findings.total(),
            validated: VALIDATED_FIELDS,
            unvalidated: UNVALIDATED_FIELDS,
            dma_admission: Admission::NotEstablished
        })
    );
    assert_eq!(unit.findings.items().len(), 20);
    let three = syn_with(|blocks| {
        for block in blocks.iter_mut() {
            block.entries = reserved_aliases(31);
        }
    });
    let error = refused(&three);
    assert_eq!(error, Error::TooManyDeviations);
    assert_eq!(error.class(), Class::Unsupported);
    // Exactly 64 findings before the last check that can add one (the
    // superseded 10h HATS): the 65th still refuses (codex-r3 reproducer).
    let mut bytes = syn_with(|blocks| {
        for block in blocks.iter_mut() {
            block.entries = reserved_aliases(21);
        }
        blocks[0].word &= !(3 << 30);
    });
    bytes[40] = 1;
    seal(&mut bytes);
    assert_eq!(refused(&bytes), Error::TooManyDeviations);
    // Without the HATS disagreement the 64 are returned in full.
    let mut bytes = syn_with(|blocks| {
        for block in blocks.iter_mut() {
            block.entries = reserved_aliases(21);
        }
    });
    bytes[40] = 1;
    seal(&mut bytes);
    assert_eq!(parse_full(&bytes).1.findings.items().len(), MAX_FINDINGS);
    // Every Bits finding's unexpected bits lie within its raw value.
    let (_, unit) = parse_full(&qemu());
    for finding in unit.findings.items() {
        if let Detail::Bits { raw, unexpected } = finding.detail {
            assert_eq!(unexpected & !raw, 0);
        }
    }
}

#[test]
fn every_single_byte_corruption_is_handled() {
    // No panic over these finite corruptions (evidence, not a proof of
    // every bound); whatever is not refused names a capability whose
    // registers lie in configuration space.
    for good in [syn(), qemu()] {
        for at in 0..good.len() {
            for value in [
                0x00, 0x01, 0x04, 0x40, 0x43, 0x48, 0x80, 0xf0, 0xf8, 0xfc, 0xff,
            ] {
                let mut bytes = good.clone();
                bytes[at] = value;
                seal(&mut bytes);
                let (result, unit) = parse_full(&bytes);
                if result.is_ok() {
                    assert!(unit.capability_registers().is_some(), "byte {at}");
                }
            }
        }
        for cut in HEADER_BYTES..good.len() {
            let mut bytes = good[..cut].to_vec();
            seal(&mut bytes);
            let _ = parse_boxed(&bytes);
        }
    }
}

#[test]
fn register_window_placement() {
    let rows = [
        (0, 0x9fc00, 1),
        (0x10_0000, 0x7ff0_0000, 1),
        (0xf700_0000, 0x0100_0000, 2),
    ];
    assert_eq!(
        placement(SYN_BASE, 512 << 10, rows.into_iter()),
        Ok(Placement::Reserved)
    );
    assert_eq!(
        placement(0xfed8_0000, 16 << 10, rows.into_iter()),
        Ok(Placement::Unlisted)
    );
    // Inside usable RAM, or straddling into it, or in ACPI NVS.
    assert_eq!(placement(0x4000_0000, 16 << 10, rows.into_iter()), Err(1));
    assert_eq!(placement(0x7fff_c000, 16 << 10, rows.into_iter()), Err(1));
    let nvs = [(SYN_BASE, 0x1000, 4)];
    assert_eq!(placement(SYN_BASE, 512 << 10, nvs.into_iter()), Err(4));
    // A row touching but not overlapping does not count.
    let touching = [(SYN_BASE - 0x8_0000, 0x8_0000, 1)];
    assert_eq!(
        placement(SYN_BASE, 512 << 10, touching.into_iter()),
        Ok(Placement::Unlisted)
    );
}

/// A model of the table QEMU 10.2.1 builds for `-device amd-iommu` on q35,
/// from reading its `build_amd_iommu` (hw/i386/acpi-build.c at v10.2.1;
/// values only, nothing copied): revision 1, IVinfo EFRSup | PAsize 40, a
/// 10h block whose feature field keeps only GTSup and GASup (its HATS and
/// GATS shifts overflow the 32-bit field, so HATS reads 00b), and an 11h
/// block with flags HtTunEn | IotlbSup and the EFR image PreFSup, PPRSup,
/// GTSup, IASup, GASup, HESup, GATS 10b, HATS 10b. Not an observed table.
fn qemu_10_2_1_model(dma_translation: bool) -> Vec<u8> {
    let mut ten = qemu_block();
    ten.word = 0x44;
    let mut eleven = qemu_block();
    eleven.kind = 0x11;
    eleven.flags = 0x11;
    eleven.word = if dma_translation {
        0
    } else {
        ATTRIBUTE_HAT_DIS
    };
    eleven.efr = 0x29d3 | if dma_translation { 0 } else { 3 << 10 };
    table(1, 0x2801, &[ten.bytes(), eleven.bytes()])
}

#[test]
fn qemu_10_2_1_model_deviates_only_in_its_superseded_hats() {
    let (result, unit) = parse_full(&qemu_10_2_1_model(true));
    assert_eq!(
        result,
        Ok(Validation {
            deviations: unit.findings.total(),
            validated: VALIDATED_FIELDS,
            unvalidated: UNVALIDATED_FIELDS,
            dma_admission: Admission::NotEstablished
        })
    );
    assert_eq!(
        unit.findings.items(),
        [Finding {
            block: 0x10,
            offset: 48 + 20,
            field: Field::HatsDisagrees,
            detail: Detail::Hats {
                raw: 0x44,
                table: 0,
                efr: 2
            },
        }]
    );
    assert_eq!(
        (unit.used, unit.host_levels(), unit.window()),
        (0x11, Some(6), 16 << 10)
    );
    // With dma-translation=off: HATDis, and HATS 11b beside it.
    assert!(matches!(
        refused(&qemu_10_2_1_model(false)),
        Error::HostTranslationDisabled { kind: 0x11, .. }
    ));
}

#[test]
fn reserved_encodings_of_consumed_and_validated_fields() {
    // HATS 11b in a superseded 10h block refuses, though 11h is used.
    let bytes = syn_with(|blocks| blocks[0].word |= 3 << 30);
    assert_eq!(
        refused(&bytes),
        Error::HatsReserved {
            offset: 48 + 20,
            kind: 0x10,
            raw: u64::from(SYN_FEATURE | (3 << 30))
        }
    );
    // HATDis in an unused 40h block beside a used 10h, with HATS 11b
    // there: refused (HATDis is checked in every wide block).
    let mut blocks = [syn_block(0x10), syn_block(0x40)];
    blocks[1].word |= ATTRIBUTE_HAT_DIS;
    blocks[1].efr |= 3 << 10;
    let bytes: Vec<Vec<u8>> = blocks.iter().map(Block::bytes).collect();
    assert!(matches!(
        refused(&table(2, SYN_IVINFO, &bytes)),
        Error::HostTranslationDisabled { kind: 0x40, .. }
    ));
    // HATS 11b beside HATDis: host translation is off, refused as such.
    let bytes = syn_with(|blocks| {
        blocks[1..].iter_mut().for_each(|b| {
            b.efr |= 3 << 10;
            b.word |= ATTRIBUTE_HAT_DIS;
        })
    });
    assert!(matches!(
        refused(&bytes),
        Error::HostTranslationDisabled { .. }
    ));
    // GATS 11b with GTSup: a deviation in the 10h field and in EFR images.
    let mut block = syn_block(0x10);
    block.word = SYN_FEATURE | FEATURE_GTSUP | FEATURE_GATS;
    assert_eq!(
        findings(&table(2, SYN_IVINFO, &[block.bytes()])),
        [Field::GatsReserved]
    );
    block.word = SYN_FEATURE | FEATURE_GTSUP | (2 << 28);
    clean(&table(2, SYN_IVINFO, &[block.bytes()]));
    let bytes = syn_with(|blocks| {
        blocks[1..]
            .iter_mut()
            .for_each(|b| b.efr |= EFR_GTSUP | EFR_GATS)
    });
    assert_eq!(findings(&bytes), [Field::GatsReserved; 2]);
    // GATS in the EFR without GTSup is "not meaningful" there, not reserved.
    let bytes = syn_with(|blocks| blocks[1..].iter_mut().for_each(|b| b.efr |= EFR_GATS));
    clean(&bytes);
    // A superseded 10h HATS that differs from the EFR image.
    let bytes = syn_with(|blocks| blocks[0].word = (SYN_FEATURE & !(3 << 30)) | (1 << 30));
    assert_eq!(findings(&bytes), [Field::HatsDisagrees]);
}

#[test]
fn decision_interface_exposes_only_validated_fields() {
    // What the types do ensure (module documentation; the rest is a review
    // rule): `Unit`'s public fields are validated ones, the raw images are
    // private, and `Unit::images` only formats them.
    let source = include_str!("../ivrs.rs");
    let body = &source[source.find("pub struct Unit {").unwrap()..];
    let body = &body[..body.find("\n}\n").unwrap()];
    let public: Vec<&str> = body
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pub "))
        .filter_map(|l| l.split(':').next())
        .collect();
    assert_eq!(
        public,
        [
            "struct Unit {",
            "revision",
            "devid",
            "capability",
            "base",
            "segment",
            "used",
            "present",
            "entries",
            "findings"
        ]
    );
    for private in [
        "ivinfo",
        "info",
        "flags",
        "feature",
        "attributes",
        "efr",
        "efr2",
    ] {
        assert!(
            body.contains(&std::format!("\n    {private}:")),
            "{private}"
        );
    }
    // `Images` has no readable field outside this module, and `Unit` has
    // no `Debug` outside tests.
    let images = &source[source.find("pub struct Images {").unwrap()..];
    let images = &images[..images.find("\n}\n").unwrap()];
    assert!(!images.lines().skip(1).any(|l| l.trim().starts_with("pub ")));
    assert!(source.contains("#[cfg_attr(test, derive(Debug))]\npub struct Unit {"));
    let unit = clean(&syn());
    let report = std::format!("{} {}", unit.images().header(), unit.images().efr());
    assert_eq!(
        report,
        "info=0x0000 flags=0x20 efr=0x0000000000000a42 efr2=0x0"
    );
    // The validated and unvalidated lists do not overlap.
    for field in UNVALIDATED_FIELDS {
        assert!(!VALIDATED_FIELDS.contains(field), "{field}");
    }
    // The accessors decisions may use read only validated bits: flipping
    // every carried EFR field (all but HATS, PCSup, GATS, reserved) leaves
    // them unchanged.
    let carried = !(EFR_RESERVED | (3 << 10) | EFR_PC_SUP | EFR_GATS);
    let a = clean(&syn());
    let b = clean(&syn_with(|blocks| {
        blocks[1..]
            .iter_mut()
            .for_each(|b| b.efr ^= carried & !EFR_GTSUP)
    }));
    assert_eq!(
        (a.host_levels(), a.window(), a.pre_boot_protection()),
        (b.host_levels(), b.window(), b.pre_boot_protection())
    );
}
