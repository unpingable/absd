//! AMD-Vi discovery: the ACPI IVRS table, parsed and checked against AMD
//! I/O Virtualization Technology (IOMMU) Specification #48882 rev 3.11
//! (§5.2, Tables 85–113; capability registers §3.2; EFR/EFR2, MMIO
//! Offsets 0030h and 01A0h).
//!
//! Pure: the kernel hands in the bytes `acpi::read_table` validated
//! (src/acpi_boot.rs), and everything here runs in host tests. Nothing is
//! programmed, and no outcome of [`parse`] is permission to program
//! anything.
//!
//! ## Two layers
//!
//! **Refused** (`Err`): the table cannot be relied on structurally, or it
//! is outside this backend's scope. Length, checksum, revision, block and
//! entry layout and bounds, undefined block or entry types, range pairing,
//! overlaps other than the one tolerated shape, alias targets and chains,
//! capability offset placement, base alignment and range, segment, one
//! unit, IVMD (well formed: unsupported; reserved bits set: malformed),
//! agreement between the blocks of one unit, HATDis, and the reserved
//! encodings of fields the enforcement path will consume (HATS = 11b in any
//! block, the superseded 10h included; F0h UID format; special variety).
//! Each refusal is classed [`Class::Malformed`] (breaks a stated rule) or
//! [`Class::Unsupported`] (valid but out of scope, or two descriptions ABSD
//! will not choose between).
//!
//! **Not refused** (`Ok(Validation)`): structurally valid, and the result
//! says so through separate properties, never one word: the deviations
//! found (each a [`Finding`]: block type, byte offset of the field, field,
//! and a typed [`Detail`]: raw value with the offending bits, a disallowed
//! encoding, the two disagreeing HATS codes, or the tolerated alias
//! range), the fields validated
//! ([`VALIDATED_FIELDS`]), the fields carried unvalidated
//! ([`UNVALIDATED_FIELDS`]), and DMA admission, which increment 2 never
//! establishes. Conformance is not capability: a table with deviations
//! could later be admitted under a named, reviewed quirk for an exact
//! deviation (owner decision, coordination record#111, 2026-10-30; none exists),
//! and a table with none may still be refused as unsupported. "No
//! deviation" means none *within the validated subset*, not conformance
//! to rev 3.11 in every field.
//!
//! Rule for consumers: no field may influence an enforcement decision unless
//! its semantics are validated. That rule is kept by review of the
//! consumers, not guaranteed by the types. The types make the plain
//! misuse unavailable: the unvalidated images are private to [`Unit`],
//! [`Unit::images`] only formats them, and `Unit` has no `Debug` outside
//! host tests. They do not stop safe code from reading the diagnostic
//! payload of a deviation ([`Finding::detail`], which carries the raw field
//! it is about) or of a refusal. Increment 2 has no enforcement consumer;
//! the one consumer (src/acpi_boot.rs) only reports.
//!
//! ## Reserved fields: the firmware's requirement and ABSD's policy
//!
//! Rev 3.11 "Conventions" (p. 29) requires of the writer: "Reserved fields
//! in a memory location must be zero." The specification does not
//! prescribe what an OS reading an IVRS must do with a table that breaks
//! that requirement. ABSD's chosen policy: a nonzero reserved field in the
//! validated subset is a deviation, never silently ignored
//! and never silently cleared; a reserved *encoding* of a field the
//! enforcement path consumes refuses the table.
//!
//! ## The validated subset
//!
//! - IVRS header: signature, length, checksum, revision (01h/02h),
//!   reserved bytes 40–47; IVinfo EFRSup (bit 0) and DMA remap (bit 1)
//!   consumed, reserved bits 31:23 and 4:2 checked. IVinfo HtAtsResv,
//!   VAsize, PAsize, GVAsize: carried, not validated.
//! - Every IVHD (10h, 11h, 40h): type, length, DeviceID, capability offset,
//!   base, segment, IOMMU info reserved bits 15:13 and 7:5 (UnitID, MSInum
//!   carried, not validated), and for 11h/40h flags reserved bits 7:6
//!   (flag bits 5:0 and 10h flags carried as recommendations, not
//!   validated).
//! - 10h feature field: whole field reserved without EFRSup; with EFRSup,
//!   HATS (consumed; 11b refuses), PNBanks/PNCounters (consumed only as
//!   "counters present", for the window size), GATS (11b with GTSup is a
//!   deviation; nonzero without GTSup is a deviation), MsiNumPPR (nonzero
//!   without the 10h PPRSup flag is a deviation). PASmax, HESup, GASup,
//!   IASup, GLXSup, GTSup, NXSup, XTSup: carried, not validated.
//! - 11h/40h attributes: HATDis (consumed; set refuses), reserved bits
//!   31:28 and 12:1 (Table 102's "12:0" read as 12:1 beside HATDis);
//!   MsiNumPPR, PNBanks, PNCounters carried, not validated.
//! - EFR image: HATS (consumed; 11b refuses unless HATDis), PCSup
//!   (consumed: window size), GATS (11b with GTSup is a deviation), IASup
//!   (a defined single bit, consumed by increment 3 to decide whether
//!   INVALIDATE_IOMMU_ALL is issued), PerfOptSup (a defined single bit,
//!   consumed by increment 3 to decide whether PerfOptEn must be cleared),
//!   reserved bits 60:57, 30, 27:26.
//!   **Every other EFR field is carried as an
//!   unvalidated image**, encodings unchecked: SNPSup, ForcePhyDestSup,
//!   V2HADDisSup, VMGuardIOSup, vIommuSup, InvIotlbTypeSup, V2HDDisSup,
//!   HDSup, AttrFWSup, EPHSup, HASup, GIoSup, SnoopAttrSup, MsiCapMmioSup,
//!   BlkStopMrkSup, MarcSup, PPRAutoRspSup, PprOvrflwEarlySup,
//!   DevTblSegSup, USSup, PASmax, SATSSup, DualEventLogSup, DualPprLogSup,
//!   GAMSup, SmiFRC, SmiFSup, GLXSup, HESup, GASup, GAPPISup, GTSup,
//!   NXSup, XTSup, PPRSup, PreFSup.
//! - EFR2 image: reserved bits 63:17, 10, 0 only; **every defined EFR2
//!   field is carried unvalidated** (SmeTioSupDis, XteeSup,
//!   SnpPageMode0Sup, HpteRsvdBitsMode, HTRangeIgnore, NumIntRemapSup,
//!   SNPAVICSup, GAPPIDisSup, GCR3TRPModeSup, TMPMSup, SevSnpIoSup).
//! - Device entries (the scope the enforcement path consumes): every type
//!   and length; reserved entries (0, 40h, 41h, 44h, 45h) all zero;
//!   range pairing and order; type 4 setting 00h; alias bytes 4 and 7
//!   (deviation); special DeviceID 0000h (deviation) and variety (refuses);
//!   extended setting bits 30:3 (deviation); F0h placement, ordering, UID
//!   format and length (refuses), HID/CID representation and string UIDs
//!   under DMA remap (deviations; the ACPI/PNP character classes come from
//!   the ACPI specification, not pinned here). DTE setting bytes and the
//!   extended setting's defined bits are carried, not interpreted.
//! - Agreement: 10h, 11h and 40h for one unit agree on base and segment;
//!   40h repeats the used block's fixed entries (any order), flags, info,
//!   attributes and EFR images; a superseded 10h HATS that differs from
//!   the used EFR image is a deviation.
//!
//! The block used is 11h, else 10h, else 40h (§5.2: 11h supersedes 10h; a
//! 40h block may describe the whole population).
//!
//! ## Device entry overlaps
//!
//! "Each DeviceID is described by one IVHD device entry" (§5.2.2.1), and an
//! alias may not lie over an All, Select or Start of Range entry for the
//! same peripherals. Every overlap is refused but one, which firmware the
//! backend targets uses and whose meaning is not in doubt; it is accepted
//! **as a named deviation** ([`Field::AliasOverRangeTail`]), so a table
//! with it always reports that deviation: a plain type 3 range `[p0, p1]` and an
//! Alias Start of Range (43h) `[a0, a1]` such that `[a0, a1]` is exactly
//! one whole bus, `p0 < a0 <= p1 <= a1`, equal DTE settings, at most once
//! per block ([`tail_alias`]). The alias wins for those IDs. Its target
//! must be named by a plain entry and not aliased.

pub const HEADER_BYTES: usize = 48;
/// Plain and alias entries kept per block (ranges count once).
pub const MAX_SPANS: usize = 32;
pub const MAX_SPECIALS: usize = 16;
pub const MAX_HIDS: usize = 8;
/// Longest ACPI UID kept for an F0h entry; a longer one is valid but
/// unsupported.
pub const MAX_UID: usize = 16;
/// Deviations kept. A table with more is refused (unsupported), so a
/// returned list is always complete.
pub const MAX_FINDINGS: usize = 64;

/// IVinfo bit 0: extended feature support (11h/40h blocks are meaningful).
pub const IVINFO_EFR_SUP: u32 = 1;
/// IVinfo bit 1: firmware used the IOMMU for pre-boot DMA protection.
pub const IVINFO_DMA_REMAP: u32 = 1 << 1;
/// IVinfo bits 31:23 and 4:2 must be zero (Table 88).
const IVINFO_RESERVED: u32 = 0xff80_0000 | 0b1_1100;
/// 11h/40h flags bits 7:6 are reserved (Tables 97, 101); in 10h they are
/// PPRSup and PreFSup (Table 92).
const FLAGS_RESERVED_WIDE: u8 = 0xc0;
const FLAGS_PPR_SUP: u8 = 0x80;
/// IOMMU info bits 15:13 and 7:5 (Table 93).
const INFO_RESERVED: u16 = 0xe0e0;
/// 11h/40h attributes bits 31:28 and 12:1 (Tables 98, 102).
const ATTRIBUTES_RESERVED: u32 = 0xf000_0000 | 0x1ffe;
/// 10h feature field (Table 94).
const FEATURE_GTSUP: u32 = 1 << 2;
const FEATURE_GATS: u32 = 3 << 28;
const FEATURE_MSI_NUM_PPR: u32 = 0x1f << 23;
/// EFR (MMIO 0030h) reserved bits 60:57, 30, 27:26.
const EFR_RESERVED: u64 = (0xf << 57) | (1 << 30) | (3 << 26);
/// EFR2 (MMIO 01A0h) reserved bits 63:17, 10, 0.
const EFR2_RESERVED: u64 = !0x1_ffff | (1 << 10) | 1;
/// Extended DTE setting bits 30:3 must be zero (Table 108).
const EXTENDED_RESERVED: u32 = 0x7fff_fff8;
/// IVMD flags 7:4 must be zero (Table 113).
const IVMD_FLAGS_RESERVED: u8 = 0xf0;

/// IVHD type 11h/40h attributes bit 0 (Tables 98, 102).
pub const ATTRIBUTE_HAT_DIS: u32 = 1;
/// EFR (MMIO 0030h) bit 9: performance counters, so a 512 KiB register
/// window (§3.2, Capability Offset 04h).
pub const EFR_PC_SUP: u64 = 1 << 9;
const EFR_HATS_SHIFT: u32 = 10;
/// EFR GTSup (bit 4) and GATS (13:12, 11b reserved).
const EFR_GTSUP: u64 = 1 << 4;
const EFR_GATS: u64 = 3 << 12;

/// The IOMMU capability block's registers, Capability Offsets 00h–14h
/// (§3.2): it must lie whole in conventional configuration space, at a
/// dword-aligned offset from 40h (PCI capability list rules).
pub const CAPABILITY_BLOCK_BYTES: u16 = 0x18;
const CONFIG_SPACE_BYTES: u16 = 0x100;

const SMALL_WINDOW: u64 = 16 << 10;
const LARGE_WINDOW: u64 = 512 << 10;
const PHYSICAL_LIMIT: u64 = 1 << 52;

/// What a refusal says about the table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    /// It breaks a rule rev 3.11 states (layout, bounds, a reserved field
    /// or encoding, a "must").
    Malformed,
    /// It is valid, but outside what this backend implements, or it gives
    /// two descriptions ABSD will not choose between.
    Unsupported,
}

impl Class {
    pub fn name(&self) -> &'static str {
        match self {
            Class::Malformed => "malformed",
            Class::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryProblem {
    /// A device entry type rev 3.11 does not define.
    UnknownType(u8),
    /// The entry runs past the end of its block.
    Truncated,
    /// A reserved entry (type 0, 40h, 41h, 44h, 45h) that is not all zero.
    Padding,
    /// A range start not immediately followed by a type 4 end, or an end
    /// with no start, or a block that ends inside a range.
    Unpaired,
    /// A range whose end precedes its start.
    Reversed,
    /// A type 4 entry with a nonzero DTE setting byte (Table 105: 00h).
    EndSetting,
    /// Special device variety other than IOAPIC (1) or HPET (2).
    SpecialVariety(u8),
    /// The same IOAPIC or HPET handle listed twice (unsupported: two
    /// sources for one handle).
    SpecialDuplicate,
    /// An ACPI HID (F0h) entry in a 10h or 11h block.
    HidInFixedBlock,
    /// A fixed-length entry after a variable-length one (§5.2.2.1).
    FixedAfterHid,
    /// An F0h entry whose UID format is reserved or disagrees with its
    /// length.
    HidUid,
    /// An F0h UID longer than [`MAX_UID`] (unsupported).
    UidCapacity,
    /// More entries than this parser keeps (unsupported).
    TooMany,
    /// Two entries name one DeviceID, other than the accepted alias shape.
    Overlap,
    /// Two alias entries name the same DeviceID.
    AliasOverlap,
    /// An alias target that no plain entry names.
    AliasTargetUndeclared,
    /// An alias target that is itself aliased.
    AliasChain,
}

impl EntryProblem {
    pub fn class(&self) -> Class {
        match self {
            EntryProblem::SpecialDuplicate | EntryProblem::UidCapacity | EntryProblem::TooMany => {
                Class::Unsupported
            }
            _ => Class::Malformed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Fewer bytes than the 48-byte header.
    Short,
    Signature,
    /// The header's length differs from the bytes handed in.
    Length,
    Checksum,
    /// Revision 03h–FFh, reserved (Table 87).
    Revision(u8),
    /// A block's length is below its header size or runs past the table.
    BlockLength {
        offset: usize,
    },
    /// A block type that is neither IVHD nor IVMD.
    UnknownBlock {
        offset: usize,
        kind: u8,
    },
    /// An IVMD block with reserved bits set or a forbidden flag
    /// combination (Tables 111–113).
    IvmdMalformed {
        offset: usize,
        kind: u8,
    },
    /// A well-formed IVMD block: unity/exclusion ranges are not implemented.
    Ivmd {
        offset: usize,
        kind: u8,
    },
    /// 40h in a revision 1 table, or 11h/40h while IVinfo[EFRSup] = 0.
    BlockNotAllowed {
        offset: usize,
        kind: u8,
    },
    /// An IVHD without a device entry.
    NoEntries {
        offset: usize,
    },
    Entry {
        offset: usize,
        problem: EntryProblem,
    },
    /// No IVHD block at all (§5.2: one or more IVDBs, each IOMMU an IVHD).
    NoIvhd,
    /// The capability block cannot lie at this offset in conventional
    /// configuration space ([`capability_registers`]).
    CapabilityOffset {
        offset: usize,
        capability: u16,
    },
    /// An IVHD for a second IOMMU (another DeviceID or capability offset).
    SecondUnit {
        offset: usize,
    },
    /// Two IVHDs of one type for the same unit.
    DuplicateBlock {
        offset: usize,
    },
    /// IVHDs for the same unit disagree (`field` names what).
    Inconsistent {
        offset: usize,
        field: &'static str,
    },
    /// A nonzero segment: unsupported in 10h, malformed in 11h/40h (Tables
    /// 96 and 100 give the value 0000h).
    Segment {
        offset: usize,
        kind: u8,
        segment: u16,
    },
    /// Base not aligned to its register window (§3.2, Capability Offset
    /// 04h).
    BaseAlignment(u64),
    /// Base zero or its window beyond 52 bits.
    BaseRange(u64),
    /// HATS = 11b, reserved (MMIO 0030h; Table 94), in any block, the
    /// superseded 10h included.
    HatsReserved {
        offset: usize,
        kind: u8,
        raw: u64,
    },
    /// HATDis = 1 in any 11h/40h block: no host translation to build on.
    HostTranslationDisabled {
        offset: usize,
        kind: u8,
        raw: u64,
    },
    /// More than [`MAX_FINDINGS`] deviations: refused rather than reported
    /// incompletely.
    TooManyDeviations,
}

impl Error {
    /// A short name for the boot report.
    pub fn name(&self) -> &'static str {
        match self {
            Error::Short => "short",
            Error::Signature => "signature",
            Error::Length => "length",
            Error::Checksum => "checksum",
            Error::Revision(_) => "revision-reserved",
            Error::BlockLength { .. } => "block-length",
            Error::UnknownBlock { .. } => "block-type-undefined",
            Error::IvmdMalformed { .. } => "ivmd-malformed",
            Error::Ivmd { .. } => "ivmd-present",
            Error::BlockNotAllowed { .. } => "block-not-allowed",
            Error::NoEntries { .. } => "no-entries",
            Error::Entry { .. } => "entry",
            Error::NoIvhd => "no-ivhd",
            Error::CapabilityOffset { .. } => "capability-offset",
            Error::SecondUnit { .. } => "second-iommu",
            Error::DuplicateBlock { .. } => "duplicate-block",
            Error::Inconsistent { .. } => "inconsistent",
            Error::Segment { .. } => "segment",
            Error::BaseAlignment(_) => "base-alignment",
            Error::BaseRange(_) => "base-range",
            Error::HatsReserved { .. } => "hats-reserved",
            Error::HostTranslationDisabled { .. } => "host-translation-disabled",
            Error::TooManyDeviations => "too-many-deviations",
        }
    }

    pub fn class(&self) -> Class {
        match self {
            Error::Entry { problem, .. } => problem.class(),
            Error::Segment { kind, .. } if *kind != 0x10 => Class::Malformed,
            Error::Ivmd { .. }
            | Error::SecondUnit { .. }
            | Error::DuplicateBlock { .. }
            | Error::Inconsistent { .. }
            | Error::Segment { .. }
            | Error::BaseRange(_)
            | Error::HostTranslationDisabled { .. }
            | Error::TooManyDeviations => Class::Unsupported,
            _ => Class::Malformed,
        }
    }

    /// The table offset the refusal is about, when there is one.
    pub fn offset(&self) -> Option<usize> {
        match *self {
            Error::BlockLength { offset }
            | Error::UnknownBlock { offset, .. }
            | Error::IvmdMalformed { offset, .. }
            | Error::Ivmd { offset, .. }
            | Error::BlockNotAllowed { offset, .. }
            | Error::NoEntries { offset }
            | Error::Entry { offset, .. }
            | Error::CapabilityOffset { offset, .. }
            | Error::SecondUnit { offset }
            | Error::DuplicateBlock { offset }
            | Error::Inconsistent { offset, .. }
            | Error::Segment { offset, .. }
            | Error::HatsReserved { offset, .. }
            | Error::HostTranslationDisabled { offset, .. } => Some(offset),
            _ => None,
        }
    }
}

/// A rule the table breaks without making the fields ABSD reads unreadable
/// (module documentation, "Reserved fields").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Field {
    /// IVRS bytes 40–47 (Table 86).
    HeaderReserved,
    /// IVinfo 31:23, 4:2 (Table 88).
    IvinfoReserved,
    /// 11h/40h flags 7:6 (Tables 97, 101).
    FlagsReserved,
    /// IOMMU info 15:13, 7:5 (Table 93).
    InfoReserved,
    /// 11h/40h attributes 31:28, 12:1 (Tables 98, 102).
    AttributesReserved,
    /// 10h feature field while IVinfo[EFRSup] = 0 (Table 91).
    FeatureReserved,
    /// EFR image 60:57, 30, 27:26 (MMIO 0030h).
    EfrReserved,
    /// EFR2 image 63:17, 10, 0 (MMIO 01A0h).
    Efr2Reserved,
    /// 10h GATS nonzero while GTSup = 0 (Table 94).
    GatsWithoutGtsup,
    /// 10h MsiNumPPR nonzero while PPRSup = 0 (Table 94).
    MsiNumPprWithoutPprSup,
    /// Alias entry bytes 4 or 7 nonzero (Table 107).
    AliasReserved,
    /// Special entry DeviceID nonzero (Table 107: 0000h).
    SpecialDeviceId,
    /// Extended DTE setting 30:3 (Table 108).
    ExtendedReserved,
    /// F0h HID neither an integer nor an ACPI/PNP ID (Table 110 notes 1, 2).
    HidFormat,
    /// F0h CID nonzero and not in the HID's format (Table 110 note 3).
    CidFormat,
    /// F0h without a string UID while IVinfo[DMA remap] = 1 (Table 88
    /// note 1).
    UidNotString,
    /// GATS = 11b (reserved) with GTSup set, in the 10h feature field or an
    /// EFR image (Table 94; MMIO 0030h).
    GatsReserved,
    /// The superseded 10h HATS differs from the used block's EFR image.
    HatsDisagrees,
    /// The one tolerated overlap: an alias range over a range's tail
    /// (§5.2.2.1 forbids it). Detail: [`Detail::AliasRange`].
    AliasOverRangeTail,
}

impl Field {
    pub fn name(&self) -> &'static str {
        match self {
            Field::HeaderReserved => "header-reserved",
            Field::IvinfoReserved => "ivinfo-reserved",
            Field::FlagsReserved => "flags-reserved",
            Field::InfoReserved => "info-reserved",
            Field::AttributesReserved => "attributes-reserved",
            Field::FeatureReserved => "feature-reserved-without-efrsup",
            Field::EfrReserved => "efr-reserved",
            Field::Efr2Reserved => "efr2-reserved",
            Field::GatsWithoutGtsup => "gats-without-gtsup",
            Field::MsiNumPprWithoutPprSup => "msinumppr-without-pprsup",
            Field::AliasReserved => "alias-reserved",
            Field::SpecialDeviceId => "special-devid",
            Field::ExtendedReserved => "extended-reserved",
            Field::HidFormat => "hid-format",
            Field::CidFormat => "cid-format",
            Field::UidNotString => "uid-not-string",
            Field::GatsReserved => "gats-reserved",
            Field::HatsDisagrees => "hats-disagrees-with-efr",
            Field::AliasOverRangeTail => "alias-over-range-tail",
        }
    }

    /// `reserved` (a field that must be zero) or `constraint`.
    pub fn rule(&self) -> &'static str {
        match self {
            Field::GatsWithoutGtsup
            | Field::MsiNumPprWithoutPprSup
            | Field::HidFormat
            | Field::CidFormat
            | Field::UidNotString
            | Field::HatsDisagrees => "constraint",
            Field::AliasOverRangeTail => "tolerated-overlap",
            _ => "reserved",
        }
    }
}

/// One deviation, for the report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Finding {
    /// The block the field is in: 10h, 11h or 40h, or 0 for the IVRS
    /// header.
    pub block: u8,
    /// Table offset of the field (for an alias range, of its 43h entry).
    pub offset: u32,
    pub field: Field,
    pub detail: Detail,
}

/// What a finding says, with one meaning per variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Detail {
    /// `raw` is the whole field as read; `unexpected` the set bits that make
    /// the rule fail (always a subset of `raw`): reserved bits, a field
    /// that must be zero, or the bits forming a reserved encoding.
    Bits { raw: u64, unexpected: u64 },
    /// A field whose whole value is an encoding the rule does not allow
    /// (an HID/CID that is no valid ID form; a UID format other than
    /// string): no bit subset is meaningful.
    Encoding { raw: u64 },
    /// A superseded 10h feature field (`raw`) whose HATS code `table`
    /// differs from the used EFR image's HATS code `efr`.
    Hats { raw: u64, table: u8, efr: u8 },
    /// The tolerated alias range: its DeviceIDs, the DeviceID they alias
    /// to in this block, and the table offset of its type 4 end entry. No
    /// single raw field holds this.
    AliasRange {
        first: u16,
        last: u16,
        target: u16,
        end_offset: u32,
    },
}

impl core::fmt::Display for Detail {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Detail::Bits { raw, unexpected } => {
                write!(f, "raw={raw:#x} unexpected={unexpected:#x}")
            }
            Detail::Encoding { raw } => write!(f, "raw={raw:#x} encoding=not-allowed"),
            Detail::Hats { raw, table, efr } => {
                write!(f, "raw={raw:#x} hats={table:#04b} efr-hats={efr:#04b}")
            }
            Detail::AliasRange {
                first,
                last,
                target,
                end_offset,
            } => write!(
                f,
                "first={first:#06x} last={last:#06x} target={target:#06x} end-offset={end_offset:#x}"
            ),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Findings {
    items: [Finding; MAX_FINDINGS],
    count: usize,
    /// More than [`MAX_FINDINGS`] were found; `parse` refuses the table.
    overflow: bool,
}

impl Findings {
    pub const EMPTY: Findings = Findings {
        items: [Finding {
            block: 0,
            offset: 0,
            field: Field::HeaderReserved,
            detail: Detail::Bits {
                raw: 0,
                unexpected: 0,
            },
        }; MAX_FINDINGS],
        count: 0,
        overflow: false,
    };

    /// Every deviation found (never truncated: see [`MAX_FINDINGS`]).
    pub fn items(&self) -> &[Finding] {
        &self.items[..self.count]
    }

    pub fn total(&self) -> usize {
        self.count
    }

    fn note(&mut self, block: u8, offset: usize, field: Field, raw: u64, unexpected: u64) {
        self.note_detail(block, offset, field, Detail::Bits { raw, unexpected });
    }

    fn note_detail(&mut self, block: u8, offset: usize, field: Field, detail: Detail) {
        if cfg!(absd_mutant_ivrs_ignore_reserved) {
            return;
        }
        if self.count == MAX_FINDINGS {
            self.overflow = true;
            return;
        }
        self.items[self.count] = Finding {
            block,
            offset: offset as u32,
            field,
            detail,
        };
        self.count += 1;
    }
}

/// The entry type a span came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpanKind {
    /// Type 1.
    All,
    /// Type 2, or 46h.
    Select,
    /// Type 3 + 4.
    Range,
    /// 47h + 4.
    ExtendedRange,
    /// 42h.
    AliasSelect,
    /// 43h + 4.
    AliasRange,
}

/// One plain or alias entry; a range counts once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Span {
    pub kind: SpanKind,
    pub first: u16,
    pub last: u16,
    /// DTE setting byte (Table 106).
    pub setting: u8,
    /// Extended DTE setting (46h/47h only).
    pub extended: Option<u32>,
    /// The requester ID the devices use instead of their own (42h/43h).
    pub alias: Option<u16>,
    /// Table offset of the (first) entry, for refusals.
    pub offset: u32,
}

impl Span {
    const EMPTY: Span = Span {
        kind: SpanKind::Select,
        first: 0,
        last: 0,
        setting: 0,
        extended: None,
        alias: None,
        offset: 0,
    };

    fn overlaps(&self, other: &Span) -> bool {
        self.first <= other.last && other.first <= self.last
    }

    fn contains(&self, id: u16) -> bool {
        self.first <= id && id <= self.last
    }

    /// The same description, wherever it sits in its block.
    fn same(&self, other: &Span) -> bool {
        (
            self.first,
            self.last,
            self.setting,
            self.extended,
            self.alias,
        ) == (
            other.first,
            other.last,
            other.setting,
            other.extended,
            other.alias,
        )
    }
}

/// The one overlap accepted (module documentation, "Device entries"):
/// `alias`, an Alias Start of Range covering exactly one whole bus, lies
/// over the tail of `plain`, a type 3 range, never its start, with the same
/// DTE setting.
pub fn tail_alias(plain: &Span, alias: &Span) -> bool {
    if cfg!(absd_mutant_ivrs_broad_alias) {
        return alias.alias.is_some() && plain.alias.is_none() && plain.setting == alias.setting;
    }
    plain.kind == SpanKind::Range
        && alias.kind == SpanKind::AliasRange
        && plain.setting == alias.setting
        && alias.first & 0xff == 0
        && alias.last == alias.first | 0xff
        && plain.first < alias.first
        && alias.first <= plain.last
        && plain.last <= alias.last
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Variety {
    IoApic,
    Hpet,
}

/// A special device entry (48h): an IOAPIC or HPET and the DeviceID its
/// interrupts carry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Special {
    pub variety: Variety,
    pub handle: u8,
    pub source: u16,
    pub setting: u8,
}

/// An ACPI HID named device (F0h), recorded only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hid {
    pub devid: u16,
    pub setting: u8,
    pub hid: [u8; 8],
    pub cid: [u8; 8],
    pub uid_format: u8,
    pub uid_len: u8,
    pub uid: [u8; MAX_UID],
}

impl Hid {
    /// The UID bytes (never longer than [`MAX_UID`]).
    pub fn uid(&self) -> &[u8] {
        let len = usize::from(self.uid_len).min(MAX_UID);
        &self.uid[..len]
    }
}

/// Table 110 notes 2 and 3: a 32-bit integer in the low four bytes with the
/// upper four zero, or an 8-character ACPI ID, or a 7-character PNP ID with
/// a zero eighth byte. The character classes are the ACPI specification's
/// (ACPI ID: four uppercase letters or digits then four hex digits; PNP
/// ID: three uppercase letters then four hex digits); that document is not
/// pinned in this lane. All zero means absent.
pub fn acpi_id_ok(id: &[u8; 8]) -> bool {
    let upper = |b: u8| b.is_ascii_uppercase();
    let hex = |b: u8| b.is_ascii_hexdigit();
    let integer = id[4..].iter().all(|&b| b == 0) && id[..4].iter().any(|&b| b != 0);
    let acpi =
        id[..4].iter().all(|&b| upper(b) || b.is_ascii_digit()) && id[4..].iter().all(|&b| hex(b));
    let pnp = id[..3].iter().all(|&b| upper(b)) && id[3..7].iter().all(|&b| hex(b)) && id[7] == 0;
    integer || acpi || pnp
}

/// The device entries of one IVHD block.
#[derive(Clone, Copy, Debug)]
pub struct Entries {
    spans: [Span; MAX_SPANS],
    span_count: usize,
    specials: [Special; MAX_SPECIALS],
    special_count: usize,
    hids: [Hid; MAX_HIDS],
    hid_count: usize,
    /// All-zero reserved entries skipped.
    pub padding: usize,
}

impl Entries {
    pub const EMPTY: Entries = Entries {
        spans: [Span::EMPTY; MAX_SPANS],
        span_count: 0,
        specials: [Special {
            variety: Variety::IoApic,
            handle: 0,
            source: 0,
            setting: 0,
        }; MAX_SPECIALS],
        special_count: 0,
        hids: [Hid {
            devid: 0,
            setting: 0,
            hid: [0; 8],
            cid: [0; 8],
            uid_format: 0,
            uid_len: 0,
            uid: [0; MAX_UID],
        }; MAX_HIDS],
        hid_count: 0,
        padding: 0,
    };

    pub fn spans(&self) -> &[Span] {
        &self.spans[..self.span_count]
    }

    pub fn specials(&self) -> &[Special] {
        &self.specials[..self.special_count]
    }

    pub fn hids(&self) -> &[Hid] {
        &self.hids[..self.hid_count]
    }

    /// Fixed-length content equal as a multiset (order ignored), HIDs
    /// ignored.
    fn same_fixed(&self, other: &Entries) -> bool {
        let spans = |entries: &Entries, span: &Span| {
            entries.spans().iter().filter(|s| s.same(span)).count()
        };
        let specials = |entries: &Entries, special: &Special| {
            entries.specials().iter().filter(|s| *s == special).count()
        };
        self.span_count == other.span_count
            && self.special_count == other.special_count
            && self
                .spans()
                .iter()
                .all(|span| spans(self, span) == spans(other, span))
            && self
                .specials()
                .iter()
                .all(|special| specials(self, special) == specials(other, special))
    }
}

/// How the IOMMU sees requests from one DeviceID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    /// No entry names it.
    Undescribed,
    /// Its own DeviceID.
    Own,
    /// Another DeviceID (an alias entry).
    Alias(u16),
}

/// The one supported remapping unit.
///
/// Decision code may use the public fields and accessors only; they cover
/// validated fields ([`VALIDATED_FIELDS`]). The raw flags, info, IVinfo,
/// 10h feature word, attributes and EFR/EFR2 images are private; the
/// accessors that read them ([`Unit::host_levels`], [`Unit::window`],
/// [`Unit::pre_boot_protection`]) use only validated bits; [`Unit::images`]
/// only formats. `Debug` exists in host tests only. The deviation list
/// ([`Unit::findings`]) is diagnostic and does carry raw values: keeping
/// decision code off it is a review rule (module documentation), not a
/// type guarantee.
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub struct Unit {
    pub revision: u8,
    ivinfo: u32,
    /// The IOMMU's own PCI function (segment 0).
    pub devid: u16,
    /// Within conventional configuration space ([`capability_registers`]).
    pub capability: u8,
    pub base: u64,
    pub segment: u16,
    info: u16,
    /// Flags of the block used.
    flags: u8,
    /// Flags of the 10h block, when there is one.
    flags_10h: Option<u8>,
    /// Type of the block used: 0x11, else 0x10, else 0x40.
    pub used: u8,
    /// IVHD types present for this unit: bit 0 = 10h, 1 = 11h, 2 = 40h.
    pub present: u8,
    /// 10h IOMMU feature reporting (meaningful only with EFRSup).
    feature: Option<u32>,
    /// 11h/40h attributes, EFR and EFR2 images.
    attributes: Option<u32>,
    efr: Option<u64>,
    efr2: Option<u64>,
    /// Entries of the block used, with the 40h block's HIDs when present.
    pub entries: Entries,
    /// Deviations found within the validated subset.
    pub findings: Findings,
}

impl Unit {
    pub const EMPTY: Unit = Unit {
        revision: 0,
        ivinfo: 0,
        devid: 0,
        capability: 0,
        base: 0,
        segment: 0,
        info: 0,
        flags: 0,
        flags_10h: None,
        used: 0,
        present: 0,
        feature: None,
        attributes: None,
        efr: None,
        efr2: None,
        entries: Entries::EMPTY,
        findings: Findings::EMPTY,
    };

    /// Host page-table levels the unit supports (HATS), when the table
    /// says (an EFR image, or a 10h feature field under EFRSup).
    pub fn host_levels(&self) -> Option<u8> {
        let hats = match (self.efr, self.feature) {
            (Some(efr), _) => (efr >> EFR_HATS_SHIFT) as u8 & 3,
            (None, Some(feature)) if self.ivinfo & IVINFO_EFR_SUP != 0 => (feature >> 30) as u8,
            _ => return None,
        };
        (hats < 3).then_some(4 + hats)
    }

    /// Performance counters, hence a 512 KiB register window; unknown
    /// counts as absent (a 16 KiB window).
    pub fn counters(&self) -> bool {
        match (self.efr, self.feature) {
            (Some(efr), _) => efr & EFR_PC_SUP != 0,
            // 10h: PNBanks (22:17) and PNCounters (16:13), Table 94 note.
            (None, Some(feature)) if self.ivinfo & IVINFO_EFR_SUP != 0 => {
                (feature >> 13) & 0x3ff != 0
            }
            _ => false,
        }
    }

    /// Bytes of the MMIO register window.
    pub fn window(&self) -> u64 {
        if self.counters() {
            LARGE_WINDOW
        } else {
            SMALL_WINDOW
        }
    }

    /// IVinfo EFRSup (validated).
    pub fn efr_sup(&self) -> bool {
        self.ivinfo & IVINFO_EFR_SUP != 0
    }

    /// The HATS code [`Unit::host_levels`] is computed from (EFR image of the
    /// used block, else the 10h field under EFRSup); validated.
    pub fn hats_code(&self) -> Option<u8> {
        self.host_levels().map(|levels| levels - 4)
    }

    /// IASup (EFR bit 6, a defined single bit) of the used block's EFR
    /// image, when it has one.
    pub fn ia_sup(&self) -> Option<bool> {
        self.efr.map(|efr| efr & (1 << 6) != 0)
    }

    /// PerfOptSup (EFR bit 45, a defined single bit) of the used block's EFR
    /// image, when it has one.
    pub fn perf_opt_sup(&self) -> Option<bool> {
        self.efr.map(|efr| efr & (1 << 45) != 0)
    }

    /// Whether `flags` (a wide block's flags byte, from a finding) equals
    /// this unit's 10h flags byte. A comparison for quirk matching only; it
    /// exposes no image value (review rule, module documentation).
    pub fn flags_equal_10h(&self, flags: u8) -> bool {
        self.flags_10h == Some(flags)
    }

    pub fn pre_boot_protection(&self) -> bool {
        self.ivinfo & IVINFO_DMA_REMAP != 0
    }

    /// The requester ID the IOMMU sees for `devid`.
    pub fn source(&self, devid: u16) -> Source {
        let spans = self.entries.spans();
        if let Some(alias) = spans
            .iter()
            .find(|span| span.alias.is_some() && span.contains(devid))
        {
            return Source::Alias(alias.alias.unwrap_or(devid));
        }
        if spans.iter().any(|span| span.contains(devid)) {
            Source::Own
        } else {
            Source::Undescribed
        }
    }

    pub fn aliased(&self) -> usize {
        self.entries
            .spans()
            .iter()
            .filter(|span| span.alias.is_some())
            .map(|span| usize::from(span.last.saturating_sub(span.first)) + 1)
            .sum()
    }

    /// The raw images, for reports only (module documentation: most of
    /// their bits are carried, not validated).
    pub fn images(&self) -> Images {
        Images {
            info: self.info,
            flags: self.flags,
            efr: self.efr,
            efr2: self.efr2,
        }
    }

    /// The configuration offsets of the capability header and the two base
    /// address registers; the parser guarantees they exist.
    pub fn capability_registers(&self) -> Option<[u8; 3]> {
        capability_registers(u16::from(self.capability))
    }
}

/// Configuration offsets of the IOMMU capability header (00h) and base
/// address low/high registers (04h, 08h) for a capability at `offset`,
/// or `None` when the whole block (00h–14h) cannot lie there: below 40h,
/// not dword aligned, or running past FFh.
pub fn capability_registers(offset: u16) -> Option<[u8; 3]> {
    let fits = offset >= 0x40
        && offset.is_multiple_of(4)
        && offset
            .checked_add(CAPABILITY_BLOCK_BYTES)
            .is_some_and(|end| end <= CONFIG_SPACE_BYTES);
    if !fits && !cfg!(absd_mutant_ivrs_any_capability) {
        return None;
    }
    let base = u8::try_from(offset).ok()?;
    Some([base, base.checked_add(4)?, base.checked_add(8)?])
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from(u32_at(bytes, offset)) | (u64::from(u32_at(bytes, offset + 4)) << 32)
}

fn ivhd_header(kind: u8) -> usize {
    if kind == 0x10 { 24 } else { 40 }
}

/// An IVHD block's fixed header.
#[derive(Clone, Copy)]
struct Ivhd {
    offset: usize,
    kind: u8,
    flags: u8,
    length: usize,
    devid: u16,
    capability: u16,
    base: u64,
    segment: u16,
    info: u16,
    word: u32,
    efr: u64,
    efr2: u64,
}

impl Ivhd {
    fn read(bytes: &[u8], offset: usize, kind: u8, length: usize) -> Ivhd {
        let block = &bytes[offset..offset + length];
        let wide = kind != 0x10;
        Ivhd {
            offset,
            kind,
            flags: block[1],
            length,
            devid: u16_at(block, 4),
            capability: u16_at(block, 6),
            base: u64_at(block, 8),
            segment: u16_at(block, 16),
            info: u16_at(block, 18),
            word: u32_at(block, 20),
            efr: if wide { u64_at(block, 24) } else { 0 },
            efr2: if wide { u64_at(block, 32) } else { 0 },
        }
    }

    fn entries<'b>(&self, bytes: &'b [u8]) -> (usize, &'b [u8]) {
        let start = self.offset + ivhd_header(self.kind);
        (start, &bytes[start..self.offset + self.length])
    }

    /// The header's reserved fields, the encodings of the validated feature
    /// fields, and stated constraints. A reserved HATS refuses: the
    /// enforcement path consumes it.
    fn check(&self, ivinfo: u32, findings: &mut Findings) -> Result<(), Error> {
        let at = self.offset;
        let efr_sup = ivinfo & IVINFO_EFR_SUP != 0;
        if self.kind == 0x10
            && efr_sup
            && self.word >> 30 == 3
            && !cfg!(absd_mutant_ivrs_hats_used_only)
        {
            return Err(Error::HatsReserved {
                offset: at + 20,
                kind: self.kind,
                raw: u64::from(self.word),
            });
        }
        // HATDis in any wide block, used or not: HATS is then not
        // meaningful there, and ABSD will not choose another block's.
        if self.kind != 0x10 && self.word & ATTRIBUTE_HAT_DIS != 0 {
            return Err(Error::HostTranslationDisabled {
                offset: at + 20,
                kind: self.kind,
                raw: u64::from(self.word),
            });
        }
        if self.kind != 0x10
            && (self.efr >> EFR_HATS_SHIFT) & 3 == 3
            && !cfg!(absd_mutant_ivrs_hats_used_only)
        {
            return Err(Error::HatsReserved {
                offset: at + 24,
                kind: self.kind,
                raw: self.efr,
            });
        }
        if self.info & INFO_RESERVED != 0 {
            findings.note(
                self.kind,
                at + 18,
                Field::InfoReserved,
                u64::from(self.info),
                u64::from(self.info & INFO_RESERVED),
            );
        }
        if self.kind == 0x10 {
            if ivinfo & IVINFO_EFR_SUP == 0 {
                if self.word != 0 {
                    findings.note(
                        self.kind,
                        at + 20,
                        Field::FeatureReserved,
                        u64::from(self.word),
                        u64::from(self.word),
                    );
                }
            } else if !cfg!(absd_mutant_ivrs_skip_constraints) {
                if self.word & FEATURE_GATS != 0 && self.word & FEATURE_GTSUP == 0 {
                    findings.note(
                        self.kind,
                        at + 20,
                        Field::GatsWithoutGtsup,
                        u64::from(self.word),
                        u64::from(self.word & FEATURE_GATS),
                    );
                }
                if self.word & FEATURE_MSI_NUM_PPR != 0 && self.flags & FLAGS_PPR_SUP == 0 {
                    findings.note(
                        self.kind,
                        at + 20,
                        Field::MsiNumPprWithoutPprSup,
                        u64::from(self.word),
                        u64::from(self.word & FEATURE_MSI_NUM_PPR),
                    );
                }
                if self.word & FEATURE_GTSUP != 0 && self.word & FEATURE_GATS == FEATURE_GATS {
                    findings.note(
                        self.kind,
                        at + 20,
                        Field::GatsReserved,
                        u64::from(self.word),
                        u64::from(FEATURE_GATS),
                    );
                }
            }
            return Ok(());
        }
        if self.flags & FLAGS_RESERVED_WIDE != 0 {
            findings.note(
                self.kind,
                at + 1,
                Field::FlagsReserved,
                u64::from(self.flags),
                u64::from(self.flags & FLAGS_RESERVED_WIDE),
            );
        }
        if self.word & ATTRIBUTES_RESERVED != 0 {
            findings.note(
                self.kind,
                at + 20,
                Field::AttributesReserved,
                u64::from(self.word),
                u64::from(self.word & ATTRIBUTES_RESERVED),
            );
        }
        if self.efr & EFR_RESERVED != 0 {
            findings.note(
                self.kind,
                at + 24,
                Field::EfrReserved,
                self.efr,
                self.efr & EFR_RESERVED,
            );
        }
        if self.efr2 & EFR2_RESERVED != 0 {
            findings.note(
                self.kind,
                at + 32,
                Field::Efr2Reserved,
                self.efr2,
                self.efr2 & EFR2_RESERVED,
            );
        }
        if self.efr & EFR_GTSUP != 0
            && self.efr & EFR_GATS == EFR_GATS
            && !cfg!(absd_mutant_ivrs_skip_constraints)
        {
            findings.note(self.kind, at + 24, Field::GatsReserved, self.efr, EFR_GATS);
        }
        Ok(())
    }
}

fn entry_error(offset: usize, problem: EntryProblem) -> Error {
    Error::Entry { offset, problem }
}

fn push_span(entries: &mut Entries, span: Span) -> Result<(), Error> {
    if entries.span_count == MAX_SPANS {
        return Err(entry_error(span.offset as usize, EntryProblem::TooMany));
    }
    entries.spans[entries.span_count] = span;
    entries.span_count += 1;
    Ok(())
}

/// Parses and checks the device entries of one IVHD block. `base` is the
/// table offset of `raw`, for refusals.
fn parse_entries(
    kind: u8,
    ivinfo: u32,
    base: usize,
    raw: &[u8],
    out: &mut Entries,
    findings: &mut Findings,
) -> Result<(), Error> {
    *out = Entries::EMPTY;
    let mut at = 0;
    // A range start waiting for its type 4 end.
    let mut pending: Option<Span> = None;
    let mut seen_hid = false;
    let mut described = 0usize;
    while at < raw.len() {
        let offset = base + at;
        let kind_byte = raw[at];
        let length = match kind_byte >> 6 {
            0 => 4,
            1 => 8,
            _ => {
                if kind_byte != 0xf0 {
                    return Err(entry_error(offset, EntryProblem::UnknownType(kind_byte)));
                }
                if raw.len() - at < 22 {
                    return Err(entry_error(offset, EntryProblem::Truncated));
                }
                22 + usize::from(raw[at + 21])
            }
        };
        let entry = raw
            .get(at..at + length)
            .ok_or(entry_error(offset, EntryProblem::Truncated))?;
        if pending.is_some() && kind_byte != 4 {
            #[cfg(not(absd_mutant_ivrs_unpaired))]
            return Err(entry_error(offset, EntryProblem::Unpaired));
            #[cfg(absd_mutant_ivrs_unpaired)]
            {
                pending = None;
            }
        }
        if kind_byte < 0x80 && seen_hid {
            return Err(entry_error(offset, EntryProblem::FixedAfterHid));
        }
        let devid = u16_at(entry, 1);
        let setting = entry[3];
        let plain = |kind: SpanKind, extended: Option<u32>| Span {
            kind,
            first: devid,
            last: devid,
            setting,
            extended,
            alias: None,
            offset: offset as u32,
        };
        let extended = |entry: &[u8], findings: &mut Findings| {
            let value = u32_at(entry, 4);
            if value & EXTENDED_RESERVED != 0 {
                findings.note(
                    kind,
                    offset + 4,
                    Field::ExtendedReserved,
                    u64::from(value),
                    u64::from(value & EXTENDED_RESERVED),
                );
            }
            value
        };
        let alias = |entry: &[u8], findings: &mut Findings| {
            if entry[4] != 0 || entry[7] != 0 {
                findings.note(
                    kind,
                    offset + 4,
                    Field::AliasReserved,
                    u64::from(u32_at(entry, 4)),
                    u64::from(u32_at(entry, 4) & 0xff00_00ff),
                );
            }
            u16_at(entry, 5)
        };
        match kind_byte {
            // Reserved entries whose bytes Tables 105 and 107 give as zero.
            0 | 0x40 | 0x41 | 0x44 | 0x45 => {
                if entry.iter().skip(1).any(|&byte| byte != 0) {
                    return Err(entry_error(offset, EntryProblem::Padding));
                }
                out.padding += 1;
            }
            1 => {
                push_span(
                    out,
                    Span {
                        first: 0,
                        last: 0xffff,
                        ..plain(SpanKind::All, None)
                    },
                )?;
                described += 1;
            }
            2 => {
                push_span(out, plain(SpanKind::Select, None))?;
                described += 1;
            }
            3 => pending = Some(plain(SpanKind::Range, None)),
            4 => {
                let Some(start) = pending.take() else {
                    return Err(entry_error(offset, EntryProblem::Unpaired));
                };
                if setting != 0 {
                    return Err(entry_error(offset, EntryProblem::EndSetting));
                }
                if devid < start.first {
                    return Err(entry_error(offset, EntryProblem::Reversed));
                }
                push_span(
                    out,
                    Span {
                        last: devid,
                        ..start
                    },
                )?;
                described += 1;
            }
            0x42 => {
                let target = alias(entry, findings);
                push_span(
                    out,
                    Span {
                        alias: Some(target),
                        ..plain(SpanKind::AliasSelect, None)
                    },
                )?;
                described += 1;
            }
            0x43 => {
                let target = alias(entry, findings);
                pending = Some(Span {
                    alias: Some(target),
                    ..plain(SpanKind::AliasRange, None)
                });
            }
            0x46 => {
                let value = extended(entry, findings);
                push_span(out, plain(SpanKind::Select, Some(value)))?;
                described += 1;
            }
            0x47 => {
                let value = extended(entry, findings);
                pending = Some(plain(SpanKind::ExtendedRange, Some(value)));
            }
            0x48 => {
                if devid != 0 {
                    findings.note(
                        kind,
                        offset + 1,
                        Field::SpecialDeviceId,
                        u64::from(devid),
                        u64::from(devid),
                    );
                }
                let variety = match entry[7] {
                    1 => Variety::IoApic,
                    2 => Variety::Hpet,
                    other => {
                        return Err(entry_error(offset, EntryProblem::SpecialVariety(other)));
                    }
                };
                let special = Special {
                    variety,
                    handle: entry[4],
                    source: u16_at(entry, 5),
                    setting,
                };
                if out
                    .specials()
                    .iter()
                    .any(|seen| (seen.variety, seen.handle) == (variety, special.handle))
                {
                    return Err(entry_error(offset, EntryProblem::SpecialDuplicate));
                }
                if out.special_count == MAX_SPECIALS {
                    return Err(entry_error(offset, EntryProblem::TooMany));
                }
                out.specials[out.special_count] = special;
                out.special_count += 1;
                described += 1;
            }
            0xf0 => {
                if kind != 0x40 {
                    return Err(entry_error(offset, EntryProblem::HidInFixedBlock));
                }
                let format = entry[20];
                let uid_len = usize::from(entry[21]);
                if format > 2 || (format == 0) != (uid_len == 0) {
                    return Err(entry_error(offset, EntryProblem::HidUid));
                }
                if uid_len > MAX_UID {
                    return Err(entry_error(offset, EntryProblem::UidCapacity));
                }
                if out.hid_count == MAX_HIDS {
                    return Err(entry_error(offset, EntryProblem::TooMany));
                }
                let mut hid = Hid {
                    devid,
                    setting,
                    hid: [0; 8],
                    cid: [0; 8],
                    uid_format: format,
                    uid_len: uid_len as u8,
                    uid: [0; MAX_UID],
                };
                hid.hid.copy_from_slice(&entry[4..12]);
                hid.cid.copy_from_slice(&entry[12..20]);
                hid.uid[..uid_len].copy_from_slice(&entry[22..22 + uid_len]);
                if !cfg!(absd_mutant_ivrs_skip_constraints) {
                    if !acpi_id_ok(&hid.hid) {
                        findings.note_detail(
                            kind,
                            offset + 4,
                            Field::HidFormat,
                            Detail::Encoding {
                                raw: u64::from_le_bytes(hid.hid),
                            },
                        );
                    }
                    if hid.cid != [0; 8] && !acpi_id_ok(&hid.cid) {
                        findings.note_detail(
                            kind,
                            offset + 12,
                            Field::CidFormat,
                            Detail::Encoding {
                                raw: u64::from_le_bytes(hid.cid),
                            },
                        );
                    }
                    if ivinfo & IVINFO_DMA_REMAP != 0 && format != 2 {
                        findings.note_detail(
                            kind,
                            offset + 20,
                            Field::UidNotString,
                            Detail::Encoding {
                                raw: u64::from(format),
                            },
                        );
                    }
                }
                out.hids[out.hid_count] = hid;
                out.hid_count += 1;
                seen_hid = true;
                described += 1;
            }
            other => return Err(entry_error(offset, EntryProblem::UnknownType(other))),
        }
        at += length;
    }
    if let Some(start) = pending {
        #[cfg(not(absd_mutant_ivrs_unpaired))]
        return Err(entry_error(start.offset as usize, EntryProblem::Unpaired));
        #[cfg(absd_mutant_ivrs_unpaired)]
        let _ = start;
    }
    if described == 0 {
        return Err(Error::NoEntries { offset: base });
    }
    check_overlaps(kind, out, findings)
}

/// The overlap rule in the module documentation.
fn check_overlaps(kind: u8, entries: &Entries, findings: &mut Findings) -> Result<(), Error> {
    let spans = entries.spans();
    let mut tolerated = 0;
    for (index, span) in spans.iter().enumerate() {
        for earlier in &spans[..index] {
            if !span.overlaps(earlier) {
                continue;
            }
            let accepted = match (span.alias.is_some(), earlier.alias.is_some()) {
                (true, true) => {
                    if cfg!(absd_mutant_ivrs_alias_overlap) {
                        continue;
                    }
                    return Err(entry_error(
                        span.offset as usize,
                        EntryProblem::AliasOverlap,
                    ));
                }
                (false, false) => {
                    cfg!(absd_mutant_ivrs_plain_overlap)
                        && span.setting == earlier.setting
                        && span.extended == earlier.extended
                }
                (true, false) => tail_alias(earlier, span),
                (false, true) => tail_alias(span, earlier),
            };
            if !accepted || cfg!(absd_mutant_ivrs_strict_overlap) {
                return Err(entry_error(span.offset as usize, EntryProblem::Overlap));
            }
            tolerated += 1;
            if tolerated > 1 && !cfg!(absd_mutant_ivrs_broad_alias) {
                return Err(entry_error(span.offset as usize, EntryProblem::Overlap));
            }
            // Accepted, but a deviation from §5.2.2.1 all the same.
            let (alias, target) = match (span.alias, earlier.alias) {
                (Some(target), _) => (span, target),
                (None, Some(target)) => (earlier, target),
                // Only the plain-overlap mutant accepts two plain ranges.
                (None, None) if cfg!(absd_mutant_ivrs_plain_overlap) => (earlier, 0),
                (None, None) => {
                    return Err(entry_error(span.offset as usize, EntryProblem::Overlap));
                }
            };
            if !cfg!(absd_mutant_ivrs_silent_alias) {
                findings.note_detail(
                    kind,
                    alias.offset as usize,
                    Field::AliasOverRangeTail,
                    // A 43h start is immediately followed by its type 4 end.
                    Detail::AliasRange {
                        first: alias.first,
                        last: alias.last,
                        target,
                        end_offset: alias.offset + 8,
                    },
                );
            }
        }
    }
    for span in spans {
        let Some(target) = span.alias else { continue };
        if !cfg!(absd_mutant_ivrs_alias_target)
            && !spans
                .iter()
                .any(|other| other.alias.is_none() && other.contains(target))
        {
            return Err(entry_error(
                span.offset as usize,
                EntryProblem::AliasTargetUndeclared,
            ));
        }
        if spans
            .iter()
            .any(|other| other.alias.is_some() && other.contains(target))
        {
            return Err(entry_error(span.offset as usize, EntryProblem::AliasChain));
        }
    }
    Ok(())
}

/// An IVMD block's reserved fields and flag rule (Tables 111–113).
fn ivmd_conforms(block: &[u8]) -> bool {
    let flags = block[1];
    let reserved_ids = match block[0] {
        0x20 => u32_at(block, 4) != 0 || u16_at(block, 8) != 0,
        0x21 => u16_at(block, 6) != 0,
        _ => false,
    };
    let exclusion = flags & 0b1000 != 0;
    // IR = IW = 0 requires Unity = 0 (unless ExclusionRange overrides them).
    let unity_without_access = !exclusion && flags & 0b0110 == 0 && flags & 1 != 0;
    flags & IVMD_FLAGS_RESERVED == 0
        && block[10..16].iter().all(|&b| b == 0)
        && !reserved_ids
        && !unity_without_access
}

fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

/// Layer 1 (module documentation): validates an IVRS and describes its one
/// unit into `unit`. `Err` is a refusal and leaves `unit` meaningless. `Ok`
/// says whether any deviation was found within the validated subset; the
/// deviations are in `unit.findings`. Neither outcome is permission to
/// configure anything. `scratch` is working space for the cross-checked
/// blocks (kept out of the caller's stack frame).
pub fn parse(bytes: &[u8], unit: &mut Unit, scratch: &mut Entries) -> Result<Validation, Error> {
    *unit = Unit::EMPTY;
    if bytes.len() < HEADER_BYTES {
        return Err(Error::Short);
    }
    if &bytes[..4] != b"IVRS" {
        return Err(Error::Signature);
    }
    if u32_at(bytes, 4) as usize != bytes.len() {
        return Err(Error::Length);
    }
    if !cfg!(absd_mutant_ivrs_skip_checksum) && checksum(bytes) != 0 {
        return Err(Error::Checksum);
    }
    let revision = bytes[8];
    if !(1..=2).contains(&revision) {
        return Err(Error::Revision(revision));
    }
    let mut findings = Findings::EMPTY;
    let ivinfo = u32_at(bytes, 36);
    if ivinfo & IVINFO_RESERVED != 0 {
        findings.note(
            0,
            36,
            Field::IvinfoReserved,
            u64::from(ivinfo),
            u64::from(ivinfo & IVINFO_RESERVED),
        );
    }
    if bytes[40..48].iter().any(|&byte| byte != 0) {
        findings.note(
            0,
            40,
            Field::HeaderReserved,
            u64_at(bytes, 40),
            u64_at(bytes, 40),
        );
    }

    // Pass 1: every block's bounds, type and reserved fields, every IVHD's
    // entries, and the one-unit rule. Records the 10h, 11h and 40h blocks.
    let mut first: Option<Ivhd> = None;
    let mut by_type: [Option<Ivhd>; 3] = [None; 3];
    let mut offset = HEADER_BYTES;
    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            return Err(Error::BlockLength { offset });
        }
        let kind = bytes[offset];
        let length = usize::from(u16_at(bytes, offset + 2));
        let minimum = match kind {
            0x10 | 0x11 | 0x40 => ivhd_header(kind),
            0x20..=0x22 => 32,
            other => {
                return Err(Error::UnknownBlock {
                    offset,
                    kind: other,
                });
            }
        };
        if length < minimum || length > bytes.len() - offset {
            return Err(Error::BlockLength { offset });
        }
        if (0x20..=0x22).contains(&kind) {
            if length != 32 {
                return Err(Error::BlockLength { offset });
            }
            if !ivmd_conforms(&bytes[offset..offset + 32]) {
                return Err(Error::IvmdMalformed { offset, kind });
            }
            if !cfg!(absd_mutant_ivrs_accept_ivmd) {
                return Err(Error::Ivmd { offset, kind });
            }
            offset += length;
            continue;
        }
        if (kind == 0x40 && revision < 2) || (kind != 0x10 && ivinfo & IVINFO_EFR_SUP == 0) {
            return Err(Error::BlockNotAllowed { offset, kind });
        }
        let ivhd = Ivhd::read(bytes, offset, kind, length);
        if capability_registers(ivhd.capability).is_none() {
            return Err(Error::CapabilityOffset {
                offset,
                capability: ivhd.capability,
            });
        }
        if kind != 0x10 && ivhd.segment != 0 {
            return Err(Error::Segment {
                offset,
                kind,
                segment: ivhd.segment,
            });
        }
        ivhd.check(ivinfo, &mut findings)?;
        let (start, raw) = ivhd.entries(bytes);
        parse_entries(kind, ivinfo, start, raw, scratch, &mut findings)?;
        match first {
            None => first = Some(ivhd),
            Some(unit) => {
                if (unit.devid, unit.capability) != (ivhd.devid, ivhd.capability) {
                    if !cfg!(absd_mutant_ivrs_second_unit) {
                        return Err(Error::SecondUnit { offset });
                    }
                    offset += length;
                    continue;
                }
                if unit.base != ivhd.base {
                    return Err(Error::Inconsistent {
                        offset,
                        field: "base",
                    });
                }
                if unit.segment != ivhd.segment {
                    return Err(Error::Inconsistent {
                        offset,
                        field: "segment",
                    });
                }
            }
        }
        let slot = match kind {
            0x10 => 0,
            0x11 => 1,
            _ => 2,
        };
        if by_type[slot].is_some() {
            return Err(Error::DuplicateBlock { offset });
        }
        by_type[slot] = Some(ivhd);
        offset += length;
    }
    let Some(head) = first else {
        return Err(Error::NoIvhd);
    };
    if head.segment != 0 {
        return Err(Error::Segment {
            offset: head.offset,
            kind: head.kind,
            segment: head.segment,
        });
    }
    let Some(used) = by_type[1].or(by_type[0]).or(by_type[2]) else {
        return Err(Error::NoIvhd);
    };

    // Pass 2: the used block's entries, and a 40h block against it. Its
    // findings were noted in pass 1.
    let mut again = Findings::EMPTY;
    let (start, raw) = used.entries(bytes);
    parse_entries(used.kind, ivinfo, start, raw, &mut unit.entries, &mut again)?;
    if let Some(mixed) = by_type[2].filter(|_| used.kind != 0x40) {
        let (start, raw) = mixed.entries(bytes);
        parse_entries(mixed.kind, ivinfo, start, raw, scratch, &mut again)?;
        let field = if !scratch.same_fixed(&unit.entries) {
            Some("entries")
        } else if mixed.flags != used.flags && used.kind == 0x11 {
            Some("flags")
        } else if mixed.info != used.info {
            Some("info")
        } else if used.kind == 0x11 && mixed.word != used.word {
            Some("attributes")
        } else if used.kind == 0x11 && (mixed.efr, mixed.efr2) != (used.efr, used.efr2) {
            Some("efr")
        } else {
            None
        };
        if let Some(field) = field {
            return Err(Error::Inconsistent {
                offset: mixed.offset,
                field,
            });
        }
        unit.entries.hids = scratch.hids;
        unit.entries.hid_count = scratch.hid_count;
    }

    unit.revision = revision;
    unit.ivinfo = ivinfo;
    unit.devid = used.devid;
    // Bounded by `capability_registers` above.
    unit.capability = used.capability as u8;
    unit.base = used.base;
    unit.segment = used.segment;
    unit.info = used.info;
    unit.flags = used.flags;
    unit.used = used.kind;
    unit.present = by_type
        .iter()
        .enumerate()
        .filter(|(_, block)| block.is_some())
        .fold(0, |bits, (index, _)| bits | (1 << index));
    unit.feature = by_type[0].map(|block| block.word);
    unit.flags_10h = by_type[0].map(|block| block.flags);
    unit.attributes = (used.kind != 0x10).then_some(used.word);
    unit.efr = (used.kind != 0x10).then_some(used.efr);
    unit.efr2 = (used.kind != 0x10).then_some(used.efr2);
    // HATDis and reserved HATS were refused per block in pass 1.
    let window = unit.window();
    if !unit.base.is_multiple_of(window) {
        return Err(Error::BaseAlignment(unit.base));
    }
    if unit.base == 0
        || unit
            .base
            .checked_add(window)
            .is_none_or(|end| end > PHYSICAL_LIMIT)
    {
        return Err(Error::BaseRange(unit.base));
    }
    // A superseded 10h HATS that disagrees with the EFR image the used
    // block carries: the image is the one ABSD reads (§5.2, 11h
    // supersedes), but both claim to copy the same register.
    if let (Some(ten), Some(efr)) = (by_type[0], unit.efr)
        && unit.ivinfo & IVINFO_EFR_SUP != 0
        && u64::from(ten.word >> 30) != (efr >> EFR_HATS_SHIFT) & 3
    {
        findings.note_detail(
            0x10,
            ten.offset + 20,
            Field::HatsDisagrees,
            Detail::Hats {
                raw: u64::from(ten.word),
                table: (ten.word >> 30) as u8,
                efr: ((efr >> EFR_HATS_SHIFT) & 3) as u8,
            },
        );
    }
    // After the last finding can have been noted: a list that lost one is
    // refused, never returned.
    if findings.overflow {
        return Err(Error::TooManyDeviations);
    }
    unit.findings = findings;
    Ok(Validation {
        deviations: findings.total(),
        validated: VALIDATED_FIELDS,
        unvalidated: UNVALIDATED_FIELDS,
        dma_admission: Admission::NotEstablished,
    })
}

/// Raw header and feature images of the used block, for reports only. There
/// is no public numeric getter: safe code outside this module can only
/// format them ([`Images::header`], [`Images::efr`]). The formatted text
/// contains the full images and could be parsed back; using it for a
/// decision is excluded by the review rule (module documentation), not by
/// the types.
#[derive(Clone, Copy)]
pub struct Images {
    info: u16,
    flags: u8,
    efr: Option<u64>,
    efr2: Option<u64>,
}

impl Images {
    /// `info=0x.... flags=0x..` for the report.
    pub fn header(&self) -> impl core::fmt::Display {
        let (info, flags) = (self.info, self.flags);
        Text(move |f: &mut core::fmt::Formatter<'_>| {
            write!(f, "info={info:#06x} flags={flags:#04x}")
        })
    }

    /// `efr=0x... efr2=0x...`, or `efr=none`, for the report.
    pub fn efr(&self) -> impl core::fmt::Display {
        let (efr, efr2) = (self.efr, self.efr2);
        Text(move |f: &mut core::fmt::Formatter<'_>| match efr {
            Some(efr) => write!(f, "efr={efr:#018x} efr2={:#x}", efr2.unwrap_or(0)),
            None => f.write_str("efr=none"),
        })
    }
}

/// Formats through a closure; holds no readable value.
struct Text<F>(F);

impl<F: Fn(&mut core::fmt::Formatter<'_>) -> core::fmt::Result> core::fmt::Display for Text<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        (self.0)(f)
    }
}

/// Whether DMA may be admitted on the strength of this table. Increment 2
/// establishes nothing: no enforcement path exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    NotEstablished,
}

impl Admission {
    pub fn name(&self) -> &'static str {
        match self {
            Admission::NotEstablished => "not-established",
        }
    }
}

/// What a parse that was not refused establishes, as separate properties.
/// Being returned at all means the table is structurally valid. A table
/// with no deviation is not thereby supported, and one with deviations is
/// not thereby unusable: a reviewed, named quirk could later admit an exact
/// deviation (none exists), and scope rules refuse valid tables.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Validation {
    /// Deviations found within the validated subset (`Unit::findings`).
    pub deviations: usize,
    /// The fields whose values and encodings were checked.
    pub validated: &'static [&'static str],
    /// Fields carried as images, not checked beyond reserved bit positions.
    pub unvalidated: &'static [&'static str],
    /// Always `NotEstablished` in increment 2.
    pub dma_admission: Admission,
}

/// The validated subset (module documentation), as field names.
pub const VALIDATED_FIELDS: &[&str] = &[
    "ivrs.signature",
    "ivrs.length",
    "ivrs.checksum",
    "ivrs.revision",
    "ivrs.reserved",
    "ivinfo.efrsup",
    "ivinfo.dma-remap",
    "ivinfo.reserved",
    "ivhd.type",
    "ivhd.length",
    "ivhd.deviceid",
    "ivhd.capability-offset",
    "ivhd.base",
    "ivhd.segment",
    "ivhd.info.reserved",
    "ivhd.flags.reserved(11h,40h)",
    "10h.feature(reserved-without-efrsup)",
    "10h.feature.hats",
    "10h.feature.gats",
    "10h.feature.msinumppr",
    "10h.feature.pnbanks-pncounters(nonzero)",
    "attributes.hatdis",
    "attributes.reserved",
    "efr.hats",
    "efr.pcsup",
    "efr.gats",
    "efr.iasup(1 defined bit)",
    "efr.perfoptsup(1 defined bit)",
    "efr.reserved",
    "efr2.reserved",
    "entries.type-length-order-pairing",
    "entries.overlaps-aliases",
    "entries.reserved",
    "entries.dte-setting(all 8 bits defined, Table 106)",
    "entries.extended-setting(bits 30:3 reserved; 31, 2:0 defined, Table 108)",
    "entries.special.variety",
    "entries.f0h.uid-format-length",
    "entries.f0h.hid-cid-representation",
    "blocks.agreement",
];

/// Carried, not validated: no enforcement decision may read them.
pub const UNVALIDATED_FIELDS: &[&str] = &[
    "ivinfo.htatsresv",
    "ivinfo.vasize",
    "ivinfo.pasize",
    "ivinfo.gvasize",
    "ivhd.info.unitid",
    "ivhd.info.msinum",
    "ivhd.flags(defined bits)",
    "10h.feature(pasmax,hesup,gasup,iasup,glxsup,gtsup,nxsup,xtsup)",
    "attributes(msinumppr,pnbanks,pncounters)",
    "efr(all fields but hats,pcsup,gats,iasup,perfoptsup)",
    "efr2(all defined fields)",
];

/// Where the unit's register window sits in the boot memory map.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Placement {
    /// Every overlapping row is typed reserved.
    Reserved,
    /// No row overlaps it (QEMU lists no row for its IOMMU window).
    Unlisted,
}

/// Memory-map type 2 (Multiboot2 / E820 reserved).
pub const MEMORY_RESERVED: u32 = 2;

/// Refuses a register window that overlaps any memory-map row not typed
/// reserved (RAM, ACPI reclaim or NVS, defective): programming registers
/// there would alias memory. Returns the offending row type.
pub fn placement(
    start: u64,
    length: u64,
    rows: impl Iterator<Item = (u64, u64, u32)>,
) -> Result<Placement, u32> {
    let end = start.saturating_add(length);
    let mut listed = false;
    for (base, size, kind) in rows {
        if base < end && start < base.saturating_add(size) {
            if kind != MEMORY_RESERVED {
                return Err(kind);
            }
            listed = true;
        }
    }
    Ok(if listed {
        Placement::Reserved
    } else {
        Placement::Unlisted
    })
}

#[cfg(test)]
mod tests;
