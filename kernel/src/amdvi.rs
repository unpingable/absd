//! The first AMD-Vi domain (#111 increment 3): pure encodings and decisions,
//! checked against AMD #48882 rev 3.11 and host-tested. The kernel side
//! (src/amdvi_hw.rs) writes what this module builds into memory and MMIO.
//!
//! - Device table entries (Table 7, Table 8): every DeviceID gets an entry
//!   with V=1, TV=0, IR=IW=0: a request needing a table walk has its walk
//!   terminated (Table 8), so its DMA is blocked; Mode and the root pointer
//!   are ignored and written as zero. This is the one blocked form: QEMU
//!   10.2.1 (dma-remap=on) passes a V=1 TV=1 Mode=000b function through
//!   untranslated whatever IR/IW say, and switches a function from its
//!   passthrough region to translation only when an INVALIDATE_DEVTAB_ENTRY
//!   for that DeviceID is processed while its entry has TV=0 or Mode≠0
//!   (amdvi-oracle INTERFACE v2 §2), so every entry is invalidated by
//!   DeviceID after the unit is enabled (src/amdvi_hw.rs). V=0 would pass
//!   DMA through untranslated and is never written. Interrupts are aborted
//!   (IV=1, IntCtl=00b) except for the IVRS special sources (IOAPIC, HPET),
//!   whose interrupts pass unmapped (IV=0). Exactly one DeviceID, the
//!   admitted device, gets a translated entry: Mode=011b (three levels,
//!   39-bit IOVA), the domain's root, IR=IW=1 at the DTE so the leaf PTEs
//!   alone decide, its own DomainID.
//! - Page tables (Figures 9, 10; Tables 15, 17, 18): IOVA = physical address
//!   of each granted 4 KiB page; only granted pages are present; leaf
//!   permissions per page; a granted page can be revoked (leaf zeroed), never
//!   remapped.
//! - Commands (§2.4, Figures 44–46, 51): COMPLETION_WAIT with a store,
//!   INVALIDATE_DEVTAB_ENTRY, INVALIDATE_IOMMU_PAGES (whole domain or one
//!   page), INVALIDATE_IOMMU_ALL.
//! - Events (Figure 54, Table 42; IO_PAGE_FAULT Figure 56,
//!   ILLEGAL_DEV_TABLE_ENTRY Figure 55): decoded for the report.
//! - Admission (owner decisions on coordination record#111, 2026-10-30): the table
//!   must be structurally valid with no deviation, or every deviation must
//!   be covered by a registered quirk whose conditions hold against the live
//!   registers; the live capability header and EFR must agree with the
//!   table on every field the path consumes; and the device's requester-ID
//!   closure must be its own DeviceID alone and disjoint from any tolerated
//!   alias range and its target.
//!
//! Fields the path consumes and where they come from: IVHD DeviceID,
//! capability offset, base (validated by `ivrs`); HATS (EFR image, checked
//! against the live EFR); PCSup (window size; checked against the live EFR);
//! IASup (live EFR bit 6, a defined single bit: decides whether
//! INVALIDATE_IOMMU_ALL may be issued, and must agree with the image); EFRSup
//! (IVinfo bit 0, checked against the capability header bit 27); device
//! scope and aliases (`ivrs`). The IVHD Coherent flag is **not** consumed:
//! setup writes Control.Coherent=1 explicitly and follows every table
//! change with explicit invalidation and a completion wait. The capability
//! header's HtTunnel bit is consumed (it turns on HtTunEn, so tunnel
//! traffic is translated) and the live EFR's PerfOptSup (PerfOptEn is
//! cleared when present).

use crate::ivrs::{Detail, Field, Finding, Source, Unit, Validation};

/// Bytes of one device table entry, and entries in a full table.
pub const DTE_BYTES: usize = 32;
pub const DEVICE_TABLE_ENTRIES: usize = 1 << 16;
/// MMIO 0000h Size field: (2 MiB / 4 KiB) - 1.
pub const DEVICE_TABLE_SIZE_FIELD: u64 = 0x1ff;
/// Command buffer and event log: 256 entries of 16 bytes (4 KiB), length
/// code 1000b (MMIO 0008h ComLen, 0010h EventLen).
pub const RING_ENTRIES: usize = 256;
pub const RING_LENGTH_CODE: u64 = 0b1000;

/// Host page-table depth used (DTE Mode 011b): 39-bit IOVA.
pub const MODE: u8 = 3;
pub const IOVA_LIMIT: u64 = 1 << 39;
pub const PAGE: u64 = 4096;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;

/// DomainID of every blocked entry (DTE: "DomainID must be valid when V=1").
pub const BLOCKED_DOMAIN: u16 = 0;
/// The edu's translated domain (the only one before #116).
pub const DOMAIN: u16 = 1;
/// The second device's domain (#116: the NVMe).
pub const SECOND_DOMAIN: u16 = 2;

/// MSI address range, never granted.
pub const MSI_START: u64 = 0xfee0_0000;
pub const MSI_END: u64 = 0xfef0_0000;
/// Pages one grant may hold.
pub const MAX_GRANT: usize = 32;

// --- Device table entries (Table 7) ---------------------------------------

const DTE_V: u64 = 1;
const DTE_TV: u64 = 1 << 1;
const DTE_MODE_SHIFT: u32 = 9;
const DTE_IR: u64 = 1 << 61;
const DTE_IW: u64 = 1 << 62;
/// Third qword (bits 191:128): IV is bit 128; IntCtl 189:188 = 00b aborts.
const DTE_IV: u64 = 1;

/// How a blocked entry treats the device's interrupts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Interrupts {
    /// IV=1, IntCtl=00b: fixed and arbitrated interrupts target aborted.
    Abort,
    /// IV=0: interrupts pass unmapped (IVRS special sources only).
    Pass,
}

/// DMA blocked: V=1, TV=0, IR=IW=0; Mode and root zero (ignored, Table 8).
pub fn dte_blocked(domain: u16, interrupts: Interrupts) -> [u64; 4] {
    [
        // The mutant writes the earlier V=1 TV=1 Mode=0 IR=IW=0 form, which
        // QEMU 10.2.1 passes through (negative control for the decoy check).
        if cfg!(absd_mutant_amdvi_blocked_passthrough_form) {
            DTE_V | DTE_TV
        } else {
            DTE_V
        },
        u64::from(domain),
        match interrupts {
            Interrupts::Abort if cfg!(absd_mutant_amdvi_irq_pass_bits) => DTE_IV | (1 << 58),
            Interrupts::Abort => DTE_IV,
            Interrupts::Pass => 0,
        },
        0,
    ]
}

/// Translated through `root` at depth [`MODE`]; IR=IW=1 at the DTE so the
/// page tables decide. Interrupts (increment 7): IV=1, IntCtl=10b (remapped
/// through `ir_table`, a 128-byte aligned table of [`IR_TABLE_ENTRIES`]
/// basic IRTEs, IntTabLen 1001b), IG=0, every pass bit clear.
pub fn dte_translated(domain: u16, root: u64, ir_table: u64) -> [u64; 4] {
    let intctl = if cfg!(absd_mutant_amdvi_irq_forward) {
        DTE_INTCTL_FORWARD
    } else {
        DTE_INTCTL_REMAP
    };
    [
        DTE_V | DTE_TV | (u64::from(MODE) << DTE_MODE_SHIFT) | (root & ADDRESS) | DTE_IR | DTE_IW,
        u64::from(domain),
        DTE_IV | (IR_TABLE_LEN_CODE << 1) | (ir_table & IR_TABLE_ROOT) | intctl,
        0,
    ]
}

// --- Interrupt remapping (Table 7 bits 191:128, Figure 15) ------------------

/// IntCtl (DTE bits 189:188, qword 2 bits 61:60): 10b remaps fixed and
/// arbitrated interrupts through the table; 01b (forward unmapped) is never
/// written (QEMU 10.2.1 delivers vector 0 for it).
const DTE_INTCTL_REMAP: u64 = 0b10 << 60;
const DTE_INTCTL_FORWARD: u64 = 0b01 << 60;
/// Interrupt table root pointer, DTE bits 179:134 (qword 2 bits 51:6).
const IR_TABLE_ROOT: u64 = 0x000f_ffff_ffff_ffc0;
/// IntTabLen 1001b: 512 entries. QEMU 10.2.1 ignores IntTabLen and indexes
/// any of 0x000–0x1ff, so the table covers all of them (DESIGN §4a).
const IR_TABLE_LEN_CODE: u64 = 0b1001;
pub const IR_TABLE_ENTRIES: usize = 512;
/// Bytes per basic IRTE (GAEn clear).
pub const IRTE_BYTES: usize = 4;
/// Pass bits in qword 2: InitPass 184, EIntPass 185, NMIPass 186, Lint0Pass
/// 190, Lint1Pass 191. Never set by ABSD.
pub const DTE_PASS_BITS: u64 = (1 << 56) | (1 << 57) | (1 << 58) | (1 << 62) | (1 << 63);

/// The one interrupt grant of the enforced boots: index and vector.
pub const IR_INDEX: u16 = 0x10;
pub const IR_VECTOR: u8 = 0x41;

/// A basic 32-bit IRTE (Figure 15): RemapEn=1, SupIOPF=0, IntType=000b
/// (fixed), RqEoi=0, DM=0 (physical), GuestMode=0, `dest`, `vector`.
pub fn irte_basic(vector: u8, dest: u8) -> u32 {
    1 | (u32::from(dest) << 8) | (u32::from(vector) << 16)
}

/// The offset of capability `id` in conventional configuration space,
/// walking the list from 34h: aligned, at or above 40h, at most 48 steps
/// (no loops). `read` returns the dword at an offset.
pub fn find_capability(mut read: impl FnMut(u8) -> u32, id: u8) -> Option<u8> {
    if (read(0x04) >> 16) & (1 << 4) == 0 {
        return None;
    }
    let mut at = read(0x34) as u8 & 0xfc;
    for _ in 0..48 {
        if at < 0x40 {
            return None;
        }
        let header = read(at);
        if header as u8 == id {
            return Some(at);
        }
        at = (header >> 8) as u8 & 0xfc;
    }
    None
}

/// MSI capability programming for one vector (PCI 3.0 §6.8.1): the
/// configuration dword writes, in order, that set the complete message
/// address (address-high zeroed on a 64-bit capability) and data and then
/// enable MSI with one message (MME=0, per-vector masking untouched).
/// `header` is the capability's first dword as read. `None` when the
/// capability's whole extent (address, data and, with per-vector masking,
/// the mask and pending dwords) does not fit below 100h: nothing is written.
/// Returns the writes and how many of them are used (3 or 4).
pub fn msi_writes(
    cap: u8,
    header: u32,
    address: u32,
    data: u16,
) -> Option<([(u8, u32); 4], usize)> {
    let wide = header & (1 << 23) != 0;
    let masking = header & (1 << 24) != 0;
    let extent: u16 = match (wide, masking) {
        (false, false) => 0x0c,
        (true, false) => 0x10,
        (false, true) => 0x14,
        (true, true) => 0x18,
    };
    if cap & 3 != 0 || u16::from(cap) < 0x40 || u16::from(cap) + extent > 0x100 {
        return None;
    }
    let enable = (header & !(0b111 << 20)) | (1 << 16);
    Some(if wide {
        (
            [
                (cap + 0x04, address),
                (cap + 0x08, 0),
                (cap + 0x0c, u32::from(data)),
                (cap, enable),
            ],
            4,
        )
    } else {
        (
            [
                (cap + 0x04, address),
                (cap + 0x08, u32::from(data)),
                (cap, enable),
                (0, 0),
            ],
            3,
        )
    })
}

/// MSI-X capability dword 0 with MSI-X Enable (bit 31) and Function Mask
/// (bit 30) set together, the rest as read (#116 ADD-7: the NVMe's vectors
/// are used but never sent by ABSD; only a device that ignores the mask
/// could send one, and the deny-all table must stop it).
pub fn msix_enable_masked(header: u32) -> u32 {
    let mask = if cfg!(absd_mutant_amdvi_msix_unmasked) {
        0
    } else {
        1 << 30
    };
    header | (1 << 31) | mask
}

/// The Event Log Tail register's offset (bits 18:4), if it lies inside a
/// ring of `ring_bytes`. A tail outside the ring (an all-ones read, a unit
/// gone wrong) can never be reached by a cursor that wraps at the ring's
/// end: the caller treats it as a failed unit and an incomplete record.
pub fn event_tail(raw: u64, ring_bytes: u64) -> Option<u64> {
    let tail = raw & 0x7fff0;
    if tail < ring_bytes || cfg!(absd_mutant_amdvi_tail_unchecked) {
        Some(tail)
    } else {
        None
    }
}

/// The one observation of the event log (DESIGN §4a "Event-log tail").
///
/// Invariant: every path that observes or drains the event log (setup's
/// batch and pre-arm gates, every completion boundary, revoke, restart,
/// SYNC) goes through this function, which latches the fault record
/// incomplete on Status EventOverflow or an Event Log Tail outside the ring,
/// fails the unit on an invalid tail, and returns no tail then, so nothing
/// is walked or consumed past it.
///
/// With a valid tail it feeds every pending code (`code(offset)`, head to
/// tail, wrapping, at most the ring's entries) to `health` without
/// consuming, and returns the tail a drain may consume up to.
pub fn observe_log(
    raw_tail: u64,
    overflow: bool,
    head: u64,
    ring_bytes: u64,
    health: &mut lifecycle::Health,
    record: &mut lifecycle::FaultRecord,
    mut code: impl FnMut(u64) -> u8,
) -> Option<u64> {
    let tail = event_tail(raw_tail, ring_bytes);
    let latch = if cfg!(absd_mutant_amdvi_tail_record_kept) {
        overflow
    } else {
        overflow || tail.is_none()
    };
    record.observe(0, latch);
    let Some(tail) = tail else {
        if !cfg!(absd_mutant_amdvi_tail_health_kept) {
            health.fail(lifecycle::FailReason::EventTail);
        }
        return None;
    };
    let mut at = head;
    for _ in 0..ring_bytes / 16 {
        if at == tail {
            break;
        }
        health.event(code(at));
        at = (at + 16) % ring_bytes;
    }
    Some(tail)
}

/// INVALIDATE_INTERRUPT_TABLE (Figure 48).
pub fn invalidate_interrupt_table(devid: u16) -> [u32; 4] {
    [u32::from(devid), 0x5 << 28, 0, 0]
}

// --- Page tables (Figures 9, 10; Tables 15, 17, 18) ------------------------

const PR: u64 = 1;
const NEXT_LEVEL_SHIFT: u32 = 9;
const PTE_IR: u64 = 1 << 61;
const PTE_IW: u64 = 1 << 62;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Perm {
    pub read: bool,
    pub write: bool,
}

impl Perm {
    pub const READ: Perm = Perm {
        read: true,
        write: false,
    };
    pub const WRITE: Perm = Perm {
        read: false,
        write: true,
    };
    pub const READ_WRITE: Perm = Perm {
        read: true,
        write: true,
    };

    fn bits(self) -> u64 {
        (if self.read { PTE_IR } else { 0 }) | (if self.write { PTE_IW } else { 0 })
    }
}

/// A directory entry at any level above 1: present, pointing at the next
/// table whose level is `next_level`, IR=IW=1 (the leaf decides).
pub fn pde(next_table: u64, next_level: u8) -> u64 {
    PR | (u64::from(next_level) << NEXT_LEVEL_SHIFT) | (next_table & ADDRESS) | PTE_IR | PTE_IW
}

/// A 4 KiB leaf: present, NextLevel 0, FC=0.
pub fn pte(page: u64, perm: Perm) -> u64 {
    PR | (page & ADDRESS) | perm.bits()
}

/// Index of `iova` in a table of `level` (Table 15).
pub fn index(iova: u64, level: u8) -> usize {
    ((iova >> (12 + 9 * (u32::from(level) - 1))) & 0x1ff) as usize
}

/// Page-table pages, by physical address. The kernel backs this with
/// frames (physical == virtual); host tests with a map.
pub trait Tables {
    /// A zeroed 4 KiB table; its physical address.
    fn allocate(&mut self) -> Option<u64>;
    fn read(&self, table: u64, index: usize) -> u64;
    fn write(&mut self, table: u64, index: usize, value: u64);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapError {
    Unaligned,
    OutOfRange,
    /// The IOVA is already mapped (nothing is remapped in this increment).
    Mapped,
    NoTable,
    /// Nothing is mapped at the IOVA (revoking).
    NotMapped,
}

/// Maps the page at `iova` to `page` with `perm`, creating tables under
/// `root` (a level-[`MODE`] table).
pub fn map(
    tables: &mut impl Tables,
    root: u64,
    iova: u64,
    page: u64,
    perm: Perm,
) -> Result<(), MapError> {
    if !iova.is_multiple_of(PAGE) || !page.is_multiple_of(PAGE) {
        return Err(MapError::Unaligned);
    }
    if iova >= IOVA_LIMIT || page & !ADDRESS != 0 {
        return Err(MapError::OutOfRange);
    }
    let mut table = root;
    let mut level = MODE;
    while level > 1 {
        let slot = index(iova, level);
        let entry = tables.read(table, slot);
        table = if entry & PR != 0 {
            entry & ADDRESS
        } else {
            let next = tables.allocate().ok_or(MapError::NoTable)?;
            tables.write(table, slot, pde(next, level - 1));
            next
        };
        level -= 1;
    }
    let slot = index(iova, 1);
    if tables.read(table, slot) & PR != 0 {
        return Err(MapError::Mapped);
    }
    tables.write(table, slot, pte(page, perm));
    Ok(())
}

/// Revokes the page at `iova`: its leaf entry becomes zero (not present).
/// Tables above it stay (they hold nothing else that changes).
pub fn unmap(tables: &mut impl Tables, root: u64, iova: u64) -> Result<(), MapError> {
    if !iova.is_multiple_of(PAGE) {
        return Err(MapError::Unaligned);
    }
    if iova >= IOVA_LIMIT {
        return Err(MapError::OutOfRange);
    }
    let mut table = root;
    let mut level = MODE;
    while level > 1 {
        let entry = tables.read(table, index(iova, level));
        if entry & PR == 0 {
            return Err(MapError::NotMapped);
        }
        table = entry & ADDRESS;
        level -= 1;
    }
    let slot = index(iova, 1);
    if tables.read(table, slot) & PR == 0 {
        return Err(MapError::NotMapped);
    }
    tables.write(table, slot, 0);
    Ok(())
}

/// The walk hardware does for an untranslated access to `iova` (Tables 17,
/// 18: permissions ANDed down the levels, the DTE's IR=IW=1 included):
/// the page and effective permission, or `None` when not present.
pub fn translate(tables: &impl Tables, root: u64, iova: u64) -> Option<(u64, Perm)> {
    if iova >= IOVA_LIMIT {
        return None;
    }
    let mut table = root;
    let mut perm = Perm::READ_WRITE;
    let mut level = MODE;
    loop {
        let entry = tables.read(table, index(iova, level));
        if entry & PR == 0 {
            return None;
        }
        perm.read &= entry & PTE_IR != 0;
        perm.write &= entry & PTE_IW != 0;
        let next = ((entry >> NEXT_LEVEL_SHIFT) & 7) as u8;
        if level == 1 {
            return (next == 0).then_some((entry & ADDRESS, perm));
        }
        if next != level - 1 {
            return None;
        }
        table = entry & ADDRESS;
        level -= 1;
    }
}

// --- Grants ------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantError {
    Empty,
    TooMany,
    Unaligned(u64),
    /// Zero, at or past the IOVA limit or the device's DMA reach, or in the
    /// MSI range.
    Forbidden(u64),
    /// Overlaps memory the IOMMU itself uses, or another forbidden range.
    Reserved(u64),
    Duplicate(u64),
    /// Granted to two devices (#116).
    Overlap(u64),
}

/// A grant is a list of (physical page, permission); IOVA = physical.
/// `reach` is the device's DMA address limit (exclusive); `reserved` are
/// physical ranges `[start, end)` no grant may touch.
pub fn check_grant(
    pages: &[(u64, Perm)],
    reach: u64,
    reserved: &[(u64, u64)],
) -> Result<(), GrantError> {
    if pages.is_empty() {
        return Err(GrantError::Empty);
    }
    if pages.len() > MAX_GRANT {
        return Err(GrantError::TooMany);
    }
    for (at, &(page, perm)) in pages.iter().enumerate() {
        if !page.is_multiple_of(PAGE) {
            return Err(GrantError::Unaligned(page));
        }
        let end = page.checked_add(PAGE).ok_or(GrantError::Forbidden(page))?;
        if page == 0
            || end > IOVA_LIMIT
            || end > reach
            || (page < MSI_END && MSI_START < end)
            || !(perm.read || perm.write)
        {
            return Err(GrantError::Forbidden(page));
        }
        if reserved
            .iter()
            .any(|&(start, stop)| page < stop && start < end)
        {
            return Err(GrantError::Reserved(page));
        }
        if pages[..at].iter().any(|&(other, _)| other == page) {
            return Err(GrantError::Duplicate(page));
        }
    }
    Ok(())
}

// --- Commands (§2.4) ---------------------------------------------------------

/// COMPLETION_WAIT (Figure 44): store `data` to `store` (8-byte aligned
/// system memory) when every earlier command has completed; f=1.
pub fn completion_wait(store: u64, data: u64) -> [u32; 4] {
    [
        (store as u32 & !7) | 0b101,
        (0x1 << 28) | ((store >> 32) as u32 & 0xf_ffff),
        data as u32,
        (data >> 32) as u32,
    ]
}

/// INVALIDATE_DEVTAB_ENTRY (Figure 45).
pub fn invalidate_devtab(devid: u16) -> [u32; 4] {
    [u32::from(devid), 0x2 << 28, 0, 0]
}

/// INVALIDATE_IOMMU_PAGES for the whole IOVA space of `domain` (Figure 46,
/// S=1 with every address bit from 12 set: Table 14), PDE=1.
pub fn invalidate_domain(domain: u16) -> [u32; 4] {
    [
        0,
        (0x3 << 28) | u32::from(domain),
        0xffff_f000 | 0b11,
        0x7fff_ffff,
    ]
}

/// INVALIDATE_IOMMU_PAGES for one 4 KiB page (S=0), PDE=1.
pub fn invalidate_page(domain: u16, iova: u64) -> [u32; 4] {
    [
        0,
        (0x3 << 28) | u32::from(domain),
        (iova as u32 & 0xffff_f000) | 0b10,
        (iova >> 32) as u32,
    ]
}

/// INVALIDATE_IOMMU_ALL (Figure 51); only when the live EFR has IASup.
pub fn invalidate_all() -> [u32; 4] {
    [0, 0x8 << 28, 0, 0]
}

/// The invalidations that establish deny-by-default once the unit is
/// enabled, before anything is granted (owner, coordination record#111 2026-10-30):
/// INVALIDATE_IOMMU_ALL when the live EFR has IASup, then one
/// INVALIDATE_DEVTAB_ENTRY for every DeviceID 0..=FFFFh whose entry was
/// written (all of them), whatever PCI enumeration found and whether or
/// not a driver asks. On QEMU 10.2.1 (dma-remap=on) a requester leaves its
/// passthrough region only on its own INVALIDATE_DEVTAB_ENTRY, so this is
/// what puts every requester, including firmware-left masters and every
/// member of an alias closure, behind its blocked entry. `target` is only
/// for the mutant that invalidates the granted device alone.
pub fn deny_by_default_invalidations(ia_sup: bool, target: u16) -> impl Iterator<Item = [u32; 4]> {
    let all = ia_sup.then(invalidate_all);
    let ids = if cfg!(absd_mutant_amdvi_invalidate_target_only) {
        u32::from(target)..=u32::from(target)
    } else {
        0..=u32::from(u16::MAX)
    };
    all.into_iter()
        .chain(ids.map(|id| invalidate_devtab(id as u16)))
}

/// One step of [`enforcement_plan`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step {
    /// Submit this command.
    Submit([u32; 4]),
    /// COMPLETION_WAIT and read the store back (label for the report; empty
    /// for intermediate batches).
    Complete(&'static str),
    /// Write target `n`'s translated entry (its grant); until here every
    /// entry, the targets' included, is blocked.
    GrantTarget(usize),
}

/// Batch size between completions in the deny-by-default sweep (half the
/// 256-entry command ring).
pub const SWEEP_BATCH: usize = 128;

/// Translated targets one boot may hold (#116: the edu and one NVMe or,
/// #123, one AHCI controller).
pub const MAX_TARGETS: usize = 3;

/// The AHCI controller's pinned function (#123): bus 0, device 7, function
/// 0, DeviceID 0x0038. QEMU q35's built-in ICH9 AHCI at 00:1f.2 holds the
/// boot CD and stays an inherited master the deny-by-default sweep blocks;
/// it is never a target.
pub const AHCI_PIN: (u8, u8, u8) = (0, 7, 0);

/// The AHCI backend's buffer set, in `ahci_block::dma_pages` order, with
/// each page's role and the least the controller needs: it writes the
/// command header's byte count (PRDBC) into the command list and received
/// FISes into the FIS area, reads the command FIS and PRDT from the command
/// table, and moves data both ways through the bounce page.
pub const AHCI_ROLES: [(&str, Perm); 4] = [
    ("cl", Perm::READ_WRITE),
    ("fis", Perm::READ_WRITE),
    ("ctba", Perm::READ),
    ("bounce", Perm::READ_WRITE),
];

/// Whether page `index` of an AHCI buffer set (`AHCI_ROLES` order) may be
/// revoked alone while the port runs. The command list and FIS area are
/// mapped by the controller when ST and FRE are set and used from that
/// mapping until they are cleared (QEMU's AHCI caches them), so a page
/// revocation of either would be acknowledged without being enforced:
/// refused. The command table and bounce page are fetched per command, so
/// their revocation takes effect at the next command.
pub fn ahci_page_revocable(index: usize) -> bool {
    matches!(index, 2 | 3)
}

/// The second translated target of a boot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Second {
    None,
    Nvme,
    Ahci,
}

/// Why no second target can be chosen; the boot refuses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecondRefusal {
    /// An AHCI disk was selected but no AHCI controller is at [`AHCI_PIN`].
    AhciNotPinned,
    /// An NVMe and the pinned AHCI controller would both be targets: more
    /// than [`MAX_TARGETS`].
    NvmeAndAhci,
}

impl SecondRefusal {
    pub fn word(self) -> &'static str {
        match self {
            SecondRefusal::AhciNotPinned => "ahci-not-at-00:07.0",
            SecondRefusal::NvmeAndAhci => "nvme-and-ahci",
        }
    }
}

/// The second target (#123): the AHCI controller only when a disk was
/// selected (`ahci_selected`) and an AHCI controller is at the pin
/// (`ahci_pinned`), never together with an NVMe; otherwise the NVMe when
/// one is present (#116, unchanged); otherwise none.
pub fn second_target(
    nvme: bool,
    ahci_selected: bool,
    ahci_pinned: bool,
) -> Result<Second, SecondRefusal> {
    match (nvme, ahci_selected, ahci_pinned) {
        (_, true, false) => Err(SecondRefusal::AhciNotPinned),
        (true, true, true) => Err(SecondRefusal::NvmeAndAhci),
        (false, true, true) => Ok(Second::Ahci),
        (true, false, _) => Ok(Second::Nvme),
        (false, false, _) => Ok(Second::None),
    }
}

/// Everything after IommuEn, in order (owner, coordination record#111 2026-10-30:
/// deny-by-default for every requester before anything is granted): the
/// whole [`deny_by_default_invalidations`] sweep with a completion every
/// [`SWEEP_BATCH`] commands and at its end; only then the grants. Each
/// target `(DeviceID, DomainID)` in `targets` gets its translated entry, its
/// own INVALIDATE_DEVTAB_ENTRY, a whole-domain INVALIDATE_IOMMU_PAGES for
/// its own domain and its INVALIDATE_INTERRUPT_TABLE; one completion
/// follows them all. Arming follows the plan. (#116: the plan was written
/// for exactly one target and one domain; abstraction leak L2.)
pub fn enforcement_plan<'a>(
    ia_sup: bool,
    targets: &'a [(u16, u16)],
    priority: &'a [u16],
) -> impl Iterator<Item = Step> + 'a {
    let first_target = targets.first().map_or(0, |&(id, _)| id);
    let sweep = deny_by_default_invalidations(ia_sup, first_target)
        .enumerate()
        .flat_map(|(at, command)| {
            core::iter::once(Step::Submit(command))
                .chain((at % SWEEP_BATCH == SWEEP_BATCH - 1).then_some(Step::Complete("")))
        });
    // Increment 6: the DeviceIDs known to be bus-mastering at hand-off (and
    // the IDs their requests arrive as) are invalidated first and completed,
    // so on QEMU 10.2.1, which moves a function off passthrough only on its
    // own INVALIDATE_DEVTAB_ENTRY, an inherited master is blocked within one
    // completion of IommuEn rather than somewhere in the 65 536-entry sweep.
    // At most SWEEP_BATCH entries; the full sweep still covers every ID.
    let first: &[u16] = &priority[..priority.len().min(SWEEP_BATCH)];
    let late = cfg!(absd_mutant_amdvi_priority_late);
    let front = first
        .iter()
        .map(|&id| Step::Submit(invalidate_devtab(id)))
        .chain((!first.is_empty()).then_some(Step::Complete("inherited")));
    let (front_early, front_late) = (
        front.clone().filter(move |_| !late),
        front.filter(move |_| late),
    );
    let targets = &targets[..targets.len().min(MAX_TARGETS)];
    let grant = targets
        .iter()
        .enumerate()
        .flat_map(|(at, &(target, domain))| {
            [
                Step::GrantTarget(at),
                Step::Submit(invalidate_devtab(target)),
                Step::Submit(invalidate_domain(domain)),
                Step::Submit(if cfg!(absd_mutant_amdvi_irq_no_invalidate) {
                    invalidate_domain(domain)
                } else {
                    invalidate_interrupt_table(target)
                }),
            ]
        })
        .chain(core::iter::once(Step::Complete("grant")));
    // The mutant grants before the sweep (the ordering the owner forbids).
    let early = cfg!(absd_mutant_amdvi_grant_first);
    let before = grant.clone().filter(move |_| early);
    let after = grant.filter(move |_| !early);
    front_early
        .chain(before)
        .chain(sweep)
        .chain(front_late)
        .chain(core::iter::once(Step::Complete("invalidate")))
        .chain(after)
}

/// Grants of different devices may not share a page (#116, admission):
/// with IOVA = physical, a shared page would be reachable by both
/// requesters, so the boundary between them would not exist. Every pair of
/// grants in `grants` (each device's every buffer set) must be disjoint;
/// the first page found in two of them is refused. (Abstraction leak L3:
/// the single-device grant model had no cross-device rule.)
pub fn check_disjoint(grants: &[&[(u64, Perm)]]) -> Result<(), GrantError> {
    for (at, grant) in grants.iter().enumerate() {
        for &(page, _) in grant.iter() {
            let base = page & !(PAGE - 1);
            let clash = grants[at + 1..]
                .iter()
                .any(|other| other.iter().any(|&(o, _)| o & !(PAGE - 1) == base));
            if clash && !cfg!(absd_mutant_amdvi_overlap_unchecked) {
                return Err(GrantError::Overlap(base));
            }
        }
    }
    Ok(())
}

// --- Events (Figure 54, Table 42) ------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    IllegalDevTableEntry {
        devid: u16,
        address: u64,
    },
    /// `write`: RW bit; `permission`: PE bit; `present`: PR bit.
    IoPageFault {
        devid: u16,
        domain: u16,
        address: u64,
        write: bool,
        permission: bool,
        present: bool,
        interrupt: bool,
    },
    /// Any other code, raw.
    Other {
        code: u8,
        raw: [u32; 4],
    },
}

impl Event {
    pub fn decode(raw: [u32; 4]) -> Event {
        let code = (raw[1] >> 28) as u8;
        let devid = raw[0] as u16;
        let address = u64::from(raw[2]) | (u64::from(raw[3]) << 32);
        match code {
            0b0001 => Event::IllegalDevTableEntry {
                devid,
                address: address & !3,
            },
            0b0010 => Event::IoPageFault {
                devid,
                domain: raw[1] as u16,
                address,
                write: raw[1] & (1 << 21) != 0,
                permission: raw[1] & (1 << 22) != 0,
                present: raw[1] & (1 << 20) != 0,
                interrupt: raw[1] & (1 << 19) != 0,
            },
            other => Event::Other { code: other, raw },
        }
    }
}

// --- Admission -------------------------------------------------------------

/// Registers read from the unit itself, for comparison with the table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Live {
    /// Capability Offset 00h (§3.2).
    pub cap_header: u32,
    /// MMIO 0030h; 0 (not read) when the capability header lacks EFRSup.
    pub efr: u64,
    /// MMIO 4000h (Counter Configuration), read only when the unit has
    /// performance counters (PCSup; the 512 KiB window).
    pub counters: Option<u64>,
}

const CAP_EFR_SUP: u32 = 1 << 27;
const EFR_HATS_SHIFT: u32 = 10;
const EFR_PC_SUP: u64 = 1 << 9;
/// EFR IASup (bit 6): INVALIDATE_IOMMU_ALL supported.
pub const EFR_IA_SUP: u64 = 1 << 6;
/// EFR PerfOptSup (bit 45): MMIO 016Ch PerfOptEn exists.
pub const EFR_PERF_OPT_SUP: u64 = 1 << 45;

impl Live {
    pub fn ia_sup(&self) -> bool {
        self.efr & EFR_IA_SUP != 0
    }

    pub fn perf_opt_sup(&self) -> bool {
        self.efr & EFR_PERF_OPT_SUP != 0
    }

    fn hats(&self) -> u8 {
        ((self.efr >> EFR_HATS_SHIFT) & 3) as u8
    }
}

/// A named, versioned compatibility rule for one exact deviation (owner
/// decision on coordination record#111, 2026-10-30, conditions 1–5).
#[derive(Debug)]
pub struct Quirk {
    pub name: &'static str,
    pub version: u8,
    /// Does this quirk cover `finding` for this unit and these registers?
    covers: fn(&Unit, &Finding, &Live) -> bool,
}

/// QEMU (observed: 10.2.1, `hw/i386/acpi-build.c` `build_amd_iommu`): the
/// superseded 10h feature field's HATS reads 00b because the generator's
/// shift overflows the 32-bit field, while the used 11h EFR image says 10b.
/// Covered only when: the finding is exactly that (block 10h, the field at
/// the 10h block's offset 20, `hats=0 efr-hats=2`); the 11h block is used;
/// and the live EFR's HATS equals the image's (so the superseded value is
/// the wrong one and the path, which reads the image, is unaffected).
pub const QEMU_SUPERSEDED_10H_HATS: Quirk = Quirk {
    name: "qemu-superseded-10h-hats",
    version: 1,
    covers: |unit, finding, live| {
        unit.used == 0x11
            && finding.block == 0x10
            && finding.field == Field::HatsDisagrees
            && matches!(
                finding.detail,
                Detail::Hats {
                    table: 0,
                    efr: 2,
                    ..
                }
            )
            && unit.hats_code() == Some(2)
            && live.hats() == 2
    },
};

/// EFR PPRSup (bit 1).
const EFR_PPR_SUP: u64 = 1 << 1;

/// Q-L1. A wide (11h/40h) block whose flags byte is the 10h flags byte
/// copied: bit 7 is PPRSup in 10h (Table 92) and reserved in 11h/40h
/// (Tables 97, 101). Observed on firmware the backend targets and checked
/// against that unit's live registers (lane record). Covered only when: the finding is a
/// wide block's flags-reserved finding whose unexpected bits are exactly
/// bit 7; that flags byte equals the unit's 10h flags byte; and the live
/// EFR has PPRSup, so the copied bit says what the hardware says. ABSD
/// consumes no IVHD flag, so the bit cannot alter isolation.
pub const WIDE_FLAGS_PPR_COPY: Quirk = Quirk {
    name: "wide-flags-ppr-copy",
    version: 1,
    covers: |unit, finding, live| {
        matches!(finding.block, 0x11 | 0x40)
            && finding.field == Field::FlagsReserved
            && matches!(finding.detail, Detail::Bits { raw, unexpected }
                if (unexpected == 0x80
                    || (cfg!(absd_mutant_amdvi_quirk_ppr_bits) && unexpected & 0x80 != 0))
                    && raw <= 0xff
                    && unit.flags_equal_10h(raw as u8))
            && (live.efr & EFR_PPR_SUP != 0 || cfg!(absd_mutant_amdvi_quirk_ppr))
    },
};

/// Q-L2. A wide block's attributes word with the performance-counter count
/// at the MMIO 4000h position (NCounter, bits 10:7) instead of PNCounters
/// (16:13): reserved bits inside 10:7 set, PNCounters zero. Observed on
/// firmware the backend targets and checked against that unit's live
/// registers (lane record).
/// Covered only when: the finding is a wide block's attributes-reserved
/// finding whose unexpected bits lie only in 10:7; PNCounters is zero; and
/// the live Counter Configuration register (read) gives NCounter equal to
/// bits 10:7 and NCounterBanks equal to PNBanks. ABSD reads only HATDis
/// from the attributes word (the window comes from the EFR's PCSup), so the
/// bits cannot alter isolation.
pub const WIDE_ATTRIBUTES_COUNTERS_MISPLACED: Quirk = Quirk {
    name: "wide-attributes-counters-misplaced",
    version: 1,
    covers: |_, finding, live| {
        let Detail::Bits { raw, unexpected } = finding.detail else {
            return false;
        };
        let Some(counters) = live.counters else {
            return false;
        };
        matches!(finding.block, 0x11 | 0x40)
            && finding.field == Field::AttributesReserved
            && unexpected != 0
            && unexpected & !0x780 == 0
            && (raw >> 13) & 0xf == 0
            // NCounter 1 is a reserved encoding (MMIO 4000h, 10:7).
            && ((raw >> 7) & 0xf != 1 || cfg!(absd_mutant_amdvi_quirk_reserved_count))
            && ((raw >> 7) & 0xf == (counters >> 7) & 0xf
                || cfg!(absd_mutant_amdvi_quirk_ncounter))
            && ((raw >> 17) & 0x3f == (counters >> 12) & 0x3f
                || cfg!(absd_mutant_amdvi_quirk_banks))
    },
};

/// The alias range over a range's tail (owner decision, coordination record#111,
/// 2026-10-30): accepted at table level as a scoped exclusion; the
/// condition is enforced per device by [`admit_device`] (no admitted
/// device's requester-ID closure may touch the aliased bus or its target).
pub const ALIAS_OVER_RANGE_TAIL_SCOPED: Quirk = Quirk {
    name: "alias-over-range-tail-scoped",
    version: 1,
    covers: |_, finding, _| {
        finding.field == Field::AliasOverRangeTail
            && matches!(finding.detail, Detail::AliasRange { .. })
    },
};

/// Registered quirks.
pub const QUIRKS: &[&Quirk] = &[
    &QEMU_SUPERSEDED_10H_HATS,
    &WIDE_FLAGS_PPR_COPY,
    &WIDE_ATTRIBUTES_COUNTERS_MISPLACED,
    &ALIAS_OVER_RANGE_TAIL_SCOPED,
];

/// MMIO 0030h, Extended Feature Register.
pub const MMIO_EFR: u64 = 0x0030;
/// MMIO 4000h, Counter Configuration.
pub const MMIO_COUNTER_CONFIG: u64 = 0x4000;

/// Whether the Counter Configuration register (MMIO 4000h) may be read,
/// in prerequisite order: the live capability header has EFRSup (otherwise
/// 0030h is reserved and its value means nothing), the image has PCSup
/// (otherwise the mapped window is 16 KiB), and the live EFR (`efr`) has
/// PCSup (otherwise the unit decodes 16 KiB and the counter registers are
/// reserved).
pub fn counter_config_readable(unit: &Unit, cap_header: u32, efr: u64) -> bool {
    (cap_header & CAP_EFR_SUP != 0 || cfg!(absd_mutant_amdvi_efr_unsupported))
        && unit.counters()
        && (efr & EFR_PC_SUP != 0 || cfg!(absd_mutant_amdvi_counter_read))
}

/// The live registers admission compares, read through `read` (an MMIO
/// offset to its 64-bit value) in prerequisite order: EFR only when the
/// capability header has EFRSup (otherwise recorded as 0, never read), then
/// Counter Configuration only when [`counter_config_readable`].
pub fn acquire_live(unit: &Unit, cap_header: u32, mut read: impl FnMut(u64) -> u64) -> Live {
    let efr = if cap_header & CAP_EFR_SUP != 0 || cfg!(absd_mutant_amdvi_efr_unsupported) {
        read(MMIO_EFR)
    } else {
        0
    };
    let counters =
        counter_config_readable(unit, cap_header, efr).then(|| read(MMIO_COUNTER_CONFIG));
    Live {
        cap_header,
        efr,
        counters,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableRefusal {
    /// IVinfo EFRSup disagrees with the capability header's EFRSup.
    EfrSupMismatch,
    /// The live EFR disagrees with the image on HATS, PCSup, IASup or
    /// PerfOptSup.
    EfrMismatch,
    /// No usable host page-table depth.
    NoHostLevels,
    /// A deviation no registered quirk covers (index into the findings).
    Uncovered(usize),
}

/// The table as admitted: how many deviations quirks covered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableAdmission {
    pub quirked: usize,
}

/// Whether DMA may ever be admitted on this table (conditions on the table
/// and live registers only; the device is [`admit_device`]).
pub fn admit_table(
    unit: &Unit,
    validation: &Validation,
    live: &Live,
) -> Result<TableAdmission, TableRefusal> {
    if unit.efr_sup() != (live.cap_header & CAP_EFR_SUP != 0) {
        return Err(TableRefusal::EfrSupMismatch);
    }
    let Some(levels) = unit.host_levels() else {
        return Err(TableRefusal::NoHostLevels);
    };
    if levels < MODE {
        return Err(TableRefusal::NoHostLevels);
    }
    // Every consumed capability must agree with the live register.
    if unit.efr_sup()
        && (unit.hats_code() != Some(live.hats())
            || unit.counters() != (live.efr & EFR_PC_SUP != 0)
            || unit.ia_sup().is_some_and(|image| image != live.ia_sup())
            || unit
                .perf_opt_sup()
                .is_some_and(|image| image != live.perf_opt_sup()))
    {
        return Err(TableRefusal::EfrMismatch);
    }
    let mut quirked = 0;
    for (at, finding) in unit.findings.items().iter().enumerate() {
        let covered = QUIRKS
            .iter()
            .any(|quirk| (quirk.covers)(unit, finding, live));
        if !covered && !cfg!(absd_mutant_amdvi_quirk_any) {
            return Err(TableRefusal::Uncovered(at));
        }
        quirked += 1;
    }
    debug_assert_eq!(quirked, validation.deviations);
    Ok(TableAdmission { quirked })
}

/// The quirk covering `finding`, for the report.
pub fn quirk_for(unit: &Unit, finding: &Finding, live: &Live) -> Option<&'static Quirk> {
    QUIRKS
        .iter()
        .copied()
        .find(|quirk| (quirk.covers)(unit, finding, live))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceRefusal {
    /// The IOMMU's own function.
    Iommu,
    /// No IVHD entry names it.
    Undescribed,
    /// Its requests carry another DeviceID.
    Aliased(u16),
    /// Another DeviceID's requests carry this one (a shared requester ID).
    SharedRequester(u16),
    /// It is an IVRS special source (IOAPIC/HPET).
    SpecialSource,
    /// Its closure touches a tolerated alias range or its target.
    TouchesToleratedAlias,
}

/// The alias-closure rule (owner decision, 2026-10-30): the device's
/// requester-ID closure, every DeviceID whose requests reach the IOMMU as
/// this device's, directly or through aliasing, must be the device alone,
/// and must be disjoint from every tolerated alias range and its target.
/// Chains are refused by the parser, so one step of aliasing is the whole
/// closure.
pub fn admit_device(unit: &Unit, devid: u16) -> Result<(), DeviceRefusal> {
    if devid == unit.devid {
        return Err(DeviceRefusal::Iommu);
    }
    // The owner's scoped exclusion first: nothing near a tolerated alias.
    for finding in unit.findings.items() {
        // Each finding carries its own block's target: a superseded block's
        // alias may name a different device than the selected block's.
        if let Detail::AliasRange {
            first,
            last,
            target,
            ..
        } = finding.detail
        {
            let target = if cfg!(absd_mutant_amdvi_tolerated_selected_target) {
                unit.entries
                    .spans()
                    .iter()
                    .find(|span| span.first == first && span.last == last)
                    .and_then(|span| span.alias)
                    .unwrap_or(target)
            } else {
                target
            };
            if !cfg!(absd_mutant_amdvi_ignore_tolerated)
                && ((first <= devid && devid <= last) || target == devid)
            {
                return Err(DeviceRefusal::TouchesToleratedAlias);
            }
        }
    }
    match unit.source(devid) {
        Source::Own => {}
        Source::Undescribed => return Err(DeviceRefusal::Undescribed),
        Source::Alias(target) => return Err(DeviceRefusal::Aliased(target)),
    }
    for span in unit.entries.spans() {
        if span.alias == Some(devid) && !cfg!(absd_mutant_amdvi_ignore_closure) {
            return Err(DeviceRefusal::SharedRequester(span.first));
        }
    }
    if unit.entries.specials().iter().any(|s| s.source == devid) {
        return Err(DeviceRefusal::SpecialSource);
    }
    Ok(())
}

/// Every DeviceID's initial entry, the target's included: blocked
/// (interrupts passed for special sources). The target's translated entry
/// ([`dte_translated`]) is written only at [`Step::GrantTarget`].
pub fn dte_initial(unit: &Unit, devid: u16) -> [u64; 4] {
    let special = unit.entries.specials().iter().any(|s| s.source == devid);
    dte_blocked(
        BLOCKED_DOMAIN,
        if special {
            Interrupts::Pass
        } else {
            Interrupts::Abort
        },
    )
}

pub mod lifecycle;
pub mod scope;

#[cfg(test)]
mod tests;
