//! Whole-RAM admission plan for the x86 boot: which usable bytes become
//! tracked frames, how large the boot-placed tag table is, which GiBs need a
//! direct-map page directory, and where that block goes. Pure arithmetic;
//! the boot code reads the Multiboot2 map, applies the plan, and builds the
//! mapping.
//!
//! Rule: below 1 GiB, usable RAM is tracked at 4 KiB granularity (boot.S
//! identity-maps that GiB). From 1 GiB up to `PHYSICAL_TRACKING_BOUND`, only
//! whole 2 MiB pages inside a usable row are tracked, so the kernel direct
//! map built from them covers RAM and nothing else (no write-back alias of
//! a device or firmware range). Everything else is clipped and disclosed.

use crate::memory::{
    MAX_TRACKED_FRAMES, PAGE_SIZE, PHYSICAL_TRACKING_BOUND, TRACKED_PHYSICAL_LIMIT,
};

pub const ONE_GIB: u64 = 1 << 30;
pub const TWO_MIB: u64 = 2 << 20;
/// GiBs the direct map may cover; one bit each in `Plan::gibs`.
const _: () = assert!(PHYSICAL_TRACKING_BOUND / ONE_GIB <= 64);

/// A callback-driven walk over usable `(start, end)` rows.
pub type Rows<'a> = &'a dyn Fn(&mut dyn FnMut(u64, u64));

/// The trackable parts of usable `[start, end)`: the 4 KiB-aligned part
/// below 1 GiB and the 2 MiB-aligned part from 1 GiB to the bound. Empty
/// parts are `(0, 0)`.
pub fn tracked_parts(start: u64, end: u64) -> [(u64, u64); 2] {
    let part = |low: Option<u64>, high: u64| match low {
        Some(low) if low < high => (low, high),
        _ => (0, 0),
    };
    let low = part(
        start.checked_next_multiple_of(PAGE_SIZE),
        (end & !(PAGE_SIZE - 1)).min(ONE_GIB),
    );
    let high = part(
        start.max(ONE_GIB).checked_next_multiple_of(TWO_MIB),
        end.min(PHYSICAL_TRACKING_BOUND) & !(TWO_MIB - 1),
    );
    [low, high]
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Plan {
    /// Bytes of whole pages inside usable rows (before any clipping).
    pub usable_bytes: u64,
    /// Bytes `tracked_parts` keeps (rows assumed disjoint, as firmware gives).
    pub tracked_bytes: u64,
    /// Highest tracked end.
    pub tracked_end: u64,
    /// Bit g set: GiB g (g >= 1) holds tracked 2 MiB pages.
    pub gibs: u64,
}

impl Plan {
    pub fn from_rows(rows: Rows) -> Self {
        let mut plan = Self::default();
        rows(&mut |start, end| {
            if let Some(low) = start.checked_next_multiple_of(PAGE_SIZE) {
                plan.usable_bytes += (end & !(PAGE_SIZE - 1)).saturating_sub(low);
            }
            for (part_start, part_end) in tracked_parts(start, end) {
                if part_start == part_end {
                    continue;
                }
                plan.tracked_bytes += part_end - part_start;
                plan.tracked_end = plan.tracked_end.max(part_end);
                if part_start >= ONE_GIB {
                    for gib in part_start / ONE_GIB..=(part_end - 1) / ONE_GIB {
                        plan.gibs |= 1 << gib;
                    }
                }
            }
        });
        plan
    }
    /// Whether the built-in 256 MiB table is too small for this map.
    pub fn needs_table(&self) -> bool {
        self.tracked_end > TRACKED_PHYSICAL_LIMIT
    }
    /// Tags in the boot-placed table (0 when the built-in table suffices).
    pub fn tag_frames(&self) -> usize {
        if self.needs_table() {
            ((self.tracked_end / PAGE_SIZE) as usize).max(MAX_TRACKED_FRAMES + 1)
        } else {
            0
        }
    }
    /// Page directories the direct map needs above the first GiB.
    pub fn directories(&self) -> usize {
        self.gibs.count_ones() as usize
    }
    /// Bytes to reserve: the directories first, then the tag table.
    pub fn block_bytes(&self) -> u64 {
        if !self.needs_table() {
            return 0;
        }
        let tags = (self.tag_frames() as u64 * 4).next_multiple_of(PAGE_SIZE);
        self.directories() as u64 * PAGE_SIZE + tags
    }
}

/// What the boot does with one tracked 2 MiB page above the first GiB.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectPage {
    /// Identity-map it write-back.
    Map,
    /// A device mapping already covers part of it (firmware reported device
    /// memory, such as a framebuffer, inside a usable row): never alias it;
    /// reserve the whole page instead.
    DeviceExcluded,
}

/// Walks the tracked 2 MiB pages from 1 GiB to `limit` in order. A page is
/// tracked when its first frame is free (`ram_plan` admits only whole 2 MiB
/// pages there); `device` says whether a device mapping overlaps a range.
pub fn direct_pages(
    limit: u64,
    is_free: &dyn Fn(u64) -> bool,
    device: &dyn Fn(u64, u64) -> bool,
    f: &mut dyn FnMut(u64, DirectPage),
) {
    let mut page = ONE_GIB;
    while page < limit {
        if is_free(page) {
            f(
                page,
                if device(page, page + TWO_MIB) {
                    DirectPage::DeviceExcluded
                } else {
                    DirectPage::Map
                },
            );
        }
        page += TWO_MIB;
    }
}

/// Lowest page-aligned start of `bytes` inside one usable row, below
/// `limit`, overlapping no excluded range.
pub fn place(bytes: u64, rows: Rows, exclusions: &[(u64, u64)], limit: u64) -> Option<u64> {
    if bytes == 0 {
        return None;
    }
    let fits = |at: u64| {
        let Some(end) = at.checked_add(bytes).filter(|&end| end <= limit) else {
            return false;
        };
        let mut inside = false;
        rows(&mut |start, row_end| inside |= start <= at && end <= row_end);
        inside && !exclusions.iter().any(|&(s, e)| s < end && at < e)
    };
    let mut best: Option<u64> = None;
    let mut consider = |candidate: u64| {
        if let Some(at) = candidate.checked_next_multiple_of(PAGE_SIZE)
            && best.is_none_or(|best| at < best)
            && fits(at)
        {
            best = Some(at);
        }
    };
    for &(_, end) in exclusions {
        consider(end);
    }
    rows(&mut |start, _| consider(start));
    best
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn walk(rows: &[(u64, u64)]) -> impl Fn(&mut dyn FnMut(u64, u64)) + '_ {
        move |f: &mut dyn FnMut(u64, u64)| {
            for &(s, e) in rows {
                f(s, e)
            }
        }
    }

    /// QEMU q35 with -m 4G: 2 GiB below the PCI hole, 2 GiB above 4 GiB.
    const Q35_4G: [(u64, u64); 3] = [
        (0, 0x9fc00),
        (0x10_0000, 0x7ffd_f000),
        (0x1_0000_0000, 0x1_8000_0000),
    ];

    #[test]
    fn parts_split_at_one_gib_and_round_high_ranges_to_two_mib() {
        assert_eq!(tracked_parts(0x1003, 0x9fc00), [(0x2000, 0x9f000), (0, 0)]);
        assert_eq!(
            tracked_parts(0x10_0000, 0x7ffd_f000),
            [(0x10_0000, ONE_GIB), (ONE_GIB, 0x7fe0_0000)]
        );
        assert_eq!(
            tracked_parts(0x1_0000_1000, 0x1_0040_0000),
            [(0, 0), (0x1_0020_0000, 0x1_0040_0000)]
        );
        // Less than one aligned 2 MiB page above 1 GiB is clipped entirely.
        assert_eq!(tracked_parts(0x4010_0000, 0x4030_0000), [(0, 0), (0, 0)]);
        assert_eq!(tracked_parts(u64::MAX - 10, u64::MAX), [(0, 0), (0, 0)]);
    }

    #[test]
    fn bound_clips_ram_above_64_gib_and_is_disclosed() {
        assert_eq!(PHYSICAL_TRACKING_BOUND, 64 << 30);
        let rows = [(0x10_0000, 0x8000_0000), (0x1_0000_0000, 0x18_0000_0000)];
        let plan = Plan::from_rows(&walk(&rows));
        assert_eq!(plan.tracked_end, PHYSICAL_TRACKING_BOUND);
        assert_eq!(
            plan.usable_bytes - plan.tracked_bytes,
            0x18_0000_0000 - PHYSICAL_TRACKING_BOUND
        );
        assert_eq!(plan.tag_frames(), crate::memory::MAX_EXTENDED_FRAMES);
        // GiB 1 and GiBs 4..63.
        assert_eq!(plan.directories(), 1 + 60);
        assert_eq!(plan.block_bytes(), 61 * PAGE_SIZE + (64 << 20));
    }

    #[test]
    fn q35_four_gib_plan_tracks_above_four_gib() {
        let plan = Plan::from_rows(&walk(&Q35_4G));
        assert!(plan.needs_table());
        assert_eq!(plan.tracked_end, 0x1_8000_0000);
        assert_eq!(plan.gibs, (1 << 1) | (1 << 4) | (1 << 5));
        assert_eq!(plan.tag_frames(), 0x18_0000);
        // Clipped: the 1 GiB..2 GiB row tail below its last 2 MiB page.
        assert_eq!(
            plan.usable_bytes - plan.tracked_bytes,
            0x7ffd_f000 - 0x7fe0_0000
        );
        assert_eq!(plan.block_bytes(), 3 * PAGE_SIZE + 0x60_0000);
    }

    #[test]
    fn small_maps_keep_the_built_in_table() {
        let plan = Plan::from_rows(&walk(&[(0, 0x9fc00), (0x10_0000, 0x7fe_0000)]));
        assert!(!plan.needs_table());
        assert_eq!(
            (plan.tag_frames(), plan.directories(), plan.block_bytes()),
            (0, 0, 0)
        );
        let empty = Plan::from_rows(&walk(&[]));
        assert_eq!(empty, Plan::default());
    }

    #[test]
    fn device_memory_inside_a_usable_row_is_excluded_not_mapped() {
        // Tracked: 1 GiB..1 GiB + 8 MiB and 4 GiB..4 GiB + 4 MiB. A
        // framebuffer reported inside the first row covers parts of two
        // pages; one device range outside tracked RAM changes nothing.
        let free = |page: u64| {
            (ONE_GIB..ONE_GIB + 8 * (1 << 20)).contains(&page)
                || (4 * ONE_GIB..4 * ONE_GIB + 4 * (1 << 20)).contains(&page)
        };
        let devices = [
            (ONE_GIB + TWO_MIB + 0x1000, ONE_GIB + 2 * TWO_MIB + 0x1000),
            (0xfd00_0000, 0xfe00_0000),
        ];
        let device = |s: u64, e: u64| devices.iter().any(|&(ds, de)| ds < e && s < de);
        let mut seen = Vec::new();
        direct_pages(5 * ONE_GIB, &free, &device, &mut |page, what| {
            seen.push((page, what))
        });
        use DirectPage::{DeviceExcluded, Map};
        assert_eq!(
            seen,
            [
                (ONE_GIB, Map),
                (ONE_GIB + TWO_MIB, DeviceExcluded),
                (ONE_GIB + 2 * TWO_MIB, DeviceExcluded),
                (ONE_GIB + 3 * TWO_MIB, Map),
                (4 * ONE_GIB, Map),
                (4 * ONE_GIB + TWO_MIB, Map),
            ]
        );
    }

    #[test]
    fn placement_avoids_exclusions_and_respects_rows_and_limit() {
        let exclusions = [
            (0, 0x10_0000),
            (0x10_0000, 0x30_0000),
            (0x2000_0000, 0x2040_0000),
        ];
        let walker = walk(&Q35_4G);
        assert_eq!(
            place(0x60_3000, &walker, &exclusions, ONE_GIB),
            Some(0x30_0000)
        );
        // Too large for the space before the page-test window: placed after
        // it, if the limit allows.
        assert_eq!(
            place(0x2000_0000, &walker, &exclusions, 2 * ONE_GIB),
            Some(0x2040_0000)
        );
        assert_eq!(place(0x2000_0000, &walker, &exclusions, ONE_GIB), None);
        // Nothing fits below the limit.
        assert_eq!(place(ONE_GIB, &walker, &exclusions, ONE_GIB), None);
        assert_eq!(place(0, &walker, &exclusions, ONE_GIB), None);
        // A row that ends inside the request is not used.
        let short: Vec<(u64, u64)> = std::vec![(0x10_0000, 0x20_0000)];
        assert_eq!(place(0x20_0000, &walk(&short), &[], ONE_GIB), None);
    }
}
