//! x86 whole-RAM frame tracking: the boot-placed tag table and the kernel
//! direct map of tracked RAM above the first GiB (docs/x86-whole-ram-20261015).
//!
//! The boot reads the Multiboot2 map once to plan (`absd_kernel::ram_plan`).
//! When usable RAM reaches past the built-in 256 MiB table, one block below
//! 1 GiB (identity-mapped by boot.S) holds the direct-map page directories
//! and a tag table sized to the highest tracked frame; it is reserved like
//! the kernel image. Tracked 2 MiB pages from 1 GiB up are then identity
//! mapped (supervisor, write-back, no-execute) in the shared boot PDPT, so
//! physical == virtual holds for every tracked frame, in every CR3: user
//! roots and AP boot CR3 point at the same PDPT. The device window
//! (mmio.rs, PDPT 256..259) lies above the 64 GiB bound.

use absd_kernel::memory::{
    Frame, FrameAllocator, FrameOwner, FrameState, PAGE_SIZE, PHYSICAL_TRACKING_BOUND,
};
use absd_kernel::ram_plan::{self, DirectPage, ONE_GIB, Plan, TWO_MIB};
use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::serial::{decimal, hex, write};
use crate::vm::ADDRESS_MASK;

const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const HUGE: u64 = 1 << 7;
const NO_EXECUTE: u64 = 1 << 63;
/// main.rs's boot page-map round trips briefly remap these 2 MiB pages, so
/// the block must not sit there, and no frame there may be handed out while
/// they run (`hold_page_test_window`).
const PAGE_TEST_WINDOW: (u64, u64) = (0x2000_0000, 0x2040_0000);
const WINDOW_FRAMES: usize = ((PAGE_TEST_WINDOW.1 - PAGE_TEST_WINDOW.0) / PAGE_SIZE) as usize;
/// Placement exclusions: low memory, kernel image, boot block, page-test
/// window, and up to 60 modules. More modules refuse the boot table
/// (disclosed); they are still all reserved.
const MAX_EXCLUSIONS: usize = 64;
const FOUR_GIB: u64 = 4 << 30;
/// 64 MiB of device memory inside usable rows: four 4K framebuffers.
const MAX_DEVICE_PAGES: usize = 32;
const PATTERN: u64 = 0x5748_4f4c_4552_414d;
/// One bit per 2 MiB page below the bound: set when `map_direct` installed
/// a write-back identity mapping for it.
const DIRECT_WORDS: usize = (PHYSICAL_TRACKING_BOUND / TWO_MIB / 64) as usize;
static DIRECT: [AtomicU64; DIRECT_WORDS] = [const { AtomicU64::new(0) }; DIRECT_WORDS];

#[derive(Clone, Copy, Default)]
pub struct Installed {
    pub plan: Plan,
    /// Physical `[start, end)` of directories + tag table, or `(0, 0)`.
    pub block: (u64, u64),
    /// Why the plan's table could not be installed; the built-in 256 MiB
    /// table stays and the rest is clipped.
    pub refused: Option<&'static str>,
    /// 2 MiB direct-map pages installed above the first GiB.
    pub mapped_pages: usize,
    /// Tracked 2 MiB pages a device mapping covers: reserved, not mapped.
    /// More than fit here fail the boot closed.
    pub device_excluded: [Option<u64>; MAX_DEVICE_PAGES],
}

/// Walks the usable (type 1) rows of Multiboot2 tag 6. Malformed input
/// yields nothing more; `load_memory_map` refuses it on its own walk.
fn usable_rows(info: *const u8, total_size: usize, f: &mut dyn FnMut(u64, u64)) {
    tags(info, total_size, &mut |kind, tag, size| {
        if kind != 6 || size < 16 {
            return;
        }
        let stride = unsafe { core::ptr::read_unaligned(tag.add(8).cast::<u32>()) } as usize;
        if stride < 24 || !(size - 16).is_multiple_of(stride) {
            return;
        }
        let mut row = 16;
        while row < size {
            let at = unsafe { tag.add(row) };
            let base = unsafe { core::ptr::read_unaligned(at.cast::<u64>()) };
            let length = unsafe { core::ptr::read_unaligned(at.add(8).cast::<u64>()) };
            let kind = unsafe { core::ptr::read_unaligned(at.add(16).cast::<u32>()) };
            if kind == 1
                && let Some(end) = base.checked_add(length)
            {
                f(base, end);
            }
            row += stride;
        }
    });
}

/// Walks well-formed tags up to the end tag. Returns whether the walk
/// reached the end tag with every tag (and every memory-map tag's stride)
/// well-formed: the same acceptance as `load_memory_map`.
fn tags(info: *const u8, total_size: usize, f: &mut dyn FnMut(u32, *const u8, usize)) -> bool {
    let mut offset = 8usize;
    while offset.checked_add(8).is_some_and(|end| end <= total_size) {
        let tag = unsafe { info.add(offset) };
        let kind = unsafe { core::ptr::read_unaligned(tag.cast::<u32>()) };
        let size = unsafe { core::ptr::read_unaligned(tag.add(4).cast::<u32>()) } as usize;
        if kind == 0 {
            return true;
        }
        if size < 8 || offset.checked_add(size).is_none_or(|end| end > total_size) {
            return false;
        }
        if kind == 6 && size >= 16 {
            let stride = unsafe { core::ptr::read_unaligned(tag.add(8).cast::<u32>()) } as usize;
            if stride < 24 || !(size - 16).is_multiple_of(stride) {
                return false;
            }
        }
        f(kind, tag, size);
        offset += (size + 7) & !7;
    }
    false
}

/// Every boot module (Multiboot2 tag 3) as `[start, end)`.
fn modules(info: *const u8, total_size: usize, f: &mut dyn FnMut(u64, u64)) {
    tags(info, total_size, &mut |kind, tag, size| {
        if kind == 3 && size >= 16 {
            let start = unsafe { core::ptr::read_unaligned(tag.add(8).cast::<u32>()) } as u64;
            let end = unsafe { core::ptr::read_unaligned(tag.add(12).cast::<u32>()) } as u64;
            f(start, end);
        }
    });
}

/// Low memory, the kernel image and the Multiboot2 block; main.rs reserves
/// these (`reserve_boot_owned_memory`).
fn fixed_boot_owned(info: *const u8, total_size: usize) -> [(u64, u64); 3] {
    unsafe extern "C" {
        static __kernel_start: u8;
        static __kernel_end: u8;
    }
    [
        (0, 0x10_0000),
        (
            core::ptr::addr_of!(__kernel_start) as u64,
            core::ptr::addr_of!(__kernel_end) as u64,
        ),
        (info as u64, (info as u64).saturating_add(total_size as u64)),
    ]
}

/// Plans from the map and, when the built-in table is too small, places
/// and installs the boot table. Runs before any frame is usable, and writes
/// nothing unless the map is well-formed.
pub fn install_table(info: *const u8, total_size: usize, frames: &mut FrameAllocator) -> Installed {
    let mut installed = Installed::default();
    if !tags(info, total_size, &mut |_, _, _| {}) {
        return installed;
    }
    let rows = |f: &mut dyn FnMut(u64, u64)| usable_rows(info, total_size, f);
    installed.plan = Plan::from_rows(&rows);
    let plan = installed.plan;
    if !plan.needs_table() {
        return installed;
    }
    let mut exclusions = [(0, 0); MAX_EXCLUSIONS];
    exclusions[..3].copy_from_slice(&fixed_boot_owned(info, total_size));
    exclusions[3] = PAGE_TEST_WINDOW;
    let mut count = 4;
    let mut overflow = false;
    modules(info, total_size, &mut |start, end| {
        if count == MAX_EXCLUSIONS {
            overflow = true;
        } else {
            exclusions[count] = (start, end);
            count += 1;
        }
    });
    if overflow {
        installed.refused = Some("modules");
        return installed;
    }
    let Some(at) = ram_plan::place(plan.block_bytes(), &rows, &exclusions[..count], ONE_GIB) else {
        installed.refused = Some("placement");
        return installed;
    };
    let table_at = at + plan.directories() as u64 * PAGE_SIZE;
    // The block lies in usable RAM below 1 GiB (identity-mapped), outside
    // every boot-owned range, and nothing else refers to it yet.
    let table = unsafe { core::slice::from_raw_parts_mut(table_at as *mut u32, plan.tag_frames()) };
    if !frames.extend_tags(table) {
        installed.refused = Some("install");
        return installed;
    }
    installed.block = (at, at + plan.block_bytes());
    installed
}

/// Marks the trackable parts of one usable row free (the `ram_plan` rule).
pub fn add_usable(frames: &mut FrameAllocator, start: u64, end: u64) {
    for (part_start, part_end) in ram_plan::tracked_parts(start, end) {
        frames.add_usable(part_start, part_end);
    }
}

fn boot_pdpt() -> *mut u64 {
    unsafe extern "C" {
        static boot_pml4: u8;
    }
    let pml4 = core::ptr::addr_of!(boot_pml4) as *const u64;
    (unsafe { core::ptr::read_volatile(pml4) } & ADDRESS_MASK) as *mut u64
}

/// Whether any 2 MiB page overlapping `[start, end)` is direct-mapped
/// write-back; `mmio::map` refuses such a range rather than alias it.
pub fn overlaps_direct_map(start: u64, end: u64) -> bool {
    let first = start / TWO_MIB;
    let last = end.min(PHYSICAL_TRACKING_BOUND).div_ceil(TWO_MIB);
    (first..last)
        .any(|page| DIRECT[(page / 64) as usize].load(Ordering::Acquire) & (1 << (page % 64)) != 0)
}

/// Identity-maps every tracked 2 MiB page above the first GiB with the
/// block's directories. Runs right after `load_memory_map`, before any other
/// reservation or allocation. A page that an earlier device mapping covers
/// (firmware reporting, say, the framebuffer inside a usable row) is not
/// aliased write-back: it is reserved and disclosed instead. Fails closed on
/// anything else.
pub fn map_direct(frames: &mut FrameAllocator, installed: &mut Installed) -> bool {
    let directories_end = installed.block.0 + installed.plan.directories() as u64 * PAGE_SIZE;
    let mut next = installed.block.0;
    let mut created = 0u64;
    let mut ok = true;
    let pdpt = boot_pdpt();
    let excluded = &mut installed.device_excluded;
    let mapped = &mut installed.mapped_pages;
    ram_plan::direct_pages(
        frames.tracked_limit(),
        &|page| frames.state(Frame(page)) == FrameState::Free,
        &crate::mmio::overlaps,
        &mut |page, what| {
            if !ok {
                return;
            }
            if what == DirectPage::DeviceExcluded {
                match excluded.iter_mut().find(|slot| slot.is_none()) {
                    Some(slot) => *slot = Some(page),
                    None => ok = false,
                }
                return;
            }
            let gib = page / ONE_GIB;
            if gib >= PHYSICAL_TRACKING_BOUND / ONE_GIB {
                ok = false;
                return;
            }
            let slot = unsafe { pdpt.add(gib as usize) };
            let mut entry = unsafe { core::ptr::read_volatile(slot) };
            if entry & PRESENT == 0 {
                if next >= directories_end {
                    ok = false;
                    return;
                }
                for index in 0..512 {
                    unsafe { core::ptr::write_volatile((next as *mut u64).add(index), 0) };
                }
                entry = next | PRESENT | WRITABLE;
                unsafe { core::ptr::write_volatile(slot, entry) };
                created |= 1 << gib;
                next += PAGE_SIZE;
            } else if created & (1 << gib) == 0 {
                // Someone else owns this GiB of the kernel half: refuse.
                ok = false;
                return;
            }
            let directory = (entry & ADDRESS_MASK) as *mut u64;
            let index = ((page / TWO_MIB) % 512) as usize;
            unsafe {
                core::ptr::write_volatile(
                    directory.add(index),
                    page | PRESENT | WRITABLE | HUGE | NO_EXECUTE,
                )
            };
            let bit = page / TWO_MIB;
            DIRECT[(bit / 64) as usize].fetch_or(1 << (bit % 64), Ordering::AcqRel);
            *mapped += 1;
        },
    );
    // Entries only went from not-present to present; reload CR3 anyway so
    // no paging-structure cache can hold a stale PDPT entry.
    unsafe {
        asm!("mov {0}, cr3", "mov cr3, {0}", out(reg) _, options(nostack, preserves_flags));
    }
    // Device-covered pages leave the free pool before anything allocates.
    ok && installed
        .device_excluded
        .iter()
        .flatten()
        .all(|&page| frames.reserve(page, page + TWO_MIB))
}

/// Reserves every boot module and the table block. Low memory, the kernel
/// image and the boot block are reserved by main.rs. Fails closed.
pub fn reserve(
    info: *const u8,
    total_size: usize,
    frames: &mut FrameAllocator,
    installed: &Installed,
) -> bool {
    let mut clean = true;
    modules(info, total_size, &mut |start, end| {
        clean &= frames.reserve(start, end);
    });
    clean && frames.reserve(installed.block.0, installed.block.1)
}

/// `FRAMES TRACKED`: what the allocator admits, the tracked span, and how
/// many usable bytes it leaves out.
pub fn disclose(frames: &FrameAllocator, installed: &Installed, admitted: usize) {
    write("FRAMES TRACKED usable=");
    decimal(admitted as u64);
    write(" limit=");
    decimal(frames.tracked_limit());
    write(" clipped=");
    decimal(
        installed
            .plan
            .usable_bytes
            .saturating_sub(admitted as u64 * PAGE_SIZE),
    );
    write(" bound=");
    decimal(PHYSICAL_TRACKING_BOUND);
    write(if installed.refused.is_some() {
        " table=builtin-refused"
    } else if installed.block.1 != 0 {
        " table=boot"
    } else {
        " table=builtin"
    });
    write(" direct_map_pages=");
    decimal(installed.mapped_pages as u64);
    write("\n");
    if let Some(reason) = installed.refused {
        write("FRAMES TABLE REFUSED reason=");
        write(reason);
        write("\n");
    }
    for &page in installed.device_excluded.iter().flatten() {
        write("FRAMES DEVICE EXCLUDED start=");
        hex(page);
        write(" end=");
        hex(page + TWO_MIB);
        write(" (device mapping inside a usable row; reserved, not direct-mapped)\n");
    }
}

/// The map and every reserved range, for the host-side oracle.
pub fn disclose_inputs(info: *const u8, total_size: usize, installed: &Installed) {
    usable_rows(info, total_size, &mut |start, end| {
        write("WHOLE RAM MAP usable start=");
        hex(start);
        write(" end=");
        hex(end);
        write("\n");
    });
    let reserved = |kind: &str, start: u64, end: u64| {
        write("WHOLE RAM RESERVED start=");
        hex(start);
        write(" end=");
        hex(end);
        write(" kind=");
        write(kind);
        write("\n");
    };
    let [low, image, boot] = fixed_boot_owned(info, total_size);
    reserved("low", low.0, low.1);
    reserved("kernel", image.0, image.1);
    reserved("multiboot", boot.0, boot.1);
    modules(info, total_size, &mut |start, end| {
        reserved("module", start, end)
    });
    if installed.block.1 != 0 {
        reserved("table", installed.block.0, installed.block.1);
    }
    for &page in installed.device_excluded.iter().flatten() {
        reserved("device", page, page + TWO_MIB);
    }
}

/// Frames of the page-test window that were free, now held unavailable.
pub struct HeldWindow([u64; WINDOW_FRAMES / 64]);

/// Takes every free frame of the page-test window out of the free pool
/// while main.rs's page-map round trips remap that window.
pub fn hold_page_test_window(frames: &mut FrameAllocator) -> HeldWindow {
    let mut held = HeldWindow([0; WINDOW_FRAMES / 64]);
    for index in 0..WINDOW_FRAMES {
        let frame = PAGE_TEST_WINDOW.0 + index as u64 * PAGE_SIZE;
        if frames.state(Frame(frame)) == FrameState::Free {
            assert!(frames.reserve(frame, frame + PAGE_SIZE));
            held.0[index / 64] |= 1 << (index % 64);
        }
    }
    held
}

/// Returns the held frames to the free pool, one run at a time.
pub fn release_page_test_window(frames: &mut FrameAllocator, held: HeldWindow) {
    let is_held = |index: usize| held.0[index / 64] & (1 << (index % 64)) != 0;
    let mut index = 0;
    while index < WINDOW_FRAMES {
        if !is_held(index) {
            index += 1;
            continue;
        }
        let run = index;
        while index < WINDOW_FRAMES && is_held(index) {
            index += 1;
        }
        let start = PAGE_TEST_WINDOW.0 + run as u64 * PAGE_SIZE;
        let end = PAGE_TEST_WINDOW.0 + index as u64 * PAGE_SIZE;
        assert_eq!(frames.unreserve(start, end), index - run);
    }
}

fn touched(address: u64, marks: &[u64]) -> bool {
    address.is_multiple_of(TWO_MIB) || marks.contains(&address)
}

/// `whole-ram-test`: allocate every tracked free frame, write and read one
/// per 2 MiB page (and the first above 256 MiB and 4 GiB, and the last)
/// through the direct map, free them all, and require the starting counts.
pub fn self_test(frames: &mut FrameAllocator) -> bool {
    let start_free = frames.free_frames();
    if frames.allocated_frames() != 0 {
        return false;
    }
    let mut count = 0usize;
    let (mut above_256m, mut above_4g, mut highest) = (0u64, 0u64, 0u64);
    while let Some(frame) = frames.allocate(FrameOwner::Kernel) {
        let address = frame.start_address();
        count += 1;
        if above_256m == 0 && address >= 256 << 20 {
            above_256m = address;
        }
        if above_4g == 0 && address >= FOUR_GIB {
            above_4g = address;
        }
        highest = highest.max(address);
    }
    let marks = [above_256m, above_4g, highest];
    let mut written = 0u64;
    let words = (PAGE_SIZE / 8) as usize;
    let walk = |verify: bool, frames: &mut FrameAllocator| -> Option<u64> {
        let mut seen = 0u64;
        for index in 0..frames.tracked_frames() {
            let address = index as u64 * PAGE_SIZE;
            if frames.state(Frame(address)) != FrameState::Allocated(FrameOwner::Kernel) {
                continue;
            }
            if touched(address, &marks) {
                let page = address as *mut u64;
                let value = address ^ PATTERN;
                unsafe {
                    if verify {
                        if core::ptr::read_volatile(page) != value
                            || core::ptr::read_volatile(page.add(words - 1)) != !value
                        {
                            return None;
                        }
                    } else {
                        core::ptr::write_volatile(page, value);
                        core::ptr::write_volatile(page.add(words - 1), !value);
                    }
                }
                seen += 1;
            }
            if verify && frames.free(Frame(address), FrameOwner::Kernel).is_err() {
                return None;
            }
        }
        Some(seen)
    };
    // Write every mark first, then verify while freeing, so an alias between
    // two pages would show as a mismatch.
    if let Some(seen) = walk(false, frames) {
        written = seen;
    }
    let verified = walk(true, frames);
    write("WHOLE RAM ALLOC frames=");
    decimal(count as u64);
    write(" start_free=");
    decimal(start_free as u64);
    write(" above_256m=");
    hex(above_256m);
    write(" above_4g=");
    hex(above_4g);
    write(" highest=");
    hex(highest);
    write(" written=");
    decimal(written);
    write(" verified=");
    decimal(verified.unwrap_or(0));
    write("\n");
    let ok = verified == Some(written)
        && written != 0
        && count == start_free
        && above_256m != 0
        && above_4g != 0
        && frames.free_frames() == start_free
        && frames.allocated_frames() == 0;
    // The exhaustion above is the test's own; later peaks are the suite's.
    frames.reset_peak();
    write("WHOLE RAM FREE free=");
    decimal(frames.free_frames() as u64);
    write(" allocated=");
    decimal(frames.allocated_frames() as u64);
    write("\n");
    ok
}

/// Holds every free frame below 4 GiB as `Kernel` for the rest of the boot,
/// so the userspace suite that follows runs on frames above 4 GiB: page
/// tables, kernel stacks, user pages and user copies. Returns the first
/// frame a later allocation receives.
pub fn pin_below_four_gib(frames: &mut FrameAllocator) -> Option<(usize, u64)> {
    let mut pinned = 0;
    loop {
        let frame = frames.allocate(FrameOwner::Kernel)?;
        if frame.start_address() >= FOUR_GIB {
            frames.free(frame, FrameOwner::Kernel).ok()?;
            return Some((pinned, frame.start_address()));
        }
        pinned += 1;
    }
}
