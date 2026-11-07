//! User address-space construction, mapping, and teardown.
//!
//! All page-table memory is reached through the kernel identity map: the
//! boot map of the first GiB plus the direct map of tracked RAM above it
//! (`whole_ram`), so every frame used here must come from the tracked
//! allocator, whose frames are all identity-mapped.
//!
//! Ownership: PML4 entry 0 of every user root points at the shared kernel
//! PDPT and is never owned by a process. PML4 entry 1, the PDPT, every page
//! directory, every page table, and every mapped user frame are owned by the
//! process whose PID tagged them, and `destroy` returns exactly those frames.
//! The region spans `USER_DIRECTORIES` directories (PDPT entries from 0);
//! directory 0 exists from `create`, others appear on first use. Leaf tables
//! are reached through those owned directory entries, never a side table.

use absd_kernel::frame_geometry::MAX_LEAF_TABLES;
use absd_kernel::layout::{USER_DIRECTORIES, USER_REGION_BASE, USER_REGION_END};
use absd_kernel::memory::{
    ENTRY_NO_EXECUTE, ENTRY_PRESENT, ENTRY_USER, ENTRY_WRITABLE, Frame, FrameAllocator, FrameError,
    FrameOwner, PAGE_SIZE,
};
use absd_kernel::process::AddressSpace;

pub const PAGE_TABLE_ENTRIES: usize = 512;
pub const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const USER_PML4_INDEX: usize = ((USER_REGION_BASE >> 39) & 0x1ff) as usize;

/// The global frame allocator is serialized by the big kernel lock once the
/// kernel-only AP is admitted. The AP may touch it only in a bounded fixture
/// while holding that lock; no driver or ordinary AP scheduler path does.
static mut FRAMES: FrameAllocator = FrameAllocator::new();

/// # Safety
///
/// The returned reference must not outlive the current kernel entry, and the
/// caller must not hold two live references at once.
pub unsafe fn frames() -> &'static mut FrameAllocator {
    crate::kernel_lock::assert_current_owner();
    unsafe { &mut *core::ptr::addr_of_mut!(FRAMES) }
}

/// Fills one identity-mapped frame with zero, eight bytes at a time.
pub unsafe fn zero_frame(frame: Frame) {
    unsafe { fill_frame(frame, 0) }
}

/// Fills one identity-mapped frame with a repeated byte pattern.
pub unsafe fn fill_frame(frame: Frame, byte: u8) {
    let words = frame.start_address() as *mut u64;
    let word = u64::from_ne_bytes([byte; 8]);
    for index in 0..(PAGE_SIZE as usize / 8) {
        unsafe {
            core::ptr::write_volatile(words.add(index), word);
        }
    }
}

/// Page-table entry reads, counted only for the host fixture's search
/// bound (feature `vm-read-count`, never in a kernel build).
#[cfg(feature = "vm-read-count")]
pub static ENTRY_READS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

unsafe fn read_entry(table: u64, index: usize) -> u64 {
    #[cfg(feature = "vm-read-count")]
    ENTRY_READS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    unsafe { core::ptr::read_volatile((table as *const u64).add(index)) }
}

unsafe fn write_entry(table: u64, index: usize, value: u64) {
    unsafe {
        core::ptr::write_volatile((table as *mut u64).add(index), value);
    }
}

/// Builds an empty user address space for `pid`: a fresh PML4 whose entry 0
/// shares `kernel_pdpt` (supervisor only) and whose entry 1 leads to a
/// process-owned PDPT and first page directory.
///
/// # Safety
///
/// `kernel_pdpt` must be the physical address of the boot PDPT.
pub unsafe fn create(
    frames: &mut FrameAllocator,
    pid: u32,
    kernel_pdpt: u64,
) -> Option<AddressSpace> {
    let mut space = AddressSpace::EMPTY;
    let owner = FrameOwner::PageTable(pid);
    let root = frames.allocate(owner)?;
    space.root = root.start_address();
    let Some(pdpt) = frames.allocate(owner) else {
        unsafe { destroy(frames, &mut space, pid).ok()? };
        return None;
    };
    space.pdpt = pdpt.start_address();
    unsafe {
        zero_frame(root);
        zero_frame(pdpt);
        write_entry(space.root, 0, kernel_pdpt | ENTRY_PRESENT | ENTRY_WRITABLE);
        write_entry(
            space.root,
            USER_PML4_INDEX,
            space.pdpt | ENTRY_PRESENT | ENTRY_WRITABLE | ENTRY_USER,
        );
    }
    if unsafe { directory(frames, &mut space, pid, 0) }.is_none() {
        unsafe { destroy(frames, &mut space, pid).ok()? };
        return None;
    }
    Some(space)
}

/// The owned page directory for GiB `index` of the region, allocated and
/// linked into the PDPT on first use. None when no frame is available.
unsafe fn directory(
    frames: &mut FrameAllocator,
    space: &mut AddressSpace,
    pid: u32,
    index: usize,
) -> Option<u64> {
    if space.directories[index] == 0 {
        let frame = frames.allocate(FrameOwner::PageTable(pid))?;
        unsafe {
            zero_frame(frame);
            write_entry(
                space.pdpt,
                index,
                frame.start_address() | ENTRY_PRESENT | ENTRY_WRITABLE | ENTRY_USER,
            );
        }
        space.directories[index] = frame.start_address();
    }
    Some(space.directories[index])
}

/// Present entries of a leaf table, kept in bits 52-61 of the directory
/// entry that references it; the processor ignores those bits in an entry
/// that references a table, and every reader masks with `ADDRESS_MASK`.
/// User directories never map 2 MiB pages: in a PS=1 entry bits 59-62 are
/// protection-key bits. `leaf_link` and `adjust_leaf_count` refuse such an
/// entry outright rather than read or write a count in it.
const LEAF_COUNT_SHIFT: u32 = 52;
const LEAF_COUNT_MASK: u64 = 0x3ff << LEAF_COUNT_SHIFT;
/// PS: the entry maps a 2 MiB page instead of referencing a table.
const ENTRY_PAGE_SIZE: u64 = 1 << 7;
const ENTRY_EXECUTE_DISABLE: u64 = 1 << 63;

// The count must sit only in bits the processor ignores in a directory entry
// that references a page table (Intel SDM Vol. 3A 4.5, AMD APM Vol. 2 5.3):
// bits 52-62. Not the address (12-51), the flags (0-11) or XD (63).
const _: () = {
    assert!(LEAF_COUNT_MASK & ADDRESS_MASK == 0);
    assert!(LEAF_COUNT_MASK & 0xfff == 0);
    assert!(LEAF_COUNT_MASK & ENTRY_EXECUTE_DISABLE == 0);
    assert!(LEAF_COUNT_MASK & !(((1u64 << 63) - 1) & !((1u64 << 52) - 1)) == 0);
    assert!(ENTRY_NO_EXECUTE == ENTRY_EXECUTE_DISABLE);
    assert!(PAGE_TABLE_ENTRIES as u64 <= LEAF_COUNT_MASK >> LEAF_COUNT_SHIFT);
};

fn leaf_count(link: u64) -> u64 {
    (link & LEAF_COUNT_MASK) >> LEAF_COUNT_SHIFT
}

/// Adds `delta` to the present count of the leaf table for `leaf`, which
/// must exist.
unsafe fn adjust_leaf_count(space: &AddressSpace, leaf: usize, delta: i64) {
    let directory = space.directories[leaf / PAGE_TABLE_ENTRIES];
    let index = leaf % PAGE_TABLE_ENTRIES;
    let link = unsafe { read_entry(directory, index) };
    assert!(
        link & ENTRY_PAGE_SIZE == 0,
        "user directory entry maps a 2 MiB page"
    );
    let count = leaf_count(link).checked_add_signed(delta).unwrap();
    assert!(count <= PAGE_TABLE_ENTRIES as u64);
    unsafe {
        write_entry(
            directory,
            index,
            (link & !LEAF_COUNT_MASK) | count << LEAF_COUNT_SHIFT,
        )
    };
}

/// The directory entry referencing the leaf table covering `address`, if
/// that table exists.
unsafe fn leaf_link(space: &AddressSpace, address: u64) -> Option<u64> {
    let leaf = leaf_of(address)?;
    let directory = space.directories[leaf / PAGE_TABLE_ENTRIES];
    if directory == 0 {
        return None;
    }
    let entry = unsafe { read_entry(directory, leaf % PAGE_TABLE_ENTRIES) };
    assert!(
        entry & ENTRY_PAGE_SIZE == 0,
        "user directory entry maps a 2 MiB page"
    );
    (entry & ENTRY_PRESENT != 0).then_some(entry)
}

/// Leaf number (2 MiB unit) of a user-region address.
fn leaf_of(address: u64) -> Option<usize> {
    (USER_REGION_BASE..USER_REGION_END)
        .contains(&address)
        .then(|| ((address - USER_REGION_BASE) >> 21) as usize)
}

/// The owned leaf page table covering `address`, if one exists.
pub unsafe fn leaf_table(space: &AddressSpace, address: u64) -> Option<u64> {
    unsafe { leaf_link(space, address) }.map(|link| link & ADDRESS_MASK)
}

/// Present entries in the leaf table covering `address` (zero without one).
/// Read only by the host fixture's count invariant.
#[allow(dead_code)]
pub unsafe fn leaf_mapped(space: &AddressSpace, address: u64) -> u64 {
    unsafe { leaf_link(space, address) }.map_or(0, leaf_count)
}

/// Why a page could not be mapped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapError {
    /// Unaligned or outside the user region.
    BadAddress,
    /// The page already has a mapping.
    AlreadyMapped,
    /// No page-table slot or no frame was available.
    NoMemory,
}

/// Maps one zeroed, process-owned frame at `address` and returns its physical
/// address. Refuses addresses outside the user region, unaligned addresses,
/// and already-mapped pages. At most `MAX_LEAF_TABLES` leaf tables are owned;
/// a directory or leaf created before a later frame shortage is retained and
/// charged until `destroy`.
///
/// # Safety
///
/// `space` must have been produced by `create` and have one exclusive CPU
/// owner. A bounded AP fixture may map its own active root under the kernel
/// lock; no remote CPU may use that root. Tracked frames are identity-mapped
/// (boot map and whole-RAM direct map), and reclamation waits for actual RSP/CR3/TSS departure ACK.
pub unsafe fn map_user_page(
    frames: &mut FrameAllocator,
    space: &mut AddressSpace,
    pid: u32,
    address: u64,
    writable: bool,
    executable: bool,
) -> Result<u64, MapError> {
    if !address.is_multiple_of(PAGE_SIZE) || !(USER_REGION_BASE..USER_REGION_END).contains(&address)
    {
        return Err(MapError::BadAddress);
    }
    let leaf = ((address - USER_REGION_BASE) >> 21) as usize;
    let table = match unsafe { leaf_table(space, address) } {
        Some(table) => table,
        None => {
            if space.tables >= MAX_LEAF_TABLES {
                return Err(MapError::NoMemory);
            }
            let directory = unsafe { directory(frames, space, pid, leaf / PAGE_TABLE_ENTRIES) }
                .ok_or(MapError::NoMemory)?;
            let table_frame = frames
                .allocate(FrameOwner::PageTable(pid))
                .ok_or(MapError::NoMemory)?;
            unsafe {
                zero_frame(table_frame);
                write_entry(
                    directory,
                    leaf % PAGE_TABLE_ENTRIES,
                    table_frame.start_address() | ENTRY_PRESENT | ENTRY_WRITABLE | ENTRY_USER,
                );
            }
            space.tables += 1;
            table_frame.start_address()
        }
    };
    let page_index = ((address >> 12) & 0x1ff) as usize;
    if unsafe { read_entry(table, page_index) } & ENTRY_PRESENT != 0 {
        return Err(MapError::AlreadyMapped);
    }
    let backing = frames
        .allocate(FrameOwner::UserPage(pid))
        .ok_or(MapError::NoMemory)?;
    let mut flags = ENTRY_PRESENT | ENTRY_USER;
    if writable {
        flags |= ENTRY_WRITABLE;
    }
    if !executable {
        flags |= ENTRY_NO_EXECUTE;
    }
    unsafe {
        zero_frame(backing);
        write_entry(table, page_index, backing.start_address() | flags);
        adjust_leaf_count(space, leaf, 1);
    }
    Ok(backing.start_address())
}

/// Whether `address` has a present user mapping in the owned tables.
pub unsafe fn is_mapped(space: &AddressSpace, address: u64) -> bool {
    unsafe { translate(space, address) }.is_some()
}

/// Lowest page-aligned address in `[base, end)` starting a run of `count`
/// unmapped pages, if any; `base` and `end` must be page-aligned and inside
/// the user region and `count` at least one, or there is none. Each leaf is looked up once. A leaf with no table
/// is a whole free run. A leaf with fewer free pages than the run still
/// needs can complete no run, so only its trailing free pages (read
/// backwards) carry into the next leaf. Other leaves are read in order. The
/// result is the same lowest run as a page-by-page search.
pub unsafe fn find_unmapped_run(
    space: &AddressSpace,
    base: u64,
    end: u64,
    count: u64,
) -> Option<u64> {
    // Enforced in every build: a caller passing unaligned bounds or a zero
    // count gets no run (map then refuses) instead of an unspecified one.
    if !base.is_multiple_of(PAGE_SIZE)
        || !end.is_multiple_of(PAGE_SIZE)
        || count == 0
        || base < USER_REGION_BASE
        || end > USER_REGION_END
    {
        return None;
    }
    let mut run_start = base;
    let mut run = 0;
    let mut page = base;
    while page < end {
        let stop = (((page >> 21) + 1) << 21).min(end);
        let pages = (stop - page) / PAGE_SIZE;
        let Some(link) = (unsafe { leaf_link(space, page) }) else {
            if run == 0 {
                run_start = page;
            }
            if run + pages >= count {
                return Some(run_start);
            }
            run += pages;
            page = stop;
            continue;
        };
        let table = link & ADDRESS_MASK;
        let first = ((page >> 12) & 0x1ff) as usize;
        let free = PAGE_TABLE_ENTRIES as u64 - leaf_count(link);
        if free < count - run {
            // Too few free pages to finish any run here (so not all 512 are
            // free): carry only the free pages at the end of the range.
            let mut trailing = 0;
            while trailing < pages
                && unsafe { read_entry(table, first + (pages - 1 - trailing) as usize) }
                    & ENTRY_PRESENT
                    == 0
            {
                trailing += 1;
            }
            if trailing < pages {
                run = trailing;
                run_start = stop - trailing * PAGE_SIZE;
            } else {
                if run == 0 {
                    run_start = page;
                }
                run += pages;
            }
            page = stop;
            continue;
        }
        for index in first..first + pages as usize {
            if unsafe { read_entry(table, index) } & ENTRY_PRESENT != 0 {
                run = 0;
            } else {
                if run == 0 {
                    run_start = page;
                }
                run += 1;
                if run == count {
                    return Some(run_start);
                }
            }
            page += PAGE_SIZE;
        }
        // An unaligned base or end leaves part of a page, which holds no run.
        page = stop;
    }
    None
}

/// Removes one user mapping and returns its frame. The page table itself is
/// kept until the address space is destroyed. Refuses unmapped pages.
///
/// # Safety
///
/// `space` must have been produced by `create`. If it is the active CR3 the
/// caller is responsible for the TLB (`invalidate_page` or a CR3 reload).
pub unsafe fn unmap_user_page(
    frames: &mut FrameAllocator,
    space: &mut AddressSpace,
    pid: u32,
    address: u64,
) -> Result<(), FrameError> {
    let Some(table) = (unsafe { leaf_table(space, address) }) else {
        return Err(FrameError::NotAllocated);
    };
    let page_index = ((address >> 12) & 0x1ff) as usize;
    let entry = unsafe { read_entry(table, page_index) };
    if entry & (ENTRY_PRESENT | ENTRY_USER) != (ENTRY_PRESENT | ENTRY_USER) {
        return Err(FrameError::NotAllocated);
    }
    frames.free(Frame(entry & ADDRESS_MASK), FrameOwner::UserPage(pid))?;
    unsafe {
        write_entry(table, page_index, 0);
        adjust_leaf_count(space, ((address - USER_REGION_BASE) >> 21) as usize, -1);
    }
    Ok(())
}

/// Physical address backing a user virtual address, via the owned tables.
pub unsafe fn translate(space: &AddressSpace, address: u64) -> Option<u64> {
    let table = unsafe { leaf_table(space, address) }?;
    let entry = unsafe { read_entry(table, ((address >> 12) & 0x1ff) as usize) };
    if entry & (ENTRY_PRESENT | ENTRY_USER) != (ENTRY_PRESENT | ENTRY_USER) {
        return None;
    }
    Some((entry & ADDRESS_MASK) + (address & (PAGE_SIZE - 1)))
}

/// Returns every frame owned by this address space and clears the record.
/// Works on partially built spaces, so failed loads reclaim cleanly.
///
/// # Safety
///
/// `space.root` must not be the active CR3. The caller must switch to the
/// boot page tables first.
pub unsafe fn destroy(
    frames: &mut FrameAllocator,
    space: &mut AddressSpace,
    pid: u32,
) -> Result<usize, FrameError> {
    let mut released = 0;
    for slot in 0..USER_DIRECTORIES {
        let directory = space.directories[slot];
        if directory == 0 {
            continue;
        }
        for leaf in 0..PAGE_TABLE_ENTRIES {
            let link = unsafe { read_entry(directory, leaf) };
            if link & ENTRY_PRESENT == 0 {
                continue;
            }
            let table = link & ADDRESS_MASK;
            for index in 0..PAGE_TABLE_ENTRIES {
                let entry = unsafe { read_entry(table, index) };
                if entry & ENTRY_PRESENT != 0 {
                    frames.free(Frame(entry & ADDRESS_MASK), FrameOwner::UserPage(pid))?;
                    released += 1;
                }
            }
            frames.free(Frame(table), FrameOwner::PageTable(pid))?;
            released += 1;
            unsafe { write_entry(directory, leaf, 0) };
            space.tables -= 1;
        }
        frames.free(Frame(directory), FrameOwner::PageTable(pid))?;
        released += 1;
        space.directories[slot] = 0;
    }
    debug_assert_eq!(space.tables, 0);
    for level in [&mut space.pdpt, &mut space.root] {
        if *level != 0 {
            frames.free(Frame(*level), FrameOwner::PageTable(pid))?;
            released += 1;
            *level = 0;
        }
    }
    space.heap_hint = 0;
    Ok(released)
}
