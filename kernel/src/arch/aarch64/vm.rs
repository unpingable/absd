//! ARM 4 KiB user page tables; shared allocator ownership and bounded mappings.
use absd_kernel::layout::{USER_REGION_BASE, USER_REGION_END};
use absd_kernel::memory::{Frame, FrameAllocator, FrameError, FrameOwner, PAGE_SIZE};
const ENTRY_PRESENT: u64 = 1;
const ENTRY_USER: u64 = 1 << 6;
const ENTRY_NO_EXECUTE: u64 = 1 << 54;
use absd_kernel::process::{AddressSpace, PageTableSlot};

pub const PAGE_TABLE_ENTRIES: usize = 512;
pub const ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;
const USER_PML4_INDEX: usize = ((USER_REGION_BASE >> 39) & 0x1ff) as usize;

/// The global frame allocator is serialized by the big kernel lock once the
/// kernel-only AP is admitted. The AP may touch it only in a bounded fixture
/// while holding that lock; no driver or ordinary AP scheduler path does.
static mut FRAMES: FrameAllocator = FrameAllocator::with_base(0x40000000);

/// # Safety
///
/// The returned reference must not outlive the current kernel entry, and the
/// caller must not hold two live references at once.
pub unsafe fn frames() -> &'static mut FrameAllocator {
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

unsafe fn read_entry(table: u64, index: usize) -> u64 {
    unsafe { core::ptr::read_volatile((table as *const u64).add(index)) }
}

unsafe fn write_entry(table: u64, index: usize, value: u64) {
    unsafe {
        core::ptr::write_volatile((table as *mut u64).add(index), value);
    }
}

/// Builds an empty user address space for `pid`: a fresh PML4 whose entry 0
/// shares `kernel_pdpt` (supervisor only) and whose entry 1 leads to a
/// process-owned PDPT and page directory.
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
    let Some(directory) = frames.allocate(owner) else {
        unsafe { destroy(frames, &mut space, pid).ok()? };
        return None;
    };
    space.directory = directory.start_address();
    unsafe {
        zero_frame(root);
        zero_frame(pdpt);
        zero_frame(directory);
        write_entry(space.root, 0, kernel_pdpt | 3);
        write_entry(space.root, USER_PML4_INDEX, space.pdpt | 3);
        write_entry(space.pdpt, 0, space.directory | 3);
    }
    Some(space)
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
/// and already-mapped pages.
///
/// # Safety
///
/// `space` must have been produced by `create` and have one exclusive CPU
/// owner. A bounded AP fixture may map its own active root under the kernel
/// lock; no remote CPU may use that root. Tracked frames are identity-mapped
/// below 256 MiB, and reclamation waits for actual RSP/CR3/TSS departure ACK.
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
    let directory_index = ((address >> 21) & 0x1ff) as usize;
    let slot_index = if let Some(index) = space
        .page_tables
        .iter()
        .position(|slot| slot.frame != 0 && slot.directory_index == directory_index)
    {
        index
    } else {
        let index = space
            .page_tables
            .iter()
            .position(|slot| slot.frame == 0)
            .ok_or(MapError::NoMemory)?;
        let table_frame = frames
            .allocate(FrameOwner::PageTable(pid))
            .ok_or(MapError::NoMemory)?;
        unsafe {
            zero_frame(table_frame);
            write_entry(
                space.directory,
                directory_index,
                table_frame.start_address() | 3,
            );
        }
        space.page_tables[index] = PageTableSlot {
            directory_index,
            frame: table_frame.start_address(),
        };
        index
    };
    let table = space.page_tables[slot_index].frame;
    let page_index = ((address >> 12) & 0x1ff) as usize;
    if unsafe { read_entry(table, page_index) } & ENTRY_PRESENT != 0 {
        return Err(MapError::AlreadyMapped);
    }
    let backing = frames
        .allocate(FrameOwner::UserPage(pid))
        .ok_or(MapError::NoMemory)?;
    let mut flags = 3 | ENTRY_USER | (1 << 10) | (3 << 8) | (1 << 2) | (1 << 53);
    if !writable {
        flags |= 1 << 7;
    }
    if !executable {
        flags |= ENTRY_NO_EXECUTE;
    }
    unsafe {
        zero_frame(backing);
        write_entry(table, page_index, backing.start_address() | flags);
    }
    Ok(backing.start_address())
}

/// Whether `address` has a present user mapping in the owned tables.
pub unsafe fn is_mapped(space: &AddressSpace, address: u64) -> bool {
    unsafe { translate(space, address) }.is_some()
}

/// Lowest page-aligned address in `[base, end)` starting a run of `count`
/// unmapped pages, if any.
pub unsafe fn find_unmapped_run(
    space: &AddressSpace,
    base: u64,
    end: u64,
    count: u64,
) -> Option<u64> {
    let mut run_start = base;
    let mut run = 0;
    let mut page = base;
    while page < end {
        if unsafe { is_mapped(space, page) } {
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
    let directory_index = ((address >> 21) & 0x1ff) as usize;
    let Some(slot) = space
        .page_tables
        .iter()
        .find(|slot| slot.frame != 0 && slot.directory_index == directory_index)
    else {
        return Err(FrameError::NotAllocated);
    };
    let page_index = ((address >> 12) & 0x1ff) as usize;
    let entry = unsafe { read_entry(slot.frame, page_index) };
    if entry & (ENTRY_PRESENT | ENTRY_USER) != (ENTRY_PRESENT | ENTRY_USER) {
        return Err(FrameError::NotAllocated);
    }
    frames.free(Frame(entry & ADDRESS_MASK), FrameOwner::UserPage(pid))?;
    unsafe {
        write_entry(slot.frame, page_index, 0);
    }
    Ok(())
}

/// Physical address backing a user virtual address, via the owned tables.
pub unsafe fn translate(space: &AddressSpace, address: u64) -> Option<u64> {
    let directory_index = ((address >> 21) & 0x1ff) as usize;
    let slot = space
        .page_tables
        .iter()
        .find(|slot| slot.frame != 0 && slot.directory_index == directory_index)?;
    let entry = unsafe { read_entry(slot.frame, ((address >> 12) & 0x1ff) as usize) };
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
    for slot in space.page_tables.iter_mut() {
        if slot.frame == 0 {
            continue;
        }
        for index in 0..PAGE_TABLE_ENTRIES {
            let entry = unsafe { read_entry(slot.frame, index) };
            if entry & ENTRY_PRESENT != 0 {
                frames.free(Frame(entry & ADDRESS_MASK), FrameOwner::UserPage(pid))?;
                released += 1;
            }
        }
        frames.free(Frame(slot.frame), FrameOwner::PageTable(pid))?;
        released += 1;
        *slot = PageTableSlot::EMPTY;
    }
    for level in [&mut space.directory, &mut space.pdpt, &mut space.root] {
        if *level != 0 {
            frames.free(Frame(*level), FrameOwner::PageTable(pid))?;
            released += 1;
            *level = 0;
        }
    }
    Ok(released)
}
