//! Physical-frame ownership and page-table value types for the x86_64 kernel.
//!
//! Every 4 KiB frame below `TRACKED_PHYSICAL_LIMIT` has one tag: unavailable,
//! free, or allocated to a specific owner. Ownership is explicit so the kernel
//! can answer which process owns a frame, whether it backs a page table, user
//! memory, or a kernel stack, and what must be returned when a process ends.

pub const PAGE_SIZE: u64 = 4096;
/// Frames at or above this physical address are never tracked or allocated.
pub const TRACKED_PHYSICAL_LIMIT: u64 = MAX_TRACKED_FRAMES as u64 * PAGE_SIZE;
pub const MAX_TRACKED_FRAMES: usize = 65536;
/// Owner identifiers must fit the low 28 bits of a frame tag.
pub const MAX_OWNER_ID: u32 = (1 << 28) - 1;

const TAG_SHIFT: u32 = 28;
const OWNER_MASK: u32 = MAX_OWNER_ID;
const STATE_UNAVAILABLE: u32 = 0;
const STATE_FREE: u32 = 1;
const STATE_KERNEL: u32 = 2;
const STATE_PAGE_TABLE: u32 = 3;
const STATE_USER_PAGE: u32 = 4;
const STATE_KERNEL_STACK: u32 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame(pub u64);
impl Frame {
    pub const fn start_address(self) -> u64 {
        self.0
    }
}

/// Who an allocated frame belongs to and what role it plays.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameOwner {
    /// Kernel-global memory that is never reclaimed on process exit.
    Kernel,
    /// A page-table level owned exclusively by one process's address space.
    PageTable(u32),
    /// User code, data, or stack backing owned by one process.
    UserPage(u32),
    /// A process's kernel-mode stack.
    KernelStack(u32),
}

impl FrameOwner {
    pub const fn pid(self) -> Option<u32> {
        match self {
            Self::Kernel => None,
            Self::PageTable(pid) | Self::UserPage(pid) | Self::KernelStack(pid) => Some(pid),
        }
    }
    const fn encode(self) -> Option<u32> {
        let (state, owner) = match self {
            Self::Kernel => (STATE_KERNEL, 0),
            Self::PageTable(pid) => (STATE_PAGE_TABLE, pid),
            Self::UserPage(pid) => (STATE_USER_PAGE, pid),
            Self::KernelStack(pid) => (STATE_KERNEL_STACK, pid),
        };
        if owner > MAX_OWNER_ID {
            return None;
        }
        Some((state << TAG_SHIFT) | owner)
    }
    const fn decode(tag: u32) -> Option<Self> {
        let owner = tag & OWNER_MASK;
        match tag >> TAG_SHIFT {
            STATE_KERNEL => Some(Self::Kernel),
            STATE_PAGE_TABLE => Some(Self::PageTable(owner)),
            STATE_USER_PAGE => Some(Self::UserPage(owner)),
            STATE_KERNEL_STACK => Some(Self::KernelStack(owner)),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameState {
    Untracked,
    Unavailable,
    Free,
    Allocated(FrameOwner),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    Untracked,
    NotAllocated,
    WrongOwner(FrameOwner),
    InvalidOwner,
}

/// Fixed-capacity physical-frame allocator with per-frame ownership tags.
///
/// Frames are marked usable from the Multiboot2 memory map, then reserved
/// ranges (low memory, kernel image, boot information) are removed before any
/// allocation. Allocation and release are O(frames) scans guided by a hint;
/// correctness and visibility matter more than speed at this stage.
pub struct FrameAllocator {
    base: u64,
    tags: [u32; MAX_TRACKED_FRAMES],
    hint: usize,
    /// Optional ceiling on `allocated_frames`, used to force exhaustion in
    /// tests without actually running the machine out of memory.
    quota: Option<usize>,
    regions: usize,
    free_frames: usize,
    allocated_frames: usize,
    peak_allocated: usize,
}

impl FrameAllocator {
    pub const fn new() -> Self {
        Self::with_base(0)
    }

    /// Tracks exactly one bounded 256 MiB physical window.
    pub const fn with_base(base: u64) -> Self {
        assert!(base.is_multiple_of(PAGE_SIZE));
        assert!(base <= u64::MAX - TRACKED_PHYSICAL_LIMIT);
        Self {
            base,
            tags: [STATE_UNAVAILABLE; MAX_TRACKED_FRAMES],
            hint: 0,
            quota: None,
            regions: 0,
            free_frames: 0,
            allocated_frames: 0,
            peak_allocated: 0,
        }
    }

    fn index(&self, frame: Frame) -> Option<usize> {
        let relative = frame.0.checked_sub(self.base)?;
        (relative.is_multiple_of(PAGE_SIZE) && relative < TRACKED_PHYSICAL_LIMIT)
            .then_some((relative / PAGE_SIZE) as usize)
    }
    fn clipped(&self, address: u64) -> u64 {
        address
            .saturating_sub(self.base)
            .min(TRACKED_PHYSICAL_LIMIT)
    }

    /// Marks whole frames inside `[start, end)` free. Returns the number of
    /// newly usable frames; ranges above the tracked limit are clipped.
    pub fn add_usable(&mut self, start: u64, end: u64) -> usize {
        let start = self.clipped(align_up(start));
        let end = self.clipped(align_down(end));
        if start >= end {
            return 0;
        }
        self.regions += 1;
        let mut added = 0;
        for index in (start / PAGE_SIZE) as usize..(end / PAGE_SIZE) as usize {
            if self.tags[index] == STATE_UNAVAILABLE {
                self.tags[index] = STATE_FREE << TAG_SHIFT;
                added += 1;
            }
        }
        self.free_frames += added;
        added
    }

    /// Removes every frame overlapping `[start, end)` from the free pool.
    /// Returns false if any of those frames was already allocated.
    pub fn reserve(&mut self, start: u64, end: u64) -> bool {
        let start = self.clipped(align_down(start));
        let end = self.clipped(align_up(end));
        let mut clean = true;
        for index in (start / PAGE_SIZE) as usize..(end / PAGE_SIZE) as usize {
            match self.tags[index] >> TAG_SHIFT {
                STATE_FREE => {
                    self.tags[index] = STATE_UNAVAILABLE;
                    self.free_frames -= 1;
                }
                STATE_UNAVAILABLE => {}
                _ => clean = false,
            }
        }
        clean
    }

    pub fn usable_regions(&self) -> usize {
        self.regions
    }
    pub fn free_frames(&self) -> usize {
        self.free_frames
    }
    pub fn allocated_frames(&self) -> usize {
        self.allocated_frames
    }
    pub fn peak_allocated(&self) -> usize {
        self.peak_allocated
    }
    /// The ceiling on `allocated_frames`, if one is set.
    pub fn quota(&self) -> Option<usize> {
        self.quota
    }
    /// Refuses allocations that would raise `allocated_frames` above `quota`.
    pub fn set_quota(&mut self, quota: Option<usize>) {
        self.quota = quota;
    }

    pub fn state(&self, frame: Frame) -> FrameState {
        let Some(index) = self.index(frame) else {
            return FrameState::Untracked;
        };
        let tag = self.tags[index];
        match tag >> TAG_SHIFT {
            STATE_UNAVAILABLE => FrameState::Unavailable,
            STATE_FREE => FrameState::Free,
            _ => match FrameOwner::decode(tag) {
                Some(owner) => FrameState::Allocated(owner),
                None => FrameState::Unavailable,
            },
        }
    }

    /// Counts frames of any role owned by `pid`.
    pub fn frames_owned_by(&self, pid: u32) -> usize {
        self.tags
            .iter()
            .filter(|&&tag| FrameOwner::decode(tag).and_then(FrameOwner::pid) == Some(pid))
            .count()
    }

    pub fn allocate(&mut self, owner: FrameOwner) -> Option<Frame> {
        self.allocate_contiguous(1, owner)
    }

    /// Allocates `count` physically consecutive frames, all tagged `owner`.
    pub fn allocate_contiguous(&mut self, count: usize, owner: FrameOwner) -> Option<Frame> {
        let tag = owner.encode()?;
        if count == 0 || count > self.free_frames {
            return None;
        }
        if self
            .quota
            .is_some_and(|quota| self.allocated_frames + count > quota)
        {
            return None;
        }
        let mut run_start = self.hint;
        let mut run = 0;
        let mut index = self.hint;
        while index < MAX_TRACKED_FRAMES {
            if self.tags[index] >> TAG_SHIFT == STATE_FREE {
                if run == 0 {
                    run_start = index;
                }
                run += 1;
                if run == count {
                    for slot in &mut self.tags[run_start..run_start + count] {
                        *slot = tag;
                    }
                    self.free_frames -= count;
                    self.allocated_frames += count;
                    self.peak_allocated = self.peak_allocated.max(self.allocated_frames);
                    if run_start == self.hint {
                        self.hint = run_start + count;
                    }
                    return Some(Frame(self.base + run_start as u64 * PAGE_SIZE));
                }
            } else {
                run = 0;
            }
            index += 1;
        }
        None
    }

    /// Returns one frame to the free pool. The caller must name the owner it
    /// believes holds the frame; a mismatch or a free frame is rejected so
    /// double frees and ownership confusion surface immediately.
    pub fn free(&mut self, frame: Frame, owner: FrameOwner) -> Result<(), FrameError> {
        let index = self.index(frame).ok_or(FrameError::Untracked)?;
        let expected = owner.encode().ok_or(FrameError::InvalidOwner)?;
        let tag = self.tags[index];
        match tag >> TAG_SHIFT {
            STATE_UNAVAILABLE => return Err(FrameError::Untracked),
            STATE_FREE => return Err(FrameError::NotAllocated),
            _ => {}
        }
        #[cfg(absd_mutant_free_any_owner)]
        let _ = expected;
        #[cfg(not(absd_mutant_free_any_owner))]
        if tag != expected {
            return Err(FrameError::WrongOwner(
                FrameOwner::decode(tag).ok_or(FrameError::Untracked)?,
            ));
        }
        self.tags[index] = STATE_FREE << TAG_SHIFT;
        self.free_frames += 1;
        self.allocated_frames -= 1;
        self.hint = self.hint.min(index);
        Ok(())
    }
}

impl Default for FrameAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// One-page allocator used while the full heap/paging subsystem is still
/// deliberately small. It reuses one freed allocation and rejects overflow.
pub struct TinyHeap {
    start: usize,
    end: usize,
    cursor: usize,
    recycled: usize,
}
impl TinyHeap {
    pub const fn new(start: usize, bytes: usize) -> Self {
        Self {
            start,
            end: start + bytes,
            cursor: start,
            recycled: 0,
        }
    }
    pub fn allocate(&mut self, bytes: usize, align: usize) -> Option<*mut u8> {
        if self.recycled != 0 {
            let value = self.recycled;
            self.recycled = 0;
            return Some(value as *mut u8);
        }
        if align == 0 || !align.is_power_of_two() {
            return None;
        }
        let address = self.cursor.checked_add(align - 1)? & !(align - 1);
        let end = address.checked_add(bytes)?;
        if end > self.end {
            return None;
        }
        self.cursor = end;
        Some(address as *mut u8)
    }
    pub fn free(&mut self, pointer: *mut u8, bytes: usize) -> bool {
        let address = pointer as usize;
        if self.recycled != 0
            || address < self.start
            || address.checked_add(bytes).is_none_or(|end| end > self.end)
        {
            return false;
        }
        self.recycled = address;
        true
    }
}
pub const fn align_down(value: u64) -> u64 {
    value & !(PAGE_SIZE - 1)
}
pub const fn align_up(value: u64) -> u64 {
    (value + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Page {
    start: u64,
}
impl Page {
    pub const fn containing(address: u64) -> Self {
        Self {
            start: align_down(address),
        }
    }
    pub const fn pml4_index(self) -> usize {
        ((self.start >> 39) & 0x1ff) as usize
    }
    pub const fn pdpt_index(self) -> usize {
        ((self.start >> 30) & 0x1ff) as usize
    }
}
pub const ENTRY_PRESENT: u64 = 1;
pub const ENTRY_WRITABLE: u64 = 1 << 1;
pub const ENTRY_USER: u64 = 1 << 2;
pub const ENTRY_NO_EXECUTE: u64 = 1 << 63;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageTableEntry(u64);
impl PageTableEntry {
    pub const fn new(frame: Frame, flags: u64) -> Self {
        Self((frame.start_address() & 0x000f_ffff_ffff_f000) | flags)
    }
    pub const fn frame(self) -> Frame {
        Frame(self.0 & 0x000f_ffff_ffff_f000)
    }
    pub const fn is_present(self) -> bool {
        self.0 & ENTRY_PRESENT != 0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::boxed::Box;

    #[test]
    fn nonzero_physical_window_preserves_bounds_and_ownership() {
        let base = 0x4000_0000;
        let mut frames = Box::new(FrameAllocator::with_base(base));
        assert_eq!(frames.add_usable(0, base), 0);
        assert_eq!(frames.add_usable(base, base + 3 * PAGE_SIZE), 3);
        assert!(frames.reserve(base, base + PAGE_SIZE));
        let frame = frames.allocate(FrameOwner::UserPage(7)).unwrap();
        assert_eq!(frame, Frame(base + PAGE_SIZE));
        assert_eq!(frames.state(Frame(PAGE_SIZE)), FrameState::Untracked);
        assert_eq!(
            frames.state(Frame(base + TRACKED_PHYSICAL_LIMIT)),
            FrameState::Untracked
        );
        assert_eq!(
            frames.free(frame, FrameOwner::UserPage(8)),
            Err(FrameError::WrongOwner(FrameOwner::UserPage(7)))
        );
        frames.free(frame, FrameOwner::UserPage(7)).unwrap();
        assert_eq!(frames.allocated_frames(), 0);
        assert_eq!(frames.free_frames(), 2);
    }

    fn allocator() -> Box<FrameAllocator> {
        Box::new(FrameAllocator::new())
    }

    #[test]
    fn allocator_aligns_and_iterates_usable_frames() {
        let mut frames = allocator();
        assert_eq!(frames.add_usable(0x1003, 0x4001), 2);
        assert_eq!(frames.allocate(FrameOwner::Kernel), Some(Frame(0x2000)));
        assert_eq!(frames.allocate(FrameOwner::Kernel), Some(Frame(0x3000)));
        assert_eq!(frames.allocate(FrameOwner::Kernel), None);
    }

    #[test]
    fn allocator_excludes_low_kernel_and_boot_ranges() {
        let mut frames = allocator();
        assert_eq!(frames.add_usable(0, 0x9000), 9);
        assert!(frames.reserve(0, 0x2000));
        assert!(frames.reserve(0x3000, 0x5800));
        assert_eq!(frames.free_frames(), 4);
        assert_eq!(frames.allocate(FrameOwner::Kernel), Some(Frame(0x2000)));
        assert_eq!(frames.allocate(FrameOwner::Kernel), Some(Frame(0x6000)));
        assert_eq!(frames.state(Frame(0x4000)), FrameState::Unavailable);
        assert_eq!(
            frames.state(Frame(TRACKED_PHYSICAL_LIMIT)),
            FrameState::Untracked
        );
    }

    #[test]
    fn freed_frames_are_reused_and_ownership_is_checked() {
        let mut frames = allocator();
        frames.add_usable(0x10000, 0x13000);
        let table = frames.allocate(FrameOwner::PageTable(7)).unwrap();
        let page = frames.allocate(FrameOwner::UserPage(7)).unwrap();
        assert_eq!(frames.allocated_frames(), 2);
        assert_eq!(frames.frames_owned_by(7), 2);
        assert_eq!(
            frames.state(page),
            FrameState::Allocated(FrameOwner::UserPage(7))
        );
        assert_eq!(
            frames.free(page, FrameOwner::UserPage(8)),
            Err(FrameError::WrongOwner(FrameOwner::UserPage(7)))
        );
        assert_eq!(
            frames.free(page, FrameOwner::PageTable(7)),
            Err(FrameError::WrongOwner(FrameOwner::UserPage(7)))
        );
        assert_eq!(frames.free(page, FrameOwner::UserPage(7)), Ok(()));
        assert_eq!(
            frames.free(page, FrameOwner::UserPage(7)),
            Err(FrameError::NotAllocated)
        );
        assert_eq!(
            frames.free(Frame(0x1234), FrameOwner::Kernel),
            Err(FrameError::Untracked)
        );
        assert_eq!(
            frames.free(Frame(0x20000), FrameOwner::Kernel),
            Err(FrameError::Untracked)
        );
        assert_eq!(frames.allocate(FrameOwner::KernelStack(9)), Some(page));
        assert_eq!(frames.free(table, FrameOwner::PageTable(7)), Ok(()));
        assert_eq!(frames.frames_owned_by(7), 0);
        assert_eq!(frames.allocated_frames(), 1);
        assert_eq!(frames.peak_allocated(), 2);
    }

    #[test]
    fn repeated_allocate_free_cycles_do_not_leak() {
        let mut frames = allocator();
        frames.add_usable(0x100000, 0x110000);
        let baseline = frames.free_frames();
        for cycle in 0..500u32 {
            let owner = FrameOwner::UserPage(cycle % 5 + 1);
            let a = frames.allocate(owner).unwrap();
            let b = frames.allocate(owner).unwrap();
            let c = frames.allocate(owner).unwrap();
            assert!(frames.free(b, owner).is_ok());
            assert!(frames.free(a, owner).is_ok());
            assert!(frames.free(c, owner).is_ok());
            assert_eq!(frames.free_frames(), baseline);
        }
        assert_eq!(frames.peak_allocated(), 3);
        assert_eq!(frames.allocated_frames(), 0);
    }

    #[test]
    fn contiguous_runs_skip_gaps_and_are_freed_frame_by_frame() {
        let mut frames = allocator();
        frames.add_usable(0x10000, 0x16000);
        let hole = frames.allocate(FrameOwner::Kernel).unwrap();
        let second = frames.allocate(FrameOwner::Kernel).unwrap();
        assert!(frames.free(hole, FrameOwner::Kernel).is_ok());
        let stack = frames
            .allocate_contiguous(3, FrameOwner::KernelStack(2))
            .unwrap();
        assert_eq!(stack, Frame(second.start_address() + PAGE_SIZE));
        assert!(frames.allocate_contiguous(2, FrameOwner::Kernel).is_none());
        for page in 0..3 {
            assert!(
                frames
                    .free(
                        Frame(stack.start_address() + page * PAGE_SIZE),
                        FrameOwner::KernelStack(2)
                    )
                    .is_ok()
            );
        }
        assert_eq!(frames.free_frames(), 5);
        assert!(frames.allocate_contiguous(0, FrameOwner::Kernel).is_none());
        assert!(
            frames
                .allocate(FrameOwner::UserPage(MAX_OWNER_ID + 1))
                .is_none()
        );
    }

    #[test]
    fn quota_bounds_allocation_without_touching_free_frames() {
        let mut frames = allocator();
        frames.add_usable(0x10000, 0x20000);
        frames.set_quota(Some(2));
        let a = frames.allocate(FrameOwner::Kernel).unwrap();
        let b = frames.allocate(FrameOwner::Kernel).unwrap();
        assert!(frames.allocate(FrameOwner::Kernel).is_none());
        assert!(frames.allocate_contiguous(2, FrameOwner::Kernel).is_none());
        assert_eq!(frames.free_frames(), 14);
        assert!(frames.free(a, FrameOwner::Kernel).is_ok());
        assert!(frames.allocate(FrameOwner::Kernel).is_some());
        frames.set_quota(None);
        assert!(frames.allocate_contiguous(3, FrameOwner::Kernel).is_some());
        assert!(frames.free(b, FrameOwner::Kernel).is_ok());
    }

    #[test]
    fn page_indices_and_entry_preserve_frame_identity() {
        let page = Page::containing(0xffff_8000_1234_5678);
        assert_eq!(page.pml4_index(), 256);
        assert_eq!(page.pdpt_index(), 0);
        let entry = PageTableEntry::new(Frame(0x1234_5000), ENTRY_PRESENT | ENTRY_WRITABLE);
        assert!(entry.is_present());
        assert_eq!(entry.frame(), Frame(0x1234_5000));
    }

    #[test]
    fn tiny_heap_reuses_and_bounds_an_allocation() {
        let mut bytes = [0u8; 4096];
        let mut heap = TinyHeap::new(bytes.as_mut_ptr() as usize, bytes.len());
        let first = heap.allocate(64, 16).unwrap();
        assert!(heap.free(first, 64));
        assert_eq!(heap.allocate(64, 16), Some(first));
        assert_eq!(heap.allocate(4096, 16), None);
        assert_eq!(heap.allocate(1, 3), None);
    }
}
