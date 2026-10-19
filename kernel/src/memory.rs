//! Physical-frame ownership and page-table value types for the x86_64 kernel.
//!
//! Every tracked 4 KiB frame has one tag: unavailable, free, or allocated to a
//! specific owner. The built-in table covers `TRACKED_PHYSICAL_LIMIT`; a boot
//! may install a larger table (`extend_tags`) up to `PHYSICAL_TRACKING_BOUND`. Ownership is explicit so the kernel
//! can answer which process owns a frame, whether it backs a page table, user
//! memory, or a kernel stack, and what must be returned when a process ends.

pub const PAGE_SIZE: u64 = 4096;
/// Span of the built-in tag table (256 MiB above the base). Without
/// `extend_tags`, frames at or above it are never tracked or allocated.
pub const TRACKED_PHYSICAL_LIMIT: u64 = MAX_TRACKED_FRAMES as u64 * PAGE_SIZE;
pub const MAX_TRACKED_FRAMES: usize = 65536;
/// Explicit upper bound on tracked physical memory with an installed table:
/// 64 GiB, twice the largest current target (HP Z2 Mini G3, 32 GiB). Usable
/// RAM above it is clipped and disclosed at boot. A full table is 64 MiB.
pub const PHYSICAL_TRACKING_BOUND: u64 = 64 << 30;
pub const MAX_EXTENDED_FRAMES: usize = (PHYSICAL_TRACKING_BOUND / PAGE_SIZE) as usize;
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

#[cfg(feature = "frame-admission-core")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    Invalid,
    AlreadyAdmitted,
    NoCapacity,
    NoRecord,
    StillOwned,
}

#[cfg(feature = "frame-admission-core")]
#[derive(Clone, Copy)]
struct Reservation {
    pid: u32,
    total: u32,
    used: u32,
}

#[cfg(feature = "frame-admission-core")]
impl Reservation {
    const EMPTY: Self = Self {
        pid: 0,
        total: 0,
        used: 0,
    };
}

/// Fixed-capacity physical-frame allocator with per-frame ownership tags.
///
/// Frames are marked usable from the Multiboot2 memory map, then reserved
/// ranges (low memory, kernel image, boot information) are removed before any
/// allocation. Allocation and release are O(frames) scans guided by a hint;
/// correctness and visibility matter more than speed at this stage.
/// `frames_owned_by` scans only up to the highest frame ever allocated.
pub struct FrameAllocator {
    base: u64,
    tags: Tags,
    /// One past the highest tag index ever allocated; never lowered.
    high_water: usize,
    hint: usize,
    /// Optional ceiling on `allocated_frames`, used to force exhaustion in
    /// tests without actually running the machine out of memory.
    quota: Option<usize>,
    regions: usize,
    free_frames: usize,
    allocated_frames: usize,
    peak_allocated: usize,
    #[cfg(feature = "frame-admission-core")]
    reservations: [Reservation; crate::process::MAX_PROCESSES],
    #[cfg(feature = "frame-admission-core")]
    idle_reserved: usize,
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
            tags: Tags {
                inline: [STATE_UNAVAILABLE; MAX_TRACKED_FRAMES],
                installed: None,
            },
            high_water: 0,
            hint: 0,
            quota: None,
            regions: 0,
            free_frames: 0,
            allocated_frames: 0,
            peak_allocated: 0,
            #[cfg(feature = "frame-admission-core")]
            reservations: [Reservation::EMPTY; crate::process::MAX_PROCESSES],
            #[cfg(feature = "frame-admission-core")]
            idle_reserved: 0,
        }
    }

    /// Replaces the built-in table with `tags`, one entry per frame from the
    /// base, before any frame is usable. Refuses a table no larger than the
    /// built-in one, one beyond `MAX_EXTENDED_FRAMES`, a second install, or
    /// an allocator that already has usable frames.
    pub fn extend_tags(&mut self, tags: &'static mut [u32]) -> bool {
        if self.tags.installed.is_some()
            || self.regions != 0
            || self.free_frames != 0
            || self.allocated_frames != 0
            || tags.len() <= MAX_TRACKED_FRAMES
            || tags.len() > MAX_EXTENDED_FRAMES
            || self
                .base
                .checked_add(tags.len() as u64 * PAGE_SIZE)
                .is_none()
        {
            return false;
        }
        tags.fill(STATE_UNAVAILABLE);
        self.tags.installed = Some(tags);
        true
    }
    /// Number of frames with a tag, from the base.
    pub fn tracked_frames(&self) -> usize {
        self.tags.len()
    }
    /// Physical end of the tracked span; nothing at or above it is tracked.
    pub fn tracked_limit(&self) -> u64 {
        self.base + self.tags.len() as u64 * PAGE_SIZE
    }

    fn index(&self, frame: Frame) -> Option<usize> {
        let relative = frame.0.checked_sub(self.base)?;
        (relative.is_multiple_of(PAGE_SIZE) && relative < self.tracked_limit() - self.base)
            .then_some((relative / PAGE_SIZE) as usize)
    }
    fn clipped(&self, address: u64) -> u64 {
        address
            .saturating_sub(self.base)
            .min(self.tracked_limit() - self.base)
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
                self.hint = self.hint.min(index);
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
        if start >= end {
            return true;
        }
        #[cfg(feature = "frame-admission-core")]
        {
            let removed = self.tags[(start / PAGE_SIZE) as usize..(end / PAGE_SIZE) as usize]
                .iter()
                .filter(|&&tag| tag >> TAG_SHIFT == STATE_FREE)
                .count();
            if removed > self.free_frames - self.idle_reserved {
                return false;
            }
        }
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

    /// Returns frames of `[start, end)` that a caller itself took out with
    /// `reserve` to the free pool, without counting a new usable region.
    /// The caller must name only frames it reserved from free; any other
    /// frame in the range must not be unavailable. Returns the count.
    pub fn unreserve(&mut self, start: u64, end: u64) -> usize {
        let start = self.clipped(align_up(start));
        let end = self.clipped(align_down(end));
        let mut released = 0;
        for index in (start / PAGE_SIZE) as usize..(end / PAGE_SIZE) as usize {
            if self.tags[index] == STATE_UNAVAILABLE {
                self.tags[index] = STATE_FREE << TAG_SHIFT;
                self.hint = self.hint.min(index);
                released += 1;
            }
        }
        self.free_frames += released;
        released
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
    /// Restarts the peak at the current allocation, after a boot self-test
    /// that allocated everything on purpose.
    pub fn reset_peak(&mut self) {
        self.peak_allocated = self.allocated_frames;
    }
    /// The ceiling on `allocated_frames`, if one is set.
    pub fn quota(&self) -> Option<usize> {
        self.quota
    }
    /// Refuses allocations that would raise `allocated_frames` above `quota`.
    pub fn set_quota(&mut self, quota: Option<usize>) {
        #[cfg(feature = "frame-admission-core")]
        assert!(quota.is_none_or(|q| q >= self.allocated_frames + self.idle_reserved));
        self.quota = quota;
    }

    /// Total process-owned frames, including page tables and kernel stack.
    /// A successful spawn publishes the promise only after initialization.
    /// Future single-frame allocations have backing; virtual address limits,
    /// page-table slot limits and contiguous allocations remain separate.
    #[cfg(feature = "frame-admission-core")]
    pub fn admit(&mut self, pid: u32, total: usize) -> Result<(), AdmissionError> {
        if pid == 0
            || pid > MAX_OWNER_ID
            || total == 0
            || total > crate::syscall::MAX_FRAME_ADMISSION_FRAMES as usize
        {
            return Err(AdmissionError::Invalid);
        }
        if self.reservation_index(pid).is_some() {
            return Err(AdmissionError::AlreadyAdmitted);
        }
        let used = self.frames_owned_by(pid);
        let idle = total.checked_sub(used).ok_or(AdmissionError::Invalid)?;
        if idle > self.available_frames() - self.idle_reserved {
            return Err(AdmissionError::NoCapacity);
        }
        let slot = self
            .reservations
            .iter_mut()
            .find(|r| r.pid == 0)
            .ok_or(AdmissionError::NoRecord)?;
        *slot = Reservation {
            pid,
            total: total as u32,
            used: used as u32,
        };
        self.idle_reserved += idle;
        Ok(())
    }

    #[cfg(feature = "frame-admission-core")]
    fn available_frames(&self) -> usize {
        self.free_frames.min(
            self.quota
                .map_or(usize::MAX, |q| q.saturating_sub(self.allocated_frames)),
        )
    }

    #[cfg(feature = "frame-admission-core")]
    fn reservation_index(&self, pid: u32) -> Option<usize> {
        self.reservations
            .iter()
            .position(|r| r.pid == pid && pid != 0)
    }

    #[cfg(feature = "frame-admission-core")]
    pub fn reservation(&self, pid: u32) -> Option<(usize, usize)> {
        self.reservation_index(pid).map(|i| {
            let r = self.reservations[i];
            (r.total as usize, r.used as usize)
        })
    }

    #[cfg(feature = "frame-admission-core")]
    pub fn idle_reserved_frames(&self) -> usize {
        self.idle_reserved
    }

    /// Snapshot all records, including fully consumed commitments (idle zero).
    #[cfg(feature = "frame-admission-core")]
    pub fn admission_accounting(&self) -> AdmissionAccounting {
        let mut result = AdmissionAccounting {
            records: 0,
            total: 0,
            used: 0,
            idle: self.idle_reserved as u64,
            consistent: true,
        };
        let mut unused = 0u64;
        for r in self.reservations.iter().filter(|r| r.pid != 0) {
            result.records += 1;
            result.total += u64::from(r.total);
            result.used += u64::from(r.used);
            match r.total.checked_sub(r.used) {
                Some(n) => unused += u64::from(n),
                None => result.consistent = false,
            }
        }
        result.consistent &= unused == result.idle;
        result
    }

    /// Reclamation must return actual frames before retiring the promise.
    #[cfg(feature = "frame-admission-core")]
    pub fn retire_reservation(&mut self, pid: u32) -> Result<(), AdmissionError> {
        if let Some(i) = self.reservation_index(pid) {
            if self.reservations[i].used != 0 {
                return Err(AdmissionError::StillOwned);
            }
            self.idle_reserved -= self.reservations[i].total as usize;
            self.reservations[i] = Reservation::EMPTY;
        }
        Ok(())
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
        self.tags[..self.high_water]
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
        #[cfg(feature = "frame-admission-core")]
        let reservation = owner.pid().and_then(|pid| self.reservation_index(pid));
        #[cfg(feature = "frame-admission-core")]
        {
            let allowance = reservation.map_or(self.available_frames() - self.idle_reserved, |i| {
                let r = self.reservations[i];
                (r.total - r.used) as usize
            });
            if count > allowance {
                return None;
            }
        }
        // The hint may name a reserved or occupied prefix. Skip that prefix
        // once; retain the first short free fragment for smaller requests.
        while self.hint < self.tags.len() && self.tags[self.hint] >> TAG_SHIFT != STATE_FREE {
            self.hint += 1;
        }
        let mut run_start = self.hint;
        let mut run = 0;
        let mut index = self.hint;
        while index < self.tags.len() {
            if self.tags[index] >> TAG_SHIFT == STATE_FREE {
                if run == 0 {
                    run_start = index;
                }
                run += 1;
                if run == count {
                    for slot in &mut self.tags[run_start..run_start + count] {
                        *slot = tag;
                    }
                    self.high_water = self.high_water.max(run_start + count);
                    self.free_frames -= count;
                    self.allocated_frames += count;
                    #[cfg(feature = "frame-admission-core")]
                    if let Some(i) = reservation {
                        self.reservations[i].used += count as u32;
                        self.idle_reserved -= count;
                    }
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
        #[cfg(feature = "frame-admission-core")]
        if let Some(i) = owner.pid().and_then(|pid| self.reservation_index(pid)) {
            self.reservations[i].used -= 1;
            self.idle_reserved += 1;
        }
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

/// One tag per tracked frame: the built-in 256 MiB table, or a larger
/// boot-placed table that replaces it before any frame becomes usable.
struct Tags {
    inline: [u32; MAX_TRACKED_FRAMES],
    installed: Option<&'static mut [u32]>,
}

impl core::ops::Deref for Tags {
    type Target = [u32];
    fn deref(&self) -> &[u32] {
        match &self.installed {
            Some(tags) => tags,
            None => &self.inline,
        }
    }
}

impl core::ops::DerefMut for Tags {
    fn deref_mut(&mut self) -> &mut [u32] {
        match &mut self.installed {
            Some(tags) => tags,
            None => &mut self.inline,
        }
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
    fn first_fit_revisits_short_fragments_and_new_low_ranges() {
        let mut frames = allocator();
        frames.add_usable(64 * PAGE_SIZE, 70 * PAGE_SIZE);
        let first = frames.allocate(FrameOwner::Kernel).unwrap();
        frames.allocate(FrameOwner::Kernel).unwrap();
        frames.free(first, FrameOwner::Kernel).unwrap();
        assert_eq!(
            frames.allocate_contiguous(4, FrameOwner::Kernel),
            Some(Frame(66 * PAGE_SIZE))
        );
        assert_eq!(frames.allocate(FrameOwner::Kernel), Some(first));
        assert_eq!(frames.allocate(FrameOwner::Kernel), None);
        frames.add_usable(8 * PAGE_SIZE, 10 * PAGE_SIZE);
        assert_eq!(
            frames.allocate_contiguous(2, FrameOwner::Kernel),
            Some(Frame(8 * PAGE_SIZE))
        );
    }

    #[test]
    fn first_fit_addresses_match_independent_bitmap_after_capacity_mutations() {
        // The oracle always searches the complete small bitmap from zero;
        // it has no search hint or run-state implementation in common.
        for seed in 1..=16u64 {
            let mut frames = allocator();
            let mut bitmap = [0u8; 96]; // unavailable, free, allocated
            frames.add_usable(32 * PAGE_SIZE, 64 * PAGE_SIZE);
            bitmap[32..64].fill(1);
            let mut rng = seed;
            for _ in 0..2000 {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                let low = ((rng >> 32) % 96) as usize;
                let end = (low + ((rng >> 40) % 8 + 1) as usize).min(96);
                match rng >> 48 & 7 {
                    0..=3 => {
                        let count = ((rng >> 56) % 8 + 1) as usize;
                        let expected = bitmap
                            .windows(count)
                            .position(|w| w.iter().all(|&s| s == 1));
                        assert_eq!(
                            frames.allocate_contiguous(count, FrameOwner::Kernel),
                            expected.map(|i| Frame(i as u64 * PAGE_SIZE))
                        );
                        if let Some(i) = expected {
                            bitmap[i..i + count].fill(2);
                        }
                    }
                    4 => {
                        if bitmap[low] == 2 {
                            frames
                                .free(Frame(low as u64 * PAGE_SIZE), FrameOwner::Kernel)
                                .unwrap();
                            bitmap[low] = 1;
                        }
                    }
                    5 => {
                        let clean = !bitmap[low..end].contains(&2);
                        assert_eq!(
                            frames.reserve(low as u64 * PAGE_SIZE, end as u64 * PAGE_SIZE),
                            clean
                        );
                        for state in &mut bitmap[low..end] {
                            if *state == 1 {
                                *state = 0;
                            }
                        }
                    }
                    _ => {
                        let added = bitmap[low..end].iter().filter(|&&s| s == 0).count();
                        assert_eq!(
                            frames.add_usable(low as u64 * PAGE_SIZE, end as u64 * PAGE_SIZE),
                            added
                        );
                        for state in &mut bitmap[low..end] {
                            if *state == 0 {
                                *state = 1;
                            }
                        }
                    }
                }
                assert_eq!(
                    frames.free_frames(),
                    bitmap.iter().filter(|&&s| s == 1).count()
                );
                assert_eq!(
                    frames.allocated_frames(),
                    bitmap.iter().filter(|&&s| s == 2).count()
                );
            }
        }
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

    fn extended(frames_tracked: usize) -> Box<FrameAllocator> {
        let mut frames = allocator();
        let table = std::vec![0xffff_ffffu32; frames_tracked].leak();
        assert!(frames.extend_tags(table));
        frames
    }

    #[test]
    fn extended_table_tracks_frames_above_the_built_in_window_and_four_gib() {
        let limit = 5u64 << 30;
        let mut frames = extended((limit / PAGE_SIZE) as usize);
        assert_eq!(frames.tracked_limit(), limit);
        assert_eq!(frames.tracked_frames(), (limit / PAGE_SIZE) as usize);
        // Every tag starts unavailable, whatever the table held before.
        assert_eq!(frames.state(Frame(4 << 30)), FrameState::Unavailable);
        // A range across the old 256 MiB limit is no longer clipped.
        assert_eq!(
            frames.add_usable(
                TRACKED_PHYSICAL_LIMIT - PAGE_SIZE,
                TRACKED_PHYSICAL_LIMIT + 2 * PAGE_SIZE
            ),
            3
        );
        assert_eq!(frames.add_usable(4 << 30, (4 << 30) + 2 * PAGE_SIZE), 2);
        // A range across the installed limit is clipped there.
        assert_eq!(
            frames.add_usable(limit - PAGE_SIZE, limit + 16 * PAGE_SIZE),
            1
        );
        assert_eq!(frames.state(Frame(limit)), FrameState::Untracked);
        assert_eq!(
            frames.free(Frame(limit), FrameOwner::Kernel),
            Err(FrameError::Untracked)
        );
        assert!(frames.reserve(TRACKED_PHYSICAL_LIMIT - PAGE_SIZE, TRACKED_PHYSICAL_LIMIT));
        assert_eq!(frames.free_frames(), 5);
        let mut held = std::vec::Vec::new();
        while let Some(frame) = frames.allocate(FrameOwner::UserPage(3)) {
            held.push(frame);
        }
        assert_eq!(
            held,
            [
                Frame(TRACKED_PHYSICAL_LIMIT),
                Frame(TRACKED_PHYSICAL_LIMIT + PAGE_SIZE),
                Frame(4 << 30),
                Frame((4 << 30) + PAGE_SIZE),
                Frame(limit - PAGE_SIZE),
            ]
        );
        assert_eq!(frames.frames_owned_by(3), 5);
        assert_eq!(
            frames.free(held[4], FrameOwner::UserPage(4)),
            Err(FrameError::WrongOwner(FrameOwner::UserPage(3)))
        );
        for frame in held.iter().rev() {
            frames.free(*frame, FrameOwner::UserPage(3)).unwrap();
        }
        assert_eq!(frames.frames_owned_by(3), 0);
        assert_eq!((frames.free_frames(), frames.allocated_frames()), (5, 0));
        assert_eq!(frames.peak_allocated(), 5);
        frames.reset_peak();
        assert_eq!(frames.peak_allocated(), 0);
        // The quota hook still bounds an extended table.
        frames.set_quota(Some(1));
        assert!(frames.allocate(FrameOwner::Kernel).is_some());
        assert!(frames.allocate(FrameOwner::Kernel).is_none());
    }

    #[test]
    fn unreserve_returns_held_frames_without_a_new_region() {
        let mut frames = allocator();
        frames.add_usable(0x10000, 0x20000);
        let regions = frames.usable_regions();
        assert!(frames.reserve(0x12000, 0x14000));
        assert_eq!(frames.free_frames(), 14);
        let first = frames.allocate(FrameOwner::Kernel).unwrap();
        assert_eq!(first, Frame(0x10000));
        assert_eq!(frames.unreserve(0x12000, 0x14000), 2);
        assert_eq!(frames.free_frames(), 15);
        assert_eq!(frames.usable_regions(), regions);
        assert_eq!(frames.state(Frame(0x12000)), FrameState::Free);
        assert_eq!(frames.allocate(FrameOwner::Kernel), Some(Frame(0x11000)));
        assert_eq!(frames.allocate(FrameOwner::Kernel), Some(Frame(0x12000)));
    }

    /// Host cost of the whole-table scans after a full-RAM peak (lane #43
    /// receipt): `frames_owned_by` with `high_water` at the table end, and a
    /// census that calls `state()` per frame as `kernel_frame_census` does.
    /// A host measurement of the library, not a kernel run. Run with
    /// `cargo test -p absd-kernel --lib whole_table_scan_cost -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn whole_table_scan_cost() {
        for gib in [32u64, 64] {
            let tracked = ((gib << 30) / PAGE_SIZE) as usize;
            let mut frames = extended(tracked);
            frames.add_usable(0, gib << 30);
            let mut last = None;
            while let Some(frame) = frames.allocate(FrameOwner::UserPage(7)) {
                last = Some(frame);
            }
            frames.free(last.unwrap(), FrameOwner::UserPage(7)).unwrap();
            let best = |scan: &dyn Fn() -> usize| {
                (0..5)
                    .map(|_| {
                        let start = std::time::Instant::now();
                        core::hint::black_box(scan());
                        start.elapsed().as_micros()
                    })
                    .min()
                    .unwrap()
            };
            let owned = best(&|| core::hint::black_box(&frames).frames_owned_by(9));
            let census = best(&|| {
                let frames = core::hint::black_box(&frames);
                (0..frames.tracked_frames())
                    .filter(|&i| {
                        matches!(
                            frames.state(Frame(i as u64 * PAGE_SIZE)),
                            FrameState::Allocated(FrameOwner::Kernel)
                        )
                    })
                    .count()
            });
            std::println!(
                "WHOLE TABLE SCAN gib={gib} tags={tracked} frames_owned_by_us={owned} state_census_us={census}"
            );
        }
    }

    #[test]
    fn extended_table_is_bounded_and_installed_once_before_use() {
        assert_eq!(
            MAX_EXTENDED_FRAMES as u64 * PAGE_SIZE,
            PHYSICAL_TRACKING_BOUND
        );
        let mut frames = allocator();
        assert!(!frames.extend_tags(std::vec![0u32; MAX_TRACKED_FRAMES].leak()));
        assert!(!frames.extend_tags(std::vec![0u32; MAX_EXTENDED_FRAMES + 1].leak()));
        assert_eq!(frames.tracked_limit(), TRACKED_PHYSICAL_LIMIT);
        assert!(frames.extend_tags(std::vec![0u32; MAX_EXTENDED_FRAMES].leak()));
        assert_eq!(frames.tracked_limit(), PHYSICAL_TRACKING_BOUND);
        assert!(!frames.extend_tags(std::vec![0u32; MAX_TRACKED_FRAMES + 1].leak()));
        let mut used = allocator();
        used.add_usable(0x10000, 0x20000);
        assert!(!used.extend_tags(std::vec![0u32; MAX_TRACKED_FRAMES + 1].leak()));
        assert_eq!(used.tracked_limit(), TRACKED_PHYSICAL_LIMIT);
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

#[cfg(all(test, feature = "frame-admission-core"))]
#[path = "memory_reservation_tests.rs"]
mod reservation_tests;

#[cfg(feature = "frame-admission-core")]
#[derive(Debug, Clone, Copy)]
pub struct AdmissionAccounting {
    pub records: usize,
    pub total: u64,
    pub used: u64,
    pub idle: u64,
    pub consistent: bool,
}
#[cfg(feature = "frame-admission-core")]
impl AdmissionAccounting {
    pub fn clean(&self) -> bool {
        self.consistent && self.records == 0 && self.total == 0 && self.used == 0 && self.idle == 0
    }
}

#[cfg(all(test, feature = "frame-admission-core"))]
mod accounting_tests {
    use super::*;
    #[test]
    fn terminal_check_rejects_consumed_idle_and_corrupt_records_without_panicking() {
        let mut f = FrameAllocator::new();
        f.add_usable(0, 16 * PAGE_SIZE);
        assert!(f.admission_accounting().clean());
        f.admit(1, 1).unwrap();
        assert!(!f.admission_accounting().clean());
        let page = f.allocate(FrameOwner::UserPage(1)).unwrap();
        let a = f.admission_accounting();
        assert_eq!((a.records, a.total, a.used, a.idle), (1, 1, 1, 0));
        assert!(a.consistent);
        assert!(!a.clean());
        f.reservations[0].used = 2;
        assert!(!f.admission_accounting().consistent);
        f.reservations[0].used = 1;
        f.idle_reserved = 1;
        assert!(!f.admission_accounting().consistent);
        f.idle_reserved = 0;
        f.free(page, FrameOwner::UserPage(1)).unwrap();
        f.retire_reservation(1).unwrap();
        assert!(f.admission_accounting().clean());
    }
    #[test]
    fn admitted_high_frames_preserve_fixed_wire_cap() {
        let base = 1u64 << 32;
        let mut f = FrameAllocator::with_base(base);
        f.add_usable(base, base + 8 * PAGE_SIZE);
        assert_eq!(f.admit(1, 65537), Err(AdmissionError::Invalid));
        f.admit(1, 8).unwrap();
        assert!(f.allocate(FrameOwner::UserPage(2)).is_none());
        let page = f.allocate(FrameOwner::UserPage(1)).unwrap();
        assert!(page.start_address() >= base);
        f.free(page, FrameOwner::UserPage(1)).unwrap();
        f.retire_reservation(1).unwrap();
        assert!(f.admission_accounting().clean());
    }
}
