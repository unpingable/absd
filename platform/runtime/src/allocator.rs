//! A small process-local allocator for `alloc` collections.
//!
//! Page-sized allocations fitting one anonymous-map call own dedicated pages
//! and return them on deallocation. Other allocations use an address-ordered
//! first-fit list with coalescing; those pooled pages stay until teardown.
//! Larger pooled requests map bounded chunks and check actual contiguous fit.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::cmp::max;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

const PAGE_SIZE: usize = 4096;
const MIN_GROW_PAGES: usize = 4;
const MAX_MAP_PAGES: usize = 64;
// Current syscall ABI heap window (abi/src/layout.rs): 32 MiB. This bounds
// one pooled growth attempt; partial successful maps remain reusable.
const MAX_GROW_PAGES: usize = 8192;

#[repr(C)]
struct FreeNode {
    size: usize,
    next: *mut FreeNode,
}

const MIN_BLOCK_SIZE: usize = size_of::<FreeNode>();

struct AllocatorState {
    head: *mut FreeNode,
}

impl AllocatorState {
    const fn new() -> Self {
        Self {
            head: ptr::null_mut(),
        }
    }

    /// Inserts one suitably aligned region, then joins adjacent neighbors.
    unsafe fn add_region(&mut self, address: usize, size: usize) {
        if size < MIN_BLOCK_SIZE || !address.is_multiple_of(MIN_BLOCK_SIZE) {
            return;
        }
        let node = address as *mut FreeNode;
        let mut link = &mut self.head as *mut *mut FreeNode;
        unsafe {
            while !(*link).is_null() && (*link as usize) < address {
                link = &mut (**link).next;
            }
            node.write(FreeNode { size, next: *link });
            *link = node;

            let mut current = self.head;
            while !current.is_null() {
                let next = (*current).next;
                if !next.is_null()
                    && (current as usize)
                        .checked_add((*current).size)
                        .is_some_and(|end| end == next as usize)
                {
                    (*current).size += (*next).size;
                    (*current).next = (*next).next;
                } else {
                    current = next;
                }
            }
        }
    }

    unsafe fn take_first_fit(&mut self, size: usize, align: usize) -> *mut u8 {
        let mut link = &mut self.head as *mut *mut FreeNode;
        unsafe {
            while !(*link).is_null() {
                let node = *link;
                let block_start = node as usize;
                let Some(block_end) = block_start.checked_add((*node).size) else {
                    return ptr::null_mut();
                };
                let Some(allocation_start) = align_up(block_start, align) else {
                    return ptr::null_mut();
                };
                let Some(allocation_end) = allocation_start.checked_add(size) else {
                    return ptr::null_mut();
                };
                if allocation_end <= block_end {
                    let next = (*node).next;
                    *link = next;
                    let prefix = allocation_start - block_start;
                    let suffix = block_end - allocation_end;
                    if prefix != 0 {
                        self.add_region(block_start, prefix);
                    }
                    if suffix != 0 {
                        self.add_region(allocation_end, suffix);
                    }
                    return allocation_start as *mut u8;
                }
                link = &mut (*node).next;
            }
        }
        ptr::null_mut()
    }
}

/// A reusable `no_std` global allocator backed by ABSD anonymous mappings.
pub struct MapAllocator {
    locked: AtomicBool,
    state: UnsafeCell<AllocatorState>,
}

// ABSD currently has one userspace execution thread per process. The lock
// still makes allocator state coherent across preemption and future callers.
unsafe impl Sync for MapAllocator {}

impl MapAllocator {
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            state: UnsafeCell::new(AllocatorState::new()),
        }
    }

    fn lock(&self) -> AllocatorGuard<'_> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        AllocatorGuard { allocator: self }
    }
}

impl Default for MapAllocator {
    fn default() -> Self {
        Self::new()
    }
}

struct AllocatorGuard<'a> {
    allocator: &'a MapAllocator,
}

impl AllocatorGuard<'_> {
    fn state(&mut self) -> &mut AllocatorState {
        unsafe { &mut *self.allocator.state.get() }
    }
}

impl Drop for AllocatorGuard<'_> {
    fn drop(&mut self) {
        self.allocator.locked.store(false, Ordering::Release);
    }
}

unsafe impl GlobalAlloc for MapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let Some((size, align)) = normalized_layout(layout) else {
            return ptr::null_mut();
        };
        let mut guard = self.lock();
        // Classification precedes any pool lookup: dealloc receives only the
        // original Layout, so an eligible pointer must own its entire map.
        if let Some(pages) = dedicated_pages(size, align) {
            crate::heap_diag(size, pages);
            return crate::map(pages as u64);
        }
        let available = unsafe { guard.state().take_first_fit(size, align) };
        if !available.is_null() {
            return available;
        }

        // One syscall remains bounded even for unusually aligned layouts.
        let Some(required) = size.checked_add(align - 1) else {
            return ptr::null_mut();
        };
        let Some(rounded) = required.checked_add(PAGE_SIZE - 1) else {
            return ptr::null_mut();
        };
        let pages = max(rounded / PAGE_SIZE, MIN_GROW_PAGES);
        crate::heap_diag(size, pages);
        if pages <= MAX_MAP_PAGES {
            let region = crate::map(pages as u64);
            if region.is_null() {
                return ptr::null_mut();
            }
            unsafe {
                guard.state().add_region(region as usize, pages * PAGE_SIZE);
                return guard.state().take_first_fit(size, align);
            }
        }
        // Returned dedicated maps leave holes. The nominal number of mapped
        // pages does not prove a contiguous fit: check after every chunk.
        // Keep the original remaining-request chunk sizes; once that total is
        // reached, fill one page at a time until fit or bounded refusal.
        // Successful maps make monotonic progress while this lock is held;
        // failed attempts strictly lower the chunk cap, ending at one page.
        let mut mapped = 0usize;
        let mut chunk_cap = MAX_MAP_PAGES;
        while mapped < MAX_GROW_PAGES {
            let chunk = pages
                .saturating_sub(mapped)
                .max(1)
                .min(chunk_cap)
                .min(MAX_GROW_PAGES - mapped);
            let region = crate::map(chunk as u64);
            if region.is_null() {
                if chunk == 1 {
                    return ptr::null_mut();
                }
                chunk_cap = chunk / 2;
                continue;
            }
            unsafe { guard.state().add_region(region as usize, chunk * PAGE_SIZE) };
            mapped += chunk;
            let available = unsafe { guard.state().take_first_fit(size, align) };
            if !available.is_null() {
                return available;
            }
        }
        ptr::null_mut()
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let Some((size, align)) = normalized_layout(layout) else {
            return;
        };
        let mut guard = self.lock();
        if let Some(pages) = dedicated_pages(size, align) {
            crate::unmap(pointer, pages as u64);
            return;
        }
        unsafe {
            guard.state().add_region(pointer as usize, size);
        }
    }
}

fn dedicated_pages(size: usize, align: usize) -> Option<usize> {
    if size < PAGE_SIZE || align > PAGE_SIZE {
        return None;
    }
    let pages = size.checked_add(PAGE_SIZE - 1)? / PAGE_SIZE;
    (pages <= MAX_MAP_PAGES).then_some(pages)
}

fn normalized_layout(layout: Layout) -> Option<(usize, usize)> {
    // A 16-byte minimum makes every prefix and suffix large enough to hold a
    // free-list node, so splitting never loses alignment slivers.
    let align = max(layout.align(), MIN_BLOCK_SIZE);
    let size = max(layout.size(), MIN_BLOCK_SIZE);
    Some((align_up(size, MIN_BLOCK_SIZE)?, align))
}

fn align_up(value: usize, align: usize) -> Option<usize> {
    value.checked_add(align - 1).map(|sum| sum & !(align - 1))
}
