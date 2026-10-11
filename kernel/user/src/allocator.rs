//! A small process-local allocator for `alloc` collections.
//!
//! It grows by asking the existing anonymous-map syscall for at most 64 pages
//! at a time. Freed allocations return to an address-ordered first-fit list;
//! adjacent regions coalesce. Whole mapped chunks intentionally remain owned
//! by the process until teardown, which already reclaims every user mapping.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::cmp::max;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use absd_abi::syscall::MAX_MAP_PAGES;

const PAGE_SIZE: usize = 4096;
const MIN_GROW_PAGES: usize = 4;

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
        if pages > MAX_MAP_PAGES as usize {
            return ptr::null_mut();
        }
        let Ok(region) = crate::map(pages as u64) else {
            return ptr::null_mut();
        };
        unsafe {
            guard.state().add_region(region as usize, pages * PAGE_SIZE);
            guard.state().take_first_fit(size, align)
        }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let Some((size, _)) = normalized_layout(layout) else {
            return;
        };
        let mut guard = self.lock();
        unsafe {
            guard.state().add_region(pointer as usize, size);
        }
    }
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
