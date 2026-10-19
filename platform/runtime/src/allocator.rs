//! A small process-local allocator for `alloc` collections.
//!
//! Page-sized allocations fitting one anonymous-map call own dedicated pages
//! and return them on deallocation. Other allocations use an address-ordered
//! first-fit list with coalescing; those pooled pages stay until teardown,
//! except that when a request for pages of its own finds no room in the
//! window, one free, page-aligned pooled run of at most 64 pages is unmapped
//! and the request retried once. A held block is never moved or unmapped,
//! and a request that still fails after the retry is refused as before.
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
// A class represents [2^class, 2^(class+1)). Cursors may skip only nodes
// smaller than its lower bound, never a node rejected just for alignment.
const FIT_CLASSES: usize = usize::BITS as usize;

// Host model only (R15): free-list nodes visited by every list walk, per
// test thread. Production builds the runtime with `test = false`.
#[cfg(test)]
std::thread_local! {
    pub(crate) static NODE_VISITS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[inline(always)]
fn count_visit() {
    #[cfg(test)]
    NODE_VISITS.with(|visits| visits.set(visits.get() + 1));
}

struct AllocatorState {
    head: *mut FreeNode,
    // A node on the list, or null. An insertion above it starts its
    // address-ordered walk there (R15): frees in ascending address order,
    // such as Lua's luaE_shrinkCI, then cost one step each instead of a walk
    // of the whole list.
    hint: *mut FreeNode,
    // Each entry is null or a LIVE predecessor: every node through it is
    // smaller than that class's lower bound. Allocation only shrinks/removes
    // free runs; insertion/coalescing resets all entries before mutation.
    fit_before: [*mut FreeNode; FIT_CLASSES],
}

impl AllocatorState {
    const fn new() -> Self {
        Self {
            head: ptr::null_mut(),
            hint: ptr::null_mut(),
            fit_before: [ptr::null_mut(); FIT_CLASSES],
        }
    }

    /// Inserts one suitably aligned region in address order, then joins it
    /// with its neighbors. The list is fully coalesced before and after each
    /// change, so only the new region's two neighbors can be adjacent to it.
    unsafe fn add_region(&mut self, address: usize, size: usize) {
        if size < MIN_BLOCK_SIZE || !address.is_multiple_of(MIN_BLOCK_SIZE) {
            return;
        }
        // A free or new mapping can introduce an earlier fit and coalescing
        // can retire either neighboring node. No cursor survives insertion.
        self.fit_before.fill(ptr::null_mut());
        let mut node = address as *mut FreeNode;
        let mut previous: *mut FreeNode = ptr::null_mut();
        let mut link = &mut self.head as *mut *mut FreeNode;
        unsafe {
            if !self.hint.is_null() && (self.hint as usize) < address {
                previous = self.hint;
                link = &mut (*self.hint).next;
            }
            while !(*link).is_null() && (*link as usize) < address {
                count_visit();
                previous = *link;
                link = &mut (**link).next;
            }
            let next = *link;
            node.write(FreeNode { size, next });
            *link = node;

            if !next.is_null()
                && address
                    .checked_add(size)
                    .is_some_and(|end| end == next as usize)
            {
                (*node).size += (*next).size;
                (*node).next = (*next).next;
            }
            if !previous.is_null()
                && (previous as usize)
                    .checked_add((*previous).size)
                    .is_some_and(|end| end == address)
            {
                (*previous).size += (*node).size;
                (*previous).next = (*node).next;
                node = previous;
            }
            self.hint = node;
        }
    }

    unsafe fn take_first_fit(&mut self, size: usize, align: usize) -> *mut u8 {
        debug_assert!(size >= MIN_BLOCK_SIZE);
        let class = (usize::BITS - 1 - size.leading_zeros()) as usize;
        let lower = 1usize << class;
        let mut link = &mut self.head as *mut *mut FreeNode;
        unsafe {
            let before = self.fit_before[class];
            if !before.is_null() {
                link = &mut (*before).next;
            }
            let mut small_prefix = true;
            while !(*link).is_null() {
                count_visit();
                let node = *link;
                if small_prefix && (*node).size < lower {
                    self.fit_before[class] = node;
                } else {
                    // A size/alignment miss here does not establish that
                    // every other request in this class would also miss.
                    small_prefix = false;
                }
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
                    // Split in place. The node was a whole free run of a
                    // fully coalesced list, so neither remainder touches
                    // another free node and both keep its place in address
                    // order. Remainders too small for a node are dropped,
                    // as add_region drops them.
                    let next = (*node).next;
                    let prefix = allocation_start - block_start;
                    let suffix = block_end - allocation_end;
                    let mut rest = next;
                    if suffix >= MIN_BLOCK_SIZE && allocation_end.is_multiple_of(MIN_BLOCK_SIZE) {
                        let tail = allocation_end as *mut FreeNode;
                        tail.write(FreeNode { size: suffix, next });
                        rest = tail;
                    }
                    if prefix >= MIN_BLOCK_SIZE {
                        (*node).size = prefix;
                        (*node).next = rest;
                    } else {
                        *link = rest;
                        // Other classes may name this node as their skipped
                        // predecessor. It is about to become caller memory
                        // (or be unmapped by R16), so retire those pointers.
                        for cursor in &mut self.fit_before {
                            if *cursor == node {
                                *cursor = ptr::null_mut();
                            }
                        }
                        if self.hint == node {
                            self.hint = ptr::null_mut();
                        }
                    }
                    return allocation_start as *mut u8;
                }
                link = &mut (*node).next;
            }
        }
        ptr::null_mut()
    }
}

#[cfg(test)]
impl MapAllocator {
    /// Host model only: calls `visit(address, size)` for each free-list node.
    pub(crate) fn for_each_free(&self, mut visit: impl FnMut(usize, usize)) {
        let mut guard = self.lock();
        let mut node = guard.state().head;
        while !node.is_null() {
            unsafe {
                visit(node as usize, (*node).size);
                node = (*node).next;
            }
        }
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

    /// Page-equivalents of reusable pooled bytes, summed before rounding.
    /// Includes free-node storage; excludes live blocks and dedicated maps.
    /// This is not a count of aligned reclaimable pages or a fit guarantee.
    /// Valid free nodes are disjoint within the bounded anonymous heap window,
    /// so their aggregate byte length fits usize. No allocation, syscall,
    /// logging or callback may occur while this guard protects node pointers.
    pub fn free_pooled_pages(&self) -> usize {
        let mut guard = self.lock();
        let mut node = guard.state().head;
        let mut bytes = 0usize;
        while !node.is_null() {
            // The allocator lock excludes list mutation and pool unmapping.
            unsafe {
                bytes += (*node).size;
                node = (*node).next;
            }
        }
        bytes / PAGE_SIZE
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
            let region = crate::map(pages as u64);
            if !region.is_null() {
                return region;
            }
            // The window may be full of free pooled pages (R16). Take one
            // page-aligned run of this size (at most 64 pages) out of a
            // single free-list node before unmapping it: held blocks are
            // never in the list, so none is moved or unmapped. Retry once;
            // the block still owns its entire map, so dealloc is unchanged.
            let run = unsafe { guard.state().take_first_fit(pages * PAGE_SIZE, PAGE_SIZE) };
            if run.is_null() {
                return ptr::null_mut();
            }
            // By construction this cannot fail: every pooled page came from
            // a successful map and is still mapped. Should the kernel refuse
            // anyway, the run is still mapped and free: return it to the
            // list and refuse the request.
            if !crate::try_unmap(run, pages as u64) {
                unsafe { guard.state().add_region(run as usize, pages * PAGE_SIZE) };
                return ptr::null_mut();
            }
            crate::heap_diag_pool_unmap(size, pages);
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

#[cfg(test)]
mod cursor_tests {
    use super::*;
    use std::alloc::{alloc_zeroed, dealloc};

    struct Region(*mut u8, Layout);
    impl Region {
        fn new(bytes: usize) -> Self {
            let layout = Layout::from_size_align(bytes, PAGE_SIZE).unwrap();
            let base = unsafe { alloc_zeroed(layout) };
            assert!(!base.is_null());
            Self(base, layout)
        }
        fn address(&self, offset: usize) -> usize {
            assert!(offset < self.1.size());
            self.0 as usize + offset
        }
    }
    impl Drop for Region {
        fn drop(&mut self) {
            unsafe { dealloc(self.0, self.1) }
        }
    }

    // Independent address-ordered oracle ignores the cursor table entirely.
    unsafe fn expected(state: &AllocatorState, size: usize, align: usize) -> *mut u8 {
        let mut node = state.head;
        while !node.is_null() {
            unsafe {
                let start = ((node as usize) + align - 1) & !(align - 1);
                if start + size <= node as usize + (*node).size {
                    return start as *mut u8;
                }
                node = (*node).next;
            }
        }
        ptr::null_mut()
    }

    unsafe fn invariants(state: &AllocatorState) {
        let mut nodes = Vec::new();
        let mut node = state.head;
        let mut end = 0;
        while !node.is_null() {
            unsafe {
                assert!(node as usize > end, "ordered, disjoint, fully coalesced");
                assert!((*node).size >= MIN_BLOCK_SIZE);
                end = node as usize + (*node).size;
                nodes.push((node, (*node).size));
                node = (*node).next;
            }
        }
        for (class, &cursor) in state.fit_before.iter().enumerate() {
            if cursor.is_null() {
                continue;
            }
            let index = nodes
                .iter()
                .position(|(p, _)| *p == cursor)
                .expect("live cursor");
            assert!(nodes[..=index].iter().all(|(_, n)| *n < (1usize << class)));
        }
    }

    #[test]
    fn size_class_cursor_skips_repeated_small_prefix() {
        let region = Region::new(32768);
        let mut state = AllocatorState::new();
        unsafe {
            for i in 0..128 {
                state.add_region(region.address(i * 32), 16);
            }
            state.add_region(region.address(8192), 8192);
            NODE_VISITS.with(|v| v.set(0));
            for i in 0..128 {
                assert_eq!(
                    state.take_first_fit(64, 16) as usize,
                    region.address(8192 + i * 64)
                );
                invariants(&state);
            }
            let visits = NODE_VISITS.with(|v| v.get());
            // Exactly one walk over the 128-node prefix, then one candidate
            // per request. The original head scan takes 128*129 visits.
            assert_eq!(visits, 256);
        }
    }

    #[test]
    fn cursor_does_not_skip_smaller_request_in_same_class_or_alignment_fit() {
        let region = Region::new(4096);
        let mut state = AllocatorState::new();
        unsafe {
            state.add_region(region.address(16), 96);
            state.add_region(region.address(256), 256);
            // 112 and 64 share class6; the first run must remain eligible.
            assert_eq!(state.take_first_fit(112, 16) as usize, region.address(256));
            assert_eq!(state.take_first_fit(64, 16) as usize, region.address(16));
            invariants(&state);
        }
        let mut state = AllocatorState::new();
        unsafe {
            state.add_region(region.address(16), 64);
            state.add_region(region.address(256), 64);
            assert_eq!(state.take_first_fit(64, 256) as usize, region.address(256));
            assert_eq!(state.take_first_fit(64, 16) as usize, region.address(16));
            invariants(&state);
        }
    }

    #[test]
    fn freeing_and_coalescing_restore_earlier_first_fit() {
        let region = Region::new(4096);
        let mut state = AllocatorState::new();
        unsafe {
            state.add_region(region.address(0), 32);
            state.add_region(region.address(256), 256);
            assert_eq!(state.take_first_fit(64, 16) as usize, region.address(256));
            state.add_region(region.address(32), 32);
            assert_eq!(state.take_first_fit(64, 16) as usize, region.address(0));
            invariants(&state);
        }
    }

    #[test]
    fn removal_invalidates_other_class_cursor_before_caller_reuses_node() {
        let region = Region::new(4096);
        let mut state = AllocatorState::new();
        unsafe {
            state.add_region(region.address(0), 16);
            state.add_region(region.address(64), 64);
            assert!(state.take_first_fit(128, 16).is_null());
            assert_eq!(state.fit_before[7] as usize, region.address(64));
            let p = state.take_first_fit(64, 16);
            assert_eq!(p as usize, region.address(64));
            ptr::write_bytes(p, 0xa5, 64);
            invariants(&state);
            assert!(state.take_first_fit(128, 16).is_null());
            assert_eq!(state.take_first_fit(16, 16) as usize, region.address(0));
            invariants(&state);
        }
    }

    #[test]
    fn mixed_classes_splits_frees_and_refusals_match_head_scan() {
        let region = Region::new(65536);
        let mut state = AllocatorState::new();
        let mut held = Vec::new();
        let mut random = 0x72u32;
        unsafe {
            state.add_region(region.address(0), 65536);
            for round in 0..4000 {
                random = random.wrapping_mul(1664525).wrapping_add(1013904223);
                if !held.is_empty() && (random & 3 == 0 || held.len() > 100) {
                    let index = random as usize % held.len();
                    let (pointer, size) = held.swap_remove(index);
                    state.add_region(pointer as usize, size);
                } else {
                    let size = [16, 32, 48, 64, 96, 112, 128, 256, 512, 4096][random as usize % 10];
                    let align = 16usize << ((random >> 8) % 5);
                    let want = expected(&state, size, align);
                    let got = state.take_first_fit(size, align);
                    assert_eq!(got, want, "head-first fit at round {round}");
                    if !got.is_null() {
                        ptr::write_bytes(got, (round & 255) as u8, size);
                        held.push((got, size));
                    }
                }
                invariants(&state);
            }
            for (pointer, size) in held {
                state.add_region(pointer as usize, size);
            }
            invariants(&state);
            assert_eq!(state.head as usize, region.address(0));
            assert_eq!((*state.head).size, 65536);
            assert!((*state.head).next.is_null());
        }
    }
}
