//! #115: runs the actual x86 VM source (`src/vm.rs`) over an owned host arena
//! for whichever layout this build selects (default, or the
//! `builder-large-envelope` 3 GiB region). Identity-mapped physical memory is
//! substituted by aligned host memory; no CR3, TLB or hardware claim follows.
//! The heap-hint rule is mirrored from `syscall_map`/`syscall_unmap` and
//! checked against an exhaustive lowest-run search.
use absd_kernel::frame_geometry::MAX_LEAF_TABLES;
use absd_kernel::layout::{
    USER_DIRECTORIES, USER_HEAP_BASE, USER_HEAP_END, USER_LEAVES, USER_REGION_BASE, USER_REGION_END,
};
use absd_kernel::memory::{FrameAllocator, PAGE_SIZE};
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ptr::NonNull;

mod kernel_lock {
    pub fn assert_current_owner() {
        panic!("global allocator is outside this serial host fixture");
    }
}
#[allow(dead_code)]
#[path = "../src/vm.rs"]
mod vm;

struct Arena {
    ptr: NonNull<u8>,
    layout: Layout,
}
impl Arena {
    fn new(pages: usize) -> Self {
        let layout =
            Layout::from_size_align(pages * PAGE_SIZE as usize, PAGE_SIZE as usize).unwrap();
        let ptr = NonNull::new(unsafe { alloc_zeroed(layout) }).expect("host arena allocation");
        Self { ptr, layout }
    }
    fn pool(&self) -> FrameAllocator {
        let start = self.ptr.as_ptr() as u64;
        assert_eq!(start & !vm::ADDRESS_MASK, 0);
        let mut f = FrameAllocator::with_base(start);
        f.add_usable(start, start + self.layout.size() as u64);
        f
    }
}
impl Drop for Arena {
    fn drop(&mut self) {
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) }
    }
}

/// Small deterministic generator; no external crates in this fixture.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn main() {
    unsafe {
        bounds_and_lazy_directories();
        leaf_cap_and_teardown();
        isolation();
        run_search_matches_exhaustive();
        dense_leaves_match_exhaustive();
        heap_hint_matches_lowest_run();
    }
    println!(
        "LARGE ENVELOPE VM OK directories={USER_DIRECTORIES} leaves={USER_LEAVES} max_leaf_tables={MAX_LEAF_TABLES} heap_pages={}",
        (USER_HEAP_END - USER_HEAP_BASE) / PAGE_SIZE
    );
}

unsafe fn bounds_and_lazy_directories() {
    let arena = Arena::new(64);
    let mut f = arena.pool();
    let free = f.free_frames();
    let mut space = unsafe { vm::create(&mut f, 1, 0) }.unwrap();
    // Root, PDPT and directory 0 only.
    assert_eq!(free - f.free_frames(), 3);
    assert_eq!(space.directories.iter().filter(|&&d| d != 0).count(), 1);
    for bad in [
        USER_REGION_BASE - PAGE_SIZE,
        USER_REGION_END,
        USER_REGION_END + PAGE_SIZE,
        USER_HEAP_BASE + 1,
        0,
    ] {
        assert_eq!(
            unsafe { vm::map_user_page(&mut f, &mut space, 1, bad, true, false) },
            Err(vm::MapError::BadAddress),
            "{bad:#x}"
        );
    }
    // The first and last page of every directory map, creating it on demand.
    for d in 0..USER_DIRECTORIES as u64 {
        for address in [
            USER_REGION_BASE + (d << 30),
            USER_REGION_BASE + ((d + 1) << 30) - PAGE_SIZE,
        ] {
            let before = f.free_frames();
            let frame =
                unsafe { vm::map_user_page(&mut f, &mut space, 1, address, true, false) }.unwrap();
            assert!(unsafe { vm::is_mapped(&space, address) });
            assert_eq!(
                unsafe { vm::translate(&space, address + 8) },
                Some(frame + 8)
            );
            assert!(before - f.free_frames() >= 2);
            assert_eq!(
                unsafe { vm::map_user_page(&mut f, &mut space, 1, address, true, false) },
                Err(vm::MapError::AlreadyMapped)
            );
        }
        assert_ne!(space.directories[d as usize], 0);
    }
    unsafe { vm::unmap_user_page(&mut f, &mut space, 1, USER_REGION_BASE) }.unwrap();
    assert!(unsafe { vm::unmap_user_page(&mut f, &mut space, 1, USER_REGION_BASE) }.is_err());
    assert!(unsafe { vm::unmap_user_page(&mut f, &mut space, 1, USER_REGION_END) }.is_err());
    unsafe { vm::destroy(&mut f, &mut space, 1) }.unwrap();
    assert_eq!(f.free_frames(), free);
    assert_eq!(space, absd_kernel::process::AddressSpace::EMPTY);
}

unsafe fn leaf_cap_and_teardown() {
    let arena = Arena::new(2 * MAX_LEAF_TABLES + USER_DIRECTORIES + 16);
    let mut f = arena.pool();
    let free = f.free_frames();
    let mut space = unsafe { vm::create(&mut f, 2, 0) }.unwrap();
    // One page in each of MAX_LEAF_TABLES distinct leaves, spread across the
    // whole region, then a new leaf is refused but an owned leaf still maps.
    let stride = (USER_LEAVES / MAX_LEAF_TABLES).max(1) as u64;
    let mut leaves = Vec::new();
    let mut leaf = 0u64;
    while leaves.len() < MAX_LEAF_TABLES {
        let address = USER_REGION_BASE + (leaf << 21);
        unsafe { vm::map_user_page(&mut f, &mut space, 2, address, true, false) }.unwrap();
        leaves.push(leaf);
        leaf = (leaf + stride) % USER_LEAVES as u64;
        if leaves.contains(&leaf) {
            leaf = (0..USER_LEAVES as u64)
                .find(|l| !leaves.contains(l))
                .unwrap();
        }
    }
    assert_eq!(space.tables, MAX_LEAF_TABLES);
    let fresh = (0..USER_LEAVES as u64).find(|l| !leaves.contains(l));
    if let Some(fresh) = fresh {
        let held = f.free_frames();
        assert_eq!(
            unsafe {
                vm::map_user_page(
                    &mut f,
                    &mut space,
                    2,
                    USER_REGION_BASE + (fresh << 21),
                    true,
                    false,
                )
            },
            Err(vm::MapError::NoMemory)
        );
        assert_eq!(f.free_frames(), held, "a refused leaf allocates nothing");
    }
    let owned = USER_REGION_BASE + (leaves[0] << 21) + PAGE_SIZE;
    unsafe { vm::map_user_page(&mut f, &mut space, 2, owned, true, false) }.unwrap();
    let used = free - f.free_frames();
    let released = unsafe { vm::destroy(&mut f, &mut space, 2) }.unwrap();
    assert_eq!(released, used);
    assert_eq!(f.free_frames(), free);
}

unsafe fn isolation() {
    let arena = Arena::new(64);
    let mut f = arena.pool();
    let free = f.free_frames();
    let mut a = unsafe { vm::create(&mut f, 3, 0) }.unwrap();
    let mut b = unsafe { vm::create(&mut f, 4, 0) }.unwrap();
    let address = USER_HEAP_END - PAGE_SIZE;
    let pa = unsafe { vm::map_user_page(&mut f, &mut a, 3, address, true, false) }.unwrap();
    assert!(!unsafe { vm::is_mapped(&b, address) });
    let pb = unsafe { vm::map_user_page(&mut f, &mut b, 4, address, true, false) }.unwrap();
    assert_ne!(pa, pb);
    assert_ne!(a.directories, b.directories);
    // Freeing pid 3's frame as pid 4 must be refused by ownership tags.
    assert!(unsafe { vm::unmap_user_page(&mut f, &mut a, 4, address) }.is_err());
    unsafe { vm::unmap_user_page(&mut f, &mut a, 3, address) }.unwrap();
    assert_eq!(unsafe { vm::translate(&b, address) }, Some(pb));
    unsafe { vm::destroy(&mut f, &mut a, 3) }.unwrap();
    unsafe { vm::destroy(&mut f, &mut b, 4) }.unwrap();
    assert_eq!(f.free_frames(), free);
}

unsafe fn exhaustive_run(
    space: &absd_kernel::process::AddressSpace,
    base: u64,
    end: u64,
    count: u64,
) -> Option<u64> {
    let mut page = base;
    while page + count * PAGE_SIZE <= end {
        if (0..count).all(|i| !unsafe { vm::is_mapped(space, page + i * PAGE_SIZE) }) {
            return Some(page);
        }
        page += PAGE_SIZE;
    }
    None
}

unsafe fn run_search_matches_exhaustive() {
    let arena = Arena::new(4096);
    let mut f = arena.pool();
    let mut space = unsafe { vm::create(&mut f, 5, 0) }.unwrap();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    // A sparse pattern over the first 8 MiB of the heap plus its last leaf.
    let window = 2048u64;
    for _ in 0..600 {
        let page = rng.next() % window;
        let address = USER_HEAP_BASE + page * PAGE_SIZE;
        let _ = unsafe { vm::map_user_page(&mut f, &mut space, 5, address, true, false) };
    }
    let tail = USER_HEAP_END - (1 << 21);
    for i in (0..512).step_by(3) {
        unsafe { vm::map_user_page(&mut f, &mut space, 5, tail + i * PAGE_SIZE, true, false) }
            .unwrap();
    }
    for _ in 0..400 {
        let start = USER_HEAP_BASE + (rng.next() % (window + 64)) * PAGE_SIZE;
        let count = rng.next() % 70 + 1;
        let end = (start + (rng.next() % 600 + count) * PAGE_SIZE).min(USER_HEAP_END);
        assert_eq!(
            unsafe { vm::find_unmapped_run(&space, start, end, count) },
            unsafe { exhaustive_run(&space, start, end, count) },
            "start={start:#x} end={end:#x} count={count}"
        );
    }
    for count in [1, 2, 64] {
        assert_eq!(
            unsafe { vm::find_unmapped_run(&space, tail, USER_HEAP_END, count) },
            unsafe { exhaustive_run(&space, tail, USER_HEAP_END, count) }
        );
    }
    unsafe { vm::destroy(&mut f, &mut space, 5) }.unwrap();
}

/// Every leaf's stored present count equals its actually mapped pages.
unsafe fn assert_leaf_counts(space: &absd_kernel::process::AddressSpace, from: u64, leaves: u64) {
    for leaf in 0..leaves {
        let start = from + (leaf << 21);
        let mapped = (0..512)
            .filter(|i| unsafe { vm::is_mapped(space, start + i * PAGE_SIZE) })
            .count();
        assert_eq!(
            unsafe { vm::leaf_mapped(space, start) },
            mapped as u64,
            "leaf {start:#x}"
        );
    }
}

/// Nearly full leaves (0-80 holes each, free runs straddling leaf
/// boundaries) exercise the skip of leaves with too few free pages; the
/// search must still return the exhaustive lowest run after maps and unmaps.
unsafe fn dense_leaves_match_exhaustive() {
    const LEAVES: u64 = 8;
    let arena = Arena::new(LEAVES as usize * 512 + 64);
    let mut f = arena.pool();
    let mut space = unsafe { vm::create(&mut f, 9, 0) }.unwrap();
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for leaf in 0..LEAVES {
        let holes = rng.next() % 81;
        let mut free = [false; 512];
        for _ in 0..holes {
            free[(rng.next() % 512) as usize] = true;
        }
        // Some leaves end or begin with a free run that meets a neighbour's.
        match leaf % 4 {
            1 => free[512 - 20..].fill(true),
            2 => free[..30].fill(true),
            _ => {}
        }
        for (i, &hole) in free.iter().enumerate() {
            if !hole {
                let address = USER_HEAP_BASE + (leaf << 21) + i as u64 * PAGE_SIZE;
                unsafe { vm::map_user_page(&mut f, &mut space, 9, address, true, false) }.unwrap();
            }
        }
    }
    let end = USER_HEAP_BASE + (LEAVES << 21);
    for round in 0..6 {
        unsafe { assert_leaf_counts(&space, USER_HEAP_BASE, LEAVES) };
        for _ in 0..500 {
            let start = USER_HEAP_BASE + (rng.next() % (LEAVES * 512)) * PAGE_SIZE;
            let count = rng.next() % 64 + 1;
            assert_eq!(
                unsafe { vm::find_unmapped_run(&space, start, end, count) },
                unsafe { exhaustive_run(&space, start, end, count) },
                "round={round} start={start:#x} count={count}"
            );
        }
        // Unmap a few pages to change the pattern between rounds.
        for _ in 0..40 {
            let address = USER_HEAP_BASE + (rng.next() % (LEAVES * 512)) * PAGE_SIZE;
            if unsafe { vm::is_mapped(&space, address) } {
                unsafe { vm::unmap_user_page(&mut f, &mut space, 9, address) }.unwrap();
            }
        }
    }
    unsafe { vm::destroy(&mut f, &mut space, 9) }.unwrap();
    unsafe { skipping_bounds_entry_reads() };
    unsafe { exact_free_count_boundaries() };
}

/// Review A-2: leaves with fewer free pages than a 64-page run must be
/// skipped, not read entry by entry. Only measurable with `vm-read-count`.
#[cfg(feature = "vm-read-count")]
unsafe fn skipping_bounds_entry_reads() {
    use std::sync::atomic::Ordering;
    const LEAVES: u64 = 8;
    let arena = Arena::new(LEAVES as usize * 512 + 64);
    let mut f = arena.pool();
    let mut space = unsafe { vm::create(&mut f, 11, 0) }.unwrap();
    // Every eighth page free: 64 holes per leaf would allow no 64-run, and
    // one fewer keeps each leaf under the skip threshold.
    for page in 0..LEAVES * 512 {
        if page % 8 != 3 || page % 512 == 3 {
            let address = USER_HEAP_BASE + page * PAGE_SIZE;
            unsafe { vm::map_user_page(&mut f, &mut space, 11, address, true, false) }.unwrap();
        }
    }
    let end = USER_HEAP_BASE + (LEAVES << 21);
    let before = vm::ENTRY_READS.load(Ordering::Relaxed);
    assert_eq!(
        unsafe { vm::find_unmapped_run(&space, USER_HEAP_BASE, end, 64) },
        None
    );
    let reads = vm::ENTRY_READS.load(Ordering::Relaxed) - before;
    // A page-by-page search reads at least one entry per page (4,096).
    assert!(reads < 64, "{reads} entry reads for {} pages", LEAVES * 512);
    unsafe { vm::destroy(&mut f, &mut space, 11) }.unwrap();
}
#[cfg(not(feature = "vm-read-count"))]
unsafe fn skipping_bounds_entry_reads() {}

/// A leaf whose free pages exactly equal what the run still needs must be
/// read, alone and when the run is carried in from the previous leaf.
unsafe fn exact_free_count_boundaries() {
    let arena = Arena::new(3 * 512 + 64);
    let mut f = arena.pool();
    let mut space = unsafe { vm::create(&mut f, 10, 0) }.unwrap();
    let leaf = |n: u64| USER_HEAP_BASE + (n << 21);
    // Leaf 0: last 10 pages free. Leaf 1: first 20 free. Leaf 2: pages
    // 100..120 free (exactly 20, contiguous, mid-leaf).
    for (n, free) in [(0u64, 502..512), (1, 0..20), (2, 100..120)] {
        for i in 0..512u64 {
            if !free.contains(&i) {
                unsafe {
                    vm::map_user_page(&mut f, &mut space, 10, leaf(n) + i * PAGE_SIZE, true, false)
                }
                .unwrap();
            }
        }
    }
    let end = leaf(3);
    for (start, count, expected) in [
        (leaf(0), 30, Some(leaf(0) + 502 * PAGE_SIZE)),
        (
            leaf(1) + 20 * PAGE_SIZE,
            20,
            Some(leaf(2) + 100 * PAGE_SIZE),
        ),
        (leaf(0), 31, None),
    ] {
        assert_eq!(
            unsafe { vm::find_unmapped_run(&space, start, end, count) },
            expected
        );
        assert_eq!(
            unsafe { exhaustive_run(&space, start, end, count) },
            expected
        );
    }
    // Review A-1 and integration: unaligned bounds or a zero count are
    // refused in every build (they used to spin, then returned junk).
    assert_eq!(
        unsafe { vm::find_unmapped_run(&space, leaf(2) + 0x800, end, 21) },
        None
    );
    assert_eq!(
        unsafe { vm::find_unmapped_run(&space, leaf(0) + 0x800, end, 10) },
        None
    );
    assert_eq!(
        unsafe { vm::find_unmapped_run(&space, leaf(2), leaf(2) + 300 * PAGE_SIZE + 0x800, 21) },
        None
    );
    assert_eq!(
        unsafe { vm::find_unmapped_run(&space, leaf(0), end, 0) },
        None
    );
    // Integration review L-3: bounds outside the user region are refused.
    assert_eq!(
        unsafe { vm::find_unmapped_run(&space, USER_REGION_BASE - PAGE_SIZE, end, 1) },
        None
    );
    assert_eq!(
        unsafe {
            vm::find_unmapped_run(
                &space,
                USER_REGION_END - PAGE_SIZE,
                USER_REGION_END + PAGE_SIZE,
                1,
            )
        },
        None
    );
    unsafe { vm::destroy(&mut f, &mut space, 10) }.unwrap();
}

/// Mirrors syscall_map/syscall_unmap: search from max(hint, base); advance the
/// hint only when the run started at the search start; lower it on unmap.
unsafe fn heap_hint_matches_lowest_run() {
    let arena = Arena::new(4096);
    let mut f = arena.pool();
    let mut space = unsafe { vm::create(&mut f, 6, 0) }.unwrap();
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let mut held: Vec<(u64, u64)> = Vec::new();
    let mut mapped_pages = 0u64;
    for _ in 0..3000 {
        if held.is_empty() || (!rng.next().is_multiple_of(3) && mapped_pages < 3000) {
            let pages = rng.next() % 64 + 1;
            let start = space.heap_hint.max(USER_HEAP_BASE);
            let hinted = unsafe { vm::find_unmapped_run(&space, start, USER_HEAP_END, pages) };
            let lowest =
                unsafe { vm::find_unmapped_run(&space, USER_HEAP_BASE, USER_HEAP_END, pages) };
            assert_eq!(hinted, lowest, "hint {:#x} pages {pages}", space.heap_hint);
            let base = hinted.unwrap();
            for i in 0..pages {
                unsafe {
                    vm::map_user_page(&mut f, &mut space, 6, base + i * PAGE_SIZE, true, false)
                }
                .unwrap();
            }
            if base == start {
                space.heap_hint = base + pages * PAGE_SIZE;
            }
            held.push((base, pages));
            mapped_pages += pages;
        } else {
            let (base, pages) = held.swap_remove((rng.next() as usize) % held.len());
            for i in 0..pages {
                unsafe { vm::unmap_user_page(&mut f, &mut space, 6, base + i * PAGE_SIZE) }
                    .unwrap();
            }
            if base < space.heap_hint {
                space.heap_hint = base;
            }
            mapped_pages -= pages;
        }
        let hint = space.heap_hint.max(USER_HEAP_BASE);
        let mut page = USER_HEAP_BASE;
        while page < hint {
            assert!(
                unsafe { vm::is_mapped(&space, page) },
                "unmapped {page:#x} below hint {hint:#x}"
            );
            page += PAGE_SIZE;
        }
    }
    unsafe { vm::destroy(&mut f, &mut space, 6) }.unwrap();
}
