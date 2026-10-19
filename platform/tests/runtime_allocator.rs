//! Owned-page return and one concrete contiguous-growth regression using
//! the production allocator. The host global allocator is unchanged.
//! The local bitmap implements the kernel's lowest-free-run map contract;
//! unmap validates the whole range before changing it. Page tables/TLBs and
//! the production runtime syscall/accounting wrapper are not host-modeled.

use std::alloc::{GlobalAlloc, Layout, alloc_zeroed, dealloc, handle_alloc_error};
use std::cell::RefCell;
use std::io::Write;
use std::ptr;

#[path = "../runtime/src/allocator.rs"]
mod allocator;

const PAGE: usize = 4096;

struct Arena {
    pointer: *mut u8,
    layout: Layout,
    used: Vec<bool>,
    requests: Vec<usize>,
    accounted_pages: usize,
    frame_limit: usize,
    unmaps: usize,
    refuse_unmap: bool,
    refuse_pool_unmap: bool,
    pool_unmaps: Vec<usize>,
    scan_pages: usize,
}

impl Arena {
    fn new(pages: usize) -> Self {
        let layout = Layout::from_size_align(pages * PAGE, 2 * PAGE).unwrap();
        let pointer = unsafe { alloc_zeroed(layout) };
        if pointer.is_null() {
            handle_alloc_error(layout);
        }
        Self {
            pointer,
            layout,
            used: vec![false; pages],
            requests: Vec::new(),
            accounted_pages: 0,
            frame_limit: pages,
            unmaps: 0,
            refuse_unmap: false,
            refuse_pool_unmap: false,
            pool_unmaps: Vec::new(),
            scan_pages: 0,
        }
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        unsafe { dealloc(self.pointer, self.layout) };
    }
}

thread_local! {
    static ARENA: RefCell<Option<Arena>> = const { RefCell::new(None) };
}

struct LocalMaps;

impl LocalMaps {
    fn new(pages: usize) -> Self {
        let arena = Arena::new(pages);
        ARENA.with(|state| {
            let mut state = state.borrow_mut();
            assert!(state.is_none(), "one arena per test thread");
            *state = Some(arena);
        });
        Self
    }

    fn counts(&self) -> (usize, usize, usize) {
        ARENA.with(|state| {
            let state = state.borrow();
            let arena = state.as_ref().unwrap();
            assert_eq!(
                arena.accounted_pages,
                arena.used.iter().filter(|&&p| p).count()
            );
            (arena.accounted_pages, arena.requests.len(), arena.unmaps)
        })
    }

    fn refuse_pool_unmap(&self) {
        ARENA.with(|state| state.borrow_mut().as_mut().unwrap().refuse_pool_unmap = true);
    }

    /// Review N1: every free-list byte must lie on a mapped page. Unmapped
    /// pages are poisoned, so a node left on an unmapped run would also be
    /// visibly corrupt.
    fn assert_free_list_mapped(&self, allocator: &allocator::MapAllocator) -> usize {
        let mut free = 0;
        ARENA.with(|state| {
            let state = state.borrow();
            let arena = state.as_ref().unwrap();
            allocator.for_each_free(|address, size| {
                let offset = address - arena.pointer as usize;
                let first = offset / PAGE;
                let end = (offset + size).div_ceil(PAGE);
                assert!(
                    arena.used[first..end].iter().all(|&p| p),
                    "free-list bytes {address:#x}+{size} on an unmapped page"
                );
                free += size;
            });
        });
        free
    }

    fn scan_pages(&self) -> usize {
        ARENA.with(|state| state.borrow().as_ref().unwrap().scan_pages)
    }

    fn pool_unmaps(&self) -> Vec<usize> {
        ARENA.with(|state| state.borrow().as_ref().unwrap().pool_unmaps.clone())
    }

    fn base(&self) -> *mut u8 {
        ARENA.with(|state| state.borrow().as_ref().unwrap().pointer)
    }

    fn frame_limit(&self, pages: usize) {
        ARENA.with(|state| state.borrow_mut().as_mut().unwrap().frame_limit = pages);
    }

    fn refuse_unmap(&self) {
        ARENA.with(|state| state.borrow_mut().as_mut().unwrap().refuse_unmap = true);
    }

    fn valid_requests(&self) -> bool {
        ARENA.with(|state| {
            state
                .borrow()
                .as_ref()
                .unwrap()
                .requests
                .iter()
                .all(|&p| (1..=64).contains(&p))
        })
    }
}

impl Drop for LocalMaps {
    fn drop(&mut self) {
        // Drop the host-owned storage after releasing the RefCell borrow.
        let arena = ARENA.with(|state| state.borrow_mut().take());
        drop(arena);
    }
}

fn map(pages: u64) -> *mut u8 {
    let Ok(pages) = usize::try_from(pages) else {
        return ptr::null_mut();
    };
    ARENA.with(|state| {
        let mut state = state.borrow_mut();
        let arena = state.as_mut().expect("map requires local arena");
        arena.requests.push(pages);
        if pages == 0
            || pages > 64
            || pages > arena.used.len()
            || arena
                .accounted_pages
                .checked_add(pages)
                .is_none_or(|n| n > arena.frame_limit)
        {
            return ptr::null_mut();
        }
        let Some(first) = arena
            .used
            .windows(pages)
            .position(|run| run.iter().all(|&p| !p))
        else {
            arena.scan_pages += arena.used.len();
            return ptr::null_mut();
        };
        // The kernel's find_unmapped_run examines every page up to the end
        // of the lowest free run (vm.rs find_unmapped_run).
        arena.scan_pages += first + pages;
        let pointer = unsafe { arena.pointer.add(first * PAGE) };
        unsafe { ptr::write_bytes(pointer, 0, pages * PAGE) };
        arena.used[first..first + pages].fill(true);
        arena.accounted_pages += pages;
        pointer
    })
}

const UNMAP_POISON: u8 = 0xdd;

fn unmap(pointer: *mut u8, pages: u64) {
    let outcome = unmap_outcome(pointer, pages, false);
    if outcome != 0 {
        if outcome == 101 {
            let _ = std::io::stdout().write_all(b"UNMAP_REFUSAL pages=17 mapped=17 exit=101\n");
        }
        std::process::exit(outcome);
    }
}

fn try_unmap(pointer: *mut u8, pages: u64) -> bool {
    match unmap_outcome(pointer, pages, true) {
        0 => true,
        1 => false,
        // An invalid range is an allocator bug: fail loudly in the model.
        outcome => std::process::exit(outcome),
    }
}

fn unmap_outcome(pointer: *mut u8, pages: u64, pool: bool) -> i32 {
    ARENA.with(|state| {
        let mut state = state.borrow_mut();
        let arena = state.as_mut().expect("unmap requires local arena");
        let Some(offset) = (pointer as usize).checked_sub(arena.pointer as usize) else {
            return 102;
        };
        let Ok(pages) = usize::try_from(pages) else {
            return 102;
        };
        let first = offset / PAGE;
        let Some(end) = first.checked_add(pages) else {
            return 102;
        };
        if pages == 0
            || pages > 64
            || !offset.is_multiple_of(PAGE)
            || end > arena.used.len()
            || !arena.used[first..end].iter().all(|&p| p)
        {
            return 102;
        }
        if pool && arena.refuse_pool_unmap {
            return 1; // Refused: no state or count change.
        }
        if arena.refuse_unmap {
            // No state/count change. This branch is exercised only in the
            // child control; exit rather than unwind through GlobalAlloc.
            return if pages == 17 && arena.accounted_pages == 17 {
                101
            } else {
                102
            };
        }
        arena.used[first..end].fill(false);
        arena.accounted_pages -= pages;
        arena.unmaps += 1;
        unsafe { ptr::write_bytes(pointer, UNMAP_POISON, pages * PAGE) };
        0
    })
}

fn heap_diag(_size: usize, _pages: usize) {}

fn heap_diag_pool_unmap(_size: usize, pages: usize) {
    ARENA.with(|state| state.borrow_mut().as_mut().unwrap().pool_unmaps.push(pages));
}

#[test]
fn observed_page_allocations_return_only_their_owned_pages() {
    let maps = LocalMaps::new(64);
    let allocator = allocator::MapAllocator::new();
    let pin_layout = Layout::from_size_align(PAGE, 2 * PAGE).unwrap();
    let small_layout = Layout::from_size_align(24, 16).unwrap();
    unsafe {
        // High alignment keeps this allocation in the original four-page
        // pool, with free space that a page-sized request could otherwise use.
        let pin = allocator.alloc(pin_layout);
        let small = allocator.alloc(small_layout);
        assert!(!pin.is_null() && !small.is_null());
        assert!((pin as usize).is_multiple_of(2 * PAGE));
        ptr::write_bytes(pin, 0x5a, PAGE);
        ptr::write_bytes(small, 0x39, 24);
        assert_eq!(maps.counts().0, 4);
        let mut returned = 0;
        for (size, pages) in [(65544, 17), (65536, 16), (35000, 9), (4095, 1)] {
            let layout = Layout::from_size_align(size, 16).unwrap();
            let block = allocator.alloc(layout);
            assert!(!block.is_null());
            assert!((block as usize).is_multiple_of(PAGE));
            assert!(
                block as usize >= maps.base() as usize + 4 * PAGE,
                "dedicated class bypasses reusable pooled storage"
            );
            assert_eq!(maps.counts().0, 4 + pages);
            assert!(
                std::slice::from_raw_parts(block, size)
                    .iter()
                    .all(|&b| b == 0)
            );
            ptr::write_bytes(block, 0xa7, size);
            allocator.dealloc(block, layout);
            returned += 1;
            assert_eq!(maps.counts().0, 4, "actual mapped pages return");
            assert_eq!(maps.counts().2, returned);
            assert!(
                std::slice::from_raw_parts(pin, PAGE)
                    .iter()
                    .all(|&b| b == 0x5a)
            );
            assert!(
                std::slice::from_raw_parts(small, 24)
                    .iter()
                    .all(|&b| b == 0x39)
            );
        }
        // 4095 normalizes to one page. Small and high-alignment allocations
        // retain their original pool behavior and do not call unmap.
        allocator.dealloc(small, small_layout);
        allocator.dealloc(pin, pin_layout);
        assert_eq!(maps.counts().0, 4);
        assert_eq!(maps.counts().2, returned);
        assert!(maps.valid_requests());
    }
}

#[test]
fn one_direct_hole_requires_actual_contiguous_fit_and_bounded_refusal() {
    let maps = LocalMaps::new(130);
    let allocator = allocator::MapAllocator::new();
    let page = Layout::from_size_align(PAGE, 16).unwrap();
    let large = Layout::from_size_align(64 * PAGE + 16, 16).unwrap();
    unsafe {
        let hole = allocator.alloc(page);
        let pin = allocator.alloc(page);
        assert_eq!(hole, maps.base());
        assert_eq!(pin, maps.base().add(PAGE));
        ptr::write_bytes(pin, 0xc3, PAGE);
        allocator.dealloc(hole, page);

        // Nominal65-page growth maps64 at page2, then1 in the hole at0.
        // Fixed-total growth wrongly refuses here. One further page at66
        // creates the real contiguous fit, without growing another64 pages.
        let block = allocator.alloc(large);
        assert_eq!(block, maps.base().add(2 * PAGE));
        assert_eq!(maps.counts().0, 67, "66 pooled pages and one live pin");
        ptr::write_bytes(block, 0x71, large.size());
        assert_eq!(*block.add(large.size() - 1), 0x71);
        assert!(
            std::slice::from_raw_parts(pin, PAGE)
                .iter()
                .all(|&b| b == 0xc3)
        );
        allocator.dealloc(block, large);

        // The pin separates page0 from the128-page tail. There is no
        // contiguous129-page fit even after every remaining page is mapped.
        let impossible = Layout::from_size_align(129 * PAGE, 16).unwrap();
        let before = maps.counts().1;
        let refused = allocator.alloc(impossible);
        assert!(refused.is_null());
        let after = maps.counts();
        assert_eq!(after.0, 130, "partial growth remains fully accounted");
        assert!(
            after.1 - before <= 130 + 7,
            "finite local window plus halving refusals"
        );
        assert!(maps.valid_requests());
        assert!(
            std::slice::from_raw_parts(pin, PAGE)
                .iter()
                .all(|&b| b == 0xc3)
        );
        let small_layout = Layout::from_size_align(24, 16).unwrap();
        let reused = allocator.alloc(small_layout);
        assert_eq!(
            reused,
            maps.base(),
            "partial pooled regions remain reusable"
        );
        allocator.dealloc(reused, small_layout);
        allocator.dealloc(pin, page);
        assert_eq!(maps.counts().0, 129);
    }
}

#[test]
fn realloc_preserves_layout_ownership_and_refused_unmap_exits() {
    const CHILD: &str = "ABSD_ALLOCATOR_UNMAP_REFUSAL_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let maps = LocalMaps::new(64);
        let allocator = allocator::MapAllocator::new();
        let layout = Layout::from_size_align(65544, 16).unwrap();
        let block = unsafe { allocator.alloc(layout) };
        assert!(!block.is_null());
        assert_eq!(maps.counts().0, 17);
        maps.refuse_unmap();
        unsafe { allocator.dealloc(block, layout) };
        std::process::exit(103); // Missing unmap must not look like refusal.
    }
    let maps = LocalMaps::new(64);
    let allocator = allocator::MapAllocator::new();
    let small_layout = Layout::from_size_align(48, 16).unwrap();
    let large_layout = Layout::from_size_align(65544, 16).unwrap();
    unsafe {
        let small = allocator.alloc(small_layout);
        assert!(!small.is_null());
        ptr::write_bytes(small, 0xb7, 48);
        let large = allocator.realloc(small, small_layout, large_layout.size());
        assert!(!large.is_null());
        assert!(
            std::slice::from_raw_parts(large, 48)
                .iter()
                .all(|&b| b == 0xb7)
        );
        assert_eq!(maps.counts().0, 21);
        let small = allocator.realloc(large, large_layout, small_layout.size());
        assert!(!small.is_null());
        assert!(
            std::slice::from_raw_parts(small, 48)
                .iter()
                .all(|&b| b == 0xb7)
        );
        assert_eq!(maps.counts().0, 4);
        assert_eq!(maps.counts().2, 1, "old direct layout returns17 pages");
        maps.frame_limit(4);
        let refused = allocator.realloc(small, small_layout, large_layout.size());
        assert!(refused.is_null());
        assert!(
            std::slice::from_raw_parts(small, 48)
                .iter()
                .all(|&b| b == 0xb7)
        );
        assert_eq!(maps.counts().0, 4);
        assert_eq!(maps.counts().2, 1, "failed growth keeps old allocation");
        allocator.dealloc(small, small_layout);
    }
    // A separate process observes the non-unwinding refusal path. The
    // marker prevents an unrelated Rust test failure(status101) passing.
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "realloc_preserves_layout_ownership_and_refused_unmap_exits",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert_eq!(child.status.code(), Some(101));
    assert!(
        child
            .stdout
            .windows(b"UNMAP_REFUSAL pages=17 mapped=17 exit=101\n".len())
            .any(|part| part == b"UNMAP_REFUSAL pages=17 mapped=17 exit=101\n")
    );
}

// R16 (REQUESTS.md R16, SPEC A23): a pooled workload that fills the window
// and frees everything leaves every page mapped in the pool. A request in
// the dedicated class (1..=64 pages, alignment at most a page) used to be
// refused then; now one whole free pooled run of its size is returned to the
// window and the request is mapped, still owning its entire map.
const R16_WINDOW: usize = 256;

/// The sorter's shape: one pooled block grown by realloc doubling until
/// the window refuses it, then freed. Returns with every window page
/// mapped and owned by the pool.
unsafe fn r16_exhaust_with_pooled_growth(maps: &LocalMaps, allocator: &allocator::MapAllocator) {
    let mut layout = Layout::from_size_align(300_000, 16).unwrap();
    let mut block = unsafe { allocator.alloc(layout) };
    assert!(!block.is_null());
    loop {
        let grown = unsafe { allocator.realloc(block, layout, layout.size() * 2) };
        if grown.is_null() {
            break;
        }
        block = grown;
        layout = Layout::from_size_align(layout.size() * 2, 16).unwrap();
    }
    unsafe { allocator.dealloc(block, layout) };
    assert_eq!(
        maps.counts().0,
        R16_WINDOW,
        "the pool holds the whole window"
    );
    assert_eq!(maps.counts().2, 0, "pooled pages are never unmapped");
}

#[test]
fn r16_dedicated_class_served_from_window_held_by_pool() {
    let maps = LocalMaps::new(R16_WINDOW);
    let allocator = allocator::MapAllocator::new();
    unsafe {
        r16_exhaust_with_pooled_growth(&maps, &allocator);
        // A live pooled block must survive every page-run return.
        let pin_layout = Layout::from_size_align(2000, 16).unwrap();
        let pin = allocator.alloc(pin_layout);
        assert!(!pin.is_null(), "small request served from the pool");
        ptr::write_bytes(pin, 0x4e, 2000);
        let big = Layout::from_size_align(200 * PAGE, 16).unwrap();
        let b = allocator.alloc(big);
        assert!(!b.is_null(), "over-64-page request served from the pool");
        allocator.dealloc(b, big);
        assert_eq!(maps.counts().2, 0, "pooled classes unmap nothing");
        // Each dedicated-class size: the full window refuses one map, one
        // free pooled run of exactly that size is unmapped, and the retry
        // maps it. Freeing the block unmaps its own pages.
        for pages in [1usize, 2, 17, 64] {
            let layout = Layout::from_size_align(pages * PAGE, 16).unwrap();
            let (mapped, requests, unmaps) = maps.counts();
            let block = allocator.alloc(layout);
            assert!(!block.is_null(), "R16: {pages} pages now served");
            assert!((block as usize).is_multiple_of(PAGE));
            let after = maps.counts();
            if mapped == R16_WINDOW {
                assert_eq!(after.1, requests + 2, "one refused map, one retry");
                assert_eq!(after.2, unmaps + 1, "one pooled run returned");
            }
            assert!(after.0 <= R16_WINDOW);
            ptr::write_bytes(block, 0x6d, layout.size());
            maps.assert_free_list_mapped(&allocator);
            allocator.dealloc(block, layout);
            assert_eq!(maps.counts().2, after.2 + 1, "the block's own map");
            assert!(
                std::slice::from_raw_parts(pin, 2000)
                    .iter()
                    .all(|&x| x == 0x4e)
            );
        }
        allocator.dealloc(pin, pin_layout);
        assert!(maps.valid_requests());
    }
}

#[test]
fn r16_no_free_pooled_run_refuses_without_unmapping() {
    let maps = LocalMaps::new(R16_WINDOW);
    let allocator = allocator::MapAllocator::new();
    unsafe {
        r16_exhaust_with_pooled_growth(&maps, &allocator);
        // A live pooled block holds all but a few pages of the window, so
        // no free run of 17 pages exists anywhere.
        let live_layout = Layout::from_size_align(250 * PAGE, 16).unwrap();
        let live = allocator.alloc(live_layout);
        assert!(!live.is_null());
        ptr::write_bytes(live, 0x2b, live_layout.size());
        let layout = Layout::from_size_align(17 * PAGE, 16).unwrap();
        let before = maps.counts();
        assert!(allocator.alloc(layout).is_null());
        let after = maps.counts();
        assert_eq!(after.0, R16_WINDOW);
        assert_eq!(after.1, before.1 + 1, "one refused map, no retry");
        assert_eq!(after.2, before.2, "live pooled pages are never unmapped");
        assert!(
            std::slice::from_raw_parts(live, live_layout.size())
                .iter()
                .all(|&x| x == 0x2b)
        );
        allocator.dealloc(live, live_layout);
        assert!(maps.valid_requests());
    }
}

#[test]
fn r16_dedicated_class_recovers_after_pooled_exhaustion() {
    let maps = LocalMaps::new(R16_WINDOW);
    let allocator = allocator::MapAllocator::new();
    unsafe {
        r16_exhaust_with_pooled_growth(&maps, &allocator);
        // In-process recovery: with the pool holding the whole window free,
        // each dedicated-class size is served, usable and returned, and the
        // window is never exceeded.
        for pages in [1usize, 2, 17, 64] {
            let layout = Layout::from_size_align(pages * PAGE, 16).unwrap();
            let block = allocator.alloc(layout);
            assert!(!block.is_null(), "{pages} pages after NOMEM");
            assert!((block as usize).is_multiple_of(PAGE));
            ptr::write_bytes(block, 0x6d, layout.size());
            maps.assert_free_list_mapped(&allocator);
            assert_eq!(*block.add(layout.size() - 1), 0x6d);
            allocator.dealloc(block, layout);
            assert!(maps.counts().0 <= R16_WINDOW);
        }
        // Many live dedicated-class blocks at once, then all freed: the
        // window is shared, not lost.
        let layout = Layout::from_size_align(8 * PAGE, 16).unwrap();
        let mut live = Vec::new();
        for _ in 0..R16_WINDOW / 8 / 2 {
            let block = allocator.alloc(layout);
            assert!(!block.is_null());
            live.push(block);
        }
        for block in live {
            allocator.dealloc(block, layout);
        }
        let again = allocator.alloc(Layout::from_size_align(PAGE, 16).unwrap());
        assert!(!again.is_null());
        allocator.dealloc(again, Layout::from_size_align(PAGE, 16).unwrap());
        assert!(maps.counts().0 <= R16_WINDOW);
        assert!(maps.valid_requests());
    }
}

// Interface owner's case: a pooled peak fills the window and is freed, then
// 64 pages are served by returning one pooled run; with the pool still held
// the same request is refused without any unmap.
#[test]
fn r16_pooled_peak_then_64_pages_served_when_freed_refused_when_held() {
    let layout = Layout::from_size_align(64 * PAGE, 16).unwrap();
    {
        let maps = LocalMaps::new(R16_WINDOW);
        let allocator = allocator::MapAllocator::new();
        unsafe {
            r16_exhaust_with_pooled_growth(&maps, &allocator);
            let block = allocator.alloc(layout);
            assert!(!block.is_null(), "freed pool: 64 pages served");
            assert_eq!(maps.pool_unmaps(), vec![64], "diag sees one 64-page run");
            maps.assert_free_list_mapped(&allocator);
            assert_eq!(maps.counts().0, R16_WINDOW);
            allocator.dealloc(block, layout);
            assert_eq!(maps.counts().0, R16_WINDOW - 64);
            assert!(maps.valid_requests());
        }
    }
    let maps = LocalMaps::new(R16_WINDOW);
    let allocator = allocator::MapAllocator::new();
    unsafe {
        r16_exhaust_with_pooled_growth(&maps, &allocator);
        let held_layout = Layout::from_size_align(R16_WINDOW * PAGE, 16).unwrap();
        let held = allocator.alloc(held_layout);
        assert!(!held.is_null(), "the whole pool is held");
        let before = maps.counts();
        assert!(allocator.alloc(layout).is_null(), "held pool: refused");
        assert_eq!(maps.counts().1, before.1 + 1, "one refused map, no retry");
        assert_eq!(maps.counts().2, before.2, "no unmap");
        assert!(maps.pool_unmaps().is_empty());
        allocator.dealloc(held, held_layout);
    }
}

// A held pooled block is never moved or unmapped by a pool return, and its
// contents are unchanged. The block sits at the window base (pages 0..10);
// the exhaustion's first growth mapped 64 + 10 pages, so the returned run
// (pages 10..74) crosses a map-call boundary at page 64. The kernel's unmap
// is page-granular and keeps no map-call identity; the model does the same.
#[test]
fn r16_held_pooled_block_intact_after_pool_unmap() {
    let maps = LocalMaps::new(R16_WINDOW);
    let allocator = allocator::MapAllocator::new();
    unsafe {
        r16_exhaust_with_pooled_growth(&maps, &allocator);
        let held_layout = Layout::from_size_align(10 * PAGE, 2 * PAGE).unwrap();
        let held = allocator.alloc(held_layout);
        assert_eq!(held, maps.base(), "pooled (high alignment), first fit");
        for i in 0..held_layout.size() {
            *held.add(i) = (i % 251) as u8;
        }
        let layout = Layout::from_size_align(64 * PAGE, 16).unwrap();
        let block = allocator.alloc(layout);
        assert_eq!(
            block,
            maps.base().add(10 * PAGE),
            "run right after the held block"
        );
        assert_eq!(maps.pool_unmaps(), vec![64]);
        assert_eq!(allocator.free_pooled_pages(), R16_WINDOW - 10 - 64);
        assert_free_metric(&maps, &allocator);
        maps.assert_free_list_mapped(&allocator);
        assert_eq!(maps.counts().2, 1);
        ptr::write_bytes(block, 0xee, layout.size());
        assert!((0..held_layout.size()).all(|i| *held.add(i) == (i % 251) as u8));
        allocator.dealloc(block, layout);
        assert!((0..held_layout.size()).all(|i| *held.add(i) == (i % 251) as u8));
        allocator.dealloc(held, held_layout);
        assert!(maps.valid_requests());
    }
}

// Review N2: the run is unmapped but the retry itself fails (frame limit).
// The request is refused, there is no second unmap, and the pool shrank by
// exactly that run.
#[test]
fn r16_retry_failure_refuses_and_pool_shrinks_by_the_run() {
    let maps = LocalMaps::new(R16_WINDOW);
    let allocator = allocator::MapAllocator::new();
    unsafe {
        r16_exhaust_with_pooled_growth(&maps, &allocator);
        let free_before = maps.assert_free_list_mapped(&allocator);
        assert_eq!(free_before, R16_WINDOW * PAGE);
        assert_free_metric(&maps, &allocator);
        maps.frame_limit(R16_WINDOW - 65);
        let before = maps.counts();
        let layout = Layout::from_size_align(64 * PAGE, 16).unwrap();
        assert!(allocator.alloc(layout).is_null());
        let after = maps.counts();
        assert_eq!(after.0, R16_WINDOW - 64, "the run left the window");
        assert_eq!(after.1, before.1 + 2, "refused map and refused retry");
        assert_eq!(after.2, before.2 + 1, "exactly one unmap");
        assert_eq!(maps.pool_unmaps(), vec![64]);
        maps.assert_free_list_mapped(&allocator);
        let free_after = maps.assert_free_list_mapped(&allocator);
        assert_eq!(
            free_before - free_after,
            64 * PAGE,
            "pool shrank by the run"
        );
        assert_eq!(allocator.free_pooled_pages(), R16_WINDOW - 64);
        assert_free_metric(&maps, &allocator);
        assert!(maps.valid_requests());
    }
}

// Owner minor: should the kernel refuse the pool unmap, the run is still
// mapped and free; it returns to the list and the request is refused.
#[test]
fn r16_refused_pool_unmap_returns_the_run_and_refuses() {
    let maps = LocalMaps::new(R16_WINDOW);
    let allocator = allocator::MapAllocator::new();
    unsafe {
        r16_exhaust_with_pooled_growth(&maps, &allocator);
        let free_before = maps.assert_free_list_mapped(&allocator);
        maps.refuse_pool_unmap();
        let before = maps.counts();
        let layout = Layout::from_size_align(64 * PAGE, 16).unwrap();
        assert!(allocator.alloc(layout).is_null());
        assert_eq!(maps.counts(), (R16_WINDOW, before.1 + 1, before.2));
        assert!(maps.pool_unmaps().is_empty(), "no diag without an unmap");
        assert_eq!(maps.assert_free_list_mapped(&allocator), free_before);
        assert_eq!(allocator.free_pooled_pages(), free_before / PAGE);
        assert_free_metric(&maps, &allocator);
        // The returned run is reusable, coalesced back into one region.
        let whole = Layout::from_size_align(R16_WINDOW * PAGE, 16).unwrap();
        let block = allocator.alloc(whole);
        assert!(!block.is_null());
        allocator.dealloc(block, whole);
    }
}

// R15 (REQUESTS.md R15): Lua's deep recursion f(50000) on ABSD. The kit's
// realloc always allocates, copies and frees (C-INTERFACE.md section 3), so
// the model below reproduces its calls: `size + 16` bytes, alignment 16.
const R15_WINDOW: usize = 8192;
const KIT_SLOT: usize = 16;

fn node_visits() -> usize {
    allocator::NODE_VISITS.with(|visits| visits.get())
}

/// The kit's realloc over the runtime: new block, copy, free the old one.
/// `new == 0` frees the block.
unsafe fn kit_realloc(
    allocator: &allocator::MapAllocator,
    block: *mut u8,
    old: usize,
    new: usize,
) -> *mut u8 {
    let old_layout = Layout::from_size_align(old + KIT_SLOT, 16).unwrap();
    unsafe {
        if new == 0 {
            allocator.dealloc(block, old_layout);
            return ptr::null_mut();
        }
        let grown = allocator.alloc(Layout::from_size_align(new + KIT_SLOT, 16).unwrap());
        if !grown.is_null() && !block.is_null() {
            ptr::copy_nonoverlapping(block, grown, old.min(new) + KIT_SLOT);
            allocator.dealloc(block, old_layout);
        }
        grown
    }
}

#[derive(Debug)]
#[allow(dead_code)] // Read through Debug in the test output.
struct R15Cost {
    maps: usize,
    unmaps: usize,
    scan_pages: usize,
    copied: usize,
    visits: usize,
    peak_mapped: usize,
}

/// One block doubled by the kit's realloc from 4 KiB towards `last` bytes.
/// Returns the costs and the size whose doubling was refused, if any.
fn r15_doubling(last: usize) -> (R15Cost, Option<usize>) {
    let maps = LocalMaps::new(R15_WINDOW);
    let allocator = allocator::MapAllocator::new();
    let visits = node_visits();
    let (mut copied, mut peak, mut refused) = (0, 0, None);
    let mut size = 4096;
    unsafe {
        let mut block = kit_realloc(&allocator, ptr::null_mut(), 0, size);
        assert!(!block.is_null());
        while size < last {
            let grown = kit_realloc(&allocator, block, size, size * 2);
            peak = peak.max(maps.counts().0);
            if grown.is_null() {
                refused = Some(size * 2);
                break;
            }
            copied += size + KIT_SLOT;
            block = grown;
            size *= 2;
        }
        if refused.is_some() {
            // The held block and the free pool fill the window: no run of
            // the doubled size is contiguous.
            let free = maps.assert_free_list_mapped(&allocator);
            assert_eq!(maps.counts().0, R15_WINDOW);
            assert!(free >= R15_WINDOW * PAGE - 2 * (size + KIT_SLOT + PAGE));
        }
        kit_realloc(&allocator, block, size, 0);
    }
    let (_, maps_requested, unmaps) = maps.counts();
    assert!(maps.valid_requests());
    let cost = R15Cost {
        maps: maps_requested,
        unmaps,
        scan_pages: maps.scan_pages(),
        copied,
        visits: node_visits() - visits,
        peak_mapped: peak,
    };
    (cost, refused)
}

// The brief's growth pattern: 4 KiB doubled with the old block freed after
// each copy. Up to 8 MiB every cost is linear in the final size: maps are
// 64-page chunks plus single pages into earlier holes, copies sum to under
// the final size, and the free list stays a handful of nodes. The 16 MiB
// step is refused by the 32 MiB window: the moving realloc needs a fresh
// contiguous run above the held 8 MiB block, and the freed smaller blocks
// below it cannot join it. That is the documented exhaustion, not a stall.
#[test]
fn r15_realloc_doubling_is_linear_and_16_mib_meets_the_window() {
    let (cost, refused) = r15_doubling(8 << 20);
    eprintln!("R15 doubling 4 KiB..8 MiB: {cost:?}");
    assert_eq!(refused, None);
    let final_pages = (8 << 20) / PAGE;
    assert!(cost.maps <= 2 * final_pages / 64 + 64, "{cost:?}");
    assert!(cost.copied < 8 << 20, "{cost:?}");
    assert!(cost.visits < 4000, "{cost:?}");
    assert!(cost.scan_pages <= cost.maps * R15_WINDOW / 2, "{cost:?}");
    let (cost, refused) = r15_doubling(16 << 20);
    eprintln!("R15 doubling 4 KiB..16 MiB: {cost:?} refused={refused:?}");
    assert_eq!(refused, Some(16 << 20));
}

/// Lua's shape for `f(depth)`: one 64-byte CallInfo per level (80 bytes
/// with the kit header, lstate.c luaE_extendCI) and a stack of 16-byte
/// slots, four per level, grown by doubling through the kit's realloc
/// (ldo.c luaD_growstack). After the return the collector's luaE_shrinkCI
/// frees every other CallInfo in address order (lstate.c:143-160), then
/// lua_close frees the rest (luaE_freeCI). Returns the free-list nodes
/// visited by the alternate frees and by all CallInfo frees.
fn r15_lua_call_info_shape(depth: usize) -> (usize, usize) {
    let maps = LocalMaps::new(R15_WINDOW);
    let allocator = allocator::MapAllocator::new();
    let ci = Layout::from_size_align(64 + KIT_SLOT, 16).unwrap();
    let mut call_infos = Vec::with_capacity(depth);
    let mut stack_size = 45 * 16;
    unsafe {
        let mut stack = kit_realloc(&allocator, ptr::null_mut(), 0, stack_size);
        for level in 0..depth {
            if (level + 1) * 4 * 16 > stack_size {
                stack = kit_realloc(&allocator, stack, stack_size, stack_size * 2);
                assert!(!stack.is_null());
                stack_size *= 2;
            }
            let block = allocator.alloc(ci);
            assert!(!block.is_null());
            call_infos.push(block);
        }
        call_infos.sort_unstable();
        let before = node_visits();
        for block in call_infos.iter().skip(1).step_by(2) {
            allocator.dealloc(*block, ci);
        }
        let alternate = node_visits() - before;
        for block in call_infos.iter().step_by(2) {
            allocator.dealloc(*block, ci);
        }
        let frees = node_visits() - before;
        kit_realloc(&allocator, stack, stack_size, 0);
        assert!(maps.valid_requests());
        (alternate, frees)
    }
}

// The cost that stalled f(50000): every free walked the whole free list,
// and luaE_shrinkCI leaves depth/2 nodes that no free can coalesce, so the
// frees cost about depth*depth/4 visits (100,043,745 at depth 20,000 before
// the repair). Now each free starts at the last insertion and joins only its
// two neighbors: the frees of f(50000) visit a bounded number of nodes each.
#[test]
fn r15_lua_deep_recursion_frees_are_linear() {
    for depth in [5_000, 50_000] {
        let (alternate, frees) = r15_lua_call_info_shape(depth);
        eprintln!(
            "R15 Lua shape depth={depth}: alternate-free visits={alternate} all-free visits={frees}"
        );
        assert!(frees <= 8 * depth, "depth {depth}: {frees} visits");
    }
}

// R15 repair invariants: after every operation of a mixed workload the free
// list is in strictly ascending address order, fully coalesced (no node ends
// where the next begins), on mapped pages, and free plus held bytes equal
// the pooled pages; every held block keeps its contents.
#[test]
fn r15_free_list_stays_sorted_coalesced_and_exact() {
    let maps = LocalMaps::new(R15_WINDOW);
    let allocator = allocator::MapAllocator::new();
    let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut held: Vec<(*mut u8, Layout, u8)> = Vec::new();
    let check = |held_bytes: usize| {
        let mut last_end = 0usize;
        let mut free = 0usize;
        allocator.for_each_free(|address, size| {
            assert!(
                address > last_end || last_end == 0,
                "order or adjacency at {address:#x}"
            );
            assert_ne!(address, last_end, "uncoalesced neighbors at {address:#x}");
            last_end = address + size;
            free += size;
        });
        assert_eq!(maps.assert_free_list_mapped(&allocator), free);
        free + held_bytes
    };
    unsafe {
        for step in 0..20_000 {
            let roll = next();
            if held.is_empty() || roll % 3 != 0 {
                let size = match roll % 7 {
                    0 => 16 + (roll >> 8) as usize % 4096,
                    1 => 300_000 + (roll >> 8) as usize % 200_000,
                    2 => 64 + KIT_SLOT,
                    _ => 16 + (roll >> 8) as usize % 400,
                };
                let align = if roll % 11 == 0 { 2 * PAGE } else { 16 };
                let layout = Layout::from_size_align(size, align).unwrap();
                let block = allocator.alloc(layout);
                if block.is_null() {
                    continue;
                }
                let fill = (step % 251) as u8;
                ptr::write_bytes(block, fill, size);
                held.push((block, layout, fill));
            } else if roll % 97 == 0 {
                // luaE_shrinkCI's shape: every other held block, ascending.
                held.sort_by_key(|(block, _, _)| *block as usize);
                let mut index = 1;
                while index < held.len() {
                    let (block, layout, fill) = held.remove(index);
                    assert!(
                        std::slice::from_raw_parts(block, layout.size())
                            .iter()
                            .all(|&b| b == fill)
                    );
                    allocator.dealloc(block, layout);
                    index += 1;
                }
            } else {
                let index = (roll >> 8) as usize % held.len();
                let (block, layout, fill) = held.swap_remove(index);
                assert!(
                    std::slice::from_raw_parts(block, layout.size())
                        .iter()
                        .all(|&b| b == fill)
                );
                allocator.dealloc(block, layout);
            }
            let pooled_held: usize = held
                .iter()
                .filter(|(_, l, _)| {
                    !(l.size() >= PAGE && l.size() <= 64 * PAGE && l.align() <= PAGE)
                })
                .map(|(_, l, _)| l.size().max(16).next_multiple_of(16))
                .sum();
            let total = check(pooled_held);
            let mapped_pooled = maps.counts().0 * PAGE
                - held
                    .iter()
                    .filter(|(_, l, _)| {
                        l.size() >= PAGE && l.size() <= 64 * PAGE && l.align() <= PAGE
                    })
                    .map(|(_, l, _)| l.size().div_ceil(PAGE) * PAGE)
                    .sum::<usize>();
            assert_eq!(total, mapped_pooled, "step {step}");
        }
        held.sort_by_key(|(block, _, _)| *block as usize);
        for (block, layout, _) in held.drain(..) {
            allocator.dealloc(block, layout);
        }
    }
    assert_eq!(check(0), maps.counts().0 * PAGE);
    assert!(maps.valid_requests());
}

// A3 production observation, cross-checked with the existing test-only visitor.
fn assert_free_metric(maps: &LocalMaps, allocator: &allocator::MapAllocator) {
    let counts = maps.counts();
    let mut before = Vec::new();
    allocator.for_each_free(|address, size| before.push((address, size)));
    let expected = before.iter().map(|(_, size)| *size).sum::<usize>() / PAGE;
    let visits = allocator::NODE_VISITS.with(|v| v.get());
    assert_eq!(allocator.free_pooled_pages(), expected);
    assert_eq!(allocator.free_pooled_pages(), expected);
    assert_eq!(allocator::NODE_VISITS.with(|v| v.get()), visits);
    assert_eq!(maps.counts(), counts, "observation does not map/unmap");
    let mut after = Vec::new();
    allocator.for_each_free(|address, size| after.push((address, size)));
    assert_eq!(after, before, "observation does not alter free nodes");
}

#[test]
fn a3_free_pool_aggregate_rounding_and_coalescing() {
    let maps = LocalMaps::new(16);
    let allocator = allocator::MapAllocator::new();
    assert_eq!(allocator.free_pooled_pages(), 0);
    assert_free_metric(&maps, &allocator);
    let layout = Layout::from_size_align(PAGE / 2, 16).unwrap();
    unsafe {
        let blocks: Vec<_> = (0..8).map(|_| allocator.alloc(layout)).collect();
        assert!(blocks.iter().all(|p| !p.is_null()));
        assert_eq!(allocator.free_pooled_pages(), 0);
        allocator.dealloc(blocks[0], layout);
        assert_eq!(allocator.free_pooled_pages(), 0);
        allocator.dealloc(blocks[2], layout);
        assert_eq!(
            allocator.free_pooled_pages(),
            1,
            "sum fragments before rounding"
        );
        assert_free_metric(&maps, &allocator);
        let first = allocator.alloc(layout);
        assert_eq!(first, blocks[0], "observation preserves first fit");
        allocator.dealloc(first, layout);
        for i in [1, 3, 4, 5, 6, 7] {
            allocator.dealloc(blocks[i], layout);
        }
        assert_eq!(allocator.free_pooled_pages(), 4);
        assert_free_metric(&maps, &allocator);
    }
}

#[test]
fn a3_free_pool_excludes_dedicated_and_counts_alignment_fragments() {
    let maps = LocalMaps::new(32);
    let allocator = allocator::MapAllocator::new();
    unsafe {
        let dedicated = Layout::from_size_align(PAGE, 16).unwrap();
        let p = allocator.alloc(dedicated);
        assert!(!p.is_null());
        assert_eq!(allocator.free_pooled_pages(), 0);
        allocator.dealloc(p, dedicated);
        assert_eq!(allocator.free_pooled_pages(), 0);
        let small = Layout::from_size_align(16, 16).unwrap();
        let aligned = Layout::from_size_align(16, 2 * PAGE).unwrap();
        let a = allocator.alloc(small);
        let b = allocator.alloc(aligned);
        assert!(!a.is_null() && !b.is_null());
        assert_eq!((b as usize) % (2 * PAGE), 0);
        assert_eq!(allocator.free_pooled_pages(), 3);
        assert_free_metric(&maps, &allocator);
        allocator.dealloc(a, small);
        allocator.dealloc(b, aligned);
        assert_eq!(allocator.free_pooled_pages(), 4);
        assert_free_metric(&maps, &allocator);
    }
}
