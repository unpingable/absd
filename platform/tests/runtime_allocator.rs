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
            return ptr::null_mut();
        };
        let pointer = unsafe { arena.pointer.add(first * PAGE) };
        unsafe { ptr::write_bytes(pointer, 0, pages * PAGE) };
        arena.used[first..first + pages].fill(true);
        arena.accounted_pages += pages;
        pointer
    })
}

fn unmap(pointer: *mut u8, pages: u64) {
    let outcome = ARENA.with(|state| {
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
        0
    });
    if outcome != 0 {
        if outcome == 101 {
            let _ = std::io::stdout().write_all(b"UNMAP_REFUSAL pages=17 mapped=17 exit=101\n");
        }
        std::process::exit(outcome);
    }
}

fn heap_diag(_size: usize, _pages: usize) {}

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
