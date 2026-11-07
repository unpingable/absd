//! #115: frame admission over the actual x86 VM source (`src/vm.rs`) and
//! the actual frame allocator, for whichever layout this build selects.
//! Falsifies, on a host arena: a reservation caps data and page-table frames
//! together; an unreserved process cannot take reserved capacity; admission
//! refuses what the pool cannot back; teardown returns every frame and the
//! promise; a service charged `service_frames` maps its whole heap prefix and
//! can still grow its whole stack (review claude-kernel-review-01 B-1/B-2).
//! `map` mirrors `syscall_map` (lowest run from the hint up to
//! `heap_search_end`, all-or-nothing).
use absd_kernel::elf;
use absd_kernel::frame_geometry::{heap_search_end, service_frames};
use absd_kernel::layout::{
    SERVICE_HEAP_END, SERVICE_HEAP_PAGES, USER_HEAP_BASE, USER_HEAP_END, USER_IMAGE_MIN,
    USER_STACK_BASE, USER_STACK_PAGES, USER_STACK_TOP,
};
use absd_kernel::memory::{AdmissionError, FrameAllocator, PAGE_SIZE};
use absd_kernel::process::AddressSpace;
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
        let mut f = FrameAllocator::with_base(start);
        let frames = self.layout.size() / PAGE_SIZE as usize;
        if frames > absd_kernel::memory::MAX_TRACKED_FRAMES {
            // The whole-RAM tag table, as a large guest installs at boot.
            assert!(f.extend_tags(Box::leak(vec![0u32; frames].into_boxed_slice())));
        }
        f.add_usable(start, start + self.layout.size() as u64);
        f
    }
}
impl Drop for Arena {
    fn drop(&mut self) {
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) }
    }
}

/// `syscall_map` for one process: Some(base) or None (refused, rolled back).
unsafe fn map(
    f: &mut FrameAllocator,
    space: &mut AddressSpace,
    pid: u32,
    pages: u64,
) -> Option<u64> {
    let start = space.heap_hint.max(USER_HEAP_BASE);
    let end = heap_search_end(f.reservation(pid).is_some());
    let base = unsafe { vm::find_unmapped_run(space, start, end, pages) }?;
    for index in 0..pages {
        if unsafe { vm::map_user_page(f, space, pid, base + index * PAGE_SIZE, true, false) }
            .is_err()
        {
            for undo in 0..index {
                unsafe { vm::unmap_user_page(f, space, pid, base + undo * PAGE_SIZE) }.unwrap();
            }
            return None;
        }
    }
    if base == start {
        space.heap_hint = base + pages * PAGE_SIZE;
    }
    Some(base)
}

/// Maps in 64-page calls, then single pages, until refused; returns pages.
unsafe fn fill(f: &mut FrameAllocator, space: &mut AddressSpace, pid: u32) -> u64 {
    let mut mapped = 0;
    for chunk in [64, 1] {
        while unsafe { map(f, space, pid, chunk) }.is_some() {
            mapped += chunk;
        }
    }
    mapped
}

/// Frames the address space itself holds: root, PDPT, directories, leaves.
fn table_frames(space: &AddressSpace) -> usize {
    2 + space.directories.iter().filter(|&&d| d != 0).count() + space.tables
}

fn main() {
    unsafe {
        reservation_caps_data_and_tables();
        unreserved_cannot_take_reserved();
        admission_refuses_unbacked_promises();
        service_budget_backs_heap_prefix_and_whole_stack();
    }
    println!(
        "LARGE ENVELOPE ADMISSION OK heap_pages={} service_heap_pages={SERVICE_HEAP_PAGES}",
        (USER_HEAP_END - USER_HEAP_BASE) / PAGE_SIZE
    );
}

unsafe fn reservation_caps_data_and_tables() {
    let arena = Arena::new(4096);
    let mut f = arena.pool();
    let free = f.free_frames();
    let mut space = unsafe { vm::create(&mut f, 7, 0) }.unwrap();
    f.admit(7, 600).unwrap();
    let pages = unsafe { fill(&mut f, &mut space, 7) };
    let owned = f.frames_owned_by(7);
    // Every frame the process holds is inside its promise, and the data
    // pages plus every table it needed account for all of them.
    assert_eq!(f.reservation(7), Some((600, owned)));
    assert!(owned <= 600);
    assert_eq!(owned, pages as usize + table_frames(&space));
    // Refusal is bounded by the promise, not by the pool, which is far
    // from empty: the next page is refused and leaves the count in bounds.
    assert!(f.free_frames() > 3000);
    assert!(unsafe { map(&mut f, &mut space, 7, 1) }.is_none());
    assert!(f.frames_owned_by(7) <= 600);
    // Teardown returns every frame; only then may the promise retire.
    assert_eq!(f.retire_reservation(7), Err(AdmissionError::StillOwned));
    let released = unsafe { vm::destroy(&mut f, &mut space, 7) }.unwrap();
    assert_eq!(released, owned);
    assert_eq!(f.reservation(7), Some((600, 0)));
    f.retire_reservation(7).unwrap();
    assert_eq!(f.idle_reserved_frames(), 0);
    assert_eq!(f.free_frames(), free);
}

unsafe fn unreserved_cannot_take_reserved() {
    let arena = Arena::new(2048);
    let mut f = arena.pool();
    let free = f.free_frames();
    let mut admitted = unsafe { vm::create(&mut f, 7, 0) }.unwrap();
    f.admit(7, 900).unwrap();
    let idle = f.idle_reserved_frames();
    // An ordinary process fills everything it may take ...
    let mut ordinary = unsafe { vm::create(&mut f, 8, 0) }.unwrap();
    let taken = unsafe { fill(&mut f, &mut ordinary, 8) };
    assert!(taken > 0);
    // ... and stops with the admitted promise still idle and backed.
    assert_eq!(f.idle_reserved_frames(), idle);
    assert!(f.free_frames() >= idle);
    // The admitted process then maps up to its whole promise.
    let pages = unsafe { fill(&mut f, &mut admitted, 7) };
    assert_eq!(
        pages as usize + table_frames(&admitted),
        f.frames_owned_by(7)
    );
    assert!(
        900 - f.frames_owned_by(7) < 3,
        "promise left unused: {}",
        f.frames_owned_by(7)
    );
    // Both tear down independently and the pool is whole again.
    unsafe { vm::destroy(&mut f, &mut ordinary, 8) }.unwrap();
    unsafe { vm::destroy(&mut f, &mut admitted, 7) }.unwrap();
    f.retire_reservation(7).unwrap();
    assert_eq!(f.free_frames(), free);
}

unsafe fn admission_refuses_unbacked_promises() {
    let arena = Arena::new(1024);
    let mut f = arena.pool();
    let free = f.free_frames();
    f.admit(7, 600).unwrap();
    // Two independent promises may not exceed the pool together.
    assert_eq!(f.admit(9, free - 600 + 1), Err(AdmissionError::NoCapacity));
    f.admit(9, free - 600).unwrap();
    assert_eq!(f.admit(10, 1), Err(AdmissionError::NoCapacity));
    let accounting = f.admission_accounting();
    assert!(accounting.consistent && accounting.idle as usize == free);
    f.retire_reservation(9).unwrap();
    f.retire_reservation(7).unwrap();
    assert_eq!(f.idle_reserved_frames(), 0);
}

unsafe fn service_budget_backs_heap_prefix_and_whole_stack() {
    // The real catalog budget for an 87-page image (the fsd vector), the
    // image and initial stack mapped as the loader does, the heap filled as
    // `map` would, then the stack grown one fault at a time to its base.
    let mut image = elf::Image {
        entry: USER_IMAGE_MIN,
        segments: [elf::LoadSegment::EMPTY; elf::MAX_LOAD_SEGMENTS],
        segment_count: 1,
    };
    image.segments[0].virtual_address = USER_IMAGE_MIN;
    image.segments[0].memory_size = 87 * 4096;
    let budget = service_frames(&image).unwrap();
    let arena = Arena::new(budget + 4096);
    let mut f = arena.pool();
    let free = f.free_frames();
    let mut space = unsafe { vm::create(&mut f, 7, 0) }.unwrap();
    f.admit(7, budget).unwrap();
    for page in 0..87 {
        unsafe {
            vm::map_user_page(
                &mut f,
                &mut space,
                7,
                USER_IMAGE_MIN + page * PAGE_SIZE,
                false,
                true,
            )
        }
        .unwrap();
    }
    let mut stack = USER_STACK_TOP - USER_STACK_PAGES as u64 * PAGE_SIZE;
    for page in 0..USER_STACK_PAGES as u64 {
        unsafe { vm::map_user_page(&mut f, &mut space, 7, stack + page * PAGE_SIZE, true, false) }
            .unwrap();
    }
    // The heap stops exactly at the charged prefix, although the window
    // (and, under the envelope, the pool) continue.
    assert_eq!(unsafe { fill(&mut f, &mut space, 7) }, SERVICE_HEAP_PAGES);
    const _: () = assert!(SERVICE_HEAP_END <= USER_HEAP_END);
    // Every stack page the budget charged can still be faulted in.
    while stack > USER_STACK_BASE {
        stack -= PAGE_SIZE;
        unsafe { vm::map_user_page(&mut f, &mut space, 7, stack, true, false) }
            .unwrap_or_else(|e| panic!("stack growth at {stack:#x} refused: {e:?}"));
    }
    // What remains of the promise is the kernel stack, which this fixture
    // does not allocate.
    assert_eq!(
        budget - f.frames_owned_by(7),
        absd_kernel::layout::KERNEL_STACK_PAGES
    );
    unsafe { vm::destroy(&mut f, &mut space, 7) }.unwrap();
    f.retire_reservation(7).unwrap();
    assert_eq!(f.free_frames(), free);
}
