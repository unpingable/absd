//! Runs the actual x86 VM mapping/teardown source over an owned host arena.
//! Identity-mapped physical memory is substituted by aligned host memory.
//! No CR3, TLB, scheduler, CPU departure or hardware claim follows.
use absd_kernel::layout::{USER_HEAP_BASE, USER_REGION_BASE};
use absd_kernel::memory::{AdmissionError, FrameAllocator, FrameOwner, PAGE_SIZE};
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

fn main() {
    unsafe {
        construction_failures();
        retained_leaf_and_fixed_slots();
        contention_and_reuse();
    }
    println!("HOST VM QUALIFICATION OK actual_vm_source=true physical_identity_substitution=true");
}

unsafe fn construction_failures() {
    let arena = Arena::new(64);
    for total in 1..=3 {
        let mut f = arena.pool();
        f.admit(1, total).unwrap();
        let space = unsafe { vm::create(&mut f, 1, 0) };
        if total < 3 {
            assert!(space.is_none());
            assert_eq!(f.reservation(1), Some((total, 0)));
        } else {
            let mut space = space.unwrap();
            assert_eq!(unsafe { vm::destroy(&mut f, &mut space, 1) }.unwrap(), 3);
        }
        f.retire_reservation(1).unwrap();
        assert_eq!(
            (
                f.free_frames(),
                f.allocated_frames(),
                f.idle_reserved_frames()
            ),
            (64, 0, 0)
        );
    }
    // Quota and boot-range changes may not withdraw admitted backing.
    let mut f = arena.pool();
    f.set_quota(Some(8));
    f.admit(1, 8).unwrap();
    let start = arena.ptr.as_ptr() as u64;
    assert!(f.reserve(start + 8 * PAGE_SIZE, start + 64 * PAGE_SIZE));
    assert!(!f.reserve(start, start + PAGE_SIZE));
    assert_eq!(f.free_frames(), 8);
    assert_eq!(f.admit(2, 1), Err(AdmissionError::NoCapacity));
    let pages: Vec<_> = (0..8)
        .map(|_| f.allocate(FrameOwner::UserPage(1)).unwrap())
        .collect();
    for page in pages {
        f.free(page, FrameOwner::UserPage(1)).unwrap();
    }
    f.retire_reservation(1).unwrap();
    assert_eq!((f.free_frames(), f.idle_reserved_frames()), (8, 0));
    println!("HOST VM CONSTRUCTION OK partial_roots=2 quota_and_withdrawal=true");
}

unsafe fn retained_leaf_and_fixed_slots() {
    let arena = Arena::new(256);
    let mut f = arena.pool();
    f.admit(1, 4).unwrap();
    let mut space = unsafe { vm::create(&mut f, 1, 0) }.unwrap();
    assert_eq!(
        unsafe { vm::map_user_page(&mut f, &mut space, 1, USER_HEAP_BASE, true, false) },
        Err(vm::MapError::NoMemory)
    );
    assert!(!unsafe { vm::is_mapped(&space, USER_HEAP_BASE) });
    assert_eq!(f.reservation(1), Some((4, 4))); // the new leaf is retained and charged
    unsafe { vm::destroy(&mut f, &mut space, 1) }.unwrap();
    f.retire_reservation(1).unwrap();
    assert_eq!((f.free_frames(), f.idle_reserved_frames()), (256, 0));
    f.admit(2, 128).unwrap();
    let mut space = unsafe { vm::create(&mut f, 2, 0) }.unwrap();
    for i in 0..absd_kernel::process::MAX_USER_PAGE_TABLES {
        unsafe {
            vm::map_user_page(
                &mut f,
                &mut space,
                2,
                USER_REGION_BASE + i as u64 * (1 << 21),
                true,
                false,
            )
        }
        .unwrap();
    }
    let used = f.frames_owned_by(2);
    assert!(used < 128);
    assert_eq!(
        unsafe {
            vm::map_user_page(
                &mut f,
                &mut space,
                2,
                USER_REGION_BASE + 32 * (1 << 21),
                true,
                false,
            )
        },
        Err(vm::MapError::NoMemory)
    );
    assert_eq!(f.frames_owned_by(2), used);
    unsafe { vm::destroy(&mut f, &mut space, 2) }.unwrap();
    f.retire_reservation(2).unwrap();
    assert_eq!(
        (
            f.free_frames(),
            f.allocated_frames(),
            f.idle_reserved_frames()
        ),
        (256, 0, 0)
    );
    println!("HOST VM LIMITS OK retained_leaf_charged=true fixed_slots_not_backing=true");
}

unsafe fn contention_and_reuse() {
    let arena = Arena::new(512);
    for cycle in 0..64u32 {
        let mut f = arena.pool();
        let a = cycle * 3 + 1;
        let b = a + 1;
        let s = a + 2;
        f.admit(a, 128).unwrap();
        f.admit(s, 64).unwrap();
        let mut sa = unsafe { vm::create(&mut f, a, 0) }.unwrap();
        let mut sb = unsafe { vm::create(&mut f, b, 0) }.unwrap();
        let mut ss = unsafe { vm::create(&mut f, s, 0) }.unwrap();
        let mut bpages = 0;
        while unsafe {
            vm::map_user_page(
                &mut f,
                &mut sb,
                b,
                USER_HEAP_BASE + bpages * PAGE_SIZE,
                true,
                false,
            )
        }
        .is_ok()
        {
            bpages += 1;
        }
        assert_eq!(f.free_frames(), f.idle_reserved_frames());
        let mut apages = 0;
        while f.reservation(a).unwrap().1 < 128 {
            let physical = unsafe {
                vm::map_user_page(
                    &mut f,
                    &mut sa,
                    a,
                    USER_HEAP_BASE + apages * PAGE_SIZE,
                    true,
                    false,
                )
            }
            .unwrap();
            assert_eq!(
                unsafe { vm::translate(&sa, USER_HEAP_BASE + apages * PAGE_SIZE) },
                Some(physical)
            );
            assert_eq!(unsafe { (physical as *const u8).read_volatile() }, 0);
            unsafe { (physical as *mut u8).write_volatile(0xa5) };
            apages += 1;
        }
        assert_eq!(apages, 124); // three roots plus one leaf
        let sample = USER_HEAP_BASE + 17 * PAGE_SIZE;
        unsafe { vm::unmap_user_page(&mut f, &mut sa, a, sample) }.unwrap();
        let physical =
            unsafe { vm::map_user_page(&mut f, &mut sa, a, sample, true, false) }.unwrap();
        assert_eq!(unsafe { (physical as *const u8).read_volatile() }, 0);
        for i in 0..32 {
            unsafe {
                vm::map_user_page(
                    &mut f,
                    &mut ss,
                    s,
                    USER_HEAP_BASE + i * PAGE_SIZE,
                    true,
                    false,
                )
            }
            .unwrap();
        }
        for (pid, space) in [(a, &mut sa), (b, &mut sb), (s, &mut ss)] {
            unsafe { vm::destroy(&mut f, space, pid) }.unwrap();
            assert_eq!(f.frames_owned_by(pid), 0);
            f.retire_reservation(pid).unwrap();
            assert!(unsafe { vm::translate(space, USER_HEAP_BASE) }.is_none());
        }
        assert_eq!(
            (
                f.free_frames(),
                f.allocated_frames(),
                f.idle_reserved_frames()
            ),
            (512, 0, 0)
        );
    }
    println!("HOST VM CONTENTION OK cycles=64 zeroing_translation_reuse=true");
}
