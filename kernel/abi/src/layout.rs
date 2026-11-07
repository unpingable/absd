//! Fixed virtual-memory layout shared by the kernel, loader, and user build.
//!
//! The kernel keeps the boot identity map of the first GiB in PML4 entry 0.
//! Every user address space lives entirely inside PML4 entry 1, so user page
//! tables never shadow physical memory the kernel reaches through the
//! identity map, and everything below that entry is kernel-global.

/// Whether this build selects the #115 self-host builder resource profile.
/// Without it every value below is the accepted default.
pub const BUILDER_PROFILE: bool = cfg!(feature = "builder-profile");
/// Whether this build carries the #115 builder envelope (x86_64 only).
pub const BUILDER_LARGE_ENVELOPE: bool = cfg!(feature = "builder-large-envelope");
/// First byte of PML4 entry 1; the user region begins here.
pub const USER_REGION_BASE: u64 = 0x0000_0080_0000_0000;
/// One page directory (1 GiB) is enough for the current user programs.
#[cfg(not(feature = "builder-large-envelope"))]
pub const USER_REGION_SIZE: u64 = 1 << 30;
/// #115 builder experiment: three page directories, so the heap window can
/// sit in GiBs 1-2 while the image and stack windows stay in GiB 0. Only the
/// ceiling grows; directories, tables and frames are allocated on demand.
#[cfg(feature = "builder-large-envelope")]
pub const USER_REGION_SIZE: u64 = 3 << 30;
/// Page directories (1 GiB each) and leaf tables (2 MiB each) the region spans.
pub const USER_DIRECTORIES: usize = (USER_REGION_SIZE >> 30) as usize;
pub const USER_LEAVES: usize = (USER_REGION_SIZE >> 21) as usize;
pub const USER_REGION_END: u64 = USER_REGION_BASE + USER_REGION_SIZE;
/// Accepted ELF `PT_LOAD` window; `user/linker.ld` places `.text` at its start.
pub const USER_IMAGE_MIN: u64 = USER_REGION_BASE + 0x0040_0000;
pub const USER_IMAGE_MAX: u64 = USER_REGION_BASE + 0x0400_0000;
/// Reserved grow-down user-stack region. Only the top `USER_STACK_PAGES`
/// pages are mapped initially; faults may map one adjacent page at a
/// time down to `USER_STACK_BASE`. The page immediately below the base is a
/// permanent guard.
pub const USER_STACK_BASE: u64 = USER_REGION_BASE + 0x0800_0000;
pub const USER_STACK_MAX_PAGES: usize = 1024;
pub const USER_STACK_PAGES: usize = 2;
pub const USER_STACK_TOP: u64 = USER_STACK_BASE + USER_STACK_MAX_PAGES as u64 * 4096;
/// Anonymous pages from `map` come from this window; `unmap` returns them.
/// 32 MiB: a program that measures a deployment file by reading it whole
/// (AG's pinned-file check reads a multi-megabyte resolver image) needs more
/// than the original 4 MiB. It is a per-process ceiling on address space;
/// frames are still mapped only by `map`.
#[cfg(not(feature = "builder-large-envelope"))]
pub const USER_HEAP_BASE: u64 = USER_REGION_BASE + 0x1000_0000;
#[cfg(not(feature = "builder-profile"))]
pub const USER_HEAP_PAGES: u64 = 8192;
/// The builder profile's 384 MiB window, for native compiler builds. Not a
/// supported ABI or resource promotion.
#[cfg(all(feature = "builder-profile", not(feature = "builder-large-envelope")))]
pub const USER_HEAP_PAGES: u64 = 98304;
/// #115 builder experiment: a 2 GiB window starting at GiB 1 of the region.
#[cfg(feature = "builder-large-envelope")]
pub const USER_HEAP_BASE: u64 = USER_REGION_BASE + (1 << 30);
#[cfg(feature = "builder-large-envelope")]
pub const USER_HEAP_PAGES: u64 = (2 << 30) / 4096;
pub const USER_HEAP_END: u64 = USER_HEAP_BASE + USER_HEAP_PAGES * 4096;
/// Heap pages a process holding a frame reservation may map, and the heap an
/// admitted service's budget backs. Without the builder envelope this is the
/// whole window. With it, a reserved process keeps the profile's 384 MiB heap
/// (its map search ends there, `frame_geometry::heap_search_end`), so its
/// heap cannot spend frames promised to its stack; only unreserved processes
/// get the large window.
#[cfg(not(feature = "builder-large-envelope"))]
pub const SERVICE_HEAP_PAGES: u64 = USER_HEAP_PAGES;
#[cfg(feature = "builder-large-envelope")]
pub const SERVICE_HEAP_PAGES: u64 = 98304;
pub const SERVICE_HEAP_END: u64 = USER_HEAP_BASE + SERVICE_HEAP_PAGES * 4096;
/// Whether this build carries the #115 builder class heap.
pub const BUILDER_CLASS_HEAP: bool = cfg!(feature = "builder-class-heap");
/// #115 builder class heap: the window of the builder class only (the
/// processes the durable self-host worker spawns, and their descendants;
/// `absd_kernel::builder_class`). 512 MiB: the native kernel link (E3 step 55)
/// maps at most 119,740 heap pages (467.7 MiB) with its window unconstrained,
/// and this keeps a 9.5 % margin. Every other process keeps `USER_HEAP_PAGES`.
#[cfg(feature = "builder-class-heap")]
pub const BUILDER_CLASS_HEAP_PAGES: u64 = 131072;
#[cfg(feature = "builder-class-heap")]
pub const BUILDER_CLASS_HEAP_END: u64 = USER_HEAP_BASE + BUILDER_CLASS_HEAP_PAGES * 4096;
/// End of the largest heap window any process of this build can have; the
/// leaf-table bound is derived from it.
#[cfg(not(feature = "builder-class-heap"))]
pub const MAX_HEAP_END: u64 = USER_HEAP_END;
#[cfg(feature = "builder-class-heap")]
pub const MAX_HEAP_END: u64 = BUILDER_CLASS_HEAP_END;
/// Addresses at or above this value are never valid user pointers.
pub const USER_ADDRESS_LIMIT: u64 = 0x0000_8000_0000_0000;
/// Contiguous physical pages for each process's kernel-mode stack.
#[cfg(not(feature = "builder-profile"))]
pub const KERNEL_STACK_PAGES: usize = 8;
/// The builder profile's 64 KiB kernel stack: the Cranelift spawn-many path
/// has over 38 KiB of fixed frames.
#[cfg(feature = "builder-profile")]
pub const KERNEL_STACK_PAGES: usize = 16;

const _: () = {
    assert!(USER_REGION_BASE >> 39 == 1);
    assert!(USER_IMAGE_MIN >= USER_REGION_BASE && USER_IMAGE_MAX <= USER_REGION_END);
    assert!(USER_STACK_BASE >= USER_IMAGE_MAX && USER_STACK_TOP <= USER_REGION_END);
    assert!(USER_STACK_PAGES < USER_STACK_MAX_PAGES);
    assert!(USER_HEAP_BASE >= USER_STACK_TOP && USER_HEAP_END <= USER_REGION_END);
    assert!(USER_HEAP_BASE.is_multiple_of(2 << 20));
    assert!(SERVICE_HEAP_PAGES <= USER_HEAP_PAGES);
    // The envelope is a variant of the profile, never a separate default.
    assert!(!BUILDER_LARGE_ENVELOPE || BUILDER_PROFILE);
    // The class heap is a variant of the 384 MiB profile only.
    assert!(!BUILDER_CLASS_HEAP || (BUILDER_PROFILE && !BUILDER_LARGE_ENVELOPE));
    assert!(MAX_HEAP_END >= USER_HEAP_END && MAX_HEAP_END <= USER_REGION_END);
    assert!(USER_REGION_END <= USER_ADDRESS_LIMIT);
    // The region stays inside PML4 entry 1 and is whole page directories.
    assert!(USER_REGION_SIZE.is_multiple_of(1 << 30) && USER_REGION_SIZE <= 1 << 39);
};
