//! Fixed virtual-memory layout shared by the kernel, loader, and user build.
//!
//! The kernel keeps the boot identity map of the first GiB in PML4 entry 0.
//! Every user address space lives entirely inside PML4 entry 1, so user page
//! tables never shadow physical memory the kernel reaches through the
//! identity map, and everything below that entry is kernel-global.

/// First byte of PML4 entry 1; the user region begins here.
pub const USER_REGION_BASE: u64 = 0x0000_0080_0000_0000;
/// One page directory (1 GiB) is enough for the current user programs.
pub const USER_REGION_SIZE: u64 = 1 << 30;
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
pub const USER_HEAP_BASE: u64 = USER_REGION_BASE + 0x1000_0000;
pub const USER_HEAP_PAGES: u64 = 8192;
pub const USER_HEAP_END: u64 = USER_HEAP_BASE + USER_HEAP_PAGES * 4096;
/// Addresses at or above this value are never valid user pointers.
pub const USER_ADDRESS_LIMIT: u64 = 0x0000_8000_0000_0000;
/// Contiguous physical pages for each process's kernel-mode stack.
pub const KERNEL_STACK_PAGES: usize = 8;

const _: () = {
    assert!(USER_REGION_BASE >> 39 == 1);
    assert!(USER_IMAGE_MIN >= USER_REGION_BASE && USER_IMAGE_MAX <= USER_REGION_END);
    assert!(USER_STACK_BASE >= USER_IMAGE_MAX && USER_STACK_TOP <= USER_REGION_END);
    assert!(USER_STACK_PAGES < USER_STACK_MAX_PAGES);
    assert!(USER_HEAP_BASE >= USER_STACK_TOP && USER_HEAP_END <= USER_REGION_END);
    assert!(USER_HEAP_BASE.is_multiple_of(2 << 20));
    assert!(USER_REGION_END <= USER_ADDRESS_LIMIT);
};
