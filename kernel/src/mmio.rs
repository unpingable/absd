//! Uncached kernel mappings for device memory.
//!
//! The boot page tables identity-map only the first GiB (write-back RAM).
//! A framebuffer or a PCI BAR can be anywhere in the physical address space
//! (firmware often places 64-bit BARs far above 512 GiB), so device ranges
//! are mapped into a kernel window at 256..260 GiB virtual: 2 MiB
//! supervisor-only, non-executable, cache-disabled pages installed in the
//! shared boot PDPT. Every process address space points its PML4 entry 0
//! at that same PDPT, so the mapping is visible in every CR3 without
//! copying. Page directories come from a small static pool; mappings are
//! never removed, and a request inside a range already mapped with the same
//! attributes returns the existing address.

use crate::vm::ADDRESS_MASK;

const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const WRITE_THROUGH: u64 = 1 << 3;
const CACHE_DISABLE: u64 = 1 << 4;
const HUGE: u64 = 1 << 7;
const NO_EXECUTE: u64 = 1 << 63;
const TWO_MIB: u64 = 2 * 1024 * 1024;
const ONE_GIB: u64 = 1024 * 1024 * 1024;
/// The device window starts at PDPT index 256 of PML4 entry 0; one page
/// directory from the pool covers each GiB of it.
const WINDOW_FIRST_GIB: u64 = 256;
const DIRECTORY_POOL: usize = 4;
const WINDOW_BASE: u64 = WINDOW_FIRST_GIB * ONE_GIB;
const WINDOW_END: u64 = WINDOW_BASE + DIRECTORY_POOL as u64 * ONE_GIB;
/// Physical addresses a 2 MiB page entry can name.
const PHYSICAL_LIMIT: u64 = 1 << 52;
const REGIONS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cache {
    /// PCD|PWT: strong uncacheable, for device registers.
    Uncached,
    /// PCD only (PAT UC-): uncached, but a firmware write-combining MTRR
    /// still applies, which is what a framebuffer wants.
    UncachedMinus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapError {
    /// The range overlaps the first GiB, which is already mapped write-back
    /// as RAM; an uncached alias would conflict with it.
    InFirstGigabyte,
    /// The range reaches beyond what a page entry can address.
    AbovePhysicalLimit,
    /// The device window or the region table is full.
    WindowFull,
    /// Part of the range is already mapped with other cache attributes.
    Conflict,
    Empty,
    Frozen,
}

#[repr(C, align(4096))]
struct Directory([u64; 512]);

#[derive(Clone, Copy)]
struct Region {
    /// 2 MiB-aligned physical bounds.
    physical: u64,
    end: u64,
    virtual_base: u64,
    cache: Cache,
}

static mut POOL: [Directory; DIRECTORY_POOL] = [const { Directory([0; 512]) }; DIRECTORY_POOL];
static mut MAPPED: [Option<Region>; REGIONS] = [None; REGIONS];
/// Next free virtual address in the window.
static mut NEXT: u64 = WINDOW_BASE;
static FROZEN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn freeze() {
    crate::kernel_lock::assert_held(crate::kernel_lock::BSP);
    assert!(!FROZEN.swap(true, core::sync::atomic::Ordering::AcqRel));
    let before = snapshot();
    assert_eq!(map(1 << 51, 4096, Cache::Uncached), Err(MapError::Frozen));
    assert_eq!(snapshot(), before);
    crate::serial::write("SMP MMIO FROZEN new-map=refused\n");
}
/// Exact cursor/region count plus a diagnostic digest of mapping fields.
/// Hardware may set accessed/dirty bits after SIPI without changing a mapping.
/// Safety derives from the frozen write boundary, not digest collision odds.
pub fn snapshot() -> (u64, usize, u64) {
    crate::kernel_lock::assert_held(crate::kernel_lock::BSP);
    let mut digest = 0u64;
    unsafe {
        let entries = core::ptr::addr_of!(POOL).cast::<u64>();
        for index in 0..DIRECTORY_POOL * 512 {
            // Page walkers update A/D concurrently with kernel execution.
            // Retain every software-controlled address/attribute bit.
            let entry = core::ptr::read_volatile(entries.add(index));
            digest = digest.rotate_left(7) ^ (entry & !((1 << 5) | (1 << 6)));
        }
        (
            NEXT,
            (*core::ptr::addr_of!(MAPPED)).iter().flatten().count(),
            digest,
        )
    }
}

fn boot_pdpt() -> *mut u64 {
    unsafe extern "C" {
        static boot_pml4: u8;
    }
    let pml4 = core::ptr::addr_of!(boot_pml4) as *const u64;
    (unsafe { core::ptr::read_volatile(pml4) } & ADDRESS_MASK) as *mut u64
}

/// Maps `[physical, physical + length)` and returns the virtual address of
/// `physical`.
pub fn map(physical: u64, length: u64, cache: Cache) -> Result<u64, MapError> {
    if length == 0 {
        return Err(MapError::Empty);
    }
    let end = physical
        .checked_add(length)
        .filter(|&end| end <= PHYSICAL_LIMIT)
        .ok_or(MapError::AbovePhysicalLimit)?;
    if physical < ONE_GIB {
        return Err(MapError::InFirstGigabyte);
    }
    let start = physical & !(TWO_MIB - 1);
    let end = end.next_multiple_of(TWO_MIB);
    let regions = unsafe { &mut *core::ptr::addr_of_mut!(MAPPED) };
    let overlapping = || {
        regions
            .iter()
            .flatten()
            .filter(move |region| start < region.end && region.physical < end)
    };
    if overlapping().any(|region| region.cache != cache) {
        return Err(MapError::Conflict);
    }
    if let Some(region) = overlapping().find(|region| region.physical <= start && end <= region.end)
    {
        return Ok(region.virtual_base + (physical - region.physical));
    }
    if FROZEN.load(core::sync::atomic::Ordering::Acquire) {
        return Err(MapError::Frozen);
    }
    // A larger request over part of an existing range gets its own alias
    // with the same attributes, which x86 permits.
    let slot = regions
        .iter()
        .position(Option::is_none)
        .ok_or(MapError::WindowFull)?;
    let base = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(NEXT)) };
    let top = base
        .checked_add(end - start)
        .filter(|&top| top <= WINDOW_END)
        .ok_or(MapError::WindowFull)?;
    let attributes = PRESENT
        | WRITABLE
        | HUGE
        | NO_EXECUTE
        | match cache {
            Cache::Uncached => CACHE_DISABLE | WRITE_THROUGH,
            Cache::UncachedMinus => CACHE_DISABLE,
        };
    let pdpt = boot_pdpt();
    let mut page = start;
    let mut virtual_page = base;
    while page < end {
        let gib = virtual_page / ONE_GIB;
        let slot = unsafe { pdpt.add(gib as usize) };
        let mut entry = unsafe { core::ptr::read_volatile(slot) };
        if entry & PRESENT == 0 {
            // The kernel image is identity-mapped: the static's address is
            // its physical address.
            let directory =
                unsafe { core::ptr::addr_of_mut!(POOL[(gib - WINDOW_FIRST_GIB) as usize]) }
                    as *mut u64;
            for index in 0..512 {
                unsafe { core::ptr::write_volatile(directory.add(index), 0) };
            }
            entry = directory as u64 | PRESENT | WRITABLE;
            unsafe { core::ptr::write_volatile(slot, entry) };
        }
        let directory = (entry & ADDRESS_MASK) as *mut u64;
        let index = ((virtual_page % ONE_GIB) / TWO_MIB) as usize;
        unsafe { core::ptr::write_volatile(directory.add(index), page | attributes) };
        crate::invalidate_page(virtual_page);
        page += TWO_MIB;
        virtual_page += TWO_MIB;
    }
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(NEXT), top) };
    regions[slot] = Some(Region {
        physical: start,
        end,
        virtual_base: base,
        cache,
    });
    Ok(base + (physical - start))
}
