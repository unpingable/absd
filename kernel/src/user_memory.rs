//! Page-table walking and bounded copying for userspace pointers.

#[cfg(all(target_arch = "x86_64", not(absd_mutant_ignore_writable)))]
use crate::memory::ENTRY_WRITABLE;
use crate::memory::PAGE_SIZE;
#[cfg(target_arch = "x86_64")]
use crate::memory::{ENTRY_PRESENT, ENTRY_USER};
use crate::process::AddressSpace;

#[cfg(target_arch = "x86_64")]
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
#[cfg(target_arch = "x86_64")]
const HUGE_PAGE: u64 = 1 << 7;
pub use crate::layout::USER_ADDRESS_LIMIT;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserMemoryError {
    Empty,
    Overflow,
    SupervisorAddress,
    Unmapped,
    NotWritable,
    HugePage,
}

fn checked_range(address: u64, length: usize) -> Result<u64, UserMemoryError> {
    if length == 0 {
        return Err(UserMemoryError::Empty);
    }
    if address >= USER_ADDRESS_LIMIT {
        return Err(UserMemoryError::SupervisorAddress);
    }
    let end = address
        .checked_add(length as u64)
        .ok_or(UserMemoryError::Overflow)?;
    if end > USER_ADDRESS_LIMIT {
        return Err(UserMemoryError::SupervisorAddress);
    }
    Ok(end)
}

#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64/user_memory.rs"]
mod translation;
#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64/user_memory.rs"]
mod translation;
use translation::translated;

/// Copies bytes from a range validated against `space` into kernel memory.
///
/// # Safety
///
/// Every present page-table frame referenced by `space` must remain mapped and
/// readable through the kernel's physical-memory identity mapping for the
/// duration of this call.
pub unsafe fn copy_from_user(
    space: &AddressSpace,
    address: u64,
    destination: &mut [u8],
) -> Result<(), UserMemoryError> {
    let _ = checked_range(address, destination.len())?;
    let mut offset = 0usize;
    while offset < destination.len() {
        let user = address + offset as u64;
        // One walk per page: the translation holds for the rest of the page.
        let physical = unsafe { translated(space, user, false)? };
        let take = page_remainder(user).min(destination.len() - offset);
        unsafe {
            core::ptr::copy_nonoverlapping(
                physical as *const u8,
                destination[offset..].as_mut_ptr(),
                take,
            );
        }
        offset += take;
    }
    Ok(())
}

/// Bytes from `address` to the end of its page.
fn page_remainder(address: u64) -> usize {
    (PAGE_SIZE - (address & (PAGE_SIZE - 1))) as usize
}

/// Checks that every page of `[address, address + length)` is mapped user
/// memory with the requested writability, without touching its contents.
///
/// # Safety
///
/// Every present page-table frame referenced by `space` must remain mapped
/// and readable through the kernel's physical-memory identity mapping for
/// the duration of this call.
pub unsafe fn check_user_range(
    space: &AddressSpace,
    address: u64,
    length: usize,
    writable: bool,
) -> Result<(), UserMemoryError> {
    let end = checked_range(address, length)?;
    let mut page = address & !(PAGE_SIZE - 1);
    while page < end {
        unsafe { translated(space, page.max(address), writable)? };
        page += PAGE_SIZE;
    }
    Ok(())
}

/// Copies kernel bytes into a writable range validated against `space`.
///
/// # Safety
///
/// Every present page-table frame referenced by `space` must remain mapped and
/// writable through the kernel's physical-memory identity mapping for the
/// duration of this call.
pub unsafe fn copy_to_user(
    space: &AddressSpace,
    address: u64,
    source: &[u8],
) -> Result<(), UserMemoryError> {
    let _ = checked_range(address, source.len())?;
    let mut offset = 0usize;
    while offset < source.len() {
        let user = address + offset as u64;
        let physical = unsafe { translated(space, user, true)? };
        let take = page_remainder(user).min(source.len() - offset);
        unsafe {
            core::ptr::copy_nonoverlapping(source[offset..].as_ptr(), physical as *mut u8, take);
        }
        offset += take;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ranges_reject_empty_overflow_and_supervisor_addresses() {
        assert_eq!(checked_range(0x1000, 0), Err(UserMemoryError::Empty));
        assert_eq!(
            checked_range(u64::MAX - 1, 4),
            Err(UserMemoryError::SupervisorAddress)
        );
        assert_eq!(
            checked_range(USER_ADDRESS_LIMIT - 1, 2),
            Err(UserMemoryError::SupervisorAddress)
        );
        assert_eq!(checked_range(0x1000, 2), Ok(0x1002));
    }
    #[test]
    fn page_remainder_counts_to_the_page_end() {
        assert_eq!(page_remainder(0x1000), PAGE_SIZE as usize);
        assert_eq!(page_remainder(0x1ffe), 2);
        assert_eq!(page_remainder(0x1fff), 1);
    }
}
