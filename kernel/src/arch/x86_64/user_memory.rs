use super::*;
pub(super) unsafe fn translated(
    space: &AddressSpace,
    address: u64,
    writable: bool,
) -> Result<u64, UserMemoryError> {
    if address >= USER_ADDRESS_LIMIT {
        return Err(UserMemoryError::SupervisorAddress);
    }
    let indexes = [
        ((address >> 39) & 0x1ff) as usize,
        ((address >> 30) & 0x1ff) as usize,
        ((address >> 21) & 0x1ff) as usize,
        ((address >> 12) & 0x1ff) as usize,
    ];
    let mut table = space.root as *const u64;
    for (level, index) in indexes.into_iter().enumerate() {
        let entry = unsafe { core::ptr::read_volatile(table.add(index)) };
        if entry & (ENTRY_PRESENT | ENTRY_USER) != (ENTRY_PRESENT | ENTRY_USER) {
            return Err(UserMemoryError::Unmapped);
        }
        #[cfg(absd_mutant_ignore_writable)]
        let _ = writable;
        #[cfg(not(absd_mutant_ignore_writable))]
        if writable && entry & ENTRY_WRITABLE == 0 {
            return Err(UserMemoryError::NotWritable);
        }
        if level < 3 && entry & HUGE_PAGE != 0 {
            return Err(UserMemoryError::HugePage);
        }
        if level == 3 {
            return Ok((entry & ADDRESS_MASK) + (address & (PAGE_SIZE - 1)));
        }
        table = (entry & ADDRESS_MASK) as *const u64;
    }
    Err(UserMemoryError::Unmapped)
}
