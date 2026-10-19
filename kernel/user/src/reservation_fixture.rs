//! Private numbers and controls for this experiment, deliberately outside absd-abi.
use absd_user::{Cell, Error, syscall3};
pub const ADMIT: u64 = 0x7ff0;
pub const SPAWN: u64 = 0x7ff1;
pub const QUERY: u64 = 0x7ff2;
pub const SPAWN_IMAGE: u64 = 0x7ff3;
pub const ABORT_IMAGE: u64 = 0x7ff4;
pub fn call(n: u64, a: u64, b: u64, c: u64) -> i64 {
    unsafe { syscall3(n, a, b, c) }
}
pub fn set(cell: Cell, value: u64) -> Result<(), Error> {
    let (version, _) = cell.read()?;
    cell.transition(version, value).map(|_| ())
}
pub fn until(cell: Cell, expected: u64) -> Result<(), Error> {
    loop {
        let (version, value) = cell.read()?;
        if value & 0xffff == expected {
            return Ok(());
        }
        if value == 999 {
            return Err(Error::Invalid);
        }
        cell.wait_change_timeout(version, 1000)?;
    }
}
pub fn touch(p: *mut u8, pages: usize) {
    for i in 0..pages {
        unsafe {
            p.add(i * 4096).write_volatile(0xa5);
        }
    }
}

/// Serialized guest TSC observation; no clock-rate or latency guarantee.
pub fn ticks() -> u64 {
    unsafe {
        core::arch::asm!("lfence", options(nostack, preserves_flags));
        core::arch::x86_64::_rdtsc()
    }
}
