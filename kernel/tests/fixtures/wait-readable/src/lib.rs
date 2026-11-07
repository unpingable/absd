#![no_std]

/// The supported ABI under test; the fixture owns no kernel substitute.
pub fn raw(address: u64, count: u64, timeout: u64) -> i64 {
    let result: i64;
    unsafe {
        core::arch::asm!("int 0x80",
            inout("rax") absd_abi::syscall::SYS_WAIT_READABLE => result,
            in("rdi") address, in("rsi") count, in("rdx") timeout,
            options(nostack));
    }
    result
}

pub fn wait(handles: &[u64], timeout: u64) -> i64 {
    absd_user::wait_readable(handles, timeout).map(|mask| mask as i64).unwrap_or_else(|error| error.code())
}
