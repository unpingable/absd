use crate::serial;
use absd_kernel::syscall::ERROR_IO;
pub(crate) fn rdrand64() -> Option<u64> {
    let ecx = core::arch::x86_64::__cpuid(1).ecx;
    if ecx & (1 << 30) == 0 {
        return None;
    }
    for _ in 0..10 {
        let value: u64;
        let ok: u8;
        unsafe {
            core::arch::asm!("rdrand {value}", "setc {ok}", value = out(reg) value, ok = out(reg_byte) ok, options(nomem, nostack));
        }
        if ok == 1 {
            return Some(value);
        }
    }
    None
}

fn cmos_read(register: u8) -> u8 {
    // Bit 7 of the index keeps NMIs masked while the index is selected.
    unsafe {
        serial::outb(0x70, 0x80 | register);
        serial::inb(0x71)
    }
}

fn cmos_snapshot() -> Option<absd_kernel::rtc::Snapshot> {
    use absd_kernel::rtc::*;
    // An update cycle may begin at any moment; wait until none is in
    // progress (bounded: one lasts under 2 ms), then read.
    let mut spins = 0u32;
    while cmos_read(STATUS_A) & UPDATE_IN_PROGRESS != 0 {
        spins += 1;
        if spins > 1_000_000 {
            return None;
        }
        core::hint::spin_loop();
    }
    Some(Snapshot {
        seconds: cmos_read(SECONDS),
        minutes: cmos_read(MINUTES),
        hours: cmos_read(HOURS),
        day: cmos_read(DAY),
        month: cmos_read(MONTH),
        year: cmos_read(YEAR),
        status_b: cmos_read(STATUS_B),
    })
}

/// `wall_clock()`: the CMOS RTC as Unix seconds (see the ABI). Two equal
/// consecutive snapshots are required, so a read that straddled an update
/// is never decoded; after a bounded number of attempts it is refused.
pub(super) fn syscall_wall_clock() -> i64 {
    let mut previous = cmos_snapshot();
    for _ in 0..8 {
        let next = cmos_snapshot();
        if let (Some(a), Some(b)) = (previous, next)
            && a == b
        {
            return match absd_kernel::rtc::unix_seconds(a) {
                Some(seconds) => seconds as i64,
                None => ERROR_IO,
            };
        }
        previous = next;
    }
    ERROR_IO
}
