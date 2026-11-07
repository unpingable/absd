//! The production wrapper with a kernel transport fixture, never host int80.
#[path = "../../runtime/src/readable.rs"]
mod readable;

use std::sync::Mutex;
const SYS_WAIT_READABLE: u64 = 0x7fa8;
static CALLS: Mutex<Vec<(u64, u64, u64)>> = Mutex::new(Vec::new());

unsafe fn syscall3(number: u64, _address: u64, count: u64, ticks: u64) -> i64 {
    CALLS.lock().unwrap().push((number, count, ticks));
    // A pre-addition ABI 1 kernel refuses the number before its arguments.
    -38
}

#[test]
fn old_kernel_refusal_is_preserved_for_empty_valid_and_oversized_sets() {
    assert_eq!(readable::WAIT_READABLE_MAX, 11);
    assert_eq!(readable::WAIT_READABLE_POLL, u64::MAX);
    for count in [0, 1, 11, 12] {
        let handles = vec![0x1234_5678; count];
        assert_eq!(readable::wait_readable(&handles, u64::MAX), Err(-38));
    }
    assert_eq!(*CALLS.lock().unwrap(), vec![
        (0x7fa8, 0, u64::MAX), (0x7fa8, 1, u64::MAX),
        (0x7fa8, 11, u64::MAX), (0x7fa8, 12, u64::MAX),
    ]);
}
