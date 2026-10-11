pub(crate) fn rdrand64() -> Option<u64> {
    None
}
pub(super) fn syscall_wall_clock() -> i64 {
    absd_kernel::syscall::ERROR_NOT_IMPLEMENTED
}
