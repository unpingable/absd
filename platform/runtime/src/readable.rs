use super::{SYS_WAIT_READABLE, syscall3};

pub const WAIT_READABLE_MAX: usize = 11;
pub const WAIT_READABLE_POLL: u64 = u64::MAX;

/// Level notification for readable Pipe/Console handles, including pipe EOF.
/// A following read can still block or fail. Zero ticks waits indefinitely;
/// WAIT_READABLE_POLL returns zero when idle; finite expiry returns -110.
/// Additive ABI 1 call. All requests reach the kernel, including an empty
/// slice, so an older kernel consistently returns -38. No polling fallback.
pub fn wait_readable(handles: &[u64], ticks: u64) -> Result<u64, i64> {
    let result = unsafe { syscall3(SYS_WAIT_READABLE, handles.as_ptr() as u64, handles.len() as u64, ticks) };
    if result < 0 { Err(result) } else { Ok(result as u64) }
}
