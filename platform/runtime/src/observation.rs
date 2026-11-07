//! Private operator diagnostics, version 1, experimental syscall 0x7fc1.
//! Explicit inherited read-only Diagnostics authority; no mutation or device grant.
use super::syscall3;
pub const BYTES: usize = 256;
#[path = "capacity_wire.rs"]
mod capacity_wire;
pub use capacity_wire::Capacity;
/// Unsupported older kernels report unknown rather than a partial16-row census.
pub fn capacity() -> Result<Capacity,i64> {capacity_wire::decode(&read(capacity_wire::QUERY)?)}

pub fn read(query: u64) -> Result<[u8; BYTES], i64> {
    let mut bytes = [0u8; BYTES];
    let result = unsafe { syscall3(0x7fc1, 0, bytes.as_mut_ptr() as u64, query) };
    if result < 0 { return Err(result); }
    if word(&bytes, 0) != 1 { return Err(-22); }
    Ok(bytes)
}

pub fn word(record: &[u8; BYTES], index: usize) -> u64 {
    u64::from_le_bytes(record[index * 8..index * 8 + 8].try_into().expect("fixed diagnostic frame"))
}

pub fn state(value: u64) -> &'static str {
    match value { 0 => "empty", 1 => "starting", 2 => "runnable", 3 => "running", 4 => "waiting", 5 => "exited", 6 => "faulted", 7 => "killed", _ => "unknown" }
}
pub fn wait(value: u64) -> &'static str {
    match value { 0 => "-", 1 => "child", 2 => "cell", 3 => "pipe", 4 => "console", 5 => "sleep", 6 => "rt-release", 7 => "nic", 8 => "stop-fence", 9 => "readable", _ => "unknown" }
}
