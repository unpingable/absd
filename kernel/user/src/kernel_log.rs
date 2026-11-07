//! Experimental branch-local diagnostics. No supported ABI promotion.
#[path = "kernel_log_wire.rs"]
mod wire;
pub use wire::*;
pub const SYS_READ: u64 = 0x7fc0;
pub const SYS_SERVICE_APPEND: u64 = 0x7fc2;
/// Independent caller-owned position. 0 begins at retained oldest.
pub fn read(handle: u64, cursor: u64, frame: &mut [u8; FRAME_BYTES]) -> Result<(), i64> {
    *frame = request(Cursor::at(cursor));
    let result = unsafe { crate::syscall3(SYS_READ, handle, frame.as_mut_ptr() as u64, 0) };
    if result < 0 { Err(result) } else { Ok(()) }
}
/// Read with the shared checked v1 decoder. Handle zero resolves init's
/// retained Diagnostics grant; the display Console is not delegated.
pub fn read_decoded(handle: u64, cursor: u64) -> Result<Read, i64> {
    let mut frame = [0; FRAME_BYTES];
    read(handle, cursor, &mut frame)?;
    decode(&frame)
}
/// Init only. Services: 1 sshd, 2 fsd, 3 logd. Streams: 1 stdout, 2 stderr,
/// 3 lifecycle. Attribution is asserted by the kernel-established init role,
/// never by the service's own text. At most 256 bytes per append.
pub fn append_service(
    console: u64,
    pid: u64,
    service: u64,
    stream: u64,
    bytes: &[u8],
) -> Result<(), i64> {
    if bytes.len() > 256 {
        return Err(-22);
    }
    let mut frame = [0u8; 296];
    for (at, n) in [
        (0, 1),
        (8, pid),
        (16, service),
        (24, stream),
        (32, bytes.len() as u64),
    ] {
        frame[at..at + 8].copy_from_slice(&n.to_le_bytes());
    }
    frame[40..40 + bytes.len()].copy_from_slice(bytes);
    let result = unsafe { crate::syscall3(SYS_SERVICE_APPEND, console, frame.as_ptr() as u64, 0) };
    if result < 0 { Err(result) } else { Ok(()) }
}

/// Root-init-only read-only grant. Neither console input nor display write is copied.
pub fn mint_diagnostics(console: u64) -> Result<u64, i64> {
    let result = unsafe { crate::syscall3(0x7fc3, console, 0, 0) };
    if result < 0 {
        Err(result)
    } else {
        Ok(result as u64)
    }
}
