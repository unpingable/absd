//! Read-only boot diagnostics, independent of file server, network, and stdout.
//! Branch-local syscall 0x7fc0. Ordinary processes need the explicit inherited
//! read-only Diagnostics grant (startup role20), independent of stdout pipes.
//! Root init alone can fall back to its writable Console. No terminal input,
//! physical display-write, machine-control or clear authority is conferred.
pub use crate::kernel_log_wire::*;
pub fn read(cursor: &mut Cursor) -> Result<Read, i64> {
    read_with_handle(crate::diagnostics_handle(), cursor)
}
pub fn read_with_handle(handle: u64, cursor: &mut Cursor) -> Result<Read, i64> {
    let mut bytes = request(*cursor);
    let result = unsafe { crate::syscall3(0x7fc0, handle, bytes.as_mut_ptr() as u64, 0) };
    if result < 0 {
        return Err(result);
    }
    let read = decode(&bytes)?;
    cursor.0 = read.next;
    Ok(read)
}
