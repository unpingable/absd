//! Private, read-only terminal size observation. No termios or input authority.
//! The session service retains the only writer; children receive read rights.
use core::sync::atomic::{AtomicU64, Ordering};
use crate::{RIGHT_READ, close, duplicate, syscall3};
#[path = "terminal_wire.rs"]
mod wire;
pub use wire::{LOCAL, SSH, Size};
static OWN: AtomicU64 = AtomicU64::new(0);
static NEXT: AtomicU64 = AtomicU64::new(0);
pub(crate) fn install(handle: u64) { OWN.store(handle, Ordering::Relaxed); }
pub(crate) fn handle() -> u64 { OWN.load(Ordering::Relaxed) }
/// Latest session observation. Missing role or invalid schema remains unknown.
pub fn size() -> Option<Size> {
    let handle = handle();
    if handle == 0 { return None; }
    let mut record = [0u64; 2];
    if unsafe { syscall3(11, handle, record.as_mut_ptr() as u64, 0) } < 0 { return None; }
    Size::decode(record[1])
}
/// Session-owned writer, closed with the session child. No private input stored.
pub struct Publisher { handle: u64, version: u64 }
impl Publisher {
    pub fn new(size: Size) -> Result<Self, i64> {
        let handle = unsafe { syscall3(10, size.encode(), 0, 0) };
        if handle < 0 { return Err(handle); }
        Ok(Self { handle: handle as u64, version: 0 })
    }
    pub fn update(&mut self, size: Size) -> Result<(), i64> {
        let version = unsafe { syscall3(12, self.handle, self.version, size.encode()) };
        if version < 0 { return Err(version); }
        self.version = version as u64;
        Ok(())
    }
    /// Arm one spawn only; failure and cancellation close the read-only copy.
    pub fn give_next_child(&self) -> Result<(), i64> {
        cancel_next_child();
        NEXT.store(duplicate(self.handle, RIGHT_READ)?, Ordering::Relaxed);
        Ok(())
    }
}
impl Drop for Publisher { fn drop(&mut self) { let _ = close(self.handle); } }
pub(crate) struct Child { pub(crate) handle: u64 }
impl Drop for Child { fn drop(&mut self) { let _ = close(self.handle); } }
pub(crate) fn take_next() -> Option<Child> {
    match NEXT.swap(0, Ordering::Relaxed) { 0 => None, handle => Some(Child { handle }) }
}
pub fn cancel_next_child() { drop(take_next()); }
/// Native observation for C commands. Zero means unknown, one means known.
/// This is a private helper, not ioctl, isatty, termios, or a new syscall ABI.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __absd_terminal_size(columns: *mut u32, rows: *mut u32) -> i32 {
    let Some(size) = size().filter(|s| s.columns != 0 && s.rows != 0) else { return 0; };
    if columns.is_null() || rows.is_null() { return 0; }
    unsafe { columns.write(size.columns); rows.write(size.rows); }
    1
}
