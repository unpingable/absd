//! Experimental clock-owner mint, root init only.
pub fn mint(console: u64) -> Result<u64, i64> {
    let r = unsafe { crate::syscall3(0x7fb2, console, 0, 0) };
    if r < 0 { Err(r) } else { Ok(r as u64) }
}
