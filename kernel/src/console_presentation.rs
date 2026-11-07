//! Private physical-presentation ownership, separate from diagnostic retention.
use crate::handle::{HandleError, HandleTable, RIGHT_WRITE};

pub const SYS_PRESENTATION: u64 = absd_abi::syscall::SYS_CONSOLE_PRESENTATION;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    Rights,
    Handle(HandleError),
    Invalid,
    Unsupported,
}

/// The real syscall's authority and argument checks, before changing state.
pub fn request(
    pid: u64,
    parent: u64,
    program: usize,
    handles: &HandleTable,
    console: u64,
    mode: u64,
    reserved: u64,
) -> Result<bool, RequestError> {
    if !crate::kernel_log::root_init_role(pid, parent, program) {
        return Err(RequestError::Rights);
    }
    handles
        .console(console, RIGHT_WRITE)
        .map_err(RequestError::Handle)?;
    if mode > 1 || reserved != 0 {
        return Err(RequestError::Invalid);
    }
    Ok(mode == 1)
}
