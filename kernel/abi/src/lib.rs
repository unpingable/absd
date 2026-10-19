//! Definitions shared by the ABSD kernel and its userspace programs.
//!
//! Anything both sides must agree on lives here so it cannot drift: the
//! `int 0x80` numbers and error values, the fixed user virtual layout, the
//! embedded program catalog order, and the `wait` outcome record encoding.
#![no_std]

pub mod layout;
pub mod nic;
pub mod program;
pub mod syscall;

/// The generation of the kernel syscall ABI: the numbers, argument
/// conventions, record layouts, and error values in this crate, taken as one
/// unit. `abi_version` (syscall 42) returns it. Any change that would make a
/// program built against the previous definitions misbehave (a renumbered or
/// re-purposed syscall, a changed record layout or error meaning) increments
/// it; adding a syscall that older programs never call does not. The
/// platform repository hand-copies the syscall table rather than depending on
/// this crate, and compiles in the same value; its runtime refuses to start
/// (status 103) when the kernel answers anything else.
///
/// A new error value returned only where the previous generation disabled
/// the device (`nic_send`'s `ERROR_NO_CARRIER`, a transmit bound expiring
/// without carrier) does not increment it: `ERROR_IO` keeps its meaning,
/// and a program built against the previous definitions already treats the
/// call as fallible.
pub const KERNEL_ABI: u64 = 1;
