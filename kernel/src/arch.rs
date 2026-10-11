//! ISA execution boundary. Generic policy must not decode machine state.
#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64/mod.rs"]
mod implementation;
#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64/mod.rs"]
mod implementation;
pub use implementation::*;

/// Semantic entry and completion access; no generic register indices.
pub trait ExecutionState {
    fn argument(&self, index: usize) -> u64;
    fn set_argument(&mut self, index: usize, value: u64);
    fn set_stack(&mut self, value: u64);
    fn set_result(&mut self, value: i64);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultClass {
    Translation,
    Permission,
    Alignment,
    Undefined,
    FloatingPoint,
    Other,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Access {
    Read,
    Write,
    Execute,
}
#[derive(Clone, Copy, Debug)]
pub struct MemoryFault {
    pub class: FaultClass,
    pub access: Access,
    pub from_user: bool,
}

/// Architecture-normalized exception metadata; raw wait evidence is separate.
#[derive(Clone, Copy, Debug)]
pub struct UserFault {
    pub class: FaultClass,
    pub access: Option<Access>,
    pub from_user: bool,
    pub address: u64,
}
impl FaultClass {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Translation => "translation",
            Self::Permission => "permission",
            Self::Alignment => "alignment",
            Self::Undefined => "undefined",
            Self::FloatingPoint => "floating-point",
            Self::Other => "other",
        }
    }
}
impl Access {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Execute => "execute",
        }
    }
}
