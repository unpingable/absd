//! ABSD substitute for the `ctrlc` crate.
//!
//! The Pulse runtime depends on `pulse-agent`, whose executable installs a
//! Ctrl-C handler. ABSD has no signals and no terminal, so this crate keeps
//! the same public entry point and refuses at runtime. It is build-resolution
//! scaffolding for the experimental target, not an ABSD runtime semantic.
#![no_std]

use core::fmt;

#[derive(Debug)]
pub enum Error {
    /// This platform has no signal delivery.
    System(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System(detail) => write!(formatter, "ctrlc unavailable: {detail}"),
        }
    }
}

pub fn set_handler<F>(_handler: F) -> Result<(), Error>
where
    F: FnMut() + 'static + Send,
{
    Err(Error::System("ABSD delivers no signals"))
}
