//! A session control channel (startup roles 16 and 17): two pipes between
//! an interactive session's shell and the server that started it (sshd),
//! beside the shell's standard streams, never inside them.
//!
//! * events: the server writes, the shell reads (^C typed on the session's
//!   terminal, the server's replies);
//! * requests: the shell writes, the server reads.
//!
//! Handles reach a process only when it is spawned, so the server creates
//! both pipes before it starts the shell ([`give_next_child`]) and keeps
//! the opposite ends. The runtime passes them to the next child only and
//! closes its copies of the child's ends right after that spawn, whether
//! it succeeded or not, so end of file on either pipe means the other side
//! is gone. A process that received the channel ([`channel`]) never passes
//! it on: `std::process` gives children only what the parent names, and
//! nothing names these. What travels on the pipes is the server's and the
//! shell's business (the platform's `ssh/src/control.rs`), not the runtime's.

use core::cell::Cell;

use crate::{RIGHT_READ, RIGHT_WRITE, duplicate, syscall3};

const SYS_CLOSE: u64 = 9;
const SYS_PIPE_CREATE: u64 = 16;

struct Global(Cell<[u64; 2]>);
// Single-threaded: written by the CRT before `main`, then by this module.
unsafe impl Sync for Global {}

/// This process's own ends (events reader, requests writer), from its
/// startup record; zero when it has none.
static OWN: Global = Global(Cell::new([0, 0]));
/// The next child's ends (events reader, requests writer), once armed.
static NEXT: Global = Global(Cell::new([0, 0]));

pub(crate) fn install(events: u64, requests: u64) {
    OWN.0.set([events, requests]);
}

/// This process's session control channel, `(events reader, requests
/// writer)`, when the process that started it gave it one.
pub fn channel() -> Option<(u64, u64)> {
    match OWN.0.get() {
        [0, _] | [_, 0] => None,
        [events, requests] => Some((events, requests)),
    }
}

fn close(handle: u64) {
    if handle != 0 {
        unsafe { syscall3(SYS_CLOSE, handle, 0, 0) };
    }
}

/// A new pipe split into `(reader, writer)`.
fn pipe() -> Result<(u64, u64), i64> {
    let both = unsafe { syscall3(SYS_PIPE_CREATE, 0, 0, 0) };
    if both < 0 {
        return Err(both);
    }
    let both = both as u64;
    let reader = duplicate(both, RIGHT_READ);
    let writer = duplicate(both, RIGHT_WRITE);
    close(both);
    match (reader, writer) {
        (Ok(reader), Ok(writer)) => Ok((reader, writer)),
        (reader, writer) => {
            close(reader.unwrap_or(0));
            close(writer.unwrap_or(0));
            Err(reader.and(writer).err().unwrap_or(-12))
        }
    }
}

/// Creates a control channel for the next child this process starts with
/// `std::process` and returns this process's ends, `(events writer,
/// requests reader)`, which the caller owns and closes. A channel armed
/// earlier and not yet spent is closed first.
pub fn give_next_child() -> Result<(u64, u64), i64> {
    drop(take_next());
    let (events_reader, events_writer) = pipe()?;
    let (requests_reader, requests_writer) = match pipe() {
        Ok(ends) => ends,
        Err(code) => {
            close(events_reader);
            close(events_writer);
            return Err(code);
        }
    };
    NEXT.0.set([events_reader, requests_writer]);
    Ok((events_writer, requests_reader))
}

/// The next child's ends, taken by the spawn that uses (or fails to use)
/// them; dropping this closes this process's copies.
pub(crate) struct ChildEnds {
    pub(crate) events: u64,
    pub(crate) requests: u64,
}

impl Drop for ChildEnds {
    fn drop(&mut self) {
        close(self.events);
        close(self.requests);
    }
}

pub(crate) fn take_next() -> Option<ChildEnds> {
    match NEXT.0.replace([0, 0]) {
        [0, 0] => None,
        [events, requests] => Some(ChildEnds { events, requests }),
    }
}

/// Closes a channel armed with [`give_next_child`] that no spawn took
/// (a spawn that failed before reaching the runtime), so that it cannot
/// reach a later, unrelated child.
pub fn cancel_next_child() {
    drop(take_next());
}
