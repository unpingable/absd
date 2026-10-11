//! ABSD file server (`absd-fsd`): one process holds the only read-write
//! block handle of the session-visible filesystem and serves every other
//! process over pre-minted pipe channels (kernel `docs/PROCESS-STARTUP.md`,
//! "File server"). This crate is the part the host can test: the wire
//! protocol, mount-list resolution, and the request dispatcher over
//! `absd-fs`, and what the loop does with the bytes a channel delivered
//! (`inbox`). The polling loop over the kernel's pipes is
//! `ssh/src/fsd_server.rs`.
//!
//! Authority: a channel is a capability. Its record in the server holds a
//! mount list (subtrees, each read-only or read-write) and an open-file
//! table. Paths resolve server-side under the mount list; `..` is taken
//! lexically and cannot leave it; there are no symbolic links. A handle is
//! a number in the channel's own table, so no channel can name another's
//! open file.
//!
//! Coherence: the server runs one request at a time to completion, so
//! every client sees one namespace and one set of file contents. Two
//! writes to the same bytes land in the order the server received them:
//! the later request wins for the bytes both cover, and each `write_at`
//! request is applied whole or not at all. A frame is bound to the holder
//! that wrote it (`proto`: the holder's sequence word and a check over the
//! frame), so a request cut off mid-frame by its holder's death is dropped
//! and can never be completed by the next holder of the channel, whose own
//! first request is taken whole from the boundary it wrote it at
//! (`inbox`).

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod civil;
pub mod inbox;
pub mod log;
pub mod proto;
pub mod recovery;
pub mod release;
mod server;
pub mod version;
#[cfg(test)]
mod tests;

pub use inbox::{Inbox, Taken};
pub use server::{CONTROL, Event, PipeState, Server};
