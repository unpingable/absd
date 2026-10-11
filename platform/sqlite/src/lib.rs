#![feature(restricted_std)]

//! SQLite on ABSD: the amalgamation is built with `SQLITE_OS_OTHER`, so
//! SQLite calls `sqlite3_os_init` here and uses only the VFS this crate
//! registers. That VFS maps SQLite's file, lock, and shared-memory
//! interfaces directly onto the mounted `absd-fs` instance: no POSIX layer.

mod libc;
mod mutex;
mod vfs;

pub use vfs::{VFS_NAME, lock_holders};

/// Installs SQLite's mutexes, initializes it (which registers the `absd`
/// VFS as the default), and keeps this crate's C symbols in the link. Call
/// once, before any other SQLite use.
pub fn initialize() {
    let status = mutex::initialize();
    assert_eq!(status, libsqlite3_sys::SQLITE_OK, "SQLite initialization");
}
