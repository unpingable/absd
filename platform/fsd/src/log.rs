//! The log files under `/var/log`: one per process that writes one (the
//! file server writes `fsd`, sshd `sshd`), each written only by its owner
//! through the ordinary filesystem, bounded, and readable by sessions.
//!
//! Bound: a log that would grow past [`LIMIT`] bytes is renamed to
//! `NAME.0` (replacing the previous `NAME.0`) and started again empty, so
//! each log holds at most `2 * LIMIT` bytes and the newest lines are always
//! kept. A line longer than [`MAX_LINE`] is cut there. When the filesystem
//! refuses a write (full, or a device failure) the line is dropped; the next
//! line that is written is preceded by `log: N lines dropped`.

use alloc::format;
use alloc::vec::Vec;

use absd_fs::{Device, Error, Fs, OpenFlags};

use crate::civil::Utc;

pub const DIR: &[u8] = b"/var/log";
/// Largest size of one log file before it is rotated.
pub const LIMIT: u64 = 64 * 1024;
/// Longest line kept, newline included.
pub const MAX_LINE: usize = 512;

/// `TIME PROGRAM: TEXT\n`, TIME the RTC's UTC second (`-` when the kernel
/// refuses a reading). Bytes outside printable ASCII become `?`.
pub fn line(wall: Option<u64>, program: &str, text: &str) -> Vec<u8> {
    let stamp = match wall {
        Some(seconds) => format!("{}", Utc::from_unix(seconds).iso()),
        None => "-".into(),
    };
    let mut out: Vec<u8> = format!("{stamp} {program}: ").into_bytes();
    out.extend(text.bytes().map(|b| if (0x20..0x7f).contains(&b) || b == b'\t' { b } else { b'?' }));
    out.truncate(MAX_LINE - 1);
    out.push(b'\n');
    out
}

/// Whether a log of `size` bytes must be rotated before `adding` more.
pub fn must_rotate(size: u64, adding: usize) -> bool {
    size > 0 && size + adding as u64 > LIMIT
}

/// The rotated name of `path`: `path.0`.
pub fn rotated(path: &[u8]) -> Vec<u8> {
    let mut name = path.to_vec();
    name.extend_from_slice(b".0");
    name
}

/// A log the file server writes into its own filesystem.
pub struct LogFile {
    path: Vec<u8>,
    program: &'static str,
    handle: Option<u64>,
    size: u64,
    pub dropped: u64,
}

impl LogFile {
    /// `program` names the writer in the lines this writes itself (the
    /// dropped-lines note).
    pub fn new(path: &[u8], program: &'static str) -> Self {
        Self { path: path.to_vec(), program, handle: None, size: 0, dropped: 0 }
    }

    fn open<D: Device>(&mut self, fs: &mut Fs<D>) -> Result<u64, Error> {
        if let Some(handle) = self.handle {
            return Ok(handle);
        }
        let flags = OpenFlags { read: false, write: true, create: true, create_new: false, truncate: false };
        let handle = fs.open(&self.path, flags)?;
        self.size = fs.fstat(handle)?.size;
        self.handle = Some(handle);
        Ok(handle)
    }

    fn rotate<D: Device>(&mut self, fs: &mut Fs<D>) -> Result<(), Error> {
        if let Some(handle) = self.handle.take() {
            fs.close(handle)?;
        }
        fs.rename(&self.path, &rotated(&self.path), false)?;
        let flags = OpenFlags { read: false, write: true, create: true, create_new: true, truncate: false };
        self.handle = Some(fs.open(&self.path, flags)?);
        self.size = 0;
        Ok(())
    }

    fn write<D: Device>(&mut self, fs: &mut Fs<D>, bytes: &[u8]) -> Result<(), Error> {
        let handle = self.open(fs)?;
        if must_rotate(self.size, bytes.len()) {
            self.rotate(fs)?;
        }
        let handle = self.handle.unwrap_or(handle);
        let written = fs.write_at(handle, self.size, bytes)?;
        self.size += written as u64;
        Ok(())
    }

    /// Appends one line; `Err` when it was dropped. The caller commits
    /// (the file server's idle commit covers it). `wall` stamps the
    /// dropped-lines note like any other line.
    pub fn append<D: Device>(&mut self, fs: &mut Fs<D>, wall: Option<u64>, text: &[u8]) -> Result<(), Error> {
        if self.dropped > 0 {
            let note = line(wall, self.program, &format!("log: {} lines dropped", self.dropped));
            if let Err(error) = self.write(fs, &note) {
                self.dropped += 1;
                return Err(error);
            }
            self.dropped = 0;
        }
        self.write(fs, text).inspect_err(|_| {
            self.dropped += 1;
            // Start from a fresh open next time (the handle may be gone
            // with a poisoned mount).
            if let Some(handle) = self.handle.take() {
                let _ = fs.close(handle);
            }
        })
    }
}
