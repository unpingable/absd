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

use absd_fs::{Error, OpenFlags};
use crate::journal::Store;

use crate::civil::Utc;

pub const DIR: &[u8] = b"/var/log";
/// Largest size of one log file before it is rotated.
pub const LIMIT: u64 = 64 * 1024;
/// Longest line kept, newline included.
pub const MAX_LINE: usize = 512;

/// `TIME PROGRAM: TEXT\n`, TIME the boot-local software civil second formatted
/// as a calendar value (`-` when the fallible clock is unavailable). A value
/// carries no UTC-accuracy guarantee. Bytes outside printable ASCII become `?`.
pub fn line(wall: Option<u64>, program: &str, text: &str) -> Vec<u8> {
    let stamp = match wall {
        Some(seconds) => format!("{}", Utc::from_unix(seconds).iso()),
        None => "-".into(),
    };
    // Even adapter labels cannot introduce terminal controls or extra fields.
    let tag: Vec<u8> = program.bytes().take(32).map(|b| {
        if b.is_ascii_alphanumeric() || b"._-".contains(&b) { b } else { b'?' }
    }).collect();
    let program = core::str::from_utf8(&tag).unwrap_or("unknown");
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

    fn open<S: Store>(&mut self, fs: &mut S) -> Result<u64, Error> {
        if let Some(handle) = self.handle {
            return Ok(handle);
        }
        let flags = OpenFlags { read: false, write: true, create: true, create_new: false, truncate: false };
        let handle = fs.open(&self.path, flags)?;
        self.size = fs.fstat(handle)?.size;
        self.handle = Some(handle);
        Ok(handle)
    }

    fn rotate<S: Store>(&mut self, fs: &mut S) -> Result<(), Error> {
        if let Some(handle) = self.handle.take() {
            fs.close(handle)?;
        }
        fs.rename(&self.path, &rotated(&self.path), false)?;
        let flags = OpenFlags { read: false, write: true, create: true, create_new: true, truncate: false };
        self.handle = Some(fs.open(&self.path, flags)?);
        self.size = 0;
        Ok(())
    }

    fn write<S: Store>(&mut self, fs: &mut S, bytes: &[u8]) -> Result<(), Error> {
        let handle = self.open(fs)?;
        if must_rotate(self.size, bytes.len()) {
            self.rotate(fs)?;
        }
        let handle = self.handle.unwrap_or(handle);
        let written = fs.write_at(handle, self.size, bytes)?;
        self.size += written as u64;
        if written != bytes.len() { return Err(Error::NoSpace); }
        Ok(())
    }

    /// Appends one line; `Err` when it was dropped. The caller commits
    /// (the file server's idle commit covers it). `wall` stamps the
    /// dropped-lines note like any other line.
    pub fn append<S: Store>(&mut self, fs: &mut S, wall: Option<u64>, text: &[u8]) -> Result<(), Error> {
        if text.len() > MAX_LINE {
            self.dropped = self.dropped.saturating_add(1);
            return Err(Error::Invalid);
        }
        if self.dropped > 0 {
            let note = line(wall, self.program, &format!("log: {} lines dropped", self.dropped));
            if let Err(error) = self.write(fs, &note) {
                self.dropped = self.dropped.saturating_add(1);
                return Err(error);
            }
            self.dropped = 0;
        }
        self.write(fs, text).inspect_err(|_| {
            self.dropped = self.dropped.saturating_add(1);
            // Start from a fresh open next time (the handle may be gone
            // with a poisoned mount).
            if let Some(handle) = self.handle.take() {
                let _ = fs.close(handle);
            }
        })
    }
}

/// How the previous generation ended, as this boot's file server recorded it
/// in its own log before serving: the `FSD RECOVERY seq=… streak=…
/// previous=…` line that follows `started: boot <id>` (ssh/src/fsd_server.rs).
/// The ledger itself cannot be read for this: the file server overwrites it
/// before anything is served (recovery::charge).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Generation {
    pub seq: u64,
    pub streak: u64,
    /// `none`, `ended`, `failed` or `not_ready` (recovery::Previous::name).
    pub previous: &'static str,
}

/// Why [`generation`] could not say: never a guess.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unknown {
    /// Neither log file holds this boot's `started:` line (rotated out, or
    /// dropped).
    NoBootLine,
    /// This boot's `started:` line has no recovery line after it.
    NoRecoveryLine,
    /// The recovery line after it is not in the recorded form.
    Malformed,
}

impl Unknown {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NoBootLine => "no line for this boot in /var/log/fsd or /var/log/fsd.0",
            Self::NoRecoveryLine => "this boot's log has no recovery line",
            Self::Malformed => "this boot's recovery line is malformed",
        }
    }
}

const PREVIOUS: [&str; 4] = ["none", "ended", "failed", "not_ready"];

/// This boot's recovery record from the file server's log: `rotated` is
/// `/var/log/fsd.0` (older lines, possibly empty) and `current` is
/// `/var/log/fsd`; `boot` is this boot's identity in lower-case hex. Takes
/// the first `started: boot <boot>` line and the first recovery line after
/// it, and refuses to take a line from any other boot.
pub fn generation(rotated: &[u8], current: &[u8], boot: &str) -> Result<Generation, Unknown> {
    let started = format!("started: boot {boot}, ");
    let mut after_start = false;
    for raw in rotated.split(|&b| b == b'\n').chain(current.split(|&b| b == b'\n')) {
        // `TIME fsd: TEXT`, the form `line` writes.
        let Some(text) = core::str::from_utf8(raw).ok().and_then(|l| l.split_once(" fsd: ")).map(|(_, t)| t)
        else {
            continue;
        };
        if text.starts_with("started: boot ") {
            if after_start {
                // Another start before this boot's recovery line: either
                // a later run (the finalize run) or another boot.
                return Err(Unknown::NoRecoveryLine);
            }
            after_start = text.starts_with(&started);
            continue;
        }
        if !after_start {
            continue;
        }
        if let Some(rest) = text.strip_prefix("FSD RECOVERY ") {
            return parse_recovery(rest).ok_or(Unknown::Malformed);
        }
    }
    Err(if after_start { Unknown::NoRecoveryLine } else { Unknown::NoBootLine })
}

fn parse_recovery(rest: &str) -> Option<Generation> {
    let mut words = rest.split(' ');
    let seq = words.next()?.strip_prefix("seq=")?;
    let streak = words.next()?.strip_prefix("streak=")?;
    let previous = words.next()?.strip_prefix("previous=")?;
    if words.next().is_some() || [seq, streak].iter().any(|n| n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    Some(Generation {
        seq: seq.parse().ok()?,
        streak: streak.parse().ok()?,
        previous: PREVIOUS.into_iter().find(|&name| name == previous)?,
    })
}

/// Line-oriented compatibility view of trusted kernel service chunks. The J1
/// journal remains authoritative for PID/stream metadata and exact bytes.
#[derive(Default)]
pub struct LegacyProjection {
    key: Option<(u64, u8)>,
    pending: Vec<u8>,
}
impl LegacyProjection {
    pub fn push(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let Some(rest) = chunk.strip_prefix(b"pid=") else {
            return out;
        };
        let Some(at) = rest.iter().position(|b| *b == b' ') else {
            return out;
        };
        let Some(pid) = core::str::from_utf8(&rest[..at])
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|p| *p > 0)
        else {
            return out;
        };
        let rest = &rest[at + 1..];
        let (stream, body) = if let Some(body) = rest.strip_prefix(b"stream=stdout ") {
            (1, body)
        } else if let Some(body) = rest.strip_prefix(b"stream=stderr ") {
            (2, body)
        } else {
            return out;
        };
        if self.key != Some((pid, stream)) {
            if !self.pending.is_empty() {
                if let Some((old, kind)) = self.key {
                    let mut line = format!(
                        "pid={old} stream={} partial: ",
                        if kind == 1 { "stdout" } else { "stderr" }
                    )
                    .into_bytes();
                    line.append(&mut self.pending);
                    out.push(line);
                }
            }
            self.key = Some((pid, stream));
        }
        for &b in body.iter().take(MAX_LINE) {
            if b == b'\n' || self.pending.len() >= 400 {
                out.push(core::mem::take(&mut self.pending));
            }
            if b != b'\n' {
                self.pending.push(b);
            }
        }
        out
    }
}
