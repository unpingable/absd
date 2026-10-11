//! The file server's wire protocol. Every integer is little-endian.
//!
//! A frame is a header ([`MAGIC`], `u32 body length`, `u64 sequence`),
//! a body, and a trailer (`u64 check`, FNV-1a over header and body). A
//! request body is `u8 op` and the op's fields; a reply body is `i64
//! status` and a payload, and a reply carries its request's sequence word.
//! A status below zero is an errno-style refusal (the values `std::fs`
//! already maps: -2 not found, -13 denied, -30 read-only, ...); otherwise
//! it is the op's result (a handle, a byte count, or zero).
//!
//! One request is outstanding per channel: a client writes a request and
//! reads its whole reply before writing the next. The sequence word
//! belongs to the holder (its PID in the high half, a count in the low
//! half), so a reader can tell its reply from one addressed to an earlier
//! holder of the channel, and the check lets `inbox` tell a whole frame
//! from bytes a dead holder left in front of it.

use alloc::vec::Vec;

/// Largest request or reply body.
pub const MAX_BODY: usize = 72 * 1024;
/// The first four bytes of every frame. Its digit is the protocol
/// generation, `absd_release::FSD_PROTOCOL`.
pub const MAGIC: [u8; 4] = *b"FSD2";
const _: () = assert!(MAGIC[3] == b'0' + absd_release::FSD_PROTOCOL as u8);
/// Header bytes: the magic, the `u32` body length, the `u64` sequence.
pub const HEADER: usize = 16;
/// Trailer bytes: the `u64` check.
pub const TRAILER: usize = 8;
/// Largest whole frame.
pub const MAX_FRAME: usize = HEADER + MAX_BODY + TRAILER;
/// Largest `read_at` or `write_at` transfer in one request.
pub const MAX_IO: usize = 64 * 1024;
/// Longest path in a request.
pub const MAX_PATH: usize = 4096;
/// Most mounts in one binding.
pub const MAX_MOUNTS: usize = 8;
/// `attr` payload: kind u32, readonly u32, size, fs id, serial, links,
/// mtime (Unix seconds of the last change to content, size, or entries;
/// 0 is unknown). Filesystem format 2 (`docs/FILESYSTEM.md`).
pub const ATTR_BYTES: usize = 48;
/// `SPACE` payload length.
pub const SPACE_BYTES: usize = 32;
/// Longest `NOTICE` text.
pub const MAX_NOTICE: usize = 400;

pub mod op {
    pub const OPEN: u8 = 1;
    pub const CLOSE: u8 = 2;
    pub const READ_AT: u8 = 3;
    pub const WRITE_AT: u8 = 4;
    pub const SET_LEN: u8 = 5;
    pub const SYNC: u8 = 6;
    pub const FSTAT: u8 = 7;
    pub const STAT: u8 = 8;
    pub const SET_READONLY: u8 = 9;
    pub const SET_READONLY_PATH: u8 = 10;
    pub const MKDIR: u8 = 11;
    pub const RMDIR: u8 = 12;
    pub const UNLINK: u8 = 13;
    pub const RENAME: u8 = 14;
    pub const READ_DIR: u8 = 15;
    pub const CANONICAL: u8 = 16;
    pub const LOCK: u8 = 17;
    /// This channel's mount list.
    pub const MOUNTS: u8 = 18;
    /// Bind one of this session's spares for a child (`u8 spare`, `u8 how`,
    /// mounts when `how` is [`super::derive::LIST`]).
    pub const DERIVE: u8 = 19;
    /// Unbind one of this session's spares (`u8 spare`).
    pub const UNDERIVE: u8 = 20;
    /// The filesystem's capacity as the server's format knows it:
    /// [`SPACE_BYTES`] of payload (block bytes u32, data blocks u32, free
    /// blocks u32, reserved u32, filesystem id u64, commit sequence u64).
    /// Every binding shares the one filesystem, so it is the same for all.
    pub const SPACE: u8 = 21;
    /// Commit every change the server has accepted, from any channel, and
    /// flush the device; the reply's payload is the commit sequence now
    /// durable (u64). No handle needed: it makes nothing visible that was
    /// not already accepted, it only stops waiting for the idle bound.
    pub const COMMIT: u8 = 22;
    /// The server's identity (`docs/RELEASE.md` section 3): no fields; the
    /// payload is `u32 fsd_protocol`, `u32 fs_format`, `u16 length`, and the
    /// release id. Answered on every channel, bound or not, so a client
    /// can ask before anything else; [`crate::version`] decodes and checks
    /// it. A server older than the op answers `-95` (or `-13` on a channel
    /// it does not serve), and one that cannot parse the frame never
    /// answers: a client treats all three as a refusal.
    pub const VERSION: u8 = 23;
    /// Control only: bind a slot to a session (`u8 slot`, `u8 spare
    /// count`, spares, mounts).
    pub const BIND: u8 = 32;
    /// Control only: end a session (`u8 slot`).
    pub const RELEASE: u8 = 33;
    /// Control only: a line of text for the machine's console (the file
    /// server has init's console; sshd has none). At most
    /// [`super::MAX_NOTICE`] bytes; the server prints it as `sshd: TEXT`
    /// with bytes outside printable ASCII shown as `?`.
    pub const NOTICE: u8 = 34;
}

pub mod derive {
    /// The child gets exactly the session's mounts.
    pub const SAME: u8 = 0;
    /// The session's mounts, every one read-only.
    pub const READ_ONLY: u8 = 1;
    /// An explicit list, each mount inside one of the session's with no
    /// more access.
    pub const LIST: u8 = 2;
}

/// Mount access in the wire list.
pub const MOUNT_RO: u8 = 1;
pub const MOUNT_RW: u8 = 2;

/// Refusals beyond what `absd-fs` itself reports.
pub mod status {
    pub const NOT_FOUND: i64 = -2;
    pub const IO: i64 = -5;
    pub const BAD_HANDLE: i64 = -9;
    pub const AGAIN: i64 = -11;
    pub const DENIED: i64 = -13;
    pub const BUSY: i64 = -16;
    pub const INVALID: i64 = -22;
    pub const TOO_MANY: i64 = -24;
    pub const READ_ONLY: i64 = -30;
    /// Also the filesystem's `UnsupportedFormat`: another format version.
    pub const UNSUPPORTED: i64 = -95;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
    /// Normalized absolute path, never `/` itself.
    pub path: Vec<u8>,
    pub writable: bool,
}

impl Mount {
    pub fn new(path: &[u8], writable: bool) -> Self {
        Self { path: path.to_vec(), writable }
    }
}

pub struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    pub fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        if self.0.len() < count {
            return None;
        }
        let (head, tail) = self.0.split_at(count);
        self.0 = tail;
        Some(head)
    }
    pub fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    pub fn i64(&mut self) -> Option<i64> {
        Some(self.u64()? as i64)
    }
    pub fn rest(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.0)
    }
    pub fn mounts(&mut self) -> Option<Vec<Mount>> {
        let count = self.u8()? as usize;
        if count > MAX_MOUNTS {
            return None;
        }
        let mut mounts = Vec::with_capacity(count);
        for _ in 0..count {
            let writable = match self.u8()? {
                MOUNT_RO => false,
                MOUNT_RW => true,
                _ => return None,
            };
            let length = self.u16()? as usize;
            if length > MAX_PATH {
                return None;
            }
            mounts.push(Mount { path: self.take(length)?.to_vec(), writable });
        }
        Some(mounts)
    }
}

/// Builds one frame: header and trailer are filled in by
/// [`Frame::finish_seq`]; [`Frame::finish`] uses sequence 0, which the
/// sender restamps with [`stamp_seq`].
pub struct Frame(pub Vec<u8>);

impl Frame {
    pub fn request(op: u8) -> Self {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&[0; HEADER]);
        bytes.push(op);
        Self(bytes)
    }
    pub fn reply(status: i64) -> Self {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&[0; HEADER]);
        bytes.extend_from_slice(&status.to_le_bytes());
        Self(bytes)
    }
    pub fn u8(mut self, value: u8) -> Self {
        self.0.push(value);
        self
    }
    pub fn u16(mut self, value: u16) -> Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }
    pub fn u32(mut self, value: u32) -> Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }
    pub fn u64(mut self, value: u64) -> Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }
    pub fn bytes(mut self, value: &[u8]) -> Self {
        // Exactly what this appends plus the trailer `finish` adds: a 64 KiB
        // payload must not double the buffer to 128 KiB (one mapped-page
        // step per channel that first carried one, in the repair's churn).
        self.0.reserve_exact(value.len() + TRAILER);
        self.0.extend_from_slice(value);
        self
    }
    pub fn mounts(mut self, mounts: &[Mount]) -> Self {
        self.0.push(mounts.len() as u8);
        for mount in mounts {
            self.0.push(if mount.writable { MOUNT_RW } else { MOUNT_RO });
            self.0.extend_from_slice(&(mount.path.len() as u16).to_le_bytes());
            self.0.extend_from_slice(&mount.path);
        }
        self
    }
    pub fn finish(self) -> Vec<u8> {
        self.finish_seq(0)
    }
    pub fn finish_seq(mut self, seq: u64) -> Vec<u8> {
        let body = (self.0.len() - HEADER) as u32;
        self.0[..4].copy_from_slice(&MAGIC);
        self.0[4..8].copy_from_slice(&body.to_le_bytes());
        self.0[8..16].copy_from_slice(&seq.to_le_bytes());
        let sum = fnv1a(&self.0);
        self.0.extend_from_slice(&sum.to_le_bytes());
        self.0
    }
}

/// The body length and sequence word a header announces, or `None` when
/// the bytes are no header: not the magic, a zero length, or a body over
/// the largest frame.
pub fn parse_header(header: &[u8]) -> Option<(usize, u64)> {
    if header.len() < HEADER || header[..4] != MAGIC {
        return None;
    }
    let length = u32::from_le_bytes(header[4..8].try_into().ok()?) as usize;
    if !(1..=MAX_BODY).contains(&length) {
        return None;
    }
    Some((length, u64::from_le_bytes(header[8..16].try_into().ok()?)))
}

/// 64-bit FNV-1a over `bytes`.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// Whether `frame` is exactly one frame (header, body, trailer) whose
/// trailer is the check of its header and body.
pub fn verify(frame: &[u8]) -> bool {
    let Some((length, _)) = parse_header(frame) else {
        return false;
    };
    frame.len() == HEADER + length + TRAILER
        && fnv1a(&frame[..HEADER + length]).to_le_bytes() == frame[HEADER + length..]
}

/// Gives a finished frame the sender's sequence word and the matching
/// check.
pub fn stamp_seq(frame: &mut [u8], seq: u64) {
    frame[8..16].copy_from_slice(&seq.to_le_bytes());
    let end = frame.len() - TRAILER;
    let sum = fnv1a(&frame[..end]);
    frame[end..].copy_from_slice(&sum.to_le_bytes());
}

/// Lexical normalization: absolute, `.` and empty components dropped, `..`
/// taken lexically and never above `/`. Exact on ABSD, which has no
/// symbolic links. `None` for a relative path or a NUL byte.
pub fn normalize(path: &[u8]) -> Option<Vec<u8>> {
    if path.first() != Some(&b'/') || path.contains(&0) || path.len() > MAX_PATH {
        return None;
    }
    let mut parts: Vec<&[u8]> = Vec::new();
    for part in path.split(|byte| *byte == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    let mut out = Vec::with_capacity(path.len());
    for part in &parts {
        out.push(b'/');
        out.extend_from_slice(part);
    }
    if out.is_empty() {
        out.push(b'/');
    }
    Some(out)
}

/// Whether `path` is `prefix` or lies below it (both normalized).
pub fn within(path: &[u8], prefix: &[u8]) -> bool {
    prefix == b"/"
        || path == prefix
        || (path.len() > prefix.len() && path.starts_with(prefix) && path[prefix.len()] == b'/')
}
