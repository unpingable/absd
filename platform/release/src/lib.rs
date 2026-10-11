//! ABSD release identity (`docs/RELEASE.md`, sections 2 and 3): the
//! identity compiled into every program of a build, and the release record
//! `/releases/<id>/release` that the file server checks against it before
//! it serves.
//!
//! The record is exactly these bytes, each line ended by one `\n`, no
//! `\r`, no spaces, nothing after the check line:
//!
//! ```text
//! absd-release 1
//! release=<id>
//! kernel_abi=<n>
//! fsd_protocol=<n>
//! fs_format=<n>
//! app_abi=<n>
//! check=<sha256 of every byte above, lowercase hex>
//! ```
//!
//! `<id>` is `[a-z0-9.-]+`, at most [`MAX_ID`] bytes; each `<n>` is a
//! decimal `u32` without sign or leading zeros. [`parse`] accepts exactly
//! that and nothing else; [`encode`] (the host release tool's twin) writes
//! it. No field admits a range: [`compare`] requires each to equal the
//! compiled one.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;

use sha2::{Digest as _, Sha256};

/// This build's release id: `ABSD_RELEASE_ID` in the environment of the
/// compiler (the release tool sets it), else `dev` for a development
/// build. It must match the id grammar; a build with an invalid one fails
/// to compile.
pub const RELEASE_ID: &str = match option_env!("ABSD_RELEASE_ID") {
    Some(id) => id,
    None => "dev",
};
const _: () = assert!(
    valid_id(RELEASE_ID.as_bytes()),
    "ABSD_RELEASE_ID is not [a-z0-9.-]+, at most 64 bytes"
);

/// The kernel syscall ABI generation this build's runtime was written for.
/// It must equal the kernel's `absd_abi::KERNEL_ABI`: the runtime compares
/// it to the kernel's `abi_version` answer (syscall 42) at every start.
pub const KERNEL_ABI: u32 = 1;
/// The file-server wire protocol generation: the `FSD2` frame and its ops.
pub const FSD_PROTOCOL: u32 = 2;
/// The filesystem format the file server's library mounts.
pub const FS_FORMAT: u32 = 2;
/// The startup record, broker, and session-control conventions.
pub const APP_ABI: u32 = 1;

/// Longest release id.
pub const MAX_ID: usize = 64;
/// The record's first line.
pub const HEADER: &[u8] = b"absd-release 1";
/// Room for the longest [`abi_refusal_line`].
pub const ABI_LINE_BYTES: usize = 80;

const KEYS: [&[u8]; 5] = [
    b"release",
    b"kernel_abi",
    b"fsd_protocol",
    b"fs_format",
    b"app_abi",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub release: Vec<u8>,
    pub kernel_abi: u32,
    pub fsd_protocol: u32,
    pub fs_format: u32,
    pub app_abi: u32,
}

/// Why a release is refused, each with the reason word the console line
/// names (`RELEASE REFUSED reason=<reason>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// `/absd/selected` does not exist.
    NoSelectedRelease,
    /// `/absd/selected` is not one id and at most one newline.
    MalformedSelected,
    /// `/releases/<id>/release` does not exist.
    NoReleaseTree,
    MalformedRecord,
    CheckMismatch,
    ReleaseMismatch,
    KernelAbiMismatch,
    FsdProtocolMismatch,
    FsFormatMismatch,
    AppAbiMismatch,
}

impl Refusal {
    pub fn reason(self) -> &'static str {
        match self {
            Refusal::NoSelectedRelease => "no_selected_release",
            Refusal::MalformedSelected => "malformed_selected",
            Refusal::NoReleaseTree => "no_release_tree",
            Refusal::MalformedRecord => "malformed_record",
            Refusal::CheckMismatch => "check_mismatch",
            Refusal::ReleaseMismatch => "release_mismatch",
            Refusal::KernelAbiMismatch => "kernel_abi_mismatch",
            Refusal::FsdProtocolMismatch => "fsd_protocol_mismatch",
            Refusal::FsFormatMismatch => "fs_format_mismatch",
            Refusal::AppAbiMismatch => "app_abi_mismatch",
        }
    }
}

/// Whether `id` is a release id: `[a-z0-9.-]+`, at most [`MAX_ID`] bytes.
pub const fn valid_id(id: &[u8]) -> bool {
    if id.is_empty() || id.len() > MAX_ID {
        return false;
    }
    let mut at = 0;
    while at < id.len() {
        let byte = id[at];
        if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-') {
            return false;
        }
        at += 1;
    }
    true
}

/// This build's own identity, as a record would state it.
pub fn compiled() -> Record {
    Record {
        release: RELEASE_ID.as_bytes().to_vec(),
        kernel_abi: KERNEL_ABI,
        fsd_protocol: FSD_PROTOCOL,
        fs_format: FS_FORMAT,
        app_abi: APP_ABI,
    }
}

fn hex(digest: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    digest
        .iter()
        .flat_map(|byte| [DIGITS[(byte >> 4) as usize], DIGITS[(byte & 15) as usize]])
        .collect()
}

fn decimal(out: &mut Vec<u8>, value: u64) {
    let mut digits = [0u8; 20];
    let mut at = digits.len();
    let mut value = value;
    loop {
        at -= 1;
        digits[at] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[at..]);
}

/// The record's exact bytes. The id must be valid (the caller's to check;
/// [`parse`] would refuse the result otherwise).
pub fn encode(record: &Record) -> Vec<u8> {
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(HEADER);
    out.push(b'\n');
    let numbers = [
        record.kernel_abi,
        record.fsd_protocol,
        record.fs_format,
        record.app_abi,
    ];
    for (index, key) in KEYS.iter().enumerate() {
        out.extend_from_slice(key);
        out.push(b'=');
        match index {
            0 => out.extend_from_slice(&record.release),
            _ => decimal(&mut out, u64::from(numbers[index - 1])),
        }
        out.push(b'\n');
    }
    let check = hex(&Sha256::digest(&out));
    out.extend_from_slice(b"check=");
    out.extend_from_slice(&check);
    out.push(b'\n');
    out
}

fn number(text: &[u8]) -> Option<u32> {
    if text.is_empty() || text.len() > 10 || (text.len() > 1 && text[0] == b'0') {
        return None;
    }
    let mut value = 0u64;
    for &byte in text {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value * 10 + u64::from(byte - b'0');
    }
    u32::try_from(value).ok()
}

/// Parses a record strictly and verifies its check. The structure (seven
/// `\n`-ended lines, the header, the keys in order, a 64-digit lowercase
/// check) is judged first, then the check, then the values, so a record
/// damaged in a value reads as `check_mismatch` rather than as malformed.
pub fn parse(bytes: &[u8]) -> Result<Record, Refusal> {
    let malformed = Refusal::MalformedRecord;
    if bytes.last() != Some(&b'\n') || bytes.contains(&b'\r') {
        return Err(malformed);
    }
    let lines: Vec<&[u8]> = bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .collect();
    if lines.len() != 7 || lines[0] != HEADER {
        return Err(malformed);
    }
    let mut values: [&[u8]; 5] = [b""; 5];
    for (index, key) in KEYS.iter().enumerate() {
        let line = lines[1 + index];
        if line.len() <= key.len() || &line[..key.len()] != *key || line[key.len()] != b'=' {
            return Err(malformed);
        }
        values[index] = &line[key.len() + 1..];
    }
    let check = lines[6].strip_prefix(b"check=").ok_or(malformed)?;
    if check.len() != 64
        || !check
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(malformed);
    }
    let sealed = bytes.len() - lines[6].len() - 1;
    if hex(&Sha256::digest(&bytes[..sealed])) != check {
        return Err(Refusal::CheckMismatch);
    }
    if !valid_id(values[0]) {
        return Err(malformed);
    }
    Ok(Record {
        release: values[0].to_vec(),
        kernel_abi: number(values[1]).ok_or(malformed)?,
        fsd_protocol: number(values[2]).ok_or(malformed)?,
        fs_format: number(values[3]).ok_or(malformed)?,
        app_abi: number(values[4]).ok_or(malformed)?,
    })
}

/// Every field of `theirs` must equal `mine`; the first that differs, in
/// record order, is named.
pub fn compare(theirs: &Record, mine: &Record) -> Result<(), Refusal> {
    if theirs.release != mine.release {
        return Err(Refusal::ReleaseMismatch);
    }
    if theirs.kernel_abi != mine.kernel_abi {
        return Err(Refusal::KernelAbiMismatch);
    }
    if theirs.fsd_protocol != mine.fsd_protocol {
        return Err(Refusal::FsdProtocolMismatch);
    }
    if theirs.fs_format != mine.fs_format {
        return Err(Refusal::FsFormatMismatch);
    }
    if theirs.app_abi != mine.app_abi {
        return Err(Refusal::AppAbiMismatch);
    }
    Ok(())
}

/// [`parse`] then [`compare`] against `mine`.
pub fn verify(bytes: &[u8], mine: &Record) -> Result<Record, Refusal> {
    let record = parse(bytes)?;
    compare(&record, mine)?;
    Ok(record)
}

/// The id in `/absd/selected`: one valid id, then at most one `\n`.
pub fn parse_selected(bytes: &[u8]) -> Result<&[u8], Refusal> {
    let id = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if valid_id(id) {
        Ok(id)
    } else {
        Err(Refusal::MalformedSelected)
    }
}

/// `ABI REFUSED kernel=<answer> required=<KERNEL_ABI>` and a newline,
/// formatted into `buffer` without allocating: the runtime prints it
/// before it may trust any syscall but `write` and `exit`.
pub fn abi_refusal_line(answer: i64, buffer: &mut [u8; ABI_LINE_BYTES]) -> &[u8] {
    struct Line<'a> {
        buffer: &'a mut [u8; ABI_LINE_BYTES],
        at: usize,
    }
    impl Line<'_> {
        fn put(&mut self, bytes: &[u8]) {
            self.buffer[self.at..self.at + bytes.len()].copy_from_slice(bytes);
            self.at += bytes.len();
        }
        fn decimal(&mut self, mut value: u64) {
            let mut digits = [0u8; 20];
            let mut end = digits.len();
            loop {
                end -= 1;
                digits[end] = b'0' + (value % 10) as u8;
                value /= 10;
                if value == 0 {
                    break;
                }
            }
            self.put(&digits[end..]);
        }
    }
    let mut line = Line { buffer, at: 0 };
    line.put(b"ABI REFUSED kernel=");
    if answer < 0 {
        line.put(b"-");
    }
    line.decimal(answer.unsigned_abs());
    line.put(b" required=");
    line.decimal(u64::from(KERNEL_ABI));
    line.put(b"\n");
    let at = line.at;
    &buffer[..at]
}

#[cfg(test)]
mod tests;
