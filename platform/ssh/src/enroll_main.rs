#![cfg_attr(target_os = "absd", feature(restricted_std))]
//! `absd-enroll`, the worker of the dedicated enrollment image
//! (slice A; kernel `docs/USERSPACE.md`, "enrollment build"). Init gives
//! it the block device and, over absd-stream-v1, the importer's stream
//! (`ABSDFIX1`, records, end marker; `src/bin/fixture_import.rs`). It
//! accepts exactly one record and refuses everything else by name:
//!
//! - the path is `/ssh/authorized_keys`, and no second record follows;
//! - at most 16 KiB, matching the record's SHA-256;
//! - printable ASCII, tab and line ends only (CR only before LF);
//! - sshd's own rules (`keys::parse_authorized`: plain `ssh-ed25519`
//!   lines, comments and blank lines, at least one key);
//! - no key twice.
//!
//! The whole stream is read and judged before the filesystem is mounted, so
//! a refused or interrupted stream leaves the disk untouched. Then it mounts
//! the filesystem already on the device (never formatting), requires the
//! writable placeholder `/ssh/authorized_keys` the blank disk carries,
//! replaces its bytes and syncs once: one commit, so the commit protocol
//! leaves the old file or the new one (shown for abrupt QEMU stops, model
//! M1, not under the device law). It reads the file back and prints
//! `ENROLL OK keys=<n> sha256=<hex>`, or `ENROLL REFUSED reason=<word>
//! <detail>` and exits 95. The host helper (`scripts/absd_try.py`) checks
//! the whole tree afterwards. Its validator follows the same rules, and the
//! cases in `ssh/enroll-cases/` hold both to them.

// sshd's own parser; the host-key half of the module is unused here.
#[allow(dead_code)]
mod keys;

/// The one path an enrollment may write.
pub const KEYS_PATH: &str = "/ssh/authorized_keys";
/// The largest authorized_keys file an enrollment accepts.
pub const KEYS_MAX_BYTES: usize = 16 * 1024;
const MAGIC: &[u8; 8] = b"ABSDFIX1";
/// The step word the enrollment image's durable boot carries.
#[cfg_attr(not(target_os = "absd"), allow(dead_code))]
const ENROLL_STEP: u64 = 1;
/// The longest stream one valid record makes; one byte more is refused.
const STREAM_MAX: usize = 8 + 2 + KEYS_PATH.len() + 8 + 32 + KEYS_MAX_BYTES + 2;

#[derive(Debug, PartialEq)]
pub struct Refusal {
    pub reason: &'static str,
    pub detail: String,
}

fn refuse<T>(reason: &'static str, detail: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal { reason, detail: detail.into() })
}

/// An accepted enrollment: the file's bytes and its number of keys.
#[derive(Debug, PartialEq)]
pub struct Enrollment {
    pub bytes: Vec<u8>,
    pub keys: usize,
}

/// The enroll-only rules over the file's bytes (shared with the host
/// helper's `key_lines` through `ssh/enroll-cases/`).
pub fn validate_keys(bytes: &[u8]) -> Result<usize, Refusal> {
    if bytes.len() > KEYS_MAX_BYTES {
        return refuse("too-large", format!("{} bytes, at most {KEYS_MAX_BYTES}", bytes.len()));
    }
    for (index, &byte) in bytes.iter().enumerate() {
        let allowed = matches!(byte, b' '..=b'~' | b'\t' | b'\n')
            || (byte == b'\r' && bytes.get(index + 1) == Some(&b'\n'));
        if !allowed {
            return refuse("malformed", format!("byte {byte:#04x} at offset {index}"));
        }
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Refusal { reason: "malformed", detail: "not ASCII".into() })?;
    let keys = keys::parse_authorized(text).map_err(|message| Refusal {
        reason: if message == "no keys" { "empty" } else { "malformed" },
        detail: message,
    })?;
    for (index, key) in keys.iter().enumerate() {
        if keys[..index].contains(key) {
            return refuse("duplicate", format!("key {} repeats an earlier key", index + 1));
        }
    }
    Ok(keys.len())
}

fn take<'a>(stream: &mut &'a [u8], count: usize) -> Result<&'a [u8], Refusal> {
    if stream.len() < count {
        return refuse("truncated", "the stream ended inside its record");
    }
    let (head, rest) = stream.split_at(count);
    *stream = rest;
    Ok(head)
}

/// The whole input stream: exactly one record for `KEYS_PATH`, then the
/// end marker and nothing after it.
pub fn validate_stream(mut stream: &[u8]) -> Result<Enrollment, Refusal> {
    use sha2::{Digest as _, Sha256};
    if stream.len() > STREAM_MAX {
        return refuse("too-large", format!("a stream of more than {STREAM_MAX} bytes"));
    }
    if take(&mut stream, 8)? != MAGIC {
        return refuse("malformed", "not a fixture stream");
    }
    let length = u16::from_le_bytes(take(&mut stream, 2)?.try_into().unwrap()) as usize;
    if length == 0 {
        return refuse("no-record", "the stream carries no file");
    }
    let path = take(&mut stream, length)?;
    if path != KEYS_PATH.as_bytes() {
        return refuse("path", format!("only {KEYS_PATH} may be enrolled, not {}", String::from_utf8_lossy(path)));
    }
    let size = u64::from_le_bytes(take(&mut stream, 8)?.try_into().unwrap());
    if size > KEYS_MAX_BYTES as u64 {
        return refuse("too-large", format!("{size} bytes, at most {KEYS_MAX_BYTES}"));
    }
    let digest: [u8; 32] = take(&mut stream, 32)?.try_into().unwrap();
    let bytes = take(&mut stream, size as usize)?;
    if <[u8; 32]>::from(Sha256::digest(bytes)) != digest {
        return refuse("digest", "the bytes do not match the record's SHA-256");
    }
    let end = u16::from_le_bytes(take(&mut stream, 2)?.try_into().unwrap());
    if end != 0 {
        return refuse("extra-file", "a second record follows");
    }
    if !stream.is_empty() {
        return refuse("trailing", format!("{} bytes after the end marker", stream.len()));
    }
    let keys = validate_keys(bytes)?;
    Ok(Enrollment { bytes: bytes.to_vec(), keys })
}

#[cfg(target_os = "absd")]
fn enroll() -> Result<(usize, String), Refusal> {
    use std::io::Read as _;

    use absd_fs::OpenFlags;
    use absd_runtime::storage;
    use sha2::{Digest as _, Sha256};

    if absd_runtime::step() != ENROLL_STEP {
        return refuse("step", format!("step {}, not {ENROLL_STEP}", absd_runtime::step()));
    }
    let mut stream = Vec::new();
    std::io::stdin()
        .lock()
        .take(STREAM_MAX as u64 + 1)
        .read_to_end(&mut stream)
        .map_err(|error| Refusal { reason: "truncated", detail: error.to_string() })?;
    let enrollment = validate_stream(&stream)?;
    let fs_error = |error| Refusal { reason: "storage", detail: format!("{error:?}") };
    // Never formats: a blank device is refused, not initialised.
    let mounted = storage::mount(false, true).map_err(fs_error)?;
    println!("ENROLL MOUNT seq={}", mounted.sequence);
    let path = KEYS_PATH.as_bytes();
    let written = storage::with_fs(|fs| {
        match fs.stat(path) {
            Ok(attr) if attr.kind == absd_fs::Kind::File && !attr.readonly => {}
            Ok(_) => return refuse("placeholder", format!("{KEYS_PATH} is not a writable file")),
            Err(error) => return refuse("placeholder", format!("{KEYS_PATH}: {error:?}")),
        }
        let flags = OpenFlags { read: true, write: true, create: false, create_new: false, truncate: true };
        let handle = fs.open(path, flags).map_err(fs_error)?;
        let mut offset = 0;
        while offset < enrollment.bytes.len() {
            offset += fs.write_at(handle, offset as u64, &enrollment.bytes[offset..]).map_err(fs_error)?;
        }
        // The one commit: truncation and bytes become durable together.
        fs.sync().map_err(fs_error)?;
        let mut back = vec![0u8; enrollment.bytes.len() + 1];
        let mut read = 0;
        loop {
            let count = fs.read_at(handle, read as u64, &mut back[read..]).map_err(fs_error)?;
            if count == 0 || read + count == back.len() {
                read += count;
                break;
            }
            read += count;
        }
        fs.close(handle).map_err(fs_error)?;
        if back[..read] != enrollment.bytes[..] {
            return refuse("read-back", "the file read back differs from the bytes written");
        }
        fs.check().map_err(|message| Refusal { reason: "check", detail: message.into() })?;
        Ok(fs.sequence())
    })
    .ok_or(Refusal { reason: "storage", detail: "no filesystem mounted".into() })??;
    if written != mounted.sequence + 1 {
        return refuse("commits", format!("sequence {} -> {written}, one commit expected", mounted.sequence));
    }
    let digest: String = Sha256::digest(&enrollment.bytes).iter().map(|byte| format!("{byte:02x}")).collect();
    Ok((enrollment.keys, digest))
}

#[cfg(target_os = "absd")]
fn main() {
    absd_runtime::link_anchor();
    match enroll() {
        Ok((keys, digest)) => println!("ENROLL OK keys={keys} sha256={digest}"),
        Err(refusal) => {
            println!("ENROLL REFUSED reason={} {}", refusal.reason, refusal.detail);
            std::process::exit(95);
        }
    }
}

#[cfg(not(target_os = "absd"))]
fn main() {
    eprintln!("absd-enroll writes an ABSD block device; it does not run elsewhere");
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ssh/enroll-cases/<verdict>.<name>.keys`, the verdict `ok-<n>` (n
    /// keys) or `refuse-<reason>`: the host helper's test reads the same.
    #[test]
    fn shared_cases() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("enroll-cases");
        let mut seen = 0;
        for entry in std::fs::read_dir(&root).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_owned();
            let verdict = validate_keys(&std::fs::read(&path).unwrap());
            let expected = name.split('.').next().unwrap();
            if let Some(count) = expected.strip_prefix("ok-") {
                assert_eq!(verdict, Ok(count.parse().unwrap()), "{name}");
            } else if let Some(reason) = expected.strip_prefix("refuse-") {
                assert_eq!(verdict.map_err(|r| r.reason), Err(reason), "{name}");
            } else {
                panic!("case {name} names no verdict");
            }
            seen += 1;
        }
        assert!(seen >= 20, "only {seen} cases");
    }

    fn record(path: &str, bytes: &[u8]) -> Vec<u8> {
        use sha2::{Digest as _, Sha256};
        let mut out = Vec::new();
        out.extend_from_slice(&(path.len() as u16).to_le_bytes());
        out.extend_from_slice(path.as_bytes());
        out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(&Sha256::digest(bytes));
        out.extend_from_slice(bytes);
        out
    }

    fn stream(records: &[Vec<u8>]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        for one in records {
            out.extend_from_slice(one);
        }
        out.extend_from_slice(&[0, 0]);
        out
    }

    fn key(byte: u8) -> Vec<u8> {
        use base64::Engine as _;
        let blob = keys::public_blob(&[byte; 32]);
        format!("ssh-ed25519 {} user@host\n", base64::engine::general_purpose::STANDARD.encode(blob)).into_bytes()
    }

    #[test]
    fn stream_rules() {
        let one = key(1);
        let good = stream(&[record(KEYS_PATH, &one)]);
        assert_eq!(validate_stream(&good), Ok(Enrollment { bytes: one.clone(), keys: 1 }));
        let reason = |s: &[u8]| validate_stream(s).unwrap_err().reason;
        assert_eq!(reason(&stream(&[record(KEYS_PATH, &one), record("/etc/rc", b"x")])), "extra-file");
        assert_eq!(reason(&stream(&[record("/etc/rc", &one)])), "path");
        assert_eq!(reason(&stream(&[record("/ssh/authorized_keys.new", &one)])), "path");
        assert_eq!(reason(&stream(&[])), "no-record");
        assert_eq!(reason(&good[..good.len() - 1]), "truncated");
        assert_eq!(reason(&good[..20]), "truncated");
        assert_eq!(reason(&[]), "truncated");
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(reason(&trailing), "trailing");
        let mut corrupt = good.clone();
        let last = corrupt.len() - 3;
        corrupt[last] ^= 1;
        assert_eq!(reason(&corrupt), "digest");
        let mut magic = good.clone();
        magic[0] = b'X';
        assert_eq!(reason(&magic), "malformed");
        assert_eq!(reason(&stream(&[record(KEYS_PATH, b"")])), "empty");
        let mut twice = one.clone();
        twice.extend_from_slice(&one);
        assert_eq!(reason(&stream(&[record(KEYS_PATH, &twice)])), "duplicate");
        let large = vec![b'#'; KEYS_MAX_BYTES + 1];
        assert_eq!(reason(&stream(&[record(KEYS_PATH, &large)])), "too-large");
    }
}
