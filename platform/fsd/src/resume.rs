//! The operator-authorized resume slot (schema v1, 512 bytes, one fixed
//! block): path (e) of the writable-entry contract (docs/WRITABLE-ENTRY.md,
//! "Operator-authorized resume"; coordination record #63).
//!
//! The fresh-image constructor seeds `none`. The host's `release.py
//! recover` writes one record naming exactly one logical committed state:
//! the filesystem identity and sequence, the selected superblock's image
//! digest, the canonical ledger line, and the history being recovered
//! (`previous`). The next serving boot admits only if every field equals
//! what its own read-only mount selected and the guard reads exactly
//! `dirty`; it then consumes the record back to `none` as its first
//! device write (`crate::write_guard::begin`). The file is never created,
//! resized, renamed or removed by a running service, and no session can
//! bind it. Anything at the slot that is neither encoding is corrupt and
//! refuses before any write; only the host's `--revoke` rewrites `none`.

use absd_fs::{Device, Error, Fs, OpenFlags, SECTOR};
use crate::recovery::{Boot, Previous, Refusal};

pub const PATH: &[u8] = b"/var/recovery.resume";
const PREFIX: &[u8] = b"absd-resume v1 ";
/// A record line, newline included, is at most this long.
pub const LINE_MAX: usize = 300;

/// One authorization record: the five state fields, the history it
/// recovers, and when the host wrote it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record {
    /// The act's id, 32 lowercase hex digits.
    pub id: [u8; 32],
    pub fs: u64,
    pub seq: u64,
    /// The selected superblock's image digest (`Fs::image_digest`).
    pub image: [u8; 32],
    pub ledger_seq: u64,
    pub ledger_boot: Boot,
    /// `Failed` or `NotReady`: the history being recovered.
    pub previous: Previous,
    pub time: u64,
}

/// What the slot holds when it parses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Slot {
    None,
    Record(Record),
}

/// The committed state a read-only mount selected, as the record must
/// name it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct State {
    pub fs: u64,
    pub seq: u64,
    pub image: [u8; 32],
    pub ledger_seq: u64,
    pub ledger_boot: Boot,
    pub previous: Previous,
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn push_decimal(out: &mut [u8; SECTOR], at: &mut usize, mut value: u64) {
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
    push(out, at, &digits[end..]);
}

fn push_hex(out: &mut [u8; SECTOR], at: &mut usize, bytes: &[u8]) {
    for &byte in bytes {
        for nibble in [byte >> 4, byte & 0xf] {
            out[*at] = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
            *at += 1;
        }
    }
}

fn push(out: &mut [u8; SECTOR], at: &mut usize, bytes: &[u8]) {
    out[*at..*at + bytes.len()].copy_from_slice(bytes);
    *at += bytes.len();
}

/// The `none` sector.
pub const fn none() -> [u8; SECTOR] {
    let line: &[u8] = b"absd-resume v1 none\n";
    let mut out = [0; SECTOR];
    let mut at = 0;
    while at < line.len() {
        out[at] = line[at];
        at += 1;
    }
    out
}

/// The record's sector: the line with its check, zero-padded.
pub fn encode(record: &Record) -> [u8; SECTOR] {
    let mut out = [0u8; SECTOR];
    let mut at = 0;
    push(&mut out, &mut at, PREFIX);
    push(&mut out, &mut at, b"id=");
    push(&mut out, &mut at, &record.id);
    push(&mut out, &mut at, b" fs=");
    push_hex(&mut out, &mut at, &record.fs.to_be_bytes());
    push(&mut out, &mut at, b" seq=");
    push_decimal(&mut out, &mut at, record.seq);
    push(&mut out, &mut at, b" image=");
    push_hex(&mut out, &mut at, &record.image);
    push(&mut out, &mut at, b" ledger_seq=");
    push_decimal(&mut out, &mut at, record.ledger_seq);
    push(&mut out, &mut at, b" ledger_boot=");
    push(&mut out, &mut at, &record.ledger_boot);
    push(&mut out, &mut at, b" previous=");
    push(&mut out, &mut at, record.previous.name().as_bytes());
    push(&mut out, &mut at, b" time=");
    push_decimal(&mut out, &mut at, record.time);
    let check = fnv1a(&out[..at]);
    push(&mut out, &mut at, b" fnv=");
    push_hex(&mut out, &mut at, &check.to_be_bytes());
    push(&mut out, &mut at, b"\n");
    debug_assert!(at <= LINE_MAX);
    out
}

fn decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 20 || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes[0] == b'0') {
        return None;
    }
    bytes.iter().try_fold(0u64, |acc, &d| acc.checked_mul(10)?.checked_add(u64::from(d - b'0')))
}

fn hex_bytes<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    if bytes.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let mut value = 0u8;
        for &c in pair {
            let nibble = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => return None,
            };
            value = (value << 4) | nibble;
        }
        out[index] = value;
    }
    Some(out)
}

fn hex_id(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() != 32 || !bytes.iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c)) {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Some(out)
}

fn field<'a>(rest: &'a [u8], key: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    let rest = rest.strip_prefix(key)?;
    let end = rest.iter().position(|&c| c == b' ').unwrap_or(rest.len());
    Some((&rest[..end], &rest[end..]))
}

/// Parses the slot sector: `None` for anything but the two exact
/// encodings (a torn line, a changed byte, a bad check, nonzero padding,
/// an unknown version or field, a wrong length).
pub fn parse(bytes: &[u8]) -> Option<Slot> {
    if bytes.len() != SECTOR {
        return None;
    }
    if bytes == none() {
        return Some(Slot::None);
    }
    let end = bytes.iter().position(|&c| c == b'\n')?;
    if end + 1 > LINE_MAX || bytes[end + 1..].iter().any(|&c| c != 0) {
        return None;
    }
    let line = &bytes[..end];
    let rest = line.strip_prefix(PREFIX)?;
    let (id, rest) = field(rest, b"id=")?;
    let (fs, rest) = field(rest, b" fs=")?;
    let (seq, rest) = field(rest, b" seq=")?;
    let (image, rest) = field(rest, b" image=")?;
    let (ledger_seq, rest) = field(rest, b" ledger_seq=")?;
    let (ledger_boot, rest) = field(rest, b" ledger_boot=")?;
    let (previous, rest) = field(rest, b" previous=")?;
    let (time, rest) = field(rest, b" time=")?;
    let (check, rest) = field(rest, b" fnv=")?;
    if !rest.is_empty() {
        return None;
    }
    let checked = line.len() - b" fnv=".len() - check.len();
    let check: [u8; 8] = hex_bytes(check)?;
    if u64::from_be_bytes(check) != fnv1a(&line[..checked]) {
        return None;
    }
    let previous = match previous {
        b"failed" => Previous::Failed,
        b"not_ready" => Previous::NotReady,
        _ => return None,
    };
    let record = Record {
        id: hex_id(id)?,
        fs: u64::from_be_bytes(hex_bytes(fs)?),
        seq: decimal(seq)?,
        image: hex_bytes(image)?,
        ledger_seq: decimal(ledger_seq)?,
        ledger_boot: hex_id(ledger_boot)?,
        previous,
        time: decimal(time)?,
    };
    // Exactly the bytes this encoder writes, and nothing else.
    if encode(&record)[..] != bytes[..] {
        return None;
    }
    Some(Slot::Record(record))
}

/// Whether `record` names exactly the committed state `state`.
pub fn checks(record: &Record, state: &State) -> bool {
    record.fs == state.fs
        && record.seq == state.seq
        && record.image == state.image
        && record.ledger_seq == state.ledger_seq
        && record.ledger_boot == state.ledger_boot
        && record.previous == state.previous
}

/// What the slot holds: `Ok(None)` when the file does not exist (an image
/// built before the slot: no act can authorize it), `ResumeCorrupt` for
/// a wrong shape or bytes that are neither encoding.
pub fn read<D: Device>(fs: &mut Fs<D>) -> Result<Option<Slot>, Refusal> {
    let attr = match fs.stat(PATH) {
        Ok(attr) => attr,
        Err(Error::NotFound) => return Ok(None),
        Err(other) => return Err(Refusal::Storage(other)),
    };
    if attr.kind != absd_fs::Kind::File || attr.size != SECTOR as u64 || attr.readonly {
        return Err(Refusal::ResumeCorrupt);
    }
    let handle = fs.open(PATH, OpenFlags { read: true, ..OpenFlags::default() })
        .map_err(Refusal::Storage)?;
    let mut bytes = [0u8; SECTOR];
    let result = fs.read_at(handle, 0, &mut bytes);
    fs.close(handle).map_err(Refusal::Storage)?;
    if result.map_err(Refusal::Storage)? != SECTOR {
        return Err(Refusal::ResumeCorrupt);
    }
    parse(&bytes).map(Some).ok_or(Refusal::ResumeCorrupt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn golden() -> Record {
        Record {
            id: *b"00112233445566778899aabbccddeeff",
            fs: 7,
            seq: 11,
            image: hex_bytes(b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap(),
            ledger_seq: 7,
            ledger_boot: *b"0123456789abcdef0123456789abcdef",
            previous: Previous::Failed,
            time: 1_761_100_000,
        }
    }

    #[test]
    fn both_encodings_match_the_shared_golden_sectors() {
        let none_golden = include_bytes!("../../fixtures/storage-fence/resume-v1-none.bin");
        let record_golden = include_bytes!("../../fixtures/storage-fence/resume-v1-record.bin");
        assert_eq!(&none(), none_golden);
        assert_eq!(parse(none_golden), Some(Slot::None));
        assert_eq!(&encode(&golden()), record_golden);
        assert_eq!(parse(record_golden), Some(Slot::Record(golden())));
        assert_eq!(&record_golden[..15], PREFIX);
        assert_eq!(record_golden[15], b'i');
        assert_eq!(none_golden[15], b'n');
    }

    #[test]
    fn torn_changed_short_and_foreign_sectors_are_corrupt() {
        for torn in [
            &include_bytes!("../../fixtures/storage-fence/resume-v1-torn-40.bin")[..],
            &include_bytes!("../../fixtures/storage-fence/resume-v1-torn-200.bin")[..],
        ] {
            assert_eq!(parse(torn), None);
        }
        let record = encode(&golden());
        let end = record.iter().position(|&c| c == b'\n').unwrap();
        for at in 0..SECTOR {
            let mut changed = record;
            changed[at] ^= 1;
            assert_eq!(parse(&changed), None, "byte {at}");
            let mut changed = none();
            changed[at] ^= 1;
            assert_eq!(parse(&changed), None, "none byte {at}");
        }
        for cut in [0, 1, 8, 15, 16, 40, 120, 200, end - 1, end] {
            let mut torn = [0u8; SECTOR];
            torn[..cut].copy_from_slice(&record[..cut]);
            assert_eq!(parse(&torn), None, "cut {cut}");
        }
        assert_eq!(parse(&record[..SECTOR - 1]), None);
        assert_eq!(parse(&[0u8; SECTOR]), None);
        let mut v2 = record;
        v2[12] = b'2';
        assert_eq!(parse(&v2), None);
        let mut trailing = record;
        trailing[end + 1] = b'x';
        assert_eq!(parse(&trailing), None);
        // A previous outside the two recoverable histories never encodes.
        let mut ended = Vec::from(&record[..end]);
        let at = ended.windows(16).position(|w| w == b"previous=failed ").unwrap();
        ended.splice(at..at + 16, b"previous=ended  ".iter().copied());
        let mut sector = [0u8; SECTOR];
        sector[..ended.len()].copy_from_slice(&ended);
        sector[ended.len()] = b'\n';
        assert_eq!(parse(&sector), None);
    }

    #[test]
    fn a_record_round_trips_for_both_histories_and_checks_only_the_exact_state() {
        for previous in [Previous::Failed, Previous::NotReady] {
            let record = Record { previous, seq: u64::MAX, time: 0, ..golden() };
            assert_eq!(parse(&encode(&record)), Some(Slot::Record(record)));
            let state = State {
                fs: record.fs, seq: record.seq, image: record.image,
                ledger_seq: record.ledger_seq, ledger_boot: record.ledger_boot, previous,
            };
            assert!(checks(&record, &state));
            assert!(!checks(&record, &State { fs: 8, ..state }));
            assert!(!checks(&record, &State { seq: state.seq - 1, ..state }));
            let mut image = state.image;
            image[31] ^= 1;
            assert!(!checks(&record, &State { image, ..state }));
            assert!(!checks(&record, &State { ledger_seq: 8, ..state }));
            assert!(!checks(&record, &State { ledger_boot: [b'f'; 32], ..state }));
            let other = if previous == Previous::Failed { Previous::NotReady } else { Previous::Failed };
            assert!(!checks(&record, &State { previous: other, ..state }));
        }
    }
}
