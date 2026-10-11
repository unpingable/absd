//! The recovery ledger: how many served generations in a row reached
//! readiness and did not end as the operator asked. The kernel's init
//! stops resetting the machine once that streak reaches its budget
//! (kernel `docs/service-lifecycle-20261008/RECOVERY-BUDGET.md`).
//!
//! The file server owns the ledger and charges it at startup, before it
//! serves anything: the entry it writes already counts this generation as
//! not ended, so a later failure of sshd or of the file server itself
//! needs no write. sshd leaves two facts (`served-ready` before it
//! listens, `served-end` as the last act of a requested halt or restart)
//! the file server leaves one (`served-stopped` on its orderly end), and
//! init, through the file server run once more in its finalize mode after
//! the orderly end completed, leaves the last (`served-completed`). The
//! next generation reads them, all tied to the previous boot id; the
//! streak clears only when all four are there.
//!
//! Every file is created once, at the first boot with this contract, in a
//! staging directory renamed into place (one commit), and has a fixed
//! size from then on: the ledger and the facts are overwritten in place,
//! so a charge allocates nothing and a full disk still serves. A fact
//! that is all zero bytes is absent.

use alloc::vec::Vec;

use absd_fs::{Device, Error, Fs, OpenFlags};

/// Where every file of this module lives; created by the file server.
pub const DIR: &[u8] = b"/var/state";
/// The staging directory of the first creation, renamed to [`DIR`] once
/// complete; one left behind is removed and the creation redone.
pub const STAGING: &[u8] = b"/var/state.new";
/// The ledger: one line, `absd-recovery v1 seq=<n> boot=<hex32> streak=<k> fnv=<hex16>`,
/// zero-padded to [`LEDGER_BYTES`].
pub const LEDGER: &[u8] = b"/var/state/recovery";
/// Present once the ledger was created on this disk: from then on a
/// missing or unreadable ledger is lost state, not a first boot.
pub const INIT: &[u8] = b"/var/state/recovery.init";
/// The facts sshd and the file server leave; sshd's only writable path.
pub const FACTS: &[u8] = b"/var/state/facts";
/// sshd: written and synced before `SSH LISTENING`.
pub const SERVED_READY: &[u8] = b"/var/state/facts/served-ready";
/// sshd: written and synced as the last act of a requested halt or restart.
pub const SERVED_END: &[u8] = b"/var/state/facts/served-end";
/// The file server: written before its final commit on control-channel EOF.
pub const SERVED_STOPPED: &[u8] = b"/var/state/facts/served-stopped";
/// init's verdict: the file server in finalize mode writes it after init
/// reaped the file server with status 0, drained every orphan within its
/// bound, and saw the worker's stream end cleanly.
pub const SERVED_COMPLETED: &[u8] = b"/var/state/facts/served-completed";
/// Every fact, in the order the clear condition names them.
pub const FACT_FILES: [&[u8]; 4] = [SERVED_READY, SERVED_END, SERVED_STOPPED, SERVED_COMPLETED];
/// The ledger file's fixed size.
pub const LEDGER_BYTES: usize = 128;
/// Each fact file's fixed size.
pub const FACT_BYTES: usize = 64;
const PREFIX: &[u8] = b"absd-recovery v1 seq=";

/// A boot identity as both services print it: 32 lowercase hex digits.
pub type Boot = [u8; 32];

/// One ledger line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ledger {
    pub seq: u64,
    pub boot: Boot,
    pub streak: u64,
}

/// How the previous generation ended, as the ledger and facts tell it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Previous {
    /// First boot with a ledger on this disk.
    None,
    /// A requested halt or restart that the file server completed.
    Ended,
    /// Reached readiness and did not end as requested.
    Failed,
    /// Never reached readiness (a pre-ready refusal, or a stop before
    /// sshd listened): the streak carries, unchanged.
    NotReady,
}

impl Previous {
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Ended => "ended",
            Self::Failed => "failed",
            Self::NotReady => "not_ready",
        }
    }
}

/// Why the file server refuses to serve: a closed list, each a pre-ready
/// refusal (the boot stops; nothing resets it).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// The ledger was established on this disk and is now missing.
    Lost,
    /// The ledger exists and does not parse or fails its check.
    Corrupt,
    /// A ledger without the initialization marker beside it.
    UninitializedLedger,
    /// The filesystem refused a read, write, or commit.
    Storage(Error),
}

impl Refusal {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Lost => "lost",
            Self::Corrupt => "corrupt",
            Self::UninitializedLedger => "uninitialized_ledger",
            Self::Storage(_) => "storage",
        }
    }
}

/// 64-bit FNV-1a, the check the channel frames use too.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn push_decimal(out: &mut Vec<u8>, mut value: u64) {
    let mut digits = [0u8; 20];
    let mut at = digits.len();
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

fn push_hex16(out: &mut Vec<u8>, value: u64) {
    for shift in (0..16).rev() {
        let nibble = ((value >> (shift * 4)) & 0xf) as u8;
        out.push(if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 });
    }
}

fn decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 19 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    bytes.iter().try_fold(0u64, |acc, &d| acc.checked_mul(10)?.checked_add(u64::from(d - b'0')))
}

fn hex16(bytes: &[u8]) -> Option<u64> {
    if bytes.len() != 16 {
        return None;
    }
    bytes.iter().try_fold(0u64, |acc, &c| {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => return None,
        };
        Some((acc << 4) | u64::from(v))
    })
}

fn boot_of(bytes: &[u8]) -> Option<Boot> {
    if bytes.len() != 32 || !bytes.iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c)) {
        return None;
    }
    let mut boot = [0u8; 32];
    boot.copy_from_slice(bytes);
    Some(boot)
}

/// Splits `key=value` fields on single spaces, in order.
fn field<'a>(rest: &'a [u8], key: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    let rest = rest.strip_prefix(key)?;
    let end = rest.iter().position(|&c| c == b' ' || c == b'\n').unwrap_or(rest.len());
    Some((&rest[..end], &rest[end..]))
}

/// The first line of a fixed-size file: everything up to and including
/// the first newline, provided the rest is zero padding.
fn first_line(bytes: &[u8]) -> Option<&[u8]> {
    let end = bytes.iter().position(|&c| c == b'\n')?;
    if bytes[end + 1..].iter().any(|&c| c != 0) {
        return None;
    }
    Some(&bytes[..=end])
}

fn padded(line: Vec<u8>, size: usize) -> Vec<u8> {
    debug_assert!(line.len() <= size);
    let mut out = line;
    out.resize(size, 0);
    out
}

/// The ledger line for `ledger`, with its check and a trailing newline.
pub fn format_ledger(ledger: &Ledger) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(PREFIX);
    push_decimal(&mut out, ledger.seq);
    out.extend_from_slice(b" boot=");
    out.extend_from_slice(&ledger.boot);
    out.extend_from_slice(b" streak=");
    push_decimal(&mut out, ledger.streak);
    let check = fnv1a(&out);
    out.extend_from_slice(b" fnv=");
    push_hex16(&mut out, check);
    out.push(b'\n');
    out
}

/// Parses a ledger file (the line, possibly zero-padded); `None` for
/// anything but exactly the format [`format_ledger`] writes with a
/// matching check.
pub fn parse_ledger(bytes: &[u8]) -> Option<Ledger> {
    let line = first_line(bytes)?.strip_suffix(b"\n")?;
    let rest = line.strip_prefix(PREFIX)?;
    let (seq, rest) = field(rest, b"")?;
    let (boot, rest) = field(rest, b" boot=")?;
    let (streak, rest) = field(rest, b" streak=")?;
    let (check, rest) = field(rest, b" fnv=")?;
    if !rest.is_empty() {
        return None;
    }
    let checked = line.len() - b" fnv=".len() - check.len();
    if hex16(check)? != fnv1a(&line[..checked]) {
        return None;
    }
    Some(Ledger { seq: decimal(seq)?, boot: boot_of(boot)?, streak: decimal(streak)? })
}

/// A fact file's content: `boot=<hex32>` or `boot=<hex32> action=<word>`,
/// one line, zero-padded to [`FACT_BYTES`].
pub fn format_fact(boot: &Boot, action: Option<&str>) -> Vec<u8> {
    let mut out = Vec::with_capacity(FACT_BYTES);
    out.extend_from_slice(b"boot=");
    out.extend_from_slice(boot);
    if let Some(action) = action {
        out.extend_from_slice(b" action=");
        out.extend_from_slice(action.as_bytes());
    }
    out.push(b'\n');
    padded(out, FACT_BYTES)
}

/// The boot id a fact file names, if it holds one (an all-zero file is an
/// absent fact).
pub fn fact_boot(bytes: &[u8]) -> Option<Boot> {
    let line = first_line(bytes)?.strip_suffix(b"\n")?;
    let (boot, rest) = field(line, b"boot=")?;
    if !(rest.is_empty() || rest.starts_with(b" action=")) {
        return None;
    }
    boot_of(boot)
}

/// The streak this generation starts with, from the previous ledger line
/// and the facts the previous generation left (each already tied to its
/// boot id by the caller).
pub fn evaluate(previous: Option<&Ledger>, ready: bool, ended: bool) -> (u64, Previous) {
    match previous {
        None => (0, Previous::None),
        Some(_) if ended => (0, Previous::Ended),
        Some(prev) if ready => (prev.streak.saturating_add(1), Previous::Failed),
        Some(prev) => (prev.streak, Previous::NotReady),
    }
}

/// The whole file at `path`, at most `most` bytes: `Ok(None)` when it does
/// not exist, `Err(())` when it is not a readable file of that size.
fn small_file<D: Device>(fs: &mut Fs<D>, path: &[u8], most: usize) -> Result<Option<Vec<u8>>, ()> {
    let attr = match fs.stat(path) {
        Ok(attr) => attr,
        Err(Error::NotFound) => return Ok(None),
        Err(_) => return Err(()),
    };
    if attr.kind != absd_fs::Kind::File || attr.size > most as u64 {
        return Err(());
    }
    let flags = OpenFlags { read: true, write: false, create: false, create_new: false, truncate: false };
    let handle = fs.open(path, flags).map_err(|_| ())?;
    let mut bytes = alloc::vec![0u8; attr.size as usize];
    let mut filled = 0;
    let outcome = loop {
        if filled == bytes.len() {
            break Ok(());
        }
        match fs.read_at(handle, filled as u64, &mut bytes[filled..]) {
            Ok(0) | Err(_) => break Err(()),
            Ok(count) => filled += count,
        }
    };
    let _ = fs.close(handle);
    outcome.map(|()| Some(bytes))
}

/// Overwrites an existing fixed-size file in place from offset 0: no
/// allocation, no namespace change.
fn overwrite<D: Device>(fs: &mut Fs<D>, path: &[u8], data: &[u8]) -> Result<(), Error> {
    let flags = OpenFlags { read: false, write: true, create: false, create_new: false, truncate: false };
    let handle = fs.open(path, flags)?;
    let mut written = 0;
    let outcome = loop {
        if written == data.len() {
            break Ok(());
        }
        match fs.write_at(handle, written as u64, &data[written..]) {
            Ok(0) => break Err(Error::NoSpace),
            Ok(count) => written += count,
            Err(e) => break Err(e),
        }
    };
    fs.close(handle)?;
    outcome
}

/// Creates a file and writes it whole (the first creation only).
fn create<D: Device>(fs: &mut Fs<D>, path: &[u8], data: &[u8]) -> Result<(), Error> {
    let flags = OpenFlags { read: false, write: true, create: true, create_new: true, truncate: false };
    let handle = fs.open(path, flags)?;
    let mut written = 0;
    let outcome = loop {
        if written == data.len() {
            break Ok(());
        }
        match fs.write_at(handle, written as u64, &data[written..]) {
            Ok(0) => break Err(Error::NoSpace),
            Ok(count) => written += count,
            Err(e) => break Err(e),
        }
    };
    fs.close(handle)?;
    outcome
}

fn exists<D: Device>(fs: &mut Fs<D>, path: &[u8]) -> Result<bool, Error> {
    match fs.stat(path) {
        Ok(_) => Ok(true),
        Err(Error::NotFound) => Ok(false),
        Err(e) => Err(e),
    }
}

fn fact_matches<D: Device>(fs: &mut Fs<D>, path: &[u8], boot: &Boot) -> bool {
    matches!(small_file(fs, path, FACT_BYTES), Ok(Some(bytes)) if fact_boot(&bytes).as_ref() == Some(boot))
}

/// The first boot with this contract: every file is made under
/// [`STAGING`], committed, and the directory renamed to [`DIR`] in one
/// commit. A staging directory a reset left behind is removed first.
fn first_creation<D: Device>(fs: &mut Fs<D>, boot: &Boot) -> Result<Ledger, Error> {
    if exists(fs, STAGING)? {
        fs.remove_tree(STAGING, true)?;
    }
    let ledger = Ledger { seq: 1, boot: *boot, streak: 0 };
    let staged = |path: &[u8]| {
        let mut p = STAGING.to_vec();
        p.extend_from_slice(&path[DIR.len()..]);
        p
    };
    fs.mkdir(STAGING)?;
    fs.mkdir(&staged(FACTS))?;
    create(fs, &staged(INIT), b"")?;
    create(fs, &staged(LEDGER), &padded(format_ledger(&ledger), LEDGER_BYTES))?;
    for fact in FACT_FILES {
        create(fs, &staged(fact), &[0u8; FACT_BYTES])?;
    }
    fs.sync()?;
    fs.rename(STAGING, DIR, true)?;
    Ok(ledger)
}

/// Charges the ledger for the generation `boot`: reads the previous line
/// and the facts, overwrites the line, clears the facts, and commits, all
/// before the caller serves anything. The returned ledger is this
/// generation's; `Previous` says how the last one ended.
pub fn charge<D: Device>(fs: &mut Fs<D>, boot: &Boot) -> Result<(Ledger, Previous), Refusal> {
    if !exists(fs, DIR).map_err(Refusal::Storage)? {
        let ledger = first_creation(fs, boot).map_err(Refusal::Storage)?;
        return Ok((ledger, Previous::None));
    }
    let initialized = exists(fs, INIT).map_err(Refusal::Storage)?;
    let previous = match (small_file(fs, LEDGER, LEDGER_BYTES), initialized) {
        (Ok(Some(bytes)), true) => parse_ledger(&bytes).ok_or(Refusal::Corrupt)?,
        (Ok(None), true) | (Ok(None), false) => return Err(Refusal::Lost),
        (Ok(Some(_)), false) | (Err(()), false) => return Err(Refusal::UninitializedLedger),
        (Err(()), true) => return Err(Refusal::Corrupt),
    };
    let ready = fact_matches(fs, SERVED_READY, &previous.boot);
    // Requested by the operator (sshd), committed by the file server, and
    // completed by init: each alone is insufficient (an unexpected exit 0,
    // a crash after the request, an end that escalated after the server
    // stopped).
    let ended = fact_matches(fs, SERVED_END, &previous.boot)
        && fact_matches(fs, SERVED_STOPPED, &previous.boot)
        && fact_matches(fs, SERVED_COMPLETED, &previous.boot);
    let (streak, how) = evaluate(Some(&previous), ready, ended);
    let ledger = Ledger { seq: previous.seq.saturating_add(1), boot: *boot, streak };
    overwrite(fs, LEDGER, &padded(format_ledger(&ledger), LEDGER_BYTES)).map_err(Refusal::Storage)?;
    for fact in FACT_FILES {
        overwrite(fs, fact, &[0u8; FACT_BYTES]).map_err(Refusal::Storage)?;
    }
    fs.sync().map_err(Refusal::Storage)?;
    Ok((ledger, how))
}

/// The file server's own fact at its orderly end, before its final commit.
pub fn stopped<D: Device>(fs: &mut Fs<D>, boot: &Boot) -> Result<(), Error> {
    overwrite(fs, SERVED_STOPPED, &format_fact(boot, None))
}

/// init's verdict, written by the file server in finalize mode: the
/// orderly end of `boot` completed. Committed by the caller's sync.
pub fn completed<D: Device>(fs: &mut Fs<D>, boot: &Boot) -> Result<(), Error> {
    overwrite(fs, SERVED_COMPLETED, &format_fact(boot, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::rc::Rc;
    use core::cell::RefCell;
    use std::collections::BTreeMap;

    use absd_fs::SECTOR;

    #[derive(Clone)]
    struct Disk(Rc<RefCell<BTreeMap<u64, [u8; SECTOR]>>>);

    impl Device for Disk {
        fn sectors(&self) -> u64 {
            4096
        }
        fn read(&mut self, sector: u64, buffer: &mut [u8; SECTOR]) -> Result<(), Error> {
            *buffer = self.0.borrow().get(&sector).copied().unwrap_or([0; SECTOR]);
            Ok(())
        }
        fn write(&mut self, sector: u64, buffer: &[u8; SECTOR]) -> Result<(), Error> {
            self.0.borrow_mut().insert(sector, *buffer);
            Ok(())
        }
        fn flush(&mut self) -> Result<(), Error> {
            Ok(())
        }
    }

    fn image() -> Disk {
        let disk = Disk(Rc::new(RefCell::new(BTreeMap::new())));
        absd_fs::format(&mut disk.clone(), 7).unwrap();
        let mut fs = Fs::mount(disk.clone(), true).unwrap();
        fs.mkdir(b"/var").unwrap();
        fs.sync().unwrap();
        disk
    }

    fn boot(n: u8) -> Boot {
        let mut b = [b'0'; 32];
        b[31] = b'0' + n;
        b
    }

    fn mount(disk: &Disk) -> Fs<Disk> {
        Fs::mount(disk.clone(), true).unwrap()
    }

    /// What sshd does through its facts mount: overwrite in place, sync.
    fn fact(fs: &mut Fs<Disk>, path: &[u8], boot: &Boot, action: Option<&str>) {
        overwrite(fs, path, &format_fact(boot, action)).unwrap();
        fs.sync().unwrap();
    }

    fn read(fs: &mut Fs<Disk>, path: &[u8]) -> Vec<u8> {
        small_file(fs, path, LEDGER_BYTES).unwrap().unwrap()
    }

    #[test]
    fn a_ledger_line_round_trips_padded_and_carries_its_check() {
        let ledger = Ledger { seq: 7, boot: boot(3), streak: 2 };
        let line = format_ledger(&ledger);
        assert!(line.starts_with(b"absd-recovery v1 seq=7 boot=000"));
        assert_eq!(parse_ledger(&line), Some(ledger));
        assert_eq!(parse_ledger(&padded(line.clone(), LEDGER_BYTES)), Some(ledger));
        let mut flipped = line.clone();
        let at = flipped.iter().position(|&c| c == b'2').unwrap();
        flipped[at] = b'3';
        assert_eq!(parse_ledger(&flipped), None, "a changed digit fails the check");
        assert_eq!(parse_ledger(&line[..line.len() - 1]), None, "no newline");
        let mut trailing = padded(line.clone(), LEDGER_BYTES);
        trailing[LEDGER_BYTES - 1] = b'x';
        assert_eq!(parse_ledger(&trailing), None, "padding must be zero");
        assert_eq!(parse_ledger(b"absd-recovery v1 seq=1 boot=x streak=0 fnv=0000000000000000\n"), None);
        assert_eq!(parse_ledger(&[0u8; LEDGER_BYTES]), None);
    }

    #[test]
    fn a_fact_names_its_boot_and_an_all_zero_fact_is_absent() {
        assert_eq!(format_fact(&boot(1), None).len(), FACT_BYTES);
        assert_eq!(fact_boot(&format_fact(&boot(1), None)), Some(boot(1)));
        assert_eq!(fact_boot(&format_fact(&boot(1), Some("restart"))), Some(boot(1)));
        assert_eq!(fact_boot(&[0u8; FACT_BYTES]), None);
        assert_eq!(fact_boot(b"boot=abc\n"), None);
        assert_eq!(fact_boot(b"boot=00000000000000000000000000000001 junk\n"), None);
    }

    #[test]
    fn evaluation_counts_only_ready_generations_and_clears_only_on_an_ended_one() {
        let prev = Ledger { seq: 4, boot: boot(1), streak: 2 };
        assert_eq!(evaluate(None, false, false), (0, Previous::None));
        assert_eq!(evaluate(Some(&prev), true, false), (3, Previous::Failed));
        assert_eq!(evaluate(Some(&prev), false, false), (2, Previous::NotReady));
        assert_eq!(evaluate(Some(&prev), true, true), (0, Previous::Ended));
    }

    #[test]
    fn the_first_boot_creates_every_file_in_one_renamed_directory() {
        let disk = image();
        let mut fs = mount(&disk);
        let (ledger, how) = charge(&mut fs, &boot(1)).unwrap();
        assert_eq!((ledger.seq, ledger.streak, how), (1, 0, Previous::None));
        drop(fs);
        let mut fs = mount(&disk);
        assert!(!exists(&mut fs, STAGING).unwrap());
        assert!(exists(&mut fs, INIT).unwrap());
        assert_eq!(parse_ledger(&read(&mut fs, LEDGER)), Some(ledger));
        for fact in FACT_FILES {
            assert_eq!(read(&mut fs, fact), [0u8; FACT_BYTES]);
        }
    }

    #[test]
    fn a_staging_directory_left_by_a_reset_is_redone_not_trusted() {
        let disk = image();
        let mut fs = mount(&disk);
        // The reset came after staging was complete but before the rename.
        fs.mkdir(STAGING).unwrap();
        fs.mkdir(b"/var/state.new/facts").unwrap();
        create(&mut fs, b"/var/state.new/recovery.init", b"").unwrap();
        create(&mut fs, b"/var/state.new/recovery", &padded(format_ledger(&Ledger { seq: 9, boot: boot(9), streak: 9 }), LEDGER_BYTES)).unwrap();
        fs.sync().unwrap();
        drop(fs);
        let mut fs = mount(&disk);
        let (ledger, how) = charge(&mut fs, &boot(1)).unwrap();
        assert_eq!((ledger.seq, ledger.streak, how), (1, 0, Previous::None));
        assert!(!exists(&mut fs, STAGING).unwrap());
    }

    #[test]
    fn a_charge_allocates_nothing_so_a_full_disk_still_serves() {
        let disk = image();
        let mut fs = mount(&disk);
        charge(&mut fs, &boot(1)).unwrap();
        fact(&mut fs, SERVED_READY, &boot(1), None);
        // Fill every data block.
        let flags = OpenFlags { read: false, write: true, create: true, create_new: true, truncate: false };
        let handle = fs.open(b"/var/filler", flags).unwrap();
        let chunk = [0xa5u8; 4096];
        let mut at = 0u64;
        loop {
            match fs.write_at(handle, at, &chunk) {
                Ok(n) => at += n as u64,
                Err(Error::NoSpace) => break,
                Err(e) => panic!("{e:?}"),
            }
        }
        fs.close(handle).unwrap();
        fs.sync().unwrap();
        assert_eq!(fs.free_blocks(), 0);
        drop(fs);
        let mut fs = mount(&disk);
        assert_eq!(fs.free_blocks(), 0);
        let (ledger, how) = charge(&mut fs, &boot(2)).unwrap();
        assert_eq!((ledger.streak, how), (1, Previous::Failed));
        stopped(&mut fs, &boot(2)).unwrap();
        fact(&mut fs, SERVED_END, &boot(2), Some("halt"));
        completed(&mut fs, &boot(2)).unwrap();
        fs.sync().unwrap();
        drop(fs);
        let mut fs = mount(&disk);
        assert_eq!(charge(&mut fs, &boot(3)).unwrap().0.streak, 0, "cleared on a full disk too");
    }

    #[test]
    fn three_failed_generations_charge_a_streak_of_three_before_anything_is_served() {
        let disk = image();
        let mut streaks = Vec::new();
        for n in 1..=5 {
            let mut fs = mount(&disk);
            let (ledger, _) = charge(&mut fs, &boot(n)).unwrap();
            streaks.push(ledger.streak);
            // sshd reaches readiness, then the generation dies with no end
            // fact and, for odd boots, no stopped fact either (fsd died).
            fact(&mut fs, SERVED_READY, &boot(n), None);
            if n % 2 == 0 {
                stopped(&mut fs, &boot(n)).unwrap();
                fs.sync().unwrap();
            }
        }
        assert_eq!(streaks, [0, 1, 2, 3, 4]);
    }

    #[test]
    fn a_generation_that_never_listened_carries_the_streak_unchanged() {
        let disk = image();
        let mut fs = mount(&disk);
        charge(&mut fs, &boot(1)).unwrap();
        fact(&mut fs, SERVED_READY, &boot(1), None);
        drop(fs);
        let mut fs = mount(&disk);
        assert_eq!(charge(&mut fs, &boot(2)).unwrap().0.streak, 1);
        // boot 2 stops before sshd listens: no facts at all.
        drop(fs);
        let mut fs = mount(&disk);
        let (ledger, how) = charge(&mut fs, &boot(3)).unwrap();
        assert_eq!((ledger.streak, how), (1, Previous::NotReady));
    }

    #[test]
    fn only_a_requested_end_that_the_file_server_completed_clears_the_streak() {
        let disk = image();
        let mut fs = mount(&disk);
        charge(&mut fs, &boot(1)).unwrap();
        fact(&mut fs, SERVED_READY, &boot(1), None);
        drop(fs);
        let mut fs = mount(&disk);
        assert_eq!(charge(&mut fs, &boot(2)).unwrap().0.streak, 1);
        // An unexpected exit 0: fsd stops cleanly but sshd asked for nothing.
        fact(&mut fs, SERVED_READY, &boot(2), None);
        stopped(&mut fs, &boot(2)).unwrap();
        fs.sync().unwrap();
        drop(fs);
        let mut fs = mount(&disk);
        let (ledger, how) = charge(&mut fs, &boot(3)).unwrap();
        assert_eq!((ledger.streak, how), (2, Previous::Failed));
        // A requested restart whose file server never reached its end.
        fact(&mut fs, SERVED_READY, &boot(3), None);
        fact(&mut fs, SERVED_END, &boot(3), Some("restart"));
        drop(fs);
        let mut fs = mount(&disk);
        assert_eq!(charge(&mut fs, &boot(4)).unwrap().0.streak, 3);
        // Requested and committed by the file server, but init never
        // finalized (the end escalated after the server stopped, or sshd
        // faulted after writing its request): not cleared.
        fact(&mut fs, SERVED_READY, &boot(4), None);
        fact(&mut fs, SERVED_END, &boot(4), Some("halt"));
        stopped(&mut fs, &boot(4)).unwrap();
        fs.sync().unwrap();
        drop(fs);
        let mut fs = mount(&disk);
        assert_eq!(charge(&mut fs, &boot(5)).unwrap().0.streak, 4);
        // init's verdict without the server's own fact is not enough either.
        fact(&mut fs, SERVED_READY, &boot(5), None);
        fact(&mut fs, SERVED_END, &boot(5), Some("halt"));
        completed(&mut fs, &boot(5)).unwrap();
        fs.sync().unwrap();
        drop(fs);
        let mut fs = mount(&disk);
        assert_eq!(charge(&mut fs, &boot(6)).unwrap().0.streak, 5);
        // The real thing: requested, committed, and finalized by init.
        fact(&mut fs, SERVED_READY, &boot(6), None);
        fact(&mut fs, SERVED_END, &boot(6), Some("halt"));
        stopped(&mut fs, &boot(6)).unwrap();
        completed(&mut fs, &boot(6)).unwrap();
        fs.sync().unwrap();
        drop(fs);
        let mut fs = mount(&disk);
        let (ledger, how) = charge(&mut fs, &boot(7)).unwrap();
        assert_eq!((ledger.seq, ledger.streak, how), (7, 0, Previous::Ended));
    }

    #[test]
    fn facts_of_an_older_generation_do_not_count_and_are_cleared_at_charge() {
        let disk = image();
        let mut fs = mount(&disk);
        charge(&mut fs, &boot(1)).unwrap();
        // Facts naming some other boot: ignored.
        fact(&mut fs, SERVED_READY, &boot(9), None);
        fact(&mut fs, SERVED_END, &boot(9), Some("halt"));
        stopped(&mut fs, &boot(9)).unwrap();
        completed(&mut fs, &boot(9)).unwrap();
        fs.sync().unwrap();
        drop(fs);
        let mut fs = mount(&disk);
        let (ledger, how) = charge(&mut fs, &boot(2)).unwrap();
        assert_eq!((ledger.streak, how), (0, Previous::NotReady));
        for fact in FACT_FILES {
            assert_eq!(read(&mut fs, fact), [0u8; FACT_BYTES], "{} survived the charge", core::str::from_utf8(fact).unwrap());
        }
    }

    #[test]
    fn lost_or_corrupt_state_is_refused_and_never_becomes_a_fresh_counter() {
        let disk = image();
        let mut fs = mount(&disk);
        charge(&mut fs, &boot(1)).unwrap();
        fs.unlink(LEDGER).unwrap();
        fs.sync().unwrap();
        drop(fs);
        let mut fs = mount(&disk);
        assert_eq!(charge(&mut fs, &boot(2)).unwrap_err(), Refusal::Lost);
        create(&mut fs, LEDGER, b"absd-recovery v1 seq=1 boot=0 streak=0 fnv=0\n").unwrap();
        fs.sync().unwrap();
        drop(fs);
        let mut fs = mount(&disk);
        assert_eq!(charge(&mut fs, &boot(2)).unwrap_err(), Refusal::Corrupt);
        // A ledger without its marker is not a first boot either.
        fs.unlink(INIT).unwrap();
        fs.sync().unwrap();
        drop(fs);
        let mut fs = mount(&disk);
        assert_eq!(charge(&mut fs, &boot(2)).unwrap_err(), Refusal::UninitializedLedger);
        // The state directory without any file: lost, not first.
        let disk = image();
        let mut fs = mount(&disk);
        fs.mkdir(DIR).unwrap();
        fs.sync().unwrap();
        drop(fs);
        let mut fs = mount(&disk);
        assert_eq!(charge(&mut fs, &boot(2)).unwrap_err(), Refusal::Lost);
    }
}
