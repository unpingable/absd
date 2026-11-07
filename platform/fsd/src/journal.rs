//! Bounded service history, written by FSD itself (never an RPC to itself).
//! J1 is an escaped, line-oriented export format; metadata precedes text.
//! Producer text cannot introduce records, tags, or terminal controls.
use absd_fs::{Device, Error, Fs, OpenFlags};
use alloc::{
    collections::VecDeque,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

/// The journal owns policy; storage can be FSD-local or its exclusive RPC
/// client. Each remote operation must impose its own finite transport bound.
pub trait Store {
    fn mkdir(&mut self, path: &[u8]) -> Result<(), Error>;
    fn open(&mut self, path: &[u8], flags: OpenFlags) -> Result<u64, Error>;
    fn close(&mut self, handle: u64) -> Result<(), Error>;
    fn fstat(&mut self, handle: u64) -> Result<absd_fs::Attr, Error>;
    fn read_at(&mut self, handle: u64, offset: u64, bytes: &mut [u8]) -> Result<usize, Error>;
    fn write_at(&mut self, handle: u64, offset: u64, bytes: &[u8]) -> Result<usize, Error>;
    fn set_len(&mut self, handle: u64, size: u64) -> Result<(), Error>;
    fn rename(&mut self, from: &[u8], to: &[u8], noreplace: bool) -> Result<(), Error>;
    fn unlink(&mut self, path: &[u8]) -> Result<(), Error>;
    fn sync(&mut self) -> Result<(), Error>;
}
impl<D: Device> Store for Fs<D> {
    fn mkdir(&mut self, p: &[u8]) -> Result<(), Error> {
        Fs::mkdir(self, p)
    }
    fn open(&mut self, p: &[u8], f: OpenFlags) -> Result<u64, Error> {
        Fs::open(self, p, f)
    }
    fn close(&mut self, h: u64) -> Result<(), Error> {
        Fs::close(self, h)
    }
    fn fstat(&mut self, h: u64) -> Result<absd_fs::Attr, Error> {
        Fs::fstat(self, h)
    }
    fn read_at(&mut self, h: u64, o: u64, b: &mut [u8]) -> Result<usize, Error> {
        Fs::read_at(self, h, o, b)
    }
    fn write_at(&mut self, h: u64, o: u64, b: &[u8]) -> Result<usize, Error> {
        Fs::write_at(self, h, o, b)
    }
    fn set_len(&mut self, h: u64, n: u64) -> Result<(), Error> {
        Fs::set_len(self, h, n)
    }
    fn rename(&mut self, a: &[u8], b: &[u8], n: bool) -> Result<(), Error> {
        Fs::rename(self, a, b, n)
    }
    fn unlink(&mut self, p: &[u8]) -> Result<(), Error> {
        Fs::unlink(self, p)
    }
    fn sync(&mut self) -> Result<(), Error> {
        Fs::sync(self)
    }
}

pub const DIR: &[u8] = b"/var/log/journal";
pub const CURRENT: &[u8] = b"/var/log/journal/current";
pub const FILE_LIMIT: u64 = 128 * 1024;
pub const MAX_RECORD: usize = 1536;
pub const MEMORY_LIMIT: usize = 64 * 1024;
pub const MAX_SOURCES: usize = 16;
/// Admission slots for actual managed producers and diagnostic routing. Other
/// typed labels share the remaining slots; they cannot displace these names.
pub const RESERVED_SOURCES: [&str; 6] = [
    "kernel",
    "unknown",
    "collector",
    "service.sshd",
    "service.fsd",
    "service.logd",
];
const _: () = assert!(RESERVED_SOURCES.len() <= MAX_SOURCES);
pub const SUPPRESSED: u64 = 1 << 32;
pub const ACQUISITION_TIME: u64 = 1 << 33;
pub const SOURCE_WINDOW: u64 = 1000;
pub const SOURCE_RECORDS: u64 = 32;
const MAX_TEXT: usize = 320;
pub const FILES: [&str; 4] = ["previous.0", "previous", "current.0", "current"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub boot: [u8; 32],
    pub sequence: u64,
    pub ticks: u64,
    pub severity: u8,
    pub source: String,
    pub kernel_sequence: Option<u64>,
    pub flags: u64,
    /// Escaped bytes, not trusted metadata.
    pub message: String,
}
impl Record {
    pub fn encode(&self) -> Vec<u8> {
        format!(
            "J1 {} {} {} {} {} {} {} {}\n",
            core::str::from_utf8(&self.boot).unwrap_or("invalid"),
            self.sequence,
            self.ticks,
            self.severity,
            self.source,
            self.kernel_sequence
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".into()),
            self.flags,
            self.message
        )
        .into_bytes()
    }
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_RECORD {
            return None;
        }
        let s = core::str::from_utf8(bytes)
            .ok()?
            .strip_suffix('\n')
            .unwrap_or(core::str::from_utf8(bytes).ok()?);
        let mut p = s.splitn(9, ' ');
        if p.next()? != "J1" {
            return None;
        }
        let boot: [u8; 32] = p.next()?.as_bytes().try_into().ok()?;
        if !boot
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return None;
        }
        let sequence = p.next()?.parse().ok()?;
        let ticks = p.next()?.parse().ok()?;
        let severity = p.next()?.parse::<u8>().ok()?;
        if severity > 7 {
            return None;
        }
        let source = p.next()?;
        if !valid_source(source) {
            return None;
        }
        let k = p.next()?;
        let kernel_sequence = if k == "-" {
            None
        } else {
            Some(k.parse().ok()?)
        };
        let flags = p.next()?.parse().ok()?;
        let message = p.next()?;
        decode_text(message)?;
        Some(Self {
            boot,
            sequence,
            ticks,
            severity,
            source: source.into(),
            kernel_sequence,
            flags,
            message: message.into(),
        })
    }
}
fn valid_source(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
pub fn escape_text(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        if (32..127).contains(&b) && b != b'\\' {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    out
}
pub fn decode_text(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    let b = s.as_bytes();
    while i < b.len() {
        if b[i] == b'\\' {
            if b.get(i + 1) != Some(&b'x') || i + 3 >= b.len() {
                return None;
            }
            let hex = core::str::from_utf8(&b[i + 2..i + 4]).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 4;
        } else {
            if !(32..127).contains(&b[i]) {
                return None;
            }
            out.push(b[i]);
            i += 1;
        }
    }
    Some(out)
}
struct Source {
    name: String,
    window: u64,
    count: u64,
    suppressed: u64,
}
/// Collector state is volatile and bounded; the kernel ring remains the
/// independent emergency route. No reader owns this queue or stalls capture.
pub struct Journal {
    boot: [u8; 32],
    next: u64,
    sources: Vec<Source>,
    memory: VecDeque<Record>,
    bytes: usize,
    pub suppressed: u64,
    pub evicted: u64,
    pub sink_lost: u64,
    pub kernel_lost: u64,
    pub kernel_producer_dropped: u64,
    pub collector_pid: Option<u64>,
    pub sample_ticks: u64,
    pub rotations: u64,
    pub written: u64,
    pub flushed: u64,
    pub sink_error: Option<Error>,
    file: Option<u64>,
    size: u64,
    retry_at: u64,
    pub resumed_kernel: Option<u64>,
    pub partial_tail: u64,
}
impl Journal {
    pub fn new(boot: [u8; 32]) -> Self {
        let mut sources = Vec::with_capacity(MAX_SOURCES);
        for name in RESERVED_SOURCES {
            sources.push(Source {
                name: name.into(),
                window: 0,
                count: 0,
                suppressed: 0,
            });
        }
        Self {
            boot,
            next: 1,
            sources,
            memory: VecDeque::new(),
            bytes: 0,
            suppressed: 0,
            evicted: 0,
            sink_lost: 0,
            kernel_lost: 0,
            kernel_producer_dropped: 0,
            collector_pid: None,
            sample_ticks: 0,
            rotations: 0,
            written: 0,
            flushed: 0,
            sink_error: None,
            file: None,
            size: 0,
            retry_at: 0,
            resumed_kernel: None,
            partial_tail: 0,
        }
    }
    pub fn recent(&self) -> &VecDeque<Record> {
        &self.memory
    }
    pub fn memory_bytes(&self) -> usize {
        self.bytes
    }
    pub fn capture(
        &mut self,
        ticks: u64,
        source: &str,
        severity: u8,
        kernel_sequence: Option<u64>,
        flags: u64,
        text: &[u8],
    ) -> Option<Record> {
        if !valid_source(source) || severity > 7 {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }
        let slot = self
            .sources
            .iter()
            .position(|s| s.name == source)
            .or_else(|| {
                if self.sources.len() == MAX_SOURCES {
                    None
                } else {
                    self.sources.push(Source {
                        name: source.into(),
                        window: ticks / SOURCE_WINDOW,
                        count: 0,
                        suppressed: 0,
                    });
                    Some(self.sources.len() - 1)
                }
            });
        let Some(slot) = slot else {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        };
        let s = &mut self.sources[slot];
        let window = ticks / SOURCE_WINDOW;
        if s.window != window {
            s.window = window;
            s.count = 0;
        }
        if s.count >= SOURCE_RECORDS {
            s.suppressed = s.suppressed.saturating_add(1);
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }
        s.count += 1;
        let dropped = core::mem::take(&mut s.suppressed);
        let message = if dropped > 0 {
            format!(
                "[suppressed={dropped}] {}",
                escape_text(&text[..text.len().min(MAX_TEXT)])
            )
        } else {
            escape_text(&text[..text.len().min(MAX_TEXT)])
        };
        let record = Record {
            boot: self.boot,
            sequence: self.next,
            ticks,
            severity,
            source: source.into(),
            kernel_sequence,
            flags: flags
                | u64::from(text.len() > MAX_TEXT)
                | if dropped > 0 { SUPPRESSED } else { 0 },
            message,
        };
        self.next = self.next.saturating_add(1);
        let n = record.encode().len();
        // A noisy producer can occupy at most one quarter of memory.
        while self
            .memory
            .iter()
            .filter(|r| r.source == source)
            .map(|r| r.encode().len())
            .sum::<usize>()
            + n
            > MEMORY_LIMIT / 4
        {
            let Some(i) = self.memory.iter().position(|r| r.source == source) else {
                break;
            };
            if let Some(old) = self.memory.remove(i) {
                self.bytes -= old.encode().len();
                self.evicted = self.evicted.saturating_add(1);
                if old.sequence > self.written {
                    self.sink_lost = self.sink_lost.saturating_add(1);
                }
            }
        }
        while self.bytes + n > MEMORY_LIMIT {
            if let Some(old) = self.memory.pop_front() {
                self.bytes -= old.encode().len();
                self.evicted = self.evicted.saturating_add(1);
                if old.sequence > self.written {
                    self.sink_lost = self.sink_lost.saturating_add(1);
                }
            } else {
                break;
            }
        }
        self.bytes += n;
        self.memory.push_back(record.clone());
        Some(record)
    }
    /// Recover sequence/cursor from this boot; on a new boot retain one
    /// prior boot. Namespace updates commit independently. Abrupt loss
    /// during rollover may leave a partial previous set; records retain IDs.
    pub fn open<S: Store>(&mut self, fs: &mut S) -> Result<(), Error> {
        match fs.mkdir(DIR) {
            Ok(()) | Err(Error::Exists) => {}
            Err(e) => return Err(e),
        }
        let mut last = None;
        for path in [b"/var/log/journal/current.0".as_slice(), CURRENT] {
            match read_bounded(fs, path) {
                Ok(bytes) => {
                    for raw in bytes
                        .split_inclusive(|b| *b == b'\n')
                        .filter(|r| r.last() == Some(&b'\n'))
                    {
                        if let Some(r) = Record::parse(raw) {
                            last = Some(r.boot);
                            if r.boot == self.boot {
                                self.next = self.next.max(r.sequence.saturating_add(1));
                                self.written = self.written.max(r.sequence);
                                self.resumed_kernel = self.resumed_kernel.max(r.kernel_sequence);
                            }
                        }
                    }
                }
                Err(Error::NotFound) => {}
                Err(e) => return Err(e),
            }
        }
        if last.is_some_and(|boot| boot != self.boot) {
            for (old, new) in [
                (
                    b"/var/log/journal/current.0".as_slice(),
                    b"/var/log/journal/previous.0".as_slice(),
                ),
                (CURRENT, b"/var/log/journal/previous".as_slice()),
            ] {
                match fs.unlink(new) {
                    Ok(()) | Err(Error::NotFound) => {}
                    Err(e) => return Err(e),
                }
                match fs.rename(old, new, false) {
                    Ok(()) | Err(Error::NotFound) => {}
                    Err(e) => return Err(e),
                }
            }
            self.resumed_kernel = None;
        }
        let handle = fs.open(
            CURRENT,
            OpenFlags {
                write: true,
                create: true,
                ..Default::default()
            },
        )?;
        self.file = Some(handle);
        self.size = match fs.fstat(handle) {
            Ok(a) => a.size,
            Err(e) => {
                self.file = None;
                let _ = fs.close(handle);
                return Err(e);
            }
        };
        // Repair only an incomplete trailing write, never inventing a record.
        // The lost suffix is counted and the next collector start declares it.
        let bytes = match read_bounded(fs, CURRENT) {
            Ok(b) => b,
            Err(e) => {
                self.file = None;
                let _ = fs.close(handle);
                return Err(e);
            }
        };
        let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        if complete < bytes.len() {
            self.partial_tail = self
                .partial_tail
                .saturating_add((bytes.len() - complete) as u64);
            if let Err(e) = fs.set_len(handle, complete as u64) {
                self.file = None;
                let _ = fs.close(handle);
                return Err(e);
            }
            self.size = complete as u64;
        }
        self.file = Some(handle);
        Ok(())
    }
    /// Recent memory also holds unacknowledged records. Only its bounded
    /// evictions count as unconfirmed loss; backoff itself discards nothing.
    /// Shutdown gets one immediate attempt; a failed attempt reinstates the
    /// ordinary backoff. The drain must stop rather than clear it again.
    pub fn retry_now(&mut self, now: u64) {
        self.retry_at = self.retry_at.min(now);
    }
    pub fn pending(&self) -> usize {
        self.memory
            .iter()
            .filter(|r| r.sequence > self.written)
            .count()
    }
    /// Attempt one ordered record using the current collector clock. A lost
    /// reply closes the handle; reopening reconciles the complete J1 prefix
    /// before retrying, so an already completed append is not duplicated.
    pub fn flush_one<S: Store>(&mut self, fs: &mut S, now: u64) -> Result<Option<Record>, Error> {
        if now < self.retry_at {
            return Ok(None);
        }
        let Some(record) = self
            .memory
            .iter()
            .find(|r| r.sequence > self.written)
            .cloned()
        else {
            return Ok(None);
        };
        let result = (|| {
            if self.file.is_none() {
                self.open(fs)?;
            }
            if self.written >= record.sequence {
                return Ok(());
            }
            let bytes = record.encode();
            if self.size + bytes.len() as u64 > FILE_LIMIT {
                if let Some(h) = self.file.take() {
                    fs.close(h)?;
                }
                fs.rename(CURRENT, b"/var/log/journal/current.0", false)?;
                self.size = 0;
                self.rotations = self.rotations.saturating_add(1);
                self.file = Some(fs.open(
                    CURRENT,
                    OpenFlags {
                        write: true,
                        create_new: true,
                        ..Default::default()
                    },
                )?);
            }
            let h = self.file.ok_or(Error::BadHandle)?;
            if fs.write_at(h, self.size, &bytes)? != bytes.len() {
                return Err(Error::NoSpace);
            }
            self.size += bytes.len() as u64;
            self.written = record.sequence;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.sink_error = None;
                Ok(Some(record))
            }
            Err(e) => {
                self.sink_error = Some(e);
                self.retry_at = now.saturating_add(1000);
                if let Some(h) = self.file.take() {
                    let _ = fs.close(h);
                }
                Err(e)
            }
        }
    }
    /// Compatibility entry for local users that capture before persisting.
    pub fn persist<S: Store>(&mut self, fs: &mut S, record: &Record) {
        let _ = self.flush_one(fs, record.ticks);
    }
    pub fn sync<S: Store>(&mut self, fs: &mut S) -> Result<(), Error> {
        match fs.sync() {
            Ok(()) => {
                self.flushed = self.written;
                if self.pending() == 0 {
                    self.sink_error = None;
                }
                Ok(())
            }
            Err(e) => {
                self.sink_error = Some(e);
                Err(e)
            }
        }
    }
    pub fn health(&self) -> String {
        self.health_at(self.sample_ticks)
    }
    fn health_at(&self, sample_ticks: u64) -> String {
        format!(
            "journal boot={} collector_pid={:?} sample_ticks={} counter_scope=collector_generation pending={} persistence={} written={} flushed={} suppressed={} rotations={} memory_evicted={} sink_lost={} kernel_lost={} kernel_producer_dropped={} partial_tail_bytes={} error={:?}\n",
            core::str::from_utf8(&self.boot).unwrap_or("invalid"),
            self.collector_pid,
            sample_ticks,
            self.pending(),
            if self.sink_error == Some(Error::Device(-110)) {
                "unconfirmed"
            } else if self.pending() > 0 && self.sink_error.is_none() {
                "buffered"
            } else if self.sink_error.is_none() && self.file.is_some() {
                "written"
            } else {
                "volatile"
            },
            self.written,
            self.flushed,
            self.suppressed,
            self.rotations,
            self.evicted,
            self.sink_lost,
            self.kernel_lost,
            self.kernel_producer_dropped,
            self.partial_tail,
            self.sink_error
        )
    }
}
/// Persistent health is a changed-state receipt, not a liveness heartbeat.
/// The clock is excluded from its key. Idle polls neither sync nor rewrite.
pub struct HealthPublisher {
    next: u64,
    last: Option<String>,
}
impl Default for HealthPublisher {
    fn default() -> Self {
        Self::new()
    }
}
impl HealthPublisher {
    pub const fn new() -> Self {
        Self {
            next: 0,
            last: None,
        }
    }
    pub fn publish<S: Store>(
        &mut self,
        journal: &mut Journal,
        store: &mut S,
        now: u64,
    ) -> Result<bool, Error> {
        if now < self.next {
            return Ok(false);
        }
        self.next = now.saturating_add(1000);
        let result = (|| {
            if let Some(error) = journal.sink_error {
                if journal.pending() != 0 {
                    return Err(error);
                }
            }
            if journal.written != journal.flushed || journal.sink_error.is_some() {
                journal.sync(store)?;
            }
            let key = journal.health_at(0);
            if self.last.as_ref() == Some(&key) {
                return Ok(false);
            }
            journal.sample_ticks = now;
            let health = journal.health();
            let handle = store.open(
                b"/var/log/journal-health",
                OpenFlags {
                    write: true,
                    create: true,
                    ..Default::default()
                },
            )?;
            let written = (|| {
                if store.write_at(handle, 0, health.as_bytes())? != health.len() {
                    return Err(Error::NoSpace);
                }
                store.set_len(handle, health.len() as u64)
            })();
            let closed = store.close(handle);
            written?;
            closed?;
            // This sync covers the changed health receipt itself. The
            // published journal high-water mark already had a successful
            // sync above; a failed receipt flush never invents durability.
            store.sync()?;
            self.last = Some(key);
            Ok(true)
        })();
        if let Err(error) = result {
            journal.sink_error = Some(error);
        }
        result
    }
}

/// Files may be modified by privileged code; readers never allocate based
/// on untrusted file size. A partial final record is ignored by parsing.
pub fn read_bounded<S: Store>(fs: &mut S, path: &[u8]) -> Result<Vec<u8>, Error> {
    let h = fs.open(
        path,
        OpenFlags {
            read: true,
            ..Default::default()
        },
    )?;
    let mut out = vec![0; FILE_LIMIT as usize];
    let result = fs.read_at(h, 0, &mut out);
    let _ = fs.close(h);
    out.truncate(result?);
    Ok(out)
}
