//! Boot-scoped diagnostic retention. Writers and readers try once: never spin
//! on a preempted writer, allocate, or call a display/filesystem consumer.
use crate::handle::{HandleError, HandleTable, Object, RIGHT_READ, RIGHT_WRITE};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub const CAPACITY: usize = 128;
pub const MAX_MESSAGE: usize = 480;
pub const FRAME_BYTES: usize = 576;
pub const TRUNCATED: u32 = 1;
pub const PARTIAL: u32 = 2;
pub const EMERGENCY: u32 = 4;
pub const INFERRED: u32 = 8;
pub const LOSS: u32 = 16;
pub const SYS_LOG_READ: u64 = 0x7fc0;
pub const fn root_init_role(pid: u64, parent: u64, program: usize) -> bool {
    pid == 1 && parent == crate::process::KERNEL_PARENT && program == crate::program::INIT as usize
}
pub const fn reader_authorized(object: Object, rights: u8, allow_console: bool) -> bool {
    (matches!(object, Object::Diagnostics) && rights & RIGHT_READ != 0)
        || (allow_console && matches!(object, Object::Console) && rights & RIGHT_WRITE != 0)
}
/// Handle zero resolves existing Diagnostics READ, or the explicit root-init
/// Console fallback. A stdout pipe never supplies either authority.
pub fn authorize_reader_for(
    handles: &HandleTable,
    handle: u64,
    allow_console: bool,
) -> Result<(), HandleError> {
    if handle == 0 {
        if handles.diagnostics_readable()
            || (allow_console && handles.console_rights() & RIGHT_WRITE != 0)
        {
            Ok(())
        } else {
            Err(HandleError::Rights)
        }
    } else {
        let found = handles.lookup(handle)?;
        if reader_authorized(found.object, found.rights, allow_console) {
            Ok(())
        } else {
            Err(HandleError::Rights)
        }
    }
}
/// Shared request parser used by the real syscall before reading retention.
pub fn read_request(bytes: &[u8; FRAME_BYTES], reserved: u64) -> Result<u64, i64> {
    if reserved != 0
        || bytes[..4] != 1u32.to_le_bytes()
        || bytes[4..8] != [0; 4]
        || bytes[16..].iter().any(|&b| b != 0)
    {
        return Err(-22);
    }
    Ok(u64::from_le_bytes(bytes[8..16].try_into().unwrap()))
}
pub struct ServiceRecord {
    pub source: &'static [u8],
    pub severity: u8,
    pub message: [u8; 320],
    pub len: usize,
}
/// Shared append parser/attribution used by the actual init-only syscall.
pub fn service_request(bytes: &[u8; 296], reserved: u64) -> Result<ServiceRecord, i64> {
    let word = |at| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    let (version, pid, service, stream, len) = (word(0), word(8), word(16), word(24), word(32));
    if reserved != 0
        || version != 1
        || pid == 0
        || !(1..=3).contains(&service)
        || !(1..=3).contains(&stream)
        || len > 256
        || bytes[40 + len as usize..].iter().any(|&b| b != 0)
    {
        return Err(-22);
    }
    struct Message {
        bytes: [u8; 320],
        len: usize,
    }
    impl core::fmt::Write for Message {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let n = s.len().min(self.bytes.len() - self.len);
            self.bytes[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
            self.len += n;
            Ok(())
        }
    }
    use core::fmt::Write;
    let mut message = Message {
        bytes: [0; 320],
        len: 0,
    };
    let _ = write!(
        message,
        "pid={pid} stream={} ",
        match stream {
            1 => "stdout",
            2 => "stderr",
            _ => "lifecycle",
        }
    );
    let prefix = message.len;
    message.bytes[prefix..prefix + len as usize].copy_from_slice(&bytes[40..40 + len as usize]);
    message.len += len as usize;
    Ok(ServiceRecord {
        source: match service {
            1 => b"service.sshd",
            2 => b"service.fsd",
            3 => b"service.logd",
            _ => unreachable!(), // validated before parsing producer bytes
        },
        severity: match stream {
            2 => 4,
            3 => 5,
            _ => 6,
        },
        message: message.bytes,
        len: message.len,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record {
    pub sequence: u64,
    pub ticks: Option<u64>,
    pub flags: u32,
    pub severity: u8,
    source_len: u8,
    len: u16,
    source: [u8; 16],
    message: [u8; MAX_MESSAGE],
}
impl Record {
    const EMPTY: Self = Self {
        sequence: 0,
        ticks: None,
        flags: 0,
        severity: 6,
        source_len: 0,
        len: 0,
        source: [0; 16],
        message: [0; MAX_MESSAGE],
    };
    pub fn text(&self) -> &[u8] {
        &self.message[..self.len as usize]
    }
    pub fn source(&self) -> &[u8] {
        &self.source[..self.source_len as usize]
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Read {
    pub record: Option<Record>,
    pub next: u64,
    pub oldest: u64,
    pub end: u64,
    pub lost: u64,
    pub producer_dropped: u64,
}
impl Read {
    pub fn encode(&self) -> [u8; FRAME_BYTES] {
        let mut b = [0; FRAME_BYTES];
        b[0..4].copy_from_slice(&1u32.to_le_bytes());
        b[4..8].copy_from_slice(&u32::from(self.record.is_some()).to_le_bytes());
        for (at, n) in [
            (8, self.next),
            (16, self.oldest),
            (24, self.end),
            (32, self.lost),
            (40, self.producer_dropped),
        ] {
            b[at..at + 8].copy_from_slice(&n.to_le_bytes());
        }
        if let Some(r) = self.record {
            b[48..56].copy_from_slice(&r.sequence.to_le_bytes());
            b[56..64].copy_from_slice(&r.ticks.unwrap_or(u64::MAX).to_le_bytes());
            b[64..68].copy_from_slice(&r.flags.to_le_bytes());
            b[68] = r.severity;
            b[69] = r.source_len;
            b[70..72].copy_from_slice(&r.len.to_le_bytes());
            b[72..88].copy_from_slice(&r.source);
            b[88..568].copy_from_slice(&r.message);
        }
        b
    }
}
struct Ring {
    records: [Record; CAPACITY],
    end: u64,
    partial: Record,
    discarding: bool,
}
impl Ring {
    const fn new() -> Self {
        Self {
            records: [Record::EMPTY; CAPACITY],
            end: 1,
            partial: Record::EMPTY,
            discarding: false,
        }
    }
    fn insert(&mut self, mut r: Record) {
        // Exhaustion is unreachable in practice; stop rather than wrap identity.
        if self.end == u64::MAX {
            return;
        }
        r.sequence = self.end;
        self.records[((self.end - 1) % CAPACITY as u64) as usize] = r;
        self.end += 1;
    }
    fn finish(&mut self, flags: u32) {
        if self.partial.len == 0 && !self.discarding {
            return;
        }
        self.partial.flags |= flags | INFERRED;
        let text = self.partial.text();
        // Existing streamed diagnostics have no structured severity/source.
        // Infer only a printable first subsystem token and conservative hints.
        let len = text
            .iter()
            .take(16)
            .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            .count();
        if len != 0 {
            self.partial.source[..len].copy_from_slice(&self.partial.message[..len]);
            self.partial.source_len = len as u8;
        } else {
            self.partial.source[..6].copy_from_slice(b"kernel");
            self.partial.source_len = 6;
        }
        self.partial.severity = if text_contains(self.partial.text(), b"PANIC") {
            2
        } else if text_contains(self.partial.text(), b"FAILED")
            || text_contains(self.partial.text(), b"ERROR")
        {
            3
        } else if text_contains(self.partial.text(), b"WARN") {
            4
        } else {
            6
        };
        if flags & LOSS != 0 {
            self.partial.source = [0; 16];
            self.partial.source[..7].copy_from_slice(b"unknown");
            self.partial.source_len = 7;
            self.partial.severity = 6;
        }
        self.insert(self.partial);
        self.partial = Record::EMPTY;
        self.discarding = false;
    }
}
fn text_contains(text: &[u8], needle: &[u8]) -> bool {
    text.windows(needle.len()).any(|w| w == needle)
}

pub struct Log {
    busy: AtomicBool,
    dropped: AtomicU64,
    damaged: AtomicBool,
    ring: UnsafeCell<Ring>,
}
// Every ring access is protected by the one-shot Acquire/Release lock. A
// failed acquisition touches only an atomic counter, including IRQ reentry.
unsafe impl Sync for Log {}
impl Default for Log {
    fn default() -> Self {
        Self::new()
    }
}
impl Log {
    pub const fn new() -> Self {
        Self {
            busy: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
            damaged: AtomicBool::new(false),
            ring: UnsafeCell::new(Ring::new()),
        }
    }
    fn with<T>(&self, f: impl FnOnce(&mut Ring) -> T) -> Option<T> {
        if self
            .busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return None;
        }
        struct Guard<'a>(&'a AtomicBool);
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _guard = Guard(&self.busy);
        Some(f(unsafe { &mut *self.ring.get() }))
    }
    #[cfg(test)]
    pub(crate) fn test_while_locked(&self, f: impl FnOnce()) {
        self.with(|_| f()).unwrap();
    }
    pub fn emit(
        &self,
        source: &[u8],
        severity: u8,
        ticks: Option<u64>,
        message: &[u8],
        flags: u32,
    ) -> bool {
        let written = self
            .with(|ring| {
                let mut r = Record::EMPTY;
                r.ticks = ticks;
                r.flags = flags;
                r.severity = severity.min(7);
                r.source_len = source.len().min(16) as u8;
                r.source[..r.source_len as usize].copy_from_slice(&source[..r.source_len as usize]);
                r.len = message.len().min(MAX_MESSAGE) as u16;
                r.message[..r.len as usize].copy_from_slice(&message[..r.len as usize]);
                if message.len() > MAX_MESSAGE {
                    r.flags |= TRUNCATED;
                }
                ring.insert(r);
            })
            .is_some();
        if !written {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        written
    }
    /// Fragmented console bytes require the existing kernel console/BKL
    /// serialization; concurrent producers use emit for complete records.
    pub fn byte(&self, b: u8, ticks: Option<u64>) {
        if self
            .with(|ring| {
                if b == b'\n' {
                    ring.finish(if self.damaged.swap(false, Ordering::AcqRel) {
                        LOSS
                    } else {
                        0
                    });
                    return;
                }
                if ring.partial.len == 0 {
                    ring.partial.ticks = ticks;
                }
                if (ring.partial.len as usize) < MAX_MESSAGE {
                    ring.partial.message[ring.partial.len as usize] = b;
                    ring.partial.len += 1;
                } else {
                    ring.partial.flags |= TRUNCATED;
                    ring.discarding = true;
                }
            })
            .is_none()
        {
            self.damaged.store(true, Ordering::Release);
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    /// Explicitly publish a pending non-newline fragment at a fatal boundary.
    pub fn flush(&self) {
        if self
            .with(|r| {
                r.finish(
                    PARTIAL
                        | if self.damaged.swap(false, Ordering::AcqRel) {
                            LOSS
                        } else {
                            0
                        },
                )
            })
            .is_none()
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    /// A slow reader receives its exact overwritten sequence count. Cursor 0
    /// starts at current oldest, reporting retention prefix in oldest itself.
    pub fn read(&self, cursor: u64) -> Result<Read, i64> {
        self.with(|ring| {
            let oldest = ring.end.saturating_sub(CAPACITY as u64).max(1);
            if cursor > ring.end {
                return Err(-22);
            }
            let at = if cursor == 0 {
                oldest
            } else {
                cursor.max(oldest)
            };
            let record = if at < ring.end {
                Some(ring.records[((at - 1) % CAPACITY as u64) as usize])
            } else {
                None
            };
            Ok(Read {
                record,
                next: at + u64::from(record.is_some()),
                oldest,
                end: ring.end,
                lost: if cursor == 0 {
                    0
                } else {
                    oldest.saturating_sub(cursor)
                },
                producer_dropped: self.dropped.load(Ordering::Relaxed),
            })
        })
        .unwrap_or(Err(-11))
    }
}
/// Retained from the first Rust console output; assembly/firmware predates it.
pub static LOG: Log = Log::new();
static CLOCK_READY: AtomicBool = AtomicBool::new(false);
pub fn clock_ready() {
    CLOCK_READY.store(true, Ordering::Release);
}
pub fn timestamp(ticks: u64) -> Option<u64> {
    CLOCK_READY.load(Ordering::Acquire).then_some(ticks)
}
