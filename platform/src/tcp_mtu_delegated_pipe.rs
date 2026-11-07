//! Bounded observations of actual kernel-pipe I/O, published after I/O ends.
use absd_net::datagram::channel::Pipe;
use std::{cell::RefCell, rc::Rc};

pub const CHUNKS: usize = 512;
pub const BYTES: usize = 65_536;
pub fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "none".into();
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn output(observer: &str, text: String) {
    if observer == "owner" {
        println!("{text}");
    } else {
        eprintln!("{text}");
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counts {
    pub read_calls: usize,
    pub write_calls: usize,
    pub request_bytes: usize,
    pub reply_bytes: usize,
}
struct Chunk {
    direction: &'static str,
    ordinal: usize,
    offset: usize,
    at: u64,
    bytes: Vec<u8>,
}
pub struct Ledger {
    chunks: Vec<Chunk>,
    counts: Counts,
    ordinals: [usize; 2],
    last_ms: u64,
    pub request_eof: Option<u64>,
    pub reply_eof: Option<u64>,
    failed: bool,
}
impl Ledger {
    pub fn new() -> Self {
        Self {
            chunks: Vec::new(),
            counts: Counts {
                read_calls: 0,
                write_calls: 0,
                request_bytes: 0,
                reply_bytes: 0,
            },
            ordinals: [0, 0],
            last_ms: 0,
            request_eof: None,
            reply_eof: None,
            failed: false,
        }
    }
    pub fn counts(&self) -> Counts {
        self.counts
    }
    pub fn good(&self) -> bool {
        !self.failed
    }
    fn record(
        &mut self,
        direction: &'static str,
        bytes: &[u8],
        at: u64,
        read: bool,
    ) -> Result<(), i64> {
        let (index, offset) = if direction == "request" {
            (0, self.counts.request_bytes)
        } else {
            (1, self.counts.reply_bytes)
        };
        // Space is checked before the underlying operation, too. Keep any
        // actual returned bytes even if the post-I/O clock then refuses.
        if self.chunks.len() >= CHUNKS || offset.checked_add(bytes.len()).is_none_or(|n| n > BYTES)
        {
            self.failed = true;
            return Err(-5);
        }
        self.ordinals[index] += 1;
        self.chunks.push(Chunk {
            direction,
            ordinal: self.ordinals[index],
            offset,
            at,
            bytes: bytes.to_vec(),
        });
        if direction == "request" {
            self.counts.request_bytes += bytes.len();
            if bytes.is_empty() && read {
                self.request_eof = Some(at);
            }
        } else {
            self.counts.reply_bytes += bytes.len();
            if bytes.is_empty() && read {
                self.reply_eof = Some(at);
            }
        }
        if at < self.last_ms || (bytes.is_empty() && !read) {
            self.failed = true;
        }
        self.last_ms = at;
        if self.failed { Err(-5) } else { Ok(()) }
    }
    pub fn emit(&self, observer: &str, child: usize, phase: &str) {
        for c in &self.chunks {
            output(
                observer,
                format!(
                    "TCP MTU DELEGATED PIPE v=1 observer={observer} child={child} phase={phase} direction={} ordinal={} offset={} at_ms={} bytes={} hex={}",
                    c.direction,
                    c.ordinal,
                    c.offset,
                    c.at,
                    c.bytes.len(),
                    hex(&c.bytes)
                ),
            );
        }
        output(
            observer,
            format!(
                "TCP MTU DELEGATED PIPE_SEAL v=1 observer={observer} child={child} phase={phase} records={} request_bytes={} reply_bytes={} read_calls={} write_calls={} request_eof={} reply_eof={} failed={}",
                self.chunks.len(),
                self.counts.request_bytes,
                self.counts.reply_bytes,
                self.counts.read_calls,
                self.counts.write_calls,
                self.request_eof
                    .map_or_else(|| "none".into(), |n| n.to_string()),
                self.reply_eof
                    .map_or_else(|| "none".into(), |n| n.to_string()),
                u8::from(self.failed)
            ),
        );
    }
}
pub struct Observed<P: Pipe> {
    pub inner: P,
    pub ledger: Rc<RefCell<Ledger>>,
    owner: bool,
}
impl<P: Pipe> Observed<P> {
    pub fn new(inner: P, ledger: Rc<RefCell<Ledger>>, owner: bool) -> Self {
        Self {
            inner,
            ledger,
            owner,
        }
    }
    fn space(&self) -> Result<(), i64> {
        let l = self.ledger.borrow();
        if !l.good()
            || l.chunks.len() >= CHUNKS
            || l.counts.request_bytes > BYTES - 256
            || l.counts.reply_bytes > BYTES - 256
        {
            Err(-5)
        } else {
            Ok(())
        }
    }
}
impl<P: Pipe> Pipe for Observed<P> {
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        self.space()?;
        if bytes.is_empty() || bytes.len() > 256 {
            return Err(-22);
        }
        self.ledger.borrow_mut().counts.read_calls += 1;
        let result = self.inner.read(bytes);
        if let Ok(Some(n)) = result {
            if n > bytes.len() {
                return Err(-5);
            }
            self.ledger.borrow_mut().record(
                if self.owner { "request" } else { "reply" },
                &bytes[..n],
                self.inner.now_ms(),
                true,
            )?;
        }
        result
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        self.space()?;
        if bytes.is_empty() || bytes.len() > 256 {
            return Err(-22);
        }
        self.ledger.borrow_mut().counts.write_calls += 1;
        let result = self.inner.write(bytes);
        if let Ok(Some(n)) = result {
            if n > bytes.len() {
                return Err(-5);
            }
            self.ledger.borrow_mut().record(
                if self.owner { "reply" } else { "request" },
                &bytes[..n],
                self.inner.now_ms(),
                false,
            )?;
        }
        result
    }
    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
}
