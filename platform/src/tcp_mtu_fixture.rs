//! Private finite native qualification fixture. The local Pipe exercises real
//! Client and Session codecs, without claiming a kernel pipe or child process.
use absd_net::{FRAME_MAX, Link, LinkReading, NicLink, Stack, datagram, stream};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

pub const PEER: [u8; 4] = [198, 51, 100, 2];
pub const WHOLE_MS: u64 = 30_000;
pub const REFUSAL_MS: u64 = 12_000;
pub const POSITIVE_MS: u64 = 10_000;
pub const MAX_RECORDS: usize = 128;

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Clone)]
pub struct Frame {
    pub tx: bool,
    pub ordinal: usize,
    pub positive: bool,
    pub at_ms: u64,
    pub bytes: Vec<u8>,
}
#[derive(Default)]
pub struct Trace {
    pub frames: Vec<Frame>,
    pub tx: usize,
    pub rx: usize,
    pub positive: bool,
    pub flushed: usize,
}
impl Trace {
    fn push(&mut self, tx: bool, bytes: &[u8], at_ms: u64) -> Result<(), i64> {
        let ordinal = if tx { &mut self.tx } else { &mut self.rx };
        if *ordinal >= MAX_RECORDS || bytes.len() > FRAME_MAX {
            return Err(-5);
        }
        *ordinal += 1;
        self.frames.push(Frame {
            tx,
            ordinal: *ordinal,
            positive: self.positive,
            at_ms,
            bytes: bytes.to_vec(),
        });
        Ok(())
    }
    pub fn flush(&mut self) {
        for f in &self.frames[self.flushed..] {
            println!(
                "TCP MTU FRAME v=1 direction={} ordinal={} phase={} at_ms={} bytes={} hex={}",
                if f.tx { "tx" } else { "rx" },
                f.ordinal,
                if f.positive { "positive" } else { "refusal" },
                f.at_ms,
                f.bytes.len(),
                hex(&f.bytes)
            );
        }
        self.flushed = self.frames.len();
    }
}
pub struct ReceiptLink {
    pub inner: NicLink,
    pub trace: Rc<RefCell<Trace>>,
}
impl Link for ReceiptLink {
    fn mac(&self) -> [u8; 6] {
        self.inner.mac()
    }
    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
    fn pause(&self, ms: u64) {
        self.inner.pause(ms)
    }
    fn link_up(&self) -> bool {
        self.inner.link_up()
    }
    fn disabled(&self) -> bool {
        self.inner.disabled()
    }
    fn read(&self) -> Option<LinkReading> {
        self.inner.read()
    }
    fn send(&mut self, b: &[u8]) -> Result<(), i64> {
        self.inner.send(b)?;
        self.trace.borrow_mut().push(true, b, self.inner.now_ms())
    }
    fn receive(&mut self, b: &mut [u8; FRAME_MAX], timeout: u64) -> Result<Option<usize>, i64> {
        let n = self.inner.receive(b, timeout)?;
        if let Some(n) = n {
            if n > FRAME_MAX {
                return Err(-5);
            }
            self.trace
                .borrow_mut()
                .push(false, &b[..n], self.inner.now_ms())?;
        }
        Ok(n)
    }
}
pub struct Context {
    pub stack: Stack<ReceiptLink>,
    pub session: Option<stream::Session>,
    pub trace: Rc<RefCell<Trace>>,
    pub rpc: usize,
    pub positive: bool,
    pub whole: u64,
    last: Cell<u64>,
    failed_clock: Cell<bool>,
}
impl Context {
    pub fn new(
        stack: Stack<ReceiptLink>,
        trace: Rc<RefCell<Trace>>,
        whole: u64,
        start: u64,
    ) -> Self {
        Self {
            stack,
            session: None,
            trace,
            rpc: 0,
            positive: false,
            whole,
            last: Cell::new(start),
            failed_clock: Cell::new(false),
        }
    }
    pub fn time(&self, until: u64) -> Result<u64, String> {
        let now = absd_runtime::boot_millis();
        if self.failed_clock.get() || now < self.last.get() || now >= self.whole.min(until) {
            self.failed_clock.set(true);
            return Err("original clock budget exhausted or rewound".into());
        }
        self.last.set(now);
        Ok(now)
    }
    pub fn poll(&mut self) -> Result<(), String> {
        self.time(self.whole)?;
        self.stack.poll();
        self.trace.borrow_mut().flush();
        self.time(self.whole)?;
        Ok(())
    }
    pub fn revoke(&mut self) -> Result<(), String> {
        let mut session = self.session.take().ok_or("missing session")?;
        session.revoke(&mut self.stack);
        Ok(())
    }
}
pub struct LocalPipe {
    pub context: Rc<RefCell<Context>>,
    input: Vec<u8>,
    output: Vec<u8>,
    read_at: usize,
}
impl LocalPipe {
    pub fn new(context: Rc<RefCell<Context>>) -> Self {
        Self {
            context,
            input: Vec::new(),
            output: Vec::new(),
            read_at: 0,
        }
    }
}
impl datagram::channel::Pipe for LocalPipe {
    fn now_ms(&self) -> u64 {
        let c = self.context.borrow();
        c.time(c.whole).unwrap_or(u64::MAX)
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        if bytes.is_empty()
            || bytes.len() > 256
            || !self.output.is_empty()
            || self.input.len() + bytes.len() > stream::MAX_MESSAGE + 2
        {
            return Err(-22);
        }
        self.input.extend_from_slice(bytes);
        Ok(Some(bytes.len()))
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        if self.output.is_empty() {
            if self.input.len() < 2 {
                return Err(-22);
            }
            let wanted = usize::from(u16::from_be_bytes([self.input[0], self.input[1]]));
            if !(12..=stream::MAX_MESSAGE).contains(&wanted) || self.input.len() != wanted + 2 {
                return Err(-22);
            }
            let mut c = self.context.borrow_mut();
            if c.rpc >= MAX_RECORDS {
                return Err(-5);
            }
            c.poll().map_err(|_| -5)?;
            let mut session = c.session.take().ok_or(-5i64)?;
            let mut reply = [0; datagram::MAX_MESSAGE];
            let n = session.request(&mut c.stack, &self.input[2..], &mut reply);
            c.session = Some(session);
            if !(12..=stream::MAX_MESSAGE).contains(&n) {
                return Err(-5);
            }
            c.rpc += 1;
            let at = c.time(c.whole).map_err(|_| -5)?;
            println!(
                "TCP MTU RPC v=1 index={} phase={} at_ms={at} request_bytes={wanted} request_hex={} reply_bytes={n} reply_hex={}",
                c.rpc,
                if c.positive { "positive" } else { "refusal" },
                hex(&self.input[2..]),
                hex(&reply[..n])
            );
            self.output.extend_from_slice(&(n as u16).to_be_bytes());
            self.output.extend_from_slice(&reply[..n]);
            self.input.clear();
        }
        let n = bytes.len().min(self.output.len() - self.read_at);
        if n == 0 {
            return Err(-22);
        }
        bytes[..n].copy_from_slice(&self.output[self.read_at..self.read_at + n]);
        self.read_at += n;
        if self.read_at == self.output.len() {
            self.output.clear();
            self.read_at = 0;
        }
        Ok(Some(n))
    }
}
pub fn pause(ms: u64) {
    absd_runtime::sleep_ticks(ms.max(40));
}
