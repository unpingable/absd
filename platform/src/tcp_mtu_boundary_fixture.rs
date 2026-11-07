//! Finite local Client/Session fixture; no delegated process or kernel pipe.
use absd_net::{FRAME_MAX, Link, LinkReading, NicLink, Stack, datagram, stream};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

pub const PEER: [u8; 4] = [198, 51, 100, 2];
pub const LIMIT: usize = 256;
pub const SLOTS: [&str; 3] = ["target", "unaffected", "reserved"];
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
pub fn pause(ms: u64) {
    absd_runtime::sleep_ticks(ms.max(40));
}

pub struct Frame {
    pub tx: bool,
    pub ordinal: usize,
    pub phase: &'static str,
    pub at: u64,
    pub bytes: Vec<u8>,
}
pub struct Trace {
    pub frames: Vec<Frame>,
    pub tx: usize,
    pub rx: usize,
    pub phase: &'static str,
    flushed: usize,
}
impl Trace {
    pub fn new() -> Self {
        Self {
            frames: Vec::new(),
            tx: 0,
            rx: 0,
            phase: "setup",
            flushed: 0,
        }
    }
    fn push(&mut self, tx: bool, bytes: &[u8], at: u64) -> Result<(), i64> {
        let ordinal = if tx { &mut self.tx } else { &mut self.rx };
        if *ordinal >= LIMIT || bytes.len() > FRAME_MAX {
            return Err(-5);
        }
        *ordinal += 1;
        self.frames.push(Frame {
            tx,
            ordinal: *ordinal,
            phase: self.phase,
            at,
            bytes: bytes.to_vec(),
        });
        Ok(())
    }
    pub fn flush(&mut self) {
        for f in &self.frames[self.flushed..] {
            println!(
                "TCP MTU BOUNDARY FRAME v=1 direction={} ordinal={} phase={} at_ms={} bytes={} hex={}",
                if f.tx { "tx" } else { "rx" },
                f.ordinal,
                f.phase,
                f.at,
                f.bytes.len(),
                hex(&f.bytes)
            );
        }
        self.flushed = self.frames.len();
    }
    pub fn controls(&self) -> Vec<usize> {
        self.frames
            .iter()
            .filter(|f| {
                let b = &f.bytes;
                !f.tx
                    && b.len() >= 42
                    && b[12..14] == [8, 0]
                    && b[14] == 0x45
                    && b[23] == 1
                    && b[34..36] == [3, 4]
            })
            .map(|f| f.ordinal)
            .collect()
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
    pub sessions: [Option<stream::Session>; 3],
    pub trace: Rc<RefCell<Trace>>,
    pub rpc: usize,
    pub until: u64,
    last: Cell<u64>,
    clock_failed: Cell<bool>,
}
impl Context {
    pub fn new(
        stack: Stack<ReceiptLink>,
        trace: Rc<RefCell<Trace>>,
        start: u64,
        until: u64,
    ) -> Self {
        Self {
            stack,
            sessions: [None, None, None],
            trace,
            rpc: 0,
            until,
            last: Cell::new(start),
            clock_failed: Cell::new(false),
        }
    }
    pub fn time(&self) -> Result<u64, String> {
        let now = absd_runtime::boot_millis();
        if self.clock_failed.get() || now < self.last.get() || now >= self.until {
            self.clock_failed.set(true);
            return Err("original clock budget exhausted or rewound".into());
        }
        self.last.set(now);
        Ok(now)
    }
    pub fn poll(&mut self) -> Result<(), String> {
        self.time()?;
        self.stack.poll();
        self.trace.borrow_mut().flush();
        self.time()?;
        Ok(())
    }
    pub fn revoke(&mut self, slot: usize) -> Result<(), String> {
        self.time()?;
        let mut session = self.sessions[slot].take().ok_or("missing session")?;
        session.revoke(&mut self.stack);
        Ok(())
    }
}
pub struct LocalPipe {
    context: Rc<RefCell<Context>>,
    slot: usize,
    input: Vec<u8>,
    output: Vec<u8>,
    read_at: usize,
}
impl LocalPipe {
    pub fn new(context: Rc<RefCell<Context>>, slot: usize) -> Self {
        Self {
            context,
            slot,
            input: Vec::new(),
            output: Vec::new(),
            read_at: 0,
        }
    }
}
impl datagram::channel::Pipe for LocalPipe {
    fn now_ms(&self) -> u64 {
        self.context.borrow().time().unwrap_or(u64::MAX)
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
            if c.rpc >= LIMIT {
                return Err(-5);
            }
            c.poll().map_err(|_| -5)?;
            let mut session = c.sessions[self.slot].take().ok_or(-5i64)?;
            let mut reply = [0; datagram::MAX_MESSAGE];
            let n = session.request(&mut c.stack, &self.input[2..], &mut reply);
            c.sessions[self.slot] = Some(session);
            if !(12..=stream::MAX_MESSAGE).contains(&n) {
                return Err(-5);
            }
            c.rpc += 1;
            let at = c.time().map_err(|_| -5)?;
            println!(
                "TCP MTU BOUNDARY RPC v=1 index={} slot={} logical={} phase={} at_ms={at} request_bytes={wanted} request_hex={} reply_bytes={n} reply_hex={}",
                c.rpc,
                SLOTS[self.slot],
                self.slot + 1,
                c.trace.borrow().phase,
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
