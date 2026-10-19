//! Owned native capability adapter. Unknown completion spends the pipe.
use crate::engine::{Hooks, Outcome};
use absd_net::{datagram::channel::Pipe, ipv6, stream};
use std::{fmt, io};

// Family selection is explicit at construction and never retried with another
// family. Both clients own one pipe and preserve their existing wire codecs.
enum Client<P: Pipe> {
    V4(stream::Client<P>),
    V6(ipv6::stream::Client<P>),
}
impl<P: Pipe> Client<P> {
    fn now_ms(&self) -> u64 {
        match self {
            Self::V4(client) => client.now_ms(),
            Self::V6(client) => client.now_ms(),
        }
    }
    fn connect(&mut self, deadline: u64) -> Result<(), stream::Error> {
        match self {
            Self::V4(client) => client.connect(deadline),
            Self::V6(client) => client.connect(deadline),
        }
    }
    fn read(&mut self, bytes: &mut [u8], deadline: u64) -> Result<usize, stream::Error> {
        match self {
            Self::V4(client) => client.read(bytes, deadline),
            Self::V6(client) => client.read(bytes, deadline),
        }
    }
    fn write(&mut self, bytes: &[u8], deadline: u64) -> Result<usize, stream::Error> {
        match self {
            Self::V4(client) => client.write(bytes, deadline),
            Self::V6(client) => client.write(bytes, deadline),
        }
    }
    fn close(&mut self, deadline: u64) -> Result<(), stream::Error> {
        match self {
            Self::V4(client) => client.close(deadline),
            Self::V6(client) => client.close(deadline),
        }
    }
    fn max_io(&self) -> usize {
        match self {
            Self::V4(_) => stream::MAX_IO,
            Self::V6(_) => ipv6::stream::MAX_IO,
        }
    }
}

pub const RX_LIMIT: u64 = 131_072;
pub const TX_LIMIT: u64 = 32_768;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Read,
    Write,
}
impl Direction {
    pub fn code(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct IoEvent {
    pub direction: Direction,
    pub requested: usize,
    pub accepted: usize,
    pub native_error: Option<stream::Error>,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Metrics {
    pub read_calls: u64,
    pub write_calls: u64,
    pub read_requested: u64,
    pub read_accepted: u64,
    pub write_requested: u64,
    pub write_accepted: u64,
    pub read_again: u64,
    pub write_again: u64,
    pub short_writes: u64,
    pub connect_calls: u64,
    pub close_calls: u64,
    pub native_eof: bool,
    pub pipe_fenced: bool,
}
#[derive(Debug)]
struct Failure {
    outcome: Outcome,
    native: Option<stream::Error>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {:?}", self.outcome.code(), self.native)
    }
}
impl std::error::Error for Failure {}

pub struct NativeTransport<P: Pipe> {
    client: Option<Client<P>>,
    deadline: u64,
    last: u64,
    hooks: Hooks,
    pub metrics: Metrics,
    pub outcome: Option<Outcome>,
    pub native_error: Option<stream::Error>,
}
impl<P: Pipe> NativeTransport<P> {
    pub fn new(pipe: P, deadline: u64, hooks: Hooks) -> Self {
        Self::from_client(
            Client::V4(stream::Client::new(pipe, crate::PEER, hooks.pause_ms)),
            deadline,
            hooks,
        )
    }
    /// Consume a dedicated IPv6 stream channel for this exact scoped peer.
    /// The NIC owner must independently grant it; an address grants no authority.
    pub fn new_ipv6(pipe: P, peer: ipv6::Address, deadline: u64, hooks: Hooks) -> Self {
        Self::from_client(
            Client::V6(ipv6::stream::Client::new(pipe, peer, hooks.pause_ms)),
            deadline,
            hooks,
        )
    }
    fn from_client(client: Client<P>, deadline: u64, hooks: Hooks) -> Self {
        let last = client.now_ms();
        Self {
            client: Some(client),
            deadline,
            last,
            hooks,
            metrics: Metrics::default(),
            outcome: None,
            native_error: None,
        }
    }
    pub fn check(&mut self) -> io::Result<()> {
        if self.client.is_none() {
            return Err(self.error(Outcome::Native, Some(stream::Error::Stale)));
        }
        if (self.hooks.cancelled)() {
            return Err(self.error(Outcome::Cancelled, None));
        }
        let now = self.client.as_ref().unwrap().now_ms();
        let outcome = if now < self.last {
            Some(Outcome::Clock)
        } else if now >= self.deadline {
            Some(Outcome::Timeout)
        } else {
            None
        };
        self.last = now;
        if let Some(outcome) = outcome {
            return Err(self.error(outcome, None));
        }
        Ok(())
    }
    fn error(&mut self, outcome: Outcome, native: Option<stream::Error>) -> io::Error {
        if self.outcome.is_none() {
            self.outcome = Some(outcome);
            self.native_error = native;
        }
        self.fence();
        let kind = match outcome {
            Outcome::Timeout => io::ErrorKind::TimedOut,
            Outcome::Clock => io::ErrorKind::InvalidData,
            Outcome::Cancelled => io::ErrorKind::Interrupted,
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, Failure { outcome, native })
    }
    fn native_failure(&mut self, error: stream::Error) -> io::Error {
        let now = self.client.as_ref().map(|client| client.now_ms());
        let outcome = if error == stream::Error::Clock || now.is_some_and(|now| now < self.last) {
            Outcome::Clock
        } else if error == stream::Error::Timeout || now.is_some_and(|now| now >= self.deadline) {
            Outcome::Timeout
        } else {
            Outcome::Native
        };
        self.error(outcome, Some(error))
    }
    pub fn fence(&mut self) {
        self.client = None;
        self.metrics.pipe_fenced = true;
    }
    pub fn connect(&mut self) -> io::Result<()> {
        self.check()?;
        self.metrics.connect_calls += 1;
        let result = self.client.as_mut().unwrap().connect(self.deadline);
        result.map_err(|e| self.native_failure(e))
    }
    pub fn close(&mut self) -> io::Result<()> {
        self.check()?;
        self.metrics.close_calls += 1;
        let result = self.client.as_mut().unwrap().close(self.deadline);
        let result = result.map_err(|e| self.native_failure(e));
        self.fence();
        result
    }
    fn event(
        &self,
        direction: Direction,
        requested: usize,
        accepted: usize,
        error: Option<stream::Error>,
    ) {
        (self.hooks.io_event)(IoEvent {
            direction,
            requested,
            accepted,
            native_error: error,
        });
    }
}
impl<P: Pipe> io::Read for NativeTransport<P> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.metrics.native_eof {
            return Ok(0);
        }
        if self.metrics.read_accepted == RX_LIMIT {
            return Err(self.error(Outcome::WireBudget, None));
        }
        let count = bytes
            .len()
            .min(self.client.as_ref().unwrap().max_io())
            .min((RX_LIMIT - self.metrics.read_accepted) as usize);
        self.metrics.read_calls += 1;
        self.metrics.read_requested += count as u64;
        let result = self
            .client
            .as_mut()
            .unwrap()
            .read(&mut bytes[..count], self.deadline);
        match result {
            Ok(n) => {
                self.metrics.read_accepted += n as u64;
                self.event(Direction::Read, count, n, None);
                Ok(n)
            }
            Err(stream::Error::Again) => {
                self.metrics.read_again += 1;
                self.event(Direction::Read, count, 0, Some(stream::Error::Again));
                Err(io::ErrorKind::WouldBlock.into())
            }
            Err(stream::Error::Eof) => {
                self.metrics.native_eof = true;
                self.native_error = Some(stream::Error::Eof);
                self.event(Direction::Read, count, 0, Some(stream::Error::Eof));
                Ok(0)
            }
            Err(e) => {
                self.event(Direction::Read, count, 0, Some(e));
                Err(self.native_failure(e))
            }
        }
    }
}
impl<P: Pipe> io::Write for NativeTransport<P> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.check()?;
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.metrics.write_accepted == TX_LIMIT {
            return Err(self.error(Outcome::WireBudget, None));
        }
        let count = bytes
            .len()
            .min(self.client.as_ref().unwrap().max_io())
            .min((TX_LIMIT - self.metrics.write_accepted) as usize);
        self.metrics.write_calls += 1;
        self.metrics.write_requested += count as u64;
        let result = self
            .client
            .as_mut()
            .unwrap()
            .write(&bytes[..count], self.deadline);
        match result {
            Ok(n) => {
                self.metrics.write_accepted += n as u64;
                if n < count {
                    self.metrics.short_writes += 1;
                }
                self.event(Direction::Write, count, n, None);
                Ok(n)
            }
            Err(stream::Error::Again) => {
                self.metrics.write_again += 1;
                self.event(Direction::Write, count, 0, Some(stream::Error::Again));
                Err(io::ErrorKind::WouldBlock.into())
            }
            Err(stream::Error::WriteClosed) => {
                self.native_error = Some(stream::Error::WriteClosed);
                self.event(Direction::Write, count, 0, Some(stream::Error::WriteClosed));
                Err(io::ErrorKind::BrokenPipe.into())
            }
            Err(e) => {
                self.event(Direction::Write, count, 0, Some(e));
                Err(self.native_failure(e))
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::RefCell,
        collections::VecDeque,
        io::{Read, Write},
        rc::Rc,
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Mutex,
        },
    };
    static LOCK: Mutex<()> = Mutex::new(());
    static NOW: AtomicU64 = AtomicU64::new(1);
    static CANCELLED: AtomicBool = AtomicBool::new(false);
    fn now() -> u64 {
        NOW.load(Ordering::Relaxed)
    }
    fn hooks() -> Hooks {
        Hooks {
            now_ms: now,
            pause_ms: |_| {},
            cancelled: || CANCELLED.load(Ordering::Relaxed),
            io_event: |_| {},
            phase_event: |_| {},
        }
    }
    enum Reply {
        Connected,
        Accepted(usize),
        Bytes(&'static [u8]),
        Error(stream::Error),
        Lost,
        Expired,
        WrongPeer,
        InvalidCount,
        Closed,
    }
    #[derive(Default)]
    struct Record {
        calls: Vec<u8>,
        dropped: bool,
        accepted: Vec<u8>,
    }
    struct FixturePipe {
        record: Rc<RefCell<Record>>,
        replies: VecDeque<Reply>,
        input: Vec<u8>,
        output: VecDeque<u8>,
        lost: bool,
        expire_on_read: bool,
    }
    impl FixturePipe {
        fn new(replies: Vec<Reply>) -> (Self, Rc<RefCell<Record>>) {
            let record = Rc::new(RefCell::new(Record::default()));
            (
                Self {
                    record: record.clone(),
                    replies: replies.into(),
                    input: Vec::new(),
                    output: VecDeque::new(),
                    lost: false,
                    expire_on_read: false,
                },
                record,
            )
        }
    }
    impl Drop for FixturePipe {
        fn drop(&mut self) {
            self.record.borrow_mut().dropped = true;
        }
    }
    impl Pipe for FixturePipe {
        fn now_ms(&self) -> u64 {
            now()
        }
        fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
            // Fragment the framed capability exchange independently of stream WRITE counts.
            let n = bytes.len().min(5);
            self.input.extend_from_slice(&bytes[..n]);
            if self.input.len() >= 2 {
                let length = u16::from_be_bytes([self.input[0], self.input[1]]) as usize;
                if self.input.len() == length + 2 {
                    let request = std::mem::take(&mut self.input);
                    let op = request[3];
                    self.record.borrow_mut().calls.push(op);
                    let mut reply = request[2..14].to_vec();
                    reply[10..12].fill(0);
                    match self
                        .replies
                        .pop_front()
                        .expect("unexpected native transaction")
                    {
                        Reply::Connected => {
                            assert_eq!(op, stream::CONNECT);
                            reply[10..12].copy_from_slice(&1u16.to_be_bytes());
                            reply.push(1);
                        }
                        Reply::Accepted(count) => {
                            assert_eq!(op, stream::WRITE);
                            assert!(count <= length - 12);
                            reply[10..12].copy_from_slice(&(count as u16).to_be_bytes());
                            self.record
                                .borrow_mut()
                                .accepted
                                .extend_from_slice(&request[14..14 + count]);
                        }
                        Reply::Bytes(bytes) => {
                            assert_eq!(op, stream::READ);
                            reply[10..12].copy_from_slice(&(bytes.len() as u16).to_be_bytes());
                            reply.extend_from_slice(bytes);
                        }
                        Reply::Error(error) => reply[2] = error.code(),
                        Reply::Lost => {
                            self.lost = true;
                            return Ok(Some(n));
                        }
                        Reply::Expired => {
                            self.expire_on_read = true;
                            return Ok(Some(n));
                        }
                        Reply::WrongPeer => {
                            reply[4] ^= 1;
                        }
                        Reply::InvalidCount => {
                            assert_eq!(op, stream::WRITE);
                            reply[10..12].copy_from_slice(&1025u16.to_be_bytes());
                        }
                        Reply::Closed => {
                            assert_eq!(op, stream::CLOSE);
                        }
                    }
                    self.output.extend((reply.len() as u16).to_be_bytes());
                    self.output.extend(reply);
                }
            }
            Ok(Some(n))
        }
        fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
            if self.expire_on_read {
                NOW.store(100, Ordering::Relaxed);
                return Err(-5);
            }
            if self.lost {
                return Err(-5);
            }
            let n = bytes.len().min(3).min(self.output.len());
            if n == 0 {
                return Ok(None);
            }
            for b in &mut bytes[..n] {
                *b = self.output.pop_front().unwrap();
            }
            Ok(Some(n))
        }
    }
    fn reset() {
        NOW.store(1, Ordering::Relaxed);
        CANCELLED.store(false, Ordering::Relaxed);
    }
    #[test]
    fn native_short_write_and_again_preserve_exact_accepted_prefixes() {
        let _lock = LOCK.lock().unwrap();
        reset();
        let (pipe, record) = FixturePipe::new(vec![
            Reply::Connected,
            Reply::Accepted(3),
            Reply::Error(stream::Error::Again),
            Reply::Accepted(3),
        ]);
        let mut t = NativeTransport::new(pipe, 100, hooks());
        t.connect().unwrap();
        assert_eq!(t.write(b"abcdef").unwrap(), 3);
        assert_eq!(
            t.write(b"def").unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(t.write(b"def").unwrap(), 3);
        assert_eq!(record.borrow().accepted, b"abcdef");
        assert_eq!(t.metrics.short_writes, 1);
        assert_eq!(t.metrics.write_again, 1);
        assert_eq!(t.metrics.write_accepted, 6);
    }
    #[test]
    fn lost_write_reply_drops_the_pipe_and_never_replays_the_request() {
        let _lock = LOCK.lock().unwrap();
        reset();
        let (pipe, record) = FixturePipe::new(vec![Reply::Connected, Reply::Lost]);
        let mut t = NativeTransport::new(pipe, 100, hooks());
        t.connect().unwrap();
        assert!(t.write(b"abc").is_err());
        assert_eq!(t.native_error, Some(stream::Error::Channel(-5)));
        assert!(t.metrics.pipe_fenced);
        assert!(record.borrow().dropped);
        assert!(t.write(b"abc").is_err());
        assert!(t.read(&mut [0; 4]).is_err());
        assert_eq!(record.borrow().calls, vec![stream::CONNECT, stream::WRITE]);
    }
    #[test]
    fn write_half_close_preserves_reads_and_raw_eof() {
        let _lock = LOCK.lock().unwrap();
        reset();
        let (pipe, _) = FixturePipe::new(vec![
            Reply::Connected,
            Reply::Error(stream::Error::WriteClosed),
            Reply::Bytes(b"ok"),
            Reply::Error(stream::Error::Eof),
        ]);
        let mut t = NativeTransport::new(pipe, 100, hooks());
        t.connect().unwrap();
        assert_eq!(
            t.write(b"abc").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(t.native_error, Some(stream::Error::WriteClosed));
        assert!(!t.metrics.pipe_fenced);
        let mut bytes = [0; 4];
        assert_eq!(t.read(&mut bytes).unwrap(), 2);
        assert_eq!(&bytes[..2], b"ok");
        assert_eq!(t.read(&mut bytes).unwrap(), 0);
        assert_eq!(t.native_error, Some(stream::Error::Eof));
        assert!(t.metrics.native_eof);
        assert_eq!(t.read(&mut bytes).unwrap(), 0);
        assert_eq!(t.metrics.read_calls, 2);
    }
    #[test]
    fn cancellation_rewind_and_deadline_refuse_without_further_ipc() {
        let _lock = LOCK.lock().unwrap();
        for cause in [Outcome::Cancelled, Outcome::Clock, Outcome::Timeout] {
            reset();
            let (pipe, record) = FixturePipe::new(vec![Reply::Connected]);
            let mut t = NativeTransport::new(pipe, 100, hooks());
            t.connect().unwrap();
            match cause {
                Outcome::Cancelled => CANCELLED.store(true, Ordering::Relaxed),
                Outcome::Clock => NOW.store(0, Ordering::Relaxed),
                _ => NOW.store(100, Ordering::Relaxed),
            }
            assert!(t.write(b"abc").is_err());
            assert_eq!(t.outcome, Some(cause));
            NOW.store(1, Ordering::Relaxed);
            CANCELLED.store(false, Ordering::Relaxed);
            assert!(t.check().is_err());
            assert_eq!(t.outcome, Some(cause));
            assert!(record.borrow().dropped);
            assert_eq!(record.borrow().calls, vec![stream::CONNECT]);
        }
    }
    #[test]
    fn ipc_failure_at_deadline_retains_raw_error_with_timeout_outcome() {
        let _lock = LOCK.lock().unwrap();
        reset();
        let (pipe, record) = FixturePipe::new(vec![Reply::Connected, Reply::Expired]);
        let mut t = NativeTransport::new(pipe, 100, hooks());
        t.connect().unwrap();
        assert!(t.write(b"abc").is_err());
        assert_eq!(t.outcome, Some(Outcome::Timeout));
        assert_eq!(t.native_error, Some(stream::Error::Channel(-5)));
        assert!(record.borrow().dropped);
    }

    #[test]
    fn empty_io_does_not_connect_and_native_transfers_stop_at_exact_wire_budgets() {
        let _lock = LOCK.lock().unwrap();
        reset();
        let mut replies = vec![Reply::Connected];
        replies.extend((0..TX_LIMIT / 1024).map(|_| Reply::Accepted(1024)));
        let (pipe, record) = FixturePipe::new(replies);
        let mut t = NativeTransport::new(pipe, 100, hooks());
        assert_eq!(t.write(&[]).unwrap(), 0);
        assert_eq!(t.read(&mut []).unwrap(), 0);
        t.flush().unwrap();
        assert!(record.borrow().calls.is_empty());
        let offered = [b'x'; 2048];
        for _ in 0..TX_LIMIT / 1024 {
            assert_eq!(t.write(&offered).unwrap(), 1024);
        }
        assert_eq!(t.metrics.write_accepted, TX_LIMIT);
        assert_eq!(t.metrics.write_requested, TX_LIMIT);
        assert!(t.write(b"x").is_err());
        assert_eq!(t.outcome, Some(Outcome::WireBudget));
        assert_eq!(record.borrow().calls.len(), 1 + (TX_LIMIT / 1024) as usize);
        assert!(record.borrow().dropped);

        static CHUNK: [u8; 1024] = [b'x'; 1024];
        let mut replies = vec![Reply::Connected];
        replies.extend((0..RX_LIMIT / 1024).map(|_| Reply::Bytes(&CHUNK)));
        let (pipe, record) = FixturePipe::new(replies);
        let mut t = NativeTransport::new(pipe, 100, hooks());
        let mut bytes = [0; 2048];
        for _ in 0..RX_LIMIT / 1024 {
            assert_eq!(t.read(&mut bytes).unwrap(), 1024);
            assert_eq!(&bytes[..1024], &CHUNK);
        }
        assert_eq!(t.metrics.read_accepted, RX_LIMIT);
        assert_eq!(t.metrics.read_requested, RX_LIMIT);
        assert!(t.read(&mut bytes).is_err());
        assert_eq!(t.outcome, Some(Outcome::WireBudget));
        assert!(!t.metrics.native_eof);
        assert_eq!(record.borrow().calls.len(), 1 + (RX_LIMIT / 1024) as usize);
        assert!(record.borrow().dropped);
    }

    #[test]
    fn typed_native_refusals_and_malformed_replies_fence_before_any_later_transaction() {
        let _lock = LOCK.lock().unwrap();
        for error in [
            stream::Error::Invalid,
            stream::Error::Oversize,
            stream::Error::Stale,
            stream::Error::Denied,
            stream::Error::LinkDown,
            stream::Error::DeviceFailed,
            stream::Error::LinkUnknown,
        ] {
            reset();
            let (pipe, record) = FixturePipe::new(vec![Reply::Connected, Reply::Error(error)]);
            let mut t = NativeTransport::new(pipe, 100, hooks());
            t.connect().unwrap();
            assert!(t.write(b"x").is_err());
            assert_eq!(t.native_error, Some(error));
            assert_eq!(t.outcome, Some(Outcome::Native));
            assert!(record.borrow().dropped);
            assert!(t.write(b"x").is_err());
            assert_eq!(record.borrow().calls, vec![stream::CONNECT, stream::WRITE]);
        }
        for reply in [Reply::WrongPeer, Reply::InvalidCount] {
            reset();
            let (pipe, record) = FixturePipe::new(vec![Reply::Connected, reply]);
            let mut t = NativeTransport::new(pipe, 100, hooks());
            t.connect().unwrap();
            assert!(t.write(b"x").is_err());
            assert_eq!(t.native_error, Some(stream::Error::Channel(-22)));
            assert!(record.borrow().dropped);
            assert!(t.read(&mut [0; 1]).is_err());
            assert_eq!(record.borrow().calls, vec![stream::CONNECT, stream::WRITE]);
        }
    }

    #[test]
    fn graceful_native_close_is_one_accepted_transaction_and_drops_the_owned_pipe() {
        let _lock = LOCK.lock().unwrap();
        reset();
        let (pipe, record) = FixturePipe::new(vec![Reply::Connected, Reply::Closed]);
        let mut t = NativeTransport::new(pipe, 100, hooks());
        t.connect().unwrap();
        t.close().unwrap();
        assert_eq!(t.metrics.close_calls, 1);
        assert!(t.metrics.pipe_fenced);
        assert!(record.borrow().dropped);
        assert!(t.close().is_err());
        assert_eq!(t.metrics.close_calls, 1);
        assert_eq!(record.borrow().calls, vec![stream::CONNECT, stream::CLOSE]);
    }
}
