//! Client for one exact-peer outbound stream capability. A failed/expired
//! framed transaction is never retried; queued WRITE effects may be unknown.
use super::*;
use crate::datagram::{
    self as d,
    channel::{Pipe, transact_versioned},
};
use core::cell::Cell;

// transact's Pipe clock is normally monotonic. Enforce that assumption at
// each framed-I/O clock observation, including a rewind during a transaction.
struct MonotonicPipe<'a, P> {
    pipe: &'a mut P,
    last: Cell<u64>,
    rewound: Cell<bool>,
}
impl<P: Pipe> Pipe for MonotonicPipe<'_, P> {
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        self.pipe.read(bytes)
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        self.pipe.write(bytes)
    }
    fn now_ms(&self) -> u64 {
        let now = self.pipe.now_ms();
        if now < self.last.get() {
            self.rewound.set(true);
        }
        self.last.set(now);
        if self.rewound.get() { u64::MAX } else { now }
    }
}

pub struct Client<P: Pipe> {
    pipe: P,
    peer: Address,
    pause: fn(u64),
    live: bool,
    connected: bool,
    last_ms: Option<u64>,
    inbound: bool,
}
impl<P: Pipe> Client<P> {
    pub fn new(pipe: P, peer: Address, pause: fn(u64)) -> Self {
        Self {
            pipe,
            peer,
            pause,
            live: true,
            connected: false,
            last_ms: None,
            inbound: false,
        }
    }
    pub(super) fn server(pipe: P, peer: Address, pause: fn(u64)) -> Self {
        let mut client = Self::new(pipe, peer, pause);
        client.inbound = true;
        client
    }
    pub fn peer(&self) -> Address {
        self.peer
    }
    pub fn now_ms(&self) -> u64 {
        self.pipe.now_ms()
    }
    fn time(&mut self, deadline: u64) -> Result<u64, Error> {
        if !self.live {
            return Err(Error::Stale);
        }
        let now = self.pipe.now_ms();
        if self.last_ms.is_some_and(|last| now < last) {
            self.live = false;
            return Err(Error::Clock);
        }
        self.last_ms = Some(now);
        if now >= deadline {
            self.live = false;
            return Err(Error::Timeout);
        }
        Ok(now)
    }
    fn malformed(&mut self) -> Error {
        self.live = false;
        Error::Channel(-22)
    }
    fn call(
        &mut self,
        op: u8,
        data: &[u8],
        capacity: usize,
        deadline: u64,
        reply: &mut [u8; d::MAX_MESSAGE],
    ) -> Result<(usize, usize), Error> {
        if data.len() > MAX_IO || capacity > MAX_IO {
            return Err(Error::Oversize);
        }
        let now = self.time(deadline)?;
        let mut request = [0; MAX_MESSAGE];
        let version = if self.inbound {
            server::VERSION
        } else {
            VERSION
        };
        let family = if self.inbound { 4 } else { 0 };
        request[0] = version;
        request[3] = family;
        request[1] = op;
        request[4..8].copy_from_slice(&self.peer.ip);
        request[8..10].copy_from_slice(&self.peer.port.to_be_bytes());
        let count = if op == WRITE {
            data.len()
        } else if op == READ {
            capacity
        } else {
            0
        };
        request[10..12].copy_from_slice(&(count as u16).to_be_bytes());
        request[12..12 + data.len()].copy_from_slice(data);
        let mut checked = MonotonicPipe {
            pipe: &mut self.pipe,
            last: Cell::new(now),
            rewound: Cell::new(false),
        };
        let result = transact_versioned(
            &mut checked,
            &request[..12 + data.len()],
            reply,
            (deadline - now).min(1000),
            version,
            family,
        );
        checked.now_ms();
        let rewound = checked.rewound.get();
        self.last_ms = Some(checked.last.get());
        if rewound {
            self.live = false;
            return Err(Error::Clock);
        }
        let n = match result {
            Ok(n) => n,
            Err(e) => {
                self.live = false;
                return Err(if e == -110 && self.pipe.now_ms() >= deadline {
                    Error::Timeout
                } else {
                    Error::Channel(e)
                });
            }
        };
        self.time(deadline)?;
        if reply[4..8] != self.peer.ip || reply[8..10] != self.peer.port.to_be_bytes() {
            return Err(self.malformed());
        }
        let length = u16::from_be_bytes([reply[10], reply[11]]) as usize;
        if reply[2] != 0 {
            if n != 12 || length != 0 {
                return Err(self.malformed());
            }
            let error = Error::decode(reply[2]).ok_or_else(|| self.malformed())?;
            if !matches!(
                error,
                Error::Again | Error::Eof | Error::WriteClosed | Error::Oversize | Error::Invalid
            ) {
                self.live = false;
            }
            return Err(error);
        }
        let valid = match op {
            CONNECT | STATUS | server::LISTEN | server::ACCEPT => {
                n == 13 && length == 1 && reply[12] & !7 == 0
            }
            READ => length > 0 && length <= capacity && n == 12 + length,
            WRITE => n == 12 && length <= data.len() && (data.is_empty() || length > 0),
            SHUTDOWN_WRITE | CLOSE | ABORT => n == 12 && length == 0,
            _ => false,
        };
        if !valid {
            return Err(self.malformed());
        }
        Ok((n, length))
    }
    pub fn connect(&mut self, deadline: u64) -> Result<(), Error> {
        let mut reply = [0; d::MAX_MESSAGE];
        let mut op = if self.connected {
            STATUS
        } else if self.inbound {
            server::LISTEN
        } else {
            CONNECT
        };
        loop {
            match self.call(op, &[], 0, deadline, &mut reply) {
                Err(Error::Again) if self.inbound => {
                    (self.pause)(5);
                    continue;
                }
                Err(error) => return Err(error),
                Ok(_) => {}
            }
            op = if self.inbound && !self.connected {
                server::ACCEPT
            } else {
                STATUS
            };
            if reply[12] & 1 != 0 {
                self.connected = true;
                return Ok(());
            }
            (self.pause)(5);
        }
    }
    pub fn write(&mut self, bytes: &[u8], deadline: u64) -> Result<usize, Error> {
        if !self.connected {
            self.connect(deadline)?;
        }
        self.call(WRITE, bytes, 0, deadline, &mut [0; d::MAX_MESSAGE])
            .map(|(_, n)| n)
    }
    pub fn read(&mut self, bytes: &mut [u8], deadline: u64) -> Result<usize, Error> {
        if bytes.is_empty() {
            return Err(Error::Invalid);
        }
        if !self.connected {
            self.connect(deadline)?;
        }
        let mut reply = [0; d::MAX_MESSAGE];
        let (_, n) = self.call(READ, &[], bytes.len().min(MAX_IO), deadline, &mut reply)?;
        bytes[..n].copy_from_slice(&reply[12..12 + n]);
        Ok(n)
    }
    pub fn write_all(&mut self, bytes: &[u8], deadline: u64) -> Result<(), Error> {
        let mut at = 0;
        while at < bytes.len() {
            match self.write(&bytes[at..(at + MAX_IO).min(bytes.len())], deadline) {
                Ok(n) => at += n,
                Err(Error::Again) => (self.pause)(5),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    pub fn read_exact(&mut self, bytes: &mut [u8], deadline: u64) -> Result<(), Error> {
        let mut at = 0;
        while at < bytes.len() {
            match self.read(&mut bytes[at..], deadline) {
                Ok(n) => at += n,
                Err(Error::Again) => (self.pause)(5),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    pub fn shutdown_write(&mut self, deadline: u64) -> Result<(), Error> {
        if !self.connected {
            self.connect(deadline)?;
        }
        self.call(SHUTDOWN_WRITE, &[], 0, deadline, &mut [0; d::MAX_MESSAGE])
            .map(|_| ())
    }
    pub fn close(&mut self, deadline: u64) -> Result<(), Error> {
        let result = self
            .call(CLOSE, &[], 0, deadline, &mut [0; d::MAX_MESSAGE])
            .map(|_| ());
        self.live = false;
        result
    }
    pub fn abort(&mut self, deadline: u64) -> Result<(), Error> {
        let result = self
            .call(ABORT, &[], 0, deadline, &mut [0; d::MAX_MESSAGE])
            .map(|_| ());
        self.live = false;
        result
    }
}
