//! One fixed outbound IPv4 Echo request through an owner-issued pipe grant.
//! The private stack preserves smoltcp's ARP/IPv4/ICMP implementation. A
//! consumer cannot choose an identifier, sequence, body, type or lifetime.
use crate::{Config, FRAME_MAX, Link, LinkReading, NetError, Stack};
use alloc::{rc::Rc, vec};
use core::{
    cell::RefCell,
    sync::atomic::{AtomicU64, Ordering},
};
use smoltcp::{
    iface::SocketHandle,
    socket::icmp,
    wire::{Icmpv4Packet, IpAddress, Ipv4Address},
};
#[cfg(test)]
mod tests;
#[cfg(target_os = "absd")]
pub use crate::datagram::channel::KernelPipe;
pub use crate::datagram::channel::Pipe;

pub const MAX_GRANTS: usize = 1;
pub const PACKET_LEN: usize = 40;
pub const MAX_LIFETIME_MS: u64 = 8_000;
pub const FRAME_MS: u64 = 250;
pub const VERSION: u8 = 1;
pub const START: u8 = 1;
pub const OBSERVE: u8 = 2;
pub const CLOSE: u8 = 3;
pub const REQUEST_LEN: usize = 8;
pub const RESPONSE_LEN: usize = 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Denied,
    Exhausted,
    Stale,
    Again,
    Spent,
    Expired,
    Clock,
    LinkDown,
    DeviceFailed,
    LinkUnknown,
    LinkIo,
    Entropy,
}
impl Error {
    pub fn code(self) -> u8 {
        match self {
            Self::Invalid => 1,
            Self::Denied => 2,
            Self::Exhausted => 3,
            Self::Stale => 4,
            Self::Again => 5,
            Self::Spent => 6,
            Self::Expired => 7,
            Self::Clock => 8,
            Self::LinkDown => 9,
            Self::DeviceFailed => 10,
            Self::LinkUnknown => 11,
            Self::LinkIo => 12,
            Self::Entropy => 13,
        }
    }
}

/// Local checked reference only. The actual client authority is its pipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    instance: u64,
    epoch: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub peer: [u8; 4],
    pub identifier: u16,
    pub sequence: u16,
    pub instance: u64,
    pub epoch: u64,
    pub nonce: u64,
    pub boot_rtt_ms: u64,
}
struct Entry {
    endpoint: Endpoint,
    peer: [u8; 4],
    until: u64,
    packet: [u8; PACKET_LEN],
    handle: Option<SocketHandle>,
    started: Option<u64>,
    consumed: bool,
}
struct Boundary {
    active: bool,
    last: u64,
    until: u64,
    cause: Option<Error>,
    armed: bool,
    submitted: bool,
    local: [u8; 4],
    peer: [u8; 4],
    packet: [u8; PACKET_LEN],
}
impl Boundary {
    fn retire(&mut self, cause: Error) {
        self.active = false;
        self.cause = Some(cause);
    }
}
struct Guarded<L: Link> {
    inner: L,
    boundary: Rc<RefCell<Boundary>>,
}
impl<L: Link> Guarded<L> {
    fn check(&self) -> Result<u64, Error> {
        let mut b = self.boundary.borrow_mut();
        if !b.active {
            return Err(b.cause.unwrap_or(Error::Stale));
        }
        let now = self.inner.now_ms();
        let cause = if now < b.last {
            Some(Error::Clock)
        } else if now >= b.until {
            Some(Error::Expired)
        } else {
            match self.inner.read() {
                None => Some(Error::LinkUnknown),
                Some(r) if r.disabled => Some(Error::DeviceFailed),
                Some(r) if !r.link_up => Some(Error::LinkDown),
                Some(_) => None,
            }
        };
        if let Some(error) = cause {
            b.retire(error);
            return Err(error);
        }
        b.last = now;
        Ok(now)
    }
}
impl<L: Link> Link for Guarded<L> {
    fn mac(&self) -> [u8; 6] {
        self.inner.mac()
    }
    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
    fn pause(&self, ms: u64) {
        self.inner.pause(ms);
    }
    fn read(&self) -> Option<LinkReading> {
        self.inner.read()
    }
    fn send(&mut self, frame: &[u8]) -> Result<(), i64> {
        self.check().map_err(|_| -5i64)?;
        // The engine may emit its ordinary ARP/control replies. Its one
        // application Echo Request must be this exact issued packet once.
        let icmp = frame.len() >= 34 && frame[12..14] == [8, 0] && frame[23] == 1;
        if icmp && (frame[14] != 0x45 || frame.len() < 42) {
            self.boundary.borrow_mut().retire(Error::Denied);
            return Err(-5);
        }
        if icmp && frame[34] == 8 {
            let mut b = self.boundary.borrow_mut();
            if !b.armed
                || b.submitted
                || frame.len() != 14 + 20 + PACKET_LEN
                || frame[14] != 0x45
                || frame[26..30] != b.local
                || frame[30..34] != b.peer
                || frame[34..] != b.packet
            {
                b.retire(Error::Denied);
                return Err(-5);
            }
            // Mark before the non-atomic call, including an uncertain Err.
            b.submitted = true;
        }
        let effect = self.inner.send(frame);
        if effect.is_err() {
            self.boundary.borrow_mut().retire(Error::LinkIo);
        }
        let after = self.check();
        if effect.is_err() || after.is_err() {
            return Err(-5);
        }
        effect
    }
    fn receive(
        &mut self,
        buffer: &mut [u8; FRAME_MAX],
        timeout: u64,
    ) -> Result<Option<usize>, i64> {
        self.check().map_err(|_| -5i64)?;
        let result = self.inner.receive(buffer, timeout);
        if result.is_err() {
            self.boundary.borrow_mut().retire(Error::LinkIo);
        }
        self.check().map_err(|_| -5i64)?;
        result
    }
}
static INSTANCE: AtomicU64 = AtomicU64::new(1);

/// Sole NIC owner for this bounded invocation. No underlying Stack or raw
/// socket escapes; this is opt-in and leaves Stack::open/SSH unchanged.
pub struct Owner<L: Link> {
    stack: Stack<Guarded<L>>,
    boundary: Rc<RefCell<Boundary>>,
    instance: u64,
    next_epoch: u64,
    entry: Option<Entry>,
}
impl<L: Link> Owner<L> {
    pub fn open(link: L, config: Config) -> Result<Self, NetError> {
        if link.now_ms() > i64::MAX as u64 {
            return Err(NetError::Config);
        }
        let instance = INSTANCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| NetError::Config)?;
        let boundary = Rc::new(RefCell::new(Boundary {
            active: false,
            last: link.now_ms(),
            until: 0,
            cause: None,
            armed: false,
            submitted: false,
            local: config.address.octets(),
            peer: [0; 4],
            packet: [0; PACKET_LEN],
        }));
        let stack = Stack::open(
            Guarded {
                inner: link,
                boundary: boundary.clone(),
            },
            config,
        )?;
        Ok(Self {
            stack,
            boundary,
            instance,
            next_epoch: 1,
            entry: None,
        })
    }
    pub fn socket_count(&self) -> usize {
        self.stack.socket_count()
    }
    fn lookup(&self, endpoint: Endpoint) -> Result<&Entry, Error> {
        self.entry
            .as_ref()
            .filter(|e| e.endpoint == endpoint)
            .ok_or(Error::Stale)
    }
    fn live(&mut self, endpoint: Endpoint) -> Result<u64, Error> {
        self.lookup(endpoint)?;
        match self.stack.port.link.check() {
            Ok(now) => Ok(now),
            Err(error) => {
                self.fence();
                Err(error)
            }
        }
    }
    /// The trusted issuer authorizes one exact on-link unicast peer and a
    /// absolute boot-clock deadline no more than eight seconds away.
    /// Randomness fails closed, without retry or restarting invocation time.
    pub fn grant<F: FnMut(&mut [u8]) -> Result<(), i64>>(
        &mut self,
        peer: [u8; 4],
        until: u64,
        mut entropy: F,
    ) -> Result<Endpoint, Error> {
        if self.entry.is_some() {
            return Err(Error::Exhausted);
        }
        let local = u32::from_be_bytes(self.stack.config.address.octets());
        let mask = u32::MAX << (32 - self.stack.config.prefix_len);
        let remote = u32::from_be_bytes(peer);
        let subnet = local & mask;
        if peer[0] == 0
            || peer[0] == 127
            || peer[0] >= 224
            || remote == local
            || remote == subnet
            || remote == (subnet | !mask)
            || (remote & mask) != subnet
        {
            return Err(Error::Denied);
        }
        let now = self.stack.port.link.inner.now_ms();
        if now > i64::MAX as u64 || until > i64::MAX as u64 {
            return Err(Error::Clock);
        }
        if until
            .checked_sub(now)
            .is_none_or(|left| left == 0 || left > MAX_LIFETIME_MS)
        {
            return Err(Error::Invalid);
        }
        let epoch = self.next_epoch;
        let next_epoch = epoch.checked_add(1).ok_or(Error::Exhausted)?;
        let mut random = [0; 12];
        entropy(&mut random).map_err(|_| Error::Entropy)?;
        let identifier = u16::from_be_bytes(random[..2].try_into().unwrap());
        let sequence = u16::from_be_bytes(random[2..4].try_into().unwrap());
        let nonce = u64::from_be_bytes(random[4..].try_into().unwrap());
        if identifier == 0 || sequence == 0 || nonce == 0 {
            return Err(Error::Entropy);
        }
        let mut packet = [0; PACKET_LEN];
        packet[0] = 8;
        packet[4..6].copy_from_slice(&identifier.to_be_bytes());
        packet[6..8].copy_from_slice(&sequence.to_be_bytes());
        packet[8..16].copy_from_slice(b"ABSDPING");
        packet[16..24].copy_from_slice(&self.instance.to_be_bytes());
        packet[24..32].copy_from_slice(&epoch.to_be_bytes());
        packet[32..40].copy_from_slice(&nonce.to_be_bytes());
        Icmpv4Packet::new_unchecked(&mut packet[..]).fill_checksum();
        *self.boundary.borrow_mut() = Boundary {
            active: true,
            last: now,
            until,
            cause: None,
            armed: false,
            submitted: false,
            local: self.stack.config.address.octets(),
            peer,
            packet,
        };
        if let Err(error) = self.stack.port.link.check() {
            self.fence();
            return Err(error);
        }
        let buffer =
            || icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; PACKET_LEN]);
        let mut socket = icmp::Socket::new(buffer(), buffer());
        if socket.bind(icmp::Endpoint::Ident(identifier)).is_err() {
            self.fence();
            return Err(Error::Invalid);
        }
        let endpoint = Endpoint {
            instance: self.instance,
            epoch,
        };
        self.entry = Some(Entry {
            endpoint,
            peer,
            until,
            packet,
            handle: Some(self.stack.sockets.add(socket)),
            started: None,
            consumed: false,
        });
        self.next_epoch = next_epoch;
        Ok(endpoint)
    }
    pub fn expires_ms(&self, endpoint: Endpoint) -> Result<u64, Error> {
        Ok(self.lookup(endpoint)?.until)
    }
    pub fn start(&mut self, endpoint: Endpoint, peer: [u8; 4]) -> Result<(), Error> {
        let now = self.live(endpoint)?;
        let e = self.lookup(endpoint)?;
        if peer != e.peer {
            return Err(Error::Denied);
        }
        if e.started.is_some() || e.consumed {
            return Err(Error::Spent);
        }
        let handle = e.handle.unwrap();
        let packet = e.packet;
        self.boundary.borrow_mut().armed = true;
        self.entry.as_mut().unwrap().started = Some(now);
        if self
            .stack
            .sockets
            .get_mut::<icmp::Socket>(handle)
            .send_slice(&packet, IpAddress::Ipv4(Ipv4Address::from(peer)))
            .is_err()
        {
            self.fence();
            return Err(Error::Exhausted);
        }
        self.live(endpoint)?;
        Ok(())
    }
    /// One queued packet is inspected per call. Unrelated packets are
    /// discarded without extending the grant; there is no peer authentication.
    pub fn observe(&mut self, endpoint: Endpoint) -> Result<Observation, Error> {
        self.live(endpoint)?;
        let e = self.lookup(endpoint)?;
        if e.consumed {
            return Err(Error::Spent);
        }
        let Some(start) = e.started else {
            return Err(Error::Again);
        };
        let handle = e.handle.unwrap();
        let expected = e.packet;
        let peer = e.peer;
        let mut bytes = [0; PACKET_LEN];
        let (length, source) = self
            .stack
            .sockets
            .get_mut::<icmp::Socket>(handle)
            .recv_slice(&mut bytes)
            .map_err(|_| Error::Again)?;
        let now = self.live(endpoint)?;
        if length != PACKET_LEN
            || source != IpAddress::Ipv4(Ipv4Address::from(peer))
            || bytes[..2] != [0, 0]
            || bytes[4..] != expected[4..]
            || !Icmpv4Packet::new_unchecked(&bytes[..]).verify_checksum()
            || !self.boundary.borrow().submitted
        {
            return Err(Error::Again);
        }
        let result = Observation {
            peer,
            identifier: u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
            sequence: u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
            instance: endpoint.instance,
            epoch: endpoint.epoch,
            nonce: u64::from_be_bytes(bytes[32..40].try_into().unwrap()),
            boot_rtt_ms: now.checked_sub(start).ok_or(Error::Clock)?,
        };
        self.stack.sockets.remove(handle);
        let e = self.entry.as_mut().unwrap();
        e.handle = None;
        e.consumed = true;
        Ok(result)
    }
    pub fn close(&mut self, endpoint: Endpoint) -> Result<(), Error> {
        self.lookup(endpoint)?;
        self.fence();
        Ok(())
    }
    /// Drop local queues immediately; already submitted effects are unknown.
    pub fn fence(&mut self) {
        if let Some(e) = self.entry.take() {
            if let Some(h) = e.handle {
                self.stack.sockets.remove(h);
            }
        }
        self.stack.port.rx_length = None;
        self.boundary.borrow_mut().active = false;
    }
    pub fn poll(&mut self) -> Result<(), Error> {
        let Some(e) = self.entry.as_ref() else {
            return Ok(());
        };
        let endpoint = e.endpoint;
        self.live(endpoint)?;
        if self.entry.as_ref().unwrap().handle.is_some() {
            self.stack.poll();
        }
        self.live(endpoint)?;
        Ok(())
    }
    pub fn wait(&mut self, ms: u64) -> Result<(), Error> {
        let Some(e) = self.entry.as_ref() else {
            return Ok(());
        };
        let endpoint = e.endpoint;
        self.live(endpoint)?;
        self.stack.wait(ms.min(10));
        self.live(endpoint)?;
        Ok(())
    }
}

fn encode(op: u8, observation: Observation, reply: &mut [u8; RESPONSE_LEN]) {
    reply[0] = VERSION;
    reply[1] = op;
    reply[4..8].copy_from_slice(&observation.peer);
    reply[8..10].copy_from_slice(&observation.identifier.to_be_bytes());
    reply[10..12].copy_from_slice(&observation.sequence.to_be_bytes());
    reply[12..20].copy_from_slice(&observation.instance.to_be_bytes());
    reply[20..28].copy_from_slice(&observation.epoch.to_be_bytes());
    reply[28..36].copy_from_slice(&observation.nonce.to_be_bytes());
    reply[36..44].copy_from_slice(&observation.boot_rtt_ms.to_be_bytes());
}
pub fn decode(reply: &[u8; RESPONSE_LEN], peer: [u8; 4]) -> Result<Observation, Error> {
    if reply[..4] != [VERSION, OBSERVE, 0, 0] || reply[4..8] != peer || reply[44..] != [0; 4] {
        return Err(Error::Invalid);
    }
    let observation = Observation {
        peer,
        identifier: u16::from_be_bytes(reply[8..10].try_into().unwrap()),
        sequence: u16::from_be_bytes(reply[10..12].try_into().unwrap()),
        instance: u64::from_be_bytes(reply[12..20].try_into().unwrap()),
        epoch: u64::from_be_bytes(reply[20..28].try_into().unwrap()),
        nonce: u64::from_be_bytes(reply[28..36].try_into().unwrap()),
        boot_rtt_ms: u64::from_be_bytes(reply[36..44].try_into().unwrap()),
    };
    if observation.identifier == 0
        || observation.sequence == 0
        || observation.instance == 0
        || observation.epoch == 0
        || observation.nonce == 0
        || observation.boot_rtt_ms >= MAX_LIFETIME_MS
    {
        return Err(Error::Invalid);
    }
    Ok(observation)
}

/// Fixed eight-byte requests and 48-byte replies; no variable body or type.
pub struct Channel {
    endpoint: Endpoint,
    until: u64,
    last: u64,
    deadline: Option<u64>,
    input: [u8; REQUEST_LEN],
    used: usize,
    output: [u8; RESPONSE_LEN],
    sent: usize,
    pending: bool,
    live: bool,
    closing: bool,
}
impl Channel {
    pub fn new<L: Link>(owner: &mut Owner<L>, endpoint: Endpoint) -> Result<Self, Error> {
        let last = owner.live(endpoint)?;
        Ok(Self {
            endpoint,
            until: owner.expires_ms(endpoint)?,
            last,
            deadline: None,
            input: [0; REQUEST_LEN],
            used: 0,
            output: [0; RESPONSE_LEN],
            sent: 0,
            pending: false,
            live: true,
            closing: false,
        })
    }
    pub fn revoke<L: Link>(&mut self, owner: &mut Owner<L>) {
        let _ = owner.close(self.endpoint);
        self.live = false;
        self.pending = false;
        self.used = 0;
        self.sent = 0;
        self.output.fill(0);
    }
    fn clock<L: Link, P: Pipe>(&mut self, owner: &mut Owner<L>, pipe: &P) -> bool {
        let now = pipe.now_ms();
        if now < self.last
            || now >= self.until
            || self.deadline.is_some_and(|d| now >= d)
            || (!self.closing && owner.live(self.endpoint).is_err())
        {
            self.revoke(owner);
            return false;
        }
        self.last = now;
        true
    }
    pub fn poll<L: Link, P: Pipe>(&mut self, owner: &mut Owner<L>, pipe: &mut P) -> bool {
        if !self.live || !self.clock(owner, pipe) {
            return false;
        }
        if self.pending {
            match pipe.write(&self.output[self.sent..]) {
                Ok(Some(n)) if n > 0 && n <= RESPONSE_LEN - self.sent => {
                    self.sent += n;
                    if self.sent == RESPONSE_LEN {
                        self.pending = false;
                        self.sent = 0;
                        self.deadline = None;
                        if self.closing {
                            self.live = false;
                        }
                    }
                }
                Ok(None) => {}
                _ => self.revoke(owner),
            }
            if self.live {
                self.clock(owner, pipe);
            }
            return self.live;
        }
        let first_deadline = self.last.checked_add(FRAME_MS);
        match pipe.read(&mut self.input[self.used..]) {
            Ok(Some(n)) if n > 0 && n <= REQUEST_LEN - self.used => {
                if self.used == 0 {
                    // Anchor successful first bytes to the pre-I/O clock.
                    // A straddling read may consume bytes, but cannot receive
                    // a fresh frame budget or execute a late START.
                    self.deadline = first_deadline;
                    if self.deadline.is_none() {
                        self.revoke(owner);
                        return false;
                    }
                }
                self.used += n;
            }
            Ok(None) => {}
            _ => self.revoke(owner),
        }
        if !self.live || !self.clock(owner, pipe) {
            return false;
        }
        if self.used == REQUEST_LEN {
            let op = self.input[1];
            let peer: [u8; 4] = self.input[4..8].try_into().unwrap();
            self.output.fill(0);
            self.output[0] = VERSION;
            self.output[1] = op;
            let result = if self.input[..1] != [VERSION]
                || self.input[2..4] != [0, 0]
                || !matches!(op, START | OBSERVE | CLOSE)
            {
                Err(Error::Invalid)
            } else if owner.lookup(self.endpoint).is_ok_and(|e| e.peer != peer) {
                Err(Error::Denied)
            } else {
                match op {
                    START => owner.start(self.endpoint, peer),
                    OBSERVE => owner
                        .observe(self.endpoint)
                        .map(|o| encode(op, o, &mut self.output)),
                    CLOSE => {
                        self.closing = true;
                        owner.close(self.endpoint)
                    }
                    _ => unreachable!(),
                }
            };
            if let Err(error) = result {
                self.output[2] = error.code();
            }
            self.pending = true;
            self.used = 0;
            self.deadline = pipe.now_ms().checked_add(FRAME_MS);
            if self.deadline.is_none() {
                self.revoke(owner);
            }
        }
        self.live
    }
}

/// The invocation's absolute boot deadline is supplied by the caller and
/// never restarted for bootstrap, denial, START, polling or CLOSE. An
/// uncertain write/read retires the stream; no START retry is attempted.
pub fn transact<P: Pipe>(
    pipe: &mut P,
    request: &[u8; REQUEST_LEN],
    until: u64,
    last: &mut u64,
) -> Result<[u8; RESPONSE_LEN], i64> {
    fn check<P: Pipe>(pipe: &P, until: u64, last: &mut u64) -> Result<(), i64> {
        let now = pipe.now_ms();
        if now < *last || now >= until {
            return Err(-110);
        }
        *last = now;
        Ok(())
    }
    let mut at = 0;
    while at < request.len() {
        check(pipe, until, last)?;
        match pipe.write(&request[at..])? {
            Some(n) if n > 0 && n <= request.len() - at => at += n,
            None => {}
            _ => return Err(-5),
        }
        check(pipe, until, last)?;
    }
    let mut reply = [0; RESPONSE_LEN];
    at = 0;
    while at < reply.len() {
        check(pipe, until, last)?;
        match pipe.read(&mut reply[at..])? {
            Some(n) if n > 0 && n <= reply.len() - at => at += n,
            None => {}
            _ => return Err(-5),
        }
        check(pipe, until, last)?;
    }
    if reply[0] != VERSION || reply[1] != request[1] || reply[3] != 0 || reply[44..] != [0; 4] {
        return Err(-22);
    }
    if (reply[2] != 0 && (!(1..=13).contains(&reply[2]) || reply[4..44] != [0; 40]))
        || (reply[2] == 0 && request[1] != OBSERVE && reply[4..44] != [0; 40])
    {
        return Err(-22);
    }
    Ok(reply)
}
