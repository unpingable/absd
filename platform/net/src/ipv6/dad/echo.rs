//! One fixed IPv6 Echo diagnostic through a private, DAD-guarded owner.
//! The original DAD owner stays alive; no raw Stack or ICMP socket escapes.
use super::*;
#[cfg(target_os = "absd")]
pub use crate::datagram::channel::KernelPipe;
pub use crate::datagram::channel::Pipe;
use core::sync::atomic::{AtomicU64, Ordering};
use smoltcp::{iface::SocketHandle, socket::icmp};

pub const VERSION: u8 = 1;
pub const FAMILY: u8 = 6;
pub const START: u8 = 1;
pub const OBSERVE: u8 = 2;
pub const CLOSE: u8 = 3;
pub const PACKET_LEN: usize = 40;
pub const REQUEST_LEN: usize = 24;
pub const RESPONSE_LEN: usize = 64;
pub const BOOTSTRAP_LEN: usize = 40;
pub const FRAME_MS: u64 = 250;
pub const MAX_LIFETIME_MS: u64 = ACTIVE_MS;
const MAX_TRANSFERS: usize = 4096;

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
    Link,
    Entropy,
    Interrupted,
    Dad(super::Error),
    Engine,
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
            Self::Link => 9,
            Self::Entropy => 10,
            Self::Interrupted => 11,
            Self::Dad(_) => 12,
            Self::Engine => 13,
        }
    }
}
fn dad_error(error: super::Error) -> Error {
    match error {
        super::Error::Clock => Error::Clock,
        super::Error::Timeout => Error::Expired,
        other => Error::Dad(other),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    pub ip: [u8; 16],
    pub scope: u32,
}
pub fn fixture_peer() -> Peer {
    let address = Policy::fixture().peer;
    Peer {
        ip: address.ip,
        scope: address.scope,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    instance: u64,
    epoch: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub peer: Peer,
    pub identifier: u16,
    pub sequence: u16,
    pub instance: u64,
    pub epoch: u64,
    pub nonce: u64,
    /// START-to-observation in the boot domain, including ND/queue/scheduling.
    pub boot_elapsed_ms: u64,
}

/// Shared only by this private owner, its Link wrapper and Port admission.
/// There is no public constructor or traffic-derived grant.
pub(crate) struct Admission {
    live: bool,
    armed: bool,
    submitted: bool,
    consumed: bool,
    fault: Option<Error>,
    local: [u8; 16],
    mac: [u8; 6],
    peer: Peer,
    packet: [u8; PACKET_LEN],
}
impl Admission {
    pub(crate) fn retire(&mut self) {
        self.live = false;
    }
    pub(crate) fn peer(&self) -> Option<[u8; 16]> {
        (self.live && !self.consumed).then_some(self.peer.ip)
    }
    pub(crate) fn accepts(&self, frame: &[u8]) -> bool {
        if !self.live
            || !self.armed
            || !self.submitted
            || self.consumed
            || frame.len() != 54 + PACKET_LEN
            || frame[..6] != self.mac
            || frame[6] & 1 != 0
            || frame[6..12] == [0; 6]
            || frame[12..14] != [0x86, 0xdd]
            || frame[14] >> 4 != 6
            || frame[18..21] != [0, PACKET_LEN as u8, 58]
            || frame[22..38] != self.peer.ip
            || frame[38..54] != self.local
            || frame[54..56] != [129, 0]
            || frame[58..] != self.packet[4..]
        {
            return false;
        }
        Icmpv6Packet::new_unchecked(&frame[54..]).verify_checksum(
            &Ipv6Address::from(self.peer.ip),
            &Ipv6Address::from(self.local),
        )
    }
    fn sending(&mut self, frame: &[u8]) -> Result<(), Error> {
        if let Some(error) = self.fault {
            return Err(error);
        }
        if frame.len() >= 55 && frame[12..14] == [0x86, 0xdd] && frame[20] == 58 && frame[54] == 128
        {
            if !self.live
                || !self.armed
                || self.submitted
                || frame.len() != 54 + PACKET_LEN
                || frame[14] >> 4 != 6
                || frame[6..12] != self.mac
                || frame[18..21] != [0, PACKET_LEN as u8, 58]
                || frame[22..38] != self.local
                || frame[38..54] != self.peer.ip
                || frame[54..] != self.packet
            {
                self.fault = Some(Error::Denied);
                self.retire();
                return Err(Error::Denied);
            }
            // A call returning Err can already have submitted the first effect.
            self.submitted = true;
        }
        Ok(())
    }
}
struct EchoLink<L: Link> {
    inner: L,
    admission: Rc<RefCell<Admission>>,
}
impl<L: Link> Link for EchoLink<L> {
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
        if self.admission.borrow().fault.is_some() {
            None
        } else {
            self.inner.read()
        }
    }
    fn send(&mut self, frame: &[u8]) -> Result<(), i64> {
        self.admission
            .borrow_mut()
            .sending(frame)
            .map_err(|_| REFUSED)?;
        let result = self.inner.send(frame);
        if result.is_err() {
            let mut a = self.admission.borrow_mut();
            a.fault = Some(Error::Interrupted);
            a.retire();
        }
        result
    }
    fn receive(&mut self, frame: &mut [u8; FRAME_MAX], timeout: u64) -> Result<Option<usize>, i64> {
        self.inner.receive(frame, timeout)
    }
}
struct Entry {
    endpoint: Endpoint,
    handle: Option<SocketHandle>,
    packet: [u8; PACKET_LEN],
    start: Option<u64>,
    consumed: bool,
    closing: bool,
    channel_issued: bool,
}
static INSTANCE: AtomicU64 = AtomicU64::new(1);
fn reserve(counter: &AtomicU64) -> Result<u64, Error> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        .map_err(|_| Error::Exhausted)
}
pub struct Owner<L: Link> {
    dad: super::Owner<EchoLink<L>>,
    admission: Rc<RefCell<Admission>>,
    instance: u64,
    next_epoch: u64,
    issued: bool,
    entry: Option<Entry>,
}
impl<L: Link> Owner<L> {
    /// Fixed direct-link policy; the original invocation sample precedes DAD.
    pub fn acquire<E>(
        link: L,
        start: u64,
        entropy: impl FnMut(&mut [u8]) -> Result<(), E>,
    ) -> Result<Self, Error> {
        let instance = reserve(&INSTANCE)?;
        let policy = Policy::fixture();
        let admission = Rc::new(RefCell::new(Admission {
            live: false,
            armed: false,
            submitted: false,
            consumed: false,
            fault: None,
            local: policy.config.address,
            mac: link.mac(),
            peer: fixture_peer(),
            packet: [0; PACKET_LEN],
        }));
        let dad = super::Owner::acquire(
            EchoLink {
                inner: link,
                admission: admission.clone(),
            },
            policy,
            start,
            entropy,
        )
        .map_err(dad_error)?;
        Ok(Self {
            dad,
            admission,
            instance,
            next_epoch: 1,
            issued: false,
            entry: None,
        })
    }
    fn lookup(&self, endpoint: Endpoint) -> Result<&Entry, Error> {
        self.entry
            .as_ref()
            .filter(|e| e.endpoint == endpoint)
            .ok_or(Error::Stale)
    }
    pub fn check(&mut self) -> Result<u64, Error> {
        let fault = self.admission.borrow().fault;
        if fault.is_none()
            && self
                .entry
                .as_ref()
                .is_some_and(|e| !e.consumed && !e.closing)
            && !self.admission.borrow().live
        {
            self.retire();
            return Err(Error::Stale);
        }
        let result = self.dad.check().map_err(dad_error);
        if let Some(error) = fault {
            self.retire();
            return Err(error);
        }
        if let Err(error) = result {
            self.retire();
            return Err(error);
        }
        Ok(self.dad.guard.borrow().last)
    }
    fn live(&mut self, endpoint: Endpoint) -> Result<u64, Error> {
        self.lookup(endpoint)?;
        self.check()
    }
    /// One grant per owner, only for the fixed peer/scope. No caller lifetime.
    pub fn grant<E>(
        &mut self,
        peer: Peer,
        mut entropy: impl FnMut(&mut [u8]) -> Result<(), E>,
    ) -> Result<Endpoint, Error> {
        self.check()?;
        if self.issued {
            return Err(Error::Exhausted);
        }
        if peer != fixture_peer() {
            return Err(Error::Denied);
        }
        let epoch = self.next_epoch;
        let next = epoch.checked_add(1).ok_or(Error::Exhausted)?;
        let mut random = [0; 12];
        let result = entropy(&mut random);
        self.check()?;
        if result.is_err() {
            self.retire();
            return Err(Error::Entropy);
        }
        let id = u16::from_be_bytes(random[..2].try_into().unwrap());
        let seq = u16::from_be_bytes(random[2..4].try_into().unwrap());
        let nonce = u64::from_be_bytes(random[4..].try_into().unwrap());
        if id == 0 || seq == 0 || nonce == 0 {
            self.retire();
            return Err(Error::Entropy);
        }
        let mut packet = [0; PACKET_LEN];
        packet[0] = 128;
        packet[4..6].copy_from_slice(&id.to_be_bytes());
        packet[6..8].copy_from_slice(&seq.to_be_bytes());
        packet[8..16].copy_from_slice(b"ABSDPNG6");
        packet[16..24].copy_from_slice(&self.instance.to_be_bytes());
        packet[24..32].copy_from_slice(&epoch.to_be_bytes());
        packet[32..40].copy_from_slice(&nonce.to_be_bytes());
        Icmpv6Packet::new_unchecked(&mut packet[..]).fill_checksum(
            &Ipv6Address::from(Policy::fixture().config.address),
            &Ipv6Address::from(peer.ip),
        );
        let buffer =
            || icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; PACKET_LEN]);
        let mut socket = icmp::Socket::new(buffer(), buffer());
        socket
            .bind(icmp::Endpoint::Ident(id))
            .map_err(|_| Error::Engine)?;
        let stack = self.dad.stack.as_mut().ok_or(Error::Stale)?;
        let handle = stack.sockets.add(socket);
        let endpoint = Endpoint {
            instance: self.instance,
            epoch,
        };
        {
            let mut a = self.admission.borrow_mut();
            a.live = true;
            a.packet = packet;
        }
        stack.port.ipv6_echo = Some(self.admission.clone());
        self.entry = Some(Entry {
            endpoint,
            handle: Some(handle),
            packet,
            start: None,
            consumed: false,
            closing: false,
            channel_issued: false,
        });
        self.issued = true;
        self.next_epoch = next;
        self.live(endpoint)?;
        Ok(endpoint)
    }
    pub fn start(&mut self, endpoint: Endpoint, peer: Peer) -> Result<(), Error> {
        let now = self.live(endpoint)?;
        if peer != fixture_peer() {
            return Err(Error::Denied);
        }
        let entry = self.lookup(endpoint)?;
        if entry.start.is_some() || entry.consumed || entry.closing {
            return Err(Error::Spent);
        }
        let packet = entry.packet;
        let handle = entry.handle.ok_or(Error::Spent)?;
        self.admission.borrow_mut().armed = true;
        self.entry.as_mut().unwrap().start = Some(now);
        let result = self
            .dad
            .stack
            .as_mut()
            .unwrap()
            .sockets
            .get_mut::<icmp::Socket>(handle)
            .send_slice(&packet, IpAddress::Ipv6(Ipv6Address::from(peer.ip)));
        if result.is_err() {
            self.retire();
            return Err(Error::Exhausted);
        }
        self.live(endpoint)?;
        Ok(())
    }
    pub fn observe(&mut self, endpoint: Endpoint) -> Result<Observation, Error> {
        self.live(endpoint)?;
        let entry = self.lookup(endpoint)?;
        if entry.consumed || entry.closing {
            return Err(Error::Spent);
        }
        let start = entry.start.ok_or(Error::Again)?;
        let handle = entry.handle.ok_or(Error::Spent)?;
        let packet = entry.packet;
        let mut received = [0; PACKET_LEN];
        let (n, source) = self
            .dad
            .stack
            .as_mut()
            .unwrap()
            .sockets
            .get_mut::<icmp::Socket>(handle)
            .recv_slice(&mut received)
            .map_err(|_| Error::Again)?;
        let now = self.live(endpoint)?;
        let peer = fixture_peer();
        if n != PACKET_LEN
            || source != IpAddress::Ipv6(Ipv6Address::from(peer.ip))
            || received[..2] != [129, 0]
            || received[4..] != packet[4..]
            || !self.admission.borrow().submitted
            || !Icmpv6Packet::new_unchecked(&received[..]).verify_checksum(
                &Ipv6Address::from(peer.ip),
                &Ipv6Address::from(Policy::fixture().config.address),
            )
        {
            return Err(Error::Again);
        }
        let result = Observation {
            peer,
            identifier: u16::from_be_bytes(packet[4..6].try_into().unwrap()),
            sequence: u16::from_be_bytes(packet[6..8].try_into().unwrap()),
            instance: endpoint.instance,
            epoch: endpoint.epoch,
            nonce: u64::from_be_bytes(packet[32..40].try_into().unwrap()),
            boot_elapsed_ms: now.checked_sub(start).ok_or(Error::Clock)?,
        };
        self.cancel(endpoint)?;
        self.entry.as_mut().unwrap().consumed = true;
        Ok(result)
    }
    fn cancel(&mut self, endpoint: Endpoint) -> Result<(), Error> {
        self.lookup(endpoint)?;
        if let Some(handle) = self.entry.as_mut().unwrap().handle.take() {
            self.dad
                .stack
                .as_mut()
                .ok_or(Error::Stale)?
                .sockets
                .remove(handle);
        }
        self.admission.borrow_mut().consumed = true;
        if let Some(stack) = self.dad.stack.as_mut() {
            stack.port.ipv6_echo = None;
        }
        Ok(())
    }
    pub fn close(&mut self, endpoint: Endpoint) -> Result<(), Error> {
        self.lookup(endpoint)?;
        self.retire();
        Ok(())
    }
    pub fn retire(&mut self) {
        self.admission.borrow_mut().retire();
        self.entry.take();
        self.dad.retire();
    }
    pub fn stop_ms(&self) -> u64 {
        self.dad.stop_ms()
    }
    pub fn observations(&self) -> Observations {
        self.dad.observations()
    }
    pub fn socket_count(&self) -> usize {
        self.dad.socket_count()
    }
    fn poll(&mut self, endpoint: Endpoint) -> Result<(), Error> {
        self.live(endpoint)?;
        self.dad.stack.as_mut().unwrap().poll();
        self.live(endpoint)?;
        Ok(())
    }
    pub fn wait(&mut self) -> Result<(), Error> {
        if let Err(error) = self.dad.wait() {
            self.retire();
            return Err(dad_error(error));
        }
        self.check()?;
        Ok(())
    }
    pub fn bootstrap(&mut self) -> Result<[u8; BOOTSTRAP_LEN], Error> {
        self.check()?;
        let mut bytes = [0; BOOTSTRAP_LEN];
        bytes[..2].copy_from_slice(&[VERSION, FAMILY]);
        bytes[4..20].copy_from_slice(&fixture_peer().ip);
        bytes[20..24].copy_from_slice(&fixture_peer().scope.to_be_bytes());
        bytes[24..32].copy_from_slice(&(self.dad.until_ms() - TOTAL_MS).to_be_bytes());
        bytes[32..40].copy_from_slice(&self.stop_ms().to_be_bytes());
        Ok(bytes)
    }
}
impl<L: Link> Drop for Owner<L> {
    fn drop(&mut self) {
        self.retire();
    }
}

pub fn decode_bootstrap(bytes: &[u8; BOOTSTRAP_LEN], now: u64) -> Result<(Peer, u64), Error> {
    let peer = Peer {
        ip: bytes[4..20].try_into().unwrap(),
        scope: u32::from_be_bytes(bytes[20..24].try_into().unwrap()),
    };
    let start = u64::from_be_bytes(bytes[24..32].try_into().unwrap());
    let stop = u64::from_be_bytes(bytes[32..40].try_into().unwrap());
    let until = start
        .checked_add(TOTAL_MS)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or(Error::Clock)?;
    if bytes[..4] != [VERSION, FAMILY, 0, 0] || peer != fixture_peer() {
        return Err(Error::Denied);
    }
    if now < start {
        return Err(Error::Clock);
    }
    if now >= stop || stop > until || stop - now > MAX_LIFETIME_MS {
        return Err(Error::Expired);
    }
    Ok((peer, stop))
}
pub fn request(op: u8, peer: Peer) -> [u8; REQUEST_LEN] {
    let mut bytes = [0; REQUEST_LEN];
    bytes[..4].copy_from_slice(&[VERSION, op, 0, FAMILY]);
    bytes[4..20].copy_from_slice(&peer.ip);
    bytes[20..24].copy_from_slice(&peer.scope.to_be_bytes());
    bytes
}
fn encode(observation: Observation, bytes: &mut [u8; RESPONSE_LEN]) {
    bytes[4..20].copy_from_slice(&observation.peer.ip);
    bytes[20..24].copy_from_slice(&observation.peer.scope.to_be_bytes());
    bytes[24..26].copy_from_slice(&observation.identifier.to_be_bytes());
    bytes[26..28].copy_from_slice(&observation.sequence.to_be_bytes());
    bytes[28..36].copy_from_slice(&observation.instance.to_be_bytes());
    bytes[36..44].copy_from_slice(&observation.epoch.to_be_bytes());
    bytes[44..52].copy_from_slice(&observation.nonce.to_be_bytes());
    bytes[52..60].copy_from_slice(&observation.boot_elapsed_ms.to_be_bytes());
}
pub fn decode(bytes: &[u8; RESPONSE_LEN], peer: Peer) -> Result<Observation, Error> {
    if bytes[..4] != [VERSION, OBSERVE, 0, FAMILY]
        || bytes[4..20] != peer.ip
        || bytes[20..24] != peer.scope.to_be_bytes()
        || bytes[60..] != [0; 4]
    {
        return Err(Error::Invalid);
    }
    let o = Observation {
        peer,
        identifier: u16::from_be_bytes(bytes[24..26].try_into().unwrap()),
        sequence: u16::from_be_bytes(bytes[26..28].try_into().unwrap()),
        instance: u64::from_be_bytes(bytes[28..36].try_into().unwrap()),
        epoch: u64::from_be_bytes(bytes[36..44].try_into().unwrap()),
        nonce: u64::from_be_bytes(bytes[44..52].try_into().unwrap()),
        boot_elapsed_ms: u64::from_be_bytes(bytes[52..60].try_into().unwrap()),
    };
    if o.identifier == 0
        || o.sequence == 0
        || o.instance == 0
        || o.epoch == 0
        || o.nonce == 0
        || o.boot_elapsed_ms >= MAX_LIFETIME_MS
    {
        return Err(Error::Invalid);
    }
    Ok(o)
}
pub struct Channel {
    endpoint: Endpoint,
    input: [u8; REQUEST_LEN],
    used: usize,
    output: [u8; RESPONSE_LEN],
    sent: usize,
    pending: bool,
    deadline: Option<u64>,
    live: bool,
    closing: bool,
}
impl Channel {
    pub fn new<L: Link>(owner: &mut Owner<L>, endpoint: Endpoint) -> Result<Self, Error> {
        owner.live(endpoint)?;
        if owner.lookup(endpoint)?.channel_issued {
            return Err(Error::Exhausted);
        }
        owner.entry.as_mut().unwrap().channel_issued = true;
        Ok(Self {
            endpoint,
            input: [0; REQUEST_LEN],
            used: 0,
            output: [0; RESPONSE_LEN],
            sent: 0,
            pending: false,
            deadline: None,
            live: true,
            closing: false,
        })
    }
    pub fn revoke<L: Link>(&mut self, owner: &mut Owner<L>) {
        let _ = owner.close(self.endpoint);
        self.live = false;
        self.pending = false;
        self.output.fill(0);
        self.used = 0;
        self.sent = 0;
    }
    pub fn poll<L: Link, P: Pipe>(&mut self, owner: &mut Owner<L>, pipe: &mut P) -> bool {
        if !self.live {
            return false;
        }
        // Refuse expiry already observed before entering the engine, which
        // can dispatch the START queued by the preceding Channel call.
        let before = match owner.live(self.endpoint) {
            Ok(now) => now,
            Err(_) => {
                self.revoke(owner);
                return false;
            }
        };
        if self.deadline.is_some_and(|end| before >= end) {
            self.revoke(owner);
            return false;
        }
        if owner.poll(self.endpoint).is_err() {
            self.revoke(owner);
            return false;
        }
        let now = match owner.live(self.endpoint) {
            Ok(now) => now,
            Err(_) => {
                self.revoke(owner);
                return false;
            }
        };
        if self.deadline.is_some_and(|end| now >= end) {
            self.revoke(owner);
            return false;
        }
        let end = self.deadline.or_else(|| now.checked_add(FRAME_MS));
        if self.pending {
            let effect = pipe.write(&self.output[self.sent..]);
            // Check after even a completing write; first bytes cannot be recalled.
            let after = owner.live(self.endpoint);
            if after.is_err() || end.is_none_or(|end| after.unwrap() >= end) {
                self.revoke(owner);
                return false;
            }
            match effect {
                Ok(Some(n)) if n > 0 && n <= RESPONSE_LEN - self.sent => {
                    self.sent += n;
                    if self.sent == RESPONSE_LEN {
                        self.pending = false;
                        self.sent = 0;
                        self.deadline = None;
                        self.output.fill(0);
                        if self.closing {
                            self.revoke(owner);
                        }
                    }
                }
                Ok(None) => {}
                _ => self.revoke(owner),
            }
            return self.live;
        }
        let effect = pipe.read(&mut self.input[self.used..]);
        let after = match owner.live(self.endpoint) {
            Ok(now) => now,
            Err(_) => {
                self.revoke(owner);
                return false;
            }
        };
        if self.deadline.is_some_and(|end| after >= end) {
            self.revoke(owner);
            return false;
        }
        match effect {
            Ok(Some(n)) if n > 0 && n <= REQUEST_LEN - self.used => {
                if end.is_none_or(|end| after >= end) {
                    self.revoke(owner);
                    return false;
                }
                self.deadline = end;
                self.used += n;
                if self.used != REQUEST_LEN {
                    return true;
                }
                self.output.fill(0);
                let op = self.input[1];
                self.output[..4].copy_from_slice(&[VERSION, op, 0, FAMILY]);
                let peer = Peer {
                    ip: self.input[4..20].try_into().unwrap(),
                    scope: u32::from_be_bytes(self.input[20..24].try_into().unwrap()),
                };
                let result = if self.input[0] != VERSION
                    || self.input[2..4] != [0, FAMILY]
                    || !matches!(op, START | OBSERVE | CLOSE)
                {
                    Err(Error::Invalid)
                } else if peer != fixture_peer() {
                    Err(Error::Denied)
                } else {
                    match op {
                        START => owner.start(self.endpoint, peer),
                        OBSERVE => owner
                            .observe(self.endpoint)
                            .map(|o| encode(o, &mut self.output)),
                        CLOSE => owner.cancel(self.endpoint).map(|()| {
                            owner.entry.as_mut().unwrap().closing = true;
                            self.closing = true;
                        }),
                        _ => unreachable!(),
                    }
                };
                if let Err(error) = result {
                    self.output[2] = error.code();
                }
                let now = match owner.live(self.endpoint) {
                    Ok(now) => now,
                    Err(_) => {
                        self.revoke(owner);
                        return false;
                    }
                };
                self.used = 0;
                self.pending = true;
                self.deadline = now.checked_add(FRAME_MS);
                if self.deadline.is_none() {
                    self.revoke(owner);
                }
            }
            Ok(None) => {}
            _ => self.revoke(owner),
        }
        self.live
    }
}

/// A bounded transaction never retries a START after uncertain I/O.
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
    check(pipe, until, last)?;
    let end = last.checked_add(FRAME_MS).ok_or(-110i64)?.min(until);
    let mut at = 0;
    let mut reply = [0; RESPONSE_LEN];
    for _ in 0..MAX_TRANSFERS {
        check(pipe, end, last)?;
        if at < REQUEST_LEN {
            match pipe.write(&request[at..])? {
                Some(n) if n > 0 && n <= REQUEST_LEN - at => at += n,
                None => {}
                _ => return Err(-5),
            }
        } else {
            let offset = at - REQUEST_LEN;
            match pipe.read(&mut reply[offset..])? {
                Some(n) if n > 0 && n <= RESPONSE_LEN - offset => at += n,
                None => {}
                _ => return Err(-5),
            }
        }
        check(pipe, end, last)?;
        if at == REQUEST_LEN + RESPONSE_LEN {
            if reply[..2] != request[..2]
                || reply[3] != FAMILY
                || reply[60..] != [0; 4]
                || (reply[2] != 0 && (!(1..=13).contains(&reply[2]) || reply[4..60] != [0; 56]))
                || (reply[2] == 0 && request[1] != OBSERVE && reply[4..60] != [0; 56])
            {
                return Err(-22);
            }
            return Ok(reply);
        }
    }
    Err(-110)
}
#[cfg(test)]
mod tests;
