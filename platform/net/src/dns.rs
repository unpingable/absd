//! Bounded A/AAAA stub resolver over delegated datagram authority.
//! Optional explicitly granted TCP fallback; no cache, ambient NIC or smoltcp public types.
//! The requested record family does not select or enlarge transport authority.
use crate::datagram::{
    self as d, Address,
    channel::{Pipe, transact},
};

pub mod tcp;
pub const LOOKUP_MS: u64 = 3000;
pub const MAX_TCP_RESPONSE: usize = 4096;
pub const MAX_CNAME: usize = 8;
pub const MAX_ADDRESSES: usize = 8;
const RETRY_MS: u64 = 750;
const MAX_RECORDS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidName,
    Malformed,
    NxDomain,
    NoAddress,
    Refused,
    ServerFailure,
    ResponseCode(u8),
    Truncated,
    TooLarge,
    CnameLoop,
    Exhausted,
    Timeout,
    Transport(d::Error),
    Channel(i64),
    Stream(crate::stream::Error),
    /// Opt-in unauthenticated, complete-packet-correlated IPv6 diagnostic.
    Ipv6Feedback(crate::ipv6::feedback::Observation),
    Clock,
}

/// A bound transport's receive must preserve datagrams and filter the exact
/// configured peer. Operations must return by the supplied absolute deadline.
/// pause must advance a monotonic clock without spinning. An interrupted pipe
/// transaction invalidates the transport; it must never retry a SEND itself.
pub trait Transport {
    /// Optional authorized TCP exchange. UDP-only transports retain explicit
    /// Truncated refusal. Must not renew deadline or resubmit uncertain writes.
    fn tcp(
        &mut self,
        _query: &[u8],
        _bytes: &mut [u8; MAX_TCP_RESPONSE],
        _deadline: u64,
    ) -> Result<usize, Error> {
        Err(Error::Truncated)
    }
    fn now_ms(&self) -> u64;
    fn pause(&mut self, ms: u64);
    fn send(&mut self, bytes: &[u8], deadline: u64) -> Result<(), Error>;
    fn receive(
        &mut self,
        bytes: &mut [u8; d::MAX_DATAGRAM],
        deadline: u64,
    ) -> Result<Option<usize>, Error>;
}

/// Owns one delegated pipe and its configured peer. Changing resolver identity
/// requires a fresh owner-issued endpoint, not a request on this transport.
pub struct Datagram<P: Pipe> {
    pipe: P,
    peer: Address,
    pause: fn(u64),
    live: bool,
}
impl<P: Pipe> Datagram<P> {
    pub fn new(pipe: P, peer: Address, pause: fn(u64)) -> Self {
        Self {
            pipe,
            peer,
            pause,
            live: true,
        }
    }
    fn call(
        &mut self,
        op: u8,
        data: &[u8],
        deadline: u64,
        reply: &mut [u8; d::MAX_MESSAGE],
    ) -> Result<usize, Error> {
        if !self.live {
            return Err(Error::Transport(d::Error::Stale));
        }
        let left = deadline
            .checked_sub(self.pipe.now_ms())
            .filter(|n| *n > 0)
            .ok_or(Error::Timeout)?;
        let mut request = [0; d::MAX_MESSAGE];
        request[0] = d::VERSION;
        request[1] = op;
        if op == d::SEND {
            if data.len() > d::MAX_DATAGRAM {
                return Err(Error::TooLarge);
            }
            request[4..8].copy_from_slice(&self.peer.ip);
            request[8..10].copy_from_slice(&self.peer.port.to_be_bytes());
            request[10..12].copy_from_slice(&(data.len() as u16).to_be_bytes());
            request[12..12 + data.len()].copy_from_slice(data);
        } else {
            request[10..12].copy_from_slice(&(d::MAX_DATAGRAM as u16).to_be_bytes());
        }
        let n = match transact(
            &mut self.pipe,
            &request[..12 + data.len()],
            reply,
            left.min(1000),
        ) {
            Ok(n) => n,
            Err(e) => {
                self.live = false;
                if e == -110 && self.pipe.now_ms() >= deadline {
                    return Err(Error::Timeout);
                }
                return Err(Error::Channel(e));
            }
        };
        let length = u16::from_be_bytes([reply[10], reply[11]]) as usize;
        if reply[2] == 0 {
            if (op == d::SEND && (n != 12 || reply[4..12] != [0; 8]))
                || (op == d::RECEIVE
                    && (n != 12 + length
                        || reply[4..8] != self.peer.ip
                        || reply[8..10] != self.peer.port.to_be_bytes()))
            {
                self.live = false;
                return Err(Error::Malformed);
            }
            return Ok(n);
        }
        if n != 12 || reply[4..10] != [0; 6] || (!matches!(reply[2], 7 | 12..=15) && length != 0) {
            self.live = false;
            return Err(Error::Malformed);
        }
        let error = match reply[2] {
            1 => d::Error::Invalid,
            2 => d::Error::Denied,
            3 => d::Error::InUse,
            4 => d::Error::Exhausted,
            5 => d::Error::Oversize,
            6 => d::Error::Again,
            7 => d::Error::TooSmall { needed: length },
            8 => d::Error::Stale,
            9 => d::Error::LinkDown,
            10 => d::Error::DeviceFailed,
            11 => d::Error::LinkUnknown,
            12 if length <= 15 && length != 4 => {
                d::Error::Icmp(crate::icmp::Error::DestinationUnreachable { code: length as u8 })
            }
            13 if length <= 1 => {
                d::Error::Icmp(crate::icmp::Error::TimeExceeded { code: length as u8 })
            }
            14 if length == 0 || (crate::icmp::MIN_MTU as usize..1500).contains(&length) => {
                d::Error::Icmp(crate::icmp::Error::FragmentationNeeded { mtu: length as u16 })
            }
            15 if op == d::SEND
                && length < data.len()
                && (crate::icmp::MIN_MTU as usize - 28..d::MAX_DATAGRAM).contains(&length) =>
            {
                d::Error::PathMtu { maximum: length }
            }
            _ => {
                self.live = false;
                return Err(Error::Malformed);
            }
        };
        Err(Error::Transport(error))
    }
}
impl<P: Pipe> Transport for Datagram<P> {
    fn now_ms(&self) -> u64 {
        self.pipe.now_ms()
    }
    fn pause(&mut self, ms: u64) {
        (self.pause)(ms);
    }
    fn send(&mut self, bytes: &[u8], deadline: u64) -> Result<(), Error> {
        match self.call(d::SEND, bytes, deadline, &mut [0; d::MAX_MESSAGE]) {
            Err(Error::Transport(d::Error::PathMtu { .. })) => Err(Error::TooLarge),
            other => other.map(|_| ()),
        }
    }
    fn receive(
        &mut self,
        bytes: &mut [u8; d::MAX_DATAGRAM],
        deadline: u64,
    ) -> Result<Option<usize>, Error> {
        let mut reply = [0; d::MAX_MESSAGE];
        match self.call(d::RECEIVE, &[], deadline, &mut reply) {
            Ok(n) => {
                bytes[..n - 12].copy_from_slice(&reply[12..n]);
                Ok(Some(n - 12))
            }
            Err(Error::Transport(d::Error::Again)) => Ok(None),
            Err(Error::Transport(d::Error::TooSmall { .. } | d::Error::Oversize)) => {
                Err(Error::TooLarge)
            }
            Err(e) => Err(e),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer {
    pub addresses: [[u8; 4]; MAX_ADDRESSES],
    pub count: usize,
    pub cname_transitions: usize,
}

/// IPv6 addresses from an AAAA question. The DNS transport may itself use
/// either IP family; this result does not grant access to any returned address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnswerV6 {
    pub addresses: [[u8; 16]; MAX_ADDRESSES],
    pub count: usize,
    pub cname_transitions: usize,
}

// Only these two widths may instantiate the shared parser and query engine.
// The type fixes both the question type and the returned address width.
trait AddressFamily {
    const QTYPE: u16;
}
impl AddressFamily for [u8; 4] {
    const QTYPE: u16 = 1;
}
impl AddressFamily for [u8; 16] {
    const QTYPE: u16 = 28;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AddressAnswer<const N: usize> {
    addresses: [[u8; N]; MAX_ADDRESSES],
    count: usize,
    cname_transitions: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Name {
    bytes: [u8; 255],
    len: usize,
}
impl Name {
    fn parse(text: &str) -> Result<Self, Error> {
        let text = text.strip_suffix('.').unwrap_or(text);
        let mut name = Self {
            bytes: [0; 255],
            len: 0,
        };
        for label in text.split('.') {
            if label.is_empty()
                || label.len() > 63
                || name.len + label.len() + 2 > 255
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(Error::InvalidName);
            }
            name.bytes[name.len] = label.len() as u8;
            name.len += 1;
            for b in label.bytes() {
                name.bytes[name.len] = b.to_ascii_lowercase();
                name.len += 1;
            }
        }
        name.len += 1;
        Ok(name)
    }
    fn wire(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

fn word(packet: &[u8], at: usize) -> Result<u16, Error> {
    let bytes = packet.get(at..at + 2).ok_or(Error::Malformed)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Return normalized name and the first byte after its encoded representation.
/// Compression targets must precede their pointer. Backward-only pointers and
/// a packet-sized step budget bound even a literal-label/pointer cycle.
fn name(packet: &[u8], start: usize) -> Result<(Name, usize), Error> {
    let mut out = Name {
        bytes: [0; 255],
        len: 0,
    };
    let mut pos = start;
    let mut end = None;
    let mut steps = 0;
    loop {
        steps += 1;
        if steps > packet.len() {
            return Err(Error::Malformed);
        }
        let b = *packet.get(pos).ok_or(Error::Malformed)?;
        if b & 0xc0 == 0xc0 {
            let target = (word(packet, pos)? & 0x3fff) as usize;
            if target < 12 || target >= pos {
                return Err(Error::Malformed);
            }
            end.get_or_insert(pos + 2);
            pos = target;
            continue;
        }
        if b & 0xc0 != 0 {
            return Err(Error::Malformed);
        }
        pos += 1;
        if out.len + b as usize + 1 > 255 {
            return Err(Error::Malformed);
        }
        out.bytes[out.len] = b;
        out.len += 1;
        if b == 0 {
            return Ok((out, end.unwrap_or(pos)));
        }
        let label = packet.get(pos..pos + b as usize).ok_or(Error::Malformed)?;
        for byte in label {
            // This initial hostname interface deliberately excludes arbitrary
            // binary DNS labels; it does not reinterpret dots within labels.
            if !byte.is_ascii_alphanumeric() && *byte != b'-' && *byte != b'_' {
                return Err(Error::Malformed);
            }
            out.bytes[out.len] = byte.to_ascii_lowercase();
            out.len += 1;
        }
        pos += b as usize;
    }
}

#[derive(Clone, Copy)]
struct Record {
    owner: Name,
    kind: u16,
    class: u16,
    data: usize,
    end: usize,
}
fn record(packet: &[u8], at: usize) -> Result<(Record, usize), Error> {
    let (owner, at) = name(packet, at)?;
    let kind = word(packet, at)?;
    let class = word(packet, at + 2)?;
    let len = word(packet, at + 8)? as usize;
    let data = at + 10;
    let end = data + len;
    if end > packet.len() {
        return Err(Error::Malformed);
    }
    if class == 1 && ((kind == 1 && len != 4) || (kind == 28 && len != 16)) {
        return Err(Error::Malformed);
    }
    if class == 1 && kind == 5 && name(packet, data)?.1 != end {
        return Err(Error::Malformed);
    }
    Ok((
        Record {
            owner,
            kind,
            class,
            data,
            end,
        },
        end,
    ))
}

// Ignore unrelated transactions/questions; malformed matching messages fail.
enum Reply<const N: usize = 4> {
    Ignore,
    Addresses(AddressAnswer<N>),
    Alias(Name),
}
fn response<const N: usize>(
    packet: &[u8],
    id: u16,
    question: Name,
    history: &mut alloc::vec::Vec<Name>,
) -> Result<Reply<N>, Error>
where
    [u8; N]: AddressFamily,
{
    if packet.len() < 2 || word(packet, 0)? != id {
        return Ok(Reply::Ignore);
    }
    if packet.len() < 12 {
        return Err(Error::Malformed);
    }
    let flags = word(packet, 2)?;
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 {
        return Ok(Reply::Ignore);
    }
    if word(packet, 4)? != 1 {
        return Err(Error::Malformed);
    }
    let (q, mut at) = name(packet, 12)?;
    if q != question || word(packet, at)? != <[u8; N]>::QTYPE || word(packet, at + 2)? != 1 {
        return Ok(Reply::Ignore);
    }
    at += 4;
    if flags & 0x0040 != 0 {
        return Err(Error::Malformed);
    }
    if flags & 0x0200 != 0 {
        return Err(Error::Truncated);
    }
    let answers = word(packet, 6)? as usize;
    let total = answers + word(packet, 8)? as usize + word(packet, 10)? as usize;
    if total > MAX_RECORDS {
        return Err(Error::Exhausted);
    }
    // Offsets, not expanded RR copies: memory is bounded independently of names.
    let answer_start = at;
    for _ in 0..total {
        at = record(packet, at)?.1;
    }
    if at != packet.len() {
        return Err(Error::Malformed);
    }
    match flags & 15 {
        0 => {}
        3 => return Err(Error::NxDomain),
        5 => return Err(Error::Refused),
        2 => return Err(Error::ServerFailure),
        code => return Err(Error::ResponseCode(code as u8)),
    }
    let mut current = question;
    loop {
        let mut next = None;
        let mut addresses = [[0; N]; MAX_ADDRESSES];
        let mut count = 0;
        let mut has_address = false;
        let mut pos = answer_start;
        for _ in 0..answers {
            let (r, end) = record(packet, pos)?;
            pos = end;
            if r.owner != current || r.class != 1 {
                continue;
            }
            has_address |= matches!(r.kind, 1 | 28);
            if r.kind == <[u8; N]>::QTYPE {
                let address: [u8; N] = packet[r.data..r.end]
                    .try_into()
                    .map_err(|_| Error::Malformed)?;
                if !addresses[..count].contains(&address) {
                    if count == MAX_ADDRESSES {
                        return Err(Error::Exhausted);
                    }
                    addresses[count] = address;
                    count += 1;
                }
            } else if r.kind == 5 {
                let alias = name(packet, r.data)?.0;
                if next.is_some_and(|previous| previous != alias) {
                    return Err(Error::Malformed);
                }
                next = Some(alias);
            }
        }
        if let Some(next) = next {
            if has_address {
                return Err(Error::Malformed);
            }
            if history.contains(&next) {
                return Err(Error::CnameLoop);
            }
            if history.len() > MAX_CNAME {
                return Err(Error::Exhausted);
            }
            history.push(next);
            current = next;
        } else if count != 0 {
            return Ok(Reply::Addresses(AddressAnswer {
                addresses,
                count,
                cname_transitions: history.len() - 1,
            }));
        } else if current != question {
            return Ok(Reply::Alias(current));
        } else {
            return Err(Error::NoAddress);
        }
    }
}

/// One synchronous lookup at a time. Owns the transport for its whole lifetime;
/// IDs never repeat within this instance (including failed lookups).
/// Native consumers use `with_entropy`; `new` also permits deterministic
/// caller-selected seeds. Neither constructor authenticates DNS or ICMP.
pub struct Resolver<T: Transport> {
    transport: T,
    seed: u16,
    issued: u32,
    retired: bool,
}
impl<T: Transport> Resolver<T> {
    /// Draws the initial ID from the caller's existing entropy provider.
    /// Provider failure is returned unchanged; no query or fallback seed is
    /// produced. A 16-bit random start does not hide later sequential IDs.
    pub fn with_entropy<E>(
        transport: T,
        fill: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<Self, E> {
        let mut seed = [0; 2];
        fill(&mut seed)?;
        Ok(Self::new(transport, u16::from_be_bytes(seed)))
    }

    pub fn new(transport: T, initial_id: u16) -> Self {
        Self {
            transport,
            seed: initial_id,
            issued: 0,
            retired: false,
        }
    }
    fn id(&mut self) -> Result<u16, Error> {
        if self.issued == 65536 {
            return Err(Error::Exhausted);
        }
        let id = self.seed.wrapping_add(self.issued as u16);
        self.issued += 1;
        Ok(id)
    }
    /// Timeout retires this resolver even if no frame was partial. Drop it
    /// and acquire a fresh owner-issued channel; stream cancellation cannot
    /// promise a recoverable frame boundary or recall already queued queries.
    pub fn lookup(&mut self, hostname: &str) -> Result<Answer, Error> {
        self.lookup_family::<4>(hostname).map(|answer| Answer {
            addresses: answer.addresses,
            count: answer.count,
            cname_transitions: answer.cname_transitions,
        })
    }
    /// Resolve AAAA records with the same bounds, deadlines and explicitly
    /// delegated transport as `lookup`. No A fallback, synthesized addresses,
    /// additional endpoint grant or implicit TCP authority is introduced.
    /// Timeout retires both entrypoints on this resolver.
    pub fn lookup_aaaa(&mut self, hostname: &str) -> Result<AnswerV6, Error> {
        self.lookup_family::<16>(hostname).map(|answer| AnswerV6 {
            addresses: answer.addresses,
            count: answer.count,
            cname_transitions: answer.cname_transitions,
        })
    }
    fn lookup_family<const N: usize>(&mut self, hostname: &str) -> Result<AddressAnswer<N>, Error>
    where
        [u8; N]: AddressFamily,
    {
        if self.retired {
            return Err(Error::Transport(d::Error::Stale));
        }
        let result = self.lookup_inner::<N>(hostname);
        if result == Err(Error::Timeout) {
            self.retired = true;
        }
        result
    }
    fn lookup_inner<const N: usize>(&mut self, hostname: &str) -> Result<AddressAnswer<N>, Error>
    where
        [u8; N]: AddressFamily,
    {
        let mut question = Name::parse(hostname)?;
        let mut history = alloc::vec![question];
        let start = self.transport.now_ms();
        let deadline = start.checked_add(LOOKUP_MS).ok_or(Error::Clock)?;
        let mut last = start;
        loop {
            let id = self.id()?;
            let mut query = [0; 271];
            query[..2].copy_from_slice(&id.to_be_bytes());
            query[2] = 1;
            query[5] = 1;
            query[12..12 + question.len].copy_from_slice(question.wire());
            let length = 12 + question.len + 4;
            let length_of_query = length;
            query[length - 4..length - 2].copy_from_slice(&<[u8; N]>::QTYPE.to_be_bytes());
            query[length - 1] = 1;
            let mut sent = 0;
            let mut retry = 0;
            loop {
                let now = self.transport.now_ms();
                if now < last {
                    return Err(Error::Clock);
                }
                last = now;
                if now >= deadline {
                    return Err(Error::Timeout);
                }
                if sent < 2 && now >= retry {
                    match self.transport.send(&query[..length], deadline) {
                        Ok(()) => {
                            sent += 1;
                            retry = now.checked_add(RETRY_MS).ok_or(Error::Clock)?;
                        }
                        Err(Error::Transport(d::Error::Again)) => {}
                        Err(e) => return Err(e),
                    }
                }
                let mut packet = [0; d::MAX_DATAGRAM];
                if let Some(length) = self.transport.receive(&mut packet, deadline)? {
                    if length > packet.len() {
                        return Err(Error::TooLarge);
                    }
                    let after = self.transport.now_ms();
                    if after < last {
                        return Err(Error::Clock);
                    }
                    last = after;
                    if after >= deadline {
                        return Err(Error::Timeout);
                    }
                    let mut parsed = response::<N>(&packet[..length], id, question, &mut history);
                    if matches!(parsed, Err(Error::Truncated)) {
                        let mut answer = [0; MAX_TCP_RESPONSE];
                        let count =
                            self.transport
                                .tcp(&query[..length_of_query], &mut answer, deadline)?;
                        if count > MAX_TCP_RESPONSE {
                            return Err(Error::TooLarge);
                        }
                        parsed = response::<N>(&answer[..count], id, question, &mut history);
                        if matches!(parsed, Ok(Reply::Ignore)) {
                            return Err(Error::Malformed);
                        }
                    }
                    let finished = self.transport.now_ms();
                    if finished < last {
                        return Err(Error::Clock);
                    }
                    last = finished;
                    if finished >= deadline {
                        return Err(Error::Timeout);
                    }
                    match parsed? {
                        Reply::Ignore => {}
                        Reply::Addresses(answer) => return Ok(answer),
                        Reply::Alias(alias) => {
                            question = alias;
                            break;
                        }
                    }
                }
                self.transport.pause(5);
            }
        }
    }
}

#[cfg(test)]
mod tests;
