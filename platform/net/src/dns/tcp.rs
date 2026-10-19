//! Explicitly paired UDP/TCP DNS authority on one serialized native channel.
//! Grant construction, not request bytes, chooses both exact peers.
use super::*;
use crate::{Link, Stack, stream};
use alloc::rc::Rc;
use core::cell::RefCell;

pub struct Session {
    udp: d::Session,
    tcp: stream::Session,
}
impl Session {
    pub fn grant<L: Link>(
        stack: &mut Stack<L>,
        udp: d::Grant,
        tcp: stream::Grant,
    ) -> Result<Self, stream::Error> {
        if udp.peer != tcp.peer {
            return Err(stream::Error::Denied);
        }
        let mut datagram = d::Session::grant(stack, udp).map_err(|e| match e {
            d::Error::InUse => stream::Error::InUse,
            d::Error::Exhausted => stream::Error::Exhausted,
            _ => stream::Error::Invalid,
        })?;
        match stream::Session::grant(stack, tcp) {
            Ok(tcp) => Ok(Self { udp: datagram, tcp }),
            Err(e) => {
                datagram.revoke(stack);
                Err(e)
            }
        }
    }
}
impl stream::channel::Handler for Session {
    fn request<L: Link>(
        &mut self,
        stack: &mut Stack<L>,
        request: &[u8],
        reply: &mut [u8; d::MAX_MESSAGE],
    ) -> usize {
        if request
            .get(1)
            .is_some_and(|op| (stream::CONNECT..=stream::ABORT).contains(op))
        {
            self.tcp.request(stack, request, reply)
        } else {
            self.udp.request(stack, request, reply)
        }
    }
    fn revoke<L: Link>(&mut self, stack: &mut Stack<L>) {
        self.udp.revoke(stack);
        self.tcp.revoke(stack);
    }
}
pub type Channel = stream::channel::Channel<Session>;

struct Shared<P>(Rc<RefCell<P>>);
impl<P: Pipe> Pipe for Shared<P> {
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        self.0.borrow_mut().read(bytes)
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        self.0.borrow_mut().write(bytes)
    }
    fn now_ms(&self) -> u64 {
        self.0.borrow().now_ms()
    }
}
/// One owned, serialized pipe carries only the owner's two same-peer grants.
/// No TCP contact occurs unless the resolver receives a matching UDP TC reply.
pub struct DatagramTcp<P: Pipe> {
    udp: Datagram<Shared<P>>,
    tcp: stream::Client<Shared<P>>,
    live: bool,
}
impl<P: Pipe> DatagramTcp<P> {
    pub fn new(pipe: P, peer: Address, pause: fn(u64)) -> Self {
        let shared = Rc::new(RefCell::new(pipe));
        Self {
            live: true,
            udp: Datagram::new(Shared(shared.clone()), peer, pause),
            tcp: stream::Client::new(Shared(shared), peer, pause),
        }
    }
}
fn failure(error: stream::Error) -> Error {
    match error {
        stream::Error::Timeout => Error::Timeout,
        stream::Error::Clock => Error::Clock,
        other => Error::Stream(other),
    }
}
impl<P: Pipe> Transport for DatagramTcp<P> {
    fn now_ms(&self) -> u64 {
        self.udp.now_ms()
    }
    fn pause(&mut self, ms: u64) {
        self.udp.pause(ms)
    }
    fn send(&mut self, bytes: &[u8], deadline: u64) -> Result<(), Error> {
        if !self.live {
            return Err(Error::Stream(stream::Error::Stale));
        }
        let result = self.udp.send(bytes, deadline);
        self.live &= self.udp.live;
        result
    }
    fn receive(
        &mut self,
        bytes: &mut [u8; d::MAX_DATAGRAM],
        deadline: u64,
    ) -> Result<Option<usize>, Error> {
        if !self.live {
            return Err(Error::Stream(stream::Error::Stale));
        }
        let result = self.udp.receive(bytes, deadline);
        self.live &= self.udp.live;
        result
    }
    fn tcp(
        &mut self,
        query: &[u8],
        bytes: &mut [u8; MAX_TCP_RESPONSE],
        deadline: u64,
    ) -> Result<usize, Error> {
        if !self.live {
            return Err(Error::Stream(stream::Error::Stale));
        }
        let result = self.exchange(query, bytes, deadline);
        if result.is_err() {
            self.live = false;
        }
        result
    }
}
impl<P: Pipe> DatagramTcp<P> {
    fn exchange(
        &mut self,
        query: &[u8],
        bytes: &mut [u8; MAX_TCP_RESPONSE],
        deadline: u64,
    ) -> Result<usize, Error> {
        let matching = validate_query(query)?;
        self.tcp.connect(deadline).map_err(failure)?;
        // Never resubmit either write after an uncertain framed IPC outcome.
        self.tcp
            .write_all(&(query.len() as u16).to_be_bytes(), deadline)
            .map_err(failure)?;
        self.tcp.write_all(query, deadline).map_err(failure)?;
        loop {
            let mut prefix = [0; 2];
            self.tcp
                .read_exact(&mut prefix, deadline)
                .map_err(failure)?;
            let length = u16::from_be_bytes(prefix) as usize;
            if length > MAX_TCP_RESPONSE {
                return Err(Error::TooLarge);
            }
            if length < 12 {
                return Err(Error::Malformed);
            }
            self.tcp
                .read_exact(&mut bytes[..length], deadline)
                .map_err(failure)?;
            // Ignore unmatched frames without resending the TCP query or
            // renewing the original absolute lookup deadline.
            if matches_response(&matching, &bytes[..length]) {
                return Ok(length);
            }
        }
    }
}

/// Shared pure matcher for scoped transports; malformed queries are refused
/// before any connection or write. It retains the original A/AAAA parser.
pub(crate) struct QueryMatch {
    id: u16,
    question: Name,
    ipv6_answer: bool,
}
pub(crate) fn validate_query(query: &[u8]) -> Result<QueryMatch, Error> {
    if !(17..=271).contains(&query.len()) {
        return Err(Error::Malformed);
    }
    let id = word(query, 0)?;
    let (question, at) = name(query, 12)?;
    if at + 4 != query.len()
        || word(query, 2)? != 0x0100
        || word(query, 4)? != 1
        || query[6..12] != [0; 6]
        || word(query, at + 2)? != 1
    {
        return Err(Error::Malformed);
    }
    let ipv6_answer = match word(query, at)? {
        1 => false,
        28 => true,
        _ => return Err(Error::Malformed),
    };
    Ok(QueryMatch {
        id,
        question,
        ipv6_answer,
    })
}

/// Only the parser's explicit Ignore result discards a TCP frame. A matched
/// malformed/error response is returned to the resolver, preserving its verdict.
pub(crate) fn matches_response(query: &QueryMatch, bytes: &[u8]) -> bool {
    let unrelated = if query.ipv6_answer {
        matches!(
            response::<16>(
                bytes,
                query.id,
                query.question,
                &mut alloc::vec![query.question]
            ),
            Ok(Reply::Ignore)
        )
    } else {
        matches!(
            response::<4>(
                bytes,
                query.id,
                query.question,
                &mut alloc::vec![query.question]
            ),
            Ok(Reply::Ignore)
        )
    };
    !unrelated
}
