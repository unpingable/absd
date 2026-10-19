//! Explicit paired IPv6 UDP/TCP grants on one owned serialized pipe.
//! The resolver chooses fallback after a matching truncated UDP response;
//! neither question family nor request bytes creates TCP authority.
use super::{Address, Grant as DatagramGrant, channel::Handler, dns::Datagram, session, stream};
use crate::{
    Link, Stack,
    datagram::channel::Pipe,
    dns::{Error, MAX_TCP_RESPONSE, Transport},
};
use alloc::rc::Rc;
use core::cell::RefCell;
#[cfg(test)]
mod tests;

pub struct Session {
    udp: session::Session,
    tcp: stream::Session,
}

impl Session {
    pub fn grant<L: Link>(
        stack: &mut Stack<L>,
        udp: DatagramGrant,
        tcp: stream::Grant,
    ) -> Result<Self, stream::Error> {
        if udp.peer != tcp.peer {
            return Err(stream::Error::Denied);
        }
        let mut udp = session::Session::grant(stack, udp).map_err(|error| match error {
            super::Error::Denied => stream::Error::Denied,
            super::Error::InUse => stream::Error::InUse,
            super::Error::Exhausted => stream::Error::Exhausted,
            super::Error::LinkDown => stream::Error::LinkDown,
            super::Error::DeviceFailed => stream::Error::DeviceFailed,
            super::Error::LinkUnknown => stream::Error::LinkUnknown,
            _ => stream::Error::Invalid,
        })?;
        match stream::Session::grant(stack, tcp) {
            Ok(tcp) => Ok(Self { udp, tcp }),
            Err(error) => {
                udp.revoke(stack);
                Err(error)
            }
        }
    }
}

impl Handler for Session {
    fn feedback_endpoint(&self) -> Option<super::Endpoint> {
        Some(self.udp.feedback_endpoint())
    }
    fn request<L: Link>(
        &mut self,
        stack: &mut Stack<L>,
        request: &[u8],
        reply: &mut [u8; session::MAX_MESSAGE],
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

pub type Channel = super::channel::Channel<Session>;
struct Shared<P>(Rc<RefCell<P>>);
impl<P: Pipe> Pipe for Shared<P> {
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        self.0.borrow_mut().read(b)
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        self.0.borrow_mut().write(b)
    }
    fn now_ms(&self) -> u64 {
        self.0.borrow().now_ms()
    }
}

pub struct DatagramTcp<P: Pipe> {
    udp: Datagram<Shared<P>>,
    tcp: stream::Client<Shared<P>>,
    live: bool,
}
impl<P: Pipe> DatagramTcp<P> {
    pub fn new(pipe: P, peer: Address, pause: fn(u64)) -> Self {
        let shared = Rc::new(RefCell::new(pipe));
        Self {
            udp: Datagram::new(Shared(shared.clone()), peer, pause),
            tcp: stream::Client::new(Shared(shared), peer, pause),
            live: true,
        }
    }
    pub fn live(&self) -> bool {
        self.live
    }
    fn exchange(
        &mut self,
        query: &[u8],
        answer: &mut [u8; MAX_TCP_RESPONSE],
        deadline: u64,
    ) -> Result<usize, Error> {
        let matching = crate::dns::tcp::validate_query(query)?;
        self.tcp.connect(deadline).map_err(failure)?;
        // validate_query bounds the question to 271 bytes. Submit its length
        // and bytes together (RFC 7766 section 8); write_all may still make
        // bounded suffix writes after a known partial acceptance. An uncertain
        // WRITE never resubmits either prefix or question.
        let mut framed = [0; 2 + 271];
        framed[..2].copy_from_slice(&(query.len() as u16).to_be_bytes());
        framed[2..2 + query.len()].copy_from_slice(query);
        self.tcp
            .write_all(&framed[..2 + query.len()], deadline)
            .map_err(failure)?;
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
                .read_exact(&mut answer[..length], deadline)
                .map_err(failure)?;
            if crate::dns::tcp::matches_response(&matching, &answer[..length]) {
                return Ok(length);
            }
        }
    }
}
fn failure(error: stream::Error) -> Error {
    match error {
        stream::Error::Timeout => Error::Timeout,
        stream::Error::Clock => Error::Clock,
        error => Error::Stream(error),
    }
}
impl<P: Pipe> Transport for DatagramTcp<P> {
    fn now_ms(&self) -> u64 {
        self.udp.now_ms()
    }
    fn pause(&mut self, ms: u64) {
        self.udp.pause(ms)
    }
    fn send(&mut self, b: &[u8], deadline: u64) -> Result<(), Error> {
        if !self.live {
            return Err(Error::Stream(stream::Error::Stale));
        }
        let result = self.udp.send(b, deadline);
        self.live &= self.udp.live();
        result
    }
    fn receive(
        &mut self,
        b: &mut [u8; crate::datagram::MAX_DATAGRAM],
        deadline: u64,
    ) -> Result<Option<usize>, Error> {
        if !self.live {
            return Err(Error::Stream(stream::Error::Stale));
        }
        let result = self.udp.receive(b, deadline);
        self.live &= self.udp.live();
        result
    }
    fn tcp(
        &mut self,
        query: &[u8],
        b: &mut [u8; MAX_TCP_RESPONSE],
        deadline: u64,
    ) -> Result<usize, Error> {
        if !self.live {
            return Err(Error::Stream(stream::Error::Stale));
        }
        let result = self.exchange(query, b, deadline);
        if result.is_err() {
            self.live = false;
        }
        result
    }
}
