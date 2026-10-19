//! Owned UDP framing. Unknown SEND completion drops the actual channel.
use absd_net::datagram::{
    self as d,
    channel::{Pipe, transact},
};
use absd_net::ipv6;
use std::cell::Cell;

/// The address selects a codec, never authority. The pipe's owner must have
/// independently granted this exact peer, including its service-local scope.
#[derive(Clone, Copy)]
pub(crate) enum Peer {
    V4(d::Address),
    V6(ipv6::Address),
}
impl Peer {
    fn header(self) -> usize {
        match self {
            Self::V4(_) => 12,
            Self::V6(_) => ipv6::session::HEADER,
        }
    }
    pub(crate) fn max_datagram(self) -> usize {
        match self {
            Self::V4(_) => d::MAX_DATAGRAM,
            Self::V6(_) => ipv6::MAX_DATAGRAM,
        }
    }
    pub(crate) fn socket_addr(self) -> std::net::SocketAddr {
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
        match self {
            Self::V4(peer) => SocketAddr::from((Ipv4Addr::from(peer.ip), peer.port)),
            // Quinn uses this only as the fixed connection identity. Native
            // scope remains in the v2 channel; it is not a Linux interface id.
            Self::V6(peer) => {
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(peer.ip), peer.port, 0, 0))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Config,
    Clock,
    Deadline,
    Cancelled,
    Fenced,
    Unknown(i64),
    Malformed,
    Limit,
    Native(d::Error),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Metrics {
    pub send_calls: u64,
    pub send_accepted: u64,
    pub send_bytes: u64,
    pub exhausted: u64,
    pub receive_calls: u64,
    pub received: u64,
    pub receive_bytes: u64,
    pub again: u64,
    pub close_calls: u64,
    pub close_accepted: bool,
    pub pipe_fenced: bool,
    pub unknown_send: bool,
    pub last_send_ms: Option<u64>,
    pub fence_ms: Option<u64>,
    pub sends_after_fence: u64,
}

struct Checked<P> {
    pipe: P,
    last: Cell<u64>,
    violation: Cell<Option<Failure>>,
    deadline: u64,
    cancelled: fn() -> bool,
}
impl<P: Pipe> Checked<P> {
    fn observe(&self) -> u64 {
        let now = self.pipe.now_ms();
        let failure = if now < self.last.get() {
            Some(Failure::Clock)
        } else if (self.cancelled)() {
            Some(Failure::Cancelled)
        } else if now >= self.deadline {
            Some(Failure::Deadline)
        } else {
            None
        };
        if self.violation.get().is_none() {
            self.violation.set(failure);
        }
        self.last.set(now);
        if self.violation.get().is_some() {
            self.deadline
        } else {
            now
        }
    }
    fn usable(&self) -> Result<(), i64> {
        self.observe();
        if self.violation.get().is_some() {
            Err(-110)
        } else {
            Ok(())
        }
    }
}
impl<P: Pipe> Pipe for Checked<P> {
    fn now_ms(&self) -> u64 {
        self.observe()
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        self.usable()?;
        self.pipe.read(bytes)
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        self.usable()?;
        self.pipe.write(bytes)
    }
}

pub struct NativeTransport<P: Pipe> {
    pipe: Option<Checked<P>>,
    peer: Peer,
    pub metrics: Metrics,
    pub failure: Option<Failure>,
}
impl<P: Pipe> NativeTransport<P> {
    pub fn new(pipe: P, peer: d::Address, deadline: u64, cancelled: fn() -> bool) -> Self {
        Self::from_peer(pipe, Peer::V4(peer), deadline, cancelled)
    }
    /// Consume one already-granted IPv6 datagram channel. The selected family
    /// never falls back, including after malformed or unauthorized operations.
    pub fn new_ipv6(pipe: P, peer: ipv6::Address, deadline: u64, cancelled: fn() -> bool) -> Self {
        Self::from_peer(pipe, Peer::V6(peer), deadline, cancelled)
    }
    pub(crate) fn from_peer(pipe: P, peer: Peer, deadline: u64, cancelled: fn() -> bool) -> Self {
        let now = pipe.now_ms();
        Self {
            pipe: Some(Checked {
                pipe,
                last: Cell::new(now),
                violation: Cell::new(None),
                deadline,
                cancelled,
            }),
            peer,
            metrics: Metrics::default(),
            failure: None,
        }
    }
    pub fn fence(&mut self) {
        if self.metrics.fence_ms.is_none() {
            self.metrics.fence_ms = self.pipe.as_ref().map(|pipe| pipe.pipe.now_ms());
        }
        drop(self.pipe.take());
        self.metrics.pipe_fenced = true;
    }
    pub fn check(&mut self) -> Result<u64, Failure> {
        let Some(pipe) = &self.pipe else {
            return Err(Failure::Fenced);
        };
        let now = pipe.observe();
        let failure = pipe.violation.get();
        if let Some(failure) = failure {
            self.failure.get_or_insert(failure);
            self.fence();
            return Err(failure);
        }
        Ok(now)
    }
    fn fail<T>(&mut self, failure: Failure, uncertain_send: bool) -> Result<T, Failure> {
        self.failure.get_or_insert(failure);
        self.metrics.unknown_send |= uncertain_send;
        self.fence();
        Err(failure)
    }
    fn call(
        &mut self,
        opcode: u8,
        bytes: &[u8],
        reply: &mut [u8; d::MAX_MESSAGE],
    ) -> Result<usize, Failure> {
        match self.peer {
            Peer::V4(peer) => self.call_v4(peer, opcode, bytes, reply),
            Peer::V6(peer) => self.call_v6(peer, opcode, bytes, reply),
        }
    }
    fn call_v4(
        &mut self,
        peer: d::Address,
        opcode: u8,
        bytes: &[u8],
        reply: &mut [u8; d::MAX_MESSAGE],
    ) -> Result<usize, Failure> {
        let now = self.check()?;
        if bytes.len() > crate::engine::SEND_MTU {
            return self.fail(Failure::Limit, false);
        }
        let mut request = [0; d::MAX_MESSAGE];
        request[0] = d::VERSION;
        request[1] = opcode;
        if opcode == d::SEND {
            request[4..8].copy_from_slice(&peer.ip);
            request[8..10].copy_from_slice(&peer.port.to_be_bytes());
            request[10..12].copy_from_slice(&(bytes.len() as u16).to_be_bytes());
            request[12..12 + bytes.len()].copy_from_slice(bytes);
        } else if opcode == d::RECEIVE {
            request[10..12].copy_from_slice(&(d::MAX_DATAGRAM as u16).to_be_bytes());
        }
        let pipe = self.pipe.as_mut().ok_or(Failure::Fenced)?;
        let left = pipe.deadline.checked_sub(now).ok_or(Failure::Deadline)?;
        let response = transact(pipe, &request[..12 + bytes.len()], reply, left.min(250));
        let violation = pipe.violation.get();
        let length = match response {
            Ok(length) => length,
            Err(code) => {
                return self.fail(
                    violation.unwrap_or(Failure::Unknown(code)),
                    opcode == d::SEND,
                );
            }
        };
        // A clock/cancellation/expiry observation during the transaction is terminal
        // even when a framed reply happened to arrive. No later operation follows.
        if let Some(failure) = violation {
            return self.fail(failure, opcode == d::SEND);
        }
        let count = u16::from_be_bytes([reply[10], reply[11]]) as usize;
        if reply[2] == 0 {
            let valid = if opcode == d::RECEIVE {
                count <= d::MAX_DATAGRAM
                    && length == 12 + count
                    && reply[4..8] == peer.ip
                    && reply[8..10] == peer.port.to_be_bytes()
            } else {
                length == 12 && reply[4..12] == [0; 8]
            };
            if !valid {
                return self.fail(Failure::Malformed, opcode == d::SEND);
            }
            return Ok(count);
        }
        if length != 12
            || reply[4..10] != [0; 6]
            || (!matches!(reply[2], 7 | 12..=15) && count != 0)
        {
            return self.fail(Failure::Malformed, opcode == d::SEND);
        }
        let error = match reply[2] {
            1 => d::Error::Invalid,
            2 => d::Error::Denied,
            3 => d::Error::InUse,
            4 if opcode == d::SEND => d::Error::Exhausted,
            5 => d::Error::Oversize,
            6 if opcode == d::RECEIVE => d::Error::Again,
            7 if opcode == d::RECEIVE && count > d::MAX_DATAGRAM => {
                d::Error::TooSmall { needed: count }
            }
            8 => d::Error::Stale,
            9 => d::Error::LinkDown,
            10 => d::Error::DeviceFailed,
            11 => d::Error::LinkUnknown,
            12 if count <= 15 && count != 4 => {
                d::Error::Icmp(absd_net::icmp::Error::DestinationUnreachable { code: count as u8 })
            }
            13 if count <= 1 => {
                d::Error::Icmp(absd_net::icmp::Error::TimeExceeded { code: count as u8 })
            }
            14 if count == 0 || (absd_net::icmp::MIN_MTU as usize..1500).contains(&count) => {
                d::Error::Icmp(absd_net::icmp::Error::FragmentationNeeded { mtu: count as u16 })
            }
            15 if opcode == d::SEND
                && count < bytes.len()
                && (absd_net::icmp::MIN_MTU as usize - 28..d::MAX_DATAGRAM).contains(&count) =>
            {
                d::Error::PathMtu { maximum: count }
            }
            _ => return self.fail(Failure::Malformed, opcode == d::SEND),
        };
        if error == d::Error::Exhausted || error == d::Error::Again {
            Err(Failure::Native(error))
        } else {
            self.fail(Failure::Native(error), false)
        }
    }
    fn call_v6(
        &mut self,
        peer: ipv6::Address,
        opcode: u8,
        bytes: &[u8],
        reply: &mut [u8; d::MAX_MESSAGE],
    ) -> Result<usize, Failure> {
        use ipv6::session::{FAMILY, HEADER, MAX_MESSAGE, VERSION};
        let now = self.check()?;
        if bytes.len() > crate::engine::SEND_MTU {
            return self.fail(Failure::Limit, false);
        }
        let mut request = [0; MAX_MESSAGE];
        request[0] = VERSION;
        request[1] = opcode;
        request[3] = FAMILY;
        if opcode == d::SEND {
            request[4..20].copy_from_slice(&peer.ip);
            request[20..24].copy_from_slice(&peer.scope.to_be_bytes());
            request[24..26].copy_from_slice(&peer.port.to_be_bytes());
            request[26..28].copy_from_slice(&(bytes.len() as u16).to_be_bytes());
            request[HEADER..HEADER + bytes.len()].copy_from_slice(bytes);
        } else if opcode == d::RECEIVE {
            request[26..28].copy_from_slice(&(ipv6::MAX_DATAGRAM as u16).to_be_bytes());
        }
        let pipe = self.pipe.as_mut().ok_or(Failure::Fenced)?;
        let left = pipe.deadline.checked_sub(now).ok_or(Failure::Deadline)?;
        let mut response = [0; MAX_MESSAGE];
        let result = ipv6::channel::transact(
            pipe,
            &request[..HEADER + bytes.len()],
            &mut response,
            left.min(250),
        );
        let violation = pipe.violation.get();
        let length = match result {
            Ok(length) => length,
            Err(code) => {
                return self.fail(
                    violation.unwrap_or(Failure::Unknown(code)),
                    opcode == d::SEND,
                );
            }
        };
        if let Some(failure) = violation {
            return self.fail(failure, opcode == d::SEND);
        }
        let count = u16::from_be_bytes([response[26], response[27]]) as usize;
        if response[2] == 0 {
            let valid = if opcode == d::RECEIVE {
                count <= ipv6::MAX_DATAGRAM
                    && length == HEADER + count
                    && response[4..20] == peer.ip
                    && response[20..24] == peer.scope.to_be_bytes()
                    && response[24..26] == peer.port.to_be_bytes()
            } else {
                length == HEADER && response[4..HEADER] == [0; HEADER - 4]
            };
            if !valid {
                return self.fail(Failure::Malformed, opcode == d::SEND);
            }
            reply[..length].copy_from_slice(&response[..length]);
            return Ok(count);
        }
        if length != HEADER || response[4..26] != [0; 22] || (response[2] != 7 && count != 0) {
            return self.fail(Failure::Malformed, opcode == d::SEND);
        }
        let error = match response[2] {
            1 => d::Error::Invalid,
            2 => d::Error::Denied,
            3 => d::Error::InUse,
            4 if opcode == d::SEND => d::Error::Exhausted,
            5 => d::Error::Oversize,
            6 if opcode == d::RECEIVE => d::Error::Again,
            7 if opcode == d::RECEIVE && count > ipv6::MAX_DATAGRAM => {
                d::Error::TooSmall { needed: count }
            }
            8 => d::Error::Stale,
            9 => d::Error::LinkDown,
            10 => d::Error::DeviceFailed,
            11 => d::Error::LinkUnknown,
            // ICMPv4 status forms are not part of the IPv6 v2 response ABI.
            _ => return self.fail(Failure::Malformed, opcode == d::SEND),
        };
        if error == d::Error::Exhausted || error == d::Error::Again {
            Err(Failure::Native(error))
        } else {
            self.fail(Failure::Native(error), false)
        }
    }
    pub fn send(&mut self, bytes: &[u8]) -> Result<bool, Failure> {
        if self.metrics.pipe_fenced {
            self.metrics.sends_after_fence += 1;
        }
        let now = self.check()?;
        if self.metrics.send_accepted >= crate::engine::PACKET_LIMIT
            || self
                .metrics
                .send_bytes
                .checked_add(bytes.len() as u64)
                .is_none_or(|n| n > crate::engine::TX_LIMIT)
        {
            return self.fail(Failure::Limit, false);
        }
        self.metrics.send_calls += 1;
        self.metrics.last_send_ms = Some(now);
        match self.call(d::SEND, bytes, &mut [0; d::MAX_MESSAGE]) {
            Ok(_) => {
                self.metrics.send_accepted += 1;
                self.metrics.send_bytes += bytes.len() as u64;
                Ok(true)
            }
            Err(Failure::Native(d::Error::Exhausted)) => {
                self.metrics.exhausted += 1;
                Ok(false)
            }
            Err(failure) => Err(failure),
        }
    }
    pub fn receive(&mut self, bytes: &mut [u8; d::MAX_DATAGRAM]) -> Result<Option<usize>, Failure> {
        self.check()?;
        // Refuse before native RECEIVE can consume a datagram. Reserve a full
        // maximum-sized datagram; its actual accepted length is counted below.
        if self.metrics.received >= crate::engine::PACKET_LIMIT
            || self
                .metrics
                .receive_bytes
                .checked_add(self.peer.max_datagram() as u64)
                .is_none_or(|n| n > crate::engine::RX_LIMIT)
        {
            return self.fail(Failure::Limit, false);
        }
        self.metrics.receive_calls += 1;
        let mut reply = [0; d::MAX_MESSAGE];
        match self.call(d::RECEIVE, &[], &mut reply) {
            Ok(length) => {
                let header = self.peer.header();
                bytes[..length].copy_from_slice(&reply[header..header + length]);
                self.metrics.received += 1;
                self.metrics.receive_bytes += length as u64;
                Ok(Some(length))
            }
            Err(Failure::Native(d::Error::Again)) => {
                self.metrics.again += 1;
                Ok(None)
            }
            Err(failure) => Err(failure),
        }
    }
    pub fn close(&mut self) -> Result<(), Failure> {
        self.metrics.close_calls += 1;
        self.call(d::CLOSE, &[], &mut [0; d::MAX_MESSAGE])?;
        self.metrics.close_accepted = true;
        self.fence();
        Ok(())
    }
}
