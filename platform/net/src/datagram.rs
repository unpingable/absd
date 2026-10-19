//! Native static-IPv4 datagrams. The NIC holder constructs exact grants;
//! clients receive a dedicated pipe session, never a NIC or socket number.
//! See docs/NATIVE-UDP.md for authority, bounds and replacement semantics.

use super::*;
use core::sync::atomic::{AtomicU64, Ordering};
use smoltcp::socket::udp;
use smoltcp::wire::IpEndpoint;

pub const MAX_DATAGRAM: usize = 1472;
pub const QUEUE_PACKETS: usize = 4;
pub const MAX_ENDPOINTS: usize = 8;
pub const MAX_MESSAGE: usize = MAX_DATAGRAM + 12;
pub const VERSION: u8 = 1;
pub const SEND: u8 = 1;
pub const RECEIVE: u8 = 2;
pub const CLOSE: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    pub ip: [u8; 4],
    pub port: u16,
}

impl Address {
    fn wire(self) -> IpEndpoint {
        IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::from(self.ip)), self.port)
    }
}

/// Only the trusted NIC holder creates grants. Local ports are explicit,
/// nonprivileged, exclusive and bound to the configured local IPv4 address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub local_port: u16,
    pub peer: Address,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Denied,
    InUse,
    Exhausted,
    Oversize,
    Again,
    /// The queued datagram remains intact for a larger receive.
    TooSmall {
        needed: usize,
    },
    Stale,
    LinkDown,
    DeviceFailed,
    LinkUnknown,
    /// Matched, unauthenticated feedback about a recently submitted packet.
    Icmp(crate::icmp::Error),
    /// This grant learned a smaller ceiling; no packet was enqueued.
    PathMtu {
        maximum: usize,
    },
}

impl Error {
    pub fn code(self) -> u8 {
        match self {
            Self::Invalid => 1,
            Self::Denied => 2,
            Self::InUse => 3,
            Self::Exhausted => 4,
            Self::Oversize => 5,
            Self::Again => 6,
            Self::TooSmall { .. } => 7,
            Self::Stale => 8,
            Self::LinkDown => 9,
            Self::DeviceFailed => 10,
            Self::LinkUnknown => 11,
            Self::Icmp(crate::icmp::Error::DestinationUnreachable { .. }) => 12,
            Self::Icmp(crate::icmp::Error::TimeExceeded { .. }) => 13,
            Self::Icmp(crate::icmp::Error::FragmentationNeeded { .. }) => 14,
            Self::PathMtu { .. } => 15,
        }
    }
}

/// A service-local reference, not a serializable authority token. A client
/// uses its kernel pipe capability; request bytes never select an endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    instance: u64,
    slot: usize,
    epoch: u64,
}

struct Entry {
    socket: Option<SocketHandle>,
    grant: Grant,
    epoch: u64,
}

pub(super) struct Endpoints {
    instance: u64,
    entries: Vec<Entry>,
    next_epoch: u64,
}

static INSTANCE: AtomicU64 = AtomicU64::new(1);

impl Endpoints {
    pub(super) fn active(&self) -> bool {
        self.entries.iter().any(|e| e.socket.is_some())
    }
    pub(super) fn new() -> Result<Self, NetError> {
        let instance = INSTANCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| NetError::Config)?;
        Ok(Self {
            instance,
            entries: Vec::new(),
            next_epoch: 1,
        })
    }

    fn entry(&self, endpoint: Endpoint) -> Result<&Entry, Error> {
        if endpoint.instance != self.instance {
            return Err(Error::Stale);
        }
        self.entries
            .get(endpoint.slot)
            .filter(|e| e.epoch == endpoint.epoch && e.socket.is_some())
            .ok_or(Error::Stale)
    }
}

impl<L: Link> Stack<L> {
    /// Called by the NIC holder, never by untrusted request bytes.
    pub fn datagram_bind(&mut self, grant: Grant) -> Result<Endpoint, Error> {
        let ip = u32::from_be_bytes(grant.peer.ip);
        let local = u32::from_be_bytes(self.config.address.octets());
        let mask = u32::MAX << (32 - self.config.prefix_len);
        let subnet = local & mask;
        if grant.local_port < 1024
            || grant.peer.port == 0
            || grant.peer.ip[0] == 0
            || grant.peer.ip[0] == 127
            || grant.peer.ip[0] >= 224
            || ip == local
            || ip == subnet
            || ip == (subnet | !mask)
            || (ip & mask != subnet && self.config.gateway.is_none())
        {
            return Err(Error::Denied);
        }
        if self
            .datagrams
            .entries
            .iter()
            .any(|e| e.socket.is_some() && e.grant.local_port == grant.local_port)
        {
            return Err(Error::InUse);
        }
        let vacant = self
            .datagrams
            .entries
            .iter()
            .position(|e| e.socket.is_none());
        if vacant.is_none() && self.datagrams.entries.len() >= MAX_ENDPOINTS {
            return Err(Error::Exhausted);
        }
        let epoch = self.datagrams.next_epoch;
        self.datagrams.next_epoch = epoch.checked_add(1).ok_or(Error::Exhausted)?;
        let buffer = || {
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; QUEUE_PACKETS],
                vec![0; MAX_DATAGRAM * QUEUE_PACKETS],
            )
        };
        let mut socket = udp::Socket::new(buffer(), buffer());
        socket
            .bind((self.config.address, grant.local_port))
            .map_err(|_| Error::Invalid)?;
        let entry = Entry {
            socket: Some(self.sockets.add(socket)),
            grant,
            epoch,
        };
        let slot = if let Some(slot) = vacant {
            self.datagrams.entries[slot] = entry;
            slot
        } else {
            self.datagrams.entries.push(entry);
            self.datagrams.entries.len() - 1
        };
        self.port.feedback.bind(
            slot,
            epoch,
            self.config.address.octets(),
            self.config.prefix_len,
            grant.local_port,
            grant.peer,
        );
        Ok(Endpoint {
            instance: self.datagrams.instance,
            slot,
            epoch,
        })
    }

    fn datagram_live(&mut self) -> Result<(), Error> {
        let result = match self.read_link() {
            None => Err(Error::LinkUnknown),
            Some(r) if r.disabled => Err(Error::DeviceFailed),
            Some(r) if !r.link_up => Err(Error::LinkDown),
            Some(_) => Ok(()),
        };
        if result.is_err() {
            self.datagram_fence();
            self.stream_fence();
            self.ipv6_fence();
        }
        result
    }

    /// Success means queued locally. UDP has no delivery acknowledgment.
    /// Icmp/PathMtu refuse this SEND before enqueueing; asynchronous Icmp
    /// feedback can concern an earlier transaction on the same grant.
    pub fn datagram_send(
        &mut self,
        endpoint: Endpoint,
        peer: Address,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let entry = self.datagrams.entry(endpoint)?;
        if peer != entry.grant.peer {
            return Err(Error::Denied);
        }
        if bytes.len() > MAX_DATAGRAM {
            return Err(Error::Oversize);
        }
        let handle = entry.socket.unwrap();
        self.datagram_live()?;
        let now = self.port.link.now_ms();
        let maximum = self
            .port
            .feedback
            .maximum(endpoint.slot, endpoint.epoch, now);
        if bytes.len() > maximum {
            return Err(Error::PathMtu { maximum });
        }
        if let Some(error) = self.port.feedback.take(endpoint.slot, endpoint.epoch, now) {
            return Err(Error::Icmp(error));
        }
        self.sockets
            .get_mut::<udp::Socket>(handle)
            .send_slice(bytes, peer.wire())
            .map_err(|e| match e {
                udp::SendError::BufferFull => Error::Exhausted,
                udp::SendError::Unaddressable => Error::Invalid,
            })
    }

    /// Polls once, preserving datagram boundaries. Unauthorized sources are
    /// discarded with bounded work; a small buffer never consumes a packet.
    pub fn datagram_receive(
        &mut self,
        endpoint: Endpoint,
        bytes: &mut [u8],
    ) -> Result<(usize, Address), Error> {
        let entry = self.datagrams.entry(endpoint)?;
        let handle = entry.socket.unwrap();
        let peer = entry.grant.peer;
        self.datagram_live()?;
        if let Some(error) =
            self.port
                .feedback
                .take(endpoint.slot, endpoint.epoch, self.port.link.now_ms())
        {
            return Err(Error::Icmp(error));
        }
        let socket = self.sockets.get_mut::<udp::Socket>(handle);
        for _ in 0..QUEUE_PACKETS {
            let (packet, meta) = socket.peek().map_err(|_| Error::Again)?;
            if meta.endpoint != peer.wire() || packet.len() > MAX_DATAGRAM {
                let _ = socket.recv();
                continue;
            }
            if bytes.len() < packet.len() {
                return Err(Error::TooSmall {
                    needed: packet.len(),
                });
            }
            let (length, _) = socket.recv_slice(bytes).map_err(|_| Error::Again)?;
            return Ok((length, peer));
        }
        Err(Error::Again)
    }

    /// Immediate local discard, including queued TX/RX; packets already
    /// emitted cannot be recalled. Vacated references never revive.
    pub fn datagram_close(&mut self, endpoint: Endpoint) -> Result<(), Error> {
        let handle = self.datagrams.entry(endpoint)?.socket.unwrap();
        self.sockets.remove(handle);
        self.datagrams.entries[endpoint.slot].socket = None;
        self.port.feedback.revoke(endpoint.slot);
        Ok(())
    }

    /// Fence every endpoint after carrier/configuration/device failure or
    /// service shutdown. Reopening requires fresh owner-issued grants.
    pub fn datagram_fence(&mut self) {
        self.port.feedback.fence();
        for entry in &mut self.datagrams.entries {
            if let Some(handle) = entry.socket.take() {
                self.sockets.remove(handle);
            }
        }
    }
}

/// One channel's implicit endpoint. A request cannot select another
/// channel's grant. The owner must close it at pipe EOF/error/partial-frame
/// timeout; the target adapter below enforces that lifecycle.
pub struct Session {
    endpoint: Endpoint,
}

impl Session {
    pub fn grant<L: Link>(stack: &mut Stack<L>, grant: Grant) -> Result<Self, Error> {
        Ok(Self {
            endpoint: stack.datagram_bind(grant)?,
        })
    }

    pub fn revoke<L: Link>(&mut self, stack: &mut Stack<L>) {
        let _ = stack.datagram_close(self.endpoint);
    }

    /// Request: version, opcode, reserved[2], peer IPv4, peer port BE,
    /// length BE, data (SEND only). RECEIVE length is buffer capacity.
    /// Reply: version, opcode, status, reserved, peer, port, length BE,
    /// data (successful RECEIVE only). Other replies are exactly 12 bytes.
    /// Malformed messages never execute an operation.
    pub fn request<L: Link>(
        &mut self,
        stack: &mut Stack<L>,
        request: &[u8],
        reply: &mut [u8; MAX_MESSAGE],
    ) -> usize {
        reply[..12].fill(0);
        reply[0] = VERSION;
        reply[1] = request.get(1).copied().unwrap_or(0);
        let result = (|| {
            if request.len() < 12 || request[0] != VERSION || request[2..4] != [0, 0] {
                return Err(Error::Invalid);
            }
            let peer = Address {
                ip: request[4..8].try_into().unwrap(),
                port: u16::from_be_bytes(request[8..10].try_into().unwrap()),
            };
            let length = u16::from_be_bytes(request[10..12].try_into().unwrap()) as usize;
            match request[1] {
                SEND => {
                    if request.len() != 12 + length {
                        return Err(Error::Invalid);
                    }
                    stack.datagram_send(self.endpoint, peer, &request[12..])?;
                    Ok(0)
                }
                RECEIVE => {
                    if request.len() != 12
                        || peer
                            != (Address {
                                ip: [0; 4],
                                port: 0,
                            })
                        || length > MAX_DATAGRAM
                    {
                        return Err(Error::Invalid);
                    }
                    let (length, peer) =
                        stack.datagram_receive(self.endpoint, &mut reply[12..12 + length])?;
                    reply[4..8].copy_from_slice(&peer.ip);
                    reply[8..10].copy_from_slice(&peer.port.to_be_bytes());
                    reply[10..12].copy_from_slice(&(length as u16).to_be_bytes());
                    Ok(length)
                }
                CLOSE => {
                    if request.len() != 12 || request[4..12] != [0; 8] {
                        return Err(Error::Invalid);
                    }
                    stack.datagram_close(self.endpoint)?;
                    Ok(0)
                }
                _ => Err(Error::Invalid),
            }
        })();
        match result {
            Ok(length) => 12 + length,
            Err(error) => {
                reply[2] = error.code();
                if let Error::TooSmall { needed } = error {
                    reply[10..12].copy_from_slice(&(needed as u16).to_be_bytes());
                }
                let detail = match error {
                    Error::Icmp(
                        crate::icmp::Error::DestinationUnreachable { code }
                        | crate::icmp::Error::TimeExceeded { code },
                    ) => Some(code as u16),
                    Error::Icmp(crate::icmp::Error::FragmentationNeeded { mtu }) => Some(mtu),
                    Error::PathMtu { maximum } => Some(maximum as u16),
                    _ => None,
                };
                if let Some(detail) = detail {
                    reply[10..12].copy_from_slice(&detail.to_be_bytes());
                }
                12
            }
        }
    }
}

pub mod channel;
