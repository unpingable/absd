//! Bounded static, on-link IPv6 UDP. Only the NIC holder installs an
//! address/link identity and creates exact peer grants. Neighbor discovery
//! resolves delivery addresses; received packets never construct authority.

use super::*;
use core::sync::atomic::{AtomicU64, Ordering};
use smoltcp::socket::udp;
use smoltcp::wire::{IpEndpoint, Ipv6Address};

pub use crate::datagram::Error;
#[cfg(test)]
mod boundary_tests;
pub mod channel;
pub mod dad;
pub use dad::echo;
pub use dad::echo_responder;
pub mod dns;
pub mod dns_tcp;
pub mod feedback;
pub mod routing;
pub mod session;
pub mod stream;

pub const MAX_DATAGRAM: usize = 1232;
pub const QUEUE_PACKETS: usize = 4;
pub const MAX_ENDPOINTS: usize = 8;

/// One owner-configured address and link identity. Scope is an owner-issued
/// service-local interface identity, not a field trusted from a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub address: [u8; 16],
    pub prefix_len: u8,
    pub scope: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    pub ip: [u8; 16],
    pub port: u16,
    pub scope: u32,
}

impl Address {
    fn wire(self) -> IpEndpoint {
        IpEndpoint::new(IpAddress::Ipv6(Ipv6Address::from(self.ip)), self.port)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub local_port: u16,
    pub peer: Address,
}

/// Process-local reference to one implementation generation. This Rust
/// representation is neither a transferable schema nor a capability.
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
    config: Option<Config>,
    entries: Vec<Entry>,
    next_epoch: u64,
    last_ms: Option<u64>,
}

static INSTANCE: AtomicU64 = AtomicU64::new(1);

impl Endpoints {
    pub(super) fn new() -> Result<Self, NetError> {
        let instance = INSTANCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| NetError::Config)?;
        Ok(Self {
            instance,
            config: None,
            entries: Vec::new(),
            next_epoch: 1,
            last_ms: None,
        })
    }

    fn active(&self) -> bool {
        self.entries.iter().any(|entry| entry.socket.is_some())
    }

    fn entry(&self, endpoint: Endpoint) -> Result<&Entry, Error> {
        if endpoint.instance != self.instance {
            return Err(Error::Stale);
        }
        self.entries
            .get(endpoint.slot)
            .filter(|entry| entry.epoch == endpoint.epoch && entry.socket.is_some())
            .ok_or(Error::Stale)
    }
}

/// Initial address policy supports global, unique-local and link-local
/// unicast. IPv4-compatible/mapped, unspecified, loopback, multicast and
/// reserved address families are refused rather than inferred or translated.
fn usable_address(ip: [u8; 16]) -> bool {
    ip[0] & 0xe0 == 0x20
        || ip[0] & 0xfe == 0xfc
        || (ip[0] == 0xfe && ip[1] == 0x80 && ip[2..8].iter().all(|byte| *byte == 0))
}

fn same_prefix(left: [u8; 16], right: [u8; 16], prefix_len: u8) -> bool {
    let whole = usize::from(prefix_len / 8);
    let remaining = prefix_len % 8;
    left[..whole] == right[..whole]
        && (remaining == 0 || (left[whole] ^ right[whole]) & (u8::MAX << (8 - remaining)) == 0)
}

/// Static first-slice ingress policy, before the protocol engine. Only
/// ordinary UDP and direct-neighbor NS/NA are supported. IPv6 extension
/// headers, fragments, proxy NA, routers, DAD and other ICMPv6 messages are
/// refused here. This deliberately narrower policy is not general RFC 4861
/// conformance. TCP has a separate exact-flow ingress predicate. smoltcp
/// remains the checksum, ND and transport implementation.
pub(super) fn ingress(frame: &[u8], config: Option<Config>, peers: &[Option<[u8; 16]>]) -> bool {
    ingress_router(frame, config, peers, None)
}

pub(super) fn ingress_router(
    frame: &[u8],
    config: Option<Config>,
    peers: &[Option<[u8; 16]>],
    router: Option<[u8; 16]>,
) -> bool {
    if frame.len() < 14 || frame[12..14] != [0x86, 0xdd] {
        return true;
    }
    let Some(config) = config else {
        return false;
    };
    if frame.len() < 54 || frame[14] >> 4 != 6 {
        return false;
    }
    let length = usize::from(u16::from_be_bytes([frame[18], frame[19]]));
    if length > 1240 || frame.len() < 54 + length {
        return false;
    }
    let source: [u8; 16] = frame[22..38].try_into().unwrap();
    let destination: [u8; 16] = frame[38..54].try_into().unwrap();
    if !usable_address(source) || source == config.address {
        return false;
    }
    if frame[20] == 17 {
        return destination == config.address
            && same_prefix(source, config.address, config.prefix_len);
    }
    if frame[20] != 58 || length < 24 || frame[21] != 255 {
        return false;
    }
    let payload = &frame[54..54 + length];
    if payload[1] != 0 || !matches!(payload[0], 135 | 136) {
        return false;
    }
    let source_ip = Ipv6Address::from(source);
    let destination_ip = Ipv6Address::from(destination);
    let packet = smoltcp::wire::Icmpv6Packet::new_unchecked(payload);
    if !packet.verify_checksum(&source_ip, &destination_ip) {
        return false;
    }
    let target: [u8; 16] = payload[8..24].try_into().unwrap();
    let mut solicited = [0; 16];
    solicited[0] = 0xff;
    solicited[1] = 2;
    solicited[11] = 1;
    solicited[12] = 0xff;
    solicited[13..].copy_from_slice(&config.address[13..]);
    if payload[0] == 135 {
        if target != config.address
            || (destination != config.address && destination != solicited)
            || (!same_prefix(source, config.address, config.prefix_len)
                && !(source[0] == 0xfe && source[1] == 0x80))
        {
            return false;
        }
    } else {
        let mut all_nodes = [0; 16];
        all_nodes[0] = 0xff;
        all_nodes[1] = 2;
        all_nodes[15] = 1;
        if (payload[4] & 0x80 != 0 && router != Some(source))
            || target != source
            || !peers.contains(&Some(source))
            || (destination != config.address && destination != all_nodes)
            || (destination[0] == 0xff && payload[4] & 0x40 != 0)
        {
            return false;
        }
    }
    let mut options = &payload[24..];
    while !options.is_empty() {
        if options.len() < 2 || options[1] == 0 {
            return false;
        }
        let length = usize::from(options[1]) * 8;
        if options.len() < length {
            return false;
        }
        if matches!(options[0], 1 | 2)
            && (length != 8
                || options[0] != if payload[0] == 135 { 1 } else { 2 }
                || options[2] & 1 != 0
                || options[2..8] != frame[6..12])
        {
            return false;
        }
        options = &options[length..];
    }
    true
}

impl<L: Link> Stack<L> {
    /// Install once from trusted owner configuration. No default route,
    /// router advertisement, SLAAC, DHCPv6 or discovery-derived authority.
    /// Reconfiguration requires a fresh Stack, fencing the old generation.
    pub fn configure_ipv6(&mut self, config: Config) -> Result<(), Error> {
        if config.scope == 0
            || !(1..=128).contains(&config.prefix_len)
            || !usable_address(config.address)
        {
            return Err(Error::Denied);
        }
        if self.ipv6_datagrams.config.is_some() {
            return Err(Error::InUse);
        }
        let mut added = false;
        self.iface.update_ip_addrs(|addresses| {
            added = addresses
                .push(IpCidr::new(
                    IpAddress::Ipv6(Ipv6Address::from(config.address)),
                    config.prefix_len,
                ))
                .is_ok();
        });
        if !added {
            return Err(Error::Exhausted);
        }
        self.ipv6_datagrams.config = Some(config);
        self.port.ipv6_config = Some(config);
        self.ipv6_datagrams.last_ms = Some(self.port.link.now_ms());
        Ok(())
    }

    pub fn ipv6_config(&self) -> Option<Config> {
        self.ipv6_datagrams.config
    }

    /// Constructed only by the NIC holder. A nonzero scope must name this
    /// exact configured link, including for global/unique-local addresses.
    pub fn ipv6_bind(&mut self, grant: Grant) -> Result<Endpoint, Error> {
        let config = self.ipv6_datagrams.config.ok_or(Error::Denied)?;
        if grant.local_port < 1024
            || grant.peer.port == 0
            || grant.peer.scope != config.scope
            || !usable_address(grant.peer.ip)
            || grant.peer.ip == config.address
            || (!same_prefix(config.address, grant.peer.ip, config.prefix_len)
                && !self
                    .port
                    .ipv6_route
                    .as_ref()
                    .is_some_and(|route| route.route.peer == grant.peer))
        {
            return Err(Error::Denied);
        }
        self.ipv6_live()?;
        if self
            .ipv6_datagrams
            .entries
            .iter()
            .any(|entry| entry.socket.is_some() && entry.grant.local_port == grant.local_port)
        {
            return Err(Error::InUse);
        }
        let vacant = self
            .ipv6_datagrams
            .entries
            .iter()
            .position(|entry| entry.socket.is_none());
        if vacant.is_none() && self.ipv6_datagrams.entries.len() >= MAX_ENDPOINTS {
            return Err(Error::Exhausted);
        }
        let epoch = self.ipv6_datagrams.next_epoch;
        self.ipv6_datagrams.next_epoch = epoch.checked_add(1).ok_or(Error::Exhausted)?;
        let buffer = || {
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; QUEUE_PACKETS],
                vec![0; MAX_DATAGRAM * QUEUE_PACKETS],
            )
        };
        let mut socket = udp::Socket::new(buffer(), buffer());
        socket
            .bind((Ipv6Address::from(config.address), grant.local_port))
            .map_err(|_| Error::Invalid)?;
        let entry = Entry {
            socket: Some(self.sockets.add(socket)),
            grant,
            epoch,
        };
        let slot = if let Some(slot) = vacant {
            self.ipv6_datagrams.entries[slot] = entry;
            slot
        } else {
            self.ipv6_datagrams.entries.push(entry);
            self.ipv6_datagrams.entries.len() - 1
        };
        self.port.ipv6_peers[slot] = Some(grant.peer.ip);
        if let Some(route) = &mut self.port.ipv6_route {
            route.bound(slot, grant);
        }
        self.port
            .ipv6_feedback
            .bind(slot, epoch, config.address, grant.local_port, grant.peer);
        Ok(Endpoint {
            instance: self.ipv6_datagrams.instance,
            slot,
            epoch,
        })
    }

    fn ipv6_live(&mut self) -> Result<(), Error> {
        let now = self.port.link.now_ms();
        let rewind = self.ipv6_datagrams.last_ms.is_some_and(|last| now < last);
        self.ipv6_datagrams.last_ms = Some(now);
        let result = if rewind {
            Err(Error::Stale)
        } else {
            match self.read_link() {
                None => Err(Error::LinkUnknown),
                Some(reading) if reading.disabled => Err(Error::DeviceFailed),
                Some(reading) if !reading.link_up => Err(Error::LinkDown),
                Some(_) => Ok(()),
            }
        };
        if result.is_err() {
            self.ipv6_fence();
            self.datagram_fence();
            self.stream_fence();
        }
        result
    }

    pub(super) fn ipv6_maintain(&mut self) {
        if self.ipv6_datagrams.active() || self.ipv6_streams.active() {
            let _ = self.ipv6_live();
        }
    }

    /// Success means queued locally, never delivery. The fixed 1232-byte
    /// data ceiling keeps an ordinary IPv6/UDP packet at 1280 bytes; this
    /// does not implement routed PMTU or ICMPv6 Packet Too Big advice.
    pub fn ipv6_send(
        &mut self,
        endpoint: Endpoint,
        peer: Address,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let entry = self.ipv6_datagrams.entry(endpoint)?;
        if peer != entry.grant.peer {
            return Err(Error::Denied);
        }
        if bytes.len() > MAX_DATAGRAM {
            return Err(Error::Oversize);
        }
        let handle = entry.socket.unwrap();
        self.ipv6_live()?;
        self.sockets
            .get_mut::<udp::Socket>(handle)
            .send_slice(bytes, peer.wire())
            .map_err(|error| match error {
                udp::SendError::BufferFull => Error::Exhausted,
                udp::SendError::Unaddressable => Error::Invalid,
            })
    }

    /// Unauthorized source tuples are discarded with bounded work. TooSmall
    /// preserves the complete datagram for a later, sufficiently large read.
    pub fn ipv6_receive(
        &mut self,
        endpoint: Endpoint,
        bytes: &mut [u8],
    ) -> Result<(usize, Address), Error> {
        let entry = self.ipv6_datagrams.entry(endpoint)?;
        let handle = entry.socket.unwrap();
        let peer = entry.grant.peer;
        self.ipv6_live()?;
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

    fn ipv6_feedback_stamp(&mut self, endpoint: Endpoint) -> Result<feedback::Stamp, Error> {
        self.ipv6_datagrams.entry(endpoint)?;
        self.ipv6_live()?;
        let generation = self
            .port
            .ipv6_feedback
            .generation()
            .ok_or(Error::Exhausted)?;
        Ok(feedback::Stamp {
            endpoint,
            generation,
        })
    }
    fn ipv6_feedback_valid(&mut self, stamp: feedback::Stamp) -> bool {
        self.ipv6_datagrams.entry(stamp.endpoint).is_ok()
            && self.ipv6_live().is_ok()
            && self.port.ipv6_feedback.generation() == Some(stamp.generation)
    }

    /// One unauthenticated diagnostic about a recently submitted complete
    /// packet; no route/MTU/retry authority. The endpoint selects the slot.
    pub fn ipv6_feedback(
        &mut self,
        endpoint: Endpoint,
    ) -> Result<Option<feedback::Observation>, Error> {
        self.ipv6_datagrams.entry(endpoint)?;
        self.ipv6_live()?;
        if self.port.ipv6_feedback.generation().is_none() {
            return Err(Error::Exhausted);
        }
        Ok(self
            .port
            .ipv6_feedback
            .take(endpoint.slot, endpoint.epoch, self.port.link.now_ms()))
    }

    pub fn ipv6_close(&mut self, endpoint: Endpoint) -> Result<(), Error> {
        let handle = self.ipv6_datagrams.entry(endpoint)?.socket.unwrap();
        self.sockets.remove(handle);
        self.ipv6_datagrams.entries[endpoint.slot].socket = None;
        self.port.ipv6_peers[endpoint.slot] = None;
        if let Some(route) = &mut self.port.ipv6_route {
            route.ports[endpoint.slot] = None;
        }
        self.port.ipv6_feedback.revoke(endpoint.slot);
        Ok(())
    }

    /// Discard queued traffic and revoke every reference. The configured
    /// logical address/link may remain, but authority is never rebound:
    /// recovery needs fresh owner-issued grants with fresh epochs. Neighbor
    /// cache and timers are engine state, not exported replacement state;
    /// a successor reconstructs them and validates outside this generation.
    /// Already emitted packets cannot be recalled or rolled back.
    pub fn ipv6_fence(&mut self) {
        self.ipv6_stream_fence();
        if let Some(echo) = self.port.ipv6_echo.take() {
            echo.borrow_mut().retire();
        }
        if let Some(responder) = self.port.ipv6_responder.take() {
            responder.borrow_mut().retire();
        }
        self.port.ipv6_peers.fill(None);
        if let Some(route) = &mut self.port.ipv6_route {
            route.ports.fill(None);
        }
        self.port.ipv6_feedback.fence();
        for entry in &mut self.ipv6_datagrams.entries {
            if let Some(handle) = entry.socket.take() {
                self.sockets.remove(handle);
            }
        }
    }
}

#[cfg(test)]
mod tests;
