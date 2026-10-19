//! Observed ICMPv6 errors about complete, recently submitted UDP packets.
//! No route, socket, address, retry or packet-construction authority follows.
use super::{Address, MAX_ENDPOINTS};
use alloc::vec::Vec;
use smoltcp::wire::{Icmpv6Packet, IpAddress, Ipv6Address, UdpPacket};

pub const RECENT_MS: u64 = 1000;
pub const HISTORY: usize = 4;
/// Complete invoking packet must fit the minimum-MTU error envelope.
pub const MAX_QUOTE: usize = 1232;
pub const WIRE_LEN: usize = 8;
pub const FEEDBACK: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub kind: u8,
    pub code: u8,
    /// Packet Too Big's untrusted 32-bit MTU; zero for other errors.
    pub detail: u32,
}
impl Observation {
    pub fn encode(self) -> [u8; WIRE_LEN] {
        let mut bytes = [self.kind, self.code, 0, 0, 0, 0, 0, 0];
        bytes[4..].copy_from_slice(&self.detail.to_be_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != WIRE_LEN || bytes[2..4] != [0, 0] {
            return None;
        }
        let result = Self {
            kind: bytes[0],
            code: bytes[1],
            detail: u32::from_be_bytes(bytes[4..8].try_into().ok()?),
        };
        match (result.kind, result.code, result.detail) {
            (1, 0..=6, 0) | (3, 0..=1, 0) | (2, 0, 1..=u32::MAX) => Some(result),
            _ => None,
        }
    }
}
/// Internal proof-framer stamp, not a transferable capability or wire token.
#[derive(Clone, Copy)]
pub(super) struct Stamp {
    pub(super) endpoint: super::Endpoint,
    pub(super) generation: u64,
}
struct Submitted {
    packet: Vec<u8>,
    peer_mac: [u8; 6],
    at: u64,
}
struct Flow {
    local: [u8; 16],
    port: u16,
    peer: Address,
    epoch: u64,
    recent: [Option<Submitted>; HISTORY],
    next: usize,
    pending: Option<(Observation, u64)>,
}
pub(crate) struct Feedback {
    mac: [u8; 6],
    flows: [Option<Flow>; MAX_ENDPOINTS],
    last: u64,
    fault_generation: Option<u64>,
}
impl Feedback {
    pub(crate) fn new(mac: [u8; 6]) -> Self {
        Self {
            mac,
            flows: core::array::from_fn(|_| None),
            last: 0,
            fault_generation: Some(1),
        }
    }
    pub(crate) fn bind(
        &mut self,
        slot: usize,
        epoch: u64,
        local: [u8; 16],
        port: u16,
        peer: Address,
    ) {
        self.flows[slot] = Some(Flow {
            local,
            port,
            peer,
            epoch,
            recent: core::array::from_fn(|_| None),
            next: 0,
            pending: None,
        });
    }
    pub(crate) fn revoke(&mut self, slot: usize) {
        self.flows[slot] = None;
    }
    pub(crate) fn fence(&mut self) {
        self.flows.fill_with(|| None);
    }
    /// A failed I/O can have an irreversible effect. It establishes no new
    /// successful-submission evidence and invalidates previous correlation.
    pub(crate) fn lost(&mut self) {
        self.fault_generation = self.fault_generation.and_then(|n| n.checked_add(1));
        for flow in self.flows.iter_mut().flatten() {
            flow.recent.fill_with(|| None);
            flow.pending = None;
        }
    }
    fn clock(&mut self, now: u64) {
        if now < self.last {
            self.lost();
        }
        self.last = now;
        for flow in self.flows.iter_mut().flatten() {
            for record in &mut flow.recent {
                if record
                    .as_ref()
                    .is_some_and(|r| now.checked_sub(r.at).is_none_or(|age| age > RECENT_MS))
                {
                    *record = None;
                }
            }
            if flow
                .pending
                .is_some_and(|(_, at)| now.checked_sub(at).is_none_or(|age| age > RECENT_MS))
            {
                flow.pending = None;
            }
        }
    }
    pub(crate) fn generation(&self) -> Option<u64> {
        self.fault_generation
    }
    pub(crate) fn take(&mut self, slot: usize, epoch: u64, now: u64) -> Option<Observation> {
        self.clock(now);
        self.fault_generation?;
        self.flows[slot]
            .as_mut()
            .filter(|f| f.epoch == epoch)?
            .pending
            .take()
            .map(|(o, _)| o)
    }
    /// Called only after Link::send returned Ok. That is local submission,
    /// not physical wire delivery, freshness or authenticated provenance.
    pub(crate) fn submitted(&mut self, frame: &[u8], now: u64) {
        if self.fault_generation.is_none() || !self.flows.iter().any(Option::is_some) {
            return;
        }
        self.clock(now);
        if self.fault_generation.is_none() {
            return;
        }
        let Some(ip) = ipv6(frame) else {
            return;
        };
        if ip[6] != 17
            || ip.len() < 48
            || ip.len() > MAX_QUOTE
            || frame[6..12] != self.mac
            || frame[0] & 1 != 0
            || frame[..6] == [0; 6]
        {
            return;
        }
        let udp = &ip[40..];
        if word(udp, 4) as usize != udp.len() || word(udp, 6) == 0 {
            return;
        }
        let source = IpAddress::Ipv6(Ipv6Address::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap()));
        let target = IpAddress::Ipv6(Ipv6Address::from(
            <[u8; 16]>::try_from(&ip[24..40]).unwrap(),
        ));
        let Ok(packet) = UdpPacket::new_checked(udp) else {
            return;
        };
        if !packet.verify_checksum(&source, &target) {
            return;
        }
        for flow in self.flows.iter_mut().flatten() {
            if ip[8..24] == flow.local
                && ip[24..40] == flow.peer.ip
                && word(udp, 0) == flow.port
                && word(udp, 2) == flow.peer.port
            {
                flow.recent[flow.next] = Some(Submitted {
                    packet: ip.to_vec(),
                    peer_mac: frame[..6].try_into().unwrap(),
                    at: now,
                });
                flow.next = (flow.next + 1) % HISTORY;
                break;
            }
        }
    }
    /// Observation happens before the narrower engine ingress refusal.
    /// Unsupported errors never reach the engine and cannot change ND/routes.
    pub(crate) fn received(&mut self, frame: &[u8], now: u64) {
        if self.fault_generation.is_none() || !self.flows.iter().any(Option::is_some) {
            return;
        }
        self.clock(now);
        if self.fault_generation.is_none() {
            return;
        }
        let Some(ip) = ipv6(frame) else {
            return;
        };
        if ip[6] != 58
            || ip.len() < 96
            || ip.len() > 1280
            || ip[7] == 0
            || frame[..6] != self.mac
            || frame[6] & 1 != 0
            || frame[6..12] == [0; 6]
        {
            return;
        }
        let payload = &ip[40..];
        let detail = u32::from_be_bytes(payload[4..8].try_into().unwrap());
        let observation = Observation {
            kind: payload[0],
            code: payload[1],
            detail,
        };
        if Observation::decode(&observation.encode()).is_none() {
            return;
        }
        let source = Ipv6Address::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap());
        let target = Ipv6Address::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap());
        let Ok(packet) = Icmpv6Packet::new_checked(payload) else {
            return;
        };
        if !packet.verify_checksum(&source, &target) {
            return;
        }
        let quote = &payload[8..];
        // Exact bytes include the complete UDP body and checksum, not just
        // ports or a normalized packet. Routed/hop-limit changes are refused.
        if quote.len() < 48
            || quote.len() > MAX_QUOTE
            || quote[0] >> 4 != 6
            || quote[6] != 17
            || quote.len() != 40 + word(quote, 4) as usize
        {
            return;
        }
        for flow in self.flows.iter_mut().flatten() {
            if ip[8..24] != flow.peer.ip || ip[24..40] != flow.local {
                continue;
            }
            if !flow
                .recent
                .iter()
                .flatten()
                .any(|r| r.packet == quote && r.peer_mac == frame[6..12])
            {
                continue;
            }
            // Identical retransmissions have no wire generation identity.
            // Consume every matching record so one quote cannot be repeated
            // against copies already submitted in this correlation window.
            for record in &mut flow.recent {
                if record.as_ref().is_some_and(|r| r.packet == quote) {
                    *record = None;
                }
            }
            // A matched terminal report supersedes unread advice. Otherwise
            // retain the first observation; correlation history stays spent.
            let terminal_over_advice = observation.kind == 1
                && flow
                    .pending
                    .as_ref()
                    .is_some_and(|(pending, _)| matches!(pending.kind, 2 | 3));
            if flow.pending.is_none() || terminal_over_advice {
                flow.pending = Some((observation, now));
            }
            break;
        }
    }
}
fn word(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}
fn ipv6(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 54 || frame[12..14] != [0x86, 0xdd] || frame[14] >> 4 != 6 {
        return None;
    }
    let end = 54 + word(frame, 18) as usize;
    if frame.len() != end || end > crate::FRAME_MAX {
        return None;
    }
    Some(&frame[14..end])
}
#[cfg(test)]
mod tests;
