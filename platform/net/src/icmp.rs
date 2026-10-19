//! Read-only ICMPv4 feedback for current native UDP grants.
//!
//! This is advisory correlation, not authenticated provenance. The engine
//! still implements IPv4, UDP and echo. No ICMP transmission or route change
//! is exposed to a client. See docs/NATIVE-ICMP.md for the restricted scope.
use crate::datagram::{Address, MAX_DATAGRAM, MAX_ENDPOINTS};
use smoltcp::wire::{Icmpv4Packet, IpProtocol, Ipv4Packet};

/// A quote must name one of the last four successful NIC submissions for
/// this grant and arrive within this bound. NIC success is not wire delivery.
pub const RECENT_MS: u64 = 1000;
/// Deliberate native UDP policy, not an IPv4 minimum-MTU conformance claim.
/// Smaller advice is ignored so one report cannot exclude classic DNS data.
pub const MIN_MTU: u16 = 576;
/// Advice can lower admission for one bounded episode, without refreshing
/// this deadline when another quote arrives during the same episode.
pub const CEILING_MS: u64 = 10_000;
const HISTORY: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    DestinationUnreachable {
        code: u8,
    },
    TimeExceeded {
        code: u8,
    },
    /// Zero means an older router supplied no next-hop MTU. Accepted
    /// nonzero advice lowers this grant's UDP admission for CEILING_MS.
    FragmentationNeeded {
        mtu: u16,
    },
}

#[derive(Clone, Copy)]
struct Submitted {
    // Total length, identification, flags/offset, addresses, UDP header.
    // TTL, TOS and the IPv4 checksum may change in transit.
    key: [u8; 22],
    at: u64,
}

struct Flow {
    local: [u8; 4],
    mask: u32,
    port: u16,
    peer: Address,
    epoch: u64,
    recent: [Option<Submitted>; HISTORY],
    next: usize,
    pending: Option<(Error, u64)>,
    maximum: usize,
    ceiling_until: Option<u64>,
}

/// The NIC holder registers a slot only when it constructs a native grant.
/// A slot is reset at every grant generation, revoke and link fence.
pub(super) struct Feedback {
    flows: [Option<Flow>; MAX_ENDPOINTS],
    last_ms: u64,
    mac: [u8; 6],
}

impl Feedback {
    pub(super) fn new(mac: [u8; 6]) -> Self {
        Self {
            flows: core::array::from_fn(|_| None),
            last_ms: 0,
            mac,
        }
    }

    pub(super) fn active(&self) -> bool {
        self.flows.iter().any(Option::is_some)
    }

    pub(super) fn bind(
        &mut self,
        slot: usize,
        epoch: u64,
        local: [u8; 4],
        prefix_len: u8,
        port: u16,
        peer: Address,
    ) {
        self.flows[slot] = Some(Flow {
            local,
            mask: u32::MAX << (32 - prefix_len),
            port,
            peer,
            epoch,
            recent: [None; HISTORY],
            next: 0,
            pending: None,
            maximum: MAX_DATAGRAM,
            ceiling_until: None,
        });
    }

    pub(super) fn revoke(&mut self, slot: usize) {
        self.flows[slot] = None;
    }
    pub(super) fn fence(&mut self) {
        self.flows.fill_with(|| None);
    }

    pub(super) fn maximum(&mut self, slot: usize, epoch: u64, now: u64) -> usize {
        self.clock(now);
        self.flows[slot]
            .as_ref()
            .filter(|f| f.epoch == epoch)
            .map_or(MAX_DATAGRAM, |f| f.maximum)
    }

    pub(super) fn take(&mut self, slot: usize, epoch: u64, now: u64) -> Option<Error> {
        self.clock(now);
        let (error, at) = self.flows[slot]
            .as_mut()
            .filter(|f| f.epoch == epoch)?
            .pending
            .take()?;
        now.checked_sub(at)
            .filter(|age| *age <= RECENT_MS)
            .map(|_| error)
    }

    fn clock(&mut self, now: u64) {
        for flow in self.flows.iter_mut().flatten() {
            if now < self.last_ms {
                flow.recent.fill(None);
                flow.pending = None;
            }
            if now < self.last_ms || flow.ceiling_until.is_some_and(|until| now >= until) {
                flow.maximum = MAX_DATAGRAM;
                flow.ceiling_until = None;
            }
        }
        self.last_ms = now;
    }

    /// Called only after Link::send returned Ok, never on local enqueue.
    pub(super) fn submitted(&mut self, frame: &[u8], now: u64) {
        if !self.active() {
            return;
        }
        self.clock(now);
        let Some(ip) = ethernet_ipv4(frame) else {
            return;
        };
        // The pinned engine emits no options and sets DF. Retaining only
        // this form makes the later minimum-quote comparison unambiguous.
        if ip.len() < 28 || ip[0] != 0x45 || ip[9] != 17 || word(ip, 6) != 0x4000 {
            return;
        }
        let udp = &ip[20..];
        if word(udp, 4) as usize != ip.len() - 20 {
            return;
        }
        for flow in self.flows.iter_mut().flatten() {
            if ip[12..16] == flow.local
                && ip[16..20] == flow.peer.ip
                && word(udp, 0) == flow.port
                && word(udp, 2) == flow.peer.port
            {
                flow.recent[flow.next] = Some(Submitted {
                    key: key(ip),
                    at: now,
                });
                flow.next = (flow.next + 1) % HISTORY;
                break;
            }
        }
    }

    /// Observe without consuming or changing the frame passed to smoltcp.
    pub(super) fn received(&mut self, frame: &[u8], now: u64) {
        if !self.active() {
            return;
        }
        self.clock(now);
        let Some(ip) = ethernet_ipv4(frame) else {
            return;
        };
        if frame[..6] != self.mac || frame[6] & 1 != 0 || frame[6..12] == [0; 6] {
            return;
        }
        if ip[9] != 1 || !unicast(&ip[12..16]) {
            return;
        }
        let header = (ip[0] as usize & 15) * 4;
        let icmp = &ip[header..];
        let Ok(packet) = Icmpv4Packet::new_checked(icmp) else {
            return;
        };
        if !packet.verify_checksum() || icmp.len() < 36 {
            return;
        }
        let error = match (icmp[0], icmp[1]) {
            (3, 4) => Error::FragmentationNeeded { mtu: word(icmp, 6) },
            (3, code @ 0..=15) => Error::DestinationUnreachable { code },
            (11, code @ 0..=1) => Error::TimeExceeded { code },
            _ => return,
        };
        let quoted = &icmp[8..];
        // A minimum quote does not contain the complete original packet.
        // Do not run Ipv4Packet::new_checked, which requires total_len
        // bytes. All indexed bytes are bounded first; checksum validation
        // uses the engine's header-only accessor after the explicit checks.
        if quoted[0] != 0x45
            || quoted[9] != 17
            || word(quoted, 2) < 28
            || word(quoted, 6) != 0x4000
            || !Ipv4Packet::new_unchecked(quoted).verify_checksum()
            || word(quoted, 24) != word(quoted, 2) - 20
        {
            return;
        }
        let quoted_key = key(quoted);
        for flow in self.flows.iter_mut().flatten() {
            if ip[16..20] != flow.local {
                continue;
            }
            let source = u32::from_be_bytes(ip[12..16].try_into().unwrap());
            let local = u32::from_be_bytes(flow.local);
            let subnet = local & flow.mask;
            if source == local || source == subnet || source == (subnet | !flow.mask) {
                continue;
            }
            let Some(index) = flow.recent.iter().position(|record| {
                record.is_some_and(|r| {
                    now.checked_sub(r.at).is_some_and(|age| age <= RECENT_MS) && r.key == quoted_key
                })
            }) else {
                continue;
            };
            if let Error::FragmentationNeeded { mtu } = error {
                // Ignore small/invalid advice. An existing episode never
                // extends, and an unrepresentable deadline cannot lower it.
                // No route-wide cache, probing, fragmentation or TCP change.
                if mtu != 0 {
                    if mtu < MIN_MTU || mtu >= word(quoted, 2) {
                        return;
                    }
                    if flow.ceiling_until.is_none() {
                        let Some(until) = now.checked_add(CEILING_MS) else {
                            return;
                        };
                        flow.ceiling_until = Some(until);
                    }
                    flow.maximum = flow.maximum.min(mtu as usize - 28);
                }
            }
            flow.recent[index] = None;
            if flow
                .pending
                .is_none_or(|(_, at)| now.checked_sub(at).is_none_or(|age| age > RECENT_MS))
            {
                flow.pending = Some((error, now));
            }
            break;
        }
    }
}

fn word(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

fn key(ip: &[u8]) -> [u8; 22] {
    let mut result = [0; 22];
    result[..6].copy_from_slice(&ip[2..8]);
    result[6..14].copy_from_slice(&ip[12..20]);
    result[14..].copy_from_slice(&ip[20..28]);
    result
}

fn unicast(ip: &[u8]) -> bool {
    ip[0] != 0 && ip[0] != 127 && ip[0] < 224
}

fn ethernet_ipv4(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 34 || frame[12..14] != [8, 0] {
        return None;
    }
    let bytes = &frame[14..];
    let header = (bytes[0] as usize & 15) * 4;
    if header < 20 || header > word(bytes, 2) as usize {
        return None;
    }
    let packet = Ipv4Packet::new_checked(bytes).ok()?;
    if packet.version() != 4
        || !packet.verify_checksum()
        || packet.more_frags()
        || packet.frag_offset() != 0
        || word(bytes, 6) & 0x8000 != 0
        || !matches!(packet.next_header(), IpProtocol::Icmp | IpProtocol::Udp)
    {
        return None;
    }
    Some(&bytes[..packet.total_len() as usize])
}
