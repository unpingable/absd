//! Experimental, explicit-grant TCP fragmentation-needed refusal.
//! No MSS mutation, recovery, retransmission, route cache or peer authentication.
use super::{Address, MAX_ENDPOINTS};
use smoltcp::wire::{Ipv4Packet, TcpPacket};
pub const VERSION: u8 = 4;
pub const STATUS: u8 = 17;
pub const RECENT_MS: u64 = 1000;
pub const HISTORY: usize = 4;
pub const MIN_MTU: u16 = 576;
#[derive(Clone, Copy)]
struct Submitted {
    key: [u8; 22],
    at: u64,
}
struct Flow {
    epoch: u64,
    local: [u8; 4],
    mask: u32,
    port: u16,
    peer: Address,
    expires: u64,
    recent: [Option<Submitted>; HISTORY],
    next: usize,
    pending: Option<u16>,
    stopped: bool,
    clock_failed: bool,
}
pub(crate) struct Feedback {
    flows: [Option<Flow>; MAX_ENDPOINTS],
    last: u64,
    mac: [u8; 6],
}
impl Feedback {
    pub(crate) fn new(mac: [u8; 6]) -> Self {
        Self {
            flows: core::array::from_fn(|_| None),
            last: 0,
            mac,
        }
    }
    pub(crate) fn active(&self) -> bool {
        self.flows.iter().any(Option::is_some)
    }
    pub(crate) fn bind(
        &mut self,
        slot: usize,
        epoch: u64,
        local: [u8; 4],
        prefix: u8,
        port: u16,
        peer: Address,
        expires: u64,
        now: u64,
    ) {
        self.clock(now);
        self.flows[slot] = Some(Flow {
            epoch,
            local,
            mask: u32::MAX << (32 - prefix),
            port,
            peer,
            expires,
            recent: [None; HISTORY],
            next: 0,
            pending: None,
            stopped: false,
            clock_failed: false,
        });
    }
    pub(crate) fn revoke(&mut self, slot: usize) {
        self.flows[slot] = None;
    }
    pub(crate) fn fence(&mut self) {
        self.flows.fill_with(|| None);
    }
    fn clock(&mut self, now: u64) {
        for flow in self.flows.iter_mut().flatten() {
            if now < self.last {
                flow.clock_failed = true;
            }
            if now < self.last || now >= flow.expires {
                flow.recent.fill(None);
                flow.pending = None;
                flow.stopped = true;
            }
        }
        self.last = now;
    }
    pub(crate) fn clock_fault(&mut self, slot: usize, epoch: u64, now: u64) -> bool {
        if !self.active() {
            return false;
        }
        self.clock(now);
        self.flows[slot]
            .as_ref()
            .is_some_and(|f| f.epoch == epoch && f.clock_failed)
    }
    pub(crate) fn fault(&mut self, slot: usize, epoch: u64, now: u64) -> Option<u16> {
        if !self.active() {
            return None;
        }
        self.clock(now);
        self.flows[slot]
            .as_ref()
            .filter(|f| f.epoch == epoch)?
            .pending
    }
    /// Called only after successful Link::send of the actual full TCP frame.
    pub(crate) fn submitted(&mut self, frame: &[u8], now: u64) {
        if !self.active() {
            return;
        }
        self.clock(now);
        if frame.len() < 54 || frame[12..14] != [8, 0] || frame[14] != 0x45 || frame[23] != 6 {
            return;
        }
        let Ok(ip) = Ipv4Packet::new_checked(&frame[14..]) else {
            return;
        };
        if !ip.verify_checksum() || word(&frame[14..], 6) != 0x4000 {
            return;
        }
        let total = usize::from(ip.total_len());
        if total < 40 || frame.len() != 14 + total {
            return;
        }
        let Ok(tcp) = TcpPacket::new_checked(ip.payload()) else {
            return;
        };
        if !tcp.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into())
            || tcp.options_summary().is_err()
        {
            return;
        }
        for flow in self.flows.iter_mut().flatten() {
            if !flow.stopped
                && flow.pending.is_none()
                && ip.src_addr().octets() == flow.local
                && ip.dst_addr().octets() == flow.peer.ip
                && tcp.src_port() == flow.port
                && tcp.dst_port() == flow.peer.port
            {
                flow.recent[flow.next] = Some(Submitted {
                    key: key(&frame[14..14 + total]),
                    at: now,
                });
                flow.next = (flow.next + 1) % HISTORY;
                break;
            }
        }
    }
    /// Latch evidence only. Never remove a socket during Interface receive.
    pub(crate) fn received(&mut self, frame: &[u8], now: u64) {
        if !self.active() {
            return;
        }
        self.clock(now);
        let Some(ip) = crate::icmp::ethernet_ipv4(frame) else {
            return;
        };
        if frame[..6] != self.mac
            || frame[6] & 1 != 0
            || frame[6..12] == [0; 6]
            || ip[9] != 1
            || !unicast(&ip[12..16])
        {
            return;
        }
        let icmp = &ip[usize::from(ip[0] & 15) * 4..];
        if icmp.len() < 36
            || icmp[..2] != [3, 4]
            || icmp[4..6] != [0, 0]
            || smoltcp::wire::Icmpv4Packet::new_checked(icmp).is_err()
            || !smoltcp::wire::Icmpv4Packet::new_unchecked(icmp).verify_checksum()
        {
            return;
        }
        let quote = &icmp[8..];
        let mtu = word(icmp, 6);
        if quote[0] != 0x45
            || quote[9] != 6
            || word(quote, 2) < 40
            || word(quote, 6) != 0x4000
            || quote.len() > usize::from(word(quote, 2))
            || !Ipv4Packet::new_unchecked(quote).verify_checksum()
            || mtu < MIN_MTU
            || mtu >= word(quote, 2)
        {
            return;
        }
        let quoted_key = key(quote);
        for flow in self.flows.iter_mut().flatten() {
            if flow.stopped || flow.pending.is_some() || ip[16..20] != flow.local {
                continue;
            }
            let source = u32::from_be_bytes(ip[12..16].try_into().unwrap());
            let local = u32::from_be_bytes(flow.local);
            let subnet = local & flow.mask;
            if source == local || source == subnet || source == (subnet | !flow.mask) {
                continue;
            }
            let Some(index) = flow.recent.iter().position(|r| {
                r.is_some_and(|r| {
                    r.key == quoted_key && now.checked_sub(r.at).is_some_and(|age| age <= RECENT_MS)
                })
            }) else {
                continue;
            };
            flow.recent[index] = None;
            flow.pending = Some(mtu);
            flow.stopped = true;
            break;
        }
    }
    /// Pending refusal prevents this flow's next same-poll egress before
    /// maintenance can remove its socket. Other flows/default SSH are inert.
    pub(crate) fn egress(&mut self, frame: &[u8], now: u64) -> bool {
        if !self.active() {
            return true;
        }
        self.clock(now);
        if frame.len() < 54 || frame[12..14] != [8, 0] || frame[14] != 0x45 || frame[23] != 6 {
            return true;
        }
        self.flows
            .iter()
            .flatten()
            .find(|f| {
                frame[26..30] == f.local
                    && frame[30..34] == f.peer.ip
                    && word(frame, 34) == f.port
                    && word(frame, 36) == f.peer.port
            })
            .is_none_or(|f| !f.stopped)
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
