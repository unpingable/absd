//! One opt-in direct-server DHCP lease, followed by bounded delegated DNS.
//! The leased Stack is private. Static Stack::open and SSH are unchanged.
//! RFC 2131/2132 supply DHCP; RFC 5227 supplies the bounded ARP probe shape.
//! No renew/rebind, remembered lease, relay, or address replacement is offered.
use super::*;
use alloc::rc::Rc;
use core::cell::RefCell;
use datagram::channel::{Channel, Pipe};
use smoltcp::socket::dhcpv4;
use smoltcp::wire::{DhcpPacket, DhcpRepr};

pub const ACQUIRE_MS: u64 = 20_000;
pub const ACTIVE_MS: u64 = 8_000;
pub const DNS_LOCAL_PORT: u16 = 7204;
const REFUSED: i64 = -125;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Denied,
    Malformed,
    Clock,
    Timeout,
    Link,
    Conflict,
    Nak,
    Retired,
    Engine,
}

/// Trusted construction selects this controlled, direct-server fixture.
/// Fields are private: DHCP bytes cannot change the authorization rule.
#[derive(Clone, Copy)]
pub struct Policy {
    server: [u8; 4],
    server_mac: [u8; 6],
    address: [u8; 4],
    mask: [u8; 4],
    prefix: u8,
}
impl Policy {
    pub const fn fixture() -> Self {
        Self {
            server: [192, 0, 2, 1],
            server_mac: [0x52, 0x55, 0, 0, 3, 1],
            address: [192, 0, 2, 100],
            mask: [255, 255, 255, 0],
            prefix: 24,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub address: [u8; 4],
    pub resolver: [u8; 4],
    pub xid: u32,
    /// Conservative origin: first successful selecting REQUEST submission.
    pub request_ms: u64,
    pub renew_ms: u64,
    pub rebind_ms: u64,
    pub expires_ms: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Selecting,
    Requesting,
    Candidate,
    Active,
    Retired,
}
struct Guard {
    policy: Policy,
    mac: [u8; 6],
    phase: Phase,
    xid: Option<u32>,
    offer: Option<[u8; 4]>,
    request_ms: Option<u64>,
    lease: Option<Lease>,
    last_ms: u64,
    deadline: u64,
    error: Option<Error>,
    refused: u64,
}
impl Guard {
    fn new(policy: Policy, mac: [u8; 6], now: u64) -> Result<Self, Error> {
        if now
            .checked_add(ACQUIRE_MS + 3_600_000)
            .is_none_or(|n| n > i64::MAX as u64)
        {
            return Err(Error::Clock);
        }
        Ok(Self {
            policy,
            mac,
            phase: Phase::Selecting,
            xid: None,
            offer: None,
            request_ms: None,
            lease: None,
            last_ms: now,
            deadline: now.checked_add(ACQUIRE_MS).ok_or(Error::Clock)?,
            error: None,
            refused: 0,
        })
    }
    fn retire(&mut self, error: Error) -> Error {
        self.error.get_or_insert(error);
        self.phase = Phase::Retired;
        self.error.unwrap()
    }
    fn check(&mut self, now: u64, link: Option<LinkReading>) -> Result<(), Error> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let error = if now < self.last_ms {
            Some(Error::Clock)
        } else if now >= self.deadline
            || self
                .lease
                .is_some_and(|l| now >= l.renew_ms || now >= l.expires_ms)
        {
            Some(Error::Timeout)
        } else if link.is_none_or(|r| !r.link_up || r.disabled) {
            Some(Error::Link)
        } else {
            None
        };
        self.last_ms = now;
        match error {
            Some(error) => Err(self.retire(error)),
            None => Ok(()),
        }
    }
    fn outgoing(&mut self, message: Message, now: u64) -> Result<(), Error> {
        if self.phase == Phase::Selecting && message.kind == 1 {
            self.xid = Some(message.xid);
            self.offer = None;
            self.request_ms = None;
            return Ok(());
        }
        if self.phase == Phase::Requesting
            && message.kind == 3
            && Some(message.xid) == self.xid
            && message.requested == self.offer
            && message.server == Some(self.policy.server)
        {
            self.request_ms.get_or_insert(now);
            return Ok(());
        }
        Err(self.retire(Error::Denied))
    }
    fn incoming(&mut self, message: Message) -> bool {
        if Some(message.xid) != self.xid || message.server != Some(self.policy.server) {
            self.refused += 1;
            return false;
        }
        if message.kind == 6 && self.request_ms.is_some() {
            self.retire(Error::Nak);
            return false;
        }
        if self.phase == Phase::Selecting
            && message.kind == 2
            && message.address == self.policy.address
        {
            self.offer = Some(message.address);
            self.phase = Phase::Requesting;
            return true;
        }
        if self.phase == Phase::Requesting && message.kind == 5 {
            if let Ok(lease) = message.lease(self) {
                self.lease = Some(lease);
                self.phase = Phase::Candidate;
                return true;
            }
        }
        // Duplicate ACKs, including unchanged renewals, never refresh timers.
        self.refused += 1;
        false
    }
    fn arp(&mut self, frame: &[u8]) {
        if self.lease.is_none()
            || frame.len() < 42
            || frame[12..14] != [8, 6]
            || frame[14..20] != [0, 1, 8, 0, 6, 4]
            || !matches!(u16::from_be_bytes([frame[20], frame[21]]), 1 | 2)
            || frame[6..12] != frame[22..28]
            || frame[22..28] == self.mac
        {
            return;
        }
        if frame[28..32] == self.policy.address
            || (frame[28..32] == [0; 4] && frame[38..42] == self.policy.address)
        {
            self.retire(Error::Conflict);
        }
    }
}

#[derive(Clone, Copy)]
struct Message {
    kind: u8,
    xid: u32,
    address: [u8; 4],
    server: Option<[u8; 4]>,
    requested: Option<[u8; 4]>,
    mask: Option<[u8; 4]>,
    router: Option<[u8; 4]>,
    dns: Option<[u8; 4]>,
    lease: Option<u32>,
    renew: Option<u32>,
    rebind: Option<u32>,
}
impl Message {
    fn lease(self, guard: &Guard) -> Result<Lease, Error> {
        let p = guard.policy;
        if Some(self.address) != guard.offer
            || self.mask != Some(p.mask)
            || self.router != Some(p.server)
            || self.dns != Some(p.server)
        {
            return Err(Error::Denied);
        }
        let seconds = self
            .lease
            .filter(|s| (60..=3600).contains(s))
            .ok_or(Error::Denied)? as u64;
        let t1 = self.renew.map(u64::from).unwrap_or(seconds / 2);
        let t2 = self.rebind.map(u64::from).unwrap_or(seconds * 7 / 8);
        if t1 == 0 || t1 >= t2 || t2 >= seconds {
            return Err(Error::Denied);
        }
        let request = guard.request_ms.ok_or(Error::Denied)?;
        let stamp = |seconds: u64| request.checked_add(seconds * 1000).ok_or(Error::Clock);
        Ok(Lease {
            address: p.address,
            resolver: p.server,
            xid: self.xid,
            request_ms: request,
            renew_ms: stamp(t1)?,
            rebind_ms: stamp(t2)?,
            expires_ms: stamp(seconds)?,
        })
    }
}

fn word(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}
fn sum(bytes: &[u8]) -> u32 {
    bytes
        .chunks(2)
        .map(|s| u16::from_be_bytes([s[0], *s.get(1).unwrap_or(&0)]) as u32)
        .sum()
}
fn valid_sum(mut sum: u32) -> bool {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum == 0xffff
}
fn dhcp_traffic(frame: &[u8]) -> bool {
    if frame.len() < 34 || frame[12..14] != [8, 0] || frame[23] != 17 {
        return false;
    }
    let at = 14 + usize::from(frame[14] & 15) * 4;
    frame.len() >= at + 4
        && (matches!(word(frame, at), 67 | 68) || matches!(word(frame, at + 2), 67 | 68))
}

/// Strict profile framing precedes smoltcp's more permissive option iterator.
fn message(frame: &[u8], inbound: bool, p: Policy, mac: [u8; 6]) -> Result<Message, Error> {
    if frame.len() < 282
        || frame.len() > FRAME_MAX
        || frame[12..14] != [8, 0]
        || frame[14] != 0x45
        || frame[23] != 17
        || word(frame, 20) & 0x3fff != 0
        || usize::from(word(frame, 16)) + 14 != frame.len()
        || !valid_sum(sum(&frame[14..34]))
    {
        return Err(Error::Malformed);
    }
    let ip = &frame[14..];
    let udp = &frame[34..];
    if usize::from(word(udp, 4)) != udp.len() || udp.len() < 248 {
        return Err(Error::Malformed);
    }
    if word(udp, 6) != 0 && !valid_sum(sum(&ip[12..20]) + 17 + udp.len() as u32 + sum(udp)) {
        return Err(Error::Malformed);
    }
    let packet = &udp[8..];
    if packet[1..4] != [1, 6, 0]
        || packet[24..28] != [0; 4]
        || word(packet, 10) & 0x7fff != 0
        || packet[28..34] != mac
        || packet[12..16] != [0; 4]
    {
        return Err(Error::Denied);
    }
    if inbound {
        if frame[6..12] != p.server_mac
            || (frame[..6] != mac && frame[..6] != [255; 6])
            || ip[12..16] != p.server
            || (ip[16..20] != [255; 4] && ip[16..20] != p.address)
            || word(udp, 0) != 67
            || word(udp, 2) != 68
            || packet[0] != 2
        {
            return Err(Error::Denied);
        }
    } else if frame[6..12] != mac
        || frame[..6] != [255; 6]
        || ip[12..16] != [0; 4]
        || ip[16..20] != [255; 4]
        || word(udp, 0) != 68
        || word(udp, 2) != 67
        || packet[0] != 1
    {
        return Err(Error::Denied);
    }
    let mut seen = [false; 256];
    let mut at = 240;
    let mut ended = false;
    while at < packet.len() {
        let kind = packet[at] as usize;
        at += 1;
        if kind == 0 {
            continue;
        }
        if kind == 255 {
            ended = true;
            break;
        }
        let length = *packet.get(at).ok_or(Error::Malformed)? as usize;
        at += 1;
        if seen[kind] || at + length > packet.len() || kind == 52 {
            return Err(Error::Malformed);
        }
        seen[kind] = true;
        let expected = match kind {
            53 => Some(1),
            1 | 3 | 6 | 50 | 51 | 54 | 58 | 59 => Some(4),
            _ => None,
        };
        if expected.is_some_and(|n| n != length) {
            return Err(Error::Malformed);
        }
        at += length;
    }
    if !ended || packet[at..].iter().any(|b| *b != 0) || !seen[53] {
        return Err(Error::Malformed);
    }
    let packet = DhcpPacket::new_checked(packet).map_err(|_| Error::Malformed)?;
    let repr = DhcpRepr::parse(&packet).map_err(|_| Error::Malformed)?;
    if repr.client_identifier.is_some_and(|id| id.0 != mac) {
        return Err(Error::Denied);
    }
    let kind = packet.options().find(|o| o.kind == 53).unwrap().data[0];
    if inbound && !matches!(kind, 2 | 5 | 6) {
        return Err(Error::Denied);
    }
    if inbound && kind == 6 && repr.your_ip.octets() != [0; 4] {
        return Err(Error::Malformed);
    }
    let dns = repr
        .dns_servers
        .as_ref()
        .and_then(|s| s.first())
        .map(|a| a.octets());
    Ok(Message {
        kind,
        xid: repr.transaction_id,
        address: repr.your_ip.octets(),
        server: repr.server_identifier.map(|a| a.octets()),
        requested: repr.requested_ip.map(|a| a.octets()),
        mask: repr.subnet_mask.map(|a| a.octets()),
        router: repr.router.map(|a| a.octets()),
        dns,
        lease: repr.lease_duration,
        renew: repr.renew_duration,
        rebind: repr.rebind_duration,
    })
}

struct Guarded<L: Link> {
    link: L,
    guard: Rc<RefCell<Guard>>,
}
impl<L: Link> Guarded<L> {
    fn check(&self) -> Result<(), Error> {
        self.guard
            .borrow_mut()
            .check(self.link.now_ms(), self.link.read())
    }
}
impl<L: Link> Link for Guarded<L> {
    fn mac(&self) -> [u8; 6] {
        self.link.mac()
    }
    fn now_ms(&self) -> u64 {
        self.link.now_ms()
    }
    fn read(&self) -> Option<LinkReading> {
        self.link.read()
    }
    fn pause(&self, ms: u64) {
        self.link.pause(ms);
    }
    fn send(&mut self, frame: &[u8]) -> Result<(), i64> {
        self.check().map_err(|_| REFUSED)?;
        let (p, mac, phase) = {
            let g = self.guard.borrow();
            (g.policy, g.mac, g.phase)
        };
        let outgoing = if dhcp_traffic(frame) {
            Some(message(frame, false, p, mac).map_err(|_| {
                self.guard.borrow_mut().retire(Error::Engine);
                REFUSED
            })?)
        } else {
            if phase != Phase::Active && (frame.len() < 42 || frame[12..14] != [8, 6]) {
                self.guard.borrow_mut().retire(Error::Engine);
                return Err(REFUSED);
            }
            None
        };
        // Validate transition before submitting; a refused Link send ends this invocation.
        if let Some(message) = outgoing {
            self.guard
                .borrow_mut()
                .outgoing(message, self.link.now_ms())
                .map_err(|_| REFUSED)?;
        }
        self.link.send(frame).map_err(|code| {
            self.guard.borrow_mut().retire(Error::Link);
            code
        })?;
        self.check().map_err(|_| REFUSED)
    }
    fn receive(
        &mut self,
        bytes: &mut [u8; FRAME_MAX],
        timeout_ms: u64,
    ) -> Result<Option<usize>, i64> {
        self.check().map_err(|_| REFUSED)?;
        let mut timeout = timeout_ms;
        for _ in 0..16 {
            let received = self.link.receive(bytes, timeout).map_err(|code| {
                self.guard.borrow_mut().retire(Error::Link);
                code
            })?;
            self.check().map_err(|_| REFUSED)?;
            let Some(length) = received else {
                return Ok(None);
            };
            if length > bytes.len() {
                self.guard.borrow_mut().retire(Error::Link);
                return Err(REFUSED);
            }
            let frame = &bytes[..length];
            let mut g = self.guard.borrow_mut();
            g.arp(frame);
            if g.error.is_some() {
                return Err(REFUSED);
            }
            if dhcp_traffic(frame) {
                let accepted = match message(frame, true, g.policy, g.mac) {
                    Ok(message) => g.incoming(message),
                    Err(_) => {
                        g.refused += 1;
                        false
                    }
                };
                if g.error.is_some() {
                    return Err(REFUSED);
                }
                if accepted {
                    return Ok(Some(length));
                }
            } else if g.phase == Phase::Active {
                return Ok(Some(length));
            }
            timeout = 0;
        }
        Ok(None)
    }
}

fn arp(mac: [u8; 6], address: [u8; 4], announce: bool) -> [u8; 42] {
    let mut frame = [0; 42];
    frame[..6].fill(255);
    frame[6..12].copy_from_slice(&mac);
    frame[12..22].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
    frame[22..28].copy_from_slice(&mac);
    if announce {
        frame[28..32].copy_from_slice(&address);
    }
    frame[38..42].copy_from_slice(&address);
    frame
}

fn decline(mac: [u8; 6], policy: Policy, lease: Lease) -> [u8; 298] {
    let mut frame = [0; 298];
    frame[..6].fill(255);
    frame[6..12].copy_from_slice(&mac);
    frame[12..14].copy_from_slice(&[8, 0]);
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&284u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 17;
    frame[30..34].fill(255);
    // Fold before complementing; the fixed IPv4 header can carry a sum > u16.
    let mut folded = sum(&frame[14..34]);
    while folded > 0xffff {
        folded = (folded & 0xffff) + (folded >> 16);
    }
    frame[24..26].copy_from_slice(&(!(folded as u16)).to_be_bytes());
    frame[34..36].copy_from_slice(&68u16.to_be_bytes());
    frame[36..38].copy_from_slice(&67u16.to_be_bytes());
    frame[38..40].copy_from_slice(&264u16.to_be_bytes());
    frame[42..46].copy_from_slice(&[1, 1, 6, 0]);
    frame[46..50].copy_from_slice(&lease.xid.to_be_bytes());
    frame[70..76].copy_from_slice(&mac);
    frame[278..282].copy_from_slice(&[99, 130, 83, 99]);
    frame[282..285].copy_from_slice(&[53, 1, 4]);
    frame[285..287].copy_from_slice(&[50, 4]);
    frame[287..291].copy_from_slice(&lease.address);
    frame[291..293].copy_from_slice(&[54, 4]);
    frame[293..297].copy_from_slice(&policy.server);
    frame[297] = 255;
    frame
}

/// Sole NIC owner for one lease and one fixed delegated DNS endpoint.
pub struct Owner<L: Link> {
    stack: Option<Stack<Guarded<L>>>,
    guard: Rc<RefCell<Guard>>,
    issued: bool,
}
impl<L: Link> Owner<L> {
    pub fn acquire(link: L, policy: Policy) -> Result<Self, Error> {
        let mac = link.mac();
        let now = link.now_ms();
        let guard = Rc::new(RefCell::new(Guard::new(policy, mac, now)?));
        let mut port = Port {
            link: Guarded {
                link,
                guard: guard.clone(),
            },
            frame_mtu: FRAME_MAX,
            rx: Box::new([0; FRAME_MAX]),
            rx_length: None,
            tx: Box::new([0; FRAME_MAX]),
            divert: None,
            raw: VecDeque::new(),
            stats: Stats::default(),
            // DHCP acquisition grants no inbound application listener.
            server_rules: [None; crate::stream::MAX_ENDPOINTS],
            feedback: icmp::Feedback::new(mac),
            ipv6_feedback: ipv6::feedback::Feedback::new(mac),
            // Acquisition has no IPv6 owner configuration or peer grants.
            ipv6_config: None,
            ipv6_route: None,
            ipv6_echo: None,
            ipv6_responder: None,
            ipv6_peers: [None; crate::ipv6::MAX_ENDPOINTS],
            ipv6_tcp_peers: [None; crate::ipv6::stream::MAX_ENDPOINTS],
        };
        port.link.check()?;
        let mut config = IfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        config.random_seed = seed(mac, now);
        let mut iface = Interface::new(config, &mut port, Instant::from_millis(now as i64));
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(dhcpv4::Socket::new());
        loop {
            port.link.check()?;
            iface.poll(
                Instant::from_millis(port.link.now_ms() as i64),
                &mut port,
                &mut sockets,
            );
            port.link.check()?;
            let event = sockets.get_mut::<dhcpv4::Socket>(handle).poll();
            if let Some(dhcpv4::Event::Configured(config)) = event {
                let lease = guard.borrow().lease.ok_or(Error::Engine)?;
                if config.address.address().octets() != lease.address
                    || config.address.prefix_len() != policy.prefix
                    || config.server.address.octets() != policy.server
                    || config.server.identifier.octets() != policy.server
                    || config.router.map(|a| a.octets()) != Some(policy.server)
                    || config.dns_servers.len() != 1
                    || config.dns_servers[0].octets() != lease.resolver
                {
                    return Err(Error::Engine);
                }
                break;
            }
            port.link.pause(1);
        }
        // No renewing socket survives activation. Its private timer state is never
        // used to extend this invocation; the independently checked bound is T1.
        drop(sockets);
        drop(iface);
        let lease = guard.borrow().lease.ok_or(Error::Engine)?;
        let mut next = port
            .link
            .now_ms()
            .checked_add(u64::from(lease.xid % 1001))
            .ok_or(Error::Clock)?;
        let probing = (|| {
            for index in 0..5 {
                while port.link.now_ms() < next {
                    port.link.check()?;
                    let _ = port.link.receive(&mut port.rx, 1);
                    port.link.check()?;
                    port.link.pause(1);
                }
                port.link
                    .send(&arp(mac, lease.address, index >= 3))
                    .map_err(|_| Error::Link)?;
                next = port
                    .link
                    .now_ms()
                    .checked_add(if index < 2 {
                        1000 + u64::from((lease.xid >> (index * 5)) % 1001)
                    } else {
                        2000
                    })
                    .ok_or(Error::Clock)?;
            }
            port.link.check()?;
            Ok(())
        })();
        if probing == Err(Error::Conflict) {
            // One tightly constructed protocol refusal is permitted after the
            // conflict fence. No application Stack or general send is exposed.
            let now = port.link.link.now_ms();
            let refusal_allowed = {
                let g = guard.borrow();
                now >= g.last_ms && now < g.deadline.min(lease.renew_ms).min(lease.expires_ms)
            };
            if refusal_allowed
                && port
                    .link
                    .link
                    .read()
                    .is_some_and(|r| r.link_up && !r.disabled)
            {
                let _ = port.link.link.send(&decline(mac, policy, lease));
            }
        }
        probing?;
        {
            let mut g = guard.borrow_mut();
            g.phase = Phase::Active;
            g.deadline = port
                .link
                .now_ms()
                .checked_add(ACTIVE_MS)
                .ok_or(Error::Clock)?
                .min(lease.renew_ms);
        }
        let config = Config {
            address: Ipv4Address::from(lease.address),
            prefix_len: policy.prefix,
            gateway: Some(Ipv4Address::from(policy.server)),
            rx_buffer: 1024,
            tx_buffer: 1024,
        };
        let stack = Stack::open(port.link, config).map_err(|_| Error::Engine)?;
        Ok(Self {
            stack: Some(stack),
            guard,
            issued: false,
        })
    }
    fn check(&mut self) -> Result<(), Error> {
        let result = self.stack.as_ref().ok_or(Error::Retired)?.link().check();
        if result.is_err() {
            self.stack.take();
        }
        result
    }
    pub fn lease(&self) -> Lease {
        self.guard.borrow().lease.unwrap()
    }
    pub fn stop_ms(&self) -> u64 {
        self.guard.borrow().deadline
    }
    pub fn refused_frames(&self) -> u64 {
        self.guard.borrow().refused
    }
    pub fn dns_channel(&mut self) -> Result<Channel, Error> {
        self.check()?;
        if self.issued {
            return Err(Error::Denied);
        }
        let grant = datagram::Grant {
            local_port: DNS_LOCAL_PORT,
            peer: datagram::Address {
                ip: self.lease().resolver,
                port: 53,
            },
        };
        let channel =
            Channel::grant(self.stack.as_mut().unwrap(), grant).map_err(|_| Error::Engine)?;
        self.issued = true;
        Ok(channel)
    }
    pub fn poll<P: Pipe>(&mut self, channel: &mut Channel, pipe: &mut P) -> Result<bool, Error> {
        self.check()?;
        self.stack.as_mut().unwrap().poll();
        self.check()?;
        let live = channel.poll(self.stack.as_mut().unwrap(), pipe);
        self.check()?;
        if !live {
            self.retire();
        }
        Ok(live)
    }
    pub fn wait(&mut self) -> Result<(), Error> {
        self.check()?;
        self.stack.as_mut().unwrap().wait(1);
        self.check()
    }
    pub fn retire(&mut self) {
        self.guard.borrow_mut().retire(Error::Retired);
        // Drops every socket/queue/classic closing entry and the Interface.
        // A Channel kept by a caller has no Stack or NIC with which to act.
        self.stack.take();
    }
}
impl<L: Link> Drop for Owner<L> {
    fn drop(&mut self) {
        self.retire();
    }
}

#[cfg(test)]
mod tests;
