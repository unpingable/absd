//! Opt-in, sole-Link-owner DAD for one bounded static DNS invocation.
//! Candidate configuration and the delegated channel remain private until
//! preflight succeeds. No traffic creates address or endpoint authority.
use super::*;
use alloc::rc::Rc;
use core::cell::RefCell;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    Icmpv6Packet, Icmpv6Repr, IpProtocol, Ipv6Packet, Ipv6Repr, NdiscNeighborFlags, NdiscRepr,
};
pub mod echo;
pub mod echo_responder;

pub const TOTAL_MS: u64 = 12_000;
pub const ACQUIRE_MS: u64 = 3_000;
pub const ACTIVE_MS: u64 = 8_000;
pub const OBSERVE_MS: u64 = 1_000;
pub const MAX_DEFENSES: u8 = 4;
const REFUSED: i64 = -125;
const MAX_FRAMES: u16 = 128;
const ACQUIRE_CALLS: u32 = 4096;
const ACTIVE_CALLS: u32 = 32768;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Denied,
    Entropy,
    Clock,
    Timeout,
    Link,
    Conflict,
    Ambiguous,
    Exhausted,
    Interrupted,
    Retired,
    Engine,
}

/// Trusted construction selects a fixed controlled direct-link profile.
/// Values in received frames cannot change it.
#[derive(Clone, Copy)]
pub struct Policy {
    config: Config,
    peer: Address,
    port: u16,
}
impl Policy {
    pub const fn fixture() -> Self {
        let mut address = [0; 16];
        address[0] = 0xfd;
        address[2] = 0xab;
        address[3] = 0x5d;
        address[15] = 0x15;
        let mut peer = address;
        peer[15] = 2;
        Self {
            config: Config {
                address,
                prefix_len: 64,
                scope: 1,
            },
            peer: Address {
                ip: peer,
                port: 42010,
                scope: 1,
            },
            port: 7002,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Observations {
    pub probes_submitted: u8,
    pub defenses_submitted: u8,
    pub received_frames: u16,
    pub malformed: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Tentative,
    Active,
    Retired,
}
struct Guard {
    policy: Policy,
    mac: [u8; 6],
    phase: Phase,
    last: u64,
    until: u64,
    deadline: u64,
    missed: u64,
    error: Option<Error>,
    last_defense: Option<u64>,
    defense_attempts: u8,
    calls: u32,
    observations: Observations,
}
impl Guard {
    fn new(
        policy: Policy,
        mac: [u8; 6],
        start: u64,
        now: u64,
        link: Option<LinkReading>,
    ) -> Result<Self, Error> {
        if mac == [0; 6] || mac[0] & 1 != 0 {
            return Err(Error::Denied);
        }
        let until = start
            .checked_add(TOTAL_MS)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(Error::Clock)?;
        let deadline = start.checked_add(ACQUIRE_MS).ok_or(Error::Clock)?;
        let missed = link.ok_or(Error::Link)?.rx_missed;
        let mut guard = Self {
            policy,
            mac,
            phase: Phase::Tentative,
            last: start,
            until,
            deadline,
            missed,
            error: None,
            last_defense: None,
            defense_attempts: 0,
            calls: 0,
            observations: Observations::default(),
        };
        guard.check(now, link)?;
        Ok(guard)
    }
    fn retire(&mut self, error: Error) -> Error {
        let error = *self.error.get_or_insert(error);
        self.phase = Phase::Retired;
        error
    }
    fn time(&mut self, now: u64) -> Result<(), Error> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let error = if now < self.last || now > i64::MAX as u64 {
            Some(Error::Clock)
        } else if now >= self.deadline || now >= self.until {
            Some(Error::Timeout)
        } else {
            None
        };
        self.last = now;
        match error {
            Some(error) => Err(self.retire(error)),
            None => Ok(()),
        }
    }
    fn check(&mut self, now: u64, link: Option<LinkReading>) -> Result<(), Error> {
        self.time(now)?;
        if link.is_none_or(|r| !r.link_up || r.disabled || r.rx_missed != self.missed) {
            return Err(self.retire(Error::Link));
        }
        Ok(())
    }
    fn activate(&mut self, now: u64) -> Result<(), Error> {
        self.time(now)?;
        if self.phase != Phase::Tentative || self.observations.probes_submitted != 1 {
            return Err(self.retire(Error::Denied));
        }
        self.deadline = now
            .checked_add(ACTIVE_MS)
            .ok_or_else(|| self.retire(Error::Clock))?
            .min(self.until);
        self.phase = Phase::Active;
        self.calls = 0;
        Ok(())
    }
    fn call(&mut self) -> Result<(), Error> {
        let bound = if self.phase == Phase::Tentative {
            ACQUIRE_CALLS
        } else {
            ACTIVE_CALLS
        };
        if self.calls >= bound {
            return Err(self.retire(Error::Exhausted));
        }
        self.calls += 1;
        Ok(())
    }
    fn frame(&mut self, frame: &[u8]) -> Result<bool, Error> {
        if self.observations.received_frames >= MAX_FRAMES {
            return Err(self.retire(Error::Exhausted));
        }
        self.observations.received_frames += 1;
        match inspect(frame, self.policy.config.address, self.mac) {
            Message::Other => Ok(false),
            Message::Malformed => {
                self.observations.malformed += 1;
                Ok(true)
            }
            Message::Ambiguous => Err(self.retire(Error::Ambiguous)),
            Message::Advertisement => Err(self.retire(Error::Conflict)),
            Message::Dad if self.phase == Phase::Tentative => Err(self.retire(Error::Conflict)),
            Message::Dad => Ok(true),
        }
    }
    fn defend(&mut self, now: u64) -> Result<(), Error> {
        self.time(now)?;
        if self.phase != Phase::Active {
            return Err(self.retire(Error::Denied));
        }
        if self.defense_attempts >= MAX_DEFENSES
            || self
                .last_defense
                .is_some_and(|at| now.saturating_sub(at) < OBSERVE_MS)
        {
            return Err(self.retire(Error::Exhausted));
        }
        self.defense_attempts += 1;
        self.last_defense = Some(now);
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Message {
    Other,
    Malformed,
    Dad,
    Advertisement,
    Ambiguous,
}
fn solicited(address: [u8; 16]) -> [u8; 16] {
    let mut result = [0; 16];
    result[0] = 0xff;
    result[1] = 2;
    result[11] = 1;
    result[12] = 0xff;
    result[13..].copy_from_slice(&address[13..]);
    result
}
fn all_nodes() -> [u8; 16] {
    let mut result = [0; 16];
    result[0] = 0xff;
    result[1] = 2;
    result[15] = 1;
    result
}
fn multicast_mac(ip: [u8; 16]) -> [u8; 6] {
    [0x33, 0x33, ip[12], ip[13], ip[14], ip[15]]
}
/// Only direct ordinary ND is in this fixed profile; no extension/fragment
/// normalization, proxy identity, or traffic-derived configuration follows.
fn inspect(frame: &[u8], candidate: [u8; 16], mac: [u8; 6]) -> Message {
    if frame.len() < 54 || frame[12..14] != [0x86, 0xdd] || frame[14] >> 4 != 6 || frame[20] != 58 {
        return Message::Other;
    }
    // Only NS/NA belong to this guard. Other ICMPv6, including short Echo
    // messages and quoted errors with ordinary hop limits, stays with Stack.
    if !matches!(frame.get(54).copied(), Some(135 | 136)) {
        return Message::Other;
    }
    let length = u16::from_be_bytes([frame[18], frame[19]]) as usize;
    if frame.len() != 54 + length || length < 24 || frame[21] != 255 {
        return Message::Malformed;
    }
    let payload = &frame[54..];
    if payload[8..24] != candidate {
        return Message::Other;
    }
    if payload[1] != 0 || frame[6] & 1 != 0 || frame[6..12] == [0; 6] {
        return Message::Malformed;
    }
    let source: [u8; 16] = frame[22..38].try_into().unwrap();
    let destination: [u8; 16] = frame[38..54].try_into().unwrap();
    let Ok(packet) = Icmpv6Packet::new_checked(payload) else {
        return Message::Malformed;
    };
    if !packet.verify_checksum(&Ipv6Address::from(source), &Ipv6Address::from(destination)) {
        return Message::Malformed;
    }
    let dad = payload[0] == 135 && source == [0; 16];
    let advert = payload[0] == 136;
    if dad {
        if destination != solicited(candidate) || frame[..6] != multicast_mac(destination) {
            return Message::Malformed;
        }
    } else if advert {
        if !super::usable_address(source)
            || (destination != all_nodes() && destination != candidate)
            || frame[..6]
                != if destination == all_nodes() {
                    multicast_mac(destination)
                } else {
                    mac
                }
            || (destination[0] == 0xff && payload[4] & 0x40 != 0)
        {
            return Message::Malformed;
        }
    } else {
        return Message::Other;
    }
    let mut options = &payload[24..];
    while !options.is_empty() {
        if options.len() < 2 || options[1] == 0 {
            return Message::Malformed;
        }
        let length = usize::from(options[1]) * 8;
        if options.len() < length
            || (dad && options[0] == 1)
            || (advert && options[0] == 2 && (length != 8 || options[2..8] != frame[6..12]))
        {
            return Message::Malformed;
        }
        options = &options[length..];
    }
    if frame[6..12] == mac {
        return Message::Ambiguous;
    }
    if dad {
        Message::Dad
    } else {
        Message::Advertisement
    }
}
fn packet(policy: Policy, mac: [u8; 6], defend: bool) -> Vec<u8> {
    let candidate = Ipv6Address::from(policy.config.address);
    let (source, target, nd) = if defend {
        (
            candidate,
            Ipv6Address::from(all_nodes()),
            NdiscRepr::NeighborAdvert {
                flags: NdiscNeighborFlags::OVERRIDE,
                target_addr: candidate,
                lladdr: Some(HardwareAddress::Ethernet(EthernetAddress(mac)).into()),
            },
        )
    } else {
        (
            Ipv6Address::UNSPECIFIED,
            Ipv6Address::from(solicited(policy.config.address)),
            NdiscRepr::NeighborSolicit {
                target_addr: candidate,
                lladdr: None,
            },
        )
    };
    let icmp = Icmpv6Repr::Ndisc(nd);
    let mut frame = vec![0; 54 + icmp.buffer_len()];
    frame[..6].copy_from_slice(&multicast_mac(target.octets()));
    frame[6..12].copy_from_slice(&mac);
    frame[12..14].copy_from_slice(&[0x86, 0xdd]);
    Ipv6Repr {
        src_addr: source,
        dst_addr: target,
        next_header: IpProtocol::Icmpv6,
        payload_len: icmp.buffer_len(),
        hop_limit: 255,
    }
    .emit(&mut Ipv6Packet::new_unchecked(&mut frame[14..]));
    icmp.emit(
        &source,
        &target,
        &mut Icmpv6Packet::new_unchecked(&mut frame[54..]),
        &ChecksumCapabilities::default(),
    );
    frame
}
struct Guarded<L: Link> {
    link: Rc<RefCell<L>>,
    guard: Rc<RefCell<Guard>>,
}
fn check_link<L: Link>(link: &Rc<RefCell<L>>, guard: &Rc<RefCell<Guard>>) -> Result<u64, Error> {
    let link = link.borrow();
    let reading = link.read();
    let now = link.now_ms();
    guard.borrow_mut().check(now, reading)?;
    Ok(now)
}
impl<L: Link> Guarded<L> {
    fn check(&self) -> Result<(), Error> {
        check_link(&self.link, &self.guard).map(|_| ())
    }
    fn failed(&self, error: Error) -> i64 {
        self.guard.borrow_mut().retire(error);
        REFUSED
    }
    fn fixed_send(&mut self, defend: bool) -> Result<(), Error> {
        self.check()?;
        let now = self.link.borrow().now_ms();
        let frame = {
            let mut g = self.guard.borrow_mut();
            if defend {
                g.defend(now)?;
            } else if g.phase != Phase::Tentative || g.observations.probes_submitted != 0 {
                return Err(g.retire(Error::Denied));
            }
            packet(g.policy, g.mac, defend)
        };
        self.check()?;
        let sent = self.link.borrow_mut().send(&frame);
        let after = self.check();
        if sent.is_err() {
            return Err(self.guard.borrow_mut().retire(Error::Link));
        }
        {
            let mut g = self.guard.borrow_mut();
            if defend {
                g.observations.defenses_submitted += 1;
            } else {
                g.observations.probes_submitted += 1;
            }
        }
        after
    }
}
impl<L: Link> Link for Guarded<L> {
    fn mac(&self) -> [u8; 6] {
        self.link.borrow().mac()
    }
    fn now_ms(&self) -> u64 {
        self.link.borrow().now_ms()
    }
    fn pause(&self, ms: u64) {
        if self.check().is_ok() {
            self.link.borrow().pause(ms.min(1));
            let _ = self.check();
        }
    }
    fn read(&self) -> Option<LinkReading> {
        let reading = self.link.borrow().read();
        if self
            .guard
            .borrow_mut()
            .check(self.link.borrow().now_ms(), reading)
            .is_ok()
        {
            reading
        } else {
            None
        }
    }
    fn send(&mut self, frame: &[u8]) -> Result<(), i64> {
        self.check().map_err(|_| REFUSED)?;
        if self.guard.borrow().phase != Phase::Active {
            return Err(self.failed(Error::Denied));
        }
        let sent = self.link.borrow_mut().send(frame);
        let after = self.check();
        if sent.is_err() {
            return Err(self.failed(Error::Link));
        }
        after.map_err(|_| REFUSED)
    }
    fn receive(
        &mut self,
        buffer: &mut [u8; FRAME_MAX],
        timeout_ms: u64,
    ) -> Result<Option<usize>, i64> {
        self.check().map_err(|_| REFUSED)?;
        let mut timeout = timeout_ms.min(1);
        for _ in 0..16 {
            self.guard.borrow_mut().call().map_err(|_| REFUSED)?;
            let result = self.link.borrow_mut().receive(buffer, timeout);
            let after = self.check();
            let result = result.map_err(|_| self.failed(Error::Link))?;
            after.map_err(|_| REFUSED)?;
            let Some(length) = result else {
                return Ok(None);
            };
            if length > FRAME_MAX {
                return Err(self.failed(Error::Link));
            }
            let frame = &buffer[..length];
            let (event, active) = {
                let mut g = self.guard.borrow_mut();
                let event = inspect(frame, g.policy.config.address, g.mac);
                let consumed = g.frame(frame).map_err(|_| REFUSED)?;
                (
                    if consumed { event } else { Message::Other },
                    g.phase == Phase::Active,
                )
            };
            if event == Message::Dad && active {
                self.fixed_send(true).map_err(|_| REFUSED)?;
            }
            if event == Message::Other && active {
                return Ok(Some(length));
            }
            timeout = 0;
        }
        Err(self.failed(Error::Exhausted))
    }
}
struct GuardPipe<'a, P: channel::Pipe, L: Link> {
    pipe: &'a mut P,
    guard: Rc<RefCell<Guard>>,
    link: Rc<RefCell<L>>,
}
impl<P: channel::Pipe, L: Link> GuardPipe<'_, P, L> {
    fn check(&self) -> Result<(), i64> {
        // Resample the actual owner Link, never a cached Channel step time.
        check_link(&self.link, &self.guard).map_err(|_| REFUSED)?;
        let mut g = self.guard.borrow_mut();
        if g.phase != Phase::Active {
            g.retire(Error::Retired);
            return Err(REFUSED);
        }
        Ok(())
    }
}
impl<P: channel::Pipe, L: Link> channel::Pipe for GuardPipe<'_, P, L> {
    fn now_ms(&self) -> u64 {
        let _ = self.check();
        self.link.borrow().now_ms()
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        self.check()?;
        let result = self.pipe.read(bytes);
        let after = self.check();
        if result.is_err() {
            self.guard.borrow_mut().retire(Error::Interrupted);
            return Err(REFUSED);
        }
        after?;
        result
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        self.check()?;
        let result = self.pipe.write(bytes);
        let after = self.check();
        if result.is_err() {
            self.guard.borrow_mut().retire(Error::Interrupted);
            return Err(REFUSED);
        }
        after?;
        result
    }
}
/// Fixed native DAD bootstrap schema 1: version/reserved, exact peer,
/// original invocation start and active stop. Bytes describe policy, not grants.
pub const BOOTSTRAP_LEN: usize = 40;
pub fn decode_bootstrap(bytes: &[u8; BOOTSTRAP_LEN], now: u64) -> Result<(Address, u64), Error> {
    let peer = Address {
        ip: bytes[2..18].try_into().unwrap(),
        scope: u32::from_be_bytes(bytes[18..22].try_into().unwrap()),
        port: u16::from_be_bytes(bytes[22..24].try_into().unwrap()),
    };
    let start = u64::from_be_bytes(bytes[24..32].try_into().unwrap());
    let stop = u64::from_be_bytes(bytes[32..40].try_into().unwrap());
    let until = start
        .checked_add(TOTAL_MS)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or(Error::Clock)?;
    if bytes[..2] != [1, 0] || peer != Policy::fixture().peer {
        return Err(Error::Denied);
    }
    if now < start {
        return Err(Error::Clock);
    }
    if now >= stop || stop > until {
        return Err(Error::Timeout);
    }
    Ok((peer, stop))
}
/// One private Stack and framer. No caller can retain either across retirement.
pub struct Owner<L: Link> {
    stack: Option<Stack<Guarded<L>>>,
    channel: Option<channel::Channel>,
    guard: Rc<RefCell<Guard>>,
    issued: bool,
}
impl<L: Link> Owner<L> {
    /// `start` is the original invocation sample, before entropy/bootstrap.
    /// Link and Pipe clocks must observe that same boot domain.
    pub fn acquire<E>(
        link: L,
        policy: Policy,
        start: u64,
        mut entropy: impl FnMut(&mut [u8]) -> Result<(), E>,
    ) -> Result<Self, Error> {
        let reading = link.read();
        let now = link.now_ms();
        let guard = Rc::new(RefCell::new(Guard::new(
            policy,
            link.mac(),
            start,
            now,
            reading,
        )?));
        let mut link = Guarded {
            link: Rc::new(RefCell::new(link)),
            guard: guard.clone(),
        };
        let mut random = [0; 2];
        let entropy_result = entropy(&mut random);
        let after_entropy = link.check();
        if entropy_result.is_err() {
            return Err(Error::Entropy);
        }
        after_entropy?;
        let probe_at = link
            .now_ms()
            .checked_add(u64::from(u16::from_le_bytes(random) % 1001))
            .ok_or(Error::Clock)?;
        let mut buffer = [0; FRAME_MAX];
        while link.now_ms() < probe_at {
            link.receive(&mut buffer, 1)
                .map_err(|_| guard.borrow().error.unwrap_or(Error::Link))?;
            link.pause(1);
        }
        link.check()?;
        link.receive(&mut buffer, 0)
            .map_err(|_| guard.borrow().error.unwrap_or(Error::Link))?;
        link.fixed_send(false)?;
        let finish = link.now_ms().checked_add(OBSERVE_MS).ok_or(Error::Clock)?;
        while link.now_ms() < finish {
            link.receive(&mut buffer, 1)
                .map_err(|_| guard.borrow().error.unwrap_or(Error::Link))?;
            link.pause(1);
        }
        // Observe currently queued conflict frames at the boundary too. There
        // is no atomic wire-empty/activation transition or uniqueness proof.
        link.receive(&mut buffer, 0)
            .map_err(|_| guard.borrow().error.unwrap_or(Error::Link))?;
        link.check()?;
        guard.borrow_mut().activate(link.now_ms())?;
        let mut stack = Stack::open(link, crate::Config::qemu_user()).map_err(|_| Error::Engine)?;
        stack
            .configure_ipv6(policy.config)
            .map_err(|_| Error::Engine)?;
        let mut owner = Self {
            stack: Some(stack),
            channel: None,
            guard,
            issued: false,
        };
        owner.check()?;
        Ok(owner)
    }
    pub fn check(&mut self) -> Result<(), Error> {
        let result = self
            .stack
            .as_ref()
            .ok_or_else(|| self.guard.borrow().error.unwrap_or(Error::Retired))?
            .link()
            .check();
        if result.is_err() {
            self.channel.take();
            self.stack.take();
        }
        result
    }
    pub fn bootstrap(&mut self) -> Result<[u8; BOOTSTRAP_LEN], Error> {
        self.check()?;
        let g = self.guard.borrow();
        let mut b = [0; BOOTSTRAP_LEN];
        b[0] = 1;
        b[2..18].copy_from_slice(&g.policy.peer.ip);
        b[18..22].copy_from_slice(&g.policy.peer.scope.to_be_bytes());
        b[22..24].copy_from_slice(&g.policy.peer.port.to_be_bytes());
        b[24..32].copy_from_slice(&(g.until - TOTAL_MS).to_be_bytes());
        b[32..40].copy_from_slice(&g.deadline.to_be_bytes());
        Ok(b)
    }
    pub fn peer(&self) -> Address {
        self.guard.borrow().policy.peer
    }
    pub fn until_ms(&self) -> u64 {
        self.guard.borrow().until
    }
    pub fn stop_ms(&self) -> u64 {
        self.guard.borrow().deadline
    }
    pub fn observations(&self) -> Observations {
        self.guard.borrow().observations
    }
    pub fn socket_count(&self) -> usize {
        self.stack.as_ref().map_or(0, Stack::socket_count)
    }
    pub fn start_dns(&mut self) -> Result<(), Error> {
        self.check()?;
        if self.issued {
            return Err(Error::Denied);
        }
        self.issued = true;
        let policy = self.guard.borrow().policy;
        let channel = match channel::Channel::grant(
            self.stack.as_mut().unwrap(),
            Grant {
                local_port: policy.port,
                peer: policy.peer,
            },
        ) {
            Ok(channel) => channel,
            Err(_) => {
                self.guard.borrow_mut().retire(Error::Engine);
                self.retire();
                return Err(Error::Engine);
            }
        };
        self.channel = Some(channel);
        self.check()
    }
    pub fn poll<P: channel::Pipe>(&mut self, pipe: &mut P) -> Result<bool, Error> {
        self.check()?;
        if self.channel.is_none() {
            return Err(Error::Denied);
        }
        self.stack.as_mut().unwrap().poll();
        self.check()?;
        let mut pipe = GuardPipe {
            pipe,
            guard: self.guard.clone(),
            link: self.stack.as_ref().unwrap().link().link.clone(),
        };
        let live = self
            .channel
            .as_mut()
            .unwrap()
            .poll(self.stack.as_mut().unwrap(), &mut pipe);
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
        self.channel.take();
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
