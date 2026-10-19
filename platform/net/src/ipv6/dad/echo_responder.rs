//! Explicit sole-NIC-owner authority for one inbound IPv6 Echo reply.
//! smoltcp parses and emits the protocol; this module bounds its authority.
use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

pub use super::echo::Peer;
pub const MAX_PACKET: usize = 1240;
pub const MAX_LIFETIME_MS: u64 = ACTIVE_MS;
static INSTANCE: AtomicU64 = AtomicU64::new(1);
fn reserve(counter: &AtomicU64) -> Result<u64, Error> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        .map_err(|_| Error::Exhausted)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Dad(super::Error),
    Denied,
    Exhausted,
    Stale,
    Again,
    Spent,
    Interrupted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    instance: u64,
    generation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub endpoint: Endpoint,
    pub peer: Peer,
    pub identifier: u16,
    pub sequence: u16,
    pub icmp_bytes: u16,
    /// The underlying send returned Ok, followed by a valid owner check.
    /// This is not proof of peer receipt, physical RTT or authentication.
    pub submitted_at_ms: u64,
}

/// Private shared admission, installed only after DAD and explicit activation.
pub(crate) struct Admission {
    live: bool,
    peer: Peer,
    local: [u8; 16],
    mac: [u8; 6],
    peer_mac: [u8; 6],
    request: Option<Vec<u8>>,
    attempted: bool,
    submitted_at: Option<u64>,
    fault: Option<Error>,
}
impl Admission {
    pub(crate) fn retire(&mut self) {
        self.live = false;
        self.request.take();
        self.submitted_at = None;
    }
    pub(crate) fn peer(&self) -> Option<[u8; 16]> {
        (self.live && !self.attempted).then_some(self.peer.ip)
    }
    pub(crate) fn admit(&mut self, frame: &[u8]) -> bool {
        if !self.live
            || self.request.is_some()
            || self.attempted
            || self.fault.is_some()
            || frame.len() < 62
            || frame.len() > 54 + MAX_PACKET
            || frame[..6] != self.mac
            || frame[6] & 1 != 0
            || frame[6..12] == [0; 6]
            || frame[6..12] == self.mac
            || frame[12..14] != [0x86, 0xdd]
            || frame[14] >> 4 != 6
            || usize::from(u16::from_be_bytes([frame[18], frame[19]])) != frame.len() - 54
            || frame[20] != 58
            || frame[21] == 0
            || frame[22..38] != self.peer.ip
            || frame[38..54] != self.local
            || frame[54..56] != [128, 0]
        {
            return false;
        }
        if !Icmpv6Packet::new_unchecked(&frame[54..]).verify_checksum(
            &Ipv6Address::from(self.peer.ip),
            &Ipv6Address::from(self.local),
        ) {
            return false;
        }
        self.peer_mac.copy_from_slice(&frame[6..12]);
        self.request = Some(frame[54..].to_vec());
        true
    }
    fn sending(&mut self, frame: &[u8]) -> Result<bool, Error> {
        if let Some(error) = self.fault {
            return Err(error);
        }
        // Only Echo Reply is authorized here. ND/DAD remains the original
        // guarded engine path; this private Stack has no application sockets.
        if frame.len() < 55
            || frame[12..14] != [0x86, 0xdd]
            || frame[20] != 58
            || !matches!(frame[54], 129 | 135 | 136)
        {
            self.fault = Some(Error::Denied);
            self.retire();
            return Err(Error::Denied);
        }
        if matches!(frame[54], 135 | 136) {
            return Ok(false);
        }
        let valid = self.request.as_ref().is_some_and(|request| {
            self.live
                && !self.attempted
                && frame.len() == 54 + request.len()
                && frame[..6] == self.peer_mac
                && frame[6..12] == self.mac
                && frame[14] >> 4 == 6
                && frame[20] == 58
                && usize::from(u16::from_be_bytes([frame[18], frame[19]])) == request.len()
                && frame[22..38] == self.local
                && frame[38..54] == self.peer.ip
                && frame[54..56] == [129, 0]
                && frame[58..] == request[4..]
                && Icmpv6Packet::new_unchecked(&frame[54..]).verify_checksum(
                    &Ipv6Address::from(self.local),
                    &Ipv6Address::from(self.peer.ip),
                )
        });
        if !valid {
            self.fault = Some(Error::Denied);
            self.retire();
            return Err(Error::Denied);
        }
        // Spend before underlying I/O: even Err may have an external effect.
        self.attempted = true;
        Ok(true)
    }
}
struct ResponderLink<L: Link> {
    inner: L,
    admission: Rc<RefCell<Admission>>,
}
impl<L: Link> Link for ResponderLink<L> {
    fn mac(&self) -> [u8; 6] {
        self.inner.mac()
    }
    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
    fn pause(&self, ms: u64) {
        self.inner.pause(ms);
    }
    fn read(&self) -> Option<LinkReading> {
        if self.admission.borrow().fault.is_some() {
            None
        } else {
            self.inner.read()
        }
    }
    fn receive(&mut self, frame: &mut [u8; FRAME_MAX], timeout: u64) -> Result<Option<usize>, i64> {
        self.inner.receive(frame, timeout)
    }
    fn send(&mut self, frame: &[u8]) -> Result<(), i64> {
        let reply = self
            .admission
            .borrow_mut()
            .sending(frame)
            .map_err(|_| REFUSED)?;
        let result = self.inner.send(frame);
        let mut a = self.admission.borrow_mut();
        if result.is_err() {
            a.fault = Some(Error::Interrupted);
            a.retire();
        } else if reply {
            a.submitted_at = Some(self.inner.now_ms());
        }
        result
    }
}

/// One private DAD owner; no Stack, socket, Link or child handle is exported.
pub struct Owner<L: Link> {
    dad: super::Owner<ResponderLink<L>>,
    admission: Rc<RefCell<Admission>>,
    instance: u64,
    endpoint: Option<Endpoint>,
    next_generation: u64,
    issued: bool,
    observed: bool,
}
pub fn fixture_peer() -> Peer {
    super::echo::fixture_peer()
}
impl<L: Link> Owner<L> {
    pub fn acquire<E>(
        link: L,
        start: u64,
        entropy: impl FnMut(&mut [u8]) -> Result<(), E>,
    ) -> Result<Self, Error> {
        let instance = reserve(&INSTANCE)?;
        let admission = Rc::new(RefCell::new(Admission {
            live: false,
            peer: fixture_peer(),
            local: Policy::fixture().config.address,
            mac: link.mac(),
            peer_mac: [0; 6],
            request: None,
            attempted: false,
            submitted_at: None,
            fault: None,
        }));
        let dad = super::Owner::acquire(
            ResponderLink {
                inner: link,
                admission: admission.clone(),
            },
            Policy::fixture(),
            start,
            entropy,
        )
        .map_err(Error::Dad)?;
        Ok(Self {
            dad,
            admission,
            instance,
            endpoint: None,
            next_generation: 1,
            issued: false,
            observed: false,
        })
    }
    pub fn check(&mut self) -> Result<(), Error> {
        let fault = self.admission.borrow().fault;
        let result = self.dad.check();
        if let Some(error) = fault {
            self.retire();
            return Err(error);
        }
        if let Err(error) = result {
            self.retire();
            return Err(Error::Dad(error));
        }
        Ok(())
    }
    fn live(&mut self, endpoint: Endpoint) -> Result<(), Error> {
        if self.endpoint != Some(endpoint) {
            return Err(Error::Stale);
        }
        self.check()
    }
    pub fn activate(&mut self, peer: Peer) -> Result<Endpoint, Error> {
        self.check()?;
        if self.issued {
            return Err(Error::Exhausted);
        }
        if peer != fixture_peer() {
            return Err(Error::Denied);
        }
        let generation = self.next_generation;
        self.next_generation = generation.checked_add(1).ok_or(Error::Exhausted)?;
        let endpoint = Endpoint {
            instance: self.instance,
            generation,
        };
        self.endpoint = Some(endpoint);
        self.issued = true;
        self.admission.borrow_mut().live = true;
        self.dad
            .stack
            .as_mut()
            .ok_or(Error::Stale)?
            .port
            .ipv6_responder = Some(self.admission.clone());
        self.live(endpoint)?;
        Ok(endpoint)
    }
    pub fn poll(&mut self, endpoint: Endpoint) -> Result<(), Error> {
        self.live(endpoint)?;
        self.dad.stack.as_mut().ok_or(Error::Stale)?.poll();
        self.live(endpoint)
    }
    pub fn wait(&mut self) -> Result<(), Error> {
        if let Err(error) = self.dad.wait() {
            self.retire();
            return Err(Error::Dad(error));
        }
        self.check()
    }
    pub fn observe(&mut self, endpoint: Endpoint) -> Result<Observation, Error> {
        self.live(endpoint)?;
        if self.observed {
            return Err(Error::Spent);
        }
        let result = {
            let a = self.admission.borrow();
            let at = a.submitted_at.ok_or(Error::Again)?;
            let request = a.request.as_ref().ok_or(Error::Stale)?;
            Observation {
                endpoint,
                peer: a.peer,
                identifier: u16::from_be_bytes([request[4], request[5]]),
                sequence: u16::from_be_bytes([request[6], request[7]]),
                icmp_bytes: request.len() as u16,
                submitted_at_ms: at,
            }
        };
        self.observed = true;
        self.admission.borrow_mut().retire();
        self.dad
            .stack
            .as_mut()
            .ok_or(Error::Stale)?
            .port
            .ipv6_responder = None;
        Ok(result)
    }
    pub fn possible_reply_effects(&self) -> u8 {
        u8::from(self.admission.borrow().attempted)
    }
    pub fn socket_count(&self) -> usize {
        self.dad.socket_count()
    }
    pub fn stop_ms(&self) -> u64 {
        self.dad.stop_ms()
    }
    pub fn observations(&self) -> Observations {
        self.dad.observations()
    }
    pub fn retire(&mut self) {
        self.admission.borrow_mut().retire();
        self.endpoint = None;
        self.dad.retire();
    }
}
impl<L: Link> Drop for Owner<L> {
    fn drop(&mut self) {
        self.retire();
    }
}
#[cfg(test)]
mod tests;
