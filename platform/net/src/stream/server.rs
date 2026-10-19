//! One preauthorized inbound flow, not a general accept loop. LISTEN and
//! ACCEPT consume the owner's existing endpoint; packets never mint grants.
use super::*;
use crate::datagram::channel::Pipe;
use alloc::vec;

pub const VERSION: u8 = 3;
pub const LISTEN: u8 = 32;
pub const ACCEPT: u8 = 33;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub local_port: u16,
    pub peer: Address,
    /// 100..=10,000 ms from LISTEN, bounded by the original grant lifetime.
    pub accept_timeout_ms: u64,
    /// 100..=60,000 ms from owner construction, never renewed by ACCEPT.
    pub lifetime_ms: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct Filter {
    local: [u8; 4],
    port: u16,
    peer: Address,
    expires: u64,
    last_ms: u64,
    pub(super) fault: Option<Error>,
}

/// Restrict only reserved server ports. Other listeners/outbound flows keep
/// their existing policy. IPv4 fragments are unsupported by this engine;
/// a truncated header cannot form a valid TCP SYN or consume a listen slot.
pub(crate) fn ingress(frame: &[u8], filters: &[Option<Filter>; MAX_ENDPOINTS]) -> bool {
    if frame.len() < 34 || frame[12..14] != [8, 0] || frame[14] >> 4 != 4 || frame[23] != 6 {
        return true;
    }
    let header = usize::from(frame[14] & 15) * 4;
    if header < 20 || frame.len() < 14 + header + 4 {
        return true;
    }
    let tcp = 14 + header;
    let port = u16::from_be_bytes([frame[tcp + 2], frame[tcp + 3]]);
    let Some(rule) = filters.iter().flatten().find(|r| r.port == port) else {
        return true;
    };
    rule.fault.is_none()
        && header == 20
        && frame.len() >= tcp + 20
        && u16::from_be_bytes([frame[20], frame[21]]) & 0x3fff == 0
        && frame[30..34] == rule.local
        && frame[26..30] == rule.peer.ip
        && frame[tcp..tcp + 2] == rule.peer.port.to_be_bytes()
}

/// A sticky observed fence. Recovery cannot revive an old flow.
pub(crate) fn observe(filters: &mut [Option<Filter>; MAX_ENDPOINTS], now: u64) {
    for r in filters.iter_mut().flatten() {
        if r.fault.is_none() {
            r.fault = if now < r.last_ms {
                Some(Error::Clock)
            } else if now >= r.expires {
                Some(Error::Timeout)
            } else {
                None
            };
        }
        r.last_ms = now;
    }
}
pub(crate) fn observe_link(
    filters: &mut [Option<Filter>; MAX_ENDPOINTS],
    reading: Option<LinkReading>,
) {
    let error = match reading {
        None => Some(Error::LinkUnknown),
        Some(r) if r.disabled => Some(Error::DeviceFailed),
        Some(r) if !r.link_up => Some(Error::LinkDown),
        Some(_) => None,
    };
    if let Some(error) = error {
        for rule in filters.iter_mut().flatten() {
            rule.fault.get_or_insert(error);
        }
    }
}
/// A returned I/O refusal is an observed boundary even when the next link
/// status read looks healthy. Latch before Interface can dispatch another TX.
pub(crate) fn observe_error(filters: &mut [Option<Filter>; MAX_ENDPOINTS], code: i64) {
    let error = if code == NIC_NO_CARRIER {
        Error::LinkDown
    } else {
        Error::DeviceFailed
    };
    for rule in filters.iter_mut().flatten() {
        rule.fault.get_or_insert(error);
    }
}
pub(crate) fn egress(frame: &[u8], filters: &[Option<Filter>; MAX_ENDPOINTS]) -> bool {
    if frame.len() < 54 || frame[12..14] != [8, 0] || frame[14] != 0x45 || frame[23] != 6 {
        return true;
    }
    let port = u16::from_be_bytes([frame[34], frame[35]]);
    filters
        .iter()
        .flatten()
        .find(|r| r.port == port)
        .is_none_or(|r| {
            r.fault.is_none()
                && frame[26..30] == r.local
                && frame[30..34] == r.peer.ip
                && frame[36..38] == r.peer.port.to_be_bytes()
        })
}

impl<L: Link> Stack<L> {
    pub fn stream_server_grant(&mut self, grant: Grant) -> Result<Endpoint, Error> {
        let mask = u32::MAX << (32 - self.config.prefix_len);
        if u32::from_be_bytes(grant.peer.ip) & mask
            != u32::from_be_bytes(self.config.address.octets()) & mask
        {
            return Err(Error::Invalid);
        }
        let endpoint = self.stream_grant(super::Grant {
            local_port: grant.local_port,
            peer: grant.peer,
            connect_timeout_ms: grant.accept_timeout_ms,
            lifetime_ms: grant.lifetime_ms,
        })?;
        self.streams.entries[endpoint.slot].inbound = true;
        // Installed before any LISTEN socket or Interface poll exists.
        self.port.server_rules[endpoint.slot] = Some(Filter {
            local: self.config.address.octets(),
            port: grant.local_port,
            peer: grant.peer,
            expires: self.streams.entries[endpoint.slot].expires,
            last_ms: self.streams.entries[endpoint.slot].last_ms,
            fault: None,
        });
        Ok(endpoint)
    }

    pub fn stream_listen(&mut self, endpoint: Endpoint) -> Result<Status, Error> {
        let slot = self.stream_checked(endpoint)?;
        let e = &self.streams.entries[slot];
        if !e.inbound || e.started.is_some() {
            return Err(Error::Invalid);
        }
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; BUFFER_BYTES]),
            tcp::SocketBuffer::new(vec![0; BUFFER_BYTES]),
        );
        socket.set_timeout(None);
        socket
            .listen((self.config.address, e.grant.local_port))
            .map_err(|_| Error::Invalid)?;
        let handle = self.sockets.add(socket);
        let e = &mut self.streams.entries[slot];
        e.socket = Some(handle);
        let started = self.port.link.now_ms();
        e.started = Some(started);
        if let Some(rule) = &mut self.port.server_rules[slot] {
            rule.expires = started
                .saturating_add(e.grant.connect_timeout_ms)
                .min(e.expires);
        }
        Ok(Status {
            connected: false,
            write_closed: false,
            peer_finished: false,
        })
    }

    pub fn stream_accept(&mut self, endpoint: Endpoint) -> Result<Status, Error> {
        let slot = self.stream_checked(endpoint)?;
        let e = &self.streams.entries[slot];
        if !e.inbound || e.started.is_none() || e.accepted {
            return Err(Error::Invalid);
        }
        if !e.connected {
            return Err(Error::Again);
        }
        let actual = self
            .sockets
            .get::<tcp::Socket>(e.socket.ok_or(Error::Closed)?)
            .remote_endpoint();
        if actual
            != Some(smoltcp::wire::IpEndpoint::new(
                Ipv4Address::from(e.grant.peer.ip).into(),
                e.grant.peer.port,
            ))
        {
            self.stream_abort(endpoint)?;
            return Err(Error::Denied);
        }
        self.streams.entries[slot].accepted = true;
        if let Some(rule) = &mut self.port.server_rules[slot] {
            rule.expires = self.streams.entries[slot].expires;
        }
        self.port.stats.accepted += 1;
        self.stream_status(endpoint)
    }

    /// Immediate software queue discard; no terminal reset is retained.
    pub fn stream_server_fence(&mut self) {
        for (slot, e) in self.streams.entries.iter_mut().enumerate() {
            if e.inbound {
                e.live = false;
                e.error.get_or_insert(Error::Stale);
                if let Some(handle) = e.socket.take() {
                    self.sockets.remove(handle);
                    self.port.stats.released += 1;
                }
                e.closing = None;
                self.port.server_rules[slot] = None;
            }
        }
    }

    fn stream_server_discard(&mut self, endpoint: Endpoint) {
        if endpoint.instance != self.streams.instance {
            return;
        }
        if let Some(e) = self.streams.entries.get_mut(endpoint.slot)
            && e.epoch == endpoint.epoch
            && e.inbound
        {
            e.live = false;
            e.error.get_or_insert(Error::Stale);
            if let Some(handle) = e.socket.take() {
                self.sockets.remove(handle);
                self.port.stats.released += 1;
            }
            e.closing = None;
            self.port.server_rules[endpoint.slot] = None;
        }
    }

    fn stream_server_authorized(&mut self, endpoint: Endpoint, terminal_ack: bool) -> bool {
        if endpoint.instance != self.streams.instance {
            return false;
        }
        let now = self.port.link.now_ms();
        observe(&mut self.port.server_rules, now);
        let reading = self.port.link.read();
        observe_link(&mut self.port.server_rules, reading);
        let valid = self
            .streams
            .entries
            .get_mut(endpoint.slot)
            .is_some_and(|e| {
                let valid = e.epoch == endpoint.epoch
                    && e.inbound
                    && (e.live || terminal_ack)
                    && e.error.is_none()
                    && self.port.server_rules[endpoint.slot].is_none_or(|r| r.fault.is_none())
                    && reading.is_some_and(|r| r.link_up && !r.disabled)
                    && now >= e.last_ms
                    && now < e.expires
                    && (e.accepted
                        || e.started.is_none_or(|start| {
                            now.saturating_sub(start) < e.grant.connect_timeout_ms
                        }));
                if valid {
                    e.last_ms = now;
                }
                valid
            });
        if !valid {
            self.stream_server_discard(endpoint);
        }
        valid
    }
}

/// Typed v3/family4 session, with one implicit owner-issued endpoint.
pub struct Session {
    inner: super::Session,
    terminal_ack: bool,
}
impl Session {
    pub fn grant<L: Link>(stack: &mut Stack<L>, grant: Grant) -> Result<Self, Error> {
        Ok(Self {
            inner: super::Session {
                endpoint: stack.stream_server_grant(grant)?,
                peer: grant.peer,
                inbound: true,
            },
            terminal_ack: false,
        })
    }
    pub fn request<L: Link>(
        &mut self,
        stack: &mut Stack<L>,
        bytes: &[u8],
        reply: &mut [u8; crate::datagram::MAX_MESSAGE],
    ) -> usize {
        let n = self.inner.request(stack, bytes, reply);
        if reply[2] == 0 && matches!(bytes.get(1), Some(&CLOSE) | Some(&ABORT)) {
            // This permits the terminal acknowledgement and bounded drain,
            // never fresh endpoint operations or a renewed lifetime.
            self.terminal_ack = true;
        }
        n
    }
    pub fn revoke<L: Link>(&mut self, stack: &mut Stack<L>) {
        self.inner.revoke(stack)
    }
}
impl channel::Handler for Session {
    fn request<L: Link>(
        &mut self,
        stack: &mut Stack<L>,
        bytes: &[u8],
        reply: &mut [u8; crate::datagram::MAX_MESSAGE],
    ) -> usize {
        self.request(stack, bytes, reply)
    }
    fn revoke<L: Link>(&mut self, stack: &mut Stack<L>) {
        self.revoke(stack)
    }
    fn authorized<L: Link>(&mut self, stack: &mut Stack<L>) -> bool {
        stack.stream_server_authorized(self.inner.endpoint, self.terminal_ack)
    }
    fn fence<L: Link>(&mut self, stack: &mut Stack<L>) {
        stack.stream_server_discard(self.inner.endpoint);
    }
}
pub struct Channel(channel::Channel<Session>);
impl Channel {
    pub fn grant<L: Link>(stack: &mut Stack<L>, grant: Grant) -> Result<Self, Error> {
        Ok(Self(
            channel::Channel::new(Session::grant(stack, grant)?).strict(),
        ))
    }
    pub fn poll<L: Link, P: Pipe>(&mut self, stack: &mut Stack<L>, pipe: &mut P) -> bool {
        self.0.poll(stack, pipe)
    }
    pub fn revoke<L: Link>(&mut self, stack: &mut Stack<L>) {
        self.0.revoke(stack)
    }
    pub fn live(&self) -> bool {
        self.0.live()
    }
}
pub struct Client<P: Pipe>(super::Client<P>, bool);
impl<P: Pipe> Client<P> {
    pub fn new(pipe: P, peer: Address, pause: fn(u64)) -> Self {
        Self(super::Client::server(pipe, peer, pause), false)
    }
    pub fn accept(&mut self, deadline: u64) -> Result<(), Error> {
        if self.1 {
            return Err(Error::Invalid);
        }
        self.0.connect(deadline)?;
        self.1 = true;
        Ok(())
    }
    pub fn read(&mut self, bytes: &mut [u8], deadline: u64) -> Result<usize, Error> {
        if !self.1 {
            return Err(Error::Again);
        }
        self.0.read(bytes, deadline)
    }
    pub fn write_all(&mut self, bytes: &[u8], deadline: u64) -> Result<(), Error> {
        if !self.1 {
            return Err(Error::Again);
        }
        self.0.write_all(bytes, deadline)
    }
    pub fn shutdown_write(&mut self, deadline: u64) -> Result<(), Error> {
        if !self.1 {
            return Err(Error::Again);
        }
        self.0.shutdown_write(deadline)
    }
    pub fn close(&mut self, deadline: u64) -> Result<(), Error> {
        self.0.close(deadline)
    }
}

/// One typed v3 transaction. Partial failures retire the caller's pipe; a
/// possibly executed WRITE must not be retried. Client enforces that rule.
pub fn transact<P: Pipe>(
    pipe: &mut P,
    request: &[u8],
    reply: &mut [u8; crate::datagram::MAX_MESSAGE],
    timeout: u64,
) -> Result<usize, i64> {
    crate::datagram::channel::transact_versioned(pipe, request, reply, timeout, VERSION, 4)
}
