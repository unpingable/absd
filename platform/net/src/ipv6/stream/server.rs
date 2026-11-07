//! One preauthorized on-link inbound flow; packets never mint grants.
//! This v3/family-6 protocol is separate from the outbound v2 Session.
use super::*;
use crate::datagram::channel::Pipe;

pub const VERSION: u8 = 3;
pub const LISTEN: u8 = 32;
pub const ACCEPT: u8 = 33;
pub use super::{FAMILY, HEADER, MAX_MESSAGE};
mod channel;
mod client;
pub use channel::{Channel, transact};
pub use client::Client;
#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub local_port: u16,
    pub peer: Address,
    /// 100..=10,000 ms from LISTEN, bounded by the original owner lifetime.
    pub accept_timeout_ms: u64,
    /// 100..=60,000 ms from owner construction, never renewed by ACCEPT.
    pub lifetime_ms: u64,
}
#[derive(Clone, Copy)]
pub(crate) struct Filter {
    local: [u8; 16],
    port: u16,
    peer: Address,
    expires: u64,
    last_ms: u64,
    pub(crate) fault: Option<Error>,
}
pub(crate) fn live_rule(rule: &Option<Filter>) -> bool {
    rule.is_none_or(|r| r.fault.is_none())
}
pub(crate) fn observe(
    rules: &mut [Option<Filter>; MAX_ENDPOINTS],
    now: u64,
    link: Option<LinkReading>,
) {
    for r in rules.iter_mut().flatten() {
        let fault = if now < r.last_ms {
            Some(Error::Clock)
        } else if now >= r.expires {
            Some(Error::Timeout)
        } else {
            match link {
                None => Some(Error::LinkUnknown),
                Some(r) if r.disabled => Some(Error::DeviceFailed),
                Some(r) if !r.link_up => Some(Error::LinkDown),
                Some(_) => None,
            }
        };
        r.fault = r.fault.or(fault);
        r.last_ms = now;
    }
}
pub(crate) fn observe_error(rules: &mut [Option<Filter>; MAX_ENDPOINTS], code: i64) {
    for r in rules.iter_mut().flatten() {
        r.fault.get_or_insert(if code == NIC_NO_CARRIER {
            Error::LinkDown
        } else {
            Error::DeviceFailed
        });
    }
}
/// Existing Flow ingress remains the exact IP/scope/port admission predicate.
/// This additional server guard latches its original accept/owner boundary.
pub(crate) fn ingress(frame: &[u8], rules: &[Option<Filter>; MAX_ENDPOINTS]) -> bool {
    if frame.len() < 58 || frame[12..14] != [0x86, 0xdd] || frame[20] != 6 {
        return true;
    }
    let port = u16::from_be_bytes([frame[56], frame[57]]);
    rules
        .iter()
        .flatten()
        .find(|r| r.port == port)
        .is_none_or(|r| {
            r.fault.is_none()
                && frame[22..38] == r.peer.ip
                && frame[38..54] == r.local
                && frame[54..56] == r.peer.port.to_be_bytes()
        })
}
pub(crate) fn egress(frame: &[u8], rules: &[Option<Filter>; MAX_ENDPOINTS]) -> bool {
    if frame.len() < 58 || frame[12..14] != [0x86, 0xdd] || frame[20] != 6 {
        return true;
    }
    let port = u16::from_be_bytes([frame[54], frame[55]]);
    rules
        .iter()
        .flatten()
        .find(|r| r.port == port)
        .is_none_or(|r| {
            r.fault.is_none()
                && frame[22..38] == r.local
                && frame[38..54] == r.peer.ip
                && frame[56..58] == r.peer.port.to_be_bytes()
        })
}
impl<L: Link> Stack<L> {
    pub fn ipv6_stream_server_grant(&mut self, grant: Grant) -> Result<Endpoint, Error> {
        let config = self.ipv6_config().ok_or(Error::Denied)?;
        if !super::super::same_prefix(config.address, grant.peer.ip, config.prefix_len) {
            return Err(Error::Denied);
        }
        let endpoint = self.ipv6_stream_grant(super::Grant {
            local_port: grant.local_port,
            peer: grant.peer,
            connect_timeout_ms: grant.accept_timeout_ms,
            lifetime_ms: grant.lifetime_ms,
        })?;
        let e = &mut self.ipv6_streams.entries[endpoint.slot];
        e.inbound = true;
        self.port.ipv6_server_rules[endpoint.slot] = Some(Filter {
            local: config.address,
            port: grant.local_port,
            peer: grant.peer,
            expires: e.expires,
            last_ms: e.last_ms,
            fault: None,
        });
        Ok(endpoint)
    }
    fn ipv6_server_checked(&mut self, endpoint: Endpoint) -> Result<usize, Error> {
        if !self.ipv6_streams.entry(endpoint)?.inbound {
            return Err(Error::Invalid);
        }
        self.ipv6_server_maintain(false);
        let e = self
            .ipv6_streams
            .entries
            .get(endpoint.slot)
            .ok_or(Error::Stale)?;
        if e.epoch != endpoint.epoch || endpoint.instance != self.ipv6_streams.instance {
            return Err(Error::Stale);
        }
        if let Some(error) = e.error {
            return Err(error);
        }
        if !e.live {
            return Err(Error::Stale);
        }
        Ok(endpoint.slot)
    }
    pub fn ipv6_stream_listen(&mut self, endpoint: Endpoint) -> Result<Status, Error> {
        let slot = self.ipv6_server_checked(endpoint)?;
        let e = &self.ipv6_streams.entries[slot];
        if e.started.is_some() {
            return Err(Error::Invalid);
        }
        let now = self.port.link.now_ms();
        if now < e.last_ms || now >= e.expires {
            let error = if now < e.last_ms {
                Error::Clock
            } else {
                Error::Timeout
            };
            self.ipv6_server_discard(endpoint);
            self.ipv6_streams.entries[slot].error = Some(error);
            return Err(error);
        }
        let local = self.ipv6_config().ok_or(Error::Denied)?.address;
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; BUFFER_BYTES]),
            tcp::SocketBuffer::new(vec![0; BUFFER_BYTES]),
        );
        socket.set_timeout(None);
        socket
            .listen((Ipv6Address::from(local), e.grant.local_port))
            .map_err(|_| Error::Invalid)?;
        let handle = self.sockets.add(socket);
        let e = &mut self.ipv6_streams.entries[slot];
        e.socket = Some(handle);
        e.started = Some(now);
        self.port.ipv6_tcp_peers[slot] = Some(Flow {
            local_port: e.grant.local_port,
            peer: e.grant.peer,
        });
        if let Some(rule) = &mut self.port.ipv6_server_rules[slot] {
            rule.expires = now
                .saturating_add(e.grant.connect_timeout_ms)
                .min(e.expires);
        }
        Ok(Status {
            connected: false,
            write_closed: false,
            peer_finished: false,
        })
    }
    pub fn ipv6_stream_accept(&mut self, endpoint: Endpoint) -> Result<Status, Error> {
        let slot = self.ipv6_server_checked(endpoint)?;
        let e = &self.ipv6_streams.entries[slot];
        if e.started.is_none() || e.accepted {
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
                Ipv6Address::from(e.grant.peer.ip).into(),
                e.grant.peer.port,
            ))
        {
            self.ipv6_server_discard(endpoint);
            return Err(Error::Denied);
        }
        self.ipv6_streams.entries[slot].accepted = true;
        if let Some(rule) = &mut self.port.ipv6_server_rules[slot] {
            rule.expires = self.ipv6_streams.entries[slot].expires;
        }
        self.port.stats.accepted += 1;
        self.ipv6_stream_status(endpoint)
    }
    pub fn ipv6_stream_server_fence(&mut self) {
        for slot in 0..self.ipv6_streams.entries.len() {
            if self.ipv6_streams.entries[slot].inbound {
                let endpoint = Endpoint {
                    instance: self.ipv6_streams.instance,
                    slot,
                    epoch: self.ipv6_streams.entries[slot].epoch,
                };
                self.ipv6_server_discard(endpoint);
                self.ipv6_streams.entries[slot]
                    .error
                    .get_or_insert(Error::Stale);
            }
        }
    }
    fn ipv6_server_discard(&mut self, endpoint: Endpoint) {
        if endpoint.instance != self.ipv6_streams.instance {
            return;
        }
        let Some(e) = self.ipv6_streams.entries.get_mut(endpoint.slot) else {
            return;
        };
        if e.epoch != endpoint.epoch || !e.inbound {
            return;
        }
        e.live = false;
        if let Some(h) = e.socket.take() {
            self.sockets.remove(h);
            self.port.stats.released += 1;
        }
        e.closing = None;
        self.port.ipv6_server_rules[endpoint.slot] = None;
        self.port.ipv6_tcp_peers[endpoint.slot] = None;
    }
    pub(super) fn ipv6_server_retire(
        &mut self,
        endpoint: Endpoint,
        abort: bool,
    ) -> Result<(), Error> {
        let slot = self.ipv6_server_checked(endpoint)?;
        let e = &mut self.ipv6_streams.entries[slot];
        e.live = false;
        if !abort
            && e.accepted
            && let Some(h) = e.socket
        {
            self.sockets.get_mut::<tcp::Socket>(h).close();
            e.closing = Some(self.port.link.now_ms());
        } else {
            self.ipv6_server_discard(endpoint);
        }
        Ok(())
    }
    pub(super) fn ipv6_server_maintain(&mut self, after_poll: bool) {
        if !self
            .ipv6_streams
            .entries
            .iter()
            .any(|e| e.inbound && (e.live || e.socket.is_some()))
        {
            return;
        }
        let now = self.port.link.now_ms();
        observe(&mut self.port.ipv6_server_rules, now, self.port.link.read());
        for slot in 0..self.ipv6_streams.entries.len() {
            let e = &mut self.ipv6_streams.entries[slot];
            if !e.inbound || (!e.live && e.socket.is_none()) {
                continue;
            }
            let fault = self.port.ipv6_server_rules[slot].and_then(|r| r.fault);
            e.last_ms = now;
            e.error = e.error.or(fault);
            let mut remove = e.error.is_some();
            if let Some(h) = e.socket {
                let socket = self.sockets.get_mut::<tcp::Socket>(h);
                let state = socket.state();
                if matches!(state, TcpState::Established | TcpState::CloseWait) {
                    e.connected = true;
                }
                if matches!(
                    state,
                    TcpState::CloseWait
                        | TcpState::Closing
                        | TcpState::LastAck
                        | TcpState::TimeWait
                ) {
                    e.peer_finished = true;
                }
                if e.live && e.started.is_some() && state == TcpState::Closed {
                    e.error.get_or_insert(Error::Closed);
                    remove = true;
                }
                if !e.live
                    && e.closing
                        .is_some_and(|start| now.saturating_sub(start) >= CLOSE_LINGER_MS)
                    || after_poll && !e.live && state == TcpState::Closed
                {
                    remove = true;
                }
            }
            if remove {
                e.live = false;
                if let Some(h) = e.socket.take() {
                    self.sockets.remove(h);
                    self.port.stats.released += 1;
                }
                e.closing = None;
                self.port.ipv6_tcp_peers[slot] = None;
                self.port.ipv6_server_rules[slot] = None;
            }
        }
    }
    fn ipv6_server_authorized(&mut self, endpoint: Endpoint, terminal_ack: bool) -> bool {
        self.ipv6_server_maintain(false);
        let now = self.port.link.now_ms();
        let link = self.port.link.read();
        let valid = self
            .ipv6_streams
            .entries
            .get(endpoint.slot)
            .is_some_and(|e| {
                endpoint.instance == self.ipv6_streams.instance
                    && e.epoch == endpoint.epoch
                    && e.inbound
                    && (e.live || terminal_ack)
                    && e.error.is_none()
                    && now >= e.last_ms
                    && now < e.expires
                    && link.is_some_and(|r| r.link_up && !r.disabled)
                    && self.port.ipv6_server_rules[endpoint.slot].is_none_or(|r| r.fault.is_none())
            });
        if valid {
            self.ipv6_streams.entries[endpoint.slot].last_ms = now;
        }
        valid
    }
}

pub struct Session {
    endpoint: Endpoint,
    peer: Address,
    terminal_ack: bool,
}
impl Session {
    pub fn grant<L: Link>(stack: &mut Stack<L>, grant: Grant) -> Result<Self, Error> {
        Ok(Self {
            endpoint: stack.ipv6_stream_server_grant(grant)?,
            peer: grant.peer,
            terminal_ack: false,
        })
    }
    pub fn request<L: Link>(
        &mut self,
        stack: &mut Stack<L>,
        request: &[u8],
        reply: &mut [u8; MAX_MESSAGE],
    ) -> usize {
        reply[..HEADER].fill(0);
        reply[0] = VERSION;
        reply[1] = request.get(1).copied().unwrap_or(0);
        reply[3] = FAMILY;
        reply[4..20].copy_from_slice(&self.peer.ip);
        reply[20..24].copy_from_slice(&self.peer.scope.to_be_bytes());
        reply[24..26].copy_from_slice(&self.peer.port.to_be_bytes());
        let result = (|| {
            if request.len() < HEADER
                || request[0] != VERSION
                || request[2] != 0
                || request[3] != FAMILY
            {
                return Err(Error::Invalid);
            }
            if request[4..20] != self.peer.ip
                || request[20..24] != self.peer.scope.to_be_bytes()
                || request[24..26] != self.peer.port.to_be_bytes()
            {
                return Err(Error::Denied);
            }
            let length = u16::from_be_bytes([request[26], request[27]]) as usize;
            if request[1] != WRITE && request.len() != HEADER {
                return Err(Error::Invalid);
            }
            match request[1] {
                LISTEN | ACCEPT | STATUS => {
                    if length != 0 {
                        return Err(Error::Invalid);
                    }
                    let status = match request[1] {
                        LISTEN => stack.ipv6_stream_listen(self.endpoint)?,
                        ACCEPT => stack.ipv6_stream_accept(self.endpoint)?,
                        _ => stack.ipv6_stream_status(self.endpoint)?,
                    };
                    reply[HEADER] = u8::from(status.connected)
                        | (u8::from(status.write_closed) << 1)
                        | (u8::from(status.peer_finished) << 2);
                    reply[26..28].copy_from_slice(&1u16.to_be_bytes());
                    Ok(1)
                }
                WRITE => {
                    if length > MAX_IO || request.len() != HEADER + length {
                        return Err(Error::Invalid);
                    }
                    let n = stack.ipv6_stream_write(self.endpoint, &request[HEADER..])?;
                    reply[26..28].copy_from_slice(&(n as u16).to_be_bytes());
                    Ok(0)
                }
                READ => {
                    if length == 0 || length > MAX_IO {
                        return Err(Error::Invalid);
                    }
                    let n = stack
                        .ipv6_stream_read(self.endpoint, &mut reply[HEADER..HEADER + length])?;
                    reply[26..28].copy_from_slice(&(n as u16).to_be_bytes());
                    Ok(n)
                }
                SHUTDOWN_WRITE | CLOSE | ABORT => {
                    if length != 0 {
                        return Err(Error::Invalid);
                    }
                    match request[1] {
                        SHUTDOWN_WRITE => stack.ipv6_stream_shutdown_write(self.endpoint)?,
                        CLOSE => stack.ipv6_stream_close(self.endpoint)?,
                        _ => stack.ipv6_stream_abort(self.endpoint)?,
                    };
                    if request[1] != SHUTDOWN_WRITE {
                        self.terminal_ack = true;
                    }
                    Ok(0)
                }
                _ => Err(Error::Invalid),
            }
        })();
        match result {
            Ok(n) => HEADER + n,
            Err(e) => {
                reply[2] = e.code();
                reply[26..28].fill(0);
                HEADER
            }
        }
    }
    pub fn revoke<L: Link>(&mut self, stack: &mut Stack<L>) {
        if !self.terminal_ack {
            stack.ipv6_server_discard(self.endpoint);
        }
    }
}
