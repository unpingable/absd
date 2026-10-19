//! Native exact-peer scoped IPv6 outbound TCP streams. Only the NIC holder constructs grants.
//! Clients use a dedicated pipe capability, never an engine socket or NIC.
pub use super::session::{FAMILY, HEADER, MAX_MESSAGE, VERSION};
use super::*;
pub use crate::stream::{
    ABORT, CLOSE, CONNECT, Error, READ, SHUTDOWN_WRITE, STATUS, Status, WRITE,
};
use smoltcp::wire::Ipv6Address;
pub mod channel;
pub mod client;
pub use channel::Channel;
pub use client::Client;
#[cfg(test)]
mod tests;
use core::sync::atomic::{AtomicU64, Ordering};
use smoltcp::socket::Socket as EngineSocket;

pub const MAX_ENDPOINTS: usize = 8;
pub const BUFFER_BYTES: usize = 1024;
// TCP requires a configured path at least as large as the Stack's immutable
// IP MTU (default 1500/MSS1440, opt-in 1280/MSS1220), including any explicit
// router. Smaller paths and dynamic PTB adaptation remain unsupported.
pub const MAX_IO: usize = 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub local_port: u16,
    pub peer: Address,
    /// 100..=10,000 ms from the first CONNECT request.
    pub connect_timeout_ms: u64,
    /// 100..=60,000 ms from grant construction, at least connect_timeout_ms.
    pub lifetime_ms: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    instance: u64,
    slot: usize,
    epoch: u64,
}
struct Entry {
    grant: Grant,
    epoch: u64,
    live: bool,
    socket: Option<SocketHandle>,
    started: Option<u64>,
    expires: u64,
    last_ms: u64,
    closing: Option<u64>,
    error: Option<Error>,
    connected: bool,
    write_closed: bool,
    peer_finished: bool,
}
pub(crate) struct Endpoints {
    instance: u64,
    next_epoch: u64,
    entries: Vec<Entry>,
}
static INSTANCE: AtomicU64 = AtomicU64::new(1);
impl Endpoints {
    pub(crate) fn new() -> Result<Self, NetError> {
        let instance = INSTANCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| NetError::Config)?;
        Ok(Self {
            instance,
            next_epoch: 1,
            entries: Vec::new(),
        })
    }
    pub(crate) fn active(&self) -> bool {
        self.entries.iter().any(|e| e.live || e.socket.is_some())
    }
    pub(super) fn reserved(&self, port: u16) -> bool {
        self.entries
            .iter()
            .any(|e| (e.live || e.socket.is_some()) && e.grant.local_port == port)
    }
    fn entry(&self, endpoint: Endpoint) -> Result<&Entry, Error> {
        if endpoint.instance != self.instance {
            return Err(Error::Stale);
        }
        self.entries
            .get(endpoint.slot)
            .filter(|e| e.epoch == endpoint.epoch && e.live)
            .ok_or(Error::Stale)
    }
    #[cfg(test)]
    pub(crate) fn set_epoch_for_test(&mut self, epoch: u64) {
        self.next_epoch = epoch;
    }
}
impl<L: Link> Stack<L> {
    /// Reserves authority/resources only; no TCP handshake until CONNECT.
    pub fn ipv6_stream_grant(&mut self, grant: Grant) -> Result<Endpoint, Error> {
        let config = self.ipv6_config().ok_or(Error::Denied)?;
        if grant.local_port < 1024
            || grant.peer.port == 0
            || grant.peer.scope != config.scope
            || !super::usable_address(grant.peer.ip)
            || grant.peer.ip == config.address
            || (!super::same_prefix(config.address, grant.peer.ip, config.prefix_len)
                && !self
                    .port
                    .ipv6_route
                    .as_ref()
                    .is_some_and(|route| route.route.peer == grant.peer))
        {
            return Err(Error::Denied);
        }
        if !(100..=10000).contains(&grant.connect_timeout_ms)
            || !(grant.connect_timeout_ms..=60000).contains(&grant.lifetime_ms)
        {
            return Err(Error::Invalid);
        }
        self.ipv6_stream_live()?;
        if self.ipv6_streams.reserved(grant.local_port)
            || self.sockets.iter().any(|(_, socket)| matches!(socket, EngineSocket::Tcp(s)
                if s.local_endpoint().is_some_and(|e| e.addr == IpAddress::Ipv6(Ipv6Address::from(config.address)) && e.port == grant.local_port)))
        { return Err(Error::InUse); }
        let vacant = self
            .ipv6_streams
            .entries
            .iter()
            .position(|e| !e.live && e.socket.is_none());
        if vacant.is_none() && self.ipv6_streams.entries.len() == MAX_ENDPOINTS {
            return Err(Error::Exhausted);
        }
        let now = self.port.link.now_ms();
        let expires = now.checked_add(grant.lifetime_ms).ok_or(Error::Invalid)?;
        let epoch = self.ipv6_streams.next_epoch;
        self.ipv6_streams.next_epoch = epoch.checked_add(1).ok_or(Error::Exhausted)?;
        let entry = Entry {
            grant,
            epoch,
            live: true,
            socket: None,
            started: None,
            expires,
            last_ms: now,
            closing: None,
            error: None,
            connected: false,
            write_closed: false,
            peer_finished: false,
        };
        let slot = if let Some(slot) = vacant {
            self.ipv6_streams.entries[slot] = entry;
            slot
        } else {
            self.ipv6_streams.entries.push(entry);
            self.ipv6_streams.entries.len() - 1
        };
        Ok(Endpoint {
            instance: self.ipv6_streams.instance,
            slot,
            epoch,
        })
    }
    fn ipv6_stream_live(&mut self) -> Result<(), Error> {
        let result = match self.read_link() {
            None => Err(Error::LinkUnknown),
            Some(r) if r.disabled => Err(Error::DeviceFailed),
            Some(r) if !r.link_up => Err(Error::LinkDown),
            Some(_) => Ok(()),
        };
        if result.is_err() {
            self.ipv6_fence();
            self.stream_fence();
            self.datagram_fence();
        }
        result
    }
    fn ipv6_stream_checked(&mut self, endpoint: Endpoint) -> Result<usize, Error> {
        self.ipv6_streams.entry(endpoint)?;
        self.ipv6_stream_live()?;
        self.ipv6_stream_maintain(false);
        let entry = self.ipv6_streams.entry(endpoint)?;
        if let Some(error) = entry.error {
            return Err(error);
        }
        Ok(endpoint.slot)
    }
    pub fn ipv6_stream_connect(&mut self, endpoint: Endpoint) -> Result<Status, Error> {
        let slot = self.ipv6_stream_checked(endpoint)?;
        if self.ipv6_streams.entries[slot].started.is_none() {
            let grant = self.ipv6_streams.entries[slot].grant;
            let address = self.ipv6_config().ok_or(Error::Denied)?.address;
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; BUFFER_BYTES]),
                tcp::SocketBuffer::new(vec![0; BUFFER_BYTES]),
            );
            socket.set_timeout(None); // this grant has explicit connect/lifetime deadlines
            socket
                .connect(
                    self.iface.context(),
                    (Ipv6Address::from(grant.peer.ip), grant.peer.port),
                    (Ipv6Address::from(address), grant.local_port),
                )
                .map_err(|_| Error::Invalid)?;
            let handle = self.sockets.add(socket);
            let now = self.port.link.now_ms();
            self.ipv6_streams.entries[slot].socket = Some(handle);
            self.port.ipv6_tcp_peers[slot] = Some(Flow {
                local_port: grant.local_port,
                peer: grant.peer,
            });
            self.ipv6_streams.entries[slot].started = Some(now);
            self.port.stats.connected += 1;
        }
        self.ipv6_stream_status(endpoint)
    }
    pub fn ipv6_stream_status(&mut self, endpoint: Endpoint) -> Result<Status, Error> {
        let slot = self.ipv6_stream_checked(endpoint)?;
        let e = &self.ipv6_streams.entries[slot];
        Ok(Status {
            connected: e.connected,
            write_closed: e.write_closed,
            peer_finished: e.peer_finished,
        })
    }
    /// Success means locally queued bytes, never peer/application receipt.
    pub fn ipv6_stream_write(&mut self, endpoint: Endpoint, bytes: &[u8]) -> Result<usize, Error> {
        let slot = self.ipv6_stream_checked(endpoint)?;
        let e = &self.ipv6_streams.entries[slot];
        if bytes.len() > MAX_IO {
            return Err(Error::Oversize);
        }
        if e.write_closed {
            return Err(Error::WriteClosed);
        }
        if !e.connected {
            return Err(Error::Again);
        }
        let socket = self
            .sockets
            .get_mut::<tcp::Socket>(e.socket.ok_or(Error::Closed)?);
        if !socket.may_send() {
            return Err(Error::Closed);
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        match socket.send_slice(bytes) {
            Ok(0) => Err(Error::Again),
            Ok(n) => Ok(n),
            Err(_) => Err(Error::Closed),
        }
    }
    pub fn ipv6_stream_read(
        &mut self,
        endpoint: Endpoint,
        bytes: &mut [u8],
    ) -> Result<usize, Error> {
        let slot = self.ipv6_stream_checked(endpoint)?;
        let e = &self.ipv6_streams.entries[slot];
        if bytes.is_empty() || bytes.len() > MAX_IO {
            return Err(Error::Invalid);
        }
        if !e.connected {
            return Err(Error::Again);
        }
        let socket = self
            .sockets
            .get_mut::<tcp::Socket>(e.socket.ok_or(Error::Closed)?);
        if !socket.can_recv() && e.peer_finished {
            return Err(Error::Eof);
        }
        match socket.recv_slice(bytes) {
            Ok(0) => Err(Error::Again),
            Ok(n) => Ok(n),
            Err(tcp::RecvError::Finished) => Err(Error::Eof),
            Err(_) => Err(Error::Closed),
        }
    }
    /// Sends FIN after queued data but retains read authority and this handle.
    pub fn ipv6_stream_shutdown_write(&mut self, endpoint: Endpoint) -> Result<(), Error> {
        let slot = self.ipv6_stream_checked(endpoint)?;
        let e = &mut self.ipv6_streams.entries[slot];
        if !e.connected {
            return Err(Error::Again);
        }
        if !e.write_closed {
            self.sockets
                .get_mut::<tcp::Socket>(e.socket.ok_or(Error::Closed)?)
                .close();
            e.write_closed = true;
        }
        Ok(())
    }
    fn ipv6_stream_retire(&mut self, endpoint: Endpoint, abort: bool) -> Result<(), Error> {
        self.ipv6_streams.entry(endpoint)?;
        let e = &mut self.ipv6_streams.entries[endpoint.slot];
        e.live = false;
        if e.socket.is_none() {
            self.port.ipv6_tcp_peers[endpoint.slot] = None;
        }
        if let Some(handle) = e.socket {
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            if abort {
                socket.abort();
                self.port.stats.reset += 1;
            } else {
                socket.close();
            }
            e.closing = Some(self.port.link.now_ms());
        }
        Ok(())
    }
    pub fn ipv6_stream_close(&mut self, endpoint: Endpoint) -> Result<(), Error> {
        self.ipv6_stream_retire(endpoint, false)
    }
    pub fn ipv6_stream_abort(&mut self, endpoint: Endpoint) -> Result<(), Error> {
        self.ipv6_stream_retire(endpoint, true)
    }
    /// Local fencing discards queues; it cannot recall externally emitted data.
    pub fn ipv6_stream_fence(&mut self) {
        self.port.ipv6_tcp_peers.fill(None);
        for e in &mut self.ipv6_streams.entries {
            e.live = false;
            if let Some(h) = e.socket.take() {
                self.sockets.remove(h);
                self.port.stats.released += 1;
            }
        }
    }
    pub(crate) fn ipv6_stream_maintain(&mut self, after_poll: bool) {
        let now = self.port.link.now_ms();
        for (slot, e) in self.ipv6_streams.entries.iter_mut().enumerate() {
            let mut aborted_now = false;
            let boundary = if now < e.last_ms {
                Some(Error::Clock)
            } else if now >= e.expires {
                Some(Error::Timeout)
            } else {
                None
            };
            if !e.live
                && e.socket.is_some()
                && let Some(error) = boundary
            {
                // A spent application reference needs no terminal reply.
                // Retire immediately: smoltcp abort alone retains buffers,
                // whereas removing the socket discards all queued bytes.
                e.error = e.error.or(Some(error));
                e.last_ms = now;
                self.sockets.remove(e.socket.take().unwrap());
                e.closing = None;
                self.port.ipv6_tcp_peers[slot] = None;
                self.port.stats.released += 1;
                continue;
            }
            // CLOSE spends application authority, but its retained queue
            // remains inside the original grant's clock/lifetime bounds.
            // Set the first error and abort once; later phases must not
            // rearm that reset or keep the closing slot alive indefinitely.
            if (e.live || e.socket.is_some()) && e.error.is_none() {
                e.error = boundary;
                e.last_ms = now;
                if let Some(handle) = e.socket {
                    let socket = self.sockets.get_mut::<tcp::Socket>(handle);
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
                    if e.live && !e.connected && e.error.is_none() {
                        if state == TcpState::Closed {
                            e.error = Some(Error::Closed);
                        } else if e.started.is_some_and(|start| {
                            now.saturating_sub(start) >= e.grant.connect_timeout_ms
                        }) {
                            e.error = Some(Error::Timeout);
                        }
                    }
                    if e.live
                        && e.connected
                        && state == TcpState::Closed
                        && !e.peer_finished
                        && e.error.is_none()
                    {
                        e.error = Some(Error::Closed);
                    }
                    if e.error.is_some() {
                        socket.abort();
                        e.closing = Some(now);
                        aborted_now = true;
                    }
                }
            }
            if let Some(handle) = e.socket {
                let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                let state = socket.state();
                // An aborted socket is Closed immediately, but smoltcp emits
                // its reset during poll. Preserve that single opportunity;
                // authority is already spent and Closed cannot transmit data.
                if after_poll && !aborted_now && e.closing.is_some() && state == TcpState::Closed {
                    self.sockets.remove(handle);
                    e.socket = None;
                    e.closing = None;
                    self.port.ipv6_tcp_peers[slot] = None;
                    self.port.stats.released += 1;
                } else if state != TcpState::Closed
                    && e.closing
                        .is_some_and(|start| now.saturating_sub(start) >= CLOSE_LINGER_MS)
                {
                    socket.abort(); // bounded release on the next maintenance pass
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Flow {
    pub(crate) local_port: u16,
    pub(crate) peer: Address,
}

/// One implicit endpoint per service channel; no endpoint selector in requests.
pub struct Session {
    endpoint: Endpoint,
    peer: Address,
}
impl Session {
    pub fn grant<L: Link>(stack: &mut Stack<L>, grant: Grant) -> Result<Self, Error> {
        Ok(Self {
            endpoint: stack.ipv6_stream_grant(grant)?,
            peer: grant.peer,
        })
    }
    pub fn revoke<L: Link>(&mut self, stack: &mut Stack<L>) {
        let _ = stack.ipv6_stream_abort(self.endpoint);
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
                || (request[2] != 0 || request[3] != FAMILY)
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
                CONNECT | STATUS => {
                    if length != 0 {
                        return Err(Error::Invalid);
                    }
                    let status = if request[1] == CONNECT {
                        stack.ipv6_stream_connect(self.endpoint)?
                    } else {
                        stack.ipv6_stream_status(self.endpoint)?
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
}

/// This TCP profile retains its exact Flow filter and physical 1500-byte
/// ceiling. The device boundary applies a Stack's smaller selected MTU before
/// this predicate, and the engine derives MSS from that immutable MTU. No extension headers,
/// fragments, listener or ICMPv6 PTB behavior is implied. An off-link flow still
/// requires its separate exact route and stream grant before it reaches here.
pub(crate) fn ingress(
    frame: &[u8],
    config: Option<super::Config>,
    flows: &[Option<Flow>; MAX_ENDPOINTS],
) -> bool {
    let Some(config) = config else {
        return false;
    };
    if frame.len() < 74 || frame[12..14] != [0x86, 0xdd] || frame[14] >> 4 != 6 || frame[20] != 6 {
        return false;
    }
    let length = usize::from(u16::from_be_bytes([frame[18], frame[19]]));
    if !(20..=1460).contains(&length)
        || frame.len() < 54 + length
        || frame[38..54] != config.address
    {
        return false;
    }
    let source_port = u16::from_be_bytes([frame[54], frame[55]]);
    let target_port = u16::from_be_bytes([frame[56], frame[57]]);
    flows.iter().flatten().any(|flow| {
        flow.peer.scope == config.scope
            && frame[22..38] == flow.peer.ip
            && flow.peer.port == source_port
            && flow.local_port == target_port
    })
}
