//! Native outbound TCP streams. Only the NIC holder constructs grants.
//! Clients use a dedicated pipe capability, never an engine socket or NIC.
use super::*;
use crate::datagram::Address;
use core::sync::atomic::{AtomicU64, Ordering};
use smoltcp::socket::Socket as EngineSocket;

pub const MAX_ENDPOINTS: usize = 8;
pub const BUFFER_BYTES: usize = 8192;
pub const MAX_IO: usize = 1024;
pub const MAX_MESSAGE: usize = MAX_IO + 12;
pub const VERSION: u8 = 1;
pub const CONNECT: u8 = 16;
pub const STATUS: u8 = 17;
pub const WRITE: u8 = 18;
pub const READ: u8 = 19;
pub const SHUTDOWN_WRITE: u8 = 20;
pub const CLOSE: u8 = 21;
pub const ABORT: u8 = 22;

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
pub enum Error {
    Invalid,
    Denied,
    InUse,
    Exhausted,
    Again,
    Eof,
    Closed,
    Stale,
    Timeout,
    LinkDown,
    DeviceFailed,
    LinkUnknown,
    WriteClosed,
    Oversize,
    Clock,
    /// Local framed IPC failed; a WRITE may already have queued bytes.
    Channel(i64),
}
impl Error {
    pub fn code(self) -> u8 {
        match self {
            Self::Invalid => 1,
            Self::Denied => 2,
            Self::InUse => 3,
            Self::Exhausted => 4,
            Self::Again => 5,
            Self::Eof => 6,
            Self::Closed => 7,
            Self::Stale => 8,
            Self::Timeout => 9,
            Self::LinkDown => 10,
            Self::DeviceFailed => 11,
            Self::LinkUnknown => 12,
            Self::WriteClosed => 13,
            Self::Oversize => 14,
            Self::Clock => 15,
            Self::Channel(_) => 16,
        }
    }
    fn decode(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Invalid,
            2 => Self::Denied,
            3 => Self::InUse,
            4 => Self::Exhausted,
            5 => Self::Again,
            6 => Self::Eof,
            7 => Self::Closed,
            8 => Self::Stale,
            9 => Self::Timeout,
            10 => Self::LinkDown,
            11 => Self::DeviceFailed,
            12 => Self::LinkUnknown,
            13 => Self::WriteClosed,
            14 => Self::Oversize,
            15 => Self::Clock,
            _ => return None,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub connected: bool,
    pub write_closed: bool,
    pub peer_finished: bool,
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
    inbound: bool,
    accepted: bool,
}
pub(super) struct Endpoints {
    instance: u64,
    next_epoch: u64,
    entries: Vec<Entry>,
}
static INSTANCE: AtomicU64 = AtomicU64::new(1);
impl Endpoints {
    pub(super) fn new() -> Result<Self, NetError> {
        let instance = INSTANCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| NetError::Config)?;
        Ok(Self {
            instance,
            next_epoch: 1,
            entries: Vec::new(),
        })
    }
    pub(super) fn active(&self) -> bool {
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
    pub fn stream_grant(&mut self, grant: Grant) -> Result<Endpoint, Error> {
        let ip = u32::from_be_bytes(grant.peer.ip);
        let local = u32::from_be_bytes(self.config.address.octets());
        let mask = u32::MAX << (32 - self.config.prefix_len);
        let subnet = local & mask;
        if grant.local_port < 1024
            || grant.peer.port == 0
            || grant.peer.ip[0] == 0
            || grant.peer.ip[0] == 127
            || grant.peer.ip[0] >= 224
            || ip == local
            || ip == subnet
            || ip == (subnet | !mask)
            || (ip & mask != subnet && self.config.gateway.is_none())
            || !(100..=10000).contains(&grant.connect_timeout_ms)
            || !(grant.connect_timeout_ms..=60000).contains(&grant.lifetime_ms)
        {
            return Err(Error::Invalid);
        }
        if self.streams.reserved(grant.local_port)
            || self.listeners.iter().any(|entry| entry.port == grant.local_port)
            || self.sockets.iter().any(|(_,socket)| {
            matches!(socket,EngineSocket::Tcp(s) if s.local_endpoint().is_some_and(|e|e.port==grant.local_port))
        }) {return Err(Error::InUse)}
        let vacant = self
            .streams
            .entries
            .iter()
            .position(|e| !e.live && e.socket.is_none());
        if vacant.is_none() && self.streams.entries.len() == MAX_ENDPOINTS {
            return Err(Error::Exhausted);
        }
        let now = self.port.link.now_ms();
        let expires = now.checked_add(grant.lifetime_ms).ok_or(Error::Invalid)?;
        let epoch = self.streams.next_epoch;
        self.streams.next_epoch = epoch.checked_add(1).ok_or(Error::Exhausted)?;
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
            inbound: false,
            accepted: false,
        };
        let slot = if let Some(slot) = vacant {
            self.streams.entries[slot] = entry;
            slot
        } else {
            self.streams.entries.push(entry);
            self.streams.entries.len() - 1
        };
        Ok(Endpoint {
            instance: self.streams.instance,
            slot,
            epoch,
        })
    }
    fn stream_live(&mut self) -> Result<(), Error> {
        let result = match self.read_link() {
            None => Err(Error::LinkUnknown),
            Some(r) if r.disabled => Err(Error::DeviceFailed),
            Some(r) if !r.link_up => Err(Error::LinkDown),
            Some(_) => Ok(()),
        };
        if result.is_err() {
            self.stream_fence();
            self.datagram_fence();
            self.ipv6_fence();
        }
        result
    }
    fn stream_checked(&mut self, endpoint: Endpoint) -> Result<usize, Error> {
        self.streams.entry(endpoint)?;
        self.stream_live()?;
        self.stream_maintain(false);
        let entry = self.streams.entry(endpoint)?;
        if let Some(error) = entry.error {
            return Err(error);
        }
        Ok(endpoint.slot)
    }
    pub fn stream_connect(&mut self, endpoint: Endpoint) -> Result<Status, Error> {
        let slot = self.stream_checked(endpoint)?;
        if self.streams.entries[slot].inbound {
            return Err(Error::Denied);
        }
        if self.streams.entries[slot].started.is_none() {
            let grant = self.streams.entries[slot].grant;
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; BUFFER_BYTES]),
                tcp::SocketBuffer::new(vec![0; BUFFER_BYTES]),
            );
            socket.set_timeout(None); // this grant has explicit connect/lifetime deadlines
            socket
                .connect(
                    self.iface.context(),
                    (Ipv4Address::from(grant.peer.ip), grant.peer.port),
                    grant.local_port,
                )
                .map_err(|_| Error::Invalid)?;
            let handle = self.sockets.add(socket);
            let now = self.port.link.now_ms();
            self.streams.entries[slot].socket = Some(handle);
            self.streams.entries[slot].started = Some(now);
            self.port.stats.connected += 1;
        }
        self.stream_status(endpoint)
    }
    pub fn stream_status(&mut self, endpoint: Endpoint) -> Result<Status, Error> {
        let slot = self.stream_checked(endpoint)?;
        let e = &self.streams.entries[slot];
        Ok(Status {
            connected: e.connected,
            write_closed: e.write_closed,
            peer_finished: e.peer_finished,
        })
    }
    /// Success means locally queued bytes, never peer/application receipt.
    pub fn stream_write(&mut self, endpoint: Endpoint, bytes: &[u8]) -> Result<usize, Error> {
        let slot = self.stream_checked(endpoint)?;
        let e = &self.streams.entries[slot];
        if bytes.len() > MAX_IO {
            return Err(Error::Oversize);
        }
        if e.write_closed {
            return Err(Error::WriteClosed);
        }
        if !e.connected || (e.inbound && !e.accepted) {
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
    pub fn stream_read(&mut self, endpoint: Endpoint, bytes: &mut [u8]) -> Result<usize, Error> {
        let slot = self.stream_checked(endpoint)?;
        let e = &self.streams.entries[slot];
        if bytes.is_empty() || bytes.len() > MAX_IO {
            return Err(Error::Invalid);
        }
        if !e.connected || (e.inbound && !e.accepted) {
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
    pub fn stream_shutdown_write(&mut self, endpoint: Endpoint) -> Result<(), Error> {
        let slot = self.stream_checked(endpoint)?;
        let e = &mut self.streams.entries[slot];
        if !e.connected || (e.inbound && !e.accepted) {
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
    fn stream_retire(&mut self, endpoint: Endpoint, abort: bool) -> Result<(), Error> {
        self.streams.entry(endpoint)?;
        let e = &mut self.streams.entries[endpoint.slot];
        e.live = false;
        if e.socket.is_none() {
            self.port.server_rules[endpoint.slot] = None;
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
    pub fn stream_close(&mut self, endpoint: Endpoint) -> Result<(), Error> {
        self.stream_retire(endpoint, false)
    }
    pub fn stream_abort(&mut self, endpoint: Endpoint) -> Result<(), Error> {
        if self.streams.entry(endpoint)?.inbound {
            let e = &mut self.streams.entries[endpoint.slot];
            e.live = false;
            if let Some(handle) = e.socket.take() {
                self.sockets.remove(handle);
                self.port.stats.released += 1;
            }
            e.closing = None;
            self.port.server_rules[endpoint.slot] = None;
            return Ok(());
        }
        self.stream_retire(endpoint, true)
    }
    /// Local fencing discards queues; it cannot recall externally emitted data.
    pub fn stream_fence(&mut self) {
        self.port.server_rules.fill(None);
        for e in &mut self.streams.entries {
            e.live = false;
            if e.inbound {
                e.error.get_or_insert(Error::Stale);
            }
            if let Some(h) = e.socket.take() {
                self.sockets.remove(h);
                self.port.stats.released += 1;
            }
        }
    }
    pub(super) fn stream_maintain(&mut self, after_poll: bool) {
        let now = self.port.link.now_ms();
        for (slot, e) in self.streams.entries.iter_mut().enumerate() {
            // Inbound authority also bounds retained graceful-close queues.
            // Removing the socket discards data; no reset opportunity survives.
            if e.inbound && (e.live || e.socket.is_some()) {
                let boundary =
                    if let Some(error) = self.port.server_rules[slot].and_then(|r| r.fault) {
                        Some(error)
                    } else if now < e.last_ms {
                        Some(Error::Clock)
                    } else if now >= e.expires
                        || (!e.accepted
                            && e.started.is_some_and(|start| {
                                now.saturating_sub(start) >= e.grant.connect_timeout_ms
                            }))
                    {
                        Some(Error::Timeout)
                    } else {
                        None
                    };
                if let Some(error) = boundary {
                    e.error.get_or_insert(error);
                    e.last_ms = now;
                    if let Some(handle) = e.socket.take() {
                        self.sockets.remove(handle);
                        self.port.stats.released += 1;
                    }
                    e.closing = None;
                    self.port.server_rules[slot] = None;
                    continue;
                }
                e.last_ms = now;
            }
            let mut aborted_now = false;
            if e.live && e.error.is_none() {
                e.error = if now < e.last_ms {
                    Some(Error::Clock)
                } else if now >= e.expires {
                    Some(Error::Timeout)
                } else {
                    None
                };
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
                    if !e.connected && e.error.is_none() {
                        if state == TcpState::Closed {
                            e.error = Some(Error::Closed);
                        } else if e.started.is_some_and(|start| {
                            now.saturating_sub(start) >= e.grant.connect_timeout_ms
                        }) {
                            e.error = Some(Error::Timeout);
                        }
                    }
                    if e.connected
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
                    self.port.server_rules[slot] = None;
                    e.closing = None;
                    self.port.stats.released += 1;
                } else if e
                    .closing
                    .is_some_and(|start| now.saturating_sub(start) >= CLOSE_LINGER_MS)
                {
                    socket.abort(); // bounded release on the next maintenance pass
                }
            }
        }
    }
}

/// One implicit endpoint per service channel; no endpoint selector in requests.
pub struct Session {
    endpoint: Endpoint,
    peer: Address,
    inbound: bool,
}
impl Session {
    pub fn grant<L: Link>(stack: &mut Stack<L>, grant: Grant) -> Result<Self, Error> {
        Ok(Self {
            endpoint: stack.stream_grant(grant)?,
            peer: grant.peer,
            inbound: false,
        })
    }
    pub fn revoke<L: Link>(&mut self, stack: &mut Stack<L>) {
        let _ = stack.stream_abort(self.endpoint);
    }
    pub fn request<L: Link>(
        &mut self,
        stack: &mut Stack<L>,
        request: &[u8],
        reply: &mut [u8; crate::datagram::MAX_MESSAGE],
    ) -> usize {
        reply[..12].fill(0);
        let version = if self.inbound {
            server::VERSION
        } else {
            VERSION
        };
        let family = if self.inbound { 4 } else { 0 };
        reply[0] = version;
        reply[3] = family;
        reply[1] = request.get(1).copied().unwrap_or(0);
        reply[4..8].copy_from_slice(&self.peer.ip);
        reply[8..10].copy_from_slice(&self.peer.port.to_be_bytes());
        let result = (|| {
            if request.len() < 12
                || request[0] != version
                || request[2] != 0
                || request[3] != family
            {
                return Err(Error::Invalid);
            }
            if request[4..8] != self.peer.ip || request[8..10] != self.peer.port.to_be_bytes() {
                return Err(Error::Denied);
            }
            let length = u16::from_be_bytes([request[10], request[11]]) as usize;
            if request[1] != WRITE && request.len() != 12 {
                return Err(Error::Invalid);
            }
            match request[1] {
                CONNECT | STATUS | server::LISTEN | server::ACCEPT => {
                    if length != 0 {
                        return Err(Error::Invalid);
                    }
                    let status = match request[1] {
                        CONNECT if !self.inbound => stack.stream_connect(self.endpoint)?,
                        server::LISTEN if self.inbound => stack.stream_listen(self.endpoint)?,
                        server::ACCEPT if self.inbound => stack.stream_accept(self.endpoint)?,
                        STATUS => stack.stream_status(self.endpoint)?,
                        _ => return Err(Error::Invalid),
                    };
                    reply[12] = u8::from(status.connected)
                        | (u8::from(status.write_closed) << 1)
                        | (u8::from(status.peer_finished) << 2);
                    reply[10..12].copy_from_slice(&1u16.to_be_bytes());
                    Ok(1)
                }
                WRITE => {
                    if length > MAX_IO || request.len() != 12 + length {
                        return Err(Error::Invalid);
                    }
                    let n = stack.stream_write(self.endpoint, &request[12..])?;
                    reply[10..12].copy_from_slice(&(n as u16).to_be_bytes());
                    Ok(0)
                }
                READ => {
                    if length == 0 || length > MAX_IO {
                        return Err(Error::Invalid);
                    }
                    let n = stack.stream_read(self.endpoint, &mut reply[12..12 + length])?;
                    reply[10..12].copy_from_slice(&(n as u16).to_be_bytes());
                    Ok(n)
                }
                SHUTDOWN_WRITE | CLOSE | ABORT => {
                    if length != 0 {
                        return Err(Error::Invalid);
                    }
                    match request[1] {
                        SHUTDOWN_WRITE => stack.stream_shutdown_write(self.endpoint)?,
                        CLOSE => stack.stream_close(self.endpoint)?,
                        _ => stack.stream_abort(self.endpoint)?,
                    };
                    Ok(0)
                }
                _ => Err(Error::Invalid),
            }
        })();
        match result {
            Ok(n) => 12 + n,
            Err(e) => {
                reply[2] = e.code();
                reply[10..12].fill(0);
                12
            }
        }
    }
}
pub mod channel;
pub mod client;
pub use client::Client;

pub mod server;
