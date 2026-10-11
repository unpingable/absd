//! IPv4 and TCP for one ABSD process: smoltcp 0.14 over the kernel's NIC
//! frame calls (kernel `docs/NETWORK.md`).
//!
//! The kernel moves whole Ethernet frames and nothing else. This crate is
//! the protocol stack, linked into the one process that holds the NIC
//! handle: ARP, IPv4 (static address, no fragments), ICMP echo replies, and
//! TCP. There is no `std::net` behind it and no socket object in the
//! kernel; a connection is a smoltcp socket inside this process.
//!
//! The process drives it with a poll loop:
//!
//! ```text
//! let mut stack = Stack::open(NicLink::from_startup()?, Config::qemu_user())?;
//! let listener = stack.listen(22, 2)?;
//! loop {
//!     stack.poll();
//!     while let Some(connection) = stack.accept(listener) { ... }
//!     // recv / send / close on connections; never block here
//!     stack.wait(10);
//! }
//! ```
//!
//! `poll` runs smoltcp once at the tick clock's millisecond; `wait` blocks
//! in `nic_receive` for at most min(smoltcp's next timer, `max_ms`, 10) ms
//! and at least one tick, and keeps a frame that arrives for the next
//! `poll`. A link that fails instead of blocking (a disabled NIC answers
//! every call at once) still waits out the bound on the local clock, so a
//! dead link degrades the loop to the idle cadence and cannot spin it.
//! `recv` and `send` never block: `Ok(0)` means "nothing now".

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use smoltcp::iface::{Config as IfaceConfig, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};

pub use smoltcp::socket::tcp::State as TcpState;
pub use smoltcp::wire::Ipv4Address;

/// Largest frame the NIC ABI carries: header plus a 1500-byte payload.
pub const FRAME_MAX: usize = 1514;
/// Longest single wait `wait` ever makes.
pub const MAX_WAIT_MS: u64 = 10;
/// Raw frames of a diverted EtherType kept for the application.
const RAW_QUEUE: usize = 16;
/// A connection the application closed is dropped after this long even if
/// the peer never finishes the close (FIN-WAIT-2 has no timer of its own).
const CLOSE_LINGER_MS: u64 = 30_000;
/// A connection that receives nothing for this long is aborted by smoltcp,
/// whatever its state: a half-open handshake, a passive idle established
/// connection, or one with unacknowledged data.
const TCP_TIMEOUT_MS: u64 = 60_000;

/// What the stack needs from a NIC. [`NicLink`] is the kernel's; tests use
/// an in-memory pair.
pub trait Link {
    fn mac(&self) -> [u8; 6];
    /// Sends one frame of 14..=1514 bytes.
    fn send(&mut self, frame: &[u8]) -> Result<(), i64>;
    /// The next frame's length. `timeout_ms` 0 polls; otherwise waits at
    /// most that long. `Ok(None)` when nothing arrived.
    fn receive(
        &mut self,
        buffer: &mut [u8; FRAME_MAX],
        timeout_ms: u64,
    ) -> Result<Option<usize>, i64>;
    /// Milliseconds on a monotonic clock.
    fn now_ms(&self) -> u64;
    /// Waits out `ms` on the local clock. `Stack::wait` falls back to this
    /// only when `receive` could not block because the link failed
    /// immediately, so a dead link degrades the poll loop to the ordinary
    /// idle cadence instead of a spin.
    fn pause(&self, ms: u64);
    /// Whether the link has carrier right now. A link that cannot tell
    /// reports true; the in-memory pair always has carrier.
    fn link_up(&self) -> bool {
        true
    }
    /// Whether the device has disabled itself for the rest of the boot
    /// (the kernel's fail-closed NIC: every call answers -5 from then on).
    /// Distinct from a link without carrier, which recovers by itself. A
    /// link that cannot tell reports false.
    fn disabled(&self) -> bool {
        false
    }
}

/// The kernel NIC handle as a [`Link`]: `nic_send`, `nic_receive`, and the
/// tick clock (`absd_runtime::boot_millis`; one tick is about 1 ms, so a
/// `timeout_ms` is passed as that many ticks).
#[cfg(target_os = "absd")]
pub struct NicLink {
    handle: u64,
    mac: [u8; 6],
}

#[cfg(target_os = "absd")]
impl NicLink {
    /// The handle the startup record named (role 12).
    pub fn from_startup() -> Result<Self, NetError> {
        match absd_runtime::nic::handle() {
            0 => Err(NetError::NoNic),
            handle => Self::open(handle),
        }
    }

    /// Checks the NIC is not disabled and reads its MAC address. The link
    /// may be down: the kernel grants a present, initialized NIC whose
    /// link is down (`NIC LINK DOWN AT PROBE`), frames flow once carrier
    /// returns with nothing re-opened (shown on QEMU; whether a physical
    /// NIC completes transmit descriptors without carrier is an open
    /// per-device obligation, kernel docs/NETWORK.md), and
    /// [`Link::link_up`] reads the live flag. Only a disabled NIC
    /// (`Nic(-5)`) refuses to open.
    pub fn open(handle: u64) -> Result<Self, NetError> {
        let info = absd_runtime::nic::info(handle).map_err(NetError::Nic)?;
        let flags = u16::from_le_bytes([info[6], info[7]]);
        if flags & absd_runtime::nic::FLAG_DISABLED != 0 {
            return Err(NetError::Nic(-5));
        }
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&info[..6]);
        Ok(Self { handle, mac })
    }

    pub fn handle(&self) -> u64 {
        self.handle
    }
}

#[cfg(target_os = "absd")]
impl Link for NicLink {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn send(&mut self, frame: &[u8]) -> Result<(), i64> {
        absd_runtime::nic::send(self.handle, frame)
    }

    fn receive(
        &mut self,
        buffer: &mut [u8; FRAME_MAX],
        timeout_ms: u64,
    ) -> Result<Option<usize>, i64> {
        match absd_runtime::nic::receive(self.handle, buffer, timeout_ms) {
            Ok(length) => Ok(Some(length)),
            Err(absd_runtime::nic::ERROR_AGAIN | absd_runtime::nic::ERROR_TIMEOUT) => Ok(None),
            Err(code) => Err(code),
        }
    }

    fn now_ms(&self) -> u64 {
        absd_runtime::boot_millis()
    }

    fn pause(&self, ms: u64) {
        // One tick is about 1 ms (kernel `nic_receive` timeouts are passed
        // the same way), so the existing sleep syscall is the wait.
        absd_runtime::sleep_ticks(ms);
    }

    fn link_up(&self) -> bool {
        absd_runtime::nic::info(self.handle).is_ok_and(|info| {
            u16::from_le_bytes([info[6], info[7]]) & absd_runtime::nic::FLAG_LINK_UP != 0
        })
    }

    fn disabled(&self) -> bool {
        absd_runtime::nic::info(self.handle).is_ok_and(|info| {
            u16::from_le_bytes([info[6], info[7]]) & absd_runtime::nic::FLAG_DISABLED != 0
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetError {
    /// The process was given no NIC handle.
    NoNic,
    /// A kernel refusal (negative code) from a NIC call.
    Nic(i64),
    /// The configuration is unusable (address, prefix, or gateway).
    Config,
    /// No such listener or connection (never issued, or already released).
    Unknown,
    /// The port is already listened on.
    InUse,
    /// The peer finished sending and everything it sent has been read.
    Finished,
    /// The connection is closed or was reset; nothing more moves.
    Closed,
}

/// A static IPv4 configuration.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub address: Ipv4Address,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Address>,
    /// Per-connection receive and send buffers, in bytes.
    pub rx_buffer: usize,
    pub tx_buffer: usize,
}

impl Config {
    /// QEMU's user network (`-netdev user`): 10.0.2.15/24, gateway 10.0.2.2.
    pub const fn qemu_user() -> Self {
        Self {
            address: Ipv4Address::new(10, 0, 2, 15),
            prefix_len: 24,
            gateway: Some(Ipv4Address::new(10, 0, 2, 2)),
            rx_buffer: 64 * 1024,
            tx_buffer: 64 * 1024,
        }
    }
}

/// Frame and connection counters since `open`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Frames taken from the link (diverted ones included).
    pub rx_frames: u64,
    /// Frames the stack or `raw_send` handed to the link.
    pub tx_frames: u64,
    /// Link calls that failed (the kernel's refusal is in `last_error`).
    pub link_errors: u64,
    pub last_error: i64,
    /// Frames of the diverted EtherType queued for the application, and
    /// those dropped because the queue was full.
    pub raw_frames: u64,
    pub raw_dropped: u64,
    pub accepted: u64,
    pub connected: u64,
    /// Connections released after a close or abort.
    pub released: u64,
    /// Connections that ended in a reset or timeout rather than a close.
    pub reset: u64,
}

/// The smoltcp device over a [`Link`], with one frame of look-ahead: a
/// frame `wait` received is kept here until the next `poll` takes it.
struct Port<L: Link> {
    link: L,
    rx: Box<[u8; FRAME_MAX]>,
    rx_length: Option<usize>,
    tx: Box<[u8; FRAME_MAX]>,
    divert: Option<[u8; 2]>,
    raw: VecDeque<Vec<u8>>,
    stats: Stats,
}

impl<L: Link> Port<L> {
    fn link_error(&mut self, code: i64) {
        self.stats.link_errors += 1;
        self.stats.last_error = code;
    }

    /// Takes the next frame off the link into `rx`, diverting frames of the
    /// application's EtherType. Returns whether a frame for smoltcp is held.
    /// `Err` is the link's own failure, already counted: the receive could
    /// not have blocked, so a caller that meant to wait must wait itself.
    fn fill(&mut self, timeout_ms: u64) -> Result<bool, i64> {
        if self.rx_length.is_some() {
            return Ok(true);
        }
        let mut timeout = timeout_ms;
        // Diverted frames do not count against the wait; a bounded number
        // are taken per call so a flood cannot hold the caller here.
        for _ in 0..RAW_QUEUE {
            match self.link.receive(&mut self.rx, timeout) {
                Ok(Some(length)) => {
                    self.stats.rx_frames += 1;
                    if let Some(kind) = self.divert
                        && length >= 14
                        && self.rx[12..14] == kind
                    {
                        if self.raw.len() < RAW_QUEUE {
                            self.raw.push_back(self.rx[..length].to_vec());
                            self.stats.raw_frames += 1;
                        } else {
                            self.stats.raw_dropped += 1;
                        }
                        timeout = 0;
                        continue;
                    }
                    self.rx_length = Some(length);
                    return Ok(true);
                }
                Ok(None) => return Ok(false),
                Err(code) => {
                    self.link_error(code);
                    return Err(code);
                }
            }
        }
        Ok(false)
    }
}

struct RxToken<'a> {
    frame: &'a [u8],
}

impl phy::RxToken for RxToken<'_> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(self.frame)
    }
}

struct TxToken<'a, L: Link> {
    link: &'a mut L,
    buffer: &'a mut [u8; FRAME_MAX],
    stats: &'a mut Stats,
}

impl<L: Link> phy::TxToken for TxToken<'_, L> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, length: usize, f: F) -> R {
        // smoltcp never builds more than the MTU it was given; a larger
        // request is still refused here rather than truncated.
        let length_ok = length <= FRAME_MAX;
        let result = f(&mut self.buffer[..length.min(FRAME_MAX)]);
        if !length_ok {
            self.stats.link_errors += 1;
            return result;
        }
        match self.link.send(&self.buffer[..length]) {
            Ok(()) => self.stats.tx_frames += 1,
            Err(code) => {
                self.stats.link_errors += 1;
                self.stats.last_error = code;
            }
        }
        result
    }
}

impl<L: Link> phy::Device for Port<L> {
    type RxToken<'a>
        = RxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = TxToken<'a, L>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.fill(0) != Ok(true) {
            return None;
        }
        let length = self.rx_length.take()?;
        Some((
            RxToken {
                frame: &self.rx[..length],
            },
            TxToken {
                link: &mut self.link,
                buffer: &mut self.tx,
                stats: &mut self.stats,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            link: &mut self.link,
            buffer: &mut self.tx,
            stats: &mut self.stats,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        capabilities.max_transmission_unit = FRAME_MAX;
        capabilities.max_burst_size = Some(1);
        capabilities
    }
}

/// A listening port, by table slot and generation. The epoch distinguishes
/// a live listener from a spent one whose slot a later `listen` reused; a
/// spent handle never names a live listener again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Listener {
    index: usize,
    epoch: u64,
}

/// One TCP connection. It stays valid until `close` or `abort`; after that
/// every call on it returns `NetError::Unknown`. The epoch distinguishes a
/// connection from an earlier one whose socket-set slot was recycled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Connection {
    handle: SocketHandle,
    epoch: u64,
}

struct ListenerEntry {
    port: u16,
    /// Bumped each time the slot is vacated, so a handle minted for an
    /// earlier generation never matches the slot again.
    epoch: u64,
    /// Sockets in LISTEN (or partway through a handshake) for this port.
    backlog: Vec<SocketHandle>,
}

struct Closing {
    handle: SocketHandle,
    since_ms: u64,
}

/// The protocol stack of one process.
pub struct Stack<L: Link> {
    port: Port<L>,
    iface: Interface,
    sockets: SocketSet<'static>,
    config: Config,
    listeners: Vec<ListenerEntry>,
    connections: Vec<(SocketHandle, u64)>,
    next_epoch: u64,
    closing: Vec<Closing>,
}

fn seed(link_mac: [u8; 6], now: u64) -> u64 {
    #[cfg(target_os = "absd")]
    if let Ok(id) = absd_runtime::boot_id() {
        return u64::from_le_bytes(id[..8].try_into().unwrap_or([0; 8])) ^ now;
    }
    let mut mac = [0u8; 8];
    mac[..6].copy_from_slice(&link_mac);
    u64::from_le_bytes(mac) ^ now.rotate_left(29) ^ 0x9e37_79b9_7f4a_7c15
}

impl<L: Link> Stack<L> {
    pub fn open(link: L, config: Config) -> Result<Self, NetError> {
        if config.prefix_len == 0
            || config.prefix_len > 30
            || config.rx_buffer == 0
            || config.tx_buffer == 0
        {
            return Err(NetError::Config);
        }
        let mac = link.mac();
        let now = link.now_ms();
        let mut port = Port {
            link,
            rx: Box::new([0; FRAME_MAX]),
            rx_length: None,
            tx: Box::new([0; FRAME_MAX]),
            divert: None,
            raw: VecDeque::new(),
            stats: Stats::default(),
        };
        let mut iface_config = IfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        iface_config.random_seed = seed(mac, now);
        let mut iface = Interface::new(iface_config, &mut port, Instant::from_millis(now as i64));
        let mut added = true;
        iface.update_ip_addrs(|addresses| {
            added = addresses
                .push(IpCidr::new(
                    IpAddress::Ipv4(config.address),
                    config.prefix_len,
                ))
                .is_ok();
        });
        if !added {
            return Err(NetError::Config);
        }
        if let Some(gateway) = config.gateway {
            iface
                .routes_mut()
                .add_default_ipv4_route(gateway)
                .map_err(|_| NetError::Config)?;
        }
        Ok(Self {
            port,
            iface,
            sockets: SocketSet::new(Vec::new()),
            config,
            listeners: Vec::new(),
            connections: Vec::new(),
            next_epoch: 1,
            closing: Vec::new(),
        })
    }

    pub fn mac(&self) -> [u8; 6] {
        self.port.link.mac()
    }

    pub fn config(&self) -> Config {
        self.config
    }

    pub fn stats(&self) -> Stats {
        self.port.stats
    }

    /// Sockets the stack holds: every listener's backlog, open connections,
    /// and connections still closing.
    pub fn socket_count(&self) -> usize {
        self.sockets.iter().count()
    }

    /// Whether the link has carrier right now ([`Link::link_up`]). A stack
    /// opened with the link down is complete and listening; it serves once
    /// carrier returns, with nothing re-opened.
    pub fn link_up(&self) -> bool {
        self.port.link.link_up()
    }

    /// Whether the NIC has disabled itself ([`Link::disabled`]): nothing
    /// will flow again this boot, every call fails at once, and `wait`
    /// paces the loop at the idle cadence. The caller decides what that
    /// means for its service; the stack only reports it.
    pub fn disabled(&self) -> bool {
        self.port.link.disabled()
    }

    pub fn link(&self) -> &L {
        &self.port.link
    }

    fn now(&self) -> Instant {
        Instant::from_millis(self.port.link.now_ms() as i64)
    }

    fn new_socket(&self) -> tcp::Socket<'static> {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; self.config.rx_buffer]),
            tcp::SocketBuffer::new(vec![0; self.config.tx_buffer]),
        );
        socket.set_timeout(Some(Duration::from_millis(TCP_TIMEOUT_MS)));
        socket
    }

    /// Runs smoltcp once: frames in, timers, frames out. Returns whether a
    /// socket may have changed state.
    pub fn poll(&mut self) -> bool {
        let now = self.now();
        let changed = self.iface.poll(now, &mut self.port, &mut self.sockets)
            == PollResult::SocketStateChanged;
        self.maintain();
        changed
    }

    /// Blocks until a frame arrives or smoltcp's next timer is due, for at
    /// most `max_ms` (and never more than [`MAX_WAIT_MS`]); at least one
    /// tick unless `max_ms` is 0. A frame that arrives is kept for `poll`.
    /// A link that fails instead of blocking still waits out the bound on
    /// the local clock: a dead link degrades the loop to the idle cadence,
    /// never to a spin, and the failure is counted in `stats().link_errors`.
    pub fn wait(&mut self, max_ms: u64) {
        if max_ms == 0 || self.port.rx_length.is_some() {
            return;
        }
        let now = self.now();
        let limit = max_ms.min(MAX_WAIT_MS);
        let delay = self
            .iface
            .poll_delay(now, &self.sockets)
            .map_or(limit, |delay| delay.total_millis());
        let bound = delay.clamp(1, limit);
        if self.port.fill(bound).is_err() {
            self.port.link.pause(bound);
        }
    }

    /// Re-arms listeners and releases connections whose close finished.
    fn maintain(&mut self) {
        for index in 0..self.listeners.len() {
            for slot in 0..self.listeners[index].backlog.len() {
                let handle = self.listeners[index].backlog[slot];
                let port = self.listeners[index].port;
                let socket = self.sockets.get_mut::<tcp::Socket>(handle);
                // A handshake reset by the peer leaves the socket closed:
                // listen on it again.
                if socket.state() == TcpState::Closed {
                    let _ = socket.listen(port);
                }
            }
        }
        let now = self.port.link.now_ms();
        let mut index = 0;
        while index < self.closing.len() {
            let entry = &self.closing[index];
            let socket = self.sockets.get_mut::<tcp::Socket>(entry.handle);
            let state = socket.state();
            let finished = matches!(state, TcpState::Closed | TcpState::TimeWait);
            if finished {
                let entry = self.closing.swap_remove(index);
                self.sockets.remove(entry.handle);
                self.port.stats.released += 1;
            } else if now.saturating_sub(entry.since_ms) > CLOSE_LINGER_MS {
                // The bound expired: abort, but release only on a later
                // pass, once the next `poll` has dispatched the reset —
                // removing the socket here would drop it silently.
                socket.abort();
                self.port.stats.reset += 1;
                index += 1;
            } else {
                index += 1;
            }
        }
    }

    /// Listens on `port` with `backlog` sockets (1..=8) ready to take
    /// handshakes; `accept` replaces each one it hands out. A slot vacated
    /// by `unlisten` is filled before the table grows, so a service that
    /// re-binds its port does not grow the table without bound.
    pub fn listen(&mut self, port: u16, backlog: usize) -> Result<Listener, NetError> {
        if port == 0 || !(1..=8).contains(&backlog) {
            return Err(NetError::Config);
        }
        if self.listeners.iter().any(|entry| entry.port == port) {
            return Err(NetError::InUse);
        }
        let mut sockets = Vec::with_capacity(backlog);
        for _ in 0..backlog {
            let mut socket = self.new_socket();
            socket.listen(port).map_err(|_| NetError::Config)?;
            sockets.push(self.sockets.add(socket));
        }
        if let Some(index) = self.listeners.iter().position(|entry| entry.port == 0) {
            let entry = &mut self.listeners[index];
            entry.port = port;
            entry.backlog = sockets;
            return Ok(Listener {
                index,
                epoch: entry.epoch,
            });
        }
        self.listeners.push(ListenerEntry {
            port,
            epoch: 0,
            backlog: sockets,
        });
        Ok(Listener {
            index: self.listeners.len() - 1,
            epoch: 0,
        })
    }

    /// Stops listening: every socket of the backlog (listening, or partway
    /// through a handshake nobody accepted) is dropped, so a later SYN to
    /// the port finds no socket and is answered with a reset. Connections
    /// already accepted are untouched. The listener is spent: `accept`
    /// returns nothing from it and a later `listen` reusing its table slot
    /// cannot revive it. The port can be listened on again.
    pub fn unlisten(&mut self, listener: Listener) -> Result<(), NetError> {
        let entry = match self.listeners.get_mut(listener.index) {
            Some(entry) if entry.epoch == listener.epoch && entry.port != 0 => entry,
            _ => return Err(NetError::Unknown),
        };
        entry.port = 0;
        entry.epoch += 1;
        for handle in core::mem::take(&mut entry.backlog) {
            self.sockets.get_mut::<tcp::Socket>(handle).abort();
            self.sockets.remove(handle);
        }
        Ok(())
    }

    /// Connections closed by the application whose close has not finished
    /// (the stack drops each once it has, or after a bound).
    pub fn closing_count(&self) -> usize {
        self.closing.len()
    }

    /// Listener table slots, live or vacated.
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    /// A connection whose handshake completed on `listener`, if any. Its
    /// backlog place is refilled with a fresh listening socket.
    pub fn accept(&mut self, listener: Listener) -> Option<Connection> {
        let entry = self.listeners.get(listener.index)?;
        if entry.epoch != listener.epoch {
            return None;
        }
        let port = entry.port;
        let position = entry.backlog.iter().position(|&handle| {
            !matches!(
                self.sockets.get::<tcp::Socket>(handle).state(),
                TcpState::Listen | TcpState::SynReceived | TcpState::Closed
            )
        })?;
        let handle = self.listeners[listener.index].backlog.swap_remove(position);
        let mut socket = self.new_socket();
        if socket.listen(port).is_ok() {
            let replacement = self.sockets.add(socket);
            self.listeners[listener.index].backlog.push(replacement);
        }
        let connection = self.mint_connection(handle);
        self.port.stats.accepted += 1;
        Some(connection)
    }

    /// Accepts the next connection permitted by `allow`, aborting refused
    /// connections before returning one to the application. The callback
    /// sees the peer endpoint, or `None` if the stack cannot identify it.
    /// A missing peer is always refused. This keeps refusal and socket
    /// release in one path, before the application creates a session slot.
    pub fn accept_filtered(
        &mut self,
        listener: Listener,
        mut allow: impl FnMut(Option<(Ipv4Address, u16)>) -> bool,
    ) -> Option<(Connection, (Ipv4Address, u16))> {
        while let Some(connection) = self.accept(listener) {
            let peer = self.remote(connection).ok().flatten();
            let permitted = allow(peer);
            if let (true, Some(peer)) = (permitted, peer) {
                return Some((connection, peer));
            }
            self.abort(connection).expect("accepted socket abort");
        }
        None
    }

    /// Starts a connection to `remote:port` from `local_port`; it is usable
    /// once `state` reports it established.
    pub fn connect(
        &mut self,
        remote: Ipv4Address,
        port: u16,
        local_port: u16,
    ) -> Result<Connection, NetError> {
        let mut socket = self.new_socket();
        socket
            .connect(
                self.iface.context(),
                (IpAddress::Ipv4(remote), port),
                local_port,
            )
            .map_err(|_| NetError::Config)?;
        let handle = self.sockets.add(socket);
        let connection = self.mint_connection(handle);
        self.port.stats.connected += 1;
        Ok(connection)
    }

    fn mint_connection(&mut self, handle: SocketHandle) -> Connection {
        let epoch = self.next_epoch;
        self.next_epoch += 1;
        self.connections.push((handle, epoch));
        Connection { handle, epoch }
    }

    fn socket(&mut self, connection: Connection) -> Result<&mut tcp::Socket<'static>, NetError> {
        if !self
            .connections
            .contains(&(connection.handle, connection.epoch))
        {
            return Err(NetError::Unknown);
        }
        Ok(self.sockets.get_mut::<tcp::Socket>(connection.handle))
    }

    pub fn state(&mut self, connection: Connection) -> Result<TcpState, NetError> {
        Ok(self.socket(connection)?.state())
    }

    /// An accepted service may opt out of the default 60-second transport
    /// timeout when it owns its own application deadlines. The default
    /// aborts any connection that receives nothing for 60 seconds, a
    /// passive idle one included; sshd opts out because it enforces its own
    /// idle deadline. Other consumers retain the default unless they
    /// explicitly opt out.
    pub fn disable_transport_timeout(&mut self, connection: Connection) -> Result<(), NetError> {
        self.socket(connection)?.set_timeout(None);
        Ok(())
    }

    pub fn remote(
        &mut self,
        connection: Connection,
    ) -> Result<Option<(Ipv4Address, u16)>, NetError> {
        Ok(self.socket(connection)?.remote_endpoint().map(|endpoint| {
            let IpAddress::Ipv4(address) = endpoint.addr;
            (address, endpoint.port)
        }))
    }

    /// Copies received bytes into `buffer`: `Ok(0)` when none are waiting,
    /// `Err(Finished)` once the peer's FIN has been reached,
    /// `Err(Closed)` after a reset or timeout.
    pub fn recv(&mut self, connection: Connection, buffer: &mut [u8]) -> Result<usize, NetError> {
        let socket = self.socket(connection)?;
        match socket.recv_slice(buffer) {
            Ok(count) => Ok(count),
            Err(tcp::RecvError::Finished) => Err(NetError::Finished),
            // Still opening: nothing yet, not an error.
            Err(tcp::RecvError::InvalidState)
                if matches!(socket.state(), TcpState::SynSent | TcpState::SynReceived) =>
            {
                Ok(0)
            }
            Err(tcp::RecvError::InvalidState) => Err(NetError::Closed),
        }
    }

    /// Queues as much of `bytes` as the send buffer has room for and
    /// returns that count (`Ok(0)` under backpressure).
    pub fn send(&mut self, connection: Connection, bytes: &[u8]) -> Result<usize, NetError> {
        let socket = self.socket(connection)?;
        if !socket.may_send() {
            return Err(NetError::Closed);
        }
        socket.send_slice(bytes).map_err(|_| NetError::Closed)
    }

    /// Free space in the send buffer.
    pub fn send_room(&mut self, connection: Connection) -> Result<usize, NetError> {
        let socket = self.socket(connection)?;
        Ok(socket.send_capacity() - socket.send_queue())
    }

    /// Bytes queued but not yet acknowledged by the peer.
    pub fn send_queue(&mut self, connection: Connection) -> Result<usize, NetError> {
        Ok(self.socket(connection)?.send_queue())
    }

    /// Whether the peer can still send (no FIN seen and not reset).
    pub fn may_recv(&mut self, connection: Connection) -> Result<bool, NetError> {
        Ok(self.socket(connection)?.may_recv())
    }

    fn retire(&mut self, connection: Connection, abort: bool) -> Result<(), NetError> {
        let socket = self.socket(connection)?;
        if abort {
            socket.abort();
            self.port.stats.reset += 1;
        } else {
            let state = socket.state();
            socket.close();
            if state == TcpState::Closed {
                // Reset or timed out before the application closed it.
                self.port.stats.reset += 1;
            }
        }
        self.connections
            .retain(|&entry| entry != (connection.handle, connection.epoch));
        let since_ms = self.port.link.now_ms();
        self.closing.push(Closing {
            handle: connection.handle,
            since_ms,
        });
        Ok(())
    }

    /// Sends FIN after everything queued. The stack releases the socket
    /// once the close completes (or after a bound); the handle is spent.
    pub fn close(&mut self, connection: Connection) -> Result<(), NetError> {
        self.retire(connection, false)
    }

    /// Sends RST and releases the socket at the next `poll`.
    pub fn abort(&mut self, connection: Connection) -> Result<(), NetError> {
        self.retire(connection, true)
    }

    /// Frames of `ethertype` bypass the stack and queue for `raw_receive`
    /// (at most 16; more are counted and dropped). For control traffic
    /// outside IPv4, such as a test harness's.
    pub fn divert(&mut self, ethertype: Option<u16>) {
        self.port.divert = ethertype.map(u16::to_be_bytes);
    }

    pub fn raw_receive(&mut self) -> Option<Vec<u8>> {
        self.port.raw.pop_front()
    }

    /// Sends one whole frame as given.
    pub fn raw_send(&mut self, frame: &[u8]) -> Result<(), NetError> {
        match self.port.link.send(frame) {
            Ok(()) => {
                self.port.stats.tx_frames += 1;
                Ok(())
            }
            Err(code) => {
                self.port.link_error(code);
                Err(NetError::Nic(code))
            }
        }
    }
}
