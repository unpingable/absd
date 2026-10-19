//! IPv4, TCP and bounded native UDP: smoltcp 0.14 over the kernel's NIC
//! frame calls (kernel `docs/NETWORK.md`).
//!
//! The kernel moves whole Ethernet frames and nothing else. This crate is
//! the protocol stack, linked into the one process that holds the NIC
//! handle: ARP, IPv4 (static address, no fragments), ICMP echo replies, and
//! TCP and UDP. There is no `std::net` behind it and no socket object in the
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
pub mod datagram;
#[cfg(feature = "dhcpv4")]
pub mod dhcp;
pub mod dns;
pub mod echo;
pub mod icmp;
pub mod ipv6;
pub mod sntp;
pub mod stream;
#[cfg(test)]
extern crate std;

#[cfg(test)]
mod mtu_tests;
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
    /// Sends one frame of 14..=1514 bytes. `Err(NIC_NO_CARRIER)` is the
    /// kernel's link outcome (no carrier; the NIC stays enabled); any other
    /// `Err` is a kernel refusal.
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
    /// Carrier, the disabled latch and the missed-frame counter from one
    /// `nic_info` call; `None` when the read was refused ("unknown": neither
    /// healthy nor disabled). The default has no counter.
    fn read(&self) -> Option<LinkReading> {
        Some(LinkReading {
            link_up: self.link_up(),
            disabled: self.disabled(),
            rx_missed: 0,
        })
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

    fn read(&self) -> Option<LinkReading> {
        absd_runtime::nic::info(self.handle)
            .ok()
            .map(|info| reading_from_info(&info))
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
    /// Frames refused before device delivery because they exceed this Stack's IP MTU.
    pub rx_oversize: u64,
    /// Frames the stack or `raw_send` handed to the link.
    pub tx_frames: u64,
    /// Whole device emissions refused locally before Link::send.
    pub tx_oversize: u64,
    /// Failed Link calls or refused oversized device emissions. A kernel
    /// refusal is in `last_error`; a local MTU refusal leaves it unchanged.
    pub link_errors: u64,
    pub last_error: i64,
    /// Sends the kernel refused for lack of carrier ([`NIC_NO_CARRIER`]):
    /// the frame was not reported done and the NIC is not disabled. Also
    /// counted in `link_errors`.
    pub no_carrier: u64,
    /// The last send was refused for lack of carrier; the kernel may still
    /// hold a descriptor (kernel docs/NETWORK.md). Cleared by any other send
    /// result: an accepted send, or a refusal such as a disabled NIC's.
    pub tx_held: bool,
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
    /// Immutable Ethernet capability; physical buffers remain FRAME_MAX bytes.
    frame_mtu: usize,
    rx: Box<[u8; FRAME_MAX]>,
    rx_length: Option<usize>,
    tx: Box<[u8; FRAME_MAX]>,
    divert: Option<[u8; 2]>,
    raw: VecDeque<Vec<u8>>,
    stats: Stats,
    feedback: icmp::Feedback,
    ipv6_feedback: ipv6::feedback::Feedback,
    ipv6_config: Option<ipv6::Config>,
    ipv6_route: Option<ipv6::routing::State>,
    ipv6_echo: Option<alloc::rc::Rc<core::cell::RefCell<ipv6::echo::Admission>>>,
    ipv6_responder: Option<alloc::rc::Rc<core::cell::RefCell<ipv6::echo_responder::Admission>>>,
    ipv6_peers: [Option<[u8; 16]>; ipv6::MAX_ENDPOINTS],
    ipv6_tcp_peers: [Option<ipv6::stream::Flow>; ipv6::stream::MAX_ENDPOINTS],
    server_rules: [Option<stream::server::Filter>; stream::MAX_ENDPOINTS],
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
            let received = self.link.receive(&mut self.rx, timeout);
            if self.server_rules.iter().any(Option::is_some) {
                stream::server::observe(&mut self.server_rules, self.link.now_ms());
                stream::server::observe_link(&mut self.server_rules, self.link.read());
            }
            match received {
                Ok(Some(length)) => {
                    self.stats.rx_frames += 1;
                    if length > self.frame_mtu {
                        self.stats.rx_oversize += 1;
                        timeout = 0;
                        continue;
                    }
                    if !stream::server::ingress(&self.rx[..length], &self.server_rules) {
                        timeout = 0;
                        continue;
                    }
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
                    let mut peers = [None; ipv6::MAX_ENDPOINTS + ipv6::stream::MAX_ENDPOINTS + 2];
                    peers[..ipv6::MAX_ENDPOINTS].copy_from_slice(&self.ipv6_peers);
                    if let Some(route) = &self.ipv6_route {
                        for peer in &mut peers[..ipv6::MAX_ENDPOINTS] {
                            if *peer == Some(route.route.peer.ip) {
                                *peer = Some(route.route.router);
                            }
                        }
                    }
                    for (slot, flow) in self.ipv6_tcp_peers.iter().enumerate() {
                        peers[ipv6::MAX_ENDPOINTS + slot] = flow.map(|flow| {
                            self.ipv6_route
                                .as_ref()
                                .filter(|route| route.route.peer == flow.peer)
                                .map_or(flow.peer.ip, |route| route.route.router)
                        });
                    }
                    peers[ipv6::MAX_ENDPOINTS + ipv6::stream::MAX_ENDPOINTS] = self
                        .ipv6_echo
                        .as_ref()
                        .and_then(|echo| echo.borrow().peer());
                    peers[ipv6::MAX_ENDPOINTS + ipv6::stream::MAX_ENDPOINTS + 1] = self
                        .ipv6_responder
                        .as_ref()
                        .and_then(|responder| responder.borrow().peer());
                    let frame = &self.rx[..length];
                    self.ipv6_feedback.received(frame, self.link.now_ms());
                    let tcp_v6 = length >= 54 && frame[12..14] == [0x86, 0xdd] && frame[20] == 6;
                    let admitted = if tcp_v6 {
                        ipv6::stream::ingress(frame, self.ipv6_config, &self.ipv6_tcp_peers)
                    } else {
                        let ordinary = if let Some(route) = &self.ipv6_route {
                            ipv6::ingress_router(
                                frame,
                                self.ipv6_config,
                                &peers,
                                route
                                    .active(&self.ipv6_tcp_peers)
                                    .then_some(route.route.router),
                            )
                        } else {
                            ipv6::ingress(frame, self.ipv6_config, &peers)
                        };
                        ordinary
                            || self
                                .ipv6_route
                                .as_ref()
                                .is_some_and(|route| route.ingress(frame, self.ipv6_config))
                            || self
                                .ipv6_echo
                                .as_ref()
                                .is_some_and(|echo| echo.borrow().accepts(frame))
                            || self
                                .ipv6_responder
                                .as_ref()
                                .is_some_and(|responder| responder.borrow_mut().admit(frame))
                    };
                    if !admitted {
                        timeout = 0;
                        continue;
                    }
                    if self.feedback.active() {
                        self.feedback
                            .received(&self.rx[..length], self.link.now_ms());
                    }
                    self.rx_length = Some(length);
                    return Ok(true);
                }
                Ok(None) => return Ok(false),
                Err(code) => {
                    self.ipv6_feedback.lost();
                    stream::server::observe_error(&mut self.server_rules, code);
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

/// The kernel's `nic_send` link outcome (kernel abi `ERROR_NO_CARRIER`): the
/// frame was not reported done because the link has no carrier; the NIC is
/// not disabled, and later sends may be refused the same way, at once,
/// until carrier returns. TCP repairs the loss; nothing here retries.
pub const NIC_NO_CARRIER: i64 = -100;

/// Counts one [`Link::send`] result.
fn count_send(stats: &mut Stats, sent: Result<(), i64>) {
    match sent {
        Ok(()) => {
            stats.tx_frames += 1;
            stats.tx_held = false;
        }
        Err(code) => {
            stats.link_errors += 1;
            stats.last_error = code;
            stats.tx_held = code == NIC_NO_CARRIER;
            if stats.tx_held {
                stats.no_carrier += 1;
            }
        }
    }
}

struct TxToken<'a, L: Link> {
    link: &'a mut L,
    frame_mtu: usize,
    buffer: &'a mut [u8; FRAME_MAX],
    stats: &'a mut Stats,
    feedback: &'a mut icmp::Feedback,
    ipv6_feedback: &'a mut ipv6::feedback::Feedback,
    server_rules: &'a mut [Option<stream::server::Filter>; stream::MAX_ENDPOINTS],
}

impl<L: Link> phy::TxToken for TxToken<'_, L> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, length: usize, f: F) -> R {
        // smoltcp never builds more than the MTU it was given; a larger
        // request is still refused here rather than truncated.
        let length_ok = length <= self.frame_mtu;
        // Pinned emitters leave some unused fields unwritten. Initialize
        // this frame so a preceding packet cannot supply those wire bytes.
        self.buffer[..length.min(FRAME_MAX)].fill(0);
        let result = f(&mut self.buffer[..length.min(FRAME_MAX)]);
        if !length_ok {
            self.stats.tx_oversize += 1;
            // Preserve the existing error observation/fencing boundary.
            self.stats.link_errors += 1;
            return result;
        }
        if self.server_rules.iter().any(Option::is_some) {
            stream::server::observe(self.server_rules, self.link.now_ms());
            stream::server::observe_link(self.server_rules, self.link.read());
            if !stream::server::egress(&self.buffer[..length], self.server_rules) {
                return result;
            }
        }
        let sent = self.link.send(&self.buffer[..length]);
        if let Err(code) = sent {
            stream::server::observe_error(self.server_rules, code);
        }
        if sent.is_ok() && self.feedback.active() {
            self.feedback
                .submitted(&self.buffer[..length], self.link.now_ms());
        }
        if sent.is_ok() {
            self.ipv6_feedback
                .submitted(&self.buffer[..length], self.link.now_ms());
        } else {
            self.ipv6_feedback.lost();
        }
        count_send(self.stats, sent);
        if self.server_rules.iter().any(Option::is_some) {
            stream::server::observe(self.server_rules, self.link.now_ms());
            stream::server::observe_link(self.server_rules, self.link.read());
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
        if self.server_rules.iter().any(Option::is_some) {
            stream::server::observe(&mut self.server_rules, self.link.now_ms());
            stream::server::observe_link(&mut self.server_rules, self.link.read());
        }
        if !stream::server::ingress(&self.rx[..length], &self.server_rules) {
            return None;
        }
        Some((
            RxToken {
                frame: &self.rx[..length],
            },
            TxToken {
                link: &mut self.link,
                frame_mtu: self.frame_mtu,
                buffer: &mut self.tx,
                stats: &mut self.stats,
                server_rules: &mut self.server_rules,
                feedback: &mut self.feedback,
                ipv6_feedback: &mut self.ipv6_feedback,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            link: &mut self.link,
            frame_mtu: self.frame_mtu,
            buffer: &mut self.tx,
            stats: &mut self.stats,
            feedback: &mut self.feedback,
            ipv6_feedback: &mut self.ipv6_feedback,
            server_rules: &mut self.server_rules,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        capabilities.max_transmission_unit = self.frame_mtu;
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
    datagrams: datagram::Endpoints,
    ipv6_datagrams: ipv6::Endpoints,
    ipv6_streams: ipv6::stream::Endpoints,
    streams: stream::Endpoints,
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
        Self::open_with_ip_mtu(link, config, 1500)
    }

    /// Construct one Stack with an immutable conservative IP MTU.
    ///
    /// Only the existing 1500-byte profile and explicit IPv6-minimum 1280-byte
    /// profile are supported. smoltcp snapshots this capability when its
    /// Interface is created, before any address, route or endpoint is active.
    /// This applies to both IP families in this private Stack; it is not a
    /// per-peer setting, learned PMTU or authority to reconfigure another owner.
    /// Physical Link buffers and ordinary Stack::open remain unchanged.
    /// This bounds all device RX, including diverted raw RX, and smoltcp TX.
    /// The owner's direct raw_send retains its separate Link authority.
    pub fn open_with_ip_mtu(link: L, config: Config, ip_mtu: usize) -> Result<Self, NetError> {
        if !matches!(ip_mtu, 1280 | 1500) {
            return Err(NetError::Config);
        }
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
            frame_mtu: ip_mtu + 14,
            rx: Box::new([0; FRAME_MAX]),
            rx_length: None,
            tx: Box::new([0; FRAME_MAX]),
            divert: None,
            raw: VecDeque::new(),
            stats: Stats::default(),
            server_rules: [None; stream::MAX_ENDPOINTS],
            feedback: icmp::Feedback::new(mac),
            ipv6_feedback: ipv6::feedback::Feedback::new(mac),
            ipv6_config: None,
            ipv6_route: None,
            ipv6_echo: None,
            ipv6_responder: None,
            ipv6_peers: [None; ipv6::MAX_ENDPOINTS],
            ipv6_tcp_peers: [None; ipv6::stream::MAX_ENDPOINTS],
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
            datagrams: datagram::Endpoints::new()?,
            ipv6_datagrams: ipv6::Endpoints::new()?,
            ipv6_streams: ipv6::stream::Endpoints::new()?,
            streams: stream::Endpoints::new()?,
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

    /// The immutable IP MTU selected before this Interface was constructed.
    pub fn ip_mtu(&self) -> usize {
        self.port.frame_mtu - 14
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

    /// One reading of the NIC ([`Link::read`]); `None` when it was refused.
    pub fn read_link(&self) -> Option<LinkReading> {
        self.port.link.read()
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
        let server_link_errors = self.port.stats.link_errors;
        self.ipv6_maintain();
        self.ipv6_stream_maintain(false);
        if (self.datagrams.active() || self.streams.active())
            && self.read_link().is_none_or(|r| !r.link_up || r.disabled)
        {
            self.datagram_fence();
            self.stream_fence();
            self.ipv6_fence();
        }
        if self.streams.active() {
            self.stream_maintain(false);
        }
        let now = self.now();
        let changed = self.iface.poll(now, &mut self.port, &mut self.sockets)
            == PollResult::SocketStateChanged;
        self.maintain();
        self.ipv6_stream_maintain(true);
        if self.port.stats.link_errors != server_link_errors {
            self.stream_server_fence();
        }
        if self.streams.active() {
            self.stream_maintain(true);
        }
        if (self.datagrams.active() || self.streams.active())
            && self.read_link().is_none_or(|r| !r.link_up || r.disabled)
        {
            self.datagram_fence();
            self.stream_fence();
            self.ipv6_fence();
        }
        self.ipv6_maintain();
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
            self.ipv6_fence();
            self.stream_server_fence();
            self.port.link.pause(bound);
        }
        self.ipv6_maintain();
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
                    let _ = socket.listen((self.config.address, port));
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
        if self.streams.reserved(port) || self.listeners.iter().any(|entry| entry.port == port) {
            return Err(NetError::InUse);
        }
        let mut sockets = Vec::with_capacity(backlog);
        for _ in 0..backlog {
            let mut socket = self.new_socket();
            socket
                .listen((self.config.address, port))
                .map_err(|_| NetError::Config)?;
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
        if socket.listen((self.config.address, port)).is_ok() {
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
        if self.streams.reserved(local_port) {
            return Err(NetError::InUse);
        }
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
        Ok(self
            .socket(connection)?
            .remote_endpoint()
            .and_then(|endpoint| match endpoint.addr {
                IpAddress::Ipv4(address) => Some((address, endpoint.port)),
                IpAddress::Ipv6(_) => None,
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

    /// Sends one whole frame as given through the owner's existing raw Link
    /// authority. This bypasses smoltcp and its selected IP MTU; the Link's
    /// physical-frame contract remains applicable.
    pub fn raw_send(&mut self, frame: &[u8]) -> Result<(), NetError> {
        let sent = self.port.link.send(frame);
        count_send(&mut self.port.stats, sent);
        sent.map_err(NetError::Nic)
    }
}

/// The `nic_info` record (kernel abi/src/nic.rs `NicInfo::to_bytes`).
pub const INFO_BYTES: usize = 64;
const INFO_RX_MISSED: usize = 24;
const INFO_FLAG_LINK_UP: u16 = 1;
const INFO_FLAG_DISABLED: u16 = 1 << 1;
/// [`NetWatch::sample`]'s period: five reads a second idle, not one per
/// 10 ms loop pass (each read also drains the device's MPC register).
pub const NET_SAMPLE_MS: u64 = 200;

/// One `nic_info` reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkReading {
    pub link_up: bool,
    pub disabled: bool,
    /// Frames the device missed for lack of a descriptor, since boot.
    pub rx_missed: u64,
}

/// Decodes the flags and `rx_missed` of a `nic_info` record.
pub fn reading_from_info(info: &[u8; INFO_BYTES]) -> LinkReading {
    let flags = u16::from_le_bytes([info[6], info[7]]);
    let mut missed = [0u8; 8];
    missed.copy_from_slice(&info[INFO_RX_MISSED..INFO_RX_MISSED + 8]);
    LinkReading {
        link_up: flags & INFO_FLAG_LINK_UP != 0,
        disabled: flags & INFO_FLAG_DISABLED != 0,
        rx_missed: u64::from_le_bytes(missed),
    }
}

/// Carrier as last observed; `Unknown` when the read was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    Up,
    Down,
    Unknown,
}

impl Carrier {
    pub fn word(self) -> &'static str {
        match self {
            Carrier::Up => "up",
            Carrier::Down => "down",
            Carrier::Unknown => "unknown",
        }
    }
}

/// A service's view of its NIC, reported on transitions only (record §4 A3,
/// §9 D3): a change of carrier or of the disabled latch; counters alone are
/// not one. Carrier up observes the device, never reachability. A send
/// refused for lack of carrier is a third input, reported on its own line
/// ([`NetWatch::tx_changed`]).
#[derive(Debug, Default)]
pub struct NetWatch {
    carrier: Option<Carrier>,
    disabled: Option<bool>,
    rx_missed: u64,
    next_ms: u64,
    tx_held: bool,
}

impl NetWatch {
    pub const fn new() -> Self {
        Self {
            carrier: None,
            disabled: None,
            rx_missed: 0,
            next_ms: 0,
            tx_held: false,
        }
    }

    /// Reads the NIC now; true on the first call and on every transition.
    pub fn observe<L: Link>(&mut self, stack: &Stack<L>) -> bool {
        self.next_ms = stack.link().now_ms().saturating_add(NET_SAMPLE_MS);
        let (carrier, disabled) = match stack.read_link() {
            Some(r) => {
                self.rx_missed = r.rx_missed;
                let carrier = if r.link_up {
                    Carrier::Up
                } else {
                    Carrier::Down
                };
                (carrier, Some(r.disabled))
            }
            None => (Carrier::Unknown, None),
        };
        let changed = self.carrier != Some(carrier) || self.disabled != disabled;
        (self.carrier, self.disabled) = (Some(carrier), disabled);
        changed
    }

    /// `observe` once `NET_SAMPLE_MS` has passed on the link's clock since
    /// the last reading; false, with no read, before then.
    pub fn sample<L: Link>(&mut self, stack: &Stack<L>) -> bool {
        self.sample_fresh(stack).unwrap_or(false)
    }

    /// `Some(changed)` means this call actually read the NIC, including a
    /// refused read represented as Unknown. `None` means cached state only.
    /// An owner may timestamp the former, never rejuvenate the latter.
    /// This preserves `sample`'s cadence and transition-only boolean.
    pub fn sample_fresh<L: Link>(&mut self, stack: &Stack<L>) -> Option<bool> {
        if self.carrier.is_some() && stack.link().now_ms() < self.next_ms {
            return None;
        }
        Some(self.observe(stack))
    }

    pub fn carrier(&self) -> Carrier {
        self.carrier.unwrap_or(Carrier::Unknown)
    }

    /// True only when the last reading succeeded and said disabled.
    pub fn disabled(&self) -> bool {
        self.disabled == Some(true)
    }

    /// Last reading's flag, without substituting false for a refused read.
    /// The caller still needs `sample_fresh` to bind a new sample interval.
    pub fn disabled_reading(&self) -> Option<bool> {
        self.disabled
    }

    /// `link=… disabled=0|1|unknown rx_missed=N link_errors=N` (`rx_missed`
    /// from the last successful reading, `link_errors` the stack's count).
    pub fn fields<L: Link>(&self, stack: &Stack<L>) -> alloc::string::String {
        let disabled = match self.disabled {
            Some(true) => "1",
            Some(false) => "0",
            None => "unknown",
        };
        alloc::format!(
            "link={} disabled={disabled} rx_missed={} link_errors={}",
            self.carrier().word(),
            self.rx_missed,
            stack.stats().link_errors
        )
    }

    /// True when the stack's transmit hold ([`Stats::tx_held`]) changed
    /// since the last call: a send refused for lack of carrier sets it, any
    /// other send result clears it. Reads no NIC state; nothing at
    /// readiness, since the hold starts clear. A hold set and cleared
    /// between two calls prints no line; `no_carrier` still counts it.
    pub fn tx_changed<L: Link>(&mut self, stack: &Stack<L>) -> bool {
        let held = stack.stats().tx_held;
        let changed = held != self.tx_held;
        self.tx_held = held;
        changed
    }

    /// `held=0|1 no_carrier=N`.
    pub fn tx_fields<L: Link>(&self, stack: &Stack<L>) -> alloc::string::String {
        alloc::format!(
            "held={} no_carrier={}",
            u8::from(self.tx_held),
            stack.stats().no_carrier
        )
    }
}
