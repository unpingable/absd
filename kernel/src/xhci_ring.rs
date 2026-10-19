//! xHCI ring, event, port and descriptor rules, kept apart from the MMIO
//! driver (`src/xhci.rs`) so they run under `cargo test` on the host.
//!
//! Everything the controller writes is untrusted: an event is accepted only
//! when its TRB type is an event type and it answers the one command or
//! control transfer the driver has outstanding. Anything else is reported by
//! name and the driver stops using the controller (fail closed); it never
//! guesses which outstanding work an event might have meant.
//!
//! Rings are fixed-size arrays of 16-byte TRBs. A producer ring (command,
//! endpoint zero) ends in a Link TRB that points back to its first TRB with
//! Toggle Cycle set; the event ring is one segment the consumer wraps by
//! itself. The driver has at most one command or one control transfer in
//! flight, so a producer ring can never overrun the controller's dequeue
//! pointer: that bound is the driver's calling discipline, not a check here.

pub const TRB_BYTES: u64 = 16;
/// TRBs in each producer ring, the last of which is the Link TRB.
pub const COMMAND_RING_TRBS: usize = 16;
/// Small on purpose: a three-TRB control transfer then regularly crosses
/// the Link TRB, so that path is exercised on every enumeration.
pub const TRANSFER_RING_TRBS: usize = 8;
/// The architectural minimum event ring segment size.
pub const EVENT_RING_TRBS: usize = 16;

pub const TRB_NORMAL: u32 = 1;
pub const TRB_SETUP: u32 = 2;
pub const TRB_DATA: u32 = 3;
pub const TRB_STATUS: u32 = 4;
pub const TRB_LINK: u32 = 6;
pub const TRB_ENABLE_SLOT: u32 = 9;
pub const TRB_DISABLE_SLOT: u32 = 10;
pub const TRB_ADDRESS_DEVICE: u32 = 11;
pub const TRB_CONFIGURE_ENDPOINT: u32 = 12;
pub const TRB_EVALUATE_CONTEXT: u32 = 13;
pub const TRB_NOOP_COMMAND: u32 = 23;
pub const EVENT_TRANSFER: u32 = 32;
pub const EVENT_COMMAND_COMPLETION: u32 = 33;
pub const EVENT_PORT_STATUS_CHANGE: u32 = 34;
pub const EVENT_HOST_CONTROLLER: u32 = 37;
/// The last architecturally defined event type (MFINDEX Wrap).
const EVENT_LAST: u32 = 39;

pub const TRB_CYCLE: u32 = 1;
pub const LINK_TOGGLE_CYCLE: u32 = 1 << 1;
pub const TRB_IOC: u32 = 1 << 5;
pub const TRB_IDT: u32 = 1 << 6;
/// Interrupt-on-Short-Packet: a data TRB that receives less than its length
/// reports a Short Packet event instead of ending silently.
pub const TRB_ISP: u32 = 1 << 2;
/// Setup Stage TRB Transfer Type: IN data stage.
pub const SETUP_IN_DATA: u32 = 3 << 16;
/// Data and Status Stage TRB direction bit: IN.
pub const DIRECTION_IN: u32 = 1 << 16;

pub const COMPLETION_SUCCESS: u8 = 1;
pub const COMPLETION_SHORT_PACKET: u8 = 13;

pub const fn trb_type(control: u32) -> u32 {
    (control >> 10) & 0x3f
}

pub const fn control(kind: u32) -> u32 {
    kind << 10
}

/// The producer side of a ring whose last TRB links back to the first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Producer {
    entries: usize,
    enqueue: usize,
    cycle: bool,
    wraps: u64,
}

/// Where the next TRB goes and with which cycle bit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Slot {
    pub index: usize,
    pub cycle: bool,
    /// After this TRB is written, the Link TRB (the ring's last entry) is
    /// handed to the controller with this cycle bit; the producer has then
    /// moved to index 0 with its cycle inverted.
    pub link: Option<bool>,
}

impl Producer {
    /// A ring of `entries` TRBs including the Link TRB.
    pub const fn new(entries: usize) -> Self {
        assert!(entries >= 2);
        Self {
            entries,
            enqueue: 0,
            cycle: true,
            wraps: 0,
        }
    }

    pub fn claim(&mut self) -> Slot {
        let mut slot = Slot {
            index: self.enqueue,
            cycle: self.cycle,
            link: None,
        };
        self.enqueue += 1;
        if self.enqueue == self.entries - 1 {
            slot.link = Some(self.cycle);
            self.enqueue = 0;
            self.cycle = !self.cycle;
            self.wraps += 1;
        }
        slot
    }

    pub fn enqueue(&self) -> usize {
        self.enqueue
    }

    pub fn cycle(&self) -> bool {
        self.cycle
    }

    pub fn wraps(&self) -> u64 {
        self.wraps
    }

    pub fn link_index(&self) -> usize {
        self.entries - 1
    }
}

/// The consumer side of a one-segment event ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Consumer {
    entries: usize,
    dequeue: usize,
    cycle: bool,
    wraps: u64,
}

impl Consumer {
    pub const fn new(entries: usize) -> Self {
        assert!(entries >= 1);
        Self {
            entries,
            dequeue: 0,
            cycle: true,
            wraps: 0,
        }
    }

    /// Whether the controller has written the TRB at the dequeue index.
    pub fn owned(&self, control: u32) -> bool {
        (control & TRB_CYCLE != 0) == self.cycle
    }

    pub fn advance(&mut self) {
        self.dequeue += 1;
        if self.dequeue == self.entries {
            self.dequeue = 0;
            self.cycle = !self.cycle;
            self.wraps += 1;
        }
    }

    pub fn dequeue(&self) -> usize {
        self.dequeue
    }

    pub fn cycle(&self) -> bool {
        self.cycle
    }

    pub fn wraps(&self) -> u64 {
        self.wraps
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    CommandCompletion {
        command: u64,
        code: u8,
        slot: u8,
    },
    Transfer {
        trb: u64,
        code: u8,
        residual: u32,
        slot: u8,
        endpoint: u8,
        event_data: bool,
    },
    PortStatusChange {
        port: u8,
    },
    HostController {
        code: u8,
    },
    /// A defined event type this driver never asks for (bandwidth request,
    /// doorbell, device notification, MFINDEX wrap).
    Other {
        kind: u8,
    },
}

/// A TRB on the event ring whose type is not an event type at all.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Malformed {
    pub kind: u8,
}

pub fn decode(trb: [u32; 4]) -> Result<Event, Malformed> {
    let pointer = u64::from(trb[0]) | (u64::from(trb[1]) << 32);
    let code = (trb[2] >> 24) as u8;
    let kind = trb_type(trb[3]);
    let slot = (trb[3] >> 24) as u8;
    Ok(match kind {
        EVENT_TRANSFER => Event::Transfer {
            trb: pointer,
            code,
            residual: trb[2] & 0x00ff_ffff,
            slot,
            endpoint: ((trb[3] >> 16) & 0x1f) as u8,
            event_data: trb[3] & (1 << 2) != 0,
        },
        EVENT_COMMAND_COMPLETION => Event::CommandCompletion {
            command: pointer,
            code,
            slot,
        },
        EVENT_PORT_STATUS_CHANGE => Event::PortStatusChange {
            port: (trb[0] >> 24) as u8,
        },
        EVENT_HOST_CONTROLLER => Event::HostController { code },
        35..=EVENT_LAST => Event::Other { kind: kind as u8 },
        _ => return Err(Malformed { kind: kind as u8 }),
    })
}

/// The one thing the driver is waiting for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Wait {
    /// The completion of the command TRB at this bus address.
    Command { trb: u64 },
    /// The end of a control transfer occupying TRBs `first..=last` (in ring
    /// order; `last` carries IOC) on this slot's endpoint; `data` is its
    /// data-stage TRB (ISP set), the only one that may report a short packet.
    Transfer {
        first: u64,
        data: u64,
        last: u64,
        slot: u8,
        endpoint: u8,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// The awaited work finished, successfully or not.
    Complete { code: u8, slot: u8, residual: u32 },
    /// A port changed state; the driver reads PORTSC itself.
    PortChange { port: u8 },
    /// The data stage ended short with `residual` bytes not transferred;
    /// the status stage's event still follows and ends the transfer.
    Short { residual: u32 },
    /// Not what is outstanding: the driver's picture of the controller is
    /// wrong, so it stops using it.
    Unexpected(Event),
}

/// Whether `pointer` names one of a transfer's TRBs. A transfer that
/// crosses the Link TRB has `last < first`; its TRBs are then the tail of
/// the ring from `first` and the head of the ring up to `last`, which the
/// caller expresses with `ring_base` and `ring_end` (exclusive of the Link).
pub fn in_transfer(pointer: u64, first: u64, last: u64, ring_base: u64, ring_end: u64) -> bool {
    if !pointer.is_multiple_of(TRB_BYTES) {
        return false;
    }
    if first <= last {
        (first..=last).contains(&pointer)
    } else {
        (first..ring_end).contains(&pointer) || (ring_base..=last).contains(&pointer)
    }
}

/// Judges one decoded event against the outstanding wait. `ring` is the
/// endpoint ring's `(base, end)` bus addresses, used only for transfers.
pub fn judge(event: Event, wait: Wait, ring: (u64, u64)) -> Verdict {
    match (event, wait) {
        (Event::PortStatusChange { port }, _) => Verdict::PortChange { port },
        (
            Event::CommandCompletion {
                command,
                code,
                slot,
            },
            Wait::Command { trb },
        ) if command == trb => Verdict::Complete {
            code,
            slot,
            residual: 0,
        },
        (
            Event::Transfer {
                trb,
                code,
                residual,
                slot,
                endpoint,
                event_data: false,
            },
            Wait::Transfer {
                data,
                slot: want_slot,
                endpoint: want_endpoint,
                ..
            },
        ) if slot == want_slot
            && endpoint == want_endpoint
            && trb == data
            && code == COMPLETION_SHORT_PACKET =>
        {
            Verdict::Short { residual }
        }
        (
            Event::Transfer {
                trb,
                code,
                residual,
                slot,
                endpoint,
                event_data: false,
            },
            Wait::Transfer {
                first,
                last,
                slot: want_slot,
                endpoint: want_endpoint,
                ..
            },
        ) if slot == want_slot
            && endpoint == want_endpoint
            && in_transfer(trb, first, last, ring.0, ring.1)
            // Only the IOC TRB may report success; an earlier stage reports
            // only by failing.
            && (trb == last || code != COMPLETION_SUCCESS) =>
        {
            Verdict::Complete {
                code,
                slot,
                residual,
            }
        }
        (event, _) => Verdict::Unexpected(event),
    }
}

pub const PORTSC_CCS: u32 = 1;
pub const PORTSC_PED: u32 = 1 << 1;
pub const PORTSC_OCA: u32 = 1 << 3;
pub const PORTSC_PR: u32 = 1 << 4;
pub const PORTSC_PP: u32 = 1 << 9;
pub const PORTSC_LWS: u32 = 1 << 16;
pub const PORTSC_CSC: u32 = 1 << 17;
pub const PORTSC_OCC: u32 = 1 << 20;
pub const PORTSC_PRC: u32 = 1 << 21;
/// CSC, PEC, WRC, OCC, PRC, PLC, CEC: write-one-to-clear change bits.
pub const PORTSC_CHANGES: u32 = 0x7f << 17;
pub const PORTSC_WPR: u32 = 1 << 31;

/// The PORTSC value that changes nothing when written back: PED (write one
/// disables the port), the change bits (write one clears) and the
/// write-one actions (PR, LWS, WPR) are all written as zero.
pub fn portsc_neutral(value: u32) -> u32 {
    value & !(PORTSC_PED | PORTSC_PR | PORTSC_LWS | PORTSC_CHANGES | PORTSC_WPR)
}

/// An over-current port is unavailable even without software power control.
/// PP is an availability condition only when the controller advertises PPC.
pub fn port_power_ready(value: u32, controlled: bool) -> bool {
    value & PORTSC_OCA == 0 && (!controlled || value & PORTSC_PP != 0)
}

/// At most one enable attempt per port observation; never enable during OCA.
pub fn port_power_on_needed(value: u32, controlled: bool) -> bool {
    controlled && value & (PORTSC_PP | PORTSC_OCA) == 0
}

/// Internal scan observation, not an exported state-transfer schema.
pub fn port_observation(value: u32, controlled: bool) -> u16 {
    (value & (PORTSC_CCS | PORTSC_OCA | if controlled { PORTSC_PP } else { 0 })) as u16
}

/// A cleared over-current condition merits another bounded power attempt,
/// even when PP is still zero and no connection transition occurred.
pub fn port_observation_changed(previous: u16, value: u32, controlled: bool) -> bool {
    value & (PORTSC_CSC | PORTSC_OCC) != 0 || previous != port_observation(value, controlled)
}

/// Changes on an unavailable, unbound port do not justify reconstruction
/// until it becomes usable. Watch retries its power without resetting.
pub fn port_recovery_changed(previous: u16, value: u32, controlled: bool) -> bool {
    if !port_power_ready(u32::from(previous), controlled) && !port_power_ready(value, controlled) {
        return false;
    }
    port_observation_changed(previous, value, controlled)
}

/// Watching has no bound slot or report TD. Losing power there does not
/// require reconstruction; keep watching the independent usable ports.
pub fn port_watch_changed(previous: u16, value: u32, controlled: bool) -> bool {
    port_power_ready(value, controlled)
        && (value & PORTSC_CCS != 0 || port_power_ready(u32::from(previous), controlled))
        && port_recovery_changed(previous, value, controlled)
}

pub fn port_watch_restored(previous: u16, value: u32, controlled: bool) -> bool {
    !port_power_ready(u32::from(previous), controlled) || value & PORTSC_OCC != 0
}

/// Per-port power backoff and a three-failure, ten-minute accounting window.
/// Private service policy, carried through successors without authority.
#[derive(Clone, Copy, Debug)]
pub struct PortPowerRetry {
    last: [u32; 256],
    window: [u64; 256],
    state: [u8; 256],
    now: u64,
    requested: Option<u8>,
    attempting: Option<u8>,
    initial_power: Option<u8>,
}

impl PortPowerRetry {
    pub const INTERVAL: u32 = 1_000;
    pub const MAX_FAILURES: u8 = 3;
    pub const DECAY_TICKS: u64 = 600_000;
    const FAULTED: u8 = 0x80;
    const COUNT: u8 = 0x7f;

    pub fn new(now: u64) -> Self {
        Self {
            last: [now as u32; 256],
            window: [now; 256],
            state: [0; 256],
            now,
            requested: None,
            attempting: None,
            initial_power: None,
        }
    }

    pub fn blocked(&self, port: u8) -> bool {
        port == 0
            || (self.state[usize::from(port)] & Self::COUNT >= Self::MAX_FAILURES
                && self.now.wrapping_sub(self.window[usize::from(port)]) < Self::DECAY_TICKS)
    }

    /// The supervisor supplies its monotonic PIT tick before policy events.
    pub fn advance(&mut self, now: u64) {
        self.now = now;
    }

    fn expire(&mut self, port: u8) {
        let i = usize::from(port);
        if self.now.wrapping_sub(self.window[i]) >= Self::DECAY_TICKS {
            self.state[i] &= Self::FAULTED;
        }
    }

    /// Merely observing an unpowered, unbound port does not spend a failure.
    pub fn observe_unavailable(&mut self, port: u8) {
        if port != 0 {
            self.expire(port);
            self.state[usize::from(port)] |= Self::FAULTED;
        }
    }

    /// Charge a current-port power-loss fence, or an unsuccessful attempt.
    /// Closing the active attempt here prevents successor() charging twice.
    pub fn unavailable(&mut self, port: u8) -> Option<u8> {
        if port == 0 {
            return None;
        }
        self.observe_unavailable(port);
        if self.attempting == Some(port) {
            self.attempting = None;
        }
        if self.initial_power == Some(port) {
            self.initial_power = None;
        }
        let i = usize::from(port);
        let previous = self.state[i] & Self::COUNT;
        if previous == 0 {
            self.window[i] = self.now;
        }
        let count = previous.saturating_add(1).min(Self::MAX_FAILURES);
        self.state[i] = Self::FAULTED | count;
        (previous < Self::MAX_FAILURES && count == Self::MAX_FAILURES).then_some(port)
    }

    /// Healthy ports still get their ordinary initialization power write.
    /// A port already known unavailable retains its backoff across reset.
    pub fn initial_request(&mut self, now: u64, port: u8, value: u32, controlled: bool) -> bool {
        self.advance(now);
        self.expire(port);
        let rebuilding = self.initial_power == Some(port);
        if rebuilding {
            self.initial_power = None;
        }
        if self.blocked(port) || !port_power_on_needed(value, controlled) {
            return false;
        }
        if !rebuilding && self.state[usize::from(port)] & Self::FAULTED != 0 {
            return self.request(now, port, value, controlled);
        }
        self.last[usize::from(port)] = now as u32;
        true
    }

    /// Reserve a reconstruction for a power restoration on an unbound port.
    /// A failed attempt is charged when it returns unbound or is superseded.
    pub fn reconstruct(&mut self, port: u8) -> bool {
        self.expire(port);
        if self.blocked(port) || self.requested.is_some() {
            return false;
        }
        let used =
            (self.state[usize::from(port)] & Self::COUNT) + u8::from(self.attempting == Some(port));
        if used >= Self::MAX_FAILURES {
            return false;
        }
        self.observe_unavailable(port);
        self.requested = Some(port);
        true
    }

    /// Ends the prior attempt before carrying the next one into a successor.
    pub fn successor(&mut self) -> Option<u8> {
        let refused = self.unbound();
        self.attempting = self.requested.take().filter(|port| !self.blocked(*port));
        self.initial_power = self.attempting;
        refused
    }

    /// The target did not bind. Refuse only this port after its allowance,
    /// retaining all other ports' observations.
    pub fn unbound(&mut self) -> Option<u8> {
        let port = self.attempting.take()?;
        self.unavailable(port)
    }

    /// The current HID configuration and checked initial TD post succeeded.
    /// Close its active attempt; binding does not forgive recent failures.
    pub fn bound(&mut self, port: u8) -> Option<u8> {
        self.expire(port);
        if self.blocked(port) {
            return None;
        }
        let refused = if self.attempting == Some(port) {
            self.attempting = None;
            None
        } else {
            self.unbound()
        };
        if self.initial_power == Some(port) {
            self.initial_power = None;
        }
        refused
    }

    pub fn request(&mut self, now: u64, port: u8, value: u32, controlled: bool) -> bool {
        self.advance(now);
        self.expire(port);
        if self.blocked(port) {
            return false;
        }
        let last = &mut self.last[usize::from(port)];
        let interval = Self::INTERVAL << u32::from(self.state[usize::from(port)] & Self::COUNT);
        if port_power_on_needed(value, controlled) && (now as u32).wrapping_sub(*last) >= interval {
            *last = now as u32;
            true
        } else {
            false
        }
    }
}

pub fn port_speed(portsc: u32) -> u8 {
    ((portsc >> 10) & 0xf) as u8
}

/// The default protocol speed IDs.
pub const SPEED_FULL: u8 = 1;
pub const SPEED_LOW: u8 = 2;
pub const SPEED_HIGH: u8 = 3;
pub const SPEED_SUPER: u8 = 4;

pub fn speed_name(speed: u8) -> &'static str {
    match speed {
        SPEED_FULL => "full",
        SPEED_LOW => "low",
        SPEED_HIGH => "high",
        SPEED_SUPER => "super",
        _ => "other",
    }
}

/// Endpoint zero's packet size before the device descriptor is read: the
/// only legal size at low and super speed, the largest at high speed, and
/// the smallest at full speed (fixed up from the descriptor's first eight
/// bytes). Other speeds (SuperSpeedPlus, or a speed ID remapped by the
/// Supported Protocol capability) are refused.
pub fn initial_max_packet(speed: u8) -> Option<u16> {
    match speed {
        SPEED_LOW | SPEED_FULL => Some(8),
        SPEED_HIGH => Some(64),
        SPEED_SUPER => Some(512),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutError {
    /// CAPLENGTH smaller than the capability registers themselves.
    CapLength(u8),
    NoSlots,
    NoPorts,
    /// A register block reaches past the BAR.
    OutsideBar {
        region: &'static str,
        end: u64,
    },
}

/// Register block offsets inside BAR0, each checked to lie inside it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layout {
    pub operational: u64,
    pub runtime: u64,
    pub doorbells: u64,
    /// Offset of the first extended capability, or 0.
    pub extended: u64,
    pub max_slots: u8,
    pub max_ports: u8,
    /// 32 or 64 (HCCPARAMS1.CSZ).
    pub context_bytes: u64,
    /// HCCPARAMS1.AC64: the controller can address above 4 GiB.
    pub addresses_64: bool,
    /// HCCPARAMS1.PPC: ports power up only when software sets PORTSC.PP.
    pub port_power_control: bool,
    pub bar_bytes: u64,
}

pub fn layout(
    caplength: u8,
    hcsparams1: u32,
    hccparams1: u32,
    dboff: u32,
    rtsoff: u32,
    bar_bytes: u64,
) -> Result<Layout, LayoutError> {
    if caplength < 0x20 {
        return Err(LayoutError::CapLength(caplength));
    }
    let max_slots = hcsparams1 as u8;
    let max_ports = (hcsparams1 >> 24) as u8;
    if max_slots == 0 {
        return Err(LayoutError::NoSlots);
    }
    if max_ports == 0 {
        return Err(LayoutError::NoPorts);
    }
    let operational = u64::from(caplength);
    let runtime = u64::from(rtsoff & !0x1f);
    let doorbells = u64::from(dboff & !0x3);
    let extended = u64::from(hccparams1 >> 16) * 4;
    let inside = |region, end: u64| {
        if end > bar_bytes {
            Err(LayoutError::OutsideBar { region, end })
        } else {
            Ok(())
        }
    };
    inside("capability", 0x20)?;
    // USBCMD..CONFIG, then one 16-byte register set per port at 0x400.
    inside(
        "operational",
        operational + 0x400 + 0x10 * u64::from(max_ports),
    )?;
    // MFINDEX block, then interrupter 0 (the only one used).
    inside("runtime", runtime + 0x20 + 0x20)?;
    // The host controller doorbell and one per slot.
    inside("doorbell", doorbells + 4 * (u64::from(max_slots) + 1))?;
    if extended != 0 {
        inside("extended capability", extended + 4)?;
    }
    Ok(Layout {
        operational,
        runtime,
        doorbells,
        extended,
        max_slots,
        max_ports,
        context_bytes: if hccparams1 & (1 << 2) != 0 { 64 } else { 32 },
        addresses_64: hccparams1 & 1 != 0,
        port_power_control: hccparams1 & (1 << 3) != 0,
        bar_bytes,
    })
}

/// The standard GET_DESCRIPTOR request (device-to-host, standard, device).
pub fn get_descriptor_setup(kind: u8, index: u8, length: u16) -> u64 {
    0x80 | (6 << 8) | (u64::from(kind) << 24) | (u64::from(index) << 16) | (u64::from(length) << 48)
}

pub const DESCRIPTOR_DEVICE: u8 = 1;
pub const DEVICE_DESCRIPTOR_BYTES: u16 = 18;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorError {
    Short(usize),
    Length(u8),
    Type(u8),
    /// bMaxPacketSize0 not legal for the descriptor's USB version.
    MaxPacket(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceDescriptor {
    pub usb: u16,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    /// Endpoint zero's packet size in bytes (decoded from the exponent for
    /// USB 3).
    pub max_packet0: u16,
    pub vendor: u16,
    pub product: u16,
    pub device: u16,
    pub configurations: u8,
}

/// Endpoint zero's packet size from the first eight bytes of a device
/// descriptor.
pub fn max_packet0(prefix: &[u8]) -> Result<u16, DescriptorError> {
    if prefix.len() < 8 {
        return Err(DescriptorError::Short(prefix.len()));
    }
    if prefix[0] != DEVICE_DESCRIPTOR_BYTES as u8 {
        return Err(DescriptorError::Length(prefix[0]));
    }
    if prefix[1] != DESCRIPTOR_DEVICE {
        return Err(DescriptorError::Type(prefix[1]));
    }
    let usb = u16::from_le_bytes([prefix[2], prefix[3]]);
    let raw = prefix[7];
    if usb >= 0x0300 {
        if raw != 9 {
            return Err(DescriptorError::MaxPacket(raw));
        }
        return Ok(512);
    }
    match raw {
        8 | 16 | 32 | 64 => Ok(u16::from(raw)),
        _ => Err(DescriptorError::MaxPacket(raw)),
    }
}

pub fn device_descriptor(bytes: &[u8]) -> Result<DeviceDescriptor, DescriptorError> {
    if bytes.len() < usize::from(DEVICE_DESCRIPTOR_BYTES) {
        return Err(DescriptorError::Short(bytes.len()));
    }
    let max_packet0 = max_packet0(bytes)?;
    let word = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
    Ok(DeviceDescriptor {
        usb: word(2),
        class: bytes[4],
        subclass: bytes[5],
        protocol: bytes[6],
        max_packet0,
        vendor: word(8),
        product: word(10),
        device: word(12),
        configurations: bytes[17],
    })
}

pub fn completion_name(code: u8) -> &'static str {
    match code {
        0 => "Invalid",
        1 => "Success",
        2 => "DataBufferError",
        3 => "BabbleDetected",
        4 => "UsbTransactionError",
        5 => "TrbError",
        6 => "StallError",
        7 => "ResourceError",
        8 => "BandwidthError",
        9 => "NoSlotsAvailable",
        10 => "InvalidStreamType",
        11 => "SlotNotEnabled",
        12 => "EndpointNotEnabled",
        13 => "ShortPacket",
        17 => "ParameterError",
        19 => "ContextStateError",
        21 => "EventRingFull",
        24 => "CommandRingStopped",
        25 => "CommandAborted",
        26 => "Stopped",
        _ => "Other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn producer_hands_over_the_link_and_toggles_cycle() {
        let mut ring = Producer::new(4);
        assert_eq!(
            ring.claim(),
            Slot {
                index: 0,
                cycle: true,
                link: None
            }
        );
        assert_eq!(ring.claim().index, 1);
        // Index 2 is the last usable slot; index 3 is the Link TRB.
        assert_eq!(
            ring.claim(),
            Slot {
                index: 2,
                cycle: true,
                link: Some(true)
            }
        );
        assert_eq!(ring.wraps(), 1);
        assert_eq!(
            ring.claim(),
            Slot {
                index: 0,
                cycle: false,
                link: None
            }
        );
        assert_eq!(ring.claim().index, 1);
        assert_eq!(
            ring.claim(),
            Slot {
                index: 2,
                cycle: false,
                link: Some(false)
            }
        );
        assert_eq!((ring.enqueue(), ring.cycle(), ring.wraps()), (0, true, 2));
    }

    #[test]
    fn producer_never_hands_out_the_link_slot() {
        let mut ring = Producer::new(COMMAND_RING_TRBS);
        for _ in 0..10 * COMMAND_RING_TRBS {
            assert!(ring.claim().index < ring.link_index());
        }
    }

    #[test]
    fn consumer_toggles_cycle_at_the_segment_end() {
        let mut events = Consumer::new(2);
        assert!(events.owned(TRB_CYCLE));
        assert!(!events.owned(0));
        events.advance();
        assert_eq!((events.dequeue(), events.cycle()), (1, true));
        events.advance();
        assert_eq!(
            (events.dequeue(), events.cycle(), events.wraps()),
            (0, false, 1)
        );
        assert!(events.owned(0));
        assert!(!events.owned(TRB_CYCLE));
    }

    fn event(kind: u32, pointer: u64, status: u32, high: u32) -> [u32; 4] {
        [
            pointer as u32,
            (pointer >> 32) as u32,
            status,
            control(kind) | high | TRB_CYCLE,
        ]
    }

    #[test]
    fn decode_rejects_non_event_types() {
        for kind in [0, TRB_NORMAL, TRB_LINK, TRB_NOOP_COMMAND, 31, 40, 63] {
            assert_eq!(
                decode(event(kind, 0, 0, 0)),
                Err(Malformed { kind: kind as u8 })
            );
        }
        assert_eq!(decode(event(38, 0, 0, 0)), Ok(Event::Other { kind: 38 }));
    }

    #[test]
    fn decode_reads_fields() {
        assert_eq!(
            decode(event(
                EVENT_COMMAND_COMPLETION,
                0x1234_5670,
                1 << 24,
                3 << 24
            )),
            Ok(Event::CommandCompletion {
                command: 0x1234_5670,
                code: 1,
                slot: 3
            })
        );
        assert_eq!(
            decode(event(
                EVENT_TRANSFER,
                0x2000,
                (13 << 24) | 10,
                (1 << 24) | (1 << 16)
            )),
            Ok(Event::Transfer {
                trb: 0x2000,
                code: 13,
                residual: 10,
                slot: 1,
                endpoint: 1,
                event_data: false
            })
        );
        assert_eq!(
            decode(event(EVENT_PORT_STATUS_CHANGE, 5 << 24, 1 << 24, 0)),
            Ok(Event::PortStatusChange { port: 5 })
        );
    }

    const RING: (u64, u64) = (0x1000, 0x1000 + 15 * TRB_BYTES);

    #[test]
    fn judge_matches_only_the_outstanding_command() {
        let wait = Wait::Command { trb: 0x1010 };
        let ok = Event::CommandCompletion {
            command: 0x1010,
            code: 1,
            slot: 2,
        };
        assert_eq!(
            judge(ok, wait, RING),
            Verdict::Complete {
                code: 1,
                slot: 2,
                residual: 0
            }
        );
        let other = Event::CommandCompletion {
            command: 0x1020,
            code: 1,
            slot: 2,
        };
        assert_eq!(judge(other, wait, RING), Verdict::Unexpected(other));
        let transfer = Event::Transfer {
            trb: 0x1010,
            code: 1,
            residual: 0,
            slot: 1,
            endpoint: 1,
            event_data: false,
        };
        assert_eq!(judge(transfer, wait, RING), Verdict::Unexpected(transfer));
        assert_eq!(
            judge(Event::PortStatusChange { port: 1 }, wait, RING),
            Verdict::PortChange { port: 1 }
        );
        let fatal = Event::HostController { code: 21 };
        assert_eq!(judge(fatal, wait, RING), Verdict::Unexpected(fatal));
    }

    #[test]
    fn judge_transfer_success_only_at_the_last_trb() {
        let wait = Wait::Transfer {
            first: 0x1000,
            data: 0x1010,
            last: 0x1020,
            slot: 1,
            endpoint: 1,
        };
        let at = |trb, code| Event::Transfer {
            trb,
            code,
            residual: 0,
            slot: 1,
            endpoint: 1,
            event_data: false,
        };
        assert!(matches!(
            judge(at(0x1020, 1), wait, RING),
            Verdict::Complete { code: 1, .. }
        ));
        // A stalled data stage ends the transfer early.
        assert!(matches!(
            judge(at(0x1010, 6), wait, RING),
            Verdict::Complete { code: 6, .. }
        ));
        // Success reported for a TRB that never asked for an event.
        assert!(matches!(
            judge(at(0x1010, 1), wait, RING),
            Verdict::Unexpected(_)
        ));
        // Outside the transfer, misaligned, or another endpoint.
        assert!(matches!(
            judge(at(0x1030, 1), wait, RING),
            Verdict::Unexpected(_)
        ));
        assert!(matches!(
            judge(at(0x1018, 6), wait, RING),
            Verdict::Unexpected(_)
        ));
        let mut wrong_endpoint = at(0x1020, 1);
        if let Event::Transfer { endpoint, .. } = &mut wrong_endpoint {
            *endpoint = 2;
        }
        assert!(matches!(
            judge(wrong_endpoint, wait, RING),
            Verdict::Unexpected(_)
        ));
    }

    #[test]
    fn judge_short_packet_only_at_the_data_trb() {
        let wait = Wait::Transfer {
            first: 0x1000,
            data: 0x1010,
            last: 0x1020,
            slot: 1,
            endpoint: 1,
        };
        let at = |trb, code, residual| Event::Transfer {
            trb,
            code,
            residual,
            slot: 1,
            endpoint: 1,
            event_data: false,
        };
        assert_eq!(
            judge(at(0x1010, COMPLETION_SHORT_PACKET, 46), wait, RING),
            Verdict::Short { residual: 46 }
        );
        // A short packet anywhere else ends the transfer as an error code.
        assert!(matches!(
            judge(at(0x1000, COMPLETION_SHORT_PACKET, 0), wait, RING),
            Verdict::Complete { code: 13, .. }
        ));
        // Another endpoint's short packet is not this transfer's.
        let mut other = at(0x1010, COMPLETION_SHORT_PACKET, 4);
        if let Event::Transfer { endpoint, .. } = &mut other {
            *endpoint = 2;
        }
        assert_eq!(judge(other, wait, RING), Verdict::Unexpected(other));
    }

    #[test]
    fn transfer_range_follows_the_link() {
        // TRBs 13, 14, then (after the Link at 15) 0.
        let first = RING.0 + 13 * TRB_BYTES;
        let last = RING.0;
        assert!(in_transfer(first, first, last, RING.0, RING.1));
        assert!(in_transfer(
            RING.0 + 14 * TRB_BYTES,
            first,
            last,
            RING.0,
            RING.1
        ));
        assert!(in_transfer(RING.0, first, last, RING.0, RING.1));
        // The Link TRB itself and TRBs after `last` are not the transfer's.
        assert!(!in_transfer(RING.1, first, last, RING.0, RING.1));
        assert!(!in_transfer(
            RING.0 + TRB_BYTES,
            first,
            last,
            RING.0,
            RING.1
        ));
    }

    #[test]
    fn neutral_portsc_preserves_power_and_clears_nothing() {
        let value = PORTSC_CCS | PORTSC_PED | PORTSC_PP | PORTSC_CSC | PORTSC_PRC | (3 << 10);
        let neutral = portsc_neutral(value);
        assert_eq!(neutral, PORTSC_CCS | PORTSC_PP | (3 << 10));
        assert_eq!(port_speed(value), SPEED_HIGH);
    }

    #[test]
    fn port_power_refusal_is_local_and_never_enables_over_current() {
        // Source-only negative inputs: QEMU 8.2.2 does not produce PPC/OCA.
        let cases = [
            (false, 0, true, false),
            (false, PORTSC_PP, true, false),
            (false, PORTSC_OCA, false, false),
            (true, 0, false, true),
            (true, PORTSC_PP, true, false),
            (true, PORTSC_OCA, false, false),
            (true, PORTSC_OCA | PORTSC_PP, false, false),
            (true, u32::MAX, false, false),
        ];
        for (controlled, value, ready, enable) in cases {
            assert_eq!(port_power_ready(value, controlled), ready);
            assert_eq!(port_power_on_needed(value, controlled), enable);
        }
        let link = PORTSC_CCS | PORTSC_PED | (u32::from(SPEED_HIGH) << 10);
        let ports = [(5, link | PORTSC_OCA), (6, link), (7, link | PORTSC_PP)];
        let selected = ports
            .iter()
            .find(|(_, value)| port_power_ready(*value, true));
        assert_eq!(selected.map(|(port, _)| *port), Some(7));
        assert!(!port_power_ready(ports[0].1, true));
    }

    #[test]
    fn port_watch_notices_power_restoration_without_connection_change() {
        let blocked = PORTSC_CCS | PORTSC_OCA;
        let previous = port_observation(blocked, true);
        assert!(!port_observation_changed(previous, blocked, true));
        // Clearing OCA merits a fresh bounded PP attempt even with PP=0.
        assert!(port_observation_changed(previous, PORTSC_CCS, true));
        assert!(port_observation_changed(
            port_observation(PORTSC_CCS, true),
            PORTSC_CCS | PORTSC_PP,
            true
        ));
        // A complete over-current pulse may leave the same live state.
        assert!(port_observation_changed(
            previous,
            blocked | PORTSC_OCC,
            true
        ));
        assert!(port_observation_changed(
            previous,
            blocked | PORTSC_CSC,
            true
        ));
        // The raw observation notices a pulse. Recovery suppresses a
        // reconstruction for a still-unavailable port and retries in Watch.
        let cleared_pulse = PORTSC_CCS | PORTSC_OCC | PORTSC_CSC;
        assert!(!port_recovery_changed(previous, cleared_pulse, true));
        assert!(port_recovery_changed(
            previous,
            cleared_pulse | PORTSC_PP,
            true
        ));
    }

    #[test]
    fn port_watch_ignores_unrelated_and_uncontrolled_power_bits() {
        let baseline = PORTSC_CCS | PORTSC_PP;
        let previous = port_observation(baseline, true);
        assert!(!port_observation_changed(
            previous,
            baseline | PORTSC_PED | PORTSC_PRC | (u32::from(SPEED_HIGH) << 10),
            true
        ));
        assert!(!port_observation_changed(
            port_observation(PORTSC_CCS, false),
            baseline,
            false
        ));
        assert!(port_observation_changed(previous, PORTSC_CCS, true));
    }

    #[test]
    fn power_retry_is_per_port_bounded_and_does_not_enable_active_over_current() {
        let mut retry = PortPowerRetry::new(u64::MAX - 499);
        assert!(!retry.request(499, 1, 0, true));
        assert!(retry.request(500, 1, 0, true));
        assert!(!retry.request(500, 1, 0, true));
        assert!(retry.request(500, 2, 0, true));
        assert!(!retry.request(1_500, 1, PORTSC_OCA, true));
        assert!(!retry.request(1_500, 1, 0, false));
        assert!(!retry.request(1_500, 1, PORTSC_PP, true));
        assert!(!retry.request(1_500, 0, 0, true));
        assert!(retry.request(1_500, 1, 0, true));
    }

    #[test]
    fn scan_watch_successor_sequence_keeps_a_repeated_power_trip_local() {
        // Scripted PORTSC device: every PP write trips to PP0/OCA0/OCC1.
        // After an optional fault removal, a PP write sticks with stable CCS.
        // The rules here are also called by the production state machine.
        fn sequence(remove_at: Option<u64>, old_policy: bool) -> (u8, u32, bool) {
            let mut generation = 0;
            let mut scan = true;
            let mut value = 0;
            let mut observed = 0;
            let mut retry = PortPowerRetry::new(0);
            let mut settle = None;
            let mut writes = 0;
            for now in 0..10_000 {
                if scan {
                    generation += 1;
                    if generation > 32 {
                        return (generation, writes, false);
                    }
                    if port_power_ready(value, true) {
                        return (generation, writes, true);
                    }
                    // Power and the one Scan retry finish before Watch.
                    writes += 2;
                    value = PORTSC_OCC;
                    observed = port_observation(value, true);
                    if !old_policy {
                        value &= !PORTSC_CHANGES;
                    }
                    retry = PortPowerRetry::new(now);
                    settle = None;
                    scan = false;
                }
                if let Some(start) = settle {
                    if now - start < 20 {
                        continue;
                    }
                    settle = None;
                }
                let changed = if old_policy {
                    port_observation_changed(observed, value, true)
                } else {
                    port_recovery_changed(observed, value, true)
                };
                if changed {
                    scan = true;
                    continue;
                }
                observed = port_observation(value, true);
                value &= !PORTSC_CHANGES;
                if retry.request(now, 1, value, true) {
                    writes += 1;
                    value = if remove_at.is_some_and(|tick| now >= tick) {
                        PORTSC_PP | PORTSC_CCS
                    } else {
                        PORTSC_OCC
                    };
                    settle = Some(now);
                }
            }
            (generation, writes, false)
        }
        let (generations, writes, bound) = sequence(None, false);
        assert_eq!(generations, 1);
        assert_eq!(writes, 11);
        assert!(!bound);
        assert_eq!(sequence(Some(5_000), false), (2, 7, true));
        // The reviewed policy consumes every successor on the same fault.
        assert_eq!(sequence(None, true), (33, 64, false));
    }

    #[test]
    fn late_trip_scan_watch_successor_keeps_other_ports_available() {
        // The same 50-tick trip and 80,000-tick later keyboard as the red
        // baseline. Calls now follow the runtime's retained policy and Watch
        // predicate. The fixture does not model descriptor/TD authority.
        fn sequence(
            reset_history: bool,
            reset_power: bool,
            clears_at: Option<u64>,
        ) -> (u8, u32, Option<u8>, bool) {
            let mut successors = 0;
            let mut scan = true;
            let mut scan_wait = None;
            let mut value = 0;
            let mut observed = 0;
            let mut trip = None;
            let mut settle = None;
            let mut retry = PortPowerRetry::new(0);
            let mut selected = None;
            let mut writes = 0;
            for now in 0..100_000 {
                if trip.is_some_and(|deadline| now >= deadline) {
                    value = PORTSC_OCC;
                    trip = None;
                }
                if scan {
                    if successors == 32 {
                        break;
                    }
                    if reset_history {
                        retry = PortPowerRetry::new(now);
                    } else {
                        retry.successor();
                    }
                    if now >= 80_000 && !retry.blocked(2) {
                        selected = Some(2);
                        retry.bound(2);
                        break;
                    }
                    if reset_power && successors != 0 {
                        value = 0;
                        trip = None;
                    }
                    if retry.initial_request(now, 1, value, true) {
                        writes += 1;
                        value = PORTSC_PP | PORTSC_CCS;
                        trip = (!clears_at.is_some_and(|tick| now >= tick)).then_some(now + 50);
                    }
                    scan_wait = Some(now);
                    settle = None;
                    scan = false;
                }
                if let Some(start) = scan_wait {
                    if now - start < 20 {
                        continue;
                    }
                    scan_wait = None;
                    if !port_power_ready(value, true) {
                        retry.observe_unavailable(1);
                    }
                    if !retry.blocked(1)
                        && port_power_ready(value, true)
                        && clears_at.is_some_and(|tick| now >= tick)
                    {
                        // Successful current binding is the policy credit.
                        // It reconstructs no old slot or handle.
                        retry.bound(1);
                        selected = Some(1);
                        break;
                    }
                    observed = port_observation(value, true);
                    value &= !PORTSC_CHANGES;
                    retry.unbound();
                }
                if let Some(start) = settle {
                    if now - start < 20 {
                        continue;
                    }
                    settle = None;
                }
                if !port_power_ready(value, true) {
                    retry.observe_unavailable(1);
                }
                if !retry.blocked(1) && port_watch_changed(observed, value, true) {
                    let restored = port_watch_restored(observed, value, true);
                    if !restored || retry.reconstruct(1) {
                        successors += 1;
                        scan = true;
                        continue;
                    }
                }
                observed = port_observation(value, true);
                value &= !PORTSC_CHANGES;
                if retry.request(now, 1, value, true) {
                    writes += 1;
                    value = PORTSC_PP | PORTSC_CCS;
                    trip = (!clears_at.is_some_and(|tick| now >= tick)).then_some(now + 50);
                    settle = Some(now);
                    continue;
                }
                if now >= 80_000
                    && port_watch_changed(
                        port_observation(PORTSC_PP, true),
                        PORTSC_PP | PORTSC_CCS | PORTSC_CSC,
                        true,
                    )
                {
                    successors += 1;
                    scan = true;
                }
            }
            (successors, writes, selected, retry.blocked(1))
        }
        for reset_power in [false, true] {
            let (successors, writes, selected, refused) = sequence(false, reset_power, None);
            assert!(
                successors < 32,
                "late trip exhausted all successors: {successors}"
            );
            assert_eq!(successors, PortPowerRetry::MAX_FAILURES + 1);
            assert_eq!(selected, Some(2), "a healthy later port was never selected");
            assert!(refused);
            assert!(writes >= u32::from(PortPowerRetry::MAX_FAILURES));
            assert!(writes <= 1 + 2 * u32::from(PortPowerRetry::MAX_FAILURES));
            let (successors, _, selected, refused) = sequence(false, reset_power, Some(2_000));
            assert!(successors < 32);
            assert_eq!(selected, Some(1));
            assert!(!refused);
            // Removing the policy carry reproduces exhaustion even with the
            // corrected no-fence-on-unbound-loss predicate.
            let (successors, _, selected, _) = sequence(true, reset_power, None);
            assert_eq!(successors, 32);
            assert_eq!(selected, None);
        }
    }

    #[test]
    fn port_watch_loss_and_empty_restoration_do_not_request_reconstruction() {
        let ready = port_observation(PORTSC_PP | PORTSC_CCS, true);
        assert!(!port_watch_changed(ready, PORTSC_OCC | PORTSC_CSC, true));
        assert!(!port_watch_changed(0, PORTSC_PP | PORTSC_OCC, true));
        assert!(port_watch_changed(0, PORTSC_PP | PORTSC_CCS, true));
        assert!(port_watch_changed(ready, PORTSC_PP | PORTSC_CSC, true));
        assert!(port_watch_restored(ready, PORTSC_PP | PORTSC_OCC, true));
        assert!(!port_watch_restored(ready, PORTSC_PP | PORTSC_CSC, true));
        // The current enumeration/transfer retains its strict change rule.
        assert!(port_observation_changed(ready, PORTSC_OCC, true));
    }

    #[test]
    fn power_reconstruction_allowance_is_local_and_charged_once() {
        let mut retry = PortPowerRetry::new(0);
        assert!(!retry.reconstruct(0));
        for attempt in 1..=PortPowerRetry::MAX_FAILURES {
            assert!(retry.reconstruct(1));
            assert!(!retry.reconstruct(2)); // one pending reconstruction
            assert_eq!(retry.successor(), None);
            assert_eq!(
                retry.unbound(),
                (attempt == PortPowerRetry::MAX_FAILURES).then_some(1)
            );
            assert_eq!(retry.unbound(), None);
        }
        assert!(retry.blocked(1));
        assert!(!retry.reconstruct(1));
        assert!(!retry.request(100_000, 1, 0, true));
        assert!(!retry.initial_request(100_000, 1, 0, true));
        assert!(!retry.blocked(2));
        retry.bound(2);
        assert!(retry.blocked(1));
        retry.bound(1);
        assert!(retry.blocked(1));
        assert!(retry.reconstruct(2));
    }

    #[test]
    fn active_restoration_reserves_its_allowance_before_failure_is_charged() {
        let mut retry = PortPowerRetry::new(0);
        // A port status event can request another reconstruction while a
        // previous restoration is still enumerating, before Watch is reached.
        for _ in 0..PortPowerRetry::MAX_FAILURES {
            assert!(retry.reconstruct(1));
            retry.successor();
        }
        assert!(!retry.blocked(1)); // the third attempt has not failed yet
        assert!(
            !retry.reconstruct(1),
            "active attempt overspent the allowance"
        );
        assert_eq!(retry.unbound(), Some(1));
        assert!(retry.blocked(1));
        assert!(!retry.blocked(2));
    }

    #[test]
    fn restoration_can_repower_after_our_reset_and_binding_closes_the_attempt() {
        let mut retry = PortPowerRetry::new(0);
        retry.observe_unavailable(1);
        assert!(!retry.request(999, 1, 0, true));
        assert!(retry.request(1_000, 1, 0, true));
        assert!(retry.reconstruct(1));
        retry.successor();
        // HCRST may clear PP. The admitted target gets exactly one ordinary
        // initialization write despite its retained retry deadline.
        assert!(retry.initial_request(1_021, 1, 0, true));
        assert!(!retry.initial_request(1_021, 1, 0, true));
        retry.bound(1);
        assert_eq!(retry.unbound(), None);
        assert!(!retry.blocked(1));
        // A superseded attempt is charged even if Watch was never reached.
        assert!(retry.reconstruct(1));
        retry.successor();
        retry.successor();
        assert!(!retry.request(3_020, 1, 0, true));
        assert!(retry.request(3_021, 1, 0, true));
    }

    #[test]
    fn binding_another_port_finishes_the_restoration_target_once() {
        let mut retry = PortPowerRetry::new(0);
        for attempt in 1..=PortPowerRetry::MAX_FAILURES {
            assert!(retry.reconstruct(1));
            retry.successor();
            assert_eq!(
                retry.bound(2),
                (attempt == PortPowerRetry::MAX_FAILURES).then_some(1)
            );
            assert_eq!(retry.unbound(), None);
            assert!(!retry.blocked(2));
        }
        assert!(retry.blocked(1));
    }

    // A power-loss fence must notify the retained policy. The baseline's
    // unavailable() only marks the port and the runtime omits this notice
    // at several fences. Even supplying that notice cannot bound its loop.
    fn power_loss_contract_sequence(bind_first: bool) -> (u8, u32, bool) {
        let mut retry = PortPowerRetry::new(0);
        let (mut now, mut writes, mut successors) = (0, 0, 0);
        loop {
            if retry.blocked(1) || now >= 100_000 {
                break;
            }
            if retry.initial_request(now, 1, 0, true) {
                writes += 1;
            } else {
                // PP is reset-cleared. The scripted device cannot become
                // ready until production policy actually permits a write.
                now += 1;
                continue;
            }
            now += 20;
            let ready = PORTSC_PP | PORTSC_CCS;
            if retry.blocked(1) || !port_power_ready(ready, true) {
                break;
            }
            assert!(!retry.request(now, 1, ready, true));
            if bind_first {
                assert_eq!(retry.bound(1), None);
            }
            now += 50;
            retry.unavailable(1);
            if successors == 32 {
                break;
            }
            successors += 1;
            retry.successor();
            now += 1;
        }
        (successors, writes, retry.blocked(1))
    }

    #[test]
    fn power_loss_contract_trip_during_enumeration_is_charged() {
        let (successors, writes, blocked) = power_loss_contract_sequence(false);
        assert!(
            blocked && successors <= PortPowerRetry::MAX_FAILURES + 1,
            "enumeration-time trip uncharged: successors={successors} writes={writes} blocked={blocked}"
        );
    }

    #[test]
    fn power_loss_contract_configure_then_trip_keeps_history() {
        let (successors, writes, blocked) = power_loss_contract_sequence(true);
        assert!(
            blocked && successors <= PortPowerRetry::MAX_FAILURES + 1,
            "configure-then-trip uncharged: successors={successors} writes={writes} blocked={blocked}"
        );
    }

    #[test]
    fn power_loss_contract_old_failures_decay_after_ten_minutes() {
        let mut retry = PortPowerRetry::new(0);
        for _ in 0..PortPowerRetry::MAX_FAILURES {
            assert!(retry.reconstruct(1));
            retry.successor();
            retry.unbound();
        }
        assert!(retry.blocked(1));
        assert!(!retry.request(599_999, 1, 0, true));
        assert!(
            retry.request(600_001, 1, 0, true),
            "failures older than ten minutes still refuse the port"
        );
        assert!(!retry.blocked(1));
    }

    #[test]
    fn transfer_error_power_loss_routes_to_the_charged_fence() {
        // Host tests cannot execute the kernel's MMIO error glue. Guard its
        // actual source wiring separately from the shared policy sequence.
        let source = include_str!("xhci_keyboard.rs");
        let branch = source
            .split_once("    if let Err(error) = result {")
            .unwrap()
            .1
            .split_once("pub(super) fn stop_before_finish")
            .unwrap()
            .0;
        assert!(
            branch.contains("runtime.fence_power("),
            "a transfer error can fence a power-lost port without charging it"
        );
        let ownership = branch.find("ownership_holds()").unwrap();
        let read = branch.find("read32(").unwrap();
        assert!(
            ownership < read,
            "error-path PORTSC read lacks prior ownership check"
        );
        assert!(branch.contains("Phase::Recovering") && branch.contains("current_port()"));
        assert!(branch.contains("Phase::Running") && branch.contains("runtime.port"));
        assert!(branch.contains("port != 0"));
        // The preceding guard covers dispatch after a failed transfer before
        // its PSC is consumed, both before configuration and while bound.
        // These transitions execute production policy, not MMIO or the glue.
        for bind_first in [false, true] {
            let (successors, _, blocked) = power_loss_contract_sequence(bind_first);
            assert!(blocked && successors <= PortPowerRetry::MAX_FAILURES + 1);
        }
    }

    #[test]
    fn power_loss_fence_finishes_the_active_attempt_once() {
        let mut retry = PortPowerRetry::new(0);
        for attempt in 1..=PortPowerRetry::MAX_FAILURES {
            assert!(retry.reconstruct(1));
            retry.successor();
            assert_eq!(
                retry.unavailable(1),
                (attempt == PortPowerRetry::MAX_FAILURES).then_some(1)
            );
            assert_eq!(retry.successor(), None);
            assert_eq!(retry.unbound(), None);
            assert_eq!(retry.blocked(1), attempt == PortPowerRetry::MAX_FAILURES);
            assert!(!retry.blocked(2));
        }
    }

    #[test]
    fn binding_closes_the_attempt_without_forgiving_a_recent_trip() {
        let mut retry = PortPowerRetry::new(0);
        for attempt in 1..=PortPowerRetry::MAX_FAILURES {
            if attempt > 1 {
                assert!(retry.reconstruct(1));
                retry.successor();
            }
            assert_eq!(retry.bound(1), None);
            assert_eq!(retry.unbound(), None);
            assert_eq!(
                retry.unavailable(1),
                (attempt == PortPowerRetry::MAX_FAILURES).then_some(1)
            );
        }
        assert!(retry.blocked(1));
    }

    #[test]
    fn decay_crosses_low_tick_wrap_and_begins_a_new_window() {
        let start = u64::from(u32::MAX) - 100;
        let mut retry = PortPowerRetry::new(start);
        for _ in 0..PortPowerRetry::MAX_FAILURES {
            retry.unavailable(1);
        }
        assert!(!retry.request(start + PortPowerRetry::DECAY_TICKS - 1, 1, 0, true));
        assert!(retry.request(start + PortPowerRetry::DECAY_TICKS, 1, 0, true));
        assert!(!retry.blocked(1));
        // The next failure begins a fresh window, rather than reappearing
        // when the low tick bits happen to match an old timestamp.
        retry.unavailable(1);
        retry.advance(start + 2 * PortPowerRetry::DECAY_TICKS - 1);
        retry.unavailable(1);
        assert!(!retry.blocked(1));
        retry.unavailable(1);
        assert!(retry.blocked(1));
        retry.advance(start + 2 * PortPowerRetry::DECAY_TICKS);
        assert!(!retry.blocked(1));
    }

    #[test]
    fn layout_refuses_registers_outside_the_bar() {
        // QEMU qemu-xhci: CAPLENGTH 0x40, 64 slots, 8 ports, DBOFF 0x2000,
        // RTSOFF 0x1000, 16 KiB BAR.
        let hcs = 64 | (1 << 8) | (8 << 24);
        let good = layout(0x40, hcs, 0x0008_0000, 0x2000, 0x1000, 0x4000).unwrap();
        assert_eq!(
            (
                good.operational,
                good.runtime,
                good.doorbells,
                good.extended
            ),
            (0x40, 0x1000, 0x2000, 0x20)
        );
        assert_eq!(good.context_bytes, 32);
        assert!(!good.port_power_control);
        let powered = layout(0x40, hcs, 1 << 3, 0x2000, 0x1000, 0x4000).unwrap();
        assert!(powered.port_power_control);
        assert_eq!(
            layout(0x40, hcs, 0, 0x2000, 0x1000, 0x40),
            Err(LayoutError::OutsideBar {
                region: "operational",
                end: 0x40 + 0x400 + 0x80
            })
        );
        assert_eq!(
            layout(0x40, hcs, 0, 0x3ff0, 0x1000, 0x4000),
            Err(LayoutError::OutsideBar {
                region: "doorbell",
                end: 0x3ff0 + 4 * 65
            })
        );
        assert_eq!(
            layout(0x10, hcs, 0, 0x2000, 0x1000, 0x4000),
            Err(LayoutError::CapLength(0x10))
        );
        assert_eq!(
            layout(0x40, 8 << 24, 0, 0x2000, 0x1000, 0x4000),
            Err(LayoutError::NoSlots)
        );
    }

    #[test]
    fn setup_packet_encodes_get_descriptor() {
        let setup = get_descriptor_setup(DESCRIPTOR_DEVICE, 0, 18);
        assert_eq!(
            setup.to_le_bytes(),
            [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 18, 0]
        );
    }

    #[test]
    fn device_descriptor_is_validated() {
        // QEMU usb-kbd (USB 2.0, full/high speed).
        let bytes = [
            18, 1, 0x00, 0x02, 0, 0, 0, 64, 0x27, 0x06, 0x01, 0x00, 0, 0, 1, 2, 3, 1,
        ];
        let descriptor = device_descriptor(&bytes).unwrap();
        assert_eq!(
            (descriptor.usb, descriptor.vendor, descriptor.product),
            (0x0200, 0x0627, 0x0001)
        );
        assert_eq!((descriptor.max_packet0, descriptor.configurations), (64, 1));
        assert_eq!(
            device_descriptor(&bytes[..17]),
            Err(DescriptorError::Short(17))
        );
        let mut bad = bytes;
        bad[1] = 2;
        assert_eq!(device_descriptor(&bad), Err(DescriptorError::Type(2)));
        bad = bytes;
        bad[7] = 7;
        assert_eq!(device_descriptor(&bad), Err(DescriptorError::MaxPacket(7)));
        bad = bytes;
        bad[3] = 3;
        bad[7] = 9;
        assert_eq!(device_descriptor(&bad).unwrap().max_packet0, 512);
        bad[7] = 64;
        assert_eq!(device_descriptor(&bad), Err(DescriptorError::MaxPacket(64)));
        assert_eq!(max_packet0(&bytes[..8]), Ok(64));
    }

    #[test]
    fn initial_packet_sizes_by_speed() {
        assert_eq!(initial_max_packet(SPEED_FULL), Some(8));
        assert_eq!(initial_max_packet(SPEED_LOW), Some(8));
        assert_eq!(initial_max_packet(SPEED_HIGH), Some(64));
        assert_eq!(initial_max_packet(SPEED_SUPER), Some(512));
        assert_eq!(initial_max_packet(5), None);
    }
}
