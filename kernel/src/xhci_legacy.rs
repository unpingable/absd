//! xHCI extended-capability traversal and the USB Legacy Support
//! BIOS-to-OS ownership handoff, kept apart from the MMIO driver
//! (`src/xhci.rs`) so they run under `cargo test` on the host. Lane record:
//! docs/xhci-hw-readiness-20261010/RECORD.md.
//!
//! The handoff (xHCI 1.2 section 4.22.1, register layout 7.1): firmware that
//! drives the controller itself (legacy keyboard emulation through SMM)
//! holds the HC BIOS Owned Semaphore (USBLEGSUP bit 16). The OS sets the HC
//! OS Owned Semaphore (bit 24, alone in byte 3, so it is written with one
//! byte store that cannot disturb the firmware's byte) and waits for
//! firmware to clear the BIOS semaphore. Only when the BIOS semaphore is
//! observed clear and the OS semaphore observed set does ABSD own the
//! controller; only then does it clear the SMI enables in USBLEGCTLSTS (and
//! write one to the SMI event status bits to clear them). Writing the OS
//! semaphore is a request, never ownership. A wait that ends without the
//! firmware letting go leaves the controller as firmware has it.
//!
//! Outcomes, in the managed-resource vocabulary of
//! docs/OWNERSHIP-BOUNDARIES.md: `Confirmed` (ABSD owns: COMPLETED);
//! `FirmwareRetained` (the effect did not occur: REFUSED, firmware still
//! owns); `OsSemaphoreLost`, `Lost`, `NotResponding` (contradictory or
//! unreadable: INDETERMINATE, treated like firmware ownership); `SmiStuck`
//! (ownership COMPLETED but the legacy SMIs could not be turned off: ABSD
//! owns a controller it refuses to use).

pub const EXT_LEGACY: u32 = 1;
pub const EXT_PROTOCOL: u32 = 2;
/// Extended capabilities walked before the list is refused as unbounded.
pub const EXT_LIMIT: u32 = 32;

// Field layouts from xHCI 1.2: USBLEGSUP, section 7.1.1 Table 7-4 (HC BIOS
// Owned Semaphore bit 16, HC OS Owned Semaphore bit 24); USBLEGCTLSTS,
// section 7.1.2 Table 7-5 (SMI enables bits 0, 4, 13, 14, 15; RsvdP bits
// 3:1, 12:5, 19:17; RO shadows 16 and 20; RsvdZ 28:21; RW1C SMI event bits
// 29, 30, 31). SMI_ENABLES, SMI_EVENTS and CTL_PRESERVE are each the union
// of the Table 7-5 rows of one kind (RW SMI enable, RW1C, RsvdP), so the
// table fixes them.
pub const LEGSUP_BIOS_OWNED: u32 = 1 << 16;
pub const LEGSUP_OS_OWNED: u32 = 1 << 24;
/// USBLEGCTLSTS SMI enables: USB SMI, Host System Error SMI, OS Ownership
/// SMI, PCI Command SMI, BAR SMI.
pub const SMI_ENABLES: u32 = 1 | (1 << 4) | (1 << 13) | (1 << 14) | (1 << 15);
/// USBLEGCTLSTS write-one-to-clear SMI event bits: OS Ownership Change, PCI
/// Command, BAR.
pub const SMI_EVENTS: u32 = 0b111 << 29;
/// USBLEGCTLSTS RsvdP fields, written back as read.
pub const CTL_PRESERVE: u32 = (0b111 << 1) | (0xff << 5) | (0b111 << 17);

/// The USBLEGCTLSTS value that disables every legacy SMI and clears the
/// SMI events, preserving the RsvdP fields.
pub fn smi_disable_value(control: u32) -> u32 {
    (control & CTL_PRESERVE) | SMI_EVENTS
}

/// Firmware has let go and the OS semaphore is set.
pub fn os_owns(legsup: u32) -> bool {
    legsup != u32::MAX && legsup & LEGSUP_BIOS_OWNED == 0 && legsup & LEGSUP_OS_OWNED != 0
}

/// The registers the walk reads. Offsets are BAR offsets, 4-byte aligned,
/// already checked by the walk to lie inside the BAR.
pub trait CapabilitySpace {
    /// A capability header (ID, Next Capability Pointer, specific bits).
    fn header(&mut self, offset: u64) -> u32;
    /// Any other dword of a capability.
    fn word(&mut self, offset: u64) -> u32;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalkError {
    /// More than EXT_LIMIT capabilities.
    Unbounded,
    /// A capability whose registers reach past the BAR.
    OutsideBar { offset: u64, end: u64 },
    /// A header read as all ones: the function is not answering.
    NotResponding { offset: u64 },
    /// Two USB Legacy Support capabilities: which one firmware honours is
    /// unknown.
    DuplicateLegacy { first: u64, second: u64 },
}

/// Problems with a capability's contents (not with the list's structure),
/// acted on only after ownership is settled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentRefusal {
    /// A Supported Protocol capability names no port, or ports past
    /// MaxPorts.
    PortRange { first: u8, count: u8 },
    /// A Supported Protocol capability defines its own speed IDs (PSIC).
    ProtocolSpeeds { major: u8 },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Capabilities {
    /// Offset of the USB Legacy Support capability.
    pub legacy: Option<u64>,
    pub usb2: Option<(u8, u8)>,
    pub usb3: Option<(u8, u8)>,
    /// The first content problem found, if any.
    pub content: Option<ContentRefusal>,
    pub walked: u32,
}

/// Walks the extended capability list from `first` (0: none), reading
/// headers through `space`. Structure problems end the walk with an error;
/// content problems are recorded for the caller to act on later.
pub fn walk(
    space: &mut impl CapabilitySpace,
    first: u64,
    bar_bytes: u64,
    max_ports: u8,
) -> Result<Capabilities, WalkError> {
    let mut found = Capabilities::default();
    let mut offset = first;
    let inside = |offset: u64, bytes: u64| {
        let end = offset + bytes;
        if end > bar_bytes {
            Err(WalkError::OutsideBar { offset, end })
        } else {
            Ok(())
        }
    };
    while offset != 0 {
        found.walked += 1;
        if found.walked > EXT_LIMIT {
            return Err(WalkError::Unbounded);
        }
        inside(offset, 4)?;
        let head = space.header(offset);
        if head == u32::MAX {
            return Err(WalkError::NotResponding { offset });
        }
        match head & 0xff {
            EXT_LEGACY => {
                inside(offset, 8)?;
                if let Some(first) = found.legacy {
                    return Err(WalkError::DuplicateLegacy {
                        first,
                        second: offset,
                    });
                }
                found.legacy = Some(offset);
            }
            EXT_PROTOCOL => {
                inside(offset, 12)?;
                let ports = space.word(offset + 8);
                let (first, count) = (ports as u8, (ports >> 8) as u8);
                let major = (head >> 24) as u8;
                if first == 0
                    || count == 0
                    || u16::from(first) + u16::from(count) - 1 > u16::from(max_ports)
                {
                    found
                        .content
                        .get_or_insert(ContentRefusal::PortRange { first, count });
                } else if ports >> 28 != 0 {
                    found
                        .content
                        .get_or_insert(ContentRefusal::ProtocolSpeeds { major });
                } else {
                    let range = Some((first, count));
                    match major {
                        2 if found.usb2.is_none() => found.usb2 = range,
                        3 if found.usb3.is_none() => found.usb3 = range,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        let next = u64::from((head >> 8) & 0xff);
        if next == 0 {
            break;
        }
        offset += 4 * next;
    }
    Ok(found)
}

/// The legacy registers and a clock, as the handoff sees them.
pub trait LegacyAccess {
    /// USBLEGSUP.
    fn read_legsup(&mut self) -> u32;
    /// One byte store of 1 to USBLEGSUP byte 3 (the OS semaphore).
    fn request_os(&mut self);
    /// One byte store of 0 to USBLEGSUP byte 3: the request withdrawn.
    fn withdraw_os(&mut self);
    /// USBLEGCTLSTS.
    fn read_control(&mut self) -> u32;
    fn write_control(&mut self, value: u32);
    /// Monotonic ticks.
    fn now(&mut self) -> u64;
    /// Waits for the next tick.
    fn pause(&mut self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Confirmed {
    /// USBLEGSUP and USBLEGCTLSTS as found.
    pub initial: u32,
    pub initial_control: u32,
    /// Whether ABSD had to set the OS semaphore (false: already set).
    pub requested: bool,
    /// Ticks from the request until the BIOS semaphore read clear.
    pub waited: u64,
    /// USBLEGCTLSTS before and after the SMI disable.
    pub smi_before: u32,
    pub smi_after: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffError {
    /// The BIOS semaphore was still set when the bound expired.
    FirmwareRetained { legsup: u32, waited: u64 },
    /// The OS semaphore read clear after ABSD set it, before firmware let
    /// go: firmware cleared it, or the write did not take.
    OsSemaphoreLost { legsup: u32 },
    /// USBLEGSUP read as all ones.
    NotResponding,
    /// Ownership had been confirmed, then the semaphores stopped showing
    /// it (BIOS set again or OS clear).
    Lost { legsup: u32 },
    /// As `Lost`, but seen after ABSD had cleared the SMI enables (which
    /// were `smi_before`): firmware owns a controller whose SMI control
    /// ABSD changed.
    LostAfterSmi { legsup: u32, smi_before: u32 },
    /// ABSD owns the controller, but SMI enables stayed set after it
    /// cleared them.
    SmiStuck { before: u32, after: u32 },
}

impl HandoffError {
    /// Whether ABSD owns the controller despite the error (so it may halt
    /// it and take it off the bus); otherwise the controller is left as
    /// firmware has it.
    pub fn absd_owns(self) -> bool {
        matches!(self, Self::SmiStuck { .. })
    }
}

/// Re-checks ownership at a later point (before any further change to the
/// controller): the semaphores must still show the OS as sole owner.
pub fn holds(access: &mut impl LegacyAccess) -> Result<(), HandoffError> {
    let legsup = access.read_legsup();
    if legsup == u32::MAX {
        return Err(HandoffError::NotResponding);
    }
    if !os_owns(legsup) {
        return Err(HandoffError::Lost { legsup });
    }
    Ok(())
}

/// The custody label for a handoff that did not give ABSD the controller,
/// from the error and USBLEGSUP read after any request was withdrawn.
/// `firmware`: firmware still holds its semaphore and nothing of ABSD's is
/// outstanding. `indeterminate-late-release`: the wait ended, but firmware
/// had let go by the time the request was withdrawn, so nobody may own the
/// controller. `indeterminate-smi-cleared`: firmware took it back after
/// ABSD had cleared the SMI enables. `indeterminate`: contradictory or
/// unreadable semaphores.
pub fn custody(error: HandoffError, legsup_after: u32) -> &'static str {
    match error {
        HandoffError::FirmwareRetained { .. }
            if legsup_after != u32::MAX && legsup_after & LEGSUP_BIOS_OWNED == 0 =>
        {
            "indeterminate-late-release"
        }
        HandoffError::FirmwareRetained { .. } => "firmware",
        HandoffError::LostAfterSmi { .. } => "indeterminate-smi-cleared",
        _ => "indeterminate",
    }
}

/// The handoff. Until it returns `Ok`, the only writes it makes are the
/// OS-semaphore byte store and (after ownership is confirmed) USBLEGCTLSTS.
/// The wait for firmware is bounded by `limit` ticks from the request.
/// When it fails without ABSD owning the controller, a request ABSD made
/// is withdrawn (one byte store of 0), so firmware is not left with an
/// outstanding request it might honour later. That includes
/// `NotResponding` after the request: a controller that stops answering
/// mid-poll and later recovers must not find the request still set (a
/// store to a function that is gone is lost, and changes nothing).
pub fn handoff(access: &mut impl LegacyAccess, limit: u64) -> Result<Confirmed, HandoffError> {
    let initial = access.read_legsup();
    if initial == u32::MAX {
        return Err(HandoffError::NotResponding);
    }
    let requested = initial & LEGSUP_OS_OWNED == 0;
    let result = negotiate(access, limit, initial, requested);
    if let Err(error) = result
        && requested
        && !error.absd_owns()
    {
        access.withdraw_os();
    }
    result
}

fn negotiate(
    access: &mut impl LegacyAccess,
    limit: u64,
    initial: u32,
    requested: bool,
) -> Result<Confirmed, HandoffError> {
    let initial_control = access.read_control();
    if requested {
        access.request_os();
    }
    let start = access.now();
    loop {
        let legsup = access.read_legsup();
        if legsup == u32::MAX {
            return Err(HandoffError::NotResponding);
        }
        if legsup & LEGSUP_OS_OWNED == 0 {
            return Err(HandoffError::OsSemaphoreLost { legsup });
        }
        if legsup & LEGSUP_BIOS_OWNED == 0 {
            break;
        }
        let waited = access.now().wrapping_sub(start);
        if waited > limit {
            return Err(HandoffError::FirmwareRetained { legsup, waited });
        }
        access.pause();
    }
    let waited = access.now().wrapping_sub(start);
    // A second, independent read must agree before ownership is acted on.
    holds(access)?;
    let smi_before = access.read_control();
    access.write_control(smi_disable_value(smi_before));
    let smi_after = access.read_control();
    // Ownership must still hold after the SMI write (the write itself is
    // something firmware could react to).
    holds(access).map_err(|error| match error {
        HandoffError::Lost { legsup } => HandoffError::LostAfterSmi { legsup, smi_before },
        other => other,
    })?;
    if smi_after & SMI_ENABLES != 0 {
        return Err(HandoffError::SmiStuck {
            before: smi_before,
            after: smi_after,
        });
    }
    Ok(Confirmed {
        initial,
        initial_control,
        requested,
        waited,
        smi_before,
        smi_after,
    })
}

/// Qualification only: a scripted model of firmware's side of the USB
/// Legacy Support capability, for controllers (QEMU's) that have none. It
/// keeps USBLEGSUP/USBLEGCTLSTS, answers the OS semaphore according to its
/// behaviour, and records a violation whenever the driver changes the
/// controller (or its SMI control) while the model does not show the OS as
/// owner. The driver routes its register writes and PCI command changes
/// through `controller_write`; the model sees nothing the driver does
/// outside those paths.
pub mod model {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Behaviour {
        /// BIOS-owned; releases as soon as the OS asks.
        Release,
        /// BIOS-owned; releases this many ticks after the OS asks.
        Delayed(u64),
        /// BIOS-owned; never releases.
        Never,
        /// BIOS-owned; when the OS asks, firmware also turns on more SMIs
        /// and raises an SMI event, then releases after this many ticks.
        SmiFlip(u64),
        /// BIOS-owned; releases at once, but its SMI enables ignore writes.
        SmiStuck,
        /// BIOS-owned; when the OS asks, firmware clears both semaphores.
        ClearsOs,
        /// BIOS-owned; releases at once, then takes the controller back at
        /// this USBLEGSUP read after the SMI control write (1: the first).
        Reacquire(u32),
        /// Neither semaphore set, SMIs enabled.
        Unowned,
        /// Two USB Legacy Support capabilities (the splice presents both).
        Duplicate,
    }

    impl Behaviour {
        pub fn parse(name: &[u8]) -> Option<Self> {
            Some(match name {
                b"release" => Self::Release,
                b"delayed" => Self::Delayed(300),
                b"late" => Self::Delayed(1500),
                b"reacquire-smi" => Self::Reacquire(1),
                b"never" => Self::Never,
                b"smi-flip" => Self::SmiFlip(50),
                b"smi-stuck" => Self::SmiStuck,
                b"clears-os" => Self::ClearsOs,
                b"reacquire" => Self::Reacquire(2),
                b"reacquire-late" => Self::Reacquire(3),
                b"unowned" => Self::Unowned,
                b"duplicate" => Self::Duplicate,
                _ => return None,
            })
        }
    }

    /// The SMI enables firmware leaves on: USB SMI and OS Ownership SMI.
    pub const FIRMWARE_SMIS: u32 = 1 | (1 << 13);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Firmware {
        pub behaviour: Behaviour,
        legsup: u32,
        control: u32,
        requested_at: Option<u64>,
        control_written: bool,
        reads_after_control: u32,
        /// Firmware took the controller back (Reacquire); it keeps it.
        reacquired: bool,
        pub violations: u32,
        /// The first violation: what was written, and where.
        pub first_violation: Option<(&'static str, u64)>,
        pub requests: u32,
        pub withdrawals: u32,
    }

    impl Firmware {
        pub fn new(behaviour: Behaviour) -> Self {
            Self {
                behaviour,
                legsup: match behaviour {
                    Behaviour::Unowned => EXT_LEGACY,
                    _ => EXT_LEGACY | LEGSUP_BIOS_OWNED,
                },
                control: FIRMWARE_SMIS,
                requested_at: None,
                control_written: false,
                reads_after_control: 0,
                reacquired: false,
                violations: 0,
                first_violation: None,
                requests: 0,
                withdrawals: 0,
            }
        }

        /// USBLEGSUP and USBLEGCTLSTS as they stand, without advancing.
        pub fn registers(&self) -> (u32, u32) {
            (self.legsup, self.control)
        }

        /// Whether the semaphores show the OS as sole owner.
        pub fn os_owns(&self) -> bool {
            os_owns(self.legsup)
        }

        fn violation(&mut self, what: &'static str, offset: u64) {
            self.violations += 1;
            self.first_violation.get_or_insert((what, offset));
        }

        fn advance(&mut self, now: u64) {
            let Some(at) = self.requested_at else {
                return;
            };
            if self.reacquired || self.legsup & LEGSUP_BIOS_OWNED == 0 {
                return;
            }
            let elapsed = now.wrapping_sub(at);
            let release = match self.behaviour {
                Behaviour::Release | Behaviour::SmiStuck | Behaviour::Reacquire(_) => true,
                Behaviour::Delayed(ticks) | Behaviour::SmiFlip(ticks) => elapsed >= ticks,
                Behaviour::Never | Behaviour::ClearsOs | Behaviour::Unowned => false,
                Behaviour::Duplicate => true,
            };
            if release {
                self.legsup &= !LEGSUP_BIOS_OWNED;
            }
        }

        /// USBLEGSUP.
        pub fn read_legsup(&mut self, now: u64) -> u32 {
            self.advance(now);
            if self.control_written
                && let Behaviour::Reacquire(at) = self.behaviour
            {
                self.reads_after_control += 1;
                if self.reads_after_control == at {
                    self.reacquired = true;
                    self.legsup = (self.legsup | LEGSUP_BIOS_OWNED) & !LEGSUP_OS_OWNED;
                }
            }
            self.legsup
        }

        /// A byte store to USBLEGSUP byte `byte` (0..=3).
        pub fn write_legsup_byte(&mut self, byte: u64, value: u8, now: u64) {
            match byte {
                3 => {
                    if value & 1 != 0 {
                        self.requests += 1;
                        self.legsup |= LEGSUP_OS_OWNED;
                        self.requested_at.get_or_insert(now);
                        match self.behaviour {
                            Behaviour::SmiFlip(_) => {
                                self.control |= (1 << 4) | (1 << 15) | (1 << 29);
                            }
                            Behaviour::ClearsOs => {
                                self.legsup &= !(LEGSUP_OS_OWNED | LEGSUP_BIOS_OWNED);
                            }
                            _ => {}
                        }
                    } else {
                        // A withdrawn request is no request: a delayed
                        // release does not happen any more.
                        self.legsup &= !LEGSUP_OS_OWNED;
                        self.requested_at = None;
                        self.withdrawals += 1;
                    }
                    self.advance(now);
                }
                // Only firmware writes the BIOS semaphore's byte; the ID and
                // pointer bytes are read-only.
                2 => self.violation("legsup bios byte", byte),
                _ => {}
            }
        }

        /// A dword store to USBLEGSUP: only the OS semaphore is the
        /// driver's; a change to the BIOS semaphore is a violation.
        pub fn write_legsup(&mut self, value: u32, now: u64) {
            if (value ^ self.legsup) & LEGSUP_BIOS_OWNED != 0 {
                self.violation("legsup bios semaphore", 0);
            }
            self.write_legsup_byte(3, (value >> 24) as u8, now);
        }

        /// USBLEGCTLSTS.
        pub fn read_control(&mut self, now: u64) -> u32 {
            self.advance(now);
            self.control
        }

        pub fn write_control(&mut self, value: u32, now: u64) {
            self.advance(now);
            if !self.os_owns() {
                self.violation("smi control", 4);
            }
            self.control_written = true;
            let enables = if self.behaviour == Behaviour::SmiStuck {
                self.control & SMI_ENABLES
            } else {
                value & SMI_ENABLES
            };
            let events = self.control & SMI_EVENTS & !(value & SMI_EVENTS);
            self.control = (self.control & !(SMI_ENABLES | SMI_EVENTS)) | enables | events;
        }

        /// The driver changed the controller (a register write outside this
        /// capability, or the PCI command register): legitimate only while
        /// the OS owns it.
        pub fn controller_write(&mut self, what: &'static str, offset: u64, now: u64) {
            self.advance(now);
            if !self.os_owns() {
                self.violation(what, offset);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    use super::model::{Behaviour, FIRMWARE_SMIS, Firmware};
    use super::*;

    /// A capability list held in memory: dword index = offset / 4.
    struct Space(Vec<u32>);

    impl CapabilitySpace for Space {
        fn header(&mut self, offset: u64) -> u32 {
            self.0[(offset / 4) as usize]
        }
        fn word(&mut self, offset: u64) -> u32 {
            self.0[(offset / 4) as usize]
        }
    }

    fn header(id: u32, next_dwords: u32, specific: u32) -> u32 {
        id | (next_dwords << 8) | (specific << 16)
    }

    /// QEMU qemu-xhci's list as the guest reads it (two Supported Protocol
    /// capabilities at 0x20 and 0x30), with room to splice after it.
    fn qemu_like() -> Space {
        let mut words = vec![0u32; 0x1000 / 4];
        words[0x20 / 4] = header(EXT_PROTOCOL, 4, 0x0200);
        words[0x28 / 4] = 5 | (4 << 8);
        words[0x30 / 4] = header(EXT_PROTOCOL, 0, 0x0300);
        words[0x38 / 4] = 1 | (4 << 8);
        Space(words)
    }

    #[test]
    fn walk_reads_protocols_and_legacy() {
        let mut space = qemu_like();
        let found = walk(&mut space, 0x20, 0x1000, 8).unwrap();
        assert_eq!(found.usb2, Some((5, 4)));
        assert_eq!(found.usb3, Some((1, 4)));
        assert_eq!(found.legacy, None);
        assert_eq!(found.walked, 2);
        // A legacy capability spliced after the last one.
        space.0[0x30 / 4] = header(EXT_PROTOCOL, (0x100 - 0x30) / 4, 0x0300);
        space.0[0x100 / 4] = header(EXT_LEGACY, 0, LEGSUP_BIOS_OWNED >> 16);
        let found = walk(&mut space, 0x20, 0x1000, 8).unwrap();
        assert_eq!(found.legacy, Some(0x100));
        assert_eq!(found.walked, 3);
        assert_eq!(walk(&mut space, 0, 0x1000, 8).unwrap().walked, 0);
    }

    #[test]
    fn walk_refuses_malformed_lists() {
        // Duplicate legacy capability.
        let mut space = qemu_like();
        space.0[0x30 / 4] = header(EXT_PROTOCOL, (0x100 - 0x30) / 4, 0x0300);
        space.0[0x100 / 4] = header(EXT_LEGACY, 4, 1);
        space.0[0x110 / 4] = header(EXT_LEGACY, 0, 1);
        assert_eq!(
            walk(&mut space, 0x20, 0x1000, 8),
            Err(WalkError::DuplicateLegacy {
                first: 0x100,
                second: 0x110
            })
        );
        // A chain that never ends within the bound (1-dword steps).
        let mut chain = Space(vec![header(0xc0, 1, 0); 0x1000 / 4]);
        assert_eq!(walk(&mut chain, 0x20, 0x1000, 8), Err(WalkError::Unbounded));
        // Legacy registers past the BAR.
        let mut space = qemu_like();
        space.0[0x30 / 4] = header(EXT_PROTOCOL, (0xfc - 0x30) / 4, 0x0300);
        space.0[0xfc / 4] = header(EXT_LEGACY, 0, 1);
        assert_eq!(
            walk(&mut space, 0x20, 0x100, 8),
            Err(WalkError::OutsideBar {
                offset: 0xfc,
                end: 0x104
            })
        );
        // The first capability past the BAR.
        assert_eq!(
            walk(&mut qemu_like(), 0x1000, 0x1000, 8),
            Err(WalkError::OutsideBar {
                offset: 0x1000,
                end: 0x1004
            })
        );
        // An all-ones header: nothing answering.
        let mut space = qemu_like();
        space.0[0x30 / 4] = u32::MAX;
        assert_eq!(
            walk(&mut space, 0x20, 0x1000, 8),
            Err(WalkError::NotResponding { offset: 0x30 })
        );
    }

    #[test]
    fn walk_defers_content_problems() {
        let mut space = qemu_like();
        space.0[0x28 / 4] = 7 | (4 << 8); // ports 7-10 of 8
        space.0[0x38 / 4] = 1 | (4 << 8) | (1 << 28); // PSIC 1
        let found = walk(&mut space, 0x20, 0x1000, 8).unwrap();
        assert_eq!(
            found.content,
            Some(ContentRefusal::PortRange { first: 7, count: 4 })
        );
        assert_eq!(found.usb2, None);
        assert_eq!(found.usb3, None);
        space.0[0x28 / 4] = 5 | (4 << 8);
        assert_eq!(
            walk(&mut space, 0x20, 0x1000, 8).unwrap().content,
            Some(ContentRefusal::ProtocolSpeeds { major: 3 })
        );
        space.0[0x28 / 4] = 0;
        assert_eq!(
            walk(&mut space, 0x20, 0x1000, 8).unwrap().content,
            Some(ContentRefusal::PortRange { first: 0, count: 0 })
        );
    }

    #[test]
    fn smi_disable_keeps_reserved_and_clears_events() {
        let control = 0xffff_ffff;
        let value = smi_disable_value(control);
        assert_eq!(value & SMI_ENABLES, 0);
        assert_eq!(value & SMI_EVENTS, SMI_EVENTS);
        assert_eq!(value & CTL_PRESERVE, CTL_PRESERVE);
        assert_eq!(smi_disable_value(FIRMWARE_SMIS), SMI_EVENTS);
    }

    /// The handoff driven against the firmware model, one tick per pause.
    /// Every write the handoff makes goes to the model, which flags
    /// premature ones.
    struct Bench {
        firmware: Firmware,
        now: u64,
        /// Simulates a driver that changes the controller before the
        /// handoff returns (the premature-manipulation negative control).
        premature: bool,
    }

    impl LegacyAccess for Bench {
        fn read_legsup(&mut self) -> u32 {
            self.firmware.read_legsup(self.now)
        }
        fn request_os(&mut self) {
            if self.premature {
                self.firmware.controller_write("usbcmd", 0x80, self.now);
            }
            self.firmware.write_legsup_byte(3, 1, self.now);
        }
        fn withdraw_os(&mut self) {
            self.firmware.write_legsup_byte(3, 0, self.now);
        }
        fn read_control(&mut self) -> u32 {
            self.firmware.read_control(self.now)
        }
        fn write_control(&mut self, value: u32) {
            self.firmware.write_control(value, self.now);
        }
        fn now(&mut self) -> u64 {
            self.now
        }
        fn pause(&mut self) {
            self.now += 1;
        }
    }

    fn bench(behaviour: Behaviour) -> Bench {
        Bench {
            firmware: Firmware::new(behaviour),
            now: 1000,
            premature: false,
        }
    }

    const LIMIT: u64 = 1000;

    #[test]
    fn immediate_release_is_confirmed_then_smis_disabled() {
        let mut b = bench(Behaviour::Release);
        let done = handoff(&mut b, LIMIT).unwrap();
        assert!(done.requested);
        assert_eq!(done.waited, 0);
        assert_eq!(done.initial & LEGSUP_BIOS_OWNED, LEGSUP_BIOS_OWNED);
        assert_eq!(done.smi_before, FIRMWARE_SMIS);
        assert_eq!(done.smi_after & SMI_ENABLES, 0);
        assert_eq!(b.firmware.violations, 0);
        assert!(b.firmware.os_owns());
        assert_eq!(holds(&mut b), Ok(()));
    }

    #[test]
    fn delayed_release_waits_within_the_bound() {
        let mut b = bench(Behaviour::Delayed(300));
        let done = handoff(&mut b, LIMIT).unwrap();
        assert_eq!(done.waited, 300);
        assert_eq!(b.firmware.violations, 0);
        // A release later than the bound is a refusal, not a success.
        let mut late = bench(Behaviour::Delayed(LIMIT + 5));
        assert!(matches!(
            handoff(&mut late, LIMIT),
            Err(HandoffError::FirmwareRetained { waited, .. }) if waited == LIMIT + 1
        ));
    }

    #[test]
    fn firmware_that_never_releases_is_left_owning() {
        let mut b = bench(Behaviour::Never);
        let error = handoff(&mut b, LIMIT).unwrap_err();
        assert!(
            matches!(error, HandoffError::FirmwareRetained { legsup, waited }
            if legsup & LEGSUP_BIOS_OWNED != 0 && waited == LIMIT + 1)
        );
        assert!(!error.absd_owns());
        // No SMI control write, nothing else.
        assert_eq!(b.firmware.read_control(b.now), FIRMWARE_SMIS);
        assert_eq!(b.firmware.violations, 0);
        // Bounded: the clock advanced by exactly the limit plus one tick.
        assert_eq!(b.now, 1000 + LIMIT + 1);
    }

    #[test]
    fn smi_changes_during_negotiation_are_all_disabled_after() {
        let mut b = bench(Behaviour::SmiFlip(50));
        let done = handoff(&mut b, LIMIT).unwrap();
        assert_eq!(done.waited, 50);
        assert_eq!(
            done.smi_before & (SMI_ENABLES | SMI_EVENTS),
            FIRMWARE_SMIS | (1 << 4) | (1 << 15) | (1 << 29)
        );
        assert_eq!(done.smi_after & (SMI_ENABLES | SMI_EVENTS), 0);
        assert_eq!(b.firmware.violations, 0);
    }

    #[test]
    fn stuck_smis_are_refused_with_absd_owning() {
        let mut b = bench(Behaviour::SmiStuck);
        let error = handoff(&mut b, LIMIT).unwrap_err();
        assert!(matches!(error, HandoffError::SmiStuck { after, .. } if after & SMI_ENABLES != 0));
        assert!(error.absd_owns());
        assert_eq!(b.firmware.violations, 0);
    }

    #[test]
    fn contradictory_semaphores_are_not_ownership() {
        let mut b = bench(Behaviour::ClearsOs);
        assert_eq!(
            handoff(&mut b, LIMIT),
            Err(HandoffError::OsSemaphoreLost { legsup: EXT_LEGACY })
        );
        assert_eq!(b.firmware.violations, 0);
        // Taken back right after the SMI write: lost inside the handoff.
        let mut b = bench(Behaviour::Reacquire(1));
        assert!(matches!(
            handoff(&mut b, LIMIT),
            Err(HandoffError::LostAfterSmi { legsup, .. }) if legsup & LEGSUP_BIOS_OWNED != 0
        ));
        // Taken back at the next check: the handoff succeeds, the later
        // `holds` (before any controller change) catches it.
        let mut b = bench(Behaviour::Reacquire(2));
        handoff(&mut b, LIMIT).unwrap();
        assert!(matches!(holds(&mut b), Err(HandoffError::Lost { .. })));
        b.firmware.controller_write("usbcmd", 0x80, b.now);
        assert_eq!(b.firmware.violations, 1);
    }

    #[test]
    fn unowned_controller_is_claimed() {
        let mut b = bench(Behaviour::Unowned);
        let done = handoff(&mut b, LIMIT).unwrap();
        assert_eq!(done.initial & (LEGSUP_BIOS_OWNED | LEGSUP_OS_OWNED), 0);
        assert!(done.requested);
        assert_eq!(done.smi_after & SMI_ENABLES, 0);
        assert_eq!(b.firmware.violations, 0);
        // Already OS-owned: no second request.
        let again = handoff(&mut b, LIMIT).unwrap();
        assert!(!again.requested);
        assert_eq!(b.firmware.requests, 1);
    }

    #[test]
    fn all_ones_is_not_answering() {
        struct Gone;
        impl LegacyAccess for Gone {
            fn read_legsup(&mut self) -> u32 {
                u32::MAX
            }
            fn request_os(&mut self) {
                panic!("no write to a function that is not answering");
            }
            fn withdraw_os(&mut self) {
                panic!("no write to a function that is not answering");
            }
            fn read_control(&mut self) -> u32 {
                u32::MAX
            }
            fn write_control(&mut self, _: u32) {
                panic!("no write to a function that is not answering");
            }
            fn now(&mut self) -> u64 {
                0
            }
            fn pause(&mut self) {}
        }
        assert_eq!(handoff(&mut Gone, LIMIT), Err(HandoffError::NotResponding));
        assert_eq!(holds(&mut Gone), Err(HandoffError::NotResponding));
    }

    #[test]
    fn a_controller_that_stops_answering_mid_poll_has_the_request_withdrawn() {
        /// The bench, with USBLEGSUP reading all ones from tick `gone`
        /// until tick `back`, then answering again.
        struct Vanishing {
            bench: Bench,
            gone: u64,
            back: u64,
        }
        impl LegacyAccess for Vanishing {
            fn read_legsup(&mut self) -> u32 {
                let now = self.bench.now;
                if (self.gone..self.back).contains(&now) {
                    u32::MAX
                } else {
                    self.bench.read_legsup()
                }
            }
            fn request_os(&mut self) {
                self.bench.request_os();
            }
            fn withdraw_os(&mut self) {
                self.bench.withdraw_os();
            }
            fn read_control(&mut self) -> u32 {
                self.bench.read_control()
            }
            fn write_control(&mut self, value: u32) {
                self.bench.write_control(value);
            }
            fn now(&mut self) -> u64 {
                self.bench.now()
            }
            fn pause(&mut self) {
                self.bench.pause();
            }
        }
        let start = 1000;
        // The model receives the withdrawal store even while reads fail (a
        // transient read failure): this proves the store is issued and that
        // a delivered one cancels the request, not that it lands on a
        // function that is truly gone (there it is lost; see `handoff`).
        // Firmware that never releases; the controller drops out 100
        // ticks into the poll and comes back after the handoff gave up.
        let mut v = Vanishing {
            bench: bench(Behaviour::Never),
            gone: start + 100,
            back: start + 200,
        };
        assert_eq!(handoff(&mut v, LIMIT), Err(HandoffError::NotResponding));
        assert_eq!(v.bench.now, start + 100);
        assert_eq!(v.bench.firmware.withdrawals, 1);
        assert_eq!(v.bench.firmware.violations, 0);
        v.bench.now = v.back + LIMIT;
        let after = v.read_legsup();
        assert_eq!(after, EXT_LEGACY | LEGSUP_BIOS_OWNED);
        assert_eq!(v.read_control(), FIRMWARE_SMIS);
        assert_eq!(custody(HandoffError::NotResponding, after), "indeterminate");
        // Firmware that would release while the controller is not
        // answering: the withdrawal cancels the release, so on recovery
        // the semaphores are as found, not OS-owned with nobody holding it.
        let mut v = Vanishing {
            bench: bench(Behaviour::Delayed(300)),
            gone: start + 100,
            back: start + 200,
        };
        assert_eq!(handoff(&mut v, LIMIT), Err(HandoffError::NotResponding));
        assert_eq!(v.bench.firmware.withdrawals, 1);
        v.bench.now = v.back + LIMIT;
        assert_eq!(v.read_legsup(), EXT_LEGACY | LEGSUP_BIOS_OWNED);
        assert!(!v.bench.firmware.os_owns());
        assert_eq!(v.bench.firmware.violations, 0);
        // Not answering from the first read: nothing requested, nothing
        // withdrawn (also `all_ones_is_not_answering`).
        let mut v = Vanishing {
            bench: bench(Behaviour::Never),
            gone: 0,
            back: u64::MAX,
        };
        assert_eq!(handoff(&mut v, LIMIT), Err(HandoffError::NotResponding));
        assert_eq!(v.bench.firmware.withdrawals, 0);
        assert_eq!(
            v.bench.firmware.read_legsup(v.bench.now),
            EXT_LEGACY | LEGSUP_BIOS_OWNED
        );
    }

    #[test]
    fn the_model_flags_premature_controller_changes() {
        // The negative control the kernel cases rely on: a driver that
        // touches the controller before ownership is confirmed is seen.
        let mut b = bench(Behaviour::Delayed(10));
        b.premature = true;
        handoff(&mut b, LIMIT).unwrap();
        assert_eq!(b.firmware.violations, 1);
        assert_eq!(b.firmware.first_violation, Some(("usbcmd", 0x80)));
        // SMI control written while firmware owns.
        let mut f = Firmware::new(Behaviour::Never);
        f.write_control(0, 0);
        assert_eq!(f.first_violation, Some(("smi control", 4)));
        // Writing the BIOS semaphore is never the driver's.
        let mut f = Firmware::new(Behaviour::Release);
        f.write_legsup(0, 0);
        assert_eq!(f.first_violation, Some(("legsup bios semaphore", 0)));
    }

    #[test]
    fn a_handoff_that_trusts_its_own_write_is_caught() {
        // Missing-confirmation negative control: treating the OS semaphore
        // write as ownership and writing SMI control at once is flagged.
        let mut f = Firmware::new(Behaviour::Never);
        f.write_legsup_byte(3, 1, 0);
        let control = f.read_control(0);
        f.write_control(smi_disable_value(control), 0);
        f.controller_write("usbcmd", 0x80, 0);
        assert_eq!(f.violations, 2);
    }

    #[test]
    fn a_request_that_fails_is_withdrawn_and_custody_named() {
        // Never: the request is withdrawn, the semaphores are as found.
        let mut b = bench(Behaviour::Never);
        let error = handoff(&mut b, LIMIT).unwrap_err();
        let after = b.firmware.read_legsup(b.now);
        assert_eq!(after, EXT_LEGACY | LEGSUP_BIOS_OWNED);
        assert_eq!(b.firmware.withdrawals, 1);
        assert_eq!(custody(error, after), "firmware");
        // Late: firmware would release after the bound; the withdrawal
        // cancels it, so it never does.
        let mut b = bench(Behaviour::Delayed(LIMIT + 500));
        let error = handoff(&mut b, LIMIT).unwrap_err();
        b.now += 2 * LIMIT;
        let after = b.firmware.read_legsup(b.now);
        assert_eq!(after, EXT_LEGACY | LEGSUP_BIOS_OWNED);
        assert_eq!(custody(error, after), "firmware");
        // Had firmware let go anyway, the label says nobody may own it.
        assert_eq!(custody(error, EXT_LEGACY), "indeterminate-late-release");
        // Lost after the SMI write: named apart, carrying the old enables.
        let mut b = bench(Behaviour::Reacquire(1));
        let error = handoff(&mut b, LIMIT).unwrap_err();
        assert!(
            matches!(error, HandoffError::LostAfterSmi { smi_before, .. }
            if smi_before == FIRMWARE_SMIS)
        );
        assert_eq!(custody(error, 0), "indeterminate-smi-cleared");
        assert_eq!(b.firmware.withdrawals, 1);
        // Nothing withdrawn when nothing was requested, or when ABSD owns.
        let mut b = bench(Behaviour::SmiStuck);
        handoff(&mut b, LIMIT).unwrap_err();
        assert_eq!(b.firmware.withdrawals, 0);
        assert_eq!(
            custody(HandoffError::NotResponding, u32::MAX),
            "indeterminate"
        );
    }
}
