//! Device scope for an operator-mode target (design section 4): whether a
//! named function may be given a domain. Pure, over facts the kernel reads.
//!
//! Two phases. [`admit_scope`] judges immutable facts, compared across
//! observations by comparing the [`Scope`] it returns; [`admit_ordering`]
//! judges Device Control, which the driver itself corrects.
//!
//! The AHCI sibling entry rests on facts read from reference_host under Linux and on
//! the per-boot re-check here. They do not show that the function can never
//! issue a request, or how internal routing behaves; the owner accepted that
//! residual on 2026-11-04, and no claim of isolation from it is made.

use crate::amdvi::DeviceRefusal;
use crate::mcfg::{ExtError, ExtFacts};

/// PCIe capability Device/Port Type values.
pub const EXPRESS_ENDPOINT: u8 = 0;
pub const EXPRESS_ROOT_PORT: u8 = 4;

const CLASS_AHCI: u32 = 0x01_0601;
const CLASS_ETHERNET: u32 = 0x02_0000;
const RTL8125_REVISION: u8 = 0x05;
const HEADER_MULTIFUNCTION: u8 = 0x80;
/// AMD's PCIe dummy function, beside the E5's AHCI function.
const AHCI_SIBLING: (u16, u16, u32) = (0x1022, 0x145a, 0x13_0000);
const DEVCTL_RELAXED_ORDERING: u16 = 1 << 4;
const DEVCTL_NO_SNOOP: u16 = 1 << 11;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Driver {
    Ahci,
    Rtl8125,
}

impl Driver {
    pub fn owner(self) -> &'static str {
        match self {
            Driver::Ahci => "ahci",
            Driver::Rtl8125 => "rtl8125",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeRefusal {
    Identity,
    Revision,
    Header,
    PortType,
    Requester,
    Path,
    Peers,
    Sibling,
    Translated,
    Sriov,
    ExtendedUnreadable,
    Ordering,
    Ivrs(DeviceRefusal),
}

impl ScopeRefusal {
    pub fn word(self) -> &'static str {
        match self {
            ScopeRefusal::Identity => "identity",
            ScopeRefusal::Revision => "revision",
            ScopeRefusal::Header => "header",
            ScopeRefusal::PortType => "port-type",
            ScopeRefusal::Requester => "requester",
            ScopeRefusal::Path => "path",
            ScopeRefusal::Peers => "peers",
            ScopeRefusal::Sibling => "sibling",
            ScopeRefusal::Translated => "translated-traffic",
            ScopeRefusal::Sriov => "sr-iov",
            ScopeRefusal::ExtendedUnreadable => "extended-unreadable",
            ScopeRefusal::Ordering => "ordering",
            ScopeRefusal::Ivrs(_) => "ivrs",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpstreamPort {
    pub express_type: Option<u8>,
    pub secondary: u8,
    pub subordinate: u8,
}

/// Another function of the target's device. BARs are read, never sized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SiblingFacts {
    pub function: u8,
    pub vendor: u16,
    pub device: u16,
    pub class: u32,
    pub bus_master: bool,
    /// I/O or memory decode on.
    pub decode: bool,
    pub bars_zero: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct ScopeFacts {
    pub vendor: u16,
    pub device: u16,
    pub subsystem: u32,
    pub class: u32,
    pub revision: u8,
    pub header_type: u8,
    pub bus: u8,
    pub express_type: Option<u8>,
    /// Device Capabilities phantom functions supported.
    pub phantom_supported: u8,
    /// Device Control phantom functions enable.
    pub phantom_enabled: bool,
    pub upstream: Option<UpstreamPort>,
    /// Another device number answers on this bus.
    pub peers: bool,
    pub siblings: [Option<SiblingFacts>; 7],
    pub extended: Result<ExtFacts, ExtError>,
}

/// What was admitted: the immutable facts, for comparing observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    driver: Driver,
    vendor: u16,
    device: u16,
    class: u32,
    revision: u8,
    bus: u8,
    sibling: Option<SiblingFacts>,
}

impl Scope {
    pub fn driver(&self) -> Driver {
        self.driver
    }

    /// An accepted sibling exists: routing past it is unverified.
    pub fn sibling_accepted(&self) -> bool {
        self.sibling.is_some()
    }
}

/// QEMU's emulated ICH9 on bus 0, only in Q10 test builds. This limits where
/// the form can run; it does not prove an endpoint is emulated.
fn is_fixture(facts: &ScopeFacts) -> bool {
    (cfg!(feature = "contain-qemu-fixture") || cfg!(absd_mutant_scope_fixture_any))
        && (facts.vendor, facts.device, facts.subsystem, facts.class)
            == (0x8086, 0x2922, 0x1100_1af4, CLASS_AHCI)
}

fn identity(driver: Driver, facts: &ScopeFacts) -> Result<(), ScopeRefusal> {
    let expected = match driver {
        Driver::Ahci => (0x1022, 0x7901, CLASS_AHCI),
        Driver::Rtl8125 => (0x10ec, 0x8125, CLASS_ETHERNET),
    };
    if (facts.vendor, facts.device, facts.class) != expected {
        return Err(ScopeRefusal::Identity);
    }
    if driver == Driver::Rtl8125 && facts.revision != RTL8125_REVISION {
        return Err(ScopeRefusal::Revision);
    }
    Ok(())
}

fn sibling_ok(driver: Driver, sibling: &SiblingFacts) -> bool {
    cfg!(absd_mutant_scope_sibling_any)
        || (driver == Driver::Ahci
            && (sibling.vendor, sibling.device, sibling.class) == AHCI_SIBLING
            && !sibling.bus_master
            && !sibling.decode
            && sibling.bars_zero)
}

/// The physical shape: everything the fixture form cannot have.
fn physical_shape(facts: &ScopeFacts) -> Result<(), ScopeRefusal> {
    if facts.express_type != Some(EXPRESS_ENDPOINT) {
        return Err(ScopeRefusal::PortType);
    }
    if facts.phantom_supported != 0 || facts.phantom_enabled {
        return Err(ScopeRefusal::Requester);
    }
    let path_ok = facts.upstream.is_some_and(|port| {
        port.express_type == Some(EXPRESS_ROOT_PORT)
            && port.secondary == facts.bus
            && port.subordinate == facts.bus
    });
    if !path_ok && !cfg!(absd_mutant_scope_path_ignored) {
        return Err(ScopeRefusal::Path);
    }
    if facts.peers && !cfg!(absd_mutant_scope_peers_ignored) {
        return Err(ScopeRefusal::Peers);
    }
    let extended = facts
        .extended
        .map_err(|_| ScopeRefusal::ExtendedUnreadable)?;
    if (extended.ats_enabled && !cfg!(absd_mutant_scope_ats_ignored))
        || extended.pasid_enabled
        || extended.pri_enabled
    {
        return Err(ScopeRefusal::Translated);
    }
    if extended.sriov_vfs_enabled {
        return Err(ScopeRefusal::Sriov);
    }
    Ok(())
}

/// Whether `facts` may be given a domain for `driver`. `ivrs` is
/// `amdvi::admit_device`'s result for the function.
pub fn admit_scope(
    driver: Driver,
    facts: &ScopeFacts,
    ivrs: Result<(), DeviceRefusal>,
) -> Result<Scope, ScopeRefusal> {
    let fixture = driver == Driver::Ahci && is_fixture(facts);
    if !fixture {
        identity(driver, facts)?;
    }
    if facts.header_type & !HEADER_MULTIFUNCTION != 0 {
        return Err(ScopeRefusal::Header);
    }
    if driver == Driver::Rtl8125 && facts.header_type & HEADER_MULTIFUNCTION != 0 {
        return Err(ScopeRefusal::Sibling);
    }
    if fixture {
        if facts.bus != 0 {
            return Err(ScopeRefusal::Path);
        }
    } else {
        physical_shape(facts)?;
    }
    let mut sibling = None;
    for found in facts.siblings.iter().flatten() {
        if !sibling_ok(driver, found) {
            return Err(ScopeRefusal::Sibling);
        }
        sibling = Some(*found);
    }
    ivrs.map_err(ScopeRefusal::Ivrs)?;
    Ok(Scope {
        driver,
        vendor: facts.vendor,
        device: facts.device,
        class: facts.class,
        revision: facts.revision,
        bus: facts.bus,
        sibling,
    })
}

/// Relaxed Ordering and No Snoop must read clear in Device Control.
pub fn admit_ordering(device_control: u16) -> Result<(), ScopeRefusal> {
    if device_control & (DEVCTL_RELAXED_ORDERING | DEVCTL_NO_SNOOP) != 0 {
        return Err(ScopeRefusal::Ordering);
    }
    Ok(())
}

/// The order a driver takes a target through (design section 5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyStep {
    /// Scope admitted, nothing written.
    Eligible,
    /// Bus Master Enable read back clear, the DTE still blocked.
    BusMasterClear,
    /// Device Control corrected and read back.
    OrderingChecked,
    /// The DMA surface initialised, the device having no path to it.
    SurfaceReady,
    /// The translated DTE published and its invalidation completed.
    Exposed,
    /// Scope and ordering checked again; the driver may arm.
    Admitted,
}

/// Refuses a step out of order, so a grant cannot precede the clear.
#[derive(Clone, Copy, Debug)]
pub struct CustodySequence {
    done: u8,
}

const CUSTODY_ORDER: [CustodyStep; 6] = [
    CustodyStep::Eligible,
    CustodyStep::BusMasterClear,
    CustodyStep::OrderingChecked,
    CustodyStep::SurfaceReady,
    CustodyStep::Exposed,
    CustodyStep::Admitted,
];

impl CustodySequence {
    pub const NEW: Self = CustodySequence { done: 0 };

    pub fn advance(&mut self, step: CustodyStep) -> bool {
        let mutant = cfg!(absd_mutant_contain_grant_before_clear)
            && step == CustodyStep::Exposed
            && self.done >= 1;
        if CUSTODY_ORDER.get(self.done as usize) == Some(&step) || mutant {
            self.done = CUSTODY_ORDER.iter().position(|s| *s == step).unwrap_or(0) as u8 + 1;
            true
        } else {
            false
        }
    }

    /// From here the surface stays device-exposed for the rest of the boot.
    pub fn exposed(&self) -> bool {
        self.done >= 5
    }
}

/// The refusal path's exceptions when clearing bus mastering: IOMMUs, host
/// bridges, the function holding the framebuffer and the bridges above it.
/// `class` is base class and subclass.
pub fn refusal_exempt(class: u32, is_display: bool, on_display_path: bool) -> bool {
    class == 0x0806
        || class == 0x0600
        || is_display
        || (on_display_path && !cfg!(absd_mutant_refusal_clears_display_path))
}

#[cfg(test)]
mod tests;
