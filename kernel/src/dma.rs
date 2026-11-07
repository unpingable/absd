//! The one choke point that arms PCI bus mastering (#111 DESIGN §0).
//!
//! Every driver that lets a device reach memory calls [`arm`] (or
//! [`arm_ide`]) with its declaration from `absd_kernel::dma_policy`. The
//! setters in `pci` take an [`Armed`] token, which only this module can
//! make (its field is private), names the one function admitted, and is
//! spent by the write; `pci`'s only configuration writer accepts either
//! that or a guarded value (src/pci.rs). A host test (`dma_policy::tests`)
//! backs this with a source check against raw port I/O, which types cannot
//! rule out. The decision is `dma_policy::decide` under the boot's
//! profile. Increment 2 boots only `Recording` (observational): every arm
//! proceeds exactly as before and is recorded per function. With the
//! `dma-report` option each arm is also printed as a `DMA ARM` line, and
//! functions firmware left bus-mastering are listed as `DMA INHERITED`
//! before any driver runs; those are not mediated by anything here.
//! Production boots report them only (owner decision, Option A): no
//! physical DMA-containment claim while they are not controlled, and
//! clearing BME after kernel entry would not remove the exposure before it
//! (docs/RTL8125.md).

use crate::pci::{self, Function};
use crate::serial::Serial;
use absd_kernel::dma_policy::{self, Declaration, Profile, Refusal, State, VmEnvelopeObserved};
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};

/// Permission to set bus mastering on one function, from [`arm`] only.
pub struct Armed {
    function: Function,
}

impl Armed {
    pub fn function(&self) -> Function {
        self.function
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Refused {
    pub state: State,
    pub profile: Profile,
    pub reason: Refusal,
}

const MAX_RECORDS: usize = 8;

#[derive(Clone, Copy)]
struct Record {
    function: Function,
    owner: &'static str,
    arms: u32,
}

static mut RECORDS: [Option<Record>; MAX_RECORDS] = [None; MAX_RECORDS];
static REPORT: AtomicBool = AtomicBool::new(false);

/// Buffer sets retained for the rest of the boot (#111 DESIGN §4): the dma
/// seam is their custodian. Nothing here or elsewhere frees or re-grants
/// them; the record only counts and reports.
static RETAINED_SETS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Takes custody of `owner`'s buffer set `set` (its pages): reported, never
/// released for the rest of the boot.
pub fn retain(owner: &'static str, set: usize, pages: &[u64]) {
    let total = RETAINED_SETS.fetch_add(1, Ordering::AcqRel) + 1;
    let _ = writeln!(
        Serial,
        "DMA RETAINED owner={owner} set={set} pages={} first={:#x} custodian=dma release=never retained-sets={total}",
        pages.len(),
        pages.first().copied().unwrap_or(0)
    );
}

/// Prints a `DMA ARM` line for every later arm (boot option `dma-report`).
pub fn report_arms() {
    REPORT.store(true, Ordering::Release);
}

/// One function found with Bus Master Enable set at hand-off.
#[derive(Clone, Copy, PartialEq)]
pub struct Inherited {
    pub function: Function,
    pub vendor: u16,
    pub device: u16,
    pub class: u32,
    pub command: u16,
}

/// At most this many inherited bus masters are recorded; more sets the
/// overflow flag, on which the AMD-Vi boots refuse to enable (their
/// disclosure and priority invalidation would be incomplete).
pub const MAX_INHERITED: usize = 64;
static mut INHERITED: dma_policy::BoundedSet<Inherited, MAX_INHERITED> =
    dma_policy::BoundedSet::EMPTY;
static INHERITED_REPORTED: AtomicBool = AtomicBool::new(false);

/// Records every function whose bus mastering is already on (firmware or an
/// earlier stage left it; no `dma::arm` admitted it). Configuration reads
/// only: nothing is printed and nothing changes (#111 increment 6). Called
/// at kernel entry, before anything else touches PCI, and may be called
/// again later (the AMD-Vi boots call it once more just before the unit is
/// enabled): a function seen bus-mastering by any call stays recorded.
pub fn snapshot_inherited() {
    let table = unsafe { &mut *core::ptr::addr_of_mut!(INHERITED) };
    pci::each(|function| {
        let command = pci::command(function);
        if command & (1 << 2) == 0 {
            return;
        }
        let (vendor, device) = pci::ids(function);
        let entry = Inherited {
            function,
            vendor,
            device,
            class: pci::read32(function, 0x08) >> 8,
            command,
        };
        let _ = table.insert_by(entry, |i| i.function);
    });
}

/// Whether more inherited bus masters were seen than recorded.
pub fn inherited_overflow() -> bool {
    unsafe { &*core::ptr::addr_of!(INHERITED) }.overflow()
}

/// The recorded inherited bus masters.
pub fn inherited() -> impl Iterator<Item = Inherited> {
    unsafe { &*core::ptr::addr_of!(INHERITED) }.iter()
}

/// Prints the boot report's inherited bus-master list, once:
/// `DMA INHERITED bdf=... vendor:device=... bme=1` per function, then a
/// total. Observation only: the dma seam mediates new enables; these
/// functions are outside containment in normal boots (DESIGN §5,
/// physical-support blocker).
pub fn report_inherited() {
    if INHERITED_REPORTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let mut total = 0u32;
    for i in inherited() {
        total += 1;
        let _ = writeln!(
            Serial,
            "DMA INHERITED bdf={:02x}:{:02x}.{} vendor:device={:04x}:{:04x} bme=1 class={:#08x} command={:#06x} containment=uncontained",
            i.function.bus,
            i.function.device,
            i.function.function,
            i.vendor,
            i.device,
            i.class,
            i.command,
        );
    }
    let _ = writeln!(
        Serial,
        "DMA INHERITED total={total}{}",
        if inherited_overflow() {
            " list=truncated"
        } else {
            ""
        }
    );
}

static ENFORCED: AtomicBool = AtomicBool::new(false);

/// Selects `Enforced` for the rest of the boot: only `Contained` functions
/// arm. Used only by the AMD-Vi enforce-test boot (src/amdvi_hw.rs), which
/// starts no other bus-mastering driver.
pub fn enforce() {
    ENFORCED.store(true, Ordering::Release);
}

/// The boot's profile: `Recording` unless the enforce-test boot chose
/// `Enforced`.
fn profile() -> Profile {
    if ENFORCED.load(Ordering::Acquire) {
        Profile::Enforced
    } else {
        Profile::Recording
    }
}

/// Records the arm; returns how many times this function was armed, or
/// 0 when the record table is full (reported as `arms=untracked`).
fn record(function: Function, owner: &'static str) -> u32 {
    let records = unsafe { &mut *core::ptr::addr_of_mut!(RECORDS) };
    if let Some(record) = records
        .iter_mut()
        .flatten()
        .find(|r| r.function == function)
    {
        record.arms = record.arms.saturating_add(1);
        record.owner = owner;
        return record.arms;
    }
    if let Some(slot) = records.iter_mut().find(|slot| slot.is_none()) {
        *slot = Some(Record {
            function,
            owner,
            arms: 1,
        });
        return 1;
    }
    0
}

/// An arm count, or `untracked` past the record table.
struct Arms(u32);

impl core::fmt::Display for Arms {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            0 => f.write_str("untracked"),
            count => write!(f, "{count}"),
        }
    }
}

/// Functions an ABSD-programmed domain contains right now (#116): set by
/// src/amdvi_hw.rs from a [`crate::amdvi_hw::Contained`] proof once the
/// function's domain is live and invalidated, cleared at its revocation.
/// `arm` decides on the declaration's state unless the function is here
/// (`dma_policy::effective_state`). Abstraction leak L4: declarations are
/// static, containment is a run-time fact of one boot.
static mut LIVE_DOMAINS: dma_policy::LiveDomains<Function, { absd_kernel::amdvi::MAX_TARGETS }> =
    dma_policy::LiveDomains::EMPTY;

fn live_domains()
-> &'static mut dma_policy::LiveDomains<Function, { absd_kernel::amdvi::MAX_TARGETS }> {
    // One mutable reference per call; no caller holds it across another.
    unsafe { &mut *core::ptr::addr_of_mut!(LIVE_DOMAINS) }
}

/// Records that `domain` contains its function (from here until
/// [`release_contained`]). Returns false when the record is full.
pub fn register_contained(domain: &crate::amdvi_hw::Contained) -> bool {
    // Contain mode registers only through `contain::contain_target`: a
    // retained proof cannot revive a registration there.
    !contain_mode() && live_domains().register(domain.function(), domain.domain())
}

/// The function's domain is no longer live (revoked or unit failed).
pub fn release_contained(function: Function) {
    live_domains().release(function);
}

/// The DomainID that contains `function` now, if any.
pub fn contained(function: Function) -> Option<u16> {
    if contain_mode() {
        return None;
    }
    live_domains().domain(function)
}

/// Whether this boot is a `dma-contain` boot, and the terminal latch.
static CONTAIN_MODE: AtomicBool = AtomicBool::new(false);
static CONTAIN_FAILED: AtomicBool = AtomicBool::new(false);

/// `dma-contain` targets with a live domain (design section 4), one grant per
/// function per boot. Only `contain::contain_target` registers.
static mut CONTAIN_REGISTRY: dma_policy::ContainRegistry<
    Function,
    { absd_kernel::amdvi::MAX_TARGETS },
> = dma_policy::ContainRegistry::EMPTY;

fn contain_registry()
-> &'static mut dma_policy::ContainRegistry<Function, { absd_kernel::amdvi::MAX_TARGETS }> {
    // One mutable reference per call; no caller holds it across another.
    unsafe { &mut *core::ptr::addr_of_mut!(CONTAIN_REGISTRY) }
}

/// Selects contain mode for the rest of the boot; also selects `Enforced`.
pub fn enter_contain_mode() {
    CONTAIN_MODE.store(true, Ordering::Release);
    enforce();
}

/// The terminal transition's first step: no more arms and no more domains
/// this boot, and every registration gone.
pub fn latch_contain_failed() {
    CONTAIN_FAILED.store(true, Ordering::Release);
    contain_registry().release_all();
}

fn contain_mode() -> bool {
    CONTAIN_MODE.load(Ordering::Acquire)
}

fn contain_latched() -> bool {
    CONTAIN_FAILED.load(Ordering::Acquire)
}

/// Registers a target's live domain. False once latched, when the function
/// was already registered this boot, or when the record is full.
pub(crate) fn register_contain_target(
    function: Function,
    owner: &'static str,
    domain: u16,
) -> bool {
    !contain_latched() && contain_registry().register(function, owner, domain)
}

/// A contained target's domain is no longer live (revoked).
pub(crate) fn release_contain_target(function: Function) {
    contain_registry().release(function);
}

/// The domain the seam would use for this function and owner, in either mode.
fn registered(function: Function, owner: &str) -> Option<u16> {
    if contain_mode() {
        contain_registry().domain(function, owner)
    } else {
        contained(function)
    }
}

/// The live domain the seam holds for this function and owner.
pub fn domain_for(function: Function, owner: &str) -> Option<u16> {
    registered(function, owner)
}

/// Every arm entry point's first check.
fn gate(function: Function, owner: &str) -> Result<(), Refusal> {
    dma_policy::contain_gate(
        contain_mode(),
        registered(function, owner),
        contain_latched(),
    )
}

fn admit(
    function: Function,
    declaration: &'static Declaration,
    witness: Option<&VmEnvelopeObserved>,
) -> Result<Armed, Refused> {
    let effective = Declaration {
        state: dma_policy::effective_state(
            declaration.state,
            registered(function, declaration.owner),
        ),
        ..*declaration
    };
    let decision = gate(function, declaration.owner)
        .and_then(|()| dma_policy::admit(profile(), &effective, witness));
    report(function, declaration.owner, effective.state, decision)
}

fn admit_state(function: Function, owner: &'static str, state: State) -> Result<Armed, Refused> {
    let decision =
        gate(function, owner).and_then(|()| match dma_policy::decide(profile(), state) {
            dma_policy::Decision::Arm => Ok(()),
            dma_policy::Decision::Refuse => Err(Refusal::Profile),
        });
    report(function, owner, state, decision)
}

fn report(
    function: Function,
    owner: &'static str,
    state: State,
    decision: Result<(), Refusal>,
) -> Result<Armed, Refused> {
    let profile = profile();
    let arms = record(function, owner);
    if REPORT.load(Ordering::Acquire) {
        let _ = writeln!(
            Serial,
            "DMA ARM pci={:02x}:{:02x}.{} owner={} state={} profile={} decision={} containment={} arms={} pci-bme-refusals={}",
            function.bus,
            function.device,
            function.function,
            owner,
            state.name(),
            profile.name(),
            match decision {
                Ok(()) => "arm",
                Err(Refusal::Profile) => "refuse",
                Err(Refusal::WitnessMissing) => "refuse-witness-missing",
                Err(Refusal::NotRegistered) => "refuse-not-registered",
                Err(Refusal::Latched) => "refuse-latched",
            },
            if matches!(state, State::Contained { .. }) {
                "contained"
            } else {
                "uncontained"
            },
            Arms(arms),
            pci::bus_master_refusals(),
        );
    }
    match decision {
        Ok(()) => Ok(Armed { function }),
        Err(reason) => Err(Refused {
            state,
            profile,
            reason,
        }),
    }
}

/// Memory decoding, bus mastering and the INTx mask, for a polled driver
/// (formerly `pci::enable_polled_dma`).
pub fn arm(function: Function, declaration: &'static Declaration) -> Result<(), Refused> {
    let armed = admit(function, declaration, None)?;
    pci::set_polled_dma(armed);
    Ok(())
}

/// As [`arm`], for a declaration that needs ABSD's VM-environment check
/// (`dma_policy::Witness::VmEnvelopeObserved`): the token is the proof the
/// check passed. Detected, not verified: it does not authenticate the
/// hypervisor or the host IOMMU.
pub fn arm_in_vm(
    function: Function,
    declaration: &'static Declaration,
    observed: &VmEnvelopeObserved,
) -> Result<(), Refused> {
    let armed = admit(function, declaration, Some(observed))?;
    pci::set_polled_dma(armed);
    Ok(())
}

/// I/O decoding and bus mastering for ATA bus-master IDE (formerly
/// `pci::enable_ide_dma`).
pub fn arm_ide(function: Function, declaration: &'static Declaration) -> Result<(), Refused> {
    let armed = admit(function, declaration, None)?;
    pci::set_ide_dma(armed);
    Ok(())
}

/// Bus mastering for the one function an ABSD-programmed AMD-Vi domain
/// contains. The state is `Contained` only on the strength of `domain`,
/// which src/amdvi_hw.rs makes after the domain's tables are live and their
/// invalidation has completed; it must name this function.
pub fn arm_contained(
    function: Function,
    owner: &'static str,
    domain: &crate::amdvi_hw::Contained,
) -> Result<(), Refused> {
    let devid = (u16::from(function.bus) << 8)
        | (u16::from(function.device) << 3)
        | u16::from(function.function);
    let state = if domain.devid() == devid {
        State::Contained {
            unit: 0,
            domain: domain.domain(),
        }
    } else {
        State::Unavailable(dma_policy::Unavailability::GroupUnverified)
    };
    let armed = admit_state(function, owner, state)?;
    pci::set_polled_dma(armed);
    Ok(())
}
