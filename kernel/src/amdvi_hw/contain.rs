//! Operator-mode containment (#111, #123 step 2; design:
//! docs/superpowers/specs/2026-11-04-amdvi-operator-design.md). An ordinary
//! boot with `dma-contain=` enables the unit, blocks every requester, and
//! gives each named driver a domain only through the steps here, or leaves
//! it off and says why. Decisions are `absd_kernel::amdvi::scope` and
//! `dma_policy::contain_gate`; this file applies them.
//!
//! After bring-up, only [`poll`] issues unit commands for a running boot (with
//! `expose`, between driver operations, and the check, which is the whole
//! boot). Driver failure paths call [`retire`], which only records: they may
//! be deep inside an operation, and must not reach back into the session. The
//! work happens at the next [`poll`], every driver operation starts with one,
//! and the exit path takes a last one.
//!
//! The kernel reports what it observed and concludes nothing:
//! `qualification=none` is a constant. Claims live in the run record.

use super::*;
use absd_kernel::amdvi::lifecycle::{
    Attribution, CheckFacts, CheckOutcome, OperatorAction, OperatorNext,
};
use absd_kernel::amdvi::scope::{
    self, CustodySequence, CustodyStep, Driver, Scope, ScopeFacts, ScopeRefusal, SiblingFacts,
    UpstreamPort,
};
use absd_kernel::dma_contain::{Bdf, Word};
use absd_kernel::mcfg::{self, ExtError};

const AHCI_DOMAIN: u16 = 2;
const RTL8125_DOMAIN: u16 = 3;
const CAP_EXPRESS: u8 = 0x10;
const RESERVED_RANGES: usize = 12;
const MAX_REPORTED_OTHERS: u64 = 16;

/// One named driver's target.
struct Target {
    driver: Driver,
    function: Function,
    custody: CustodySequence,
    scope: Option<Scope>,
    ecam: Option<u64>,
    grant: [(u64, Perm); amdvi::MAX_GRANT],
    grant_len: usize,
    /// A failure after exposure ended this surface.
    retired: bool,
    /// Its DTE has been blocked again and that completed or failed.
    blocked: bool,
}

/// The enabled unit and what hangs off it. BSP only.
struct Operator {
    unit: &'static absd_kernel::ivrs::Unit,
    rings: Rings,
    tables: Frames,
    devtab: u64,
    health: Health,
    record: FaultRecord,
    reserved: [(u64, u64); RESERVED_RANGES],
    reserved_len: usize,
    terminal: bool,
    /// Why the unit may no longer be relied on, once observed.
    lost: Option<&'static str>,
    /// Events from requesters that are not live targets: blocked, as designed.
    other_events: u64,
    /// For the summary: what the table needed.
    deviations: usize,
    quirked: usize,
}

static mut WORD: Option<Word> = None;
static mut OPERATOR: Option<Operator> = None;
static mut TARGETS: [Option<Target>; 2] = [const { None }; 2];
static mut FRAME_BASELINE: usize = 0;

fn operator() -> Option<&'static mut Operator> {
    unsafe { (*core::ptr::addr_of_mut!(OPERATOR)).as_mut() }
}

fn targets() -> &'static mut [Option<Target>; 2] {
    unsafe { &mut *core::ptr::addr_of_mut!(TARGETS) }
}

fn word() -> Option<Word> {
    unsafe { *core::ptr::addr_of!(WORD) }
}

/// Whether this is a `dma-contain` boot.
pub fn active() -> bool {
    word().is_some()
}

/// How long the census watches the event log.
const CENSUS_SECONDS: u64 = 60;

/// Whether this boot is the zero-target census.
pub fn census() -> bool {
    word().is_some_and(|w| w.is_census())
}

fn function_of(bdf: Bdf) -> Function {
    Function {
        bus: bdf.bus,
        device: bdf.device,
        function: bdf.function,
    }
}

/// The function the boot word names for `driver`.
pub fn named(driver: Driver) -> Option<Function> {
    let word = word()?;
    match driver {
        Driver::Ahci => word.ahci,
        Driver::Rtl8125 => word.rtl8125,
    }
    .map(function_of)
}

/// Frames the unit holds for the rest of the boot: the ordinary heap test
/// compares against this, since they are never freed.
pub fn frame_baseline() -> usize {
    unsafe { *core::ptr::addr_of!(FRAME_BASELINE) }
}

fn refuse_target(driver: Driver, function: Function, reason: &str) {
    let _ = writeln!(
        Serial,
        "DMA CONTAIN REFUSED pci={} driver={} reason={reason}",
        Id(devid(function)),
        driver.owner()
    );
}

fn base_class(function: Function) -> u32 {
    pci::read32(function, 0x08) >> 16
}

fn is_display(function: Function) -> bool {
    pci::ids(function).0 != 0xffff && base_class(function) >> 8 == 0x03
}

/// The one display-class function, and how many there are.
fn display_function() -> (Option<Function>, usize) {
    let (mut found, mut count) = (None, 0);
    pci::each(|function| {
        if is_display(function) {
            found = Some(function);
            count += 1;
        }
    });
    (found, count)
}

/// Whether `function` is a bridge whose bus range holds `bus`.
fn bridge_covers(function: Function, bus: u8) -> bool {
    if (pci::read32(function, 0x0c) >> 16) & 0x7f != 1 {
        return false;
    }
    let buses = pci::read32(function, 0x18);
    let (secondary, subordinate) = ((buses >> 8) as u8, (buses >> 16) as u8);
    secondary <= bus && bus <= subordinate
}

/// The PCIe capability, when its registers read below fit in the 256 bytes of
/// conventional space: a pointer past that is treated as no capability, which
/// scope refuses for a physical target.
fn express_capability(function: Function) -> Option<u8> {
    amdvi::find_capability(|at| pci::read32(function, at), CAP_EXPRESS).filter(|&at| at <= 0xf4)
}

fn express_type(function: Function) -> Option<u8> {
    let cap = express_capability(function)?;
    Some(((pci::read32(function, cap) >> 20) & 0xf) as u8)
}

fn upstream_port(bus: u8) -> Option<UpstreamPort> {
    let mut found = None;
    pci::each(|function| {
        if (pci::read32(function, 0x0c) >> 16) & 0x7f == 1
            && (pci::read32(function, 0x18) >> 8) as u8 == bus
        {
            let buses = pci::read32(function, 0x18);
            found = Some(UpstreamPort {
                express_type: express_type(function),
                secondary: (buses >> 8) as u8,
                subordinate: (buses >> 16) as u8,
            });
        }
    });
    found
}

fn sibling_facts(function: Function) -> SiblingFacts {
    let (vendor, device) = pci::ids(function);
    let command = pci::command(function);
    SiblingFacts {
        function: function.function,
        vendor,
        device,
        class: pci::read32(function, 0x08) >> 8,
        bus_master: command & (1 << 2) != 0,
        decode: command & 0b11 != 0,
        bars_zero: (0..6u8).all(|bar| pci::read32(function, 0x10 + bar * 4) == 0),
    }
}

/// The function's configuration page, mapped once. Read-only: no ECAM write
/// exists anywhere in the kernel.
fn map_ecam(function: Function) -> Option<u64> {
    let page = crate::acpi_boot::config_page(function.bus, function.device, function.function)?;
    crate::mmio::map(page, PAGE, crate::mmio::Cache::Uncached).ok()
}

fn gather(function: Function, ecam: Option<u64>) -> ScopeFacts {
    let read = |at: u8| pci::read32(function, at);
    let (vendor, device) = pci::ids(function);
    let class_rev = read(0x08);
    let header_type = (read(0x0c) >> 16) as u8;
    let cap = express_capability(function);
    let (express, phantom_supported, phantom_enabled) = match cap {
        Some(at) => (
            Some(((read(at) >> 20) & 0xf) as u8),
            ((read(at + 4) >> 3) & 0b11) as u8,
            read(at + 8) & (1 << 9) != 0,
        ),
        None => (None, 0, false),
    };
    let mut peers = false;
    for number in 0..32u8 {
        let other = Function {
            bus: function.bus,
            device: number,
            function: 0,
        };
        if number != function.device && pci::ids(other).0 != 0xffff {
            peers = true;
        }
    }
    let mut siblings = [None; 7];
    let mut count = 0;
    if header_type & 0x80 != 0 {
        for number in 0..8u8 {
            let other = Function {
                function: number,
                ..function
            };
            if number != function.function && pci::ids(other).0 != 0xffff && count < 7 {
                siblings[count] = Some(sibling_facts(other));
                count += 1;
            }
        }
    }
    let extended = match ecam {
        Some(address) => mcfg::extended_facts(|at| unsafe {
            core::ptr::read_volatile((address + u64::from(at)) as *const u32)
        }),
        None => Err(ExtError::Unreadable),
    };
    ScopeFacts {
        vendor,
        device,
        subsystem: read(0x2c),
        class: class_rev >> 8,
        revision: class_rev as u8,
        header_type,
        bus: function.bus,
        express_type: express,
        phantom_supported,
        phantom_enabled,
        upstream: upstream_port(function.bus),
        peers,
        siblings,
        extended,
    }
}

fn observe_scope(
    driver: Driver,
    function: Function,
    unit: &absd_kernel::ivrs::Unit,
    ecam: Option<u64>,
) -> Result<Scope, ScopeRefusal> {
    scope::admit_scope(
        driver,
        &gather(function, ecam),
        amdvi::admit_device(unit, devid(function)),
    )
}

/// Everything up to the sweep's completion, with no target granted.
fn bring_up() -> Result<Operator, Unavailable> {
    let OpenUnit {
        unit,
        mmio,
        live,
        deviations,
        quirked,
    } = open_unit()?;
    let frames = unsafe { crate::vm::frames() };
    let pages = DEVICE_TABLE_ENTRIES * amdvi::DTE_BYTES / PAGE as usize;
    let Some(table) = frames.allocate_contiguous(pages, FrameOwner::Kernel) else {
        return Err(unavailable("memory", format_args!("reason=device-table")));
    };
    let devtab = table.start_address();
    let (Some(command), Some(events), Some(store)) =
        (zeroed_frame(), zeroed_frame(), zeroed_frame())
    else {
        return Err(unavailable("memory", format_args!("reason=rings")));
    };
    for id in 0..DEVICE_TABLE_ENTRIES {
        write_dte(devtab, id as u16, amdvi::dte_initial(unit, id as u16));
    }
    fence();
    let (mut rings, enabled_tsc) = enable_unit(mmio, &live, devtab, command, events, store)?;
    let mut health = Health::default();
    let mut record = FaultRecord::new(Observer::AbsdEventLog, environment());
    let (priority, count) = inherited_priority(unit);
    let mut invalidated = 0u32;
    let mut inherited_done = count == 0;
    for step in amdvi::enforcement_plan(live.ia_sup(), &[], &priority[..count]) {
        match step {
            Step::Submit(command) => {
                rings.submit(command);
                if inherited_done {
                    invalidated += u32::from(command[1] >> 28 == 0x2);
                }
            }
            Step::Complete(label) => {
                if !health.completion(rings.wait(label)) {
                    return Err(unavailable(
                        "invalidate",
                        format_args!("reason=no-completion step={label}"),
                    ));
                }
                inherited_done |= label == "inherited";
                let (_, overflow) = rings.observe_log(&mut health, &mut record);
                if overflow {
                    return Err(unavailable(
                        "unit-failed",
                        format_args!("reason=event-log-overflow step={label}"),
                    ));
                }
                if let Some(reason) = health.failed() {
                    return Err(unavailable(
                        "unit-failed",
                        format_args!("reason={} step={label}", reason.word()),
                    ));
                }
            }
            Step::GrantTarget(_) => {}
        }
    }
    report_window(enabled_tsc, tsc());
    let _ = writeln!(
        Serial,
        "AMDVI DENY-BY-DEFAULT devtab-invalidated={invalidated} of={DEVICE_TABLE_ENTRIES}"
    );
    if invalidated as usize != DEVICE_TABLE_ENTRIES {
        return Err(unavailable(
            "invalidate",
            format_args!("reason=incomplete invalidated={invalidated}"),
        ));
    }
    let mut reserved = [(0, 0); RESERVED_RANGES];
    reserved[..4].copy_from_slice(&[
        (
            devtab,
            devtab + (DEVICE_TABLE_ENTRIES * amdvi::DTE_BYTES) as u64,
        ),
        (command, command + PAGE),
        (events, events + PAGE),
        (store, store + PAGE),
    ]);
    Ok(Operator {
        unit,
        rings,
        tables: Frames,
        devtab,
        health,
        record,
        reserved,
        reserved_len: 4,
        terminal: false,
        lost: None,
        other_events: 0,
        deviations,
        quirked,
    })
}

/// Grants one translated domain: DTE, invalidations, completion, evidence.
fn publish(op: &mut Operator, id: u16, domain: u16, root: u64, ir_table: u64) -> bool {
    write_dte(op.devtab, id, amdvi::dte_translated(domain, root, ir_table));
    fence();
    op.rings.submit(amdvi::invalidate_devtab(id));
    op.rings.submit(amdvi::invalidate_domain(domain));
    op.rings.submit(amdvi::invalidate_interrupt_table(id));
    let done = op.health.completion(op.rings.wait("grant"));
    observe(op);
    done && op.lost.is_none()
}

/// Every observation boundary: overflow or a failed unit is recorded for the
/// caller, which runs the terminal transition before returning to a driver.
fn observe(op: &mut Operator) {
    let (_, overflow) = op.rings.observe_log(&mut op.health, &mut op.record);
    note_loss(op, overflow);
}

fn note_loss(op: &mut Operator, overflow: bool) {
    if op.lost.is_none() {
        if overflow && !cfg!(absd_mutant_contain_overflow_unnoted) {
            op.lost = Some("event-log-overflow");
        } else if op.health.failed().is_some() {
            op.lost = Some("unit-failed");
        }
    }
}

fn note_reserved(op: &mut Operator, start: u64, end: u64) {
    if op.reserved_len < RESERVED_RANGES {
        op.reserved[op.reserved_len] = (start, end);
        op.reserved_len += 1;
    }
}

/// No unit contains anything: clear Bus Master Enable, R2 only, except the
/// named exceptions, each printed as uncontained. No claim follows.
fn close_masters_on_refusal() {
    let (display, _) = display_function();
    let mut closed = 0u32;
    let mut stuck = 0u32;
    pci::each(|function| {
        if !pci::bus_master(function) {
            return;
        }
        let is_display = display == Some(function);
        let on_path = display.is_some_and(|d| bridge_covers(function, d.bus));
        if scope::refusal_exempt(base_class(function), is_display, on_path) {
            let _ = writeln!(
                Serial,
                "DMA CONTAIN EXCEPTION pci={} containment=uncontained path=refusal",
                Id(devid(function))
            );
            return;
        }
        pci::disable_dma(function);
        if pci::bus_master(function) {
            stuck += 1;
        } else {
            closed += 1;
        }
    });
    let _ = writeln!(
        Serial,
        "DMA CONTAIN INHERITED-BME closed={closed} stuck={stuck} path=refusal step=R2 claims=none"
    );
}

/// The boot word was accepted. Selects `Enforced` before anything else, then
/// brings the unit up and blocks every requester. A failure leaves every
/// later arm refused; the boot continues.
pub fn enter(
    word: Word,
    smp: crate::acpi_boot::SmpView,
    info: *const u8,
    total: usize,
    options: Options,
) {
    unsafe { *core::ptr::addr_of_mut!(WORD) = Some(word) };
    crate::dma::enter_contain_mode();
    crate::serial::write("DMA CONTAIN START\n");
    crate::acpi_boot::report(info, total, smp, options.poweroff, options.reset);
    let env = if core::arch::x86_64::__cpuid(1).ecx & (1 << 31) != 0 {
        "hypervisor"
    } else {
        "bare-metal"
    };
    match bring_up() {
        Ok(op) => {
            unsafe { *core::ptr::addr_of_mut!(OPERATOR) = Some(op) };
            crate::serial::flush_screen();
            crate::dma::report_inherited();
            let _ = writeln!(
                Serial,
                "AMDVI OPERATOR unit=enabled deny-by-default={DEVICE_TABLE_ENTRIES} env={env} qualification=none"
            );
            poll();
        }
        Err(_) => {
            crate::serial::flush_screen();
            crate::dma::report_inherited();
            close_masters_on_refusal();
            let _ = writeln!(
                Serial,
                "AMDVI OPERATOR unit=refused env={env} qualification=none"
            );
        }
    }
    unsafe {
        *core::ptr::addr_of_mut!(FRAME_BASELINE) = crate::vm::frames().allocated_frames();
    }
}

/// What the boot line says beyond the word.
#[derive(Clone, Copy)]
pub struct Options {
    pub poweroff: bool,
    pub reset: bool,
}

fn slot(driver: Driver) -> usize {
    match driver {
        Driver::Ahci => 0,
        Driver::Rtl8125 => 1,
    }
}

fn domain_of(driver: Driver) -> u16 {
    match driver {
        Driver::Ahci => AHCI_DOMAIN,
        Driver::Rtl8125 => RTL8125_DOMAIN,
    }
}

fn check_ordering(function: Function) -> Result<(), &'static str> {
    if express_type(function).is_none() {
        // The fixture form: no Device Control to judge.
        return Ok(());
    }
    let control = absd_kernel::rtl8125_pci::express_device_control(|at| pci::read32(function, at))
        .map_err(|_| "ordering")?;
    scope::admit_ordering(control).map_err(|r| r.word())
}

/// Design section 5, steps 1 to 3, after the driver's own read-only checks:
/// the scope, Bus Master Enable clear and read back with the DTE still
/// blocked, and ordering corrected. Refuses and prints on any failure.
pub fn take(driver: Driver, function: Function) -> bool {
    crate::kernel_lock::assert_bsp_device_access();
    let result = (|| -> Result<(), &'static str> {
        if named(driver) != Some(function) {
            return Err("not-named");
        }
        let op = operator().ok_or("unit-unavailable")?;
        if op.terminal {
            return Err("unit-failed");
        }
        if targets()[slot(driver)].is_some() {
            return Err("already-taken");
        }
        let ecam = if express_type(function).is_some() {
            map_ecam(function)
        } else {
            None
        };
        let observed =
            observe_scope(driver, function, op.unit, ecam).map_err(|refusal| refusal.word())?;
        let mut target = Target {
            driver,
            function,
            custody: CustodySequence::NEW,
            scope: Some(observed),
            ecam,
            grant: [(0, Perm::READ); amdvi::MAX_GRANT],
            grant_len: 0,
            retired: false,
            blocked: false,
        };
        let inherited = pci::bus_master(function);
        target.custody.advance(CustodyStep::Eligible);
        if !cfg!(absd_mutant_contain_skip_bme_clear) {
            pci::disable_dma(function);
        }
        if pci::bus_master(function) && !cfg!(absd_mutant_contain_skip_bme_clear) {
            return Err("bus-master-stuck");
        }
        target.custody.advance(CustodyStep::BusMasterClear);
        if express_type(function).is_some() {
            absd_kernel::rtl8125_pci::disable_ordering(
                |at| pci::read32(function, at),
                |at, value| pci::write32(function, at, value),
            )
            .map_err(|_| "ordering")?;
        }
        check_ordering(function)?;
        target.custody.advance(CustodyStep::OrderingChecked);
        let _ = writeln!(
            Serial,
            "DMA CONTAIN TAKEN pci={} driver={} inherited={} scope=ok{}",
            Id(devid(function)),
            driver.owner(),
            if inherited { "yes" } else { "no" },
            if observed.sibling_accepted() {
                " sibling=accepted-routing-unverified"
            } else {
                ""
            }
        );
        targets()[slot(driver)] = Some(target);
        Ok(())
    })();
    if let Err(reason) = result {
        refuse_target(driver, function, reason);
        return false;
    }
    true
}

/// Design section 5, step 5: the driver has initialised its surface; from
/// here it is device-exposed for the rest of the boot. Grants the domain.
pub fn expose(driver: Driver, function: Function, pages: &[(u64, Perm)]) -> bool {
    crate::kernel_lock::assert_bsp_device_access();
    // The admission boundary: what the log holds so far is acted on as usual.
    // This target has no registration yet, so nothing there can revoke it, and
    // a live target's faults are not lost.
    poll();
    let result = (|| -> Result<(), &'static str> {
        let op = operator().ok_or("unit-unavailable")?;
        if op.terminal {
            return Err("unit-failed");
        }
        let target = targets()[slot(driver)].as_mut().ok_or("not-taken")?;
        if target.function != function || !target.custody.advance(CustodyStep::SurfaceReady) {
            return Err("custody-order");
        }
        amdvi::check_grant(pages, amdvi::IOVA_LIMIT, &op.reserved[..op.reserved_len])
            .map_err(|_| "grant")?;
        let other = targets()[1 - slot(driver)].as_ref();
        let other_grant = other.map_or(&[][..], |t| &t.grant[..t.grant_len]);
        amdvi::check_disjoint(&[pages, other_grant]).map_err(|_| "grant-overlap")?;
        let (Some(root), Some(ir_table)) = (op.tables.allocate(), zeroed_frame()) else {
            return Err("memory");
        };
        for &(page, perm) in pages {
            amdvi::map(&mut op.tables, root, page, page, perm).map_err(|_| "map")?;
        }
        if cfg!(absd_mutant_contain_extra_page) {
            let canary = page_address(core::ptr::addr_of!(CANARY));
            amdvi::map(&mut op.tables, root, canary, canary, Perm::READ_WRITE)
                .map_err(|_| "map")?;
        }
        note_reserved(op, root, root + PAGE);
        note_reserved(op, ir_table, ir_table + PAGE);
        let target = targets()[slot(driver)].as_mut().ok_or("not-taken")?;
        if !target.custody.advance(CustodyStep::Exposed) {
            return Err("custody-order");
        }
        target.grant[..pages.len()].copy_from_slice(pages);
        target.grant_len = pages.len();
        let domain = domain_of(driver);
        if !publish(op, devid(function), domain, root, ir_table) {
            return Err("unit-failed");
        }
        if !crate::dma::register_contain_target(function, driver.owner(), domain) {
            return Err("registration");
        }
        let _ = writeln!(
            Serial,
            "DMA CONTAIN pci={} driver={} domain={domain} scope=ok pages={} interrupts=deny-all",
            Id(devid(function)),
            driver.owner(),
            pages.len()
        );
        Ok(())
    })();
    if let Err(reason) = result {
        refuse_target(driver, function, reason);
        poll();
        return false;
    }
    true
}

/// Design section 5, step 6: immutable scope compared with the first
/// observation, ordering again. The driver then arms through the dma seam.
pub fn admit(driver: Driver, function: Function) -> bool {
    crate::kernel_lock::assert_bsp_device_access();
    let result = (|| -> Result<(), &'static str> {
        let op = operator().ok_or("unit-unavailable")?;
        let target = targets()[slot(driver)].as_mut().ok_or("not-taken")?;
        let again = observe_scope(driver, function, op.unit, target.ecam)
            .map_err(|refusal| refusal.word())?;
        if target.scope != Some(again) {
            return Err("scope-changed");
        }
        check_ordering(function)?;
        if !target.custody.advance(CustodyStep::Admitted) {
            return Err("custody-order");
        }
        Ok(())
    })();
    if let Err(reason) = result {
        refuse_target(driver, function, reason);
        return false;
    }
    true
}

/// Whether this target's surface has been exposed: every later failure is
/// terminal for that surface.
pub fn exposed(driver: Driver) -> bool {
    targets()[slot(driver)]
        .as_ref()
        .is_some_and(|t| t.custody.exposed())
}

/// The terminal transition (design section 8), once: the latch, bus mastering
/// clear on every driver target armed or not, registrations gone, driver
/// service closed before anything touches descriptors again. IommuEn and the
/// DTEs stay as they are, pages stay retained, and the display is untouched.
pub fn terminal(reason: &str) {
    if let Some(op) = operator() {
        if op.terminal {
            return;
        }
        op.terminal = true;
    }
    crate::dma::latch_contain_failed();
    for target in targets().iter().flatten() {
        pci::disable_dma(target.function);
        let bme = pci::bus_master(target.function);
        let _ = writeln!(
            Serial,
            "DMA CONTAIN STOPPED pci={} driver={} bme={} step=R2 claims=none",
            Id(devid(target.function)),
            target.driver.owner(),
            if bme { "on" } else { "clear" }
        );
    }
    stop_driver(Driver::Ahci);
    stop_driver(Driver::Rtl8125);
    let _ = writeln!(
        Serial,
        "DMA CONTAIN TERMINAL reason={reason} other-events={} record=incomplete qualification=none",
        operator().map_or(0, |op| op.other_events)
    );
}

/// Closes a driver's service. Its surface stays retained for the boot.
fn stop_driver(driver: Driver) {
    match driver {
        Driver::Ahci => {
            if let Some(withdrawn) = crate::ahci_block::withdraw() {
                withdrawn.reset();
            }
            crate::ahci_block::retire_buffers();
        }
        Driver::Rtl8125 => crate::rtl8125_device::contain_stop(),
    }
}

/// A failure after exposure ends that surface for the boot. Safe from inside a
/// driver operation: it clears bus mastering, drops the registration, and leaves
/// blocking the DTE to the next [`poll`]. Nothing to do for a target never
/// exposed, whose DTE never left the blocked form.
pub fn retire(driver: Driver) {
    let Some(target) = targets()[slot(driver)].as_mut() else {
        return;
    };
    if !target.custody.exposed() || target.retired {
        return;
    }
    target.retired = true;
    pci::disable_dma(target.function);
    crate::dma::release_contain_target(target.function);
}

/// Blocks the DTE of every retired target. After a terminal transition the unit
/// takes no more commands.
fn block_retired() {
    let Some(op) = operator() else {
        return;
    };
    for target in targets().iter_mut().flatten() {
        // A lost unit takes no more commands, and its DTEs stay as they are.
        if op.terminal || op.lost.is_some() {
            return;
        }
        if !target.retired || target.blocked {
            continue;
        }
        target.blocked = true;
        let id = devid(target.function);
        write_dte(
            op.devtab,
            id,
            amdvi::dte_blocked(amdvi::BLOCKED_DOMAIN, amdvi::Interrupts::Abort),
        );
        fence();
        op.rings.submit(amdvi::invalidate_devtab(id));
        op.rings
            .submit(amdvi::invalidate_domain(domain_of(target.driver)));
        op.rings.submit(amdvi::invalidate_interrupt_table(id));
        let completed = op.health.completion(op.rings.wait("revoke"));
        observe(op);
        let _ = writeln!(
            Serial,
            "DMA CONTAIN RETIRED pci={} driver={} r3={} retained=yes",
            Id(id),
            target.driver.owner(),
            if completed {
                "completed"
            } else {
                "unit-failed"
            }
        );
    }
}

/// Blocks what is retired, then runs the terminal transition if that or anything
/// before it lost the unit. Returns whether the unit is still usable.
fn block_and_settle() -> bool {
    block_retired();
    if let Some(reason) = operator().and_then(|op| op.lost) {
        terminal(reason);
        return false;
    }
    true
}

/// One target faulted: its R1-R4 in order, the other device left running.
/// R1 closes the driver, R2 clears bus mastering, R3 blocks the domain, and only
/// then R4 stops the device.
fn revoke_target(id: u16) {
    let Some(driver) = targets()
        .iter()
        .flatten()
        .find(|t| devid(t.function) == id)
        .map(|t| t.driver)
    else {
        return;
    };
    let _ = writeln!(
        Serial,
        "DMA CONTAIN REVOKED pci={} driver={} reason=io-page-fault",
        Id(id),
        driver.owner()
    );
    let withdrawn = match driver {
        Driver::Ahci => {
            crate::ahci_block::retire_buffers();
            crate::ahci_block::withdraw()
        }
        Driver::Rtl8125 => None,
    };
    retire(driver);
    let usable = block_and_settle();
    if let Some(withdrawn) = withdrawn {
        withdrawn.reset();
    }
    if usable && driver == Driver::Rtl8125 {
        crate::rtl8125_device::contain_stop();
    }
}

fn service() {
    if !block_and_settle() || operator().is_none_or(|op| op.terminal) {
        return;
    }
    let Some(op) = operator() else {
        return;
    };
    let mut ids = [0u16; 2];
    let mut count = 0;
    for target in targets().iter().flatten() {
        if crate::dma::domain_for(target.function, target.driver.owner()).is_some() {
            ids[count] = devid(target.function);
            count += 1;
        }
    }
    let mut revoke = lifecycle::RevokeSet::EMPTY;
    let mut consumed = 0u64;
    let reported = op.other_events;
    let mut others = 0u64;
    let (_, overflow) = op
        .rings
        .drain(&mut op.health, &mut op.record, &mut |event, raw| {
            consumed += 1;
            let record = FaultRecord::new(Observer::AbsdEventLog, environment());
            match lifecycle::operator_event_action(event, &ids[..count]) {
                OperatorAction::RevokeTarget(id) => {
                    revoke.add(id);
                    report_event(event, raw, &record);
                }
                OperatorAction::Report => {
                    // Reported up to a bound: a noisy blocked master must not
                    // turn the console into its log. All are counted.
                    if reported + others < MAX_REPORTED_OTHERS {
                        report_event(event, raw, &record);
                    }
                    others += 1;
                }
            }
        });
    op.other_events += others;
    op.record.observe(consumed, false);
    note_loss(op, overflow);
    let lost = op.lost;
    match lifecycle::operator_next(
        lifecycle::operator_log_terminal(overflow, lost.is_some()),
        &revoke,
    ) {
        OperatorNext::Terminal => terminal(lost.unwrap_or("event-log-overflow")),
        OperatorNext::Revoke => {
            for &id in revoke.ids() {
                revoke_target(id);
            }
        }
        OperatorNext::Nothing => {}
    }
}

/// A fatal path: a panic or a kernel exception may be inside any operation, so
/// nothing here touches the session or a driver. Stops later service, and fences
/// what it can through configuration writes alone.
pub fn fatal() {
    FATAL.store(true, core::sync::atomic::Ordering::Release);
    crate::serial::flush_screen();
    if !active() {
        return;
    }
    crate::dma::latch_contain_failed();
    for target in targets().iter().flatten() {
        pci::disable_dma(target.function);
    }
}

static FATAL: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// A check's verdict has been judged on its last service: nothing after it may
/// observe anything that would change what it printed.
static SEALED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Whether exit must leave drivers alone: a fatal path may be inside one. Only
/// in a `dma-contain` boot, where [`fatal`] has already cleared bus mastering.
pub fn skip_driver_shutdown() -> bool {
    active() && FATAL.load(core::sync::atomic::Ordering::Acquire)
}

/// The running boot's service boundary (design section 8). BSP only, and only
/// between driver operations: at the start of each, at the scheduler, the idle
/// loop, and on exit. Finishes retirements, reads the log, and acts on it. Only
/// a target with a live registration can be at fault: before that it was
/// blocked.
pub fn poll() {
    static SERVICING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    if FATAL.load(core::sync::atomic::Ordering::Acquire)
        || SEALED.load(core::sync::atomic::Ordering::Acquire)
        || SERVICING.swap(true, core::sync::atomic::Ordering::AcqRel)
    {
        return;
    }
    service();
    SERVICING.store(false, core::sync::atomic::Ordering::Release);
}

/// FNV-1a of a sector the CPU can read: what a read actually returned.
fn sector_digest(address: u64) -> u64 {
    let bytes = unsafe { core::slice::from_raw_parts(address as *const u8, 512) };
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// `dma-contain-check` (design section 10): the AHCI target's permitted read,
/// then one aimed at a never-granted page. Writes nothing to disk. Halts,
/// holding the screen. The kernel is the only observer of this result.
pub fn run_check(force_retire: bool) -> ! {
    let attribution = Attribution::for_build();
    let canary = page_address(core::ptr::addr_of!(CANARY));
    let canary_ptr = canary as *mut u8;
    unsafe { core::ptr::write_bytes(canary_ptr, 0xcc, PAGE as usize) };
    fence();
    let target = named(Driver::Ahci).map(devid);
    let mut facts = CheckFacts {
        drained: false,
        permitted_ok: false,
        submitted: false,
        canary_unchanged: false,
        fault_matches: false,
        completed: false,
        port_retired: false,
        bme_clear: false,
        later_read_matches: false,
        record_complete: false,
    };
    let mut faults = 0u64;
    let mut forbidden_cycles = 0u64;
    let first = crate::ahci_block::read_raw(0, 1, None);
    facts.permitted_ok = matches!(first, Ok((_, Completion::Done)));
    // What the read returned, not where: the buffer is the same each time.
    let first_digest = first
        .as_ref()
        .ok()
        .map(|&(address, _)| sector_digest(address));
    if let (Some(op), true) = (operator(), facts.permitted_ok) {
        let (_, before) = op
            .rings
            .drain(&mut op.health, &mut op.record, &mut |_, _| {});
        note_loss(op, before);
        facts.drained = op.lost.is_none();
    }
    // No session borrow across the driver call, which can retire the port. A
    // failed precondition means the forbidden command is never submitted.
    if let (Some(id), true) = (target, facts.drained) {
        if force_retire {
            crate::ahci_block::pretend_timeout();
        }
        let started = tsc();
        let forbidden = crate::ahci_block::read_raw(0, 1, Some(canary));
        forbidden_cycles = tsc().wrapping_sub(started);
        facts.submitted = crate::ahci_block::last_command_submitted();
        facts.completed = matches!(forbidden, Ok((_, Completion::Done)));
        if let Some(op) = operator() {
            let mut matched = false;
            let (_, overflow) =
                op.rings
                    .drain(&mut op.health, &mut op.record, &mut |event, raw| {
                        matched |= lifecycle::fault_attributes(
                            event,
                            id,
                            AHCI_DOMAIN,
                            canary,
                            attribution,
                        );
                        faults += 1;
                        report_event(
                            event,
                            raw,
                            &FaultRecord::new(Observer::AbsdEventLog, environment()),
                        );
                    });
            note_loss(op, overflow);
            facts.fault_matches = matched;
            facts.record_complete = op.lost.is_none() && op.record.complete();
        }
        facts.canary_unchanged = unsafe { core::slice::from_raw_parts(canary_ptr, PAGE as usize) }
            .iter()
            .all(|&byte| byte == 0xcc);
        facts.port_retired = crate::ahci_block::retired().0;
        facts.bme_clear = !pci::bus_master(function_of_devid(id));
        if facts.completed {
            let again = crate::ahci_block::read_raw(0, 1, None);
            facts.later_read_matches = match (again, first_digest) {
                (Ok((address, Completion::Done)), Some(digest)) => sector_digest(address) == digest,
                _ => false,
            };
        }
    }
    poll();
    // That service did R3 and may have found the unit lost: judge what is now
    // true, not what was true before it.
    facts.record_complete &=
        operator().is_some_and(|op| op.lost.is_none() && !op.terminal && op.record.complete());
    SEALED.store(true, core::sync::atomic::Ordering::Release);
    let outcome = lifecycle::check_verdict(&facts);
    clean_screen();
    if let Some((disk, selected)) = crate::ahci_block::last_disk() {
        let _ = writeln!(
            Serial,
            "DMA CONTAIN DISK port={} serial={} model={} selected={}",
            disk.port,
            core::str::from_utf8(disk.serial()).unwrap_or("?"),
            core::str::from_utf8(disk.model()).unwrap_or("?"),
            if selected { "yes" } else { "no" },
        );
    }
    let _ = writeln!(
        Serial,
        "DMA CONTAIN CHECK permitted={} forbidden={} attribution={} faults={faults} forbidden-cycles={forbidden_cycles} record={} observer=kernel-only qualification=none",
        if facts.permitted_ok { "ok" } else { "FAILED" },
        outcome.word(),
        attribution.word(),
        if facts.record_complete {
            "complete"
        } else {
            "incomplete"
        },
    );
    crate::serial::finish_output();
    let (bytes, digest) = crate::serial::evidence();
    let _ = writeln!(
        Serial,
        "DMA CONTAIN EVIDENCE digest={digest:016x} bytes={bytes}"
    );
    crate::exit_qemu(u32::from(outcome == CheckOutcome::Failed))
}

/// Fixture builds only (`dma-contain-inject=`): drives the running-health
/// paths under QEMU, then shows what a later block operation gets.
pub fn run_inject(kind: &[u8]) -> ! {
    if !cfg!(feature = "contain-qemu-fixture") {
        crate::exit_qemu(1)
    }
    if kind == b"check-retire" {
        run_check(true);
    }
    let canary = page_address(core::ptr::addr_of!(CANARY));
    let reads = match kind {
        b"target-fault" => 1,
        b"overflow" => 4,
        _ => 0,
    };
    // QEMU 10.2.1 reports EventOverflow only with event interrupts on.
    if kind == b"port-retire" {
        crate::ahci_block::pretend_timeout();
        let _ = crate::ahci_block::read_raw(0, 1, None);
    }
    if kind == b"overflow"
        && let Some(op) = operator()
    {
        let control = op.rings.mmio.read(CONTROL);
        op.rings.mmio.write(CONTROL, control | (1 << 3));
    }
    for _ in 0..reads {
        let _ = crate::ahci_block::read_raw(0, 1, Some(canary));
    }
    if kind == b"unit-error"
        && let Some(op) = operator()
    {
        op.rings.submit([0, 0xf << 28, 0, 0]);
        let _ = op.health.completion(op.rings.wait("inject"));
    }
    poll();
    let mut sector = [0u8; absd_kernel::syscall::BLOCK_SECTOR_BYTES];
    let after = crate::block::read_sector(0, &mut sector);
    let function = named(Driver::Ahci).unwrap_or(AHCI_FUNCTION);
    let rearm = crate::dma::arm(function, &absd_kernel::dma_policy::AHCI_BLOCK);
    let _ = writeln!(
        Serial,
        "DMA CONTAIN INJECT kind={} later-read={} rearm={} bme={}",
        core::str::from_utf8(kind).unwrap_or("?"),
        if after.is_ok() { "ok" } else { "refused" },
        if rearm.is_ok() { "armed" } else { "refused" },
        if pci::bus_master(function) {
            "on"
        } else {
            "clear"
        }
    );
    crate::exit_qemu(0)
}

fn function_of_devid(id: u16) -> Function {
    Function {
        bus: (id >> 8) as u8,
        device: ((id >> 3) & 0x1f) as u8,
        function: (id & 7) as u8,
    }
}

/// One scope result, kept for the summary.
#[derive(Clone, Copy)]
struct CensusRow {
    function: Function,
    driver: Driver,
    ids: (u16, u16),
    verdict: &'static str,
    extended: bool,
    bme: bool,
    sibling: Option<SiblingFacts>,
}

/// hardware_fixture has no UART, so a photograph of the screen is the record. The console
/// wraps, which leaves older lines below the newest: this starts the summary
/// on a clean screen. Serial and the digest are unaffected.
fn clean_screen() {
    crate::framebuffer::clear();
}

fn census_function(function: Function, driver: Driver) -> Option<CensusRow> {
    let op = operator()?;
    let ecam = if express_type(function).is_some() {
        map_ecam(function)
    } else {
        None
    };
    let facts = gather(function, ecam);
    let _ = writeln!(
        Serial,
        "DMA CENSUS pci={} driver={} ids={:04x}:{:04x} class={:#08x} rev={:#04x} header={:#04x} bme={} extended={}",
        Id(devid(function)),
        driver.owner(),
        facts.vendor,
        facts.device,
        facts.class,
        facts.revision,
        facts.header_type,
        u8::from(pci::bus_master(function)),
        if facts.extended.is_ok() {
            "read"
        } else {
            "unreadable"
        },
    );
    for sibling in facts.siblings.iter().flatten() {
        let _ = writeln!(
            Serial,
            "DMA CENSUS sibling-of={} function={} ids={:04x}:{:04x} class={:#08x} bme={} decode={} bars-zero={}",
            Id(devid(function)),
            sibling.function,
            sibling.vendor,
            sibling.device,
            sibling.class,
            u8::from(sibling.bus_master),
            u8::from(sibling.decode),
            u8::from(sibling.bars_zero),
        );
    }
    let verdict = scope::admit_scope(
        driver,
        &facts,
        amdvi::admit_device(op.unit, devid(function)),
    );
    let verdict = match verdict {
        Ok(_) => "ok",
        Err(refusal) => refusal.word(),
    };
    let _ = writeln!(
        Serial,
        "DMA CENSUS pci={} scope={verdict}",
        Id(devid(function)),
    );
    Some(CensusRow {
        function,
        driver,
        ids: (facts.vendor, facts.device),
        verdict,
        extended: facts.extended.is_ok(),
        bme: pci::bus_master(function),
        sibling: facts.siblings.iter().flatten().next().copied(),
    })
}

/// `dma-contain=none` (design section 10): what scope sees on this machine,
/// then the event log for a fixed time, then a one-screen summary. Starts no
/// driver. Holds the screen; never continues into an ordinary boot.
pub fn run_census(seconds: Option<u64>) -> ! {
    let mut rows = [None; 6];
    let mut row_count = 0;
    pci::each(|function| {
        let row = match pci::ids(function) {
            (0x1022, 0x7901) | (0x8086, 0x2922) => census_function(function, Driver::Ahci),
            (0x10ec, 0x8125) => census_function(function, Driver::Rtl8125),
            _ => None,
        };
        if row_count < rows.len() {
            rows[row_count] = row;
            row_count += usize::from(row.is_some());
        }
    });
    let mut requesters = [(0u16, 0u64); 8];
    let mut other = 0u64;
    let target_ticks = seconds.unwrap_or(CENSUS_SECONDS) * 1000;
    let start = crate::timer_ticks.load(core::sync::atomic::Ordering::Relaxed);
    unsafe { core::arch::asm!("sti", options(nostack, preserves_flags)) };
    let elapsed = loop {
        let now = crate::timer_ticks.load(core::sync::atomic::Ordering::Relaxed);
        let elapsed = now.wrapping_sub(start);
        if elapsed >= target_ticks {
            break elapsed;
        }
        if let Some(op) = operator() {
            let (_, overflow) =
                op.rings
                    .drain(&mut op.health, &mut op.record, &mut |event, _raw| {
                        let id = event_requester(event);
                        match requesters.iter_mut().find(|(at, n)| *at == id || *n == 0) {
                            Some(row) => {
                                row.0 = id;
                                row.1 += 1;
                            }
                            None => other += 1,
                        }
                    });
            note_loss(op, overflow);
            if op.lost.is_some() {
                break elapsed;
            }
        }
        core::hint::spin_loop();
    };
    unsafe { core::arch::asm!("cli", options(nostack, preserves_flags)) };
    let Some(op) = operator() else {
        let _ = writeln!(Serial, "DMA CENSUS unit=refused qualification=none");
        crate::serial::finish_output();
        let (bytes, digest) = crate::serial::evidence();
        let _ = writeln!(
            Serial,
            "DMA CONTAIN EVIDENCE digest={digest:016x} bytes={bytes}"
        );
        crate::exit_qemu(1)
    };
    clean_screen();
    let _ = writeln!(
        Serial,
        "DMA CENSUS SUMMARY inherited-masters={} qualification=none",
        crate::dma::inherited().count()
    );
    for row in rows.iter().flatten() {
        let _ = writeln!(
            Serial,
            "DMA CENSUS pci={} driver={} ids={:04x}:{:04x} bme={} extended={} scope={}",
            Id(devid(row.function)),
            row.driver.owner(),
            row.ids.0,
            row.ids.1,
            u8::from(row.bme),
            if row.extended { "read" } else { "unreadable" },
            row.verdict
        );
        if let Some(sibling) = row.sibling {
            let _ = writeln!(
                Serial,
                "DMA CENSUS sibling function={} ids={:04x}:{:04x} class={:#08x} bme={} decode={} bars-zero={}",
                sibling.function,
                sibling.vendor,
                sibling.device,
                sibling.class,
                u8::from(sibling.bus_master),
                u8::from(sibling.decode),
                u8::from(sibling.bars_zero),
            );
        }
    }
    let _ = writeln!(
        Serial,
        "DMA CENSUS unit=enabled ticks={elapsed} record={} event-log={} qualification=none",
        if op.record.complete() {
            "complete"
        } else {
            "incomplete"
        },
        op.lost.unwrap_or("running")
    );
    let _ = writeln!(
        Serial,
        "DMA CENSUS table=ok deviations={} quirked={} display=blocked other-requester-reports-bounded={MAX_REPORTED_OTHERS}",
        op.deviations, op.quirked
    );
    for &(id, count) in requesters.iter().filter(|(_, n)| *n != 0) {
        let _ = writeln!(
            Serial,
            "DMA CENSUS events requester={} count={count}",
            Id(id)
        );
    }
    let _ = writeln!(Serial, "DMA CENSUS events other-requesters={other}");
    crate::serial::finish_output();
    let (bytes, digest) = crate::serial::evidence();
    let _ = writeln!(
        Serial,
        "DMA CONTAIN EVIDENCE digest={digest:016x} bytes={bytes}"
    );
    crate::exit_qemu(0)
}
