//! Boot-time ACPI consumption (docs/x86-acpi-20261015/RESULT.md).
//!
//! Opt-in by boot option: `acpi` reads and reports the tables; with
//! `acpi-poweroff` a successful end of boot (exit code 0) also enters S5
//! through PM1a/PM1b. Parsing is the library's (`absd_kernel::acpi`); this
//! module only supplies physical access and serial records.
//!
//! Physical access (policy in `acpi::admit`, host-tested): a range wholly
//! inside the first GiB is read through the boot identity map. A range
//! wholly above it is read through `mmio::scratch_map`, one view of two
//! 2 MiB pages that takes no mmio region slot, remapped read-only and
//! write-back for each read, and only when the Multiboot2 memory map types
//! every byte of the range reserved, ACPI reclaim or ACPI NVS. The view is
//! unmapped when the walk ends. A straddling range, one needing more than
//! two pages, or one in other memory is refused with an `ACPI ACCESS
//! REFUSED` line. This runs on the BSP before any AP start and before
//! `mmio::freeze`.
//!
//! AMD-Vi discovery (#111 increment 2): the IVRS, when listed, is read the
//! same way, validated by `absd_kernel::ivrs`, cross-checked against the
//! IOMMU's PCI function (configuration reads only) and the memory map, and
//! reported as `AMDVI` lines. Nothing is mapped, written or enabled: no
//! MMIO register is read, so the firmware's handoff state of the unit
//! (Control, Status, the live EFR) is not observed here.

use crate::mmio;
use crate::serial::{Serial, finish_output as serial_finish_output, inb, write};
use absd_kernel::acpi::{self, Access, Memory};
use absd_kernel::ivrs::{self, Entries, Placement, Source, Unit, Variety};
use absd_kernel::survey_facts::{TAG_ACPI_NEW, TAG_ACPI_OLD, TAG_MEMORY_MAP, tags};
use core::arch::asm;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};

struct Physical {
    memory_map: Option<&'static [u8]>,
    remaps: u64,
    lowest: u64,
    highest: u64,
    refusals: u64,
}

impl Memory for Physical {
    fn bytes(&mut self, physical: u64, length: usize) -> Option<&[u8]> {
        let address = match acpi::admit(physical, length, self.memory_map) {
            Ok(Access::Identity) => physical,
            Ok(Access::Window {
                base,
                pages,
                offset,
            }) => match mmio::scratch_map(base, pages) {
                Ok(virt) => {
                    self.remaps += 1;
                    virt + offset
                }
                Err(error) => {
                    self.refusals += 1;
                    let _ = writeln!(
                        Serial,
                        "ACPI ACCESS REFUSED address={physical:#x} length={length} reason=Map{error:?}"
                    );
                    return None;
                }
            },
            Err(error) => {
                self.refusals += 1;
                let _ = writeln!(
                    Serial,
                    "ACPI ACCESS REFUSED address={physical:#x} length={length} reason={error:?}"
                );
                return None;
            }
        };
        self.lowest = self.lowest.min(physical);
        self.highest = self.highest.max(physical + length as u64);
        Some(unsafe { core::slice::from_raw_parts(address as *const u8, length) })
    }
}

#[derive(Clone, Copy)]
struct PowerOff {
    pm1a: u16,
    pm1b: Option<u16>,
    typ_a: u8,
    typ_b: u8,
}

static ARMED: AtomicBool = AtomicBool::new(false);
static mut POWER: Option<PowerOff> = None;

// Written only by BSP discovery before AP startup; immutable afterward.
// No borrowed table storage survives.
// Separate publication from S5: DSDT/PM1 eligibility cannot suppress reset.
static RESET_PUBLISHED: AtomicBool = AtomicBool::new(false);
static mut RESET: Result<acpi::ResetPlan, acpi::ResetError> = Err(acpi::ResetError::Disabled);

fn publish_reset(plan: Result<acpi::ResetPlan, acpi::ResetError>) {
    unsafe { core::ptr::write(core::ptr::addr_of_mut!(RESET), plan) };
    RESET_PUBLISHED.store(true, Ordering::Release);
}

pub fn reset_plan() -> Result<acpi::ResetPlan, acpi::ResetError> {
    if !RESET_PUBLISHED.load(Ordering::Acquire) {
        return Err(acpi::ResetError::Disabled);
    }
    unsafe { core::ptr::read(core::ptr::addr_of!(RESET)) }
}

/// What the existing SMP bring-up will assume, for the MADT cross-check.
pub struct SmpView {
    /// A kernel-only AP start is configured for this boot.
    pub active: bool,
    /// `cpu::count()`: the bring-up registers APIC IDs 1..count as APs.
    pub assumed_cpus: usize,
}

fn bsp_apic_id() -> u32 {
    use core::arch::x86_64::{__cpuid, __cpuid_count};
    if __cpuid(0).eax >= 0xb {
        let leaf = __cpuid_count(0xb, 0);
        if leaf.ebx & 0xffff != 0 {
            return leaf.edx;
        }
    }
    __cpuid(1).ebx >> 24
}

fn inw(port: u16) -> u16 {
    let value: u16;
    unsafe {
        asm!("in ax, dx", in("dx") port, out("ax") value, options(nomem, nostack, preserves_flags));
    }
    value
}

fn outw(port: u16, value: u16) {
    unsafe {
        asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags));
    }
}

fn opt_port(port: Option<u16>) -> u64 {
    port.map_or(0, u64::from)
}

fn space(space: u8) -> &'static str {
    match space {
        acpi::SPACE_MEMORY => "memory",
        acpi::SPACE_IO => "io",
        acpi::SPACE_PCI => "pci",
        _ => "other",
    }
}

/// Reads, validates and reports the ACPI tables, and arms S5 power-off when
/// `poweroff` is set and the sleep type and PM1 ports were found. Returns
/// whether the walk reached the end (`ACPI OK`). `reset` caches a checked
/// Q35 plan only on a successful required walk. Never panics on a table.
pub fn report(
    info: *const u8,
    total_size: usize,
    smp: SmpView,
    poweroff: bool,
    reset: bool,
) -> bool {
    // A failed required walk leaves a named refusal, never a partially armed plan.
    if reset {
        publish_reset(Err(acpi::ResetError::Walk));
    }
    let block = unsafe { core::slice::from_raw_parts(info, total_size) };
    let mut tag = None;
    let mut memory_map = None;
    for (kind, bytes) in tags(block) {
        if kind == TAG_ACPI_NEW || (kind == TAG_ACPI_OLD && tag.is_none()) {
            tag = Some((kind, &bytes[8..]));
        }
        if kind == TAG_MEMORY_MAP && memory_map.is_none() {
            memory_map = Some(bytes);
        }
    }
    let Some((kind, rsdp)) = tag else {
        write("ACPI REFUSED stage=rsdp reason=NoTag\n");
        return false;
    };
    let rsdp = match acpi::parse_rsdp(rsdp) {
        Ok(rsdp) => rsdp,
        Err(error) => {
            let _ = writeln!(Serial, "ACPI REFUSED stage=rsdp reason={error:?}");
            return false;
        }
    };
    let _ = writeln!(
        Serial,
        "ACPI RSDP tag={} revision={} rsdt={:#x} xsdt={:#x}",
        if kind == TAG_ACPI_NEW { "new" } else { "old" },
        rsdp.revision,
        rsdp.rsdt,
        rsdp.xsdt.unwrap_or(0)
    );
    let mut memory = Physical {
        memory_map,
        remaps: 0,
        lowest: u64::MAX,
        highest: 0,
        refusals: 0,
    };
    let ok = walk(&mut memory, &rsdp, smp, poweroff, reset);
    mmio::scratch_clear();
    let lowest = if memory.lowest == u64::MAX {
        0
    } else {
        memory.lowest
    };
    let above = if memory.highest > acpi::IDENTITY_LIMIT {
        "yes"
    } else {
        "no"
    };
    let _ = writeln!(
        Serial,
        "ACPI LOCATION lowest={lowest:#x} highest={:#x} above-first-gib={above} mmio-slots=0 scratch-pages={} scratch-remaps={} access-refusals={}",
        memory.highest,
        mmio::SCRATCH_PAGES,
        memory.remaps,
        memory.refusals
    );
    if ok {
        write("ACPI OK\n");
    }
    ok
}

fn walk(
    memory: &mut Physical,
    rsdp: &acpi::Rsdp,
    smp: SmpView,
    poweroff: bool,
    reset: bool,
) -> bool {
    let root = match acpi::read_root(memory, rsdp) {
        Ok(root) => root,
        Err(error) => {
            let _ = writeln!(Serial, "ACPI REFUSED stage=root reason={error:?}");
            return false;
        }
    };
    let _ = writeln!(
        Serial,
        "ACPI ROOT kind={} address={:#x} tables={}",
        if root.xsdt { "XSDT" } else { "RSDT" },
        root.address,
        root.count
    );
    for entry in root.entries() {
        let sig = core::str::from_utf8(&entry.signature).unwrap_or("????");
        match entry.header {
            Ok(header) => {
                let _ = writeln!(
                    Serial,
                    "ACPI TABLE sig={sig} address={:#x} length={} revision={}",
                    entry.address, header.length, header.revision
                );
            }
            Err(error) => {
                let _ = writeln!(
                    Serial,
                    "ACPI TABLE REFUSED sig={sig} address={:#x} reason={error:?}",
                    entry.address
                );
            }
        }
    }
    amdvi(memory, &root);
    if crate::contain::active() {
        keep_contain_tables(memory, &root);
    }
    let madt_ok = madt(memory, &root, smp);
    let fadt = match root
        .find(b"FACP")
        .and_then(|address| acpi::read_table(memory, address, Some(b"FACP")))
        .and_then(|(_, bytes)| acpi::parse_fadt(bytes))
    {
        Ok(fadt) => fadt,
        Err(error) => {
            let _ = writeln!(Serial, "ACPI REFUSED stage=fadt reason={error:?}");
            return false;
        }
    };
    let ports = acpi::pm1_ports(&fadt);
    // A firmware-named port is read only when power-off was asked for.
    let sci_en = match ports {
        Ok((pm1a, _)) if poweroff => {
            if inw(pm1a) & 1 != 0 {
                "1"
            } else {
                "0"
            }
        }
        _ => "unread",
    };
    let _ = writeln!(
        Serial,
        "ACPI FADT revision={} length={} flags={:#x} sci={} pm1a-cnt={:#x} pm1b-cnt={:#x} pm1-cnt-len={} sci-en={} hw-reduced={} smi-cmd={:#x}",
        fadt.revision,
        fadt.length,
        fadt.flags,
        fadt.sci,
        fadt.pm1a_cnt,
        fadt.pm1b_cnt,
        fadt.pm1_cnt_len,
        sci_en,
        u8::from(fadt.flags & acpi::FADT_HW_REDUCED != 0),
        fadt.smi_cmd
    );
    match fadt.reset {
        Some((gas, value)) => {
            let _ = writeln!(
                Serial,
                "ACPI FADT RESET supported={} space={} address={:#x} width={} value={:#04x} machine-reset-port={} machine-reset-value={}",
                u8::from(fadt.flags & acpi::FADT_RESET_REG_SUP != 0),
                space(gas.space),
                gas.address,
                gas.width,
                value,
                // `machine_reset` writes 0x02 then 0x06 to I/O port 0xcf9.
                if gas.space == acpi::SPACE_IO && gas.address == 0xcf9 {
                    "same"
                } else {
                    "different"
                },
                if value == 0x06 { "same" } else { "different" }
            );
        }
        None => write("ACPI FADT RESET absent (table too short)\n"),
    }
    let s5 = s5(memory, &fadt);
    match (ports, s5) {
        (Ok((pm1a, pm1b)), Some((typ_a, typ_b))) => {
            let _ = writeln!(
                Serial,
                "ACPI S5 slp-typa={typ_a} slp-typb={typ_b} pm1a={:#x} pm1b={:#x}",
                pm1a,
                opt_port(pm1b)
            );
            if poweroff {
                unsafe {
                    core::ptr::write(
                        core::ptr::addr_of_mut!(POWER),
                        Some(PowerOff {
                            pm1a,
                            pm1b,
                            typ_a,
                            typ_b,
                        }),
                    );
                }
                ARMED.store(true, Ordering::Release);
                write("ACPI POWEROFF ARMED\n");
            }
        }
        (Err(error), _) => {
            let _ = writeln!(Serial, "ACPI S5 REFUSED reason=Pm1{error:?} fallback=halt");
        }
        (Ok(_), None) => {}
    }
    if poweroff && !ARMED.load(Ordering::Acquire) {
        write("ACPI POWEROFF REFUSED fallback=halt\n");
    }
    if reset && madt_ok {
        let plan = acpi::qemu_reset_plan(true, Some(&fadt));
        match plan {
            Ok(_) => write("ACPI RESET ARMED profile=q35-byte-io port=0xcf9 value=0x0f\n"),
            Err(error) => {
                let _ = writeln!(
                    Serial,
                    "ACPI RESET REFUSED reason={error:?} fallback=legacy"
                );
            }
        }
        publish_reset(plan);
    }
    madt_ok
}

fn s5(memory: &mut Physical, fadt: &acpi::Fadt) -> Option<(u8, u8)> {
    let Some(address) = fadt.dsdt_address() else {
        write("ACPI S5 REFUSED reason=DsdtAddress fallback=halt\n");
        return None;
    };
    let dsdt = match acpi::read_table(memory, address, Some(b"DSDT")) {
        Ok((header, bytes)) => {
            let _ = writeln!(
                Serial,
                "ACPI DSDT address={address:#x} length={} revision={}",
                header.length, header.revision
            );
            bytes
        }
        Err(error) => {
            let _ = writeln!(Serial, "ACPI S5 REFUSED reason=Dsdt{error:?} fallback=halt");
            return None;
        }
    };
    match acpi::s5_sleep_types(dsdt) {
        Ok(types) => Some(types),
        Err(error) => {
            let _ = writeln!(Serial, "ACPI S5 REFUSED reason={error:?} fallback=halt");
            None
        }
    }
}

fn madt(memory: &mut Physical, root: &acpi::Root, smp: SmpView) -> bool {
    let madt = match root
        .find(b"APIC")
        .and_then(|address| acpi::read_table(memory, address, Some(b"APIC")))
        .and_then(|(_, bytes)| acpi::parse_madt(bytes))
    {
        Ok(madt) => madt,
        Err(error) => {
            let _ = writeln!(Serial, "ACPI REFUSED stage=madt reason={error:?}");
            return false;
        }
    };
    if crate::smp_operator::enabled() {
        let (low, high): (u32, u32);
        unsafe {
            asm!("rdmsr", in("ecx") 0x1bu32, out("eax") low, out("edx") high, options(nomem, nostack));
        }
        let msr = (u64::from(high) << 32) | u64::from(low);
        if msr & (1 << 11) == 0
            || msr & (1 << 10) != 0
            || absd_kernel::operator_policy::topology(
                madt.cpus(),
                bsp_apic_id(),
                madt.lapic_address,
                msr & 0x000f_ffff_ffff_f000,
                crate::cpu::count(),
            )
            .is_err()
        {
            write("SMP OPERATOR REFUSED reason=topology\n");
            return false;
        }
        let _ = write!(
            Serial,
            "SMP OPERATOR TOPOLOGY enabled={} ids=0",
            crate::cpu::count()
        );
        for id in 1..crate::cpu::count() {
            let _ = write!(Serial, ",{id}");
        }
        write(" bsp=0 lapic=matched\n");
    }
    for cpu in madt.cpus() {
        let _ = writeln!(
            Serial,
            "ACPI MADT CPU kind={} uid={} apic={} enabled={} online-capable={}",
            match cpu.kind {
                acpi::CpuKind::Xapic => "xapic",
                acpi::CpuKind::X2apic => "x2apic",
            },
            cpu.uid,
            cpu.apic,
            u8::from(cpu.enabled()),
            u8::from(cpu.online_capable())
        );
    }
    for io in madt.ioapics() {
        let _ = writeln!(
            Serial,
            "ACPI MADT IOAPIC id={} address={:#x} gsi-base={}",
            io.id, io.address, io.gsi_base
        );
    }
    for iso in madt.isos() {
        let _ = writeln!(
            Serial,
            "ACPI MADT ISO bus={} irq={} gsi={} flags={:#06x}",
            iso.bus, iso.source, iso.gsi, iso.flags
        );
    }
    let enabled = madt.enabled();
    let _ = writeln!(
        Serial,
        "ACPI MADT cpus={} online-capable={} disabled={} ioapics={} isos={} other={} lapic={:#x} pcat-compat={}",
        enabled,
        madt.online_capable(),
        madt.cpus().len() - enabled - madt.online_capable(),
        madt.ioapics().len(),
        madt.isos().len(),
        madt.other,
        madt.lapic_address,
        madt.flags & 1
    );
    // The bring-up does not consult the MADT: it registers APIC IDs
    // 1..assumed as APs. Disclose whether the firmware agrees; change
    // nothing.
    let bsp = bsp_apic_id();
    let bsp_listed = madt.has_apic(bsp);
    let ids_listed = (1..smp.assumed_cpus as u32).all(|id| madt.has_apic(id));
    let result = if !smp.active {
        "not-compared"
    } else if bsp_listed && ids_listed && enabled == smp.assumed_cpus {
        "match"
    } else {
        "MISMATCH"
    };
    let _ = writeln!(
        Serial,
        "ACPI MADT SMP-CHECK bsp-apic={bsp} bsp-listed={} bringup={} assumed-cpus={} assumed-ids-listed={} madt-cpus={enabled} result={result}",
        if bsp_listed { "yes" } else { "no" },
        if smp.active {
            "kernel-only-ap"
        } else {
            "inactive"
        },
        smp.assumed_cpus,
        if ids_listed { "yes" } else { "no" },
    );
    true
}

/// Enters S5 when `acpi-poweroff` armed it; returns only if the machine is
/// still running afterwards, having said so, so the caller's default end
/// (debug-exit, else halt) follows.
pub fn poweroff_if_armed() {
    if !ARMED.load(Ordering::Acquire) {
        return;
    }
    let Some(power) = (unsafe { core::ptr::read(core::ptr::addr_of!(POWER)) }) else {
        return;
    };
    unsafe { asm!("cli", options(nomem, nostack)) };
    let _ = writeln!(
        Serial,
        "ACPI S5 POWEROFF pm1a={:#x} slp-typa={} pm1b={:#x} slp-typb={}",
        power.pm1a,
        power.typ_a,
        opt_port(power.pm1b),
        power.typ_b
    );
    serial_finish_output();
    // Let the UART drain its FIFO and shift register (bounded).
    for _ in 0..1_000_000 {
        if unsafe { inb(0x3f8 + 5) } & 0x40 != 0 {
            break;
        }
        core::hint::spin_loop();
    }
    // SLP_TYP first, then SLP_TYP|SLP_EN, to PM1a and then PM1b, as ACPICA
    // does; every other bit of each register is preserved.
    let a = inw(power.pm1a);
    let b = power.pm1b.map(inw);
    // Interrupts are off, so the library (built with a red zone) is safe.
    outw(power.pm1a, acpi::pm1_sleep_value(a, power.typ_a, false));
    if let (Some(port), Some(b)) = (power.pm1b, b) {
        outw(port, acpi::pm1_sleep_value(b, power.typ_b, false));
    }
    outw(power.pm1a, acpi::pm1_sleep_value(a, power.typ_a, true));
    if let (Some(port), Some(b)) = (power.pm1b, b) {
        outw(port, acpi::pm1_sleep_value(b, power.typ_b, true));
    }
    for _ in 0..10_000_000 {
        core::hint::spin_loop();
    }
    write("ACPI S5 POWEROFF FAILED fallback=halt\n");
}

// The parsed unit is ~1.5 KiB: kept off the 32 KiB bootstrap stack.
static mut UNIT: Unit = Unit::EMPTY;
static mut SCRATCH: Entries = Entries::EMPTY;
/// Set when discovery reached its `AMDVI RESULT` line (structurally valid,
/// PCI and memory-map cross-checks passed); read by increment 3's
/// enforce-test boot (src/amdvi_hw.rs). Nothing else reads it.
static mut DISCOVERED: Option<Discovered> = None;

static mut MCFG: Option<absd_kernel::mcfg::Regions> = None;

/// What the `dma-contain` path needs later: MCFG. No output, and only in that boot.
fn keep_contain_tables(memory: &mut Physical, root: &acpi::Root) {
    let Ok(address) = root.find(b"MCFG") else {
        return;
    };
    if let Ok((_, bytes)) = acpi::read_table(memory, address, Some(b"MCFG"))
        && let Ok(regions) = absd_kernel::mcfg::parse(bytes)
    {
        unsafe { *core::ptr::addr_of_mut!(MCFG) = Some(regions) };
    }
}

/// A function's ECAM configuration page, when MCFG describes it.
pub fn config_page(bus: u8, device: u8, function: u8) -> Option<u64> {
    unsafe { *core::ptr::addr_of!(MCFG) }?.config_page(bus, device, function)
}

/// What discovery established, for the enforce-test boot.
#[derive(Clone, Copy)]
pub struct Discovered {
    pub validation: ivrs::Validation,
    /// The capability header as read in the PCI cross-check.
    pub cap_header: u32,
}

/// The discovered unit, when discovery reached its result line.
pub fn discovered() -> Option<(&'static Unit, Discovered)> {
    let found = unsafe { *core::ptr::addr_of!(DISCOVERED) }?;
    Some((unsafe { &*core::ptr::addr_of!(UNIT) }, found))
}

fn bdf(id: u16) -> (u16, u16, u16) {
    (id >> 8, (id >> 3) & 0x1f, id & 7)
}

struct Id(u16);

impl core::fmt::Display for Id {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (bus, device, function) = bdf(self.0);
        write!(f, "{bus:02x}:{device:02x}.{function}")
    }
}

fn text(bytes: &[u8]) -> &str {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    match core::str::from_utf8(&bytes[..end]) {
        Ok(text) if text.bytes().all(|b| b.is_ascii_graphic()) => text,
        _ => "?",
    }
}

/// Discovery only (#111 increment 2): find, validate and report the one
/// AMD-Vi unit, or the precise refusal. Enables nothing.
///
/// A structurally valid table is reported with every deviation the parser
/// found in its validated subset, cross-checked against PCI and the memory
/// map, and summarised by one `AMDVI RESULT` line that carries the scope as
/// separate properties: structure, deviations, how many fields were
/// validated and carried unvalidated, and DMA admission, which increment 2
/// never establishes.
fn amdvi(memory: &mut Physical, root: &acpi::Root) {
    let address = match root.find(b"IVRS") {
        Ok(address) => address,
        Err(acpi::Error::Missing) => {
            write("AMDVI NONE reason=no-ivrs\n");
            return;
        }
        Err(error) => {
            let _ = writeln!(
                Serial,
                "AMDVI REFUSED class={} reason=table-{error:?}",
                table_class(error)
            );
            return;
        }
    };
    let bytes = match acpi::read_table(memory, address, Some(b"IVRS")) {
        Ok((_, bytes)) => bytes,
        Err(error) => {
            let _ = writeln!(
                Serial,
                "AMDVI REFUSED class={} reason=table-{error:?} address={address:#x}",
                table_class(error)
            );
            return;
        }
    };
    let unit = unsafe { &mut *core::ptr::addr_of_mut!(UNIT) };
    let scratch = unsafe { &mut *core::ptr::addr_of_mut!(SCRATCH) };
    let ivinfo = if bytes.len() >= ivrs::HEADER_BYTES {
        u32::from_le_bytes([bytes[36], bytes[37], bytes[38], bytes[39]])
    } else {
        0
    };
    let _ = writeln!(
        Serial,
        "AMDVI IVRS address={address:#x} length={} revision={} ivinfo={ivinfo:#010x} efrsup={} preboot-dma-protection={}",
        bytes.len(),
        bytes.get(8).copied().unwrap_or(0),
        ivinfo & ivrs::IVINFO_EFR_SUP,
        (ivinfo & ivrs::IVINFO_DMA_REMAP) >> 1
    );
    let validation = match ivrs::parse(bytes, unit, scratch) {
        Ok(validation) => validation,
        Err(error) => {
            report_refusal(&error);
            return;
        }
    };
    report_unit(unit);
    for finding in unit.findings.items() {
        let _ = writeln!(
            Serial,
            "AMDVI DEVIATION block={} offset={:#x} field={} rule={} {}",
            Block(finding.block),
            finding.offset,
            finding.field.name(),
            finding.field.rule(),
            finding.detail
        );
    }
    let window = unit.window();
    let (base_check, cap_header) = match pci_cross_check(unit) {
        Ok(check) => check,
        Err(reason) => {
            let _ = writeln!(
                Serial,
                "AMDVI REFUSED class={} reason=pci-{reason}",
                pci_refusal_class(reason)
            );
            return;
        }
    };
    let rows = memory.memory_map.map(acpi::memory_map_entries);
    let placement = match rows {
        None => {
            write("AMDVI REFUSED class=unsupported reason=no-memory-map\n");
            return;
        }
        Some(rows) => ivrs::placement(unit.base, window, rows),
    };
    match placement {
        Ok(placement) => {
            let _ = writeln!(
                Serial,
                "AMDVI MEMORY base={:#x} window={window:#x} map={}",
                unit.base,
                match placement {
                    Placement::Reserved => "reserved",
                    Placement::Unlisted => "unlisted",
                }
            );
        }
        Err(kind) => {
            let _ = writeln!(
                Serial,
                "AMDVI REFUSED class=mismatch reason=base-in-memory base={:#x} window={window:#x} row-type={kind}",
                unit.base
            );
            return;
        }
    }
    report_handoff();
    let _ = writeln!(
        Serial,
        "AMDVI RESULT devid={} base={:#x} pci-base={} structure=valid deviations={} validated-fields={} unvalidated-fields={} dma-admission={} preboot-dma=uncontained",
        Id(unit.devid),
        unit.base,
        match base_check {
            BaseCheck::Matched => "matched",
            BaseCheck::Unverified => "unverified-enable-0",
        },
        validation.deviations,
        validation.validated.len(),
        validation.unvalidated.len(),
        validation.dma_admission.name()
    );
    unsafe {
        *core::ptr::addr_of_mut!(DISCOVERED) = Some(Discovered {
            validation,
            cap_header,
        })
    };
}

/// A finding's block: the IVRS header, or an IVHD type.
struct Block(u8);

impl core::fmt::Display for Block {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            0 => f.write_str("header"),
            kind => write!(f, "{kind:02x}h"),
        }
    }
}

/// An IVRS the ACPI reader refuses: a second IVRS (§5.2: "a single
/// IVRS in a system"), a bad checksum or length are malformed; a table the
/// reader cannot reach or count is beyond what it supports.
fn table_class(error: acpi::Error) -> &'static str {
    match error {
        acpi::Error::Unreachable | acpi::Error::TooManyTables => ivrs::Class::Unsupported.name(),
        _ => ivrs::Class::Malformed.name(),
    }
}

/// What is known about the unit's live state. No IOMMU MMIO register is
/// read in increment 2 (Control, Status and the live EFR are unobserved),
/// so the firmware's handoff state is printed as not observed; what ABSD
/// itself did is a fact of this code: it wrote nothing to the unit.
fn report_handoff() {
    if cfg!(absd_mutant_amdvi_claim_disabled) {
        write("AMDVI HANDOFF iommu-en=0 translation=none absd-enabled=no\n");
        return;
    }
    write("AMDVI HANDOFF iommu-en=not-observed translation=not-observed absd-enabled=no\n");
}

fn report_refusal(error: &ivrs::Error) {
    let _ = write!(
        Serial,
        "AMDVI REFUSED class={} reason={}",
        error.class().name(),
        error.name()
    );
    if let Some(offset) = error.offset() {
        let _ = write!(Serial, " offset={offset:#x}");
    }
    let _ = match *error {
        ivrs::Error::Entry { problem, .. } => writeln!(Serial, " problem={problem:?}"),
        ivrs::Error::Inconsistent { field, .. } => writeln!(Serial, " field={field}"),
        ivrs::Error::UnknownBlock { kind, .. }
        | ivrs::Error::Ivmd { kind, .. }
        | ivrs::Error::IvmdMalformed { kind, .. }
        | ivrs::Error::BlockNotAllowed { kind, .. } => writeln!(Serial, " block={kind:#04x}"),
        ivrs::Error::Revision(value) => writeln!(Serial, " revision={value}"),
        ivrs::Error::Segment { segment, kind, .. } => {
            writeln!(Serial, " block={kind:#04x} segment={segment}")
        }
        ivrs::Error::CapabilityOffset { capability, .. } => {
            writeln!(Serial, " capability={capability:#x}")
        }
        ivrs::Error::HatsReserved { kind, raw, .. } => {
            writeln!(Serial, " block={kind:#04x} raw={raw:#x}")
        }
        ivrs::Error::HostTranslationDisabled { kind, raw, .. } => {
            writeln!(Serial, " block={kind:#04x} raw={raw:#x}")
        }
        ivrs::Error::BaseAlignment(base) | ivrs::Error::BaseRange(base) => {
            writeln!(Serial, " base={base:#x}")
        }
        _ => writeln!(Serial),
    };
}

/// A PCI cross-check refusal. Apart from an out-of-range capability offset
/// (malformed; the parser already refuses it), these say the table and this
/// machine disagree (no such function, not an IOMMU, another base): the
/// table is not checked against the spec here but against the hardware, so
/// the class is `mismatch`.
fn pci_refusal_class(reason: &str) -> &'static str {
    if reason == "capability-offset" {
        ivrs::Class::Malformed.name()
    } else {
        "mismatch"
    }
}

fn report_unit(unit: &Unit) {
    // Raw images for the report only; decisions use validated accessors.
    let images = unit.images();
    let _ = write!(
        Serial,
        "AMDVI UNIT devid={} cap={:#x} base={:#x} window={:#x} segment={} {} used={:02x}h present=",
        Id(unit.devid),
        unit.capability,
        unit.base,
        unit.window(),
        unit.segment,
        images.header(),
        unit.used
    );
    let mut first = true;
    for (bit, name) in [(1u8, "10h"), (2, "11h"), (4, "40h")] {
        if unit.present & bit != 0 {
            let _ = write!(Serial, "{}{name}", if first { "" } else { "," });
            first = false;
        }
    }
    let _ = write!(Serial, " {}", images.efr());
    match unit.host_levels() {
        Some(levels) => {
            let _ = writeln!(Serial, " host-levels={levels} ivmd=0");
        }
        None => write(" host-levels=unknown ivmd=0\n"),
    }
    for span in unit.entries.spans() {
        let _ = write!(
            Serial,
            "AMDVI ENTRY {} first={} last={} setting={:#04x}",
            if span.alias.is_some() {
                "alias"
            } else {
                "plain"
            },
            Id(span.first),
            Id(span.last),
            span.setting
        );
        if let Some(extended) = span.extended {
            let _ = write!(Serial, " extended={extended:#010x}");
        }
        match span.alias {
            Some(target) => {
                let _ = writeln!(Serial, " source={}", Id(target));
            }
            None => write("\n"),
        }
    }
    for special in unit.entries.specials() {
        let _ = writeln!(
            Serial,
            "AMDVI SPECIAL {} handle={} source={} setting={:#04x}",
            match special.variety {
                Variety::IoApic => "ioapic",
                Variety::Hpet => "hpet",
            },
            special.handle,
            Id(special.source),
            special.setting
        );
    }
    for hid in unit.entries.hids() {
        let _ = writeln!(
            Serial,
            "AMDVI HID devid={} hid={} uid={} setting={:#04x} use=recorded-only",
            Id(hid.devid),
            text(&hid.hid),
            text(hid.uid()),
            hid.setting
        );
    }
    let _ = writeln!(
        Serial,
        "AMDVI SUMMARY spans={} aliased-ids={} specials={} hids={} padding={} own-source={}",
        unit.entries.spans().len(),
        unit.aliased(),
        unit.entries.specials().len(),
        unit.entries.hids().len(),
        unit.entries.padding,
        match unit.source(unit.devid) {
            Source::Own => "yes",
            Source::Alias(_) => "alias",
            Source::Undescribed => "undescribed",
        }
    );
}

/// How far the capability's base address registers could be compared.
#[derive(Clone, Copy)]
enum BaseCheck {
    /// Enable = 1 and the registers name the IVHD base.
    Matched,
    /// Enable = 0: the registers are not (yet) the decode address (§3.2,
    /// Capability Offset 04h[Enable]), so they can neither confirm nor
    /// contradict the IVHD. QEMU 8.2.2 shows this, with registers that do
    /// not encode its base at all.
    Unverified,
}

/// The IVHD's DeviceID must be an IOMMU function (class 08h/06h/00h, §3)
/// with an IOMMU capability block (ID 0Fh, type 3) at the IVHD's offset;
/// when the block's Enable bit is set its base address registers must name
/// the IVHD base (§3.2). Configuration reads only. The register offsets come
/// from `Unit::capability_registers`, which the parser bounds to
/// conventional configuration space; a unit that somehow names an offset
/// outside it is refused here, never read.
fn pci_cross_check(unit: &Unit) -> Result<(BaseCheck, u32), &'static str> {
    let (bus, device, function) = bdf(unit.devid);
    let function = crate::pci::Function {
        bus: bus as u8,
        device: device as u8,
        function: function as u8,
    };
    let read = |offset: u8| crate::pci::read32(function, offset);
    let Some([cap, low_at, high_at]) = unit.capability_registers() else {
        return Err("capability-offset");
    };
    if read(0) & 0xffff == 0xffff {
        return Err("absent");
    }
    let class = read(0x08) >> 8;
    // Walk the list from 0x34 (bounded) to find the IVHD's offset.
    let mut at = if read(0x04) >> 16 & 0x10 != 0 {
        read(0x34) as u8 & 0xfc
    } else {
        0
    };
    let mut steps = 0;
    while at != 0 && at != cap && steps < 48 {
        at = (read(at) >> 8) as u8 & 0xfc;
        steps += 1;
    }
    let header = read(cap);
    let low = read(low_at);
    let high = read(high_at);
    let base = (u64::from(high) << 32) | u64::from(low & 0xffff_c000);
    let _ = writeln!(
        Serial,
        "AMDVI PCI devid={} ids={:#010x} class={class:#08x} cap={cap:#x} listed={} cap-header={header:#010x} base-low={low:#010x} base-high={high:#010x} base={base:#x} base-enable={}",
        Id(unit.devid),
        read(0),
        if at == cap { "yes" } else { "no" },
        low & 1
    );
    if class != 0x08_0600 {
        return Err("class");
    }
    if at != cap {
        return Err("capability-not-listed");
    }
    if header & 0xff != 0x0f || (header >> 16) & 7 != 3 {
        return Err("capability-type");
    }
    if low & 1 == 0 {
        return Ok((BaseCheck::Unverified, header));
    }
    if base != unit.base {
        return Err("base");
    }
    Ok((BaseCheck::Matched, header))
}
