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

use crate::mmio;
use crate::serial::{Serial, inb, write};
use absd_kernel::acpi::{self, Access, Memory};
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
/// whether the walk reached the end (`ACPI OK`). Never panics on a table.
pub fn report(info: *const u8, total_size: usize, smp: SmpView, poweroff: bool) -> bool {
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
    let ok = walk(&mut memory, &rsdp, smp, poweroff);
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

fn walk(memory: &mut Physical, rsdp: &acpi::Rsdp, smp: SmpView, poweroff: bool) -> bool {
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
