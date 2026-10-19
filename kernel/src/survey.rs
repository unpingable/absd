//! The physical survey boot (`survey` as the mode word): identity by reads
//! only, then a compact summary that stays on the screen until power-off
//! (docs/hardware/HP-Z2-MINI-G3-FIRST-BOOT.md).
//!
//! What it does beyond the common boot path (framebuffer probe, IDT, frame
//! allocator, paging and heap self-checks, the PIT/8259 timer probe): CPUID
//! and one RDRAND draw, the Multiboot2 tags GRUB passed, and a scan of PCI
//! configuration space by reads only. It never claims a PCI function,
//! writes configuration space, maps a BAR, starts a storage or network
//! controller, touches the legacy ATA ports, or starts userspace; the boot
//! diverges here before the block probe and the NIC option are looked at.
//! `forbid` makes the first three a panic while the survey runs, and the
//! QEMU gate (scripts/survey-gate.sh) checks the device traces.

use absd_kernel::survey_facts::{self as facts, MemoryMap};

use crate::pci;
use crate::serial::{self, decimal, hex, hex_digits, write};

static mut ACTIVE: bool = false;

/// Panics if the survey boot reaches `what`: device initialization is
/// outside the survey, so reaching it is a kernel bug.
pub fn forbid(what: &str) {
    if unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ACTIVE)) } {
        panic!("survey guard: {what} reached from the survey boot");
    }
}

#[derive(Clone, Copy)]
struct Cpu {
    vendor: [u8; 12],
    brand: [u8; 48],
    signature: u32,
    lm: bool,
    nx: bool,
    pae: bool,
    msr: bool,
    tsc: bool,
    fxsr: bool,
    sse2: bool,
    apic: bool,
    x2apic: bool,
    hypervisor: bool,
    rdrand_cpuid: bool,
    rdrand_draw: bool,
}

static mut CPU: Option<Cpu> = None;

fn bit(value: u32, index: u32) -> bool {
    value & (1 << index) != 0
}

fn text(bytes: &[u8]) -> &str {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    let trimmed = &bytes[..end];
    let start = trimmed
        .iter()
        .position(|&byte| byte != b' ')
        .unwrap_or(trimmed.len());
    core::str::from_utf8(&trimmed[start..]).unwrap_or("?")
}

fn flag(name: &str, value: bool) {
    write(" ");
    write(name);
    write(if value { "=1" } else { "=0" });
}

/// Starts the survey: CPU identity and the entropy source. Called once the
/// IDT is live so a fault here is reported, not a triple fault.
pub fn cpu() {
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(ACTIVE), true) };
    use core::arch::x86_64::__cpuid;
    let leaf0 = __cpuid(0);
    let mut vendor = [0u8; 12];
    vendor[..4].copy_from_slice(&leaf0.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&leaf0.edx.to_le_bytes());
    vendor[8..].copy_from_slice(&leaf0.ecx.to_le_bytes());
    let leaf1 = __cpuid(1);
    let extended = __cpuid(0x8000_0000).eax;
    let ext_edx = if extended >= 0x8000_0001 {
        __cpuid(0x8000_0001).edx
    } else {
        0
    };
    let mut brand = [0u8; 48];
    if extended >= 0x8000_0004 {
        for (index, leaf) in (0x8000_0002u32..=0x8000_0004).enumerate() {
            let result = __cpuid(leaf);
            for (word, value) in [result.eax, result.ebx, result.ecx, result.edx]
                .iter()
                .enumerate()
            {
                let at = index * 16 + word * 4;
                brand[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
    }
    let rdrand_cpuid = bit(leaf1.ecx, 30);
    let cpu = Cpu {
        vendor,
        brand,
        signature: leaf1.eax,
        lm: bit(ext_edx, 29),
        nx: bit(ext_edx, 20),
        pae: bit(leaf1.edx, 6),
        msr: bit(leaf1.edx, 5),
        tsc: bit(leaf1.edx, 4),
        fxsr: bit(leaf1.edx, 24),
        sse2: bit(leaf1.edx, 26),
        apic: bit(leaf1.edx, 9),
        x2apic: bit(leaf1.ecx, 21),
        hypervisor: bit(leaf1.ecx, 31),
        rdrand_cpuid,
        // The same bounded draw `boot_id` uses; the value is not shown.
        rdrand_draw: rdrand_cpuid && crate::syscalls::rdrand64().is_some(),
    };
    unsafe { *core::ptr::addr_of_mut!(CPU) = Some(cpu) };
    let (family, model, stepping) = facts::cpu_signature(cpu.signature);
    write("CPU vendor=");
    write(text(&cpu.vendor));
    write(" family=0x");
    hex_digits(u64::from(family), 2);
    write(" model=0x");
    hex_digits(u64::from(model), 2);
    write(" stepping=");
    decimal(u64::from(stepping));
    write(" signature=0x");
    hex_digits(u64::from(cpu.signature), 8);
    write("\n");
    write("CPU brand=");
    write(text(&cpu.brand));
    write("\n");
    write("CPU FEATURES");
    for (name, value) in [
        ("lm", cpu.lm),
        ("nx", cpu.nx),
        ("pae", cpu.pae),
        ("msr", cpu.msr),
        ("tsc", cpu.tsc),
        ("fxsr", cpu.fxsr),
        ("sse2", cpu.sse2),
        ("apic", cpu.apic),
        ("x2apic", cpu.x2apic),
        ("hypervisor", cpu.hypervisor),
    ] {
        flag(name, value);
    }
    write("\n");
    // Everything below is what boot.S and the kernel already used to get
    // here (EFER.LME/NXE, PAE paging, RDMSR/WRMSR, RDTSC, SSE state).
    let required = [
        ("lm", cpu.lm),
        ("nx", cpu.nx),
        ("pae", cpu.pae),
        ("msr", cpu.msr),
        ("tsc", cpu.tsc),
        ("fxsr", cpu.fxsr),
        ("sse2", cpu.sse2),
    ];
    if required.iter().all(|(_, present)| *present) {
        write("CPU ACCEPTED lm nx pae msr tsc fxsr sse2\n");
    } else {
        write("CPU REFUSED missing=");
        for (name, _) in required.iter().filter(|(_, present)| !*present) {
            write(name);
            write(" ");
        }
        write("\n");
        crate::exit_qemu(1);
    }
    write(match (cpu.rdrand_cpuid, cpu.rdrand_draw) {
        (true, true) => "ENTROPY OK rdrand cpuid.1:ecx.30=1 draw=ok\n",
        (true, false) => {
            "ENTROPY REFUSED rdrand cpuid.1:ecx.30=1 draw=failed (10 tries); boot_id unavailable\n"
        }
        _ => "ENTROPY REFUSED rdrand cpuid.1:ecx.30=0; boot_id unavailable\n",
    });
}

#[derive(Clone, Copy)]
struct PciEntry {
    function: pci::Function,
    vendor: u16,
    device: u16,
    class: u32,
}

const MAX_ENTRIES: usize = 64;

fn bdf(function: pci::Function) {
    hex_digits(u64::from(function.bus), 2);
    write(":");
    hex_digits(u64::from(function.device), 2);
    write(".");
    hex_digits(u64::from(function.function), 1);
}

fn ids(entry: &PciEntry) {
    hex_digits(u64::from(entry.vendor), 4);
    write(":");
    hex_digits(u64::from(entry.device), 4);
}

fn class_dotted(class: u32) {
    hex_digits(u64::from(class >> 16) & 0xff, 2);
    write(".");
    hex_digits(u64::from(class >> 8) & 0xff, 2);
    write(".");
    hex_digits(u64::from(class) & 0xff, 2);
}

fn mib(bytes: u64) {
    decimal(bytes >> 20);
    write(" MiB");
}

/// One serial-only line per function: every field read, nothing sized.
fn record(function: pci::Function) {
    let id = pci::read32(function, 0x00);
    let command = pci::read32(function, 0x04);
    let class = pci::read32(function, 0x08);
    let header = (pci::read32(function, 0x0c) >> 16) & 0xff;
    serial::record_only(|| {
        write("RECORD PCI ");
        bdf(function);
        write(" id=");
        hex_digits(u64::from(id), 8);
        write(" rev=");
        hex_digits(u64::from(class & 0xff), 2);
        write(" class=");
        hex_digits(u64::from(class >> 8), 6);
        write(" header=");
        hex_digits(u64::from(header), 2);
        write(" command_status=");
        hex_digits(u64::from(command), 8);
        let bars = match header & 0x7f {
            0 => 6,
            1 => 2,
            _ => 0,
        };
        if header & 0x7f == 0 {
            write(" subsystem=");
            hex_digits(u64::from(pci::read32(function, 0x2c)), 8);
        }
        if header & 0x7f == 1 {
            write(" buses=");
            hex_digits(u64::from(pci::read32(function, 0x18)), 8);
        }
        write(" bars_raw_unsized=");
        for index in 0..bars {
            if index > 0 {
                write(",");
            }
            hex_digits(u64::from(pci::read32(function, 0x10 + 4 * index)), 8);
        }
        write("\n");
    });
}

/// The rest of the survey, from the Multiboot2 tags to the summary; never
/// returns to the ordinary boot path.
pub fn finish(
    info: *const u8,
    total_size: usize,
    readback: bool,
    ticks: u64,
    tsc: u64,
    calibration: &Result<facts::TimerCalibration, &'static str>,
) -> ! {
    let block = unsafe { core::slice::from_raw_parts(info, total_size) };
    let efi = facts::has_tag(block, facts::TAG_EFI64) || facts::has_tag(block, facts::TAG_EFI32);
    let acpi = if facts::has_tag(block, facts::TAG_ACPI_NEW) {
        "rsdp v2 tag present"
    } else if facts::has_tag(block, facts::TAG_ACPI_OLD) {
        "rsdp v1 tag present"
    } else {
        "no rsdp tag"
    };
    let smbios = if facts::has_tag(block, facts::TAG_SMBIOS) {
        "tag present"
    } else {
        "no tag"
    };
    let loader = facts::tag_string(block, facts::TAG_LOADER_NAME)
        .and_then(|bytes| core::str::from_utf8(bytes).ok())
        .unwrap_or("?");
    let line = facts::tag_string(block, facts::TAG_COMMAND_LINE)
        .and_then(|bytes| core::str::from_utf8(bytes).ok())
        .unwrap_or("?");
    write("BOOT firmware=");
    write(if efi { "EFI" } else { "BIOS" });
    write(" loader=");
    write(loader);
    write(" efi_memory_map=");
    write(if facts::has_tag(block, facts::TAG_EFI_MEMORY_MAP) {
        "tag"
    } else {
        "none"
    });
    write(" cmdline=");
    write(line);
    write("\n");
    write("ACPI not consumed (");
    write(acpi);
    write(") SMBIOS not consumed (");
    write(smbios);
    write(")\n");

    let map = facts::memory_map(block).unwrap_or_default();
    let frames = unsafe { crate::vm::frames() };
    let free = frames.free_frames() as u64;
    write("MEMORY map entries=");
    decimal(u64::from(map.entries));
    write(" usable=");
    mib(map.usable_bytes);
    write(" in ");
    decimal(u64::from(map.usable_regions));
    write(" regions reserved=");
    mib(map.reserved_bytes);
    write(" acpi=");
    mib(map.acpi_reclaimable_bytes);
    write(" nvs=");
    mib(map.acpi_nvs_bytes);
    write(" bad=");
    mib(map.bad_bytes);
    write(" highest=");
    hex(map.highest_end);
    write("\n");
    write("MEMORY OK tracked_limit=");
    mib(frames.tracked_limit());
    write(" free_frames=");
    decimal(free);
    write(" (");
    mib(free * 4096);
    write(") frame/paging/heap checks passed\n");
    write("TIMER OK path=pit-8254-ch0-1000hz 8259-irq0 vector=32 ticks=");
    decimal(ticks);
    write(" tsc_cycles=");
    decimal(tsc);
    write(" (uncalibrated) lapic=unused ioapic=unused\n");
    // Clock 6a: the same line the boot printed, as a survey fact.
    match calibration {
        Ok(c) => {
            let mut buf = [0u8; facts::TIMER_CALIBRATION_LINE_MAX];
            write(
                facts::format_timer_calibration(c, &mut buf)
                    .unwrap_or("TIMER CALIBRATION FAILED reason=format"),
            );
        }
        Err(reason) => {
            write("TIMER CALIBRATION FAILED reason=");
            write(reason);
        }
    }
    write("\n");

    let mut entries = [None::<PciEntry>; MAX_ENTRIES];
    let mut count = 0usize;
    pci::each(|function| {
        record(function);
        let (vendor, device) = pci::ids(function);
        if count < MAX_ENTRIES {
            entries[count] = Some(PciEntry {
                function,
                vendor,
                device,
                class: pci::read32(function, 0x08) >> 8,
            });
        }
        count += 1;
    });
    write("PCI ENUMERATION OK functions=");
    decimal(count as u64);
    write(" (configuration reads only; BARs raw, unsized, serial RECORD lines)\n");

    summary(
        &entries[..count.min(MAX_ENTRIES)],
        count,
        &map,
        free,
        ticks,
        readback,
        efi,
    )
}

fn summary(
    entries: &[Option<PciEntry>],
    count: usize,
    map: &MemoryMap,
    free: u64,
    ticks: u64,
    readback: bool,
    efi: bool,
) -> ! {
    let entries = || entries.iter().flatten();
    let is = |entry: &&PciEntry, class: u32| entry.class >> 16 == class;
    let storage = entries().filter(|entry| is(entry, 0x01)).count();
    let network = entries().filter(|entry| is(entry, 0x02)).count();
    const SHOWN: usize = 4;
    let shown_storage = storage.clamp(1, SHOWN);
    let shown_network = network.clamp(1, SHOWN);
    // Rows the summary needs apart from the PCI cells, the final halt
    // notice included; the cells get whatever else fits under the ring's
    // one blank row.
    let fixed = 17 + shown_storage + shown_network;
    let screen = crate::framebuffer::summary();
    let per_row = screen
        .as_ref()
        .map_or(4, |screen| facts::pci_cells_per_row(screen.columns));
    let cell_rows = screen.as_ref().map_or(usize::MAX, |screen| {
        screen.rows.saturating_sub(1 + fixed).max(1)
    });
    let cells = entries().count().min(cell_rows.saturating_mul(per_row));

    write("ABSD PHYSICAL SURVEY v1: identity by reads only\n");
    if let Some(cpu) = unsafe { *core::ptr::addr_of!(CPU) } {
        let (family, model, stepping) = facts::cpu_signature(cpu.signature);
        write("CPU ");
        write(text(&cpu.vendor));
        write(" ");
        hex_digits(u64::from(family), 2);
        write("/");
        hex_digits(u64::from(model), 2);
        write("/");
        decimal(u64::from(stepping));
        write(" ");
        write(text(&cpu.brand));
        write("\n");
        write("CPU ACCEPTED hypervisor=");
        write(if cpu.hypervisor { "yes" } else { "no" });
        write(if cpu.rdrand_draw {
            " RDRAND ok (cpuid+draw)\n"
        } else if cpu.rdrand_cpuid {
            " RDRAND REFUSED (draw failed)\n"
        } else {
            " RDRAND REFUSED (absent)\n"
        });
    }
    write("BOOT ");
    write(if efi { "EFI" } else { "BIOS" });
    write(" via Multiboot2; ACPI not consumed\n");
    write("MEMORY OK usable=");
    mib(map.usable_bytes);
    write(" regions=");
    decimal(u64::from(map.usable_regions));
    write(" used=first ");
    mib(unsafe { crate::vm::frames() }.tracked_limit());
    write(" free_frames=");
    decimal(free);
    write("\n");
    write("TIMER OK PIT/8259 IRQ0 ticks=");
    decimal(ticks);
    write(" LAPIC unused\n");
    match screen {
        Some(screen) => {
            let geometry = screen.geometry;
            write("FRAMEBUFFER ");
            decimal(geometry.width as u64);
            write("x");
            decimal(geometry.height as u64);
            write("x");
            decimal(geometry.bytes_per_pixel as u64 * 8);
            write(" pitch=");
            decimal(geometry.pitch as u64);
            write(" console=");
            decimal(screen.columns as u64);
            write("x");
            decimal(screen.rows as u64);
            write(if readback {
                " readback OK\n"
            } else {
                " readback FAILED\n"
            });
        }
        None => write("FRAMEBUFFER none\n"),
    }
    write("PCI functions=");
    decimal(count as u64);
    write(" (BB:DD.F VVVV:DDDD class)\n");
    for (index, entry) in entries().take(cells).enumerate() {
        bdf(entry.function);
        write(" ");
        ids(entry);
        write(" ");
        hex_digits(u64::from(entry.class), 6);
        let last = index + 1 == cells;
        if last || (index + 1) % per_row == 0 {
            write("\n");
        } else {
            write("  ");
        }
    }
    if count > cells {
        write("PCI +");
        decimal((count - cells) as u64);
        write(" more on serial (RECORD PCI lines)\n");
    }
    let mut listed = 0;
    for entry in entries().filter(|entry| is(entry, 0x01)).take(SHOWN) {
        let (kind, driver) = facts::storage_kind((entry.class >> 8) as u8, entry.class as u8);
        write("STORAGE CONTROLLER ");
        bdf(entry.function);
        write(" ");
        ids(entry);
        write(" ");
        write(kind);
        write(" driver=");
        write(driver);
        write(" NOT INITIALIZED\n");
        listed += 1;
    }
    if listed == 0 {
        write("STORAGE CONTROLLER none (no PCI class 01 function)\n");
    }
    listed = 0;
    for entry in entries().filter(|entry| is(entry, 0x02)).take(SHOWN) {
        write("NETWORK CONTROLLER ");
        bdf(entry.function);
        write(" ");
        ids(entry);
        write(" class=");
        class_dotted(entry.class);
        write(" driver=");
        write(if (entry.vendor, entry.device) == facts::E1000_IDS {
            "e1000"
        } else {
            "none"
        });
        write(" NOT INITIALIZED\n");
        listed += 1;
    }
    if listed == 0 {
        write("NETWORK CONTROLLER none (no PCI class 02 function)\n");
    }
    if count > MAX_ENTRIES {
        write("PCI list capped at ");
        decimal(MAX_ENTRIES as u64);
        write(" functions\n");
    }
    write("PERSISTENT WRITES: DISABLED");
    write(if crate::block::WRITES_BUILT {
        " (no storage driver started)\n"
    } else {
        " (read-only build, no storage driver started)\n"
    });
    write("STORAGE CONTROLLER INITIALIZATION: NOT PERFORMED\n");
    write("NETWORK INITIALIZATION: DISABLED\n");
    write("PHYSICAL SURVEY COMPLETE\n");
    write("ABSD BOOT OK\n");
    write("SAFE TO POWER OFF\n");
    crate::exit_qemu(0)
}
