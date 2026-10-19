//! AHCI census: what SATA controllers and devices a machine has, learnt
//! with IDENTIFY DEVICE alone (AHCI census, slice 1).
//!
//! A separate boot entry (`ahci-census`), before storage or userspace. For
//! every PCI mass-storage function: an AHCI controller (class 01.06.01) that
//! firmware left in AHCI mode is claimed, its ABAR mapped, and each
//! implemented port read; a port with an ATA device on an active link gets
//! exactly one command, IDENTIFY DEVICE (0xEC), through a command list and
//! FIS area in static kernel memory, with the port's command engine stopped
//! and restarted around it and its original command list and FIS base
//! restored afterwards. An engine not shown quiescent (CR/FR still set after
//! the bound) fails closed at controller level: bus mastering is turned off
//! before anything is printed, that controller's walk stops (no further AHCI
//! register write to it; the final bus-master-off PCI config write repeats),
//! the port's bases are not rewritten, and after a failed post-command stop
//! the static buffers are retired for the rest of the census
//! (`survey_facts::ahci_after_stop`). Later controllers' ports are still read
//! (SSTS, SIG, CMD, FBS) before an ATA port is skipped on the retired buffers.
//! A pre-command stop failure on CR returns before FRE is cleared (ST is
//! already off). No interrupt source is disabled explicitly (GHC.IE, PxIE and
//! MSI are left as found); INTx stays masked in the PCI command. ATAPI devices, devices on low-power links, offline
//! PHYs and ports waiting for staggered spin-up are reported from the port
//! registers and never sent a command. Refused, with a line and without a
//! register write: RAID-class functions (01.04, the Z2's 8086:2822 in RAID
//! mode) and Intel RST RAID device ids whatever their class, controllers
//! with AHCI mode off (GHC.AE=0), BIOS-owned HBAs (BOHC.BOS), ports with
//! FIS-based switching on, and ports the ABAR or CAP.NP does not cover.
//! No write, no flush, no reset of the HBA, no interrupt: every wait is
//! polled with interrupts enabled for the tick bound and a TSC backstop
//! behind it, so a dead PIT or a wedged drive ends in a line, not a hang.
//! One census, then the kernel stops.

use absd_kernel::survey_facts as facts;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::{mmio, pci, serial};

const CLASS_MASS_STORAGE: u8 = 0x01;
const SUBCLASS_RAID: u8 = 0x04;
const SUBCLASS_SATA: u8 = 0x06;
const INTERFACE_AHCI: u8 = 0x01;
const ABAR: u8 = 5;
/// Intel Rapid Storage RAID-mode device ids: refused by id as well as by
/// class, in case a firmware setting presents one as 01.06.
const RST_RAID_IDS: [(u16, u16); 3] = [(0x8086, 0x2822), (0x8086, 0x282a), (0x8086, 0x2826)];

const REG_CAP: u64 = 0x00;
const REG_GHC: u64 = 0x04;
const REG_PI: u64 = 0x0c;
const REG_VS: u64 = 0x10;
const REG_CAP2: u64 = 0x24;
const REG_BOHC: u64 = 0x28;
const PORT_BASE: u64 = 0x100;
const PORT_STRIDE: u64 = 0x80;
const PX_CLB: u64 = 0x00;
const PX_CLBU: u64 = 0x04;
const PX_FB: u64 = 0x08;
const PX_FBU: u64 = 0x0c;
const PX_IS: u64 = 0x10;
const PX_CMD: u64 = 0x18;
const PX_TFD: u64 = 0x20;
const PX_SIG: u64 = 0x24;
const PX_SSTS: u64 = 0x28;
const PX_SERR: u64 = 0x30;
const PX_CI: u64 = 0x38;
const PX_FBS: u64 = 0x40;

const GHC_AE: u32 = 1 << 31;
const CAP_SSS: u32 = 1 << 27;
const CAP2_BOH: u32 = 1;
const BOHC_BOS: u32 = 1;
const CMD_ST: u32 = 1;
const CMD_SUD: u32 = 1 << 1;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;
const FBS_EN: u32 = 1;
const TFD_ERR: u32 = 1;
const TFD_DRQ: u32 = 1 << 3;
const TFD_BSY: u32 = 1 << 7;
const IS_TFES: u32 = 1 << 30;
const SIG_ATA: u32 = 0x0000_0101;
const SIG_ATAPI: u32 = 0xeb14_0101;
const ATA_IDENTIFY_DEVICE: u8 = 0xec;
/// Ticks (~1 ms) for a port engine to stop, and for IDENTIFY (a drive may
/// spin up before it answers).
const STOP_TICKS: u64 = 600;
const COMMAND_TICKS: u64 = 10_000;
/// TSC cycles allowed per tick of bound when the PIT itself is dead: about
/// ten milliseconds at 3.4 GHz, so the backstop is roughly ten times the
/// tick bound.
const TSC_PER_TICK_BACKSTOP: u64 = 1 << 25;
const MAX_PORTS: u64 = 32;

#[repr(C, align(1024))]
struct CommandList([u8; 1024]);
#[repr(C, align(256))]
struct ReceivedFis([u8; 256]);
#[repr(C, align(128))]
struct CommandTable([u8; 256]);
#[repr(C, align(4096))]
struct Data([u8; 4096]);

static mut COMMAND_LIST: CommandList = CommandList([0; 1024]);
static mut RECEIVED_FIS: ReceivedFis = ReceivedFis([0; 256]);
static mut COMMAND_TABLE: CommandTable = CommandTable([0; 256]);
static mut DATA: Data = Data([0; 4096]);
/// Set when a port engine was not shown quiescent after it had the static
/// buffers: no later IDENTIFY, on any controller, uses them.
static BUFFERS_RETIRED: AtomicBool = AtomicBool::new(false);
/// The stuck-stop fixture (`ahci-census-pretend-stuck-stop`): the first
/// IDENTIFY's post-command stop is treated as failed, so QEMU, whose engine
/// always stops, exercises the fail-closed path. Consumed once.
static PRETEND_STUCK_STOP: AtomicBool = AtomicBool::new(false);

#[derive(Default)]
pub struct Totals {
    pub controllers: u64,
    pub refused: u64,
    pub ports: u64,
    pub ports_refused: u64,
    pub ata: u64,
    pub atapi: u64,
    pub present_unprobed: u64,
    pub identified: u64,
    pub commands: u64,
    pub stop_failures: u64,
}

fn out(s: &str) {
    serial::write(s)
}
fn dec(v: u64) {
    serial::decimal(v)
}
fn hex(v: u64, digits: u32) {
    out("0x");
    serial::hex_digits(v, digits)
}
fn bdf(f: pci::Function) {
    serial::hex_digits(u64::from(f.bus), 2);
    out(":");
    serial::hex_digits(u64::from(f.device), 2);
    out(".");
    dec(u64::from(f.function));
}
fn ids(f: pci::Function) {
    let (vendor, device) = pci::ids(f);
    serial::hex_digits(u64::from(vendor), 4);
    out(":");
    serial::hex_digits(u64::from(device), 4);
}
fn class(f: pci::Function) {
    let value = pci::read32(f, 0x08);
    for (shift, sep) in [(24u32, "="), (16, "."), (8, ".")] {
        out(sep);
        serial::hex_digits(u64::from((value >> shift) & 0xff), 2);
    }
}
fn quoted(bytes: &[u8]) {
    out("\"");
    for &b in bytes {
        let c = [if (0x20..0x7f).contains(&b) && b != b'"' {
            b
        } else {
            b'?'
        }];
        out(core::str::from_utf8(&c).unwrap_or("?"));
    }
    out("\"");
}

fn ticks() -> u64 {
    crate::timer_ticks.load(core::sync::atomic::Ordering::Relaxed)
}
fn tsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

struct Hba {
    registers: u64,
    size: u64,
}
impl Hba {
    fn read(&self, offset: u64) -> u32 {
        unsafe { core::ptr::read_volatile((self.registers + offset) as *const u32) }
    }
    fn write(&self, offset: u64, value: u32) {
        unsafe { core::ptr::write_volatile((self.registers + offset) as *mut u32, value) }
    }
    fn port(&self, index: u64, offset: u64) -> u64 {
        PORT_BASE + index * PORT_STRIDE + offset
    }
    /// Polls `offset` until `(value & mask) == want`, with interrupts enabled
    /// so the tick bound advances (the boot timer probe left them off) and a
    /// TSC backstop in case the PIT is dead; interrupts are off again on
    /// return, as before. INTx of this function is masked; only IRQ0 and
    /// IRQ4 are unmasked at the 8259.
    fn wait(&self, offset: u64, mask: u32, want: u32, bound: u64) -> bool {
        let start = ticks();
        let start_tsc = tsc();
        let backstop = bound.saturating_mul(TSC_PER_TICK_BACKSTOP);
        unsafe { core::arch::asm!("sti", options(nostack, preserves_flags)) };
        let ok = loop {
            if self.read(offset) & mask == want {
                break true;
            }
            if ticks().wrapping_sub(start) > bound || tsc().wrapping_sub(start_tsc) > backstop {
                break false;
            }
            core::hint::spin_loop();
        };
        unsafe { core::arch::asm!("cli", options(nostack, preserves_flags)) };
        ok
    }
}

/// The census entry: every controller, every port, then a summary.
pub fn census(pretend_raid: bool, pretend_stuck_stop: bool) -> Totals {
    PRETEND_STUCK_STOP.store(pretend_stuck_stop, Ordering::Relaxed);
    let mut totals = Totals::default();
    let mut functions: [Option<pci::Function>; 8] = [None; 8];
    let mut count = 0usize;
    pci::each(|function| {
        let value = pci::read32(function, 0x08);
        let (class_code, subclass) = ((value >> 24) as u8, (value >> 16) as u8);
        if class_code == CLASS_MASS_STORAGE
            && (subclass == SUBCLASS_RAID || subclass == SUBCLASS_SATA)
            && count < functions.len()
        {
            functions[count] = Some(function);
            count += 1;
        }
    });
    if count == 0 {
        out("AHCI CENSUS none (no PCI class 01.06 SATA or 01.04 RAID function)\n");
    }
    for (index, function) in functions[..count].iter().flatten().enumerate() {
        let value = pci::read32(*function, 0x08);
        let (subclass, interface) = ((value >> 16) as u8, (value >> 8) as u8);
        let rst = RST_RAID_IDS.contains(&pci::ids(*function));
        let raid = subclass == SUBCLASS_RAID || rst || (pretend_raid && index == 0);
        if raid {
            out("AHCI CENSUS controller=");
            bdf(*function);
            out(" ");
            ids(*function);
            out(" class");
            class(*function);
            out(
                " mode=raid REFUSED firmware RAID owns these disks: ports not probed, no register touched, no command issued",
            );
            if rst && subclass != SUBCLASS_RAID {
                out(" by=device-id");
            }
            if pretend_raid && subclass != SUBCLASS_RAID && !rst {
                out(" fixture=pretend-raid");
            }
            out("\n");
            totals.refused += 1;
            continue;
        }
        if interface != INTERFACE_AHCI {
            out("AHCI CENSUS controller=");
            bdf(*function);
            out(" ");
            ids(*function);
            out(" class");
            class(*function);
            out(" mode=sata-non-ahci REFUSED not an AHCI programming interface\n");
            totals.refused += 1;
            continue;
        }
        controller(*function, &mut totals);
    }
    out("AHCI CENSUS OK controllers=");
    dec(totals.controllers);
    out(" refused=");
    dec(totals.refused);
    out(" ports=");
    dec(totals.ports);
    out(" ports_refused=");
    dec(totals.ports_refused);
    out(" ata=");
    dec(totals.ata);
    out(" atapi=");
    dec(totals.atapi);
    out(" present_unprobed=");
    dec(totals.present_unprobed);
    out(" identified=");
    dec(totals.identified);
    out(" commands=");
    dec(totals.commands);
    out(" (IDENTIFY DEVICE only) writes=0\n");
    out(
        "AHCI CENSUS COMPLETE no device written; probed ports returned to the firmware's command list and FIS base with ST/FRE off",
    );
    if totals.stop_failures != 0 {
        out(" except ");
        dec(totals.stop_failures);
        out(
            " whose engine was not shown quiescent: its controller's walk stopped there with bus mastering off at once, \
             its bases untouched if the stop failed before IDENTIFY or left on the census buffers if after",
        );
        if BUFFERS_RETIRED.load(Ordering::Relaxed) {
            out(" (census DMA buffers retired)");
        }
    }
    out("; PCI command left with memory decode on, INTx masked, bus mastering off\n");
    totals
}

fn controller(function: pci::Function, totals: &mut Totals) {
    out("AHCI CENSUS controller=");
    bdf(function);
    out(" ");
    ids(function);
    out(" class");
    class(function);
    if let Err(error) = pci::claim(function, "ahci-census") {
        out(" REFUSED claim ");
        out(match error {
            pci::ClaimError::Owned(owner) => owner,
            pci::ClaimError::Full => "owner table full",
        });
        out("\n");
        totals.refused += 1;
        return;
    }
    let bar = match pci::memory_bar(function, ABAR) {
        Ok(bar) => bar,
        Err(_) => {
            out(" REFUSED ABAR (BAR5) is not an assigned memory BAR\n");
            totals.refused += 1;
            return;
        }
    };
    let size = pci::memory_bar_size(function, ABAR).unwrap_or(0);
    if size < PORT_BASE + PORT_STRIDE {
        out(" abar=");
        hex(bar, 16);
        out(" REFUSED ABAR too small for one port (");
        hex(size, 8);
        out(" bytes)\n");
        totals.refused += 1;
        return;
    }
    let registers = match mmio::map(bar, size, mmio::Cache::Uncached) {
        Ok(registers) => registers,
        Err(_) => {
            out(" REFUSED ABAR ");
            hex(bar, 16);
            out(" could not be mapped\n");
            totals.refused += 1;
            return;
        }
    };
    pci::enable_memory(function);
    let hba = Hba { registers, size };
    let cap = hba.read(REG_CAP);
    let cap2 = hba.read(REG_CAP2);
    let bohc = if cap2 & CAP2_BOH != 0 {
        Some(hba.read(REG_BOHC))
    } else {
        None
    };
    let version = hba.read(REG_VS);
    let pi = hba.read(REG_PI);
    let ghc = hba.read(REG_GHC);
    let ports_max = u64::from((cap & 0x1f) + 1);
    out(" abar=");
    hex(bar, 16);
    out(" abar_bytes=");
    hex(size, 8);
    out(" version=");
    dec(u64::from(version >> 16));
    out(".");
    dec(u64::from((version >> 8) & 0xff));
    out(".");
    dec(u64::from(version & 0xff));
    out(" cap=");
    hex(u64::from(cap), 8);
    out(" ports_implemented=");
    hex(u64::from(pi), 8);
    out(" np=");
    dec(ports_max);
    out(" ncs=");
    dec(u64::from(((cap >> 8) & 0x1f) + 1));
    out(if cap & (1 << 31) != 0 {
        " s64a=yes"
    } else {
        " s64a=no"
    });
    out(if cap & CAP_SSS != 0 {
        " sss=yes"
    } else {
        " sss=no"
    });
    match bohc {
        None => out(" bohc=none"),
        Some(value) => {
            out(" bohc=");
            hex(u64::from(value), 8);
        }
    }
    if bohc.is_some_and(|value| value & BOHC_BOS != 0) {
        out(" REFUSED firmware owns the HBA (BOHC.BOS): ports not probed\n");
        totals.refused += 1;
        return;
    }
    if ghc & GHC_AE == 0 {
        // Firmware left AHCI mode off; turning it on is a mode change this
        // census does not make on a preserve-only machine.
        out(" ahci_enable=no REFUSED firmware left AHCI mode off (GHC.AE=0): ports not probed\n");
        totals.refused += 1;
        return;
    }
    out(" ahci_enable=yes\n");
    totals.controllers += 1;
    // Bus mastering only now, for the one IDENTIFY DMA per port into
    // kernel memory; off again after the walk.
    pci::enable_polled_dma(function);
    for index in 0..MAX_PORTS {
        if pi & (1 << index) == 0 {
            continue;
        }
        totals.ports += 1;
        if index >= ports_max || hba.port(index, PORT_STRIDE) > hba.size {
            out("AHCI PORT ");
            dec(index);
            out(" REFUSED implemented bit beyond CAP.NP or the ABAR: not read\n");
            totals.ports_refused += 1;
            continue;
        }
        if let Some((stop, stage)) = port(&hba, cap, index, totals) {
            // Fail closed: no further port of this controller, bus mastering
            // off before anything else (survey_facts::ahci_after_stop).
            let action = facts::ahci_after_stop(stop);
            if action.disable_bus_master_now {
                pci::disable_dma(function);
            }
            // Diagnostics only after the containment above.
            out(" identify=FAILED ");
            out(stage);
            out("\n");
            totals.stop_failures += 1;
            totals.refused += 1;
            out("AHCI CENSUS controller=");
            bdf(function);
            out(" REFUSED port ");
            dec(index);
            out(" engine not shown quiescent (");
            out(stage);
            out("): walk stopped, bus mastering off, ");
            out(if stop == facts::AhciStop::FailedAfterCommand {
                "bases left on the census buffers, census DMA buffers retired"
            } else {
                "bases untouched"
            });
            out(", remaining ports not probed\n");
            break;
        }
    }
    pci::disable_dma(function);
}

/// Reports one port; Some when its engine was not shown quiescent, which
/// ends the controller's walk.
fn port(
    hba: &Hba,
    cap: u32,
    index: u64,
    totals: &mut Totals,
) -> Option<(facts::AhciStop, &'static str)> {
    let ssts = hba.read(hba.port(index, PX_SSTS));
    let sig = hba.read(hba.port(index, PX_SIG));
    let cmd = hba.read(hba.port(index, PX_CMD));
    let fbs = hba.read(hba.port(index, PX_FBS));
    let det = ssts & 0xf;
    let spd = (ssts >> 4) & 0xf;
    let ipm = (ssts >> 8) & 0xf;
    out("AHCI PORT ");
    dec(index);
    out(" det=");
    dec(u64::from(det));
    out(" spd=");
    out(match spd {
        1 => "gen1",
        2 => "gen2",
        3 => "gen3",
        0 => "none",
        _ => "other",
    });
    out(" ipm=");
    let ipm_name = match ipm {
        0 => "none",
        1 => "active",
        2 => "partial",
        6 => "slumber",
        8 => "devsleep",
        _ => "other",
    };
    out(ipm_name);
    out(" sig=");
    hex(u64::from(sig), 8);
    match det {
        0 if cap & CAP_SSS != 0 && cmd & CMD_SUD == 0 => {
            out(" not-spun-up (staggered spin-up, SUD=0) identify=skipped\n");
            totals.present_unprobed += 1;
            return None;
        }
        0 => {
            out(" no-device\n");
            return None;
        }
        1 => {
            out(" phy-offline (device presence detected, no communication) identify=skipped\n");
            totals.present_unprobed += 1;
            return None;
        }
        3 => {}
        _ => {
            out(" phy-offline (BIST or unknown DET) identify=skipped\n");
            totals.present_unprobed += 1;
            return None;
        }
    }
    if ipm != 1 {
        out(" device-present link=");
        out(ipm_name);
        out(" identify=skipped (link in low power; no wake issued)\n");
        totals.present_unprobed += 1;
        return None;
    }
    if fbs & FBS_EN != 0 {
        out(" device-present REFUSED FIS-based switching enabled (PxFBS.EN): identify=skipped\n");
        totals.ports_refused += 1;
        return None;
    }
    match sig {
        SIG_ATAPI => {
            totals.atapi += 1;
            out(" atapi identify=skipped (no PACKET command issued)\n");
        }
        SIG_ATA => {
            totals.ata += 1;
            out(" ata");
            if BUFFERS_RETIRED.load(Ordering::Relaxed) {
                out(" identify=skipped (census DMA buffers retired after a failed engine stop)\n");
                totals.present_unprobed += 1;
                return None;
            }
            match identify(hba, index) {
                Ok(words) => {
                    totals.commands += 1;
                    if facts::ata_identify_incomplete(&words) {
                        out(" identify=incomplete (word 0 bit 2: power-up in standby)\n");
                        return None;
                    }
                    totals.identified += 1;
                    let (model, serial, firmware) = facts::ata_identify_strings(&words);
                    out(" model=");
                    quoted(model);
                    out(" serial=");
                    quoted(serial);
                    out(" firmware=");
                    quoted(firmware);
                    out(" sectors=");
                    dec(facts::ata_identify_sectors(&words));
                    out(if facts::ata_identify_lba48(&words) {
                        " lba48=yes"
                    } else {
                        " lba48=no"
                    });
                    out(" logical_sector=");
                    match facts::ata_identify_logical_sector_bytes(&words) {
                        Some(bytes) => dec(u64::from(bytes)),
                        None => out("invalid"),
                    }
                    out(" rotation=");
                    match facts::ata_identify_rotation(&words) {
                        facts::Rotation::NonRotating => out("solid-state"),
                        facts::Rotation::Rpm(rpm) => dec(u64::from(rpm)),
                        facts::Rotation::Unknown => out("unknown"),
                    }
                    out(" identify=ok\n");
                }
                Err((stage, counted, stop)) => {
                    if counted {
                        totals.commands += 1;
                    }
                    if stop != facts::AhciStop::Quiescent {
                        // The caller turns bus mastering off before it
                        // prints this port's failure or anything else.
                        return Some((stop, stage));
                    }
                    out(" identify=FAILED ");
                    out(stage);
                    out("\n");
                }
            }
        }
        _ => {
            out(" unknown-signature identify=skipped\n");
            totals.present_unprobed += 1;
        }
    }
    None
}

/// One IDENTIFY DEVICE on `index`: stop the port's engine, point it at the
/// kernel's command list and FIS area, run the command, stop the engine
/// again and, only if it stopped, restore the firmware's bases. Err carries
/// the stage that failed, whether a command was issued, and whether the
/// engines were shown quiescent (`survey_facts::ahci_after_stop` decides the
/// rest: a failed stop before the command leaves the bases untouched, one
/// after it leaves them on the census buffers and retires those buffers).
fn identify(hba: &Hba, index: u64) -> Result<[u16; 256], (&'static str, bool, facts::AhciStop)> {
    let cmd = hba.port(index, PX_CMD);
    let saved_clb = (
        hba.read(hba.port(index, PX_CLB)),
        hba.read(hba.port(index, PX_CLBU)),
    );
    let saved_fb = (
        hba.read(hba.port(index, PX_FB)),
        hba.read(hba.port(index, PX_FBU)),
    );
    let saved_cmd = hba.read(cmd);
    // Stop: ST off, wait CR; FRE off, wait FR.
    hba.write(cmd, saved_cmd & !CMD_ST);
    if !hba.wait(cmd, CMD_CR, 0, STOP_TICKS) {
        return Err((
            "port engine did not stop (CR); bases untouched",
            false,
            facts::AhciStop::FailedBeforeCommand,
        ));
    }
    hba.write(cmd, hba.read(cmd) & !CMD_FRE);
    if !hba.wait(cmd, CMD_FR, 0, STOP_TICKS) {
        return Err((
            "FIS receive did not stop (FR); bases untouched",
            false,
            facts::AhciStop::FailedBeforeCommand,
        ));
    }
    let list = core::ptr::addr_of_mut!(COMMAND_LIST) as u64;
    let fis = core::ptr::addr_of_mut!(RECEIVED_FIS) as u64;
    let table = core::ptr::addr_of_mut!(COMMAND_TABLE) as u64;
    let data = core::ptr::addr_of_mut!(DATA) as u64;
    unsafe {
        (*core::ptr::addr_of_mut!(COMMAND_LIST)).0.fill(0);
        (*core::ptr::addr_of_mut!(RECEIVED_FIS)).0.fill(0);
        (*core::ptr::addr_of_mut!(COMMAND_TABLE)).0.fill(0);
        (*core::ptr::addr_of_mut!(DATA)).0.fill(0);
    }
    // Command header 0: CFL = 5 dwords, PRDTL = 1, CTBA = table.
    let header = list as *mut u32;
    unsafe {
        header.write_volatile(5 | (1 << 16));
        header.add(1).write_volatile(0);
        header.add(2).write_volatile(table as u32);
        header.add(3).write_volatile((table >> 32) as u32);
    }
    // Register H2D FIS: type 0x27, C=1, command IDENTIFY DEVICE, device 0.
    let cfis = table as *mut u8;
    unsafe {
        cfis.write_volatile(0x27);
        cfis.add(1).write_volatile(1 << 7);
        cfis.add(2).write_volatile(ATA_IDENTIFY_DEVICE);
        cfis.add(7).write_volatile(0);
    }
    // PRDT entry 0 at table + 0x80: DBA = data, DBC = 511 (512 bytes).
    let prdt = (table + 0x80) as *mut u32;
    unsafe {
        prdt.write_volatile(data as u32);
        prdt.add(1).write_volatile((data >> 32) as u32);
        prdt.add(2).write_volatile(0);
        prdt.add(3).write_volatile(511);
    }
    hba.write(hba.port(index, PX_CLB), list as u32);
    hba.write(hba.port(index, PX_CLBU), (list >> 32) as u32);
    hba.write(hba.port(index, PX_FB), fis as u32);
    hba.write(hba.port(index, PX_FBU), (fis >> 32) as u32);
    hba.write(hba.port(index, PX_SERR), u32::MAX);
    hba.write(hba.port(index, PX_IS), u32::MAX);
    hba.write(cmd, hba.read(cmd) | CMD_FRE);
    let result = (|| {
        // BSY and DRQ must be clear before ST is set (AHCI 1.3 §10.3.1).
        if !hba.wait(hba.port(index, PX_TFD), TFD_BSY | TFD_DRQ, 0, STOP_TICKS) {
            return Err((
                "device busy before the command (TFD)",
                false,
                facts::AhciStop::Quiescent,
            ));
        }
        hba.write(cmd, hba.read(cmd) | CMD_ST);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        hba.write(hba.port(index, PX_CI), 1);
        if !hba.wait(hba.port(index, PX_CI), 1, 0, COMMAND_TICKS) {
            return Err((
                "IDENTIFY did not complete within the bound",
                true,
                facts::AhciStop::Quiescent,
            ));
        }
        let is = hba.read(hba.port(index, PX_IS));
        let tfd = hba.read(hba.port(index, PX_TFD));
        if is & IS_TFES != 0 || tfd & TFD_ERR != 0 {
            return Err((
                "IDENTIFY reported an error (TFES/ERR)",
                true,
                facts::AhciStop::Quiescent,
            ));
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        let mut words = [0u16; 256];
        let bytes = core::ptr::addr_of!(DATA) as *const u8;
        for (i, word) in words.iter_mut().enumerate() {
            let pair = unsafe {
                [
                    bytes.add(2 * i).read_volatile(),
                    bytes.add(2 * i + 1).read_volatile(),
                ]
            };
            *word = u16::from_le_bytes(pair);
        }
        Ok(words)
    })();
    // Stop again; only an engine shown quiescent gets its firmware bases back.
    hba.write(cmd, hba.read(cmd) & !CMD_ST);
    let stopped = hba.wait(cmd, CMD_CR, 0, STOP_TICKS);
    hba.write(cmd, hba.read(cmd) & !CMD_FRE);
    let stopped = stopped && hba.wait(cmd, CMD_FR, 0, STOP_TICKS);
    let stopped = stopped && !PRETEND_STUCK_STOP.swap(false, Ordering::Relaxed);
    let stop = if stopped {
        facts::AhciStop::Quiescent
    } else {
        facts::AhciStop::FailedAfterCommand
    };
    let action = facts::ahci_after_stop(stop);
    if action.restore_bases {
        hba.write(hba.port(index, PX_CLB), saved_clb.0);
        hba.write(hba.port(index, PX_CLBU), saved_clb.1);
        hba.write(hba.port(index, PX_FB), saved_fb.0);
        hba.write(hba.port(index, PX_FBU), saved_fb.1);
        hba.write(cmd, saved_cmd & !(CMD_ST | CMD_FRE));
    }
    if !action.buffers_reusable {
        BUFFERS_RETIRED.store(true, Ordering::Relaxed);
    }
    match result {
        Ok(words) if stopped => Ok(words),
        Ok(_) => Err((
            "engine did not stop after IDENTIFY; bases not restored, data discarded",
            true,
            stop,
        )),
        Err((stage, counted, _)) if !stopped => Err((stage, counted, stop)),
        Err(error) => Err(error),
    }
}
