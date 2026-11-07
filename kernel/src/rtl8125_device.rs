//! Opt-in RTL8125B bring-up entries (docs/RTL8125.md), coordination record #109.
//! Each `rtl8125-*` entry is a separate boot mode that runs on the BSP
//! before storage, SMP or user space, reports on serial and ends the boot.
//! The `net-rtl8125` NIC (end of this file) is the only path `nic_device`
//! reaches; no default boot reaches this file.
//!
//! Every path follows the same stages. Before the chip is identified as a
//! supported 8125B only the PCI-side fence is touched (Codex 4). Bus
//! mastering is set only inside the declared externally contained envelope
//! (`rtl8125_pci::containment`: a KVM guest on q35; #111, re-review 2) and
//! with PCIe Relaxed Ordering and No Snoop disabled (`rtl8125_pci::
//! ordering`, re-review 3). Once armed, DMA memory never goes back to the
//! kernel: every release leaves it quarantined for the boot
//! (`rtl8125_ring::Custody`, re-review 2). After a confirmed stop and fence
//! the diagnostic modes read status words, and buffers only of descriptors
//! the chip handed back. A stop and fence is attempted on `exit_qemu`/halt
//! (`shutdown`, review F4).

use crate::{mmio, pci};
use absd_kernel::amdvi::{self, scope::Driver};
use absd_kernel::dma_policy;
use absd_kernel::rtl8125::{self, Identity, Io};
use absd_kernel::rtl8125_pci;
use absd_kernel::rtl8125_ring::{self as ring, Port};
use core::fmt::Write;

const BUS_MASTER: u16 = 1 << 2;
const MEMORY: u16 = 1 << 1;
const INTX_DISABLE: u16 = 1 << 10;

#[allow(dead_code)] // Nested refusal details are emitted through Debug.
#[derive(Clone, Copy, Debug)]
pub enum Error {
    Absent,
    /// A `dma-contain` boot could not take this function.
    NotContained,
    /// Outside the declared externally contained envelope: no DMA.
    Uncontained(rtl8125_pci::Uncontained),
    /// The run harness did not confirm the physical Device Control.
    PhysicalCheck(Go),
    QualificationOnly,
    AlreadyAttempted,
    Pci(rtl8125_pci::Refusal),
    Claim(pci::ClaimError),
    /// Bus mastering did not read back clear after the fencing write.
    BusMaster,
    Map(mmio::MapError),
    Chip(rtl8125::Error),
}

pub struct Log;
impl Write for Log {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        crate::serial::write(text);
        Ok(())
    }
}

pub struct Mac(pub [u8; 6]);
impl core::fmt::Display for Mac {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let m = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    }
}

#[derive(Clone, Copy)]
struct Registers {
    base: u64,
}
impl Registers {
    fn at(&self, offset: u32, width: u64) -> u64 {
        debug_assert!(
            u64::from(offset) % width == 0
                && u64::from(offset) + width <= rtl8125_pci::REGISTER_BYTES
        );
        self.base + u64::from(offset)
    }
}
impl Io for Registers {
    fn read8(&mut self, offset: u32) -> u8 {
        unsafe { core::ptr::read_volatile(self.at(offset, 1) as *const u8) }
    }
    fn read16(&mut self, offset: u32) -> u16 {
        unsafe { core::ptr::read_volatile(self.at(offset, 2) as *const u16) }
    }
    fn read32(&mut self, offset: u32) -> u32 {
        unsafe { core::ptr::read_volatile(self.at(offset, 4) as *const u32) }
    }
    fn write8(&mut self, offset: u32, value: u8) {
        unsafe { core::ptr::write_volatile(self.at(offset, 1) as *mut u8, value) }
    }
    fn write16(&mut self, offset: u32, value: u16) {
        unsafe { core::ptr::write_volatile(self.at(offset, 2) as *mut u16, value) }
    }
    fn write32(&mut self, offset: u32, value: u32) {
        unsafe { core::ptr::write_volatile(self.at(offset, 4) as *mut u32, value) }
    }
    fn delay_ms(&mut self, ms: u32) -> bool {
        crate::i219_device::delay_ms(ms)
    }
}

static mut ATTEMPTED: bool = false;

/// Boot options shared by every RTL8125 entry (set once, before the entry).
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// rge's fixed 8125B PHY constants (`rtl8125-no-phy-tuning` clears it).
    pub phy_tuning: bool,
    /// Seconds `rtl8125-phy` holds the link (`rtl8125-hold=`).
    pub hold_s: u32,
    /// Extra wire passes of 16 frames (`rtl8125-wire-passes=`); 0 = one
    /// batch of 8 frames, the original wire mode.
    pub wire_passes: u32,
}
static mut OPTIONS: Options = Options {
    phy_tuning: true,
    hold_s: 45,
    wire_passes: 0,
};
pub fn set_options(options: Options) {
    unsafe { *core::ptr::addr_of_mut!(OPTIONS) = options }
    let _ = writeln!(Log, "RTL8125 OPTIONS {options:?}");
}
fn options() -> Options {
    unsafe { *core::ptr::addr_of!(OPTIONS) }
}

/// The admitted, claimed and mapped function with bus mastering off.
struct Device {
    function: pci::Function,
    io: Registers,
    admitted: rtl8125_pci::Admitted,
    /// ABSD turned memory decode on and must turn it off at release.
    decode_ours: bool,
}

fn command(function: pci::Function) -> u16 {
    pci::read32(function, 4) as u16
}
/// Writes the command half only; zeros into status keep its RW1C bits.
fn set_command(function: pci::Function, value: u16) {
    pci::write32(function, 4, u32::from(value));
}

/// Admission, claim, the bus-master fence and the mapping, in that order.
/// Bus mastering is cleared (and must read back clear) before the first
/// MMIO access; INTx is masked; nothing else in config space is written.
fn open() -> Result<Device, Error> {
    crate::kernel_lock::assert_bsp_device_access();
    if crate::smp_user::enabled() || crate::smp_startup::enabled() {
        return Err(Error::QualificationOnly);
    }
    if unsafe { *core::ptr::addr_of!(ATTEMPTED) } {
        return Err(Error::AlreadyAttempted);
    }
    unsafe {
        *core::ptr::addr_of_mut!(ATTEMPTED) = true;
    }
    // A `dma-contain` boot takes the named function, never the first match.
    let function = if crate::contain::active() {
        crate::contain::named(Driver::Rtl8125)
            .filter(|&f| pci::ids(f) == (rtl8125_pci::VENDOR, rtl8125_pci::DEVICE))
            .ok_or(Error::Absent)?
    } else {
        pci::find_id(rtl8125_pci::VENDOR, rtl8125_pci::DEVICE).ok_or(Error::Absent)?
    };
    let admitted =
        rtl8125_pci::admit(|offset| pci::read32(function, offset)).map_err(Error::Pci)?;
    let _ = writeln!(
        Log,
        "RTL8125 PCI {:02x}:{:02x}.{} id=10ec:8125 rev={:02x} bar2={:#x} command={:04x}",
        function.bus,
        function.device,
        function.function,
        admitted.revision,
        admitted.bar,
        admitted.command
    );
    pci::claim(function, "rtl8125").map_err(Error::Claim)?;
    // Design section 5, steps 1 to 3, before the fence: it would hide what
    // firmware left. The DTE stays blocked throughout.
    if crate::contain::active() && !crate::contain::take(Driver::Rtl8125, function) {
        return Err(Error::NotContained);
    }
    let decode_ours = admitted.command & MEMORY == 0;
    let fenced = (admitted.command & !BUS_MASTER) | MEMORY | INTX_DISABLE;
    set_command(function, fenced);
    if command(function) & BUS_MASTER != 0 {
        return Err(Error::BusMaster);
    }
    let _ = writeln!(
        Log,
        "RTL8125 FENCE bus_master_inherited={} bus_master=0 decode_inherited={} command={:04x}",
        u8::from(admitted.command & BUS_MASTER != 0),
        u8::from(!decode_ours),
        command(function)
    );
    let base = mmio::map(
        admitted.bar,
        rtl8125_pci::REGISTER_BYTES,
        mmio::Cache::Uncached,
    )
    .map_err(Error::Map)?;
    Ok(Device {
        function,
        io: Registers { base },
        admitted,
        decode_ours,
    })
}

/// What CPUID and 00:00.0 say about where this boot runs (CPUID is read by
/// `Envelope::probe` in the library; only the host bridge comes from here).
fn envelope() -> rtl8125_pci::Envelope {
    let host_bridge = pci::read32(
        pci::Function {
            bus: 0,
            device: 0,
            function: 0,
        },
        0,
    );
    rtl8125_pci::Envelope::probe(host_bridge)
}

/// Why the physical-check handshake did not give a go.
#[allow(dead_code)] // Emitted through Debug.
#[derive(Clone, Copy, Debug)]
pub enum Go {
    /// No UART at COM2 (LSR reads all ones): no harness attached.
    NoChannel,
    /// No byte within the bound.
    Timeout,
    /// The harness answered something other than `G` (it sends `N` when
    /// the physical register still shows Relaxed Ordering or No Snoop).
    Refused(u8),
    TimerUnavailable,
}

const COM2: u16 = 0x2f8;
/// How long the guest waits for the harness's answer.
const GO_WAIT_MS: u32 = 60_000;

/// The physical-check handshake (owner condition on #109, 6528357691).
/// Under VFIO the guest sees its own view of Device Control; the reference_host
/// harness reads the physical register (`setpci -s 02:00.0
/// CAP_EXP+8.w`) when it sees the line below, and answers `G` on COM2 only
/// if Relaxed Ordering and No Snoop are clear there. Bounded; anything but
/// `G` refuses DMA. Reads COM2's line status and data registers only.
///
/// This is trusted experimental apparatus, and the claim holds only for
/// that workflow (`tools/corrective/run-dma.sh`): a fresh, exclusive COM2
/// channel created for this one guest run, the correct helper
/// (`go-agent.py`), 02:00.0 being the function assigned to this guest, and
/// no other writer changing the host's configuration between the helper's
/// reading and the arm. The guest cannot tell a fresh `G` from a stale,
/// delayed or corrupted one: the message carries no request identity and
/// UART errors are not checked. Robustness against such a `G` is
/// unestablished (Codex final review).
fn physical_go(what: &str) -> Result<(), Error> {
    let lsr = || unsafe { crate::serial::inb(COM2 + 5) };
    if lsr() == 0xff {
        let _ = writeln!(Log, "RTL8125 DEVCTL PHYSICAL-CHECK {what} result=NoChannel");
        return Err(Error::PhysicalCheck(Go::NoChannel));
    }
    // Discard bytes already waiting. This is hygiene only: it does not
    // establish that a later byte answers this request (a delayed earlier
    // `G` could still arrive); freshness rests on the apparatus above.
    for _ in 0..16 {
        if lsr() & 1 == 0 {
            break;
        }
        let _ = unsafe { crate::serial::inb(COM2) };
    }
    let _ = writeln!(
        Log,
        "RTL8125 DEVCTL AWAITING-PHYSICAL-CHECK {what} channel=com2 wait_ms={GO_WAIT_MS}"
    );
    let mut waited = 0;
    let result = loop {
        if lsr() & 1 != 0 {
            match unsafe { crate::serial::inb(COM2) } {
                b'G' => break Ok(()),
                other => break Err(Go::Refused(other)),
            }
        }
        if waited >= GO_WAIT_MS {
            break Err(Go::Timeout);
        }
        if !crate::i219_device::delay_ms(10) {
            break Err(Go::TimerUnavailable);
        }
        waited += 10;
    };
    let _ = writeln!(
        Log,
        "RTL8125 DEVCTL PHYSICAL-CHECK {what} result={result:?} waited_ms={waited}"
    );
    result.map_err(Error::PhysicalCheck)
}

/// Before any DMA-mode chip work: the envelope, then Relaxed Ordering (and
/// No Snoop) disabled by a read-modify-write of Device Control with read
/// back (`rtl8125_pci::disable_ordering`; owner option 1 on #109), then the
/// harness's physical confirmation. `arm` re-reads Device Control again
/// right before bus mastering is set (`admit_dma`): nothing assumes the
/// bit survived a reset in between.
fn prepare_dma(what: &str, function: pci::Function) -> Result<(), Error> {
    if crate::contain::active() {
        // `take` corrected ordering. Under VFIO the guest's Device Control is
        // not the physical register, so the harness check stays there; on
        // bare metal the read-back is of the physical register.
        if core::arch::x86_64::__cpuid(1).ecx & (1 << 31) != 0 {
            physical_go(what)?;
        }
        return Ok(());
    }
    let found = envelope();
    if let Err(why) = rtl8125_pci::containment(&found) {
        let _ = writeln!(
            Log,
            "RTL8125 CONTAINMENT {what} hypervisor={} host_bridge={:08x} verdict=uncontained",
            u8::from(found.hypervisor()),
            found.host_bridge()
        );
        return Err(Error::Uncontained(why));
    }
    let change = rtl8125_pci::disable_ordering(
        |offset| pci::read32(function, offset),
        |offset, value| pci::write32(function, offset, value),
    );
    match change {
        Ok(c) => {
            let _ = writeln!(
                Log,
                "RTL8125 DEVCTL cleared guest_before={:#06x} guest_after={:#06x} written={} offset={:#04x} relaxed_ordering=0 no_snoop=0 (guest view)",
                c.before,
                c.after,
                u8::from(c.written),
                c.offset
            );
        }
        Err(why) => {
            let _ = writeln!(
                Log,
                "RTL8125 DEVCTL NOT-CLEARED {what} {why:?} (guest view)"
            );
            return Err(Error::Uncontained(why));
        }
    }
    physical_go(what)?;
    admit_dma(what, function).map(|_| ())
}

/// The DMA admission (#111, re-review 2): live DMA only inside the
/// declared envelope. Checks that a KVM guest on q35's compatibility
/// signals are observed (detected, not verified), not that the host IOMMU
/// confines the function. No option bypasses it.
fn admit_dma(what: &str, function: pci::Function) -> Result<dma_policy::VmEnvelopeObserved, Error> {
    let found = envelope();
    // PCIe Device Control as this boot reads it (re-review 3). Relaxed
    // Ordering or No Snoop refuses DMA; nothing is written. Under VFIO this
    // is the guest's view of the register: the host-side value is recorded
    // separately in the run evidence.
    let devctl = rtl8125_pci::express_device_control(|offset| pci::read32(function, offset));
    let verdict = rtl8125_pci::containment(&found)
        .and_then(|observed| devctl.and_then(rtl8125_pci::ordering).map(|()| observed));
    let _ = writeln!(
        Log,
        "RTL8125 CONTAINMENT {what} hypervisor={} vendor={:?} host_bridge={:08x} devctl={devctl:x?} relaxed_ordering={} no_snoop={} verdict={} checked=vm-envelope-and-guest-devctl vm-envelope=detected-not-verified host-iommu=declared-assumption-not-absd-enforcement",
        u8::from(found.hypervisor()),
        core::str::from_utf8(&found.vendor()).unwrap_or("?"),
        found.host_bridge(),
        devctl.map_or(9, |d| u8::from(
            d & rtl8125_pci::DEVCTL_RELAXED_ORDERING != 0
        )),
        devctl.map_or(9, |d| u8::from(d & rtl8125_pci::DEVCTL_NO_SNOOP != 0)),
        match verdict {
            Ok(_) => "inside",
            Err(_) => "uncontained",
        }
    );
    verdict.map_err(Error::Uncontained)
}

impl Device {
    /// The PCI-side fence and release: bus mastering off and memory decode
    /// as firmware left it. The only cleanup before the chip is identified.
    fn release(&self) -> u16 {
        let mut value = command(self.function) & !BUS_MASTER;
        if self.decode_ours {
            value &= !MEMORY;
        }
        set_command(self.function, value);
        let after = command(self.function);
        let _ = writeln!(
            Log,
            "RTL8125 RELEASE bus_master={} decode={} command={:04x} inherited={:04x}",
            u8::from(after & BUS_MASTER != 0),
            u8::from(after & MEMORY != 0),
            after,
            self.admitted.command
        );
        after
    }

    /// Identification, the first chip access. On refusal only the PCI-side
    /// fence is released: nothing 8125B-specific is written to a chip that
    /// is not known to be one (Codex 4).
    fn identify(&mut self, what: &str) -> Option<Identity> {
        match rtl8125::identify(&mut self.io) {
            Ok(id) => {
                report(&id);
                Some(id)
            }
            Err(error) => {
                let _ = writeln!(
                    Log,
                    "RTL8125 {what} REFUSED {error:?} cleanup=pci-fence-only"
                );
                self.release();
                None
            }
        }
    }

    /// Bus mastering on, recorded for `shutdown` first; true if it reads
    /// back set. Refused (bus mastering never set) outside the envelope.
    fn arm(&mut self) -> bool {
        if crate::contain::active() {
            return self.arm_contained();
        }
        let Ok(observed) = admit_dma("arm", self.function) else {
            return false;
        };
        let Some(next) = custody().arm() else {
            let _ = writeln!(Log, "RTL8125 ARM REFUSED custody={:?}", custody());
            return false;
        };
        set_custody(next);
        unsafe {
            *core::ptr::addr_of_mut!(ARMED) = Some((self.function, self.io));
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        // Bus Master Enable only through the dma seam (#111): `dma::arm`
        // decides from the declaration and sets the command bits from an
        // Armed token (memory decode and INTx disable are already set by
        // the fence, so the register ends as before).
        if crate::dma::arm_in_vm(self.function, &dma_policy::RTL8125, &observed).is_err() {
            let _ = writeln!(Log, "RTL8125 ARM REFUSED dma-seam=refused");
            return false;
        }
        let armed = command(self.function);
        let _ = writeln!(Log, "RTL8125 ARMED command={armed:04x}");
        armed & BUS_MASTER != 0
    }

    /// Design section 5, steps 5 and 6. Custody moves at exposure rather than
    /// at the arm: from here any release quarantines, armed or not.
    fn arm_contained(&mut self) -> bool {
        let Some(next) = custody().arm() else {
            let _ = writeln!(Log, "RTL8125 ARM REFUSED custody={:?}", custody());
            return false;
        };
        set_custody(next);
        unsafe {
            *core::ptr::addr_of_mut!(ARMED) = Some((self.function, self.io));
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        // Negative control: withhold the receive buffers from the domain.
        let grant = dma_grant();
        let granted = if cfg!(absd_mutant_rtl8125_no_rx_grant) {
            &grant[..ring::SURFACE.rx_buffers.0]
        } else {
            &grant[..]
        };
        if !crate::contain::expose(Driver::Rtl8125, self.function, granted)
            || !crate::contain::admit(Driver::Rtl8125, self.function)
        {
            return false;
        }
        if crate::dma::arm(self.function, &dma_policy::RTL8125_CONTAINED).is_err() {
            let _ = writeln!(Log, "RTL8125 ARM REFUSED dma-seam=refused");
            return false;
        }
        let armed = command(self.function);
        let _ = writeln!(Log, "RTL8125 ARMED command={armed:04x} containment=domain");
        armed & BUS_MASTER != 0
    }
}

/// The function and registers while bus mastering may be on.
static mut ARMED: Option<(pci::Function, Registers)> = None;

/// Stops an armed chip and fences bus mastering. Returns whether the chip
/// confirmed its stop (both FIFOs empty and idle, `rtl8125::settle`) and
/// bus mastering read back clear. Neither shows that writes the chip
/// already issued have landed, so armed memory becomes `Quarantined` for
/// the boot whatever this returns (re-review 2); it is never scrubbed or
/// given back.
fn disarm(function: pci::Function, io: &mut Registers, what: &str) -> bool {
    let stopped = rtl8125::quiesce(io);
    set_command(function, command(function) & !BUS_MASTER);
    let after = command(function);
    let master = after & BUS_MASTER != 0;
    let clean = stopped.is_ok() && !master;
    set_custody(custody().release(stopped.is_ok(), !master));
    if clean {
        unsafe { *core::ptr::addr_of_mut!(ARMED) = None };
    }
    // After exposure a stop ends the surface: registration gone, DTE blocked.
    crate::contain::retire(Driver::Rtl8125);
    let _ = writeln!(
        Log,
        "RTL8125 STOP {what} chip={stopped:?} bus_master={} custody={:?}",
        u8::from(master),
        custody()
    );
    clean
}

/// Called from `exit_qemu` (halt, panic, every mode's end): an armed chip
/// is stopped and fenced so it does not outlive the kernel that armed it
/// (review F4). Runs at most once, on the BSP only.
pub fn shutdown() {
    static mut DONE: bool = false;
    if crate::kernel_lock::active() && crate::cpu::id() != crate::kernel_lock::BSP {
        return;
    }
    unsafe {
        if *core::ptr::addr_of!(DONE) {
            return;
        }
        *core::ptr::addr_of_mut!(DONE) = true;
    }
    let Some((function, mut io)) = (unsafe { *core::ptr::addr_of!(ARMED) }) else {
        return;
    };
    let clean = disarm(function, &mut io, "at-exit");
    let _ = writeln!(
        Log,
        "RTL8125 SHUTDOWN attempted stop_confirmed_and_bus_master_clear={} (an attempt, not a guarantee: posted-write drain is not shown)",
        u8::from(clean)
    );
}

fn report(id: &Identity) {
    let _ = writeln!(
        Log,
        "RTL8125 CHIP {:?} txcfg={:08x} xid={:03x}",
        id.chip,
        id.txcfg,
        rtl8125::xid(id.txcfg)
    );
    let _ = writeln!(
        Log,
        "RTL8125 MAC idr={} permanent={} station=permanent",
        Mac(id.mac),
        Mac(id.permanent)
    );
    let _ = writeln!(
        Log,
        "RTL8125 PHY id={:08x} bmcr={:04x} bmsr={:04x} anar={:04x} phystat={:04x}",
        id.phy_id, id.bmcr, id.bmsr, id.anar, id.phystat
    );
    let _ = writeln!(
        Log,
        "RTL8125 STATE cmd={:02x} imr={:08x} rxcfg={:08x}",
        id.cmd, id.imr, id.rxcfg
    );
}

/// S1: identity by reads only, then release. Returns whether the device was
/// identified and released with bus mastering off.
pub fn probe() -> bool {
    let mut device = match open() {
        Ok(device) => device,
        Err(error) => {
            let _ = writeln!(Log, "RTL8125 PROBE REFUSED {error:?}");
            return false;
        }
    };
    if device.identify("PROBE").is_none() {
        return false;
    }
    let released = device.release() & BUS_MASTER == 0;
    let _ = writeln!(
        Log,
        "RTL8125 FIRMWARE loaded=none dma=never-enabled writes=ocp-read-commands-only"
    );
    if released {
        let _ = writeln!(Log, "RTL8125 PROBE OK");
    }
    released
}

fn speed_name(speed: rtl8125::Speed) -> &'static str {
    match speed {
        rtl8125::Speed::Down => "down",
        rtl8125::Speed::Mbps10 => "10",
        rtl8125::Speed::Mbps100 => "100",
        rtl8125::Speed::Mbps1000 => "1000",
        rtl8125::Speed::Mbps2500 => "2500",
        rtl8125::Speed::Unknown => "unknown",
    }
}

/// What `hold_link` saw: when BMSR first showed link, how often it changed
/// after that, and the last sample.
struct Held {
    up_at_ms: Option<u32>,
    changes: u32,
    last: rtl8125::CableLink,
}

/// Waits up to `seconds` for link (BMSR, `rtl8125::cable_link`), then holds
/// it for `hold` seconds so the link partner can be read, printing every
/// change and a line every 30 s. A stalled timer or a failed read is an
/// error, never a result (Codex 5). The speed printed is PHYSTAT's claim,
/// not an established speed: the partner's report is the evidence.
fn hold_link(io: &mut Registers, seconds: u32, hold: u32) -> Result<Held, rtl8125::Error> {
    let mut elapsed_ms = 0u32;
    let mut held = Held {
        up_at_ms: None,
        changes: 0,
        last: rtl8125::cable_link(io)?,
    };
    let mut first = true;
    loop {
        let deadline = match held.up_at_ms {
            Some(at) => at + hold * 1000,
            None => seconds * 1000,
        };
        if elapsed_ms >= deadline {
            return Ok(held);
        }
        let link = rtl8125::cable_link(io)?;
        if first || link.up != held.last.up || link.phystat_claim != held.last.phystat_claim {
            let _ = writeln!(
                Log,
                "RTL8125 LINK t_ms={elapsed_ms} up={} speed=unestablished phystat_claim={} phystat={:04x} bmsr={:04x}",
                u8::from(link.up),
                speed_name(link.phystat_claim),
                link.phystat,
                link.bmsr
            );
            if held.up_at_ms.is_some() && link.up != held.last.up {
                held.changes += 1;
            }
        }
        first = false;
        held.last = link;
        if link.up && held.up_at_ms.is_none() {
            held.up_at_ms = Some(elapsed_ms);
            let _ = writeln!(
                Log,
                "RTL8125 LINK UP t_ms={elapsed_ms} source=bmsr holding_s={hold}"
            );
        }
        if let Some(at) = held.up_at_ms
            && elapsed_ms > at
            && (elapsed_ms - at).is_multiple_of(30_000)
        {
            let _ = writeln!(
                Log,
                "RTL8125 LINK HOLD t_s={} up={} phystat={:04x} bmsr={:04x} changes={}",
                (elapsed_ms - at) / 1000,
                u8::from(link.up),
                link.phystat,
                link.bmsr,
                held.changes
            );
        }
        if !io.delay_ms(100) {
            let _ = writeln!(Log, "RTL8125 LINK WATCH timer unavailable");
            return Err(rtl8125::Error::TimerUnavailable);
        }
        elapsed_ms += 100;
    }
}

/// S2: rge's chip and PHY initialization without firmware, an explicit
/// 10/100/1000/2500 advertisement (no pause), then link observed through
/// BMSR and the chip stopped. Bus mastering stays off throughout. Returns
/// whether BMSR showed link, it held without change, the stop was clean and
/// bus mastering read back clear. The speed is not part of the verdict.
pub fn phy_link() -> bool {
    let mut device = match open() {
        Ok(device) => device,
        Err(error) => {
            let _ = writeln!(Log, "RTL8125 PHY REFUSED {error:?}");
            return false;
        }
    };
    if device.identify("PHY").is_none() {
        return false;
    }
    let result = (|| {
        let init = rtl8125::chip_init(&mut device.io)?;
        let _ = writeln!(Log, "RTL8125 INIT {init:?}");
        let _ = writeln!(
            Log,
            "RTL8125 FIRMWARE skipped=mac-mcu-patch mcu_break_points=cleared"
        );
        let rcode = rtl8125::phy_config(&mut device.io, options().phy_tuning)?;
        let _ = writeln!(
            Log,
            "RTL8125 FIRMWARE skipped=phy-ram-code-patch rcode={rcode:04x} patched_rcode={:04x} patch_present={}",
            rtl8125::PATCHED_RCODE,
            u8::from(rcode == rtl8125::PATCHED_RCODE)
        );
        let adv = rtl8125::advertise_all(&mut device.io)?;
        let _ = writeln!(
            Log,
            "RTL8125 ADVERTISED anar={:04x} gtcr={:04x} a5d4={:04x} pause=0",
            adv.anar, adv.gtcr, adv.adv_2500
        );
        hold_link(&mut device.io, 20, options().hold_s)
    })();
    // Bus mastering was never set; the chip is still stopped and checked.
    let stopped = rtl8125::settle(&mut device.io);
    let _ = writeln!(Log, "RTL8125 STOP {stopped:?}");
    let released = device.release() & BUS_MASTER == 0;
    match result {
        Ok(held) => {
            let _ = writeln!(Log, "RTL8125 FIRMWARE loaded=none dma=never-enabled");
            let up = held.up_at_ms.is_some() && held.last.up;
            let ok = up && held.changes == 0 && released && stopped.is_ok();
            let _ = writeln!(
                Log,
                "RTL8125 PHY {} link={} changes_after_up={} hold_s={} speed=unestablished phystat_claim={}",
                if ok { "OK" } else { "FAILED" },
                if up { "up" } else { "down" },
                held.changes,
                options().hold_s,
                speed_name(held.last.phystat_claim)
            );
            ok
        }
        Err(error) => {
            let _ = writeln!(Log, "RTL8125 PHY FAILED {error:?}");
            false
        }
    }
}

// ---- S3: MAC loopback (docs/RTL8125.md, "DMA custody") ----

const RING: usize = ring::TX_SLOTS;
const BUFFER: usize = ring::BUFFER;
const FRAMES: usize = rtl8125::LOOPBACK_LENGTHS.len();
/// RX slots of the `net-rtl8125` NIC. S3 and the wire modes use the first
/// `RING` slots, with EOR at slot `RING - 1`.
const NIC_RX: usize = ring::RX_SLOTS;
const _: () =
    assert!(FRAMES < RING && RING <= NIC_RX && NIC_RX * rtl8125::DESCRIPTOR_BYTES <= 4096);

/// Rings and buffers the chip may reach while armed. Page aligned; both
/// rings start on 256-byte boundaries as rge requires.
///
/// Each of the four parts starts on its own page, so a domain can give each
/// the least permission it needs (design section 7): no page holds two roles.
#[repr(C, align(4096))]
struct Paged<T>(T);

#[repr(C, align(4096))]
struct Dma {
    tx_ring: Paged<[u8; RING * rtl8125::DESCRIPTOR_BYTES]>,
    rx_ring: Paged<[u8; NIC_RX * rtl8125::DESCRIPTOR_BYTES]>,
    tx_buffers: Paged<[[u8; BUFFER]; RING]>,
    rx_buffers: Paged<[[u8; BUFFER]; NIC_RX]>,
}
static mut DMA: Dma = Dma {
    tx_ring: Paged([0; RING * rtl8125::DESCRIPTOR_BYTES]),
    rx_ring: Paged([0; NIC_RX * rtl8125::DESCRIPTOR_BYTES]),
    tx_buffers: Paged([[0; BUFFER]; RING]),
    rx_buffers: Paged([[0; BUFFER]; NIC_RX]),
};
const _: () = {
    assert!(core::mem::offset_of!(Dma, tx_ring) == ring::SURFACE.tx_ring.0 * 4096);
    assert!(core::mem::offset_of!(Dma, rx_ring) == ring::SURFACE.rx_ring.0 * 4096);
    assert!(core::mem::offset_of!(Dma, tx_buffers) == ring::SURFACE.tx_buffers.0 * 4096);
    assert!(core::mem::offset_of!(Dma, rx_buffers) == ring::SURFACE.rx_buffers.0 * 4096);
    assert!(core::mem::size_of::<Dma>() == ring::SURFACE.pages() * 4096);
};

/// The whole surface as a grant, each page with its role's permission.
fn dma_grant() -> [(u64, amdvi::Perm); ring::SURFACE.pages()] {
    let base = dma() as u64;
    core::array::from_fn(|page| (base + page as u64 * 4096, ring::SURFACE.perm_of(page)))
}

/// Who may touch `DMA` (`rtl8125_ring::Custody`, host-tested): Kernel ->
/// Device at arming, then Quarantined for the boot after any release.
use ring::Custody;
static mut CUSTODY: Custody = Custody::Kernel;
fn custody() -> Custody {
    unsafe { *core::ptr::addr_of!(CUSTODY) }
}
fn set_custody(next: Custody) {
    unsafe { *core::ptr::addr_of_mut!(CUSTODY) = next }
}

fn dma() -> *mut Dma {
    core::ptr::addr_of_mut!(DMA)
}
fn tx_ring() -> *mut u8 {
    unsafe { core::ptr::addr_of_mut!((*dma()).tx_ring.0).cast() }
}
fn rx_ring() -> *mut u8 {
    unsafe { core::ptr::addr_of_mut!((*dma()).rx_ring.0).cast() }
}
fn tx_buffer(index: usize) -> *mut u8 {
    unsafe { core::ptr::addr_of_mut!((*dma()).tx_buffers.0[index]).cast() }
}
fn rx_buffer(index: usize) -> *mut u8 {
    unsafe { core::ptr::addr_of_mut!((*dma()).rx_buffers.0[index]).cast() }
}
fn put32(ring: *mut u8, index: usize, field: usize, value: u32) {
    unsafe {
        core::ptr::write_volatile(
            ring.add(index * rtl8125::DESCRIPTOR_BYTES + field)
                .cast::<u32>(),
            value,
        )
    }
}
fn put64(ring: *mut u8, index: usize, field: usize, value: u64) {
    unsafe {
        core::ptr::write_volatile(
            ring.add(index * rtl8125::DESCRIPTOR_BYTES + field)
                .cast::<u64>(),
            value,
        )
    }
}
fn get32(ring: *mut u8, index: usize, field: usize) -> u32 {
    unsafe {
        core::ptr::read_volatile(
            ring.add(index * rtl8125::DESCRIPTOR_BYTES + field)
                .cast::<u32>(),
        )
    }
}

/// The loopback negative controls, each chosen by its own option word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    None,
    /// TX descriptor 3 is posted without OWN: the chip must stop there and
    /// the RX descriptors it never fills stay device-owned at release.
    Hole,
    /// RX buffers are offered as 64 bytes: no test frame fits.
    ShortRx,
    /// TXCFG without the MAC loopback field.
    NoLoopback,
}

struct ArmedRings {
    mac: [u8; 6],
    /// TX descriptors handed to the chip with OWN set.
    posted: [bool; FRAMES],
    offered: usize,
    elapsed_ms: u32,
    isr: u32,
}

/// Builds the rings in kernel custody, configures the MAC with bus mastering
/// still off, then arms: bus mastering on, TX/RX on, doorbell. Waits up to
/// two seconds for every posted descriptor to come back.
// One index addresses two rings, their buffers and the frame table.
#[allow(clippy::needless_range_loop)]
fn arm_and_run(
    device: &mut Device,
    id: &Identity,
    control: Control,
) -> Result<ArmedRings, rtl8125::Error> {
    let init = rtl8125::chip_init(&mut device.io)?;
    let _ = writeln!(Log, "RTL8125 INIT {init:?}");
    let rcode = rtl8125::phy_config(&mut device.io, options().phy_tuning)?;
    let _ = writeln!(
        Log,
        "RTL8125 FIRMWARE skipped=mac-mcu-patch,phy-ram-code-patch rcode={rcode:04x}"
    );
    assert_eq!(custody(), Custody::Kernel);
    let mac = id.permanent;
    unsafe { core::ptr::write_bytes(dma(), 0, 1) };
    let offered = if control == Control::ShortRx {
        64
    } else {
        BUFFER
    };
    let mut posted = [false; FRAMES];
    for index in 0..RING {
        let last = index == RING - 1;
        put64(
            rx_ring(),
            index,
            rtl8125::RX_ADDRESS,
            rx_buffer(index) as u64,
        );
        if index < FRAMES {
            let len = rtl8125::LOOPBACK_LENGTHS[index];
            let buffer = tx_buffer(index);
            for offset in 0..len {
                unsafe {
                    buffer
                        .add(offset)
                        .write(rtl8125::loopback_byte(mac, index, offset))
                };
            }
            put64(tx_ring(), index, rtl8125::TX_ADDRESS, buffer as u64);
            let mut cmdsts = rtl8125::tx_cmdsts(len, last);
            if control == Control::Hole && index == 3 {
                cmdsts &= !rtl8125::OWN;
            }
            posted[index] = cmdsts & rtl8125::OWN != 0;
            put32(tx_ring(), index, rtl8125::TX_CMDSTS, cmdsts);
            put32(
                rx_ring(),
                index,
                rtl8125::RX_CMDSTS,
                rtl8125::rx_cmdsts(offered, last),
            );
        } else {
            let end = if last { rtl8125::EOR } else { 0 };
            put32(tx_ring(), index, rtl8125::TX_CMDSTS, end);
            put32(rx_ring(), index, rtl8125::RX_CMDSTS, end);
        }
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    rtl8125::configure_mac(
        &mut device.io,
        mac,
        tx_ring() as u64,
        rx_ring() as u64,
        control != Control::NoLoopback,
    )?;
    let _ = writeln!(
        Log,
        "RTL8125 LOOPBACK RINGS tx={:#x} rx={:#x} buffers={:#x}..{:#x} frames={FRAMES} ring={RING} offered={offered} control={control:?}",
        tx_ring() as u64,
        rx_ring() as u64,
        tx_buffer(0) as u64,
        rx_buffer(RING - 1) as u64 + BUFFER as u64
    );
    // Arm: custody first, then bus mastering, then the chip.
    if !device.arm() {
        return Err(rtl8125::Error::StillEnabled);
    }
    rtl8125::start(&mut device.io);
    let mut elapsed_ms = 0;
    while elapsed_ms < 2000 {
        let tx_back = (0..FRAMES)
            .filter(|&i| get32(tx_ring(), i, rtl8125::TX_CMDSTS) & rtl8125::OWN == 0)
            .count();
        let rx_back = (0..FRAMES)
            .filter(|&i| get32(rx_ring(), i, rtl8125::RX_CMDSTS) & rtl8125::OWN == 0)
            .count();
        if tx_back == FRAMES && rx_back == FRAMES {
            break;
        }
        if !device.io.delay_ms(1) {
            return Err(rtl8125::Error::TimerUnavailable);
        }
        elapsed_ms += 1;
    }
    let isr = device.io.read32(rtl8125::ISR);
    Ok(ArmedRings {
        mac,
        posted,
        offered,
        elapsed_ms,
        isr,
    })
}

/// The release shared by S3 and the wire mode, after the chip was
/// identified: stop and fence. True if the stop was confirmed and bus
/// mastering read back clear, the condition for reading descriptors the
/// chip handed back; memory is quarantined either way.
fn release_after_run(device: &mut Device, what: &str) -> bool {
    let function = device.function;
    let armed = custody() == Custody::Device;
    let clean = disarm(function, &mut device.io, what);
    if !clean && !armed {
        // Bus mastering was never set and no memory was offered: nothing to
        // quarantine, but the chip is not shown stopped either.
        let _ = writeln!(
            Log,
            "RTL8125 CUSTODY kernel: nothing was armed; chip not shown quiescent"
        );
    } else if !clean {
        let _ = writeln!(
            Log,
            "RTL8125 CUSTODY quarantined: stop not confirmed or bus mastering still on; nothing read"
        );
    } else if armed {
        let _ = writeln!(
            Log,
            "RTL8125 CUSTODY quarantined: armed memory is never returned or scrubbed; status words are read, buffers only of descriptors the chip handed back (OWN clear)"
        );
    }
    clean
}

/// S3: frames from TX through the chip's MAC loopback into RX, compared
/// byte for byte after the chip confirmed its stop and bus mastering is
/// off. Only buffers of RX descriptors the chip handed back are read
/// (`rtl8125_ring::inspectable`); the memory stays quarantined. Returns
/// whether every frame matched and the release was clean.
pub fn loopback(control: Control) -> bool {
    let mut device = match open() {
        Ok(device) => device,
        Err(error) => {
            let _ = writeln!(Log, "RTL8125 LOOPBACK REFUSED {error:?}");
            return false;
        }
    };
    let Some(id) = device.identify("LOOPBACK") else {
        return false;
    };
    if let Err(error) = prepare_dma("loopback", device.function) {
        device.release();
        let _ = writeln!(Log, "RTL8125 LOOPBACK REFUSED {error:?}");
        return false;
    }
    let run = arm_and_run(&mut device, &id, control);
    // Release, on every path: stop the chip, then bus mastering off and
    // read back, and only then look at what the chip left in memory.
    if !release_after_run(&mut device, "loopback") {
        device.release();
        let _ = writeln!(
            Log,
            "RTL8125 LOOPBACK FAILED custody={:?} run={:?}",
            custody(),
            run.as_ref().map(|_| ())
        );
        return false;
    }
    let armed = match run {
        Ok(armed) => armed,
        Err(error) => {
            let _ = writeln!(
                Log,
                "RTL8125 LOOPBACK FAILED {error:?} custody={:?}",
                custody()
            );
            device.release();
            return false;
        }
    };
    let _ = writeln!(
        Log,
        "RTL8125 LOOPBACK WAIT elapsed_ms={} isr={:08x}",
        armed.elapsed_ms, armed.isr
    );
    let mac = armed.mac;
    let mut sent = 0;
    let mut matched = 0;
    // Descriptors still OWN at release, and never-offered descriptors
    // the chip wrote anyway: two different failures, counted apart.
    let mut still_owned = 0;
    let mut unexpected_writes = 0;
    for index in 0..RING {
        let cmdsts = get32(tx_ring(), index, rtl8125::TX_CMDSTS);
        if index < FRAMES {
            let slot = rtl8125::tx_slot(cmdsts);
            // A slot never posted cannot count as sent.
            let posted = armed.posted[index];
            sent += usize::from(posted && slot == rtl8125::TxSlot::Sent);
            let _ = writeln!(
                Log,
                "RTL8125 TX {index} cmdsts={cmdsts:08x} posted={} {slot:?}",
                u8::from(posted)
            );
        }
        if cmdsts & rtl8125::OWN != 0 {
            still_owned += 1;
            let _ = writeln!(
                Log,
                "RTL8125 CUSTODY device-owned-at-release ring=tx index={index}"
            );
        }
    }
    for index in 0..RING {
        let cmdsts = get32(rx_ring(), index, rtl8125::RX_CMDSTS);
        if cmdsts & rtl8125::OWN != 0 {
            still_owned += 1;
            let _ = writeln!(
                Log,
                "RTL8125 CUSTODY device-owned-at-release ring=rx index={index} (buffer not read)"
            );
            continue;
        }
        if index >= FRAMES {
            // Never offered: its descriptor word is read (not its buffer)
            // to detect a write the chip should not have made.
            let untouched = if index == RING - 1 { rtl8125::EOR } else { 0 };
            if cmdsts != untouched {
                let _ = writeln!(
                    Log,
                    "RTL8125 RX {index} cmdsts={cmdsts:08x} written-though-never-offered"
                );
                unexpected_writes += 1;
            }
            continue;
        }
        match rtl8125::rx_slot(cmdsts, armed.offered) {
            rtl8125::RxSlot::Frame(len) if ring::inspectable(true, cmdsts) => {
                // Handed back: the data preceded the write-back (see
                // `inspectable`), so the buffer holds the frame.
                let bytes = unsafe { core::slice::from_raw_parts(rx_buffer(index), len) };
                match rtl8125::check_loopback(mac, index, bytes) {
                    Ok(fcs) => {
                        matched += 1;
                        let _ = writeln!(
                            Log,
                            "RTL8125 RX {index} cmdsts={cmdsts:08x} len={len} sent={} match=exact fcs={}",
                            rtl8125::LOOPBACK_LENGTHS[index],
                            u8::from(fcs)
                        );
                    }
                    Err(mismatch) => {
                        let _ = writeln!(
                            Log,
                            "RTL8125 RX {index} cmdsts={cmdsts:08x} len={len} MISMATCH {mismatch:?}"
                        );
                    }
                }
            }
            slot => {
                let _ = writeln!(
                    Log,
                    "RTL8125 RX {index} cmdsts={cmdsts:08x} REFUSED {slot:?}"
                );
            }
        }
    }
    if still_owned != 0 {
        let _ = writeln!(
            Log,
            "RTL8125 CUSTODY still-device-owned={still_owned} buffers not read, not reclaimed, quarantined"
        );
    }
    let released = device.release() & BUS_MASTER == 0;
    let ok = sent == FRAMES
        && matched == FRAMES
        && still_owned == 0
        && unexpected_writes == 0
        && released;
    let _ = writeln!(
        Log,
        "RTL8125 LOOPBACK {} sent={sent} matched={matched}/{FRAMES} still_owned_at_release={still_owned} never_offered_written={unexpected_writes} control={control:?}",
        if ok { "OK" } else { "FAILED" }
    );
    ok
}

// ---- Optional: real wire against the link partner (no loopback) ----

/// Waits (bounded) until no TX slot in `slots` is the chip's.
fn tx_drained(io: &mut Registers, slots: core::ops::Range<usize>, ms: u32) -> bool {
    for _ in 0..ms {
        for _ in 0..1000 {
            if slots
                .clone()
                .all(|i| get32(tx_ring(), i, rtl8125::TX_CMDSTS) & rtl8125::OWN == 0)
            {
                return true;
            }
        }
        if !io.delay_ms(1) {
            return false;
        }
    }
    false
}

/// What the sustained passes did: the request, what completed, and how
/// many returned descriptors carried error bits. Complete only when every
/// requested pass drained without error (review F8, Codex 6).
#[derive(Clone, Copy, Debug)]
struct Passes {
    requested: u32,
    completed: u32,
    failed_descriptors: u32,
}
impl Passes {
    fn complete(&self) -> bool {
        self.completed == self.requested && self.failed_descriptors == 0
    }
}

/// Sustained TX (only after the first 8 frames came back clean and their
/// statuses were kept, re-review 5): `passes` passes over the whole
/// ring, slot k carrying test frame k % 8 (TX buffers are only read, so two
/// slots may share one). Each pass posts all 16 slots from where the chip
/// stopped (slot 8), rings once, and must drain within 200 ms. The peer's
/// capture and counters measure loss and corruption.
fn wire_passes(io: &mut Registers, passes: u32) -> Passes {
    let mut out = Passes {
        requested: passes,
        completed: 0,
        failed_descriptors: 0,
    };
    for slot in FRAMES..RING {
        put64(
            tx_ring(),
            slot,
            rtl8125::TX_ADDRESS,
            tx_buffer(slot % FRAMES) as u64,
        );
    }
    for _ in 0..passes {
        for k in 0..RING {
            let slot = (FRAMES + k) % RING;
            let len = rtl8125::LOOPBACK_LENGTHS[slot % FRAMES];
            put64(
                tx_ring(),
                slot,
                rtl8125::TX_ADDRESS,
                tx_buffer(slot % FRAMES) as u64,
            );
            put32(
                tx_ring(),
                slot,
                rtl8125::TX_CMDSTS,
                rtl8125::tx_cmdsts(len, slot == RING - 1),
            );
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        rtl8125::doorbell(io);
        if !tx_drained(io, 0..RING, 200) {
            let _ = writeln!(Log, "RTL8125 WIRE PASSES stalled after {}", out.completed);
            break;
        }
        let failed = (0..RING)
            .filter(|&i| {
                matches!(
                    rtl8125::tx_slot(get32(tx_ring(), i, rtl8125::TX_CMDSTS)),
                    rtl8125::TxSlot::Failed(_)
                )
            })
            .count() as u32;
        out.failed_descriptors += failed;
        if failed != 0 {
            let _ = writeln!(
                Log,
                "RTL8125 WIRE PASSES error bits after {}",
                out.completed
            );
            break;
        }
        out.completed += 1;
    }
    let _ = writeln!(
        Log,
        "RTL8125 WIRE PASSES requested={} completed={} complete={} frames_posted={} per_index_posted={} failed_descriptors={}",
        out.requested,
        out.completed,
        u8::from(out.complete()),
        FRAMES as u32 + out.completed * RING as u32,
        1 + 2 * out.completed,
        out.failed_descriptors
    );
    out
}

/// Waits up to `seconds` for a link that stays up for three seconds of
/// 100 ms samples of `rtl8125::cable_link`, i.e. the PHY's BMSR, the
/// register shown to follow the cable (diag-1). PHYSTAT is not trusted for
/// link: after S3 it claimed link with the cable down (wire-1,
/// p1-cold-wire) and then never showed a single speed (p2a-wire). The
/// caller has just programmed the advertisement and restarted negotiation,
/// whatever state it started from. Returns the last sample once stable,
/// `None` if no stable link came, or the read/timer error.
fn stable_link(
    io: &mut Registers,
    seconds: u32,
) -> Result<Option<rtl8125::CableLink>, rtl8125::Error> {
    let mut last: Option<rtl8125::CableLink> = None;
    let mut same = 0;
    for step in 0..seconds * 10 {
        let link = rtl8125::cable_link(io)?;
        if last.is_none_or(|l| l.up != link.up || l.phystat_claim != link.phystat_claim) {
            let _ = writeln!(
                Log,
                "RTL8125 LINK t_ms={} up={} speed=unestablished phystat_claim={} phystat={:04x} bmsr={:04x}",
                step * 100,
                u8::from(link.up),
                speed_name(link.phystat_claim),
                link.phystat,
                link.bmsr
            );
            if last.is_none_or(|l| l.up != link.up) {
                same = 0;
            }
        }
        last = Some(link);
        same += 1;
        if link.up && same >= 30 {
            let _ = writeln!(
                Log,
                "RTL8125 LINK STABLE source=bmsr speed=unestablished phystat_claim={}",
                speed_name(link.phystat_claim)
            );
            return Ok(Some(link));
        }
        if !io.delay_ms(100) {
            return Err(rtl8125::Error::TimerUnavailable);
        }
    }
    Ok(None)
}

/// Prints the first `limit` bytes of a received frame as hex.
fn hex_line(index: usize, bytes: &[u8], limit: usize) {
    let _ = write!(Log, "RTL8125 WIRE RX {index} bytes=");
    for byte in bytes.iter().take(limit) {
        let _ = write!(Log, "{byte:02x}");
    }
    let _ = writeln!(Log);
}

/// The S3 frames sent unlooped onto the cable after an explicit 2.5G
/// advertisement, then up to 30 s of listening with the whole RX ring
/// offered. The peer's capture is the evidence for TX delivery: a returned
/// TX descriptor is not a delivered frame (review F8), and this mode says
/// so. Received frames are printed in hex for comparison with the peer's
/// capture. Returns whether every requested descriptor came back without
/// error bits, every requested pass completed, at least one whole frame
/// was received and the release was clean (the memory stays quarantined).
#[allow(clippy::needless_range_loop)]
pub fn wire() -> bool {
    let mut device = match open() {
        Ok(device) => device,
        Err(error) => {
            let _ = writeln!(Log, "RTL8125 WIRE REFUSED {error:?}");
            return false;
        }
    };
    let Some(id) = device.identify("WIRE") else {
        return false;
    };
    if let Err(error) = prepare_dma("wire", device.function) {
        device.release();
        let _ = writeln!(Log, "RTL8125 WIRE REFUSED {error:?}");
        return false;
    }
    let mac = id.permanent;
    let run = (|| {
        rtl8125::chip_init(&mut device.io)?;
        let rcode = rtl8125::phy_config(&mut device.io, options().phy_tuning)?;
        let adv = rtl8125::advertise_all(&mut device.io)?;
        let _ = writeln!(
            Log,
            "RTL8125 FIRMWARE skipped=mac-mcu-patch,phy-ram-code-patch rcode={rcode:04x} anar={:04x} a5d4={:04x} pause=0",
            adv.anar, adv.adv_2500
        );
        if stable_link(&mut device.io, 20)?.is_none() {
            return Ok(None);
        }
        assert_eq!(custody(), Custody::Kernel);
        unsafe { core::ptr::write_bytes(dma(), 0, 1) };
        for index in 0..RING {
            let last = index == RING - 1;
            put64(
                rx_ring(),
                index,
                rtl8125::RX_ADDRESS,
                rx_buffer(index) as u64,
            );
            put32(
                rx_ring(),
                index,
                rtl8125::RX_CMDSTS,
                rtl8125::rx_cmdsts(BUFFER, last),
            );
            if index < FRAMES {
                let len = rtl8125::LOOPBACK_LENGTHS[index];
                let buffer = tx_buffer(index);
                for offset in 0..len {
                    unsafe {
                        buffer
                            .add(offset)
                            .write(rtl8125::loopback_byte(mac, index, offset))
                    };
                }
                put64(tx_ring(), index, rtl8125::TX_ADDRESS, buffer as u64);
                put32(
                    tx_ring(),
                    index,
                    rtl8125::TX_CMDSTS,
                    rtl8125::tx_cmdsts(len, last),
                );
            } else {
                put32(
                    tx_ring(),
                    index,
                    rtl8125::TX_CMDSTS,
                    if last { rtl8125::EOR } else { 0 },
                );
            }
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        rtl8125::configure_mac(
            &mut device.io,
            mac,
            tx_ring() as u64,
            rx_ring() as u64,
            false,
        )?;
        if !device.arm() {
            return Err(rtl8125::Error::StillEnabled);
        }
        rtl8125::start(&mut device.io);
        // The first batch is judged and its statuses kept before any slot
        // is posted again: a later pass would overwrite them (re-review 5).
        let drained = tx_drained(&mut device.io, 0..FRAMES, 200);
        let mut initial = [0u32; FRAMES];
        for (index, status) in initial.iter_mut().enumerate() {
            *status = get32(tx_ring(), index, rtl8125::TX_CMDSTS);
        }
        let initial_clean = drained
            && initial
                .iter()
                .all(|&c| rtl8125::tx_slot(c) == rtl8125::TxSlot::Sent);
        let passes = match options().wire_passes {
            0 => None,
            requested if initial_clean => Some(wire_passes(&mut device.io, requested)),
            requested => {
                let _ = writeln!(
                    Log,
                    "RTL8125 WIRE PASSES requested={requested} completed=0 complete=0 reason=first-batch-not-clean drained={}",
                    u8::from(drained)
                );
                Some(Passes {
                    requested,
                    completed: 0,
                    failed_descriptors: 0,
                })
            }
        };
        let _ = writeln!(
            Log,
            "RTL8125 WIRE LISTENING frames_sent={FRAMES} listen_s=30"
        );
        let mut elapsed_ms = 0;
        while elapsed_ms < 30_000 {
            let rx = (0..RING)
                .filter(|&i| get32(rx_ring(), i, rtl8125::RX_CMDSTS) & rtl8125::OWN == 0)
                .count();
            if rx >= 3 {
                break;
            }
            if !device.io.delay_ms(10) {
                return Err(rtl8125::Error::TimerUnavailable);
            }
            elapsed_ms += 10;
        }
        Ok(Some((passes, elapsed_ms, initial)))
    })();
    if !release_after_run(&mut device, "wire") {
        device.release();
        let _ = writeln!(
            Log,
            "RTL8125 WIRE FAILED custody={:?} run={run:?}",
            custody()
        );
        return false;
    }
    let (passes, elapsed_ms, initial) = match run {
        Ok(Some(found)) => found,
        other => {
            let _ = writeln!(Log, "RTL8125 WIRE FAILED {other:?} custody={:?}", custody());
            device.release();
            return false;
        }
    };
    let _ = writeln!(Log, "RTL8125 WIRE WAIT elapsed_ms={elapsed_ms}");
    let mut tx_back = 0;
    let mut tx_failed = 0;
    for (index, &cmdsts) in initial.iter().enumerate() {
        match rtl8125::tx_slot(cmdsts) {
            rtl8125::TxSlot::Sent => tx_back += 1,
            rtl8125::TxSlot::Failed(_) => tx_failed += 1,
            rtl8125::TxSlot::Owned => {}
        }
        let _ = writeln!(
            Log,
            "RTL8125 WIRE TX {index} cmdsts={cmdsts:08x} len={}",
            rtl8125::LOOPBACK_LENGTHS[index]
        );
    }
    let mut frames = 0;
    let mut owned = 0;
    for index in 0..RING {
        let cmdsts = get32(rx_ring(), index, rtl8125::RX_CMDSTS);
        match rtl8125::rx_slot(cmdsts, BUFFER) {
            // An RX slot still offered is expected: nothing arrived for it.
            rtl8125::RxSlot::Owned => owned += 1,
            // Only handed-back descriptors' buffers are read.
            rtl8125::RxSlot::Frame(len) if ring::inspectable(true, cmdsts) => {
                frames += 1;
                let _ = writeln!(Log, "RTL8125 WIRE RX {index} cmdsts={cmdsts:08x} len={len}");
                let bytes = unsafe { core::slice::from_raw_parts(rx_buffer(index), len) };
                hex_line(index, bytes, 64);
            }
            slot => {
                let _ = writeln!(
                    Log,
                    "RTL8125 WIRE RX {index} cmdsts={cmdsts:08x} REFUSED {slot:?}"
                );
            }
        }
    }
    let _ = writeln!(
        Log,
        "RTL8125 CUSTODY rx-still-offered={owned} buffers not read, not reclaimed; all DMA memory quarantined"
    );
    let released = device.release() & BUS_MASTER == 0;
    let passes_ok = passes.is_none_or(|p| p.complete());
    let ok = tx_back == FRAMES && tx_failed == 0 && passes_ok && frames > 0 && released;
    let _ = writeln!(
        Log,
        "RTL8125 WIRE {} descriptors_returned={tx_back}/{FRAMES} descriptors_failed={tx_failed} passes={}/{} rx_frames={frames} delivery=unverified-needs-peer-capture",
        if ok { "DONE" } else { "FAILED" },
        passes.map_or(0, |p| p.completed),
        passes.map_or(0, |p| p.requested)
    );
    ok
}

// ---- Lane 2 diagnostic: which link register follows the cable ----

/// Disposable diagnostic (`rtl8125-linkdiag`): S2's init and advertisement,
/// then every 100 ms for 30 s one line of raw link state: PHYSTAT, BMCR,
/// BMSR read twice (it latches link-down), ANAR, GTCR, PHY OCP 0xa5d4,
/// partner abilities (MII 5, 10) and the PHY state (0xa420 & 7). Bus
/// mastering stays off. Returns true when the run completed.
pub fn link_diagnostic() -> bool {
    let mut device = match open() {
        Ok(device) => device,
        Err(error) => {
            let _ = writeln!(Log, "RTL8125 DIAG REFUSED {error:?}");
            return false;
        }
    };
    if device.identify("DIAG").is_none() {
        return false;
    }
    let result = (|| {
        rtl8125::chip_init(&mut device.io)?;
        rtl8125::phy_config(&mut device.io, options().phy_tuning)?;
        let adv = rtl8125::advertise_all(&mut device.io)?;
        let _ = writeln!(Log, "RTL8125 DIAG START advertised={adv:?}");
        let io = &mut device.io;
        for step in 0..300u32 {
            let phystat = io.read16(rtl8125::PHYSTAT);
            let bmcr = rtl8125::read_mii(io, rtl8125::MII_BMCR)?;
            let bmsr1 = rtl8125::read_mii(io, rtl8125::MII_BMSR)?;
            let bmsr2 = rtl8125::read_mii(io, rtl8125::MII_BMSR)?;
            let anar = rtl8125::read_mii(io, rtl8125::MII_ANAR)?;
            let lpa = rtl8125::read_mii(io, 5)?;
            let gtcr = rtl8125::read_mii(io, rtl8125::MII_100T2CR)?;
            let gtsr = rtl8125::read_mii(io, 10)?;
            let a5d4 = rtl8125::read_phy_ocp(io, 0xa5d4)?;
            let state = rtl8125::read_phy_ocp(io, 0xa420)? & 7;
            let _ = writeln!(
                Log,
                "RTL8125 DIAG t_ms={} phystat={phystat:04x} bmcr={bmcr:04x} bmsr={bmsr1:04x}/{bmsr2:04x} anar={anar:04x} lpa={lpa:04x} gtcr={gtcr:04x} gtsr={gtsr:04x} a5d4={a5d4:04x} phy_state={state}",
                step * 100
            );
            if !io.delay_ms(100) {
                return Err(rtl8125::Error::TimerUnavailable);
            }
        }
        Ok(())
    })();
    let stopped = rtl8125::settle(&mut device.io);
    let released = device.release() & BUS_MASTER == 0;
    let _ = writeln!(
        Log,
        "RTL8125 DIAG END result={result:?} stop={stopped:?} released={released}"
    );
    result.is_ok() && stopped.is_ok() && released
}

// ---- P4: the opt-in `net-rtl8125` NIC behind nic_device ----
//
// One TX ring of 16 slots and one RX ring of 32 in `DMA`, pinned for the
// rest of the boot once armed (as the I219's queues are): no reprobe or
// reuse after DMA. Polled; no chip interrupt source is enabled. The ring
// rules live in `absd_kernel::rtl8125_ring` (host-tested); this is their
// port onto the hardware. Sends are synchronous (`SYS_NIC_SEND`).

pub use crate::e1000::{Identity as NicIdentity, SendError};
use absd_kernel::nic::NicInfo;

/// Ring geometry, as `probe_nic` reports it.
pub const NIC_GEOMETRY: (usize, usize, usize) = (NIC_RX, RING, BUFFER);

/// Why `nic_take_frame` refuses: the ring fault that disabled the NIC.
pub type Disabled = ring::Fault;

struct Nic {
    device: Device,
    core: ring::Nic,
    /// The hardware side of a disable has run.
    stopped: bool,
}
static mut NIC: Option<Nic> = None;
fn nic() -> Option<&'static mut Nic> {
    crate::kernel_lock::assert_bsp_device_access();
    unsafe { (*core::ptr::addr_of_mut!(NIC)).as_mut() }
}

/// `rtl8125_ring::Port` over `DMA` and the mapped registers.
struct Hw<'a> {
    io: &'a mut Registers,
}

impl Port for Hw<'_> {
    fn rx_cmdsts(&mut self, slot: usize) -> u32 {
        get32(rx_ring(), slot, rtl8125::RX_CMDSTS)
    }
    fn set_rx_cmdsts(&mut self, slot: usize, value: u32) {
        put32(rx_ring(), slot, rtl8125::RX_CMDSTS, value)
    }
    fn set_rx_extsts(&mut self, slot: usize, value: u32) {
        put32(rx_ring(), slot, rtl8125::RX_EXTSTS, value)
    }
    fn set_rx_address(&mut self, slot: usize, address: u64) {
        put64(rx_ring(), slot, rtl8125::RX_ADDRESS, address)
    }
    fn rx_buffer_address(&self, slot: usize) -> u64 {
        rx_buffer(slot) as u64
    }
    fn rx_bytes(&self, slot: usize, len: usize) -> &[u8] {
        unsafe { core::slice::from_raw_parts(rx_buffer(slot), len.min(BUFFER)) }
    }
    fn tx_cmdsts(&mut self, slot: usize) -> u32 {
        get32(tx_ring(), slot, rtl8125::TX_CMDSTS)
    }
    fn set_tx_cmdsts(&mut self, slot: usize, value: u32) {
        put32(tx_ring(), slot, rtl8125::TX_CMDSTS, value)
    }
    fn set_tx_address(&mut self, slot: usize, address: u64) {
        put64(tx_ring(), slot, rtl8125::TX_ADDRESS, address)
    }
    fn tx_buffer_address(&self, slot: usize) -> u64 {
        tx_buffer(slot) as u64
    }
    fn tx_buffer(&mut self, slot: usize) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(tx_buffer(slot), BUFFER) }
    }
    fn fence(&mut self) {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
    fn doorbell(&mut self) {
        rtl8125::doorbell(self.io);
    }
    fn isr(&mut self) -> u32 {
        self.io.read32(rtl8125::ISR)
    }
    fn ack_isr(&mut self, bits: u32) {
        self.io.write32(rtl8125::ISR, bits);
    }
    fn carrier(&mut self) -> Result<bool, rtl8125::Error> {
        rtl8125::cable_link(self.io).map(|link| link.up)
    }
    fn delay_ms(&mut self, ms: u32) -> bool {
        self.io.delay_ms(ms)
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub enum ProbeError {
    Absent,
    /// Outside the declared envelope (`NIC UNAVAILABLE Rtl8125(Uncontained(..))`).
    Uncontained(rtl8125_pci::Uncontained),
    Open(Error),
    Refused,
    Chip(rtl8125::Error),
}

/// Bring-up as in the S2/wire modes (no firmware, no pause), the rings
/// built by `rtl8125_ring`, the validated permanent address installed,
/// bus mastering armed last; then a bounded wait for a BMSR link.
pub fn nic_probe() -> Result<NicIdentity, ProbeError> {
    let mut device = open().map_err(|e| match e {
        Error::Absent => ProbeError::Absent,
        e => ProbeError::Open(e),
    })?;
    let Some(id) = device.identify("NIC") else {
        return Err(ProbeError::Refused);
    };
    if let Err(error) = prepare_dma("nic", device.function) {
        device.release();
        return Err(match error {
            Error::Uncontained(why) => ProbeError::Uncontained(why),
            error => ProbeError::Open(error),
        });
    }
    let mac = id.permanent;
    let result = (|| {
        rtl8125::chip_init(&mut device.io)?;
        let rcode = rtl8125::phy_config(&mut device.io, options().phy_tuning)?;
        let adv = rtl8125::advertise_all(&mut device.io)?;
        let _ = writeln!(
            Log,
            "RTL8125 FIRMWARE skipped=mac-mcu-patch,phy-ram-code-patch rcode={rcode:04x} anar={:04x} a5d4={:04x} pause=0",
            adv.anar, adv.adv_2500
        );
        assert_eq!(custody(), Custody::Kernel);
        unsafe { core::ptr::write_bytes(dma(), 0, 1) };
        ring::build_rings(&mut Hw { io: &mut device.io });
        rtl8125::configure_mac(
            &mut device.io,
            mac,
            tx_ring() as u64,
            rx_ring() as u64,
            false,
        )?;
        Ok(())
    })();
    if let Err(error) = result {
        // Nothing was armed: bus mastering is still off.
        let _ = rtl8125::quiesce(&mut device.io);
        device.release();
        return Err(ProbeError::Chip(error));
    }
    if !device.arm() {
        let function = device.function;
        disarm(function, &mut device.io, "nic-arm-failed");
        device.release();
        return Err(ProbeError::Open(Error::BusMaster));
    }
    rtl8125::enable(&mut device.io);
    let link = match stable_link(&mut device.io, 20) {
        Ok(link) => link,
        Err(error) => {
            // A read or timer failure after arming (re-review 4): stop, fence
            // and keep the rings quarantined; the probe fails. No carrier
            // (`Ok(None)`) is different: the NIC is up without link.
            let function = device.function;
            disarm(function, &mut device.io, "nic-link-error");
            device.release();
            let _ = writeln!(Log, "RTL8125 NIC FAILED link={error:?} custody=quarantined");
            return Err(ProbeError::Chip(error));
        }
    };
    let _ = writeln!(
        Log,
        "RTL8125 NIC ACTIVE tx_ring={RING} rx_ring={NIC_RX} buffer={BUFFER} link={link:?} station={} custody=device-pinned",
        Mac(mac)
    );
    let identity = NicIdentity {
        pci: device.function,
        mac,
    };
    unsafe {
        *core::ptr::addr_of_mut!(NIC) = Some(Nic {
            device,
            core: ring::Nic::new(mac),
            stopped: false,
        });
    }
    Ok(identity)
}

impl Nic {
    fn port(&mut self) -> (Hw<'_>, &mut ring::Nic) {
        (
            Hw {
                io: &mut self.device.io,
            },
            &mut self.core,
        )
    }

    /// The hardware side of a ring fault, once: attempt the stop and the bus
    /// mastering fence, then quarantine the rings for the boot whatever the
    /// stop showed.
    fn settle_fault(&mut self) {
        let Some(fault) = self.core.fault() else {
            return;
        };
        if self.stopped {
            return;
        }
        self.stopped = true;
        let function = self.device.function;
        let clean = disarm(function, &mut self.device.io, "nic-disabled");
        // Never given back, whatever the stop showed (`disarm` quarantines):
        // a late write of the chip could still land in them (re-review 1).
        let _ = writeln!(
            Log,
            "RTL8125 NIC DISABLED reason={fault:?} stop_confirmed_and_bus_master_clear={} custody=quarantined rings=retained-not-reoffered info={:?} collisions={}",
            u8::from(clean),
            self.core.info,
            self.core.collisions
        );
    }
}

pub fn nic_present() -> bool {
    nic().is_some()
}
pub fn nic_disabled() -> bool {
    nic().is_some_and(|n| n.core.fault().is_some())
}
pub fn nic_link_up() -> bool {
    let Some(n) = nic() else {
        return false;
    };
    let (mut hw, core) = n.port();
    let up = core.carrier(&mut hw) == Ok(true);
    n.settle_fault();
    up
}

/// The I219/e1000 send outcomes, synchronous: `Ok` only once the device
/// reported the descriptor done without error (`rtl8125_ring::Nic::send`).
pub fn nic_send(length: u64, fill: impl FnOnce(&mut [u8]) -> bool) -> Result<(), SendError> {
    let Some(n) = nic() else {
        return Err(SendError::Disabled);
    };
    let (mut hw, core) = n.port();
    let outcome = core.send(&mut hw, length, fill);
    n.settle_fault();
    match outcome {
        ring::Send::Sent => Ok(()),
        ring::Send::Length => Err(SendError::Length),
        ring::Send::Copy => Err(SendError::Copy),
        ring::Send::NoCarrier => Err(SendError::NoCarrier),
        ring::Send::Disabled => Err(SendError::Disabled),
    }
}

/// One received frame, FCS checked and removed, delivered by copy.
pub fn nic_take_frame(deliver: impl FnOnce(&[u8]) -> bool) -> Result<Option<usize>, Disabled> {
    let Some(n) = nic() else {
        return Ok(None);
    };
    let (mut hw, core) = n.port();
    let taken = core.take(&mut hw, deliver);
    n.settle_fault();
    match taken {
        Ok(ring::Take::Frame(bytes)) => Ok(Some(bytes)),
        Ok(ring::Take::Empty) => Ok(None),
        Err(fault) => Err(fault),
    }
}

pub fn nic_info() -> Option<NicInfo> {
    let n = nic()?;
    let (mut hw, core) = n.port();
    let info = core.info(&mut hw);
    n.settle_fault();
    Some(info)
}

/// The contain path's stop: service closed before anything touches a
/// descriptor again, custody quarantined, for the boot.
pub fn contain_stop() {
    match nic() {
        Some(found) => {
            found.core.disable(ring::Fault::ContainmentLost);
            found.settle_fault();
        }
        None => shutdown(),
    }
}
