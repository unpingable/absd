//! BSP-only MSI-X transport. No AP startup and no event-ring access in ISR.
use crate::{ap, mmio, pci, serial};
use absd_kernel::{
    interrupt_vector,
    pci_interrupt::{self, ConfigSpace, Msix},
    xhci_irq::{self, Error, State},
    xhci_ring::Layout,
};
use core::sync::atomic::{AtomicU64, Ordering, fence};

pub static STATE: State = State::new();
static EOI: AtomicU64 = AtomicU64::new(0);
static VECTOR_CONTROL: AtomicU64 = AtomicU64::new(0);

struct Config(pci::Function);
impl ConfigSpace for Config {
    fn read32(&mut self, offset: u8) -> u32 {
        pci::read32(self.0, offset)
    }
}

pub struct Route {
    function: pci::Function,
    capability: Msix,
    msi: Option<u8>,
    table: u64,
    lapic: u64,
    destination: u8,
    touched: bool,
}

fn read(address: u64) -> u32 {
    unsafe { core::ptr::read_volatile(address as *const u32) }
}
fn write(address: u64, value: u32) {
    unsafe { core::ptr::write_volatile(address as *mut u32, value) };
}

impl Route {
    /// Caller already owns the function. This maps/initializes only the
    /// BSP LAPIC; it never changes a controller interrupt control here.
    pub fn prepare(
        function: pci::Function,
        registers: u64,
        layout: Layout,
        hcsparams1: u32,
        extended: (u64, u64),
    ) -> Result<Self, Error> {
        let caps = pci_interrupt::discover(&mut Config(function)).map_err(Error::Capabilities)?;
        let capability = caps.msix.ok_or(Error::MissingMsix)?;
        xhci_irq::validate(
            capability,
            layout,
            ((hcsparams1 >> 8) & 0x7ff) as u16,
            extended,
        )?;
        let features = core::arch::x86_64::__cpuid(1);
        if features.edx & (1 << 9) == 0 {
            return Err(Error::Apic);
        }
        let (low, high): (u32, u32);
        unsafe {
            core::arch::asm!("rdmsr",in("ecx")0x1bu32,out("eax")low,out("edx")high,options(nomem,nostack));
        }
        if low & (1 << 8) == 0 || low & (1 << 10) != 0 {
            return Err(Error::Apic);
        }
        let physical = ((u64::from(high) << 32) | u64::from(low)) & 0x000f_ffff_ffff_f000;
        let regions_before = mmio::snapshot().1;
        let lapic = mmio::map(physical, 4096, mmio::Cache::Uncached).map_err(|_| Error::Map)?;
        let regions_after = mmio::snapshot().1;
        serial::write("XHCI LAPIC MMIO regions_added=");
        serial::decimal((regions_after - regions_before) as u64);
        serial::write(" regions_used=");
        serial::decimal(regions_after as u64);
        serial::write("\n");
        ap::configure_bsp_lapic_mapping(lapic);
        ap::enable_bsp_lapic();
        if read(lapic + 0x80) & 0xff >= u32::from(interrupt_vector::USB) {
            return Err(Error::Apic);
        }
        let destination = (read(lapic + 0x20) >> 24) as u8;
        EOI.store(lapic + 0xb0, Ordering::Release);
        Ok(Self {
            function,
            capability,
            msi: caps.msi.map(|m| m.capability),
            table: registers + capability.table.offset,
            lapic,
            destination,
            touched: false,
        })
    }
    pub fn configure(&mut self, generation: u64) -> Result<(), Error> {
        self.touched = true;
        let (capability, msi, destination) = (self.capability, self.msi, self.destination);
        xhci_irq::configure_msix(self, capability, msi, destination, interrupt_vector::USB)?;
        if self.pending() {
            return Err(Error::Drain);
        }
        fence(Ordering::SeqCst);
        VECTOR_CONTROL.store(self.table + 12, Ordering::Release);
        STATE.arm(generation);
        Ok(())
    }
    /// Deferred recovery keeps route work below its fixed per-tick budget.
    pub fn runtime_capable(&self) -> bool {
        self.capability.vectors <= 32
    }

    pub fn runtime_rearm(&mut self, generation: u64) -> Result<(), Error> {
        if !self.runtime_capable() {
            return Err(Error::Interrupters {
                vectors: self.capability.vectors,
                max: 32,
            });
        }
        self.configure(generation)
    }
    /// Caller rechecks legacy ownership immediately before this operation.
    pub fn enable(&mut self, masked: bool) -> Result<(), Error> {
        fence(Ordering::SeqCst);
        let capability = self.capability;
        xhci_irq::enable_msix(self, capability, masked)
    }
    pub fn pending(&self) -> bool {
        let vector = u64::from(interrupt_vector::USB);
        let bit = 1u32 << (vector % 32);
        let bank = 16 * (vector / 32);
        (read(self.lapic + 0x100 + bank) | read(self.lapic + 0x200 + bank)) & bit != 0
    }
    /// Transport is fenced before IF may be enabled by the drain loop.
    /// Permanent gate/ISR and static storage remain valid even on failure.
    pub fn disable(&mut self) -> Result<(), Error> {
        if !self.touched {
            return Ok(());
        }
        let capability = self.capability;
        let result = xhci_irq::disable_msix(self, capability);
        STATE.retire();
        // Readback after configuration disable and the posted table mask.
        let _ = read(self.table + 12);
        result
    }
}

impl xhci_irq::MsixAccess for Route {
    fn config_read(&mut self, offset: u8) -> u32 {
        pci::read32(self.function, offset)
    }
    fn config_write(&mut self, offset: u8, value: u32) {
        pci::write32(self.function, offset, value);
    }
    fn entry_read(&mut self, index: u16, word: u8) -> u32 {
        assert!(index < self.capability.vectors && word < 4);
        read(self.table + 16 * u64::from(index) + 4 * u64::from(word))
    }
    fn entry_write(&mut self, index: u16, word: u8, value: u32) {
        assert!(index < self.capability.vectors && word < 4);
        write(
            self.table + 16 * u64::from(index) + 4 * u64::from(word),
            value,
        );
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn xhci_interrupt() {
    if STATE.interrupt() {
        let control = VECTOR_CONTROL.load(Ordering::Acquire);
        if control != 0 {
            write(control, read(control) | 1);
            let _ = read(control);
        }
    }
    let eoi = EOI.load(Ordering::Acquire);
    if eoi != 0 {
        write(eoi, 0);
    }
}

/// Deterministic entry fixture uses the real gate/stub/ISR, with no device
/// claim that these software interrupts were hardware MSI-X messages.
pub fn inject_storm() {
    for _ in 0..=xhci_irq::INTERRUPT_BUDGET {
        unsafe {
            core::arch::asm!("int {vector}",vector=const interrupt_vector::USB);
        }
    }
}

/// Explicit recovery qualification fixture, never a device MSI-X claim.
pub fn inject_late_entry() {
    unsafe {
        core::arch::asm!("int {vector}", vector=const interrupt_vector::USB);
    }
}
