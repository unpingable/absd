//! One controlled, kernel-only application processor for lifecycle fixtures.
//!
//! The only admitted AP is xAPIC ID 1 in the two-CPU local VM. It has no
//! ring-3 descriptor, ordinary scheduler, device reference, PIC/timer owner,
//! or serial path. The BSP owns fixture creation and every stop decision.
//! AP interrupt entry observes a mailbox; only post-pivot Rust publishes the
//! departed token. This module is inert until the BSP explicitly configures
//! and starts it after the shared boot PDPT and xAPIC mapping are final.

use absd_kernel::arch::{TSS_SELECTOR, TSS_SIZE, interrupt_gate_options, tss_descriptor};
use absd_kernel::process::CpuClaim;
use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering, fence};

global_asm!(include_str!("ap_boot.S"), options(att_syntax));

const AP_ID: u8 = 1;
const AP_IPI_VECTOR: u8 = absd_kernel::interrupt_vector::AP_IPI;
pub const BSP_ACK_VECTOR: u8 = absd_kernel::interrupt_vector::BSP_ACK;
const AP_SPURIOUS_VECTOR: u8 = absd_kernel::interrupt_vector::APIC_SPURIOUS;
const TRAMPOLINE_PAGE: u32 = 0x7000;
const PAGE_BYTES: usize = 4096;
const TRAMPOLINE_STACK_RESERVE: usize = 256;
const STACK_BYTES: usize = 16 * 1024;
const START_TSC_BOUND: u64 = 1 << 34;
const STOP_TSC_BOUND: u64 = 1 << 34;
pub const FIXTURE_STOP_TSC_BOUND: u64 = STOP_TSC_BOUND;
const ICR_TSC_BOUND: u64 = 1 << 30;
const INIT_SETTLE_TSC: u64 = 1 << 26;
const SIPI_SETTLE_TSC: u64 = 1 << 22;

const LAPIC_ID: u64 = 0x020;
const LAPIC_EOI: u64 = 0x0b0;
const LAPIC_SVR: u64 = 0x0f0;
const LAPIC_ICR_LOW: u64 = 0x300;
const LAPIC_ICR_HIGH: u64 = 0x310;
const LAPIC_LVT_TIMER: u64 = 0x320;
const LAPIC_LVT_LINT0: u64 = 0x350;
const LAPIC_LVT_LINT1: u64 = 0x360;
const LAPIC_LVT_ERROR: u64 = 0x370;
const LVT_MASKED: u32 = 1 << 16;
const ICR_BUSY: u32 = 1 << 12;
const INIT_ASSERT: u32 = 0x0000_c500;
const INIT_DEASSERT: u32 = 0x0000_8500;
const STARTUP: u32 = 0x0000_0600;
const FIXED: u32 = 0;

/// Proof-carrying label for the fixed local-VM SIPI page. The caller must
/// establish that the complete page is type-1 Multiboot RAM below EBDA, is
/// disjoint from the kernel, Multiboot data/modules and all live low-memory
/// consumers, and remains reserved for the AP until the VM stops. The kernel
/// allocator already reserves 0..1 MiB but that alone is not a RAM proof.
pub struct ValidatedLowPage {
    physical: u32,
    _private: (),
}

impl ValidatedLowPage {
    /// # Safety
    /// The BSP must have checked every proof obligation in the type comment.
    pub(crate) unsafe fn from_verified_multiboot_page(physical: u32) -> Self {
        assert_eq!(
            physical, TRAMPOLINE_PAGE,
            "only controlled SIPI page 0x7000 admitted"
        );
        Self {
            physical,
            _private: (),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StopToken {
    pub slot: usize,
    pub pid: u64,
    pub claim: CpuClaim,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixtureMode {
    /// Logical user-owned state represented by a real claimed CR3/stack/TSS;
    /// the AP remains CPL0 throughout this fixture.
    LogicalUser,
    /// A bounded CPL0 handler that can yield the BKL at a named safe point.
    BoundedHandler,
    /// A bounded mapping continuation with a live resource pin.
    MappingContinuation,
    /// Stop is observed after the exact CPU claim but before victim hardware
    /// resources are loaded. The entry gate must suppress the callback.
    EarlyStop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserReturnKind {
    Ordinary,
    RealTime,
}

#[derive(Clone, Copy, Debug)]
pub struct VictimLease {
    pub token: StopToken,
    pub mode: FixtureMode,
    pub cr3: u64,
    pub kernel_stack_base: u64,
    pub kernel_stack_top: u64,
}

/// Called on the AP while it holds the BKL. It must claim exactly one
/// Created/Runnable fixture task and return its real CPU1 claim and resources.
/// It must not return a borrow into the process table.
pub type ClaimFixture = unsafe fn() -> Option<VictimLease>;
/// Called on the victim stack with no BKL. It may acquire/yield the BKL only
/// at its controlled safe points, must finish in bounded time, must not enter
/// user mode, and must return without retaining task/device/table references.
pub type RunFixture = unsafe fn(VictimLease);
/// Dedicated prepublication fixture: AP holds BKL, verifies the BSP-owned
/// spawner token, and changes only Active -> Requested. It cannot reclaim.
pub type StopBspFixture = unsafe fn(StopToken) -> bool;

#[derive(Clone, Copy)]
struct Config {
    low_page: u32,
    lapic: u64,
}

#[repr(C, align(16))]
struct Stack([u8; STACK_BYTES]);

#[repr(C, packed)]
struct Tss {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    io_map_base: u16,
}

impl Tss {
    const EMPTY: Self = Self {
        reserved0: 0,
        rsp: [0; 3],
        reserved1: 0,
        ist: [0; 7],
        reserved2: 0,
        reserved3: 0,
        io_map_base: TSS_SIZE as u16,
    };
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtGate {
    low: u16,
    selector: u16,
    options: u16,
    middle: u16,
    high: u32,
    reserved: u32,
}

impl IdtGate {
    const EMPTY: Self = Self {
        low: 0,
        selector: 0,
        options: 0,
        middle: 0,
        high: 0,
        reserved: 0,
    };
    const fn new(address: u64, ist: u16) -> Self {
        Self {
            low: address as u16,
            selector: 0x08,
            options: interrupt_gate_options(ist),
            middle: (address >> 16) as u16,
            high: (address >> 32) as u32,
            reserved: 0,
        }
    }
}

#[repr(C, packed)]
struct DescriptorPointer {
    limit: u16,
    base: u64,
}

static mut CONFIG: Option<Config> = None;
static mut CLAIM_FIXTURE: Option<ClaimFixture> = None;
static mut RUN_FIXTURE: Option<RunFixture> = None;
static mut STOP_BSP_FIXTURE: Option<StopBspFixture> = None;
static mut ACTIVE_LEASE: Option<VictimLease> = None;
static mut AP_TSS: [Tss; crate::cpu::MAX_CPUS - 1] =
    [const { Tss::EMPTY }; crate::cpu::MAX_CPUS - 1];
static mut AP_GDT: [[u64; 5]; crate::cpu::MAX_CPUS - 1] =
    [[0, 0x00af9a000000ffff, 0x00af92000000ffff, 0, 0]; crate::cpu::MAX_CPUS - 1];
static mut AP_IDT: [[IdtGate; 256]; crate::cpu::MAX_CPUS - 1] =
    [[IdtGate::EMPTY; 256]; crate::cpu::MAX_CPUS - 1];
static mut AP_BOOT_STACK: [Stack; crate::cpu::MAX_CPUS - 1] =
    [const { Stack([0; STACK_BYTES]) }; crate::cpu::MAX_CPUS - 1];
static mut AP_ENTRY_STACK: [Stack; crate::cpu::MAX_CPUS - 1] =
    [const { Stack([0; STACK_BYTES]) }; crate::cpu::MAX_CPUS - 1];
static mut AP_IPI_STACK: [Stack; crate::cpu::MAX_CPUS - 1] =
    [const { Stack([0; STACK_BYTES]) }; crate::cpu::MAX_CPUS - 1];
static mut AP_FAULT_STACK: [Stack; crate::cpu::MAX_CPUS - 1] =
    [const { Stack([0; STACK_BYTES]) }; crate::cpu::MAX_CPUS - 1];

static LAPIC_VIRT: AtomicU64 = AtomicU64::new(0);
static ONLINE: [AtomicBool; crate::cpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::cpu::MAX_CPUS];
static FAILED: [AtomicBool; crate::cpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::cpu::MAX_CPUS];
static COMMAND: [AtomicU8; crate::cpu::MAX_CPUS] =
    [const { AtomicU8::new(0) }; crate::cpu::MAX_CPUS]; // 1: victim, 2: BSP stop, 3: return guard, 4: lock probe
static USER_REFUSAL_KIND: AtomicU8 = AtomicU8::new(0);
static LOCK_PROBE_COUNT: AtomicU64 = AtomicU64::new(0);
static IN_FIXTURE: AtomicBool = AtomicBool::new(false);
static CLAIMED: AtomicBool = AtomicBool::new(false);
static RESOURCE_ACTIVE: AtomicBool = AtomicBool::new(false);
static HANDLER_ACTIVE: AtomicBool = AtomicBool::new(false);
static REQUEST_STATE: AtomicU8 = AtomicU8::new(0); // 1 request, 2 observed, 3 ACK
static OBSERVED_COUNT: AtomicU64 = AtomicU64::new(0);
static ACK_COUNT: AtomicU64 = AtomicU64::new(0);
static REQUEST_SLOT: AtomicU64 = AtomicU64::new(0);
static REQUEST_PID: AtomicU64 = AtomicU64::new(0);
static REQUEST_EPOCH: AtomicU64 = AtomicU64::new(0);
static ACK_STATE: AtomicU8 = AtomicU8::new(0); // 1 ready, 2 consumed
static ACK_SLOT: AtomicU64 = AtomicU64::new(0);
static ACK_PID: AtomicU64 = AtomicU64::new(0);
static ACK_EPOCH: AtomicU64 = AtomicU64::new(0);
static BSP_STOP_SLOT: AtomicU64 = AtomicU64::new(0);
static BSP_STOP_PID: AtomicU64 = AtomicU64::new(0);
static BSP_STOP_EPOCH: AtomicU64 = AtomicU64::new(0);
static BSP_STOP_COMMITTED: AtomicBool = AtomicBool::new(false);

// Used only by ap_enter_victim in ap_boot.S. The assembly saves its caller
// RSP here, then restores AP-owned RSP/CR3/TSS before returning to Rust.
#[unsafe(no_mangle)]
static mut AP_SAVED_RSP: u64 = 0;
#[unsafe(no_mangle)]
static mut AP_BOOT_CR3: u64 = 0;
#[unsafe(no_mangle)]
static mut AP_ENTRY_STACK_TOP: u64 = 0;
#[unsafe(no_mangle)]
static mut AP_TSS_RSP0_ADDRESS: u64 = 0;
#[repr(align(16))]
// The assembly uses the storage symbol directly for FXSAVE/FXRSTOR.
#[allow(dead_code)]
struct Fxsave([u8; 512]);
#[unsafe(no_mangle)]
static mut AP_IRQ_FXSAVE: Fxsave = Fxsave([0; 512]);

unsafe extern "C" {
    static ap_trampoline_start: u8;
    static ap_trampoline_end: u8;
    static ap_trampoline_gdt: u8;
    static ap_trampoline_gdtr: u8;
    static ap_trampoline_far: u8;
    static ap_trampoline_cr3: u8;
    static ap_trampoline_stack: u8;
    static ap_trampoline_entry: u8;
    static ap_trampoline_long: u8;
    static ap_ipi_stub: u8;
    static ap_spurious_stub: u8;
    static ap_unexpected_stub: u8;
    static boot_pml4: u8;
    static __kernel_start: u8;
    static __kernel_end: u8;
    fn ap_enter_victim(root: u64, stack_top: u64, rsp0: u64);
}

fn boot_stack_top(id: u8) -> u64 {
    assert!(id > 0 && (id as usize) < crate::cpu::count());
    unsafe {
        core::ptr::addr_of!(AP_BOOT_STACK)
            .cast::<Stack>()
            .add(id as usize - 1) as u64
            + STACK_BYTES as u64
    }
}

fn entry_stack_top(id: u8) -> u64 {
    assert!(id > 0 && (id as usize) < crate::cpu::count());
    unsafe {
        core::ptr::addr_of!(AP_ENTRY_STACK)
            .cast::<Stack>()
            .add(id as usize - 1) as u64
            + STACK_BYTES as u64
    }
}

fn ipi_stack_top(id: u8) -> u64 {
    assert!(id > 0 && (id as usize) < crate::cpu::count());
    unsafe {
        core::ptr::addr_of!(AP_IPI_STACK)
            .cast::<Stack>()
            .add(id as usize - 1) as u64
            + STACK_BYTES as u64
    }
}

fn fault_stack_top(id: u8) -> u64 {
    assert!(id > 0 && (id as usize) < crate::cpu::count());
    unsafe {
        core::ptr::addr_of!(AP_FAULT_STACK)
            .cast::<Stack>()
            .add(id as usize - 1) as u64
            + STACK_BYTES as u64
    }
}

fn lapic_base() -> u64 {
    let base = LAPIC_VIRT.load(Ordering::Acquire);
    assert_ne!(base, 0, "AP LAPIC not configured");
    base
}

pub(crate) fn lapic_read(offset: u64) -> u32 {
    unsafe { core::ptr::read_volatile((lapic_base() + offset) as *const u32) }
}

pub(crate) fn lapic_write(offset: u64, value: u32) {
    unsafe { core::ptr::write_volatile((lapic_base() + offset) as *mut u32, value) }
}

fn read_apic_base() -> (u32, u32) {
    let low: u32;
    let high: u32;
    unsafe {
        asm!("rdmsr", in("ecx") 0x1bu32, out("eax") low, out("edx") high,
             options(nomem, nostack));
    }
    (low, high)
}

fn write_apic_base(low: u32, high: u32) {
    unsafe {
        asm!("wrmsr", in("ecx") 0x1bu32, in("eax") low, in("edx") high,
             options(nomem, nostack));
    }
}

/// BSP-only xAPIC software enable. IDT 0xff and 0xf2 must already be
/// installed by the BSP owner. LINT0 remains unmasked ExtINT so legacy
/// PIC/PIT/COM1 delivery continues on the BSP; the AP masks only its LINTs.
pub fn enable_bsp_lapic() {
    bsp_only();
    assert_ne!(
        core::arch::x86_64::__cpuid(1).edx & (1 << 9),
        0,
        "controlled AP gate requires xAPIC"
    );
    let (low, high) = read_apic_base();
    assert_ne!(low & (1 << 8), 0, "not BSP APIC identity");
    assert_eq!(low & (1 << 10), 0, "x2APIC is outside controlled gate");
    if low & (1 << 11) == 0 {
        write_apic_base(low | (1 << 11), high);
    }
    let svr = lapic_read(LAPIC_SVR);
    lapic_write(
        LAPIC_SVR,
        (svr & !0xff) | 0x100 | u32::from(AP_SPURIOUS_VECTOR),
    );
    let lint0 = lapic_read(LAPIC_LVT_LINT0);
    if lint0 & (7 << 8) != 7 << 8 || lint0 & LVT_MASKED != 0 {
        lapic_write(LAPIC_LVT_LINT0, 7 << 8); // BSP ExtINT virtual wire
    }
    assert_eq!(
        lapic_read(LAPIC_LVT_LINT0) & ((7 << 8) | LVT_MASKED),
        7 << 8
    );
}

fn bsp_only() {
    assert!(
        crate::cpu::is_bootstrap_processor(),
        "AP called BSP control API"
    );
}

/// BSP-only, before AP startup. The caller supplies an independently
/// validated low page and a mapped uncached xAPIC register base. No later
/// shared PDPT mapping may be installed after AP startup in this gate.
pub fn configure(page: ValidatedLowPage, lapic_virt: u64) {
    bsp_only();
    assert!(!ONLINE[AP_ID as usize].load(Ordering::Acquire));
    assert_eq!(lapic_virt & 0xfff, 0, "unaligned LAPIC mapping");
    assert_ne!(lapic_virt, 0);
    unsafe {
        assert!((*core::ptr::addr_of!(CONFIG)).is_none());
        core::ptr::write(
            core::ptr::addr_of_mut!(CONFIG),
            Some(Config {
                low_page: page.physical,
                lapic: lapic_virt,
            }),
        );
    }
    configure_bsp_lapic_mapping(lapic_virt);
}

/// Map ownership for BSP device IRQ delivery, independently of AP startup.
/// Caller supplies a validated uncached mapping; an existing mapping cannot
/// be replaced. This neither installs an AP trampoline nor starts an AP.
pub fn configure_bsp_lapic_mapping(lapic_virt: u64) {
    bsp_only();
    assert!(!ONLINE[AP_ID as usize].load(Ordering::Acquire));
    assert_ne!(lapic_virt, 0);
    assert_eq!(lapic_virt & 0xfff, 0);
    let before = LAPIC_VIRT.load(Ordering::Acquire);
    assert!(before == 0 || before == lapic_virt);
    LAPIC_VIRT.store(lapic_virt, Ordering::Release);
}

/// Install the only AP fixture callbacks before sending its first command.
/// The claim callback executes under the BKL on AP; the run callback executes
/// on the real victim stack without the BKL and must obey its bounded lease.
pub fn install_fixture_callbacks(claim: ClaimFixture, run: RunFixture) {
    bsp_only();
    assert!(!CLAIMED.load(Ordering::Acquire));
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!(CLAIM_FIXTURE), Some(claim));
        core::ptr::write(core::ptr::addr_of_mut!(RUN_FIXTURE), Some(run));
    }
}

pub fn install_bsp_stop_fixture(callback: StopBspFixture) {
    bsp_only();
    assert!(!IN_FIXTURE.load(Ordering::Acquire));
    unsafe { core::ptr::write(core::ptr::addr_of_mut!(STOP_BSP_FIXTURE), Some(callback)) };
}

fn offset(label: *const u8, start: usize, end: usize) -> usize {
    let value = label as usize;
    assert!(
        (start..end).contains(&value),
        "AP trampoline label outside image"
    );
    value - start
}

fn patch_u32(page: u32, at: usize, value: u32) {
    assert!(at + 4 <= PAGE_BYTES - TRAMPOLINE_STACK_RESERVE);
    unsafe { core::ptr::write_unaligned((page as usize + at) as *mut u32, value) }
}

fn patch_u64(page: u32, at: usize, value: u64) {
    assert!(at + 8 <= PAGE_BYTES - TRAMPOLINE_STACK_RESERVE);
    unsafe { core::ptr::write_unaligned((page as usize + at) as *mut u64, value) }
}

fn install_trampoline(page: u32, id: u8) {
    // AP's first CR3 identity-maps only the first GiB. The linker span
    // includes every AP stack, descriptor table, mailbox, FPU scratch and
    // Rust/assembly entry used before the controlled victim CR3 is loaded.
    let kernel_start = core::ptr::addr_of!(__kernel_start) as usize;
    let kernel_end = core::ptr::addr_of!(__kernel_end) as usize;
    assert!(
        kernel_start >= 0x10_0000 && kernel_start < kernel_end && kernel_end < (1usize << 30),
        "AP kernel image exceeds boot identity map"
    );
    let start = core::ptr::addr_of!(ap_trampoline_start) as usize;
    let end = core::ptr::addr_of!(ap_trampoline_end) as usize;
    assert!((kernel_start..kernel_end).contains(&start) && end <= kernel_end);
    let length = end.checked_sub(start).expect("AP trampoline bounds");
    assert!(length > 0 && length <= PAGE_BYTES - TRAMPOLINE_STACK_RESERVE);
    let dst = page as usize as *mut u8;
    unsafe { core::ptr::copy_nonoverlapping(start as *const u8, dst, length) };
    let gdtr = offset(core::ptr::addr_of!(ap_trampoline_gdtr), start, end);
    let gdt = offset(core::ptr::addr_of!(ap_trampoline_gdt), start, end);
    let far = offset(core::ptr::addr_of!(ap_trampoline_far), start, end);
    let long = offset(core::ptr::addr_of!(ap_trampoline_long), start, end);
    let cr3 = offset(core::ptr::addr_of!(ap_trampoline_cr3), start, end);
    let stack = offset(core::ptr::addr_of!(ap_trampoline_stack), start, end);
    let entry = offset(core::ptr::addr_of!(ap_trampoline_entry), start, end);
    patch_u32(page, gdtr + 2, page + gdt as u32);
    patch_u32(page, far, page + long as u32);
    let boot_root = core::ptr::addr_of!(boot_pml4) as usize;
    assert!((kernel_start..kernel_end).contains(&boot_root) && boot_root & 0xfff == 0);
    patch_u32(page, cr3, boot_root as u32);
    patch_u64(page, stack, boot_stack_top(id));
    patch_u64(page, entry, ap_kernel_main as *const () as usize as u64);
    if id == AP_ID {
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(AP_BOOT_CR3), boot_root as u64);
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(AP_ENTRY_STACK_TOP),
                entry_stack_top(id),
            );
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(AP_TSS_RSP0_ADDRESS),
                core::ptr::addr_of_mut!(AP_TSS[0].rsp) as u64,
            );
        }
    }
    fence(Ordering::SeqCst);
}

fn wait_icr_idle() {
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    while lapic_read(LAPIC_ICR_LOW) & ICR_BUSY != 0 {
        assert!(
            unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < ICR_TSC_BOUND,
            "xAPIC ICR delivery did not finish"
        );
        core::hint::spin_loop();
    }
}

fn send_ipi_to(id: u8, low: u32) {
    wait_icr_idle();
    lapic_write(LAPIC_ICR_HIGH, u32::from(id) << 24);
    lapic_write(LAPIC_ICR_LOW, low);
    wait_icr_idle();
}

fn send_ipi(low: u32) {
    send_ipi_to(AP_ID, low)
}

fn tsc_delay(bound: u64) {
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    while unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < bound {
        core::hint::spin_loop();
    }
}

/// Start only APIC ID 1; AP stays CPL0 on its private stacks until a
/// controlled fixture command. No ordinary task can be scheduled there.
pub fn start_kernel_only() {
    bsp_only();
    enable_bsp_lapic();
    // ONLINE fences private descriptors and the last shared trampoline read.
    // Never patch the shared low page until the preceding AP acknowledged it.
    for id in 1..crate::cpu::count() {
        start_one(id as u8);
    }
}
fn start_one(id: u8) {
    bsp_only();
    assert!(!ONLINE[id as usize].load(Ordering::Acquire));
    let config = unsafe { (*core::ptr::addr_of!(CONFIG)).expect("AP not configured") };
    assert_eq!(config.low_page, TRAMPOLINE_PAGE);
    assert_eq!(config.lapic, lapic_base());
    assert_eq!(
        lapic_read(LAPIC_ID) >> 24,
        0,
        "controlled VM BSP APIC ID must be 0"
    );
    install_trampoline(config.low_page, id);
    send_ipi_to(id, INIT_ASSERT);
    tsc_delay(INIT_SETTLE_TSC);
    send_ipi_to(id, INIT_DEASSERT);
    tsc_delay(SIPI_SETTLE_TSC);
    send_ipi_to(id, STARTUP | (TRAMPOLINE_PAGE >> 12));
    tsc_delay(SIPI_SETTLE_TSC);
    if !ONLINE[id as usize].load(Ordering::Acquire) {
        send_ipi_to(id, STARTUP | (TRAMPOLINE_PAGE >> 12));
    }
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    while !ONLINE[id as usize].load(Ordering::Acquire) {
        assert!(
            !FAILED[id as usize].load(Ordering::Acquire),
            "controlled AP failed closed"
        );
        assert!(
            unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < START_TSC_BOUND,
            "controlled AP did not enter kernel-only loop"
        );
        core::hint::spin_loop();
    }
}

/// Queue one fixture. The BSP must have installed callbacks and must release
/// the BKL before waiting for `poll_claimed` or the AP callback cannot claim.
pub fn start_fixture() {
    bsp_only();
    assert!(ONLINE[AP_ID as usize].load(Ordering::Acquire));
    assert!(!FAILED[AP_ID as usize].load(Ordering::Acquire));
    assert!(unsafe { (*core::ptr::addr_of!(CLAIM_FIXTURE)).is_some() });
    assert!(unsafe { (*core::ptr::addr_of!(RUN_FIXTURE)).is_some() });
    assert_eq!(
        REQUEST_STATE.load(Ordering::Acquire),
        0,
        "previous AP stop has not completed its drain"
    );
    assert_eq!(ACK_STATE.load(Ordering::Acquire), 0);
    assert!(
        IN_FIXTURE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok(),
        "AP fixture already active"
    );
    assert_eq!(
        COMMAND[AP_ID as usize].swap(1, Ordering::AcqRel),
        0,
        "AP fixture already queued"
    );
    send_ipi(FIXED | u32::from(AP_IPI_VECTOR));
}

/// One controlled AP request against a BSP spawner paused after Created
/// child + handle installation. The caller still owns its task resources;
/// it must release BKL before polling and abort child/handle after re-entry.
pub fn start_bsp_stop_fixture(token: StopToken) {
    bsp_only();
    assert_eq!(token.claim.cpu, crate::kernel_lock::BSP);
    assert!(ONLINE[AP_ID as usize].load(Ordering::Acquire));
    assert!(!FAILED[AP_ID as usize].load(Ordering::Acquire));
    assert!(unsafe { (*core::ptr::addr_of!(STOP_BSP_FIXTURE)).is_some() });
    assert!(
        IN_FIXTURE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    );
    assert!(!BSP_STOP_COMMITTED.load(Ordering::Acquire));
    store_token(token, &BSP_STOP_SLOT, &BSP_STOP_PID, &BSP_STOP_EPOCH);
    assert_eq!(COMMAND[AP_ID as usize].swap(2, Ordering::AcqRel), 0);
    send_ipi(FIXED | u32::from(AP_IPI_VECTOR));
}

/// Executable negative control only: ask AP itself to take the forbidden
/// ordinary or RT user-return path through the real scheduler guard. A
/// correct boot exits the local VM with status 11 in either case; the BSP
/// prints distinct fixture markers. No AP ring-3 instruction is executed.
pub fn trigger_user_return_refusal(kind: UserReturnKind) {
    bsp_only();
    assert!(ONLINE[AP_ID as usize].load(Ordering::Acquire));
    assert!(!IN_FIXTURE.load(Ordering::Acquire));
    USER_REFUSAL_KIND.store(
        match kind {
            UserReturnKind::Ordinary => 1,
            UserReturnKind::RealTime => 2,
        },
        Ordering::Release,
    );
    assert_eq!(COMMAND[AP_ID as usize].swap(3, Ordering::AcqRel), 0);
    send_ipi(FIXED | u32::from(AP_IPI_VECTOR));
}

/// Queue one fixed AP critical section while the BSP still holds the BKL.
/// The AP enters no task, device, serial, or ordinary scheduler path. The
/// BSP must release the BKL before waiting for `lock_probe_count` to advance.
pub fn start_lock_probe() {
    bsp_only();
    assert!(ONLINE[AP_ID as usize].load(Ordering::Acquire));
    assert!(!FAILED[AP_ID as usize].load(Ordering::Acquire));
    assert!(!IN_FIXTURE.load(Ordering::Acquire));
    assert_eq!(REQUEST_STATE.load(Ordering::Acquire), 0);
    assert_eq!(ACK_STATE.load(Ordering::Acquire), 0);
    assert_eq!(
        COMMAND[AP_ID as usize].swap(4, Ordering::AcqRel),
        0,
        "AP command already queued"
    );
    send_ipi(FIXED | u32::from(AP_IPI_VECTOR));
}

/// Completed AP lock-probe critical sections, sampled by BSP with Acquire.
pub fn lock_probe_count() -> u64 {
    bsp_only();
    LOCK_PROBE_COUNT.load(Ordering::Acquire)
}

pub fn poll_bsp_stop_committed(token: StopToken) -> bool {
    bsp_only();
    BSP_STOP_COMMITTED.load(Ordering::Acquire)
        && StopToken {
            slot: BSP_STOP_SLOT.load(Ordering::Relaxed) as usize,
            pid: BSP_STOP_PID.load(Ordering::Relaxed),
            claim: CpuClaim {
                cpu: crate::kernel_lock::BSP,
                epoch: BSP_STOP_EPOCH.load(Ordering::Relaxed),
            },
        } == token
}

/// After BSP's own post-pivot drain/outcome receipt, release the dedicated
/// fixture slot. AP never publishes the BSP departure ACK itself.
pub fn complete_bsp_stop_fixture(token: StopToken) {
    bsp_only();
    crate::kernel_lock::assert_held(crate::kernel_lock::BSP);
    assert!(poll_bsp_stop_committed(token));
    BSP_STOP_COMMITTED.store(false, Ordering::Release);
    IN_FIXTURE.store(false, Ordering::Release);
}

fn token_from_fields(slot: &AtomicU64, pid: &AtomicU64, epoch: &AtomicU64) -> StopToken {
    StopToken {
        slot: slot.load(Ordering::Relaxed) as usize,
        pid: pid.load(Ordering::Relaxed),
        claim: CpuClaim {
            cpu: AP_ID,
            epoch: epoch.load(Ordering::Relaxed),
        },
    }
}

fn store_token(token: StopToken, slot: &AtomicU64, pid: &AtomicU64, epoch: &AtomicU64) {
    slot.store(token.slot as u64, Ordering::Relaxed);
    pid.store(token.pid, Ordering::Relaxed);
    epoch.store(token.claim.epoch, Ordering::Relaxed);
}

/// Observe the exact AP claim after its callback has claimed a real task.
/// Does not consume the token; a later stop must pass the same tuple.
pub fn poll_claimed() -> Option<StopToken> {
    bsp_only();
    CLAIMED
        .load(Ordering::Acquire)
        .then(|| token_from_fields(&REQUEST_SLOT, &REQUEST_PID, &REQUEST_EPOCH))
}

/// Hardware-resource phase, distinct from the claim. The AP calls a Release
/// gate on the victim stack only after loading victim RSP, CR3 and TSS.rsp0.
/// A stop sent before this phase is safe: the gate skips callback execution.
pub fn poll_resource_active(token: StopToken) -> bool {
    bsp_only();
    CLAIMED.load(Ordering::Acquire)
        && token_from_fields(&REQUEST_SLOT, &REQUEST_PID, &REQUEST_EPOCH) == token
        && RESOURCE_ACTIVE.load(Ordering::Acquire)
}

/// An in-handler fixture must wait for this separately from resource entry.
/// The bounded callback sets it at its named safe point under its own policy.
pub fn poll_handler_active(token: StopToken) -> bool {
    bsp_only();
    poll_resource_active(token) && HANDLER_ACTIVE.load(Ordering::Acquire)
}

/// Called only from the controlled AP callback after entering its bounded
/// handler. It may not create device/serial references or return to ring 3.
pub fn mark_handler_active() {
    if crate::cpu::is_bootstrap_processor() || !RESOURCE_ACTIVE.load(Ordering::Acquire) {
        fail_closed();
    }
    HANDLER_ACTIVE.store(true, Ordering::Release);
}

/// AP callback-side stop observation. It returns true only after the AP IPI
/// handler has Acquire-observed the exact current claim; no ACK is implied.
/// The callback must retire in bounded time and return to ap_enter_victim,
/// which leaves RSP/CR3/TSS before the ACK is published. No BKL is taken.
pub fn fixture_stop_requested(token: StopToken) -> bool {
    if crate::cpu::is_bootstrap_processor()
        || !RESOURCE_ACTIVE.load(Ordering::Acquire)
        || crate::kernel_lock::owner() == Some(crate::kernel_lock::FIXTURE_AP)
    {
        fail_closed();
    }
    match REQUEST_STATE.load(Ordering::Acquire) {
        0 | 1 => false,
        2 => {
            if token_from_fields(&REQUEST_SLOT, &REQUEST_PID, &REQUEST_EPOCH) != token {
                fail_closed();
            }
            true
        }
        _ => fail_closed(),
    }
}

/// AP fixture's bounded-wait failure path. It never calls the BSP panic,
/// serial, or device code and remains terminal even without QEMU debug-exit.
pub fn fixture_fail_closed() -> ! {
    if crate::cpu::is_bootstrap_processor() {
        panic!("AP fixture failure called on BSP");
    }
    fail_closed()
}

/// Publish the stop request and exact token with Release before sending the
/// IPI. The AP handler only observes it; it never acknowledges departure.
pub fn signal_stop(slot: usize, pid: u64, claim: CpuClaim) {
    bsp_only();
    assert_eq!(claim.cpu, AP_ID);
    assert!(ONLINE[AP_ID as usize].load(Ordering::Acquire));
    let expected = token_from_fields(&REQUEST_SLOT, &REQUEST_PID, &REQUEST_EPOCH);
    assert_eq!(
        expected,
        StopToken { slot, pid, claim },
        "AP stop claim changed"
    );
    match REQUEST_STATE.load(Ordering::Acquire) {
        1..=3 => return, // exact-token repeat never republishes or redrains
        0 => {}
        _ => panic!("invalid AP stop state"),
    }
    // An exact repeat remains valid after AP departure has cleared CLAIMED
    // and before BSP drains its ACK. Only first publication needs a live claim.
    assert!(CLAIMED.load(Ordering::Acquire));
    assert_ne!(
        ACK_STATE.load(Ordering::Acquire),
        1,
        "prior AP ACK not consumed"
    );
    REQUEST_STATE.store(1, Ordering::Release);
    send_ipi(FIXED | u32::from(AP_IPI_VECTOR));
}

/// Non-consuming snapshot for the existing repeat-stop qualification case.
/// BSP holds BKL, so the matching departure cannot be drained or reused here.
pub fn poll_ack_pending(token: StopToken) -> bool {
    bsp_only();
    crate::kernel_lock::assert_held(crate::kernel_lock::BSP);
    if ACK_STATE.load(Ordering::Acquire) != 1 {
        return false;
    }
    assert_eq!(token_from_fields(&ACK_SLOT, &ACK_PID, &ACK_EPOCH), token);
    assert_eq!(REQUEST_STATE.load(Ordering::Acquire), 3);
    assert!(!CLAIMED.load(Ordering::Acquire));
    assert!(!RESOURCE_ACTIVE.load(Ordering::Acquire));
    assert!(!HANDLER_ACTIVE.load(Ordering::Acquire));
    true
}

/// Acquire the single post-departure ACK. The caller must revalidate exact
/// PID/slot/epoch under BKL before clearing owner or reclaiming resources.
pub fn poll_departed() -> Option<StopToken> {
    bsp_only();
    if ACK_STATE
        .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return None;
    }
    Some(token_from_fields(&ACK_SLOT, &ACK_PID, &ACK_EPOCH))
}

/// BSP calls this under the BKL only after it has verified the exact ACK,
/// cleared owner, drained resources/handles, published one outcome and
/// completed the waiting caller. This is the next-fixture admission boundary.
pub fn complete_drain(token: StopToken) {
    bsp_only();
    crate::kernel_lock::assert_held(crate::kernel_lock::BSP);
    assert_eq!(ACK_STATE.load(Ordering::Acquire), 2);
    assert_eq!(REQUEST_STATE.load(Ordering::Acquire), 3);
    assert_eq!(token_from_fields(&ACK_SLOT, &ACK_PID, &ACK_EPOCH), token);
    assert!(!CLAIMED.load(Ordering::Acquire));
    assert!(!RESOURCE_ACTIVE.load(Ordering::Acquire));
    assert!(!HANDLER_ACTIVE.load(Ordering::Acquire));
    ACK_STATE.store(0, Ordering::Release);
    REQUEST_STATE.store(0, Ordering::Release);
    IN_FIXTURE.store(false, Ordering::Release);
}

pub fn failed() -> bool {
    FAILED[AP_ID as usize].load(Ordering::Acquire)
}

/// Number of distinct stop requests the AP IPI handler has observed.
/// Only a successful Requested -> Observed transition increments it.
pub fn observed_count() -> u64 {
    bsp_only();
    OBSERVED_COUNT.load(Ordering::Acquire)
}

/// Number of post-departure ACKs published by the AP fixture loop.
/// A BSP drain reads this only after acquiring the corresponding ACK.
pub fn ack_count() -> u64 {
    bsp_only();
    ACK_COUNT.load(Ordering::Acquire)
}

fn fail_closed() -> ! {
    let id = (core::arch::x86_64::__cpuid(1).ebx >> 24) as usize;
    if id < crate::cpu::MAX_CPUS {
        FAILED[id].store(true, Ordering::Release);
    }
    // Local-VM debug exit makes a fault visible even if the AP had held the
    // BKL. A silent AP halt would leave BSP lock acquisition unbounded.
    unsafe {
        asm!("cli", "out dx, eax", in("dx") 0xf4u16,
                  in("eax") 6u32, options(nomem, nostack))
    };
    loop {
        unsafe { asm!("hlt", options(nomem, nostack)) }
    }
}

#[unsafe(no_mangle)]
extern "C" fn ap_unexpected() -> ! {
    fail_closed()
}

pub fn legacy_gdt_base() -> u64 {
    core::ptr::addr_of!(AP_GDT) as u64
}

fn install_ap_descriptors() {
    let id = crate::cpu::raw_id();
    crate::cpu::prepare_identity(id);
    unsafe {
        let tss = core::ptr::addr_of_mut!(AP_TSS)
            .cast::<Tss>()
            .add(id as usize - 1);
        core::ptr::write_unaligned(
            core::ptr::addr_of_mut!((*tss).rsp).cast::<u64>(),
            entry_stack_top(id),
        );
        core::ptr::write_unaligned(
            core::ptr::addr_of_mut!((*tss).ist).cast::<u64>(),
            ipi_stack_top(id),
        );
        core::ptr::write_unaligned(
            core::ptr::addr_of_mut!((*tss).ist).cast::<u64>().add(1),
            fault_stack_top(id),
        );
        let [low, high] = tss_descriptor(tss as u64, TSS_SIZE - 1);
        let gdt = core::ptr::addr_of_mut!(AP_GDT)
            .cast::<[u64; 5]>()
            .add(id as usize - 1);
        (*gdt)[3] = low;
        (*gdt)[4] = high;
        let gdtr = DescriptorPointer {
            limit: (core::mem::size_of::<[u64; 5]>() - 1) as u16,
            base: gdt as u64,
        };
        asm!("lgdt [{}]", in(reg) &raw const gdtr,
             options(readonly, nostack, preserves_flags));
        asm!("ltr ax", in("ax") TSS_SELECTOR,
             options(nostack, preserves_flags));
        crate::cpu::publish_identity(id);
        if crate::smp_user::enabled() {
            crate::enable_write_protect();
            crate::cpu::install_tss_and_gdt();
            crate::cpu::install_ipi_stack(ipi_stack_top(id));
        }
        let idt = core::ptr::addr_of_mut!(AP_IDT)
            .cast::<[IdtGate; 256]>()
            .add(id as usize - 1);
        for vector in 0..256 {
            core::ptr::write(
                (*idt).as_mut_ptr().add(vector),
                IdtGate::new(core::ptr::addr_of!(ap_unexpected_stub) as u64, 2),
            );
        }
        core::ptr::write(
            (*idt).as_mut_ptr().add(AP_IPI_VECTOR as usize),
            IdtGate::new(core::ptr::addr_of!(ap_ipi_stub) as u64, 1),
        );
        core::ptr::write(
            (*idt).as_mut_ptr().add(AP_SPURIOUS_VECTOR as usize),
            IdtGate::new(core::ptr::addr_of!(ap_spurious_stub) as u64, 1),
        );
        let idtr = DescriptorPointer {
            limit: (core::mem::size_of::<[IdtGate; 256]>() - 1) as u16,
            base: idt as u64,
        };
        if crate::smp_user::enabled() {
            crate::smp_user::install_ap_idt(idt.cast::<u8>());
        }
        asm!("lidt [{}]", in(reg) &raw const idtr,
             options(readonly, nostack, preserves_flags));
    }
}

fn enable_ap_lapic() {
    let (low, high) = read_apic_base();
    if low & (1 << 8) != 0 || low & (1 << 10) != 0 {
        fail_closed();
    }
    if low & (1 << 11) == 0 {
        write_apic_base(low | (1 << 11), high);
    }
    let id = lapic_read(LAPIC_ID) >> 24;
    if id != u32::from(crate::cpu::id()) || crate::cpu::is_bootstrap_processor() {
        fail_closed();
    }
    // The AP accepts only its fixed mailbox IPI and spurious vector. It
    // owns no timer, legacy PIC, device IRQ or local LINT delivery.
    lapic_write(LAPIC_LVT_TIMER, LVT_MASKED);
    lapic_write(LAPIC_LVT_LINT0, LVT_MASKED);
    lapic_write(LAPIC_LVT_LINT1, LVT_MASKED);
    lapic_write(LAPIC_LVT_ERROR, LVT_MASKED);
    lapic_write(LAPIC_SVR, 0x100 | u32::from(AP_SPURIOUS_VECTOR));
}

/// Called on AP's own IST stack by the IPI stub. The Release observation
/// says only that the request was seen, never that task resources departed.
#[unsafe(no_mangle)]
extern "C" fn ap_ipi_observe() {
    if REQUEST_STATE
        .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
        && OBSERVED_COUNT.fetch_add(1, Ordering::Release) == u64::MAX
    {
        fail_closed();
    }
    lapic_write(LAPIC_EOI, 0);
}

/// Called only by the BSP's dedicated 0xf2 interrupt stub, after it has
/// saved volatile registers and FPU state. EOI only; process drain remains
/// in the BSP scheduler under BKL after the interrupt returns.
#[unsafe(no_mangle)]
pub extern "C" fn bsp_ap_ack_interrupt() {
    lapic_write(LAPIC_EOI, 0);
}

/// Called by AP assembly with IF=0 on the just-loaded victim stack. A
/// request already present at this boundary suppresses callback execution;
/// the assembly still pivots back before any ACK can be published.
#[unsafe(no_mangle)]
extern "C" fn ap_victim_entry_gate() -> u64 {
    RESOURCE_ACTIVE.store(true, Ordering::Release);
    let state = REQUEST_STATE.load(Ordering::Acquire);
    if state == 0 {
        return 1;
    }
    let lease = unsafe { (*core::ptr::addr_of!(ACTIVE_LEASE)).expect("AP lease absent") };
    let requested = token_from_fields(&REQUEST_SLOT, &REQUEST_PID, &REQUEST_EPOCH);
    if !matches!(state, 1 | 2) || requested != lease.token {
        fail_closed();
    }
    0
}

/// Called on the real victim stack by ap_enter_victim. No AP syscall or
/// ordinary scheduler entry is reachable from this callback boundary.
#[unsafe(no_mangle)]
extern "C" fn ap_fixture_run_current() {
    let lease = unsafe { (*core::ptr::addr_of!(ACTIVE_LEASE)).expect("AP fixture missing lease") };
    // The IPI may arrive between the assembly entry gate and this call.
    // Recheck the exact request at the callback boundary so a request that
    // has already been published cannot start the controlled callback.
    match REQUEST_STATE.load(Ordering::Acquire) {
        0 => {}
        1 | 2 => {
            if token_from_fields(&REQUEST_SLOT, &REQUEST_PID, &REQUEST_EPOCH) != lease.token {
                fail_closed();
            }
            return;
        }
        _ => fail_closed(),
    }
    let callback = unsafe { (*core::ptr::addr_of!(RUN_FIXTURE)).expect("AP run callback missing") };
    unsafe { callback(lease) };
}

fn wait_for_observed_stop(lease: VictimLease) {
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    unsafe { asm!("sti", options(nomem, nostack)) };
    loop {
        match REQUEST_STATE.load(Ordering::Acquire) {
            2 => {
                unsafe { asm!("cli", options(nomem, nostack)) };
                let requested = token_from_fields(&REQUEST_SLOT, &REQUEST_PID, &REQUEST_EPOCH);
                if requested != lease.token {
                    fail_closed();
                }
                return;
            }
            0 | 1 => {}
            _ => fail_closed(),
        }
        // AP owns no timer. Polling the TSC with IF=1 bounds a missing
        // request or lost IPI without relying on another wake source.
        if unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) >= STOP_TSC_BOUND {
            fail_closed();
        }
        core::hint::spin_loop();
    }
}

fn assert_ap_departed(lease: VictimLease) {
    let rsp: u64;
    let cr3: u64;
    unsafe {
        asm!("mov {}, rsp", out(reg) rsp, options(nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
    }
    let tss_ptr = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(AP_TSS_RSP0_ADDRESS)) };
    let rsp0 = unsafe { core::ptr::read_unaligned(tss_ptr as *const u64) };
    let boot = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(AP_BOOT_CR3)) };
    let ap_stack_base = core::ptr::addr_of!(AP_BOOT_STACK).cast::<Stack>() as u64;
    if rsp < ap_stack_base
        || rsp >= ap_stack_base + STACK_BYTES as u64
        || rsp >= lease.kernel_stack_base && rsp < lease.kernel_stack_top
        || cr3 != boot
        || cr3 == lease.cr3
        || rsp0 != entry_stack_top(AP_ID)
        || rsp0 >= lease.kernel_stack_base && rsp0 < lease.kernel_stack_top
    {
        fail_closed();
    }
}

fn run_one_fixture() {
    if !crate::kernel_lock::active() {
        fail_closed();
    }
    crate::kernel_lock::acquire(crate::kernel_lock::FIXTURE_AP);
    let callback =
        unsafe { (*core::ptr::addr_of!(CLAIM_FIXTURE)).expect("AP claim callback missing") };
    let Some(lease) = (unsafe { callback() }) else {
        fail_closed()
    };
    if lease.token.claim.cpu != AP_ID
        || lease.token.pid == 0
        || lease.cr3 == 0
        || lease.kernel_stack_base == 0
        || lease.kernel_stack_top <= lease.kernel_stack_base
        || lease.kernel_stack_top & 0xf != 0
    {
        fail_closed();
    }
    unsafe { core::ptr::write(core::ptr::addr_of_mut!(ACTIVE_LEASE), Some(lease)) };
    store_token(lease.token, &REQUEST_SLOT, &REQUEST_PID, &REQUEST_EPOCH);
    CLAIMED.store(true, Ordering::Release);
    crate::kernel_lock::release(crate::kernel_lock::FIXTURE_AP);
    if lease.mode == FixtureMode::EarlyStop {
        // This is the deterministic claim-to-hardware boundary case. The BSP
        // may request stop once it sees CLAIMED; AP remains on its own stack,
        // boot CR3 and entry TSS until its IPI handler observes that token.
        wait_for_observed_stop(lease);
    }
    // A request may arrive before this call or while the callback runs.
    // Only this assembly may touch the victim stack/CR3/TSS on AP.
    unsafe { ap_enter_victim(lease.cr3, lease.kernel_stack_top, lease.kernel_stack_top) };
    assert_ap_departed(lease);
    RESOURCE_ACTIVE.store(false, Ordering::Release);
    HANDLER_ACTIVE.store(false, Ordering::Release);
    if crate::kernel_lock::owner() == Some(crate::kernel_lock::FIXTURE_AP) {
        fail_closed();
    }
    // The assembly has restored AP RSP, boot CR3 and entry TSS.rsp0. Keep
    // interrupts enabled only while waiting for the IPI observation.
    wait_for_observed_stop(lease);
    unsafe { core::ptr::write(core::ptr::addr_of_mut!(ACTIVE_LEASE), None) };
    store_token(lease.token, &ACK_SLOT, &ACK_PID, &ACK_EPOCH);
    REQUEST_STATE.store(3, Ordering::Release);
    CLAIMED.store(false, Ordering::Release);
    if ACK_COUNT.fetch_add(1, Ordering::Release) == u64::MAX {
        fail_closed();
    }
    ACK_STATE.store(1, Ordering::Release);
    // Wake a BSP that is in idle `hlt`; it will Acquire the ACK and drain.
    // The fixed IPI is handled by its own BSP gate installed by the owner.
    // That BSP gate must not acquire the BKL or mutate the process table.
    send_ipi_to(0, FIXED | u32::from(BSP_ACK_VECTOR));
}

fn run_bsp_stop_fixture() {
    if !crate::kernel_lock::active() {
        fail_closed();
    }
    crate::kernel_lock::acquire(crate::kernel_lock::FIXTURE_AP);
    let token = StopToken {
        slot: BSP_STOP_SLOT.load(Ordering::Acquire) as usize,
        pid: BSP_STOP_PID.load(Ordering::Acquire),
        claim: CpuClaim {
            cpu: crate::kernel_lock::BSP,
            epoch: BSP_STOP_EPOCH.load(Ordering::Acquire),
        },
    };
    let callback =
        unsafe { (*core::ptr::addr_of!(STOP_BSP_FIXTURE)).expect("AP BSP-stop callback missing") };
    let committed = unsafe { callback(token) };
    crate::kernel_lock::release(crate::kernel_lock::FIXTURE_AP);
    if !committed {
        fail_closed();
    }
    BSP_STOP_COMMITTED.store(true, Ordering::Release);
    send_ipi_to(0, FIXED | u32::from(BSP_ACK_VECTOR));
}

fn run_lock_probe() {
    if !crate::kernel_lock::active() {
        fail_closed();
    }
    crate::kernel_lock::acquire(crate::kernel_lock::FIXTURE_AP);
    crate::kernel_lock::assert_held(crate::kernel_lock::FIXTURE_AP);
    if LOCK_PROBE_COUNT.fetch_add(1, Ordering::Release) == u64::MAX {
        fail_closed();
    }
    crate::kernel_lock::release(crate::kernel_lock::FIXTURE_AP);
    send_ipi_to(0, FIXED | u32::from(BSP_ACK_VECTOR));
}

/// The low trampoline calls this after entering long mode on AP_BOOT_STACK.
#[unsafe(no_mangle)]
extern "C" fn ap_kernel_main() -> ! {
    unsafe { asm!("cli", options(nomem, nostack)) };
    let id = (core::arch::x86_64::__cpuid(1).ebx >> 24) as u8;
    if id == 0 || id as usize >= crate::cpu::count() {
        fail_closed();
    }
    install_ap_descriptors();
    enable_ap_lapic();
    crate::modern_smp::capture_topology(id as usize);
    ONLINE[id as usize].store(true, Ordering::Release);
    loop {
        match COMMAND[id as usize].swap(0, Ordering::AcqRel) {
            0 => unsafe { asm!("sti", "hlt", "cli", options(nomem, nostack)) },
            1..=3 if id != AP_ID || crate::cpu::count() != 2 => fail_closed(),
            // Global lock probe is AP1-only and consumed before scheduler entry.
            4 if id != AP_ID => fail_closed(),
            1 => run_one_fixture(),
            2 => run_bsp_stop_fixture(),
            3 => match USER_REFUSAL_KIND.load(Ordering::Acquire) {
                1 | 2 => crate::sched::ap_resume_guard_negative(),
                _ => fail_closed(),
            },
            4 => run_lock_probe(),
            5 => crate::smp_user::start_ap(),
            _ => fail_closed(),
        }
    }
}

/// The prototype command is unavailable to normal boots.
pub fn start_user_scheduler() {
    bsp_only();
    assert!(crate::smp_user::enabled());
    for id in 1..crate::cpu::count() {
        assert!(ONLINE[id].load(Ordering::Acquire));
        assert_eq!(COMMAND[id].swap(5, Ordering::AcqRel), 0);
        send_task_ipi(id as u8);
    }
}
pub fn send_task_ipi(cpu: u8) {
    assert!(crate::smp_user::enabled());
    assert!((cpu as usize) < crate::cpu::count());
    send_ipi_to(
        cpu,
        FIXED
            | if cpu != 0 {
                u32::from(AP_IPI_VECTOR)
            } else {
                u32::from(absd_kernel::interrupt_vector::BSP_STOP)
            },
    );
}
pub fn task_eoi() {
    lapic_write(LAPIC_EOI, 0);
}
