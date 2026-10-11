//! CPU-owned execution storage. Installed private GDT geometry locates the
//! immutable logical identity; bootstrap alone derives it from hardware.
//! Ring-3 may reload GS, so identity does not depend on a GS/SWAPGS contract.

use absd_kernel::arch::{TSS_SELECTOR, TSS_SIZE, tss_descriptor};
use absd_kernel::process::{FpuState, SAVED_FRAME_WORDS};
use core::arch::asm;
use core::mem::offset_of;

pub const MAX_CPUS: usize = 6;
#[unsafe(no_mangle)]
pub static AP_CPU_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(2);
pub fn count() -> usize {
    AP_CPU_COUNT.load(core::sync::atomic::Ordering::Acquire) as usize
}
pub fn mask() -> u8 {
    (1u8 << count()) - 1
}
pub fn configure_count(count: usize) {
    assert!(
        crate::smp_user::enabled()
            && cfg!(feature = "smp-scheduler-test")
            && is_bootstrap_processor()
    );
    assert!(matches!(count, 2 | 4 | 6));
    AP_CPU_COUNT.store(count as u32, core::sync::atomic::Ordering::Release);
}
pub const LOCAL_BYTES: usize = core::mem::size_of::<CpuLocal>();
pub const NO_TASK: usize = usize::MAX;
const ENTRY_STACK_BYTES: usize = 16 * 1024;
const REPORT_STACK_BYTES: usize = 8 * 1024;
const DOUBLE_FAULT_STACK_BYTES: usize = 16 * 1024;
const TRANSITION_STACK_BYTES: usize = 16 * 1024;

#[repr(C, align(16))]
struct Stack<const N: usize>([u8; N]);

#[repr(C, packed)]
struct TaskStateSegment {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    io_map_base: u16,
}

impl TaskStateSegment {
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

#[repr(C, align(16))]
pub struct CpuLocal {
    logical_cpu_id: u8,
    identity_ready: core::sync::atomic::AtomicBool,
    current: usize,
    pending_preempt: u64,
    user_fpu: FpuState,
    serial_fpu: FpuState,
    tss: TaskStateSegment,
    gdt: [u64; 7],
    breakpoint_seen: u8,
    page_fault_seen: u8,
    double_fault_seen: u8,
    kernel_fault_expected: u8,
    reporting: u8,
    entry_stack: Stack<ENTRY_STACK_BYTES>,
    report_stack: Stack<REPORT_STACK_BYTES>,
    double_fault_stack: Stack<DOUBLE_FAULT_STACK_BYTES>,
    transition_stack: Stack<TRANSITION_STACK_BYTES>,
    return_frame: [u64; SAVED_FRAME_WORDS],
}

#[unsafe(no_mangle)]
pub static mut BSP_CPU_LOCAL: CpuLocal = CpuLocal::empty();
#[unsafe(no_mangle)]
pub static mut AP_USER_CPU_LOCAL: [CpuLocal; MAX_CPUS - 1] =
    [const { CpuLocal::empty() }; MAX_CPUS - 1];

impl CpuLocal {
    const fn empty() -> Self {
        Self {
            logical_cpu_id: u8::MAX,
            identity_ready: core::sync::atomic::AtomicBool::new(false),
            current: NO_TASK,
            pending_preempt: 0,
            user_fpu: FpuState([0; 512]),
            serial_fpu: FpuState([0; 512]),
            tss: TaskStateSegment::EMPTY,
            gdt: [
                0,
                0x00af9a000000ffff,
                0x00af92000000ffff,
                0,
                0,
                0x00affa000000ffff,
                0x00aff2000000ffff,
            ],
            breakpoint_seen: 0,
            page_fault_seen: 0,
            double_fault_seen: 0,
            kernel_fault_expected: 0,
            reporting: 0,
            entry_stack: Stack([0; ENTRY_STACK_BYTES]),
            report_stack: Stack([0; REPORT_STACK_BYTES]),
            double_fault_stack: Stack([0; DOUBLE_FAULT_STACK_BYTES]),
            transition_stack: Stack([0; TRANSITION_STACK_BYTES]),
            return_frame: [0; SAVED_FRAME_WORDS],
        }
    }
}

pub const ID_OFFSET: usize = offset_of!(CpuLocal, logical_cpu_id);
pub const ID_READY_OFFSET: usize = offset_of!(CpuLocal, identity_ready);
pub const GDT_OFFSET: usize = offset_of!(CpuLocal, gdt);
pub const USER_FPU_OFFSET: usize = offset_of!(CpuLocal, user_fpu);
pub const SERIAL_FPU_OFFSET: usize = offset_of!(CpuLocal, serial_fpu);
pub const BREAKPOINT_SEEN_OFFSET: usize = offset_of!(CpuLocal, breakpoint_seen);
pub const PAGE_FAULT_SEEN_OFFSET: usize = offset_of!(CpuLocal, page_fault_seen);
pub const DOUBLE_FAULT_SEEN_OFFSET: usize = offset_of!(CpuLocal, double_fault_seen);
pub const KERNEL_FAULT_EXPECTED_OFFSET: usize = offset_of!(CpuLocal, kernel_fault_expected);
pub const TSS_RSP0_OFFSET: usize = offset_of!(CpuLocal, tss) + offset_of!(TaskStateSegment, rsp);
pub const ENTRY_STACK_TOP_OFFSET: usize = offset_of!(CpuLocal, entry_stack) + ENTRY_STACK_BYTES;
pub const REPORT_STACK_TOP_OFFSET: usize = offset_of!(CpuLocal, report_stack) + REPORT_STACK_BYTES;
pub const TRANSITION_STACK_TOP_OFFSET: usize =
    offset_of!(CpuLocal, transition_stack) + TRANSITION_STACK_BYTES;
pub const RETURN_FRAME_OFFSET: usize = offset_of!(CpuLocal, return_frame);

#[repr(C, packed)]
struct DescriptorPointer {
    limit: u16,
    base: u64,
}

/// Exact CPU storage pointer; identity-only access does not authorize AP user
/// storage. Callers of `local()` retain the qualification-mode refusal.
fn storage(id: u8) -> *mut CpuLocal {
    if id == 0 {
        core::ptr::addr_of_mut!(BSP_CPU_LOCAL)
    } else {
        unsafe {
            core::ptr::addr_of_mut!(AP_USER_CPU_LOCAL)
                .cast::<CpuLocal>()
                .add(id as usize - 1)
        }
    }
}

fn descriptor() -> DescriptorPointer {
    let mut pointer = DescriptorPointer { limit: 0, base: 0 };
    unsafe {
        asm!("sgdt [{}]", in(reg) &raw mut pointer, options(nostack, preserves_flags));
    }
    pointer
}

fn anchor(pointer: DescriptorPointer) -> absd_kernel::arch::CpuAnchor {
    absd_kernel::arch::cpu_anchor(
        pointer.base,
        pointer.limit,
        unsafe { core::ptr::addr_of!((*storage(0)).gdt) as u64 },
        unsafe { core::ptr::addr_of!((*storage(1)).gdt) as u64 },
        LOCAL_BYTES as u64,
        crate::ap::legacy_gdt_base(),
        count(),
        MAX_CPUS,
    )
}

/// Cannot use console/panic: their ownership assertions need this identity.
fn invalid_identity() -> ! {
    // Separate direct diagnostic channel; never invokes console/lock identity.
    unsafe {
        asm!("cli", "out dx, al", in("dx") 0xe9u16, in("al") b'I', options(nostack));
    }
    unsafe {
        asm!("cli", "out dx, eax", in("dx") 0xf4u16, in("eax") 3u32, options(nostack));
    }
    loop {
        unsafe { asm!("hlt", options(nomem, nostack)) }
    }
}

pub fn raw_id() -> u8 {
    if raw_is_bootstrap_processor() {
        0
    } else {
        let id = (core::arch::x86_64::__cpuid(1).ebx >> 24) as u8;
        if id == 0 || id as usize >= count() {
            invalid_identity();
        }
        id
    }
}

fn logical_id() -> u8 {
    use absd_kernel::arch::CpuAnchor;
    use core::sync::atomic::Ordering;
    match anchor(descriptor()) {
        CpuAnchor::Cpu(id) => unsafe {
            let cpu = storage(id);
            if !(*cpu).identity_ready.load(Ordering::Acquire)
                || core::ptr::read_volatile(core::ptr::addr_of!((*cpu).logical_cpu_id)) != id
            {
                invalid_identity();
            }
            id
        },
        CpuAnchor::Invalid => invalid_identity(),
        CpuAnchor::Unknown => {
            let id = raw_id();
            // Only before this CPU's first private descriptor installation.
            if unsafe { (*storage(id)).identity_ready.load(Ordering::Acquire) } {
                invalid_identity();
            }
            id
        }
    }
}

pub fn id() -> u8 {
    logical_id()
}

fn local() -> *mut CpuLocal {
    let id = id();
    assert!(
        id == 0 || crate::smp_user::enabled(),
        "AP CPU-local user state outside test boot"
    );
    storage(id)
}

#[cfg(feature = "smp-scheduler-test")]
static IDENTITY_CONTROL: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

#[cfg(feature = "smp-scheduler-test")]
pub fn configure_identity_control(value: u8) {
    assert!(crate::smp_user::enabled() && value <= 3 && value != 0);
    assert_eq!(
        IDENTITY_CONTROL.swap(value, core::sync::atomic::Ordering::AcqRel),
        0
    );
}

/// Initialization is the sole identity writer. A later private5 -> private7
/// rebind preserves the same immutable metadata and readiness publication.
pub fn prepare_identity(id: u8) {
    if raw_id() != id {
        invalid_identity();
    }
    unsafe {
        let field = core::ptr::addr_of_mut!((*storage(id)).logical_cpu_id);
        let previous = core::ptr::read_volatile(field);
        if previous == u8::MAX {
            core::ptr::write_volatile(field, id);
        } else if previous != id {
            invalid_identity();
        }
    }
}

pub fn publish_identity(id: u8) {
    #[cfg(feature = "smp-scheduler-test")]
    if id == 1 {
        match IDENTITY_CONTROL.load(core::sync::atomic::Ordering::Acquire) {
            1 => unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!((*storage(id)).logical_cpu_id),
                    0,
                );
            },
            2 => unsafe {
                // Cross-wire the AP's staged installation to the valid BSP anchor.
                // Independent raw identity + expected anchor must reject it before admission.
                let pointer = DescriptorPointer {
                    limit: 55,
                    base: core::ptr::addr_of!((*storage(0)).gdt) as u64,
                };
                asm!("lgdt [{}]", in(reg) &raw const pointer, options(readonly, nostack, preserves_flags));
            },
            3 => return, // Subsequent private-anchor consumption must reject not-ready.
            _ => {}
        }
    }
    if raw_id() != id || anchor(descriptor()) != absd_kernel::arch::CpuAnchor::Cpu(id) {
        invalid_identity();
    }
    unsafe {
        let cpu = storage(id);
        if core::ptr::read_volatile(core::ptr::addr_of!((*cpu).logical_cpu_id)) != id {
            invalid_identity();
        }
        (*cpu)
            .identity_ready
            .store(true, core::sync::atomic::Ordering::Release);
    }
}

pub fn install_ipi_stack(top: u64) {
    unsafe {
        core::ptr::write_unaligned(
            core::ptr::addr_of_mut!((*local()).tss.ist)
                .cast::<u64>()
                .add(1),
            top,
        );
    }
}

pub fn current() -> usize {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*local()).current)) }
}

pub fn set_current(index: usize) {
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*local()).current), index) }
}

pub fn set_pending_preempt(value: bool) {
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*local()).pending_preempt),
            u64::from(value),
        )
    }
}

pub fn take_pending_preempt() -> bool {
    unsafe {
        let field = core::ptr::addr_of_mut!((*local()).pending_preempt);
        let value = core::ptr::read_volatile(field) != 0;
        core::ptr::write_volatile(field, 0);
        value
    }
}

pub fn user_fpu() -> *mut FpuState {
    unsafe { core::ptr::addr_of_mut!((*local()).user_fpu) }
}

pub fn entry_stack_top() -> u64 {
    unsafe { core::ptr::addr_of!((*local()).entry_stack) as u64 + ENTRY_STACK_BYTES as u64 }
}

pub fn tss_rsp0() -> u64 {
    unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*local()).tss.rsp).cast::<u64>()) }
}

pub fn set_tss_rsp0(value: u64) {
    unsafe {
        core::ptr::write_unaligned(
            core::ptr::addr_of_mut!((*local()).tss.rsp).cast::<u64>(),
            value,
        )
    }
}

pub fn on_cpu_stack(rsp: u64) -> bool {
    let local = local();
    unsafe {
        for (base, size) in [
            (
                core::ptr::addr_of!((*local).entry_stack) as u64,
                ENTRY_STACK_BYTES,
            ),
            (
                core::ptr::addr_of!((*local).transition_stack) as u64,
                TRANSITION_STACK_BYTES,
            ),
        ] {
            if rsp >= base && rsp < base + size as u64 {
                return true;
            }
        }
    }
    false
}

pub fn arm_kernel_fault() {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*local()).kernel_fault_expected), 1)
    }
}

pub fn page_fault_seen() -> bool {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*local()).page_fault_seen)) != 0 }
}

pub fn clear_breakpoint_seen() {
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*local()).breakpoint_seen), 0) }
}

pub fn breakpoint_seen() -> bool {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*local()).breakpoint_seen)) != 0 }
}

pub fn begin_fault_report() -> bool {
    unsafe {
        let field = core::ptr::addr_of_mut!((*local()).reporting);
        if core::ptr::read_volatile(field) != 0 {
            return false;
        }
        core::ptr::write_volatile(field, 1);
        true
    }
}

/// Bit 8 of IA32_APIC_BASE identifies the BSP. The controlled kernel-only AP
/// has separate CPL0 entry state and no ordinary user-return path.
pub fn is_bootstrap_processor() -> bool {
    let id = id();
    id == 0
}

pub fn raw_is_bootstrap_processor() -> bool {
    if core::arch::x86_64::__cpuid(1).edx & (1 << 9) == 0 {
        return true;
    }
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") 0x1bu32,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack)
        );
    }
    let _ = high;
    absd_kernel::arch::apic_base_is_bsp(low)
}

pub fn refuse_application_processor() -> ! {
    unsafe {
        asm!("cli", "out dx, eax", in("dx") 0xf4u16, in("eax") 5u32, options(nostack));
    }
    loop {
        unsafe { asm!("hlt", options(nomem, nostack)) }
    }
}

pub fn install_tss_and_gdt() {
    let id = raw_id();
    assert!(
        id == 0 || crate::smp_user::enabled(),
        "AP user descriptors outside test boot"
    );
    prepare_identity(id);
    unsafe {
        let cpu = storage(id);
        let tss = core::ptr::addr_of_mut!((*cpu).tss);
        core::ptr::write_unaligned(
            core::ptr::addr_of_mut!((*tss).rsp).cast::<u64>(),
            core::ptr::addr_of!((*cpu).entry_stack) as u64 + ENTRY_STACK_BYTES as u64,
        );
        core::ptr::write_unaligned(
            core::ptr::addr_of_mut!((*tss).ist).cast::<u64>(),
            core::ptr::addr_of!((*cpu).double_fault_stack) as u64 + DOUBLE_FAULT_STACK_BYTES as u64,
        );
        (*tss).io_map_base = TSS_SIZE as u16;
        let [low, high] = tss_descriptor(tss as u64, TSS_SIZE - 1);
        (*cpu).gdt[3] = low;
        (*cpu).gdt[4] = high;
        let pointer = DescriptorPointer {
            limit: (core::mem::size_of::<[u64; 7]>() - 1) as u16,
            base: core::ptr::addr_of!((*cpu).gdt) as u64,
        };
        asm!("lgdt [{}]", in(reg) &raw const pointer, options(readonly, nostack, preserves_flags));
        asm!("ltr ax", in("ax") TSS_SELECTOR, options(nostack, preserves_flags));
    }
    publish_identity(id);
}
