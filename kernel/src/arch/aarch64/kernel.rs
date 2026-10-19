#![no_std]
#![no_main]
#![allow(dead_code)]
use absd_kernel::{
    arch::{ExecutionContext, FpuState},
    memory::FrameOwner,
};
use core::arch::asm;
use core::ffi::c_void;
mod fdt;
mod runtime;
#[path = "../../sched.rs"]
mod sched;
#[path = "../../syscalls.rs"]
mod syscalls;
mod virtio;
mod vm;
use runtime as arch_runtime;
mod block;
mod cpu;
mod kernel_lock;
mod nic;
mod serial;
mod suite;
use nic as nic_device;
mod litmus;
mod smp;
mod up_only;
use up_only::*;
core::arch::global_asm!(include_str!("boot.S"), cpu_entry_top=const cpu::ENTRY_TOP, cpu_transition_top=const cpu::TRANSITION_TOP, cpu_local_bytes=const cpu::LOCAL_BYTES);

static mut BOOT_ROOT: u64 = 0;
static mut UART: u64 = 0x09000000;
static mut GICD: u64 = 0;
/// GICv2: the CPU interface. GICv3: the redistributor region, and its size.
static mut GICC: u64 = 0;
static mut GICR_BYTES: u64 = 0;
static mut GIC_V3: bool = false;
/// PSCI by `smc` (firmware at EL3, or QEMU's EL2 entry) instead of `hvc`.
static mut PSCI_SMC: bool = false;
/// The exception level the boot stub entered at, in bits [3:0] (boot.S
/// stores it); bit 8 says EL2 would not clear HCR_EL2.E2H (no FEAT_E2H0),
/// which the stub's non-VHE setup does not handle.
#[unsafe(no_mangle)]
pub static mut ARM_ENTRY_EL: u64 = 0;

/// One PSCI call through the conduit the device tree named. SMCCC 1.0
/// lets the callee change x1-x3 (results) and x4-x17.
#[inline(never)]
pub unsafe fn psci(function: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let result: u64;
    unsafe {
        if PSCI_SMC {
            asm!("smc #0", inlateout("x0") function => result, inlateout("x1") a1 => _, inlateout("x2") a2 => _,
                inlateout("x3") a3 => _, out("x4") _, out("x5") _, out("x6") _, out("x7") _, out("x8") _, out("x9") _,
                out("x10") _, out("x11") _, out("x12") _, out("x13") _, out("x14") _, out("x15") _, out("x16") _,
                out("x17") _, options(nostack));
        } else {
            asm!("hvc #0", inlateout("x0") function => result, inlateout("x1") a1 => _, inlateout("x2") a2 => _,
                inlateout("x3") a3 => _, out("x4") _, out("x5") _, out("x6") _, out("x7") _, out("x8") _, out("x9") _,
                out("x10") _, out("x11") _, out("x12") _, out("x13") _, out("x14") _, out("x15") _, out("x16") _,
                out("x17") _, options(nostack));
        }
    }
    result
}
static mut CONTROLLED: bool = false;
static mut KERNEL_TABLE: u64 = 0;
#[allow(non_upper_case_globals)]
static timer_ticks: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
unsafe extern "C" {
    static __kernel_end: u8;
    static entry_stack_top: u8;
    fn arm_enter(frame: *const ExecutionContext, fp: *const FpuState, stack: u64, root: u64) -> !;
    fn arm_depart(root: u64, continuation: extern "C" fn() -> !) -> !;
}
fn read32(address: u64) -> u32 {
    unsafe { core::ptr::read_volatile(address as *const u32) }
}
fn read64(address: u64) -> u64 {
    unsafe { core::ptr::read_volatile(address as *const u64) }
}
fn write32(address: u64, value: u32) {
    unsafe {
        core::ptr::write_volatile(address as *mut u32, value);
        asm!("dsb sy", options(nostack));
    }
}
fn out(s: &str) {
    for b in s.bytes() {
        unsafe {
            while read32(UART + 0x18) & (1 << 5) != 0 {
                core::hint::spin_loop();
            }
            write32(UART, b as u32);
        }
    }
}
fn number(n: u64) {
    if n >= 10 {
        number(n / 10);
    }
    let b = [b'0' + (n % 10) as u8];
    out(core::str::from_utf8(&b).unwrap());
}
fn poweroff() -> ! {
    unsafe {
        psci(0x84000008, 0, 0, 0);
    }
    loop {
        unsafe {
            asm!("wfi");
        }
    }
}
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    out("ABSD ARM PANIC: ");
    let _ = write!(Serial, "{info}");
    out("\n");
    poweroff()
}
struct Serial;
impl core::fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        out(s);
        Ok(())
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}
#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn memcpy(
    destination: *mut c_void,
    source: *const c_void,
    count: usize,
) -> *mut c_void {
    let mut index = 0;
    while index < count {
        unsafe {
            core::ptr::write_volatile(
                destination.cast::<u8>().add(index),
                core::ptr::read_volatile(source.cast::<u8>().add(index)),
            );
        }
        index += 1;
    }
    destination
}

#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn memset(destination: *mut c_void, value: i32, count: usize) -> *mut c_void {
    let mut index = 0;
    while index < count {
        unsafe {
            core::ptr::write_volatile(destination.cast::<u8>().add(index), value as u8);
        }
        index += 1;
    }
    destination
}

#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn memcmp(left: *const c_void, right: *const c_void, count: usize) -> i32 {
    let mut index = 0;
    while index < count {
        let a = unsafe { core::ptr::read_volatile(left.cast::<u8>().add(index)) };
        let b = unsafe { core::ptr::read_volatile(right.cast::<u8>().add(index)) };
        if a != b {
            return a as i32 - b as i32;
        }
        index += 1;
    }
    0
}

/// Equality-only comparison; optimized code (the rasterizer crate) emits it
/// for slice equality.
#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn bcmp(left: *const c_void, right: *const c_void, count: usize) -> i32 {
    unsafe { memcmp(left, right, count) }
}

fn timer() {
    let freq: u64;
    unsafe {
        asm!("mrs {}, cntfrq_el0",out(reg)freq);
        asm!("msr cntv_tval_el0, {}","msr cntv_ctl_el0, {}","isb",in(reg)(freq/1000),in(reg)1u64);
    }
}
unsafe fn entry(table: u64, index: usize, value: u64) {
    unsafe {
        core::ptr::write_volatile((table as *mut u64).add(index), value);
    }
}
unsafe fn mmu() -> u64 {
    unsafe {
        let frames = vm::frames();
        let root = frames.allocate(FrameOwner::Kernel).unwrap();
        let l1 = frames.allocate(FrameOwner::Kernel).unwrap();
        vm::zero_frame(root);
        vm::zero_frame(l1);
        entry(root.0, 0, l1.0 | 3);
        entry(l1.0, 0, 1 | (1 << 10) | (1 << 53) | (1 << 54));
        entry(l1.0, 1, 0x40000000 | 1 | (1 << 10) | (3 << 8) | (1 << 2));
        enable_root(root.0);
        BOOT_ROOT = root.0;
        l1.0
    }
}
unsafe fn enable_root(root: u64) {
    unsafe {
        asm!("msr mair_el1, {}","msr tcr_el1, {}","msr ttbr0_el1, {}","dsb sy","isb",in(reg)0xff00u64,in(reg)(16u64|(1<<8)|(1<<10)|(3<<12)|(1<<23)|(2<<32)),in(reg)root);
        let mut sctlr: u64;
        asm!("mrs {}, sctlr_el1",out(reg)sctlr);
        sctlr |= 1 | (1 << 2) | (1 << 12);
        asm!("msr sctlr_el1, {}","isb",in(reg)sctlr);
    }
}
/// The interrupts this kernel takes: the virtual timer PPI 27 and SGIs 1
/// (wake) and 2 (remote stop). No SPI is used.
const GIC_LOCAL_MASK: u32 = (1 << 27) | (1 << 1) | (1 << 2);
const GICR_FRAME_BYTES: u64 = 0x20000;

unsafe fn gic_cpu() {
    unsafe {
        if GIC_V3 {
            gic3_cpu();
            return;
        }
        write32(GICD + 0x100, GIC_LOCAL_MASK);
        write32(GICC + 4, 0xff);
        write32(GICC, 1);
    }
}

/// This CPU's affinity, as GICR_TYPER[63:32] and ICC_SGI1R_EL1 encode it.
fn affinity() -> u32 {
    let mpidr: u64;
    unsafe { asm!("mrs {}, mpidr_el1", out(reg) mpidr) };
    ((mpidr & 0xff)
        | ((mpidr >> 8) & 0xff) << 8
        | ((mpidr >> 16) & 0xff) << 16
        | ((mpidr >> 32) & 0xff) << 24) as u32
}

/// GICv3, per CPU: find this CPU's redistributor frame by affinity, wake it,
/// put the local interrupts in group 1 (group 0 would arrive as FIQ, which
/// stays masked) and enable them, then the system-register CPU interface.
/// Returns the frame for the boot record.
unsafe fn gic3_cpu() -> u64 {
    unsafe {
        // The region must lie in the Device block mmu() maps (the low GiB).
        let region_end = GICC
            .checked_add(GICR_BYTES)
            .expect("GICv3 redistributor region");
        assert!(
            region_end <= 0x4000_0000,
            "GICv3 redistributor region outside the device window"
        );
        let mut frame = GICC;
        loop {
            assert!(
                frame + GICR_FRAME_BYTES <= region_end,
                "GICv3 redistributor for this CPU missing"
            );
            let typer = read64(frame + 0x08);
            // A VLPI-capable (GICv4) redistributor has a larger frame; the
            // walk would be wrong from the first one.
            assert!(
                typer & (1 << 1) == 0,
                "GICv3 redistributor with VLPIs unsupported"
            );
            if (typer >> 32) as u32 == affinity() {
                break;
            }
            assert!(
                typer & (1 << 4) == 0,
                "GICv3 redistributor for this CPU missing"
            );
            frame += GICR_FRAME_BYTES;
        }
        write32(frame + 0x14, read32(frame + 0x14) & !(1 << 1));
        let mut bound = 1_000_000u32;
        while read32(frame + 0x14) & (1 << 2) != 0 {
            bound -= 1;
            assert!(bound > 0, "GICv3 redistributor did not wake");
        }
        let sgi_base = frame + 0x10000;
        write32(sgi_base + 0x80, read32(sgi_base + 0x80) | GIC_LOCAL_MASK);
        // One explicit priority for each local interrupt (the reset value is
        // not architected), below the mask PMR opens: a byte per INTID.
        for intid in [1u64, 2, 27] {
            let word = sgi_base + 0x400 + (intid / 4) * 4;
            let shift = (intid % 4) * 8;
            write32(word, (read32(word) & !(0xff << shift)) | (0xa0 << shift));
        }
        write32(sgi_base + 0x100, GIC_LOCAL_MASK);
        let mut sre: u64;
        asm!("mrs {}, S3_0_C12_C12_5", out(reg) sre);
        asm!("msr S3_0_C12_C12_5, {}", "isb", in(reg) sre | 1);
        asm!("mrs {}, S3_0_C12_C12_5", out(reg) sre);
        assert!(sre & 1 != 0, "GICv3 system register interface not enabled");
        // EOImode 0: one end-of-interrupt write both drops priority and
        // deactivates, which gic_end relies on.
        asm!("msr S3_0_C12_C12_4, {}", in(reg) 0u64);
        asm!("msr S3_0_C4_C6_0, {}", in(reg) 0xffu64);
        asm!("msr S3_0_C12_C12_3, {}", in(reg) 0u64);
        asm!("msr S3_0_C12_C12_7, {}", "isb", in(reg) 1u64);
        frame
    }
}

/// GICv3 distributor control: write, then wait for the register write to
/// take effect (RWP).
unsafe fn gic3_distributor(control: u32) {
    unsafe {
        write32(GICD, control);
        let mut bound = 1_000_000u32;
        while read32(GICD) & (1 << 31) != 0 {
            bound -= 1;
            assert!(bound > 0, "GICv3 distributor did not settle");
        }
    }
}

/// The interrupt being taken: GICv2 from the CPU interface, GICv3 from the
/// system register.
unsafe fn gic_acknowledge() -> u32 {
    unsafe {
        if GIC_V3 {
            let iar: u64;
            asm!("mrs {}, S3_0_C12_C12_0", out(reg) iar);
            iar as u32
        } else {
            read32(GICC + 12)
        }
    }
}

unsafe fn gic_end(irq: u32) {
    unsafe {
        if GIC_V3 {
            if irq & 1023 < 1020 {
                asm!("msr S3_0_C12_C12_1, {}", in(reg) irq as u64);
            }
        } else {
            write32(GICC + 16, irq);
        }
    }
}

/// GICv3: an SGI to one CPU of affinity-cluster 0, by its Aff0 bit.
pub fn gic3_sgi(target: u8, number: u32) {
    let value = ((number as u64) << 24) | (1u64 << target);
    unsafe { asm!("dsb ishst", "msr S3_0_C12_C11_5, {}", "isb", in(reg) value) };
}

pub fn gic_is_v3() -> bool {
    unsafe { GIC_V3 }
}
#[unsafe(no_mangle)]
pub extern "C" fn arm_main(dtb: u64) -> ! {
    unsafe {
        out("ABSD ARM64 KERNEL BOOT\n");
        // Before anything can refuse: a refusal powers off through PSCI,
        // and from an EL2 entry that must be smc (an hvc would land in
        // whatever EL2 vectors were left). The tree's own answer follows.
        let entry_el = ARM_ENTRY_EL & 0xf;
        PSCI_SMC = entry_el == 2;
        assert!(entry_el <= 2, "entry at EL3 unsupported");
        assert!(
            ARM_ENTRY_EL & 0x100 == 0,
            "EL2 without FEAT_E2H0 (E2H fixed) unsupported"
        );
        assert!((0x40000000..0x60000000).contains(&dtb));
        let len = u32::from_be(core::ptr::read_unaligned((dtb + 4) as *const u32)) as usize;
        assert!((40..=2 * 1024 * 1024).contains(&len));
        let board =
            fdt::parse(core::slice::from_raw_parts(dtb as *const u8, len)).expect("virt DTB");
        smp::configure(&board);
        litmus::configure(board.early_publication);
        if board.reset {
            assert!(smp::enabled(), "reset fixture requires SMP qualification");
            suite::arm_restart();
        }
        UART = board.uart;
        GICD = board.gicd;
        GICC = board.gicc;
        GICR_BYTES = board.gic_region_bytes;
        GIC_V3 = board.gic == Some(fdt::Gic::V3);
        PSCI_SMC = board.psci == Some(fdt::Psci::Smc);
        out("ARM BOOT entry_el=");
        number(entry_el);
        out(if PSCI_SMC {
            " psci=smc\n"
        } else {
            " psci=hvc\n"
        });
        out("ARM RAM REGION base=");
        serial::hex(board.ram.0);
        out(" bytes=");
        serial::hex(board.ram.1);
        out("\n");
        let frames = vm::frames();
        frames.add_usable(board.ram.0, board.ram.0 + board.ram.1);
        assert!(frames.reserve(board.ram.0, core::ptr::addr_of!(__kernel_end) as u64));
        assert!(frames.reserve(dtb, dtb + board.dtb_bytes as u64));
        assert!(frames.free_frames() > 0);
        out("ARM RAM OK frames=");
        number(frames.free_frames() as u64);
        out("\n");
        let l1 = mmu();
        let mmfr2: u64;
        let alignment_sctlr: u64;
        asm!("mrs {}, id_aa64mmfr2_el1", out(reg) mmfr2);
        asm!("mrs {}, sctlr_el1", out(reg) alignment_sctlr);
        out("ARM ALIGNMENT CONFIG mmfr2=");
        serial::hex(mmfr2);
        out(" sctlr=");
        serial::hex(alignment_sctlr);
        out("\n");

        out("ARM MMU OK\n");
        CONTROLLED = true;
        asm!("brk #16");
        assert!(!CONTROLLED);
        out("ARM EXCEPTION OK\n");
        if GIC_V3 {
            // The distributor must be the architecture revision the tree
            // claims (GICD_PIDR2.ArchRev); then affinity routing before
            // anything per CPU, group 1 enabled after. ID_AA64PFR0_EL1.GIC
            // is reported, not required: QEMU under HVF shows the host's
            // 0 while it still serves the ICC registers by trapping them;
            // a CPU truly without the interface takes an undefined
            // instruction at the first ICC access, which is loud.
            let pfr0: u64;
            asm!("mrs {}, id_aa64pfr0_el1", out(reg) pfr0);
            let revision = (read32(GICD + 0xffe8) >> 4) & 0xf;
            assert!(
                revision == 3,
                "GIC distributor architecture revision unsupported"
            );
            gic3_distributor(1 << 4);
            let frame = gic3_cpu();
            gic3_distributor((1 << 4) | (1 << 1));
            out("ARM GIC version=3 gicd=");
            serial::hex(GICD);
            out(" gicr=");
            serial::hex(GICC);
            out(" frame=");
            serial::hex(frame);
            out(" pfr0_gic=");
            number((pfr0 >> 24) & 0xf);
            out("\n");
        } else {
            write32(GICD, 0);
            gic_cpu();
            write32(GICD, 1);
            out("ARM GIC version=2 gicd=");
            serial::hex(GICD);
            out(" gicc=");
            serial::hex(GICC);
            out("\n");
        }
        timer();
        asm!("msr daifclr, #2");
        while timer_ticks.load(core::sync::atomic::Ordering::Relaxed) < 5 {
            asm!("wfi");
        }
        asm!("msr daifset, #2");
        out("ARM TIMER OK\n");
        for base in &board.virtio[..board.virtio_count] {
            match virtio::get(*base, 8) {
                2 => {
                    block::init(*base).expect("virtio block");
                    if !block::writable() {
                        assert!(matches!(
                            block::write_sector(0, &[0x55; 512]),
                            Err(block::BlockError::ReadOnly)
                        ));
                    }
                    out("ARM VIRTIO BLOCK READY\n");
                    out("ARM BLOCK MMIO base=");
                    serial::hex(*base);
                    out("\n");
                }
                1 => {
                    nic::init(*base).expect("virtio net");
                    out("ARM VIRTIO NET READY\n");
                }
                0 => {}
                _ => panic!("unsupported virtio device"),
            }
        }
        KERNEL_TABLE = l1;
        smp::bring_up();
        sched::set_boot_mode(if block::sector_count().is_some() || nic::present() {
            sched::BootMode::Durable
        } else {
            sched::BootMode::External
        });
        sched::init();
        let pid = if smp::enabled() {
            sched::spawn_with_arg(0, 0, 9090)
        } else {
            sched::spawn(0, 0)
        }
        .expect("portable init");
        assert_eq!(pid, 1);
        out("ARM EL0 ENTER\n");
        smp::start_execution();
        sched::start()
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// Assembly supplies an exclusive, complete 800-byte saved exception frame.
pub unsafe extern "C" fn arm_exception(frame: *mut ExecutionContext, kind: u64) {
    unsafe {
        let esr: u64;
        asm!("mrs {}, esr_el1",out(reg)esr);
        if kind == 1 || kind == 3 {
            let irq = gic_acknowledge();
            let source = irq & 1023;
            smp::irq(source);
            if source == 27 {
                if cpu::is_bootstrap_processor() {
                    timer_ticks.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                }
                timer();
            }
            gic_end(irq);
            if kind == 3 {
                kernel_lock::acquire(cpu::id());
                if smp::observe_stop() {
                    sched::switch_from_frame(frame.cast(), false);
                }
                if source == 27 {
                    sched::user_timer_schedule(frame.cast());
                }
                kernel_lock::release(cpu::id());
            }
            return;
        }
        if kind == 0 && esr >> 26 == 0x3c && CONTROLLED {
            CONTROLLED = false;
            let pc = (*frame).pc() + 4;
            core::ptr::write((frame as *mut u64).add(32), pc);
            return;
        }
        if kind == 2 {
            kernel_lock::acquire(cpu::id());
        }
        if kind == 2 && esr >> 26 == 0x15 {
            syscalls::user_syscall_dispatch(frame.cast());
            kernel_lock::release(cpu::id());
            return;
        }
        if kind == 2 {
            let address: u64;
            asm!("mrs {}, far_el1",out(reg)address);
            if sched::user_stack_page_fault(frame as u64, address, esr, (*frame).stack_pointer())
                == 1
            {
                sched::bsp_pagefault_stop_guard();
                kernel_lock::release(cpu::id());
                return;
            }
            let pc = (*frame).pc();
            core::ptr::write(
                cpu::user_fpu(),
                core::ptr::read(frame.cast::<u8>().add(272).cast()),
            );
            // Abandon the task-owned stack/root before calling the terminal path.
            cpu::set_fault((esr >> 26, esr, pc));
            arm_depart(BOOT_ROOT, report_fault);
        }
        panic!("unexpected EL1 exception kind {kind} esr={esr:x}");
    }
}
extern "C" fn report_fault() -> ! {
    let (v, e, p) = cpu::fault();
    sched::user_exception(v, e, p)
}
pub fn debug_assert_interrupts_disabled() {
    let daif: u64;
    unsafe {
        asm!("mrs {}, daif",out(reg)daif);
    }
    assert_ne!(daif & (1 << 7), 0);
}
pub fn set_kernel_stack(_: u64) {}
pub fn invalidate_page(_: u64) {
    unsafe {
        asm!("dsb ishst", "tlbi vmalle1", "dsb ish", "isb");
    }
}
pub fn exit_qemu(code: u32) -> ! {
    out("ARM MACHINE STOP code=");
    number(code as u64);
    out("\n");
    poweroff()
}
pub fn machine_reset() -> ! {
    unsafe {
        psci(0x84000009, 0, 0, 0);
    }
    panic!("PSCI reset returned")
}
