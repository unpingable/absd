#![no_std]
#![no_main]

#[cfg(feature = "ap-startup")]
compile_error!("SMP_SERIALIZATION_LIFECYCLE refuses generic AP startup");

#[cfg(feature = "ap-userspace")]
compile_error!("SMP_SERIALIZATION_LIFECYCLE refuses AP userspace");

mod ap;
#[path = "arch/x86_64/runtime.rs"]
mod arch_runtime;
mod ata;
mod block;
mod cpu;
mod e1000;
mod framebuffer;
mod kernel_lock;
mod mmio;
mod modern_smp;
mod nvme;
mod nvme_check;
mod pci;
mod sched;
mod serial;
mod smp_app_pressure;
mod smp_app_scale;
mod smp_bench;
mod smp_fixture;
mod smp_fpu;
mod smp_leaf_measure;
mod smp_measure;
mod smp_nway;
mod smp_startup;
mod smp_timer;
mod smp_user;
mod suite;
mod survey;
mod syscalls;
mod vm;

use absd_kernel::arch::{DOUBLE_FAULT_IST, interrupt_gate_options};
use absd_kernel::memory::{
    ENTRY_PRESENT, ENTRY_WRITABLE, Frame, FrameAllocator, FrameError, FrameOwner, FrameState, Page,
    PageTableEntry, TinyHeap,
};
use core::arch::asm;
use core::ffi::c_void;
use core::fmt::Write;
use core::panic::PanicInfo;
use serial::{Serial, write as serial_write};

core::arch::global_asm!(
    include_str!("cpu_identity.S"),
    include_str!("smp_epoch.S"),
    include_str!("boot.S"),
    cpu_local_bytes = const crate::cpu::LOCAL_BYTES,
    cpu_gdt = const crate::cpu::GDT_OFFSET,
    cpu_identity_id = const crate::cpu::ID_OFFSET,
    cpu_identity_ready = const crate::cpu::ID_READY_OFFSET,
    cpu_user_fpu = const cpu::USER_FPU_OFFSET,
    cpu_serial_fpu = const cpu::SERIAL_FPU_OFFSET,
    cpu_breakpoint_seen = const cpu::BREAKPOINT_SEEN_OFFSET,
    cpu_page_fault_seen = const cpu::PAGE_FAULT_SEEN_OFFSET,
    cpu_double_fault_seen = const cpu::DOUBLE_FAULT_SEEN_OFFSET,
    cpu_kernel_fault_expected = const cpu::KERNEL_FAULT_EXPECTED_OFFSET,
    cpu_tss_rsp0 = const cpu::TSS_RSP0_OFFSET,
    cpu_entry_stack_top = const cpu::ENTRY_STACK_TOP_OFFSET,
    cpu_report_stack_top = const cpu::REPORT_STACK_TOP_OFFSET,
    cpu_transition_stack_top = const cpu::TRANSITION_STACK_TOP_OFFSET,
    cpu_return_frame = const cpu::RETURN_FRAME_OFFSET,
    options(att_syntax)
);

const DEBUG_EXIT: u16 = 0xf4;
/// Program catalog index of the kernel-started init process.
const INIT_PROGRAM: usize = 0;

#[unsafe(no_mangle)]
static timer_ticks: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    framebuffer::fault_colors();
    serial_write("ABSD PANIC: ");
    let _ = write!(Serial, "{info}");
    serial_write("\n");
    exit_qemu(1)
}

// The host Rust target's `core` archive retains this landing-pad symbol even
// with `panic = abort`; a freestanding kernel deliberately has no unwinder.
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}

// The fixed-capacity allocator initializes arrays. With no libc in this
// freestanding binary, provide the compiler's ordinary byte-copy helpers.
// Safety for all three: the compiler only emits calls with valid, correctly
// sized pointers, exactly as it would for a C library implementation.
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

#[cfg(debug_assertions)]
#[inline(always)]
pub fn debug_assert_interrupts_disabled() {
    let rflags: u64;
    unsafe {
        asm!("pushfq", "pop {}", out(reg) rflags, options(preserves_flags));
    }
    debug_assert_eq!(rflags & (1 << 9), 0, "user kernel entry left IF set");
}

#[cfg(not(debug_assertions))]
#[inline(always)]
pub const fn debug_assert_interrupts_disabled() {}

fn enable_write_protect() {
    unsafe {
        let mut cr0: u64;
        asm!("mov {}, cr0", out(reg) cr0, options(nostack, preserves_flags));
        // Keep supervisor writes subject to page-table permissions too.
        cr0 |= 1 << 16;
        asm!("mov cr0, {}", in(reg) cr0, options(nostack, preserves_flags));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(multiboot_info: *const u8) -> ! {
    if !cpu::is_bootstrap_processor() {
        cpu::refuse_application_processor();
    }
    enable_write_protect();
    serial::init();
    let total_size = unsafe { core::ptr::read_unaligned(multiboot_info.cast::<u32>()) };
    let bench = has_command_line(multiboot_info, total_size as usize, b"smp-user-bench");
    let app_scale = has_option(multiboot_info, total_size as usize, b"smp-real-app-scale");
    let app_leaf = has_option(multiboot_info, total_size as usize, b"smp-app-leaf-meter");
    assert!(
        !app_leaf || app_scale,
        "leaf meter requires closed application gate"
    );
    let app_bad_output = has_option(
        multiboot_info,
        total_size as usize,
        b"smp-app-scale-bad-output",
    );
    let app_no_timer = has_option(
        multiboot_info,
        total_size as usize,
        b"smp-app-scale-no-timer",
    );
    assert!(
        !app_scale || bench,
        "real application scale requires benchmark test mode"
    );
    assert!(
        !(app_bad_output || app_no_timer) || app_scale,
        "application controls require closed gate"
    );
    assert!(
        !(app_bad_output && app_no_timer),
        "conflicting application controls"
    );
    if app_scale {
        let allowed: [&[u8]; 10] = [
            b"smp-real-app-scale",
            b"smp-bench-up",
            b"smp-user-preempt",
            b"smp-scheduler-test",
            b"smp-cpus=2",
            b"smp-cpus=4",
            b"smp-cpus=6",
            b"smp-app-scale-bad-output",
            b"smp-app-scale-no-timer",
            b"smp-app-leaf-meter",
        ];
        for word in options(multiboot_info, total_size as usize) {
            assert!(
                allowed.contains(&word),
                "real application scale refuses unrelated option"
            );
            assert_eq!(
                options(multiboot_info, total_size as usize)
                    .filter(|other| *other == word)
                    .count(),
                1,
                "real application scale refuses duplicate option"
            );
        }
    }
    let scale = has_option(multiboot_info, total_size as usize, b"smp-scale-test");
    let meter_off = has_option(multiboot_info, total_size as usize, b"smp-scale-meter-off");
    let meter_omit = has_option(multiboot_info, total_size as usize, b"smp-scale-omit-path");
    let wrong_path = has_option(multiboot_info, total_size as usize, b"smp-scale-wrong-path");
    let short_work = has_option(multiboot_info, total_size as usize, b"smp-scale-short-work");
    assert!(!scale || bench, "scale requires benchmark qualification");
    assert!(
        !(meter_off || meter_omit || short_work || wrong_path) || scale,
        "scale controls require closed gate"
    );
    assert!(
        u8::from(meter_omit) + u8::from(short_work) + u8::from(wrong_path) <= 1
            && !(meter_off && (meter_omit || wrong_path)),
        "conflicting scale controls"
    );
    let bench_up = has_option(multiboot_info, total_size as usize, b"smp-bench-up");
    if scale {
        let allowed: [&[u8]; 10] = [
            b"smp-scale-test",
            b"smp-bench-up",
            b"smp-scale-meter-off",
            b"smp-scale-omit-path",
            b"smp-scale-short-work",
            b"smp-scale-wrong-path",
            b"smp-user-preempt",
            b"smp-scheduler-test",
            b"smp-cpus=4",
            b"smp-cpus=6",
        ];
        for word in options(multiboot_info, total_size as usize) {
            assert!(
                allowed.contains(&word) || word == b"smp-cpus=2",
                "scale refuses unrelated boot option"
            );
            assert_eq!(
                options(multiboot_info, total_size as usize)
                    .filter(|other| *other == word)
                    .count(),
                1,
                "scale refuses duplicate boot option"
            );
            assert!(
                !bench_up || !word.starts_with(b"smp-cpus="),
                "scale UP refuses CPU admission option"
            );
        }
    }
    assert!(
        !bench_up || bench,
        "benchmark UP requires qualification mode"
    );
    let user_test =
        has_command_line(multiboot_info, total_size as usize, b"smp-user-test") || bench;
    let user_pressure = has_command_line(multiboot_info, total_size as usize, b"smp-user-pressure")
        || has_option(multiboot_info, total_size as usize, b"smp-user-pressure");
    assert!(
        !has_option(multiboot_info, total_size as usize, b"smp-user-test"),
        "smp-user-test must be the qualification mode word"
    );
    if user_test || user_pressure {
        assert!(!(user_test && user_pressure), "conflicting SMP user modes");
        for mode in [
            b"smp-lifecycle".as_slice(),
            b"smp-created-stop",
            b"smp-ap-user-refuse",
            b"smp-ap-rt-refuse",
        ] {
            assert!(
                !has_command_line(multiboot_info, total_size as usize, mode)
                    && !has_option(multiboot_info, total_size as usize, mode),
                "conflicting SMP fixture"
            );
        }
        smp_user::configure();
        if bench {
            smp_bench::configure(
                bench_up,
                scale,
                meter_off,
                if meter_omit {
                    1
                } else if wrong_path {
                    3
                } else if short_work {
                    2
                } else {
                    0
                },
            );
        }
        if user_pressure {
            smp_user::pressure_mode();
        }
    }
    let ap_preempt = has_option(multiboot_info, total_size as usize, b"smp-user-preempt");
    assert!(
        !bench || bench_up || ap_preempt,
        "SMP benchmark requires AP preemption"
    );
    if ap_preempt {
        assert!(!bench_up, "UP benchmark cannot arm an AP timer");
        assert!(
            user_test || user_pressure,
            "AP timer requires qualification boot"
        );
        smp_timer::configure();
    }
    let modern = has_option(multiboot_info, total_size as usize, b"smp-scheduler-test");
    let rt_policy = has_option(multiboot_info, total_size as usize, b"smp-rt-core-policy");
    let nway = has_option(multiboot_info, total_size as usize, b"smp-nway-test");
    let multicore_startup = has_option(
        multiboot_info,
        total_size as usize,
        b"smp-startup-nway-test",
    );
    let multicore_pressure = has_option(
        multiboot_info,
        total_size as usize,
        b"smp-multicore-pressure",
    );
    let skip_app_timer = has_option(multiboot_info, total_size as usize, b"smp-app-skip-timer");
    assert!(
        !skip_app_timer || multicore_pressure,
        "app timer control requires multicore pressure"
    );
    if multicore_pressure || multicore_startup || scale || app_scale {
        let counts: [&[u8]; 3] = [b"2", b"4", b"6"];
        let mut seen = false;
        for value in options(multiboot_info, total_size as usize)
            .filter_map(|word| word.strip_prefix(b"smp-cpus="))
        {
            assert!(
                !seen && counts.contains(&value),
                "invalid or duplicate multicore CPU count"
            );
            seen = true;
        }
    }
    let four = has_option(multiboot_info, total_size as usize, b"smp-cpus=4");
    let six = has_option(multiboot_info, total_size as usize, b"smp-cpus=6");
    if four || six {
        assert!(
            modern
                && ap_preempt
                && ((user_test && (nway || scale || app_scale))
                    || (user_pressure && (multicore_pressure || multicore_startup)))
                && !(four && six),
            "N-way CPUs require closed scheduler qualification"
        );
        cpu::configure_count(if four { 4 } else { 6 });
    }

    assert!(
        !scale || (!user_pressure && !nway && !rt_policy && (bench_up || modern)),
        "scale requires closed placement mode"
    );
    assert!(
        !(meter_omit || wrong_path) || (!bench_up && !meter_off),
        "meter control requires active serialization"
    );
    let mut scheduler_mutant = 0;
    for (number, option) in [
        (1, b"smp-queue-duplicate".as_slice()),
        (2, b"smp-queue-lost"),
        (3, b"smp-migrate-early"),
    ] {
        if has_option(multiboot_info, total_size as usize, option) {
            assert!(
                modern && scheduler_mutant == 0,
                "scheduler mutant requires unique test gate"
            );
            scheduler_mutant = number;
        }
    }
    assert!(
        !scale || scheduler_mutant == 0,
        "scale refuses scheduler mutant"
    );
    assert!(
        !rt_policy || modern,
        "RT topology test requires scheduler test"
    );
    if modern {
        assert!(
            (user_test || user_pressure) && !bench_up && ap_preempt,
            "scheduler requires preemptive qualification"
        );
        let rt_active = has_command_line(multiboot_info, total_size as usize, b"rt-class")
            || has_command_line(multiboot_info, total_size as usize, b"rt-test");
        modern_smp::configure(rt_policy, rt_active, scheduler_mutant);
    }
    for (control, option) in [
        (1, b"cpu-identity-wrong-id".as_slice()),
        (2, b"cpu-identity-alias"),
        (3, b"cpu-identity-uninitialized"),
    ] {
        if has_option(multiboot_info, total_size as usize, option) {
            assert!(modern, "identity control requires scheduler qualification");
            #[cfg(feature = "smp-scheduler-test")]
            cpu::configure_identity_control(control);
            #[cfg(not(feature = "smp-scheduler-test"))]
            {
                let _ = control;
                panic!("identity control requires qualification build");
            }
        }
    }
    if app_scale {
        assert!(
            bench_up || modern,
            "real application SMP requires scheduler gate"
        );
        assert!(
            !bench_up
                || !modern
                    && !four
                    && !six
                    && !has_option(multiboot_info, total_size as usize, b"smp-cpus=2"),
            "real application UP refuses multicore placement"
        );
        assert!(
            !app_no_timer || !bench_up,
            "native timer control requires SMP"
        );
        smp_app_scale::configure(if app_bad_output {
            1
        } else if app_no_timer {
            2
        } else {
            0
        });
        if app_leaf {
            smp_leaf_measure::configure();
        }
    }
    let fpu_migration = has_option(
        multiboot_info,
        total_size as usize,
        b"smp-fpu-migration-test",
    );
    let mut fpu_mutant = 0;
    for (number, option) in [
        (1, b"smp-fpu-skip-restore".as_slice()),
        (2, b"smp-fpu-crosswire".as_slice()),
    ] {
        if has_option(multiboot_info, total_size as usize, option) {
            assert!(
                fpu_migration && fpu_mutant == 0,
                "FPU migration mutant requires closed unique gate"
            );
            fpu_mutant = number;
        }
    }
    if fpu_migration {
        assert!(
            user_test && modern && !bench && !rt_policy && scheduler_mutant == 0,
            "FPU migration requires closed preemptive scheduler test"
        );
        assert!(
            !has_option(
                multiboot_info,
                total_size as usize,
                b"handoff-negative-test"
            ),
            "FPU migration refuses unrelated handoff mutant"
        );
        smp_fpu::configure(fpu_mutant);
    }
    let nway_restore = has_option(
        multiboot_info,
        total_size as usize,
        b"smp-nway-restore-sentinel",
    );
    let nway_cancel = has_option(
        multiboot_info,
        total_size as usize,
        b"smp-nway-retained-cancel",
    );
    let nway_terminal = has_option(
        multiboot_info,
        total_size as usize,
        b"smp-nway-terminal-cpu",
    );
    assert!(
        !(nway_restore || nway_cancel || nway_terminal) || nway,
        "N-way mutant requires closed fixture"
    );
    assert!(
        u8::from(nway_restore) + u8::from(nway_cancel) + u8::from(nway_terminal) <= 1,
        "N-way requires one substitution control"
    );
    if nway {
        assert!(
            user_test && modern && !bench && !rt_policy && !fpu_migration,
            "N-way fixture requires closed preemptive scheduler test"
        );
        smp_nway::configure(nway_restore, nway_cancel, nway_terminal);
    }
    let ap_app = has_option(multiboot_info, total_size as usize, b"smp-ap-app");
    let bsp_app = has_option(multiboot_info, total_size as usize, b"smp-bsp-app");
    let frame_mutant = has_option(
        multiboot_info,
        total_size as usize,
        b"smp-bsp-frame-budget-mutant",
    );
    assert!(
        !frame_mutant || bsp_app,
        "frame budget control requires BSP application gate"
    );
    let refusal_mutant = has_option(
        multiboot_info,
        total_size as usize,
        b"smp-bsp-refusal-mutant",
    );
    assert!(
        !refusal_mutant || bsp_app,
        "refusal control requires BSP application gate"
    );
    assert!(
        !(frame_mutant && refusal_mutant),
        "conflicting BSP accounting controls"
    );
    assert!(
        !bsp_app || (multicore_pressure && !ap_app && !skip_app_timer),
        "BSP application observation requires its exclusive multicore gate"
    );
    let app_targets: [&[u8]; 5] = [b"1", b"2", b"3", b"4", b"5"];
    let targets = options(multiboot_info, total_size as usize)
        .filter_map(|word| word.strip_prefix(b"smp-app-cpu="));
    let mut app_cpu = 1;
    let mut target_count = 0;
    for value in targets {
        assert!(
            multicore_pressure && ap_app,
            "application CPU requires closed multicore app mode"
        );
        target_count += 1;
        assert_eq!(target_count, 1, "duplicate application CPU option");
        app_cpu = app_targets
            .iter()
            .position(|target| *target == value)
            .expect("invalid application CPU") as u8
            + 1;
    }
    if multicore_pressure {
        let ordinary_bsp_mode =
            has_command_line(multiboot_info, total_size as usize, b"smp-user-pressure")
                || has_command_line(multiboot_info, total_size as usize, b"external")
                || has_command_line(multiboot_info, total_size as usize, b"block-probe")
                || has_command_line(multiboot_info, total_size as usize, b"net-probe")
                || command_line_number(multiboot_info, total_size as usize, b"durable=").is_some();
        assert!(
            modern
                && user_pressure
                && ap_preempt
                && ((ap_app && has_command_line(multiboot_info, total_size as usize, b"external"))
                    || (bsp_app && ordinary_bsp_mode))
                && !user_test
                && !nway
                && !fpu_migration
                && !bench
                && !rt_policy
                && scheduler_mutant == 0
                && !has_option(multiboot_info, total_size as usize, b"smp-user-startup")
                && !has_option(multiboot_info, total_size as usize, b"served")
                && !has_option(multiboot_info, total_size as usize, b"served-fsd-exit-test"),
            "multicore pressure requires closed external AP app mode"
        );
        if bsp_app {
            smp_app_pressure::configure_bsp();
            if frame_mutant {
                smp_app_pressure::frame_mutant();
            }
            if refusal_mutant {
                smp_app_pressure::refusal_mutant();
            }
        } else {
            smp_app_pressure::configure(app_cpu, skip_app_timer);
        }
    }
    if ap_app {
        assert!(
            user_pressure
                && ap_preempt
                && has_command_line(multiboot_info, total_size as usize, b"external"),
            "native AP app requires external preemptive qualification"
        );
        smp_user::native_app_mode(app_cpu);
    }
    let startup_pressure = has_option(multiboot_info, total_size as usize, b"smp-user-startup");
    if multicore_startup {
        assert!(
            startup_pressure
                && user_pressure
                && modern
                && ap_preempt
                && (four || six)
                && !multicore_pressure
                && !ap_app
                && !bsp_app
                && !rt_policy
                && !user_test
                && !bench
                && !fpu_migration
                && !nway
                && scheduler_mutant == 0
                && (has_command_line(multiboot_info, total_size as usize, b"block-probe")
                    || has_command_line(multiboot_info, total_size as usize, b"net-probe")),
            "N-way startup requires closed pre-device qualification"
        );
        smp_app_pressure::configure_startup();
    }
    let skip_startup_map = has_option(multiboot_info, total_size as usize, b"smp-startup-skip-map");
    let fail_startup_actor = has_option(
        multiboot_info,
        total_size as usize,
        b"smp-startup-fail-actor",
    );
    if startup_pressure {
        assert!(
            user_pressure && ap_preempt,
            "startup pressure requires preemptive qualification"
        );
        assert!(
            !has_option(
                multiboot_info,
                total_size as usize,
                b"smp-device-first-poll"
            ),
            "conflicting startup fixtures"
        );
        smp_startup::configure(skip_startup_map, fail_startup_actor);
    } else {
        assert!(
            !skip_startup_map && !fail_startup_actor,
            "startup mutant requires qualification boot"
        );
    }
    if has_option(
        multiboot_info,
        total_size as usize,
        b"smp-startup-last-window-omit",
    ) {
        assert!(
            multicore_startup,
            "startup window control requires closed N-way gate"
        );
        smp_startup::omit_last_window();
    }
    if has_option(
        multiboot_info,
        total_size as usize,
        b"smp-nvme-skip-first-poll",
    ) {
        assert!(
            user_pressure
                && ap_preempt
                && !startup_pressure
                && !multicore_pressure
                && has_command_line(multiboot_info, total_size as usize, b"block-probe"),
            "NVMe first-poll control requires legacy preemptive block qualification"
        );
        smp_user::skip_nvme_first_poll();
    }
    if has_option(
        multiboot_info,
        total_size as usize,
        b"smp-capacity-ignore-reservation",
    ) {
        assert!(
            user_pressure,
            "capacity mutant requires pressure qualification"
        );
        smp_user::ignore_reservation();
    }
    for (id, name) in [
        (1, b"smp-timer-disabled".as_slice()),
        (2, b"smp-timer-no-schedule"),
        (3, b"smp-timer-no-eoi"),
        (4, b"smp-timer-rt-owner"),
        (5, b"smp-timer-fpu-restore"),
        (6, b"smp-timer-return-reset"),
    ] {
        if has_option(multiboot_info, total_size as usize, name) {
            assert!(
                ap_preempt && user_test && !fpu_migration,
                "timer mutant requires qualification boot"
            );
            smp_timer::set_mutant(id);
        }
    }
    for (id, name) in [
        (1, b"smp-user-double-claim".as_slice()),
        (2, b"smp-user-lost-wake"),
        (3, b"smp-user-early-ack"),
        (4, b"smp-user-early-finish"),
        (5, b"smp-user-serialized"),
    ] {
        if has_command_line(multiboot_info, total_size as usize, name)
            || has_option(multiboot_info, total_size as usize, name)
        {
            assert!(
                user_test && !fpu_migration,
                "SMP mutant requires qualification boot"
            );
            smp_user::set_mutant(id);
        }
    }
    if user_test
        && has_option(
            multiboot_info,
            total_size as usize,
            b"handoff-negative-test",
        )
    {
        sched::arm_handoff_negative();
    }
    let kernel_only_ap = (user_test && !bench_up)
        || user_pressure
        || has_option(multiboot_info, total_size as usize, b"smp-kernel-only")
        || has_command_line(multiboot_info, total_size as usize, b"smp-lifecycle")
        || has_command_line(multiboot_info, total_size as usize, b"smp-created-stop")
        || has_command_line(multiboot_info, total_size as usize, b"smp-ap-user-refuse")
        || has_command_line(multiboot_info, total_size as usize, b"smp-ap-rt-refuse");
    assert!(
        !bench_up || !kernel_only_ap,
        "UP benchmark refuses AP startup options"
    );
    // Served failure recovery is qualified as a UP whole-machine reset.
    // Do not start an AP in this composition until an AP quiescence/reset
    // boundary has its own qualification.
    if kernel_only_ap && has_option(multiboot_info, total_size as usize, b"served") {
        serial_write("SERVED KERNEL-ONLY AP REFUSED\n");
        exit_qemu(1);
    }
    if has_command_line(multiboot_info, total_size as usize, b"bsp-refusal-test") {
        serial_write("BSP REFUSAL FIXTURE\n");
        cpu::refuse_application_processor();
    }
    unsafe {
        HALT_ON_EXIT = has_option(multiboot_info, total_size as usize, b"halt-on-exit");
    }
    // Establish the framebuffer before the first marker so the screen
    // carries the same stream as serial from its first line.
    let framebuffer = framebuffer::init(multiboot_info, total_size as usize);
    let survey = has_command_line(multiboot_info, total_size as usize, b"survey");
    serial_write("ABSD KERNEL BOOT\n");
    serial_write("boot protocol: multiboot2\n");
    serial_write("multiboot info: ");
    serial_hex(multiboot_info as usize as u64);
    serial_write("\n");
    serial_write("multiboot bytes: ");
    serial_hex(total_size as u64);
    serial_write("\n");
    let readback = match framebuffer {
        Ok(()) => framebuffer_probe(),
        Err(reason) => {
            serial_write("framebuffer: unavailable ");
            let _ = write!(Serial, "{reason:?}");
            serial_write("\n");
            false
        }
    };
    cpu::install_tss_and_gdt();
    if !exercise_idt() {
        serial_write("IDT TEST FAILED\n");
        exit_qemu(1);
    }
    serial_write("IDT BREAKPOINT OK\n");
    if survey {
        survey::cpu();
    }
    // Single core with interrupts disabled: this is the only live reference
    // until the process runtime starts and takes over allocator access.
    let frames = unsafe { vm::frames() };
    if !load_memory_map(multiboot_info, total_size as usize, frames) {
        serial_write("memory-map: malformed or unavailable\n");
        exit_qemu(1);
    }
    if !reserve_boot_owned_memory(multiboot_info, total_size as usize, frames) {
        serial_write("memory-map: boot reservation overlaps an allocation\n");
        exit_qemu(1);
    }
    serial_write("usable memory regions: ");
    serial_hex(frames.usable_regions() as u64);
    serial_write("\n");
    serial_write("free frames: ");
    serial_decimal(frames.free_frames() as u64);
    serial_write("\n");
    let first = match frames.allocate(FrameOwner::Kernel) {
        Some(frame) => frame,
        None => {
            serial_write("frame allocation: unavailable\n");
            exit_qemu(1);
        }
    };
    let second = match frames.allocate(FrameOwner::Kernel) {
        Some(frame) => frame,
        None => {
            serial_write("frame allocation: exhausted\n");
            exit_qemu(1);
        }
    };
    serial_write("allocated frame 0: ");
    serial_hex(first.start_address());
    serial_write("\n");
    serial_write("allocated frame 1: ");
    serial_hex(second.start_address());
    serial_write("\n");
    let free_before = frames.free_frames();
    let allocated_before = frames.allocated_frames();
    if frames.free(first, FrameOwner::UserPage(1))
        != Err(FrameError::WrongOwner(FrameOwner::Kernel))
        || frames.state(first) != FrameState::Allocated(FrameOwner::Kernel)
        || frames.free_frames() != free_before
        || frames.allocated_frames() != allocated_before
    {
        serial_write("FRAME OWNER CHECK FAILED\n");
        exit_qemu(1);
    }
    serial_write("FRAME OWNER CHECK OK\n");
    inspect_paging_primitives(first);
    if !page_map_roundtrip(frames, second) {
        serial_write("PAGE MAP FAILED\n");
        exit_qemu(1);
    }
    if frames.free(first, FrameOwner::Kernel).is_err()
        || frames.free(second, FrameOwner::Kernel).is_err()
        || frames.allocated_frames() != 0
    {
        serial_write("FRAME RELEASE FAILED\n");
        exit_qemu(1);
    }
    serial_write("PAGE MAP OK\n");
    let ticks = timer_test();
    if ticks < 5 {
        serial_write("TIMER FAILED ticks=");
        serial_decimal(ticks);
        serial_write(" (no PIT interrupts through the 8259 within the TSC bound)\n");
        exit_qemu(1);
    }
    serial_write("TIMER OK ticks=");
    serial_decimal(ticks);
    serial_write("\n");
    if !heap_roundtrip(frames) || frames.allocated_frames() != 0 {
        serial_write("HEAP FAILED\n");
        exit_qemu(1);
    }
    serial_write("HEAP OK\n");
    if kernel_only_ap {
        kernel_lock::activate_on_bsp();
    }
    if survey {
        // Identity by reads only; diverges before any device is started.
        let tsc = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TIMER_TSC_CYCLES)) };
        survey::finish(multiboot_info, total_size as usize, readback, ticks, tsc);
    }
    if !block::WRITES_BUILT {
        serial_write("BLOCK WRITES DISABLED: read-only build\n");
    }
    let startup = if startup_pressure {
        smp_startup::prepare_mapping(
            has_command_line(multiboot_info, total_size as usize, b"net-probe")
                || has_option(multiboot_info, total_size as usize, b"net"),
        );
        unsafe {
            sched::init();
            assert!(sched::exhaustion_test(INIT_PROGRAM));
        }
        if multicore_startup {
            serial_write(
                "SMP STARTUP MODEL exhaustion=passed real-init=uncreated phase=before-sipi\n",
            );
        }
        start_kernel_only_ap(multiboot_info, total_size as usize);
        Some((smp_startup::begin(), mmio::snapshot()))
    } else {
        None
    };
    match block::probe(option_value(
        multiboot_info,
        total_size as usize,
        b"nvme-write=",
    )) {
        Ok(sectors) => {
            serial_write("BLOCK DEVICE OK sectors=");
            serial_decimal(sectors);
            serial_write("\n");
            serial_write(match block::backend() {
                Some(block::Backend::Nvme) => "BLOCK BACKEND nvme",
                _ => "BLOCK BACKEND ata",
            });
            serial_write(if block::writable() {
                " access=read-write\n"
            } else {
                " access=read-only\n"
            });
        }
        Err(block::BlockError::Absent) => serial_write("block: no device\n"),
        Err(error) => {
            serial_write("BLOCK DEVICE FAILED: ");
            let _ = write!(Serial, "{error:?}");
            serial_write("\n");
            exit_qemu(1);
        }
    }
    // The network interface exists for a boot only when asked for: `net` as
    // an option, or the NIC qualification boot `net-probe`.
    let net_probe = has_command_line(multiboot_info, total_size as usize, b"net-probe");
    // Qualification only: the ring fault is injected in any boot that probes
    // the NIC, so a `net` worker (the platform matrix) can be run over a
    // device that disables itself at its first ring access.
    let ring_fault = has_option(multiboot_info, total_size as usize, b"nic-ring-fault");
    if net_probe || has_option(multiboot_info, total_size as usize, b"net") {
        probe_nic(ring_fault);
    }
    if has_command_line(multiboot_info, total_size as usize, b"nvme-qualify-write") {
        nvme_check::run(nvme_check::Phase::Write);
    }
    if has_command_line(multiboot_info, total_size as usize, b"nvme-qualify-verify") {
        nvme_check::run(nvme_check::Phase::Verify);
    }
    if let Some((pid, mapping)) = startup {
        if multicore_startup {
            assert!(
                if net_probe {
                    e1000::present()
                } else {
                    block::backend().is_some()
                },
                "N-way startup selected device unavailable"
            );
        }
        smp_startup::finish(pid, mapping);
    }
    if kernel_only_ap && !startup_pressure {
        start_kernel_only_ap(multiboot_info, total_size as usize);
        if has_option(
            multiboot_info,
            total_size as usize,
            b"smp-device-first-poll",
        ) {
            smp_fixture::arm_device_first_polls();
        }
    }
    let ap_return_probe =
        if has_command_line(multiboot_info, total_size as usize, b"smp-ap-user-refuse") {
            Some(ap::UserReturnKind::Ordinary)
        } else if has_command_line(multiboot_info, total_size as usize, b"smp-ap-rt-refuse") {
            Some(ap::UserReturnKind::RealTime)
        } else {
            None
        };
    if let Some(kind) = ap_return_probe {
        serial_write(match kind {
            ap::UserReturnKind::Ordinary => "SMP AP ORDINARY RETURN REFUSAL\n",
            ap::UserReturnKind::RealTime => "SMP AP RT RETURN REFUSAL\n",
        });
        ap::trigger_user_return_refusal(kind);
        let start = unsafe { core::arch::x86_64::_rdtsc() };
        while unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start)
            < ap::FIXTURE_STOP_TSC_BOUND
        {
            core::hint::spin_loop();
        }
        serial_write("SMP AP USER RETURN WAS NOT REFUSED\n");
        exit_qemu(1);
    }
    if has_command_line(multiboot_info, total_size as usize, b"kernel-fault-test") {
        // Negative control: an unarmed kernel-mode page fault must be
        // reported as a kernel fault, never recovered from or retried.
        serial_write("KERNEL FAULT TEST\n");
        unsafe {
            trigger_page_fault();
        }
        serial_write("KERNEL FAULT NOT REPORTED\n");
        exit_qemu(1);
    }
    let fault_test = has_command_line(multiboot_info, total_size as usize, b"fault-test");
    if fault_test {
        unsafe {
            cpu::arm_kernel_fault();
            trigger_page_fault();
        }
        if !cpu::page_fault_seen() {
            serial_write("PAGE FAULT FAILED\n");
            exit_qemu(1);
        }
        serial_write("PAGE FAULT OK\n");
    }
    if has_command_line(
        multiboot_info,
        total_size as usize,
        b"handoff-negative-test",
    ) {
        serial_write("HANDOFF NEGATIVE FIXTURE\n");
        sched::arm_handoff_negative();
    }
    // The kernel chooses validation policy and passes the matching word to
    // userspace init. Init remains PID 1 and starts shell/fuzz itself.
    let shell = has_command_line(multiboot_info, total_size as usize, b"shell");
    let fuzz = has_command_line(multiboot_info, total_size as usize, b"fuzz");
    let hostile = has_command_line(multiboot_info, total_size as usize, b"hostile");
    let fpu_test = has_command_line(multiboot_info, total_size as usize, b"fpu-test");
    let external = has_command_line(multiboot_info, total_size as usize, b"external");
    let external_live = has_command_line(multiboot_info, total_size as usize, b"external-live");
    let block_probe = has_command_line(multiboot_info, total_size as usize, b"block-probe");
    let durable_step = command_line_number(multiboot_info, total_size as usize, b"durable=");
    let init_mode = if let Some(step) = durable_step {
        // The step rides above init's mode byte; a step that would lose its
        // high bits there would silently run a different step.
        if step > u64::MAX >> absd_kernel::program::INIT_STEP_SHIFT {
            serial_write("DURABLE STEP OUT OF RANGE\n");
            exit_qemu(1);
        }
        sched::set_boot_mode(sched::BootMode::Durable);
        // `fsd`: the file server holds the block handle and the worker gets
        // channels to it instead (docs/PROCESS-STARTUP.md, "File server").
        // `served`: the same composition with a lifecycle of its own (no
        // worker deadline; init ends the boot when the worker asks). Init
        // owns that policy; the kernel only forwards the word.
        let fsd = has_option(multiboot_info, total_size as usize, b"fsd");
        let served = has_option(multiboot_info, total_size as usize, b"served");
        let fsd_exit_test =
            has_option(multiboot_info, total_size as usize, b"served-fsd-exit-test");
        if fsd_exit_test && !served {
            serial_write("FSD EXIT FIXTURE NEEDS served\n");
            exit_qemu(1);
        }
        if served && !fsd {
            serial_write("SERVED BOOT NEEDS fsd\n");
            exit_qemu(1);
        }
        let mode = if served {
            if fsd_exit_test {
                absd_kernel::program::INIT_MODE_SERVED_FSD_EXIT_TEST
            } else {
                absd_kernel::program::INIT_MODE_SERVED_FSD
            }
        } else if fsd {
            absd_kernel::program::INIT_MODE_DURABLE_FSD
        } else {
            absd_kernel::program::INIT_MODE_DURABLE
        };
        absd_kernel::program::init_arg(mode, step)
    } else if block_probe {
        sched::set_boot_mode(sched::BootMode::Durable);
        absd_kernel::program::INIT_MODE_BLOCK_PROBE
    } else if net_probe {
        sched::set_boot_mode(sched::BootMode::NetProbe);
        absd_kernel::program::init_arg(
            absd_kernel::program::INIT_MODE_NET_PROBE,
            u64::from(ring_fault),
        )
    } else if external_live {
        sched::set_boot_mode(sched::BootMode::External);
        absd_kernel::program::INIT_MODE_EXTERNAL_LIVE
    } else if external {
        sched::set_boot_mode(sched::BootMode::External);
        absd_kernel::program::INIT_MODE_EXTERNAL
    } else if shell {
        sched::set_boot_mode(sched::BootMode::Shell);
        absd_kernel::program::INIT_MODE_SHELL
    } else if fuzz {
        sched::set_boot_mode(sched::BootMode::Fuzz);
        absd_kernel::program::INIT_MODE_FUZZ
    } else if has_command_line(multiboot_info, total_size as usize, b"rt-class") {
        sched::set_boot_mode(sched::BootMode::RtClass);
        absd_kernel::program::INIT_MODE_RT_CLASS
    } else if has_command_line(multiboot_info, total_size as usize, b"rt-test") {
        sched::set_boot_mode(sched::BootMode::RtTest);
        absd_kernel::program::INIT_MODE_RT_TEST
    } else if has_command_line(multiboot_info, total_size as usize, b"smp-lifecycle") {
        if !kernel_only_ap {
            serial_write("SMP LIFECYCLE REQUIRES KERNEL-ONLY AP\n");
            exit_qemu(1);
        }
        smp_fixture::install();
        sched::set_boot_mode(sched::BootMode::SmpLifecycle);
        absd_kernel::program::INIT_MODE_SMP_LIFECYCLE
    } else if has_command_line(multiboot_info, total_size as usize, b"smp-created-stop") {
        if !kernel_only_ap {
            serial_write("SMP CREATED STOP REQUIRES KERNEL-ONLY AP\n");
            exit_qemu(1);
        }
        smp_fixture::install_created_stop();
        sched::set_boot_mode(sched::BootMode::SmpCreatedStop);
        absd_kernel::program::INIT_MODE_SMP_CREATED_STOP
    } else if fpu_test {
        sched::set_boot_mode(sched::BootMode::FpuTest);
        absd_kernel::program::INIT_MODE_FPU_TEST
    } else if hostile {
        sched::set_boot_mode(sched::BootMode::Hostile);
        absd_kernel::program::INIT_MODE_HOSTILE
    } else if has_command_line(multiboot_info, total_size as usize, b"machine-recover-test") {
        absd_kernel::program::INIT_MODE_MACHINE_RECOVER_TEST
    } else {
        absd_kernel::program::INIT_MODE_SUITE
    };
    unsafe {
        if !startup_pressure {
            sched::init();
        }
        if !startup_pressure && !sched::exhaustion_test(INIT_PROGRAM) {
            exit_qemu(1);
        }
        serial_write("SPAWN EXHAUSTION OK\n");
        if let Err(error) = sched::spawn_with_arg(
            if user_test {
                absd_kernel::program::SMP_USER as usize
            } else {
                INIT_PROGRAM
            },
            absd_kernel::process::KERNEL_PARENT,
            if user_test {
                smp_user::controller_role()
            } else {
                init_mode
            },
        ) {
            serial_write("INIT SPAWN FAILED: ");
            let _ = write!(Serial, "{error:?}");
            serial_write("\n");
            exit_qemu(1);
        }
        if sched::boot_mode() == sched::BootMode::SmpLifecycle {
            smp_fixture::stopped_pipe_wake_control();
        }
        serial_write("PROCESS MODEL OK\n");
        if user_pressure {
            if smp_app_pressure::enabled() {
                for role in 200..200 + smp_app_pressure::reservation() {
                    sched::spawn_with_arg(
                        absd_kernel::program::SMP_USER as usize,
                        absd_kernel::process::KERNEL_PARENT,
                        role,
                    )
                    .expect("multicore AP pressure fixture");
                }
            } else {
                sched::spawn_with_arg(
                    absd_kernel::program::SMP_USER as usize,
                    absd_kernel::process::KERNEL_PARENT,
                    31,
                )
                .expect("AP pressure fixture");
                if ap_preempt {
                    sched::spawn_with_arg(
                        absd_kernel::program::SMP_USER as usize,
                        absd_kernel::process::KERNEL_PARENT,
                        45,
                    )
                    .expect("AP preemptible pressure fixture");
                }
            }
        }
        if (user_test || user_pressure) && !startup_pressure && !bench_up {
            ap::start_user_scheduler();
            smp_app_pressure::calibrate_before_users();
        }
        sched::start()
    }
}

/// Probes the e1000 and reports it. A NIC that is absent or refused is
/// reported by name and the boot goes on without one: nothing is granted.
/// A NIC whose link is down is granted all the same and reported as such.
fn probe_nic(inject_ring_fault: bool) {
    match e1000::probe() {
        Ok(identity) => {
            let function = identity.pci;
            serial_write("NIC CONTROLLER pci=");
            serial::hex_digits(u64::from(function.bus), 2);
            serial_write(":");
            serial::hex_digits(u64::from(function.device), 2);
            serial_write(".");
            serial::hex_digits(u64::from(function.function), 1);
            serial_write(" vendor=8086 device=100e mac=");
            for (index, byte) in identity.mac.iter().enumerate() {
                if index > 0 {
                    serial_write(":");
                }
                serial::hex_digits(u64::from(*byte), 2);
            }
            serial_write("\n");
            serial_write(if e1000::link_up() {
                "NETWORK LINK OK rx_descriptors="
            } else {
                "NIC LINK DOWN AT PROBE rx_descriptors="
            });
            serial_decimal(absd_kernel::e1000_ring::RX_DESCRIPTORS as u64);
            serial_write(" tx_descriptors=");
            serial_decimal(absd_kernel::e1000_ring::TX_DESCRIPTORS as u64);
            serial_write(" buffer_bytes=");
            serial_decimal(absd_kernel::e1000_ring::BUFFER_BYTES as u64);
            serial_write("\n");
            if inject_ring_fault && let Some(head) = e1000::inject_rx_head_fault() {
                serial_write("NIC RING FAULT INJECTED rdh=");
                serial_decimal(u64::from(head));
                serial_write("\n");
            }
        }
        Err(error) => {
            serial_write("NIC UNAVAILABLE ");
            let _ = write!(Serial, "{error:?}");
            serial_write("\n");
        }
    }
}

fn load_memory_map(info: *const u8, total_size: usize, frames: &mut FrameAllocator) -> bool {
    // Multiboot2 tags begin after the 8-byte fixed header and are eight-byte
    // aligned. Map tag type 6 carries available physical regions (type 1).
    let mut offset = 8usize;
    while offset.checked_add(8).is_some_and(|end| end <= total_size) {
        let tag = unsafe { info.add(offset) };
        let kind = unsafe { core::ptr::read_unaligned(tag.cast::<u32>()) };
        let size = unsafe { core::ptr::read_unaligned(tag.add(4).cast::<u32>()) } as usize;
        if kind == 0 {
            return frames.free_frames() != 0;
        }
        if size < 8 || offset.checked_add(size).is_none_or(|end| end > total_size) {
            return false;
        }
        if kind == 6 && size >= 16 {
            let entry_size =
                unsafe { core::ptr::read_unaligned(tag.add(8).cast::<u32>()) } as usize;
            if entry_size < 24 || !(size - 16).is_multiple_of(entry_size) {
                return false;
            }
            let mut entry = 16usize;
            while entry < size {
                let row = unsafe { tag.add(entry) };
                let base = unsafe { core::ptr::read_unaligned(row.cast::<u64>()) };
                let length = unsafe { core::ptr::read_unaligned(row.add(8).cast::<u64>()) };
                let entry_kind = unsafe { core::ptr::read_unaligned(row.add(16).cast::<u32>()) };
                if entry_kind == 1 {
                    let Some(end) = base.checked_add(length) else {
                        return false;
                    };
                    frames.add_usable(base, end);
                }
                entry += entry_size;
            }
        }
        offset += (size + 7) & !7;
    }
    false
}

/// Admit the fixed QEMU SIPI page only when the firmware memory map names
/// the whole page usable RAM and no known boot-owned span overlaps it. The
/// allocator already reserves the entire first MiB separately.
fn validated_ap_page(info: *const u8, total_size: usize) -> Option<ap::ValidatedLowPage> {
    unsafe extern "C" {
        static __kernel_start: u8;
        static __kernel_end: u8;
    }
    const PAGE: u64 = 0x7000;
    const TOP: u64 = PAGE + 4096;
    let overlaps = |start: u64, end: u64| start < TOP && PAGE < end;
    let ebda_segment = unsafe { core::ptr::read_unaligned(0x40eu64 as *const u16) };
    let ebda_start = u64::from(ebda_segment) * 16;
    if ebda_start == 0
        || TOP > ebda_start
        || overlaps(info as u64, (info as u64).checked_add(total_size as u64)?)
        || overlaps(
            core::ptr::addr_of!(__kernel_start) as u64,
            core::ptr::addr_of!(__kernel_end) as u64,
        )
    {
        return None;
    }
    let mut usable = false;
    let mut offset = 8usize;
    while offset.checked_add(8).is_some_and(|end| end <= total_size) {
        let tag = unsafe { info.add(offset) };
        let kind = unsafe { core::ptr::read_unaligned(tag.cast::<u32>()) };
        let size = unsafe { core::ptr::read_unaligned(tag.add(4).cast::<u32>()) } as usize;
        if kind == 0 {
            break;
        }
        if size < 8 || offset.checked_add(size).is_none_or(|end| end > total_size) {
            return None;
        }
        if kind == 3 {
            if size < 16 {
                return None;
            }
            let start = unsafe { core::ptr::read_unaligned(tag.add(8).cast::<u32>()) } as u64;
            let end = unsafe { core::ptr::read_unaligned(tag.add(12).cast::<u32>()) } as u64;
            if overlaps(start, end) {
                return None;
            }
        }
        if kind == 6 {
            if size < 16 {
                return None;
            }
            let stride = unsafe { core::ptr::read_unaligned(tag.add(8).cast::<u32>()) } as usize;
            if stride < 24 || !(size - 16).is_multiple_of(stride) {
                return None;
            }
            let mut row_offset = 16;
            while row_offset < size {
                let row = unsafe { tag.add(row_offset) };
                let base = unsafe { core::ptr::read_unaligned(row.cast::<u64>()) };
                let length = unsafe { core::ptr::read_unaligned(row.add(8).cast::<u64>()) };
                let entry_kind = unsafe { core::ptr::read_unaligned(row.add(16).cast::<u32>()) };
                let end = base.checked_add(length)?;
                if base <= PAGE && TOP <= end && entry_kind == 1 {
                    usable = true;
                } else if entry_kind != 1 && overlaps(base, end) {
                    return None;
                }
                row_offset += stride;
            }
        }
        offset += (size + 7) & !7;
    }
    if !usable {
        return None;
    }
    Some(unsafe { ap::ValidatedLowPage::from_verified_multiboot_page(PAGE as u32) })
}

/// All device and framebuffer MMIO mappings precede this boundary. AP code
/// shares the boot PDPT, so this gate adds only the LAPIC mapping before SIPI
/// and admits no later shared page-table edit in the controlled VM.
fn start_kernel_only_ap(info: *const u8, total_size: usize) {
    kernel_lock::assert_held(kernel_lock::BSP);
    let Some(page) = validated_ap_page(info, total_size) else {
        serial_write("SMP AP LOW PAGE REFUSED\n");
        exit_qemu(1);
    };
    if core::arch::x86_64::__cpuid(1).edx & (1 << 9) == 0 {
        serial_write("SMP APIC ABSENT\n");
        exit_qemu(1);
    }
    let (low, high): (u32, u32);
    unsafe {
        asm!("rdmsr", in("ecx") 0x1bu32, out("eax") low, out("edx") high, options(nomem, nostack));
    }
    let apic_base = (u64::from(high) << 32) | u64::from(low);
    if apic_base & (1 << 11) == 0 || apic_base & (1 << 10) != 0 {
        serial_write("SMP XAPIC REFUSED\n");
        exit_qemu(1);
    }
    let physical = apic_base & 0x000f_ffff_ffff_f000;
    let virt = match mmio::map(physical, 4096, mmio::Cache::Uncached) {
        Ok(virt) => virt,
        Err(_) => {
            serial_write("SMP LAPIC MAP REFUSED\n");
            exit_qemu(1);
        }
    };
    for id in 1..cpu::count() {
        kernel_lock::register_kernel_only_ap(id as u8);
    }
    mmio::freeze();
    ap::configure(page, virt);
    ap::start_kernel_only();
    modern_smp::topology_online();
    serial_write("SMP AP KERNEL ONLY ONLINE\n");
    smp_fixture::qualify_wait_sites();
}

fn reserve_boot_owned_memory(
    info: *const u8,
    total_size: usize,
    frames: &mut FrameAllocator,
) -> bool {
    unsafe extern "C" {
        static __kernel_start: u8;
        static __kernel_end: u8;
    }
    let kernel_start = core::ptr::addr_of!(__kernel_start) as u64;
    let kernel_end = core::ptr::addr_of!(__kernel_end) as u64;
    frames.reserve(0, 0x10_0000)
        && frames.reserve(kernel_start, kernel_end)
        && frames.reserve(info as u64, (info as u64).saturating_add(total_size as u64))
}

fn inspect_paging_primitives(frame: Frame) {
    // Construct and inspect a PML4-style entry only; the Multiboot trampoline
    // continues to own the active identity mapping until a later milestone.
    let entry = PageTableEntry::new(frame, ENTRY_PRESENT | ENTRY_WRITABLE);
    let probe = Page::containing(0xffff_8000_0000_0000);
    serial_write("paging probe pml4 index: ");
    serial_hex(probe.pml4_index() as u64);
    serial_write("\n");
    serial_write("paging entry frame: ");
    serial_hex(entry.frame().start_address());
    serial_write("\n");
}

use vm::{ADDRESS_MASK, PAGE_TABLE_ENTRIES};
const HUGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;
const HUGE_PAGE: u64 = 1 << 7;
const HUGE_ADDRESS_MASK: u64 = 0x000f_ffff_ffe0_0000;
const PAGE_TEST_ADDRESS: u64 = 0x2000_0000;
const PAGE_TEST_VALUE: u64 = 0x4153_4244_5041_4745;
const HEAP_TEST_ADDRESS: u64 = 0x2020_0000;

fn page_map_roundtrip(frames: &mut FrameAllocator, backing: Frame) -> bool {
    let Some(table_frame) = frames.allocate(FrameOwner::Kernel) else {
        return false;
    };
    unsafe extern "C" {
        static boot_pml4: u8;
    }
    unsafe {
        let pml4 = core::ptr::addr_of!(boot_pml4) as *mut u64;
        let pml4_index = ((PAGE_TEST_ADDRESS >> 39) & 0x1ff) as usize;
        let pdpt_frame = core::ptr::read_volatile(pml4.add(pml4_index)) & ADDRESS_MASK;
        if pdpt_frame == 0 {
            return false;
        }
        let pdpt = pdpt_frame as *mut u64;
        let pdpt_index = ((PAGE_TEST_ADDRESS >> 30) & 0x1ff) as usize;
        let pd_frame = core::ptr::read_volatile(pdpt.add(pdpt_index)) & ADDRESS_MASK;
        if pd_frame == 0 {
            return false;
        }
        let pd = pd_frame as *mut u64;
        let pd_index = ((PAGE_TEST_ADDRESS >> 21) & 0x1ff) as usize;
        let original_pde = core::ptr::read_volatile(pd.add(pd_index));
        if original_pde & (ENTRY_PRESENT | HUGE_PAGE) != (ENTRY_PRESENT | HUGE_PAGE) {
            return false;
        }
        let table = table_frame.start_address() as *mut u64;
        for index in 0..PAGE_TABLE_ENTRIES {
            core::ptr::write_volatile(table.add(index), 0);
        }
        let huge_base = original_pde & HUGE_ADDRESS_MASK;
        for index in 0..PAGE_TABLE_ENTRIES {
            core::ptr::write_volatile(
                table.add(index),
                (huge_base + index as u64 * 4096) | ENTRY_PRESENT | ENTRY_WRITABLE,
            );
        }
        let page_index = ((PAGE_TEST_ADDRESS & (HUGE_PAGE_SIZE - 1)) / 4096) as usize;
        core::ptr::write_volatile(
            table.add(page_index),
            backing.start_address() | ENTRY_PRESENT | ENTRY_WRITABLE,
        );
        core::ptr::write_volatile(
            pd.add(pd_index),
            table_frame.start_address() | ENTRY_PRESENT | ENTRY_WRITABLE,
        );
        invalidate_page(PAGE_TEST_ADDRESS);
        core::ptr::write_volatile(PAGE_TEST_ADDRESS as *mut u64, PAGE_TEST_VALUE);
        let read_back = core::ptr::read_volatile(PAGE_TEST_ADDRESS as *const u64);
        core::ptr::write_volatile(table.add(page_index), 0);
        invalidate_page(PAGE_TEST_ADDRESS);
        let unmapped = core::ptr::read_volatile(table.add(page_index)) == 0;
        core::ptr::write_volatile(pd.add(pd_index), original_pde);
        invalidate_page(PAGE_TEST_ADDRESS);
        read_back == PAGE_TEST_VALUE
            && unmapped
            && frames.free(table_frame, FrameOwner::Kernel).is_ok()
    }
}

fn heap_roundtrip(frames: &mut FrameAllocator) -> bool {
    let Some(backing) = frames.allocate(FrameOwner::Kernel) else {
        return false;
    };
    let Some(table_frame) = frames.allocate(FrameOwner::Kernel) else {
        return false;
    };
    unsafe extern "C" {
        static boot_pml4: u8;
    }
    unsafe {
        let pml4 = core::ptr::addr_of!(boot_pml4) as *mut u64;
        let pml4_index = ((HEAP_TEST_ADDRESS >> 39) & 0x1ff) as usize;
        let pdpt_frame = core::ptr::read_volatile(pml4.add(pml4_index)) & ADDRESS_MASK;
        if pdpt_frame == 0 {
            return false;
        }
        let pdpt = pdpt_frame as *mut u64;
        let pdpt_index = ((HEAP_TEST_ADDRESS >> 30) & 0x1ff) as usize;
        let pd_frame = core::ptr::read_volatile(pdpt.add(pdpt_index)) & ADDRESS_MASK;
        if pd_frame == 0 {
            return false;
        }
        let pd = pd_frame as *mut u64;
        let pd_index = ((HEAP_TEST_ADDRESS >> 21) & 0x1ff) as usize;
        let original_pde = core::ptr::read_volatile(pd.add(pd_index));
        if original_pde & (ENTRY_PRESENT | HUGE_PAGE) != (ENTRY_PRESENT | HUGE_PAGE) {
            return false;
        }
        let table = table_frame.start_address() as *mut u64;
        for index in 0..PAGE_TABLE_ENTRIES {
            core::ptr::write_volatile(table.add(index), 0);
        }
        let huge_base = original_pde & HUGE_ADDRESS_MASK;
        for index in 0..PAGE_TABLE_ENTRIES {
            core::ptr::write_volatile(
                table.add(index),
                (huge_base + index as u64 * 4096) | ENTRY_PRESENT | ENTRY_WRITABLE,
            );
        }
        let page_index = ((HEAP_TEST_ADDRESS & (HUGE_PAGE_SIZE - 1)) / 4096) as usize;
        core::ptr::write_volatile(
            table.add(page_index),
            backing.start_address() | ENTRY_PRESENT | ENTRY_WRITABLE,
        );
        core::ptr::write_volatile(
            pd.add(pd_index),
            table_frame.start_address() | ENTRY_PRESENT | ENTRY_WRITABLE,
        );
        invalidate_page(HEAP_TEST_ADDRESS);
        let mut heap = TinyHeap::new(HEAP_TEST_ADDRESS as usize, 4096);
        let success = match heap.allocate(64, 16) {
            Some(first) => {
                core::ptr::write_volatile(first.cast::<u64>(), 0x4845_4150_5445_5354);
                let retained =
                    core::ptr::read_volatile(first.cast::<u64>()) == 0x4845_4150_5445_5354;
                let freed = heap.free(first, 64);
                let reused = heap.allocate(64, 16).is_some_and(|second| second == first);
                retained && freed && reused
            }
            None => false,
        };
        core::ptr::write_volatile(table.add(page_index), 0);
        invalidate_page(HEAP_TEST_ADDRESS);
        let unmapped = core::ptr::read_volatile(table.add(page_index)) == 0;
        core::ptr::write_volatile(pd.add(pd_index), original_pde);
        invalidate_page(HEAP_TEST_ADDRESS);
        success
            && unmapped
            && frames.free(backing, FrameOwner::Kernel).is_ok()
            && frames.free(table_frame, FrameOwner::Kernel).is_ok()
    }
}

pub(crate) unsafe fn set_kernel_stack(stack_top: u64) {
    cpu::set_tss_rsp0(stack_top);
}

pub(crate) fn invalidate_page(address: u64) {
    unsafe {
        asm!("invlpg [{}]", in(reg) address, options(nostack, preserves_flags));
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry {
    low: u16,
    selector: u16,
    options: u16,
    middle: u16,
    high: u32,
    reserved: u32,
}
impl IdtEntry {
    const EMPTY: Self = Self {
        low: 0,
        selector: 0,
        options: 0,
        middle: 0,
        high: 0,
        reserved: 0,
    };
    const fn handler(address: u64, ist: u16) -> Self {
        Self {
            low: address as u16,
            selector: 0x08,
            options: interrupt_gate_options(ist),
            middle: (address >> 16) as u16,
            high: (address >> 32) as u32,
            reserved: 0,
        }
    }
    const fn user_handler(address: u64) -> Self {
        Self {
            low: address as u16,
            selector: 0x08,
            options: 0xee00,
            middle: (address >> 16) as u16,
            high: (address >> 32) as u32,
            reserved: 0,
        }
    }
}
#[repr(C, packed)]
struct Idtr {
    limit: u16,
    base: u64,
}
static mut IDT: [IdtEntry; 256] = [IdtEntry::EMPTY; 256];

fn exercise_idt() -> bool {
    unsafe extern "C" {
        static breakpoint_stub: u8;
        static page_fault_stub: u8;
        static double_fault_stub: u8;
        static timer_stub: u8;
        static syscall_stub: u8;
        static exception_stub_table: [u64; 32];
        static spurious_interrupt_stub: u8;
        static serial_stub: u8;
        static block_stub: u8;
        static bsp_ap_ack_stub: u8;
        static bsp_user_stop_stub: u8;
    }
    unsafe {
        let idt = core::ptr::addr_of_mut!(IDT);
        // Every CPU exception gets a gate so a ring-3 fault of any kind is
        // reported to the process instead of escalating to a double fault.
        for (vector, stub) in exception_stub_table.iter().enumerate() {
            core::ptr::write(
                (*idt).get_unchecked_mut(vector),
                IdtEntry::handler(*stub, 0),
            );
        }
        core::ptr::write(
            (*idt).get_unchecked_mut(3),
            IdtEntry::handler(core::ptr::addr_of!(breakpoint_stub) as u64, 0),
        );
        core::ptr::write(
            (*idt).get_unchecked_mut(14),
            IdtEntry::handler(core::ptr::addr_of!(page_fault_stub) as u64, 0),
        );
        core::ptr::write(
            (*idt).get_unchecked_mut(8),
            IdtEntry::handler(
                core::ptr::addr_of!(double_fault_stub) as u64,
                DOUBLE_FAULT_IST,
            ),
        );
        core::ptr::write(
            (*idt).get_unchecked_mut(32),
            IdtEntry::handler(core::ptr::addr_of!(timer_stub) as u64, 0),
        );
        core::ptr::write(
            (*idt).get_unchecked_mut(36),
            IdtEntry::handler(core::ptr::addr_of!(serial_stub) as u64, 0),
        );
        core::ptr::write(
            (*idt).get_unchecked_mut(46),
            IdtEntry::handler(core::ptr::addr_of!(block_stub) as u64, 0),
        );
        core::ptr::write(
            (*idt).get_unchecked_mut(0xf2),
            IdtEntry::handler(core::ptr::addr_of!(bsp_ap_ack_stub) as u64, 0),
        );
        core::ptr::write(
            (*idt).get_unchecked_mut(0xf3),
            IdtEntry::handler(core::ptr::addr_of!(bsp_user_stop_stub) as u64, 0),
        );
        for vector in [39, 47, 0xff] {
            core::ptr::write(
                (*idt).get_unchecked_mut(vector),
                IdtEntry::handler(core::ptr::addr_of!(spurious_interrupt_stub) as u64, 0),
            );
        }
        core::ptr::write(
            (*idt).get_unchecked_mut(0x80),
            IdtEntry::user_handler(core::ptr::addr_of!(syscall_stub) as u64),
        );
        let descriptor = Idtr {
            limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16,
            base: idt as u64,
        };
        asm!("lidt [{}]", in(reg) &raw const descriptor, options(readonly, nostack, preserves_flags));
        cpu::clear_breakpoint_seen();
        asm!("int3", options(preserves_flags));
        cpu::breakpoint_seen()
    }
}

fn timer_test() -> u64 {
    unsafe {
        timer_ticks.store(0, core::sync::atomic::Ordering::Relaxed);
        // Remap the legacy PIC away from CPU exceptions. Only IRQ0 (PIT) is
        // unmasked; the second PIC stays masked and its cascade is masked too.
        use serial::outb;
        outb(0x20, 0x11);
        outb(0xa0, 0x11);
        outb(0x21, 32);
        outb(0xa1, 40);
        outb(0x21, 4);
        outb(0xa1, 2);
        outb(0x21, 1);
        outb(0xa1, 1);
        outb(0x21, 0xee); /* IRQ0 (PIT) and IRQ4 (COM1) unmasked */
        outb(0xa1, 0xff);
        serial::enable_input();
        // PIT channel 0, lobyte/hibyte, rate generator, ~1000 Hz.
        outb(0x43, 0x36);
        outb(0x40, 0xa9);
        outb(0x40, 0x04);
        // Spin rather than halt: on hardware whose legacy PIT or PIC never
        // delivers, `hlt` would wait forever with nothing on the screen.
        // The TSC bound turns that into a visible TIMER FAILED.
        let start = core::arch::x86_64::_rdtsc();
        asm!("sti", options(nostack, preserves_flags));
        loop {
            let ticks = timer_ticks.load(core::sync::atomic::Ordering::Relaxed);
            let elapsed = core::arch::x86_64::_rdtsc().wrapping_sub(start);
            if ticks >= 5 || elapsed > TIMER_TSC_BOUND {
                asm!("cli", options(nostack, preserves_flags));
                core::ptr::write_volatile(core::ptr::addr_of_mut!(TIMER_TSC_CYCLES), elapsed);
                return ticks;
            }
            core::hint::spin_loop();
        }
    }
}

/// About five seconds of TSC at 3.4 GHz; far beyond five 1 ms PIT ticks.
const TIMER_TSC_BOUND: u64 = 1 << 34;
/// TSC cycles the timer probe waited, reported (uncalibrated) by the survey.
static mut TIMER_TSC_CYCLES: u64 = 0;

/// Draws every printable character through the ordinary console path, then
/// reads the framebuffer back and requires every pixel of every cell.
/// Returns whether the read-back matched.
fn framebuffer_probe() -> bool {
    let Some(start) = framebuffer::position() else {
        return false;
    };
    // The probe text is ASCII.
    serial_write(unsafe { core::str::from_utf8_unchecked(framebuffer::PROBE_TEXT) });
    serial_write("\n");
    let Some(summary) = framebuffer::summary() else {
        serial_write("FRAMEBUFFER CONSOLE FAILED: console disabled while drawing\n");
        return false;
    };
    match framebuffer::verify(start, framebuffer::PROBE_TEXT) {
        Ok(cells) => {
            let geometry = summary.geometry;
            serial_write("FRAMEBUFFER CONSOLE OK width=");
            serial_decimal(geometry.width as u64);
            serial_write(" height=");
            serial_decimal(geometry.height as u64);
            serial_write(" pitch=");
            serial_decimal(geometry.pitch as u64);
            serial_write(" bpp=");
            serial_decimal(geometry.bytes_per_pixel as u64 * 8);
            serial_write(" rgb=");
            for channel in [geometry.red, geometry.green, geometry.blue] {
                serial_decimal(u64::from(channel.shift));
                serial_write(":");
                serial_decimal(u64::from(channel.bits));
                serial_write(if channel == geometry.blue { "" } else { "," });
            }
            serial_write(" columns=");
            serial_decimal(summary.columns as u64);
            serial_write(" rows=");
            serial_decimal(summary.rows as u64);
            serial_write(" scale=");
            serial_decimal(summary.scale as u64);
            serial_write(" probe_row=");
            serial_decimal(start.1 as u64);
            serial_write(" cells=");
            serial_decimal(cells as u64);
            serial_write(" address=");
            serial_hex(summary.address);
            serial_write("\n");
            true
        }
        Err((column, row)) => {
            serial_write("FRAMEBUFFER CONSOLE FAILED column=");
            serial_decimal(column as u64);
            serial_write(" row=");
            serial_decimal(row as u64);
            serial_write("\n");
            false
        }
    }
}

/// The first space-separated word of the command line selects the boot
/// mode; later words are options.
fn mode_word(info: *const u8, total_size: usize) -> Option<&'static [u8]> {
    command_line(info, total_size)?
        .split(|&byte| byte == b' ')
        .find(|word| !word.is_empty())
}

fn options(info: *const u8, total_size: usize) -> impl Iterator<Item = &'static [u8]> {
    command_line(info, total_size)
        .unwrap_or(&[])
        .split(|&byte| byte == b' ')
        .filter(|word| !word.is_empty())
        .skip(1)
}

fn has_command_line(info: *const u8, total_size: usize, expected: &[u8]) -> bool {
    mode_word(info, total_size) == Some(expected)
}

fn has_option(info: *const u8, total_size: usize, name: &[u8]) -> bool {
    options(info, total_size).any(|word| word == name)
}

/// The value of the first `prefix`VALUE option word.
fn option_value(info: *const u8, total_size: usize, prefix: &[u8]) -> Option<&'static [u8]> {
    options(info, total_size).find_map(|word| word.strip_prefix(prefix))
}

/// `prefix` followed by a decimal number as the whole mode word.
fn command_line_number(info: *const u8, total_size: usize, prefix: &[u8]) -> Option<u64> {
    let line = mode_word(info, total_size)?;
    let digits = line.strip_prefix(prefix)?;
    if digits.is_empty() || digits.len() > 19 {
        return None;
    }
    let mut value = 0u64;
    for byte in digits {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
    }
    Some(value)
}

/// The Multiboot2 command line tag's bytes without the terminating NUL.
fn command_line(info: *const u8, total_size: usize) -> Option<&'static [u8]> {
    let mut offset = 8usize;
    while offset.checked_add(8).is_some_and(|end| end <= total_size) {
        let tag = unsafe { info.add(offset) };
        let kind = unsafe { core::ptr::read_unaligned(tag.cast::<u32>()) };
        let size = unsafe { core::ptr::read_unaligned(tag.add(4).cast::<u32>()) } as usize;
        if kind == 0 || size < 8 || offset.checked_add(size).is_none_or(|end| end > total_size) {
            return None;
        }
        if kind == 1 && size > 8 {
            let bytes = unsafe { core::slice::from_raw_parts(tag.add(8), size - 9) };
            return Some(bytes);
        }
        offset += (size + 7) & !7;
    }
    None
}

unsafe extern "C" {
    fn trigger_page_fault();
}

/// COM1 has received data: bank it for whichever process reads the console.
#[unsafe(no_mangle)]
pub extern "C" fn serial_input_interrupt() {
    unsafe { serial::drain_input() }
}

/// A CPU exception raised in ring 0, or a double fault: a kernel bug. Print
/// what is known and stop QEMU with a distinct status.
#[unsafe(no_mangle)]
pub extern "C" fn kernel_exception_report(vector: u64, error: u64, rip: u64) -> ! {
    // A fault while reporting must not loop through the report path again.
    if !cpu::begin_fault_report() {
        exit_qemu(2);
    }
    framebuffer::fault_colors();
    let cr2: u64;
    unsafe {
        asm!("mov {}, cr2", out(reg) cr2, options(nostack, preserves_flags));
    }
    serial_write("KERNEL FAULT vector=");
    serial_decimal(vector);
    serial_write(" error=");
    serial_hex(error);
    serial_write(" rip=");
    serial_hex(rip);
    serial_write(" cr2=");
    serial_hex(cr2);
    serial_write("\n");
    exit_qemu(2)
}

use serial::{decimal as serial_decimal, hex as serial_hex};

/// Resets the machine for `machine_restart`: first the reset control
/// register at port 0xcf9 (a hard reset on PIIX and ICH chipsets; QEMU's
/// i440fx and q35 implement it), then the 8042 keyboard controller's reset
/// line, then a triple fault (an empty IDT and a breakpoint). Under QEMU the
/// first one resets the machine, or ends QEMU when it runs with
/// `-no-reboot`. On physical hardware none of the three is tested.
pub(crate) fn machine_reset() -> ! {
    framebuffer::notice("ABSD RESTART code=", 0);
    unsafe {
        asm!("out dx, al", in("dx") 0xcf9u16, in("al") 0x02u8, options(nomem, nostack));
        asm!("out dx, al", in("dx") 0xcf9u16, in("al") 0x06u8, options(nomem, nostack));
        for _ in 0..1_000_000 {
            core::hint::spin_loop();
        }
        for _ in 0..0x1_0000 {
            let status: u8;
            asm!("in al, dx", out("al") status, in("dx") 0x64u16, options(nomem, nostack));
            if status & 2 == 0 {
                break;
            }
        }
        asm!("out dx, al", in("dx") 0x64u16, in("al") 0xfeu8, options(nomem, nostack));
        for _ in 0..1_000_000 {
            core::hint::spin_loop();
        }
        let empty = [0u8; 10];
        asm!("lidt [{}]", "int3", in(reg) empty.as_ptr(), options(nostack));
    }
    loop {
        unsafe {
            asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}

/// `halt-on-exit`: skip the debug-exit device and halt instead, as a
/// machine without one would, so the host can inspect the final screen.
static mut HALT_ON_EXIT: bool = false;

/// Ends the boot. The framebuffer alone gets a final `ABSD HALT` line (in
/// the failure colours for a nonzero code); serial output is unchanged.
/// Under QEMU the debug-exit device stops the machine; elsewhere the CPU
/// halts with the screen as the last record.
pub(crate) fn exit_qemu(code: u32) -> ! {
    let code = if code == 0 && serial::tx_dropped() != 0 {
        1
    } else {
        code
    };
    if code != 0 {
        framebuffer::fault_colors();
    }
    framebuffer::notice("ABSD HALT code=", u64::from(code));
    unsafe {
        if !core::ptr::read_volatile(core::ptr::addr_of!(HALT_ON_EXIT)) {
            asm!("out dx, eax", in("dx") DEBUG_EXIT, in("eax") ((code << 1) | 1), options(nomem, nostack));
        }
    }
    loop {
        unsafe {
            asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}
