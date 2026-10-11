//! How a boot ends. The default suite evaluates every runtime counter and
//! the reclamation of frames, cells, and pipes; shell/fuzz policy validates
//! the userspace init that launched and collected the selected child.

use crate::sched::{
    BootMode, KERNEL_STACK_BYTES, boot_mode, cells, now, object_tables_empty, pipes, stats, table,
};
use crate::serial;
use crate::vm;
use absd_kernel::layout::{USER_HEAP_PAGES, USER_STACK_MAX_PAGES, USER_STACK_PAGES};
use absd_kernel::process::MAX_PROCESSES;

/// Set by `machine_restart`: a boot that ends well resets the machine
/// instead of halting it.
static mut RESTART_ARMED: bool = false;
pub(crate) fn arm_restart() {
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(RESTART_ARMED), true) };
}

/// The end of a boot whose accounting passed: a restart if one was armed,
/// otherwise the halt (QEMU's debug-exit with the success code). A failed
/// boot never restarts; it halts with its failure code.
fn end_boot() -> ! {
    if unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RESTART_ARMED)) } {
        serial::write("MACHINE RESTART\n");
        crate::machine_reset()
    }
    crate::exit_qemu(0)
}

/// Generous per-process frame ceiling used only to bound the stress check.
const FRAMES_PER_PROCESS_BOUND: usize = 24;

const MIN_STRESS_SPAWNS: u64 = 200;

/// The boot fails if any kernel stack came within this margin of overflow.
const KERNEL_STACK_MARGIN: u64 = 2048;

/// Evaluates the whole boot once no process can run. The kernel-owned init
/// process must have exited cleanly and every process-owned frame must have
/// been returned.
pub unsafe fn finish_process_suite() -> ! {
    if crate::smp_user::enabled() && crate::smp_user::standalone() {
        crate::smp_user::finish();
    }
    crate::smp_user::pressure_finish();

    unsafe {
        crate::sched::flush_rt_trace();
        let stats = stats();
        let frames = vm::frames();
        let table = table();
        let allocated = frames.allocated_frames();
        if matches!(
            boot_mode(),
            BootMode::External
                | BootMode::Durable
                | BootMode::NetProbe
                | BootMode::RtTest
                | BootMode::RtClass
                | BootMode::SmpLifecycle
                | BootMode::SmpCreatedStop
        ) {
            let label = match boot_mode() {
                BootMode::Durable => "DURABLE",
                BootMode::NetProbe => "NET",
                BootMode::RtTest => "RT",
                BootMode::RtClass => "RTC",
                BootMode::SmpLifecycle => "SMP-LIFECYCLE",
                BootMode::SmpCreatedStop => "SMP-CREATED-STOP",
                _ => "EXTERNAL",
            };
            serial::write(label);
            serial::write(" status=");
            match stats.init_status {
                Some(status) => serial::signed(status),
                None => serial::write("none"),
            }
            serial::write(" frames=");
            serial::decimal(allocated as u64);
            serial::write(" processes=");
            serial::decimal(table.occupied_count() as u64);
            serial::write(" cells=");
            serial::decimal(cells().live() as u64);
            serial::write(" pipes=");
            serial::decimal(pipes().live() as u64);
            if boot_mode() == BootMode::Durable {
                let block = crate::block::stats();
                serial::write(" block_reads=");
                serial::decimal(block.reads);
                serial::write(" block_writes=");
                serial::decimal(block.writes);
                serial::write(" block_flushes=");
                serial::decimal(block.flushes);
                serial::write(" block_errors=");
                serial::decimal(block.errors);
                serial::write(" block_waits=");
                serial::decimal(block.waits);
                serial::write(" block_irqs=");
                serial::decimal(crate::block::interrupts());
                serial::write(" ticks=");
                serial::decimal(now());
            }
            serial::write("\n");
            if let Some(nic) = crate::e1000::info() {
                serial::write("NIC STATS rx_frames=");
                serial::decimal(nic.rx_frames);
                serial::write(" rx_refused=");
                serial::decimal(nic.rx_refused);
                serial::write(" rx_missed=");
                serial::decimal(nic.rx_missed);
                serial::write(" tx_frames=");
                serial::decimal(nic.tx_frames);
                serial::write(" tx_refused=");
                serial::decimal(nic.tx_refused);
                serial::write(" tx_errors=");
                serial::decimal(nic.tx_errors);
                serial::write(" flags=");
                serial::decimal(u64::from(nic.flags));
                serial::write("\n");
            }
            if stats.init_status
                != Some(if boot_mode() == BootMode::SmpCreatedStop {
                    -1
                } else {
                    0
                })
                || allocated != stats.frame_baseline
                || table.occupied_count() != 0
                || !object_tables_empty()
                || (crate::kernel_lock::active() && crate::smp_fixture::wait_cases() != 5)
                || (boot_mode() == BootMode::SmpLifecycle
                    && (crate::smp_fixture::drained() != 4
                        || crate::smp_fixture::stop_trace_count() != 4
                        || crate::smp_fixture::stopped_wake_refused() != 1
                        || crate::smp_fixture::mapping_pin()
                        || crate::ap::failed()))
                || (boot_mode() == BootMode::SmpCreatedStop
                    && (crate::smp_fixture::created_aborted() != 1 || crate::ap::failed()))
            {
                serial::write(label);
                serial::write(" WORKLOAD FAILED\n");
                crate::exit_qemu(1);
            }
            serial::write(label);
            serial::write(" WORKLOAD OK\n");
            if boot_mode() == BootMode::SmpLifecycle {
                serial::write("SMP STOP max_fence_ticks=");
                serial::decimal(crate::smp_fixture::max_stop_fence_ticks());
                serial::write(" samples=4\n");
            }
            serial::write("ABSD BOOT OK\n");
            end_boot();
        }
        if boot_mode() == BootMode::Fuzz {
            // Init reports success only after fuzz exits normally and all
            // adopted descendants are collected.
            serial::write("FUZZ status=");
            match stats.init_status {
                Some(status) => serial::signed(status),
                None => serial::write("none"),
            }
            serial::write(" frames=");
            serial::decimal(allocated as u64);
            serial::write(" spawns=");
            serial::decimal(stats.spawns);
            serial::write(" kills=");
            serial::decimal(stats.kills);
            serial::write(" refused handle=");
            serial::decimal(stats.handle_refusals);
            serial::write(" pointer=");
            serial::decimal(stats.pointer_refusals);
            serial::write(" unknown=");
            serial::decimal(stats.unknown_refusals);
            serial::write("\n");
            if stats.init_status != Some(0)
                || allocated != stats.frame_baseline
                || table.occupied_count() != 0
                || !object_tables_empty()
                || stats.unknown_refusals == 0
                || stats.handle_refusals == 0
                || stats.pointer_refusals == 0
            {
                serial::write("FUZZ FAILED\n");
                crate::exit_qemu(1);
            }
            serial::write("FUZZ OK\n");
            serial::write("ABSD BOOT OK\n");
            end_boot();
        }
        if boot_mode() == BootMode::Hostile {
            // Init reports success only after every hostile case was contained
            // and both witnesses finished; the counters pin the boot's exact
            // fault/kill/refusal totals (docs/HOSTILE-USERSPACE.md).
            serial::write("HOSTILE status=");
            match stats.init_status {
                Some(status) => serial::signed(status),
                None => serial::write("none"),
            }
            serial::write(" frames=");
            serial::decimal(allocated as u64);
            serial::write(" faults=");
            serial::decimal(stats.faults);
            serial::write(" kills=");
            serial::decimal(stats.kills);
            serial::write(" preempts=");
            serial::decimal(stats.preempts);
            serial::write(" refused unknown=");
            serial::decimal(stats.unknown_refusals);
            serial::write(" pointer=");
            serial::decimal(stats.pointer_refusals);
            serial::write(" handle=");
            serial::decimal(stats.handle_refusals);
            serial::write(" wait=");
            serial::decimal(stats.wait_refusals);
            serial::write(" spawn=");
            serial::decimal(stats.spawn_refusals);
            serial::write(" map=");
            serial::decimal(stats.map_refusals);
            serial::write(" cell=");
            serial::decimal(stats.cell_refusals);
            serial::write(" pipe=");
            serial::decimal(stats.pipe_refusals);
            serial::write(" timeouts=");
            serial::decimal(stats.timeouts);
            serial::write("\n");
            // Twelve fatal cases, thirty-two crash/relaunch cycles, and two
            // mapped-fault cases fault; twenty-one kills (the flood, thirteen
            // fork-bomb children, and the lifecycle/kill cases); the battery
            // refuses exactly seventeen bad pointers and a hundred thousand
            // invalid numbers; the state-machine spike pins every remaining
            // refusal class (docs/HOSTILE-USERSPACE.md).
            if stats.init_status != Some(0)
                || allocated != stats.frame_baseline
                || table.occupied_count() != 0
                || !object_tables_empty()
                || stats.faults != 46
                || stats.kills != 21
                || stats.preempts < 2
                || stats.unknown_refusals < 100_004
                || stats.pointer_refusals != 17
                || stats.handle_refusals != 33
                || stats.wait_refusals != 2
                || stats.spawn_refusals != 1
                || stats.map_refusals != 12
                || stats.cell_refusals != 1
                || stats.pipe_refusals != 1
                || stats.timeouts != 2
            {
                serial::write("HOSTILE FAILED\n");
                crate::exit_qemu(1);
            }
            serial::write("HOSTILE OK\n");
            serial::write("ABSD BOOT OK\n");
            end_boot();
        }
        if boot_mode() == BootMode::FpuTest {
            // Init reports success only after both isolation tasks kept their
            // own MXCSR/XMM state across every switch, the unmasked SIMD
            // exception case faulted on vector 19, and each post-teardown
            // witness saw the kernel's default control state. The counters
            // pin the boot: exactly one fault (the #XM case) and one kill
            // (the dirty-loop teardown case), with real preemption
            // (docs/HOSTILE-USERSPACE.md).
            serial::write("FPU status=");
            match stats.init_status {
                Some(status) => serial::signed(status),
                None => serial::write("none"),
            }
            serial::write(" frames=");
            serial::decimal(allocated as u64);
            serial::write(" faults=");
            serial::decimal(stats.faults);
            serial::write(" kills=");
            serial::decimal(stats.kills);
            serial::write(" preempts=");
            serial::decimal(stats.preempts);
            serial::write(" peer_preempts=");
            serial::decimal(stats.fpu_peer_preempts);
            serial::write("\n");
            if stats.init_status != Some(0)
                || allocated != stats.frame_baseline
                || table.occupied_count() != 0
                || !object_tables_empty()
                || stats.faults != 1
                || stats.kills != 1
                || stats.fpu_peer_preempts < 2
            {
                serial::write("FPU FAILED\n");
                crate::exit_qemu(1);
            }
            serial::write("FPU OK\n");
            serial::write("ABSD BOOT OK\n");
            end_boot();
        }
        if boot_mode() == BootMode::Shell {
            // Init reports success only after shell exits normally and all
            // adopted descendants are collected.
            serial::write("SHELL SESSION status=");
            match stats.init_status {
                Some(status) => serial::signed(status),
                None => serial::write("none"),
            }
            serial::write(" frames=");
            serial::decimal(allocated as u64);
            serial::write(" console_reads=");
            serial::decimal(stats.console_reads);
            serial::write("/");
            serial::decimal(stats.console_waits);
            serial::write(" dropped=");
            serial::decimal(serial::input_dropped());
            serial::write("\n");
            if stats.init_status != Some(0)
                || allocated != stats.frame_baseline
                || table.occupied_count() != 0
                || !object_tables_empty()
                || stats.console_waits == 0
                || serial::input_dropped() != 0
            {
                serial::write("SHELL SESSION FAILED\n");
                crate::exit_qemu(1);
            }
            serial::write("SHELL SESSION OK\n");
            serial::write("ABSD BOOT OK\n");
            end_boot();
        }
        serial::write("FRAMES baseline=");
        serial::decimal(stats.frame_baseline as u64);
        serial::write(" peak=");
        serial::decimal(frames.peak_allocated() as u64);
        serial::write(" final=");
        serial::decimal(allocated as u64);
        serial::write(" spawns=");
        serial::decimal(stats.spawns);
        serial::write(" reaps=");
        serial::decimal(stats.reaps);
        serial::write(" maps=");
        serial::decimal(stats.maps);
        serial::write(" unmaps=");
        serial::decimal(stats.unmaps);
        serial::write(" cells=");
        serial::decimal(cells().live() as u64);
        serial::write(" transitions=");
        serial::decimal(stats.transitions);
        serial::write("/");
        serial::decimal(stats.stale_transitions);
        serial::write(" cell_waits=");
        serial::decimal(stats.cell_waits);
        serial::write("/");
        serial::decimal(stats.cell_wakeups);
        serial::write(" pipes=");
        serial::decimal(pipes().live() as u64);
        serial::write(" pipe_io=");
        serial::decimal(stats.pipe_writes);
        serial::write("/");
        serial::decimal(stats.pipe_reads);
        serial::write(" pipe_waits=");
        serial::decimal(stats.pipe_waits);
        serial::write("/");
        serial::decimal(stats.pipe_wakeups);
        serial::write(" sleeps=");
        serial::decimal(stats.sleeps);
        serial::write(" timeouts=");
        serial::decimal(stats.timeouts);
        serial::write(" idle=");
        serial::decimal(stats.idle_entries);
        serial::write(" ticks=");
        serial::decimal(now());
        serial::write(" kstack_peak=");
        serial::decimal(stats.kernel_stack_peak);
        serial::write("/");
        serial::decimal(KERNEL_STACK_BYTES);
        serial::write("\n");
        serial::write("STACK GROW pages=");
        serial::decimal(stats.stack_grows);
        serial::write("\n");
        serial::write("COUNTERS exits=");
        serial::decimal(stats.exits);
        serial::write(" faults=");
        serial::decimal(stats.faults);
        serial::write(" kills=");
        serial::decimal(stats.kills);
        serial::write(" preempts=");
        serial::decimal(stats.preempts);
        serial::write(" writes=");
        serial::decimal(stats.writes);
        serial::write(" refused unknown=");
        serial::decimal(stats.unknown_refusals);
        serial::write(" pointer=");
        serial::decimal(stats.pointer_refusals);
        serial::write(" handle=");
        serial::decimal(stats.handle_refusals);
        serial::write(" wait=");
        serial::decimal(stats.wait_refusals);
        serial::write(" spawn=");
        serial::decimal(stats.spawn_refusals);
        serial::write(" map=");
        serial::decimal(stats.map_refusals);
        serial::write(" init=");
        match stats.init_status {
            Some(status) => serial::signed(status),
            None => serial::write("none"),
        }
        serial::write("\n");
        let reclaimed = allocated == stats.frame_baseline
            && table.occupied_count() == 0
            && object_tables_empty();
        // The suite has one process fill its whole heap window on purpose.
        let frame_bound = if crate::smp_app_pressure::bsp_mode() {
            // These fixed kernel-owned fixtures consume reserved process
            // slots but carry a separately validated ELF/stack/table budget.
            // Keep the ordinary per-slot allowance and full heap probe intact.
            let reserved = crate::smp_user::pressure_reservation() as usize;
            let actor_frames = crate::smp_app_pressure::reserved_frames();
            let ordinary_slots = MAX_PROCESSES.checked_sub(reserved).unwrap();
            let ordinary_bound =
                ordinary_slots * FRAMES_PER_PROCESS_BOUND + USER_HEAP_PAGES as usize;
            let total_bound = ordinary_bound + actor_frames;
            serial::write("SMP BSP FRAME BOUND reserved=");
            for (name, value) in [
                ("", reserved),
                (" actor-frames=", actor_frames),
                (" ordinary-slots=", ordinary_slots),
                (" ordinary-bound=", ordinary_bound),
                (" total-bound=", total_bound),
                (" peak=", frames.peak_allocated() - stats.frame_baseline),
            ] {
                serial::write(name);
                serial::decimal(value as u64);
            }
            serial::write(" ignored=0\n");
            total_bound
        } else {
            MAX_PROCESSES * FRAMES_PER_PROCESS_BOUND + USER_HEAP_PAGES as usize
        };
        let bounded = frames.peak_allocated() - stats.frame_baseline <= frame_bound
            && stats.kernel_stack_peak + KERNEL_STACK_MARGIN <= KERNEL_STACK_BYTES;
        let lifecycle = stats.init_status == Some(0)
            && stats.spawns >= MIN_STRESS_SPAWNS
            && stats.reaps == stats.spawns
            && stats.exits + stats.faults + stats.kills == stats.spawns
            && stats.kills >= 1
            && stats.faults >= 2
            // The original process-capacity probe and the surviving-client
            // no-headroom replacement each refuse exactly one spawn.
            && stats.spawn_refusals == 2
            && stats.wait_refusals == 1
            && stats.maps >= 100
            && stats.map_refusals == 5
            && stats.transitions >= 100
            && stats.stale_transitions >= 1
            // The cell program refuses once; object-capacity pressure does
            // three fill/free/refill cycles with two boundaries per cycle.
            && stats.cell_refusals == 1 + 3 * 2
            // The watcher blocks only if it runs before init finishes moving
            // the cell; the timed wait is the one guaranteed cell wait.
            && stats.cell_waits >= 1
            && stats.cell_wakeups + stats.timeouts >= stats.cell_waits
            && stats.pipe_reads >= 4
            && stats.pipe_writes >= 4
            && stats.pipe_waits >= 1
            && stats.pipe_wakeups <= stats.pipe_waits
            && stats.pipe_wakeups + stats.timeouts >= stats.pipe_waits
            // Pipe-capacity pressure likewise reaches two boundaries in each
            // of three allocation/free cycles.
            && stats.pipe_refusals == 3 * 2
            && stats.sleeps >= 1
            && stats.timeouts == 13
            && stats.idle_entries >= 1;
        // stack-grow crosses nine lazy boundaries from the initial two mapped
        // pages; overflow independently maps every remaining reserved
        // page before faulting on the permanent guard.
        let stack = stats.stack_grows == 9 + (USER_STACK_MAX_PAGES - USER_STACK_PAGES) as u64;
        let abi = stats.writes >= 5
            // The fuzz-free suite's one unknown number, and init's call of
            // the retired `stop` (28).
            && stats.unknown_refusals == 1 + 1
            // Existing supervisor/unmapped/range probes contribute four;
            // hello-a adds three read-only output records (info, wait, cell);
            // the pipe-info check adds two bad record pointers and init's
            // frame-stats probe one.
            && stats.pointer_refusals == 4 + 3 + 2 + 1
            // Handle-capacity pressure adds seven refusals. Process-rights
            // checks add eight, including three stale handles after reap.
            // The two child-console probes each refuse one inherited read.
            // Six supervised workers each prove their
            // narrowed cell rights and consumed process handle are enforced;
            // eight recovery workers each prove their consumed process handle;
            // the surviving-client workload does the same for its client,
            // nine service workers, fourteen full-capacity fillers, and
            // thirteen headroom fillers; its client also proves two denied
            // writes and each worker proves two more;
            // PID 1 proves an adopted PID is not info/kill authority, then
            // handle-pressure adoption adds one full duplicate and two
            // full-table object-creation refusals. The input-stream child
            // proves its input is read-only and captured console write-only.
            // The pipe-info check refuses an unknown and a stale handle.
            // The machine-right check refuses ten attempts in init (a
            // right outside the kind; stop and restart through the wrong
            // narrowed copy; recover through the stop-only and the
            // restart-only copy; stop and restart through the recover-only
            // copy; recover, and stop, with no handle; stop with the wrong
            // kind) and five in each of its two probe children (stop,
            // restart, and recover through init's handle value; recover and
            // stop through the handle handed to it). Neither the PID nor the
            // boot mode is consulted, so every refusal is a handle refusal.
            && stats.handle_refusals
                == 67 + 7 + 8 + 2 + 6 * 2 + 8 + (37 - 2 * crate::smp_user::pressure_reservation()) + 20 + 2 + 3 + 2 + 2 + 10 + 2 * 5
            && stats.preempts >= 2;
        if !reclaimed || !bounded || !lifecycle || !stack || !abi {
            serial::write("USER PROCESS SUITE FAILED\n");
            crate::exit_qemu(1);
        }
        serial::write("OBJECT TABLES EMPTY OK\n");
        serial::write("SYSCALL ABI OK\n");
        serial::write("USER MEMORY VALIDATION OK\n");
        serial::write("PROCESS HANDLE ISOLATION OK\n");
        serial::write("PROCESS EXIT OK\n");
        serial::write("PROCESS FAULT ISOLATION OK\n");
        serial::write("USER PREEMPTION OK\n");
        serial::write("SPAWN OK\n");
        serial::write("SPAWN BOUNDED OK\n");
        serial::write("REAP OK\n");
        serial::write("PROCESS RECLAIM OK\n");
        serial::write("PROCESS STRESS OK\n");
        serial::write("USER PROCESSES OK\n");
        serial::write("USER SCHEDULER OK\n");
        serial::write("ABSD BOOT OK\n");
        end_boot()
    }
}
