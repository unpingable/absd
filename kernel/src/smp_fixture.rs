//! Four bounded, kernel-owned AP lifecycle cases.  These are qualification
//! fixtures, not an AP process scheduler or a userspace admission interface.

use crate::{ap, cpu, kernel_lock, sched, serial, syscalls, vm};
use absd_kernel::handle::{Object, RIGHT_READ, RIGHT_WRITE};
use absd_kernel::layout::{USER_HEAP_BASE, USER_STACK_TOP};
use absd_kernel::process::{KERNEL_PARENT, ProcessState, StopState, TransferWait, WaitKind};
use absd_kernel::syscall::FRAME_RAX;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

static EXPECTED_PID: AtomicU64 = AtomicU64::new(0);
static EXPECTED_SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);
static NEXT_MODE: AtomicUsize = AtomicUsize::new(0);
static DRAINED: AtomicUsize = AtomicUsize::new(0);
static MAPPING_PIN: AtomicBool = AtomicBool::new(false);
static CREATED_PID: AtomicU64 = AtomicU64::new(0);
static CREATED_ABORTED: AtomicUsize = AtomicUsize::new(0);
static STOPPED_WAKE_REFUSED: AtomicUsize = AtomicUsize::new(0);
static WAIT_CASES: AtomicUsize = AtomicUsize::new(0);
static DEVICE_FIRST_POLL_ARMED: AtomicUsize = AtomicUsize::new(0);
static STOP_REQUEST_PID: AtomicU64 = AtomicU64::new(0);
static STOP_REQUEST_SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);
static STOP_REQUEST_EPOCH: AtomicU64 = AtomicU64::new(0);
static STOP_REQUEST_TICK: AtomicU64 = AtomicU64::new(0);
static STOP_OBSERVED_BASE: AtomicU64 = AtomicU64::new(0);
static STOP_ACK_BASE: AtomicU64 = AtomicU64::new(0);
static STOP_TRACE_COUNT: AtomicUsize = AtomicUsize::new(0);
static MAX_STOP_FENCE_TICKS: AtomicU64 = AtomicU64::new(0);

pub fn stop_trace_count() -> usize {
    STOP_TRACE_COUNT.load(Ordering::Acquire)
}

pub fn max_stop_fence_ticks() -> u64 {
    MAX_STOP_FENCE_TICKS.load(Ordering::Acquire)
}

/// BSP's exact BKL-owned request linearization. AP never reads PIT ticks;
/// the sampled request/fence interval is a measurement, not a hard bound.
pub fn record_remote_request(token: ap::StopToken) {
    kernel_lock::assert_held(kernel_lock::BSP);
    assert_eq!(token.claim.cpu, kernel_lock::FIXTURE_AP);
    assert_eq!(STOP_REQUEST_PID.load(Ordering::Acquire), 0);
    STOP_REQUEST_SLOT.store(token.slot, Ordering::Relaxed);
    STOP_REQUEST_EPOCH.store(token.claim.epoch, Ordering::Relaxed);
    STOP_REQUEST_TICK.store(sched::now(), Ordering::Relaxed);
    STOP_OBSERVED_BASE.store(ap::observed_count(), Ordering::Relaxed);
    STOP_ACK_BASE.store(ap::ack_count(), Ordering::Relaxed);
    STOP_REQUEST_PID.store(token.pid, Ordering::Release);
    serial::write("SMP STOP phase=request pid=");
    serial::decimal(token.pid);
    serial::write(" slot=");
    serial::decimal(token.slot as u64);
    serial::write(" epoch=");
    serial::decimal(token.claim.epoch);
    serial::write(" tick=");
    serial::decimal(sched::now());
    serial::write("\n");
}

pub fn wait_cases() -> usize {
    WAIT_CASES.load(Ordering::Acquire)
}

/// Opt-in qualification only. The command paths call `device_first_poll`
/// after submitting real work, while their controller and transfer buffers
/// are still live. Probes happen before the AP starts and are not armed.
pub fn arm_device_first_polls() {
    kernel_lock::assert_held(kernel_lock::BSP);
    assert_eq!(cpu::current(), cpu::NO_TASK);
    assert_eq!(DEVICE_FIRST_POLL_ARMED.swap(0b1_0110, Ordering::AcqRel), 0);
}

pub fn device_first_poll(site: kernel_lock::WaitSite) {
    crate::smp_user::device_first_poll(site);
    let bit = match site {
        kernel_lock::WaitSite::Ata => 1 << 1,
        kernel_lock::WaitSite::Nvme => 1 << 2,
        kernel_lock::WaitSite::NicSend => 1 << 4,
        _ => panic!("invalid device first-poll site"),
    };
    if DEVICE_FIRST_POLL_ARMED.fetch_and(!bit, Ordering::AcqRel) & bit == 0 {
        return;
    }
    kernel_lock::assert_held(kernel_lock::BSP);
    assert_ne!(cpu::current(), cpu::NO_TASK, "device wait lacks task owner");
    let before = kernel_lock::wait_evidence(site);
    let before_ap = ap::lock_probe_count();
    let before_tick = sched::now();
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    ap::start_lock_probe();
    loop {
        kernel_lock::wait_for_irq(site);
        if ap::lock_probe_count() == before_ap + 1 && sched::now() > before_tick {
            break;
        }
        assert!(
            unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start)
                < ap::FIXTURE_STOP_TSC_BOUND,
            "device first-poll progress absent"
        );
    }
    let after = kernel_lock::wait_evidence(site);
    assert!(after.entered > before.entered);
    assert_eq!(
        after.entered - before.entered,
        after.revalidated - before.revalidated
    );
    assert!(after.pit_progress > before.pit_progress);
    serial::write("SMP DEVICE_WAIT site=");
    serial::write(wait_site_name(site));
    serial::write(" mode=injected-first-poll entered=");
    serial::decimal(after.entered - before.entered);
    serial::write(" pit_progress=");
    serial::decimal(after.pit_progress - before.pit_progress);
    serial::write(" revalidated=");
    serial::decimal(after.revalidated - before.revalidated);
    serial::write(" ap_lock=1 owner=BSP completion=unchecked\n");
}

fn wait_site_name(site: kernel_lock::WaitSite) -> &'static str {
    match site {
        kernel_lock::WaitSite::Ata => "ata",
        kernel_lock::WaitSite::Nvme => "nvme",
        kernel_lock::WaitSite::NicProbe => "nic_probe",
        kernel_lock::WaitSite::NicSend => "nic_send",
        kernel_lock::WaitSite::Idle => "idle",
        kernel_lock::WaitSite::None => panic!("invalid wait qualification site"),
    }
}

/// Fixed local-VM substitution cases use each production wait boundary with
/// no device command outstanding. BSP releases serialization in `sti;hlt;cli`;
/// the AP acquires it once, its IPI wakes BSP, PIT advances, and BSP validates
/// the same continuation on reacquisition. Real device completions are
/// separately qualified with the ATA/NVMe/NIC test boots.
pub fn qualify_wait_sites() {
    kernel_lock::assert_held(kernel_lock::BSP);
    assert_eq!(cpu::current(), cpu::NO_TASK);
    for site in [
        kernel_lock::WaitSite::Ata,
        kernel_lock::WaitSite::Nvme,
        kernel_lock::WaitSite::NicProbe,
        kernel_lock::WaitSite::NicSend,
        kernel_lock::WaitSite::Idle,
    ] {
        let before = kernel_lock::wait_evidence(site);
        let before_ap = ap::lock_probe_count();
        let before_tick = sched::now();
        let start = unsafe { core::arch::x86_64::_rdtsc() };
        ap::start_lock_probe();
        loop {
            if site == kernel_lock::WaitSite::Idle {
                kernel_lock::idle_wait();
            } else {
                kernel_lock::wait_for_irq(site);
            }
            if ap::lock_probe_count() == before_ap + 1 && sched::now() > before_tick {
                break;
            }
            assert!(
                unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start)
                    < ap::FIXTURE_STOP_TSC_BOUND,
                "AP lock/PIT wait progress did not occur"
            );
        }
        let after = kernel_lock::wait_evidence(site);
        assert!(after.entered > before.entered);
        assert_eq!(
            after.entered - before.entered,
            after.revalidated - before.revalidated
        );
        assert!(after.pit_progress > before.pit_progress);
        assert_eq!(kernel_lock::owner(), Some(kernel_lock::BSP));
        WAIT_CASES.fetch_add(1, Ordering::AcqRel);
        serial::write("SMP WAIT site=");
        serial::write(wait_site_name(site));
        serial::write(" mode=synthetic entered=");
        serial::decimal(after.entered - before.entered);
        serial::write(" pit_progress=");
        serial::decimal(after.pit_progress - before.pit_progress);
        serial::write(" ap_lock=1 owner=BSP\n");
    }
}

pub fn install() {
    kernel_lock::assert_held(kernel_lock::BSP);
    ap::install_fixture_callbacks(claim_child, run_child);
}

pub fn install_created_stop() {
    kernel_lock::assert_held(kernel_lock::BSP);
    ap::install_bsp_stop_fixture(request_bsp_spawner_stop);
}

pub fn created_aborted() -> usize {
    CREATED_ABORTED.load(Ordering::Acquire)
}

pub fn stopped_wake_refused() -> usize {
    STOPPED_WAKE_REFUSED.load(Ordering::Acquire)
}

/// An actual pipe waker sees a real stopped waiting address space. A queued
/// byte and mapped user-memory sentinel would both change if it retried a
/// transfer after Requested; the process must remain non-runnable instead.
pub unsafe fn stopped_pipe_wake_control() {
    kernel_lock::assert_held(kernel_lock::BSP);
    let pid = unsafe {
        sched::spawn_with_arg(absd_kernel::program::SLEEPER as usize, KERNEL_PARENT, 1000)
    }
    .expect("stopped-wake fixture spawn failed");
    let index = unsafe { sched::table() }
        .slot_of(pid)
        .expect("fixture slot absent");
    let pipe = unsafe { sched::pipes() }
        .create(RIGHT_READ | RIGHT_WRITE)
        .expect("fixture pipe absent");
    assert_eq!(unsafe { sched::pipes() }.write(pipe, &[0x33]), Ok(1));
    let address = USER_STACK_TOP - 8;
    let physical = unsafe { vm::translate(&sched::table().entries[index].address_space, address) }
        .expect("fixture user stack not mapped");
    unsafe { core::ptr::write_volatile(physical as *mut u8, 0x5a) };
    {
        let process = &mut unsafe { sched::table() }.entries[index];
        assert_eq!(process.state, ProcessState::Runnable);
        assert!(process.cpu_owner.is_none());
        process.state = ProcessState::Waiting;
        process.stop = StopState::Requested;
        process.wait_kind = WaitKind::Pipe;
        process.wait_pipe = Some(pipe);
        process.wait_transfer = Some(TransferWait {
            address,
            length: 1,
            write: false,
        });
        process.task.context[FRAME_RAX] = 0x5a5a_55aa;
    }
    let status = unsafe { sched::pipes() }.status(pipe).unwrap();
    unsafe { syscalls::wake_pipe_waiters(pipe, status) };
    let process = &unsafe { sched::table() }.entries[index];
    assert_eq!(process.state, ProcessState::Waiting);
    assert_eq!(process.stop, StopState::Requested);
    assert_eq!(process.wait_kind, WaitKind::Pipe);
    assert_eq!(process.task.context[FRAME_RAX], 0x5a5a_55aa);
    assert_eq!(
        unsafe { core::ptr::read_volatile(physical as *const u8) },
        0x5a
    );
    assert_eq!(unsafe { sched::pipes() }.status(pipe).unwrap().available, 1);
    {
        let process = &mut unsafe { sched::table() }.entries[index];
        process.stop = StopState::Departed; // locally unowned stop
        process.clear_wait();
        process.state = ProcessState::Killed;
    }
    assert_eq!(
        unsafe { sched::pipes() }.release(pipe, true, true),
        Ok(None)
    );
    unsafe { sched::terminate(index) };
    STOPPED_WAKE_REFUSED.fetch_add(1, Ordering::AcqRel);
}

/// The sole controlled serialization gap between installing a child handle
/// and publishing that still-Created child. AP can request stop against the
/// exact BSP owner, but cannot reclaim the spawner or activate the child.
pub fn prepublication_gap(current: usize, child: u64, handle: u64) {
    kernel_lock::assert_held(kernel_lock::BSP);
    assert_eq!(cpu::current(), current);
    let table = unsafe { sched::table() };
    let spawner = &table.entries[current];
    let claim = spawner.cpu_owner.expect("Created spawner not CPU-owned");
    assert_eq!(claim.cpu, kernel_lock::BSP);
    assert_eq!(spawner.state, ProcessState::Running);
    assert_eq!(spawner.stop, StopState::Active);
    assert_eq!(
        spawner.handles.lookup(handle).unwrap().object,
        Object::Process(child)
    );
    let child_slot = table.slot_of(child).expect("Created child missing");
    assert_eq!(table.entries[child_slot].state, ProcessState::Created);
    let token = ap::StopToken {
        slot: current,
        pid: spawner.pid,
        claim,
    };
    assert_eq!(CREATED_PID.swap(child, Ordering::AcqRel), 0);
    ap::start_bsp_stop_fixture(token);
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    kernel_lock::release(kernel_lock::BSP);
    unsafe { asm!("sti", options(nomem, nostack)) };
    while !ap::poll_bsp_stop_committed(token) {
        if unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) >= ap::FIXTURE_STOP_TSC_BOUND
        {
            unsafe { asm!("cli", options(nomem, nostack)) };
            kernel_lock::acquire(kernel_lock::BSP);
            panic!("Created spawner stop was not committed");
        }
        core::hint::spin_loop();
    }
    unsafe { asm!("cli", options(nomem, nostack)) };
    kernel_lock::acquire(kernel_lock::BSP);
    let table = unsafe { sched::table() };
    assert_eq!(table.entries[current].pid, token.pid);
    assert_eq!(table.entries[current].cpu_owner, Some(token.claim));
    assert_eq!(table.entries[current].stop, StopState::Requested);
    assert_eq!(table.entries[child_slot].state, ProcessState::Created);
    assert!(table.entries[current].handles.has_process(child));
    serial::write("SMP CREATED phase=request-observed-bsp pid=");
    serial::decimal(token.pid);
    serial::write(" child=");
    serial::decimal(child);
    serial::write(" tick=");
    serial::decimal(sched::now());
    serial::write("\n");
}

unsafe fn request_bsp_spawner_stop(token: ap::StopToken) -> bool {
    kernel_lock::assert_held(kernel_lock::FIXTURE_AP);
    let child_pid = CREATED_PID.load(Ordering::Acquire);
    let table = unsafe { sched::table() };
    let child_created = table
        .slot_of(child_pid)
        .is_some_and(|slot| table.entries[slot].state == ProcessState::Created);
    let Some(spawner) = table.entries.get_mut(token.slot) else {
        return false;
    };
    if child_pid == 0
        || spawner.pid != token.pid
        || spawner.cpu_owner != Some(token.claim)
        || spawner.state != ProcessState::Running
        || spawner.stop != StopState::Active
        || !spawner.handles.has_process(child_pid)
        || !child_created
    {
        return false;
    }
    spawner.stop = StopState::Requested;
    true
}

/// BSP calls this only after its CPU-owned reaper has checked actual
/// RSP/CR3/TSS departure and drained the stopped spawner. The child was
/// never published; its installed handle and all frames were rolled back.
pub fn on_bsp_spawner_departed(token: ap::StopToken) {
    kernel_lock::assert_held(kernel_lock::BSP);
    assert!(ap::poll_bsp_stop_committed(token));
    let child = CREATED_PID.load(Ordering::Acquire);
    assert_ne!(child, 0);
    assert!(unsafe { sched::table() }.slot_of(child).is_none());
    CREATED_PID.store(0, Ordering::Release);
    CREATED_ABORTED.fetch_add(1, Ordering::AcqRel);
    serial::write("SMP CREATED phase=departed-drained pid=");
    serial::decimal(token.pid);
    serial::write(" tick=");
    serial::decimal(sched::now());
    serial::write("\n");
    ap::complete_bsp_stop_fixture(token);
}

pub fn drained() -> usize {
    DRAINED.load(Ordering::Acquire)
}

pub fn mapping_pin() -> bool {
    MAPPING_PIN.load(Ordering::Acquire)
}

/// This runs after the child is published, while the spawner still owns the
/// BSP syscall stack.  AP may claim only that child; the BSP yields the BKL
/// without yielding its own process ownership or any mutable table borrow.
pub fn after_publication(current: usize, child: u64) {
    kernel_lock::assert_held(kernel_lock::BSP);
    assert_eq!(cpu::current(), current);
    let mode = NEXT_MODE.fetch_add(1, Ordering::AcqRel);
    assert!(mode < 4, "unexpected lifecycle child publication");
    let table = unsafe { sched::table() };
    let child_slot = table.slot_of(child).expect("fixture child absent");
    assert_eq!(table.entries[child_slot].state, ProcessState::Runnable);
    assert_eq!(table.entries[current].state, ProcessState::Running);
    let parent_pid = table.entries[current].pid;
    let parent_claim = table.entries[current].cpu_owner.expect("spawner unowned");
    assert_eq!(parent_claim.cpu, kernel_lock::BSP);
    EXPECTED_SLOT.store(child_slot, Ordering::Relaxed);
    EXPECTED_PID.store(child, Ordering::Release);
    ap::start_fixture();
    // AP has no PIT source; the BSP's TSC bound does not depend on an IRQ.
    // IRQ0/4/14 remain lock-free while this continuation is open.
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    kernel_lock::release(kernel_lock::BSP);
    unsafe { asm!("sti", options(nomem, nostack)) };
    let token = loop {
        if let Some(token) = ap::poll_claimed() {
            if token.slot != child_slot || token.pid != child {
                unsafe { asm!("cli", options(nomem, nostack)) };
                kernel_lock::acquire(kernel_lock::BSP);
                panic!("AP claimed a different child");
            }
            let active = if mode == 3 {
                true // AP is held before resource entry for this control.
            } else if mode == 0 {
                ap::poll_resource_active(token)
            } else {
                ap::poll_handler_active(token)
            };
            if active {
                break token;
            }
        }
        if unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) >= ap::FIXTURE_STOP_TSC_BOUND
        {
            unsafe { asm!("cli", options(nomem, nostack)) };
            kernel_lock::acquire(kernel_lock::BSP);
            panic!("AP fixture did not claim resources");
        }
        core::hint::spin_loop();
    };
    unsafe { asm!("cli", options(nomem, nostack)) };
    kernel_lock::acquire(kernel_lock::BSP);
    let table = unsafe { sched::table() };
    assert_eq!(table.entries[current].pid, parent_pid);
    assert_eq!(table.entries[current].cpu_owner, Some(parent_claim));
    assert_eq!(table.entries[child_slot].cpu_owner, Some(token.claim));
    assert_eq!(table.entries[child_slot].stop, StopState::Active);
    if mode == 3 {
        // This request is committed while AP owns the process but before it
        // loads victim resources. Repeating the exact token must be a no-op;
        // a single post-pivot ACK and drain still produce one outcome.
        table.entries[child_slot].stop = StopState::Requested;
        record_remote_request(token);
        let ack_before = ap::ack_count();
        kernel_lock::signal_remote_stop(child_slot, child, token.claim);
        // Select the existing repeat-stop case after AP departure but before
        // BSP consumes its ACK. BKL remains held, so no drain or slot reuse
        // can occur; AP's early-stop path needs no BKL to leave resources.
        let start = unsafe { core::arch::x86_64::_rdtsc() };
        while !ap::poll_ack_pending(token) {
            assert!(
                unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start)
                    < ap::FIXTURE_STOP_TSC_BOUND,
                "repeat-stop fixture did not reach AP departure"
            );
            core::hint::spin_loop();
        }
        assert_eq!(ap::ack_count(), ack_before + 1);
        serial::write("SMP STOP REPEAT phase=departed-before-drain\n");
        kernel_lock::signal_remote_stop(child_slot, child, token.claim);
    }
}

unsafe fn claim_child() -> Option<ap::VictimLease> {
    kernel_lock::assert_held(kernel_lock::FIXTURE_AP);
    let pid = EXPECTED_PID.load(Ordering::Acquire);
    let slot = EXPECTED_SLOT.load(Ordering::Relaxed);
    let table = unsafe { sched::table() };
    let process = table.entries.get_mut(slot)?;
    if pid == 0 || process.pid != pid || process.state != ProcessState::Runnable {
        return None;
    }
    let claim = process.claim_cpu(kernel_lock::FIXTURE_AP);
    Some(ap::VictimLease {
        token: ap::StopToken { slot, pid, claim },
        mode: match NEXT_MODE.load(Ordering::Acquire) - 1 {
            0 => ap::FixtureMode::LogicalUser,
            1 => ap::FixtureMode::BoundedHandler,
            2 => ap::FixtureMode::MappingContinuation,
            3 => ap::FixtureMode::EarlyStop,
            _ => return None,
        },
        cr3: process.address_space.root,
        kernel_stack_base: process.task.kernel_stack_base,
        kernel_stack_top: process.task.kernel_stack_top,
    })
}

unsafe fn run_child(lease: ap::VictimLease) {
    match lease.mode {
        ap::FixtureMode::LogicalUser => {}
        ap::FixtureMode::EarlyStop => ap::fixture_fail_closed(),
        ap::FixtureMode::BoundedHandler => ap::mark_handler_active(),
        ap::FixtureMode::MappingContinuation => {
            kernel_lock::acquire(kernel_lock::FIXTURE_AP);
            {
                let process = &mut unsafe { sched::table() }.entries[lease.token.slot];
                assert_eq!(process.pid, lease.token.pid);
                assert_eq!(process.cpu_owner, Some(lease.token.claim));
                assert_eq!(process.stop, StopState::Active);
                unsafe {
                    vm::map_user_page(
                        vm::frames(),
                        &mut process.address_space,
                        process.pid as u32,
                        USER_HEAP_BASE,
                        true,
                        false,
                    )
                }
                .expect("AP mapping fixture failed");
            }
            // The map is committed; this continuation pin remains until the
            // handler stops, so BSP reclamation must wait for departure ACK.
            MAPPING_PIN.store(true, Ordering::Release);
            kernel_lock::release(kernel_lock::FIXTURE_AP);
            // Publish the continuation only after mapping and pin commit.
            // BSP may now request stop while the pin is still live.
            ap::mark_handler_active();
        }
    }
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    while !ap::fixture_stop_requested(lease.token) {
        if unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) >= ap::FIXTURE_STOP_TSC_BOUND
        {
            ap::fixture_fail_closed();
        }
        core::hint::spin_loop();
    }
    if lease.mode == ap::FixtureMode::MappingContinuation {
        MAPPING_PIN.store(false, Ordering::Release);
    }
}

/// Called under BSP serialization after exact ACK and terminal drain, before
/// AP fixture state is reusable.  No process slot reference survives drain.
pub fn on_drain(token: ap::StopToken) {
    kernel_lock::assert_held(kernel_lock::BSP);
    assert_eq!(EXPECTED_PID.load(Ordering::Acquire), token.pid);
    assert_eq!(EXPECTED_SLOT.load(Ordering::Relaxed), token.slot);
    assert!(!mapping_pin(), "mapping continuation survived departure");
    assert_eq!(STOP_REQUEST_PID.load(Ordering::Acquire), token.pid);
    assert_eq!(STOP_REQUEST_SLOT.load(Ordering::Relaxed), token.slot);
    assert_eq!(
        STOP_REQUEST_EPOCH.load(Ordering::Relaxed),
        token.claim.epoch
    );
    assert_eq!(
        ap::observed_count(),
        STOP_OBSERVED_BASE.load(Ordering::Relaxed) + 1,
        "AP stop was not observed exactly once"
    );
    assert_eq!(
        ap::ack_count(),
        STOP_ACK_BASE.load(Ordering::Relaxed) + 1,
        "AP departure was not acknowledged exactly once"
    );
    let requested = STOP_REQUEST_TICK.load(Ordering::Relaxed);
    let fence = sched::now();
    let latency = fence.checked_sub(requested).expect("stop tick reversed");
    MAX_STOP_FENCE_TICKS.fetch_max(latency, Ordering::AcqRel);
    serial::write("SMP STOP phase=departed-drained pid=");
    serial::decimal(token.pid);
    serial::write(" slot=");
    serial::decimal(token.slot as u64);
    serial::write(" epoch=");
    serial::decimal(token.claim.epoch);
    serial::write(" request_tick=");
    serial::decimal(requested);
    serial::write(" fence_tick=");
    serial::decimal(fence);
    serial::write(" latency_ticks=");
    serial::decimal(latency);
    serial::write(" observed=1 ack=1 drain=1\n");
    STOP_REQUEST_PID.store(0, Ordering::Release);
    EXPECTED_PID.store(0, Ordering::Release);
    EXPECTED_SLOT.store(usize::MAX, Ordering::Relaxed);
    DRAINED.fetch_add(1, Ordering::AcqRel);
    STOP_TRACE_COUNT.fetch_add(1, Ordering::AcqRel);
}
