//! Closed boot-phase pressure fixture; mappings still precede SIPI.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
static ENABLED: AtomicBool = AtomicBool::new(false);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static SKIP_MAP: AtomicBool = AtomicBool::new(false);
static FAIL_ACTOR: AtomicBool = AtomicBool::new(false);
static OMIT_LAST_WINDOW: AtomicBool = AtomicBool::new(false);
pub fn omit_last_window() {
    assert!(enabled() && crate::smp_app_pressure::startup_mode());
    assert!(!OMIT_LAST_WINDOW.swap(true, Ordering::AcqRel));
    crate::serial::write("SMP STARTUP INJECT omitted-window-cpu=");
    crate::serial::decimal(crate::cpu::count() as u64 - 1);
    crate::serial::write("\n");
}
static FIRST: [AtomicBool; 6] = [const { AtomicBool::new(false) }; 6];
static WINDOWS: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];
static mut PIDS: [u64; 10] = [0; 10];
static mut FRAME_BASELINE: usize = 0;
static mut WAIT_BEFORE: [[u64; crate::cpu::MAX_CPUS]; 6] = [[0; crate::cpu::MAX_CPUS]; 6];
static CPU_WINDOWS: [[AtomicU64; crate::cpu::MAX_CPUS]; 6] =
    [const { [const { AtomicU64::new(0) }; crate::cpu::MAX_CPUS] }; 6];
pub fn snapshot_before_wait(site: crate::kernel_lock::WaitSite) {
    if !active() || !crate::smp_app_pressure::startup_mode() {
        return;
    }
    crate::kernel_lock::assert_held(0);
    let snapshot = core::array::from_fn(|cpu| {
        if cpu < crate::cpu::count() {
            crate::smp_user::calls_on(cpu)
        } else {
            0
        }
    });
    unsafe { (*core::ptr::addr_of_mut!(WAIT_BEFORE))[site as usize] = snapshot };
}
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}
pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}
pub fn configure(skip_map: bool, fail_actor: bool) {
    assert!(
        cfg!(feature = "smp-user-test")
            && crate::smp_user::enabled()
            && !crate::smp_user::standalone()
    );
    assert!(!ENABLED.swap(true, Ordering::AcqRel));
    SKIP_MAP.store(skip_map, Ordering::Release);
    FAIL_ACTOR.store(fail_actor, Ordering::Release);
}
pub fn actor_failure() -> bool {
    active() && FAIL_ACTOR.load(Ordering::Acquire)
}
pub fn prepare_mapping(nic: bool) {
    if SKIP_MAP.load(Ordering::Acquire) {
        return;
    }
    match crate::nvme::prepare_qualification_mapping() {
        Ok(()) | Err(crate::nvme::NvmeError::Absent) => {}
        Err(error) => panic!("startup NVMe mapping: {error:?}"),
    }
    if nic {
        match crate::e1000::prepare_qualification_mapping() {
            Ok(()) | Err(crate::e1000::NicError::Absent) => {}
            Err(error) => panic!("startup NIC mapping: {error:?}"),
        }
    }
}
pub fn begin() -> u64 {
    assert!(enabled());
    assert!(!ACTIVE.swap(true, Ordering::AcqRel));
    if crate::smp_app_pressure::startup_mode() {
        return begin_multicore();
    }
    let pid = unsafe { crate::sched::spawn_startup_actor() };
    assert_eq!(pid, 1);
    crate::ap::start_user_scheduler();
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    while crate::smp_user::ap_calls() == 0 {
        assert!(
            unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < 1 << 34,
            "startup AP readiness"
        );
        crate::smp_user::idle_wait();
    }
    crate::serial::write("SMP STARTUP AP READY cpu=1\n");
    pid
}
pub fn window(site: usize) {
    if active() {
        if crate::smp_app_pressure::startup_mode() {
            // The BSP exclusively owns this continuation; copy its immutable
            // snapshot. No process/controller/table borrow crosses the wait.
            let before = unsafe { (*core::ptr::addr_of!(WAIT_BEFORE))[site] };
            let start = unsafe { core::arch::x86_64::_rdtsc() };
            while !(1..crate::cpu::count()).all(|cpu| crate::smp_user::calls_on(cpu) > before[cpu])
            {
                assert!(
                    unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < 1 << 32,
                    "startup every-AP pinned-wait progress"
                );
                core::hint::spin_loop();
            }
            for (cpu, windows) in CPU_WINDOWS[site]
                .iter()
                .enumerate()
                .take(crate::cpu::count())
                .skip(1)
            {
                if OMIT_LAST_WINDOW.load(Ordering::Acquire) && cpu + 1 == crate::cpu::count() {
                    continue;
                }
                windows.fetch_add(1, Ordering::AcqRel);
            }
        }
        WINDOWS[site].fetch_add(1, Ordering::Relaxed);
    }
}
pub fn first_poll(site: crate::kernel_lock::WaitSite) {
    if !active() || FIRST[site as usize].swap(true, Ordering::AcqRel) {
        return;
    }
    let before = crate::kernel_lock::wait_evidence(site);
    let calls = crate::smp_user::ap_calls();
    crate::kernel_lock::wait_for_irq(site);
    let after = crate::kernel_lock::wait_evidence(site);
    assert!(crate::smp_user::ap_calls() > calls);
    assert_eq!(after.entered - before.entered, 1);
    assert_eq!(after.revalidated - before.revalidated, 1);
    assert!(after.pit_progress > before.pit_progress);
    crate::serial::write("SMP STARTUP FIRST POLL site=");
    crate::serial::decimal(site as u64);
    crate::serial::write(" revalidated=1 completion=unchecked\n");
}
pub fn finish(pid: u64, mapping: (u64, usize, u64)) {
    assert_eq!(
        crate::mmio::snapshot(),
        mapping,
        "shared MMIO changed after SIPI"
    );
    if crate::smp_app_pressure::startup_mode() {
        finish_multicore(pid);
    }
    crate::smp_user::startup_stop();
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    while !crate::smp_user::startup_quiescent() {
        assert!(
            unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < 1 << 34,
            "startup departure fence"
        );
        crate::smp_user::idle_wait();
    }
    crate::kernel_lock::assert_held(0);
    crate::smp_user::startup_assert_fence();
    unsafe {
        assert_eq!(crate::vm::frames().frames_owned_by(pid as u32), 0);
        assert!(crate::sched::object_tables_empty());
        let stats = crate::sched::stats();
        assert_eq!(stats.init_status, Some(0), "startup actor failed");
        assert_eq!(
            (
                stats.spawns,
                stats.exits,
                stats.faults,
                stats.kills,
                stats.reaps
            ),
            (1, 1, 0, 0, 1),
            "startup lifecycle accounting"
        );
        assert!(crate::sched::table().rewind_newest_pid(pid));
        crate::sched::stats().frame_baseline = crate::vm::frames().allocated_frames();
        crate::sched::stats().init_status = None;
    }
    ACTIVE.store(false, Ordering::Release);
    crate::smp_user::startup_clear();
    crate::serial::write("SMP STARTUP SUMMARY cpu=1 ata=");
    crate::serial::decimal(WINDOWS[1].load(Ordering::Acquire));
    crate::serial::write(" nvme=");
    crate::serial::decimal(WINDOWS[2].load(Ordering::Acquire));
    crate::serial::write(" nic-probe=");
    crate::serial::decimal(WINDOWS[3].load(Ordering::Acquire));
    crate::serial::write(
        " bootstrap-exits=1 faults=0 kills=0 mappings=unchanged reclaimed=1 pid-rewind=fenced\n",
    );
}

fn begin_multicore() -> u64 {
    crate::kernel_lock::assert_held(0);
    let actors = crate::smp_app_pressure::reservation() as usize;
    assert!(matches!(crate::cpu::count(), 4 | 6));
    unsafe { FRAME_BASELINE = kernel_frame_census() };
    for index in 0..actors {
        let pid = unsafe { crate::sched::spawn_startup_actor_role(200 + index as u64) };
        assert_eq!(pid, index as u64 + 1);
        unsafe { (*core::ptr::addr_of_mut!(PIDS))[index] = pid };
        crate::serial::write("SMP STARTUP RESTRICTED pid=");
        crate::serial::decimal(pid);
        crate::serial::write(" role=");
        crate::serial::decimal(200 + index as u64);
        crate::serial::write(" handles=0 spawn=0 console=0 phase=before-ap-command\n");
    }
    assert_eq!(
        crate::smp_app_pressure::reserved_frames(),
        crate::smp_app_pressure::ACTOR_FRAMES * actors
    );
    crate::ap::start_user_scheduler();
    crate::smp_app_pressure::calibrate_before_users();
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    while !crate::smp_app_pressure::startup_ready() {
        assert!(
            unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < 1 << 34,
            "startup every-AP saved/resume readiness"
        );
        crate::smp_user::idle_wait();
    }
    for cpu in 1..crate::cpu::count() {
        crate::serial::write("SMP STARTUP AP READY cpu=");
        crate::serial::decimal(cpu as u64);
        crate::serial::write(" actors=2 saved=1 resumed=1\n");
    }
    crate::smp_app_pressure::app_begin();
    crate::serial::write("SMP STARTUP INTERVAL BEGIN phase=device-probe real-init=uncreated\n");
    1
}

fn finish_multicore(pid: u64) -> ! {
    assert_eq!(pid, 1);
    crate::smp_app_pressure::app_end();
    crate::serial::write("SMP STARTUP INTERVAL END phase=device-probe\n");
    crate::smp_user::startup_stop();
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    while !crate::smp_user::startup_quiescent() {
        assert!(
            unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < 1 << 34,
            "startup departure fence"
        );
        crate::smp_user::idle_wait();
    }
    crate::kernel_lock::assert_held(0);
    crate::smp_user::startup_assert_fence();
    let actors = crate::smp_app_pressure::reservation() as usize;
    let pids = unsafe { *core::ptr::addr_of!(PIDS) };
    assert!(pids[actors..].iter().all(|pid| *pid == 0));
    unsafe {
        for (index, pid) in pids[..actors].iter().enumerate() {
            assert_eq!(*pid, index as u64 + 1);
            assert_eq!(crate::vm::frames().frames_owned_by(*pid as u32), 0);
            crate::serial::write("SMP STARTUP RECLAIM pid=");
            crate::serial::decimal(*pid);
            crate::serial::write(" role=");
            crate::serial::decimal(200 + index as u64);
            crate::serial::write(" frames=0 departed=1 fence=all-ap-idle\n");
        }
        assert!(crate::sched::object_tables_empty());
        let stats = crate::sched::stats();
        assert_eq!(stats.init_status, Some(0));
        assert_eq!(
            (
                stats.spawns,
                stats.exits,
                stats.faults,
                stats.kills,
                stats.reaps
            ),
            (actors as u64, actors as u64, 0, 0, actors as u64),
            "startup lifecycle accounting"
        );
    }
    crate::modern_smp::finish();
    crate::smp_timer::report();
    crate::smp_app_pressure::report();
    for site in 1..=4 {
        let total = WINDOWS[site].load(Ordering::Acquire);
        crate::serial::write("SMP STARTUP WINDOW TOTAL site=");
        crate::serial::decimal(site as u64);
        crate::serial::write(" intervals=");
        crate::serial::decimal(total);
        crate::serial::write("\n");
        for (cpu, counter) in CPU_WINDOWS[site]
            .iter()
            .enumerate()
            .take(crate::cpu::count())
            .skip(1)
        {
            let windows = counter.load(Ordering::Acquire);
            assert_eq!(windows, total, "startup per-AP window evidence");
            crate::serial::write("SMP STARTUP WINDOW site=");
            crate::serial::decimal(site as u64);
            crate::serial::write(" cpu=");
            crate::serial::decimal(cpu as u64);
            crate::serial::write(" intervals=");
            crate::serial::decimal(windows);
            crate::serial::write(" all-ap-progress=1\n");
        }
    }
    for pid in pids[..actors].iter().rev() {
        assert!(unsafe { crate::sched::table() }.rewind_newest_pid(*pid));
    }
    let baseline = unsafe { FRAME_BASELINE };
    let final_frames = kernel_frame_census();
    let retained = final_frames
        .checked_sub(baseline)
        .expect("startup kernel frame baseline");
    crate::serial::write("SMP STARTUP FRAMES baseline=");
    crate::serial::decimal(baseline as u64);
    crate::serial::write(" final=");
    crate::serial::decimal(final_frames as u64);
    crate::serial::write(" kernel-retained=");
    crate::serial::decimal(retained as u64);
    crate::serial::write(" actor-owned=0 devices=initialized-not-quiesced\n");
    crate::serial::write("SMP STARTUP SUMMARY cpus=");
    crate::serial::decimal(crate::cpu::count() as u64);
    crate::serial::write(" actors=");
    crate::serial::decimal(actors as u64);
    crate::serial::write(
        " faults=0 kills=0 mappings=unchanged reclaimed=1 pid-rewind=fenced real-init=uncreated\nSMP NWAY STARTUP OK\nABSD BOOT OK\n",
    );
    crate::exit_qemu(0)
}

fn kernel_frame_census() -> usize {
    use absd_kernel::memory::{Frame, FrameOwner, FrameState, PAGE_SIZE};
    crate::kernel_lock::assert_held(0);
    let frames = unsafe { crate::vm::frames() };
    let mut allocated = 0;
    for index in 0..frames.tracked_frames() {
        if let FrameState::Allocated(owner) = frames.state(Frame(index as u64 * PAGE_SIZE)) {
            assert_eq!(
                owner,
                FrameOwner::Kernel,
                "startup retains process-tagged frame"
            );
            allocated += 1;
        }
    }
    assert_eq!(allocated, frames.allocated_frames());
    allocated
}
