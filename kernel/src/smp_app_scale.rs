//! Closed six-job native application fixture. All mutable observations are
//! BKL-owned; admission is tied to a built supervisor family before publish.
use absd_kernel::handle::RIGHT_READ;
use absd_kernel::object::PipeId;
use absd_kernel::process::{Process, ProcessState, StopState, WaitKind};
use absd_kernel::syscall::ERROR_NOT_IMPLEMENTED;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(false);
static CONTROL: AtomicU64 = AtomicU64::new(0);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static ROOT: AtomicBool = AtomicBool::new(false);
const BYTES: usize = 34 * 32768;
const OUTPUT: &[u8] = b"bytes=1114112 lines=32768 words=196608 unique=3\nalpha=98304\nbeta=65536\ngamma=32768\nABSD RUST TEXT STATS OK\n";
#[derive(Clone, Copy)]
struct Job {
    supervisor: u64,
    sup_slot: usize,
    sup_generation: u64,
    sup_calls: u64,
    slot: usize,
    pid: u64,
    generation: u64,
    input: Option<PipeId>,
    calls: u64,
    preempts: u64,
    resumed: bool,
    exited: bool,
    reclaimed: bool,
    fed: bool,
    output: bool,
    latched: bool,
    omitted: bool,
}
const EMPTY: Job = Job {
    supervisor: 0,
    sup_slot: usize::MAX,
    sup_generation: 0,
    sup_calls: 0,
    slot: usize::MAX,
    pid: 0,
    generation: 0,
    input: None,
    calls: 0,
    preempts: 0,
    resumed: false,
    exited: false,
    reclaimed: false,
    fed: false,
    output: false,
    latched: false,
    omitted: false,
};
static mut JOBS: [Job; 6] = [EMPTY; 6];
static mut START: u64 = 0;
static mut DONE: bool = false;

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}
pub fn configure(control: u64) {
    assert!(cfg!(feature = "smp-user-test") && crate::smp_user::enabled());
    assert!(crate::smp_bench::mode() != 0 && !crate::smp_bench::scale());
    assert!(control <= 2 && !ENABLED.swap(true, Ordering::AcqRel));
    CONTROL.store(control, Ordering::Release);
}
fn cpu(index: usize) -> u8 {
    (index % crate::smp_bench::cpus()) as u8
}
fn fields(label: &str, values: &[(&str, u64)]) {
    crate::serial::write(label);
    for (name, value) in values {
        crate::serial::write(name);
        crate::serial::decimal(*value);
    }
    crate::serial::write("\n");
}
fn rows() -> &'static mut [Job; 6] {
    crate::kernel_lock::assert_current_owner();
    unsafe { &mut *core::ptr::addr_of_mut!(JOBS) }
}
pub fn prepare(slot: usize, p: &Process) {
    if !enabled() {
        return;
    }
    assert_eq!(p.state, ProcessState::Created);
    // Existing exhaustion control builds/removes INIT before the real root.
    if p.program == absd_kernel::program::INIT as usize {
        assert!(!ROOT.load(Ordering::Acquire) && p.parent == 0);
        assert!(rows().iter().all(|r| r.supervisor == 0 && r.pid == 0));
        return;
    }
    if p.program == absd_kernel::program::SMP_USER as usize {
        let role = p.task.context[absd_kernel::syscall::FRAME_RDX];
        if role == 0 {
            assert_eq!((p.pid, p.parent), (1, 0));
            return;
        }
        assert!((350..=355).contains(&role) && p.parent == 1);
        let index = (role - 350) as usize;
        assert_eq!(rows()[index].supervisor, 0);
        rows()[index].supervisor = p.pid;
        rows()[index].sup_slot = slot;
        fields(
            "SMP APP SCALE SUPERVISOR",
            &[
                (" job=", index as u64),
                (" pid=", p.pid),
                (" cpu=", cpu(index) as u64),
            ],
        );
    } else {
        assert_eq!(p.program, absd_kernel::program::EXTERNAL_WORKLOAD as usize);
        let index = rows()
            .iter()
            .position(|r| r.supervisor == p.parent && r.supervisor != 0)
            .expect("native child outside admitted supervisor family");
        let r = &mut rows()[index];
        assert_eq!(r.pid, 0);
        r.slot = slot;
        r.pid = p.pid;
        fields(
            "SMP APP SCALE NATIVE",
            &[
                (" job=", index as u64),
                (" slot=", slot as u64),
                (" pid=", p.pid),
                (" parent=", p.parent),
                (" cpu=", cpu(index) as u64),
            ],
        );
    }
}
pub fn placement(p: &Process) -> Option<u8> {
    if !enabled() {
        return None;
    }
    if p.pid == 1 {
        return Some(0);
    }
    rows()
        .iter()
        .position(|r| r.supervisor == p.pid || r.pid == p.pid)
        .map(cpu)
}
pub fn permits(p: &Process) -> bool {
    enabled()
        && p.program == absd_kernel::program::EXTERNAL_WORKLOAD as usize
        && rows()
            .iter()
            .any(|r| r.pid == p.pid && r.supervisor == p.parent && !r.exited)
        && p.class.rt().is_none()
}
pub fn activated(slot: usize, p: &Process) {
    if !enabled() {
        return;
    }
    let generation = if crate::modern_smp::enabled() {
        crate::modern_smp::generation(slot)
    } else {
        0
    };
    if p.program == absd_kernel::program::INIT as usize {
        assert!(!ROOT.load(Ordering::Acquire) && p.parent == 0);
        return;
    }
    if p.pid == 1 {
        assert_eq!(p.program, absd_kernel::program::SMP_USER as usize);
        assert!(!ROOT.swap(true, Ordering::AcqRel));
        fields(
            "SMP APP SCALE ROOT",
            &[
                (" slot=", slot as u64),
                (" pid=", p.pid),
                (" generation=", generation),
                (" cpu=", 0),
            ],
        );
        return;
    }
    if p.program == absd_kernel::program::SMP_USER as usize {
        let index = rows().iter().position(|r| r.supervisor == p.pid).unwrap();
        rows()[index].sup_generation = generation;
        fields(
            "SMP APP SCALE SUPKEY",
            &[
                (" job=", index as u64),
                (" slot=", slot as u64),
                (" pid=", p.pid),
                (" generation=", generation),
                (" cpu=", cpu(index) as u64),
            ],
        );
        return;
    }
    let r = rows()
        .iter_mut()
        .find(|r| r.pid == p.pid)
        .expect("native publication outside family");
    assert_eq!(r.slot, slot);
    r.generation = generation;
}
pub fn trap(slot: usize, p: &Process) {
    if !enabled() {
        return;
    }
    if p.program == absd_kernel::program::SMP_USER as usize {
        if p.pid == 1 {
            return;
        }
        let index = supervisor_index(p);
        let r = &mut rows()[index];
        assert_eq!(r.sup_slot, slot);
        assert_eq!(p.cpu_owner.unwrap().cpu, cpu(index));
        if crate::modern_smp::enabled() {
            assert_eq!(r.sup_generation, crate::modern_smp::generation(slot));
        }
        if r.sup_calls == 0 {
            fields(
                "SMP APP SCALE SUPTRAP",
                &[
                    (" job=", index as u64),
                    (" pid=", p.pid),
                    (" generation=", r.sup_generation),
                    (" cpu=", cpu(index) as u64),
                ],
            );
        }
        r.sup_calls += 1;
        return;
    }
    let index = rows()
        .iter()
        .position(|r| r.pid == p.pid)
        .expect("unregistered native trap");
    let r = &mut rows()[index];
    assert_eq!((r.slot, r.supervisor), (slot, p.parent));
    assert!(!r.exited && p.cpu_owner.unwrap().cpu == cpu(index));
    if crate::modern_smp::enabled() {
        assert_eq!(r.generation, crate::modern_smp::generation(slot));
    }
    if r.preempts > 0 {
        r.resumed = true;
    }
    if r.calls == 0 {
        fields(
            "SMP APP SCALE TRAP",
            &[
                (" job=", index as u64),
                (" slot=", slot as u64),
                (" pid=", p.pid),
                (" generation=", r.generation),
                (" cpu=", cpu(index) as u64),
            ],
        );
        crate::serial::write("SMP APP SCALE IDENTITY cpl=3 cr3=owned\n");
    }
    r.calls += 1;
}
pub fn saved(slot: usize, p: &Process, preempted: bool) {
    if !enabled()
        || !preempted
        || !ACTIVE.load(Ordering::Acquire)
        || p.program != absd_kernel::program::EXTERNAL_WORKLOAD as usize
    {
        return;
    }
    let index = rows().iter().position(|r| r.pid == p.pid).unwrap();
    let r = &mut rows()[index];
    assert_eq!(r.slot, slot);
    assert_eq!(p.parent, r.supervisor);
    assert!(!r.exited && p.state == ProcessState::Running && p.stop == StopState::Active);
    if crate::modern_smp::enabled() {
        assert_eq!(r.generation, crate::modern_smp::generation(slot));
    }
    assert!(p.task.context_valid && p.task.context[16] & 3 == 3);
    assert_eq!(p.cpu_owner.unwrap().cpu, cpu(index));
    assert_eq!(crate::cpu::id(), cpu(index));
    if CONTROL.load(Ordering::Acquire) == 2 && index == 5 {
        if !r.omitted {
            r.omitted = true;
            fields(
                "SMP APP SCALE INJECT",
                &[
                    (" job=", 5),
                    (" pid=", p.pid),
                    (" cpu=", cpu(index) as u64),
                    (" saved=", 1),
                    (" preempt-credit-omitted=", 1),
                ],
            );
        }
        return;
    }
    r.preempts += 1;
    if r.preempts == 1 {
        fields(
            "SMP APP SCALE PREEMPT",
            &[
                (" job=", index as u64),
                (" pid=", p.pid),
                (" generation=", r.generation),
                (" cpu=", cpu(index) as u64),
                (" saved=", 1),
            ],
        );
    }
}
pub fn terminal(p: &Process) {
    if !enabled() || p.program != absd_kernel::program::EXTERNAL_WORKLOAD as usize {
        return;
    }
    if p.state == ProcessState::Created {
        if let Some(r) = rows().iter_mut().find(|r| r.pid == p.pid) {
            assert!(!r.exited);
            *r = Job {
                supervisor: r.supervisor,
                sup_slot: r.sup_slot,
                sup_generation: r.sup_generation,
                sup_calls: r.sup_calls,
                ..EMPTY
            };
        }
        return;
    }
    let r = rows()
        .iter_mut()
        .find(|r| r.pid == p.pid)
        .expect("unregistered native terminal");
    assert!(r.latched);
    assert!(
        p.cpu_owner.is_none() && p.state == ProcessState::Exited && p.exit_status == 0 && !r.exited
    );
    r.exited = true;
}
/// Latch identity before queue removal. Departure was already proved by the
/// caller; this copied observation is not a new departure/ACK mechanism.
pub fn before_remove(slot: usize, p: &Process) {
    if !enabled() || p.program != absd_kernel::program::EXTERNAL_WORKLOAD as usize {
        return;
    }
    let r = rows().iter_mut().find(|r| r.pid == p.pid).unwrap();
    assert_eq!((r.slot, r.supervisor), (slot, p.parent));
    if crate::modern_smp::enabled() {
        assert_eq!(r.generation, crate::modern_smp::generation(slot));
    }
    assert!(
        !r.latched
            && !r.exited
            && p.state == ProcessState::Exited
            && p.exit_status == 0
            && p.cpu_owner.is_none()
    );
    r.latched = true;
    let index = rows().iter().position(|row| row.pid == p.pid).unwrap();
    let r = rows()[index];
    fields(
        "SMP APP SCALE DEPART",
        &[
            (" job=", index as u64),
            (" slot=", slot as u64),
            (" pid=", p.pid),
            (" generation=", r.generation),
            (" owner=", 0),
        ],
    );
}
pub fn reclaimed(p: &Process) {
    if !enabled() || p.program != absd_kernel::program::EXTERNAL_WORKLOAD as usize {
        return;
    }
    let r = rows().iter_mut().find(|r| r.pid == p.pid).unwrap();
    assert!(r.exited && !r.reclaimed && p.cpu_owner.is_none());
    assert_eq!(
        unsafe { crate::vm::frames() }.frames_owned_by(p.pid as u32),
        0
    );
    assert_eq!(p.handles.live_count(), 0);
    r.reclaimed = true;
    let index = rows().iter().position(|row| row.pid == p.pid).unwrap();
    let r = rows()[index];
    fields(
        "SMP APP SCALE RECLAIM",
        &[
            (" job=", index as u64),
            (" pid=", p.pid),
            (" generation=", r.generation),
            (" frames=", 0),
            (" handles=", 0),
        ],
    );
}
fn supervisor_index(p: &Process) -> usize {
    assert_eq!(p.program, absd_kernel::program::SMP_USER as usize);
    rows()
        .iter()
        .position(|r| r.supervisor == p.pid && r.supervisor != 0)
        .expect("not a supervisor")
}
pub fn call(slot: usize, op: u64, a: u64, b: u64) -> i64 {
    if !enabled() {
        return ERROR_NOT_IMPLEMENTED;
    }
    crate::kernel_lock::assert_current_owner();
    if op == 42 {
        return 6;
    }
    if matches!(op, 44 | 45) {
        assert_eq!(unsafe { crate::sched::table() }.entries[slot].pid, 1);
        if op == 44 {
            return start();
        }
        done();
        return 0;
    }
    let index = supervisor_index(&unsafe { crate::sched::table() }.entries[slot]);
    if op == 43 {
        assert_eq!(rows()[index].pid, a);
        assert!(rows()[index].input.is_none());
        let id = unsafe { crate::sched::table() }.entries[slot]
            .handles
            .pipe(b, RIGHT_READ)
            .unwrap();
        assert!(!rows().iter().any(|r| r.input == Some(id)));
        rows()[index].input = Some(id);
        return 0;
    }
    assert!(ACTIVE.load(Ordering::Acquire));
    assert!(
        rows()[index].reclaimed,
        "completion before native wait/reclaim fence"
    );
    if op == 46 {
        assert_eq!((a, b), (BYTES as u64, 0x2add9dc5));
        assert!(!rows()[index].fed);
        rows()[index].fed = true;
        return 0;
    }
    if op == 47 {
        assert_eq!(b, OUTPUT.len() as u64);
        let p = &unsafe { crate::sched::table() }.entries[slot];
        let mut bytes = [0u8; OUTPUT.len()];
        unsafe { absd_kernel::user_memory::copy_from_user(&p.address_space, a, &mut bytes) }
            .unwrap();
        if CONTROL.load(Ordering::Acquire) == 1 && index == 5 {
            bytes[0] ^= 1;
            crate::serial::write(
                "SMP APP SCALE INJECT kind=output job=5 observed-byte-substituted=1\n",
            );
        }
        assert_eq!(bytes, OUTPUT, "native output mismatch");
        assert!(!rows()[index].output);
        rows()[index].output = true;
        return 0;
    }
    ERROR_NOT_IMPLEMENTED
}
fn start() -> i64 {
    assert!(!ACTIVE.load(Ordering::Acquire) && unsafe { START } == 0);
    if !(0..6).all(|i| crate::smp_user::shared_load(240 + i) == 1 && rows()[i].input.is_some()) {
        return 0;
    }
    assert_eq!(unsafe { crate::sched::table() }.occupied_count(), 13);
    assert_eq!(unsafe { crate::sched::pipes() }.live(), 12);
    for index in 0..6 {
        let r = rows()[index];
        let p = &unsafe { crate::sched::table() }.entries[r.slot];
        assert_eq!((p.pid, p.parent), (r.pid, r.supervisor));
        if p.state != ProcessState::Waiting || p.cpu_owner.is_some() {
            return 0;
        }
        assert_eq!(p.wait_kind, WaitKind::Pipe);
        assert_eq!(p.wait_pipe, r.input);
        let transfer = p.wait_transfer.unwrap();
        assert!(!transfer.write && transfer.length > 0 && p.task.context_valid);
        assert_eq!(p.task.context[16] & 3, 3);
        let status = unsafe { crate::sched::pipes() }
            .status(r.input.unwrap())
            .unwrap();
        assert_eq!(
            (status.available, status.readers, status.writers),
            (0, 1, 1)
        );
        assert_eq!(p.stop, StopState::Active);
        assert!(p.class.rt().is_none() && r.calls > 0 && !r.exited);
        crate::modern_smp::assert_blocked(r.slot, r.pid, r.generation);
    }
    crate::smp_leaf_measure::report_config();
    fields(
        "SMP APP SCALE START",
        &[
            (" jobs=", 6),
            (" cpus=", crate::smp_bench::cpus() as u64),
            (" bytes-per-job=", BYTES as u64),
            (" blocked=", 6),
        ],
    );
    unsafe { START = crate::smp_measure::clock() };
    ACTIVE.store(true, Ordering::Release);
    crate::smp_measure::arm(1);
    1
}
fn done() {
    assert!(ACTIVE.load(Ordering::Acquire) && !unsafe { DONE });
    let elapsed = crate::smp_measure::clock()
        .checked_sub(unsafe { START })
        .unwrap();
    crate::smp_measure::disarm(1);
    let t = unsafe { crate::sched::table() };
    assert_eq!(t.occupied_count(), 1);
    for index in 0..6 {
        let r = rows()[index];
        assert!(
            r.fed
                && r.output
                && r.exited
                && r.reclaimed
                && crate::smp_user::shared_load(248 + index) == 1
        );
        if crate::smp_bench::cpus() > 1 {
            assert!(
                r.preempts > 0 && r.resumed,
                "native job lacked timer-preemption/resume witness"
            );
        }
        fields(
            "SMP APP SCALE JOB",
            &[
                (" job=", index as u64),
                (" pid=", r.pid),
                (" parent=", r.supervisor),
                (" slot=", r.slot as u64),
                (" generation=", r.generation),
                (" cpu=", cpu(index) as u64),
                (" calls=", r.calls),
                (" preempts=", r.preempts),
                (" resumed=", u64::from(r.resumed)),
                (" input=", BYTES as u64),
                (" output=", OUTPUT.len() as u64),
                (" exited=", 1),
                (" reclaimed=", 1),
            ],
        );
    }
    ACTIVE.store(false, Ordering::Release);
    unsafe { DONE = true };
    fields(
        "SMP APP SCALE DONE",
        &[
            (" jobs=", 6),
            (" cpus=", crate::smp_bench::cpus() as u64),
            (" input=", 6 * BYTES as u64),
            (" output=", 6 * OUTPUT.len() as u64),
            (" tsc=", elapsed),
        ],
    );
    crate::smp_measure::report(1);
    crate::smp_leaf_measure::report();
}
pub fn finish() -> ! {
    assert!(unsafe { DONE } && !ACTIVE.load(Ordering::Acquire));
    let s = unsafe { crate::sched::stats() };
    assert_eq!(s.init_status, Some(0));
    assert_eq!(
        (s.spawns, s.exits, s.reaps, s.faults, s.kills),
        (13, 13, 13, 0, 0)
    );
    fields(
        "SMP APP SCALE FENCE",
        &[
            (
                " frames=",
                (unsafe { crate::vm::frames() }.allocated_frames() - s.frame_baseline) as u64,
            ),
            (
                " processes=",
                unsafe { crate::sched::table() }.occupied_count() as u64,
            ),
            (" cells=", unsafe { crate::sched::cells() }.live() as u64),
            (" pipes=", unsafe { crate::sched::pipes() }.live() as u64),
            (" aps-idle=", crate::smp_user::idle_count() as u64),
        ],
    );
    crate::serial::write(
        "SMP APP SCALE OK jobs=6 tasks=13 input=exact output=exact reclaimed=1\nABSD BOOT OK\n",
    );
    crate::exit_qemu(0)
}
