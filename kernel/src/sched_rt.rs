//! Runtime bridge for the bounded RT class; ordinary waits retain their code.
use super::{BootMode, boot_mode, now};
use crate::serial;
use absd_kernel::process::{Process, ProcessState, WaitKind};
use absd_kernel::rt::{BoundedRt, Priority, SchedulingClass, State};

// Bounded qualification trace: numeric records only on the scheduling path.
// Formatting/COM1 output occurs once, after all tasks have terminated.
const TRACE_CAPACITY: usize = 8192;
#[derive(Clone, Copy)]
struct Record {
    label: &'static str,
    values: [u64; 8],
    len: usize,
}
const EMPTY_RECORD: Record = Record {
    label: "",
    values: [0; 8],
    len: 0,
};
static mut TRACE: [Record; TRACE_CAPACITY] = [EMPTY_RECORD; TRACE_CAPACITY];
static mut TRACE_LEN: usize = 0;
fn event(label: &'static str, fields: &[(&str, u64)]) {
    assert!(fields.len() <= 8);
    // All callers run with interrupts disabled on this single CPU.
    unsafe {
        let len = core::ptr::read(core::ptr::addr_of!(TRACE_LEN));
        assert!(len < TRACE_CAPACITY, "RT qualification trace overflow");
        let mut record = Record {
            label,
            values: [0; 8],
            len: fields.len(),
        };
        for (index, &(_, value)) in fields.iter().enumerate() {
            record.values[index] = value;
        }
        core::ptr::write(
            core::ptr::addr_of_mut!(TRACE).cast::<Record>().add(len),
            record,
        );
        core::ptr::write(core::ptr::addr_of_mut!(TRACE_LEN), len + 1);
    }
}
pub(crate) fn flush() {
    unsafe {
        let len = core::ptr::read(core::ptr::addr_of!(TRACE_LEN));
        for index in 0..len {
            let record = core::ptr::read(core::ptr::addr_of!(TRACE).cast::<Record>().add(index));
            let keys: &[&str] = match record.label {
                "RT CONFIG" => &[
                    " pid=",
                    " tick=",
                    " mode=",
                    " priority=",
                    " first=",
                    " period=",
                    " budget=",
                    " state=",
                ],
                "RT CHARGE" => &[" pid=", " tick=", " seq=", " consumed=", " remaining="],
                "RT PERIOD" => &[
                    " pid=",
                    " seq=",
                    " release=",
                    " dispatch=",
                    " consumed=",
                    " budget=",
                    " normal=",
                    " state=",
                ],
                "RT RELEASE" => &[
                    " pid=",
                    " requested=",
                    " actual=",
                    " missed=",
                    " skipped=",
                    " total_missed=",
                    " late=",
                    " seq=",
                ],
                "RT DISPATCH" => &[
                    " pid=",
                    " seq=",
                    " requested=",
                    " actual=",
                    " latency=",
                    " from=",
                ],
                "RT SELECT" => &[" pid=", " tick=", " from=", " priority=", " remaining="],
                "RT EXHAUST" | "RT REMOVE" => &[" pid=", " tick="],
                "RT IDLE" => &[" tick="],
                _ if record.label.starts_with("RT STATE") => &[
                    " pid=",
                    " tick=",
                    " from=",
                    " to=",
                    " seq=",
                    " consumed=",
                    " remaining=",
                ],
                _ => panic!("unknown RT trace record"),
            };
            assert_eq!(keys.len(), record.len);
            serial::record_only(|| {
                serial::write(record.label);
                for (key, value) in keys.iter().zip(record.values) {
                    serial::write(key);
                    serial::decimal(value);
                }
                serial::write("\n");
            });
        }
        core::ptr::write(core::ptr::addr_of_mut!(TRACE_LEN), 0);
    }
}
pub(super) fn idle() {
    event("RT IDLE", &[(" tick=", now())]);
}
fn transition(process: &Process, from: State, reason: &'static str) {
    let rt = process.class.rt().unwrap();
    let label = match reason {
        "release" => "RT STATE event=release",
        "dispatch" => "RT STATE event=dispatch",
        "exhaust" => "RT STATE event=exhaust",
        "complete" => "RT STATE event=complete",
        "block" => "RT STATE event=block",
        "wake" => "RT STATE event=wake",
        "preempt" => "RT STATE event=preempt",
        _ => panic!("unknown RT transition"),
    };
    event(
        label,
        &[
            (" pid=", process.pid),
            (" tick=", now()),
            (" from=", from as u64),
            (" to=", rt.state as u64),
            (" seq=", rt.sequence),
            (" consumed=", rt.consumed),
            (" remaining=", rt.remaining()),
        ],
    );
}

fn park(process: &mut Process) {
    process.state = ProcessState::Waiting;
    process.wait_kind = WaitKind::RtRelease;
    process.wake_at = Some(process.class.rt().unwrap().next_release);
}

/// Closed fixture configuration. The scheduler itself does not inspect program IDs.
pub(super) fn configure(index: usize, process: &mut Process, mode: u64) {
    if !matches!(boot_mode(), BootMode::RtTest | BootMode::RtClass)
        || process.program != absd_kernel::program::RT_PROBE as usize
        || mode == 0
    {
        return;
    }
    let (priority, delay, period, budget) = match mode {
        1..=8 | 11 | 12 => (Priority::RtLow, 10, 20, 5),
        9 => (Priority::RtLow, 10, 20, 5),
        10 => (Priority::RtLow, 10, 30, 8),
        13 => (Priority::RtHigh, 14, 30, 5),
        _ => return,
    };
    let first = now()
        .checked_add(delay)
        .expect("RT fixture clock exhausted");
    let mut rt = BoundedRt::new(priority, first, period, budget);
    // Deliberate initial ordinary sleep: exact wake/exhaust/release boundaries.
    // Only fixture initialization; normal blocking uses the existing wait paths.
    if mode == 8 || mode == 11 {
        rt.state = State::Blocked;
        process.state = ProcessState::Waiting;
        process.wait_kind = WaitKind::Sleep;
        process.wake_at = Some(first + if mode == 8 { period - budget } else { period });
    }
    process.class = SchedulingClass::BoundedRt(rt);
    if rt.state == State::Waiting {
        park(process);
    }
    // Published child remains parked until init has committed scenario sleep.
    // Pending slot+PID is fixture identity, not a general admission API.
    unsafe {
        let entry = core::ptr::addr_of_mut!(PENDING)
            .cast::<Option<(u64, u64)>>()
            .add(index);
        assert!(
            core::ptr::read(entry).is_none(),
            "pending RT fixture slot reused"
        );
        core::ptr::write(entry, Some((process.pid, mode)));
    }
}

fn config_record(process: &Process, mode: u64) {
    let rt = process.class.rt().unwrap();
    let priority = rt.priority;
    let first = rt.release;
    let period = rt.period;
    let budget = rt.budget;
    event(
        "RT CONFIG",
        &[
            (" pid=", process.pid),
            (" tick=", now()),
            (" mode=", mode),
            (" priority=", priority as u64),
            (" first=", first),
            (" period=", period),
            (" budget=", budget),
            (" state=", rt.state as u64),
        ],
    );
}

pub(super) fn outgoing(process: &mut Process, timer: bool) {
    let Some(rt) = process.class.rt_mut() else {
        return;
    };
    assert_eq!(crate::cpu::id(), 0, "RT outgoing phases belong to CPU0");
    if timer {
        let from = rt.state;
        let exhausted = rt.charge_tick();
        event(
            "RT CHARGE",
            &[
                (" pid=", process.pid),
                (" tick=", now()),
                (" seq=", rt.sequence),
                (" consumed=", rt.consumed),
                (" remaining=", rt.remaining()),
            ],
        );
        if exhausted {
            event("RT EXHAUST", &[(" pid=", process.pid), (" tick=", now())]);
            transition(process, from, "exhaust");
            park(process);
            return;
        }
    }
    let rt = process.class.rt_mut().unwrap();
    let from = rt.state;
    if from == State::Running {
        if process.state == ProcessState::Waiting {
            rt.block();
        } else {
            rt.preempt();
        }
        transition(
            process,
            from,
            if process.state == ProcessState::Waiting {
                "block"
            } else {
                "preempt"
            },
        );
    }
}

pub(crate) fn complete(process: &mut Process) {
    let rt = process.class.rt_mut().unwrap();
    let from = rt.state;
    rt.complete();
    transition(process, from, "complete");
    park(process);
}

/// Every ordinary wait completion uses this gate; waking never resets consumption.
pub(crate) fn make_runnable(process: &mut Process) {
    if process.stop != absd_kernel::process::StopState::Active {
        return;
    }
    if let Some(rt) = process.class.rt_mut() {
        let from = rt.state;
        rt.wake();
        transition(process, from, "wake");
        match process.class.rt().unwrap().state {
            State::Runnable => process.state = ProcessState::Runnable,
            State::Waiting | State::Exhausted => park(process),
            _ => panic!("RT wake left an ineligible state"),
        }
    } else {
        process.state = ProcessState::Runnable;
    }
    crate::modern_smp::publish(process);
    crate::smp_user::notify_process(process);
}

pub(super) fn release_due(process: &mut Process, tick: u64) {
    if pending_pid(process.pid) {
        return;
    }
    assert_eq!(crate::cpu::id(), 0, "RT timer phases belong to CPU0");
    if !process.is_live() || process.stop != absd_kernel::process::StopState::Active {
        return;
    }
    let Some(rt) = process.class.rt_mut() else {
        return;
    };
    assert!(
        process.cpu_owner.is_none(),
        "RT release before CPU0 departure"
    );
    if tick < rt.next_release {
        return;
    }
    let from = rt.state;
    if rt.sequence > 0 {
        event(
            "RT PERIOD",
            &[
                (" pid=", process.pid),
                (" seq=", rt.sequence),
                (" release=", rt.release),
                (" dispatch=", rt.first_dispatch.unwrap_or(u64::MAX)),
                (" consumed=", rt.consumed),
                (" budget=", rt.budget),
                (" normal=", rt.normal_ticks),
                (" state=", from as u64),
            ],
        );
    }
    let release = rt.release_at(tick).unwrap();
    event(
        "RT RELEASE",
        &[
            (" pid=", process.pid),
            (" requested=", rt.release),
            (" actual=", tick),
            (" missed=", release.skipped + u64::from(release.unfinished)),
            (" skipped=", release.skipped),
            (" total_missed=", rt.missed_total),
            (" late=", release.late),
            (" seq=", rt.sequence),
        ],
    );
    transition(process, from, "release");
    if process.class.rt().unwrap().state == State::Runnable {
        if process.state == ProcessState::Waiting {
            assert_eq!(process.wait_kind, WaitKind::RtRelease);
            process.clear_wait();
        }
        process.state = ProcessState::Runnable;
        crate::modern_smp::publish(process);
    }
}

pub(super) fn dispatch(process: &mut Process, previous_pid: u64) {
    let Some(rt) = process.class.rt_mut() else {
        return;
    };
    let tick = now();
    let from = rt.state;
    if rt.dispatch(tick) {
        event(
            "RT DISPATCH",
            &[
                (" pid=", process.pid),
                (" seq=", rt.sequence),
                (" requested=", rt.release),
                (" actual=", tick),
                (" latency=", tick - rt.release),
                (" from=", previous_pid),
            ],
        );
    }
    event(
        "RT SELECT",
        &[
            (" pid=", process.pid),
            (" tick=", tick),
            (" from=", previous_pid),
            (" priority=", rt.priority as u64),
            (" remaining=", rt.remaining()),
        ],
    );
    transition(process, from, "dispatch");
}

pub(super) fn remove(process: &mut Process) {
    if matches!(boot_mode(), BootMode::RtTest | BootMode::RtClass) {
        unsafe {
            for index in 0..absd_kernel::process::MAX_PROCESSES {
                let ptr = core::ptr::addr_of_mut!(PENDING)
                    .cast::<Option<(u64, u64)>>()
                    .add(index);
                if core::ptr::read(ptr).is_some_and(|(pid, _)| pid == process.pid) {
                    core::ptr::write(ptr, None);
                    process.class = SchedulingClass::Normal;
                    return;
                }
            }
        }
    }
    if process.class.rt().is_some() {
        event("RT REMOVE", &[(" pid=", process.pid), (" tick=", now())]);
        process.class = SchedulingClass::Normal;
    }
}

/// The process transport state and explicit class state agree at every selection.
pub(super) fn assert_bridge(process: &Process) {
    if let Some(rt) = process.class.rt() {
        rt.assert_valid();
        assert!(process.is_live());
        match rt.state {
            State::Runnable => assert_eq!(process.state, ProcessState::Runnable),
            State::Running => assert_eq!(process.state, ProcessState::Running),
            State::Blocked => {
                assert_eq!(process.state, ProcessState::Waiting);
                assert_ne!(process.wait_kind, WaitKind::RtRelease);
            }
            State::Waiting | State::Exhausted => {
                assert_eq!(process.state, ProcessState::Waiting);
                assert_eq!(process.wait_kind, WaitKind::RtRelease);
                assert_eq!(process.wake_at, Some(rt.next_release));
            }
        }
    }
}

static mut PENDING: [Option<(u64, u64)>; absd_kernel::process::MAX_PROCESSES] =
    [None; absd_kernel::process::MAX_PROCESSES];
pub(crate) fn pending_pid(pid: u64) -> bool {
    if !matches!(boot_mode(), BootMode::RtTest | BootMode::RtClass) {
        return false;
    }
    unsafe {
        (0..absd_kernel::process::MAX_PROCESSES).any(|i| {
            core::ptr::read(
                core::ptr::addr_of!(PENDING)
                    .cast::<Option<(u64, u64)>>()
                    .add(i),
            )
            .is_some_and(|(p, _)| p == pid)
        })
    }
}
/// Fixture-only cohort publication, called after the parent sleep commits.
/// Period/budget/priority and scheduler selection remain untouched.
pub(crate) fn arm_fixture(table: &mut absd_kernel::process::ProcessTable, current: usize) {
    if !matches!(boot_mode(), BootMode::RtTest | BootMode::RtClass)
        || table.entries[current].pid != 1
    {
        return;
    }
    assert_eq!(table.entries[current].state, ProcessState::Waiting);
    assert_eq!(table.entries[current].wait_kind, WaitKind::Sleep);
    let anchor = now().checked_add(10).expect("RT fixture clock exhausted");
    for index in 0..absd_kernel::process::MAX_PROCESSES {
        let ptr = unsafe {
            core::ptr::addr_of_mut!(PENDING)
                .cast::<Option<(u64, u64)>>()
                .add(index)
        };
        let Some((pid, mode)) = (unsafe { core::ptr::read(ptr) }) else {
            continue;
        };
        let p = &mut table.entries[index];
        assert_eq!(p.pid, pid, "stale pending fixture PID");
        assert!(p.is_live());
        assert!(p.cpu_owner.is_none(), "pending fixture already CPU-owned");
        let rt = p.class.rt_mut().expect("pending fixture lost class");
        assert_eq!(rt.sequence, 0, "fixture armed after release");
        assert!(matches!(rt.state, State::Waiting | State::Blocked));
        let first = anchor
            .checked_add(if mode == 13 { 4 } else { 0 })
            .expect("RT fixture clock exhausted");
        rt.release = first;
        rt.next_release = first;
        let wake = first
            .checked_add(if mode == 8 {
                rt.period - rt.budget
            } else if mode == 11 {
                rt.period
            } else {
                0
            })
            .expect("RT fixture wake exhausted");
        p.wake_at = Some(wake);
        unsafe {
            core::ptr::write(ptr, None);
        }
        config_record(p, mode);
    }
}
