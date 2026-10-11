//! Bounded 2/4/6-CPU qualification. Protocol records are BKL-owned;
//! early vector-entry epochs are CPU-written atomics on the shared fixture page.
use absd_kernel::process::{MAX_PROCESSES, Process, ProcessState};
use core::sync::atomic::{AtomicBool, Ordering};
static RESTORE_MUTANT: AtomicBool = AtomicBool::new(false);
static INJECTED: AtomicBool = AtomicBool::new(false);
static CANCEL_MUTANT: AtomicBool = AtomicBool::new(false);
static TERMINAL_MUTANT: AtomicBool = AtomicBool::new(false);
static ENABLED: AtomicBool = AtomicBool::new(false);
#[unsafe(no_mangle)]
static SMP_NWAY_EPOCH_PTR: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static mut OVERLAP: bool = false;
static mut PREEMPTS: [u64; MAX_PROCESSES] = [0; MAX_PROCESSES];
static mut IDENTITIES: [u64; MAX_PROCESSES] = [0; MAX_PROCESSES];
static mut WORKERS: u64 = 0;
static mut USERS: u64 = 0;
static mut BLOCKS: [u64; crate::cpu::MAX_CPUS] = [0; crate::cpu::MAX_CPUS];
static mut PIPES: [u64; crate::cpu::MAX_CPUS] = [0; crate::cpu::MAX_CPUS];
static mut FAULTS: [u64; crate::cpu::MAX_CPUS] = [0; crate::cpu::MAX_CPUS];
static mut COMPOSE: [[u64; 5]; crate::cpu::MAX_CPUS] = [[0; 5]; crate::cpu::MAX_CPUS];
static mut COMPOSE_TIMERS: [[u64; crate::cpu::MAX_CPUS]; MAX_PROCESSES] =
    [[0; crate::cpu::MAX_CPUS]; MAX_PROCESSES];
#[derive(Clone, Copy)]
struct Terminal {
    pid: u64,
    generation: u64,
    role: u64,
    claim: absd_kernel::process::CpuClaim,
    kind: u64,
}
static mut TERMINALS: [Option<Terminal>; MAX_PROCESSES] = [None; MAX_PROCESSES];
static mut TARGETS: [u8; MAX_PROCESSES] = [u8::MAX; MAX_PROCESSES];
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}
#[cfg(feature = "smp-scheduler-test")]
pub fn requires_running_stop(caller: usize, child: usize) -> bool {
    if !enabled() {
        return false;
    }
    crate::kernel_lock::assert_current_owner();
    matches!(crate::smp_user::fixture_role(caller), 120 | 196)
        && ((144..=149).contains(&crate::smp_user::fixture_role(child))
            || crate::smp_user::fixture_role(child) == 165)
}
pub fn configure(restore_mutant: bool, cancel_mutant: bool, terminal_mutant: bool) {
    assert!(
        crate::modern_smp::enabled()
            && crate::smp_user::standalone()
            && !crate::smp_fpu::enabled()
            && crate::smp_bench::mode() == 0
    );
    assert!(!ENABLED.swap(true, Ordering::AcqRel));
    RESTORE_MUTANT.store(restore_mutant, Ordering::Release);
    CANCEL_MUTANT.store(cancel_mutant, Ordering::Release);
    TERMINAL_MUTANT.store(terminal_mutant, Ordering::Release);
    SMP_NWAY_EPOCH_PTR.store(crate::smp_user::nway_epoch_pointer(), Ordering::Release);
}
pub fn overlap(slot: usize) -> i64 {
    crate::kernel_lock::assert_current_owner();
    assert!(enabled() && crate::cpu::id() == 0);
    assert_eq!(crate::smp_user::fixture_role(slot), 128);
    let p = &unsafe { crate::sched::table() }.entries[slot];
    assert_eq!(p.cpu_owner.unwrap().cpu, 0);
    unsafe {
        assert!(!OVERLAP);
        for cpu in 0..crate::cpu::count() {
            let before = crate::smp_user::nway_sample(420 + cpu);
            let after = crate::smp_user::nway_sample(430 + cpu);
            let first = crate::smp_user::nway_sample(440 + cpu);
            let last = crate::smp_user::nway_sample(450 + cpu);
            assert_eq!(before, after, "N-way overlap crossed user entry");
            assert!(last > first, "N-way overlap missing CPU progress");
            fields(
                "SMP NWAY OVERLAP",
                &[
                    (" observer=", p.pid),
                    (" generation=", crate::modern_smp::generation(slot)),
                    (" cpu=", cpu as u64),
                    (" mask=", crate::cpu::mask() as u64),
                    (" before=", before),
                    (" after=", after),
                    (" first=", first),
                    (" last=", last),
                    (" cpl=", 3),
                ],
            );
        }
        OVERLAP = true;
    }
    observer_snapshot();
    0
}
pub fn observer_snapshot() {
    let sample = crate::smp_user::nway_sample;
    fields(
        "SMP NWAY OBSERVER",
        &[
            (" phase=", sample(480)),
            (" start=", sample(492)),
            (" attempts=", sample(481)),
            (" rejects=", sample(482)),
            (" changed-mask=", sample(483)),
            (" missing-mask=", sample(484)),
            (" polls=", sample(485)),
            (" cpu0=", sample(486)),
            (" cpu1=", sample(487)),
            (" cpu2=", sample(488)),
            (" cpu3=", sample(489)),
            (" cpu4=", sample(490)),
            (" cpu5=", sample(491)),
        ],
    );
}
pub fn serialization_refusal(progress: u64) {
    assert!(enabled());
    if progress == 1
        && !unsafe { OVERLAP }
        && crate::smp_user::nway_sample(410) == 0
        && crate::smp_user::nway_sample(480) == 2
        && crate::smp_user::nway_sample(481) > 0
    {
        crate::serial::write("SMP NWAY SERIALIZATION REFUSED overlap=0 observer-started=1\n");
    }
}
pub fn placement(role: u64) -> u8 {
    let cpu = match role {
        120 | 160..=165 => 0,
        128..=139 => ((role - 128) / 2) as u8,
        144..=149 => (role - 144) as u8,
        176..=181 => (role - 176) as u8,
        184..=189 => (role - 184) as u8,
        196 => 1,
        _ => panic!("unknown N-way qualification role"),
    };
    assert!(
        (cpu as usize) < crate::cpu::count(),
        "offline fixture placement"
    );
    // Validate the intended role/topology first. This closed substitution
    // advances all worker counters through CPU0 time slicing, never overlap.
    if crate::smp_user::serialized_nway() {
        0
    } else {
        cpu
    }
}
fn fields(label: &str, values: &[(&str, u64)]) {
    crate::kernel_lock::assert_current_owner();
    crate::serial::write(label);
    for (name, value) in values {
        crate::serial::write(name);
        crate::serial::decimal(*value);
    }
    crate::serial::write("\n");
}
fn identity(slot: usize, p: &Process) {
    unsafe {
        if IDENTITIES[slot] != p.pid {
            IDENTITIES[slot] = p.pid;
            PREEMPTS[slot] = 0;
            COMPOSE_TIMERS[slot] = [0; crate::cpu::MAX_CPUS];
            TERMINALS[slot] = None;
            TARGETS[slot] = u8::MAX;
        }
    }
}
pub fn saved(slot: usize, p: &Process, preempted: bool) {
    if !enabled() {
        return;
    }
    let role = crate::smp_user::fixture_role(slot);
    identity(slot, p);
    let worker = (128..=139).contains(&role);
    // Live assembly holds R12 and XMM15 without a voluntary trap. The frame
    // ABI puts R12 at word3; XMM15 is FXSAVE byte400. Do not count setup polls.
    let id = role.wrapping_sub(128);
    let live = !worker
        || (p.task.context[3] == (0x1122_3344_5566_7788 ^ id)
            && u64::from_le_bytes(p.task.fpu.0[400..408].try_into().unwrap())
                == (0x1357_9bdf_2468_ace0 ^ id)
            && u64::from_le_bytes(p.task.fpu.0[408..416].try_into().unwrap())
                == (0xfedc_ba98_7654_3210 ^ id));
    if preempted && live {
        unsafe {
            PREEMPTS[slot] += 1;
            if PREEMPTS[slot] == 1 {
                fields(
                    "SMP NWAY PREEMPT",
                    &[
                        (" pid=", p.pid),
                        (" generation=", crate::modern_smp::generation(slot)),
                        (" role=", role),
                        (" cpu=", crate::cpu::id() as u64),
                        (" saved=", 1),
                    ],
                );
            }
        }
    }
    if preempted && role == 165 {
        let cpu = crate::cpu::id() as usize;
        unsafe {
            COMPOSE_TIMERS[slot][cpu] += 1;
            if COMPOSE_TIMERS[slot][cpu] == 1 {
                compose_event(
                    "TIMER",
                    p.pid,
                    crate::modern_smp::generation(slot),
                    role,
                    cpu as u8,
                    p.claim_epoch,
                    &[(" saved=", 1)],
                );
            }
        }
    }
    if role == 162 && p.state == ProcessState::Waiting {
        let cpu = crate::cpu::id() as usize;
        assert!(cpu > 0 && cpu < crate::cpu::count());
        unsafe {
            COMPOSE[cpu][0] += 1;
        }
        compose_event(
            "BLOCK",
            p.pid,
            crate::modern_smp::generation(slot),
            role,
            cpu as u8,
            p.claim_epoch,
            &[(" saved=", 1)],
        );
    }
    if (184..=189).contains(&role) && p.state == ProcessState::Waiting {
        let cpu = crate::cpu::id() as usize;
        unsafe {
            BLOCKS[cpu] += 1;
        }
        fields(
            "SMP NWAY BLOCK",
            &[
                (" pid=", p.pid),
                (" generation=", crate::modern_smp::generation(slot)),
                (" cpu=", cpu as u64),
                (" saved=", 1),
            ],
        );
    }
}
pub fn preempts(pid: u64) -> i64 {
    unsafe {
        (0..MAX_PROCESSES)
            .find(|&i| IDENTITIES[i] == pid)
            .map_or(0, |i| PREEMPTS[i] as i64)
    }
}
pub fn compose_timers(pid: u64, cpu: u64) -> i64 {
    crate::kernel_lock::assert_current_owner();
    assert!(enabled() && cpu > 0 && cpu < crate::cpu::count() as u64);
    unsafe {
        let slot = crate::sched::table()
            .slot_of(pid)
            .expect("unknown composition child");
        assert_eq!(crate::smp_user::fixture_role(slot), 165);
        assert_eq!(IDENTITIES[slot], pid);
        COMPOSE_TIMERS[slot][cpu as usize] as i64
    }
}
fn compose_event(
    label: &str,
    pid: u64,
    generation: u64,
    role: u64,
    cpu: u8,
    epoch: u64,
    extra: &[(&str, u64)],
) {
    crate::kernel_lock::assert_current_owner();
    crate::serial::write("SMP NWAY COMPOSE ");
    crate::serial::write(label);
    let base = [
        (" pid=", pid),
        (" generation=", generation),
        (" role=", role),
        (" cpu=", cpu as u64),
        (" epoch=", epoch),
    ];
    for (name, value) in base.iter().chain(extra.iter()) {
        crate::serial::write(name);
        crate::serial::decimal(*value);
    }
    crate::serial::write("\n");
}
pub fn compose_refusal(p: &Process, generation: u64, cpu: u8, to: u8) {
    assert!(enabled() && p.state == ProcessState::Waiting && p.cpu_owner.is_none());
    assert!(cpu > 0 && (cpu as usize) < crate::cpu::count() && to == 0);
    unsafe {
        COMPOSE[cpu as usize][1] += 1;
    }
    compose_event(
        "REFUSE",
        p.pid,
        generation,
        162,
        cpu,
        p.claim_epoch,
        &[(" to=", to as u64), (" waiting=", 1)],
    );
}
pub fn retain_cancel(role: u64) -> bool {
    if enabled() && role == 162 && CANCEL_MUTANT.load(Ordering::Acquire) {
        crate::serial::write("SMP NWAY COMPOSE INJECT retained-cancel=1\n");
        true
    } else {
        false
    }
}
pub fn compose_departure(
    slot: usize,
    p: &Process,
    generation: u64,
    claim: absd_kernel::process::CpuClaim,
) {
    if !enabled() {
        return;
    }
    let role = crate::smp_user::fixture_role(slot);
    if !(162..=165).contains(&role) {
        return;
    }
    let kind = if p.stop == absd_kernel::process::StopState::Departed {
        2
    } else if p.state == ProcessState::Faulted {
        1
    } else if p.state == ProcessState::Exited {
        0
    } else {
        return;
    };
    identity(slot, p);
    assert!(p.cpu_owner.is_none() && claim.cpu > 0);
    assert!(matches!((role, kind), (162 | 164, 0) | (163, 1) | (165, 2)));
    unsafe {
        let prior = TERMINALS[slot];
        assert!(prior.is_none(), "duplicate composition departure");
        TERMINALS[slot] = Some(Terminal {
            pid: p.pid,
            generation,
            role,
            claim,
            kind,
        });
    }
    compose_event(
        "DEPART",
        p.pid,
        generation,
        role,
        claim.cpu,
        claim.epoch,
        &[(" kind=", kind), (" departed=", 1)],
    );
}
pub fn witness(slot: usize, expected: u64, stage: u64) -> i64 {
    let p = &unsafe { crate::sched::table() }.entries[slot];
    let cpu = crate::cpu::id();
    assert_eq!(expected, u64::from(cpu));
    assert_eq!(p.cpu_owner.unwrap().cpu, cpu);
    let role = crate::smp_user::fixture_role(slot);
    identity(slot, p);
    unsafe {
        if (128..=139).contains(&role) {
            assert_eq!(stage, role - 128);
            assert!(
                PREEMPTS[slot] > 0,
                "worker did not receive timer preemption"
            );
            WORKERS += 1;
        } else if (160..=165).contains(&role) {
            USERS += 1;
            if (162..=165).contains(&role) && stage == 1 {
                assert!(cpu > 0 && TARGETS[slot] == u8::MAX);
                TARGETS[slot] = cpu;
            }
        } else if (184..=189).contains(&role) {
            assert_eq!(stage, 0);
            assert!(BLOCKS[cpu as usize] > 0);
            PIPES[cpu as usize] += 1;
        } else {
            panic!("unexpected N-way user witness");
        }
        fields(
            "SMP NWAY USER",
            &[
                (" pid=", p.pid),
                (" generation=", crate::modern_smp::generation(slot)),
                (" role=", role),
                (" cpu=", cpu as u64),
                (" stage=", stage),
                (" epoch=", p.claim_epoch),
                (" preempts=", PREEMPTS[slot]),
                (" cpl=", 3),
            ],
        );
    }
    i64::from(cpu)
}
pub fn terminal(slot: usize, p: &Process, role: u64) {
    if !enabled() {
        return;
    }
    if (162..=165).contains(&role) {
        // Unpublished Created rollback has never executed and has no departure.
        if p.state == ProcessState::Created {
            return;
        }
        let terminal = unsafe {
            let ptr = core::ptr::addr_of_mut!(TERMINALS)
                .cast::<Option<Terminal>>()
                .add(slot);
            let value = ptr.read();
            ptr.write(None);
            value
        };
        let mut t = terminal.expect("composition terminal without departure");
        assert_eq!((t.pid, t.role), (p.pid, role));
        assert!(p.cpu_owner.is_none());
        if role == 165 && TERMINAL_MUTANT.load(Ordering::Acquire) {
            crate::serial::write("SMP NWAY COMPOSE INJECT terminal-cpu=0\n");
            t.claim.cpu = 0;
        }
        assert_eq!(
            t.claim.cpu,
            unsafe { TARGETS[slot] },
            "composition terminal CPU differs from user witness"
        );
        let outcome = match t.kind {
            0 => {
                assert_eq!(p.state, ProcessState::Exited);
                assert_eq!(p.exit_status, 7);
                7
            }
            1 => {
                assert_eq!(p.state, ProcessState::Faulted);
                assert_eq!(p.fault_vector, 14);
                14
            }
            2 => {
                assert_eq!(p.state, ProcessState::Killed);
                0
            }
            _ => unreachable!(),
        };
        unsafe {
            COMPOSE[t.claim.cpu as usize][2 + t.kind as usize] += 1;
        }
        compose_event(
            "TERMINAL",
            t.pid,
            t.generation,
            role,
            t.claim.cpu,
            t.claim.epoch,
            &[
                (" kind=", t.kind),
                (" outcome=", outcome),
                (" departed=", 1),
            ],
        );
        return;
    }
    let cpu = placement(role) as usize;
    if (176..=181).contains(&role) {
        assert_eq!(p.state, ProcessState::Faulted);
        assert_eq!(p.fault_vector, 14);
        unsafe {
            FAULTS[cpu] += 1;
        }
        fields(
            "SMP NWAY FAULT",
            &[
                (" pid=", p.pid),
                (" cpu=", cpu as u64),
                (" vector=", 14),
                (" departed=", 1),
            ],
        );
    }
}
pub fn verify(transfers: u64, steals: u64) {
    let cpus = crate::cpu::count() as u64;
    unsafe {
        assert!({ OVERLAP }, "N-way overlap witness missing");
        assert_eq!({ WORKERS }, cpus * 2);
        assert_eq!({ USERS }, 16 * (cpus + 1) + 48 + 9 * (cpus - 1));
        assert_eq!(transfers, 16 * cpus + 32 + 4 * (cpus - 1));
        assert_eq!(steals, 16);
        for cpu in 0..crate::cpu::count() {
            assert_eq!(PIPES[cpu], 1);
            assert_eq!(BLOCKS[cpu], 1);
            assert_eq!(FAULTS[cpu], 1);
            if cpu > 0 {
                assert!(crate::smp_timer::per_cpu_irqs(cpu) > 0);
            }
            fields(
                "SMP NWAY CPU",
                &[
                    (" cpu=", cpu as u64),
                    (" pipes=", PIPES[cpu]),
                    (" blocks=", BLOCKS[cpu]),
                    (" faults=", FAULTS[cpu]),
                ],
            );
            assert_eq!(
                COMPOSE[cpu],
                if cpu == 0 { [0; 5] } else { [1, 1, 2, 1, 1] }
            );
            fields(
                "SMP NWAY COMPOSE CPU",
                &[
                    (" cpu=", cpu as u64),
                    (" blocks=", COMPOSE[cpu][0]),
                    (" refusals=", COMPOSE[cpu][1]),
                    (" exits=", COMPOSE[cpu][2]),
                    (" faults=", COMPOSE[cpu][3]),
                    (" kills=", COMPOSE[cpu][4]),
                ],
            );
        }
        assert!(
            (*core::ptr::addr_of!(TERMINALS))
                .iter()
                .all(Option::is_none)
        );
        fields("SMP NWAY COMPOSE PROOF", &[(" tasks=", 4 * (cpus - 1))]);
        fields(
            "SMP NWAY PROOF",
            &[
                (" cpus=", cpus),
                (" workers=", WORKERS),
                (" users=", USERS),
                (" transfers=", transfers),
                (" steals=", steals),
            ],
        );
    }
}

/// Substitute only the resumed last-CPU worker's XMM15 scratch. This is a
/// closed negative control, excluded from normal/default boots.
pub fn restore_negative(slot: usize, p: &Process) {
    if !enabled() || !RESTORE_MUTANT.load(Ordering::Acquire) {
        return;
    }
    let role = crate::smp_user::fixture_role(slot);
    if (128..=139).contains(&role)
        && crate::cpu::id() as usize == crate::cpu::count() - 1
        && unsafe { IDENTITIES[slot] == p.pid && PREEMPTS[slot] > 0 }
    {
        if !INJECTED.swap(true, Ordering::AcqRel) {
            fields(
                "SMP NWAY INJECT",
                &[
                    (" restore-sentinel=", 1),
                    (" cpu=", crate::cpu::id() as u64),
                    (" pid=", p.pid),
                    (" role=", role),
                ],
            );
        }
        unsafe {
            core::ptr::write_bytes(crate::cpu::user_fpu().cast::<u8>().add(400), 0, 16);
        }
    }
}
