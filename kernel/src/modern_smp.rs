//! Test-only bounded multi-CPU scheduler tranche. The BKL remains the authority for
//! queue, placement, lifecycle and transfer transactions.
use absd_kernel::process::{CpuClaim, MAX_PROCESSES, Process, ProcessState, StopState};
use absd_kernel::run_queue::{Key, Queues};
use absd_kernel::topology::{CpuTopology, Level};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(false);
static RT_ACTIVE: AtomicBool = AtomicBool::new(false);
static RT_POLICY: AtomicBool = AtomicBool::new(false);
static mut QUEUES: Queues = Queues::new();
static mut PENDING: [u8; MAX_PROCESSES] = [u8::MAX; MAX_PROCESSES];
static mut STEAL: [bool; MAX_PROCESSES] = [false; MAX_PROCESSES];
static mut TRANSFERS: u64 = 0;
static mut STEALS: u64 = 0;
static mut WITNESSES: [u64; 3] = [0; 3];
static mut ARM_BLOCK: u64 = 0;
static mut ARM_STOP: u64 = 0;
static mut DEFERRED: u64 = 0;
static mut CANCELED: [u64; 2] = [0; 2];
#[derive(Clone, Copy)]
struct TransferFrame {
    root: u64,
    context: [u64; absd_kernel::process::SAVED_FRAME_WORDS],
    fpu: absd_kernel::process::FpuState,
}
static mut TRANSFER_FRAME: [Option<TransferFrame>; MAX_PROCESSES] = [None; MAX_PROCESSES];
static mut MUTANT: u8 = 0;
static APIC: [AtomicU32; crate::cpu::MAX_CPUS] =
    [const { AtomicU32::new(0) }; crate::cpu::MAX_CPUS];
static PACKAGE: [AtomicU32; crate::cpu::MAX_CPUS] =
    [const { AtomicU32::new(0) }; crate::cpu::MAX_CPUS];
static CORE: [AtomicU32; crate::cpu::MAX_CPUS] =
    [const { AtomicU32::new(0) }; crate::cpu::MAX_CPUS];
static SHIFT: [AtomicU32; crate::cpu::MAX_CPUS] =
    [const { AtomicU32::new(0) }; crate::cpu::MAX_CPUS];
static READY: [AtomicBool; crate::cpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::cpu::MAX_CPUS];

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}
pub fn configure(rt_policy: bool, rt_active: bool, mutant: u8) {
    if !cfg!(feature = "smp-scheduler-test") {
        panic!("scheduler prototype requires smp-scheduler-test build");
    }
    assert!(crate::smp_user::enabled() && crate::smp_timer::enabled());
    assert!(crate::cpu::is_bootstrap_processor());
    assert!(!ENABLED.swap(true, Ordering::AcqRel));
    RT_POLICY.store(rt_policy, Ordering::Release);
    RT_ACTIVE.store(rt_active, Ordering::Release);
    assert!(mutant <= 3);
    unsafe {
        MUTANT = mutant;
        QUEUES = Queues::with_cpus(crate::cpu::count() as u8);
    }
    capture_topology(0);
}
pub fn capture_topology(cpu: usize) {
    if !enabled() {
        return;
    }
    let maximum = core::arch::x86_64::__cpuid(0).eax;
    let mut decoded = None;
    for leaf in [0x1f, 0x0b] {
        if maximum < leaf {
            continue;
        }
        let mut levels = [Level {
            shift: 0,
            count: 0,
            kind: 0,
            apic: 0,
        }; 8];
        let mut n = 0;
        for sub in 0..8 {
            let c = core::arch::x86_64::__cpuid_count(leaf, sub);
            let count = (c.ebx & 0xffff) as u16;
            let kind = ((c.ecx >> 8) & 255) as u8;
            if count == 0 || kind == 0 {
                break;
            }
            levels[n] = Level {
                shift: (c.eax & 31) as u8,
                count,
                kind,
                apic: c.edx,
            };
            n += 1;
        }
        decoded = absd_kernel::topology::decode(&levels[..n]);
        if decoded.is_some() {
            break;
        }
    }
    let t = decoded.expect("unsupported qualification CPU topology");
    assert!(cpu < crate::cpu::count());
    assert_eq!(
        t.apic, cpu as u32,
        "qualification requires contiguous xAPIC IDs"
    );
    APIC[cpu].store(t.apic, Ordering::Relaxed);
    PACKAGE[cpu].store(t.package, Ordering::Relaxed);
    CORE[cpu].store(t.core, Ordering::Relaxed);
    SHIFT[cpu].store(u32::from(t.smt_shift), Ordering::Relaxed);
    READY[cpu].store(true, Ordering::Release);
}
fn topology(cpu: usize) -> CpuTopology {
    assert!(
        READY[cpu].load(Ordering::Acquire),
        "CPU topology unpublished"
    );
    CpuTopology {
        apic: APIC[cpu].load(Ordering::Relaxed),
        package: PACKAGE[cpu].load(Ordering::Relaxed),
        core: CORE[cpu].load(Ordering::Relaxed),
        smt_shift: SHIFT[cpu].load(Ordering::Relaxed) as u8,
    }
}
fn fields(label: &str, values: &[(&str, u64)]) {
    crate::serial::write(label);
    for (name, value) in values {
        crate::serial::write(name);
        crate::serial::decimal(*value);
    }
    crate::serial::write("\n");
}
pub fn topology_online() {
    if !enabled() {
        return;
    }
    for cpu in 0..crate::cpu::count() {
        let t = topology(cpu);
        let siblings = (0..crate::cpu::count())
            .filter(|&other| t.same_core(topology(other)))
            .fold(0, |mask, other| mask | (1 << other));
        fields(
            "SMP TOPOLOGY",
            &[
                (" cpu=", cpu as u64),
                (" apic=", u64::from(t.apic)),
                (" package=", u64::from(t.package)),
                (" core=", u64::from(t.core)),
                (" siblings=", siblings),
                (" online=", 1),
                (" parked=", u64::from(cpu > 0)),
            ],
        );
    }
    if RT_POLICY.load(Ordering::Acquire) {
        // AP has not received its userspace-start command or armed its timer.
        assert_eq!(crate::cpu::current(), crate::cpu::NO_TASK);
        fields(
            "SMP RT CORE POLICY",
            &[
                (" rt-cpu=", 0),
                (" sibling=", u64::from(topology(0).same_core(topology(1)))),
                (" ap-parked=", 1),
                (" rt-migratable=", 0),
            ],
        );
        crate::serial::write("RT SMT SIBLING CONTENTION UNQUALIFIED\nABSD BOOT OK\n");
        crate::exit_qemu(0);
    }
    if RT_ACTIVE.load(Ordering::Acquire)
        && (1..crate::cpu::count()).any(|cpu| topology(0).same_core(topology(cpu)))
    {
        crate::serial::write(
            "SMP RT SIBLING PRESSURE REFUSED
",
        );
        crate::exit_qemu(1);
    }
}
unsafe fn queues() -> &'static mut Queues {
    crate::kernel_lock::assert_current_owner();
    unsafe { &mut *core::ptr::addr_of_mut!(QUEUES) }
}
fn movable(process: &Process) -> bool {
    process.program == absd_kernel::program::SMP_USER as usize
        && ((56..=60).contains(&process.task.context[absd_kernel::syscall::FRAME_RDX])
            || (crate::smp_nway::enabled()
                && matches!(
                    process.task.context[absd_kernel::syscall::FRAME_RDX],
                    160..=165
                ))
            || (crate::smp_fpu::enabled()
                && process.task.context[absd_kernel::syscall::FRAME_RDX] == 61))
        && process.class.rt().is_none()
}
pub fn register(slot: usize, process: &Process, cpu: u8) {
    if !enabled() {
        return;
    }
    assert!(matches!(
        process.state,
        ProcessState::Runnable | ProcessState::Waiting
    ));
    assert!(process.cpu_owner.is_none() && process.claim_epoch == 0);
    let rt = process.class.rt().is_some();
    let allowed = if movable(process) {
        crate::cpu::mask()
    } else {
        1 << cpu
    };
    unsafe {
        queues().register(slot, process.pid, cpu, allowed, rt);
        PENDING[slot] = u8::MAX;
        STEAL[slot] = false;
    }
}
pub fn placement(slot: usize, pid: u64) -> Option<u8> {
    if !enabled() {
        return None;
    }
    unsafe {
        let q = queues();
        let k = q.key(slot)?;
        assert_eq!(k.pid, pid);
        Some(q.cpu(k))
    }
}
/// Copied pre-start qualification check; no queue borrow crosses release.
pub fn assert_blocked(slot: usize, pid: u64, generation: u64) {
    if !enabled() {
        assert_eq!(generation, 0);
        return;
    }
    unsafe {
        let q = queues();
        let key = q.key(slot).unwrap();
        assert_eq!((key.pid, key.generation), (pid, generation));
        assert!(!q.queued(key) && !q.running(key));
        assert_eq!(PENDING[slot], u8::MAX);
        assert!(!STEAL[slot]);
    }
}
pub fn placement_of_pid(pid: u64) -> Option<u8> {
    if !enabled() {
        return None;
    }
    unsafe {
        let q = queues();
        (0..MAX_PROCESSES).find_map(|i| q.key(i).filter(|k| k.pid == pid).map(|k| q.cpu(k)))
    }
}
fn key_for(pid: u64) -> Key {
    unsafe {
        let q = queues();
        (0..MAX_PROCESSES)
            .find_map(|i| q.key(i).filter(|k| k.pid == pid))
            .expect("unregistered runnable task")
    }
}
pub fn publish(process: &Process) {
    if !enabled() || !process.is_runnable() {
        return;
    }
    unsafe {
        let k = key_for(process.pid);
        let q = queues();
        // Only a caller repeating prepare_runnable may encounter an existing
        // membership. The actual common wake gate asserts Waiting first.
        if !q.queued(k) {
            q.publish(k);
        }
        if PENDING[k.slot] != u8::MAX {
            let to = PENDING[k.slot];
            PENDING[k.slot] = u8::MAX;
            transfer(k, process, to, false);
        }
        crate::smp_user::notify_process(process);
        if STEAL[k.slot] {
            for cpu in 0..crate::cpu::count() as u8 {
                if queues().can_transfer(k, cpu) {
                    crate::smp_user::notify_cpu(cpu);
                }
            }
        }
    }
}
pub fn claimed(slot: usize, claim: CpuClaim, process: &Process) {
    if !enabled() {
        return;
    }
    unsafe {
        let q = queues();
        let k = q.key(slot).unwrap();
        if let Some(expected) = TRANSFER_FRAME[slot] {
            assert_eq!(
                expected.root, process.address_space.root,
                "migrated root changed before claim"
            );
            assert!(
                expected.context == process.task.context,
                "migrated context changed before claim"
            );
            assert!(
                expected.fpu.0 == process.task.fpu.0,
                "migrated FPU changed before claim"
            );
            crate::smp_fpu::migrated(slot, process.pid);
            TRANSFER_FRAME[slot] = None;
        }
        q.claim(k, claim.cpu, claim.epoch);
    }
}
pub fn departed(slot: usize, claim: CpuClaim) {
    if !enabled() {
        return;
    }
    unsafe {
        let q = queues();
        let k = q.key(slot).unwrap();
        q.depart(k, claim.cpu, claim.epoch);
        let p = &crate::sched::table().entries[slot];
        crate::smp_nway::compose_departure(slot, p, k.generation, claim);
        if p.state != ProcessState::Running || p.stop != StopState::Active {
            if PENDING[slot] != u8::MAX {
                let stop = p.stop != StopState::Active;
                CANCELED[usize::from(stop)] += 1;
                fields(
                    "SMP QUEUE CANCEL",
                    &[
                        (" pid=", p.pid),
                        (" epoch=", claim.epoch),
                        (" stop=", u64::from(stop)),
                        (" departed=", 1),
                    ],
                );
            }
            if !crate::smp_nway::retain_cancel(crate::smp_user::fixture_role(slot)) {
                PENDING[slot] = u8::MAX;
            }
        }
    }
}
pub fn remove(slot: usize) {
    if !enabled() {
        return;
    }
    unsafe {
        crate::smp_fpu::removed(slot);
        let q = queues();
        if let Some(k) = q.key(slot) {
            q.remove(k);
        }
        PENDING[slot] = u8::MAX;
        STEAL[slot] = false;
        TRANSFER_FRAME[slot] = None;
    }
}
fn transfer(k: Key, p: &Process, to: u8, steal: bool) {
    crate::smp_fpu::migration_compatible();
    assert!(p.is_runnable() && p.task.context_valid && p.stop == StopState::Active);
    assert_eq!(p.pid, k.pid);
    assert!(READY[to as usize].load(Ordering::Acquire));
    unsafe {
        let q = queues();
        let from = q.cpu(k);
        assert_eq!(q.epoch(k), p.claim_epoch);
        // Non-PCID CR3 reload and CPU-owned stack/TSS departure were checked
        // before `departed`; user leaves never carry the global bit.
        q.transfer(k, to, p.task.context_valid);
        TRANSFER_FRAME[k.slot] = Some(TransferFrame {
            root: p.address_space.root,
            context: p.task.context,
            fpu: p.task.fpu,
        });
        TRANSFERS += 1;
        if steal {
            STEAL[k.slot] = false;
            STEALS += 1;
        }
        fields(
            "SMP QUEUE TRANSFER",
            &[
                (" n=", TRANSFERS),
                (" pid=", k.pid),
                (" slot=", k.slot as u64),
                (" generation=", k.generation),
                (" epoch=", p.claim_epoch),
                (" from=", u64::from(from)),
                (" to=", u64::from(to)),
                (" saved=", 1),
                (" departed=", 1),
                (" steal=", u64::from(steal)),
            ],
        );
        crate::smp_user::notify_process(p);
    }
}
pub fn assert_all() {
    if !enabled() {
        return;
    }
    unsafe {
        let q = queues();
        let t = crate::sched::table();
        for (slot, p) in t.entries.iter().enumerate() {
            let Some(k) = q.key(slot) else {
                assert!(
                    !p.is_runnable() && p.cpu_owner.is_none(),
                    "runnable task lost queue registration"
                );
                continue;
            };
            assert_eq!(k.pid, p.pid, "stale runnable slot");
            assert_eq!(
                q.queued(k),
                p.is_runnable(),
                "lost/extra runnable membership"
            );
            assert_eq!(
                q.running(k),
                p.cpu_owner.is_some(),
                "CPU claim/model disagreement"
            );
            if let Some(claim) = p.cpu_owner {
                assert_eq!(q.cpu(k), claim.cpu);
                assert!(!q.queued(k));
            }
            if p.class.rt().is_some() {
                assert_eq!(q.cpu(k), 0, "RT outside CPU0 queue");
            }
        }
    }
}
pub fn select(current: usize, cpu: u8, allow_steal: bool) -> Option<usize> {
    if allow_steal && let Some(index) = crate::smp_user::negative_selection(cpu) {
        return Some(index);
    }
    assert_all();
    unsafe {
        let q = queues();
        let t = crate::sched::table();
        let priority = (0..MAX_PROCESSES)
            .filter(|&i| q.candidate(cpu, i).is_some())
            .map(|i| t.entries[i].class.priority())
            .max();
        if let Some(priority) = priority {
            return (1..=MAX_PROCESSES)
                .map(|n| (current + n) % MAX_PROCESSES)
                .find(|&i| {
                    q.candidate(cpu, i).is_some() && t.entries[i].class.priority() == priority
                });
        }
        if allow_steal {
            let armed = STEAL;
            for (i, may_steal) in armed.into_iter().enumerate() {
                if let Some(k) = (0..crate::cpu::count() as u8)
                    .filter(|&other| other != cpu)
                    .find_map(|other| q.candidate(other, i))
                    && may_steal
                    && q.can_transfer(k, cpu)
                    && t.entries[i].is_runnable()
                    && t.entries[i].task.context_valid
                {
                    transfer(k, &t.entries[i], cpu, true);
                    return Some(i);
                }
            }
        }
        None
    }
}
pub fn request(pid: u64, to: u8) -> i64 {
    if !enabled() || usize::from(to) >= crate::cpu::count() {
        return absd_kernel::syscall::ERROR_NOT_IMPLEMENTED;
    }
    unsafe {
        let q = queues();
        let Some(k) = (0..MAX_PROCESSES).find_map(|i| q.key(i).filter(|k| k.pid == pid)) else {
            return absd_kernel::syscall::ERROR_AGAIN;
        };
        let p = &crate::sched::table().entries[k.slot];
        // Closed composition audit precedes the generic pending-request refusal,
        // so retaining a canceled destination cannot masquerade as expected Again.
        if crate::smp_nway::enabled()
            && crate::smp_user::fixture_role(k.slot) == 162
            && p.state == ProcessState::Waiting
        {
            assert_eq!(q.allowed(k), crate::cpu::mask());
            assert_eq!(p.stop, StopState::Active);
            assert!(p.cpu_owner.is_none() && p.task.context_valid);
            assert_eq!(
                PENDING[k.slot],
                u8::MAX,
                "blocked migration retained pending destination"
            );
            assert!(!q.queued(k));
            crate::smp_nway::compose_refusal(p, k.generation, q.cpu(k), to);
            return absd_kernel::syscall::ERROR_AGAIN;
        }
        if q.allowed(k) != crate::cpu::mask()
            || p.stop != StopState::Active
            || q.cpu(k) == to
            || PENDING[k.slot] != u8::MAX
        {
            return absd_kernel::syscall::ERROR_AGAIN;
        }
        if p.state == ProcessState::Running && p.cpu_owner.is_some() {
            if MUTANT == 3 {
                transfer(k, p, to, false);
            }
            defer(k, p, to);
            return 0;
        }
        if !p.is_runnable() || !q.can_transfer(k, to) {
            return absd_kernel::syscall::ERROR_AGAIN;
        }
        transfer(k, p, to, false);
        crate::smp_user::notify_runnable();
        0
    }
}
pub fn arm_steal(pid: u64) -> i64 {
    unsafe {
        let k = key_for(pid);
        let p = &crate::sched::table().entries[k.slot];
        assert!(
            queues().allowed(k) == crate::cpu::mask()
                && p.stop == StopState::Active
                && p.claim_epoch > 0
        );
        STEAL[k.slot] = true;
        crate::smp_user::notify_runnable();
    }
    0
}
pub fn witness(stage: u64) -> i64 {
    assert!(stage < 3);
    let slot = crate::cpu::current();
    let p = &unsafe { crate::sched::table() }.entries[slot];
    let k = key_for(p.pid);
    assert_eq!(unsafe { queues() }.allowed(k), crate::cpu::mask());
    let cpu = crate::cpu::id();
    assert_eq!(cpu, u8::from(stage == 1));
    fields(
        "SMP QUEUE USER",
        &[
            (" pid=", p.pid),
            (" generation=", k.generation),
            (" epoch=", p.claim_epoch),
            (" cpu=", u64::from(cpu)),
            (" stage=", stage),
            (" cpl=", 3),
        ],
    );
    unsafe {
        WITNESSES[stage as usize] += 1;
    }
    i64::from(cpu)
}
pub fn generation(slot: usize) -> u64 {
    unsafe { queues().key(slot).unwrap().generation }
}
pub fn verify() {
    assert_all();
    if crate::smp_nway::enabled() {
        unsafe {
            crate::smp_nway::verify(TRANSFERS, STEALS);
        }
        return;
    }
    if crate::smp_fpu::enabled() {
        unsafe {
            assert_eq!({ TRANSFERS }, 32);
            assert_eq!({ STEALS }, 0);
            assert_eq!({ WITNESSES }, [16, 16, 16]);
            assert_eq!({ CANCELED }, [0, 0]);
            fields(
                "SMP QUEUE PROOF",
                &[
                    (" transfers=", TRANSFERS),
                    (" steals=", STEALS),
                    (" before=", WITNESSES[0]),
                    (" remote=", WITNESSES[1]),
                    (" returned=", WITNESSES[2]),
                ],
            );
        }
        return;
    }
    unsafe {
        assert_eq!({ TRANSFERS }, 112);
        assert_eq!({ STEALS }, 16);
        assert_eq!({ WITNESSES }, [80, 80, 32]);
        assert_eq!({ CANCELED }, [32, 16]);
        assert!(DEFERRED >= 48);
        fields(
            "SMP QUEUE CANCEL PROOF",
            &[
                (" blocks=", CANCELED[0]),
                (" stops=", CANCELED[1]),
                (" deferred=", DEFERRED),
            ],
        );
        fields(
            "SMP QUEUE PROOF",
            &[
                (" transfers=", TRANSFERS),
                (" steals=", STEALS),
                (" before=", WITNESSES[0]),
                (" remote=", WITNESSES[1]),
                (" returned=", WITNESSES[2]),
            ],
        );
    }
}
pub fn finish() {
    if !enabled() {
        return;
    }
    assert_all();
    assert!(
        unsafe { queues() }.empty(),
        "machine quiescence retains queue authority"
    );
    crate::serial::write("SMP QUEUE QUIESCENT registered=0 queued=0 running=0\n");
}
pub fn mutate_publication(process: &Process) {
    if !enabled() || !process.is_runnable() {
        return;
    }
    unsafe {
        let k = key_for(process.pid);
        if MUTANT == 1 {
            queues().publish(k);
        }
        if MUTANT == 2 {
            queues().remove(k);
        }
    }
}

pub fn steal_available(cpu: u8) -> bool {
    if !enabled() {
        return false;
    }
    unsafe {
        let q = queues();
        (0..MAX_PROCESSES).any(|i| {
            STEAL[i]
                && (0..crate::cpu::count() as u8)
                    .filter(|&other| other != cpu)
                    .any(|other| {
                        q.candidate(other, i)
                            .is_some_and(|k| q.can_transfer(k, cpu))
                    })
        })
    }
}

fn defer(k: Key, p: &Process, to: u8) {
    assert!(
        p.state == ProcessState::Running && p.cpu_owner.is_some() && p.stop == StopState::Active
    );
    unsafe {
        assert_eq!(queues().allowed(k), crate::cpu::mask());
        assert_eq!(PENDING[k.slot], u8::MAX);
        PENDING[k.slot] = to;
        DEFERRED += 1;
        fields(
            "SMP QUEUE DEFER",
            &[
                (" pid=", p.pid),
                (" epoch=", p.claim_epoch),
                (" to=", u64::from(to)),
            ],
        );
    }
}
pub fn arm_cancel(pid: u64, kind: u8) -> i64 {
    assert!(enabled());
    let k = key_for(pid);
    assert_eq!(unsafe { queues() }.allowed(k), crate::cpu::mask());
    unsafe {
        match kind {
            1 => {
                assert_eq!({ ARM_BLOCK }, 0);
                ARM_BLOCK = pid;
            }
            2 => {
                assert_eq!({ ARM_STOP }, 0);
                ARM_STOP = pid;
            }
            _ => panic!("unknown cancel fixture"),
        }
    }
    0
}
pub fn before_block_entry(p: &Process, number: u64) {
    if !enabled() {
        return;
    }
    unsafe {
        if ARM_BLOCK == p.pid && number == absd_kernel::syscall::SYS_READ {
            ARM_BLOCK = 0;
            let cpu = p.cpu_owner.unwrap().cpu;
            if crate::smp_nway::enabled()
                && crate::smp_user::fixture_role(key_for(p.pid).slot) == 162
            {
                assert!(cpu > 0 && (cpu as usize) < crate::cpu::count());
            } else {
                assert_eq!(cpu, 1);
            }
            let k = key_for(p.pid);
            defer(k, p, 0);
        }
    }
}
pub fn before_stop(p: &Process) {
    if !enabled() {
        return;
    }
    unsafe {
        if ARM_STOP == p.pid {
            ARM_STOP = 0;
            let cpu = p.cpu_owner.unwrap().cpu;
            if crate::smp_nway::enabled()
                && crate::smp_user::fixture_role(key_for(p.pid).slot) == 165
            {
                assert!(cpu > 0 && (cpu as usize) < crate::cpu::count());
            } else {
                assert_eq!(cpu, 1);
            }
            let k = key_for(p.pid);
            defer(k, p, 0);
        }
    }
}
