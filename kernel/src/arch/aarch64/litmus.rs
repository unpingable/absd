//! Controlled atomic publication witnesses, paired with the bounded host model.
//! These finite runs do not by themselves prove ARM weak-memory completeness.
use absd_kernel::owner_lock::OwnerLock;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
// A peer must never combine an old ticket for another CPU with a new target.
// Its channel contains only its own tickets; DONE fences metadata reuse.
static GO: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static CASE: AtomicUsize = AtomicUsize::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
static FLAG: AtomicU64 = AtomicU64::new(0);
static REFS: AtomicU64 = AtomicU64::new(0);
static DATA: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static RESULT: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static SEEN: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static CONTROL: AtomicBool = AtomicBool::new(false);
static LOCK: OwnerLock = OwnerLock::new();
const NAMES: [&str; 10] = [
    "message-passing",
    "store-load-publication",
    "queue-handoff",
    "ownership-token",
    "generation-replacement",
    "task-stop-observation",
    "refcount-reclaim",
    "wake-after-state",
    "lock-handoff",
    "object-visibility",
];
pub fn configure(early_publication: bool) {
    CONTROL.store(early_publication, Ordering::Release);
}
fn wait_until(predicate: impl Fn() -> bool) {
    let end = super::virtio::counter() + super::virtio::frequency() * 2;
    while !predicate() {
        assert!(
            super::virtio::counter() < end,
            "controlled publication timeout"
        );
        core::hint::spin_loop();
    }
}
pub fn primary() {
    let mut sequence = 0;
    for (target, ticket) in GO.iter().enumerate().take(crate::cpu::count()).skip(1) {
        for case in 1..=10 {
            for _ in 0..16 {
                sequence += 1;
                for i in 0..4 {
                    DATA[i].store(0, Ordering::Relaxed);
                    RESULT[i].store(0, Ordering::Relaxed);
                }
                FLAG.store(0, Ordering::Relaxed);
                REFS.store(2, Ordering::Relaxed);
                DONE.store(0, Ordering::Relaxed);
                CASE.store(case, Ordering::Relaxed);
                if case == 9 {
                    while LOCK.try_acquire(0).is_err() {
                        core::hint::spin_loop();
                    }
                }
                ticket.store(sequence, Ordering::Release);
                if CONTROL.load(Ordering::Acquire) && case == 1 {
                    FLAG.store(sequence, Ordering::Release);
                    wait_until(|| DONE.load(Ordering::Acquire) == sequence);
                    assert_eq!(
                        RESULT[0].load(Ordering::Relaxed),
                        sequence,
                        "deterministic early publication exposed stale value"
                    );
                }
                if case == 2 {
                    DATA[0].store(1, Ordering::SeqCst);
                    let observed = DATA[1].load(Ordering::SeqCst);
                    wait_until(|| DONE.load(Ordering::Acquire) == sequence);
                    assert!(
                        observed != 0 || RESULT[0].load(Ordering::Relaxed) != 0,
                        "forbidden SC store-load outcome"
                    );
                } else if case == 7 {
                    wait_until(|| REFS.load(Ordering::Acquire) == 1);
                    assert_eq!(REFS.fetch_sub(1, Ordering::AcqRel), 1);
                    assert_eq!(
                        DATA[0].load(Ordering::Relaxed),
                        sequence,
                        "reclaim before final reference publication"
                    );
                    wait_until(|| DONE.load(Ordering::Acquire) == sequence);
                } else {
                    for (i, data) in DATA.iter().enumerate() {
                        data.store(sequence + i as u64, Ordering::Relaxed);
                    }
                    if case == 9 {
                        LOCK.release(0);
                    } else {
                        FLAG.store(sequence, Ordering::Release);
                    }
                    wait_until(|| DONE.load(Ordering::Acquire) == sequence);
                    for (i, result) in RESULT.iter().enumerate() {
                        assert_eq!(
                            result.load(Ordering::Relaxed),
                            sequence + i as u64,
                            "publication state mismatch"
                        );
                    }
                }
            }
            use core::fmt::Write;
            let _ = writeln!(
                crate::Serial,
                "ARM LITMUS case={} peer={target} witnesses=16 PASS",
                NAMES[case - 1]
            );
        }
    }
    crate::out("ARM WEAK MEMORY WITNESSES OK\n");
}
pub fn secondary(cpu: usize) {
    let sequence = GO[cpu].load(Ordering::Acquire);
    if sequence == 0 || SEEN[cpu].load(Ordering::Relaxed) == sequence {
        return;
    }
    let case = CASE.load(Ordering::Relaxed);
    if case == 2 {
        DATA[1].store(1, Ordering::SeqCst);
        RESULT[0].store(DATA[0].load(Ordering::SeqCst), Ordering::Relaxed);
    } else if case == 7 {
        DATA[0].store(sequence, Ordering::Relaxed);
        assert_eq!(REFS.fetch_sub(1, Ordering::Release), 2);
    } else {
        if case == 9 {
            while LOCK.try_acquire(cpu as u8).is_err() {
                core::hint::spin_loop();
            }
        } else {
            wait_until(|| FLAG.load(Ordering::Acquire) == sequence);
        }
        for (i, result) in RESULT.iter().enumerate() {
            result.store(DATA[i].load(Ordering::Relaxed), Ordering::Relaxed);
        }
        if case == 9 {
            LOCK.release(cpu as u8);
        }
    }
    SEEN[cpu].store(sequence, Ordering::Relaxed);
    DONE.store(sequence, Ordering::Release);
}
