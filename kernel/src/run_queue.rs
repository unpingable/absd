//! Bounded per-CPU queue authority. Callers serialize transactions and prove
//! hardware departure before `depart`. No shared-address-space execution.
use crate::process::MAX_PROCESSES;
pub const MAX_CPUS: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub slot: usize,
    pub pid: u64,
    pub generation: u64,
}
#[derive(Clone, Copy)]
struct Entry {
    key: Key,
    cpu: u8,
    allowed: u8,
    rt: bool,
    running: bool,
    epoch: u64,
    departed: u64,
}
const EMPTY: Entry = Entry {
    key: Key {
        slot: 0,
        pid: 0,
        generation: 0,
    },
    cpu: 0,
    allowed: 0,
    rt: false,
    running: false,
    epoch: 0,
    departed: 0,
};
#[derive(Clone)]
pub struct Queues {
    entries: [Entry; MAX_PROCESSES],
    queues: [[Option<Key>; MAX_PROCESSES]; MAX_CPUS],
    cpus: u8,
    generation: u64,
}
impl Default for Queues {
    fn default() -> Self {
        Self::new()
    }
}
impl Queues {
    pub const fn new() -> Self {
        Self::with_cpus(2)
    }
    pub const fn with_cpus(cpus: u8) -> Self {
        assert!(cpus >= 1 && cpus <= MAX_CPUS as u8);
        Self {
            entries: [EMPTY; MAX_PROCESSES],
            queues: [[None; MAX_PROCESSES]; MAX_CPUS],
            cpus,
            generation: 0,
        }
    }
    pub fn key(&self, slot: usize) -> Option<Key> {
        let key = self.entries[slot].key;
        (key.pid != 0).then_some(key)
    }
    fn entry(&self, key: Key) -> Entry {
        let e = self.entries[key.slot];
        assert_eq!(e.key, key, "stale queue registration");
        assert_ne!(key.pid, 0);
        e
    }
    pub fn register(&mut self, slot: usize, pid: u64, cpu: u8, allowed: u8, rt: bool) -> Key {
        assert!(
            cpu < self.cpus
                && pid != 0
                && allowed & (1 << cpu) != 0
                && allowed & !((1u8 << self.cpus) - 1) == 0
        );
        assert!(self.key(slot).is_none(), "live queue slot reused");
        assert!(
            !self.entries.iter().any(|e| e.key.pid == pid),
            "duplicate live PID registration"
        );
        assert!(!rt || (cpu == 0 && allowed == 1), "RT placement refused");
        self.generation = self
            .generation
            .checked_add(1)
            .expect("queue generation wrap");
        let key = Key {
            slot,
            pid,
            generation: self.generation,
        };
        self.entries[slot] = Entry {
            key,
            cpu,
            allowed,
            rt,
            ..EMPTY
        };
        key
    }
    pub fn cpu(&self, key: Key) -> u8 {
        self.entry(key).cpu
    }
    pub fn running(&self, key: Key) -> bool {
        self.entry(key).running
    }
    pub fn allowed(&self, key: Key) -> u8 {
        self.entry(key).allowed
    }
    pub fn epoch(&self, key: Key) -> u64 {
        self.entry(key).epoch
    }
    pub fn queued(&self, key: Key) -> bool {
        let e = self.entry(key);
        let memberships = self
            .queues
            .iter()
            .filter(|q| q[key.slot] == Some(key))
            .count();
        assert!(memberships <= 1, "duplicate queue owner");
        if memberships != 0 {
            assert!(!e.running, "running task queued");
            assert_eq!(self.queues[e.cpu as usize][key.slot], Some(key));
        }
        memberships == 1
    }
    pub fn publish(&mut self, key: Key) {
        let e = self.entry(key);
        assert!(
            !e.running && e.epoch == e.departed,
            "runnable before departure"
        );
        assert!(!self.queued(key), "duplicate runnable publication");
        self.queues[e.cpu as usize][key.slot] = Some(key);
    }
    pub fn candidate(&self, cpu: u8, slot: usize) -> Option<Key> {
        assert!(cpu < self.cpus, "offline queue candidate");
        self.queues[cpu as usize][slot]
    }
    pub fn claim(&mut self, key: Key, cpu: u8, epoch: u64) {
        let e = self.entry(key);
        assert_eq!(e.cpu, cpu, "wrong queue claim");
        assert!(self.queued(key) && !e.running);
        assert_eq!(epoch, e.epoch.checked_add(1).unwrap(), "stale claim epoch");
        self.queues[cpu as usize][key.slot] = None;
        self.entries[key.slot].running = true;
        self.entries[key.slot].epoch = epoch;
    }
    pub fn depart(&mut self, key: Key, cpu: u8, epoch: u64) {
        let e = self.entry(key);
        assert!(
            e.running && e.cpu == cpu && e.epoch == epoch,
            "stale departure"
        );
        assert!(!self.queued(key));
        self.entries[key.slot].running = false;
        self.entries[key.slot].departed = epoch;
    }
    pub fn can_transfer(&self, key: Key, to: u8) -> bool {
        let e = self.entry(key);
        to < self.cpus
            && e.cpu != to
            && !e.rt
            && e.allowed & (1 << to) != 0
            && !e.running
            && e.epoch > 0
            && e.departed == e.epoch
            && self.queued(key)
    }
    pub fn transfer(&mut self, key: Key, to: u8, saved: bool) {
        let e = self.entry(key);
        assert!(saved && self.can_transfer(key, to), "unsafe queue transfer");
        self.queues[e.cpu as usize][key.slot] = None;
        self.entries[key.slot].cpu = to;
        self.queues[to as usize][key.slot] = Some(key);
        assert!(self.queued(key));
    }
    pub fn remove(&mut self, key: Key) {
        let e = self.entry(key);
        assert!(
            !e.running && e.epoch == e.departed,
            "release before departure"
        );
        for queue in &mut self.queues {
            queue[key.slot] = None;
        }
        self.entries[key.slot] = EMPTY;
    }
    pub fn empty(&self) -> bool {
        self.entries.iter().all(|e| e.key.pid == 0)
            && self.queues.iter().flatten().all(Option::is_none)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transfers_preserve_single_authority_over_repeated_claims() {
        let mut q = Queues::new();
        let key = q.register(0, 7, 0, 3, false);
        q.publish(key);
        for epoch in 1..=64 {
            let cpu = q.cpu(key);
            q.claim(key, cpu, epoch);
            assert!(!q.queued(key) && !q.can_transfer(key, 1 - cpu));
            q.depart(key, cpu, epoch);
            // Departure alone does not publish a task (it may be blocked/stopping).
            assert!(!q.can_transfer(key, 1 - cpu));
            q.publish(key);
            q.transfer(key, 1 - cpu, true);
            assert!(q.candidate(cpu, 0).is_none());
            assert_eq!(q.candidate(1 - cpu, 0), Some(key));
        }
        q.remove(key);
        assert!(q.empty());
    }
    #[test]
    fn pinned_rt_never_transfers() {
        let mut q = Queues::new();
        let k = q.register(0, 9, 0, 1, true);
        q.publish(k);
        q.claim(k, 0, 1);
        q.depart(k, 0, 1);
        q.publish(k);
        assert!(!q.can_transfer(k, 1));
    }
    #[test]
    #[should_panic(expected = "duplicate runnable publication")]
    fn duplicate_wake_rejected() {
        let mut q = Queues::new();
        let k = q.register(0, 9, 0, 3, false);
        q.publish(k);
        q.publish(k);
    }
    #[test]
    #[should_panic(expected = "unsafe queue transfer")]
    fn migration_before_departure_rejected() {
        let mut q = Queues::new();
        let k = q.register(0, 9, 0, 3, false);
        q.publish(k);
        q.claim(k, 0, 1);
        q.transfer(k, 1, true);
    }
    #[test]
    #[should_panic(expected = "stale queue registration")]
    fn reused_slot_and_pid_reject_old_generation() {
        let mut q = Queues::new();
        let k = q.register(0, 9, 0, 3, false);
        q.remove(k);
        let newer = q.register(0, 9, 0, 3, false);
        assert_ne!(k, newer);
        q.publish(k);
    }
    #[test]
    fn two_stealers_cannot_transfer_the_same_owner() {
        let mut q = Queues::new();
        let k = q.register(0, 9, 0, 3, false);
        q.publish(k);
        q.claim(k, 0, 1);
        q.depart(k, 0, 1);
        q.publish(k);
        assert!(q.can_transfer(k, 1));
        q.transfer(k, 1, true);
        assert!(!q.can_transfer(k, 1));
    }
    #[test]
    #[should_panic(expected = "duplicate live PID registration")]
    fn duplicate_pid_rejected() {
        let mut q = Queues::new();
        q.register(0, 7, 0, 3, false);
        q.register(1, 7, 1, 3, false);
    }
    #[test]
    #[should_panic(expected = "unsafe queue transfer")]
    fn unpublished_saved_context_refused() {
        let mut q = Queues::new();
        let k = q.register(0, 7, 0, 3, false);
        q.publish(k);
        q.claim(k, 0, 1);
        q.depart(k, 0, 1);
        q.publish(k);
        q.transfer(k, 1, false);
    }
    #[test]
    fn bounded_two_task_transition_histories() {
        fn explore(q: Queues, depth: u8) -> usize {
            for slot in 0..2 {
                if let Some(k) = q.key(slot) {
                    assert!(!(q.running(k) && q.queued(k)));
                    assert_eq!(
                        q.queues
                            .iter()
                            .filter(|queue| queue[slot] == Some(k))
                            .count(),
                        usize::from(q.queued(k))
                    );
                }
            }
            if depth == 0 {
                return 1;
            }
            let mut histories = 0;
            for slot in 0..2 {
                let Some(k) = q.key(slot) else {
                    continue;
                };
                let cpu = q.cpu(k);
                if q.running(k) {
                    let mut next = q.clone();
                    next.depart(k, cpu, q.epoch(k));
                    histories += explore(next, depth - 1);
                } else if q.queued(k) {
                    let mut next = q.clone();
                    next.claim(k, cpu, q.epoch(k) + 1);
                    histories += explore(next, depth - 1);
                    if q.can_transfer(k, 1 - cpu) {
                        let mut next = q.clone();
                        next.transfer(k, 1 - cpu, true);
                        histories += explore(next, depth - 1);
                    }
                    let mut next = q.clone();
                    next.remove(k);
                    histories += explore(next, depth - 1);
                } else {
                    let mut next = q.clone();
                    next.publish(k);
                    histories += explore(next, depth - 1);
                    let mut next = q.clone();
                    next.remove(k);
                    histories += explore(next, depth - 1);
                }
            }
            histories.max(1)
        }
        let mut q = Queues::new();
        let a = q.register(0, 7, 0, 3, false);
        let b = q.register(1, 8, 1, 3, false);
        q.publish(a);
        q.publish(b);
        assert!(explore(q, 8) > 1000);
    }
}

#[cfg(test)]
mod nway_tests {
    use super::*;
    fn full_mask(cpus: u8) -> u8 {
        ((1u16 << cpus) - 1) as u8
    }

    fn assert_one_owner(q: &Queues, key: Key, online: u8) {
        let memberships = (0..online)
            .filter(|&cpu| q.candidate(cpu, key.slot) == Some(key))
            .count();
        assert!(memberships <= 1, "duplicate queue membership");
        assert_ne!(
            q.running(key),
            memberships == 1,
            "lost or double-owned task"
        );
    }

    #[test]
    fn online_counts_2_4_6_accept_only_online_cpu_masks_and_transfer_each_way() {
        for cpus in [2u8, 4, 6] {
            let online = full_mask(cpus);
            assert!(cpus as usize <= MAX_CPUS);
            let mut q = Queues::with_cpus(cpus);
            let key = q.register(0, 100 + u64::from(cpus), 0, online, false);
            q.publish(key);
            q.claim(key, 0, 1);
            q.depart(key, 0, 1);
            q.publish(key);

            for destination in 1..cpus {
                assert!(q.can_transfer(key, destination));
                q.transfer(key, destination, true);
                assert_eq!(q.cpu(key), destination);
                assert_one_owner(&q, key, cpus);
                for other in 0..cpus {
                    assert_eq!(q.candidate(other, 0) == Some(key), other == destination);
                }
                let epoch = q.epoch(key) + 1;
                q.claim(key, destination, epoch);
                assert_one_owner(&q, key, cpus);
                q.depart(key, destination, epoch);
                q.publish(key);
            }
            q.remove(key);
            assert!(q.empty());
        }
    }

    #[test]
    fn rt_stays_on_cpu_zero_for_each_online_count() {
        for cpus in [2u8, 4, 6] {
            let mut q = Queues::with_cpus(cpus);
            let key = q.register(0, 200 + u64::from(cpus), 0, 1, true);
            q.publish(key);
            q.claim(key, 0, 1);
            q.depart(key, 0, 1);
            q.publish(key);
            for destination in 1..cpus {
                assert!(!q.can_transfer(key, destination));
            }
            assert_eq!(q.cpu(key), 0);
        }
    }

    #[test]
    fn multiple_idle_thieves_have_one_winner_when_transfer_and_claim_are_one_transaction() {
        for cpus in [2u8, 4, 6] {
            let mut q = Queues::with_cpus(cpus);
            let key = q.register(0, 300 + u64::from(cpus), 0, full_mask(cpus), false);

            for _round in 0..(u64::from(cpus) * 3) {
                let owner = q.cpu(key);
                q.publish(key);
                let source_epoch = q.epoch(key) + 1;
                q.claim(key, owner, source_epoch);
                q.depart(key, owner, source_epoch);
                q.publish(key);

                let mut winners = 0;
                for offset in 1..cpus {
                    let thief = (owner + offset) % cpus;
                    if q.can_transfer(key, thief) {
                        // Represents one BKL-protected transfer plus destination claim.
                        q.transfer(key, thief, true);
                        q.claim(key, thief, source_epoch + 1);
                        winners += 1;
                        assert_one_owner(&q, key, cpus);
                    }
                }
                assert_eq!(
                    winners, 1,
                    "one immediate-claim thief should win this round"
                );
                let destination = q.cpu(key);
                let destination_epoch = q.epoch(key);
                q.depart(key, destination, destination_epoch);
                assert!(!q.running(key));
                assert!((0..cpus).all(|cpu| q.candidate(cpu, 0).is_none()));
                assert_eq!(destination, (owner + 1) % cpus);
            }
            q.remove(key);
            assert!(q.empty());
        }
    }

    #[test]
    fn slot_reuse_after_remote_departure_rejects_old_generation_and_clears_all_rows() {
        let mut q = Queues::with_cpus(6);
        let old = q.register(3, 403, 0, 0x3f, false);
        q.publish(old);
        q.claim(old, 0, 1);
        q.depart(old, 0, 1);
        q.publish(old);
        q.transfer(old, 5, true);
        q.claim(old, 5, 2);
        q.depart(old, 5, 2);
        q.remove(old);
        for cpu in 0..6 {
            assert_eq!(q.candidate(cpu, 3), None);
        }

        let new = q.register(3, 403, 2, 0x3f, false);
        assert_ne!(old.generation, new.generation);
        q.publish(new);
        assert_eq!(q.candidate(2, 3), Some(new));
    }

    #[test]
    #[should_panic(expected = "offline queue candidate")]
    fn offline_candidate_is_rejected() {
        Queues::with_cpus(4).candidate(4, 0);
    }

    #[test]
    #[should_panic]
    fn registration_rejects_offline_cpu() {
        Queues::with_cpus(4).register(0, 1, 4, 0x10, false);
    }

    #[test]
    #[should_panic]
    fn registration_rejects_mask_with_offline_bits() {
        Queues::with_cpus(4).register(0, 1, 0, 0x1f, false);
    }

    #[test]
    #[should_panic(expected = "RT placement refused")]
    fn rt_registration_rejects_nonzero_cpu() {
        Queues::with_cpus(6).register(0, 1, 1, 0x02, true);
    }

    #[test]
    #[should_panic(expected = "stale queue registration")]
    fn stale_key_cannot_publish_reused_slot() {
        let mut q = Queues::with_cpus(6);
        let old = q.register(2, 7, 0, 0x3f, false);
        q.publish(old);
        q.remove(old);
        let _new = q.register(2, 7, 0, 0x3f, false);
        q.publish(old);
    }

    #[test]
    #[should_panic(expected = "unsafe queue transfer")]
    fn offline_transfer_destination_is_rejected() {
        let mut q = Queues::with_cpus(4);
        let key = q.register(0, 8, 0, 0x0f, false);
        q.publish(key);
        q.claim(key, 0, 1);
        q.depart(key, 0, 1);
        q.publish(key);
        q.transfer(key, 4, true);
    }

    #[test]
    #[should_panic(expected = "unsafe queue transfer")]
    fn transfer_without_saved_context_is_rejected() {
        let mut q = Queues::with_cpus(6);
        let key = q.register(0, 9, 0, 0x3f, false);
        q.publish(key);
        q.claim(key, 0, 1);
        q.depart(key, 0, 1);
        q.publish(key);
        q.transfer(key, 5, false);
    }
}
