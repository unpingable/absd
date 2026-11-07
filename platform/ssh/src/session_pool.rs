//! Fixed session-channel partitions: remotes never consume local login slots.
pub const LOCAL_SESSIONS: usize = 2;
pub const REMOTE_SESSIONS: usize = 4;
pub const CHANNELS_PER_SHELL: usize = 3;
pub const LOCAL_SLOTS: usize = LOCAL_SESSIONS * CHANNELS_PER_SHELL;
pub const SESSION_SLOTS: usize = (LOCAL_SESSIONS + REMOTE_SESSIONS) * CHANNELS_PER_SHELL;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Origin {
    Local,
    Remote,
}
impl Origin {
    fn index(self) -> usize {
        usize::from(self == Self::Remote)
    }
}
pub struct Pool {
    busy: Vec<bool>,
    sessions: [usize; 2],
    local: bool,
    remote_limit: usize,
}
impl Pool {
    pub fn new(slots: usize, local: bool, remote_limit: usize) -> Self {
        Self {
            busy: vec![false; slots + 1],
            sessions: [0; 2],
            local,
            remote_limit: remote_limit.min(REMOTE_SESSIONS),
        }
    }
    fn range(&self, origin: Origin) -> std::ops::Range<usize> {
        match (origin, self.local) {
            (Origin::Local, true) => 1..(LOCAL_SLOTS + 1).min(self.busy.len()),
            (Origin::Local, false) => 1..1,
            (Origin::Remote, true) => (LOCAL_SLOTS + 1).min(self.busy.len())..self.busy.len(),
            (Origin::Remote, false) => 1..self.busy.len(),
        }
    }
    pub fn free(&self, origin: Origin) -> Vec<usize> {
        let limit = match origin {
            Origin::Local => LOCAL_SESSIONS,
            Origin::Remote => self.remote_limit,
        };
        if self.sessions[origin.index()] >= limit {
            return Vec::new();
        }
        self.range(origin)
            .filter(|&slot| !self.busy[slot])
            .collect()
    }
    pub fn claim(&mut self, origin: Origin, slots: &[usize]) {
        assert!(!slots.is_empty());
        for (at, &slot) in slots.iter().enumerate() {
            assert!(
                self.range(origin).contains(&slot)
                    && !self.busy[slot]
                    && !slots[..at].contains(&slot)
            );
        }
        for &slot in slots {
            self.busy[slot] = true;
        }
        self.sessions[origin.index()] += 1;
    }
    /// Called only after the actual FSD RELEASE acknowledged revocation.
    pub fn release(&mut self, origin: Origin, slots: &[usize]) {
        assert!(self.sessions[origin.index()] > 0);
        for &slot in slots {
            assert!(self.range(origin).contains(&slot) && self.busy[slot]);
            self.busy[slot] = false;
        }
        self.sessions[origin.index()] -= 1;
    }
    pub fn sessions(&self) -> usize {
        self.sessions.iter().sum()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn shell(pool: &mut Pool, origin: Origin) -> Option<Vec<usize>> {
        let free = pool.free(origin);
        if free.len() < CHANNELS_PER_SHELL {
            return None;
        }
        let slots = free[..CHANNELS_PER_SHELL].to_vec();
        pool.claim(origin, &slots);
        Some(slots)
    }
    #[test]
    fn four_remotes_cannot_take_either_local_shell_and_release_reuses_exact_slots() {
        let mut pool = Pool::new(SESSION_SLOTS, true, 4);
        let remotes: Vec<_> = (0..4)
            .map(|_| shell(&mut pool, Origin::Remote).unwrap())
            .collect();
        assert!(shell(&mut pool, Origin::Remote).is_none());
        let first = shell(&mut pool, Origin::Local).unwrap();
        let second = shell(&mut pool, Origin::Local).unwrap();
        assert_eq!(first, [1, 2, 3]);
        assert_eq!(second, [4, 5, 6]);
        assert_eq!(pool.sessions(), 6);
        assert!(shell(&mut pool, Origin::Local).is_none());
        pool.release(Origin::Remote, &remotes[1]);
        assert_eq!(shell(&mut pool, Origin::Remote).unwrap(), remotes[1]);
        pool.release(Origin::Local, &first);
        assert_eq!(shell(&mut pool, Origin::Local).unwrap(), first);
        assert_eq!(
            remotes.iter().flatten().copied().collect::<Vec<_>>(),
            (7..=18).collect::<Vec<_>>()
        );
    }
    #[test]
    fn locals_first_leave_four_complete_remote_pipeline_bindings() {
        let mut pool = Pool::new(18, true, 4);
        for _ in 0..2 {
            shell(&mut pool, Origin::Local).unwrap();
        }
        for _ in 0..4 {
            shell(&mut pool, Origin::Remote).unwrap();
        }
        assert_eq!(pool.sessions(), 6);
        assert!(pool.free(Origin::Remote).is_empty());
    }
    #[test]
    fn configured_remote_limit_and_old_small_pool_fail_bounded() {
        let mut pool = Pool::new(18, true, 2);
        for _ in 0..2 {
            shell(&mut pool, Origin::Remote).unwrap();
        }
        assert!(shell(&mut pool, Origin::Remote).is_none());
        assert!(shell(&mut pool, Origin::Local).is_some());
        let mut old = Pool::new(10, true, 4);
        assert!(shell(&mut old, Origin::Remote).is_some());
        assert!(shell(&mut old, Origin::Remote).is_none());
    }
}
