//! Bounded fixed-priority class. One instance, one phase, no queued releases.
//! Runtime order: charge, deschedule/block, release, wake, select, dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Priority {
    Normal,
    RtLow,
    RtHigh,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Waiting,
    Runnable,
    Running,
    Blocked,
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulingClass {
    Normal,
    BoundedRt(BoundedRt),
}
impl SchedulingClass {
    pub const fn priority(&self) -> Priority {
        match self {
            Self::Normal => Priority::Normal,
            Self::BoundedRt(rt) => rt.priority,
        }
    }
    pub const fn rt(&self) -> Option<&BoundedRt> {
        match self {
            Self::Normal => None,
            Self::BoundedRt(rt) => Some(rt),
        }
    }
    pub fn rt_mut(&mut self) -> Option<&mut BoundedRt> {
        match self {
            Self::Normal => None,
            Self::BoundedRt(rt) => Some(rt),
        }
    }
    pub fn eligible(&self) -> bool {
        match self {
            Self::Normal => true,
            Self::BoundedRt(rt) => {
                rt.assert_valid();
                rt.state == State::Runnable
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Release {
    pub skipped: u64,
    pub unfinished: bool,
    pub late: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedRt {
    pub priority: Priority,
    pub state: State,
    pub period: u64,
    pub budget: u64,
    pub release: u64,
    pub next_release: u64,
    pub consumed: u64,
    pub sequence: u64,
    pub missed_total: u64,
    pub late: u64,
    pub first_dispatch: Option<u64>,
    pub normal_ticks: u64,
}
impl BoundedRt {
    pub fn new(priority: Priority, first_release: u64, period: u64, budget: u64) -> Self {
        assert!(priority != Priority::Normal && budget > 0 && budget < period);
        Self {
            priority,
            state: State::Waiting,
            period,
            budget,
            release: first_release,
            next_release: first_release,
            consumed: 0,
            sequence: 0,
            missed_total: 0,
            late: 0,
            first_dispatch: None,
            normal_ticks: 0,
        }
    }
    pub fn remaining(&self) -> u64 {
        self.budget
            .checked_sub(self.consumed)
            .expect("RT budget underflow")
    }
    pub fn assert_valid(&self) {
        assert!(self.budget > 0 && self.budget < self.period);
        assert!(self.priority != Priority::Normal);
        let remaining = self.remaining();
        match self.state {
            State::Runnable | State::Running => assert!(self.sequence > 0 && remaining > 0),
            State::Exhausted => assert!(remaining == 0),
            State::Waiting | State::Blocked => (),
        }
    }
    /// Replenish exactly once per due phase; blocked conditions remain blocked.
    /// Any uncompleted previous instance is a miss, including an exhausted one.
    /// Skipped boundaries collapse into this single instance, never a backlog.
    pub fn release_at(&mut self, tick: u64) -> Option<Release> {
        if tick < self.next_release {
            return None;
        }
        let skipped = (tick - self.next_release) / self.period;
        let unfinished = self.sequence > 0 && self.state != State::Waiting;
        self.release = self.next_release + skipped * self.period;
        self.next_release = self
            .release
            .checked_add(self.period)
            .expect("RT clock exhausted");
        self.consumed = 0;
        self.first_dispatch = None;
        self.normal_ticks = 0;
        self.sequence += skipped + 1;
        self.missed_total += skipped + u64::from(unfinished);
        self.late = tick - self.release;
        if self.state != State::Blocked {
            self.state = State::Runnable;
        }
        self.assert_valid();
        Some(Release {
            skipped,
            unfinished,
            late: self.late,
        })
    }
    pub fn dispatch(&mut self, tick: u64) -> bool {
        self.assert_valid();
        assert_eq!(self.state, State::Runnable);
        self.state = State::Running;
        let first = self.first_dispatch.is_none();
        if first {
            self.first_dispatch = Some(tick);
        }
        first
    }
    /// Charge only a scheduled task. Exhaustion cannot be reversed by wake/yield.
    pub fn charge_tick(&mut self) -> bool {
        self.assert_valid();
        assert_eq!(self.state, State::Running);
        self.consumed += 1;
        if self.remaining() == 0 {
            self.state = State::Exhausted;
        }
        self.assert_valid();
        self.state == State::Exhausted
    }
    pub fn preempt(&mut self) {
        if self.state == State::Running {
            self.state = State::Runnable;
        }
        self.assert_valid();
    }
    pub fn block(&mut self) {
        assert_eq!(self.state, State::Running);
        self.state = State::Blocked;
        self.assert_valid();
    }
    pub fn complete(&mut self) {
        assert_eq!(self.state, State::Running);
        self.state = State::Waiting;
        self.assert_valid();
    }
    pub fn wake(&mut self) {
        if self.state == State::Blocked {
            self.state = if self.sequence == 0 {
                State::Waiting
            } else if self.remaining() == 0 {
                State::Exhausted
            } else {
                State::Runnable
            };
        }
        self.assert_valid();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn task() -> BoundedRt {
        BoundedRt::new(Priority::RtLow, 10, 20, 5)
    }
    fn running() -> BoundedRt {
        let mut r = task();
        r.release_at(10);
        r.dispatch(10);
        r
    }
    #[test]
    fn block_wake_never_replenishes_and_unused_budget_never_carries() {
        let mut r = running();
        r.charge_tick();
        r.charge_tick();
        r.block();
        assert_eq!(r.remaining(), 3);
        r.wake();
        r.dispatch(15);
        assert_eq!(r.remaining(), 3);
        r.complete();
        assert!(!r.release_at(30).unwrap().unfinished);
        assert_eq!(r.remaining(), 5);
        assert_eq!(r.state, State::Runnable);
        assert_eq!(r.release_at(30), None);
        assert_eq!(r.remaining(), 5);
    }
    #[test]
    fn all_states_have_explicit_release_semantics() {
        for state in [
            State::Waiting,
            State::Runnable,
            State::Running,
            State::Blocked,
            State::Exhausted,
        ] {
            let mut r = running();
            r.state = state;
            r.consumed = if state == State::Exhausted { 5 } else { 2 };
            let event = r.release_at(30).unwrap();
            assert_eq!(event.unfinished, state != State::Waiting);
            assert_eq!(
                r.state,
                if state == State::Blocked {
                    State::Blocked
                } else {
                    State::Runnable
                }
            );
            assert_eq!(r.remaining(), 5);
        }
    }
    #[test]
    fn skipped_periods_have_one_instance_and_one_fresh_budget() {
        let mut r = running();
        r.block();
        let event = r.release_at(93).unwrap();
        assert_eq!((event.skipped, event.unfinished, event.late), (3, true, 3));
        assert_eq!(
            (r.release, r.next_release, r.sequence, r.missed_total),
            (90, 110, 5, 4)
        );
        assert_eq!(r.state, State::Blocked);
        assert_eq!(r.remaining(), 5);
        r.wake();
        assert_eq!(r.state, State::Runnable);
        assert_eq!(r.remaining(), 5);
    }
    #[test]
    fn exhaustion_is_sticky_until_release_and_ordered_before_replenishment() {
        let mut r = running();
        for _ in 0..4 {
            assert!(!r.charge_tick());
        }
        assert!(r.charge_tick());
        for _ in 0..10 {
            r.wake();
            r.preempt();
            assert_eq!(r.state, State::Exhausted);
        }
        assert_eq!(r.remaining(), 0);
        assert_eq!(r.release_at(29), None);
        r.release_at(30);
        assert_eq!(r.remaining(), 5);
        assert_eq!(r.state, State::Runnable);
    }
    #[test]
    fn coincident_wake_release_uses_new_budget_and_blocked_state() {
        let mut r = running();
        r.charge_tick();
        r.block();
        r.release_at(30);
        assert_eq!(r.state, State::Blocked);
        assert_eq!(r.remaining(), 5);
        r.wake();
        r.dispatch(30);
        assert_eq!(r.state, State::Running);
        assert_eq!(r.remaining(), 5);
        assert_eq!(r.missed_total, 1);
    }
    #[test]
    #[should_panic]
    fn waiting_cannot_consume() {
        task().charge_tick();
    }
    #[test]
    #[should_panic]
    fn blocked_cannot_consume() {
        let mut r = running();
        r.block();
        r.charge_tick();
    }
    #[test]
    #[should_panic]
    fn exhausted_cannot_consume() {
        let mut r = running();
        for _ in 0..6 {
            r.charge_tick();
        }
    }
    #[test]
    fn repeated_block_wake_and_yield_do_not_create_burst_budget() {
        let mut r = running();
        for _ in 0..3 {
            r.charge_tick();
        }
        for _ in 0..64 {
            r.block();
            r.wake();
            r.dispatch(15);
            r.preempt();
            r.dispatch(15);
            assert_eq!(r.remaining(), 2);
        }
        r.complete();
        r.release_at(70);
        assert_eq!(r.remaining(), 5);
        assert_eq!(r.sequence, 4);
        assert_eq!(r.release_at(70), None);
        r.dispatch(70);
        r.charge_tick();
        assert_eq!(r.release_at(70), None);
        assert_eq!(r.remaining(), 4);
    }
    #[test]
    fn exact_boundary_charge_precedes_new_budget() {
        let mut r = running();
        r.block();
        r.wake();
        r.dispatch(25);
        for tick in 26..=30 {
            let exhausted = r.charge_tick();
            assert_eq!(exhausted, tick == 30);
            if tick == 30 {
                assert_eq!(r.state, State::Exhausted);
                assert_eq!(r.remaining(), 0);
                let event = r.release_at(tick).unwrap();
                assert!(event.unfinished);
                assert_eq!(
                    (r.state, r.remaining(), r.release),
                    (State::Runnable, 5, 30)
                );
            }
        }
    }
    #[test]
    fn early_block_completion_cannot_admit_before_first_release() {
        let mut r = task();
        r.state = State::Blocked;
        r.wake();
        assert_eq!(r.state, State::Waiting);
        assert_eq!(r.sequence, 0);
        assert_eq!(r.release_at(9), None);
        r.release_at(10);
        assert_eq!(r.state, State::Runnable);
    }
    #[test]
    #[should_panic]
    fn exhausted_cannot_complete_to_evade_suspension() {
        let mut r = running();
        for _ in 0..5 {
            r.charge_tick();
        }
        r.complete();
    }
    #[test]
    #[should_panic]
    fn blocked_cannot_dispatch() {
        let mut r = running();
        r.block();
        r.dispatch(11);
    }
}
