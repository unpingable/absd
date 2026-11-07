//! One collector only: bounded boot-local crash restart decisions.
//! Resource refusals and explicit attachment retirement use backoff without
//! consuming the four successful crash replacements. No live substitution.
pub const BACKOFF: u64 = 1000;
pub const MAX_RESTARTS: u8 = 4;
/// Private logger/init lifecycle v1; shared golden in tests/fixtures.
pub const REATTACH_EXIT_STATUS: i64 = 75;
pub const EXHAUSTED_NOTICE: &str =
    "Logging stopped after four crash replacements. Volatile diagnostics remain available.";
pub const QUARANTINED_NOTICE: &str = "Logger child is quarantined. Replacement and raw-handle actions are stopped; cleanup remains unconfirmed.";
pub const UNCONFIRMED_NOTICE: &str =
    "Logger child identity is unconfirmed. Automatic replacement is stopped.";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Dormant,
    Starting,
    Running,
    Backoff,
    Exhausted,
    Stopped,
}
pub struct Policy {
    pub state: State,
    pub restarts: u8,
    pub due: u64,
    crash_replacement: bool,
    pub unproductive: u32,
    productive: bool,
    first_collected_at: Option<u64>,
    saturated_cadence: u8,
    report_attempt: bool,
}
impl Policy {
    pub const fn new() -> Self {
        Self {
            state: State::Dormant,
            restarts: 0,
            due: 0,
            crash_replacement: false,
            unproductive: 0,
            productive: false,
            first_collected_at: None,
            saturated_cadence: 0,
            report_attempt: true,
        }
    }
    /// Authorize one construction attempt. A child does not exist yet.
    pub fn begin(&mut self, now: u64) -> bool {
        if self.state == State::Dormant || (self.state == State::Backoff && now >= self.due) {
            self.report_attempt = self.should_notice();
            self.productive = false;
            self.first_collected_at = None;
            self.state = State::Starting;
            true
        } else {
            false
        }
    }
    /// Charge only once the spawn syscall has actually created a child.
    pub fn spawned(&mut self) {
        assert_eq!(self.state, State::Starting);
        if self.crash_replacement {
            self.restarts += 1;
        }
        self.state = State::Running;
    }
    /// No process was created; retain any pending crash charge for later.
    pub fn refused(&mut self, now: u64) {
        if self.state == State::Starting {
            self.backoff(now);
        }
    }
    /// Called only after reaping the exact previous child identity.
    pub fn ended(&mut self, now: u64, status: i64) {
        if self.state == State::Stopped {
            return;
        }
        assert_eq!(self.state, State::Running);
        self.crash_replacement = status != REATTACH_EXIT_STATUS;
        if self.crash_replacement && self.restarts >= MAX_RESTARTS {
            self.state = State::Exhausted;
        } else {
            self.backoff(now);
        }
    }
    fn backoff(&mut self, now: u64) {
        if !self.productive {
            if self.unproductive == u32::MAX {
                self.saturated_cadence = (self.saturated_cadence + 1) % 60;
            }
            self.unproductive = self.unproductive.saturating_add(1);
        }
        let delay = match self.unproductive {
            0 | 1 => BACKOFF,
            2 => 2000,
            3 => 4000,
            4 => 8000,
            5 => 16000,
            6 => 30000,
            _ => 60000,
        };
        self.state = State::Backoff;
        self.due = now.saturating_add(delay);
    }
    /// Only a later fresh, synced acquisition at least one minute after
    /// this exact generation's first milestone proves sustained productivity.
    pub fn collected(&mut self, now: u64) -> bool {
        if self.state != State::Running || self.productive {
            return false;
        }
        let Some(first) = self.first_collected_at else {
            self.first_collected_at = Some(now);
            return false;
        };
        if now.saturating_sub(first) < 60000 {
            return false;
        }
        self.productive = true;
        self.unproductive = 0;
        self.saturated_cadence = 0;
        self.report_attempt = true;
        true
    }
    pub fn reporting(&self) -> bool {
        self.report_attempt
    }
    /// Initial transitions, then every sixtieth attempt; saturation keeps
    /// the same finite cadence instead of creating silence or a busy stream.
    pub fn should_notice(&self) -> bool {
        self.unproductive <= 7
            || if self.unproductive == u32::MAX {
                self.saturated_cadence == 0
            } else {
                self.unproductive.is_multiple_of(60)
            }
    }
    pub fn stop(&mut self) {
        self.state = State::Stopped;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn start(p: &mut Policy, now: u64) {
        assert!(p.begin(now));
        assert!(!p.begin(u64::MAX), "construction already in progress");
        p.spawned();
        assert!(!p.begin(u64::MAX), "live identity cannot be replaced");
    }
    #[test]
    fn no_live_substitution_and_four_automatic_crash_restarts() {
        let mut p = Policy::new();
        start(&mut p, 0);
        let mut now = 0;
        for n in 1..=4 {
            p.ended(now, -1);
            assert!(!p.begin(p.due - 1));
            now = p.due;
            start(&mut p, now);
            assert_eq!(p.restarts, n as u8);
        }
        p.ended(now, 3);
        assert_eq!(p.state, State::Exhausted);
        assert!(!p.begin(u64::MAX));
    }
    #[test]
    fn more_than_four_refused_constructions_then_capacity_returns() {
        let mut p = Policy::new();
        let mut now = 0;
        for _ in 0..8 {
            assert!(p.begin(now));
            p.refused(now);
            now = p.due;
        }
        assert_eq!(p.restarts, 0, "no child existed");
        start(&mut p, now);
        assert_eq!(p.restarts, 0);
    }
    #[test]
    fn transient_begin_failures_and_mixed_crashes_preserve_real_crash_history() {
        let mut p = Policy::new();
        let mut now = 0;
        start(&mut p, now);
        for _ in 0..80 {
            p.ended(now, REATTACH_EXIT_STATUS);
            now = p.due;
            start(&mut p, now);
        }
        assert_eq!(p.restarts, 0);
        for n in 1..=4 {
            p.ended(now, -1);
            for _ in 0..8 {
                now = p.due;
                assert!(p.begin(now));
                p.refused(now);
                assert_eq!(p.restarts, n - 1);
            }
            now = p.due;
            start(&mut p, now);
            assert_eq!(p.restarts, n);
            for _ in 0..8 {
                p.ended(now, REATTACH_EXIT_STATUS);
                now = p.due;
                start(&mut p, now);
                assert_eq!(
                    p.restarts, n,
                    "transient exit neither charges nor refunds a genuine crash"
                );
            }
        }
        p.ended(now, -1);
        assert_eq!(p.state, State::Exhausted);
        assert!(!p.begin(u64::MAX));
    }
    #[test]
    fn orderly_stop_never_restarts_even_after_terminal_notice() {
        let mut p = Policy::new();
        start(&mut p, 0);
        p.stop();
        p.ended(1, REATTACH_EXIT_STATUS);
        assert_eq!(p.state, State::Stopped);
        assert!(!p.begin(u64::MAX));
    }
    #[test]
    fn lifecycle_v1_golden() {
        assert_eq!(
            include_str!("../../tests/fixtures/logd-lifecycle-v1.txt")
                .trim()
                .parse::<i64>()
                .unwrap(),
            REATTACH_EXIT_STATUS
        );
    }
}

#[cfg(test)]
mod round3_regression {
    use super::*;
    #[test]
    fn consecutive_unproductive_attempts_back_off_to_a_finite_periodic_rate() {
        let mut p = Policy::new();
        let mut now = 0;
        assert!(p.begin(now));
        p.spawned();
        for delay in [1000, 2000, 4000, 8000, 16000, 30000, 60000, 60000, 60000] {
            p.ended(now, REATTACH_EXIT_STATUS);
            assert_eq!(p.due - now, delay);
            now = p.due;
            assert!(p.begin(now));
            p.spawned();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reap {
    Confirmed,
    Pending,
    Quarantined,
}
pub struct ReapGuard {
    pub quarantined: bool,
}
impl ReapGuard {
    pub const fn new() -> Self {
        Self { quarantined: false }
    }
    pub fn poll(&mut self, wait: impl FnOnce() -> Result<(), i64>) -> Reap {
        if self.quarantined {
            return Reap::Quarantined;
        }
        match wait() {
            Ok(()) => Reap::Confirmed,
            Err(-110) => Reap::Pending,
            Err(_) => {
                self.quarantined = true;
                Reap::Quarantined
            }
        }
    }
}
/// Readable supervisor observation carried by the existing typed lifecycle ring.
pub fn write_observation(
    out: &mut impl core::fmt::Write,
    retrying: bool,
    count: u32,
    restarts: u8,
    retry_ticks: u64,
) -> core::fmt::Result {
    write!(
        out,
        "Logging {}. consecutive_unproductive={} crash_restarts={} retry_ticks={}",
        if retrying {
            "is retrying"
        } else {
            "collected and synced new records"
        },
        count,
        restarts,
        retry_ticks
    )
}
/// Bounded exact-line parser, reset for each exact child/pipe identity.
pub struct Collected {
    line: [u8; 160],
    used: usize,
    overflow: bool,
}
impl Collected {
    pub const fn new() -> Self {
        Self {
            line: [0; 160],
            used: 0,
            overflow: false,
        }
    }
    pub fn push(&mut self, bytes: &[u8]) -> bool {
        let mut matched = false;
        for &byte in bytes {
            if byte == b'\n' {
                matched |= !self.overflow && Self::valid(&self.line[..self.used]);
                self.used = 0;
                self.overflow = false;
            } else if self.used < self.line.len() {
                self.line[self.used] = byte;
                self.used += 1;
            } else {
                self.overflow = true;
            }
        }
        matched
    }
    fn valid(line: &[u8]) -> bool {
        let Some(rest) = line.strip_prefix(b"LOGD COLLECTED boot=") else {
            return false;
        };
        if rest.len() < 32
            || !rest[..32]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return false;
        }
        let Some(rest) = rest[32..].strip_prefix(b" written=") else {
            return false;
        };
        let Some(space) = rest.iter().position(|b| *b == b' ') else {
            return false;
        };
        let Some(flushed) = rest[space..].strip_prefix(b" flushed=") else {
            return false;
        };
        let Some(written) = decimal(&rest[..space]) else {
            return false;
        };
        decimal(flushed).is_some_and(|flushed| written > 0 && flushed >= written)
    }
}
fn decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0u64, |n, b| {
        if b.is_ascii_digit() {
            n.checked_mul(10)?.checked_add(u64::from(b - b'0'))
        } else {
            None
        }
    })
}
#[cfg(test)]
mod round3_boundaries {
    use super::*;
    #[test]
    fn a_non_timeout_reap_error_keeps_custody_but_cannot_block_general_reaping_or_repeat_raw_actions()
     {
        let mut guard = ReapGuard::new();
        assert_eq!(guard.poll(|| Err(-110)), Reap::Pending);
        assert_eq!(guard.poll(|| Err(-9)), Reap::Quarantined);
        assert!(guard.quarantined);
        assert_eq!(
            guard.poll(|| panic!("quarantined raw handle must not be touched")),
            Reap::Quarantined
        );
    }
    #[test]
    fn only_a_complete_collected_line_can_credit_a_generation() {
        let mut probe = Collected::new();
        assert!(!probe.push(b"LOGD COLLECTED boot="));
        assert!(!probe.push(b"0123456789abcdef0123456789abcdef written=42 flushed=42"));
        assert!(probe.push(b"\n"));
        for bad in [
            b"prefix LOGD COLLECTED boot=0123456789abcdef0123456789abcdef written=42 flushed=42\n"
                .as_slice(),
            b"LOGD READY boot=0123456789abcdef0123456789abcdef written=42 flushed=42\n",
            b"LOGD COLLECTED boot=0123456789abcdef0123456789abcdef written=42 flushed=41\n",
        ] {
            assert!(!probe.push(bad));
        }
    }
}

#[cfg(test)]
mod productivity_tests {
    use super::*;
    #[test]
    fn capped_periodic_recovery_saturates_counts_and_only_collected_resets_them() {
        let mut p = Policy::new();
        assert!(p.begin(0));
        p.spawned();
        for _ in 0..1000 {
            p.ended(p.due, 75);
            assert!(p.begin(p.due));
            p.spawned();
        }
        assert_eq!(p.restarts, 0);
        assert_eq!(p.unproductive, 1000);
        p.unproductive = u32::MAX;
        p.ended(100000000, 75);
        assert_eq!(p.unproductive, u32::MAX);
        assert_eq!(p.due, 100060000);
        assert!(p.begin(p.due));
        p.spawned();
        let first = p.due;
        assert!(!p.collected(first));
        assert!(!p.collected(first + 59999));
        assert_eq!(p.unproductive, u32::MAX);
        assert!(p.collected(first + 60000));
        assert_eq!(p.unproductive, 0);
        p.ended(100130000, -1);
        assert!(p.begin(p.due));
        p.spawned();
        assert_eq!(p.restarts, 1);
        let first = p.due;
        assert!(!p.collected(first));
        assert!(p.collected(first + 60000));
        assert_eq!(p.restarts, 1);
        p.ended(100200000, 75);
        assert_eq!(p.unproductive, 0);
        assert_eq!(p.due, 100201000);
    }
}

#[cfg(test)]
mod notice_tests {
    use super::*;
    #[test]
    fn duplicate_attempt_notices_are_summarized_at_the_capped_rate() {
        let mut p = Policy::new();
        for (count, notice) in [
            (7, true),
            (8, false),
            (9, false),
            (60, true),
            (61, false),
            (120, true),
        ] {
            p.unproductive = count;
            assert_eq!(p.should_notice(), notice);
        }
    }
}

#[cfg(test)]
mod round4_regression {
    use super::*;
    #[test]
    fn collect_once_then_transient_exit_does_not_erase_exponential_backoff() {
        let mut p = Policy::new();
        let mut now = 0;
        assert!(p.begin(now));
        p.spawned();
        for delay in [1000, 2000, 4000, 8000, 16000, 30000, 60000, 60000] {
            assert!(!p.collected(now));
            p.ended(now + 100, 75);
            assert_eq!(p.due - (now + 100), delay);
            now = p.due;
            assert!(p.begin(now));
            p.spawned();
        }
        assert_eq!(p.restarts, 0);
    }
    #[test]
    fn capped_retry_summaries_do_not_go_silent_for_exponential_hours() {
        let mut p = Policy::new();
        for count in [60, 120, 180, 240, 300, 3600] {
            p.unproductive = count;
            assert!(p.should_notice(), "count={count}");
        }
    }
}

#[cfg(test)]
mod sustained_tests {
    use super::*;
    #[test]
    fn lifetime_without_a_later_sync_does_not_reset_and_saturation_stays_periodic() {
        let mut p = Policy::new();
        assert!(p.begin(0));
        p.spawned();
        assert!(!p.collected(0));
        p.ended(60001, 75);
        assert_eq!(p.unproductive, 1);
        assert!(p.begin(p.due));
        p.spawned();
        p.unproductive = u32::MAX;
        for n in 1..=120 {
            p.ended(p.due, 75);
            assert_eq!(p.should_notice(), n % 60 == 0);
            assert!(p.begin(p.due));
            p.spawned();
        }
    }
}
