//! The `pcm-stop` fixture's sequence, written against a small device trait so
//! a host test can drive it with controlled completion timing:
//! `rustc --edition 2024 --test user/src/pcm_stop.rs`.
//!
//! The fixture fills the bounded queue and then requests STOP. Two outcomes
//! are legal. Usually buffers are still pending: STOP returns AGAIN, latches
//! submission off, and succeeds once the queue drains. But the device may
//! complete every buffer between the last refused submission and STOP; STOP
//! then withdraws the device at once. Both must end with submission and
//! status refused.

pub trait Device {
    /// Submit one 1920-byte period.
    fn submit(&mut self) -> i64;
    fn stop(&mut self) -> i64;
    fn status(&mut self, state: &mut [u64; 6]) -> i64;
    fn time(&mut self) -> u64;
    fn sleep(&mut self, ticks: u64);
}

pub struct Codes {
    pub again: i64,
    pub io: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Stopped {
    /// STOP observed pending buffers; `frames` were submitted and completed.
    Pending { frames: u64, elapsed: u64 },
    /// Every buffer completed before STOP; `frames` were accepted.
    AlreadyDrained { frames: u64, elapsed: u64 },
}

pub fn run(d: &mut impl Device, codes: &Codes) -> Result<Stopped, &'static str> {
    let start = d.time();
    let mut accepted = 0u64;
    loop {
        let n = d.submit();
        if n == codes.again {
            break;
        }
        if n != 1920 || accepted > 100 {
            return Err("stop saturation");
        }
        accepted += 1;
    }
    let mut state = [0u64; 6];
    let first = d.stop();
    if first == 0 {
        // The legal already-drained transition: withdrawal must be complete.
        if d.submit() != codes.io {
            return Err("stop allowed new submission");
        }
        if d.status(&mut state) != codes.io {
            return Err("stopped device still running");
        }
        return Ok(Stopped::AlreadyDrained {
            frames: accepted * 480,
            elapsed: d.time().wrapping_sub(start),
        });
    }
    if first != codes.again {
        return Err("stop did not observe pending data");
    }
    if d.submit() != codes.io {
        return Err("stop allowed new submission");
    }
    loop {
        if d.status(&mut state) != 0 {
            return Err("stop drain status");
        }
        if state[4] == 0 {
            break;
        }
        if d.time().wrapping_sub(start) > 2000 {
            return Err("stop drain deadline");
        }
        d.sleep(1);
    }
    if state[2] != accepted * 480 || state[3] != state[2] {
        return Err("stop completion count");
    }
    // The same bounded QEMU WAV capture grace as the tone producer.
    d.sleep(50);
    if d.stop() != 0 {
        return Err("stop reset");
    }
    if d.status(&mut state) != codes.io {
        return Err("stopped device still running");
    }
    Ok(Stopped::Pending {
        frames: state[2],
        elapsed: d.time().wrapping_sub(start),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODES: Codes = Codes { again: -11, io: -5 };

    /// A five-buffer device whose completions happen only where a test says.
    struct Model {
        pending: u64,
        submitted: u64,
        completed: u64,
        stopping: bool,
        stopped: bool,
        /// Complete everything between the full queue and STOP.
        drain_before_stop: bool,
        /// Buffers completed per status poll while draining.
        per_poll: u64,
        /// Negative controls.
        stop_ignores_latch: bool,
        stop_result: Option<i64>,
        clock: u64,
    }

    impl Model {
        fn new() -> Self {
            Self {
                pending: 0,
                submitted: 0,
                completed: 0,
                stopping: false,
                stopped: false,
                drain_before_stop: false,
                per_poll: 1,
                stop_ignores_latch: false,
                stop_result: None,
                clock: 100,
            }
        }
        fn complete(&mut self, n: u64) {
            let n = n.min(self.pending);
            self.pending -= n;
            self.completed += n * 480;
        }
    }

    impl Device for Model {
        fn submit(&mut self) -> i64 {
            if self.stopping && !self.stop_ignores_latch {
                return CODES.io;
            }
            if self.pending == 5 {
                return CODES.again;
            }
            self.pending += 1;
            self.submitted += 480;
            1920
        }
        fn stop(&mut self) -> i64 {
            if let Some(result) = self.stop_result {
                return result;
            }
            if self.drain_before_stop {
                self.complete(5);
            }
            self.stopping = true;
            if self.pending != 0 {
                return CODES.again;
            }
            self.stopped = true;
            0
        }
        fn status(&mut self, state: &mut [u64; 6]) -> i64 {
            if self.stopped {
                return CODES.io;
            }
            self.complete(self.per_poll);
            *state = [1, 0, self.submitted, self.completed, self.pending, 0];
            0
        }
        fn time(&mut self) -> u64 {
            self.clock += 1;
            self.clock
        }
        fn sleep(&mut self, ticks: u64) {
            self.clock += ticks;
        }
    }

    #[test]
    fn pending_buffers_drain_then_stop_resets() {
        let mut model = Model::new();
        match run(&mut model, &CODES) {
            Ok(Stopped::Pending { frames, .. }) => assert_eq!(frames, 5 * 480),
            other => panic!("{other:?}"),
        }
        assert!(model.stopped);
    }

    #[test]
    fn completion_before_stop_is_a_legal_clean_stop() {
        let mut model = Model::new();
        model.drain_before_stop = true;
        match run(&mut model, &CODES) {
            Ok(Stopped::AlreadyDrained { frames, .. }) => assert_eq!(frames, 5 * 480),
            other => panic!("{other:?}"),
        }
        assert!(model.stopped);
    }

    #[test]
    fn immediate_stop_that_still_accepts_submission_fails() {
        let mut model = Model::new();
        model.drain_before_stop = true;
        model.stop_ignores_latch = true;
        assert_eq!(run(&mut model, &CODES), Err("stop allowed new submission"));
    }

    #[test]
    fn pending_stop_that_still_accepts_submission_fails() {
        let mut model = Model::new();
        model.stop_ignores_latch = true;
        assert_eq!(run(&mut model, &CODES), Err("stop allowed new submission"));
    }

    #[test]
    fn other_stop_errors_fail() {
        let mut model = Model::new();
        model.stop_result = Some(CODES.io);
        assert_eq!(
            run(&mut model, &CODES),
            Err("stop did not observe pending data")
        );
    }

    #[test]
    fn a_drain_that_never_finishes_meets_the_deadline() {
        let mut model = Model::new();
        model.per_poll = 0;
        assert_eq!(run(&mut model, &CODES), Err("stop drain deadline"));
    }
}
