//! Cadence for a live child's timed status query; not a cached exit result.
use std::{
    io,
    time::{Duration, Instant},
};
const INTERVAL: Duration = Duration::from_millis(10);

pub(crate) fn poll<T>(
    next: &mut Option<Instant>,
    now: Instant,
    wait: impl FnOnce() -> io::Result<Option<T>>,
) -> io::Result<Option<T>> {
    if next.is_some_and(|deadline| now < deadline) {
        return Ok(None);
    }
    let result = wait();
    // Start-to-start: the timed query itself counts toward the interval.
    // An observed exit or error is returned immediately, never cached here.
    *next = match &result {
        Ok(None) => now.checked_add(INTERVAL),
        _ => None,
    };
    result
}

/// Makes the next query due at once: the final look before a child is ended
/// by force must not be deferred past an exit that already happened.
pub(crate) fn due_now(next: &mut Option<Instant>) {
    *next = None;
}

#[cfg(test)]
mod tests {
    use super::{INTERVAL, due_now, poll};
    use std::{
        cell::Cell,
        io,
        time::{Duration, Instant},
    };
    #[test]
    fn first_check_is_immediate_then_early_checks_do_not_wait() {
        let now = Instant::now();
        let mut next = None;
        let calls = Cell::new(0);
        assert_eq!(
            poll::<u32>(&mut next, now, || {
                calls.set(calls.get() + 1);
                Ok(None)
            })
            .unwrap(),
            None
        );
        for ms in 0..10 {
            assert_eq!(
                poll::<u32>(&mut next, now + Duration::from_millis(ms), || {
                    calls.set(calls.get() + 1);
                    Ok(None)
                })
                .unwrap(),
                None
            );
        }
        assert_eq!(calls.get(), 1);
    }
    #[test]
    fn exact_boundary_observes_exit_and_does_not_cache_it() {
        let now = Instant::now();
        let mut next = None;
        assert_eq!(poll::<u32>(&mut next, now, || Ok(None)).unwrap(), None);
        assert_eq!(
            poll(&mut next, now + INTERVAL, || Ok(Some(7))).unwrap(),
            Some(7)
        );
        assert_eq!(
            poll(&mut next, now + INTERVAL, || Ok(Some(9))).unwrap(),
            Some(9)
        );
        assert!(next.is_none());
    }
    #[test]
    fn wait_error_is_returned_and_does_not_hide_next_error() {
        let now = Instant::now();
        let mut next = None;
        assert_eq!(poll::<u32>(&mut next, now, || Ok(None)).unwrap(), None);
        let error = poll::<u32>(&mut next, now + INTERVAL, || {
            Err(io::Error::other("wait failed"))
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "wait failed");
        assert!(next.is_none());
        assert!(poll::<u32>(&mut next, now + INTERVAL, || Err(io::Error::other("again"))).is_err());
    }
    #[test]
    fn blocking_wait_time_counts_toward_interval() {
        let now = Instant::now();
        let mut next = None;
        assert_eq!(poll::<u32>(&mut next, now, || Ok(None)).unwrap(), None);
        // The first call hypothetically occupied eleven milliseconds. The
        // next caller supplies a fresh clock sample, not the outer pump's now.
        assert_eq!(
            poll(&mut next, now + Duration::from_millis(11), || Ok(Some(3))).unwrap(),
            Some(3)
        );
    }
    #[test]
    fn final_query_is_not_deferred_by_an_earlier_live_observation() {
        // Live at 97 ms (next check 107 ms), exit at 99 ms, shutdown grace
        // over at 100 ms: the final query must still see the exit.
        let start = Instant::now();
        let mut next = None;
        let at = |ms| start + Duration::from_millis(ms);
        assert_eq!(poll::<u32>(&mut next, at(97), || Ok(None)).unwrap(), None);
        assert_eq!(poll(&mut next, at(100), || Ok(Some(7))).unwrap(), None);
        due_now(&mut next);
        assert_eq!(poll(&mut next, at(100), || Ok(Some(7))).unwrap(), Some(7));
    }
    #[test]
    fn live_checks_restart_from_each_due_start_time() {
        let now = Instant::now();
        let mut next = None;
        for ms in [0, 10, 20] {
            assert_eq!(
                poll::<u32>(&mut next, now + Duration::from_millis(ms), || Ok(None)).unwrap(),
                None
            );
            assert_eq!(next, Some(now + Duration::from_millis(ms) + INTERVAL));
            assert_eq!(
                poll::<u32>(&mut next, now + Duration::from_millis(ms + 9), || panic!(
                    "too early"
                ))
                .unwrap(),
                None
            );
        }
    }
}
