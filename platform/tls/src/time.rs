//! Explicit fixture time; no wall-clock fallback or global time mutation.
use core::sync::atomic::{AtomicU64, Ordering};
use rustls::{pki_types::UnixTime, time_provider::TimeProvider};
use std::time::Duration;

#[derive(Debug)]
pub struct FixtureTime {
    unix: u64,
    anchor: u64,
    until: u64,
    last: AtomicU64,
    now: fn() -> u64,
}
impl FixtureTime {
    pub fn new(unix: Option<u64>, anchor: u64, until: u64, now: fn() -> u64) -> Option<Self> {
        let unix = unix.filter(|n| *n > 0)?;
        unix.checked_add(15)?;
        if until <= anchor || until > anchor.checked_add(15_000)? {
            return None;
        }
        Some(Self {
            unix,
            anchor,
            until,
            last: AtomicU64::new(anchor),
            now,
        })
    }
}
impl TimeProvider for FixtureTime {
    fn current_time(&self) -> Option<UnixTime> {
        let now = (self.now)();
        if now < self.anchor || now >= self.until {
            return None;
        }
        self.last
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |last| {
                (now >= last).then_some(now)
            })
            .ok()?;
        Some(UnixTime::since_unix_epoch(Duration::from_secs(
            self.unix.checked_add((now - self.anchor) / 1000)?,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static NOW: AtomicU64 = AtomicU64::new(0);
    fn now() -> u64 {
        NOW.load(Ordering::Relaxed)
    }
    #[test]
    fn owner_time_advances_only_with_usable_bounded_boot_time() {
        let _lock = LOCK.lock().unwrap();
        NOW.store(1000, Ordering::Relaxed);
        let t = FixtureTime::new(Some(1_700_000_000), 1000, 16_000, now).unwrap();
        assert_eq!(t.current_time().unwrap().as_secs(), 1_700_000_000);
        NOW.store(2999, Ordering::Relaxed);
        assert_eq!(t.current_time().unwrap().as_secs(), 1_700_000_001);
        NOW.store(2000, Ordering::Relaxed);
        assert!(t.current_time().is_none());
        NOW.store(16_000, Ordering::Relaxed);
        assert!(t.current_time().is_none());
        assert!(FixtureTime::new(None, 0, 10, now).is_none());
        assert!(FixtureTime::new(Some(0), 0, 10, now).is_none());
        assert!(FixtureTime::new(Some(u64::MAX), 0, 10, now).is_none());
        assert!(FixtureTime::new(Some(1), u64::MAX - 1, u64::MAX, now).is_none());
    }
}
