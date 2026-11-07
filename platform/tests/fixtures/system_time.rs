use std::{
    sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed},
    time::Duration,
};
static CIVIL: AtomicI64 = AtomicI64::new(-5);
static TICK: AtomicU64 = AtomicU64::new(42_000);
fn ticks() -> u64 {
    TICK.load(Relaxed)
}
fn wall_clock_seconds() -> Result<u64, i64> {
    let value = CIVIL.load(Relaxed);
    if value < 0 {
        Err(value)
    } else {
        Ok(value as u64)
    }
}
#[test]
fn actual_std_pal_survives_unknown_but_shared_fallible_c_bridge_refuses() {
    CIVIL.store(-5, Relaxed);
    TICK.store(42_000, Relaxed);
    assert_eq!(__absd_std_wall_clock_seconds(), -5);
    let now = pal::SystemTime::now();
    assert_eq!(now.sub_time(&pal::UNIX_EPOCH), Ok(Duration::from_secs(42)));
    CIVIL.store(-22, Relaxed);
    assert_eq!(__absd_std_wall_clock_seconds(), -22);
    assert_eq!(pal::SystemTime::now(), now);
    CIVIL.store(1_700_000_000, Relaxed);
    assert_eq!(
        pal::SystemTime::now().sub_time(&pal::UNIX_EPOCH),
        Ok(Duration::from_secs(1_700_000_000))
    );
}
#[test]
fn civil_steps_do_not_move_the_actual_pal_monotonic_wait_coordinate() {
    TICK.store(1000, Relaxed);
    let start = pal::Instant::now();
    let end = start
        .checked_add_duration(&Duration::from_millis(50))
        .unwrap();
    let mut passes = 0;
    while pal::Instant::now() < end {
        CIVIL.store(if passes % 2 == 0 { 4_000_000_000 } else { 10 }, Relaxed);
        let _ = pal::SystemTime::now();
        passes += 1;
        TICK.fetch_add(10, Relaxed);
    }
    assert_eq!(passes, 5);
    assert_eq!(
        pal::Instant::now().checked_sub_instant(&start),
        Some(Duration::from_millis(50))
    );
}
