//! Pure wire conformance only; real transport names are checked by native builds.
unsafe fn syscall3(_: u64, _: u64, _: u64, _: u64) -> i64 {
    panic!("transport must not execute in host wire test")
}
fn clock_owner_handle() -> u64 {
    0
}
#[path = "../runtime/src/civil_clock.rs"]
mod clock;
fn hex(text: &str) -> Vec<u8> {
    let h = text.trim();
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}
#[test]
fn actual_kernel_info_vector_decodes() {
    let b = hex(include_str!("fixtures/civil-info-v1.hex"));
    let i = clock::decode(b.as_slice().try_into().unwrap()).unwrap();
    let floor: u64 = include_str!("fixtures/civil-rtc-floor-v1.txt")
        .trim()
        .parse()
        .unwrap();
    assert_eq!(clock::MIN_RTC_UNIX_SECONDS, floor);
    assert_eq!(i.unix_ns, Some(floor * clock::NS));
    assert_eq!(i.source, clock::RTC);
    assert_eq!(i.attempt_source, clock::RTC);
    assert!(!i.stale());
}
#[test]
fn actual_manual_request_vector_matches() {
    assert_eq!(
        clock::set_request(200_000_000_000, 10, clock::MANUAL, [0; 4], 0, 0, 0).as_slice(),
        hex(include_str!("fixtures/civil-set-v1.hex"))
    );
}
#[test]
fn corrupt_and_inconsistent_frames_refuse_without_raw_fallback() {
    let mut b: [u8; 96] = hex(include_str!("fixtures/civil-info-v1.hex"))
        .try_into()
        .unwrap();
    b[0] = 2;
    assert!(clock::decode(&b).is_err());
    b[0] = 1;
    b[92] = 1;
    assert!(clock::decode(&b).is_err());
    b[92] = 0;
    b[40] = 1;
    assert!(clock::decode(&b).is_err());
    b[40] = 0;
    b[4] = 0;
    assert!(clock::decode(&b).is_err());
}

#[test]
fn shared_status_exposes_rtc_divergence_and_unsynchronized_quality() {
    let b = hex(include_str!("fixtures/civil-info-v1.hex"));
    let mut i = clock::decode(b.as_slice().try_into().unwrap()).unwrap();
    let line = i.status(Ok(1_767_225_599)).to_string();
    assert!(line.contains("raw_rtc_seconds=1767225599"));
    assert!(line.contains("civil_minus_raw_rtc_ns=1000000000"));
    assert!(line.contains("synchronization=unsynchronized"));
    assert!(line.contains("last_success_tick="));
    let absent = i.status(Err(-5)).to_string();
    assert!(absent.contains("raw_rtc_seconds=unknown"));
    assert!(absent.contains("raw_rtc_error=-5"));
    i.unix_ns = None;
    assert!(
        i.status(Ok(99))
            .to_string()
            .contains("civil_minus_raw_rtc_ns=unknown")
    );
    assert!(
        i.status(Ok(99))
            .to_string()
            .contains("synchronization=unavailable")
    );
    i.unix_ns = Some(1_767_225_600 * clock::NS);
    i.source = clock::SNTP_UNAUTHENTICATED;
    i.flags |= 2;
    assert!(
        i.status(Ok(99))
            .to_string()
            .contains("synchronization=stale")
    );
}

#[test]
fn actual_status_explains_before_floor_rtc_without_making_unknown_time_valid() {
    let b = hex(include_str!("fixtures/civil-info-v1.hex"));
    let mut i = clock::decode(b.as_slice().try_into().unwrap()).unwrap();
    i.flags = 0;
    i.source = 0;
    i.unix_ns = None;
    i.age_ticks = u64::MAX;
    i.generation = 0;
    i.last_error = -116;
    let line = i.status(Ok(1_767_225_599)).to_string();
    assert!(line.contains("known=false"));
    assert!(line.contains("source=unknown"));
    assert!(line.contains("last_error=-116"));
    assert!(
        line.contains("last_error_reason=rtc-before-build-floor"),
        "{line}"
    );
    assert!(line.contains("raw_rtc_seconds=1767225599"));
    assert!(
        line.contains("raw_rtc_bootstrap=before-build-floor"),
        "{line}"
    );
    assert!(
        line.contains("rtc_bootstrap_floor_seconds=1767225600"),
        "{line}"
    );
    let advanced_raw = i.status(Ok(1_767_225_600)).to_string();
    assert!(advanced_raw.contains("last_error_reason=rtc-before-build-floor"));
    assert!(advanced_raw.contains("raw_rtc_bootstrap=not-before-build-floor"));
    // Later provider errors replace last_error; the raw RTC explanation stays.
    i.last_error = -110;
    i.attempt_source = clock::SNTP_UNAUTHENTICATED;
    assert!(
        i.status(Ok(1_767_225_599))
            .to_string()
            .contains("raw_rtc_bootstrap=before-build-floor")
    );
    i.last_error = -116;
    assert!(
        !i.status(Ok(1_767_225_599))
            .to_string()
            .contains("last_error_reason=rtc-before-build-floor")
    );
    assert!(
        i.status(Ok(1_767_225_600))
            .to_string()
            .contains("raw_rtc_bootstrap=not-before-build-floor")
    );
    assert!(
        i.status(Err(-5))
            .to_string()
            .contains("raw_rtc_bootstrap=unavailable")
    );
    // The same raw observation does not invalidate an explicit operator date.
    i.flags = 1;
    i.source = clock::MANUAL;
    i.unix_ns = Some(0);
    i.generation = 1;
    let line = i.status(Ok(946_684_800)).to_string();
    assert!(line.contains("source=operator-asserted known=true"));
    assert!(line.contains("raw_rtc_bootstrap=before-build-floor"));
}
