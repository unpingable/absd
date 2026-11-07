//! Boot-local civil time. Correction never writes the scheduler tick counter.
pub const INFO_BYTES: usize = 96;
pub const REQUEST_BYTES: usize = 64;
pub const NS: u64 = 1_000_000_000;
/// Fixed reproducible RTC bootstrap floor, not a host build timestamp.
pub const MIN_RTC_UNIX_SECONDS: u64 = 1_767_225_600; // 2026-01-01T00:00:00Z
pub const MAX_UNIX_SECONDS: u64 = 4_102_444_799; // 2099-12-31T23:59:59 UTC
pub const UNKNOWN: u32 = 0;
pub const RTC: u32 = 1;
pub const MANUAL: u32 = 2;
pub const SNTP_UNAUTHENTICATED: u32 = 3;
pub const VALID: u32 = 1;
pub const STALE: u32 = 2;
pub fn authorize_update(
    handles: &crate::handle::HandleTable,
    handle: u64,
) -> Result<(), crate::handle::HandleError> {
    let found = handles.lookup(handle)?;
    if found.object != crate::handle::Object::Clock {
        return Err(crate::handle::HandleError::Rights);
    }
    found.require(crate::handle::RIGHT_WRITE)
}
pub fn elapsed_ns(ticks: u64) -> Option<u64> {
    u64::try_from(u128::from(ticks) * 1193 * 3 * NS as u128 / 3_579_545).ok()
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Clock {
    initialized: bool,
    source: u32,
    base_ns: u64,
    sample_tick: u64,
    generation: u64,
    max_age: u64,
    last_attempt: u64,
    last_error: i64,
    peer: u32,
    rtt_ms: u32,
    attempt_source: u32,
    attempt_peer: u32,
    peer_port: u16,
    attempt_peer_port: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Info {
    pub flags: u32,
    pub source: u32,
    pub now_ns: Option<u64>,
    pub sample_tick: u64,
    pub now_tick: u64,
    pub age: u64,
    pub generation: u64,
    pub max_age: u64,
    pub last_attempt: u64,
    pub last_error: i64,
    pub peer: u32,
    pub rtt_ms: u32,
    pub attempt_source: u32,
    pub attempt_peer: u32,
    pub peer_port: u16,
    pub attempt_peer_port: u16,
}
/// Bounded failure-event suppression in the same boot-monotonic domain.
pub struct EventLimiter {
    last: Option<(u32, u32, u16, i64, u64)>,
    suppressed: u64,
}
impl Default for EventLimiter {
    fn default() -> Self {
        Self::new()
    }
}
impl EventLimiter {
    pub const fn new() -> Self {
        Self {
            last: None,
            suppressed: 0,
        }
    }
    pub fn failure(
        &mut self,
        source: u32,
        peer: u32,
        port: u16,
        error: i64,
        now: u64,
    ) -> Option<u64> {
        if self.last.is_some_and(|(s, p, port_before, e, t)| {
            s == source
                && p == peer
                && port_before == port
                && e == error
                && now >= t
                && now - t < 60_000
        }) {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }
        let dropped = self.suppressed;
        self.suppressed = 0;
        self.last = Some((source, peer, port, error, now));
        Some(dropped)
    }
    pub fn recovered(&mut self) -> u64 {
        let n = self.suppressed;
        self.suppressed = 0;
        self.last = None;
        n
    }
}
pub fn source_name(source: u32) -> &'static str {
    match source {
        RTC => "rtc-unverified",
        MANUAL => "operator-asserted",
        SNTP_UNAUTHENTICATED => "sntp-unauthenticated-estimate",
        _ => "unknown",
    }
}
impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}
impl Clock {
    pub const fn new() -> Self {
        Self {
            initialized: false,
            source: UNKNOWN,
            base_ns: 0,
            sample_tick: 0,
            generation: 0,
            max_age: 0,
            last_attempt: 0,
            last_error: 0,
            peer: 0,
            rtt_ms: 0,
            attempt_source: UNKNOWN,
            attempt_peer: 0,
            peer_port: 0,
            attempt_peer_port: 0,
        }
    }
    pub fn initialized(&self) -> bool {
        self.initialized
    }
    pub fn initialize_rtc(&mut self, seconds: Option<u64>, now: u64) {
        self.initialize_rtc_result(seconds.ok_or(-5), now);
    }
    pub fn initialize_rtc_result(&mut self, result: Result<u64, i64>, now: u64) {
        if self.initialized {
            return;
        }
        self.initialized = true;
        self.last_attempt = now;
        self.attempt_source = RTC;
        match result {
            // The raw device reading remains available through SYS30. Only
            // adoption as civil time is refused; operator assertions retain
            // their full supported range and do not pass this bootstrap gate.
            Ok(s) if s < MIN_RTC_UNIX_SECONDS => self.last_error = crate::syscall::ERROR_STALE,
            Ok(s) if s <= MAX_UNIX_SECONDS => {
                self.source = RTC;
                self.base_ns = s * NS;
                self.sample_tick = now;
                self.generation = 1;
            }
            Ok(_) => self.last_error = -22,
            Err(e) => self.last_error = e,
        }
    }
    pub fn info(&self, now: u64) -> Info {
        let age = if self.source == UNKNOWN {
            None
        } else {
            now.checked_sub(self.sample_tick)
        };
        let value = if self.source != UNKNOWN {
            age.and_then(elapsed_ns)
                .and_then(|n| self.base_ns.checked_add(n))
                .filter(|&n| n / NS <= MAX_UNIX_SECONDS)
        } else {
            None
        };
        Info {
            flags: if value.is_some() { VALID } else { 0 }
                | if self.max_age != 0 && age.is_none_or(|n| n > self.max_age) {
                    STALE
                } else {
                    0
                },
            source: self.source,
            now_ns: value,
            sample_tick: self.sample_tick,
            now_tick: now,
            age: age.unwrap_or(u64::MAX),
            generation: self.generation,
            max_age: self.max_age,
            last_attempt: self.last_attempt,
            last_error: self.last_error,
            peer: self.peer,
            rtt_ms: self.rtt_ms,
            attempt_source: self.attempt_source,
            attempt_peer: self.attempt_peer,
            peer_port: self.peer_port,
            attempt_peer_port: self.attempt_peer_port,
        }
    }
    pub fn update(&mut self, request: &[u8; REQUEST_BYTES], now: u64) -> Result<(), i64> {
        let word = |at| u64::from_le_bytes(request[at..at + 8].try_into().unwrap());
        let u32_at = |at| u32::from_le_bytes(request[at..at + 4].try_into().unwrap());
        let (version, operation, source, peer) = (u32_at(0), u32_at(4), u32_at(8), u32_at(12));
        let (base, sampled, max_age, rtt, error) =
            (word(16), word(24), word(32), word(40), word(48) as i64);
        let peer_port = u16::from_le_bytes(request[56..58].try_into().unwrap());
        if version != 1
            || request[58..].iter().any(|&b| b != 0)
            || !matches!(source, MANUAL | SNTP_UNAUTHENTICATED)
        {
            return Err(-22);
        }
        if operation == 2 {
            if source != SNTP_UNAUTHENTICATED
                || base != 0
                || sampled != 0
                || max_age != 0
                || rtt != 0
                || error >= 0
                || peer_port == 0
                || peer >> 24 == 0
                || peer >> 24 >= 224
            {
                return Err(-22);
            }
            self.last_attempt = now;
            self.last_error = error;
            self.attempt_source = source;
            self.attempt_peer = peer;
            self.attempt_peer_port = peer_port;
            return Ok(());
        }
        if operation != 1
            || base / NS > MAX_UNIX_SECONDS
            || sampled > now
            || now - sampled > 10_000
            || rtt > 8000
            || error != 0
        {
            return Err(-22);
        }
        if source == MANUAL && (peer != 0 || rtt != 0 || max_age != 0 || peer_port != 0) {
            return Err(-22);
        }
        if source == SNTP_UNAUTHENTICATED
            && (peer == 0
                || peer >> 24 == 0
                || peer >> 24 >= 224
                || peer_port == 0
                || max_age == 0
                || max_age > 86_400 * 3_579_545 / 3579)
        {
            return Err(-22);
        }
        // Ensure the value at receipt is representable before committing state.
        if elapsed_ns(now - sampled)
            .and_then(|n| base.checked_add(n))
            .is_none_or(|n| n / NS > MAX_UNIX_SECONDS)
        {
            return Err(-22);
        }
        let generation = self.generation.checked_add(1).ok_or(-75)?;
        self.initialized = true;
        self.source = source;
        self.base_ns = base;
        self.sample_tick = sampled;
        self.generation = generation;
        self.max_age = max_age;
        self.peer = peer;
        self.peer_port = peer_port;
        self.rtt_ms = rtt as u32;
        self.last_attempt = now;
        self.last_error = 0;
        self.attempt_source = source;
        self.attempt_peer = peer;
        self.attempt_peer_port = peer_port;
        Ok(())
    }
}
impl Info {
    pub fn encode(&self) -> [u8; INFO_BYTES] {
        let mut b = [0; INFO_BYTES];
        for (at, n) in [
            (0, 1u32),
            (4, self.flags),
            (8, self.source),
            (12, self.attempt_source),
            (72, self.peer),
            (76, self.rtt_ms),
            (88, self.attempt_peer),
        ] {
            b[at..at + 4].copy_from_slice(&n.to_le_bytes());
        }
        for (at, n) in [
            (16, self.now_ns.unwrap_or(u64::MAX)),
            (24, self.sample_tick),
            (32, self.now_tick),
            (40, self.age),
            (48, self.generation),
            (56, self.last_attempt),
            (64, self.last_error as u64),
            (80, self.max_age),
        ] {
            b[at..at + 8].copy_from_slice(&n.to_le_bytes());
        }
        b[92..94].copy_from_slice(&self.peer_port.to_le_bytes());
        b[94..96].copy_from_slice(&self.attempt_peer_port.to_le_bytes());
        b
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request(source: u32, seconds: u64, tick: u64) -> [u8; REQUEST_BYTES] {
        let mut b = [0; REQUEST_BYTES];
        b[..4].copy_from_slice(&1u32.to_le_bytes());
        b[4] = 1;
        b[8..12].copy_from_slice(&source.to_le_bytes());
        b[16..24].copy_from_slice(&(seconds * NS).to_le_bytes());
        b[24..32].copy_from_slice(&tick.to_le_bytes());
        if source == SNTP_UNAUTHENTICATED {
            b[12..16].copy_from_slice(&0x0a000202u32.to_le_bytes());
            b[56..58].copy_from_slice(&123u16.to_le_bytes());
            b[32..40].copy_from_slice(&100u64.to_le_bytes());
        }
        b
    }
    #[test]
    fn unknown_rtc_and_elapsed_progression_are_honest() {
        let mut c = Clock::new();
        c.initialize_rtc(None, 12);
        assert_eq!(c.info(20).now_ns, None);
        assert_eq!(c.info(20).source, UNKNOWN);
        let mut c = Clock::new();
        c.initialize_rtc(Some(1_767_225_600), 10);
        assert_eq!(
            c.info(1010).now_ns,
            Some(1_767_225_600 * NS + elapsed_ns(1000).unwrap())
        );
    }
    #[test]
    fn rtc_bootstrap_floor_boundaries_and_hardware_failure_are_explicit() {
        for seconds in [0, 946_684_800, 1_767_225_599] {
            let mut c = Clock::new();
            c.initialize_rtc_result(Ok(seconds), 17);
            let i = c.info(17);
            assert_eq!(i.now_ns, None, "before-floor RTC {seconds}");
            assert_eq!((i.source, i.generation, i.flags), (UNKNOWN, 0, 0));
            assert_eq!(
                (i.last_error, i.last_attempt, i.attempt_source),
                (-116, 17, RTC)
            );
        }
        for seconds in [1_767_225_600, MAX_UNIX_SECONDS] {
            let mut c = Clock::new();
            c.initialize_rtc_result(Ok(seconds), 17);
            let i = c.info(17);
            assert_eq!(i.now_ns, Some(seconds * NS));
            assert_eq!((i.source, i.generation, i.last_error), (RTC, 1, 0));
        }
        let mut c = Clock::new();
        c.initialize_rtc_result(Ok(MAX_UNIX_SECONDS + 1), 17);
        assert_eq!((c.info(17).now_ns, c.info(17).last_error), (None, -22));
        let mut c = Clock::new();
        c.initialize_rtc_result(Err(-5), 17);
        assert_eq!((c.info(17).now_ns, c.info(17).last_error), (None, -5));
    }
    #[test]
    fn explicit_operator_assertions_can_override_rejected_rtc_across_supported_range() {
        let mut c = Clock::new();
        c.initialize_rtc_result(Ok(946_684_800), 17);
        assert_eq!(c.info(17).now_ns, None);
        for seconds in [0, 946_684_800, MAX_UNIX_SECONDS] {
            c.update(&request(MANUAL, seconds, 17), 17).unwrap();
            let i = c.info(17);
            assert_eq!(i.now_ns, Some(seconds * NS));
            assert_eq!((i.source, i.last_error), (MANUAL, 0));
        }
        let before = c;
        assert_eq!(
            c.update(&request(MANUAL, MAX_UNIX_SECONDS + 1, 17), 17),
            Err(-22)
        );
        assert_eq!(c, before);
    }
    #[test]
    fn backward_and_forward_steps_keep_the_original_monotonic_sample_and_rate() {
        let mut c = Clock::new();
        c.initialize_rtc(Some(1_767_235_600), 0);
        c.update(&request(MANUAL, 100, 500), 500).unwrap();
        assert_eq!(c.info(600).age, 100);
        assert_eq!(
            c.info(600).now_ns,
            Some(100 * NS + elapsed_ns(100).unwrap())
        );
        c.update(&request(MANUAL, 20000, 510), 510).unwrap();
        assert_eq!(c.info(600).age, 90);
        assert_eq!(
            c.info(600).now_ns,
            Some(20000 * NS + elapsed_ns(90).unwrap())
        );
    }
    #[test]
    fn sync_failure_preserves_last_success_and_stale_is_independent() {
        let mut c = Clock::new();
        c.update(&request(SNTP_UNAUTHENTICATED, 200, 20), 20)
            .unwrap();
        let mut bad = request(SNTP_UNAUTHENTICATED, 0, 0);
        bad[4] = 2;
        bad[32..40].fill(0);
        bad[48..56].copy_from_slice(&(-110i64).to_le_bytes());
        c.update(&bad, 50).unwrap();
        let i = c.info(50);
        assert_eq!(
            (i.source, i.last_error, i.generation),
            (SNTP_UNAUTHENTICATED, -110, 1)
        );
        assert_eq!(i.flags & STALE, 0);
        assert_ne!(c.info(121).flags & STALE, 0);
    }
    #[test]
    fn rejected_requests_leave_state_unchanged() {
        let mut c = Clock::new();
        c.initialize_rtc(Some(1_767_225_600), 0);
        let before = c;
        let mut r = request(MANUAL, 200, 11);
        assert_eq!(c.update(&r, 10), Err(-22));
        assert_eq!(c, before);
        r = request(MANUAL, 200, 10);
        r[63] = 1;
        assert_eq!(c.update(&r, 10), Err(-22));
        assert_eq!(c, before);
    }
    #[test]
    fn generation_exhaustion_refuses_without_partial_correction() {
        let mut c = Clock::new();
        c.initialize_rtc(Some(1_767_225_600), 0);
        c.generation = u64::MAX;
        let before = c;
        assert_eq!(c.update(&request(MANUAL, 200, 10), 10), Err(-75));
        assert_eq!(c, before);
    }
    #[test]
    fn clock_writer_is_exact_live_object_not_diagnostics_or_console() {
        use crate::handle::{HandleError, HandleTable, Object, RIGHT_READ, RIGHT_WRITE};
        let mut t = HandleTable::new(2);
        let c = t.insert(Object::Console, RIGHT_WRITE).unwrap();
        let d = t.insert(Object::Diagnostics, RIGHT_READ).unwrap();
        assert_eq!(authorize_update(&t, c), Err(HandleError::Rights));
        assert_eq!(authorize_update(&t, d), Err(HandleError::Rights));
        assert_eq!(
            t.insert(Object::Clock, RIGHT_READ),
            Err(HandleError::Rights)
        );
        let h = t.insert(Object::Clock, RIGHT_WRITE).unwrap();
        assert_eq!(authorize_update(&t, h), Ok(()));
        t.close(h).unwrap();
        assert_eq!(authorize_update(&t, h), Err(HandleError::Invalid));
    }
    #[test]
    fn shared_information_golden_and_request_vectors_match() {
        fn decode(hex: &str) -> std::vec::Vec<u8> {
            let h = hex.trim();
            (0..h.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
                .collect()
        }
        let mut c = Clock::new();
        let floor: u64 = include_str!("../tests/fixtures/civil-rtc-floor-v1.txt")
            .trim()
            .parse()
            .unwrap();
        assert_eq!(MIN_RTC_UNIX_SECONDS, floor);
        c.initialize_rtc(Some(floor), 0);
        assert_eq!(
            c.info(0).encode().as_slice(),
            decode(include_str!("../tests/fixtures/civil-info-v1.hex"))
        );
        let bytes = decode(include_str!("../tests/fixtures/civil-set-v1.hex"));
        c.update(bytes.as_slice().try_into().unwrap(), 10).unwrap();
        assert_eq!(c.info(10).now_ns, Some(200 * NS));
    }
    #[test]
    fn failure_events_are_bounded_and_recovery_retains_suppression_count() {
        let mut l = EventLimiter::new();
        assert_eq!(l.failure(3, 1, 123, -110, 0), Some(0));
        assert_eq!(l.failure(3, 1, 123, -110, 1), None);
        assert_eq!(l.failure(3, 1, 123, -110, 59999), None);
        assert_eq!(l.failure(3, 1, 123, -110, 60000), Some(2));
        assert_eq!(l.failure(3, 1, 123, -22, 60001), Some(0));
        assert_eq!(l.failure(3, 1, 123, -22, 60002), None);
        assert_eq!(l.recovered(), 1);
        assert_eq!(l.failure(3, 1, 123, -22, 60003), Some(0));
    }
}
