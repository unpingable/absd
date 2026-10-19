use super::*;
use alloc::{rc::Rc, vec, vec::Vec};
use core::cell::{Cell, RefCell};

const NONCE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
fn ntp(unix: u64, fraction: u32) -> [u8; 8] {
    (((unix + NTP_UNIX) << 32) | u64::from(fraction)).to_be_bytes()
}
fn packet(nonce: [u8; 8], unix: u64) -> [u8; 48] {
    let mut p = [0; 48];
    p[0] = 0x24;
    p[1] = 10;
    p[16..24].copy_from_slice(&ntp(unix - 1, 0));
    p[24..32].copy_from_slice(&nonce);
    p[32..40].copy_from_slice(&ntp(unix, 1));
    p[40..48].copy_from_slice(&ntp(unix, 2));
    p
}
#[test]
fn narrow_v4_reply_is_a_claim_with_an_explicit_era() {
    assert_eq!(
        parse_reply(&packet(NONCE, MIN_UNIX), NONCE),
        Ok(Claim {
            unix_seconds: MIN_UNIX,
            fraction_2p32: 2
        })
    );
    let mut last = packet(NONCE, MAX_UNIX);
    last[32..40].copy_from_slice(&ntp(MAX_UNIX - 1, u32::MAX));
    last[40..48].copy_from_slice(&ntp(MAX_UNIX, 0));
    assert!(parse_reply(&last, NONCE).is_ok());
    last[47] = 1;
    assert_eq!(parse_reply(&last, NONCE), Err(Refusal::EraUnknown));
    for unix in [MIN_UNIX - 1, MAX_UNIX + 1, 2_082_758_400] {
        assert_eq!(
            parse_reply(&packet(NONCE, unix), NONCE),
            Err(Refusal::EraUnknown)
        );
    }
}
#[test]
fn leap_kod_version_mode_origin_zero_reversed_and_duplicate_are_refused() {
    for (at, value, reason) in [
        (0, 0x1c, Refusal::Header),
        (0, 0x23, Refusal::Header),
        (0, 0x64, Refusal::Leap),
        (0, 0xa4, Refusal::Leap),
        (0, 0xe4, Refusal::Leap),
        (1, 0, Refusal::KoD),
        (1, 16, Refusal::Stratum),
        (24, 0, Refusal::Origin),
    ] {
        let mut p = packet(NONCE, MIN_UNIX);
        p[at] = value;
        assert_eq!(parse_reply(&p, NONCE), Err(reason));
    }
    for at in [16, 32, 40] {
        let mut p = packet(NONCE, MIN_UNIX);
        p[at..at + 8].fill(0);
        assert_eq!(parse_reply(&p, NONCE), Err(Refusal::Zero));
    }
    let mut p = packet(NONCE, MIN_UNIX);
    p[32..40].copy_from_slice(&ntp(MIN_UNIX, 2));
    assert_eq!(parse_reply(&p, NONCE), Err(Refusal::Duplicate));
    p[32..40].copy_from_slice(&ntp(MIN_UNIX, 3));
    assert_eq!(parse_reply(&p, NONCE), Err(Refusal::Reversed));
    p[16..24].copy_from_slice(&ntp(MIN_UNIX + 1, 0));
    assert_eq!(parse_reply(&p, NONCE), Err(Refusal::Reversed));
}
#[test]
fn no_short_long_extension_or_mac_form_is_accepted() {
    let p = packet(NONCE, MIN_UNIX);
    for n in 0..48 {
        assert_eq!(parse_reply(&p[..n], NONCE), Err(Refusal::Length));
    }
    for extra in [1, 4, 16, 20, 32, 1024] {
        let mut extended = p.to_vec();
        extended.resize(48 + extra, 0);
        assert_eq!(parse_reply(&extended, NONCE), Err(Refusal::Length));
    }
}

struct Wire {
    now: Rc<Cell<u64>>,
    sent: Rc<RefCell<Vec<(Vec<u8>, u64)>>>,
    answer: bool,
    claim: u64,
    receive_at: Option<u64>,
    rtc_reads: Rc<Cell<u32>>,
    send_error: Option<dns::Error>,
    advance_on_send: Option<u64>,
    jump_pause: Option<u64>,
    old_origin: bool,
    answer_after: usize,
}
impl Transport for Wire {
    fn now_ms(&self) -> u64 {
        self.now.get()
    }
    fn pause(&mut self, ms: u64) {
        self.now
            .set(self.jump_pause.take().unwrap_or(self.now.get() + ms));
    }
    fn send(&mut self, bytes: &[u8], deadline: u64) -> Result<(), dns::Error> {
        self.sent.borrow_mut().push((bytes.to_vec(), deadline));
        if let Some(now) = self.advance_on_send.take() {
            self.now.set(now);
        }
        self.send_error.map_or(Ok(()), Err)
    }
    fn receive(
        &mut self,
        bytes: &mut [u8; datagram::MAX_DATAGRAM],
        _: u64,
    ) -> Result<Option<usize>, dns::Error> {
        if !self.answer || self.sent.borrow().len() < self.answer_after {
            return Ok(None);
        }
        if let Some(now) = self.receive_at.take() {
            self.now.set(now);
        }
        let sent = self.sent.borrow();
        let index = if self.old_origin { 0 } else { sent.len() - 1 };
        let nonce = sent[index].0[40..48].try_into().unwrap();
        let p = packet(nonce, self.claim);
        bytes[..48].copy_from_slice(&p);
        Ok(Some(48))
    }
}
fn wire() -> Wire {
    Wire {
        now: Rc::new(Cell::new(100)),
        sent: Rc::new(RefCell::new(Vec::new())),
        answer: true,
        claim: MIN_UNIX,
        receive_at: Some(120),
        rtc_reads: Rc::new(Cell::new(0)),
        send_error: None,
        advance_on_send: None,
        jump_pause: None,
        old_origin: false,
        answer_after: 1,
    }
}
fn entropy(bytes: &mut [u8]) -> Result<(), ()> {
    bytes.copy_from_slice(&NONCE);
    Ok(())
}
#[test]
fn success_reports_only_claim_rtc_and_boot_span_and_spends_the_query() {
    let w = wire();
    let sent = w.sent.clone();
    let reads = w.rtc_reads.clone();
    let mut query = Query::new(w);
    let result = query
        .observe(entropy, || {
            reads.set(reads.get() + 1);
            Ok(MIN_UNIX + 30)
        })
        .unwrap();
    assert_eq!(
        (
            result.boot_sent_ms,
            result.boot_received_ms,
            result.boot_rtt_ms
        ),
        (100, 120, 20)
    );
    assert_eq!(result.unauthenticated_difference(), Some(-30));
    assert_eq!(reads.get(), 1);
    assert_eq!(sent.borrow().len(), 1);
    assert_eq!(
        query.observe(entropy, || panic!("retired RTC read")),
        Err(Error::Retired)
    );
    assert_eq!(sent.borrow().len(), 1);
}
#[test]
fn absent_rtc_is_reported_without_inventing_a_civil_value() {
    let mut query = Query::new(wire());
    let result = query.observe(entropy, || Err(-5)).unwrap();
    assert_eq!(result.rtc, Err(-5));
    assert_eq!(result.unauthenticated_difference(), None);
}
#[test]
fn no_reply_has_three_unique_requests_and_original_absolute_bounds() {
    let mut w = wire();
    w.answer = false;
    let sent = w.sent.clone();
    let now = w.now.clone();
    let mut query = Query::new(w);
    let mut nonce = 0u64;
    let result = query.observe(
        |bytes| {
            nonce += 1;
            bytes.copy_from_slice(&nonce.to_be_bytes());
            Ok::<_, ()>(())
        },
        || panic!("no RTC without response"),
    );
    assert_eq!(result, Err(Error::Timeout));
    assert_eq!(sent.borrow().len(), 3);
    assert_eq!(now.get(), 6100);
    assert_eq!(query.until, Some(8100));
    assert_eq!(
        sent.borrow().iter().map(|s| s.1).collect::<Vec<_>>(),
        vec![2100, 4100, 6100]
    );
    assert!(
        sent.borrow()
            .iter()
            .all(|s| s.0.len() == 48 && s.0[0] == 0x23 && s.0[1..40] == [0; 39])
    );
}
#[test]
fn missing_zero_or_repeated_entropy_never_uses_a_fallback() {
    let w = wire();
    let sent = w.sent.clone();
    let mut q = Query::new(w);
    assert_eq!(
        q.observe(|_| Err::<(), _>(()), || panic!("RTC")),
        Err(Error::Entropy)
    );
    assert!(sent.borrow().is_empty());
    let w = wire();
    let sent = w.sent.clone();
    let mut q = Query::new(w);
    assert_eq!(
        q.observe(
            |b| {
                b.fill(0);
                Ok::<_, ()>(())
            },
            || panic!("RTC")
        ),
        Err(Error::Entropy)
    );
    assert!(sent.borrow().is_empty());
    let mut w = wire();
    w.answer = false;
    let sent = w.sent.clone();
    let mut q = Query::new(w);
    assert_eq!(q.observe(entropy, || panic!("RTC")), Err(Error::Entropy));
    assert_eq!(sent.borrow().len(), 1);
}
#[test]
fn late_receive_rtc_read_and_clock_rewind_never_return_an_observation() {
    for (after, expected) in [(2100, Error::Late), (99, Error::Clock)] {
        let mut w = wire();
        w.receive_at = Some(after);
        let mut q = Query::new(w);
        assert_eq!(
            q.observe(entropy, || panic!("refusal precedes RTC")),
            Err(expected)
        );
    }
    let w = wire();
    let now = w.now.clone();
    let mut q = Query::new(w);
    assert_eq!(
        q.observe(entropy, || {
            now.set(2100);
            Ok(MIN_UNIX)
        }),
        Err(Error::Late)
    );
    let mut w = wire();
    w.answer = false;
    w.jump_pause = Some(8100);
    let sent = w.sent.clone();
    let mut q = Query::new(w);
    assert_eq!(q.observe(entropy, || panic!("RTC")), Err(Error::Timeout));
    assert_eq!(sent.borrow().len(), 1);
}
#[test]
fn uncertain_or_straddling_send_records_first_effect_without_retry() {
    for (error, advance, expected) in [
        (
            Some(dns::Error::Channel(-5)),
            None,
            Error::Transport(dns::Error::Channel(-5)),
        ),
        (None, Some(2100), Error::Late),
    ] {
        let mut w = wire();
        w.send_error = error;
        w.advance_on_send = advance;
        let sent = w.sent.clone();
        let mut q = Query::new(w);
        assert_eq!(q.observe(entropy, || panic!("RTC")), Err(expected));
        assert_eq!(sent.borrow().len(), 1); // An effect may already have occurred.
        assert_eq!(q.observe(entropy, || panic!("RTC")), Err(Error::Retired));
        assert_eq!(sent.borrow().len(), 1);
    }
}
#[test]
fn backward_civil_claim_changes_no_boot_deadline_or_elapsed_observation() {
    let mut before = None;
    for claim in [MIN_UNIX + 86400, MIN_UNIX] {
        let mut w = wire();
        w.claim = claim;
        let sent = w.sent.clone();
        let now = w.now.clone();
        let mut q = Query::new(w);
        let observed = q.observe(entropy, || Ok(MIN_UNIX + 2 * 86400)).unwrap();
        assert_eq!(
            (q.until, sent.borrow()[0].1, now.get(), observed.boot_rtt_ms),
            (Some(8100), 2100, 120, 20)
        );
        if let Some(previous) = before {
            assert!(observed.claim.unix_seconds < previous);
        }
        before = Some(observed.claim.unix_seconds);
    }
}
#[test]
fn prior_attempt_reply_is_refused_even_after_a_new_request() {
    let mut w = wire();
    w.answer_after = 2;
    w.old_origin = true;
    w.receive_at = None;
    let sent = w.sent.clone();
    let mut q = Query::new(w);
    let mut nonce = 0u64;
    let result = q.observe(
        |bytes| {
            nonce += 1;
            bytes.copy_from_slice(&nonce.to_be_bytes());
            Ok::<_, ()>(())
        },
        || panic!("stale RTC"),
    );
    assert_eq!(result, Err(Error::Refused(Refusal::Origin)));
    assert_eq!(sent.borrow().len(), 2);
    assert_eq!(
        q.observe(entropy, || panic!("retired")),
        Err(Error::Retired)
    );
}
#[test]
fn native_startup_time_and_overflow_cannot_create_a_fresh_budget() {
    let w = wire();
    w.now.set(8100);
    let sent = w.sent.clone();
    let mut q = Query::with_start(w, 100, 100);
    assert_eq!(
        q.observe(
            |_| -> Result<(), ()> { panic!("expired before entropy") },
            || panic!("RTC")
        ),
        Err(Error::Timeout)
    );
    assert!(sent.borrow().is_empty());
    let w = wire();
    let sent = w.sent.clone();
    let mut q = Query::with_start(w, u64::MAX, u64::MAX);
    assert_eq!(q.observe(entropy, || panic!("RTC")), Err(Error::Clock));
    assert!(sent.borrow().is_empty());
    let w = wire();
    w.now.set(150);
    let sent = w.sent.clone();
    let mut q = Query::with_start(w, 100, 200);
    assert_eq!(q.observe(entropy, || panic!("RTC")), Err(Error::Clock));
    assert!(sent.borrow().is_empty());
}
