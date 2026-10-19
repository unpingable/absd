use super::*;
use alloc::vec;
const LOCAL_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
fn ip(last: u8) -> [u8; 16] {
    let mut a = [0; 16];
    a[0] = 0xfd;
    a[15] = last;
    a
}
fn peer() -> Address {
    Address {
        ip: ip(2),
        port: 42019,
        scope: 7,
    }
}
fn sum(bytes: &[u8]) -> u16 {
    let mut n: u32 = bytes
        .chunks(2)
        .map(|b| u16::from_be_bytes([b[0], *b.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while n > 65535 {
        n = (n & 65535) + (n >> 16);
    }
    !(n as u16)
}
fn checksum(source: [u8; 16], target: [u8; 16], protocol: u8, payload: &mut [u8], at: usize) {
    payload[at..at + 2].fill(0);
    let mut p = source.to_vec();
    p.extend_from_slice(&target);
    p.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, protocol]);
    p.extend_from_slice(payload);
    let value = sum(&p);
    payload[at..at + 2].copy_from_slice(&value.to_be_bytes());
}
fn ethernet(
    source: [u8; 16],
    target: [u8; 16],
    protocol: u8,
    payload: &[u8],
    outgoing: bool,
) -> Vec<u8> {
    let (src, dst) = if outgoing {
        (LOCAL_MAC, PEER_MAC)
    } else {
        (PEER_MAC, LOCAL_MAC)
    };
    let mut b = vec![0; 54 + payload.len()];
    b[..6].copy_from_slice(&dst);
    b[6..12].copy_from_slice(&src);
    b[12..14].copy_from_slice(&[0x86, 0xdd]);
    b[14] = 0x60;
    b[18..20].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    b[20] = protocol;
    b[21] = 64;
    b[22..38].copy_from_slice(&source);
    b[38..54].copy_from_slice(&target);
    b[54..].copy_from_slice(payload);
    b
}
fn submitted(byte: u8, size: usize) -> Vec<u8> {
    let mut payload = vec![byte; 8 + size];
    payload[..2].copy_from_slice(&49152u16.to_be_bytes());
    payload[2..4].copy_from_slice(&42019u16.to_be_bytes());
    payload[4..6].copy_from_slice(&((8 + size) as u16).to_be_bytes());
    checksum(ip(1), ip(2), 17, &mut payload, 6);
    ethernet(ip(1), ip(2), 17, &payload, true)
}
fn error(frame: &[u8], observation: Observation) -> Vec<u8> {
    let mut payload = observation.encode().to_vec();
    payload.extend_from_slice(&frame[14..]);
    checksum(ip(2), ip(1), 58, &mut payload, 2);
    ethernet(ip(2), ip(1), 58, &payload, false)
}
fn port_unreachable() -> Observation {
    Observation {
        kind: 1,
        code: 4,
        detail: 0,
    }
}
fn observer() -> Feedback {
    let mut f = Feedback::new(LOCAL_MAC);
    f.bind(0, 1, ip(1), 49152, peer());
    f
}
#[test]
fn literal_fixed_result_preserves_full_32_bit_advice_and_refuses_unknown_forms() {
    let literal = [2, 0, 0, 0, 0x89, 0xab, 0xcd, 0xef];
    assert_eq!(
        Observation::decode(&literal),
        Some(Observation {
            kind: 2,
            code: 0,
            detail: 0x89abcdef
        })
    );
    assert_eq!(Observation::decode(&literal).unwrap().encode(), literal);
    for bad in [
        [2, 1, 0, 0, 0, 0, 5, 0],
        [2, 0, 0, 0, 0, 0, 0, 0],
        [1, 7, 0, 0, 0, 0, 0, 0],
        [1, 4, 1, 0, 0, 0, 0, 0],
        [1, 4, 0, 0, 0, 0, 0, 1],
        [128, 0, 0, 0, 0, 0, 0, 0],
    ] {
        assert_eq!(Observation::decode(&bad), None);
    }
    assert_eq!(Observation::decode(&literal[..7]), None);
}
#[test]
fn complete_successfully_submitted_packet_correlates_once() {
    let mut f = observer();
    let sent = submitted(1, 24);
    let reply = error(&sent, port_unreachable());
    f.received(&reply, 100);
    assert_eq!(f.take(0, 1, 100), None);
    f.submitted(&sent, 100);
    f.received(&reply, 101);
    assert_eq!(f.take(0, 1, 101), Some(port_unreachable()));
    f.received(&reply, 102);
    assert_eq!(f.take(0, 1, 102), None);
}
#[test]
fn complete_quote_bytes_and_checksum_and_outer_identity_are_required() {
    let sent = submitted(1, 24);
    let good = error(&sent, port_unreachable());
    for offset in [0, 6, 22, 38, 54, 55, 56, 62, 69, 86, 110] {
        let mut f = observer();
        f.submitted(&sent, 100);
        let mut bad = good.clone();
        bad[offset] ^= 1;
        // Recompute outer ICMP checksum so inner/body mutations are not
        // refused only by the outer checksum rather than exact correlation.
        if offset >= 62 {
            checksum(ip(2), ip(1), 58, &mut bad[54..], 2);
        }
        f.received(&bad, 101);
        assert_eq!(f.take(0, 1, 101), None, "offset {offset}");
    }
    let mut f = observer();
    f.submitted(&sent, 100);
    let shorter = error(&sent[..sent.len() - 1], port_unreachable());
    f.received(&shorter, 101);
    assert_eq!(f.take(0, 1, 101), None);
    let mut extra = good.clone();
    extra.push(0);
    f.received(&extra, 101);
    assert_eq!(f.take(0, 1, 101), None);
    f.received(&good, 101);
    assert_eq!(f.take(0, 1, 101), Some(port_unreachable()));
}
#[test]
fn full_quote_ceiling_does_not_construct_record_for_larger_valid_udp() {
    let mut f = observer();
    let large = submitted(1, MAX_QUOTE - 47);
    f.submitted(&large, 100);
    assert!(
        f.flows[0]
            .as_ref()
            .unwrap()
            .recent
            .iter()
            .all(Option::is_none)
    );
    let edge = submitted(2, MAX_QUOTE - 48);
    f.submitted(&edge, 100);
    assert_eq!(
        f.flows[0].as_ref().unwrap().recent.iter().flatten().count(),
        1
    );
}
#[test]
fn finite_history_eviction_first_pending_and_identical_copy_consumption_are_explicit() {
    let mut f = observer();
    for n in 0..=HISTORY {
        f.submitted(&submitted(n as u8, 24), 100);
    }
    f.received(&error(&submitted(0, 24), port_unreachable()), 101);
    assert_eq!(f.take(0, 1, 101), None);
    let first = submitted(1, 24);
    let second = submitted(2, 24);
    f.received(&error(&first, port_unreachable()), 101);
    f.received(
        &error(
            &second,
            Observation {
                kind: 2,
                code: 0,
                detail: 0x12345678,
            },
        ),
        101,
    );
    assert_eq!(f.take(0, 1, 101), Some(port_unreachable()));
    assert_eq!(
        f.take(0, 1, 101),
        None,
        "later report lost while first pending"
    );
    f.submitted(&first, 102);
    f.submitted(&first, 102);
    let reply = error(&first, port_unreachable());
    f.received(&reply, 103);
    f.take(0, 1, 103);
    f.received(&reply, 104);
    assert_eq!(f.take(0, 1, 104), None);
}
fn submitted_query(id: u16, question: &[u8]) -> Vec<u8> {
    let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    query[..2].copy_from_slice(&id.to_be_bytes());
    query.extend_from_slice(question);
    query.extend_from_slice(&[0, 1, 0, 1]);
    let mut frame = submitted(0, query.len());
    frame[62..].copy_from_slice(&query);
    checksum(ip(1), ip(2), 17, &mut frame[54..], 6);
    frame
}
#[test]
fn previous_query_complete_quote_still_matches_after_a_distinct_query_submission() {
    let first = submitted_query(0x1234, b"\x05first\x07example\0");
    let second = submitted_query(0x1235, b"\x06second\x07example\0");
    assert_ne!(first[14..], second[14..]);
    let mut f = observer();
    f.submitted(&first, 100);
    // A successful DNS answer does not notify or clear this endpoint observer.
    f.submitted(&second, 120);
    f.received(&error(&first, port_unreachable()), 121);
    assert_eq!(f.take(0, 1, 121), Some(port_unreachable()));
    assert_eq!(f.take(0, 1, 121), None);
}
#[test]
fn matched_unreachable_replaces_pending_advice_and_consumes_its_matching_history() {
    let first = submitted_query(0x1234, b"\x05first\x07example\0");
    let second = submitted_query(0x1235, b"\x06second\x07example\0");
    for advice in [
        Observation {
            kind: 2,
            code: 0,
            detail: 1280,
        },
        Observation {
            kind: 3,
            code: 0,
            detail: 0,
        },
        Observation {
            kind: 3,
            code: 1,
            detail: 0,
        },
    ] {
        let mut f = observer();
        f.submitted(&first, 100);
        f.submitted(&second, 100);
        f.received(&error(&first, advice), 101);
        let later = error(&second, port_unreachable());
        f.received(&later, 102);
        assert_eq!(f.take(0, 1, 103), Some(port_unreachable()));
        assert_eq!(f.take(0, 1, 103), None, "replacement is consumed once");
        f.received(&later, 104);
        f.received(&error(&first, advice), 104);
        assert_eq!(
            f.take(0, 1, 104),
            None,
            "both matching histories stay consumed"
        );
    }
}
#[test]
fn unsubmitted_or_wrong_quote_terminal_report_cannot_replace_pending_advice() {
    let first = submitted_query(0x1234, b"\x05first\x07example\0");
    let second = submitted_query(0x1235, b"\x06second\x07example\0");
    let advice = Observation {
        kind: 2,
        code: 0,
        detail: 1280,
    };
    for mode in 0..2 {
        let mut f = observer();
        f.submitted(&first, 100);
        if mode == 1 {
            f.submitted(&second, 100);
        }
        f.received(&error(&first, advice), 101);
        let mut later = error(&second, port_unreachable());
        if mode == 1 {
            // Preserve a valid outer checksum while changing the quoted ID.
            later[110] ^= 1;
            checksum(ip(2), ip(1), 58, &mut later[54..], 2);
        }
        f.received(&later, 102);
        assert_eq!(f.take(0, 1, 103), Some(advice), "mode {mode}");
        assert_eq!(f.take(0, 1, 103), None);
    }
}
#[test]
fn pending_terminal_remains_first_and_later_advice_or_terminal_history_is_spent() {
    let first = submitted(1, 24);
    let second = submitted(2, 24);
    for later in [
        Observation {
            kind: 2,
            code: 0,
            detail: 1280,
        },
        Observation {
            kind: 3,
            code: 1,
            detail: 0,
        },
        Observation {
            kind: 1,
            code: 1,
            detail: 0,
        },
    ] {
        let mut f = observer();
        f.submitted(&first, 100);
        f.submitted(&second, 100);
        f.received(&error(&first, port_unreachable()), 101);
        f.received(&error(&second, later), 102);
        assert_eq!(f.take(0, 1, 103), Some(port_unreachable()));
        f.received(&error(&second, later), 104);
        assert_eq!(f.take(0, 1, 104), None);
    }
}
#[test]
fn pending_advice_remains_first_and_later_advice_history_is_spent() {
    let first = submitted(1, 24);
    let second = submitted(2, 24);
    let advice = [
        Observation {
            kind: 2,
            code: 0,
            detail: 1280,
        },
        Observation {
            kind: 3,
            code: 0,
            detail: 0,
        },
        Observation {
            kind: 3,
            code: 1,
            detail: 0,
        },
    ];
    for pending in advice {
        for later in advice {
            let mut f = observer();
            f.submitted(&first, 100);
            f.submitted(&second, 100);
            f.received(&error(&first, pending), 101);
            let later_report = error(&second, later);
            f.received(&later_report, 102);
            assert_eq!(f.take(0, 1, 103), Some(pending));
            assert_eq!(f.take(0, 1, 103), None);
            f.received(&later_report, 104);
            f.received(&error(&first, pending), 104);
            assert_eq!(f.take(0, 1, 104), None, "both histories stay consumed");

            // A fresh submission, rather than replay of the spent quote,
            // makes this same later observation eligible again.
            f.submitted(&second, 105);
            f.received(&later_report, 106);
            assert_eq!(f.take(0, 1, 106), Some(later));
        }
    }
}
#[test]
fn submitted_history_and_pending_age_include_1000_ms_but_refuse_1001_ms() {
    assert_eq!(RECENT_MS, 1000);
    let sent = submitted_query(0x1234, b"\x05first\x07example\0");
    let report = error(&sent, port_unreachable());
    for (age, expected) in [(1000, Some(port_unreachable())), (1001, None)] {
        let mut f = observer();
        f.submitted(&sent, 100);
        f.received(&report, 100 + age);
        assert_eq!(f.take(0, 1, 100 + age), expected, "submitted age {age}");

        let mut f = observer();
        f.submitted(&sent, 100);
        f.received(&report, 101);
        assert_eq!(f.take(0, 1, 101 + age), expected, "pending age {age}");
    }
}
#[test]
fn stale_pending_and_history_rewind_close_reissue_and_io_loss_clear_correlation() {
    for mode in 0..7 {
        let mut f = observer();
        let sent = submitted(1, 24);
        let reply = error(&sent, port_unreachable());
        f.submitted(&sent, 100);
        f.received(&reply, 101);
        match mode {
            0 => {
                f.take(0, 1, 1102);
            }
            1 => {
                f.take(0, 1, 99);
            }
            2 => f.revoke(0),
            3 => f.bind(0, 2, ip(1), 49152, peer()),
            4 => f.lost(),
            5 => f.fence(),
            _ => {
                f.clock(1102);
            }
        }
        f.received(&reply, 1103);
        assert_eq!(f.take(0, 1, 1103), None, "case {mode}");
        assert_eq!(f.take(0, 2, 1103), None, "new epoch case {mode}");
    }
}
#[test]
fn pending_and_history_cannot_cross_slot_epoch_or_peer() {
    let mut f = observer();
    let sent = submitted(1, 24);
    f.submitted(&sent, 100);
    f.received(&error(&sent, port_unreachable()), 101);
    assert_eq!(f.take(0, 2, 101), None);
    assert_eq!(f.take(1, 1, 101), None);
    assert_eq!(f.take(0, 1, 101), Some(port_unreachable()));
    f.bind(
        0,
        2,
        ip(1),
        49152,
        Address {
            ip: ip(3),
            ..peer()
        },
    );
    f.submitted(&sent, 102);
    f.received(&error(&sent, port_unreachable()), 103);
    assert_eq!(f.take(0, 2, 103), None);
}
#[test]
fn uncertain_submission_establishes_no_record_and_lost_io_erases_prior_evidence() {
    let mut f = observer();
    let sent = submitted(1, 24);
    let reply = error(&sent, port_unreachable());
    // No submitted() call represents an underlying send that returned Err,
    // even though that first I/O could already have had an effect.
    f.lost();
    f.received(&reply, 100);
    assert_eq!(f.take(0, 1, 100), None);
    f.submitted(&sent, 101);
    f.lost();
    f.received(&reply, 102);
    assert_eq!(f.take(0, 1, 102), None);
}

struct LocalLink;
impl crate::Link for LocalLink {
    fn mac(&self) -> [u8; 6] {
        LOCAL_MAC
    }
    fn send(&mut self, _: &[u8]) -> Result<(), i64> {
        Ok(())
    }
    fn receive(&mut self, _: &mut [u8; crate::FRAME_MAX], _: u64) -> Result<Option<usize>, i64> {
        Ok(None)
    }
    fn now_ms(&self) -> u64 {
        100
    }
    fn pause(&self, _: u64) {}
}
fn stack() -> crate::Stack<LocalLink> {
    let mut s = crate::Stack::open(LocalLink, crate::Config::qemu_user()).unwrap();
    s.configure_ipv6(super::super::Config {
        address: ip(1),
        prefix_len: 64,
        scope: 7,
    })
    .unwrap();
    s
}
fn session(s: &mut crate::Stack<LocalLink>) -> super::super::session::Session {
    super::super::session::Session::grant(
        s,
        super::super::Grant {
            local_port: 49152,
            peer: peer(),
        },
    )
    .unwrap()
}
fn feedback_request() -> [u8; 28] {
    let mut b = [0; 28];
    b[0] = 2;
    b[1] = 4;
    b[3] = 6;
    b
}
fn pending(s: &mut crate::Stack<LocalLink>) {
    let sent = submitted(1, 24);
    s.port.ipv6_feedback.submitted(&sent, 100);
    s.port
        .ipv6_feedback
        .received(&error(&sent, port_unreachable()), 100);
}
#[test]
fn literal_v2_feedback_response_and_malformed_request_do_not_select_or_consume_another_slot() {
    use super::super::session::{HEADER, MAX_MESSAGE};
    let mut s = stack();
    let mut owner = session(&mut s);
    pending(&mut s);
    let request = feedback_request();
    let mut reply = [0; MAX_MESSAGE];
    for at in [0, 2, 3, 4, 20, 24, 26, 27] {
        let mut bad = request;
        bad[at] ^= 1;
        assert_eq!(owner.request(&mut s, &bad, &mut reply), HEADER);
        assert_eq!(reply[2], 1);
    }
    assert_eq!(owner.request(&mut s, &request, &mut reply), 36);
    let literal = [
        2, 4, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 1, 4,
        0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(&reply[..36], &literal);
    owner.request(&mut s, &request, &mut reply);
    assert_eq!(reply[2], 6);
    assert_eq!(&reply[4..HEADER], &[0; 24]);
    let mut close = request;
    close[1] = 3;
    owner.request(&mut s, &close, &mut reply);
    owner.request(&mut s, &request, &mut reply);
    assert_eq!(reply[2], 8);
    let mut next = session(&mut s);
    next.request(&mut s, &request, &mut reply);
    assert_eq!(reply[2], 6);
}
#[test]
fn pending_feedback_response_partial_io_then_interruption_fences_and_is_not_reissued() {
    use super::super::{
        channel::{Channel, Pipe},
        session::MAX_MESSAGE,
    };
    struct Broken {
        input: alloc::collections::VecDeque<u8>,
        output: Vec<u8>,
        writes: usize,
    }
    impl Pipe for Broken {
        fn now_ms(&self) -> u64 {
            100
        }
        fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
            let n = b.len().min(self.input.len());
            for x in &mut b[..n] {
                *x = self.input.pop_front().unwrap();
            }
            Ok(Some(n))
        }
        fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
            self.writes += 1;
            if self.writes == 1 {
                self.output.extend_from_slice(&b[..3]);
                Ok(Some(3))
            } else {
                Err(-5)
            }
        }
    }
    let mut s = stack();
    let own = session(&mut s);
    pending(&mut s);
    let mut c = Channel::new(own);
    let mut bytes = vec![0, 28];
    bytes.extend_from_slice(&feedback_request());
    let mut pipe = Broken {
        input: bytes.into(),
        output: Vec::new(),
        writes: 0,
    };
    assert!(c.poll(&mut s, &mut pipe));
    assert!(c.poll(&mut s, &mut pipe));
    assert!(c.poll(&mut s, &mut pipe));
    assert!(!c.poll(&mut s, &mut pipe));
    assert_eq!(
        pipe.output.len(),
        3,
        "partial reply is an irreversible first effect"
    );
    assert_eq!(s.socket_count(), 0);
    assert!(!c.poll(&mut s, &mut pipe));
    assert_eq!(pipe.writes, 2);
    let mut next = session(&mut s);
    let mut out = [0; MAX_MESSAGE];
    next.request(&mut s, &feedback_request(), &mut out);
    assert_eq!(out[2], 6);
}

struct Pump {
    input: alloc::collections::VecDeque<u8>,
    output: Vec<u8>,
    trip: Option<alloc::rc::Rc<core::cell::Cell<bool>>>,
    limit: usize,
    now: u64,
}
impl super::super::channel::Pipe for Pump {
    fn now_ms(&self) -> u64 {
        self.now
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        let n = b.len().min(self.input.len());
        for x in &mut b[..n] {
            *x = self.input.pop_front().unwrap();
        }
        Ok(Some(n))
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        let n = b.len().min(self.limit);
        self.output.extend_from_slice(&b[..n]);
        if let Some(trip) = &self.trip {
            trip.set(true);
        }
        Ok(Some(n))
    }
}
fn pump() -> Pump {
    let mut b = vec![0, 28];
    b.extend_from_slice(&feedback_request());
    Pump {
        input: b.into(),
        output: Vec::new(),
        trip: None,
        limit: usize::MAX,
        now: 100,
    }
}
#[test]
fn serialized_feedback_is_fenced_before_first_write_after_loss_close_reissue_or_recovery() {
    use super::super::{Grant, channel::Channel};
    for mode in 0..8 {
        let mut s = stack();
        let own = session(&mut s);
        let endpoint = own.feedback_endpoint();
        pending(&mut s);
        let mut c = Channel::new(own);
        let mut p = pump();
        assert!(c.poll(&mut s, &mut p));
        assert!(c.poll(&mut s, &mut p));
        match mode {
            0 => s.port.ipv6_feedback.lost(),
            1 => s.ipv6_close(endpoint).unwrap(),
            2 => {
                s.ipv6_close(endpoint).unwrap();
                s.ipv6_bind(Grant {
                    local_port: 49152,
                    peer: peer(),
                })
                .unwrap();
            }
            3 => s.ipv6_fence(),
            4 => {
                s.port.ipv6_feedback.lost();
                pending(&mut s);
            }
            5 => {
                s.port.ipv6_feedback.fault_generation = Some(u64::MAX);
                s.port.ipv6_feedback.lost();
            }
            6 => p.now = 99,
            _ => p.now = 350,
        }
        assert!(!c.poll(&mut s, &mut p), "case {mode}");
        assert!(p.output.is_empty(), "case {mode}");
        assert!(!c.poll(&mut s, &mut p));
        assert_eq!(
            s.socket_count(),
            usize::from(mode == 2),
            "old revoke cannot remove reissued endpoint"
        );
    }
}
#[test]
fn checked_fault_generation_exhaustion_refuses_without_reviving_after_rebind() {
    let mut s = stack();
    let own = session(&mut s);
    let e = own.feedback_endpoint();
    s.port.ipv6_feedback.fault_generation = Some(u64::MAX);
    s.port.ipv6_feedback.lost();
    pending(&mut s);
    assert_eq!(s.ipv6_feedback(e), Err(super::super::Error::Exhausted));
    s.ipv6_close(e).unwrap();
    let next = session(&mut s);
    assert_eq!(
        s.ipv6_feedback(next.feedback_endpoint()),
        Err(super::super::Error::Exhausted)
    );
}
#[test]
fn feedback_write_straddling_link_loss_keeps_possible_first_bytes_and_blocks_later_output() {
    use super::super::channel::Channel;
    struct SwitchLink(alloc::rc::Rc<core::cell::Cell<bool>>);
    impl crate::Link for SwitchLink {
        fn mac(&self) -> [u8; 6] {
            LOCAL_MAC
        }
        fn send(&mut self, _: &[u8]) -> Result<(), i64> {
            Ok(())
        }
        fn receive(
            &mut self,
            _: &mut [u8; crate::FRAME_MAX],
            _: u64,
        ) -> Result<Option<usize>, i64> {
            Ok(None)
        }
        fn now_ms(&self) -> u64 {
            100
        }
        fn pause(&self, _: u64) {}
        fn read(&self) -> Option<crate::LinkReading> {
            Some(crate::LinkReading {
                link_up: !self.0.get(),
                disabled: false,
                rx_missed: 0,
            })
        }
    }
    for limit in [3, usize::MAX] {
        let trip = alloc::rc::Rc::new(core::cell::Cell::new(false));
        let mut s =
            crate::Stack::open(SwitchLink(trip.clone()), crate::Config::qemu_user()).unwrap();
        s.configure_ipv6(super::super::Config {
            address: ip(1),
            prefix_len: 64,
            scope: 7,
        })
        .unwrap();
        let own = super::super::session::Session::grant(
            &mut s,
            super::super::Grant {
                local_port: 49152,
                peer: peer(),
            },
        )
        .unwrap();
        let sent = submitted(1, 24);
        s.port.ipv6_feedback.submitted(&sent, 100);
        s.port
            .ipv6_feedback
            .received(&error(&sent, port_unreachable()), 100);
        let mut c = Channel::new(own);
        let mut p = pump();
        p.limit = limit;
        p.trip = Some(trip.clone());
        assert!(c.poll(&mut s, &mut p));
        assert!(c.poll(&mut s, &mut p));
        assert!(!c.poll(&mut s, &mut p));
        assert_eq!(
            p.output.len(),
            limit.min(38),
            "first write effect cannot be recalled, even if complete"
        );
        trip.set(false);
        assert!(!c.poll(&mut s, &mut p));
        assert_eq!(p.output.len(), limit.min(38));
        assert_eq!(s.socket_count(), 0);
    }
}
