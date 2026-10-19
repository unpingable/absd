use super::*;
use crate::dns::Transport;
use alloc::{collections::VecDeque, rc::Rc, vec, vec::Vec};
use core::cell::RefCell;
struct State {
    input: VecDeque<u8>,
    written: Vec<u8>,
    now: u64,
    read_advance: u64,
}
#[derive(Clone)]
struct Script(Rc<RefCell<State>>);
impl Pipe for Script {
    fn now_ms(&self) -> u64 {
        self.0.borrow().now
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        let mut s = self.0.borrow_mut();
        let n = b.len().min(s.input.len());
        for x in &mut b[..n] {
            *x = s.input.pop_front().unwrap();
        }
        let advance = s.read_advance;
        s.now += advance;
        Ok(Some(n))
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        self.0.borrow_mut().written.extend_from_slice(b);
        Ok(Some(b.len()))
    }
}
fn peer() -> Address {
    let mut ip = [0; 16];
    ip[0] = 0xfd;
    ip[15] = 2;
    Address {
        ip,
        scope: 7,
        port: 42019,
    }
}
fn response(op: u8, status: u8, body: &[u8]) -> Vec<u8> {
    let mut b = vec![0; HEADER];
    b[0] = 2;
    b[1] = op;
    b[2] = status;
    b[3] = 6;
    b[26..28].copy_from_slice(&(body.len() as u16).to_be_bytes());
    b.extend_from_slice(body);
    let mut framed = (b.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&b);
    framed
}
fn script(bytes: Vec<u8>) -> Script {
    Script(Rc::new(RefCell::new(State {
        input: bytes.into(),
        written: Vec::new(),
        now: 10,
        read_advance: 0,
    })))
}
fn dns_answer(id: u16, question: &[u8]) -> Vec<u8> {
    // Literal ordinary A response, independent of the resolver query writer.
    let mut body = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    body[..2].copy_from_slice(&id.to_be_bytes());
    body.extend_from_slice(question);
    body.extend_from_slice(&[
        0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 9,
    ]);
    let mut framed = response(RECEIVE, 0, &body);
    framed[6..22].copy_from_slice(&peer().ip);
    framed[22..26].copy_from_slice(&peer().scope.to_be_bytes());
    framed[26..28].copy_from_slice(&peer().port.to_be_bytes());
    framed
}
fn requests(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut parsed = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let length = u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap()) as usize;
        parsed.push(bytes[at + 2..at + 2 + length].to_vec());
        at += 2 + length;
    }
    assert_eq!(at, bytes.len());
    parsed
}
#[test]
fn ptb_and_both_time_exceeded_codes_are_advisory_before_a_real_resolver_answer() {
    for advice in [
        [2, 0, 0, 0, 0x89, 0xab, 0xcd, 0xef],
        [3, 0, 0, 0, 0, 0, 0, 0],
        [3, 1, 0, 0, 0, 0, 0, 0],
    ] {
        let mut input = response(SEND, 0, &[]);
        input.extend(response(4, 0, &advice));
        input.extend(dns_answer(0x1234, b"\x05first\x07example\0"));
        let pipe = script(input);
        let observe = pipe.clone();
        let mut resolver =
            crate::dns::Resolver::new(Datagram::with_feedback(pipe, peer(), |_| {}), 0x1234);
        let answer = resolver.lookup("first.example").unwrap();
        assert_eq!(answer.count, 1);
        assert_eq!(answer.addresses[0], [192, 0, 2, 9]);
        let sent = requests(&observe.0.borrow().written);
        assert_eq!(
            sent.iter().map(|b| b[1]).collect::<Vec<_>>(),
            [SEND, 4, RECEIVE]
        );
        assert_eq!(&sent[0][HEADER..HEADER + 2], &[0x12, 0x34]);
        assert!(observe.0.borrow().input.is_empty());
    }
}
#[test]
fn type_one_remains_terminal_without_a_receive_or_an_automatic_retry() {
    for code in 0..=6 {
        let body = [1, code, 0, 0, 0, 0, 0, 0];
        let pipe = script(response(4, 0, &body));
        let observe = pipe.clone();
        let mut d = Datagram::with_feedback(pipe, peer(), |_| {});
        assert_eq!(
            d.receive(&mut [0; crate::datagram::MAX_DATAGRAM], 1000),
            Err(Error::Ipv6Feedback(feedback::Observation {
                kind: 1,
                code,
                detail: 0,
            }))
        );
        assert!(d.live());
        assert_eq!(observe.0.borrow().written.len(), 30);
        assert_eq!(observe.0.borrow().written[3], 4);
    }
}
#[test]
fn advisory_receive_keeps_the_original_deadline_and_uncertain_read_effect() {
    let mut input = response(4, 0, &[2, 0, 0, 0, 0, 0, 5, 0]);
    input.extend(response(RECEIVE, 6, &[]));
    let pipe = script(input);
    let observe = pipe.clone();
    observe.0.borrow_mut().read_advance = 20;
    let mut d = Datagram::with_feedback(pipe, peer(), |_| {});
    // FEEDBACK finishes at 50. The following RECEIVE prefix reaches the
    // original deadline at 70; consuming advice must not renew that bound.
    assert_eq!(
        d.receive(&mut [0; crate::datagram::MAX_DATAGRAM], 70),
        Err(Error::Timeout)
    );
    assert!(!d.live());
    assert_eq!(observe.0.borrow().now, 70);
    assert_eq!(observe.0.borrow().input.len(), HEADER);
    let sent = requests(&observe.0.borrow().written);
    assert_eq!(sent.iter().map(|b| b[1]).collect::<Vec<_>>(), [4, RECEIVE]);
    let before = observe.0.borrow().written.len();
    assert!(
        d.receive(&mut [0; crate::datagram::MAX_DATAGRAM], 1000)
            .is_err()
    );
    assert_eq!(observe.0.borrow().written.len(), before);
}
#[test]
fn repeated_advisories_reach_original_resolver_timeout_with_exactly_two_sends() {
    for advice in [
        [2, 0, 0, 0, 0, 0, 5, 0],
        [3, 0, 0, 0, 0, 0, 0, 0],
        [3, 1, 0, 0, 0, 0, 0, 0],
    ] {
        let mut transaction = response(SEND, 0, &[]);
        transaction.extend(response(4, 0, &advice));
        transaction.extend(response(RECEIVE, 6, &[]));
        let mut input = transaction.clone();
        input.extend_from_slice(&transaction);
        // More advice is available, but cannot renew the lookup or authorize
        // a third SEND. Each framed reply has two actual pipe reads.
        input.extend_from_slice(&transaction);
        let pipe = script(input);
        let observe = pipe.clone();
        observe.0.borrow_mut().read_advance = 250;
        let mut resolver =
            crate::dns::Resolver::new(Datagram::with_feedback(pipe, peer(), |_| {}), 0x1234);
        assert_eq!(resolver.lookup("first.example"), Err(Error::Timeout));
        let state = observe.0.borrow();
        assert_eq!(state.now, 3010, "original 10 + 3000 ms deadline");
        let sent = requests(&state.written);
        assert_eq!(
            sent.iter().map(|b| b[1]).collect::<Vec<_>>(),
            [SEND, 4, RECEIVE, SEND, 4, RECEIVE]
        );
        assert_eq!(
            &sent[0][HEADER..],
            &sent[3][HEADER..],
            "retry preserves the exact question and ID"
        );
        assert_eq!(state.input.iter().copied().collect::<Vec<_>>(), transaction);
        let before = state.written.len();
        drop(state);
        assert_eq!(
            resolver.lookup("second.example"),
            Err(Error::Transport(DatagramError::Stale))
        );
        assert_eq!(
            observe.0.borrow().written.len(),
            before,
            "timed-out channel stays retired"
        );
    }
}
#[test]
fn late_previous_query_type_one_can_end_the_next_lookup_on_a_reused_endpoint() {
    let mut input = response(SEND, 0, &[]);
    input.extend(response(4, 6, &[]));
    input.extend(dns_answer(0x1234, b"\x05first\x07example\0"));
    input.extend(response(SEND, 0, &[]));
    // This endpoint diagnostic can quote the earlier successful query. Its
    // eight-byte reply contains no ID with which the adapter could reject it.
    input.extend(response(4, 0, &[1, 4, 0, 0, 0, 0, 0, 0]));
    let second_answer = dns_answer(0x1235, b"\x06second\x07example\0");
    input.extend_from_slice(&second_answer);
    let pipe = script(input);
    let observe = pipe.clone();
    let mut resolver =
        crate::dns::Resolver::new(Datagram::with_feedback(pipe, peer(), |_| {}), 0x1234);
    assert!(resolver.lookup("first.example").is_ok());
    assert_eq!(
        resolver.lookup("second.example"),
        Err(Error::Ipv6Feedback(feedback::Observation {
            kind: 1,
            code: 4,
            detail: 0,
        }))
    );
    let sent = requests(&observe.0.borrow().written);
    assert_eq!(
        sent.iter().map(|b| b[1]).collect::<Vec<_>>(),
        [SEND, 4, RECEIVE, SEND, 4]
    );
    assert_eq!(&sent[0][HEADER..HEADER + 2], &[0x12, 0x34]);
    assert_eq!(&sent[3][HEADER..HEADER + 2], &[0x12, 0x35]);
    assert_eq!(
        observe.0.borrow().input.iter().copied().collect::<Vec<_>>(),
        second_answer
    );
}
#[test]
fn default_constructor_does_not_issue_feedback_and_again_opt_in_continues_to_receive() {
    let pipe = script(response(RECEIVE, 6, &[]));
    let seen = pipe.clone();
    let mut d = Datagram::new(pipe, peer(), |_| {});
    assert_eq!(
        d.receive(&mut [0; crate::datagram::MAX_DATAGRAM], 1000),
        Ok(None)
    );
    assert_eq!(seen.0.borrow().written[3], RECEIVE);
    let mut input = response(4, 6, &[]);
    input.extend(response(RECEIVE, 6, &[]));
    let pipe = script(input);
    let seen = pipe.clone();
    let mut d = Datagram::with_feedback(pipe, peer(), |_| {});
    assert_eq!(
        d.receive(&mut [0; crate::datagram::MAX_DATAGRAM], 1000),
        Ok(None)
    );
    let written = &seen.0.borrow().written;
    assert_eq!(written.len(), 60);
    assert_eq!(written[3], 4);
    assert_eq!(written[33], RECEIVE);
}
#[test]
fn malformed_or_interrupted_feedback_retires_transport_without_retry() {
    for body in [
        vec![1, 4, 0, 0, 0, 0, 0],
        vec![1, 4, 1, 0, 0, 0, 0, 0],
        vec![128, 0, 0, 0, 0, 0, 0, 0],
        vec![2, 0, 0, 0, 0, 0, 0, 0],
        vec![3, 2, 0, 0, 0, 0, 0, 0],
    ] {
        let pipe = script(response(4, 0, &body));
        let seen = pipe.clone();
        let mut d = Datagram::with_feedback(pipe, peer(), |_| {});
        assert_eq!(
            d.receive(&mut [0; crate::datagram::MAX_DATAGRAM], 1000),
            Err(Error::Malformed)
        );
        assert!(!d.live());
        let before = seen.0.borrow().written.len();
        assert!(
            d.receive(&mut [0; crate::datagram::MAX_DATAGRAM], 1000)
                .is_err()
        );
        assert_eq!(seen.0.borrow().written.len(), before);
    }
    let mut bytes = response(4, 0, &[1, 4, 0, 0, 0, 0, 0, 0]);
    bytes.pop();
    let pipe = script(bytes);
    let seen = pipe.clone();
    let mut d = Datagram::with_feedback(pipe, peer(), |_| {});
    assert_eq!(
        d.receive(&mut [0; crate::datagram::MAX_DATAGRAM], 1000),
        Err(Error::Channel(-5))
    );
    assert!(!d.live());
    let n = seen.0.borrow().written.len();
    assert!(
        d.receive(&mut [0; crate::datagram::MAX_DATAGRAM], 1000)
            .is_err()
    );
    assert_eq!(seen.0.borrow().written.len(), n);
}
