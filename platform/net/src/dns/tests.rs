use super::*;
use alloc::{vec, vec::Vec};
use std::collections::VecDeque;

// Independent RFC 1035 fixture construction. No resolver query/name writer is
// used for expected packets. The literal baseline is also checked below.
fn wire(s: &str) -> Vec<u8> {
    let mut b = Vec::new();
    for l in s.split('.') {
        b.push(l.len() as u8);
        b.extend_from_slice(l.as_bytes());
    }
    b.push(0);
    b
}
fn rr(owner: &[u8], kind: u16, data: &[u8]) -> Vec<u8> {
    let mut b = owner.to_vec();
    b.extend_from_slice(&kind.to_be_bytes());
    b.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
    b.extend_from_slice(&(data.len() as u16).to_be_bytes());
    b.extend_from_slice(data);
    b
}
fn reply(id: u16, q: &str, records: Vec<Vec<u8>>) -> Vec<u8> {
    let mut b = vec![
        0x12,
        0x34,
        0x81,
        0x80,
        0,
        1,
        0,
        records.len() as u8,
        0,
        0,
        0,
        0,
    ];
    b[..2].copy_from_slice(&id.to_be_bytes());
    b.extend(wire(q));
    b.extend_from_slice(&[0, 1, 0, 1]);
    for r in records {
        b.extend(r);
    }
    b
}
fn a(id: u16) -> Vec<u8> {
    reply(
        id,
        "www.example",
        vec![rr(&[0xc0, 0x0c], 1, &[192, 0, 2, 9])],
    )
}
struct Fake {
    now: u64,
    replies: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
    fail: Option<Error>,
    pauses: usize,
}
impl Fake {
    fn new(replies: Vec<Vec<u8>>) -> Self {
        Self {
            now: 0,
            replies: replies.into(),
            sent: Vec::new(),
            fail: None,
            pauses: 0,
        }
    }
}
impl Transport for Fake {
    fn now_ms(&self) -> u64 {
        self.now
    }
    fn pause(&mut self, ms: u64) {
        self.now += ms;
        self.pauses += 1;
    }
    fn send(&mut self, b: &[u8], _: u64) -> Result<(), Error> {
        if let Some(e) = self.fail {
            return Err(e);
        }
        self.sent.push(b.to_vec());
        Ok(())
    }
    fn receive(&mut self, b: &mut [u8; d::MAX_DATAGRAM], _: u64) -> Result<Option<usize>, Error> {
        Ok(self.replies.pop_front().map(|p| {
            b[..p.len()].copy_from_slice(&p);
            p.len()
        }))
    }
}
fn parse(p: &[u8]) -> Result<Reply, Error> {
    let q = Name::parse("www.example").unwrap();
    response(p, 0x1234, q, &mut vec![q])
}
fn error(p: &[u8], expected: Error) {
    assert!(matches!(parse(p),Err(e) if e==expected));
}
#[test]
fn golden_a_query_and_response() {
    let literal = vec![
        0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 3, b'w', b'w', b'w', 7, b'e', b'x', b'a',
        b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0,
        2, 9,
    ];
    assert_eq!(a(0x1234), literal);
    let mut r = Resolver::new(Fake::new(vec![literal]), 0x1234);
    let result = r.lookup("WWW.Example.").unwrap();
    assert_eq!(result.count, 1);
    assert_eq!(result.addresses[0], [192, 0, 2, 9]);
    let mut expected = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    expected.extend(wire("www.example"));
    expected.extend_from_slice(&[0, 1, 0, 1]);
    assert_eq!(r.transport.sent, [expected]);
}
#[test]
fn names_and_boundaries() {
    for bad in ["", ".", "x..y", "x..", "a b", "a\\b", "é.example"] {
        assert_eq!(Name::parse(bad), Err(Error::InvalidName));
    }
    assert!(Name::parse(&"x".repeat(63)).is_ok());
    assert_eq!(Name::parse(&"x".repeat(64)), Err(Error::InvalidName));
    let longest = alloc::format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(Name::parse(&longest).unwrap().len, 255);
    assert_eq!(Name::parse(&(longest + "x")), Err(Error::InvalidName));
}
#[test]
fn reordered_cname_and_unrelated_records() {
    let p = reply(
        0x1234,
        "www.example",
        vec![
            rr(&wire("target.example"), 1, &[1, 2, 3, 4]),
            rr(&wire("unrelated.example"), 1, &[9, 9, 9, 9]),
            rr(&[0xc0, 12], 5, &wire("target.example")),
        ],
    );
    match parse(&p).unwrap() {
        Reply::Addresses(a) => {
            assert_eq!(a.count, 1);
            assert_eq!(a.addresses[0], [1, 2, 3, 4]);
            assert_eq!(a.cname_transitions, 1)
        }
        _ => panic!(),
    }
}
#[test]
fn separate_cname_query_and_loop() {
    let first = reply(
        0x1234,
        "www.example",
        vec![rr(&[0xc0, 12], 5, &wire("alias.example"))],
    );
    let second = reply(
        0x1235,
        "alias.example",
        vec![rr(&[0xc0, 12], 1, &[1, 2, 3, 4])],
    );
    let mut r = Resolver::new(Fake::new(vec![first.clone(), second]), 0x1234);
    assert_eq!(r.lookup("www.example").unwrap().cname_transitions, 1);
    assert_eq!(r.transport.sent.len(), 2);
    let second = reply(
        0x1235,
        "alias.example",
        vec![rr(&[0xc0, 12], 5, &wire("www.example"))],
    );
    assert_eq!(
        Resolver::new(Fake::new(vec![first, second]), 0x1234).lookup("www.example"),
        Err(Error::CnameLoop)
    );
}
#[test]
fn cname_depth_and_conflicting_data() {
    let mut records = Vec::new();
    let mut prev = alloc::string::String::from("www.example");
    for i in 0..9 {
        let next = alloc::format!("c{i}.example");
        records.push(rr(&wire(&prev), 5, &wire(&next)));
        prev = next;
    }
    error(&reply(0x1234, "www.example", records), Error::Exhausted);
    error(
        &reply(
            0x1234,
            "www.example",
            vec![
                rr(&[0xc0, 12], 5, &wire("a.example")),
                rr(&[0xc0, 12], 5, &wire("b.example")),
            ],
        ),
        Error::Malformed,
    );
    error(
        &reply(
            0x1234,
            "www.example",
            vec![
                rr(&[0xc0, 12], 5, &wire("a.example")),
                rr(&[0xc0, 12], 1, &[1, 2, 3, 4]),
            ],
        ),
        Error::Malformed,
    );
}
#[test]
fn negative_rcodes_and_truncated_no_partial_success() {
    for (code, e) in [
        (3, Error::NxDomain),
        (5, Error::Refused),
        (2, Error::ServerFailure),
        (1, Error::ResponseCode(1)),
    ] {
        let mut p = reply(0x1234, "www.example", vec![]);
        p[3] = 0x80 | code;
        error(&p, e);
    }
    error(&reply(0x1234, "www.example", vec![]), Error::NoAddress);
    let mut p = a(0x1234);
    p[2] |= 2;
    error(&p, Error::Truncated);
}
#[test]
fn unmatched_id_question_type_and_source_transport_contract() {
    let mut q = a(0x1234);
    q[25] = 28; // question type AAAA
    let packets = vec![
        a(0x9999),
        reply(0x1234, "other.example", vec![]),
        q,
        a(0x1234),
    ];
    let mut r = Resolver::new(Fake::new(packets), 0x1234);
    assert!(r.lookup("www.example").is_ok());
    assert_eq!(r.transport.pauses, 3);
}
#[test]
fn malformed_prefixes_lengths_counts_and_pointers() {
    let p = a(0x1234);
    for end in 2..p.len() {
        assert!(parse(&p[..end]).is_err(), "prefix {end}");
    }
    let mut p = a(0x1234);
    p.push(0);
    error(&p, Error::Malformed);
    for mutation in [0, 1, 2, 3, 4] {
        let mut p = a(0x1234);
        match mutation {
            0 => p[40] = 255,
            1 => {
                p[29] = 0xc0;
                p[30] = 29
            }
            2 => {
                p[29] = 0xc0;
                p[30] = 46
            }
            3 => p[29] = 0x80,
            _ => p[5] = 2,
        };
        error(&p, Error::Malformed);
    }
    let mut p = a(0x1234);
    p[7] = 65;
    error(&p, Error::Exhausted);
    // backward pointer plus a literal cycle, both bounded and rejected
    let mut p = vec![0; 12];
    p.extend_from_slice(&[1, b'a', 0xc0, 12]);
    assert_eq!(name(&p, 12), Err(Error::Malformed));
}
#[test]
fn bounded_address_set_duplicates_and_sections() {
    let records = (0..9)
        .map(|i| rr(&[0xc0, 12], 1, &[192, 0, 2, i]))
        .collect();
    error(&reply(0x1234, "www.example", records), Error::Exhausted);
    match parse(&reply(
        0x1234,
        "www.example",
        vec![rr(&[0xc0, 12], 1, &[1, 2, 3, 4]); 9],
    ))
    .unwrap()
    {
        Reply::Addresses(a) => assert_eq!(a.count, 1),
        _ => panic!(),
    }
    let mut additional = a(0x1234);
    additional[7] = 0;
    additional[11] = 1;
    error(&additional, Error::NoAddress);
}
#[test]
fn deadline_retry_and_late_responses() {
    let mut r = Resolver::new(Fake::new(vec![]), 0x1234);
    assert_eq!(r.lookup("www.example"), Err(Error::Timeout));
    assert_eq!(r.transport.now, LOOKUP_MS);
    assert_eq!(r.transport.sent.len(), 2);
    assert_eq!(r.transport.sent[0], r.transport.sent[1]);
    assert_eq!(r.transport.pauses, 600);
    assert_eq!(
        r.lookup("www.example"),
        Err(Error::Transport(d::Error::Stale))
    );
    // A fresh owner-issued transport is required; stale IDs still do not match.
    let mut r = Resolver::new(Fake::new(vec![a(0x1234), a(0x1235)]), 0x1235);
    assert!(r.lookup("www.example").is_ok());
    assert_eq!(r.transport.sent.last().unwrap()[..2], [0x12, 0x35]);
}
#[test]
fn id_exhaustion_and_transport_errors() {
    let mut r = Resolver::new(Fake::new(vec![a(0x1234)]), 0x1234);
    r.issued = 65536;
    assert_eq!(r.lookup("www.example"), Err(Error::Exhausted));
    assert!(r.transport.sent.is_empty());
    for e in [
        d::Error::Exhausted,
        d::Error::Denied,
        d::Error::LinkDown,
        d::Error::DeviceFailed,
        d::Error::LinkUnknown,
        d::Error::Stale,
    ] {
        let mut f = Fake::new(vec![]);
        f.fail = Some(Error::Transport(e));
        assert_eq!(
            Resolver::new(f, 7).lookup("www.example"),
            Err(Error::Transport(e))
        );
    }
    let mut r = Resolver::new(Fake::new(vec![]), 65535);
    assert_eq!(r.id(), Ok(65535));
    assert_eq!(r.id(), Ok(0));
    r.issued = 65535;
    assert_eq!(r.id(), Ok(65534));
    assert_eq!(r.id(), Err(Error::Exhausted));
}
#[test]
fn every_single_byte_mutation_is_bounded() {
    let original = a(0x1234);
    for at in 0..original.len() {
        for byte in 0..=255 {
            let mut p = original.clone();
            p[at] = byte;
            let _ = parse(&p);
        }
    }
}

// The adapter is checked separately from parser fixtures: framed pipe bytes
// must keep exact-peer authority and must become unusable after interruption.
struct ScriptPipe {
    input: VecDeque<u8>,
    output: Vec<u8>,
    now: u64,
    broken: bool,
}
impl ScriptPipe {
    fn new(body: &[u8]) -> Self {
        let mut input = VecDeque::from((body.len() as u16).to_be_bytes().to_vec());
        input.extend(body);
        Self {
            input,
            output: Vec::new(),
            now: 0,
            broken: false,
        }
    }
}
impl Pipe for ScriptPipe {
    fn now_ms(&self) -> u64 {
        self.now
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        self.now += 1;
        if self.broken {
            return Err(-5);
        }
        let n = b.len().min(self.input.len());
        for byte in &mut b[..n] {
            *byte = self.input.pop_front().unwrap()
        }
        Ok(Some(n))
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        self.now += 1;
        self.output.extend(b);
        Ok(Some(b.len()))
    }
}
fn pause_unused(_: u64) {}
#[test]
fn pipe_adapter_checks_peer_boundaries_and_send_frame() {
    let peer = Address {
        ip: [192, 0, 2, 53],
        port: 53,
    };
    let mut reply = vec![1, d::RECEIVE, 0, 0, 192, 0, 2, 53, 0, 53, 0, 3, 1, 2, 3];
    let mut transport = Datagram::new(ScriptPipe::new(&reply), peer, pause_unused);
    let mut bytes = [0; d::MAX_DATAGRAM];
    assert_eq!(transport.receive(&mut bytes, 100), Ok(Some(3)));
    assert_eq!(&bytes[..3], &[1, 2, 3]);
    reply[7] = 54;
    let mut transport = Datagram::new(ScriptPipe::new(&reply), peer, pause_unused);
    assert_eq!(transport.receive(&mut bytes, 100), Err(Error::Malformed));
    assert_eq!(
        transport.send(b"x", 100),
        Err(Error::Transport(d::Error::Stale))
    );
    let mut transport = Datagram::new(
        ScriptPipe::new(&[1, d::SEND, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        peer,
        pause_unused,
    );
    assert_eq!(transport.send(b"abc", 100), Ok(()));
    assert_eq!(
        &transport.pipe.output,
        &[
            0, 15, 1, 1, 0, 0, 192, 0, 2, 53, 0, 53, 0, 3, b'a', b'b', b'c'
        ]
    );
}
#[test]
fn interrupted_pipe_is_never_resent_and_again_is_not_terminal() {
    let peer = Address {
        ip: [192, 0, 2, 53],
        port: 53,
    };
    let mut p = ScriptPipe::new(&[]);
    p.broken = true;
    let mut transport = Datagram::new(p, peer, pause_unused);
    assert_eq!(transport.send(b"query", 100), Err(Error::Channel(-5)));
    let sent = transport.pipe.output.len();
    assert_eq!(
        transport.send(b"query", 100),
        Err(Error::Transport(d::Error::Stale))
    );
    assert_eq!(transport.pipe.output.len(), sent);
    let mut transport = Datagram::new(
        ScriptPipe::new(&[1, d::RECEIVE, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        peer,
        pause_unused,
    );
    assert_eq!(transport.receive(&mut [0; d::MAX_DATAGRAM], 100), Ok(None));
    assert!(transport.live);
}

#[test]
fn native_icmp_status_reaches_dns_without_retry_or_tcp_authority() {
    let peer = Address {
        ip: [192, 0, 2, 53],
        port: 53,
    };
    for (status, detail, expected) in [
        (
            12,
            3,
            d::Error::Icmp(crate::icmp::Error::DestinationUnreachable { code: 3 }),
        ),
        (
            13,
            0,
            d::Error::Icmp(crate::icmp::Error::TimeExceeded { code: 0 }),
        ),
        (
            14,
            576,
            d::Error::Icmp(crate::icmp::Error::FragmentationNeeded { mtu: 576 }),
        ),
    ] {
        let mut p = ScriptPipe::new(&[1, d::SEND, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut response = [1, d::RECEIVE, status, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        response[10..12].copy_from_slice(&(detail as u16).to_be_bytes());
        p.input.extend([0, 12]);
        p.input.extend(response);
        let mut resolver = Resolver::new(Datagram::new(p, peer, pause_unused), 0x1234);
        assert_eq!(
            resolver.lookup("www.example"),
            Err(Error::Transport(expected))
        );
        assert!(resolver.transport.pipe.input.is_empty());
        assert!(resolver.transport.now_ms() < LOOKUP_MS);
        assert_eq!(resolver.transport.pipe.output.len(), 14 + 29 + 14);
    }
    for (status, detail) in [
        (12, 4),
        (12, 16),
        (13, 2),
        (14, 575),
        (14, 1500),
        (15, 547),
        (15, 548), // PathMtu is a SEND refusal, never a RECEIVE result.
        (15, 1472),
    ] {
        let mut body = [1, d::RECEIVE, status, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        body[10..12].copy_from_slice(&(detail as u16).to_be_bytes());
        let mut transport = Datagram::new(ScriptPipe::new(&body), peer, pause_unused);
        assert_eq!(
            transport.receive(&mut [0; d::MAX_DATAGRAM], 100),
            Err(Error::Malformed)
        );
        assert!(!transport.live);
    }
}

#[test]
fn dns_send_decodes_ceiling_and_refuses_old_icmp_without_retry() {
    let peer = Address {
        ip: [192, 0, 2, 53],
        port: 53,
    };
    let mut status = [1, d::SEND, 15, 0, 0, 0, 0, 0, 0, 0, 2, 36];
    let mut raw = Datagram::new(ScriptPipe::new(&status), peer, pause_unused);
    assert_eq!(
        raw.call(d::SEND, &[42; 549], 100, &mut [0; d::MAX_MESSAGE]),
        Err(Error::Transport(d::Error::PathMtu { maximum: 548 }))
    );
    let mut transport = Datagram::new(ScriptPipe::new(&status), peer, pause_unused);
    assert_eq!(transport.send(&[42; 549], 100), Err(Error::TooLarge));
    let mut malformed = Datagram::new(ScriptPipe::new(&status), peer, pause_unused);
    assert_eq!(malformed.send(b"query", 100), Err(Error::Malformed));
    // An asynchronous old ICMP can refuse this SEND. Its reply establishes
    // local non-enqueue, not an uncertain framed-write outcome. No retry.
    status[2] = 12;
    status[10..12].copy_from_slice(&3u16.to_be_bytes());
    let mut resolver = Resolver::new(
        Datagram::new(ScriptPipe::new(&status), peer, pause_unused),
        0x1234,
    );
    assert_eq!(
        resolver.lookup("www.example"),
        Err(Error::Transport(d::Error::Icmp(
            crate::icmp::Error::DestinationUnreachable { code: 3 }
        )))
    );
    assert_eq!(resolver.transport.pipe.output.len(), 14 + 29);
    assert!(resolver.transport.pipe.input.is_empty());
}

#[test]
fn entropy_seed_is_used_and_provider_failure_never_submits_a_query() {
    let transport = Fake::new(vec![a(0xbeef)]);
    let mut resolver = Resolver::with_entropy(transport, |bytes| {
        assert_eq!(bytes.len(), 2);
        bytes.copy_from_slice(&[0xbe, 0xef]);
        Ok::<(), i64>(())
    })
    .unwrap();
    assert!(resolver.lookup("www.example").is_ok());
    assert_eq!(&resolver.transport.sent[0][..2], &[0xbe, 0xef]);
    // A provider's failure propagates exactly; no time/boot-ID/static seed
    // fallback can yield a resolver after it.
    struct NoQueries(std::rc::Rc<core::cell::Cell<usize>>);
    impl Transport for NoQueries {
        fn now_ms(&self) -> u64 {
            0
        }
        fn pause(&mut self, _: u64) {}
        fn send(&mut self, _: &[u8], _: u64) -> Result<(), Error> {
            self.0.set(self.0.get() + 1);
            Ok(())
        }
        fn receive(
            &mut self,
            _: &mut [u8; d::MAX_DATAGRAM],
            _: u64,
        ) -> Result<Option<usize>, Error> {
            self.0.set(self.0.get() + 1);
            Ok(None)
        }
    }
    let calls = std::rc::Rc::new(core::cell::Cell::new(0));
    assert!(matches!(
        Resolver::with_entropy(NoQueries(calls.clone()), |_| Err::<(), i64>(-38)),
        Err(-38)
    ));
    assert_eq!(calls.get(), 0);
}
#[test]
fn exactly_eight_cname_transitions_succeed() {
    let mut records = Vec::new();
    let mut prev = alloc::string::String::from("www.example");
    for i in 0..8 {
        let next = alloc::format!("c{i}.example");
        records.push(rr(&wire(&prev), 5, &wire(&next)));
        prev = next;
    }
    records.push(rr(&wire(&prev), 1, &[1, 2, 3, 4]));
    match parse(&reply(0x1234, "www.example", records)).unwrap() {
        Reply::Addresses(a) => assert_eq!(a.cname_transitions, 8),
        _ => panic!(),
    }
}
#[test]
fn all_ids_are_unique_and_exhaustion_refuses_wrap_reuse() {
    let mut resolver = Resolver::new(Fake::new(vec![]), 49157);
    let mut seen = [false; 65536];
    for _ in 0..65536 {
        let id = resolver.id().unwrap() as usize;
        assert!(!seen[id]);
        seen[id] = true;
    }
    assert!(seen.into_iter().all(|v| v));
    assert_eq!(resolver.id(), Err(Error::Exhausted));
}

#[test]
fn parsing_time_cannot_turn_a_late_answer_into_success() {
    struct Clocked {
        inner: Fake,
        reads: core::cell::Cell<usize>,
        times: [u64; 4],
    }
    impl Transport for Clocked {
        fn now_ms(&self) -> u64 {
            let at = self.reads.get();
            self.reads.set(at + 1);
            self.times[at.min(3)]
        }
        fn pause(&mut self, ms: u64) {
            self.inner.pause(ms)
        }
        fn send(&mut self, b: &[u8], deadline: u64) -> Result<(), Error> {
            self.inner.send(b, deadline)
        }
        fn receive(
            &mut self,
            b: &mut [u8; d::MAX_DATAGRAM],
            deadline: u64,
        ) -> Result<Option<usize>, Error> {
            self.inner.receive(b, deadline)
        }
    }
    for (times, expected) in [
        ([0, 1, 2, 3000], Error::Timeout),
        ([0, 1, 2, 1], Error::Clock),
    ] {
        let transport = Clocked {
            inner: Fake::new(vec![a(0x1234)]),
            reads: core::cell::Cell::new(0),
            times,
        };
        assert_eq!(
            Resolver::new(transport, 0x1234).lookup("www.example"),
            Err(expected)
        );
    }
}

#[test]
fn rpc_deadline_expiry_is_timeout_and_stream_never_revives() {
    struct Expiring {
        now: u64,
        expires: u64,
    }
    impl Pipe for Expiring {
        fn now_ms(&self) -> u64 {
            self.now
        }
        fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
            Ok(Some(b.len()))
        }
        fn read(&mut self, _: &mut [u8]) -> Result<Option<usize>, i64> {
            self.now = self.expires;
            Err(-110)
        }
    }
    for (expires, expected) in [(100, Error::Timeout), (30, Error::Channel(-110))] {
        let mut transport = Datagram::new(
            Expiring { now: 0, expires },
            Address {
                ip: [192, 0, 2, 53],
                port: 53,
            },
            pause_unused,
        );
        assert_eq!(
            transport.receive(&mut [0; d::MAX_DATAGRAM], 100),
            Err(expected)
        );
        assert_eq!(
            transport.send(b"query", 200),
            Err(Error::Transport(d::Error::Stale))
        );
    }
}

#[test]
fn opted_in_tcp_fallback_reuses_question_id_and_absolute_deadline() {
    struct Fallback {
        udp: Fake,
        tcp: Vec<u8>,
        calls: usize,
        deadline: u64,
    }
    impl Transport for Fallback {
        fn now_ms(&self) -> u64 {
            self.udp.now_ms()
        }
        fn pause(&mut self, n: u64) {
            self.udp.pause(n)
        }
        fn send(&mut self, b: &[u8], d: u64) -> Result<(), Error> {
            self.udp.send(b, d)
        }
        fn receive(
            &mut self,
            b: &mut [u8; d::MAX_DATAGRAM],
            d: u64,
        ) -> Result<Option<usize>, Error> {
            self.udp.receive(b, d)
        }
        fn tcp(
            &mut self,
            q: &[u8],
            b: &mut [u8; MAX_TCP_RESPONSE],
            deadline: u64,
        ) -> Result<usize, Error> {
            self.calls += 1;
            self.deadline = deadline;
            assert_eq!(&q[..2], &[0x12, 0x34]);
            b[..self.tcp.len()].copy_from_slice(&self.tcp);
            Ok(self.tcp.len())
        }
    }
    let mut truncated = a(0x1234);
    truncated[2] |= 2;
    let mut resolver = Resolver::new(
        Fallback {
            udp: Fake::new(vec![truncated]),
            tcp: a(0x1234),
            calls: 0,
            deadline: 0,
        },
        0x1234,
    );
    assert_eq!(
        resolver.lookup("www.example").unwrap().addresses[0],
        [192, 0, 2, 9]
    );
    assert_eq!(resolver.transport.calls, 1);
    assert_eq!(resolver.transport.deadline, LOOKUP_MS);
    assert_eq!(resolver.transport.udp.sent.len(), 1);
}

const IPV6_ADDRESS: [u8; 16] = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];

fn aaaa_reply(id: u16, question: &str, records: Vec<Vec<u8>>) -> Vec<u8> {
    let mut packet = reply(id, question, records);
    let at = 12 + wire(question).len();
    packet[at..at + 2].copy_from_slice(&28u16.to_be_bytes());
    packet
}
fn aaaa(id: u16) -> Vec<u8> {
    aaaa_reply(id, "www.example", vec![rr(&[0xc0, 12], 28, &IPV6_ADDRESS)])
}
fn parse_aaaa(packet: &[u8]) -> Result<Reply<16>, Error> {
    let question = Name::parse("www.example").unwrap();
    response(packet, 0x1234, question, &mut vec![question])
}
fn aaaa_error(packet: &[u8], expected: Error) {
    assert!(matches!(parse_aaaa(packet), Err(error) if error == expected));
}

#[test]
fn golden_aaaa_query_and_response_preserve_a_entrypoint() {
    // Literal RFC 3596 AAAA RDATA and independently written question bytes.
    let literal = vec![
        0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 3, b'w', b'w', b'w', 7, b'e', b'x', b'a',
        b'm', b'p', b'l', b'e', 0, 0, 28, 0, 1, 0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16, 0x20, 1,
        0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
    ];
    assert_eq!(aaaa(0x1234), literal);
    let mut resolver = Resolver::new(Fake::new(vec![literal, a(0x1235)]), 0x1234);
    let answer: AnswerV6 = resolver.lookup_aaaa("WWW.Example.").unwrap();
    assert_eq!(answer.addresses[0], IPV6_ADDRESS);
    assert_eq!((answer.count, answer.cname_transitions), (1, 0));
    assert_eq!(answer.addresses[1..], [[0; 16]; MAX_ADDRESSES - 1]);
    let expected = vec![
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm',
        b'p', b'l', b'e', 0, 0, 28, 0, 1,
    ];
    assert_eq!(resolver.transport.sent, [expected]);
    let answer: Answer = resolver.lookup("www.example").unwrap();
    assert_eq!(answer.addresses[0], [192, 0, 2, 9]);
    assert_eq!(&resolver.transport.sent[1][..2], &[0x12, 0x35]);
    assert_eq!(&resolver.transport.sent[1][25..29], &[0, 1, 0, 1]);
}

#[test]
fn aaaa_ignores_unmatched_id_question_type_and_class() {
    let wrong_type = a(0x1234);
    let wrong_name = aaaa_reply(0x1234, "other.example", vec![]);
    let mut wrong_class = aaaa(0x1234);
    wrong_class[28] = 3;
    let packets = vec![
        aaaa(0x9999),
        wrong_type,
        wrong_name,
        wrong_class,
        aaaa(0x1234),
    ];
    let mut resolver = Resolver::new(Fake::new(packets), 0x1234);
    assert_eq!(
        resolver.lookup_aaaa("www.example").unwrap().addresses[0],
        IPV6_ADDRESS
    );
    assert_eq!(resolver.transport.pauses, 4);
    assert_eq!(resolver.transport.sent.len(), 1);
}

#[test]
fn address_families_do_not_satisfy_each_others_questions() {
    let only_v4 = aaaa_reply(
        0x1234,
        "www.example",
        vec![rr(&[0xc0, 12], 1, &[192, 0, 2, 9])],
    );
    let only_v6 = reply(
        0x1234,
        "www.example",
        vec![rr(&[0xc0, 12], 28, &IPV6_ADDRESS)],
    );
    aaaa_error(&only_v4, Error::NoAddress);
    error(&only_v6, Error::NoAddress);
    let mixed = vec![
        rr(&[0xc0, 12], 1, &[192, 0, 2, 9]),
        rr(&[0xc0, 12], 28, &IPV6_ADDRESS),
    ];
    match parse_aaaa(&aaaa_reply(0x1234, "www.example", mixed.clone())).unwrap() {
        Reply::Addresses(answer) => {
            assert_eq!(answer.count, 1);
            assert_eq!(answer.addresses[0], IPV6_ADDRESS);
        }
        _ => panic!(),
    }
    match parse(&reply(0x1234, "www.example", mixed)).unwrap() {
        Reply::Addresses(answer) => {
            assert_eq!(answer.count, 1);
            assert_eq!(answer.addresses[0], [192, 0, 2, 9]);
        }
        _ => panic!(),
    }
}

#[test]
fn aaaa_reordered_cname_chain_uses_only_final_owner_answer_section() {
    let packet = aaaa_reply(
        0x1234,
        "www.example",
        vec![
            rr(&wire("target.example"), 28, &IPV6_ADDRESS),
            rr(&wire("unrelated.example"), 28, &[1; 16]),
            rr(&wire("alias.example"), 5, &wire("target.example")),
            rr(&[0xc0, 12], 5, &wire("alias.example")),
            rr(&wire("target.example"), 1, &[192, 0, 2, 9]),
        ],
    );
    match parse_aaaa(&packet).unwrap() {
        Reply::Addresses(answer) => {
            assert_eq!((answer.count, answer.cname_transitions), (1, 2));
            assert_eq!(answer.addresses[0], IPV6_ADDRESS);
        }
        _ => panic!(),
    }
    let mut additional = aaaa(0x1234);
    additional[7] = 0;
    additional[11] = 1;
    aaaa_error(&additional, Error::NoAddress);
    let mut authority = aaaa(0x1234);
    authority[7] = 0;
    authority[9] = 1;
    aaaa_error(&authority, Error::NoAddress);
}

#[test]
fn aaaa_separate_cname_query_preserves_type_and_detects_loop() {
    let first = aaaa_reply(
        0x1234,
        "www.example",
        vec![rr(&[0xc0, 12], 5, &wire("alias.example"))],
    );
    let second = aaaa_reply(
        0x1235,
        "alias.example",
        vec![rr(&[0xc0, 12], 28, &IPV6_ADDRESS)],
    );
    let mut resolver = Resolver::new(Fake::new(vec![first.clone(), second]), 0x1234);
    assert_eq!(
        resolver
            .lookup_aaaa("www.example")
            .unwrap()
            .cname_transitions,
        1
    );
    assert_eq!(resolver.transport.sent.len(), 2);
    let mut expected = vec![0x12, 0x35, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    expected.extend_from_slice(&[
        5, b'a', b'l', b'i', b'a', b's', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 28, 0,
        1,
    ]);
    assert_eq!(resolver.transport.sent[1], expected);
    let looped = aaaa_reply(
        0x1235,
        "alias.example",
        vec![rr(&[0xc0, 12], 5, &wire("www.example"))],
    );
    assert_eq!(
        Resolver::new(Fake::new(vec![first, looped]), 0x1234).lookup_aaaa("www.example"),
        Err(Error::CnameLoop),
    );
}

#[test]
fn cname_refuses_address_conflicts_in_either_family() {
    for address in [
        rr(&[0xc0, 12], 1, &[192, 0, 2, 9]),
        rr(&[0xc0, 12], 28, &IPV6_ADDRESS),
    ] {
        let records = vec![rr(&[0xc0, 12], 5, &wire("alias.example")), address];
        error(
            &reply(0x1234, "www.example", records.clone()),
            Error::Malformed,
        );
        aaaa_error(
            &aaaa_reply(0x1234, "www.example", records),
            Error::Malformed,
        );
    }
    aaaa_error(
        &aaaa_reply(
            0x1234,
            "www.example",
            vec![
                rr(&[0xc0, 12], 5, &wire("a.example")),
                rr(&[0xc0, 12], 5, &wire("b.example")),
            ],
        ),
        Error::Malformed,
    );
}

#[test]
fn aaaa_address_and_cname_bounds_remain_independent() {
    let addresses: Vec<_> = (0..9)
        .map(|i| {
            let mut address = IPV6_ADDRESS;
            address[15] = i;
            rr(&[0xc0, 12], 28, &address)
        })
        .collect();
    aaaa_error(
        &aaaa_reply(0x1234, "www.example", addresses),
        Error::Exhausted,
    );
    match parse_aaaa(&aaaa_reply(
        0x1234,
        "www.example",
        vec![rr(&[0xc0, 12], 28, &IPV6_ADDRESS); 9],
    ))
    .unwrap()
    {
        Reply::Addresses(answer) => assert_eq!(answer.count, 1),
        _ => panic!(),
    }
    for count in [8, 9] {
        let mut records = Vec::new();
        let mut previous = alloc::string::String::from("www.example");
        for i in 0..count {
            let next = alloc::format!("v{i}.example");
            records.push(rr(&wire(&previous), 5, &wire(&next)));
            previous = next;
        }
        records.push(rr(&wire(&previous), 28, &IPV6_ADDRESS));
        let packet = aaaa_reply(0x1234, "www.example", records);
        if count == 8 {
            match parse_aaaa(&packet).unwrap() {
                Reply::Addresses(answer) => assert_eq!(answer.cname_transitions, 8),
                _ => panic!(),
            }
        } else {
            aaaa_error(&packet, Error::Exhausted);
        }
    }
    let mut count = aaaa(0x1234);
    count[7] = 65;
    aaaa_error(&count, Error::Exhausted);
}

#[test]
fn malformed_aaaa_lengths_prefixes_and_trailing_bytes_refuse() {
    let original = aaaa(0x1234);
    for end in 2..original.len() {
        assert!(parse_aaaa(&original[..end]).is_err(), "prefix {end}");
    }
    let mut trailing = original;
    trailing.push(0);
    aaaa_error(&trailing, Error::Malformed);
    for length in [0, 4, 15, 17] {
        let data = vec![0; length];
        let records = vec![rr(&[0xc0, 12], 28, &data)];
        aaaa_error(
            &aaaa_reply(0x1234, "www.example", records.clone()),
            Error::Malformed,
        );
        // A lookups validate malformed known records too; no partial success.
        let mut records = records;
        records.push(rr(&[0xc0, 12], 1, &[192, 0, 2, 9]));
        error(&reply(0x1234, "www.example", records), Error::Malformed);
    }
}

struct AaaaFallback {
    udp: Fake,
    reply: Vec<u8>,
    queries: Vec<Vec<u8>>,
    deadline: u64,
}
impl Transport for AaaaFallback {
    fn now_ms(&self) -> u64 {
        self.udp.now_ms()
    }
    fn pause(&mut self, n: u64) {
        self.udp.pause(n)
    }
    fn send(&mut self, bytes: &[u8], deadline: u64) -> Result<(), Error> {
        self.udp.send(bytes, deadline)
    }
    fn receive(
        &mut self,
        bytes: &mut [u8; d::MAX_DATAGRAM],
        deadline: u64,
    ) -> Result<Option<usize>, Error> {
        self.udp.receive(bytes, deadline)
    }
    fn tcp(
        &mut self,
        query: &[u8],
        bytes: &mut [u8; MAX_TCP_RESPONSE],
        deadline: u64,
    ) -> Result<usize, Error> {
        self.queries.push(query.to_vec());
        self.deadline = deadline;
        bytes[..self.reply.len()].copy_from_slice(&self.reply);
        Ok(self.reply.len())
    }
}

#[test]
fn aaaa_tcp_fallback_is_explicit_same_query_and_deadline() {
    let mut truncated = aaaa(0x1234);
    truncated[2] |= 2;
    assert_eq!(
        Resolver::new(Fake::new(vec![truncated.clone()]), 0x1234).lookup_aaaa("www.example"),
        Err(Error::Truncated),
    );
    let mut resolver = Resolver::new(
        AaaaFallback {
            udp: Fake::new(vec![truncated]),
            reply: aaaa(0x1234),
            queries: Vec::new(),
            deadline: 0,
        },
        0x1234,
    );
    assert_eq!(
        resolver.lookup_aaaa("www.example").unwrap().addresses[0],
        IPV6_ADDRESS
    );
    assert_eq!(resolver.transport.queries, resolver.transport.udp.sent);
    assert_eq!(resolver.transport.queries.len(), 1);
    assert_eq!(&resolver.transport.queries[0][25..29], &[0, 28, 0, 1]);
    assert_eq!(resolver.transport.deadline, LOOKUP_MS);
    assert_eq!(resolver.transport.udp.now, 0);
}

#[test]
fn aaaa_tcp_refuses_wrong_question_family_and_second_truncation() {
    let mut truncated = aaaa(0x1234);
    truncated[2] |= 2;
    let no_address = aaaa_reply(
        0x1234,
        "www.example",
        vec![rr(&[0xc0, 12], 1, &[192, 0, 2, 9])],
    );
    for (reply, expected) in [
        (a(0x1234), Error::Malformed),
        (aaaa(0x9999), Error::Malformed),
        (
            aaaa_reply(0x1234, "other.example", vec![]),
            Error::Malformed,
        ),
        (no_address, Error::NoAddress),
        (truncated.clone(), Error::Truncated),
    ] {
        let mut resolver = Resolver::new(
            AaaaFallback {
                udp: Fake::new(vec![truncated.clone()]),
                reply,
                queries: Vec::new(),
                deadline: 0,
            },
            0x1234,
        );
        assert_eq!(resolver.lookup_aaaa("www.example"), Err(expected));
        assert_eq!(resolver.transport.queries.len(), 1);
        assert_eq!(resolver.transport.udp.sent.len(), 1);
    }
}

#[test]
fn aaaa_timeout_and_id_exhaustion_apply_across_both_entrypoints() {
    let mut resolver = Resolver::new(Fake::new(vec![]), 0x1234);
    assert_eq!(resolver.lookup_aaaa("www.example"), Err(Error::Timeout));
    assert_eq!(resolver.transport.sent.len(), 2);
    assert_eq!(resolver.transport.sent[0], resolver.transport.sent[1]);
    assert_eq!(resolver.transport.now, LOOKUP_MS);
    assert_eq!(
        resolver.lookup("www.example"),
        Err(Error::Transport(d::Error::Stale))
    );
    assert_eq!(
        resolver.lookup_aaaa("www.example"),
        Err(Error::Transport(d::Error::Stale))
    );
    assert_eq!(resolver.transport.sent.len(), 2);
    let mut resolver = Resolver::new(Fake::new(vec![]), 0x1234);
    resolver.issued = 65536;
    assert_eq!(resolver.lookup_aaaa("www.example"), Err(Error::Exhausted));
    assert!(resolver.transport.sent.is_empty());
}

#[test]
fn aaaa_native_denial_exhaustion_and_interruption_issue_no_fallback() {
    let peer = Address {
        ip: [192, 0, 2, 53],
        port: 53,
    };
    for (status, error) in [(2, d::Error::Denied), (4, d::Error::Exhausted)] {
        let bytes = [1, d::SEND, status, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut resolver = Resolver::new(
            Datagram::new(ScriptPipe::new(&bytes), peer, pause_unused),
            0x1234,
        );
        assert_eq!(
            resolver.lookup_aaaa("www.example"),
            Err(Error::Transport(error))
        );
        assert_eq!(resolver.transport.pipe.output.len(), 14 + 29);
        assert!(resolver.transport.pipe.input.is_empty());
    }
    let mut pipe = ScriptPipe::new(&[]);
    pipe.broken = true;
    let mut resolver = Resolver::new(Datagram::new(pipe, peer, pause_unused), 0x1234);
    assert_eq!(resolver.lookup_aaaa("www.example"), Err(Error::Channel(-5)));
    let sent = resolver.transport.pipe.output.len();
    assert_eq!(
        resolver.lookup("www.example"),
        Err(Error::Transport(d::Error::Stale))
    );
    assert_eq!(resolver.transport.pipe.output.len(), sent);
}

#[test]
fn aaaa_single_byte_mutations_are_bounded() {
    let original = aaaa(0x1234);
    for at in 0..original.len() {
        for byte in 0..=255 {
            let mut packet = original.clone();
            packet[at] = byte;
            let _ = parse_aaaa(&packet);
        }
    }
}

#[test]
fn paired_tcp_adapter_preserves_query_family_and_ignores_other_family_frames() {
    use alloc::rc::Rc;
    use core::cell::RefCell;
    struct SharedScript(Rc<RefCell<ScriptPipe>>);
    impl Pipe for SharedScript {
        fn now_ms(&self) -> u64 {
            self.0.borrow().now_ms()
        }
        fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
            self.0.borrow_mut().read(bytes)
        }
        fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
            self.0.borrow_mut().write(bytes)
        }
    }
    fn frame(pipe: &mut ScriptPipe, op: u8, amount: usize, data: &[u8]) {
        let mut body = vec![1, op, 0, 0, 192, 0, 2, 53, 0, 53];
        body.extend_from_slice(&(amount as u16).to_be_bytes());
        body.extend_from_slice(data);
        pipe.input.extend((body.len() as u16).to_be_bytes());
        pipe.input.extend(body);
    }
    for ipv6 in [false, true] {
        let (answer, unrelated) = if ipv6 {
            (aaaa(0x1234), a(0x1234))
        } else {
            (a(0x1234), aaaa(0x1234))
        };
        let mut truncated = answer.clone();
        truncated[2] |= 2;
        let mut pipe = ScriptPipe::new(&[1, d::SEND, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        frame(&mut pipe, d::RECEIVE, truncated.len(), &truncated);
        frame(&mut pipe, crate::stream::CONNECT, 1, &[1]);
        frame(&mut pipe, crate::stream::WRITE, 2, &[]);
        frame(&mut pipe, crate::stream::WRITE, 29, &[]);
        for packet in [unrelated, answer] {
            frame(
                &mut pipe,
                crate::stream::READ,
                2,
                &(packet.len() as u16).to_be_bytes(),
            );
            frame(&mut pipe, crate::stream::READ, packet.len(), &packet);
        }
        let state = Rc::new(RefCell::new(pipe));
        let transport = tcp::DatagramTcp::new(
            SharedScript(state.clone()),
            Address {
                ip: [192, 0, 2, 53],
                port: 53,
            },
            pause_unused,
        );
        let mut resolver = Resolver::new(transport, 0x1234);
        if ipv6 {
            assert_eq!(
                resolver.lookup_aaaa("www.example").unwrap().addresses[0],
                IPV6_ADDRESS
            );
        } else {
            assert_eq!(
                resolver.lookup("www.example").unwrap().addresses[0],
                [192, 0, 2, 9]
            );
        }
        let state = state.borrow();
        assert!(state.input.is_empty());
        let mut at = 0;
        let mut operations = Vec::new();
        while at < state.output.len() {
            let length = u16::from_be_bytes([state.output[at], state.output[at + 1]]) as usize;
            operations.push(state.output[at + 3]);
            at += 2 + length;
        }
        assert_eq!(
            operations,
            [
                d::SEND,
                d::RECEIVE,
                crate::stream::CONNECT,
                crate::stream::WRITE,
                crate::stream::WRITE,
                crate::stream::READ,
                crate::stream::READ,
                crate::stream::READ,
                crate::stream::READ
            ]
        );
    }
}

#[test]
fn paired_tcp_adapter_refuses_unsupported_or_malformed_queries_before_io() {
    use alloc::rc::Rc;
    use core::cell::Cell;
    struct NoIo(Rc<Cell<usize>>);
    impl Pipe for NoIo {
        fn now_ms(&self) -> u64 {
            0
        }
        fn read(&mut self, _: &mut [u8]) -> Result<Option<usize>, i64> {
            self.0.set(self.0.get() + 1);
            Err(-5)
        }
        fn write(&mut self, _: &[u8]) -> Result<Option<usize>, i64> {
            self.0.set(self.0.get() + 1);
            Err(-5)
        }
    }
    let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend(wire("www.example"));
    query.extend_from_slice(&[0, 28, 0, 1]);
    for case in 0..6 {
        let mut bad = query.clone();
        match case {
            0 => bad[26] = 15,
            1 => bad[28] = 3,
            2 => {
                bad.pop();
            }
            3 => bad.push(0),
            4 => bad[2] = 0x81,
            _ => bad[7] = 1,
        }
        let calls = Rc::new(Cell::new(0));
        let mut transport = tcp::DatagramTcp::new(
            NoIo(calls.clone()),
            Address {
                ip: [192, 0, 2, 53],
                port: 53,
            },
            pause_unused,
        );
        assert_eq!(
            transport.tcp(&bad, &mut [0; MAX_TCP_RESPONSE], 100),
            Err(Error::Malformed)
        );
        assert_eq!(calls.get(), 0);
    }
}

#[test]
fn interrupted_udp_transaction_fences_the_entire_paired_channel() {
    use alloc::rc::Rc;
    use core::cell::RefCell;
    struct SharedScript(Rc<RefCell<ScriptPipe>>);
    impl Pipe for SharedScript {
        fn now_ms(&self) -> u64 {
            self.0.borrow().now_ms()
        }
        fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
            self.0.borrow_mut().read(bytes)
        }
        fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
            self.0.borrow_mut().write(bytes)
        }
    }
    let peer = Address {
        ip: [192, 0, 2, 53],
        port: 53,
    };
    let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend(wire("www.example"));
    query.extend_from_slice(&[0, 28, 0, 1]);
    for receive_first in [false, true] {
        let mut pipe = ScriptPipe::new(&[]);
        // Request writes succeed, then reply reading fails. In the SEND
        // branch the remote enqueue outcome is therefore unknown.
        pipe.broken = true;
        let shared = Rc::new(RefCell::new(pipe));
        let mut transport = tcp::DatagramTcp::new(SharedScript(shared.clone()), peer, pause_unused);
        let interrupted = if receive_first {
            transport
                .receive(&mut [0; d::MAX_DATAGRAM], 100)
                .map(|_| ())
        } else {
            transport.send(&query, 100)
        };
        assert_eq!(interrupted, Err(Error::Channel(-5)));
        let bytes_after_interruption = shared.borrow().output.len();
        assert!(bytes_after_interruption >= 14);
        let tcp = transport.tcp(&query, &mut [0; MAX_TCP_RESPONSE], 1000);
        let udp_send = transport.send(&query, 1000);
        let udp_receive = transport.receive(&mut [0; d::MAX_DATAGRAM], 1000);
        assert_eq!(tcp, Err(Error::Stream(crate::stream::Error::Stale)));
        assert_eq!(udp_send, Err(Error::Stream(crate::stream::Error::Stale)));
        assert_eq!(udp_receive, Err(Error::Stream(crate::stream::Error::Stale)));
        assert_eq!(shared.borrow().output.len(), bytes_after_interruption);
    }
}
