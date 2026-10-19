use super::*;
use crate::{dns::Resolver, ipv6::session::*};
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

fn peer() -> Address {
    let mut ip = [0; 16];
    ip[0] = 0xfd;
    ip[15] = 2;
    Address {
        ip,
        port: 53,
        scope: 7,
    }
}
fn query(v6: bool) -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(b"\x03www\x07example\0");
    q.extend_from_slice(&[0, if v6 { 28 } else { 1 }, 0, 1]);
    q
}
fn answer(v6: bool) -> Vec<u8> {
    let mut q = query(v6);
    q[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    q[7] = 1;
    q.extend_from_slice(&[
        0xc0,
        12,
        0,
        if v6 { 28 } else { 1 },
        0,
        1,
        0,
        0,
        0,
        60,
        0,
        if v6 { 16 } else { 4 },
    ]);
    if v6 {
        let mut ip = [0; 16];
        ip[..4].copy_from_slice(&[0x20, 1, 0x0d, 0xb8]);
        ip[15] = 9;
        q.extend_from_slice(&ip)
    } else {
        q.extend_from_slice(&[192, 0, 2, 9])
    }
    q
}
struct Script {
    input: VecDeque<u8>,
    output: Vec<u8>,
    now: u64,
}
struct ScriptPipe(Rc<RefCell<Script>>);
impl Pipe for ScriptPipe {
    fn now_ms(&self) -> u64 {
        self.0.borrow().now
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        let mut state = self.0.borrow_mut();
        state.now += 1;
        if state.input.is_empty() {
            return Ok(None);
        }
        let n = b.len().min(state.input.len()).min(3);
        for item in &mut b[..n] {
            *item = state.input.pop_front().unwrap()
        }
        Ok(Some(n))
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        let mut s = self.0.borrow_mut();
        s.now += 1;
        s.output.extend_from_slice(b);
        Ok(Some(b.len()))
    }
}
fn frame(s: &mut Script, op: u8, length: usize, data: &[u8], address: bool, status: u8) {
    let mut b = vec![0; HEADER];
    b[0] = VERSION;
    b[1] = op;
    b[2] = status;
    b[3] = FAMILY;
    if address {
        b[4..20].copy_from_slice(&peer().ip);
        b[20..24].copy_from_slice(&peer().scope.to_be_bytes());
        b[24..26].copy_from_slice(&peer().port.to_be_bytes());
    }
    b[26..28].copy_from_slice(&(length as u16).to_be_bytes());
    b.extend_from_slice(data);
    s.input.extend((b.len() as u16).to_be_bytes());
    s.input.extend(b);
}
fn stream_script(packets: Vec<Vec<u8>>) -> Script {
    let mut s = Script {
        input: VecDeque::new(),
        output: Vec::new(),
        now: 0,
    };
    frame(&mut s, stream::CONNECT, 1, &[1], true, 0);
    frame(&mut s, stream::WRITE, 2 + query(true).len(), &[], true, 0);
    for packet in packets {
        frame(
            &mut s,
            stream::READ,
            2,
            &(packet.len() as u16).to_be_bytes(),
            true,
            0,
        );
        frame(&mut s, stream::READ, packet.len(), &packet, true, 0);
    }
    s
}
fn operations(s: &Script) -> Vec<u8> {
    let mut at = 0;
    let mut ops = Vec::new();
    while at < s.output.len() {
        let n = u16::from_be_bytes(s.output[at..at + 2].try_into().unwrap()) as usize;
        ops.push(s.output[at + 3]);
        at += 2 + n;
    }
    ops
}

#[test]
fn paired_scoped_adapter_falls_back_a_and_aaaa_ignoring_other_family_frame() {
    for v6 in [false, true] {
        let matching = answer(v6);
        let mut truncated = matching.clone();
        truncated[2] |= 2;
        let mut s = Script {
            input: VecDeque::new(),
            output: Vec::new(),
            now: 0,
        };
        frame(&mut s, SEND, 0, &[], false, 0);
        frame(&mut s, RECEIVE, truncated.len(), &truncated, true, 0);
        s.input
            .extend(stream_script(vec![answer(!v6), matching]).input);
        let shared = Rc::new(RefCell::new(s));
        let mut resolver = Resolver::new(
            DatagramTcp::new(ScriptPipe(shared.clone()), peer(), |_| {}),
            0x1234,
        );
        if v6 {
            assert_eq!(
                resolver.lookup_aaaa("www.example").unwrap().addresses[0],
                core::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9).octets()
            );
        } else {
            assert_eq!(
                resolver.lookup("www.example").unwrap().addresses[0],
                [192, 0, 2, 9]
            );
        }
        let s = shared.borrow();
        assert!(s.input.is_empty());
        assert_eq!(
            operations(&s),
            [
                SEND,
                RECEIVE,
                stream::CONNECT,
                stream::WRITE,
                stream::READ,
                stream::READ,
                stream::READ,
                stream::READ
            ]
        );
        assert!(s.now < crate::dns::LOOKUP_MS);
    }
}

#[test]
fn invalid_query_refuses_before_io_and_matching_malformed_is_not_ignored() {
    for at in [2, 7, 26, 28] {
        let shared = Rc::new(RefCell::new(stream_script(vec![])));
        let mut transport = DatagramTcp::new(ScriptPipe(shared.clone()), peer(), |_| {});
        let mut bad = query(true);
        bad[at] ^= 0xff;
        assert_eq!(
            transport.tcp(&bad, &mut [0; MAX_TCP_RESPONSE], 1000),
            Err(Error::Malformed)
        );
        assert!(shared.borrow().output.is_empty());
    }
    let mut malformed = answer(true);
    malformed.pop();
    let shared = Rc::new(RefCell::new(stream_script(vec![malformed.clone()])));
    let mut transport = DatagramTcp::new(ScriptPipe(shared), peer(), |_| {});
    let mut bytes = [0; MAX_TCP_RESPONSE];
    assert_eq!(
        transport.tcp(&query(true), &mut bytes, 1000),
        Ok(malformed.len())
    );
    assert_eq!(&bytes[..malformed.len()], malformed.as_slice());
}

#[test]
fn unmatched_frame_does_not_renew_absolute_deadline_or_repeat_query() {
    let shared = Rc::new(RefCell::new(stream_script(vec![answer(false)])));
    let mut transport = DatagramTcp::new(ScriptPipe(shared.clone()), peer(), |_| {});
    assert_eq!(
        transport.tcp(&query(true), &mut [0; MAX_TCP_RESPONSE], 180),
        Err(Error::Timeout)
    );
    let s = shared.borrow();
    assert_eq!(s.now, 180);
    assert_eq!(
        operations(&s)
            .iter()
            .filter(|op| **op == stream::WRITE)
            .count(),
        1
    );
    let written = s.output.len();
    drop(s);
    assert!(!transport.live());
    assert_eq!(
        transport.tcp(&query(true), &mut [0; MAX_TCP_RESPONSE], 1000),
        Err(Error::Stream(stream::Error::Stale))
    );
    assert_eq!(shared.borrow().output.len(), written);
}

#[test]
fn length_prefix_and_question_are_offered_in_one_tcp_write() {
    let shared = Rc::new(RefCell::new(stream_script(vec![answer(true)])));
    let mut transport = DatagramTcp::new(ScriptPipe(shared.clone()), peer(), |_| {});
    let question = query(true);
    assert_eq!(
        transport.tcp(&question, &mut [0; MAX_TCP_RESPONSE], 1000),
        Ok(answer(true).len())
    );
    let s = shared.borrow();
    let mut at = 0;
    let mut writes = Vec::new();
    while at < s.output.len() {
        let n = u16::from_be_bytes(s.output[at..at + 2].try_into().unwrap()) as usize;
        let request = &s.output[at + 2..at + 2 + n];
        if request[1] == stream::WRITE {
            writes.push(request[HEADER..].to_vec());
        }
        at += 2 + n;
    }
    let mut expected = (question.len() as u16).to_be_bytes().to_vec();
    expected.extend_from_slice(&question);
    assert_eq!(writes, [expected]);
    assert!(s.input.is_empty());
    assert!(s.now < 1000);
}

#[test]
fn matching_id_short_tcp_frame_is_malformed_without_reading_body_or_waiting() {
    for length in 2..12 {
        let mut packet = vec![0; length];
        packet[..2].copy_from_slice(&0x1234u16.to_be_bytes());
        let shared = Rc::new(RefCell::new(stream_script(vec![packet])));
        let mut transport = DatagramTcp::new(ScriptPipe(shared.clone()), peer(), |_| {});
        assert_eq!(
            transport.tcp(&query(true), &mut [0; MAX_TCP_RESPONSE], 1000),
            Err(Error::Malformed),
            "short frame length {length}"
        );
        assert!(!transport.live());
        let s = shared.borrow();
        assert_eq!(
            operations(&s),
            [stream::CONNECT, stream::WRITE, stream::READ]
        );
        assert!(!s.input.is_empty(), "short body must not be consumed");
        assert!(s.now < 1000);
        let written = s.output.len();
        drop(s);
        assert_eq!(
            transport.tcp(&query(true), &mut [0; MAX_TCP_RESPONSE], 1000),
            Err(Error::Stream(stream::Error::Stale))
        );
        assert_eq!(shared.borrow().output.len(), written);
    }
}

#[test]
fn udp_denial_does_not_issue_connect_or_fallback() {
    let mut s = Script {
        input: VecDeque::new(),
        output: Vec::new(),
        now: 0,
    };
    frame(&mut s, SEND, 0, &[], false, 2);
    let shared = Rc::new(RefCell::new(s));
    let mut resolver = Resolver::new(
        DatagramTcp::new(ScriptPipe(shared.clone()), peer(), |_| {}),
        0x1234,
    );
    assert_eq!(
        resolver.lookup_aaaa("www.example"),
        Err(Error::Transport(super::super::Error::Denied))
    );
    assert_eq!(operations(&shared.borrow()), [SEND]);
}
