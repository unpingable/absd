//! Deterministic local channel cases. Execution requires separate admission.
use crate::{
    PEER,
    engine::PACKET_LIMIT,
    transport::{Failure, NativeTransport},
};
use absd_net::datagram::{self as d, channel::Pipe};
use std::{cell::Cell, collections::VecDeque, rc::Rc};

struct Script {
    request: Vec<u8>,
    output: VecDeque<u8>,
    statuses: VecDeque<u8>,
    frames: Rc<Cell<u64>>,
    drops: Rc<Cell<u64>>,
    now: Rc<Cell<u64>>,
    fail_reply: bool,
    malformed_reply: bool,
    expire_during_write: bool,
}
impl Script {
    fn new(statuses: &[u8]) -> Self {
        Self {
            request: Vec::new(),
            output: VecDeque::new(),
            statuses: statuses.iter().copied().collect(),
            frames: Rc::new(Cell::new(0)),
            drops: Rc::new(Cell::new(0)),
            now: Rc::new(Cell::new(1)),
            fail_reply: false,
            malformed_reply: false,
            expire_during_write: false,
        }
    }
}
impl Pipe for Script {
    fn now_ms(&self) -> u64 {
        self.now.get()
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        if self.fail_reply {
            return Err(-5);
        }
        if self.output.is_empty() {
            return Ok(None);
        }
        let count = bytes.len().min(7).min(self.output.len());
        for byte in &mut bytes[..count] {
            *byte = self.output.pop_front().unwrap();
        }
        Ok(Some(count))
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        let count = bytes.len().min(7);
        self.request.extend_from_slice(&bytes[..count]);
        if self.expire_during_write {
            self.now.set(1000);
        }
        if self.request.len() >= 2 {
            let wanted = 2 + u16::from_be_bytes([self.request[0], self.request[1]]) as usize;
            if self.request.len() == wanted {
                self.frames.set(self.frames.get() + 1);
                let status = self.statuses.pop_front().unwrap_or(0);
                let mut reply = [
                    0,
                    12,
                    d::VERSION,
                    self.request[3],
                    status,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ];
                if self.malformed_reply {
                    reply[5] = 1;
                }
                self.output.extend(reply);
                self.request.clear();
            }
        }
        Ok(Some(count))
    }
}
impl Drop for Script {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
fn active(script: Script) -> NativeTransport<Script> {
    NativeTransport::new(script, PEER, 1000, || false)
}

#[test]
fn exhaustion_is_known_not_queued_and_channel_stays_live() {
    let script = Script::new(&[4, 0]);
    let frames = script.frames.clone();
    let drops = script.drops.clone();
    let mut native = active(script);
    assert_eq!(native.send(b"same datagram"), Ok(false));
    assert_eq!(drops.get(), 0);
    assert_eq!(native.send(b"same datagram"), Ok(true));
    assert_eq!(frames.get(), 2);
    assert_eq!(native.metrics.send_accepted, 1);
    assert_eq!(native.metrics.exhausted, 1);
}
#[test]
fn unknown_send_drops_owned_pipe_and_later_send_cannot_issue_request() {
    let mut script = Script::new(&[]);
    script.fail_reply = true;
    let frames = script.frames.clone();
    let drops = script.drops.clone();
    let mut native = active(script);
    assert_eq!(native.send(b"one"), Err(Failure::Unknown(-5)));
    assert_eq!(frames.get(), 1);
    assert_eq!(drops.get(), 1);
    assert!(native.metrics.unknown_send);
    assert_eq!(native.send(b"two"), Err(Failure::Fenced));
    assert_eq!(frames.get(), 1);
    assert_eq!(native.metrics.sends_after_fence, 1);
}
#[test]
fn receive_packet_cap_refuses_before_native_consumption() {
    let script = Script::new(&[]);
    let frames = script.frames.clone();
    let mut native = active(script);
    native.metrics.received = PACKET_LIMIT;
    assert_eq!(
        native.receive(&mut [0; d::MAX_DATAGRAM]),
        Err(Failure::Limit)
    );
    assert_eq!(frames.get(), 0);
    assert_eq!(native.metrics.receive_calls, 0);
}
#[test]
fn clock_rewind_fences_before_native_request() {
    let script = Script::new(&[]);
    let now = script.now.clone();
    let frames = script.frames.clone();
    let mut native = active(script);
    now.set(0);
    assert_eq!(native.send(b"one"), Err(Failure::Clock));
    assert_eq!(frames.get(), 0);
}
#[test]
fn unauthorized_native_destination_is_terminal_and_typed() {
    let mut native = active(Script::new(&[2]));
    assert_eq!(native.send(b"one"), Err(Failure::Native(d::Error::Denied)));
    assert!(native.metrics.pipe_fenced);
    assert!(!native.metrics.unknown_send);
}

#[test]
fn malformed_success_reply_is_unknown_and_fences() {
    let mut script = Script::new(&[]);
    script.malformed_reply = true;
    let drops = script.drops.clone();
    let frames = script.frames.clone();
    let mut native = active(script);
    assert_eq!(native.send(b"one"), Err(Failure::Unknown(-22)));
    assert!(native.metrics.unknown_send);
    assert_eq!(drops.get(), 1);
    assert_eq!(frames.get(), 1);
}
#[test]
fn deadline_and_cancellation_issue_no_request() {
    for cancelled in [false, true] {
        let script = Script::new(&[]);
        let frames = script.frames.clone();
        let mut native = NativeTransport::new(
            script,
            PEER,
            if cancelled { 1000 } else { 1 },
            if cancelled { || true } else { || false },
        );
        assert_eq!(
            native.send(b"one"),
            Err(if cancelled {
                Failure::Cancelled
            } else {
                Failure::Deadline
            })
        );
        assert_eq!(frames.get(), 0);
        assert!(native.metrics.pipe_fenced);
    }
}

#[test]
fn deadline_during_partial_request_fences_without_completing_frame() {
    let mut script = Script::new(&[]);
    script.expire_during_write = true;
    let frames = script.frames.clone();
    let drops = script.drops.clone();
    let mut native = active(script);
    assert_eq!(native.send(b"one"), Err(Failure::Deadline));
    assert_eq!(frames.get(), 0);
    assert_eq!(drops.get(), 1);
    assert!(native.metrics.unknown_send);
}
#[test]
fn insufficient_receive_byte_budget_refuses_before_io() {
    let script = Script::new(&[]);
    let frames = script.frames.clone();
    let mut native = active(script);
    native.metrics.receive_bytes = crate::engine::RX_LIMIT - 1;
    assert_eq!(
        native.receive(&mut [0; d::MAX_DATAGRAM]),
        Err(Failure::Limit)
    );
    assert_eq!(frames.get(), 0);
    assert_eq!(native.metrics.receive_calls, 0);
}

// These responses are literal v2 wire fixtures, independent of the transport's
// encoder. Scope 73 is an owner-local identity, not a host interface number.
const V6_PEER: absd_net::ipv6::Address = absd_net::ipv6::Address {
    ip: [0xfd, 0, 0xab, 0x5d, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
    scope: 73,
    port: 4443,
};

struct V6Script {
    request: Vec<u8>,
    requests: Rc<std::cell::RefCell<Vec<Vec<u8>>>>,
    replies: VecDeque<Vec<u8>>,
    output: VecDeque<u8>,
    drops: Rc<Cell<u64>>,
    now: Rc<Cell<u64>>,
    fail_reply: bool,
    expire_during_write: bool,
}
impl V6Script {
    fn new(replies: Vec<Vec<u8>>) -> Self {
        Self {
            request: Vec::new(),
            requests: Rc::new(std::cell::RefCell::new(Vec::new())),
            replies: replies.into(),
            output: VecDeque::new(),
            drops: Rc::new(Cell::new(0)),
            now: Rc::new(Cell::new(1)),
            fail_reply: false,
            expire_during_write: false,
        }
    }
}
impl Pipe for V6Script {
    fn now_ms(&self) -> u64 {
        self.now.get()
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        if self.fail_reply {
            return Err(-5);
        }
        if self.output.is_empty() {
            return Ok(None);
        }
        let count = bytes.len().min(7).min(self.output.len());
        for byte in &mut bytes[..count] {
            *byte = self.output.pop_front().unwrap();
        }
        Ok(Some(count))
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        let count = bytes.len().min(7);
        self.request.extend_from_slice(&bytes[..count]);
        if self.expire_during_write {
            self.now.set(1000);
        }
        if self.request.len() >= 2 {
            let wanted = 2 + u16::from_be_bytes([self.request[0], self.request[1]]) as usize;
            if self.request.len() == wanted {
                self.requests
                    .borrow_mut()
                    .push(std::mem::take(&mut self.request));
                self.output
                    .extend(self.replies.pop_front().expect("unexpected transaction"));
            }
        }
        Ok(Some(count))
    }
}
impl Drop for V6Script {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
fn v6_status(opcode: u8, status: u8, count: u16) -> Vec<u8> {
    let mut reply = vec![0; 30];
    reply[..6].copy_from_slice(&[0, 28, 2, opcode, status, 6]);
    reply[28..30].copy_from_slice(&count.to_be_bytes());
    reply
}
fn v6_received(body: &[u8]) -> Vec<u8> {
    let mut reply = v6_status(d::RECEIVE, 0, body.len() as u16);
    reply[..2].copy_from_slice(&((28 + body.len()) as u16).to_be_bytes());
    reply[6..22].copy_from_slice(&V6_PEER.ip);
    reply[22..26].copy_from_slice(&73u32.to_be_bytes());
    reply[26..28].copy_from_slice(&4443u16.to_be_bytes());
    reply.extend_from_slice(body);
    reply
}
fn active_v6(script: V6Script) -> NativeTransport<V6Script> {
    NativeTransport::new_ipv6(script, V6_PEER, 1000, || false)
}

#[test]
fn ipv6_exhaustion_retries_same_scoped_bytes_and_close_fences() {
    let script = V6Script::new(vec![
        v6_status(d::SEND, 4, 0),
        v6_status(d::SEND, 0, 0),
        v6_status(d::CLOSE, 0, 0),
    ]);
    let requests = script.requests.clone();
    let drops = script.drops.clone();
    let mut native = active_v6(script);
    assert_eq!(native.send(b"same"), Ok(false));
    assert_eq!(drops.get(), 0);
    assert_eq!(native.send(b"same"), Ok(true));
    let mut expected = vec![0, 32, 2, 1, 0, 6];
    expected.extend_from_slice(&V6_PEER.ip);
    expected.extend_from_slice(&73u32.to_be_bytes());
    expected.extend_from_slice(&4443u16.to_be_bytes());
    expected.extend_from_slice(&4u16.to_be_bytes());
    expected.extend_from_slice(b"same");
    assert_eq!(&requests.borrow()[..], &[expected.clone(), expected]);
    assert_eq!(native.close(), Ok(()));
    assert_eq!(drops.get(), 1);
    assert_eq!(requests.borrow()[2], v6_status(d::CLOSE, 0, 0));
    assert_eq!(native.send(b"later"), Err(Failure::Fenced));
    assert_eq!(requests.borrow().len(), 3);
}

#[test]
fn ipv6_receive_uses_v2_capacity_and_exact_scoped_peer() {
    let script = V6Script::new(vec![v6_received(b"udp")]);
    let requests = script.requests.clone();
    let mut native = active_v6(script);
    let mut bytes = [0; d::MAX_DATAGRAM];
    assert_eq!(native.receive(&mut bytes), Ok(Some(3)));
    assert_eq!(&bytes[..3], b"udp");
    assert_eq!(requests.borrow()[0], v6_status(d::RECEIVE, 0, 1232));
    assert_eq!(native.metrics.receive_bytes, 3);
}

#[test]
fn ipv6_wrong_ip_scope_or_port_response_fences_without_fallback() {
    for offset in [6, 22, 26] {
        let mut reply = v6_received(b"udp");
        reply[offset] ^= 1;
        let script = V6Script::new(vec![reply]);
        let requests = script.requests.clone();
        let drops = script.drops.clone();
        let mut native = active_v6(script);
        assert_eq!(
            native.receive(&mut [0; d::MAX_DATAGRAM]),
            Err(Failure::Malformed)
        );
        assert_eq!(drops.get(), 1);
        assert_eq!(native.send(b"later"), Err(Failure::Fenced));
        assert_eq!(requests.borrow().len(), 1);
    }
}

#[test]
fn ipv6_wrong_version_family_opcode_or_success_reserved_bytes_fence() {
    for offset in [2, 3, 5, 6, 29] {
        let mut reply = v6_status(d::SEND, 0, 0);
        reply[offset] ^= 1;
        let script = V6Script::new(vec![reply]);
        let requests = script.requests.clone();
        let mut native = active_v6(script);
        assert!(matches!(
            native.send(b"one"),
            Err(Failure::Unknown(-22) | Failure::Malformed)
        ));
        assert!(native.metrics.unknown_send);
        assert_eq!(requests.borrow().len(), 1);
        assert_eq!(native.send(b"later"), Err(Failure::Fenced));
        assert_eq!(requests.borrow().len(), 1);
    }
}

#[test]
fn ipv6_typed_again_is_live_but_denied_and_v4_statuses_are_terminal() {
    let mut native = active_v6(V6Script::new(vec![
        v6_status(d::RECEIVE, 6, 0),
        v6_received(b"ok"),
    ]));
    assert_eq!(native.receive(&mut [0; d::MAX_DATAGRAM]), Ok(None));
    assert_eq!(native.receive(&mut [0; d::MAX_DATAGRAM]), Ok(Some(2)));
    for status in [2, 12, 13, 14, 15] {
        let mut native = active_v6(V6Script::new(vec![v6_status(d::SEND, status, 0)]));
        assert_eq!(
            native.send(b"one"),
            Err(if status == 2 {
                Failure::Native(d::Error::Denied)
            } else {
                Failure::Malformed
            })
        );
        assert!(native.metrics.pipe_fenced);
    }
}

#[test]
fn ipv6_unknown_send_drops_pipe_and_never_retries() {
    let mut script = V6Script::new(vec![v6_status(d::SEND, 0, 0)]);
    script.fail_reply = true;
    let requests = script.requests.clone();
    let drops = script.drops.clone();
    let mut native = active_v6(script);
    assert_eq!(native.send(b"one"), Err(Failure::Unknown(-5)));
    assert!(native.metrics.unknown_send);
    assert_eq!(drops.get(), 1);
    assert_eq!(native.send(b"two"), Err(Failure::Fenced));
    assert_eq!(requests.borrow().len(), 1);
}

#[test]
fn ipv6_deadline_during_partial_send_fences_before_frame_completion() {
    let mut script = V6Script::new(vec![]);
    script.expire_during_write = true;
    let requests = script.requests.clone();
    let drops = script.drops.clone();
    let mut native = active_v6(script);
    assert_eq!(native.send(b"one"), Err(Failure::Deadline));
    assert_eq!(drops.get(), 1);
    assert!(native.metrics.unknown_send);
    assert!(requests.borrow().is_empty());
}

#[test]
fn ipv6_receive_budget_and_send_mtu_refuse_before_io() {
    for receive in [false, true] {
        let script = V6Script::new(vec![]);
        let requests = script.requests.clone();
        let mut native = active_v6(script);
        if receive {
            native.metrics.receive_bytes = crate::engine::RX_LIMIT - 1231;
            assert_eq!(
                native.receive(&mut [0; d::MAX_DATAGRAM]),
                Err(Failure::Limit)
            );
        } else {
            assert_eq!(native.send(&[0; 1201]), Err(Failure::Limit));
        }
        assert!(requests.borrow().is_empty());
        assert!(native.metrics.pipe_fenced);
    }
}

#[test]
fn ipv6_engine_address_does_not_reinterpret_owner_scope_as_host_interface() {
    let peer = crate::transport::Peer::V6(V6_PEER);
    assert_eq!(peer.max_datagram(), 1232);
    match peer.socket_addr() {
        std::net::SocketAddr::V6(address) => {
            assert_eq!(address.ip().octets(), V6_PEER.ip);
            assert_eq!(address.port(), 4443);
            assert_eq!(address.scope_id(), 0);
            assert_eq!(address.flowinfo(), 0);
        }
        _ => panic!("implicit family change"),
    }
}

#[test]
fn ipv6_clock_deadline_and_cancellation_refuse_before_io() {
    for reason in 0..3 {
        let script = V6Script::new(vec![]);
        let now = script.now.clone();
        let requests = script.requests.clone();
        let drops = script.drops.clone();
        let mut native = NativeTransport::new_ipv6(
            script,
            V6_PEER,
            if reason == 1 { 1 } else { 1000 },
            if reason == 2 { || true } else { || false },
        );
        if reason == 0 {
            now.set(0);
        }
        assert_eq!(
            native.send(b"one"),
            Err(match reason {
                0 => Failure::Clock,
                1 => Failure::Deadline,
                _ => Failure::Cancelled,
            })
        );
        assert!(requests.borrow().is_empty());
        assert_eq!(drops.get(), 1);
    }
}

#[test]
fn ipv6_error_shape_and_receive_count_are_checked_before_consumption() {
    for (opcode, status, count) in [
        (d::SEND, 6, 0),
        (d::RECEIVE, 4, 0),
        (d::RECEIVE, 7, 1232),
        (d::RECEIVE, 8, 1),
    ] {
        let mut native = active_v6(V6Script::new(vec![v6_status(opcode, status, count)]));
        let result = if opcode == d::SEND {
            native.send(b"one").map(|_| ())
        } else {
            native.receive(&mut [0; d::MAX_DATAGRAM]).map(|_| ())
        };
        assert_eq!(result, Err(Failure::Malformed));
        assert!(native.metrics.pipe_fenced);
    }
    let mut native = active_v6(V6Script::new(vec![v6_status(d::RECEIVE, 7, 1233)]));
    assert_eq!(
        native.receive(&mut [0; d::MAX_DATAGRAM]),
        Err(Failure::Native(d::Error::TooSmall { needed: 1233 }))
    );
    assert!(native.metrics.pipe_fenced);
    let mut native = active_v6(V6Script::new(vec![v6_received(&[0; 1233])]));
    assert_eq!(
        native.receive(&mut [0; d::MAX_DATAGRAM]),
        Err(Failure::Unknown(-22))
    );
    assert_eq!(native.metrics.received, 0);
}
