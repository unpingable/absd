//! Local framed-channel controls, not independent Linux or native evidence.
use crate::{Hooks, Outcome, transport::NativeTransport};
use absd_net::{FRAME_MAX, Link, Stack, ipv6, stream::Error};
use ipv6::stream::{self, Session};
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    io::{Read, Write},
    rc::Rc,
};

const PEER: ipv6::Address = ipv6::Address {
    ip: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
    scope: 7,
    port: 4443,
};
fn hooks() -> Hooks {
    Hooks {
        now_ms: || 1,
        pause_ms: |_| {},
        cancelled: || false,
        io_event: |_| {},
        phase_event: |_| {},
    }
}
#[derive(Default)]
struct Record {
    requests: Vec<Vec<u8>>,
    replies: Vec<Vec<u8>>,
    accepted: Vec<u8>,
    dropped: bool,
}
type Responder = Box<dyn FnMut(&[u8]) -> Vec<u8>>;
struct Pipe {
    record: Rc<RefCell<Record>>,
    clock: Rc<Cell<u64>>,
    input: Vec<u8>,
    output: VecDeque<u8>,
    respond: Responder,
    read_fault: Rc<Cell<Option<i64>>>,
    write_clock: Option<u64>,
}
impl Drop for Pipe {
    fn drop(&mut self) {
        self.record.borrow_mut().dropped = true;
    }
}
impl ipv6::channel::Pipe for Pipe {
    fn now_ms(&self) -> u64 {
        self.clock.get()
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        let n = bytes.len().min(7);
        self.input.extend_from_slice(&bytes[..n]);
        if let Some(now) = self.write_clock.take() {
            self.clock.set(now);
        }
        if self.input.len() >= 2 {
            let length = u16::from_be_bytes([self.input[0], self.input[1]]) as usize;
            assert!((stream::HEADER..=stream::MAX_MESSAGE).contains(&length));
            assert!(self.input.len() <= length + 2);
            if self.input.len() == length + 2 {
                let frame = std::mem::take(&mut self.input);
                let request = &frame[2..];
                self.record.borrow_mut().requests.push(request.to_vec());
                let reply = (self.respond)(request);
                self.record.borrow_mut().replies.push(reply.clone());
                self.output.extend((reply.len() as u16).to_be_bytes());
                self.output.extend(reply);
            }
        }
        Ok(Some(n))
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        if let Some(error) = self.read_fault.get() {
            return Err(error);
        }
        let n = bytes.len().min(3).min(self.output.len());
        if n == 0 {
            return Ok(None);
        }
        for byte in &mut bytes[..n] {
            *byte = self.output.pop_front().unwrap();
        }
        Ok(Some(n))
    }
}
fn pipe(respond: Responder) -> (Pipe, Rc<RefCell<Record>>) {
    let record = Rc::new(RefCell::new(Record::default()));
    (
        Pipe {
            record: record.clone(),
            clock: Rc::new(Cell::new(1)),
            input: vec![],
            output: VecDeque::new(),
            respond,
            read_fault: Rc::new(Cell::new(None)),
            write_clock: None,
        },
        record,
    )
}
enum Reply {
    Connected,
    Accepted(usize),
    Bytes(&'static [u8]),
    Error(Error),
    Closed,
}
fn scripted(replies: Vec<Reply>) -> (Pipe, Rc<RefCell<Record>>) {
    let mut replies: VecDeque<_> = replies.into();
    let accepted = Rc::new(RefCell::new(Vec::new()));
    let accepted_copy = accepted.clone();
    let (mut pipe, record) = pipe(Box::new(move |request| {
        assert_eq!(request[0], stream::VERSION);
        assert_eq!(request[2], 0);
        assert_eq!(request[3], stream::FAMILY);
        assert_eq!(&request[4..20], &PEER.ip);
        assert_eq!(&request[20..24], &PEER.scope.to_be_bytes());
        assert_eq!(&request[24..26], &PEER.port.to_be_bytes());
        let mut reply = request[..stream::HEADER].to_vec();
        reply[26..28].fill(0);
        match replies
            .pop_front()
            .expect("unexpected transaction or family fallback")
        {
            Reply::Connected => {
                assert_eq!(request[1], stream::CONNECT);
                reply[26..28].copy_from_slice(&1u16.to_be_bytes());
                reply.push(1);
            }
            Reply::Accepted(n) => {
                assert_eq!(request[1], stream::WRITE);
                assert!(n <= request.len() - stream::HEADER);
                accepted_copy
                    .borrow_mut()
                    .extend_from_slice(&request[stream::HEADER..stream::HEADER + n]);
                reply[26..28].copy_from_slice(&(n as u16).to_be_bytes());
            }
            Reply::Bytes(bytes) => {
                assert_eq!(request[1], stream::READ);
                reply[26..28].copy_from_slice(&(bytes.len() as u16).to_be_bytes());
                reply.extend_from_slice(bytes);
            }
            Reply::Error(error) => reply[2] = error.code(),
            Reply::Closed => assert_eq!(request[1], stream::CLOSE),
        }
        reply
    }));
    let mut responder = std::mem::replace(&mut pipe.respond, Box::new(|_| unreachable!()));
    let copy = record.clone();
    pipe.respond = Box::new(move |request| {
        let reply = responder(request);
        copy.borrow_mut().accepted = accepted.borrow().clone();
        reply
    });
    (pipe, record)
}

#[test]
fn ipv6_fragmented_channel_keeps_scoped_peer_short_writes_and_eof() {
    let (pipe, record) = scripted(vec![
        Reply::Connected,
        Reply::Accepted(2),
        Reply::Error(Error::Again),
        Reply::Accepted(4),
        Reply::Bytes(b"ok"),
        Reply::Error(Error::Eof),
        Reply::Closed,
    ]);
    let mut transport = NativeTransport::new_ipv6(pipe, PEER, 100, hooks());
    transport.connect().unwrap();
    assert_eq!(transport.write(b"abcdef").unwrap(), 2);
    assert_eq!(
        transport.write(b"cdef").unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(transport.write(b"cdef").unwrap(), 4);
    let mut bytes = [0; 4];
    assert_eq!(transport.read(&mut bytes).unwrap(), 2);
    assert_eq!(&bytes[..2], b"ok");
    assert_eq!(transport.read(&mut bytes).unwrap(), 0);
    assert_eq!(transport.read(&mut bytes).unwrap(), 0);
    transport.close().unwrap();
    assert_eq!(record.borrow().accepted, b"abcdef");
    assert_eq!(record.borrow().requests.len(), 7);
    assert!(record.borrow().dropped);
    assert_eq!(transport.metrics.short_writes, 1);
    assert_eq!(transport.metrics.write_again, 1);
    assert!(transport.metrics.native_eof && transport.metrics.pipe_fenced);
}

#[test]
fn ipv6_unknown_write_completion_drops_pipe_without_retry_or_ipv4_fallback() {
    let (pipe, record) = scripted(vec![Reply::Connected, Reply::Accepted(3)]);
    let fault = pipe.read_fault.clone();
    let mut transport = NativeTransport::new_ipv6(pipe, PEER, 100, hooks());
    transport.connect().unwrap();
    // The complete WRITE reaches the service; its reply is then lost.
    fault.set(Some(-5));
    assert!(transport.write(b"abc").is_err());
    assert!(transport.write(b"abc").is_err());
    assert_eq!(record.borrow().accepted, b"abc");
    assert_eq!(record.borrow().requests.len(), 2);
    assert!(record.borrow().dropped);
}

#[test]
fn ipv6_wrong_reply_identity_and_family_fence_the_adapter() {
    for offset in [0, 3, 4, 20, 24] {
        let (mut pipe, record) = scripted(vec![Reply::Connected]);
        let mut respond = std::mem::replace(&mut pipe.respond, Box::new(|_| unreachable!()));
        pipe.respond = Box::new(move |request| {
            let mut reply = respond(request);
            reply[offset] ^= 1;
            reply
        });
        let mut transport = NativeTransport::new_ipv6(pipe, PEER, 100, hooks());
        assert!(transport.connect().is_err());
        assert!(transport.write(b"never").is_err());
        assert_eq!(record.borrow().requests.len(), 1);
        assert!(record.borrow().dropped);
        assert!(transport.metrics.pipe_fenced);
    }
}

#[test]
fn ipv6_pipe_error_deadline_and_clock_rewind_refuse_further_io() {
    for fault in 0..3 {
        let (mut pipe, record) = scripted(vec![Reply::Connected]);
        match fault {
            0 => pipe.read_fault.set(Some(-5)),
            1 => pipe.write_clock = Some(100),
            _ => pipe.write_clock = Some(0),
        }
        let mut transport = NativeTransport::new_ipv6(pipe, PEER, 100, hooks());
        assert!(transport.connect().is_err());
        assert!(transport.connect().is_err());
        assert!(record.borrow().dropped);
        assert_eq!(record.borrow().requests.len(), usize::from(fault == 0));
        assert_eq!(
            transport.outcome,
            Some(match fault {
                0 => Outcome::Native,
                1 => Outcome::Timeout,
                _ => Outcome::Clock,
            })
        );
    }
}

struct QuietLink {
    sent: Rc<Cell<usize>>,
}
impl Link for QuietLink {
    fn mac(&self) -> [u8; 6] {
        [2, 0, 0, 0, 0, 1]
    }
    fn now_ms(&self) -> u64 {
        1
    }
    fn pause(&self, _: u64) {}
    fn send(&mut self, _: &[u8]) -> Result<(), i64> {
        self.sent.set(self.sent.get() + 1);
        Ok(())
    }
    fn receive(&mut self, _: &mut [u8; FRAME_MAX], _: u64) -> Result<Option<usize>, i64> {
        Ok(None)
    }
}

#[test]
fn ipv6_real_session_refuses_wrong_ip_scope_and_port_before_any_frame() {
    for field in 0..3 {
        let sent = Rc::new(Cell::new(0));
        let mut stack = Stack::open(
            QuietLink { sent: sent.clone() },
            absd_net::Config::qemu_user(),
        )
        .unwrap();
        let mut local = PEER.ip;
        local[15] = 1;
        stack
            .configure_ipv6(ipv6::Config {
                address: local,
                prefix_len: 64,
                scope: PEER.scope,
            })
            .unwrap();
        let mut session = Session::grant(
            &mut stack,
            stream::Grant {
                local_port: 40000,
                peer: PEER,
                connect_timeout_ms: 1000,
                lifetime_ms: 10000,
            },
        )
        .unwrap();
        let (pipe, record) = pipe(Box::new(move |request| {
            let mut reply = [0; stream::MAX_MESSAGE];
            let n = session.request(&mut stack, request, &mut reply);
            assert_eq!(stack.socket_count(), 0, "wrong peer dispatched CONNECT");
            reply[..n].to_vec()
        }));
        let mut wrong = PEER;
        match field {
            0 => wrong.ip[15] = 3,
            1 => wrong.scope += 1,
            _ => wrong.port += 1,
        }
        let mut transport = NativeTransport::new_ipv6(pipe, wrong, 100, hooks());
        assert!(transport.connect().is_err());
        assert!(transport.write(b"never").is_err());
        assert_eq!(record.borrow().replies[0][2], Error::Denied.code());
        assert_eq!(record.borrow().requests.len(), 1);
        assert!(record.borrow().dropped);
        assert_eq!(sent.get(), 0);
    }
}

#[test]
fn ipv6_public_engine_entry_drops_pipe_before_connect_when_root_is_invalid() {
    let (pipe, record) = scripted(vec![]);
    let report = crate::run_ipv6(
        pipe,
        PEER,
        &[0x30, 0],
        crate::Settings {
            unix_seconds: Some(1_792_211_400),
            child_start_ms: 1,
            grant_expiry_ms: 100,
            expected_body_len: 2,
        },
        hooks(),
    );
    assert_eq!(report.outcome, Outcome::Config);
    assert_eq!(report.phase, crate::Phase::Fenced);
    assert_eq!(report.metrics.connect_calls, 0);
    assert_eq!(report.metrics.read_calls, 0);
    assert_eq!(report.metrics.write_calls, 0);
    assert!(report.metrics.pipe_fenced);
    assert!(record.borrow().requests.is_empty());
    assert!(record.borrow().dropped);
}

#[test]
fn ipv6_public_engine_handshake_failure_drains_bounded_fatal_output_and_fences() {
    let root = std::fs::read(
        std::env::var("ABSD_TLS_ROOT_DER").expect("sealed public fixture root required"),
    )
    .unwrap();
    let mut injected = false;
    let (pipe, record) = pipe(Box::new(move |request| {
        assert_eq!(request[0], stream::VERSION);
        assert_eq!(request[2], 0);
        assert_eq!(request[3], stream::FAMILY);
        assert_eq!(&request[4..20], &PEER.ip);
        assert_eq!(&request[20..24], &PEER.scope.to_be_bytes());
        assert_eq!(&request[24..26], &PEER.port.to_be_bytes());
        let mut reply = request[..stream::HEADER].to_vec();
        reply[26..28].fill(0);
        match request[1] {
            stream::CONNECT => {
                reply[26..28].copy_from_slice(&1u16.to_be_bytes());
                reply.push(1);
            }
            stream::WRITE => {
                let length = request.len() - stream::HEADER;
                assert!(length <= stream::MAX_IO);
                reply[26..28].copy_from_slice(&(length as u16).to_be_bytes());
            }
            stream::READ => {
                assert!(!injected, "normal read resumed after TLS processing error");
                injected = true;
                // Actual rustls must reject this invalid TLS content type and
                // produce its fatal alert; the service does not synthesize it.
                let invalid_record = [0xff, 3, 3, 0, 0];
                reply[26..28].copy_from_slice(&(invalid_record.len() as u16).to_be_bytes());
                reply.extend_from_slice(&invalid_record);
            }
            _ => panic!("close, retry or other transaction after TLS failure"),
        }
        reply
    }));
    let report = crate::run_ipv6(
        pipe,
        PEER,
        &root,
        crate::Settings {
            unix_seconds: Some(1_792_211_400),
            child_start_ms: 1,
            grant_expiry_ms: 100,
            expected_body_len: 0,
        },
        hooks(),
    );
    assert_eq!(report.outcome, Outcome::Tls);
    assert_eq!(report.tls_error_code, Some("TLS_PROTOCOL"));
    assert_eq!(report.phase, crate::Phase::Fenced);
    assert!(!report.authenticated);
    assert_eq!(report.http_emitted, 0);
    assert_eq!(report.preauth_http_emitted, 0);
    assert_eq!(report.metrics.connect_calls, 1);
    assert_eq!(report.metrics.read_calls, 1);
    assert_eq!(report.metrics.close_calls, 0);
    assert!(report.metrics.write_accepted <= 1024);
    assert!(report.metrics.pipe_fenced);
    let drain = report
        .error_output
        .as_ref()
        .expect("TLS error output missing");
    assert!(drain.queued && drain.queue_drained);
    assert_eq!(drain.error, None);
    assert!((1..=16).contains(&drain.attempts));
    assert!((1..=1024).contains(&drain.native_bytes_accepted));
    let record = record.borrow();
    assert!(record.dropped);
    assert_eq!(record.requests[0][1], stream::CONNECT);
    assert_eq!(
        record
            .requests
            .iter()
            .filter(|r| r[1] == stream::CONNECT)
            .count(),
        1
    );
    let read = record
        .requests
        .iter()
        .position(|r| r[1] == stream::READ)
        .unwrap();
    assert!(
        read > 1,
        "no ClientHello was submitted before the injected record"
    );
    assert!(
        record.requests[1..read]
            .iter()
            .all(|r| r[1] == stream::WRITE)
    );
    assert!(
        record.requests[read + 1..]
            .iter()
            .all(|r| r[1] == stream::WRITE)
    );
    let fatal: Vec<u8> = record.requests[read + 1..]
        .iter()
        .flat_map(|r| r[stream::HEADER..].iter().copied())
        .collect();
    assert_eq!(fatal, [21, 3, 3, 0, 2, 2, 50]);
    assert_eq!(drain.native_bytes_accepted as usize, fatal.len());
    assert_eq!(
        drain.native_write_calls as usize,
        record.requests.len() - read - 1
    );
    assert_eq!(
        report.metrics.write_accepted as usize,
        record
            .requests
            .iter()
            .filter(|r| r[1] == stream::WRITE)
            .map(|r| r.len() - stream::HEADER)
            .sum::<usize>()
    );
}
