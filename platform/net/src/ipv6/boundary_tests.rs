//! Channel and consumer boundary cases, separate from engine-pair tests.
use super::*;
use super::{channel::*, session::*};
use crate::dns::{Error as DnsError, Transport};
use std::cell::Cell;
use std::rc::Rc;

struct LocalLink;
impl Link for LocalLink {
    fn mac(&self) -> [u8; 6] {
        [2, 0, 0, 0, 0, 1]
    }
    fn send(&mut self, _: &[u8]) -> Result<(), i64> {
        Ok(())
    }
    fn receive(&mut self, _: &mut [u8; FRAME_MAX], _: u64) -> Result<Option<usize>, i64> {
        Ok(None)
    }
    fn now_ms(&self) -> u64 {
        0
    }
    fn pause(&self, _: u64) {}
}
fn peer() -> Address {
    let mut ip = [0; 16];
    ip[0] = 0xfd;
    ip[15] = 2;
    Address {
        ip,
        port: 42010,
        scope: 7,
    }
}
fn stack() -> Stack<LocalLink> {
    let mut s = Stack::open(LocalLink, crate::Config::qemu_user()).unwrap();
    let mut address = peer().ip;
    address[15] = 1;
    s.configure_ipv6(Config {
        address,
        prefix_len: 64,
        scope: 7,
    })
    .unwrap();
    s
}
fn grant() -> Grant {
    Grant {
        local_port: 7002,
        peer: peer(),
    }
}
fn request(op: u8) -> [u8; HEADER] {
    let mut b = [0; HEADER];
    b[0] = VERSION;
    b[1] = op;
    b[3] = FAMILY;
    if op == SEND {
        b[4..20].copy_from_slice(&peer().ip);
        b[20..24].copy_from_slice(&7u32.to_be_bytes());
        b[24..26].copy_from_slice(&42010u16.to_be_bytes());
    }
    b
}

#[test]
fn v2_golden_header_and_negative_requests_preserve_queue() {
    let golden = [
        2, 1, 0, 6, 253, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 7, 164, 26, 0, 0,
    ];
    assert_eq!(request(SEND), golden);
    let mut s = stack();
    let mut session = Session::grant(&mut s, grant()).unwrap();
    let mut reply = [0; MAX_MESSAGE];
    for (offset, value, status) in [
        (0, 1, 1),
        (2, 1, 1),
        (3, 4, 1),
        (23, 8, 2),
        (25, 27, 2),
        (27, 1, 1),
        (1, 255, 1),
    ] {
        let mut b = golden;
        b[offset] = value;
        assert_eq!(session.request(&mut s, &b, &mut reply), HEADER);
        assert_eq!(reply[2], status, "offset {offset}");
        assert_eq!(&reply[4..HEADER], &[0; HEADER - 4]);
    }
    for _ in 0..QUEUE_PACKETS {
        assert_eq!(session.request(&mut s, &golden, &mut reply), HEADER);
        assert_eq!(reply[2], 0);
    }
    session.request(&mut s, &golden, &mut reply);
    assert_eq!(reply[2], Error::Exhausted.code());
    session.request(&mut s, &request(CLOSE), &mut reply);
    assert_eq!(reply[2], 0);
    session.request(&mut s, &golden, &mut reply);
    assert_eq!(reply[2], Error::Stale.code());
}

#[test]
fn receive_and_close_refuse_address_bytes_and_trailing_data() {
    let mut s = stack();
    let mut session = Session::grant(&mut s, grant()).unwrap();
    let mut reply = [0; MAX_MESSAGE];
    for op in [RECEIVE, CLOSE] {
        let mut b = request(op);
        b[4] = 1;
        session.request(&mut s, &b, &mut reply);
        assert_eq!(reply[2], Error::Invalid.code());
        let mut b = request(op).to_vec();
        b.push(0);
        session.request(&mut s, &b, &mut reply);
        assert_eq!(reply[2], Error::Invalid.code());
    }
    session.request(&mut s, &request(SEND), &mut reply);
    assert_eq!(reply[2], 0);
}

struct MemoryPipe {
    input: VecDeque<u8>,
    output: Vec<u8>,
    clock: Rc<Cell<u64>>,
    writes: usize,
    fail_write: bool,
    rewind: bool,
    blocked_write: bool,
    jump_final_read: bool,
    jump_final_write: bool,
}
impl MemoryPipe {
    fn new(input: &[u8]) -> Self {
        Self {
            input: input.iter().copied().collect(),
            output: Vec::new(),
            clock: Rc::new(Cell::new(10)),
            writes: 0,
            fail_write: false,
            rewind: false,
            blocked_write: false,
            jump_final_read: false,
            jump_final_write: false,
        }
    }
}
impl Pipe for MemoryPipe {
    fn now_ms(&self) -> u64 {
        self.clock.get()
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        self.clock.set(self.clock.get() + 1);
        if self.input.is_empty() {
            return Ok(None);
        }
        let n = b.len().min(self.input.len()).min(3);
        for item in b.iter_mut().take(n) {
            *item = self.input.pop_front().unwrap();
        }
        if self.input.is_empty() && self.jump_final_read {
            self.clock.set(1000);
        }
        Ok(Some(n))
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        self.writes += 1;
        if self.fail_write && self.writes > 1 {
            return Err(-5);
        }
        self.clock
            .set(if self.rewind { 0 } else { self.clock.get() + 1 });
        if self.blocked_write {
            return Ok(None);
        }
        let n = b.len().min(3);
        self.output.extend_from_slice(&b[..n]);
        if self.output.len() >= HEADER + 2 && self.jump_final_write {
            self.clock.set(1000);
        }
        Ok(Some(n))
    }
}
fn framed(reply: &[u8]) -> Vec<u8> {
    let mut b = (reply.len() as u16).to_be_bytes().to_vec();
    b.extend_from_slice(reply);
    b
}

#[test]
fn transaction_refuses_version_family_lengths_interruption_and_rewind() {
    for (offset, value) in [(0, 1), (1, RECEIVE), (3, 4)] {
        let mut reply = request(SEND);
        reply[4..].fill(0);
        reply[offset] = value;
        let mut p = MemoryPipe::new(&framed(&reply));
        assert_eq!(
            transact(&mut p, &request(SEND), &mut [0; MAX_MESSAGE], 1000),
            Err(-22)
        );
    }
    for length in [0u16, 27, (MAX_MESSAGE + 1) as u16] {
        let mut p = MemoryPipe::new(&length.to_be_bytes());
        assert_eq!(
            transact(&mut p, &request(SEND), &mut [0; MAX_MESSAGE], 1000),
            Err(-22)
        );
    }
    let mut p = MemoryPipe::new(&[]);
    p.fail_write = true;
    assert_eq!(
        transact(&mut p, &request(SEND), &mut [0; MAX_MESSAGE], 1000),
        Err(-5)
    );
    assert_eq!(p.writes, 2);
    let mut p = MemoryPipe::new(&[]);
    p.rewind = true;
    assert_eq!(
        transact(&mut p, &request(SEND), &mut [0; MAX_MESSAGE], 1000),
        Err(-22)
    );
    let mut p = MemoryPipe::new(&[]);
    assert_eq!(
        transact(&mut p, &request(SEND), &mut [0; MAX_MESSAGE], 30),
        Err(-110)
    );
}

#[test]
fn partial_channel_and_blocked_reply_expire_and_release_port() {
    for block_reply in [false, true] {
        let mut s = stack();
        let mut ch = Channel::grant(&mut s, grant()).unwrap();
        let input = if block_reply {
            framed(&request(SEND))
        } else {
            vec![0]
        };
        let mut p = MemoryPipe::new(&input);
        p.blocked_write = true;
        for _ in 0..20 {
            assert!(ch.poll(&mut s, &mut p));
        }
        p.clock.set(1000);
        assert!(!ch.poll(&mut s, &mut p));
        assert!(!ch.live());
        assert!(s.ipv6_bind(grant()).is_ok());
    }
}

#[test]
fn dns_reply_scope_mismatch_and_unknown_v4_status_fence_transport() {
    for scope_mismatch in [true, false] {
        let mut reply = request(RECEIVE);
        if scope_mismatch {
            reply[4..20].copy_from_slice(&peer().ip);
            reply[20..24].copy_from_slice(&8u32.to_be_bytes());
            reply[24..26].copy_from_slice(&peer().port.to_be_bytes());
        } else {
            reply[2] = 14;
        }
        let p = MemoryPipe::new(&framed(&reply));
        let mut t = super::dns::Datagram::new(p, peer(), |_| {});
        assert_eq!(
            t.receive(&mut [0; crate::datagram::MAX_DATAGRAM], 1000),
            Err(DnsError::Malformed)
        );
        assert!(!t.live());
        assert_eq!(t.send(b"x", 1000), Err(DnsError::Transport(Error::Stale)));
    }
}

#[test]
fn interrupted_dns_send_never_issues_a_second_request() {
    let mut p = MemoryPipe::new(&[]);
    p.fail_write = true;
    let mut t = super::dns::Datagram::new(p, peer(), |_| {});
    assert_eq!(t.send(b"x", 1000), Err(DnsError::Channel(-5)));
    assert!(!t.live());
    assert_eq!(t.send(b"x", 1000), Err(DnsError::Transport(Error::Stale)));
}

#[test]
fn final_pipe_io_cannot_cross_deadline_and_keep_authority() {
    let mut s = stack();
    let mut ch = Channel::grant(&mut s, grant()).unwrap();
    let mut p = MemoryPipe::new(&framed(&request(SEND)));
    p.jump_final_read = true;
    for _ in 0..20 {
        if !ch.poll(&mut s, &mut p) {
            break;
        }
    }
    assert!(!ch.live());
    assert!(p.output.is_empty());
    let mut ch = Channel::grant(&mut s, grant()).unwrap();
    let mut p = MemoryPipe::new(&framed(&request(SEND)));
    p.jump_final_write = true;
    for _ in 0..40 {
        if !ch.poll(&mut s, &mut p) {
            break;
        }
    }
    assert!(!ch.live());
    assert_eq!(p.output.len(), HEADER + 2);
    let mut reply = request(SEND);
    reply[4..].fill(0);
    let mut p = MemoryPipe::new(&framed(&reply));
    p.jump_final_read = true;
    assert_eq!(
        transact(&mut p, &request(SEND), &mut [0; MAX_MESSAGE], 500),
        Err(-110)
    );
}
