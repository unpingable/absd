use super::*;
use crate::stream::{self as s, server as v};
use alloc::vec;
fn step<L: Link>(wire: &Rc<RefCell<Wire>>, owner: &mut Stack<L>, client: &mut Stack<End>) {
    owner.poll();
    client.poll();
    wire.borrow_mut().now_ms += 1;
}
fn grant(port: u16) -> v::Grant {
    v::Grant {
        local_port: port,
        peer: datagram::Address {
            ip: [10, 0, 2, 2],
            port: 42030,
        },
        accept_timeout_ms: 1000,
        lifetime_ms: 10000,
    }
}
fn connected() -> (
    Rc<RefCell<Wire>>,
    Stack<End>,
    Stack<End>,
    Connection,
    s::Endpoint,
) {
    let (wire, mut owner, mut client) = pair(0);
    let e = owner.stream_server_grant(grant(7005)).unwrap();
    owner.stream_listen(e).unwrap();
    let peer = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7005, 42030)
        .unwrap();
    let mut accepted = false;
    for _ in 0..1000 {
        step(&wire, &mut owner, &mut client);
        match owner.stream_accept(e) {
            Ok(_) => {
                accepted = true;
                break;
            }
            Err(s::Error::Again) => {}
            other => panic!("{other:?}"),
        }
    }
    assert!(accepted);
    (wire, owner, client, peer, e)
}
fn applications(wire: &Wire) -> usize {
    wire.queues[1]
        .iter()
        .filter(|f| {
            if f.len() < 54 || f[12..14] != [8, 0] || f[23] != 6 {
                return false;
            }
            let ip = usize::from(f[14] & 15) * 4;
            if ip < 20 || f.len() < 14 + ip + 20 {
                return false;
            }
            let tcp = usize::from(f[14 + ip + 12] >> 4) * 4;
            usize::from(u16::from_be_bytes([f[16], f[17]])) > ip + tcp
        })
        .count()
}
#[test]
fn preissued_identity_bounds_slots_and_never_rebinds_a_spent_handle() {
    let (_, mut owner, mut other) = pair(0);
    let e = owner.stream_server_grant(grant(7005)).unwrap();
    assert_eq!(owner.socket_count(), 0);
    assert_eq!(owner.stream_connect(e), Err(s::Error::Denied));
    assert_eq!(other.stream_accept(e), Err(s::Error::Stale));
    assert_eq!(owner.listen(7005, 1), Err(NetError::InUse));
    assert_eq!(
        owner.stream_grant(s::Grant {
            local_port: 7005,
            peer: grant(7005).peer,
            connect_timeout_ms: 1000,
            lifetime_ms: 10000
        }),
        Err(s::Error::InUse)
    );
    for port in 7006..7013 {
        owner.stream_server_grant(grant(port)).unwrap();
    }
    assert_eq!(
        owner.stream_server_grant(grant(7013)),
        Err(s::Error::Exhausted)
    );
    owner.stream_abort(e).unwrap();
    let fresh = owner.stream_server_grant(grant(7005)).unwrap();
    assert_ne!(e, fresh);
    assert_eq!(owner.stream_listen(e), Err(s::Error::Stale));
    owner.stream_server_fence();
    assert_eq!(owner.socket_count(), 0);
    for port in [0, 53, 1023] {
        assert_eq!(
            owner.stream_server_grant(grant(port)),
            Err(s::Error::Invalid)
        );
    }
    for ip in [
        [10, 0, 2, 15],
        [10, 0, 2, 0],
        [10, 0, 2, 255],
        [127, 0, 0, 1],
        [224, 0, 0, 1],
        [192, 0, 2, 1],
    ] {
        let mut g = grant(7005);
        g.peer.ip = ip;
        assert_eq!(owner.stream_server_grant(g), Err(s::Error::Invalid));
    }
}
#[test]
fn wrong_peer_syn_cannot_occupy_the_single_listener() {
    let (wire, mut owner, mut client) = pair(0);
    let e = owner.stream_server_grant(grant(7005)).unwrap();
    owner.stream_listen(e).unwrap();
    let wrong = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7005, 42031)
        .unwrap();
    for _ in 0..100 {
        step(&wire, &mut owner, &mut client);
    }
    assert_eq!(owner.stream_accept(e), Err(s::Error::Again));
    assert!(owner.sockets.iter().any(|(_,socket)|matches!(socket,smoltcp::socket::Socket::Tcp(t) if t.state()==TcpState::Listen)));
    client.abort(wrong).unwrap();
    let _peer = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7005, 42030)
        .unwrap();
    let mut accepted = false;
    for _ in 0..500 {
        step(&wire, &mut owner, &mut client);
        if owner.stream_accept(e).is_ok() {
            accepted = true;
            break;
        }
    }
    assert!(accepted);
    assert_eq!(owner.stream_accept(e), Err(s::Error::Invalid));
}
#[test]
fn exact_ingress_checks_ip_port_family_header_and_cached_frames() {
    let (_, mut owner, _) = pair(0);
    let _e = owner.stream_server_grant(grant(7005)).unwrap();
    let mut f = [0u8; 54];
    f[12..14].copy_from_slice(&[8, 0]);
    f[14] = 0x45;
    f[23] = 6;
    f[26..30].copy_from_slice(&[10, 0, 2, 2]);
    f[30..34].copy_from_slice(&[10, 0, 2, 15]);
    f[34..36].copy_from_slice(&42030u16.to_be_bytes());
    f[36..38].copy_from_slice(&7005u16.to_be_bytes());
    assert!(v::ingress(&f, &owner.port.server_rules));
    for at in [26, 30, 34] {
        let mut bad = f;
        bad[at] ^= 1;
        assert!(!v::ingress(&bad, &owner.port.server_rules));
    }
    let mut fragmented = f;
    fragmented[20] = 0x20;
    assert!(!v::ingress(&fragmented, &owner.port.server_rules));
    let mut other = f;
    other[36..38].copy_from_slice(&22u16.to_be_bytes());
    assert!(v::ingress(&other, &owner.port.server_rules));
    let mut cached = f;
    cached[26] ^= 1;
    owner.port.rx[..54].copy_from_slice(&cached);
    owner.port.rx_length = Some(54);
    assert!(phy::Device::receive(&mut owner.port, Instant::from_millis(1)).is_none());
}

#[test]
fn half_closed_peer_receives_final_echo_before_server_fin() {
    let (wire, mut owner, mut client) = pair(0);
    let e = owner.stream_server_grant(grant(7005)).unwrap();
    owner.stream_listen(e).unwrap();
    let remote = client
        .stream_grant(s::Grant {
            local_port: 42030,
            peer: datagram::Address {
                ip: [10, 0, 2, 15],
                port: 7005,
            },
            connect_timeout_ms: 1000,
            lifetime_ms: 10000,
        })
        .unwrap();
    client.stream_connect(remote).unwrap();
    let mut accepted = false;
    for _ in 0..1000 {
        step(&wire, &mut owner, &mut client);
        if owner.stream_accept(e).is_ok() {
            accepted = true;
            break;
        }
    }
    assert!(accepted);
    client.stream_write(remote, b"request").unwrap();
    client.stream_shutdown_write(remote).unwrap();
    let mut body = Vec::new();
    let mut bytes = [0; 32];
    let mut eof = false;
    for _ in 0..1000 {
        step(&wire, &mut owner, &mut client);
        match owner.stream_read(e, &mut bytes) {
            Ok(n) => body.extend_from_slice(&bytes[..n]),
            Err(s::Error::Again) => {}
            Err(s::Error::Eof) => {
                eof = true;
                break;
            }
            e => panic!("{e:?}"),
        }
    }
    assert!(eof);
    assert_eq!(body, b"request");
    owner.stream_write(e, b"after-fin").unwrap();
    owner.stream_shutdown_write(e).unwrap();
    let mut echoed = Vec::new();
    let mut eof = false;
    for _ in 0..1000 {
        step(&wire, &mut owner, &mut client);
        match client.stream_read(remote, &mut bytes) {
            Ok(n) => echoed.extend_from_slice(&bytes[..n]),
            Err(s::Error::Again) => {}
            Err(s::Error::Eof) => {
                eof = true;
                break;
            }
            e => panic!("{e:?}"),
        }
    }
    assert!(eof);
    assert_eq!(echoed, b"after-fin");
    owner.stream_close(e).unwrap();
    client.stream_close(remote).unwrap();
}

#[test]
fn checked_epochs_and_observed_link_failures_cannot_revive_grants() {
    let (_, mut owner, _) = pair(0);
    owner.streams.set_epoch_for_test(u64::MAX);
    assert_eq!(
        owner.stream_server_grant(grant(7005)),
        Err(s::Error::Exhausted)
    );
    for status in [reading(false, false, 0), reading(true, true, 0), None] {
        let state = Rc::new(RefCell::new(SwitchState {
            now_ms: 1,
            reading: reading(true, false, 0),
            reads: 0,
        }));
        let mut owner = Stack::open(SwitchLink(state.clone()), dead_config()).unwrap();
        let e = owner.stream_server_grant(grant(7005)).unwrap();
        owner.stream_listen(e).unwrap();
        state.borrow_mut().reading = status;
        assert!(owner.stream_accept(e).is_err());
        assert_eq!(owner.socket_count(), 0);
        state.borrow_mut().reading = reading(true, false, 0);
        assert_eq!(owner.stream_listen(e), Err(s::Error::Stale));
    }
}

struct LateReceive {
    end: End,
    jump: Rc<std::cell::Cell<u64>>,
    send_jump: Rc<std::cell::Cell<u64>>,
}
impl Link for LateReceive {
    fn mac(&self) -> [u8; 6] {
        self.end.mac()
    }
    fn send(&mut self, b: &[u8]) -> Result<(), i64> {
        let result = self.end.send(b);
        self.end.wire.borrow_mut().now_ms += self.send_jump.replace(0);
        result
    }
    fn receive(&mut self, b: &mut [u8; FRAME_MAX], t: u64) -> Result<Option<usize>, i64> {
        let jump = self.jump.replace(0);
        self.end.wire.borrow_mut().now_ms += jump;
        self.end.receive(b, t)
    }
    fn now_ms(&self) -> u64 {
        self.end.now_ms()
    }
    fn pause(&self, n: u64) {
        self.end.pause(n)
    }
}
#[test]
fn expiry_observed_during_interface_poll_prevents_queued_application_send() {
    let (wire, _unused, mut client) = pair(0);
    let jump = Rc::new(std::cell::Cell::new(0));
    let mut owner = Stack::open(
        LateReceive {
            end: End {
                wire: wire.clone(),
                side: 0,
                mac: [2, 0, 0, 0, 0, 15],
            },
            jump: jump.clone(),
            send_jump: Rc::new(std::cell::Cell::new(0)),
        },
        Config {
            address: Ipv4Address::new(10, 0, 2, 15),
            prefix_len: 24,
            gateway: None,
            rx_buffer: 8192,
            tx_buffer: 8192,
        },
    )
    .unwrap();
    let e = owner.stream_server_grant(grant(7005)).unwrap();
    owner.stream_listen(e).unwrap();
    let _peer = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7005, 42030)
        .unwrap();
    let mut accepted = false;
    for _ in 0..1000 {
        step(&wire, &mut owner, &mut client);
        if owner.stream_accept(e).is_ok() {
            accepted = true;
            break;
        }
    }
    assert!(accepted);
    owner
        .stream_write(e, b"not-after-observed-boundary")
        .unwrap();
    wire.borrow_mut().queues[1].clear();
    jump.set(10001);
    owner.poll();
    owner.poll();
    assert_eq!(owner.socket_count(), 0);
    assert_eq!(owner.stream_status(e), Err(s::Error::Timeout));
    assert_eq!(applications(&wire.borrow()), 0);
}

#[test]
fn a_send_straddling_expiry_keeps_its_first_effect_and_fences_later_sends() {
    let (wire, _unused, mut client) = pair(0);
    let send_jump = Rc::new(std::cell::Cell::new(0));
    let mut owner = Stack::open(
        LateReceive {
            end: End {
                wire: wire.clone(),
                side: 0,
                mac: [2, 0, 0, 0, 0, 15],
            },
            jump: Rc::new(std::cell::Cell::new(0)),
            send_jump: send_jump.clone(),
        },
        Config {
            address: Ipv4Address::new(10, 0, 2, 15),
            prefix_len: 24,
            gateway: None,
            rx_buffer: 8192,
            tx_buffer: 8192,
        },
    )
    .unwrap();
    let e = owner.stream_server_grant(grant(7005)).unwrap();
    owner.stream_listen(e).unwrap();
    let _peer = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7005, 42030)
        .unwrap();
    let mut accepted = false;
    for _ in 0..1000 {
        step(&wire, &mut owner, &mut client);
        if owner.stream_accept(e).is_ok() {
            accepted = true;
            break;
        }
    }
    assert!(accepted);
    owner.stream_write(e, b"first-effect").unwrap();
    wire.borrow_mut().queues[1].clear();
    send_jump.set(10001);
    owner.poll();
    assert!(
        wire.borrow().queues[1]
            .iter()
            .any(|f| f.windows(12).any(|b| b == b"first-effect"))
    );
    let frames = wire.borrow().queues[1].len();
    owner.poll();
    assert_eq!(wire.borrow().queues[1].len(), frames);
    assert_eq!(owner.socket_count(), 0);
    assert_eq!(owner.stream_status(e), Err(s::Error::Timeout));
}

struct IoRefusal {
    end: End,
    rx_error: Rc<std::cell::Cell<i64>>,
    tx_error: Rc<std::cell::Cell<i64>>,
    submissions: Rc<std::cell::Cell<usize>>,
    uncertain_effect: bool,
}
impl Link for IoRefusal {
    fn mac(&self) -> [u8; 6] {
        self.end.mac()
    }
    fn send(&mut self, bytes: &[u8]) -> Result<(), i64> {
        self.submissions.set(self.submissions.get() + 1);
        let error = self.tx_error.replace(0);
        if error != 0 {
            if self.uncertain_effect {
                self.end.send(bytes)?;
            }
            Err(error)
        } else {
            self.end.send(bytes)
        }
    }
    fn receive(&mut self, bytes: &mut [u8; FRAME_MAX], timeout: u64) -> Result<Option<usize>, i64> {
        let error = self.rx_error.replace(0);
        if error != 0 {
            Err(error)
        } else {
            self.end.receive(bytes, timeout)
        }
    }
    fn now_ms(&self) -> u64 {
        self.end.now_ms()
    }
    fn pause(&self, n: u64) {
        self.end.pause(n)
    }
    // Link::read deliberately stays healthy after either transient refusal.
}
fn io_refusal_pair(
    uncertain_effect: bool,
) -> (Rc<RefCell<Wire>>, Stack<IoRefusal>, Stack<End>, s::Endpoint) {
    let (wire, _unused, mut client) = pair(0);
    let mut owner = Stack::open(
        IoRefusal {
            end: End {
                wire: wire.clone(),
                side: 0,
                mac: [2, 0, 0, 0, 0, 15],
            },
            rx_error: Rc::new(std::cell::Cell::new(0)),
            tx_error: Rc::new(std::cell::Cell::new(0)),
            submissions: Rc::new(std::cell::Cell::new(0)),
            uncertain_effect,
        },
        Config {
            address: Ipv4Address::new(10, 0, 2, 15),
            prefix_len: 24,
            gateway: None,
            rx_buffer: 8192,
            tx_buffer: 8192,
        },
    )
    .unwrap();
    let e = owner.stream_server_grant(grant(7005)).unwrap();
    owner.stream_listen(e).unwrap();
    client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7005, 42030)
        .unwrap();
    for _ in 0..1000 {
        step(&wire, &mut owner, &mut client);
        if owner.stream_accept(e).is_ok() {
            wire.borrow_mut().queues[1].clear();
            owner.port.link.submissions.set(0);
            return (wire, owner, client, e);
        }
    }
    panic!("fixture handshake did not complete")
}
#[test]
fn failed_send_retains_only_its_possible_first_effect_with_healthy_link_read() {
    for code in [-5, NIC_NO_CARRIER] {
        for uncertain in [false, true] {
            let (wire, mut owner, _client, e) = io_refusal_pair(uncertain);
            for _ in 0..4 {
                owner.stream_write(e, &[0x5a; 1024]).unwrap();
            }
            owner.port.link.tx_error.set(code);
            let now = owner.now();
            // Deliberately exercise Interface directly: final Stack cleanup
            // cannot conceal later submissions within the same dispatch.
            owner.iface.poll(now, &mut owner.port, &mut owner.sockets);
            owner.iface.poll(now, &mut owner.port, &mut owner.sockets);
            assert_eq!(owner.port.link.submissions.get(), 1);
            assert_eq!(applications(&wire.borrow()), usize::from(uncertain));
            assert!(owner.port.link.read().unwrap().link_up);
            owner.poll();
            assert_eq!(owner.socket_count(), 0);
            assert_eq!(owner.port.link.submissions.get(), 1);
        }
    }
}
#[test]
fn receive_refusal_fences_queued_egress_before_interface_dispatch() {
    for code in [-5, NIC_NO_CARRIER] {
        let (wire, mut owner, _client, e) = io_refusal_pair(false);
        owner
            .stream_write(e, b"queued-before-receive-error")
            .unwrap();
        owner.port.link.rx_error.set(code);
        let now = owner.now();
        owner.iface.poll(now, &mut owner.port, &mut owner.sockets);
        assert!(owner.port.link.read().unwrap().link_up);
        assert_eq!(owner.port.link.submissions.get(), 0);
        assert_eq!(applications(&wire.borrow()), 0);
        owner.poll();
        assert_eq!(owner.socket_count(), 0);
        assert_eq!(owner.port.link.submissions.get(), 0);
    }
}

struct ReplyFixture {
    bytes: VecDeque<u8>,
    written: Vec<u8>,
    wire: Rc<RefCell<Wire>>,
    now: u64,
    jump_on_write: Option<u64>,
    reads: usize,
    eof: bool,
}
impl datagram::channel::Pipe for ReplyFixture {
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        self.reads += 1;
        if self.bytes.is_empty() {
            return Ok(if self.eof { Some(0) } else { None });
        }
        let n = bytes.len().min(self.bytes.len());
        for byte in &mut bytes[..n] {
            *byte = self.bytes.pop_front().unwrap();
        }
        Ok(Some(n))
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        self.written.extend_from_slice(bytes);
        if let Some(now) = self.jump_on_write.take() {
            self.wire.borrow_mut().now_ms = now;
        }
        Ok(Some(bytes.len()))
    }
    fn now_ms(&self) -> u64 {
        self.now
    }
}
fn server_request(op: u8, length: u16) -> Vec<u8> {
    let mut body = vec![3, op, 0, 4, 10, 0, 2, 2, 0xa4, 0x2e, 0, 0];
    body[10..12].copy_from_slice(&length.to_be_bytes());
    framed(&body)
}
fn pending_read_reply() -> (
    Rc<RefCell<Wire>>,
    Stack<End>,
    Stack<End>,
    v::Channel,
    ReplyFixture,
) {
    let (wire, mut owner, mut client) = pair(0);
    let mut channel = v::Channel::grant(&mut owner, grant(7005)).unwrap();
    let mut pipe = ReplyFixture {
        bytes: server_request(v::LISTEN, 0).into(),
        written: Vec::new(),
        wire: wire.clone(),
        now: 100,
        jump_on_write: None,
        reads: 0,
        eof: false,
    };
    for _ in 0..3 {
        assert!(channel.poll(&mut owner, &mut pipe));
    }
    assert_eq!(pipe.written[4], 0);
    pipe.written.clear();
    let peer = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7005, 42030)
        .unwrap();
    for _ in 0..100 {
        step(&wire, &mut owner, &mut client);
    }
    pipe.bytes.extend(server_request(v::ACCEPT, 0));
    for _ in 0..3 {
        assert!(channel.poll(&mut owner, &mut pipe));
    }
    assert_eq!(pipe.written[4], 0);
    pipe.written.clear();
    client.send(peer, b"private-response").unwrap();
    for _ in 0..100 {
        step(&wire, &mut owner, &mut client);
    }
    wire.borrow_mut().now_ms = 9999;
    pipe.bytes.extend(server_request(s::READ, 64));
    // READ takes actual accepted TCP data into pending pipe output, but no
    // reply byte is submitted yet. Its frame deadline is still in the future.
    assert!(channel.poll(&mut owner, &mut pipe));
    assert!(channel.poll(&mut owner, &mut pipe));
    assert!(pipe.written.is_empty());
    (wire, owner, client, channel, pipe)
}
#[test]
fn pending_read_reply_cannot_outlive_endpoint_authority() {
    for boundary in 0..4 {
        let (wire, mut owner, _client, mut channel, mut pipe) = pending_read_reply();
        match boundary {
            0 => wire.borrow_mut().now_ms = 10001,
            1 => wire.borrow_mut().now_ms = 9998,
            2 => v::observe_error(&mut owner.port.server_rules, -5),
            _ => owner.stream_server_fence(),
        }
        let reads = pipe.reads;
        assert!(!channel.poll(&mut owner, &mut pipe));
        assert!(!channel.poll(&mut owner, &mut pipe));
        assert!(pipe.written.is_empty());
        assert_eq!(pipe.reads, reads);
        assert_eq!(owner.socket_count(), 0);
    }
}
#[test]
fn pipe_write_crossing_authority_bound_keeps_only_its_first_effect() {
    let (_wire, mut owner, _client, mut channel, mut pipe) = pending_read_reply();
    pipe.jump_on_write = Some(10001);
    assert!(!channel.poll(&mut owner, &mut pipe));
    assert!(pipe.written.windows(16).any(|b| b == b"private-response"));
    let first = pipe.written.clone();
    assert!(!channel.poll(&mut owner, &mut pipe));
    assert_eq!(pipe.written, first);
    assert_eq!(owner.socket_count(), 0);
}
#[test]
fn fresh_pipe_read_requires_live_endpoint_and_close_ack_keeps_bounded_drain() {
    let (wire, mut owner, _) = pair(0);
    let mut channel = v::Channel::grant(&mut owner, grant(7005)).unwrap();
    let mut pipe = ReplyFixture {
        bytes: server_request(v::LISTEN, 0).into(),
        written: Vec::new(),
        wire,
        now: 100,
        jump_on_write: None,
        reads: 0,
        eof: false,
    };
    v::observe_error(&mut owner.port.server_rules, -5);
    assert!(!channel.poll(&mut owner, &mut pipe));
    assert_eq!(pipe.reads, 0);
    let (_wire, mut owner, _client, mut channel, mut pipe) = pending_read_reply();
    assert!(channel.poll(&mut owner, &mut pipe));
    pipe.written.clear();
    pipe.bytes.extend(server_request(s::CLOSE, 0));
    for _ in 0..3 {
        assert!(channel.poll(&mut owner, &mut pipe));
    }
    assert_eq!(pipe.written.len(), 14);
    assert_eq!(pipe.written[4], 0);
    assert_eq!(owner.socket_count(), 1);
    pipe.eof = true;
    assert!(!channel.poll(&mut owner, &mut pipe));
    assert_eq!(owner.socket_count(), 1);
    owner.stream_server_fence();
    assert_eq!(owner.socket_count(), 0);
}
#[test]
fn pending_close_ack_cannot_survive_expiry_rewind_or_explicit_fence() {
    for boundary in 0..4 {
        let (wire, mut owner, _client, mut channel, mut pipe) = pending_read_reply();
        assert!(channel.poll(&mut owner, &mut pipe));
        pipe.written.clear();
        pipe.bytes.extend(server_request(s::CLOSE, 0));
        assert!(channel.poll(&mut owner, &mut pipe));
        assert!(channel.poll(&mut owner, &mut pipe));
        match boundary {
            0 => wire.borrow_mut().now_ms = 10001,
            1 => wire.borrow_mut().now_ms = 9998,
            2 => owner.stream_fence(),
            _ => owner.stream_server_fence(),
        }
        assert!(!channel.poll(&mut owner, &mut pipe));
        assert!(pipe.written.is_empty());
        assert_eq!(owner.socket_count(), 0);
    }
}
#[test]
fn old_pending_channel_cannot_discard_an_explicit_new_generation() {
    let (_wire, mut owner, _client, mut channel, mut pipe) = pending_read_reply();
    owner.stream_server_fence();
    let fresh = owner.stream_server_grant(grant(7005)).unwrap();
    assert!(!channel.poll(&mut owner, &mut pipe));
    assert!(pipe.written.is_empty());
    owner.stream_listen(fresh).unwrap();
    assert_eq!(owner.socket_count(), 1);
    owner.stream_server_fence();
}

struct ClientPipe {
    incoming: VecDeque<u8>,
    written: Rc<RefCell<Vec<u8>>>,
}
impl datagram::channel::Pipe for ClientPipe {
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        let n = b.len().min(self.incoming.len());
        for x in &mut b[..n] {
            *x = self.incoming.pop_front().unwrap()
        }
        Ok(Some(n))
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        self.written.borrow_mut().extend_from_slice(b);
        Ok(Some(b.len()))
    }
    fn now_ms(&self) -> u64 {
        100
    }
}
fn framed(reply: &[u8]) -> Vec<u8> {
    let mut b = (reply.len() as u16).to_be_bytes().to_vec();
    b.extend_from_slice(reply);
    b
}
#[test]
fn typed_client_waits_for_accept_and_fences_a_wrong_version_reply() {
    let header = [3, 32, 0, 4, 10, 0, 2, 2, 0xa4, 0x2e, 0, 1, 0];
    let mut replies = framed(&header);
    let mut again = header[..12].to_vec();
    again[1] = 33;
    again[2] = 5;
    again[11] = 0;
    replies.extend(framed(&again));
    let mut ready = header;
    ready[1] = 33;
    ready[12] = 1;
    replies.extend(framed(&ready));
    let written = Rc::new(RefCell::new(Vec::new()));
    let mut client = v::Client::new(
        ClientPipe {
            incoming: replies.into(),
            written: written.clone(),
        },
        grant(7005).peer,
        |_| {},
    );
    assert_eq!(client.read(&mut [0; 1], 1000), Err(s::Error::Again));
    client.accept(1000).unwrap();
    assert_eq!(client.accept(1000), Err(s::Error::Invalid));
    let bytes = written.borrow();
    assert_eq!(bytes.len(), 42);
    assert_eq!((bytes[3], bytes[17], bytes[31]), (32, 33, 33));
    assert_eq!(
        &bytes[..14],
        &[0, 12, 3, 32, 0, 4, 10, 0, 2, 2, 0xa4, 0x2e, 0, 0]
    );
    drop(bytes);
    let mut wrong = header;
    wrong[0] = 1;
    wrong[3] = 0;
    let written = Rc::new(RefCell::new(Vec::new()));
    let mut client = v::Client::new(
        ClientPipe {
            incoming: framed(&wrong).into(),
            written: written.clone(),
        },
        grant(7005).peer,
        |_| {},
    );
    assert_eq!(client.accept(1000), Err(s::Error::Channel(-22)));
    let before = written.borrow().len();
    assert_eq!(client.accept(1000), Err(s::Error::Stale));
    assert_eq!(written.borrow().len(), before);
}

#[test]
fn session_cancellation_discards_a_connected_queued_write() {
    let (wire, mut owner, mut client) = pair(0);
    let mut session = v::Session::grant(&mut owner, grant(7005)).unwrap();
    let mut request = vec![3, 32, 0, 4, 10, 0, 2, 2, 0xa4, 0x2e, 0, 0];
    let mut reply = [0; datagram::MAX_MESSAGE];
    session.request(&mut owner, &request, &mut reply);
    assert_eq!(reply[2], 0);
    let _peer = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7005, 42030)
        .unwrap();
    request[1] = v::ACCEPT;
    let mut accepted = false;
    for _ in 0..1000 {
        step(&wire, &mut owner, &mut client);
        session.request(&mut owner, &request, &mut reply);
        if reply[2] == 0 {
            accepted = true;
            break;
        }
    }
    assert!(accepted);
    request[1] = s::WRITE;
    request[11] = 15;
    request.extend_from_slice(b"discard-on-eof");
    // The literal length deliberately mismatches first: no partial WRITE.
    session.request(&mut owner, &request, &mut reply);
    assert_eq!(reply[2], s::Error::Invalid.code());
    request[11] = 14;
    session.request(&mut owner, &request, &mut reply);
    assert_eq!(reply[2], 0);
    wire.borrow_mut().queues[1].clear();
    session.revoke(&mut owner);
    session.revoke(&mut owner);
    owner.poll();
    assert_eq!(owner.socket_count(), 0);
    assert_eq!(applications(&wire.borrow()), 0);
    assert!(owner.port.server_rules.iter().all(Option::is_none));
}

#[test]
fn accept_uses_existing_identity_and_original_lifetime_without_early_io() {
    let (wire, mut owner, mut client) = pair(0);
    let mut g = grant(7005);
    g.accept_timeout_ms = 10000;
    let e = owner.stream_server_grant(g).unwrap();
    owner.stream_listen(e).unwrap();
    let _peer = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7005, 42030)
        .unwrap();
    let mut connected = false;
    for _ in 0..1000 {
        step(&wire, &mut owner, &mut client);
        if owner.stream_status(e).unwrap().connected {
            connected = true;
            break;
        }
    }
    assert!(connected);
    assert_eq!(owner.stream_read(e, &mut [0; 1]), Err(s::Error::Again));
    assert_eq!(owner.stream_write(e, b"early"), Err(s::Error::Again));
    wire.borrow_mut().now_ms = 9999;
    assert!(owner.stream_accept(e).unwrap().connected);
    wire.borrow_mut().now_ms = 10001;
    assert_eq!(owner.stream_status(e), Err(s::Error::Timeout));
    assert_eq!(owner.socket_count(), 0);
}
#[test]
fn literal_v3_header_and_malformed_requests_execute_no_listen() {
    let (_, mut owner, _) = pair(0);
    let mut session = v::Session::grant(&mut owner, grant(7005)).unwrap();
    let listen = [3, 32, 0, 4, 10, 0, 2, 2, 0xa4, 0x2e, 0, 0]; // 42030 big endian.
    let mut reply = [0; datagram::MAX_MESSAGE];
    for (at, value) in [(0, 1), (2, 1), (3, 6), (10, 1)] {
        let mut bad = listen;
        bad[at] = value;
        assert_eq!(session.request(&mut owner, &bad, &mut reply), 12);
        assert_eq!(reply[2], s::Error::Invalid.code());
        assert_eq!(owner.socket_count(), 0);
    }
    let mut bad = listen;
    bad[9] ^= 1;
    session.request(&mut owner, &bad, &mut reply);
    assert_eq!(reply[2], s::Error::Denied.code());
    assert_eq!(session.request(&mut owner, &listen, &mut reply), 13);
    assert_eq!(
        &reply[..13],
        &[3, 32, 0, 4, 10, 0, 2, 2, 0xa4, 0x2e, 0, 1, 0]
    );
    session.request(&mut owner, &listen, &mut reply);
    assert_eq!(reply[2], s::Error::Invalid.code());
    session.revoke(&mut owner);
    assert_eq!(owner.socket_count(), 0);
}
#[test]
fn half_close_echo_backpressure_and_eof_remain_distinct() {
    let (wire, mut owner, mut client, peer, e) = connected();
    assert_eq!(client.send(peer, b"request").unwrap(), 7);
    client.close(peer).unwrap();
    let mut input = Vec::new();
    let mut b = [0; 128];
    let mut eof = false;
    for _ in 0..2000 {
        step(&wire, &mut owner, &mut client);
        match owner.stream_read(e, &mut b) {
            Ok(n) => input.extend_from_slice(&b[..n]),
            Err(s::Error::Again) => {}
            Err(s::Error::Eof) => {
                eof = true;
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(eof);
    assert_eq!(input, b"request");
    let block = [0x55; s::MAX_IO];
    let mut total = 0;
    loop {
        match owner.stream_write(e, &block) {
            Ok(n) => total += n,
            Err(s::Error::Again) => break,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(total, s::BUFFER_BYTES);
    owner.stream_shutdown_write(e).unwrap();
    assert_eq!(owner.stream_write(e, b"late"), Err(s::Error::WriteClosed));
    owner.stream_close(e).unwrap();
    assert_eq!(owner.stream_read(e, &mut b), Err(s::Error::Stale));
    owner.stream_server_fence();
    assert_eq!(owner.socket_count(), 0);
}
#[test]
fn accept_and_lifetime_bounds_discard_queued_bytes_without_rearming() {
    let (wire, mut owner, mut client) = pair(0);
    let e = owner.stream_server_grant(grant(7005)).unwrap();
    owner.stream_listen(e).unwrap();
    wire.borrow_mut().now_ms += 1000;
    assert_eq!(owner.stream_accept(e), Err(s::Error::Timeout));
    assert_eq!(owner.socket_count(), 0);
    let (wire, mut owner, mut client, _peer, e) = connected();
    owner.stream_write(e, b"must-not-emit").unwrap();
    owner.stream_close(e).unwrap();
    wire.borrow_mut().queues[1].clear();
    wire.borrow_mut().now_ms = 10001;
    owner.poll();
    owner.poll();
    assert_eq!(owner.socket_count(), 0);
    assert_eq!(applications(&wire.borrow()), 0);
    assert_eq!(owner.stream_status(e), Err(s::Error::Stale));
    let _ = &mut client;
}
#[test]
fn closing_only_rewind_and_explicit_fence_drop_queues() {
    let (wire, mut owner, _client, _peer, e) = connected();
    owner.stream_write(e, b"queued").unwrap();
    owner.stream_close(e).unwrap();
    wire.borrow_mut().queues[1].clear();
    wire.borrow_mut().now_ms = 0;
    owner.poll();
    owner.poll();
    assert_eq!(owner.socket_count(), 0);
    assert_eq!(applications(&wire.borrow()), 0);
    assert_eq!(owner.stream_accept(e), Err(s::Error::Stale));
}

struct PipeFixture {
    now: Rc<RefCell<u64>>,
    bytes: VecDeque<u8>,
    eof: bool,
    advance: Option<u64>,
}
impl datagram::channel::Pipe for PipeFixture {
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        if let Some(now) = self.advance.take() {
            *self.now.borrow_mut() = now
        }
        if self.bytes.is_empty() {
            return Ok(if self.eof { Some(0) } else { None });
        }
        let n = b.len().min(self.bytes.len());
        for x in &mut b[..n] {
            *x = self.bytes.pop_front().unwrap()
        }
        Ok(Some(n))
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        Ok(Some(b.len()))
    }
    fn now_ms(&self) -> u64 {
        *self.now.borrow()
    }
}
#[test]
fn eof_partial_expiry_rewind_and_late_completion_revoke_the_channel() {
    for mode in 0..4 {
        let (_, mut owner, _) = pair(0);
        let mut channel = v::Channel::grant(&mut owner, grant(7005)).unwrap();
        let clock = Rc::new(RefCell::new(100));
        let mut pipe = PipeFixture {
            now: clock.clone(),
            bytes: VecDeque::new(),
            eof: mode == 0,
            advance: None,
        };
        if mode > 0 {
            pipe.bytes.push_back(0);
            assert!(channel.poll(&mut owner, &mut pipe));
            *clock.borrow_mut() = if mode == 1 {
                350
            } else if mode == 2 {
                99
            } else {
                101
            };
            if mode == 3 {
                pipe.bytes.push_back(12);
                pipe.advance = Some(350)
            }
        }
        assert!(!channel.poll(&mut owner, &mut pipe));
        assert_eq!(owner.socket_count(), 0);
        assert!(owner.port.server_rules.iter().all(Option::is_none));
        assert!(owner.stream_server_grant(grant(7005)).is_ok());
    }
}
