//! Actual smoltcp pair plus bounded pipe controls. Runtime execution is separate.
use super::*;
use std::cell::RefCell;
use std::rc::Rc;

struct Wire {
    queues: [VecDeque<Vec<u8>>; 2],
    frames: [Vec<Vec<u8>>; 2],
    now: u64,
    link: Option<LinkReading>,
    send_error: Option<i64>,
    read_calls: usize,
}
struct End {
    wire: Rc<RefCell<Wire>>,
    side: usize,
}
impl Link for End {
    fn mac(&self) -> [u8; 6] {
        [2, 0, 0, 0, 0, self.side as u8 + 1]
    }
    fn send(&mut self, frame: &[u8]) -> Result<(), i64> {
        let mut w = self.wire.borrow_mut();
        if let Some(e) = w.send_error {
            return Err(e);
        }
        w.frames[self.side].push(frame.to_vec());
        w.queues[1 - self.side].push_back(frame.to_vec());
        Ok(())
    }
    fn receive(&mut self, out: &mut [u8; FRAME_MAX], _: u64) -> Result<Option<usize>, i64> {
        Ok(self.wire.borrow_mut().queues[self.side]
            .pop_front()
            .map(|f| {
                out[..f.len()].copy_from_slice(&f);
                f.len()
            }))
    }
    fn now_ms(&self) -> u64 {
        self.wire.borrow().now
    }
    fn pause(&self, ms: u64) {
        self.wire.borrow_mut().now += ms;
    }
    fn read(&self) -> Option<LinkReading> {
        self.wire.borrow_mut().read_calls += 1;
        self.wire.borrow().link
    }
}
fn ip(n: u8) -> [u8; 16] {
    let mut a = [0; 16];
    a[..4].copy_from_slice(&[0xfd, 0, 0xab, 0x5d]);
    a[15] = n;
    a
}
fn peer(n: u8, port: u16) -> Address {
    Address {
        ip: ip(n),
        port,
        scope: 1,
    }
}
fn grant(port: u16) -> Grant {
    Grant {
        local_port: port,
        peer: peer(2, 42030),
        accept_timeout_ms: 1000,
        lifetime_ms: 10000,
    }
}
struct Pair {
    wire: Rc<RefCell<Wire>>,
    server: Stack<End>,
    client: Stack<End>,
}
impl Pair {
    fn new() -> Self {
        let wire = Rc::new(RefCell::new(Wire {
            queues: [VecDeque::new(), VecDeque::new()],
            frames: [vec![], vec![]],
            now: 100,
            link: Some(LinkReading {
                link_up: true,
                disabled: false,
                rx_missed: 0,
            }),
            send_error: None,
            read_calls: 0,
        }));
        let stack = |side| {
            let mut s = Stack::open(
                End {
                    wire: wire.clone(),
                    side,
                },
                crate::Config::qemu_user(),
            )
            .unwrap();
            s.configure_ipv6(super::super::super::Config {
                address: ip(side as u8 + 1),
                prefix_len: 64,
                scope: 1,
            })
            .unwrap();
            s
        };
        let server = stack(0);
        let client = stack(1);
        Self {
            wire,
            server,
            client,
        }
    }
    fn step(&mut self) {
        self.client.poll();
        self.server.poll();
        self.wire.borrow_mut().now += 1;
    }
    fn connect(&mut self) -> (Endpoint, Endpoint) {
        let s = self.server.ipv6_stream_server_grant(grant(7005)).unwrap();
        self.server.ipv6_stream_listen(s).unwrap();
        let c = self
            .client
            .ipv6_stream_grant(super::super::Grant {
                local_port: 42030,
                peer: peer(1, 7005),
                connect_timeout_ms: 1000,
                lifetime_ms: 10000,
            })
            .unwrap();
        self.client.ipv6_stream_connect(c).unwrap();
        for _ in 0..500 {
            self.step();
            if self.server.ipv6_stream_accept(s).is_ok() {
                return (s, c);
            }
        }
        panic!("exact native IPv6 pair did not establish");
    }
}
fn request(op: u8) -> [u8; HEADER] {
    let mut b = [0; HEADER];
    b[0] = VERSION;
    b[1] = op;
    b[3] = FAMILY;
    b[4..20].copy_from_slice(&ip(2));
    b[20..24].copy_from_slice(&1u32.to_be_bytes());
    b[24..26].copy_from_slice(&42030u16.to_be_bytes());
    b
}
fn frame() -> [u8; 74] {
    let mut b = [0; 74];
    b[12..14].copy_from_slice(&[0x86, 0xdd]);
    b[14] = 0x60;
    b[18..20].copy_from_slice(&20u16.to_be_bytes());
    b[20] = 6;
    b[21] = 64;
    b[22..38].copy_from_slice(&ip(2));
    b[38..54].copy_from_slice(&ip(1));
    b[54..56].copy_from_slice(&42030u16.to_be_bytes());
    b[56..58].copy_from_slice(&7005u16.to_be_bytes());
    b[66] = 0x50;
    b[67] = 2;
    b
}
fn vector(name: &str) -> Vec<u8> {
    let text = include_str!("../../../../../fixtures/native-ipv6-tcp-server/wire-v3.txt");
    let hex = text
        .lines()
        .find_map(|l| l.strip_prefix(&std::format!("{name}=")))
        .unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn reserved_grant_has_no_socket_tcp_or_nd_until_listen() {
    let mut p = Pair::new();
    let e = p.server.ipv6_stream_server_grant(grant(7005)).unwrap();
    for _ in 0..5 {
        p.step();
    }
    assert_eq!(p.server.socket_count(), 0);
    assert!(p.server.port.ipv6_tcp_peers.iter().all(Option::is_none));
    assert!(p.wire.borrow().frames[0].is_empty());
    assert!(!p.server.port.ipv6_cached_ingress(&frame()));
    p.server.ipv6_stream_listen(e).unwrap();
    assert!(p.server.port.ipv6_cached_ingress(&frame()));
    assert_eq!(p.server.socket_count(), 1);
}
#[test]
fn grants_are_exact_onlink_scoped_and_bounded() {
    let mut p = Pair::new();
    for mut g in [grant(0), grant(53), grant(1023)] {
        assert_eq!(p.server.ipv6_stream_server_grant(g), Err(Error::Denied));
        g.local_port = 7005;
        g.peer.port = 0;
        assert_eq!(p.server.ipv6_stream_server_grant(g), Err(Error::Denied));
    }
    for (address, scope) in [
        (ip(1), 1),
        ([0; 16], 1),
        (
            {
                let mut a = ip(2);
                a[0] = 0xff;
                a
            },
            1,
        ),
        (
            {
                let mut a = ip(2);
                a[7] = 1;
                a
            },
            1,
        ),
        (ip(2), 0),
        (ip(2), 2),
    ] {
        let mut g = grant(7005);
        g.peer.ip = address;
        g.peer.scope = scope;
        assert_eq!(p.server.ipv6_stream_server_grant(g), Err(Error::Denied));
    }
    for (accept, life) in [(99, 10000), (10001, 20000), (1000, 999), (1000, 60001)] {
        let mut g = grant(7005);
        g.accept_timeout_ms = accept;
        g.lifetime_ms = life;
        assert_eq!(p.server.ipv6_stream_server_grant(g), Err(Error::Invalid));
    }
    assert_eq!(p.server.socket_count(), 0);
    assert!(p.wire.borrow().frames[0].is_empty());
}
#[test]
fn shared_slots_duplicates_foreign_epochs_and_overflow_refuse() {
    let mut p = Pair::new();
    let old = p.server.ipv6_stream_server_grant(grant(7005)).unwrap();
    assert_eq!(
        p.server.ipv6_stream_grant(super::super::Grant {
            local_port: 7005,
            peer: peer(2, 42030),
            connect_timeout_ms: 1000,
            lifetime_ms: 10000
        }),
        Err(Error::InUse)
    );
    for port in 7006..7013 {
        p.server.ipv6_stream_server_grant(grant(port)).unwrap();
    }
    assert_eq!(
        p.server.ipv6_stream_server_grant(grant(7013)),
        Err(Error::Exhausted)
    );
    assert_eq!(p.client.ipv6_stream_listen(old), Err(Error::Stale));
    p.server.ipv6_stream_abort(old).unwrap();
    let fresh = p.server.ipv6_stream_server_grant(grant(7005)).unwrap();
    assert_ne!(old, fresh);
    assert_eq!(p.server.ipv6_stream_listen(old), Err(Error::Stale));
    p.server.ipv6_stream_server_fence();
    p.server.ipv6_streams.set_epoch_for_test(u64::MAX);
    assert_eq!(
        p.server.ipv6_stream_server_grant(grant(7005)),
        Err(Error::Exhausted)
    );
    let mut p = Pair::new();
    p.wire.borrow_mut().now = u64::MAX - 50;
    assert_eq!(
        p.server.ipv6_stream_server_grant(grant(7005)),
        Err(Error::Invalid)
    );
}
#[test]
fn outbound_endpoint_cannot_listen_and_server_cannot_connect() {
    let mut p = Pair::new();
    let s = p.server.ipv6_stream_server_grant(grant(7005)).unwrap();
    assert_eq!(p.server.ipv6_stream_connect(s), Err(Error::Invalid));
    let c = p
        .client
        .ipv6_stream_grant(super::super::Grant {
            local_port: 42030,
            peer: peer(1, 7005),
            connect_timeout_ms: 1000,
            lifetime_ms: 10000,
        })
        .unwrap();
    assert_eq!(p.client.ipv6_stream_listen(c), Err(Error::Invalid));
    assert_eq!(p.server.ipv6_stream_accept(s), Err(Error::Invalid));
}
#[test]
fn wrong_source_syn_cannot_occupy_then_exact_client_connects() {
    let mut p = Pair::new();
    let s = p.server.ipv6_stream_server_grant(grant(7005)).unwrap();
    p.server.ipv6_stream_listen(s).unwrap();
    let wrong = p
        .client
        .ipv6_stream_grant(super::super::Grant {
            local_port: 42031,
            peer: peer(1, 7005),
            connect_timeout_ms: 1000,
            lifetime_ms: 10000,
        })
        .unwrap();
    p.client.ipv6_stream_connect(wrong).unwrap();
    for _ in 0..100 {
        p.step();
    }
    assert_eq!(p.server.ipv6_stream_accept(s), Err(Error::Again));
    assert_eq!(
        p.server
            .sockets
            .get::<tcp::Socket>(p.server.ipv6_streams.entries[s.slot].socket.unwrap())
            .state(),
        TcpState::Listen
    );
    assert!(
        !p.wire.borrow().frames[0]
            .iter()
            .any(|f| f.len() > 57 && f[20] == 6)
    );
    p.client.ipv6_stream_abort(wrong).unwrap();
    let c = p
        .client
        .ipv6_stream_grant(super::super::Grant {
            local_port: 42030,
            peer: peer(1, 7005),
            connect_timeout_ms: 1000,
            lifetime_ms: 10000,
        })
        .unwrap();
    p.client.ipv6_stream_connect(c).unwrap();
    let mut ok = false;
    for _ in 0..500 {
        p.step();
        if p.server.ipv6_stream_accept(s).is_ok() {
            ok = true;
            break;
        }
    }
    assert!(ok);
    assert_eq!(p.server.ipv6_stream_accept(s), Err(Error::Invalid));
}
#[test]
fn tuple_scope_no_flow_and_cached_tcp_are_rechecked() {
    let mut p = Pair::new();
    let e = p.server.ipv6_stream_server_grant(grant(7005)).unwrap();
    let f = frame();
    assert!(!p.server.port.ipv6_cached_ingress(&f));
    p.server.ipv6_stream_listen(e).unwrap();
    assert!(p.server.port.ipv6_cached_ingress(&f));
    for at in [22, 38, 54, 56] {
        let mut bad = f;
        bad[at] ^= 1;
        assert!(!p.server.port.ipv6_cached_ingress(&bad));
    }
    p.server.port.ipv6_config.as_mut().unwrap().scope = 2;
    assert!(!p.server.port.ipv6_cached_ingress(&f));
    p.server.port.ipv6_config.as_mut().unwrap().scope = 1;
    p.wire.borrow_mut().queues[0].push_back(f.to_vec());
    assert_eq!(p.server.port.fill(0), Ok(true));
    p.server.ipv6_stream_server_fence();
    assert!(phy::Device::receive(&mut p.server.port, Instant::from_millis(100)).is_none());
    assert_eq!(p.server.port.rx_length, None);
}
#[test]
fn configured_address_ns_maintenance_is_separate_from_server_flow_authority() {
    let mut p = Pair::new();
    let e = p.server.ipv6_stream_server_grant(grant(7005)).unwrap();
    let c = p
        .client
        .ipv6_stream_grant(super::super::Grant {
            local_port: 42030,
            peer: peer(1, 7005),
            connect_timeout_ms: 1000,
            lifetime_ms: 10000,
        })
        .unwrap();
    p.client.ipv6_stream_connect(c).unwrap();
    p.client.poll();
    let ns = p.wire.borrow().frames[1]
        .iter()
        .find(|f| f.len() > 54 && f[20] == 58 && f[54] == 135)
        .unwrap()
        .clone();
    assert!(p.server.port.ipv6_cached_ingress(&ns));
    assert!(!p.server.port.ipv6_cached_ingress(&frame()));
    p.server.poll();
    assert_eq!(p.server.socket_count(), 0);
    assert!(
        p.wire.borrow().frames[0]
            .iter()
            .any(|f| f.len() > 54 && f[20] == 58 && f[54] == 136)
    );
    p.server.ipv6_stream_listen(e).unwrap();
    assert!(p.server.port.ipv6_cached_ingress(&frame()));
    p.server.ipv6_stream_server_fence();
    assert!(p.server.port.ipv6_cached_ingress(&ns));
    assert!(!p.server.port.ipv6_cached_ingress(&frame()));
    let before = p.wire.borrow().frames[0].len();
    p.wire.borrow_mut().queues[0].push_back(ns);
    p.server.poll();
    assert_eq!(p.server.socket_count(), 0);
    assert!(
        p.wire.borrow().frames[0][before..]
            .iter()
            .any(|f| f.len() > 54 && f[20] == 58 && f[54] == 136)
    );
    assert!(
        !p.wire.borrow().frames[0][before..]
            .iter()
            .any(|f| f.len() > 54 && f[20] == 6)
    );
}
#[test]
fn actual_half_close_echo_preserves_bytes_and_fin_drain() {
    let mut p = Pair::new();
    let (s, c) = p.connect();
    assert_eq!(p.client.ipv6_stream_write(c, b"bounded echo"), Ok(12));
    p.client.ipv6_stream_shutdown_write(c).unwrap();
    let mut body = vec![];
    let mut echo = vec![];
    let mut server_fin = false;
    for _ in 0..500 {
        p.step();
        let mut b = [0; 64];
        match p.server.ipv6_stream_read(s, &mut b) {
            Ok(n) => {
                body.extend_from_slice(&b[..n]);
                assert_eq!(p.server.ipv6_stream_write(s, &b[..n]), Ok(n));
            }
            Err(Error::Eof) if !server_fin => {
                p.server.ipv6_stream_shutdown_write(s).unwrap();
                server_fin = true;
            }
            _ => {}
        }
        match p.client.ipv6_stream_read(c, &mut b) {
            Ok(n) => echo.extend_from_slice(&b[..n]),
            Err(Error::Eof) => break,
            _ => {}
        }
    }
    assert_eq!(body, b"bounded echo");
    assert_eq!(echo, body);
    assert!(server_fin);
    p.server.ipv6_stream_close(s).unwrap();
    assert!(p.server.ipv6_stream_write(s, b"late").is_err());
    for _ in 0..500 {
        p.step();
        if p.server.socket_count() == 0 {
            break;
        }
    }
    p.server.ipv6_stream_server_fence();
    assert_eq!(p.server.socket_count(), 0);
    assert!(p.server.port.ipv6_tcp_peers.iter().all(Option::is_none));
}
#[test]
fn accept_and_lifetime_are_original_and_faults_spend_queues() {
    for kind in 0..5 {
        let mut p = Pair::new();
        let e = p.server.ipv6_stream_server_grant(grant(7005)).unwrap();
        p.server.ipv6_stream_listen(e).unwrap();
        match kind {
            0 => p.wire.borrow_mut().now = 1100,
            1 => p.wire.borrow_mut().now = 99,
            2 => p.wire.borrow_mut().link = None,
            3 => p.wire.borrow_mut().link.as_mut().unwrap().link_up = false,
            _ => p.wire.borrow_mut().link.as_mut().unwrap().disabled = true,
        }
        p.server.poll();
        assert_eq!(p.server.socket_count(), 0);
        assert!(p.server.ipv6_stream_listen(e).is_err());
        assert!(p.server.port.ipv6_tcp_peers.iter().all(Option::is_none));
    }
    let mut p = Pair::new();
    let (s, _) = p.connect();
    assert_eq!(p.server.ipv6_streams.entries[s.slot].expires, 10100);
    p.server.ipv6_stream_write(s, b"queued").unwrap();
    let before = p.wire.borrow().frames[0].len();
    p.wire.borrow_mut().now = 10100;
    p.server.poll();
    assert_eq!(p.server.socket_count(), 0);
    assert_eq!(p.wire.borrow().frames[0].len(), before);
}
#[test]
fn returned_io_fault_latches_even_when_link_status_recovers() {
    let mut p = Pair::new();
    let (s, _) = p.connect();
    p.server.ipv6_stream_write(s, b"queued").unwrap();
    p.wire.borrow_mut().send_error = Some(-5);
    p.server.poll();
    assert_eq!(p.server.socket_count(), 0);
    p.wire.borrow_mut().send_error = None;
    let n = p.wire.borrow().frames[0].len();
    p.server.poll();
    assert_eq!(p.wire.borrow().frames[0].len(), n);
    assert!(p.server.ipv6_stream_write(s, b"later").is_err());
}
#[test]
fn literal_vectors_and_malformed_requests_have_exact_typed_no_effect_replies() {
    let mut p = Pair::new();
    let mut s = Session::grant(&mut p.server, grant(7005)).unwrap();
    let mut reply = [0; MAX_MESSAGE];
    let wrong = vector("wrong-peer");
    let n = s.request(&mut p.server, &wrong[2..], &mut reply);
    assert_eq!(
        [&(n as u16).to_be_bytes()[..], &reply[..n]].concat(),
        vector("denied")
    );
    let request = request(LISTEN);
    for at in [0, 2, 3, 26] {
        let mut bad = request;
        bad[at] ^= 1;
        let n = s.request(&mut p.server, &bad, &mut reply);
        assert_eq!(n, HEADER);
        assert_eq!(reply[2], Error::Invalid.code());
        assert_eq!(p.server.socket_count(), 0);
    }
    let n = s.request(&mut p.server, &vector("listen")[2..], &mut reply);
    assert_eq!(
        [&(n as u16).to_be_bytes()[..], &reply[..n]].concat(),
        vector("listening")
    );
    assert_eq!(p.server.socket_count(), 1);
}
struct PipeState {
    input: VecDeque<u8>,
    output: Vec<u8>,
    wire: Rc<RefCell<Wire>>,
    block: bool,
    eof: bool,
    advance: u64,
}
impl Pipe for PipeState {
    fn now_ms(&self) -> u64 {
        self.wire.borrow().now
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        if self.eof {
            return Ok(Some(0));
        }
        let n = b.len().min(self.input.len());
        for x in &mut b[..n] {
            *x = self.input.pop_front().unwrap();
        }
        self.wire.borrow_mut().now += self.advance;
        Ok((n > 0).then_some(n))
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        if self.block {
            return Ok(None);
        }
        self.output.extend_from_slice(b);
        self.wire.borrow_mut().now += self.advance;
        Ok(Some(b.len()))
    }
}
fn pipe(p: &Pair, bytes: &[u8]) -> PipeState {
    PipeState {
        input: bytes.iter().copied().collect(),
        output: vec![],
        wire: p.wire.clone(),
        block: false,
        eof: false,
        advance: 0,
    }
}
fn channel(p: &mut Pair) -> Channel {
    Channel::grant(&mut p.server, grant(7005)).unwrap()
}
#[test]
fn strict_pending_reply_expires_without_write_or_socket() {
    let mut p = Pair::new();
    let mut c = channel(&mut p);
    let mut io = pipe(&p, &vector("listen"));
    assert!(c.poll(&mut p.server, &mut io));
    assert!(c.poll(&mut p.server, &mut io));
    assert_eq!(p.server.socket_count(), 1);
    io.block = true;
    assert!(c.poll(&mut p.server, &mut io));
    p.wire.borrow_mut().now = 350;
    assert!(!c.poll(&mut p.server, &mut io));
    assert!(io.output.is_empty());
    assert_eq!(p.server.socket_count(), 0);
}
#[test]
fn actual_partial_prefix_timeout_and_true_eof_discard_before_owner_expiry() {
    for eof in [false, true] {
        let mut p = Pair::new();
        let mut c = channel(&mut p);
        let mut io = pipe(&p, &[0]);
        assert!(c.poll(&mut p.server, &mut io));
        if eof {
            io.eof = true;
        } else {
            p.wire.borrow_mut().now = 350;
        }
        assert!(!c.poll(&mut p.server, &mut io));
        assert_eq!(p.server.socket_count(), 0);
        assert!(io.output.is_empty());
        assert!(p.wire.borrow().now < 10100);
    }
}
#[test]
fn owner_boundary_crossed_during_pipe_read_prevents_listen_effect() {
    let mut p = Pair::new();
    let mut c = channel(&mut p);
    let mut io = pipe(&p, &vector("listen"));
    assert!(c.poll(&mut p.server, &mut io));
    io.advance = 10000;
    assert!(!c.poll(&mut p.server, &mut io));
    assert_eq!(p.server.socket_count(), 0);
    assert!(io.output.is_empty());
}
#[test]
fn pending_terminal_ack_cannot_survive_explicit_fence_or_epoch_reuse() {
    let mut p = Pair::new();
    let mut c = channel(&mut p);
    let mut input = vec![0, 28];
    input.extend_from_slice(&request(ABORT));
    let mut io = pipe(&p, &input);
    assert!(c.poll(&mut p.server, &mut io));
    assert!(c.poll(&mut p.server, &mut io));
    assert!(c.session.terminal_ack);
    p.server.ipv6_stream_server_fence();
    assert!(!c.poll(&mut p.server, &mut io));
    assert!(io.output.is_empty());
    let fresh = p.server.ipv6_stream_server_grant(grant(7005)).unwrap();
    assert_eq!(p.server.ipv6_streams.entries[fresh.slot].epoch, fresh.epoch);
    assert!(!c.poll(&mut p.server, &mut io));
    assert_eq!(p.server.ipv6_streams.entry(fresh).unwrap().error, None);
}

#[test]
fn exact_configured_route_does_not_authorize_inbound_server() {
    let mut p = Pair::new();
    let mut off = peer(3, 42030);
    off.ip[7] = 1;
    p.server
        .configure_ipv6_route(super::super::super::routing::Route {
            router: ip(2),
            peer: off,
        })
        .unwrap();
    let mut g = grant(7005);
    g.peer = off;
    assert_eq!(p.server.ipv6_stream_server_grant(g), Err(Error::Denied));
    assert_eq!(p.server.socket_count(), 0);
    assert!(p.server.port.ipv6_tcp_peers.iter().all(Option::is_none));
}
#[test]
fn pending_reply_link_fault_prevents_any_pipe_write() {
    let mut p = Pair::new();
    let mut c = channel(&mut p);
    let mut io = pipe(&p, &vector("listen"));
    assert!(c.poll(&mut p.server, &mut io));
    assert!(c.poll(&mut p.server, &mut io));
    p.wire.borrow_mut().link.as_mut().unwrap().link_up = false;
    assert!(!c.poll(&mut p.server, &mut io));
    assert!(io.output.is_empty());
    assert_eq!(p.server.socket_count(), 0);
    assert!(p.server.port.ipv6_tcp_peers.iter().all(Option::is_none));
}
#[test]
fn post_write_boundary_discards_future_authority_without_recalling_written_bytes() {
    let mut p = Pair::new();
    let mut c = channel(&mut p);
    let mut io = pipe(&p, &vector("listen"));
    assert!(c.poll(&mut p.server, &mut io));
    assert!(c.poll(&mut p.server, &mut io));
    io.advance = 10000;
    assert!(!c.poll(&mut p.server, &mut io));
    assert_eq!(io.output, vector("listening"));
    assert_eq!(p.server.socket_count(), 0);
    let n = io.output.len();
    assert!(!c.poll(&mut p.server, &mut io));
    assert_eq!(io.output.len(), n);
}
#[test]
fn cached_outbound_flow_is_rejected_after_its_original_fence() {
    let mut p = Pair::new();
    let (s, c) = p.connect();
    p.server.ipv6_stream_write(s, b"cached").unwrap();
    p.server.poll();
    assert_eq!(p.client.port.fill(0), Ok(true));
    p.client.ipv6_stream_fence();
    assert!(phy::Device::receive(&mut p.client.port, Instant::from_millis(200)).is_none());
    assert!(p.client.ipv6_stream_status(c).is_err());
}

#[test]
fn unused_server_adds_no_link_status_observations() {
    let mut p = Pair::new();
    let before = p.wire.borrow().read_calls;
    p.server.poll();
    assert_eq!(p.wire.borrow().read_calls, before);
}
#[test]
fn cached_outbound_neighbor_reply_is_rejected_after_fence() {
    let mut p = Pair::new();
    let s = p.server.ipv6_stream_server_grant(grant(7005)).unwrap();
    p.server.ipv6_stream_listen(s).unwrap();
    let c = p
        .client
        .ipv6_stream_grant(super::super::Grant {
            local_port: 42030,
            peer: peer(1, 7005),
            connect_timeout_ms: 1000,
            lifetime_ms: 10000,
        })
        .unwrap();
    p.client.ipv6_stream_connect(c).unwrap();
    p.client.poll();
    p.server.poll();
    assert_eq!(p.client.port.fill(0), Ok(true));
    let length = p.client.port.rx_length.unwrap();
    assert_eq!(p.client.port.rx[20], 58);
    assert_eq!(p.client.port.rx[54], 136);
    assert!(length >= 78);
    p.client.ipv6_stream_fence();
    assert!(phy::Device::receive(&mut p.client.port, Instant::from_millis(101)).is_none());
}
#[path = "../../../../../src/ipv6_tcp_server_clock.rs"]
mod completion_clock;
#[test]
fn completion_clock_refuses_eof_wait_and_empty_drain_substitutions() {
    // Real EOF/normal wait/zero sockets must not skip the same actual owner
    // clock helper when the preceding bounded operation crosses its limit.
    for event in [
        "result-read-EOF",
        "normal-child-wait",
        "empty-terminal-drain",
    ] {
        let mut previous = 9999;
        let eof = true;
        let sockets = 0;
        assert!(eof && sockets == 0);
        assert_eq!(
            completion_clock::observe(&mut previous, 10000, 10000),
            Err("owner completion deadline"),
            "{event}"
        );
        assert_eq!(previous, 9999);
    }
    let mut previous = 100;
    assert!(completion_clock::observe(&mut previous, 10000, 101).is_ok());
    assert_eq!(
        completion_clock::observe(&mut previous, 10000, 100),
        Err("owner completion clock rewind")
    );
}
struct ScriptPipe {
    input: VecDeque<u8>,
    sent: Rc<RefCell<Vec<u8>>>,
    now: Rc<std::cell::Cell<u64>>,
    step: u64,
    rewind: bool,
    read_step: u64,
}
impl Pipe for ScriptPipe {
    fn now_ms(&self) -> u64 {
        self.now.get()
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        let n = b.len().min(self.input.len());
        for byte in &mut b[..n] {
            *byte = self.input.pop_front().unwrap();
        }
        if self.rewind {
            self.now.set(self.now.get() - 1);
        } else {
            self.now
                .set(self.now.get() + self.step + if n == 0 { self.read_step } else { 0 });
        }
        Ok((n > 0).then_some(n))
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        self.sent.borrow_mut().extend_from_slice(b);
        self.now.set(self.now.get() + self.step);
        Ok(Some(b.len()))
    }
}
fn scripted(replies: &[u8]) -> (ScriptPipe, Rc<RefCell<Vec<u8>>>) {
    let sent = Rc::new(RefCell::new(vec![]));
    (
        ScriptPipe {
            input: replies.iter().copied().collect(),
            sent: sent.clone(),
            now: Rc::new(std::cell::Cell::new(100)),
            step: 0,
            rewind: false,
            read_step: 0,
        },
        sent,
    )
}
fn accept_reply() -> Vec<u8> {
    let mut r = vector("listening");
    r[3] = ACCEPT;
    r[30] = 1;
    r
}
#[test]
fn actual_client_accept_and_transact_use_exact_v3_vectors() {
    let mut replies = vector("listening");
    replies.extend_from_slice(&accept_reply());
    let (io, sent) = scripted(&replies);
    let mut client = Client::new(io, peer(2, 42030), |_| {});
    client.accept(1000).unwrap();
    let mut expected = vector("listen");
    let mut accept = vector("listen");
    accept[3] = ACCEPT;
    expected.extend_from_slice(&accept);
    assert_eq!(*sent.borrow(), expected);
    assert_eq!(client.accept(1000), Err(Error::Invalid));
    let (mut io, sent) = scripted(&vector("listening"));
    let mut reply = [0; MAX_MESSAGE];
    assert_eq!(
        transact(&mut io, &vector("listen")[2..], &mut reply, 100),
        Ok(29)
    );
    assert_eq!(*sent.borrow(), vector("listen"));
    assert_eq!(&reply[..29], &vector("listening")[2..]);
}
#[test]
fn actual_client_refuses_reply_tuple_scope_version_and_family_substitutions() {
    for at in [2, 3, 5, 6, 22, 26] {
        let mut reply = vector("listening");
        reply[at] ^= 1;
        let (io, _) = scripted(&reply);
        let mut client = Client::new(io, peer(2, 42030), |_| {});
        assert_eq!(
            client.accept(1000),
            Err(Error::Channel(-22)),
            "reply byte {at}"
        );
        assert_eq!(client.accept(1000), Err(Error::Stale));
    }
}
#[test]
fn actual_client_refuses_unknown_status_and_malformed_reply_shapes() {
    let mut cases = vec![];
    let mut unknown = vector("denied");
    unknown[4] = 99;
    cases.push(unknown);
    let mut flags = vector("listening");
    flags[30] = 8;
    cases.push(flags);
    let mut count = vector("listening");
    count[29] = 2;
    cases.push(count);
    let mut prefix = vector("listening");
    prefix[1] = 27;
    cases.push(prefix);
    for reply in cases {
        let (io, _) = scripted(&reply);
        let mut client = Client::new(io, peer(2, 42030), |_| {});
        assert_eq!(client.accept(1000), Err(Error::Channel(-22)));
        assert_eq!(client.accept(1000), Err(Error::Stale));
    }
}
#[test]
fn actual_client_transaction_timeout_and_rewind_are_terminal_without_retry() {
    let (mut io, sent) = scripted(&vector("listening"));
    io.step = 1000;
    let mut client = Client::new(io, peer(2, 42030), |_| {});
    assert_eq!(client.accept(1000), Err(Error::Timeout));
    let count = sent.borrow().len();
    assert_eq!(client.accept(1000), Err(Error::Stale));
    assert_eq!(sent.borrow().len(), count);
    let (mut io, sent) = scripted(&vector("listening"));
    io.rewind = true;
    let mut client = Client::new(io, peer(2, 42030), |_| {});
    assert_eq!(client.accept(1000), Err(Error::Clock));
    let count = sent.borrow().len();
    assert_eq!(client.accept(1000), Err(Error::Stale));
    assert_eq!(sent.borrow().len(), count);
}
#[test]
fn actual_client_uncertain_write_is_not_retried() {
    let mut replies = vector("listening");
    replies.extend_from_slice(&accept_reply());
    let (mut io, sent) = scripted(&replies);
    let now = io.now.clone();
    io.step = 0;
    let mut client = Client::new(io, peer(2, 42030), |_| {});
    client.accept(1000).unwrap();
    // Empty reply source advances to the caller deadline after a request was
    // emitted. A lost reply cannot authorize a second WRITE of the bytes.
    client.pipe.read_step = 1000;
    assert!(client.write(b"one effect", 1000).is_err());
    let bytes = sent.borrow().clone();
    assert!(bytes.windows(10).any(|w| w == b"one effect"));
    assert_eq!(client.write(b"one effect", 2000), Err(Error::Stale));
    assert_eq!(*sent.borrow(), bytes);
    assert!(now.get() >= 1000);
}

#[test]
fn unused_server_actual_transmission_adds_no_link_status_reads() {
    let mut p = Pair::new();
    let before = p.wire.borrow().read_calls;
    let bytes = [0u8; 60];
    let token = phy::Device::transmit(&mut p.server.port, Instant::from_millis(100)).unwrap();
    phy::TxToken::consume(token, bytes.len(), |out| out.copy_from_slice(&bytes));
    assert_eq!(p.wire.borrow().frames[0], vec![bytes.to_vec()]);
    assert_eq!(p.wire.borrow().read_calls, before);
}

#[test]
fn redundant_shutdown_then_close_can_lose_the_live_endpoint() {
    let mut p = Pair::new();
    let (s, c) = p.connect();
    p.client.ipv6_stream_shutdown_write(c).unwrap();
    for _ in 0..100 {
        p.step();
        if p.server.ipv6_stream_read(s, &mut [0; 1]) == Err(Error::Eof) {
            break;
        }
    }
    assert_eq!(p.server.ipv6_stream_read(s, &mut [0; 1]), Err(Error::Eof));
    p.server.ipv6_stream_shutdown_write(s).unwrap();
    for _ in 0..100 {
        p.step();
        if p.server.socket_count() == 0 {
            break;
        }
    }
    // This is the old fixture sequence, not a library behavior change.
    assert_eq!(p.server.socket_count(), 0);
    assert_eq!(
        p.server.ipv6_streams.entries[s.slot].error,
        Some(Error::Closed)
    );
    assert_eq!(p.server.ipv6_stream_close(s), Err(Error::Stale));
}

// Actual Client -> transact -> Channel -> Session -> smoltcp pair. No canned
// transaction replies: both socket engines and every framed reply are real.
struct LiveBridge {
    pair: Pair,
    channel: Channel,
    io: PipeState,
    remote: Option<Endpoint>,
    drained_before_ack: bool,
    to_send: VecDeque<u8>,
    remote_shutdown: bool,
    echoed: Vec<u8>,
    remote_eof: bool,
}
impl LiveBridge {
    fn new() -> Self {
        let mut pair = Pair::new();
        let channel = channel(&mut pair);
        let io = pipe(&pair, &[]);
        Self {
            pair,
            channel,
            io,
            remote: None,
            drained_before_ack: false,
            to_send: VecDeque::new(),
            remote_shutdown: false,
            echoed: vec![],
            remote_eof: false,
        }
    }
    fn advance(&mut self) {
        self.channel.poll(&mut self.pair.server, &mut self.io);
        if self.remote.is_none() && self.pair.server.socket_count() == 1 {
            let endpoint = self
                .pair
                .client
                .ipv6_stream_grant(super::super::Grant {
                    local_port: 42030,
                    peer: peer(1, 7005),
                    connect_timeout_ms: 1000,
                    lifetime_ms: 10000,
                })
                .unwrap();
            self.pair.client.ipv6_stream_connect(endpoint).unwrap();
            self.remote = Some(endpoint);
        }
        self.network_step();
        if self.channel.session.terminal_ack && !self.drained_before_ack {
            // Substitute the scheduler ordering that defeated the old fixture:
            // FIN/ACK and socket removal happen before terminal reply output.
            for _ in 0..100 {
                self.network_step();
                if self.pair.server.socket_count() == 0 {
                    break;
                }
            }
            assert_eq!(self.pair.server.socket_count(), 0);
            assert!(self.io.output.is_empty());
            self.drained_before_ack = true;
        }
    }
    fn network_step(&mut self) {
        if let Some(remote) = self.remote {
            if !self.to_send.is_empty() {
                let bytes: Vec<u8> = self.to_send.iter().take(511).copied().collect();
                match self.pair.client.ipv6_stream_write(remote, &bytes) {
                    Ok(n) => {
                        self.to_send.drain(..n);
                    }
                    Err(Error::Again) => {}
                    other => panic!("actual peer write {other:?}"),
                }
                if self.to_send.is_empty() {
                    self.pair.client.ipv6_stream_shutdown_write(remote).unwrap();
                    self.remote_shutdown = true;
                }
            }
        }
        self.pair.step();
        if let Some(remote) = self.remote {
            let mut bytes = [0; 511];
            match self.pair.client.ipv6_stream_read(remote, &mut bytes) {
                Ok(n) => self.echoed.extend_from_slice(&bytes[..n]),
                Err(Error::Eof) => self.remote_eof = true,
                Err(Error::Again) => {}
                other => panic!("actual peer read {other:?}"),
            }
        }
    }
}
struct LivePipe(Rc<RefCell<LiveBridge>>);
impl Pipe for LivePipe {
    fn now_ms(&self) -> u64 {
        self.0.borrow().pair.wire.borrow().now
    }
    fn write(&mut self, bytes: &[u8]) -> Result<Option<usize>, i64> {
        let mut bridge = self.0.borrow_mut();
        bridge.io.input.extend(bytes.iter().copied());
        bridge.advance();
        Ok(Some(bytes.len()))
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>, i64> {
        let mut bridge = self.0.borrow_mut();
        bridge.advance();
        let n = bytes.len().min(bridge.io.output.len());
        bytes[..n].copy_from_slice(&bridge.io.output[..n]);
        bridge.io.output.drain(..n);
        Ok((n > 0).then_some(n))
    }
}
#[test]
fn actual_client_single_close_ack_survives_fin_ack_and_socket_removal() {
    let bridge = Rc::new(RefCell::new(LiveBridge::new()));
    let mut client = Client::new(LivePipe(bridge.clone()), peer(2, 42030), |_| {});
    client.accept(10000).unwrap();
    let data: Vec<u8> = (0..3072).map(|i| (i * 131 ^ (i >> 7)) as u8).collect();
    bridge.borrow_mut().to_send.extend(data.iter().copied());
    let mut received = vec![];
    loop {
        let mut bytes = [0; 511];
        match client.read(&mut bytes, 10000) {
            Ok(n) => {
                received.extend_from_slice(&bytes[..n]);
                client.write_all(&bytes[..n], 10000).unwrap();
            }
            Err(Error::Again) => {}
            Err(Error::Eof) => break,
            other => panic!("actual child read {other:?}"),
        }
    }
    assert_eq!(received, data);
    client.close(10000).unwrap();
    assert_eq!(client.write(b"spent", 10000), Err(Error::Stale));
    let mut b = bridge.borrow_mut();
    assert!(b.drained_before_ack);
    assert_eq!(b.pair.server.socket_count(), 0);
    assert!(
        b.pair
            .server
            .port
            .ipv6_tcp_peers
            .iter()
            .all(Option::is_none)
    );
    assert!(
        b.pair
            .server
            .port
            .ipv6_server_rules
            .iter()
            .all(Option::is_none)
    );
    assert!(b.remote_shutdown && b.remote_eof);
    assert_eq!(b.echoed, data);
    b.io.eof = true;
    let LiveBridge {
        pair, channel, io, ..
    } = &mut *b;
    assert!(!channel.poll(&mut pair.server, io));
}
