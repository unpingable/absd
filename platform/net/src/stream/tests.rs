use super::*;
use crate::stream as s;
fn grant(port: u16) -> s::Grant {
    s::Grant {
        local_port: port,
        peer: datagram::Address {
            ip: [10, 0, 2, 15],
            port: 7000,
        },
        connect_timeout_ms: 1000,
        lifetime_ms: 60000,
    }
}
fn connected() -> (
    Rc<RefCell<Wire>>,
    Stack<End>,
    Stack<End>,
    Connection,
    s::Endpoint,
) {
    let (wire, mut server, mut owner) = pair(0);
    let listener = server.listen(7000, 1).unwrap();
    let endpoint = owner.stream_grant(grant(40000)).unwrap();
    assert!(!owner.stream_connect(endpoint).unwrap().connected);
    let mut accepted = None;
    for _ in 0..1000 {
        step(&wire, &mut server, &mut owner);
        if accepted.is_none() {
            accepted = server.accept(listener);
        }
        if accepted.is_some() && owner.stream_status(endpoint).unwrap().connected {
            break;
        }
    }
    (wire, server, owner, accepted.unwrap(), endpoint)
}
#[test]
fn grants_reserve_without_network_and_refuse_expansion_or_exhaustion() {
    let (_, mut server, mut owner) = pair(0);
    let baseline = owner.socket_count();
    let listener = owner.listen(41000, 1).unwrap();
    assert_eq!(owner.stream_grant(grant(41000)), Err(s::Error::InUse));
    owner.unlisten(listener).unwrap();
    let e = owner.stream_grant(grant(40000)).unwrap();
    assert_eq!(owner.socket_count(), baseline);
    assert_eq!(owner.stream_grant(grant(40000)), Err(s::Error::InUse));
    assert_eq!(owner.listen(40000, 1), Err(NetError::InUse));
    assert_eq!(
        owner.connect(Ipv4Address::new(10, 0, 2, 15), 7000, 40000),
        Err(NetError::InUse)
    );
    assert_eq!(server.stream_status(e), Err(s::Error::Stale));
    for port in 40001..40008 {
        owner.stream_grant(grant(port)).unwrap();
    }
    assert_eq!(owner.stream_grant(grant(40008)), Err(s::Error::Exhausted));
    owner.stream_abort(e).unwrap();
    let fresh = owner.stream_grant(grant(40000)).unwrap();
    assert_ne!(fresh, e);
    assert_eq!(owner.stream_connect(e), Err(s::Error::Stale));
    owner.stream_fence();
    assert_eq!(owner.socket_count(), baseline);
    for ip in [
        [0, 1, 2, 3],
        [127, 0, 0, 1],
        [224, 0, 0, 1],
        [255, 255, 255, 255],
        [10, 0, 2, 0],
        [10, 0, 2, 255],
        [10, 0, 2, 2],
        [192, 0, 2, 1],
    ] {
        let mut g = grant(40000);
        g.peer.ip = ip;
        assert_eq!(owner.stream_grant(g), Err(s::Error::Invalid));
    }
    for local in [0, 53, 1023] {
        let mut g = grant(local);
        g.peer.port = 53;
        assert_eq!(owner.stream_grant(g), Err(s::Error::Invalid));
    }
}
#[test]
fn checked_identity_and_clock_counters_never_wrap_or_revive() {
    let (wire, _, mut owner) = pair(0);
    owner.streams.set_epoch_for_test(u64::MAX);
    assert_eq!(owner.stream_grant(grant(40000)), Err(s::Error::Exhausted));
    owner.streams.set_epoch_for_test(1);
    let e = owner.stream_grant(grant(40000)).unwrap();
    wire.borrow_mut().now_ms = 0;
    assert_eq!(owner.stream_status(e), Err(s::Error::Clock));
    owner.stream_abort(e).unwrap();
    assert_eq!(owner.stream_status(e), Err(s::Error::Stale));
}
#[test]
fn partial_io_backpressure_and_stream_boundaries() {
    let (wire, mut server, mut owner, peer, e) = connected();
    let block = [0x55; s::MAX_IO];
    let mut queued = 0;
    loop {
        match owner.stream_write(e, &block) {
            Ok(n) => queued += n,
            Err(s::Error::Again) => break,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(queued, s::BUFFER_BYTES);
    assert_eq!(
        owner.stream_write(e, &[0; s::MAX_IO + 1]),
        Err(s::Error::Oversize)
    );
    let mut received = Vec::new();
    let mut reply = Vec::new();
    let mut small = [0; 137];
    for _ in 0..10000 {
        step(&wire, &mut server, &mut owner);
        if server.send_room(peer).unwrap() >= small.len() {
            if let Ok(n) = server.recv(peer, &mut small) {
                if n > 0 {
                    received.extend_from_slice(&small[..n]);
                    server.send(peer, &small[..n]).unwrap();
                }
            }
        }
        match owner.stream_read(e, &mut small) {
            Ok(n) => reply.extend_from_slice(&small[..n]),
            Err(s::Error::Again) => {}
            other => panic!("{other:?}"),
        }
        if reply.len() == queued {
            break;
        }
    }
    assert_eq!(reply.len(), queued);
    assert_eq!(reply, received);
    assert!(reply.iter().all(|b| *b == 0x55));
    owner.stream_abort(e).unwrap();
    step(&wire, &mut server, &mut owner);
    assert_eq!(owner.stream_status(e), Err(s::Error::Stale));
    assert_eq!(owner.socket_count(), 0);
}
#[test]
fn write_half_close_retains_reads_and_eof_is_not_again() {
    let (wire, mut server, mut owner, peer, e) = connected();
    owner.stream_write(e, b"request").unwrap();
    owner.stream_shutdown_write(e).unwrap();
    assert_eq!(owner.stream_write(e, b"late"), Err(s::Error::WriteClosed));
    let mut body = Vec::new();
    let mut b = [0; 128];
    let mut fin = false;
    for _ in 0..10000 {
        step(&wire, &mut server, &mut owner);
        match server.recv(peer, &mut b) {
            Ok(n) => body.extend_from_slice(&b[..n]),
            Err(NetError::Finished) => {
                fin = true;
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(fin);
    assert_eq!(body, b"request");
    server.send(peer, b"after-fin").unwrap();
    server.close(peer).unwrap();
    let mut received = Vec::new();
    let mut eof = false;
    for _ in 0..10000 {
        step(&wire, &mut server, &mut owner);
        match owner.stream_read(e, &mut b) {
            Ok(n) => received.extend_from_slice(&b[..n]),
            Err(s::Error::Again) => {}
            Err(s::Error::Eof) => {
                eof = true;
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(eof);
    assert_eq!(received, b"after-fin");
    owner.stream_close(e).unwrap();
    step(&wire, &mut server, &mut owner);
    assert_eq!(owner.stream_grant(grant(40000)), Err(s::Error::InUse));
    wire.borrow_mut().now_ms += 30001;
    for _ in 0..3 {
        step(&wire, &mut server, &mut owner);
    }
    assert_eq!(owner.socket_count(), 0);
}
#[test]
fn refused_and_reset_connections_are_terminal() {
    let (wire, mut server, mut owner, peer, e) = connected();
    server.abort(peer).unwrap();
    for _ in 0..20 {
        step(&wire, &mut server, &mut owner)
    }
    assert_eq!(owner.stream_read(e, &mut [0; 1]), Err(s::Error::Closed));
    owner.stream_abort(e).unwrap();
    step(&wire, &mut server, &mut owner);
    assert_eq!(owner.socket_count(), 0);
    let e = owner
        .stream_grant(s::Grant {
            peer: datagram::Address {
                port: 7100,
                ..grant(40001).peer
            },
            ..grant(40001)
        })
        .unwrap();
    owner.stream_connect(e).unwrap();
    for _ in 0..100 {
        step(&wire, &mut server, &mut owner)
    }
    assert_eq!(owner.stream_status(e), Err(s::Error::Closed));
}
#[test]
fn abort_spends_authority_then_polls_reset_before_socket_reclamation() {
    let (wire, mut server, mut owner, peer, e) = connected();
    owner.stream_abort(e).unwrap();
    assert_eq!(owner.stream_status(e), Err(s::Error::Stale));
    // The first step emits reset, the second lets the independent endpoint
    // process it. Local socket resources are reclaimed after that first poll.
    step(&wire, &mut server, &mut owner);
    assert_eq!(owner.socket_count(), 0);
    step(&wire, &mut server, &mut owner);
    assert_eq!(server.state(peer), Ok(TcpState::Closed));
}

// Advance the shared clock inside iface.poll, after its pre-maintenance
// snapshot. This exercises an error first detected in post-maintenance.
struct LateClock {
    end: End,
    jump: Rc<std::cell::Cell<u64>>,
}
impl Link for LateClock {
    fn mac(&self) -> [u8; 6] {
        self.end.mac()
    }
    fn send(&mut self, bytes: &[u8]) -> Result<(), i64> {
        self.end.send(bytes)
    }
    fn receive(
        &mut self,
        buffer: &mut [u8; FRAME_MAX],
        timeout: u64,
    ) -> Result<Option<usize>, i64> {
        self.end.wire.borrow_mut().now_ms += self.jump.replace(0);
        self.end.receive(buffer, timeout)
    }
    fn now_ms(&self) -> u64 {
        self.end.now_ms()
    }
    fn pause(&self, ms: u64) {
        self.end.pause(ms)
    }
}
#[test]
fn expiry_first_observed_after_poll_retains_reset_until_next_dispatch() {
    let (wire, mut server, _) = pair(0);
    let jump = Rc::new(std::cell::Cell::new(0));
    let mut owner = Stack::open(
        LateClock {
            end: End {
                wire: wire.clone(),
                side: 1,
                mac: [2, 0, 0, 0, 0, 2],
            },
            jump: jump.clone(),
        },
        Config {
            address: Ipv4Address::new(10, 0, 2, 2),
            prefix_len: 24,
            gateway: None,
            rx_buffer: 8192,
            tx_buffer: 8192,
        },
    )
    .unwrap();
    let listener = server.listen(7000, 1).unwrap();
    let endpoint = owner
        .stream_grant(s::Grant {
            connect_timeout_ms: 100,
            lifetime_ms: 200,
            ..grant(40000)
        })
        .unwrap();
    owner.stream_connect(endpoint).unwrap();
    let mut peer = None;
    for _ in 0..50 {
        server.poll();
        owner.poll();
        wire.borrow_mut().now_ms += 1;
        if peer.is_none() {
            peer = server.accept(listener);
        }
        if peer.is_some() && owner.stream_status(endpoint).unwrap().connected {
            break;
        }
    }
    let peer = peer.unwrap();
    jump.set(201);
    owner.poll(); // expiry is first observed by the post pass
    assert_eq!(owner.stream_status(endpoint), Err(s::Error::Timeout));
    assert_eq!(owner.socket_count(), 1);
    owner.poll(); // the aborted socket dispatches its reset, then is reclaimed
    assert_eq!(owner.socket_count(), 0);
    server.poll();
    assert_eq!(server.state(peer), Ok(TcpState::Closed));
}
#[test]
fn connect_and_dormant_lifetime_timeouts_are_bounded() {
    let (wire, mut server, mut owner) = pair(1);
    let mut g = grant(40000);
    g.connect_timeout_ms = 100;
    g.lifetime_ms = 200;
    let e = owner.stream_grant(g).unwrap();
    owner.stream_connect(e).unwrap();
    for _ in 0..101 {
        step(&wire, &mut server, &mut owner)
    }
    assert_eq!(owner.stream_status(e), Err(s::Error::Timeout));
    owner.stream_abort(e).unwrap();
    assert_eq!(owner.socket_count(), 0);
    let e = owner.stream_grant(g).unwrap();
    wire.borrow_mut().now_ms += 201;
    assert_eq!(owner.stream_status(e), Err(s::Error::Timeout));
    assert_eq!(owner.socket_count(), 0);
}
#[test]
fn closing_slots_count_against_the_same_resource_ceiling() {
    let (wire, mut server, mut owner, peer, e) = connected();
    owner.stream_close(e).unwrap();
    for port in 40001..40008 {
        owner.stream_grant(grant(port)).unwrap();
    }
    assert_eq!(owner.stream_grant(grant(40008)), Err(s::Error::Exhausted));
    for _ in 0..20 {
        step(&wire, &mut server, &mut owner)
    } // peer has not closed its sending side
    assert_eq!(owner.stream_grant(grant(40008)), Err(s::Error::Exhausted));
    wire.borrow_mut().now_ms += 30001;
    for _ in 0..3 {
        step(&wire, &mut server, &mut owner)
    }
    assert!(owner.stream_grant(grant(40008)).is_ok());
    let _ = server.abort(peer);
}
#[test]
fn carrier_unknown_and_device_failure_fence_native_grants_only() {
    for (reading, error) in [
        (None, s::Error::LinkUnknown),
        (reading(false, false, 0), s::Error::LinkDown),
        (reading(true, true, 0), s::Error::DeviceFailed),
    ] {
        let (state, mut owner, _) = switch(Some(LinkReading {
            link_up: true,
            disabled: false,
            rx_missed: 0,
        }));
        let e = owner
            .stream_grant(s::Grant {
                peer: datagram::Address {
                    ip: [10, 0, 2, 2],
                    port: 53,
                },
                ..grant(40000)
            })
            .unwrap();
        state.borrow_mut().reading = reading;
        assert_eq!(owner.stream_connect(e), Err(error));
        state.borrow_mut().reading = Some(LinkReading {
            link_up: true,
            disabled: false,
            rx_missed: 0,
        });
        assert_eq!(owner.stream_status(e), Err(s::Error::Stale));
    }
}
fn request(op: u8, peer: datagram::Address, data: &[u8], capacity: u16) -> Vec<u8> {
    let mut bytes = vec![1, op, 0, 0];
    bytes.extend_from_slice(&peer.ip);
    bytes.extend_from_slice(&peer.port.to_be_bytes());
    bytes.extend_from_slice(
        &(if op == s::WRITE {
            data.len() as u16
        } else {
            capacity
        })
        .to_be_bytes(),
    );
    bytes.extend_from_slice(data);
    bytes
}
#[test]
fn session_validates_peer_and_frame_before_any_connect_or_write() {
    let (_, _, mut owner) = pair(0);
    let g = grant(40000);
    let mut session = s::Session::grant(&mut owner, g).unwrap();
    let mut reply = [0; datagram::MAX_MESSAGE];
    let wrong = request(
        s::CONNECT,
        datagram::Address {
            port: 7001,
            ..g.peer
        },
        &[],
        0,
    );
    session.request(&mut owner, &wrong, &mut reply);
    assert_eq!(reply[2], s::Error::Denied.code());
    assert_eq!(owner.socket_count(), 0);
    let valid = request(s::CONNECT, g.peer, &[], 0);
    for end in 0..12 {
        session.request(&mut owner, &valid[..end], &mut reply);
        assert_eq!(reply[2], s::Error::Invalid.code());
    }
    let mut bad = valid.clone();
    bad[2] = 1;
    session.request(&mut owner, &bad, &mut reply);
    assert_eq!(reply[2], s::Error::Invalid.code());
    assert_eq!(owner.socket_count(), 0);
    session.request(&mut owner, &valid, &mut reply);
    assert_eq!(reply[2], 0);
    assert_eq!(owner.socket_count(), 1);
    session.request(&mut owner, &valid, &mut reply);
    assert_eq!(owner.socket_count(), 1);
    session.revoke(&mut owner);
    owner.poll();
    assert_eq!(owner.socket_count(), 0);
}
#[test]
fn partial_frames_blocked_readers_and_eof_revoke_reserved_authority() {
    for mode in 0..3 {
        let (_, _, mut owner) = pair(0);
        let mut channel = s::channel::Channel::grant(&mut owner, grant(40000)).unwrap();
        let bytes = request(s::STATUS, grant(40000).peer, &[], 0);
        let mut input = VecDeque::from((bytes.len() as u16).to_be_bytes().to_vec());
        input.extend(bytes);
        let mut pipe = TestPipe {
            input,
            output: Vec::new(),
            now: 0,
            eof: false,
            block: mode == 1,
        };
        if mode == 0 {
            pipe.input = VecDeque::from(vec![0]);
            channel.poll(&mut owner, &mut pipe);
            pipe.now = 251;
        } else if mode == 1 {
            for _ in 0..20 {
                channel.poll(&mut owner, &mut pipe);
            }
            pipe.now = 251;
        } else {
            pipe.input.clear();
            pipe.eof = true;
        }
        assert!(!channel.poll(&mut owner, &mut pipe));
        assert!(owner.stream_grant(grant(40000)).is_ok());
    }
}
#[test]
fn paired_dns_grants_refuse_different_resolvers_and_rollback_failure() {
    let (_, _, mut owner) = pair(0);
    let udp = datagram::Grant {
        local_port: 40000,
        peer: grant(40000).peer,
    };
    let bad = s::Grant {
        peer: datagram::Address {
            port: 7001,
            ..udp.peer
        },
        ..grant(40000)
    };
    assert!(matches!(
        dns::tcp::Session::grant(&mut owner, udp, bad),
        Err(s::Error::Denied)
    ));
    assert_eq!(owner.socket_count(), 0);
    let reserved = owner.stream_grant(grant(40000)).unwrap();
    assert!(matches!(
        dns::tcp::Session::grant(&mut owner, udp, grant(40000)),
        Err(s::Error::InUse)
    ));
    let endpoint = owner.datagram_bind(udp).unwrap();
    owner.datagram_close(endpoint).unwrap();
    owner.stream_abort(reserved).unwrap();
}

struct ScriptIo {
    input: VecDeque<u8>,
    output: Vec<u8>,
    now: u64,
    rewind_on_write: bool,
}
struct Script(Rc<RefCell<ScriptIo>>);
impl datagram::channel::Pipe for Script {
    fn now_ms(&self) -> u64 {
        self.0.borrow().now
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        let mut io = self.0.borrow_mut();
        io.output.extend_from_slice(b);
        if io.rewind_on_write {
            io.now = 0;
        }
        Ok(Some(b.len()))
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        let mut io = self.0.borrow_mut();
        let n = b.len().min(io.input.len());
        for byte in &mut b[..n] {
            *byte = io.input.pop_front().unwrap()
        }
        Ok(Some(n))
    }
}
fn response(op: u8, status: u8, amount: u16, bytes: &[u8]) -> Vec<u8> {
    let mut out = ((12 + bytes.len()) as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&[1, op, status, 0]);
    out.extend_from_slice(&grant(40000).peer.ip);
    out.extend_from_slice(&grant(40000).peer.port.to_be_bytes());
    out.extend_from_slice(&amount.to_be_bytes());
    out.extend_from_slice(bytes);
    out
}
fn script(frames: Vec<Vec<u8>>) -> (Rc<RefCell<ScriptIo>>, s::Client<Script>) {
    let io = Rc::new(RefCell::new(ScriptIo {
        input: frames.into_iter().flatten().collect(),
        output: Vec::new(),
        now: 1,
        rewind_on_write: false,
    }));
    (
        io.clone(),
        s::Client::new(Script(io), grant(40000).peer, |_| {}),
    )
}
fn emitted(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let n = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        out.push(bytes[pos + 2..pos + 2 + n].to_vec());
        pos += 2 + n;
    }
    out
}
#[test]
fn client_retries_only_known_unaccepted_write_suffix_and_keeps_eof_separate() {
    let (io, mut client) = script(vec![
        response(s::CONNECT, 0, 1, &[1]),
        response(s::WRITE, 0, 2, &[]),
        response(s::WRITE, 0, 3, &[]),
        response(s::READ, s::Error::Eof.code(), 0, &[]),
        response(s::WRITE, 0, 1, &[]),
    ]);
    client.connect(1000).unwrap();
    client.write_all(b"hello", 1000).unwrap();
    assert_eq!(client.read(&mut [0; 20], 1000), Err(s::Error::Eof));
    assert_eq!(client.write(b"!", 1000), Ok(1));
    let requests = emitted(&io.borrow().output);
    assert_eq!(&requests[1][12..], b"hello");
    assert_eq!(&requests[2][12..], b"llo");
    assert_eq!(requests.len(), 5);
}
#[test]
fn client_uncertain_write_reply_and_bad_peer_never_reissue_write() {
    for wrong in [false, true] {
        let mut frames = vec![response(s::CONNECT, 0, 1, &[1])];
        if wrong {
            let mut reply = response(s::WRITE, 0, 1, &[]);
            reply[9] ^= 1;
            frames.push(reply);
        }
        let (io, mut client) = script(frames);
        client.connect(1000).unwrap();
        assert!(matches!(
            client.write(b"x", 1000),
            Err(s::Error::Channel(_))
        ));
        let size = io.borrow().output.len();
        assert_eq!(client.write(b"x", 1000), Err(s::Error::Stale));
        assert_eq!(io.borrow().output.len(), size);
    }
}
#[test]
fn client_deadline_fences_before_more_ipc() {
    let (io, mut client) = script(vec![]);
    assert_eq!(client.connect(1), Err(s::Error::Timeout));
    assert_eq!(client.connect(1000), Err(s::Error::Stale));
    assert!(io.borrow().output.is_empty());
}
#[test]
fn client_clock_rewind_during_framed_io_stops_before_more_bytes() {
    let (io, mut client) = script(vec![response(s::CONNECT, 0, 1, &[1])]);
    io.borrow_mut().rewind_on_write = true;
    assert_eq!(client.connect(1000), Err(s::Error::Clock));
    assert_eq!(io.borrow().output.len(), 2); // prefix only, no request body
    let size = io.borrow().output.len();
    io.borrow_mut().now = 10;
    assert_eq!(client.connect(1000), Err(s::Error::Stale));
    assert_eq!(io.borrow().output.len(), size);
}
