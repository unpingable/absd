//! Local engine and channel controls; independent Linux/native results are
//! separate. The passive test socket below is not a public listener grant.
use super::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

struct Wire {
    queues: [VecDeque<Vec<u8>>; 2],
    frames: [Vec<Vec<u8>>; 2],
    now: u64,
    reading: Option<LinkReading>,
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
        let mut wire = self.wire.borrow_mut();
        wire.frames[self.side].push(frame.to_vec());
        wire.queues[1 - self.side].push_back(frame.to_vec());
        Ok(())
    }
    fn receive(&mut self, b: &mut [u8; FRAME_MAX], _: u64) -> Result<Option<usize>, i64> {
        Ok(self.wire.borrow_mut().queues[self.side]
            .pop_front()
            .map(|f| {
                b[..f.len()].copy_from_slice(&f);
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
        self.wire.borrow().reading
    }
}
fn ip(last: u8) -> [u8; 16] {
    let mut b = [0; 16];
    b[0] = 0xfd;
    b[15] = last;
    b
}
fn peer(last: u8, port: u16) -> Address {
    Address {
        ip: ip(last),
        port,
        scope: 7,
    }
}
fn grant(port: u16) -> Grant {
    Grant {
        local_port: port,
        peer: peer(1, 7000),
        connect_timeout_ms: 1000,
        lifetime_ms: 60000,
    }
}
fn pair() -> (Rc<RefCell<Wire>>, Stack<End>, Stack<End>) {
    let wire = Rc::new(RefCell::new(Wire {
        queues: [VecDeque::new(), VecDeque::new()],
        frames: [Vec::new(), Vec::new()],
        now: 100,
        reading: Some(LinkReading {
            link_up: true,
            disabled: false,
            rx_missed: 0,
        }),
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
        s.configure_ipv6(super::super::Config {
            address: ip(side as u8 + 1),
            prefix_len: 64,
            scope: 7,
        })
        .unwrap();
        s
    };
    let server = stack(0);
    let owner = stack(1);
    (wire, server, owner)
}
fn step(wire: &Rc<RefCell<Wire>>, server: &mut Stack<End>, owner: &mut Stack<End>) {
    server.poll();
    owner.poll();
    wire.borrow_mut().now += 1;
}
fn connected() -> (
    Rc<RefCell<Wire>>,
    Stack<End>,
    Stack<End>,
    SocketHandle,
    Endpoint,
) {
    let (wire, mut server, mut owner) = pair();
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 8192]),
        tcp::SocketBuffer::new(vec![0; 8192]),
    );
    socket.listen((Ipv6Address::from(ip(1)), 7000)).unwrap();
    let passive = server.sockets.add(socket);
    server.port.ipv6_tcp_peers[0] = Some(Flow {
        local_port: 7000,
        peer: peer(2, 40000),
    });
    let endpoint = owner.ipv6_stream_grant(grant(40000)).unwrap();
    assert!(!owner.ipv6_stream_connect(endpoint).unwrap().connected);
    for _ in 0..1000 {
        step(&wire, &mut server, &mut owner);
        if owner.ipv6_stream_status(endpoint).unwrap().connected {
            return (wire, server, owner, passive, endpoint);
        }
    }
    panic!("IPv6 engine pair did not establish");
}

#[test]
fn grants_are_exact_scoped_bounded_and_emit_nothing_before_connect() {
    let (wire, mut other, mut owner) = pair();
    let endpoint = owner.ipv6_stream_grant(grant(40000)).unwrap();
    assert_eq!(owner.socket_count(), 0);
    assert!(owner.port.ipv6_tcp_peers.iter().all(Option::is_none));
    assert_eq!(owner.ipv6_stream_grant(grant(40000)), Err(Error::InUse));
    assert_eq!(other.ipv6_stream_status(endpoint), Err(Error::Stale));
    for port in 40001..40008 {
        owner.ipv6_stream_grant(grant(port)).unwrap();
    }
    assert_eq!(owner.ipv6_stream_grant(grant(40008)), Err(Error::Exhausted));
    owner.ipv6_stream_abort(endpoint).unwrap();
    let replacement = owner.ipv6_stream_grant(grant(40000)).unwrap();
    assert_ne!(endpoint, replacement);
    assert_eq!(owner.ipv6_stream_connect(endpoint), Err(Error::Stale));
    owner.ipv6_fence();
    for peer in [
        Address {
            scope: 8,
            ..peer(1, 7000)
        },
        peer(2, 7000),
        Address {
            ip: [0; 16],
            ..peer(1, 7000)
        },
        Address {
            ip: [0xff; 16],
            ..peer(1, 7000)
        },
    ] {
        assert_eq!(
            owner.ipv6_stream_grant(Grant {
                peer,
                ..grant(40000)
            }),
            Err(Error::Denied)
        );
    }
    assert!(wire.borrow().frames.iter().all(Vec::is_empty));
}

#[test]
fn epoch_deadline_clock_and_link_faults_fail_closed() {
    let (wire, _, mut owner) = pair();
    owner.ipv6_streams.set_epoch_for_test(u64::MAX);
    assert_eq!(owner.ipv6_stream_grant(grant(40000)), Err(Error::Exhausted));
    owner.ipv6_streams.set_epoch_for_test(1);
    let endpoint = owner.ipv6_stream_grant(grant(40000)).unwrap();
    wire.borrow_mut().now = 99;
    assert_eq!(owner.ipv6_stream_status(endpoint), Err(Error::Clock));
    owner.ipv6_fence();
    wire.borrow_mut().now = 100;
    let endpoint = owner
        .ipv6_stream_grant(Grant {
            lifetime_ms: 1000,
            ..grant(40000)
        })
        .unwrap();
    wire.borrow_mut().now = 1100;
    assert_eq!(owner.ipv6_stream_status(endpoint), Err(Error::Timeout));
    owner.ipv6_fence();
    let endpoint = owner.ipv6_stream_grant(grant(40000)).unwrap();
    wire.borrow_mut().reading = None;
    assert_eq!(owner.ipv6_stream_connect(endpoint), Err(Error::LinkUnknown));
    assert_eq!(owner.ipv6_stream_status(endpoint), Err(Error::Stale));
    assert_eq!(owner.socket_count(), 0);
}

#[test]
fn engine_mss_remains_1440_and_stream_half_close_preserves_reply() {
    let (wire, mut server, mut owner, passive, endpoint) = connected();
    let syn = wire.borrow().frames[1]
        .iter()
        .find(|frame| frame.len() >= 74 && frame[20] == 6 && frame[67] & 2 != 0)
        .cloned()
        .unwrap();
    let packet = smoltcp::wire::TcpPacket::new_checked(&syn[54..]).unwrap();
    let repr = smoltcp::wire::TcpRepr::parse(
        &packet,
        &IpAddress::Ipv6(Ipv6Address::from(ip(2))),
        &IpAddress::Ipv6(Ipv6Address::from(ip(1))),
        &phy::ChecksumCapabilities::default(),
    )
    .unwrap();
    assert_eq!(repr.max_seg_size, Some(1440));
    assert_eq!(
        owner.ipv6_stream_write(endpoint, &[0x55; MAX_IO]),
        Ok(MAX_IO)
    );
    assert_eq!(
        owner.ipv6_stream_write(endpoint, b"full"),
        Err(Error::Again)
    );
    assert_eq!(
        owner.ipv6_stream_write(endpoint, &[0; MAX_IO + 1]),
        Err(Error::Oversize)
    );
    owner.ipv6_stream_shutdown_write(endpoint).unwrap();
    assert_eq!(
        owner.ipv6_stream_write(endpoint, b"late"),
        Err(Error::WriteClosed)
    );
    let mut request = Vec::new();
    let mut answer = Vec::new();
    let mut finished = false;
    for _ in 0..10000 {
        step(&wire, &mut server, &mut owner);
        let socket = server.sockets.get_mut::<tcp::Socket>(passive);
        let mut b = [0; 137];
        if !finished {
            match socket.recv_slice(&mut b) {
                Ok(n) => {
                    request.extend_from_slice(&b[..n]);
                    if n > 0 {
                        assert_eq!(socket.send_slice(&b[..n]), Ok(n));
                    }
                }
                Err(tcp::RecvError::Finished) => {
                    socket.close();
                    finished = true;
                }
                Err(error) => panic!("passive receive {error:?}"),
            }
        }
        match owner.ipv6_stream_read(endpoint, &mut b) {
            Ok(n) => answer.extend_from_slice(&b[..n]),
            Err(Error::Again) => {}
            Err(Error::Eof) => break,
            Err(error) => panic!("owner receive {error:?}"),
        }
    }
    assert!(finished);
    assert_eq!(request, vec![0x55; MAX_IO]);
    assert_eq!(answer, request);
    assert!(
        wire.borrow().frames[1]
            .iter()
            .all(|frame| frame.len() <= 1514)
    );
    owner.ipv6_stream_abort(endpoint).unwrap();
    step(&wire, &mut server, &mut owner);
    assert_eq!(owner.socket_count(), 0);
}

fn application_bytes(frame: &[u8]) -> usize {
    if frame.len() < 74 || frame[12..14] != [0x86, 0xdd] || frame[20] != 6 {
        return 0;
    }
    let segment = usize::from(u16::from_be_bytes([frame[18], frame[19]]));
    segment.saturating_sub(usize::from(frame[66] >> 4) * 4)
}

#[test]
fn graceful_close_discards_undrained_data_at_grant_expiry_once() {
    let (wire, _server, mut owner, _, endpoint) = connected();
    let expires = wire.borrow().now + 2;
    owner.ipv6_streams.entries[endpoint.slot].expires = expires;
    owner
        .ipv6_stream_write(endpoint, b"not-after-expiry")
        .unwrap();
    owner.ipv6_stream_close(endpoint).unwrap();
    let handle = owner.ipv6_streams.entries[endpoint.slot].socket.unwrap();
    assert!(owner.sockets.get::<tcp::Socket>(handle).send_queue() > 0);
    let before = wire.borrow().frames[1].len();
    wire.borrow_mut().now = expires;
    owner.poll();
    assert!(
        wire.borrow().frames[1][before..]
            .iter()
            .all(|frame| application_bytes(frame) == 0)
    );
    assert_eq!(owner.ipv6_stream_status(endpoint), Err(Error::Stale));
    assert_eq!(owner.socket_count(), 0);
    assert!(owner.port.ipv6_tcp_peers.iter().all(Option::is_none));
    let after = wire.borrow().frames[1].len();
    for _ in 0..3 {
        owner.ipv6_stream_maintain(false);
        owner.ipv6_stream_maintain(true);
    }
    assert_eq!(wire.borrow().frames[1].len(), after);
    let fresh = owner.ipv6_stream_grant(grant(40000)).unwrap();
    assert_ne!(fresh, endpoint);
    assert_eq!(
        owner.ipv6_stream_write(endpoint, b"late"),
        Err(Error::Stale)
    );
    owner.ipv6_stream_abort(fresh).unwrap();
}

#[test]
fn closing_only_clock_rewind_discards_queue_and_keeps_old_handle_stale() {
    let (wire, _, mut owner, _, endpoint) = connected();
    owner
        .ipv6_stream_write(endpoint, b"not-after-rewind")
        .unwrap();
    owner.ipv6_stream_close(endpoint).unwrap();
    let handle = owner.ipv6_streams.entries[endpoint.slot].socket.unwrap();
    assert!(owner.sockets.get::<tcp::Socket>(handle).send_queue() > 0);
    let previous = owner.ipv6_streams.entries[endpoint.slot].last_ms;
    wire.borrow_mut().now = previous - 1;
    let before = wire.borrow().frames[1].len();
    // Exercise the stream's own pre-poll boundary independently of the
    // enclosing IPv6 clock guard, then repeat both maintenance phases.
    owner.ipv6_stream_maintain(false);
    assert_eq!(owner.socket_count(), 0);
    owner.ipv6_stream_maintain(false);
    owner.poll();
    assert!(
        wire.borrow().frames[1][before..]
            .iter()
            .all(|frame| application_bytes(frame) == 0)
    );
    assert_eq!(owner.socket_count(), 0);
    assert_eq!(owner.ipv6_stream_status(endpoint), Err(Error::Stale));
    assert!(owner.port.ipv6_tcp_peers.iter().all(Option::is_none));
}

fn header(op: u8) -> [u8; HEADER] {
    let mut b = [0; HEADER];
    b[0] = VERSION;
    b[1] = op;
    b[3] = FAMILY;
    b[4..20].copy_from_slice(&peer(1, 7000).ip);
    b[20..24].copy_from_slice(&7u32.to_be_bytes());
    b[24..26].copy_from_slice(&7000u16.to_be_bytes());
    b
}
#[test]
fn session_v2_refuses_wrong_family_scope_and_malformed_io_before_connect() {
    let (_, _, mut owner) = pair();
    let mut session = Session::grant(&mut owner, grant(40000)).unwrap();
    let mut reply = [0; MAX_MESSAGE];
    for (offset, value, expected) in [
        (0, 1, Error::Invalid),
        (2, 1, Error::Invalid),
        (3, 4, Error::Invalid),
        (23, 8, Error::Denied),
        (25, 89, Error::Denied),
        (27, 1, Error::Invalid),
    ] {
        let mut b = header(CONNECT);
        b[offset] = value;
        assert_eq!(session.request(&mut owner, &b, &mut reply), HEADER);
        assert_eq!(reply[2], expected.code());
    }
    assert_eq!(
        session.request(&mut owner, &header(STATUS), &mut reply),
        HEADER + 1
    );
    assert_eq!(reply[3], FAMILY);
    assert_eq!(reply[HEADER], 0);
    assert_eq!(owner.socket_count(), 0);
}

struct MemoryPipe {
    input: VecDeque<u8>,
    clock: Rc<Cell<u64>>,
    writes: Rc<Cell<usize>>,
    fail_after: usize,
}
impl channel::Pipe for MemoryPipe {
    fn now_ms(&self) -> u64 {
        self.clock.get()
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        self.clock.set(self.clock.get() + 1);
        if self.input.is_empty() {
            return Ok(None);
        }
        let n = b.len().min(self.input.len()).min(3);
        for byte in &mut b[..n] {
            *byte = self.input.pop_front().unwrap();
        }
        Ok(Some(n))
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        self.clock.set(self.clock.get() + 1);
        let count = self.writes.get() + 1;
        self.writes.set(count);
        if count > self.fail_after {
            return Err(-5);
        }
        Ok(Some(b.len()))
    }
}
#[test]
fn interrupted_write_fences_client_without_second_request() {
    let mut reply = header(CONNECT).to_vec();
    reply[26..28].copy_from_slice(&1u16.to_be_bytes());
    reply.push(1);
    let mut input = (reply.len() as u16).to_be_bytes().to_vec();
    input.extend_from_slice(&reply);
    let writes = Rc::new(Cell::new(0));
    let clock = Rc::new(Cell::new(100));
    let pipe = MemoryPipe {
        input: input.into_iter().collect(),
        clock,
        writes: writes.clone(),
        fail_after: 4,
    };
    let mut client = Client::new(pipe, peer(1, 7000), |_| {});
    client.connect(1000).unwrap();
    assert_eq!(client.write(&[0; MAX_IO], 1000), Err(Error::Channel(-5)));
    let before = writes.get();
    assert_eq!(client.write(b"again", 1000), Err(Error::Stale));
    assert_eq!(writes.get(), before);
}

#[test]
fn ingress_keeps_udp_1280_and_admits_only_authorized_tcp_up_to_1500() {
    let config = Some(super::super::Config {
        address: ip(2),
        prefix_len: 64,
        scope: 7,
    });
    let mut flows = [None; MAX_ENDPOINTS];
    flows[0] = Some(Flow {
        local_port: 40000,
        peer: peer(1, 7000),
    });
    let mut frame = vec![0; 1514];
    frame[12..14].copy_from_slice(&[0x86, 0xdd]);
    frame[14] = 0x60;
    frame[18..20].copy_from_slice(&1460u16.to_be_bytes());
    frame[20] = 6;
    frame[22..38].copy_from_slice(&ip(1));
    frame[38..54].copy_from_slice(&ip(2));
    frame[54..56].copy_from_slice(&7000u16.to_be_bytes());
    frame[56..58].copy_from_slice(&40000u16.to_be_bytes());
    assert!(ingress(&frame, config, &flows));
    assert!(!ingress(&frame, config, &[None; MAX_ENDPOINTS]));
    frame[55] ^= 1;
    assert!(!ingress(&frame, config, &flows));
    frame[55] ^= 1;
    frame[18..20].copy_from_slice(&1461u16.to_be_bytes());
    assert!(!ingress(&frame, config, &flows));
    frame[18..20].copy_from_slice(&1460u16.to_be_bytes());
    frame[20] = 17;
    assert!(!super::super::ingress(&frame, config, &[Some(ip(1))]));
}
