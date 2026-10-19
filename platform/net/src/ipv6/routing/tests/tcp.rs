//! Actual smoltcp pairs behind a deterministic link-layer router fixture.
//! Linux forwarding/wire proof remains a separate native occurrence.
use super::*;
use crate::ipv6::{dns_tcp, stream};
use smoltcp::socket::{tcp, udp};

fn tcp_grant() -> stream::Grant {
    stream::Grant {
        local_port: 7003,
        peer: route().peer,
        connect_timeout_ms: 1000,
        lifetime_ms: 3000,
    }
}
fn active(s: &Stack<LinkEnd>) -> bool {
    s.port
        .ipv6_route
        .as_ref()
        .unwrap()
        .active(&s.port.ipv6_tcp_peers)
}
fn tcp_frame(peer: Address, port: u16) -> Vec<u8> {
    let mut body = [0; 20];
    body[..2].copy_from_slice(&peer.port.to_be_bytes());
    body[2..4].copy_from_slice(&port.to_be_bytes());
    body[12] = 0x50;
    body[13] = 0x10;
    let mut f = packet(peer.ip, 6, &body);
    checksum(&mut f, 70);
    f
}

#[test]
fn routed_tcp_grant_requires_exact_installed_peer_and_emits_nothing_before_connect() {
    let (w, mut s) = stack();
    assert_eq!(s.ipv6_stream_grant(tcp_grant()), Err(stream::Error::Denied));
    s.configure_ipv6_route(route()).unwrap();
    for peer in [
        Address {
            ip: ip(2, 10),
            ..route().peer
        },
        Address {
            port: 54,
            ..route().peer
        },
        Address {
            scope: 8,
            ..route().peer
        },
    ] {
        assert_eq!(
            s.ipv6_stream_grant(stream::Grant {
                peer,
                ..tcp_grant()
            }),
            Err(stream::Error::Denied)
        );
    }
    admission(&w, &mut s, advertisement(route().router), false);
    let e = s.ipv6_stream_grant(tcp_grant()).unwrap();
    admission(&w, &mut s, advertisement(route().router), false);
    admission(&w, &mut s, tcp_frame(route().peer, 7003), false);
    assert!(!active(&s));
    assert_eq!(s.socket_count(), 0);
    assert!(w.borrow().sent.is_empty());
    s.ipv6_stream_abort(e).unwrap();
    assert!(!active(&s));
}

#[test]
fn routed_tcp_activity_compares_full_peer_not_ip_or_any_live_flow() {
    let (w, mut s) = stack();
    s.configure_ipv6_route(route()).unwrap();
    // Internal substitution controls isolate the derived ND predicate from
    // grant validation. Such Flow records cannot be supplied through a pipe.
    for peer in [
        Address {
            port: 54,
            ..route().peer
        },
        Address {
            scope: 8,
            ..route().peer
        },
        Address {
            ip: ip(1, 3),
            ..route().peer
        },
    ] {
        s.port.ipv6_tcp_peers[0] = Some(stream::Flow {
            local_port: 7003,
            peer,
        });
        assert!(!active(&s));
        admission(&w, &mut s, advertisement(route().router), false);
    }
    s.port.ipv6_tcp_peers.fill(None);
    let e = s.ipv6_stream_grant(tcp_grant()).unwrap();
    s.ipv6_stream_connect(e).unwrap();
    assert!(active(&s));
    admission(&w, &mut s, advertisement(ip(1, 3)), false);
    admission(&w, &mut s, advertisement(route().peer.ip), false);
    admission(&w, &mut s, advertisement(route().router), true);
    s.port.rx_length = None;
    // Existing TCP ingress remains exact tuple filtering, independently of ND.
    for (peer, port) in [
        (
            Address {
                ip: ip(2, 10),
                ..route().peer
            },
            7003,
        ),
        (
            Address {
                port: 54,
                ..route().peer
            },
            7003,
        ),
        (route().peer, 7004),
    ] {
        admission(&w, &mut s, tcp_frame(peer, port), false);
    }
    admission(&w, &mut s, tcp_frame(route().peer, 7003), true);
    s.port.rx_length = None;
    s.ipv6_stream_fence();
    assert!(!active(&s));
    admission(&w, &mut s, advertisement(route().router), false);
}

#[test]
fn routed_udp_and_tcp_retirement_remove_only_their_own_router_authority() {
    let (w, mut s) = stack();
    s.configure_ipv6_route(route()).unwrap();
    let udp = s.ipv6_bind(grant()).unwrap();
    let tcp = s.ipv6_stream_grant(tcp_grant()).unwrap();
    s.ipv6_stream_connect(tcp).unwrap();
    s.ipv6_close(udp).unwrap();
    assert!(active(&s));
    admission(&w, &mut s, advertisement(route().router), true);
    s.port.rx_length = None;
    s.ipv6_stream_fence();
    assert!(!active(&s));
    let udp = s.ipv6_bind(grant()).unwrap();
    let tcp = s.ipv6_stream_grant(tcp_grant()).unwrap();
    s.ipv6_stream_connect(tcp).unwrap();
    s.ipv6_stream_fence();
    assert!(active(&s));
    s.ipv6_close(udp).unwrap();
    assert!(!active(&s));
    admission(&w, &mut s, advertisement(route().router), false);
}

#[test]
fn routed_tcp_abort_expiry_rewind_link_and_fence_discard_queued_input() {
    for mode in 0..5 {
        let (w, mut s) = stack();
        s.configure_ipv6_route(route()).unwrap();
        let e = s.ipv6_stream_grant(tcp_grant()).unwrap();
        s.ipv6_stream_connect(e).unwrap();
        // Both packets existed before the observed terminal boundary.
        w.borrow_mut()
            .incoming
            .push_back(advertisement(route().router));
        w.borrow_mut()
            .incoming
            .push_back(tcp_frame(route().peer, 7003));
        match mode {
            0 => s.ipv6_stream_abort(e).unwrap(),
            1 => w.borrow_mut().now += tcp_grant().lifetime_ms,
            2 => w.borrow_mut().now -= 1,
            3 => w.borrow_mut().reading = None,
            _ => s.ipv6_fence(),
        }
        // Existing abort may retain its single reset opportunity until the
        // after-poll maintenance pass; no application bytes are queued here.
        for _ in 0..3 {
            poll(&w, &mut s);
        }
        assert_eq!(s.socket_count(), 0, "mode {mode}");
        assert!(!active(&s), "mode {mode}");
        assert!(s.ipv6_stream_write(e, b"late").is_err());
        assert_eq!(s.port.rx_length, None);
        w.borrow_mut().incoming.clear();
        admission(&w, &mut s, advertisement(route().router), false);
        admission(&w, &mut s, tcp_frame(route().peer, 7003), false);
    }
}

struct RoutedWire {
    now: u64,
    queues: [VecDeque<Vec<u8>>; 2],
    sent: [Vec<Vec<u8>>; 2],
    resolve: bool,
}
struct RoutedEnd(Rc<RefCell<RoutedWire>>, usize);
fn host_ip(side: usize) -> [u8; 16] {
    if side == 0 {
        local().address
    } else {
        route().peer.ip
    }
}
fn next_hop(side: usize) -> [u8; 16] {
    ip(if side == 0 { 1 } else { 2 }, 2)
}
fn host_mac(side: usize) -> [u8; 6] {
    [2, 0, 0, 0, 0x10, side as u8 + 1]
}
fn router_mac(side: usize) -> [u8; 6] {
    [2, 0, 0, 0, 0x20, side as u8 + 1]
}
fn router_na(side: usize) -> Vec<u8> {
    let mut f = advertisement(next_hop(side));
    f[..6].copy_from_slice(&host_mac(side));
    f[6..12].copy_from_slice(&router_mac(side));
    f[38..54].copy_from_slice(&host_ip(side));
    f[80..86].copy_from_slice(&router_mac(side));
    checksum(&mut f, 56);
    f
}
impl Link for RoutedEnd {
    fn mac(&self) -> [u8; 6] {
        host_mac(self.1)
    }
    fn now_ms(&self) -> u64 {
        self.0.borrow().now
    }
    fn pause(&self, ms: u64) {
        self.0.borrow_mut().now += ms;
    }
    fn read(&self) -> Option<LinkReading> {
        Some(LinkReading {
            link_up: true,
            disabled: false,
            rx_missed: 0,
        })
    }
    fn receive(&mut self, b: &mut [u8; FRAME_MAX], _: u64) -> Result<Option<usize>, i64> {
        Ok(self.0.borrow_mut().queues[self.1].pop_front().map(|f| {
            b[..f.len()].copy_from_slice(&f);
            f.len()
        }))
    }
    fn send(&mut self, f: &[u8]) -> Result<(), i64> {
        let mut w = self.0.borrow_mut();
        w.sent[self.1].push(f.to_vec());
        if f.len() >= 86 && f[20] == 58 && f[54] == 135 {
            assert_eq!(
                &f[62..78],
                &next_hop(self.1),
                "engine resolved an off-link peer directly"
            );
            if w.resolve {
                w.queues[self.1].push_back(router_na(self.1));
            }
        } else if f.len() >= 62 && matches!(f[20], 6 | 17) {
            assert_eq!(&f[..6], &router_mac(self.1));
            assert_eq!(&f[22..38], &host_ip(self.1));
            assert_eq!(&f[38..54], &host_ip(1 - self.1));
            let mut forwarded = f.to_vec();
            forwarded[..6].copy_from_slice(&host_mac(1 - self.1));
            forwarded[6..12].copy_from_slice(&router_mac(1 - self.1));
            forwarded[21] -= 1;
            w.queues[1 - self.1].push_back(forwarded);
        }
        Ok(())
    }
}
struct Pair {
    wire: Rc<RefCell<RoutedWire>>,
    owner: Stack<RoutedEnd>,
    server: Stack<RoutedEnd>,
    tcp: SocketHandle,
    udp: SocketHandle,
    question: Vec<u8>,
    response: VecDeque<u8>,
    tcp_queries: usize,
    udp_queries: usize,
    answer_tcp: bool,
}
fn response(query: &[u8], truncated: bool) -> Vec<u8> {
    assert_eq!(&query[12..25], b"\x03www\x07example\0");
    let v6 = query[26] == 28;
    let mut b = query.to_vec();
    b[2..4].copy_from_slice(&(if truncated { 0x8380u16 } else { 0x8180u16 }).to_be_bytes());
    b[6..8].copy_from_slice(&(if truncated { 0u16 } else { 1u16 }).to_be_bytes());
    if !truncated {
        b.extend_from_slice(&[
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
        b.extend_from_slice(if v6 {
            &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]
        } else {
            &[192, 0, 2, 9]
        });
    }
    b
}
impl Pair {
    fn new() -> Self {
        Self::with_ip_mtu(1500)
    }
    fn with_ip_mtu(ip_mtu: usize) -> Self {
        let wire = Rc::new(RefCell::new(RoutedWire {
            now: 100,
            queues: [VecDeque::new(), VecDeque::new()],
            sent: [Vec::new(), Vec::new()],
            resolve: true,
        }));
        let make = |side| {
            let mut s = Stack::open_with_ip_mtu(
                RoutedEnd(wire.clone(), side),
                crate::Config {
                    gateway: None,
                    ..crate::Config::qemu_user()
                },
                ip_mtu,
            )
            .unwrap();
            s.configure_ipv6(Config {
                address: host_ip(side),
                prefix_len: 64,
                scope: 7,
            })
            .unwrap();
            s.configure_ipv6_route(Route {
                router: next_hop(side),
                peer: Address {
                    ip: host_ip(1 - side),
                    scope: 7,
                    port: if side == 0 { 53 } else { 7002 },
                },
            })
            .unwrap();
            s
        };
        let owner = make(0);
        let mut server = make(1);
        // This is a controlled passive engine fixture, not a new server API.
        let mut tcp = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 8192]),
            tcp::SocketBuffer::new(vec![0; 8192]),
        );
        tcp.listen((Ipv6Address::from(host_ip(1)), 53)).unwrap();
        let tcp = server.sockets.add(tcp);
        let mut udp = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]),
        );
        udp.bind((Ipv6Address::from(host_ip(1)), 53)).unwrap();
        let udp = server.sockets.add(udp);
        server.port.ipv6_peers[0] = Some(host_ip(0));
        server.port.ipv6_route.as_mut().unwrap().ports[0] = Some(53);
        server.port.ipv6_tcp_peers[0] = Some(stream::Flow {
            local_port: 53,
            peer: Address {
                ip: host_ip(0),
                port: 7003,
                scope: 7,
            },
        });
        Self {
            wire,
            owner,
            server,
            tcp,
            udp,
            question: Vec::new(),
            response: VecDeque::new(),
            tcp_queries: 0,
            udp_queries: 0,
            answer_tcp: true,
        }
    }
    fn pump(&mut self) {
        self.owner.poll();
        self.server.poll();
        let udp = self.server.sockets.get_mut::<udp::Socket>(self.udp);
        if udp.can_recv() {
            let (query, meta) = udp.recv().map(|(b, m)| (b.to_vec(), m)).unwrap();
            self.udp_queries += 1;
            udp.send_slice(&response(&query, true), meta.endpoint)
                .unwrap();
        }
        let tcp = self.server.sockets.get_mut::<tcp::Socket>(self.tcp);
        if tcp.can_recv() {
            let bytes = tcp.recv(|b| (b.len(), b.to_vec())).unwrap();
            self.question.extend(bytes);
        }
        while self.question.len() >= 2 {
            let n = u16::from_be_bytes([self.question[0], self.question[1]]) as usize;
            if self.question.len() < n + 2 {
                break;
            }
            let query: Vec<u8> = self.question.drain(..n + 2).skip(2).collect();
            self.tcp_queries += 1;
            if self.answer_tcp {
                let answer = response(&query, false);
                self.response.extend((answer.len() as u16).to_be_bytes());
                self.response.extend(answer);
            }
        }
        if tcp.can_send() && !self.response.is_empty() {
            let contiguous: Vec<_> = self.response.iter().copied().collect();
            let n = tcp.send_slice(&contiguous).unwrap();
            self.response.drain(..n);
        }
        if tcp.state() == TcpState::CloseWait {
            tcp.close();
        }
        self.wire.borrow_mut().now += 1;
    }
}
struct TestServerPipe(Rc<RefCell<PipeQueues>>, Rc<RefCell<RoutedWire>>);
impl Pipe for TestServerPipe {
    fn now_ms(&self) -> u64 {
        self.1.borrow().now
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        let mut q = self.0.borrow_mut();
        let n = b.len().min(q.requests.len()).min(7);
        for x in &mut b[..n] {
            *x = q.requests.pop_front().unwrap();
        }
        Ok((n != 0).then_some(n))
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        self.0.borrow_mut().responses.extend(b);
        Ok(Some(b.len()))
    }
}
struct TestClientPipe {
    pair: Pair,
    channel: dns_tcp::Channel,
    queues: Rc<RefCell<PipeQueues>>,
}
impl TestClientPipe {
    fn new(answer_tcp: bool) -> Self {
        Self::with_ip_mtu(answer_tcp, 1500)
    }
    fn with_ip_mtu(answer_tcp: bool, mtu: usize) -> Self {
        let mut pair = Pair::with_ip_mtu(mtu);
        pair.answer_tcp = answer_tcp;
        let session = dns_tcp::Session::grant(
            &mut pair.owner,
            grant(),
            stream::Grant {
                lifetime_ms: 60000,
                ..tcp_grant()
            },
        )
        .unwrap();
        Self {
            pair,
            channel: dns_tcp::Channel::new(session),
            queues: Rc::new(RefCell::new(PipeQueues {
                requests: VecDeque::new(),
                responses: VecDeque::new(),
            })),
        }
    }
    fn pump(&mut self) {
        self.pair.pump();
        self.channel.poll(
            &mut self.pair.owner,
            &mut TestServerPipe(self.queues.clone(), self.pair.wire.clone()),
        );
    }
}
impl Pipe for TestClientPipe {
    fn now_ms(&self) -> u64 {
        self.pair.wire.borrow().now
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        self.pump();
        let mut q = self.queues.borrow_mut();
        let n = b.len().min(q.responses.len()).min(11);
        for x in &mut b[..n] {
            *x = q.responses.pop_front().unwrap();
        }
        Ok((n != 0).then_some(n))
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        self.queues.borrow_mut().requests.extend(b);
        self.pump();
        Ok(Some(b.len()))
    }
}

struct SharedClient(Rc<RefCell<TestClientPipe>>);
impl Pipe for SharedClient {
    fn now_ms(&self) -> u64 {
        self.0.borrow().now_ms()
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        self.0.borrow_mut().read(b)
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        self.0.borrow_mut().write(b)
    }
}

#[test]
fn routed_dns_tcp_silence_keeps_original_lookup_deadline_without_resending_query() {
    let shared = Rc::new(RefCell::new(TestClientPipe::new(false)));
    let mut resolver = crate::dns::Resolver::new(
        dns_tcp::DatagramTcp::new(SharedClient(shared.clone()), route().peer, |_| {}),
        0x1234,
    );
    assert_eq!(
        resolver.lookup("www.example"),
        Err(crate::dns::Error::Timeout)
    );
    let p = shared.borrow();
    assert_eq!(p.pair.udp_queries, 1);
    assert_eq!(p.pair.tcp_queries, 1);
    assert!(p.pair.wire.borrow().now <= 100 + crate::dns::LOOKUP_MS + 10);
}

#[test]
fn real_routed_engine_pair_dns_tc_falls_back_for_a_and_aaaa_under_original_deadline() {
    for v6 in [false, true] {
        let shared = Rc::new(RefCell::new(TestClientPipe::new(true)));
        let mut resolver = crate::dns::Resolver::new(
            dns_tcp::DatagramTcp::new(SharedClient(shared.clone()), route().peer, |_| {}),
            0x1234,
        );
        if v6 {
            assert_eq!(
                resolver.lookup_aaaa("www.example").unwrap().addresses[0],
                ip_answer()
            );
        } else {
            assert_eq!(
                resolver.lookup("www.example").unwrap().addresses[0],
                [192, 0, 2, 9]
            );
        }
        let p = shared.borrow();
        assert_eq!(p.pair.udp_queries, 1);
        assert_eq!(p.pair.tcp_queries, 1);
        assert!(p.pair.wire.borrow().now < 100 + crate::dns::LOOKUP_MS);
        let syn = p.pair.wire.borrow().sent[0]
            .iter()
            .find(|f| f.len() >= 74 && f[20] == 6 && f[67] & 2 != 0)
            .unwrap()
            .clone();
        let packet = smoltcp::wire::TcpPacket::new_checked(&syn[54..]).unwrap();
        let repr = smoltcp::wire::TcpRepr::parse(
            &packet,
            &IpAddress::Ipv6(Ipv6Address::from(host_ip(0))),
            &IpAddress::Ipv6(Ipv6Address::from(host_ip(1))),
            &phy::ChecksumCapabilities::default(),
        )
        .unwrap();
        assert_eq!(repr.max_seg_size, Some(1440));
    }
}
fn ip_answer() -> [u8; 16] {
    [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]
}

#[test]
fn routed_engine_mtu_controls_syn_mss_and_bidirectional_full_size_data_segments() {
    // Private engine sockets have a large receive window so the selected MSS,
    // rather than the public stream's 1024-byte buffer, bounds actual segments.
    // Public grant/pipe behavior is covered by the separate DNS consumer test.
    for mtu in [1280, 1500] {
        let mut p = Pair::with_ip_mtu(mtu);
        let mut client = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 8192]),
            tcp::SocketBuffer::new(vec![0; 8192]),
        );
        client
            .connect(
                p.owner.iface.context(),
                (Ipv6Address::from(host_ip(1)), 53),
                (Ipv6Address::from(host_ip(0)), 7003),
            )
            .unwrap();
        let client = p.owner.sockets.add(client);
        p.owner.port.ipv6_tcp_peers[0] = Some(stream::Flow {
            local_port: 7003,
            peer: route().peer,
        });
        let left: Vec<u8> = (0..3000).map(|i| (i % 251) as u8).collect();
        let right: Vec<u8> = (0..3000).map(|i| (250 - i % 251) as u8).collect();
        let mut queued = false;
        let mut received_left = Vec::new();
        let mut received_right = Vec::new();
        for _ in 0..5000 {
            p.owner.poll();
            p.server.poll();
            let a = p.owner.sockets.get_mut::<tcp::Socket>(client);
            let b = p.server.sockets.get_mut::<tcp::Socket>(p.tcp);
            if !queued && a.state() == TcpState::Established && b.state() == TcpState::Established {
                assert_eq!(a.send_slice(&left).unwrap(), left.len());
                assert_eq!(b.send_slice(&right).unwrap(), right.len());
                queued = true;
            }
            if a.can_recv() {
                a.recv(|bytes| {
                    received_left.extend_from_slice(bytes);
                    (bytes.len(), ())
                })
                .unwrap();
            }
            if b.can_recv() {
                b.recv(|bytes| {
                    received_right.extend_from_slice(bytes);
                    (bytes.len(), ())
                })
                .unwrap();
            }
            if received_left.len() == right.len() && received_right.len() == left.len() {
                break;
            }
            p.wire.borrow_mut().now += 1;
        }
        assert!(queued);
        assert_eq!(received_left, right);
        assert_eq!(received_right, left);
        let wire = p.wire.borrow();
        for side in 0..2 {
            let mut syns = 0;
            let mut largest = 0;
            for f in &wire.sent[side] {
                assert!(f.len() <= mtu + 14);
                if f.len() < 74 || f[20] != 6 {
                    continue;
                }
                let packet = smoltcp::wire::TcpPacket::new_checked(&f[54..]).unwrap();
                let repr = smoltcp::wire::TcpRepr::parse(
                    &packet,
                    &IpAddress::Ipv6(Ipv6Address::from(host_ip(side))),
                    &IpAddress::Ipv6(Ipv6Address::from(host_ip(1 - side))),
                    &phy::ChecksumCapabilities::default(),
                )
                .unwrap();
                if f[67] & 2 != 0 {
                    syns += 1;
                    assert_eq!(repr.max_seg_size, Some((mtu - 60) as u16));
                }
                if !repr.payload.is_empty() {
                    largest = largest.max(f.len() - 14);
                }
            }
            assert_eq!(syns, 1, "one handshake in each direction");
            assert_eq!(
                largest, mtu,
                "large-window data must exercise the selected MTU"
            );
        }
        assert_eq!(p.owner.stats().tx_oversize, 0);
        assert_eq!(p.server.stats().tx_oversize, 0);
    }
}

#[test]
fn conservative_1280_same_resolver_a_then_aaaa_keeps_grants_and_deadlines() {
    let shared = Rc::new(RefCell::new(TestClientPipe::with_ip_mtu(true, 1280)));
    let mut resolver = crate::dns::Resolver::new(
        dns_tcp::DatagramTcp::new(SharedClient(shared.clone()), route().peer, |_| {}),
        0x1234,
    );
    let start = shared.borrow().now_ms();
    assert_eq!(
        resolver.lookup("www.example").unwrap().addresses[0],
        [192, 0, 2, 9]
    );
    let second = shared.borrow().now_ms();
    assert!(second < start + crate::dns::LOOKUP_MS);
    assert_eq!(
        resolver.lookup_aaaa("www.example").unwrap().addresses[0],
        ip_answer()
    );
    assert!(shared.borrow().now_ms() < second + crate::dns::LOOKUP_MS);
    drop(resolver);
    let mut p = shared.borrow_mut();
    assert_eq!((p.pair.udp_queries, p.pair.tcp_queries), (2, 2));
    let wire = p.pair.wire.borrow();
    let syns: Vec<_> = wire.sent[0]
        .iter()
        .filter(|f| f.len() >= 74 && f[20] == 6 && f[67] & 0x12 == 2)
        .collect();
    assert_eq!(syns.len(), 1);
    let packet = smoltcp::wire::TcpPacket::new_checked(&syns[0][54..]).unwrap();
    let repr = smoltcp::wire::TcpRepr::parse(
        &packet,
        &IpAddress::Ipv6(Ipv6Address::from(host_ip(0))),
        &IpAddress::Ipv6(Ipv6Address::from(host_ip(1))),
        &phy::ChecksumCapabilities::default(),
    )
    .unwrap();
    assert_eq!(repr.max_seg_size, Some(1220));
    assert!(wire.sent.iter().flatten().all(|f| f.len() <= 1294));
    drop(wire);
    p.pair.owner.ipv6_fence();
    assert_eq!(p.pair.owner.socket_count(), 0);
}

#[test]
fn same_routed_resolver_a_then_aaaa_reuses_one_connection_and_closes() {
    let shared = Rc::new(RefCell::new(TestClientPipe::new(true)));
    let mut resolver = crate::dns::Resolver::new(
        dns_tcp::DatagramTcp::new(SharedClient(shared.clone()), route().peer, |_| {}),
        0x1234,
    );
    let first_start = shared.borrow().now_ms();
    assert_eq!(
        resolver.lookup("www.example").unwrap().addresses[0],
        [192, 0, 2, 9]
    );
    let second_start = shared.borrow().now_ms();
    assert!(second_start < first_start + crate::dns::LOOKUP_MS);
    assert_eq!(
        resolver.lookup_aaaa("www.example").unwrap().addresses[0],
        ip_answer()
    );
    assert!(shared.borrow().now_ms() < second_start + crate::dns::LOOKUP_MS);
    drop(resolver);
    {
        let p = shared.borrow();
        assert_eq!((p.pair.udp_queries, p.pair.tcp_queries), (2, 2));
        assert_eq!(
            p.pair.wire.borrow().sent[0]
                .iter()
                .filter(|f| f.len() >= 74 && f[20] == 6 && f[67] & 0x12 == 2)
                .count(),
            1,
            "a second TCP connection replaced the first"
        );
    }
    let mut close = [0; HEADER];
    close[..4].copy_from_slice(&[
        crate::ipv6::session::VERSION,
        stream::CLOSE,
        0,
        crate::ipv6::session::FAMILY,
    ]);
    close[4..20].copy_from_slice(&route().peer.ip);
    close[20..24].copy_from_slice(&route().peer.scope.to_be_bytes());
    close[24..26].copy_from_slice(&route().peer.port.to_be_bytes());
    let mut reply = [0; MAX_MESSAGE];
    assert_eq!(
        crate::ipv6::channel::transact(&mut SharedClient(shared.clone()), &close, &mut reply, 1000),
        Ok(HEADER)
    );
    assert_eq!(&reply[..HEADER], &close);
    let mut p = shared.borrow_mut();
    for _ in 0..64 {
        p.pump();
    }
    for side in 0..2 {
        assert!(
            p.pair.wire.borrow().sent[side]
                .iter()
                .any(|f| f.len() >= 74 && f[20] == 6 && f[67] & 1 != 0),
            "side {side} FIN absent after paired close"
        );
    }
    p.pair.owner.ipv6_fence();
    assert_eq!(p.pair.owner.socket_count(), 0);
}

#[test]
fn routed_stream_close_drains_only_until_original_lifetime_then_late_nd_refuses() {
    let mut p = Pair::new();
    let e = p.owner.ipv6_stream_grant(tcp_grant()).unwrap();
    p.owner.ipv6_stream_connect(e).unwrap();
    for _ in 0..100 {
        p.pump();
        if p.owner.ipv6_stream_status(e).unwrap().connected {
            break;
        }
    }
    assert!(p.owner.ipv6_stream_status(e).unwrap().connected);
    p.owner.ipv6_stream_write(e, b"pending").unwrap();
    p.owner.ipv6_stream_close(e).unwrap();
    for _ in 0..64 {
        p.pump();
    }
    for side in 0..2 {
        assert!(
            p.wire.borrow().sent[side]
                .iter()
                .any(|f| f.len() >= 74 && f[20] == 6 && f[67] & 1 != 0),
            "side {side} FIN absent"
        );
    }
    assert!(
        p.owner
            .port
            .ipv6_route
            .as_ref()
            .unwrap()
            .active(&p.owner.port.ipv6_tcp_peers)
    );
    assert!(p.owner.ipv6_stream_write(e, b"late").is_err());
    p.wire.borrow_mut().now = 100 + tcp_grant().lifetime_ms;
    p.wire.borrow_mut().queues[0].push_back(router_na(0));
    p.owner.poll();
    assert_eq!(p.owner.socket_count(), 0);
    assert!(
        !p.owner
            .port
            .ipv6_route
            .as_ref()
            .unwrap()
            .active(&p.owner.port.ipv6_tcp_peers)
    );
    assert_eq!(p.owner.port.rx_length, None);
}
