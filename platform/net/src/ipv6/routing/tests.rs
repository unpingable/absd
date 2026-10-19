//! Actual engine + framed DNS consumer with a controlled router fixture.
//! The fixture constructs ND/UDP independently; it is not Linux wire proof.
use super::*;
use crate::ipv6::channel::{Channel, Pipe};
use crate::ipv6::session::{HEADER, MAX_MESSAGE, Session};
use std::cell::RefCell;
use std::rc::Rc;

const LOCAL_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const ROUTER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
fn local() -> Config {
    Config {
        address: ip(1, 0x15),
        prefix_len: 64,
        scope: 7,
    }
}
fn ip(net: u8, last: u8) -> [u8; 16] {
    let mut ip = [0; 16];
    ip[0] = 0xfd;
    ip[7] = net;
    ip[15] = last;
    ip
}
fn route() -> Route {
    Route {
        router: ip(1, 2),
        peer: Address {
            ip: ip(2, 9),
            port: 53,
            scope: 7,
        },
    }
}
fn grant() -> Grant {
    Grant {
        local_port: 7002,
        peer: route().peer,
    }
}

// RFC 8200 pseudo-header and RFC 1071 one's-complement sum. No product
// packet constructor is used for the independently submitted fixture bytes.
fn checksum(frame: &mut [u8], offset: usize) {
    frame[offset..offset + 2].fill(0);
    let length = frame.len() - 54;
    let mut sum: u32 = frame[22..54]
        .chunks_exact(2)
        .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
        .sum();
    sum += length as u32 + u32::from(frame[20]);
    for bytes in frame[54..].chunks(2) {
        sum += u32::from(bytes[0]) * 256 + u32::from(*bytes.get(1).unwrap_or(&0));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let value = !(sum as u16);
    frame[offset..offset + 2]
        .copy_from_slice(&if value == 0 { u16::MAX } else { value }.to_be_bytes());
}
fn packet(source: [u8; 16], protocol: u8, body: &[u8]) -> Vec<u8> {
    let mut f = vec![0; 54 + body.len()];
    f[..6].copy_from_slice(&LOCAL_MAC);
    f[6..12].copy_from_slice(&ROUTER_MAC);
    f[12..14].copy_from_slice(&[0x86, 0xdd]);
    f[14] = 0x60;
    f[18..20].copy_from_slice(&(body.len() as u16).to_be_bytes());
    f[20] = protocol;
    f[21] = 255;
    f[22..38].copy_from_slice(&source);
    f[38..54].copy_from_slice(&local().address);
    f[54..].copy_from_slice(body);
    f
}
fn advertisement(router: [u8; 16]) -> Vec<u8> {
    let mut body = [0; 32];
    body[0] = 136;
    body[4] = 0xe0;
    body[8..24].copy_from_slice(&router);
    body[24..26].copy_from_slice(&[2, 1]);
    body[26..32].copy_from_slice(&ROUTER_MAC);
    let mut f = packet(router, 58, &body);
    checksum(&mut f, 56);
    f
}
fn udp(source: Address, port: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 8 + body.len()];
    bytes[..2].copy_from_slice(&source.port.to_be_bytes());
    bytes[2..4].copy_from_slice(&port.to_be_bytes());
    let n = bytes.len() as u16;
    bytes[4..6].copy_from_slice(&n.to_be_bytes());
    bytes[8..].copy_from_slice(body);
    let mut f = packet(source.ip, 17, &bytes);
    checksum(&mut f, 60);
    f
}

struct Wire {
    now: u64,
    reading: Option<LinkReading>,
    incoming: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
    resolve: bool,
    dns: bool,
    truncated: bool,
}
struct LinkEnd(Rc<RefCell<Wire>>);
impl Link for LinkEnd {
    fn mac(&self) -> [u8; 6] {
        LOCAL_MAC
    }
    fn now_ms(&self) -> u64 {
        self.0.borrow().now
    }
    fn read(&self) -> Option<LinkReading> {
        self.0.borrow().reading
    }
    fn pause(&self, n: u64) {
        self.0.borrow_mut().now += n;
    }
    fn receive(&mut self, b: &mut [u8; FRAME_MAX], _: u64) -> Result<Option<usize>, i64> {
        Ok(self.0.borrow_mut().incoming.pop_front().map(|f| {
            b[..f.len()].copy_from_slice(&f);
            f.len()
        }))
    }
    fn send(&mut self, f: &[u8]) -> Result<(), i64> {
        let mut w = self.0.borrow_mut();
        w.sent.push(f.to_vec());
        if f.len() >= 86 && f[20] == 58 && f[54] == 135 && w.resolve {
            assert_eq!(&f[62..78], &route().router);
            w.incoming.push_back(advertisement(route().router));
        }
        if f.len() >= 62 && f[20] == 17 && w.dns {
            let query = &f[62..];
            assert_eq!(&query[2..12], &[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
            assert_eq!(&query[12..25], b"\x03www\x07example\0");
            let v6 = query[26] == 28;
            assert_eq!(&query[25..], &[0, if v6 { 28 } else { 1 }, 0, 1]);
            let mut answer = query.to_vec();
            answer[2..4]
                .copy_from_slice(&if w.truncated { 0x8380u16 } else { 0x8180u16 }.to_be_bytes());
            if !w.truncated {
                answer[7] = 1;
                answer.extend_from_slice(&[
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
                    answer.extend_from_slice(&[
                        0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
                    ]);
                } else {
                    answer.extend_from_slice(&[192, 0, 2, 9]);
                }
            }
            w.incoming.push_back(udp(route().peer, 7002, &answer));
        }
        Ok(())
    }
}
fn stack() -> (Rc<RefCell<Wire>>, Stack<LinkEnd>) {
    let w = Rc::new(RefCell::new(Wire {
        now: 100,
        reading: Some(LinkReading {
            link_up: true,
            disabled: false,
            rx_missed: 0,
        }),
        incoming: VecDeque::new(),
        sent: Vec::new(),
        resolve: true,
        dns: false,
        truncated: false,
    }));
    let mut s = Stack::open(
        LinkEnd(w.clone()),
        crate::Config {
            gateway: None,
            ..crate::Config::qemu_user()
        },
    )
    .unwrap();
    s.configure_ipv6(local()).unwrap();
    (w, s)
}
fn poll(w: &Rc<RefCell<Wire>>, s: &mut Stack<LinkEnd>) {
    s.poll();
    w.borrow_mut().now += 1;
}
fn udp_count(w: &Rc<RefCell<Wire>>) -> usize {
    w.borrow()
        .sent
        .iter()
        .filter(|f| f.len() >= 62 && f[20] == 17)
        .count()
}

// Observe the Port's decision before the engine or endpoint receive filter
// can consume the evidence. Accepted positive controls leave their exact
// bytes held for the caller's next engine poll.
fn admission(w: &Rc<RefCell<Wire>>, s: &mut Stack<LinkEnd>, frame: Vec<u8>, allowed: bool) {
    assert_eq!(s.port.rx_length, None);
    let length = frame.len();
    w.borrow_mut().incoming.push_back(frame.clone());
    assert_eq!(s.port.fill(0), Ok(allowed));
    assert_eq!(s.port.rx_length, allowed.then_some(length));
    assert!(w.borrow().incoming.is_empty());
    if allowed {
        assert_eq!(&s.port.rx[..length], frame.as_slice());
    }
}

#[test]
fn exact_route_configuration_is_once_only_and_not_a_default_or_grant() {
    let (_, mut s) = stack();
    assert_eq!(s.ipv6_bind(grant()), Err(Error::Denied));
    for bad in [
        Route {
            router: local().address,
            ..route()
        },
        Route {
            router: ip(2, 2),
            ..route()
        },
        Route {
            router: [0; 16],
            ..route()
        },
        Route {
            peer: Address {
                scope: 8,
                ..route().peer
            },
            ..route()
        },
        Route {
            peer: Address {
                ip: ip(1, 9),
                ..route().peer
            },
            ..route()
        },
        Route {
            peer: Address {
                port: 0,
                ..route().peer
            },
            ..route()
        },
    ] {
        assert_eq!(s.configure_ipv6_route(bad), Err(Error::Denied));
        assert_eq!(s.ipv6_route(), None);
    }
    s.configure_ipv6_route(route()).unwrap();
    assert_eq!(s.configure_ipv6_route(route()), Err(Error::InUse));
    assert!(s.iface.routes().get_default_ipv6_route().is_none());
    assert_eq!(s.socket_count(), 0);
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
        assert_eq!(s.ipv6_bind(Grant { peer, ..grant() }), Err(Error::Denied));
    }
    let stream = s
        .ipv6_stream_grant(stream::Grant {
            local_port: 7003,
            peer: route().peer,
            connect_timeout_ms: 1000,
            lifetime_ms: 1000,
        })
        .unwrap();
    // Route and endpoint reservation alone still create no engine socket.
    assert_eq!(s.socket_count(), 0);
    assert!(!s.port.ipv6_route.as_ref().unwrap().active(&s.port.ipv6_tcp_peers));
    s.ipv6_stream_abort(stream).unwrap();
    s.ipv6_bind(grant()).unwrap();
}

#[test]
fn active_grants_and_full_engine_route_table_refuse_configuration_without_partial_state() {
    let (_, mut s) = stack();
    let e = s
        .ipv6_bind(Grant {
            peer: Address {
                ip: ip(1, 2),
                ..route().peer
            },
            ..grant()
        })
        .unwrap();
    assert_eq!(s.configure_ipv6_route(route()), Err(Error::InUse));
    s.ipv6_close(e).unwrap();
    s.iface.routes_mut().update(|routes| {
        while routes
            .push(smoltcp::iface::Route::new_ipv6_gateway(Ipv6Address::from(
                ip(1, 3),
            )))
            .is_ok()
        {}
    });
    assert_eq!(s.configure_ipv6_route(route()), Err(Error::Exhausted));
    assert_eq!(s.ipv6_route(), None);
    assert_eq!(s.ipv6_bind(grant()), Err(Error::Denied));
}

#[test]
fn actual_engine_resolves_only_router_and_keeps_logical_peer_and_datagram_bounds() {
    let (w, mut s) = stack();
    s.configure_ipv6_route(route()).unwrap();
    let e = s.ipv6_bind(grant()).unwrap();
    let data = vec![0x5a; MAX_DATAGRAM];
    s.ipv6_send(e, route().peer, &data).unwrap();
    for _ in 0..8 {
        poll(&w, &mut s);
    }
    let sent = w.borrow();
    let packets: Vec<_> = sent
        .sent
        .iter()
        .filter(|f| f.len() >= 62 && f[20] == 17)
        .collect();
    assert_eq!(packets.len(), 1);
    let f = packets[0];
    assert_eq!(&f[..6], &ROUTER_MAC);
    assert_eq!(&f[22..38], &local().address);
    assert_eq!(&f[38..54], &route().peer.ip);
    assert_eq!(&f[62..], data);
    assert_eq!(f.len(), 14 + 1280);
    drop(sent);
    assert_eq!(
        s.ipv6_send(e, route().peer, &[0; MAX_DATAGRAM + 1]),
        Err(Error::Oversize)
    );
    w.borrow_mut()
        .incoming
        .push_back(udp(route().peer, 7002, b"reply"));
    poll(&w, &mut s);
    assert_eq!(
        s.ipv6_receive(e, &mut [0; 4]),
        Err(Error::TooSmall { needed: 5 })
    );
    let mut bytes = [0; 5];
    assert_eq!(s.ipv6_receive(e, &mut bytes), Ok((5, route().peer)));
    assert_eq!(&bytes, b"reply");
}

#[test]
fn router_na_requires_current_grant_and_valid_direct_neighbor_envelope() {
    let (w, mut s) = stack();
    s.configure_ipv6_route(route()).unwrap();
    let valid = advertisement(route().router);
    w.borrow_mut().incoming.push_back(valid.clone());
    poll(&w, &mut s);
    assert_eq!(s.port.rx_length, None);
    let e = s.ipv6_bind(grant()).unwrap();
    let peers = [Some(route().router)];
    assert!(ingress_router(
        &valid,
        Some(local()),
        &peers,
        Some(route().router)
    ));
    assert!(!ingress(&valid, Some(local()), &peers));
    for case in 0..5 {
        let mut f = valid.clone();
        match case {
            0 => f[21] = 254,
            1 => f[56] ^= 1,
            2 => f[85] ^= 1,
            3 => f[77] ^= 1,
            _ => f[79] = 0,
        }
        if case >= 2 {
            checksum(&mut f, 56);
        }
        assert!(
            !ingress_router(&f, Some(local()), &peers, Some(route().router)),
            "{case}"
        );
    }
    let offlink_na = advertisement(route().peer.ip);
    assert!(!ingress_router(
        &offlink_na,
        Some(local()),
        &peers,
        Some(route().router)
    ));
    s.ipv6_close(e).unwrap();
    assert!(!s.port.ipv6_route.as_ref().unwrap().active(&s.port.ipv6_tcp_peers));
}

#[test]
fn router_r_flag_requires_exact_gateway_and_current_routed_grant_before_engine() {
    let (w, mut s) = stack();
    s.configure_ipv6_route(route()).unwrap();
    let routed = s.ipv6_bind(grant()).unwrap();
    let other_peer = Address {
        ip: ip(1, 3),
        ..route().peer
    };
    let other = s
        .ipv6_bind(Grant {
            local_port: 7003,
            peer: other_peer,
        })
        .unwrap();

    // A live routed grant does not authorize another granted on-link peer's
    // R=1 advertisement. All other envelope fields and its checksum are valid.
    let foreign_router = advertisement(other_peer.ip);
    admission(&w, &mut s, foreign_router.clone(), false);
    let mut foreign_host = foreign_router;
    foreign_host[58] &= !0x80;
    checksum(&mut foreign_host, 56);
    admission(&w, &mut s, foreign_host, true);
    poll(&w, &mut s);
    admission(&w, &mut s, advertisement(route().router), true);
    poll(&w, &mut s);

    s.ipv6_close(routed).unwrap();
    s.ipv6_close(other).unwrap();
    let direct_router = s
        .ipv6_bind(Grant {
            local_port: 7004,
            peer: Address {
                ip: route().router,
                ..route().peer
            },
        })
        .unwrap();
    assert!(!s.port.ipv6_route.as_ref().unwrap().active(&s.port.ipv6_tcp_peers));
    // The gateway is now an ordinary on-link peer, without a routed grant.
    // Its R=1 advertisement must not reach the engine through that authority.
    admission(&w, &mut s, advertisement(route().router), false);
    let mut direct_host = advertisement(route().router);
    direct_host[58] &= !0x80;
    checksum(&mut direct_host, 56);
    admission(&w, &mut s, direct_host, true);
    poll(&w, &mut s);
    s.ipv6_close(direct_router).unwrap();
}

#[test]
fn on_link_grant_does_not_activate_routed_port_or_off_link_ingress() {
    let (w, mut s) = stack();
    s.configure_ipv6_route(route()).unwrap();
    let direct_peer = Address {
        ip: route().router,
        ..route().peer
    };
    let direct = s
        .ipv6_bind(Grant {
            local_port: grant().local_port,
            peer: direct_peer,
        })
        .unwrap();
    let state = s.port.ipv6_route.as_ref().unwrap();
    assert!(!state.active(&s.port.ipv6_tcp_peers));
    assert!(state.ports.iter().all(Option::is_none));
    admission(
        &w,
        &mut s,
        udp(route().peer, grant().local_port, b"off-link"),
        false,
    );
    admission(
        &w,
        &mut s,
        udp(direct_peer, grant().local_port, b"direct"),
        true,
    );
    poll(&w, &mut s);
    let mut bytes = [0; 8];
    assert_eq!(s.ipv6_receive(direct, &mut bytes), Ok((6, direct_peer)));
    assert_eq!(&bytes[..6], b"direct");
    s.ipv6_close(direct).unwrap();
}

#[test]
fn routed_ingress_refuses_wrong_tuple_truncation_and_bad_checksum_without_queue_pressure() {
    let (w, mut s) = stack();
    s.configure_ipv6_route(route()).unwrap();
    let e = s.ipv6_bind(grant()).unwrap();
    let valid = udp(route().peer, 7002, b"ok");
    for case in 0..6 {
        let mut f = valid.clone();
        match case {
            0 => f[37] ^= 1,
            1 => f[55] ^= 1,
            2 => f[57] ^= 1,
            3 => {
                f.pop();
            }
            4 => f[59] ^= 1,
            _ => f[60] ^= 1,
        }
        if case <= 2 {
            checksum(&mut f, 60);
        }
        let frame_length = f.len();
        w.borrow_mut().incoming.push_back(f);
        // The checksum is the engine's responsibility. Wrong tuple, length
        // and truncation must be refused earlier, before queue admission.
        assert_eq!(s.port.fill(0), Ok(case == 5), "admission {case}");
        assert_eq!(s.port.rx_length, (case == 5).then_some(frame_length));
        poll(&w, &mut s);
        let handle = s.ipv6_datagrams.entry(e).unwrap().socket.unwrap();
        assert!(
            !s.sockets.get::<udp::Socket>(handle).can_recv(),
            "queue {case}"
        );
        assert_eq!(s.ipv6_receive(e, &mut [0; 8]), Err(Error::Again), "{case}");
    }
    w.borrow_mut().incoming.push_back(valid);
    poll(&w, &mut s);
    assert_eq!(s.ipv6_receive(e, &mut [0; 2]), Ok((2, route().peer)));
    s.ipv6_close(e).unwrap();
    assert!(
        !s.port
            .ipv6_route
            .as_ref()
            .unwrap()
            .ingress(&udp(route().peer, 7002, b"late"), Some(local()))
    );
}

#[test]
fn wrong_source_ports_cannot_consume_real_routed_socket_queue_capacity() {
    let (w, mut s) = stack();
    s.configure_ipv6_route(route()).unwrap();
    let e = s.ipv6_bind(grant()).unwrap();
    let handle = s.ipv6_datagrams.entry(e).unwrap().socket.unwrap();
    assert_eq!(QUEUE_PACKETS, 4);
    for value in 0..QUEUE_PACKETS - 1 {
        admission(
            &w,
            &mut s,
            udp(route().peer, grant().local_port, &[value as u8]),
            true,
        );
        poll(&w, &mut s);
    }
    assert!(s.sockets.get::<udp::Socket>(handle).can_recv());
    for _ in 0..QUEUE_PACKETS * 2 {
        let wrong = Address {
            port: route().peer.port + 1,
            ..route().peer
        };
        admission(
            &w,
            &mut s,
            udp(wrong, grant().local_port, b"pressure"),
            false,
        );
        poll(&w, &mut s);
        // Do not invoke ipv6_receive here: its exact-peer discard would hide
        // unwanted packets occupying the one remaining engine queue slot.
        let (head, _) = s.sockets.get_mut::<udp::Socket>(handle).peek().unwrap();
        assert_eq!(head, &[0]);
    }
    admission(
        &w,
        &mut s,
        udp(route().peer, grant().local_port, &[3]),
        true,
    );
    poll(&w, &mut s);
    for value in 0..QUEUE_PACKETS {
        let mut body = [0; 1];
        assert_eq!(s.ipv6_receive(e, &mut body), Ok((1, route().peer)));
        assert_eq!(body, [value as u8]);
    }
    assert!(!s.sockets.get::<udp::Socket>(handle).can_recv());
    assert_eq!(s.ipv6_receive(e, &mut [0; 1]), Err(Error::Again));
    s.ipv6_close(e).unwrap();
}

#[test]
fn missing_router_does_not_fall_back_to_peer_nd_or_another_route() {
    let (w, mut s) = stack();
    w.borrow_mut().resolve = false;
    s.configure_ipv6_route(route()).unwrap();
    let e = s.ipv6_bind(grant()).unwrap();
    s.ipv6_send(e, route().peer, b"pending").unwrap();
    for _ in 0..20 {
        poll(&w, &mut s);
    }
    assert_eq!(udp_count(&w), 0);
    let sent = w.borrow();
    assert!(!sent.sent.is_empty());
    assert!(
        sent.sent
            .iter()
            .all(|f| f[20] == 58 && f[54] == 135 && f[62..78] == route().router)
    );
}

#[test]
fn close_fault_and_rewind_discard_queued_route_data_without_reviving_handles() {
    for mode in 0..3 {
        let (w, mut s) = stack();
        s.configure_ipv6_route(route()).unwrap();
        let e = s.ipv6_bind(grant()).unwrap();
        s.ipv6_send(e, route().peer, b"must-not-emit").unwrap();
        match mode {
            0 => {
                s.ipv6_close(e).unwrap();
            }
            1 => w.borrow_mut().reading = None,
            _ => w.borrow_mut().now = 99,
        }
        poll(&w, &mut s);
        assert_eq!(udp_count(&w), 0);
        assert_eq!(s.socket_count(), 0);
        assert_eq!(s.ipv6_send(e, route().peer, b"stale"), Err(Error::Stale));
        assert!(!s.port.ipv6_route.as_ref().unwrap().active(&s.port.ipv6_tcp_peers));
        w.borrow_mut().reading = Some(LinkReading {
            link_up: true,
            disabled: false,
            rx_missed: 0,
        });
        let new = s.ipv6_bind(grant()).unwrap();
        assert_ne!(e, new);
        s.ipv6_close(new).unwrap();
        assert_eq!(s.ipv6_route(), Some(route()));
    }
}

struct PipeQueues {
    requests: VecDeque<u8>,
    responses: VecDeque<u8>,
}
struct ServerPipe(Rc<RefCell<PipeQueues>>, Rc<RefCell<Wire>>);
impl Pipe for ServerPipe {
    fn now_ms(&self) -> u64 {
        self.1.borrow().now
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        let mut q = self.0.borrow_mut();
        let n = b.len().min(q.requests.len()).min(7);
        for b in &mut b[..n] {
            *b = q.requests.pop_front().unwrap();
        }
        Ok((n != 0).then_some(n))
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        self.0.borrow_mut().responses.extend(b);
        Ok(Some(b.len()))
    }
}
struct ClientPipe {
    stack: Stack<LinkEnd>,
    channel: Channel,
    q: Rc<RefCell<PipeQueues>>,
    wire: Rc<RefCell<Wire>>,
}
impl ClientPipe {
    fn pump(&mut self) {
        self.stack.poll();
        self.channel.poll(
            &mut self.stack,
            &mut ServerPipe(self.q.clone(), self.wire.clone()),
        );
        self.wire.borrow_mut().now += 1;
    }
}
impl Pipe for ClientPipe {
    fn now_ms(&self) -> u64 {
        self.wire.borrow().now
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        self.pump();
        let mut q = self.q.borrow_mut();
        let n = b.len().min(q.responses.len()).min(11);
        for b in &mut b[..n] {
            *b = q.responses.pop_front().unwrap();
        }
        Ok((n != 0).then_some(n))
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        self.q.borrow_mut().requests.extend(b);
        self.pump();
        Ok(Some(b.len()))
    }
}

#[test]
fn actual_framed_dns_consumer_resolves_a_aaaa_and_refuses_tc_without_routed_tcp_grant() {
    for mode in 0..3 {
        let (wire, mut s) = stack();
        wire.borrow_mut().dns = true;
        wire.borrow_mut().truncated = mode == 2;
        s.configure_ipv6_route(route()).unwrap();
        let channel = Channel::grant(&mut s, grant()).unwrap();
        let p = ClientPipe {
            stack: s,
            channel,
            q: Rc::new(RefCell::new(PipeQueues {
                requests: VecDeque::new(),
                responses: VecDeque::new(),
            })),
            wire: wire.clone(),
        };
        let mut resolver = crate::dns::Resolver::new(
            super::super::dns::Datagram::new(p, route().peer, |_| {}),
            0x1234,
        );
        match mode {
            0 => assert_eq!(
                resolver.lookup("www.example").unwrap().addresses[0],
                [192, 0, 2, 9]
            ),
            1 => assert_eq!(
                resolver.lookup_aaaa("www.example").unwrap().addresses[0],
                [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]
            ),
            _ => assert_eq!(
                resolver.lookup("www.example"),
                Err(crate::dns::Error::Truncated)
            ),
        }
        assert_eq!(udp_count(&wire), 1);
        assert!(
            wire.borrow()
                .sent
                .iter()
                .all(|f| f.len() < 54 || f[20] != 6)
        );
        assert!(wire.borrow().now < 100 + crate::dns::LOOKUP_MS);
    }
}

#[test]
fn channel_revocation_clears_router_admission_and_queued_data() {
    let (w, mut s) = stack();
    s.configure_ipv6_route(route()).unwrap();
    let mut session = Session::grant(&mut s, grant()).unwrap();
    let mut request = [0; HEADER + 1];
    request[..4].copy_from_slice(&[2, 1, 0, 6]);
    request[4..20].copy_from_slice(&route().peer.ip);
    request[20..24].copy_from_slice(&7u32.to_be_bytes());
    request[24..26].copy_from_slice(&53u16.to_be_bytes());
    request[27] = 1;
    request[HEADER] = 0xa5;
    let mut reply = [0; MAX_MESSAGE];
    assert_eq!(session.request(&mut s, &request, &mut reply), HEADER);
    assert_eq!(reply[2], 0);
    let mut ch = Channel::new(session);
    ch.revoke(&mut s);
    poll(&w, &mut s);
    assert!(!ch.live());
    assert_eq!(udp_count(&w), 0);
    assert_eq!(s.socket_count(), 0);
    assert!(!s.port.ipv6_route.as_ref().unwrap().active(&s.port.ipv6_tcp_peers));
}

mod tcp;
