//! Engine-pair boundary tests. These do not establish independent Linux,
//! NIC multicast reception, DAD, routed PMTU or native guest interoperability.

use super::*;
use std::cell::RefCell;
use std::rc::Rc;

struct Wire {
    queues: [VecDeque<Vec<u8>>; 2],
    sent: [Vec<Vec<u8>>; 2],
    now: u64,
    reading: Option<LinkReading>,
    receive_error: bool,
    uncertain_send: bool,
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
        wire.sent[self.side].push(frame.to_vec());
        wire.queues[1 - self.side].push_back(frame.to_vec());
        if wire.uncertain_send { Err(-5) } else { Ok(()) }
    }

    fn receive(
        &mut self,
        buffer: &mut [u8; FRAME_MAX],
        _timeout_ms: u64,
    ) -> Result<Option<usize>, i64> {
        let mut wire = self.wire.borrow_mut();
        if wire.receive_error {
            return Err(-5);
        }
        Ok(wire.queues[self.side].pop_front().map(|frame| {
            buffer[..frame.len()].copy_from_slice(&frame);
            frame.len()
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
    let mut ip = [0; 16];
    ip[0] = 0xfd;
    ip[15] = last;
    ip
}

fn address(last: u8, port: u16) -> Address {
    Address {
        ip: ip(last),
        port,
        scope: 7,
    }
}

fn config(last: u8) -> Config {
    Config {
        address: ip(last),
        prefix_len: 64,
        scope: 7,
    }
}

fn pair() -> (Rc<RefCell<Wire>>, Stack<End>, Stack<End>) {
    let wire = Rc::new(RefCell::new(Wire {
        queues: [VecDeque::new(), VecDeque::new()],
        sent: [Vec::new(), Vec::new()],
        now: 100,
        reading: Some(LinkReading {
            link_up: true,
            disabled: false,
            rx_missed: 0,
        }),
        receive_error: false,
        uncertain_send: false,
    }));
    let stack = |side| {
        let mut stack = Stack::open(
            End {
                wire: wire.clone(),
                side,
            },
            crate::Config {
                address: Ipv4Address::new(10, 0, 2, side as u8 + 1),
                prefix_len: 24,
                gateway: None,
                rx_buffer: 1024,
                tx_buffer: 1024,
            },
        )
        .unwrap();
        stack.configure_ipv6(config(side as u8 + 1)).unwrap();
        stack
    };
    let left = stack(0);
    let right = stack(1);
    (wire, left, right)
}

fn bind_pair(left: &mut Stack<End>, right: &mut Stack<End>) -> (Endpoint, Endpoint) {
    let a = left
        .ipv6_bind(Grant {
            local_port: 49152,
            peer: address(2, 5353),
        })
        .unwrap();
    let b = right
        .ipv6_bind(Grant {
            local_port: 5353,
            peer: address(1, 49152),
        })
        .unwrap();
    (a, b)
}

#[test]
fn shared_receive_error_fences_ipv4_listener_and_invalidates_ipv6_feedback() {
    let (wire, mut owner, mut peer) = pair();
    let (_udp, _) = bind_pair(&mut owner, &mut peer);
    let listener = owner
        .stream_server_grant(crate::stream::server::Grant {
            local_port: 7005,
            peer: crate::datagram::Address {
                ip: [10, 0, 2, 2],
                port: 42030,
            },
            accept_timeout_ms: 1000,
            lifetime_ms: 10000,
        })
        .unwrap();
    owner.stream_listen(listener).unwrap();
    let feedback_generation = owner.port.ipv6_feedback.generation().unwrap();
    assert_eq!(owner.socket_count(), 2);

    // A transient receive refusal is observed even if status remains up.
    wire.borrow_mut().receive_error = true;
    owner.poll();
    assert!(owner.port.ipv6_feedback.generation().unwrap() > feedback_generation);
    assert_eq!(owner.socket_count(), 1);
    assert_eq!(owner.stream_accept(listener), Err(crate::stream::Error::Stale));

    wire.borrow_mut().receive_error = false;
    owner.poll();
    assert_eq!(owner.stream_listen(listener), Err(crate::stream::Error::Stale));
}

fn step(wire: &Rc<RefCell<Wire>>, left: &mut Stack<End>, right: &mut Stack<End>) {
    left.poll();
    right.poll();
    wire.borrow_mut().now += 1;
}

fn v6_protocol(frame: &[u8], protocol: u8) -> bool {
    frame.len() >= 54 && frame[12..14] == [0x86, 0xdd] && frame[20] == protocol
}

#[test]
fn nd_and_maximum_udp_datagram_keep_packet_boundaries() {
    let (wire, mut left, mut right) = pair();
    let (a, b) = bind_pair(&mut left, &mut right);
    let data: Vec<u8> = (0..MAX_DATAGRAM).map(|n| n as u8).collect();
    left.ipv6_send(a, address(2, 5353), &data).unwrap();
    for _ in 0..20 {
        step(&wire, &mut left, &mut right);
    }
    assert_eq!(
        right.ipv6_receive(b, &mut [0; 1]),
        Err(Error::TooSmall {
            needed: MAX_DATAGRAM
        })
    );
    let mut received = [0; MAX_DATAGRAM];
    assert_eq!(
        right.ipv6_receive(b, &mut received),
        Ok((MAX_DATAGRAM, address(1, 49152)))
    );
    assert_eq!(received.as_slice(), data.as_slice());
    right.ipv6_send(b, address(1, 49152), b"").unwrap();
    for _ in 0..20 {
        step(&wire, &mut left, &mut right);
    }
    assert_eq!(left.ipv6_receive(a, &mut []), Ok((0, address(2, 5353))));
    assert_eq!(left.ipv6_receive(a, &mut received), Err(Error::Again));
    let wire = wire.borrow();
    let frames = wire.sent.iter().flatten().collect::<Vec<_>>();
    assert!(
        frames
            .iter()
            .any(|frame| v6_protocol(frame, 58) && frame[54] == 135)
    );
    assert!(
        frames
            .iter()
            .any(|frame| v6_protocol(frame, 58) && frame[54] == 136)
    );
    assert!(
        frames
            .iter()
            .any(|frame| v6_protocol(frame, 17) && frame.len() == 1294)
    );
    assert!(
        frames
            .iter()
            .all(|frame| !v6_protocol(frame, 17) || frame.len() <= 1294)
    );
}

#[test]
fn configuration_and_exact_grants_refuse_other_authority() {
    let (_, mut left, _) = pair();
    assert_eq!(left.configure_ipv6(config(3)), Err(Error::InUse));
    assert_eq!(left.ipv6_config(), Some(config(1)));
    let valid = Grant {
        local_port: 49152,
        peer: address(2, 5353),
    };
    for peer in [
        Address {
            scope: 0,
            ..valid.peer
        },
        Address {
            scope: 8,
            ..valid.peer
        },
        Address {
            port: 0,
            ..valid.peer
        },
        address(1, 5353),
        Address {
            ip: [0; 16],
            ..valid.peer
        },
        Address {
            ip: [0xff; 16],
            ..valid.peer
        },
        Address {
            ip: core::net::Ipv6Addr::LOCALHOST.octets(),
            ..valid.peer
        },
        Address {
            ip: core::net::Ipv4Addr::new(192, 0, 2, 2)
                .to_ipv6_mapped()
                .octets(),
            ..valid.peer
        },
        Address {
            ip: [0x20; 16],
            ..valid.peer
        },
    ] {
        assert_eq!(left.ipv6_bind(Grant { peer, ..valid }), Err(Error::Denied));
    }
    assert_eq!(
        left.ipv6_bind(Grant {
            local_port: 53,
            ..valid
        }),
        Err(Error::Denied)
    );
    assert_eq!(left.socket_count(), 0);
    let endpoint = left.ipv6_bind(valid).unwrap();
    assert_eq!(left.ipv6_bind(valid), Err(Error::InUse));
    assert_eq!(
        left.ipv6_send(endpoint, address(3, 5353), b"x"),
        Err(Error::Denied)
    );
    assert_eq!(
        left.ipv6_send(
            endpoint,
            Address {
                scope: 8,
                ..valid.peer
            },
            b"x"
        ),
        Err(Error::Denied)
    );
    assert_eq!(
        left.ipv6_send(endpoint, valid.peer, &[0; MAX_DATAGRAM + 1]),
        Err(Error::Oversize)
    );
}

#[test]
fn bounded_queues_and_endpoint_slots_do_not_revive_references() {
    let (_, mut left, mut right) = pair();
    let valid = Grant {
        local_port: 49152,
        peer: address(2, 5353),
    };
    let endpoint = left.ipv6_bind(valid).unwrap();
    for _ in 0..QUEUE_PACKETS {
        left.ipv6_send(endpoint, valid.peer, b"x").unwrap();
    }
    assert_eq!(
        left.ipv6_send(endpoint, valid.peer, b"x"),
        Err(Error::Exhausted)
    );
    assert_eq!(
        right.ipv6_send(endpoint, valid.peer, b"x"),
        Err(Error::Stale)
    );
    for index in 1..MAX_ENDPOINTS {
        left.ipv6_bind(Grant {
            local_port: valid.local_port + index as u16,
            ..valid
        })
        .unwrap();
    }
    assert_eq!(
        left.ipv6_bind(Grant {
            local_port: 60000,
            ..valid
        }),
        Err(Error::Exhausted)
    );
    left.ipv6_close(endpoint).unwrap();
    let replacement = left.ipv6_bind(valid).unwrap();
    assert_ne!(endpoint, replacement);
    assert_eq!(
        left.ipv6_send(endpoint, valid.peer, b"x"),
        Err(Error::Stale)
    );
    left.ipv6_fence();
    assert_eq!(left.socket_count(), 0);
    assert_eq!(left.ipv6_close(replacement), Err(Error::Stale));
    assert_eq!(left.ipv6_datagrams.entries.len(), MAX_ENDPOINTS);
    left.ipv6_datagrams.next_epoch = u64::MAX;
    assert_eq!(left.ipv6_bind(valid), Err(Error::Exhausted));
    assert_eq!(left.socket_count(), 0);
}

#[test]
fn unauthorized_source_port_is_discarded_before_authorized_receive() {
    let (wire, mut left, mut right) = pair();
    let (a, b) = bind_pair(&mut left, &mut right);
    let other = right
        .ipv6_bind(Grant {
            local_port: 5354,
            peer: address(1, 49152),
        })
        .unwrap();
    right.ipv6_send(other, address(1, 49152), b"other").unwrap();
    right.ipv6_send(b, address(1, 49152), b"accepted").unwrap();
    for _ in 0..20 {
        step(&wire, &mut left, &mut right);
    }
    let mut bytes = [0; 32];
    assert_eq!(left.ipv6_receive(a, &mut bytes), Ok((8, address(2, 5353))));
    assert_eq!(&bytes[..8], b"accepted");
    assert_eq!(left.ipv6_receive(a, &mut bytes), Err(Error::Again));
}

#[test]
fn clock_and_link_refusals_fence_queued_traffic() {
    for mode in 0..5 {
        let (wire, mut left, _) = pair();
        let grant = Grant {
            local_port: 49152,
            peer: address(2, 5353),
        };
        let endpoint = left.ipv6_bind(grant).unwrap();
        left.ipv6_send(endpoint, grant.peer, b"pending").unwrap();
        match mode {
            0 => wire.borrow_mut().now = 99,
            1 => wire.borrow_mut().reading = None,
            2 => wire.borrow_mut().reading.as_mut().unwrap().link_up = false,
            3 => wire.borrow_mut().reading.as_mut().unwrap().disabled = true,
            4 => wire.borrow_mut().receive_error = true,
            _ => unreachable!(),
        }
        if mode == 4 {
            left.wait(1);
        } else {
            left.poll();
        }
        assert_eq!(
            left.ipv6_send(endpoint, grant.peer, b"later"),
            Err(Error::Stale)
        );
        assert_eq!(left.socket_count(), 0);
        assert!(wire.borrow().sent[0].is_empty());
    }
}

#[test]
fn prefix_bounds_are_exact_and_configuration_rejects_non_unicast() {
    assert!(same_prefix(ip(2), ip(3), 127));
    assert!(!same_prefix(ip(2), ip(3), 128));
    assert!(same_prefix(ip(2), ip(3), 64));
    let (_, left, _) = pair();
    let mut stack = Stack::open(left.port.link, crate::Config::qemu_user()).unwrap();
    for candidate in [
        Config {
            scope: 0,
            ..config(1)
        },
        Config {
            prefix_len: 0,
            ..config(1)
        },
        Config {
            prefix_len: 129,
            ..config(1)
        },
        Config {
            address: [0; 16],
            ..config(1)
        },
        Config {
            address: [0xff; 16],
            ..config(1)
        },
        Config {
            address: core::net::Ipv6Addr::LOCALHOST.octets(),
            ..config(1)
        },
    ] {
        assert_eq!(stack.configure_ipv6(candidate), Err(Error::Denied));
    }
    assert_eq!(stack.ipv6_config(), None);
    stack.configure_ipv6(config(1)).unwrap();
}

#[test]
fn classic_tcp_listener_remains_bound_to_ipv4_with_ipv6_enabled() {
    let (_, mut left, _) = pair();
    left.listen(22, 2).unwrap();
    for handle in &left.listeners[0].backlog {
        assert_eq!(
            left.sockets
                .get::<tcp::Socket>(*handle)
                .listen_endpoint()
                .addr,
            Some(IpAddress::Ipv4(left.config.address))
        );
    }
}

#[test]
fn malformed_neighbor_advertisements_do_not_release_pending_datagram() {
    for case in 0..3 {
        let (wire, mut left, mut right) = pair();
        let (a, _) = bind_pair(&mut left, &mut right);
        left.ipv6_send(a, address(2, 5353), b"pending").unwrap();
        left.poll();
        right.poll();
        let valid = wire.borrow_mut().queues[0]
            .pop_front()
            .expect("neighbor advertisement");
        assert!(v6_protocol(&valid, 58) && valid[54] == 136);
        let mut malformed = valid.clone();
        match case {
            0 => malformed[21] = 64,
            1 => malformed[56] ^= 1,
            2 => {
                // A zero-length ND option is invalid even with a correct
                // checksum; keep checksum and option validation independent.
                malformed[79] = 0;
                smoltcp::wire::Icmpv6Packet::new_unchecked(&mut malformed[54..])
                    .fill_checksum(&Ipv6Address::from(ip(2)), &Ipv6Address::from(ip(1)));
            }
            _ => unreachable!(),
        }
        wire.borrow_mut().queues[0].push_back(malformed);
        for _ in 0..5 {
            left.poll();
            wire.borrow_mut().now += 1;
        }
        assert!(
            !wire.borrow().sent[0]
                .iter()
                .any(|frame| v6_protocol(frame, 17))
        );
        wire.borrow_mut().queues[0].push_back(valid);
        for _ in 0..20 {
            step(&wire, &mut left, &mut right);
        }
        assert!(
            wire.borrow().sent[0]
                .iter()
                .any(|frame| v6_protocol(frame, 17))
        );
    }
}

#[test]
fn bad_udp_checksum_is_discarded_and_a_later_valid_datagram_survives() {
    let (wire, mut left, mut right) = pair();
    let (a, b) = bind_pair(&mut left, &mut right);
    right.ipv6_send(b, address(1, 49152), b"checked").unwrap();
    for _ in 0..20 {
        right.poll();
        let udp = {
            let mut wire = wire.borrow_mut();
            let position = wire.queues[0]
                .iter()
                .position(|frame| v6_protocol(frame, 17));
            position.and_then(|position| wire.queues[0].remove(position))
        };
        if let Some(valid) = udp {
            let mut malformed = valid.clone();
            malformed[60] ^= 1;
            wire.borrow_mut().queues[0].push_back(malformed);
            left.poll();
            assert_eq!(left.ipv6_receive(a, &mut [0; 32]), Err(Error::Again));
            wire.borrow_mut().queues[0].push_back(valid);
            left.poll();
            let mut bytes = [0; 32];
            assert_eq!(left.ipv6_receive(a, &mut bytes), Ok((7, address(2, 5353))));
            assert_eq!(&bytes[..7], b"checked");
            return;
        }
        left.poll();
        wire.borrow_mut().now += 1;
    }
    panic!("no UDP frame after neighbor discovery");
}

fn advertisement() -> Vec<u8> {
    let mut frame = vec![0; 86];
    frame[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    frame[12..14].copy_from_slice(&[0x86, 0xdd]);
    frame[14] = 0x60;
    frame[18..20].copy_from_slice(&32u16.to_be_bytes());
    frame[20] = 58;
    frame[21] = 255;
    frame[22..38].copy_from_slice(&ip(2));
    frame[38..54].copy_from_slice(&ip(1));
    frame[54] = 136;
    frame[58] = 0x60;
    frame[62..78].copy_from_slice(&ip(2));
    frame[78] = 2;
    frame[79] = 1;
    frame[80..86].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    checksum_nd(&mut frame);
    frame
}

fn checksum_nd(frame: &mut [u8]) {
    let source: [u8; 16] = frame[22..38].try_into().unwrap();
    let destination: [u8; 16] = frame[38..54].try_into().unwrap();
    smoltcp::wire::Icmpv6Packet::new_unchecked(&mut frame[54..])
        .fill_checksum(&Ipv6Address::from(source), &Ipv6Address::from(destination));
}

#[test]
fn ingress_refuses_proxy_unrelated_malformed_and_unsupported_paths() {
    let config = Some(config(1));
    let mut peers = [None; MAX_ENDPOINTS];
    peers[0] = Some(ip(2));
    let valid = advertisement();
    assert!(ingress(&valid, config, &peers));
    assert!(!ingress(&valid, None, &peers));
    assert!(!ingress(&valid, config, &[None; MAX_ENDPOINTS]));
    assert!(ingress(&[0; 14], config, &peers));
    for case in 0..12 {
        let mut changed = valid.clone();
        match case {
            0 => changed[21] = 254,
            1 => changed[55] = 1,
            2 => changed[77] = 3, // Proxy target differs from source.
            3 => changed[79] = 0,
            4 => {
                changed.extend_from_slice(&[0; 8]);
                changed[18..20].copy_from_slice(&40u16.to_be_bytes());
                changed[79] = 2; // Wrong known Ethernet option length.
            }
            5 => changed[78] = 1,    // Source LLA option in an advertisement.
            6 => changed[85] = 3,    // Option and Ethernet source disagree.
            7 => changed[20] = 0,    // Hop-by-hop extension.
            8 => changed[20] = 44,   // Fragment extension.
            9 => changed[20] = 6,    // IPv6 TCP not yet admitted.
            10 => changed[54] = 134, // Router advertisements grant no routes.
            11 => changed[18..20].copy_from_slice(&33u16.to_be_bytes()),
            _ => unreachable!(),
        }
        checksum_nd(&mut changed);
        assert!(!ingress(&changed, config, &peers), "case {case}");
    }
    let mut unknown_option = valid;
    unknown_option.extend_from_slice(&[254, 1, 0, 0, 0, 0, 0, 0]);
    unknown_option[18..20].copy_from_slice(&40u16.to_be_bytes());
    checksum_nd(&mut unknown_option);
    assert!(ingress(&unknown_option, config, &peers));
}

#[test]
fn ingress_accepts_only_the_configured_solicited_node_and_target() {
    let mut solicitation = advertisement();
    solicitation[54] = 135;
    solicitation[58] = 0;
    solicitation[62..78].copy_from_slice(&ip(1));
    solicitation[78] = 1;
    let mut destination = [0; 16];
    destination[0] = 0xff;
    destination[1] = 2;
    destination[11] = 1;
    destination[12] = 0xff;
    destination[15] = 1;
    solicitation[38..54].copy_from_slice(&destination);
    checksum_nd(&mut solicitation);
    let peers = [None; MAX_ENDPOINTS];
    assert!(ingress(&solicitation, Some(config(1)), &peers));
    solicitation[51] = 1; // Wrong upper solicited-node suffix byte.
    checksum_nd(&mut solicitation);
    assert!(!ingress(&solicitation, Some(config(1)), &peers));
    solicitation[38..54].copy_from_slice(&destination);
    solicitation[77] = 3;
    checksum_nd(&mut solicitation);
    assert!(!ingress(&solicitation, Some(config(1)), &peers));
    solicitation[62..78].copy_from_slice(&ip(1));
    solicitation[22..38].fill(0); // DAD is an explicit unsupported path.
    checksum_nd(&mut solicitation);
    assert!(!ingress(&solicitation, Some(config(1)), &peers));
}

#[test]
fn actual_engine_closed_udp_peer_yields_complete_correlated_port_unreachable() {
    let (wire, mut left, mut right) = pair();
    let endpoint = left
        .ipv6_bind(Grant {
            local_port: 49152,
            peer: address(2, 42019),
        })
        .unwrap();
    left.ipv6_send(endpoint, address(2, 42019), b"complete-small-query")
        .unwrap();
    assert_eq!(
        left.ipv6_feedback(endpoint),
        Ok(None),
        "local enqueue is not submission"
    );
    for _ in 0..20 {
        step(&wire, &mut left, &mut right);
    }
    {
        let wire = wire.borrow();
        let submitted = wire.sent[0].iter().find(|f| v6_protocol(f, 17)).unwrap();
        let peer = &wire.sent[1];
        let advertisement = peer
            .iter()
            .position(|f| v6_protocol(f, 58) && f[54] == 136)
            .unwrap();
        let error = peer
            .iter()
            .position(|f| v6_protocol(f, 58) && f[54..56] == [1, 4])
            .unwrap();
        assert!(
            advertisement < error,
            "exercise actual transmit buffer reuse"
        );
        assert_eq!(&peer[advertisement][58..62], &[0x40, 0, 0, 0]);
        // The same peer buffer previously held nonzero NA flags here. The
        // pinned error emitter leaves its unused word unwritten; the owner
        // adapter must initialize it before checksum and local submission.
        assert_eq!(&peer[error][58..62], &[0; 4]);
        assert_eq!(&peer[error][62..], &submitted[14..]);
        let packet = smoltcp::wire::Icmpv6Packet::new_checked(&peer[error][54..]).unwrap();
        assert!(packet.verify_checksum(&Ipv6Address::from(ip(2)), &Ipv6Address::from(ip(1))));
    }
    assert_eq!(
        left.ipv6_feedback(endpoint),
        Ok(Some(feedback::Observation {
            kind: 1,
            code: 4,
            detail: 0
        }))
    );
    assert_eq!(left.ipv6_feedback(endpoint), Ok(None));
    assert!(
        wire.borrow().sent[1]
            .iter()
            .any(|f| v6_protocol(f, 58) && f[54..56] == [1, 4])
    );
    left.ipv6_close(endpoint).unwrap();
    assert_eq!(left.ipv6_feedback(endpoint), Err(Error::Stale));
}

#[test]
fn uncertain_actual_link_send_retains_first_effect_without_feedback_evidence() {
    let (wire, mut left, mut right) = pair();
    let (a, b) = bind_pair(&mut left, &mut right);
    left.ipv6_send(a, address(2, 5353), b"learn-neighbor")
        .unwrap();
    for _ in 0..20 {
        step(&wire, &mut left, &mut right);
    }
    right.ipv6_receive(b, &mut [0; 64]).unwrap();
    let endpoint = left
        .ipv6_bind(Grant {
            local_port: 49153,
            peer: address(2, 42019),
        })
        .unwrap();
    wire.borrow_mut().uncertain_send = true;
    left.ipv6_send(endpoint, address(2, 42019), b"possible-first-effect")
        .unwrap();
    for _ in 0..20 {
        step(&wire, &mut left, &mut right);
    }
    assert!(
        wire.borrow().sent[0]
            .iter()
            .any(|f| v6_protocol(f, 17) && f[56..58] == 42019u16.to_be_bytes()),
        "send error does not imply effect absence"
    );
    assert!(left.stats().link_errors > 0);
    assert_eq!(
        left.ipv6_feedback(endpoint),
        Ok(None),
        "Err establishes no successful-submission correlation"
    );
}
