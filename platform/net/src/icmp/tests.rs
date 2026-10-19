use super::*;
use crate::icmp::{CEILING_MS, Error as FeedbackError, Feedback, RECENT_MS};

const LOCAL: [u8; 4] = [10, 0, 2, 15];
const PEER: datagram::Address = datagram::Address {
    ip: [10, 0, 2, 2],
    port: 53,
};
const MAC: [u8; 6] = [2, 0, 0, 0, 0, 15];

// Independent RFC 791/792/1191 fixture writer, not the product decoder or
// the engine's encoder. Every checksum is computed over the actual bytes.
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        sum += ((chunk[0] as u32) << 8) | chunk.get(1).copied().unwrap_or(0) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn ip_checksum(ip: &mut [u8]) {
    let header = (ip[0] as usize & 15) * 4;
    ip[10..12].fill(0);
    let c = checksum(&ip[..header]);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
}
fn submitted(data: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 14 + 28 + data.len()];
    b[..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    b[6..12].copy_from_slice(&MAC);
    b[12..14].copy_from_slice(&[8, 0]);
    let ip = &mut b[14..];
    ip[..10].copy_from_slice(&[0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 64, 17]);
    let length = ip.len() as u16;
    ip[2..4].copy_from_slice(&length.to_be_bytes());
    ip[12..16].copy_from_slice(&LOCAL);
    ip[16..20].copy_from_slice(&PEER.ip);
    ip[20..22].copy_from_slice(&7002u16.to_be_bytes());
    ip[22..24].copy_from_slice(&PEER.port.to_be_bytes());
    ip[24..26].copy_from_slice(&((data.len() + 8) as u16).to_be_bytes());
    ip[28..].copy_from_slice(data);
    let mut pseudo = Vec::from(LOCAL);
    pseudo.extend(PEER.ip);
    pseudo.extend([0, 17]);
    pseudo.extend(((8 + data.len()) as u16).to_be_bytes());
    pseudo.extend(&ip[20..]);
    let c = checksum(&pseudo);
    ip[26..28].copy_from_slice(&if c == 0 { 65535 } else { c }.to_be_bytes());
    ip_checksum(ip);
    b
}
fn error_frame(sent: &[u8], kind: u8, code: u8, mtu: u16) -> Vec<u8> {
    let mut b = vec![0; 14 + 20 + 8 + 28];
    b[..6].copy_from_slice(&MAC);
    b[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 9]);
    b[12..14].copy_from_slice(&[8, 0]);
    let ip = &mut b[14..];
    ip[..10].copy_from_slice(&[0x45, 0, 0, 56, 0x45, 0x67, 0, 0, 64, 1]);
    // A router, deliberately different from the granted peer.
    ip[12..16].copy_from_slice(&[10, 0, 2, 9]);
    ip[16..20].copy_from_slice(&LOCAL);
    ip[20] = kind;
    ip[21] = code;
    ip[26..28].copy_from_slice(&mtu.to_be_bytes());
    ip[28..].copy_from_slice(&sent[14..42]);
    // A router can decrement TTL before discovering the forwarding error.
    ip[36] -= 1;
    ip_checksum(&mut ip[28..]);
    let c = checksum(&ip[20..]);
    ip[22..24].copy_from_slice(&c.to_be_bytes());
    ip_checksum(ip);
    b
}
fn fix_outer(frame: &mut [u8]) {
    let ip = &mut frame[14..];
    ip[22..24].fill(0);
    let c = checksum(&ip[20..]);
    ip[22..24].copy_from_slice(&c.to_be_bytes());
    ip_checksum(ip);
}
fn feedback() -> Feedback {
    let mut f = Feedback::new(MAC);
    f.bind(0, 1, LOCAL, 24, 7002, PEER);
    f
}

#[test]
fn minimum_router_quote_accepts_changed_ttl_and_retains_error_details() {
    let sent = submitted(&[42; 100]);
    for (kind, code, expected) in [
        (3, 3, FeedbackError::DestinationUnreachable { code: 3 }),
        (3, 13, FeedbackError::DestinationUnreachable { code: 13 }),
        (11, 0, FeedbackError::TimeExceeded { code: 0 }),
        (11, 1, FeedbackError::TimeExceeded { code: 1 }),
    ] {
        let mut f = feedback();
        f.submitted(&sent, 1);
        f.received(&error_frame(&sent, kind, code, 0), 2);
        assert_eq!(f.take(0, 1, 2), Some(expected));
        f.received(&error_frame(&sent, kind, code, 0), 3);
        assert_eq!(
            f.take(0, 1, 3),
            None,
            "one submission admits at most one error"
        );
    }
}

#[test]
fn unsubmitted_expired_rewound_rebound_and_wrong_epoch_quotes_are_ignored() {
    let sent = submitted(b"dns query");
    let frame = error_frame(&sent, 3, 3, 0);
    let mut f = feedback();
    f.received(&frame, 1);
    assert_eq!(f.take(0, 1, 1), None);
    f.submitted(&sent, 2);
    f.received(&frame, 2 + RECENT_MS + 1);
    assert_eq!(f.take(0, 1, 2 + RECENT_MS + 1), None);
    f.submitted(&sent, 5000);
    f.received(&frame, 4999);
    assert_eq!(f.take(0, 1, 4999), None);
    f.submitted(&sent, 5000);
    f.received(&frame, 5001);
    assert_eq!(f.take(0, 2, 5001), None);
    assert_eq!(f.take(0, 1, 5001 + RECENT_MS + 1), None);
    f.submitted(&sent, 7000);
    f.revoke(0);
    f.bind(0, 2, LOCAL, 24, 7002, PEER);
    f.received(&frame, 7001);
    assert_eq!(f.take(0, 2, 7001), None);
    f.submitted(&sent, 7002);
    f.fence();
    f.bind(0, 3, LOCAL, 24, 7002, PEER);
    f.received(&frame, 7003);
    assert_eq!(f.take(0, 3, 7003), None);
}

#[test]
fn malformed_unrelated_nonunicast_fragment_and_invariant_mutations_do_not_match() {
    let sent = submitted(&[42; 100]);
    let valid = error_frame(&sent, 3, 3, 0);
    // Outer IP checksum, ICMP checksum, quoted IP checksum, tuple, IPID,
    // UDP length/checksum, source class, L2 destination and fragment bits.
    for case in 0..24 {
        let mut frame = valid.clone();
        match case {
            0 => frame[24] ^= 1,
            1 => frame[36] ^= 1,
            2 => {
                frame[52] ^= 1;
                fix_outer(&mut frame);
            }
            3..=10 => {
                let at = [44, 46, 48, 54, 58, 62, 66, 68][case - 3];
                frame[at] ^= 1;
                ip_checksum(&mut frame[42..]);
                fix_outer(&mut frame);
            }
            11 => {
                frame[26] = 224;
                fix_outer(&mut frame);
            }
            12 => {
                frame[29] = 255;
                fix_outer(&mut frame);
            }
            13 => {
                frame[33] = 14;
                fix_outer(&mut frame);
            }
            14 => {
                frame[20] |= 0x20;
                fix_outer(&mut frame);
            }
            15 => {
                frame[21] |= 1;
                fix_outer(&mut frame);
            }
            16 => {
                frame[34] = 5;
                fix_outer(&mut frame);
            }
            17 => {
                frame[35] = 16;
                fix_outer(&mut frame);
            }
            18 => frame[0] ^= 1,
            19 => frame[6] |= 1,
            20 => {
                frame[42] = 0x46;
                fix_outer(&mut frame);
            }
            21 => {
                frame[40] = 0;
                frame[41] = 67;
                frame[35] = 4;
                fix_outer(&mut frame);
            }
            22 => {
                frame[14] = 0x40;
                frame[24..26].fill(0);
            }
            23 => {
                frame[14] = 0x4f;
                frame[24..26].fill(0);
            }
            _ => unreachable!(),
        }
        let mut f = feedback();
        f.submitted(&sent, 1);
        f.received(&frame, 2);
        assert_eq!(f.take(0, 1, 2), None, "case {case}");
    }
    for length in 0..valid.len() {
        let mut f = feedback();
        f.submitted(&sent, 1);
        f.received(&valid[..length], 2);
        assert_eq!(f.take(0, 1, 2), None, "prefix {length}");
    }
}

#[test]
fn submission_history_and_pending_feedback_are_bounded_and_endpoint_local() {
    let mut f = feedback();
    f.bind(1, 2, LOCAL, 24, 7003, PEER);
    let mut frames = Vec::new();
    for byte in 0..5 {
        let sent = submitted(&[byte; 100]);
        f.submitted(&sent, 1);
        frames.push(error_frame(&sent, 3, 3, 0));
    }
    f.received(&frames[0], 2);
    assert_eq!(f.take(0, 1, 2), None, "oldest submission was replaced");
    f.received(&frames[1], 2);
    f.received(&frames[2], 2);
    assert_eq!(f.take(1, 2, 2), None);
    assert_eq!(
        f.take(0, 1, 2),
        Some(FeedbackError::DestinationUnreachable { code: 3 })
    );
    assert_eq!(f.take(0, 1, 2), None, "one pending event per grant");
}

#[test]
fn matched_fragment_needed_is_local_floored_and_bounded_without_refresh() {
    let sent = submitted(&[42; 1000]);
    let mut f = feedback();
    f.bind(1, 2, LOCAL, 24, 7003, PEER);
    let mut now = 1;
    for mtu in [576, 900, 0] {
        f.submitted(&sent, now);
        f.received(&error_frame(&sent, 3, 4, mtu), now + 1);
        assert_eq!(
            f.take(0, 1, now + 1),
            Some(FeedbackError::FragmentationNeeded { mtu })
        );
        assert_eq!(f.maximum(0, 1, now + 1), 548);
        assert_eq!(f.maximum(1, 2, now + 1), datagram::MAX_DATAGRAM);
        now += 2;
    }
    for mtu in [1, 67, 68, 575, 1028, 1500, 65535] {
        f.submitted(&sent, now);
        f.received(&error_frame(&sent, 3, 4, mtu), now + 1);
        assert_eq!(f.take(0, 1, now + 1), None);
        assert_eq!(f.maximum(0, 1, now + 1), 548);
        now += 2;
    }
    f.submitted(&sent, CEILING_MS);
    f.received(&error_frame(&sent, 3, 4, 576), CEILING_MS + 1);
    assert_eq!(f.maximum(0, 1, CEILING_MS + 1), 548);
    assert_eq!(f.maximum(0, 1, CEILING_MS + 2), datagram::MAX_DATAGRAM);
    // An overflow cannot construct an unbounded episode.
    f.submitted(&sent, u64::MAX - 2);
    f.received(&error_frame(&sent, 3, 4, 576), u64::MAX - 1);
    assert_eq!(f.maximum(0, 1, u64::MAX - 1), datagram::MAX_DATAGRAM);
    f.revoke(0);
    f.bind(0, 3, LOCAL, 24, 7002, PEER);
    assert_eq!(f.maximum(0, 3, u64::MAX - 1), datagram::MAX_DATAGRAM);
}

#[test]
fn rewind_discards_advice_and_pending_event_does_not_prevent_a_smaller_ceiling() {
    let sent = submitted(&[42; 1000]);
    let mut f = feedback();
    f.submitted(&sent, 100);
    f.received(&error_frame(&sent, 3, 3, 0), 101);
    f.submitted(&sent, 102);
    f.received(&error_frame(&sent, 3, 4, 576), 103);
    assert_eq!(
        f.take(0, 1, 103),
        Some(FeedbackError::DestinationUnreachable { code: 3 })
    );
    assert_eq!(f.maximum(0, 1, 103), 548);
    assert_eq!(f.maximum(0, 1, 102), datagram::MAX_DATAGRAM);
    assert_eq!(f.take(0, 1, 102), None);
}

#[test]
fn outer_ipv4_options_and_changed_quoted_tos_are_accepted() {
    let sent = submitted(b"query");
    let mut frame = error_frame(&sent, 3, 3, 0);
    frame[43] = 3;
    ip_checksum(&mut frame[42..]);
    fix_outer(&mut frame);
    frame.splice(34..34, [1, 1, 0, 0]);
    let ip = &mut frame[14..];
    ip[0] = 0x46;
    ip[2..4].copy_from_slice(&60u16.to_be_bytes());
    ip_checksum(ip);
    let mut f = feedback();
    f.submitted(&sent, 1);
    f.received(&frame, 2);
    assert_eq!(
        f.take(0, 1, 2),
        Some(FeedbackError::DestinationUnreachable { code: 3 })
    );
}

#[test]
fn link_failure_fences_observation_and_ceiling_before_fresh_grant() {
    let state = Rc::new(RefCell::new(SwitchState {
        now_ms: 1,
        reading: reading(true, false, 0),
        reads: 0,
    }));
    let mut stack = Stack::open(
        SwitchLink(state.clone()),
        Config {
            address: Ipv4Address::from(LOCAL),
            ..dead_config()
        },
    )
    .unwrap();
    let grant = udp_grant(7002, 2, 53);
    let old = stack.datagram_bind(grant).unwrap();
    let sent = submitted(&[42; 1000]);
    let mut frame = error_frame(&sent, 3, 4, 576);
    frame[..6].copy_from_slice(&stack.mac());
    stack.port.feedback.submitted(&sent, 1);
    stack.port.feedback.received(&frame, 1);
    assert_eq!(stack.port.feedback.maximum(0, 1, 1), 548);
    state.borrow_mut().reading = None;
    assert_eq!(
        stack.datagram_send(old, grant.peer, b"next"),
        Err(datagram::Error::LinkUnknown)
    );
    state.borrow_mut().reading = reading(true, false, 0);
    let fresh = stack.datagram_bind(grant).unwrap();
    assert_eq!(
        stack.datagram_send(old, grant.peer, b"old"),
        Err(datagram::Error::Stale)
    );
    assert_eq!(stack.datagram_send(fresh, grant.peer, &[42; 549]), Ok(()));
    assert_eq!(
        stack.datagram_receive(fresh, &mut [0; 1472]),
        Err(datagram::Error::Again)
    );
}

#[test]
fn real_udp_submission_reaches_native_capability_and_revoke_discards_observation() {
    let (wire, mut a, mut b) = pair(0);
    let ga = udp_grant(7002, 2, 53);
    let ea = a.datagram_bind(ga).unwrap();
    let learn = udp_grant(1077, 15, 7002);
    let eb = b.datagram_bind(learn).unwrap();
    // Learn ARP without delivering to the granted UDP source port.
    b.datagram_send(eb, learn.peer, b"learn").unwrap();
    for _ in 0..20 {
        step(&wire, &mut a, &mut b);
    }
    a.datagram_send(ea, ga.peer, &[42; 1000]).unwrap();
    a.poll();
    let sent = wire.borrow_mut().queues[1].pop_front().unwrap();
    assert_eq!(&sent[20..22], &[0x40, 0], "pinned engine must emit DF");
    let frame = error_frame(&sent, 3, 4, 576);
    wire.borrow_mut().queues[0].push_back(frame.clone());
    a.poll();
    assert_eq!(
        a.datagram_receive(ea, &mut [0; 1500]),
        Err(datagram::Error::Icmp(FeedbackError::FragmentationNeeded {
            mtu: 576
        }))
    );
    assert_eq!(
        a.datagram_send(ea, ga.peer, &[0; 549]),
        Err(datagram::Error::PathMtu { maximum: 548 })
    );
    assert_eq!(
        a.datagram_send(
            ea,
            datagram::Address {
                port: 54,
                ..ga.peer
            },
            &[0; 549]
        ),
        Err(datagram::Error::Denied)
    );
    a.datagram_close(ea).unwrap();
    let fresh = a.datagram_bind(ga).unwrap();
    wire.borrow_mut().queues[0].push_back(frame);
    a.poll();
    assert_eq!(
        a.datagram_receive(fresh, &mut [0; 1500]),
        Err(datagram::Error::Again)
    );
    assert_eq!(a.datagram_send(fresh, ga.peer, &[0; 549]), Ok(()));
}

#[test]
fn failed_nic_submission_never_records_a_quote_candidate() {
    use smoltcp::phy::TxToken as _;
    struct Refusing;
    impl Link for Refusing {
        fn mac(&self) -> [u8; 6] {
            MAC
        }
        fn send(&mut self, _: &[u8]) -> Result<(), i64> {
            Err(NIC_NO_CARRIER)
        }
        fn receive(&mut self, _: &mut [u8; FRAME_MAX], _: u64) -> Result<Option<usize>, i64> {
            Ok(None)
        }
        fn now_ms(&self) -> u64 {
            1
        }
        fn pause(&self, _: u64) {}
    }
    let sent = submitted(b"query");
    let mut f = feedback();
    let mut link = Refusing;
    let mut buffer = [0; FRAME_MAX];
    let mut stats = Stats::default();
    let mut ipv6_feedback = crate::ipv6::feedback::Feedback::new(MAC);
    TxToken {
        link: &mut link,
        frame_mtu: FRAME_MAX,
        buffer: &mut buffer,
        stats: &mut stats,
        feedback: &mut f,
        ipv6_feedback: &mut ipv6_feedback,
        server_rules: &mut [None; stream::MAX_ENDPOINTS],
    }
    .consume(sent.len(), |b| b.copy_from_slice(&sent));
    assert_eq!(stats.link_errors, 1);
    f.received(&error_frame(&sent, 3, 3, 0), 2);
    assert_eq!(f.take(0, 1, 2), None);
}

#[test]
fn implicit_native_session_encodes_typed_feedback_and_mtu_ceiling() {
    let (_, mut a, _) = pair(0);
    let grant = udp_grant(7002, 2, 53);
    let mut session = datagram::Session::grant(&mut a, grant).unwrap();
    let sent = submitted(&[42; 1000]);
    a.port.feedback.submitted(&sent, 1);
    a.port.feedback.received(&error_frame(&sent, 3, 4, 576), 1);
    let request = udp_request(
        datagram::RECEIVE,
        datagram::Address {
            ip: [0; 4],
            port: 0,
        },
        &[],
        1472,
    );
    let mut reply = [0; datagram::MAX_MESSAGE];
    assert_eq!(session.request(&mut a, &request, &mut reply), 12);
    assert_eq!(
        &reply[..12],
        &[1, datagram::RECEIVE, 14, 0, 0, 0, 0, 0, 0, 0, 2, 64]
    );
    let request = udp_request(datagram::SEND, grant.peer, &[42; 549], 0);
    assert_eq!(session.request(&mut a, &request, &mut reply), 12);
    assert_eq!(
        &reply[..12],
        &[1, datagram::SEND, 15, 0, 0, 0, 0, 0, 0, 0, 2, 36]
    );
    session.revoke(&mut a);
    assert_eq!(a.socket_count(), 0);
}

#[test]
fn old_icmp_refuses_next_send_before_any_queueing() {
    let (_, mut a, _) = pair(0);
    let grant = udp_grant(7002, 2, 53);
    let endpoint = a.datagram_bind(grant).unwrap();
    let sent = submitted(b"old query");
    a.port.feedback.submitted(&sent, 1);
    a.port.feedback.received(&error_frame(&sent, 3, 3, 0), 1);
    assert_eq!(
        a.datagram_send(endpoint, grant.peer, b"new query"),
        Err(datagram::Error::Icmp(
            FeedbackError::DestinationUnreachable { code: 3 }
        ))
    );
    a.poll();
    assert_eq!(
        a.stats().tx_frames,
        0,
        "refused SEND queued neither a UDP packet nor neighbor resolution"
    );
    assert_eq!(a.datagram_send(endpoint, grant.peer, b"new query"), Ok(()));
}
