use super::*;
use crate::stream::{self as s, server as v};
use alloc::vec;

fn grant() -> v::Grant {
    v::Grant {
        local_port: 7005,
        peer: datagram::Address {
            ip: [10, 0, 2, 2],
            port: 42030,
        },
        accept_timeout_ms: 1000,
        lifetime_ms: 10000,
    }
}

// Independent byte/checksum fixture, not the observation parser's serializer.
fn checksums(frame: &mut [u8]) {
    let ihl = usize::from(frame[14] & 15) * 4;
    let end = 14 + usize::from(u16::from_be_bytes([frame[16], frame[17]]));
    let tcp = 14 + ihl;
    frame[24..26].fill(0);
    let sum = independent_checksum(&frame[14..tcp]);
    frame[24..26].copy_from_slice(&sum.to_be_bytes());
    frame[tcp + 16..tcp + 18].fill(0);
    let mut pseudo = frame[26..34].to_vec();
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&((end - tcp) as u16).to_be_bytes());
    pseudo.extend_from_slice(&frame[tcp..end]);
    let sum = independent_checksum(&pseudo);
    frame[tcp + 16..tcp + 18].copy_from_slice(&sum.to_be_bytes());
}

fn syn(port: u16, sequence: u32) -> Vec<u8> {
    let mut frame = vec![0; 58];
    frame[..6].copy_from_slice(&[2, 0, 0, 0, 0, 15]);
    frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    frame[12..14].copy_from_slice(&[8, 0]);
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&44u16.to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&[10, 0, 2, 2]);
    frame[30..34].copy_from_slice(&[10, 0, 2, 15]);
    frame[34..36].copy_from_slice(&port.to_be_bytes());
    frame[36..38].copy_from_slice(&7005u16.to_be_bytes());
    frame[38..42].copy_from_slice(&sequence.to_be_bytes());
    frame[46] = 0x60;
    frame[47] = 2;
    frame[48..50].copy_from_slice(&8192u16.to_be_bytes());
    frame[54..58].copy_from_slice(&[2, 4, 5, 180]);
    checksums(&mut frame);
    frame
}

#[test]
fn counted_discard_names_exact_observed_and_expected_tuple() {
    let (wire, mut owner, _) = pair(0);
    let endpoint = owner.stream_server_grant(grant()).unwrap();
    owner.stream_listen(endpoint).unwrap();
    let first = syn(42031, 0x12345678);
    assert!(!v::ingress(&first, &owner.port.server_rules));
    assert!(v::peer_refusal(&first, &owner.port.server_rules).is_some());
    assert_eq!(owner.stats().tcp_server_peer_dropped, 0); // Pure classification.
    wire.borrow_mut().queues[0].push_back(first);
    owner.poll();
    let stats = owner.stats();
    assert_eq!(stats.tcp_server_peer_dropped, 1);
    assert_eq!(
        stats.last_tcp_server_peer_refusal,
        Some(v::PeerRefusal {
            source: datagram::Address {
                ip: [10, 0, 2, 2],
                port: 42031
            },
            destination: datagram::Address {
                ip: [10, 0, 2, 15],
                port: 7005
            },
            expected_peer: grant().peer,
            tcp_flags: 2,
            tcp_sequence: 0x12345678,
            frame_bytes: 58,
        })
    );
    owner.poll();
    assert_eq!(owner.stats(), stats); // No second observation of the consumed frame.
    assert_eq!(owner.stream_accept(endpoint), Err(s::Error::Again));
}

#[test]
fn wrong_ip_and_wrong_port_count_but_authorized_connection_still_accepts() {
    let (wire, mut owner, mut client) = pair(0);
    let endpoint = owner.stream_server_grant(grant()).unwrap();
    owner.stream_listen(endpoint).unwrap();
    let mut wrong_ip = syn(42030, 123);
    wrong_ip[29] = 3;
    checksums(&mut wrong_ip);
    for frame in [wrong_ip, syn(42031, 124)] {
        wire.borrow_mut().queues[0].push_back(frame);
        owner.poll();
    }
    assert_eq!(owner.stats().tcp_server_peer_dropped, 2);
    let _connection = client
        .connect(Ipv4Address::new(10, 0, 2, 15), 7005, 42030)
        .unwrap();
    let mut accepted = false;
    for _ in 0..1000 {
        owner.poll();
        client.poll();
        wire.borrow_mut().now_ms += 1;
        if owner.stream_accept(endpoint).is_ok() {
            accepted = true;
            break;
        }
    }
    assert!(accepted);
    assert_eq!(owner.stats().tcp_server_peer_dropped, 2);
}

#[test]
fn no_rule_allowed_other_port_and_api_denial_are_not_ingress_drops() {
    let (wire, mut owner, _) = pair(0);
    wire.borrow_mut().queues[0].push_back(syn(42031, 1));
    owner.poll();
    assert_eq!(owner.stats().tcp_server_peer_dropped, 0);
    let endpoint = owner.stream_server_grant(grant()).unwrap();
    for mut frame in [syn(42030, 2), syn(42031, 3)] {
        if frame[34..36] == 42031u16.to_be_bytes() {
            frame[36..38].copy_from_slice(&7006u16.to_be_bytes());
            checksums(&mut frame);
        }
        assert!(v::ingress(&frame, &owner.port.server_rules));
        assert!(v::peer_refusal(&frame, &owner.port.server_rules).is_none());
        wire.borrow_mut().queues[0].push_back(frame);
        owner.poll();
    }
    assert_eq!(owner.stream_connect(endpoint), Err(s::Error::Denied));
    assert_eq!(owner.stats().tcp_server_peer_dropped, 0);
    assert!(owner.stats().last_tcp_server_peer_refusal.is_none());
}

#[test]
fn malformed_headers_checksums_options_fragments_and_wrong_local_are_excluded() {
    let (wire, mut owner, _) = pair(0);
    owner.stream_server_grant(grant()).unwrap();
    let good = syn(42031, 1);
    let mut cases = Vec::new();
    for length in [0, 13, 33, 37, 53, 57] {
        cases.push(good[..length].to_vec());
    }
    for at in [24, 50] {
        let mut frame = good.clone();
        frame[at] ^= 1;
        cases.push(frame);
    }
    for total in [19u16, 39, 45, u16::MAX] {
        let mut frame = good.clone();
        frame[16..18].copy_from_slice(&total.to_be_bytes());
        cases.push(frame);
    }
    for data_offset in [0x40, 0x70, 0x61] {
        let mut frame = good.clone();
        frame[46] = data_offset;
        checksums(&mut frame);
        cases.push(frame);
    }
    for fragment in [0x2000u16, 1, 0x8000] {
        let mut frame = good.clone();
        frame[20..22].copy_from_slice(&fragment.to_be_bytes());
        checksums(&mut frame);
        cases.push(frame);
    }
    let mut options = good.clone();
    options[55] = 1;
    checksums(&mut options);
    cases.push(options);
    let mut other_local = good.clone();
    other_local[33] = 16;
    checksums(&mut other_local);
    cases.push(other_local);
    let mut ip_options = good.clone();
    ip_options.splice(34..34, [0; 4]);
    ip_options[14] = 0x46;
    ip_options[16..18].copy_from_slice(&48u16.to_be_bytes());
    checksums(&mut ip_options);
    cases.push(ip_options);
    for frame in cases {
        assert!(v::peer_refusal(&frame, &owner.port.server_rules).is_none());
        wire.borrow_mut().queues[0].push_back(frame);
        owner.poll();
        assert_eq!(owner.stats().tcp_server_peer_dropped, 0);
    }
}

#[test]
fn valid_minimum_ethernet_padding_is_not_truncation_or_extra_packet_data() {
    let (_, mut owner, _) = pair(0);
    owner.stream_server_grant(grant()).unwrap();
    let mut frame = syn(42031, 1);
    frame.resize(60, 0);
    assert_eq!(
        v::peer_refusal(&frame, &owner.port.server_rules)
            .unwrap()
            .frame_bytes,
        60
    );
    frame[59] = 1;
    assert!(v::peer_refusal(&frame, &owner.port.server_rules).is_none());
    frame[59] = 0;
    frame.push(0);
    assert!(v::peer_refusal(&frame, &owner.port.server_rules).is_none());
}

#[test]
fn cached_frame_becomes_peer_mismatch_and_is_consumed_exactly_once() {
    let (wire, mut owner, _) = pair(0);
    // Cache while no rule exists, then install a rule for a different peer.
    wire.borrow_mut().queues[0].push_back(syn(42031, 99));
    owner.wait(1);
    assert!(owner.port.rx_length.is_some());
    assert_eq!(owner.stats().tcp_server_peer_dropped, 0);
    owner.stream_server_grant(grant()).unwrap();
    assert!(phy::Device::receive(&mut owner.port, Instant::from_millis(1)).is_none());
    assert!(owner.port.rx_length.is_none());
    assert_eq!(owner.stats().tcp_server_peer_dropped, 1);
    assert!(phy::Device::receive(&mut owner.port, Instant::from_millis(1)).is_none());
    assert_eq!(owner.stats().tcp_server_peer_dropped, 1);
}

#[test]
fn cached_later_expired_or_faulted_frame_is_not_a_peer_mismatch_observation() {
    for expired in [false, true] {
        let (wire, mut owner, _) = pair(0);
        wire.borrow_mut().queues[0].push_back(syn(42031, 99));
        owner.wait(1);
        owner.stream_server_grant(grant()).unwrap();
        if expired {
            wire.borrow_mut().now_ms = 10001;
        } else {
            v::observe_link(&mut owner.port.server_rules, reading(false, false, 0));
        }
        assert!(phy::Device::receive(&mut owner.port, Instant::from_millis(10001)).is_none());
        assert_eq!(owner.stats().tcp_server_peer_dropped, 0);
        assert!(owner.stats().last_tcp_server_peer_refusal.is_none());
    }
}

#[test]
fn close_rebind_and_fence_preserve_inert_history_without_endpoint_revival() {
    let (wire, mut owner, _) = pair(0);
    let old = owner.stream_server_grant(grant()).unwrap();
    wire.borrow_mut().queues[0].push_back(syn(42031, 1));
    owner.poll();
    let observed = owner.stats();
    owner.stream_abort(old).unwrap();
    wire.borrow_mut().queues[0].push_back(syn(42031, 2));
    owner.poll();
    assert_eq!(owner.stats().tcp_server_peer_dropped, 1);
    let mut next = grant();
    next.peer.port = 42032;
    let fresh = owner.stream_server_grant(next).unwrap();
    assert_ne!(old, fresh);
    assert_eq!(owner.stream_listen(old), Err(s::Error::Stale));
    assert_eq!(
        owner.stats().last_tcp_server_peer_refusal,
        observed.last_tcp_server_peer_refusal
    );
    wire.borrow_mut().queues[0].push_back(syn(42030, 3));
    owner.poll();
    assert_eq!(owner.stats().tcp_server_peer_dropped, 2);
    assert_eq!(
        owner
            .stats()
            .last_tcp_server_peer_refusal
            .unwrap()
            .expected_peer,
        next.peer
    );
    owner.stream_server_fence();
    let last = owner.stats();
    wire.borrow_mut().queues[0].push_back(syn(42031, 4));
    owner.poll();
    assert_eq!(
        owner.stats().tcp_server_peer_dropped,
        last.tcp_server_peer_dropped
    );
    assert_eq!(
        owner.stats().last_tcp_server_peer_refusal,
        last.last_tcp_server_peer_refusal
    );
    let (_, other, _) = pair(0);
    assert_eq!(other.stats().tcp_server_peer_dropped, 0);
    assert!(other.stats().last_tcp_server_peer_refusal.is_none());
}

#[test]
fn saturation_retains_latest_tuple_and_does_not_change_filtering() {
    let (wire, mut owner, _) = pair(0);
    let endpoint = owner.stream_server_grant(grant()).unwrap();
    owner.stream_listen(endpoint).unwrap();
    owner.port.stats.tcp_server_peer_dropped = u64::MAX - 1;
    for (port, seq) in [(42031, 10), (42032, 11)] {
        wire.borrow_mut().queues[0].push_back(syn(port, seq));
        owner.poll();
        assert_eq!(owner.stats().tcp_server_peer_dropped, u64::MAX);
        let last = owner.stats().last_tcp_server_peer_refusal.unwrap();
        assert_eq!(last.source.port, port);
        assert_eq!(last.tcp_sequence, seq);
        assert_eq!(owner.stream_accept(endpoint), Err(s::Error::Again));
    }
}
