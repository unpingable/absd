// Independent byte writer plus actual socket/client/adapter controls.
use super::*;
use crate::{
    stream as s,
    stream::mtu::{Feedback, HISTORY, RECENT_MS},
};
const LOCAL: [u8; 4] = [10, 0, 2, 2];
const MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const PEER: datagram::Address = datagram::Address {
    ip: [10, 0, 2, 15],
    port: 7000,
};
fn grant(port: u16) -> s::Grant {
    s::Grant {
        local_port: port,
        peer: PEER,
        connect_timeout_ms: 1000,
        lifetime_ms: 60000,
    }
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for p in bytes.chunks(2) {
        sum += ((p[0] as u32) << 8) | u32::from(*p.get(1).unwrap_or(&0));
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn fix_ip(ip: &mut [u8]) {
    ip[10..12].fill(0);
    let n = usize::from(ip[0] & 15) * 4;
    let c = checksum(&ip[..n]);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
}
fn sent(seq: u32) -> Vec<u8> {
    let mut f = vec![0; 14 + 40 + 1024];
    f[..6].copy_from_slice(&[2, 0, 0, 0, 0, 15]);
    f[6..12].copy_from_slice(&MAC);
    f[12..14].copy_from_slice(&[8, 0]);
    let ip = &mut f[14..];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&1064u16.to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&LOCAL);
    ip[16..20].copy_from_slice(&PEER.ip);
    ip[20..22].copy_from_slice(&40000u16.to_be_bytes());
    ip[22..24].copy_from_slice(&PEER.port.to_be_bytes());
    ip[24..28].copy_from_slice(&seq.to_be_bytes());
    ip[32] = 0x50;
    ip[33] = 0x18;
    ip[34..36].copy_from_slice(&4096u16.to_be_bytes());
    ip[40..].fill(0x55);
    let mut pseudo = LOCAL.to_vec();
    pseudo.extend(PEER.ip);
    pseudo.extend([0, 6]);
    pseudo.extend(1044u16.to_be_bytes());
    pseudo.extend_from_slice(&ip[20..]);
    let c = checksum(&pseudo);
    ip[36..38].copy_from_slice(&c.to_be_bytes());
    fix_ip(ip);
    f
}
fn quote(sent: &[u8], mtu: u16) -> Vec<u8> {
    let mut f = vec![0; 14 + 56];
    f[..6].copy_from_slice(&MAC);
    f[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 9]);
    f[12..14].copy_from_slice(&[8, 0]);
    let ip = &mut f[14..];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&56u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 1;
    ip[12..16].copy_from_slice(&[10, 0, 2, 9]);
    ip[16..20].copy_from_slice(&LOCAL);
    ip[20] = 3;
    ip[21] = 4;
    ip[26..28].copy_from_slice(&mtu.to_be_bytes());
    ip[28..].copy_from_slice(&sent[14..42]);
    ip[36] -= 1;
    fix_ip(&mut ip[28..]);
    fix_outer(&mut f);
    f
}
fn fix_outer(frame: &mut [u8]) {
    let ip = &mut frame[14..];
    ip[22..24].fill(0);
    let c = checksum(&ip[20..]);
    ip[22..24].copy_from_slice(&c.to_be_bytes());
    fix_ip(ip);
}
fn feedback() -> Feedback {
    let mut f = Feedback::new(MAC);
    f.bind(0, 7, LOCAL, 24, 40000, PEER, 60001, 1);
    f
}
#[test]
fn minimum_tcp_quote_latches_once_blocks_matching_egress_and_keeps_other_flow() {
    let packet = sent(100);
    // Linux can include a 548-byte original prefix, not the full 1064-byte
    // original datagram. It must not require complete quoted payload.
    let mut longer = quote(&packet, 900);
    longer.extend_from_slice(&packet[42..14 + 548]);
    longer[16..18].copy_from_slice(&576u16.to_be_bytes());
    fix_outer(&mut longer);
    let mut extended = feedback();
    extended.submitted(&packet, 1);
    extended.received(&longer, 2);
    assert_eq!(extended.fault(0, 7, 2), Some(900));
    for mtu in [576, 900, 1063] {
        let mut f = feedback();
        f.bind(1, 8, LOCAL, 24, 40001, PEER, 60001, 1);
        f.submitted(&packet, 1);
        f.received(&quote(&packet, mtu), 2);
        assert_eq!(f.fault(0, 7, 2), Some(mtu));
        assert_eq!(f.fault(1, 8, 2), None);
        assert!(!f.egress(&packet, 2));
        let mut other = packet.clone();
        other[35] ^= 1;
        assert!(f.egress(&other, 2));
        f.received(&quote(&packet, 576), 3);
        assert_eq!(
            f.fault(0, 7, 3),
            Some(mtu),
            "first terminal advice is sticky"
        );
    }
}
#[test]
fn zero_small_equal_or_larger_mtu_has_no_refusal() {
    let packet = sent(100);
    for mtu in [0, 1, 68, 575, 1064, 1499, 1500, 65535] {
        let mut f = feedback();
        f.submitted(&packet, 1);
        f.received(&quote(&packet, mtu), 2);
        assert_eq!(f.fault(0, 7, 2), None, "mtu {mtu}");
        assert!(f.egress(&packet, 2));
    }
}
#[test]
fn malformed_outer_and_quote_substitutions_do_not_become_advice() {
    let packet = sent(100);
    for case in 0..25 {
        let mut input = quote(&packet, 900);
        match case {
            0 => input[0] ^= 1,
            1 => input[6] |= 1,
            2 => input[6..12].fill(0),
            3 => input[26..30].copy_from_slice(&LOCAL),
            4 => input[26..30].copy_from_slice(&[0, 0, 0, 1]),
            5 => input[26..30].copy_from_slice(&[127, 0, 0, 1]),
            6 => input[26..30].copy_from_slice(&[224, 0, 0, 1]),
            7 => input[26..30].copy_from_slice(&[10, 0, 2, 0]),
            8 => input[26..30].copy_from_slice(&[10, 0, 2, 255]),
            9 => input[30] ^= 1,
            10 => input[34] = 11,
            11 => input[35] = 3,
            12 => input[38] = 1,
            13 => input[42] = 0x46,
            14 => input[51] = 17,
            15 => input[48] = 0,
            16 => input[54] ^= 1,
            17 => input[58] ^= 1,
            18 => input[62] ^= 1,
            19 => input[66] ^= 1,
            20 => {
                input.truncate(69);
                input[16..18].copy_from_slice(&55u16.to_be_bytes());
            }
            21 => input[46..48].copy_from_slice(&39u16.to_be_bytes()),
            22 => input[20] = 0x20,
            23 => input[42] = 0x65,
            24 => input[23] = 17,
            _ => unreachable!(),
        }
        if matches!(case, 13..=19 | 21 | 23) {
            fix_ip(&mut input[42..]);
        }
        fix_outer(&mut input);
        let mut f = feedback();
        f.submitted(&packet, 1);
        f.received(&input, 2);
        assert_eq!(f.fault(0, 7, 2), None, "case {case}");
    }
    for at in [24, 36, 52] {
        let mut input = quote(&packet, 900);
        input[at] ^= 1;
        if at == 52 {
            fix_outer(&mut input);
        }
        let mut f = feedback();
        f.submitted(&packet, 1);
        f.received(&input, 2);
        assert_eq!(f.fault(0, 7, 2), None);
    }
}
#[test]
fn history_eviction_age_rewind_and_expiry_are_bounded() {
    let packet = sent(100);
    for age in [RECENT_MS, RECENT_MS + 1] {
        let mut f = feedback();
        f.submitted(&packet, 1);
        f.received(&quote(&packet, 900), 1 + age);
        assert_eq!(
            f.fault(0, 7, 1 + age),
            if age == RECENT_MS { Some(900) } else { None }
        );
    }
    let mut f = feedback();
    for n in 0..=HISTORY {
        f.submitted(&sent(100 + n as u32), 1);
    }
    f.received(&quote(&packet, 900), 2);
    assert_eq!(f.fault(0, 7, 2), None);
    f.received(&quote(&sent(104), 900), 2);
    assert_eq!(f.fault(0, 7, 2), Some(900));
    let mut f = feedback();
    f.submitted(&packet, 10);
    f.received(&quote(&packet, 900), 9);
    assert_eq!(f.fault(0, 7, 9), None);
    assert!(f.clock_fault(0, 7, 9));
    // Alternate hook clock history: the last observer sample can be newer
    // than Entry.last_ms. Maintenance must propagate the observed rewind,
    // not leave a connected-looking but permanently blocked endpoint.
    let (wire, _peer, mut owner, _connection, endpoint) = connected();
    let now = wire.borrow().now_ms;
    owner.port.tcp_mtu.submitted(&packet, now + 10);
    wire.borrow_mut().now_ms = now + 1;
    assert_eq!(owner.stream_status(endpoint), Err(s::Error::Clock));
    let mut f = feedback();
    f.submitted(&packet, 60000);
    f.received(&quote(&packet, 900), 60001);
    assert_eq!(f.fault(0, 7, 60001), None);
}
#[test]
fn binding_scope_starts_empty_but_equal_later_wire_bytes_do_not_authenticate_history() {
    let packet = sent(100);
    let advice = quote(&packet, 900);
    let mut f = feedback();
    f.submitted(&packet, 1);
    f.revoke(0);
    f.bind(0, 8, LOCAL, 24, 40000, PEER, 60001, 2);
    f.received(&advice, 2);
    assert_eq!(f.fault(0, 8, 2), None);
    f.submitted(&packet, 3);
    f.received(&advice, 3);
    assert_eq!(f.fault(0, 8, 3), Some(900));
    assert_eq!(
        f.fault(0, 7, 3),
        None,
        "local epoch check is not wire provenance"
    );
    f.fence();
    assert!(!f.active());
    assert!(f.egress(&packet, 3));
}
fn connected() -> (
    Rc<RefCell<Wire>>,
    Stack<End>,
    Stack<End>,
    Connection,
    s::Endpoint,
) {
    let (wire, mut peer, mut owner) = pair(0);
    let listener = peer.listen(7000, 1).unwrap();
    let endpoint = owner.stream_grant_mtu_refusal(grant(40000)).unwrap();
    owner.stream_connect(endpoint).unwrap();
    let mut accepted = None;
    for _ in 0..1000 {
        step(&wire, &mut peer, &mut owner);
        if accepted.is_none() {
            accepted = peer.accept(listener);
        }
        if accepted.is_some() && owner.stream_status(endpoint).unwrap().connected {
            break;
        }
    }
    (wire, peer, owner, accepted.unwrap(), endpoint)
}
fn first_submission_with_pending_ack(
    wire: &Rc<RefCell<Wire>>,
    peer: &mut Stack<End>,
    owner: &mut Stack<End>,
    endpoint: s::Endpoint,
) -> Vec<u8> {
    assert_eq!(owner.stream_write(endpoint, &[0x55; 1024]), Ok(1024));
    owner.poll();
    let packet = wire.borrow().queues[0]
        .iter()
        .find(|f| f.len() >= 54 && f[23] == 6 && u16::from_be_bytes([f[16], f[17]]) > 900)
        .unwrap()
        .clone();
    let acknowledgement = u32::from_be_bytes(packet[38..42].try_into().unwrap())
        .wrapping_add(1024)
        .to_be_bytes();
    // Drive only the independent peer, including its delayed ACK timer. Leave
    // that actual ACK queued for the owner's next poll. Queued writes alone
    // do not establish available congestion-window or Nagle allowance.
    for _ in 0..=300 {
        peer.poll();
        let pending = wire.borrow().queues[1].iter().any(|f| {
            f.len() >= 54
                && f[23] == 6
                && f[26..30] == PEER.ip
                && f[30..34] == LOCAL
                && f[34..36] == PEER.port.to_be_bytes()
                && f[36..38] == 40000u16.to_be_bytes()
                && f[47] & 0x10 != 0
                && f[42..46] == acknowledgement
        });
        if pending {
            return packet;
        }
        wire.borrow_mut().now_ms += 1;
    }
    panic!("independent peer must queue an actual ACK within the recent-history bound");
}
#[test]
fn actual_successful_tcp_submission_then_minimum_quote_removes_only_its_socket_and_queues() {
    // Both branches have the same actual first submission, pending peer ACK
    // and further queued bytes. Calibrate actual application egress without
    // advice, then put advice before that ACK in the negative branch.
    {
        let (wire, mut peer, mut owner, _connection, endpoint) = connected();
        first_submission_with_pending_ack(&wire, &mut peer, &mut owner, endpoint);
        assert_eq!(owner.stream_write(endpoint, &[0x66; 1024]), Ok(1024));
        assert_eq!(owner.stream_write(endpoint, &[0x77; 1024]), Ok(1024));
        let before = wire.borrow().sent;
        owner.poll();
        assert!(
            wire.borrow().sent > before,
            "queued data actually reaches egress without advice"
        );
        assert!(
            wire.borrow().queues[0].iter().any(|f| {
                f.len() >= 54
                    && f[23] == 6
                    && f[26..30] == LOCAL
                    && f[34..36] == 40000u16.to_be_bytes()
                    && f.get(34 + usize::from(f[46] >> 4) * 4) == Some(&0x66)
            }),
            "the newly queued application bytes, not a control frame, reached egress"
        );
    }
    let (wire, mut peer, mut owner, _connection, endpoint) = connected();
    let other = owner.stream_grant(grant(40001)).unwrap();
    let packet = first_submission_with_pending_ack(&wire, &mut peer, &mut owner, endpoint);
    assert_eq!(u16::from_be_bytes([packet[20], packet[21]]), 0x4000);
    assert_eq!(owner.stream_write(endpoint, &[0x66; 1024]), Ok(1024));
    assert_eq!(owner.stream_write(endpoint, &[0x77; 1024]), Ok(1024));
    let sent_before = wire.borrow().sent;
    wire.borrow_mut().queues[1].push_front(quote(&packet, 900));
    owner.poll();
    assert_eq!(
        owner.stream_status(endpoint),
        Err(s::Error::FragmentationNeeded { mtu: 900 })
    );
    assert_eq!(owner.socket_count(), 0);
    assert_eq!(
        wire.borrow().sent,
        sent_before,
        "pending same-poll output is refused before removal"
    );
    assert_eq!(
        owner.stream_write(endpoint, b"later"),
        Err(s::Error::FragmentationNeeded { mtu: 900 })
    );
    assert!(!owner.stream_status(other).unwrap().connected);
    owner.stream_abort(endpoint).unwrap();
    assert_eq!(owner.stream_status(endpoint), Err(s::Error::Stale));
    let fresh = owner.stream_grant_mtu_refusal(grant(40000)).unwrap();
    assert_ne!(fresh, endpoint);
}
#[test]
fn legacy_grants_leave_observer_inert_and_unsent_or_failed_submission_cannot_register() {
    let (_, _, mut owner) = pair(0);
    let endpoint = owner.stream_grant(grant(40000)).unwrap();
    assert!(!owner.port.tcp_mtu.active());
    let packet = sent(100);
    owner.port.tcp_mtu.received(&quote(&packet, 900), 1);
    assert!(!owner.stream_status(endpoint).unwrap().connected);
    let mut f = feedback();
    f.received(&quote(&packet, 900), 2);
    assert_eq!(f.fault(0, 7, 2), None);
    // Corrupt full TCP checksum cannot enter history even if a local fixture
    // pretends submission succeeded. Failed Link sends never call submitted.
    let mut corrupt = packet.clone();
    corrupt[50] ^= 1;
    f.submitted(&corrupt, 2);
    f.received(&quote(&packet, 900), 3);
    assert_eq!(f.fault(0, 7, 3), None);
}
struct Plan {
    code: u8,
    length: u16,
    body: Vec<u8>,
    version: Option<u8>,
    wrong_peer: bool,
}
struct Script {
    input: Vec<u8>,
    output: VecDeque<u8>,
    plans: VecDeque<Plan>,
    calls: Rc<RefCell<Vec<Vec<u8>>>>,
    now: Rc<std::cell::Cell<u64>>,
    advance: u64,
}
impl datagram::channel::Pipe for Script {
    fn now_ms(&self) -> u64 {
        self.now.get()
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        let n = b.len().min(7);
        self.input.extend_from_slice(&b[..n]);
        if self.input.len() >= 2
            && self.input.len()
                == 2 + usize::from(u16::from_be_bytes([self.input[0], self.input[1]]))
        {
            let request = core::mem::take(&mut self.input);
            self.calls.borrow_mut().push(request[2..].to_vec());
            let plan = self.plans.pop_front().expect("unexpected automatic retry");
            let mut reply = request[2..14].to_vec();
            reply[2] = plan.code;
            reply[10..12].copy_from_slice(&plan.length.to_be_bytes());
            if let Some(v) = plan.version {
                reply[0] = v;
            }
            if plan.wrong_peer {
                reply[4] ^= 1;
            }
            reply.extend(plan.body);
            self.output.extend((reply.len() as u16).to_be_bytes());
            self.output.extend(reply);
        }
        Ok(Some(n))
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        let n = b.len().min(3).min(self.output.len());
        if n == 0 {
            return Ok(None);
        }
        for byte in &mut b[..n] {
            *byte = self.output.pop_front().unwrap();
        }
        self.now.set(self.now.get() + self.advance);
        Ok(Some(n))
    }
}
fn plan(code: u8, length: u16, body: &[u8]) -> Plan {
    Plan {
        code,
        length,
        body: body.to_vec(),
        version: None,
        wrong_peer: false,
    }
}
fn script(plans: Vec<Plan>) -> Script {
    Script {
        input: Vec::new(),
        output: VecDeque::new(),
        plans: plans.into(),
        calls: Rc::new(RefCell::new(Vec::new())),
        now: Rc::new(std::cell::Cell::new(1)),
        advance: 0,
    }
}
fn pause(_: u64) {}
#[test]
fn real_client_decodes_v4_terminal_metadata_and_does_not_repeat_accepted_write() {
    let p = script(vec![plan(0, 1, &[1]), plan(0, 3, &[]), plan(17, 900, &[])]);
    let calls = p.calls.clone();
    let mut c = s::Client::new_mtu_refusal(p, PEER, pause);
    c.connect(100).unwrap();
    assert_eq!(c.write(b"abc", 100), Ok(3));
    assert_eq!(
        c.read(&mut [0; 8], 100),
        Err(s::Error::FragmentationNeeded { mtu: 900 })
    );
    let before = calls.borrow().clone();
    assert_eq!(c.write(b"abc", 100), Err(s::Error::Stale));
    assert_eq!(*calls.borrow(), before);
    assert_eq!(before.len(), 3);
    assert!(before.iter().all(|r| r[0] == 4));
}
#[test]
fn legacy_or_malformed_v4_error_shape_and_cross_version_reply_refuse() {
    for case in 0..8 {
        let mut reply = plan(17, 900, &[]);
        match case {
            0 => reply.length = 0,
            1 => reply.length = 575,
            2 => reply.length = 1500,
            3 => reply.body.push(0),
            4 => reply.code = 18,
            5 => reply.version = Some(1),
            6 => reply.wrong_peer = true,
            7 => {}
            _ => unreachable!(),
        }
        let p = script(vec![reply]);
        let calls = p.calls.clone();
        let mut c = if case == 7 {
            s::Client::new(p, PEER, pause)
        } else {
            s::Client::new_mtu_refusal(p, PEER, pause)
        };
        assert_eq!(c.connect(100), Err(s::Error::Channel(-22)), "case {case}");
        assert_eq!(c.connect(100), Err(s::Error::Stale));
        assert_eq!(calls.borrow().len(), 1);
    }
}
#[test]
fn actual_v4_session_serializes_metadata_without_body_and_legacy_session_stays_v1() {
    let (_, _, mut owner) = pair(0);
    let mut session = s::Session::grant_mtu_refusal(&mut owner, grant(40000)).unwrap();
    let packet = sent(100);
    owner.port.tcp_mtu.submitted(&packet, 1);
    owner.port.tcp_mtu.received(&quote(&packet, 900), 1);
    owner.stream_maintain(false);
    let mut request = [0; 12];
    request[0] = 4;
    request[1] = s::STATUS;
    request[4..8].copy_from_slice(&PEER.ip);
    request[8..10].copy_from_slice(&PEER.port.to_be_bytes());
    let mut reply = [0; datagram::MAX_MESSAGE];
    assert_eq!(session.request(&mut owner, &request, &mut reply), 12);
    assert_eq!(&reply[..4], &[4, s::STATUS, 17, 0]);
    assert_eq!(&reply[10..12], &900u16.to_be_bytes());
    let mut legacy = s::Session::grant(&mut owner, grant(40001)).unwrap();
    request[0] = 1;
    assert_eq!(legacy.request(&mut owner, &request, &mut reply), 13);
    assert_eq!(reply[0], 1);
    assert_eq!(reply[2], 0);
}
#[test]
fn experimental_dns_preserves_typed_refusal_and_never_reconnects_or_reissues_lookup() {
    let p = script(vec![plan(17, 900, &[])]);
    let calls = p.calls.clone();
    let mut transport = dns::tcp::DatagramTcp::new_mtu_refusal(p, PEER, pause);
    let query: &[u8] = &[
        0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0, 0, 1, 0, 1,
    ];
    let mut output = [0; dns::MAX_TCP_RESPONSE];
    assert_eq!(
        dns::Transport::tcp(&mut transport, query, &mut output, 100),
        Err(dns::Error::Stream(s::Error::FragmentationNeeded {
            mtu: 900
        }))
    );
    assert_eq!(
        dns::Transport::tcp(&mut transport, query, &mut output, 100),
        Err(dns::Error::Stream(s::Error::Stale))
    );
    assert_eq!(calls.borrow().len(), 1);
}
#[test]
fn experimental_client_deadline_crossing_still_fences_with_original_bound() {
    let mut p = script(vec![plan(17, 900, &[])]);
    p.advance = 100;
    let calls = p.calls.clone();
    let mut c = s::Client::new_mtu_refusal(p, PEER, pause);
    assert_eq!(c.connect(100), Err(s::Error::Timeout));
    assert_eq!(c.connect(1000), Err(s::Error::Stale));
    assert_eq!(calls.borrow().len(), 1);
}

#[test]
fn actual_tx_token_failed_link_call_never_creates_tcp_history() {
    use smoltcp::phy::TxToken as _;
    struct Refuse;
    impl Link for Refuse {
        fn mac(&self) -> [u8; 6] {
            MAC
        }
        fn now_ms(&self) -> u64 {
            1
        }
        fn pause(&self, _: u64) {}
        fn send(&mut self, _: &[u8]) -> Result<(), i64> {
            Err(-5)
        }
        fn receive(&mut self, _: &mut [u8; FRAME_MAX], _: u64) -> Result<Option<usize>, i64> {
            Ok(None)
        }
    }
    let packet = sent(100);
    let mut tcp = feedback();
    let mut link = Refuse;
    let mut scratch = [0; FRAME_MAX];
    let mut stats = Stats::default();
    TxToken {
        link: &mut link,
        frame_mtu: FRAME_MAX,
        buffer: &mut scratch,
        stats: &mut stats,
        server_rules: &mut [None; s::MAX_ENDPOINTS],
        ipv6_server_rules: &mut [None; ipv6::stream::MAX_ENDPOINTS],
        feedback: &mut icmp::Feedback::new(MAC),
        tcp_mtu: &mut tcp,
        ipv6_feedback: &mut ipv6::feedback::Feedback::new(MAC),
    }
    .consume(packet.len(), |bytes| bytes.copy_from_slice(&packet));
    assert_eq!(stats.tx_frames, 0);
    assert_eq!(stats.link_errors, 1);
    tcp.received(&quote(&packet, 900), 2);
    assert_eq!(tcp.fault(0, 7, 2), None);
}

#[test]
fn explicit_dns_pair_selects_tcp_v4_keeps_udp_v1_and_revokes_both_scopes() {
    let (_, _, mut owner) = pair(0);
    let udp = datagram::Grant {
        local_port: 40000,
        peer: PEER,
    };
    let mut wrong = grant(40000);
    wrong.peer.port += 1;
    assert!(matches!(
        dns::tcp::Session::grant_mtu_refusal(&mut owner, udp, wrong),
        Err(s::Error::Denied)
    ));
    assert!(!owner.datagrams.active());
    assert!(!owner.port.tcp_mtu.active());
    let blocker = owner.stream_grant(grant(40000)).unwrap();
    assert!(matches!(
        dns::tcp::Session::grant_mtu_refusal(&mut owner, udp, grant(40000)),
        Err(s::Error::InUse)
    ));
    assert!(
        !owner.datagrams.active(),
        "partial paired construction rolls back its UDP grant"
    );
    assert!(!owner.port.tcp_mtu.active());
    owner.stream_abort(blocker).unwrap();
    let mut pair = dns::tcp::Session::grant_mtu_refusal(&mut owner, udp, grant(40000)).unwrap();
    assert!(owner.datagrams.active());
    assert!(owner.port.tcp_mtu.active());
    let mut request = [0; 12];
    request[0] = 4;
    request[1] = s::STATUS;
    request[4..8].copy_from_slice(&PEER.ip);
    request[8..10].copy_from_slice(&PEER.port.to_be_bytes());
    let mut reply = [0; datagram::MAX_MESSAGE];
    assert_eq!(
        s::channel::Handler::request(&mut pair, &mut owner, &request, &mut reply),
        13
    );
    assert_eq!(reply[0], 4);
    assert_eq!(reply[2], 0);
    request[0] = 1;
    request[1] = datagram::RECEIVE;
    request[4..10].fill(0);
    request[10..12].copy_from_slice(&8u16.to_be_bytes());
    assert_eq!(
        s::channel::Handler::request(&mut pair, &mut owner, &request, &mut reply),
        12
    );
    assert_eq!(reply[0], 1);
    assert_eq!(reply[2], datagram::Error::Again.code());
    s::channel::Handler::revoke(&mut pair, &mut owner);
    assert!(!owner.datagrams.active());
    assert!(!owner.port.tcp_mtu.active());
}
