use super::*;
use alloc::{collections::VecDeque, vec::Vec};
const LOCAL: [u8; 4] = [192, 0, 2, 100];
const PEER: [u8; 4] = [192, 0, 2, 1];
const MAC: [u8; 6] = [2, 0, 0, 0, 0, 100];
const PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
struct State {
    now: u64,
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
    reading: Option<LinkReading>,
    send_advance: u64,
    send_error: Option<i64>,
    receive_advance: u64,
}
struct TestLink(Rc<RefCell<State>>);
impl Link for TestLink {
    fn mac(&self) -> [u8; 6] {
        MAC
    }
    fn now_ms(&self) -> u64 {
        self.0.borrow().now
    }
    fn pause(&self, ms: u64) {
        self.0.borrow_mut().now += ms;
    }
    fn read(&self) -> Option<LinkReading> {
        self.0.borrow().reading
    }
    fn send(&mut self, bytes: &[u8]) -> Result<(), i64> {
        let mut state = self.0.borrow_mut();
        state.tx.push(bytes.to_vec()); // The effect is retained even on Err.
        let advance = state.send_advance;
        state.now += advance;
        state.send_error.map_or(Ok(()), Err)
    }
    fn receive(&mut self, bytes: &mut [u8; FRAME_MAX], _: u64) -> Result<Option<usize>, i64> {
        let mut state = self.0.borrow_mut();
        let advance = state.receive_advance;
        state.now += advance;
        Ok(state.rx.pop_front().map(|packet| {
            bytes[..packet.len()].copy_from_slice(&packet);
            packet.len()
        }))
    }
}
fn entropy(bytes: &mut [u8]) -> Result<(), i64> {
    bytes.copy_from_slice(&[
        0x12, 0x34, 0x56, 0x78, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    ]);
    Ok(())
}
fn opened() -> (Owner<TestLink>, Rc<RefCell<State>>) {
    let state = Rc::new(RefCell::new(State {
        now: 1,
        rx: VecDeque::new(),
        tx: Vec::new(),
        reading: Some(LinkReading {
            link_up: true,
            disabled: false,
            rx_missed: 0,
        }),
        send_advance: 0,
        send_error: None,
        receive_advance: 0,
    }));
    let owner = Owner::open(
        TestLink(state.clone()),
        Config {
            address: LOCAL.into(),
            prefix_len: 24,
            gateway: None,
            rx_buffer: 1024,
            tx_buffer: 1024,
        },
    )
    .unwrap();
    (owner, state)
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += (u16::from(pair[0]) << 8 | u16::from(*pair.get(1).unwrap_or(&0))) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn fix(frame: &mut [u8]) {
    frame[24..26].fill(0);
    let value = checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&value.to_be_bytes());
    frame[36..38].fill(0);
    let value = checksum(&frame[34..]);
    frame[36..38].copy_from_slice(&value.to_be_bytes());
}
fn arp_reply() -> Vec<u8> {
    let mut bytes = Vec::from(MAC);
    bytes.extend(PEER_MAC);
    bytes.extend([8, 6, 0, 1, 8, 0, 6, 4, 0, 2]);
    bytes.extend(PEER_MAC);
    bytes.extend(PEER);
    bytes.extend(MAC);
    bytes.extend(LOCAL);
    bytes
}
fn request_frame(
    owner: &mut Owner<TestLink>,
    state: &Rc<RefCell<State>>,
    endpoint: Endpoint,
) -> Vec<u8> {
    owner.start(endpoint, PEER).unwrap();
    owner.poll().unwrap();
    assert_eq!(
        &state.borrow().tx[0][12..14],
        &[8, 6],
        "engine must resolve its real neighbor"
    );
    state.borrow_mut().rx.push_back(arp_reply());
    owner.poll().unwrap();
    let sent: Vec<_> = state
        .borrow()
        .tx
        .iter()
        .filter(|b| b.len() >= 35 && b[23] == 1 && b[34] == 8)
        .cloned()
        .collect();
    assert_eq!(sent.len(), 1);
    sent[0].clone()
}
fn response(request: &[u8]) -> Vec<u8> {
    let mut bytes = request.to_vec();
    bytes[..6].copy_from_slice(&MAC);
    bytes[6..12].copy_from_slice(&PEER_MAC);
    bytes[26..30].copy_from_slice(&PEER);
    bytes[30..34].copy_from_slice(&LOCAL);
    bytes[34] = 0;
    fix(&mut bytes);
    bytes
}

#[test]
fn literal_request_and_observation_vectors_fix_both_formats() {
    let (mut owner, _) = opened();
    owner.instance = 0x0102030405060708;
    owner.next_epoch = 0x1112131415161718;
    let endpoint = owner.grant(PEER, 1000, entropy).unwrap();
    let literal = [
        0x08, 0x00, 0x6b, 0x3f, 0x12, 0x34, 0x56, 0x78, 0x41, 0x42, 0x53, 0x44, 0x50, 0x49, 0x4e,
        0x47, 1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x21, 0x22,
        0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    ];
    assert_eq!(owner.lookup(endpoint).unwrap().packet, literal);
    assert_eq!(checksum(&literal), 0);
    let observation = Observation {
        peer: PEER,
        identifier: 0x1234,
        sequence: 0x5678,
        instance: endpoint.instance,
        epoch: endpoint.epoch,
        nonce: 0x2122232425262728,
        boot_rtt_ms: 9,
    };
    let wire = [
        1, 2, 0, 0, 192, 0, 2, 1, 0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0, 0, 0, 0,
        0, 0, 0, 9, 0, 0, 0, 0,
    ];
    let mut output = [0; RESPONSE_LEN];
    encode(OBSERVE, observation, &mut output);
    assert_eq!(output, wire);
    assert_eq!(decode(&wire, PEER), Ok(observation));
    for at in [0, 1, 2, 3, 4, 44, 45, 46, 47] {
        let mut changed = wire;
        changed[at] ^= 1;
        assert_eq!(decode(&changed, PEER), Err(Error::Invalid));
    }
}
#[test]
fn actual_engine_arp_echo_and_one_consumed_observation() {
    let (mut owner, state) = opened();
    let endpoint = owner.grant(PEER, 1000, entropy).unwrap();
    let request = request_frame(&mut owner, &state, endpoint);
    assert_eq!(owner.start(endpoint, PEER), Err(Error::Spent));
    state.borrow_mut().now += 9;
    state.borrow_mut().rx.push_back(response(&request));
    owner.poll().unwrap();
    let found = owner.observe(endpoint).unwrap();
    assert_eq!(found.boot_rtt_ms, 9);
    assert_eq!(found.nonce, 0x2122232425262728);
    assert_eq!(owner.observe(endpoint), Err(Error::Spent));
    assert_eq!(owner.socket_count(), 0);
    assert_eq!(owner.grant(PEER, 1000, entropy), Err(Error::Exhausted));
    owner.close(endpoint).unwrap();
}
#[test]
fn peer_authority_capacity_entropy_and_checked_epoch_refuse() {
    let (mut owner, _) = opened();
    for peer in [
        [0, 0, 0, 0],
        [127, 0, 0, 1],
        [224, 0, 0, 1],
        LOCAL,
        [192, 0, 2, 0],
        [192, 0, 2, 255],
        [192, 0, 3, 1],
    ] {
        assert_eq!(owner.grant(peer, 1000, entropy), Err(Error::Denied));
    }
    for until in [0, 1, MAX_LIFETIME_MS + 2] {
        assert_eq!(owner.grant(PEER, until, entropy), Err(Error::Invalid));
    }
    assert_eq!(owner.grant(PEER, 1000, |_| Err(-5)), Err(Error::Entropy));
    assert_eq!(
        owner.grant(PEER, 1000, |b| {
            b.fill(0);
            Ok(())
        }),
        Err(Error::Entropy)
    );
    let old = owner.grant(PEER, 1000, entropy).unwrap();
    assert_eq!(owner.grant(PEER, 1000, entropy), Err(Error::Exhausted));
    assert_eq!(owner.start(old, [192, 0, 2, 2]), Err(Error::Denied));
    assert!(owner.lookup(old).unwrap().started.is_none());
    owner.close(old).unwrap();
    let new = owner.grant(PEER, 1000, entropy).unwrap();
    assert_ne!(new, old);
    assert_eq!(owner.start(old, PEER), Err(Error::Stale));
    owner.close(new).unwrap();
    owner.next_epoch = u64::MAX;
    assert_eq!(owner.grant(PEER, 1000, entropy), Err(Error::Exhausted));
}
#[test]
fn queue_close_expiry_and_rewind_remove_request_before_any_wire_effect() {
    for case in 0..3 {
        let (mut owner, state) = opened();
        let endpoint = owner.grant(PEER, 1000, entropy).unwrap();
        owner.start(endpoint, PEER).unwrap();
        match case {
            0 => owner.close(endpoint).unwrap(),
            1 => state.borrow_mut().now = 1001,
            _ => state.borrow_mut().now = 0,
        }
        let result = owner.poll();
        if case != 0 {
            assert_eq!(
                result,
                Err(if case == 1 {
                    Error::Expired
                } else {
                    Error::Clock
                })
            );
        }
        assert!(state.borrow().tx.is_empty());
        assert_eq!(owner.socket_count(), 0);
        assert_eq!(owner.start(endpoint, PEER), Err(Error::Stale));
    }
}
#[test]
fn unknown_down_disabled_and_receive_time_advance_fence() {
    for reading in [
        None,
        Some(LinkReading {
            link_up: false,
            disabled: false,
            rx_missed: 0,
        }),
        Some(LinkReading {
            link_up: true,
            disabled: true,
            rx_missed: 0,
        }),
    ] {
        let (mut owner, state) = opened();
        let e = owner.grant(PEER, 1000, entropy).unwrap();
        owner.start(e, PEER).unwrap();
        state.borrow_mut().reading = reading;
        assert!(owner.poll().is_err());
        assert_eq!(owner.socket_count(), 0);
        assert!(state.borrow().tx.is_empty());
    }
    let (mut owner, state) = opened();
    let e = owner.grant(PEER, 1000, entropy).unwrap();
    owner.start(e, PEER).unwrap();
    state.borrow_mut().receive_advance = 1000;
    assert_eq!(owner.poll(), Err(Error::Expired));
    assert_eq!(owner.socket_count(), 0);
}
#[test]
fn submitted_send_straddling_expiry_or_returning_error_retains_first_effect_only() {
    for failed in [false, true] {
        let (mut owner, state) = opened();
        let e = owner.grant(PEER, 1000, entropy).unwrap();
        owner.start(e, PEER).unwrap();
        owner.poll().unwrap();
        state.borrow_mut().rx.push_back(arp_reply());
        if failed {
            state.borrow_mut().send_error = Some(-100);
        } else {
            state.borrow_mut().send_advance = 1000;
        }
        assert_eq!(
            owner.poll(),
            Err(if failed {
                Error::LinkIo
            } else {
                Error::Expired
            })
        );
        let count = state
            .borrow()
            .tx
            .iter()
            .filter(|b| b.len() >= 35 && b[23] == 1 && b[34] == 8)
            .count();
        assert_eq!(
            count, 1,
            "the first submitted effect is retained, never claimed absent"
        );
        let effects = state.borrow().tx.len();
        owner.poll().unwrap();
        assert_eq!(state.borrow().tx.len(), effects);
        assert_eq!(owner.start(e, PEER), Err(Error::Stale));
        assert_eq!(owner.socket_count(), 0);
    }
}
#[test]
fn malformed_unrelated_and_replayed_wire_replies_never_observe() {
    for case in 0..13 {
        let (mut owner, state) = opened();
        let e = owner.grant(PEER, 1000, entropy).unwrap();
        let sent = request_frame(&mut owner, &state, e);
        let mut packet = response(&sent);
        match case {
            0 => packet[34] = 8,
            1 => packet[35] = 1,
            2 => packet[38] ^= 1,
            3 => packet[40] ^= 1,
            4 => packet[42] ^= 1,
            5 => packet[58] ^= 1,
            6 => packet[66] ^= 1,
            7 => packet[29] ^= 1,
            8 => packet[33] ^= 1,
            9 => packet[20] |= 0x20,
            10 => {
                packet.pop();
                let size = (packet.len() - 14) as u16;
                packet[16..18].copy_from_slice(&size.to_be_bytes());
            }
            11 => {
                packet.push(0);
                let size = (packet.len() - 14) as u16;
                packet[16..18].copy_from_slice(&size.to_be_bytes());
            }
            12 => {}
            _ => unreachable!(),
        }
        fix(&mut packet);
        if case == 12 {
            packet[36] ^= 1;
        }
        state.borrow_mut().rx.push_back(packet);
        owner.poll().unwrap();
        assert_eq!(owner.observe(e), Err(Error::Again), "case {case}");
        if case == 6 {
            let old = response(&sent);
            owner.close(e).unwrap();
            let fresh = owner.grant(PEER, 1000, entropy).unwrap();
            owner.start(fresh, PEER).unwrap();
            state.borrow_mut().rx.push_back(old);
            owner.poll().unwrap();
            assert_eq!(
                owner.observe(fresh),
                Err(Error::Again),
                "old epoch cannot match new grant"
            );
        }
    }
}
#[test]
fn receive_queue_is_one_packet_and_duplicate_observation_is_spent() {
    let (mut owner, state) = opened();
    let e = owner.grant(PEER, 1000, entropy).unwrap();
    let sent = request_frame(&mut owner, &state, e);
    let valid = response(&sent);
    let mut unrelated = valid.clone();
    unrelated[66] ^= 1;
    fix(&mut unrelated);
    state.borrow_mut().rx.extend([unrelated, valid.clone()]);
    owner.poll().unwrap();
    let h = owner.lookup(e).unwrap().handle.unwrap();
    let socket = owner.stack.sockets.get::<icmp::Socket>(h);
    assert_eq!(socket.packet_recv_capacity(), 1);
    assert!(socket.recv_queue() <= PACKET_LEN);
    assert_eq!(owner.observe(e), Err(Error::Again));
    state.borrow_mut().rx.push_back(valid);
    owner.poll().unwrap();
    assert!(owner.observe(e).is_ok());
    assert_eq!(owner.observe(e), Err(Error::Spent));
}

struct TestPipe {
    input: VecDeque<u8>,
    output: Vec<u8>,
    now: Rc<RefCell<State>>,
    eof: bool,
    write_limit: usize,
    fail_write: bool,
    read_limit: usize,
    read_advance: u64,
    read_effect: usize,
}
impl Pipe for TestPipe {
    fn now_ms(&self) -> u64 {
        self.now.borrow().now
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        if self.input.is_empty() {
            return Ok(if self.eof { Some(0) } else { None });
        }
        let n = b.len().min(self.input.len()).min(self.read_limit);
        for byte in &mut b[..n] {
            *byte = self.input.pop_front().unwrap();
        }
        self.read_effect += n;
        self.now.borrow_mut().now += self.read_advance;
        Ok(Some(n))
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        if self.fail_write {
            return Err(-5);
        }
        let n = b.len().min(self.write_limit);
        if n == 0 {
            return Ok(None);
        }
        self.output.extend_from_slice(&b[..n]);
        Ok(Some(n))
    }
}
fn pipe(state: Rc<RefCell<State>>, input: &[u8]) -> TestPipe {
    TestPipe {
        input: input.iter().copied().collect(),
        output: Vec::new(),
        now: state,
        eof: false,
        write_limit: RESPONSE_LEN,
        fail_write: false,
        read_limit: REQUEST_LEN,
        read_advance: 0,
        read_effect: 0,
    }
}

#[test]
fn delayed_first_partial_or_full_start_read_retires_before_request_execution() {
    for (limit, delay) in [
        (3, FRAME_MS),
        (REQUEST_LEN, FRAME_MS),
        (3, FRAME_MS + 1),
        (REQUEST_LEN, FRAME_MS + 1),
    ] {
        let (mut owner, state) = opened();
        let endpoint = owner.grant(PEER, 1000, entropy).unwrap();
        let mut channel = Channel::new(&mut owner, endpoint).unwrap();
        let mut transport = pipe(state.clone(), &[1, START, 0, 0, 192, 0, 2, 1]);
        transport.read_limit = limit;
        transport.read_advance = delay;
        assert!(!channel.poll(&mut owner, &mut transport));
        assert_eq!(
            transport.read_effect, limit,
            "the first read consumed bytes; no rollback is claimed"
        );
        assert_eq!(transport.input.len(), REQUEST_LEN - limit);
        assert!(transport.output.is_empty());
        assert_eq!(owner.socket_count(), 0);
        assert_eq!(owner.start(endpoint, PEER), Err(Error::Stale));
        owner.poll().unwrap();
        assert!(
            state.borrow().tx.is_empty(),
            "no START operation or wire submission after the late first read"
        );
    }
}

#[test]
fn cross_owner_references_do_not_select_another_grant() {
    let (mut a, _) = opened();
    let (mut b, state) = opened();
    let old = a.grant(PEER, 1000, entropy).unwrap();
    let current = b.grant(PEER, 1000, entropy).unwrap();
    assert_eq!(b.start(old, PEER), Err(Error::Stale));
    assert_eq!(b.close(old), Err(Error::Stale));
    assert!(b.lookup(current).is_ok());
    assert!(state.borrow().tx.is_empty());
}

#[test]
fn malformed_fixed_requests_cannot_queue_a_probe() {
    for (offset, value) in [(0, 0), (1, 0), (1, 8), (2, 1), (3, 1)] {
        let (mut owner, state) = opened();
        let e = owner.grant(PEER, 1000, entropy).unwrap();
        let mut c = Channel::new(&mut owner, e).unwrap();
        let mut request = [1, 1, 0, 0, 192, 0, 2, 1];
        request[offset] = value;
        let mut p = pipe(state.clone(), &request);
        c.poll(&mut owner, &mut p);
        c.poll(&mut owner, &mut p);
        assert_eq!(p.output[2], Error::Invalid.code());
        assert!(owner.lookup(e).unwrap().started.is_none());
        owner.poll().unwrap();
        assert!(state.borrow().tx.is_empty());
    }
}

#[test]
fn failed_reply_pipe_after_start_discards_locally_queued_request() {
    let (mut owner, state) = opened();
    let e = owner.grant(PEER, 1000, entropy).unwrap();
    let mut c = Channel::new(&mut owner, e).unwrap();
    let mut p = pipe(state.clone(), &[1, 1, 0, 0, 192, 0, 2, 1]);
    assert!(c.poll(&mut owner, &mut p));
    p.fail_write = true;
    assert!(!c.poll(&mut owner, &mut p));
    assert_eq!(owner.socket_count(), 0);
    owner.poll().unwrap();
    assert!(state.borrow().tx.is_empty());
    assert_eq!(owner.start(e, PEER), Err(Error::Stale));
}
#[test]
fn literal_pipe_start_denial_and_no_arbitrary_request_body() {
    let (mut owner, state) = opened();
    let e = owner.grant(PEER, 1000, entropy).unwrap();
    let mut c = Channel::new(&mut owner, e).unwrap();
    let mut p = pipe(state.clone(), &[1, 1, 0, 0, 192, 0, 2, 2]);
    assert!(c.poll(&mut owner, &mut p));
    assert!(c.poll(&mut owner, &mut p));
    assert_eq!(&p.output[..4], &[1, 1, 2, 0]);
    assert!(owner.lookup(e).unwrap().started.is_none());
    p.input.extend([1, 1, 0, 0, 192, 0, 2, 1]);
    assert!(c.poll(&mut owner, &mut p));
    assert!(c.poll(&mut owner, &mut p));
    let mut ack = [0; RESPONSE_LEN];
    ack[..2].copy_from_slice(&[1, 1]);
    assert_eq!(&p.output[RESPONSE_LEN..], &ack);
    assert!(state.borrow().tx.is_empty());
    p.input.extend([1, 8, 0, 0, 192, 0, 2, 1]);
    c.poll(&mut owner, &mut p);
    c.poll(&mut owner, &mut p);
    assert_eq!(
        &p.output[RESPONSE_LEN * 2..RESPONSE_LEN * 2 + 4],
        &[1, 8, 1, 0]
    );
}
#[test]
fn partial_eof_expiry_output_stall_and_pipe_rewind_revoke_queued_data() {
    for case in 0..4 {
        let (mut owner, state) = opened();
        let e = owner.grant(PEER, 1000, entropy).unwrap();
        let mut c = Channel::new(&mut owner, e).unwrap();
        let mut p = pipe(
            state.clone(),
            if case == 2 {
                &[1, 1, 0, 0, 192, 0, 2, 1]
            } else {
                &[1, 1, 0]
            },
        );
        assert!(c.poll(&mut owner, &mut p));
        match case {
            0 => p.eof = true,
            1 | 2 => {
                p.write_limit = 0;
                state.borrow_mut().now += FRAME_MS;
            }
            _ => state.borrow_mut().now = 0,
        }
        assert!(!c.poll(&mut owner, &mut p));
        assert_eq!(owner.socket_count(), 0);
        owner.poll().unwrap();
        assert!(state.borrow().tx.is_empty());
    }
}
#[test]
fn uncertain_client_write_stops_without_retry_or_deadline_restart() {
    struct Partial {
        now: u64,
        writes: Vec<Vec<u8>>,
    }
    impl Pipe for Partial {
        fn now_ms(&self) -> u64 {
            self.now
        }
        fn read(&mut self, _: &mut [u8]) -> Result<Option<usize>, i64> {
            unreachable!()
        }
        fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
            self.writes.push(b.to_vec());
            self.now += 1;
            if self.writes.len() == 1 {
                Ok(Some(3))
            } else {
                Err(-5)
            }
        }
    }
    let mut p = Partial {
        now: 1,
        writes: Vec::new(),
    };
    let mut last = 1;
    let request = [1, 1, 0, 0, 192, 0, 2, 1];
    assert_eq!(transact(&mut p, &request, 100, &mut last), Err(-5));
    assert_eq!(p.writes.len(), 2);
    assert_eq!(p.writes[1], request[3..]);
    let mut p = Partial {
        now: 100,
        writes: Vec::new(),
    };
    let mut last = 1;
    assert_eq!(transact(&mut p, &request, 100, &mut last), Err(-110));
    assert!(p.writes.is_empty());
}

#[test]
fn bounded_four_operation_schedules_preserve_one_submission_and_terminal_fencing() {
    // 8^4 actual API schedules, not a second implementation of the state
    // machine. Fixed clock/link and prelearned ARP are explicit assumptions.
    for schedule in 0usize..4096 {
        let (mut owner, state) = opened();
        let e = owner.grant(PEER, 1000, entropy).unwrap();
        state.borrow_mut().rx.push_back(arp_reply());
        owner.poll().unwrap();
        let mut code = schedule;
        for _ in 0..4 {
            match code % 8 {
                0 => {
                    let _ = owner.start(e, PEER);
                }
                1 => {
                    let _ = owner.poll();
                }
                2 => {
                    let _ = owner.close(e);
                }
                3 => state.borrow_mut().now = 1000,
                4 => state.borrow_mut().now = 0,
                5 => {
                    let _ = owner.start(e, [192, 0, 2, 2]);
                }
                6 => {
                    let _ = owner.observe(e);
                }
                _ => owner.fence(),
            }
            code /= 8;
            assert!(owner.socket_count() <= MAX_GRANTS, "schedule {schedule}");
            let requests = state
                .borrow()
                .tx
                .iter()
                .filter(|b| b.len() >= 35 && b[23] == 1 && b[34] == 8)
                .count();
            assert!(
                requests <= 1,
                "schedule {schedule}: more than one submitted request"
            );
            if owner.entry.is_none() {
                assert!(!owner.boundary.borrow().active);
                assert_eq!(owner.socket_count(), 0);
            }
        }
    }
}
