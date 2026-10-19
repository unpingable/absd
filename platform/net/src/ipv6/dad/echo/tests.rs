//! Source-authored boundary cases. The peer is a separate unfiltered instance
//! of the same pinned engine, not a relaxation of production Port admission.
use super::*;
use smoltcp::{
    iface::{Config as IfaceConfig, Interface, SocketSet},
    phy::{Device, DeviceCapabilities, Medium},
    time::Instant,
    wire::{EthernetAddress, HardwareAddress, IpCidr},
};
const MAC: [u8; 6] = [0x52, 0x54, 0, 0xab, 0x5d, 0x15];
const PEER_MAC: [u8; 6] = [0x52, 0x55, 0, 0, 2, 2];
fn up() -> Option<LinkReading> {
    Some(LinkReading {
        link_up: true,
        disabled: false,
        rx_missed: 0,
    })
}
struct State {
    now: u64,
    reading: Option<LinkReading>,
    sent: Vec<Vec<u8>>,
    to_peer: VecDeque<Vec<u8>>,
    incoming: VecDeque<Vec<u8>>,
    echo_advance: u64,
    echo_error: bool,
    receive_error: bool,
}
struct Mock(Rc<RefCell<State>>);
impl Link for Mock {
    fn mac(&self) -> [u8; 6] {
        MAC
    }
    fn now_ms(&self) -> u64 {
        self.0.borrow().now
    }
    fn read(&self) -> Option<LinkReading> {
        self.0.borrow().reading
    }
    fn pause(&self, ms: u64) {
        self.0.borrow_mut().now += ms;
    }
    fn send(&mut self, f: &[u8]) -> Result<(), i64> {
        let mut s = self.0.borrow_mut();
        s.sent.push(f.to_vec());
        s.to_peer.push_back(f.to_vec());
        if is_request(f) {
            s.now += s.echo_advance;
            if s.echo_error {
                return Err(-5);
            }
        }
        Ok(())
    }
    fn receive(&mut self, b: &mut [u8; FRAME_MAX], _: u64) -> Result<Option<usize>, i64> {
        let mut s = self.0.borrow_mut();
        if s.receive_error {
            return Err(-5);
        }
        match s.incoming.pop_front() {
            Some(f) => {
                b[..f.len()].copy_from_slice(&f);
                Ok(Some(f.len()))
            }
            None => Ok(None),
        }
    }
}
struct Rx(Vec<u8>);
impl smoltcp::phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
struct Tx(Rc<RefCell<State>>);
impl smoltcp::phy::TxToken for Tx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, n: usize, f: F) -> R {
        let mut b = vec![0; n];
        let r = f(&mut b);
        self.0.borrow_mut().incoming.push_back(b);
        r
    }
}
struct DevicePeer(Rc<RefCell<State>>);
impl Device for DevicePeer {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx;
    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx)> {
        let frame = self.0.borrow_mut().to_peer.pop_front()?;
        Some((Rx(frame), Tx(self.0.clone())))
    }
    fn transmit(&mut self, _: Instant) -> Option<Tx> {
        Some(Tx(self.0.clone()))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ethernet;
        c.max_transmission_unit = FRAME_MAX;
        c
    }
}
struct PeerEngine {
    iface: Interface,
    device: DevicePeer,
    sockets: SocketSet<'static>,
}
impl PeerEngine {
    fn new(s: Rc<RefCell<State>>) -> Self {
        let mut device = DevicePeer(s);
        let mut config = IfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(PEER_MAC)));
        config.random_seed = 7;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|a| {
            a.push(IpCidr::new(
                IpAddress::Ipv6(Ipv6Address::from(fixture_peer().ip)),
                64,
            ))
            .unwrap();
        });
        Self {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
        }
    }
    fn poll(&mut self) {
        let now = self.device.0.borrow().now;
        self.iface.poll(
            Instant::from_millis(now as i64),
            &mut self.device,
            &mut self.sockets,
        );
    }
}
fn unissued() -> (Rc<RefCell<State>>, Owner<Mock>) {
    let s = Rc::new(RefCell::new(State {
        now: 100,
        reading: up(),
        sent: Vec::new(),
        to_peer: VecDeque::new(),
        incoming: VecDeque::new(),
        echo_advance: 0,
        echo_error: false,
        receive_error: false,
    }));
    let owner = Owner::acquire(Mock(s.clone()), 100, |b| {
        b.fill(0);
        Ok::<_, ()>(())
    })
    .unwrap();
    (s, owner)
}
fn ready() -> (Rc<RefCell<State>>, Owner<Mock>, Endpoint, PeerEngine) {
    let (s, mut owner) = unissued();
    let endpoint = owner
        .grant(fixture_peer(), |b| {
            b.fill(1);
            Ok::<_, ()>(())
        })
        .unwrap();
    let peer = PeerEngine::new(s.clone());
    (s, owner, endpoint, peer)
}
fn is_request(f: &[u8]) -> bool {
    f.len() >= 55 && f[12..14] == [0x86, 0xdd] && f[20] == 58 && f[54] == 128
}
fn requests(s: &State) -> usize {
    s.sent.iter().filter(|f| is_request(f)).count()
}
fn drive(owner: &mut Owner<Mock>, e: Endpoint, peer: &mut PeerEngine) {
    for _ in 0..8 {
        owner.poll(e).unwrap();
        peer.poll();
    }
}
fn reply(owner: &Owner<Mock>) -> Vec<u8> {
    let a = owner.admission.borrow();
    let mut f = vec![0; 54 + PACKET_LEN];
    f[..6].copy_from_slice(&MAC);
    f[6..12].copy_from_slice(&PEER_MAC);
    f[12..15].copy_from_slice(&[0x86, 0xdd, 0x60]);
    f[18..22].copy_from_slice(&[0, 40, 58, 64]);
    f[22..38].copy_from_slice(&a.peer.ip);
    f[38..54].copy_from_slice(&a.local);
    f[54..].copy_from_slice(&a.packet);
    f[54] = 129;
    recalc(&mut f);
    f
}
fn recalc(f: &mut [u8]) {
    let src = Ipv6Address::from(<[u8; 16]>::try_from(&f[22..38]).unwrap());
    let dst = Ipv6Address::from(<[u8; 16]>::try_from(&f[38..54]).unwrap());
    Icmpv6Packet::new_unchecked(&mut f[54..]).fill_checksum(&src, &dst);
}
struct Stream {
    state: Rc<RefCell<State>>,
    input: VecDeque<u8>,
    output: Vec<u8>,
    limit: usize,
    read_advance: u64,
    write_advance: u64,
    error: bool,
    eof: bool,
    blocked: bool,
    calls: usize,
}
impl Stream {
    fn new(s: Rc<RefCell<State>>) -> Self {
        Self {
            state: s,
            input: VecDeque::new(),
            output: Vec::new(),
            limit: 64,
            read_advance: 0,
            write_advance: 0,
            error: false,
            eof: false,
            blocked: false,
            calls: 0,
        }
    }
    fn ask(&mut self, op: u8) {
        self.input.extend(request(op, fixture_peer()));
    }
}
impl Pipe for Stream {
    fn now_ms(&self) -> u64 {
        0
    } // Owner must resample actual Link, not this cached value.
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        self.calls += 1;
        let n = b.len().min(self.input.len()).min(self.limit);
        for v in &mut b[..n] {
            *v = self.input.pop_front().unwrap();
        }
        self.state.borrow_mut().now += self.read_advance;
        if self.error {
            Err(-5)
        } else if self.eof {
            Ok(Some(0))
        } else if n == 0 {
            Ok(None)
        } else {
            Ok(Some(n))
        }
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        self.calls += 1;
        let n = if self.blocked {
            0
        } else {
            b.len().min(self.limit)
        };
        self.output.extend_from_slice(&b[..n]);
        self.state.borrow_mut().now += self.write_advance;
        if self.error {
            Err(-5)
        } else if n == 0 {
            Ok(None)
        } else {
            Ok(Some(n))
        }
    }
}
#[test]
fn actual_engine_echo_roundtrip_resolves_nd_without_udp_authority_and_consumes_once() {
    let (s, mut o, e, mut p) = ready();
    assert!(
        o.dad
            .stack
            .as_ref()
            .unwrap()
            .port
            .ipv6_peers
            .iter()
            .all(Option::is_none)
    );
    assert_eq!(o.observe(e), Err(Error::Again));
    o.start(e, fixture_peer()).unwrap();
    drive(&mut o, e, &mut p);
    let observed = o.observe(e).unwrap();
    assert_eq!(observed.peer, fixture_peer());
    assert_ne!(observed.nonce, 0);
    assert_eq!(requests(&s.borrow()), 1);
    assert_eq!(o.socket_count(), 0);
    assert_eq!(o.observe(e), Err(Error::Spent));
    assert_eq!(o.start(e, fixture_peer()), Err(Error::Spent));
    assert_eq!(
        o.grant(fixture_peer(), |b| {
            b.fill(1);
            Ok::<_, ()>(())
        }),
        Err(Error::Exhausted)
    );
    let state = s.borrow();
    let wire = state.sent.iter().find(|f| is_request(f)).unwrap();
    assert_eq!(wire.len(), 94);
    assert_eq!(&wire[54..], &o.entry.as_ref().unwrap().packet);
    assert!(
        state
            .sent
            .iter()
            .any(|f| f.len() >= 55 && f[54] == 135 && f[22..38] != [0; 16])
    );
    drop(state);
    o.close(e).unwrap();
    assert_eq!(o.start(e, fixture_peer()), Err(Error::Stale));
}
#[test]
fn default_ingress_and_active_owner_refuse_incoming_echo_requests() {
    let (s, mut o, e, mut p) = ready();
    let mut f = reply(&o);
    f[54] = 128;
    recalc(&mut f);
    assert!(!crate::ipv6::ingress(
        &f,
        Some(Policy::fixture().config),
        &[Some(fixture_peer().ip)]
    ));
    let (plain_state, plain_owner) = unissued();
    plain_owner.admission.borrow_mut().retire();
    drop(plain_owner);
    plain_state.borrow_mut().sent.clear();
    plain_state.borrow_mut().to_peer.clear();
    let mut plain = Stack::open(Mock(plain_state.clone()), crate::Config::qemu_user()).unwrap();
    plain.configure_ipv6(Policy::fixture().config).unwrap();
    plain_state.borrow_mut().incoming.push_back(f.clone());
    plain.poll();
    assert!(plain_state.borrow().sent.is_empty());
    s.borrow_mut().incoming.push_back(f.clone());
    o.poll(e).unwrap();
    assert!(
        !s.borrow()
            .sent
            .iter()
            .any(|f| f.len() >= 55 && f[54] == 129)
    );
    assert!(!o.admission.borrow().submitted);
    o.start(e, fixture_peer()).unwrap();
    drive(&mut o, e, &mut p);
    s.borrow_mut().incoming.push_back(f);
    o.poll(e).unwrap();
    assert!(
        !s.borrow()
            .sent
            .iter()
            .any(|f| f.len() >= 55 && f[54] == 129)
    );
}
#[test]
fn exact_reply_admission_refuses_early_and_mutated_wire_fields() {
    let (_, mut o, e, _) = ready();
    let valid = reply(&o);
    assert!(!o.admission.borrow().accepts(&valid));
    o.start(e, fixture_peer()).unwrap();
    assert!(!o.admission.borrow().accepts(&valid));
    o.admission.borrow_mut().submitted = true;
    assert!(o.admission.borrow().accepts(&valid));
    for offset in [0, 6, 12, 14, 18, 20, 22, 38, 54, 55, 58, 60, 62, 70, 78, 86] {
        let mut f = valid.clone();
        f[offset] ^= if offset == 14 { 0x10 } else { 1 };
        if !matches!(offset, 12 | 14 | 18 | 20) {
            recalc(&mut f);
        }
        assert!(!o.admission.borrow().accepts(&f), "offset {offset}");
    }
    let mut f = valid.clone();
    f[56] ^= 1;
    assert!(!o.admission.borrow().accepts(&f));
    let mut f = valid.clone();
    f.push(0);
    assert!(!o.admission.borrow().accepts(&f));
    assert!(!o.admission.borrow().accepts(&valid[..93]));
    o.admission.borrow_mut().consumed = true;
    assert!(!o.admission.borrow().accepts(&valid));
}
#[test]
fn scope_peer_generation_entropy_and_slot_boundaries_refuse() {
    let (_, mut o, e, _) = ready();
    let mut wrong = fixture_peer();
    wrong.scope = 2;
    assert_eq!(o.start(e, wrong), Err(Error::Denied));
    wrong = fixture_peer();
    wrong.ip[15] = 3;
    assert_eq!(o.start(e, wrong), Err(Error::Denied));
    let counter = AtomicU64::new(u64::MAX);
    assert_eq!(reserve(&counter), Err(Error::Exhausted));
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    for failed in [false, true] {
        let (_, mut owner) = unissued();
        owner.next_epoch = u64::MAX;
        assert_eq!(
            owner.grant(fixture_peer(), |_| Ok::<_, ()>(())),
            Err(Error::Exhausted)
        );
        owner.next_epoch = 2;
        assert_eq!(
            owner.grant(fixture_peer(), |b| {
                b.fill(0);
                if failed { Err(()) } else { Ok(()) }
            }),
            Err(Error::Entropy)
        );
        assert!(owner.entry.is_none());
        assert_eq!(owner.socket_count(), 0);
    }
}
#[test]
fn uncertain_first_send_is_recorded_and_never_retried() {
    let (s, mut o, e, mut p) = ready();
    o.start(e, fixture_peer()).unwrap();
    s.borrow_mut().echo_error = true;
    for _ in 0..8 {
        p.poll();
        if o.poll(e).is_err() {
            break;
        }
    }
    assert_eq!(requests(&s.borrow()), 1);
    assert!(o.admission.borrow().submitted);
    assert_eq!(o.socket_count(), 0);
    assert!(o.start(e, fixture_peer()).is_err());
    assert!(o.poll(e).is_err());
    assert_eq!(requests(&s.borrow()), 1);
}
#[test]
fn send_straddling_stop_retains_first_effect_and_retires() {
    let (s, mut o, e, mut p) = ready();
    o.start(e, fixture_peer()).unwrap();
    {
        let mut state = s.borrow_mut();
        state.now = o.stop_ms() - 1;
        state.echo_advance = 2;
    }
    for _ in 0..8 {
        p.poll();
        if o.poll(e).is_err() {
            break;
        }
    }
    assert_eq!(requests(&s.borrow()), 1);
    assert_eq!(o.socket_count(), 0);
    assert!(o.poll(e).is_err());
}
#[test]
fn queued_data_is_fenced_on_expiry_rewind_link_rx_loss_and_receive_error() {
    for mode in 0..8 {
        let (s, mut o, e, _) = ready();
        o.start(e, fixture_peer()).unwrap();
        {
            let mut state = s.borrow_mut();
            match mode {
                0 => state.now = o.stop_ms(),
                1 => state.now = 99,
                2 => state.reading = None,
                3 => state.reading.as_mut().unwrap().link_up = false,
                4 => state.reading.as_mut().unwrap().disabled = true,
                5 => state.reading.as_mut().unwrap().rx_missed = 1,
                6 => state.receive_error = true,
                _ => o.dad.stack.as_mut().unwrap().ipv6_fence(),
            }
        }
        assert!(o.poll(e).is_err(), "mode {mode}");
        assert_eq!(o.socket_count(), 0);
        assert_eq!(requests(&s.borrow()), 0);
    }
}
#[test]
fn pending_observation_cannot_escape_close_fault_or_successor_owner() {
    for mode in 0..4 {
        let (s, mut o, e, mut p) = ready();
        o.start(e, fixture_peer()).unwrap();
        drive(&mut o, e, &mut p);
        let mut c = Channel::new(&mut o, e).unwrap();
        let mut io = Stream::new(s.clone());
        io.ask(OBSERVE);
        assert!(c.poll(&mut o, &mut io));
        assert_eq!(c.output[2], 0);
        assert!(c.pending);
        if mode == 3 {
            let (_, mut fresh, fresh_ep, _) = ready();
            assert!(!c.poll(&mut fresh, &mut io));
            assert!(fresh.live(fresh_ep).is_ok());
        } else {
            match mode {
                0 => o.close(e).unwrap(),
                1 => s.borrow_mut().reading = None,
                _ => s.borrow_mut().now = o.stop_ms(),
            }
            assert!(!c.poll(&mut o, &mut io));
        }
        assert!(io.output.is_empty());
    }
}
#[test]
fn delayed_first_partial_or_full_read_eof_and_uncertain_read_never_start() {
    for mode in 0..5 {
        let (s, mut o, e, _) = ready();
        let mut c = Channel::new(&mut o, e).unwrap();
        let mut io = Stream::new(s.clone());
        io.ask(START);
        match mode {
            0 => {
                io.limit = 1;
                io.read_advance = 250;
            }
            1 => io.read_advance = 250,
            2 => io.eof = true,
            3 => io.error = true,
            _ => {
                io.limit = 1;
            }
        }
        if mode == 4 {
            assert!(c.poll(&mut o, &mut io));
            s.borrow_mut().now += 250;
        }
        assert!(!c.poll(&mut o, &mut io));
        assert_eq!(o.socket_count(), 0);
        assert_eq!(requests(&s.borrow()), 0);
        assert!(!o.admission.borrow().armed);
    }
}
#[test]
fn final_write_crossing_frame_or_owner_boundary_retains_only_possible_effect() {
    for stop in [false, true] {
        let (s, mut o, e, _) = ready();
        let mut c = Channel::new(&mut o, e).unwrap();
        let mut io = Stream::new(s.clone());
        io.ask(START);
        if stop {
            s.borrow_mut().now = o.stop_ms() - 1;
        }
        assert!(c.poll(&mut o, &mut io));
        assert!(c.pending);
        let frame_deadline = c.deadline.unwrap();
        assert!(s.borrow().now < frame_deadline);
        assert!(s.borrow().now < o.stop_ms());
        if stop {
            io.write_advance = 2;
        } else {
            io.write_advance = 250;
        }
        assert!(!c.poll(&mut o, &mut io));
        assert_eq!(io.output.len(), 64);
        if stop {
            assert!(s.borrow().now >= o.stop_ms());
            assert!(s.borrow().now < frame_deadline);
        }
        assert_eq!(o.socket_count(), 0);
        let written = io.output.clone();
        assert!(!c.poll(&mut o, &mut io));
        assert_eq!(io.output, written);
    }
}
#[test]
fn expired_pending_frame_before_owner_stop_refuses_without_pipe_or_network_effect() {
    let (s, mut o, e, _) = ready();
    let mut c = Channel::new(&mut o, e).unwrap();
    let mut io = Stream::new(s.clone());
    io.ask(START);
    assert!(c.poll(&mut o, &mut io));
    assert!(c.pending);
    s.borrow_mut().now = o.stop_ms() - 1;
    assert!(c.deadline.unwrap() <= s.borrow().now);
    assert!(s.borrow().now < o.stop_ms());
    let calls = io.calls;
    let sent = s.borrow().sent.len();
    assert!(!c.poll(&mut o, &mut io));
    assert_eq!(io.calls, calls);
    assert!(io.output.is_empty());
    assert_eq!(s.borrow().sent.len(), sent);
    assert_eq!(requests(&s.borrow()), 0);
    assert_eq!(o.socket_count(), 0);
    assert!(!c.poll(&mut o, &mut io));
    assert_eq!(io.calls, calls);
    assert_eq!(s.borrow().sent.len(), sent);
}
#[test]
fn blocked_partial_and_closing_responses_are_bounded_and_close_ack_is_empty() {
    for mode in 0..3 {
        let (s, mut o, e, _) = ready();
        let mut c = Channel::new(&mut o, e).unwrap();
        let mut io = Stream::new(s.clone());
        io.ask(CLOSE);
        assert!(c.poll(&mut o, &mut io));
        assert_eq!(o.socket_count(), 0);
        if mode == 0 {
            assert!(!c.poll(&mut o, &mut io));
            assert_eq!(io.output[..4], [1, 3, 0, 6]);
            assert_eq!(io.output[4..], [0; 60]);
        } else {
            if mode == 1 {
                io.blocked = true;
            } else {
                io.limit = 1;
            }
            assert!(c.poll(&mut o, &mut io));
            s.borrow_mut().now += 250;
            assert!(!c.poll(&mut o, &mut io));
        }
        assert!(o.entry.is_none());
    }
}
#[test]
fn active_dad_conflict_and_defense_quota_retire_echo_authority() {
    for conflict in [true, false] {
        let (s, mut o, e, _) = ready();
        if conflict {
            s.borrow_mut().incoming.push_back(super::super::packet(
                Policy::fixture(),
                PEER_MAC,
                true,
            ));
            assert!(o.poll(e).is_err());
        } else {
            for index in 0..5 {
                s.borrow_mut().now += 1000;
                s.borrow_mut().incoming.push_back(super::super::packet(
                    Policy::fixture(),
                    PEER_MAC,
                    false,
                ));
                let result = o.poll(e);
                if index < 4 {
                    assert!(result.is_ok());
                } else {
                    assert!(result.is_err());
                }
            }
        }
        assert_eq!(o.socket_count(), 0);
        assert!(o.start(e, fixture_peer()).is_err());
    }
}
#[test]
fn literal_framing_bootstrap_and_observation_vectors_refuse_family_substitution() {
    assert_eq!(
        request(START, fixture_peer()),
        [
            1, 1, 0, 6, 0xfd, 0, 0xab, 0x5d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1
        ]
    );
    let observation = Observation {
        peer: fixture_peer(),
        identifier: 0x1234,
        sequence: 0x5678,
        instance: 1,
        epoch: 2,
        nonce: 0x0102030405060708,
        boot_elapsed_ms: 9,
    };
    let mut expected = [
        1, 2, 0, 6, 0xfd, 0, 0xab, 0x5d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 0x12,
        0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8,
        0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0,
    ];
    let mut bytes = [0; 64];
    bytes[..4].copy_from_slice(&[1, 2, 0, 6]);
    encode(observation, &mut bytes);
    assert_eq!(bytes, expected);
    assert_eq!(decode(&bytes, fixture_peer()), Ok(observation));
    expected[3] = 0;
    assert_eq!(decode(&expected, fixture_peer()), Err(Error::Invalid));
    let (s, mut o, _, _) = ready();
    let mut boot = o.bootstrap().unwrap();
    assert_eq!(
        boot,
        [
            1, 6, 0, 0, 0xfd, 0, 0xab, 0x5d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0,
            0, 0, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0x23, 0x8c
        ]
    );
    assert_eq!(
        decode_bootstrap(&boot, s.borrow().now).unwrap().0,
        fixture_peer()
    );
    boot[1] = 0;
    assert_eq!(decode_bootstrap(&boot, s.borrow().now), Err(Error::Denied));
}
#[test]
fn client_transfer_budget_and_uncertain_first_write_do_not_retry() {
    let (s, _, _, _) = ready();
    let mut io = Stream::new(s);
    io.blocked = true;
    let mut last = 0;
    assert_eq!(
        transact(&mut io, &request(START, fixture_peer()), 1000, &mut last),
        Err(-110)
    );
    assert_eq!(io.calls, MAX_TRANSFERS);
    io.calls = 0;
    io.blocked = false;
    io.error = true;
    assert_eq!(
        transact(&mut io, &request(START, fixture_peer()), 1000, &mut last),
        Err(-5)
    );
    assert_eq!(io.calls, 1);
    assert_eq!(io.output.len(), 24);
}
#[test]
fn one_channel_per_grant_and_wait_error_retire_all_owned_state() {
    let (s, mut o, e, _) = ready();
    let mut c = Channel::new(&mut o, e).unwrap();
    assert!(matches!(Channel::new(&mut o, e), Err(Error::Exhausted)));
    let mut io = Stream::new(s.clone());
    io.ask(START);
    assert!(c.poll(&mut o, &mut io));
    assert!(c.pending);
    s.borrow_mut().receive_error = true;
    assert!(o.wait().is_err());
    assert!(o.entry.is_none());
    assert!(!o.admission.borrow().live);
    assert_eq!(o.socket_count(), 0);
    assert!(!c.poll(&mut o, &mut io));
    assert!(io.output.is_empty());
    assert!(matches!(Channel::new(&mut o, e), Err(Error::Stale)));
}
#[test]
fn no_progress_read_crossing_partial_frame_or_original_stop_refuses() {
    for partial in [true, false] {
        let (s, mut o, e, _) = ready();
        let mut c = Channel::new(&mut o, e).unwrap();
        let mut io = Stream::new(s.clone());
        if partial {
            io.input.push_back(1);
            assert!(c.poll(&mut o, &mut io));
            io.read_advance = 250;
        } else {
            s.borrow_mut().now = o.stop_ms() - 1;
            io.read_advance = 2;
        }
        assert!(!c.poll(&mut o, &mut io));
        assert_eq!(requests(&s.borrow()), 0);
        assert_eq!(o.socket_count(), 0);
    }
}
fn exchange(
    o: &mut Owner<Mock>,
    c: &mut Channel,
    io: &mut Stream,
    peer: &mut PeerEngine,
    op: u8,
    address: Peer,
) -> ([u8; RESPONSE_LEN], bool) {
    let begin = io.output.len();
    io.input.extend(request(op, address));
    for _ in 0..32 {
        let live = c.poll(o, io);
        peer.poll();
        if io.output.len() == begin + RESPONSE_LEN {
            return (io.output[begin..].try_into().unwrap(), live);
        }
        assert!(live);
    }
    panic!("issued channel did not finish bounded transaction")
}
#[test]
fn issued_channel_denial_engine_observation_spent_and_empty_close_compose() {
    let (s, mut o, e, mut peer) = ready();
    let mut c = Channel::new(&mut o, e).unwrap();
    let mut io = Stream::new(s.clone());
    let mut wrong = fixture_peer();
    wrong.scope += 1;
    let (denied, live) = exchange(&mut o, &mut c, &mut io, &mut peer, START, wrong);
    assert!(live);
    assert_eq!(denied[2], Error::Denied.code());
    assert_eq!(denied[4..], [0; 60]);
    assert_eq!(requests(&s.borrow()), 0);
    let (started, live) = exchange(&mut o, &mut c, &mut io, &mut peer, START, fixture_peer());
    assert!(live);
    assert_eq!(started[..4], [1, 1, 0, 6]);
    let mut result = None;
    for _ in 0..8 {
        let (reply, live) = exchange(&mut o, &mut c, &mut io, &mut peer, OBSERVE, fixture_peer());
        assert!(live);
        if reply[2] == 0 {
            result = Some(decode(&reply, fixture_peer()).unwrap());
            break;
        }
        assert_eq!(reply[2], Error::Again.code());
    }
    assert_eq!(result.unwrap().instance, e.instance);
    assert_eq!(requests(&s.borrow()), 1);
    let (spent, _) = exchange(&mut o, &mut c, &mut io, &mut peer, OBSERVE, fixture_peer());
    assert_eq!(spent[2], Error::Spent.code());
    let (closed, live) = exchange(&mut o, &mut c, &mut io, &mut peer, CLOSE, fixture_peer());
    assert!(!live);
    assert_eq!(closed[..4], [1, 3, 0, 6]);
    assert_eq!(closed[4..], [0; 60]);
    assert_eq!(o.socket_count(), 0);
    assert!(o.entry.is_none());
    assert!(!o.admission.borrow().live);
}
#[test]
fn expired_pending_start_ack_cannot_dispatch_after_queued_neighbor_advertisement() {
    let (s, mut o, e, mut peer) = ready();
    let mut c = Channel::new(&mut o, e).unwrap();
    let mut io = Stream::new(s.clone());
    io.ask(START);
    assert!(c.poll(&mut o, &mut io));
    assert!(c.pending);
    assert!(o.entry.as_ref().unwrap().start.is_some());
    io.blocked = true;
    // A live pre-expiry poll emits NS while leaving START's ACK blocked.
    assert!(c.poll(&mut o, &mut io));
    peer.poll();
    assert!(
        s.borrow().incoming.iter().any(|f| f.len() >= 78
            && f[20] == 58
            && f[54] == 136
            && f[62..78] == fixture_peer().ip)
    );
    assert_eq!(requests(&s.borrow()), 0);
    assert!(io.output.is_empty());
    let deadline = c.deadline.unwrap();
    assert!(s.borrow().now < deadline && deadline < o.stop_ms());
    s.borrow_mut().now = deadline;
    // Old ordering could ingest NA then dispatch Echo before the frame check.
    // This regression and its pre-fix counterexample remain UNEXECUTED.
    assert!(!c.poll(&mut o, &mut io));
    assert_eq!(requests(&s.borrow()), 0);
    assert!(io.output.is_empty());
    assert_eq!(o.socket_count(), 0);
    assert!(o.entry.is_none());
    assert!(!c.pending);
}
