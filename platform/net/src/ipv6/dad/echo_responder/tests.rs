//! The protocol peer is a separate unfiltered pinned smoltcp instance.
//! Literal substitutions exercise authority; Linux interoperability is later.
use super::*;
use smoltcp::{
    iface::{Config as IfaceConfig, Interface, SocketSet},
    phy::{Device, DeviceCapabilities, Medium},
    socket::icmp,
    time::Instant,
    wire::{EthernetAddress, HardwareAddress, IpCidr},
};
const MAC: [u8; 6] = [0x52, 0x54, 0, 0xab, 0x5d, 0x15];
const REMOTE: [u8; 6] = [0x52, 0x55, 0, 0, 2, 2];
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
    incoming: VecDeque<Vec<u8>>,
    to_peer: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
    send_error: bool,
    send_advance: u64,
    receive_error: bool,
    receive_advance: u64,
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
    fn send(&mut self, frame: &[u8]) -> Result<(), i64> {
        let mut s = self.0.borrow_mut();
        s.sent.push(frame.to_vec());
        s.to_peer.push_back(frame.to_vec());
        if reply(frame) {
            s.now += s.send_advance;
            if s.send_error {
                return Err(-5);
            }
        }
        Ok(())
    }
    fn receive(&mut self, bytes: &mut [u8; FRAME_MAX], _: u64) -> Result<Option<usize>, i64> {
        let mut s = self.0.borrow_mut();
        s.now += s.receive_advance;
        if s.receive_error {
            return Err(-5);
        }
        Ok(s.incoming.pop_front().map(|frame| {
            bytes[..frame.len()].copy_from_slice(&frame);
            frame.len()
        }))
    }
}
fn state() -> Rc<RefCell<State>> {
    Rc::new(RefCell::new(State {
        now: 100,
        reading: up(),
        incoming: VecDeque::new(),
        to_peer: VecDeque::new(),
        sent: Vec::new(),
        send_error: false,
        send_advance: 0,
        receive_error: false,
        receive_advance: 0,
    }))
}
fn acquired() -> (Rc<RefCell<State>>, Owner<Mock>) {
    let s = state();
    let owner = Owner::acquire(Mock(s.clone()), 100, |b| {
        b.fill(0);
        Ok::<_, ()>(())
    })
    .unwrap();
    (s, owner)
}
fn active() -> (Rc<RefCell<State>>, Owner<Mock>, Endpoint) {
    let (s, mut owner) = acquired();
    let endpoint = owner.activate(fixture_peer()).unwrap();
    (s, owner, endpoint)
}
fn reply(frame: &[u8]) -> bool {
    frame.len() >= 62 && frame[12..14] == [0x86, 0xdd] && frame[20] == 58 && frame[54] == 129
}
fn checksum(frame: &mut [u8]) {
    let source = Ipv6Address::from(<[u8; 16]>::try_from(&frame[22..38]).unwrap());
    let dest = Ipv6Address::from(<[u8; 16]>::try_from(&frame[38..54]).unwrap());
    Icmpv6Packet::new_unchecked(&mut frame[54..]).fill_checksum(&source, &dest);
}
fn request(data: &[u8], id: u16, seq: u16) -> Vec<u8> {
    let mut f = vec![0; 62 + data.len()];
    f[..6].copy_from_slice(&MAC);
    f[6..12].copy_from_slice(&REMOTE);
    f[12..18].copy_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
    f[18..20].copy_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    f[20] = 58;
    f[21] = 64;
    f[22..38].copy_from_slice(&fixture_peer().ip);
    f[38..54].copy_from_slice(&Policy::fixture().config.address);
    f[54] = 128;
    f[58..60].copy_from_slice(&id.to_be_bytes());
    f[60..62].copy_from_slice(&seq.to_be_bytes());
    f[62..].copy_from_slice(data);
    checksum(&mut f);
    f
}
fn inject(s: &Rc<RefCell<State>>, frame: Vec<u8>) {
    s.borrow_mut().incoming.push_back(frame);
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
        let mut bytes = vec![0; n];
        let result = f(&mut bytes);
        self.0.borrow_mut().incoming.push_back(bytes);
        result
    }
}
struct DevicePeer(Rc<RefCell<State>>);
impl Device for DevicePeer {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx;
    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx)> {
        let f = self.0.borrow_mut().to_peer.pop_front()?;
        Some((Rx(f), Tx(self.0.clone())))
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
    handle: smoltcp::iface::SocketHandle,
}
impl PeerEngine {
    fn new(s: Rc<RefCell<State>>, id: u16) -> Self {
        let mut device = DevicePeer(s);
        let mut config = IfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(REMOTE)));
        config.random_seed = 7;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|ips| {
            ips.push(IpCidr::new(
                IpAddress::Ipv6(Ipv6Address::from(fixture_peer().ip)),
                64,
            ))
            .unwrap();
        });
        let buffer =
            || icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY], vec![0; MAX_PACKET]);
        let mut socket = icmp::Socket::new(buffer(), buffer());
        socket.bind(icmp::Endpoint::Ident(id)).unwrap();
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(socket);
        Self {
            iface,
            device,
            sockets,
            handle,
        }
    }
    fn send(&mut self, packet: &[u8]) {
        self.sockets
            .get_mut::<icmp::Socket>(self.handle)
            .send_slice(
                packet,
                IpAddress::Ipv6(Ipv6Address::from(Policy::fixture().config.address)),
            )
            .unwrap();
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
fn drive(
    s: &Rc<RefCell<State>>,
    owner: &mut Owner<Mock>,
    endpoint: Endpoint,
    peer: &mut PeerEngine,
) {
    for _ in 0..30 {
        peer.poll();
        owner.poll(endpoint).unwrap();
        peer.poll();
        s.borrow_mut().now += 2;
    }
}
fn peer_ns(frame: &[u8]) -> bool {
    frame.len() >= 78
        && frame[12..14] == [0x86, 0xdd]
        && frame[20] == 58
        && frame[54] == 135
        && frame[62..78] == fixture_peer().ip
}
fn solicitation() -> Vec<u8> {
    // Genuine ordinary NS with SLLA gives the engine the peer MAC, without
    // consuming the application activation. The engine supplies its NA.
    let mut ns = request(&[0; 24], 0, 0);
    ns.truncate(86);
    ns[18..20].copy_from_slice(&32u16.to_be_bytes());
    ns[54..].fill(0);
    ns[54] = 135;
    ns[62..78].copy_from_slice(&Policy::fixture().config.address);
    ns[78..80].copy_from_slice(&[1, 1]);
    ns[80..86].copy_from_slice(&REMOTE);
    ns[21] = 255;
    checksum(&mut ns);
    ns
}
fn warm_stack<L: Link>(s: &Rc<RefCell<State>>, stack: &mut Stack<L>) {
    inject(s, solicitation());
    stack.poll();
    assert!(
        s.borrow()
            .sent
            .iter()
            .any(|f| f.len() >= 78 && f[54] == 136)
    );
    assert!(!s.borrow().sent.iter().any(|f| peer_ns(f)));
    s.borrow_mut().sent.clear();
}
fn warm(s: &Rc<RefCell<State>>, owner: &mut Owner<Mock>, endpoint: Endpoint) {
    inject(s, solicitation());
    owner.poll(endpoint).unwrap();
    assert!(
        s.borrow()
            .sent
            .iter()
            .any(|f| f.len() >= 78 && f[54] == 136)
    );
    assert!(!s.borrow().sent.iter().any(|f| peer_ns(f)));
    s.borrow_mut().sent.clear();
}

#[test]
fn actual_engine_request_reply_mirrors_linux_sized_message_once() {
    let (s, mut owner, e) = active();
    let mut peer = PeerEngine::new(s.clone(), 0x1234);
    let f = request(&[0xa5; 56], 0x1234, 7);
    peer.send(&f[54..]);
    drive(&s, &mut owner, e, &mut peer);
    let (bytes, ip) = peer
        .sockets
        .get_mut::<icmp::Socket>(peer.handle)
        .recv()
        .unwrap();
    assert_eq!(
        ip,
        IpAddress::Ipv6(Ipv6Address::from(Policy::fixture().config.address))
    );
    assert_eq!(&bytes[4..], &f[58..]);
    assert_eq!(bytes[0], 129);
    let report = owner.observe(e).unwrap();
    assert_eq!(
        (report.identifier, report.sequence, report.icmp_bytes),
        (0x1234, 7, 64)
    );
    assert_eq!(owner.observe(e), Err(Error::Spent));
    assert_eq!(owner.possible_reply_effects(), 1);
    assert_eq!(owner.socket_count(), 0);
    peer.send(&f[54..]);
    drive(&s, &mut owner, e, &mut peer);
    assert_eq!(s.borrow().sent.iter().filter(|f| reply(f)).count(), 1);
}
#[test]
fn header_only_zero_identifiers_and_maximum_packet_use_actual_engine() {
    for len in [0, MAX_PACKET - 8] {
        let (s, mut owner, e) = active();
        let mut peer = PeerEngine::new(s.clone(), 0);
        let f = request(&vec![0x6b; len], 0, 0);
        peer.send(&f[54..]);
        drive(&s, &mut owner, e, &mut peer);
        let (bytes, _) = peer
            .sockets
            .get_mut::<icmp::Socket>(peer.handle)
            .recv()
            .unwrap();
        assert_eq!(bytes.len(), 8 + len);
        assert_eq!(&bytes[4..], &f[58..]);
        assert_eq!(owner.observe(e).unwrap().icmp_bytes as usize, 8 + len);
    }
}
#[test]
fn default_stack_and_acquired_but_inactive_owner_refuse_requests() {
    let s = state();
    let mut stack = Stack::open(Mock(s.clone()), crate::Config::qemu_user()).unwrap();
    stack.configure_ipv6(Policy::fixture().config).unwrap();
    warm_stack(&s, &mut stack);
    inject(&s, request(b"default", 1, 1));
    stack.poll();
    assert!(!s.borrow().sent.iter().any(|f| reply(f)));
    assert!(!s.borrow().sent.iter().any(|f| peer_ns(f)));
    let (s, mut owner) = acquired();
    warm_stack(&s, owner.dad.stack.as_mut().unwrap());
    inject(&s, request(b"inactive", 1, 1));
    owner.dad.stack.as_mut().unwrap().poll();
    owner.check().unwrap();
    assert!(!s.borrow().sent.iter().any(|f| reply(f)));
    assert!(!s.borrow().sent.iter().any(|f| peer_ns(f)));
    assert!(!owner.issued);
}
#[test]
fn invalid_scope_does_not_consume_one_owner_activation() {
    let (_, mut owner) = acquired();
    let mut peer = fixture_peer();
    peer.scope += 1;
    assert_eq!(owner.activate(peer), Err(Error::Denied));
    let e = owner.activate(fixture_peer()).unwrap();
    assert_eq!(owner.activate(fixture_peer()), Err(Error::Exhausted));
    owner.retire();
    assert_eq!(owner.observe(e), Err(Error::Stale));
    assert!(owner.activate(fixture_peer()).is_err());
}
#[test]
fn identity_and_generation_exhaustion_refuse_without_wraparound() {
    let counter = AtomicU64::new(u64::MAX);
    assert_eq!(reserve(&counter), Err(Error::Exhausted));
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    let (_, mut owner) = acquired();
    owner.next_generation = u64::MAX;
    assert_eq!(owner.activate(fixture_peer()), Err(Error::Exhausted));
    assert!(!owner.issued);
    assert!(!owner.admission.borrow().live);
}
#[test]
fn malformed_and_off_peer_frames_cannot_consume_or_expand_authority() {
    let good = request(b"body", 1, 2);
    for which in 0..16 {
        let (_, owner, _) = active();
        let mut bad = good.clone();
        match which {
            0 => bad[22] = 0xff,
            1 => bad[37] = 3,
            2 => bad[53] = 16,
            3 => bad[0] ^= 1,
            4 => bad[6] |= 1,
            5 => bad[6..12].fill(0),
            6 => bad[20] = 44,
            7 => bad[20] = 0,
            8 => bad[55] = 1,
            9 => bad[56] ^= 1,
            10 => {
                bad.pop();
            }
            11 => bad.push(0),
            12 => bad[21] = 0,
            13 => {
                bad.truncate(61);
                bad[18..20].copy_from_slice(&7u16.to_be_bytes());
            }
            14 => bad[6..12].copy_from_slice(&MAC),
            15 => bad[54] = 129,
            _ => unreachable!(),
        }
        if !matches!(which, 9 | 10 | 11) {
            checksum(&mut bad);
        }
        assert!(!owner.admission.borrow_mut().admit(&bad), "case {which}");
        assert!(owner.admission.borrow_mut().admit(&good));
    }
    let (_, owner, _) = active();
    assert!(
        !owner
            .admission
            .borrow_mut()
            .admit(&request(&vec![1; MAX_PACKET - 7], 1, 1))
    );
}
#[test]
fn later_requests_cannot_overwrite_pending_or_submitted_correlation() {
    let (s, mut owner, e) = active();
    warm(&s, &mut owner, e);
    let first = request(b"first", 42, 7);
    inject(&s, first.clone());
    inject(&s, request(b"other", 43, 8));
    owner.poll(e).unwrap();
    inject(&s, request(b"again", 44, 9));
    owner.poll(e).unwrap();
    let report = owner.observe(e).unwrap();
    assert_eq!((report.identifier, report.sequence), (42, 7));
    let sent = s.borrow();
    let replies: Vec<_> = sent.sent.iter().filter(|f| reply(f)).collect();
    assert_eq!(replies.len(), 1);
    assert_eq!(&replies[0][58..], &first[58..]);
}
#[test]
fn uncertain_send_records_possible_first_effect_then_never_replays() {
    let (s, mut owner, e) = active();
    warm(&s, &mut owner, e);
    s.borrow_mut().send_error = true;
    inject(&s, request(b"one", 1, 1));
    assert_eq!(owner.poll(e), Err(Error::Interrupted));
    assert_eq!(owner.possible_reply_effects(), 1);
    assert_eq!(owner.socket_count(), 0);
    assert!(owner.observe(e).is_err());
    s.borrow_mut().send_error = false;
    inject(&s, request(b"two", 2, 2));
    assert!(owner.poll(e).is_err());
    assert_eq!(s.borrow().sent.iter().filter(|f| reply(f)).count(), 1);
}
#[test]
fn send_straddling_owner_deadline_retains_first_effect_but_no_observation() {
    let (s, mut owner, e) = active();
    warm(&s, &mut owner, e);
    let advance = owner.stop_ms() - s.borrow().now;
    s.borrow_mut().send_advance = advance;
    inject(&s, request(b"late", 1, 1));
    assert!(owner.poll(e).is_err());
    assert_eq!(owner.possible_reply_effects(), 1);
    assert_eq!(s.borrow().sent.iter().filter(|f| reply(f)).count(), 1);
    assert!(owner.observe(e).is_err());
    assert!(owner.poll(e).is_err());
}
#[test]
fn queued_request_expires_before_dispatch_without_reply_effect() {
    let (s, mut owner, e) = active();
    warm(&s, &mut owner, e);
    inject(&s, request(b"queued", 1, 1));
    owner.wait().unwrap();
    assert!(owner.admission.borrow().request.is_some());
    s.borrow_mut().now = owner.stop_ms();
    assert!(owner.poll(e).is_err());
    assert_eq!(owner.possible_reply_effects(), 0);
    assert!(!s.borrow().sent.iter().any(|f| reply(f)));
}
#[test]
fn expiry_rewind_link_disable_and_rx_loss_retire_before_new_submission() {
    for which in 0..5 {
        let (s, mut owner, e) = active();
        warm(&s, &mut owner, e);
        inject(&s, request(b"blocked", 1, 1));
        match which {
            0 => s.borrow_mut().now = owner.stop_ms(),
            1 => s.borrow_mut().now = 0,
            2 => s.borrow_mut().reading = None,
            3 => s.borrow_mut().reading.as_mut().unwrap().disabled = true,
            4 => s.borrow_mut().reading.as_mut().unwrap().rx_missed += 1,
            _ => unreachable!(),
        }
        assert!(owner.poll(e).is_err());
        assert_eq!(owner.possible_reply_effects(), 0);
        assert_eq!(owner.socket_count(), 0);
    }
}
#[test]
fn receive_crossing_deadline_and_receive_error_fence_pending_authority() {
    for error in [false, true] {
        let (s, mut owner, e) = active();
        inject(&s, request(b"read", 1, 1));
        if error {
            s.borrow_mut().receive_error = true;
        } else {
            let advance = owner.stop_ms() - s.borrow().now;
            s.borrow_mut().receive_advance = advance;
        }
        assert!(owner.wait().is_err());
        assert_eq!(owner.endpoint, None);
        assert_eq!(owner.possible_reply_effects(), 0);
        assert!(owner.poll(e).is_err());
    }
}
#[test]
fn fresh_owner_cannot_use_stale_endpoint_or_retained_pending_request() {
    let (s, mut old, e) = active();
    inject(&s, request(b"old", 1, 1));
    old.wait().unwrap();
    old.retire();
    assert!(old.admission.borrow().request.is_none());
    let (_, mut fresh, f) = active();
    assert_ne!(e, f);
    assert_eq!(fresh.poll(e), Err(Error::Stale));
    assert_eq!(fresh.observe(f), Err(Error::Again));
    assert_eq!(fresh.possible_reply_effects(), 0);
}
#[test]
fn explicit_retirement_and_drop_remove_admission_and_pending_reply() {
    let (s, mut owner, e) = active();
    inject(&s, request(b"drop", 1, 1));
    owner.wait().unwrap();
    let admission = owner.admission.clone();
    drop(owner);
    assert!(!admission.borrow().live);
    assert!(admission.borrow().request.is_none());
    assert!(!s.borrow().sent.iter().any(|f| reply(f)));
    let (_, mut other, _) = active();
    assert_eq!(other.poll(e), Err(Error::Stale));
}
#[test]
fn active_dad_defense_and_quota_remain_under_original_guard() {
    let (s, mut owner, e) = active();
    let mut probe = packet(Policy::fixture(), REMOTE, false);
    probe[6..12].copy_from_slice(&REMOTE);
    for _ in 0..MAX_DEFENSES {
        inject(&s, probe.clone());
        owner.poll(e).unwrap();
        s.borrow_mut().now += OBSERVE_MS;
    }
    assert_eq!(owner.observations().defenses_submitted, MAX_DEFENSES);
    inject(&s, probe);
    assert!(owner.poll(e).is_err());
    assert_eq!(owner.possible_reply_effects(), 0);
}
#[test]
fn tentative_conflict_and_active_conflict_never_enable_response() {
    let s = state();
    let mut na = packet(Policy::fixture(), REMOTE, true);
    na[6..12].copy_from_slice(&REMOTE);
    inject(&s, na.clone());
    assert!(matches!(
        Owner::acquire(Mock(s.clone()), 100, |b| {
            b.fill(0);
            Ok::<_, ()>(())
        }),
        Err(Error::Dad(super::super::Error::Conflict))
    ));
    assert!(!s.borrow().sent.iter().any(|f| reply(f)));
    let (s, mut owner, e) = active();
    warm(&s, &mut owner, e);
    inject(&s, na);
    inject(&s, request(b"conflict", 1, 1));
    assert!(owner.poll(e).is_err());
    assert_eq!(owner.possible_reply_effects(), 0);
    assert!(!s.borrow().sent.iter().any(|f| reply(f) || peer_ns(f)));
}

#[test]
fn uncached_peer_drops_reply_and_later_na_cannot_rearm_the_grant() {
    let (s, mut owner, e) = active();
    let first = request(b"uncached", 51, 2);
    inject(&s, first.clone());
    owner.poll(e).unwrap();
    assert!(s.borrow().sent.iter().any(|f| peer_ns(f)));
    assert!(!s.borrow().sent.iter().any(|f| reply(f)));
    assert_eq!(owner.observe(e), Err(Error::Again));
    assert_eq!(owner.possible_reply_effects(), 0);

    let mut na = solicitation();
    na[54] = 136;
    na[58] = 0x60; // Solicited + Override; target is this exact peer.
    na[62..78].copy_from_slice(&fixture_peer().ip);
    na[78] = 2;
    checksum(&mut na);
    inject(&s, na);
    owner.poll(e).unwrap();
    inject(&s, first.clone());
    owner.poll(e).unwrap();
    assert!(!s.borrow().sent.iter().any(|f| reply(f)));
    assert_eq!(owner.observe(e), Err(Error::Again));
    assert_eq!(
        owner.admission.borrow().request.as_deref(),
        Some(&first[54..])
    );
    assert_eq!(owner.activate(fixture_peer()), Err(Error::Exhausted));
    let stop = owner.stop_ms();
    s.borrow_mut().now = stop;
    assert_eq!(owner.poll(e), Err(Error::Dad(super::super::Error::Timeout)));
    assert_eq!(owner.possible_reply_effects(), 0);
    assert_eq!(owner.socket_count(), 0);
}
#[test]
fn outbound_other_protocol_and_uncorrelated_reply_are_refused() {
    let (_, owner, _) = active();
    let mut a = owner.admission.borrow_mut();
    let mut wrong = request(b"bad", 1, 1);
    assert_eq!(a.sending(&wrong), Err(Error::Denied));
    drop(a);
    let (_, owner, _) = active();
    assert!(owner.admission.borrow_mut().admit(&request(b"right", 1, 1)));
    wrong[54] = 129;
    checksum(&mut wrong);
    assert_eq!(
        owner.admission.borrow_mut().sending(&wrong),
        Err(Error::Denied)
    );
    assert!(!owner.admission.borrow().attempted);
}
