//! Deterministic source controls; independent Linux qualification is separate.
use super::*;
use channel::Pipe;
const MAC: [u8; 6] = [0x52, 0x54, 0, 0xab, 0x5d, 0x15];
const PEER: [u8; 6] = [0x52, 0x55, 0, 0, 2, 2];
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
    incoming: VecDeque<(u64, Vec<u8>)>,
    send_advance: u64,
    read_advance: u64,
    send_error: bool,
    receive_error: bool,
    stalled: bool,
    dns: bool,
    feedback: Option<crate::ipv6::feedback::Observation>,
    taken: u32,
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
        let mut s = self.0.borrow_mut();
        if !s.stalled {
            s.now += ms;
        }
    }
    fn send(&mut self, f: &[u8]) -> Result<(), i64> {
        let mut s = self.0.borrow_mut();
        s.sent.push(f.to_vec());
        s.now += s.send_advance;
        if (s.dns || s.feedback.is_some())
            && f.len() >= 78
            && f[20] == 58
            && f[54] == 135
            && f[22..38] != [0; 16]
        {
            let mut p = Policy::fixture();
            p.config.address = p.peer.ip;
            let now = s.now;
            s.incoming.push_back((now, packet(p, PEER, true)));
        }
        if f.len() >= 74 && f[20] == 17 {
            let now = s.now;
            if let Some(observation) = s.feedback {
                s.incoming.push_back((now, feedback_error(f, observation)));
            } else if s.dns {
                s.incoming.push_back((now, dns_answer(f)));
            }
        }
        if s.send_error { Err(-5) } else { Ok(()) }
    }
    fn receive(&mut self, b: &mut [u8; FRAME_MAX], _: u64) -> Result<Option<usize>, i64> {
        let mut s = self.0.borrow_mut();
        s.now += s.read_advance;
        if s.receive_error {
            return Err(-5);
        }
        if s.incoming.front().is_some_and(|(at, _)| *at <= s.now) {
            let (_, f) = s.incoming.pop_front().unwrap();
            s.taken += 1;
            b[..f.len()].copy_from_slice(&f);
            Ok(Some(f.len()))
        } else {
            Ok(None)
        }
    }
}
fn link() -> (Rc<RefCell<State>>, Mock) {
    let s = Rc::new(RefCell::new(State {
        now: 100,
        reading: up(),
        sent: Vec::new(),
        incoming: VecDeque::new(),
        send_advance: 0,
        read_advance: 0,
        send_error: false,
        receive_error: false,
        stalled: false,
        dns: false,
        feedback: None,
        taken: 0,
    }));
    (s.clone(), Mock(s))
}
fn acquire(l: Mock) -> Result<Owner<Mock>, Error> {
    Owner::acquire(l, Policy::fixture(), 100, |b| {
        b.fill(0);
        Ok::<(), ()>(())
    })
}
fn ready() -> (Rc<RefCell<State>>, Owner<Mock>) {
    let (s, l) = link();
    (s, acquire(l).unwrap())
}
fn recalc(f: &mut [u8]) {
    let src = Ipv6Address::from(<[u8; 16]>::try_from(&f[22..38]).unwrap());
    let dst = Ipv6Address::from(<[u8; 16]>::try_from(&f[38..54]).unwrap());
    Icmpv6Packet::new_unchecked(&mut f[54..]).fill_checksum(&src, &dst);
}
fn feedback_error(submitted: &[u8], observation: crate::ipv6::feedback::Observation) -> Vec<u8> {
    let mut frame = vec![0; 62 + submitted.len() - 14];
    frame[..6].copy_from_slice(&MAC);
    frame[6..12].copy_from_slice(&PEER);
    frame[12..15].copy_from_slice(&[0x86, 0xdd, 0x60]);
    let length = (frame.len() - 54) as u16;
    frame[18..20].copy_from_slice(&length.to_be_bytes());
    frame[20..22].copy_from_slice(&[58, 64]);
    frame[22..38].copy_from_slice(&submitted[38..54]);
    frame[38..54].copy_from_slice(&submitted[22..38]);
    frame[54..62].copy_from_slice(&observation.encode());
    frame[62..].copy_from_slice(&submitted[14..]);
    recalc(&mut frame);
    frame
}
fn unicast_advertisement(solicited: bool) -> Vec<u8> {
    let p = Policy::fixture();
    let mut frame = packet(p, PEER, true);
    frame[..6].copy_from_slice(&MAC);
    frame[38..54].copy_from_slice(&p.config.address);
    if solicited {
        frame[58] |= 0x40;
    }
    recalc(&mut frame);
    frame
}
fn sum(b: &[u8]) -> u16 {
    let mut n: u32 = b
        .chunks(2)
        .map(|b| u16::from_be_bytes([b[0], *b.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while n > 65535 {
        n = (n & 65535) + (n >> 16);
    }
    !(n as u16)
}
fn dns_answer(q: &[u8]) -> Vec<u8> {
    let question = &q[62..];
    let typ = u16::from_be_bytes(
        question[question.len() - 4..question.len() - 2]
            .try_into()
            .unwrap(),
    );
    let data = if typ == 1 {
        vec![192, 0, 2, 88]
    } else {
        let mut a = vec![0; 16];
        a[0] = 0x20;
        a[1] = 1;
        a[15] = 0x88;
        a
    };
    let mut dns = question.to_vec();
    dns[2..4].copy_from_slice(&[0x81, 0x80]);
    dns[6..8].copy_from_slice(&[0, 1]);
    dns.extend_from_slice(&[0xc0, 0x0c]);
    dns.extend_from_slice(&typ.to_be_bytes());
    dns.extend_from_slice(&[0, 1, 0, 0, 0, 30]);
    dns.extend_from_slice(&(data.len() as u16).to_be_bytes());
    dns.extend(data);
    let mut f = vec![0; 62 + dns.len()];
    f[..6].copy_from_slice(&MAC);
    f[6..12].copy_from_slice(&PEER);
    f[12..15].copy_from_slice(&[0x86, 0xdd, 0x60]);
    let n = (8 + dns.len()) as u16;
    f[18..20].copy_from_slice(&n.to_be_bytes());
    f[20..22].copy_from_slice(&[17, 64]);
    f[22..38].copy_from_slice(&q[38..54]);
    f[38..54].copy_from_slice(&q[22..38]);
    f[54..56].copy_from_slice(&42010u16.to_be_bytes());
    f[56..58].copy_from_slice(&7002u16.to_be_bytes());
    f[58..60].copy_from_slice(&n.to_be_bytes());
    f[62..].copy_from_slice(&dns);
    let mut pseudo = f[22..54].to_vec();
    pseudo.extend_from_slice(&u32::from(n).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    pseudo.extend_from_slice(&f[54..]);
    let v = sum(&pseudo);
    f[60..62].copy_from_slice(&(if v == 0 { 65535 } else { v }).to_be_bytes());
    f
}
struct Stream {
    state: Rc<RefCell<State>>,
    input: VecDeque<u8>,
    output: VecDeque<u8>,
    limit: usize,
    advance: u64,
    fail: bool,
    reading_after: Option<Option<LinkReading>>,
}
impl Stream {
    fn new(state: Rc<RefCell<State>>) -> Self {
        Self {
            state,
            input: VecDeque::new(),
            output: VecDeque::new(),
            limit: 256,
            advance: 0,
            fail: false,
            reading_after: None,
        }
    }
}
impl Pipe for Stream {
    fn now_ms(&self) -> u64 {
        0
    } // Deliberately cached: owner must sample actual Link.
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        let n = b.len().min(self.input.len()).min(self.limit);
        for v in &mut b[..n] {
            *v = self.input.pop_front().unwrap();
        }
        self.state.borrow_mut().now += self.advance;
        if let Some(r) = self.reading_after {
            self.state.borrow_mut().reading = r;
        }
        if self.fail {
            Err(-5)
        } else if n == 0 {
            Ok(None)
        } else {
            Ok(Some(n))
        }
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        let n = b.len().min(self.limit);
        self.output.extend(&b[..n]);
        self.state.borrow_mut().now += self.advance;
        if let Some(r) = self.reading_after {
            self.state.borrow_mut().reading = r;
        }
        if self.fail {
            Err(-5)
        } else if n == 0 {
            Ok(None)
        } else {
            Ok(Some(n))
        }
    }
}
fn send_request(peer: Address, b: &[u8]) -> Vec<u8> {
    let mut r = vec![0; session::HEADER + b.len()];
    r[..4].copy_from_slice(&[2, 1, 0, 6]);
    r[4..20].copy_from_slice(&peer.ip);
    r[20..24].copy_from_slice(&peer.scope.to_be_bytes());
    r[24..26].copy_from_slice(&peer.port.to_be_bytes());
    r[26..28].copy_from_slice(&(b.len() as u16).to_be_bytes());
    r[28..].copy_from_slice(b);
    let mut f = (r.len() as u16).to_be_bytes().to_vec();
    f.extend(r);
    f
}
#[test]
fn fixed_wire_forms_and_independent_checksums_are_exact() {
    let p = Policy::fixture();
    assert_eq!(
        p.config.address,
        [0xfd, 0, 0xab, 0x5d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x15]
    );
    let ns = packet(p, MAC, false);
    let na = packet(p, MAC, true);
    assert_eq!(ns.len(), 78);
    assert_eq!(
        &ns[..14],
        &[
            0x33, 0x33, 0xff, 0, 0, 0x15, 0x52, 0x54, 0, 0xab, 0x5d, 0x15, 0x86, 0xdd
        ]
    );
    assert_eq!(&ns[14..22], &[0x60, 0, 0, 0, 0, 24, 58, 255]);
    assert_eq!(&ns[22..38], &[0; 16]);
    assert_eq!(&ns[38..54], &solicited(p.config.address));
    assert_eq!(&ns[54..56], &[135, 0]);
    assert_eq!(&ns[58..62], &[0; 4]);
    assert_eq!(&ns[62..], &p.config.address);
    assert_eq!(na.len(), 86);
    assert_eq!(
        &na[..14],
        &[
            0x33, 0x33, 0, 0, 0, 1, 0x52, 0x54, 0, 0xab, 0x5d, 0x15, 0x86, 0xdd
        ]
    );
    assert_eq!(&na[14..22], &[0x60, 0, 0, 0, 0, 32, 58, 255]);
    assert_eq!(&na[22..38], &p.config.address);
    assert_eq!(
        &na[38..54],
        &[0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    );
    assert_eq!(&na[54..56], &[136, 0]);
    assert_eq!(&na[62..78], &p.config.address);
    assert_eq!(&na[58..62], &[0x20, 0, 0, 0]);
    assert_eq!(&na[78..], &[2, 1, 0x52, 0x54, 0, 0xab, 0x5d, 0x15]);
    for f in [ns, na] {
        let mut b = f[22..54].to_vec();
        b.extend_from_slice(&((f.len() - 54) as u32).to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 58]);
        b.extend_from_slice(&f[54..]);
        assert_eq!(sum(&b), 0);
    }
}
#[test]
fn preflight_sends_no_application_or_grant_and_uses_original_budget() {
    let (s, mut o) = ready();
    assert_eq!(s.borrow().now, 1100);
    assert_eq!(o.socket_count(), 0);
    assert_eq!(s.borrow().sent, vec![packet(Policy::fixture(), MAC, false)]);
    assert_eq!(o.observations().probes_submitted, 1);
    assert_eq!(o.until_ms(), 12100);
    assert_eq!(o.stop_ms(), 9100);
    o.start_dns().unwrap();
    assert_eq!(o.socket_count(), 1);
    assert_eq!(o.start_dns(), Err(Error::Denied));
    o.retire();
    assert_eq!(o.socket_count(), 0);
    assert_eq!(o.check(), Err(Error::Retired));
}
#[test]
fn entropy_failure_late_entropy_overflow_and_start_rewind_do_not_submit() {
    let (s, l) = link();
    assert!(matches!(
        Owner::acquire(l, Policy::fixture(), 100, |_| Err::<(), ()>(())),
        Err(Error::Entropy)
    ));
    assert!(s.borrow().sent.is_empty());
    let (s, l) = link();
    let ss = s.clone();
    assert!(matches!(
        Owner::acquire(l, Policy::fixture(), 100, move |b| {
            b.fill(0);
            ss.borrow_mut().now = 3100;
            Ok::<(), ()>(())
        }),
        Err(Error::Timeout)
    ));
    assert!(s.borrow().sent.is_empty());
    let (_, l) = link();
    assert!(matches!(
        Owner::acquire(l, Policy::fixture(), u64::MAX, |_| Ok::<(), ()>(())),
        Err(Error::Clock)
    ));
    let (_, l) = link();
    assert!(matches!(
        Owner::acquire(l, Policy::fixture(), 101, |_| Ok::<(), ()>(())),
        Err(Error::Clock)
    ));
}
#[test]
fn duplicate_before_probe_and_at_final_observation_refuse_before_activation() {
    for (at, defend) in [(100, false), (100, true), (1100, true)] {
        let (s, l) = link();
        s.borrow_mut()
            .incoming
            .push_back((at, packet(Policy::fixture(), PEER, defend)));
        assert!(matches!(acquire(l), Err(Error::Conflict)));
        assert!(s.borrow().sent.iter().all(|f| f[22..38] == [0; 16]));
    }
}
#[test]
fn own_mac_reflections_refuse_without_assuming_loopback_identity() {
    let (s, l) = link();
    s.borrow_mut()
        .incoming
        .push_back((101, packet(Policy::fixture(), MAC, false)));
    assert!(matches!(acquire(l), Err(Error::Ambiguous)));
}
#[test]
fn valid_unicast_na_refuses_tentative_before_probe_and_at_final_observation() {
    for at in [100, 1100] {
        for solicited in [false, true] {
            let (state, link) = link();
            state
                .borrow_mut()
                .incoming
                .push_back((at, unicast_advertisement(solicited)));
            assert!(matches!(acquire(link), Err(Error::Conflict)));
            let state = state.borrow();
            assert_eq!(state.sent.len(), usize::from(at == 1100));
            assert!(state.sent.iter().all(|frame| frame[22..38] == [0; 16]));
        }
    }
}
#[test]
fn unicast_na_conflict_is_phase_independent_but_invalid_nd_never_claims_conflict() {
    for active in [false, true] {
        for solicited in [false, true] {
            let mut guard = Guard::new(Policy::fixture(), MAC, 100, 100, up()).unwrap();
            if active {
                guard.observations.probes_submitted = 1;
                guard.activate(100).unwrap();
            }
            assert_eq!(
                guard.frame(&unicast_advertisement(solicited)),
                Err(Error::Conflict)
            );
            assert_eq!(guard.phase, Phase::Retired);
            assert_eq!(guard.check(100, up()), Err(Error::Conflict));
        }
        for mode in 0..8 {
            let mut frame = unicast_advertisement(false);
            match mode {
                0 => frame[21] = 254,
                1 => frame[55] = 1,
                2 => frame[56] ^= 1,
                3 => frame[0] ^= 1,
                4 => frame[22..38].fill(0),
                5 => frame[85] ^= 1,
                6 => {
                    frame[..6].copy_from_slice(&multicast_mac(all_nodes()));
                    frame[38..54].copy_from_slice(&all_nodes());
                    frame[58] |= 0x40;
                }
                7 => frame[79] = 0,
                _ => unreachable!(),
            }
            if mode != 2 {
                recalc(&mut frame);
            }
            assert_eq!(
                inspect(&frame, Policy::fixture().config.address, MAC),
                Message::Malformed
            );
            let mut guard = Guard::new(Policy::fixture(), MAC, 100, 100, up()).unwrap();
            if active {
                guard.observations.probes_submitted = 1;
                guard.activate(100).unwrap();
            }
            let phase = guard.phase;
            assert_eq!(guard.frame(&frame), Ok(true));
            assert_eq!(guard.phase, phase);
            assert_eq!(guard.observations.malformed, 1);
        }
    }
}
#[test]
fn non_nd_icmpv6_bypasses_nd_only_hop_and_minimum_length_checks() {
    let mut echo = vec![0; 62];
    echo[..6].copy_from_slice(&MAC);
    echo[6..12].copy_from_slice(&PEER);
    echo[12..15].copy_from_slice(&[0x86, 0xdd, 0x60]);
    echo[18..20].copy_from_slice(&8u16.to_be_bytes());
    echo[20..22].copy_from_slice(&[58, 64]);
    echo[22..38].copy_from_slice(&Policy::fixture().peer.ip);
    echo[38..54].copy_from_slice(&Policy::fixture().config.address);
    echo[54] = 128;
    recalc(&mut echo);
    assert_eq!(
        inspect(&echo, Policy::fixture().config.address, MAC),
        Message::Other
    );
    for kind in [135, 136] {
        echo[54] = kind;
        echo[21] = 255;
        recalc(&mut echo);
        assert_eq!(
            inspect(&echo, Policy::fixture().config.address, MAC),
            Message::Malformed
        );
    }
}
#[test]
fn malformed_dad_fields_never_create_conflict_or_defense() {
    let original = packet(Policy::fixture(), PEER, false);
    for case in 0..9 {
        let mut f = original.clone();
        match case {
            0 => f[21] = 254,
            1 => f[55] = 1,
            2 => f[57] ^= 1,
            3 => f[53] ^= 1,
            4 => f[0] ^= 1,
            5 => {
                f.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0]);
                f[18..20].copy_from_slice(&32u16.to_be_bytes());
            }
            6 => {
                f.extend_from_slice(&[254, 0]);
                f[18..20].copy_from_slice(&26u16.to_be_bytes());
            }
            7 => {
                f.push(0);
            }
            8 => f[6] |= 1,
            _ => unreachable!(),
        };
        if case != 2 && case != 7 {
            recalc(&mut f);
        }
        assert_eq!(
            inspect(&f, Policy::fixture().config.address, MAC),
            Message::Malformed,
            "case {case}"
        );
    }
}
#[test]
fn unknown_options_reserved_and_unrelated_nd_keep_actual_semantics() {
    let p = Policy::fixture();
    let mut f = packet(p, PEER, false);
    f[58] = 0x88;
    f.extend_from_slice(&[254, 1, 1, 2, 3, 4, 5, 6]);
    f[18..20].copy_from_slice(&32u16.to_be_bytes());
    recalc(&mut f);
    assert_eq!(inspect(&f, p.config.address, MAC), Message::Dad);
    f[22..38].copy_from_slice(&p.peer.ip);
    recalc(&mut f);
    assert_eq!(inspect(&f, p.config.address, MAC), Message::Other);
    let mut other = p;
    other.config.address = p.peer.ip;
    assert_eq!(
        inspect(&packet(other, PEER, true), p.config.address, MAC),
        Message::Other
    );
    let mut ra = packet(p, PEER, true);
    ra[54] = 134;
    recalc(&mut ra);
    assert_eq!(inspect(&ra, p.config.address, MAC), Message::Other);
}
#[test]
fn acquisition_uncertain_send_and_straddling_receive_keep_first_effect_only() {
    for error in [false, true] {
        let (s, l) = link();
        s.borrow_mut().send_advance = 3000;
        s.borrow_mut().send_error = error;
        assert!(acquire(l).is_err());
        assert_eq!(s.borrow().sent.len(), 1);
    }
    let (s, l) = link();
    s.borrow_mut().read_advance = 3000;
    s.borrow_mut().incoming.push_back((100, vec![0; 60]));
    assert!(acquire(l).is_err());
    assert!(s.borrow().sent.is_empty());
    assert_eq!(s.borrow().taken, 1);
}
#[test]
fn stalled_clock_receive_work_and_link_loss_cannot_succeed() {
    let (s, l) = link();
    s.borrow_mut().stalled = true;
    assert!(matches!(acquire(l), Err(Error::Exhausted)));
    assert_eq!(s.borrow().sent.len(), 1);
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
        let (_, l) = link();
        l.0.borrow_mut().reading = reading;
        assert!(matches!(acquire(l), Err(Error::Link)));
    }
    let (s, l) = link();
    for _ in 0..16 {
        s.borrow_mut().incoming.push_back((100, vec![0; 60]));
    }
    assert!(matches!(acquire(l), Err(Error::Exhausted)));
}
#[test]
fn active_defense_is_fixed_and_quota_refusal_retires_owned_state() {
    let (s, mut o) = ready();
    o.start_dns().unwrap();
    let mut p = Stream::new(s.clone());
    for n in 0..4 {
        let mut state = s.borrow_mut();
        state.now = 1100 + n * 1000;
        let at = state.now;
        state
            .incoming
            .push_back((at, packet(Policy::fixture(), PEER, false)));
        drop(state);
        o.poll(&mut p).unwrap();
    }
    assert_eq!(o.observations().defenses_submitted, 4);
    assert_eq!(s.borrow().sent.iter().filter(|f| f[54] == 136).count(), 4);
    assert!(
        s.borrow().sent[1..]
            .iter()
            .all(|f| *f == packet(Policy::fixture(), MAC, true))
    );
    s.borrow_mut().now = 5100;
    s.borrow_mut()
        .incoming
        .push_back((5100, packet(Policy::fixture(), PEER, false)));
    assert_eq!(o.poll(&mut p), Err(Error::Exhausted));
    assert_eq!(o.socket_count(), 0);
    assert!(o.channel.is_none());
    assert_eq!(s.borrow().sent.len(), 5);
}
#[test]
fn rate_limit_conflicting_advertisement_and_counter_change_are_terminal() {
    for mode in 0..3 {
        let (s, mut o) = ready();
        o.start_dns().unwrap();
        let mut p = Stream::new(s.clone());
        if mode == 0 {
            s.borrow_mut()
                .incoming
                .push_back((1100, packet(Policy::fixture(), PEER, false)));
            o.poll(&mut p).unwrap();
            s.borrow_mut()
                .incoming
                .push_back((1100, packet(Policy::fixture(), PEER, false)));
        } else if mode == 1 {
            s.borrow_mut()
                .incoming
                .push_back((1100, packet(Policy::fixture(), PEER, true)));
        } else {
            s.borrow_mut().reading.as_mut().unwrap().rx_missed = 1;
        }
        assert!(o.poll(&mut p).is_err());
        assert_eq!(o.socket_count(), 0);
        assert!(o.channel.is_none());
    }
}
#[test]
fn active_uncertain_defense_and_application_send_never_submit_twice() {
    let (s, mut o) = ready();
    o.start_dns().unwrap();
    s.borrow_mut().send_error = true;
    s.borrow_mut()
        .incoming
        .push_back((1100, packet(Policy::fixture(), PEER, false)));
    let mut p = Stream::new(s.clone());
    assert!(o.poll(&mut p).is_err());
    assert_eq!(s.borrow().sent.len(), 2);
    assert!(o.poll(&mut p).is_err());
    assert_eq!(s.borrow().sent.len(), 2);
    let (s, mut o) = ready();
    o.start_dns().unwrap();
    let until = o.stop_ms();
    let g = o.stack.as_ref().unwrap().link();
    s.borrow_mut().send_advance = until - 1100;
    let mut token = Guarded {
        link: g.link.clone(),
        guard: g.guard.clone(),
    };
    assert!(token.send(&[7; 60]).is_err());
    assert_eq!(s.borrow().sent.len(), 2);
    assert!(token.send(&[7; 60]).is_err());
    assert_eq!(s.borrow().sent.len(), 2);
    assert!(o.check().is_err());
    assert_eq!(o.socket_count(), 0);
}
#[test]
fn pending_partial_and_final_writes_resample_actual_link_clock() {
    for partial in [false, true] {
        let (s, mut o) = ready();
        o.start_dns().unwrap();
        let mut p = Stream::new(s.clone());
        p.input.extend(send_request(o.peer(), b"queued"));
        for _ in 0..2 {
            o.poll(&mut p).unwrap();
        }
        assert!(p.output.is_empty());
        p.limit = if partial { 1 } else { 256 };
        p.advance = o.stop_ms() - s.borrow().now;
        assert!(o.poll(&mut p).is_err());
        let n = p.output.len();
        assert_eq!(n, if partial { 1 } else { 30 });
        assert!(o.poll(&mut p).is_err());
        assert_eq!(p.output.len(), n);
        assert_eq!(o.socket_count(), 0);
    }
}
#[test]
fn pipe_read_link_loss_and_interruption_fence_before_application_queueing() {
    for mode in 0..2 {
        let (s, mut o) = ready();
        o.start_dns().unwrap();
        let mut p = Stream::new(s.clone());
        p.input.extend(send_request(o.peer(), b"never-queued"));
        if mode == 0 {
            p.reading_after = Some(None);
        } else {
            p.fail = true;
        }
        assert!(o.poll(&mut p).is_err());
        assert_eq!(o.socket_count(), 0);
        assert_eq!(s.borrow().sent.len(), 1);
    }
}
#[test]
fn blocked_replies_rewind_and_fresh_owner_never_restore_stale_output() {
    let (s, mut o) = ready();
    o.start_dns().unwrap();
    let mut p = Stream::new(s.clone());
    p.input.extend(send_request(o.peer(), b"old"));
    for _ in 0..2 {
        o.poll(&mut p).unwrap();
    }
    p.limit = 0;
    o.poll(&mut p).unwrap();
    s.borrow_mut().now = 100;
    assert!(o.poll(&mut p).is_err());
    assert!(o.channel.is_none());
    assert!(p.output.is_empty());
    let (next, mut fresh) = ready();
    fresh.start_dns().unwrap();
    let mut newpipe = Stream::new(next.clone());
    fresh.poll(&mut newpipe).unwrap();
    assert!(newpipe.output.is_empty());
    fresh.poll(&mut p).unwrap();
    assert!(p.output.is_empty());
    assert_eq!(next.borrow().sent.len(), 1);
}
struct Client<'a> {
    owner: &'a mut Owner<Mock>,
    pipe: &'a mut Stream,
}
impl Pipe for Client<'_> {
    fn now_ms(&self) -> u64 {
        self.pipe.state.borrow().now
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        self.pipe.input.extend(b);
        Ok(Some(b.len()))
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        self.owner.poll(self.pipe).map_err(|_| -5i64)?;
        let n = b.len().min(self.pipe.output.len());
        for v in &mut b[..n] {
            *v = self.pipe.output.pop_front().unwrap();
        }
        self.pipe.state.borrow_mut().now += 1;
        if n == 0 { Ok(None) } else { Ok(Some(n)) }
    }
}
#[test]
fn actual_engine_channel_and_resolver_work_after_dad_activation() {
    let (s, mut o) = ready();
    s.borrow_mut().dns = true;
    o.start_dns().unwrap();
    let peer = o.peer();
    let mut p = Stream::new(s.clone());
    let client = Client {
        owner: &mut o,
        pipe: &mut p,
    };
    let transport = crate::ipv6::dns::Datagram::new(client, peer, |_| {});
    let mut resolver = crate::dns::Resolver::new(transport, 0x1234);
    let a = resolver.lookup("a.example").unwrap();
    assert_eq!(a.addresses[0], [192, 0, 2, 88]);
    let a = resolver.lookup_aaaa("aaaa.example").unwrap();
    assert_eq!(a.addresses[0][15], 0x88);
    drop(resolver);
    assert_eq!(s.borrow().sent[0], packet(Policy::fixture(), MAC, false));
    assert!(s.borrow().sent.iter().skip(1).any(|f| f[20] == 17));
    o.retire();
    assert_eq!(o.socket_count(), 0);
}
#[test]
fn active_owner_preserves_real_submitted_datagram_feedback_through_issued_pipe() {
    use crate::ipv6::feedback::{FEEDBACK, Observation, WIRE_LEN};
    for observation in [
        Observation {
            kind: 1,
            code: 4,
            detail: 0,
        },
        Observation {
            kind: 2,
            code: 0,
            detail: 1500,
        },
        Observation {
            kind: 3,
            code: 0,
            detail: 0,
        },
    ] {
        let (state, mut owner) = ready();
        state.borrow_mut().feedback = Some(observation);
        owner.start_dns().unwrap();
        let peer = owner.peer();
        let mut pipe = Stream::new(state.clone());
        let mut client = Client {
            owner: &mut owner,
            pipe: &mut pipe,
        };
        let request = send_request(peer, b"actual-dad-feedback");
        let mut reply = [0; session::MAX_MESSAGE];
        assert_eq!(
            channel::transact(&mut client, &request[2..], &mut reply, 250),
            Ok(session::HEADER)
        );
        assert_eq!(reply[2], 0);
        let mut request = [0; session::HEADER];
        request[..4].copy_from_slice(&[session::VERSION, FEEDBACK, 0, session::FAMILY]);
        let mut observed = false;
        for _ in 0..8 {
            let n = channel::transact(&mut client, &request, &mut reply, 250).unwrap();
            if reply[2] == crate::ipv6::Error::Again.code() {
                continue;
            }
            assert_eq!(reply[2], 0);
            assert_eq!(n, session::HEADER + WIRE_LEN);
            assert_eq!(
                Observation::decode(&reply[session::HEADER..n]),
                Some(observation)
            );
            observed = true;
            break;
        }
        assert!(
            observed,
            "actual hop64 ICMPv6 feedback must cross the active DAD owner"
        );
        assert_eq!(
            channel::transact(&mut client, &request, &mut reply, 250),
            Ok(session::HEADER)
        );
        assert_eq!(reply[2], crate::ipv6::Error::Again.code());
        drop(client);
        owner.check().unwrap();
        assert_eq!(owner.observations().malformed, 0);
        assert_eq!(
            state
                .borrow()
                .sent
                .iter()
                .filter(|frame| frame[20] == 17)
                .count(),
            1
        );
        owner.retire();
        assert_eq!(owner.socket_count(), 0);
    }
}

#[test]
fn bootstrap_literal_schema_and_original_deadline_refuse_mutations() {
    let (_, mut owner) = ready();
    let b = owner.bootstrap().unwrap();
    assert_eq!(&b[..2], &[1, 0]);
    assert_eq!(&b[18..24], &[0, 0, 0, 1, 0xa4, 0x1a]);
    assert_eq!(&b[24..32], &100u64.to_be_bytes());
    assert_eq!(&b[32..40], &9100u64.to_be_bytes());
    assert_eq!(decode_bootstrap(&b, 1100), Ok((owner.peer(), 9100)));
    assert_eq!(decode_bootstrap(&b, 9100), Err(Error::Timeout));
    assert_eq!(decode_bootstrap(&b, 99), Err(Error::Clock));
    for offset in [0, 1, 2, 18, 22] {
        let mut bad = b;
        bad[offset] ^= 1;
        assert!(decode_bootstrap(&bad, 1100).is_err());
    }
    let mut bad = b;
    bad[24..32].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(decode_bootstrap(&bad, 1100), Err(Error::Clock));
    let mut bad = b;
    bad[32..40].copy_from_slice(&12101u64.to_be_bytes());
    assert_eq!(decode_bootstrap(&bad, 1100), Err(Error::Timeout));
}
#[test]
fn malformed_advertisements_do_not_claim_conflict_or_trigger_response() {
    let p = Policy::fixture();
    for mode in 0..6 {
        let mut f = packet(p, PEER, true);
        match mode {
            0 => f[22..38].fill(0),
            1 => f[58] |= 0x40,
            2 => f[85] ^= 1,
            3 => f[79] = 0,
            4 => f[0] ^= 1,
            5 => f[55] = 1,
            _ => unreachable!(),
        }
        recalc(&mut f);
        assert_eq!(inspect(&f, p.config.address, MAC), Message::Malformed);
    }
}
#[test]
fn receive_error_and_recovered_link_do_not_revive_retired_owner() {
    let (s, l) = link();
    s.borrow_mut().receive_error = true;
    assert!(matches!(acquire(l), Err(Error::Link)));
    assert!(s.borrow().sent.is_empty());
    let (s, mut o) = ready();
    o.start_dns().unwrap();
    let mut p = Stream::new(s.clone());
    s.borrow_mut().receive_error = true;
    assert!(o.poll(&mut p).is_err());
    s.borrow_mut().receive_error = false;
    s.borrow_mut().reading = up();
    assert!(o.poll(&mut p).is_err());
    assert!(o.channel.is_none());
    assert_eq!(o.socket_count(), 0);
}
#[test]
fn private_channel_wrong_peer_denial_cannot_submit_application_datagram() {
    let (s, mut o) = ready();
    o.start_dns().unwrap();
    let mut p = Stream::new(s.clone());
    let mut wrong = o.peer();
    wrong.port += 1;
    p.input.extend(send_request(wrong, b"denied"));
    for _ in 0..3 {
        o.poll(&mut p).unwrap();
    }
    let response = p.output.iter().copied().collect::<Vec<_>>();
    assert_eq!(response.len(), 30);
    assert_eq!(response[4], v6_denied());
    assert_eq!(s.borrow().sent.len(), 1);
}
fn v6_denied() -> u8 {
    crate::ipv6::Error::Denied.code()
}
#[test]
fn guard_activation_and_finite_frame_budget_refuse_without_authority() {
    let mut g = Guard::new(Policy::fixture(), MAC, 100, 100, up()).unwrap();
    assert_eq!(g.activate(100), Err(Error::Denied));
    assert_eq!(g.phase, Phase::Retired);
    let mut g = Guard::new(Policy::fixture(), MAC, 100, 100, up()).unwrap();
    for _ in 0..MAX_FRAMES {
        assert_eq!(g.frame(&[0; 60]), Ok(false));
    }
    assert_eq!(g.frame(&[0; 60]), Err(Error::Exhausted));
    assert_eq!(g.phase, Phase::Retired);
}
