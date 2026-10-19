//! Deterministic controls, authored here but executed only on the admitted host.
use super::*;
use std::cell::Cell;

const MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
const XID: u32 = 0x12345678;
fn up() -> Option<LinkReading> {
    Some(LinkReading {
        link_up: true,
        disabled: false,
        rx_missed: 0,
    })
}
fn fix_lengths(frame: &mut Vec<u8>) {
    let ip = (frame.len() - 14) as u16;
    let udp = (frame.len() - 34) as u16;
    frame[16..18].copy_from_slice(&ip.to_be_bytes());
    frame[38..40].copy_from_slice(&udp.to_be_bytes());
    frame[24..26].fill(0);
    let mut checksum = sum(&frame[14..34]);
    while checksum > 0xffff {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }
    frame[24..26].copy_from_slice(&(!(checksum as u16)).to_be_bytes());
}
fn reply(kind: u8) -> Vec<u8> {
    let p = Policy::fixture();
    let mut f = vec![0; 282];
    f[..6].copy_from_slice(&MAC);
    f[6..12].copy_from_slice(&p.server_mac);
    f[12..15].copy_from_slice(&[8, 0, 0x45]);
    f[22..24].copy_from_slice(&[64, 17]);
    f[26..30].copy_from_slice(&p.server);
    f[30..34].copy_from_slice(&p.address);
    f[34..38].copy_from_slice(&[0, 67, 0, 68]);
    f[42..46].copy_from_slice(&[2, 1, 6, 0]);
    f[46..50].copy_from_slice(&XID.to_be_bytes());
    if kind != 6 {
        f[58..62].copy_from_slice(&p.address);
    }
    f[70..76].copy_from_slice(&MAC);
    f[278..282].copy_from_slice(&[99, 130, 83, 99]);
    f.extend_from_slice(&[53, 1, kind, 54, 4]);
    f.extend_from_slice(&p.server);
    for (code, bytes) in [
        (1, p.mask),
        (3, p.server),
        (6, p.server),
        (51, 120u32.to_be_bytes()),
        (58, 60u32.to_be_bytes()),
        (59, 105u32.to_be_bytes()),
    ] {
        f.extend_from_slice(&[code, 4]);
        f.extend_from_slice(&bytes);
    }
    f.push(255);
    fix_lengths(&mut f);
    f
}
fn parsed(kind: u8) -> Message {
    message(&reply(kind), true, Policy::fixture(), MAC).unwrap()
}
fn requesting() -> Guard {
    let mut g = Guard::new(Policy::fixture(), MAC, 100).unwrap();
    let mut discover = parsed(2);
    discover.kind = 1;
    g.outgoing(discover, 100).unwrap();
    assert!(g.incoming(parsed(2)));
    let mut request = parsed(5);
    request.kind = 3;
    request.requested = Some(g.policy.address);
    g.outgoing(request, 200).unwrap();
    g
}
fn active() -> Guard {
    let mut g = requesting();
    assert!(g.incoming(parsed(5)));
    g.phase = Phase::Active;
    g.deadline = 8200;
    g
}

#[test]
fn exact_profile_accepts_offer_ack_and_uses_first_request_time() {
    let mut g = requesting();
    let mut retry = parsed(5);
    retry.kind = 3;
    retry.requested = Some(g.policy.address);
    g.outgoing(retry, 5000).unwrap();
    assert!(g.incoming(parsed(5)));
    let lease = g.lease.unwrap();
    assert_eq!(
        (
            lease.request_ms,
            lease.renew_ms,
            lease.rebind_ms,
            lease.expires_ms
        ),
        (200, 60200, 105200, 120200)
    );
    assert_eq!(g.phase, Phase::Candidate);
}
#[test]
fn wrong_xid_offer_is_counted_without_advancing_selection_or_deadline() {
    let mut guard = Guard::new(Policy::fixture(), MAC, 100).unwrap();
    let mut discover = parsed(2);
    discover.kind = 1;
    guard.outgoing(discover, 100).unwrap();
    let deadline = guard.deadline;
    let mut frame = reply(2);
    frame[46..50].copy_from_slice(&(XID ^ 1).to_be_bytes());
    let wrong = message(&frame, true, Policy::fixture(), MAC).unwrap();
    assert!(!guard.incoming(wrong));
    assert_eq!(guard.refused, 1);
    assert_eq!(guard.phase, Phase::Selecting);
    assert_eq!(guard.xid, Some(XID));
    assert_eq!(guard.offer, None);
    assert_eq!(guard.request_ms, None);
    assert_eq!(guard.error, None);
    assert_eq!(guard.deadline, deadline);
    // Valid same-shape calibration is accepted after that counted refusal.
    assert!(guard.incoming(parsed(2)));
    assert_eq!(guard.refused, 1);
    assert_eq!(guard.phase, Phase::Requesting);
    assert_eq!(guard.deadline, deadline);
}
#[test]
fn reply_correlation_and_duplicate_ack_cannot_create_or_extend_authority() {
    let mut g = Guard::new(Policy::fixture(), MAC, 100).unwrap();
    assert!(!g.incoming(parsed(5)));
    let mut g = requesting();
    for change in 0..4 {
        let mut m = parsed(5);
        match change {
            0 => m.xid ^= 1,
            1 => m.server = Some([192, 0, 2, 2]),
            2 => m.address[3] += 1,
            _ => m.router = Some([192, 0, 2, 2]),
        }
        assert!(!g.incoming(m));
        assert!(g.lease.is_none());
    }
    assert!(g.incoming(parsed(5)));
    let before = g.lease;
    let mut repeated = parsed(5);
    repeated.lease = Some(3600);
    assert!(!g.incoming(repeated));
    g.phase = Phase::Active;
    assert!(!g.incoming(repeated));
    assert_eq!(g.lease, before);
}
#[test]
fn malformed_option_tail_duplicate_overload_and_dns_list_are_refused() {
    for tail in [
        &[99, 4, 0][..],
        &[54, 4, 192, 0, 2, 1, 255],
        &[52, 1, 1, 255],
        &[6, 8, 192, 0, 2, 1, 192, 0, 2, 2, 255],
    ] {
        let mut f = reply(5);
        if tail[0] == 6 {
            // Remove the existing DNS field, then supply a single unsupported list.
            let at = 282 + 3 + 6 + 6 + 6;
            f.drain(at..at + 6);
        }
        f.pop();
        f.extend_from_slice(tail);
        fix_lengths(&mut f);
        assert_eq!(
            message(&f, true, Policy::fixture(), MAC).err(),
            Some(Error::Malformed)
        );
    }
    let mut trailing = reply(5);
    trailing.push(1);
    fix_lengths(&mut trailing);
    assert_eq!(
        message(&trailing, true, Policy::fixture(), MAC).err(),
        Some(Error::Malformed)
    );
}
#[test]
fn frame_lengths_fragments_checksums_cookie_mac_and_server_are_checked() {
    for at in [0, 6, 16, 20, 24, 26, 34, 38, 43, 44, 66, 70, 278] {
        let mut f = reply(5);
        f[at] ^= 1;
        assert!(
            message(&f, true, Policy::fixture(), MAC).is_err(),
            "byte {at}"
        );
    }
    for n in [0, 13, 33, 41, 281] {
        assert!(message(&reply(5)[..n], true, Policy::fixture(), MAC).is_err());
    }
    let mut checksum = reply(5);
    checksum[40..42].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(
        message(&checksum, true, Policy::fixture(), MAC).err(),
        Some(Error::Malformed)
    );
}
#[test]
fn missing_invalid_infinite_lease_and_timer_order_refuse_activation() {
    for seconds in [None, Some(0), Some(59), Some(3601), Some(u32::MAX)] {
        let mut g = requesting();
        let mut m = parsed(5);
        m.lease = seconds;
        assert!(!g.incoming(m));
        assert!(g.lease.is_none());
    }
    for (t1, t2) in [(0, 100), (100, 100), (110, 100), (60, 120)] {
        let mut g = requesting();
        let mut m = parsed(5);
        m.renew = Some(t1);
        m.rebind = Some(t2);
        assert!(!g.incoming(m));
        assert!(g.lease.is_none());
    }
    let mut g = requesting();
    let mut m = parsed(5);
    m.renew = None;
    m.rebind = None;
    assert!(g.incoming(m));
    assert_eq!(g.lease.unwrap().renew_ms, 60200);
}
#[test]
fn nak_link_loss_deadline_and_rewind_are_terminal() {
    let mut g = active();
    assert!(!g.incoming(parsed(6)));
    assert_eq!(g.error, Some(Error::Nak));
    for (now, link, error) in [
        (8200, up(), Error::Timeout),
        (99, up(), Error::Clock),
        (100, None, Error::Link),
        (
            100,
            Some(LinkReading {
                link_up: false,
                disabled: false,
                rx_missed: 0,
            }),
            Error::Link,
        ),
    ] {
        let mut g = active();
        assert_eq!(g.check(now, link), Err(error));
        assert_eq!(g.check(100, up()), Err(error));
        assert_eq!(g.phase, Phase::Retired);
    }
}
#[test]
fn conflict_detection_distinguishes_an_ordinary_who_has_request() {
    let mut g = active();
    let mut f = arp(g.policy.server_mac, g.policy.address, false);
    f[28..32].copy_from_slice(&g.policy.server);
    g.arp(&f);
    assert!(g.error.is_none());
    f[28..32].fill(0);
    g.arp(&f);
    assert_eq!(g.error, Some(Error::Conflict));
    let mut g = active();
    f[28..32].copy_from_slice(&g.policy.address);
    g.arp(&f);
    assert_eq!(g.error, Some(Error::Conflict));
    let mut g = active();
    g.arp(&arp(MAC, g.policy.address, true));
    assert!(g.error.is_none());
}
#[test]
fn decline_is_one_exact_broadcast_protocol_refusal() {
    let g = active();
    let f = decline(MAC, g.policy, g.lease.unwrap());
    let m = message(&f, false, g.policy, MAC).unwrap();
    assert_eq!(m.kind, 4);
    assert_eq!(m.requested, Some(g.policy.address));
    assert_eq!(m.server, Some(g.policy.server));
    assert_eq!(m.xid, XID);
}

struct Recording {
    now: Rc<Cell<u64>>,
    frames: Rc<RefCell<Vec<Vec<u8>>>>,
    advance_on_send: Option<u64>,
}
impl Link for Recording {
    fn mac(&self) -> [u8; 6] {
        MAC
    }
    fn now_ms(&self) -> u64 {
        self.now.get()
    }
    fn pause(&self, ms: u64) {
        self.now.set(self.now.get() + ms);
    }
    fn send(&mut self, frame: &[u8]) -> Result<(), i64> {
        self.frames.borrow_mut().push(frame.to_vec());
        if let Some(now) = self.advance_on_send.take() {
            self.now.set(now);
        }
        Ok(())
    }
    fn receive(&mut self, _: &mut [u8; FRAME_MAX], _: u64) -> Result<Option<usize>, i64> {
        Ok(None)
    }
}
struct Script {
    now: Rc<Cell<u64>>,
    input: VecDeque<u8>,
    output: Vec<u8>,
}
impl Pipe for Script {
    fn now_ms(&self) -> u64 {
        self.now.get()
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        let n = b.len().min(self.input.len());
        for x in &mut b[..n] {
            *x = self.input.pop_front().unwrap();
        }
        Ok(if n == 0 { None } else { Some(n) })
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        self.output.extend_from_slice(b);
        Ok(Some(b.len()))
    }
}
fn owner() -> (Owner<Recording>, Rc<Cell<u64>>, Rc<RefCell<Vec<Vec<u8>>>>) {
    let now = Rc::new(Cell::new(200));
    let frames = Rc::new(RefCell::new(Vec::new()));
    let guard = Rc::new(RefCell::new(active()));
    let stack = Stack::open(
        Guarded {
            link: Recording {
                now: now.clone(),
                frames: frames.clone(),
                advance_on_send: None,
            },
            guard: guard.clone(),
        },
        Config {
            address: Ipv4Address::from(Policy::fixture().address),
            prefix_len: 24,
            gateway: None,
            rx_buffer: 1024,
            tx_buffer: 1024,
        },
    )
    .unwrap();
    (
        Owner {
            stack: Some(stack),
            guard,
            issued: false,
        },
        now,
        frames,
    )
}
#[test]
fn expiry_drops_the_private_stack_with_queued_datagram_and_spent_grant() {
    let (mut owner, now, frames) = owner();
    let mut channel = owner.dns_channel().unwrap();
    assert!(matches!(owner.dns_channel(), Err(Error::Denied)));
    let mut request = vec![
        0,
        13,
        1,
        datagram::SEND,
        0,
        0,
        192,
        0,
        2,
        1,
        0,
        53,
        0,
        1,
        b'x',
    ];
    let mut pipe = Script {
        now: now.clone(),
        input: request.drain(..).collect(),
        output: Vec::new(),
    };
    owner.poll(&mut channel, &mut pipe).unwrap();
    owner.poll(&mut channel, &mut pipe).unwrap();
    assert_eq!(owner.stack.as_ref().unwrap().socket_count(), 1);
    let before = frames.borrow().len();
    now.set(owner.stop_ms());
    assert_eq!(owner.poll(&mut channel, &mut pipe), Err(Error::Timeout));
    assert!(owner.stack.is_none());
    assert_eq!(frames.borrow().len(), before);
    assert!(matches!(owner.dns_channel(), Err(Error::Retired)));
    assert_eq!(owner.poll(&mut channel, &mut pipe), Err(Error::Retired));
}
#[test]
fn frame_guard_blocks_submission_even_without_owner_polling() {
    let (mut owner, now, frames) = owner();
    now.set(owner.stop_ms());
    let result = owner.stack.as_mut().unwrap().port.link.send(&[0; 60]);
    assert_eq!(result, Err(REFUSED));
    assert!(frames.borrow().is_empty());
    owner.retire();
    assert!(owner.stack.is_none());
}
#[test]
fn a_send_straddling_expiry_records_its_effect_then_fences_all_later_work() {
    let (mut owner, now, frames) = owner();
    let mut channel = owner.dns_channel().unwrap();
    // One application UDP frame for the exact granted tuple. The injected
    // Link records its irreversible submission, then advances the clock.
    let mut frame = vec![0; 43];
    frame[..6].copy_from_slice(&Policy::fixture().server_mac);
    frame[6..12].copy_from_slice(&MAC);
    frame[12..15].copy_from_slice(&[8, 0, 0x45]);
    frame[22..24].copy_from_slice(&[64, 17]);
    frame[26..30].copy_from_slice(&Policy::fixture().address);
    frame[30..34].copy_from_slice(&Policy::fixture().server);
    frame[34..36].copy_from_slice(&DNS_LOCAL_PORT.to_be_bytes());
    frame[36..38].copy_from_slice(&53u16.to_be_bytes());
    frame[42] = b'x';
    fix_lengths(&mut frame);
    let stop = owner.stop_ms();
    let link = &mut owner.stack.as_mut().unwrap().port.link;
    link.link.advance_on_send = Some(stop);
    assert_eq!(link.send(&frame), Err(REFUSED));
    assert_eq!(frames.borrow().as_slice(), &[frame.clone()]);
    assert_eq!(link.guard.borrow().error, Some(Error::Timeout));
    assert_eq!(link.send(&frame), Err(REFUSED));
    assert_eq!(frames.borrow().len(), 1);
    let mut pipe = Script {
        now,
        input: VecDeque::new(),
        output: Vec::new(),
    };
    assert_eq!(owner.poll(&mut channel, &mut pipe), Err(Error::Timeout));
    assert!(owner.stack.is_none());
    assert_eq!(owner.poll(&mut channel, &mut pipe), Err(Error::Retired));
    assert_eq!(frames.borrow().len(), 1);
    assert!(pipe.output.is_empty());
}
#[test]
fn acquisition_and_clock_overflow_are_bounded() {
    assert!(matches!(
        Guard::new(Policy::fixture(), MAC, u64::MAX),
        Err(Error::Clock)
    ));
    let mut g = Guard::new(Policy::fixture(), MAC, 100).unwrap();
    assert_eq!(g.check(100 + ACQUIRE_MS, up()), Err(Error::Timeout));
}
